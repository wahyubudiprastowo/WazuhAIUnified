"""Restartable alert-window discovery and persistent, deduplicated IOC backlog."""
import ipaddress
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from soc_analysis import IOC_FIELDS, explain_rule, observable_kind, public_indicator
from detection_taxonomy import classify as classify_detection, telemetry_fields, telemetry_source
import entity_resolver


def stamp(value):
    return value.astimezone(timezone.utc).isoformat()


def bounds(payload):
    try:
        start = datetime.fromisoformat(str(payload['start']).replace('Z', '+00:00'))
        end = datetime.fromisoformat(str(payload['end']).replace('Z', '+00:00'))
        if start.tzinfo is None or end.tzinfo is None or not start < end or end - start > timedelta(days=186):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError('Provide start/end with timezone; end must follow start, maximum 186 days') from None
    return stamp(start), stamp(end)


def value_at(source, field):
    for key in field.split('.'):
        if not isinstance(source, dict):
            return None
        source = source.get(key)
    return source


def observables(event):
    found = {}
    for key, field in IOC_FIELDS.items():
        value = value_at(event, field)
        if not isinstance(value, str):
            continue
        kind = observable_kind(key)
        value = value.strip()
        if kind == 'ip':
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                continue
        elif kind in {'domain', 'md5', 'sha1', 'sha256'}:
            value = value.lower().rstrip('.')
        row = {'kind': kind, 'indicator': value}
        if public_indicator(row):
            found[(kind, value)] = row
    return list(found.values())


def rollup_dimensions(event):
    """Return bounded analytical dimensions without retaining the raw event."""
    rule = event.get('rule') if isinstance(event.get('rule'), dict) else {}
    agent = event.get('agent') if isinstance(event.get('agent'), dict) else {}
    decoder = event.get('decoder') if isinstance(event.get('decoder'), dict) else {}

    def first(*paths):
        for path in paths:
            value = value_at(event, path)
            if value not in (None, '', []):
                return value
        return None

    rows = [('total', 'all', 'All indexed alerts')]
    scalar = {
        'rule': (rule.get('id'), rule.get('description')),
        'decoder': (decoder.get('name'), decoder.get('name')),
        'source_ip': (first('data.srcip', 'data.src_ip', 'data.source.ip', 'data.office365.ClientIP'), None),
        'destination_ip': (first('data.dstip', 'data.dst_ip', 'data.destination.ip'), None),
        'identity': (first('data.office365.UserId', 'data.dstuser', 'data.srcuser',
                           'data.win.eventdata.targetUserName', 'data.user'), None),
        'asset': (agent.get('name') or agent.get('id'), agent.get('name')),
        'destination_port': (first('data.dstport', 'data.dst_port', 'data.destination.port'), None),
        'application': (first('data.app', 'data.application', 'data.appcat', 'data.service'), None),
        'firewall_policy': (first('data.policyid', 'data.policy_id', 'data.policyname', 'data.rule_name'), None),
        'direction': (first('data.direction', 'data.flow_direction'), None),
        'network_action': (first('data.action', 'data.event.action', 'data.status'), None),
        'forti_type': (first('data.type'), None),
        'forti_subtype': (first('data.subtype'), None),
        'severity': (str(rule.get('level')) if rule.get('level') is not None else None, None),
    }
    for dimension, (value, label) in scalar.items():
        if isinstance(value, (str, int, float)) and str(value).strip():
            text = str(value).strip()[:240]
            rows.append((dimension, text, str(label or text).strip()[:300]))
    if "fortigate" in str(decoder.get('name') or '').lower():
        profile = "/".join(str(value).strip().lower()[:80] for value in (
            first('data.type') or 'unknown', first('data.subtype') or 'unknown',
            first('data.action', 'data.event.action', 'data.status') or 'unknown',
        ))
        rows.append(('forti_profile', profile, profile))
    mitre = rule.get('mitre') if isinstance(rule.get('mitre'), dict) else {}
    technique_ids = mitre.get('id') or []
    if isinstance(technique_ids, str):
        technique_ids = [technique_ids]
    for technique in technique_ids[:12] if isinstance(technique_ids, list) else []:
        if str(technique).strip():
            rows.append(('mitre', str(technique).strip()[:64], str(technique).strip()[:64]))
    # These are compact labels, not copies of the raw log. They allow the UI to
    # show what telemetry can support without replaying an alert archive.
    classification = classify_detection(event)
    rows.append(('detection_family', classification['family'], classification['family']))
    rows.append(('detection_confidence', classification['confidence'], classification['confidence']))
    # A taxonomy mapping fills legitimate rule-tag gaps but never replaces an
    # explicit Wazuh ATT&CK mapping.
    explicit_mitre = {str(item).strip() for item in technique_ids if str(item).strip()} if isinstance(technique_ids, list) else set()
    for technique in classification['mitre']:
        if technique not in explicit_mitre:
            rows.append(('mitre', technique, technique))
    source = telemetry_source(event)
    rows.append(('telemetry_source', source, source))
    field_source, available_fields = telemetry_fields(event)
    for field in available_fields:
        rows.append(('telemetry_field', field_source + '|' + field, field))
    return rows


def rollup_bucket(value, minutes=5):
    parsed = value.astimezone(timezone.utc)
    return stamp(parsed.replace(minute=(parsed.minute // minutes) * minutes, second=0, microsecond=0))


BACKFILL_FIELDS = {
    'rule': ('rule.id', 100), 'decoder': ('decoder.name', 50),
    'source_ip': ('data.srcip', 100), 'destination_ip': ('data.dstip', 100),
    'identity': ('data.office365.UserId', 100), 'asset': ('agent.name', 50),
    'destination_port': ('data.dstport', 50), 'application': ('data.app', 50),
    'firewall_policy': ('data.policyid', 50), 'direction': ('data.direction', 20),
    'network_action': ('data.action', 20), 'forti_type': ('data.type', 20),
    'forti_subtype': ('data.subtype', 20),
    'mitre': ('rule.mitre.id', 50), 'severity': ('rule.level', 20),
}

# These filters run only in the dedicated Forti historical worker. They
# deliberately cover high-signal FortiGate security events, not ordinary
# accepted/closed traffic or policy/application-control volume.
FORTI_SECURITY_FILTERS = {
    'ips_blocked': {
        'bool': {'filter': [
            {'term': {'decoder.name': 'fortigate-firewall-v5'}},
            {'term': {'data.subtype': 'ips'}},
            {'terms': {'data.action': ['block', 'blocked', 'deny', 'denied', 'drop', 'dropped']}},
        ]},
    },
    'ips_detected': {
        'bool': {'filter': [
            {'term': {'decoder.name': 'fortigate-firewall-v5'}},
            {'term': {'data.subtype': 'ips'}},
            {'terms': {'data.action': ['detect', 'detected', 'alert', 'monitor']}},
        ]},
    },
    'malware': {
        'bool': {'filter': [{'term': {'decoder.name': 'fortigate-firewall-v5'}}], 'should': [
            {'terms': {'data.subtype': ['virus', 'antivirus']}},
            {'match_phrase': {'rule.description': 'virus detected'}},
        ], 'minimum_should_match': 1},
    },
}

FORTI_SECURITY_LABELS = {
    'ips_blocked': 'FortiGate IPS blocked',
    'ips_detected': 'FortiGate IPS detected',
    'malware': 'FortiGate malware signal',
}

# Keep this projection in sync with rollup_dimensions; never fetch full raw logs.
ROLLUP_SOURCE_FIELDS = [
    '@timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.mitre.id',
    'agent.id', 'agent.name', 'agent.ip', 'host.id', 'host.name', 'decoder.name',
    'data.srcip', 'data.src_ip', 'data.source.ip', 'data.office365.ClientIP',
    'data.dstip', 'data.dst_ip', 'data.destination.ip',
    'data.dstport', 'data.dst_port', 'data.destination.port',
    'data.office365.UserId', 'data.dstuser', 'data.srcuser',
    'data.win.eventdata.targetUserName', 'data.user', 'data.action', 'data.event.action', 'data.status',
    'data.url', 'data.http.url', 'data.full_url', 'data.request',
    'data.app', 'data.application', 'data.appcat', 'data.service',
    'data.policyid', 'data.policy_id', 'data.policyname', 'data.rule_name',
    'data.direction', 'data.flow_direction', 'data.proto', 'data.protocol', 'data.network.protocol',
    'data.type', 'data.subtype', 'data.attack', 'data.attackid', 'data.msg', 'data.logdesc',
    'data.hostname', 'data.host', 'data.process.name', 'data.process', 'data.parent_process',
    'data.hash', 'data.file_hash', 'data.win.eventdata.image', 'data.win.eventdata.parentImage',
    'data.win.eventdata.hashes', 'data.office365.Workload', 'data.office365.Operation',
    'data.office365.ObjectId', 'data.office365.SessionId', 'data.session', 'data.logon_id',
    'data.audit.exe', 'data.exe', 'data.audit.command', 'data.command', 'data.cmd',
    'data.audit.uid', 'data.uid',
    'data.docker.container.id', 'data.docker.container.name', 'data.docker.image',
    'data.container.id', 'data.container.name', 'data.container.image', 'data.container_name', 'data.image',
]


def history(search, payload):
    start, end = bounds(payload)
    offset = int(payload.get('offset', 0))
    if offset < 0 or offset > 9950:
        raise ValueError('Narrow the date/filter selection to browse beyond 10,000 events')
    filters = [{'range': {'@timestamp': {'gte': start, 'lt': end}}}]
    for key, field in [('rule', 'rule.id'), ('agent', 'agent.id'), ('source', 'decoder.name')]:
        if payload.get(key):
            value = str(payload[key])
            if len(value) > 150:
                raise ValueError('Filter too long')
            filters.append({'term': {field: value}})
    level = int(payload.get('min_level', 0))
    if not 0 <= level <= 15:
        raise ValueError('Level must be 0..15')
    filters.append({'range': {'rule.level': {'gte': level}}})
    query = str(payload.get('query', '')).strip()
    if len(query) > 200:
        raise ValueError('Search too long')
    if query:
        filters.append({'simple_query_string': {'query': query, 'default_operator': 'and',
            'fields': ['rule.description', 'rule.id', 'agent.name', 'agent.ip', 'data.srcip',
                       'data.dstip', 'data.office365.ClientIP', 'data.office365.Operation', 'syscheck.path']}})
    request = {'timeout': '15s', 'from': offset, 'size': 50, 'track_total_hits': True,
        'sort': [{'@timestamp': 'desc'}], 'query': {'bool': {'filter': filters}},
        '_source': ['@timestamp', 'rule', 'agent', 'data', 'decoder', 'syscheck', 'location', 'GeoLocation']}
    if offset == 0:
        hours = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()/3600
        request['aggs'] = {'timeline': {'date_histogram': {'field': '@timestamp',
            'fixed_interval': '1h' if hours <= 48 else '1d', 'min_doc_count': 0,
            'extended_bounds': {'min': start, 'max': stamp(datetime.fromisoformat(end)-timedelta(milliseconds=1))}}}}
    data = search(request)
    hits = data.get('hits', {})
    total = hits.get('total', {})
    return {'ok': not data.get('timed_out') and not data.get('_shards', {}).get('failed'),
        'start': start, 'end': end, 'offset': offset,
        'total': total.get('value', 0) if isinstance(total, dict) else total,
        'events': [{'id': h['_id'], 'index': h.get('_index'), **h['_source'],
                    'analysis': explain_rule(h['_source'].get('rule', {}))} for h in hits.get('hits', [])],
        'timeline': data.get('aggregations', {}).get('timeline', {}).get('buckets', [])}


class Pipeline:
    def __init__(self, automation, request):
        self.automation, self.request = automation, request
        self.stop = threading.Event()
        self.error = None
        self.active = False
        # The monotonic pass is the primary reader. Delay the overlapping replay
        # after startup so it cannot compete with index recovery or dashboard load.
        self.last_live = time.time()
        self.last_rollup_cleanup = 0.0
        self.last_backfill = 0.0
        self.last_forti_security_backfill = 0.0
        self.last_taxonomy_materialization = 0.0
        self.entity_queue_error = None
        with automation.db() as db:
            entity_resolver.ensure_schema(db)
            db.execute('CREATE TABLE IF NOT EXISTS stream_state (id INTEGER PRIMARY KEY, start TEXT, checkpoint TEXT, scanned INTEGER DEFAULT 0)')
            if 'live_checkpoint' not in {r[1] for r in db.execute('PRAGMA table_info(stream_state)')}:
                db.execute('ALTER TABLE stream_state ADD COLUMN live_checkpoint TEXT')
            columns = {r[1] for r in db.execute('PRAGMA table_info(stream_state)')}
            if 'checkpoint_scanned' not in columns:
                db.execute('ALTER TABLE stream_state ADD COLUMN checkpoint_scanned INTEGER DEFAULT 0')
            if 'replay_scanned' not in columns:
                db.execute('ALTER TABLE stream_state ADD COLUMN replay_scanned INTEGER DEFAULT 0')
            columns = {r[1] for r in db.execute('PRAGMA table_info(stream_state)')}
            for name, definition in (
                ('last_scan_at', 'REAL'),
                ('last_scan_duration_ms', 'INTEGER DEFAULT 0'),
                ('last_scan_query_took_ms', 'INTEGER DEFAULT 0'),
                ('last_scan_events', 'INTEGER DEFAULT 0'),
                ('last_scan_committed_events', 'INTEGER DEFAULT 0'),
                ('last_scan_stream', 'TEXT'),
            ):
                if name not in columns:
                    db.execute(f'ALTER TABLE stream_state ADD COLUMN {name} {definition}')
            db.execute('CREATE TABLE IF NOT EXISTS ioc_queue (kind TEXT, indicator TEXT, first_seen TEXT, last_seen TEXT, level INTEGER, next_attempt REAL DEFAULT 0, attempts INTEGER DEFAULT 0, PRIMARY KEY(kind,indicator))')
            if 'count' not in {r[1] for r in db.execute('PRAGMA table_info(ioc_queue)')}:
                db.execute('ALTER TABLE ioc_queue ADD COLUMN count INTEGER DEFAULT 0')
            db.execute('CREATE INDEX IF NOT EXISTS ioc_queue_due ON ioc_queue(next_attempt,level)')
            db.execute('CREATE INDEX IF NOT EXISTS ioc_queue_priority ON ioc_queue(next_attempt,level,count,last_seen)')
            db.execute('''CREATE TABLE IF NOT EXISTS detection_rollups (
                bucket TEXT NOT NULL, dimension TEXT NOT NULL, value TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0, max_level INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT, label TEXT, PRIMARY KEY(bucket,dimension,value))''')
            db.execute('CREATE INDEX IF NOT EXISTS detection_rollups_dimension_time ON detection_rollups(dimension,bucket)')
            db.execute('CREATE INDEX IF NOT EXISTS detection_rollups_time ON detection_rollups(bucket)')
            db.execute('''CREATE TABLE IF NOT EXISTS taxonomy_rollup_buckets (
                bucket TEXT PRIMARY KEY, materialized_at REAL NOT NULL, source TEXT NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS taxonomy_rollup_buckets_time ON taxonomy_rollup_buckets(materialized_at)')
            db.execute('''CREATE TABLE IF NOT EXISTS scan_batches (
                batch_key TEXT PRIMARY KEY, stream TEXT NOT NULL, window_start TEXT NOT NULL,
                window_end TEXT NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
                ioc_count INTEGER NOT NULL DEFAULT 0, committed_at REAL NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS scan_batches_window ON scan_batches(stream,window_start,window_end)')
            db.execute('''CREATE TABLE IF NOT EXISTS rollup_windows (
                bucket_epoch INTEGER PRIMARY KEY, bucket TEXT NOT NULL UNIQUE, source TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0, completed_at REAL NOT NULL,
                batch_key TEXT NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS rollup_windows_time ON rollup_windows(bucket_epoch)')
            db.execute('''CREATE TABLE IF NOT EXISTS rollup_backfill_state (
                id INTEGER PRIMARY KEY, cursor TEXT, target TEXT, completed INTEGER DEFAULT 0,
                chunks INTEGER DEFAULT 0, events INTEGER DEFAULT 0, last_run REAL,
                last_duration_ms INTEGER DEFAULT 0, last_query_took_ms INTEGER DEFAULT 0, error TEXT,
                current_chunk_minutes INTEGER DEFAULT 0, success_streak INTEGER DEFAULT 0,
                failures INTEGER DEFAULT 0, next_run REAL DEFAULT 0, mode TEXT DEFAULT 'linear')''')
            backfill_columns = {row[1] for row in db.execute('PRAGMA table_info(rollup_backfill_state)')}
            for name, definition in {
                'current_chunk_minutes': 'INTEGER DEFAULT 0',
                'success_streak': 'INTEGER DEFAULT 0',
                'failures': 'INTEGER DEFAULT 0',
                'next_run': 'REAL DEFAULT 0',
                'mode': "TEXT DEFAULT 'linear'",
            }.items():
                if name not in backfill_columns:
                    db.execute(f'ALTER TABLE rollup_backfill_state ADD COLUMN {name} {definition}')
            # Forti security metrics have their own cursor. This keeps a new
            # historical dimension from replaying the broad alert rollup.
            db.execute('''CREATE TABLE IF NOT EXISTS forti_security_backfill_state (
                id INTEGER PRIMARY KEY, cursor TEXT, target TEXT, completed INTEGER DEFAULT 0,
                chunks INTEGER DEFAULT 0, events INTEGER DEFAULT 0, last_run REAL,
                last_duration_ms INTEGER DEFAULT 0, last_query_took_ms INTEGER DEFAULT 0,
                error TEXT, next_run REAL DEFAULT 0)''')

        # Existing installations already have useful rollups. This idempotent
        # ledger seed is deliberately isolated from schema setup so a dashboard
        # probe can retry it while the materializer holds a rollup write lock.
        self._seed_rollup_windows_with_retry()

    def _seed_rollup_windows_with_retry(self):
        statement = '''INSERT OR IGNORE INTO rollup_windows
            (bucket_epoch,bucket,source,event_count,completed_at,batch_key)
            SELECT CAST(strftime('%s',bucket) AS INTEGER),bucket,'legacy',count,?,
                   'legacy:' || bucket
            FROM detection_rollups
            WHERE dimension='total' AND strftime('%s',bucket) IS NOT NULL'''
        for attempt in range(5):
            try:
                with self.automation.db() as db:
                    if db.execute('SELECT 1 FROM rollup_windows LIMIT 1').fetchone():
                        return
                    if not db.execute("SELECT 1 FROM detection_rollups WHERE dimension='total' LIMIT 1").fetchone():
                        return
                    db.execute(statement, (time.time(),))
                return
            except sqlite3.OperationalError as exc:
                if 'locked' not in str(exc).lower() or attempt == 4:
                    raise
                time.sleep(0.25 * (2 ** attempt))

    def status(self, lightweight=False):
        if lightweight:
            try:
                with self.automation.read_db() as db:
                    row = db.execute('''SELECT start,checkpoint,scanned,live_checkpoint,
                        checkpoint_scanned,replay_scanned,last_scan_at,last_scan_duration_ms,
                        last_scan_query_took_ms,last_scan_events,last_scan_committed_events,
                        last_scan_stream FROM stream_state WHERE id=1''').fetchone()
                    total, pending = db.execute(
                        'SELECT COUNT(*),COALESCE(SUM(next_attempt<=?),0) FROM ioc_queue',
                        (time.time(),)).fetchone()
                    rollup = db.execute("""SELECT MIN(bucket),MAX(bucket),COUNT(*),
                        COALESCE(SUM(count),0) FROM detection_rollups
                        WHERE dimension='total'""").fetchone()
                    backfill = db.execute('''SELECT cursor,target,completed,chunks,events,
                        error,next_run FROM rollup_backfill_state WHERE id=1''').fetchone()
                checkpoint = row[1] if row else None
                lag_seconds = None
                if checkpoint:
                    try:
                        lag_seconds = max(0, int(time.time() -
                            datetime.fromisoformat(checkpoint).timestamp()))
                    except (TypeError, ValueError):
                        pass
                caught_up = lag_seconds is not None and lag_seconds <= 15 * 60
                last_scan = self._scan_status(row)
                return {
                    'enabled': self.automation.config().get('SOC_STREAM_ENABLED') == 'true',
                    'active': self.active, 'error': self.error,
                    'started_at': row[0] if row else None, 'checkpoint': checkpoint,
                    'checkpoint_events_scanned': row[4] if row else 0,
                    'live_replay_events_scanned': row[5] if row else 0,
                    'live_through': row[3] if row else None,
                    'lag_seconds': lag_seconds, 'caught_up': caught_up,
                    'scan_status': 'caught_up' if caught_up else ('scanning' if self.active else 'behind'),
                    'unique_scan_counter': 'checkpoint_events_scanned',
                    'replay_counter_note': 'Replay overlaps the checkpoint stream and must not be added to unique event totals.',
                    'last_scan': last_scan,
                    'historical_scope_complete': bool(backfill[2]) if backfill else False,
                    'raw_archives_scanned': False,
                    'rollup': {
                        'enabled': self.automation.config().get('SOC_ROLLUP_ENABLED', 'true') == 'true',
                        'first_bucket': rollup[0] if rollup else None,
                        'last_bucket': rollup[1] if rollup else None,
                        'buckets': int(rollup[2] or 0) if rollup else 0,
                        'events': int(rollup[3] or 0) if rollup else 0,
                        'backfill': {
                            'cursor': backfill[0] if backfill else None,
                            'target': backfill[1] if backfill else None,
                            'complete': bool(backfill[2]) if backfill else False,
                            'chunks': int(backfill[3] or 0) if backfill else 0,
                            'events': int(backfill[4] or 0) if backfill else 0,
                            'error': backfill[5] if backfill else None,
                            'next_run': backfill[6] if backfill else None,
                        },
                    },
                    'entity_graph': {'status': 'not_checked',
                                     'detail': 'Detailed entity graph status omitted from bounded health read.'},
                    'queued_indicators': int(total or 0), 'due_indicators': int(pending or 0),
                    'scope': 'wazuh-alerts-* only; bounded health snapshot',
                    'status': 'degraded' if self.error else 'ok',
                    'error_scope': 'last_scan_cycle' if self.error else None,
                    'status_scope': 'bounded_runtime_snapshot',
                    'detail_available': False,
                }
            except (sqlite3.Error, OSError) as exc:
                return {
                    'enabled': self.automation.config().get('SOC_STREAM_ENABLED') == 'true',
                    'active': self.active, 'error': self.error,
                    'scan_status': 'unavailable', 'status': 'degraded',
                    'status_scope': 'bounded_runtime_snapshot', 'detail_available': False,
                    'reason': 'local pipeline status read unavailable',
                    'error_detail': str(exc)[:240],
                }
        with self.automation.db() as db:
            row = db.execute('''SELECT start,checkpoint,scanned,live_checkpoint,checkpoint_scanned,
                replay_scanned,last_scan_at,last_scan_duration_ms,last_scan_query_took_ms,
                last_scan_events,last_scan_committed_events,last_scan_stream
                FROM stream_state WHERE id=1''').fetchone()
            total, pending = db.execute('SELECT COUNT(*),COALESCE(SUM(next_attempt<=?),0) FROM ioc_queue', (time.time(),)).fetchone()
            rollup = db.execute("SELECT MIN(bucket),MAX(bucket),COUNT(*),COALESCE(SUM(count),0) FROM detection_rollups WHERE dimension='total'").fetchone()
            backfill = db.execute('''SELECT cursor,target,completed,chunks,events,last_run,
                last_duration_ms,last_query_took_ms,error,current_chunk_minutes,success_streak,
                failures,next_run,mode FROM rollup_backfill_state WHERE id=1''').fetchone()
            forti_backfill = db.execute('''SELECT cursor,target,completed,chunks,events,last_run,
                last_duration_ms,last_query_took_ms,error,next_run
                FROM forti_security_backfill_state WHERE id=1''').fetchone()
            committed_batches = int(db.execute('SELECT COUNT(*) FROM scan_batches').fetchone()[0] or 0)
            taxonomy_done = int(db.execute('SELECT COUNT(*) FROM taxonomy_rollup_buckets').fetchone()[0] or 0)
            taxonomy_total = int(db.execute("SELECT COUNT(DISTINCT bucket) FROM detection_rollups WHERE dimension='total'").fetchone()[0] or 0)
            entity_graph = entity_resolver.status(db)
        checkpoint = row[1] if row else None
        lag_seconds = None
        if checkpoint:
            try:
                lag_seconds = max(0, int(time.time()-datetime.fromisoformat(checkpoint).timestamp()))
            except (TypeError, ValueError):
                pass
        caught_up = lag_seconds is not None and lag_seconds <= 15 * 60
        last_scan = self._scan_status(row)
        gaps = self.rollup_gaps()
        effective_chunk = int(backfill[9] or 0) if backfill else 0
        interval = int(self.automation.config().get('SOC_ROLLUP_BACKFILL_MIN_INTERVAL_SECONDS', 30))
        estimated_cycles = ((int(gaps.get('missing') or 0) + max(1, effective_chunk // 5) - 1)
                            // max(1, effective_chunk // 5)) if effective_chunk else None
        backfill_status = {
            'enabled': self.automation.config().get('SOC_ROLLUP_BACKFILL_ENABLED', 'true') == 'true',
            'cursor': backfill[0] if backfill else None, 'target': backfill[1] if backfill else None,
            'complete': bool(backfill[2]) if backfill else False,
            'chunks': int(backfill[3] or 0) if backfill else 0,
            'events': int(backfill[4] or 0) if backfill else 0,
            'last_run': backfill[5] if backfill else None,
            'last_duration_ms': int(backfill[6] or 0) if backfill else 0,
            'last_query_took_ms': int(backfill[7] or 0) if backfill else 0,
            'error': backfill[8] if backfill else None,
            'current_chunk_minutes': effective_chunk,
            'success_streak': int(backfill[10] or 0) if backfill else 0,
            'failures': int(backfill[11] or 0) if backfill else 0,
            'next_run': backfill[12] if backfill else None,
            'mode': backfill[13] if backfill else 'linear',
            'estimated_cycles': estimated_cycles,
            'estimated_completion_seconds': estimated_cycles * interval if estimated_cycles is not None else None,
        }
        forti_backfill_status = {
            'enabled': self.automation.config().get('SOC_FORTI_SECURITY_BACKFILL_ENABLED', 'true') == 'true',
            'cursor': forti_backfill[0] if forti_backfill else None,
            'target': forti_backfill[1] if forti_backfill else None,
            'complete': bool(forti_backfill[2]) if forti_backfill else False,
            'chunks': int(forti_backfill[3] or 0) if forti_backfill else 0,
            'events': int(forti_backfill[4] or 0) if forti_backfill else 0,
            'last_run': forti_backfill[5] if forti_backfill else None,
            'last_duration_ms': int(forti_backfill[6] or 0) if forti_backfill else 0,
            'last_query_took_ms': int(forti_backfill[7] or 0) if forti_backfill else 0,
            'error': forti_backfill[8] if forti_backfill else None,
            'next_run': forti_backfill[9] if forti_backfill else None,
            'scope': 'fortigate-firewall-v5 only; IPS blocked/detected and malware signals',
        }
        return {'enabled': self.automation.config().get('SOC_STREAM_ENABLED') == 'true',
                'active': self.active, 'error': self.error, 'started_at': row[0] if row else None,
                'checkpoint': checkpoint, 'legacy_scanned_including_replay': row[2] if row else 0,
                'checkpoint_events_scanned': row[4] if row else 0, 'live_replay_events_scanned': row[5] if row else 0,
                'live_through': row[3] if row else None,
                'lag_seconds': lag_seconds, 'caught_up': caught_up,
                'scan_status': 'caught_up' if caught_up else ('scanning' if self.active else 'behind'),
                'unique_scan_counter': 'checkpoint_events_scanned',
                'replay_counter_note': 'Replay overlaps the checkpoint stream and must not be added to unique event totals.',
                'last_scan': last_scan,
                'status': 'degraded' if self.error else 'ok',
                'error_scope': 'last_scan_cycle' if self.error else None,
                'historical_scope_complete': backfill_status['complete'],
                'historical_scope_note': ('Configured historical rollup backfill is complete.' if backfill_status['complete']
                                          else 'Live discovery is current; throttled historical rollup backfill progresses only while caught up.'),
                'raw_archives_scanned': False,
                'rollup': {'enabled': self.automation.config().get('SOC_ROLLUP_ENABLED', 'true') == 'true',
                           'first_bucket': rollup[0], 'last_bucket': rollup[1],
                           'buckets': int(rollup[2] or 0), 'events': int(rollup[3] or 0),
                           'bucket_minutes': 5,
                           'retention_days': int(self.automation.config().get('SOC_ROLLUP_RETENTION_DAYS', 180)),
                           'committed_batches': committed_batches,
                           'taxonomy_materialization': {'completed_buckets': taxonomy_done,
                                                       'total_buckets': taxonomy_total,
                                                       'pending_buckets': max(0, taxonomy_total - taxonomy_done)},
                           'gaps': gaps, 'backfill': backfill_status,
                           'forti_security_backfill': forti_backfill_status},
                'entity_graph': {**entity_graph, 'drain_error': self.entity_queue_error},
                'queued_indicators': total, 'due_indicators': pending,
                'scope': 'wazuh-alerts-* only; initial 24h, 5-minute checkpoints, 2-minute ingest delay; periodic late-event replay; older logs require backfill'}

    def rollup_gaps(self, start=None, end=None, sample_limit=12):
        """Report missing completed 5-minute windows without querying the Indexer."""
        with self.automation.db() as db:
            state = db.execute('SELECT start,checkpoint FROM stream_state WHERE id=1').fetchone()
            backfill = db.execute('SELECT target FROM rollup_backfill_state WHERE id=1').fetchone()
        if not end:
            end = state[1] if state and state[1] else None
        if not start:
            start = backfill[0] if backfill and backfill[0] else (state[0] if state else None)
        if not start or not end:
            return {'status': 'not_started', 'expected': 0, 'completed': 0, 'missing': 0,
                    'coverage_percent': 0.0, 'ranges': []}
        start_dt = datetime.fromisoformat(str(start).replace('Z', '+00:00')).astimezone(timezone.utc)
        end_dt = datetime.fromisoformat(str(end).replace('Z', '+00:00')).astimezone(timezone.utc)
        start_dt = start_dt.replace(minute=(start_dt.minute // 5) * 5, second=0, microsecond=0)
        end_dt = end_dt.replace(minute=(end_dt.minute // 5) * 5, second=0, microsecond=0)
        start_epoch, end_epoch = int(start_dt.timestamp()), int(end_dt.timestamp())
        expected = max(0, (end_epoch - start_epoch) // 300)
        if not expected:
            return {'status': 'empty_range', 'expected': 0, 'completed': 0, 'missing': 0,
                    'coverage_percent': 100.0, 'ranges': []}
        with self.automation.db() as db:
            completed = int(db.execute('''SELECT COUNT(*) FROM rollup_windows
                WHERE bucket_epoch>=? AND bucket_epoch<?''', (start_epoch, end_epoch)).fetchone()[0] or 0)
            rows = db.execute('''WITH points(epoch) AS (
                    SELECT ? UNION ALL
                    SELECT bucket_epoch FROM rollup_windows WHERE bucket_epoch>=? AND bucket_epoch<?
                    UNION ALL SELECT ?
                ), ordered AS (
                    SELECT epoch,LEAD(epoch) OVER (ORDER BY epoch) AS next_epoch FROM points
                )
                SELECT epoch+300,next_epoch-300,(next_epoch-epoch)/300-1
                FROM ordered WHERE next_epoch-epoch>300 LIMIT ?''',
                (start_epoch - 300, start_epoch, end_epoch, end_epoch, max(1, int(sample_limit)))).fetchall()
        missing = max(0, expected - completed)
        ranges = [{'start': stamp(datetime.fromtimestamp(first, timezone.utc)),
                   'end': stamp(datetime.fromtimestamp(last + 300, timezone.utc)),
                   'buckets': int(count)} for first, last, count in rows]
        return {'status': 'complete' if missing == 0 else 'gaps_detected', 'expected': expected,
                'completed': completed, 'missing': missing,
                'coverage_percent': round(completed / expected * 100, 2), 'ranges': ranges}

    def backfill_once(self):
        config = self.automation.config()
        if config.get('SOC_ROLLUP_ENABLED', 'true') != 'true' or config.get('SOC_ROLLUP_BACKFILL_ENABLED', 'true') != 'true':
            return False
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        lookback_days = max(7, min(180, int(config.get('SOC_ROLLUP_BACKFILL_DAYS', 30))))
        base_chunk = max(5, min(120, int(config.get('SOC_ROLLUP_BACKFILL_CHUNK_MINUTES', 30))))
        max_chunk = max(base_chunk, min(360, int(config.get('SOC_ROLLUP_BACKFILL_MAX_CHUNK_MINUTES', 120))))
        normal_interval = max(30, int(config.get('SOC_ROLLUP_BACKFILL_INTERVAL_SECONDS', 120)))
        min_interval = max(15, min(normal_interval, int(config.get('SOC_ROLLUP_BACKFILL_MIN_INTERVAL_SECONDS', 30))))
        fast_query_ms = max(100, int(config.get('SOC_ROLLUP_BACKFILL_FAST_QUERY_MS', 1500)))
        desired_target = now - timedelta(days=lookback_days)
        desired_target = desired_target.replace(minute=0)
        with self.automation.db() as db:
            state = db.execute('''SELECT cursor,target,completed,current_chunk_minutes,
                success_streak,failures,next_run FROM rollup_backfill_state WHERE id=1''').fetchone()
            if not state:
                earliest = db.execute("SELECT MIN(bucket) FROM detection_rollups WHERE dimension='total'").fetchone()[0]
                cursor = datetime.fromisoformat(earliest) if earliest else now - timedelta(hours=24)
                target = desired_target
                db.execute('INSERT INTO rollup_backfill_state(id,cursor,target,completed) VALUES (1,?,?,0)',
                           (stamp(cursor), stamp(target)))
                chunk_minutes, success_streak, failures, next_run = base_chunk, 0, 0, 0
            else:
                cursor = datetime.fromisoformat(state[0]) if state[0] else now - timedelta(hours=24)
                target = desired_target
                chunk_minutes = max(base_chunk, min(max_chunk, int(state[3] or base_chunk)))
                success_streak, failures, next_run = int(state[4] or 0), int(state[5] or 0), float(state[6] or 0)
                # The target is a rolling lookback boundary. Keeping the oldest
                # target forever makes a configured 30-day scope grow without bound.
                db.execute('UPDATE rollup_backfill_state SET target=?,completed=0 WHERE id=1', (stamp(target),))
            checkpoint_row = db.execute('SELECT checkpoint FROM stream_state WHERE id=1').fetchone()
            checkpoint = checkpoint_row[0] if checkpoint_row and checkpoint_row[0] else stamp(now - timedelta(minutes=10))
        if next_run > time.time():
            return False
        if cursor > target:
            mode = 'linear'
            end = cursor
            start = max(target, end - timedelta(minutes=chunk_minutes))
        else:
            gaps = self.rollup_gaps(stamp(target), checkpoint, sample_limit=1)
            if not gaps.get('ranges'):
                with self.automation.db() as db:
                    db.execute("UPDATE rollup_backfill_state SET completed=1,error=NULL,mode='complete' WHERE id=1")
                return False
            mode = 'repair'
            gap = gaps['ranges'][0]
            start = datetime.fromisoformat(gap['start'])
            gap_end = datetime.fromisoformat(gap['end'])
            end = min(gap_end, start + timedelta(minutes=chunk_minutes))
        aggs = {
            dimension: {'terms': {'field': field, 'size': size}}
            for dimension, (field, size) in BACKFILL_FIELDS.items()
        }
        aggs['max_level'] = {'max': {'field': 'rule.level'}}
        request = {
            'size': 0, 'track_total_hits': False, 'timeout': '12s',
            'query': {'range': {'@timestamp': {'gte': stamp(start), 'lt': stamp(end)}}},
            'aggs': {'rollup': {'date_histogram': {'field': '@timestamp', 'fixed_interval': '5m', 'min_doc_count': 1},
                                'aggs': aggs}},
        }
        started = time.monotonic()
        try:
            data = self.request('/wazuh-alerts-*/_search', request)
            if not isinstance(data, dict) or data.get('timed_out') or data.get('_shards', {}).get('failed'):
                raise RuntimeError('Partial historical aggregation; backfill cursor not advanced')
            buckets = ((data.get('aggregations') or {}).get('rollup') or {}).get('buckets')
            if not isinstance(buckets, list):
                raise RuntimeError('Historical aggregation missing rollup buckets')
            rows = []
            events = 0
            for bucket in buckets:
                bucket_key = bucket.get('key_as_string')
                if not bucket_key:
                    continue
                count = int(bucket.get('doc_count') or 0)
                events += count
                max_level = int(((bucket.get('max_level') or {}).get('value')) or 0)
                rows.append((bucket_key, 'total', 'all', count, max_level, bucket_key, 'All indexed alerts'))
                for dimension in BACKFILL_FIELDS:
                    aggregate = bucket.get(dimension) or {}
                    for item in aggregate.get('buckets') or []:
                        value = str(item.get('key_as_string', item.get('key', ''))).strip()[:240]
                        if value:
                            rows.append((bucket_key, dimension, value, int(item.get('doc_count') or 0),
                                         max_level, bucket_key, value[:300]))
                    other = int(aggregate.get('sum_other_doc_count') or 0)
                    if other:
                        rows.append((bucket_key, dimension, '__other__', other, max_level, bucket_key,
                                     'Other values outside bounded historical top terms'))
            duration_ms = int((time.monotonic() - started) * 1000)
            with self.automation.db() as db:
                if rows:
                    db.executemany('''INSERT OR REPLACE INTO detection_rollups
                        (bucket,dimension,value,count,max_level,last_seen,label) VALUES (?,?,?,?,?,?,?)''', rows)
                bucket_counts = {}
                for row in rows:
                    if row[1] != 'total':
                        continue
                    try:
                        key = rollup_bucket(datetime.fromisoformat(str(row[0]).replace('Z', '+00:00')))
                    except ValueError:
                        key = str(row[0])
                    bucket_counts[key] = int(row[3] or 0)
                window_rows = []
                point = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
                batch_key = 'backfill:' + stamp(start) + ':' + stamp(end)
                while point < end:
                    bucket = stamp(point)
                    window_rows.append((int(point.timestamp()), bucket, 'backfill',
                                        bucket_counts.get(bucket, 0), time.time(), batch_key))
                    point += timedelta(minutes=5)
                db.executemany('''INSERT INTO rollup_windows
                    (bucket_epoch,bucket,source,event_count,completed_at,batch_key)
                    VALUES (?,?,?,?,?,?) ON CONFLICT(bucket_epoch) DO UPDATE SET
                    source=excluded.source,event_count=MAX(rollup_windows.event_count,excluded.event_count),
                    completed_at=excluded.completed_at,batch_key=excluded.batch_key''', window_rows)
                query_took = int(data.get('took') or duration_ms)
                fast = query_took <= fast_query_ms and duration_ms <= fast_query_ms * 2
                next_streak = success_streak + 1 if fast else 0
                next_chunk = chunk_minutes
                if fast and next_streak >= 2:
                    next_chunk, next_streak = min(max_chunk, chunk_minutes + base_chunk), 0
                elif not fast:
                    next_chunk = max(base_chunk, chunk_minutes // 2)
                cooldown = min_interval if fast else normal_interval
                next_cursor = stamp(start) if mode == 'linear' else stamp(cursor)
                db.execute('''UPDATE rollup_backfill_state SET cursor=?,completed=0,chunks=chunks+1,
                    events=events+?,last_run=?,last_duration_ms=?,last_query_took_ms=?,error=NULL,
                    current_chunk_minutes=?,success_streak=?,failures=0,next_run=?,mode=? WHERE id=1''',
                    (next_cursor, events, time.time(), duration_ms, query_took, next_chunk,
                     next_streak, time.time() + cooldown, mode))
            return True
        except Exception as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            next_failures = failures + 1
            retry_delay = min(3600, normal_interval * (2 ** min(next_failures, 4)))
            with self.automation.db() as db:
                db.execute('''UPDATE rollup_backfill_state SET last_run=?,last_duration_ms=?,error=?,
                    current_chunk_minutes=?,success_streak=0,failures=?,next_run=?,mode='cooldown' WHERE id=1''',
                    (time.time(), duration_ms, str(exc)[:500], max(base_chunk, chunk_minutes // 2),
                     next_failures, time.time() + retry_delay))
            raise

    def forti_security_backfill_once(self):
        """Materialize bounded Forti IPS/malware counters for older rollups.

        This deliberately does not use the generic rollup query, raw archives,
        scrolls, or stored event documents. The worker owns only the
        ``forti_security`` dimension and is scheduled after the main rollup is
        caught up, so its replacement rows cannot race live ingestion.
        """
        config = self.automation.config()
        if (config.get('SOC_ROLLUP_ENABLED', 'true') != 'true'
                or config.get('SOC_FORTI_SECURITY_BACKFILL_ENABLED', 'true') != 'true'):
            return False
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        lookback_days = max(7, min(180, int(config.get('SOC_ROLLUP_BACKFILL_DAYS', 30))))
        # The dedicated query touches one decoder and returns only three
        # counters. It can safely use a larger fixed chunk than the generic
        # rollup when the stream is caught up; a slow query gets a cooldown.
        chunk_minutes = max(5, min(120, int(config.get('SOC_FORTI_SECURITY_BACKFILL_CHUNK_MINUTES', 120))))
        interval = max(60, int(config.get('SOC_FORTI_SECURITY_BACKFILL_INTERVAL_SECONDS', 60)))
        target = (now - timedelta(days=lookback_days)).replace(minute=0)
        cursor = now - timedelta(minutes=2)
        with self.automation.db() as db:
            state = db.execute('''SELECT cursor,target,completed,chunks,events,next_run
                FROM forti_security_backfill_state WHERE id=1''').fetchone()
            if not state:
                db.execute('''INSERT INTO forti_security_backfill_state
                    (id,cursor,target,completed,next_run) VALUES (1,?,?,0,0)''',
                           (stamp(cursor), stamp(target)))
                chunks, events, next_run = 0, 0, 0.0
            else:
                cursor = datetime.fromisoformat(str(state[0]).replace('Z', '+00:00')) if state[0] else cursor
                chunks, events, next_run = int(state[3] or 0), int(state[4] or 0), float(state[5] or 0)
                # The configured window moves daily. Preserve the old cursor
                # so only the newly requested older period is added.
                db.execute('UPDATE forti_security_backfill_state SET target=?,completed=0 WHERE id=1',
                           (stamp(target),))
        if next_run > time.time():
            return False
        if cursor <= target:
            with self.automation.db() as db:
                db.execute('''UPDATE forti_security_backfill_state
                    SET completed=1,error=NULL,next_run=0 WHERE id=1''')
            return False

        end = cursor
        start = max(target, end - timedelta(minutes=chunk_minutes))
        request = {
            'size': 0,
            'track_total_hits': False,
            'timeout': '12s',
            'query': {'bool': {'filter': [
                {'range': {'@timestamp': {'gte': stamp(start), 'lt': stamp(end)}}},
                {'term': {'decoder.name': 'fortigate-firewall-v5'}},
            ]}},
            'aggs': {'rollup': {'date_histogram': {
                'field': '@timestamp', 'fixed_interval': '5m', 'min_doc_count': 0,
                'extended_bounds': {'min': stamp(start), 'max': stamp(end - timedelta(milliseconds=1))},
            }, 'aggs': {'forti_security': {
                'filters': {'filters': FORTI_SECURITY_FILTERS},
                'aggs': {'max_level': {'max': {'field': 'rule.level'}}},
            }}}},
        }
        started = time.monotonic()
        try:
            data = self.request('/wazuh-alerts-*/_search', request)
            if not isinstance(data, dict) or data.get('timed_out') or data.get('_shards', {}).get('failed'):
                raise RuntimeError('Partial Forti security aggregation; cursor not advanced')
            buckets = ((data.get('aggregations') or {}).get('rollup') or {}).get('buckets')
            if not isinstance(buckets, list):
                raise RuntimeError('Forti security aggregation missing rollup buckets')
            rows, observed_events = [], 0
            for bucket in buckets:
                bucket_key = bucket.get('key_as_string')
                if not bucket_key:
                    continue
                observed_events += int(bucket.get('doc_count') or 0)
                for signal, aggregate in ((bucket.get('forti_security') or {}).get('buckets') or {}).items():
                    count = int((aggregate or {}).get('doc_count') or 0)
                    if not count:
                        continue
                    level = int(((aggregate or {}).get('max_level') or {}).get('value') or 0)
                    rows.append((bucket_key, 'forti_security', signal, count, level, bucket_key,
                                 FORTI_SECURITY_LABELS.get(signal, signal)))
            duration_ms = int((time.monotonic() - started) * 1000)
            with self.automation.db() as db:
                # The dimension is exclusively owned by this worker. Replacing
                # the chunk makes retries and upgrades idempotent.
                db.execute('''DELETE FROM detection_rollups
                    WHERE dimension='forti_security' AND bucket>=? AND bucket<?''',
                           (stamp(start), stamp(end)))
                if rows:
                    db.executemany('''INSERT INTO detection_rollups
                        (bucket,dimension,value,count,max_level,last_seen,label) VALUES (?,?,?,?,?,?,?)''', rows)
                query_took = int(data.get('took') or duration_ms)
                cooldown = interval if query_took <= 1500 and duration_ms <= 3000 else max(300, interval * 5)
                db.execute('''UPDATE forti_security_backfill_state SET cursor=?,completed=0,
                    chunks=?,events=?,last_run=?,last_duration_ms=?,last_query_took_ms=?,
                    error=NULL,next_run=? WHERE id=1''',
                           (stamp(start), chunks + 1, events + observed_events, time.time(), duration_ms,
                            query_took, time.time() + cooldown))
            return True
        except Exception as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            with self.automation.db() as db:
                db.execute('''UPDATE forti_security_backfill_state SET last_run=?,last_duration_ms=?,
                    error=?,next_run=? WHERE id=1''',
                           (time.time(), duration_ms, str(exc)[:500], time.time() + min(3600, interval * 2)))
            raise

    def rollup_summary(self, start, end, limit=20):
        start, end = bounds({'start': start, 'end': end})
        query_start = rollup_bucket(datetime.fromisoformat(start))
        dimensions = ('rule', 'decoder', 'source_ip', 'destination_ip', 'identity', 'asset',
                      'destination_port', 'application', 'firewall_policy', 'direction', 'mitre', 'severity',
                      'network_action', 'forti_type', 'forti_subtype', 'forti_profile', 'forti_security',
                      'detection_family', 'detection_confidence', 'telemetry_source', 'telemetry_field')
        result = {}
        with self.automation.db() as db:
            for dimension in dimensions:
                # Readiness needs every source/field contract bucket, not only
                # the 20 highest-volume values used for ordinary dashboard lists.
                dimension_limit = 250 if dimension == 'telemetry_field' else 50 if dimension == 'telemetry_source' else int(limit)
                rows = db.execute('''SELECT value,SUM(count),MAX(max_level),MAX(last_seen),MAX(label)
                    FROM detection_rollups WHERE dimension=? AND bucket>=? AND bucket<?
                    GROUP BY value ORDER BY SUM(count) DESC,value LIMIT ?''',
                    (dimension, query_start, end, dimension_limit)).fetchall()
                result[dimension] = [{'value': value, 'count': int(count or 0),
                                      'max_level': int(level or 0), 'last_seen': seen, 'label': label}
                                     for value, count, level, seen, label in rows]
            timeline = db.execute('''SELECT bucket,SUM(count) FROM detection_rollups
                WHERE dimension='total' AND bucket>=? AND bucket<? GROUP BY bucket ORDER BY bucket''',
                (query_start, end)).fetchall()
            coverage = db.execute("SELECT MIN(bucket),MAX(bucket),COUNT(*) FROM detection_rollups WHERE bucket>=? AND bucket<?",
                                  (query_start, end)).fetchone()
            taxonomy_coverage = db.execute('''SELECT COUNT(DISTINCT total.bucket),
                COUNT(DISTINCT CASE WHEN EXISTS (
                    SELECT 1 FROM detection_rollups family
                    WHERE family.bucket=total.bucket AND family.dimension='detection_family'
                ) OR EXISTS (
                    SELECT 1 FROM taxonomy_rollup_buckets marker WHERE marker.bucket=total.bucket
                ) THEN total.bucket END)
                FROM detection_rollups total
                WHERE total.dimension='total' AND total.bucket>=? AND total.bucket<?''',
                (query_start, end)).fetchone()
            backfill_cursor = db.execute('SELECT cursor FROM rollup_backfill_state WHERE id=1').fetchone()
            stream_checkpoint = db.execute('SELECT checkpoint FROM stream_state WHERE id=1').fetchone()
        span_hours = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() / 3600
        merge_minutes = 60 if span_hours <= 48 else 360 if span_hours <= 24 * 14 else 1440
        merged = {}
        for bucket, count in timeline:
            point = datetime.fromisoformat(bucket)
            minute_of_day = point.hour * 60 + point.minute
            rounded = point.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
                minutes=(minute_of_day // merge_minutes) * merge_minutes)
            key = stamp(rounded)
            merged[key] = merged.get(key, 0) + int(count or 0)
        start_covered = bool((backfill_cursor and backfill_cursor[0] and backfill_cursor[0] <= query_start)
                             or (coverage[0] and coverage[0] <= query_start))
        end_floor = rollup_bucket(datetime.fromisoformat(end)-timedelta(minutes=10))
        end_covered = bool((stream_checkpoint and stream_checkpoint[0] and stream_checkpoint[0] >= end_floor)
                           or (coverage[1] and coverage[1] >= end_floor))
        gap_end = end_floor
        if stream_checkpoint and stream_checkpoint[0] and stream_checkpoint[0] < gap_end:
            gap_end = stream_checkpoint[0]
        gaps = self.rollup_gaps(query_start, gap_end)
        return {'ok': True, 'start': start, 'end': end, 'bucket_minutes': 5,
                'timeline_interval_minutes': merge_minutes,
                'timeline': [{'key': key, 'doc_count': value} for key, value in sorted(merged.items())],
                'dimensions': result,
                'coverage': {'first_bucket': coverage[0], 'last_bucket': coverage[1], 'rows': int(coverage[2] or 0),
                             'complete': start_covered and end_covered and gaps['missing'] == 0,
                             'gaps': gaps,
                             'taxonomy': {'buckets_total': int(taxonomy_coverage[0] or 0),
                                          'buckets_ready': int(taxonomy_coverage[1] or 0),
                                          'complete': bool(taxonomy_coverage[0]) and
                                          int(taxonomy_coverage[0] or 0) == int(taxonomy_coverage[1] or 0)}}}

    def materialize_taxonomy_once(self, limit=120):
        """Backfill compact attack labels from existing local rule rollups.

        Historical five-minute rollups intentionally omit raw event fields. This
        local-only pass can safely recover family and ATT&CK labels from the
        stored rule descriptions, but retains ``rule_matched`` confidence rather
        than pretending required network or identity fields were present.
        """
        limit = max(1, min(int(limit), 500))
        with self.automation.db() as db:
            buckets = db.execute('''SELECT DISTINCT r.bucket
                FROM detection_rollups r LEFT JOIN taxonomy_rollup_buckets t ON t.bucket=r.bucket
                WHERE r.dimension='total' AND t.bucket IS NULL ORDER BY r.bucket LIMIT ?''', (limit,)).fetchall()
            if not buckets:
                return 0
            completed, additions = [], []
            for (bucket,) in buckets:
                # Live stream rows already contain taxonomy dimensions. Mark the
                # bucket complete rather than adding duplicate aggregate counts.
                present = db.execute('''SELECT 1 FROM detection_rollups
                    WHERE bucket=? AND dimension='detection_family' LIMIT 1''', (bucket,)).fetchone()
                if not present:
                    rule_rows = db.execute('''SELECT value,count,max_level,last_seen,label FROM detection_rollups
                        WHERE bucket=? AND dimension='rule' ''', (bucket,)).fetchall()
                    for value, count, level, last_seen, label in rule_rows:
                        rule_id = str(value).split(' | ', 1)[0]
                        result = classify_detection({'rule': {'id': rule_id, 'description': label or value}})
                        dimensions = [('detection_family', result['family']),
                                      ('detection_confidence', result['confidence'])]
                        dimensions.extend(('mitre', technique) for technique in result['mitre'])
                        for dimension, item in dimensions:
                            additions.append((bucket, dimension, item, int(count or 0), int(level or 0), last_seen, item))
                completed.append((bucket, time.time(), 'local_rule_rollup'))
            if additions:
                db.executemany('''INSERT INTO detection_rollups(bucket,dimension,value,count,max_level,last_seen,label)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(bucket,dimension,value) DO UPDATE SET
                    count=detection_rollups.count+excluded.count,
                    max_level=MAX(detection_rollups.max_level,excluded.max_level),
                    last_seen=MAX(detection_rollups.last_seen,excluded.last_seen)''', additions)
            db.executemany('''INSERT OR REPLACE INTO taxonomy_rollup_buckets(bucket,materialized_at,source)
                VALUES (?,?,?)''', completed)
        return len(completed)

    def candidates(self, limit=100):
        with self.automation.db() as db:
            rows = db.execute("SELECT kind,indicator,level,last_seen,count FROM ioc_queue WHERE next_attempt<=? ORDER BY level DESC,count DESC,last_seen DESC,next_attempt,first_seen LIMIT ?", (time.time(),limit)).fetchall()
        return [{'kind': k, 'indicator': i, 'level': l, 'last_seen': seen, 'occurrences': count or 0, 'scope': 'persistent queue'} for k,i,l,seen,count in rows]

    def attempted(self, candidate, retry=False):
        with self.automation.db() as db:
            db.execute('UPDATE ioc_queue SET next_attempt=?,attempts=attempts+1 WHERE kind=? AND indicator=?',
                (time.time()+(3600 if retry else 21600), candidate['kind'], candidate['indicator']))

    @staticmethod
    def _scan_status(row):
        """Expose measured window metrics without implying raw-log coverage."""
        if not row or row[6] is None:
            return {'status': 'not_observed', 'stream': None, 'at': None,
                    'duration_ms': None, 'query_took_ms': None, 'events': None,
                    'committed_events': None}
        return {'status': 'measured', 'stream': row[11], 'at': row[6],
                'duration_ms': int(row[7] or 0), 'query_took_ms': int(row[8] or 0),
                'events': int(row[9] or 0), 'committed_events': int(row[10] or 0)}

    def _commit_scan_window(self, recent, checkpoint, end, batch, rollups, scanned, rollup_enabled,
                            entity_records=None, entity_candidates=0, entity_queued=0,
                            scan_metrics=None):
        """Atomically persist one completed discovery window exactly once."""
        stream = 'replay' if recent else 'checkpoint'
        window_start, window_end = stamp(checkpoint), stamp(end)
        batch_key = f'{stream}:{window_start}:{window_end}'
        with self.automation.db() as db:
            inserted = db.execute('''INSERT OR IGNORE INTO scan_batches
                (batch_key,stream,window_start,window_end,event_count,ioc_count,committed_at)
                VALUES (?,?,?,?,?,?,?)''',
                (batch_key, stream, window_start, window_end, int(scanned), len(batch), time.time())).rowcount
            if not inserted:
                return False
            if entity_records:
                entity_resolver.ingest_prepared(db, entity_records)
                entity_resolver.remove_queued(db, (record['evidence_id'] for record in entity_records))
            represented = len(entity_records or []) + int(entity_queued)
            coalesced = max(0, int(entity_candidates) - represented)
            db.execute('''INSERT OR REPLACE INTO entity_graph_batches
                (batch_key,candidate_count,stored_count,queued_count,coalesced_count,dropped_count,committed_at)
                VALUES (?,?,?,?,?,?,?)''', (batch_key, int(entity_candidates), len(entity_records or []),
                    int(entity_queued), coalesced, 0, time.time()))
            if recent:
                db.executemany('''INSERT INTO ioc_queue
                    (kind,indicator,first_seen,last_seen,level,count) VALUES (?,?,?,?,?,0)
                    ON CONFLICT(kind,indicator) DO UPDATE SET
                    first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),
                    level=MAX(level,excluded.level)''',
                    [(kind, indicator, values[0], values[1], values[2])
                     for (kind, indicator), values in batch.items()])
            else:
                db.executemany('''INSERT INTO ioc_queue
                    (kind,indicator,first_seen,last_seen,level,count) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(kind,indicator) DO UPDATE SET
                    first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),
                    level=MAX(level,excluded.level),count=count+excluded.count''',
                    [(kind, indicator, *values) for (kind, indicator), values in batch.items()])
            if rollups:
                db.executemany('''INSERT INTO detection_rollups(bucket,dimension,value,count,max_level,last_seen,label)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(bucket,dimension,value) DO UPDATE SET
                    count=detection_rollups.count+excluded.count,
                    max_level=MAX(detection_rollups.max_level,excluded.max_level),
                    last_seen=MAX(detection_rollups.last_seen,excluded.last_seen),
                    label=CASE WHEN excluded.last_seen>=detection_rollups.last_seen THEN excluded.label ELSE detection_rollups.label END''',
                    [(bucket, dimension, value, values[0], values[1], values[2], values[3])
                     for (bucket, dimension, value), values in rollups.items()])
            if rollup_enabled:
                per_bucket = {bucket: values[0] for (bucket, dimension, _), values in rollups.items()
                              if dimension == 'total'}
                point = checkpoint.replace(minute=(checkpoint.minute // 5) * 5, second=0, microsecond=0)
                window_rows = []
                while point < end:
                    bucket = stamp(point)
                    window_rows.append((int(point.timestamp()), bucket, 'stream', per_bucket.get(bucket, 0),
                                        time.time(), batch_key))
                    point += timedelta(minutes=5)
                db.executemany('''INSERT INTO rollup_windows
                    (bucket_epoch,bucket,source,event_count,completed_at,batch_key) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(bucket_epoch) DO UPDATE SET
                    source=excluded.source,event_count=MAX(rollup_windows.event_count,excluded.event_count),
                    completed_at=excluded.completed_at,batch_key=excluded.batch_key''', window_rows)
            if time.time() - self.last_rollup_cleanup >= 3600:
                retention = max(7, int(self.automation.config().get('SOC_ROLLUP_RETENTION_DAYS', 180)))
                cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention)
                db.execute('DELETE FROM detection_rollups WHERE bucket<?', (stamp(cutoff_dt),))
                db.execute('DELETE FROM rollup_windows WHERE bucket_epoch<?', (int(cutoff_dt.timestamp()),))
                db.execute('DELETE FROM scan_batches WHERE committed_at<?', (cutoff_dt.timestamp(),))
                entity_resolver.cleanup(db, int(self.automation.config().get('SOC_ENTITY_RETENTION_DAYS', 30)))
                self.last_rollup_cleanup = time.time()
            field = 'live_checkpoint' if recent else 'checkpoint'
            counter = 'replay_scanned' if recent else 'checkpoint_scanned'
            if recent:
                updated = db.execute(f'UPDATE stream_state SET {field}=?,{counter}={counter}+? WHERE id=1',
                                     (window_end, int(scanned))).rowcount
            else:
                updated = db.execute(f'''UPDATE stream_state SET {field}=?,{counter}={counter}+?
                    WHERE id=1 AND {field}=?''', (window_end, int(scanned), window_start)).rowcount
            if not updated:
                raise RuntimeError('Stale discovery window; transaction rolled back')
            metrics = scan_metrics or {}
            db.execute('''UPDATE stream_state SET last_scan_at=?,last_scan_duration_ms=?,
                last_scan_query_took_ms=?,last_scan_events=?,last_scan_committed_events=?,
                last_scan_stream=? WHERE id=1''',
                (float(metrics.get('at') or time.time()), int(metrics.get('duration_ms') or 0),
                 int(metrics.get('query_took_ms') or 0), int(metrics.get('events') or 0),
                 int(metrics.get('committed_events') or 0), stream))
        return True

    def drain_entity_queue_once(self, config=None):
        """Drain durable local evidence without depending on the Wazuh stream switch."""
        config = config or self.automation.config()
        batch_size = max(10, min(1000, int(config.get('SOC_ENTITY_DRAIN_BATCH_SIZE', 100))))
        with self.automation.db() as db:
            return entity_resolver.drain_queue(db, batch_size)

    def scan_window(self, recent=False):
        now = datetime.now(timezone.utc)
        config = self.automation.config()
        window_seconds = max(60, min(900, int(config.get('SOC_STREAM_WINDOW_SECONDS', 300))))
        page_size = max(100, min(1000, int(config.get('SOC_STREAM_PAGE_SIZE', 500))))
        with self.automation.db() as db:
            row = db.execute('SELECT start,checkpoint FROM stream_state WHERE id=1').fetchone()
            if not row:
                start = stamp(now-timedelta(hours=24))
                db.execute('INSERT INTO stream_state(id,start,checkpoint,scanned) VALUES (1,?,?,0)', (start,start))
                row = (start,start)
        checkpoint = datetime.fromisoformat(row[1])
        end = min(checkpoint + timedelta(seconds=window_seconds), now-timedelta(minutes=2))
        if end <= checkpoint or (not recent and (end-checkpoint).total_seconds()<60):
            return False
        start = max(datetime.fromisoformat(row[0]), checkpoint-timedelta(seconds=window_seconds))
        if recent:
            end = now-timedelta(minutes=2)
            start = end-timedelta(minutes=10)
        scroll_id, scanned, committed_scanned = None, 0, 0
        rollups, batch, entity_records, entity_overflow, entity_candidates, entity_queued = {}, {}, {}, {}, 0, 0
        entity_limit = max(50, min(10000, int(config.get('SOC_ENTITY_MAX_EVIDENCE_PER_WINDOW', 500))))
        entity_queue_batch = min(500, entity_limit)
        entity_batch_key = f"{'replay' if recent else 'checkpoint'}:{stamp(checkpoint)}:{stamp(end)}"

        def flush_entity_overflow():
            nonlocal entity_queued
            if not entity_overflow:
                return
            with self.automation.db() as db:
                entity_queued += entity_resolver.enqueue_prepared(
                    db, entity_batch_key, entity_overflow.values())
            entity_overflow.clear()

        rollup_enabled = not recent and self.automation.config().get('SOC_ROLLUP_ENABLED', 'true') == 'true'
        scan_started = time.monotonic()
        query_took_ms = 0
        try:
            data = self.request('/wazuh-alerts-*/_search?scroll=2m', {'size': page_size, 'sort': ['_doc'],
                'timeout': '15s', 'query': {'range': {'@timestamp': {'gte': stamp(start), 'lt': stamp(end)}}},
                '_source': sorted(set(ROLLUP_SOURCE_FIELDS + list(IOC_FIELDS.values())))})
            try:
                query_took_ms = max(0, int(data.get('took') or 0))
            except (AttributeError, TypeError, ValueError):
                query_took_ms = 0
            while True:
                scroll_id = data.get('_scroll_id', scroll_id)
                if data.get('timed_out') or data.get('_shards', {}).get('failed'):
                    raise RuntimeError('Partial index response; checkpoint not advanced')
                if not isinstance(data.get('hits', {}).get('hits'), list):
                    raise RuntimeError('Invalid index response; checkpoint not advanced')
                hits = data.get('hits', {}).get('hits', [])
                if not hits:
                    break
                if not scroll_id:
                    raise RuntimeError('Missing scroll cursor; checkpoint not advanced')
                for hit in hits:
                    event = hit.get('_source', {})
                    seen = event.get('@timestamp') or stamp(start)
                    try:
                        seen_time = datetime.fromisoformat(str(seen).replace('Z', '+00:00'))
                    except (TypeError, ValueError):
                        seen_time = checkpoint
                    if recent or seen_time >= checkpoint:
                        committed_scanned += 1
                    if rollup_enabled and seen_time >= checkpoint:
                        bucket = rollup_bucket(seen_time)
                        level = int(event.get('rule', {}).get('level', 0) or 0)
                        for dimension, value, label in rollup_dimensions(event):
                            key = (bucket, dimension, value)
                            current = rollups.get(key)
                            if current:
                                current[0] += 1
                                current[1] = max(current[1], level)
                                if str(seen) >= current[2]:
                                    current[2], current[3] = str(seen), label
                            else:
                                rollups[key] = [1, level, str(seen), label]
                    for item in observables(event):
                        key = (item['kind'],item['indicator'])
                        level = int(event.get('rule', {}).get('level', 0))
                        old = batch.get(key, (seen,seen,level,0))
                        increment = 0 if recent or seen_time < checkpoint else 1
                        batch[key] = (min(old[0],seen),max(old[1],seen),max(old[2],level),old[3]+increment)
                    prepared = entity_resolver.prepare_wazuh_evidence(
                        event, str(hit.get('_id') or ''), str(hit.get('_index') or ''))
                    if prepared:
                        entity_candidates += 1
                        current = entity_records.get(prepared['evidence_id'])
                        if current:
                            current['occurrence_count'] += 1
                            current['last_seen'] = max(current['last_seen'], prepared['observed_at'])
                        elif len(entity_records) < entity_limit:
                            entity_records[prepared['evidence_id']] = prepared
                        else:
                            current = entity_overflow.get(prepared['evidence_id'])
                            if current:
                                current['occurrence_count'] += 1
                                current['last_seen'] = max(current['last_seen'], prepared['observed_at'])
                            else:
                                entity_overflow[prepared['evidence_id']] = prepared
                            if len(entity_overflow) >= entity_queue_batch:
                                flush_entity_overflow()
                scanned += len(hits)
                data = self.request('/_search/scroll', {'scroll': '2m', 'scroll_id': scroll_id})
            flush_entity_overflow()
            self._commit_scan_window(recent, checkpoint, end, batch, rollups,
                                     committed_scanned, rollup_enabled, list(entity_records.values()),
                                     entity_candidates, entity_queued, {
                                         'at': time.time(),
                                         'duration_ms': int((time.monotonic() - scan_started) * 1000),
                                         'query_took_ms': query_took_ms,
                                         'events': scanned,
                                         'committed_events': committed_scanned,
                                     })
            return True
        finally:
            if scroll_id:
                try:
                    self.request('/_search/scroll', {'scroll_id': [scroll_id]}, 'DELETE')
                except Exception:
                    pass

    def loop(self):
        while not self.stop.wait(2):
            try:
                config = self.automation.config()
                # Local queue work remains available when Wazuh polling is paused.
                try:
                    self.drain_entity_queue_once(config)
                    self.entity_queue_error = None
                except Exception as exc:
                    self.entity_queue_error = self.automation.clean_error(exc)
                if config.get('SOC_STREAM_ENABLED') != 'true':
                    continue
                self.active = True
                replay_interval = int(config.get('SOC_STREAM_REPLAY_INTERVAL_SECONDS', 1800))
                scan_pause = int(config.get('SOC_STREAM_SCAN_PAUSE_SECONDS', 10))
                if time.time()-self.last_live >= replay_interval:
                    self.scan_window(recent=True)
                    self.last_live=time.time()
                advanced = self.scan_window()
                backfill_interval = int(config.get('SOC_ROLLUP_BACKFILL_INTERVAL_SECONDS', 120))
                backfill_poll_interval = max(15, min(backfill_interval, int(
                    config.get('SOC_ROLLUP_BACKFILL_MIN_INTERVAL_SECONDS', 30))))
                if (not advanced and self.status().get('caught_up')
                        and time.time() - self.last_backfill >= backfill_poll_interval):
                    try:
                        self.backfill_once()
                    except Exception:
                        # Backfill health is persisted separately and must never
                        # make the live discovery stream appear failed.
                        pass
                    self.last_backfill = time.time()
                rollup_state = self.status().get('rollup', {}) if not advanced else {}
                forti_interval = max(60, int(config.get('SOC_FORTI_SECURITY_BACKFILL_INTERVAL_SECONDS', 60)))
                if (not advanced and self.status().get('caught_up')
                        and rollup_state.get('backfill', {}).get('complete')
                        and time.time() - self.last_forti_security_backfill >= forti_interval):
                    try:
                        self.forti_security_backfill_once()
                    except Exception:
                        # This optional historical enrichment owns no live
                        # checkpoint and must never impair alert discovery.
                        pass
                    self.last_forti_security_backfill = time.time()
                if (not advanced and self.status().get('caught_up')
                        and time.time() - self.last_taxonomy_materialization >= 30):
                    # SQLite-only historical enrichment has no Indexer cost.
                    self.materialize_taxonomy_once()
                    self.last_taxonomy_materialization = time.time()
                self.error = None
                self.stop.wait(scan_pause if advanced else max(15, scan_pause))
            except Exception as exc:
                self.error = self.automation.clean_error(exc)
                self.stop.wait(30)
            finally:
                self.active = False

    def start(self):
        threading.Thread(target=self.loop, daemon=True).start()
