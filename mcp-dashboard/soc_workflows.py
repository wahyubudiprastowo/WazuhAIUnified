"""Menu bindings and a bounded, opt-in execution queue for discovered MCP tools.

Catalog discovery and history reads never execute a tool. Unknown tools require
review; host actions and writes cannot enter the background read queue.
"""
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

MENU_TOOLS = {
    'l1': '''get_wazuh_alerts get_wazuh_alert_summary analyze_alert_patterns
        get_alerts_aggregated search_security_events get_top_security_threats
        blueteam_wazuh_alerts blueteam_wazuh_get_security_events
        blueteam_wazuh_alert_summarize wazuh_alert_aggregate_analysis
        blueteam_false_positive_tracker blueteam_false_positive_kb''',
    'l2': '''analyze_security_threat check_ioc_reputation search_external_context
        perform_risk_assessment advanced_three_sum_correlation advanced_attack_graph
        advanced_threat_intelligence blueteam_beacon_detect blueteam_attack_chain
        blueteam_threat_card blueteam_wazuh_alert_compare three_sum_correlation
        blueteam_investigate_ip blueteam_extract_iocs blueteam_mitre_lookup
        blueteam_stix_killchain blueteam_attack_graph blueteam_pivot_suggest
        blueteam_semantic_search''',
    'l3': '''crowdsec_ip_reputation crowdsec_ip_reputation_bulk greynoise_ip_context
        threatfox_ioc_search threatfox_ioc_search_bulk blueteam_ip_blacklist
        blueteam_ioc_search blueteam_breach_check blueteam_lookup_ip_abuseipdb
        blueteam_lookup_hash_virustotal blueteam_lookup_domain_virustotal
        argus_ip_lookup netra_ip_analysis sangfor_blocklist_check sangfor_blocklist_list
        blueteam_unified_threat_score blueteam_curated_threat_report
        blueteam_baseline_profile blueteam_calendar_heatmap blueteam_baseline_drift
        blueteam_wazuh_geo_distribution blueteam_ai_bot_recon wazuh_email_lookup
        wazuh_domain_lookup blueteam_whois_lookup blueteam_crtsh_lookup
        wazuh_compromised_emails_analysis wazuh_attack_velocity
        wazuh_alert_focused_crawl blueteam_threat_hunt blueteam_ioc_lifecycle
        blueteam_wazuh_geo_heatmap otx_lookup otx_lookup_bulk cyfirma_ioc_feed
        cyfirma_ioc_lookup blueteam_threat_intel_aggregate urlhaus_lookup
        urlhaus_hash_lookup urlhaus_lookup_bulk stealer_log_check
        blueteam_stix_analyze blueteam_campaign_watch blueteam_domain_permute''',
    'vuln': '''get_wazuh_vulnerabilities get_wazuh_critical_vulnerabilities
        get_wazuh_vulnerability_summary blueteam_wazuh_vulnerabilities
        blueteam_cve_lookup blueteam_cve_epss blueteam_cve_kev blueteam_cve_poc
        blueteam_cve_score blueteam_cve_ssvc blueteam_dependency_scan
        blueteam_cve_advisory blueteam_cve_attack_mapping''',
    'assets': '''get_wazuh_agents get_wazuh_running_agents check_agent_health
        get_agent_processes get_agent_ports get_agent_configuration
        blueteam_list_listening_ports blueteam_list_connections blueteam_hash_file
        blueteam_find_suid_files blueteam_find_world_writable blueteam_rootkit_scan
        blueteam_lynis_audit blueteam_check_updates blueteam_check_open_firewall
        blueteam_who_is_logged_in blueteam_last_logins blueteam_failed_logins
        blueteam_sudo_history blueteam_list_users blueteam_check_ssh_authorized_keys
        blueteam_list_processes blueteam_list_cron_jobs blueteam_wazuh_agents
        blueteam_wazuh_agents_summary blueteam_wazuh_get_groups
        blueteam_asset_context blueteam_owned_domains blueteam_set_owned_domains''',
    'incidents': '''wazuh_block_ip wazuh_isolate_host wazuh_kill_process
        wazuh_disable_user wazuh_quarantine_file wazuh_active_response
        wazuh_firewall_drop wazuh_host_deny wazuh_restart wazuh_check_blocked_ip
        wazuh_check_agent_isolation wazuh_check_process wazuh_check_user_status
        wazuh_check_file_quarantine wazuh_unisolate_host wazuh_enable_user
        wazuh_restore_file wazuh_firewall_allow wazuh_host_allow
        blueteam_fail2ban_status blueteam_fail2ban_jail_status blueteam_fail2ban_unban
        blueteam_mark_investigated blueteam_investigation_summary
        blueteam_investigation_history blueteam_case_create blueteam_case_add_iocs
        blueteam_case_add_verdict blueteam_case_get blueteam_case_list''',
    'workbench': '''generate_security_report run_compliance_check get_iso27001_dashboard
        get_iso27001_control_detail get_sca_policy_checks get_iso27001_gap_analysis
        get_iso27001_alerts blueteam_wazuh_compliance blueteam_export_report
        blueteam_investigation_workflow blueteam_prompt_route blueteam_playbook_run
        blueteam_wazuh_get_agent_sca blueteam_wazuh_get_sca_policy_checks
        blueteam_wazuh_list_sca_policies blueteam_document_convert
        blueteam_capture_traffic blueteam_check_webshell jarm_fingerprint''',
    'history': '''blueteam_read_auth_log blueteam_read_syslog blueteam_read_web_log
        blueteam_journalctl blueteam_wazuh_indexer_search wazuh_alert_dsl_query
        wazuh_alert_timeline blueteam_wazuh_export blueteam_wazuh_syscheck''',
    'settings': '''get_wazuh_statistics get_wazuh_weekly_stats get_wazuh_cluster_health
        get_wazuh_cluster_nodes get_wazuh_rules_summary get_wazuh_remoted_stats
        get_wazuh_log_collector_stats search_wazuh_manager_logs
        get_wazuh_manager_error_logs validate_wazuh_connection blueteam_system_health
        blueteam_wazuh_get_rules blueteam_wazuh_get_decoders
        blueteam_wazuh_get_cluster_nodes blueteam_wazuh_manager_logs
        blueteam_index_schema blueteam_metrics blueteam_wazuh_get_rule_files
        blueteam_wazuh_get_rule_file_content''',
}
BINDINGS = {name: menu for menu, names in MENU_TOOLS.items() for name in names.split()}

# Curated secondary surface for contextual Security Findings pivots. These remain
# analyst-triggered cached reads; membership never makes a tool run on page load.
FINDING_TOOLS = frozenset('''analyze_alert_patterns blueteam_attack_chain
    blueteam_pivot_suggest blueteam_false_positive_kb blueteam_wazuh_get_decoders
    get_wazuh_rules_summary blueteam_baseline_drift wazuh_email_lookup
    wazuh_compromised_emails_analysis blueteam_investigate_ip
    blueteam_unified_threat_score blueteam_campaign_watch
    blueteam_threat_intel_aggregate blueteam_ioc_lifecycle wazuh_attack_velocity
    blueteam_cve_epss blueteam_cve_kev blueteam_cve_poc blueteam_cve_ssvc
    blueteam_cve_attack_mapping blueteam_cve_advisory'''.split())

# Explicitly reviewed exclusions, not a destructive-name heuristic.
APPROVAL_TOOLS = {
    'wazuh_block_ip', 'wazuh_isolate_host', 'wazuh_kill_process',
    'wazuh_disable_user', 'wazuh_quarantine_file', 'wazuh_active_response',
    'wazuh_firewall_drop', 'wazuh_host_deny', 'wazuh_restart',
    'wazuh_unisolate_host', 'wazuh_enable_user', 'wazuh_restore_file',
    'wazuh_firewall_allow', 'wazuh_host_allow', 'blueteam_fail2ban_unban',
    'blueteam_mark_investigated', 'blueteam_false_positive_tracker',
    'blueteam_case_create', 'blueteam_case_add_iocs', 'blueteam_case_add_verdict',
    'blueteam_set_owned_domains', 'blueteam_playbook_run',
    'blueteam_investigation_workflow', 'blueteam_export_report',
    'blueteam_capture_traffic', 'blueteam_check_webshell', 'jarm_fingerprint',
    'blueteam_find_suid_files', 'blueteam_find_world_writable',
    'blueteam_rootkit_scan', 'blueteam_lynis_audit', 'blueteam_document_convert',
    'blueteam_domain_permute', 'blueteam_hash_file',
    'blueteam_check_ssh_authorized_keys', 'blueteam_wazuh_indexer_search',
    'wazuh_alert_dsl_query', 'blueteam_wazuh_export', 'wazuh_alert_focused_crawl',
    'blueteam_prompt_route',
}
PROVIDERS = ('crowdsec', 'greynoise', 'threatfox', 'otx', 'virustotal', 'urlhaus',
             'abuseipdb', 'cyfirma', 'cve_', 'breach', 'stealer', 'whois', 'crtsh',
             'reputation', 'threat_intel', 'unified_threat', 'argus', 'netra', 'sangfor')


def policy(tool):
    name = str(tool.get('name', ''))
    menu = BINDINGS.get(name)
    approved = name in APPROVAL_TOOLS or menu is None
    external = any(part in name for part in PROVIDERS)
    surfaces = [menu] if menu else ['tools']
    if name in FINDING_TOOLS:
        surfaces.append('findings')
    return {
        'menu': menu or 'tools', 'mapped': menu is not None,
        'surfaces': surfaces,
        'mode': 'approval' if approved else 'cached_read',
        'trigger': 'analyst_request', 'automatic': False,
        'cache_seconds': 21600 if external else 900,
        'dependency': 'provider_or_feed' if external else 'local_or_wazuh',
        'reason': ('Explicit operator confirmation required; excluded from background reads.'
                   if approved else 'Cached, deduplicated read; queued only on analyst request.'),
    }


class WorkflowBusy(RuntimeError):
    pass


class Workflows:
    MAX_PENDING = 24
    MAX_ROWS = 5000
    MAX_RESULT_BYTES = 512_000
    RETENTION_SECONDS = 30 * 86400
    EXTERNAL_RUNS_PER_HOUR = 4
    LOCAL_RUNS_PER_HOUR = 12

    def __init__(self, path, lookup, call, clean=lambda value: value):
        self.path = Path(path)
        self.lookup, self.call, self.clean = lookup, call, clean
        self._init_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._ready = False
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()

    @contextmanager
    def db(self):
        with self._init_lock:
            if not self._ready:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(self.path, timeout=5) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('''CREATE TABLE IF NOT EXISTS workflow_jobs (
                        id TEXT PRIMARY KEY, cache_key TEXT NOT NULL, source TEXT NOT NULL,
                        name TEXT NOT NULL, menu TEXT NOT NULL, arguments TEXT NOT NULL,
                        status TEXT NOT NULL, created REAL NOT NULL, finished REAL,
                        expires REAL, result TEXT, error TEXT)''')
                    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS workflow_active ON workflow_jobs(cache_key) WHERE status IN ('queued','running')")
                    db.execute('CREATE INDEX IF NOT EXISTS workflow_history ON workflow_jobs(menu,created DESC)')
                    db.execute('CREATE INDEX IF NOT EXISTS workflow_cache ON workflow_jobs(cache_key,finished DESC)')
                self._ready = True
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def submit(self, source, name, arguments):
        tool = self.lookup(source, name)
        if not tool:
            raise ValueError('Unknown tool')
        rule = policy(tool)
        if rule['mode'] != 'cached_read':
            raise ValueError('This tool requires a confirmed run in Tool Console')
        if not isinstance(arguments, dict):
            raise TypeError('Arguments must be an object')
        arguments = dict(arguments)
        if 'params' in arguments:
            if set(arguments) != {'params'} or not isinstance(arguments['params'], dict):
                raise ValueError('Invalid params wrapper')
            arguments = dict(arguments['params'])
        for key in tool.get('required_fields', []):
            if arguments.get(key) in (None, '', []):
                raise ValueError('Missing required field: ' + key)
        # Honor smaller caller limits, and bound known output controls.
        for field in tool.get('schema_fields', []):
            key = field['name']
            if key in {'limit', 'max_results', 'max_events', 'size', 'max_alerts'}:
                value = arguments.get(key, field.get('default') or 50)
                arguments[key] = max(1, min(100, int(value)))
        if arguments.get('bypass_redaction'):
            raise ValueError('Unredacted output is not allowed in workflow history')
        for key in ('ips', 'indicators', 'search_terms', 'urls', 'cve_ids'):
            if isinstance(arguments.get(key), list) and len(arguments[key]) > 10:
                raise ValueError('At most 10 indicators per workflow run')
        encoded = json.dumps(arguments, sort_keys=True, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode()) > 16_384:
            raise ValueError('Arguments exceed 16 KiB')
        key = hashlib.sha256(f'{source}:{name}:{encoded}'.encode()).hexdigest()
        now = time.time()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT * FROM workflow_jobs WHERE cache_key=? AND
                (status IN ('queued','running') OR expires>?) ORDER BY created DESC LIMIT 1''', (key, now)).fetchone()
            if row:
                return self._public(row, cached=row['status'] == 'completed')
            recent = db.execute('SELECT name FROM workflow_jobs WHERE created>?', (now - 3600,)).fetchall()
            dependency = rule['dependency']
            count = sum(policy({'name': item['name']})['dependency'] == dependency for item in recent)
            limit = self.EXTERNAL_RUNS_PER_HOUR if dependency == 'provider_or_feed' else self.LOCAL_RUNS_PER_HOUR
            if count >= limit:
                label = 'provider' if dependency == 'provider_or_feed' else 'Wazuh/local'
                raise WorkflowBusy(f'Workflow {label} budget exhausted ({limit} runs/hour); use saved history')
            if db.execute("SELECT COUNT(*) FROM workflow_jobs WHERE status IN ('queued','running')").fetchone()[0] >= self.MAX_PENDING:
                raise WorkflowBusy('Workflow queue full; retry after current jobs finish')
            job_id = uuid.uuid4().hex
            db.execute('INSERT INTO workflow_jobs(id,cache_key,source,name,menu,arguments,status,created) VALUES (?,?,?,?,?,?,?,?)',
                       (job_id, key, source, name, rule['menu'], encoded, 'queued', now))
            row = db.execute('SELECT * FROM workflow_jobs WHERE id=?', (job_id,)).fetchone()
        self._wake.set()
        return self._public(row)

    @staticmethod
    def _public(row, cached=False):
        result = {key: row[key] for key in ('id', 'source', 'name', 'menu', 'status', 'created', 'finished', 'expires', 'error')}
        result['cached'] = cached
        result['result'] = json.loads(row['result']) if row['result'] else None
        return result

    def get(self, job_id):
        with self.db() as db:
            row = db.execute('SELECT * FROM workflow_jobs WHERE id=?', (str(job_id),)).fetchone()
        if not row:
            raise ValueError('Workflow job not found')
        return self._public(row)

    def history(self, menu=None, start=None, end=None):
        filters, args = [], []
        if menu:
            filters.append('menu=?')
            args.append(menu)
        if start is not None:
            filters.append('created>=?')
            args.append(start)
        if end is not None:
            filters.append('created<?')
            args.append(end)
        where = ' WHERE ' + ' AND '.join(filters) if filters else ''
        with self.db() as db:
            # Do not load result blobs merely to display a history list.
            rows = db.execute('SELECT id,source,name,menu,status,created,finished,expires,error FROM workflow_jobs' + where +
                              ' ORDER BY created DESC LIMIT 50', args).fetchall()
            counts = dict(db.execute('SELECT status,COUNT(*) FROM workflow_jobs GROUP BY status').fetchall())
        return {'jobs': [dict(row) for row in rows], 'counts': counts, 'limit': 50,
                'retention_days': 30, 'max_retained_jobs': self.MAX_ROWS, 'workers': 1,
                'external_runs_per_hour': self.EXTERNAL_RUNS_PER_HOUR,
                'local_runs_per_hour': self.LOCAL_RUNS_PER_HOUR}

    def run_once(self):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM workflow_jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if not row:
                return False
            db.execute("UPDATE workflow_jobs SET status='running' WHERE id=?", (row['id'],))
        rule = policy({'name': row['name']})
        try:
            if rule['mode'] != 'cached_read':
                raise ValueError('Tool policy changed; manual review required')
            result = self.call(row['source'], row['name'], json.loads(row['arguments']))
            if not result.get('ok'):
                raise RuntimeError(result.get('text') or 'Tool returned an error')
            # Persist one structured representation, not duplicate MCP/raw payloads.
            structured = result.get('json')
            plain_text = result.get('text')
            result = {key: result.get(key) for key in ('ok', 'name', 'source', 'duration_ms')}
            result['json'] = structured
            result['text'] = None if structured is not None else plain_text
            encoded = self.clean(json.dumps(result, ensure_ascii=True))
            if len(encoded.encode()) > self.MAX_RESULT_BYTES:
                raise ValueError('Result exceeds workflow storage limit; narrow the query')
            status, error, ttl = 'completed', None, rule['cache_seconds']
        except Exception as exc:  # noqa: BLE001 - provider/tool failures become durable job state
            encoded, status, error, ttl = None, 'failed', str(self.clean(str(exc)))[:500], 300
        now = time.time()
        with self.db() as db:
            db.execute('UPDATE workflow_jobs SET status=?,finished=?,expires=?,result=?,error=? WHERE id=?',
                       (status, now, now + ttl, encoded, error, row['id']))
            db.execute("DELETE FROM workflow_jobs WHERE status IN ('completed','failed') AND created<?", (now - self.RETENTION_SECONDS,))
            db.execute("DELETE FROM workflow_jobs WHERE id IN (SELECT id FROM workflow_jobs WHERE status IN ('completed','failed') ORDER BY created DESC LIMIT -1 OFFSET ?)", (self.MAX_ROWS,))
        return True

    def start(self):
        with self._start_lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            with self.db() as db:
                # Never blindly replay an interrupted call after a server restart.
                db.execute("UPDATE workflow_jobs SET status='failed',error='Worker restarted; review before retry',finished=?,expires=? WHERE status='running'", (time.time(), time.time() + 300))
            self._thread = threading.Thread(target=self._loop, name='soc-workflows', daemon=True)
            self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                worked = self.run_once()
            except Exception:  # noqa: BLE001 - keep the worker alive; run_once records job errors
                worked = False
            self._wake.wait(5 if worked else 10)
            self._wake.clear()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
