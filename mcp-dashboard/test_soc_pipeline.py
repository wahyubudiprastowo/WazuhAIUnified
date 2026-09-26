import tempfile
import time
import unittest
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
import soc_automation as soc
from soc_pipeline import Pipeline, bounds, history, observables
import entity_resolver


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config={**soc.DEFAULTS,'SOC_CVE_BUDGET':'0','SOC_IOC_BUDGET':'1'}
        self.worker=soc.Automation(lambda:self.config,Mock(),Mock(),Mock(),Mock(),Mock(),Path(self.temp.name)/'state.db')
        self.request=Mock()
        self.pipeline=Pipeline(self.worker,self.request)
        self.event={'@timestamp':datetime.now(timezone.utc).isoformat(),'rule':{'level':12},'data':{'srcip':'1.1.1.1','url':'/'}}

    def test_rollup_seed_retries_transient_database_lock(self):
        connection = Mock()
        connection.execute.side_effect = [sqlite3.OperationalError('database is locked'), Mock()]

        @contextmanager
        def locked_db():
            yield connection

        with patch.object(self.worker, 'db', side_effect=[locked_db(), locked_db()]):
            self.pipeline._seed_rollup_windows_with_retry()
        self.assertEqual(connection.execute.call_count, 2)

    def test_lightweight_status_is_explicitly_bounded(self):
        status = self.pipeline.status(lightweight=True)
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["status_scope"], "bounded_runtime_snapshot")
        self.assertFalse(status["detail_available"])
        self.assertEqual(status["entity_graph"]["status"], "not_checked")

    def test_failed_window_replays_without_duplicate_indicators(self):
        first={'_scroll_id':'cursor','hits':{'hits':[{'_source':self.event}]}}
        self.request.side_effect=[first,RuntimeError('timeout'),{}]
        with self.assertRaises(RuntimeError):self.pipeline.scan_window()
        initial=self.pipeline.status()
        self.assertEqual(initial['checkpoint'],initial['started_at'])
        self.assertEqual(initial['queued_indicators'],0)
        self.assertEqual(initial['rollup']['events'],0)
        with self.worker.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM entity_evidence').fetchone()[0], 0)
        self.request.side_effect=[first,{'_scroll_id':'cursor','hits':{'hits':[]}},{}]
        self.assertTrue(self.pipeline.scan_window())
        latest=self.pipeline.status()
        self.assertNotEqual(latest['checkpoint'],initial['checkpoint'])
        self.assertEqual(latest['queued_indicators'],1)
        self.assertEqual(latest['checkpoint_events_scanned'],1)
        self.assertEqual(latest['rollup']['events'],1)
        self.assertEqual(self.pipeline.candidates()[0]['occurrences'],1)
        with self.worker.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM entity_evidence').fetchone()[0], 1)
        start = datetime.fromisoformat(initial['checkpoint'])
        end = datetime.fromisoformat(latest['checkpoint'])
        self.assertFalse(self.pipeline._commit_scan_window(
            False, start, end, {('ip','1.1.1.1'):(self.event['@timestamp'],self.event['@timestamp'],12,1)},
            {}, 1, True))
        self.assertEqual(self.pipeline.candidates()[0]['occurrences'],1)
        self.assertEqual(self.pipeline.status()['checkpoint_events_scanned'],1)
        with self.worker.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM entity_evidence').fetchone()[0], 1)
        self.assertEqual(latest['unique_scan_counter'],'checkpoint_events_scanned')
        self.assertFalse(latest['historical_scope_complete'])
        self.assertFalse(latest['raw_archives_scanned'])
        self.pipeline.attempted(self.pipeline.candidates()[0])
        self.assertEqual(self.pipeline.candidates(),[])
        self.assertEqual(Pipeline(self.worker,self.request).status()['queued_indicators'],1)

    def test_ioc_rollup_and_checkpoint_rollback_together(self):
        self.request.side_effect = [{'hits': {'hits': []}}]
        self.pipeline.scan_window()
        initial = self.pipeline.status()
        page = {'_scroll_id': 'cursor', 'hits': {'hits': [{'_source': self.event}]}}
        self.request.side_effect = [page, {'_scroll_id': 'cursor', 'hits': {'hits': []}}, {}]
        with self.worker.db() as db:
            db.execute("""CREATE TRIGGER reject_test_batch BEFORE INSERT ON rollup_windows
                BEGIN SELECT RAISE(ABORT,'test rollback'); END""")
        with self.assertRaises(Exception):
            self.pipeline.scan_window()
        with self.worker.db() as db:
            db.execute('DROP TRIGGER reject_test_batch')
        latest = self.pipeline.status()
        self.assertEqual(latest['checkpoint'], initial['checkpoint'])
        self.assertEqual(latest['queued_indicators'], 0)
        self.assertEqual(latest['rollup']['events'], 0)

    def test_entity_graph_window_budget_is_bounded_and_reported(self):
        self.config['SOC_ENTITY_MAX_EVIDENCE_PER_WINDOW'] = '50'
        status = self.pipeline.status()
        if not status['checkpoint']:
            self.request.side_effect = [{'hits': {'hits': []}}]
            self.pipeline.scan_window()
            status = self.pipeline.status()
        start = datetime.fromisoformat(status['checkpoint'])
        hits = []
        for index in range(60):
            event = {
                '@timestamp': (start + timedelta(minutes=1)).isoformat(),
                'rule': {'id': '9001', 'level': 12, 'description': 'High-signal network alert'},
                'agent': {'id': '001', 'name': 'edge-fw'},
                'data': {'srcip': f'198.51.100.{index + 1}', 'dstip': '10.0.0.8'},
            }
            hits.append({'_id': f'event-{index}', '_index': 'wazuh-alerts-test', '_source': event})
        self.request.side_effect = [
            {'_scroll_id': 'cursor', 'hits': {'hits': hits}},
            {'_scroll_id': 'cursor', 'hits': {'hits': []}}, {},
        ]
        self.assertTrue(self.pipeline.scan_window())
        with self.worker.db() as db:
            row = db.execute('''SELECT candidate_count,stored_count,queued_count,coalesced_count,dropped_count
                FROM entity_graph_batches ORDER BY committed_at DESC LIMIT 1''').fetchone()
            queue_count = db.execute("SELECT COUNT(*) FROM entity_graph_queue").fetchone()[0]
            stored = db.execute("SELECT COUNT(*) FROM entity_evidence WHERE source='wazuh'").fetchone()[0]
        self.assertEqual(row, (60, 50, 10, 0, 0))
        self.assertEqual(queue_count, 10)
        self.assertEqual(stored, 50)

        restarted = Pipeline(self.worker, self.request)
        self.assertEqual(restarted.status()["entity_graph"]["queue"]["pending"], 10)
        with self.worker.db() as db:
            drained = entity_resolver.drain_queue(db, 10)
            self.assertEqual(drained["processed"], 10)
        with self.worker.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM entity_graph_queue").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM entity_evidence WHERE source='wazuh'").fetchone()[0], 60)

    def test_entity_queue_drains_from_local_store_when_wazuh_stream_is_paused(self):
        prepared = entity_resolver.prepare_evidence(
            "wazuh", "paused-stream-event", "2026-09-24T10:00:00Z",
            {"srcip": "198.51.100.20"}, "Network alert", "high", 90)
        with self.worker.db() as db:
            self.assertEqual(entity_resolver.enqueue_prepared(db, "paused-window", [prepared]), 1)
        self.config["SOC_STREAM_ENABLED"] = "false"

        drained = self.pipeline.drain_entity_queue_once(self.config)

        self.assertEqual(drained["processed"], 1)
        self.request.assert_not_called()
        with self.worker.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM entity_graph_queue").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM entity_evidence").fetchone()[0], 1)

    def test_rollup_gap_detection_distinguishes_empty_and_missing_windows(self):
        self.request.side_effect = [{'hits': {'hits': []}}]
        self.assertTrue(self.pipeline.scan_window())
        status = self.pipeline.status()
        gaps = self.pipeline.rollup_gaps(status['started_at'], status['checkpoint'])
        self.assertEqual(gaps['status'], 'complete')
        self.assertEqual(gaps['missing'], 0)
        with self.worker.db() as db:
            db.execute('DELETE FROM rollup_windows')
        gaps = self.pipeline.rollup_gaps(status['started_at'], status['checkpoint'])
        self.assertEqual(gaps['status'], 'gaps_detected')
        self.assertEqual(gaps['missing'], 1)
        self.assertEqual(gaps['ranges'][0]['buckets'], 1)

    def test_detection_rollup_materializes_soc_dimensions(self):
        status = self.pipeline.status()
        if not status['checkpoint']:
            self.request.side_effect = [{'hits': {'hits': []}}]
            self.pipeline.scan_window()
            status = self.pipeline.status()
        start = datetime.fromisoformat(status['checkpoint'])
        event = {
            '@timestamp': (start + timedelta(minutes=1)).isoformat(),
            'rule': {'id': '9001', 'level': 12, 'description': 'Fortigate brute force login failed',
                     'mitre': {'id': ['T1110']}},
            'agent': {'name': 'edge-fw'}, 'decoder': {'name': 'fortigate'},
            'data': {'srcip': '1.1.1.1', 'dstip': '10.0.0.8', 'dstport': '443',
                     'app': 'HTTPS', 'policyid': '42', 'direction': 'incoming',
                     'office365': {'UserId': 'analyst@example.com'}},
        }
        page = {'_scroll_id': 'cursor', 'hits': {'hits': [{'_source': event}]}}
        self.request.side_effect = [page, {'_scroll_id': 'cursor', 'hits': {'hits': []}}, {}]
        self.assertTrue(self.pipeline.scan_window())
        summary = self.pipeline.rollup_summary(start.isoformat(), (start + timedelta(minutes=10)).isoformat())
        source_fields = self.request.call_args_list[0].args[1]['_source']
        for field in ('rule.id', 'decoder.name', 'data.dstport', 'data.policyid', 'data.office365.UserId', 'rule.mitre.id'):
            self.assertIn(field, source_fields)
        self.assertEqual(summary['timeline'][0]['doc_count'], 1)
        self.assertEqual(summary['dimensions']['rule'][0]['value'], '9001')
        self.assertEqual(summary['dimensions']['decoder'][0]['value'], 'fortigate')
        self.assertEqual(summary['dimensions']['destination_ip'][0]['value'], '10.0.0.8')
        self.assertEqual(summary['dimensions']['mitre'][0]['value'], 'T1110')
        self.assertEqual(summary['dimensions']['detection_family'][0]['value'], 'bruteforce')
        self.assertTrue(summary['coverage']['taxonomy']['complete'])

    def test_historical_backfill_is_bounded_aggregation_and_advances_cursor(self):
        self.config.update({'SOC_ROLLUP_BACKFILL_DAYS': '7', 'SOC_ROLLUP_BACKFILL_CHUNK_MINUTES': '30'})

        def response(path, payload):
            bucket = payload['query']['range']['@timestamp']['gte']
            return {'took': 8, '_shards': {'failed': 0}, 'aggregations': {'rollup': {'buckets': [{
                'key_as_string': bucket, 'doc_count': 25, 'max_level': {'value': 12},
                'rule': {'buckets': [{'key': '9001', 'doc_count': 20}], 'sum_other_doc_count': 5},
                'decoder': {'buckets': [{'key': 'fortigate', 'doc_count': 25}]},
            }]}}}

        self.request.side_effect = response
        self.assertTrue(self.pipeline.backfill_once())
        request = self.request.call_args.args[1]
        self.assertEqual(request['size'], 0)
        self.assertFalse(request['track_total_hits'])
        self.assertEqual(request['timeout'], '12s')
        self.assertNotIn('_source', request)
        self.assertNotIn('request_cache', request)
        status = self.pipeline.status()
        self.assertEqual(status['rollup']['backfill']['chunks'], 1)
        self.assertEqual(status['rollup']['backfill']['events'], 25)
        with self.worker.db() as db:
            rule = db.execute("SELECT count FROM detection_rollups WHERE dimension='rule' AND value='9001'").fetchone()
            other = db.execute("SELECT count FROM detection_rollups WHERE dimension='rule' AND value='__other__'").fetchone()
            completed = db.execute("SELECT event_count FROM rollup_windows ORDER BY bucket_epoch LIMIT 1").fetchone()
        self.assertEqual(rule[0], 20)
        self.assertEqual(other[0], 5)
        self.assertEqual(completed[0], 25)

    def test_forti_security_backfill_is_decoder_scoped_and_idempotent(self):
        self.config.update({
            'SOC_FORTI_SECURITY_BACKFILL_ENABLED': 'true',
            'SOC_FORTI_SECURITY_BACKFILL_CHUNK_MINUTES': '120',
            'SOC_FORTI_SECURITY_BACKFILL_INTERVAL_SECONDS': '300',
            'SOC_ROLLUP_BACKFILL_DAYS': '7',
            'SOC_ROLLUP_BACKFILL_CHUNK_MINUTES': '30',
        })

        def response(path, payload):
            bucket = payload['query']['bool']['filter'][0]['range']['@timestamp']['gte']
            return {'took': 6, '_shards': {'failed': 0}, 'aggregations': {'rollup': {'buckets': [{
                'key_as_string': bucket, 'doc_count': 4,
                'forti_security': {'buckets': {
                    'ips_blocked': {'doc_count': 3, 'max_level': {'value': 12}},
                    'ips_detected': {'doc_count': 0, 'max_level': {'value': None}},
                    'malware': {'doc_count': 1, 'max_level': {'value': 10}},
                }},
            }]}}}

        self.request.side_effect = response
        self.assertTrue(self.pipeline.forti_security_backfill_once())
        request = self.request.call_args.args[1]
        self.assertEqual(request['size'], 0)
        self.assertFalse(request['track_total_hits'])
        self.assertNotIn('_source', request)
        self.assertNotIn('scroll', str(request))
        self.assertEqual(request['query']['bool']['filter'][1],
                         {'term': {'decoder.name': 'fortigate-firewall-v5'}})
        start = datetime.fromisoformat(request['query']['bool']['filter'][0]['range']['@timestamp']['gte'])
        end = datetime.fromisoformat(request['query']['bool']['filter'][0]['range']['@timestamp']['lt'])
        self.assertEqual(int((end - start).total_seconds() // 60), 120)
        with self.worker.db() as db:
            ips_blocked = db.execute("SELECT count,label FROM detection_rollups WHERE dimension='forti_security' AND value='ips_blocked'").fetchone()
            malware = db.execute("SELECT count,label FROM detection_rollups WHERE dimension='forti_security' AND value='malware'").fetchone()
        self.assertEqual(ips_blocked, (3, 'FortiGate IPS blocked'))
        self.assertEqual(malware, (1, 'FortiGate malware signal'))
        status = self.pipeline.status()['rollup']['forti_security_backfill']
        self.assertEqual(status['chunks'], 1)
        self.assertEqual(status['events'], 4)

    def test_partial_backfill_does_not_advance_cursor(self):
        self.request.return_value = {'timed_out': True, '_shards': {'failed': 1}}
        with self.assertRaises(RuntimeError):
            self.pipeline.backfill_once()
        status = self.pipeline.status()['rollup']['backfill']
        self.assertEqual(status['chunks'], 0)
        self.assertFalse(status['complete'])
        self.assertIn('cursor not advanced', status['error'])

    def test_fast_backfill_adapts_chunk_and_uses_rolling_target(self):
        self.config.update({
            'SOC_ROLLUP_BACKFILL_DAYS': '7',
            'SOC_ROLLUP_BACKFILL_CHUNK_MINUTES': '30',
            'SOC_ROLLUP_BACKFILL_MAX_CHUNK_MINUTES': '120',
            'SOC_ROLLUP_BACKFILL_MIN_INTERVAL_SECONDS': '15',
            'SOC_ROLLUP_BACKFILL_FAST_QUERY_MS': '1500',
        })
        self.request.return_value = {
            'took': 10, '_shards': {'failed': 0},
            'aggregations': {'rollup': {'buckets': []}},
        }
        old_target = datetime.now(timezone.utc) - timedelta(days=30)
        cursor = datetime.now(timezone.utc) - timedelta(days=1)
        with self.worker.db() as db:
            db.execute('''INSERT INTO rollup_backfill_state
                (id,cursor,target,completed,current_chunk_minutes,next_run)
                VALUES (1,?,?,0,30,0)''', (cursor.isoformat(), old_target.isoformat()))
        self.assertTrue(self.pipeline.backfill_once())
        with self.worker.db() as db:
            db.execute('UPDATE rollup_backfill_state SET next_run=0 WHERE id=1')
        self.assertTrue(self.pipeline.backfill_once())
        status = self.pipeline.status()['rollup']['backfill']
        target = datetime.fromisoformat(status['target'])
        self.assertLess(abs((target - (datetime.now(timezone.utc) - timedelta(days=7))).total_seconds()), 3700)
        self.assertEqual(status['current_chunk_minutes'], 60)
        self.assertEqual(status['failures'], 0)
        self.assertGreater(status['next_run'], time.time())

    def test_completed_linear_backfill_repairs_internal_gap(self):
        self.config['SOC_ROLLUP_BACKFILL_DAYS'] = '7'
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        target = (now - timedelta(days=7)).replace(minute=0)
        checkpoint = target + timedelta(minutes=15)
        with self.worker.db() as db:
            db.execute('INSERT INTO stream_state(id,start,checkpoint,scanned) VALUES (1,?,?,0)',
                       (target.isoformat(), checkpoint.isoformat()))
            db.execute('''INSERT INTO rollup_backfill_state
                (id,cursor,target,completed,current_chunk_minutes,next_run)
                VALUES (1,?,?,1,30,0)''', (target.isoformat(), target.isoformat()))
        self.request.return_value = {
            'took': 5, '_shards': {'failed': 0},
            'aggregations': {'rollup': {'buckets': []}},
        }
        self.assertTrue(self.pipeline.backfill_once())
        request = self.request.call_args.args[1]
        self.assertEqual(request['query']['range']['@timestamp']['gte'], target.isoformat())
        self.assertEqual(self.pipeline.status()['rollup']['backfill']['mode'], 'repair')
        self.assertEqual(self.pipeline.rollup_gaps(target.isoformat(), checkpoint.isoformat())['missing'], 0)

    def test_private_paths_and_invalid_hashes_not_sent(self):
        self.assertEqual(observables({'data':{'srcip':'10.1.1.1','url':'/.env'},'syscheck':{'md5_after':'bad'}}),[])
        self.assertEqual(len(observables(self.event)),1)

    def test_recent_pass_does_not_skip_historical_checkpoint(self):
        self.request.side_effect=[{'hits':{'hits':[]}}]
        self.pipeline.scan_window(recent=True)
        status=self.pipeline.status()
        self.assertEqual(status['checkpoint'],status['started_at'])
        self.assertIsNotNone(status['live_through'])

    def test_all_observables_are_queued_and_live_replay_does_not_inflate_counts(self):
        event = {**self.event, 'data': {'srcip': '1.1.1.1', 'dstip': '8.8.8.8'}}
        page = {'_scroll_id': 'cursor', 'hits': {'hits': [{'_source': event}]}}
        self.request.side_effect = [page, {'_scroll_id': 'cursor', 'hits': {'hits': []}}, {}]
        self.assertTrue(self.pipeline.scan_window(recent=True))
        with self.worker.db() as db:
            queued = db.execute('SELECT indicator,count FROM ioc_queue ORDER BY indicator').fetchall()
        self.assertEqual(queued, [('1.1.1.1', 0), ('8.8.8.8', 0)])

    def test_dates_and_history_query_contract(self):
        for payload in [{},{'start':'2026-01-01','end':'2026-01-02'},
                        {'start':'2026-01-01T00:00:00Z','end':'2027-01-01T00:00:00Z'}]:
            with self.assertRaises(ValueError):bounds(payload)
        search=Mock(return_value={'hits':{'total':{'value':1},'hits':[{'_id':'event','_source':self.event}]}})
        result=history(search,{'start':'2026-09-01T00:00:00+07:00','end':'2026-09-02T00:00:00+07:00','rule':'123'})
        self.assertTrue(result['ok'])
        self.assertIn('2026-08-31T17:00:00',result['start'])
        self.assertIn({'term':{'rule.id':'123'}},search.call_args.args[0]['query']['bool']['filter'])
        self.assertIn('analysis',result['events'][0])

    def test_report_retention_and_lookup_by_date(self):
        report={'coverage':{},'findings':[],'generated_at':'2026-09-11T00:00:00Z','ai':{'status':'queued'}}
        with self.worker.db() as db:
            db.execute('INSERT INTO reports VALUES (1,?,?)',(datetime.now(timezone.utc).timestamp(),__import__('json').dumps(report)))
        now=datetime.now(timezone.utc)
        self.assertEqual(self.worker.reports((now-timedelta(days=1)).isoformat(),(now+timedelta(days=1)).isoformat())[0]['id'],1)
        self.assertEqual(self.worker.report(1)['ai']['status'],'queued')
        with self.assertRaises(ValueError):self.worker.report(999)


if __name__=='__main__':unittest.main()
