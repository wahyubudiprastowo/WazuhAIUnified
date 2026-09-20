import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from datetime import datetime, timezone, timedelta
import soc_automation as soc
from soc_pipeline import Pipeline, bounds, history, observables


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config={**soc.DEFAULTS,'SOC_CVE_BUDGET':'0','SOC_IOC_BUDGET':'1'}
        self.worker=soc.Automation(lambda:self.config,Mock(),Mock(),Mock(),Mock(),Mock(),Path(self.temp.name)/'state.db')
        self.request=Mock()
        self.pipeline=Pipeline(self.worker,self.request)
        self.event={'@timestamp':datetime.now(timezone.utc).isoformat(),'rule':{'level':12},'data':{'srcip':'1.1.1.1','url':'/'}}

    def test_failed_window_replays_without_duplicate_indicators(self):
        first={'_scroll_id':'cursor','hits':{'hits':[{'_source':self.event}]}}
        self.request.side_effect=[first,RuntimeError('timeout'),{}]
        with self.assertRaises(RuntimeError):self.pipeline.scan_window()
        initial=self.pipeline.status()
        self.assertEqual(initial['checkpoint'],initial['started_at'])
        self.assertEqual(initial['queued_indicators'],0)
        self.assertEqual(initial['rollup']['events'],0)
        self.request.side_effect=[first,{'_scroll_id':'cursor','hits':{'hits':[]}},{}]
        self.assertTrue(self.pipeline.scan_window())
        latest=self.pipeline.status()
        self.assertNotEqual(latest['checkpoint'],initial['checkpoint'])
        self.assertEqual(latest['queued_indicators'],1)
        self.assertEqual(latest['checkpoint_events_scanned'],1)
        self.assertEqual(latest['rollup']['events'],1)
        self.assertEqual(self.pipeline.candidates()[0]['occurrences'],1)
        start = datetime.fromisoformat(initial['checkpoint'])
        end = datetime.fromisoformat(latest['checkpoint'])
        self.assertFalse(self.pipeline._commit_scan_window(
            False, start, end, {('ip','1.1.1.1'):(self.event['@timestamp'],self.event['@timestamp'],12,1)},
            {}, 1, True))
        self.assertEqual(self.pipeline.candidates()[0]['occurrences'],1)
        self.assertEqual(self.pipeline.status()['checkpoint_events_scanned'],1)
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
            'rule': {'id': '9001', 'level': 12, 'description': 'Fortigate deny',
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

    def test_partial_backfill_does_not_advance_cursor(self):
        self.request.return_value = {'timed_out': True, '_shards': {'failed': 1}}
        with self.assertRaises(RuntimeError):
            self.pipeline.backfill_once()
        status = self.pipeline.status()['rollup']['backfill']
        self.assertEqual(status['chunks'], 0)
        self.assertFalse(status['complete'])
        self.assertIn('cursor not advanced', status['error'])

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
