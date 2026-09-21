import base64
import tempfile
import time
import unittest
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor

import soc_automation as soc
import server
from soc_contract import CONTRACT_VERSION


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {**soc.DEFAULTS, "SOC_IOC_BUDGET": "1", "SOC_CVE_BUDGET": "0"}
        self.coverage = {"ok": True, "total_events": 1000000, "events_with_observable": 100,
            "observables": [{"indicator": "8.8.8.8", "kind": "ip", "level": 12, "occurrences": 3},
                            {"indicator": "1.1.1.1", "kind": "ip", "level": 5, "occurrences": 7}], "rules": []}
        self.intel = Mock(return_value={"ok": True, "data": {"results": [{"provider": "otx", "is_malicious": False,
                                                   "detail": {"pulse_count": 0}}]}, "generated_at": soc.now()})
        self.call = Mock(return_value={"ok": True, "data": {"items": [], "feeds": {}, "next_offset": None}})
        self.worker = soc.Automation(lambda: self.config, lambda: self.coverage, self.intel,
            Mock(return_value={"total": 3, "events": []}), Mock(return_value={"ok": True, "items": [], "total": 0}),
            self.call, Path(self.temp.name) / 'state.db')

    def test_real_candidates_bounded_and_rotated_no_match_not_safe(self):
        first = self.worker.build()
        self.assertEqual(first['coverage']['indexed_events'], 1000000)
        self.assertEqual(first['coverage']['analyzed_candidates'], 1)
        self.assertEqual(first['findings'][0]['status'], 'needs_review')
        self.assertFalse(first['findings'][0]['compromise_confirmed'])
        second = self.worker.build()
        self.assertEqual(second['coverage']['analyzed_candidates'], 2)
        self.assertEqual(self.intel.call_count, 2)
        self.worker.build()
        self.assertEqual(self.intel.call_count, 2)

    def test_cyfirma_matches_local_evidence_not_every_feed_item(self):
        self.config['SOC_IOC_BUDGET'] = '0'
        self.call.return_value = {'ok': True, 'data': {'items': [
            {'iocs':['8.8.8.8'], 'name':'test match'}, {'iocs':['9.9.9.9'], 'name':'external only'}], 'next_offset':None}}
        result = self.worker.build()
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['indicator'], '8.8.8.8')
        self.assertEqual(result['findings'][0]['status'], 'suspected')
        self.intel.assert_not_called()

    def test_cyfirma_feed_is_daily_idempotent_and_history_uses_no_provider(self):
        observed = datetime(2026, 9, 19, 9, tzinfo=timezone.utc).timestamp()
        rows = [{
            'id': 'indicator--one', 'scope': 'tailored',
            'name': 'Observed exploit infrastructure CVE-2026-12345',
            'description': 'Provider indicator mentioning CVE-2026-12345.',
            'confidence': 85, 'iocs': ['198.51.100.8', 'malicious.example'],
            'labels': ['malicious-activity'], 'modified': '2026-09-19T08:00:00Z',
        }]
        status = {'tailored': {'status': 'loaded', 'loaded': 1, 'reported': 1,
                               'fetched_at': '2026-09-19T09:00:00+00:00'}}
        self.worker._store_cyfirma_observations(rows, status, observed)
        self.worker._store_cyfirma_observations(rows, status, observed + 300)
        history = self.worker.cyfirma_updates(
            datetime(2026, 9, 19, tzinfo=timezone.utc).isoformat(),
            datetime(2026, 9, 20, tzinfo=timezone.utc).isoformat())
        self.assertEqual(history['summary']['indicators'], 1)
        self.assertEqual(history['summary']['tailored'], 1)
        self.assertEqual(history['summary']['cve_linked'], 1)
        self.assertEqual(history['items'][0]['cves'], ['CVE-2026-12345'])
        self.assertEqual(history['cve_items'][0]['cves'], ['CVE-2026-12345'])
        self.assertEqual(history['provider_calls'], 0)
        self.assertNotIn('iocs', history['items'][0])
        with self.worker.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM cyfirma_observations').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM cyfirma_feed_runs').fetchone()[0], 1)

    def test_existing_cyfirma_cache_is_materialized_without_provider_call(self):
        fetched_at = '2026-09-19T09:00:00+00:00'
        self.worker.put('feed:tailored', {
            'rows': [{'id': 'indicator--cached', 'scope': 'tailored',
                      'name': 'Cached provider record', 'confidence': 'high',
                      'iocs': ['198.51.100.9']}],
            'status': {'status': 'loaded', 'loaded': 1, 'reported': 1,
                       'fetched_at': fetched_at},
        }, 3600)
        history = self.worker.cyfirma_updates(
            datetime(2026, 9, 19, tzinfo=timezone.utc).isoformat(),
            datetime(2026, 9, 20, tzinfo=timezone.utc).isoformat())
        self.assertEqual(history['summary']['indicators'], 1)
        self.assertEqual(history['items'][0]['name'], 'Cached provider record')
        self.assertEqual(history['items'][0]['confidence'], 0)
        self.assertEqual(history['provider_calls'], 0)
        self.call.assert_not_called()

    def test_private_ips_paths_and_urls_not_disclosed(self):
        for kind, indicator in [('ip', '10.1.1.1'), ('url', '/.env'), ('url', 'http://127.0.0.1/'),
                                ('url','https://example.com/?token=secret'), ('domain','internal')]:
            self.assertFalse(soc.public_indicator({'kind':kind, 'indicator':indicator}))
        self.assertNotEqual(soc.normalized('https://example.com/A'), soc.normalized('https://example.com/a'))

    def test_failed_index_does_not_publish_success(self):
        self.coverage['ok'] = False
        self.worker.run()
        self.assertIn('incomplete', self.worker.status()['error'])
        self.assertIsNone(self.worker.status()['latest'])

    def test_reports_persist_and_concurrent_notifications_deduplicate(self):
        self.worker.run()
        report = self.worker.status()['latest']
        self.config['SOC_EMAIL_ENABLED'] = 'true'
        with patch.object(soc, 'deliver', return_value={'status':'accepted'}) as deliver:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: self.worker.send(report, 'email'), range(2)))
            self.assertEqual(deliver.call_count, 1)
            self.assertEqual({r['status'] for r in results}, {'accepted','cooldown'})
        self.assertEqual(self.worker.status()['latest']['id'], report['id'])

    def test_ai_disabled_never_contacts_model_and_validates_output(self):
        report = self.worker.build()
        with patch.object(soc, 'post_chat') as request:
            self.assertEqual(soc.analyze_with_model(self.config, report)['status'], 'disabled')
            request.assert_not_called()
            self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
            request.return_value = {'choices':[{'message':{'content':'{"summary":"ok"}'}}]}
            with self.assertRaises(ValueError):
                soc.analyze_with_model(self.config, report)
            request.return_value = {'choices':[{'message':{'content':'{"summary":"ok","assessment":"Evidence required","recommendations":["Review"],"gaps":[]}'}}]}
            analyzed = soc.analyze_with_model(self.config, report)
            self.assertEqual(analyzed['status'], 'completed')
            self.assertEqual(analyzed['contract_version'], CONTRACT_VERSION)
            self.assertEqual(analyzed['result']['contract']['scope'], 'window')
            payload = request.call_args.args[1]
            self.assertNotIn('tools', payload)
            self.assertIn('UNTRUSTED DATA', payload['messages'][0]['content'])
            self.assertIn(CONTRACT_VERSION, payload['messages'][0]['content'])

    def test_report_publishes_before_ai_and_poll_skips_unchanged_payload(self):
        self.config.update(AI_ANALYST_ENABLED='true',AI_AUTO_ANALYZE='true')
        with patch.object(soc,'analyze_with_model') as model:
            self.worker.run()
            model.assert_not_called()
        status=self.worker.status()
        self.assertEqual(status['latest']['ai']['status'],'queued')
        compact=self.worker.status(status['revision'])
        self.assertTrue(compact['unchanged'])
        self.assertIsNone(compact['latest'])
        self.worker.store_ai(status['latest'],{'status':'error','error':'test timeout'})
        self.assertFalse(self.worker.status(status['revision'])['unchanged'])

    def test_config_requires_delivery_details_and_preserves_existing_keys(self):
        self.assertTrue(soc.validate({**soc.DEFAULTS, 'SOC_EMAIL_ENABLED':'true'}))
        self.assertEqual(soc.validate(soc.DEFAULTS), [])
        serialized = server._serialize_env({'EXISTING_OPTION':'keep', 'SOC_IOC_BUDGET':'2'})
        self.assertIn('EXISTING_OPTION=keep', serialized)
        _, errors = server._validate_config_update({'SOC_SMTP_FROM':'x@example.com\nBcc:evil@example.com'})
        self.assertTrue(errors)

    def test_oauth_uses_sasl_not_mailbox_password(self):
        smtp = Mock()
        config = {**self.config, 'SOC_SMTP_AUTH': 'oauth2',
                  'SOC_SMTP_USER': 'sender@example.com', 'SOC_SMTP_PASSWORD': 'not-a-token'}
        with patch.object(soc, 'smtp_token', return_value='access-token'):
            soc.smtp_authenticate(smtp, config)
        mechanism, callback = smtp.auth.call_args.args
        self.assertEqual(mechanism, 'XOAUTH2')
        self.assertEqual(callback(), 'user=sender@example.com\x01auth=Bearer access-token\x01\x01')
        self.assertEqual(callback(b'error'), '')
        smtp.login.assert_not_called()

    def test_smtp_diagnostics_preserve_tls_on_auth_failure_without_sending(self):
        config = {**self.config, 'SOC_SMTP_HOST': 'smtp.example.com', 'SOC_SMTP_AUTH': 'oauth2'}
        with patch.object(soc.smtplib, 'SMTP') as constructor, \
             patch.object(soc, 'smtp_token', return_value='opaque-token'), \
             patch.object(soc, 'smtp_authenticate', side_effect=soc.smtplib.SMTPAuthenticationError(535, b'Authentication unsuccessful')):
            result = soc.smtp_test(config)
            self.assertTrue(result['tcp'])
            self.assertTrue(result['tls'])
            self.assertFalse(result['authenticated'])
            self.assertFalse(result['sent'])
            self.assertEqual(result['smtp_code'], 535)
            constructor.return_value.__enter__.return_value.send_message.assert_not_called()

    def test_smtp_diagnostics_identify_missing_send_as_app_role(self):
        config = {**self.config, 'SOC_SMTP_HOST': 'smtp.example.com', 'SOC_SMTP_AUTH': 'oauth2',
                  'SOC_SMTP_USER': 'sender@example.com', 'SOC_EMAIL_ENABLED': 'false',
                  'SOC_REPORT_RECIPIENTS': 'one@example.com,two@example.com'}
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
        claims = base64.urlsafe_b64encode(b'{"roles":["Mail.ReadWrite"]}').decode().rstrip('=')
        token = f'{header}.{claims}.signature'
        with patch.object(soc, 'smtp_token', return_value=token), \
             patch.object(soc.smtplib, 'SMTP') as constructor:
            smtp = constructor.return_value.__enter__.return_value
            smtp.auth.side_effect = soc.smtplib.SMTPAuthenticationError(535, b'Authentication unsuccessful')
            result = soc.smtp_test(config)
        self.assertFalse(result['email_enabled'])
        self.assertEqual(result['recipient_count'], 2)
        self.assertFalse(result['smtp_send_as_app'])
        self.assertIn('missing SMTP.SendAsApp', result['next_step'])

    def test_ai_test_persists_result_and_respects_active_analysis(self):
        self.worker.run()
        with patch.object(soc, 'analyze_with_model', return_value={'status': 'completed', 'result': {'summary': 'verified'}}) as model:
            self.assertEqual(self.worker.test_ai()['status'], 'completed')
            self.assertEqual(self.worker.status()['latest']['ai']['result']['summary'], 'verified')
            self.worker.running = True
            self.assertEqual(self.worker.test_ai()['status'], 'busy')
            self.assertEqual(model.call_count, 1)

    def test_ai_gateway_error_text_is_not_reported_as_connected(self):
        response = Mock()
        response.headers = {'Content-Type': 'text/event-stream'}
        response.read.side_effect = [
            b'data: {"model":"route","choices":[{"delta":{"content":"[Error: You have hit your limit. Please try again later.]"},"finish_reason":"stop"}]}\n\n',
            b'',
        ]
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(soc.urllib.request, 'urlopen', return_value=context):
            with self.assertRaisesRegex(RuntimeError, 'provider rejected'):
                soc.post_chat('http://model/chat/completions', {'model': 'route'})

    def test_ai_error_classifier_does_not_reject_normal_analysis(self):
        self.assertIsNone(soc._chat_content_error('Rate limit activity was observed in the supplied firewall logs and should be investigated.'))
        self.assertIn('quota', soc._chat_content_error('[Error: quota exceeded]'))

    def test_model_connection_returns_structured_provider_error(self):
        config = {**self.config, 'AI_ANALYST_ENABLED': 'true',
                  'AI_PROVIDER_BASE_URL': 'http://model/v1', 'AI_MODEL': 'model'}
        with patch.object(soc, 'post_chat', side_effect=RuntimeError('AI provider rejected the request: quota exceeded')):
            result = soc.test_model_connection(config)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['model'], 'model')
        self.assertIn('quota exceeded', result['error'])

    def test_targeted_finding_ai_is_bounded_and_cached(self):
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        finding = {'id': 'rule:5710', 'title': 'SSH authentication failures', 'severity': 'high',
                   'rule': '5710', 'raw': {'password': 'must-not-leak'}, 'description': 'Observed in Wazuh'}
        self.worker.evidence.return_value = {'total': 20, 'events': [{
            'id': 'event-1', '@timestamp': '2026-09-15T10:00:00Z',
            'rule': {'id': '5710', 'level': 10, 'description': 'SSH authentication failure'},
            'agent': {'name': 'linux-01'},
            'data': {'srcip': '198.51.100.10', 'dstip': '10.0.0.8', 'srcuser': 'admin', 'action': 'failed'}}]}
        model_result = {'status': 'completed', 'model': 'model', 'result': {'summary': 'Review authentication evidence'}}
        with patch.object(soc, 'analyze_finding_with_model', return_value=model_result) as model:
            first = self.worker.analyze_finding(finding)
            second = self.worker.analyze_finding(finding)
        self.assertEqual(first['status'], 'completed')
        self.assertEqual(second['cache']['status'], 'hit')
        self.assertEqual(model.call_count, 1)
        self.assertNotIn('raw', model.call_args.args[1])
        local = model.call_args.args[1]['local_evidence'][0]
        self.assertEqual(local['source_ip'], '198.51.100.10')
        self.assertEqual(local['destination_ip'], '10.0.0.8')
        self.assertEqual(local['user'], 'admin')

    def test_cached_cve_intelligence_is_bounded_and_unexpired(self):
        self.worker.put("cve:CVE-2026-99999", {"cve": {"data": {"components": {"in_kev": True}}}}, 60)
        result = self.worker.cached_cve_intelligence(["CVE-2026-99999", "not-a-cve"])
        self.assertIn("CVE-2026-99999", result)
        self.assertTrue(result["CVE-2026-99999"]["data"]["cve"]["data"]["components"]["in_kev"])

    def test_cve_history_is_daily_idempotent_and_uses_no_provider_calls(self):
        observed = datetime(2026, 9, 18, 10, tzinfo=timezone.utc).timestamp()
        report = {"vulnerabilities": [{
            "cve": "CVE-2026-99999", "agent": "server-01", "agent_id": "001",
            "package": "openssl", "version": "3.0.0", "severity": "Critical",
            "published_at": "2026-09-17T00:00:00Z", "detected_at": "2026-09-18T09:00:00Z",
            "intelligence": {"cve": {"data": {"risk_score": 92, "components": {
                "epss_probability": 0.91, "in_kev": True, "poc_confidence": "high"}}}},
        }]}
        self.worker._store_cve_observations(report, observed, 101)
        self.worker._store_cve_observations(report, observed + 60, 101)
        history = self.worker.cve_history(
            datetime(2026, 9, 18, tzinfo=timezone.utc).isoformat(),
            datetime(2026, 9, 19, tzinfo=timezone.utc).isoformat())
        self.assertEqual(history["observations"], 1)
        self.assertEqual(history["unique_cves"], 1)
        self.assertEqual(history["affected_assets"], 1)
        self.assertEqual(history["provider_calls"], 0)
        self.assertTrue(history["items"][0]["kev"])
        self.assertEqual(history["items"][0]["agent"]["name"], "server-01")

    def test_materialized_history_summary_preserves_soc_dimensions(self):
        created = time.time()
        report = {
            'generated_at': '2026-09-15T10:00:00Z',
            'coverage': {'indexed_events': 3000000},
            'rules': [{'rule_id': '5710', 'level': 10, 'count': 20,
                       'description': 'SSH authentication failure', 'analysis': {'title': 'Authentication failure'}}],
            'findings': [{'indicator': '198.51.100.10', 'kind': 'ip', 'status': 'suspected', 'event_total': 20,
                          'evidence': [{'event_id': 'event-1', 'timestamp': '2026-09-15T10:00:00Z',
                              'rule': {'id': '5710', 'level': 10, 'description': 'SSH authentication failure'},
                              'source_ip': '198.51.100.10', 'destination_ip': '10.0.0.8',
                              'device': 'linux-01', 'user': 'admin', 'action': 'failed'}]}],
            'vulnerabilities': [],
            'ai': {'status': 'completed', 'result': {
                'verdict': {'status': 'suspicious', 'severity': 'high'},
                'attack_categories': [{'category': 'authentication', 'count': 20, 'severity': 'high'}],
                'network_paths': [{'source': '198.51.100.10', 'destination': '10.0.0.8', 'events': 20}],
                'identities': [{'user': 'admin', 'activity': 'failed login'}]}}}
        with self.worker.db() as db:
            db.execute('INSERT INTO reports(id,created,data) VALUES (?,?,?)', (7, created, __import__('json').dumps(report)))

        rows = self.worker._summary_rows(created - 1, created + 1)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['attack_categories'][0]['category'], 'authentication')
        self.assertEqual(rows[0]['top_destinations'][0]['value'], '10.0.0.8')
        self.assertEqual(rows[0]['top_identities'][0]['value'], 'admin')
        with self.worker.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM report_summaries').fetchone()[0], 1)
            duplicate_window = __import__('copy').deepcopy(report)
            duplicate_window['findings'][0]['event_total'] = 10
            duplicate_window['ai']['result']['attack_categories'][0]['count'] = 10
            db.execute('INSERT INTO reports(id,created,data) VALUES (?,?,?)',
                       (8, created + 10, __import__('json').dumps(duplicate_window)))
        summary = self.worker.history_summary(
            datetime.fromtimestamp(created - 1, timezone.utc).isoformat(),
            datetime.fromtimestamp(created + 20, timezone.utc).isoformat())
        self.assertEqual(summary['totals']['reports'], 2)
        self.assertEqual(summary['totals']['findings'], 1)
        self.assertEqual(summary['top_source_ips'][0]['count'], 20)
        self.assertEqual(summary['attack_categories'][0]['count'], 20)

    def test_finding_ai_queue_is_persistent_deduplicated_and_profiled(self):
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        finding = {'id': 'ip:8.8.8.8', 'title': 'FortiGate scan', 'category': 'ip', 'ip': '8.8.8.8',
                   'types': ['fortigate', 'network'], 'description': 'Blocked scan observed'}
        queued = self.worker.queue_finding_analysis(finding)
        duplicate = self.worker.queue_finding_analysis(finding)
        self.assertEqual(queued['status'], 'queued')
        self.assertEqual(queued['profile']['id'], 'network')
        self.assertEqual(duplicate['job_id'], queued['job_id'])
        with patch.object(soc, 'analyze_finding_with_model', return_value={'status': 'completed', 'model': 'model', 'result': {'summary': 'reviewed'}}) as model:
            self.worker.start()
            deadline = time.time() + 3
            while time.time() < deadline and self.worker.finding_analysis_job(queued['job_id'])['status'] != 'completed':
                time.sleep(.05)
            result = self.worker.finding_analysis_job(queued['job_id'])
            self.worker.stop.set()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['result']['analysis_profile']['id'], 'network')
        self.assertIn('analyst_memory', model.call_args.args[1])

    def test_analyst_feedback_is_validated_persisted_and_added_to_memory(self):
        finding = {'id': 'rule:5710', 'title': 'SSH authentication failures', 'category': 'wazuh'}
        invalid = self.worker.save_finding_feedback(finding['id'], 'benign_forever', 'unsupported', finding)
        self.assertFalse(invalid['ok'])
        saved = self.worker.save_finding_feedback(finding['id'], 'false_positive', 'Approved scanner', finding)
        self.assertTrue(saved['ok'])
        history = self.worker.finding_feedback(finding['id'])
        self.assertEqual(history['items'][0]['disposition'], 'false_positive')
        self.assertEqual(history['items'][0]['note'], 'Approved scanner')
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        model_result = {'status': 'completed', 'model': 'model', 'result': {'summary': 'Review current evidence'}}
        with patch.object(soc, 'analyze_finding_with_model', return_value=model_result) as model:
            result = self.worker.analyze_finding(finding, force=True)
        self.assertEqual(result['memory']['analyst_feedback'], 1)
        self.assertEqual(model.call_args.args[1]['analyst_memory']['analyst_feedback'][0]['disposition'], 'false_positive')

    def test_finding_ai_queue_has_backpressure_metrics_and_failed_retry(self):
        self.config['AI_FINDING_QUEUE_MAX'] = '10'
        jobs = [self.worker.queue_finding_analysis({'id': f'rule:{index}', 'title': f'Finding {index}'}) for index in range(10)]
        self.assertTrue(all(job['status'] == 'queued' for job in jobs))
        full = self.worker.queue_finding_analysis({'id': 'rule:overflow', 'title': 'Overflow'})
        self.assertEqual(full['status'], 'queue_full')
        summary = self.worker.finding_analysis_jobs()
        self.assertEqual(summary['counts']['queued'], 10)
        self.assertEqual(summary['queue_limit'], 10)
        failed_id = jobs[0]['job_id']
        with self.worker.db() as db:
            db.execute("UPDATE finding_ai_jobs SET status='failed',error='provider timeout' WHERE id=?", (failed_id,))
        retried = self.worker.retry_finding_analysis_job(failed_id)
        self.assertEqual(retried['status'], 'queued')
        self.assertNotEqual(retried['job_id'], failed_id)

    def test_stale_finding_job_expires_without_overwriting_other_jobs(self):
        self.config['AI_FINDING_LEASE_SECONDS'] = '30'
        stale = self.worker.queue_finding_analysis({'id': 'rule:stale', 'title': 'Stale job'})
        healthy = self.worker.queue_finding_analysis({'id': 'rule:healthy', 'title': 'Healthy job'})
        with self.worker.db() as db:
            db.execute("UPDATE finding_ai_jobs SET status='processing',updated=?,attempts=1 WHERE id=?",
                       (time.time() - 31, stale['job_id']))
        self.assertEqual(self.worker.expire_stale_finding_jobs(), 1)
        self.assertEqual(self.worker.finding_analysis_job(stale['job_id'])['status'], 'failed')
        self.assertEqual(self.worker.finding_analysis_job(healthy['job_id'])['status'], 'queued')
        retried = self.worker.retry_finding_analysis_job(stale['job_id'])
        self.assertEqual(retried['status'], 'queued')

    def test_existing_finding_job_table_is_migrated_in_place(self):
        db_path = Path(self.temp.name) / 'legacy.db'
        connection = sqlite3.connect(db_path)
        with connection as db:
            db.execute('CREATE TABLE finding_ai_jobs (id TEXT PRIMARY KEY, cache_key TEXT, finding_id TEXT, created REAL, updated REAL, status TEXT, request TEXT, force INTEGER, result TEXT, error TEXT)')
            db.execute("INSERT INTO finding_ai_jobs VALUES ('legacy','key','finding',1,1,'completed','{}',0,'{}',NULL)")
        connection.close()
        worker = soc.Automation(lambda: self.config, lambda: self.coverage, self.intel,
            Mock(), Mock(), self.call, db_path)
        jobs = worker.finding_analysis_jobs()
        self.assertEqual(jobs['recent'][0]['job_id'], 'legacy')
        self.assertEqual(jobs['recent'][0]['attempts'], 0)

    def test_concurrency_gate_respects_runtime_worker_limit(self):
        gate = soc._ConcurrencyGate(lambda: self.config, "AI_FINDING_WORKERS", 2)
        self.config['AI_FINDING_WORKERS'] = '2'
        self.assertTrue(gate.acquire(blocking=False))
        self.assertTrue(gate.acquire(blocking=False))
        self.assertFalse(gate.acquire(blocking=False))  # capacity reached
        gate.release()
        self.assertTrue(gate.acquire(blocking=False))
        # Raising the limit at runtime is respected without a new semaphore.
        self.config['AI_FINDING_WORKERS'] = '4'
        self.assertTrue(gate.acquire(blocking=False))
        gate.release()
        gate.release()
        gate.release()

    def test_finding_jobs_expose_worker_metrics(self):
        self.config['AI_FINDING_WORKERS'] = '3'
        summary = self.worker.finding_analysis_jobs()
        self.assertEqual(summary['workers'], 3)
        self.assertEqual(summary['active'], 0)

    def test_finding_analysis_gate_is_independent_of_report_ai_lock(self):
        # The per-finding path must not serialize behind the report ai_lock.
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model',
                           AI_FINDING_WORKERS='4')
        self.worker.ai_lock.acquire()
        try:
            acquired = self.worker.finding_ai_gate.acquire(blocking=False)
            self.assertTrue(acquired, "finding AI should run despite report analysis being busy")
            self.worker.finding_ai_gate.release()
        finally:
            self.worker.ai_lock.release()

    def test_oauth_validation_requires_application_credentials(self):
        config = {**self.config, 'SOC_EMAIL_ENABLED': 'true', 'SOC_SMTP_HOST': 'smtp.example.com',
                  'SOC_SMTP_FROM': 'sender@example.com', 'SOC_SMTP_USER': 'sender@example.com',
                  'SOC_REPORT_RECIPIENTS': 'soc@example.com',
                  'SOC_SMTP_AUTH': 'oauth2', 'SOC_SMTP_OAUTH_USE_M365': 'true'}
        self.assertTrue(soc.validate(config))
        config.update(M365_TENANT_ID='tenant', M365_CLIENT_ID='client', M365_CLIENT_SECRET='secret')
        self.assertEqual(soc.validate(config), [])


if __name__ == '__main__':
    unittest.main()
