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

    def test_crowdsec_watchlist_is_captured_with_budget_and_not_duplicated(self):
        self.config.update({"CROWDSEC_WATCHLIST_IPS": "9.9.9.9,8.8.8.8", "SOC_IOC_BUDGET": "1"})
        report = self.worker.build()
        self.assertEqual(report["findings"][0]["indicator"], "9.9.9.9")
        self.intel.assert_called_once_with("aggregate", "9.9.9.9", None)

    def test_cyfirma_matches_local_evidence_not_every_feed_item(self):
        self.config['SOC_IOC_BUDGET'] = '0'
        self.call.return_value = {'ok': True, 'data': {'items': [
            {'iocs':['8.8.8.8'], 'name':'test match'}, {'iocs':['9.9.9.9'], 'name':'external only'}], 'next_offset':None}}
        result = self.worker.build()
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['indicator'], '8.8.8.8')
        self.assertEqual(result['findings'][0]['status'], 'suspected')
        self.intel.assert_not_called()

    def test_cyfirma_partial_feed_rotates_and_matches_ledger_without_redownload(self):
        self.config.update(SOC_IOC_BUDGET='0', SOC_CYFIRMA_MAX_PAGES='1',
                           SOC_CYFIRMA_PAGE_SIZE='20')

        def feed_call(_source, _tool, request):
            if request['offset'] == 0:
                return {'ok': True, 'data': {'items': [{
                    'id': 'indicator--page-one', 'scope': request['scope'],
                    'name': 'first page', 'iocs': ['9.9.9.9'],
                }], 'feeds': {request['scope']: {'count': 40}}, 'next_offset': 20}}
            return {'ok': True, 'data': {'items': [{
                'id': 'indicator--page-two', 'scope': request['scope'],
                'name': 'later page', 'iocs': ['8.8.8.8'],
            }], 'feeds': {request['scope']: {'count': 40}}, 'next_offset': None}}

        self.call.side_effect = feed_call
        first = self.worker.build()
        self.assertEqual(first['findings'], [])
        self.assertEqual(self.worker._cyfirma_feed_offset('tailored'), 20)
        second = self.worker.build()
        self.assertEqual(second['findings'][0]['indicator'], '8.8.8.8')
        self.assertEqual(second['findings'][0]['status'], 'suspected')
        self.assertEqual(self.worker._cyfirma_feed_offset('tailored'), 0)
        self.intel.assert_not_called()

    def test_taxii_partial_sweep_uses_a_durable_cursor(self):
        self.config.update({
            "SOC_CYFIRMA_TAXII_ENABLED": "true",
            "SOC_CYFIRMA_TAXII_COLLECTION_URL": "https://api.cyfirma.com/taxii2/collections/abc/",
            "SOC_CYFIRMA_TAXII_BEARER_TOKEN": "token",
            "SOC_CYFIRMA_TAXII_MAX_PAGES": "1",
            "SOC_CYFIRMA_TAXII_INTERVAL_SECONDS": "900",
        })
        pages = [
            ([{"id": "indicator--first", "scope": "taxii", "type": "indicator", "name": "first", "iocs": ["8.8.8.8"], "valid_until": "2026-10-01T00:00:00Z"}],
             {"reported": 1, "more": True, "next_cursor": "next-token"}),
            ([{"id": "indicator--second", "scope": "taxii", "type": "indicator", "name": "second", "iocs": ["1.1.1.1"]}],
             {"reported": 1, "more": False, "next_cursor": ""}),
        ]
        with patch.object(soc.cyfirma_taxii, "fetch", side_effect=pages) as fetch:
            self.worker._refresh_external_collectors()
            self.assertEqual(fetch.call_args.kwargs["cursor"], "")
            self.assertEqual(self.worker._connector_cursor("taxii"), "next-token")
            with self.worker.db() as db:
                db.execute("DELETE FROM cache WHERE key='cyfirma_taxii:refresh'")
            self.worker._refresh_external_collectors()
        self.assertEqual(fetch.call_args.kwargs["cursor"], "next-token")
        self.assertEqual(self.worker._connector_cursor("taxii"), "")
        # Deployment verification runs in a separate Python process. It must
        # derive collector status from durable cursor/cache state, not memory.
        self.worker.external_collectors = {}
        with self.worker.db() as db:
            db.execute("DELETE FROM cache WHERE key='cyfirma_taxii:refresh'")
        status = self.worker.external_intelligence_status()["cyfirma_taxii"]
        self.assertEqual(status["cursor"]["status"], "loaded")
        self.assertEqual(status["status"], "loaded")
        self.assertEqual(status["collection"], "https://api.cyfirma.com/taxii2/collections/abc")
        self.assertEqual(status["freshness"]["earliest_valid_until"], "2026-10-01T00:00:00Z")

    def test_external_status_reports_stored_research_without_runtime_memory(self):
        with self.worker.db() as db:
            soc.cyfirma_research.store(db, [{
                "title": "Stored CYFIRMA research", "url": "https://www.cyfirma.com/research/example/",
            }])
        self.worker.external_collectors = {}
        status = self.worker.external_intelligence_status()["cyfirma_research"]
        self.assertEqual(status["items"], 1)
        self.assertEqual(status["status"], "stored")

    def test_lightweight_status_is_bounded_and_does_not_expand_detail_reads(self):
        with self.worker.db():
            pass
        status = self.worker.status(lightweight=True)
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["status_scope"], "bounded_runtime_snapshot")
        self.assertFalse(status["detail_available"])
        self.assertEqual(status["history"], [])
        external = self.worker.external_intelligence_status(lightweight=True)
        self.assertEqual(external["status"], "ok")
        self.assertEqual(external["status_scope"], "bounded_runtime_snapshot")
        self.assertFalse(external["detail_available"])
        self.assertEqual(external["cyfirma_research"]["items"], 0)

    def test_provider_policy_downranks_scanner_context_and_keeps_flow_direction(self):
        scanner = soc.provider_policy(
            {"indicator": "198.51.100.8", "level": 10},
            [{"provider": "greynoise", "detail": {"classification": "unknown", "noise": True}}], [],
            [{"source_ip": "198.51.100.8", "destination_ip": "10.0.0.8", "action": "deny"}],
        )
        self.assertEqual(scanner["status"], "scanner_context")
        self.assertTrue(scanner["flow"]["blocked"])
        self.assertEqual(scanner["flow"]["source_matches"], 1)
        corroborated = soc.provider_policy(
            {"indicator": "198.51.100.8", "level": 12},
            [{"provider": "otx", "is_malicious": True}, {"provider": "virustotal", "is_malicious": True}],
            [{"id": "indicator--1"}],
            [{"source_ip": "198.51.100.8", "action": "allow"}],
        )
        self.assertEqual(corroborated["status"], "suspected")
        self.assertEqual(corroborated["confidence"], "corroborated_local_evidence")
        self.assertTrue(corroborated["flow"]["allowed"])

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
        self.assertEqual(history['items'][0]['indicator_type'], 'indicator')
        self.assertEqual(history['timeline'][0]['doc_count'], 1)
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
            self.assertEqual(analyzed['audit']['skill_version'], soc.WINDOW_AI_SKILL_VERSION)
            self.assertEqual(len(analyzed['audit']['prompt_sha256']), 64)
            self.assertEqual(len(analyzed['audit']['input_sha256']), 64)
            self.assertNotIn('input', analyzed['audit'])
            payload = request.call_args.args[1]
            self.assertNotIn('tools', payload)
            self.assertIn('UNTRUSTED DATA', payload['messages'][0]['content'])
            self.assertIn(CONTRACT_VERSION, payload['messages'][0]['content'])

    def test_window_ai_rejects_narrative_as_completed_json(self):
        report = self.worker.build()
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        with patch.object(soc, 'post_chat', return_value={'choices': [{'finish_reason': 'stop',
                'message': {'content': 'The activity appears suspicious; investigate the source.'}}]}):
            with self.assertRaisesRegex(ValueError, 'malformed output'):
                soc.analyze_with_model(self.config, report)

    def test_window_ai_rejects_unknown_citations_and_marks_uncited_claims(self):
        context = {'rules': [{'rule_id': '5710'}], 'top_findings': [{'evidence': [
            {'event_id': 'event-1', 'rule_id': '5710'}]}]}
        parsed = {
            'summary': 'Review authentication activity', 'assessment': 'Evidence requires validation.',
            'verdict': {'status': 'suspicious', 'severity': 'high', 'confidence': 'high'},
            'attack_categories': [{'category': 'authentication', 'count': 4, 'evidence': ['event-1', 'fake-id']}],
            'network_paths': [{'source': '198.51.100.10', 'destination': '10.0.0.8', 'events': 4, 'evidence': ['5710']}],
            'identities': [{'user': 'admin', 'activity': 'failed login'}],
            'attack_narrative': [{'stage': 'Observed', 'detail': 'Repeated authentication failures', 'evidence': ['not-supplied']}],
            'action_plan': {'l1': [], 'l2': [], 'l3': [], 'response': []}, 'gaps': [],
        }
        result = soc.normalize_ai_result(parsed, {'limitations': []}, context)
        self.assertEqual(result['attack_categories'][0]['evidence'], ['event-1'])
        self.assertEqual(result['attack_categories'][0]['citation_status'], 'unverified')
        self.assertEqual(result['network_paths'][0]['citation_status'], 'verified_reference')
        self.assertEqual(result['network_paths'][0]['reference_validation'], 'ids_available_in_context')
        self.assertEqual(result['network_paths'][0]['semantic_support'], 'not_assessed')
        self.assertEqual(result['identities'][0]['citation_status'], 'unverified')
        self.assertEqual(result['attack_narrative'][0]['evidence'], [])
        self.assertEqual(result['verdict']['confidence'], 'low')
        self.assertEqual(result['verdict']['status'], 'needs_review')
        self.assertEqual(result['evidence_references'], ['5710', 'event-1'])

    def test_window_asset_and_provider_claims_require_matching_provenance(self):
        provider = soc._compact_provider_snapshot({
            'provider': 'OTX', 'status': 'ok', 'matched': 1, 'context': 2, 'errors': 0,
            'cves': [], 'tags': [],
        })
        context = {
            'rules': [], 'provider_coverage': [provider], 'vulnerability_focus': [],
            'top_findings': [{'evidence': [{
                'event_id': 'event-1', 'rule_id': '5710', 'device': 'web-01',
                'source_ip': '198.51.100.7', 'destination_ip': '10.0.0.8', 'user': 'analyst',
            }]}],
        }
        parsed = {
            'summary': 'Review the observed activity', 'assessment': 'Evidence needs review.',
            'verdict': {'status': 'suspicious', 'severity': 'high', 'confidence': 'high'},
            'affected_assets': [
                {'asset': 'web-01', 'role': 'reporter', 'evidence_ids': ['event-1']},
                {'asset': 'not-a-real-host', 'role': 'target', 'evidence_ids': ['event-1']},
            ],
            'provider_findings': [
                {'provider': 'OTX', 'verdict': 'match', 'evidence_ids': [provider['evidence_id']]},
                {'provider': 'UnknownProvider', 'verdict': 'match', 'evidence_ids': ['forged']},
            ],
            'action_plan': {'l1': [], 'l2': [], 'l3': [], 'response': []}, 'gaps': [],
        }
        result = soc.normalize_ai_result(parsed, {'limitations': []}, context)
        self.assertEqual(result['affected_assets'][0]['citation_status'], 'verified_reference')
        self.assertEqual(result['affected_assets'][0]['reference_validation'], 'entity_role_link_available')
        self.assertEqual(result['affected_assets'][0]['semantic_support'], 'not_assessed')
        self.assertEqual(result['affected_assets'][0]['role'], 'reporter')
        self.assertEqual(result['affected_assets'][1]['citation_status'], 'unverified')
        self.assertEqual(result['provider_findings'][0]['verdict'], 'match')
        self.assertEqual(result['provider_findings'][0]['signal'], 'Stored aggregate: 1 match(es), 2 context record(s), 0 error(s).')
        self.assertEqual(result['provider_findings'][0]['evidence_ids'], [provider['evidence_id']])
        self.assertEqual(result['provider_findings'][0]['reference_validation'], 'stored_provider_snapshot_match')
        self.assertEqual(result['provider_findings'][0]['semantic_support'], 'not_assessed')
        self.assertEqual(len(result['provider_findings']), 1)
        self.assertEqual(result['verdict']['confidence'], 'low')

    def test_deterministic_window_fallback_exposes_reference_vs_semantic_state(self):
        fallback = soc.local_ai_fallback({'intelligence_deck': {
            'top_findings': [{'indicator': '198.51.100.1', 'attack_category': 'bruteforce',
                'event_total': 1, 'risk_score': 30, 'evidence': [{'event_id': 'event-1', 'rule_id': '5710',
                    'source_ip': '198.51.100.1', 'destination_ip': '10.0.0.5', 'device': 'web-01'}]}],
            'vulnerability_focus': [{'cve': 'CVE-2024-1234', 'asset': 'web-01', 'severity': 'High',
                'package': 'nginx', 'version': '1.2.3', 'score': {}}],
            'provider_coverage': [{'provider': 'OTX', 'matched': 1, 'context': 0, 'errors': 0}],
        }}, 'model unavailable')['result']
        self.assertEqual(fallback['semantic_validation']['status'], 'analyst_review_required')
        self.assertEqual(fallback['attack_narrative'][0]['semantic_support'], 'not_assessed')
        self.assertEqual(fallback['provider_findings'][0]['reference_validation'], 'stored_provider_snapshot_match')
        self.assertEqual(fallback['cve_priorities'][0]['reference_validation'], 'vulnerability_inventory_snapshot_match')

    def test_finding_ai_audit_is_durable_and_cached_runs_do_not_duplicate(self):
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        finding = {'id': 'rule:5710', 'title': 'SSH authentication failures', 'rule': '5710',
                   'provider_results': [{'provider': 'OTX', 'status': 'matched', 'matched': 1, 'summary': 'IOC match'}]}
        self.worker.evidence.return_value = {'total': 1, 'events': [
            {'id': 'event-1', 'rule': {'id': '5710'}, 'agent': {'name': 'linux-01'}}]}
        model_result = {'status': 'completed', 'model': 'model', 'result': {'summary': 'Review evidence'}}
        with patch.object(soc, 'analyze_finding_with_model', return_value=model_result):
            first = self.worker.analyze_finding(finding)
            second = self.worker.analyze_finding(finding)
        audit = first['audit']
        self.assertEqual(audit['scope'], 'finding')
        self.assertEqual(audit['skill_version'], soc.FINDING_SKILL_VERSION)
        self.assertIn('event-1', audit['evidence_ids'])
        self.assertTrue(any(ref.startswith('finding-provider:') for ref in audit['evidence_ids']))
        self.assertEqual(len(audit['input_sha256']), 64)
        trusted = self.worker.finding_ai_advisory('rule:5710', audit['run_id'])
        self.assertEqual(trusted['audit']['run_id'], audit['run_id'])
        self.assertIn('event-1', trusted['audit']['evidence_ids'])
        self.assertIsNone(self.worker.finding_ai_advisory('rule:5710', 'forged-run'))
        self.assertEqual(second['cache']['status'], 'hit')
        self.worker.evidence.reset_mock()
        history = self.worker.finding_analysis_history('rule:5710')
        self.worker.evidence.assert_not_called()
        self.assertEqual(len(history['items']), 1)
        self.assertEqual(history['items'][0]['run_id'], audit['run_id'])
        self.assertEqual(history['items'][0]['result_sha256'], audit['result_sha256'])
        self.assertNotIn('raw', history['items'][0])

    def test_finding_ai_citations_are_validated_against_supplied_evidence(self):
        context = {'id': 'finding-1', 'local_evidence': [{'event_id': 'event-1', 'rule': {'id': '5710'}}]}
        result = soc.normalize_finding_ai_result({
            'summary': 'Review login failures',
            'verdict': {'status': 'suspicious', 'severity': 'high', 'confidence': 'high'},
            'source_facts': [
                {'fact': 'Repeated failures were observed.', 'evidence_ids': ['event-1']},
                {'fact': 'An unknown event was observed.', 'evidence_ids': ['invented-event']},
                'Legacy uncited claim',
            ],
            'inference': 'Could indicate credential guessing.', 'actions': {}, 'gaps': [],
        }, context)
        self.assertEqual(result['source_facts'], ['Repeated failures were observed.'])
        self.assertEqual(result['source_fact_citations'], [{'fact': 'Repeated failures were observed.',
            'evidence_ids': ['event-1'], 'reference_validation': 'ids_available_in_context',
            'semantic_support': 'not_assessed'}])
        self.assertEqual(result['unverified_source_facts'], ['An unknown event was observed.', 'Legacy uncited claim'])

    def test_finding_assets_and_provider_consensus_are_source_bound(self):
        context = soc._finding_provenance_context({
            'id': 'finding-entity-test',
            'local_evidence': [{'event_id': 'event-1', 'rule': {'id': '5710'},
                                'device': 'linux-01', 'source_ip': '198.51.100.5'}],
            'provider_results': [{'provider': 'OTX', 'status': 'matched', 'matched': 1,
                                  'summary': 'Stored match'}],
            'asset_context': [{'asset': 'db-01', 'owner': 'payments', 'criticality': 'critical',
                               'network_zone': 'restricted', 'cpe': 'cpe:2.3:a:vendor:db:1.0:*:*:*:*:*:*:*'}],
        })
        provider_id = context['provider_evidence'][0]['evidence_id']
        result = soc.normalize_finding_ai_result({
            'summary': 'Review local evidence',
            'verdict': {'status': 'suspicious', 'severity': 'high', 'confidence': 'high'},
            'source_facts': [{'fact': 'The event is present.', 'evidence_ids': ['event-1']}],
            'affected_assets': [{'asset': 'linux-01', 'role': 'target', 'evidence_ids': ['event-1']}],
            'provider_consensus': [{'provider': 'OTX', 'status': 'matched', 'evidence_ids': [provider_id]}],
            'inference': 'Review required', 'actions': {}, 'gaps': [],
        }, context)
        self.assertEqual(result['affected_assets'][0]['role'], 'reporter')
        self.assertEqual(result['affected_assets'][0]['impact_status'], 'not_established')
        self.assertEqual(result['affected_assets'][0]['reference_validation'], 'entity_role_link_available')
        self.assertEqual(result['affected_assets'][0]['semantic_support'], 'not_assessed')
        cmdb_asset = next(asset for asset in result['affected_assets'] if asset['asset'] == 'db-01')
        self.assertEqual(cmdb_asset['impact_status'], 'inventory_context_only')
        self.assertEqual(cmdb_asset['owner'], 'payments')
        self.assertTrue(any(ref.startswith('cmdb-asset:') for ref in cmdb_asset['evidence_ids']))
        self.assertEqual(result['provider_consensus'][0]['evidence_ids'], [provider_id])
        self.assertTrue(result['provider_consensus'][0]['not_local_activity_proof'])
        self.assertEqual(result['provider_consensus'][0]['reference_validation'], 'stored_provider_snapshot_match')
        self.assertEqual(result['provider_consensus'][0]['semantic_support'], 'not_assessed')
        self.assertEqual(result['verdict']['confidence'], 'low')
        self.assertTrue(any('role did not match' in gap for gap in result['gaps']))
        self.assertEqual(result['evidence_references'], ['event-1'])
        self.assertEqual(result['verdict']['confidence'], 'low')
        self.assertEqual(result['verdict']['status'], 'needs_review')
        self.assertTrue(any('role did not match' in item for item in result['gaps']))

    def test_finding_ai_truncated_output_is_rejected_for_local_fallback(self):
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        with patch.object(soc, 'post_chat', return_value={'choices': [{'finish_reason': 'length',
                'message': {'content': '{"summary":"partial"}'}}]}):
            with self.assertRaisesRegex(ValueError, 'truncated'):
                soc.analyze_finding_with_model(self.config, {'id': 'finding-1'})

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
            self.assertEqual(self.worker.status()['latest']['ai']['audit']['scope'], 'window')
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

    def test_finding_ai_uses_bounded_local_entity_timeline_with_citable_provenance(self):
        self.config.update(AI_ANALYST_ENABLED='true', AI_PROVIDER_BASE_URL='http://model/v1', AI_MODEL='model')
        finding = {'id': 'ip:198.51.100.25', 'title': 'Network alert', 'category': 'ip',
                   'indicator': '198.51.100.25', 'range': '7d'}
        self.worker.evidence.return_value = {'total': 0, 'events': []}
        related = {'status': 'available', 'source': 'local durable entity graph', 'truncated': False,
                   'interpretation': 'Chronological sequence; co-observation does not establish causality.',
                   'events': [{'evidence_id': 'graph-evidence-1', 'source': 'defender_xdr',
                               'source_record_id': 'dx-1', 'timestamp': '2026-09-24T10:00:00+00:00',
                               'title': 'Risky sign-in', 'attack_techniques': [{'id': 'T1078'}],
                               'matched_entities': [{'type': 'ip', 'value': '198.51.100.25'}]}]}
        model_result = {'status': 'completed', 'model': 'model', 'result': {'summary': 'Review related identity activity'}}
        with patch.object(self.worker, 'entity_timeline', return_value=related) as timeline, \
             patch.object(soc, 'analyze_finding_with_model', return_value=model_result) as model:
            result = self.worker.analyze_finding(finding)
        self.assertEqual(timeline.call_args.args[0], [{'entity_type': 'ip', 'entity_value': '198.51.100.25'}])
        self.assertEqual(timeline.call_args.kwargs['limit'], 10)
        context = model.call_args.args[1]
        self.assertEqual(context['related_evidence']['events'][0]['evidence_id'], 'graph-evidence-1')
        self.assertIn('graph-evidence-1', result['audit']['evidence_ids'])
        self.assertEqual(result['related_evidence']['source'], 'local durable entity graph')
        self.assertIn('does not establish causality', result['related_evidence']['interpretation'])

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
        self.assertEqual(rows[0]['top_destinations'][0]['count'], 1)
        self.assertEqual(rows[0]['top_identities'][0]['value'], 'admin')
        self.assertEqual(rows[0]['top_identities'][0]['count'], 1)
        stale_summary = dict(rows[0], aggregation_version=1,
            top_destinations=[{'value': '10.0.0.8', 'count': 20}],
            top_identities=[{'value': 'admin', 'count': 20}])
        with self.worker.db() as db:
            db.execute('UPDATE report_summaries SET data=? WHERE report_id=7',
                       (__import__('json').dumps(stale_summary),))
        refreshed = self.worker._summary_rows(created - 1, created + 1)[0]
        self.assertEqual(refreshed['aggregation_version'], 2)
        self.assertEqual(refreshed['top_destinations'][0]['count'], 1)
        self.assertEqual(refreshed['top_identities'][0]['count'], 1)
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

    def test_finding_ai_watchdog_survives_database_lock_and_recovers(self):
        calls = []

        def locked_once():
            calls.append(True)
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            return 0

        with patch.object(self.worker, "expire_stale_finding_jobs", side_effect=locked_once):
            self.assertIsNone(self.worker._finding_ai_watchdog_cycle())
            self.assertEqual(self.worker.finding_ai_watchdog_state["status"], "degraded")
            self.assertEqual(self.worker.finding_ai_watchdog_state["lock_events"], 1)
            self.assertEqual(self.worker._finding_ai_watchdog_cycle(), 0)
        self.assertEqual(self.worker.finding_ai_watchdog_state["status"], "ok")
        self.assertIsNone(self.worker.finding_ai_watchdog_state["last_error"])
        self.assertEqual(self.worker.finding_analysis_jobs()["watchdog"]["status"], "ok")

    def test_external_collector_lock_is_degraded_and_recovers(self):
        self.config.update({
            "SOC_CYFIRMA_RESEARCH_ENABLED": "false",
            "SOC_CYFIRMA_TAXII_ENABLED": "false",
            "SOC_CYFIRMA_ORG_VULN_ENABLED": "false",
            "DEFENDER_XDR_ENABLED": "true",
        })
        locked = sqlite3.OperationalError("database is locked")
        with patch.object(soc.defender_xdr, "collect", side_effect=locked):
            self.worker._refresh_external_collectors()
        failed = self.worker.external_collectors["defender_xdr"]
        self.assertEqual(failed["status"], "degraded")
        self.assertTrue(failed["retryable"])
        self.assertIn("database is locked", failed["reason"])

        with patch.object(soc.defender_xdr, "collect", return_value={"status": "ok", "observations": 4}):
            self.worker._refresh_external_collectors_safely()
        self.assertEqual(self.worker.external_collectors["defender_xdr"]["status"], "ok")

    def test_external_collector_unexpected_error_does_not_escape_scheduler_boundary(self):
        self.config.update({
            "SOC_CYFIRMA_RESEARCH_ENABLED": "false",
            "SOC_CYFIRMA_TAXII_ENABLED": "false",
            "SOC_CYFIRMA_ORG_VULN_ENABLED": "false",
        })
        with patch.object(self.worker, "_refresh_external_collectors", side_effect=RuntimeError("collector failure")):
            self.worker._refresh_external_collectors_safely()
        failed = self.worker.external_collectors["defender_xdr"]
        self.assertEqual(failed["status"], "error")
        self.assertFalse(failed["retryable"])
        self.assertIn("collector failure", failed["reason"])

    def test_schema_initialization_retries_transient_database_lock(self):
        calls = []
        original = self.worker._initialize_schema

        def flaky(connection):
            if not calls:
                calls.append(True)
                raise sqlite3.OperationalError("database is locked")
            return original(connection)

        with patch.object(self.worker, "_initialize_schema", side_effect=flaky):
            with self.worker.db() as db:
                self.assertEqual(db.execute("SELECT 1").fetchone()[0], 1)
        self.assertTrue(self.worker.db_initialized)
        self.assertEqual(len(calls), 1)

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
