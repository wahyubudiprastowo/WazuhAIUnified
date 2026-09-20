import unittest
from unittest.mock import Mock
from soc_analysis import coverage, explain_rule, IOC_FIELDS, vulnerability_inventory


class RuleTests(unittest.TestCase):
    def test_allowed_traffic_is_not_an_attack(self):
        result = explain_rule({"description": "Fortigate: App passed by firewall.", "groups": ["fortigate"]})
        self.assertEqual(result["title"], "Koneksi diizinkan oleh firewall")
        self.assertIn("bukan bukti serangan", result["meaning"])
        self.assertEqual(result["cves"], [])

    def test_mail_access_is_audit(self):
        result = explain_rule({"description": "Office 365: MailItemsAccessed", "groups": ["office365"]})
        self.assertEqual(result["status"], "Audit akses email")

    def test_failed_database_authentication(self):
        result = explain_rule({"description": "MS SQL server logon failure", "groups": []})
        self.assertEqual(result["title"], "Percobaan autentikasi gagal")

    def test_queue_health_not_attack(self):
        result = explain_rule({"description": "Agent event queue is full. Events may be lost."})
        self.assertEqual(result["status"], "Risiko kehilangan telemetri")

    def test_suspicious_cloud_activity_not_generic_audit(self):
        result = explain_rule({"description": "Office 365: Suspicious download activity by user", "groups": ["office365"]})
        self.assertEqual(result["status"], "Anomali akses data")

    def test_remote_login_not_confirmed_compromise(self):
        result = explain_rule({"description": "Successful Remote Logon Detected - ANONYMOUS LOGON/NTLM possible pass-the-hash"})
        self.assertIn("belum membuktikan", result["meaning"])

    def test_cve_only_when_explicit(self):
        self.assertEqual(explain_rule({"description": "SQL injection"})["cves"], [])
        self.assertEqual(explain_rule({"description": "Exploit CVE-2024-6387 detected"})["cves"], ["CVE-2024-6387"])

    def test_unknown_rule_keeps_original(self):
        result = explain_rule({"description": "Unclassified product event", "groups": "custom"})
        self.assertEqual(result["basis"], "fallback")
        self.assertEqual(result["original"], "Unclassified product event")


class CoverageTests(unittest.TestCase):
    def test_inventory_uses_current_state_index(self):
        search = Mock(return_value={"hits": {"total": {"value": 1}, "hits": [{"_id": "a", "_source": {"agent": {"name": "host"}, "vulnerability": {"id": "CVE-2024-6387"}}}]}})
        result = vulnerability_inventory(search, {"severity": "Critical", "search": "CVE-2024-6387"})
        query, index = search.call_args.args
        self.assertEqual(index, "wazuh-states-vulnerabilities-*")
        self.assertNotIn("@timestamp", str(query))
        self.assertEqual(result["items"][0]["agent"]["name"], "host")
        self.assertEqual(query["size"], 25)

    def test_inventory_validation(self):
        for payload in [{"severity": "bad"}, {"offset": -1}, {"offset": 10000}, {"limit": 0},
                        {"limit": 101}, {"search": "x" * 151}]:
            with self.assertRaises(ValueError):
                vulnerability_inventory(Mock(), payload)

    def test_inventory_limit_is_bounded_and_explicit(self):
        search = Mock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
        result = vulnerability_inventory(search, {"limit": 100})
        self.assertEqual(search.call_args.args[0]["size"], 100)
        self.assertEqual(result["limit"], 100)

    def test_inventory_can_skip_expensive_summary_aggregations(self):
        search = Mock(return_value={"hits": {"total": {"value": 3}, "hits": []}})
        result = vulnerability_inventory(search, {"limit": 100, "include_summary": False})
        self.assertNotIn("aggs", search.call_args.args[0])
        self.assertEqual(result["inventory_total"], 3)

    def test_full_count_and_bounded_candidates_are_distinct(self):
        bucket = {"key": "8.8.8.8", "doc_count": 7, "max_level": {"value": 5}, "rules": {"buckets": [{"key": "81633"}]}}
        search = Mock(return_value={"hits": {"total": {"value": 12000, "relation": "eq"}}, "aggregations": {
            "with_observable": {"doc_count": 9000}, "source_ip": {"buckets": [bucket]},
            "m365_ip": {"buckets": [dict(bucket, doc_count=2)]}, "rules": {"buckets": [], "sum_other_doc_count": 20}}})
        result = coverage(search, "24h")
        self.assertTrue(result["ok"])
        self.assertEqual(result["total_events"], 12000)
        self.assertEqual(result["events_with_observable"], 9000)
        self.assertEqual(len(result["observables"]), 1)
        self.assertEqual(result["observables"][0]["occurrences"], 9)
        self.assertEqual(len(result["observables"][0]["fields"]), 2)
        self.assertEqual(result["other_rule_events"], 20)
        self.assertEqual(result["fields_checked"], list(IOC_FIELDS.values()))
        self.assertTrue(search.call_args.args[0]["track_total_hits"])
        self.assertEqual(search.call_args.args[0]["size"], 0)

    def test_priority_rules_and_decoder_coverage_are_merged_without_duplicates(self):
        common = {"key": "1001", "doc_count": 500, "event": {"hits": {"hits": [{"_source": {
            "rule": {"id": "1001", "level": 5, "description": "Frequent event"}, "agent": {"name": "host-a"},
            "decoder": {"name": "json"}, "@timestamp": "2026-09-15T01:00:00Z"}}]}}}
        priority = {"key": "9001", "doc_count": 2, "event": {"hits": {"hits": [{"_source": {
            "rule": {"id": "9001", "level": 14, "description": "Rare critical event"}, "agent": {"name": "fortigate"},
            "decoder": {"name": "fortigate"}, "location": "syslog", "@timestamp": "2026-09-15T02:00:00Z"}}]}}}
        decoder = {"key": "fortigate", "doc_count": 2000, "max_level": {"value": 14}, "event": priority["event"]}
        search = Mock(return_value={"hits": {"total": {"value": 2500}}, "aggregations": {
            "rules": {"buckets": [common], "sum_other_doc_count": 0},
            "priority_rules": {"rules": {"buckets": [priority, common]}}, "sources": {"buckets": [decoder]}}})
        result = coverage(search, "24h")
        self.assertEqual({row["rule_id"] for row in result["rules"]}, {"1001", "9001"})
        self.assertEqual(result["rule_candidates"]["unique"], 2)
        self.assertEqual(result["decoders"][0]["name"], "fortigate")
        self.assertEqual(result["decoders"][0]["latest_rule_id"], "9001")
        query = search.call_args.args[0]
        self.assertEqual(query["aggs"]["sources"]["terms"]["size"], 100)
        self.assertEqual(query["aggs"]["priority_rules"]["filter"]["range"]["rule.level"]["gte"], 10)

    def test_enhanced_coverage_failure_preserves_legacy_data(self):
        legacy = {"hits": {"total": {"value": 42}}, "aggregations": {
            "rules": {"buckets": [], "sum_other_doc_count": 0},
            "sources": {"buckets": [{"key": "fortigate", "doc_count": 40}]},
            "with_observable": {"doc_count": 4}}}
        search = Mock(side_effect=[RuntimeError("unsupported aggregation"), legacy])

        result = coverage(search, "24h")

        self.assertTrue(result["ok"])
        self.assertEqual(result["total_events"], 42)
        self.assertEqual(result["coverage_mode"], "legacy_fallback")
        self.assertIn("legacy coverage", result["coverage_warning"])
        self.assertEqual(result["decoders"][0]["name"], "fortigate")
        self.assertEqual(search.call_count, 2)
        fallback_query = search.call_args.args[0]
        self.assertNotIn("priority_rules", fallback_query["aggs"])
        self.assertEqual(fallback_query["aggs"]["sources"]["terms"]["size"], 10)

    def test_private_ip_not_eligible(self):
        search = Mock(return_value={"aggregations": {"source_ip": {"buckets": [{"key": "10.0.0.1", "doc_count": 1}]}}})
        self.assertFalse(coverage(search, "1h")["observables"][0]["public"])

    def test_local_url_paths_remain_evidence_not_external_candidates(self):
        for value in ['/', '/.env', 'https://10.0.0.1/a', 'https://host.internal/a',
                      'https://example.com/?token=secret', 'https://[broken']:
            search = Mock(return_value={'aggregations': {'url': {'buckets': [{'key': value, 'doc_count': 1}]}}})
            row = coverage(search, '24h')['observables'][0]
            self.assertEqual(row['indicator'], value)
            self.assertFalse(row['public'], value)

    def test_partial_index_result_not_complete(self):
        for response in [{"timed_out": True}, {"_shards": {"failed": 1}}]:
            self.assertFalse(coverage(Mock(return_value=response), "1h")["ok"])


if __name__ == "__main__":
    unittest.main()
