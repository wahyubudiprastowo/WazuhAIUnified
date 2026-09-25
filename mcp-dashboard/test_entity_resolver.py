import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent))

import defender_xdr
import entity_resolver


class EntityResolverTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        entity_resolver.ensure_schema(self.db)

    def tearDown(self):
        self.db.close()

    def test_canonical_types_and_url_secret_are_normalized(self):
        document = {
            "alerts": [{"evidence": [
                {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "::ffff:203.0.113.9"},
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "HOST-01.Example.COM.",
                 "mdeDeviceId": "ABC-123"},
                {"@odata.type": "#microsoft.graph.security.userEvidence",
                 "userAccount": {"userPrincipalName": "Analyst@Example.COM"}},
                {"@odata.type": "#microsoft.graph.security.urlEvidence",
                 "url": "HTTPS://Portal.Example.COM/login?token=very-secret"},
                {"@odata.type": "#microsoft.graph.security.fileEvidence",
                 "fileDetails": {"sha256": "A" * 64}},
                {"azureResourceId": "/subscriptions/ABC/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1"},
            ]}],
            "description": "Affected CVE-2026-12345", "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "packageName": "OpenSSL", "packageVersion": "3.0.1",
        }
        rows = entity_resolver.extract_entities(document)
        values = {(row["type"], row["value"]) for row in rows}
        self.assertIn(("ip", "203.0.113.9"), values)
        self.assertIn(("hostname", "host-01.example.com"), values)
        self.assertIn(("hostname_alias", "host-01"), values)
        self.assertIn(("user", "analyst@example.com"), values)
        self.assertIn(("hash", "sha256:" + "a" * 64), values)
        self.assertIn(("cve", "CVE-2026-12345"), values)
        self.assertIn(("package", "openssl@3.0.1"), values)
        url = next(value for kind, value in values if kind == "url")
        self.assertIn("?q=", url)
        self.assertNotIn("very-secret", url)

    def test_relation_keeps_provenance_time_source_and_confidence(self):
        prepared = entity_resolver.prepare_evidence(
            "defender_xdr", "incident-1", "2026-09-23T10:00:00Z",
            {"ipAddress": "203.0.113.10", "userPrincipalName": "analyst@example.test"},
            "Suspicious sign-in", "high", 92,
        )
        result = entity_resolver.ingest_prepared(self.db, [prepared])
        row = self.db.execute('''SELECT evidence_id,observed_at,source,confidence
            FROM entity_relations LIMIT 1''').fetchone()
        self.assertEqual(result["evidence"], 1)
        self.assertEqual(row[0], prepared["evidence_id"])
        self.assertEqual(row[2], "defender_xdr")
        self.assertGreater(row[1], 0)
        self.assertGreaterEqual(row[3], 1)

    def test_graph_queue_schema_migrates_existing_batch_rows_without_loss(self):
        self.db.execute("DROP TABLE entity_graph_queue")
        self.db.execute("DROP TABLE entity_graph_batches")
        self.db.execute('''CREATE TABLE entity_graph_batches (
            batch_key TEXT PRIMARY KEY,candidate_count INTEGER NOT NULL,
            stored_count INTEGER NOT NULL,dropped_count INTEGER NOT NULL,committed_at REAL NOT NULL)''')
        self.db.execute("INSERT INTO entity_graph_batches VALUES ('legacy',4,3,1,100)")
        entity_resolver.ensure_schema(self.db)
        status = entity_resolver.status(self.db)
        self.assertEqual(status["latest_batch"]["candidates"], 4)
        self.assertEqual(status["latest_batch"]["queued"], 0)
        self.assertEqual(status["batch_history"]["dropped"], 1)
        self.assertEqual(status["batch_history"]["batches"], 1)
        self.assertEqual(status["queue"]["pending"], 0)

    def test_wazuh_nested_asset_and_network_flow_are_preserved(self):
        prepared = entity_resolver.prepare_wazuh_evidence({
            "@timestamp": "2026-09-23T10:00:00Z",
            "rule": {"id": "9001", "level": 12, "description": "Blocked connection"},
            "agent": {"id": "001", "name": "EDGE-FW", "ip": "10.0.0.5"},
            "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.8"},
        }, "event-1", "wazuh-alerts-4.x")
        entity_resolver.ingest_prepared(self.db, [prepared])
        values = {(row[0], row[1]) for row in self.db.execute(
            "SELECT entity_type,canonical_value FROM entity_nodes").fetchall()}
        self.assertIn(("device", "001"), values)
        self.assertIn(("hostname", "edge-fw"), values)
        self.assertIn(("ip", "203.0.113.10"), values)
        relation = self.db.execute(
            "SELECT relation_type FROM entity_relations WHERE relation_type='communicates_with'").fetchone()
        self.assertEqual(relation, ("communicates_with",))

    def test_weak_cve_and_package_overlap_cannot_merge_incidents(self):
        local = entity_resolver.prepare_evidence(
            "wazuh", "local-1", "2026-09-23T10:00:00Z",
            {"cve": "CVE-2026-12345", "packageName": "openssl", "packageVersion": "3.0.1"})
        defender = entity_resolver.prepare_evidence(
            "defender_xdr", "defender-1", "2026-09-23T10:01:00Z",
            {"cve": "CVE-2026-12345", "packageName": "openssl", "packageVersion": "3.0.1"})
        entity_resolver.ingest_prepared(self.db, [local, defender])
        match = entity_resolver.correlate_evidence(
            self.db, defender, "incident-1", "Vulnerability reference", "medium", "active")
        self.assertIsNone(match)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_clusters").fetchone()[0], 0)

    def test_defender_matches_durable_local_graph_and_is_idempotent(self):
        local = entity_resolver.prepare_evidence(
            "wazuh", "event-1", "2026-09-23T10:00:00Z",
            {"srcip": "203.0.113.10", "userPrincipalName": "ANALYST@EXAMPLE.TEST",
             "deviceDnsName": "HOST-01"}, "Wazuh alert", "12", 90)
        defender = entity_resolver.prepare_evidence(
            "defender_xdr", "record-1", "2026-09-23T10:02:00Z",
            {"ipAddress": "203.0.113.10", "userPrincipalName": "analyst@example.test",
             "deviceDnsName": "host-01"}, "Defender incident", "high", 90)
        entity_resolver.ingest_prepared(self.db, [local, defender, local, defender])
        first = entity_resolver.correlate_evidence(
            self.db, defender, "incident-1", "Defender incident", "high", "active")
        second = entity_resolver.correlate_evidence(
            self.db, defender, "incident-1", "Defender incident", "high", "active")
        self.assertEqual(first["cluster_id"], second["cluster_id"])
        self.assertEqual(first["confidence"], "confirmed_by_multi_source")
        self.assertEqual(first["matches"]["identity"], ["analyst@example.test"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_clusters").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_evidence").fetchone()[0], 2)

    def test_cross_source_candidates_keep_provenance_and_never_claim_confirmation(self):
        now = time.time()
        wazuh = entity_resolver.prepare_evidence(
            "wazuh", "wz-1", now,
            {"userPrincipalName": "analyst@example.test", "srcip": "198.51.100.11"},
            "Repeated sign-in failure", "12", 80)
        m365 = entity_resolver.prepare_evidence(
            "m365", "m365-1", now + 90,
            {"userPrincipalName": "ANALYST@example.test", "clientIp": "198.51.100.11"},
            "Risky sign-in", "high", 80)
        entity_resolver.ingest_prepared(self.db, [wazuh, m365])

        result = entity_resolver.materialize_correlation_candidates(self.db)
        candidates = entity_resolver.correlation_candidates(self.db)
        self.assertGreaterEqual(result["candidates"], 1)
        candidate = next(row for row in candidates["items"] if row["primary_entity"]["type"] == "user")
        self.assertEqual(candidate["classification"], "candidate")
        self.assertFalse(candidate["confirmed"])
        self.assertEqual(set(candidate["sources"]), {"wazuh", "m365"})
        self.assertEqual({row["evidence_id"] for row in candidate["evidence"]},
                         {wazuh["evidence_id"], m365["evidence_id"]})
        self.assertTrue(all(row["source_record_id"] for row in candidate["evidence"]))

    def test_candidate_status_distinguishes_not_run_from_completed_empty_run(self):
        before = entity_resolver.correlation_candidates(self.db)
        self.assertEqual(before["status"], "materializing")
        self.assertIsNone(before["last_materialized_at"])

        entity_resolver.materialize_correlation_candidates(self.db)
        after = entity_resolver.correlation_candidates(self.db)
        self.assertEqual(after["status"], "no_candidates")
        self.assertIsNotNone(after["last_materialized_at"])
        self.assertEqual(after["observations_considered"], 0)

        historical = entity_resolver.correlation_candidates(self.db, start=time.time() - 48 * 3600)
        self.assertEqual(historical["status"], "partial")
        self.assertFalse(historical["range_covered"])

    def test_entity_timeline_is_chronological_and_only_shows_explicit_attack_mapping(self):
        first = entity_resolver.prepare_wazuh_evidence({
            "@timestamp": "2026-09-24T10:00:00Z",
            "rule": {"id": "9101", "level": 12, "description": "Suspicious process",
                     "mitre": {"id": ["T1059.001"], "tactic": ["Execution"],
                               "technique": ["PowerShell"]}},
            "decoder": {"name": "windows_eventchannel"},
            "agent": {"id": "007", "name": "HOST-7"},
            "data": {"srcip": "198.51.100.20", "user": "analyst@example.test"},
        }, "wz-event-1", "wazuh-alerts-4.x")
        second = entity_resolver.prepare_evidence(
            "defender_xdr", "dx-event-2", "2026-09-24T10:05:00Z",
            {"userPrincipalName": "analyst@example.test", "title": "Risky sign-in"},
            "Risky sign-in", "high", 85)
        entity_resolver.ingest_prepared(self.db, [first, second])

        result = entity_resolver.entity_timeline(
            self.db, [{"entity_type": "user", "entity_value": "analyst@example.test"}],
            entity_resolver._epoch("2026-09-24T09:00:00Z"),
            entity_resolver._epoch("2026-09-24T11:00:00Z"), 20)
        self.assertEqual(result["status"], "available")
        self.assertEqual([event["source"] for event in result["events"]], ["wazuh", "defender_xdr"])
        mapped, unmapped = result["events"]
        self.assertEqual(mapped["attack_techniques"][0]["id"], "T1059.001")
        self.assertEqual(mapped["attack_techniques"][0]["mapping_source"], "wazuh_rule.mitre")
        self.assertEqual(unmapped["attack_mapping_status"], "not_mapped_in_source_evidence")
        self.assertEqual(mapped["matched_entities"], [{"type": "user", "value": "analyst@example.test"}])
        self.assertTrue(mapped["source_record_id"])
        self.assertIn("does not establish causality", result["interpretation"])

    def test_same_source_two_events_and_weak_shared_cve_do_not_make_candidates(self):
        now = time.time()
        one = entity_resolver.prepare_evidence(
            "wazuh", "wz-one", now, {"cve": "CVE-2026-12345", "srcip": "198.51.100.12"})
        two = entity_resolver.prepare_evidence(
            "wazuh", "wz-two", now + 60, {"cve": "CVE-2026-12345", "srcip": "198.51.100.12"})
        entity_resolver.ingest_prepared(self.db, [one, two])
        entity_resolver.materialize_correlation_candidates(self.db)
        groups = entity_resolver.correlation_candidates(self.db)
        self.assertFalse(groups["items"])

    def test_recent_defender_updates_are_one_incident_card(self):
        defender_xdr.ensure_schema(self.db)
        for index, observed in enumerate((100.0, 200.0)):
            raw = {"id": "incident-1", "lastUpdateDateTime": f"2026-09-23T10:0{index}:00Z",
                   "alerts": [{"evidence": [{"ipAddress": "203.0.113.10"}]}]}
            self.db.execute('''INSERT INTO defender_xdr_observations
                (item_key,observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (f"item-{index}", observed, observed, "alert-1", "incident-1", "high", "active",
                 "malware", "Same incident", json.dumps(raw)))
        result = defender_xdr.status(self.db)
        self.assertEqual(len(result["recent"]), 1)
        self.assertEqual(result["recent"][0]["incident_id"], "incident-1")
        self.assertTrue(result["recent"][0]["cluster_id"].startswith("cluster-"))

    def test_retention_cleanup_respects_foreign_keys(self):
        prepared = entity_resolver.prepare_evidence(
            "wazuh", "old-event", 1.0,
            {"srcip": "203.0.113.10", "dstip": "10.0.0.8"}, "Old evidence", "10", 80)
        entity_resolver.ingest_prepared(self.db, [prepared])
        result = entity_resolver.cleanup(self.db, 7)
        self.assertEqual(result["evidence"], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_evidence").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_nodes").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
