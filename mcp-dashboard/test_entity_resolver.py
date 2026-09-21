import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

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
