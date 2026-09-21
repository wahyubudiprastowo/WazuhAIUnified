import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

import cyfirma_research
import cyfirma_taxii
import cyfirma_org_vulnerability
import defender_xdr
from detection_taxonomy import classify, consensus_confidence, telemetry_fields, telemetry_source
from soc_pipeline import Pipeline, rollup_dimensions
from telemetry_contract import summary


class DetectionImprovementTests(unittest.TestCase):
    @staticmethod
    def _pipeline(path):
        class Automation:
            def __init__(self, db_path):
                self.db_path = db_path

            @contextmanager
            def db(self):
                db = sqlite3.connect(self.db_path)
                try:
                    yield db
                    db.commit()
                finally:
                    db.close()

            @staticmethod
            def config():
                return {"SOC_STREAM_ENABLED": "true", "SOC_ROLLUP_ENABLED": "true"}

            @staticmethod
            def clean_error(error):
                return str(error)

        return Pipeline(Automation(path), lambda *_args, **_kwargs: {})

    def test_sqli_requires_web_evidence_and_remains_an_attempt(self):
        result = classify({"rule": {"id": "1", "description": "SQL injection blocked"},
                           "data": {"srcip": "198.51.100.8", "dstip": "10.0.0.4",
                                    "url": "/search?q=union", "action": "deny"}})
        self.assertEqual(result["family"], "web_attack.sqli")
        self.assertEqual(result["confidence"], "evidence_complete")
        self.assertEqual(result["assertion"], "attempt_or_signal")

    def test_rollup_stores_compact_detection_labels(self):
        event = {"rule": {"id": "2", "description": "Nmap port scan"},
                 "decoder": {"name": "fortigate"},
                 "data": {"srcip": "198.51.100.9", "dstip": "10.0.0.2", "dstport": "22", "action": "deny"}}
        rows = rollup_dimensions(event)
        self.assertIn(("detection_family", "scan", "scan"), rows)
        self.assertIn(("telemetry_source", "fortigate", "fortigate"), rows)
        self.assertIn(("mitre", "T1595", "T1595"), rows)
        self.assertEqual(telemetry_source(event), "fortigate")
        self.assertEqual(telemetry_fields(event)[0], "fortigate")

    def test_ndr_consensus_requires_local_evidence_and_provider_context(self):
        event = {"rule": {"id": "3", "description": "Periodic C2 beaconing"},
                 "decoder": {"name": "zeek"},
                 "data": {"srcip": "198.51.100.10", "dstip": "10.0.0.9",
                          "dstport": "443", "action": "allow"}}
        result = consensus_confidence(event, provider_matches=1)
        self.assertEqual(result["family"], "beaconing")
        self.assertEqual(result["confidence"], "confirmed_by_multi_source")
        self.assertIn("T1071", result["mitre"])

    def test_existing_rule_rollups_are_classified_without_indexer_access(self):
        with tempfile.TemporaryDirectory() as directory:
            pipeline = self._pipeline(Path(directory) / "state.db")
            with pipeline.automation.db() as db:
                db.executemany('''INSERT INTO detection_rollups
                    (bucket,dimension,value,count,max_level,last_seen,label) VALUES (?,?,?,?,?,?,?)''', [
                    ("2026-09-21T00:00:00+00:00", "total", "all", 8, 12, "2026-09-21T00:04:00+00:00", "All"),
                    ("2026-09-21T00:00:00+00:00", "rule", "100", 8, 12, "2026-09-21T00:04:00+00:00", "Nmap port scan"),
                ])
            self.assertEqual(pipeline.materialize_taxonomy_once(), 1)
            with pipeline.automation.db() as db:
                rows = db.execute("SELECT dimension,value,count FROM detection_rollups WHERE bucket=?", ("2026-09-21T00:00:00+00:00",)).fetchall()
        self.assertIn(("detection_family", "scan", 8), rows)
        self.assertIn(("mitre", "T1595", 8), rows)

    def test_readiness_field_buckets_are_not_cut_off_by_dashboard_list_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            pipeline = self._pipeline(Path(directory) / "state.db")
            bucket = "2026-09-23T09:00:00+00:00"
            with pipeline.automation.db() as db:
                db.executemany('''INSERT INTO detection_rollups
                    (bucket,dimension,value,count,max_level,last_seen,label) VALUES (?,?,?,?,?,?,?)''', [
                    (bucket, "telemetry_field", f"source|field_{index}", 1, 0,
                     "2026-09-23T09:04:00+00:00", f"field_{index}") for index in range(30)
                ])
            result = pipeline.rollup_summary(
                "2026-09-23T09:00:00+00:00", "2026-09-23T10:00:00+00:00", limit=20)
        self.assertEqual(len(result["dimensions"]["telemetry_field"]), 30)

    def test_contract_does_not_claim_missing_sources_are_covered(self):
        result = summary({"decoder": [{"value": "fortigate", "count": 9}], "telemetry_field": [
            {"value": "fortigate|source_ip", "count": 9},
            {"value": "fortigate|destination_ip", "count": 9},
        ]}, cloud_total=0)
        by_key = {row["key"]: row for row in result["sources"]}
        self.assertEqual(by_key["fortigate"]["status"], "observed_incomplete")
        self.assertEqual(by_key["fortigate"]["available_fields"], ["source_ip", "destination_ip"])
        self.assertIn("firewall_policy", by_key["fortigate"]["missing_fields"])
        self.assertEqual(by_key["defender_xdr"]["status"], "not_observed")

    def test_fortiweb_contract_does_not_inflate_fortigate_coverage(self):
        result = summary({"decoder": [{"value": "fortiweb-json", "count": 9}], "telemetry_field": []})
        by_key = {row["key"]: row for row in result["sources"]}
        self.assertEqual(by_key["fortigate"]["status"], "not_observed")
        self.assertEqual(by_key["fortiweb"]["status"], "observed_incomplete")

    def test_contract_requires_fields_freshness_and_healthy_materialization_for_ready(self):
        now = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc).timestamp()
        required = ("source_ip", "destination_ip", "destination_port", "action",
                    "firewall_policy", "application", "direction")
        dimensions = {
            "telemetry_source": [{"value": "fortigate", "count": 20,
                                  "last_seen": "2026-09-23T09:58:00+00:00"}],
            "telemetry_field": [{"value": f"fortigate|{field}", "count": 20} for field in required],
        }
        result = summary(dimensions, now=now, materialization_complete=True)
        by_key = {row["key"]: row for row in result["sources"]}
        self.assertEqual(by_key["fortigate"]["status"], "ready")
        self.assertEqual(result["summary"]["ready_sources"], 1)

        stale = summary(dimensions, now=now + 90000, materialization_complete=True)
        self.assertEqual({row["key"]: row for row in stale["sources"]}["fortigate"]["status"], "stale")

        degraded = summary(dimensions, now=now, materialization_complete=False)
        self.assertEqual({row["key"]: row for row in degraded["sources"]}["fortigate"]["status"], "degraded")

        sparse = {**dimensions, "telemetry_field": [
            {"value": f"fortigate|{field}", "count": 1} for field in required
        ]}
        incomplete = summary(sparse, now=now, materialization_complete=True)
        fortigate = {row["key"]: row for row in incomplete["sources"]}["fortigate"]
        self.assertEqual(fortigate["status"], "observed_incomplete")
        self.assertEqual(fortigate["available_fields"], list(required))
        self.assertEqual(fortigate["undercovered_fields"], list(required))
        self.assertEqual(fortigate["field_coverage"]["source_ip"], 0.05)

    def test_defender_contract_uses_ledger_field_profile_and_health(self):
        now = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc).timestamp()
        defender = {
            "enabled": True, "configured": True, "observations": 4, "status": "error",
            "last_observed_at": "2026-09-23T09:59:00+00:00",
            "field_sample_size": 4,
            "field_counts": {field: 4 for field in (
                "alert_or_incident", "severity", "entities", "status", "first_seen", "last_update")},
        }
        result = summary({}, defender=defender, now=now, materialization_complete=True)
        row = {item["key"]: item for item in result["sources"]}["defender_xdr"]
        self.assertEqual(row["status"], "degraded")
        self.assertEqual(row["missing_fields"], [])
        self.assertIn("error", row["status_reason"])

    def test_defender_status_profiles_stored_entities_without_provider_call(self):
        db = sqlite3.connect(":memory:")
        defender_xdr.ensure_schema(db)
        observed = datetime(2026, 9, 23, 9, 59, tzinfo=timezone.utc).timestamp()
        raw = {"createdDateTime": "2026-09-23T09:30:00Z", "lastUpdateDateTime": "2026-09-23T09:59:00Z",
               "alerts": [{"ipAddress": "198.51.100.4", "userPrincipalName": "analyst@example.test"}]}
        db.execute("""INSERT INTO defender_xdr_observations
            (item_key,observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("item", observed, observed, "alert-1", "incident-1", "high", "active", "", "Test", json.dumps(raw)))
        db.execute("INSERT INTO defender_xdr_checkpoint(source,checkpoint,updated_at,status,detail) VALUES (?,?,?,?,?)",
                   ("graph:incidents", "2026-09-23T09:59:00Z", observed, "ok", "{}"))
        result = defender_xdr.status(db)
        db.close()
        self.assertEqual(result["field_sample_size"], 1)
        self.assertEqual(set(result["available_fields"]), {
            "alert_or_incident", "severity", "entities", "status", "first_seen", "last_update"})
        self.assertEqual(result["last_observed_at"], "2026-09-23T09:59:00+00:00")

    def test_defender_collection_time_does_not_fake_source_last_update(self):
        db = sqlite3.connect(":memory:")
        defender_xdr.ensure_schema(db)
        observed = datetime(2026, 9, 23, 9, 59, tzinfo=timezone.utc).timestamp()
        raw = {"createdDateTime": "2026-09-23T09:30:00Z",
               "alerts": [{"ipAddress": "198.51.100.4"}]}
        db.execute("""INSERT INTO defender_xdr_observations
            (item_key,observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("item", observed, observed, "alert-1", "incident-1", "high", "active", "", "Test", json.dumps(raw)))
        result = defender_xdr.status(db)
        db.close()
        self.assertIn("alert_or_incident", result["available_fields"])
        self.assertIn("first_seen", result["available_fields"])
        self.assertNotIn("last_update", result["available_fields"])
        self.assertEqual(result["field_counts"]["last_update"], 0)

    def test_generic_syslog_is_not_claimed_as_auditd(self):
        event = {"decoder": {"name": "syslog"}, "data": {"srcip": "198.51.100.7"}}
        self.assertEqual(telemetry_source(event), "other")

    def test_generic_windows_event_is_not_claimed_as_sysmon(self):
        event = {"decoder": {"name": "windows_eventchannel"}, "data": {"win": {"system": {
            "eventID": "4625", "providerName": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
        }}}}
        self.assertEqual(telemetry_source(event), "other")

    def test_sysmon_provider_and_fortiweb_are_separate_sources(self):
        sysmon = {"decoder": {"name": "windows_eventchannel"}, "data": {"win": {"system": {
            "eventID": "1", "providerName": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational",
        }}}}
        fortiweb = {"decoder": {"name": "fortiweb-json"}, "data": {"srcip": "198.51.100.1"}}
        self.assertEqual(telemetry_source(sysmon), "windows_sysmon")
        self.assertEqual(telemetry_source(fortiweb), "fortiweb")

    def test_fortigate_ips_drop_is_an_exploit_signal_but_forward_traffic_is_not(self):
        dropped = {
            "rule": {"id": "81629", "description": "Fortigate attack dropped"},
            "decoder": {"name": "fortigate-firewall-v5"},
            "data": {"type": "utm", "subtype": "ips", "action": "dropped",
                     "srcip": "198.51.100.12", "dstip": "10.0.0.12", "dstport": "443"},
        }
        accepted = {
            "rule": {"id": "81618", "description": "Fortigate: App passed by firewall."},
            "decoder": {"name": "fortigate-firewall-v5"},
            "data": {"type": "traffic", "subtype": "forward", "action": "accept",
                     "srcip": "198.51.100.13", "dstip": "10.0.0.13", "dstport": "443"},
        }
        self.assertEqual(classify(dropped)["family"], "exploit_attempt")
        self.assertEqual(classify(dropped)["confidence"], "evidence_complete")
        self.assertEqual(classify(accepted)["family"], "other")
        self.assertIn(("forti_profile", "utm/ips/dropped", "utm/ips/dropped"), rollup_dimensions(dropped))

    def test_research_listing_parser_and_local_ledger(self):
        parser = cyfirma_research._ListingParser()
        parser.feed('''<div class="blog-row"><div class="blog-content"><date>2026-09-17</date><h6><a href="/research/fvs/">Fortnightly Vulnerability Summary</a></h6><p>Observed vulnerabilities.</p></div></div>''')
        self.assertEqual(parser.items[0]["title"], "Fortnightly Vulnerability Summary")
        with tempfile.TemporaryDirectory() as directory:
            db = sqlite3.connect(Path(directory) / "state.db")
            with db:
                self.assertEqual(cyfirma_research.store(db, parser.items, 1_789_603_200), 1)
                self.assertEqual(cyfirma_research.store(db, parser.items, 1_789_603_500), 1)
                result = cyfirma_research.history(db, limit=5)
                dated = cyfirma_research.history(
                    db, "2026-09-17T00:00:00+00:00", "2026-09-18T00:00:00+00:00", 5)
            db.close()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["provider_calls"], 0)
        self.assertEqual(dated["total"], 1)
        self.assertEqual(dated["items"][0]["published_at"], "2026-09-17")

    def test_taxii_indicator_normalization_is_bounded_and_only_accepts_cyfirma_collections(self):
        item = cyfirma_taxii.normalize_indicator({
            "type": "indicator", "id": "indicator--1", "name": "Known scanner",
            "pattern": "[ipv4-addr:value = '203.0.113.9' OR domain-name:value = 'example.test']",
            "labels": ["scanner"], "external_references": [{"external_id": "CVE-2026-12345"}],
        })
        self.assertEqual(item["scope"], "taxii")
        self.assertEqual(item["iocs"], ["203.0.113.9", "example.test"])
        self.assertEqual(item["ioc_types"], ["ip", "domain"])
        with self.assertRaises(ValueError):
            cyfirma_taxii._collection_url("https://example.invalid/collections/x/")
        self.assertEqual(
            cyfirma_taxii._collection_url("https://api.cyfirma.com/taxii2/collections/abc/"),
            "https://api.cyfirma.com/taxii2/collections/abc/",
        )

    def test_taxii_cursor_is_sent_only_as_an_opaque_query_value(self):
        response = MagicMock()
        response.read.return_value = b'{"objects": [], "more": true, "next": "opaque-token"}'
        context = MagicMock()
        context.__enter__.return_value = response
        with patch.object(cyfirma_taxii.urllib.request, "urlopen", return_value=context) as request:
            rows, status = cyfirma_taxii.fetch(
                "https://api.cyfirma.com/taxii2/collections/abc/", "token", limit=20, cursor="prior-token")
        self.assertEqual(rows, [])
        self.assertTrue(status["more"])
        self.assertEqual(status["next_cursor"], "opaque-token")
        self.assertIn("next=prior-token", request.call_args.args[0].full_url)

    def test_org_vulnerability_page_is_bounded_and_reports_next_page(self):
        response = MagicMock()
        response.read.return_value = b'{"items": [{"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2026-12345"}]}'
        context = MagicMock()
        context.__enter__.return_value = response
        with patch.object(cyfirma_org_vulnerability.urllib.request, "urlopen", return_value=context) as request:
            rows, status = cyfirma_org_vulnerability.fetch("key", page_size=1, page=3)
        self.assertEqual(len(rows), 1)
        self.assertTrue(status["more"])
        self.assertEqual(status["next_page"], 4)
        self.assertIn("page=3", request.call_args.args[0].full_url)

    def test_org_vulnerability_normalizes_stix_and_rejects_untrusted_endpoint(self):
        item = cyfirma_org_vulnerability.normalize({
            "type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2026-12345",
            "description": "Example", "external_references": [{"source_name": "cve", "external_id": "CVE-2026-12345"}],
        })
        self.assertEqual(item["scope"], "org_vulnerability")
        self.assertEqual(item["cves"], ["CVE-2026-12345"])
        with self.assertRaises(ValueError):
            cyfirma_org_vulnerability._endpoint("https://example.invalid/vulnerabilities")

    def test_defender_is_noop_until_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            db = sqlite3.connect(Path(directory) / "state.db")
            with db:
                result = defender_xdr.collect(db, {"DEFENDER_XDR_ENABLED": "false"})
            db.close()
        self.assertEqual(result, {"enabled": False, "status": "disabled", "observations": 0})

    def test_defender_incidents_are_checkpointed_and_read_from_local_ledger(self):
        original_token, original_request = defender_xdr._token, defender_xdr._request_json
        requested = []
        try:
            defender_xdr._token = lambda *_args, **_kwargs: "token"
            defender_xdr._request_json = lambda url, *_args, **_kwargs: requested.append(url) or {"value": [{
                "id": "incident-1", "incidentName": "Suspicious mailbox rule", "severity": "high",
                "status": "active", "classification": "TruePositive", "lastUpdateTime": "2026-09-22T00:00:00Z",
            }]}
            with tempfile.TemporaryDirectory() as directory:
                db = sqlite3.connect(Path(directory) / "state.db")
                with db:
                    result = defender_xdr.collect(db, {
                        "DEFENDER_XDR_ENABLED": "true", "DEFENDER_XDR_TENANT_ID": "tenant",
                        "DEFENDER_XDR_CLIENT_ID": "client", "DEFENDER_XDR_CLIENT_SECRET": "secret",
                        "DEFENDER_XDR_COLLECTION_MODE": "incidents", "DEFENDER_XDR_BATCH_SIZE": "10",
                    })
                    history = defender_xdr.history(db, "2026-09-21T00:00:00Z", "2026-09-23T00:00:00Z")
                db.close()
        finally:
            defender_xdr._token, defender_xdr._request_json = original_token, original_request
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["mode"], "incidents")
        self.assertIn("/api/incidents?", requested[0])
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["incident_id"], "incident-1")
        self.assertEqual(history["provider_calls"], 0)

    def test_defender_graph_mode_uses_security_incident_read_contract(self):
        original_token, original_request = defender_xdr._token, defender_xdr._request_json
        calls = []
        try:
            defender_xdr._token = lambda *args, **_kwargs: calls.append(args[3]) or "token"
            defender_xdr._request_json = lambda url, *_args, **_kwargs: calls.append(url) or {"value": []}
            with tempfile.TemporaryDirectory() as directory:
                db = sqlite3.connect(Path(directory) / "state.db")
                with db:
                    result = defender_xdr.collect(db, {
                        "DEFENDER_XDR_ENABLED": "true", "DEFENDER_XDR_TENANT_ID": "tenant",
                        "DEFENDER_XDR_CLIENT_ID": "client", "DEFENDER_XDR_CLIENT_SECRET": "secret",
                        "DEFENDER_XDR_API_PROVIDER": "graph", "DEFENDER_XDR_COLLECTION_MODE": "incidents",
                    })
                db.close()
        finally:
            defender_xdr._token, defender_xdr._request_json = original_token, original_request
        self.assertEqual(result["provider"], "graph")
        self.assertEqual(calls[0], "https://graph.microsoft.com/.default")
        self.assertIn("https://graph.microsoft.com/v1.0/security/incidents?", calls[1])

    def test_defender_correlation_uses_local_ledger_and_exact_entities_only(self):
        with tempfile.TemporaryDirectory() as directory:
            db = sqlite3.connect(Path(directory) / "state.db")
            with db:
                defender_xdr.ensure_schema(db)
                db.execute('''INSERT INTO defender_xdr_observations
                    (item_key,observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data)
                    VALUES (?,?,?,?,?,?,?,?,?,?)''', (
                        "item-1", 1_789_603_200, 1_789_603_200, "alert-1", "incident-1", "high", "active",
                        "malware", "Suspicious endpoint", '{"id":"incident-1","deviceName":"HOST-01","userPrincipalName":"analyst@example.com","ipAddress":"203.0.113.10"}',
                    ))
                result = defender_xdr.correlate(db, {
                    "network": [{"source": "203.0.113.10", "destination": "10.0.0.3", "agent": "host-01"}],
                    "identity": [{"user": "analyst@example.com"}], "m365": [], "assets": [],
                })
            db.close()
        self.assertEqual(result["provider_calls"], 0)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["matches"]["ip"], ["203.0.113.10"])
        self.assertEqual(result["items"][0]["matches"]["identity"], ["analyst@example.com"])
        self.assertEqual(result["items"][0]["confidence"], "confirmed_by_multi_source")


if __name__ == "__main__":
    unittest.main()
