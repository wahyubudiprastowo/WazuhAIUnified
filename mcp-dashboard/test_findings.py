import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import server


class FindingTests(unittest.TestCase):
    def setUp(self):
        server._finding_cache.clear()
        server._overview_cache_init()
        with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
            db.execute("DELETE FROM api_snapshots WHERE namespace = 'finding_intel'")
            db.execute("DELETE FROM provider_history_provider")
            db.execute("DELETE FROM provider_history_cve")
            db.execute("DELETE FROM provider_history_summary")
            db.execute("DELETE FROM provider_history")

    def test_read_only_allowlist(self):
        with patch.object(server, "_safe_call") as call:
            with self.assertRaises(ValueError):
                server._finding_intel("wazuh_restart", "host")
            call.assert_not_called()

    def test_private_ip_skipped(self):
        with patch.object(server, "_safe_call") as call:
            self.assertFalse(server._finding_intel("crowdsec", "10.0.0.1")["ok"])
            call.assert_not_called()

    def test_private_ipv6_not_sent_to_providers(self):
        with patch.object(server, "_safe_call") as call:
            self.assertFalse(server._finding_intel("aggregate", "fd00::1")["ok"])
            self.assertFalse(server._finding_intel("otx", "::1")["ok"])
            call.assert_not_called()

    def test_detection_layers_do_not_claim_empty_sources_are_ready(self):
        layers = server._detection_layers(
            {"total_alerts": 0}, [], [], {"total": 0}, {}, 0, 0, {}, {},
            {"sources": [{"key": "fortigate", "observed_events": 0},
                         {"key": "ids_ndr", "observed_events": 0},
                         {"key": "waf_web", "observed_events": 0},
                         {"key": "container_runtime", "observed_events": 0},
                         {"key": "m365_audit", "observed_events": 0},
                         {"key": "defender_xdr", "observed_events": 0}]},
        )
        self.assertTrue(all(row["status"] == "not_observed" for row in layers))
        network = next(row for row in layers if row["key"] == "network")
        self.assertEqual(network["count"], 0)

    def test_detection_layers_propagate_incomplete_source_contract(self):
        layers = server._detection_layers(
            {"total_alerts": 10}, [], [], {"total": 0}, {}, 0, 0, {}, {},
            {"sources": [
                {"key": "fortigate", "observed_events": 25, "status": "observed_incomplete",
                 "available_fields": ["source_ip"], "missing_fields": ["destination_ip", "action"],
                 "status_reason": "Events exist, but required detection fields are missing."},
                {"key": "ids_ndr", "observed_events": 0, "status": "not_observed"},
            ]},
        )
        network = next(row for row in layers if row["key"] == "network")
        self.assertEqual(network["status"], "observed_incomplete")
        self.assertEqual(network["count"], 25)
        self.assertIn("action", network["missing_fields"])
        self.assertNotEqual(network["status"], "ready")

    def test_count_only_detection_layers_are_not_marked_ready(self):
        layers = server._detection_layers(
            {"total_alerts": 100}, [], [], {"total": 30}, {}, 50, 0,
            {"total_vulnerabilities": 20}, {}, {"sources": []},
        )
        by_key = {row["key"]: row for row in layers}
        for key in ("fim", "auth", "vuln", "siem"):
            self.assertEqual(by_key[key]["status"], "observed_incomplete")
            self.assertIn("field coverage has not been measured", by_key[key]["status_reason"])

    def test_attack_surface_only_links_co_observed_source_and_asset(self):
        result = server._attack_surface([
            {"rule_id": "1001", "count": 7, "source_ips": ["198.51.100.8"], "agent": "edge-01"},
            {"rule_id": "1002", "count": 3, "source_ips": [], "agent": "db-01"},
        ], [{"ip": "198.51.100.8", "hits": 7}], {}, {"cities": []})
        self.assertEqual({row["name"] for row in result["targets"]}, {"edge-01", "db-01"})
        self.assertEqual(result["relationships"], [{
            "source_ip": "198.51.100.8", "target": "edge-01", "alerts": 7,
            "rules": ["1001"], "relationship": "co_observed_in_rule_aggregation",
        }])
        self.assertIn("does not prove", result["relationship_note"])

    def test_shared_cache(self):
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": {"reputation": "unknown"}}) as call:
            with ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(lambda _: server._finding_intel("crowdsec", "8.8.8.8"), range(3)))
            self.assertEqual(call.call_count, 1)
            self.assertEqual(sum(r["cached"] for r in results), 2)

    def test_feed_errors_not_success(self):
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": {"errors": {"global": "Unavailable"}}}):
            self.assertFalse(server._finding_intel("feed_global")["ok"])

    def test_partial_aggregate_preserves_provider_results(self):
        data = {"results": [{"provider": "otx", "detail": {"pulse_count": 0}}], "errors": ["ThreatFox not configured"]}
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": data}):
            result = server._finding_intel("aggregate", "8.8.8.8")
            self.assertTrue(result["ok"])
            self.assertTrue(result["partial"])
            self.assertEqual(result["data"]["results"][0]["detail"]["pulse_count"], 0)

    def test_aggregate_all_errors_not_success(self):
        data = {"results": [{"provider": "otx", "error": "timeout"}], "errors": ["otx: timeout"]}
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": data}):
            self.assertFalse(server._finding_intel("aggregate", "8.8.8.8")["ok"])

    def test_aggregate_tolerates_non_object_provider_detail(self):
        data = {"results": [{"provider": "otx", "detail": ["legacy", "shape"]}]}
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": data}):
            result = server._finding_intel("aggregate", "1.0.0.1")
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["results"][0]["provider"], "otx")

    def test_findings_provider_and_cve_tabs_are_lazy_and_deduplicated(self):
        source = (Path(server.STATIC) / "findings.js").read_text()
        select_block = source[source.index("function select(row)"):source.index("function overview(row)")]
        self.assertNotIn("loadIntel(row", select_block)
        self.assertNotIn("loadEvidence(row", select_block)
        self.assertNotIn("loadCve(row", select_block)
        intel_block = source[source.index("async function loadIntel"):source.index("async function loadCve")]
        self.assertIn('intel("aggregate", indicator)', intel_block)
        self.assertNotIn('intel("crowdsec"', intel_block)
        self.assertIn("findingWorkflowTools", source)

    def test_feed_pagination(self):
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": {"items": []}}) as call:
            server._finding_intel("feed", "20")
            self.assertEqual(call.call_args.args[2]["offset"], 20)

    def test_direct_ioc_no_results_is_not_error(self):
        with patch.object(server, "_safe_call", return_value={"ok": True, "data": {"query_status": "no_results", "results": []}}):
            result = server._finding_intel("threatfox", "8.8.8.8")
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["query_status"], "no_results")

    def test_latest_provider_history_reuses_stored_intelligence(self):
        indicator = "203.0.113.247"
        stored = {"data": {"results": [{"provider": "otx", "is_malicious": True}],
                            "cyfirma_matches": [{"id": "indicator--test"}]}}
        with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
            db.execute("INSERT OR REPLACE INTO provider_history(namespace,cache_key,indicator,observed_at,bucket_hour,payload) VALUES (?,?,?,?,?,?)",
                ("finding_intel", "test-latest", indicator, time.time(), int(time.time() // 3600 * 3600), json.dumps(stored)))
        result = server._latest_provider_history(indicator)
        self.assertEqual(result["results"][0]["provider"], "otx")
        self.assertEqual(result["cyfirma_matches"][0]["id"], "indicator--test")

    def test_provider_freshness_reads_persisted_snapshot_without_api_call(self):
        stored = {"data": {"results": [{
            "provider": "test-provider", "detail": {"quota_remaining": 17, "skip_reason": "cached"},
        }]}}
        now = time.time()
        with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
            db.execute("INSERT OR REPLACE INTO provider_history(namespace,cache_key,indicator,observed_at,bucket_hour,payload) VALUES (?,?,?,?,?,?)",
                ("finding_intel", "test-freshness", "198.51.100.7", now,
                 int(now // 3600 * 3600), json.dumps(stored)))
        with patch.object(server, "_safe_call") as call:
            result = server._provider_freshness()
        row = next(item for item in result["providers"] if item["provider"] == "test-provider")
        self.assertEqual(row["quota_remaining"], 17)
        self.assertEqual(row["reason_not_used"], "cached")
        call.assert_not_called()

    def test_provider_history_7d_summary_is_materialized_sql(self):
        indicator = "203.0.113.88"
        data = {"data": {
            "aggregated_risk_level": "high", "consensus_malicious": True,
            "results": [
                {"provider": "otx", "is_malicious": True,
                 "detail": {"quota_remaining": 21, "cves": ["CVE-2026-12345"]}},
                {"provider": "virustotal", "error": "rate limited"},
            ],
            "cyfirma_matches": [{"id": "indicator--one"}],
        }}
        server._provider_history_write("finding_intel", {"kind": "aggregate", "indicator": indicator}, data)
        now = datetime.now(timezone.utc)
        result = server._provider_history_payload(
            (now - timedelta(days=7)).isoformat(), (now + timedelta(minutes=1)).isoformat(), offset=20)
        summary = result["summary"]
        self.assertEqual(summary["snapshots"], 1)
        self.assertEqual(summary["unique_indicators"], 1)
        self.assertEqual(summary["provider_results"], 1)
        self.assertEqual(summary["provider_matches"], 1)
        self.assertEqual(summary["provider_errors"], 1)
        self.assertEqual(summary["cyfirma_matches"], 1)
        self.assertEqual(summary["cve_refs"], ["CVE-2026-12345"])
        self.assertEqual(summary["materialization"]["source"], "sqlite_normalized_summary")
        self.assertTrue(summary["materialization"]["complete"])
        self.assertEqual(result["intelligence"], [])
        self.assertEqual(result["indicator_catalog"][0]["indicator"], indicator)
        with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM provider_history_summary").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM provider_history_provider").fetchone()[0], 2)

    def test_provider_history_can_follow_event_timestamp(self):
        event_time = datetime.now(timezone.utc) - timedelta(days=2)
        data = {"data": {"results": [{"provider": "crowdsec", "risk_level": "high"}]}}
        server._provider_history_write(
            "finding_intel", {"kind": "aggregate", "indicator": "198.51.100.44"},
            data, event_time.isoformat())
        history = server._provider_history_payload(
            (event_time - timedelta(minutes=1)).isoformat(),
            (event_time + timedelta(minutes=1)).isoformat())
        self.assertEqual(history["summary"]["snapshots"], 1)
        self.assertEqual(history["intelligence"][0]["indicator"], "198.51.100.44")

    def test_provider_history_30d_includes_old_materialized_snapshot_without_provider_call(self):
        observed = time.time() - 20 * 86400
        stored = {"data": {"results": [{"provider": "cyfirma", "risk_level": "high"}]}}
        with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
            cursor = db.execute("""INSERT INTO provider_history
                (namespace,cache_key,indicator,observed_at,bucket_hour,payload) VALUES (?,?,?,?,?,?)""",
                ("finding_intel", "old-30d", "198.51.100.30", observed,
                 int(observed // 3600 * 3600), json.dumps(stored)))
            server._provider_history_materialize(db, cursor.lastrowid, "198.51.100.30", observed, stored)
        now = datetime.now(timezone.utc)
        seven = server._provider_history_payload(
            (now - timedelta(days=7)).isoformat(), (now + timedelta(minutes=1)).isoformat())
        thirty = server._provider_history_payload(
            (now - timedelta(days=30)).isoformat(), (now + timedelta(minutes=1)).isoformat())
        self.assertEqual(seven["summary"]["snapshots"], 0)
        self.assertEqual(thirty["summary"]["snapshots"], 1)
        self.assertEqual(thirty["summary"]["providers"][0]["provider"], "cyfirma")

    def test_evidence_uses_exact_structured_query(self):
        with patch.object(server, "_indexer_search", return_value={"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}) as search:
            result = server._finding_evidence({"kind": "rule", "value": 'x" OR *', "range": "7d"})
            query = search.call_args.args[0]
            self.assertEqual(query["query"]["bool"]["filter"][1]["bool"]["should"], [{"term": {"rule.id": 'x" OR *'}}])
            self.assertTrue(query["track_total_hits"])
            self.assertEqual(result["total"], 0)

    def test_mcp_handshake_reused_and_actions_not_retried(self):
        server._infokom_session.update(expires=0, id=None)
        with patch.object(server, "_initialize_infokom", return_value="session") as init, \
             patch.object(server, "_infokom_headers", return_value={}), \
             patch.object(server, "_http_json", return_value=({}, {"result": {}})) as request:
            server._infokom_rpc("tools/list", {}, "one")
            server._infokom_rpc("tools/list", {}, "two")
            self.assertEqual(init.call_count, 1)
            request.side_effect = RuntimeError("Connection lost")
            with self.assertRaises(RuntimeError):
                server._infokom_rpc("tools/call", {}, "action")
            self.assertEqual(request.call_count, 3)
            self.assertEqual(server._infokom_session["expires"], 0)

    def test_persistent_incident_contract(self):
        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": [{"case_id": "case_1", "title": "Test"}], "duration_ms": 4,
        }):
            result = server._incident_cases()
            self.assertTrue(result["ok"])
            self.assertEqual(result["cases"][0]["case_id"], "case_1")

        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": {"case_id": "case_2"}, "duration_ms": 5,
        }) as call:
            result = server._incident_create({
                "title": "Repeated source", "srcips": ["8.8.8.8", "bad", "8.8.8.8"], "notes": "evidence",
                "initial_evidence": [{"evidence_type": "event", "title": "Rule match",
                                      "source": "wazuh", "source_ref": "event-1"}],
            })
            self.assertTrue(result["ok"])
            self.assertEqual(call.call_args.args[2]["srcips"], ["8.8.8.8"])
            self.assertEqual(call.call_args.args[2]["initial_evidence"][0]["source_ref"], "event-1")

    def test_incident_detail_reads_transactional_store_only(self):
        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": {"case_id": "case_12345", "revision": 3, "evidence": []},
            "duration_ms": 2,
        }) as call, patch.object(server, "_indexer_search") as indexer:
            result = server._incident_get({"case_id": "case_12345"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["source"], "transactional_case_store")
        self.assertEqual(call.call_args.args[1], "blueteam_case_get")
        indexer.assert_not_called()

    def test_incident_mutation_forwards_revision_and_server_actor(self):
        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": {"case_id": "case_12345", "revision": 8}, "duration_ms": 3,
        }) as call:
            result = server._incident_mutate({
                "action": "assign", "case_id": "case_12345", "expected_revision": 7,
                "owner": "soc-l2", "sla_due": "2026-10-01T00:00:00Z", "actor": "spoofed",
            })
        self.assertTrue(result["ok"])
        self.assertEqual(call.call_args.args[1], "blueteam_case_assign")
        arguments = call.call_args.args[2]
        self.assertEqual(arguments["expected_revision"], 7)
        self.assertEqual(arguments["actor"], server.DASHBOARD_ACCESS_USERNAME)

    def test_incident_mutation_surfaces_revision_conflict(self):
        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": {"error": "revision_conflict", "current_revision": 9},
        }):
            result = server._incident_mutate({
                "action": "note", "case_id": "case_12345", "expected_revision": 8,
                "body": "stale note",
            })
        self.assertFalse(result["ok"])
        self.assertEqual(result["status_code"], 409)
        self.assertEqual(result["current_revision"], 9)

    def test_incident_pages_and_date_bounds_are_forwarded_to_case_store(self):
        with patch.object(server, "_normalized_call", return_value={
            "ok": True, "json": {"items": [], "total": 51, "limit": 25, "offset": 25}, "duration_ms": 2,
        }) as call:
            result = server._incident_cases_sync({
                "start": "2026-09-01T00:00:00+00:00", "end": "2026-09-02T00:00:00+00:00",
                "limit": 25, "offset": 25,
            })
        arguments = call.call_args.args[2]
        self.assertEqual(arguments["offset"], 25)
        self.assertEqual(arguments["limit"], 25)
        self.assertEqual(arguments["start"], "2026-09-01T00:00:00+00:00")
        self.assertEqual(result["pagination"]["next_offset"], 50)

    def test_incident_cache_key_includes_page_coordinates(self):
        source = Path(server.__file__).read_text(encoding="utf-8")
        self.assertIn('(\"range\", \"start\", \"end\", \"limit\", \"offset\")', source)

    def test_operational_evidence_contract(self):
        data = {
            "hits": {"total": {"value": 15, "relation": "eq"}},
            "took": 17,
            "timed_out": False,
            "_shards": {"total": 3, "successful": 3, "failed": 0},
            "aggregations": {
                "network_events": {"sample": {"hits": {"hits": [{"_source": {
                    "@timestamp": "2026-09-15T10:00:00Z", "agent": {"name": "edge-fw"},
                    "decoder": {"name": "fortigate"}, "data": {
                        "srcip": "8.8.8.8", "dstip": "10.0.0.5", "dstport": "443",
                        "app": "HTTPS", "policyid": "42", "direction": "incoming",
                    },
                }}]}}},
                "identity_events": {"sample": {"hits": {"hits": [{"_source": {
                    "@timestamp": "2026-09-15T10:01:00Z", "agent": {"name": "m365"},
                    "data": {"office365": {"UserId": "analyst@example.com", "Operation": "UserLoggedIn",
                                              "SessionId": "session-1", "ClientIP": "8.8.4.4"}},
                }}]}}},
                "decoders": {"buckets": [{"key": "fortigate", "doc_count": 12,
                    "max_level": {"value": 10}, "sample": {"hits": {"hits": [{"_source": {
                        "@timestamp": "2026-09-15T10:00:00Z", "rule": {"description": "Firewall deny"},
                        }}]}}}]},
                "decoder_named_events": {"doc_count": 13},
                "unmatched_decoder": {"doc_count": 2},
                "mitre_techniques": {"buckets": [{"key": "T1110", "doc_count": 7}]},
                "mitre_timeline": {"buckets": [{"key_as_string": "2026-09-15T10:00:00Z",
                    "techniques": {"buckets": [{"key": "T1110", "doc_count": 7}]}}]},
                "dropped_events": {"doc_count": 1},
                "agent_flooding": {"doc_count": 2},
                "manager_queue": {"doc_count": 3},
            },
        }
        evidence = server._operational_evidence(data, 31)
        self.assertEqual(evidence["network"]["events"][0]["destination"], "10.0.0.5")
        self.assertEqual(evidence["identity"]["events"][0]["user"], "analyst@example.com")
        self.assertEqual(evidence["decoders"]["items"][0]["name"], "fortigate")
        self.assertEqual(evidence["data_quality"]["indexed_events"], 15)
        self.assertEqual(evidence["data_quality"]["decoder_coverage_percent"], 86.67)
        self.assertEqual(evidence["decoders"]["named_events"], 13)
        self.assertEqual(evidence["mitre"]["timeline"][0]["techniques"][0]["technique"], "T1110")
        self.assertEqual(evidence["telemetry"]["manager_queue"], 3)
        self.assertEqual(evidence["telemetry"]["indexer"]["health"], "healthy")

    def test_asset_context_merges_local_cmdb_without_wazuh_lookup(self):
        assets = [{
            "agent_id": "007", "host": "edge-fw.example.internal", "name": "Edge Firewall",
            "owner": "Network SOC", "criticality": "critical", "environment": "production",
            "network_zone": "dmz", "vendor": "Fortinet", "version": "7.4.3",
            "cpe": "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
        }, {
            "host": "billing.example.internal", "name": "Billing", "owner": "Finance",
            "criticality": "high",
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps(assets), encoding="utf-8")
            with patch.object(server, "SOC_CMDB_FILE", path):
                server._cmdb_cache.update({"path": None, "mtime_ns": None, "size": None,
                    "assets": [], "loaded_at": None, "error": None})
                result = server._asset_context([{
                    "id": "007", "name": "edge-fw.example.internal", "ip": "10.0.0.1",
                    "labels": {"owner": "Wazuh Owner"},
                }])
        managed = next(row for row in result["rows"] if row["managed"])
        unmanaged = next(row for row in result["rows"] if not row["managed"])
        self.assertEqual(managed["owner"], "Wazuh Owner")
        self.assertEqual(managed["criticality"], "critical")
        self.assertEqual(managed["source"], "Wazuh + CMDB")
        self.assertEqual(unmanaged["name"], "Billing")
        self.assertEqual(result["status"]["matched_agents"], 1)
        self.assertEqual(result["status"]["unmanaged_assets"], 1)

    def test_asset_context_keeps_last_valid_snapshot_on_parse_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps([{"host": "db.internal", "owner": "DBA"}]), encoding="utf-8")
            with patch.object(server, "SOC_CMDB_FILE", path):
                server._cmdb_cache.update({"path": None, "mtime_ns": None, "size": None,
                    "assets": [], "loaded_at": None, "error": None})
                first, first_status = server._load_cmdb_assets()
                path.write_text("{broken", encoding="utf-8")
                os.utime(path, ns=(time.time_ns(), time.time_ns()))
                retained, status = server._load_cmdb_assets()
        self.assertEqual(first[0]["owner"], "DBA")
        self.assertFalse(first_status["cached"])
        self.assertEqual(retained, first)
        self.assertTrue(status["cached"])
        self.assertTrue(status["error"])

    def test_asset_context_does_not_correlate_sample_rows_by_reused_agent_id(self):
        assets = [{
            "agent_id": "001", "host": "sample.invalid", "owner": "Example owner",
            "criticality": "critical", "purpose": "SAMPLE - replace before production",
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps(assets), encoding="utf-8")
            with patch.object(server, "SOC_CMDB_FILE", path):
                server._cmdb_cache.update({"path": None, "mtime_ns": None, "size": None,
                    "assets": [], "loaded_at": None, "error": None})
                result = server._asset_context([{"id": "001", "name": "production-server"}])
        self.assertEqual(result["rows"][0]["source"], "Wazuh")
        self.assertIsNone(result["rows"][0]["owner"])
        self.assertEqual(result["status"]["matched_agents"], 0)
        self.assertEqual(result["status"]["sample_assets"], 1)
        self.assertEqual(result["status"]["authoritative_assets"], 0)

    def test_asset_context_rejects_ambiguous_cmdb_identity_instead_of_first_match(self):
        assets = [
            {"agent_id": "007", "host": "edge-a.internal", "owner": "Network"},
            {"agent_id": "007", "host": "edge-b.internal", "owner": "Platform"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps(assets), encoding="utf-8")
            with patch.object(server, "SOC_CMDB_FILE", path):
                server._cmdb_cache.update({"path": None, "mtime_ns": None, "size": None,
                    "assets": [], "loaded_at": None, "error": None})
                result = server._asset_context([{"id": "007", "name": "unknown-host"}])
                finding = server._finding_asset_context({"assets": ["007"]})
        self.assertEqual(result["rows"][0]["cmdb_match_status"], "ambiguous")
        self.assertEqual(result["rows"][0]["source"], "Wazuh")
        self.assertIsNone(result["rows"][0]["owner"])
        self.assertEqual(result["status"]["ambiguous_agent_matches"], 1)
        self.assertEqual(result["status"]["ambiguous_identifiers"], 1)
        self.assertEqual(finding, [])

    def test_case_cve_links_require_explicit_structured_entities(self):
        links = server._case_cve_links([{
            "case_id": "case_1", "title": "Mentions CVE-2026-99999 but is not evidence",
            "entities": [{"type": "cve", "value": "cve-2026-12345"},
                         {"type": "asset", "value": "CVE-2026-88888"}],
            "iocs": ["CVE-2026-77777", "not-a-cve"],
        }])
        self.assertEqual(links, {
            "CVE-2026-12345": ["case_1"], "CVE-2026-77777": ["case_1"],
        })

    def test_cve_exposure_schema_additively_migrates_existing_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "overview.db"
            with sqlite3.connect(database) as db:
                db.execute("""CREATE TABLE cve_exposure_summary (
                    snapshot_key TEXT NOT NULL, path_key TEXT NOT NULL, observed_at REAL NOT NULL,
                    requested_range TEXT NOT NULL, cve TEXT NOT NULL, asset TEXT, agent_id TEXT,
                    component TEXT, version TEXT, cpe TEXT, cpe_status TEXT, epss REAL, kev INTEGER,
                    poc INTEGER, internet_exposure INTEGER, patch_state TEXT, case_id TEXT,
                    risk_score REAL, priority TEXT, PRIMARY KEY(snapshot_key,path_key))""")
            original_initialized = server._overview_db_initialized
            try:
                with patch.object(server, "OVERVIEW_CACHE_DB", database):
                    server._overview_db_initialized = False
                    server._overview_cache_init()
                    with sqlite3.connect(database) as db:
                        columns = {row[1] for row in db.execute("PRAGMA table_info(cve_exposure_summary)")}
                self.assertTrue({"owner", "criticality", "environment", "network_zone",
                                 "asset_match", "component_match", "patch_evidence"} <= columns)
            finally:
                server._overview_db_initialized = original_initialized

    def test_finding_asset_context_is_local_and_bounded(self):
        assets = [{"host": "app.internal", "name": "Payments API", "owner": "Payments",
                   "criticality": "critical", "network_zone": "dmz", "cpe": "cpe:test"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps(assets), encoding="utf-8")
            with patch.object(server, "SOC_CMDB_FILE", path), patch.object(server, "_indexer_search") as search:
                server._cmdb_cache.update({"path": None, "mtime_ns": None, "size": None,
                    "assets": [], "loaded_at": None, "error": None})
                finding = server._enrich_finding_asset_context({"id": "rule:1", "assets": ["app.internal"]})
        self.assertEqual(finding["asset_context"][0]["owner"], "Payments")
        self.assertEqual(finding["asset_context"][0]["criticality"], "critical")
        self.assertEqual(finding["asset_context"][0]["evidence"], "Matched from local CMDB")
        search.assert_not_called()

    def test_local_alert_query_is_bounded_and_aggregation_only(self):
        response = {"hits": {"total": {"value": 1}}, "aggregations": {
                        "l1_alerts": {"sample": {"hits": {"hits": [{"_id": "event-1", "_index": "wazuh-alerts-4.x",
                            "_source": {"@timestamp": "2026-09-15T10:00:00Z", "rule": {"id": "100", "level": 12,
                            "description": "High risk alert"}, "agent": {"name": "server-1"},
                            "decoder": {"name": "fortigate"}, "data": {"srcip": "8.8.8.8", "dstip": "10.0.0.8"}}}]}}},
                        "m365": {"doc_count": 1, "workload": {"buckets": [{"key": "AzureActiveDirectory", "doc_count": 1}]},
                            "operation": {"buckets": []}, "client_ip": {"buckets": []}, "subscription": {"buckets": []},
                            "sample": {"hits": {"hits": []}}},
                    },
                    "_shards": {"total": 1, "successful": 1, "failed": 0}}
        window = {"requested": "24h", "tool_range": "24h", "label": "24 hours",
                  "bounds": {"gte": "now-24h", "lt": "now"}}
        with patch.object(server, "_indexer_search", return_value=response) as search:
            result = server._local_alert_window(window)
        query = search.call_args.args[0]
        self.assertEqual(query["size"], 0)
        self.assertTrue(query["track_total_hits"])
        self.assertEqual(query["aggs"]["network_events"]["aggs"]["sample"]["top_hits"]["size"], 12)
        self.assertEqual(query["aggs"]["identity_events"]["aggs"]["sample"]["top_hits"]["size"], 12)
        self.assertIn("decoder_named_events", query["aggs"])
        self.assertIn("operational_evidence", result)
        self.assertEqual(result["l1_queue"][0]["event_id"], "event-1")
        self.assertEqual(result["l1_queue"][0]["sla_minutes"], 30)
        self.assertEqual(result["cloud_m365"]["total"], 1)

    def test_long_range_cache_miss_returns_materialized_summary_and_builds_async(self):
        placeholder = {"generated_at": "now", "materialization": {"status": "building"}}
        with patch.object(server, "_overview_cache_read", return_value=None), \
             patch.object(server, "_overview_refresh_async") as refresh, \
             patch.object(server, "_materialized_overview", return_value=placeholder), \
             patch.object(server, "_overview") as overview:
            result = server._overview_cached({"range": "7d"})
        self.assertEqual(result["cache"]["status"], "building")
        self.assertFalse(result["materialization"]["exact"] if "exact" in result["materialization"] else False)
        refresh.assert_called_once()
        overview.assert_not_called()

    def test_background_overview_refresh_exposes_safe_stale_error(self):
        key = "test-background-refresh-error"
        server._overview_refresh_errors.pop(key, None)
        try:
            with patch.object(server, "_overview", side_effect=RuntimeError("indexer unavailable")):
                server._overview_refresh_worker(key, {"requested": "24h"}, {"range": "24h"}, 120)
            self.assertEqual(server._overview_refresh_errors.get(key),
                             "Background refresh failed; retaining the last valid snapshot.")
        finally:
            server._overview_refresh_errors.pop(key, None)

    def test_complete_rollup_serves_long_range_without_indexer_refresh(self):
        placeholder = {"generated_at": "now", "materialization": {"status": "rollup", "exact": True}}
        with patch.object(server, "_overview_cache_read", return_value=None), \
             patch.object(server, "_overview_refresh_async") as refresh, \
             patch.object(server, "_materialized_overview", return_value=placeholder), \
             patch.object(server, "_overview") as overview:
            result = server._overview_cached({"range": "30d"})
        self.assertEqual(result["cache"]["status"], "rollup")
        refresh.assert_not_called()
        overview.assert_not_called()

    def test_materialized_overview_marks_decoder_coverage_as_unavailable(self):
        window = {"requested": "7d", "label": "7 days", "bounds": {"gte": "now-7d", "lt": "now"}}
        rollup = {
            "coverage": {"complete": False, "rows": 2,
                          "gaps": {"coverage_percent": 12.43, "missing": 100}},
            "timeline": [{"key": "2026-09-20T00:00:00Z", "doc_count": 42}],
            "dimensions": {}, "bucket_minutes": 5,
        }
        with patch.object(server.automation, "history_summary", return_value={"totals": {}}), \
             patch.object(server.automation, "report_timeline", return_value=[]), \
             patch.object(server.pipeline, "rollup_summary", return_value=rollup):
            result = server._materialized_overview(window, {"range": "7d"})
        quality = result["operational_evidence"]["data_quality"]
        self.assertEqual(quality["indexed_events"], 42)
        self.assertEqual(quality["rollup_coverage_percent"], 12.43)
        self.assertIsNone(quality["decoder_coverage_percent"])
        self.assertTrue(quality["partial"])

    def test_finding_case_sync_reuses_case_and_records_analyst_verdict(self):
        calls = []

        def normalized(source, name, arguments):
            calls.append((source, name, arguments))
            if name == "blueteam_case_list":
                return {"ok": True, "json": [{"case_id": "case_existing", "title": "Finding: Scanner", "revision": 2}]}
            if name == "blueteam_case_add_evidence":
                return {"ok": True, "json": {"case_id": "case_existing", "revision": 3}}
            return {"ok": True, "json": {"status": "recorded"}, "duration_ms": 3}

        with patch.object(server, "_normalized_call", side_effect=normalized):
            result = server._sync_finding_case(
                {"id": "ip:8.8.8.8", "category": "ip", "title": "Scanner", "ip": "8.8.8.8"},
                "false_positive", "Approved scanner", {
                    "contract": {"id": "senior-soc-ai", "version": "1.0.0"},
                    "summary": "Repeated scan matches approved scanner", "source_facts": ["Wazuh rule 31101"],
                    "inference": "Likely authorized scan", "gaps": ["No change ticket attached"],
                    "actions": {"l1": [], "l2": [], "l3": [], "response": []},
                    "verdict": {"status": "suspicious", "confidence": "high"},
                })
        self.assertTrue(result["ok"])
        self.assertEqual(result["case_id"], "case_existing")
        evidence = next(call for call in calls if call[1] == "blueteam_case_add_evidence")
        self.assertEqual(evidence[2]["expected_revision"], 2)
        self.assertTrue(evidence[2]["payload"]["advisory_only"])
        self.assertIn("gaps", evidence[2]["payload"]["advisory"])
        mark = next(call for call in calls if call[1] == "blueteam_mark_investigated")
        self.assertEqual(mark[2]["verdict"], "false_positive")
        self.assertEqual(mark[2]["expected_revision"], 3)
        self.assertIn("AI advisory", mark[2]["notes"])

    def test_finding_case_sync_skips_non_ip_without_side_effects(self):
        with patch.object(server, "_normalized_call") as call:
            result = server._sync_finding_case(
                {"id": "cve:CVE-2026-1", "category": "vuln", "title": "CVE-2026-1"},
                "needs_review")
        self.assertTrue(result["skipped"])
        call.assert_not_called()

    def test_finding_case_sync_creates_missing_case(self):
        calls = []

        def normalized(source, name, arguments):
            calls.append((name, arguments))
            if name == "blueteam_case_list":
                return {"ok": True, "json": []}
            if name == "blueteam_case_create":
                return {"ok": True, "json": {"case_id": "case_new", "revision": 1}}
            return {"ok": True, "json": {"status": "recorded"}}

        with patch.object(server, "_normalized_call", side_effect=normalized):
            result = server._sync_finding_case(
                {"id": "ip:1.1.1.1", "category": "ip", "title": "New source", "ip": "1.1.1.1"},
                "escalated", "Correlated activity")
        self.assertTrue(result["ok"])
        self.assertEqual([name for name, _ in calls], [
            "blueteam_case_list", "blueteam_case_create", "blueteam_mark_investigated"
        ])
        self.assertEqual(calls[-1][1]["case_id"], "case_new")


if __name__ == "__main__":
    unittest.main()
