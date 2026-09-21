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
            })
            self.assertTrue(result["ok"])
            self.assertEqual(call.call_args.args[2]["srcips"], ["8.8.8.8"])

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

    def test_finding_case_sync_reuses_case_and_records_analyst_verdict(self):
        calls = []

        def normalized(source, name, arguments):
            calls.append((source, name, arguments))
            if name == "blueteam_case_list":
                return {"ok": True, "json": [{"case_id": "case_existing", "title": "Finding: Scanner"}]}
            return {"ok": True, "json": {"status": "recorded"}, "duration_ms": 3}

        with patch.object(server, "_normalized_call", side_effect=normalized):
            result = server._sync_finding_case(
                {"id": "ip:8.8.8.8", "category": "ip", "title": "Scanner", "ip": "8.8.8.8"},
                "false_positive", "Approved scanner", {"verdict": {"status": "noise", "confidence": "high"}})
        self.assertTrue(result["ok"])
        self.assertEqual(result["case_id"], "case_existing")
        mark = next(call for call in calls if call[1] == "blueteam_mark_investigated")
        self.assertEqual(mark[2]["verdict"], "false_positive")
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
                return {"ok": True, "json": {"case_id": "case_new"}}
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
