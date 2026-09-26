"""Static regression checks for bounded dashboard view lifecycle behavior."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class FrontendLifecycleTests(unittest.TestCase):
    def test_ai_provenance_is_visible_without_claiming_semantic_validation(self):
        automation = (ROOT / "static" / "automation.js").read_text(encoding="utf-8")
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn("not whether evidence meaning supports the claim", automation)
        self.assertIn("semantic support is not assessed", findings)
        self.assertIn("semantic support not assessed", automation)
        self.assertIn("row.evidence_ids || row.evidence || []", automation)
        self.assertIn("reference_validation", (ROOT / "soc_automation.py").read_text(encoding="utf-8"))
        self.assertIn("Reference ID available in input context", findings)
        self.assertIn("/api/findings/ai-history", findings)
        self.assertIn('self.path == "/api/findings/ai-history"', server)

    def test_defender_alerts_are_collected_and_rendered_as_alert_records(self):
        collector = (ROOT / "defender_xdr.py").read_text(encoding="utf-8")
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        history = (ROOT / "static" / "history.js").read_text(encoding="utf-8")
        self.assertIn('"alerts": {"path": "/v1.0/security/alerts_v2"', collector)
        self.assertIn("recent_alerts", findings)
        self.assertIn("Open alert in Microsoft Defender", findings)
        self.assertIn("record_type === 'alert'", history)

    def test_coverage_is_limited_to_evidence_views(self):
        source = (ROOT / "static" / "analysis-workspace.js").read_text(encoding="utf-8")
        self.assertIn('const coverageViews = new Set(["findings", ...areas]);', source)
        self.assertIn('if (!coverageEnabled(state.view)) return;', source)
        self.assertIn('view === "command" && new URLSearchParams(window.location.search).get("enterprise") === "1"', source)

    def test_overview_does_not_automatically_enrich_first_indicator(self):
        source = (ROOT / "static" / "analysis-workspace.js").read_text(encoding="utf-8")
        load_start = source.index("async function loadCoverage")
        load_end = source.index('document.addEventListener("soc:overview"', load_start)
        self.assertNotIn("analyze(a.selected)", source[load_start:load_end])

    def test_coverage_is_reused_for_the_same_window(self):
        source = (ROOT / "static" / "analysis-workspace.js").read_text(encoding="utf-8")
        self.assertIn("a.coverage && a.coverageWindow === windowKey", source)
        self.assertIn("Date.now() - a.coverageLoadedAt < 120000", source)
        self.assertIn("a.loadingWindow === windowKey", source)

    def test_overview_renders_only_the_active_view(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        render_start = source.index("function renderOverview(data)")
        render_end = source.index("async function postJson", render_start)
        render_body = source[render_start:render_end]
        self.assertIn("renderView(state.view, data);", render_body)
        self.assertNotIn("renderPosture(data);", render_body)
        self.assertNotIn("renderIncidentBoard(data);", render_body)

    def test_case_store_is_loaded_only_for_case_owning_views(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('if (["incidents", "l1"].includes(state.view)) void loadPersistentCases();', source)

    def test_findings_network_work_is_gated_by_active_view(self):
        source = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        self.assertIn("if (findingsActive())", source)
        self.assertIn('if (event.detail.view !== "findings") return;', source)

    def test_findings_and_coverage_hydrate_overview_if_initial_event_was_missed(self):
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        workspace = (ROOT / "static" / "analysis-workspace.js").read_text(encoding="utf-8")
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("if (state.overview) receiveOverview(state.overview);", findings)
        self.assertIn("if (state.overview && coverageEnabled(state.view)) setTimeout(loadCoverage, 0);", workspace)
        self.assertIn("findings.js?v=20260925-4", html)
        self.assertIn("analysis-workspace.js?v=20260925-3", html)

    def test_findings_renderer_surfaces_bad_payload_instead_of_sticking_on_loading(self):
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("function buildRowsFromData()", findings)
        self.assertIn("Findings could not be rendered", findings)
        self.assertIn("Security Findings module failed", app)
        self.assertIn("Unable to load ${scriptUrl}", app)
        self.assertIn('findings: "Security Findings"', app)
        self.assertIn("app.js?v=20260926-25", html)
        self.assertIn("findings.js?v=20260925-4", html)

    def test_findings_fall_back_to_available_overview_and_show_coverage_state(self):
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        workspace = (ROOT / "static" / "analysis-workspace.js").read_text(encoding="utf-8")
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("f.coverage?.rules?.length ? f.coverage.rules : d.threats", findings)
        self.assertIn("d.operational_evidence?.decoders?.items", findings)
        self.assertIn('setCoverageStatus("error", e.message)', workspace)
        self.assertIn('id="findingsScope"', html)
        self.assertIn('alertCount == null ? "-"', findings)
        self.assertIn('d.detail_materialization?.status === "building"', findings)
        self.assertIn('overview.detail_materialization?.status === "building"', (ROOT / "static" / "app.js").read_text(encoding="utf-8"))
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('"l1": {"status": l1_detail_status, "message": l1_detail_message}', server)
        self.assertIn('correlation_groups', (ROOT / "static" / "app.js").read_text(encoding="utf-8"))
        self.assertIn("Candidates are not confirmed incidents or attack paths", (ROOT / "static" / "app.js").read_text(encoding="utf-8"))
        self.assertIn('DASHBOARD_BUILD_ID = "2026-09-26-patch29"', server)

    def test_workflow_runner_is_centralized_in_tool_console(self):
        source = (ROOT / "static" / "workflows.js").read_text(encoding="utf-8")
        self.assertIn('const menus = ["tools"];', source)
        self.assertIn('state.tools.filter(t => t.workflow)', source)
        self.assertIn('{ menu: null, start, end }', source)

    def test_exposure_graph_has_no_static_environment_entities(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("DVWA/app logs", source)
        self.assertNotIn('title: "SQL server"', source)

    def test_duplicate_operational_panels_have_single_owner(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn('id="l1Agents"', html)
        self.assertNotIn('id="workbenchProviderDeck"', html)
        self.assertNotIn('id="findingHealth"', html)
        self.assertIn('id="agentTable"', html)
        self.assertIn('id="providerIntelGrid"', html)

    def test_command_center_keeps_executive_scope_and_details_have_owners(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        command = html[html.index('id="commandView"'):html.index('id="workbenchView"')]
        self.assertNotIn('id="attackMap"', command)
        self.assertNotIn('id="detectionLayers"', command)
        self.assertNotIn('id="cloudM365Panel"', command)
        self.assertNotIn('id="socDataCoverage"', command)
        self.assertNotIn('id="sourceIpList"', command)
        self.assertIn('id="attackMap"', html[html.index('id="l3View"'):html.index('id="vulnView"')])

    def test_range_refresh_reuses_configuration_and_tool_inventory(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('const settingsPromise = state.settings ? Promise.resolve()', source)
        self.assertIn('const toolsPromise = state.tools.length ? Promise.resolve()', source)

    def test_removed_panels_do_not_leave_dead_renderers_or_polling(self):
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        findings = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        automation = (ROOT / "static" / "automation.js").read_text(encoding="utf-8")
        self.assertNotIn("function renderCoverageGrid", app)
        self.assertNotIn("function renderHealth", findings)
        self.assertNotIn("'settings','workbench','l1','l2'", automation)

    def test_incident_ui_consumes_server_pagination(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="incidentPager"', html)
        self.assertIn('data-case-page="next"', source)
        self.assertIn('offset, limit: state.casePagination.limit', source)

    def test_command_situation_uses_case_store_entity_contract_and_marks_unknowns(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('entity.entity_type', source)
        self.assertIn('entity.entity_value', source)
        self.assertIn('groups.status === "partial"', source)
        self.assertIn('"Not configured"', source)
        self.assertIn('"Unknown"', source)
        self.assertIn('id="situationDecision"', html)
        self.assertIn('data.attack_activity', source)
        self.assertIn('data-view-link="${esc(item.view)}"', source)
        self.assertIn('not proof that an attack succeeded', source)

    def test_case_timeline_is_evidence_sequence_not_attack_path(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('postJson("/api/incidents/timeline"', source)
        self.assertIn("Chronological evidence linked to case entities", source)
        self.assertIn("This is not an attack path", source)
        self.assertIn("No explicit ATT&amp;CK technique mapping stored", source)
        self.assertIn('self.path == "/api/incidents/timeline"', server)

    def test_incident_detail_is_an_editable_versioned_workspace(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        for action in ("assign", "status", "note", "evidence", "containment", "resolve", "reopen", "close"):
            self.assertIn(f'data-case-action="{action}"', source)
        self.assertIn('expected_revision: number(record.revision)', source)
        self.assertIn('postJson("/api/incidents/get"', source)
        self.assertIn('postJson("/api/incidents/action"', source)
        self.assertIn('error.payload?.error === "revision_conflict"', source)

    def test_detection_readiness_uses_explicit_contract_states(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        layer_start = source.index("function renderDetectionLayers")
        layer_end = source.index("function renderCloudM365", layer_start)
        self.assertNotIn('status === "active"', source[layer_start:layer_end])
        for status in ("ready", "observed_incomplete", "degraded", "stale", "not_observed"):
            self.assertIn(status, source)
            self.assertIn(f".telemetrySource.{status}", styles)

    def test_historical_unknowns_are_not_rendered_as_zero_or_empty_findings(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('data.agents?.status === "unavailable"', source)
        self.assertIn('data.alerts?.severity_status === "unavailable"', source)
        self.assertIn('cloud.status === "unavailable"', source)
        self.assertIn('vulns.status === "partial"', source)
        self.assertIn('"sampled": None', server)
        self.assertIn('"total": None, "workloads": [], "operations": [], "client_ips": [], "events": []', server)

    def test_runtime_build_identity_is_visible_for_deployment_verification(self):
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        deploy_check = (ROOT.parent / "tools" / "check_dashboard_deploy.sh").read_text(encoding="utf-8")
        self.assertIn('build ${overview.build_id || "unknown"}', source)
        self.assertIn('DASHBOARD_BUILD_ID = "2026-09-26-patch29"', server)
        self.assertIn("Shared dashboard/materializer code parity", deploy_check)
        self.assertIn("mcp-dashboard mcp-materializer", deploy_check)

    def test_cached_overview_keeps_snapshot_provenance_and_stamps_service_build(self):
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn("def _stamp_overview_service_identity", server)
        self.assertIn('data.setdefault("snapshot_build_id", snapshot_build)', server)
        self.assertIn('data["service_build_id"] = DASHBOARD_BUILD_ID', server)

    def test_runtime_smoke_waits_for_the_requested_range_after_hash_navigation(self):
        source = (ROOT / "check_findings_ui.py").read_text(encoding="utf-8")
        self.assertIn("state.overview?.window?.range === expected", source)
        self.assertIn("state.overviewLoad?.windowKey === JSON.stringify(currentWindowPayload())", source)


if __name__ == "__main__":
    unittest.main()
