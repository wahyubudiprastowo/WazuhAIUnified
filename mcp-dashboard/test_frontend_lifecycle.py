"""Static regression checks for bounded dashboard view lifecycle behavior."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class FrontendLifecycleTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
