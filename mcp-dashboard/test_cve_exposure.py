import unittest

from cve_exposure import build_exposure_graph, normalize_cmdb_asset, parse_cpe
from soc_contract import CONTRACT_VERSION, apply_contract


class CpeTests(unittest.TestCase):
    def test_cpe_23_is_parsed_and_invalid_value_is_not_silently_accepted(self):
        valid = parse_cpe("cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*")
        self.assertTrue(valid["valid"])
        self.assertEqual(valid["vendor"], "fortinet")
        self.assertEqual(valid["version"], "7.4.3")
        invalid = parse_cpe("cpe:/a:vendor:product")
        self.assertFalse(invalid["valid"])
        self.assertEqual(invalid["status"], "invalid")

    def test_cmdb_old_shape_remains_valid_and_components_are_normalized(self):
        asset = normalize_cmdb_asset({
            "agent_id": "007", "host": "edge.internal", "vendor": "Fortinet", "version": "7.4.3",
            "cpe": "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
            "patch_state": "pending", "internet_exposed": True,
        })
        self.assertEqual(asset["cpe_status"], "valid")
        self.assertEqual(asset["component_count"], 1)
        self.assertEqual(asset["components"][0]["patch_state"], "pending")

    def test_sample_cmdb_is_retained_but_not_authoritative(self):
        asset = normalize_cmdb_asset({
            "agent_id": "001", "host": "sample.internal", "owner": "Example owner",
            "purpose": "SAMPLE - replace with verified inventory before production",
        })
        self.assertEqual(asset["quality_status"], "sample")
        self.assertFalse(asset["authoritative"])


class ExposureGraphTests(unittest.TestCase):
    def test_graph_links_inventory_cmdb_signals_and_case(self):
        cmdb = [normalize_cmdb_asset({
            "agent_id": "007", "name": "Edge Firewall", "owner": "Network SOC",
            "criticality": "critical", "internet_exposed": True,
            "components": [{
                "name": "fortios", "version": "7.4.3",
                "cpe": "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
                "patch_state": "pending",
            }],
        })]
        items = [{
            "agent": {"id": "007", "name": "edge.internal"},
            "package": {"name": "fortios", "version": "7.4.3"},
            "vulnerability": {"id": "CVE-2026-12345", "severity": "Critical"},
            "in_kev": True, "has_poc": True, "observed_exploitation": False,
            "case_id": "CASE-42",
        }]
        graph = build_exposure_graph(items, cmdb)
        self.assertEqual(graph["summary"]["paths"], 1)
        self.assertEqual(graph["summary"]["valid_cpe"], 1)
        self.assertEqual(graph["summary"]["case_linked"], 1)
        path = graph["paths"][0]
        self.assertEqual(path["owner"], "Network SOC")
        self.assertEqual(path["patch_state"], "pending")
        self.assertTrue(path["kev"])
        self.assertTrue(any(edge["relationship"] == "tracked_by" for edge in graph["edges"]))

    def test_graph_is_bounded_and_does_not_claim_exploitation(self):
        items = [{
            "agent": {"id": str(index)}, "package": {"name": "pkg"},
            "vulnerability": {"id": f"CVE-2026-{10000 + index}", "severity": "High"},
        } for index in range(5)]
        graph = build_exposure_graph(items, [], max_paths=2)
        self.assertTrue(graph["bounded"])
        self.assertEqual(len(graph["paths"]), 2)
        self.assertTrue(all(row["exposure_state"] == "inventory_confirmed" for row in graph["paths"]))
        self.assertTrue(all(row["observed_exploitation"] is None for row in graph["paths"]))

    def test_graph_reuses_cached_cve_enrichment_without_provider_calls(self):
        items = [{
            "agent": {"id": "1"}, "package": {"name": "openssl"},
            "vulnerability": {"id": "CVE-2026-99999", "severity": "High"},
            "intelligence": {"cve": {"data": {"components": {
                "epss_probability": 0.42, "in_kev": True, "poc_confidence": "confirmed",
            }}}},
        }]
        path = build_exposure_graph(items, [])["paths"][0]
        self.assertEqual(path["epss"], 0.42)
        self.assertTrue(path["kev"])
        self.assertTrue(path["poc"])

    def test_graph_keeps_organization_cve_context_as_non_exploit_evidence(self):
        items = [{
            "agent": {"id": "1"}, "package": {"name": "openssl"},
            "vulnerability": {"id": "CVE-2026-77777", "severity": "High"},
            "cyfirma_org_vulnerability": [{"name": "CYFIRMA advisory", "confidence": 80}],
        }]
        graph = build_exposure_graph(items, [])
        path = graph["paths"][0]
        self.assertEqual(path["cyfirma_org_records"], 1)
        self.assertIsNone(path["observed_exploitation"])
        self.assertIn("CYFIRMA Organization Vulnerability V2 STIX local ledger", path["provenance"])

    def test_sample_asset_cannot_attach_context_to_a_real_agent_with_same_id(self):
        sample = normalize_cmdb_asset({
            "agent_id": "001", "owner": "Example owner", "internet_exposed": True,
            "cpe": "cpe:2.3:a:example:portal:1.0:*:*:*:*:*:*:*",
            "purpose": "SAMPLE - replace before production",
        })
        item = {"agent": {"id": "001", "name": "real-server"},
                "package": {"name": "openssl", "version": "3.0.0"},
                "vulnerability": {"id": "CVE-2026-70001", "severity": "High"}}
        graph = build_exposure_graph([item], [sample])
        path = graph["paths"][0]
        self.assertEqual(path["asset_match"], "unmatched")
        self.assertIsNone(path["owner"])
        self.assertIsNone(path["internet_exposed"])
        self.assertEqual(path["cpe_status"], "missing")
        self.assertEqual(path["patch_state"], "unknown")
        self.assertEqual(path["patch_evidence"],
                         "Patch state not supplied; active Wazuh CVE finding is not patch verification")
        self.assertEqual(graph["coverage"]["patch_state"], 0)
        self.assertEqual(graph["cmdb_quality"]["sample"], 1)

    def test_patch_coverage_requires_an_explicit_inventory_or_cmdb_state(self):
        item = {"agent": {"id": "007"}, "package": {"name": "openssl"},
                "vulnerability": {"id": "CVE-2026-70006", "severity": "High"}}
        absent = build_exposure_graph([item], [])
        self.assertEqual(absent["paths"][0]["patch_state"], "unknown")
        self.assertEqual(absent["coverage"]["patch_state"], 0)

        explicit = {**item, "package": {"name": "openssl", "patch_state": "pending"}}
        measured = build_exposure_graph([explicit], [])
        self.assertEqual(measured["paths"][0]["patch_state"], "pending")
        self.assertEqual(measured["coverage"]["patch_state"], 1)

    def test_asset_cpe_is_only_used_for_matching_package_and_version(self):
        asset = normalize_cmdb_asset({
            "agent_id": "007", "owner": "Platform", "application": "web portal",
            "vendor": "F5", "version": "1.24.0",
            "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
        })
        unrelated = {"agent": {"id": "007"}, "package": {"name": "perl", "version": "5.0"},
                     "vulnerability": {"id": "CVE-2026-70002", "severity": "High"}}
        mismatch = {"agent": {"id": "007"}, "package": {"name": "nginx", "version": "1.25.0"},
                    "vulnerability": {"id": "CVE-2026-70003", "severity": "High"}}
        matching = {"agent": {"id": "007"}, "package": {"name": "nginx", "version": "1.24.0-2"},
                    "vulnerability": {"id": "CVE-2026-70004", "severity": "High"}}
        paths = build_exposure_graph([unrelated, mismatch, matching], [asset])["paths"]
        by_cve = {row["cve"]: row for row in paths}
        self.assertEqual(by_cve["CVE-2026-70002"]["component_match"], "package_unmatched")
        self.assertEqual(by_cve["CVE-2026-70002"]["cpe_status"], "missing")
        self.assertEqual(by_cve["CVE-2026-70003"]["component_match"], "version_mismatch")
        self.assertEqual(by_cve["CVE-2026-70003"]["cpe_status"], "missing")
        self.assertEqual(by_cve["CVE-2026-70004"]["component_match"], "package_version")
        self.assertEqual(by_cve["CVE-2026-70004"]["cpe_status"], "valid")

    def test_graph_links_only_explicit_materialized_case_entities(self):
        item = {"agent": {"id": "7"}, "package": {"name": "openssl", "version": "3.0"},
                "vulnerability": {"id": "CVE-2026-70005", "severity": "High"}}
        path = build_exposure_graph(
            [item], [], case_links={"CVE-2026-70005": ["case_1", "case_2"]}
        )["paths"][0]
        self.assertEqual(path["case_id"], "case_1")
        self.assertEqual(path["case_ids"], ["case_1", "case_2"])


class SeniorSocContractTests(unittest.TestCase):
    def test_contract_normalizes_unsupported_enums_without_dropping_fields(self):
        result = apply_contract({
            "summary": "Evidence review", "verdict": {
                "status": "owned", "severity": "urgent", "confidence": "certain", "reason": "unsupported labels",
            },
            "source_facts": ["event-1"], "gaps": [], "custom_field": "preserved",
        }, "finding")
        self.assertEqual(result["contract"]["version"], CONTRACT_VERSION)
        self.assertEqual(result["contract"]["validation_status"], "normalized")
        self.assertEqual(result["verdict"]["status"], "needs_review")
        self.assertEqual(result["verdict"]["severity"], "unknown")
        self.assertEqual(result["verdict"]["confidence"], "low")
        self.assertIn("inference is required", result["contract"]["violations"])
        self.assertIn("actions must be an object", result["contract"]["violations"])
        self.assertEqual(result["custom_field"], "preserved")

    def test_contract_is_valid_only_when_all_required_sections_are_present(self):
        incomplete = apply_contract({
            "summary": "Assessment", "verdict": {"status": "needs_review", "severity": "low",
                                                      "confidence": "low", "reason": "Pending review"},
            "source_facts": [], "inference": "Observed fields need analyst validation.", "gaps": [],
        }, "finding")
        self.assertEqual(incomplete["contract"]["validation_status"], "normalized")
        self.assertIn("actions must be an object", incomplete["contract"]["violations"])

        complete = apply_contract({
            "summary": "Assessment", "verdict": {"status": "needs_review", "severity": "low",
                                                      "confidence": "low", "reason": "Pending review"},
            "source_facts": ["event-1"], "inference": "Observed fields need analyst validation.",
            "actions": {lane: [] for lane in ("l1", "l2", "l3", "response")}, "gaps": [],
        }, "finding")
        self.assertEqual(complete["contract"]["validation_status"], "valid")


if __name__ == "__main__":
    unittest.main()
