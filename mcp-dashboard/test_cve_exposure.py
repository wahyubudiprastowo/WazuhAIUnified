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
        self.assertEqual(result["custom_field"], "preserved")


if __name__ == "__main__":
    unittest.main()
