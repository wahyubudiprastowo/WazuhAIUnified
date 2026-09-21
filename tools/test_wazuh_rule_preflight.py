import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wazuh_rule_preflight import preflight


class WazuhRulePreflightTests(unittest.TestCase):
    def test_duplicate_rules_are_not_planned_as_new(self):
        xml = "<group><rule id='120001' level='3'><decoded_as>fortigate</decoded_as></rule></group>"
        with tempfile.TemporaryDirectory() as root:
            existing, candidate = Path(root, "existing"), Path(root, "candidate")
            existing.mkdir()
            candidate.mkdir()
            (existing / "local.xml").write_text(xml)
            (candidate / "upstream.xml").write_text(xml)
            result = preflight(existing, candidate)
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["plans"][0]["new"])

    def test_conflicting_rule_id_blocks_import(self):
        with tempfile.TemporaryDirectory() as root:
            existing, candidate = Path(root, "existing"), Path(root, "candidate")
            existing.mkdir()
            candidate.mkdir()
            (existing / "local.xml").write_text("<group><rule id='120001' level='3'/></group>")
            (candidate / "upstream.xml").write_text("<group><rule id='120001' level='12'/></group>")
            result = preflight(existing, candidate)
        self.assertTrue(result["errors"])

    def test_wazuh_decoder_fragments_are_inventory_safe(self):
        fragment = "<decoder name='fortigate'><prematch>^date=</prematch></decoder>\n<decoder name='fortigate-fields'><parent>fortigate</parent><regex>srcip=(\\S+)</regex></decoder>"
        with tempfile.TemporaryDirectory() as root:
            existing, candidate = Path(root, "existing"), Path(root, "candidate")
            existing.mkdir()
            candidate.mkdir()
            (candidate / "fortigate.xml").write_text(fragment)
            result = preflight(existing, candidate)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["plans"][0]["decoders"], ["fortigate", "fortigate-fields"])


if __name__ == "__main__":
    unittest.main()
