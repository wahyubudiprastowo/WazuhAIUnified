"""The optional enterprise overlay must not hide established dashboard panels by default."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class EnterpriseOverlayTests(unittest.TestCase):
    def test_overlay_is_explicitly_opt_in(self):
        source = (ROOT / "static" / "enterprise.js").read_text(encoding="utf-8")
        self.assertIn('get("enterprise") !== "1") return;', source)

    def test_overlay_styles_do_not_hide_default_dashboard_panels(self):
        stylesheet = (ROOT / "static" / "enterprise.css").read_text(encoding="utf-8")
        self.assertNotIn("#commandView .coveragePanel { display: none; }", stylesheet)

    def test_findings_module_does_not_override_the_startup_route(self):
        source = (ROOT / "static" / "findings.js").read_text(encoding="utf-8")
        executable = [line.strip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith("//")]
        self.assertNotEqual(executable[-2], 'setView("findings");')


if __name__ == "__main__":
    unittest.main()
