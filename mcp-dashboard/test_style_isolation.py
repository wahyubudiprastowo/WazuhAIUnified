"""Regression checks for dashboard stylesheet ownership and DOM targets."""

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent


class _IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []

    def handle_starttag(self, _tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])


class StyleIsolationTests(unittest.TestCase):
    def test_findings_styles_do_not_override_the_application_shell(self):
        stylesheet = (ROOT / "static" / "findings.css").read_text(encoding="utf-8")
        shell_selector = re.compile(r"^\s*(?::root|body(?:\b|:)|\.sidebar\b|\.topbar\b|\.app\b|\.glassPanel\b)")
        leaks = [line for line in stylesheet.splitlines() if shell_selector.match(line)]
        self.assertEqual(leaks, [], f"Findings stylesheet must not own the global shell: {leaks}")

    def test_dashboard_dom_ids_are_unique(self):
        parser = _IdCollector()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        duplicates = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
        self.assertEqual(duplicates, [], f"Duplicate DOM targets: {duplicates}")


if __name__ == "__main__":
    unittest.main()
