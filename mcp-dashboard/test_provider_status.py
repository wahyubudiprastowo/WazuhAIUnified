import unittest

from server import _provider_test_status


class ProviderStatusTests(unittest.TestCase):
    def test_error_text_inside_successful_mcp_response(self):
        for message, expected in [
            ("[crowdsec_ip_reputation] Error: Rate limit reached (429).", "rate limited"),
            ("THREATFOX_API_KEY not set", "needs configuration"),
            ("Error: upstream unavailable", "error"),
            ("UNKNOWN - No threat intel sources available", "insufficient data"),
        ]:
            with self.subTest(message=message):
                self.assertEqual(_provider_test_status({"ok": True, "text": message}), (expected, False))

    def test_no_match_is_successful_connection_only(self):
        self.assertEqual(_provider_test_status({"ok": True, "json": {"query_status": "no_results"}}), ("connected; no match", True))

    def test_numeric_ioc_content_does_not_look_like_auth_failure(self):
        result = {
            "ok": True,
            "json": {"provider": "cyfirma", "items": [{"id": "indicator--401403", "labels": ["BLOCK"]}], "errors": {}},
            "text": '{"provider":"cyfirma","items":[{"id":"indicator--401403"}]}',
        }
        self.assertEqual(_provider_test_status(result), ("connected", True))

    def test_structured_error_and_empty_response(self):
        self.assertEqual(_provider_test_status({"ok": True, "json": {"error": "upstream failed"}}), ("error", False))
        self.assertEqual(_provider_test_status({"ok": True}), ("empty response", False))

    def test_feed_indicator_cannot_impersonate_provider_failure(self):
        self.assertEqual(_provider_test_status({"ok": True, "json": {
            "items": [{"id": "indicator--429", "description": "invalid API rate limit"}], "errors": {}},
            "text": 'indicator--429 invalid API rate limit'}), ("connected", True))
        self.assertEqual(_provider_test_status({"ok": True, "json": {
            "errors": {"tailored": "HTTP 429"}}}), ("rate limited", False))
