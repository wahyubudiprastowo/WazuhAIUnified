import base64
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class HttpSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'static').mkdir()
        (self.root / 'static' / 'index.html').write_text('Dashboard')
        (self.root / 'private.env').write_text('private')
        (self.root / 'static' / 'escape').symlink_to(self.root / 'private.env')
        self.patch = patch.multiple(server, STATIC=self.root / 'static', DASHBOARD_ACCESS_TOKEN='')
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.http = server.BoundedThreadingHTTPServer(('127.0.0.1', 0), server.Handler, max_threads=4)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(*self.http.server_address, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_static_and_head_confined(self):
        for method in ('GET', 'HEAD'):
            self.assertEqual(self.request(method, '/')[0], 200)
            for path in ('/static/../private.env', '/static/%2e%2e/private.env', '/static/escape', '/private.env'):
                self.assertEqual(self.request(method, path)[0], 404)

    def test_request_body_and_origin(self):
        self.assertEqual(self.request('POST', '/api/tools', '[]')[0], 400)
        self.assertEqual(self.request('POST', '/api/tools', headers={'Content-Length': '1048577'})[0], 413)
        self.assertEqual(self.request('POST', '/api/tools', '{}', {'Origin': 'https://untrusted.example'})[0], 403)

    def test_optional_auth_and_approval(self):
        with patch.object(server, 'DASHBOARD_ACCESS_TOKEN', 'test-access-token'):
            self.assertEqual(self.request('GET', '/')[0], 401)
            self.assertEqual(self.request('POST', '/api/tools', '{}')[0], 401)
            auth = base64.b64encode(b'soc:test-access-token').decode()
            self.assertEqual(self.request('GET', '/', headers={'Authorization': 'Basic ' + auth})[0], 200)
            wrong_user = base64.b64encode(b'other:test-access-token').decode()
            self.assertEqual(self.request('GET', '/', headers={'Authorization': 'Basic ' + wrong_user})[0], 401)
        with patch.object(server, '_tool_by_name', return_value={'name': 'wazuh_block_ip'}), patch.object(server, '_normalized_call') as call:
            status, _ = self.request('POST', '/api/call', '{"source":"gensecai","name":"wazuh_block_ip","arguments":{}}')
            self.assertEqual(status, 403)
            call.assert_not_called()

    def test_provider_url_masked_without_overwriting_config(self):
        with patch.object(server, 'AI_PROVIDER_BASE_URL', 'https://gateway.example/private-token/v1'):
            field = next(f for f in server._public_config()['fields'] if f['key'] == 'AI_PROVIDER_BASE_URL')
            self.assertEqual(field['value'], '')
            self.assertEqual(field['type'], 'secret')


if __name__ == '__main__':
    unittest.main()
