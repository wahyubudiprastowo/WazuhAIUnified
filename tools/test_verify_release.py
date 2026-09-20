import hashlib
import tempfile
import unittest
from pathlib import Path

import verify_release


class ReleaseScannerTests(unittest.TestCase):
    def test_fingerprint_matches_assignment_and_url_component(self):
        value = 'revoked-test-token-123'
        fingerprints = {hashlib.sha256(value.encode()).hexdigest()}
        self.assertTrue(verify_release.contains_known_leak(f'API_KEY={value}', fingerprints))
        self.assertTrue(verify_release.contains_known_leak(f'https://host/{value}/v1', fingerprints))
        self.assertFalse(verify_release.contains_known_leak('API_KEY=__API_KEY__', fingerprints))

    def test_markdown_and_examples_are_not_blanket_exempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'notes.md'
            marker = '-----BEGIN ' + 'PRIVATE KEY-----'
            path.write_text(marker + '\nnot-a-real-key')
            self.assertTrue(verify_release.scan_text(path, 'notes.md'))
            example = Path(directory) / 'service.env.example'
            example.write_text('SERVICE_API_KEY=real-looking-token')
            self.assertTrue(verify_release.scan_text(example, 'service.env.example'))


if __name__ == '__main__':
    unittest.main()
