"""Browser regressions using real dashboard assets and isolated synthetic APIs.

Run with a Python environment containing Playwright and Chromium:
    python -m unittest test_browser_findings
No production server, provider, database or AI endpoint is used.
"""
import asyncio
import json
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None


ROOT = Path(__file__).parent


class AssetHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path.split('?')[0] == '/':
            self.path = '/static/index.html'
        super().do_GET()

    def log_message(self, *_args):
        pass


def overview(window='24h'):
    """Synthetic telemetry for client contract tests, never production data."""
    return {
        'requested_range': window, 'window': {'range': window},
        'generated_at': '2026-09-25T10:00:00Z',
        'build_id': 'browser-fixture', 'cache': {'status': 'hit'},
        'alerts': {'status': 'available', 'total_alerts': 3},
        'threats': [{'rule_id': f'fixture-{window}', 'description': f'Fixture {window}',
                     'level': 12, 'count': 3, 'groups': ['authentication']}],
        'tools': {'total': 0}, 'errors': {},
    }


@unittest.skipIf(async_playwright is None, 'Playwright is required for browser verification')
class FindingsBrowserTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = ThreadingHTTPServer(('127.0.0.1', 0), AssetHandler)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.http.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join()

    async def asyncSetUp(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context(viewport={'width': 1440, 'height': 1000})
        self.page = await self.context.new_page()
        self.errors = []
        self.calls = []
        self.overview_calls = 0
        self.overview_hook = None
        self.coverage_hook = None
        self.settings_error = False
        self.page.on('pageerror', lambda error: self.errors.append(str(error)))
        await self.context.route('**/*', self.route)

    async def asyncTearDown(self):
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def route(self, route):
        request = route.request
        if not request.url.startswith(self.url):
            return await route.abort()
        path = request.url[len(self.url):].split('?')[0]
        if not path.startswith('/api/'):
            return await route.continue_()
        body = request.post_data_json or {}
        self.calls.append((path, body))
        data = {}
        status = 200
        if path == '/api/overview':
            self.overview_calls += 1
            if self.overview_hook:
                data, status = await self.overview_hook(body, self.overview_calls)
            else:
                data = overview(body.get('range', '24h'))
        elif path == '/api/settings':
            if self.settings_error:
                return await route.fulfill(status=401, body='')
            data = {'fields': [], 'config': {'fields': []}}
        elif path == '/api/tools':
            data = {'tools': [], 'summary': {}, 'categories': {}}
        elif path == '/api/analysis/coverage':
            data = {'ok': True, 'rules': [], 'decoders': [], 'observables': [],
                    'range': body.get('range', '24h'), 'total_events': 3}
            if self.coverage_hook:
                data, status = await self.coverage_hook(body)
        elif path == '/api/findings/ai-jobs':
            data = {'counts': {}, 'recent': []}
        elif path == '/api/automation/status':
            data = {'latest': None, 'history': []}
        return await route.fulfill(status=status, content_type='application/json', body=json.dumps(data))

    async def open(self, window='24h'):
        await self.page.goto(f'{self.url}/#view=findings&range={window}', wait_until='load')
        await self.page.wait_for_function('window.SocFindings?.ready === true')

    async def wait_row(self, window):
        await self.page.locator(f'[data-finding-id="rule:fixture-{window}"]').wait_for()

    async def test_real_assets_initialize_and_render_overview_on_direct_route(self):
        await self.open()
        await self.wait_row('24h')
        self.assertEqual(self.errors, [])
        self.assertEqual(await self.page.locator('.findingAiButton').count(), 1)
        self.assertFalse(any(path in {'/api/findings/ai-analysis', '/api/findings/intel', '/api/call'}
                             for path, _ in self.calls))

    async def test_late_old_window_response_cannot_replace_selected_range(self):
        old_started = asyncio.Event()
        release_old = asyncio.Event()

        async def delayed(body, number):
            if number == 1:
                old_started.set()
                await release_old.wait()
            return overview(body.get('range', '24h')), 200

        self.overview_hook = delayed
        await self.open()
        await asyncio.wait_for(old_started.wait(), 5)
        await self.page.select_option('#rangeSelect', '7d')
        await self.wait_row('7d')
        async with self.page.expect_response(lambda r: r.url.endswith('/api/overview')
                                             and r.request.post_data_json.get('range') == '24h'):
            release_old.set()
        await self.page.wait_for_timeout(150)
        self.assertEqual(await self.page.evaluate('state.overview.window.range'), '7d')
        self.assertEqual(await self.page.locator('[data-finding-id="rule:fixture-24h"]').count(), 0)
        self.assertEqual(self.errors, [])

    async def test_initial_overview_failure_exits_findings_loading(self):
        async def failure(_body, _number):
            return {'error': 'Fixture overview unavailable'}, 503

        self.overview_hook = failure
        await self.open()
        await self.page.wait_for_function("document.querySelector('#status').textContent.includes('Fixture overview unavailable')")
        self.assertNotIn('Loading findings', await self.page.locator('#findingsCount').inner_text())
        self.assertNotIn('Waiting for telemetry', await self.page.locator('#findingDetail').inner_text())
        self.assertIn('Fixture overview unavailable', await self.page.locator('#findingsScope').inner_text())
        self.assertEqual(self.errors, [])

    async def test_dependency_auth_failure_does_not_abort_or_leave_unhandled_rejection(self):
        async def delayed(body, _number):
            await asyncio.sleep(0.35)
            return overview(body.get('range', '24h')), 200

        self.overview_hook = delayed
        self.settings_error = True
        await self.open()
        await self.wait_row('24h')
        await self.page.wait_for_timeout(100)
        self.assertEqual(self.errors, [])

    async def test_failed_refresh_keeps_last_good_findings_visible(self):
        await self.open()
        await self.wait_row('24h')

        async def failure(_body, _number):
            return {'error': 'Fixture refresh unavailable'}, 503

        self.overview_hook = failure
        await self.page.click('#refreshBtn')
        await self.page.wait_for_function("document.querySelector('#status').textContent.includes('Fixture refresh unavailable')")
        await self.wait_row('24h')
        self.assertIn('Fixture refresh unavailable', await self.page.locator('#findingsScope').inner_text())
        self.assertEqual(self.errors, [])

    async def test_null_overview_is_rejected_and_does_not_erase_last_good_data(self):
        await self.open()
        await self.wait_row('24h')

        async def null_response(_body, _number):
            return None, 200

        self.overview_hook = null_response
        await self.page.click('#refreshBtn')
        await self.page.wait_for_function("document.querySelector('#status').textContent.includes('invalid overview payload')")
        await self.wait_row('24h')
        self.assertEqual(await self.page.evaluate('state.overview.window.range'), '24h')
        self.assertEqual(self.errors, [])

    async def test_old_coverage_cannot_publish_into_new_window(self):
        coverage_started = asyncio.Event()
        release_coverage = asyncio.Event()
        release_overview = asyncio.Event()

        async def delayed_coverage(body):
            if body.get('range') == '24h':
                coverage_started.set()
                await release_coverage.wait()
            return {'ok': True, 'total_events': 987, 'rules': [], 'observables': [], 'decoders': []}, 200

        async def delayed_overview(body, _number):
            if body.get('range') == '7d':
                await release_overview.wait()
            return overview(body.get('range', '24h')), 200

        self.coverage_hook = delayed_coverage
        self.overview_hook = delayed_overview
        await self.open()
        await self.wait_row('24h')
        await asyncio.wait_for(coverage_started.wait(), 5)
        await self.page.evaluate("() => { window.coveragePublications = []; const original = window.SocFindings.setCoverage; window.SocFindings.setCoverage = data => { window.coveragePublications.push(data.total_events); original(data); }; }")
        await self.page.select_option('#rangeSelect', '7d')
        async with self.page.expect_response(lambda r: r.url.endswith('/api/analysis/coverage')):
            release_coverage.set()
        await self.page.wait_for_timeout(100)
        self.assertEqual(await self.page.evaluate('window.coveragePublications'), [])
        self.assertEqual(await self.page.locator('.findingRow').count(), 0)
        release_overview.set()
        await self.wait_row('7d')
        self.assertEqual(self.errors, [])

    async def test_direct_routes_reload_and_back_keep_window_and_mobile_content(self):
        for window in ('24h', '7d', '30d', 'custom'):
            with self.subTest(window=window):
                suffix = '&start=2026-09-20T00:00:00Z&end=2026-09-21T00:00:00Z' if window == 'custom' else ''
                await self.page.goto(f'{self.url}/#view=findings&range={window}{suffix}')
                await self.wait_row(window)
                await self.page.reload(wait_until='load')
                await self.wait_row(window)
                self.assertEqual(await self.page.input_value('#rangeSelect'), window)
        await self.page.select_option('#rangeSelect', '7d')
        await self.wait_row('7d')
        await self.page.go_back()
        await self.wait_row('custom')
        await self.page.go_forward()
        await self.wait_row('7d')
        for width in (1440, 1024, 768, 390):
            await self.page.set_viewport_size({'width': width, 'height': 1000})
            overflow = await self.page.evaluate("() => [...document.querySelectorAll('body *')].filter(el => el.getBoundingClientRect().right > innerWidth + 1 && el.getBoundingClientRect().width > 0).slice(0, 8).map(el => ({tag: el.tagName, id: el.id, class: el.className, right: el.getBoundingClientRect().right}))")
            self.assertFalse(await self.page.evaluate('document.documentElement.scrollWidth > innerWidth'), f'width={width}: {overflow}')
        self.assertEqual(self.errors, [])

    async def test_partial_snapshot_and_coverage_failure_keep_bounded_overview(self):
        async def partial(body, _number):
            data = overview(body.get('range', '24h'))
            data['detail_materialization'] = {'status': 'building'}
            data['alerts'] = {'status': 'materializing', 'total_alerts': None}
            return data, 200

        async def coverage_failure(_body):
            return {'error': 'Fixture coverage unavailable'}, 503

        self.overview_hook = partial
        self.coverage_hook = coverage_failure
        await self.open('30d')
        await self.wait_row('30d')
        await self.page.wait_for_function("document.querySelector('#findingsScope').textContent.includes('Fixture coverage unavailable')")
        self.assertEqual(await self.page.locator('#findingsSummary strong').first.inner_text(), '-')
        self.assertEqual(self.errors, [])

    async def test_timeout_exits_loading_and_allows_retry(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def stalled(body, _number):
            started.set()
            await release.wait()
            return overview(body.get('range', '24h')), 200

        self.overview_hook = stalled
        await self.page.clock.install()
        await self.open()
        await asyncio.wait_for(started.wait(), 5)
        await self.page.clock.fast_forward(31000)
        await self.page.wait_for_function("document.querySelector('#findingsScope').textContent.includes('timed out')")
        self.assertTrue(await self.page.locator('#refreshBtn').is_enabled())
        release.set()
        self.overview_hook = None
        await self.page.click('#refreshBtn')
        await self.wait_row('24h')
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
