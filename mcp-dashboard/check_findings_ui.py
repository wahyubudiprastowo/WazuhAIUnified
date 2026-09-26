"""Bounded authenticated runtime smoke check; never invokes AI or provider tools.

Run: .ui-check/bin/python mcp-dashboard/check_findings_ui.py [--screenshots]
Artifacts are private and ignored by git and the Docker build context.
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
READ_ENDPOINTS = {
    "/api/overview", "/api/settings", "/api/tools", "/api/analysis/coverage",
    "/api/findings/ai-jobs", "/api/automation/status",
    "/api/intelligence/cyfirma", "/api/intelligence/cyfirma-research",
    "/api/intelligence/defender-xdr", "/api/incidents/list",
    "/api/pipeline/status", "/api/findings/feedback/history",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    parser.add_argument("--env-file", type=Path, default=ROOT / "dashboard.env")
    parser.add_argument("--screenshots", action="store_true")
    args = parser.parse_args()
    cfg = {}
    for line in args.env_file.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            cfg[key.strip()] = value.strip().strip('"').strip("'")
    token = cfg.get("DASHBOARD_ACCESS_TOKEN", "")
    if not token:
        raise SystemExit("DASHBOARD_ACCESS_TOKEN is required")
    secrets = [v for k, v in cfg.items()
               if any(word in k for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")) and v]

    def redact(value):
        result = str(value)
        for secret in secrets:
            result = result.replace(secret, "[REDACTED]")
        return result

    now = datetime.now(timezone.utc)
    output = ROOT / "artifacts" / now.strftime("g00-%Y%m%dT%H%M%SZ")
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    report = {"observed_at": now.isoformat(), "windows": [], "network": [],
              "browser_errors": [], "blocked_actions": [], "assets": {}, "passed": False}
    base = args.base_url.rstrip("/")
    origin = urlsplit(base)
    failure = None
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000}, reduced_motion="reduce",
            http_credentials={"username": cfg.get("DASHBOARD_ACCESS_USERNAME", "soc"),
                              "password": token})

        def route_request(route):
            url = urlsplit(route.request.url)
            if (url.scheme, url.netloc) != (origin.scheme, origin.netloc):
                return route.abort()
            if url.path.startswith("/api/") and url.path not in READ_ENDPOINTS:
                report["blocked_actions"].append(url.path)
                return route.abort()
            return route.continue_()

        context.route("**/*", route_request)
        page = context.new_page()
        page.on("pageerror", lambda error: report["browser_errors"].append(redact(error)))
        page.on("response", lambda response: report["network"].append(
            {"path": urlsplit(response.url).path, "status": response.status})
            if urlsplit(response.url).path.startswith("/api/") else None)
        try:
            for window in ("24h", "7d", "30d", "custom"):
                params = {"view": "findings", "range": window}
                if window == "custom":
                    params.update(start=(now - timedelta(days=2)).strftime("%Y-%m-%dT00:00"),
                                  end=(now - timedelta(days=1)).strftime("%Y-%m-%dT00:00"))
                page.goto(base + "/#" + urlencode(params), wait_until="domcontentloaded")
                # Hash navigation reuses the document.  Do not accept the
                # previous range's ready state before the new overview lands.
                page.wait_for_function(
                    "expected => window.SocFindings?.ready && "
                    "state.overview?.window?.range === expected && "
                    "state.overviewLoad?.windowKey === JSON.stringify(currentWindowPayload()) && "
                    "['ready','error'].includes(state.overviewLoad.status)",
                    arg=window, timeout=45000)
                page.wait_for_function("""() => {
                    const text = document.querySelector('#findingsScope')?.textContent || '';
                    return !/Loading full aggregation|Memuat agregasi lengkap/.test(text);
                }""", timeout=45000)
                record = page.evaluate("""() => ({
                    selected_range: currentWindowPayload().range,
                    overview_range: state.overview?.window?.range,
                    build_id: state.overview?.build_id,
                    load_status: state.overviewLoad.status,
                    visible_rows: document.querySelectorAll('.findingRow').length,
                    ai_controls: document.querySelectorAll('.findingRowShell .findingAiButton').length,
                    count: document.querySelector('#findingsCount')?.textContent,
                    source_error_keys: Object.keys(state.overview?.errors || {}),
                    cache_status: state.overview?.cache?.status
                })""")
                report["windows"].append(record)
                assert record["selected_range"] == window, record
                assert record["overview_range"] == window, record
                assert record["load_status"] == "ready", record
                assert record["visible_rows"] > 0, record
                assert record["ai_controls"] == record["visible_rows"], record
                if args.screenshots:
                    page.screenshot(path=str(output / (window + ".png")))

            page.goto(base + "/#view=command&range=24h", wait_until="domcontentloaded")
            page.wait_for_function("state.overviewLoad.status === 'ready'", timeout=45000)
            report["charts"] = page.evaluate("""() => ({
                trend_svg: document.querySelectorAll('#hourlySpark svg').length,
                severity_bars: document.querySelectorAll('#severityBars .barFill').length
            })""")
            assert report["charts"]["trend_svg"] > 0, report["charts"]
            assert report["charts"]["severity_bars"] == 4, report["charts"]
            if args.screenshots:
                page.screenshot(path=str(output / "command-center.png"))
                page.locator("#hourlySpark").screenshot(path=str(output / "alert-trend.png"))
                page.locator("#severityBars").screenshot(path=str(output / "severity.png"))
            page.goto(base + "/#view=findings&range=24h", wait_until="domcontentloaded")
            page.wait_for_function("state.overviewLoad.status === 'ready'", timeout=45000)
            report["viewports"] = {}
            for width in (1440, 1024, 768, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                page.wait_for_timeout(150)
                overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
                report["viewports"][str(width)] = {"overflow": overflow}
                assert not overflow, width
            if args.screenshots:
                page.screenshot(path=str(output / "findings-mobile.png"))
                page.locator("#findingsRows").scroll_into_view_if_needed()
                page.screenshot(path=str(output / "findings-mobile-content.png"))
            for filename in ("index.html", "app.js", "findings.js",
                             "analysis-workspace.js", "findings.css"):
                response = context.request.get(base + ("/" if filename == "index.html"
                                                       else "/static/" + filename))
                body = response.body()
                same = body == (ROOT / "static" / filename).read_bytes()
                report["assets"][filename] = {
                    "status": response.status, "source_matches": same,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "content_type": response.headers.get("content-type")}
                assert response.status == 200 and same, filename
            assert not report["browser_errors"], report["browser_errors"]
            assert not report["blocked_actions"], report["blocked_actions"]
            report["passed"] = True
        except Exception as error:
            failure = redact(error)
            report["failure"] = failure
        finally:
            context.close()
            browser.close()
            manifest = output / "summary.json"
            manifest.write_text(redact(json.dumps(report, indent=2)))
            os.chmod(manifest, 0o600)
            print(redact(json.dumps(report, indent=2)), flush=True)
            print("Private evidence directory:", output, flush=True)
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
