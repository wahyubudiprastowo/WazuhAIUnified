"""Read-only browser smoke test against the running SOC dashboard."""
from pathlib import Path
import json
from playwright.sync_api import sync_playwright

output = Path(__file__).parent / "artifacts"
output.mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto("http://127.0.0.1:8088", wait_until="domcontentloaded")
    page.wait_for_function("document.querySelector('#workbenchView .analysisMetrics')", timeout=180000)
    print("Coverage:", page.locator("#workbenchView .analysisMetrics").inner_text(), flush=True)
    page.evaluate("setView('workbench')")
    page.wait_for_function("!document.querySelector('#workbenchView .analysisTable').textContent.includes('Memuat...')", timeout=180000)
    print("Providers:", page.locator("#workbenchView .analysisTable").inner_text(), flush=True)
    page.screenshot(path=str(output / "analysis-workbench.png"))
    for view in ["findings", "workbench", "l1", "l2", "tools"]:
        page.evaluate("view => setView(view)", view)
        for width in [2560, 1440, 1024, 390]:
            page.set_viewport_size({"width": width, "height": 1000})
            overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
            print(view, width, "overflow:", overflow, flush=True)
            assert not overflow, (view, width)
        if view != "tools":
            page.screenshot(path=str(output / f"analysis-{view}-mobile.png"))
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.evaluate("setView('l1')")
    page.screenshot(path=str(output / "analysis-l1.png"))
    page.locator("#l1Queue [data-analysis-rule]").first.click()
    assert page.locator("#findingsView").evaluate("e => e.classList.contains('active')")
    assert "Makna alert" in page.locator("#findingDetail").inner_text()
    page.screenshot(path=str(output / "analysis-rule-detail.png"))
    theme = page.locator(".findingDetail").evaluate("e => getComputedStyle(e).backgroundColor")
    assert theme != "rgb(255, 255, 255)", theme
    print("Finding theme:", theme, flush=True)
    page.evaluate("setView('l2')")
    page.locator("#l2View [data-analysis-open]").first.click()
    assert page.locator("#findingsView").evaluate("e => e.classList.contains('active')")
    print("Selected IOC:", page.locator(".findingDetailHead h2").inner_text(), flush=True)
    page.locator('[data-finding-tab="intel"]').click()
    page.wait_for_function("!document.querySelector('#findingProviders').textContent.includes('Fetching')", timeout=180000)
    page.screenshot(path=str(output / "analysis-intelligence.png"))
    print("Browser errors:", json.dumps(errors), flush=True)
    assert not errors
    browser.close()
