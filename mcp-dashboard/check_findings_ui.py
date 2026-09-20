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
    page.locator(".findingRow").first.wait_for(timeout=180000)
    page.screenshot(path=str(output / "findings-desktop.png"))
    print("Desktop loaded:", page.locator("#findingsCount").inner_text(), flush=True)
    page.locator('[data-finding-category="m365"]').click()
    page.locator('[data-finding-tab="evidence"]').click()
    page.wait_for_function("!document.querySelector('#findingEvents').textContent.includes('Loading matching')", timeout=90000)
    print("M365 evidence:", page.locator("#findingEvents").inner_text()[:180], flush=True)
    page.screenshot(path=str(output / "findings-m365.png"))
    page.locator('[data-finding-category="vuln"]').click()
    page.locator('[data-finding-tab="cve"]').click()
    page.wait_for_function("!document.querySelector('#findingCveScore').textContent.includes('Fetching')", timeout=180000)
    print("CVE context:", page.locator("#findingCveScore").inner_text()[:400], flush=True)
    page.screenshot(path=str(output / "findings-cve.png"))
    page.wait_for_function("Number(document.querySelector('[data-finding-category=cyfirma] span').textContent)>0", timeout=180000)
    page.locator('[data-finding-category="cyfirma"]').click()
    print("CYFIRMA records:", page.locator("#findingsCount").inner_text(), flush=True)
    page.screenshot(path=str(output / "findings-cyfirma.png"))
    page.locator("#findingSearch").fill("no-such-observable-zzz")
    assert page.locator("#findingsRows").inner_text().startswith("No matching")
    page.locator("#findingSearch").fill("")
    page.locator('[data-finding-category="ip"]').click()
    page.locator('[data-finding-tab="intel"]').click()
    page.wait_for_function("!document.querySelector('#findingIntel-aggregate')?.textContent.includes('Fetching')", timeout=180000)
    print("IP intelligence:", page.locator("#findingProviders").inner_text()[:500], flush=True)
    page.screenshot(path=str(output / "findings-intel.png"))
    for width in [1440, 1024, 768, 390]:
        page.set_viewport_size({"width": width, "height": 1000})
        overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
        print("Viewport", width, "overflow:", overflow, flush=True)
        assert not overflow
    page.screenshot(path=str(output / "findings-mobile.png"), full_page=True)
    print("Browser errors:", json.dumps(errors), flush=True)
    browser.close()
    assert not errors
