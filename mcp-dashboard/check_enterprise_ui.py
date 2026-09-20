from pathlib import Path
from playwright.sync_api import sync_playwright

out = Path(__file__).parent / "artifacts"
out.mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1050}, reduced_motion="reduce")
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("http://127.0.0.1:8088", wait_until="domcontentloaded")
    page.locator('[data-view="vuln"]').click()
    page.locator("#entVulnDetail h2").wait_for(timeout=180000)
    print("Inventory:", page.locator("#enterpriseInventory .entMetrics").inner_text(), flush=True)
    page.screenshot(path=str(out / "enterprise-vulnerabilities-id.png"))
    page.locator("#entVulnSearch").fill("CVE-2026-54117")
    page.locator("#entVulnFilters button").click()
    page.wait_for_function("document.querySelector('#entVulnDetail h2')?.textContent === 'CVE-2026-54117'", timeout=90000)
    assert "WinSolDB" in page.locator("#entVulnDetail").inner_text()
    assert "16.0.4165.4" in page.locator("#entVulnDetail").inner_text()
    page.locator("#entCveEnrich").click()
    page.wait_for_function("document.querySelector('#entCveEnrich')?.disabled === false", timeout=180000)
    print("CVE provider result:", page.locator("#entCveIntel").inner_text()[:1400], flush=True)
    result_text = page.locator("#entCveIntel").inner_text()
    assert "9.8" in result_text or any(status in result_text for status in ["API quota", "Unavailable", "429"])
    print("CVE enrichment: result or explicit provider failure visible", flush=True)
    page.locator("#languageSelect").select_option("en")
    assert page.locator("#enterpriseInventory h2").first.inner_text() == "CVEs linked to packages and hosts"
    assert page.locator("html").get_attribute("lang") == "en"
    page.screenshot(path=str(out / "enterprise-vulnerabilities-en.png"))
    page.locator('[data-view="command"]').click()
    page.locator("#entTrend").wait_for(timeout=180000)
    page.wait_for_timeout(1000)
    for selector in ["#entTrend", "#entSeverity", "#entSources"]:
        filled = page.locator(selector).evaluate("c => { const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; let n=0; for(let i=3;i<d.length;i+=4) if(d[i]) n++; return n; }")
        assert filled > 300, (selector, filled)
        print(selector, "painted pixels", filled, flush=True)
    page.screenshot(path=str(out / "enterprise-command-en.png"))
    for view in ["command", "vuln", "findings", "workbench", "l1", "l2"]:
        page.locator(f'[data-view="{view}"]').click()
        for width in [1920, 1440, 1024, 390]:
            page.set_viewport_size({"width": width, "height": 1000})
            page.wait_for_timeout(350)
            if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                print(page.evaluate("({width:innerWidth,scroll:document.documentElement.scrollWidth,elements:Array.from(document.querySelectorAll('body *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,12).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right}))})"), flush=True)
                page.screenshot(path=str(out / "enterprise-overflow.png"))
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), (view,width)
        print(view, "responsive: PASS", flush=True)
    page.locator("#languageSelect").select_option("id")
    page.locator('[data-view="command"]').click()
    page.screenshot(path=str(out / "enterprise-command-mobile.png"))
    page.set_viewport_size({"width": 1440, "height": 1050})
    page.screenshot(path=str(out / "enterprise-command-id.png"))
    print("Browser errors:", errors, flush=True)
    assert not errors
    browser.close()
