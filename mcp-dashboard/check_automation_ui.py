"""Live browser smoke test. Does not trigger external notifications."""
import asyncio
import json
from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        await page.add_init_script("localStorage.setItem('soc-language','en')")
        await page.goto("http://127.0.0.1:8088", wait_until="domcontentloaded")
        await page.locator('.nav [data-view="settings"]').click()
        await page.locator('[name="SOC_REPORT_RECIPIENTS"]').wait_for(timeout=60000)
        await page.locator('#testSmtp').wait_for()
        assert await page.locator('#settingsView .automationFinding').count() == 0
        recipients = page.locator('[name="SOC_REPORT_RECIPIENTS"]')
        assert await recipients.is_visible() and await recipients.is_editable()
        await page.locator('.nav [data-view="workbench"]').click()
        await page.locator('.automationMetrics').wait_for(timeout=60000)
        await page.screenshot(path="/opt/wazuh-mcp-unified/.ui-check/automation-desktop.png")
        await page.locator('.automationFinding summary').first.click()
        await page.locator('.automationFinding[open] [data-automation-rule]').first.click()
        await page.wait_for_function("state.view === 'findings'")
        await page.locator('.nav [data-view="workbench"]').click()
        await page.locator('.automationCves summary').click()
        await page.locator('[data-automation-cve]').first.click()
        await page.wait_for_function("state.view === 'findings'")
        await page.locator('.nav [data-view="workbench"]').click()
        await page.locator('#languageSelect').select_option('id')
        assert await page.locator('#runAutomation').inner_text() == 'Jalankan analisis'
        await page.locator('#languageSelect').select_option('en')
        assert await page.locator('#runAutomation').inner_text() == 'Run analysis'
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.locator('#automationPanel').scroll_into_view_if_needed()
        await page.evaluate("document.querySelector('#automationPanel').scrollIntoView({block:'start'})")
        await page.screenshot(path="/opt/wazuh-mcp-unified/.ui-check/automation-mobile.png")
        panel = await page.locator('#automationPanel').bounding_box()
        assert panel['width'] <= 390, panel
        assert not errors, errors
        print(json.dumps({"page_errors": errors, "mobile_panel_width": panel['width'], "evidence_and_cve_links": "passed"}))
        await browser.close()


asyncio.run(main())
