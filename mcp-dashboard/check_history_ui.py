"""Live read-only history checks; no provider tests or notifications."""
import asyncio
import json
from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:
        browser=await p.chromium.launch()
        page=await browser.new_page(viewport={'width':1440,'height':1000})
        errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        await page.add_init_script("localStorage.setItem('soc-language','en')")
        await page.goto('http://127.0.0.1:8088',wait_until='domcontentloaded')
        await page.locator('.nav [data-view="history"]').click()
        await page.locator('[data-history-row]').first.wait_for(timeout=60000)
        await page.locator('#historyDetail h2').wait_for()
        assert await page.locator('#historyTimeline button').count()>0
        assert await page.locator('#historyDetail').inner_text()
        await page.screenshot(path='/opt/wazuh-mcp-unified/.ui-check/history-desktop.png')
        await page.locator('#historyNext').click()
        await page.wait_for_function("document.querySelector('#historyPage').textContent.startsWith('51')")
        await page.locator('#historyMode').select_option('reports')
        await page.wait_for_function("document.querySelector('#historyDetail').textContent.includes('Analysis report #')")
        await page.locator('#languageSelect').select_option('id')
        await page.wait_for_function("document.querySelector('#historySearch').textContent==='Cari'")
        await page.set_viewport_size({'width':390,'height':844})
        await page.locator('#historyFilters').scroll_into_view_if_needed()
        await page.screenshot(path='/opt/wazuh-mcp-unified/.ui-check/history-mobile.png')
        width=await page.locator('#historyView').bounding_box()
        assert width['width']<=390,width
        assert not errors,errors
        print(json.dumps({'page_errors':errors,'history_pagination':'passed','report_retrieval':'passed','mobile_width':width['width']}))
        await browser.close()


asyncio.run(main())
