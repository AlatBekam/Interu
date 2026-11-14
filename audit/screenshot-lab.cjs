const { chromium } = require('playwright-core')
const path = require('node:path')

;(async () => {
  const browser = await chromium.launch({ executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', headless: true })
  try {
    for (const [name, width, height] of [['desktop', 1440, 900], ['mobile', 390, 844]]) {
      const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 })
      await page.goto('http://127.0.0.1:3000/', { waitUntil: 'load' })
      if (!(await page.title()).includes('RUY Cyber Security Team')) throw new Error('Unexpected page title')
      await page.screenshot({ path: path.join(__dirname, `lab-home-${name}.png`), fullPage: true })
      console.log(`${name}: ${await page.title()} | screenshot saved`)
      await page.close()
    }
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
