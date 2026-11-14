const fs = require('node:fs')
const http = require('node:http')
const { chromium } = require('playwright-core')

;(async () => {
  const browser = await chromium.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true
  })
  try {
    const context = await browser.newContext()
    await context.route('**/*', route => route.abort())
    const page = await context.newPage()
    const payload = '<svg onload="window.__interuXssProof=1">'
    const url = 'http://demo.testfire.net/search.jsp?query=' + encodeURIComponent(payload)
    const { status, html } = await new Promise((resolve, reject) => {
      http.get(url, response => {
        let body = ''
        response.setEncoding('utf8')
        response.on('data', chunk => { body += chunk })
        response.on('end', () => resolve({ status: response.statusCode, html: body }))
      }).on('error', reject)
    })
    await page.setContent(html, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(500)
    const executed = await page.evaluate(() => window.__interuXssProof === 1)
    const result = { target: 'http://demo.testfire.net/search.jsp', status,
      payload, reflected: html.includes(payload), executedInReplayedResponse: executed,
      method: 'browser parses exact server response; external requests blocked; no data change' }
    fs.writeFileSync('audit/altoro-xss-verification.json', JSON.stringify(result, null, 2))
    console.log(JSON.stringify(result))
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
