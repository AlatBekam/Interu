const fs = require('node:fs')
const path = require('node:path')
const { _electron } = require('playwright-core')

const targets = [
  ['PortSwigger Gin and Juice Shop', 'https://ginandjuice.shop/', 'online'],
  ['HCL Altoro Mutual', 'http://demo.testfire.net/', 'online'],
  ['Google Firing Range', 'https://public-firing-range.appspot.com/', 'online'],
  ['Pentest Ground DVWA', 'https://pentest-ground.com:4280/', 'online'],
  ['Pentest Ground DVGA', 'https://pentest-ground.com:5013/', 'online'],
  ['Pentest Ground RestFlaw', 'https://pentest-ground.com:9000/', 'online'],
  ['Pentest Ground GuardianLeaks', 'https://pentest-ground.com:81/', 'online'],
  ['OWASP Juice Shop Docker', 'http://127.0.0.1:3001/', 'selfhost'],
  ['VAmPI Docker', 'http://127.0.0.1:3004/ui/', 'selfhost'],
  ['OWASP WebGoat Docker', 'http://127.0.0.1:3002/WebGoat/', 'selfhost']
]
const only = process.env.INTERU_BROWSER_ONLY
const selected = only ? targets.filter(([name]) => name === only) : targets
const out = path.resolve(only ? 'audit/ten-browser-single.json' : 'audit/ten-browser-benchmark.json')
const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE

;(async () => {
  const app = await _electron.launch({ executablePath: path.resolve('release/win-unpacked/Interu.exe'),
    args: [`--user-data-dir=${path.resolve('audit/ten-browser-profile')}`], env, timeout: 30000 })
  const reports = []
  try {
    const page = await app.firstWindow()
    await page.getByText('Exposure Monitor', { exact: true }).first().waitFor({ timeout: 30000 })
    await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) w.hide() })
    const proxy = await page.evaluate(() => window.ruy.proxy.start(18180))
    if (!proxy.ok) throw new Error(proxy.error || 'Proxy failed')
    await page.evaluate(() => window.ruy.proxy.setIntercept(false))
    for (const [name, url, kind] of selected) {
      const record = { name, url, kind, startedAt: new Date().toISOString() }
      try {
        await page.evaluate(host => window.ruy.proxy.setScope([host]), new URL(url).hostname)
        const opened = await page.evaluate(target => window.ruy.proxy.openBrowser(target), url)
        if (!opened.ok) throw new Error(opened.error || 'Browser failed')
        await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) w.hide() })
        const discovery = await page.evaluate(async ({ target, maxPages }) =>
          window.ruy.automation.discoverBrowser(target, maxPages, true),
          { target: url, maxPages: kind === 'online' ? 6 : 12 })
        Object.assign(record, { browserPages: discovery.pages, browserUrls: discovery.urls.length,
          forms: discovery.forms.map(f => ({ kind: f.kind, method: f.method, url: f.url })),
          accountFlow: discovery.accountFlow, accountNote: discovery.note })
        const options = { target: url, browserSeeds: discovery.urls, maxPages: kind === 'online' ? 25 : 35,
          maxDepth: 2, maxRequests: kind === 'online' ? 120 : 160,
          delayMs: kind === 'online' ? 500 : 100, timeoutMs: 10000, maxDurationMs: 120000,
          activeChecks: false, parameterChecks: true }
        await page.evaluate(input => window.ruy.automation.start(input), options)
        for (let i = 0; i < 130; i++) {
          const status = await page.evaluate(() => window.ruy.automation.status())
          if (status.status !== 'running') break
          await page.waitForTimeout(1000)
        }
        const run = await page.evaluate(() => window.ruy.automation.status())
        Object.assign(record, { status: run.status, reason: run.reason, requests: run.requests, pages: run.pages,
          errors: run.errors, findings: run.findings.map(f => ({ name: f.name, templateId: f.templateId,
            confidence: f.confidence, severity: f.severity, matchedAt: f.matchedAt, evidence: f.evidence })) })
      } catch (error) { record.error = String(error?.message || error) }
      record.finishedAt = new Date().toISOString()
      reports.push(record)
      fs.writeFileSync(out, JSON.stringify(reports, null, 2))
      console.log(`${name}: ${record.status || 'error'}, browser ${record.browserPages || 0} pages, ${record.requests || 0} scan requests, ${record.findings?.length || 0} findings, account ${record.accountFlow || '-'}${record.error ? ', ' + record.error : ''}`)
    }
  } finally { await app.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
