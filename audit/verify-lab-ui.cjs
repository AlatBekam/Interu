const fs = require('node:fs')
const path = require('node:path')
const { _electron } = require('playwright-core')

const out = path.join(__dirname, 'lab-ui-verification.json')
const flag = n => `RUY{harusnya_kamu_gabisa_liat_ini${n}}`
const countLab = list => list.filter(f => f.templateId?.startsWith('modern-backup-') || f.templateId?.startsWith('local-lab-'))
const verify = (name, list) => {
  const found = countLab(list)
  if (found.length !== 150) throw new Error(`${name}: expected 150 lab findings, got ${found.length}`)
  for (let n = 1; n <= 150; n++) if (!found.some(f => f.response?.includes(flag(n)))) throw new Error(`${name}: missing flag ${n}`)
  return { labFindings: found.length, flags: 150 }
}

;(async () => {
  const env = { ...process.env }
  delete env.ELECTRON_RUN_AS_NODE
  delete env.RUY_SMOKE_TEST
  const app = await _electron.launch({
    executablePath: path.resolve('release/win-unpacked/Interu.exe'),
    args: [`--user-data-dir=${path.join(__dirname, 'lab-ui-profile')}`],
    env, timeout: 30000
  })
  const result = {}
  try {
    const page = await app.firstWindow()
    await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) w.hide() })
    await page.getByText('Exposure Monitor', { exact: true }).first().waitFor({ timeout: 30000 })

    await page.getByText('Active Scan', { exact: true }).first().click()
    await page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill('localhost')
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await page.getByText('Rule Engine exposure templates', { exact: true }).waitFor()
    await page.getByLabel('Max pages').fill('1')
    await page.waitForTimeout(300)
    await page.getByRole('button', { name: 'Launch Scan' }).click()
    await page.getByRole('button', { name: 'Stop', exact: true }).waitFor({ timeout: 10000 })
    await page.getByRole('button', { name: 'Launch Scan' }).waitFor({ timeout: 120000 })
    result.activeScan = verify('Active Scan', await page.evaluate(() => JSON.parse(localStorage.getItem('ruy.v1.findings') || '[]')))
    fs.writeFileSync(out, JSON.stringify(result, null, 2))
    await page.screenshot({ path: path.join(__dirname, 'lab-active-scan.png') })

    await page.getByText('Rule Engine', { exact: true }).first().click()
    await page.getByRole('button', { name: 'Clear', exact: true }).click()
    await page.getByRole('button', { name: 'Run active checks' }).click()
    await page.getByText(/running 733 active check/).waitFor({ timeout: 10000 })
    await page.getByText(/done.*733 probes/).waitFor({ timeout: 120000 })
    result.ruleEngine = verify('Rule Engine', await page.evaluate(() => JSON.parse(localStorage.getItem('ruy.v1.findings') || '[]')))
    fs.writeFileSync(out, JSON.stringify(result, null, 2))
    await page.screenshot({ path: path.join(__dirname, 'lab-rule-engine.png') })

    await page.getByText('Vulnerabilities', { exact: true }).first().click()
    const search = page.locator('input[placeholder^="Search name"]')
    for (const n of [1, 150]) {
      await search.fill(flag(n))
      await page.locator('table.data tbody tr.clickable').first().click()
      await page.locator('span.pill-ok.mono').filter({ hasText: flag(n) }).first().waitFor()
      await page.getByText('Response', { exact: false }).last().waitFor()
      if (n === 150) await page.screenshot({ path: path.join(__dirname, 'lab-vulnerability-detail.png') })
    }
    result.vulnerabilityDetails = { flagsOpened: [1, 150] }
    await search.fill('')

    await page.getByText('Pentest Automation', { exact: true }).first().click()
    await page.getByLabel('Maximum pages').fill('1')
    await page.getByLabel('Crawl depth').fill('0')
    await page.getByLabel('Request budget').fill('900')
    await page.getByLabel('Minimum request interval (ms)').fill('100')
    await page.getByLabel('Total time budget (ms)').fill('120000')
    await page.getByRole('button', { name: 'Start automation' }).click()
    await page.getByText('Selected checks completed', { exact: true }).waitFor({ timeout: 150000 })
    const run = await page.evaluate(() => window.ruy.automation.status())
    result.automation = { status: run.status, requests: run.requests, ...verify('Pentest Automation', run.findings) }
    await page.screenshot({ path: path.join(__dirname, 'lab-automation.png') })
    fs.writeFileSync(out, JSON.stringify(result, null, 2))
    console.log(JSON.stringify(result, null, 2))
  } finally {
    await app.close()
  }
})().catch(error => { console.error(error); process.exitCode = 1 })
