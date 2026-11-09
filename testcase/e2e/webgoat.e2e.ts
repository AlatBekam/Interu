// Optional e2e against a WebGoat you run yourself (a deliberately vulnerable training app).
// Skipped unless WEBGOAT_URL is set. Credentials come from the environment, never from the repo.
// Scope is only the host of that URL; nothing else is contacted.
//
//   WEBGOAT_URL=http://127.0.0.1:8080/WebGoat WEBGOAT_USER=<user> WEBGOAT_PASS=<pass> \
//     npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/webgoat.e2e.ts
// Close any running Interu window first (single-instance lock). The test logs in with plain HTTP,
// then pastes the resulting session cookie into the Authenticated scan box, like an operator would.
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const URL_ = (process.env.WEBGOAT_URL ?? '').replace(/\/+$/, '')
const USER = process.env.WEBGOAT_USER ?? ''
const PASS = process.env.WEBGOAT_PASS ?? ''
const enabled = !!URL_ && !!USER && !!PASS
const HOST = enabled ? new globalThis.URL(URL_).hostname : ''

// start.mvc only answers 200 when logged in (anonymous requests are redirected to /login) and links to /logout.
const SEED = '/start.mvc'

let A: RunningApp
let cookie = ''
const numbers: Record<string, number> = {}

const stat = async (page: Page, label: string): Promise<number> => {
  const t = await page.locator('.stat', { has: page.locator('.s-label', { hasText: label }) }).locator('.s-value').first().textContent()
  return Number((t ?? '').replace(/\D/g, ''))
}
async function ruleEngineRun(page: Page): Promise<number> {
  await nav(page, 'Rule Engine')
  const clear = page.getByRole('button', { name: 'Clear' })
  if (await clear.isEnabled()) await clear.click()
  await page.getByPlaceholder('http://127.0.0.1/  ·  https://host.example.com/').fill(`${URL_}/`)
  await page.getByRole('button', { name: 'Run active checks' }).click()
  await page.locator('.feed').getByText(/> done —|dibatalkan|stopped/).first().waitFor({ state: 'visible', timeout: 240_000 })
  return stat(page, 'Findings')
}
async function crawl(page: Page): Promise<number> {
  await nav(page, 'Crawler')
  await page.getByPlaceholder('https://target-host:port').fill(`${URL_}${SEED}`)
  await page.getByRole('button', { name: 'Launch Crawl' }).click()
  await page.getByRole('button', { name: 'Launch Crawl' }).waitFor({ state: 'visible', timeout: 240_000 })
  return stat(page, 'Pages crawled')
}
/** A plain HTTP login, the way you would copy a session out of your own browser. */
async function login(): Promise<string> {
  const res = await fetch(`${URL_}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: USER, password: PASS }).toString(),
    redirect: 'manual'
  })
  const sid = res.headers.getSetCookie().map((c) => c.split(';')[0]).find((c) => /^JSESSIONID=/i.test(c))
  if (!sid) throw new Error(`login did not return a session cookie (status ${res.status})`)
  return sid
}

describe.skipIf(!enabled)('GUI e2e — authenticated scan against your own WebGoat', () => {
  beforeAll(async () => {
    cookie = await login()
    A = await launchApp()
    await nav(A.page, 'Rule Engine')
    const rm = A.page.locator('span[title="Remove"]')
    while ((await rm.count()) > 0) await rm.first().click()
    await A.page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(HOST)
    await A.page.getByRole('button', { name: 'Add' }).click()
  }, 90_000)
  afterAll(async () => { await A?.close() })

  it('baseline without credentials', async () => {
    numbers.ruleUnauth = await ruleEngineRun(A.page)
    numbers.crawlUnauth = await crawl(A.page)
    console.log(`[webgoat] without login: findings=${numbers.ruleUnauth} pages=${numbers.crawlUnauth}`)
  }, 600_000)

  it('scans with the pasted session, never logs it out, and sees more than before', async () => {
    await nav(A.page, 'Rule Engine')
    const ta = A.page.getByPlaceholder(/Authorization: Bearer/)
    await ta.fill(`Cookie: ${cookie}`)
    await ta.blur()
    await A.page.locator('.pill-info[title="Values are kept in memory only"]').filter({ hasText: 'Cookie' }).waitFor({ state: 'visible', timeout: 10_000 })
    expect(await A.page.locator('body').innerText(), 'no session value in the page text').not.toContain(cookie.split('=')[1])

    numbers.ruleAuth = await ruleEngineRun(A.page)
    numbers.crawlAuth = await crawl(A.page)
    console.log(`[webgoat] with login: findings=${numbers.ruleAuth} pages=${numbers.crawlAuth}`)
    await shot(A.page, 'webgoat-02-authenticated')

    // The session must still be valid: a logout during the crawl would have ended it.
    const check = await fetch(`${URL_}${SEED}`, { headers: { Cookie: cookie }, redirect: 'manual' })
    expect(check.status, 'session still valid after the authenticated crawl').toBe(200)
    expect(numbers.crawlAuth, 'the authenticated crawl reaches pages the anonymous one cannot').toBeGreaterThan(numbers.crawlUnauth)
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 600_000)
})
