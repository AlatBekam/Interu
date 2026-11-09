// Optional e2e against a WebGoat you run yourself (a deliberately vulnerable training app).
// Skipped unless WEBGOAT_URL is set. Credentials come from the environment, never from the repo.
// Scope is only the host of that URL; nothing else is contacted.
//
//   WEBGOAT_URL=http://127.0.0.1:8080/WebGoat WEBGOAT_USER=<user> WEBGOAT_PASS=<pass> \
//     npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/webgoat.e2e.ts
// Close any running Interu window first (single-instance lock). The Interu proxy uses its own port
// (18098) because 8080 is usually WebGoat itself or its relay.
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const URL_ = (process.env.WEBGOAT_URL ?? '').replace(/\/+$/, '')
const USER = process.env.WEBGOAT_USER ?? ''
const PASS = process.env.WEBGOAT_PASS ?? ''
const enabled = !!URL_ && !!USER && !!PASS
const HOST = enabled ? new globalThis.URL(URL_).hostname : ''

let A: RunningApp
const numbers: Record<string, number> = {}

type Info = { id: number; url: string; title: string }
const contents = (): Promise<Info[]> =>
  A.app.evaluate(({ webContents }) => webContents.getAllWebContents().map((w) => ({ id: w.id, url: w.getURL(), title: w.getTitle() })))
const inContent = async (js: string): Promise<unknown> => {
  const c = (await contents()).find((w) => w.url.startsWith(URL_))
  if (!c) throw new Error('browser content not found')
  return A.app.evaluate(({ webContents }, a) => webContents.fromId(a.id)!.executeJavaScript(a.js, true), { id: c.id, js })
}
async function until<T>(read: () => Promise<T>, ok: (v: T) => boolean, label: string, ms = 30_000): Promise<T> {
  const end = Date.now() + ms
  let last: T | undefined
  while (Date.now() < end) {
    last = await read()
    if (ok(last)) return last
    await new Promise((r) => setTimeout(r, 200))
  }
  throw new Error(`timeout waiting for ${label}; last: ${JSON.stringify(last)}`)
}
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
// start.mvc only answers 200 when logged in (anonymous requests are redirected to /login) and links to /logout.
const SEED = '/start.mvc'
async function crawl(page: Page): Promise<number> {
  await nav(page, 'Crawler')
  await page.getByPlaceholder('https://target-host:port').fill(`${URL_}${SEED}`)
  await page.getByRole('button', { name: 'Launch Crawl' }).click()
  await page.getByRole('button', { name: 'Launch Crawl' }).waitFor({ state: 'visible', timeout: 240_000 })
  return stat(page, 'Pages crawled')
}

describe.skipIf(!enabled)('GUI e2e — authenticated scan against your own WebGoat', () => {
  beforeAll(async () => {
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

  it('logs in through the Interu Browser and the session cookie is picked up', async () => {
    await nav(A.page, 'Proxy')
    await A.page.locator('input[type="number"]').fill('18098')
    await A.page.getByRole('button', { name: 'Start', exact: true }).click()
    await A.page.getByText('Proxy running').waitFor({ state: 'visible', timeout: 15_000 })
    await A.page.getByPlaceholder('http://target/').fill(`${URL_}/login`)
    await A.page.getByRole('button', { name: 'Open Browser' }).click()
    await until(contents, (l) => l.some((w) => w.url.startsWith(`${URL_}/login`) && !!w.title), 'login page')
    await inContent(`(() => { const f = document.querySelector('form'); f.elements['username'].value = ${JSON.stringify(USER)}; f.elements['password'].value = ${JSON.stringify(PASS)}; f.submit(); return true })()`)
    await until(contents, (l) => l.some((w) => w.url.startsWith(URL_) && !w.url.includes('/login')), 'logged in (left the login page)')

    await nav(A.page, 'Rule Engine')
    await A.page.getByLabel('Use Interu Browser cookies').setChecked(true, { force: true })
    await A.page.getByText(/\d+ cookies? for scope/).waitFor({ state: 'visible', timeout: 15_000 })
    const text = await A.page.locator('body').innerText()
    expect(text, 'no session value in the UI').not.toMatch(/JSESSIONID=[A-F0-9]{16,}/i)
    await shot(A.page, 'webgoat-01-cookies')
  }, 120_000)

  it('scans with the session, never logs the session out, and sees more than before', async () => {
    numbers.ruleAuth = await ruleEngineRun(A.page)
    numbers.crawlAuth = await crawl(A.page)
    console.log(`[webgoat] with login: findings=${numbers.ruleAuth} pages=${numbers.crawlAuth}`)
    await shot(A.page, 'webgoat-02-authenticated')

    // The session must still be valid: a logout during the crawl would have killed it.
    const stillIn = await inContent(`fetch(${JSON.stringify(URL_ + SEED)}, { redirect: 'manual' }).then((r) => r.type !== 'opaqueredirect' && r.status === 200)`)
    expect(stillIn, 'session still valid after the authenticated crawl').toBe(true)
    expect(numbers.crawlAuth, 'the authenticated crawl reaches pages the anonymous one cannot').toBeGreaterThan(numbers.crawlUnauth)
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 600_000)
})
