// GUI end-to-end for authenticated scanning. A local server on 127.0.0.1 has a login (cookie),
// a protected file only visible when logged in, and trap links (/logout, /delete/5). Credentials
// come from (a) the Interu Browser session cookies or (b) a header typed by hand. Nothing outside
// this machine is contacted.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/auth-scan.e2e.ts
// Close any running Interu window first (single-instance lock).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const PORT = 8097
const HOST = '127.0.0.1'
const BASE = `http://${HOST}:${PORT}`
const GITLAB_BODY = 'stages:\n  - build\nscript:\n  - make\n'

let A: RunningApp
let server: http.Server
let expired = false
const log: { path: string; cookie: string; auth: string }[] = []
const hits = (path: string): typeof log => log.filter((l) => l.path === path)

const html = (title: string, body = ''): string => `<!doctype html><title>${title}</title><body><h1>${title}</h1>${body}</body>`

function handler(req: http.IncomingMessage, res: http.ServerResponse): void {
  const path = (req.url ?? '/').split('?')[0]
  const cookie = String(req.headers.cookie ?? '')
  const auth = String(req.headers.authorization ?? '')
  log.push({ path, cookie, auth })
  const authed = !expired && (cookie.includes('sid=abc123') || auth === 'Bearer tok123')
  const redirect = (to: string): void => { res.writeHead(302, { Location: to }); res.end() }
  if (path === '/do-login') { res.writeHead(302, { Location: '/home', 'Set-Cookie': 'sid=abc123; Path=/; HttpOnly' }); return res.end() }
  if (path === '/login') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html('Login')) }
  if (path === '/logout' || path.startsWith('/delete/')) { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html('Done')) }
  if (!authed) { if (path === '/private') { res.writeHead(401); return res.end('no') } return redirect('/login') }
  if (path === '/.gitlab-ci.yml') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(GITLAB_BODY) }
  if (path === '/home') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html('Home', '<a href="/private">p</a> <a href="/logout">out</a> <a href="/delete/5">del</a>')) }
  if (path === '/private') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html('Private', 'secret')) }
  res.writeHead(404); res.end('not found')
}

type Info = { id: number; url: string; title: string }
const contents = (): Promise<Info[]> =>
  A.app.evaluate(({ webContents }) => webContents.getAllWebContents().map((w) => ({ id: w.id, url: w.getURL(), title: w.getTitle() })))

async function until<T>(read: () => Promise<T>, ok: (v: T) => boolean, label: string, ms = 20_000): Promise<T> {
  const end = Date.now() + ms
  let last: T | undefined
  while (Date.now() < end) {
    last = await read()
    if (ok(last)) return last
    await new Promise((r) => setTimeout(r, 150))
  }
  throw new Error(`timeout waiting for ${label}; last: ${JSON.stringify(last)}`)
}

const setCookies = async (page: Page, on: boolean): Promise<void> => {
  await page.getByLabel('Use Interu Browser cookies').setChecked(on, { force: true })
}
async function runActive(page: Page): Promise<void> {
  await nav(page, 'Rule Engine')
  const clear = page.getByRole('button', { name: 'Clear' })
  if (await clear.isEnabled()) await clear.click()
  await page.getByPlaceholder('http://127.0.0.1/  ·  https://host.example.com/').fill(`${BASE}/`)
  await page.getByRole('button', { name: 'Run active checks' }).click()
  await page.locator('.feed').getByText(/> done —|dibatalkan|stopped/).first().waitFor({ state: 'visible', timeout: 120_000 })
}
// A finding row names this server as its target; the Template library row of the same rule does not.
const gitlabFinding = (page: Page) => page.locator('tr', { hasText: 'Exposed .gitlab-ci.yml' }).filter({ hasText: `${HOST}:${PORT}` })

beforeAll(async () => {
  server = http.createServer(handler)
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(PORT, HOST, () => resolve()) })
  A = await launchApp()
  await nav(A.page, 'Rule Engine')
  const removeScope = A.page.locator('span[title="Remove"]')
  while ((await removeScope.count()) > 0) await removeScope.first().click()
  await A.page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(HOST)
  await A.page.getByRole('button', { name: 'Add' }).click()
}, 90_000)

afterAll(async () => {
  await A?.close()
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('GUI e2e — authenticated scanning', () => {
  it('without credentials the protected file is not found', async () => {
    await runActive(A.page)
    expect(await gitlabFinding(A.page).count()).toBe(0)
    expect(hits('/.gitlab-ci.yml').every((l) => !l.cookie && !l.auth)).toBe(true)
  }, 180_000)

  it('log in with the Interu Browser, then its cookies unlock the scan (values stay out of the UI)', async () => {
    await nav(A.page, 'Proxy')
    // 8080 may be taken (e.g. by WSL's relay), so use a port of our own.
    await A.page.locator('input[type="number"]').fill('18097')
    await A.page.getByRole('button', { name: 'Start', exact: true }).click()
    await A.page.getByText('Proxy running').waitFor({ state: 'visible', timeout: 15_000 })
    await A.page.getByPlaceholder('http://target/').fill(`${BASE}/do-login`)
    await A.page.getByRole('button', { name: 'Open Browser' }).click()
    await until(contents, (l) => l.some((w) => w.url === `${BASE}/home` && w.title === 'Home'), 'logged in, on /home')

    await nav(A.page, 'Rule Engine')
    await setCookies(A.page, true)
    await A.page.getByText(/1 cookie for scope/).waitFor({ state: 'visible', timeout: 15_000 })
    const text = await A.page.locator('body').innerText()
    const at = text.indexOf('abc123')
    expect(at, at < 0 ? '' : `cookie value visible in the UI: ...${text.slice(Math.max(0, at - 160), at + 60).replace(/\s+/g, ' ')}`).toBe(-1)
    await shot(A.page, 'auth-01-cookies')

    await runActive(A.page)
    await gitlabFinding(A.page).first().waitFor({ state: 'visible', timeout: 15_000 })
    expect(hits('/.gitlab-ci.yml').at(-1)!.cookie).toContain('sid=abc123')
  }, 180_000)

  it('a header typed by hand works without cookies', async () => {
    await nav(A.page, 'Rule Engine')
    await setCookies(A.page, false)
    await A.page.getByRole('button', { name: 'Headers', exact: true }).click()
    const ta = A.page.getByPlaceholder(/Authorization: Bearer/)
    await ta.fill('Authorization: Bearer tok123')
    await ta.blur()
    await A.page.getByText('Authorization', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 })

    await runActive(A.page)
    await gitlabFinding(A.page).first().waitFor({ state: 'visible', timeout: 15_000 })
    const last = hits('/.gitlab-ci.yml').at(-1)!
    expect(last.auth).toBe('Bearer tok123')
    expect(last.cookie).toBe('')
    await shot(A.page, 'auth-02-header')
  }, 180_000)

  it('the crawler never requests logout or delete URLs while authenticated', async () => {
    await nav(A.page, 'Crawler')
    await setCookies(A.page, true)
    log.length = 0
    await A.page.getByPlaceholder('https://target-host:port').fill(`${BASE}/home`)
    await A.page.getByRole('button', { name: 'Launch Crawl' }).click()
    await A.page.getByRole('button', { name: 'Launch Crawl' }).waitFor({ state: 'visible', timeout: 60_000 })
    expect(hits('/private').length).toBeGreaterThan(0)
    expect(hits('/logout')).toHaveLength(0)
    expect(hits('/delete/5')).toHaveLength(0)
  }, 120_000)

  it('an expired session stops the scan, is reported, and Refresh re-arms it', async () => {
    expired = true
    await runActive(A.page) // cookies and header are both still attached; the server now rejects them
    await A.page.getByText(/Sesi login habis/).waitFor({ state: 'visible', timeout: 15_000 })
    await A.page.getByText('session expired').waitFor({ state: 'visible', timeout: 15_000 })
    await nav(A.page, 'Exposure Monitor')
    await A.page.getByText(/Login session expired/).first().waitFor({ state: 'visible', timeout: 15_000 })
    await shot(A.page, 'auth-03-expired')

    expired = false
    await nav(A.page, 'Rule Engine')
    await A.page.getByRole('button', { name: 'Refresh' }).click()
    await runActive(A.page)
    await gitlabFinding(A.page).first().waitFor({ state: 'visible', timeout: 15_000 })
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 240_000)
})
