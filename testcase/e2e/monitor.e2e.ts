// GUI end-to-end for the Exposure Monitor: it must show only what Interu observed.
// A local server on 127.0.0.1 serves one exposed file; scope contains only 127.0.0.1.
// Nothing outside this machine is contacted.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/monitor.e2e.ts
// Close any running Interu window first (single-instance lock).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const PORT = 8090
const HOST = '127.0.0.1'
const GITLAB_BODY = 'stages:\n  - build\nscript:\n  - make\n'

let A: RunningApp
let server: http.Server

function listen(s: http.Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    s.once('error', reject)
    s.listen(port, HOST, () => resolve())
  })
}
const close = (s: http.Server) => new Promise<void>((resolve) => s.close(() => resolve()))

async function clearScope(page: Page): Promise<void> {
  while ((await page.locator('.pill-ok').count()) > 0) {
    await page.locator('.pill-ok span[title="Remove"]').first().click()
  }
}

async function clearFindings(page: Page): Promise<void> {
  await nav(page, 'Rule Engine')
  const clear = page.getByRole('button', { name: 'Clear' })
  if (await clear.isEnabled()) await clear.click()
}

async function runActive(page: Page, base: string): Promise<void> {
  await nav(page, 'Rule Engine')
  await page.getByPlaceholder('http://127.0.0.1/  ·  https://host.example.com/').fill(base)
  await page.getByRole('button', { name: 'Run active checks' }).click()
  await page.locator('.feed').getByText(/> done —/).waitFor({ state: 'visible', timeout: 180_000 })
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if ((req.url ?? '').startsWith('/.gitlab-ci.yml')) {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      return res.end(GITLAB_BODY)
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('not found')
  })
  await listen(server, PORT)

  A = await launchApp()
  // Shared localStorage holds the operator's scope and findings: start from a known state.
  await clearScope(A.page)
  await clearFindings(A.page)
  await nav(A.page, 'Rule Engine')
  await A.page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(HOST)
  await A.page.getByRole('button', { name: 'Add' }).click()
}, 90_000)

afterAll(async () => {
  if (A?.page) {
    try {
      await clearFindings(A.page)
      await clearScope(A.page)
    } catch { /* ignore */ }
  }
  await A?.close()
  await close(server)
})

describe('GUI e2e — Exposure Monitor shows only real activity', () => {
  it('starts empty, with no synthetic data', async () => {
    await nav(A.page, 'Exposure Monitor')
    await A.page.getByText('No activity yet in this session.').waitFor({ state: 'visible', timeout: 15_000 })
    const body = (await A.page.textContent('body')) ?? ''
    expect(body).toContain('No findings yet')
    expect(body).not.toContain('trojan beacon')
    expect(body).not.toContain('synthetically generated')
    await shot(A.page, 'monitor-01-empty')
  }, 60_000)

  it('a real finding reaches the queue, the exposure table and the activity feed', async () => {
    await runActive(A.page, `http://${HOST}:${PORT}/`)
    await nav(A.page, 'Exposure Monitor')
    await A.page.getByText('Exposed .gitlab-ci.yml').first().waitFor({ state: 'visible', timeout: 15_000 })
    const body = (await A.page.textContent('body')) ?? ''
    expect(body).toContain('New finding: Exposed .gitlab-ci.yml')
    expect(await A.page.locator('td.mono.small', { hasText: new RegExp(`^${HOST}$`) }).count()).toBeGreaterThan(0)
    await shot(A.page, 'monitor-02-with-finding')
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 240_000)

  it('has no fake-data pages and no simulation badge', async () => {
    const body = (await A.page.textContent('body')) ?? ''
    for (const gone of ['Dashboard', 'Firewall Rules', 'Reports', 'Simulation']) expect(body).not.toContain(gone)
    await shot(A.page, 'monitor-03-no-fake-pages')
  }, 60_000)

  it('a refused target is recorded as a scope decision', async () => {
    // Out of scope: the pre-check refuses before any probe, so there is no "> done" line to wait for.
    await nav(A.page, 'Rule Engine')
    await A.page.getByPlaceholder('http://127.0.0.1/  ·  https://host.example.com/').fill('http://127.0.0.2:8090/')
    await A.page.getByRole('button', { name: 'Run active checks' }).click()
    await A.page.getByText('belum ada di Authorized scope').first().waitFor({ state: 'visible', timeout: 15_000 })
    await nav(A.page, 'Exposure Monitor')
    await A.page.getByText('Blocked by scope').first().waitFor({ state: 'visible', timeout: 15_000 })
    expect((await A.page.textContent('body')) ?? '').toContain('Blocked by scope: http://127.0.0.2:8090/')
    await shot(A.page, 'monitor-04-scope')
  }, 240_000)
})
