// GUI end-to-end for the 408-template Rule Engine on main (no feature code of ours).
//   - MARKER server (127.0.0.1:8090) serves the body markers of two active templates.
//   - CATCH-ALL server (127.0.0.1:8091) answers 200 to every path with no markers.
// Both are local; scope contains only 127.0.0.1. Nothing outside this machine is contacted.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/rules-408.e2e.ts
// Close any running Interu window first (single-instance lock).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'
import { TEMPLATES } from '../../src/shared/rules'
import { KEV_COUNT } from '../../src/shared/kev'

const MARKER_PORT = 8090
const CATCH_PORT = 8091
const HOST = '127.0.0.1'
const MARKER_BASE = `http://${HOST}:${MARKER_PORT}/`
const CATCH_BASE = `http://${HOST}:${CATCH_PORT}/`

const GITLAB_BODY = 'stages:\n  - build\nscript:\n  - make\n'
const GRAPHQL_BODY = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
const IGNITION_BODY = '{"can_execute_commands":true}'

let A: RunningApp
let marker: http.Server
let catchAll: http.Server

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
  // The run logs "> done — …" once every active check has been probed.
  await page.locator('.feed').getByText(/> done —/).waitFor({ state: 'visible', timeout: 180_000 })
}

const confirmedCount = async (page: Page): Promise<number> =>
  ((await page.locator('.feed').innerText()).match(/CONFIRMED/g) ?? []).length

beforeAll(async () => {
  marker = http.createServer((req, res) => {
    const url = req.url ?? '/'
    if (url.startsWith('/.gitlab-ci.yml')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(GITLAB_BODY) }
    if (url.startsWith('/graphql')) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(GRAPHQL_BODY) }
    if (url.startsWith('/_ignition/health-check')) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(IGNITION_BODY) }
    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('not found')
  })
  catchAll = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end('<html><body>ok</body></html>')
  })
  await listen(marker, MARKER_PORT)
  await listen(catchAll, CATCH_PORT)

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
  await close(marker)
  await close(catchAll)
})

describe('GUI e2e — 408-template Rule Engine on main (local targets only)', () => {
  it('shows the full template catalog', async () => {
    await nav(A.page, 'Rule Engine')
    await A.page.getByText('Templates loaded').waitFor({ state: 'visible', timeout: 15_000 })
    expect((await A.page.textContent('body')) ?? '').toContain(String(TEMPLATES.length))
    expect(TEMPLATES.length).toBe(408)
    await shot(A.page, 'rules408-01-catalog')
  }, 60_000)

  it('confirms exactly the three served markers', async () => {
    await runActive(A.page, MARKER_BASE)
    const log = await A.page.locator('.feed').innerText()
    expect(log).toMatch(/CONFIRMED — Exposed \.gitlab-ci\.yml/)
    expect(log).toMatch(/CONFIRMED — GraphQL introspection enabled/)
    expect(log).toMatch(/CONFIRMED — Laravel Ignition reachable/)
    expect(await confirmedCount(A.page)).toBe(3)
    await shot(A.page, 'rules408-02-marker-run')
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 240_000)

  it('tags the Ignition finding with CVE-2021-3129 and a KEV badge, and shows the KEV card', async () => {
    await nav(A.page, 'Rule Engine')
    // The template library lists the same name too; only the findings row carries the KEV pill.
    const row = A.page.locator('tr', { hasText: 'Laravel Ignition reachable' }).filter({ hasText: 'KEV' })
    await row.waitFor({ state: 'visible', timeout: 15_000 })
    expect(await row.locator('.pill', { hasText: 'KEV' }).count()).toBe(1)
    expect(await row.textContent()).toContain('CVE-2021-3129')
    expect((await A.page.textContent('body')) ?? '').toContain(String(KEV_COUNT))
    await shot(A.page, 'rules408-06-ignition-kev')
  }, 60_000)

  it('shows Defense and Attack guidance for a confirmed finding', async () => {
    const row = A.page.locator('tr', { hasText: 'GraphQL introspection enabled' }).first()
    await row.waitFor({ state: 'visible', timeout: 15_000 })
    await row.click()
    await A.page.getByText('Defense — patching').waitFor({ state: 'visible', timeout: 10_000 })
    expect(await A.page.getByText('Attack').count()).toBeGreaterThan(0)
    await shot(A.page, 'rules408-03-advice')
  }, 60_000)

  it('catch-all server produces no confirmed findings', async () => {
    await clearFindings(A.page)
    await runActive(A.page, CATCH_BASE)
    const log = await A.page.locator('.feed').innerText()
    expect(log).toMatch(/CATCH-ALL/)
    expect(await confirmedCount(A.page)).toBe(0)
    await shot(A.page, 'rules408-04-catchall')
  }, 240_000)

  it('clearing removes all findings', async () => {
    await clearFindings(A.page)
    await A.page.getByText('No findings yet', { exact: false }).waitFor({ state: 'visible', timeout: 10_000 })
    await shot(A.page, 'rules408-05-cleared')
  }, 60_000)
})
