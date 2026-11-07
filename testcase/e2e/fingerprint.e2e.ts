// GUI end-to-end for product-level KEV findings: a deep scan of a local server that
// claims to be Apache must show a version-blind "KEV product" finding, and it must
// not be counted as an actively exploited CVE.
// A local server on 127.0.0.1:8081 replies "Server: Apache/2.4.58 (Unix)"; scope is 127.0.0.1 only.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/fingerprint.e2e.ts
// Close any running Interu window first (single-instance lock).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const PORT = 8081
const HOST = '127.0.0.1'

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

async function deepScan(page: Page): Promise<void> {
  await nav(page, 'Network Scanner')
  await page.getByPlaceholder('127.0.0.1  /  10.20.0.0/24  /  10.0.0.1-50').fill(HOST)
  await page.locator('select', { has: page.locator('option[value="deep"]') }).selectOption('deep')
  await page.getByRole('button', { name: 'Run Scan' }).click()
  // The log gains this line only when the scan produced new findings.
  await page.getByText('> rule engine:', { exact: false }).waitFor({ state: 'visible', timeout: 120_000 })
}

// The value shown in a stat card, found by its label.
async function statValue(page: Page, label: string): Promise<string> {
  const card = page.locator('.stat', { has: page.locator('.s-label', { hasText: label }) })
  return ((await card.locator('.s-value').textContent()) ?? '').trim()
}

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.writeHead(200, { Server: 'Apache/2.4.58 (Unix)' })
    res.end('ok')
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

describe('GUI e2e — product-level KEV findings', () => {
  it('a deep scan shows an Apache product finding as a KEV CVE count, without listing the IDs', async () => {
    await deepScan(A.page)
    await nav(A.page, 'Exposure Monitor')
    const row = A.page.locator('tr', { hasText: 'Apache HTTP Server detected' }).filter({ hasText: 'KEV product' })
    await row.waitFor({ state: 'visible', timeout: 15_000 })
    const text = (await row.textContent()) ?? ''
    expect(text).toContain('(version not verified)')
    expect(text).toMatch(/\d+ KEV CVEs? \(product\)/)
    expect(text).not.toMatch(/CVE-\d{4}-\d+/)
    await shot(A.page, 'fingerprint-01-product-finding')
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 240_000)

  it('the full list is one click away in the Rule Engine', async () => {
    await nav(A.page, 'Rule Engine')
    await A.page.locator('tr', { hasText: 'Apache HTTP Server detected' }).first().click()
    const detail = (await A.page.locator('tr.detail-row').first().textContent()) ?? ''
    expect(detail).toContain('KEV CVEs for this product (not matched to your version)')
    expect(detail).toMatch(/CVE-\d{4}-\d+/)
    await shot(A.page, 'fingerprint-03-detail')
  }, 60_000)

  it('product-level findings are not counted as actively exploited', async () => {
    await nav(A.page, 'Exposure Monitor')
    expect(await statValue(A.page, 'Actively exploited (KEV)')).toBe('0')
    await shot(A.page, 'fingerprint-02-kev-card')
  }, 60_000)
})
