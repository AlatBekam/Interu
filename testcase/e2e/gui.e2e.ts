// GUI end-to-end: drive the REAL (main-branch) Electron app through its UI, the
// way an operator would, and confirm the Repeater "Live" flow works on a real URL.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts
//
// Authorization: the only network target is the public OWASP Juice Shop demo via
// a single GET (browser-equivalent). Override with TARGET_URL. No scanning here.
//
// NOTE: main does not honor RUY_USERDATA_DIR, so the app shares the operator's
// real localStorage (scope). The test therefore clears scope itself and removes
// the host it adds, leaving scope empty (the authorization-first default).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const TARGET_URL = process.env.TARGET_URL || 'https://juice-shop.herokuapp.com/'
const TARGET_HOST = new URL(TARGET_URL).hostname

let A: RunningApp

async function clearScope(page: Page): Promise<void> {
  // ScopeBar renders one .pill-ok per host, each with a title="Remove" button.
  while ((await page.locator('.pill-ok').count()) > 0) {
    await page.locator('.pill-ok span[title="Remove"]').first().click()
  }
}

beforeAll(async () => { A = await launchApp() }, 60_000)
afterAll(async () => {
  if (A?.page) { try { await clearScope(A.page) } catch { /* ignore */ } }
  await A?.close()
})

describe('GUI e2e — Repeater Live against a real target (main build)', () => {
  it('opens Repeater, blocks an out-of-scope target, then sends once authorized', async () => {
    const page = A.page
    await nav(page, 'Repeater')
    await page.getByRole('button', { name: 'Live', exact: true }).click()
    await page.getByPlaceholder('https://target-host:port').fill(TARGET_URL)
    await page.locator('textarea.code-pane').fill(
      `GET / HTTP/1.1\nHost: ${TARGET_HOST}\nUser-Agent: Interu-E2E\nAccept: */*\n\n`
    )
    await clearScope(page) // start from a known-empty scope (no isolation on main)
    await shot(page, 'gui-01-repeater-live')

    // 1) Scope gate: with scope empty, Send is refused in the UI (⛔ note).
    await page.getByRole('button', { name: /Send/ }).click()
    await page.locator('.disclaimer', { hasText: '⛔' }).waitFor({ state: 'visible', timeout: 10_000 })
    await shot(page, 'gui-02-blocked')

    // 2) Authorize the host via the ScopeBar, then Send for real.
    await page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(TARGET_HOST)
    await page.getByRole('button', { name: 'Add' }).click()
    await page.locator('.pill-ok', { hasText: TARGET_HOST }).waitFor({ state: 'visible', timeout: 10_000 })
    await page.getByRole('button', { name: /Send/ }).click()

    // Wait for either a rendered response or an error note (demo may be offline).
    const resp = page.locator('div.code-pane')
    const errNote = page.locator('.disclaimer', { hasText: '⚠' })
    await Promise.race([
      resp.waitFor({ state: 'visible', timeout: 30_000 }),
      errNote.waitFor({ state: 'visible', timeout: 30_000 })
    ])
    if (await errNote.isVisible()) {
      console.warn(`[skip] ${TARGET_URL} unreachable from GUI. Retry with TARGET_URL=https://demo.owasp-juice.shop`)
      await shot(page, 'gui-03-offline')
      return
    }
    const text = (await resp.innerText()).toLowerCase()
    await shot(page, 'gui-03-response')
    // A real HTTP round-trip reached the GUI, whatever the target's status — this
    // is the end-to-end proof. (The public demo now 503s; a local Juice Shop 200s.)
    expect(text).toMatch(/http\/1\.\d \d{3}/)
    if (/http\/1\.\d 2\d\d/.test(text)) {
      expect(text).toMatch(/juice shop|<app-root/)
    } else {
      console.warn(`[info] ${TARGET_URL} returned a non-2xx status (public demo is down). ` +
        `For the full content check, run a local Juice Shop and set TARGET_URL=http://localhost:3000`)
    }
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 60_000)
})
