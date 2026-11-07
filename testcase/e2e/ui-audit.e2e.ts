// Visual audit: open every sidebar page in both themes, save a screenshot of each, and fail
// on renderer errors or horizontal overflow. A local server on 127.0.0.1 supplies a few real
// findings so the tables are populated; nothing outside this machine is contacted.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/ui-audit.e2e.ts
// Screenshots: testcase/results/screenshots/ui-<page>-<theme>.png
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { Page } from 'playwright-core'
import { launchApp, nav, shot, type RunningApp } from './helpers/app'

const PORT = 8095
const HOST = '127.0.0.1'

let A: RunningApp
let server: http.Server

const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')

async function setTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
  await page.getByRole('button', { name: theme === 'light' ? 'Light' : 'Dark', exact: true }).first().click()
  await page.waitForFunction((t) => document.documentElement.dataset.theme === t, theme)
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if ((req.url ?? '').startsWith('/.gitlab-ci.yml')) {
      res.writeHead(200, { 'Content-Type': 'text/plain', Server: 'Apache/2.4.58 (Unix)' })
      return res.end('stages:\n  - build\nscript:\n  - make\n')
    }
    res.writeHead(404, { Server: 'Apache/2.4.58 (Unix)' })
    res.end('not found')
  })
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(PORT, HOST, () => resolve()) })

  A = await launchApp()
  await nav(A.page, 'Rule Engine')
  await A.page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(HOST)
  await A.page.getByRole('button', { name: 'Add' }).click()
  await A.page.getByPlaceholder('http://127.0.0.1/  ·  https://host.example.com/').fill(`http://${HOST}:${PORT}/`)
  await A.page.getByRole('button', { name: 'Run active checks' }).click()
  await A.page.locator('.feed').getByText(/> done —/).waitFor({ state: 'visible', timeout: 180_000 })
}, 240_000)

afterAll(async () => {
  await A?.close()
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('UI audit — every page, both themes', () => {
  it.each(['dark', 'light'] as const)('%s theme: all pages render without errors or overflow', async (theme) => {
    const page = A.page
    await setTheme(page, theme)
    const labels = await page.locator('nav .nav-item').allInnerTexts()
    expect(labels.length).toBeGreaterThanOrEqual(12)
    for (const label of labels) {
      await nav(page, label.trim())
      await page.waitForTimeout(250)
      const overflow = await page.evaluate(() => {
        const c = document.querySelector('.content')
        return { page: document.documentElement.scrollWidth - window.innerWidth, content: c ? c.scrollWidth - c.clientWidth : 0 }
      })
      expect(overflow.page, `${label}: page overflows horizontally`).toBeLessThanOrEqual(0)
      expect(overflow.content, `${label}: content overflows horizontally`).toBeLessThanOrEqual(0)
      await shot(page, `ui-${slug(label)}-${theme}`)
    }
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 180_000)
})
