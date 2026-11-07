// GUI end-to-end for the proxied browser: the Open Browser window must behave like a browser
// for navigation (address bar, back, forward, blocked schemes) and its traffic must go through
// the Interu proxy. A local server on 127.0.0.1 serves two pages; scope contains only 127.0.0.1;
// nothing outside this machine is contacted.
//
// Run:  npm run build && npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/browser.e2e.ts
// Close any running Interu window first (single-instance lock).
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { launchApp, nav, shot, ROOT, type RunningApp } from './helpers/app'

const PORT = 8096
const HOST = '127.0.0.1'
const A_URL = `http://${HOST}:${PORT}/a`
const B_URL = `http://${HOST}:${PORT}/b`

let A: RunningApp
let server: http.Server

const page = (title: string, body: string): string => `<!doctype html><title>${title}</title><body><h1>${title}</h1>${body}</body>`

interface Info { id: number; url: string; title: string }
const contents = (): Promise<Info[]> =>
  A.app.evaluate(({ webContents }) => webContents.getAllWebContents().map((w) => ({ id: w.id, url: w.getURL(), title: w.getTitle() })))
const content = async (): Promise<Info | undefined> => (await contents()).find((w) => w.url.startsWith(`http://${HOST}:${PORT}`))
const toolbarId = async (): Promise<number> => {
  const t = (await contents()).find((w) => w.url.startsWith('data:text/html') && w.title === 'Interu Browser')
  if (!t) throw new Error('toolbar not found')
  return t.id
}
const inToolbar = async <T>(js: string): Promise<T> => {
  const id = await toolbarId()
  return A.app.evaluate(({ webContents }, a) => webContents.fromId(a.id)!.executeJavaScript(a.js), { id, js }) as Promise<T>
}
const inContent = async (js: string): Promise<unknown> => {
  const c = await content()
  if (!c) throw new Error('content not found')
  return A.app.evaluate(({ webContents }, a) => webContents.fromId(a.id)!.executeJavaScript(a.js, true), { id: c.id, js })
}
const typeAddress = (text: string): Promise<unknown> =>
  inToolbar(`(() => { const a = document.getElementById('addr'); a.value = ${JSON.stringify(text)}; a.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' })); return true })()`)

// The browser window is not the page Playwright drives, so capture its two views from the main process.
async function shotViews(name: string): Promise<void> {
  const dir = join(ROOT, 'testcase', 'results', 'screenshots')
  mkdirSync(dir, { recursive: true })
  for (const [kind, id] of [['toolbar', await toolbarId()], ['content', (await content())!.id]] as const) {
    const b64 = await A.app.evaluate(async ({ webContents }, wid) => (await webContents.fromId(wid)!.capturePage()).toPNG().toString('base64'), id)
    writeFileSync(join(dir, `${name}-${kind}.png`), Buffer.from(b64, 'base64'))
  }
}

async function until<T>(read: () => Promise<T>, ok: (v: T) => boolean, label: string, ms = 15_000): Promise<T> {
  const end = Date.now() + ms
  let last: T | undefined
  while (Date.now() < end) {
    last = await read()
    if (ok(last)) return last
    await new Promise((r) => setTimeout(r, 150))
  }
  throw new Error(`timeout waiting for ${label}; last: ${JSON.stringify(last)}`)
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    if (req.url === '/a') return res.end(page('Page A', '<a id="next" href="/b">to b</a> <a id="blank" target="_blank" href="/b">blank</a>'))
    if (req.url === '/b') return res.end(page('Page B', '<a href="/a">to a</a>'))
    res.end(page('Other', ''))
  })
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(PORT, HOST, () => resolve()) })

  A = await launchApp()
  await nav(A.page, 'Proxy')
  while ((await A.page.locator('.pill-ok').count()) > 0) await A.page.locator('.pill-ok span[title="Remove"]').first().click()
  await A.page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill(HOST)
  await A.page.getByRole('button', { name: 'Add' }).click()
  await A.page.getByRole('button', { name: 'Start', exact: true }).click()
  await A.page.getByText('Proxy running').waitFor({ state: 'visible', timeout: 15_000 })
}, 90_000)

afterAll(async () => {
  await A?.close()
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('GUI e2e — proxied browser navigation', () => {
  it('opens on the given address and shows the page title', async () => {
    await A.page.getByPlaceholder('http://target/').fill(A_URL)
    await A.page.getByRole('button', { name: 'Open Browser' }).click()
    const c = await until(content, (v) => !!v && v.url === A_URL && v.title === 'Page A', 'content on /a')
    expect(c!.title).toBe('Page A')
    const addr = await until(() => inToolbar<string>(`document.getElementById('addr').value`), (v) => v === A_URL, 'address shows the url')
    expect(addr).toBe(A_URL)
    await shot(A.page, 'browser-01-open')
    await shotViews('browser-01')
  }, 60_000)

  it('typing another address navigates, and back / forward work', async () => {
    await typeAddress(`${HOST}:${PORT}/b`) // no scheme: normalised to http because of the port
    await until(content, (v) => v?.url === B_URL && v.title === 'Page B', 'content on /b')

    await until(() => inToolbar<boolean>(`!document.getElementById('back').disabled`), (v) => v, 'back enabled')
    await inToolbar(`document.getElementById('back').click()`)
    await until(content, (v) => v?.url === A_URL, 'back to /a')

    expect(await inToolbar<boolean>(`!document.getElementById('fwd').disabled`)).toBe(true)
    await inToolbar(`document.getElementById('fwd').click()`)
    await until(content, (v) => v?.url === B_URL, 'forward to /b')
  }, 60_000)

  it('refuses non-http(s) addresses and leaves the page where it was', async () => {
    const before = (await content())!.url
    await typeAddress('javascript:alert(1)')
    await until(() => inToolbar<boolean>(`!document.getElementById('err').hidden`), (v) => v, 'error shown in the toolbar')
    await typeAddress('file:///c:/windows/win.ini')
    await new Promise((r) => setTimeout(r, 400))
    expect((await content())!.url).toBe(before)
  }, 60_000)

  it('a target=_blank link loads in the same view, without a new window', async () => {
    await typeAddress(A_URL)
    await until(content, (v) => v?.url === A_URL, 'on /a')
    const windows = (): Promise<number> => A.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length)
    const before = await windows()
    await inContent(`document.getElementById('blank').click()`)
    await until(content, (v) => v?.url === B_URL, 'blank link opened in the same view')
    expect(await windows()).toBe(before)
    await shot(A.page, 'browser-02-after-blank')
    await shotViews('browser-02')
  }, 60_000)

  it('its traffic went through the proxy and is in HTTP History', async () => {
    await nav(A.page, 'Exposure Monitor')
    await nav(A.page, 'Proxy')
    // History only fills while the page is mounted; the browser keeps working, so trigger fresh requests.
    await typeAddress(B_URL)
    await until(content, (v) => v?.url === B_URL, 'on /b')
    await A.page.locator('td', { hasText: '/b' }).first().waitFor({ state: 'visible', timeout: 15_000 })
    expect(await A.page.locator('td', { hasText: '/b' }).count()).toBeGreaterThan(0)
    expect(A.pageErrors, `renderer errors: ${A.pageErrors.join(' | ')}`).toHaveLength(0)
  }, 60_000)
})
