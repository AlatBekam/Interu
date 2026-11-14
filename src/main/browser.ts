// The Interu proxied browser: one window = a toolbar view (address bar, back/forward/reload)
// above a content view that uses the proxied session. Navigation is decided here, in the main
// process: the toolbar only sends intents, and every address is checked with the shared
// allow-list (http/https only), so neither the toolbar nor a page can reach file:/javascript:.
import { BrowserWindow, WebContentsView, ipcMain } from 'electron'
import type { Session, IpcMainEvent, IpcMainInvokeEvent, WebContents } from 'electron'
import { join } from 'path'
import { isNavigableUrl, normalizeAddress } from '../shared/browser'
import { TOOLBAR_HEIGHT, TOOLBAR_HTML } from './browser-toolbar'
import { isUnsafeAuthedPath } from '../shared/auth'
import { randomBytes } from 'node:crypto'
import { setTimeout as pause } from 'node:timers/promises'
import { protectProxySecret } from './proxy'

export interface BrowserDiscovery {
  urls: string[]
  forms: Array<{ url: string; action: string; method: string; fields: string[]; kind: 'login' | 'register' | 'other' }>
  pages: number
  note: string
  accountFlow?: 'not-attempted' | 'no-registration-form' | 'blocked' | 'submitted-unverified' | 'session-observed'
}

async function loadBounded(wc: WebContents, url: string): Promise<void> {
  const timer = new AbortController()
  try {
    await Promise.race([
      wc.loadURL(url),
      pause(15000, undefined, { signal: timer.signal }).then(() => { wc.stop(); throw new Error('Page timeout') })
    ])
  } finally { timer.abort() }
}

async function submitAccountForm(url: string, mode: 'register' | 'login', account: { user: string; email: string; password: string }): Promise<boolean> {
  if (!alive(shell)) return false
  const origin = new URL(url).origin
  try { await loadBounded(shell.content.webContents, url) } catch { return false }
  if (new URL(shell.content.webContents.getURL()).origin !== origin) return false
  try {
    return await shell.content.webContents.executeJavaScript(`(() => {
      const d = ${JSON.stringify({ ...account, mode, origin })};
      const forms = Array.from(document.forms);
      const form = forms.find(f => f.querySelector('input[type=password]') &&
        (d.mode === 'login' || /register|sign[-_]?up|create[-_]?account/i.test(location.pathname + ' ' + f.action)));
      if (!form || form.method.toUpperCase() !== 'POST' || new URL(form.action, location.href).origin !== d.origin ||
          form.querySelector('[name*=captcha i],[id*=captcha i],[name*=otp i],[name*=mfa i],input[type=file]') ||
          form.querySelector('input[type=checkbox][required]:not(:checked)')) return false;
      const fields = Array.from(form.querySelectorAll('input'));
      const passwordFields = fields.filter(i => i.type === 'password');
      if (!passwordFields.length) return false;
      for (const input of fields) {
        const name = ((input.name || '') + ' ' + (input.id || '') + ' ' + (input.autocomplete || '')).toLowerCase();
        let value = '';
        if (input.type === 'password') value = d.password;
        else if (input.type === 'email' || /email|e-mail/.test(name)) value = d.email;
        else if (/user|login|account|nick|first.?name|last.?name/.test(name) && input.type !== 'hidden') value = d.user;
        if (value) {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          setter.call(input, value);
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
      const missing = fields.some(i => i.required && i.type !== 'hidden' && i.type !== 'checkbox' && !i.value);
      if (missing) return false;
      const submit = form.querySelector('button[type=submit],input[type=submit],button:not([type])');
      if (submit) submit.click(); else form.requestSubmit();
      return true;
    })()`, true) as boolean
  } catch { return false }
}

/** Best-effort self-registration. Generated account details never leave the main process except via the target's own form. */
export async function tryGeneratedAccount(seed: string, discovery: BrowserDiscovery): Promise<BrowserDiscovery['accountFlow']> {
  if (!alive(shell)) return 'blocked'
  const registration = discovery.forms.find(f => f.kind === 'register' && new URL(f.url).origin === new URL(seed).origin)
  if (!registration) return 'no-registration-form'
  const suffix = randomBytes(6).toString('hex')
  const account = { user: `interu_${suffix}`, email: `interu_${suffix}@example.invalid`, password: randomBytes(24).toString('base64url') + 'A1!' }
  protectProxySecret(account.password)
  const before = await shell.content.webContents.session.cookies.get({ url: seed })
  if (!await submitAccountForm(registration.url, 'register', account)) return 'blocked'
  await pause(1500)
  const login = discovery.forms.find(f => f.kind === 'login' && new URL(f.url).origin === new URL(seed).origin)
  if (login) { await submitAccountForm(login.url, 'login', account); await pause(1500) }
  const after = await shell.content.webContents.session.cookies.get({ url: seed })
  const old = new Map(before.map(c => [c.name, c.value]))
  return after.some(c => old.get(c.name) !== c.value) ? 'session-observed' : 'submitted-unverified'
}

/** Browse a small set of same-origin GET pages with the real proxied Chromium view. */
export async function discoverInProxiedBrowser(seed: string, maxPages = 12): Promise<BrowserDiscovery> {
  if (!alive(shell)) throw new Error('Interu Browser is not open')
  const origin = new URL(seed).origin
  const wc = shell.content.webContents
  const guard = (event: { preventDefault(): void }, url: string): void => {
    try { if (new URL(url).origin !== origin) event.preventDefault() } catch { event.preventDefault() }
  }
  wc.on('will-navigate', guard)
  wc.on('will-redirect', guard)
  const queue = [seed]
  const seen = new Set<string>()
  const forms: BrowserDiscovery['forms'] = []
  try { while (queue.length && seen.size < Math.min(20, Math.max(1, maxPages))) {
    const next = queue.shift()!
    if (seen.has(next) || new URL(next).origin !== origin || isUnsafeAuthedPath(next)) continue
    seen.add(next)
    try {
      await loadBounded(wc, next)
      if (new URL(wc.getURL()).origin !== origin) continue
      await pause(800)
      const page = await wc.executeJavaScript(`(async () => {
        const links = new Set();
        const collect = () => {
          for (const a of Array.from(document.querySelectorAll('a[href],a[routerlink],[data-href],[data-url]')).slice(0, 300)) {
            const href = a.getAttribute('href') || a.getAttribute('routerlink') || a.getAttribute('data-href') || a.getAttribute('data-url');
            if (href) try { links.add(new URL(href, location.href).href) } catch {}
          }
        };
        collect();
        const menus = Array.from(document.querySelectorAll('button,[role=button]')).filter(b =>
          !b.closest('form') && /account.*menu|menu.*account|navigation menu|main menu/i.test(
            (b.getAttribute('aria-label') || '') + ' ' + (b.getAttribute('title') || '') + ' ' + (b.textContent || '').trim()
          )).slice(0, 3);
        for (const menu of menus) { menu.click(); await new Promise(r => setTimeout(r, 150)); collect() }
        return { links: [...links],
        forms: Array.from(document.forms).slice(0, 30).map(f => ({
          action: f.action, method: (f.method || 'GET').toUpperCase(),
          fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0, 40)
            .map(i => i.getAttribute('name') || i.getAttribute('type') || '').filter(Boolean),
          hasPassword: !!f.querySelector('input[type=password]')
        }))
      } })()`, true) as { links: string[]; forms: Array<{ action: string; method: string; fields: string[]; hasPassword: boolean }> }
      for (const f of page.forms) {
        const label = `${next} ${f.action}`.toLowerCase()
        const kind = /register|sign[-_]?up|create[-_]?account/.test(label) ? 'register'
          : f.hasPassword || /log[-_]?in|sign[-_]?in/.test(label) ? 'login' : 'other'
        forms.push({ url: next, action: f.action, method: f.method, fields: f.fields, kind })
      }
      const candidates = page.links.filter(url => {
        try { return new URL(url).origin === origin && !isUnsafeAuthedPath(url) && !/\.(?:png|jpe?g|gif|svg|css|js|woff2?|pdf|zip)(?:\?|$)/i.test(url) } catch { return false }
      })
      candidates.sort((a, b) => Number(/register|sign[-_]?up|log[-_]?in|sign[-_]?in/i.test(b)) - Number(/register|sign[-_]?up|log[-_]?in|sign[-_]?in/i.test(a)))
      for (const url of candidates) if (!seen.has(url) && !queue.includes(url) && queue.length < 100) queue.push(url)
    } catch { /* page load failures remain visible in the browser; continue bounded discovery */ }
    await pause(500)
  } } finally { wc.removeListener('will-navigate', guard); wc.removeListener('will-redirect', guard) }
  return { urls: [...seen], forms, pages: seen.size,
    note: 'Login and registration forms were inventoried; no account was created or authenticated by discovery.' }
}

interface Shell {
  win: BrowserWindow
  toolbar: WebContentsView
  content: WebContentsView
  /** URL the operator asked for when the page failed to load (the content then shows an error page). */
  failedUrl: string | null
}

// Single reusable window, as before: a second "Open Browser" navigates it instead of stacking windows.
let shell: Shell | null = null

const alive = (s: Shell | null): s is Shell => !!s && !s.win.isDestroyed()

const errorPage = (desc: string, code: number, url: string): string => {
  const esc = (t: string): string => t.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string)
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(
    `<!doctype html><meta charset="utf-8"><body style="font-family:Segoe UI,system-ui;background:#0d0f12;color:#a9b2bf;margin:0;padding:48px;line-height:1.6">
    <h2 style="color:#e6e9ee;margin:0 0 8px">Gagal memuat halaman</h2>
    <p style="color:#ff6b63;font-family:monospace">${esc(desc)} (${code})</p>
    <p style="color:#8892a1;font-family:monospace;word-break:break-all">${esc(url)}</p>
    <p>Pastikan proxy masih jalan dan URL target benar.</p></body>`
  )
}

function pushState(s: Shell, error?: string): void {
  const tw = s.toolbar.webContents
  if (tw.isDestroyed()) return
  const wc = s.content.webContents
  const onErrorPage = wc.getURL().startsWith('data:')
  tw.send('ruy:browser:state', {
    url: onErrorPage ? (s.failedUrl ?? '') : wc.getURL(),
    title: wc.getTitle(),
    loading: wc.isLoading(),
    canGoBack: wc.navigationHistory.canGoBack(),
    canGoForward: wc.navigationHistory.canGoForward(),
    error
  })
}

function layout(s: Shell): void {
  const { width, height } = s.win.getContentBounds()
  s.toolbar.setBounds({ x: 0, y: 0, width, height: TOOLBAR_HEIGHT })
  s.content.setBounds({ x: 0, y: TOOLBAR_HEIGHT, width, height: Math.max(0, height - TOOLBAR_HEIGHT) })
}

function create(ses: Session): Shell {
  const win = new BrowserWindow({
    width: 1120,
    height: 780,
    title: 'Interu Browser — proxied',
    backgroundColor: '#0d0f12',
    autoHideMenuBar: true,
    webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false }
  })
  win.setMenuBarVisibility(false)

  const toolbar = new WebContentsView({
    webPreferences: { preload: join(__dirname, '../preload/browser.js'), sandbox: true, contextIsolation: true, nodeIntegration: false }
  })
  // Non-persistent session partition, trusts only Interu-minted certs (set up by the caller).
  const content = new WebContentsView({ webPreferences: { session: ses, sandbox: true, contextIsolation: true, nodeIntegration: false } })
  content.setBackgroundColor('#ffffff')
  win.contentView.addChildView(content)
  win.contentView.addChildView(toolbar)

  const s: Shell = { win, toolbar, content, failedUrl: null }
  const wc = content.webContents

  layout(s)
  for (const ev of ['resize', 'maximize', 'unmaximize', 'enter-full-screen', 'leave-full-screen'] as const) win.on(ev as 'resize', () => layout(s))

  // Content hardening: nothing may leave http/https, and pop-ups load in this same view (no extra windows).
  wc.setWindowOpenHandler(({ url }) => {
    if (isNavigableUrl(url)) wc.loadURL(url).catch(() => {})
    return { action: 'deny' }
  })
  wc.on('will-navigate', (e, url) => { if (!isNavigableUrl(url)) e.preventDefault() })
  wc.on('will-redirect', (e, url) => { if (!isNavigableUrl(url)) e.preventDefault() })

  for (const ev of ['did-start-loading', 'did-stop-loading', 'did-navigate', 'did-navigate-in-page'] as const) {
    wc.on(ev as 'did-navigate', () => pushState(s))
  }
  wc.on('did-start-navigation', (_e, url, _inPlace, isMainFrame) => { if (isMainFrame && !url.startsWith('data:')) s.failedUrl = null })
  wc.on('page-title-updated', (_e, title) => {
    win.setTitle(`Interu Browser — ${title || 'proxied'}`)
    pushState(s)
  })
  wc.on('did-fail-load', (_e, code, desc, failedUrl, isMainFrame) => {
    if (!isMainFrame || code === -3) return // -3 = aborted (e.g. redirect), ignore
    s.failedUrl = failedUrl
    wc.loadURL(errorPage(desc, code, failedUrl)).catch(() => {})
    pushState(s, `${desc} (${code})`)
  })
  // Keyboard shortcuts while the page has focus.
  wc.on('before-input-event', (e, input) => {
    if (input.type !== 'keyDown') return
    const key = input.key.toLowerCase()
    if (input.alt && key === 'arrowleft') { e.preventDefault(); if (wc.navigationHistory.canGoBack()) wc.navigationHistory.goBack() }
    else if (input.alt && key === 'arrowright') { e.preventDefault(); if (wc.navigationHistory.canGoForward()) wc.navigationHistory.goForward() }
    else if (key === 'f5' || (input.control && key === 'r')) { e.preventDefault(); reload(s) }
    else if (input.control && key === 'l') { e.preventDefault(); toolbar.webContents.focus(); toolbar.webContents.send('ruy:browser:focusAddress') }
  })

  toolbar.webContents.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(TOOLBAR_HTML)).catch(() => {})
  toolbar.webContents.once('did-finish-load', () => pushState(s))

  win.on('closed', () => {
    if (shell === s) shell = null
    for (const v of [content, toolbar]) { if (!v.webContents.isDestroyed()) v.webContents.close() }
  })
  return s
}

function reload(s: Shell): void {
  const wc = s.content.webContents
  if (s.failedUrl) wc.loadURL(s.failedUrl).catch(() => {})
  else wc.reload()
}

/** Open the proxied browser on `url`, or navigate the existing window. `ses` must already be proxy- and CA-configured. */
export function openProxiedBrowser(ses: Session, url: string): void {
  if (alive(shell)) {
    if (shell.win.isMinimized()) shell.win.restore()
    shell.win.focus()
    shell.content.webContents.loadURL(url).catch(() => {})
    return
  }
  shell = create(ses)
  shell.content.webContents.loadURL(url).catch(() => {})
}

/** Register the toolbar's IPC once. Every handler first checks that the call came from the toolbar view. */
export function registerBrowserIpc(): void {
  const fromToolbar = (e: IpcMainEvent | IpcMainInvokeEvent): Shell | null =>
    alive(shell) && e.sender.id === shell.toolbar.webContents.id ? shell : null

  ipcMain.handle('ruy:browser:go', (e, input: unknown) => {
    const s = fromToolbar(e)
    if (!s) return { ok: false, error: 'not allowed' }
    const r = normalizeAddress(typeof input === 'string' ? input : '')
    if (!r.ok) { pushState(s, r.error); return { ok: false, error: r.error } }
    s.content.webContents.loadURL(r.url).catch(() => {})
    return { ok: true }
  })
  ipcMain.on('ruy:browser:back', (e) => { const s = fromToolbar(e); if (s && s.content.webContents.navigationHistory.canGoBack()) s.content.webContents.navigationHistory.goBack() })
  ipcMain.on('ruy:browser:forward', (e) => { const s = fromToolbar(e); if (s && s.content.webContents.navigationHistory.canGoForward()) s.content.webContents.navigationHistory.goForward() })
  ipcMain.on('ruy:browser:reload', (e) => { const s = fromToolbar(e); if (s) reload(s) })
  ipcMain.on('ruy:browser:stop', (e) => { const s = fromToolbar(e); if (s) s.content.webContents.stop() })
  ipcMain.on('ruy:browser:focusContent', (e) => { const s = fromToolbar(e); if (s) s.content.webContents.focus() })
}
