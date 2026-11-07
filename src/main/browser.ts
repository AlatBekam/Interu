// The Interu proxied browser: one window = a toolbar view (address bar, back/forward/reload)
// above a content view that uses the proxied session. Navigation is decided here, in the main
// process: the toolbar only sends intents, and every address is checked with the shared
// allow-list (http/https only), so neither the toolbar nor a page can reach file:/javascript:.
import { BrowserWindow, WebContentsView, ipcMain } from 'electron'
import type { Session, IpcMainEvent, IpcMainInvokeEvent } from 'electron'
import { join } from 'path'
import { isNavigableUrl, normalizeAddress } from '../shared/browser'
import { TOOLBAR_HEIGHT, TOOLBAR_HTML } from './browser-toolbar'

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
