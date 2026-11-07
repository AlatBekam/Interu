import { app, shell, BrowserWindow, Menu, ipcMain, session } from 'electron'
import { join } from 'path'
import http from 'node:http'
import tls from 'node:tls'
import { sendHttp } from './http'
import { startProxy, stopProxy, setIntercept, setScope, resolveIntercept, isRunning, getPort } from './proxy'
import { exportCA, deleteCA, caFingerprint, CA_COMMON_NAME } from './ca'
import { runScan, cancelScan } from './scan'
import { openProxiedBrowser, registerBrowserIpc } from './browser'
import { hostInScope } from '../shared/http'
import type { HttpReq } from '../shared/http'
import { expandTargets, profilePorts, profileGrabsBanner, targetsInScope, MAX_ATTEMPTS } from '../shared/scan'
import type { ScanRequest, ScanResult, ScanEvent } from '../shared/scan'

function mainAppWindow(): BrowserWindow | null {
  const windows = BrowserWindow.getAllWindows()
  return windows.find((x) => !x.isDestroyed() && x.getTitle().includes('Cyber Operations')) || windows[0] || null
}

function emitToRenderer(channel: string, data: unknown): void {
  const w = mainAppWindow()
  if (!w || w.isDestroyed()) return
  w.webContents.send(channel, data)
  // When the proxy holds a request for intercept, surface the main app so the
  // operator can reach Forward/Drop even if the proxied browser covers it.
  if (channel === 'ruy:proxy:intercept') {
    if (w.isMinimized()) w.restore()
    w.show()
    w.focus()
  }
}

// The proxy brokers flaky third-party sockets; a stray error there must never
// take the whole app down. Log and keep running.
process.on('uncaughtException', (err) => console.error('[interu] uncaughtException:', err?.message || err))
process.on('unhandledRejection', (reason) => console.error('[interu] unhandledRejection:', reason))

// Port the proxied browser session is currently configured for (see ruy:proxy:openBrowser).
let proxiedSessionPort = -1

const isDev = !app.isPackaged
// RUY_SMOKE_TEST lets CI / build verification confirm the production bundle
// actually loads inside Electron (no dev server) and then exits cleanly.
const isSmokeTest = process.env.RUY_SMOKE_TEST === '1'

function createWindow(): BrowserWindow {
  const mainWindow = new BrowserWindow({
    width: 1340,
    height: 860,
    minWidth: 1024,
    minHeight: 680,
    show: false,
    title: 'Interu — Cyber Operations',
    backgroundColor: '#06070A',
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  // Native frame already provides minimize / maximize / resize / close.
  Menu.setApplicationMenu(null)

  mainWindow.on('ready-to-show', () => {
    if (!isSmokeTest) mainWindow.show()
  })

  // Open any external links in the user's real browser, never inside the app.
  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  mainWindow.webContents.on('did-finish-load', () => {
    if (isSmokeTest) {
      // Printed so the build pipeline can grep for success.
      console.log('RUY_SMOKE_RESULT: RENDER_OK')
      setTimeout(() => app.quit(), 1500)
    }
  })

  mainWindow.webContents.on('did-fail-load', (_e, code, desc, url) => {
    console.error(`RUY_SMOKE_RESULT: RENDER_FAIL code=${code} desc=${desc} url=${url}`)
    if (isSmokeTest) setTimeout(() => app.quit(), 500)
  })

  mainWindow.webContents.on('render-process-gone', (_e, details) => {
    console.error(`RUY_SMOKE_RESULT: RENDER_GONE reason=${details.reason}`)
    if (isSmokeTest) setTimeout(() => app.quit(), 500)
  })

  // RUY_START_ROUTE lets build verification open a specific screen directly
  // (e.g. "/web/proxy"); it has no effect on normal use.
  const startRoute = process.env.RUY_START_ROUTE
  const devUrl = process.env['ELECTRON_RENDERER_URL']
  if (isDev && devUrl) {
    mainWindow.loadURL(startRoute ? `${devUrl}#${startRoute}` : devUrl)
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'), startRoute ? { hash: startRoute } : undefined)
  }

  return mainWindow
}

// Single instance: a second launch focuses the existing window.
const gotLock = app.requestSingleInstanceLock()
if (!gotLock) {
  app.quit()
} else {
  let win: BrowserWindow | null = null

  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore()
      win.focus()
    }
  })

  // --- Real HTTP sender, gated by the operator-declared authorization scope ---
  ipcMain.handle('ruy:http', async (_e, payload: { req: HttpReq; scope: string[] }) => {
    const { req, scope } = payload || ({} as { req: HttpReq; scope: string[] })
    if (!req || !req.url) return { ok: false, timingMs: 0, size: 0, error: 'No request' }
    if (!hostInScope(req.url, scope || [])) {
      return {
        ok: false,
        blocked: true,
        timingMs: 0,
        size: 0,
        error: 'Target host is not in the authorized scope. Add it in Scope first.'
      }
    }
    return sendHttp(req)
  })

  // --- Real TCP connect scanner, gated by the operator-declared scope ---
  let scanSeq = 1
  ipcMain.handle('ruy:scan:tcp', async (_e, payload: { req: ScanRequest; scope: string[]; scanId?: number }): Promise<ScanResult> => {
    const { req, scope } = payload || ({} as { req: ScanRequest; scope: string[] })
    if (!req || !req.target || !req.target.trim()) return { ok: false, error: 'Target kosong.' }

    const exp = expandTargets(req.target)
    if (exp.error) return { ok: false, error: exp.error }
    if (exp.ips.length === 0) return { ok: false, error: 'Tidak ada IP yang bisa di-scan dari target itu.' }

    // Scope gate: every target IP must be authorized (exact IP or a CIDR in scope).
    const gate = targetsInScope(exp.ips, scope || [])
    if (!gate.ok) {
      return {
        ok: false,
        blocked: true,
        error: `IP ${gate.offending} di luar Authorized scope. Tambahkan host/CIDR yang kamu punya izinnya (mis. 10.20.0.0/24) di Scope dulu.`
      }
    }

    const profile = req.profile === 'quick' || req.profile === 'deep' ? req.profile : 'standard'
    const ports = profilePorts(profile)
    const attempts = exp.ips.length * ports.length
    if (attempts > MAX_ATTEMPTS) {
      return {
        ok: false,
        error: `Target terlalu besar: ${exp.ips.length} IP × ${ports.length} port = ${attempts} percobaan (maks ${MAX_ATTEMPTS}). Persempit range atau pakai profil lebih ringan.`
      }
    }

    const scanId = typeof payload?.scanId === 'number' && payload.scanId > 0 ? payload.scanId : scanSeq++
    const emit = (ev: ScanEvent): void => emitToRenderer('ruy:scan:progress', ev)
    try {
      const { summary, hosts } = await runScan(
        {
          scanId,
          target: req.target.trim(),
          profile,
          ips: exp.ips,
          ports,
          grabBanner: profileGrabsBanner(profile),
          timeoutMs: typeof req.timeoutMs === 'number' && req.timeoutMs > 0 ? Math.min(Math.max(req.timeoutMs, 100), 10000) : 1200,
          concurrency: 256
        },
        emit
      )
      return { ok: true, scanId, summary, hosts }
    } catch (e) {
      const error = (e as Error).message || 'scan failed'
      emit({ type: 'error', scanId, error })
      return { ok: false, scanId, error }
    }
  })
  ipcMain.handle('ruy:scan:cancel', (_e, scanId: number) => { cancelScan(scanId); return { ok: true } })

  // --- Real intercepting forward proxy ---
  ipcMain.handle('ruy:proxy:start', (_e, port: number) => startProxy(port || 8080, emitToRenderer))
  ipcMain.handle('ruy:proxy:stop', () => { proxiedSessionPort = -1; return stopProxy() })
  ipcMain.handle('ruy:proxy:status', () => ({ running: isRunning() }))
  ipcMain.handle('ruy:proxy:intercept', (_e, on: boolean) => { setIntercept(!!on); return { ok: true } })
  ipcMain.handle('ruy:proxy:scope', (_e, scope: string[]) => { setScope(scope); return { ok: true } })
  ipcMain.handle('ruy:proxy:resolve', (_e, p: { id: number; action: 'forward' | 'drop'; raw?: string }) => {
    resolveIntercept(p.id, p.action, p.raw)
    return { ok: true }
  })
  // Export the Interu root CA so an external browser/OS can trust it.
  ipcMain.handle('ruy:proxy:exportCA', () => {
    try {
      return { ok: true, path: exportCA(app.getPath('downloads')) }
    } catch (e) {
      return { ok: false, error: (e as Error).message }
    }
  })
  // Remove the stored root CA (encrypted key + cert). A fresh CA is minted on
  // next use; re-export & re-trust is then required.
  ipcMain.handle('ruy:proxy:removeCA', () => {
    try { deleteCA(); proxiedSessionPort = -1; return { ok: true } } catch (e) { return { ok: false, error: (e as Error).message } }
  })
  ipcMain.handle('ruy:proxy:caInfo', () => {
    try { return { ok: true, name: CA_COMMON_NAME, fingerprint: caFingerprint() } } catch (e) { return { ok: false, error: (e as Error).message } }
  })
  registerBrowserIpc()
  // Open a real browser window routed through the proxy (Burp-style). This
  // embedded session trusts the MITM certs automatically, so https is captured.
  // The window itself (address bar, back/forward/reload) lives in ./browser.
  ipcMain.handle('ruy:proxy:openBrowser', async (_e, startUrl?: string) => {
    try {
      if (!isRunning()) return { ok: false, error: 'Start the proxy first' }
      const port = getPort()
      const url = startUrl && /^https?:\/\//.test(startUrl) ? startUrl : 'http://example.com/'
      // Non-persistent session: a clean browser profile each time the app runs,
      // so stale cache / service workers from a previous run can't blank the page.
      const ses = session.fromPartition('interu-proxied')
      // Configure the session's proxy only when it changed, to avoid disrupting
      // an already-open window on repeated opens.
      if (proxiedSessionPort !== port) {
        // '<-loopback>' removes Chromium's implicit bypass of localhost/127.0.0.1, otherwise a
        // local target (the usual lab setup) would never reach the proxy and nothing is captured.
        await ses.setProxy({ proxyRules: `127.0.0.1:${port}`, proxyBypassRules: '<-loopback>' })
        // Trust ONLY certificates minted by the Interu root CA (i.e. the per-host
        // certs our MITM proxy presents for in-scope hosts). Anything else —
        // including the real certs of out-of-scope hosts that are blind-tunnelled
        // — falls back to Chromium's normal verification (cb(-3)), so a genuinely
        // invalid/forged certificate is still rejected. (Previously cb(0) trusted
        // every certificate unconditionally.)
        ses.setCertificateVerifyProc((request, cb) => {
          const cert = request.certificate as { issuerName?: string; issuer?: { commonName?: string } } | undefined
          const issuer = cert?.issuerName || cert?.issuer?.commonName || ''
          cb(issuer === CA_COMMON_NAME || issuer.includes(CA_COMMON_NAME) ? 0 : -3)
        })
        proxiedSessionPort = port
      }

      openProxiedBrowser(ses, url)
      return { ok: true }
    } catch (e) {
      return { ok: false, error: (e as Error).message }
    }
  })

  app.on('before-quit', () => { void stopProxy() })

  app.whenReady().then(async () => {
    app.setAppUserModelId('com.interu.cyberops')

    // Build-verification hook: fire one real request and print the result.
    if (process.env.RUY_HTTP_TEST) {
      const res = await sendHttp({ method: 'GET', url: process.env.RUY_HTTP_TEST, headers: {} })
      console.log(`RUY_HTTP_RESULT: ok=${res.ok} status=${res.status ?? '-'} size=${res.size} ms=${res.timingMs} err=${res.error ?? '-'}`)
      setTimeout(() => app.quit(), 300)
      return
    }

    // Build-verification hook: start the proxy and route one request through it.
    if (process.env.RUY_PROXY_TEST) {
      const r = await startProxy(18080, (ch, d) => {
        if (ch === 'ruy:proxy:log') {
          const e = d as { method?: string; host?: string; status?: number; length?: number }
          console.log(`RUY_PROXY_LOG: method=${e.method} host=${e.host} status=${e.status ?? '-'} len=${e.length ?? '-'}`)
        }
      })
      // Comma-separated scope; empty = verify the out-of-scope pass-through path.
      setScope((process.env.RUY_PROXY_SCOPE || '').split(',').filter(Boolean))
      console.log(`RUY_PROXY_START: ok=${r.ok} port=${r.port ?? '-'} err=${r.error ?? '-'}`)
      // 1) plain http through the proxy
      const req = http.request({ host: '127.0.0.1', port: 18080, method: 'GET', path: 'http://example.com/', headers: { Host: 'example.com' } }, (res) => {
        const ch: Buffer[] = []
        res.on('data', (c) => ch.push(c as Buffer))
        res.on('end', () => {
          console.log(`RUY_PROXY_CLIENT: status=${res.statusCode} size=${Buffer.concat(ch).length}`)
          // 2) https through the proxy via CONNECT + MITM
          const conn = http.request({ host: '127.0.0.1', port: 18080, method: 'CONNECT', path: 'example.com:443' })
          conn.on('connect', (_res, socket) => {
            const t = tls.connect({ socket, servername: 'example.com', rejectUnauthorized: false }, () => {
              t.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            })
            let buf = ''
            t.on('data', (d) => (buf += d.toString()))
            t.on('end', () => { console.log('RUY_MITM_CLIENT: ' + (buf.split('\r\n')[0] || 'no-status')); setTimeout(() => app.quit(), 400) })
            t.on('error', (e) => { console.log('RUY_MITM_ERR: ' + e.message); setTimeout(() => app.quit(), 300) })
          })
          conn.on('error', (e) => { console.log('RUY_MITM_CONNECT_ERR: ' + e.message); setTimeout(() => app.quit(), 300) })
          conn.end()
        })
      })
      req.on('error', (e) => { console.log('RUY_PROXY_CLIENT_ERR: ' + e.message); setTimeout(() => app.quit(), 300) })
      req.end()
      return
    }

    win = createWindow()

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) win = createWindow()
    })
  })

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit()
  })
}
