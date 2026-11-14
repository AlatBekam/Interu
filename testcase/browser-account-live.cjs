const http = require('node:http')
const { _electron } = require('playwright-core')
const path = require('node:path')
const fs = require('node:fs')

let registered = null, loggedIn = 0, privateAuthed = 0, scannerPrivateAuthed = 0
const server = http.createServer(async (req, res) => {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const data = new URLSearchParams(Buffer.concat(chunks).toString())
  const html = body => { res.setHeader('content-type', 'text/html'); res.end(body) }
  if (req.url === '/register' && req.method === 'POST') {
    registered = { user: data.get('username'), email: data.get('email'), password: data.get('password') }
    res.writeHead(302, { location: '/login' }); res.end(); return
  }
  if (req.url === '/login' && req.method === 'POST') {
    if (registered && data.get('username') === registered.user && data.get('password') === registered.password) {
      loggedIn++; res.writeHead(302, { location: '/private', 'set-cookie': 'session=interu-test-session; HttpOnly; Path=/' }); res.end()
    } else { res.writeHead(401); res.end('bad login') }
    return
  }
  if (req.url === '/private') {
    if (!req.headers.cookie?.includes('session=interu-test-session')) { res.writeHead(302, { location: '/login' }); res.end(); return }
    privateAuthed++; if (req.headers['user-agent']?.includes('Interu/1.4')) scannerPrivateAuthed++
    html(`<h1>Private account ${registered?.user}</h1>`); return
  }
  if (req.url === '/register') { html('<h1>Register</h1><form method="POST" action="/register"><input name="username" required><input name="email" type="email" required><input name="password" type="password" required><button type="submit">Register</button></form>'); return }
  if (req.url === '/login') { html('<h1>Login</h1><form method="POST" action="/login"><input name="username" required><input name="password" type="password" required><button type="submit">Login</button></form>'); return }
  if (req.url === '/') { html('<h1>Home</h1><a href="/register">Register</a><a href="/login">Login</a><a href="/private">Private</a>'); return }
  res.writeHead(404); res.end('not found')
})

;(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const url = `http://127.0.0.1:${server.address().port}/`
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE
  const app = await _electron.launch({ executablePath: path.resolve('release/win-unpacked/Interu.exe'), args: [`--user-data-dir=${path.resolve('audit/browser-account-profile')}`], env, timeout: 30000 })
  try {
    const page = await app.firstWindow()
    await page.getByText('Exposure Monitor', { exact: true }).first().waitFor({ timeout: 30000 })
    await page.evaluate(() => { window.__interuTestLogs = []; window.ruy.proxy.onLog(entry => window.__interuTestLogs.push(entry)) })
    await page.getByText('Pentest Automation', { exact: true }).first().click()
    await page.getByPlaceholder('host.example.com / 10.0.0.0/24').fill('127.0.0.1')
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await page.getByPlaceholder('https://target.example.com/app').fill(url)
    await page.getByLabel('Maximum pages').fill('12')
    await page.getByLabel('Request budget').fill('40')
    await page.getByLabel('Exposure template checks').uncheck()
    await page.getByLabel('Query probes').uncheck()
    await page.getByRole('button', { name: 'Explore + create test account + run' }).click()
    for (let i = 0; i < 90; i++) {
      const run = await page.evaluate(() => window.ruy.automation.status())
      if (run.status !== 'idle' && run.status !== 'running') break
      await page.waitForTimeout(1000)
    }
    const run = await page.evaluate(() => window.ruy.automation.status())
    const text = await page.locator('body').innerText()
    const proxyLogs = await page.evaluate(() => window.__interuTestLogs)
    const result = { registered: !!registered, loggedIn, privateAuthed, scannerPrivateAuthed, status: run.status, requests: run.requests,
      accountFlowShown: text.includes('session-observed') || text.includes('browser cookies were attached'),
      hasSecretInUi: !!registered && text.includes(registered.password),
      hasSecretInProxyLog: !!registered && JSON.stringify(proxyLogs).includes(registered.password),
      hasSessionInProxyLog: JSON.stringify(proxyLogs).includes('interu-test-session') }
    fs.writeFileSync(path.resolve('audit/browser-account-verification.json'), JSON.stringify(result, null, 2))
    console.log(JSON.stringify(result))
    if (!result.registered || !loggedIn || !scannerPrivateAuthed || !result.accountFlowShown || result.hasSecretInUi || result.hasSecretInProxyLog || result.hasSessionInProxyLog) process.exitCode = 1
  } finally {
    try { await pageSafeStop(app) } catch {}
    await Promise.race([app.close(), new Promise(resolve => setTimeout(resolve, 10000))])
    server.close()
  }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1 })

async function pageSafeStop(app) {
  const windows = app.windows()
  const main = windows[0]
  await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) if (!w.isDestroyed() && w.getTitle().startsWith('Interu Browser')) w.close() })
  if (main) await main.evaluate(() => window.ruy.proxy.stop())
  await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) if (!w.isDestroyed()) w.close() })
}
