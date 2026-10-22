import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import { URL } from 'node:url'
import { getHostCert } from './ca'
import { authorize } from './audit'
import { hostInScope } from '../shared/http'

// A real intercepting forward proxy with HTTPS MITM.
//   * http://  and (via MITM) https:// requests are captured in full and can be
//     intercepted (held, edited, forwarded or dropped).
//   * TLS is terminated locally with a per-host certificate signed by the Interu
//     root CA, so https traffic is decrypted and visible.
// Captured transactions are streamed to the renderer as events.
// Only hosts in the operator's authorized scope are decrypted, logged or
// intercepted; everything else is passed through untouched.

export type Emit = (channel: string, data: unknown) => void

let server: http.Server | null = null
let mitm: https.Server | null = null
let listenPort = 8080
let seq = 1
let intercepting = false
let emit: Emit = () => {}
let scope: string[] = []
const pending = new Map<number, (d: { action: 'forward' | 'drop'; raw?: string }) => void>()

const now = (): string => new Date().toLocaleTimeString('en-GB', { hour12: false })
const CAP = 50000

export function getPort(): number { return listenPort }
export function isRunning(): boolean { return !!server }

export function setScope(s: unknown): void {
  scope = Array.isArray(s) ? s.filter((x): x is string => typeof x === 'string') : []
}

export function setIntercept(v: boolean): void {
  intercepting = v
  if (!v) for (const [id, fn] of pending) { fn({ action: 'forward' }); pending.delete(id) }
}
export function resolveIntercept(id: number, action: 'forward' | 'drop', raw?: string): void {
  const fn = pending.get(id)
  if (fn) { pending.delete(id); fn({ action, raw }) }
}

export function stopProxy(): Promise<void> {
  return new Promise((res) => {
    for (const [id, fn] of pending) { fn({ action: 'drop' }); pending.delete(id) }
    const done = (): void => { if (!server && !mitm) res() }
    if (mitm) { mitm.close(() => { mitm = null; done() }) }
    if (server) { server.close(() => { server = null; done() }) } else done()
    if (!server && !mitm) res()
  })
}

function parseRaw(raw: string): { method: string; path: string; headers: Record<string, string>; body: string } {
  const norm = raw.replace(/\r\n/g, '\n')
  const sep = norm.indexOf('\n\n')
  const head = sep >= 0 ? norm.slice(0, sep) : norm
  const body = sep >= 0 ? norm.slice(sep + 2) : ''
  const lines = head.split('\n')
  const first = (lines.shift() || '').trim()
  const m = first.match(/^(\S+)\s+(\S+)/)
  const headers: Record<string, string> = {}
  for (const l of lines) { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim() }
  return { method: (m?.[1] || 'GET').toUpperCase(), path: m?.[2] || '/', headers, body }
}

function buildRawReq(method: string, u: URL, headers: http.IncomingHttpHeaders, body: Buffer): string {
  const hl = Object.entries(headers)
    .filter(([k]) => k.toLowerCase() !== 'proxy-connection')
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('\r\n')
  return `${method} ${u.pathname + u.search} HTTP/1.1\r\n${hl}\r\n\r\n${body.toString('utf8')}`
}

function handleRequest(clientReq: http.IncomingMessage, clientRes: http.ServerResponse, scheme: 'http' | 'https'): void {
  let u: URL
  try {
    const raw = clientReq.url || '/'
    u = /^https?:\/\//i.test(raw) ? new URL(raw) : new URL(`${scheme}://${clientReq.headers.host}${raw}`)
  } catch {
    clientRes.writeHead(400); clientRes.end('Bad proxy request'); return
  }

  const inScope = hostInScope(u.href, scope)
  const id = seq++
  const started = Date.now()
  const reqChunks: Buffer[] = []
  clientReq.on('error', () => { /* client aborted; ignore */ })
  clientRes.on('error', () => { /* response socket closed; ignore */ })
  clientReq.on('data', (c) => reqChunks.push(c as Buffer))
  clientReq.on('end', async () => {
    const reqBody = Buffer.concat(reqChunks)
    let rawReq = buildRawReq(clientReq.method || 'GET', u, clientReq.headers, reqBody)

    // In-scope traffic is the operation itself: it must also fit the RoE (window
    // may close mid-session). Out-of-scope traffic is never captured or logged.
    if (inScope) {
      const check = authorize('proxy', `${clientReq.method} ${u.href}`)
      if (!check.ok) {
        try { clientRes.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }); clientRes.end('Blocked by Interu RoE: ' + check.reason) } catch { /* gone */ }
        return
      }
    }

    if (intercepting && inScope) {
      emit('ruy:proxy:intercept', { id, raw: rawReq.slice(0, CAP), host: u.host, method: clientReq.method, path: u.pathname + u.search })
      const decision = await new Promise<{ action: 'forward' | 'drop'; raw?: string }>((res) => pending.set(id, res))
      if (decision.action === 'drop') {
        emit('ruy:proxy:log', { id, time: now(), method: clientReq.method, host: u.host, path: u.pathname + u.search, url: u.href, status: 0, length: 0, ms: Date.now() - started, kind: scheme, dropped: true })
        try { clientRes.writeHead(502); clientRes.end('Dropped by Interu') } catch { /* gone */ }
        return
      }
      if (decision.raw) rawReq = decision.raw
    }

    const parsed = parseRaw(rawReq)
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(parsed.headers)) {
      const lk = k.toLowerCase()
      if (lk === 'content-length' || lk === 'proxy-connection') continue
      headers[k] = v
    }
    const lib = u.protocol === 'https:' ? https : http
    const options: https.RequestOptions = {
      method: parsed.method,
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: parsed.path,
      headers,
      timeout: 20000,
      rejectUnauthorized: false,
      servername: u.hostname
    }
    const pReq = lib.request(options, (pRes) => {
      const resChunks: Buffer[] = []
      pRes.on('data', (c) => resChunks.push(c as Buffer))
      pRes.on('end', () => {
        const resBuf = Buffer.concat(resChunks)
        try { clientRes.writeHead(pRes.statusCode || 200, pRes.headers as http.OutgoingHttpHeaders); clientRes.end(resBuf) } catch { /* client gone */ }
        if (!inScope) return
        const statusLine = `HTTP/${pRes.httpVersion} ${pRes.statusCode} ${pRes.statusMessage || ''}`.trim()
        // One line per Set-Cookie so cookie rules can check each cookie's flags.
        const resHeaders = Object.entries(pRes.headers)
          .map(([k, v]) => (Array.isArray(v) ? v.map((x) => `${k}: ${x}`).join('\r\n') : `${k}: ${v}`))
          .join('\r\n')
        const ctype = String(pRes.headers['content-type'] || '')
        const printable = /text|json|xml|javascript|html|form|urlencoded/i.test(ctype) || !ctype
        const bodyText = printable ? resBuf.toString('utf8') : `[${resBuf.length} bytes of ${ctype || 'binary'} omitted]`
        emit('ruy:proxy:log', {
          id, time: now(), method: parsed.method, host: u.host, path: parsed.path, url: u.href,
          status: pRes.statusCode, length: resBuf.length, ms: Date.now() - started, kind: scheme,
          request: rawReq.slice(0, CAP),
          response: `${statusLine}\r\n${resHeaders}\r\n\r\n${bodyText}`.slice(0, CAP)
        })
      })
    })
    pReq.on('error', (e) => { try { clientRes.writeHead(502); clientRes.end('Upstream error: ' + e.message) } catch { /* noop */ } })
    pReq.on('timeout', () => pReq.destroy())
    if (parsed.body && parsed.method !== 'GET' && parsed.method !== 'HEAD') pReq.write(parsed.body)
    pReq.end()
  })
}

export function startProxy(port: number, emitFn: Emit): Promise<{ ok: boolean; port?: number; error?: string }> {
  return new Promise((resolve) => {
    if (server) return resolve({ ok: true, port: listenPort })
    emit = emitFn
    listenPort = port

    // MITM TLS terminator: mints a cert per SNI host from the Interu root CA.
    mitm = https.createServer({
      SNICallback: (servername, cb) => {
        try {
          const { key, cert } = getHostCert(servername)
          cb(null, tls.createSecureContext({ key, cert }))
        } catch (e) {
          cb(e as Error)
        }
      }
    })
    mitm.on('request', (req, res) => handleRequest(req, res, 'https'))
    mitm.on('clientError', (_e, sock) => { try { sock.destroy() } catch { /* noop */ } })
    mitm.on('tlsClientError', (_e, sock) => { try { sock.destroy() } catch { /* noop */ } })
    mitm.on('error', () => { /* keep proxy alive */ })

    const srv = http.createServer()
    srv.on('request', (req, res) => handleRequest(req, res, 'http'))
    srv.on('clientError', (_e, sock) => { try { sock.destroy() } catch { /* noop */ } })
    srv.on('connect', (req, clientSocket, head) => {
      // Hand the raw TLS stream to the MITM terminator instead of blind tunnelling.
      clientSocket.on('error', () => { /* client gone; ignore */ })
      const target = req.url || ''
      if (!hostInScope(`https://${target}/`, scope)) {
        // Out of scope: blind tunnel — never decrypted, logged or intercepted.
        const i = target.lastIndexOf(':')
        const host = (i > 0 ? target.slice(0, i) : target).replace(/^\[|\]$/g, '')
        const port = Number(i > 0 ? target.slice(i + 1) : '') || 443
        const up = net.connect(port, host, () => {
          clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
          if (head && head.length) up.write(head)
          up.pipe(clientSocket)
          clientSocket.pipe(up)
        })
        up.on('error', () => { try { clientSocket.destroy() } catch { /* noop */ } })
        clientSocket.on('close', () => up.destroy())
        return
      }
      try {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head && head.length) clientSocket.unshift(head)
        if (mitm) mitm.emit('connection', clientSocket)
      } catch {
        try { clientSocket.destroy() } catch { /* noop */ }
      }
    })
    srv.on('error', (e: NodeJS.ErrnoException) => resolve({ ok: false, error: e.message }))
    srv.listen(port, '127.0.0.1', () => { server = srv; resolve({ ok: true, port }) })
  })
}
