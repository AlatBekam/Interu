import http from 'node:http'
import https from 'node:https'
import { URL } from 'node:url'
import type { HttpReq, HttpRes } from '../shared/http'

const MAX_BODY = 5 * 1024 * 1024

// Real HTTP(S) client running in the Electron main process. Gives full control
// over method, path, headers and body (unlike fetch), and returns the raw
// response the way a proxy tool should. Self-signed certs are accepted because
// authorized test targets frequently use them.
export function sendHttp(req: HttpReq): Promise<HttpRes> {
  return new Promise((resolve) => {
    let u: URL
    try {
      u = new URL(req.url)
    } catch {
      return resolve({ ok: false, timingMs: 0, size: 0, error: 'Invalid URL' })
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return resolve({ ok: false, timingMs: 0, size: 0, error: 'Only http/https supported' })
    }

    const lib = u.protocol === 'https:' ? https : http
    const started = Date.now()

    // Let Node compute Content-Length; drop any stale value from the editor.
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (k.toLowerCase() === 'content-length') continue
      headers[k] = v
    }

    const options: https.RequestOptions = {
      method: (req.method || 'GET').toUpperCase(),
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers,
      timeout: req.timeoutMs ?? 15000,
      rejectUnauthorized: false
    }

    const r = lib.request(options, (res) => {
      const chunks: Buffer[] = []
      let size = 0
      let finished = false
      const finish = (): void => {
        if (finished) return
        finished = true
        const buf = Buffer.concat(chunks)
        const bodyStr = buf.toString('utf8')
        const statusLine = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage || ''}`.trim()
        // One line per Set-Cookie so cookie rules can check each cookie's flags.
        const headerLines = Object.entries(res.headers)
          .map(([k, v]) => (Array.isArray(v) ? v.map((x) => `${k}: ${x}`).join('\r\n') : `${k}: ${v}`))
          .join('\r\n')
        resolve({
          ok: true,
          status: res.statusCode,
          statusText: res.statusMessage,
          rawHeaders: headerLines,
          body: bodyStr,
          raw: `${statusLine}\r\n${headerLines}\r\n\r\n${bodyStr}`,
          timingMs: Date.now() - started,
          size: buf.length
        })
      }
      res.on('data', (c: Buffer) => {
        if (finished) return
        chunks.push(c)
        size += c.length
        // Cap the body so a huge or endless response can't exhaust memory.
        if (size >= MAX_BODY) { finish(); r.destroy() }
      })
      res.on('end', finish)
    })

    r.on('error', (e) => resolve({ ok: false, timingMs: Date.now() - started, size: 0, error: e.message }))
    r.on('timeout', () => {
      r.destroy()
      resolve({ ok: false, timingMs: Date.now() - started, size: 0, error: 'Request timed out' })
    })

    if (req.body && options.method !== 'GET' && options.method !== 'HEAD') r.write(req.body)
    r.end()
  })
}
