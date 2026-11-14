import http from 'node:http'
import https from 'node:https'
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib'
import type { HttpReq, HttpRes } from '../shared/http'

const MAX_BODY = 5 * 1024 * 1024
let allowInvalidTls = false
export function setHttpTlsPolicy(allow: boolean): void { allowInvalidTls = allow }

// Bounded HTTP transport. Redirect policy belongs to the caller so every hop
// can be checked against scope before any credentials or network traffic leave.
export function sendHttp(req: HttpReq, signal?: AbortSignal): Promise<HttpRes> {
  return new Promise((resolve) => {
    const started = Date.now()
    let u: URL
    try { u = new URL(req.url) } catch { resolve({ ok: false, timingMs: 0, size: 0, error: 'Invalid URL' }); return }
    if (!/^https?:$/.test(u.protocol) || u.username || u.password) { resolve({ ok: false, timingMs: 0, size: 0, error: 'Only HTTP(S) URLs without embedded credentials are supported' }); return }
    if (signal?.aborted) { resolve({ ok: false, timingMs: 0, size: 0, error: 'Cancelled' }); return }
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers || {})) if (!/^(content-length|transfer-encoding)$/i.test(k)) headers[k] = v
    const timeout = Math.min(120000, Math.max(100, req.timeoutMs || 15000))
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let request: http.ClientRequest | undefined
    const finish = (res: HttpRes): void => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      resolve(res)
    }
    const fail = (error: string): void => finish({ ok: false, timingMs: Date.now() - started, size: 0, error })
    const abort = (): void => { fail('Cancelled'); request?.destroy() }
    try {
      request = (u.protocol === 'https:' ? https : http).request({
        method: (req.method || 'GET').toUpperCase(), hostname: u.hostname, port: u.port || undefined,
        path: u.pathname + u.search, headers, rejectUnauthorized: !allowInvalidTls
      }, (res) => {
        const chunks: Buffer[] = []
        let size = 0
        const encoding = String(res.headers['content-encoding'] || '').toLowerCase()
        const decoder = encoding === 'gzip' ? createGunzip() : encoding === 'deflate' ? createInflate() : encoding === 'br' ? createBrotliDecompress() : null
        const stream = decoder ? res.pipe(decoder) : res
        const complete = (truncated = false): void => {
          const body = Buffer.concat(chunks).toString('utf8')
          const rawHeaders = Object.entries(res.headers).map(([k, v]) => Array.isArray(v) ? v.map(x => `${k}: ${x}`).join('\r\n') : `${k}: ${v}`).join('\r\n')
          finish({ ok: true, status: res.statusCode, statusText: res.statusMessage, rawHeaders, body,
            raw: `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage || ''}\r\n${rawHeaders}\r\n\r\n${body}`,
            timingMs: Date.now() - started, size, truncated })
        }
        stream.on('data', (chunk: Buffer) => {
          if (settled) return
          const available = MAX_BODY - size
          chunks.push(chunk.subarray(0, available)); size += Math.min(chunk.length, available)
          if (chunk.length >= available) { complete(true); stream.destroy(); res.destroy(); request?.destroy() }
        })
        stream.once('end', () => complete())
        stream.once('error', (err: Error) => { fail(err.message); res.destroy(); request?.destroy() })
        res.once('aborted', () => { fail('Response interrupted'); decoder?.destroy() })
        res.once('error', (err) => { fail(err.message); decoder?.destroy() })
      })
      request.once('error', (err) => fail(err.message))
      timer = setTimeout(() => { fail('Request deadline exceeded'); request?.destroy() }, timeout)
      signal?.addEventListener('abort', abort, { once: true })
      if (signal?.aborted) { abort(); return }
      if (req.body && !/^(GET|HEAD)$/i.test(req.method)) request.write(req.body)
      request.end()
    } catch (err) { fail((err as Error).message); request?.destroy() }
  })
}
