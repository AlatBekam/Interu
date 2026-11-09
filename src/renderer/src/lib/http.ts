import type { HttpReq, HttpRes } from '../../../shared/http'
import { hostInScope } from '../../../shared/http'
import { noteScopeBlock, pushActivity } from '../store/activity'

export type { HttpReq, HttpRes }

/** Parse a raw Burp-style request (method/path + headers + blank line + body). */
export function parseRawRequest(raw: string, base: string): HttpReq {
  const norm = raw.replace(/\r\n/g, '\n')
  const sep = norm.indexOf('\n\n')
  const head = sep >= 0 ? norm.slice(0, sep) : norm
  const body = sep >= 0 ? norm.slice(sep + 2) : ''
  const lines = head.split('\n')
  const first = (lines.shift() || '').trim()
  const m = first.match(/^(\S+)\s+(\S+)/)
  const method = (m?.[1] || 'GET').toUpperCase()
  const path = m?.[2] || '/'
  const headers: Record<string, string> = {}
  for (const l of lines) {
    const i = l.indexOf(':')
    if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim()
  }
  let url: string
  try {
    url = /^https?:\/\//i.test(path) ? path : new URL(path, base).toString()
  } catch {
    url = base
  }
  return { method, url, headers, body: body.length ? body : undefined }
}

/** scheme://host[:port] for a URL (origin), used as the Repeater/Intruder target. */
export function originOf(url: string): string {
  try {
    return new URL(url).origin
  } catch {
    return url
  }
}

/** Build a `curl` command from a raw request + target (Burp-style "Copy as curl"). */
export function toCurl(raw: string, base: string): string {
  const req = parseRawRequest(raw, base)
  const parts = [`curl -k -X ${req.method} '${req.url}'`]
  for (const [k, v] of Object.entries(req.headers)) {
    if (k.toLowerCase() === 'content-length') continue
    parts.push(`  -H '${k}: ${v}'`)
  }
  if (req.body) parts.push(`  --data '${req.body.replace(/'/g, "'\\''")}'`)
  return parts.join(' \\\n')
}

/** Minimal raw request from parts (for entries without a captured request). */
export function rawFromParts(method: string, host: string, path: string): string {
  return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Interu/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`
}

/** Scope pre-check for a feature; a refusal is also recorded in the activity log. */
export function inScopeOrNote(url: string, scope: string[], via: string): boolean {
  const ok = hostInScope(url, scope)
  if (!ok) noteScopeBlock(url, via)
  return ok
}

let authNoticed = false
/** Called when credentials change or are refreshed, so the next expiry is reported again. */
export function resetAuthNotice(): void { authNoticed = false }

/** Report an expired login session once (until credentials are changed or refreshed). */
export function noteAuthLost(target: string): void {
  if (authNoticed) return
  authNoticed = true
  pushActivity({ ts: new Date().toISOString(), level: 'warn', category: 'scan', message: 'Login session expired: authenticated scan stopped. Paste a fresh token, then press Refresh.', target })
}

/** Send a real request through the main process, gated by scope. */
export async function sendLive(req: HttpReq, scope: string[]): Promise<HttpRes> {
  if (!window.ruy?.http) {
    return { ok: false, timingMs: 0, size: 0, error: 'HTTP bridge unavailable' }
  }
  const res = await window.ruy.http.send(req, scope)
  if (res.blocked) noteScopeBlock(req.url, 'http')
  if (res.authLost) noteAuthLost(req.url)
  return res
}
