// Authenticated scanning, main-process side. Credentials live only in memory here: the operator's
// pasted headers and the Interu Browser's cookies. The renderer only ever sees counts and header
// names, never values. Every request still passes the scope gate in `ruy:http` first, so
// credentials are only attached to hosts the operator authorized.
import { ipcMain, session } from 'electron'
import type { HttpReq, HttpRes } from '../shared/http'
import { isUnsafeAuthedPath, lostSession, mergeAuth, parseAuthHeaders, type AuthConfig } from '../shared/auth'

/** The partition of the Interu Browser window (see ruy:proxy:openBrowser). */
export const PROXIED_PARTITION = 'interu-proxied'

let cfg: AuthConfig = { cookies: false, headers: '' }
let manual: Record<string, string> = {}
let lost = false

const jar = () => session.fromPartition(PROXIED_PARTITION).cookies

/** Cookie header for one URL, from the browser session (Electron applies domain/path/secure matching). */
async function cookieHeaderFor(url: string): Promise<string> {
  const cookies = await jar().get({ url })
  return cookies.map((c) => `${c.name}=${c.value}`).join('; ')
}

const fail = (error: string, authLost = false): HttpRes => ({ ok: false, timingMs: 0, size: 0, error, authLost })

/** Send through `send` with the stored credentials attached. Call only after the scope check. */
export async function sendAuthed(req: HttpReq, send: (r: HttpReq) => Promise<HttpRes>): Promise<HttpRes> {
  const cookie = cfg.cookies ? await cookieHeaderFor(req.url).catch(() => '') : ''
  const { headers, applied } = mergeAuth(req.headers || {}, manual, cookie)
  const { manual: byHand, ...rest } = req
  const auto = applied && !byHand

  if (auto && isUnsafeAuthedPath(req.url)) return fail('Skipped: logout/delete-style path while authenticated')
  if (auto && lost) return fail('Login session expired. Log in again in the Interu Browser, then press Refresh.', true)

  const res = await send({ ...rest, headers })
  if (auto && res.ok && lostSession(res.status, res.rawHeaders)) {
    lost = true
    res.authLost = true
  }
  return res
}

const parse = (c: unknown): AuthConfig | null => {
  const o = c as Partial<AuthConfig> | null
  return o && typeof o === 'object' ? { cookies: !!o.cookies, headers: typeof o.headers === 'string' ? o.headers : '' } : null
}

// Cookie domain "example.com" / ".example.com" matches the host itself and its subdomains (and the reverse for a scoped parent).
const domainMatches = (cookieDomain: string, host: string): boolean => {
  const d = cookieDomain.replace(/^\./, '').toLowerCase()
  const h = host.toLowerCase()
  return h === d || h.endsWith('.' + d) || d.endsWith('.' + h)
}

export function registerAuthIpc(): void {
  ipcMain.handle('ruy:auth:set', (_e, c: unknown) => {
    const next = parse(c)
    if (!next) return { ok: false, errors: ['Invalid auth config'] }
    const parsed = parseAuthHeaders(next.headers)
    cfg = next
    manual = parsed.headers
    lost = false
    return { ok: parsed.errors.length === 0, errors: parsed.errors }
  })
  ipcMain.handle('ruy:auth:get', () => cfg)
  // Re-arm after the operator logged in again.
  ipcMain.handle('ruy:auth:refresh', () => { lost = false; return { ok: true } })
  ipcMain.handle('ruy:auth:status', async (_e, scopeHosts: string[]) => {
    const all = await jar().get({}).catch(() => [])
    const hosts = (Array.isArray(scopeHosts) ? scopeHosts : []).filter((h) => typeof h === 'string' && !h.includes('/'))
    const cookieCounts: Record<string, number> = {}
    for (const h of hosts) cookieCounts[h] = all.filter((c) => c.domain && domainMatches(c.domain, h)).length
    return { lost, cookies: cfg.cookies, headerNames: Object.keys(manual), cookieCounts }
  })
}
