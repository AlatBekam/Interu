import { ipcMain } from 'electron'
import type { HttpReq, HttpRes } from '../shared/http'
import { credentialOrigin, isUnsafeAuthedPath, lostSession, mergeAuth, parseAuthHeaders, type AuthConfig } from '../shared/auth'
import { hostInScope } from '../shared/http'

let cfg: AuthConfig = { headers: '', origin: '' }
let manual: Record<string, string> = {}
let lost = false
export function clearAuth(): void { cfg = { headers: '', origin: '' }; manual = {}; lost = false }
const fail = (error: string, authLost = false): HttpRes => ({ ok: false, timingMs: 0, size: 0, error, authLost })

/** Import only cookies selected by Chromium for this target. Return metadata, never values. */
export function adoptBrowserCookies(target: string, cookies: Array<{ name: string; value: string }>, scope: string[]): { ok: boolean; count?: number } {
  const origin = credentialOrigin(target)
  if (!origin || !hostInScope(target, scope)) return { ok: false }
  const selected = cookies.filter(c => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(c.name) && c.value && !/[;\r\n]/.test(c.value))
  const header = selected.map(c => `${c.name}=${c.value}`).join('; ')
  if (!header || header.length > 8192) return { ok: false }
  cfg = { headers: '', origin }; manual = { Cookie: header }; lost = false
  return { ok: true, count: selected.length }
}

export async function sendAuthed(req: HttpReq, send: (r: HttpReq) => Promise<HttpRes>): Promise<HttpRes> {
  const bound = credentialOrigin(req.url) === cfg.origin ? manual : {}
  const { headers, applied } = mergeAuth(req.headers || {}, bound)
  const { manual: byHand, ...rest } = req
  const hasCredentials = applied || Object.keys(headers).some(k => /authorization|cookie|api[-_]?key|auth[-_]?token/i.test(k))
  const auto = hasCredentials && !byHand
  if (auto && isUnsafeAuthedPath(req.url)) return fail('Skipped: logout/delete-style path while authenticated')
  if (auto && lost && Object.keys(bound).length) return fail('Login session expired. Paste a fresh token, then press Refresh.', true)
  const res = await send({ ...rest, headers })
  if (auto && res.ok && lostSession(res.status, res.rawHeaders)) {
    if (Object.keys(bound).length) lost = true
    res.authLost = true
  }
  return res
}

export function registerAuthIpc(handle: typeof ipcMain.handle = ipcMain.handle.bind(ipcMain)): void {
  handle('ruy:auth:set', (_e, c: unknown) => {
    const input = c as Partial<AuthConfig> | null
    const text = typeof input?.headers === 'string' ? input.headers : ''
    const parsed = parseAuthHeaders(text)
    const origin = credentialOrigin(input?.origin)
    if (text.trim() && !origin) parsed.errors.push('Set the exact credential origin, for example https://app.example.com:8443')
    if (parsed.errors.length) return { ok: false, errors: parsed.errors }
    clearAuth()
    cfg = { headers: '', origin: origin || '' }
    manual = parsed.headers
    return { ok: true, errors: [] }
  })
  // Never return the credential values to another renderer mount.
  handle('ruy:auth:get', () => ({ headers: '', origin: cfg.origin }))
  handle('ruy:auth:refresh', () => { lost = false; return { ok: true } })
  handle('ruy:auth:status', () => ({ lost, origin: cfg.origin, headerNames: Object.keys(manual) }))
}
