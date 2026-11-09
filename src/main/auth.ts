// Authenticated scanning, main-process side. The operator pastes headers (an Authorization token, an
// API key, a Cookie line); they live only in memory here and are attached in the single HTTP choke
// point after the scope gate, so they are only ever sent to hosts the operator authorized. The renderer
// gets back header names, never values.
import { ipcMain } from 'electron'
import type { HttpReq, HttpRes } from '../shared/http'
import { isUnsafeAuthedPath, lostSession, mergeAuth, parseAuthHeaders, type AuthConfig } from '../shared/auth'

let cfg: AuthConfig = { headers: '' }
let manual: Record<string, string> = {}
let lost = false

const fail = (error: string, authLost = false): HttpRes => ({ ok: false, timingMs: 0, size: 0, error, authLost })

/** Send through `send` with the pasted headers attached. Call only after the scope check. */
export async function sendAuthed(req: HttpReq, send: (r: HttpReq) => Promise<HttpRes>): Promise<HttpRes> {
  const { headers, applied } = mergeAuth(req.headers || {}, manual)
  const { manual: byHand, ...rest } = req
  const auto = applied && !byHand

  if (auto && isUnsafeAuthedPath(req.url)) return fail('Skipped: logout/delete-style path while authenticated')
  if (auto && lost) return fail('Login session expired. Paste a fresh token, then press Refresh.', true)

  const res = await send({ ...rest, headers })
  if (auto && res.ok && lostSession(res.status, res.rawHeaders)) {
    lost = true
    res.authLost = true
  }
  return res
}

export function registerAuthIpc(): void {
  ipcMain.handle('ruy:auth:set', (_e, c: unknown) => {
    const text = (c as Partial<AuthConfig> | null)?.headers
    const parsed = parseAuthHeaders(typeof text === 'string' ? text : '')
    cfg = { headers: typeof text === 'string' ? text : '' }
    manual = parsed.headers
    lost = false
    return { ok: parsed.errors.length === 0, errors: parsed.errors }
  })
  ipcMain.handle('ruy:auth:get', () => cfg)
  // Re-arm after the operator pasted a fresh token.
  ipcMain.handle('ruy:auth:refresh', () => { lost = false; return { ok: true } })
  ipcMain.handle('ruy:auth:status', () => ({ lost, headerNames: Object.keys(manual) }))
}
