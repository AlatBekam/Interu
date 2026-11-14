import { describe, expect, it } from 'vitest'
import { registerAuthIpc, sendAuthed } from './auth'
import type { HttpReq, HttpRes } from '../shared/http'

type Handler = (_event: unknown, value?: unknown) => unknown
const base: HttpReq = { method: 'GET', url: 'https://app.example.test/private', headers: {} }
const ok: HttpRes = { ok: true, status: 200, rawHeaders: '', body: '', timingMs: 1, size: 0 }

describe('main-process credential boundary', () => {
  it('requires an exact origin, attaches only there, and never returns values to the UI', async () => {
    const handlers = new Map<string, Handler>()
    registerAuthIpc(((channel: string, handler: Handler) => { handlers.set(channel, handler) }) as never)
    const set = handlers.get('ruy:auth:set')!
    expect(set(null, { headers: 'Authorization: Bearer secret' })).toMatchObject({ ok: false })
    expect(set(null, { headers: 'Authorization: Bearer secret', origin: 'https://app.example.test' })).toMatchObject({ ok: true })
    expect(JSON.stringify(handlers.get('ruy:auth:get')!(null))).not.toContain('secret')
    const seen: HttpReq[] = []
    const send = async (req: HttpReq): Promise<HttpRes> => { seen.push(req); return { ...ok } }
    await sendAuthed(base, send)
    await sendAuthed({ ...base, url: 'https://other.example.test/private' }, send)
    await sendAuthed({ ...base, url: 'http://app.example.test/private' }, send)
    expect(seen[0].headers.Authorization).toBe('Bearer secret')
    expect(seen[1].headers.Authorization).toBeUndefined()
    expect(seen[2].headers.Authorization).toBeUndefined()
    expect(set(null, { headers: '' })).toMatchObject({ ok: true })
  })
  it('blocks automated logout requests with credentials', async () => {
    const handlers = new Map<string, Handler>()
    registerAuthIpc(((channel: string, handler: Handler) => { handlers.set(channel, handler) }) as never)
    handlers.get('ruy:auth:set')!(null, { headers: 'Cookie: sid=secret', origin: 'https://app.example.test' })
    let sent = false
    const response = await sendAuthed({ ...base, url: 'https://app.example.test/logout' }, async () => { sent = true; return ok })
    expect(response.ok).toBe(false)
    expect(sent).toBe(false)
    handlers.get('ruy:auth:set')!(null, { headers: '' })
  })
})
