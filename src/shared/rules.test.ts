import { describe, expect, it } from 'vitest'
import { analyzeHttpResponse, matchActive, TEMPLATES } from './rules'
import type { ProxyLogEntry } from './proxy'

const entry = (headers: string, url = 'https://shop.test/a?x=1'): ProxyLogEntry => ({
  id: 1, time: '', method: 'GET', host: 'shop.test', path: '/a', url, status: 200, ms: 1, kind: 'http',
  response: `HTTP/1.1 200 OK\r\n${headers}\r\n\r\nok`
})
const ids = (headers: string): string[] => analyzeHttpResponse(entry(headers)).map((f) => f.templateId)

describe('cookie rules', () => {
  it('flags a cookie missing HttpOnly even when another cookie has it', () => {
    const found = ids('set-cookie: a=1; HttpOnly; Secure\r\nset-cookie: b=2; Secure')
    expect(found).toContain('http-cookie-httponly')
    expect(found).not.toContain('http-cookie-secure')
  })
  it('is not fooled by a cookie named secure_x', () => {
    expect(ids('set-cookie: secure_x=1; HttpOnly')).toContain('http-cookie-secure')
  })
  it('stays quiet when every cookie has both flags', () => {
    const found = ids('set-cookie: a=1; HttpOnly; Secure')
    expect(found).not.toContain('http-cookie-httponly')
    expect(found).not.toContain('http-cookie-secure')
  })
})

describe('raw evidence', () => {
  it('keeps the replayable request and raw exchange on active findings', () => {
    const t = TEMPLATES.find((x) => x.id === 'expose-git-config')!
    const req = { method: 'GET', url: 'http://10.0.0.5/.git/config', headers: { 'User-Agent': 'Interu/1.0' } }
    const f = matchActive(t, req, { ok: true, status: 200, rawHeaders: 'content-type: text/plain', body: '[core]\nrepositoryformatversion = 0', timingMs: 5, size: 40 })
    expect(f?.req).toEqual(req)
    expect(f?.raw?.request).toContain('GET http://10.0.0.5/.git/config')
    expect(f?.raw?.response).toContain('repositoryformatversion')
  })
  it('keeps the captured exchange on proxy findings', () => {
    const csp = analyzeHttpResponse(entry('')).find((f) => f.templateId === 'http-missing-csp')
    expect(csp?.raw?.response).toContain('HTTP/1.1 200 OK')
  })
})

describe('finding targets', () => {
  it('reports header-only findings once per origin', () => {
    const csp = analyzeHttpResponse(entry('')).find((f) => f.templateId === 'http-missing-csp')
    expect(csp?.target).toBe('https://shop.test')
  })
})
