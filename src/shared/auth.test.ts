import { describe, expect, it } from 'vitest'
import { isUnsafeAuthedPath, lostSession, mergeAuth, parseAuthHeaders, redactSecrets } from './auth'

describe('parseAuthHeaders', () => {
  it('parses one Name: value per line, trimming and ignoring blanks', () => {
    const r = parseAuthHeaders('Authorization: Bearer abc.def\r\n\n  X-Api-Key :  k1  \n')
    expect(r.errors).toEqual([])
    expect(r.headers).toEqual({ Authorization: 'Bearer abc.def', 'X-Api-Key': 'k1' })
  })

  it('keeps colons inside the value', () => {
    expect(parseAuthHeaders('Cookie: a=b; c=d:e').headers).toEqual({ Cookie: 'a=b; c=d:e' })
  })

  it('reports bad lines and headers that must not be set, and keeps the good ones', () => {
    const r = parseAuthHeaders('no colon here\nHost: evil.test\nContent-Length: 5\nBad Name: x\nX-Empty:\nAuthorization: ok')
    expect(r.headers).toEqual({ Authorization: 'ok' })
    expect(r.errors).toHaveLength(5)
    expect(r.errors.join(' ')).toMatch(/Host/)
  })

  it('later duplicates win', () => {
    expect(parseAuthHeaders('X-A: 1\nx-a: 2').headers).toEqual({ 'x-a': '2' })
  })
})

describe('mergeAuth', () => {
  it('adds manual headers and browser cookies when the request has none', () => {
    const m = mergeAuth({ 'User-Agent': 'u' }, { Authorization: 'Bearer t' }, 'sid=1')
    expect(m.applied).toBe(true)
    expect(m.headers).toEqual({ 'User-Agent': 'u', Authorization: 'Bearer t', Cookie: 'sid=1' })
  })

  it("never overrides what the request already sets (case-insensitive)", () => {
    const m = mergeAuth({ cookie: 'mine=1', authorization: 'Basic x' }, { Authorization: 'Bearer t', Cookie: 'manual=1' }, 'sid=1')
    expect(m.applied).toBe(false)
    expect(m.headers).toEqual({ cookie: 'mine=1', authorization: 'Basic x' })
  })

  it('a manual Cookie header wins over browser cookies (no double Cookie)', () => {
    const m = mergeAuth({}, { Cookie: 'manual=1' }, 'sid=1')
    expect(m.headers).toEqual({ Cookie: 'manual=1' })
    expect(m.applied).toBe(true)
  })

  it('is a no-op without credentials', () => {
    const m = mergeAuth({ A: '1' }, {}, '')
    expect(m).toEqual({ headers: { A: '1' }, applied: false })
  })
})

describe('isUnsafeAuthedPath', () => {
  it.each([
    'http://a.test/logout', 'http://a.test/Sign-Out', 'http://a.test/account/signout',
    'http://a.test/api/users/delete/5', 'http://a.test/users/remove?id=1', 'http://a.test/x?action=delete',
    'http://a.test/unsubscribe', 'http://a.test/close-account', 'http://a.test/auth/revoke', 'http://a.test/user/reset_password'
  ])('flags %s', (u) => expect(isUnsafeAuthedPath(u)).toBe(true))

  it.each([
    'http://a.test/', 'http://a.test/catalog', 'http://a.test/deleted-items', 'http://a.test/profile?tab=settings',
    'http://a.test/api/orders?id=1001', 'http://a.test/blog/logs'
  ])('allows %s', (u) => expect(isUnsafeAuthedPath(u)).toBe(false))
})

describe('lostSession', () => {
  it('treats 401 as a lost session', () => {
    expect(lostSession(401, '')).toBe(true)
  })

  it('treats a redirect to a login page as a lost session', () => {
    expect(lostSession(302, 'Location: /login?next=/home')).toBe(true)
    expect(lostSession(303, 'content-type: text/html\r\nlocation: https://a.test/users/sign_in')).toBe(true)
    expect(lostSession(302, 'Location: https://sso.corp.test/oauth/authorize?x=1')).toBe(true)
  })

  it('does not trip on normal answers', () => {
    expect(lostSession(200, '')).toBe(false)
    expect(lostSession(403, '')).toBe(false) // a 403 is a legitimate access-control result
    expect(lostSession(404, '')).toBe(false)
    expect(lostSession(302, 'Location: /dashboard')).toBe(false)
    expect(lostSession(301, 'Location: /author/jane')).toBe(false)
    expect(lostSession(undefined, '')).toBe(false)
  })
})

describe('redactSecrets', () => {
  it('keeps cookie names and flags but drops the value', () => {
    expect(redactSecrets('matched: set-cookie: sid=abc123; Path=/; HttpOnly')).toBe('matched: set-cookie: sid=<redacted>; Path=/; HttpOnly')
    expect(redactSecrets('Cookie: JSESSIONID=XYZ')).toBe('Cookie: JSESSIONID=<redacted>')
  })
  it('drops bearer and basic credentials', () => {
    expect(redactSecrets('authorization: Bearer eyJ.abc.def · status 200')).toBe('authorization: Bearer <redacted> · status 200')
    expect(redactSecrets('Authorization: Basic dXNlcjpwdw==')).toBe('Authorization: Basic <redacted>')
  })
  it('leaves ordinary evidence alone', () => {
    for (const t of ['status 200', 'port 22/ssh', 'matched: stages:, script:', 'missing: x-frame-options']) expect(redactSecrets(t)).toBe(t)
  })
})
