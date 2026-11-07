import { describe, expect, it } from 'vitest'
import { isNavigableUrl, normalizeAddress } from './browser'

describe('normalizeAddress', () => {
  it('uses https for a bare domain', () => {
    expect(normalizeAddress('example.com')).toEqual({ ok: true, url: 'https://example.com/' })
    expect(normalizeAddress('  example.com/path?q=1 ')).toEqual({ ok: true, url: 'https://example.com/path?q=1' })
  })

  it('uses http for localhost, IP literals and explicit ports', () => {
    for (const [input, url] of [
      ['localhost', 'http://localhost/'],
      ['localhost:3000', 'http://localhost:3000/'],
      ['127.0.0.1', 'http://127.0.0.1/'],
      ['10.0.0.5:8080/x', 'http://10.0.0.5:8080/x'],
      ['[::1]:8080', 'http://[::1]:8080/'],
      ['shop.test:8443', 'http://shop.test:8443/']
    ]) expect(normalizeAddress(input), input).toEqual({ ok: true, url })
  })

  it('keeps an explicit http or https scheme', () => {
    expect(normalizeAddress('HTTP://A.b')).toEqual({ ok: true, url: 'http://a.b/' })
    expect(normalizeAddress('https://a.b/x')).toEqual({ ok: true, url: 'https://a.b/x' })
  })

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'file:///c:/windows/win.ini',
    'data:text/html,<b>x</b>',
    'chrome://settings',
    'view-source:http://a.b',
    'ftp://a.b/file',
    'about:blank'
  ])('rejects a non-http(s) address: %s', (input) => {
    const r = normalizeAddress(input)
    expect(r.ok).toBe(false)
  })

  it('rejects empty input and addresses with spaces', () => {
    expect(normalizeAddress('').ok).toBe(false)
    expect(normalizeAddress('   ').ok).toBe(false)
    expect(normalizeAddress('exa mple.com').ok).toBe(false)
  })
})

describe('isNavigableUrl', () => {
  it('allows only http and https', () => {
    expect(isNavigableUrl('http://a.b/')).toBe(true)
    expect(isNavigableUrl('https://a.b/')).toBe(true)
    expect(isNavigableUrl('file:///c:/x')).toBe(false)
    expect(isNavigableUrl('javascript:alert(1)')).toBe(false)
    expect(isNavigableUrl('data:text/html,x')).toBe(false)
    expect(isNavigableUrl('not a url')).toBe(false)
  })
})
