import { describe, expect, it } from 'vitest'
import {
  analyzeHttpResponse, analyzeScan, interpolate, requestVars, buildActiveRequest,
  matchActive, computeBaseline, correlate, isStatusOnly, TEMPLATES, type Template, type Finding
} from './rules'
import type { ProxyLogEntry } from './proxy'
import type { ScanHost } from './scan'
import type { HttpRes } from './http'

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

describe('finding targets', () => {
  it('reports header-only findings once per origin', () => {
    const csp = analyzeHttpResponse(entry('')).find((f) => f.templateId === 'http-missing-csp')
    expect(csp?.target).toBe('https://shop.test')
  })
})

describe('new passive templates', () => {
  it('flags a wildcard CORS header', () => {
    expect(ids('access-control-allow-origin: *')).toContain('http-cors-wildcard')
  })
  it('flags reflected-origin CORS with credentials as high', () => {
    const found = ids('access-control-allow-origin: https://evil.test\r\naccess-control-allow-credentials: true')
    expect(found).toContain('http-cors-credentials-wildcard')
  })
  it('flags a cookie without SameSite', () => {
    expect(ids('set-cookie: sid=1; HttpOnly; Secure')).toContain('http-cookie-samesite')
  })
  it('detects a leaked AWS key in the body and extracts it', () => {
    const e: ProxyLogEntry = {
      id: 1, time: '', method: 'GET', host: 'shop.test', path: '/', url: 'https://shop.test/',
      status: 200, ms: 1, kind: 'http', response: 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\nkey=AKIAIOSFODNN7EXAMPLE'
    }
    const f = analyzeHttpResponse(e).find((x) => x.templateId === 'http-secret-leak')
    expect(f).toBeTruthy()
    expect(f?.extracted?.secret).toContain('AKIAIOSFODNN7EXAMPLE')
  })
  it('extracts the Server version via kval', () => {
    const f = analyzeHttpResponse(entry('server: nginx/1.18.0')).find((x) => x.templateId === 'http-server-version')
    expect(f?.extracted?.server).toContain('nginx/1.18.0')
  })
})

describe('port / banner analysis', () => {
  const host = (version: string, port = 21): ScanHost => ({
    ip: '10.0.0.5', status: 'up', tookMs: 1,
    openPorts: [{ port, service: port === 21 ? 'ftp' : 'ssh', state: 'open', version }]
  })
  it('matches the vsftpd 2.3.4 backdoor banner', () => {
    const ids = analyzeScan([host('vsftpd 2.3.4')]).map((f) => f.templateId)
    expect(ids).toContain('banner-vsftpd-234')
    expect(ids).toContain('svc-ftp-exposed')
  })
  it('does not match vsftpd 3.0.3', () => {
    expect(analyzeScan([host('vsftpd 3.0.3')]).map((f) => f.templateId)).not.toContain('banner-vsftpd-234')
  })
  it('flags OpenSSH 9.6 as regreSSHion candidate', () => {
    expect(analyzeScan([host('OpenSSH_9.6', 22)]).map((f) => f.templateId)).toContain('banner-openssh-regresshion')
  })
  it('does not flag patched OpenSSH 9.8', () => {
    expect(analyzeScan([host('OpenSSH_9.8', 22)]).map((f) => f.templateId)).not.toContain('banner-openssh-regresshion')
  })
})

describe('variable interpolation & active request building', () => {
  it('fills BaseURL / Hostname / Scheme', () => {
    const v = requestVars('https://host.example.com:8443/app/')
    expect(v.BaseURL).toBe('https://host.example.com:8443/app')
    expect(v.Host).toBe('host.example.com')
    expect(v.Scheme).toBe('https')
    expect(interpolate('{{Scheme}}://{{Host}}/x', v)).toBe('https://host.example.com/x')
  })
  it('builds a root-relative probe URL', () => {
    const t = TEMPLATES.find((x) => x.id === 'expose-git-config')!
    const req = buildActiveRequest(t, 'http://127.0.0.1/')
    expect(req?.url).toBe('http://127.0.0.1/.git/config')
  })
})

describe('active oracle matching', () => {
  const res = (status: number, body: string, headers = ''): HttpRes => ({
    ok: true, status, statusText: 'OK', rawHeaders: headers, body,
    raw: `HTTP/1.1 ${status} OK\r\n${headers}\r\n\r\n${body}`, timingMs: 5, size: body.length
  })
  it('confirms exposed .git/config', () => {
    const t = TEMPLATES.find((x) => x.id === 'expose-git-config')!
    const f = matchActive(t, 'http://t/.git/config', res(200, '[core]\nrepositoryformatversion = 0'))
    expect(f?.confidence).toBe('confirmed')
  })
  it('extracts the PHP version from phpinfo()', () => {
    const t = TEMPLATES.find((x) => x.id === 'expose-phpinfo')!
    const f = matchActive(t, 'http://t/phpinfo.php', res(200, '<title>phpinfo()</title> PHP Version 8.1.2'))
    expect(f?.extracted?.php).toContain('8.1.2')
  })
  it('does not fire when the marker is absent', () => {
    const t = TEMPLATES.find((x) => x.id === 'expose-git-config')!
    expect(matchActive(t, 'http://t/.git/config', res(200, '<html>not here</html>'))).toBeNull()
  })
  it('demotes a status-only match on a catch-all server', () => {
    const statusOnly: Template = {
      id: 'tmp-status-only', kind: 'http-active', confidence: 'confirmed',
      request: { method: 'GET', path: '/anything' },
      info: { name: 'status only', severity: 'low' },
      matchers: [{ type: 'status', status: [200] }]
    }
    expect(isStatusOnly(statusOnly)).toBe(true)
    const baseline = computeBaseline(res(200, 'this is the catch-all homepage'))
    expect(baseline.catchAll).toBe(true)
    const f = matchActive(statusOnly, 'http://t/anything', res(200, 'x'), { baseline })
    expect(f?.confidence).toBe('suspected')
    expect(f?.evidence).toContain('catch-all')
  })
})

describe('correlation (suspected → superseded)', () => {
  it('supersedes a suspected finding when a confirmed one shares group + target', () => {
    const mk = (id: string, confidence: 'suspected' | 'confirmed', severity: Finding['severity']): Finding => ({
      key: `${id}|t`, templateId: id, name: id, severity, confidence, target: 't',
      evidence: '', source: 'active', at: ''
    })
    // expose-backup-sql and expose-dump-sql share group 'sql-dump'; both confirmed → one kept.
    const out = correlate([mk('expose-dump-sql', 'confirmed', 'high'), mk('expose-backup-sql', 'confirmed', 'high')])
    expect(out.filter((f) => !f.superseded)).toHaveLength(1)
  })
  it('leaves ungrouped findings untouched', () => {
    const f: Finding = { key: 'a|t', templateId: 'http-missing-csp', name: 'x', severity: 'low', confidence: 'confirmed', target: 't', evidence: '', source: 'proxy', at: '' }
    expect(correlate([f])[0].superseded).toBeFalsy()
  })
})

describe('template catalog integrity', () => {
  it('has unique template ids', () => {
    const ids = TEMPLATES.map((t) => t.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
  it('every active template defines a request', () => {
    for (const t of TEMPLATES.filter((x) => x.kind === 'http-active')) expect(t.request?.path).toBeTruthy()
  })
  it('carries a large catalog', () => {
    expect(TEMPLATES.length).toBeGreaterThanOrEqual(400)
  })
  it('every active template requires a content marker, never status alone (no false positives)', () => {
    for (const t of TEMPLATES.filter((x) => x.kind === 'http-active')) {
      expect(isStatusOnly(t), `${t.id} is status-only`).toBe(false)
    }
  })
  it('every template has at least one matcher', () => {
    for (const t of TEMPLATES) expect(t.matchers.length, t.id).toBeGreaterThan(0)
  })
})
