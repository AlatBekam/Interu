import { describe, expect, it } from 'vitest'
import { getAdvice } from './advice'
import type { Finding } from './rules'

const mk = (over: Partial<Finding>): Finding => ({
  key: 'k', templateId: 'x', name: 'n', severity: 'medium', confidence: 'confirmed',
  target: 'http://t.test/path', evidence: '', source: 'active', at: '', ...over
})

describe('advice per vulnerability class', () => {
  it('exposure → verify attack with a read-only curl PoC', () => {
    const a = getAdvice(mk({ templateId: 'expose-dotenv', tags: ['exposure', 'secrets'], target: 'http://t.test/.env' }))
    expect(a.attack.kind).toBe('verify')
    expect(a.attack.safe).toBe(true)
    expect(a.attack.poc).toContain('curl')
    expect(a.defense.steps.length).toBeGreaterThan(0)
  })
  it('CORS → info attack with a local fetch PoC', () => {
    const a = getAdvice(mk({ templateId: 'http-cors-wildcard', source: 'proxy' }))
    expect(a.attack.kind).toBe('info')
    expect(a.attack.poc).toContain('fetch')
  })
  it('SQL error → operator attack carrying safe boolean payloads', () => {
    const a = getAdvice(mk({ templateId: 'http-sql-error', tags: ['http', 'sqli'], source: 'proxy' }))
    expect(a.attack.kind).toBe('operator')
    expect(a.attack.payloads?.some((p) => p.includes("1'='1"))).toBe(true)
  })
  it('banner CVE → operator attack, destructive-capable, defense names the CVE', () => {
    const a = getAdvice(mk({ templateId: 'banner-vsftpd-234', cve: ['CVE-2011-2523'], source: 'scanner' }))
    expect(a.attack.kind).toBe('operator')
    expect(a.attack.safe).toBe(false)
    expect(a.defense.summary).toContain('CVE-2011-2523')
  })
  it('exposed service → operator attack with a port-aware defense config', () => {
    const a = getAdvice(mk({ templateId: 'svc-telnet-exposed', tags: ['network'], target: '10.0.0.5', port: 23, source: 'scanner' }))
    expect(a.attack.kind).toBe('operator')
    expect(a.defense.configs?.[0].code).toContain('23')
  })
  it('admin panel → operator attack with default-credential payloads', () => {
    const a = getAdvice(mk({ templateId: 'pnl-grafana', tags: ['panel'] }))
    expect(a.attack.kind).toBe('operator')
    expect(a.attack.payloads && a.attack.payloads.length).toBeGreaterThan(0)
  })
  it('missing HSTS → info attack mentioning downgrade/MITM', () => {
    const a = getAdvice(mk({ templateId: 'http-missing-hsts', source: 'proxy' }))
    expect(a.attack.kind).toBe('info')
    expect(a.defense.configs?.[0].code).toContain('Strict-Transport-Security')
  })
  it('secret leak → destructive-capable operator attack + rotate guidance', () => {
    const a = getAdvice(mk({ templateId: 'sec-stripe', tags: ['secrets'], source: 'proxy' }))
    expect(a.attack.safe).toBe(false)
    expect(a.defense.summary.toLowerCase()).toContain('rotate')
  })
  it('always returns non-empty defense & attack summaries (fallback holds)', () => {
    for (const tid of ['http-jwt-in-body', 'http-default-page', 'http-private-ip-disclosure', 'totally-unknown-id']) {
      const a = getAdvice(mk({ templateId: tid }))
      expect(a.defense.summary.length).toBeGreaterThan(0)
      expect(a.attack.summary.length).toBeGreaterThan(0)
      expect(a.defense.steps.length).toBeGreaterThan(0)
    }
  })
})
