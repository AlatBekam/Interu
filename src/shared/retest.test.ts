import { describe, expect, it } from 'vitest'
import type { Finding } from './rules'
import { appendRetest, retestPlan, retestStatus } from './retest'
import { explicitPorts } from './scan'

const base: Finding = {
  key: 'expose-dotenv|http://10.0.0.5/.env', templateId: 'expose-dotenv', name: 'Exposed .env', severity: 'critical',
  confidence: 'confirmed', target: 'http://10.0.0.5/.env', evidence: 'matched: DB_PASSWORD', source: 'active', at: '2026-10-22T09:00:00.000Z',
  req: { method: 'GET', url: 'http://10.0.0.5/.env', headers: {} },
  raw: { request: 'GET /.env', response: 'HTTP/1.1 200 OK' }
}

describe('retestPlan', () => {
  it('replays active findings, rescans port findings, skips passive proxy findings', () => {
    expect(retestPlan(base).kind).toBe('http')
    expect(retestPlan({ ...base, source: 'scanner', target: '10.0.0.5', port: 23, req: undefined })).toEqual({ kind: 'port', ip: '10.0.0.5', port: 23 })
    expect(retestPlan({ ...base, source: 'proxy', req: undefined }).kind).toBe('none')
  })
})

describe('retestStatus', () => {
  it('is closed when the check no longer matches, open when identical, changed otherwise', () => {
    expect(retestStatus(base, null)).toBe('closed')
    expect(retestStatus(base, { ...base })).toBe('open')
    expect(retestStatus(base, { ...base, evidence: 'matched: API_KEY' })).toBe('changed')
  })
})

describe('appendRetest', () => {
  it('appends history and keeps the original evidence', () => {
    const once = appendRetest([base], base.key, { at: '2026-10-22T10:00:00.000Z', status: 'open' })
    const twice = appendRetest(once, base.key, { at: '2026-10-22T11:00:00.000Z', status: 'closed' })
    expect(twice[0].retests?.map((r) => r.status)).toEqual(['open', 'closed'])
    expect(twice[0].raw).toEqual(base.raw)
    expect(twice[0].evidence).toBe(base.evidence)
  })
})

describe('explicitPorts', () => {
  it('accepts a small valid list and rejects anything else', () => {
    expect(explicitPorts([443, 23, 23])).toEqual([23, 443])
    expect(explicitPorts([0])).toBeNull()
    expect(explicitPorts(['80'])).toBeNull()
    expect(explicitPorts(Array.from({ length: 65 }, (_, i) => i + 1))).toBeNull()
  })
})
