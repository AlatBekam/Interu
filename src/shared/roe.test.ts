import { describe, expect, it } from 'vitest'
import { roeAllows, sanitizeRoe, Roe } from './roe'

const roe: Roe = {
  operation: 'OP-TEST',
  operator: 'alice',
  windowStart: '2026-10-22T08:00:00',
  windowEnd: '2026-10-22T17:00:00',
  allow: { scan: true, intruder: false }
}

describe('roeAllows', () => {
  it('denies everything without an RoE', () => {
    expect(roeAllows(null, 'scan').ok).toBe(false)
  })
  it('allows a permitted technique inside the window', () => {
    expect(roeAllows(roe, 'scan', new Date('2026-10-22T09:00:00')).ok).toBe(true)
  })
  it('denies outside the time window', () => {
    expect(roeAllows(roe, 'scan', new Date('2026-10-22T07:59:00')).ok).toBe(false)
    expect(roeAllows(roe, 'scan', new Date('2026-10-22T17:01:00')).ok).toBe(false)
  })
  it('denies a technique that is not permitted', () => {
    expect(roeAllows(roe, 'intruder', new Date('2026-10-22T09:00:00')).ok).toBe(false)
    expect(roeAllows(roe, 'active', new Date('2026-10-22T09:00:00')).ok).toBe(false)
  })
})

describe('sanitizeRoe', () => {
  it('rejects an RoE without operation or operator', () => {
    expect(sanitizeRoe({ operation: '', operator: 'x', allow: {} })).toBeNull()
    expect(sanitizeRoe(null)).toBeNull()
  })
  it('keeps only known techniques set to true and drops bad times', () => {
    const r = sanitizeRoe({ operation: 'A', operator: 'B', windowStart: 'nope', allow: { scan: true, proxy: 'yes', evil: true } })
    expect(r?.allow.scan).toBe(true)
    expect(r?.allow.proxy).toBe(false)
    expect((r?.allow as Record<string, unknown>).evil).toBeUndefined()
    expect(r?.windowStart).toBeUndefined()
  })
})
