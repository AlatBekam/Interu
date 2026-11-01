import { describe, expect, it } from 'vitest'
import type { Finding } from './rules'
import type { KevInfo } from './kev'
import { hostOf, severityLevel, eventFromFinding, priorityQueue, exposureByTarget, summarize, timeLabel } from './activity'

let n = 0
const f = (o: Partial<Finding> = {}): Finding => ({
  key: `k${n++}`, templateId: 't', name: 'N', severity: 'low', confidence: 'confirmed',
  target: 'http://127.0.0.1:8090/x', evidence: 'e', source: 'active', at: '2026-11-01T14:00:00Z', ...o
})
const kev: KevInfo = { cve: 'CVE-2021-3129', name: 'x', dateAdded: '2021-11-01', ransomware: false }

describe('hostOf', () => {
  it('collapses URLs, ports and bare hosts to one host name', () => {
    expect(hostOf('http://127.0.0.1:8090/.gitlab-ci.yml')).toBe('127.0.0.1')
    expect(hostOf('127.0.0.1')).toBe('127.0.0.1')
    expect(hostOf('127.0.0.1:80')).toBe('127.0.0.1')
    expect(hostOf('https://shop.test/a?x=1')).toBe('shop.test')
    expect(hostOf('localhost:8080')).toBe('localhost')
  })
})

describe('severityLevel', () => {
  it('maps critical and high to crit, medium to warn, low and info to info', () => {
    expect(severityLevel('critical')).toBe('crit')
    expect(severityLevel('high')).toBe('crit')
    expect(severityLevel('medium')).toBe('warn')
    expect(severityLevel('low')).toBe('info')
    expect(severityLevel('info')).toBe('info')
  })
})

describe('eventFromFinding', () => {
  it('names the finding and its target, and escalates a KEV-listed finding to crit', () => {
    const e = eventFromFinding(f({ name: 'Exposed X', severity: 'low', kev: [kev] }))
    expect(e.level).toBe('crit')
    expect(e.category).toBe('finding')
    expect(e.message).toBe('New finding: Exposed X')
    expect(e.target).toBe('http://127.0.0.1:8090/x')
  })
  it('uses the severity level when there is no KEV entry', () => {
    expect(eventFromFinding(f({ severity: 'medium' })).level).toBe('warn')
  })
})

describe('priorityQueue', () => {
  it('puts a KEV-listed low finding ahead of a critical one without KEV', () => {
    const q = priorityQueue([f({ name: 'crit', severity: 'critical' }), f({ name: 'kev', severity: 'low', kev: [kev] })])
    expect(q.map((x) => x.name)).toEqual(['kev', 'crit'])
  })
  it('orders by severity, then confirmed before suspected, and honours the limit', () => {
    const q = priorityQueue([
      f({ name: 'low', severity: 'low' }),
      f({ name: 'high-suspected', severity: 'high', confidence: 'suspected' }),
      f({ name: 'high-confirmed', severity: 'high', confidence: 'confirmed' })
    ])
    expect(q.map((x) => x.name)).toEqual(['high-confirmed', 'high-suspected', 'low'])
    expect(priorityQueue(q, 2)).toHaveLength(2)
  })
  it('does not mutate its input', () => {
    const list = [f({ severity: 'low' }), f({ severity: 'critical' })]
    priorityQueue(list)
    expect(list[0].severity).toBe('low')
  })
})

describe('exposureByTarget', () => {
  it('merges a scanner finding and an active finding on the same host into one row', () => {
    const rows = exposureByTarget([
      f({ target: '127.0.0.1', severity: 'high', source: 'scanner', port: 80 }),
      f({ target: 'http://127.0.0.1:8090/x', severity: 'low' })
    ])
    expect(rows).toHaveLength(1)
    expect(rows[0].host).toBe('127.0.0.1')
    expect(rows[0].total).toBe(2)
    expect(rows[0].bySeverity.high).toBe(1)
    expect(rows[0].bySeverity.low).toBe(1)
    expect(rows[0].kev).toBe(0)
  })
  it('sorts by KEV count, then critical count, then total', () => {
    const rows = exposureByTarget([
      f({ target: '10.0.0.1', severity: 'low' }),
      f({ target: '10.0.0.2', severity: 'low', kev: [kev] }),
      f({ target: '10.0.0.3', severity: 'critical' })
    ])
    expect(rows.map((r) => r.host)).toEqual(['10.0.0.2', '10.0.0.3', '10.0.0.1'])
  })
})

describe('summarize', () => {
  it('counts critical or high, confirmed, KEV and distinct hosts', () => {
    const s = summarize([
      f({ target: '10.0.0.1', severity: 'critical', confidence: 'confirmed', kev: [kev] }),
      f({ target: 'http://10.0.0.1:80/a', severity: 'low', confidence: 'suspected' }),
      f({ target: '10.0.0.2', severity: 'high', confidence: 'confirmed' })
    ])
    expect(s).toEqual({ critHigh: 2, confirmed: 2, kev: 1, hosts: 2 })
  })
  it('returns zeros for an empty list', () => {
    expect(summarize([])).toEqual({ critHigh: 0, confirmed: 0, kev: 0, hosts: 0 })
  })
})

describe('timeLabel', () => {
  it('formats a time as HH:MM:SS', () => {
    expect(timeLabel('2026-11-01T14:05:09')).toMatch(/^\d{2}:\d{2}:\d{2}$/)
  })
})
