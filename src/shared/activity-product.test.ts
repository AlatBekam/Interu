import { describe, expect, it } from 'vitest'
import type { Finding } from './rules'
import type { KevInfo } from './kev'
import { eventFromFinding, priorityQueue, summarize, exposureByTarget } from './activity'

const kev: KevInfo = { cve: 'CVE-2021-3129', name: 'x', dateAdded: '2021-11-01', ransomware: false }
const base = (o: Partial<Finding>): Finding => ({
  key: 'k', templateId: 't', name: 'N', severity: 'low', confidence: 'suspected',
  target: '10.0.0.1', evidence: 'e', source: 'scanner', at: '2026-11-01T00:00:00Z', ...o
})
const productLevel: Partial<Finding> = { tags: ['kev-product'], kev: [kev], severity: 'medium' }

describe('product-level hits stay quiet', () => {
  it('ranks a proven critical finding ahead of a product-level hit', () => {
    const q = priorityQueue([
      base({ key: 'p', name: 'product', ...productLevel }),
      base({ key: 'c', name: 'critical', severity: 'critical', confidence: 'confirmed' })
    ])
    expect(q.map((f) => f.name)).toEqual(['critical', 'product'])
  })

  it('does not count a product-level hit as actively exploited', () => {
    expect(summarize([base({ ...productLevel })]).kev).toBe(0)
  })

  it('keeps a product-level hit out of the per-host KEV count', () => {
    expect(exposureByTarget([base({ ...productLevel })])[0].kev).toBe(0)
  })

  it('logs a product-level hit as a warning, not critical', () => {
    expect(eventFromFinding(base({ ...productLevel })).level).toBe('warn')
  })

  it('still ranks a CVE-level KEV finding ahead of a critical one without KEV', () => {
    const q = priorityQueue([
      base({ key: 'c', name: 'critical', severity: 'critical', confidence: 'confirmed' }),
      base({ key: 'k2', name: 'cve-kev', severity: 'low', kev: [kev] })
    ])
    expect(q.map((f) => f.name)).toEqual(['cve-kev', 'critical'])
  })
})
