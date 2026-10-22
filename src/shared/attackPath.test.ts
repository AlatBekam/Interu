import { describe, expect, it } from 'vitest'
import type { Finding } from './rules'
import { buildAttackGraph, tacticOf } from './attackPath'

const f = (over: Partial<Finding>): Finding => ({
  key: 'k', templateId: 't', name: 'n', severity: 'medium', confidence: 'suspected', target: '10.0.0.5',
  evidence: 'e', source: 'scanner', at: '2026-10-22T09:00:00.000Z', ...over
})

const telnet = f({ key: 'svc-telnet|10.0.0.5:23', name: 'Telnet exposed', severity: 'high', port: 23, mitre: ['T1021'] })
const dotenv = f({ key: 'expose-dotenv|http://10.0.0.5/.env', name: 'Exposed .env', severity: 'critical', confidence: 'confirmed', target: 'http://10.0.0.5/.env', source: 'active', tags: ['secrets'] })
const csp = f({ key: 'csp|https://shop.test', name: 'Missing CSP', severity: 'low', confidence: 'confirmed', target: 'https://shop.test', source: 'proxy' })

describe('buildAttackGraph', () => {
  it('groups findings under host and service nodes', () => {
    const g = buildAttackGraph([telnet, dotenv, csp])
    const ids = g.nodes.map((n) => n.id)
    expect(ids).toEqual(expect.arrayContaining(['host:10.0.0.5', 'svc:10.0.0.5:23', 'svc:10.0.0.5:80', 'host:shop.test', 'svc:shop.test:443']))
    expect(g.edges).toContainEqual({ from: 'svc:10.0.0.5:23', to: `finding:${telnet.key}` })
  })
  it('links a finding without any port straight to its host', () => {
    const g = buildAttackGraph([f({ key: 'x', target: '10.0.0.9' })])
    expect(g.edges).toEqual([{ from: 'host:10.0.0.9', to: 'finding:x' }])
  })
  it('marks the worst confirmed finding as the critical path', () => {
    expect(buildAttackGraph([telnet, dotenv, csp]).critical).toEqual(['host:10.0.0.5', 'svc:10.0.0.5:80', `finding:${dotenv.key}`])
    expect(buildAttackGraph([telnet]).critical).toEqual([])
  })
})

describe('tacticOf', () => {
  it('uses the MITRE technique first, then the heuristic', () => {
    expect(tacticOf(telnet).name).toBe('Lateral Movement')
    expect(tacticOf(dotenv).name).toBe('Credential Access')
    expect(tacticOf(csp).name).toBe('Initial Access')
    expect(tacticOf(f({})).name).toBe('Discovery')
  })
})
