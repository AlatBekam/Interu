import { beforeEach, describe, expect, it } from 'vitest'
import type { Finding } from '../../../shared/rules'
import { addFindings, clearFindings, removeFinding } from './findings'
import { getActivity, clearActivity } from './activity'
import { inScopeOrNote } from '../lib/http'

let n = 0
const f = (o: Partial<Finding> = {}): Finding => ({
  key: `s${n++}`, templateId: 't', name: 'Exposed X', severity: 'low', confidence: 'confirmed',
  target: 'http://127.0.0.1:8090/x', evidence: 'e', source: 'active', at: '2026-11-01T00:00:00Z', ...o
})

beforeEach(() => {
  clearFindings()
  clearActivity()
})

describe('findings feed the activity log', () => {
  it('adds one event per new finding and none when the same key comes back', () => {
    const x = f()
    addFindings([x])
    addFindings([x])
    expect(getActivity().filter((e) => e.message === 'New finding: Exposed X')).toHaveLength(1)
  })

  it('records a resolved finding as ok, and clearing findings adds nothing', () => {
    const x = f()
    addFindings([x])
    clearActivity()
    removeFinding(x.key)
    const [e] = getActivity()
    expect(e.level).toBe('ok')
    expect(e.message).toBe('Resolved: Exposed X')
    clearActivity()
    clearFindings()
    expect(getActivity()).toHaveLength(0)
  })
})

describe('inScopeOrNote', () => {
  it('refuses an out-of-scope target and records the refusal', () => {
    expect(inScopeOrNote('http://10.0.0.9/', ['10.0.0.1'], 'repeater')).toBe(false)
    expect(getActivity()[0].message).toBe('Blocked by scope: http://10.0.0.9/ (repeater)')
  })

  it('allows an in-scope target and records nothing', () => {
    expect(inScopeOrNote('http://10.0.0.1/', ['10.0.0.1'], 'repeater')).toBe(true)
    expect(getActivity()).toHaveLength(0)
  })
})
