import { beforeEach, describe, expect, it } from 'vitest'
import { pushActivity, getActivity, clearActivity, noteScopeBlock } from './activity'

beforeEach(() => clearActivity())

describe('activity store', () => {
  it('keeps the newest 200 events, newest first, with unique ids', () => {
    for (let i = 0; i < 205; i++) {
      pushActivity({ ts: '2026-11-01T00:00:00Z', level: 'info', category: 'scan', message: 'm' + i })
    }
    const list = getActivity()
    expect(list).toHaveLength(200)
    expect(list[0].message).toBe('m204')
    expect(new Set(list.map((e) => e.id)).size).toBe(200)
  })

  it('records a scope block with the target and the feature that refused it', () => {
    noteScopeBlock('http://10.0.0.9/', 'repeater')
    const [e] = getActivity()
    expect(e.level).toBe('warn')
    expect(e.category).toBe('scope')
    expect(e.message).toBe('Blocked by scope: http://10.0.0.9/ (repeater)')
    expect(e.target).toBe('http://10.0.0.9/')
  })
})
