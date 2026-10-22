import { beforeEach, describe, expect, it, vi } from 'vitest'
import { freshDirs, loadMain } from '../helpers/electron-mock'

vi.mock('electron', async () => (await import('../helpers/electron-mock')).electron)

const ROE = { operation: 'OP-TC', operator: 'tester', allow: { scan: true, repeater: true, intruder: false } }

describe('UC-01 RoE gate (src/main/audit.ts authorize)', () => {
  let m: Awaited<ReturnType<typeof loadMain>>
  beforeEach(async () => {
    freshDirs()
    m = await loadMain()
  })

  it('TC-01-01 blocks every technique when no RoE is active, and logs it', () => {
    expect(m.audit.authorize('repeater', 'GET http://127.0.0.1/').ok).toBe(false)
    expect(m.audit.listAudit()).toMatchObject([{ action: 'repeater', result: 'blocked', operation: '_no-operation' }])
  })

  it('TC-01-02 allows a permitted technique and blocks a disabled one', () => {
    expect(m.audit.setRoe(ROE).ok).toBe(true)
    expect(m.audit.authorize('repeater', 'GET http://127.0.0.1/').ok).toBe(true)
    expect(m.audit.authorize('intruder', 'GET http://127.0.0.1/').ok).toBe(false)
    expect(m.audit.listAudit().map((e) => [e.action, e.result])).toEqual([
      ['roe:set', 'info'], ['repeater', 'allowed'], ['intruder', 'blocked']
    ])
  })

  it('TC-01-03 blocks outside the time window', () => {
    m.audit.setRoe({ ...ROE, windowEnd: '2000-01-01T00:00' })
    const r = m.audit.authorize('scan', '127.0.0.1 (quick)')
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toContain('jendela waktu')
  })

  it('TC-01-04 a scope rejection is blocked and logged even with a permissive RoE', () => {
    m.audit.setRoe(ROE)
    expect(m.audit.authorize('repeater', 'GET http://out-of-scope.test/', 'not in scope')).toEqual({ ok: false, reason: 'not in scope' })
    expect(m.audit.listAudit().at(-1)).toMatchObject({ action: 'repeater', result: 'blocked', detail: 'not in scope' })
  })

  it('TC-01-05 rejects an invalid RoE and keeps a valid one across an app restart', async () => {
    expect(m.audit.setRoe({ operation: '', operator: 'x', allow: {} }).ok).toBe(false)
    m.audit.setRoe(ROE)
    const restarted = await loadMain() // same userData, fresh module state
    expect(restarted.audit.getRoe()?.operation).toBe('OP-TC')
    expect(restarted.audit.authorize('intruder', 'x').ok).toBe(false)
  })
})
