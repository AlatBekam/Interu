import { beforeEach, describe, expect, it, vi } from 'vitest'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'
import { freshDirs, loadMain } from '../helpers/electron-mock'

vi.mock('electron', async () => (await import('../helpers/electron-mock')).electron)

const ROE = { operation: 'OP-TC', operator: 'tester', allow: { scan: true, repeater: true } }

describe('UC-02 hash-chained audit log on disk (src/main/audit.ts)', () => {
  let m: Awaited<ReturnType<typeof loadMain>>
  const lines = (): string[] => readFileSync(m.audit.auditFile('OP-TC'), 'utf8').trim().split('\n')
  const writeLines = (l: string[]): void => writeFileSync(m.audit.auditFile('OP-TC'), l.join('\n') + '\n')

  beforeEach(async () => {
    freshDirs()
    m = await loadMain()
    m.audit.setRoe(ROE)
    m.audit.authorize('repeater', 'GET http://127.0.0.1/a')
    m.audit.authorize('scan', '127.0.0.1 (quick)')
    m.audit.authorize('intruder', 'GET http://127.0.0.1/b')
  })

  it('TC-02-01 writes a verifiable chain of 4 entries', () => {
    expect(lines()).toHaveLength(4)
    expect(m.audit.verifyAudit()).toMatchObject({ ok: true, count: 4 })
  })

  it('TC-02-02 an edited line is reported at that line', () => {
    const l = lines()
    l[2] = l[2].replace('127.0.0.1 (quick)', '127.0.0.2 (quick)')
    writeLines(l)
    expect(m.audit.verifyAudit()).toMatchObject({ ok: false, brokenAt: 3 })
  })

  it('TC-02-03 a deleted middle line is reported', () => {
    const l = lines()
    l.splice(1, 1)
    writeLines(l)
    expect(m.audit.verifyAudit()).toMatchObject({ ok: false, brokenAt: 2 })
  })

  it('TC-02-04 the chain continues correctly after an app restart', async () => {
    const restarted = await loadMain()
    restarted.audit.authorize('repeater', 'GET http://127.0.0.1/c')
    expect(restarted.audit.verifyAudit()).toMatchObject({ ok: true, count: 5 })
  })

  it('TC-02-05 a Windows device name as operation still writes a real file', () => {
    m.audit.setRoe({ ...ROE, operation: 'NUL' })
    m.audit.authorize('repeater', 'x')
    const file = m.audit.auditFile('NUL')
    expect(basename(file)).toBe('_NUL.jsonl')
    expect(existsSync(file)).toBe(true)
    expect(m.audit.verifyAudit()).toMatchObject({ ok: true, count: 2 })
  })

  it('TC-02-06 a very long target is truncated to 500 chars', () => {
    m.audit.authorize('repeater', 'GET http://127.0.0.1/' + 'a'.repeat(5000))
    expect(m.audit.listAudit().at(-1)?.target.length).toBe(500)
  })

  it('TC-02-07 KNOWN LIMIT: dropping the last lines still verifies (no external anchor)', () => {
    writeLines(lines().slice(0, 2))
    expect(m.audit.verifyAudit()).toMatchObject({ ok: true, count: 2 })
  })
})
