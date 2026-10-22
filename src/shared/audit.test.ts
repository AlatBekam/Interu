import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { chainEntry, verifyChain, verifyLog, AuditEntry, AuditData, GENESIS } from './audit'

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')
const data = (n: number): AuditData => ({
  at: `2026-10-22T09:00:0${n}.000Z`, operation: 'OP', operator: 'alice', action: 'http', target: `http://10.0.0.${n}/`, result: 'allowed'
})

function chain(n: number): AuditEntry[] {
  const out: AuditEntry[] = []
  for (let i = 0; i < n; i++) out.push(chainEntry(out[i - 1] ?? null, data(i), sha))
  return out
}

describe('audit chain', () => {
  it('links entries from the genesis hash', () => {
    const c = chain(3)
    expect(c[0].prevHash).toBe(GENESIS)
    expect(c[1].prevHash).toBe(c[0].hash)
    expect(verifyChain(c, sha)).toEqual({ ok: true, count: 3, head: c[2].hash })
  })
  it('pinpoints an edited entry', () => {
    const c = chain(4)
    c[2] = { ...c[2], target: 'http://evil/' }
    expect(verifyChain(c, sha)).toMatchObject({ ok: false, brokenAt: 3 })
  })
  it('detects a deleted entry', () => {
    const c = chain(4)
    c.splice(1, 1)
    expect(verifyChain(c, sha)).toMatchObject({ ok: false, brokenAt: 2 })
  })
  it('verifies JSONL text and flags an unparsable line', () => {
    const text = chain(3).map((e) => JSON.stringify(e)).join('\n') + '\n'
    expect(verifyLog(text, sha).ok).toBe(true)
    const lines = text.trim().split('\n')
    lines[1] = lines[1].slice(0, -3)
    expect(verifyLog(lines.join('\n'), sha)).toMatchObject({ ok: false, brokenAt: 2 })
  })
})
