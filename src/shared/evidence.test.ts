import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { chainEntry } from './audit'
import { buildManifest, verifyManifest, isSafeRelPath, AUDIT_FILE } from './evidence'

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

function pkg() {
  const body = '{"finding":{"key":"expose-dotenv|http://10.0.0.5/.env"}}'
  const e1 = chainEntry(null, { at: '2026-10-22T09:00:00.000Z', operation: 'OP', operator: 'alice', action: 'active', target: 'GET http://10.0.0.5/.env', result: 'allowed' }, sha)
  const e2 = chainEntry(e1, { at: '2026-10-22T09:00:01.000Z', operation: 'OP', operator: 'alice', action: 'evidence:save', target: 'expose-dotenv', result: 'info', detail: `a.json sha256=${sha(body)}` }, sha)
  const files: Record<string, string> = {
    'evidence/a.json': body,
    [AUDIT_FILE]: JSON.stringify(e1) + '\n' + JSON.stringify(e2) + '\n'
  }
  const manifest = buildManifest(
    { operation: 'OP', operator: 'alice', exportedAt: '2026-10-22T10:00:00.000Z', auditHead: e2.hash },
    [{ path: 'evidence/a.json', content: files['evidence/a.json'] }],
    sha
  )
  return { files, manifest, read: (p: string) => files[p] ?? null }
}

describe('evidence manifest', () => {
  it('verifies an untouched package', () => {
    const { manifest, read } = pkg()
    expect(verifyManifest(manifest, read, sha)).toEqual({ ok: true, count: 1 })
  })
  it('names the file whose bytes changed', () => {
    const { manifest, files, read } = pkg()
    files['evidence/a.json'] = files['evidence/a.json'].replace('10.0.0.5', '10.0.0.6')
    const r = verifyManifest(manifest, read, sha)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.problems[0]).toContain('evidence/a.json')
  })
  it('still fails when the file AND its manifest hash are both rewritten', () => {
    const { manifest, files, read } = pkg()
    files['evidence/a.json'] = files['evidence/a.json'].replace('10.0.0.5', '10.0.0.6')
    manifest.files[0].sha256 = sha(files['evidence/a.json'])
    const r = verifyManifest(manifest, read, sha)
    expect(!r.ok && r.problems[0]).toContain('evidence:save')
  })
  it('rejects Windows device names in manifest paths', () => {
    expect(isSafeRelPath('evidence/CON')).toBe(false)
    expect(isSafeRelPath('nul.json')).toBe(false)
  })
  it('detects a tampered audit log inside the package', () => {
    const { manifest, files, read } = pkg()
    files[AUDIT_FILE] = files[AUDIT_FILE].replace('alice', 'mallory')
    expect(verifyManifest(manifest, read, sha).ok).toBe(false)
  })
  it('rejects path traversal in an untrusted manifest', () => {
    const { manifest, read } = pkg()
    manifest.files.push({ path: '../../secret.txt', sha256: 'x', length: 1 })
    const r = verifyManifest(manifest, read, sha)
    expect(!r.ok && r.problems.some((p) => p.includes('path tidak aman'))).toBe(true)
    expect(isSafeRelPath('evidence/a.json')).toBe(true)
    expect(isSafeRelPath('C:/x')).toBe(false)
    expect(isSafeRelPath('evidence/..')).toBe(false)
  })
})
