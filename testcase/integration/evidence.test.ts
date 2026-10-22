import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { freshDirs, loadMain, pickFolder } from '../helpers/electron-mock'
import type { Finding } from '../../src/shared/rules'

vi.mock('electron', async () => (await import('../helpers/electron-mock')).electron)

const ROE = { operation: 'OP-TC', operator: 'tester', allow: { active: true } }
const finding = (over: Partial<Finding> = {}): Finding => ({
  key: 'tpl-demo|http://127.0.0.1/demo', templateId: 'tpl-demo', name: 'Demo finding', severity: 'high',
  confidence: 'confirmed', target: 'http://127.0.0.1/demo', evidence: 'matched: demo', source: 'active',
  at: '2026-10-22T09:00:00.000Z', raw: { request: 'GET http://127.0.0.1/demo HTTP/1.1', response: 'HTTP/1.1 200 OK\n\ndemo' },
  ...over
})

describe('UC-03 evidence package (src/main/evidence.ts)', () => {
  let m: Awaited<ReturnType<typeof loadMain>>
  let pkg: string
  const evFile = (): string => join(pkg, 'evidence', readdirSync(join(pkg, 'evidence'))[0])
  const manifestPath = (): string => join(pkg, 'manifest.json')
  const verify = async () => { pickFolder(pkg); return m.evidence.verifyEvidence() }

  beforeEach(async () => {
    freshDirs()
    m = await loadMain()
    m.audit.setRoe(ROE)
    expect(m.evidence.saveEvidence(finding()).ok).toBe(true)
    const exp = m.evidence.exportEvidence()
    expect(exp).toMatchObject({ ok: true, count: 1 })
    pkg = exp.dir!
  })

  it('TC-03-01 an untouched package verifies and is anchored in this operation log', async () => {
    expect(existsSync(manifestPath())).toBe(true)
    expect(await verify()).toMatchObject({ ok: true, count: 1, unlisted: [], exportedHere: true })
  })

  it('TC-03-02 one changed character in an evidence file fails', async () => {
    writeFileSync(evFile(), readFileSync(evFile(), 'utf8').replace('Demo finding', 'Demo FindinG'))
    const v = await verify()
    expect(v.ok).toBe(false)
    expect(JSON.stringify(v)).toContain('isi berubah')
  })

  it('TC-03-03 rewriting the file AND its manifest hash still fails (evidence:save cross-check)', async () => {
    const f = evFile()
    writeFileSync(f, readFileSync(f, 'utf8').replace('Demo finding', 'Demo FindinG'))
    const manifest = JSON.parse(readFileSync(manifestPath(), 'utf8'))
    manifest.files[0].sha256 = createHash('sha256').update(readFileSync(f, 'utf8')).digest('hex')
    writeFileSync(manifestPath(), JSON.stringify(manifest, null, 2))
    const v = await verify()
    expect(v.ok).toBe(false)
    expect(JSON.stringify(v)).toContain('evidence:save')
  })

  it('TC-03-04 an extra file not in the manifest is reported', async () => {
    writeFileSync(join(pkg, 'evidence', 'planted.json'), '{}')
    expect(await verify()).toMatchObject({ unlisted: ['evidence/planted.json'] })
  })

  it('TC-03-05 a manifest entry pointing outside the package is rejected', async () => {
    const manifest = JSON.parse(readFileSync(manifestPath(), 'utf8'))
    manifest.files.push({ path: '../outside.json', sha256: 'x', length: 1 })
    writeFileSync(manifestPath(), JSON.stringify(manifest))
    expect(JSON.stringify(await verify())).toContain('path tidak aman')
  })

  it('TC-03-06 an edited audit.jsonl inside the package fails', async () => {
    const a = join(pkg, 'audit.jsonl')
    writeFileSync(a, readFileSync(a, 'utf8').replace('tester', 'someone'))
    expect((await verify()).ok).toBe(false)
  })

  it('TC-03-07 export is refused while the live audit log is broken', () => {
    const live = m.audit.auditFile('OP-TC')
    writeFileSync(live, readFileSync(live, 'utf8').replace('tester', 'someone'))
    expect(m.evidence.exportEvidence()).toMatchObject({ ok: false })
  })

  it('TC-03-08 the evidence file name is derived from a hash, never from the finding key', () => {
    expect(m.evidence.saveEvidence({ key: 1 }).ok).toBe(false)
    const r = m.evidence.saveEvidence(finding({ key: 'a/b\\c:d' }))
    expect(r.ok).toBe(true)
    expect(r.file).toMatch(/^[0-9a-f]{16}-\d+\.json$/)
    expect(existsSync(join(m.evidence.evidenceDir('OP-TC'), r.file!))).toBe(true)
  })

  it('TC-03-09 a cancelled folder dialog is reported as cancelled', async () => {
    pickFolder(null)
    expect(await m.evidence.verifyEvidence()).toEqual({ ok: false, cancelled: true })
  })
})
