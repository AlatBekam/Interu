import { app, dialog } from 'electron'
import fs from 'node:fs'
import { join, resolve, sep } from 'node:path'
import { audit, auditFile, currentOperation, getRoe, safeName, sha } from './audit'
import { verifyLog } from '../shared/audit'
import { buildManifest, verifyManifest, AUDIT_FILE, ManifestCheck } from '../shared/evidence'

// Evidence store: each confirmed finding is written once to its own JSON file
// under userData, so proof survives renderer storage limits and "Clear". File
// names derive from a hash, never from renderer-supplied text.

const MAX_BYTES = 400_000

export const evidenceDir = (operation: string): string => join(app.getPath('userData'), 'evidence', safeName(operation))

export function saveEvidence(x: unknown): { ok: boolean; file?: string; error?: string } {
  if (!x || typeof x !== 'object') return { ok: false, error: 'Bukti tidak valid.' }
  const f = x as Record<string, unknown>
  if (typeof f.key !== 'string' || typeof f.templateId !== 'string' || typeof f.target !== 'string') {
    return { ok: false, error: 'Bukti tidak valid: key/templateId/target wajib ada.' }
  }
  const r = getRoe()
  const body = JSON.stringify({ savedAt: new Date().toISOString(), operation: currentOperation(), operator: r?.operator || '-', finding: f }, null, 2)
  if (body.length > MAX_BYTES) return { ok: false, error: 'Bukti terlalu besar.' }
  const dir = evidenceDir(currentOperation())
  fs.mkdirSync(dir, { recursive: true })
  const name = `${sha(f.key).slice(0, 16)}-${Date.now()}.json`
  fs.writeFileSync(join(dir, name), body)
  audit({ action: 'evidence:save', target: f.key.slice(0, 300), result: 'info', detail: `${name} sha256=${sha(body)}` })
  return { ok: true, file: name }
}

const readText = (p: string): string | null => {
  try { return fs.readFileSync(p, 'utf8') } catch { return null }
}

/**
 * Copy the current operation's evidence + audit log into a new folder under
 * Downloads with a manifest. The manifest's own sha256 (the fingerprint) is
 * recorded in the live audit log so a recipient can confirm the package is the
 * one this app produced.
 */
export function exportEvidence(): { ok: boolean; dir?: string; count?: number; fingerprint?: string; error?: string } {
  const operation = currentOperation()
  const auditText = readText(auditFile(operation)) || ''
  const chain = verifyLog(auditText, sha)
  if (!chain.ok) return { ok: false, error: `Audit log rusak di baris ${chain.brokenAt}; ekspor dibatalkan.` }

  const src = evidenceDir(operation)
  const names = fs.existsSync(src) ? fs.readdirSync(src).filter((n) => n.endsWith('.json')).sort() : []
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const out = join(app.getPath('downloads'), `Interu-Evidence-${safeName(operation)}-${stamp}`)
  fs.mkdirSync(join(out, 'evidence'), { recursive: true })

  const files = names.map((n) => ({ path: `evidence/${n}`, content: fs.readFileSync(join(src, n), 'utf8') }))
  for (const f of files) fs.writeFileSync(join(out, f.path), f.content)
  fs.writeFileSync(join(out, AUDIT_FILE), auditText)
  const manifest = buildManifest(
    { operation, operator: getRoe()?.operator || '-', exportedAt: new Date().toISOString(), auditHead: chain.head },
    files,
    sha
  )
  const manifestText = JSON.stringify(manifest, null, 2)
  fs.writeFileSync(join(out, 'manifest.json'), manifestText)
  const fingerprint = sha(manifestText)
  audit({ action: 'evidence:export', target: out, result: 'info', detail: `files=${files.length} fingerprint=${fingerprint}` })
  return { ok: true, dir: out, count: files.length, fingerprint }
}

/** Let the operator pick an exported package folder and verify it end to end. */
export async function verifyEvidence(): Promise<(ManifestCheck & { dir: string; fingerprint: string; unlisted: string[]; exportedHere: boolean }) | { ok: false; cancelled: true }> {
  const pick = await dialog.showOpenDialog({ title: 'Pilih folder paket bukti Interu', properties: ['openDirectory'] })
  if (pick.canceled || !pick.filePaths[0]) return { ok: false, cancelled: true }
  const dir = resolve(pick.filePaths[0])
  const manifestText = readText(join(dir, 'manifest.json'))
  let manifest: unknown = null
  try { manifest = manifestText ? JSON.parse(manifestText) : null } catch { /* reported as invalid */ }
  // Manifest paths are untrusted: only read files that resolve inside the chosen folder.
  const read = (p: string): string | null => {
    const full = resolve(dir, p)
    return full.startsWith(dir + sep) ? readText(full) : null
  }
  const check = verifyManifest(manifest, read, sha)
  const listed = new Set(((manifest as { files?: { path: string }[] } | null)?.files || []).map((f) => f.path))
  const evDir = join(dir, 'evidence')
  const unlisted = fs.existsSync(evDir) ? fs.readdirSync(evDir).map((n) => `evidence/${n}`).filter((p) => !listed.has(p)) : []
  const fingerprint = manifestText ? sha(manifestText) : ''
  // On the exporting machine, the export entry in the live log anchors the package.
  const exportedHere = !!fingerprint && (readText(auditFile(currentOperation())) || '').includes(`fingerprint=${fingerprint}`)
  audit({ action: 'evidence:verify', target: dir, result: 'info', detail: `${check.ok && unlisted.length === 0 ? 'ok' : 'FAILED'} fingerprint=${fingerprint}` })
  return { ...check, dir, fingerprint, unlisted, exportedHere }
}
