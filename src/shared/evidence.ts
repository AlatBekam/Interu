// Evidence package manifest: lists every file in an exported package with its
// SHA-256, plus the head hash of the packaged audit chain. Verification recomputes
// every hash and the audit chain. Paths read from a manifest are untrusted and must
// stay inside the package folder. The hash function and file reader are injected
// so this stays framework-free and testable.

import { verifyLog, Sha } from './audit'

export const MANIFEST_FORMAT = 'interu-evidence/1'
export const AUDIT_FILE = 'audit.jsonl'

export interface ManifestFile { path: string; sha256: string; length: number }

export interface Manifest {
  format: typeof MANIFEST_FORMAT
  operation: string
  operator: string
  exportedAt: string
  auditHead: string
  files: ManifestFile[]
}

/** Windows device names (CON, NUL, COM1, ...) open a device instead of a file. */
export const isReservedName = (s: string): boolean => /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(s)

/** Relative path of 1–2 plain segments (e.g. "evidence/x.json"); no "..", no absolute paths, no device names. */
export function isSafeRelPath(p: unknown): p is string {
  return typeof p === 'string' && /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)?$/.test(p) &&
    !p.split('/').some((s) => s === '.' || s === '..' || isReservedName(s))
}

/** sha256 recorded for each evidence file name by the hash-chained `evidence:save` entries. */
function savedHashes(auditText: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const line of auditText.split('\n')) {
    if (!line.trim()) continue
    const e = JSON.parse(line) as { action?: string; detail?: string }
    const m = e.action === 'evidence:save' ? /^(\S+) sha256=([0-9a-f]{64})$/.exec(e.detail || '') : null
    if (m) out.set(m[1], m[2])
  }
  return out
}

export function buildManifest(
  meta: Pick<Manifest, 'operation' | 'operator' | 'exportedAt' | 'auditHead'>,
  files: { path: string; content: string }[],
  sha: Sha
): Manifest {
  return {
    format: MANIFEST_FORMAT,
    ...meta,
    files: files.map((f) => ({ path: f.path, sha256: sha(f.content), length: f.content.length }))
  }
}

export type ManifestCheck = { ok: true; count: number } | { ok: false; problems: string[] }

/** `read` returns a file's text, or null when it is missing. */
export function verifyManifest(m: unknown, read: (path: string) => string | null, sha: Sha): ManifestCheck {
  const mf = m as Partial<Manifest> | null
  if (!mf || mf.format !== MANIFEST_FORMAT || !Array.isArray(mf.files)) return { ok: false, problems: ['manifest.json bukan paket bukti Interu yang valid'] }
  const problems: string[] = []
  // The manifest alone is not trusted: each file must also match the hash the
  // chained audit log recorded when it was saved, so editing a file AND its
  // manifest entry is still caught.
  const auditText = read(AUDIT_FILE)
  let saved = new Map<string, string>()
  if (auditText == null) problems.push(`${AUDIT_FILE}: file hilang`)
  else {
    const chain = verifyLog(auditText, sha)
    if (!chain.ok) problems.push(`${AUDIT_FILE}: rantai rusak di baris ${chain.brokenAt} (${chain.reason})`)
    else {
      if (chain.head !== mf.auditHead) problems.push(`${AUDIT_FILE}: head hash tidak cocok dengan manifest`)
      saved = savedHashes(auditText)
    }
  }
  for (const f of mf.files) {
    if (!f || !isSafeRelPath(f.path)) { problems.push(`path tidak aman di manifest: ${String(f?.path)}`); continue }
    const content = read(f.path)
    if (content == null) { problems.push(`${f.path}: file hilang`); continue }
    const h = sha(content)
    if (h !== f.sha256) problems.push(`${f.path}: isi berubah (hash tidak cocok dengan manifest)`)
    else if (auditText != null && saved.get(f.path.split('/').pop() || '') !== h) {
      problems.push(`${f.path}: tidak cocok dengan entri evidence:save di audit log`)
    }
  }
  return problems.length ? { ok: false, problems } : { ok: true, count: mf.files.length }
}
