import { app } from 'electron'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { dirname, join } from 'node:path'
import { chainEntry, verifyLog, AuditEntry, AuditData, ChainCheck } from '../shared/audit'
import { roeAllows, sanitizeRoe, Roe, RoeCheck, Technique } from '../shared/roe'
import { isReservedName } from '../shared/evidence'

// Main-process holder of the active Rules of Engagement and writer of the
// hash-chained audit log. Both live under userData so they survive restarts and
// are never reachable from the renderer except through the IPC handlers.

export const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

const NO_OP = '_no-operation'
const roePath = (): string => join(app.getPath('userData'), 'roe.json')
export const safeName = (s: string): string => {
  const n = s.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 80) || NO_OP
  // "NUL", "CON", ... would silently write to a Windows device instead of a file.
  return isReservedName(n) ? '_' + n : n
}
export const auditFile = (operation: string): string => join(app.getPath('userData'), 'audit', safeName(operation) + '.jsonl')

let roe: Roe | null | undefined // undefined = not loaded from disk yet
const heads = new Map<string, AuditEntry | null>()

export function getRoe(): Roe | null {
  if (roe === undefined) {
    try {
      roe = sanitizeRoe(JSON.parse(fs.readFileSync(roePath(), 'utf8')))
    } catch {
      roe = null
    }
  }
  return roe
}

export function currentOperation(): string {
  return getRoe()?.operation || NO_OP
}

function lastEntry(file: string): AuditEntry | null {
  if (heads.has(file)) return heads.get(file) ?? null
  let last: AuditEntry | null = null
  try {
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n')
    if (lines[lines.length - 1]) last = JSON.parse(lines[lines.length - 1]) as AuditEntry
  } catch {
    /* no file yet, or a corrupted tail — verification will report it */
  }
  heads.set(file, last)
  return last
}

/** Append one entry to the current operation's chain. */
export function audit(d: Omit<AuditData, 'at' | 'operation' | 'operator'>): AuditEntry {
  const r = getRoe()
  const operation = r?.operation || NO_OP
  const file = auditFile(operation)
  fs.mkdirSync(dirname(file), { recursive: true })
  const e = chainEntry(lastEntry(file), { at: new Date().toISOString(), operation, operator: r?.operator || '-', ...d, target: d.target.slice(0, 500) }, sha)
  fs.appendFileSync(file, JSON.stringify(e) + '\n')
  heads.set(file, e)
  return e
}

export function setRoe(x: unknown): { ok: boolean; roe?: Roe; error?: string } {
  const r = sanitizeRoe(x)
  if (!r) return { ok: false, error: 'RoE tidak valid: nama operasi dan operator wajib diisi.' }
  fs.mkdirSync(dirname(roePath()), { recursive: true })
  fs.writeFileSync(roePath(), JSON.stringify(r, null, 2))
  roe = r
  const allowed = Object.entries(r.allow).filter(([, v]) => v).map(([k]) => k).join(',') || '-'
  audit({ action: 'roe:set', target: r.operation, result: 'info', detail: `allow=${allowed} window=${r.windowStart || '-'}..${r.windowEnd || '-'}` })
  return { ok: true, roe: r }
}

/** Decide one action against scope + RoE and record the decision either way. */
export function authorize(technique: Technique, target: string, scopeError?: string): RoeCheck {
  const check: RoeCheck = scopeError ? { ok: false, reason: scopeError } : roeAllows(getRoe(), technique)
  audit({ action: technique, target, result: check.ok ? 'allowed' : 'blocked', detail: check.ok ? undefined : check.reason })
  return check
}

export function listAudit(limit = 200): AuditEntry[] {
  try {
    const lines = fs.readFileSync(auditFile(currentOperation()), 'utf8').trim().split('\n').slice(-limit)
    const out: AuditEntry[] = []
    for (const l of lines) {
      try { out.push(JSON.parse(l) as AuditEntry) } catch { /* shown as broken by verify */ }
    }
    return out
  } catch {
    return []
  }
}

export function verifyAudit(): ChainCheck & { file: string } {
  const file = auditFile(currentOperation())
  let text = ''
  try { text = fs.readFileSync(file, 'utf8') } catch { /* empty log verifies as ok */ }
  return { ...verifyLog(text, sha), file }
}
