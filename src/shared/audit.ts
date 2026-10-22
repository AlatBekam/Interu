// Hash-chained audit log. Every entry stores the hash of the entry before it, so
// editing, deleting or reordering any line breaks the chain from that point on.
// The hash function is injected so this stays framework-free and testable; the
// main process passes node:crypto sha256.

export type Sha = (s: string) => string

export interface AuditEntry {
  seq: number
  at: string
  operation: string
  operator: string
  action: string
  target: string
  result: 'allowed' | 'blocked' | 'info'
  detail?: string
  prevHash: string
  hash: string
}

export type AuditData = Omit<AuditEntry, 'seq' | 'prevHash' | 'hash'>

export const GENESIS = '0'.repeat(64)

// Fixed field order so the hashed text never depends on object key order.
function canonical(e: Omit<AuditEntry, 'hash'>): string {
  return JSON.stringify([e.seq, e.at, e.operation, e.operator, e.action, e.target, e.result, e.detail ?? '', e.prevHash])
}

export function chainEntry(prev: AuditEntry | null, data: AuditData, sha: Sha): AuditEntry {
  const base = { ...data, seq: prev ? prev.seq + 1 : 1, prevHash: prev ? prev.hash : GENESIS }
  return { ...base, hash: sha(canonical(base)) }
}

export type ChainCheck = { ok: true; count: number; head: string } | { ok: false; brokenAt: number; reason: string }

/** Verify a parsed chain. `brokenAt` is the 1-based line of the first bad entry. */
export function verifyChain(entries: AuditEntry[], sha: Sha): ChainCheck {
  let prevHash = GENESIS
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]
    if (!e || typeof e !== 'object') return { ok: false, brokenAt: i + 1, reason: 'baris bukan entri audit' }
    if (e.seq !== i + 1) return { ok: false, brokenAt: i + 1, reason: `urutan seq tidak sesuai (diharapkan ${i + 1}, tertulis ${e.seq})` }
    if (e.prevHash !== prevHash) return { ok: false, brokenAt: i + 1, reason: 'prevHash tidak cocok dengan entri sebelumnya' }
    const { hash, ...rest } = e
    if (sha(canonical(rest)) !== hash) return { ok: false, brokenAt: i + 1, reason: 'isi entri sudah diubah (hash tidak cocok)' }
    prevHash = hash
  }
  return { ok: true, count: entries.length, head: prevHash }
}

/** Verify raw JSONL text as written to disk; a line that fails to parse breaks the chain there. */
export function verifyLog(text: string, sha: Sha): ChainCheck {
  const lines = text.split('\n').filter((l) => l.trim() !== '')
  const entries: AuditEntry[] = []
  for (let i = 0; i < lines.length; i++) {
    try {
      entries.push(JSON.parse(lines[i]) as AuditEntry)
    } catch {
      return { ok: false, brokenAt: i + 1, reason: 'baris bukan JSON yang valid' }
    }
  }
  return verifyChain(entries, sha)
}
