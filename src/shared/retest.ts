// Retest: re-run the check behind a stored finding to see whether a fix worked.
// The result is APPENDED to the finding's history; the original evidence is
// never replaced. Framework-free so it can be unit tested.

import type { Finding, RetestRecord, RetestStatus } from './rules'

export type RetestPlan =
  | { kind: 'http' }
  | { kind: 'port'; ip: string; port: number }
  | { kind: 'none'; reason: string }

/** How a finding can be retested automatically, if at all. */
export function retestPlan(f: Finding): RetestPlan {
  if (f.source === 'active' && f.req) return { kind: 'http' }
  if (f.source === 'scanner' && f.port != null) return { kind: 'port', ip: f.target, port: f.port }
  if (f.source === 'proxy') return { kind: 'none', reason: 'Temuan pasif proxy: jelajahi ulang lewat Proxy untuk memverifikasi.' }
  return { kind: 'none', reason: 'Tidak ada request tersimpan untuk diputar ulang.' }
}

/** Compare the original finding with what the retest saw (null = check no longer matches). */
export function retestStatus(old: Finding, fresh: Finding | null): RetestStatus {
  if (!fresh) return 'closed'
  return fresh.evidence === old.evidence ? 'open' : 'changed'
}

export function appendRetest(list: Finding[], key: string, rec: RetestRecord): Finding[] {
  return list.map((f) => (f.key === key ? { ...f, retests: [...(f.retests || []), rec] } : f))
}

export const latestRetest = (f: Finding): RetestRecord | undefined => f.retests?.[f.retests.length - 1]
