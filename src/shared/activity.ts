// Pure logic for the Exposure Monitor: turns findings and scan/scope/proxy
// events into a priority queue, per-host exposure and summary counts. Only
// what Interu itself observed goes in here; nothing is generated or simulated.
import type { Finding, RuleSeverity } from './rules'
import { SEVERITY_RANK } from './rules'

export type ActivityLevel = 'info' | 'warn' | 'crit' | 'ok'
export type ActivityCategory = 'finding' | 'scan' | 'scope' | 'proxy'

export interface ActivityEvent {
  id: string
  ts: string
  level: ActivityLevel
  category: ActivityCategory
  message: string
  target?: string
}

export type ActivityDraft = Omit<ActivityEvent, 'id'>

/** Host part of a target: a URL, a host:port, or a bare IP/host. */
export function hostOf(target: string): string {
  try {
    const h = new URL(target).hostname
    if (h) return h
  } catch { /* not a URL, fall through */ }
  return target.replace(/:\d+$/, '')
}

export function severityLevel(s: RuleSeverity): ActivityLevel {
  if (s === 'critical' || s === 'high') return 'crit'
  if (s === 'medium') return 'warn'
  return 'info'
}

/** A version-blind product hit (see fingerprint.ts), not a CVE that is proven exploited here. */
export function isProductLevel(f: Finding): boolean {
  return !!f.tags?.includes('kev-product')
}

export function eventFromFinding(f: Finding, at = new Date().toISOString()): ActivityDraft {
  return {
    ts: at,
    level: isProductLevel(f) ? 'warn' : f.kev?.length ? 'crit' : severityLevel(f.severity),
    category: 'finding',
    message: `New finding: ${f.name}`,
    target: f.target
  }
}

/** KEV-listed first, then severity, then confirmed before suspected. Never mutates the input. */
export function priorityQueue(findings: Finding[], limit = Infinity): Finding[] {
  const rank = (f: Finding): number[] => [
    f.kev?.length && !isProductLevel(f) ? 0 : 1,
    SEVERITY_RANK[f.severity],
    f.confidence === 'confirmed' ? 0 : 1
  ]
  return [...findings]
    .sort((a, b) => {
      const ra = rank(a)
      const rb = rank(b)
      for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] - rb[i]
      return a.target.localeCompare(b.target)
    })
    .slice(0, limit)
}

export interface TargetExposure {
  host: string
  total: number
  bySeverity: Record<RuleSeverity, number>
  kev: number
}

const emptyBySeverity = (): Record<RuleSeverity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })

export function exposureByTarget(findings: Finding[]): TargetExposure[] {
  const rows = new Map<string, TargetExposure>()
  for (const f of findings) {
    const host = hostOf(f.target)
    const row = rows.get(host) ?? { host, total: 0, bySeverity: emptyBySeverity(), kev: 0 }
    row.total++
    row.bySeverity[f.severity]++
    if (f.kev?.length && !isProductLevel(f)) row.kev++
    rows.set(host, row)
  }
  return [...rows.values()].sort((a, b) =>
    b.kev - a.kev || b.bySeverity.critical - a.bySeverity.critical || b.total - a.total
  )
}

export function summarize(findings: Finding[]): { critHigh: number; confirmed: number; kev: number; hosts: number } {
  return {
    critHigh: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length,
    confirmed: findings.filter((f) => f.confidence === 'confirmed').length,
    kev: findings.filter((f) => !!f.kev?.length && !isProductLevel(f)).length,
    hosts: new Set(findings.map((f) => hostOf(f.target))).size
  }
}

/** Local time as HH:MM:SS, 24 hours. */
export function timeLabel(iso: string): string {
  const d = new Date(iso)
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((x) => String(x).padStart(2, '0')).join(':')
}
