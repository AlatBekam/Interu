// Rules of Engagement (RoE): the operation's written authorization. The scope
// gate decides WHICH hosts may be touched; the RoE adds WHO is operating, WHEN
// the operation is allowed, and WHICH techniques are permitted. The main process
// holds the active RoE and checks it before any traffic leaves the app.
// Framework-free so main, preload and renderer can all import it.

export type Technique = 'scan' | 'proxy' | 'repeater' | 'intruder' | 'discovery' | 'active' | 'retest'

export const TECHNIQUES: { id: Technique; label: string }[] = [
  { id: 'scan', label: 'Network scan (TCP connect)' },
  { id: 'proxy', label: 'Proxy / MITM capture' },
  { id: 'repeater', label: 'Repeater (manual request)' },
  { id: 'intruder', label: 'Intruder (payload attack)' },
  { id: 'discovery', label: 'Target discovery (path brute-force)' },
  { id: 'active', label: 'Rule Engine active probes' },
  { id: 'retest', label: 'Retest of stored findings' }
]

export interface Roe {
  operation: string
  operator: string
  /** ISO / datetime-local string; omitted = no lower bound. */
  windowStart?: string
  /** ISO / datetime-local string; omitted = no upper bound. */
  windowEnd?: string
  allow: Partial<Record<Technique, boolean>>
}

export type RoeCheck = { ok: true } | { ok: false; reason: string }

export function isTechnique(x: unknown): x is Technique {
  return typeof x === 'string' && TECHNIQUES.some((t) => t.id === x)
}

/** Decide whether `technique` may run under `roe` at time `now`. No RoE = deny. */
export function roeAllows(roe: Roe | null, technique: Technique, now: Date = new Date()): RoeCheck {
  if (!roe) return { ok: false, reason: 'Belum ada Rules of Engagement aktif. Buat RoE dulu di halaman Operation.' }
  if (roe.windowStart && now.getTime() < new Date(roe.windowStart).getTime()) {
    return { ok: false, reason: `Di luar jendela waktu RoE (mulai ${roe.windowStart}).` }
  }
  if (roe.windowEnd && now.getTime() > new Date(roe.windowEnd).getTime()) {
    return { ok: false, reason: `Di luar jendela waktu RoE (berakhir ${roe.windowEnd}).` }
  }
  if (!roe.allow[technique]) return { ok: false, reason: `Teknik "${technique}" tidak diizinkan oleh RoE "${roe.operation}".` }
  return { ok: true }
}

const validTime = (s: unknown): s is string => typeof s === 'string' && s !== '' && !Number.isNaN(new Date(s).getTime())

/** Validate an untrusted RoE (from IPC or disk). Returns null when unusable. */
export function sanitizeRoe(x: unknown): Roe | null {
  if (!x || typeof x !== 'object') return null
  const r = x as Record<string, unknown>
  const operation = typeof r.operation === 'string' ? r.operation.trim().slice(0, 120) : ''
  const operator = typeof r.operator === 'string' ? r.operator.trim().slice(0, 120) : ''
  if (!operation || !operator) return null
  const allow: Partial<Record<Technique, boolean>> = {}
  const rawAllow = (r.allow && typeof r.allow === 'object' ? r.allow : {}) as Record<string, unknown>
  for (const t of TECHNIQUES) allow[t.id] = rawAllow[t.id] === true
  const roe: Roe = { operation, operator, allow }
  if (validTime(r.windowStart)) roe.windowStart = r.windowStart
  if (validTime(r.windowEnd)) roe.windowEnd = r.windowEnd
  return roe
}
