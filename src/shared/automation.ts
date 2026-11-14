import type { Finding } from './rules'

export interface AutomationOptions {
  target: string
  maxPages: number
  maxDepth: number
  maxRequests: number
  delayMs: number
  timeoutMs: number
  maxDurationMs: number
  activeChecks: boolean
  parameterChecks: boolean
  browserSeeds?: string[]
}
export const DEFAULT_AUTOMATION: AutomationOptions = {
  target: 'http://localhost:3000', maxPages: 40, maxDepth: 2, maxRequests: 1500,
  delayMs: 150, timeoutMs: 8000, maxDurationMs: 900000, activeChecks: true, parameterChecks: true
}
export type AutomationStatus = 'idle' | 'running' | 'completed' | 'cancelled' | 'limited' | 'failed'
export interface AutomationSnapshot {
  id: string
  target: string
  status: AutomationStatus
  phase: string
  requests: number
  pages: number
  errors: number
  startedAt?: string
  finishedAt?: string
  reason?: string
  options?: AutomationOptions
  findings: Finding[]
  log: string[]
}
const bounded = (v: unknown, fallback: number, min: number, max: number): number =>
  typeof v === 'number' && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.floor(v))) : fallback

export function normalizeAutomation(input: Partial<AutomationOptions>): AutomationOptions {
  const raw = String(input.target || '').trim()
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw)) throw new Error('Only HTTP(S) targets are supported')
  const u = new URL(/^https?:\/\//i.test(raw) ? raw : 'http://' + raw)
  if (!/^https?:$/.test(u.protocol) || u.username || u.password) throw new Error('Use an HTTP(S) target without embedded credentials')
  u.hash = ''
  return { target: u.href,
    maxPages: bounded(input.maxPages, 40, 1, 200), maxDepth: bounded(input.maxDepth, 2, 0, 5),
    maxRequests: bounded(input.maxRequests, 1500, 1, 3000), delayMs: bounded(input.delayMs, 150, 100, 10000),
    timeoutMs: bounded(input.timeoutMs, 8000, 500, 15000), maxDurationMs: bounded(input.maxDurationMs, 900000, 1000, 1800000),
    activeChecks: input.activeChecks === undefined ? DEFAULT_AUTOMATION.activeChecks : input.activeChecks === true,
    parameterChecks: input.parameterChecks === undefined ? DEFAULT_AUTOMATION.parameterChecks : input.parameterChecks === true,
    browserSeeds: Array.isArray(input.browserSeeds) ? input.browserSeeds.filter(url => {
      try { return new URL(url).origin === u.origin } catch { return false }
    }).slice(0, 20) : [] }
}
