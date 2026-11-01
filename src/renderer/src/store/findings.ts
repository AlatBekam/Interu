import { useSyncExternalStore } from 'react'
import type { Finding } from '../../../shared/rules'
import { sortFindings, correlate } from '../../../shared/rules'

// =========================================================================
// Shared Rule-Engine findings store. The Network Scanner and Proxy WRITE
// findings here; the Rule Engine and Vulnerabilities pages READ them. Kept in
// one external store (like settings) so every page sees the same list, and
// persisted to localStorage so findings survive a restart. De-duplicated by
// each finding's stable `key`.
// =========================================================================

const NS = 'ruy.v1.'
const KEY = NS + 'findings'
const MAX_FINDINGS = 1000

function persistenceOn(): boolean {
  try {
    const raw = window.localStorage.getItem(NS + 'settings')
    if (!raw) return true
    return (JSON.parse(raw) as { persistence?: boolean }).persistence !== false
  } catch {
    return true
  }
}

function load(): Finding[] {
  try {
    if (!persistenceOn()) return []
    const raw = window.localStorage.getItem(KEY)
    if (!raw) return []
    const arr = JSON.parse(raw) as Finding[]
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

function save(list: Finding[]): void {
  try {
    // Persistence off: also drop anything stored earlier, so Clear really clears.
    if (!persistenceOn()) return window.localStorage.removeItem(KEY)
    window.localStorage.setItem(KEY, JSON.stringify(list))
  } catch {
    /* storage unavailable — keep working in memory */
  }
}

let state: Finding[] = load()
const listeners = new Set<() => void>()

function emit(): void {
  listeners.forEach((l) => l())
}

/** Merge new findings in, replacing any with the same key (fresh evidence wins). */
export function addFindings(incoming: Finding[]): number {
  if (!incoming || incoming.length === 0) return 0
  const byKey = new Map(state.map((f) => [f.key, f]))
  let added = 0
  for (const f of incoming) {
    if (!byKey.has(f.key)) added++
    byKey.set(f.key, f)
  }
  // Correlate (oracle-confirmed supersedes suspected for the same issue), then
  // keep the most severe MAX_FINDINGS so heavy proxy traffic can't grow unbounded.
  state = sortFindings(correlate(Array.from(byKey.values()))).slice(0, MAX_FINDINGS)
  save(state)
  emit()
  return added
}

export function clearFindings(): void {
  state = []
  save(state)
  emit()
}

/** Remove a single finding by key (e.g. after a Re-test proves it resolved). */
export function removeFinding(key: string): void {
  const next = state.filter((f) => f.key !== key)
  if (next.length === state.length) return
  state = next
  save(state)
  emit()
}

export function getFindings(): Finding[] {
  return state
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

export function useFindings(): Finding[] {
  return useSyncExternalStore(subscribe, () => state, () => state)
}

/** Handy counters for dashboards / headers. */
export function useFindingCounts(): { total: number; confirmed: number; suspected: number } {
  const list = useFindings()
  return {
    total: list.length,
    confirmed: list.filter((f) => f.confidence === 'confirmed').length,
    suspected: list.filter((f) => f.confidence === 'suspected').length
  }
}
