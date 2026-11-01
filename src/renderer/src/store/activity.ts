import { useSyncExternalStore } from 'react'
import type { ActivityDraft, ActivityEvent } from '../../../shared/activity'

// In-memory feed of what Interu observed this session. Deliberately not
// persisted: a restart starts empty, which is the honest state for real activity.
const MAX_EVENTS = 200

let state: ActivityEvent[] = []
let seq = 0
const listeners = new Set<() => void>()

function emit(): void {
  listeners.forEach((l) => l())
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

export function pushActivity(d: ActivityDraft): void {
  seq++
  state = [{ ...d, id: `${Date.now()}-${seq}` }, ...state].slice(0, MAX_EVENTS)
  emit()
}

export function getActivity(): ActivityEvent[] {
  return state
}

export function clearActivity(): void {
  state = []
  emit()
}

/** Record that a feature refused a target because it is outside the authorized scope. */
export function noteScopeBlock(target: string, via: string): void {
  pushActivity({
    ts: new Date().toISOString(),
    level: 'warn',
    category: 'scope',
    message: `Blocked by scope: ${target} (${via})`,
    target
  })
}

export function useActivity(): ActivityEvent[] {
  return useSyncExternalStore(subscribe, () => state, () => state)
}
