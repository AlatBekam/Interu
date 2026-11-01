import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'

// =========================================================================
// Local persistence. Demo records and settings are stored in the renderer's
// localStorage so they survive application restarts. There is NO database
// server and NO network call — this is purely local to the app. Settings
// include a "persistence" switch and a full "reset demo environment" action,
// so the app always works even if the user turns persistence off or resets.
// =========================================================================

const NS = 'ruy.v1.'

export type ThemeName = 'dark' | 'light'

export interface Settings {
  theme: ThemeName
  persistence: boolean
  reduceMotion: boolean
  operatorName: string
  /** Hosts the operator is authorized to test. Live requests are gated to these. */
  scope: string[]
}

export const DEFAULT_SETTINGS: Settings = {
  theme: 'dark',
  persistence: true,
  reduceMotion: false,
  operatorName: 'Operator',
  scope: []
}

function persistenceOn(): boolean {
  try {
    const raw = window.localStorage.getItem(NS + 'settings')
    if (!raw) return DEFAULT_SETTINGS.persistence
    return (JSON.parse(raw) as Settings).persistence !== false
  } catch {
    return DEFAULT_SETTINGS.persistence
  }
}

function read<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(NS + key)
    if (raw == null) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

function write<T>(key: string, value: T): void {
  try {
    // The settings key itself must always persist so the toggle is sticky.
    if (key !== 'settings' && !persistenceOn()) return
    window.localStorage.setItem(NS + key, JSON.stringify(value))
  } catch {
    /* storage unavailable (private mode, blocked) — app still works in-memory */
  }
}

/** A persisted piece of state. Behaves like useState but is written to localStorage. */
export function usePersistentState<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [state, setState] = useState<T>(() => read<T>(key, initial))

  const set = useCallback(
    (v: T | ((p: T) => T)) => {
      setState((prev) => {
        const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v
        write(key, next)
        return next
      })
    },
    [key]
  )

  return [state, set]
}

// Settings are a single shared store so that every component (top-bar toggle,
// Settings page, the theme applier in App) stays in sync from one source.
let settingsState: Settings = { ...DEFAULT_SETTINGS, ...read<Settings>('settings', DEFAULT_SETTINGS) }
const settingsListeners = new Set<() => void>()

function subscribeSettings(cb: () => void): () => void {
  settingsListeners.add(cb)
  return () => settingsListeners.delete(cb)
}

export function patchSettings(p: Partial<Settings>): void {
  settingsState = { ...settingsState, ...p }
  write('settings', settingsState)
  settingsListeners.forEach((l) => l())
}

export function useSettings(): [Settings, (patch: Partial<Settings>) => void] {
  const settings = useSyncExternalStore(subscribeSettings, () => settingsState, () => settingsState)
  const patch = useCallback((p: Partial<Settings>) => patchSettings(p), [])
  return [settings, patch]
}

/** Remove every RUY key, restoring the pristine demo environment. */
export function resetDemoEnvironment(): void {
  try {
    const keys: string[] = []
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i)
      if (k && k.startsWith(NS)) keys.push(k)
    }
    keys.forEach((k) => window.localStorage.removeItem(k))
  } catch {
    /* ignore */
  }
}

/** React to a persisted boolean so the live-feed / motion settings apply app-wide. */
export function useBodyMotionFlag(reduceMotion: boolean): void {
  useEffect(() => {
    document.documentElement.dataset.reduceMotion = reduceMotion ? '1' : '0'
  }, [reduceMotion])
}

/** Apply the selected theme to <html data-theme="…"> for the whole app. */
export function useApplyTheme(theme: ThemeName): void {
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])
}
