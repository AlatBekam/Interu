import React, { useCallback, useEffect, useState } from 'react'
import { IconRefresh } from './icons'
import { Note } from './ui'
import { useSettings } from '../store/store'
import { resetAuthNotice } from '../lib/http'
import type { AuthConfig } from '../../../shared/auth'

interface Status { lost: boolean; cookies: boolean; headerNames: string[]; cookieCounts: Record<string, number> }

// Credentials for authenticated scanning. Two sources: the cookies of the Interu Browser session
// (log in there, scans reuse it) and headers typed by hand. Values stay in the main process.
export default function AuthBar() {
  const [settings] = useSettings()
  const [cfg, setCfg] = useState<AuthConfig>({ cookies: false, headers: '' })
  const [status, setStatus] = useState<Status | null>(null)
  const [errors, setErrors] = useState<string[]>([])
  const [showHeaders, setShowHeaders] = useState(false)
  const bridge = typeof window !== 'undefined' ? window.ruy?.auth : undefined

  const poll = useCallback(() => { void bridge?.status(settings.scope).then(setStatus).catch(() => {}) }, [bridge, settings.scope])

  useEffect(() => {
    void bridge?.get().then((c) => { setCfg(c); setShowHeaders(!!c.headers) }).catch(() => {})
  }, [bridge])
  useEffect(() => {
    poll()
    const t = window.setInterval(poll, 2500) // cookie counts change while the operator logs in
    return () => window.clearInterval(t)
  }, [poll])

  if (!bridge) return null

  const apply = async (next: AuthConfig): Promise<void> => {
    setCfg(next)
    const r = await bridge.set(next)
    setErrors(r.errors)
    resetAuthNotice()
    poll()
  }
  const refresh = async (): Promise<void> => { await bridge.refresh(); resetAuthNotice(); poll() }

  const total = status ? Object.values(status.cookieCounts).reduce((a, b) => a + b, 0) : 0

  return (
    <>
      <div className="intercept-bar">
        <strong>Authenticated scan</strong>
        <label className="flex items-center gap-8" style={{ cursor: 'pointer' }}>
          <span className="switch">
            <input type="checkbox" checked={cfg.cookies} onChange={(e) => void apply({ ...cfg, cookies: e.target.checked })} aria-label="Use Interu Browser cookies" />
            <span className="track" />
          </span>
          <span className="small">Use Interu Browser cookies</span>
        </label>
        {cfg.cookies && (total > 0
          ? <span className="pill pill-ok"><span className="pd" />{total} cookie{total === 1 ? '' : 's'} for scope</span>
          : <span className="pill pill-warn" title="Open Proxy, then Open Browser, and log in to a host in scope"><span className="pd" />no cookies for scope yet</span>)}
        {status && status.headerNames.length > 0 && (
          <span className="pill pill-info" title="Values are kept in memory only"><span className="pd" />{status.headerNames.join(', ')}</span>
        )}
        {status?.lost && <span className="pill pill-crit"><span className="pd" />session expired</span>}
        <div style={{ flex: 1 }} />
        <button className="btn btn-sm" onClick={() => setShowHeaders((v) => !v)} aria-expanded={showHeaders}>Headers</button>
        <button className="btn btn-sm" onClick={() => void refresh()} title="Re-arm after logging in again"><IconRefresh size={14} />Refresh</button>
      </div>
      {showHeaders && (
        <label className="field" style={{ marginBottom: 12, display: 'block' }}>
          <span className="lab">Extra headers, one per line (kept in memory only, never saved)</span>
          <textarea
            className="code-pane"
            rows={3}
            style={{ minHeight: 64 }}
            spellCheck={false}
            placeholder={'Authorization: Bearer <token>\nX-Api-Key: <key>'}
            value={cfg.headers}
            onChange={(e) => setCfg({ ...cfg, headers: e.target.value })}
            onBlur={() => void apply(cfg)}
          />
        </label>
      )}
      {errors.length > 0 && <Note kind="error">{errors.join(' · ')}</Note>}
    </>
  )
}
