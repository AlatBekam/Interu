import React, { useCallback, useEffect, useState } from 'react'
import { IconRefresh } from './icons'
import { Note } from './ui'
import { resetAuthNotice } from '../lib/http'

interface Status { lost: boolean; headerNames: string[] }

// Credentials for authenticated scanning: paste the headers of a session you already have
// (Authorization: Bearer ..., X-Api-Key: ..., or a Cookie line). They are kept in the main process
// only, are never saved, and are only sent to hosts in the Authorized scope.
export default function AuthBar() {
  const [headers, setHeaders] = useState('')
  const [status, setStatus] = useState<Status | null>(null)
  const [errors, setErrors] = useState<string[]>([])
  const bridge = typeof window !== 'undefined' ? window.ruy?.auth : undefined

  const poll = useCallback(() => { void bridge?.status().then(setStatus).catch(() => {}) }, [bridge])

  useEffect(() => { void bridge?.get().then((c) => setHeaders(c.headers)).catch(() => {}) }, [bridge])
  useEffect(() => {
    poll()
    const t = window.setInterval(poll, 2500)
    return () => window.clearInterval(t)
  }, [poll])

  if (!bridge) return null

  const apply = async (text: string): Promise<void> => {
    const r = await bridge.set({ headers: text })
    setErrors(r.errors)
    resetAuthNotice()
    poll()
  }
  const refresh = async (): Promise<void> => { await bridge.refresh(); resetAuthNotice(); poll() }

  return (
    <>
      <div className="intercept-bar">
        <strong>Authenticated scan</strong>
        <span className="small muted">Paste a token or header from your own session; it is sent only to hosts in scope.</span>
        {status && status.headerNames.length > 0 && (
          <span className="pill pill-info" title="Values are kept in memory only"><span className="pd" />{status.headerNames.join(', ')}</span>
        )}
        {status?.lost && <span className="pill pill-crit"><span className="pd" />session expired</span>}
        <div style={{ flex: 1 }} />
        <button className="btn btn-sm" onClick={() => void refresh()} title="Re-arm after pasting a fresh token"><IconRefresh size={14} />Refresh</button>
      </div>
      <label className="field" style={{ marginBottom: 12, display: 'block' }}>
        <span className="lab">Headers, one per line (kept in memory only, never saved)</span>
        <textarea
          className="code-pane"
          rows={2}
          style={{ minHeight: 56 }}
          spellCheck={false}
          placeholder={'Authorization: Bearer <token>\nCookie: JSESSIONID=<value>'}
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
          onBlur={() => void apply(headers)}
        />
      </label>
      {errors.length > 0 && <Note kind="error">{errors.join(' · ')}</Note>}
    </>
  )
}
