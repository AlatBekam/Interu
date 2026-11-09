import React, { useState } from 'react'
import { IconPlus, IconX, IconLock } from './icons'
import { useSettings } from '../store/store'
import AuthBar from './AuthBar'

// Authorization scope editor. Live requests are only permitted to hosts listed
// here — "legal-by-design". Shared across live modules via the settings store.
export default function ScopeBar({ withAuth = false }: { withAuth?: boolean }) {
  const [settings, patch] = useSettings()
  const [val, setVal] = useState('')

  const add = () => {
    const cleaned = val.trim().toLowerCase().replace(/^https?:\/\//, '')
    // Preserve IPv4 CIDR masks (e.g. 10.20.0.0/24) for the scanner; strip URL paths otherwise.
    const h = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(cleaned) ? cleaned : cleaned.replace(/\/.*$/, '')
    if (!h || settings.scope.includes(h)) return
    patch({ scope: [...settings.scope, h] })
    setVal('')
  }
  const remove = (h: string) => patch({ scope: settings.scope.filter((x) => x !== h) })

  return (
    <>
    <div className="intercept-bar">
      <IconLock size={16} />
      <strong>Authorized scope</strong>
      <div className="flex gap-8 wrap" style={{ flex: 1 }}>
        {settings.scope.length === 0 ? (
          <span className="small muted">empty — no live target allowed until you add a host you own/are authorized to test</span>
        ) : (
          settings.scope.map((h) => (
            <span key={h} className="pill pill-ok" title="Authorized host">
              <span className="pd" />{h}
              <span role="button" tabIndex={0} aria-label={`Remove ${h}`} className="pill-x" title="Remove" onClick={() => remove(h)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); remove(h) } }}><IconX size={11} /></span>
            </span>
          ))
        )}
      </div>
      <input
        type="text"
        value={val}
        onChange={(e) => setVal(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') add() }}
        placeholder="host.example.com / 10.0.0.0/24"
        style={{ width: 220 }}
      />
      <button className="btn btn-sm" onClick={add}><IconPlus size={14} />Add</button>
    </div>
    {withAuth && <AuthBar />}
    </>
  )
}
