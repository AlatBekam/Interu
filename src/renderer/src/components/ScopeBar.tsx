import React, { useState } from 'react'
import { IconPlus, IconX, IconLock } from './icons'
import { useSettings } from '../store/store'

// Authorization scope editor. Live requests are only permitted to hosts listed
// here — "legal-by-design". Shared across live modules via the settings store.
export default function ScopeBar() {
  const [settings, patch] = useSettings()
  const [val, setVal] = useState('')

  const add = () => {
    const h = val.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!h || settings.scope.includes(h)) return
    patch({ scope: [...settings.scope, h] })
    setVal('')
  }
  const remove = (h: string) => patch({ scope: settings.scope.filter((x) => x !== h) })

  return (
    <div className="intercept-bar" style={{ marginBottom: 14 }}>
      <IconLock size={16} />
      <strong style={{ fontSize: 12.5 }}>Authorized scope</strong>
      <div className="flex gap-8 wrap" style={{ flex: 1 }}>
        {settings.scope.length === 0 ? (
          <span className="small muted">empty — no live target allowed until you add a host you own/are authorized to test</span>
        ) : (
          settings.scope.map((h) => (
            <span key={h} className="pill pill-ok" title="Authorized host">
              <span className="pd" />{h}
              <span onClick={() => remove(h)} style={{ cursor: 'pointer', marginLeft: 4, opacity: 0.7 }} title="Remove"><IconX size={11} /></span>
            </span>
          ))
        )}
      </div>
      <input
        type="text"
        value={val}
        onChange={(e) => setVal(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') add() }}
        placeholder="host.example.com"
        style={{ width: 200 }}
      />
      <button className="btn btn-sm" onClick={add}><IconPlus size={14} />Add</button>
    </div>
  )
}
