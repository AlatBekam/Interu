import React, { useState } from 'react'
import { IconForward, IconRefresh, IconX, IconGlobe } from '../../components/icons'

// A SIMULATED pre-proxied browser, mirroring Burp Suite's embedded Chromium
// "Open browser" button. It renders canned local demo pages — it does NOT make
// real network requests. In the later development stage this component is the
// natural place to launch a real Chromium bound to the proxy, for authorized
// targets only.

interface Page {
  title: string
  render: (go: (p: string) => void) => React.ReactNode
}

const HOST = 'http://demo.ruy.local'

const PAGES: Record<string, Page> = {
  '/': {
    title: 'RUY Demo',
    render: (go) => (
      <div style={{ padding: 28, fontFamily: 'system-ui' }}>
        <h2 style={{ margin: 0 }}>RUY Demo Application</h2>
        <p style={{ color: '#5a6477', marginTop: 8 }}>A fabricated target used only for the simulated proxy demo.</p>
        <div style={{ display: 'flex', gap: 10, marginTop: 18, flexWrap: 'wrap' }}>
          <button className="btn btn-primary btn-sm" onClick={() => go('/login')}>Sign in</button>
          <button className="btn btn-sm" onClick={() => go('/orders')}>My orders</button>
          <button className="btn btn-sm" onClick={() => go('/admin')}>Admin</button>
        </div>
      </div>
    )
  },
  '/login': {
    title: 'Sign in',
    render: (go) => (
      <div style={{ padding: 28, maxWidth: 320, fontFamily: 'system-ui' }}>
        <h3 style={{ marginTop: 0 }}>Sign in</h3>
        <label className="field" style={{ marginBottom: 10 }}><span className="lab">Username</span><input defaultValue="demo" /></label>
        <label className="field" style={{ marginBottom: 14 }}><span className="lab">Password</span><input type="text" defaultValue="S1mul@ted!" /></label>
        <button className="btn btn-primary btn-sm" onClick={() => go('/orders')}>Log in (simulated)</button>
      </div>
    )
  },
  '/orders': {
    title: 'Orders',
    render: () => (
      <div style={{ padding: 28, fontFamily: 'system-ui' }}>
        <h3 style={{ marginTop: 0 }}>Your orders</h3>
        <table className="data"><thead><tr><th>Order</th><th>Items</th><th>Total</th></tr></thead>
          <tbody>
            <tr><td className="mono">#1001</td><td>3</td><td>$149.00</td></tr>
            <tr><td className="mono">#1004</td><td>1</td><td>$29.00</td></tr>
          </tbody></table>
      </div>
    )
  },
  '/admin': {
    title: 'Forbidden',
    render: () => (
      <div style={{ padding: 28, fontFamily: 'system-ui' }}>
        <h3 style={{ marginTop: 0, color: '#d6594f' }}>401 Unauthorized</h3>
        <p className="muted">Admin area requires elevated role (simulated response).</p>
      </div>
    )
  }
}

export default function BrowserSim({ onClose, onNavigate }: { onClose: () => void; onNavigate?: (path: string) => void }) {
  const [history, setHistory] = useState<string[]>(['/'])
  const [idx, setIdx] = useState(0)
  const [addr, setAddr] = useState(HOST + '/')

  const path = history[idx]
  const page = PAGES[path] ?? PAGES['/']

  const go = (p: string) => {
    const next = history.slice(0, idx + 1).concat(p)
    setHistory(next)
    setIdx(next.length - 1)
    setAddr(HOST + p)
    onNavigate?.(p)
  }
  const navTo = (raw: string) => {
    const p = raw.replace(HOST, '').replace(/^https?:\/\/[^/]+/, '') || '/'
    go(p.startsWith('/') ? p : '/' + p)
  }
  const back = () => { if (idx > 0) { setIdx(idx - 1); setAddr(HOST + history[idx - 1]) } }
  const fwd = () => { if (idx < history.length - 1) { setIdx(idx + 1); setAddr(HOST + history[idx + 1]) } }

  return (
    <section className="panel" style={{ overflow: 'hidden' }}>
      <div className="panel-head" style={{ gap: 8 }}>
        <button className="btn btn-ghost btn-sm" onClick={back} disabled={idx === 0} title="Back" style={{ transform: 'scaleX(-1)' }}><IconForward size={14} /></button>
        <button className="btn btn-ghost btn-sm" onClick={fwd} disabled={idx >= history.length - 1} title="Forward"><IconForward size={14} /></button>
        <button className="btn btn-ghost btn-sm" onClick={() => go(path)} title="Reload"><IconRefresh size={14} /></button>
        <input
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') navTo(addr) }}
          className="mono"
          style={{ flex: 1 }}
        />
        <span className="pill pill-info" title="Traffic is routed through the simulated RUY proxy"><IconGlobe size={12} /> via proxy (sim)</span>
        <button className="btn btn-danger btn-sm" onClick={onClose}><IconX size={14} />Close</button>
      </div>
      <div style={{ background: 'var(--obsidian-800)', minHeight: 260, borderTop: '1px solid var(--line-soft)' }}>
        {page.render(go)}
      </div>
      <div className="panel-body" style={{ paddingTop: 10, paddingBottom: 12 }}>
        <div className="small muted">
          Embedded browser is <strong>simulated</strong> and offline. Each navigation is logged to the proxy
          history. In the development stage this launches a real proxied Chromium for authorized testing.
        </div>
      </div>
    </section>
  )
}
