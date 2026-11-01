import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../../components/TopBar'
import ScopeBar from '../../components/ScopeBar'
import { Panel, Disclaimer } from '../../components/ui'
import { IconForward, IconX, IconHistory, IconGlobe, IconPlay, IconStop } from '../../components/icons'
import { HTTP_HISTORY, rawRequest, rawResponse } from '../../data/burp'
import type { ProxyLogEntry, HeldRequest } from '../../../../shared/proxy'
import BrowserSim from './BrowserSim'
import ContextMenu, { CtxState } from '../../components/ContextMenu'
import CopyButton from '../../components/CopyButton'
import { setTransfer } from '../../store/transfer'
import { originOf, toCurl, rawFromParts } from '../../lib/http'
import { analyzeHttpResponse } from '../../../../shared/rules'
import { addFindings } from '../../store/findings'

type Tab = 'request' | 'response'

export default function Proxy() {
  const hasBridge = typeof window !== 'undefined' && !!window.ruy?.proxy
  const [port, setPort] = useState(8080)
  const [running, setRunning] = useState(false)
  const [intercept, setIntercept] = useState(false)
  const [logs, setLogs] = useState<ProxyLogEntry[]>([])
  const [held, setHeld] = useState<HeldRequest | null>(null)
  const [heldEdit, setHeldEdit] = useState('')
  const [sel, setSel] = useState<ProxyLogEntry | null>(null)
  const [tab, setTab] = useState<Tab>('request')
  const [showBrowser, setShowBrowser] = useState(false)
  const [browserUrl, setBrowserUrl] = useState('http://example.com/')
  const [caNote, setCaNote] = useState('')
  const [menu, setMenu] = useState<CtxState | null>(null)
  const busy = useRef(false)
  const heldRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  // Bring the held-request panel into view the moment a request is intercepted.
  useEffect(() => {
    if (held) heldRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [held])

  const rowMenu = (e: React.MouseEvent, t: ProxyLogEntry): void => {
    e.preventDefault()
    const target = originOf(t.url)
    const raw = t.request || rawFromParts(t.method, t.host, t.path || '/')
    setMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        { label: '➤  Send to Repeater', onClick: () => { setTransfer({ to: 'repeater', target, raw, mode: 'live' }); navigate('/web/repeater') } },
        { label: '➤  Send to Intruder', onClick: () => { setTransfer({ to: 'intruder', target, raw, mode: 'live' }); navigate('/web/intruder') } },
        { sep: true },
        { label: 'Copy URL', onClick: () => navigator.clipboard?.writeText(t.url) },
        { label: 'Copy request', onClick: () => navigator.clipboard?.writeText(raw) },
        { label: 'Copy response', onClick: () => t.response && navigator.clipboard?.writeText(t.response) },
        { label: 'Copy as curl', onClick: () => navigator.clipboard?.writeText(toCurl(raw, target)) },
        { sep: true },
        { label: 'Inspect', onClick: () => { setSel(t); setTab('request') } }
      ]
    })
  }

  useEffect(() => {
    if (!hasBridge) return
    const offLog = window.ruy.proxy.onLog((d) => {
      const e = d as ProxyLogEntry
      setLogs((prev) => [e, ...prev].slice(0, 500))
      // Passive detection: feed each captured response to the Rule Engine.
      if (e.response) addFindings(analyzeHttpResponse(e))
    })
    const offInt = window.ruy.proxy.onIntercept((d) => {
      const h = d as HeldRequest
      setHeld(h)
      setHeldEdit(h.raw)
    })
    window.ruy.proxy.status().then((s) => setRunning(s.running)).catch(() => {})
    return () => { offLog(); offInt() }
  }, [hasBridge])

  const toggleProxy = async () => {
    if (busy.current || !hasBridge) return
    busy.current = true
    try {
      if (running) { await window.ruy.proxy.stop(); setRunning(false); setHeld(null) }
      else { const r = await window.ruy.proxy.start(port); setRunning(!!r.ok); if (!r.ok) alert('Gagal start proxy: ' + (r.error || 'unknown')) }
    } finally { busy.current = false }
  }

  const toggleIntercept = async () => {
    const next = !intercept
    setIntercept(next)
    if (hasBridge) await window.ruy.proxy.setIntercept(next)
    if (!next) setHeld(null)
  }

  const openBrowser = async () => {
    if (!hasBridge) return
    if (!running) { alert('Start the proxy first.'); return }
    const r = await window.ruy.proxy.openBrowser(browserUrl)
    if (!r.ok) alert('Gagal buka browser: ' + (r.error || 'unknown'))
  }

  const exportCA = async () => {
    if (!hasBridge) return
    const r = await window.ruy.proxy.exportCA()
    setCaNote(r.ok ? `✓ Root CA diekspor ke: ${r.path} — import & trust di OS/browser untuk dekripsi https di browser eksternal.` : `⚠ ${r.error}`)
  }

  const removeCA = async () => {
    if (!hasBridge) return
    if (!window.confirm('Hapus root CA Interu (cert + private key terenkripsi)? Browser/OS yang sudah mem-trust CA lama tidak akan mempercayai CA baru sampai di-export & di-trust ulang.')) return
    const r = await window.ruy.proxy.removeCA()
    setCaNote(r.ok ? '✓ Root CA dihapus. CA baru dibuat otomatis saat dipakai lagi — export & trust ulang bila perlu.' : `⚠ ${r.error}`)
  }

  const forward = async () => {
    if (!held) return
    await window.ruy.proxy.resolve(held.id, 'forward', heldEdit !== held.raw ? heldEdit : undefined)
    setHeld(null)
  }
  const drop = async () => {
    if (!held) return
    await window.ruy.proxy.resolve(held.id, 'drop')
    setHeld(null)
  }

  const loadSample = () => {
    const sample: ProxyLogEntry[] = HTTP_HISTORY.map((t) => ({
      id: t.id, time: t.time, method: t.method, host: t.host, path: t.path, url: `http://${t.host}${t.path}`,
      status: t.status, length: t.length, ms: 20, kind: 'http',
      request: rawRequest(t), response: rawResponse(t)
    }))
    setLogs(sample)
  }

  return (
    <>
      <TopBar title="Proxy" sub="Intercepting forward proxy" />
      <div className="content page">
        <Disclaimer>
          <strong>Real intercepting proxy with HTTPS MITM.</strong> Start it, then hit <strong>Open Browser</strong>
          (routes through the proxy & trusts the Interu CA automatically) — both http and https traffic are
          decrypted and captured. For an external browser, use <strong>Export CA</strong> and trust it. Only hosts
          in the <strong>Authorized scope</strong> are decrypted and captured; everything else passes through untouched.
        </Disclaimer>

        <div className="mt-16"><ScopeBar /></div>

        <div className="intercept-bar mt-16">
          <span className={`status-dot ${running ? 'on' : 'off'}`} />
          <strong style={{ fontSize: 13 }}>Proxy {running ? 'running' : 'stopped'}</strong>
          {running && <span className="pill pill-info mono"><span className="pd" />127.0.0.1:{port}</span>}
          {!running && (
            <input type="number" value={port} onChange={(e) => setPort(Number(e.target.value) || 8080)} style={{ width: 90 }} className="mono" />
          )}
          {running ? (
            <button className="btn btn-danger btn-sm" onClick={toggleProxy}><IconStop />Stop</button>
          ) : (
            <button className="btn btn-primary btn-sm" onClick={toggleProxy} disabled={!hasBridge}><IconPlay />Start</button>
          )}
          <div style={{ flex: 1 }} />
          <span className={`status-dot ${intercept ? 'on' : 'off'}`} />
          <span className="small">Intercept {intercept ? 'on' : 'off'}</span>
          <button className="btn btn-sm" onClick={toggleIntercept} disabled={!running}>{intercept ? 'Turn off' : 'Turn on'}</button>
        </div>

        <div className="intercept-bar" style={{ marginTop: -2, marginBottom: 14 }}>
          <IconGlobe size={16} />
          <strong style={{ fontSize: 12.5 }}>Browser</strong>
          <input type="text" value={browserUrl} onChange={(e) => setBrowserUrl(e.target.value)} placeholder="http://target/" className="mono" style={{ flex: 1, minWidth: 220 }} />
          <button className="btn btn-primary btn-sm" onClick={openBrowser} disabled={!running} title="Open a real browser routed through the proxy"><IconGlobe />Open Browser</button>
          <button className="btn btn-sm" onClick={exportCA} disabled={!hasBridge} title="Export the Interu root CA for external browsers">Export CA</button>
          <button className="btn btn-sm btn-danger" onClick={removeCA} disabled={!hasBridge} title="Delete the stored root CA (encrypted key + cert)">Remove CA</button>
          <button className="btn btn-ghost btn-sm" onClick={() => setShowBrowser((v) => !v)} title="Offline simulated browser">{showBrowser ? 'Close Demo' : 'Demo (offline)'}</button>
        </div>
        {caNote && <div className="disclaimer" style={{ background: 'rgba(79,178,134,0.06)', borderColor: 'rgba(79,178,134,0.25)' }}><div className="small">{caNote}</div></div>}

        {!hasBridge && <div className="disclaimer"><div>HTTP bridge tidak tersedia (jalankan dari aplikasi desktop, bukan browser biasa).</div></div>}

        {showBrowser && <div className="mb-24"><BrowserSim onClose={() => setShowBrowser(false)} /></div>}

        {held && (
          <div ref={heldRef}>
            <Panel title="⏸ Intercepted Request — held" sub={`${held.method} ${held.host}${held.path} · edit then Forward to let it through`} className="mb-24"
              right={<div className="flex gap-8"><button className="btn btn-primary btn-sm" onClick={forward}><IconForward />Forward</button><button className="btn btn-danger btn-sm" onClick={drop}><IconX />Drop</button></div>}>
              <textarea className="code-pane" value={heldEdit} onChange={(e) => setHeldEdit(e.target.value)} style={{ minHeight: 200 }} spellCheck={false} />
            </Panel>
          </div>
        )}

        <Panel
          title="HTTP History"
          sub={`${logs.length} captured · right-click a row for actions`}
          right={
            <div className="flex gap-8">
              <button className="btn btn-ghost btn-sm" onClick={loadSample} title="Load offline sample data">Load sample</button>
              <button className="btn btn-ghost btn-sm" onClick={() => setLogs([])}>Clear</button>
            </div>
          }
        >
          {logs.length === 0 ? (
            <div className="empty">
              {running
                ? `Proxy live at 127.0.0.1:${port}. Set your browser proxy here and browse an http:// target to capture traffic — or click “Load sample”.`
                : 'Start the proxy and route traffic through it, or click “Load sample” for offline demo data.'}
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>#</th><th>Time</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Length</th></tr></thead>
                <tbody>
                  {logs.map((t) => (
                    <tr key={t.id} onClick={() => { setSel(t); setTab('request') }} onContextMenu={(e) => rowMenu(e, t)} style={{ cursor: 'pointer', background: sel?.id === t.id ? 'rgba(47,102,196,0.08)' : undefined }}>
                      <td className="mono">{t.id}</td>
                      <td className="mono small">{t.time}</td>
                      <td><span className={`method ${t.method}`}>{t.method}</span></td>
                      <td className="mono small">{t.host}</td>
                      <td className="mono small">{t.path || <span className="muted">— tunnel —</span>}{t.dropped && <span className="pill pill-crit" style={{ marginLeft: 8 }}><span className="pd" />dropped</span>}</td>
                      <td>{t.status != null ? <span className={`sc s${String(t.status)[0] || '2'}`}>{t.status || '—'}</span> : <span className="muted">—</span>}</td>
                      <td className="mono small">{t.length ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {sel && (sel.request || sel.response) && (
          <Panel title="Inspector" sub={`${sel.method} ${sel.path}`} className="mt-24" right={<IconHistory />}>
            <div className="tabs">
              <button className={`tab ${tab === 'request' ? 'active' : ''}`} onClick={() => setTab('request')}>Request</button>
              <button className={`tab ${tab === 'response' ? 'active' : ''}`} onClick={() => setTab('response')}>Response</button>
            </div>
            <div style={{ paddingTop: 14 }}>
              <div className="code-head">
                <span>{tab}</span>
                <CopyButton text={tab === 'request' ? (sel.request || '') : (sel.response || '')} label={`Copy ${tab}`} />
              </div>
              <div className="code-pane">{tab === 'request' ? (sel.request || '(not captured)') : (sel.response || '(not captured)')}</div>
            </div>
          </Panel>
        )}

        {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      </div>
    </>
  )
}
