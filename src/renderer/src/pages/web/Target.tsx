import React, { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Stat, Meter } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconTarget, IconGlobe, IconPlay, IconStop } from '../../components/icons'
import { SITE_MAP, HTTP_HISTORY, rawRequest, rawResponse, HttpTx } from '../../data/burp'
import { sendLive, rawFromParts } from '../../lib/http'
import { hostInScope } from '../../../../shared/http'
import { useSettings } from '../../store/store'
import { setTransfer } from '../../store/transfer'
import ContextMenu, { CtxState } from '../../components/ContextMenu'

type Mode = 'sim' | 'live'

const WORDLIST = [
  '/', '/admin', '/login', '/dashboard', '/api', '/api/users', '/api/login', '/robots.txt',
  '/.env', '/.git/HEAD', '/backup.zip', '/config.php', '/server-status', '/uploads', '/static',
  '/debug', '/phpinfo.php', '/wp-login.php', '/.well-known/security.txt', '/sitemap.xml'
]

interface Hit { path: string; status: number | string; length: number; ms: number; raw?: string }

export default function Target() {
  const [settings] = useSettings()
  const [mode, setMode] = useState<Mode>('sim')
  const [target, setTarget] = useState('http://localhost:3000')
  const [sel, setSel] = useState<string>('/api/login')
  const [hits, setHits] = useState<Hit[]>([])
  const [selHit, setSelHit] = useState<Hit | null>(null)
  const [progress, setProgress] = useState(0)
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState('')
  const [menu, setMenu] = useState<CtxState | null>(null)
  const stopFlag = useRef(false)
  const navigate = useNavigate()

  const tx: HttpTx | undefined = HTTP_HISTORY.find((t) => t.path.startsWith(sel) && sel !== '/') ?? HTTP_HISTORY[0]

  const sendMenu = (e: React.MouseEvent, target: string, raw: string, mode: 'sim' | 'live'): void => {
    e.preventDefault()
    setMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: '➤  Send to Repeater', onClick: () => { setTransfer({ to: 'repeater', target, raw, mode }); navigate('/web/repeater') } },
        { label: '➤  Send to Intruder', onClick: () => { setTransfer({ to: 'intruder', target, raw, mode }); navigate('/web/intruder') } },
        { sep: true },
        { label: 'Copy URL', onClick: () => navigator.clipboard?.writeText(target + raw.split(' ')[1]) }
      ]
    })
  }

  const liveHost = (() => { try { return new URL(target).host } catch { return 'target' } })()

  const discover = async () => {
    const base = target.replace(/\/+$/, '')
    if (!hostInScope(base + '/', settings.scope)) {
      setNote(`⛔ ${(() => { try { return new URL(base).hostname } catch { return 'target' } })()} belum ada di Authorized scope.`)
      return
    }
    setHits([]); setSelHit(null); setProgress(0); setRunning(true); setNote(''); stopFlag.current = false
    for (let i = 0; i < WORDLIST.length; i++) {
      if (stopFlag.current) break
      const path = WORDLIST[i]
      const res = await sendLive({ method: 'GET', url: base + path, headers: { 'User-Agent': 'Interu/1.0' } }, settings.scope)
      if (res.ok && res.status !== 404) {
        setHits((h) => [...h, { path, status: res.status ?? 0, length: res.size, ms: res.timingMs, raw: res.raw }])
      }
      setProgress(Math.round(((i + 1) / WORDLIST.length) * 100))
    }
    setRunning(false)
  }

  return (
    <>
      <TopBar title="Target · Site Map" sub={mode === 'live' ? 'Live content discovery' : 'Simulated attack surface'} />
      <div className="content page">
        {mode === 'live' ? (
          <Disclaimer>
            <strong>Live content discovery</strong> sends real GET requests for a wordlist of common paths, only to
            hosts in your authorized scope. Found paths build a real map. Use on permitted systems only.
          </Disclaimer>
        ) : (
          <Disclaimer>
            <strong>Simulated site map.</strong> Fabricated demo data — nothing is crawled. Switch to Live to
            enumerate a real authorized target.
          </Disclaimer>
        )}

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <div className="theme-toggle">
            <button className={mode === 'sim' ? 'on' : ''} onClick={() => setMode('sim')}>Simulation</button>
            <button className={mode === 'live' ? 'on' : ''} onClick={() => setMode('live')}>Live</button>
          </div>
          {mode === 'live' && (
            <>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" style={{ flex: 1, minWidth: 240 }} />
              {!running ? (
                <button className="btn btn-primary" onClick={discover}><IconPlay />Discover</button>
              ) : (
                <button className="btn btn-danger" onClick={() => { stopFlag.current = true; setRunning(false) }}><IconStop />Stop</button>
              )}
            </>
          )}
        </div>

        {mode === 'live' && <ScopeBar />}
        {note && <div className="disclaimer" style={{ borderColor: 'rgba(214,89,79,0.3)', background: 'rgba(214,89,79,0.06)' }}><div>{note}</div></div>}

        {mode === 'sim' ? (
          <>
            <div className="grid grid-4 mt-16">
              <Stat label="In Scope" value="1 host" meta="demo.ruy.local" icon={<IconTarget />} />
              <Stat label="Endpoints" value={SITE_MAP.filter((n) => n.kind === 'leaf').length} meta="discovered" />
              <Stat label="Requests Logged" value={HTTP_HISTORY.length} icon={<IconGlobe />} />
              <Stat label="Interesting" value={HTTP_HISTORY.filter((t) => t.flagged).length} meta="flagged" />
            </div>
            <div className="split mt-24">
              <Panel title="Site Map" sub="demo.ruy.local · right-click an item">
                <div className="sitemap">
                  {SITE_MAP.map((n) => (
                    <div
                      key={n.path}
                      className={`node depth${n.depth} ${sel === n.path ? 'sel' : ''}`}
                      onClick={() => setSel(n.path)}
                      onContextMenu={(e) => {
                        const stx = HTTP_HISTORY.find((t) => t.path === n.path)
                        const raw = stx ? rawRequest(stx) : rawFromParts(n.method || 'GET', 'demo.ruy.local', n.path.startsWith('/') ? n.path : '/')
                        sendMenu(e, 'http://demo.ruy.local', raw, 'sim')
                      }}
                    >
                      <span style={{ opacity: 0.6 }}>{n.kind === 'dir' ? '▸' : '•'}</span>
                      <span>{n.depth === 0 ? n.path : n.path.split('/').filter(Boolean).pop() || '/'}</span>
                      {n.method && <span className={`method ${n.method}`} style={{ marginLeft: 'auto' }}>{n.method}</span>}
                      {n.status && <span className={`sc s${String(n.status)[0]}`}>{n.status}</span>}
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel title="Selected Item" sub={tx ? `${tx.method} ${tx.path}` : 'none'}>
                {tx && (
                  <div className="split" style={{ gridTemplateColumns: '1fr' }}>
                    <div><div className="code-head">Request</div><div className="code-pane" style={{ minHeight: 150, maxHeight: 190 }}>{rawRequest(tx)}</div></div>
                    <div><div className="code-head">Response</div><div className="code-pane" style={{ minHeight: 150, maxHeight: 190 }}>{rawResponse(tx)}</div></div>
                  </div>
                )}
              </Panel>
            </div>
          </>
        ) : (
          <>
            {(running || hits.length > 0) && <div className="mb-16 mt-16"><Meter value={progress} tone={progress === 100 ? 'ok' : undefined} /></div>}
            <div className="split">
              <Panel title="Discovered Paths" sub={`${hits.length} found · right-click to send`}>
                {hits.length === 0 ? (
                  <div className="empty">{running ? 'Enumerating…' : 'Press Discover to enumerate an authorized target.'}</div>
                ) : (
                  <div className="table-wrap">
                    <table className="data">
                      <thead><tr><th>Path</th><th>Status</th><th>Length</th><th>Time</th></tr></thead>
                      <tbody>
                        {hits.map((h) => (
                          <tr
                            key={h.path}
                            onClick={() => setSelHit(h)}
                            onContextMenu={(e) => sendMenu(e, target.replace(/\/+$/, ''), rawFromParts('GET', liveHost, h.path), 'live')}
                            style={{ cursor: 'pointer', background: selHit?.path === h.path ? 'rgba(47,102,196,0.08)' : undefined }}
                          >
                            <td className="mono small">{h.path}</td>
                            <td><span className={`sc s${String(h.status)[0]}`}>{h.status}</span></td>
                            <td className="mono">{h.length}</td>
                            <td className="mono small">{h.ms} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
              <Panel title="Response" sub={selHit ? `GET ${selHit.path}` : 'select a path'}>
                {selHit?.raw ? <div className="code-pane" style={{ minHeight: 300 }}>{selHit.raw}</div> : <div className="empty" style={{ minHeight: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Select a discovered path to view its real response.</div>}
              </Panel>
            </div>
          </>
        )}

        {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      </div>
    </>
  )
}
