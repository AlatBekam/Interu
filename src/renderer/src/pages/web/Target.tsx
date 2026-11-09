import React, { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Meter, Note, NoteMsg } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconPlay, IconStop } from '../../components/icons'
import { sendLive, rawFromParts, inScopeOrNote } from '../../lib/http'
import { useSettings } from '../../store/store'
import { setTransfer } from '../../store/transfer'
import ContextMenu, { CtxState } from '../../components/ContextMenu'
import CopyButton from '../../components/CopyButton'

const WORDLIST = [
  '/', '/admin', '/login', '/dashboard', '/api', '/api/users', '/api/login', '/robots.txt',
  '/.env', '/.git/HEAD', '/backup.zip', '/config.php', '/server-status', '/uploads', '/static',
  '/debug', '/phpinfo.php', '/wp-login.php', '/.well-known/security.txt', '/sitemap.xml'
]

interface Hit { path: string; status: number | string; length: number; ms: number; raw?: string }

export default function Target() {
  const [settings] = useSettings()
  const [target, setTarget] = useState('http://localhost:3000')
  const [hits, setHits] = useState<Hit[]>([])
  const [selHit, setSelHit] = useState<Hit | null>(null)
  const [progress, setProgress] = useState(0)
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState<NoteMsg | null>(null)
  const [menu, setMenu] = useState<CtxState | null>(null)
  const stopFlag = useRef(false)
  const navigate = useNavigate()

  const sendMenu = (e: React.MouseEvent, target: string, raw: string): void => {
    e.preventDefault()
    setMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Send to Repeater', onClick: () => { setTransfer({ to: 'repeater', target, raw }); navigate('/web/repeater') } },
        { label: 'Send to Intruder', onClick: () => { setTransfer({ to: 'intruder', target, raw }); navigate('/web/intruder') } },
        { sep: true },
        { label: 'Copy URL', onClick: () => navigator.clipboard?.writeText(target + raw.split(' ')[1]) },
        { label: 'Copy request', onClick: () => navigator.clipboard?.writeText(raw) }
      ]
    })
  }

  const liveHost = (() => { try { return new URL(target).host } catch { return 'target' } })()

  const discover = async () => {
    const base = target.replace(/\/+$/, '')
    if (!inScopeOrNote(base + '/', settings.scope, 'target')) {
      setNote({ kind: 'block', text: `${(() => { try { return new URL(base).hostname } catch { return 'target' } })()} belum ada di Authorized scope.` })
      return
    }
    setHits([]); setSelHit(null); setProgress(0); setRunning(true); setNote(null); stopFlag.current = false
    for (let i = 0; i < WORDLIST.length; i++) {
      if (stopFlag.current) break
      const path = WORDLIST[i]
      const res = await sendLive({ method: 'GET', url: base + path, headers: { 'User-Agent': 'Interu/1.0' } }, settings.scope)
      if (res.authLost) { stopFlag.current = true; setNote({ kind: 'error', text: 'Login session expired. Paste a fresh token, then press Refresh.' }); break }
      if (res.ok && res.status !== 404) {
        setHits((h) => [...h, { path, status: res.status ?? 0, length: res.size, ms: res.timingMs, raw: res.raw }])
      }
      setProgress(Math.round(((i + 1) / WORDLIST.length) * 100))
    }
    setRunning(false)
  }

  return (
    <>
      <TopBar title="Target · Site Map" sub="Live content discovery" />
      <div className="content page">
        <Disclaimer>
          <strong>Content discovery</strong> sends real GET requests for a wordlist of common paths, only to
          hosts in your authorized scope. Found paths build a real map. Use on permitted systems only.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" style={{ flex: 1, minWidth: 240 }} />
          {!running ? (
            <button className="btn btn-primary" onClick={discover}><IconPlay />Discover</button>
          ) : (
            <button className="btn btn-danger" onClick={() => { stopFlag.current = true; setRunning(false) }}><IconStop />Stop</button>
          )}
        </div>

        <ScopeBar withAuth />
        {note && <Note kind={note.kind}>{note.text}</Note>}

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
                        onContextMenu={(e) => sendMenu(e, target.replace(/\/+$/, ''), rawFromParts('GET', liveHost, h.path))}
                        className={selHit?.path === h.path ? 'clickable sel' : 'clickable'} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelHit(h) } }}
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
            {selHit?.raw ? (
              <>
                <div className="code-head"><span>Response</span><CopyButton text={selHit.raw} /></div>
                <div className="code-pane" style={{ minHeight: 300 }}>{selHit.raw}</div>
              </>
            ) : <div className="empty" style={{ minHeight: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Select a discovered path to view its response.</div>}
          </Panel>
        </div>

        {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      </div>
    </>
  )
}
