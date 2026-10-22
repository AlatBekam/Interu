import React, { useRef, useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Meter } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconCrosshair, IconPlay, IconStop } from '../../components/icons'
import { PAYLOAD_SETS, TARGET_HOST } from '../../data/burp'
import { parseRawRequest, sendLive } from '../../lib/http'
import { hostInScope } from '../../../../shared/http'
import { useSettings } from '../../store/store'
import { useTransfer } from '../../store/transfer'

interface Row { payload: string; status: number | string; length: number; ms: number; note?: string }
type Mode = 'sim' | 'live'

const TEMPLATE = `POST /api/login HTTP/1.1
Host: ${TARGET_HOST}
Content-Type: application/json
Connection: close

{"username": "§admin§", "password": "demo"}`

export default function Intruder() {
  const [settings] = useSettings()
  const [mode, setMode] = useState<Mode>('sim')
  const [target, setTarget] = useState('http://localhost:3000')
  const [template, setTemplate] = useState<string>(TEMPLATE)
  const [setName, setSetName] = useState<string>(Object.keys(PAYLOAD_SETS)[0])
  const [rows, setRows] = useState<Row[]>([])
  const [progress, setProgress] = useState(0)
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState('')
  const stopFlag = useRef(false)
  const timer = useRef<number | null>(null)

  // Receive a request handed over via "Send to Intruder" (adds a default marker).
  useTransfer('intruder', (p) => {
    setMode(p.mode)
    setTarget(p.target)
    setTemplate(p.raw)
    setRows([])
  })

  const positions = (template.match(/§[^§]*§/g) || []).length

  const stop = () => {
    stopFlag.current = true
    if (timer.current) window.clearInterval(timer.current)
    timer.current = null
    setRunning(false)
  }

  // --- Simulation: synthesize plausible rows locally (no traffic) ---
  const startSim = () => {
    const payloads = PAYLOAD_SETS[setName]
    setRows([]); setProgress(0); setRunning(true); setNote('')
    let i = 0
    timer.current = window.setInterval(() => {
      const p = payloads[i]
      const anomalous = /OR|UNION|DROP|'|--|admin|\.env|\.git/i.test(p)
      const status = anomalous ? (p.includes('admin') ? 200 : 500) : [200, 200, 302, 404][i % 4]
      const length = 200 + (anomalous ? 1200 + p.length * 30 : status === 404 ? 48 : 420 + p.length * 7)
      setRows((r) => [...r, { payload: p, status, length, ms: 30 + Math.floor(Math.random() * 70) }])
      i++
      setProgress(Math.round((i / payloads.length) * 100))
      if (i >= payloads.length) stop()
    }, 200)
  }

  // --- Live: substitute payload at §…§, send real requests, read real results ---
  const startLive = async () => {
    const payloads = PAYLOAD_SETS[setName]
    const probe = parseRawRequest(template.replace(/§[^§]*§/, 'x'), target)
    if (!hostInScope(probe.url, settings.scope)) {
      setNote(`⛔ ${(() => { try { return new URL(probe.url).hostname } catch { return 'target' } })()} belum ada di Authorized scope.`)
      return
    }
    setRows([]); setProgress(0); setRunning(true); setNote(''); stopFlag.current = false
    let baseLen = -1
    for (let i = 0; i < payloads.length; i++) {
      if (stopFlag.current) break
      const p = payloads[i]
      const filled = template.replace(/§[^§]*§/, p.replace(/"/g, '\\"'))
      const req = parseRawRequest(filled, target)
      const res = await sendLive(req, settings.scope, 'intruder')
      if (baseLen < 0 && res.ok) baseLen = res.size
      const outlier = res.ok && ((typeof res.status === 'number' && res.status >= 500) || (baseLen >= 0 && Math.abs(res.size - baseLen) > Math.max(40, baseLen * 0.25)))
      setRows((r) => [...r, {
        payload: p,
        status: res.ok ? (res.status ?? 0) : (res.error ?? 'err'),
        length: res.size,
        ms: res.timingMs,
        note: outlier ? 'outlier' : undefined
      }])
      setProgress(Math.round(((i + 1) / payloads.length) * 100))
    }
    setRunning(false)
  }

  const start = () => (mode === 'live' ? startLive() : startSim())

  return (
    <>
      <TopBar title="Intruder" sub="Automated payload testing" />
      <div className="content page">
        {mode === 'live' ? (
          <Disclaimer>
            <strong>Live mode fires real requests</strong> for every payload, only to hosts in your authorized
            scope. Use strictly on systems you are permitted to test.
          </Disclaimer>
        ) : (
          <Disclaimer>
            <strong>Simulation mode.</strong> Result rows are fabricated locally — nothing is sent. Switch to Live
            to run the payload set against an authorized target.
          </Disclaimer>
        )}

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <div className="theme-toggle">
            <button className={mode === 'sim' ? 'on' : ''} onClick={() => setMode('sim')}>Simulation</button>
            <button className={mode === 'live' ? 'on' : ''} onClick={() => setMode('live')}>Live</button>
          </div>
          {mode === 'live' && (
            <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" style={{ flex: 1, minWidth: 240 }} />
          )}
        </div>

        {mode === 'live' && <ScopeBar />}
        {note && <div className="disclaimer" style={{ borderColor: 'rgba(214,89,79,0.3)', background: 'rgba(214,89,79,0.06)' }}><div>{note}</div></div>}

        <div className="split mt-16">
          <Panel title="Positions" sub={`Wrap an injection point in §…§ · ${positions} marked`}>
            <div className="code-head">Request template</div>
            <textarea className="code-pane" value={template} onChange={(e) => setTemplate(e.target.value)} style={{ minHeight: 300 }} spellCheck={false} />
          </Panel>
          <Panel title="Payloads" sub="Choose a payload set">
            <label className="field mb-16"><span className="lab">Payload set</span>
              <select value={setName} onChange={(e) => setSetName(e.target.value)}>
                {Object.keys(PAYLOAD_SETS).map((k) => <option key={k} value={k}>{k} ({PAYLOAD_SETS[k].length})</option>)}
              </select>
            </label>
            <div className="code-pane" style={{ minHeight: 170 }}>{PAYLOAD_SETS[setName].join('\n')}</div>
            <div className="flex gap-12 mt-16">
              {!running ? (
                <button className="btn btn-primary" onClick={start}><IconPlay />Start attack</button>
              ) : (
                <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
              )}
            </div>
          </Panel>
        </div>

        {(rows.length > 0 || running) && (
          <Panel title="Attack Results" sub={`${rows.length}/${PAYLOAD_SETS[setName].length} · ${mode === 'live' ? 'live' : 'simulated'}`} className="mt-24" right={<IconCrosshair />}>
            <div className="mb-16"><Meter value={progress} tone={progress === 100 ? 'ok' : undefined} /></div>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>Time</th><th>Note</th></tr></thead>
                <tbody>
                  {rows.map((r, i) => {
                    const sc = typeof r.status === 'number' ? String(r.status)[0] : '5'
                    return (
                      <tr key={i} style={{ background: r.note ? 'rgba(214,168,79,0.08)' : undefined }}>
                        <td className="mono">{i}</td>
                        <td className="mono small">{r.payload}</td>
                        <td><span className={`sc s${sc}`}>{r.status}</span></td>
                        <td className="mono">{r.length}</td>
                        <td className="mono small">{r.ms} ms</td>
                        <td>{r.note && <span className="pill pill-warn"><span className="pd" />{r.note}</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </div>
    </>
  )
}
