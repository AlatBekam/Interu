import React, { useRef, useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Meter, Note, NoteMsg } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconCrosshair, IconPlay, IconStop } from '../../components/icons'
import { PAYLOAD_SETS } from '../../data/burp'
import { parseRawRequest, sendLive, inScopeOrNote } from '../../lib/http'
import { useSettings } from '../../store/store'
import { useTransfer } from '../../store/transfer'
import CopyButton from '../../components/CopyButton'

interface Row { payload: string; status: number | string; length: number; ms: number; note?: string }

const TEMPLATE = `POST /api/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Connection: close

{"username": "§admin§", "password": "demo"}`

export default function Intruder() {
  const [settings] = useSettings()
  const [target, setTarget] = useState('http://localhost:3000')
  const [template, setTemplate] = useState<string>(TEMPLATE)
  const [setName, setSetName] = useState<string>(Object.keys(PAYLOAD_SETS)[0])
  const [rows, setRows] = useState<Row[]>([])
  const [progress, setProgress] = useState(0)
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState<NoteMsg | null>(null)
  const stopFlag = useRef(false)

  // Receive a request handed over via "Send to Intruder" (adds a default marker).
  useTransfer('intruder', (p) => {
    setTarget(p.target)
    setTemplate(p.raw)
    setRows([])
  })

  const positions = (template.match(/§[^§]*§/g) || []).length

  const stop = () => {
    stopFlag.current = true
    setRunning(false)
  }

  // Substitute payload at §…§, send real requests, read real results ---
  const startLive = async () => {
    const payloads = PAYLOAD_SETS[setName]
    const probe = parseRawRequest(template.replace(/§[^§]*§/, 'x'), target)
    if (!inScopeOrNote(probe.url, settings.scope, 'intruder')) {
      setNote({ kind: 'block', text: `${(() => { try { return new URL(probe.url).hostname } catch { return 'target' } })()} belum ada di Authorized scope.` })
      return
    }
    setRows([]); setProgress(0); setRunning(true); setNote(null); stopFlag.current = false
    let baseLen = -1
    for (let i = 0; i < payloads.length; i++) {
      if (stopFlag.current) break
      const p = payloads[i]
      const filled = template.replace(/§[^§]*§/, p.replace(/"/g, '\\"'))
      const req = parseRawRequest(filled, target)
      const res = await sendLive(req, settings.scope)
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

  return (
    <>
      <TopBar title="Intruder" sub="Automated payload testing" />
      <div className="content page">
        <Disclaimer>
          <strong>Fires real requests</strong> for every payload, only to hosts in your authorized
          scope. Use strictly on systems you are permitted to test.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" style={{ flex: 1, minWidth: 240 }} />
        </div>

        <ScopeBar />
        {note && <Note kind={note.kind}>{note.text}</Note>}

        <div className="split mt-16">
          <Panel title="Positions" sub={`Wrap an injection point in §…§ · ${positions} marked`}>
            <div className="code-head"><span>Request template</span><CopyButton text={template} /></div>
            <textarea className="code-pane" value={template} onChange={(e) => setTemplate(e.target.value)} style={{ minHeight: 300 }} spellCheck={false} />
          </Panel>
          <Panel title="Payloads" sub="Choose a payload set">
            <label className="field mb-16"><span className="lab">Payload set</span>
              <select value={setName} onChange={(e) => setSetName(e.target.value)}>
                {Object.keys(PAYLOAD_SETS).map((k) => <option key={k} value={k}>{k} ({PAYLOAD_SETS[k].length})</option>)}
              </select>
            </label>
            <div className="code-head"><span>{PAYLOAD_SETS[setName].length} payloads</span><CopyButton text={PAYLOAD_SETS[setName].join('\n')} /></div>
            <div className="code-pane" style={{ minHeight: 170 }}>{PAYLOAD_SETS[setName].join('\n')}</div>
            <div className="flex gap-12 mt-16">
              {!running ? (
                <button className="btn btn-primary" onClick={startLive}><IconPlay />Start attack</button>
              ) : (
                <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
              )}
            </div>
          </Panel>
        </div>

        {(rows.length > 0 || running) && (
          <Panel title="Attack Results" sub={`${rows.length}/${PAYLOAD_SETS[setName].length}`} className="mt-24" right={<IconCrosshair />}>
            <div className="mb-16"><Meter value={progress} tone={progress === 100 ? 'ok' : undefined} /></div>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>Time</th><th>Note</th></tr></thead>
                <tbody>
                  {rows.map((r, i) => {
                    const sc = typeof r.status === 'number' ? String(r.status)[0] : '5'
                    return (
                      <tr key={i} className={r.note ? 'flag' : undefined}>
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
