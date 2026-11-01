import React, { useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconSend } from '../../components/icons'
import CopyButton from '../../components/CopyButton'
import { HTTP_HISTORY, rawRequest, rawResponse, HttpTx } from '../../data/burp'
import { parseRawRequest, sendLive } from '../../lib/http'
import { hostInScope } from '../../../../shared/http'
import { useSettings } from '../../store/store'
import { useTransfer } from '../../store/transfer'

type Mode = 'sim' | 'live'

const SIM_SEED = HTTP_HISTORY[3] // POST /api/login

export default function Repeater() {
  const [settings] = useSettings()
  const [mode, setMode] = useState<Mode>('sim')
  const [target, setTarget] = useState('http://localhost:3000')
  const [request, setRequest] = useState<string>(rawRequest(SIM_SEED))
  const [response, setResponse] = useState<string>('')
  const [meta, setMeta] = useState<{ status: string; ms: number; len: number } | null>(null)
  const [sending, setSending] = useState(false)
  const [note, setNote] = useState<string>('')

  // Receive a request handed over via "Send to Repeater".
  useTransfer('repeater', (p) => {
    setMode(p.mode)
    setTarget(p.target)
    setRequest(p.raw)
    setResponse('')
    setMeta(null)
  })

  const sendSim = () => {
    setSending(true); setResponse(''); setNote('')
    const firstLine = request.split('\n')[0] || ''
    const m = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/)
    const method = (m?.[1] as HttpTx['method']) || 'GET'
    const path = m?.[2] || '/'
    const match = HTTP_HISTORY.find((t) => t.path === path && t.method === method)
    const tx: HttpTx = match ?? { ...SIM_SEED, method, path, status: 200, mime: 'JSON', length: 256 }
    const latency = 40 + Math.floor(Math.random() * 90)
    window.setTimeout(() => {
      const res = rawResponse(tx)
      setResponse(res)
      setMeta({ status: res.split('\n')[0].replace('HTTP/1.1 ', '').trim(), ms: latency, len: res.length })
      setSending(false)
    }, latency + 120)
  }

  const sendRealLive = async () => {
    setSending(true); setResponse(''); setMeta(null); setNote('')
    const req = parseRawRequest(request, target)
    if (!hostInScope(req.url, settings.scope)) {
      setNote(`⛔ ${new URL(req.url).hostname} belum ada di Authorized scope. Tambahkan dulu di bar di atas.`)
      setSending(false)
      return
    }
    const res = await sendLive(req, settings.scope)
    setSending(false)
    if (!res.ok) {
      setNote(`⚠ ${res.error ?? 'request failed'}`)
      setResponse('')
      return
    }
    setResponse(res.raw ?? '')
    setMeta({ status: `${res.status} ${res.statusText ?? ''}`.trim(), ms: res.timingMs, len: res.size })
  }

  const send = () => (mode === 'live' ? sendRealLive() : sendSim())

  return (
    <>
      <TopBar title="Repeater" sub="Craft & resend HTTP requests" />
      <div className="content page">
        {mode === 'live' ? (
          <Disclaimer>
            <strong>Live mode sends real HTTP requests.</strong> Only hosts you add to the authorized scope are
            allowed. Use this exclusively against systems you own or are explicitly permitted to test.
          </Disclaimer>
        ) : (
          <Disclaimer>
            <strong>Simulation mode.</strong> Nothing is transmitted — responses are canned demo data. Switch to
            Live to send real requests to an authorized target.
          </Disclaimer>
        )}

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <div className="theme-toggle">
            <button className={mode === 'sim' ? 'on' : ''} onClick={() => setMode('sim')}>Simulation</button>
            <button className={mode === 'live' ? 'on' : ''} onClick={() => setMode('live')}>Live</button>
          </div>
          {mode === 'live' && (
            <label className="field" style={{ flex: 1, minWidth: 260 }}>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" />
            </label>
          )}
          <button className="btn btn-primary" onClick={send} disabled={sending}><IconSend />{sending ? 'Sending…' : 'Send'}</button>
          {meta && (
            <div className="flex gap-16 small muted">
              <span>Status: <span className="mono" style={{ color: 'var(--silver-100)' }}>{meta.status}</span></span>
              <span>Time: <span className="mono" style={{ color: 'var(--silver-100)' }}>{meta.ms} ms</span></span>
              <span>Length: <span className="mono" style={{ color: 'var(--silver-100)' }}>{meta.len}</span></span>
            </div>
          )}
        </div>

        {mode === 'live' && <ScopeBar />}
        {note && <div className="disclaimer" style={{ borderColor: 'rgba(214,89,79,0.3)', background: 'rgba(214,89,79,0.06)' }}><div>{note}</div></div>}

        <div className="split mt-16">
          <Panel title="Request">
            <div className="code-head">
              <span>{mode === 'live' ? 'Editable raw request (path + headers)' : 'Editable raw request'}</span>
              <CopyButton text={request} />
            </div>
            <textarea className="code-pane" value={request} onChange={(e) => setRequest(e.target.value)} style={{ minHeight: 360 }} spellCheck={false} />
          </Panel>
          <Panel title="Response">
            <div className="code-head">
              <span>{mode === 'live' ? 'Real response' : 'Simulated response'}</span>
              <CopyButton text={response} />
            </div>
            {response ? (
              <div className="code-pane" style={{ minHeight: 360 }}>{response}</div>
            ) : (
              <div className="empty" style={{ minHeight: 360, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {sending ? 'Awaiting response…' : 'Press Send to get a response.'}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  )
}
