import React, { useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Note, NoteMsg } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import { IconSend } from '../../components/icons'
import CopyButton from '../../components/CopyButton'
import { parseRawRequest, rawFromParts, sendLive, inScopeOrNote } from '../../lib/http'
import { useSettings } from '../../store/store'
import { useTransfer } from '../../store/transfer'

const DEFAULT_REQUEST = rawFromParts('GET', 'localhost:3000', '/')

export default function Repeater() {
  const [settings] = useSettings()
  const [target, setTarget] = useState('http://localhost:3000')
  const [request, setRequest] = useState<string>(DEFAULT_REQUEST)
  const [response, setResponse] = useState<string>('')
  const [meta, setMeta] = useState<{ status: string; ms: number; len: number } | null>(null)
  const [sending, setSending] = useState(false)
  const [note, setNote] = useState<NoteMsg | null>(null)

  // Receive a request handed over via "Send to Repeater".
  useTransfer('repeater', (p) => {
    setTarget(p.target)
    setRequest(p.raw)
    setResponse('')
    setMeta(null)
  })

  const send = async () => {
    setSending(true); setResponse(''); setMeta(null); setNote(null)
    const req = { ...parseRawRequest(request, target), manual: true }
    if (!inScopeOrNote(req.url, settings.scope, 'repeater')) {
      setNote({ kind: 'block', text: `${new URL(req.url).hostname} belum ada di Authorized scope. Tambahkan dulu di bar di atas.` })
      setSending(false)
      return
    }
    const res = await sendLive(req, settings.scope)
    setSending(false)
    if (!res.ok) {
      setNote({ kind: 'error', text: res.error ?? 'request failed' })
      setResponse('')
      return
    }
    setResponse(res.raw ?? '')
    setMeta({ status: `${res.status} ${res.statusText ?? ''}`.trim(), ms: res.timingMs, len: res.size })
  }

  return (
    <>
      <TopBar title="Repeater" sub="Craft & resend HTTP requests" />
      <div className="content page">
        <Disclaimer>
          <strong>Sends real HTTP requests.</strong> Only hosts you add to the authorized scope are
          allowed. Use this exclusively against systems you own or are explicitly permitted to test.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <label className="field" style={{ flex: 1, minWidth: 260 }}>
            <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port" className="mono" />
          </label>
          <button className="btn btn-primary" onClick={send} disabled={sending}><IconSend />{sending ? 'Sending…' : 'Send'}</button>
          {meta && (
            <div className="flex gap-16 small muted">
              <span>Status: <span className="mono fg">{meta.status}</span></span>
              <span>Time: <span className="mono fg">{meta.ms} ms</span></span>
              <span>Length: <span className="mono fg">{meta.len}</span></span>
            </div>
          )}
        </div>

        <ScopeBar withAuth />
        {note && <Note kind={note.kind}>{note.text}</Note>}

        <div className="split mt-16">
          <Panel title="Request">
            <div className="code-head">
              <span>Editable raw request (path + headers)</span>
              <CopyButton text={request} />
            </div>
            <textarea className="code-pane" value={request} onChange={(e) => setRequest(e.target.value)} style={{ minHeight: 360 }} spellCheck={false} />
          </Panel>
          <Panel title="Response">
            <div className="code-head">
              <span>Response</span>
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
