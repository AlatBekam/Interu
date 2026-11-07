import React, { useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer } from '../../components/ui'
import { IconCode, IconForward, IconClipboard } from '../../components/icons'

// Fully functional, offline transforms — no network involved. This is a real
// utility even at the UI stage.
type Op = 'url' | 'base64' | 'hex' | 'html' | 'ascii'

const htmlEntities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }

function apply(op: Op, mode: 'encode' | 'decode', input: string): string {
  try {
    switch (op) {
      case 'url':
        return mode === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input)
      case 'base64':
        return mode === 'encode'
          ? btoa(unescape(encodeURIComponent(input)))
          : decodeURIComponent(escape(atob(input)))
      case 'hex':
        return mode === 'encode'
          ? Array.from(input).map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
          : input.replace(/[^0-9a-fA-F]/g, '').replace(/(..)/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
      case 'html':
        return mode === 'encode'
          ? input.replace(/[&<>"']/g, (c) => htmlEntities[c])
          : input.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      case 'ascii':
        return mode === 'encode'
          ? Array.from(input).map((c) => c.charCodeAt(0)).join(' ')
          : input.split(/\s+/).filter(Boolean).map((n) => String.fromCharCode(Number(n))).join('')
    }
  } catch {
    return 'cannot ' + mode + ' as ' + op.toUpperCase() + ' (invalid input)'
  }
}

const OPS: { id: Op; label: string }[] = [
  { id: 'url', label: 'URL' },
  { id: 'base64', label: 'Base64' },
  { id: 'hex', label: 'Hex' },
  { id: 'html', label: 'HTML' },
  { id: 'ascii', label: 'ASCII' }
]

export default function Decoder() {
  const [input, setInput] = useState("' OR '1'='1")
  const [op, setOp] = useState<Op>('url')
  const [mode, setMode] = useState<'encode' | 'decode'>('encode')
  const output = apply(op, mode, input)

  return (
    <>
      <TopBar title="Decoder" sub="Encode & decode — fully offline" />
      <div className="content page">
        <Disclaimer>
          This tool works <strong>entirely offline</strong> and really transforms your text (URL, Base64, Hex,
          HTML entities, ASCII). No data leaves the application.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <div className="tabs" style={{ border: 'none' }}>
            {OPS.map((o) => (
              <button key={o.id} className={`tab ${op === o.id ? 'active' : ''}`} onClick={() => setOp(o.id)}>{o.label}</button>
            ))}
          </div>
          <div style={{ flex: 1 }} />
          <div className="theme-toggle">
            <button className={mode === 'encode' ? 'on' : ''} onClick={() => setMode('encode')}>Encode</button>
            <button className={mode === 'decode' ? 'on' : ''} onClick={() => setMode('decode')}>Decode</button>
          </div>
        </div>

        <div className="split">
          <Panel title="Input" right={<IconCode />}>
            <textarea className="code-pane" value={input} onChange={(e) => setInput(e.target.value)} style={{ minHeight: 240 }} spellCheck={false} />
          </Panel>
          <Panel
            title="Output"
            right={
              <div className="flex gap-8">
                <button className="btn btn-ghost btn-sm" onClick={() => setInput(output)} title="Use output as input"><IconForward size={14} />Chain</button>
                <button className="btn btn-ghost btn-sm" onClick={() => navigator.clipboard?.writeText(output)} title="Copy"><IconClipboard size={14} />Copy</button>
              </div>
            }
          >
            <div className="code-pane" style={{ minHeight: 240 }}>{output}</div>
          </Panel>
        </div>
      </div>
    </>
  )
}
