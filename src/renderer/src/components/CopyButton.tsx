import React, { useState } from 'react'
import { IconCheck } from './icons'

/** Small inline "Copy" button. Copies `text` to the clipboard and flashes a check mark. */
export default function CopyButton({ text, label = 'Copy', title }: { text: string; label?: string; title?: string }): React.JSX.Element {
  const [ok, setOk] = useState(false)
  const copy = async (): Promise<void> => {
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setOk(true)
      setTimeout(() => setOk(false), 1200)
    } catch { /* clipboard unavailable — selection + Ctrl+C still works */ }
  }
  return (
    <button type="button" className={`copy-btn${ok ? ' ok' : ''}`} onClick={copy} disabled={!text} title={title || 'Copy to clipboard'}>
      {ok ? <><IconCheck size={12} />Copied</> : label}
    </button>
  )
}
