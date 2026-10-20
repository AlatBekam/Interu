import React, { useEffect } from 'react'
import { createPortal } from 'react-dom'

export interface CtxItem {
  label?: string
  onClick?: () => void
  danger?: boolean
  sep?: boolean
  disabled?: boolean
}

export interface CtxState {
  x: number
  y: number
  items: CtxItem[]
}

export default function ContextMenu({ x, y, items, onClose }: CtxState & { onClose: () => void }) {
  useEffect(() => {
    // Close on an outside mousedown, on scroll, or on Escape. Mousedown inside
    // the menu is stopped below so item clicks still fire.
    const close = (): void => onClose()
    const onKey = (e: KeyboardEvent): void => { if (e.key === 'Escape') onClose() }
    window.addEventListener('mousedown', close)
    window.addEventListener('scroll', close, true)
    window.addEventListener('blur', close)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('mousedown', close)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('blur', close)
      window.removeEventListener('keydown', onKey)
    }
  }, [onClose])

  const rows = Math.max(items.length, 1)
  const left = Math.min(Math.max(8, x), window.innerWidth - 234)
  const top = Math.min(Math.max(8, y), window.innerHeight - rows * 34 - 16)

  // Rendered into document.body so no overflow/transform ancestor can clip or
  // mis-position it.
  return createPortal(
    <div
      className="ctx-menu"
      style={{ left, top }}
      onMouseDown={(e) => e.stopPropagation()}
      onContextMenu={(e) => { e.preventDefault(); e.stopPropagation() }}
    >
      {items.map((it, i) =>
        it.sep ? (
          <div key={i} className="ctx-sep" />
        ) : (
          <button
            key={i}
            className={`ctx-item ${it.danger ? 'danger' : ''}`}
            disabled={it.disabled}
            onClick={() => { it.onClick?.(); onClose() }}
          >
            {it.label}
          </button>
        )
      )}
    </div>,
    document.body
  )
}
