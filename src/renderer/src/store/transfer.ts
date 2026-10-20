import { useEffect, useRef } from 'react'

// One-shot handoff bus for the Burp-style "Send to Repeater / Intruder" action.
// A source module stashes a payload and navigates; the destination consumes it
// once on mount.
export interface TransferPayload {
  to: 'repeater' | 'intruder'
  target: string
  raw: string
  mode: 'sim' | 'live'
}

let pending: TransferPayload | null = null

export function setTransfer(p: TransferPayload): void {
  pending = p
}

export function takeTransfer(to: 'repeater' | 'intruder'): TransferPayload | null {
  if (pending && pending.to === to) {
    const p = pending
    pending = null
    return p
  }
  return null
}

/** Consume a pending transfer for this destination exactly once on mount. */
export function useTransfer(to: 'repeater' | 'intruder', apply: (p: TransferPayload) => void): void {
  const once = useRef(false)
  useEffect(() => {
    if (once.current) return
    once.current = true
    const p = takeTransfer(to)
    if (p) apply(p)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
}
