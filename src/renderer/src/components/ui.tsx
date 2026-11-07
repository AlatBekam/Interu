import React from 'react'
import { IconWarn, IconLock, IconCheck } from './icons'

export function Panel({
  title,
  sub,
  right,
  children,
  className
}: {
  title?: string
  sub?: string
  right?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className ?? ''}`}>
      {(title || right) && (
        <div className="panel-head">
          <div>
            {title && <h3>{title}</h3>}
            {sub && <div className="ph-sub">{sub}</div>}
          </div>
          <div style={{ flex: 1 }} />
          {right}
        </div>
      )}
      <div className="panel-body">{children}</div>
    </section>
  )
}

export function Stat({
  label,
  value,
  meta,
  icon,
  trend
}: {
  label: string
  value: React.ReactNode
  meta?: React.ReactNode
  icon?: React.ReactNode
  trend?: 'up' | 'down'
}) {
  return (
    <div className="stat">
      {icon && <div className="s-ico">{icon}</div>}
      <div className="s-label">{label}</div>
      <div className="s-value">{value}</div>
      {meta && <div className={`s-meta ${trend ? 'trend-' + trend : ''}`}>{meta}</div>}
    </div>
  )
}

/** `risk`: high is bad (default). `quality`: high is good. */
export function Gauge({ value, label, max = 100, tone = 'risk' }: { value: number; label: string; max?: number; tone?: 'risk' | 'quality' }) {
  const pct = Math.max(0, Math.min(1, value / max))
  const r = 56
  const c = 2 * Math.PI * r
  const dash = c * pct
  const color = tone === 'quality'
    ? (pct > 0.75 ? 'var(--ok)' : pct > 0.5 ? 'var(--med)' : 'var(--crit)')
    : (pct > 0.75 ? 'var(--crit)' : pct > 0.5 ? 'var(--med)' : 'var(--accent)')
  return (
    <div className="gauge">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle className="track" cx="66" cy="66" r={r} fill="none" strokeWidth="10" />
        <circle
          cx="66"
          cy="66"
          r={r}
          fill="none"
          style={{ stroke: color }}
          strokeWidth="10"
          strokeDasharray={`${dash} ${c}`}
          transform="rotate(-90 66 66)"
        />
      </svg>
      <div className="lbl">
        <span className="v">{Math.round(value)}</span>
        <span className="t">{label}</span>
      </div>
    </div>
  )
}

export function Meter({ value, tone }: { value: number; tone?: 'crit' | 'warn' | 'ok' }) {
  return (
    <div className={`meter ${tone ?? ''}`}>
      <span style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  )
}

export type NoteKind = 'warn' | 'block' | 'error' | 'ok'
/** A message with its state; pages keep one of these instead of a glyph-prefixed string. */
export interface NoteMsg { kind: NoteKind; text: string }

/** One line of context. The state shows as a 2px rail and an icon, never as emoji. */
export function Note({ kind, children }: { kind?: NoteKind; children: React.ReactNode }) {
  const Icon = kind === 'block' ? IconLock : kind === 'ok' ? IconCheck : IconWarn
  return (
    <div className="note" data-kind={kind}>
      <Icon />
      <div>{children}</div>
    </div>
  )
}

export function Disclaimer({ children }: { children: React.ReactNode }) {
  return <Note>{children}</Note>
}
