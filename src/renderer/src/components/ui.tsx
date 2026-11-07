import React from 'react'
import { IconWarn } from './icons'

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

export function Gauge({ value, label, max = 100 }: { value: number; label: string; max?: number }) {
  const pct = Math.max(0, Math.min(1, value / max))
  const r = 56
  const c = 2 * Math.PI * r
  const dash = c * pct
  const color = pct > 0.75 ? '#d6594f' : pct > 0.5 ? '#d6a84f' : '#3765b8'
  return (
    <div className="gauge">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r={r} fill="none" style={{ stroke: 'var(--panel-600)' }} strokeWidth="10" />
        <circle
          cx="66"
          cy="66"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c}`}
          transform="rotate(-90 66 66)"
          style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.6s ease' }}
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

export function Disclaimer({ children }: { children: React.ReactNode }) {
  return (
    <div className="disclaimer">
      <IconWarn />
      <div>{children}</div>
    </div>
  )
}
