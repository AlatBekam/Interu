import React from 'react'
import { kevBadge, type KevInfo } from '../../../shared/kev'

// KEV badge for a finding. A product-level hit is labelled "KEV product" and drawn
// in the warning colour, so it never reads as a CVE proven exploited on this host.
export default function KevBadge({ f }: { f: { tags?: string[]; kev?: KevInfo[] } }) {
  const b = kevBadge(f)
  if (!b) return null
  return (
    <span className={`pill ${b.text === 'KEV' ? 'pill-crit' : 'pill-warn'}`} style={{ marginLeft: 6 }} title={b.title}>
      <span className="pd" />{b.text}
    </span>
  )
}
