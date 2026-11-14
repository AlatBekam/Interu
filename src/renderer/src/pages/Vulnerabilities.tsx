import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import KevBadge from '../components/KevBadge'
import { isProductLevel } from '../../../shared/activity'
import { cveCellText, cveCellTitle } from '../../../shared/kev'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconBug, IconCheck } from '../components/icons'
import { Severity, severityPill, SEVERITY_ORDER } from '../lib/severity'
import { useFindings } from '../store/findings'
import CopyButton from '../components/CopyButton'

export default function Vulnerabilities() {
  const findings = useFindings()
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [query, setQuery] = useState('')
  const [openKey, setOpenKey] = useState<string | null>(null)

  const rows = useMemo(
    () => findings.filter((f) => {
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false
      if (query && !(`${f.name} ${f.target} ${(isProductLevel(f) ? [] : f.cve || []).join(' ')} ${f.evidence} ${f.response || ''}`.toLowerCase().includes(query.toLowerCase()))) return false
      return true
    }),
    [findings, sevFilter, query]
  )
  const counts = useMemo(() => ({
    total: findings.length,
    confirmed: findings.filter((f) => f.confidence === 'confirmed').length,
    suspected: findings.filter((f) => f.confidence === 'suspected').length,
    bad: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length
  }), [findings])

  return (
    <>
      <TopBar title="Vulnerability Assessment" sub="Click a finding to inspect its evidence and response" />
      <div className="content page">
        <Disclaimer>
          Findings produced by the scanner, proxy, Active Scan, Rule Engine, and Pentest Automation.
          <em> Confirmed</em> = directly observed evidence;
          <em> Suspected</em> = needs verification. Run a scan or active checks to populate them.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Total Findings" value={counts.total} icon={<IconBug />} />
          <Stat label="Confirmed" value={counts.confirmed} meta="proven" />
          <Stat label="Suspected" value={counts.suspected} meta="verify" />
          <Stat label="Critical / High" value={counts.bad} meta="need action" />
        </div>

        <Panel
          title="Findings"
          sub="Detected across scans and checks"
          className="mt-24"
          right={
            <div className="flex gap-12 items-center">
              <input type="text" placeholder="Search name, CVE, target…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: 220 }} />
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | 'all')} style={{ width: 150 }}>
                <option value="all">All severities</option>
                {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          }
        >
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Evidence</th><th>CVE</th><th>Src</th></tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <React.Fragment key={f.key}>
                  <tr className="clickable" tabIndex={0} aria-expanded={openKey === f.key}
                    onClick={() => setOpenKey(openKey === f.key ? null : f.key)}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpenKey(openKey === f.key ? null : f.key) } }}>
                    <td><span className={`pill ${severityPill[f.severity as Severity]}`}><span className="pd" />{f.severity}</span></td>
                    <td>
                      <span className={`pill ${f.confidence === 'confirmed' ? 'pill-ok' : 'pill-warn'}`}>
                        {f.confidence === 'confirmed' && <IconCheck size={12} />}<span className="pd" />{f.confidence}
                      </span>
                    </td>
                    <td>{f.name}<div className="small muted">{openKey === f.key ? 'Tutup bukti' : 'Klik untuk lihat bukti'}</div></td>
                    <td className="mono small">{f.target}{f.port != null ? `:${f.port}` : ''}</td>
                    <td className="small muted" style={{ maxWidth: 240 }} title={f.evidence}>{f.evidence}</td>
                    <td className="mono small">
                      <span title={cveCellTitle(f)}>{cveCellText(f)}</span>
                      <KevBadge f={f} />
                    </td>
                    <td className="small muted">{f.source}</td>
                  </tr>
                  {openKey === f.key && <tr><td colSpan={7}>
                    <div style={{ display: 'grid', gap: 12, padding: '12px 8px' }}>
                      <div><strong>{f.name}</strong><div className="small muted mono">{f.matchedAt || f.target}</div></div>
                      {(() => {
                        const flags = [...new Set((f.response || '').match(/RUY\{[^}\r\n]{1,160}\}/g) || [])]
                        return flags.length ? <div className="flex gap-8 wrap items-center"><strong>Flag ditemukan:</strong>{flags.map(flag => <span key={flag} className="pill pill-ok mono">{flag} <CopyButton text={flag} label="copy" /></span>)}</div> : null
                      })()}
                      <div><strong>Bukti aturan</strong><div className="small allow-select">{f.evidence}</div></div>
                      {f.description && <div><strong>Penjelasan</strong><div className="small allow-select">{f.description}</div></div>}
                      {f.remediation && <div><strong>Perbaikan</strong><div className="small allow-select">{f.remediation}</div></div>}
                      {f.request && <details><summary>Request <CopyButton text={f.request} label="copy" /></summary><pre className="code-pane allow-select" style={{ maxHeight: 220, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{f.request}</pre></details>}
                      {f.response && <details open><summary>Response <CopyButton text={f.response} label="copy" /></summary><pre className="code-pane allow-select" style={{ maxHeight: 320, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{f.response}</pre></details>}
                    </div>
                  </td></tr>}
                  </React.Fragment>
                ))}
                {rows.length === 0 && (
                  <tr><td colSpan={7}><div className="empty">No findings yet. Run a scan, browse via the Proxy, or run active checks in the Rule Engine.</div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  )
}
