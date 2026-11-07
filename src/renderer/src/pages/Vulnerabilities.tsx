import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import KevBadge from '../components/KevBadge'
import { isProductLevel } from '../../../shared/activity'
import { cveCellText, cveCellTitle } from '../../../shared/kev'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconBug, IconCheck } from '../components/icons'
import { Severity, severityPill, SEVERITY_ORDER } from '../lib/severity'
import { useFindings } from '../store/findings'

export default function Vulnerabilities() {
  const findings = useFindings()
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [query, setQuery] = useState('')

  const rows = useMemo(
    () => findings.filter((f) => {
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false
      if (query && !(`${f.name} ${f.target} ${(isProductLevel(f) ? [] : f.cve || []).join(' ')} ${f.evidence}`.toLowerCase().includes(query.toLowerCase()))) return false
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
      <TopBar title="Vulnerability Assessment" sub="Findings from the Rule Engine" />
      <div className="content page">
        <Disclaimer>
          Findings produced by the Rule Engine from Network Scanner results, captured proxy responses, and
          scope-gated active checks. <em>Confirmed</em> = directly observed/proven;
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
          sub="Detected by the Rule Engine"
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
                  <tr key={f.key}>
                    <td><span className={`pill ${severityPill[f.severity as Severity]}`}><span className="pd" />{f.severity}</span></td>
                    <td>
                      <span className={`pill ${f.confidence === 'confirmed' ? 'pill-ok' : 'pill-warn'}`}>
                        {f.confidence === 'confirmed' && <IconCheck size={12} />}<span className="pd" />{f.confidence}
                      </span>
                    </td>
                    <td>{f.name}{f.remediation && <div className="small muted">{f.remediation}</div>}</td>
                    <td className="mono small">{f.target}{f.port != null ? `:${f.port}` : ''}</td>
                    <td className="small muted" style={{ maxWidth: 240 }} title={f.evidence}>{f.evidence}</td>
                    <td className="mono small">
                      <span title={cveCellTitle(f)}>{cveCellText(f)}</span>
                      <KevBadge f={f} />
                    </td>
                    <td className="small muted">{f.source}</td>
                  </tr>
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
