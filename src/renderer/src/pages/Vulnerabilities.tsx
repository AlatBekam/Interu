import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import KevBadge from '../components/KevBadge'
import { isProductLevel } from '../../../shared/activity'
import { cveCellText, cveCellTitle } from '../../../shared/kev'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconBug, IconCheck } from '../components/icons'
import { MOCK_VULNS, Severity, severityPill, SEVERITY_ORDER } from '../data/mock'
import { usePersistentState } from '../store/store'
import { useFindings } from '../store/findings'

type StatusMap = Record<string, 'open' | 'investigating' | 'mitigated'>
type View = 'live' | 'demo'

export default function Vulnerabilities() {
  const findings = useFindings()
  const [view, setView] = usePersistentState<View>('vulns.view', 'live')
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [query, setQuery] = useState('')
  // User-adjusted statuses persist across restarts; defaults come from mock data.
  const [overrides, setOverrides] = usePersistentState<StatusMap>('vulns.status', {})

  const statusOf = (id: string, fallback: StatusMap[string]) => overrides[id] ?? fallback

  // -------- live findings (Rule Engine) --------
  const liveRows = useMemo(
    () => findings.filter((f) => {
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false
      if (query && !(`${f.name} ${f.target} ${(isProductLevel(f) ? [] : f.cve || []).join(' ')} ${f.evidence}`.toLowerCase().includes(query.toLowerCase()))) return false
      return true
    }),
    [findings, sevFilter, query]
  )
  const liveCounts = useMemo(() => ({
    total: findings.length,
    confirmed: findings.filter((f) => f.confidence === 'confirmed').length,
    suspected: findings.filter((f) => f.confidence === 'suspected').length,
    bad: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length
  }), [findings])

  // -------- demo catalog (static) --------
  const demoRows = useMemo(() => {
    return MOCK_VULNS.map((v) => ({ ...v, status: statusOf(v.id, v.status) })).filter((v) => {
      if (sevFilter !== 'all' && v.severity !== sevFilter) return false
      if (query && !(`${v.cve} ${v.title} ${v.asset}`.toLowerCase().includes(query.toLowerCase()))) return false
      return true
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sevFilter, query, overrides])
  const demoCounts = SEVERITY_ORDER.reduce<Record<string, number>>((a, s) => {
    a[s] = MOCK_VULNS.filter((v) => v.severity === s).length
    return a
  }, {})
  const cycle = (id: string, current: StatusMap[string]) => {
    const next = current === 'open' ? 'investigating' : current === 'investigating' ? 'mitigated' : 'open'
    setOverrides((o) => ({ ...o, [id]: next }))
  }

  const isLive = view === 'live'

  return (
    <>
      <TopBar title="Vulnerability Assessment" sub={isLive ? 'Live findings from the Rule Engine' : 'Simulated findings catalog'} />
      <div className="content page">
        {isLive ? (
          <Disclaimer>
            These are <strong>real findings</strong> produced by the Rule Engine from Network Scanner results, captured
            proxy responses, and scope-gated active checks. <em>Confirmed</em> = directly observed/proven;
            <em> Suspected</em> = needs verification. Run a scan or active checks to populate them.
          </Disclaimer>
        ) : (
          <Disclaimer>
            This is a <strong>static demonstration catalog</strong>. No real testing is performed; status changes are
            stored locally for the demo only.
          </Disclaimer>
        )}

        <div className="flex gap-12 mt-16" style={{ alignItems: 'center' }}>
          <span className="small muted">Source:</span>
          <div className="theme-toggle">
            <button className={isLive ? 'on' : ''} onClick={() => setView('live')}>Live (Rule Engine)</button>
            <button className={!isLive ? 'on' : ''} onClick={() => setView('demo')}>Demo catalog</button>
          </div>
        </div>

        {isLive ? (
          <div className="grid grid-4 mt-16">
            <Stat label="Total Findings" value={liveCounts.total} icon={<IconBug />} />
            <Stat label="Confirmed" value={liveCounts.confirmed} meta="proven" />
            <Stat label="Suspected" value={liveCounts.suspected} meta="verify" />
            <Stat label="Critical / High" value={liveCounts.bad} meta="need action" />
          </div>
        ) : (
          <div className="grid grid-4 mt-16">
            <Stat label="Total Findings" value={MOCK_VULNS.length} icon={<IconBug />} />
            <Stat label="Critical" value={demoCounts.critical} meta="require action" />
            <Stat label="High" value={demoCounts.high} />
            <Stat label="Mitigated" value={Object.values({ ...Object.fromEntries(MOCK_VULNS.map((v) => [v.id, v.status])), ...overrides }).filter((s) => s === 'mitigated').length} meta="locally tracked" />
          </div>
        )}

        <Panel
          title="Findings"
          sub={isLive ? 'Detected by the Rule Engine' : 'Click a status to cycle open → investigating → mitigated'}
          className="mt-24"
          right={
            <div className="flex gap-12 items-center">
              <input type="text" placeholder={isLive ? 'Search name, CVE, target…' : 'Search CVE, title, asset…'} value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: 220 }} />
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | 'all')} style={{ width: 150 }}>
                <option value="all">All severities</option>
                {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          }
        >
          <div className="table-wrap">
            {isLive ? (
              <table className="data">
                <thead>
                  <tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Evidence</th><th>CVE</th><th>Src</th></tr>
                </thead>
                <tbody>
                  {liveRows.map((f) => (
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
                  {liveRows.length === 0 && (
                    <tr><td colSpan={7}><div className="empty">No live findings yet. Run a scan, browse via the Proxy, or run active checks in the Rule Engine.</div></td></tr>
                  )}
                </tbody>
              </table>
            ) : (
              <table className="data">
                <thead>
                  <tr><th>ID</th><th>CVE</th><th>Title</th><th>Asset</th><th>CVSS</th><th>Severity</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {demoRows.map((v) => (
                    <tr key={v.id}>
                      <td className="mono">{v.id}</td>
                      <td className="mono small">{v.cve}</td>
                      <td>{v.title}<div className="small muted">{v.category}</div></td>
                      <td className="mono small">{v.asset}</td>
                      <td className="mono">{v.cvss.toFixed(1)}</td>
                      <td><span className={`pill ${severityPill[v.severity]}`}><span className="pd" />{v.severity}</span></td>
                      <td>
                        <button
                          className={`pill ${v.status === 'mitigated' ? 'pill-ok' : v.status === 'investigating' ? 'pill-warn' : 'pill-muted'}`}
                          style={{ cursor: 'pointer', border: '1px solid currentColor', opacity: 0.95 }}
                          onClick={() => cycle(v.id, v.status)}
                          title="Click to change status"
                        >
                          {v.status === 'mitigated' && <IconCheck size={12} />}
                          <span className="pd" />{v.status}
                        </button>
                      </td>
                    </tr>
                  ))}
                  {demoRows.length === 0 && (
                    <tr><td colSpan={7}><div className="empty">No findings match the current filter.</div></td></tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </Panel>
      </div>
    </>
  )
}
