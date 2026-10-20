import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconBug, IconCheck } from '../components/icons'
import { MOCK_VULNS, Severity, severityPill, SEVERITY_ORDER } from '../data/mock'
import { usePersistentState } from '../store/store'

type StatusMap = Record<string, 'open' | 'investigating' | 'mitigated'>

export default function Vulnerabilities() {
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [query, setQuery] = useState('')
  // User-adjusted statuses persist across restarts; defaults come from mock data.
  const [overrides, setOverrides] = usePersistentState<StatusMap>('vulns.status', {})

  const statusOf = (id: string, fallback: StatusMap[string]) => overrides[id] ?? fallback

  const rows = useMemo(() => {
    return MOCK_VULNS.map((v) => ({ ...v, status: statusOf(v.id, v.status) })).filter((v) => {
      if (sevFilter !== 'all' && v.severity !== sevFilter) return false
      if (query && !(`${v.cve} ${v.title} ${v.asset}`.toLowerCase().includes(query.toLowerCase()))) return false
      return true
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sevFilter, query, overrides])

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((a, s) => {
    a[s] = MOCK_VULNS.filter((v) => v.severity === s).length
    return a
  }, {})

  const cycle = (id: string, current: StatusMap[string]) => {
    const next = current === 'open' ? 'investigating' : current === 'investigating' ? 'mitigated' : 'open'
    setOverrides((o) => ({ ...o, [id]: next }))
  }

  return (
    <>
      <TopBar title="Vulnerability Assessment" sub="Simulated findings catalog" />
      <div className="content page">
        <Disclaimer>
          These findings are a <strong>static demonstration catalog</strong>. No real vulnerability testing,
          exploitation, or asset probing is performed. Status changes are stored locally for the demo only.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Total Findings" value={MOCK_VULNS.length} icon={<IconBug />} />
          <Stat label="Critical" value={counts.critical} meta="require action" />
          <Stat label="High" value={counts.high} />
          <Stat label="Mitigated" value={Object.values({ ...Object.fromEntries(MOCK_VULNS.map(v => [v.id, v.status])), ...overrides }).filter((s) => s === 'mitigated').length} meta="locally tracked" />
        </div>

        <Panel
          title="Findings"
          sub="Click a status to cycle open → investigating → mitigated"
          className="mt-24"
          right={
            <div className="flex gap-12 items-center">
              <input
                type="text"
                placeholder="Search CVE, title, asset…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                style={{ width: 220 }}
              />
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
                <tr><th>ID</th><th>CVE</th><th>Title</th><th>Asset</th><th>CVSS</th><th>Severity</th><th>Status</th></tr>
              </thead>
              <tbody>
                {rows.map((v) => (
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
                {rows.length === 0 && (
                  <tr><td colSpan={7}><div className="empty">No findings match the current filter.</div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  )
}
