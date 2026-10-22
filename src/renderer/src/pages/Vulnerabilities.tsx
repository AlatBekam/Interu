import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconBug, IconCheck, IconRefresh } from '../components/icons'
import { MOCK_VULNS, Severity, severityPill, SEVERITY_ORDER } from '../data/mock'
import { usePersistentState, useSettings } from '../store/store'
import { useFindings, recordRetest } from '../store/findings'
import { TEMPLATES, analyzeScan, matchActive, Finding, RetestStatus } from '../../../shared/rules'
import { latestRetest, retestPlan, retestStatus } from '../../../shared/retest'

type StatusMap = Record<string, 'open' | 'investigating' | 'mitigated'>
type View = 'live' | 'demo'

const retestPill: Record<RetestStatus, string> = {
  closed: 'pill-ok', open: 'pill-crit', changed: 'pill-warn', error: 'pill-muted', untestable: 'pill-muted'
}

/** Re-run one finding's check. Returns null when it cannot be retested automatically. */
async function retestOne(f: Finding, scope: string[]): Promise<{ status: RetestStatus; note?: string; blocked?: boolean } | null> {
  const plan = retestPlan(f)
  if (plan.kind === 'none') return null
  if (plan.kind === 'http') {
    const t = TEMPLATES.find((x) => x.id === f.templateId)
    if (!t || !f.req) return { status: 'error', note: 'Template tidak ditemukan.' }
    const res = await window.ruy.http.send(f.req, scope, 'retest')
    // No response (down, timeout, blocked) proves nothing about the fix.
    if (!res.ok) return { status: 'error', note: res.error, blocked: res.blocked }
    const fresh = matchActive(t, f.req, res)
    return { status: retestStatus(f, fresh), note: fresh?.evidence }
  }
  const res = await window.ruy.scan.run({ target: plan.ip, profile: 'quick', ports: [plan.port], retest: true }, scope, Date.now())
  if (!res.ok) return { status: 'error', note: res.error, blocked: res.blocked }
  const fresh = analyzeScan(res.hosts || []).find((x) => x.key === f.key) || null
  return { status: retestStatus(f, fresh), note: fresh?.evidence }
}

export default function Vulnerabilities() {
  const findings = useFindings()
  const [settings] = useSettings()
  const [retesting, setRetesting] = useState(false)
  const [retestNote, setRetestNote] = useState<string | null>(null)

  const runRetest = async () => {
    if (!window.ruy?.http) { setRetestNote('Bridge tidak tersedia — jalankan sebagai aplikasi desktop.'); return }
    setRetesting(true)
    const tally: Partial<Record<RetestStatus, number>> = {}
    let skipped = 0
    for (const f of findings) {
      let r: Awaited<ReturnType<typeof retestOne>>
      try {
        r = await retestOne(f, settings.scope)
      } catch (e) {
        r = { status: 'error', note: (e as Error).message }
      }
      if (!r) { skipped++; continue }
      recordRetest(f.key, { at: new Date().toISOString(), status: r.status, note: r.note })
      tally[r.status] = (tally[r.status] || 0) + 1
      if (r.blocked) { setRetestNote(`⛔ Retest dihentikan: ${r.note}`); setRetesting(false); return }
    }
    setRetestNote(`Retest selesai — closed ${tally.closed || 0} · open ${tally.open || 0} · changed ${tally.changed || 0} · error ${tally.error || 0} · manual ${skipped}`)
    setRetesting(false)
  }
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
      if (query && !(`${f.name} ${f.target} ${(f.cve || []).join(' ')} ${f.evidence}`.toLowerCase().includes(query.toLowerCase()))) return false
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
              {isLive && (
                <button className="btn btn-primary btn-sm" onClick={runRetest} disabled={retesting || findings.length === 0} title="Re-run the check behind every finding (RoE technique: retest)">
                  <IconRefresh size={14} />{retesting ? 'Retesting…' : 'Retest all'}
                </button>
              )}
              <input type="text" placeholder={isLive ? 'Search name, CVE, target…' : 'Search CVE, title, asset…'} value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: 220 }} />
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | 'all')} style={{ width: 150 }}>
                <option value="all">All severities</option>
                {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          }
        >
          {isLive && retestNote && <div className="small muted" style={{ marginBottom: 12 }}>{retestNote}</div>}
          <div className="table-wrap">
            {isLive ? (
              <table className="data">
                <thead>
                  <tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Evidence</th><th>CVE</th><th>Src</th><th>Retest</th></tr>
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
                      <td className="mono small">{f.cve?.join(', ') || '—'}</td>
                      <td className="small muted">{f.source}</td>
                      <td>{(() => {
                        const last = latestRetest(f)
                        if (!last) return <span className="small muted">{retestPlan(f).kind === 'none' ? 'manual' : '—'}</span>
                        return (
                          <span title={`${f.retests!.length} retest(s); last ${new Date(last.at).toLocaleString('en-GB')}${last.note ? ' — ' + last.note : ''}`}>
                            <span className={`pill ${retestPill[last.status]}`}><span className="pd" />{last.status}</span>
                          </span>
                        )
                      })()}</td>
                    </tr>
                  ))}
                  {liveRows.length === 0 && (
                    <tr><td colSpan={8}><div className="empty">No live findings yet. Run a scan, browse via the Proxy, or run active checks in the Rule Engine.</div></td></tr>
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
