import React, { useMemo } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Stat, Gauge, BarChart, Disclaimer, Meter } from '../components/ui'
import { IconShieldAlert, IconBug, IconScan, IconServer, IconActivity } from '../components/icons'
import { MOCK_HOSTS, MOCK_VULNS, trafficSeries, severityPill, SEVERITY_ORDER } from '../data/mock'
import { useActivity } from '../store/activity'
import { timeLabel } from '../../../shared/activity'

export default function Dashboard() {
  const traffic = useMemo(() => trafficSeries(), [])
  const recent = useActivity().slice(0, 6)

  const openVulns = MOCK_VULNS.filter((v) => v.status !== 'mitigated')
  const critical = MOCK_VULNS.filter((v) => v.severity === 'critical' && v.status !== 'mitigated').length
  const hostsUp = MOCK_HOSTS.filter((h) => h.status === 'up').length

  const sevCounts = SEVERITY_ORDER.map((s) => ({
    sev: s,
    n: MOCK_VULNS.filter((v) => v.severity === s).length
  }))

  // Deterministic composite "posture" score derived from the mock datasets.
  const riskScore = Math.min(
    100,
    critical * 18 + openVulns.length * 4 + MOCK_HOSTS.filter((h) => h.risk === 'high').length * 6
  )

  return (
    <>
      <TopBar title="Security Overview" sub="Consolidated posture across the simulated RUY estate" />
      <div className="content page">
        <Disclaimer>
          <strong>Simulated environment.</strong> Every metric, host, and event shown here is deterministic demo
          data generated locally inside this application. Nothing is scanned, intercepted, or executed on your
          real system or network.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Threat Index" value={riskScore} meta="Composite posture score" icon={<IconShieldAlert />} />
          <Stat label="Open Vulnerabilities" value={openVulns.length} meta={`${critical} critical unresolved`} icon={<IconBug />} />
          <Stat label="Monitored Hosts" value={MOCK_HOSTS.length} meta={`${hostsUp} responding`} icon={<IconServer />} />
          <Stat label="Sensors Online" value="12 / 12" meta="All collectors healthy" icon={<IconActivity />} trend="up" />
        </div>

        <div className="grid grid-3 mt-24">
          <Panel title="Risk Posture" sub="Simulated" className="grid-span">
            <div className="gauge-wrap">
              <Gauge value={riskScore} label="Index" />
              <div style={{ flex: 1 }}>
                <div className="small muted mb-16">
                  Weighted blend of unresolved critical findings, total open issues, and high-risk host exposure.
                </div>
                {sevCounts.map((s) => (
                  <div key={s.sev} className="mb-16">
                    <div className="flex justify-between small" style={{ marginBottom: 6 }}>
                      <span style={{ textTransform: 'capitalize' }}>{s.sev}</span>
                      <span className="mono">{s.n}</span>
                    </div>
                    <Meter
                      value={(s.n / Math.max(...sevCounts.map((x) => x.n), 1)) * 100}
                      tone={s.sev === 'critical' ? 'crit' : s.sev === 'high' ? 'warn' : undefined}
                    />
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          <Panel title="Network Traffic" sub="Last 24 hours · simulated req/s" className="span-2" right={<span className="pill pill-info"><span className="pd" />live model</span>}>
            <BarChart data={traffic} height={190} />
            <div className="flex justify-between small muted mt-8">
              <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
            </div>
          </Panel>
        </div>

        <div className="grid grid-2 mt-24">
          <Panel title="Priority Findings" sub="Highest-severity open issues">
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>ID</th><th>Finding</th><th>Asset</th><th>Severity</th></tr>
                </thead>
                <tbody>
                  {openVulns.slice(0, 5).map((v) => (
                    <tr key={v.id}>
                      <td className="mono">{v.id}</td>
                      <td>{v.title}</td>
                      <td className="mono small">{v.asset}</td>
                      <td><span className={`pill ${severityPill[v.severity]}`}><span className="pd" />{v.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Recent Activity" sub="What Interu observed this session" right={<IconScan />}>
            <div className="feed">
              {recent.length === 0 && <div className="empty">No activity yet.</div>}
              {recent.map((e) => (
                <div className="ln" key={e.id}>
                  <span className="ts">{timeLabel(e.ts)}</span>
                  <span className={`lv ${e.level}`}>{e.level.toUpperCase()}</span>
                  <span className="msg">{e.message}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  )
}
