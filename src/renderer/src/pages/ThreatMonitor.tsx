import React from 'react'
import TopBar from '../components/TopBar'
import KevBadge from '../components/KevBadge'
import { cveCellText, cveCellTitle } from '../../../shared/kev'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconShieldAlert, IconBug } from '../components/icons'
import { severityPill, Severity } from '../data/mock'
import { useFindings } from '../store/findings'
import { useActivity, clearActivity } from '../store/activity'
import { priorityQueue, exposureByTarget, summarize, timeLabel } from '../../../shared/activity'
import { KEV_COUNT, KEV_CATALOG_VERSION } from '../../../shared/kev'

// Shows only what Interu itself observed: its findings, scans, scope decisions and
// intercepted requests. It is not an intrusion-detection system.
export default function ThreatMonitor() {
  const findings = useFindings()
  const events = useActivity()
  const s = summarize(findings)
  const queue = priorityQueue(findings, 10)
  const hosts = exposureByTarget(findings)

  return (
    <>
      <TopBar title="Exposure Monitor" sub="Findings, exposure and activity from your own scans" />
      <div className="content page">
        <Disclaimer>
          This page shows only what Interu itself observed: findings, scans, scope decisions and intercepted requests.
          It is <strong>not an intrusion-detection system</strong> and does not watch your computer or network for attacks.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Critical / High" value={s.critHigh} meta="findings" icon={<IconShieldAlert />} />
          <Stat label="Confirmed" value={s.confirmed} meta="proven" />
          <Stat label="Actively exploited (KEV)" value={s.kev} meta="CISA catalog" icon={<IconBug />} />
          <Stat label="Hosts with findings" value={s.hosts} />
        </div>
        <div className="small muted mt-8">CISA KEV snapshot {KEV_CATALOG_VERSION} · {KEV_COUNT} entries</div>

        <Panel title="Priority queue" sub="KEV first, then severity" className="mt-24">
          {queue.length === 0 ? (
            <div className="empty">No findings yet. Run a scan or active checks.</div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>Severity</th><th>Finding</th><th>Target</th><th>CVE</th></tr>
                </thead>
                <tbody>
                  {queue.map((f) => (
                    <tr key={f.key}>
                      <td><span className={`pill ${severityPill[f.severity as Severity]}`}><span className="pd" />{f.severity}</span></td>
                      <td>{f.name}</td>
                      <td className="mono small">{f.target}{f.port != null ? `:${f.port}` : ''}</td>
                      <td className="mono small">
                        <span title={cveCellTitle(f)}>{cveCellText(f)}</span>
                        <KevBadge f={f} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Exposure by host" sub="Findings per host, by severity" className="mt-24">
          {hosts.length === 0 ? (
            <div className="empty">Nothing to show yet.</div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>Host</th><th>Critical / High</th><th>Medium</th><th>Low / Info</th><th>KEV</th></tr>
                </thead>
                <tbody>
                  {hosts.map((h) => (
                    <tr key={h.host}>
                      <td className="mono small">{h.host}</td>
                      <td>{h.bySeverity.critical + h.bySeverity.high}</td>
                      <td>{h.bySeverity.medium}</td>
                      <td>{h.bySeverity.low + h.bySeverity.info}</td>
                      <td>{h.kev}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Activity"
          sub={`${events.length} events this session`}
          className="mt-24"
          right={
            <button className="btn btn-sm" onClick={clearActivity} disabled={events.length === 0}>Clear</button>
          }
        >
          {events.length === 0 ? (
            <div className="empty">No activity yet in this session.</div>
          ) : (
            <div className="feed" style={{ maxHeight: 520 }}>
              {events.map((e) => (
                <div className="ln" key={e.id}>
                  <span className="ts">{timeLabel(e.ts)}</span>
                  <span className={`lv ${e.level}`}>{e.level.toUpperCase()}</span>
                  <span className="msg">
                    <span className="mono" style={{ color: 'var(--silver-300)' }}>[{e.category}]</span> {e.message}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </>
  )
}
