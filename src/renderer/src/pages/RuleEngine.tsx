import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Stat, Meter } from '../components/ui'
import { IconShieldAlert, IconPlay, IconCheck, IconBug, IconTrash } from '../components/icons'
import ScopeBar from '../components/ScopeBar'
import { severityPill, Severity } from '../data/mock'
import { useSettings } from '../store/store'
import { useFindings, addFindings, clearFindings } from '../store/findings'
import { hostInScope } from '../../../shared/http'
import {
  TEMPLATES, activeTemplates, buildActiveRequest, matchActive,
  Confidence, RuleSeverity, Finding
} from '../../../shared/rules'

const confPill = (c: Confidence): string => (c === 'confirmed' ? 'pill-ok' : 'pill-warn')
const sevPill = (s: RuleSeverity): string => severityPill[s as Severity]

const hasHttp = typeof window !== 'undefined' && !!window.ruy?.http

export default function RuleEngine() {
  const [settings] = useSettings()
  const findings = useFindings()
  const [target, setTarget] = useState('http://127.0.0.1/')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [log, setLog] = useState<string[]>([])
  const [note, setNote] = useState<string | null>(null)
  const [confFilter, setConfFilter] = useState<Confidence | 'all'>('all')
  const [sevFilter, setSevFilter] = useState<RuleSeverity | 'all'>('all')

  const actives = activeTemplates()

  const counts = useMemo(() => ({
    total: findings.length,
    confirmed: findings.filter((f) => f.confidence === 'confirmed').length,
    suspected: findings.filter((f) => f.confidence === 'suspected').length,
    bad: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length
  }), [findings])

  const rows = useMemo(
    () => findings.filter((f) => (confFilter === 'all' || f.confidence === confFilter) && (sevFilter === 'all' || f.severity === sevFilter)),
    [findings, confFilter, sevFilter]
  )

  const runActive = async () => {
    if (!hasHttp || !window.ruy?.http) { setNote('Bridge HTTP tidak tersedia (jalankan sebagai aplikasi desktop).'); return }
    let host = ''
    try { host = new URL(/^https?:\/\//i.test(target) ? target : 'http://' + target).hostname } catch { setNote('URL target tidak valid.'); return }
    if (!hostInScope(/^https?:\/\//i.test(target) ? target : 'http://' + target, settings.scope)) {
      setNote(`⛔ ${host} belum ada di Authorized scope. Tambahkan dulu di bar di atas.`)
      return
    }
    setNote(null)
    setRunning(true)
    setProgress(0)
    setLog([`> running ${actives.length} active check(s) against ${target}`])
    const collected: Finding[] = []
    for (let i = 0; i < actives.length; i++) {
      const t = actives[i]
      const req = buildActiveRequest(t, target)
      if (!req) continue
      setLog((l) => [...l, `> probe ${t.info.name}  (${req.method} ${req.url})`])
      try {
        const res = await window.ruy.http.send(req, settings.scope)
        if (res.blocked) { setLog((l) => [...l, `  ⛔ blocked by scope`]); break }
        const finding = matchActive(t, req.url, res)
        if (finding) {
          collected.push(finding)
          setLog((l) => [...l, `  ✔ CONFIRMED — ${finding.name} [${finding.severity}]  (${finding.evidence})`])
        } else {
          setLog((l) => [...l, `  · not present (status ${res.status ?? '-'})`])
        }
      } catch (e) {
        setLog((l) => [...l, `  ! error: ${(e as Error).message}`])
      }
      setProgress(Math.round(((i + 1) / actives.length) * 100))
    }
    const added = addFindings(collected)
    setLog((l) => [...l, `> done — ${collected.length} confirmed, ${added} new`])
    setRunning(false)
  }

  return (
    <>
      <TopBar title="Rule Engine" sub="Detection — Nuclei-style templates (Suspected → Confirmed)" />
      <div className="content page">
        <Disclaimer>
          The Rule Engine is a detection layer: it matches <strong>data-driven templates</strong> against signals
          already collected by the <strong>Network Scanner</strong> and <strong>Proxy</strong> (passive →
          <em> Suspected/Confirmed</em>), and can send <strong>scope-gated active probes</strong> to prove findings
          (<em>oracle → Confirmed</em>). No exploitation is performed; only authorized targets are probed.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Templates loaded" value={TEMPLATES.length} icon={<IconShieldAlert />} meta={`${actives.length} active`} />
          <Stat label="Findings" value={counts.total} icon={<IconBug />} />
          <Stat label="Confirmed" value={counts.confirmed} meta="proven" />
          <Stat label="Critical / High" value={counts.bad} meta="need action" />
        </div>

        <ScopeBar />

        <Panel title="Active verification (oracle)" sub="Scope-gated HTTP probes that prove a finding → Confirmed" className="mt-8">
          <div className="grid grid-3" style={{ alignItems: 'end' }}>
            <label className="field" style={{ gridColumn: 'span 2' }}>
              <span className="lab">Target base URL</span>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} disabled={running} placeholder="http://127.0.0.1/  ·  https://host.example.com/" />
            </label>
            <div className="flex gap-12">
              <button className="btn btn-primary" onClick={runActive} disabled={running || !hasHttp}>
                <IconPlay />{running ? 'Running…' : 'Run active checks'}
              </button>
            </div>
          </div>
          {!hasHttp && <div className="small muted mt-12">HTTP bridge unavailable — run the desktop app to use active checks.</div>}
          {note && <div className="small mt-12" style={{ color: 'var(--danger, #d6594f)' }}>{note}</div>}
          {(running || progress > 0) && (
            <div className="mt-16">
              <div className="flex justify-between small muted" style={{ marginBottom: 6 }}><span>{running ? 'Probing…' : 'Done'}</span><span className="mono">{progress}%</span></div>
              <Meter value={progress} tone={!running ? 'ok' : undefined} />
            </div>
          )}
          {log.length > 0 && (
            <div className="feed mt-16">
              {log.map((l, i) => <div className="ln" key={i}><span className="msg text-mono">{l}</span></div>)}
            </div>
          )}
        </Panel>

        <Panel
          title="Findings"
          sub={`${rows.length} shown · fed by Scanner, Proxy & active probes`}
          className="mt-24"
          right={
            <div className="flex gap-12 items-center">
              <select value={confFilter} onChange={(e) => setConfFilter(e.target.value as Confidence | 'all')} style={{ width: 140 }}>
                <option value="all">All confidence</option>
                <option value="confirmed">Confirmed</option>
                <option value="suspected">Suspected</option>
              </select>
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as RuleSeverity | 'all')} style={{ width: 140 }}>
                <option value="all">All severities</option>
                {(['critical', 'high', 'medium', 'low', 'info'] as RuleSeverity[]).map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <button className="btn btn-sm btn-danger" onClick={() => clearFindings()} disabled={findings.length === 0}><IconTrash size={14} />Clear</button>
            </div>
          }
        >
          {rows.length === 0 ? (
            <div className="empty">
              No findings yet. Run a <strong>Network Scan</strong>, browse through the <strong>Proxy</strong>, or run
              <strong> active checks</strong> above — findings will appear here.
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Evidence</th><th>CVE</th><th>Src</th></tr>
                </thead>
                <tbody>
                  {rows.map((f) => (
                    <tr key={f.key}>
                      <td><span className={`pill ${sevPill(f.severity)}`}><span className="pd" />{f.severity}</span></td>
                      <td>
                        <span className={`pill ${confPill(f.confidence)}`}>
                          {f.confidence === 'confirmed' && <IconCheck size={12} />}<span className="pd" />{f.confidence}
                        </span>
                      </td>
                      <td>
                        {f.name}
                        {f.remediation && <div className="small muted">{f.remediation}</div>}
                      </td>
                      <td className="mono small">{f.target}{f.port != null ? `:${f.port}` : ''}</td>
                      <td className="small muted" style={{ maxWidth: 260 }} title={f.evidence}>{f.evidence}</td>
                      <td className="mono small">{f.cve?.join(', ') || '—'}</td>
                      <td className="small muted">{f.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Template library" sub={`${TEMPLATES.length} data-driven rules`} className="mt-24">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Severity</th><th>Yields</th><th>Tags</th><th>CVE</th></tr></thead>
              <tbody>
                {TEMPLATES.map((t) => (
                  <tr key={t.id}>
                    <td className="mono small">{t.id}</td>
                    <td className="small">{t.info.name}</td>
                    <td className="small muted">{t.kind}</td>
                    <td><span className={`pill ${sevPill(t.info.severity)}`}><span className="pd" />{t.info.severity}</span></td>
                    <td><span className={`pill ${confPill(t.confidence)}`}><span className="pd" />{t.confidence}</span></td>
                    <td className="small muted">{t.info.tags?.join(', ') || '—'}</td>
                    <td className="mono small">{t.info.classification?.cve?.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  )
}
