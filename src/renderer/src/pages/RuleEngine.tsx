import React, { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/TopBar'
import { isProductLevel } from '../../../shared/activity'
import KevBadge from '../components/KevBadge'
import { cveCellText, cveCellTitle } from '../../../shared/kev'
import { Panel, Disclaimer, Stat, Meter, Note, NoteMsg } from '../components/ui'
import { IconShieldAlert, IconPlay, IconCheck, IconBug, IconTrash, IconSend } from '../components/icons'
import ScopeBar from '../components/ScopeBar'
import CopyButton from '../components/CopyButton'
import { severityPill, Severity } from '../lib/severity'
import { useSettings } from '../store/store'
import { useFindings, addFindings, clearFindings, removeFinding } from '../store/findings'
import { setTransfer } from '../store/transfer'
import { rawFromParts, inScopeOrNote, noteAuthLost } from '../lib/http'
import { noteScopeBlock } from '../store/activity'
import { getAdvice } from '../../../shared/advice'
import { KEV_COUNT, KEV_CATALOG_VERSION } from '../../../shared/kev'
import type { AttackKind } from '../../../shared/advice'
import {
  TEMPLATES, activeTemplates, buildActiveRequest, matchActive, requestVars, computeBaseline,
  Confidence, RuleSeverity, Finding, Baseline
} from '../../../shared/rules'

const attackKindPill = (k: AttackKind): string => (k === 'verify' ? 'pill-ok' : k === 'operator' ? 'pill-warn' : 'pill-info')

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
  const [note, setNote] = useState<NoteMsg | null>(null)
  const [confFilter, setConfFilter] = useState<Confidence | 'all'>('all')
  const [sevFilter, setSevFilter] = useState<RuleSeverity | 'all'>('all')
  const [showSuperseded, setShowSuperseded] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const navigate = useNavigate()

  const actives = activeTemplates()

  const httpUrlOf = (f: Finding): string | null => {
    const u = f.matchedAt || f.target
    return /^https?:\/\//i.test(u) ? u : null
  }
  const sendTo = (f: Finding, to: 'repeater' | 'intruder'): void => {
    const u = httpUrlOf(f); if (!u) return
    try {
      const x = new URL(u)
      setTransfer({ to, target: x.origin, raw: rawFromParts('GET', x.host, x.pathname + x.search) })
      navigate(to === 'repeater' ? '/web/repeater' : '/web/intruder')
    } catch { /* ignore bad url */ }
  }
  const retest = async (f: Finding): Promise<void> => {
    const t = TEMPLATES.find((x) => x.id === f.templateId)
    if (!t || t.kind !== 'http-active' || !window.ruy?.http) return
    let base = f.matchedAt || f.target
    try { base = new URL(base).origin } catch { /* keep */ }
    const req = buildActiveRequest(t, base)
    if (!req) return
    setLog((l) => [...l, `> re-test ${t.info.name} @ ${base}`])
    try {
      const res = await window.ruy.http.send(req, settings.scope)
      if (res.blocked) { noteScopeBlock(req.url, 'rule-engine'); setLog((l) => [...l, '  ! blocked by scope']); return }
      const still = matchActive(t, req.url, res, { req })
      if (still) setLog((l) => [...l, `  ✗ still present — ${still.evidence}`])
      else { removeFinding(f.key); setOpen(null); setLog((l) => [...l, '  + resolved — removed from findings']) }
    } catch (e) { setLog((l) => [...l, `  ! ${(e as Error).message}`]) }
  }

  const counts = useMemo(() => {
    const live = findings.filter((f) => !f.superseded)
    return {
      total: live.length,
      confirmed: live.filter((f) => f.confidence === 'confirmed').length,
      suspected: live.filter((f) => f.confidence === 'suspected').length,
      bad: live.filter((f) => f.severity === 'critical' || f.severity === 'high').length
    }
  }, [findings])

  const rows = useMemo(
    () => findings.filter((f) =>
      (showSuperseded || !f.superseded) &&
      (confFilter === 'all' || f.confidence === confFilter) &&
      (sevFilter === 'all' || f.severity === sevFilter)),
    [findings, confFilter, sevFilter, showSuperseded]
  )

  const runActive = async () => {
    if (!hasHttp || !window.ruy?.http) { setNote({ kind: 'error', text: 'Bridge HTTP tidak tersedia (jalankan sebagai aplikasi desktop).' }); return }
    const full = /^https?:\/\//i.test(target) ? target : 'http://' + target
    let host = ''
    try { host = new URL(full).hostname } catch { setNote({ kind: 'error', text: 'URL target tidak valid.' }); return }
    if (!inScopeOrNote(full, settings.scope, 'rule-engine')) {
      setNote({ kind: 'block', text: `${host} belum ada di Authorized scope. Tambahkan dulu di bar di atas.` })
      return
    }
    setNote(null)
    setRunning(true)
    setProgress(0)
    setLog([`> running ${actives.length} active check(s) against ${target}`])

    // --- soft-404 / catch-all baseline: probe a path that cannot exist ---
    const vars = requestVars(target)
    const baseProbe = `/interu-not-here-${vars.RandomString}.html`
    let baseline: Baseline | undefined
    try {
      const baseRes = await window.ruy.http.send({ method: 'GET', url: vars.BaseURL + baseProbe, headers: {}, timeoutMs: 8000 }, settings.scope)
      if (baseRes.blocked) { noteScopeBlock(vars.BaseURL + baseProbe, 'rule-engine'); setLog((l) => [...l, `  ! blocked by scope`]); setRunning(false); return }
      if (baseRes.authLost) {
        noteAuthLost(vars.BaseURL)
        setLog((l) => [...l, '  ! login session expired — dibatalkan'])
        setNote({ kind: 'error', text: 'Sesi login habis. Tempel token baru lalu tekan Refresh.' })
        setRunning(false); return
      }
      if (!baseRes.ok) {
        setLog((l) => [...l, `  ! host tidak bisa dihubungi (${baseRes.error || 'unknown'}) — dibatalkan`])
        setNote({ kind: 'error', text: `Host ${host} tidak merespons. Pastikan target hidup & URL benar.` })
        setRunning(false); return
      }
      baseline = computeBaseline(baseRes)
      setLog((l) => [...l, `> baseline: unknown path → status ${baseRes.status ?? '-'} (${baseline?.catchAll ? 'CATCH-ALL 2xx — status-only checks akan di-demote' : 'server membedakan 404, bagus'})`])
    } catch (e) {
      setLog((l) => [...l, `  ! baseline error: ${(e as Error).message} — lanjut tanpa baseline`])
    }

    // Probe with bounded concurrency (hundreds of templates). Only matches are
    // logged, so the console stays readable. A scope block stops all workers.
    const http = window.ruy.http
    const collected: Finding[] = []
    let idx = 0
    let done = 0
    let blocked = false
    const CONCURRENCY = 10
    const worker = async (): Promise<void> => {
      while (!blocked) {
        const i = idx++
        if (i >= actives.length) return
        const t = actives[i]
        const req = buildActiveRequest(t, target)
        if (req) {
          try {
            const res = await http.send(req, settings.scope)
            if (res.authLost) { blocked = true; noteAuthLost(req.url); setLog((l) => [...l, '  ! login session expired — stopped']); return }
            if (res.blocked) { blocked = true; noteScopeBlock(req.url, 'rule-engine'); setLog((l) => [...l, `  ! blocked by scope — stopped`]); return }
            const finding = matchActive(t, req.url, res, { req, baseline })
            if (finding) {
              collected.push(finding)
              const tag = finding.confidence === 'confirmed' ? 'CONFIRMED' : '~ suspected'
              setLog((l) => [...l, `  ${tag} — ${finding.name} [${finding.severity}]  ${req.url}`])
            }
          } catch { /* per-probe error ignored */ }
        }
        done++
        if (done % 5 === 0 || done === actives.length) setProgress(Math.round((done / actives.length) * 100))
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()))
    setProgress(100)
    const added = addFindings(collected)
    setLog((l) => [...l, `> done — ${actives.length} probes, ${collected.length} matched, ${added} new`])
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
          (<em>oracle → Confirmed</em>). Probes only <strong>read</strong> — no exploitation — and run a soft-404
          baseline first to suppress false positives. Only authorized targets are probed.
        </Disclaimer>

        <div className="grid grid-5 mt-16">
          <Stat label="Templates loaded" value={TEMPLATES.length} icon={<IconShieldAlert />} meta={`${actives.length} active`} />
          <Stat label="Findings" value={counts.total} icon={<IconBug />} />
          <Stat label="Confirmed" value={counts.confirmed} meta="proven" />
          <Stat label="Critical / High" value={counts.bad} meta="need action" />
          <Stat label="CISA KEV" value={KEV_COUNT} icon={<IconBug />} meta={`snapshot ${KEV_CATALOG_VERSION}`} />
        </div>

        <ScopeBar withAuth />

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
          {note && <div className="mt-12"><Note kind={note.kind}>{note.text}</Note></div>}
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
              <label className="small muted flex gap-12 items-center" style={{ whiteSpace: 'nowrap' }}>
                <input type="checkbox" checked={showSuperseded} onChange={(e) => setShowSuperseded(e.target.checked)} />
                superseded
              </label>
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
                    <React.Fragment key={f.key}>
                      <tr onClick={() => setOpen(open === f.key ? null : f.key)} style={{ cursor: 'pointer', opacity: f.superseded ? 0.5 : 1 }}>
                        <td><span className={`pill ${sevPill(f.severity)}`}><span className="pd" />{f.severity}</span></td>
                        <td>
                          <span className={`pill ${confPill(f.confidence)}`}>
                            {f.confidence === 'confirmed' && <IconCheck size={12} />}<span className="pd" />{f.confidence}
                          </span>
                          {f.superseded && <span className="small muted"> ·superseded</span>}
                        </td>
                        <td>
                          {f.name}
                          {f.remediation && <div className="small muted">{f.remediation}</div>}
                        </td>
                        <td className="mono small">{f.target}{f.port != null ? `:${f.port}` : ''}</td>
                        <td className="small muted" style={{ maxWidth: 260 }} title={f.evidence}>{f.evidence}</td>
                        <td className="mono small">
                          <span title={cveCellTitle(f)}>{cveCellText(f)}</span>
                          <KevBadge f={f} />
                        </td>
                        <td className="small muted">{f.source}</td>
                      </tr>
                      {open === f.key && (
                        <tr className="detail-row">
                          <td colSpan={7}>
                            <div className="small" style={{ padding: '8px 4px', display: 'grid', gap: 8 }}>
                              {f.description && <div>{f.description}</div>}
                              <div className="flex gap-12 small muted" style={{ flexWrap: 'wrap' }}>
                                <span>template: <span className="mono">{f.templateId}</span></span>
                                {f.cwe?.length ? <span>CWE: <span className="mono">{f.cwe.join(', ')}</span></span> : null}
                                {f.cvss != null ? <span>CVSS: <span className="mono">{f.cvss}</span></span> : null}
                                {f.mitre?.length ? <span>ATT&CK: <span className="mono">{f.mitre.join(', ')}</span></span> : null}
                                {f.tags?.length ? <span>tags: {f.tags.join(', ')}</span> : null}
                              </div>
                              {isProductLevel(f) && f.cve?.length ? (
                                <div className="mono small">KEV CVEs for this product (not matched to your version): {f.cve.join(', ')}</div>
                              ) : null}
                              {f.extracted && Object.keys(f.extracted).length > 0 && (
                                <div className="mono small">extracted: {Object.entries(f.extracted).map(([k, v]) => `${k}=[${v.join(', ')}]`).join('  ')}</div>
                              )}
                              {f.matchedAt && <div className="mono small muted">matched at: {f.matchedAt}</div>}

                              {(() => {
                                const adv = getAdvice(f)
                                const url = httpUrlOf(f)
                                const snippet = (label: string, code: string): React.JSX.Element => (
                                  <div className="mt-8">
                                    <div className="code-head"><span>{label}</span><CopyButton text={code} /></div>
                                    <pre className="code-pane allow-select" style={{ minHeight: 0, padding: 10, margin: 0 }}>{code}</pre>
                                  </div>
                                )
                                return (
                                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12, marginTop: 10 }}>
                                    <div className="sub-block">
                                      <div style={{ fontWeight: 600, marginBottom: 6 }}>🛡 Defense — patching</div>
                                      <div className="small">{adv.defense.summary}</div>
                                      <ol className="small" style={{ margin: '8px 0 0', paddingLeft: 18 }}>
                                        {adv.defense.steps.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
                                      </ol>
                                      {adv.defense.configs?.map((c, i) => <React.Fragment key={i}>{snippet(c.label, c.code)}</React.Fragment>)}
                                      {f.source === 'active' && hasHttp && (
                                        <button className="btn btn-sm mt-8" onClick={() => retest(f)} disabled={running}><IconCheck size={14} />Re-test fix</button>
                                      )}
                                    </div>
                                    <div className="sub-block">
                                      <div style={{ fontWeight: 600, marginBottom: 6 }}>
                                        ⚔ Attack <span className={`pill ${attackKindPill(adv.attack.kind)}`}><span className="pd" />{adv.attack.kind}</span>
                                        {!adv.attack.safe && <span className="pill pill-crit" style={{ marginLeft: 6 }}><span className="pd" />destructive-capable</span>}
                                      </div>
                                      <div className="small">{adv.attack.summary}</div>
                                      <ol className="small" style={{ margin: '8px 0 0', paddingLeft: 18 }}>
                                        {adv.attack.steps.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
                                      </ol>
                                      {adv.attack.poc && snippet('proof of concept', adv.attack.poc)}
                                      {adv.attack.payloads && adv.attack.payloads.length > 0 && snippet('payloads', adv.attack.payloads.join('\n'))}
                                      {url && (
                                        <div className="flex gap-8 mt-8">
                                          <button className="btn btn-sm" onClick={() => sendTo(f, 'repeater')}><IconSend />Send to Repeater</button>
                                          <button className="btn btn-sm" onClick={() => sendTo(f, 'intruder')}><IconSend />Send to Intruder</button>
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                )
                              })()}
                              {f.request && (
                                <details><summary className="small muted">request <CopyButton text={f.request} label="copy" /></summary>
                                  <pre className="text-mono small allow-select" style={{ whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto' }}>{f.request}</pre></details>
                              )}
                              {f.response && (
                                <details><summary className="small muted">response <CopyButton text={f.response} label="copy" /></summary>
                                  <pre className="text-mono small allow-select" style={{ whiteSpace: 'pre-wrap', maxHeight: 240, overflow: 'auto' }}>{f.response}</pre></details>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
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
