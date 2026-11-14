import React, { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Stat, Meter, Note, NoteMsg } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import CopyButton from '../../components/CopyButton'
import { IconPlay, IconStop, IconBug, IconShieldAlert, IconCrosshair, IconCheck, IconSend } from '../../components/icons'
import { severityPill, Severity } from '../../lib/severity'
import { useSettings } from '../../store/store'
import { sendLive, rawFromParts, inScopeOrNote } from '../../lib/http'
import { setTransfer } from '../../store/transfer'
import { addFindings } from '../../store/findings'
import { pushActivity } from '../../store/activity'
import type { HttpReq, HttpRes } from '../../../../shared/http'
import { CrawlController, contentTypeLabel, type CrawlForm } from '../../../../shared/crawl'
import type { Finding, RuleSeverity, Confidence } from '../../../../shared/rules'
import { activeTemplates, buildActiveRequest, computeBaseline, matchActive } from '../../../../shared/rules'
import {
  planQueryParams, sqliErrorVerdict, xssReflectVerdict, idorProbeEligible, idNeighbors, idorVerdict,
  accessVerdict, csrfMissing, sqliFinding, xssFinding, idorFinding, accessFinding, csrfFinding,
  fileDisclosureVerdict, expressionVerdict, commandOutputVerdict, ssrfErrorVerdict, differentialFinding
} from '../../../../shared/webvuln'

const hasHttp = typeof window !== 'undefined' && !!window.ruy?.http
const sevPill = (s: RuleSeverity): string => severityPill[s as Severity]
const confPill = (c: Confidence): string => (c === 'confirmed' ? 'pill-ok' : 'pill-warn')
const clamp = (n: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, n))
const MAX_ACTIVE_REQUESTS = 1500
const MAX_ACTIVE_DURATION_MS = 15 * 60 * 1000

const ctOf = (res: HttpRes): string =>
  contentTypeLabel((res.rawHeaders || '').match(/^content-type:\s*(.+)$/im)?.[1])

export default function ActiveScan() {
  const [settings] = useSettings()
  const [target, setTarget] = useState('http://localhost:3000')
  const [depth, setDepth] = useState(2)
  const [maxPages, setMaxPages] = useState(40)
  const [concurrency, setConcurrency] = useState(8)
  const [doSqli, setDoSqli] = useState(true)
  const [doXss, setDoXss] = useState(true)
  const [doIdor, setDoIdor] = useState(true)
  const [doAccess, setDoAccess] = useState(true)
  const [doAdvanced, setDoAdvanced] = useState(true)
  const [doTemplates, setDoTemplates] = useState(true)

  const [findings, setFindings] = useState<Finding[]>([])
  const [sel, setSel] = useState<Finding | null>(null)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('')
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState<NoteMsg | null>(null)
  const [log, setLog] = useState<string[]>([])
  const [stats, setStats] = useState({ pages: 0, tested: 0, requests: 0 })

  const stopRef = useRef(false)
  const issuedRef = useRef(0)
  const startedRef = useRef(0)
  const navigate = useNavigate()
  const addLog = (s: string): void => setLog((l) => [...l.slice(-500), s])

  const get = async (url: string, override?: HttpReq): Promise<HttpRes> => {
    if (stopRef.current || issuedRef.current >= MAX_ACTIVE_REQUESTS || Date.now() - startedRef.current >= MAX_ACTIVE_DURATION_MS) {
      if (!stopRef.current) addLog('  ! request or time budget reached; stopped')
      stopRef.current = true
      return { ok: false, timingMs: 0, size: 0, error: 'Scan stopped or request budget reached' }
    }
    issuedRef.current++
    const res = await sendLive(override || { method: 'GET', url, headers: { 'User-Agent': 'Interu/1.0', Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }, timeoutMs: 12000 }, settings.scope)
    if (res.authLost && !stopRef.current) { stopRef.current = true; addLog('  ! login session expired — stopped. Paste a fresh token, then press Refresh.') }
    return res
  }

  const launch = async (): Promise<void> => {
    if (!hasHttp || !window.ruy?.http) { setNote({ kind: 'error', text: 'Bridge HTTP tidak tersedia (jalankan sebagai aplikasi desktop).' }); return }
    const seed = /^https?:\/\//i.test(target) ? target.trim() : 'http://' + target.trim()
    let host = ''
    try { host = new URL(seed).hostname } catch { setNote({ kind: 'error', text: 'URL/target tidak valid.' }); return }
    if (!inScopeOrNote(seed, settings.scope, 'active-scan')) {
      setNote({ kind: 'block', text: `${host} belum ada di Authorized scope. Tambahkan dulu di bar di bawah.` }); return
    }

    setNote(null); setRunning(true); setFindings([]); setSel(null); setProgress(0); setStats({ pages: 0, tested: 0, requests: 0 })
    stopRef.current = false
    issuedRef.current = 0
    startedRef.current = Date.now()
    setLog([`> active scan @ ${seed}`])

    const scope = settings.scope
    const collected: Finding[] = []
    const seenKeys = new Set<string>()
    let reqCount = 0
    const push = (f: Finding): void => {
      if (seenKeys.has(f.key)) return
      seenKeys.add(f.key)
      collected.push(f)
      setFindings([...collected])
      addLog(`  ${f.confidence === 'confirmed' ? 'CONFIRMED' : '~ suspected'} [${f.severity}] ${f.name} @ ${f.matchedAt || f.target}`)
    }

    // ---------- Phase 1: crawl to map the attack surface ----------
    setPhase('crawling')
    const ctrl = new CrawlController([seed], { maxDepth: depth, maxPages, sameHostOnly: true, includeSubdomains: true }, scope)
    const paramTargets = new Map<string, string>() // dedupe key -> a concrete URL with that path+param-set
    const idTargets: { url: string; param: string; value: string }[] = []
    const formSeen = new Set<string>()

    const crawlWorker = async (): Promise<void> => {
      while (!stopRef.current) {
        const item = ctrl.take()
        if (!item) return
        const res = await get(item.url); reqCount++
        if (res.blocked) { stopRef.current = true; addLog('  ! blocked by scope'); return }
        const type = ctOf(res)
        const parse = ['html', 'xml', 'js', 'json', 'text', 'yaml'].includes(type)
        const node = ctrl.record(item, { status: res.ok ? res.status ?? '-' : 'ERR', type, length: res.size, ms: res.timingMs, html: parse ? res.body || '' : '', error: res.ok ? undefined : res.error })
        // Access control (suspected) + CSRF (suspected) evaluated from the crawl hit itself.
        if (doAccess && res.ok) {
          const av = accessVerdict(item.url, res.status, res.body || '')
          if (av?.suspected) push(accessFinding(item.url))
          for (const form of node.forms as CrawlForm[]) {
            if (csrfMissing(form) && !formSeen.has(form.action)) { formSeen.add(form.action); push(csrfFinding(item.url, form.action)) }
          }
        }
        // Record a representative URL per distinct path+param-set for injection.
        const addParamUrl = (raw: string): void => {
          try {
            const u = new URL(raw)
            if (![...u.searchParams.keys()].length) return
            const key = u.origin + u.pathname + '?' + [...u.searchParams.keys()].sort().join(',')
            if (!paramTargets.has(key)) paramTargets.set(key, u.toString())
            if (doIdor) for (const [k, v] of u.searchParams.entries()) if (idorProbeEligible(u.toString(), k, v)) idTargets.push({ url: u.toString(), param: k, value: v })
          } catch { /* ignore */ }
        }
        if (node.params.length) addParamUrl(item.url)
        // GET forms (search boxes etc.) → synthesise a URL so their fields get
        // the same injection pipeline. POST forms are covered by CSRF/access.
        for (const form of node.forms as CrawlForm[]) {
          if (form.method.toUpperCase() !== 'GET' || form.inputs.length === 0) continue
          try {
            const fu = new URL(form.action)
            for (const inp of form.inputs) if (inp.name) fu.searchParams.set(inp.name, '1')
            addParamUrl(fu.toString())
          } catch { /* ignore */ }
        }
        setStats((s) => ({ ...s, pages: ctrl.done, requests: reqCount }))
        setProgress(Math.min(40, Math.round((ctrl.done / Math.max(ctrl.done + ctrl.pending, 1)) * 40)))
      }
    }
    await Promise.all(Array.from({ length: clamp(concurrency, 1, 16) }, () => crawlWorker()))
    addLog(`> surface: ${ctrl.done} pages, ${paramTargets.size} param endpoint(s), ${idTargets.length} id param(s)`)

    // ---------- Phase 2: injection probes on parameters ----------
    setPhase('testing params')
    const planList = [...paramTargets.values()].slice(0, 80)
    let pIdx = 0
    let tested = 0
    const injWorker = async (): Promise<void> => {
      while (!stopRef.current) {
        const i = pIdx++
        if (i >= planList.length) return
        const url = planList[i]
        for (const plan of planQueryParams(url)) {
          if (stopRef.current) return
          const baseRes = await get(plan.baselineUrl); reqCount++
          if (!baseRes.ok || baseRes.authLost || baseRes.truncated) continue
          const baseBody = baseRes.body || ''
          if (doSqli) {
            const q = plan.probes.find((p) => p.kind === 'sqli-quote')!
            const b = plan.probes.find((p) => p.kind === 'sqli-balanced')!
            const qRes = await get(q.url); reqCount++
            const bRes = await get(b.url); reqCount++
            const v = qRes.ok && bRes.ok && !qRes.truncated && !bRes.truncated && !qRes.authLost && !bRes.authLost
              ? sqliErrorVerdict(baseBody, qRes.body || '', bRes.body || '') : null
            if (v) push(sqliFinding(url, plan.param, v, rawFromParts('GET', (() => { try { return new URL(q.url).host } catch { return host } })(), (() => { try { const u = new URL(q.url); return u.pathname + u.search } catch { return '/' } })()), qRes.raw))
          }
          if (doXss) {
            const x = plan.probes.find((p) => p.kind === 'xss')!
            const xRes = await get(x.url); reqCount++
            const v = xssReflectVerdict(xRes.body || '', x.token!, ctOf(xRes) === 'html' ? 'text/html' : 'application/json')
            if (xRes.ok && !xRes.truncated && !xRes.authLost && v?.reflected) push(xssFinding(url, plan.param, x.token!, rawFromParts('GET', (() => { try { return new URL(x.url).host } catch { return host } })(), (() => { try { const u = new URL(x.url); return u.pathname + u.search } catch { return '/' } })()), xRes.raw))
          }
          if (doAdvanced) for (const kind of ['lfi', 'ssti', 'rce', 'ssrf', 'xxe'] as const) {
            const probe = plan.probes.find((p) => p.kind === kind)
            if (!probe || stopRef.current) continue
            const result = await get(probe.url); reqCount++
            if (!result.ok || result.truncated || result.authLost || result.blocked) continue
            const body = result.body || ''
            const payload = new URL(probe.url).searchParams.get(plan.param) || ''
            const hit = kind === 'lfi' || kind === 'xxe' ? fileDisclosureVerdict(baseBody, body)
              : kind === 'ssti' ? expressionVerdict(baseBody, body, probe.token || '', payload)
              : kind === 'rce' ? commandOutputVerdict(baseBody, body, probe.token || '', payload)
              : ssrfErrorVerdict(baseBody, body)
            if (hit) push(differentialFinding(kind, url, plan.param, `GET ${probe.url}`, result.raw || ''))
          }
          tested++
          setStats((s) => ({ ...s, tested, requests: reqCount }))
          setProgress(40 + Math.min(45, Math.round((tested / Math.max(planList.length, 1)) * 45)))
        }
      }
    }
    await Promise.all(Array.from({ length: clamp(concurrency, 1, 16) }, () => injWorker()))

    // ---------- Phase 3: IDOR candidates ----------
    if (doIdor && !stopRef.current) {
      setPhase('idor')
      const idSeen = new Set<string>()
      for (const t of idTargets.slice(0, 40)) {
        if (stopRef.current) break
        const k = t.url + '|' + t.param
        if (idSeen.has(k)) continue
        idSeen.add(k)
        const orig = await get(t.url); reqCount++
        for (const nv of idNeighbors(t.value)) {
          try {
            const u = new URL(t.url); u.searchParams.set(t.param, nv)
            const nb = await get(u.toString()); reqCount++
            const v = idorVerdict({ status: orig.status, body: orig.body || '' }, { status: nb.status, body: nb.body || '' })
            if (v?.suspected) { push(idorFinding(t.url, t.param, t.value, nv, v.reason)); break }
          } catch { /* ignore */ }
        }
        setStats((s) => ({ ...s, requests: reqCount }))
      }
    }

    // ---------- Phase 4: use the same exposure templates as Rule Engine ----------
    if (doTemplates && !stopRef.current) {
      setPhase('exposure templates')
      const baseUrl = new URL(seed).origin
      const soft404 = await get(`${baseUrl}/interu-not-here-${Date.now()}`); reqCount++
      if (soft404.ok && !soft404.truncated) {
        const baseline = computeBaseline(soft404)
        const templates = activeTemplates()
        let failures = 0
        for (let i = 0; i < templates.length && !stopRef.current; i++) {
          const req = buildActiveRequest(templates[i], baseUrl)
          if (!req || req.method !== 'GET') continue
          const res = await get(req.url, req); reqCount++
          if (res.status === 429 || res.status === 503) { stopRef.current = true; addLog(`  ! server backoff HTTP ${res.status}; stopped`); break }
          if (!res.ok) { if (++failures >= 5) { stopRef.current = true; addLog('  ! five consecutive request failures; stopped') }; continue }
          failures = 0
          const hit = matchActive(templates[i], req.url, res, { req, baseline })
          if (hit) push(hit)
          setStats((s) => ({ ...s, requests: reqCount }))
          setProgress(85 + Math.round(((i + 1) / templates.length) * 15))
          await new Promise((resolve) => window.setTimeout(resolve, 50))
        }
      } else addLog('  ! soft-404 baseline unavailable; exposure templates skipped')
    }

    const added = addFindings(collected)
    setProgress(100); setPhase('done'); setRunning(false)
    const conf = collected.filter((f) => f.confidence === 'confirmed').length
    addLog(`> done — ${collected.length} finding(s): ${conf} confirmed, ${collected.length - conf} suspected · ${reqCount} requests · ${added} new in store`)
    pushActivity({ ts: new Date().toISOString(), level: conf > 0 ? 'crit' : collected.length ? 'warn' : 'ok', category: 'finding', message: `Active scan ${host}: ${conf} confirmed, ${collected.length - conf} suspected`, target: seed })
  }

  const stop = (): void => { stopRef.current = true; setRunning(false); addLog('> stop requested') }

  const sendTo = (f: Finding, to: 'repeater' | 'intruder'): void => {
    const u = f.matchedAt || f.target
    try { const x = new URL(u); setTransfer({ to, target: x.origin, raw: rawFromParts('GET', x.host, x.pathname + x.search) }); navigate(to === 'repeater' ? '/web/repeater' : '/web/intruder') } catch { /* */ }
  }

  const confirmed = findings.filter((f) => f.confidence === 'confirmed').length

  return (
    <>
      <TopBar title="Active Scan · Automation" sub="Parameter probes and Rule Engine exposure templates" />
      <div className="content page">
        <Disclaimer>
          <strong>Active vulnerability scan.</strong> Enter a target: Interu crawls it, then injects oracle-based
          probes into query parameters. <strong>SQLi</strong> is confirmed only when a quote introduces a DB error
          and a balancing control clears it. Reflected XSS, IDOR, access and CSRF checks are
          <strong> suspected</strong> candidates for manual verification. Exposure templates also check for
          distinct file content. Real requests go only to hosts in your authorized scope.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-12 wrap">
          <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target-host:port"
            className="mono" style={{ flex: 1, minWidth: 260 }} onKeyDown={(e) => { if (e.key === 'Enter' && !running) void launch() }} />
          {!running ? (
            <button className="btn btn-primary" onClick={() => void launch()}><IconPlay />Launch Scan</button>
          ) : (
            <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
          )}
        </div>

        <div className="flex gap-16 items-center mb-16 wrap" style={{ fontSize: 13 }}>
          <label className="flex gap-6 items-center">Depth
            <input type="number" min={0} max={5} value={depth} disabled={running} onChange={(e) => setDepth(clamp(parseInt(e.target.value) || 0, 0, 5))} className="mono" style={{ width: 52 }} /></label>
          <label className="flex gap-6 items-center">Max pages
            <input type="number" min={1} max={500} value={maxPages} disabled={running} onChange={(e) => setMaxPages(clamp(parseInt(e.target.value) || 1, 1, 500))} className="mono" style={{ width: 66 }} /></label>
          <label className="flex gap-6 items-center">Concurrency
            <input type="number" min={1} max={16} value={concurrency} disabled={running} onChange={(e) => setConcurrency(clamp(parseInt(e.target.value) || 1, 1, 16))} className="mono" style={{ width: 52 }} /></label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doSqli} disabled={running} onChange={(e) => setDoSqli(e.target.checked)} />SQLi</label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doXss} disabled={running} onChange={(e) => setDoXss(e.target.checked)} />XSS</label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doIdor} disabled={running} onChange={(e) => setDoIdor(e.target.checked)} />IDOR</label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doAccess} disabled={running} onChange={(e) => setDoAccess(e.target.checked)} />Access/CSRF</label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doAdvanced} disabled={running} onChange={(e) => setDoAdvanced(e.target.checked)} />LFI/XXE/SSTI/RCE/SSRF signals</label>
          <label className="flex gap-6 items-center"><input type="checkbox" checked={doTemplates} disabled={running} onChange={(e) => setDoTemplates(e.target.checked)} />Rule Engine exposure templates</label>
        </div>

        <ScopeBar withAuth />
        {note && <Note kind={note.kind}>{note.text}</Note>}

        <div className="grid grid-4 mt-16">
          <Stat label="Pages crawled" value={stats.pages} meta={running ? phase : 'in scope'} icon={<IconCrosshair />} />
          <Stat label="Params tested" value={stats.tested} meta={`${stats.requests} requests`} icon={<IconShieldAlert />} />
          <Stat label="Confirmed" value={confirmed} meta="deterministic oracle" icon={<IconCheck />} />
          <Stat label="Suspected" value={findings.length - confirmed} meta="verify manually" icon={<IconBug />} />
        </div>

        {(running || findings.length > 0) && <div className="mt-16 mb-16"><Meter value={progress} tone={progress === 100 ? 'ok' : undefined} /></div>}

        <div className="split">
          <Panel title="Findings" sub={`${findings.length} total · ${confirmed} confirmed`}>
            {findings.length === 0 ? (
              <div className="empty">{running ? `${phase}…` : 'Enter a target and press Launch Scan.'}</div>
            ) : (
              <div className="table-wrap" style={{ maxHeight: 460 }}>
                <table className="data">
                  <thead><tr><th>Sev</th><th>Conf</th><th>Finding</th><th>Where</th></tr></thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.key} className={sel?.key === f.key ? 'clickable sel' : 'clickable'} tabIndex={0} onClick={() => setSel(f)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(f) } }}>
                        <td><span className={`pill ${sevPill(f.severity)}`}>{f.severity}</span></td>
                        <td><span className={`pill ${confPill(f.confidence)}`}>{f.confidence}</span></td>
                        <td className="small">{f.name}</td>
                        <td className="mono small" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.matchedAt || f.target}>
                          {(() => { try { const u = new URL(f.matchedAt || f.target); return u.pathname + u.search } catch { return f.matchedAt || f.target } })()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Detail" sub={sel ? sel.name : 'select a finding'}>
            {!sel ? (
              <div className="empty" style={{ minHeight: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Select a finding to see the evidence.</div>
            ) : (
              <div>
                <div className="flex gap-16 wrap mb-12" style={{ fontSize: 13 }}>
                  <span>Severity <span className={`pill ${sevPill(sel.severity)}`}>{sel.severity}</span></span>
                  <span>Confidence <span className={`pill ${confPill(sel.confidence)}`}>{sel.confidence}</span></span>
                  {sel.cwe?.[0] && <span className="mono">{sel.cwe[0]}</span>}
                </div>
                <div className="mb-12"><div className="code-head"><span>Evidence</span></div><div style={{ fontSize: 13, lineHeight: 1.6 }}>{sel.evidence}</div></div>
                {sel.remediation && <div className="mb-12"><div className="code-head"><span>Remediation</span></div><div style={{ fontSize: 13, lineHeight: 1.6 }}>{sel.remediation}</div></div>}
                <div className="flex gap-8 mb-8 wrap">
                  <button className="btn btn-sm" onClick={() => sendTo(sel, 'repeater')}><IconSend />Repeater</button>
                  <button className="btn btn-sm" onClick={() => sendTo(sel, 'intruder')}><IconSend />Intruder</button>
                </div>
                {sel.response && (<><div className="code-head"><span>Response evidence</span><CopyButton text={sel.response} /></div><div className="code-pane" style={{ minHeight: 160, maxHeight: 260 }}>{sel.response.slice(0, 16000)}</div></>)}
              </div>
            )}
          </Panel>
        </div>

        {log.length > 0 && (
          <Panel title="Scan Log" sub={`${log.length} lines`}>
            <div className="code-pane" style={{ minHeight: 120, maxHeight: 220 }}>{log.join('\n')}</div>
          </Panel>
        )}
      </div>
    </>
  )
}
