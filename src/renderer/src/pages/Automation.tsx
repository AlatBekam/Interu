import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/TopBar'
import ScopeBar from '../components/ScopeBar'
import { Panel, Note } from '../components/ui'
import { DEFAULT_AUTOMATION, type AutomationOptions, type AutomationSnapshot } from '../../../shared/automation'
import { useSettings } from '../store/store'
import { setTransfer } from '../store/transfer'
import { rawFromParts } from '../lib/http'
import { severityPill } from '../lib/severity'
import type { Finding } from '../../../shared/rules'

const OWASP_2025 = [
  ['A01 Broken Access Control', 'IDOR and sensitive-route candidates; second identity required'],
  ['A02 Security Misconfiguration', 'Security headers, cookies, exposed files and admin surfaces'],
  ['A03 Software Supply Chain Failures', 'Exposed build/CI manifests only; dependency integrity requires manual review'],
  ['A04 Cryptographic Failures', 'HTTPS/HSTS and cleartext credential signals; cryptographic design requires manual review'],
  ['A05 Injection', 'Differential SQLi, XSS, LFI, XXE, SSTI, RCE and SSRF signals'],
  ['A06 Insecure Design', 'Manual business-logic and threat-model review required'],
  ['A07 Authentication Failures', 'Session expiry and authentication surface signals; account-flow review required'],
  ['A08 Software or Data Integrity Failures', 'Manual signature, update and trust-boundary review required'],
  ['A09 Security Logging & Alerting Failures', 'Manual event and alert verification required'],
  ['A10 Mishandling of Exceptional Conditions', 'Stack traces, errors and debug exposure signals']
] as const

export default function Automation() {
  const [options,setOptions] = useState<AutomationOptions>({...DEFAULT_AUTOMATION})
  const [run,setRun] = useState<AutomationSnapshot | null>(null)
  const [error,setError] = useState('')
  const [starting,setStarting] = useState(false)
  const [browserDiscovery,setBrowserDiscovery] = useState<{pages:number; forms:Array<{url:string;action:string;method:string;fields:string[];kind:string}>; note:string; accountFlow?:string} | null>(null)
  const [settings] = useSettings()
  const navigate = useNavigate()
  const bridge = window.ruy?.automation
  const busy = starting || run?.status === 'running'
  useEffect(() => {
    if (!bridge) return
    void bridge.status().then(setRun).catch(e=>setError(String(e)))
    return bridge.onProgress(setRun)
  }, [bridge])
  const start = async (exploreBrowser = false, autoAccount = false): Promise<void> => {
    if (!bridge) return
    setError(''); setStarting(true)
    try {
      await window.ruy.proxy.setScope(settings.scope)
      let browserSeeds: string[] = []
      if (exploreBrowser) {
        const status = await window.ruy.proxy.status()
        if (!status.running) {
          const proxy = await window.ruy.proxy.start(8080)
          if (!proxy.ok) throw new Error(proxy.error || 'Could not start proxy')
        }
        await window.ruy.proxy.setIntercept(false)
        if (autoAccount) await window.ruy.proxy.protectLogs(true)
        const opened = await window.ruy.proxy.openBrowser(options.target)
        if (!opened.ok) throw new Error(opened.error || 'Could not open Interu Browser')
        const discovery = await bridge.discoverBrowser(options.target, Math.min(options.maxPages, 12), autoAccount)
        browserSeeds = discovery.urls
        setBrowserDiscovery(discovery)
      } else setBrowserDiscovery(null)
      setRun(await bridge.start({...options,browserSeeds}))
    } catch(e) {setError((e as Error).message)} finally {setStarting(false)}
  }
  const exportReport = (): void => {
    if (!run) return
    const blob = new Blob([JSON.stringify({schema:'interu-run-v1',exportedAt:new Date().toISOString(),...run},null,2)],{type:'application/json'})
    const url=URL.createObjectURL(blob), a=document.createElement('a')
    a.href=url; a.download=`interu-${run.id}.json`; a.click(); window.setTimeout(()=>URL.revokeObjectURL(url),1000)
  }
  const inspect = (finding: Finding): void => {
    try {
      const u = new URL(finding.matchedAt || finding.target)
      setTransfer({to:'repeater',target:u.origin,raw:rawFromParts('GET',u.host,u.pathname+u.search)})
      navigate('/web/repeater')
    } catch {setError('This finding has no HTTP URL')}
  }
  const numeric = (key: 'maxPages'|'maxRequests'|'maxDepth'|'delayMs'|'timeoutMs'|'maxDurationMs',label:string,min:number,max:number): React.ReactNode => (
    <label className="field"><span className="lab">{label}</span><input type="number" min={min} max={max} disabled={busy} value={options[key]} onChange={e=>setOptions({...options,[key]:Number(e.target.value)})}/></label>
  )
  return <>
    <TopBar title="Pentest Automation" sub="Crawl, inspect, verify and retain evidence in one bounded run" />
    <div className="content page">
      <Panel title="Run configuration" sub="One origin per run; existing manual tools remain available">
        <label className="field"><span className="lab">Target URL</span><input value={options.target} disabled={busy} onChange={e=>setOptions({...options,target:e.target.value})} placeholder="https://target.example.com/app" /></label>
        <div className="grid grid-3 mt-16">
          {numeric('maxPages','Maximum pages',1,200)}{numeric('maxDepth','Crawl depth',0,5)}{numeric('maxRequests','Request budget',1,3000)}
          {numeric('delayMs','Minimum request interval (ms)',100,10000)}{numeric('timeoutMs','Request timeout (ms)',500,15000)}{numeric('maxDurationMs','Total time budget (ms)',1000,1800000)}
        </div>
        <div className="flex gap-16 wrap mt-16">
          <label><input type="checkbox" checked={options.activeChecks} disabled={busy} onChange={e=>setOptions({...options,activeChecks:e.target.checked})}/> Exposure template checks</label>
          <label><input type="checkbox" checked={options.parameterChecks} disabled={busy} onChange={e=>setOptions({...options,parameterChecks:e.target.checked})}/> Query probes (SQLi, XSS, LFI, XXE, SSTI, RCE, SSRF and IDOR signals)</label>
        </div>
        <p className="small muted">Runs crawl and passive analysis first. Optional parameter probes and exposure checks follow within the same budget. Redirects stay on the exact origin. Authentication expiry, repeated failures and server backoff stop the run and keep partial results.</p>
        <div className="flex gap-12 mt-16">
          <button className="btn btn-primary" disabled={busy || !bridge} onClick={()=>void start()}>{busy?'Running…':'Start automation'}</button>
          <button className="btn" disabled={busy || !bridge} onClick={()=>void start(true)}>Explore browser + run</button>
          <button className="btn" disabled={busy || !bridge} onClick={()=>void start(true,true)}>Explore + create test account + run</button>
          <button className="btn btn-danger" disabled={!busy} onClick={()=>void bridge?.cancel().catch(e=>setError(String(e)))}>Stop run</button>
          <button className="btn" disabled={!run?.id || busy} onClick={exportReport}>Export evidence JSON</button>
        </div>
      </Panel>
      <ScopeBar withAuth />
      {browserDiscovery && <Panel title="Browser discovery" sub={`${browserDiscovery.pages} same-origin pages opened through the proxy`} className="mt-16">
        <p className="small muted">{browserDiscovery.note} Forms are recorded as surfaces, not vulnerabilities or proof of login.</p>
        <div className="table-wrap"><table className="data"><thead><tr><th>Type</th><th>Method</th><th>Page</th><th>Fields</th></tr></thead><tbody>
          {browserDiscovery.forms.map((f,i)=><tr key={`${f.url}-${i}`}><td>{f.kind}</td><td>{f.method}</td><td className="mono small">{f.url}</td><td className="small">{f.fields.join(', ')}</td></tr>)}
        </tbody></table></div>
      </Panel>}
      <Panel title="OWASP Top 10:2025 coverage" sub="Rule signals and required manual checks; this is not a certification" className="mt-16">
        <div className="table-wrap"><table className="data"><thead><tr><th>Category</th><th>What this run can assess</th></tr></thead><tbody>
          {OWASP_2025.map(([category,coverage])=><tr key={category}><td>{category}</td><td>{coverage}</td></tr>)}
        </tbody></table></div>
        <p className="small muted">An empty finding list does not prove that any category is secure. Confirm candidates and complete the manual checks in the test plan.</p>
      </Panel>
      {error && <Note kind="error">{error}</Note>}
      {run?.id && <>
        <Panel title="Run status" sub={`${run.status} · ${run.phase}`} className="mt-16">
          <div className="flex gap-16 wrap"><span>{run.requests} requests</span><span>{run.pages} pages</span><span>{run.findings.length} findings</span><span>{run.errors} transport errors</span></div>
          <p className="small muted">{run.reason || 'In progress. You can navigate to another tool; the run continues.'}</p>
          <div className="small mono">Run {run.id}</div>
        </Panel>
        <Panel title="Evidence" sub="Confirmed observations and candidates are distinguished; candidates need manual validation" className="mt-16">
          <div className="table-wrap"><table className="data"><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Inspect</th></tr></thead><tbody>
            {run.findings.filter(f=>!f.superseded).map(f=><tr key={f.key}><td><span className={`pill ${severityPill[f.severity]}`}>{f.severity}</span></td><td>{f.confidence}</td><td>{f.name}<div className="small muted">{f.evidence}</div></td><td className="mono small">{f.target}</td><td><button className="btn btn-sm" onClick={()=>inspect(f)}>Repeater</button></td></tr>)}
          </tbody></table></div>
          {!run.findings.length && <div className="empty">No findings observed yet.</div>}
        </Panel>
        <Panel title="Execution log" className="mt-16"><div className="code-pane" style={{maxHeight:300}}>{run.log.join('\n')}</div></Panel>
      </>}
    </div>
  </>
}
