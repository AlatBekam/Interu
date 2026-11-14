import type { ipcMain } from 'electron'
import { randomUUID } from 'node:crypto'
import { setTimeout as pause } from 'node:timers/promises'
import { normalizeAutomation, type AutomationOptions, type AutomationSnapshot } from '../shared/automation'
import { hostInScope, type HttpReq, type HttpRes } from '../shared/http'
import { CrawlController, contentTypeLabel } from '../shared/crawl'
import { analyzeHttpResponse, activeTemplates, buildActiveRequest, computeBaseline, matchActive, correlate, sortFindings, type Finding } from '../shared/rules'
import { planQueryParams, sqliErrorVerdict, sqliFinding, xssReflectVerdict, xssFinding, accessVerdict, accessFinding, csrfMissing, csrfFinding, fileDisclosureVerdict, expressionVerdict, commandOutputVerdict, ssrfErrorVerdict, differentialFinding, idorProbeEligible, idNeighbors, idorVerdict, idorFinding } from '../shared/webvuln'
import { isUnsafeAuthedPath, redactSecrets } from '../shared/auth'
import { sendAuthed } from './auth'
import { sendHttp } from './http'

type Send = (req: HttpReq, signal: AbortSignal) => Promise<HttpRes>
class StopRun extends Error { constructor(readonly status: 'cancelled' | 'limited' | 'failed', reason: string) { super(reason) } }

/** One bounded job, independent of the renderer route. No model or remote service. */
export class AutomationRunner {
  private state: AutomationSnapshot = { id: '', target: '', status: 'idle', phase: 'idle', requests: 0, pages: 0, errors: 0, findings: [], log: [] }
  private abort?: AbortController
  private task?: Promise<void>
  private lastSend = 0
  private failures = 0
  constructor(private send: Send, private scope: () => string[], private emit: (s: AutomationSnapshot) => void = () => {}) {}
  snapshot(): AutomationSnapshot { return structuredClone(this.state) }
  wait(): Promise<void> { return this.task || Promise.resolve() }
  cancel(): void { this.abort?.abort() }
  private publish(): void { this.emit(this.snapshot()) }
  private log(message: string): void { this.state.log = [...this.state.log, `${new Date().toISOString()} ${redactSecrets(message)}`].slice(-200); this.publish() }
  start(input: Partial<AutomationOptions>): AutomationSnapshot {
    if (this.state.status === 'running') throw new Error('A run is already active; stop it before starting another')
    const options = normalizeAutomation(input)
    if (!hostInScope(options.target, this.scope())) throw new Error('Target is outside the authorized scope')
    const abort = new AbortController()
    this.abort = abort; this.failures = 0; this.lastSend = 0
    this.state = { id: randomUUID(), target: redactSecrets(options.target), status: 'running', phase: 'crawl', requests: 0, pages: 0, errors: 0,
      startedAt: new Date().toISOString(), options: { ...options, target: redactSecrets(options.target) }, findings: [], log: [] }
    this.publish()
    this.task = this.run(options, abort.signal)
    return this.snapshot()
  }
  private async run(options: AutomationOptions, signal: AbortSignal): Promise<void> {
    const started = Date.now()
    const origin = new URL(options.target).origin
    const findings = new Map<string, Finding>()
    const add = (items: Finding[]): void => {
      for (const f of items) findings.set(f.key, f)
      this.state.findings = sortFindings(correlate([...findings.values()])).slice(0, 1000)
      this.publish()
    }
    const check = (): void => {
      if (signal.aborted) throw new StopRun('cancelled', 'Stopped by operator')
      if (Date.now() - started >= options.maxDurationMs) throw new StopRun('limited', 'Time budget reached')
      if (this.state.requests >= options.maxRequests) throw new StopRun('limited', 'Request budget reached')
    }
    const get = async (url: string): Promise<HttpRes> => {
      check()
      if (new URL(url).origin !== origin || !hostInScope(url, this.scope())) throw new StopRun('failed', 'Target or redirect is outside the current authorized origin/scope')
      if (isUnsafeAuthedPath(url)) { this.log(`Skipped state-changing path: ${url}`); return {ok:false,error:'Unsafe path skipped',timingMs:0,size:0} }
      const delay = Math.max(0, options.delayMs - (Date.now() - this.lastSend))
      if (delay) await pause(delay, undefined, {signal})
      check()
      // Scope can change while waiting for the rate limiter.
      if (!hostInScope(url, this.scope())) throw new StopRun('failed', 'Scope changed; stopped before the next request')
      this.lastSend = Date.now(); this.state.requests++; this.publish()
      const remainingMs = options.maxDurationMs - (Date.now() - started)
      const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, remainingMs))])
      const res = await this.send({method:'GET',url,headers:{'User-Agent':'Interu/1.4','Accept-Encoding':'gzip, deflate, br'},timeoutMs:Math.min(options.timeoutMs, remainingMs)},requestSignal)
      if (signal.aborted) throw new StopRun('cancelled','Stopped by operator')
      if (Date.now() - started >= options.maxDurationMs) throw new StopRun('limited','Time budget reached')
      if (res.authLost) throw new StopRun('failed','Authentication expired; partial evidence retained')
      if (res.blocked) throw new StopRun('failed','Blocked by scope')
      if (res.status === 429 || res.status === 503) throw new StopRun('limited',`Server requested backoff (HTTP ${res.status})`)
      if (!res.ok) { this.state.errors++; this.failures++; this.log(`Request failed: ${res.error || 'unknown'}`) } else this.failures=0
      if (this.failures >= 5) throw new StopRun('failed','Five consecutive transport failures')
      if (res.truncated) this.log(`Incomplete response excluded from active proof: ${url}`)
      return res
    }
    try {
      this.log('Rule-based automation started')
      const crawl = new CrawlController([options.target, ...(options.browserSeeds || [])], {maxDepth:options.maxDepth,maxPages:options.maxPages,sameHostOnly:true,includeSubdomains:false}, this.scope())
      const queryUrls = new Map<string,string>()
      let item: ReturnType<CrawlController['take']>
      while ((item = crawl.take())) {
        check()
        let url = item.url
        if (new URL(url).origin !== origin) continue
        let res = await get(url)
        for (let hop=0; res.status && [301,302,303,307,308].includes(res.status) && hop<3; hop++) {
          const location = /^location:\s*(.+)$/im.exec(res.rawHeaders || '')?.[1]?.trim()
          if (!location) break
          url = new URL(location,url).href
          res = await get(url)
        }
        const ct = /^content-type:\s*(.+)$/im.exec(res.rawHeaders || '')?.[1] || ''
        const parseable = ['html','js','json','xml','text','yaml'].includes(contentTypeLabel(ct))
        const successful = res.ok && res.status != null && res.status >=200 && res.status <300 && !res.truncated
        const node = crawl.record({...item,url},{status:res.status,type:contentTypeLabel(ct),html:successful && parseable ? res.body || '' : '',error:res.error})
        this.state.pages = crawl.done
        if (successful && parseable && res.raw) {
          add(analyzeHttpResponse({id:0,time:'',method:'GET',host:new URL(url).host,path:new URL(url).pathname,url,status:res.status,ms:res.timingMs,kind:'http',response:res.raw}))
          if (accessVerdict(url,res.status,res.body || '')) add([accessFinding(url)])
          for (const form of node.forms) if (csrfMissing(form)) add([csrfFinding(url,form.action)])
        }
        const remember = (candidate: string): void => {
          const u=new URL(candidate)
          if (u.origin!==origin || !u.search || queryUrls.size>=20) return
          queryUrls.set(u.origin+u.pathname+'?'+[...u.searchParams.keys()].sort().join(','),u.href)
        }
        if (successful) {
          remember(url)
          for (const form of node.forms) if (form.method==='GET') { const u=new URL(form.action); for(const input of form.inputs) u.searchParams.set(input.name,'1'); remember(u.href) }
        }
        this.log(`Crawled ${res.status || 'ERR'} ${url}`)
      }
      if (options.parameterChecks) {
        this.state.phase='parameters'; this.publish()
        for (const url of queryUrls.values()) for (const plan of planQueryParams(url).slice(0,5)) {
          const baseline=await get(plan.baselineUrl)
          if (!baseline.ok || baseline.truncated || !baseline.status || baseline.status>=400) continue
          const quote=plan.probes.find(p=>p.kind==='sqli-quote')!
          const balanced=plan.probes.find(p=>p.kind==='sqli-balanced')!
          const q=await get(quote.url), b=await get(balanced.url)
          if(q.ok && b.ok && !q.truncated && !b.truncated) {
            const verdict=sqliErrorVerdict(baseline.body || '',q.body || '',b.body || '')
            if(verdict) add([sqliFinding(url,plan.param,verdict,`GET ${quote.url}`,`BASELINE\n${baseline.raw || ''}\nQUOTE\n${q.raw || ''}\nBALANCED\n${b.raw || ''}`)])
          }
          const probe=plan.probes.find(p=>p.kind==='xss')!
          const response=await get(probe.url)
          const type=/^content-type:\s*(.+)$/im.exec(response.rawHeaders || '')?.[1]
          if(response.ok && !response.truncated && xssReflectVerdict(response.body || '',probe.token!,type)?.reflected) add([xssFinding(url,plan.param,probe.token!,`GET ${probe.url}`,response.raw)])
          for (const kind of ['lfi','xxe','ssti','rce','ssrf'] as const) {
            const checkProbe=plan.probes.find(p=>p.kind===kind)
            if(!checkProbe) continue
            const answer=await get(checkProbe.url)
            if(!answer.ok || answer.truncated || answer.authLost || answer.blocked) continue
            const payload=new URL(checkProbe.url).searchParams.get(plan.param) || ''
            const body=answer.body || ''
            const hit=kind==='lfi' || kind==='xxe' ? fileDisclosureVerdict(baseline.body || '',body)
              : kind==='ssti' ? expressionVerdict(baseline.body || '',body,checkProbe.token || '',payload)
              : kind==='rce' ? commandOutputVerdict(baseline.body || '',body,checkProbe.token || '',payload)
              : ssrfErrorVerdict(baseline.body || '',body)
            if(hit) add([differentialFinding(kind,url,plan.param,`GET ${checkProbe.url}`,answer.raw || '')])
          }
          if(idorProbeEligible(url,plan.param,plan.origValue)) {
            for(const next of idNeighbors(plan.origValue).slice(0,1)) {
              const neighbor=new URL(url); neighbor.searchParams.set(plan.param,next)
              const answer=await get(neighbor.href)
              if(answer.ok && !answer.truncated) {
                const verdict=idorVerdict({status:baseline.status,body:baseline.body || ''},{status:answer.status,body:answer.body || ''})
                if(verdict) add([idorFinding(url,plan.param,plan.origValue,next,verdict.reason)])
              }
            }
          }
        }
      }
      if(options.activeChecks) {
        this.state.phase='templates'; this.publish()
        const base=await get(`${origin}/interu-not-here-${randomUUID()}`)
        if (!base.ok || base.truncated) throw new StopRun('failed','No reliable soft-404 baseline; active checks not started')
        const baseline=computeBaseline(base)
        for(const template of activeTemplates()) {
          const req=buildActiveRequest(template,origin)
          if(!req) continue
          const res=await get(req.url)
          const finding=matchActive(template,req.url,res,{req,baseline})
          if(finding) {add([finding]); this.log(`${finding.confidence}: ${finding.name}`)}
        }
      }
      this.state.status='completed'; this.state.phase='done'; this.state.reason='Selected checks completed'
    } catch(error) {
      const stop = error instanceof StopRun ? error : new StopRun(signal.aborted?'cancelled':'failed',signal.aborted?'Stopped by operator':(error as Error).message)
      this.state.status=stop.status; this.state.reason=stop.message; this.state.phase='stopped'
    } finally {
      this.state.finishedAt=new Date().toISOString()
      this.log(`${this.state.status}: ${this.state.reason}; ${this.state.requests} requests, ${this.state.findings.length} findings`)
    }
  }
}

export function registerAutomationIpc(handle: typeof ipcMain.handle, scope: () => string[], emit: (channel:string,data:unknown)=>void): AutomationRunner {
  const runner=new AutomationRunner((req,signal)=>sendAuthed(req,r=>sendHttp(r,signal)),scope,state=>emit('ruy:automation:progress',state))
  handle('ruy:automation:start',(_event,input)=>runner.start(input || {}))
  handle('ruy:automation:status',()=>runner.snapshot())
  handle('ruy:automation:cancel',()=>{runner.cancel();return {ok:true}})
  return runner
}
