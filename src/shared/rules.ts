// Interu Rule Engine — a Nuclei-inspired detection engine.
//
// Templates are DATA (see TEMPLATES below): each has info (name/severity/CVE/
// remediation) and a list of matchers (status / word / regex / dsl / time /
// port / service) combined with and/or, plus optional extractors that pull
// structured data (versions, tokens) out of the response. The engine evaluates
// templates against signals already collected by real modules:
//   - port/banner results from the Network Scanner  (analyzeScan)
//   - captured HTTP responses from the Proxy         (analyzeHttpResponse)
//   - active, scope-gated HTTP probes                (buildActiveRequest + matchActive)
//
// Confidence is honest:
//   - directly-observed facts over an authorized channel (missing header,
//     cookie flags, a file we actually fetched and whose distinctive content we
//     matched) are "confirmed";
//   - inferences (a service guessed from a port number, a product/CVE guessed
//     from a banner, an error string) stay "suspected".
// Port templates are ALWAYS suspected: the scanner only proves the port is open,
// not which service truly runs there. Active probes only ever READ — no
// exploitation is performed — so a "confirmed exposure" means we proved the
// resource is reachable and looks like what the template describes, nothing more.
//
// Framework-free so the main process, preload and renderer can all import it.

import type { ScanHost } from './scan'
import type { ProxyLogEntry } from './proxy'
import type { HttpReq, HttpRes } from './http'
import { evalBool, type DslContext } from './dsl'
import { kevFor, kevByProduct, type KevInfo } from './kev'
import { detectProducts, type ProductHit } from './fingerprint'
import { redactSecrets } from './auth'
import { MODERN_BACKUP_RULES } from './rulepack2025'
import { LAB_RULES } from './labRulepack'

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'suspected' | 'confirmed'
export type TemplateKind = 'port' | 'http-passive' | 'http-active'

export interface Classification {
  cve?: string[]
  cwe?: string[]
  cvss?: number
}

export interface TemplateInfo {
  name: string
  severity: RuleSeverity
  description?: string
  remediation?: string
  reference?: string[]
  classification?: Classification
  tags?: string[]
  mitre?: string[]
}

export interface Matcher {
  type: 'status' | 'word' | 'regex' | 'port' | 'service' | 'time' | 'dsl'
  /** which text to search for word/regex matchers. */
  part?: 'header' | 'body' | 'response' | 'banner'
  status?: number[]
  words?: string[]
  regex?: string[]
  ports?: number[]
  services?: string[]
  /** dsl matcher: boolean expressions over response facts (see shared/dsl.ts). */
  dsl?: string[]
  /** combine this matcher's words/regex/dsl list (default 'or'). */
  condition?: 'and' | 'or'
  /** match when the pattern is ABSENT (e.g. a missing security header). */
  negative?: boolean
  /** time matcher: match when response took at least this many ms. */
  geMs?: number
}

export interface Extractor {
  /** label the extracted value is stored under (defaults to the extractor type). */
  name?: string
  type: 'regex' | 'kval' | 'word'
  part?: Matcher['part']
  regex?: string[]
  /** regex capture group to keep (default 0 = whole match). */
  group?: number
  /** header names to read as key: value pairs. */
  kval?: string[]
  words?: string[]
}

export interface HttpRequestSpec {
  method?: string
  path: string
  headers?: Record<string, string>
  body?: string
}

export interface Template {
  id: string
  kind: TemplateKind
  confidence: Confidence
  info: TemplateInfo
  matchers: Matcher[]
  /** combine matchers (default 'and'). */
  matchersCondition?: 'and' | 'or'
  /** optional data extractors run when the template matches. */
  extractors?: Extractor[]
  /** http-active only: the probe to send (path/headers/body support {{vars}}). */
  request?: HttpRequestSpec
  /** port only: restrict which open ports the template is tried against. */
  appliesToPorts?: number[]
  /** http-passive only: only run when the captured URL uses this scheme. */
  scheme?: 'http' | 'https'
  /**
   * Correlation group. Findings that share a group + target are deduped by
   * confidence then severity, so an oracle-confirmed finding supersedes a
   * suspected one describing the same issue (see `correlate`).
   */
  group?: string
}

export interface Finding {
  key: string
  templateId: string
  name: string
  severity: RuleSeverity
  confidence: Confidence
  target: string
  port?: number
  evidence: string
  remediation?: string
  description?: string
  reference?: string[]
  cve?: string[]
  cwe?: string[]
  cvss?: number
  /** CISA KEV entries for this finding's CVEs (actively exploited); present only when listed. */
  kev?: KevInfo[]
  tags?: string[]
  mitre?: string[]
  /** structured values pulled out by the template's extractors. */
  extracted?: Record<string, string[]>
  /** where the match was observed (request line / url). */
  matchedAt?: string
  /** raw request we sent (active only), clipped — evidence for Reports. */
  request?: string
  /** raw response (clipped), evidence for Reports. */
  response?: string
  source: 'scanner' | 'proxy' | 'active'
  at: string
  /** set by correlation: a higher-confidence finding covers the same issue. */
  superseded?: boolean
}

const EVIDENCE_CLIP = 8 * 1024
function clip(s: string | undefined, n = EVIDENCE_CLIP): string {
  if (!s) return ''
  return s.length > n ? s.slice(0, n) + `\n… [${s.length - n} more bytes]` : s
}

// ----------------------------------------------------------------- matchers

interface PortCtx { port: number; service: string; banner: string }
interface HttpCtx { status?: number; headerText: string; body: string; responseRaw: string; timeMs?: number }

function pickPart(part: Matcher['part'], kind: TemplateKind, p?: PortCtx, h?: HttpCtx): string {
  if (p) return (p.banner || '')
  if (!h) return ''
  switch (part) {
    case 'header': return h.headerText
    case 'body': return h.body
    case 'response': return h.responseRaw
    default: return kind === 'http-passive' || kind === 'http-active' ? h.responseRaw : ''
  }
}

/** Build the fixed fact context a `dsl` matcher may read. */
function dslContext(p?: PortCtx, h?: HttpCtx): DslContext {
  if (p) {
    return { port: p.port, service: p.service, banner: p.banner, body: p.banner, response: p.banner, header: '', status: null, content_length: p.banner.length, duration: null }
  }
  return {
    status: h?.status ?? null,
    content_length: (h?.body || '').length,
    duration: h?.timeMs ?? null,
    body: h?.body || '',
    header: h?.headerText || '',
    response: h?.responseRaw || '',
    banner: ''
  }
}

function evalMatcher(m: Matcher, kind: TemplateKind, p?: PortCtx, h?: HttpCtx): { ok: boolean; evidence?: string } {
  switch (m.type) {
    case 'status': {
      if (!h || h.status == null) return { ok: false }
      const ok = (m.status || []).includes(h.status)
      return { ok, evidence: ok ? `status ${h.status}` : undefined }
    }
    case 'port': {
      if (!p) return { ok: false }
      const ok = (m.ports || []).includes(p.port)
      return { ok, evidence: ok ? `port ${p.port}/${p.service}` : undefined }
    }
    case 'service': {
      if (!p) return { ok: false }
      const ok = (m.services || []).map((s) => s.toLowerCase()).includes(p.service.toLowerCase())
      return { ok, evidence: ok ? `service ${p.service}` : undefined }
    }
    case 'time': {
      if (!h || h.timeMs == null || m.geMs == null) return { ok: false }
      const ok = h.timeMs >= m.geMs
      return { ok, evidence: ok ? `response ${h.timeMs}ms ≥ ${m.geMs}ms` : undefined }
    }
    case 'dsl': {
      const exprs = m.dsl || []
      if (exprs.length === 0) return { ok: false }
      const ctx = dslContext(p, h)
      const hits = exprs.filter((e) => evalBool(e, ctx))
      const present = m.condition === 'and' ? hits.length === exprs.length : hits.length > 0
      const ok = m.negative ? !present : present
      if (!ok) return { ok: false }
      return { ok, evidence: m.negative ? `dsl false` : `dsl: ${hits.join(' ; ').slice(0, 80)}` }
    }
    case 'word': {
      const hay = pickPart(m.part, kind, p, h).toLowerCase()
      const words = (m.words || []).map((w) => w.toLowerCase())
      if (words.length === 0) return { ok: false }
      const hits = words.filter((w) => hay.includes(w))
      const present = m.condition === 'and' ? hits.length === words.length : hits.length > 0
      const ok = m.negative ? !present : present
      if (!ok) return { ok: false }
      return { ok, evidence: m.negative ? `missing: ${words.join(', ')}` : `matched: ${hits.join(', ')}` }
    }
    case 'regex': {
      const hay = pickPart(m.part, kind, p, h)
      const pats = m.regex || []
      if (pats.length === 0) return { ok: false }
      const matches: string[] = []
      for (const src of pats) {
        try {
          // `m` so ^/$ anchor per header line (e.g. one Set-Cookie per line).
          const r = new RegExp(src, 'im')
          const mm = r.exec(hay)
          if (mm) matches.push(mm[0].slice(0, 60))
        } catch { /* bad pattern — skip */ }
      }
      const present = m.condition === 'and' ? matches.length === pats.length : matches.length > 0
      const ok = m.negative ? !present : present
      if (!ok) return { ok: false }
      return { ok, evidence: m.negative ? `pattern absent` : `matched: ${matches.join(' | ')}` }
    }
    default:
      return { ok: false }
  }
}

// ----------------------------------------------------------------- extractors

function runExtractors(exts: Extractor[] | undefined, kind: TemplateKind, p?: PortCtx, h?: HttpCtx): Record<string, string[]> | undefined {
  if (!exts || exts.length === 0) return undefined
  const out: Record<string, string[]> = {}
  for (const e of exts) {
    const name = e.name || e.type
    const vals: string[] = []
    if (e.type === 'kval') {
      const headerText = h?.headerText || ''
      const lines = headerText.split('\n')
      for (const key of e.kval || []) {
        const re = new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:\\s*(.*)$`, 'im')
        for (const ln of lines) {
          const mm = re.exec(ln.trim())
          if (mm) vals.push(mm[1].trim())
        }
      }
    } else if (e.type === 'regex') {
      const hay = pickPart(e.part, kind, p, h)
      const group = e.group ?? 0
      for (const src of e.regex || []) {
        try {
          const r = new RegExp(src, 'ig')
          let mm: RegExpExecArray | null
          let guard = 0
          while ((mm = r.exec(hay)) && guard++ < 20) {
            vals.push((mm[group] ?? mm[0]).slice(0, 120))
            if (mm.index === r.lastIndex) r.lastIndex++
          }
        } catch { /* skip bad pattern */ }
      }
    } else if (e.type === 'word') {
      const hay = pickPart(e.part, kind, p, h)
      const low = hay.toLowerCase()
      for (const w of e.words || []) if (low.includes(w.toLowerCase())) vals.push(w)
    }
    const uniq = Array.from(new Set(vals)).filter(Boolean)
    if (uniq.length) out[name] = uniq
  }
  return Object.keys(out).length ? out : undefined
}

function evalTemplate(t: Template, p?: PortCtx, h?: HttpCtx): { ok: boolean; evidence: string } {
  const results = t.matchers.map((m) => evalMatcher(m, t.kind, p, h))
  const cond = t.matchersCondition || 'and'
  const ok = cond === 'or' ? results.some((r) => r.ok) : results.every((r) => r.ok)
  if (!ok) return { ok: false, evidence: '' }
  const evidence = results.filter((r) => r.ok && r.evidence).map((r) => r.evidence).join(' · ')
  return { ok: true, evidence }
}

interface FindingExtras {
  port?: number
  extracted?: Record<string, string[]>
  matchedAt?: string
  request?: string
  response?: string
}

function toFinding(t: Template, target: string, evidence: string, source: Finding['source'], at: string, extra: FindingExtras = {}): Finding {
  const c = t.info.classification || {}
  const extractedBits = extra.extracted
    ? Object.entries(extra.extracted).map(([k, v]) => `${k}=${v.join(', ')}`).join(' · ')
    : ''
  const fullEvidence = redactSecrets([evidence, extractedBits].filter(Boolean).join(' · ') || t.info.name)
  const kev = kevFor(c.cve)
  return {
    key: `${t.id}|${target}${extra.port != null ? ':' + extra.port : ''}`,
    templateId: t.id,
    name: t.info.name,
    severity: t.info.severity,
    confidence: t.confidence,
    target,
    port: extra.port,
    evidence: fullEvidence,
    remediation: t.info.remediation,
    description: t.info.description,
    reference: t.info.reference,
    cve: c.cve,
    cwe: c.cwe,
    cvss: c.cvss,
    kev: kev.length ? kev : undefined,
    tags: t.info.tags,
    mitre: t.info.mitre,
    extracted: extra.extracted ? Object.fromEntries(Object.entries(extra.extracted).map(([k, v]) => [k, v.map((s) => /secret|token|password|credential/i.test(k) ? '<redacted>' : redactSecrets(s))])) : undefined,
    matchedAt: extra.matchedAt ? redactSecrets(extra.matchedAt) : undefined,
    request: extra.request ? redactSecrets(extra.request) : undefined,
    response: extra.response ? redactSecrets(extra.response) : undefined,
    source,
    at
  }
}

// ----------------------------------------------------------------- HTTP parse

export interface ParsedResponse {
  status?: number
  headerText: string
  body: string
  raw: string
}

export function parseHttpResponse(raw: string): ParsedResponse {
  const norm = (raw || '').replace(/\r/g, '')
  const sep = norm.indexOf('\n\n')
  const head = sep >= 0 ? norm.slice(0, sep) : norm
  const body = sep >= 0 ? norm.slice(sep + 2) : ''
  const lines = head.split('\n')
  const statusLine = lines[0] || ''
  const sm = /\s(\d{3})\s?/.exec(statusLine)
  const headerText = lines.slice(1).join('\n')
  return { status: sm ? Number(sm[1]) : undefined, headerText, body, raw: norm }
}

// ----------------------------------------------------------------- analyzers

/** Passive detection over Network Scanner results. */
/** Product-level KEV hit: suspected and version-blind. Null when no uncovered KEV CVE remains. */
function productFinding(
  hit: ProductHit, target: string, port: number | undefined, source: Finding['source'],
  covered: Set<string>, at: string
): Finding | null {
  const cves = kevByProduct(hit.fingerprint.kevProducts).filter((k) => !covered.has(k.cve))
  if (cves.length === 0) return null
  const label = hit.fingerprint.label
  return {
    key: `kev-product-${hit.fingerprint.id}|${target}${port != null ? ':' + port : ''}`,
    templateId: `kev-product-${hit.fingerprint.id}`,
    name: `${label} detected: ${cves.length} CVE in CISA KEV (version not verified)`,
    severity: 'medium',
    confidence: 'suspected',
    target,
    port,
    evidence: hit.evidence,
    remediation: `Patch ${label} to a supported version and check each CVE's affected range.`,
    cve: cves.map((k) => k.cve),
    kev: cves,
    tags: ['kev-product'],
    source,
    at
  }
}

export function analyzeScan(hosts: ScanHost[], at = new Date().toISOString()): Finding[] {
  const out: Finding[] = []
  const tpls = TEMPLATES.filter((t) => t.kind === 'port')
  for (const host of hosts) {
    for (const op of host.openPorts) {
      const ctx: PortCtx = { port: op.port, service: op.service, banner: op.version || '' }
      const portStart = out.length
      for (const t of tpls) {
        if (t.appliesToPorts && !t.appliesToPorts.includes(op.port)) continue
        const r = evalTemplate(t, ctx)
        if (r.ok) {
          const extracted = runExtractors(t.extractors, t.kind, ctx)
          out.push(toFinding(t, host.ip, r.evidence, 'scanner', at, { port: op.port, extracted, response: ctx.banner || undefined }))
        }
      }
      // Product-level KEV hits, minus CVEs a precise template already reported on this port.
      const covered = new Set(out.slice(portStart).flatMap((f) => f.cve ?? []))
      for (const hit of detectProducts({ banner: op.version || '' })) {
        const p = productFinding(hit, host.ip, op.port, 'scanner', covered, at)
        if (p) out.push(p)
      }
    }
  }
  return out
}

/** Passive detection over a captured HTTP response from the proxy. */
export function analyzeHttpResponse(entry: ProxyLogEntry, at = new Date().toISOString()): Finding[] {
  if (!entry || !entry.response) return []
  const parsed = parseHttpResponse(entry.response)
  const isHttps = /^https:/i.test(entry.url)
  const ctx: HttpCtx = {
    status: entry.status || parsed.status,
    headerText: parsed.headerText,
    body: parsed.body,
    responseRaw: parsed.raw,
    timeMs: entry.ms
  }
  let origin = entry.url
  try { origin = new URL(entry.url).origin } catch { /* keep full url */ }
  const out: Finding[] = []
  for (const t of TEMPLATES.filter((x) => x.kind === 'http-passive')) {
    if (t.scheme === 'https' && !isHttps) continue
    if (t.scheme === 'http' && isHttps) continue
    // Load-balancer/bot cookies are not application sessions. Keep other
    // Set-Cookie lines so a real session cookie is still evaluated.
    const ruleCtx = t.id.startsWith('http-cookie-') ? {
      ...ctx,
      headerText: ctx.headerText.split(/\r?\n/).filter(line =>
        !/^set-cookie:\s*(?:AWSALB(?:CORS|TG|TGCORS)?|__cf_bm|_cfuvid)=/i.test(line)
      ).join('\n')
    } : ctx
    const r = evalTemplate(t, undefined, ruleCtx)
    // Header-only rules describe the whole site: one finding per origin, not per URL.
    const siteWide = t.matchers.every((m) => m.part === 'header')
    if (r.ok) {
      const extracted = runExtractors(t.extractors, t.kind, undefined, ruleCtx)
      out.push(toFinding(t, siteWide ? origin : entry.url, r.evidence, 'proxy', at, {
        extracted, matchedAt: entry.url, response: clip(parsed.raw)
      }))
    }
  }
  // A real user-list JSON response containing password fields is stronger
  // evidence than a path name. Do not retain the password values in findings.
  if (entry.method.toUpperCase() === 'GET' && ctx.status === 200 &&
      /^content-type:\s*application\/(?:json|[^\r\n;]+\+json)/im.test(ctx.headerText) &&
      parsed.body.length <= 1_000_000) {
    try {
      const data = JSON.parse(parsed.body) as { users?: unknown }
      const users = Array.isArray(data?.users) ? data.users : []
      const exposed = users.filter(user => user && typeof user === 'object' &&
        typeof (user as Record<string, unknown>).password === 'string' &&
        ((user as Record<string, unknown>).password as string).length > 0 &&
        ['username', 'email', 'id'].some(key => key in (user as Record<string, unknown>)))
      if (exposed.length) out.push(toFinding({
        id: 'http-user-password-fields', kind: 'http-passive', confidence: 'confirmed', matchers: [],
        info: { name: 'User-list JSON includes password fields', severity: 'medium',
          description: 'The response returned user records with password fields. Verify caller authorization and whether the values are hashes or plaintext.',
          remediation: 'Do not serialize password or password-hash fields into API responses.',
          classification: { cwe: ['CWE-200'] }, tags: ['api', 'data-exposure'] }
      }, entry.url, `HTTP 200 JSON contained ${exposed.length} user record(s) with a password field; values omitted`, 'proxy', at, {
        matchedAt: entry.url,
        response: `HTTP 200 JSON\nusers: ${users.length} record(s); ${exposed.length} password field(s) observed. Values intentionally omitted.`
      }))
    } catch { /* malformed JSON is not evidence */ }
  }
  // Product fingerprints describe the whole site: one finding per product per origin.
  for (const hit of detectProducts({ headerText: parsed.headerText, body: parsed.body })) {
    const p = productFinding(hit, origin, undefined, 'proxy', new Set(), at)
    if (p) out.push(p)
  }
  return out
}

// --------------------------------------------------- active (oracle) probing

export const activeTemplates = (): Template[] => TEMPLATES.filter((t) => t.kind === 'http-active')

/** Variables available to an active template's path/headers/body ({{Name}}). */
export function requestVars(baseUrl: string): Record<string, string> {
  let base = baseUrl.trim()
  if (!/^https?:\/\//i.test(base)) base = 'http://' + base
  base = base.replace(/\/+$/, '')
  let u: URL | null = null
  try { u = new URL(base) } catch { /* leave null */ }
  const scheme = u?.protocol.replace(':', '') || 'http'
  const host = u?.hostname || base
  const port = u?.port || (scheme === 'https' ? '443' : '80')
  const rand = Math.random().toString(36).slice(2, 12)
  return {
    BaseURL: base,
    RootURL: `${scheme}://${host}:${port}`,
    Hostname: u?.host || host,
    Host: host,
    Port: port,
    Scheme: scheme,
    Path: u?.pathname || '/',
    RandomString: rand
  }
}

export function interpolate(tmpl: string, vars: Record<string, string>): string {
  return (tmpl || '').replace(/\{\{(\w+)\}\}/g, (full, name) => (name in vars ? vars[name] : full))
}

/** Build the real HTTP request for an active template against a base URL. */
export function buildActiveRequest(t: Template, baseUrl: string): HttpReq | null {
  if (!t.request) return null
  const vars = requestVars(baseUrl)
  const base = vars.BaseURL
  // A path may be an absolute URL (via {{BaseURL}}) or a root-relative path.
  let rawPath = interpolate(t.request.path, vars)
  let url: string
  if (/^https?:\/\//i.test(rawPath)) {
    url = rawPath
  } else {
    if (!rawPath.startsWith('/')) rawPath = '/' + rawPath
    url = base + rawPath
  }
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(t.request.headers || {})) headers[k] = interpolate(v, vars)
  return {
    method: t.request.method || 'GET',
    url,
    headers,
    body: t.request.body ? interpolate(t.request.body, vars) : undefined,
    timeoutMs: 8000
  }
}

/** A soft-404 / catch-all baseline, measured by probing a path that cannot exist. */
export interface Baseline {
  ok: boolean
  status?: number
  bodyLen: number
  /** server answered 2xx for a guaranteed-missing path → it is a catch-all. */
  catchAll: boolean
  body?: string
  headerText?: string
}

export function computeBaseline(res: HttpRes): Baseline {
  const bodyLen = (res.body || '').length
  const catchAll = !!res.ok && typeof res.status === 'number' && res.status >= 200 && res.status < 300
  return { ok: !!res.ok, status: res.status, bodyLen, catchAll, body: (res.body || '').slice(0, 65536), headerText: res.rawHeaders || '' }
}

/** True when a template decides solely on the HTTP status (no content marker). */
export function isStatusOnly(t: Template): boolean {
  return t.matchers.length > 0 && t.matchers.every((m) => m.type === 'status')
}

export interface MatchActiveOpts {
  at?: string
  req?: HttpReq
  baseline?: Baseline
}

/** Evaluate an active template against the real response it produced. */
export function matchActive(t: Template, url: string, res: HttpRes, opts: MatchActiveOpts = {}): Finding | null {
  if (!res || res.ok === false || res.authLost || res.truncated) return null
  const at = opts.at || new Date().toISOString()
  const ctx: HttpCtx = {
    status: res.status,
    headerText: res.rawHeaders || '',
    body: res.body || '',
    responseRaw: res.raw || `${res.status ?? ''}\n${res.rawHeaders ?? ''}\n\n${res.body ?? ''}`,
    timeMs: res.timingMs
  }
  const r = evalTemplate(t, undefined, ctx)
  if (!r.ok) return null

  // Soft-404 guard: on a catch-all server (2xx for anything), a status-only
  // match proves nothing — demote it to suspected and say why. Templates that
  // also match distinctive content stay confirmed, since a catch-all page won't
  // contain their marker.
  const baseline = opts.baseline
  let confidenceNote = ''
  const baselineMatches = baseline?.catchAll && evalTemplate(t, undefined, {
    status: baseline.status, body: baseline.body || '', headerText: baseline.headerText || '',
    responseRaw: `${baseline.headerText || ''}\n\n${baseline.body || ''}`
  }).ok
  const demoted = baseline?.catchAll && (isStatusOnly(t) || baselineMatches)
  const extracted = runExtractors(t.extractors, t.kind, undefined, ctx)
  const reqRaw = opts.req
    ? `${opts.req.method} ${opts.req.url}\n` + Object.entries(opts.req.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n') + (opts.req.body ? `\n\n${opts.req.body}` : '')
    : undefined

  const finding = toFinding(
    demoted ? { ...t, confidence: 'suspected' } : t,
    url,
    (demoted ? 'baseline: server is catch-all 2xx · ' : confidenceNote) + r.evidence,
    'active', at,
    { extracted, matchedAt: url, request: clip(reqRaw, 2048), response: clip(ctx.responseRaw) }
  )
  return finding
}

// --------------------------------------------------------------- correlation

/**
 * Deduplicate findings that describe the same issue on the same target. When a
 * template declares a `group`, two findings sharing that group + target are
 * collapsed: the higher-confidence (then higher-severity) one wins and the
 * other is flagged `superseded`. This is how an oracle-confirmed finding
 * upgrades a suspected one for the same vulnerability. Findings without a group
 * are returned untouched.
 */
export function correlate(list: Finding[]): Finding[] {
  const groupOf = new Map(TEMPLATES.map((t) => [t.id, t.group]))
  const best = new Map<string, Finding>()
  for (const f of list) {
    const g = groupOf.get(f.templateId)
    if (!g) continue
    const k = `${g}|${f.target}`
    const cur = best.get(k)
    if (!cur || rank(f) < rank(cur)) best.set(k, f)
  }
  return list.map((f) => {
    const g = groupOf.get(f.templateId)
    if (!g) return f
    const winner = best.get(`${g}|${f.target}`)
    const superseded = !!winner && winner.key !== f.key
    return superseded === !!f.superseded ? (superseded ? { ...f, superseded } : f) : { ...f, superseded }
  })
}

function rank(f: Finding): number {
  // lower is better: confirmed before suspected, then by severity.
  return (f.confidence === 'confirmed' ? 0 : 100) + SEVERITY_RANK[f.severity]
}

export const SEVERITY_RANK: Record<RuleSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) =>
    (Number(!!a.superseded) - Number(!!b.superseded)) ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    (a.confidence === b.confidence ? 0 : a.confidence === 'confirmed' ? -1 : 1) ||
    a.target.localeCompare(b.target)
  )
}

// ----------------------------------------------------------------- TEMPLATES
// Helpers keep the (large) catalog terse and consistent.

const S = (...status: number[]): Matcher => ({ type: 'status', status })
const W = (part: Matcher['part'], words: string[], condition: 'and' | 'or' = 'or'): Matcher => ({ type: 'word', part, words, condition })
const RX = (part: Matcher['part'], regex: string[], condition: 'and' | 'or' = 'or'): Matcher => ({ type: 'regex', part, regex, condition })

/** An exposed-file active template: GET a path, require 2xx + a distinctive body marker. */
function expose(
  id: string, path: string, severity: RuleSeverity,
  name: string, body: Matcher, remediation: string,
  opts: { tags?: string[]; cwe?: string[]; cve?: string[]; cvss?: number; group?: string; extractors?: Extractor[]; status?: number[] } = {}
): Template {
  return {
    id, kind: 'http-active', confidence: 'confirmed', group: opts.group,
    request: { method: 'GET', path },
    info: {
      name, severity, tags: opts.tags || ['exposure'], remediation,
      classification: { cwe: opts.cwe, cve: opts.cve, cvss: opts.cvss }
    },
    matchers: [S(...(opts.status || [200])), body],
    matchersCondition: 'and',
    extractors: opts.extractors
  }
}

/** A technology/panel detection active template: presence, info severity. */
function detect(
  id: string, path: string, name: string, marker: Matcher,
  opts: { severity?: RuleSeverity; tags?: string[]; status?: number[]; extractors?: Extractor[]; remediation?: string; cve?: string[] } = {}
): Template {
  return {
    id, kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path },
    info: {
      name, severity: opts.severity || 'info', tags: opts.tags || ['tech', 'panel'],
      remediation: opts.remediation || 'Restrict access to this interface to trusted networks; ensure strong authentication.',
      classification: { cwe: ['CWE-200'], cve: opts.cve }
    },
    matchers: [S(...(opts.status || [200])), marker],
    matchersCondition: 'and',
    extractors: opts.extractors
  }
}

const CURATED: Template[] = [
  // =========================================================================
  // PORT — exposed network services (suspected: only the port is proven open)
  // =========================================================================
  {
    id: 'svc-telnet-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Telnet service exposed (cleartext)', severity: 'high', tags: ['network', 'cleartext'],
      remediation: 'Disable Telnet; use SSH. Credentials over Telnet are sent in plaintext.',
      classification: { cwe: ['CWE-319'], cvss: 7.5 }, mitre: ['T1021'] },
    matchers: [{ type: 'port', ports: [23] }]
  },
  {
    id: 'svc-ftp-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'FTP service exposed', severity: 'medium', tags: ['network', 'cleartext'],
      remediation: 'Prefer SFTP/FTPS. Plain FTP transmits credentials in cleartext.',
      classification: { cwe: ['CWE-319'] } },
    matchers: [{ type: 'port', ports: [21] }]
  },
  {
    id: 'svc-smb-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'SMB service exposed', severity: 'high', tags: ['network', 'windows'],
      remediation: 'Do not expose SMB (445/139) to untrusted networks; restrict with firewall/VPN.',
      classification: { cwe: ['CWE-200'] }, mitre: ['T1021.002'] },
    matchers: [{ type: 'port', ports: [445, 139] }]
  },
  {
    id: 'svc-rdp-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'RDP service exposed', severity: 'high', tags: ['network', 'windows'],
      remediation: 'Restrict RDP (3389) behind VPN/NLA; never expose to the internet.',
      classification: { cwe: ['CWE-200'] }, mitre: ['T1021.001'] },
    matchers: [{ type: 'port', ports: [3389] }]
  },
  {
    id: 'svc-db-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Database service exposed', severity: 'high', tags: ['network', 'database'],
      remediation: 'Databases (MySQL/PostgreSQL/MSSQL/Oracle/DB2) should never be reachable from untrusted networks.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'port', ports: [3306, 5432, 1433, 1521, 50000] }]
  },
  {
    id: 'svc-nosql-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'NoSQL/cache exposed (possibly unauthenticated)', severity: 'high', tags: ['network', 'database'],
      remediation: 'Redis/MongoDB/Elasticsearch/Memcached/CouchDB/Cassandra frequently ship without auth. Bind to localhost and enable authentication.',
      classification: { cwe: ['CWE-306'] } },
    matchers: [{ type: 'port', ports: [6379, 27017, 27018, 9200, 9300, 11211, 5984, 9042] }]
  },
  {
    id: 'svc-mq-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Message broker / queue exposed', severity: 'medium', tags: ['network', 'mq'],
      remediation: 'RabbitMQ/AMQP/MQTT/Kafka brokers should not be internet-facing; require auth + TLS.',
      classification: { cwe: ['CWE-306'] } },
    matchers: [{ type: 'port', ports: [5672, 15672, 1883, 9092, 61616] }]
  },
  {
    id: 'svc-vnc-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'VNC remote desktop exposed', severity: 'high', tags: ['network'],
      remediation: 'Do not expose VNC; tunnel over SSH/VPN and require strong auth.' },
    matchers: [{ type: 'port', ports: [5900, 5901, 5902] }]
  },
  {
    id: 'svc-x11-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'X11 server exposed', severity: 'high', tags: ['network'],
      remediation: 'Never expose X11 (6000-6005); an open X server allows keylogging and screen capture.',
      classification: { cwe: ['CWE-284'] } },
    matchers: [{ type: 'port', ports: [6000, 6001, 6002] }]
  },
  {
    id: 'svc-smtp-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'SMTP service exposed', severity: 'low', tags: ['network', 'mail'],
      remediation: 'Ensure the MTA is not an open relay; require auth for submission (587).',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'port', ports: [25, 465, 587] }]
  },
  {
    id: 'svc-snmp-ldap-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Directory / management service exposed', severity: 'medium', tags: ['network'],
      remediation: 'LDAP (389/636), SNMP (161), rpcbind (111) and NFS (2049) leak internal data; restrict to trusted networks.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'port', ports: [389, 636, 161, 111, 2049] }]
  },
  {
    id: 'svc-docker-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Docker API exposed', severity: 'critical', tags: ['network', 'container'],
      remediation: 'An exposed Docker API (2375) is effectively remote root. Never expose it; require TLS + auth.',
      classification: { cwe: ['CWE-306'], cvss: 9.8 } },
    matchers: [{ type: 'port', ports: [2375, 2376] }]
  },
  {
    id: 'svc-k8s-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Kubernetes / etcd control plane exposed', severity: 'critical', tags: ['network', 'container'],
      remediation: 'kube-apiserver (6443/8080), kubelet (10250) and etcd (2379/2380) must never be internet-facing.',
      classification: { cwe: ['CWE-306'], cvss: 9.1 } },
    matchers: [{ type: 'port', ports: [6443, 10250, 2379, 2380, 8080] }],
    appliesToPorts: [6443, 10250, 2379, 2380]
  },
  {
    id: 'svc-backdoor-ports', kind: 'port', confidence: 'suspected',
    info: { name: 'Common backdoor / handler port open', severity: 'medium', tags: ['network', 'suspicious'],
      remediation: 'Ports 4444/31337/1337/12345 are frequently used by handlers and backdoors. Investigate what is listening.',
      classification: { cwe: ['CWE-506'] }, mitre: ['T1571'] },
    matchers: [{ type: 'port', ports: [4444, 31337, 1337, 12345] }]
  },

  // ---- banner → CVE (suspected until verified) ----
  // Only well-established, version-specific CVEs. A banner can be spoofed or
  // back-ported, so these stay suspected by design.
  {
    id: 'banner-vsftpd-234', kind: 'port', confidence: 'suspected', group: 'cve-vsftpd-234',
    info: { name: 'vsftpd 2.3.4 backdoor (banner match)', severity: 'critical', tags: ['ftp', 'cve'],
      remediation: 'Upgrade vsftpd immediately; 2.3.4 shipped a malicious backdoor.',
      classification: { cve: ['CVE-2011-2523'], cvss: 10.0 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['vsftpd\\s*2\\.3\\.4'] }]
  },
  {
    id: 'banner-proftpd-135', kind: 'port', confidence: 'suspected',
    info: { name: 'ProFTPD 1.3.5 mod_copy RCE (banner match)', severity: 'critical', tags: ['ftp', 'cve'],
      remediation: 'Upgrade ProFTPD; 1.3.5 mod_copy allows unauthenticated file copy / RCE.',
      classification: { cve: ['CVE-2015-3306'], cvss: 10.0 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['ProFTPD\\s*1\\.3\\.5[^0-9]'] }]
  },
  {
    id: 'banner-openssh-regresshion', kind: 'port', confidence: 'suspected',
    info: { name: 'OpenSSH regreSSHion candidate (banner match)', severity: 'high', tags: ['ssh', 'cve'],
      remediation: 'Upgrade OpenSSH to ≥ 9.8. Versions 8.5p1–9.7 are affected by CVE-2024-6387.',
      classification: { cve: ['CVE-2024-6387'], cvss: 8.1 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['OpenSSH_(?:8\\.[5-9]|9\\.[0-7])'] }]
  },
  {
    id: 'banner-openssh-userenum', kind: 'port', confidence: 'suspected',
    info: { name: 'OpenSSH < 7.7 username enumeration (banner match)', severity: 'medium', tags: ['ssh', 'cve'],
      remediation: 'Upgrade OpenSSH to ≥ 7.7; earlier versions allow username enumeration.',
      classification: { cve: ['CVE-2018-15473'], cvss: 5.3 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['OpenSSH_(?:[1-6]\\.|7\\.[0-6])'] }]
  },
  {
    id: 'banner-apache-traversal', kind: 'port', confidence: 'suspected',
    info: { name: 'Apache 2.4.49/2.4.50 path traversal (banner match)', severity: 'critical', tags: ['http', 'cve'],
      remediation: 'Upgrade Apache httpd; 2.4.49/2.4.50 are vulnerable to path traversal/RCE.',
      classification: { cve: ['CVE-2021-41773', 'CVE-2021-42013'], cvss: 9.8 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['Apache/2\\.4\\.(?:49|50)'] }]
  },
  {
    id: 'banner-nginx-chunked', kind: 'port', confidence: 'suspected',
    info: { name: 'nginx 1.3.9–1.4.0 chunked overflow (banner match)', severity: 'high', tags: ['http', 'cve'],
      remediation: 'Upgrade nginx; 1.3.9–1.4.0 are vulnerable to a stack buffer overflow.',
      classification: { cve: ['CVE-2013-2028'], cvss: 7.5 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['nginx/1\\.(?:3\\.9|3\\.1[0-9]|4\\.0)'] }]
  },
  {
    id: 'banner-exim-cve-2019-10149', kind: 'port', confidence: 'suspected',
    info: { name: 'Exim 4.87–4.91 RCE (banner match)', severity: 'critical', tags: ['smtp', 'cve'],
      remediation: 'Upgrade Exim to ≥ 4.92; 4.87–4.91 allow remote command execution ("Return of the WIZard").',
      classification: { cve: ['CVE-2019-10149'], cvss: 9.8 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['Exim\\s*4\\.8[7-9]', 'Exim\\s*4\\.9[01]'] }]
  },
  {
    id: 'banner-iis6-webdav', kind: 'port', confidence: 'suspected',
    info: { name: 'Microsoft IIS 6.0 WebDAV RCE (banner match)', severity: 'high', tags: ['http', 'cve'],
      remediation: 'IIS 6.0 is end-of-life; CVE-2017-7269 allows RCE via WebDAV. Migrate off IIS 6.0.',
      classification: { cve: ['CVE-2017-7269'], cvss: 8.8 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['Microsoft-IIS/6\\.0'] }]
  },

  // =========================================================================
  // HTTP PASSIVE — from proxy responses (confirmed facts unless inferred)
  // =========================================================================
  {
    id: 'http-missing-hsts', kind: 'http-passive', confidence: 'confirmed', scheme: 'https',
    info: { name: 'Missing HTTP Strict-Transport-Security', severity: 'low', tags: ['http', 'headers'],
      remediation: 'Add a Strict-Transport-Security header on HTTPS responses.',
      classification: { cwe: ['CWE-319'] } },
    matchers: [{ type: 'word', part: 'header', words: ['strict-transport-security'], negative: true }]
  },
  {
    id: 'http-missing-csp', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Missing Content-Security-Policy', severity: 'low', tags: ['http', 'headers'],
      remediation: 'Define a Content-Security-Policy to mitigate XSS and injection.',
      classification: { cwe: ['CWE-693'] } },
    matchers: [{ type: 'word', part: 'header', words: ['content-security-policy'], negative: true }]
  },
  {
    id: 'http-missing-xfo', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Missing X-Frame-Options (clickjacking)', severity: 'low', tags: ['http', 'headers'],
      remediation: 'Send X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive.',
      classification: { cwe: ['CWE-1021'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-frame-options', 'frame-ancestors'], negative: true, condition: 'or' }]
  },
  {
    id: 'http-missing-xcto', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Missing X-Content-Type-Options: nosniff', severity: 'info', tags: ['http', 'headers'],
      remediation: 'Send X-Content-Type-Options: nosniff to stop MIME sniffing.',
      classification: { cwe: ['CWE-693'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-content-type-options'], negative: true }]
  },
  {
    id: 'http-missing-referrer-policy', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Missing Referrer-Policy', severity: 'info', tags: ['http', 'headers'],
      remediation: 'Send a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referer leakage.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'word', part: 'header', words: ['referrer-policy'], negative: true }]
  },
  {
    id: 'http-missing-permissions-policy', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Missing Permissions-Policy', severity: 'info', tags: ['http', 'headers'],
      remediation: 'Send a Permissions-Policy to restrict powerful browser features.',
      classification: { cwe: ['CWE-693'] } },
    matchers: [{ type: 'word', part: 'header', words: ['permissions-policy', 'feature-policy'], negative: true, condition: 'or' }]
  },
  {
    id: 'http-cors-wildcard', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'CORS wildcard observed (verify data exposure)', severity: 'info', tags: ['http', 'cors'],
      remediation: 'Verify whether the response contains sensitive data. Restrict allowed origins on authenticated endpoints.',
      classification: { cwe: ['CWE-942'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^access-control-allow-origin:\\s*\\*\\s*$'] }]
  },
  {
    id: 'http-cors-credentials-wildcard', kind: 'http-passive', confidence: 'suspected',
    info: { name: 'Credentialed CORS policy (verify origin allow-list)', severity: 'medium', tags: ['http', 'cors'],
      remediation: 'Never combine Access-Control-Allow-Credentials: true with a reflected/wildcard origin.',
      classification: { cwe: ['CWE-942'] } },
    matchers: [
      { type: 'regex', part: 'header', regex: ['^access-control-allow-origin:\\s*(?!\\*).+$'] },
      { type: 'word', part: 'header', words: ['access-control-allow-credentials: true'] }
    ], matchersCondition: 'and'
  },
  {
    id: 'http-cookie-httponly', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Cookie without HttpOnly flag', severity: 'low', tags: ['http', 'cookie'],
      remediation: 'Set HttpOnly on session cookies to block script access.',
      classification: { cwe: ['CWE-1004'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^set-cookie:(?![^\\n]*;\\s*httponly\\b)[^\\n]*$'] }]
  },
  {
    id: 'http-cookie-secure', kind: 'http-passive', confidence: 'confirmed', scheme: 'https',
    info: { name: 'Cookie without Secure flag (HTTPS)', severity: 'medium', tags: ['http', 'cookie'],
      remediation: 'Set the Secure flag so cookies are only sent over HTTPS.',
      classification: { cwe: ['CWE-614'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^set-cookie:(?![^\\n]*;\\s*secure\\b)[^\\n]*$'] }]
  },
  {
    id: 'http-cookie-samesite', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Cookie without SameSite attribute', severity: 'low', tags: ['http', 'cookie'],
      remediation: 'Set SameSite=Lax or Strict on cookies to mitigate CSRF.',
      classification: { cwe: ['CWE-1275'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^set-cookie:(?![^\\n]*;\\s*samesite=)[^\\n]*$'] }]
  },
  {
    id: 'http-basic-auth-cleartext', kind: 'http-passive', confidence: 'confirmed', scheme: 'http',
    info: { name: 'HTTP Basic auth over cleartext', severity: 'medium', tags: ['http', 'auth'],
      remediation: 'Never request Basic credentials over plain HTTP; enforce HTTPS.',
      classification: { cwe: ['CWE-319'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^www-authenticate:\\s*basic'] }]
  },
  {
    id: 'http-server-version', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Server version disclosure', severity: 'low', tags: ['http', 'disclosure'],
      remediation: 'Suppress version numbers in the Server header.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^server:\\s*[^\\n]*\\d+\\.\\d+'] }],
    extractors: [{ name: 'server', type: 'kval', kval: ['server'] }]
  },
  {
    id: 'http-powered-by', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Technology disclosure via X-Powered-By', severity: 'info', tags: ['http', 'disclosure'],
      remediation: 'Remove the X-Powered-By header.', classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-powered-by'] }],
    extractors: [{ name: 'powered-by', type: 'kval', kval: ['x-powered-by'] }]
  },
  {
    id: 'http-aspnet-version', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'ASP.NET version disclosure', severity: 'info', tags: ['http', 'disclosure'],
      remediation: 'Remove X-AspNet-Version / X-AspNetMvc-Version headers.', classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-aspnet-version', 'x-aspnetmvc-version'], condition: 'or' }],
    extractors: [{ name: 'aspnet', type: 'kval', kval: ['x-aspnet-version', 'x-aspnetmvc-version'] }]
  },
  {
    id: 'http-debug-symfony', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Symfony profiler / debug header present', severity: 'medium', tags: ['http', 'debug'],
      remediation: 'Disable the Symfony profiler (debug mode) in production.',
      classification: { cwe: ['CWE-489'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-debug-token', 'x-debug-token-link'], condition: 'or' }]
  },
  {
    id: 'http-private-ip-disclosure', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Internal/private IP address disclosed', severity: 'low', tags: ['http', 'disclosure'],
      remediation: 'Avoid leaking RFC1918 addresses in headers/body (Location, Via, X-* headers).',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'header', regex: [
      '(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})'
    ] }],
    extractors: [{ name: 'ip', type: 'regex', regex: ['(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})'], part: 'header' }]
  },
  {
    id: 'http-secret-leak', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Secret / API key leaked in response body', severity: 'high', tags: ['http', 'secrets'],
      remediation: 'Remove credentials from responses and rotate any exposed key immediately.',
      classification: { cwe: ['CWE-200', 'CWE-312'] } },
    matchers: [{ type: 'regex', part: 'body', condition: 'or', regex: [
      'AKIA[0-9A-Z]{16}',                    // AWS access key id
      'AIza[0-9A-Za-z\\-_]{35}',             // Google API key
      'ghp_[0-9A-Za-z]{36}',                 // GitHub personal access token
      'xox[baprs]-[0-9A-Za-z-]{10,}',        // Slack token
      '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
    ] }],
    extractors: [{ name: 'secret', type: 'regex', part: 'body', regex: [
      'AKIA[0-9A-Z]{16}', 'AIza[0-9A-Za-z\\-_]{35}', 'ghp_[0-9A-Za-z]{36}', 'xox[baprs]-[0-9A-Za-z-]{10,}'
    ] }]
  },
  {
    id: 'http-jwt-in-body', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'JSON Web Token present in response', severity: 'info', tags: ['http', 'token'],
      remediation: 'Review whether a JWT should be returned in the body; ensure it is short-lived.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'body', regex: ['eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}'] }]
  },
  {
    id: 'http-dir-listing', kind: 'http-passive', confidence: 'confirmed', group: 'dir-listing',
    info: { name: 'Directory listing enabled', severity: 'medium', tags: ['http', 'disclosure'],
      remediation: 'Disable automatic directory indexing.', classification: { cwe: ['CWE-548'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['Index of /', '<title>Index of'], condition: 'or' }
    ], matchersCondition: 'and'
  },
  {
    id: 'http-default-page', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Default web server welcome page', severity: 'info', tags: ['http', 'default'],
      remediation: 'Replace default server pages; they reveal the stack and that the host is unconfigured.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'word', part: 'body', condition: 'or', words: [
      'Welcome to nginx!', 'Apache2 Ubuntu Default Page', 'It works!',
      'IIS Windows Server', 'Welcome to CentOS', 'Test Page for the Apache'
    ] }]
  },
  {
    id: 'http-sql-error', kind: 'http-passive', confidence: 'suspected',
    info: { name: 'SQL error message in response', severity: 'high', tags: ['http', 'sqli'],
      remediation: 'Verify for SQL injection; suppress database error messages.',
      classification: { cwe: ['CWE-89'] } },
    matchers: [{ type: 'regex', part: 'body', condition: 'or', regex: [
      'SQL syntax.*MySQL', 'Warning.*\\bmysqli?_', 'PostgreSQL.*ERROR', 'ORA-\\d{5}',
      'Microsoft OLE DB Provider for SQL Server', 'Unclosed quotation mark after the character string',
      'SQLite/JDBCDriver', 'org\\.postgresql\\.util\\.PSQLException', 'System\\.Data\\.SqlClient\\.SqlException'
    ] }]
  },
  {
    id: 'http-stacktrace', kind: 'http-passive', confidence: 'suspected',
    info: { name: 'Stack trace / debug output in response', severity: 'medium', tags: ['http', 'disclosure'],
      remediation: 'Disable debug mode in production; return generic error pages.',
      classification: { cwe: ['CWE-209'] } },
    matchers: [{ type: 'regex', part: 'body', condition: 'or', regex: [
      'Traceback \\(most recent call last\\)', 'Exception in thread', '\\bat [\\w.$]+\\([\\w.]+\\.java:\\d+\\)',
      '<b>Fatal error</b>:', '<b>Warning</b>:', 'System\\.NullReferenceException',
      '\\bat [\\w.]+ \\(.*:\\d+:\\d+\\)', 'Whoops, looks like something went wrong'
    ] }]
  },

  // =========================================================================
  // HTTP ACTIVE — scope-gated oracle probes (confirmed; READ-only, no exploit)
  // =========================================================================

  // ---- source control metadata ----
  expose('expose-git-config', '/.git/config', 'high', 'Exposed .git/config',
    W('body', ['[core]', 'repositoryformatversion']),
    'Block access to the .git directory on the web server.',
    { tags: ['exposure', 'scm'], cwe: ['CWE-538'], cvss: 7.5, group: 'git-exposed' }),
  expose('expose-git-head', '/.git/HEAD', 'high', 'Exposed .git/HEAD (repository leak)',
    RX('body', ['^ref:\\s+refs/']),
    'Block access to the .git directory; the whole repo may be downloadable.',
    { tags: ['exposure', 'scm'], cwe: ['CWE-538'], cvss: 7.5, group: 'git-exposed' }),
  expose('expose-git-credentials', '/.git-credentials', 'critical', 'Exposed .git-credentials',
    RX('body', ['https?://[^:/\\s]+:[^@/\\s]+@']),
    'Delete .git-credentials from the web root and rotate the leaked credentials.',
    { tags: ['exposure', 'secrets'], cwe: ['CWE-538'], cvss: 9.1 }),
  expose('expose-svn', '/.svn/wc.db', 'high', 'Exposed Subversion wc.db',
    W('body', ['SQLite format 3']),
    'Block access to .svn metadata directories.',
    { tags: ['exposure', 'scm'], cwe: ['CWE-538'] }),
  expose('expose-hg', '/.hg/requires', 'medium', 'Exposed Mercurial .hg metadata',
    W('body', ['revlogv1', 'store', 'dotencode'], ),
    'Block access to .hg metadata directories.',
    { tags: ['exposure', 'scm'], cwe: ['CWE-538'] }),
  expose('expose-bzr', '/.bzr/README', 'medium', 'Exposed Bazaar .bzr metadata',
    W('body', ['This is a Bazaar']),
    'Block access to .bzr metadata directories.',
    { tags: ['exposure', 'scm'], cwe: ['CWE-538'] }),

  // ---- environment, secrets & config files ----
  {
    id: 'expose-dotenv', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/.env' },
    info: { name: 'Exposed .env configuration file', severity: 'critical', tags: ['exposure', 'secrets'],
      remediation: 'Never serve .env from the web root; move secrets outside the docroot and rotate them.',
      classification: { cwe: ['CWE-538'], cvss: 9.1 } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'regex', part: 'body', regex: ['(?:^|\\n)\\s*(?:APP_|DB_|DATABASE_|SECRET|API_KEY|AWS_|MAIL_|REDIS_)[A-Z0-9_]*\\s*='] }
    ], matchersCondition: 'and',
    extractors: [{ name: 'keys', type: 'regex', part: 'body', regex: ['(?:^|\\n)\\s*([A-Z0-9_]+)\\s*='], group: 1 }]
  },
  expose('expose-aws-credentials', '/.aws/credentials', 'critical', 'Exposed AWS credentials file',
    W('body', ['aws_access_key_id', 'aws_secret_access_key']),
    'Remove the .aws directory from the web root and rotate the keys.',
    { tags: ['exposure', 'secrets', 'cloud'], cwe: ['CWE-538'], cvss: 9.8 }),
  expose('expose-npmrc', '/.npmrc', 'high', 'Exposed .npmrc (registry token)',
    RX('body', ['_authToken\\s*=', '//[^/]+/:_authToken']),
    'Remove .npmrc from the web root and rotate the npm token.',
    { tags: ['exposure', 'secrets'], cwe: ['CWE-538'] }),
  expose('expose-htpasswd', '/.htpasswd', 'high', 'Exposed .htpasswd',
    RX('body', ['^[^:\\s]+:\\$(?:apr1|2[aby]|1|5|6)\\$', '^[^:\\s]+:\\{SHA\\}']),
    'Block access to .htpasswd; it contains password hashes.',
    { tags: ['exposure', 'secrets'], cwe: ['CWE-538'] }),
  expose('expose-web-config', '/web.config', 'high', 'Exposed web.config',
    W('body', ['<configuration>', '<system.web']),
    'Block direct access to web.config; it can contain connection strings and secrets.',
    { tags: ['exposure', 'config', 'aspnet'], cwe: ['CWE-538'] }),
  expose('expose-ssh-key', '/id_rsa', 'critical', 'Exposed SSH private key',
    W('body', ['-----BEGIN', 'PRIVATE KEY'], 'and'),
    'Remove the private key from the web root and rotate the key pair.',
    { tags: ['exposure', 'secrets'], cwe: ['CWE-538'], cvss: 9.8 }),
  expose('expose-docker-compose', '/docker-compose.yml', 'medium', 'Exposed docker-compose.yml',
    W('body', ['services:', 'image:'], 'and'),
    'Do not serve docker-compose.yml; it often embeds env vars and secrets.',
    { tags: ['exposure', 'config', 'container'], cwe: ['CWE-538'] }),
  expose('expose-dockerfile', '/Dockerfile', 'low', 'Exposed Dockerfile',
    RX('body', ['^FROM\\s+\\S+']),
    'Do not serve the Dockerfile from the web root.',
    { tags: ['exposure', 'config', 'container'], cwe: ['CWE-200'] }),
  expose('expose-composer-json', '/composer.json', 'info', 'Exposed composer.json',
    W('body', ['"require"', '"autoload"']),
    'Avoid serving dependency manifests; they aid fingerprinting.',
    { tags: ['exposure', 'config', 'php'], cwe: ['CWE-200'] }),
  expose('expose-package-json', '/package.json', 'info', 'Exposed package.json',
    W('body', ['"dependencies"', '"devDependencies"']),
    'Avoid serving package.json from the web root; it aids dependency fingerprinting.',
    { tags: ['exposure', 'config', 'node'], cwe: ['CWE-200'] }),
  expose('expose-gitlab-ci', '/.gitlab-ci.yml', 'low', 'Exposed .gitlab-ci.yml',
    W('body', ['stages:', 'script:']),
    'Do not serve CI config; it can reveal pipeline secrets and internal hosts.',
    { tags: ['exposure', 'config', 'ci'], cwe: ['CWE-200'] }),
  expose('expose-ds-store', '/.DS_Store', 'low', 'Exposed .DS_Store (directory names leak)',
    W('body', ['Bud1']),
    'Remove .DS_Store files; they leak directory and file names.',
    { tags: ['exposure'], cwe: ['CWE-538'] }),
  expose('expose-wpconfig-bak', '/wp-config.php.bak', 'critical', 'Exposed wp-config.php backup',
    W('body', ['DB_PASSWORD', 'DB_NAME']),
    'Remove wp-config backups from the web root and rotate the DB credentials.',
    { tags: ['exposure', 'secrets', 'wordpress'], cwe: ['CWE-538'], cvss: 9.1 }),

  // ---- backups / database dumps ----
  expose('expose-backup-sql', '/backup.sql', 'high', 'Exposed SQL backup (backup.sql)',
    RX('body', ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE']),
    'Remove database dumps from the web root.',
    { tags: ['exposure', 'backup'], cwe: ['CWE-538'], group: 'sql-dump' }),
  expose('expose-dump-sql', '/dump.sql', 'high', 'Exposed SQL backup (dump.sql)',
    RX('body', ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE']),
    'Remove database dumps from the web root.',
    { tags: ['exposure', 'backup'], cwe: ['CWE-538'], group: 'sql-dump' }),
  expose('expose-database-sql', '/database.sql', 'high', 'Exposed SQL backup (database.sql)',
    RX('body', ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE']),
    'Remove database dumps from the web root.',
    { tags: ['exposure', 'backup'], cwe: ['CWE-538'], group: 'sql-dump' }),

  // ---- server status / info endpoints ----
  expose('expose-apache-status', '/server-status', 'medium', 'Exposed Apache server-status',
    W('body', ['Apache Server Status']),
    'Restrict mod_status to localhost.',
    { tags: ['exposure', 'apache'], cwe: ['CWE-200'] }),
  expose('expose-apache-info', '/server-info', 'medium', 'Exposed Apache server-info',
    W('body', ['Apache Server Information']),
    'Restrict mod_info to localhost or disable it.',
    { tags: ['exposure', 'apache'], cwe: ['CWE-200'] }),
  expose('expose-nginx-status', '/nginx_status', 'low', 'Exposed nginx stub_status',
    W('body', ['Active connections:'], ),
    'Restrict the stub_status endpoint to localhost.',
    { tags: ['exposure', 'nginx'], cwe: ['CWE-200'] }),
  {
    id: 'expose-phpinfo', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/phpinfo.php' },
    info: { name: 'Exposed phpinfo()', severity: 'medium', tags: ['exposure', 'php'],
      remediation: 'Remove phpinfo pages from production.', classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['phpinfo()', '<title>phpinfo()', 'PHP Version'], condition: 'or' }
    ], matchersCondition: 'and',
    extractors: [{ name: 'php', type: 'regex', part: 'body', regex: ['PHP Version ([0-9.]+)'], group: 1 }]
  },
  expose('expose-phpinfo-info', '/info.php', 'medium', 'Exposed phpinfo() (info.php)',
    W('body', ['phpinfo()', 'PHP Version']),
    'Remove phpinfo pages from production.',
    { tags: ['exposure', 'php'], cwe: ['CWE-200'],
      extractors: [{ name: 'php', type: 'regex', part: 'body', regex: ['PHP Version ([0-9.]+)'], group: 1 }] }),

  // ---- frameworks / actuators / debug surfaces ----
  expose('expose-spring-actuator', '/actuator', 'medium', 'Exposed Spring Boot Actuator index',
    W('body', ['"_links"', '/actuator/'], 'and'),
    'Restrict Spring Boot Actuator endpoints; do not expose them unauthenticated.',
    { tags: ['exposure', 'spring'], cwe: ['CWE-200'] }),
  expose('expose-actuator-env', '/actuator/env', 'high', 'Exposed Spring Actuator /env',
    W('body', ['propertySources', 'systemProperties'], 'or'),
    'Disable or secure the /env actuator; it leaks configuration and secrets.',
    { tags: ['exposure', 'spring'], cwe: ['CWE-200'], cvss: 7.5 }),
  expose('expose-actuator-health', '/actuator/health', 'info', 'Exposed Spring Actuator /health',
    W('body', ['"status":"UP"', '"status": "UP"'], 'or'),
    'Restrict actuator endpoints to internal monitoring only.',
    { tags: ['exposure', 'spring'], cwe: ['CWE-200'] }),
  expose('expose-symfony-profiler', '/_profiler', 'medium', 'Exposed Symfony profiler',
    W('body', ['Symfony Profiler', 'sf-toolbar'], 'or'),
    'Disable the Symfony profiler (APP_ENV=prod, APP_DEBUG=0).',
    { tags: ['exposure', 'php', 'debug'], cwe: ['CWE-489'] }),
  expose('expose-laravel-telescope', '/telescope/requests', 'high', 'Exposed Laravel Telescope',
    W('body', ['Telescope', 'laravel']),
    'Restrict Laravel Telescope to local/authorized users in production.',
    { tags: ['exposure', 'php', 'debug'], cwe: ['CWE-489'] }),
  expose('expose-go-pprof', '/debug/pprof/', 'medium', 'Exposed Go pprof debug endpoint',
    W('body', ['Types of profiles available', '/debug/pprof/']),
    'Do not expose net/http/pprof in production.',
    { tags: ['exposure', 'golang', 'debug'], cwe: ['CWE-200'] }),
  expose('expose-trace-axd', '/trace.axd', 'medium', 'Exposed ASP.NET trace.axd',
    W('body', ['Application Trace', 'Microsoft .NET']),
    'Disable ASP.NET tracing (trace enabled="false") in production.',
    { tags: ['exposure', 'aspnet', 'debug'], cwe: ['CWE-200'] }),
  expose('expose-elmah', '/elmah.axd', 'high', 'Exposed ELMAH error log',
    W('body', ['Error Log for', 'ELMAH']),
    'Restrict ELMAH to local access; it leaks errors and may allow log poisoning.',
    { tags: ['exposure', 'aspnet', 'debug'], cwe: ['CWE-200'] }),

  // ---- API docs / schemas ----
  expose('expose-swagger-json', '/swagger.json', 'low', 'Exposed Swagger/OpenAPI spec',
    W('body', ['"swagger"', '"openapi"'], 'or'),
    'Review whether the API spec should be public; it enumerates every endpoint.',
    { tags: ['exposure', 'api'], cwe: ['CWE-200'] }),
  expose('expose-openapi-json', '/openapi.json', 'low', 'Exposed OpenAPI spec',
    W('body', ['"openapi"', '"paths"'], 'and'),
    'Review whether the API spec should be public.',
    { tags: ['exposure', 'api'], cwe: ['CWE-200'] }),
  detect('detect-swagger-ui', '/swagger-ui.html', 'Swagger UI exposed',
    W('body', ['Swagger UI', 'swagger-ui'], 'or'), { tags: ['tech', 'api'] }),
  {
    id: 'expose-graphql-introspection', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D' },
    info: { name: 'GraphQL introspection enabled', severity: 'medium', tags: ['exposure', 'api', 'graphql'],
      remediation: 'Disable GraphQL introspection in production to stop schema enumeration.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['__schema', 'queryType'], condition: 'and' }
    ], matchersCondition: 'and'
  },

  // ---- WordPress / CMS specifics ----
  {
    id: 'expose-wp-users', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/wp-json/wp/v2/users' },
    info: { name: 'WordPress REST user enumeration', severity: 'medium', tags: ['exposure', 'wordpress'],
      remediation: 'Restrict the /wp-json/wp/v2/users endpoint; it enumerates account usernames (slugs).',
      classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'regex', part: 'body', regex: ['"slug"\\s*:\\s*"'] }
    ], matchersCondition: 'and',
    extractors: [{ name: 'user', type: 'regex', part: 'body', regex: ['"slug"\\s*:\\s*"([^"]+)"'], group: 1 }]
  },
  expose('expose-wp-debug-log', '/wp-content/debug.log', 'medium', 'Exposed WordPress debug.log',
    RX('body', ['PHP (?:Notice|Warning|Fatal error|Deprecated)']),
    'Disable WP_DEBUG_LOG in production and delete debug.log.',
    { tags: ['exposure', 'wordpress', 'debug'], cwe: ['CWE-200'] }),
  detect('detect-wp-login', '/wp-login.php', 'WordPress login page',
    W('body', ['wp-submit', 'user_login'], 'or'), { tags: ['tech', 'wordpress'] }),
  {
    id: 'detect-wp-readme', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/readme.html' },
    info: { name: 'WordPress version disclosure (readme.html)', severity: 'low', tags: ['tech', 'wordpress', 'disclosure'],
      remediation: 'Delete readme.html; it reveals the exact WordPress version.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['WordPress'] }
    ], matchersCondition: 'and',
    extractors: [{ name: 'wp-version', type: 'regex', part: 'body', regex: ['Version\\s+([0-9.]+)'], group: 1 }]
  },
  expose('expose-drupal-changelog', '/CHANGELOG.txt', 'low', 'Drupal CHANGELOG.txt version disclosure',
    W('body', ['Drupal']),
    'Remove CHANGELOG.txt; it reveals the Drupal version.',
    { tags: ['tech', 'drupal', 'disclosure'], cwe: ['CWE-200'],
      extractors: [{ name: 'drupal', type: 'regex', part: 'body', regex: ['Drupal ([0-9.]+)'], group: 1 }] }),

  // ---- policy / cross-domain files ----
  expose('expose-crossdomain-wildcard', '/crossdomain.xml', 'medium', 'Overly permissive crossdomain.xml',
    RX('body', ['allow-access-from\\s+domain="\\*"']),
    'Do not allow domain="*" in crossdomain.xml.',
    { tags: ['exposure', 'flash'], cwe: ['CWE-942'] }),
  expose('expose-clientaccesspolicy', '/clientaccesspolicy.xml', 'medium', 'Overly permissive clientaccesspolicy.xml',
    RX('body', ['<domain\\s+uri="\\*"']),
    'Do not allow uri="*" in clientaccesspolicy.xml.',
    { tags: ['exposure', 'silverlight'], cwe: ['CWE-942'] }),

  // ---- databases / search engines over HTTP ----
  expose('expose-elasticsearch', '/', 'high', 'Elasticsearch reachable (possibly unauthenticated)',
    W('body', ['"cluster_name"', '"lucene_version"'], 'and'),
    'Never expose Elasticsearch directly; put it behind auth and bind to localhost.',
    { tags: ['exposure', 'database', 'elastic'], cwe: ['CWE-306'], cvss: 7.5,
      extractors: [{ name: 'cluster', type: 'regex', part: 'body', regex: ['"cluster_name"\\s*:\\s*"([^"]+)"'], group: 1 }] }),
  expose('expose-couchdb', '/', 'high', 'CouchDB reachable (possibly unauthenticated)',
    W('body', ['"couchdb":"Welcome"', 'Welcome', 'couchdb'], 'and'),
    'Do not expose CouchDB; require authentication and restrict the bind address.',
    { tags: ['exposure', 'database', 'couchdb'], cwe: ['CWE-306'] }),

  // ---- admin panels (detection only; presence, not bypass) ----
  detect('detect-phpmyadmin', '/phpmyadmin/', 'phpMyAdmin panel exposed',
    W('body', ['phpMyAdmin'], ), { severity: 'low', tags: ['panel', 'database'] }),
  detect('detect-adminer', '/adminer.php', 'Adminer database panel exposed',
    W('body', ['Adminer', 'Login - Adminer'], 'or'), { severity: 'low', tags: ['panel', 'database'] }),
  detect('detect-tomcat-manager', '/manager/html', 'Tomcat Manager reachable',
    W('response', ['tomcat', 'manager'], 'and'), { severity: 'medium', tags: ['panel'], status: [200, 401, 403] }),
  detect('detect-solr', '/solr/', 'Apache Solr admin reachable',
    W('body', ['Solr Admin', 'solr'], 'or'), { severity: 'medium', tags: ['panel', 'search'] }),
  detect('detect-jenkins', '/login', 'Jenkins login page',
    W('response', ['x-jenkins', 'Jenkins'], 'or'), { severity: 'low', tags: ['panel', 'ci'] }),
  detect('detect-grafana', '/login', 'Grafana login page',
    W('body', ['Grafana', 'grafana-app'], 'or'), { severity: 'info', tags: ['panel', 'monitoring'] }),
  detect('detect-kibana', '/app/kibana', 'Kibana reachable',
    W('response', ['kbn-name', 'kibana'], 'or'), { severity: 'low', tags: ['panel', 'elastic'] }),
  detect('detect-gitlab', '/users/sign_in', 'GitLab sign-in page',
    W('body', ['GitLab', 'gitlab'], 'or'), { severity: 'info', tags: ['panel', 'scm'] }),
  detect('detect-jira', '/secure/Dashboard.jspa', 'Atlassian Jira reachable',
    W('response', ['atlassian', 'jira'], 'or'), { severity: 'info', tags: ['panel'] }),
  detect('detect-webmin', '/', 'Webmin panel reachable',
    W('response', ['webmin', 'Server: MiniServ'], 'or'), { severity: 'low', tags: ['panel'] })
]

// =========================================================================
// GENERATED TEMPLATE PACKS
// Data-driven expansion. Every generated template requires a DISTINCTIVE
// content marker (never status alone), so an over-tight marker yields at most a
// false negative, never a false positive. Backup/variant families share a
// `group`, so `correlate` collapses them to a single finding per host.
// =========================================================================

// ---- active exposed-file helper ----
interface AfOpts { cwe?: string[]; cve?: string[]; cvss?: number; tags?: string[]; cond?: 'and' | 'or'; rx?: boolean; part?: Matcher['part']; status?: number[]; group?: string; extractors?: Extractor[] }
function af(id: string, path: string, sev: RuleSeverity, name: string, marker: string | string[], rem: string, ex: AfOpts = {}): Template {
  const words = Array.isArray(marker) ? marker : [marker]
  const m = ex.rx ? RX(ex.part || 'body', words, ex.cond || 'or') : W(ex.part || 'body', words, ex.cond || 'or')
  return {
    id, kind: 'http-active', confidence: 'confirmed', group: ex.group,
    request: { method: 'GET', path },
    info: { name, severity: sev, tags: ex.tags || ['exposure'], remediation: rem, classification: { cwe: ex.cwe, cve: ex.cve, cvss: ex.cvss } },
    matchers: [S(...(ex.status || [200])), m], matchersCondition: 'and', extractors: ex.extractors
  }
}
const REM_BACKUP = 'Remove editor/backup copies of config files from the web root and rotate any exposed secrets.'
const REM_EXPOSE = 'Block web access to this file; it should not be served from the document root.'
const REM_SECRET = 'Remove the file from the web root and rotate every exposed credential immediately.'

// ---- 1) config backups (secret marker required → confirmed, deduped by group) ----
const BAK_SUFFIX = ['.bak', '.old', '.orig', '.save', '.swp', '~', '.txt', '.inc', '.1', '.2', '.copy', '.backup']
const BAK_CONFIG: Array<{ k: string; base: string; name: string; rx: string[]; sev: RuleSeverity; cvss?: number }> = [
  { k: 'wpconfig', base: '/wp-config.php', name: 'WordPress wp-config.php', rx: ['DB_PASSWORD', 'DB_NAME', 'AUTH_KEY'], sev: 'critical', cvss: 9.1 },
  { k: 'configphp', base: '/config.php', name: 'PHP config.php', rx: ['DB_PASSWORD', 'mysql_connect', '\\$db_pass', '\\$password'], sev: 'high' },
  { k: 'joomla', base: '/configuration.php', name: 'Joomla configuration.php', rx: ['JConfig', 'public \\$password', 'var \\$password'], sev: 'high' },
  { k: 'drupal', base: '/sites/default/settings.php', name: 'Drupal settings.php', rx: ['\\$databases', 'drupal_hash_salt'], sev: 'high' },
  { k: 'django', base: '/settings.py', name: 'Django settings.py', rx: ['SECRET_KEY\\s*=', 'DATABASES\\s*='], sev: 'high' },
  { k: 'spring', base: '/application.properties', name: 'Spring application.properties', rx: ['spring\\.datasource\\.password', 'datasource\\.password'], sev: 'high' },
  { k: 'rails', base: '/config/database.yml', name: 'Rails database.yml', rx: ['password:\\s', 'adapter:\\s'], sev: 'high', cvss: 7.5 },
  { k: 'symfony', base: '/app/config/parameters.yml', name: 'Symfony parameters.yml', rx: ['database_password', 'secret:\\s'], sev: 'high' }
]
function genBackups(): Template[] {
  const out: Template[] = []
  for (const c of BAK_CONFIG) for (const suf of BAK_SUFFIX) {
    const sfx = suf.replace(/[^a-z0-9]/gi, '') || 'tilde'
    out.push(af(`bak-${c.k}-${sfx}`, c.base + suf, c.sev, `${c.name} backup exposed (${suf})`, c.rx, REM_BACKUP,
      { rx: true, cwe: ['CWE-538'], cvss: c.cvss, tags: ['exposure', 'backup', 'secrets'], group: `bak-${c.k}` }))
  }
  return out
}

// ---- 2) environment file variants ----
const ENV_PATHS = ['/.env.bak', '/.env.old', '/.env.save', '/.env.local', '/.env.prod', '/.env.production', '/.env.dev', '/.env.development', '/.env.backup']
function genEnv(): Template[] {
  return ENV_PATHS.map((p) => af(
    `env-${p.replace(/[^a-z0-9]/gi, '')}`, p, 'critical', `Exposed environment file (${p})`,
    ['(?:^|\\n)\\s*(?:APP_|DB_|DATABASE_|SECRET|API_KEY|AWS_|MAIL_|REDIS_|JWT_|STRIPE_)[A-Z0-9_]*\\s*='], REM_SECRET,
    { rx: true, cwe: ['CWE-538'], cvss: 9.1, tags: ['exposure', 'secrets'], group: 'env-file',
      extractors: [{ name: 'keys', type: 'regex', part: 'body', regex: ['(?:^|\\n)\\s*([A-Z0-9_]+)\\s*='], group: 1 }] }))
}

// ---- 3) specific exposed files (content markers) ----
function genFiles(): Template[] {
  return [
    // VCS
    af('file-git-index', '/.git/index', 'high', 'Exposed .git/index', ['DIRC'], REM_EXPOSE, { tags: ['exposure', 'scm'], cwe: ['CWE-538'], group: 'git-exposed' }),
    af('file-git-logs', '/.git/logs/HEAD', 'high', 'Exposed .git/logs/HEAD', ['^[0-9a-f]{40}\\s'], REM_EXPOSE, { rx: true, tags: ['exposure', 'scm'], cwe: ['CWE-538'], group: 'git-exposed' }),
    af('file-git-packedrefs', '/.git/packed-refs', 'high', 'Exposed .git/packed-refs', ['# pack-refs'], REM_EXPOSE, { tags: ['exposure', 'scm'], cwe: ['CWE-538'], group: 'git-exposed' }),
    af('file-idea-datasources', '/.idea/dataSources.xml', 'high', 'Exposed JetBrains dataSources.xml (DB creds)', ['<data-source', 'jdbc'], REM_SECRET, { cond: 'and', tags: ['exposure', 'ide', 'secrets'], cwe: ['CWE-538'] }),
    af('file-idea-workspace', '/.idea/workspace.xml', 'low', 'Exposed JetBrains .idea/workspace.xml', ['<project version'], REM_EXPOSE, { tags: ['exposure', 'ide'], cwe: ['CWE-200'] }),
    af('file-sftp-config', '/sftp-config.json', 'high', 'Exposed Sublime sftp-config.json (credentials)', ['"password"', '"host"'], REM_SECRET, { cond: 'and', tags: ['exposure', 'ide', 'secrets'], cwe: ['CWE-538'] }),
    af('file-nbproject', '/nbproject/project.properties', 'low', 'Exposed NetBeans nbproject', ['javac.classpath', 'application.title'], REM_EXPOSE, { tags: ['exposure', 'ide'] }),
    // logs
    af('file-laravel-log', '/storage/logs/laravel.log', 'high', 'Exposed Laravel log', ['\\.(?:ERROR|CRITICAL): ', 'Stack trace:'], REM_EXPOSE, { rx: true, tags: ['exposure', 'logs'], cwe: ['CWE-200'] }),
    af('file-error-log', '/error.log', 'medium', 'Exposed error.log', ['\\[error\\]', 'PHP (?:Fatal|Warning|Notice)'], REM_EXPOSE, { rx: true, tags: ['exposure', 'logs'], cwe: ['CWE-200'] }),
    af('file-debug-log', '/debug.log', 'medium', 'Exposed debug.log', ['PHP (?:Notice|Warning|Fatal|Deprecated)'], REM_EXPOSE, { rx: true, tags: ['exposure', 'logs'], cwe: ['CWE-200'] }),
    af('file-npm-debug', '/npm-debug.log', 'low', 'Exposed npm-debug.log', ['npm ERR!'], REM_EXPOSE, { tags: ['exposure', 'logs'] }),
    af('file-rails-log', '/log/production.log', 'medium', 'Exposed Rails production.log', ['Started GET', 'ActionController'], REM_EXPOSE, { tags: ['exposure', 'logs'], cwe: ['CWE-200'] }),
    // CI / infra
    af('file-circleci', '/.circleci/config.yml', 'medium', 'Exposed CircleCI config', ['jobs:', 'version:'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'ci'], cwe: ['CWE-200'] }),
    af('file-gh-workflow', '/.github/workflows/ci.yml', 'medium', 'Exposed GitHub Actions workflow', ['jobs:', 'runs-on:'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'ci'], cwe: ['CWE-200'] }),
    af('file-azure-pipelines', '/azure-pipelines.yml', 'medium', 'Exposed Azure Pipelines config', ['trigger:', 'pool:'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'ci'] }),
    af('file-jenkinsfile', '/Jenkinsfile', 'medium', 'Exposed Jenkinsfile', ['pipeline {', 'stage(', 'node {'], REM_EXPOSE, { tags: ['exposure', 'ci'] }),
    af('file-drone', '/.drone.yml', 'medium', 'Exposed Drone CI config', ['kind: pipeline'], REM_EXPOSE, { tags: ['exposure', 'ci'] }),
    af('file-bitbucket', '/bitbucket-pipelines.yml', 'medium', 'Exposed Bitbucket Pipelines config', ['pipelines:'], REM_EXPOSE, { tags: ['exposure', 'ci'] }),
    af('file-travis', '/.travis.yml', 'low', 'Exposed .travis.yml', ['language:', 'script:'], REM_EXPOSE, { tags: ['exposure', 'ci'] }),
    af('file-tfstate', '/terraform.tfstate', 'high', 'Exposed Terraform state (may contain secrets)', ['"terraform_version"', '"resources"'], REM_SECRET, { cond: 'and', tags: ['exposure', 'iac', 'secrets'], cwe: ['CWE-538'] }),
    af('file-ansible', '/ansible.cfg', 'low', 'Exposed ansible.cfg', ['[defaults]', 'inventory'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'iac'] }),
    af('file-serverless', '/serverless.yml', 'medium', 'Exposed serverless.yml', ['service:', 'provider:'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'iac'] }),
    af('file-dockerrun', '/Dockerrun.aws.json', 'medium', 'Exposed Dockerrun.aws.json', ['AWSEBDockerrunVersion'], REM_EXPOSE, { tags: ['exposure', 'iac'] }),
    af('file-vagrantfile', '/Vagrantfile', 'low', 'Exposed Vagrantfile', ['Vagrant.configure'], REM_EXPOSE, { tags: ['exposure', 'iac'] }),
    // cloud creds
    af('file-aws-config', '/.aws/config', 'medium', 'Exposed AWS CLI config', ['[default]', 'region'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'cloud'], cwe: ['CWE-200'] }),
    af('file-boto', '/.boto', 'high', 'Exposed .boto credentials', ['[Credentials]', 'aws_access_key_id'], REM_SECRET, { cond: 'and', tags: ['exposure', 'cloud', 'secrets'], cwe: ['CWE-538'] }),
    af('file-s3cfg', '/.s3cfg', 'high', 'Exposed .s3cfg credentials', ['access_key', 'secret_key'], REM_SECRET, { cond: 'and', tags: ['exposure', 'cloud', 'secrets'], cwe: ['CWE-538'] }),
    af('file-docker-config', '/.docker/config.json', 'high', 'Exposed Docker registry config', ['"auths"'], REM_SECRET, { tags: ['exposure', 'cloud', 'secrets'], cwe: ['CWE-538'] }),
    af('file-kube-config', '/.kube/config', 'critical', 'Exposed Kubernetes kubeconfig', ['apiVersion', 'client-certificate-data', 'client-key-data'], REM_SECRET, { cond: 'and', tags: ['exposure', 'cloud', 'secrets'], cwe: ['CWE-538'], cvss: 9.1 }),
    af('file-netrc', '/.netrc', 'high', 'Exposed .netrc credentials', ['machine .* login .* password', 'password '], REM_SECRET, { rx: true, tags: ['exposure', 'secrets'], cwe: ['CWE-538'] }),
    // app configs
    af('file-appsettings', '/appsettings.json', 'high', 'Exposed appsettings.json (.NET)', ['ConnectionStrings', 'DefaultConnection'], REM_SECRET, { tags: ['exposure', 'config', 'aspnet'], cwe: ['CWE-538'] }),
    af('file-connstrings', '/ConnectionStrings.config', 'high', 'Exposed ConnectionStrings.config', ['connectionString'], REM_SECRET, { tags: ['exposure', 'config', 'aspnet'], cwe: ['CWE-538'] }),
    af('file-htaccess', '/.htaccess', 'low', 'Exposed .htaccess', ['RewriteEngine', 'RewriteRule', 'Options '], REM_EXPOSE, { tags: ['exposure', 'config'], cwe: ['CWE-200'] }),
    af('file-phpunit', '/phpunit.xml', 'low', 'Exposed phpunit.xml', ['<phpunit'], REM_EXPOSE, { tags: ['exposure', 'config'] }),
    // dependency manifests (fingerprinting)
    af('file-composerlock', '/composer.lock', 'info', 'Exposed composer.lock', ['"packages"', '"content-hash"'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'fingerprint'] }),
    af('file-yarnlock', '/yarn.lock', 'info', 'Exposed yarn.lock', ['# yarn lockfile'], REM_EXPOSE, { tags: ['exposure', 'fingerprint'] }),
    af('file-packagelock', '/package-lock.json', 'info', 'Exposed package-lock.json', ['"lockfileVersion"'], REM_EXPOSE, { tags: ['exposure', 'fingerprint'] }),
    af('file-gemfilelock', '/Gemfile.lock', 'info', 'Exposed Gemfile.lock', ['GEM', 'specs:'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'fingerprint'] }),
    af('file-pipfilelock', '/Pipfile.lock', 'info', 'Exposed Pipfile.lock', ['"_meta"', '"sha256"'], REM_EXPOSE, { cond: 'and', tags: ['exposure', 'fingerprint'] }),
    af('file-requirements', '/requirements.txt', 'info', 'Exposed requirements.txt', ['^[a-zA-Z0-9_.-]+==[0-9]'], REM_EXPOSE, { rx: true, tags: ['exposure', 'fingerprint'] }),
    // info / disclosure
    af('file-robots', '/robots.txt', 'info', 'robots.txt disclosed paths', ['Disallow:'], 'Review robots.txt — Disallow entries can reveal sensitive paths.', { tags: ['info', 'disclosure'], extractors: [{ name: 'disallow', type: 'regex', part: 'body', regex: ['Disallow:\\s*(\\S+)'], group: 1 }] }),
    af('file-sitemap', '/sitemap.xml', 'info', 'sitemap.xml exposed', ['<urlset', '<sitemapindex'], 'Informational: sitemap enumerates site URLs.', { tags: ['info'] }),
    af('file-securitytxt', '/.well-known/security.txt', 'info', 'security.txt present', ['Contact:'], 'Informational — good practice; verify the disclosure contact.', { tags: ['info'] })
  ]
}

// ---- 4) framework debug / actuator surfaces ----
function genActuators(): Template[] {
  const spring = (slug: string, marker: string | string[], sev: RuleSeverity = 'medium'): Template =>
    af(`act-sb-${slug}`, `/actuator/${slug}`, sev, `Spring Actuator /${slug} exposed`, marker, 'Secure or disable Spring Boot Actuator endpoints in production.', { tags: ['exposure', 'spring', 'debug'], cwe: ['CWE-200'] })
  return [
    spring('beans', '"beans"'), spring('mappings', '"mappings"'), spring('configprops', '"contexts"'),
    spring('threaddump', ['"threads"', 'threadName']), spring('loggers', '"loggers"'), spring('metrics', '"names"', 'low'),
    spring('httptrace', '"traces"'), spring('httpexchanges', '"exchanges"'), spring('scheduledtasks', '"cron"', 'low'),
    spring('prometheus', ['# HELP', '# TYPE'], 'low'), spring('gateway/routes', 'route_id'), spring('caches', '"cacheManagers"', 'low'),
    spring('conditions', '"positiveMatches"', 'low'), spring('sessions', '"sessions"'),
    // legacy (pre-2.0) actuator without /actuator prefix
    af('act-legacy-env', '/env', 'high', 'Spring legacy /env exposed', ['"systemProperties"', '"systemEnvironment"'], 'Disable or secure the legacy /env actuator; it leaks configuration.', { cond: 'or', tags: ['exposure', 'spring', 'debug'], cwe: ['CWE-200'], cvss: 7.5 }),
    af('act-legacy-trace', '/trace', 'medium', 'Spring legacy /trace exposed', ['"timestamp"', '"headers"'], 'Disable the legacy /trace actuator.', { cond: 'and', tags: ['exposure', 'spring', 'debug'] }),
    af('act-legacy-beans', '/beans', 'medium', 'Spring legacy /beans exposed', ['"bean"', '"scope"'], 'Disable the legacy /beans actuator.', { cond: 'and', tags: ['exposure', 'spring', 'debug'] }),
    // other frameworks
    // Require the value true: a false reply means the sensitive execution path is off.
    af('act-ignition', '/_ignition/health-check', 'high', 'Laravel Ignition reachable (CVE-2021-3129 surface)', ['"can_execute_commands"\\s*:\\s*true'], 'Upgrade facade/ignition and disable debug mode (APP_DEBUG=false).', { rx: true, tags: ['exposure', 'laravel', 'debug'], cwe: ['CWE-200'], cve: ['CVE-2021-3129'] }),
    af('act-horizon', '/horizon/api/stats', 'medium', 'Laravel Horizon reachable', ['"jobsPerMinute"', 'Horizon'], 'Restrict Laravel Horizon to authorized users.', { cond: 'or', tags: ['exposure', 'laravel'] }),
    af('act-debugbar', '/_debugbar/open', 'medium', 'PHP Debug Bar reachable', ['phpdebugbar', '__meta'], 'Disable PHP Debug Bar in production.', { cond: 'or', tags: ['exposure', 'php', 'debug'] }),
    af('act-wdt', '/_wdt/latest', 'medium', 'Symfony Web Debug Toolbar reachable', ['sf-toolbar', 'Symfony'], 'Disable the Symfony profiler/WDT in production.', { cond: 'or', tags: ['exposure', 'symfony', 'debug'], cwe: ['CWE-489'] }),
    af('act-rails-routes', '/rails/info/routes', 'medium', 'Rails routes info exposed', ['Helper', 'Path / Url'], 'Rails route info should not be reachable in production.', { cond: 'and', tags: ['exposure', 'rails', 'debug'] }),
    af('act-rails-props', '/rails/info/properties', 'medium', 'Rails properties info exposed', ['Ruby version', 'Rails version'], 'Rails property info should not be reachable in production.', { cond: 'and', tags: ['exposure', 'rails', 'debug'] }),
    af('act-werkzeug', '/console', 'high', 'Werkzeug debugger console reachable', ['Werkzeug', 'The console'], 'Never run the Flask/Werkzeug debugger in production.', { cond: 'and', tags: ['exposure', 'flask', 'debug'], cwe: ['CWE-489'] }),
    af('act-sidekiq', '/sidekiq', 'medium', 'Sidekiq dashboard reachable', ['Sidekiq'], 'Protect the Sidekiq dashboard with authentication.', { tags: ['exposure', 'rails', 'panel'] })
  ]
}

// ---- 5) API docs / schemas ----
function genApis(): Template[] {
  return [
    af('api-swagger-v1', '/swagger/v1/swagger.json', 'low', 'Swagger/OpenAPI spec exposed (v1)', ['"swagger"', '"openapi"'], 'Review whether the API spec should be public.', { tags: ['exposure', 'api'], cwe: ['CWE-200'] }),
    af('api-apidocs', '/api-docs', 'low', 'API docs spec exposed', ['"swagger"', '"openapi"'], 'Review whether the API spec should be public.', { tags: ['exposure', 'api'], cwe: ['CWE-200'] }),
    af('api-v2-apidocs', '/v2/api-docs', 'low', 'Springfox v2 API docs exposed', ['"swagger"'], 'Review whether the API spec should be public.', { tags: ['exposure', 'api'] }),
    af('api-v3-apidocs', '/v3/api-docs', 'low', 'springdoc v3 API docs exposed', ['"openapi"'], 'Review whether the API spec should be public.', { tags: ['exposure', 'api'] }),
    af('api-openapi-yaml', '/openapi.yaml', 'low', 'OpenAPI YAML spec exposed', ['openapi:', 'paths:'], 'Review whether the API spec should be public.', { cond: 'and', tags: ['exposure', 'api'] }),
    af('api-graphiql', '/graphiql', 'medium', 'GraphiQL IDE exposed', ['GraphiQL', 'graphiql'], 'Do not expose the GraphiQL IDE in production.', { cond: 'or', tags: ['exposure', 'api', 'graphql'] }),
    af('api-graphql-playground', '/playground', 'medium', 'GraphQL Playground exposed', ['GraphQL Playground'], 'Do not expose GraphQL Playground in production.', { tags: ['exposure', 'api', 'graphql'] }),
    af('api-wadl', '/application.wadl', 'low', 'WADL service description exposed', ['<application', 'wadl'], 'Restrict access to the WADL description.', { cond: 'or', tags: ['exposure', 'api'] }),
    af('api-oidc', '/.well-known/openid-configuration', 'info', 'OpenID Connect discovery document', ['"issuer"', '"authorization_endpoint"'], 'Informational: OIDC discovery is usually intended to be public.', { cond: 'and', tags: ['info', 'api'] }),
    af('api-odata', '/odata', 'low', 'OData endpoint exposed', ['"@odata', 'EntitySets'], 'Restrict OData metadata if not intended to be public.', { cond: 'or', tags: ['exposure', 'api'] })
  ]
}

// ---- 6) product / panel detection (path + product marker → very low FP) ----
const PANELS: Array<[string, string, string, string | string[], RuleSeverity?]> = [
  ['pnl-joomla', '/administrator/', 'Joomla administrator panel', 'Joomla', 'info'],
  ['pnl-drupal-login', '/user/login', 'Drupal login', 'Drupal', 'info'],
  ['pnl-magento', '/admin', 'Magento admin', 'Magento', 'low'],
  ['pnl-opencart', '/admin', 'OpenCart admin', 'OpenCart', 'low'],
  ['pnl-prestashop', '/admin-dev/', 'PrestaShop admin', 'PrestaShop', 'low'],
  ['pnl-phpbb', '/ucp.php', 'phpBB user panel', 'phpBB', 'info'],
  ['pnl-mediawiki', '/index.php/Special:UserLogin', 'MediaWiki login', 'MediaWiki', 'info'],
  ['pnl-moodle', '/login/index.php', 'Moodle login', 'Moodle', 'info'],
  ['pnl-nextcloud', '/login', 'Nextcloud login', 'Nextcloud', 'info'],
  ['pnl-owncloud', '/index.php/login', 'ownCloud login', 'ownCloud', 'info'],
  ['pnl-gitea', '/user/login', 'Gitea login', 'Gitea', 'info'],
  ['pnl-gogs', '/user/login', 'Gogs login', 'Gogs', 'info'],
  ['pnl-sonarqube', '/sessions/new', 'SonarQube login', 'SonarQube', 'info'],
  ['pnl-nexus', '/nexus', 'Sonatype Nexus', ['Nexus Repository', 'Sonatype'], 'info'],
  ['pnl-artifactory', '/artifactory/webapp/', 'JFrog Artifactory', ['Artifactory', 'JFrog'], 'info'],
  ['pnl-harbor', '/harbor/sign-in', 'Harbor registry login', 'Harbor', 'info'],
  ['pnl-rancher', '/dashboard/auth/login', 'Rancher login', 'Rancher', 'info'],
  ['pnl-prometheus', '/graph', 'Prometheus UI', ['Prometheus Time Series', 'Prometheus'], 'low'],
  ['pnl-alertmanager', '/#/alerts', 'Alertmanager UI', 'Alertmanager', 'low'],
  ['pnl-consul', '/ui/', 'Consul UI', 'Consul', 'low'],
  ['pnl-vault', '/ui/vault/auth', 'HashiCorp Vault UI', 'Vault', 'low'],
  ['pnl-traefik', '/dashboard/', 'Traefik dashboard', 'Traefik', 'medium'],
  ['pnl-airflow', '/login/', 'Apache Airflow login', 'Airflow', 'low'],
  ['pnl-superset', '/login/', 'Apache Superset login', 'Superset', 'info'],
  ['pnl-metabase', '/auth/login', 'Metabase login', 'Metabase', 'info'],
  ['pnl-jupyter', '/tree', 'Jupyter Notebook', 'Jupyter', 'medium'],
  ['pnl-zabbix', '/index.php', 'Zabbix login', 'Zabbix', 'info'],
  ['pnl-nagios', '/nagios/', 'Nagios', 'Nagios', 'low'],
  ['pnl-cacti', '/cacti/', 'Cacti login', 'Cacti', 'low'],
  ['pnl-phppgadmin', '/phppgadmin/', 'phpPgAdmin', 'phpPgAdmin', 'low'],
  ['pnl-pgadmin', '/pgadmin4', 'pgAdmin', 'pgAdmin', 'low'],
  ['pnl-plesk', '/login_up.php', 'Plesk panel', 'Plesk', 'low'],
  ['pnl-directadmin', '/CMD_LOGIN', 'DirectAdmin panel', 'DirectAdmin', 'low'],
  ['pnl-cpanel', '/cpanel', 'cPanel', 'cPanel', 'low'],
  ['pnl-roundcube', '/roundcube/', 'Roundcube webmail', 'Roundcube', 'info'],
  ['pnl-squirrelmail', '/squirrelmail/', 'SquirrelMail', 'SquirrelMail', 'info'],
  ['pnl-zimbra', '/zimbra/', 'Zimbra webmail', 'Zimbra', 'info'],
  ['pnl-rainloop', '/?/AdminArea', 'RainLoop admin', 'RainLoop', 'low'],
  ['pnl-teamcity', '/login.html', 'TeamCity login', 'TeamCity', 'info'],
  ['pnl-bamboo', '/userlogin!default.action', 'Bamboo login', 'Bamboo', 'info'],
  ['pnl-confluence', '/login.action', 'Confluence login', ['Confluence', 'Atlassian'], 'info'],
  ['pnl-argocd', '/login', 'Argo CD login', ['Argo CD', 'argocd'], 'low'],
  ['pnl-keycloak', '/auth/', 'Keycloak', 'Keycloak', 'info'],
  ['pnl-graylog', '/', 'Graylog', 'Graylog', 'info'],
  ['pnl-grafana-sub', '/grafana/login', 'Grafana (subpath)', 'Grafana', 'info'],
  ['pnl-wazuh', '/app/wazuh', 'Wazuh dashboard', 'Wazuh', 'low'],
  ['pnl-ghost', '/ghost/', 'Ghost admin', 'Ghost', 'info'],
  ['pnl-strapi', '/admin', 'Strapi admin', 'Strapi', 'low'],
  ['pnl-directus', '/admin/login', 'Directus admin', 'Directus', 'low'],
  ['pnl-mailcow', '/debug', 'mailcow UI', 'mailcow', 'low'],
  ['pnl-cockpit', '/cockpit/', 'Cockpit panel', 'Cockpit', 'low'],
  ['pnl-pfsense', '/', 'pfSense', 'pfSense', 'low'],
  ['pnl-opnsense', '/', 'OPNsense', 'OPNsense', 'low'],
  ['pnl-mikrotik', '/webfig/', 'MikroTik RouterOS', ['RouterOS', 'MikroTik'], 'low'],
  ['pnl-unifi', '/manage/account/login', 'Ubiquiti UniFi', 'UniFi', 'info'],
  ['pnl-synology', '/webman/index.cgi', 'Synology DSM', 'Synology', 'low'],
  ['pnl-weblogic', '/console/login/LoginForm.jsp', 'Oracle WebLogic console', 'WebLogic', 'medium'],
  ['pnl-websphere', '/ibm/console/logon.jsp', 'IBM WebSphere console', 'WebSphere', 'medium'],
  ['pnl-jboss', '/jboss-console/', 'JBoss console', 'JBoss', 'medium'],
  ['pnl-wildfly', '/', 'WildFly welcome', 'WildFly', 'info'],
  ['pnl-coldfusion', '/CFIDE/administrator/', 'Adobe ColdFusion admin', 'ColdFusion', 'medium'],
  ['pnl-tomcat-examples', '/examples/', 'Tomcat sample apps exposed', ['Apache Tomcat Examples', 'Tomcat'], 'medium'],
  ['pnl-tomcat-docs', '/docs/', 'Tomcat docs', 'Apache Tomcat', 'info'],
  ['pnl-struts-showcase', '/struts2-showcase/', 'Struts2 showcase app', 'Struts', 'medium'],
  ['pnl-eureka', '/eureka/apps', 'Netflix Eureka registry', ['applications', 'Eureka'], 'medium'],
  ['pnl-hystrix', '/hystrix', 'Hystrix dashboard', 'Hystrix', 'low'],
  ['pnl-flink', '/#/overview', 'Apache Flink dashboard', 'Flink', 'medium'],
  ['pnl-spark', '/jobs/', 'Apache Spark master UI', 'Spark', 'medium'],
  ['pnl-hadoop', '/dfshealth.html', 'Hadoop NameNode UI', 'Hadoop', 'medium'],
  ['pnl-nifi', '/nifi/', 'Apache NiFi', 'NiFi', 'medium'],
  ['pnl-minio', '/minio/', 'MinIO console', 'MinIO', 'low'],
  ['pnl-fauxton', '/_utils/', 'CouchDB Fauxton', ['Fauxton', 'CouchDB'], 'medium'],
  ['pnl-mongoexpress', '/', 'mongo-express', 'mongo-express', 'medium'],
  ['pnl-redis-commander', '/', 'Redis Commander', 'Redis Commander', 'medium'],
  ['pnl-kafka-ui', '/', 'Kafka UI', 'Kafka UI', 'low'],
  ['pnl-sentry', '/auth/login/', 'Sentry login', 'Sentry', 'info'],
  ['pnl-gitweb', '/gitweb/', 'gitweb', 'gitweb', 'low'],
  ['pnl-cgit', '/cgit/', 'cgit', 'cgit', 'low'],
  ['pnl-splunk', '/en-US/account/login', 'Splunk login', 'Splunk', 'info'],
  ['pnl-kibana-status', '/api/status', 'Kibana status API', ['kibana', 'nickname'], 'low'],
  ['pnl-elastichq', '/', 'ElasticHQ', 'ElasticHQ', 'low'],
  ['pnl-portainer', '/#!/auth', 'Portainer login', 'Portainer', 'low'],
  ['pnl-proxmox', '/', 'Proxmox VE', ['Proxmox', 'pve'], 'low'],
  ['pnl-vcenter', '/ui/', 'VMware vCenter', 'vSphere', 'low'],
  ['pnl-rabbitmq-mgmt', '/', 'RabbitMQ Management', 'RabbitMQ Management', 'medium'],
  ['pnl-kong', '/', 'Kong admin API', ['"plugins"', 'kong'], 'medium'],
  ['pnl-nacos', '/nacos/', 'Alibaba Nacos', 'Nacos', 'medium'],
  ['pnl-apollo', '/', 'Apollo config', 'Apollo', 'low'],
  ['pnl-druid', '/druid/index.html', 'Apache Druid console', 'Druid', 'medium'],
  ['pnl-presto', '/ui/', 'Presto/Trino UI', ['Presto', 'Trino'], 'low'],
  ['pnl-clickhouse', '/play', 'ClickHouse play UI', 'ClickHouse', 'low'],
  ['pnl-grafana-api', '/api/health', 'Grafana health API', ['"database"', '"version"'], 'info']
]
function genPanels(): Template[] {
  return PANELS.map(([id, path, name, marker, sev]) =>
    detect(id, path, name, W('body', Array.isArray(marker) ? marker : [marker], 'or'), { severity: sev || 'info', tags: ['panel', 'tech'] }))
}

// ---- 7) leaked-secret regexes in passive bodies (precise → very low FP) ----
const SECRETS: Array<[string, string, string, string, RuleSeverity]> = [
  ['sec-stripe', 'Stripe live secret key', 'sk_live_[0-9a-zA-Z]{24}', 'Rotate the Stripe key immediately and move it server-side.', 'critical'],
  ['sec-gh-pat', 'GitHub fine-grained token', 'github_pat_[0-9A-Za-z_]{80,}', 'Revoke the GitHub token immediately.', 'high'],
  ['sec-gh-classic', 'GitHub classic token', 'ghp_[0-9A-Za-z]{36}', 'Revoke the GitHub token immediately.', 'high'],
  ['sec-gitlab-pat', 'GitLab personal access token', 'glpat-[0-9A-Za-z_-]{20}', 'Revoke the GitLab token immediately.', 'high'],
  ['sec-slack', 'Slack token', 'xox[baprs]-[0-9A-Za-z-]{10,}', 'Revoke the Slack token immediately.', 'high'],
  ['sec-sendgrid', 'SendGrid API key', 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}', 'Rotate the SendGrid API key.', 'high'],
  ['sec-mailgun', 'Mailgun API key', 'key-[0-9a-f]{32}', 'Rotate the Mailgun API key.', 'high'],
  ['sec-twilio', 'Twilio API key SID', 'SK[0-9a-f]{32}', 'Rotate the Twilio key.', 'high'],
  ['sec-npm', 'npm access token', 'npm_[A-Za-z0-9]{36}', 'Revoke the npm token.', 'high'],
  ['sec-google-oauth', 'Google OAuth access token', 'ya29\\.[0-9A-Za-z_-]{30,}', 'Rotate the Google OAuth credentials.', 'high'],
  ['sec-pgp', 'PGP private key block', '-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Remove the private key and treat it as compromised.', 'critical']
]
function genSecrets(): Template[] {
  return SECRETS.map(([id, name, rx, rem, sev]) => ({
    id, kind: 'http-passive', confidence: 'confirmed',
    info: { name: `${name} leaked in response`, severity: sev, tags: ['http', 'secrets'], remediation: rem, classification: { cwe: ['CWE-312', 'CWE-200'] } },
    matchers: [{ type: 'regex', part: 'body', regex: [rx] }] as Matcher[],
    extractors: [{ name: 'secret', type: 'regex', part: 'body', regex: [rx] }]
  }))
}

// ---- 8) technology fingerprint via headers/cookies (info, exact names → low FP) ----
const TECH_COOKIES: Array<[string, string, string]> = [
  ['hdr-php', 'PHP', 'PHPSESSID'],
  ['hdr-java', 'Java/Servlet', 'JSESSIONID'],
  ['hdr-aspnet', 'ASP.NET', 'ASP.NET_SessionId'],
  ['hdr-laravel', 'Laravel', 'laravel_session'],
  ['hdr-codeigniter', 'CodeIgniter', 'ci_session'],
  ['hdr-express', 'Express/Connect', 'connect.sid'],
  ['hdr-django', 'Django', 'csrftoken'],
  ['hdr-rails', 'Ruby on Rails', '_session_id']
]
function genTechHeaders(): Template[] {
  const cookies: Template[] = TECH_COOKIES.map(([id, tech, cookie]) => ({
    id, kind: 'http-passive', confidence: 'confirmed',
    info: { name: `Technology fingerprint: ${tech} (${cookie})`, severity: 'info', tags: ['http', 'fingerprint'], remediation: 'Informational technology fingerprint; consider renaming default session cookies.', classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'header', regex: [`^set-cookie:\\s*${cookie.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=`] }] as Matcher[]
  }))
  const headers: Template[] = [
    { id: 'hdr-x-generator', kind: 'http-passive', confidence: 'confirmed',
      info: { name: 'Technology disclosure via X-Generator', severity: 'info', tags: ['http', 'fingerprint'], remediation: 'Remove the X-Generator header.', classification: { cwe: ['CWE-200'] } },
      matchers: [{ type: 'word', part: 'header', words: ['x-generator'] }], extractors: [{ name: 'generator', type: 'kval', kval: ['x-generator'] }] },
    { id: 'hdr-x-drupal', kind: 'http-passive', confidence: 'confirmed',
      info: { name: 'Drupal fingerprint via X-Drupal headers', severity: 'info', tags: ['http', 'fingerprint'], remediation: 'Informational Drupal fingerprint.', classification: { cwe: ['CWE-200'] } },
      matchers: [{ type: 'word', part: 'header', words: ['x-drupal-cache', 'x-drupal-dynamic-cache'], condition: 'or' }] },
    { id: 'hdr-x-varnish', kind: 'http-passive', confidence: 'confirmed',
      info: { name: 'Varnish cache fingerprint', severity: 'info', tags: ['http', 'fingerprint'], remediation: 'Informational caching fingerprint.', classification: { cwe: ['CWE-200'] } },
      matchers: [{ type: 'word', part: 'header', words: ['x-varnish', 'via: varnish'], condition: 'or' }] },
    { id: 'hdr-s3', kind: 'http-passive', confidence: 'confirmed',
      info: { name: 'AWS S3 bucket fingerprint', severity: 'info', tags: ['http', 'fingerprint', 'cloud'], remediation: 'Informational — confirms object is served from S3.', classification: { cwe: ['CWE-200'] } },
      matchers: [{ type: 'word', part: 'header', words: ['x-amz-request-id', 'x-amz-id-2'], condition: 'or' }] },
    { id: 'hdr-server-tech', kind: 'http-passive', confidence: 'confirmed',
      info: { name: 'Web server technology fingerprint', severity: 'info', tags: ['http', 'fingerprint'], remediation: 'Informational server fingerprint.', classification: { cwe: ['CWE-200'] } },
      matchers: [{ type: 'regex', part: 'header', regex: ['^server:\\s*(?:LiteSpeed|openresty|Caddy|Kestrel|Microsoft-HTTPAPI|Werkzeug|gunicorn|Jetty|WEBrick|Cowboy|Tengine)'] }], extractors: [{ name: 'server', type: 'kval', kval: ['server'] }] }
  ] as Template[]
  return [...cookies, ...headers]
}

// ---- 9) extra service-version banners (info, extract version → zero FP) ----
function genPortVersions(): Template[] {
  const mk = (id: string, name: string, rx: string, exRx: string): Template => ({
    id, kind: 'port', confidence: 'suspected',
    info: { name, severity: 'info', tags: ['network', 'fingerprint'], remediation: 'Informational banner fingerprint; suppress version strings where possible.', classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'banner', regex: [rx] }],
    extractors: [{ name: 'version', type: 'regex', part: 'banner', regex: [exRx], group: 1 }]
  })
  return [
    mk('bnr-ssh-version', 'SSH service banner', 'SSH-2\\.0-', 'SSH-2\\.0-(\\S+)'),
    mk('bnr-ftp-version', 'FTP service banner', '^220[ -].*(?:FTP|FileZilla|ProFTPD|Pure-FTPd|vsftpd)', '220[ -](.+)'),
    mk('bnr-smtp-version', 'SMTP service banner', '^220[ -].*(?:SMTP|ESMTP|Postfix|Exim|Sendmail)', '220[ -](.+)'),
    mk('bnr-http-server-banner', 'HTTP Server header (from banner)', 'Server:\\s*\\S+', 'Server:\\s*(.+)'),
    mk('bnr-mysql-banner', 'MySQL/MariaDB handshake banner', '(?:mysql_native_password|MariaDB|[0-9]\\.[0-9]+\\.[0-9]+-)', '([0-9]+\\.[0-9]+\\.[0-9]+[^\\s]*)'),
    mk('bnr-redis-banner', 'Redis banner', 'redis_version', 'redis_version:([0-9.]+)')
  ]
}

export const TEMPLATES: Template[] = [
  ...CURATED,
  ...genBackups(),
  ...genEnv(),
  ...genFiles(),
  ...genActuators(),
  ...genApis(),
  ...genPanels(),
  ...genSecrets(),
  ...genTechHeaders(),
  ...genPortVersions(),
  ...MODERN_BACKUP_RULES,
  ...LAB_RULES
]
