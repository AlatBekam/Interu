// Interu Rule Engine — a small, Nuclei-inspired detection engine.
//
// Templates are DATA (see TEMPLATES below): each has info (name/severity/CVE/
// remediation) and a list of matchers (status / word / regex / time / port /
// service) combined with and/or. The engine evaluates templates against signals
// already collected by real modules:
//   - port/banner results from the Network Scanner  (analyzeScan)
//   - captured HTTP responses from the Proxy         (analyzeHttpResponse)
//   - active, scope-gated HTTP probes                (buildActiveRequest + matchActive)
//
// Confidence is honest: directly-observed facts (missing header, cookie flags,
// active-probe hits) are "confirmed"; inferences (service guessed from a port
// number, banner → CVE, error strings) stay "suspected". Framework-free so the
// main process, preload and renderer can all import it.

import type { ScanHost } from './scan'
import type { ProxyLogEntry } from './proxy'
import type { HttpReq, HttpRes } from './http'

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
  type: 'status' | 'word' | 'regex' | 'port' | 'service' | 'time'
  /** which text to search for word/regex matchers. */
  part?: 'header' | 'body' | 'response' | 'banner'
  status?: number[]
  words?: string[]
  regex?: string[]
  ports?: number[]
  services?: string[]
  /** combine this matcher's words/regex list (default 'or'). */
  condition?: 'and' | 'or'
  /** match when the pattern is ABSENT (e.g. a missing security header). */
  negative?: boolean
  /** time matcher: match when response took at least this many ms. */
  geMs?: number
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
  /** http-active only: the probe to send. */
  request?: HttpRequestSpec
  /** port only: restrict which open ports the template is tried against. */
  appliesToPorts?: number[]
  /** http-passive only: only run when the captured URL uses this scheme. */
  scheme?: 'http' | 'https'
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
  cve?: string[]
  cwe?: string[]
  cvss?: number
  tags?: string[]
  mitre?: string[]
  source: 'scanner' | 'proxy' | 'active'
  at: string
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

function evalTemplate(t: Template, p?: PortCtx, h?: HttpCtx): { ok: boolean; evidence: string } {
  const results = t.matchers.map((m) => evalMatcher(m, t.kind, p, h))
  const cond = t.matchersCondition || 'and'
  const ok = cond === 'or' ? results.some((r) => r.ok) : results.every((r) => r.ok)
  if (!ok) return { ok: false, evidence: '' }
  const evidence = results.filter((r) => r.ok && r.evidence).map((r) => r.evidence).join(' · ')
  return { ok: true, evidence }
}

function toFinding(t: Template, target: string, evidence: string, source: Finding['source'], at: string, port?: number): Finding {
  const c = t.info.classification || {}
  return {
    key: `${t.id}|${target}${port != null ? ':' + port : ''}`,
    templateId: t.id,
    name: t.info.name,
    severity: t.info.severity,
    confidence: t.confidence,
    target,
    port,
    evidence: evidence || t.info.name,
    remediation: t.info.remediation,
    cve: c.cve,
    cwe: c.cwe,
    cvss: c.cvss,
    tags: t.info.tags,
    mitre: t.info.mitre,
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
export function analyzeScan(hosts: ScanHost[], at = new Date().toISOString()): Finding[] {
  const out: Finding[] = []
  const tpls = TEMPLATES.filter((t) => t.kind === 'port')
  for (const host of hosts) {
    for (const op of host.openPorts) {
      const ctx: PortCtx = { port: op.port, service: op.service, banner: op.version || '' }
      for (const t of tpls) {
        if (t.appliesToPorts && !t.appliesToPorts.includes(op.port)) continue
        const r = evalTemplate(t, ctx)
        if (r.ok) out.push(toFinding(t, host.ip, r.evidence, 'scanner', at, op.port))
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
    const r = evalTemplate(t, undefined, ctx)
    // Header-only rules describe the whole site: one finding per origin, not per URL.
    const siteWide = t.matchers.every((m) => m.part === 'header')
    if (r.ok) out.push(toFinding(t, siteWide ? origin : entry.url, r.evidence, 'proxy', at))
  }
  return out
}

// --------------------------------------------------- active (oracle) probing

export const activeTemplates = (): Template[] => TEMPLATES.filter((t) => t.kind === 'http-active')

/** Build the real HTTP request for an active template against a base URL. */
export function buildActiveRequest(t: Template, baseUrl: string): HttpReq | null {
  if (!t.request) return null
  let base = baseUrl.trim()
  if (!/^https?:\/\//i.test(base)) base = 'http://' + base
  base = base.replace(/\/+$/, '')
  const path = t.request.path.startsWith('/') ? t.request.path : '/' + t.request.path
  return {
    method: t.request.method || 'GET',
    url: base + path,
    headers: t.request.headers || {},
    timeoutMs: 8000
  }
}

/** Evaluate an active template against the real response it produced. */
export function matchActive(t: Template, url: string, res: HttpRes, at = new Date().toISOString()): Finding | null {
  if (!res || res.ok === false) return null
  const ctx: HttpCtx = {
    status: res.status,
    headerText: res.rawHeaders || '',
    body: res.body || '',
    responseRaw: res.raw || `${res.status ?? ''}\n${res.rawHeaders ?? ''}\n\n${res.body ?? ''}`,
    timeMs: res.timingMs
  }
  const r = evalTemplate(t, undefined, ctx)
  return r.ok ? toFinding(t, url, r.evidence, 'active', at) : null
}

export const SEVERITY_RANK: Record<RuleSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    (a.confidence === b.confidence ? 0 : a.confidence === 'confirmed' ? -1 : 1) ||
    a.target.localeCompare(b.target)
  )
}

// ----------------------------------------------------------------- TEMPLATES

export const TEMPLATES: Template[] = [
  // ---- exposed network services (port) ----
  // Port number only — the service itself is not verified, so these stay suspected.
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
      remediation: 'Do not expose SMB (445) to untrusted networks; restrict with firewall/VPN.',
      classification: { cwe: ['CWE-200'] }, mitre: ['T1021.002'] },
    matchers: [{ type: 'port', ports: [445] }]
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
      remediation: 'Databases (MySQL/PostgreSQL/MSSQL/Oracle) should never be reachable from untrusted networks.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'port', ports: [3306, 5432, 1433, 1521] }]
  },
  {
    id: 'svc-nosql-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'NoSQL/cache exposed (possibly unauthenticated)', severity: 'high', tags: ['network', 'database'],
      remediation: 'Redis/MongoDB/Elasticsearch/Memcached frequently ship without auth. Bind to localhost and enable authentication.',
      classification: { cwe: ['CWE-306'] } },
    matchers: [{ type: 'port', ports: [6379, 27017, 9200, 11211] }]
  },
  {
    id: 'svc-vnc-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'VNC remote desktop exposed', severity: 'high', tags: ['network'],
      remediation: 'Do not expose VNC; tunnel over SSH/VPN and require strong auth.' },
    matchers: [{ type: 'port', ports: [5900, 5901] }]
  },
  {
    id: 'svc-docker-exposed', kind: 'port', confidence: 'suspected',
    info: { name: 'Docker API exposed', severity: 'critical', tags: ['network', 'container'],
      remediation: 'An exposed Docker API (2375) is effectively remote root. Never expose it; require TLS + auth.',
      classification: { cwe: ['CWE-306'], cvss: 9.8 } },
    matchers: [{ type: 'port', ports: [2375, 2376] }]
  },
  // ---- banner → CVE (suspected until verified) ----
  {
    id: 'banner-vsftpd-234', kind: 'port', confidence: 'suspected',
    info: { name: 'vsftpd 2.3.4 backdoor (banner match)', severity: 'critical', tags: ['ftp', 'cve'],
      remediation: 'Upgrade vsftpd immediately; 2.3.4 shipped a malicious backdoor.',
      classification: { cve: ['CVE-2011-2523'], cvss: 10.0 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['vsftpd\\s*2\\.3\\.4'] }]
  },
  {
    id: 'banner-openssh-regresshion', kind: 'port', confidence: 'suspected',
    info: { name: 'OpenSSH regreSSHion candidate (banner match)', severity: 'high', tags: ['ssh', 'cve'],
      remediation: 'Upgrade OpenSSH to ≥ 9.8. Versions 8.5p1–9.7 are affected by CVE-2024-6387.',
      classification: { cve: ['CVE-2024-6387'], cvss: 8.1 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['OpenSSH_(?:8\\.[5-9]|9\\.[0-7])'] }]
  },
  {
    id: 'banner-apache-traversal', kind: 'port', confidence: 'suspected',
    info: { name: 'Apache 2.4.49/2.4.50 path traversal (banner match)', severity: 'critical', tags: ['http', 'cve'],
      remediation: 'Upgrade Apache httpd; 2.4.49/2.4.50 are vulnerable to path traversal/RCE.',
      classification: { cve: ['CVE-2021-41773', 'CVE-2021-42013'], cvss: 9.8 } },
    matchers: [{ type: 'regex', part: 'banner', regex: ['Apache/2\\.4\\.(?:49|50)'] }]
  },

  // ---- HTTP passive (from proxy responses) ----
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
    id: 'http-server-version', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Server version disclosure', severity: 'low', tags: ['http', 'disclosure'],
      remediation: 'Suppress version numbers in the Server header.',
      classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'regex', part: 'header', regex: ['^server:\\s*[^\\n]*\\d+\\.\\d+'] }]
  },
  {
    id: 'http-powered-by', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Technology disclosure via X-Powered-By', severity: 'info', tags: ['http', 'disclosure'],
      remediation: 'Remove the X-Powered-By header.', classification: { cwe: ['CWE-200'] } },
    matchers: [{ type: 'word', part: 'header', words: ['x-powered-by'] }]
  },
  {
    id: 'http-cookie-httponly', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Cookie without HttpOnly flag', severity: 'low', tags: ['http', 'cookie'],
      remediation: 'Set HttpOnly on session cookies to block script access.',
      classification: { cwe: ['CWE-1004'] } },
    // Per cookie line: any Set-Cookie lacking the flag, regardless of the others.
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
    id: 'http-dir-listing', kind: 'http-passive', confidence: 'confirmed',
    info: { name: 'Directory listing enabled', severity: 'medium', tags: ['http', 'disclosure'],
      remediation: 'Disable automatic directory indexing.', classification: { cwe: ['CWE-548'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['Index of /', '<title>Index of'], condition: 'or' }
    ], matchersCondition: 'and'
  },
  {
    id: 'http-sql-error', kind: 'http-passive', confidence: 'suspected',
    info: { name: 'SQL error message in response', severity: 'high', tags: ['http', 'sqli'],
      remediation: 'Verify for SQL injection; suppress database error messages.',
      classification: { cwe: ['CWE-89'] } },
    matchers: [{ type: 'regex', part: 'body', condition: 'or', regex: [
      'SQL syntax.*MySQL', 'Warning.*\\bmysqli?_', 'PostgreSQL.*ERROR', 'ORA-\\d{5}',
      'Microsoft OLE DB Provider for SQL Server', 'Unclosed quotation mark after the character string'
    ] }]
  },
  {
    id: 'http-stacktrace', kind: 'http-passive', confidence: 'suspected',
    info: { name: 'Stack trace / debug output in response', severity: 'medium', tags: ['http', 'disclosure'],
      remediation: 'Disable debug mode in production; return generic error pages.',
      classification: { cwe: ['CWE-209'] } },
    matchers: [{ type: 'regex', part: 'body', condition: 'or', regex: [
      'Traceback \\(most recent call last\\)', 'Exception in thread', '\\bat [\\w.$]+\\([\\w.]+\\.java:\\d+\\)',
      '<b>Fatal error</b>:', '<b>Warning</b>:'
    ] }]
  },

  // ---- HTTP active (scope-gated oracle → confirmed) ----
  {
    id: 'expose-git-config', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/.git/config' },
    info: { name: 'Exposed .git/config', severity: 'high', tags: ['exposure', 'scm'],
      remediation: 'Block access to the .git directory on the web server.',
      classification: { cwe: ['CWE-538'], cvss: 7.5 } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['[core]', 'repositoryformatversion'], condition: 'or' }
    ], matchersCondition: 'and'
  },
  {
    id: 'expose-dotenv', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/.env' },
    info: { name: 'Exposed .env configuration file', severity: 'critical', tags: ['exposure', 'secrets'],
      remediation: 'Never serve .env from the web root; move secrets outside the docroot.',
      classification: { cwe: ['CWE-538'], cvss: 9.1 } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'regex', part: 'body', regex: ['(?:^|\\n)\\s*(?:APP_|DB_|DATABASE_|SECRET|API_KEY|AWS_)[A-Z0-9_]*\\s*='] }
    ], matchersCondition: 'and'
  },
  {
    id: 'expose-phpinfo', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/phpinfo.php' },
    info: { name: 'Exposed phpinfo()', severity: 'medium', tags: ['exposure', 'php'],
      remediation: 'Remove phpinfo pages from production.', classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['phpinfo()', '<title>phpinfo()'], condition: 'or' }
    ], matchersCondition: 'and'
  },
  {
    id: 'expose-backup-sql', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/backup.sql' },
    info: { name: 'Exposed SQL backup', severity: 'high', tags: ['exposure', 'backup'],
      remediation: 'Remove database dumps from the web root.', classification: { cwe: ['CWE-538'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'regex', part: 'body', condition: 'or', regex: ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE'] }
    ], matchersCondition: 'and'
  },
  {
    id: 'expose-apache-status', kind: 'http-active', confidence: 'confirmed',
    request: { method: 'GET', path: '/server-status' },
    info: { name: 'Exposed Apache server-status', severity: 'medium', tags: ['exposure', 'apache'],
      remediation: 'Restrict mod_status to localhost.', classification: { cwe: ['CWE-200'] } },
    matchers: [
      { type: 'status', status: [200] },
      { type: 'word', part: 'body', words: ['Apache Server Status'] }
    ], matchersCondition: 'and'
  }
]
