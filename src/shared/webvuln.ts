// Active web-vulnerability oracles: SQLi, reflected XSS, IDOR, CSRF and broken
// access control. Pure and framework-free so it is fully unit-testable; the
// renderer supplies the real (scope-gated) HTTP sends and feeds responses back.
//
// DESIGN PRINCIPLE — zero false positives:
//   * A finding is only `confirmed` when a DETERMINISTIC oracle proves it:
//       - SQLi: a DB error string that appears ONLY after injecting a quote and
//         is absent from the untouched baseline (and ideally disappears when the
//         quote is balanced).
//       - XSS: a unique custom tag we injected is reflected VERBATIM (unencoded)
//         in an HTML response — encoded reflection (&lt;…&gt;) is NOT flagged.
//   * Anything that cannot be proven automatically (IDOR needs two identities,
//     access/CSRF need human context) is emitted as `suspected` — a labelled
//     candidate to verify, never a hard claim. This keeps the signal honest.

import type { Finding, RuleSeverity, Confidence } from './rules'
import type { CrawlForm } from './crawl'
import { redactSecrets } from './auth'

// --------------------------------------------------------------- SQLi oracle

/** DB error signatures across the common engines (ordered, first match wins). */
const SQL_ERRORS: { db: string; re: RegExp }[] = [
  { db: 'MySQL', re: /SQL syntax.*MySQL/i },
  { db: 'MySQL', re: /check the manual that corresponds to your (MySQL|MariaDB) server version/i },
  { db: 'MySQL', re: /com\.mysql\.jdbc\.exceptions/i },
  { db: 'MySQL', re: /valid MySQL result/i },
  { db: 'MySQL', re: /MySqlException/i },
  { db: 'MariaDB', re: /MariaDB server version for the right syntax/i },
  { db: 'PostgreSQL', re: /PostgreSQL.*ERROR/i },
  { db: 'PostgreSQL', re: /pg_query\(\)/i },
  { db: 'PostgreSQL', re: /PG::(Syntax|Undefined|Grouping)?Error/i },
  { db: 'PostgreSQL', re: /unterminated quoted string at or near/i },
  { db: 'MSSQL', re: /Unclosed quotation mark after the character string/i },
  { db: 'MSSQL', re: /Microsoft SQL (Server|Native Client)/i },
  { db: 'MSSQL', re: /System\.Data\.SqlClient\.SqlException/i },
  { db: 'MSSQL', re: /Incorrect syntax near/i },
  { db: 'MSSQL', re: /OLE DB.*SQL Server/i },
  { db: 'Oracle', re: /\bORA-\d{5}\b/i },
  { db: 'Oracle', re: /quoted string not properly terminated/i },
  { db: 'Oracle', re: /Oracle error/i },
  { db: 'SQLite', re: /SQLite3?::\w*Exception/i },
  { db: 'SQLite', re: /sqlite3\.OperationalError/i },
  { db: 'SQLite', re: /\bSQLITE_ERROR\s*:/i },
  { db: 'SQLite', re: /unrecognized token:/i },
  { db: 'SQLite', re: /SQLite\/JDBCDriver/i },
  { db: 'Generic', re: /java\.sql\.SQL(Syntax(Error)?)?Exception/i },
  { db: 'Generic', re: /\[ODBC .*Driver\]/i },
  { db: 'Generic', re: /SQLSTATE\[\w+\]/i }
]

/** Return the DB whose error signature is present in `text`, or null. */
export function detectSqlError(text: string): string | null {
  if (!text) return null
  for (const { db, re } of SQL_ERRORS) if (re.test(text)) return db
  return null
}

export interface SqliVerdict {
  confirmed: boolean
  db: string
  balancedClears: boolean
}

/**
 * Error-based SQLi oracle. `quoteBody` is the response to value+`'`,
 * `balancedBody` (optional) to value+`''`. Confirmed only when a DB error is
 * attributable to our injection: present after the single quote, ABSENT from the
 * untouched baseline. If balancing the quote clears the error, that is stronger
 * still. An error already in the baseline is NOT attributable → no finding.
 */
export function sqliErrorVerdict(baselineBody: string, quoteBody: string, balancedBody?: string): SqliVerdict | null {
  const err = detectSqlError(quoteBody)
  if (!err) return null
  if (detectSqlError(baselineBody)) return null // error pre-exists → not attributable
  const balancedClears = balancedBody != null ? detectSqlError(balancedBody) == null : false
  return { confirmed: balancedClears, db: err, balancedClears }
}

// ---------------------------------------------------------------- XSS oracle

/** The unique, inert custom tag we inject; its verbatim reflection is the proof. */
export function xssTag(token: string): string {
  return `<x-interu-${token}>`
}
/** A payload that breaks out of common HTML/attribute contexts then opens our tag. */
export function xssPayload(token: string): string {
  return `'"></title></textarea></script><x-interu-${token}>`
}
/** HTML-entity-encoded form of the tag (what a SAFE app would emit instead). */
export function xssEncoded(token: string): string {
  return `&lt;x-interu-${token}&gt;`
}

export interface XssVerdict {
  confirmed: boolean
  encodedInstead: boolean
  reflected?: boolean
}

/**
 * Reflected-XSS oracle. Confirmed only when our custom tag appears VERBATIM in
 * an HTML response (proving `<`/`>` were not encoded). If only the encoded form
 * is present, the app sanitised it — explicitly NOT a finding.
 */
export function xssReflectVerdict(body: string, token: string, contentType: string | undefined): XssVerdict | null {
  if (!body) return null
  const isHtml = !contentType || /html/i.test(contentType)
  const raw = body.includes(xssTag(token))
  const enc = body.includes(xssEncoded(token))
  // Reflection proves unencoded input, not executable JavaScript. Keep it a
  // candidate until an operator verifies the actual browser context.
  if (raw && isHtml) return { confirmed: false, encodedInstead: false, reflected: true }
  if (enc) return { confirmed: false, encodedInstead: true } // safe — reported as negative
  return null
}

// --------------------------------------------------------------- IDOR oracle

const ID_NAME = /(^|[_-])(id|uid|user(id|_id)?|account|acct|order|invoice|doc|docid|file|fileid|num|no|pid|oid|key)$/i

/** Is the parameter name an object identifier? A numeric search term is not. */
export function isIdLike(name: string, value: string): boolean {
  void value
  return ID_NAME.test(name) || /Id$/.test(name)
}

const PRIVATE_OBJECT_PATH = /\/(?:users?|accounts?|profiles?|orders?|invoices?|records?|documents?|files?|private|settings|admin)(?:\/|$)/i

/** A single unauthenticated 200 on a public product/blog is not an IDOR signal. */
export function idorProbeEligible(url: string, name: string, value: string): boolean {
  if (!isIdLike(name, value) || idNeighbors(value).length === 0) return false
  try { return PRIVATE_OBJECT_PATH.test(new URL(url).pathname) } catch { return false }
}

/** Neighbour values to probe for an id (numeric ±1; nothing for non-numeric). */
export function idNeighbors(value: string): string[] {
  if (!/^\d{1,12}$/.test(value)) return []
  const n = parseInt(value, 10)
  const out: string[] = []
  if (n - 1 >= 0) out.push(String(n - 1))
  out.push(String(n + 1))
  return out
}

/** Pages that indicate auth is being enforced (so a neighbour hit is NOT IDOR). */
const AUTH_WALL = /(please\s+log\s*in|sign\s*in|login\s+required|unauthori[sz]ed|access\s+denied|forbidden|session\s+expired|not\s+authori[sz]ed)/i

export interface IdorVerdict {
  suspected: boolean
  reason: string
}

/**
 * IDOR candidate oracle — SUSPECTED only (true IDOR needs two identities, which
 * automation lacks). Flags when changing an id to a neighbour still returns a
 * distinct, non-trivial 200 that is not an auth wall and differs materially from
 * the original object — i.e. the object is served with no access control in the
 * request we made. Clearly labelled for manual confirmation.
 */
export function idorVerdict(
  orig: { status?: number; body: string },
  neighbor: { status?: number; body: string }
): IdorVerdict | null {
  if (orig.status !== 200 || neighbor.status !== 200) return null
  const nb = neighbor.body || ''
  if (nb.length < 64) return null // too small to be a real object
  if (AUTH_WALL.test(nb)) return null // auth is enforced → not IDOR
  const ob = orig.body || ''
  if (nb === ob) return null // identical → likely a static/templated page, not per-id data
  // Material difference in size OR content guards against a generic error page.
  const diff = Math.abs(nb.length - ob.length)
  const ratio = ob.length ? diff / ob.length : 1
  if (diff < 32 && ratio < 0.05) return null
  return { suspected: true, reason: `neighbour id → distinct 200 (len ${ob.length}→${nb.length}), no auth wall` }
}

// --------------------------------------------------- access control & CSRF

const SENSITIVE_PATH = /\/(admin|administrator|dashboard|account|settings|manage|management|console|internal|private|users?|config|backup)(\/|$|\?)/i
const LOGINISH = /(type=["']password["']|name=["']password["']|>\s*log\s*in\s*<|>\s*sign\s*in\s*<)/i

/** SUSPECTED broken-access-control: a sensitive-looking path served 200 and the
 *  body is NOT a login page. Suspected because the name heuristic can misfire on
 *  intentionally public pages. */
export function accessVerdict(url: string, status: number | undefined, body: string): { suspected: boolean } | null {
  if (status !== 200) return null
  if (/^\s*(?:\{\s*\}|null|\{\s*"(?:user|account|profile)"\s*:\s*\{\s*\}\s*\})\s*$/i.test(body || '')) return null
  let path = url
  try { const u = new URL(url); path = u.pathname + u.search } catch { /* keep */ }
  if (!SENSITIVE_PATH.test(path)) return null
  if (LOGINISH.test(body || '')) return null // it IS gated by a login form
  return { suspected: true }
}

const STATE_CHANGING = /(login|logon|transfer|payment|delete|remove|update|change|password|passwd|admin|account|register|signup|create|add|edit|checkout)/i
const CSRF_FIELD = /(csrf|xsrf|_token|authenticity_token|requestverificationtoken|nonce|anti.?forgery)/i

/** SUSPECTED missing anti-CSRF token on a state-changing POST form (pure). */
export function csrfMissing(form: CrawlForm): boolean {
  if (form.method.toUpperCase() !== 'POST') return false
  if (!STATE_CHANGING.test(form.action) && !form.inputs.some((i) => STATE_CHANGING.test(i.name))) return false
  return !form.inputs.some((i) => CSRF_FIELD.test(i.name))
}

// ------------------------------------------------------- test-plan builders

export type ProbeKind = 'sqli-quote' | 'sqli-balanced' | 'xss' | 'lfi' | 'ssti' | 'rce' | 'ssrf' | 'xxe'

export interface ParamProbe {
  kind: ProbeKind
  url: string
  token?: string
}
export interface ParamPlan {
  param: string
  origValue: string
  baselineUrl: string
  probes: ParamProbe[]
}

function setParam(url: string, name: string, value: string): string {
  const u = new URL(url)
  u.searchParams.set(name, value)
  return u.toString()
}

let tokenSeq = 0
/** Short unique token for one XSS probe (deterministic counter + radix36). */
export function nextToken(): string {
  tokenSeq = (tokenSeq + 1) % 1e9
  return (Date.now().toString(36) + tokenSeq.toString(36)).slice(-10)
}

/**
 * Build the baseline + injection probes for every query parameter of `url`.
 * Returns [] when the URL has no query parameters.
 */
export function planQueryParams(url: string, mkToken: () => string = nextToken): ParamPlan[] {
  let params: [string, string][]
  try {
    params = [...new URL(url).searchParams.entries()]
  } catch {
    return []
  }
  const seen = new Set<string>()
  const plans: ParamPlan[] = []
  for (const [name, value] of params) {
    if (seen.has(name)) continue
    seen.add(name)
    const token = mkToken()
    plans.push({
      param: name,
      origValue: value,
      baselineUrl: setParam(url, name, value || '1'),
      probes: [
        { kind: 'sqli-quote', url: setParam(url, name, (value || '1') + "'") },
        { kind: 'sqli-balanced', url: setParam(url, name, (value || '1') + "''") },
        { kind: 'xss', url: setParam(url, name, xssPayload(token)), token },
        { kind: 'ssti', url: setParam(url, name, `{{${700000 + Number(tokenSeq % 100000)}*13}}`), token: String((700000 + Number(tokenSeq % 100000)) * 13) },
        { kind: 'rce', url: setParam(url, name, `;printf interu_${token};`), token: `interu_${token}` },
        ...(/(?:file|path|page|template|view|download|include|document|filename)/i.test(name)
          ? [{ kind: 'lfi' as const, url: setParam(url, name, '../../../../../../etc/passwd') }] : []),
        ...(/(?:url|uri|target|endpoint|callback|webhook|feed|link|proxy|source)/i.test(name)
          ? [{ kind: 'ssrf' as const, url: setParam(url, name, 'http://127.0.0.1:1/interu-ssrf-' + token), token }] : []),
        ...(/(?:xml|document|data|payload|content)/i.test(name)
          ? [{ kind: 'xxe' as const, url: setParam(url, name, `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`), token }] : [])
      ]
    })
  }
  return plans
}

/** A body must contain the distinctive file signature absent from the control. */
export function fileDisclosureVerdict(control: string, probe: string): boolean {
  return !/(?:^|\n)root:[^\r\n]*:0:0:/m.test(control) && /(?:^|\n)root:[^\r\n]*:0:0:/m.test(probe)
}

/** Arithmetic output is only a candidate: a parser or unrelated page may emit it. */
export function expressionVerdict(control: string, probe: string, expected: string, payload: string): boolean {
  return expected.length >= 6 && !control.includes(expected) && probe.includes(expected) && !probe.includes(payload)
}

export function commandOutputVerdict(control: string, probe: string, marker: string, payload: string): boolean {
  return !control.includes(marker) && probe.includes(marker) && !probe.includes(payload)
}

/** Transport errors after a loopback URL indicate an SSRF candidate, not proof. */
export function ssrfErrorVerdict(control: string, probe: string): boolean {
  return !/(?:ECONNREFUSED|connection refused|failed to connect|connect\(\) failed)/i.test(control) &&
    /(?:ECONNREFUSED|connection refused|failed to connect|connect\(\) failed)/i.test(probe)
}

export function differentialFinding(kind: 'lfi'|'xxe'|'ssti'|'rce'|'ssrf', url: string, param: string, request: string, response: string): Finding {
  const data = {
    lfi: ['Local file disclosure through path parameter', 'high', 'confirmed', 'CWE-22', 'A local passwd-file signature appeared only after the path probe.'],
    xxe: ['External entity file disclosure', 'high', 'confirmed', 'CWE-611', 'A local passwd-file signature appeared only after the XML entity probe.'],
    ssti: ['Template expression evaluation candidate', 'high', 'suspected', 'CWE-1336', 'The response contained the arithmetic result absent from the baseline; verify template context.'],
    rce: ['Command output candidate', 'high', 'suspected', 'CWE-78', 'An inert printf marker appeared without the injected command text; verify execution context.'],
    ssrf: ['Server-side fetch candidate', 'medium', 'suspected', 'CWE-918', 'A loopback connection error appeared only after the URL probe; verify with an approved callback endpoint.']
  } as const
  const [name, severity, confidence, cwe, evidence] = data[kind]
  return base(`webvuln-${kind}`, name, severity, confidence, origin(url), `webvuln:${kind}:${origin(url)}${pathOf(url)}:${param}`, {
    evidence: `Parameter "${param}": ${evidence}`, matchedAt: url, request, response,
    description: evidence, remediation: kind === 'lfi' || kind === 'xxe' ? 'Reject unsafe file/entity resolution and enforce an allowlist.' : 'Treat untrusted input as data and restrict server-side evaluation or fetch destinations.',
    cwe: [cwe], tags: [kind, 'active', 'differential']
  })
}

// ------------------------------------------------------------- findings

const CLIP = 4096
const clip = (s: string): string => (s.length > CLIP ? s.slice(0, CLIP) + '…' : s)

interface FindingExtra {
  evidence: string
  matchedAt: string
  request?: string
  response?: string
}

function base(
  templateId: string,
  name: string,
  severity: RuleSeverity,
  confidence: Confidence,
  target: string,
  key: string,
  extra: FindingExtra & Partial<Finding>
): Finding {
  return {
    key,
    templateId,
    name,
    severity,
    confidence,
    target,
    source: 'active',
    at: new Date().toISOString(),
    evidence: redactSecrets(extra.evidence),
    matchedAt: extra.matchedAt,
    request: extra.request ? clip(redactSecrets(extra.request)) : undefined,
    response: extra.response ? clip(redactSecrets(extra.response)) : undefined,
    description: extra.description,
    remediation: extra.remediation,
    cwe: extra.cwe,
    reference: extra.reference,
    tags: extra.tags
  }
}

function origin(url: string): string {
  try { return new URL(url).origin } catch { return url }
}
function pathOf(url: string): string {
  try { const u = new URL(url); return u.pathname } catch { return url }
}

export function sqliFinding(url: string, param: string, v: SqliVerdict, req?: string, res?: string): Finding {
  return base('webvuln-sqli-error', `SQL Injection (error-based, ${v.db})`, v.confirmed ? 'critical' : 'high', v.confirmed ? 'confirmed' : 'suspected', origin(url),
    `webvuln:sqli:${origin(url)}${pathOf(url)}:${param}`, {
      evidence: `Parameter "${param}" injected with a single quote produced a ${v.db} SQL error absent from the baseline${v.balancedClears ? '; balancing the quote cleared it (confirmed)' : ''}.`,
      matchedAt: url,
      request: req,
      response: res,
      description: 'User input reaches a SQL query without proper parameterisation, allowing the query to be altered.',
      remediation: 'Use parameterised queries / prepared statements; never concatenate input into SQL.',
      cwe: ['CWE-89'],
      reference: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      tags: ['sqli', 'injection', 'active']
    })
}

export function xssFinding(url: string, param: string, token: string, req?: string, res?: string): Finding {
  return base('webvuln-xss-reflected', 'Unencoded reflection (XSS candidate)', 'high', 'suspected', origin(url),
    `webvuln:xss:${origin(url)}${pathOf(url)}:${param}`, {
      evidence: `Parameter "${param}" reflected the injected tag ${xssTag(token)} verbatim (unencoded) in an HTML response.`,
      matchedAt: url,
      request: req,
      response: res,
      description: 'Input is reflected without encoding. Verify HTML context and script execution manually; reflection alone does not prove XSS.',
      remediation: 'Context-aware output encoding; a strict Content-Security-Policy as defence in depth.',
      cwe: ['CWE-79'],
      reference: ['https://owasp.org/www-community/attacks/xss/'],
      tags: ['xss', 'injection', 'active']
    })
}

export function idorFinding(url: string, param: string, from: string, to: string, reason: string): Finding {
  return base('webvuln-idor-candidate', 'IDOR candidate (broken object-level access)', 'medium', 'suspected', origin(url),
    `webvuln:idor:${origin(url)}${pathOf(url)}:${param}`, {
      evidence: `Changing "${param}" ${from}→${to} still returned another object: ${reason}. Verify manually with a second identity (needs two accounts to confirm).`,
      matchedAt: url,
      description: 'An object identifier can be tampered to access other records; confirm whether it crosses a privilege/ownership boundary.',
      remediation: 'Enforce per-request authorization that the object belongs to the caller.',
      cwe: ['CWE-639'],
      reference: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
      tags: ['idor', 'access-control', 'active', 'candidate']
    })
}

export function accessFinding(url: string): Finding {
  return base('webvuln-access-sensitive', 'Sensitive area reachable without authentication', 'medium', 'suspected', origin(url),
    `webvuln:access:${origin(url)}${pathOf(url)}`, {
      evidence: `A sensitive path (${pathOf(url)}) returned 200 and is not a login page. Verify it should require authentication.`,
      matchedAt: url,
      description: 'A path whose name implies privileged/administrative function is served without a login gate.',
      remediation: 'Require authentication and authorization on privileged routes; deny by default.',
      cwe: ['CWE-284'],
      reference: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
      tags: ['access-control', 'auth', 'active', 'candidate']
    })
}

export function csrfFinding(pageUrl: string, action: string): Finding {
  return base('webvuln-csrf-missing', 'State-changing form without anti-CSRF token', 'medium', 'suspected', origin(pageUrl),
    `webvuln:csrf:${origin(pageUrl)}:${action}`, {
      evidence: `A POST form (action ${action}) performs a state-changing action but carries no anti-CSRF token field.`,
      matchedAt: pageUrl,
      description: 'Without an unpredictable per-request token, an attacker page can submit this form on the victim’s behalf.',
      remediation: 'Add a synchroniser CSRF token (or SameSite=strict cookies + origin checks) to state-changing requests.',
      cwe: ['CWE-352'],
      reference: ['https://owasp.org/www-community/attacks/csrf'],
      tags: ['csrf', 'active', 'candidate']
    })
}
