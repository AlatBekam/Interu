// Pure, framework-free crawl logic for the Web Crawler automation module.
// All network I/O lives in the renderer page; everything here is deterministic
// and unit-testable: URL extraction/normalisation, form parsing, and a BFS
// frontier controller that enforces scope, depth and page budgets. The actual
// fetch is injected by the caller, which also keeps the authorization scope
// gate (in the main process) as the single source of truth for what is allowed.

import { hostInScope } from './http'
import { isUnsafeAuthedPath } from './auth'

export interface CrawlOptions {
  /** How many link-hops from a seed to follow (seed = depth 0). */
  maxDepth: number
  /** Hard cap on pages fetched, so a big site can't run forever. */
  maxPages: number
  /** Only follow links on the same host(s) as the seed(s). */
  sameHostOnly: boolean
  /** When sameHostOnly, also allow subdomains of a seed host. */
  includeSubdomains: boolean
}

export const DEFAULT_CRAWL_OPTIONS: CrawlOptions = {
  maxDepth: 2,
  maxPages: 150,
  sameHostOnly: true,
  includeSubdomains: true
}

export interface CrawlFormInput {
  name: string
  type: string
}
export interface CrawlForm {
  method: string
  action: string
  inputs: CrawlFormInput[]
}

export interface CrawlNode {
  url: string
  depth: number
  status?: number | string
  /** short content-type label: html, json, js, css, xml, text, bin … */
  type?: string
  length?: number
  ms?: number
  title?: string
  /** query-string parameter names seen on this URL. */
  params: string[]
  forms: CrawlForm[]
  /** number of in-scope links discovered on this page. */
  links: number
  error?: string
}

/** File extensions we never fetch while crawling (assets / binaries / media). */
const SKIP_EXT =
  /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|css|woff2?|ttf|eot|otf|mp[34]|m4[av]|ogg|wav|flac|webm|mov|avi|mkv|pdf|zip|t?gz|rar|7z|bz2|xz|tar|iso|dmg|exe|msi|apk|dll|bin|wasm|map)(\?|#|$)/i

/** Resolve `href` against `base`, drop fragments, and reject non-crawlable schemes. */
export function normalizeUrl(href: string, base: string): string | null {
  if (!href) return null
  const raw = href.trim()
  if (!raw || raw.startsWith('#')) return null
  if (/^(mailto:|tel:|javascript:|data:|blob:|about:|ftp:|sms:|file:)/i.test(raw)) return null
  let u: URL
  try {
    u = new URL(raw, base)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  u.hash = ''
  // Collapse an empty path to "/" so "http://h" and "http://h/" dedupe together.
  if (!u.pathname) u.pathname = '/'
  return u.toString()
}

/** Query-string parameter names on a URL, in order, de-duplicated. */
export function queryParams(url: string): string[] {
  try {
    const sp = new URL(url).searchParams
    const seen = new Set<string>()
    for (const k of sp.keys()) seen.add(k)
    return [...seen]
  } catch {
    return []
  }
}

/** Should this URL be fetched by the crawler (vs. recorded as a static asset)? */
export function isFetchable(url: string): boolean {
  return !SKIP_EXT.test(url)
}

function crawlPriority(url: string): number {
  const u = new URL(url)
  const path = u.pathname.toLowerCase()
  return (/(?:^|\/)(?:search|query)(?:\/|\.|$)/.test(path) ? 8 : 0) +
    (u.search ? 4 : 0) +
    (/\/(?:api|rest)\//.test(path) ? 2 : 0) -
    (/\.js$/.test(path) ? 1 : 0)
}

const HTML_TAG = /<(?:a|area|link|script|img|iframe|form|source|video|audio|object)\b[^>]{0,4096}>/gi
const ATTR_URL = /(?:href|src|action|data-href|data-url)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/gi
// Bare URLs inside inline scripts / JSON (e.g. fetch("/api/x")) — a lightweight
// endpoint sniffer that catches API paths that never appear as an <a href>.
const INLINE_URL = /(["'`])(\/[A-Za-z0-9][A-Za-z0-9._~/%?&=+:-]{0,199})\1/g
const TEMPLATE_API_URL = /\$\{[^}]{1,80}\}(\/(?:api|rest)\/[A-Za-z0-9][A-Za-z0-9._~/%?&=+:-]{0,199})/gi

/** Read only GET routes from an OpenAPI document; request bodies and mutations are ignored. */
export function extractOpenApiGetUrls(body: string, base: string): string[] {
  if (body.length > 2_000_000) return []
  const out = new Set<string>()
  const add = (path: string, names: string[]): void => {
    if (!path.startsWith('/') || path.startsWith('//') || out.size >= 100) return
    const url = normalizeUrl(path.replace(/\{[^{}]{1,60}\}/g, '1'), base)
    if (!url) return
    const u = new URL(url)
    for (const name of names.slice(0, 5)) if (/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(name)) u.searchParams.set(name, '1')
    out.add(u.href)
  }
  if (body.trimStart().startsWith('{')) {
    try {
      const spec = JSON.parse(body) as { openapi?: unknown; swagger?: unknown; paths?: Record<string, {
        get?: { parameters?: { name?: string; in?: string }[] }; parameters?: { name?: string; in?: string }[]
      }> }
      if (spec.openapi || spec.swagger) for (const [path, item] of Object.entries(spec.paths || {})) {
        if (!item?.get) continue
        const names = [...(item.parameters || []), ...(item.get.parameters || [])]
          .filter(param => param?.in === 'query').map(param => param.name || '')
        add(path, names)
      }
    } catch { /* invalid JSON is not an API spec */ }
    return [...out]
  }
  if (!/^(?:openapi|swagger):\s*\S/m.test(body)) return []
  let path = ''
  let method = ''
  let hasGet = false
  let inParams = false
  let paramIn = ''
  let paramName = ''
  let names: string[] = []
  const flushParam = (): void => { if (paramIn === 'query' && paramName) names.push(paramName); paramIn = ''; paramName = '' }
  const flushPath = (): void => { flushParam(); if (hasGet) add(path, names); names = []; hasGet = false }
  for (const line of body.split(/\r?\n/)) {
    const nextPath = /^  (\/[^:\r\n]*):\s*$/.exec(line)
    if (nextPath) { flushPath(); path = nextPath[1]; method = ''; inParams = false; continue }
    if (!path) continue
    const nextMethod = /^    (get|post|put|patch|delete|options|head):\s*$/i.exec(line)
    if (nextMethod) { flushParam(); method = nextMethod[1].toLowerCase(); hasGet ||= method === 'get'; inParams = false; continue }
    if (method !== 'get') continue
    if (/^      parameters:\s*$/.test(line)) { inParams = true; continue }
    if (/^      [A-Za-z][A-Za-z0-9_-]*:\s*/.test(line)) { flushParam(); inParams = false }
    if (!inParams) continue
    const nextParam = /^      -\s*(.*)$/.exec(line)
    if (nextParam) { flushParam(); const field = /^(in|name):\s*(\S+)/.exec(nextParam[1]); if (field?.[1] === 'in') paramIn = field[2]; if (field?.[1] === 'name') paramName = field[2]; continue }
    const field = /^        (in|name):\s*(\S+)/.exec(line)
    if (field?.[1] === 'in') paramIn = field[2]
    if (field?.[1] === 'name') paramName = field[2]
  }
  flushPath()
  return [...out]
}

/** Extract candidate links from an HTML (or JS/JSON) document, normalised & deduped. */
export function extractLinks(html: string, base: string, type: string = 'html'): string[] {
  if (!html) return []
  const out = new Set<string>()
  let m: RegExpExecArray | null
  if (type === 'html' || type === 'xml') {
    HTML_TAG.lastIndex = 0
    while ((m = HTML_TAG.exec(html))) {
      ATTR_URL.lastIndex = 0
      let attrMatch: RegExpExecArray | null
      while ((attrMatch = ATTR_URL.exec(m[0]))) {
        const n = normalizeUrl(attrMatch[2] ?? attrMatch[3] ?? attrMatch[4] ?? '', base)
        if (n) out.add(n)
      }
    }
  }
  if (type === 'html' || type === 'js' || type === 'json') {
    INLINE_URL.lastIndex = 0
    while ((m = INLINE_URL.exec(html))) {
      const before = html.slice(Math.max(0, m.index - 16), m.index)
      if (/(?:href|src|action|data-href|data-url)\s*=\s*$/i.test(before)) continue
      const n = normalizeUrl(m[2], base)
      if (n) out.add(n)
    }
    TEMPLATE_API_URL.lastIndex = 0
    while ((m = TEMPLATE_API_URL.exec(html))) {
      const n = normalizeUrl(m[1], base)
      if (n) out.add(n)
    }
  }
  if (type === 'json' || type === 'yaml') for (const url of extractOpenApiGetUrls(html, base)) out.add(url)
  return [...out]
}

const FORM_TAG = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi
const INPUT_TAG = /<(input|select|textarea)\b([^>]*)>/gi

function attr(tag: string, name: string): string {
  const m = tag.match(new RegExp(name + '\\s*=\\s*("([^"]*)"|\'([^\']*)\'|([^\\s"\'>]+))', 'i'))
  return (m && (m[2] ?? m[3] ?? m[4])) || ''
}

/** Parse <form> elements, resolving the action URL and listing named inputs. */
export function extractForms(html: string, base: string): CrawlForm[] {
  if (!html) return []
  const forms: CrawlForm[] = []
  let fm: RegExpExecArray | null
  FORM_TAG.lastIndex = 0
  while ((fm = FORM_TAG.exec(html))) {
    const head = fm[1] || ''
    const inner = fm[2] || ''
    const method = (attr('<f ' + head + '>', 'method') || 'GET').toUpperCase()
    const actionRaw = attr('<f ' + head + '>', 'action')
    const action = normalizeUrl(actionRaw, base) || base
    const inputs: CrawlFormInput[] = []
    let im: RegExpExecArray | null
    INPUT_TAG.lastIndex = 0
    while ((im = INPUT_TAG.exec(inner))) {
      const itag = '<i ' + (im[2] || '') + '>'
      const name = attr(itag, 'name')
      if (!name) continue
      const type = im[1].toLowerCase() === 'input' ? attr(itag, 'type') || 'text' : im[1].toLowerCase()
      inputs.push({ name, type })
    }
    forms.push({ method, action, inputs })
  }
  return forms
}

/** The <title> of an HTML document, trimmed and collapsed. */
export function pageTitle(html: string): string | undefined {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  if (!m) return undefined
  const t = m[1].replace(/\s+/g, ' ').trim()
  return t ? t.slice(0, 200) : undefined
}

/** Short content-type label from a Content-Type header value. */
export function contentTypeLabel(ct: string | undefined): string {
  if (!ct) return 'text'
  const t = ct.toLowerCase()
  if (t.includes('html')) return 'html'
  if (t.includes('json')) return 'json'
  if (t.includes('javascript') || t.includes('ecmascript')) return 'js'
  if (t.includes('yaml') || t.includes('yml')) return 'yaml'
  if (t.includes('css')) return 'css'
  if (t.includes('xml')) return 'xml'
  if (t.startsWith('image/')) return 'image'
  if (t.startsWith('text/')) return 'text'
  return t.split(';')[0].split('/').pop() || 'bin'
}

function hostOfUrl(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return ''
  }
}

/** Dedup key: a URL without its fragment (query kept — ?id=1 vs ?id=2 differ). */
export function dedupeKey(url: string): string {
  return normalizeUrl(url, url) || url
}

/**
 * BFS frontier controller. Holds the queue, the visited set and the recorded
 * nodes; enforces scope, same-host/subdomain policy, depth and the page budget.
 * No network calls — the caller fetches each URL `take()` returns and feeds the
 * parsed result back via `record()`.
 */
export class CrawlController {
  readonly opts: CrawlOptions
  readonly scope: string[]
  readonly rootHosts: string[]
  private queue: { url: string; depth: number }[] = []
  private seen = new Set<string>()
  private shapeCounts = new Map<string, number>()
  private started = 0
  private _nodes: CrawlNode[] = []

  constructor(seeds: string[], opts: CrawlOptions, scope: string[]) {
    this.opts = opts
    this.scope = scope
    this.rootHosts = [...new Set(seeds.map(hostOfUrl).filter(Boolean))]
    for (const s of seeds) {
      const n = normalizeUrl(s, s)
      if (n) this.enqueue(n, 0)
    }
  }

  get nodes(): CrawlNode[] {
    return this._nodes
  }
  get pending(): number {
    return this.queue.length
  }
  /** Pages recorded so far. */
  get done(): number {
    return this._nodes.length
  }
  /** Fetches handed out (recorded + in-flight) — used for the page budget. */
  get takenCount(): number {
    return this.started
  }

  /** True when the host passes scope AND the same-host/subdomain policy. */
  allowedHost(url: string): boolean {
    if (!hostInScope(url, this.scope)) return false
    if (!this.opts.sameHostOnly) return true
    const h = hostOfUrl(url)
    return this.rootHosts.some((r) => h === r || (this.opts.includeSubdomains && h.endsWith('.' + r)))
  }

  /** Try to add a URL to the frontier. Returns true if it was newly enqueued. */
  enqueue(url: string, depth: number): boolean {
    if (depth > this.opts.maxDepth) return false
    const key = dedupeKey(url)
    if (this.seen.has(key)) return false
    if (!isFetchable(url)) return false
    if (isUnsafeAuthedPath(url)) return false
    if (!this.allowedHost(url)) return false
    const u = new URL(url)
    if (u.search) {
      const shape = `${u.origin}${u.pathname}?${[...new Set(u.searchParams.keys())].sort().join(',')}`
      const count = this.shapeCounts.get(shape) || 0
      if (count >= 4) return false
      this.shapeCounts.set(shape, count + 1)
    }
    this.seen.add(key)
    this.queue.push({ url, depth })
    return true
  }

  /** Next URL to fetch, or null when the queue is empty or the budget is spent. */
  take(): { url: string; depth: number } | null {
    if (this.started >= this.opts.maxPages) return null
    if (this.queue.length === 0) return null
    const depth = this.queue[0].depth
    let best = 0
    for (let i = 1; i < this.queue.length && this.queue[i].depth === depth; i++) {
      if (crawlPriority(this.queue[i].url) > crawlPriority(this.queue[best].url)) best = i
    }
    const next = this.queue.splice(best, 1)[0]
    if (!next) return null
    this.started++
    return next
  }

  /**
   * Record a fetched page and enqueue its eligible out-links. `html` is used for
   * link/form extraction (pass '' for non-HTML). Returns the stored node.
   */
  record(
    item: { url: string; depth: number },
    res: {
      status?: number | string
      type?: string
      length?: number
      ms?: number
      title?: string
      html?: string
      error?: string
    }
  ): CrawlNode {
    const html = res.html || ''
    const extractType = res.type === 'text' && /\.ya?ml(?:\?|$)/i.test(item.url) ? 'yaml' : res.type || 'html'
    const forms = html && extractType === 'html' ? extractForms(html, item.url) : []
    let links = 0
    if (html && item.depth < this.opts.maxDepth) {
      for (const l of extractLinks(html, item.url, extractType)) {
        if (this.enqueue(l, item.depth + 1)) links++
      }
    } else if (html) {
      // At max depth we still count in-scope links for visibility, without queuing.
      for (const l of extractLinks(html, item.url, extractType)) if (this.allowedHost(l)) links++
    }
    const node: CrawlNode = {
      url: item.url,
      depth: item.depth,
      status: res.status,
      type: res.type,
      length: res.length,
      ms: res.ms,
      title: res.title,
      params: queryParams(item.url),
      forms,
      links,
      error: res.error
    }
    this._nodes.push(node)
    return node
  }
}

/** Distinct in-scope endpoints (path-level) discovered, for a summary line. */
export function uniqueEndpoints(nodes: CrawlNode[]): number {
  const set = new Set<string>()
  for (const n of nodes) {
    try {
      const u = new URL(n.url)
      set.add(u.origin + u.pathname)
    } catch {
      set.add(n.url)
    }
  }
  return set.size
}

/** Total parameter names and forms seen across a crawl (automation summary). */
export function crawlSummary(nodes: CrawlNode[]): { pages: number; params: number; forms: number; withParams: number } {
  const params = new Set<string>()
  let forms = 0
  let withParams = 0
  for (const n of nodes) {
    if (n.params.length) withParams++
    for (const p of n.params) params.add(p)
    forms += n.forms.length
  }
  return { pages: nodes.length, params: params.size, forms, withParams }
}
