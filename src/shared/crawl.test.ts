import { describe, it, expect } from 'vitest'
import {
  normalizeUrl,
  queryParams,
  isFetchable,
  extractLinks,
  extractOpenApiGetUrls,
  extractForms,
  pageTitle,
  contentTypeLabel,
  CrawlController,
  crawlSummary,
  uniqueEndpoints,
  DEFAULT_CRAWL_OPTIONS,
  type CrawlOptions
} from './crawl'

const base = 'http://demo.test/app/'

describe('normalizeUrl', () => {
  it('resolves relative paths against the base', () => {
    expect(normalizeUrl('../api/x', base)).toBe('http://demo.test/api/x')
    expect(normalizeUrl('/login', base)).toBe('http://demo.test/login')
    expect(normalizeUrl('next', base)).toBe('http://demo.test/app/next')
  })
  it('keeps absolute http(s) urls and strips fragments', () => {
    expect(normalizeUrl('https://x.test/a#frag', base)).toBe('https://x.test/a')
  })
  it('rejects non-crawlable schemes and empty/anchor hrefs', () => {
    for (const bad of ['mailto:a@b.c', 'javascript:void(0)', 'tel:+1', 'data:text/html,x', '#top', '']) {
      expect(normalizeUrl(bad, base)).toBeNull()
    }
  })
})

describe('queryParams', () => {
  it('lists distinct param names', () => {
    expect(queryParams('http://h/x?id=1&q=a&id=2')).toEqual(['id', 'q'])
    expect(queryParams('http://h/x')).toEqual([])
  })
})

describe('isFetchable', () => {
  it('skips assets and binaries, allows pages/apis', () => {
    expect(isFetchable('http://h/style.css')).toBe(false)
    expect(isFetchable('http://h/logo.png?v=2')).toBe(false)
    expect(isFetchable('http://h/app.js.map')).toBe(false)
    // .js IS fetched on purpose: inline scripts are sniffed for API endpoints.
    expect(isFetchable('http://h/app.js')).toBe(true)
    expect(isFetchable('http://h/api/users')).toBe(true)
    expect(isFetchable('http://h/page')).toBe(true)
  })
})

describe('extractLinks', () => {
  it('pulls href/src/action and inline api paths, deduped & normalised', () => {
    const html = `
      <a href="/one">1</a>
      <a href='two'>2</a>
      <link href="/style.css">
      <form action="/submit"></form>
      <script>fetch("/api/secret"); var u='/one';</script>
      <a href="mailto:x@y.z">mail</a>
    `
    const links = extractLinks(html, base)
    expect(links).toContain('http://demo.test/one')
    expect(links).toContain('http://demo.test/app/two')
    expect(links).toContain('http://demo.test/style.css')
    expect(links).toContain('http://demo.test/submit')
    expect(links).toContain('http://demo.test/api/secret')
    expect(links).not.toContain('mailto:x@y.z')
    // /one appears twice (href + inline) but is deduped
    expect(links.filter((l) => l === 'http://demo.test/one')).toHaveLength(1)
  })
  it('does not treat minified JavaScript fragments as links', () => {
    const js = `const x='href="/fake"'; const a="/api/products"; const b="/null;get"; const c="/r??this._platformLocation.getBaseHrefFromDOM()"; const d="/!1";`
    expect(extractLinks(js, 'http://demo.test/main.js', 'js')).toEqual(['http://demo.test/api/products'])
  })
  it('does not parse attribute text inside script bodies as HTML tags', () => {
    const html = `<script>const x='href="/fake"'; fetch('/api/items')</script><a href="/real">real</a>`
    const links = extractLinks(html, base, 'html')
    expect(links).toContain('http://demo.test/real')
    expect(links).toContain('http://demo.test/api/items')
    expect(links).not.toContain('http://demo.test/fake')
  })
  it('discovers a static API path and query key inside a JavaScript template string', () => {
    const js = 'return this.http.get(`${this.hostServer}/rest/products/search?q=${term}`)'
    expect(extractLinks(js, 'http://demo.test/main.js', 'js')).toContain('http://demo.test/rest/products/search?q=')
  })
})

describe('OpenAPI GET discovery', () => {
  it('extracts JSON GET paths with query parameters and ignores POST', () => {
    const spec = JSON.stringify({ openapi: '3.0.1', paths: {
      '/items/{id}': { get: { parameters: [{ in: 'query', name: 'q' }] } },
      '/delete': { post: { parameters: [{ in: 'query', name: 'id' }] } }
    } })
    expect(extractOpenApiGetUrls(spec, base)).toEqual(['http://demo.test/items/1?q=1'])
  })
  it('extracts YAML GET query keys without POST body endpoints', () => {
    const spec = `openapi: 3.0.1\npaths:\n  /eval:\n    get:\n      parameters:\n      - in: query\n        name: s\n      responses:\n        '200': {}\n  /search:\n    post:\n      requestBody: {}\n`
    expect(extractLinks(spec, 'http://demo.test/openapi.yaml', 'yaml')).toEqual(['http://demo.test/eval?s=1'])
  })
})

describe('extractForms', () => {
  it('parses method, resolved action, and named inputs', () => {
    const html = `
      <form method="post" action="/login">
        <input name="user" type="text">
        <input type="password" name="pass">
        <input type="submit" value="go">
        <textarea name="note"></textarea>
      </form>`
    const forms = extractForms(html, base)
    expect(forms).toHaveLength(1)
    expect(forms[0].method).toBe('POST')
    expect(forms[0].action).toBe('http://demo.test/login')
    const names = forms[0].inputs.map((i) => i.name)
    expect(names).toEqual(['user', 'pass', 'note'])
  })
  it('defaults method to GET and action to the page url', () => {
    const forms = extractForms('<form><input name="q"></form>', base)
    expect(forms[0].method).toBe('GET')
    expect(forms[0].action).toBe(base)
  })
})

describe('pageTitle / contentTypeLabel', () => {
  it('extracts and trims the title', () => {
    expect(pageTitle('<title>  Hello  World </title>')).toBe('Hello World')
    expect(pageTitle('<p>no title</p>')).toBeUndefined()
  })
  it('maps content types to short labels', () => {
    expect(contentTypeLabel('text/html; charset=utf-8')).toBe('html')
    expect(contentTypeLabel('application/json')).toBe('json')
    expect(contentTypeLabel('application/javascript')).toBe('js')
    expect(contentTypeLabel(undefined)).toBe('text')
  })
})

describe('CrawlController BFS', () => {
  const scope = ['demo.test']
  const opts = (o: Partial<CrawlOptions> = {}): CrawlOptions => ({ ...DEFAULT_CRAWL_OPTIONS, ...o })

  it('seeds the frontier and hands out the seed first', () => {
    const c = new CrawlController(['http://demo.test/'], opts(), scope)
    const first = c.take()
    expect(first?.url).toBe('http://demo.test/')
    expect(first?.depth).toBe(0)
  })

  it('enqueues in-scope links from a recorded page and dedupes', () => {
    const c = new CrawlController(['http://demo.test/'], opts({ maxDepth: 2 }), scope)
    const seed = c.take()!
    c.record(seed, {
      status: 200,
      type: 'html',
      html: '<a href="/a">a</a><a href="/a">dup</a><a href="/b">b</a>'
    })
    const got = new Set<string>()
    let item
    while ((item = c.take())) got.add(item.url)
    expect(got.has('http://demo.test/a')).toBe(true)
    expect(got.has('http://demo.test/b')).toBe(true)
    expect(c.done).toBe(1) // only the seed was recorded
  })

  it('blocks out-of-scope hosts', () => {
    const c = new CrawlController(['http://demo.test/'], opts(), scope)
    const seed = c.take()!
    c.record(seed, { status: 200, type: 'html', html: '<a href="http://evil.test/x">x</a>' })
    expect(c.take()).toBeNull() // evil.test filtered out
  })

  it('respects same-host policy with and without subdomains', () => {
    const sub = ['demo.test', 'sub.demo.test', 'other.test']
    const withSub = new CrawlController(['http://demo.test/'], opts({ includeSubdomains: true }), sub)
    expect(withSub.allowedHost('http://sub.demo.test/x')).toBe(true)
    expect(withSub.allowedHost('http://other.test/x')).toBe(false)
    const noSub = new CrawlController(['http://demo.test/'], opts({ includeSubdomains: false }), sub)
    expect(noSub.allowedHost('http://sub.demo.test/x')).toBe(false)
  })

  it('does not follow past maxDepth', () => {
    const c = new CrawlController(['http://demo.test/'], opts({ maxDepth: 1 }), scope)
    const seed = c.take()! // depth 0
    c.record(seed, { status: 200, type: 'html', html: '<a href="/a">a</a>' })
    const a = c.take()! // depth 1
    expect(a.depth).toBe(1)
    c.record(a, { status: 200, type: 'html', html: '<a href="/deep">deep</a>' })
    expect(c.take()).toBeNull() // /deep would be depth 2 > maxDepth 1
  })

  it('enforces the maxPages budget', () => {
    const c = new CrawlController(['http://demo.test/'], opts({ maxPages: 2, maxDepth: 5 }), scope)
    const seed = c.take()!
    c.record(seed, { status: 200, type: 'html', html: '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>' })
    expect(c.take()).not.toBeNull() // 2nd
    expect(c.take()).toBeNull() // budget (2) spent
  })
  it('caps repeated values for one path and parameter shape', () => {
    const c = new CrawlController(['http://demo.test/'], opts({ maxPages: 20 }), scope)
    for (let i = 1; i <= 12; i++) c.enqueue(`http://demo.test/catalog/product?productId=${i}`, 1)
    c.enqueue('http://demo.test/search?term=1', 1)
    const urls: string[] = []
    let item
    while ((item = c.take())) urls.push(item.url)
    expect(urls.filter(url => url.includes('/catalog/product'))).toHaveLength(4)
    expect(urls).toContain('http://demo.test/search?term=1')
  })
  it('visits a search query before less useful URLs at the same depth', () => {
    const c = new CrawlController(['http://demo.test/'], opts(), scope)
    const root = c.take()!
    c.record(root, { status: 200, type: 'html', html: '<a href="/about">about</a><a href="/api/search?q=1">search</a><script src="/main.js"></script>' })
    expect(c.take()?.url).toBe('http://demo.test/api/search?q=1')
  })

  it('skips asset extensions when queuing', () => {
    const c = new CrawlController(['http://demo.test/'], opts(), scope)
    const seed = c.take()!
    c.record(seed, { status: 200, type: 'html', html: '<a href="/a.css">css</a><a href="/b.png">png</a><a href="/c">c</a>' })
    const urls: string[] = []
    let it
    while ((it = c.take())) urls.push(it.url)
    expect(urls).toEqual(['http://demo.test/c'])
  })
  it('never queues known state-changing GET paths', () => {
    const c = new CrawlController(['http://demo.test/'], opts(), scope)
    const seed = c.take()!
    c.record(seed, { status: 200, type: 'html', html: '<a href="/createdb">db</a><a href="/start_over">reset</a><a href="/rest/items">items</a>' })
    expect(c.take()?.url).toBe('http://demo.test/rest/items')
    expect(c.take()).toBeNull()
  })
})

describe('summaries', () => {
  it('counts pages, params, forms and unique endpoints', () => {
    const c = new CrawlController(['http://demo.test/'], DEFAULT_CRAWL_OPTIONS, ['demo.test'])
    c.record({ url: 'http://demo.test/a?id=1', depth: 0 }, { status: 200, type: 'html' })
    c.record({ url: 'http://demo.test/a?id=2', depth: 0 }, { status: 200, type: 'html' })
    c.record({ url: 'http://demo.test/login', depth: 0 }, { status: 200, type: 'html', html: '<form><input name="u"></form>' })
    const s = crawlSummary(c.nodes)
    expect(s.pages).toBe(3)
    expect(s.params).toBe(1) // "id"
    expect(s.forms).toBe(1)
    expect(s.withParams).toBe(2)
    expect(uniqueEndpoints(c.nodes)).toBe(2) // /a and /login (query ignored)
  })
})
