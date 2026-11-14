import { describe, it, expect } from 'vitest'
import {
  detectSqlError,
  sqliErrorVerdict,
  xssTag,
  xssPayload,
  xssEncoded,
  xssReflectVerdict,
  isIdLike,
  idorProbeEligible,
  idNeighbors,
  idorVerdict,
  accessVerdict,
  csrfMissing,
  planQueryParams,
  sqliFinding,
  xssFinding
  , fileDisclosureVerdict, expressionVerdict, commandOutputVerdict, ssrfErrorVerdict
} from './webvuln'
import type { CrawlForm } from './crawl'

describe('detectSqlError', () => {
  it('recognises common DB error signatures', () => {
    expect(detectSqlError("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")).toBe('MySQL')
    expect(detectSqlError('Warning: pg_query(): ERROR: syntax error')).toBeTruthy()
    expect(detectSqlError('Unclosed quotation mark after the character string')).toBe('MSSQL')
    expect(detectSqlError('ORA-00933: SQL command not properly ended')).toBe('Oracle')
    expect(detectSqlError('near "\'": syntax error unrecognized token:')).toBe('SQLite')
  })
  it('recognises SQLite error text only after a quote and clears on balanced quotes', () => {
    const baseline = '{"status":"success","data":[]}'
    const quote = '<title>Error: SQLITE_ERROR: near &quot;&#39;%&#39;&quot;: syntax error</title>'
    expect(detectSqlError(quote)).toBe('SQLite')
    expect(sqliErrorVerdict(baseline, quote, baseline)).toEqual({ confirmed: true, db: 'SQLite', balancedClears: true })
    expect(sqliErrorVerdict(quote, quote, baseline)).toBeNull()
  })
  it('does NOT fire on benign text (no false positive)', () => {
    expect(detectSqlError('Welcome to the homepage. Products and services.')).toBeNull()
    expect(detectSqlError('Your query returned 5 results.')).toBeNull()
    expect(detectSqlError('')).toBeNull()
  })
})

describe('sqliErrorVerdict', () => {
  const ERR = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
  it('suspects when the error appears only after the quote without a balancing control', () => {
    const v = sqliErrorVerdict('normal page', ERR)
    expect(v?.confirmed).toBe(false)
    expect(v?.db).toBe('MySQL')
  })
  it('marks balancedClears when value+\'\' removes the error', () => {
    const v = sqliErrorVerdict('normal page', ERR, 'normal page again')
    expect(v?.balancedClears).toBe(true)
    expect(v?.confirmed).toBe(true)
  })
  it('does NOT confirm when the error pre-exists in the baseline', () => {
    expect(sqliErrorVerdict(ERR, ERR)).toBeNull()
  })
  it('does NOT confirm when no error is present', () => {
    expect(sqliErrorVerdict('page', 'page with a quote but no db error')).toBeNull()
  })
})

describe('xssReflectVerdict', () => {
  const tok = 'abc123'
  it('records verbatim unencoded reflection as a candidate', () => {
    const body = `<div>search: ${xssPayload(tok)} results</div>`
    const v = xssReflectVerdict(body, tok, 'text/html')
    expect(v?.reflected).toBe(true)
    expect(v?.confirmed).toBe(false)
  })
  it('does NOT confirm when the app encoded the tag (safe)', () => {
    const body = `<div>search: ${xssEncoded(tok)} results</div>`
    const v = xssReflectVerdict(body, tok, 'text/html')
    expect(v?.confirmed).toBe(false)
    expect(v?.encodedInstead).toBe(true)
  })
  it('does NOT confirm for non-HTML responses', () => {
    const body = `{"q":"${xssTag(tok)}"}`
    expect(xssReflectVerdict(body, tok, 'application/json')).toBeNull()
  })
  it('returns null when the token is absent', () => {
    expect(xssReflectVerdict('<p>nothing here</p>', tok, 'text/html')).toBeNull()
  })
})

describe('IDOR', () => {
  it('classifies id-like params', () => {
    expect(isIdLike('user_id', 'x')).toBe(true)
    expect(isIdLike('acct', 'x')).toBe(true)
    expect(isIdLike('productId', '3')).toBe(true)
    expect(isIdLike('q', '42')).toBe(false) // numeric search terms are not object IDs
    expect(isIdLike('q', 'hello')).toBe(false)
  })
  it('requires a private object path before probing a numeric identifier', () => {
    expect(idorProbeEligible('https://h.test/catalog/product?productId=3', 'productId', '3')).toBe(false)
    expect(idorProbeEligible('https://h.test/blog/post?postId=4', 'postId', '4')).toBe(false)
    expect(idorProbeEligible('https://h.test/records/1?user=2', 'user', '2')).toBe(true)
  })
  it('builds numeric neighbours only', () => {
    expect(idNeighbors('5')).toEqual(['4', '6'])
    expect(idNeighbors('abc')).toEqual([])
  })
  const big = 'x'.repeat(400)
  it('suspects a distinct 200 object with no auth wall', () => {
    const v = idorVerdict({ status: 200, body: 'ACCOUNT A balance 100 ' + big }, { status: 200, body: 'ACCOUNT B balance 9999 ' + 'y'.repeat(700) })
    expect(v?.suspected).toBe(true)
  })
  it('does NOT suspect when neighbour is an auth wall (no FP)', () => {
    expect(idorVerdict({ status: 200, body: 'ACCOUNT A ' + big }, { status: 200, body: 'Please log in to continue ' + big })).toBeNull()
  })
  it('does NOT suspect identical or near-identical bodies (static page)', () => {
    expect(idorVerdict({ status: 200, body: 'SAME ' + big }, { status: 200, body: 'SAME ' + big })).toBeNull()
  })
  it('does NOT suspect on non-200 neighbour', () => {
    expect(idorVerdict({ status: 200, body: 'A ' + big }, { status: 404, body: 'not found ' + big })).toBeNull()
  })
})

describe('accessVerdict', () => {
  it('suspects a sensitive path served 200 that is not a login page', () => {
    expect(accessVerdict('http://h/admin/users', 200, '<h1>User management</h1>')?.suspected).toBe(true)
  })
  it('does NOT fire when the page is a login form (no FP)', () => {
    expect(accessVerdict('http://h/admin', 200, '<form><input type="password" name="password"></form>')).toBeNull()
  })
  it('does NOT fire on non-sensitive paths or non-200', () => {
    expect(accessVerdict('http://h/products', 200, 'items')).toBeNull()
    expect(accessVerdict('http://h/admin', 302, '')).toBeNull()
  })
  it('does not flag an empty unauthenticated identity response', () => {
    expect(accessVerdict('http://h/rest/user/whoami', 200, '{"user":{}}')).toBeNull()
  })
})

describe('csrfMissing', () => {
  const form = (o: Partial<CrawlForm>): CrawlForm => ({ method: 'POST', action: 'http://h/transfer', inputs: [], ...o })
  it('flags a state-changing POST form with no token', () => {
    expect(csrfMissing(form({ inputs: [{ name: 'amount', type: 'text' }, { name: 'to', type: 'text' }] }))).toBe(true)
  })
  it('does NOT flag when a csrf token field is present (no FP)', () => {
    expect(csrfMissing(form({ inputs: [{ name: 'amount', type: 'text' }, { name: '_csrf', type: 'hidden' }] }))).toBe(false)
  })
  it('does NOT flag GET forms or non-state-changing forms', () => {
    expect(csrfMissing(form({ method: 'GET' }))).toBe(false)
    expect(csrfMissing(form({ action: 'http://h/search', inputs: [{ name: 'q', type: 'text' }] }))).toBe(false)
  })
})

describe('planQueryParams', () => {
  it('builds baseline + sqli + xss probes per param', () => {
    let i = 0
    const plans = planQueryParams('http://h/p?id=7&q=a', () => `tok${i++}`)
    expect(plans.map((p) => p.param)).toEqual(['id', 'q'])
    const idPlan = plans[0]
    expect(idPlan.baselineUrl).toContain('id=7')
    const quote = idPlan.probes.find((p) => p.kind === 'sqli-quote')!
    expect(decodeURIComponent(quote.url)).toContain("id=7'")
    const xss = idPlan.probes.find((p) => p.kind === 'xss')!
    expect(xss.token).toBe('tok0')
    expect(decodeURIComponent(xss.url)).toContain('x-interu-tok0')
  })
  it('returns [] for a URL with no query string', () => {
    expect(planQueryParams('http://h/p')).toEqual([])
  })
  it('uses a default value of 1 for an empty param', () => {
    const plans = planQueryParams('http://h/p?x=', () => 't')
    expect(plans[0].baselineUrl).toContain('x=1')
  })
})

describe('bounded differential probes', () => {
  it('plans file and URL probes only for relevant parameter names', () => {
    const plans = planQueryParams('https://h.test/read?file=a&url=b&q=c', () => 'abc')
    expect(plans[0].probes.map(p => p.kind)).toContain('lfi')
    expect(plans[1].probes.map(p => p.kind)).toContain('ssrf')
    expect(plans[2].probes.map(p => p.kind)).not.toContain('lfi')
    expect(plans[2].probes.map(p => p.kind)).not.toContain('ssrf')
  })
  it('requires a distinct local-file signature absent from the baseline', () => {
    const file = 'root:x:0:0:root:/root:/bin/bash\n'
    expect(fileDisclosureVerdict('ordinary page', file)).toBe(true)
    expect(fileDisclosureVerdict(file, file)).toBe(false)
    expect(fileDisclosureVerdict('ordinary page', 'root user')).toBe(false)
  })
  it('rejects arithmetic and command markers that are merely reflected', () => {
    expect(expressionVerdict('normal', 'result=9100000', '9100000', '{{700000*13}}')).toBe(true)
    expect(expressionVerdict('normal', '{{700000*13}} result=9100000', '9100000', '{{700000*13}}')).toBe(false)
    expect(commandOutputVerdict('normal', 'interu_token', 'interu_token', ';printf interu_token;')).toBe(true)
    expect(commandOutputVerdict('normal', ';printf interu_token;', 'interu_token', ';printf interu_token;')).toBe(false)
  })
  it('only treats a new loopback transport error as an SSRF candidate', () => {
    expect(ssrfErrorVerdict('ordinary page', 'connect ECONNREFUSED 127.0.0.1:1')).toBe(true)
    expect(ssrfErrorVerdict('connection refused', 'connection refused')).toBe(false)
  })
})

describe('finding builders', () => {
  it('sqli finding is critical/confirmed with stable key and CWE-89', () => {
    const f = sqliFinding('http://h/p?id=1', 'id', { confirmed: true, db: 'MySQL', balancedClears: true })
    expect(f.severity).toBe('critical')
    expect(f.confidence).toBe('confirmed')
    expect(f.cwe).toContain('CWE-89')
    expect(f.key).toBe('webvuln:sqli:http://h/p:id')
    expect(f.source).toBe('active')
  })
  it('xss reflection finding is high/suspected with CWE-79', () => {
    const f = xssFinding('http://h/p?q=x', 'q', 'tok')
    expect(f.severity).toBe('high')
    expect(f.confidence).toBe('suspected')
    expect(f.cwe).toContain('CWE-79')
  })
})
