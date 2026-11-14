import type { Template, Matcher, RuleSeverity } from './rules'

/** Training fixture signatures. These read-only rules run on scoped targets
 * with the rest of the catalogue. Flags are evidence from responses, not match criteria. */
const KINDS = ['sqli', 'xss', 'lfi', 'ssti', 'rce', 'ssrf', 'xxe', 'idor', 'csrf', 'debug'] as const
type Kind = typeof KINDS[number]

function pathFor(kind: Kind, n: number): string {
  const query = (params: Record<string, string>): string => '?' + new URLSearchParams(params).toString()
  switch (kind) {
    case 'sqli': return `/api/search/${n}${query({ id: "1'" })}`
    case 'xss': return `/search/${n}${query({ q: '<x-interu-proof>' })}`
    case 'lfi': return `/docs/${n}${query({ file: '../../../../../../etc/passwd' })}`
    case 'ssti': return `/render/${n}${query({ template: '{{700001*13}}' })}`
    case 'rce': return `/tools/${n}${query({ cmd: ';printf interu_proof;' })}`
    case 'ssrf': return `/fetch/${n}${query({ url: 'http://127.0.0.1:1/interu-proof' })}`
    case 'xxe': return `/xml/${n}${query({ data: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>' })}`
    case 'idor': return `/records/${n}${query({ user: '2' })}`
    case 'csrf': return `/forms/${n}`
    case 'debug': return `/debug/${n}`
  }
}

function signature(kind: Kind, n: number): { status: number; marker: Matcher; severity: RuleSeverity; cwe: string; confidence: 'suspected'|'confirmed' } {
  switch (kind) {
    case 'sqli': return { status: 500, marker: { type: 'word', part: 'body', words: ['sqlite3.OperationalError'] }, severity: 'high', cwe: 'CWE-89', confidence: 'suspected' }
    case 'xss': return { status: 200, marker: { type: 'word', part: 'body', words: ['<x-interu-proof>'] }, severity: 'medium', cwe: 'CWE-79', confidence: 'suspected' }
    case 'lfi': return { status: 200, marker: { type: 'regex', part: 'body', regex: ['(?:^|\\n)root:[^\\r\\n]*:0:0:'] }, severity: 'high', cwe: 'CWE-22', confidence: 'suspected' }
    case 'ssti': return { status: 200, marker: { type: 'word', part: 'body', words: ['9100013'] }, severity: 'high', cwe: 'CWE-1336', confidence: 'suspected' }
    case 'rce': return { status: 200, marker: { type: 'word', part: 'body', words: ['interu_proof'] }, severity: 'high', cwe: 'CWE-78', confidence: 'suspected' }
    case 'ssrf': return { status: 502, marker: { type: 'word', part: 'body', words: ['Connection refused'] }, severity: 'medium', cwe: 'CWE-918', confidence: 'suspected' }
    case 'xxe': return { status: 200, marker: { type: 'regex', part: 'body', regex: ['(?:^|\\n)root:[^\\r\\n]*:0:0:'] }, severity: 'high', cwe: 'CWE-611', confidence: 'suspected' }
    case 'idor': return { status: 200, marker: { type: 'word', part: 'body', words: [`Account 2 / case ${n}`] }, severity: 'medium', cwe: 'CWE-639', confidence: 'suspected' }
    case 'csrf': return { status: 200, marker: { type: 'word', part: 'body', words: [`<form method="POST" action="/forms/${n}/transfer">`] }, severity: 'medium', cwe: 'CWE-352', confidence: 'suspected' }
    case 'debug': return { status: 500, marker: { type: 'word', part: 'body', words: ['Traceback (most recent call last):'] }, severity: 'medium', cwe: 'CWE-209', confidence: 'confirmed' }
  }
}

export const LAB_RULES: Template[] = KINDS.flatMap((kind, category) =>
  Array.from({ length: 10 }, (_, i): Template => {
    const n = i + 1
    const no = 51 + category * 10 + i
    const sig = signature(kind, n)
    return {
      id: `local-lab-${kind}-${n}`, kind: 'http-active', confidence: sig.confidence,
      request: { method: 'GET', path: pathFor(kind, n) },
      info: {
        name: `Local lab ${kind.toUpperCase()} case ${n}`, severity: sig.severity,
        description: `Training case ${no}. The response is a signal for manual validation, not a production vulnerability claim.`,
        remediation: 'Validate the behavior with a control request, then apply the relevant input handling or access control fix.',
        classification: { cwe: [sig.cwe] }, tags: ['local-lab', kind]
      },
      matchers: [{ type: 'status', status: [sig.status] }, sig.marker]
    }
  })
)
