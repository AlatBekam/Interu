// =========================================================================
// Simulated data for the Web Security Suite (Burp-style modules).
//
// This is ALL fabricated. No HTTP request here is ever sent; no traffic is
// intercepted. The "responses" are canned strings. In a later development
// stage these modules are intended to be wired to a real proxy engine for
// testing ONLY against systems the operator is authorized to test.
// =========================================================================

export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface HttpTx {
  id: number
  time: string
  method: Method
  host: string
  path: string
  status: number
  mime: string
  length: number
  flagged?: boolean
}

export const TARGET_HOST = 'demo.ruy.local'

// -------------------------------------------------------- proxy HTTP history
export const HTTP_HISTORY: HttpTx[] = [
  { id: 1, time: '10:02:11', method: 'GET', host: TARGET_HOST, path: '/', status: 200, mime: 'HTML', length: 5120 },
  { id: 2, time: '10:02:12', method: 'GET', host: TARGET_HOST, path: '/assets/app.js', status: 200, mime: 'script', length: 88211 },
  { id: 3, time: '10:02:12', method: 'GET', host: TARGET_HOST, path: '/assets/style.css', status: 200, mime: 'CSS', length: 15321 },
  { id: 4, time: '10:02:18', method: 'POST', host: TARGET_HOST, path: '/api/login', status: 200, mime: 'JSON', length: 212, flagged: true },
  { id: 5, time: '10:02:19', method: 'GET', host: TARGET_HOST, path: '/api/profile', status: 200, mime: 'JSON', length: 640 },
  { id: 6, time: '10:02:24', method: 'GET', host: TARGET_HOST, path: '/api/orders?id=1001', status: 200, mime: 'JSON', length: 1288, flagged: true },
  { id: 7, time: '10:02:26', method: 'GET', host: TARGET_HOST, path: '/api/orders?id=1002', status: 403, mime: 'JSON', length: 96 },
  { id: 8, time: '10:02:31', method: 'POST', host: TARGET_HOST, path: '/api/search', status: 200, mime: 'JSON', length: 2048 },
  { id: 9, time: '10:02:35', method: 'GET', host: TARGET_HOST, path: '/admin', status: 302, mime: '', length: 0 },
  { id: 10, time: '10:02:40', method: 'GET', host: TARGET_HOST, path: '/admin/users', status: 401, mime: 'JSON', length: 72 },
  { id: 11, time: '10:02:44', method: 'PUT', host: TARGET_HOST, path: '/api/profile', status: 200, mime: 'JSON', length: 310 },
  { id: 12, time: '10:02:50', method: 'DELETE', host: TARGET_HOST, path: '/api/session', status: 204, mime: '', length: 0 },
  { id: 13, time: '10:02:55', method: 'GET', host: TARGET_HOST, path: '/api/export?fmt=../../etc/passwd', status: 400, mime: 'JSON', length: 118, flagged: true },
  { id: 14, time: '10:03:01', method: 'GET', host: TARGET_HOST, path: '/robots.txt', status: 200, mime: 'text', length: 142 },
  { id: 15, time: '10:03:05', method: 'GET', host: TARGET_HOST, path: '/.git/config', status: 404, mime: 'HTML', length: 512 }
]

export function rawRequest(tx: HttpTx): string {
  const body = tx.method === 'POST' && tx.path === '/api/login'
    ? '\n{\n  "username": "demo",\n  "password": "S1mul@ted!"\n}'
    : tx.method === 'POST' && tx.path === '/api/search'
      ? '\n{\n  "q": "ruy",\n  "page": 1\n}'
      : tx.method === 'PUT'
        ? '\n{\n  "displayName": "RUY Operator"\n}'
        : ''
  const ctype = body ? 'Content-Type: application/json\r\nContent-Length: ' + (body.length - 1) + '\r\n' : ''
  return (
    `${tx.method} ${tx.path} HTTP/1.1\r\n` +
    `Host: ${tx.host}\r\n` +
    `User-Agent: RUY-Suite/1.0 (simulated)\r\n` +
    `Accept: */*\r\n` +
    `Authorization: Bearer eyJhbGciOiJIUzI1NiwidHlwIjoiSldUIn0.simulated.token\r\n` +
    `Cookie: SESSION=9f2c1b7ae44d4c0b8a1f; theme=dark\r\n` +
    ctype +
    `Connection: close\r\n` +
    body
  )
}

export function rawResponse(tx: HttpTx): string {
  const line =
    tx.status === 200 ? '200 OK' :
    tx.status === 204 ? '204 No Content' :
    tx.status === 302 ? '302 Found' :
    tx.status === 400 ? '400 Bad Request' :
    tx.status === 401 ? '401 Unauthorized' :
    tx.status === 403 ? '403 Forbidden' :
    tx.status === 404 ? '404 Not Found' : `${tx.status}`
  let body = ''
  if (tx.mime === 'JSON') {
    if (tx.path === '/api/login') body = '\n{\n  "ok": true,\n  "token": "eyJ...simulated",\n  "role": "user"\n}'
    else if (tx.path.startsWith('/api/orders')) body = tx.status === 200
      ? '\n{\n  "orderId": 1001,\n  "owner": "demo",\n  "total": 149.00,\n  "items": 3\n}'
      : '\n{\n  "error": "forbidden",\n  "detail": "not your order"\n}'
    else if (tx.path === '/api/profile') body = '\n{\n  "id": 42,\n  "name": "demo",\n  "email": "demo@ruy.local"\n}'
    else body = '\n{\n  "ok": ' + (tx.status < 400) + '\n}'
  } else if (tx.mime === 'HTML') {
    body = '\n<!doctype html><html><head><title>RUY Demo</title></head>\n<body><h1>Simulated response</h1></body></html>'
  } else if (tx.mime === 'text') {
    body = '\nUser-agent: *\nDisallow: /admin\nDisallow: /api/export'
  }
  const ctype = tx.mime === 'JSON' ? 'application/json' : tx.mime === 'HTML' ? 'text/html' : 'text/plain'
  return (
    `HTTP/1.1 ${line}\r\n` +
    `Server: ruy-demo (simulated)\r\n` +
    `Content-Type: ${ctype}; charset=utf-8\r\n` +
    `Content-Length: ${Math.max(0, tx.length)}\r\n` +
    `X-Powered-By: RUY-Suite\r\n` +
    `Set-Cookie: SESSION=9f2c1b7ae44d4c0b8a1f; HttpOnly; SameSite=Lax\r\n` +
    `Connection: close\r\n` +
    body
  )
}

// site map tree derived from history
export interface SiteNode { path: string; depth: 0 | 1 | 2; method?: Method; status?: number; kind: 'dir' | 'leaf' }
export const SITE_MAP: SiteNode[] = [
  { path: TARGET_HOST, depth: 0, kind: 'dir' },
  { path: '/', depth: 1, method: 'GET', status: 200, kind: 'leaf' },
  { path: '/assets', depth: 1, kind: 'dir' },
  { path: '/assets/app.js', depth: 2, method: 'GET', status: 200, kind: 'leaf' },
  { path: '/assets/style.css', depth: 2, method: 'GET', status: 200, kind: 'leaf' },
  { path: '/api', depth: 1, kind: 'dir' },
  { path: '/api/login', depth: 2, method: 'POST', status: 200, kind: 'leaf' },
  { path: '/api/profile', depth: 2, method: 'GET', status: 200, kind: 'leaf' },
  { path: '/api/orders', depth: 2, method: 'GET', status: 200, kind: 'leaf' },
  { path: '/api/search', depth: 2, method: 'POST', status: 200, kind: 'leaf' },
  { path: '/admin', depth: 1, method: 'GET', status: 302, kind: 'dir' },
  { path: '/admin/users', depth: 2, method: 'GET', status: 401, kind: 'leaf' },
  { path: '/robots.txt', depth: 1, method: 'GET', status: 200, kind: 'leaf' }
]

// -------------------------------------------------------- intruder payloads
export const PAYLOAD_SETS: Record<string, string[]> = {
  'Common usernames': ['admin', 'administrator', 'root', 'demo', 'test', 'guest', 'operator', 'svc_backup'],
  'SQLi probes': ["'", "' OR '1'='1", "'--", '" OR 1=1--', '1; DROP TABLE users', "' UNION SELECT NULL--"],
  'Directory fuzz': ['/admin', '/.env', '/backup.zip', '/config.php', '/.git/HEAD', '/api/v1', '/debug', '/server-status'],
  'HTTP methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']
}

// -------------------------------------------------------- sequencer tokens
export function sampleTokens(n: number): string[] {
  const rng = (seed => () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)(1337)
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  return Array.from({ length: n }, () =>
    Array.from({ length: 20 }, () => chars[Math.floor(rng() * chars.length)]).join('')
  )
}
