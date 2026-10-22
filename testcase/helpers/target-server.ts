// A deliberately "vulnerable" local HTTP server used as the authorized test
// target. Listens on 127.0.0.1 only, on a random free port.

import http from 'node:http'
import type { AddressInfo } from 'node:net'

export interface Target {
  /** e.g. http://127.0.0.1:54321 (no trailing slash) */
  base: string
  /** simulate the operator's fix: /.env starts returning 404 */
  setFixed(fixed: boolean): void
  /** change the leaked secret so a retest sees different evidence */
  setEnvBody(body: string): void
  close(): Promise<void>
}

export async function startTarget(): Promise<Target> {
  let fixed = false
  let envBody = 'DB_PASSWORD=supersecret\nAPP_KEY=base64:abc\n'
  const server = http.createServer((req, res) => {
    if (req.url === '/.env') {
      if (fixed) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found'); return }
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(envBody)
      return
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><body>ok</body></html>')
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const { port } = server.address() as AddressInfo
  return {
    base: `http://127.0.0.1:${port}`,
    setFixed: (v) => { fixed = v },
    setEnvBody: (b) => { envBody = b },
    close: () => new Promise((r) => server.close(() => r()))
  }
}
