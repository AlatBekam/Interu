// Live end-to-end check of the main-branch engine against a REAL target.
//
// Gated behind LIVE=1 so a normal `npm test` never reaches out to the network.
// Run with:  npx cross-env LIVE=1 vitest run testcase/live-target.test.ts
//
// Authorization split:
//  - HTTP GET goes to the public OWASP Juice Shop demo (a GET to an app meant to
//    be viewed; browser-equivalent). Override with TARGET_URL.
//  - The port scan targets 127.0.0.1 ONLY, against a listener this test opens
//    itself. We never scan the hosted demo (shared third-party infra).
import { describe, expect, it } from 'vitest'
import net from 'node:net'
import { sendHttp } from '../src/main/http'
import { runScan, type RunParams } from '../src/main/scan'
import { hostInScope } from '../src/shared/http'
import { targetsInScope } from '../src/shared/scan'

const LIVE = !!process.env.LIVE
const TARGET_URL = process.env.TARGET_URL || 'https://juice-shop.herokuapp.com/'
const TARGET_HOST = new URL(TARGET_URL).hostname

// Reserve a loopback port and return it still open; caller closes it when done.
function openLoopbackPort(): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = net.createServer()
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo
      resolve({ port, close: () => new Promise<void>((r) => server.close(() => r())) })
    })
  })
}

describe.skipIf(!LIVE)('main engine vs. a real target (LIVE=1)', () => {
  it('scope gate allows an in-scope host and blocks empty scope', () => {
    expect(hostInScope(TARGET_URL, [TARGET_HOST])).toBe(true)
    expect(hostInScope(TARGET_URL, [])).toBe(false)
    expect(targetsInScope(['127.0.0.1'], ['127.0.0.1']).ok).toBe(true)
    expect(targetsInScope(['127.0.0.1'], []).ok).toBe(false)
  })

  it('sendHttp performs a real HTTPS GET and returns a usable response', async () => {
    const res = await sendHttp({ method: 'GET', url: TARGET_URL, headers: {}, timeoutMs: 20000 })
    if (!res.ok) {
      // Heroku free dynos were retired, so the demo may be offline/sleeping.
      console.warn(`[skip] ${TARGET_URL} unreachable (${res.error}). Retry with TARGET_URL=https://demo.owasp-juice.shop`)
      return
    }
    expect(res.status).toBe(200)
    expect(res.size).toBeGreaterThan(0)
    expect((res.body || '').toLowerCase()).toMatch(/juice shop|<app-root/)
  }, 30000)

  it('runScan reports a self-opened loopback port as open and a closed one as not', async () => {
    const live = await openLoopbackPort()
    // Reserve then immediately release a second port so it is reliably closed.
    const spare = await openLoopbackPort()
    const closedPort = spare.port
    await spare.close()
    try {
      const params: RunParams = {
        scanId: 1,
        target: '127.0.0.1',
        profile: 'quick',
        ips: ['127.0.0.1'],
        ports: [live.port, closedPort],
        grabBanner: false,
        timeoutMs: 1500,
        concurrency: 8
      }
      const { hosts } = await runScan(params, () => {})
      const openPorts = hosts.flatMap((h) => h.openPorts.map((p) => p.port))
      expect(openPorts).toContain(live.port)
      expect(openPorts).not.toContain(closedPort)
    } finally {
      await live.close()
    }
  }, 15000)
})
