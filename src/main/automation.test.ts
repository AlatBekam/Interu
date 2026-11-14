import { describe, expect, it } from 'vitest'
import { AutomationRunner } from './automation'
import type { HttpRes } from '../shared/http'

const ok = (body = '<html></html>', status = 200): HttpRes => ({
  ok: true, status, body, rawHeaders: 'content-type: text/html', raw: `HTTP/1.1 ${status} OK\r\ncontent-type: text/html\r\n\r\n${body}`, timingMs: 1, size: body.length
})
const options = { target: 'http://example.test/', activeChecks: false, parameterChecks: false, delayMs: 100 }

describe('bounded automation runner', () => {
  it('requires scope before any network request', () => {
    let calls = 0
    const runner = new AutomationRunner(async () => { calls++; return ok() }, () => [])
    expect(() => runner.start(options)).toThrow(/scope/)
    expect(calls).toBe(0)
  })
  it('stops at the request budget and retains completed pages', async () => {
    const calls: string[] = []
    const runner = new AutomationRunner(async (req) => { calls.push(req.url); return ok('<a href="/next">next</a>') }, () => ['example.test'])
    runner.start({ ...options, maxRequests: 1 })
    await runner.wait()
    expect(calls).toEqual(['http://example.test/'])
    expect(runner.snapshot()).toMatchObject({ status: 'limited', requests: 1, pages: 1 })
  })
  it('stops on authentication expiry without following links', async () => {
    let calls = 0
    const runner = new AutomationRunner(async () => { calls++; return { ...ok('<a href="/next">next</a>'), authLost: true } }, () => ['example.test'])
    runner.start(options)
    await runner.wait()
    expect(runner.snapshot()).toMatchObject({ status: 'failed', requests: 1, pages: 0 })
    expect(runner.snapshot().reason).toMatch(/Authentication expired/)
    expect(calls).toBe(1)
  })
  it('cancels a pending request', async () => {
    const runner = new AutomationRunner((_req, signal) => new Promise<HttpRes>((resolve) => {
      signal.addEventListener('abort', () => resolve({ ok: false, error: 'aborted', timingMs: 0, size: 0 }), { once: true })
    }), () => ['example.test'])
    runner.start(options)
    runner.cancel()
    await runner.wait()
    expect(runner.snapshot().status).toBe('cancelled')
  })
  it('combines crawl discovery and a differential file probe in one run', async () => {
    const calls: string[] = []
    const runner = new AutomationRunner(async req => {
      calls.push(req.url)
      const u = new URL(req.url)
      if (u.pathname === '/') return ok('<a href="/read?file=welcome">Read</a>')
      if (u.searchParams.get('file')?.includes('/etc/passwd')) return ok('root:x:0:0:root:/root:/bin/sh\n')
      return ok('<html>ordinary file</html>')
    }, () => ['example.test'])
    runner.start({ ...options, parameterChecks: true, maxPages: 2, maxDepth: 1, maxRequests: 20 })
    await runner.wait()
    expect(runner.snapshot().status).toBe('completed')
    expect(runner.snapshot().findings.some(f => f.templateId === 'webvuln-lfi' && f.confidence === 'confirmed')).toBe(true)
    expect(calls.every(url => new URL(url).origin === 'http://example.test')).toBe(true)
  })
  it('does not follow a redirect to another origin', async () => {
    const calls: string[] = []
    const runner = new AutomationRunner(async req => {
      calls.push(req.url)
      return { ...ok('', 302), rawHeaders: 'location: https://other.test/private' }
    }, () => ['example.test', 'other.test'])
    runner.start(options)
    await runner.wait()
    expect(calls).toEqual(['http://example.test/'])
    expect(runner.snapshot().status).toBe('failed')
    expect(runner.snapshot().reason).toMatch(/origin/)
  })
  it('stops immediately when the server requests backoff', async () => {
    const runner = new AutomationRunner(async () => ok('', 429), () => ['example.test'])
    runner.start(options)
    await runner.wait()
    expect(runner.snapshot()).toMatchObject({ status: 'limited', requests: 1 })
  })
})
