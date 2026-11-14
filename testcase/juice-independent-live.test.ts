import { describe, expect, it } from 'vitest'
import { writeFileSync } from 'node:fs'
import { sendHttp } from '../src/main/http'
import { AutomationRunner } from '../src/main/automation'

const live = process.env.INTERU_JUICE_BENCH === '1' ? describe : describe.skip
const target = 'http://127.0.0.1:3001/'

live('independent OWASP Juice Shop Docker benchmark', () => {
  it('discovers a differential SQLite SQLi through the JavaScript API path', async () => {
    const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => ['127.0.0.1'])
    runner.start({ target, maxPages: 40, maxDepth: 2, maxRequests: 150,
      delayMs: 100, timeoutMs: 10000, maxDurationMs: 120000,
      activeChecks: false, parameterChecks: true })
    await runner.wait()
    const result = runner.snapshot()
    const hit = result.findings.find(f => f.templateId === 'webvuln-sqli-error' && f.matchedAt?.includes('/rest/products/search'))
    expect(result.status).toBe('completed')
    expect(hit?.confidence).toBe('confirmed')
    expect(hit?.evidence).toContain('balancing the quote cleared it')
  }, 140000)

  it('runs the complete bounded automation catalogue', async () => {
    const ready = await sendHttp({ method: 'GET', url: target, headers: {}, timeoutMs: 10000 })
    if (!ready.ok || ready.status !== 200) throw new Error(`Juice Shop not ready: ${ready.error || ready.status}`)
    const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => ['127.0.0.1'])
    runner.start({ target, maxPages: 40, maxDepth: 2, maxRequests: 1000,
      delayMs: 100, timeoutMs: 10000, maxDurationMs: 240000,
      activeChecks: true, parameterChecks: true })
    await runner.wait()
    const result = runner.snapshot()
    const report = {
      target, readinessStatus: ready.status, status: result.status, reason: result.reason, requests: result.requests,
      pages: result.pages, errors: result.errors, startedAt: result.startedAt, finishedAt: result.finishedAt,
      findings: result.findings.map(f => ({ name: f.name, templateId: f.templateId,
        severity: f.severity, confidence: f.confidence, evidence: f.evidence,
        matchedAt: f.matchedAt, source: f.source })),
      log: result.log
    }
    writeFileSync('audit/juice-independent-benchmark.json', JSON.stringify(report, null, 2))
    console.log('Juice Shop benchmark:', JSON.stringify({ status: report.status, reason: report.reason,
      requests: report.requests, pages: report.pages, errors: report.errors,
      findings: report.findings.map(f => `${f.confidence}: ${f.name}`) }))
  }, 260000)
})
