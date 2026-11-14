import { describe, it } from 'vitest'
import { writeFileSync } from 'node:fs'
import { sendHttp } from '../src/main/http'
import { AutomationRunner } from '../src/main/automation'

const online = process.env.INTERU_ONLINE_BENCH === '1' ? describe : describe.skip
const target = 'https://ginandjuice.shop/'

online('independent online scanner benchmark', () => {
  it('checks transport to the PortSwigger demo', async () => {
    const res = await sendHttp({ method: 'GET', url: target, headers: {}, timeoutMs: 12000 })
    const result = { target, ok: res.ok, status: res.status, error: res.error, size: res.size, timingMs: res.timingMs }
    writeFileSync('audit/online-connectivity.json', JSON.stringify(result, null, 2))
    console.log('Online connectivity:', JSON.stringify(result))
  }, 20000)

  it('runs bounded unauthenticated automation', async () => {
    const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => ['ginandjuice.shop'])
    runner.start({ target, maxPages: 30, maxDepth: 2, maxRequests: 180,
      delayMs: 500, timeoutMs: 8000, maxDurationMs: 240000,
      activeChecks: false, parameterChecks: true })
    await runner.wait()
    const result = runner.snapshot()
    const report = {
      target, status: result.status, reason: result.reason, requests: result.requests,
      pages: result.pages, errors: result.errors, startedAt: result.startedAt, finishedAt: result.finishedAt,
      findings: result.findings.map(f => ({ name: f.name, templateId: f.templateId,
        severity: f.severity, confidence: f.confidence, evidence: f.evidence,
        matchedAt: f.matchedAt, source: f.source })),
      log: result.log
    }
    writeFileSync('audit/online-benchmark.json', JSON.stringify(report, null, 2))
    console.log('Online benchmark:', JSON.stringify({ status: report.status, reason: report.reason,
      requests: report.requests, pages: report.pages, errors: report.errors,
      findings: report.findings.map(f => `${f.confidence}: ${f.name}`) }))
  }, 260000)

  it('runs the complete active rule catalogue at low rate', async () => {
    const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => ['ginandjuice.shop'])
    runner.start({ target, maxPages: 1, maxDepth: 0, maxRequests: 800,
      delayMs: 350, timeoutMs: 8000, maxDurationMs: 450000,
      activeChecks: true, parameterChecks: false })
    await runner.wait()
    const result = runner.snapshot()
    const report = {
      target, status: result.status, reason: result.reason, requests: result.requests,
      pages: result.pages, errors: result.errors, startedAt: result.startedAt, finishedAt: result.finishedAt,
      findings: result.findings.map(f => ({ name: f.name, templateId: f.templateId,
        severity: f.severity, confidence: f.confidence, evidence: f.evidence,
        matchedAt: f.matchedAt, source: f.source })),
      log: result.log
    }
    writeFileSync('audit/online-active-rules.json', JSON.stringify(report, null, 2))
    console.log('Online active rules:', JSON.stringify({ status: report.status, reason: report.reason,
      requests: report.requests, pages: report.pages, errors: report.errors,
      findings: report.findings.map(f => `${f.confidence}: ${f.name}`) }))
  }, 470000)
})
