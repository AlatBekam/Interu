import { describe, it } from 'vitest'
import { writeFileSync } from 'node:fs'
import { sendHttp } from '../src/main/http'
import { AutomationRunner } from '../src/main/automation'

const live = process.env.INTERU_ALTORO_BENCH === '1' ? describe : describe.skip
const target = 'http://demo.testfire.net/'

live('independent Altoro Mutual online benchmark', () => {
  it('runs bounded unauthenticated automation', async () => {
    const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => ['demo.testfire.net'])
    runner.start({ target, maxPages: 35, maxDepth: 2, maxRequests: 160,
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
    writeFileSync('audit/altoro-online-benchmark.json', JSON.stringify(report, null, 2))
    console.log('Altoro benchmark:', JSON.stringify({ status: report.status, reason: report.reason,
      requests: report.requests, pages: report.pages, errors: report.errors,
      findings: report.findings.map(f => `${f.confidence}: ${f.name}`) }))
  }, 260000)
})
