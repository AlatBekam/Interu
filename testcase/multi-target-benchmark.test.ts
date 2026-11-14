import { describe, it } from 'vitest'
import { writeFileSync } from 'node:fs'
import { sendHttp } from '../src/main/http'
import { AutomationRunner } from '../src/main/automation'

const live = process.env.INTERU_MULTI_BENCH === '1' ? describe : describe.skip
const targets = [
  { name: 'PortSwigger Gin and Juice Shop', url: 'https://ginandjuice.shop/', kind: 'online' },
  { name: 'HCL Altoro Mutual', url: 'http://demo.testfire.net/', kind: 'online' },
  { name: 'Google Firing Range', url: 'https://public-firing-range.appspot.com/', kind: 'online' },
  { name: 'Pentest Ground DVWA', url: 'https://pentest-ground.com:4280/', kind: 'online' },
  { name: 'Pentest Ground DVGA', url: 'https://pentest-ground.com:5013/', kind: 'online' },
  { name: 'Pentest Ground RestFlaw', url: 'https://pentest-ground.com:9000/', kind: 'online' },
  { name: 'Pentest Ground GuardianLeaks', url: 'https://pentest-ground.com:81/', kind: 'online' },
  { name: 'OWASP Juice Shop Docker', url: 'http://127.0.0.1:3001/', kind: 'selfhost' },
  { name: 'VAmPI Docker', url: 'http://127.0.0.1:3004/ui/', kind: 'selfhost' },
  { name: 'OWASP WebGoat Docker', url: 'http://127.0.0.1:3002/WebGoat/', kind: 'selfhost' }
] as const

live('ten independent legal targets', () => {
  it('records bounded unauthenticated findings per target', async () => {
    const reports: unknown[] = []
    const selected = process.env.INTERU_MULTI_ONLY
      ? targets.filter(spec => spec.name === process.env.INTERU_MULTI_ONLY) : targets
    const reportPath = process.env.INTERU_MULTI_ONLY
      ? 'audit/multi-target-single.json' : 'audit/multi-target-benchmark.json'
    for (const spec of selected) {
      const health = await sendHttp({ method: 'GET', url: spec.url, headers: {}, timeoutMs: 12000 })
      if (!health.ok || !health.status || health.status >= 500) {
        reports.push({ ...spec, status: 'unreachable', healthStatus: health.status, healthError: health.error })
        writeFileSync(reportPath, JSON.stringify(reports, null, 2))
        continue
      }
      const runner = new AutomationRunner((req, signal) => sendHttp(req, signal), () => [new URL(spec.url).hostname])
      runner.start({ target: spec.url, maxPages: spec.kind === 'online' ? 25 : 35, maxDepth: 2,
        maxRequests: spec.kind === 'online' ? 120 : 160,
        delayMs: spec.kind === 'online' ? 500 : 100,
        timeoutMs: 10000, maxDurationMs: 120000,
        activeChecks: false, parameterChecks: true })
      await runner.wait()
      const result = runner.snapshot()
      reports.push({ ...spec, healthStatus: health.status,
        status: result.status, reason: result.reason, requests: result.requests,
        pages: result.pages, errors: result.errors, startedAt: result.startedAt, finishedAt: result.finishedAt,
        findings: result.findings.map(f => ({ name: f.name, templateId: f.templateId,
          severity: f.severity, confidence: f.confidence, evidence: f.evidence,
          matchedAt: f.matchedAt, source: f.source })),
        log: result.log })
      writeFileSync(reportPath, JSON.stringify(reports, null, 2))
      console.log(`${spec.name}: ${result.status}, ${result.requests} requests, ${result.findings.length} findings`)
    }
  }, 1500000)
})
