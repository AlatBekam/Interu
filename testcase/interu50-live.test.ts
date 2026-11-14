import { describe, expect, it } from 'vitest'
import { sendHttp } from '../src/main/http'
import { AutomationRunner } from '../src/main/automation'
import { MODERN_BACKUP_RULES } from '../src/shared/rulepack2025'
import { LAB_RULES } from '../src/shared/labRulepack'
import { buildActiveRequest, computeBaseline, matchActive } from '../src/shared/rules'

const live = process.env.INTERU50_LIVE === '1' ? describe : describe.skip
const origin = 'http://127.0.0.1:3000'
const firstVariant = MODERN_BACKUP_RULES.filter(rule => rule.id.endsWith('-1'))
const flag = (n: number): string => `RUY{harusnya_kamu_gabisa_liat_ini${n}}`

live('Interu 150 local Docker lab', () => {
  it('proves 50 distinct exposures with the Rule Engine matcher', async () => {
    const baseline = computeBaseline(await sendHttp({ method: 'GET', url: `${origin}/interu-not-here`, headers: {} }))
    const found: string[] = []
    for (let i = 0; i < firstVariant.length; i++) {
      const rule = firstVariant[i]
      const request = buildActiveRequest(rule, origin)!
      const response = await sendHttp(request)
      const finding = matchActive(rule, request.url, response, { req: request, baseline })
      expect(response.status).toBe(200)
      expect(response.body).toContain(flag(i + 1))
      expect(finding?.confidence).toBe('confirmed')
      expect(finding?.response).toContain(flag(i + 1))
      found.push(finding!.templateId)
    }
    expect(new Set(found).size).toBe(50)
  }, 30000)

  it('identifies 100 additional local cases across ten categories', async () => {
    const baseline = computeBaseline(await sendHttp({ method: 'GET', url: `${origin}/interu-not-here`, headers: {} }))
    expect(LAB_RULES).toHaveLength(100)
    for (let i = 0; i < LAB_RULES.length; i++) {
      const rule = LAB_RULES[i]
      const request = buildActiveRequest(rule, origin)!
      const response = await sendHttp(request)
      const finding = matchActive(rule, request.url, response, { req: request, baseline })
      expect(finding, rule.id).toBeTruthy()
      expect(response.body, rule.id).toContain(flag(i + 51))
      expect(finding?.response, rule.id).toContain(flag(i + 51))
    }
  }, 30000)

  it('discovers all 150 cases in one Pentest Automation run', async () => {
    const runner = new AutomationRunner((request, signal) => sendHttp(request, signal), () => ['127.0.0.1'])
    runner.start({ target: origin, maxPages: 1, maxDepth: 0, maxRequests: 900,
      delayMs: 100, timeoutMs: 2000, maxDurationMs: 120000,
      activeChecks: true, parameterChecks: true })
    await runner.wait()
    const result = runner.snapshot()
    expect(result.status).toBe('completed')
    const found = result.findings.filter(f => f.templateId.startsWith('modern-backup-') || f.templateId.startsWith('local-lab-'))
    expect(found).toHaveLength(150)
    for (let i = 1; i <= 150; i++) expect(found.some(f => f.response?.includes(flag(i)))).toBe(true)
  }, 150000)
})
