import { describe, expect, it } from 'vitest'
import { DEFAULT_AUTOMATION, normalizeAutomation } from './automation'

describe('automation configuration', () => {
  it('keeps deterministic checks enabled by default and bounds resource use', () => {
    const options = normalizeAutomation({ target: 'example.test', maxPages: 9999, maxRequests: 0, delayMs: 0 })
    expect(options.target).toBe('http://example.test/')
    expect(options.activeChecks).toBe(DEFAULT_AUTOMATION.activeChecks)
    expect(options.parameterChecks).toBe(true)
    expect(options.maxPages).toBe(200)
    expect(options.maxRequests).toBe(1)
    expect(options.delayMs).toBe(100)
  })
  it('rejects embedded credentials and non-HTTP targets', () => {
    expect(() => normalizeAutomation({ target: 'http://user:pass@example.test/' })).toThrow()
    expect(() => normalizeAutomation({ target: 'file:///tmp/secret' })).toThrow()
  })
})
