import { describe, expect, it } from 'vitest'
import { analyzeTokens, parseTokens } from './tokens'

describe('parseTokens', () => {
  it('drops blank lines and surrounding whitespace', () => {
    expect(parseTokens('  abc \r\n\n  def\n   \n')).toEqual(['abc', 'def'])
  })
  it('keeps each duplicate once, in order', () => {
    expect(parseTokens('a\nb\na\nc\nb')).toEqual(['a', 'b', 'c'])
  })
  it('returns [] for empty input', () => {
    expect(parseTokens('')).toEqual([])
    expect(parseTokens('  \n \n')).toEqual([])
  })
})

describe('analyzeTokens', () => {
  it('needs at least two tokens', () => {
    expect(analyzeTokens([])).toBeNull()
    expect(analyzeTokens(['abcd'])).toBeNull()
  })

  it('rates a counter-like sequence as weak', () => {
    const a = analyzeTokens(Array.from({ length: 50 }, (_, i) => `session${String(i).padStart(4, '0')}`))!
    expect(a.qualityPct).toBeLessThan(55)
    // The low positions barely change: the leading "session" slots carry no entropy.
    expect(a.positional.slice(0, 7).every((h) => h === 0)).toBe(true)
  })

  it('does not penalise a hex token for not using a 62-char alphabet', () => {
    // All 16 hex digits equally often: exactly 4 bits per char, the hex ceiling.
    const t = ['0123456789abcdef', 'fedcba9876543210']
    const a = analyzeTokens(t)!
    expect(a.charset).toBe('hex')
    expect(a.bitsPerChar).toBeCloseTo(4, 5)
    expect(a.qualityPct).toBe(100)
  })

  it('handles tokens of different lengths', () => {
    const a = analyzeTokens(['abcdef', 'ab', 'xyzxyzxyz'])!
    expect(a.positional).toHaveLength(9)
    expect(a.avgLen).toBeCloseTo(17 / 3, 5)
  })
})
