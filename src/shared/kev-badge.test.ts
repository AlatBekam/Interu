import { describe, expect, it } from 'vitest'
import { cveSummary, kevBadge, kevFor } from './kev'

describe('cveSummary', () => {
  it('shows a dash when there are no CVEs', () => {
    expect(cveSummary(undefined)).toBe('—')
  })
  it('keeps up to three IDs whole', () => {
    expect(cveSummary(['CVE-2021-0001', 'CVE-2021-0002'])).toBe('CVE-2021-0001, CVE-2021-0002')
  })
  it('caps the list at three and counts the rest', () => {
    expect(cveSummary(['a', 'b', 'c', 'd', 'e'])).toBe('a, b, c +2')
  })
})

describe('kevBadge', () => {
  const kev = kevFor(['CVE-2021-44228'])
  it('is null without KEV entries', () => {
    expect(kevBadge({ kev: undefined })).toBeNull()
  })
  it('labels a CVE-level match as KEV', () => {
    expect(kevBadge({ kev })?.text).toBe('KEV')
  })
  it('labels a product-level match as KEV product and says the version is unverified', () => {
    const badge = kevBadge({ tags: ['kev-product'], kev })
    expect(badge?.text).toBe('KEV product')
    expect(badge?.title).toMatch(/version not verified/)
  })
})
