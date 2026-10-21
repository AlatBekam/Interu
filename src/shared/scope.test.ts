import { describe, expect, it } from 'vitest'
import { expandTargets, ipInScope, profilePorts, MAX_ATTEMPTS } from './scan'
import { hostInScope } from './http'

describe('expandTargets', () => {
  it('normalizes leading-zero IPs to the address the scope gate checked', () => {
    expect(expandTargets('010.0.0.1').ips).toEqual(['10.0.0.1'])
  })
  it('rejects a CIDR with an empty mask', () => {
    expect(expandTargets('10.0.0.0/').error).toBeTruthy()
  })
  it('fits a /24 standard scan under MAX_ATTEMPTS', () => {
    const ips = expandTargets('10.20.0.0/24').ips
    expect(ips.length * profilePorts('standard').length).toBeLessThanOrEqual(MAX_ATTEMPTS)
  })
})

describe('ipInScope', () => {
  it('matches IPs inside a scoped CIDR only', () => {
    expect(ipInScope('10.20.0.14', ['10.20.0.0/24'])).toBe(true)
    expect(ipInScope('10.21.0.14', ['10.20.0.0/24'])).toBe(false)
  })
  it('does not read an empty mask as /0', () => {
    expect(ipInScope('8.8.8.8', ['10.0.0.0/'])).toBe(false)
  })
})

describe('hostInScope', () => {
  it('allows IP URLs inside a scoped CIDR', () => {
    expect(hostInScope('http://10.20.0.14:8080/x', ['10.20.0.0/24'])).toBe(true)
    expect(hostInScope('http://10.21.0.14/', ['10.20.0.0/24'])).toBe(false)
  })
  it('does not suffix-match IP addresses', () => {
    expect(hostInScope('http://10.0.0.1/', ['0.1'])).toBe(false)
  })
  it('judges leading-zero URL hosts by the address actually contacted', () => {
    // WHATWG URL reads 010 as octal → 8.0.0.1, which is outside 10.0.0.0/8.
    expect(hostInScope('http://010.0.0.1/', ['10.0.0.0/8'])).toBe(false)
  })
  it('matches hostnames and subdomains, ignoring a port in the scope entry', () => {
    expect(hostInScope('https://api.example.com/x', ['example.com:8443'])).toBe(true)
    expect(hostInScope('https://notexample.com/', ['example.com'])).toBe(false)
  })
  it('allows nothing with an empty scope', () => {
    expect(hostInScope('https://example.com/', [])).toBe(false)
  })
})
