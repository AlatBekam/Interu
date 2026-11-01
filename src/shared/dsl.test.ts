import { describe, expect, it } from 'vitest'
import { evaluate, evalBool, DslError } from './dsl'

const ctx = {
  status: 200,
  content_length: 1024,
  duration: 350,
  body: 'Hello <b>World</b> phpinfo()',
  header: 'server: nginx/1.18.0\ncontent-type: text/html',
  banner: 'OpenSSH_9.6',
  port: 22,
  service: 'ssh'
}

describe('dsl literals & arithmetic', () => {
  it('evaluates numbers and arithmetic', () => {
    expect(evaluate('1 + 2 * 3', {})).toBe(7)
    expect(evaluate('(1 + 2) * 3', {})).toBe(9)
    expect(evaluate('10 % 3', {})).toBe(1)
  })
  it('concatenates strings with +', () => {
    expect(evaluate('"a" + "b" + "c"', {})).toBe('abc')
    expect(evaluate('"port-" + 22', {})).toBe('port-22')
  })
  it('booleans and logical ops short-circuit', () => {
    expect(evaluate('true && false', {})).toBe(false)
    expect(evaluate('true || false', {})).toBe(true)
    expect(evaluate('!false', {})).toBe(true)
  })
})

describe('dsl comparisons against context', () => {
  it('compares numeric context values', () => {
    expect(evalBool('status == 200', ctx)).toBe(true)
    expect(evalBool('status >= 500', ctx)).toBe(false)
    expect(evalBool('content_length > 1000 && content_length < 2000', ctx)).toBe(true)
    expect(evalBool('duration >= 300', ctx)).toBe(true)
  })
  it('unknown variables are null (falsey), never throw', () => {
    expect(evalBool('nope == 1', ctx)).toBe(false)
    expect(evalBool('!nope', ctx)).toBe(true)
  })
})

describe('dsl functions', () => {
  it('contains / icontains', () => {
    expect(evalBool('contains(body, "phpinfo()")', ctx)).toBe(true)
    expect(evalBool('contains(body, "PHPINFO")', ctx)).toBe(false)
    expect(evalBool('icontains(body, "PHPINFO")', ctx)).toBe(true)
  })
  it('len / startswith / endswith', () => {
    expect(evaluate('len("abcd")', {})).toBe(4)
    expect(evalBool('startswith(banner, "OpenSSH")', ctx)).toBe(true)
    expect(evalBool('endswith(service, "sh")', ctx)).toBe(true)
  })
  it('regex() is safe and matches', () => {
    expect(evalBool('regex("nginx/[0-9.]+", header)', ctx)).toBe(true)
    expect(evalBool('regex("[", body)', ctx)).toBe(false) // bad pattern → false, no throw
  })
  it('tolower / toupper', () => {
    expect(evaluate('tolower("ABC")', {})).toBe('abc')
    expect(evaluate('toupper("abc")', {})).toBe('ABC')
  })
})

describe('dsl safety', () => {
  it('a bad expression throws DslError from evaluate but evalBool returns false', () => {
    expect(() => evaluate('1 +', {})).toThrow(DslError)
    expect(evalBool('1 +', {})).toBe(false)
  })
  it('unknown function is an error (false under evalBool)', () => {
    expect(evalBool('system("rm")', ctx)).toBe(false)
  })
})
