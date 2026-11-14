// Shared HTTP types used by the main process (real sender), the preload bridge,
// and the renderer. Kept framework-free so all three build roots can import it.

import { ipInScope, isIpv4 } from './scan'

export interface HttpReq {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  timeoutMs?: number
  /** A request the operator sends by hand (Repeater): auth is still attached, the logout/session guards are not applied. */
  manual?: boolean
}

export interface HttpRes {
  ok: boolean
  status?: number
  statusText?: string
  rawHeaders?: string
  body?: string
  raw?: string
  timingMs: number
  size: number
  error?: string
  /** true when the request was blocked by the authorization scope gate */
  blocked?: boolean
  /** true when the login session behind the attached credentials has expired; automated scans stop on it */
  authLost?: boolean
  /** Evidence hit a size limit; never use this as proof that an issue is fixed. */
  truncated?: boolean
}

/**
 * Authorization gate. A request is only allowed when its host is in the
 * operator-declared scope. IP hosts must equal a scoped IP or fall inside a
 * scoped CIDR; hostnames match a scoped hostname exactly or as a subdomain.
 * Empty scope = nothing allowed, so the tool is authorization-first by default.
 */
export function hostInScope(url: string, scope: string[]): boolean {
  let host: string
  try {
    host = new URL(url).hostname.toLowerCase()
  } catch {
    return false
  }
  if (isIpv4(host)) return ipInScope(host, scope)
  return scope.some((raw) => {
    const s = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '')
    if (!s || isIpv4(s)) return false
    return host === s || host.endsWith('.' + s)
  })
}
