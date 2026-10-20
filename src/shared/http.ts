// Shared HTTP types used by the main process (real sender), the preload bridge,
// and the renderer. Kept framework-free so all three build roots can import it.

export interface HttpReq {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  timeoutMs?: number
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
}

/**
 * Authorization gate. A request is only allowed when its host is in the
 * operator-declared scope (exact host or a subdomain of a scoped host).
 * Empty scope = nothing allowed, so the tool is authorization-first by default.
 */
export function hostInScope(url: string, scope: string[]): boolean {
  let host: string
  try {
    host = new URL(url).hostname.toLowerCase()
  } catch {
    return false
  }
  return scope.some((raw) => {
    const s = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!s) return false
    return host === s || host.endsWith('.' + s)
  })
}
