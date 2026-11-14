// Authenticated scanning: pure rules shared by the main process (which attaches the
// credentials) and the tests. The only credentials are the headers the operator pastes
// (an Authorization token, an API key, or a Cookie line copied from their own session).

export interface AuthConfig {
  /** Headers, one `Name: value` per line (Authorization, X-Api-Key, Cookie ...). */
  headers: string
  /** Exact scheme + hostname + port to which these credentials belong. */
  origin?: string
}

// Set by the HTTP stack itself; letting a pasted header override them would break requests or smuggle.
const FORBIDDEN = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'expect', 'upgrade'])
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

export function parseAuthHeaders(text: string): { headers: Record<string, string>; errors: string[] } {
  const headers: Record<string, string> = {}
  const errors: string[] = []
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim()
    if (!line) return
    const at = line.indexOf(':')
    if (at < 1) { errors.push(`Line ${i + 1}: expected "Name: value"`); return }
    const name = line.slice(0, at).trim()
    const value = line.slice(at + 1).trim()
    if (!TOKEN.test(name)) { errors.push(`Line ${i + 1}: invalid header name "${name}"`); return }
    if (FORBIDDEN.has(name.toLowerCase())) { errors.push(`Line ${i + 1}: ${name} cannot be set here`); return }
    if (!value) { errors.push(`Line ${i + 1}: ${name} has no value`); return }
    for (const k of Object.keys(headers)) if (k.toLowerCase() === name.toLowerCase()) delete headers[k]
    headers[name] = value
  })
  return { headers, errors }
}

/** Add credentials to a request without ever overriding a header the request already sets. */
export function mergeAuth(
  reqHeaders: Record<string, string>,
  manual: Record<string, string>
): { headers: Record<string, string>; applied: boolean } {
  const headers = { ...reqHeaders }
  const has = (n: string): boolean => Object.keys(headers).some((k) => k.toLowerCase() === n.toLowerCase())
  let applied = false
  for (const [k, v] of Object.entries(manual)) {
    if (!has(k)) { headers[k] = v; applied = true }
  }
  return { headers, applied }
}

// Words as whole path segments / words: logout, sign-out, delete, ... but not "deleted-items" or "logs".
const UNSAFE = /(^|[/_.=-])(log[-_]?out|sign[-_]?out|log[-_]?off|delete|remove|destroy|unsubscribe|deactivate|close[-_]?account|revoke|reset[-_]?password|change[-_]?password|createdb|initdb|start[-_]?over|reset|wipe|drop|truncate|rebuild|seed|apply|eval|exec|execute|run|shell|command)([/_.?&=#-]|$)/i

/**
 * Automated GETs can change state even without credentials. Scanners skip such
 * URLs; an operator can still send them deliberately in Repeater.
 */
export function isUnsafeAuthedPath(url: string): boolean {
  try {
    const u = new URL(url)
    return UNSAFE.test(u.pathname + u.search)
  } catch {
    return false
  }
}

const LOGIN = /(^|[/_.-])(log[-_]?in|sign[-_]?in|sso|oauth2?|authorize|auth)([/_.?&=#-]|$)/i

/** True when an authenticated request got an answer that means "you are no longer logged in". */
export function lostSession(status: number | undefined, rawHeaders: string | undefined): boolean {
  if (status === 401) return true
  if (status && status >= 300 && status < 400) {
    const m = /^location:\s*(.+)$/im.exec(rawHeaders || '')
    if (m) {
      const target = m[1].trim()
      try {
        const u = new URL(target, 'http://placeholder.invalid')
        return LOGIN.test(u.pathname + u.search)
      } catch {
        return LOGIN.test(target)
      }
    }
  }
  return false
}

/**
 * Evidence is shown in the UI and kept with the finding, so session secrets must not be copied into it:
 * `Set-Cookie: sid=abc` and `Authorization: Bearer abc` keep their names and flags, never the value.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(/((?:set-)?cookie:\s*)([^\r\n|]*)/gi, (_all, prefix: string, value: string) => {
      if (/set-cookie/i.test(prefix)) return prefix + value.replace(/^([^=;\s,]+=)[^;\s]+/, '$1<redacted>')
      return prefix + value.replace(/([^=;\s,]+=)[^;\s]+/g, '$1<redacted>')
    })
    .replace(/(authorization:\s*[A-Za-z]+\s+)[^\s|;]+/gi, '$1<redacted>')
    .replace(/((?:x-api-key|api-key|x-auth-token):\s*)[^\r\n|]+/gi, '$1<redacted>')
    .replace(/([?&](?:access_token|token|api_key|apikey|password|secret|session)=)[^&#\s]+/gi, '$1<redacted>')
    .replace(/\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}|glpat-[0-9A-Za-z_-]{20,}|sk_live_[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})\b/g, '<redacted>')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '<redacted>')
    .replace(/-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/g, '<redacted private key>')
    .replace(/((?:["']?)(?:password|passwd|secret|api_key|access_token|DB_PASSWORD|AWS_SECRET_ACCESS_KEY)["']?\s*[:=]\s*)["']?[^\s,;"'}]+["']?/gi, '$1<redacted>')
}

export function credentialOrigin(value: string | undefined): string | null {
  try {
    const u = new URL(value || '')
    return /^https?:$/.test(u.protocol) && !u.username && !u.password ? u.origin : null
  } catch { return null }
}
