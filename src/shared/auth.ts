// Authenticated scanning: pure rules shared by the main process (which attaches the
// credentials) and the tests. Credentials come from two places the operator controls:
// cookies of the Interu Browser session, and headers typed in by hand.

export interface AuthConfig {
  /** Attach the cookies of the Interu Browser session (matched to each request URL). */
  cookies: boolean
  /** Extra headers, one `Name: value` per line (Authorization, X-Api-Key, Cookie ...). */
  headers: string
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
  manual: Record<string, string>,
  cookieHeader: string
): { headers: Record<string, string>; applied: boolean } {
  const headers = { ...reqHeaders }
  const has = (n: string): boolean => Object.keys(headers).some((k) => k.toLowerCase() === n.toLowerCase())
  let applied = false
  for (const [k, v] of Object.entries(manual)) {
    if (!has(k)) { headers[k] = v; applied = true }
  }
  if (cookieHeader && !has('cookie')) { headers.Cookie = cookieHeader; applied = true }
  return { headers, applied }
}

// Words as whole path segments / words: logout, sign-out, delete, ... but not "deleted-items" or "logs".
const UNSAFE = /(^|[/_.=-])(log[-_]?out|sign[-_]?out|log[-_]?off|delete|remove|destroy|unsubscribe|deactivate|close[-_]?account|revoke|reset[-_]?password)([/_.?&=#-]|$)/i

/**
 * While logged in, an automated GET to /logout or /delete/... really does it. The scanners skip such
 * URLs when credentials are attached (the operator can still send them by hand in the Repeater).
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
    .replace(/((?:set-)?cookie:\s*[^=;\s,]+=)[^;\s|]+/gi, '$1<redacted>')
    .replace(/(authorization:\s*[A-Za-z]+\s+)[^\s|;]+/gi, '$1<redacted>')
}
