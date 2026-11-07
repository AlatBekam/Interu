// Address handling for the Interu proxied browser. Pure and framework-free so the main
// process (navigation guard) and the tests share one definition of "navigable".
import { isIpv4 } from './scan'

export type Address = { ok: true; url: string } | { ok: false; error: string }

/** Only http and https may be loaded; every other scheme (file, javascript, data, chrome...) is refused. */
export function isNavigableUrl(url: string): boolean {
  try {
    const p = new URL(url).protocol
    return p === 'http:' || p === 'https:'
  } catch {
    return false
  }
}

// "name:" followed by something that is not a port. localhost:3000 is a host and a port; javascript:alert(1) is a scheme.
const SCHEME_LIKE = /^[a-z][a-z0-9+.-]*:(?!\d+(\/|\?|#|$))/i

/** Turn what the operator typed into a URL, or say why it cannot be loaded. */
export function normalizeAddress(input: string): Address {
  const text = input.trim()
  if (!text) return { ok: false, error: 'Enter an address' }
  if (/\s/.test(text)) return { ok: false, error: 'Address cannot contain spaces' }

  let candidate = text
  if (/^https?:\/\//i.test(text)) {
    // explicit http(s): keep
  } else if (SCHEME_LIKE.test(text)) {
    return { ok: false, error: 'Only http and https addresses can be opened' }
  } else {
    const authority = text.split(/[/?#]/, 1)[0]
    const host = authority.replace(/:\d+$/, '')
    const hasPort = authority !== host
    const plain = host === 'localhost' || host.startsWith('[') || isIpv4(host) || hasPort
    candidate = (plain ? 'http://' : 'https://') + text
  }

  try {
    const u = new URL(candidate)
    if (!isNavigableUrl(u.href) || !u.hostname) return { ok: false, error: 'Invalid address' }
    return { ok: true, url: u.href }
  } catch {
    return { ok: false, error: 'Invalid address' }
  }
}
