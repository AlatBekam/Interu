// Curated product fingerprints: map what a host admits to running (scanner banner,
// response headers, HTML generator meta) onto the CISA KEV "vendor|product" keys.
// Version-blind by design: KEV has no version ranges, so a hit means "this product
// has KEV entries", never "this host is vulnerable". Keep keys exactly as they
// appear in the feed; kev.test.ts fails if a key drifts out of the snapshot.
// nginx and OpenSSH are deliberately absent: they have no KEV entries.

export interface Fingerprint {
  id: string
  label: string
  /** Exact "vendor|product" keys from the CISA feed. */
  kevProducts: string[]
  /** Matched against the scanner banner (already stripped of its "Server:" prefix). */
  banner?: RegExp
  /** Matched against response header lines (multiline). */
  header?: RegExp
  /** Matched against the response body (HTML generator meta). */
  body?: RegExp
}

export interface ProductHit {
  fingerprint: Fingerprint
  version?: string
  evidence: string
}

const GENERATOR = (name: string) => new RegExp('<meta\\s+name=["\']generator["\']\\s+content=["\']' + name + '\\s*(?:(\\d[\\d.]*))?', 'i')

export const FINGERPRINTS: Fingerprint[] = [
  {
    id: 'apache-httpd', label: 'Apache HTTP Server', kevProducts: ['Apache|HTTP Server'],
    banner: /^Apache\/(\d[\d.]*)/im,
    header: /^server:\s*Apache\/(\d[\d.]*)/im
  },
  {
    id: 'tomcat', label: 'Apache Tomcat', kevProducts: ['Apache|Tomcat'],
    banner: /^Apache-Coyote(?:\/(\d[\d.]*))?/im,
    header: /^server:\s*Apache-Coyote(?:\/(\d[\d.]*))?/im
  },
  {
    id: 'iis', label: 'Microsoft IIS', kevProducts: ['Microsoft|Internet Information Services (IIS)'],
    banner: /^Microsoft-IIS\/(\d+(?:\.\d+)?)/im,
    header: /^server:\s*Microsoft-IIS\/(\d+(?:\.\d+)?)/im
  },
  {
    id: 'php', label: 'PHP', kevProducts: ['PHP Group|PHP', 'PHP|PHP'],
    header: /^x-powered-by:\s*PHP\/(\d[\d.]*)/im
  },
  {
    id: 'proftpd', label: 'ProFTPD', kevProducts: ['ProFTPD|ProFTPD'],
    banner: /ProFTPD\s*(\d[\d.]*)/i
  },
  {
    id: 'exim', label: 'Exim', kevProducts: ['Exim|Exim'],
    banner: /Exim\s*(\d[\d.]*)/i
  },
  {
    id: 'wordpress', label: 'WordPress', kevProducts: ['WordPress|Core'],
    body: GENERATOR('WordPress')
  },
  {
    id: 'drupal', label: 'Drupal', kevProducts: ['Drupal|Core'],
    body: GENERATOR('Drupal'),
    header: /^x-generator:\s*Drupal\s*(\d+)?/im
  },
  {
    id: 'joomla', label: 'Joomla!', kevProducts: ['Joomla!|Joomla!'],
    body: GENERATOR('Joomla!')
  }
]

/** Match the curated fingerprints. One hit per product; the first source that matches wins. */
export function detectProducts(input: { banner?: string; headerText?: string; body?: string }): ProductHit[] {
  const hits: ProductHit[] = []
  for (const fp of FINGERPRINTS) {
    const sources: Array<[RegExp | undefined, string | undefined]> = [
      [fp.banner, input.banner],
      [fp.header, input.headerText],
      [fp.body, input.body]
    ]
    for (const [re, text] of sources) {
      if (!re || !text) continue
      const m = re.exec(text)
      if (!m) continue
      hits.push({ fingerprint: fp, version: m[1] || undefined, evidence: m[0].slice(0, 80) })
      break
    }
  }
  return hits
}
