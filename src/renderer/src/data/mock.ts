// =========================================================================
// Deterministic mock data for the RUY prototype.
//
// EVERYTHING here is fabricated, static demo content. Nothing in this file
// touches the real network, filesystem, or operating system. The UI labels all
// of it as SIMULATED so it can never be mistaken for genuine system activity.
// =========================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface HostResult {
  ip: string
  hostname: string
  os: string
  status: 'up' | 'filtered'
  openPorts: { port: number; service: string; state: 'open' | 'filtered'; version: string }[]
  risk: Severity
}

export interface Vulnerability {
  id: string
  cve: string
  title: string
  asset: string
  severity: Severity
  cvss: number
  category: string
  status: 'open' | 'investigating' | 'mitigated'
  discovered: string
}

export interface ThreatEvent {
  id: string
  ts: string
  level: 'info' | 'warn' | 'crit' | 'ok'
  source: string
  category: string
  message: string
}

export interface FirewallRule {
  id: string
  name: string
  direction: 'inbound' | 'outbound'
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY'
  port: string
  source: string
  action: 'allow' | 'deny'
  enabled: boolean
  builtin?: boolean
}

// --------------------------------------------------------------- scan hosts
export const MOCK_HOSTS: HostResult[] = [
  {
    ip: '10.20.0.1', hostname: 'gw-core.ruy.local', os: 'RUY-OS Router 4.2', status: 'up', risk: 'low',
    openPorts: [
      { port: 443, service: 'https', state: 'open', version: 'nginx 1.27' },
      { port: 22, service: 'ssh', state: 'open', version: 'OpenSSH 9.6' }
    ]
  },
  {
    ip: '10.20.0.14', hostname: 'vault-01.ruy.local', os: 'Linux 6.8', status: 'up', risk: 'medium',
    openPorts: [
      { port: 443, service: 'https', state: 'open', version: 'vault 1.16' },
      { port: 8200, service: 'vault', state: 'open', version: 'HashiCorp 1.16' }
    ]
  },
  {
    ip: '10.20.0.37', hostname: 'web-edge.ruy.local', os: 'Linux 6.5', status: 'up', risk: 'high',
    openPorts: [
      { port: 80, service: 'http', state: 'open', version: 'Apache 2.4.59' },
      { port: 443, service: 'https', state: 'open', version: 'Apache 2.4.59' },
      { port: 3306, service: 'mysql', state: 'open', version: 'MySQL 8.0.36' }
    ]
  },
  {
    ip: '10.20.0.52', hostname: 'ad-dc-01.ruy.local', os: 'Windows Server 2022', status: 'up', risk: 'critical',
    openPorts: [
      { port: 389, service: 'ldap', state: 'open', version: 'AD DS' },
      { port: 445, service: 'smb', state: 'open', version: 'SMBv3' },
      { port: 3389, service: 'rdp', state: 'open', version: 'RDP 10' }
    ]
  },
  {
    ip: '10.20.0.88', hostname: 'build-runner.ruy.local', os: 'Linux 6.8', status: 'up', risk: 'low',
    openPorts: [{ port: 22, service: 'ssh', state: 'open', version: 'OpenSSH 9.6' }]
  },
  {
    ip: '10.20.0.91', hostname: 'iot-cam-04.ruy.local', os: 'Embedded Linux', status: 'filtered', risk: 'medium',
    openPorts: [
      { port: 554, service: 'rtsp', state: 'open', version: 'live555' },
      { port: 80, service: 'http', state: 'filtered', version: 'lighttpd 1.4' }
    ]
  }
]

// --------------------------------------------------------------- vulnerabilities
export const MOCK_VULNS: Vulnerability[] = [
  { id: 'V-1042', cve: 'CVE-2024-3094', title: 'Backdoored compression library in build chain', asset: 'build-runner.ruy.local', severity: 'critical', cvss: 10.0, category: 'Supply Chain', status: 'investigating', discovered: '2026-10-11' },
  { id: 'V-1039', cve: 'CVE-2024-21413', title: 'Remote code execution via crafted mail link', asset: 'ad-dc-01.ruy.local', severity: 'critical', cvss: 9.8, category: 'RCE', status: 'open', discovered: '2026-10-12' },
  { id: 'V-1036', cve: 'CVE-2023-44487', title: 'HTTP/2 rapid reset denial of service', asset: 'web-edge.ruy.local', severity: 'high', cvss: 7.5, category: 'DoS', status: 'open', discovered: '2026-10-13' },
  { id: 'V-1031', cve: 'CVE-2024-6387', title: 'OpenSSH signal handler race condition', asset: 'vault-01.ruy.local', severity: 'high', cvss: 8.1, category: 'RCE', status: 'mitigated', discovered: '2026-10-09' },
  { id: 'V-1028', cve: 'CVE-2024-27198', title: 'Authentication bypass in CI server', asset: 'build-runner.ruy.local', severity: 'high', cvss: 9.8, category: 'Auth Bypass', status: 'investigating', discovered: '2026-10-14' },
  { id: 'V-1021', cve: 'CVE-2024-23897', title: 'Arbitrary file read via CLI argument parser', asset: 'web-edge.ruy.local', severity: 'medium', cvss: 6.5, category: 'Disclosure', status: 'open', discovered: '2026-10-15' },
  { id: 'V-1017', cve: 'CVE-2023-38545', title: 'Heap buffer overflow in SOCKS5 proxy', asset: 'gw-core.ruy.local', severity: 'medium', cvss: 5.9, category: 'Memory', status: 'mitigated', discovered: '2026-10-08' },
  { id: 'V-1009', cve: 'CVE-2024-4040', title: 'Server-side template injection in transfer app', asset: 'iot-cam-04.ruy.local', severity: 'medium', cvss: 6.3, category: 'Injection', status: 'open', discovered: '2026-10-16' },
  { id: 'V-1004', cve: 'CVE-2023-50164', title: 'Path traversal in file upload handler', asset: 'web-edge.ruy.local', severity: 'low', cvss: 3.7, category: 'Traversal', status: 'mitigated', discovered: '2026-10-06' }
]

// --------------------------------------------------------------- firewall rules (defaults)
export const DEFAULT_FIREWALL_RULES: FirewallRule[] = [
  { id: 'fw-1', name: 'Allow HTTPS egress', direction: 'outbound', protocol: 'TCP', port: '443', source: 'any', action: 'allow', enabled: true, builtin: true },
  { id: 'fw-2', name: 'Allow DNS', direction: 'outbound', protocol: 'UDP', port: '53', source: 'any', action: 'allow', enabled: true, builtin: true },
  { id: 'fw-3', name: 'Block inbound RDP', direction: 'inbound', protocol: 'TCP', port: '3389', source: '0.0.0.0/0', action: 'deny', enabled: true, builtin: true },
  { id: 'fw-4', name: 'Block SMB from WAN', direction: 'inbound', protocol: 'TCP', port: '445', source: '0.0.0.0/0', action: 'deny', enabled: true, builtin: true },
  { id: 'fw-5', name: 'Allow mgmt SSH (VPN)', direction: 'inbound', protocol: 'TCP', port: '22', source: '10.99.0.0/24', action: 'allow', enabled: true, builtin: true },
  { id: 'fw-6', name: 'Quarantine IoT subnet egress', direction: 'outbound', protocol: 'ANY', port: '*', source: '10.20.0.80/28', action: 'deny', enabled: false, builtin: true }
]

// --------------------------------------------------------------- threat feed generator
const SOURCES = ['10.20.0.37', '203.0.113.88', '198.51.100.23', '10.20.0.52', '192.0.2.45', '10.20.0.91']
const FEED_TEMPLATES: { level: ThreatEvent['level']; category: string; message: (s: string) => string }[] = [
  { level: 'crit', category: 'Intrusion', message: (s) => `Brute-force login burst detected from ${s} (SIMULATED)` },
  { level: 'warn', category: 'Anomaly', message: (s) => `Unusual outbound volume from ${s} flagged by heuristics` },
  { level: 'info', category: 'Discovery', message: (s) => `Port sweep observed targeting ${s}` },
  { level: 'crit', category: 'Malware', message: (s) => `Signature match: trojan beacon pattern near ${s}` },
  { level: 'ok', category: 'Mitigation', message: (s) => `Auto-rule applied, source ${s} throttled` },
  { level: 'warn', category: 'Policy', message: (s) => `TLS downgrade attempt blocked for ${s}` },
  { level: 'info', category: 'Telemetry', message: (s) => `Heartbeat received from sensor ${s}` },
  { level: 'warn', category: 'Exfil', message: (s) => `DNS tunneling pattern scored elevated for ${s}` }
]

// A small seeded PRNG keeps the "live" feed deterministic per seed so the demo
// is reproducible rather than genuinely random system data.
export function makeRng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 0xffffffff
  }
}

export function generateEvent(rng: () => number, at = new Date()): ThreatEvent {
  const tpl = FEED_TEMPLATES[Math.floor(rng() * FEED_TEMPLATES.length)]
  const src = SOURCES[Math.floor(rng() * SOURCES.length)]
  const ts = at.toLocaleTimeString('en-GB', { hour12: false })
  return {
    id: `${at.getTime()}-${Math.floor(rng() * 1e6)}`,
    ts,
    level: tpl.level,
    source: src,
    category: tpl.category,
    message: tpl.message(src)
  }
}

export function seedEvents(count: number): ThreatEvent[] {
  const rng = makeRng(20261019)
  const now = Date.now()
  const out: ThreatEvent[] = []
  for (let i = 0; i < count; i++) {
    out.push(generateEvent(rng, new Date(now - (count - i) * 7000)))
  }
  return out
}

// --------------------------------------------------------------- 24h traffic series
export function trafficSeries(): { h: string; value: number }[] {
  const rng = makeRng(424242)
  return Array.from({ length: 24 }, (_, h) => ({
    h: `${String(h).padStart(2, '0')}:00`,
    value: Math.round(40 + rng() * 60 + (h > 8 && h < 19 ? 30 : 0))
  }))
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const severityPill: Record<Severity, string> = {
  critical: 'pill-crit',
  high: 'pill-high',
  medium: 'pill-warn',
  low: 'pill-info',
  info: 'pill-muted'
}
