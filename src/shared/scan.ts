// Shared network-scan types and pure helpers used by the main process (the real
// TCP scanner), the preload bridge, and the renderer. Kept framework-free so all
// three build roots can import it. No sockets are opened here — this module only
// parses targets, picks port sets, and enforces the authorization scope by IP.

export type ScanProfile = 'quick' | 'standard' | 'deep'
export type PortState = 'open' | 'closed' | 'filtered'

export interface ScanPort {
  port: number
  service: string
  state: PortState
  /** Banner / version string when grabbed (deep profile), else ''. */
  version: string
}

export interface ScanHost {
  ip: string
  status: 'up' | 'down' | 'filtered'
  openPorts: ScanPort[]
  /** ms the host took to finish, for the console. */
  tookMs: number
}

export interface ScanRequest {
  target: string
  profile: ScanProfile
  /** Per-connection timeout in ms (optional; engine has a sane default). */
  timeoutMs?: number
}

export interface ScanSummary {
  scanId: number
  target: string
  profile: ScanProfile
  totalIps: number
  totalPorts: number
  hostsUp: number
  openPortCount: number
  startedAt: string
  tookMs: number
  cancelled: boolean
}

// Progress events streamed main -> renderer during a live scan.
export type ScanEvent =
  | { type: 'start'; scanId: number; totalIps: number; totalPorts: number; message: string }
  | { type: 'log'; scanId: number; message: string }
  | { type: 'progress'; scanId: number; done: number; total: number; percent: number }
  | { type: 'host'; scanId: number; host: ScanHost }
  | { type: 'done'; scanId: number; summary: ScanSummary }
  | { type: 'error'; scanId: number; error: string }

export interface ScanResult {
  ok: boolean
  scanId?: number
  error?: string
  /** true when the target was rejected by the authorization scope gate. */
  blocked?: boolean
  summary?: ScanSummary
  hosts?: ScanHost[]
}

// ----------------------------------------------------------------- port sets

// ~100 most common TCP ports (nmap-style top list).
export const TOP_100_PORTS: number[] = [
  7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 123,
  135, 137, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
  515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027,
  1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
  3268, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
  5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
  9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

// Additional common ports layered on top of TOP_100 for the "standard" profile.
const COMMON_EXTRA: number[] = [
  1, 3, 13, 17, 19, 24, 42, 49, 69, 70, 82, 83, 84, 85, 89, 90, 99, 100, 109, 125,
  146, 163, 175, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 406, 416,
  425, 458, 464, 481, 497, 500, 512, 524, 541, 545, 555, 563, 593, 616, 617, 625, 666,
  667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787,
  800, 801, 808, 843, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 992, 999,
  1000, 1010, 1021, 1022, 1023, 1024, 1029, 1030, 1080, 1100, 1110, 1234, 1352, 1433,
  1494, 1521, 1700, 1717, 1755, 1801, 1935, 1998, 2002, 2003, 2005, 2008, 2020, 2030,
  2048, 2100, 2103, 2222, 2301, 2323, 2381, 2601, 2638, 2809, 3001, 3005, 3007, 3011,
  3017, 3031, 3052, 3071, 3211, 3260, 3300, 3301, 3333, 3389, 3517, 3527, 3546, 3551,
  3689, 3690, 3703, 3766, 3784, 3800, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
  3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001,
  4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
  4343, 4443, 4444, 4445, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5001, 5002,
  5003, 5004, 5009, 5030, 5033, 5050, 5054, 5080, 5087, 5100, 5102, 5120, 5190, 5200,
  5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5405, 5414, 5431, 5440, 5500, 5510,
  5544, 5550, 5555, 5560, 5566, 5631, 5633, 5678, 5718, 5730, 5801, 5802, 5810, 5811,
  5815, 5822, 5825, 5850, 5859, 5862, 5877, 5901, 5902, 5903, 5904, 5906, 5907, 5910,
  5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
  5998, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112,
  6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6666,
  6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969,
  7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402,
  7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921,
  7937, 7938, 7999, 8001, 8002, 8007, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8082,
  8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192,
  8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8500,
  8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8899, 8994, 9000, 9001, 9002, 9003,
  9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9101, 9102, 9103,
  9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575,
  9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944,
  9968, 9998, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082,
  10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110,
  11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
  14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
  16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
  19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
  22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356,
  27715, 28201, 30000, 30718, 30951, 31038, 31337, 32769, 32770, 32771, 32772, 32773,
  32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785,
  33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
  44442, 44443, 44501, 45100, 48080, 49158, 49159, 49160, 49161, 49163, 49165, 49167,
  49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
  50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056,
  55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078,
  63331, 64623, 64680, 65000, 65129, 65389
]

// Service names for the well-known ports we care about labelling.
export const SERVICE_NAMES: Record<number, string> = {
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  67: 'dhcp', 68: 'dhcp', 69: 'tftp', 79: 'finger', 80: 'http', 88: 'kerberos',
  110: 'pop3', 111: 'rpcbind', 119: 'nntp', 123: 'ntp', 135: 'msrpc',
  137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap',
  161: 'snmp', 162: 'snmptrap', 179: 'bgp', 389: 'ldap', 443: 'https',
  445: 'smb', 465: 'smtps', 500: 'isakmp', 514: 'syslog', 515: 'printer',
  548: 'afp', 554: 'rtsp', 587: 'submission', 631: 'ipp', 636: 'ldaps',
  873: 'rsync', 990: 'ftps', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
  1433: 'mssql', 1434: 'mssql-m', 1521: 'oracle', 1723: 'pptp', 1883: 'mqtt',
  1900: 'upnp', 2049: 'nfs', 2082: 'cpanel', 2083: 'cpanel-ssl', 2121: 'ftp',
  2375: 'docker', 2376: 'docker-ssl', 2379: 'etcd', 3000: 'http-alt',
  3128: 'squid', 3268: 'globalcat', 3306: 'mysql', 3389: 'rdp', 3690: 'svn',
  4444: 'metasploit', 5000: 'http-alt', 5060: 'sip', 5432: 'postgresql',
  5555: 'freeciv', 5601: 'kibana', 5900: 'vnc', 5984: 'couchdb', 6000: 'x11',
  6379: 'redis', 6443: 'kubernetes', 6667: 'irc', 7070: 'realserver',
  8000: 'http-alt', 8008: 'http-alt', 8009: 'ajp13', 8080: 'http-proxy',
  8081: 'http-alt', 8086: 'influxdb', 8088: 'http-alt', 8443: 'https-alt',
  8888: 'http-alt', 9000: 'http-alt', 9042: 'cassandra', 9090: 'http-alt',
  9100: 'jetdirect', 9200: 'elasticsearch', 9300: 'elasticsearch',
  9418: 'git', 10000: 'webmin', 11211: 'memcached', 15672: 'rabbitmq',
  27017: 'mongodb', 27018: 'mongodb', 50000: 'db2'
}

export function serviceName(port: number): string {
  return SERVICE_NAMES[port] || 'unknown'
}

/** Ports probed for a given profile. "deep" uses the same set as standard but
 *  enables banner/version grabbing (see profileGrabsBanner). */
export function profilePorts(profile: ScanProfile): number[] {
  if (profile === 'quick') return dedupeSort(TOP_100_PORTS)
  // standard & deep share the broader common set
  return dedupeSort([...TOP_100_PORTS, ...COMMON_EXTRA])
}

export function profileGrabsBanner(profile: ScanProfile): boolean {
  return profile === 'deep'
}

function dedupeSort(ports: number[]): number[] {
  return Array.from(new Set(ports.filter((p) => p >= 1 && p <= 65535))).sort((a, b) => a - b)
}

// ----------------------------------------------------------------- IP helpers

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

export function isIpv4(s: string): boolean {
  const m = IPV4.exec(s.trim())
  if (!m) return false
  return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255)
}

export function ipToInt(ip: string): number {
  const m = IPV4.exec(ip.trim())
  if (!m) return -1
  return ((Number(m[1]) << 24) | (Number(m[2]) << 16) | (Number(m[3]) << 8) | Number(m[4])) >>> 0
}

export function intToIp(n: number): string {
  const u = n >>> 0
  return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`
}

/** Largest expansion we allow for a single target, to keep the UI responsive. */
export const MAX_IPS = 4096
/** Hard ceiling on total connection attempts (ips × ports) per scan. Sized so a
 *  /24 fits the standard/deep profile (254 × 705).
 *  ponytail: a fully filtered run can take ~20 min at 256 sockets; add adaptive
 *  timeouts if larger targets are ever needed. */
export const MAX_ATTEMPTS = 262144

/** CIDR mask must be 1–2 digits; `Number('')` would otherwise read as /0. */
function parseMask(maskStr: string | undefined): number {
  return maskStr !== undefined && /^\d{1,2}$/.test(maskStr) ? Number(maskStr) : -1
}

export interface ExpandResult {
  ips: string[]
  error?: string
}

/**
 * Expand a target string into a concrete list of IPv4 addresses. Supports:
 *   - single IP            10.20.0.14
 *   - CIDR                 10.20.0.0/24           (network & broadcast excluded for /0../30)
 *   - dashed range         10.20.0.10-10.20.0.50  or  10.20.0.10-50
 *   - comma / space list   10.0.0.1, 10.0.0.5
 * Hostnames are not expanded here (the scanner is IP-based); callers resolve
 * DNS separately if needed.
 */
export function expandTargets(target: string): ExpandResult {
  const tokens = (target || '').split(/[\s,]+/).map((t) => t.trim()).filter(Boolean)
  if (tokens.length === 0) return { ips: [], error: 'Target kosong.' }

  const set = new Set<string>()
  for (const tok of tokens) {
    const res = expandToken(tok)
    if (res.error) return { ips: [], error: res.error }
    for (const ip of res.ips) {
      set.add(ip)
      if (set.size > MAX_IPS) return { ips: [], error: `Target terlalu besar (> ${MAX_IPS} IP). Persempit range.` }
    }
  }
  return { ips: Array.from(set).sort((a, b) => ipToInt(a) - ipToInt(b)) }
}

function expandToken(tok: string): ExpandResult {
  // CIDR
  if (tok.includes('/')) {
    const [base, maskStr] = tok.split('/')
    const mask = parseMask(maskStr)
    if (!isIpv4(base) || mask < 0 || mask > 32) {
      return { ips: [], error: `CIDR tidak valid: ${tok}` }
    }
    const baseInt = ipToInt(base)
    const hostBits = 32 - mask
    const size = hostBits >= 32 ? 0x100000000 : 1 << hostBits
    const network = (baseInt & (hostBits === 32 ? 0 : (0xffffffff << hostBits) >>> 0)) >>> 0
    if (size > MAX_IPS) return { ips: [], error: `CIDR terlalu besar: ${tok} (> ${MAX_IPS} IP).` }
    const ips: string[] = []
    // Exclude network & broadcast for subnets larger than a point-to-point link.
    const start = mask <= 30 ? 1 : 0
    const end = mask <= 30 ? size - 2 : size - 1
    for (let i = start; i <= end; i++) ips.push(intToIp((network + i) >>> 0))
    return { ips }
  }
  // dashed range
  if (tok.includes('-')) {
    const [a, b] = tok.split('-')
    if (!isIpv4(a)) return { ips: [], error: `Range tidak valid: ${tok}` }
    let endIp: string
    if (isIpv4(b)) endIp = b
    else if (/^\d{1,3}$/.test(b)) {
      const parts = a.split('.')
      parts[3] = b
      endIp = parts.join('.')
      if (!isIpv4(endIp)) return { ips: [], error: `Range tidak valid: ${tok}` }
    } else return { ips: [], error: `Range tidak valid: ${tok}` }
    const lo = ipToInt(a)
    const hi = ipToInt(endIp)
    if (hi < lo) return { ips: [], error: `Range terbalik: ${tok}` }
    if (hi - lo + 1 > MAX_IPS) return { ips: [], error: `Range terlalu besar: ${tok} (> ${MAX_IPS} IP).` }
    const ips: string[] = []
    for (let i = lo; i <= hi; i++) ips.push(intToIp(i >>> 0))
    return { ips }
  }
  // single IP
  // Normalize so the socket gets the same address the scope gate checked
  // (`010.0.0.1` would otherwise reach the resolver and may be read as octal).
  if (isIpv4(tok)) return { ips: [intToIp(ipToInt(tok))] }
  return { ips: [], error: `Bukan IP/CIDR/range yang valid: ${tok} (hostname belum didukung, pakai IP).` }
}

/**
 * Authorization gate for scanning. An IP is allowed when a scope entry either
 * equals it exactly or is a CIDR block that contains it. Hostname scope entries
 * do not authorize IP scans. Empty scope = nothing allowed.
 */
export function ipInScope(ip: string, scope: string[]): boolean {
  const target = ipToInt(ip)
  if (target < 0) return false
  return scope.some((raw) => {
    const s = raw.trim().toLowerCase().replace(/^https?:\/\//, '')
    if (!s) return false
    if (s.includes('/')) {
      const [base, maskStr] = s.split('/')
      const mask = parseMask(maskStr)
      if (!isIpv4(base) || mask < 0 || mask > 32) return false
      const baseInt = ipToInt(base)
      const maskBits = mask === 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0
      return (target & maskBits) >>> 0 === (baseInt & maskBits) >>> 0
    }
    return isIpv4(s) && ipToInt(s) === target
  })
}

/** Convenience: are ALL target IPs covered by scope? Returns the first offender. */
export function targetsInScope(ips: string[], scope: string[]): { ok: boolean; offending?: string } {
  for (const ip of ips) if (!ipInScope(ip, scope)) return { ok: false, offending: ip }
  return { ok: true }
}
