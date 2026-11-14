// Real TCP connect scanner for the main process. Uses Node's `net` (and `tls`
// for banner grabbing on TLS ports) to probe hosts the operator is authorized to
// test. Nothing here decides authorization — the caller (index.ts) runs the
// scope gate first; this module only opens sockets and reports what it finds.

import net from 'node:net'
import tls from 'node:tls'
import type { ScanEvent, ScanHost, ScanPort, ScanProfile, ScanSummary, PortState } from '../shared/scan'
import { serviceName } from '../shared/scan'

export interface RunParams {
  scanId: number
  target: string
  profile: ScanProfile
  ips: string[]
  ports: number[]
  grabBanner: boolean
  timeoutMs: number
  concurrency: number
}

type Emit = (event: ScanEvent) => void

// Ports we attempt a TLS handshake on when grabbing a banner.
const TLS_PORTS = new Set([443, 465, 563, 636, 853, 989, 990, 993, 995, 8443, 9443, 4443, 10443])
// Ports where sending an HTTP request is the right way to coax a banner.
const HTTP_PORTS = new Set([80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200])

// Active sockets per scan, so a cancel can tear everything down immediately.
const active = new Map<number, Set<net.Socket | tls.TLSSocket>>()
const cancelled = new Set<number>()

export function cancelScan(scanId: number): void {
  // Only running scans can be cancelled; unknown ids would otherwise leak and
  // pre-cancel a later scan that reuses the id.
  const set = active.get(scanId)
  if (!set) return
  cancelled.add(scanId)
  for (const s of set) { try { s.destroy() } catch { /* ignore */ } }
}

function track(scanId: number, s: net.Socket | tls.TLSSocket): void {
  const set = active.get(scanId)
  if (!set) return
  set.add(s)
  s.once('close', () => set.delete(s))
}

/** Probe a single TCP port. open = handshake completed, closed = RST (refused),
 *  filtered = timeout / unreachable (no clear answer). */
function probePort(scanId: number, ip: string, port: number, timeoutMs: number): Promise<PortState> {
  return new Promise((resolve) => {
    if (cancelled.has(scanId)) return resolve('filtered')
    const sock = new net.Socket()
    track(scanId, sock)
    let settled = false
    const finish = (state: PortState): void => {
      if (settled) return
      settled = true
      try { sock.destroy() } catch { /* ignore */ }
      resolve(state)
    }
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => finish('open'))
    sock.once('timeout', () => finish('filtered'))
    sock.once('close', () => finish('filtered'))
    sock.once('error', (err: NodeJS.ErrnoException) => {
      finish(err.code === 'ECONNREFUSED' ? 'closed' : 'filtered')
    })
    try { sock.connect(port, ip) } catch { finish('filtered') }
  })
}

/** Best-effort banner / version grab on an already-known-open port. Bounded by
 *  timeoutMs and a small read cap; failures just yield ''. */
function grabBanner(scanId: number, ip: string, port: number, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    if (cancelled.has(scanId)) return resolve('')
    const useTls = TLS_PORTS.has(port)
    const isHttp = HTTP_PORTS.has(port)
    let buf = ''
    let settled = false
    const finish = (val: string): void => {
      if (settled) return
      settled = true
      try { sock.destroy() } catch { /* ignore */ }
      resolve(parseBanner(val))
    }

    const onData = (d: Buffer): void => {
      buf += d.toString('latin1')
      if (buf.length > 2048) finish(buf)
    }

    const sock: net.Socket | tls.TLSSocket = useTls
      ? tls.connect({ host: ip, port, servername: isHttp ? undefined : ip, rejectUnauthorized: false })
      : new net.Socket()
    track(scanId, sock)
    sock.setTimeout(timeoutMs)
    sock.on('data', onData)
    sock.once('timeout', () => finish(buf))
    sock.once('error', () => finish(buf))
    sock.once('end', () => finish(buf))
    sock.once('close', () => finish(buf))

    const sendProbe = (): void => {
      if (isHttp) {
        try { sock.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: Interu-Scanner\r\nConnection: close\r\n\r\n`) } catch { /* ignore */ }
      }
      // Non-HTTP services (ssh/ftp/smtp/pop/imap) greet on connect; just listen.
    }

    if (useTls) {
      ;(sock as tls.TLSSocket).once('secureConnect', sendProbe)
    } else {
      ;(sock as net.Socket).once('connect', sendProbe)
      try { (sock as net.Socket).connect(port, ip) } catch { finish('') }
    }
  })
}

function parseBanner(raw: string): string {
  if (!raw) return ''
  const text = raw.replace(/\r/g, '')
  // HTTP: prefer the Server header, else the status line.
  if (/^HTTP\//i.test(text)) {
    const server = /^server:\s*(.+)$/im.exec(text)
    if (server) return server[1].trim().slice(0, 80)
    const status = text.split('\n')[0]
    return status.trim().slice(0, 80)
  }
  // Line-oriented greetings (SSH / FTP / SMTP / POP3 / IMAP …): first non-empty line.
  const first = text.split('\n').map((l) => l.trim()).find((l) => l.length > 0)
  if (first) return first.slice(0, 80)
  return ''
}

async function pool<T>(items: T[], size: number, worker: (item: T) => Promise<void>): Promise<void> {
  let idx = 0
  const runners: Promise<void>[] = []
  const next = async (): Promise<void> => {
    while (idx < items.length) {
      const i = idx++
      await worker(items[i])
    }
  }
  const n = Math.max(1, Math.min(size, items.length))
  for (let k = 0; k < n; k++) runners.push(next())
  await Promise.all(runners)
}

export async function runScan(p: RunParams, emit: Emit): Promise<{ summary: ScanSummary; hosts: ScanHost[] }> {
  const { scanId, ips, ports, grabBanner: doBanner, timeoutMs, concurrency } = p
  const total = ips.length * ports.length
  const startedAt = new Date()
  const startMs = Date.now()
  active.set(scanId, new Set())

  emit({
    type: 'start',
    scanId,
    totalIps: ips.length,
    totalPorts: ports.length,
    message: `> scanning ${ips.length} host(s) × ${ports.length} port(s) = ${total} probe(s), ${p.profile} profile`
  })

  // Per-host accumulators.
  interface Acc { open: ScanPort[]; refused: number; filtered: number; remaining: number; start: number }
  const accs = new Map<string, Acc>()
  for (const ip of ips) accs.set(ip, { open: [], refused: 0, filtered: 0, remaining: ports.length, start: Date.now() })

  const hosts: ScanHost[] = []
  let done = 0
  let lastPct = -1
  let lastEmit = 0

  // Build the full task list (IP-major so a host finishes together-ish).
  const tasks: { ip: string; port: number }[] = []
  for (const ip of ips) for (const port of ports) tasks.push({ ip, port })

  await pool(tasks, concurrency, async ({ ip, port }) => {
    if (cancelled.has(scanId)) { done++; return }
    const state = await probePort(scanId, ip, port, timeoutMs)
    const acc = accs.get(ip)!
    if (state === 'open') {
      let version = ''
      if (doBanner && !cancelled.has(scanId)) version = await grabBanner(scanId, ip, port, timeoutMs)
      acc.open.push({ port, service: serviceName(port), state: 'open', version })
      emit({ type: 'log', scanId, message: `> open   ${ip}:${port}  ${serviceName(port)}${version ? '  (' + version + ')' : ''}` })
    } else if (state === 'closed') {
      acc.refused++
    } else {
      acc.filtered++
    }
    acc.remaining--
    done++

    // Finalize the host once all its ports are accounted for.
    if (acc.remaining === 0) {
      const status: ScanHost['status'] = acc.open.length > 0 || acc.refused > 0 ? 'up' : 'filtered'
      if (status === 'up') {
        const host: ScanHost = {
          ip,
          status,
          openPorts: acc.open.sort((a, b) => a.port - b.port),
          tookMs: Date.now() - acc.start
        }
        hosts.push(host)
        emit({ type: 'host', scanId, host })
      }
    }

    // Throttled progress (at most ~5×/sec or on each whole-percent change).
    const pct = Math.round((done / total) * 100)
    const now = Date.now()
    if (pct !== lastPct && now - lastEmit > 180) {
      lastPct = pct
      lastEmit = now
      emit({ type: 'progress', scanId, done, total, percent: pct })
    }
  })

  const wasCancelled = cancelled.has(scanId)
  emit({ type: 'progress', scanId, done, total, percent: total === 0 ? 100 : Math.round((done / total) * 100) })

  const openPortCount = hosts.reduce((n, h) => n + h.openPorts.length, 0)
  const summary: ScanSummary = {
    scanId,
    target: p.target,
    profile: p.profile,
    totalIps: ips.length,
    totalPorts: ports.length,
    hostsUp: hosts.length,
    openPortCount,
    startedAt: startedAt.toISOString(),
    tookMs: Date.now() - startMs,
    cancelled: wasCancelled
  }

  emit({
    type: 'log',
    scanId,
    message: wasCancelled
      ? `> scan cancelled — ${hosts.length} host(s) up, ${openPortCount} open port(s) so far`
      : `> scan complete — ${hosts.length} host(s) up, ${openPortCount} open port(s) in ${(summary.tookMs / 1000).toFixed(1)}s`
  })
  emit({ type: 'done', scanId, summary })

  // Cleanup bookkeeping for this scan.
  cancelled.delete(scanId)
  active.delete(scanId)
  hosts.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))
  return { summary, hosts }
}
