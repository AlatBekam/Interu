import React, { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Stat, Meter, Note, NoteMsg } from '../../components/ui'
import ScopeBar from '../../components/ScopeBar'
import ContextMenu, { CtxState } from '../../components/ContextMenu'
import CopyButton from '../../components/CopyButton'
import { IconTarget, IconPlay, IconStop, IconGlobe, IconBug, IconCrosshair, IconSend } from '../../components/icons'
import { useSettings } from '../../store/store'
import { sendLive, rawFromParts, inScopeOrNote } from '../../lib/http'
import { setTransfer } from '../../store/transfer'
import { addFindings } from '../../store/findings'
import { pushActivity } from '../../store/activity'
import { analyzeHttpResponse } from '../../../../shared/rules'
import type { Finding } from '../../../../shared/rules'
import {
  CrawlController,
  contentTypeLabel,
  pageTitle,
  crawlSummary,
  uniqueEndpoints,
  DEFAULT_CRAWL_OPTIONS,
  type CrawlNode
} from '../../../../shared/crawl'

const hasHttp = typeof window !== 'undefined' && !!window.ruy?.http

/** Value of a single response header from the raw header block. */
function headerValue(rawHeaders: string | undefined, name: string): string | undefined {
  if (!rawHeaders) return undefined
  const re = new RegExp('^' + name + '\\s*:\\s*(.+)$', 'im')
  const m = rawHeaders.match(re)
  return m ? m[1].trim() : undefined
}

const hostOf = (url: string): string => {
  try {
    return new URL(url).host
  } catch {
    return 'target'
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
const clamp = (n: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, n))

const scPill = (s: number | string | undefined): string => {
  const d = String(s ?? '')[0]
  return d === '2' || d === '3' || d === '4' || d === '5' ? `sc s${d}` : 'sc'
}

export default function Crawler() {
  const [settings] = useSettings()
  const [target, setTarget] = useState('http://localhost:3000')
  const [depth, setDepth] = useState(DEFAULT_CRAWL_OPTIONS.maxDepth)
  const [maxPages, setMaxPages] = useState(DEFAULT_CRAWL_OPTIONS.maxPages)
  const [concurrency, setConcurrency] = useState(8)
  const [sameHostOnly, setSameHostOnly] = useState(true)
  const [includeSubdomains, setIncludeSubdomains] = useState(true)
  const [autoDetect, setAutoDetect] = useState(true)

  const [nodes, setNodes] = useState<CrawlNode[]>([])
  const [sel, setSel] = useState<CrawlNode | null>(null)
  const [progress, setProgress] = useState(0)
  const [running, setRunning] = useState(false)
  const [note, setNote] = useState<NoteMsg | null>(null)
  const [log, setLog] = useState<string[]>([])
  const [newFindings, setNewFindings] = useState(0)
  const [menu, setMenu] = useState<CtxState | null>(null)

  const stopRef = useRef(false)
  const rawMap = useRef<Map<string, string>>(new Map())
  const navigate = useNavigate()

  const addLog = (s: string): void => setLog((l) => [...l.slice(-400), s])

  const sendMenu = (e: React.MouseEvent, node: CrawlNode): void => {
    e.preventDefault()
    let origin = node.url
    let raw = ''
    try {
      const u = new URL(node.url)
      origin = u.origin
      raw = rawFromParts('GET', u.host, u.pathname + u.search)
    } catch {
      /* ignore */
    }
    setMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        { label: 'Send to Repeater', onClick: () => { setTransfer({ to: 'repeater', target: origin, raw }); navigate('/web/repeater') } },
        { label: 'Send to Intruder', onClick: () => { setTransfer({ to: 'intruder', target: origin, raw }); navigate('/web/intruder') } },
        { sep: true },
        { label: 'Copy URL', onClick: () => navigator.clipboard?.writeText(node.url) },
        { label: 'Copy request', onClick: () => navigator.clipboard?.writeText(raw) }
      ]
    })
  }

  const launch = async (): Promise<void> => {
    if (!hasHttp || !window.ruy?.http) {
      setNote({ kind: 'error', text: 'Bridge HTTP tidak tersedia (jalankan sebagai aplikasi desktop).' })
      return
    }
    const seed = /^https?:\/\//i.test(target) ? target.trim() : 'http://' + target.trim()
    let host = ''
    try {
      host = new URL(seed).hostname
    } catch {
      setNote({ kind: 'error', text: 'URL/target tidak valid.' })
      return
    }
    if (!inScopeOrNote(seed, settings.scope, 'crawler')) {
      setNote({ kind: 'block', text: `${host} belum ada di Authorized scope. Tambahkan dulu di bar di bawah.` })
      return
    }

    setNote(null)
    setRunning(true)
    setNodes([])
    setSel(null)
    setProgress(0)
    setNewFindings(0)
    rawMap.current = new Map()
    stopRef.current = false
    setLog([`> crawl start @ ${seed}  (depth ${depth}, max ${maxPages} pages, x${clamp(concurrency, 1, 16)})`])

    const controller = new CrawlController(
      [seed],
      { maxDepth: depth, maxPages, sameHostOnly, includeSubdomains },
      settings.scope
    )

    const collected: Finding[] = []
    const seenFindingKeys = new Set<string>()
    let inFlight = 0
    let blocked = false

    const refresh = (): void => {
      setNodes([...controller.nodes])
      const total = controller.done + controller.pending + inFlight
      setProgress(total === 0 ? 0 : Math.min(99, Math.round((controller.done / total) * 100)))
    }

    const worker = async (): Promise<void> => {
      while (!stopRef.current && !blocked) {
        const item = controller.take()
        if (!item) {
          if (inFlight === 0) return
          await sleep(30)
          continue
        }
        inFlight++
        try {
          const res = await sendLive(
            { method: 'GET', url: item.url, headers: { 'User-Agent': 'Interu/1.0', Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8' }, timeoutMs: 12000 },
            settings.scope
          )
          if (res.blocked) {
            blocked = true
            addLog('  ! blocked by scope — stopped')
            break
          }
          const ct = headerValue(res.rawHeaders, 'content-type')
          const type = contentTypeLabel(ct)
          // Parse text-like bodies for links/forms; skip opaque binaries.
          const parseable = ['html', 'xml', 'js', 'json', 'text'].includes(type)
          const body = res.body || ''
          const node = controller.record(item, {
            status: res.ok ? res.status ?? '-' : 'ERR',
            type,
            length: res.size,
            ms: res.timingMs,
            title: type === 'html' ? pageTitle(body) : undefined,
            html: parseable ? body : '',
            error: res.ok ? undefined : res.error
          })
          rawMap.current.set(item.url, res.raw || res.error || '(no response)')
          if (res.ok) {
            addLog(`  ${String(node.status)} ${type.padEnd(4)} d${node.depth} ${node.params.length ? '?' + node.params.length : '  '} ${item.url}`)
          }

          // Auto-detect: run passive rule templates ONLY on 2xx, non-binary
          // responses. Judging headers on redirects (3xx), 404s or error pages
          // is the main source of false positives — a redirect stub legitimately
          // lacks the headers the real page sets — so those are skipped. Passive
          // templates are confirmed + site-wide keyed per origin, so no dupes.
          const twoxx = typeof res.status === 'number' && res.status >= 200 && res.status < 300
          if (autoDetect && res.ok && twoxx && res.raw && type !== 'image' && type !== 'bin') {
            try {
              const found = analyzeHttpResponse({
                id: 0,
                time: new Date().toISOString(),
                method: 'GET',
                host: hostOf(item.url),
                path: (() => { try { const u = new URL(item.url); return u.pathname + u.search } catch { return '/' } })(),
                url: item.url,
                status: res.status,
                length: res.size,
                ms: res.timingMs,
                kind: /^https:/i.test(item.url) ? 'https-tunnel' : 'http',
                response: res.raw
              })
              for (const f of found) {
                if (!seenFindingKeys.has(f.key)) {
                  seenFindingKeys.add(f.key)
                  collected.push(f)
                }
              }
            } catch {
              /* detection error per page ignored */
            }
          }
        } catch {
          /* per-page fetch error ignored */
        } finally {
          inFlight--
        }
        refresh()
      }
    }

    const pool = clamp(concurrency, 1, 16)
    await Promise.all(Array.from({ length: pool }, () => worker()))

    // Push discovered findings into the shared store (feeds Vulnerabilities &
    // Exposure Monitor). addFindings de-dupes by key and correlates.
    const added = autoDetect ? addFindings(collected) : 0
    setNewFindings(added)
    setProgress(100)
    setRunning(false)

    const sum = crawlSummary(controller.nodes)
    addLog(`> done — ${sum.pages} pages, ${uniqueEndpoints(controller.nodes)} endpoints, ${sum.params} params, ${sum.forms} forms${autoDetect ? `, ${added} new finding(s)` : ''}${stopRef.current ? ' (stopped)' : ''}`)
    pushActivity({
      ts: new Date().toISOString(),
      level: added > 0 ? 'warn' : 'ok',
      category: 'scan',
      message: `Crawl ${host}: ${sum.pages} pages, ${sum.forms} forms${autoDetect ? `, ${added} findings` : ''}`,
      target: seed
    })
  }

  const stop = (): void => {
    stopRef.current = true
    setRunning(false)
    addLog('> stop requested')
  }

  const sum = crawlSummary(nodes)
  const selRaw = sel ? rawMap.current.get(sel.url) : undefined

  return (
    <>
      <TopBar title="Crawler · Automation" sub="Recursive in-scope site crawl + passive auto-detect" />
      <div className="content page">
        <Disclaimer>
          <strong>Automated crawler.</strong> Enter a target and launch — Interu recursively fetches in-scope pages,
          maps endpoints, parameters and forms, and (with Auto-detect on) runs the passive rule templates on every
          response so findings flow straight into <strong>Vulnerabilities</strong> and the <strong>Exposure Monitor</strong>.
          Real GET requests are sent only to hosts in your authorized scope. Use on permitted systems only.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-12 wrap">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://target-host:port"
            className="mono"
            style={{ flex: 1, minWidth: 260 }}
            onKeyDown={(e) => { if (e.key === 'Enter' && !running) void launch() }}
          />
          {!running ? (
            <button className="btn btn-primary" onClick={() => void launch()}><IconPlay />Launch Crawl</button>
          ) : (
            <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
          )}
        </div>

        <div className="flex gap-16 items-center mb-16 wrap" style={{ fontSize: 13 }}>
          <label className="flex gap-6 items-center">Depth
            <input type="number" min={0} max={6} value={depth} disabled={running}
              onChange={(e) => setDepth(clamp(parseInt(e.target.value) || 0, 0, 6))}
              className="mono" style={{ width: 56 }} />
          </label>
          <label className="flex gap-6 items-center">Max pages
            <input type="number" min={1} max={2000} value={maxPages} disabled={running}
              onChange={(e) => setMaxPages(clamp(parseInt(e.target.value) || 1, 1, 2000))}
              className="mono" style={{ width: 72 }} />
          </label>
          <label className="flex gap-6 items-center">Concurrency
            <input type="number" min={1} max={16} value={concurrency} disabled={running}
              onChange={(e) => setConcurrency(clamp(parseInt(e.target.value) || 1, 1, 16))}
              className="mono" style={{ width: 56 }} />
          </label>
          <label className="flex gap-6 items-center">
            <input type="checkbox" checked={sameHostOnly} disabled={running} onChange={(e) => setSameHostOnly(e.target.checked)} />
            Same host only
          </label>
          <label className="flex gap-6 items-center">
            <input type="checkbox" checked={includeSubdomains} disabled={running || !sameHostOnly} onChange={(e) => setIncludeSubdomains(e.target.checked)} />
            + subdomains
          </label>
          <label className="flex gap-6 items-center">
            <input type="checkbox" checked={autoDetect} disabled={running} onChange={(e) => setAutoDetect(e.target.checked)} />
            Auto-detect (passive rules)
          </label>
        </div>

        <ScopeBar />
        {note && <Note kind={note.kind}>{note.text}</Note>}

        <div className="grid grid-4 mt-16">
          <Stat label="Pages crawled" value={sum.pages} meta={running ? 'crawling…' : 'in scope'} icon={<IconGlobe />} />
          <Stat label="Endpoints" value={uniqueEndpoints(nodes)} meta={`${sum.params} params`} icon={<IconTarget />} />
          <Stat label="Forms" value={sum.forms} meta={`${sum.withParams} param'd URLs`} icon={<IconCrosshair />} />
          <Stat label="Findings" value={newFindings} meta={autoDetect ? 'auto-detected' : 'detect off'} icon={<IconBug />} />
        </div>

        {(running || nodes.length > 0) && (
          <div className="mt-16 mb-16"><Meter value={progress} tone={progress === 100 ? 'ok' : undefined} /></div>
        )}

        <div className="split">
          <Panel title="Crawl Map" sub={`${nodes.length} pages · right-click to send`}>
            {nodes.length === 0 ? (
              <div className="empty">{running ? 'Crawling…' : 'Enter a target and press Launch Crawl.'}</div>
            ) : (
              <div className="table-wrap" style={{ maxHeight: 460 }}>
                <table className="data">
                  <thead><tr><th>URL</th><th>St</th><th>Type</th><th>D</th><th>Params</th><th>Forms</th><th>Len</th></tr></thead>
                  <tbody>
                    {nodes.map((n, i) => (
                      <tr
                        key={n.url + i}
                        onClick={() => setSel(n)}
                        onContextMenu={(e) => sendMenu(e, n)}
                        className={sel?.url === n.url ? 'clickable sel' : 'clickable'} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(n) } }}
                      >
                        <td className="mono small" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={n.url}>
                          {(() => { try { const u = new URL(n.url); return u.pathname + u.search } catch { return n.url } })()}
                        </td>
                        <td><span className={scPill(n.status)}>{n.status}</span></td>
                        <td className="mono small">{n.type}</td>
                        <td className="mono small">{n.depth}</td>
                        <td className="mono small">{n.params.length || ''}</td>
                        <td className="mono small">{n.forms.length || ''}</td>
                        <td className="mono small">{n.length ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Details" sub={sel ? sel.url : 'select a page'}>
            {!sel ? (
              <div className="empty" style={{ minHeight: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                Select a crawled page to inspect its response, parameters and forms.
              </div>
            ) : (
              <div>
                {sel.title && <div className="mb-8"><strong>{sel.title}</strong></div>}
                <div className="flex gap-16 wrap mb-12" style={{ fontSize: 13 }}>
                  <span>Status <span className={scPill(sel.status)}>{sel.status}</span></span>
                  <span>Type <span className="mono">{sel.type}</span></span>
                  <span>Depth <span className="mono">{sel.depth}</span></span>
                  <span>Links <span className="mono">{sel.links}</span></span>
                  <span>{sel.ms ?? 0} ms</span>
                </div>
                {sel.params.length > 0 && (
                  <div className="mb-12">
                    <div className="code-head"><span>Query params</span></div>
                    <div className="flex gap-6 wrap mt-6">
                      {sel.params.map((p) => <span key={p} className="pill pill-info mono">{p}</span>)}
                    </div>
                  </div>
                )}
                {sel.forms.length > 0 && (
                  <div className="mb-12">
                    <div className="code-head"><span>Forms ({sel.forms.length})</span></div>
                    {sel.forms.map((f, i) => (
                      <div key={i} className="mono small mt-6 item-box">
                        <span className={`method ${f.method}`}>{f.method}</span> {f.action}
                        {f.inputs.length > 0 && <div style={{ opacity: 0.8 }}>fields: {f.inputs.map((x) => `${x.name}:${x.type}`).join(', ')}</div>}
                      </div>
                    ))}
                  </div>
                )}
                <div className="flex gap-8 mb-8 wrap">
                  <button className="btn btn-sm" onClick={() => { try { const u = new URL(sel.url); setTransfer({ to: 'repeater', target: u.origin, raw: rawFromParts('GET', u.host, u.pathname + u.search) }); navigate('/web/repeater') } catch { /* */ } }}><IconSend />Repeater</button>
                  <button className="btn btn-sm" onClick={() => { try { const u = new URL(sel.url); setTransfer({ to: 'intruder', target: u.origin, raw: rawFromParts('GET', u.host, u.pathname + u.search) }); navigate('/web/intruder') } catch { /* */ } }}><IconSend />Intruder</button>
                </div>
                {selRaw && (
                  <>
                    <div className="code-head"><span>Response</span><CopyButton text={selRaw} /></div>
                    <div className="code-pane" style={{ minHeight: 180, maxHeight: 280 }}>{selRaw.slice(0, 20000)}</div>
                  </>
                )}
              </div>
            )}
          </Panel>
        </div>

        {log.length > 0 && (
          <Panel title="Crawl Log" sub={`${log.length} lines`}>
            <div className="code-pane" style={{ minHeight: 120, maxHeight: 220 }}>{log.join('\n')}</div>
          </Panel>
        )}

        {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      </div>
    </>
  )
}
