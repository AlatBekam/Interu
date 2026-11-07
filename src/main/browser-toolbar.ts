// The proxied browser's toolbar: one small self-contained page (loaded as a data: URL into its
// own sandboxed view). It lives outside the React renderer, so it carries its own copy of the
// Interu dark tokens (see docs/092_panduan-tampilan.md). It only sends intents through the
// preload API; the main process decides what is allowed.

export const TOOLBAR_HEIGHT = 40

const icon = (d: string): string =>
  `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`

export const TOOLBAR_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Interu Browser</title>
<style>
  :root { --bg:#12151a; --field:#0d0f12; --line:#343c48; --fg:#e6e9ee; --fg-3:#8892a1; --accent:#5b9dff; --crit:#ff6b63; --hover:#1f242c; }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: ${TOOLBAR_HEIGHT}px; background: var(--bg); color: var(--fg); overflow: hidden;
    font: 13px "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif; user-select: none; }
  body { display: flex; align-items: center; gap: 4px; padding: 0 8px; border-bottom: 1px solid var(--line); position: relative; }
  button { width: 28px; height: 28px; display: inline-flex; align-items: center; justify-content: center; flex: none;
    border: 1px solid transparent; border-radius: 3px; background: transparent; color: var(--fg); cursor: pointer; }
  button:hover:not(:disabled) { background: var(--hover); }
  button:disabled { color: var(--fg-3); opacity: .5; cursor: default; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  #addr { flex: 1; min-width: 0; height: 28px; padding: 0 10px; border: 1px solid var(--line); border-radius: 3px;
    background: var(--field); color: var(--fg); font: 12.5px "Cascadia Mono", Consolas, monospace; user-select: text; }
  #addr:focus { border-color: var(--accent); }
  #err { position: absolute; left: 100px; right: 8px; bottom: -1px; transform: translateY(100%); z-index: 2; padding: 2px 8px;
    background: var(--bg); border: 1px solid var(--crit); border-left-width: 2px; color: var(--crit); font-size: 12px; }
  #bar { position: absolute; left: 0; bottom: 0; height: 2px; width: 100%; background: var(--accent); transform-origin: left; animation: load 1.2s ease-in-out infinite; }
  @keyframes load { 0% { transform: scaleX(.05); } 60% { transform: scaleX(.8); } 100% { transform: scaleX(1); opacity: .2; } }
  @media (prefers-reduced-motion: reduce) { #bar { animation: none; transform: none; } }
  [hidden] { display: none !important; }
  .stop { display: none; } [data-loading="1"] .stop { display: block; } [data-loading="1"] .reload { display: none; }
</style></head>
<body>
  <button id="back" aria-label="Back" title="Back (Alt+Left)" disabled>${icon('<path d="M15 18l-6-6 6-6"/>')}</button>
  <button id="fwd" aria-label="Forward" title="Forward (Alt+Right)" disabled>${icon('<path d="M9 18l6-6-6-6"/>')}</button>
  <button id="reload" aria-label="Reload" title="Reload (F5)" data-loading="0">
    <span class="reload">${icon('<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/>')}</span>
    <span class="stop">${icon('<path d="M6 6l12 12M18 6L6 18"/>')}</span>
  </button>
  <input id="addr" type="text" spellcheck="false" autocomplete="off" aria-label="Address" placeholder="Enter an address, e.g. 127.0.0.1:3000" />
  <div id="err" role="alert" hidden></div>
  <div id="bar" hidden></div>
<script>
  const api = window.ruyBrowser
  const $ = (id) => document.getElementById(id)
  const addr = $('addr')
  let editing = false
  let loading = false

  function render(s) {
    loading = !!s.loading
    $('back').disabled = !s.canGoBack
    $('fwd').disabled = !s.canGoForward
    $('reload').dataset.loading = loading ? '1' : '0'
    $('reload').setAttribute('aria-label', loading ? 'Stop' : 'Reload')
    $('reload').title = loading ? 'Stop (Esc)' : 'Reload (F5)'
    $('bar').hidden = !loading
    $('err').hidden = !s.error
    $('err').textContent = s.error || ''
    if (!editing) addr.value = s.url || ''
  }
  api.onState(render)
  api.onFocusAddress(() => { addr.focus(); addr.select() })

  async function go() {
    const r = await api.go(addr.value)
    if (r && r.ok) { editing = false; api.focusContent() }
  }
  const reloadOrStop = () => (loading ? api.stop() : api.reload())

  addr.addEventListener('input', () => { editing = true })
  addr.addEventListener('focus', () => addr.select())
  addr.addEventListener('blur', () => { editing = false })
  addr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); go() }
    if (e.key === 'Escape') { editing = false; addr.blur(); api.focusContent() }
  })
  $('back').onclick = () => api.back()
  $('fwd').onclick = () => api.forward()
  $('reload').onclick = reloadOrStop
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) { e.preventDefault(); addr.focus(); addr.select() }
    else if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); api.back() }
    else if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); api.forward() }
    else if (e.key === 'F5' || (e.ctrlKey && (e.key === 'r' || e.key === 'R'))) { e.preventDefault(); api.reload() }
  })
</script></body></html>`
