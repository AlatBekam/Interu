# Interu — Cyber Operations (Windows Desktop Application)

*by RUY Cybersecurity Team*


A standalone **Windows desktop** cybersecurity *workstation prototype*. It presents a
polished security-operations interface — a full **Burp-style Web Security Suite** plus a
dashboard, network scanner, vulnerability assessment, threat monitor, firewall policy
editor, reporting and settings. It ships with **two themes** and a **Light/Dark toggle in
the top-right**: the default **"Dark Kingdom"** (obsidian black, cold white & silver type,
midnight / royal-navy accents) and **"Silver Daylight"** (light).

> **Development status (~70%).** The **Web Security Suite is real and functional**
> (intercepting HTTPS-MITM proxy, live Repeater / Intruder / Target, offline
> Decoder / Comparer / Sequencer). The **Network Scanner** runs a **real TCP connect
> scan** (scope-gated). The **Rule Engine (Detection)** is now Nuclei-grade: **408
> data-driven templates** (28 port/banner, 47 HTTP passive, 333 scope-gated active
> *oracle-confirmed* checks) with a safe **DSL matcher**, **extractors**, `{{BaseURL}}`
> **variable interpolation**, a **soft-404 baseline**, **Suspected→Confirmed correlation**,
> and full request/response **evidence** per finding — surfaced in **Vulnerabilities**.
> Each confirmed finding also carries an **Attack/Defense advisor** (patching steps +
> copy-ready config, and a verify/operator/info attack recipe with Send-to-Repeater/Intruder
> + Re-test). Request/response panes across the suite are now selectable with Copy buttons.
> Still mock / simulated UI: Dashboard, Threat Monitor, Firewall, and Reports.

> ⚠️ **Authorized use only — legal by design.** Every "Live" action is
> **authorization-gated by Scope**: real requests only reach hosts you add to the Scope
> list (empty by default → nothing allowed). Use it only against systems you own or are
> **authorized to test** (your own lab / permitted servers). A **Simulation** mode is
> provided for safe offline practice. There is **no backend, no database server, no cloud
> service, and no external API** — the app runs fully local.

---

## 1. Chosen framework & why

**Electron + React + TypeScript + Vite** (via `electron-vite`), packaged with
`electron-builder`.

The requirements prefer **Tauri 2**, *provided the environment supports the required
build tools*. This machine did **not**: it had neither the **Rust toolchain** nor the
**MSVC C++ Build Tools** that Tauri requires (only the WebView2 runtime was present).
Installing those is a multi-gigabyte, admin-elevated step. Electron, by contrast, needs
only **Node.js** — `electron` and `electron-builder` ship prebuilt binaries and generate
the Windows installer without any C/C++ compilation. Electron was therefore the
reliably-buildable choice here, which is exactly the fallback the requirements allow.
The project uses **only Electron** (no Tauri files are mixed in).

---

## 1a. Modules

**Web Security Suite** (Burp-style — real & functional, scope-gated):

Every live module is **authorization-gated**: real requests only go to hosts you add
to the **Scope** list (empty by default → nothing allowed). Legal-by-design.

| Module | Status |
|---|---|
| **Proxy** | **REAL intercepting proxy with HTTPS MITM.** Start on `127.0.0.1:<port>`; **http and decrypted https of in-scope hosts** are captured in full (out-of-scope traffic is passed through untouched; CONNECT is blind-tunnelled) with intercept **Forward/Drop/edit**. **Open Browser** launches a real browser routed through the proxy that trusts the Interu CA automatically (Burp-style). **Export CA** writes the root CA for external browsers. TLS is terminated with per-host certs minted from a local CA (`src/main/ca.ts`). |
| **Repeater** | **Live** mode sends real HTTP requests to a scoped target and shows the real response (status/time/length); Simulation mode for offline demo. |
| **Intruder** | **Live** mode fires real requests per payload (payload at `§…§`), real status/length/time + outlier flagging; plus Simulation mode. |
| **Target / Site Map** | **Live content discovery** (real path fuzzing against a scoped target) building a real map; plus the simulated map. |
| **Decoder** | **Fully working, offline** URL / Base64 / Hex / HTML-entity / ASCII encode & decode, output→input chaining. |
| **Comparer** | **Real, offline** LCS line-diff between two responses. |
| **Sequencer** | **Real Shannon-entropy** analysis (quality score + per-position bars). |

> Real traffic is handled in the Electron main process (`src/main/http.ts`,
> `src/main/proxy.ts`, `src/main/scan.ts`) and gated by the operator scope
> (`src/shared/http.ts`, `src/shared/scan.ts`).

**Operations & Detection:**

| Module | Status |
|---|---|
| **Network Scanner** | **Real TCP connect scan** (Node `net`, scope-gated): target as IP / CIDR / range / list, Quick / Standard / Deep profiles (deep grabs banners/versions), real open/closed/filtered with streamed progress and cancel; plus a Simulation mode. Results feed the Rule Engine. |
| **Rule Engine** (Detection) | **Nuclei-grade detection engine — 408 data-driven templates.** Matchers: status / word / regex / time / port / service / **dsl** (a safe, no-`eval` expression evaluator), combined and/or with negative; **extractors** pull structured data (versions, tokens, usernames); request paths support `{{BaseURL}}`-style **interpolation**. Passive over scanner results + captured proxy responses → *Suspected / Confirmed*; **333 scope-gated, read-only active HTTP probes** (e.g. `/.git/config`, `/.env`, exposures, actuators, panels) prove findings → *Confirmed*. A **soft-404 baseline** suppresses false positives, variant families **correlate** (confirmed supersedes suspected), and each finding stores full request/response **evidence**. Every confirmed finding gets an **Attack/Defense advisor**: patching steps + copy-ready config, and a `verify`/`operator`/`info` attack recipe (Send-to-Repeater/Intruder, Re-test-fix). |
| **Vulnerabilities** | Live findings from the Rule Engine (Confirmed/Suspected + evidence + CVE), with a Demo-catalog toggle. |

**Still simulated (UI / mock):** Dashboard, Threat Monitor, Firewall Rules, Reports, Settings.

> Decoder, Comparer and Sequencer run entirely offline. Proxy, Repeater, Intruder,
> Target, the Network Scanner and the Rule Engine's active checks send **real traffic**
> (gated by Scope); the scanner and passive detection also work from already-captured data.

### Theme

A **Light/Dark** switch sits in the top-right of every screen (and in Settings). The
choice is persisted locally. Dark = "Dark Kingdom" (default), Light = "Silver Daylight".

---

## 2. Prerequisites

| To run the packaged app | To build from source |
|---|---|
| 64-bit Windows 10/11 | 64-bit Windows 10/11 |
| *(WebView2 / Node.js **not** required)* | **Node.js 20+** (built & verified on Node 24.22.0 LTS) |
| | npm 10+ (bundled with Node) |
| | Internet access **once** — the first `electron-builder` run downloads NSIS packaging resources (~8 MB) |

The packaged application bundles its own Chromium + Node runtime, so **end users do not
need to install Node.js or any runtime** to launch it.

> **No MSVC / Rust / Visual Studio build tools are needed** for this Electron project.

---

## 3. Project structure

```
Interu/
├─ electron.vite.config.ts     # electron-vite: main / preload / renderer builds
├─ electron-builder.yml        # Windows packaging (NSIS installer + portable)
├─ package.json                # scripts & dependencies
├─ tsconfig*.json              # TS configs (node side + web side)
├─ build/
│  ├─ icon.svg                 # crest source
│  ├─ icon.ico                 # multi-res Windows icon (16–256px) — app + installer
│  └─ icon.png                 # 512px master
├─ scripts/
│  └─ generate-icons.mjs       # renders the crest → PNG/ICO (pure JS, no ImageMagick)
└─ src/
   ├─ main/                    # Electron main process (Node side)
   │  ├─ index.ts              #   window, security, IPC, smoke test
   │  ├─ proxy.ts              #   forward proxy + HTTPS MITM
   │  ├─ ca.ts                 #   root CA + per-host certs (for MITM)
   │  ├─ http.ts               #   real HTTP client (Live Repeater/Intruder/Target)
   │  └─ scan.ts               #   real TCP connect scanner + banner grab
   ├─ preload/                 # minimal context-isolated bridge (window.ruy)
   │  ├─ index.ts
   │  └─ index.d.ts
   ├─ shared/                  # shared by main & renderer (framework-free)
   │  ├─ http.ts               #   HTTP types + host scope gate (hostInScope)
   │  ├─ proxy.ts              #   proxy event types
   │  ├─ scan.ts               #   target parsing (IP/CIDR/range) + ipInScope
   │  ├─ rules.ts              #   Rule Engine: 408 templates, matchers, extractors,
   │  │                        #     interpolation, baseline, correlation (+ *.test.ts)
   │  ├─ dsl.ts                #   safe DSL expression evaluator (no eval) (+ *.test.ts)
   │  └─ advice.ts             #   Attack/Defense advisor per finding (+ *.test.ts)
   └─ renderer/                # the React UI
      ├─ index.html            # locked-down offline CSP
      └─ src/
         ├─ App.tsx            # HashRouter routes + theme/motion appliers
         ├─ main.tsx           # React entry
         ├─ styles/global.css  # global styling
         ├─ components/        # Sidebar, TopBar, ThemeToggle, ScopeBar, ContextMenu,
         │                     #   CopyButton, Crest, icons, ui
         ├─ pages/             # Dashboard, NetworkScanner, RuleEngine,
         │  │                  #   Vulnerabilities, ThreatMonitor, Firewall,
         │  │                  #   Reports, Settings
         │  └─ web/            # Web Security Suite: Target, Proxy, BrowserSim,
         │                     #   Repeater, Intruder, Sequencer, Decoder, Comparer
         ├─ data/mock.ts       # simulated data for the ops modules
         ├─ data/burp.ts       # simulated HTTP history / payloads / tokens
         ├─ lib/http.ts        # parse raw request, curl, sendLive
         └─ store/             # store.ts (settings+persist), transfer.ts (send-to
                               #   bus), findings.ts (Rule Engine findings store)
```

---

## 4. Scripts

| Command | What it does |
|---|---|
| `npm install` | Install dependencies (downloads the Electron binary). |
| `npm run icons` | Regenerate `build/icon.ico` / `.png` from the crest SVG. |
| `npm run dev` | Launch the app with Vite HMR (**development** — uses a dev server). |
| `npm run typecheck` | Type-check both the Node side and the web side. |
| `npm test` | Run the unit test suite (vitest) — scope, rules, DSL and advisor (56 tests). |
| `npm run build` | Production build → `out/` (main, preload, renderer). No dev server. |
| `npm run smoke` | Launch the production bundle in Electron and confirm the UI loads (prints `RUY_SMOKE_RESULT: RENDER_OK`), then exit. |
| `npm run dist` | `build` **+** package Windows installer **and** portable exe → `release/`. |
| `npm run dist:dir` | `build` **+** produce only the unpacked app folder → `release/win-unpacked/`. |

### Build & package in one go

```powershell
npm install
npm run dist
```

> **If packaging fails with** `Cannot create symbolic link … winCodeSign`: that is a known
> electron-builder issue on Windows when **Developer Mode** is off (the code-signing
> helper archive contains macOS symlinks we don't use). Fixes, cheapest first:
> 1. Set `CSC_IDENTITY_AUTO_DISCOVERY=false` and enable **Settings → For developers →
>    Developer Mode**, then rerun; **or**
> 2. Pre-extract the archive without the macOS folder (what this build did):
>    `& node_modules\7zip-bin\win\x64\7za.exe x "$env:LOCALAPPDATA\electron-builder\Cache\winCodeSign\<hash>.7z" -o"$env:LOCALAPPDATA\electron-builder\Cache\winCodeSign\winCodeSign-2.6.0" -xr!darwin -y`
>    then rerun `npm run dist`.

---

## 4a. Build from source — step by step

For someone cloning this repo for the first time. Requires only **Node.js 20+** (see
§2 — no Rust / MSVC / Visual Studio tools). Run these in **PowerShell** from the repo root.

```powershell
# 1. Get the dependencies (reads package-lock.json; also downloads the Electron binary).
#    node_modules/ is NOT in the repo — this step rebuilds it (~600 MB, normal).
npm install

# 2. (optional) Run it in dev mode to check it works — Vite HMR, closes with the window.
npm run dev

# 3. (optional) Sanity checks before packaging.
npm run typecheck     # type-check Node + web sides
npm run build         # production build → out/
npm run smoke         # launches the built bundle, expects RUY_SMOKE_RESULT: RENDER_OK

# 4. Build the distributable Windows app → release/
npm run dist          # installer + portable exe   (what you ship)
# or, just the unpacked folder (faster, for local testing):
npm run dist:dir      # → release/win-unpacked/
```

The finished artifacts land in `release/` — see §5 for which file is which. The first
`npm run dist` needs internet **once** to fetch NSIS packaging resources (~8 MB).

> If `npm run dist` fails with `Cannot create symbolic link … winCodeSign`, see the
> Developer-Mode fix under §4 ("Build & package in one go").

---

## 5. Build outputs (in `release/`) — don't confuse them

| Artifact | Type | What it is / how to use it |
|---|---|---|
| **`Interu-Setup-1.0.0.exe`** | **Installer** (NSIS) | Double-click to **install**. Lets you choose the folder, creates Start-menu & desktop shortcuts, and registers an uninstaller. Recommended for normal use. |
| **`Interu-Portable-1.0.0.exe`** | **Portable** | A single self-contained exe. Double-click to **run without installing** (it self-extracts to a temp dir). Good for a USB stick / no-install demo. |
| `win-unpacked/Interu.exe` | **Unpacked build** | The raw packaged app the installer deploys. Useful for testing the production build directly; not the artifact you distribute. |
| `*.blockmap`, `builder-debug.yml` | Build metadata | Generated by electron-builder; not something you run. |

> The **development executable** is *not* in `release/` — "development" means
> `npm run dev`, which runs Electron against the Vite dev server and is for coding only.

---

## 6. Application & window

- Product name: **Interu** — window title: **Interu — Cyber Operations**
- App identifier: `com.interu.cyberops`
- Minimum window size **1024 × 680**, opens at 1340 × 860; **maximize / minimize /
  resize / close** all work via the native window frame.
- Single-instance (a second launch focuses the existing window).
- Icon: a minimalist silver-and-midnight **crown-and-shield crest** on obsidian, applied
  to the window, taskbar, installer and shortcuts. The same crest is the in-app logo.

---

## 7. Data & persistence

- Demo records and preferences are stored **locally** in the renderer's `localStorage`
  (namespaced `ruy.v1.*`). No database server is used.
- Persisted items: scanner target/profile, vulnerability status changes, custom firewall
  rules, and settings (operator name, persistence toggle, live-feed, reduce-motion).
- **Settings → Reset demo environment** clears all stored data and restores defaults.
- The app is fully functional even with persistence turned **off** (it falls back to
  in-memory defaults), and in private/blocked-storage situations (all storage access is
  wrapped in try/catch).

---

## 8. Security posture of the app itself

- `contextIsolation: true`, `nodeIntegration: false` (note: `sandbox: false`). The
  preload exposes `window.ruy` with platform/versions plus three IPC bridges:
  `http.send`, `proxy.*` (start/stop/status/setIntercept/**setScope**/resolve/
  openBrowser/exportCA/onLog/onIntercept) and `scan.run/cancel/onProgress`. The main
  process re-checks the operator scope on every real-traffic call.
- A strict, **offline** Content-Security-Policy (`default-src 'self'`) blocks all remote
  scripts, styles, fonts and network connections. Fonts are the OS system stack, so no
  web fonts are fetched.
- External links (if any) open in the user's real browser, never inside the app.

---

## 9. Verification performed for this build

- `npm run typecheck` — passes clean (Node side + web side).
- `npm test` — **56 tests pass** (vitest): scope gate, rule matchers/extractors/baseline/
  correlation, the DSL evaluator, and the Attack/Defense advisor.
- `npm run build` — `out/main`, `out/preload`, `out/renderer` produced.
- Smoke test on the production bundle **and** on the packaged `win-unpacked` exe — both
  print `RUY_SMOKE_RESULT: RENDER_OK`, proving the UI loads over `file://` with **no dev
  server** and no localhost dependency.
- `npm run dist` — produced the Setup installer (~79 MB) and the Portable exe (~79 MB) in
  `release/`.
- The running window was screenshotted to confirm the Dark Kingdom UI renders.

Built and verified on: Windows 11 (x64), Node 24.22.0, Electron 33.4.11,
electron-builder 25.1.8.
