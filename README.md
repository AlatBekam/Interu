# Interu — Cyber Operations (Windows Desktop Application)

*by RUY Cybersecurity Team*


A standalone **Windows desktop** cybersecurity *workstation prototype*. It presents a
polished security-operations interface — a full **Burp-style Web Security Suite** plus a
dashboard, network scanner, vulnerability assessment, threat monitor, firewall policy
editor, reporting and settings. It ships with **two themes** and a **Light/Dark toggle in
the top-right**: the default **"Dark Kingdom"** (obsidian black, cold white & silver type,
midnight / royal-navy accents) and **"Silver Daylight"** (light).

> **Development stages.** This repository is the **UI stage**: every module is a UI driven
> by deterministic mock data. A later stage is intended to wire these screens to real
> engines — and any real scanning / proxying / testing must only ever run against systems
> **you are authorized to test.** The current build performs none of that.

> ⚠️ **This is a UI-only prototype.** Every security module uses **deterministic mock
> data** and local interactions. There is **no AI, no backend, no database server, no
> cloud service, and no external API.** Nothing is scanned, intercepted, tested, or
> executed against your real system or network. The interface labels all activity as
> **SIMULATED** so it can never be mistaken for genuine system activity. The app needs
> **no internet access** for its core functionality.

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

**Web Security Suite** (Burp-style, all simulated / UI-only):

Every live module is **authorization-gated**: real requests only go to hosts you add
to the **Scope** list (empty by default → nothing allowed). Legal-by-design.

| Module | Status |
|---|---|
| **Proxy** | **REAL intercepting proxy with HTTPS MITM.** Start on `127.0.0.1:<port>`; **http and decrypted https** are captured in full with intercept **Forward/Drop/edit**. **Open Browser** launches a real browser routed through the proxy that trusts the Interu CA automatically (Burp-style). **Export CA** writes the root CA for external browsers. TLS is terminated with per-host certs minted from a local CA (`src/main/ca.ts`). |
| **Repeater** | **Live** mode sends real HTTP requests to a scoped target and shows the real response (status/time/length); Simulation mode for offline demo. |
| **Intruder** | **Live** mode fires real requests per payload (payload at `§…§`), real status/length/time + outlier flagging; plus Simulation mode. |
| **Target / Site Map** | **Live content discovery** (real path fuzzing against a scoped target) building a real map; plus the simulated map. |
| **Decoder** | **Fully working, offline** URL / Base64 / Hex / HTML-entity / ASCII encode & decode, output→input chaining. |
| **Comparer** | **Real, offline** LCS line-diff between two responses. |
| **Sequencer** | **Real Shannon-entropy** analysis (quality score + per-position bars). |

> Real traffic is handled in the Electron main process (`src/main/http.ts`,
> `src/main/proxy.ts`) and gated by the operator scope (`src/shared/http.ts`).

**Operations & analysis** (kept from the original build): Dashboard, Network Scanner,
Vulnerabilities, Threat Monitor, Firewall Rules, Reports, Settings.

> Decoder, Comparer and Sequencer's maths are genuinely functional and run entirely
> offline. The networked-looking modules (Proxy, Repeater, Intruder, Target) are canned
> demo data — nothing is sent, intercepted, or tested.

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
kartikacyber/
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
   ├─ main/index.ts            # Electron main process (window, security, smoke test)
   ├─ preload/index.ts         # minimal context-isolated bridge (window.ruy)
   └─ renderer/                # the React UI
      ├─ index.html            # locked-down offline CSP
      └─ src/
         ├─ App.tsx            # HashRouter routes + theme/motion appliers
         ├─ components/        # Sidebar, TopBar, ThemeToggle, Crest, icons, UI
         ├─ pages/             # Dashboard, NetworkScanner, Vulnerabilities,
         │  │                  #   ThreatMonitor, Firewall, Reports, Settings
         │  └─ web/            # Web Security Suite: Target, Proxy, BrowserSim,
         │                     #   Repeater, Intruder, Sequencer, Decoder, Comparer
         ├─ data/mock.ts       # simulated data for the ops modules
         ├─ data/burp.ts       # simulated HTTP history / payloads / tokens
         └─ store/store.ts     # shared settings store + localStorage + reset
```

---

## 4. Scripts

| Command | What it does |
|---|---|
| `npm install` | Install dependencies (downloads the Electron binary). |
| `npm run icons` | Regenerate `build/icon.ico` / `.png` from the crest SVG. |
| `npm run dev` | Launch the app with Vite HMR (**development** — uses a dev server). |
| `npm run typecheck` | Type-check both the Node side and the web side. |
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

## 5. Build outputs (in `release/`) — don't confuse them

| Artifact | Type | What it is / how to use it |
|---|---|---|
| **`RUY-Cybersecurity-Platform-Setup-1.0.0.exe`** | **Installer** (NSIS) | Double-click to **install**. Lets you choose the folder, creates Start-menu & desktop shortcuts, and registers an uninstaller. Recommended for normal use. |
| **`RUY-Cybersecurity-Platform-Portable-1.0.0.exe`** | **Portable** | A single self-contained exe. Double-click to **run without installing** (it self-extracts to a temp dir). Good for a USB stick / no-install demo. |
| `win-unpacked/RUY Cybersecurity Platform.exe` | **Unpacked build** | The raw packaged app the installer deploys. Useful for testing the production build directly; not the artifact you distribute. |
| `*.blockmap`, `builder-debug.yml` | Build metadata | Generated by electron-builder; not something you run. |

> The **development executable** is *not* in `release/` — "development" means
> `npm run dev`, which runs Electron against the Vite dev server and is for coding only.

---

## 6. Application & window

- Product name / window title: **RUY Cybersecurity Platform**
- App identifier: `com.ruy.cybersecurity`
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

- `contextIsolation: true`, `nodeIntegration: false`; the preload exposes only a tiny
  read-only `window.ruy` (platform + runtime versions).
- A strict, **offline** Content-Security-Policy (`default-src 'self'`) blocks all remote
  scripts, styles, fonts and network connections. Fonts are the OS system stack, so no
  web fonts are fetched.
- External links (if any) open in the user's real browser, never inside the app.

---

## 9. Verification performed for this build

- `npm run typecheck` — passes clean (Node side + web side).
- `npm run build` — 47 modules transformed; `out/main`, `out/preload`, `out/renderer`
  produced.
- Smoke test on the production bundle **and** on the packaged `win-unpacked` exe — both
  print `RUY_SMOKE_RESULT: RENDER_OK`, proving the UI loads over `file://` with **no dev
  server** and no localhost dependency.
- `npm run dist` — produced the Setup installer (~79 MB) and the Portable exe (~79 MB) in
  `release/`.
- The running window was screenshotted to confirm the Dark Kingdom UI renders.

Built and verified on: Windows 11 (x64), Node 24.22.0, Electron 33.4.11,
electron-builder 25.1.8.
