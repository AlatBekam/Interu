import { contextBridge, ipcRenderer } from 'electron'
import type { HttpReq, HttpRes } from '../shared/http'
import type { AuthConfig } from '../shared/auth'
import type { ScanRequest, ScanResult, ScanEvent } from '../shared/scan'
import type { AutomationOptions, AutomationSnapshot } from '../shared/automation'

// The renderer cannot make raw cross-origin requests under the app's CSP, so
// real HTTP traffic (Repeater / live modules) goes through the main process via
// this bridge. The main process enforces the authorization scope.
const api = {
  tls: { setPolicy: (allowInvalid: boolean): Promise<{ok:boolean}> => ipcRenderer.invoke('ruy:tls:policy', allowInvalid) },
  automation: {
    discoverBrowser: (target: string, maxPages: number, autoAccount: boolean): Promise<{ urls: string[]; forms: Array<{url:string;action:string;method:string;fields:string[];kind:string}>; pages:number; note:string; accountFlow?:string }> =>
      ipcRenderer.invoke('ruy:automation:discoverBrowser', target, maxPages, autoAccount),
    start: (options: AutomationOptions): Promise<AutomationSnapshot> => ipcRenderer.invoke('ruy:automation:start', options),
    status: (): Promise<AutomationSnapshot> => ipcRenderer.invoke('ruy:automation:status'),
    cancel: (): Promise<{ok:boolean}> => ipcRenderer.invoke('ruy:automation:cancel'),
    onProgress: (callback: (state: AutomationSnapshot) => void): (()=>void) => {
      const listener = (_e: unknown, state: AutomationSnapshot): void => callback(state)
      ipcRenderer.on('ruy:automation:progress', listener)
      return () => ipcRenderer.removeListener('ruy:automation:progress', listener)
    }
  },
  platform: process.platform,
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node
  },
  http: {
    send: (req: HttpReq, scope: string[]): Promise<HttpRes> =>
      ipcRenderer.invoke('ruy:http', { req, scope })
  },
  // Pasted headers for authenticated scanning live in the main process; values never come back here.
  auth: {
    set: (c: AuthConfig): Promise<{ ok: boolean; errors: string[] }> => ipcRenderer.invoke('ruy:auth:set', c),
    get: (): Promise<AuthConfig> => ipcRenderer.invoke('ruy:auth:get'),
    refresh: (): Promise<{ ok: boolean }> => ipcRenderer.invoke('ruy:auth:refresh'),
    status: (): Promise<{ lost: boolean; headerNames: string[]; origin?: string }> => ipcRenderer.invoke('ruy:auth:status')
  },
  scan: {
    run: (req: ScanRequest, scope: string[], scanId: number): Promise<ScanResult> =>
      ipcRenderer.invoke('ruy:scan:tcp', { req, scope, scanId }),
    cancel: (scanId: number): Promise<{ ok: boolean }> =>
      ipcRenderer.invoke('ruy:scan:cancel', scanId),
    onProgress: (cb: (ev: ScanEvent) => void): (() => void) => {
      const l = (_e: unknown, d: unknown): void => cb(d as ScanEvent)
      ipcRenderer.on('ruy:scan:progress', l)
      return () => ipcRenderer.removeListener('ruy:scan:progress', l)
    }
  },
  proxy: {
    start: (port: number): Promise<{ ok: boolean; port?: number; error?: string }> =>
      ipcRenderer.invoke('ruy:proxy:start', port),
    stop: (): Promise<void> => ipcRenderer.invoke('ruy:proxy:stop'),
    status: (): Promise<{ running: boolean }> => ipcRenderer.invoke('ruy:proxy:status'),
    setIntercept: (on: boolean): Promise<{ ok: boolean }> => ipcRenderer.invoke('ruy:proxy:intercept', on),
    protectLogs: (on: boolean): Promise<{ ok: boolean }> => ipcRenderer.invoke('ruy:proxy:protectLogs', on),
    setScope: (scope: string[]): Promise<{ ok: boolean }> => ipcRenderer.invoke('ruy:proxy:scope', scope),
    resolve: (id: number, action: 'forward' | 'drop', raw?: string): Promise<{ ok: boolean }> =>
      ipcRenderer.invoke('ruy:proxy:resolve', { id, action, raw }),
    openBrowser: (url?: string): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('ruy:proxy:openBrowser', url),
    exportCA: (): Promise<{ ok: boolean; path?: string; error?: string }> =>
      ipcRenderer.invoke('ruy:proxy:exportCA'),
    removeCA: (): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('ruy:proxy:removeCA'),
    caInfo: (): Promise<{ ok: boolean; name?: string; fingerprint?: string; error?: string }> =>
      ipcRenderer.invoke('ruy:proxy:caInfo'),
    onLog: (cb: (entry: unknown) => void): (() => void) => {
      const l = (_e: unknown, d: unknown): void => cb(d)
      ipcRenderer.on('ruy:proxy:log', l)
      return () => ipcRenderer.removeListener('ruy:proxy:log', l)
    },
    onIntercept: (cb: (held: unknown) => void): (() => void) => {
      const l = (_e: unknown, d: unknown): void => cb(d)
      ipcRenderer.on('ruy:proxy:intercept', l)
      return () => ipcRenderer.removeListener('ruy:proxy:intercept', l)
    }
  }
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('ruy', api)
  } catch (error) {
    console.error('Failed to expose RUY preload API:', error)
  }
} else {
  // Fallback for the (unused) non-isolated case.
  // @ts-ignore - define on window
  window.ruy = api
}

export type RuyApi = typeof api
