// Preload for the proxied browser's toolbar page only. The toolbar sends intents; the main
// process validates them (sender check, address allow-list) and performs the navigation.
import { contextBridge, ipcRenderer } from 'electron'

export interface BrowserState {
  url: string
  title: string
  loading: boolean
  canGoBack: boolean
  canGoForward: boolean
  error?: string
}

const on = <T>(channel: string, cb: (v: T) => void): (() => void) => {
  const l = (_e: Electron.IpcRendererEvent, v: T): void => cb(v)
  ipcRenderer.on(channel, l)
  return () => ipcRenderer.removeListener(channel, l)
}

contextBridge.exposeInMainWorld('ruyBrowser', {
  go: (input: string): Promise<{ ok: boolean; error?: string }> => ipcRenderer.invoke('ruy:browser:go', String(input)),
  back: (): void => ipcRenderer.send('ruy:browser:back'),
  forward: (): void => ipcRenderer.send('ruy:browser:forward'),
  reload: (): void => ipcRenderer.send('ruy:browser:reload'),
  stop: (): void => ipcRenderer.send('ruy:browser:stop'),
  focusContent: (): void => ipcRenderer.send('ruy:browser:focusContent'),
  onState: (cb: (s: BrowserState) => void) => on('ruy:browser:state', cb),
  onFocusAddress: (cb: () => void) => on('ruy:browser:focusAddress', cb)
})
