// Shared shapes for the real proxy's streamed events.
export interface ProxyLogEntry {
  id: number
  time: string
  method: string
  host: string
  path: string
  url: string
  status?: number
  length?: number
  ms?: number
  kind: 'http' | 'https-tunnel'
  dropped?: boolean
  request?: string
  response?: string
}

export interface HeldRequest {
  id: number
  raw: string
  host: string
  method: string
  path: string
}
