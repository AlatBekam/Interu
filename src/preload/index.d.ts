import type { RuyApi } from './index'

declare global {
  interface Window {
    ruy: RuyApi
  }
}

export {}
