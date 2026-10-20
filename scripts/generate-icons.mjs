// Generates the RUY application icon from a single inline SVG crest.
// Output: build/icon.svg (source), build/icon.png (512px), build/icon.ico
// (multi-resolution Windows icon used by Electron and the installer).
//
// Pure-JS pipeline — no ImageMagick / system binaries required:
//   @resvg/resvg-js  rasterizes the SVG to PNG at each size
//   png-to-ico       packs the PNGs into a single .ico
import { Resvg } from '@resvg/resvg-js'
import pngToIco from 'png-to-ico'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const buildDir = resolve(__dirname, '..', 'build')
mkdirSync(buildDir, { recursive: true })

// Obsidian rounded-square tile with the silver/midnight crown-and-shield crest.
const SVG = `<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="256" y2="256" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0d1119"/><stop offset="1" stop-color="#06070a"/>
    </linearGradient>
    <linearGradient id="shield" x1="128" y1="40" x2="128" y2="224" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#1b3a6b"/><stop offset="1" stop-color="#0a1830"/>
    </linearGradient>
    <linearGradient id="silver" x1="72" y1="48" x2="190" y2="130" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#f3f6fb"/><stop offset="1" stop-color="#8d99ad"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="240" height="240" rx="52" fill="url(#bg)" stroke="#243248" stroke-width="2"/>
  <path d="M128 40 206 66v56c0 50-34 80-78 96-44-16-78-46-78-96V66L128 40Z"
        fill="url(#shield)" stroke="url(#silver)" stroke-width="7" stroke-linejoin="round"/>
  <path d="M128 60 184 78.5V122c0 40-26 65-56 78.5C98 187 72 162 72 122V78.5L128 60Z"
        fill="none" stroke="#3765b8" stroke-opacity="0.5" stroke-width="3.5" stroke-linejoin="round"/>
  <path d="M84 126 76 86l26 20 26-32 26 32 26-20-8 40H84Z"
        fill="url(#silver)" stroke="#f3f6fb" stroke-width="3.5" stroke-linejoin="round"/>
  <rect x="82" y="134" width="92" height="10" rx="5" fill="url(#silver)"/>
  <circle cx="102" cy="104" r="6" fill="#12284f"/>
  <circle cx="128" cy="74" r="6.5" fill="#244b8f"/>
  <circle cx="154" cy="104" r="6" fill="#12284f"/>
</svg>`

writeFileSync(resolve(buildDir, 'icon.svg'), SVG)

function raster(size) {
  const r = new Resvg(SVG, { fitTo: { mode: 'width', value: size }, background: 'rgba(0,0,0,0)' })
  return Buffer.from(r.render().asPng())
}

// 512px master PNG (used by electron-builder for non-Windows / Linux fallbacks).
writeFileSync(resolve(buildDir, 'icon.png'), raster(512))

// Windows .ico: pack the standard icon resolutions.
const sizes = [16, 24, 32, 48, 64, 128, 256]
const pngs = sizes.map((s) => raster(s))
const ico = await pngToIco(pngs)
writeFileSync(resolve(buildDir, 'icon.ico'), ico)

console.log(`Icons written to ${buildDir}`)
console.log(`  icon.ico  (${sizes.join(', ')} px) ${ico.length} bytes`)
console.log('  icon.png  (512 px)')
console.log('  icon.svg  (source)')
