import forge from 'node-forge'
import { app } from 'electron'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// Local certificate authority for HTTPS interception (TLS MITM).
// A root CA is generated once and persisted; per-host leaf certificates are
// minted on demand and cached. The embedded proxied browser trusts this CA
// automatically; for an external browser the user exports & trusts the CA.

export interface CaBundle {
  caCert: forge.pki.Certificate
  caKey: forge.pki.rsa.PrivateKey
  caPem: string
}

let bundle: CaBundle | null = null
const hostCache = new Map<string, { key: string; cert: string }>()

function caDir(): string {
  const d = join(app.getPath('userData'), 'ca')
  if (!existsSync(d)) mkdirSync(d, { recursive: true })
  return d
}

function createRootCA(): CaBundle {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000)
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 10)
  const attrs = [
    { name: 'commonName', value: 'Interu Root CA' },
    { name: 'organizationName', value: 'RUY Cybersecurity Team' },
    { shortName: 'OU', value: 'Interu Cyber Operations' }
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true }
  ])
  cert.sign(keys.privateKey, forge.md.sha256.create())
  return { caCert: cert, caKey: keys.privateKey, caPem: forge.pki.certificateToPem(cert) }
}

export function getCA(): CaBundle {
  if (bundle) return bundle
  const dir = caDir()
  const certPath = join(dir, 'interu-ca.crt')
  const keyPath = join(dir, 'interu-ca.key')
  try {
    if (existsSync(certPath) && existsSync(keyPath)) {
      const caCert = forge.pki.certificateFromPem(readFileSync(certPath, 'utf8'))
      const caKey = forge.pki.privateKeyFromPem(readFileSync(keyPath, 'utf8')) as forge.pki.rsa.PrivateKey
      bundle = { caCert, caKey, caPem: forge.pki.certificateToPem(caCert) }
      return bundle
    }
  } catch {
    /* regenerate below */
  }
  bundle = createRootCA()
  try {
    writeFileSync(certPath, bundle.caPem)
    writeFileSync(keyPath, forge.pki.privateKeyToPem(bundle.caKey))
  } catch {
    /* non-fatal */
  }
  return bundle
}

/** PEM for a leaf certificate valid for `host`, signed by the root CA. */
export function getHostCert(host: string): { key: string; cert: string } {
  const cached = hostCache.get(host)
  if (cached) return cached
  const ca = getCA()
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = Date.now().toString() + Math.floor(Math.random() * 1000)
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000)
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 2)
  cert.setSubject([{ name: 'commonName', value: host }])
  cert.setIssuer(ca.caCert.subject.attributes)
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host)
  const altName = isIp ? { type: 7, ip: host } : { type: 2, value: host }
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [altName] }
  ])
  cert.sign(ca.caKey, forge.md.sha256.create())
  const out = { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) }
  hostCache.set(host, out)
  return out
}

/** Write the root CA to a file the user can import into their OS/browser trust store. */
export function exportCA(destDir: string): string {
  const ca = getCA()
  const dest = join(destDir, 'Interu-Root-CA.crt')
  writeFileSync(dest, ca.caPem)
  return dest
}
