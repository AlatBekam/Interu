import forge from 'node-forge'
import { app, safeStorage } from 'electron'
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

// Local certificate authority for HTTPS interception (TLS MITM).
// A root CA is generated once and persisted; per-host leaf certificates are
// minted on demand and cached. The embedded proxied browser trusts this CA
// automatically; for an external browser the user exports & trusts the CA.
//
// The CA's PRIVATE KEY is secret (it can mint certs for any host), so it is
// stored encrypted at rest with Electron safeStorage — OS-backed (DPAPI on
// Windows, Keychain on macOS), bound to the current OS user. A legacy plaintext
// key from an older build is migrated to the encrypted form on first read. The
// CA certificate itself is public and stays as plain PEM.

export const CA_COMMON_NAME = 'Interu Root CA'

/** Verify the actual signature, lifetime and exact SAN; issuer text is not trust. */
export function verifyInteruCertificate(pem: string, hostname: string): boolean {
  try {
    const leaf = forge.pki.certificateFromPem(pem)
    const ca = getCA().caCert
    if (!ca.verify(leaf)) return false
    const now = new Date()
    if (now < leaf.validity.notBefore || now > leaf.validity.notAfter) return false
    const san = leaf.getExtension('subjectAltName') as { altNames?: { type: number; value?: string; ip?: string }[] } | null
    return !!san?.altNames?.some(n => (n.type === 2 ? n.value : n.type === 7 ? n.ip : '')?.toLowerCase() === hostname.toLowerCase())
  } catch { return false }
}

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

function certPathOf(): string { return join(caDir(), 'interu-ca.crt') }
function keyPlainPathOf(): string { return join(caDir(), 'interu-ca.key') }
function keyEncPathOf(): string { return join(caDir(), 'interu-ca.key.enc') }

/** Persist the CA private key, encrypted with safeStorage when available. */
function writeCaKey(pem: string): void {
  if (safeStorage.isEncryptionAvailable()) {
    writeFileSync(keyEncPathOf(), safeStorage.encryptString(pem))
    try { rmSync(keyPlainPathOf(), { force: true }) } catch { /* ignore */ }
  } else {
    // Rare: OS keyring unavailable. Fall back to plaintext so the tool still
    // works, but this is the less-safe path.
    console.warn('[interu] safeStorage unavailable — CA key stored unencrypted')
    writeFileSync(keyPlainPathOf(), pem)
  }
}

/** Read the CA private key PEM, migrating a legacy plaintext key to encrypted. */
function readCaKey(): string | null {
  const encPath = keyEncPathOf()
  const plainPath = keyPlainPathOf()
  try {
    if (existsSync(encPath) && safeStorage.isEncryptionAvailable()) {
      return safeStorage.decryptString(readFileSync(encPath))
    }
  } catch { /* fall through to plaintext/regenerate */ }
  try {
    if (existsSync(plainPath)) {
      const pem = readFileSync(plainPath, 'utf8')
      // Migrate the old plaintext key to the encrypted store, then remove it.
      if (safeStorage.isEncryptionAvailable()) writeCaKey(pem)
      return pem
    }
  } catch { /* regenerate */ }
  return null
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
  const certPath = certPathOf()
  try {
    const keyPem = readCaKey()
    if (existsSync(certPath) && keyPem) {
      const caCert = forge.pki.certificateFromPem(readFileSync(certPath, 'utf8'))
      const caKey = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey
      bundle = { caCert, caKey, caPem: forge.pki.certificateToPem(caCert) }
      return bundle
    }
  } catch {
    /* regenerate below */
  }
  bundle = createRootCA()
  try {
    writeFileSync(certPath, bundle.caPem)
    writeCaKey(forge.pki.privateKeyToPem(bundle.caKey))
  } catch {
    /* non-fatal */
  }
  return bundle
}

/** Delete the stored CA (cert + key, encrypted and legacy) and clear caches.
 *  The next getCA() mints a fresh root CA; any browser/OS that trusted the old
 *  CA no longer trusts the new one until re-exported. */
export function deleteCA(): void {
  bundle = null
  hostCache.clear()
  for (const p of [certPathOf(), keyPlainPathOf(), keyEncPathOf()]) {
    try { rmSync(p, { force: true }) } catch { /* ignore */ }
  }
}

/** SHA-256 fingerprint of the root CA cert (hex, colon-separated), for display. */
export function caFingerprint(): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(getCA().caCert)).getBytes()
  const hex = forge.md.sha256.create().update(der).digest().toHex().toUpperCase()
  return hex.match(/.{2}/g)?.join(':') ?? hex
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
