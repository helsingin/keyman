export type HealthStatus = 'ready' | 'not_configured' | 'error'

export interface Health {
  status: HealthStatus
  modulePath: string
  tokenLabel: string
  applicationLabel: string
  startedAt: string
  error?: string
}

export type KeyType = 'aes-256-gcm' | 'rsa-4096' | 'ecdsa-p256' | 'ml-dsa-65'

export interface KeyMetadata {
  id: string
  name: string
  type: KeyType
  latestVersion: number
  minDecryptVersion: number
  createdAt: string
  rotatedAt: string
}

export interface CertificateInfo {
  label: string
  subject: string
  commonName: string
  issuer: string
  serialNumber: string
  notBefore: string
  notAfter: string
  isCa: boolean
  dnsNames: string[] | null
  publicKeyAlgorithm: string
  publicKeyBits: number
  signatureAlgorithm: string
  keyUsages: string[] | null
  keyId?: string
}

export interface CSRResponse {
  keyId: string
  pem: string
}

export interface CertificateImportResponse {
  certificates: CertificateInfo[]
}

export interface LifecycleResponse {
  createdAesKey: string
  createdSigningKey: string
  createdCertificate: string
  oldKeyVersion: number
  newKeyVersion: number
  signatureBytes: number
  tlsSignatureBytes: number
  decryptedPlaintext: string
  operations: string[]
}

export interface TPM2Status {
  ready: boolean
  tcti: string
  toolsVersion: string
  randomHex?: string
  error?: string
}

export interface TPM2PCR {
  bank: string
  index: number
  value: string
}

export interface TPM2DemoResponse {
  tcti: string
  primaryContext: string
  signingKeyPublic: string
  signatureBytes: number
  secretBytes: number
  unsealedMatches: boolean
  pcrPolicyDigest: string
  pcrBoundSecretBytes: number
  pcrBoundUnsealedMatches: boolean
  quoteBytes: number
  quoteSignatureBytes: number
  attestationKeyName: string
  pcrs: TPM2PCR[]
  operations: string[]
}

export interface ConnectRequest {
  modulePath?: string
  tokenLabel?: string
  applicationLabel?: string
  pin: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    let message = response.statusText
    try {
      const body = (await response.json()) as { error?: string }
      message = body.error || message
    } catch {
      // Keep the HTTP status text when the response is not JSON.
    }
    throw new Error(message)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return response.json() as Promise<T>
}

export const api = {
  health: () => request<Health>('/api/health'),
  connect: (body: ConnectRequest) =>
    request<Health>('/api/session', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  disconnect: () =>
    request<Health>('/api/session', {
      method: 'DELETE',
    }),
  keys: () => request<KeyMetadata[]>('/api/keys'),
  createKey: (name: string, type: KeyType) =>
    request<KeyMetadata>('/api/keys', {
      method: 'POST',
      body: JSON.stringify({ name, type }),
    }),
  rotateKey: (keyId: string) =>
    request<KeyMetadata>(`/api/keys/${encodeURIComponent(keyId)}/rotate`, {
      method: 'POST',
    }),
  deleteKey: (keyId: string) =>
    request<void>(`/api/keys/${encodeURIComponent(keyId)}`, {
      method: 'DELETE',
    }),
  certificates: () => request<CertificateInfo[]>('/api/certificates'),
  deleteCertificate: (label: string) =>
    request<void>(`/api/certificates/${encodeURIComponent(label)}`, {
      method: 'DELETE',
    }),
  createCSR: (body: {
    keyId: string
    commonName: string
    organization: string
    dnsNames: string[]
  }) =>
    request<CSRResponse>('/api/certificates/csr', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  importCertificate: (body: {
    label: string
    pem?: string
    derBase64?: string
  }) =>
    request<CertificateImportResponse>('/api/certificates/import', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  selfSignCertificate: (body: {
    keyId: string
    label: string
    commonName: string
    organization: string
    dnsNames: string[]
    validHours: number
    isCa: boolean
  }) =>
    request<CertificateInfo>('/api/certificates/self-signed', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  runLifecycle: () =>
    request<LifecycleResponse>('/api/lifecycle/run', {
      method: 'POST',
    }),
  tpm2Health: () => request<TPM2Status>('/api/tpm2/health'),
  tpm2PCRs: () => request<TPM2PCR[]>('/api/tpm2/pcrs'),
  tpm2Random: () =>
    request<{ randomHex: string }>('/api/tpm2/random', {
      method: 'POST',
    }),
  tpm2Demo: () =>
    request<TPM2DemoResponse>('/api/tpm2/demo', {
      method: 'POST',
    }),
}
