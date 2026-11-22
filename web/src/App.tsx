import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ChangeEvent, ComponentProps, FormEvent, ReactNode } from 'react'
import {
  Button,
  ButtonGroup,
  Callout,
  Divider,
  FormGroup,
  HTMLSelect,
  Icon,
  InputGroup,
  NumericInput,
  Switch,
  Tag,
  TextArea,
} from '@blueprintjs/core'
import {
  api,
  CertificateInfo,
  Health,
  KeyMetadata,
  KeyType,
  LifecycleResponse,
  TPM2DemoResponse,
  TPM2PCR,
  TPM2Status,
} from './lib/api'

type Page = 'overview' | 'create' | 'keys' | 'certs' | 'proof'
type Workspace = 'hsm' | 'tpm'
type AssetKind = 'ssh' | 'tls' | 'disk' | 'vpn' | 'code'
type BackendChoice = 'hsm' | 'tpm'

interface AssetDefinition {
  kind: AssetKind
  title: string
  shortTitle: string
  description: string
  defaultName: string
  hsmKeyType: KeyType
  hsmOutcome: string
  tpmOutcome: string
  hsmHowTo: string[]
  tpmHowTo: string[]
}

interface AssetResult {
  kind: AssetKind
  title: string
  name: string
  backend: BackendChoice
  backendLabel: string
  created: string[]
  howToUse: string[]
  facts: Array<[string, string]>
  operations?: string[]
}

interface CreatedAsset {
  id: string
  createdAt: string
  result: AssetResult
}

const keyTypes: Array<{ label: string; value: KeyType }> = [
  { label: 'Encryption key (AES-256-GCM)', value: 'aes-256-gcm' },
  { label: 'Signing key (RSA-4096)', value: 'rsa-4096' },
  { label: 'Signing key (ML-DSA-65)', value: 'ml-dsa-65' },
  { label: 'Signing key (ECDSA P-256)', value: 'ecdsa-p256' },
]

const assetDefinitions: AssetDefinition[] = [
  {
    kind: 'ssh',
    title: 'SSH login key',
    shortTitle: 'SSH',
    description: 'Sign in to servers without keeping a private key in a file.',
    defaultName: 'ssh-login',
    hsmKeyType: 'rsa-4096',
    hsmOutcome: 'Portable login key protected by the HSM token.',
    tpmOutcome: 'Machine-bound login key protected by this TPM.',
    hsmHowTo: [
      'Add the token-backed key to your SSH agent.',
      'Install the public key on the server account.',
      'SSH asks the token to sign each login challenge.',
    ],
    tpmHowTo: [
      'Use a TPM-aware SSH agent on this computer.',
      'Install the public key on the server account.',
      'SSH login works only when this TPM signs the challenge.',
    ],
  },
  {
    kind: 'tls',
    title: 'TLS/SSL certificate',
    shortTitle: 'TLS',
    description: 'Create a service certificate whose private key stays protected.',
    defaultName: 'service-tls',
    hsmKeyType: 'rsa-4096',
    hsmOutcome: 'Certificate issued from an HSM-resident private key.',
    tpmOutcome: 'Service identity tied to the local trusted platform.',
    hsmHowTo: [
      'Install the certificate in the service.',
      'Configure the service to use the token-backed private key.',
      'TLS handshakes ask the HSM token to sign.',
    ],
    tpmHowTo: [
      'Use a TPM-aware TLS provider on this computer.',
      'Install the certificate in the service.',
      'TLS handshakes are signed by the TPM-bound key.',
    ],
  },
  {
    kind: 'disk',
    title: 'Disk unlock key',
    shortTitle: 'Disk',
    description: 'Protect a disk unlock secret so it is not stored in plain text.',
    defaultName: 'disk-unlock',
    hsmKeyType: 'aes-256-gcm',
    hsmOutcome: 'Data key stored in the HSM token for unlock workflows.',
    tpmOutcome: 'Secret sealed to this machine and current boot measurements.',
    hsmHowTo: [
      'Use the HSM key as the wrapping key for the disk unlock secret.',
      'Require the token and PIN during the unlock workflow.',
      'Rotate the wrapping key without copying it out of the token.',
    ],
    tpmHowTo: [
      'Bind the unlock secret to trusted boot measurements.',
      'Release it only when the measured boot state still matches.',
      'Review the attestation quote when proving machine state.',
    ],
  },
  {
    kind: 'vpn',
    title: 'VPN identity',
    shortTitle: 'VPN',
    description: 'Create a protected identity for machine or user VPN access.',
    defaultName: 'vpn-identity',
    hsmKeyType: 'rsa-4096',
    hsmOutcome: 'VPN certificate backed by a portable HSM token.',
    tpmOutcome: 'VPN identity bound to this computer.',
    hsmHowTo: [
      'Install the certificate in the VPN profile.',
      'Point the VPN client at the token-backed key.',
      'The token signs the authentication challenge.',
    ],
    tpmHowTo: [
      'Install the certificate in the VPN profile.',
      'Use a TPM-aware provider for the private-key operation.',
      'The identity works only from this machine.',
    ],
  },
  {
    kind: 'code',
    title: 'Code signing key',
    shortTitle: 'Code',
    description: 'Sign releases while keeping the private signing key protected.',
    defaultName: 'code-signing',
    hsmKeyType: 'rsa-4096',
    hsmOutcome: 'Signing key stored in the HSM token for release workflows.',
    tpmOutcome: 'Local signing key bound to this machine.',
    hsmHowTo: [
      'Connect the signing tool to the token-backed key.',
      'Require approval before each release signature.',
      'Keep the signing key non-exportable.',
    ],
    tpmHowTo: [
      'Use a TPM-aware signing provider on this computer.',
      'Sign only from this trusted machine.',
      'Use attestation evidence when proving machine state.',
    ],
  },
]

export function App() {
  const [page, setPage] = useState<Page>('overview')
  const [workspace, setWorkspace] = useState<Workspace>('hsm')
  const [health, setHealth] = useState<Health | null>(null)
  const [keys, setKeys] = useState<KeyMetadata[]>([])
  const [certificates, setCertificates] = useState<CertificateInfo[]>([])
  const [lifecycle, setLifecycle] = useState<LifecycleResponse | null>(null)
  const [tpm2Status, setTPM2Status] = useState<TPM2Status | null>(null)
  const [tpm2PCRs, setTPM2PCRs] = useState<TPM2PCR[]>([])
  const [tpm2Demo, setTPM2Demo] = useState<TPM2DemoResponse | null>(null)
  const [tpm2Random, setTPM2Random] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [modulePath, setModulePath] = useState('')
  const [tokenLabel, setTokenLabel] = useState('KEYMAN')
  const [applicationLabel, setApplicationLabel] = useState('keyman')
  const [pin, setPin] = useState('')

  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyType, setNewKeyType] = useState<KeyType>('rsa-4096')

  const [certKeyId, setCertKeyId] = useState('')
  const [certLabel, setCertLabel] = useState('')
  const [commonName, setCommonName] = useState('')
  const [organization, setOrganization] = useState('Example')
  const [dnsNames, setDNSNames] = useState('')
  const [validHours, setValidHours] = useState(24)
  const [isCA, setIsCA] = useState(false)
  const [csrKeyId, setCSRKeyId] = useState('')
  const [csrCommonName, setCSRCommonName] = useState('')
  const [csrOrganization, setCSROrganization] = useState('Example')
  const [csrDNSNames, setCSRDNSNames] = useState('')
  const [csrPEM, setCSRPEM] = useState('')
  const [importLabel, setImportLabel] = useState('')
  const [importPEM, setImportPEM] = useState('')
  const [importDERBase64, setImportDERBase64] = useState('')
  const [importFileName, setImportFileName] = useState('')
  const [assetKind, setAssetKind] = useState<AssetKind>('ssh')
  const [assetBackend, setAssetBackend] = useState<BackendChoice>('tpm')
  const [assetName, setAssetName] = useState('my-login-key')
  const [assetResult, setAssetResult] = useState<AssetResult | null>(null)
  const [createdAssets, setCreatedAssets] = useState<CreatedAsset[]>([])

  const hsmReady = health?.status === 'ready'
  const tpmReady = tpm2Status?.ready === true
  const selectedAsset = useMemo(
    () => assetDefinitions.find((asset) => asset.kind === assetKind) || assetDefinitions[0],
    [assetKind],
  )
  const tpmSessionKeys = useMemo(
    () => createdAssets.filter((asset) => asset.result.backend === 'tpm'),
    [createdAssets],
  )
  const totalKeyCount = keys.length + tpmSessionKeys.length
  const totalCertificateCount = certificates.length
  const asymmetricKeys = useMemo(
    () => keys.filter((key) => key.type === 'rsa-4096' || key.type === 'ecdsa-p256'),
    [keys],
  )

  const loadInventory = useCallback(async () => {
    const [nextKeys, nextCertificates] = await Promise.all([api.keys(), api.certificates()])
    setKeys(nextKeys)
    setCertificates(nextCertificates)
  }, [])

  const loadTPM2 = useCallback(async () => {
    const nextStatus = await api.tpm2Health()
    setTPM2Status(nextStatus)
    setTPM2Random(nextStatus.randomHex || '')
    if (nextStatus.ready) {
      setTPM2PCRs(await api.tpm2PCRs())
    } else {
      setTPM2PCRs([])
    }
  }, [])

  const refresh = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const nextHealth = await api.health()
      setHealth(nextHealth)
      if (nextHealth.modulePath) setModulePath(nextHealth.modulePath)
      if (nextHealth.tokenLabel) setTokenLabel(nextHealth.tokenLabel)
      if (nextHealth.applicationLabel) setApplicationLabel(nextHealth.applicationLabel)
      if (nextHealth.status === 'ready') {
        await loadInventory()
      } else {
        setKeys([])
        setCertificates([])
      }
      await loadTPM2()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }, [loadInventory, loadTPM2])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    if (!certKeyId && asymmetricKeys.length > 0) {
      setCertKeyId(asymmetricKeys[0].id)
    }
  }, [asymmetricKeys, certKeyId])

  useEffect(() => {
    if (!csrKeyId && asymmetricKeys.length > 0) {
      setCSRKeyId(asymmetricKeys[0].id)
    }
  }, [asymmetricKeys, csrKeyId])

  async function connect(event: FormEvent) {
    event.preventDefault()
    await runAction(async () => {
      const nextHealth = await api.connect({
        modulePath,
        tokenLabel,
        applicationLabel,
        pin,
      })
      setHealth(nextHealth)
      setPin('')
      await loadInventory()
      setNotice('Token unlocked.')
    })
  }

  async function disconnect() {
    await runAction(async () => {
      const nextHealth = await api.disconnect()
      setHealth(nextHealth)
      setKeys([])
      setCertificates([])
      setLifecycle(null)
      setNotice('Token locked.')
    })
  }

  async function createKey(event: FormEvent) {
    event.preventDefault()
    await runAction(async () => {
      await api.createKey(newKeyName.trim(), newKeyType)
      setNewKeyName('')
      await loadInventory()
      setNotice('Key created.')
    })
  }

  async function rotateKey(keyId: string) {
    await runAction(async () => {
      await api.rotateKey(keyId)
      await loadInventory()
      setNotice('Key rotated.')
    })
  }

  async function deleteKey(keyId: string) {
    if (!window.confirm(`Delete key "${keyId}" from the HSM token?`)) {
      return
    }
    await runAction(async () => {
      await api.deleteKey(keyId)
      await loadInventory()
      setNotice('Key deleted.')
    })
  }

  async function deleteCertificate(label: string) {
    if (!window.confirm(`Delete certificate "${label}" from the HSM token?`)) {
      return
    }
    await runAction(async () => {
      await api.deleteCertificate(label)
      await loadInventory()
      setNotice('Certificate deleted.')
    })
  }

  async function issueCertificate(event: FormEvent) {
    event.preventDefault()
    await runAction(async () => {
      await api.selfSignCertificate({
        keyId: certKeyId,
        label: certLabel.trim(),
        commonName: commonName.trim(),
        organization: organization.trim(),
        dnsNames: dnsNames.split(',').map((item) => item.trim()).filter(Boolean),
        validHours,
        isCa: isCA,
      })
      setCertLabel('')
      setCommonName('')
      setDNSNames('')
      await loadInventory()
      setNotice('Certificate issued.')
    })
  }

  async function createCSR(event: FormEvent) {
    event.preventDefault()
    await runAction(async () => {
      const result = await api.createCSR({
        keyId: csrKeyId,
        commonName: csrCommonName.trim(),
        organization: csrOrganization.trim(),
        dnsNames: csrDNSNames.split(',').map((item) => item.trim()).filter(Boolean),
      })
      setCSRPEM(result.pem)
      setNotice('CSR created.')
    })
  }

  async function copyCSR() {
    if (!csrPEM) {
      return
    }
    await navigator.clipboard.writeText(csrPEM)
    setNotice('CSR copied.')
  }

  async function importCertificate(event: FormEvent) {
    event.preventDefault()
    await runAction(async () => {
      await api.importCertificate({
        label: importLabel.trim(),
        pem: importPEM.trim() || undefined,
        derBase64: importPEM.trim() ? undefined : importDERBase64,
      })
      setImportLabel('')
      setImportPEM('')
      setImportDERBase64('')
      setImportFileName('')
      await loadInventory()
      setNotice('Certificate imported.')
    })
  }

  async function handleImportFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0]
    if (!file) {
      return
    }
    const data = new Uint8Array(await file.arrayBuffer())
    const text = new TextDecoder().decode(data)
    if (!importLabel.trim()) {
      setImportLabel(file.name.replace(/\.[^.]+$/, ''))
    }
    setImportFileName(file.name)
    if (text.includes('-----BEGIN CERTIFICATE-----')) {
      setImportPEM(text)
      setImportDERBase64('')
    } else {
      setImportPEM('')
      setImportDERBase64(bytesToBase64(data))
    }
    event.currentTarget.value = ''
  }

  async function runLifecycle() {
    await runAction(async () => {
      const result = await api.runLifecycle()
      setLifecycle(result)
      await loadInventory()
      setNotice('Key check completed.')
    })
  }

  async function refreshTPM2() {
    await runAction(async () => {
      await loadTPM2()
      setNotice('Trust status refreshed.')
    })
  }

  async function getTPM2Random() {
    await runAction(async () => {
      const result = await api.tpm2Random()
      setTPM2Random(result.randomHex)
      setNotice('Random value updated.')
    })
  }

  async function runTPM2Demo() {
    await runAction(async () => {
      const result = await api.tpm2Demo()
      setTPM2Demo(result)
      setTPM2PCRs(result.pcrs)
      await loadTPM2()
      setNotice('Trust check completed.')
    })
  }

  async function createProtectedAsset() {
    await runAction(async () => {
      const asset = selectedAsset
      const baseName = cleanAssetName(assetName || asset.defaultName)
      const objectName = `${baseName}-${Date.now().toString(36).slice(-5)}`

      if (assetBackend === 'hsm') {
        if (!hsmReady) {
          setNotice('Unlock the HSM token in the header, then create the protected key.')
          return
        }

        const created: string[] = []
        const facts: Array<[string, string]> = [
          ['Key', asset.title],
          ['Protection', 'HSM token'],
          ['Use case', asset.hsmOutcome],
        ]
        const key = await api.createKey(objectName, asset.hsmKeyType)
        created.push(`${friendlyKeyType(key.type)} created in the HSM token`)
        facts.push(['Key', friendlyKeyType(key.type)])

        if (asset.kind === 'tls' || asset.kind === 'vpn') {
          const certificate = await api.selfSignCertificate({
            keyId: key.id,
            label: `${objectName}-certificate`,
            commonName: `${baseName}.local`,
            organization: 'KeyMan',
            dnsNames: [`${baseName}.local`],
            validHours: 24,
            isCa: false,
          })
          created.push('Certificate issued from the protected key')
          facts.push(['Certificate', certificate.subject])
        }

        await loadInventory()
        setWorkspace('hsm')
        const nextResult: AssetResult = {
          kind: asset.kind,
          title: asset.title,
          name: baseName,
          backend: 'hsm',
          backendLabel: 'HSM token',
          created,
          howToUse: asset.hsmHowTo,
          facts,
        }
        setAssetResult(nextResult)
        rememberAsset(nextResult)
        setNotice(`${asset.shortTitle} key created in the HSM token.`)
        return
      }

      if (!tpmReady) {
        setWorkspace('tpm')
        setNotice('The TPM 2.0 device is not ready yet.')
        return
      }

      const result = await api.tpm2Demo()
      setTPM2Demo(result)
      setTPM2PCRs(result.pcrs)
      await loadTPM2()
      setWorkspace('tpm')
      const nextResult: AssetResult = {
        kind: asset.kind,
        title: asset.title,
        name: baseName,
        backend: 'tpm',
        backendLabel: 'TPM 2.0 device',
        created: tpmCreatedItems(asset, result),
        howToUse: asset.tpmHowTo,
        facts: [
          ['Key', asset.title],
          ['Protection', 'TPM 2.0 device'],
          ['Use case', asset.tpmOutcome],
          ['Measured state', `${result.pcrs.length} PCR values`],
          ['PCR-bound secret', result.pcrBoundUnsealedMatches ? 'released safely' : 'not released'],
          ['Attestation quote', `${result.quoteBytes} bytes`],
        ],
        operations: result.operations,
      }
      setAssetResult(nextResult)
      rememberAsset(nextResult)
      setNotice(`${asset.shortTitle} key created with the TPM 2.0 device.`)
    })
  }

  function rememberAsset(result: AssetResult) {
    setCreatedAssets((current) => [
      {
        id: `${result.backend}-${Date.now().toString(36)}-${current.length}`,
        createdAt: new Date().toISOString(),
        result,
      },
      ...current,
    ])
  }

  async function runAction(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      await action()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  function changePage(nextPage: Page) {
    setPage(nextPage)
    setError(null)
    setNotice(null)
  }

  return (
    <div className="hsm-shell">
      <header className="hsm-topbar">
        <div className="hsm-identity">
          <div className="hsm-title-line">
            <span className="eyebrow">Key and Certificate Management</span>
            <h1>KeyMan</h1>
          </div>
        </div>
        {hsmReady ? (
          <div className="hsm-actions">
            <Button icon="log-out" loading={busy} onClick={() => void disconnect()}>
              Lock HSM Token
            </Button>
          </div>
        ) : (
          <form className="hsm-actions unlock-actions" onSubmit={connect}>
            <InputGroup
              aria-label="HSM PIN"
              placeholder="HSM PIN"
              type="password"
              value={pin}
              onChange={(event) => setPin(event.currentTarget.value)}
            />
            <Button icon="lock" intent="primary" loading={busy} type="submit" disabled={!pin.trim()}>
              Unlock HSM Token
            </Button>
          </form>
        )}
        <div className="hsm-telemetry">
          <StatusTag ready={hsmReady} readyLabel="Token unlocked" waitingLabel="Token locked" />
          <StatusTag ready={tpmReady} readyLabel="Trust ready" waitingLabel="Trust offline" />
          <Tag minimal>{totalKeyCount} keys</Tag>
          <Tag minimal>{totalCertificateCount} certificates</Tag>
        </div>
      </header>

      <main className="hsm-main">
        <PrimaryNav page={page} setPage={changePage} />

        {error ? (
          <Callout intent="danger" icon="warning-sign" title="Operation failed">
            {error}
          </Callout>
        ) : null}
        {notice ? (
          <Callout intent="success" icon="tick-circle" title="Done">
            {notice}
          </Callout>
        ) : null}

        {page === 'overview' ? (
          <OverviewPage />
        ) : null}

        {page === 'create' ? (
          <AssetWizard
            busy={busy}
            assetKind={assetKind}
            backend={assetBackend}
            assetName={assetName}
            result={assetResult}
            hsmReady={hsmReady}
            tpmReady={tpmReady}
            setAssetKind={(value) => {
              setAssetKind(value)
              const nextAsset = assetDefinitions.find((asset) => asset.kind === value)
              if (nextAsset && (!assetName.trim() || assetName === selectedAsset.defaultName || assetName === 'my-login-key')) {
                setAssetName(nextAsset.defaultName)
              }
            }}
            setBackend={setAssetBackend}
            setAssetName={setAssetName}
            createAsset={createProtectedAsset}
          />
        ) : null}

        {page === 'keys' ? (
          <MyKeysPage
            tpmKeys={tpmSessionKeys}
            keys={keys}
            busy={busy}
            rotateKey={rotateKey}
            deleteKey={deleteKey}
          />
        ) : null}

        {page === 'certs' ? (
          <MyCertificatesPage
            certificates={certificates}
            asymmetricKeys={asymmetricKeys}
            busy={busy}
            csrKeyId={csrKeyId}
            csrCommonName={csrCommonName}
            csrOrganization={csrOrganization}
            csrDNSNames={csrDNSNames}
            csrPEM={csrPEM}
            importLabel={importLabel}
            importPEM={importPEM}
            importDERBase64={importDERBase64}
            importFileName={importFileName}
            setCSRKeyId={setCSRKeyId}
            setCSRCommonName={setCSRCommonName}
            setCSROrganization={setCSROrganization}
            setCSRDNSNames={setCSRDNSNames}
            setImportLabel={setImportLabel}
            setImportPEM={(value) => {
              setImportPEM(value)
              if (value.trim()) setImportDERBase64('')
            }}
            createCSR={createCSR}
            copyCSR={copyCSR}
            importCertificate={importCertificate}
            handleImportFile={handleImportFile}
            deleteCertificate={deleteCertificate}
          />
        ) : null}

        {page === 'proof' ? (
          <ProofPage
            workspace={workspace}
            setWorkspace={setWorkspace}
            busy={busy}
            hsmReady={hsmReady}
            tpmReady={tpmReady}
            health={health}
            keys={keys}
            certificates={certificates}
            asymmetricKeys={asymmetricKeys}
            lifecycle={lifecycle}
            pin={pin}
            newKeyName={newKeyName}
            newKeyType={newKeyType}
            certKeyId={certKeyId}
            certLabel={certLabel}
            commonName={commonName}
            organization={organization}
            dnsNames={dnsNames}
            validHours={validHours}
            isCA={isCA}
            setPin={setPin}
            setNewKeyName={setNewKeyName}
            setNewKeyType={setNewKeyType}
            setCertKeyId={setCertKeyId}
            setCertLabel={setCertLabel}
            setCommonName={setCommonName}
            setOrganization={setOrganization}
            setDNSNames={setDNSNames}
            setValidHours={setValidHours}
            setIsCA={setIsCA}
            connect={connect}
            disconnect={disconnect}
            createKey={createKey}
            rotateKey={rotateKey}
            deleteKey={deleteKey}
            deleteCertificate={deleteCertificate}
            issueCertificate={issueCertificate}
            runLifecycle={runLifecycle}
            tpm2Status={tpm2Status}
            tpm2PCRs={tpm2PCRs}
            tpm2Demo={tpm2Demo}
            tpm2Random={tpm2Random}
            refreshTPM2={refreshTPM2}
            runTPM2Demo={runTPM2Demo}
          />
        ) : null}
      </main>
    </div>
  )
}

function PrimaryNav(props: { page: Page; setPage: (page: Page) => void }) {
  const items: Array<{ page: Page; label: string; icon: ComponentProps<typeof Icon>['icon']; detail: string }> = [
    { page: 'overview', label: 'Overview', icon: 'home', detail: 'Start here' },
    { page: 'create', label: 'Create', icon: 'endorsed', detail: 'Guided setup' },
    { page: 'keys', label: 'My Keys', icon: 'key', detail: 'Inventory' },
    { page: 'certs', label: 'My Certs', icon: 'document', detail: 'Certificates' },
    { page: 'proof', label: 'Proof', icon: 'shield', detail: 'Technical evidence' },
  ]

  return (
    <nav className="primary-nav" aria-label="Primary">
      {items.map((item) => (
        <button
          className={`nav-item ${props.page === item.page ? 'is-active' : ''}`}
          key={item.page}
          type="button"
          onClick={() => props.setPage(item.page)}
        >
          <Icon icon={item.icon} />
          <span>
            <strong>{item.label}</strong>
            <small>{item.detail}</small>
          </span>
        </button>
      ))}
    </nav>
  )
}

function OverviewPage() {
  return (
    <section className="overview-page">
      <section className="hsm-panel hsm-panel-primary overview-hero">
        <div>
          <span className="eyebrow">Overview</span>
          <h2>KeyMan shows how protected keys are created, used, and proven.</h2>
          <p>
            The app is a sandbox for private-key workflows that normally depend on HSMs, smart cards, or TPM 2.0 hardware. It keeps the product story simple: choose what you need, protect the key in the right place, and keep sensitive key material out of ordinary files.
          </p>
        </div>
      </section>

      <section className="hsm-panel overview-summary">
        <div className="overview-summary-title">
          <span className="eyebrow">What it demonstrates</span>
          <h2>Hardware-backed key management without user friction</h2>
        </div>
        <ul className="overview-list">
          <li>Create turns common security goals into a guided key workflow: login keys, service certificates, disk unlock secrets, VPN identities, and release signing keys.</li>
          <li>HSM protection models portable keys that can move with a token-backed operational workflow.</li>
          <li>TPM 2.0 protection models machine-bound keys, measured boot state, sealed secrets, and attestation evidence.</li>
          <li>My Keys and My Certs show the protected inventory; Proof exposes the underlying HSM and TPM operations when technical evidence is needed.</li>
        </ul>
      </section>
    </section>
  )
}

function MyKeysPage(props: {
  tpmKeys: CreatedAsset[]
  keys: KeyMetadata[]
  busy: boolean
  rotateKey: (keyId: string) => void
  deleteKey: (keyId: string) => void
}) {
  return (
    <section className="keys-page">
      <section className="hsm-panel hsm-panel-primary">
        <div className="page-heading">
          <div>
            <span className="eyebrow">My Keys</span>
            <h2>Protected keys</h2>
          </div>
        </div>
        <UnifiedKeyList
          hsmKeys={props.keys}
          tpmKeys={props.tpmKeys}
          busy={props.busy}
          rotateKey={props.rotateKey}
          deleteKey={props.deleteKey}
        />
      </section>
    </section>
  )
}

function MyCertificatesPage(props: {
  certificates: CertificateInfo[]
  asymmetricKeys: KeyMetadata[]
  busy: boolean
  csrKeyId: string
  csrCommonName: string
  csrOrganization: string
  csrDNSNames: string
  csrPEM: string
  importLabel: string
  importPEM: string
  importDERBase64: string
  importFileName: string
  setCSRKeyId: (value: string) => void
  setCSRCommonName: (value: string) => void
  setCSROrganization: (value: string) => void
  setCSRDNSNames: (value: string) => void
  setImportLabel: (value: string) => void
  setImportPEM: (value: string) => void
  createCSR: (event: FormEvent) => void
  copyCSR: () => void
  importCertificate: (event: FormEvent) => void
  handleImportFile: (event: ChangeEvent<HTMLInputElement>) => void
  deleteCertificate: (label: string) => void
}) {
  const hasImportData = Boolean(props.importPEM.trim() || props.importDERBase64)
  return (
    <section className="certificates-page">
      <section className="cert-tools-grid">
        <section className="hsm-panel compact-panel">
          <PanelTitle eyebrow="Create CSR" title="Request certificate" icon="endorsed" />
          <form className="cert-workflow-form" onSubmit={props.createCSR}>
            <div className="hsm-form-grid cert-grid">
              <FormGroup label="Stored key" labelFor="csr-key">
                <HTMLSelect
                  id="csr-key"
                  value={props.csrKeyId}
                  onChange={(event) => props.setCSRKeyId(event.currentTarget.value)}
                  disabled={props.asymmetricKeys.length === 0}
                >
                  {props.asymmetricKeys.length === 0 ? <option value="">No signing keys</option> : null}
                  {props.asymmetricKeys.map((key) => (
                    <option key={key.id} value={key.id}>
                      {friendlyKeyName(key.name)}
                    </option>
                  ))}
                </HTMLSelect>
              </FormGroup>
              <FormGroup label="Common name" labelFor="csr-common-name">
                <InputGroup
                  id="csr-common-name"
                  placeholder="service.local"
                  value={props.csrCommonName}
                  onChange={(event) => props.setCSRCommonName(event.currentTarget.value)}
                />
              </FormGroup>
              <FormGroup label="Organization" labelFor="csr-organization">
                <InputGroup
                  id="csr-organization"
                  value={props.csrOrganization}
                  onChange={(event) => props.setCSROrganization(event.currentTarget.value)}
                />
              </FormGroup>
              <FormGroup label="Domains" labelFor="csr-dns">
                <InputGroup
                  id="csr-dns"
                  placeholder="service.local, api.local"
                  value={props.csrDNSNames}
                  onChange={(event) => props.setCSRDNSNames(event.currentTarget.value)}
                />
              </FormGroup>
            </div>
            <Button
              icon="document"
              intent="primary"
              type="submit"
              loading={props.busy}
              disabled={!props.csrKeyId || !props.csrCommonName.trim()}
            >
              Create CSR
            </Button>
          </form>
          {props.csrPEM ? (
            <div className="csr-output">
              <div className="csr-output-heading">
                <strong>CSR</strong>
                <Button icon="clipboard" minimal onClick={() => void props.copyCSR()}>
                  Copy
                </Button>
              </div>
              <TextArea readOnly value={props.csrPEM} fill />
            </div>
          ) : null}
        </section>

        <section className="hsm-panel compact-panel">
          <PanelTitle eyebrow="Import certificate" title="Store issued certificate" icon="import" />
          <form className="cert-workflow-form" onSubmit={props.importCertificate}>
            <FormGroup label="Certificate name" labelFor="import-label">
              <InputGroup
                id="import-label"
                placeholder="service-certificate"
                value={props.importLabel}
                onChange={(event) => props.setImportLabel(event.currentTarget.value)}
              />
            </FormGroup>
            <FormGroup label="Certificate file" labelFor="import-file">
              <input id="import-file" className="file-input" type="file" accept=".cer,.crt,.der,.pem" onChange={props.handleImportFile} />
            </FormGroup>
            {props.importFileName ? <Tag minimal>{props.importFileName}</Tag> : null}
            <FormGroup label="PEM certificate or chain" labelFor="import-pem">
              <TextArea
                id="import-pem"
                placeholder="-----BEGIN CERTIFICATE-----"
                value={props.importPEM}
                onChange={(event) => props.setImportPEM(event.currentTarget.value)}
                fill
              />
            </FormGroup>
            <Button
              icon="import"
              intent="primary"
              type="submit"
              loading={props.busy}
              disabled={!props.importLabel.trim() || !hasImportData}
            >
              Import certificate
            </Button>
          </form>
        </section>
      </section>

      <section className="hsm-panel hsm-panel-primary">
        <div className="page-heading">
          <div>
            <span className="eyebrow">My Certs</span>
            <h2>Certificates</h2>
          </div>
        </div>
        <CertificateList certificates={props.certificates} busy={props.busy} deleteCertificate={props.deleteCertificate} />
      </section>
    </section>
  )
}

function ProofPage(props: {
  workspace: Workspace
  setWorkspace: (value: Workspace) => void
  busy: boolean
  hsmReady: boolean
  tpmReady: boolean
  health: Health | null
  keys: KeyMetadata[]
  certificates: CertificateInfo[]
  asymmetricKeys: KeyMetadata[]
  lifecycle: LifecycleResponse | null
  pin: string
  newKeyName: string
  newKeyType: KeyType
  certKeyId: string
  certLabel: string
  commonName: string
  organization: string
  dnsNames: string
  validHours: number
  isCA: boolean
  setPin: (value: string) => void
  setNewKeyName: (value: string) => void
  setNewKeyType: (value: KeyType) => void
  setCertKeyId: (value: string) => void
  setCertLabel: (value: string) => void
  setCommonName: (value: string) => void
  setOrganization: (value: string) => void
  setDNSNames: (value: string) => void
  setValidHours: (value: number) => void
  setIsCA: (value: boolean) => void
  connect: (event: FormEvent) => void
  disconnect: () => void
  createKey: (event: FormEvent) => void
  rotateKey: (keyId: string) => void
  deleteKey: (keyId: string) => void
  deleteCertificate: (label: string) => void
  issueCertificate: (event: FormEvent) => void
  runLifecycle: () => void
  tpm2Status: TPM2Status | null
  tpm2PCRs: TPM2PCR[]
  tpm2Demo: TPM2DemoResponse | null
  tpm2Random: string
  refreshTPM2: () => void
  runTPM2Demo: () => void
}) {
  return (
    <section className="proof-page">
      <section className="hsm-panel hsm-panel-primary proof-intro">
        <div>
          <span className="eyebrow">Proof</span>
          <h2>Technical evidence and backend checks</h2>
          <p>Use this page when you want to inspect the real HSM and TPM operations behind the guided flow.</p>
        </div>
        <ButtonGroup className="segmented-choice">
          <Button active={props.workspace === 'hsm'} icon="key" rightIcon={props.workspace === 'hsm' ? 'tick' : undefined} onClick={() => props.setWorkspace('hsm')}>
            HSM token
          </Button>
          <Button active={props.workspace === 'tpm'} icon="control" rightIcon={props.workspace === 'tpm' ? 'tick' : undefined} onClick={() => props.setWorkspace('tpm')}>
            TPM 2.0 device
          </Button>
        </ButtonGroup>
      </section>

      {props.workspace === 'hsm' ? (
        <HSMWorkspace
          busy={props.busy}
          ready={props.hsmReady}
          health={props.health}
          keys={props.keys}
          certificates={props.certificates}
          asymmetricKeys={props.asymmetricKeys}
          lifecycle={props.lifecycle}
          pin={props.pin}
          newKeyName={props.newKeyName}
          newKeyType={props.newKeyType}
          certKeyId={props.certKeyId}
          certLabel={props.certLabel}
          commonName={props.commonName}
          organization={props.organization}
          dnsNames={props.dnsNames}
          validHours={props.validHours}
          isCA={props.isCA}
          setPin={props.setPin}
          setNewKeyName={props.setNewKeyName}
          setNewKeyType={props.setNewKeyType}
          setCertKeyId={props.setCertKeyId}
          setCertLabel={props.setCertLabel}
          setCommonName={props.setCommonName}
          setOrganization={props.setOrganization}
          setDNSNames={props.setDNSNames}
          setValidHours={props.setValidHours}
          setIsCA={props.setIsCA}
          connect={props.connect}
          disconnect={props.disconnect}
          createKey={props.createKey}
          rotateKey={props.rotateKey}
          deleteKey={props.deleteKey}
          deleteCertificate={props.deleteCertificate}
          issueCertificate={props.issueCertificate}
          runLifecycle={props.runLifecycle}
        />
      ) : (
        <TPMWorkspace
          busy={props.busy}
          status={props.tpm2Status}
          pcrs={props.tpm2PCRs}
          demo={props.tpm2Demo}
          randomHex={props.tpm2Random}
          refreshTPM2={props.refreshTPM2}
          runDemo={props.runTPM2Demo}
        />
      )}
    </section>
  )
}

function AssetWizard(props: {
  busy: boolean
  assetKind: AssetKind
  backend: BackendChoice
  assetName: string
  result: AssetResult | null
  hsmReady: boolean
  tpmReady: boolean
  setAssetKind: (value: AssetKind) => void
  setBackend: (value: BackendChoice) => void
  setAssetName: (value: string) => void
  createAsset: () => void
}) {
  const asset = assetDefinitions.find((item) => item.kind === props.assetKind) || assetDefinitions[0]
  const backendLabel = props.backend === 'hsm' ? 'HSM token' : 'TPM 2.0 device'
  const ready = props.backend === 'hsm' ? props.hsmReady : props.tpmReady
  const hsmLocked = props.backend === 'hsm' && !props.hsmReady

  return (
    <section className="asset-wizard hsm-panel hsm-panel-primary">
      <div className="wizard-heading">
        <div>
          <span className="eyebrow">Guided setup</span>
          <h2>Create a protected key</h2>
        </div>
      </div>

      <div className="wizard-grid">
        <div className="wizard-step">
          <span className="step-number">1</span>
          <div>
            <h3>Choose what you want to protect</h3>
            <div className="asset-choice-grid" role="list" aria-label="Key type">
              {assetDefinitions.map((item) => (
                <button
                  className={`choice-card ${props.assetKind === item.kind ? 'is-active' : ''}`}
                  key={item.kind}
                  type="button"
                  onClick={() => props.setAssetKind(item.kind)}
                >
                  <strong>{item.title}</strong>
                  <span>{item.description}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="wizard-step">
          <span className="step-number">2</span>
          <div>
            <h3>Choose how it is protected</h3>
            <div className="backend-choice-grid" role="list" aria-label="Protection backend">
              <button
                className={`choice-card backend-card ${props.backend === 'hsm' ? 'is-active' : ''}`}
                type="button"
                onClick={() => props.setBackend('hsm')}
              >
                <strong>HSM token</strong>
                <span>Portable protection for keys that move with a person, service, or release process.</span>
                <StatusTag ready={props.hsmReady} readyLabel="Unlocked" waitingLabel="Locked" />
              </button>
              <button
                className={`choice-card backend-card ${props.backend === 'tpm' ? 'is-active' : ''}`}
                type="button"
                onClick={() => props.setBackend('tpm')}
              >
                <strong>TPM 2.0 device</strong>
                <span>Machine-bound protection for passwordless login, disk unlock, and trusted-device proof.</span>
                <StatusTag ready={props.tpmReady} readyLabel="Ready" waitingLabel="Offline" />
              </button>
            </div>
          </div>
        </div>

        <div className="wizard-step final-step">
          <span className="step-number">3</span>
          <div className="final-step-content">
            <h3>Name and create</h3>
            <div className="decision-summary">
              <strong>{asset.title}</strong>
              <span>{props.backend === 'tpm' ? asset.tpmOutcome : asset.hsmOutcome}</span>
              <Tag intent={ready ? 'success' : 'warning'}>{backendLabel}</Tag>
            </div>
            <div className="asset-name-row">
              <FormGroup label="Name" labelFor="asset-name">
                <InputGroup
                  id="asset-name"
                  placeholder={asset.defaultName}
                  value={props.assetName}
                  onChange={(event) => props.setAssetName(event.currentTarget.value)}
                />
              </FormGroup>
              <Button
                icon="endorsed"
                intent="primary"
                loading={props.busy}
                disabled={hsmLocked}
                onClick={() => void props.createAsset()}
              >
                {hsmLocked ? 'Unlock HSM Token first' : `Create ${asset.shortTitle} key`}
              </Button>
            </div>
          </div>
        </div>
      </div>

      {props.result ? (
        <AssetResultPanel result={props.result} />
      ) : null}
    </section>
  )
}

function AssetResultPanel(props: { result: AssetResult }) {
  return (
    <section className={`asset-result ${props.result.backend}`}>
      <div className="asset-result-main">
        <Tag intent="success">{props.result.backendLabel}</Tag>
        <h3>{props.result.title} is ready</h3>
        <ul className="created-list">
          {props.result.created.map((item) => (
            <li key={item}>
              <Icon icon="tick-circle" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="asset-result-side">
        <h3>How to use it</h3>
        <ol className="howto-list">
          {props.result.howToUse.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ol>
      </div>
      <ProofDrawer title="Show proof" facts={props.result.facts} operations={props.result.operations} />
    </section>
  )
}

function HSMWorkspace(props: {
  busy: boolean
  ready: boolean
  health: Health | null
  keys: KeyMetadata[]
  certificates: CertificateInfo[]
  asymmetricKeys: KeyMetadata[]
  lifecycle: LifecycleResponse | null
  pin: string
  newKeyName: string
  newKeyType: KeyType
  certKeyId: string
  certLabel: string
  commonName: string
  organization: string
  dnsNames: string
  validHours: number
  isCA: boolean
  setPin: (value: string) => void
  setNewKeyName: (value: string) => void
  setNewKeyType: (value: KeyType) => void
  setCertKeyId: (value: string) => void
  setCertLabel: (value: string) => void
  setCommonName: (value: string) => void
  setOrganization: (value: string) => void
  setDNSNames: (value: string) => void
  setValidHours: (value: number) => void
  setIsCA: (value: boolean) => void
  connect: (event: FormEvent) => void
  disconnect: () => void
  createKey: (event: FormEvent) => void
  rotateKey: (keyId: string) => void
  deleteKey: (keyId: string) => void
  deleteCertificate: (label: string) => void
  issueCertificate: (event: FormEvent) => void
  runLifecycle: () => void
}) {
  if (!props.ready) {
    return (
      <section className="hsm-panel hsm-panel-primary">
        <PanelTitle eyebrow="HSM token" title="Locked" icon="lock" />
        <div className="hsm-empty">Unlock the HSM token from the header to inspect token-backed key operations.</div>
      </section>
    )
  }

  return (
    <section className="workspace-grid">
      <section className="hsm-panel hsm-panel-primary work-panel">
        <PanelTitle eyebrow="HSM token" title="Portable key workspace" icon="key" />
        <OutcomePath steps={['Create key', 'Issue certificate', 'Use from apps']} />
        <div className="outcome-grid">
          <Fact label="Keys" value={String(props.keys.length)} />
          <Fact label="Certificates" value={String(props.certificates.length)} />
          <Fact label="Protection" value="HSM token" />
          <Fact label="State" value="ready" />
        </div>
        <Divider />
        <div className="panel-section">
          <h3>Create HSM key</h3>
          <form className="inline-form" onSubmit={props.createKey}>
            <FormGroup label="Key name" labelFor="key-name">
              <InputGroup
                id="key-name"
                placeholder="service-signing-key"
                value={props.newKeyName}
                onChange={(event) => props.setNewKeyName(event.currentTarget.value)}
              />
            </FormGroup>
            <FormGroup label="Key type" labelFor="key-type">
              <HTMLSelect
                id="key-type"
                value={props.newKeyType}
                onChange={(event) => props.setNewKeyType(event.currentTarget.value as KeyType)}
              >
                {keyTypes.map((keyType) => (
                  <option key={keyType.value} value={keyType.value}>
                    {keyType.label}
                  </option>
                ))}
              </HTMLSelect>
            </FormGroup>
            <Button icon="key" intent="primary" type="submit" loading={props.busy} disabled={!props.newKeyName.trim()}>
              Create HSM key
            </Button>
          </form>
        </div>
        <Divider />
        <div className="panel-section">
          <h3>HSM protected keys</h3>
          <KeyList keys={props.keys} busy={props.busy} rotateKey={props.rotateKey} deleteKey={props.deleteKey} />
        </div>
        <Divider />
        <ButtonGroup className="action-cluster">
          <Button icon="play" intent="primary" loading={props.busy} onClick={() => void props.runLifecycle()}>
            Run key check
          </Button>
          <Button icon="log-out" onClick={() => void props.disconnect()}>
            Lock
          </Button>
        </ButtonGroup>
        {props.lifecycle ? (
          <ProofDrawer
            title="Key proof"
            facts={[
              ['Encryption key', `rotated to version ${props.lifecycle.newKeyVersion}`],
              ['Signing key', `${props.lifecycle.signatureBytes} byte signature`],
              ['Certificate', 'issued and checked'],
              ['TLS signer', `${props.lifecycle.tlsSignatureBytes} byte signature`],
            ]}
            operations={props.lifecycle.operations}
          />
        ) : null}
      </section>

      <section className="hsm-panel compact-panel">
        <PanelTitle eyebrow="Step 2" title="Issue certificate" icon="shield" />
        <form className="cert-form" onSubmit={props.issueCertificate}>
          <div className="hsm-form-grid cert-grid">
            <FormGroup label="Signing key" labelFor="cert-key">
              <HTMLSelect
                id="cert-key"
                value={props.certKeyId}
                onChange={(event) => props.setCertKeyId(event.currentTarget.value)}
                disabled={props.asymmetricKeys.length === 0}
              >
                {props.asymmetricKeys.length === 0 ? <option value="">No signing keys</option> : null}
                {props.asymmetricKeys.map((key) => (
                  <option key={key.id} value={key.id}>
                    {friendlyKeyName(key.name)}
                  </option>
                ))}
              </HTMLSelect>
            </FormGroup>
            <FormGroup label="Certificate name" labelFor="cert-label">
              <InputGroup
              id="cert-label"
              placeholder="service-certificate"
              value={props.certLabel}
                onChange={(event) => props.setCertLabel(event.currentTarget.value)}
              />
            </FormGroup>
            <FormGroup label="Service name" labelFor="common-name">
              <InputGroup
              id="common-name"
              placeholder="service.local"
              value={props.commonName}
                onChange={(event) => props.setCommonName(event.currentTarget.value)}
              />
            </FormGroup>
            <FormGroup label="Domains" labelFor="dns-names">
                <InputGroup
              id="dns-names"
              placeholder="service.local, api.local"
              value={props.dnsNames}
                onChange={(event) => props.setDNSNames(event.currentTarget.value)}
              />
            </FormGroup>
          </div>
          <details className="detail-drawer">
            <summary>More certificate options</summary>
            <div className="hsm-form-grid">
              <FormGroup label="Organization" labelFor="organization">
                <InputGroup
                  id="organization"
                  value={props.organization}
                  onChange={(event) => props.setOrganization(event.currentTarget.value)}
                />
              </FormGroup>
              <FormGroup label="Valid for (hours)" labelFor="valid-hours">
                <NumericInput
                  id="valid-hours"
                  min={1}
                  max={8760}
                  rightElement={<Tag minimal>hours</Tag>}
                  value={props.validHours}
                  onValueChange={(value) => props.setValidHours(Number.isFinite(value) ? value : 24)}
                />
              </FormGroup>
              <Switch
                checked={props.isCA}
                label="Can sign other certificates"
                onChange={(event) => props.setIsCA(event.currentTarget.checked)}
              />
            </div>
          </details>
          <Button
            icon="document"
            intent="primary"
            type="submit"
            loading={props.busy}
            disabled={!props.certKeyId || !props.certLabel.trim() || !props.commonName.trim()}
          >
            Issue certificate
          </Button>
        </form>
      </section>
    </section>
  )
}

function TPMWorkspace(props: {
  busy: boolean
  status: TPM2Status | null
  pcrs: TPM2PCR[]
  demo: TPM2DemoResponse | null
  randomHex: string
  refreshTPM2: () => void
  runDemo: () => void
}) {
  return (
    <section className="workspace-grid">
      <section className="hsm-panel hsm-panel-primary compact-panel">
        <PanelTitle eyebrow="TPM 2.0 device" title={props.status?.ready ? 'Machine trust workspace' : 'Not available'} icon="control" />
        <OutcomePath steps={['Measure boot', 'Seal secret', 'Create quote']} />
        <div className="outcome-grid">
          <Fact label="Trust device" value={props.status?.ready ? 'ready' : 'offline'} />
          <Fact label="Measurements" value={props.pcrs.length ? `${props.pcrs.length} boot values` : 'not read'} />
          <Fact label="Machine-bound key" value={props.demo ? 'created' : 'not created'} />
          <Fact label="Result" value={props.demo ? 'passed' : 'not run'} />
        </div>
        {props.status?.error ? (
          <>
            <Divider />
            <Callout intent="warning" icon="warning-sign" title="Trust device not available">
              {props.status.error}
            </Callout>
          </>
        ) : null}
        <Divider />
        <ButtonGroup className="action-cluster">
          <Button icon="play" intent="primary" loading={props.busy} disabled={!props.status?.ready} onClick={() => void props.runDemo()}>
            Run TPM trust flow
          </Button>
          <Button icon="refresh" loading={props.busy} onClick={() => void props.refreshTPM2()}>
            Refresh TPM
          </Button>
        </ButtonGroup>
        <ProofDrawer
          title="Technical proof"
          facts={[
            ['Device link', 'this machine'],
            ['Tooling', props.status?.toolsVersion || 'not detected'],
            ['Random value', shortHex(props.randomHex)],
            ['Measurements', props.pcrs.length ? `${props.pcrs.length} SHA-256 values` : 'not read'],
          ]}
        >
          {props.pcrs.length > 0 ? (
            <div className="pcr-grid">
              {props.pcrs.map((pcr) => (
                <div className="pcr-row" key={`${pcr.bank}-${pcr.index}`}>
                  <strong>PCR {pcr.index}</strong>
                  <span className="mono">{shortHex(pcr.value)}</span>
                  <Tag minimal>{pcr.bank}</Tag>
                </div>
              ))}
            </div>
          ) : null}
        </ProofDrawer>
      </section>

      <section className="hsm-panel compact-panel">
        <PanelTitle eyebrow="Result" title={props.demo ? 'Passed' : 'Not run yet'} icon="history" />
        {props.demo ? (
          <>
            <div className="outcome-grid">
              <Fact label="Signing key" value="machine-bound" />
              <Fact label="Signature" value={`${props.demo.signatureBytes} bytes`} />
              <Fact label="Sealed secret" value={props.demo.pcrBoundUnsealedMatches ? 'released safely' : 'not released'} />
              <Fact label="Quote" value={`${props.demo.quoteBytes} bytes`} />
            </div>
            <Divider />
            <ProofDrawer
              title="Run details"
              facts={[
                ['Primary key', 'created in TPM 2.0 device'],
                ['Signing key', 'non-exportable TPM key'],
                ['PCR policy', shortHex(props.demo.pcrPolicyDigest)],
                ['PCR-bound secret', props.demo.pcrBoundUnsealedMatches ? `${props.demo.pcrBoundSecretBytes} bytes released` : 'release blocked'],
                ['Attestation quote', `${props.demo.quoteBytes} bytes, ${props.demo.quoteSignatureBytes} byte signature`],
                ['AK name', shortHex(props.demo.attestationKeyName)],
              ]}
              operations={props.demo.operations}
            />
          </>
        ) : (
          <div className="hsm-empty">Run the TPM trust flow to create a machine-bound signing key, release a boot-state protected secret, and produce an attestation quote.</div>
        )}
      </section>

    </section>
  )
}

function UnifiedKeyList(props: {
  hsmKeys: KeyMetadata[]
  tpmKeys: CreatedAsset[]
  busy: boolean
  rotateKey: (keyId: string) => void
  deleteKey: (keyId: string) => void
}) {
  if (props.hsmKeys.length === 0 && props.tpmKeys.length === 0) {
    return <div className="hsm-empty">No protected keys yet. Use Create to make the first key.</div>
  }

  return (
    <div className="inventory-list">
      {props.hsmKeys.map((key) => (
        <div className="inventory-row" key={`hsm-${key.id}`}>
          <div className="inventory-row-main">
            <div className="inventory-row-heading">
              <div className="inventory-title-group">
                <strong>{friendlyKeyName(key.name)}</strong>
              </div>
              <div className="inventory-pill-row">
                <Tag minimal>HSM token</Tag>
              </div>
            </div>
            <div className="inventory-row-meta">
              {friendlyKeyDetails(key.type).map((detail) => (
                <span key={detail}>{detail}</span>
              ))}
              <span>Version {key.latestVersion}</span>
              <span>Created {formatDateTime(key.createdAt)}</span>
              {isRealTimestamp(key.rotatedAt) ? <span>Rotated {formatDateTime(key.rotatedAt)}</span> : null}
            </div>
          </div>
          <div className="inventory-row-actions">
            <Button icon="repeat" onClick={() => props.rotateKey(key.id)} loading={props.busy}>
              Rotate
            </Button>
            <Button icon="trash" intent="danger" onClick={() => props.deleteKey(key.id)} loading={props.busy}>
              Delete
            </Button>
          </div>
        </div>
      ))}
      {props.tpmKeys.map((asset) => {
        const measuredState = asset.result.facts.find(([label]) => label === 'Measured state')?.[1]
        const quote = asset.result.facts.find(([label]) => label === 'Attestation quote')?.[1]
        return (
          <div className="inventory-row" key={asset.id}>
            <div className="inventory-row-main">
              <div className="inventory-row-heading">
                <div className="inventory-title-group">
                  <strong>{asset.result.title}</strong>
                </div>
                <div className="inventory-pill-row">
                  <Tag intent="success" minimal>
                    TPM 2.0 device
                  </Tag>
                  <Tag minimal>Session proof</Tag>
                </div>
              </div>
              <div className="inventory-row-meta">
                <span>{asset.result.name}</span>
                {friendlyTPMKeyDetails(asset.result.kind).map((detail) => (
                  <span key={detail}>{detail}</span>
                ))}
                <span>Created {formatDateTime(asset.createdAt)}</span>
                {measuredState ? <span>{measuredState}</span> : null}
                {quote ? <span>Quote {quote}</span> : null}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function KeyList(props: {
  keys: KeyMetadata[]
  busy: boolean
  rotateKey: (keyId: string) => void
  deleteKey: (keyId: string) => void
}) {
  if (props.keys.length === 0) {
    return <div className="hsm-empty">No HSM token keys yet.</div>
  }
  return (
    <div className="hsm-row-list">
      {props.keys.map((key) => (
        <div className="hsm-row" key={key.id}>
          <div className="hsm-row-main">
            <strong>{friendlyKeyName(key.name)}</strong>
            <div className="hsm-row-meta">
              <span>stored in HSM token</span>
              <span>{friendlyKeyType(key.type)}</span>
              <span>version {key.latestVersion}</span>
            </div>
          </div>
          <Tag minimal>HSM token</Tag>
          <Button icon="repeat" onClick={() => props.rotateKey(key.id)} loading={props.busy}>
            Rotate
          </Button>
          <Button icon="trash" intent="danger" onClick={() => props.deleteKey(key.id)} loading={props.busy}>
            Delete
          </Button>
        </div>
      ))}
    </div>
  )
}

function CertificateList(props: { certificates: CertificateInfo[]; busy: boolean; deleteCertificate: (label: string) => void }) {
  if (props.certificates.length === 0) {
    return <div className="hsm-empty">No certificates issued yet.</div>
  }
  return (
    <div className="inventory-list">
      {props.certificates.map((certificate) => (
        <div className="inventory-row" key={`${certificate.label}-${certificate.serialNumber}`}>
          <div className="inventory-row-main">
            <div className="inventory-row-heading">
              <div className="inventory-title-group">
                <strong>{certificate.label}</strong>
                <span>{friendlyCertificateCN(certificate)}</span>
              </div>
              <div className="inventory-pill-row">
                <Tag minimal>HSM token</Tag>
                {certificate.keyId ? <Tag minimal>Key {friendlyKeyName(certificate.keyId)}</Tag> : <Tag minimal>Chain certificate</Tag>}
                {certificate.isCa ? <Tag minimal>CA</Tag> : null}
              </div>
            </div>
            <div className="inventory-row-meta">
              <span>{friendlyCertificateIssuer(certificate)}</span>
              {friendlyCertificateKeyDetails(certificate).map((detail) => (
                <span key={detail}>{detail}</span>
              ))}
              <span>{friendlySignatureAlgorithm(certificate.signatureAlgorithm)}</span>
              <span>Expires {formatDate(certificate.notAfter)}</span>
              {friendlyCertificateUsage(certificate) ? <span>{friendlyCertificateUsage(certificate)}</span> : null}
            </div>
          </div>
          <div className="inventory-row-actions">
            <Button icon="trash" intent="danger" onClick={() => props.deleteCertificate(certificate.label)} loading={props.busy}>
              Delete
            </Button>
          </div>
        </div>
      ))}
    </div>
  )
}

function PanelTitle(props: { eyebrow: string; title: string; icon: ComponentProps<typeof Icon>['icon'] }) {
  return (
    <div className="hsm-panel-title-row">
      <div>
        <span className="eyebrow">{props.eyebrow}</span>
        <h2>{props.title}</h2>
      </div>
      <Icon icon={props.icon} />
    </div>
  )
}

function OutcomePath(props: { steps: string[] }) {
  return (
    <ol className="outcome-path" aria-label="Workflow">
      {props.steps.map((step, index) => (
        <li key={step}>
          <span>{index + 1}</span>
          <strong>{step}</strong>
        </li>
      ))}
    </ol>
  )
}

function ProofDrawer(props: {
  title: string
  facts: Array<[string, string]>
  operations?: string[]
  children?: ReactNode
}) {
  return (
    <details className="detail-drawer proof-drawer">
      <summary>{props.title}</summary>
      <div className="proof-content">
        <div className="outcome-grid">
          {props.facts.map(([label, value]) => (
            <Fact key={label} label={label} value={value} mono={value.length > 28} />
          ))}
        </div>
        {props.children}
        {props.operations && props.operations.length > 0 ? (
          <ul className="hsm-log compact-log">
            {props.operations.map((item) => (
              <li key={item}>{friendlyOperation(item)}</li>
            ))}
          </ul>
        ) : null}
      </div>
    </details>
  )
}

function StatusTag(props: { ready: boolean; readyLabel: string; waitingLabel: string }) {
  return props.ready ? <Tag intent="success">{props.readyLabel}</Tag> : <Tag intent="warning">{props.waitingLabel}</Tag>
}

function Fact(props: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="hsm-fact">
      <span>{props.label}</span>
      <strong className={props.mono ? 'mono' : undefined}>{props.value}</strong>
    </div>
  )
}

function shortHex(value: string) {
  if (!value) {
    return 'not read'
  }
  const clean = value.replace(/^0x/, '')
  if (clean.length <= 18) {
    return value
  }
  return `0x${clean.slice(0, 10)}...${clean.slice(-8)}`
}

function friendlyKeyType(value: KeyType) {
  switch (value) {
    case 'aes-256-gcm':
      return 'AES data key'
    case 'rsa-4096':
      return 'RSA signing key'
    case 'ml-dsa-65':
      return 'ML-DSA-65 signing key'
    case 'ecdsa-p256':
      return 'ECDSA signing key'
    default:
      return value
  }
}

function friendlyKeyDetails(value: KeyType) {
  switch (value) {
    case 'aes-256-gcm':
      return ['AES-GCM', '256-bit', 'Encryption']
    case 'rsa-4096':
      return ['RSA', '4096-bit', 'Signing']
    case 'ml-dsa-65':
      return ['ML-DSA-65', 'Post-quantum signing']
    case 'ecdsa-p256':
      return ['ECDSA P-256', '256-bit', 'Signing']
    default:
      return [value]
  }
}

function friendlyTPMKeyDetails(kind: AssetKind) {
  if (kind === 'disk') {
    return ['Sealed secret', '256-bit', 'PCR policy']
  }
  return ['ECC P-256', '256-bit', 'Signing']
}

function friendlyKeyName(value: string) {
  if (value.startsWith('sample-aes-')) {
    return 'Key check encryption key'
  }
  if (value.startsWith('sample-rsa-')) {
    return 'Key check signing key'
  }
  return value
}

function isRealTimestamp(value: string) {
  return Boolean(value) && !value.startsWith('0001-01-01')
}

function formatDateTime(value: string) {
  if (!isRealTimestamp(value)) {
    return 'unknown'
  }
  return new Date(value).toLocaleString([], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function formatDate(value: string) {
  if (!isRealTimestamp(value)) {
    return 'unknown'
  }
  return new Date(value).toLocaleDateString()
}

function friendlyCertificateIssuer(certificate: CertificateInfo) {
  if (certificate.issuer === certificate.subject) {
    return 'Self-signed'
  }
  return `Signed by ${certificate.issuer}`
}

function friendlyCertificateCN(certificate: CertificateInfo) {
  const commonName = certificate.commonName || parseDistinguishedNameValue(certificate.subject, 'CN')
  return commonName ? `CN ${commonName}` : certificate.subject
}

function friendlyCertificateKeyDetails(certificate: CertificateInfo) {
  const details: string[] = []
  if (certificate.publicKeyAlgorithm) {
    details.push(certificate.publicKeyAlgorithm)
  }
  if (certificate.publicKeyBits) {
    details.push(`${certificate.publicKeyBits}-bit`)
  }
  return details
}

function friendlySignatureAlgorithm(value: string) {
  return value ? `Signed with ${value}` : 'Signature algorithm unknown'
}

function friendlyCertificateUsage(certificate: CertificateInfo) {
  const usages = certificate.keyUsages || []
  if (usages.length === 0) {
    return certificate.isCa ? 'CA certificate' : ''
  }
  return usages.slice(0, 3).join(', ')
}

function parseDistinguishedNameValue(value: string, key: string) {
  const prefix = `${key}=`
  return value
    .split(',')
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
    ?.slice(prefix.length)
}

function bytesToBase64(data: Uint8Array) {
  let binary = ''
  for (let index = 0; index < data.length; index += 1) {
    binary += String.fromCharCode(data[index])
  }
  return btoa(binary)
}

function cleanAssetName(value: string) {
  const clean = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return clean || 'protected-key'
}

function tpmCreatedItems(asset: AssetDefinition, result: TPM2DemoResponse) {
  const items: string[] = []

  if (asset.kind === 'disk') {
    items.push(
      result.pcrBoundUnsealedMatches
        ? 'Disk unlock secret sealed to the current boot state and released safely'
        : 'Disk unlock secret release was blocked by the current boot state',
    )
  } else if (asset.kind === 'ssh') {
    items.push('Machine-bound login key created in the TPM 2.0 device')
  } else if (asset.kind === 'code') {
    items.push('Machine-bound signing key created in the TPM 2.0 device')
  } else {
    items.push('Machine-bound service identity created in the TPM 2.0 device')
  }

  items.push(`${result.pcrs.length} boot measurements read from the device`)

  if (asset.kind !== 'disk') {
    items.push(
      result.pcrBoundUnsealedMatches
        ? 'Protected secret sealed to the current boot state'
        : 'Protected secret could not be released under the current boot state',
    )
  }

  items.push(`Attestation quote created with a ${result.quoteSignatureBytes} byte signature`)
  return items
}

function friendlyOperation(value: string) {
  if (value.startsWith('created AES-256-GCM key')) {
    return 'Created an AES-256-GCM encryption key inside the token'
  }
  if (value.startsWith('encrypted payload with key version')) {
    return value.replace('encrypted payload with', 'Encrypted test data with')
  }
  if (value.startsWith('rotated AES key to version')) {
    return value.replace('rotated AES key', 'Rotated the encryption key')
  }
  if (value === 'decrypted version 1 ciphertext after rotation') {
    return 'Verified old encrypted data still opens after rotation'
  }
  if (value.startsWith('created RSA-4096 signing key')) {
    return 'Created an RSA-4096 signing key inside the token'
  }
  if (value.startsWith('signed and verified SHA-256 digest')) {
    return value.replace('signed and verified', 'Signed and verified')
  }
  if (value.startsWith('stored self-signed certificate')) {
    return 'Stored an X.509 certificate bound to the protected key'
  }
  if (value.startsWith('loaded managed TLS certificate')) {
    return 'Loaded the certificate and signed through a managed TLS signer'
  }
  if (value.startsWith('created TPM-resident ECC signing key')) {
    return 'Created a machine-bound TPM signing key'
  }
  if (value.startsWith('created PCR policy')) {
    return 'Created a policy tied to the current boot measurements'
  }
  if (value.startsWith('unsealed') && value.includes('matching PCR policy')) {
    return 'Released the secret only after the boot measurements matched'
  }
  if (value.startsWith('created attestation key')) {
    return 'Created an attestation key and produced a signed quote'
  }
  return value
    .replace('owner hierarchy ECC primary', 'Primary trust key')
    .replace('TPM-resident ECC signing key', 'Protected signing key')
    .replace('keyedhash sealed-data object', 'Sealed secret')
}

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err)
}
