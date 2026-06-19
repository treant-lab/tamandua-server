import { Head, Link } from '@inertiajs/react'
import axios from 'axios'
import { useEffect, useMemo, useState, useCallback } from 'react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  Download,
  ExternalLink,
  Fingerprint,
  Globe,
  HelpCircle,
  Key,
  KeyRound,
  Loader2,
  Lock,
  Monitor,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface InstallationToken {
  id: string
  name: string
  expires_at?: string | null
  max_uses?: number | null
  use_count?: number
  revoked?: boolean
  consumed_at?: string | null
  consumed_agent_id?: string | null
}

interface EnrolledAgent {
  id: string
  hostname?: string | null
  os_type?: string | null
  agent_version?: string | null
  status?: string | null
  last_seen?: string | null
  created_at?: string | null
}

interface DeployAgentProps {
  organizationId: string | null
  agentServerUrl: string
  enrollmentUrl: string
  downloadUrls: {
    windowsMsi?: string | null
    windowsExe?: string | null
    linuxX64?: string | null
    macosUniversal?: string | null
  }
  tenantPublicKey?: string | null
  caIssuer?: string | null
  mtlsValidDays?: number | null
  recentAgents?: EnrolledAgent[]
}

type WizardStepStatus = 'complete' | 'in_progress' | 'waiting'
type OsTab = 'windows' | 'macos' | 'linux'
type TokenTtl = '30m' | '1h' | '24h'
type AgentRole = 'custody_operator' | 'trading_desk' | 'engineering' | 'treasury' | 'validator' | 'market_making'

const ROLE_OPTIONS: { value: AgentRole; label: string }[] = [
  { value: 'custody_operator', label: 'Custody operator' },
  { value: 'trading_desk', label: 'Trading desk' },
  { value: 'engineering', label: 'Engineering' },
  { value: 'treasury', label: 'Treasury' },
  { value: 'validator', label: 'Validator' },
  { value: 'market_making', label: 'Market making' },
]

const TTL_OPTIONS: { value: TokenTtl; label: string; ms: number }[] = [
  { value: '30m', label: '30 minutes', ms: 30 * 60 * 1000 },
  { value: '1h', label: '1 hour', ms: 60 * 60 * 1000 },
  { value: '24h', label: '24 hours', ms: 24 * 60 * 60 * 1000 },
]

export default function DeployAgent({
  organizationId,
  agentServerUrl,
  enrollmentUrl,
  downloadUrls,
  tenantPublicKey,
  caIssuer,
  mtlsValidDays,
  recentAgents: initialRecentAgents = [],
}: DeployAgentProps) {
  // Token generation state
  const [tokens, setTokens] = useState<InstallationToken[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)
  const [currentTokenId, setCurrentTokenId] = useState<string | null>(null)
  const [tokenExpiresAt, setTokenExpiresAt] = useState<Date | null>(null)
  const [tokenCreatedAt, setTokenCreatedAt] = useState<Date | null>(null)
  const [recentAgents, setRecentAgents] = useState<EnrolledAgent[]>(initialRecentAgents)
  const [agentsLoading, setAgentsLoading] = useState(false)
  const [agentsLoadError, setAgentsLoadError] = useState<string | null>(null)
  const [hostLabel, setHostLabel] = useState('')
  const [agentRole, setAgentRole] = useState<AgentRole>('engineering')
  const [tokenTtl, setTokenTtl] = useState<TokenTtl>('1h')
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Wizard step state
  const [activeOsTab, setActiveOsTab] = useState<OsTab>('windows')

  // Countdown timer for token expiry
  const [timeRemaining, setTimeRemaining] = useState<string>('')

  const currentToken = useMemo(
    () => (currentTokenId ? tokens.find(token => token.id === currentTokenId) || null : null),
    [currentTokenId, tokens]
  )

  // Determine wizard step statuses
  const checkedInAgent = useMemo(() => {
    if (currentTokenId) {
      const consumedAgentId = currentToken?.consumed_agent_id
      if (consumedAgentId) {
        return recentAgents.find(agent => agent.id === consumedAgentId) || null
      }

      return null
    }

    return null
  }, [currentToken, currentTokenId, recentAgents])

  const getStepStatuses = useCallback((): Record<number, WizardStepStatus> => {
    if (checkedInAgent) {
      return {
        1: 'complete',
        2: 'complete',
        3: 'complete',
        4: checkedInAgent.last_seen ? 'complete' : 'in_progress',
      }
    }

    if (newToken) {
      return {
        1: 'complete',
        2: 'in_progress',
        3: 'waiting',
        4: 'waiting',
      }
    }
    return {
      1: 'in_progress',
      2: 'waiting',
      3: 'waiting',
      4: 'waiting',
    }
  }, [checkedInAgent, newToken])

  const stepStatuses = getStepStatuses()

  // Token placeholder for commands
  const tokenPlaceholder = newToken || 'tmd_enroll_...'
  const displayToken = newToken
    ? `${newToken.substring(0, 24)}...${newToken.substring(newToken.length - 10)}`
    : tokenPlaceholder

  // Generate install commands. The flags stay explicit so self-hosted users can
  // swap URLs, while the hosted defaults work without extra parameters.
  const commands = useMemo(() => {
    const windowsExe = downloadUrls.windowsExe || `${enrollmentUrl.replace(/\/$/, '')}/downloads/agents/tamandua-agent-windows-x64.exe`
    const linuxBinary = downloadUrls.linuxX64

    return {
      windows: `# PowerShell (Admin)
$Token = "${newToken || '<enrollment-token>'}"
$AgentUrl = "${windowsExe}"
$AgentPath = "$env:TEMP\\tamandua-agent.exe"

Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath
Start-Process -FilePath $AgentPath -Wait -Verb RunAs -ArgumentList @(
  "install",
  "--enrollment-url", "${enrollmentUrl}",
  "--server", "${agentServerUrl}",
  "--token", $Token
)
# Installs the service and the embedded Windows driver when supported.`,
      macos: `# macOS product installer is not published on this server yet.
# Use the signed and notarized Tamandua EDR DMG/Cask release that includes
# the EndpointSecurity System Extension, then approve the extension and
# Full Disk Access on the target Mac before enrollment.`,
      linux: linuxBinary ? `# Bash (root)
curl -fsSL "${linuxBinary}" -o /tmp/tamandua-agent
chmod +x /tmp/tamandua-agent
sudo /tmp/tamandua-agent install \\
  --enrollment-url "${enrollmentUrl}" \\
  --server "${agentServerUrl}" \\
  --token "${newToken || '<enrollment-token>'}" \\
  --no-driver` : `# Linux installer is not published on this server yet.
# Publish tamandua-agent-linux-x64 to /downloads/agents first.`,
    }
  }, [agentServerUrl, downloadUrls.linuxX64, downloadUrls.windowsExe, enrollmentUrl, newToken])

  // Load existing tokens
  const loadTokens = async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await axios.get('/api/v1/admin/installation-tokens')
      setTokens(response.data.tokens || [])
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to load installation tokens')
    } finally {
      setLoading(false)
    }
  }

  const loadRecentAgents = useCallback(async () => {
    setAgentsLoading(true)
    setAgentsLoadError(null)
    try {
      const response = await axios.get('/api/v1/agents')
      const payload = response.data
      const agents = (
        Array.isArray(payload)
          ? payload
          : payload?.data || payload?.agents || payload?.items || []
      ) as EnrolledAgent[]
      setRecentAgents(agents)
    } catch (err: any) {
      // Keep token generation usable even if the agent list request fails.
      console.warn('Failed to load enrolled agents', err)
      setAgentsLoadError(err?.response?.data?.message || err?.response?.data?.error || 'Could not load enrolled agents yet')
    } finally {
      setAgentsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadTokens()
    loadRecentAgents()
  }, [loadRecentAgents])

  useEffect(() => {
    if (!newToken) return

    loadRecentAgents()
    loadTokens()
    const interval = setInterval(() => {
      loadRecentAgents()
      loadTokens()
    }, 4000)
    return () => clearInterval(interval)
  }, [loadRecentAgents, newToken])

  // Update countdown timer
  useEffect(() => {
    if (!tokenExpiresAt) {
      setTimeRemaining('')
      return
    }

    const updateTimer = () => {
      const now = new Date()
      const diff = tokenExpiresAt.getTime() - now.getTime()

      if (diff <= 0) {
        setTimeRemaining('Expired')
        setNewToken(null)
        setCurrentTokenId(null)
        setTokenExpiresAt(null)
        return
      }

      const minutes = Math.floor(diff / 60000)
      const seconds = Math.floor((diff % 60000) / 1000)
      setTimeRemaining(`${minutes}:${seconds.toString().padStart(2, '0')}`)
    }

    updateTimer()
    const interval = setInterval(updateTimer, 1000)
    return () => clearInterval(interval)
  }, [tokenExpiresAt])

  // Create new token
  const createToken = async () => {
    setCreating(true)
    setError(null)
    try {
      const ttlConfig = TTL_OPTIONS.find(t => t.value === tokenTtl)
      const expiresAt = new Date(Date.now() + (ttlConfig?.ms || 60 * 60 * 1000))

      const response = await axios.post('/api/v1/admin/installation-tokens', {
        name: hostLabel || 'Enrollment token',
        max_uses: 1,
        expires_at: expiresAt.toISOString(),
        organization_id: organizationId,
        role: agentRole,
      })

      setCurrentTokenId(response.data.id)
      setNewToken(response.data.token)
      setTokenExpiresAt(expiresAt)
      setTokenCreatedAt(new Date())
      await loadTokens()
      await loadRecentAgents()
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to create enrollment token')
    } finally {
      setCreating(false)
    }
  }

  // Regenerate token
  const regenerateToken = async () => {
    setNewToken(null)
    setCurrentTokenId(null)
    setTokenExpiresAt(null)
    setTokenCreatedAt(null)
    await createToken()
  }

  // Revoke token
  const revokeToken = async (id: string) => {
    if (!confirm('Revoke this installation token? Existing installed agents keep their issued credentials.')) return
    setError(null)
    try {
      await axios.delete(`/api/v1/admin/installation-tokens/${id}`)
      await loadTokens()
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to revoke installation token')
    }
  }

  // Copy to clipboard
  const copy = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text)
    setCopied(id)
    setTimeout(() => setCopied(null), 1600)
  }

  return (
    <MainLayout title="Deploy Agent">
      <Head title="Enroll Agent - Tamandua EDR" />

      <div className="flex gap-8">
        {/* Main Content */}
        <div className="flex-1 min-w-0">
          {/* Header */}
          <div className="flex items-start justify-between gap-4 mb-8">
            <div>
              <h1 className="text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
                Enroll a new agent
              </h1>
              <p className="mt-2 text-sm" style={{ color: 'var(--muted)' }}>
                Generate a one-time enrollment token, install the agent, and watch it check in.
              </p>
            </div>
            <Link
              href="/app/agents"
              className="flex items-center gap-1.5 text-sm font-medium transition-colors"
              style={{ color: 'var(--emerald-400)' }}
            >
              View enrolled agents
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>

          {/* Error message */}
          {error && (
            <div
              className="flex items-center gap-2 rounded-lg p-3 text-sm mb-6"
              style={{ background: 'var(--crit-bg)', border: '1px solid rgba(240, 80, 110, 0.4)', color: '#fca5a5' }}
            >
              <AlertTriangle className="h-4 w-4" />
              {error}
            </div>
          )}

          {/* Wizard Steps */}
          <div className="space-y-6">
            {/* Step 1: Generate enrollment token */}
            <WizardStep
              number={1}
              title="Generate enrollment token"
              status={stepStatuses[1]}
            >
              <div className="space-y-4">
                {/* Form fields */}
                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="block text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>
                      Host label
                    </label>
                    <input
                      type="text"
                      value={hostLabel}
                      onChange={(e) => setHostLabel(e.target.value)}
                      placeholder="OPS-WIN-05"
                      className="input-sentinel w-full"
                      disabled={!!newToken}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>
                      Role
                    </label>
                    <select
                      value={agentRole}
                      onChange={(e) => setAgentRole(e.target.value as AgentRole)}
                      className="input-sentinel w-full"
                      disabled={!!newToken}
                    >
                      {ROLE_OPTIONS.map(opt => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>
                      Token TTL
                    </label>
                    <select
                      value={tokenTtl}
                      onChange={(e) => setTokenTtl(e.target.value as TokenTtl)}
                      className="input-sentinel w-full"
                      disabled={!!newToken}
                    >
                      {TTL_OPTIONS.map(opt => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Generate button or token display */}
                {!newToken ? (
                  <button
                    onClick={createToken}
                    disabled={creating}
                    className="btn-sentinel btn-sentinel-primary"
                  >
                    {creating ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Generating...
                      </>
                    ) : (
                      <>
                        <KeyRound className="h-4 w-4" />
                        Generate enrollment token
                      </>
                    )}
                  </button>
                ) : (
                  <div
                    className="rounded-lg p-4"
                    style={{ background: 'var(--bg-2)', border: '1px solid var(--border)' }}
                  >
                    <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider mb-3" style={{ color: 'var(--emerald-400)' }}>
                      <Key className="h-3.5 w-3.5" />
                      Enrollment token · Expires in {timeRemaining}
                    </div>
                    <div className="flex items-center gap-3">
                      <code
                        className="flex-1 font-mono text-sm px-3 py-2 rounded-lg truncate"
                        style={{ background: 'var(--surface)', color: 'var(--fg)' }}
                      >
                        {displayToken}
                      </code>
                      <button
                        onClick={() => copy('token', newToken)}
                        className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                      >
                        {copied === 'token' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        Copy
                      </button>
                      <button
                        onClick={regenerateToken}
                        className="btn-sentinel btn-sentinel-ghost btn-sentinel-sm"
                      >
                        <RefreshCw className="h-4 w-4" />
                        Regenerate
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </WizardStep>

            {/* Step 2: Install the agent */}
            <WizardStep
              number={2}
              title="Install the agent"
              status={stepStatuses[2]}
            >
              <div className="space-y-4">
                {/* OS Tabs */}
                <div className="flex items-center gap-1">
                  <OsTabButton
                    os="windows"
                    active={activeOsTab === 'windows'}
                    onClick={() => setActiveOsTab('windows')}
                  />
                  <OsTabButton
                    os="macos"
                    active={activeOsTab === 'macos'}
                    onClick={() => setActiveOsTab('macos')}
                    preview
                  />
                  <OsTabButton
                    os="linux"
                    active={activeOsTab === 'linux'}
                    onClick={() => setActiveOsTab('linux')}
                    preview
                  />
                </div>

                {/* Instructions */}
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  {activeOsTab === 'windows' && 'Run from an elevated PowerShell on the target host:'}
                  {activeOsTab === 'macos' && 'macOS requires the signed DMG/Cask release with System Extension approval.'}
                  {activeOsTab === 'linux' && (downloadUrls.linuxX64 ? 'Run as root on the target Linux host:' : 'Linux binary is not published on this server yet.')}
                </p>

                {/* Code block */}
                <div
                  className="rounded-lg overflow-hidden"
                  style={{ background: 'var(--bg-2)', border: '1px solid var(--border)' }}
                >
                  <pre className="p-4 text-sm font-mono overflow-x-auto" style={{ color: 'var(--fg-2)' }}>
                    {commands[activeOsTab]}
                  </pre>
                </div>

                {/* Action buttons */}
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => copy('command', commands[activeOsTab])}
                    disabled={activeOsTab === 'macos' || (activeOsTab === 'linux' && !downloadUrls.linuxX64)}
                    className="btn-sentinel btn-sentinel-secondary"
                  >
                    {copied === 'command' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    Copy command
                  </button>
                  {activeOsTab === 'windows' && downloadUrls.windowsExe && (
                    <a
                      href={downloadUrls.windowsExe}
                      className="btn-sentinel btn-sentinel-secondary"
                    >
                      <Download className="h-4 w-4" />
                      Download EXE
                    </a>
                  )}
                  {activeOsTab === 'windows' && downloadUrls.windowsMsi && (
                    <a
                      href={downloadUrls.windowsMsi}
                      className="btn-sentinel btn-sentinel-secondary"
                    >
                      <Download className="h-4 w-4" />
                      Download MSI
                    </a>
                  )}
                  {activeOsTab === 'linux' && downloadUrls.linuxX64 && (
                    <a
                      href={downloadUrls.linuxX64}
                      className="btn-sentinel btn-sentinel-secondary"
                    >
                      <Download className="h-4 w-4" />
                      Download Linux
                    </a>
                  )}
                </div>

                {/* Trust badges */}
                <div className="flex items-center gap-4 pt-2">
                  <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
                    <ShieldCheck className="h-3.5 w-3.5" style={{ color: 'var(--emerald-400)' }} />
                    Runtime mTLS after enrollment
                  </div>
                  <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
                    <Lock className="h-3.5 w-3.5" style={{ color: 'var(--emerald-400)' }} />
                    Outbound only · no inbound port
                  </div>
                </div>
              </div>
            </WizardStep>

            {/* Step 3: Backend registers the agent */}
            <WizardStep
              number={3}
              title="Backend registers agent"
              status={stepStatuses[3]}
            >
              <div className="flex items-start justify-between gap-6">
                <div className="space-y-4">
                  <div
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium"
                    style={{
                      background: checkedInAgent ? 'var(--emerald-glow)' : 'var(--surface-2)',
                      color: checkedInAgent ? 'var(--emerald-400)' : 'var(--muted)',
                    }}
                  >
                    {checkedInAgent ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Clock className="h-3.5 w-3.5" />}
                    {checkedInAgent
                      ? 'Backend record found'
                      : currentToken?.consumed_agent_id
                        ? 'Waiting for agent inventory'
                        : agentsLoading
                          ? 'Checking token usage'
                          : 'Waiting for this token to be used'}
                  </div>

                  <div className="flex items-center gap-4">
                    {/* Animated spinner */}
                    <div
                      className="relative w-16 h-16 rounded-full flex items-center justify-center"
                      style={{ background: 'var(--surface-2)' }}
                    >
                      {!checkedInAgent && (
                        <div
                          className="absolute inset-0 rounded-full animate-spin"
                          style={{
                            border: '2px solid transparent',
                            borderTopColor: 'var(--emerald-500)',
                            animationDuration: '2s',
                          }}
                        />
                      )}
                      {checkedInAgent ? (
                        <CheckCircle2 className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
                      ) : (
                        <Shield className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                        {checkedInAgent
                          ? `${checkedInAgent.hostname || 'New endpoint'} is enrolled`
                          : currentToken?.consumed_agent_id
                            ? 'Token was consumed; waiting for inventory refresh'
                          : `Enrollment token expires in ${timeRemaining || '—'}`}
                      </p>
                      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                        {checkedInAgent
                          ? `Agent ID ${checkedInAgent.id}`
                          : currentToken?.consumed_agent_id
                            ? `Agent ID ${currentToken.consumed_agent_id}`
                          : agentsLoadError
                            ? `Agent list polling failed: ${agentsLoadError}`
                            : 'This page is waiting for the current one-time token to be consumed by an endpoint.'}
                      </p>
                      {checkedInAgent && (
                        <Link
                          href={`/app/agents/${checkedInAgent.id}`}
                          className="inline-flex items-center gap-1.5 text-xs font-medium mt-2"
                          style={{ color: 'var(--emerald-400)' }}
                        >
                          Open agent detail
                          <ExternalLink className="h-3.5 w-3.5" />
                        </Link>
                      )}
                    </div>
                  </div>
                </div>

                {/* Connection status indicators */}
                <div
                  className="rounded-lg p-4 space-y-3 min-w-[200px]"
                  style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
                >
                  <StatusIndicator label="Server URL" value={agentServerUrl} status="ok" />
                  <StatusIndicator label="mTLS" value={checkedInAgent ? 'Issued' : 'Required'} status={checkedInAgent ? 'ok' : 'pending'} />
                  <StatusIndicator label="CA reachable" value="Yes" status="ok" />
                  <StatusIndicator
                    label="Agent record"
                    value={checkedInAgent ? 'Created' : currentToken?.consumed_agent_id ? 'Token used' : agentsLoadError ? 'Check failed' : agentsLoading ? 'Polling' : 'Pending'}
                    status={checkedInAgent ? 'ok' : agentsLoadError ? 'error' : 'pending'}
                  />
                </div>
              </div>
            </WizardStep>

            {/* Step 4: Telemetry begins */}
            <WizardStep
              number={4}
              title="Telemetry begins"
              status={stepStatuses[4]}
            >
              <div className="space-y-3">
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  {checkedInAgent
                    ? 'The backend has accepted the endpoint identity. Telemetry and health updates will now appear in the operational views.'
                    : "Once telemetry starts you'll see events within seconds."}
                </p>
                <div className="flex items-center gap-3">
                  <Link href="/app/events" className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm">
                    Event History
                  </Link>
                  <Link href="/app/agents" className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm">
                    Agents
                  </Link>
                </div>
              </div>
            </WizardStep>
          </div>
        </div>

        {/* Right Sidebar */}
        <div className="w-80 flex-shrink-0 space-y-6">
          {/* How the connection works */}
          <div
            className="rounded-lg p-5"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
          >
            <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>
              How the connection works
            </h3>

            {/* Connection diagram */}
            <div className="space-y-3 mb-4">
              <ConnectionNode label="Endpoint" sublabel="PRIVATE" icon={Monitor} />
              <ConnectionArrow />
              <ConnectionNode label="mTLS" sublabel="" icon={Lock} highlight />
              <ConnectionArrow />
              <ConnectionNode label="Self-hosted backend" sublabel="PRIVATE" icon={Server} />
              <ConnectionArrow />
              <ConnectionNode label="Solana attestor" sublabel="PUBLIC" icon={Globe} />
            </div>

            <p className="text-xs" style={{ color: 'var(--muted)' }}>
              Agent connects outbound over mTLS. Your backend validates the certificate and forwards attestations to Solana for tamper-proof audit.
            </p>
          </div>

          {/* Agent identity */}
          <div
            className="rounded-lg p-5"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
          >
            <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>
              Agent identity
            </h3>

            <div className="space-y-3">
              <IdentityRow
                icon={Key}
                label="Public key"
                value={tenantPublicKey ? `${tenantPublicKey.substring(0, 8)}...${tenantPublicKey.substring(tenantPublicKey.length - 4)}` : 'Pending...'}
              />
              <IdentityRow
                icon={Shield}
                label="Issued by"
                value={caIssuer || 'ca:tamandua/2026'}
              />
              <IdentityRow
                icon={Clock}
                label="mTLS valid until"
                value={mtlsValidDays ? `${mtlsValidDays} days` : '47 days'}
              />
              <IdentityRow
                icon={Fingerprint}
                label="Hardware fingerprint"
                value="hashed locally · never sent"
                muted
              />
              <IdentityRow
                icon={Globe}
                label="Solana tenant pubkey"
                value={organizationId ? `${organizationId.substring(0, 8)}...` : 'Pending...'}
              />
            </div>
          </div>

          {/* Need help? */}
          <div
            className="rounded-lg p-5"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
          >
            <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>
              Need help?
            </h3>

            <div className="space-y-2">
              <HelpLink href="/docs/deployment" label="Read the deployment guide" />
              <HelpLink href="/docs/troubleshoot-mtls" label="Troubleshoot mTLS handshake" />
              <HelpLink href="/docs/threat-model" label="Threat model & hardening" />
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

// --- Component: Wizard Step ---
interface WizardStepProps {
  number: number
  title: string
  status: WizardStepStatus
  children: React.ReactNode
}

function WizardStep({ number, title, status, children }: WizardStepProps) {
  const isComplete = status === 'complete'
  const isActive = status === 'in_progress'
  const isWaiting = status === 'waiting'

  return (
    <div
      className={cn(
        'rounded-lg transition-all',
        isActive && 'ring-1',
      )}
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        ...(isActive && { ringColor: 'var(--emerald-500)' }),
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-4 p-5 pb-0">
        <div
          className={cn(
            'w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold flex-shrink-0',
          )}
          style={{
            background: isComplete ? 'var(--emerald-500)' : isActive ? 'var(--emerald-glow)' : 'var(--surface-2)',
            color: isComplete ? 'white' : isActive ? 'var(--emerald-400)' : 'var(--muted)',
            border: isActive ? '1px solid var(--emerald-500)' : '1px solid transparent',
          }}
        >
          {isComplete ? <Check className="h-4 w-4" /> : number}
        </div>
        <div className="flex-1 min-w-0">
          <h2
            className="text-base font-semibold"
            style={{ color: isWaiting ? 'var(--muted)' : 'var(--fg)' }}
          >
            {title}
          </h2>
        </div>
        {isComplete && (
          <span className="text-xs font-medium px-2 py-1 rounded" style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}>
            Complete
          </span>
        )}
        {isActive && (
          <span className="text-xs font-medium px-2 py-1 rounded" style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}>
            In progress
          </span>
        )}
        {isWaiting && (
          <span className="text-xs font-medium px-2 py-1 rounded" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
            Waiting
          </span>
        )}
      </div>

      {/* Content */}
      <div
        className={cn('p-5', isWaiting && 'opacity-50')}
      >
        {children}
      </div>
    </div>
  )
}

// --- Component: OS Tab Button ---
interface OsTabButtonProps {
  os: OsTab
  active: boolean
  onClick: () => void
  preview?: boolean
}

function OsTabButton({ os, active, onClick, preview }: OsTabButtonProps) {
  const labels: Record<OsTab, string> = {
    windows: 'Windows',
    macos: 'macOS',
    linux: 'Linux',
  }

  return (
    <button
      onClick={onClick}
      className={cn(
        'px-4 py-2 text-sm font-medium rounded-lg transition-colors',
      )}
      style={{
        background: active ? 'var(--emerald-glow)' : 'transparent',
        color: active ? 'var(--emerald-400)' : 'var(--muted)',
        border: active ? '1px solid var(--emerald-500)' : '1px solid transparent',
      }}
    >
      {labels[os]}
      {preview && (
        <span className="ml-1.5 text-[10px] uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>
          preview
        </span>
      )}
    </button>
  )
}

// --- Component: Status Indicator ---
interface StatusIndicatorProps {
  label: string
  value: string
  status: 'ok' | 'pending' | 'error'
}

function StatusIndicator({ label, value, status }: StatusIndicatorProps) {
  const colors = {
    ok: 'var(--emerald-400)',
    pending: 'var(--high)',
    error: 'var(--crit)',
  }

  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs" style={{ color: 'var(--muted)' }}>{label}</span>
      <div className="flex items-center gap-1.5">
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: colors[status] }}
        />
        <span className="text-xs font-mono" style={{ color: 'var(--fg-2)' }}>{value}</span>
      </div>
    </div>
  )
}

// --- Component: Connection Node ---
interface ConnectionNodeProps {
  label: string
  sublabel: string
  icon: React.ComponentType<{ className?: string }>
  highlight?: boolean
}

function ConnectionNode({ label, sublabel, icon: Icon, highlight }: ConnectionNodeProps) {
  return (
    <div
      className="flex items-center gap-3 p-3 rounded-lg"
      style={{
        background: highlight ? 'var(--emerald-glow)' : 'var(--surface-2)',
        border: highlight ? '1px solid var(--emerald-500)' : '1px solid var(--border)',
      }}
    >
      <Icon
        className="h-4 w-4 flex-shrink-0"
        style={{ color: highlight ? 'var(--emerald-400)' : 'var(--muted)' }}
      />
      <div className="min-w-0">
        <p className="text-xs font-medium" style={{ color: 'var(--fg)' }}>{label}</p>
        {sublabel && (
          <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>{sublabel}</p>
        )}
      </div>
    </div>
  )
}

// --- Component: Connection Arrow ---
function ConnectionArrow() {
  return (
    <div className="flex justify-center">
      <ChevronRight className="h-4 w-4 rotate-90" style={{ color: 'var(--subtle)' }} />
    </div>
  )
}

// --- Component: Identity Row ---
interface IdentityRowProps {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string
  muted?: boolean
}

function IdentityRow({ icon: Icon, label, value, muted }: IdentityRowProps) {
  return (
    <div className="flex items-start gap-3">
      <Icon className="h-4 w-4 flex-shrink-0 mt-0.5" style={{ color: 'var(--subtle)' }} />
      <div className="min-w-0">
        <p className="text-xs" style={{ color: 'var(--muted)' }}>{label}</p>
        <p
          className={cn('text-sm font-mono', muted && 'italic')}
          style={{ color: muted ? 'var(--subtle)' : 'var(--fg-2)' }}
        >
          {value}
        </p>
      </div>
    </div>
  )
}

// --- Component: Help Link ---
interface HelpLinkProps {
  href: string
  label: string
}

function HelpLink({ href, label }: HelpLinkProps) {
  return (
    <a
      href={href}
      className="flex items-center gap-2 text-sm transition-colors"
      style={{ color: 'var(--fg-2)' }}
      onMouseEnter={(e) => e.currentTarget.style.color = 'var(--emerald-400)'}
      onMouseLeave={(e) => e.currentTarget.style.color = 'var(--fg-2)'}
    >
      <ExternalLink className="h-3.5 w-3.5" />
      {label}
    </a>
  )
}
