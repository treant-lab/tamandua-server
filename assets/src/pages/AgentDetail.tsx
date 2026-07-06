import { useState, useEffect, useCallback, useMemo } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Monitor,
  Wifi,
  WifiOff,
  AlertCircle,
  AlertTriangle,
  Clock,
  Cpu,
  HardDrive,
  Activity,
  Shield,
  Network,
  FileSearch,
  Settings,
  RefreshCw,
  Play,
  Crosshair,
  Loader2,
  CheckCircle,
  XCircle,
  Globe,
  File,
  Server,
  MemoryStick,
  Disc,
  Gauge,
  ChevronDown,
  ChevronRight,
  Pause,
  Trash2,
  Radio,
  Clipboard,
  Terminal as TerminalIcon,
  Smartphone,
  Package,
  Lock,
  MapPin,
} from 'lucide-react'
import { cn, formatDate, formatRelativeTime, safeCapitalize, severityColor } from '@/lib/utils'
import { useAgentStatus, useEventStream, getConnectionStatusColor, getConnectionStatusText } from '@/hooks/useSocket'
import type { StreamEvent } from '@/hooks/useSocket'
import type { Agent, Alert, TelemetryEvent } from '@/types'
import axios from 'axios'
import { toast } from 'sonner'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Collector {
  name: string
  status: 'running' | 'stopped' | 'error'
  events_collected: number
  last_event_at: string | null
  error_message: string | null
}

interface HealthMetrics {
  cpu_usage: number
  memory_usage: number
  disk_usage: number
  cpu_history: number[]
  memory_history: number[]
  uptime_seconds: number
}

interface AgentConfig {
  [key: string]: unknown
}

interface EffectivePreventionPolicy {
  id: string
  name: string
  description?: string
  mode: 'detect_only' | 'detect_and_prevent'
  aggressiveness: 'disabled' | 'cautious' | 'moderate' | 'aggressive' | 'extra_aggressive'
  category_settings?: Array<{
    category: string
    aggressiveness: string
    mode: string
  }>
  network_containment?: {
    allow_dns?: boolean
    allowed_ips?: string[]
  }
}

interface AgentEvent {
  id: string
  event_type: string
  timestamp: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  summary: string
  payload: Record<string, unknown>
}

interface AgentDetailPageProps {
  agent: Agent
  collectors: Collector[]
  health: HealthMetrics | null
  events: AgentEvent[]
  alerts: Alert[]
  config: AgentConfig
}

type CapabilityMaturity = 'supported' | 'partial' | 'lab' | 'unavailable' | string

interface PlatformCapability {
  id: string
  name: string
  platform?: string
  maturity: CapabilityMaturity
  status?: CapabilityMaturity
  observed?: string
  detail?: string
}

type DataSourceKey = 'process' | 'file' | 'dns' | 'network' | 'registry' | 'driver' | 'ai' | 'ndr'
type DataSourceStatus = 'healthy' | 'stale' | 'missing'

interface AgentDataSourceHealth {
  agentId: string
  hostname?: string
  windowHours: number
  lastTelemetryAt: string | null
  sources: Array<{
    name: DataSourceKey
    status: DataSourceStatus
    count: number
    lastSeen: string | null
    missingReason: string | null
  }>
}

interface CliTokenPayload {
  token: string
  server: string
  agent_id: string
  hostname: string
  expires_at: string | null
  expires_in_seconds: number
  command: string
}

interface MobileOverview {
  agent_id: string
  mobile: boolean
  linked: boolean
  device: Record<string, any> | null
  command_device?: {
    id: string
    device_id?: string
    platform?: string
    status?: string
  } | null
  posture: Record<string, any> | null
  compliance: Record<string, any> | null
  app_inventory: {
    apps: Array<Record<string, any>>
    total: number
    high_risk?: number
    sideloaded?: number
  }
  app_guard: {
    events: Array<Record<string, any>>
    total_recent_events: number
    protected_apps?: Array<Record<string, any>>
    protected_total?: number
  }
  commands: Array<{
    id: string
    label: string
    destructive?: boolean
    execution_scope?: string
    supported_by_mobile_app?: boolean
  }>
  command_history?: Array<Record<string, any>>
  last_command?: Record<string, any> | null
}

// ---------------------------------------------------------------------------
// Event type icon map
// ---------------------------------------------------------------------------

const EVENT_TYPE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  process: Cpu,
  network: Globe,
  file: File,
  dns: Server,
  registry: Settings,
  alert: AlertTriangle,
}

// ---------------------------------------------------------------------------
// Mini gauge component
// ---------------------------------------------------------------------------

function UsageGauge({ value, label, icon: Icon, color }: {
  value: number
  label: string
  icon: React.ComponentType<{ className?: string }>
  color: string
}) {
  const clampedValue = Math.min(100, Math.max(0, value))
  const radius = 36
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (clampedValue / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-24 h-24">
        <svg className="w-24 h-24 -rotate-90" viewBox="0 0 80 80">
          <circle
            cx="40" cy="40" r={radius}
            stroke="var(--surface-alt)"
            strokeWidth="6"
            fill="none"
          />
          <circle
            cx="40" cy="40" r={radius}
            stroke="currentColor"
            className={color}
            strokeWidth="6"
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <Icon className={cn('h-4 w-4 mb-0.5', color)} />
          <span className="text-lg font-bold" style={{ color: 'var(--fg)' }}>{Math.round(clampedValue)}%</span>
        </div>
      </div>
      <span className="text-sm" style={{ color: 'var(--muted)' }}>{label}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Mini spark-line chart
// ---------------------------------------------------------------------------

function SparkLine({ data, color, height = 32 }: { data: number[]; color: string; height?: number }) {
  if (!data || data.length < 2) return null

  const max = Math.max(...data, 1)
  const width = 120
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width
    const y = height - (v / max) * height
    return `${x},${y}`
  }).join(' ')

  return (
    <svg width={width} height={height} className="inline-block">
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        className={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: Agent['status'] }) {
  const getStatusStyles = () => {
    switch (status) {
      case 'online':
        return {
          bg: 'rgba(52, 211, 153, 0.2)', // emerald-400 with alpha
          text: 'var(--emerald-400)',
          dot: 'var(--emerald-400)',
        }
      case 'degraded':
        return {
          bg: 'rgba(251, 191, 36, 0.2)', // yellow-400 with alpha
          text: 'var(--warn)',
          dot: 'var(--warn)',
        }
      case 'offline':
        return {
          bg: 'rgba(239, 68, 68, 0.2)', // red with alpha
          text: 'var(--crit)',
          dot: 'var(--crit)',
        }
      default:
        return {
          bg: 'var(--surface-alt)',
          text: 'var(--muted)',
          dot: 'var(--muted)',
        }
    }
  }

  const styles = getStatusStyles()

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
      style={{ backgroundColor: styles.bg, color: styles.text }}
    >
      <span
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: styles.dot }}
      />
      {safeCapitalize(status)}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Collector status badge
// ---------------------------------------------------------------------------

function CollectorStatusBadge({ status }: { status: Collector['status'] }) {
  const getStatusStyles = () => {
    switch (status) {
      case 'running':
        return {
          bg: 'rgba(52, 211, 153, 0.2)',
          text: 'var(--emerald-400)',
          dot: 'var(--emerald-400)',
          pulse: true,
        }
      case 'stopped':
        return {
          bg: 'var(--surface-alt)',
          text: 'var(--muted)',
          dot: 'var(--muted)',
          pulse: false,
        }
      case 'error':
        return {
          bg: 'rgba(239, 68, 68, 0.2)',
          text: 'var(--crit)',
          dot: 'var(--crit)',
          pulse: false,
        }
      default:
        return {
          bg: 'var(--surface-alt)',
          text: 'var(--muted)',
          dot: 'var(--muted)',
          pulse: false,
        }
    }
  }

  const styles = getStatusStyles()

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium"
      style={{ backgroundColor: styles.bg, color: styles.text }}
    >
      <span
        className={cn('h-1.5 w-1.5 rounded-full', styles.pulse && 'animate-pulse')}
        style={{ backgroundColor: styles.dot }}
      />
      {safeCapitalize(status)}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Quick action button
// ---------------------------------------------------------------------------

function QuickAction({ label, icon: Icon, color, onClick, loading, disabled, title }: {
  label: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  onClick: () => void
  loading?: boolean
  disabled?: boolean
  title?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      title={title}
      className={cn(
        'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors',
        disabled || loading
          ? 'cursor-not-allowed'
          : color
      )}
      style={disabled || loading ? { backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' } : undefined}
    >
      {loading ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        <Icon className="h-4 w-4" />
      )}
      {label}
    </button>
  )
}

// ---------------------------------------------------------------------------
// Confirmation dialog
// ---------------------------------------------------------------------------

function ConfirmDialog({ title, message, onConfirm, onCancel }: {
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div
        className="card-sentinel rounded-xl shadow-xl max-w-md w-full mx-4 p-6"
        style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>{title}</h3>
        <p className="text-sm mb-6" style={{ color: 'var(--muted)' }}>{message}</p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-colors hover:opacity-80"
            style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--fg)' }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors hover:opacity-90"
            style={{ backgroundColor: 'var(--crit)' }}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  )
}

function CliTokenDialog({
  payload,
  onClose,
  onCopy,
}: {
  payload: CliTokenPayload
  onClose: () => void
  onCopy: (text: string, label?: string) => void
}) {
  const loginCommand = `tamandua-ctl remote login --server ${payload.server} --token ${payload.token}`
  const shellCommand = `tamandua-ctl remote shell --agent-id ${payload.agent_id}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div
        className="card-sentinel rounded-xl shadow-xl max-w-3xl w-full mx-4 p-6"
        style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-start justify-between gap-4 mb-5">
          <div>
            <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Connect via CLI</h3>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Short-lived token for {payload.hostname || payload.agent_id}
              {payload.expires_at ? ` · expires ${formatRelativeTime(payload.expires_at)}` : ''}
            </p>
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors hover:opacity-80"
            style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--fg)' }}
          >
            Close
          </button>
        </div>

        <div className="space-y-4">
          <CommandBox
            label="Save CLI token"
            command={loginCommand}
            onCopy={() => onCopy(loginCommand, 'Login command copied')}
          />
          <CommandBox
            label="Open shell"
            command={shellCommand}
            onCopy={() => onCopy(shellCommand, 'Shell command copied')}
          />
          <CommandBox
            label="One-shot command"
            command={payload.command}
            onCopy={() => onCopy(payload.command, 'One-shot command copied')}
          />
        </div>
      </div>
    </div>
  )
}

function CommandBox({ label, command, onCopy }: { label: string; command: string; onCopy: () => void }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{label}</span>
        <button
          onClick={onCopy}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors hover:opacity-80"
          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--fg)' }}
        >
          <Clipboard className="h-3.5 w-3.5" />
          Copy
        </button>
      </div>
      <pre
        className="max-h-32 overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap break-all"
        style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--fg)', border: '1px solid var(--border)' }}
      >
        {command}
      </pre>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function AgentDetail({
  agent,
  collectors,
  health,
  events,
  alerts,
  config,
}: AgentDetailPageProps) {
  const agentPlatform = resolveAgentPlatform(agent)
  const reportedPlatformCapabilities = normalizePlatformCapabilities(
    (agent as Agent & { platformCapabilities?: PlatformCapability[]; platform_capabilities?: PlatformCapability[] }).platformCapabilities ||
      (agent as Agent & { platform_capabilities?: PlatformCapability[] }).platform_capabilities
  )
  const platformCapabilities = shouldUseMobileFallbackCapabilities(agentPlatform, reportedPlatformCapabilities)
    ? fallbackPlatformCapabilities(agentPlatform)
    : reportedPlatformCapabilities.length > 0
    ? reportedPlatformCapabilities
    : fallbackPlatformCapabilities(agentPlatform)
  const mobileAgent = isMobilePlatform(agentPlatform)
  const supportsLiveResponse = capabilityAvailable(platformCapabilities, 'live_response')
  const supportsNetworkIsolation = capabilityAvailable(platformCapabilities, 'network_isolation')
  const supportsHostResponse = !mobileAgent && supportsLiveResponse
  const unsupportedMobileActionTitle = mobileAgent
    ? 'This endpoint reports mobile posture/App Guard telemetry; host live response is not available for mobile yet.'
    : undefined
  const { connectionState: agentConnState, status: liveStatus } = useAgentStatus(agent.id)
  const {
    connectionState: eventConnState,
    events: liveEvents,
    clearEvents,
    pauseStream,
    resumeStream,
    isPaused,
  } = useEventStream(agent.id)
  const [executingAction, setExecutingAction] = useState<string | null>(null)
  const [showConfirm, setShowConfirm] = useState<{
    title: string
    message: string
    onConfirm: () => void
  } | null>(null)
  const [configExpanded, setConfigExpanded] = useState(false)
  const [performanceProfile, setPerformanceProfile] = useState<string>(
    (config?.performance_profile as string | undefined) || 'balanced'
  )
  const [savingProfile, setSavingProfile] = useState(false)
  const [effectivePolicy, setEffectivePolicy] = useState<EffectivePreventionPolicy | null>(null)
  const [policyLoading, setPolicyLoading] = useState(false)
  const [dataSourceHealth, setDataSourceHealth] = useState<AgentDataSourceHealth | null>(null)
  const [dataSourceHealthLoading, setDataSourceHealthLoading] = useState(false)
  const [dataSourceHealthError, setDataSourceHealthError] = useState<string | null>(null)
  const [cliToken, setCliToken] = useState<CliTokenPayload | null>(null)
  const [cliTokenLoading, setCliTokenLoading] = useState(false)
  const [mobileOverview, setMobileOverview] = useState<MobileOverview | null>(null)
  const [mobileOverviewLoading, setMobileOverviewLoading] = useState(false)
  const [mobileCommandLoading, setMobileCommandLoading] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    const loadEffectivePolicy = async () => {
      setPolicyLoading(true)
      try {
        const response = await axios.get(`/api/v1/prevention-policies/agent/${agent.id}`)
        if (!cancelled) {
          setEffectivePolicy(response.data?.data || null)
        }
      } catch {
        if (!cancelled) setEffectivePolicy(null)
      } finally {
        if (!cancelled) setPolicyLoading(false)
      }
    }

    loadEffectivePolicy()

    return () => {
      cancelled = true
    }
  }, [agent.id])

  const loadDataSourceHealth = useCallback(async () => {
    setDataSourceHealthLoading(true)
    setDataSourceHealthError(null)
    try {
      const response = await axios.get('/api/v1/agents/data-sources/health?hours=24')
      const rows = Array.isArray(response.data?.data) ? response.data.data : []
      const normalized = rows.map(normalizeAgentDataSourceHealth).filter(Boolean) as AgentDataSourceHealth[]
      setDataSourceHealth(normalized.find(row => row.agentId === agent.id) || null)
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number } }
      setDataSourceHealth(null)
      setDataSourceHealthError(
        axiosError.response?.status
          ? `Data source health unavailable (${axiosError.response.status})`
          : 'Data source health unavailable'
      )
    } finally {
      setDataSourceHealthLoading(false)
    }
  }, [agent.id])

  useEffect(() => {
    loadDataSourceHealth()
  }, [loadDataSourceHealth])

  const loadMobileOverview = useCallback(async () => {
    if (!mobileAgent) {
      setMobileOverview(null)
      return
    }

    setMobileOverviewLoading(true)
    try {
      const response = await axios.get(`/api/v1/mobile/agents/${agent.id}/overview`)
      setMobileOverview(response.data?.data || null)
    } catch {
      setMobileOverview(null)
    } finally {
      setMobileOverviewLoading(false)
    }
  }, [agent.id, mobileAgent])

  useEffect(() => {
    loadMobileOverview()
  }, [loadMobileOverview])

  const handleProfileChange = async (profile: string) => {
    setSavingProfile(true)
    try {
      await axios.put(`/api/v1/agents/${agent.id}/config`, {
        config: { performance_profile: profile }
      })
      setPerformanceProfile(profile)
      toast.success(`Performance profile changed to ${profile}`)
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } }
      toast.error(axiosError.response?.data?.error || 'Failed to update profile')
    } finally {
      setSavingProfile(false)
    }
  }

  // Merge live WebSocket status with Inertia props (props = base, WS = incremental overlay)
  const displayAgent = useMemo(() => ({
    ...agent,
    ...(liveStatus ? {
      status: liveStatus.status,
      last_seen: liveStatus.lastSeen ? new Date(liveStatus.lastSeen).toISOString() : agent.last_seen,
    } : {}),
  }), [agent, liveStatus])

  const currentStatus = displayAgent.status
  const rawCpu = Number(liveStatus?.cpuUsage ?? health?.cpu_usage ?? 0)
  const currentCpu = Number.isFinite(rawCpu) ? rawCpu : 0
  const rawMemory = Number(liveStatus?.memoryUsage ?? health?.memory_usage ?? 0)
  const currentMemory = Number.isFinite(rawMemory) ? rawMemory : 0
  const currentEventsPerMinute = liveStatus?.eventsPerMinute ?? null

  // Combine static events with live stream: live events first, then static, deduped by id
  const combinedEvents = useMemo(() => {
    const seen = new Set<string>()
    const merged: Array<AgentEvent | (StreamEvent & { _live: true })> = []

    // Live events take priority (newest first)
    for (const ev of liveEvents) {
      if (!seen.has(ev.id)) {
        seen.add(ev.id)
        merged.push({ ...ev, _live: true as const })
      }
    }

    // Static events from props fill in behind
    for (const ev of events) {
      if (!seen.has(ev.id)) {
        seen.add(ev.id)
        merged.push(ev)
      }
    }

    return merged
  }, [events, liveEvents])

  // -------------------------------------------------------------------
  // Response actions
  // -------------------------------------------------------------------

  const executeAction = useCallback(async (url: string, params: Record<string, unknown> = {}, label: string = '') => {
    setExecutingAction(label)
    try {
      await axios.post(url, {
        agent_id: agent.id,
        ...params,
      })
      toast.success(`Action "${label}" executed successfully`)
      router.reload()
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string; message?: string } } }
      toast.error(axiosError.response?.data?.error || axiosError.response?.data?.message || `Failed to execute ${label}`)
    } finally {
      setExecutingAction(null)
    }
  }, [agent.id])

  const handleIsolate = () => {
    if (!supportsNetworkIsolation) {
      toast.error('Network isolation is not available for this endpoint platform')
      return
    }
    setShowConfirm({
      title: 'Isolate Host',
      message: `This will isolate "${agent.hostname}" from the network. The agent will only be able to communicate with the management server. Are you sure?`,
      onConfirm: () => {
        setShowConfirm(null)
        executeAction(`/api/v1/agents/${agent.id}/isolate`, {}, 'isolate')
      },
    })
  }

  const handleUnisolate = () => {
    if (!supportsNetworkIsolation) {
      toast.error('Network isolation is not available for this endpoint platform')
      return
    }
    executeAction(`/api/v1/agents/${agent.id}/unisolate`, {}, 'unisolate')
  }

  const handleScan = () => {
    if (!supportsHostResponse) {
      toast.error('Host scan response is not available for this endpoint platform')
      return
    }
    executeAction('/api/v1/response/scan', { path: '/', recursive: true, max_depth: 5 }, 'scan')
  }

  const handleRestartAgent = () => {
    if (!supportsHostResponse) {
      toast.error('Agent restart is not available for this endpoint platform')
      return
    }
    setShowConfirm({
      title: 'Restart Agent',
      message: `This will restart the Tamandua agent on "${agent.hostname}". There will be a brief gap in monitoring. Are you sure?`,
      onConfirm: () => {
        setShowConfirm(null)
        executeAction(`/api/v1/agents/${agent.id}/restart`, {}, 'restart')
      },
    })
  }

  const handleCollectForensics = () => {
    if (!supportsHostResponse) {
      toast.error('Forensics collection is not available for this endpoint platform')
      return
    }
    executeAction('/api/v1/response/collect', { path: '/', type: 'memory' }, 'forensics')
  }

  const handleGenerateCliToken = async () => {
    if (!supportsHostResponse) {
      toast.error('Live response shell is not available for this endpoint platform')
      return
    }
    setCliTokenLoading(true)
    try {
      const response = await axios.post(`/api/v1/live-response/${agent.id}/cli-token`, {
        ttl_minutes: 15,
        server_url: window.location.origin,
      })
      setCliToken(response.data as CliTokenPayload)
      toast.success('CLI token generated')
    } catch (error: unknown) {
      const message =
        (error as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        'Failed to generate CLI token'
      toast.error(message)
    } finally {
      setCliTokenLoading(false)
    }
  }

  const handleMobileCommand = async (command: string) => {
    const commandDeviceId = mobileOverview?.command_device?.id
    const legacyDeviceId = mobileOverview?.device?.id
    if (!commandDeviceId && !legacyDeviceId) {
      toast.error('Mobile device link is not available for this endpoint')
      return
    }

    setMobileCommandLoading(command)
    try {
      if (commandDeviceId) {
        await axios.post('/api/v1/mobile/v2/commands', {
          device_id: commandDeviceId,
          command_type: command,
          payload: {},
        })
      } else {
        await axios.post(`/api/v1/mobile/devices/${legacyDeviceId}/commands/${command}`, {})
      }
      toast.success(`Mobile ${command} command queued`)
      loadMobileOverview()
    } catch (error: unknown) {
      const message =
        (error as { response?: { data?: { error?: string; message?: string } } })?.response?.data?.error ||
        (error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        `Failed to send mobile ${command} command`
      toast.error(message)
    } finally {
      setMobileCommandLoading(null)
    }
  }

  const copyText = async (text: string, label = 'Copied') => {
    await navigator.clipboard.writeText(text)
    toast.success(label)
  }

  // Format uptime
  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    if (days > 0) return `${days}d ${hours}h ${minutes}m`
    if (hours > 0) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }

  return (
    <MainLayout title="">
      <Head title={`${agent.hostname} - Tamandua EDR`} />

      {/* Confirmation dialog */}
      {showConfirm && (
        <ConfirmDialog
          title={showConfirm.title}
          message={showConfirm.message}
          onConfirm={showConfirm.onConfirm}
          onCancel={() => setShowConfirm(null)}
        />
      )}

      {cliToken && (
        <CliTokenDialog
          payload={cliToken}
          onClose={() => setCliToken(null)}
          onCopy={copyText}
        />
      )}

      <div className="space-y-6">
        {/* ================================================================
            Agent Info Header
            ================================================================ */}
        <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/agents')}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface-alt)' }}
              >
                <ArrowLeft className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
              <div className="p-3 rounded-xl bg-primary-600/20">
                <Monitor className="h-8 w-8 text-primary-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{agent.hostname}</h1>
                  <StatusBadge status={currentStatus} />
                </div>
                <div className="flex items-center gap-4 mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                  <span className="font-mono">{agent.ip_address}</span>
                  <span className="flex items-center gap-1">
                    <HardDrive className="h-3.5 w-3.5" />
                    {agent.os_type} {agent.os_version}
                  </span>
                  <span className="flex items-center gap-1">
                    <Shield className="h-3.5 w-3.5" />
                    v{agent.agent_version}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Last seen: {formatDate(displayAgent.last_seen)}
                  </span>
                  {currentEventsPerMinute !== null && (
                    <span className="flex items-center gap-1">
                      <Gauge className="h-3.5 w-3.5" />
                      {Math.round(currentEventsPerMinute)} events/min
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* Live connection indicator */}
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}
              >
                <span className={cn('h-2 w-2 rounded-full', getConnectionStatusColor(agentConnState))} />
                <span className="text-xs" style={{ color: 'var(--muted)' }}>{getConnectionStatusText(agentConnState)}</span>
                {agentConnState === 'connected' && (
                  <Radio className="h-3 w-3 animate-pulse" style={{ color: 'var(--emerald-400)' }} />
                )}
              </div>
              <button
                onClick={() => router.reload()}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface-alt)' }}
                title="Refresh"
              >
                <RefreshCw className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
            </div>
          </div>
        </div>

        {/* ================================================================
            Health Metrics
            ================================================================ */}
        <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Health Metrics</h2>

          {health ? (
            <div className="flex items-start gap-8">
              <div className="flex items-center gap-8">
                <UsageGauge
                  value={currentCpu}
                  label="CPU"
                  icon={Cpu}
                  color={currentCpu > 90 ? 'text-red-400' : currentCpu > 70 ? 'text-yellow-400' : 'text-green-400'}
                />
                <UsageGauge
                  value={currentMemory}
                  label="Memory"
                  icon={MemoryStick}
                  color={currentMemory > 90 ? 'text-red-400' : currentMemory > 70 ? 'text-yellow-400' : 'text-green-400'}
                />
                <UsageGauge
                  value={Number.isFinite(health.disk_usage) ? health.disk_usage : 0}
                  label="Disk"
                  icon={Disc}
                  color={(health.disk_usage || 0) > 90 ? 'text-red-400' : (health.disk_usage || 0) > 70 ? 'text-yellow-400' : 'text-green-400'}
                />
              </div>

              <div className="flex-1 space-y-3 ml-4">
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span style={{ color: 'var(--muted)' }}>CPU History</span>
                    <span className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>{Math.round(currentCpu)}%</span>
                  </div>
                  <SparkLine data={health.cpu_history} color="text-cyan-400" />
                </div>
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span style={{ color: 'var(--muted)' }}>Memory History</span>
                    <span className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>{Math.round(currentMemory)}%</span>
                  </div>
                  <SparkLine data={health.memory_history} color="text-violet-400" />
                </div>
                {health.uptime_seconds > 0 && (
                  <div className="text-sm" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                    Uptime: {formatUptime(health.uptime_seconds)}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
              <Activity className="h-10 w-10 mx-auto mb-2 opacity-50" />
              <p>No health metrics available</p>
            </div>
          )}
        </div>

        <DataSourcesHealthCard
          health={dataSourceHealth}
          loading={dataSourceHealthLoading}
          error={dataSourceHealthError}
          onRefresh={loadDataSourceHealth}
        />

        <PlatformCapabilitiesPanel capabilities={platformCapabilities} />

        {(mobileAgent || mobileOverview?.mobile) && (
          <MobileEndpointPanel
            overview={mobileOverview}
            loading={mobileOverviewLoading}
            commandLoading={mobileCommandLoading}
            onCommand={handleMobileCommand}
            onRefresh={loadMobileOverview}
          />
        )}

        {/* Performance Profile */}
        <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
          <div className="mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Collection Performance Profile</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Controls collector frequency and resource usage. Blocking decisions are handled separately by the prevention policy below.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-4">
            {([
              {
                id: 'lightweight',
                label: 'Lightweight',
                desc: 'Minimal resource usage. Basic process and file monitoring only.',
                color: 'border-green-500 bg-green-500/10 text-green-400',
                icon: '\u{1FAB6}',
              },
              {
                id: 'balanced',
                label: 'Balanced',
                desc: 'Moderate resource usage. All core collectors at standard intervals.',
                color: 'border-blue-500 bg-blue-500/10 text-blue-400',
                icon: '\u2696\uFE0F',
              },
              {
                id: 'aggressive',
                label: 'Aggressive',
                desc: 'Maximum detection. All collectors at high frequency, real-time analysis.',
                color: 'border-red-500 bg-red-500/10 text-red-400',
                icon: '\uD83D\uDD25',
              },
            ] as const).map((profile) => (
              <button
                key={profile.id}
                onClick={() => handleProfileChange(profile.id)}
                disabled={savingProfile}
                className={cn(
                  'p-4 rounded-xl border-2 text-left transition-all',
                  performanceProfile === profile.id
                    ? profile.color
                    : 'hover:opacity-80'
                )}
                style={performanceProfile !== profile.id ? {
                  borderColor: 'var(--border)',
                  backgroundColor: 'var(--surface-alt)',
                  color: 'var(--muted)',
                } : undefined}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">{profile.icon}</span>
                  <span className="font-semibold" style={{ color: performanceProfile === profile.id ? undefined : 'var(--fg)' }}>{profile.label}</span>
                  {performanceProfile === profile.id && (
                    <CheckCircle className="h-4 w-4 ml-auto" />
                  )}
                </div>
                <p className="text-xs opacity-80">{profile.desc}</p>
              </button>
            ))}
          </div>
          {savingProfile && (
            <div className="mt-3 flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
              <Loader2 className="h-4 w-4 animate-spin" />
              Sending profile update to agent...
            </div>
          )}
        </div>

        {/* Effective Prevention Policy */}
        <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Effective Prevention Policy</h2>
              <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                Defines whether detections only alert or can trigger automatic containment, quarantine, process termination, or network blocks.
              </p>
            </div>
            <button
              onClick={() => router.visit('/app/prevention-policies')}
              className="px-3 py-2 rounded-lg text-sm font-medium transition-colors hover:opacity-80"
              style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--fg)', border: '1px solid var(--border)' }}
            >
              Manage Policies
            </button>
          </div>

          {policyLoading ? (
            <div className="mt-4 flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading effective policy...
            </div>
          ) : effectivePolicy ? (
            <div className="mt-5 grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Policy</p>
                <p className="mt-1 font-semibold" style={{ color: 'var(--fg)' }}>{effectivePolicy.name}</p>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Mode</p>
                <p className="mt-1 font-semibold" style={{ color: effectivePolicy.mode === 'detect_and_prevent' ? 'var(--emerald-400)' : 'var(--med)' }}>
                  {effectivePolicy.mode === 'detect_and_prevent' ? 'Detect & Prevent' : 'Detect Only'}
                </p>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Aggressiveness</p>
                <p className="mt-1 font-semibold capitalize" style={{ color: 'var(--fg)' }}>
                  {effectivePolicy.aggressiveness.replace(/_/g, ' ')}
                </p>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Category Overrides</p>
                <p className="mt-1 font-semibold" style={{ color: 'var(--fg)' }}>
                  {effectivePolicy.category_settings?.length ?? 0}
                </p>
              </div>
            </div>
          ) : (
            <div className="mt-4 p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                No policy data available for this agent. The backend will fall back to the default prevention policy if one exists.
              </p>
            </div>
          )}
        </div>

        {/* Two-column layout: collectors + response actions */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ==============================================================
              Active Collectors
              ============================================================== */}
          <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Active Collectors</h2>
            </div>
            <div className="divide-y max-h-[360px] overflow-y-auto overflow-x-hidden custom-scrollbar" style={{ borderColor: 'var(--border)' }}>
              {collectors.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <Settings className="h-10 w-10 mx-auto mb-2 opacity-50" />
                  <p>No collectors reported</p>
                </div>
              ) : (
                collectors.map((collector) => (
                  <div
                    key={collector.name}
                    className="p-4 flex items-center justify-between transition-colors hover:opacity-90"
                    style={{ borderColor: 'var(--border)' }}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="p-2 rounded-lg"
                        style={{
                          backgroundColor: collector.status === 'running'
                            ? 'rgba(52, 211, 153, 0.1)'
                            : collector.status === 'error'
                              ? 'rgba(239, 68, 68, 0.1)'
                              : 'var(--surface-alt)'
                        }}
                      >
                        <Activity
                          className="h-4 w-4"
                          style={{
                            color: collector.status === 'running'
                              ? 'var(--emerald-400)'
                              : collector.status === 'error'
                                ? 'var(--crit)'
                                : 'var(--muted)'
                          }}
                        />
                      </div>
                      <div>
                        <p className="text-sm font-medium capitalize" style={{ color: 'var(--fg)' }}>{collector.name.replace(/_/g, ' ')}</p>
                        <p className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                          {collector.events_collected.toLocaleString()} events
                          {collector.last_event_at && ` \u00b7 Last: ${formatDate(collector.last_event_at)}`}
                        </p>
                        {collector.error_message && (
                          <p className="text-xs mt-0.5" style={{ color: 'var(--crit)' }}>{collector.error_message}</p>
                        )}
                      </div>
                    </div>
                    <CollectorStatusBadge status={collector.status} />
                  </div>
                ))
              )}
            </div>
          </div>

          {/* ==============================================================
              Response Actions
              ============================================================== */}
          <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Quick Actions</h2>
            </div>
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <QuickAction
                  label="Isolate Host"
                  icon={Network}
                  color="bg-red-600/20 text-red-400 hover:bg-red-600/30 border border-red-500/30"
                  onClick={handleIsolate}
                  loading={executingAction === 'isolate'}
                  disabled={!!executingAction || !supportsNetworkIsolation}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Remove Isolation"
                  icon={Network}
                  color="bg-green-600/20 text-green-400 hover:bg-green-600/30 border border-green-500/30"
                  onClick={handleUnisolate}
                  loading={executingAction === 'unisolate'}
                  disabled={!!executingAction || !supportsNetworkIsolation}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Full Scan"
                  icon={FileSearch}
                  color="bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 border border-blue-500/30"
                  onClick={handleScan}
                  loading={executingAction === 'scan'}
                  disabled={!!executingAction || !supportsHostResponse}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Restart Agent"
                  icon={RefreshCw}
                  color="bg-yellow-600/20 text-yellow-400 hover:bg-yellow-600/30 border border-yellow-500/30"
                  onClick={handleRestartAgent}
                  loading={executingAction === 'restart'}
                  disabled={!!executingAction || !supportsHostResponse}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Collect Forensics"
                  icon={FileSearch}
                  color="bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 border border-purple-500/30"
                  onClick={handleCollectForensics}
                  loading={executingAction === 'forensics'}
                  disabled={!!executingAction || !supportsHostResponse}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Connect via CLI"
                  icon={TerminalIcon}
                  color="bg-cyan-600/20 text-cyan-300 hover:bg-cyan-600/30 border border-cyan-500/30"
                  onClick={handleGenerateCliToken}
                  loading={cliTokenLoading}
                  disabled={cliTokenLoading || !supportsHostResponse}
                  title={unsupportedMobileActionTitle}
                />
                <QuickAction
                  label="Response Console"
                  icon={Crosshair}
                  color="bg-slate-600/20 text-slate-300 hover:bg-slate-600/30 border border-slate-500/30"
                  onClick={() => router.visit('/app/response')}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Two-column layout: events + alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ==============================================================
              Recent Events (live stream + static)
              ============================================================== */}
          <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recent Events</h2>
                  {eventConnState === 'connected' && (
                    <span
                      className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium"
                      style={{ backgroundColor: 'rgba(52, 211, 153, 0.1)', color: 'var(--emerald-400)' }}
                    >
                      <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ backgroundColor: 'var(--emerald-400)' }} />
                      LIVE
                    </span>
                  )}
                  {isPaused && (
                    <span
                      className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium"
                      style={{ backgroundColor: 'rgba(251, 191, 36, 0.1)', color: 'var(--warn)' }}
                    >
                      <Pause className="h-2.5 w-2.5" />
                      PAUSED
                    </span>
                  )}
                </div>
                <span className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                  {liveEvents.length > 0
                    ? `${liveEvents.length} live + ${events.length} historical`
                    : `${events.length} events`}
                </span>
              </div>
              {/* Stream controls */}
              <div className="flex items-center gap-2">
                {isPaused ? (
                  <button
                    onClick={resumeStream}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors"
                    style={{ backgroundColor: 'rgba(52, 211, 153, 0.1)', color: 'var(--emerald-400)' }}
                  >
                    <Play className="h-3 w-3" />
                    Resume
                  </button>
                ) : (
                  <button
                    onClick={pauseStream}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors"
                    style={{ backgroundColor: 'rgba(251, 191, 36, 0.1)', color: 'var(--warn)' }}
                  >
                    <Pause className="h-3 w-3" />
                    Pause
                  </button>
                )}
                <button
                  onClick={clearEvents}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors"
                  style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                >
                  <Trash2 className="h-3 w-3" />
                  Clear Live
                </button>
              </div>
            </div>
            <div className="divide-y max-h-[480px] overflow-y-auto overflow-x-hidden custom-scrollbar" style={{ borderColor: 'var(--border)' }}>
              {combinedEvents.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <Activity className="h-10 w-10 mx-auto mb-2 opacity-50" />
                  <p>No recent events</p>
                </div>
              ) : (
                combinedEvents.map((event) => {
                  const isLive = '_live' in event && event._live
                  const eventType = 'event_type' in event ? event.event_type : ('eventType' in event ? event.eventType : 'unknown')
                  const eventTimestamp = 'timestamp' in event
                    ? (typeof event.timestamp === 'number' ? new Date(event.timestamp).toISOString() : event.timestamp)
                    : ''
                  const Icon = EVENT_TYPE_ICONS[eventType] || Activity
                  return (
                    <div
                      key={event.id}
                      className={cn(
                        'p-3 transition-colors',
                        isLive && 'border-l-2'
                      )}
                      style={{
                        borderColor: 'var(--border)',
                        ...(isLive ? {
                          borderLeftColor: 'rgba(52, 211, 153, 0.6)',
                          backgroundColor: 'rgba(52, 211, 153, 0.03)',
                        } : {})
                      }}
                    >
                      <div className="flex items-start gap-3">
                        <div className={cn(
                          'p-1.5 rounded-lg mt-0.5',
                          severityColor(event.severity)
                        )}>
                          <Icon className="h-3.5 w-3.5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm truncate" style={{ color: 'var(--fg)' }}>{event.summary}</span>
                            <span className={cn(
                              'px-1.5 py-0.5 rounded text-[10px] font-medium shrink-0',
                              severityColor(event.severity)
                            )}>
                              {event.severity}
                            </span>
                            {isLive && (
                              <span
                                className="px-1.5 py-0.5 rounded text-[10px] font-medium shrink-0"
                                style={{ backgroundColor: 'rgba(52, 211, 153, 0.1)', color: 'var(--emerald-400)' }}
                              >
                                live
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                            <span>{eventType}</span>
                            <span>{formatDate(eventTimestamp)}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>

          {/* ==============================================================
              Recent Alerts
              ============================================================== */}
          <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recent Alerts</h2>
              <span className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>{alerts.length} alerts</span>
            </div>
            <div className="divide-y max-h-[480px] overflow-y-auto overflow-x-hidden custom-scrollbar" style={{ borderColor: 'var(--border)' }}>
              {alerts.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <Shield className="h-10 w-10 mx-auto mb-2 opacity-50" />
                  <p>No recent alerts</p>
                </div>
              ) : (
                alerts.map((alert) => (
                  <a
                    key={alert.id}
                    href={`/app/alerts/${alert.id}`}
                    className="block p-3 transition-colors hover:opacity-90"
                    style={{ borderColor: 'var(--border)' }}
                  >
                    <div className="flex items-start gap-3">
                      <div className={cn('p-1.5 rounded-lg mt-0.5', severityColor(alert.severity))}>
                        <AlertTriangle className="h-3.5 w-3.5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{alert.title}</span>
                          <span className={cn(
                            'px-1.5 py-0.5 rounded text-[10px] font-medium shrink-0',
                            severityColor(alert.severity)
                          )}>
                            {alert.severity}
                          </span>
                          <AlertStatusBadge status={alert.status} />
                        </div>
                        <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--muted)' }}>{alert.description}</p>
                        <div className="flex items-center gap-2 mt-0.5 text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                          <span>Score: {alert.threatScore}</span>
                          <span>{formatDate(alert.createdAt)}</span>
                        </div>
                      </div>
                    </div>
                  </a>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ================================================================
            Agent Configuration
            ================================================================ */}
        <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
          <button
            onClick={() => setConfigExpanded(!configExpanded)}
            className="w-full p-4 flex items-center justify-between transition-colors rounded-xl hover:opacity-90"
          >
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Agent Configuration</h2>
            {configExpanded ? (
              <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
            ) : (
              <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
            )}
          </button>
          {configExpanded && (
            <div className="px-4 pb-4">
              {Object.keys(config).length === 0 ? (
                <p className="text-sm" style={{ color: 'var(--muted)' }}>No configuration data available</p>
              ) : (
                <div
                  className="rounded-lg p-4 overflow-y-auto overflow-x-hidden max-h-[400px] custom-scrollbar"
                  style={{ backgroundColor: 'var(--surface-alt)' }}
                >
                  <table className="w-full text-sm">
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        <th className="text-left py-2 pr-4 font-medium" style={{ color: 'var(--muted)' }}>Key</th>
                        <th className="text-left py-2 font-medium" style={{ color: 'var(--muted)' }}>Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                      {Object.entries(config).map(([key, value]) => (
                        <tr key={key} className="hover:opacity-80">
                          <td className="py-2 pr-4 font-mono text-xs" style={{ color: 'var(--fg)' }}>{key}</td>
                          <td className="py-2 font-mono text-xs break-all" style={{ color: 'var(--muted)' }}>
                            {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ---------------------------------------------------------------------------
// Mobile endpoint panel
// ---------------------------------------------------------------------------

function MobileEndpointPanel({
  overview,
  loading,
  commandLoading,
  onCommand,
  onRefresh,
}: {
  overview: MobileOverview | null
  loading: boolean
  commandLoading: string | null
  onCommand: (command: string) => void
  onRefresh: () => void
}) {
  const linked = !!overview?.linked && !!overview.device
  const posture = overview?.posture || {}
  const apps = overview?.app_inventory?.apps || []
  const appGuardEvents = overview?.app_guard?.events || []
  const device = overview?.device || {}
  const highRiskApps = Number(overview?.app_inventory?.high_risk ?? 0)
  const sideloadedApps = Number(overview?.app_inventory?.sideloaded ?? 0)
  const protectedApps = overview?.app_guard?.protected_apps || []
  const protectedTotal = Number(overview?.app_guard?.protected_total ?? protectedApps.length)
  const commandHistory = overview?.command_history || []
  const mdmProvider = device.mdm?.provider || device.mdm_provider
  const mdmCompliance = device.mdm?.compliance_status || posture.mdm_compliance_status
  const deviceLabel =
    device.device_name ||
    [device.model, device.os_version].filter(Boolean).join(' / ') ||
    device.device_id ||
    'mobile endpoint'
  const ownerLabel = device.user_email || device.owner_email || device.user_name || 'not assigned'

  return (
    <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Smartphone className="h-5 w-5" /> Mobile Endpoint
          </h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            Mobile posture, app inventory, App Guard signals, and MDM-safe commands.
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm border disabled:opacity-50 hover:bg-[var(--surface-2)]"
          style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {loading && !overview ? (
        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading mobile endpoint data...
        </div>
      ) : !linked ? (
        <div className="rounded-lg border p-4 text-sm" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}>
          Mobile platform detected, but no mobile device record is linked to this agent yet.
        </div>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-3">
            <MobileMetric
              label="Risk"
              value={formatMobileRiskScore(posture.risk_score)}
              tone={mobileRiskTone(posture.risk_score)}
            />
            <MobileMetric label="MDM" value={formatMobileProvider(mdmProvider)} />
            <MobileMetric label="Apps" value={String(overview.app_inventory?.total ?? apps.length)} />
            <MobileMetric label="High risk" value={String(highRiskApps)} tone={highRiskApps > 0 ? 'high' : 'ok'} />
            <MobileMetric label="Sideloaded" value={String(sideloadedApps)} tone={sideloadedApps > 0 ? 'high' : 'ok'} />
            <MobileMetric label="App Guard" value={String(overview.app_guard?.total_recent_events ?? appGuardEvents.length)} />
          </div>

          <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 text-sm">
              <MobileFact label="Device" value={deviceLabel} />
              <MobileFact label="Device ID" value={device.device_id || posture.device_id || 'not reported'} />
              <MobileFact label="User" value={ownerLabel} />
              <MobileFact label="Last assessment" value={formatMobileTimestamp(posture.last_assessment || device.last_seen_at)} />
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Shield className="h-4 w-4" /> Posture
              </h3>
              <div className="space-y-2 text-sm">
                <MobileFact label="Compromised" value={posture.jailbroken_or_rooted ? 'Yes' : 'No'} danger={!!posture.jailbroken_or_rooted} />
                <MobileFact label="Passcode" value={formatMobileBoolean(posture.passcode_enabled)} danger={posture.passcode_enabled === false} />
                <MobileFact label="Encryption" value={formatMobileBoolean(posture.encryption_enabled)} danger={posture.encryption_enabled === false} />
                <MobileFact label="USB debugging" value={formatMobileBoolean(posture.usb_debugging_enabled)} danger={posture.usb_debugging_enabled === true} />
                <MobileFact label="Developer mode" value={formatMobileBoolean(posture.developer_mode_enabled)} danger={posture.developer_mode_enabled === true} />
                <MobileFact label="Compliance" value={overview.compliance?.local_compliant === false ? 'Needs review' : 'Local checks pass'} danger={overview.compliance?.local_compliant === false} />
                <MobileFact label="MDM compliance" value={mdmCompliance || 'not reported'} danger={String(mdmCompliance || '').toLowerCase().includes('non')} />
              </div>
            </div>

            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Package className="h-4 w-4" /> App Inventory
              </h3>
              {apps.length === 0 ? (
                <p className="text-sm" style={{ color: 'var(--muted)' }}>No app inventory reported yet</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar">
                  {apps.slice(0, 8).map(app => (
                    <div key={String(app.id || app.bundle_id)} className="flex items-center justify-between gap-3 text-sm">
                      <span className="truncate" style={{ color: 'var(--fg)' }}>{app.app_name || app.bundle_id}</span>
                      <span className="text-xs shrink-0" style={{ color: app.risk_level === 'high' || app.risk_level === 'critical' ? 'var(--high)' : 'var(--muted)' }}>
                        {app.risk_level || 'not scored'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Activity className="h-4 w-4" /> App Guard
              </h3>
              {appGuardEvents.length === 0 ? (
                <div className="space-y-2 text-sm">
                  <p style={{ color: 'var(--muted)' }}>No App Guard events in the recent mobile window</p>
                  <MobileFact label="Protected apps" value={String(protectedTotal)} />
                </div>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar">
                  <MobileFact label="Protected apps" value={String(protectedTotal)} />
                  {appGuardEvents.slice(0, 8).map(event => (
                    <div key={String(event.id)} className="text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate" style={{ color: 'var(--fg)' }}>{event.event_type || event.title}</span>
                        <span className="text-xs shrink-0" style={{ color: severityTextColor(event.severity) }}>{event.severity || 'info'}</span>
                      </div>
                      <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>{event.app_bundle_id || event.app_name || 'protected app'}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {(overview.commands || []).map(command => (
              <button
                key={command.id}
                onClick={() => onCommand(command.id)}
                disabled={!!commandLoading}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm border disabled:opacity-50"
                style={{
                  borderColor: command.destructive ? 'rgba(239, 68, 68, 0.4)' : 'var(--border)',
                  color: command.destructive ? 'var(--crit)' : 'var(--fg)',
                  backgroundColor: 'var(--surface-alt)',
                }}
              >
                {command.id === 'locate' ? <MapPin className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                {commandLoading === command.id ? 'Sending...' : command.label}
                {command.execution_scope === 'mdm_provider' ? (
                  <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>MDM</span>
                ) : null}
              </button>
            ))}
          </div>

          {(overview.last_command || commandHistory.length > 0) && (
            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Activity className="h-4 w-4" /> Command Sync
              </h3>
              {overview.last_command && (
                <MobileFact
                  label="Last command"
                  value={`${formatMobileCommandValue(overview.last_command.id)} / ${formatMobileCommandValue(overview.last_command.status)}`}
                  danger={overview.last_command.status === 'failed'}
                />
              )}
              {commandHistory.length > 0 && (
                <div className="mt-3 space-y-2">
                  {commandHistory.slice(0, 5).map((entry, index) => (
                    <div
                      key={`${String(entry.id || 'command')}-${String(entry.requested_at || index)}`}
                      className="rounded-md border px-3 py-2 text-sm"
                      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface)' }}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium truncate" style={{ color: 'var(--fg)' }}>
                          {formatMobileCommandValue(entry.id)}
                        </span>
                        <span
                          className="text-xs uppercase"
                          style={{ color: entry.status === 'failed' ? 'var(--high)' : 'var(--emerald-400)' }}
                        >
                          {formatMobileCommandValue(entry.status)}
                        </span>
                      </div>
                      <p className="mt-1 text-xs truncate" style={{ color: 'var(--muted)' }}>
                        {formatMobileCommandDetail(entry)}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function MobileMetric({ label, value, tone }: { label: string; value: string; tone?: 'ok' | 'high' }) {
  return (
    <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{label}</p>
      <p className="mt-1 text-lg font-semibold truncate" style={{ color: tone === 'high' ? 'var(--high)' : tone === 'ok' ? 'var(--emerald-400)' : 'var(--fg)' }}>{value}</p>
    </div>
  )
}

function MobileFact({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span style={{ color: 'var(--muted)' }}>{label}</span>
      <span className="font-medium" style={{ color: danger ? 'var(--high)' : 'var(--fg)' }}>{value}</span>
    </div>
  )
}

function formatMobileRiskScore(value: unknown): string {
  if (value === undefined || value === null || value === '') return 'Unknown'
  const score = Number(value)
  return Number.isFinite(score) ? String(score) : 'Unknown'
}

function mobileRiskTone(value: unknown): 'ok' | 'high' | undefined {
  if (value === undefined || value === null || value === '') return undefined
  const score = Number(value)
  if (!Number.isFinite(score)) return undefined
  return score >= 70 ? 'high' : 'ok'
}

function formatMobileBoolean(value: unknown): string {
  if (value === true) return 'Enabled'
  if (value === false) return 'Disabled'
  return 'Unknown'
}

function formatMobileProvider(value: unknown): string {
  const provider = String(value || '').trim()
  if (!provider || provider === 'none') return 'none'
  return provider.replace(/_/g, ' ')
}

function formatMobileTimestamp(value: unknown): string {
  if (!value) return 'not reported'
  return formatDate(String(value))
}

function formatMobileCommandValue(value: unknown): string {
  const text = String(value || '').trim()
  return text ? text.replace(/_/g, ' ') : 'unknown'
}

function formatMobileCommandDetail(entry: Record<string, any>): string {
  if (entry.error) return String(entry.error)
  const result = entry.result || {}
  if (result.message) return String(result.message)
  if (result.status) return `Server status: ${result.status}`
  if (result.id) return `Command id: ${result.id}`
  if (entry.transport) return `Transport: ${formatMobileCommandValue(entry.transport)}`
  return entry.requested_at || 'Command queued'
}

function severityTextColor(severity: unknown): string {
  switch (String(severity || '').toLowerCase()) {
    case 'critical':
      return 'var(--crit)'
    case 'high':
      return 'var(--high)'
    case 'medium':
      return 'var(--med)'
    default:
      return 'var(--muted)'
  }
}

// ---------------------------------------------------------------------------
// Data source health
// ---------------------------------------------------------------------------

const DATA_SOURCE_KEYS: DataSourceKey[] = ['process', 'file', 'dns', 'network', 'registry', 'driver', 'ai', 'ndr']

const DATA_SOURCE_LABELS: Record<DataSourceKey, string> = {
  process: 'Process',
  file: 'File',
  dns: 'DNS',
  network: 'Network',
  registry: 'Registry',
  driver: 'Driver/ETW',
  ai: 'AI',
  ndr: 'NDR',
}

function DataSourcesHealthCard({
  health,
  loading,
  error,
  onRefresh,
}: {
  health: AgentDataSourceHealth | null
  loading: boolean
  error: string | null
  onRefresh: () => void
}) {
  return (
    <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Activity className="h-5 w-5" /> Data Sources Health
          </h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            24h source status from agent telemetry contracts.
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm border disabled:opacity-50 hover:bg-[var(--surface-2)]"
          style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border px-3 py-2 text-sm" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
          {error}
        </div>
      )}

      {loading && !health ? (
        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading data source health...
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
          {DATA_SOURCE_KEYS.map(source => {
            const sourceHealth = getSourceHealth(health, source)
            const state = dataSourceState(sourceHealth.status)
            return (
              <div key={source} className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{DATA_SOURCE_LABELS[source]}</span>
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: state.color }} title={state.title} />
                </div>
                <div className="mt-3 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>{sourceHealth.count}</div>
                <div className="text-xs capitalize" style={{ color: state.color }}>{sourceHealth.status}</div>
                <div className="mt-2 text-xs min-h-8" style={{ color: 'var(--muted)' }}>
                  {sourceHealth.lastSeen
                    ? `Last seen ${formatRelativeTime(new Date(sourceHealth.lastSeen).getTime())}`
                    : formatMissingReason(sourceHealth.missingReason || 'never_seen')}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function normalizeAgentDataSourceHealth(row: any): AgentDataSourceHealth | null {
  if (!row || typeof row !== 'object') return null
  const sources = Array.isArray(row.sources) ? row.sources : []

  return {
    agentId: String(row.agentId || row.agent_id || ''),
    hostname: row.hostname ? String(row.hostname) : undefined,
    windowHours: Number(row.windowHours || row.window_hours || 24),
    lastTelemetryAt: row.lastTelemetryAt || row.last_telemetry_at || null,
    sources: sources
      .map((source: any) => {
        const name = String(source.name || source.source || '').toLowerCase() as DataSourceKey
        if (!DATA_SOURCE_KEYS.includes(name)) return null
        const count = Number(source.count ?? source.eventCount ?? source.event_count ?? 0)
        return {
          name,
          status: normalizeDataSourceStatus(source.status, count),
          count,
          lastSeen: source.lastSeen || source.last_seen || null,
          missingReason: source.missingReason || source.missing_reason || null,
        }
      })
      .filter(Boolean) as AgentDataSourceHealth['sources'],
  }
}

function getSourceHealth(health: AgentDataSourceHealth | null, source: DataSourceKey): AgentDataSourceHealth['sources'][number] {
  return health?.sources.find(item => item.name === source) || {
    name: source,
    status: 'missing',
    count: 0,
    lastSeen: null,
    missingReason: 'not_reported',
  }
}

function normalizeDataSourceStatus(rawStatus: unknown, count: number): DataSourceStatus {
  const status = String(rawStatus || '').toLowerCase()
  if (status === 'healthy' || status === 'stale' || status === 'missing') return status
  if (status === 'recent' || status === 'ok' || status === 'online') return 'healthy'
  if (status === 'none' || status === 'unknown' || status === 'offline') return 'missing'
  return count > 0 ? 'healthy' : 'missing'
}

function dataSourceState(status: DataSourceStatus) {
  if (status === 'healthy') return { color: 'var(--emerald-400)', title: 'Healthy' }
  if (status === 'stale') return { color: 'var(--high)', title: 'Stale' }
  return { color: 'var(--surface-3)', title: 'Missing' }
}

function formatMissingReason(reason: string): string {
  return reason.replace(/_/g, ' ')
}

function PlatformCapabilitiesPanel({ capabilities }: { capabilities: PlatformCapability[] }) {
  if (capabilities.length === 0) return null

  return (
    <div className="card-sentinel rounded-xl p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Platform Capability Maturity</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            Conservative OS support status; live signals do not upgrade lab or partial features to fully supported.
          </p>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {capabilities.map(capability => {
          const status = capability.status || capability.maturity
          const style = capabilityMaturityStyle(status)
          return (
            <div key={capability.id} className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{capability.name}</span>
                <span className="text-xs font-medium rounded px-2 py-0.5" style={{ backgroundColor: style.bg, color: style.color }}>
                  {status}
                </span>
              </div>
              <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
                {capability.observed === 'not_observed' ? 'No live signal observed.' : capability.detail || capability.observed || 'No signal detail.'}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function normalizePlatformCapabilities(value: unknown): PlatformCapability[] {
  if (!Array.isArray(value)) return []
  return value
    .map(item => {
      if (!item || typeof item !== 'object') return null
      const raw = item as Record<string, unknown>
      const id = String(raw.id || '')
      if (!id) return null
      const maturity = String(raw.maturity || raw.status || 'unavailable')
      return {
        id,
        name: String(raw.name || id.replace(/_/g, ' ')),
        platform: raw.platform ? String(raw.platform) : undefined,
        maturity,
        status: raw.status ? String(raw.status) : maturity,
        observed: raw.observed ? String(raw.observed) : undefined,
        detail: raw.detail ? String(raw.detail) : undefined,
      }
    })
    .filter(Boolean) as PlatformCapability[]
}

function capabilityMaturityStyle(maturity: CapabilityMaturity) {
  switch (maturity) {
    case 'supported':
      return { bg: 'rgba(52, 211, 153, 0.16)', color: 'var(--emerald-400)' }
    case 'partial':
      return { bg: 'rgba(245, 165, 36, 0.16)', color: 'var(--high)' }
    case 'lab':
      return { bg: 'rgba(59, 130, 246, 0.16)', color: 'var(--primary)' }
    default:
      return { bg: 'var(--surface-3)', color: 'var(--muted)' }
  }
}

function resolveAgentPlatform(agent: Agent): string | undefined {
  const raw = agent as unknown as Record<string, unknown>
  const mobileDevice = raw.mobile_device && typeof raw.mobile_device === 'object'
    ? raw.mobile_device as Record<string, unknown>
    : {}
  const device = raw.device && typeof raw.device === 'object'
    ? raw.device as Record<string, unknown>
    : {}
  const posture = raw.posture && typeof raw.posture === 'object'
    ? raw.posture as Record<string, unknown>
    : {}

  const candidates = [
    raw.os_type,
    raw.platform,
    raw.operating_system,
    raw.os,
    mobileDevice.platform,
    mobileDevice.os_type,
    device.platform,
    device.os_type,
    posture.platform,
    posture.os_type,
  ]

  const platform = candidates.find(value => typeof value === 'string' && value.trim())
  return platform ? String(platform) : undefined
}

function isMobilePlatform(osType?: string): boolean {
  const os = String(osType || '').toLowerCase()
  return os.includes('android') || os.includes('ios') || os.includes('iphone') || os.includes('ipad')
}

function shouldUseMobileFallbackCapabilities(osType: string | undefined, capabilities: PlatformCapability[]): boolean {
  if (!isMobilePlatform(osType)) return false
  return !capabilities.some(capability =>
    ['mobile_posture', 'app_inventory', 'app_guard', 'commercial_spyware'].includes(capability.id)
  )
}

function capabilityAvailable(capabilities: PlatformCapability[], id: string): boolean {
  const capability = capabilities.find(item => item.id === id)
  if (!capability) return false
  const status = String(capability.status || capability.maturity || '').toLowerCase()
  return status !== 'unavailable'
}

function fallbackPlatformCapabilities(osType?: string): PlatformCapability[] {
  const os = String(osType || '').toLowerCase()
  const platform = os.includes('windows') ? 'windows' :
    os.includes('linux') ? 'linux' :
    os.includes('mac') || os.includes('darwin') ? 'macos' :
    os.includes('android') ? 'android' :
    os.includes('ios') || os.includes('iphone') || os.includes('ipad') ? 'ios' :
    'unknown'
  const maturityByPlatform: Record<string, Record<string, CapabilityMaturity>> = {
    windows: { endpoint_telemetry: 'supported', kernel_sensor: 'lab', registry_telemetry: 'supported', live_response: 'partial', network_isolation: 'partial', prevention_policy: 'partial' },
    linux: { endpoint_telemetry: 'partial', kernel_sensor: 'lab', registry_telemetry: 'unavailable', live_response: 'partial', network_isolation: 'partial', prevention_policy: 'partial' },
    macos: { endpoint_telemetry: 'lab', kernel_sensor: 'lab', registry_telemetry: 'unavailable', live_response: 'lab', network_isolation: 'lab', prevention_policy: 'lab' },
    android: { endpoint_telemetry: 'partial', mobile_posture: 'supported', app_inventory: 'partial', app_guard: 'partial', commercial_spyware: 'lab', prevention_policy: 'partial' },
    ios: { endpoint_telemetry: 'partial', mobile_posture: 'supported', app_inventory: 'partial', app_guard: 'partial', commercial_spyware: 'lab', prevention_policy: 'partial' },
    unknown: { endpoint_telemetry: 'unavailable', kernel_sensor: 'unavailable', registry_telemetry: 'unavailable', live_response: 'unavailable', network_isolation: 'unavailable', prevention_policy: 'unavailable' },
  }
  const names: Record<string, string> = {
    endpoint_telemetry: 'Endpoint telemetry',
    kernel_sensor: 'Kernel / platform sensor',
    registry_telemetry: 'Registry telemetry',
    mobile_posture: 'Mobile posture',
    app_inventory: 'App inventory',
    app_guard: 'App Guard / RASP',
    commercial_spyware: 'Commercial spyware indicators',
    live_response: 'Live response shell',
    network_isolation: 'Network isolation',
    prevention_policy: 'Prevention policy enforcement',
  }

  return Object.entries(maturityByPlatform[platform]).map(([id, maturity]) => ({
    id,
    name: names[id],
    platform,
    maturity,
    status: maturity,
    observed: 'not_observed',
    detail: 'Fallback OS maturity; no backend capability signal was included.',
  }))
}

// ---------------------------------------------------------------------------
// Alert status badge (local to this page)
// ---------------------------------------------------------------------------

function AlertStatusBadge({ status }: { status: Alert['status'] }) {
  const getStatusStyles = () => {
    switch (status) {
      case 'open':
        return { bg: 'rgba(239, 68, 68, 0.2)', text: 'var(--crit)' }
      case 'investigating':
        return { bg: 'rgba(251, 191, 36, 0.2)', text: 'var(--warn)' }
      case 'resolved':
        return { bg: 'rgba(52, 211, 153, 0.2)', text: 'var(--emerald-400)' }
      case 'false_positive':
        return { bg: 'var(--surface-alt)', text: 'var(--muted)' }
      default:
        return { bg: 'var(--surface-alt)', text: 'var(--muted)' }
    }
  }

  const labels: Record<string, string> = {
    open: 'Open',
    investigating: 'Investigating',
    resolved: 'Resolved',
    false_positive: 'False Positive',
  }

  const styles = getStatusStyles()

  return (
    <span
      className="text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0"
      style={{ backgroundColor: styles.bg, color: styles.text }}
    >
      {labels[status] || status}
    </span>
  )
}
