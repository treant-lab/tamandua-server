import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Activity,
  Filter,
  Search,
  Clock,
  FileText,
  Network,
  Terminal,
  HardDrive,
  ChevronRight,
  ChevronLeft,
  Trash2,
  Play,
  Shield,
  Usb,
  Clipboard,
  Syringe,
  Key,
  Eye,
  Wifi,
  Globe,
  AlertTriangle,
  Lock,
  Cpu,
  Share2,
  RefreshCw,
  Pause,
  Download,
  ChevronDown,
  CheckCircle,
  XCircle,
  Settings,
  ExternalLink,
  Plus,
  BookOpen,
  Zap,
  Server,
  UserPlus,
  Hash,
} from 'lucide-react'
import { router } from '@inertiajs/react'
import { cn, formatDate, safeCapitalize } from '@/lib/utils'
import { useEventStream } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { ExportDropdown } from '@/components/ExportDropdown'

interface Event {
  id: string
  eventType: string
  timestamp: string | number
  agentId: string
  hostname?: string
  severity: string
  summary?: string
  sigmaRuleId?: string
  hash?: string
  payload: Record<string, any>
}

interface EventsProps {
  events: Event[]
  filters: {
    types: string[]
    agents: Array<{ id: string; hostname: string }>
  }
  pagination: {
    page: number
    perPage: number
    total: number
    totalPages: number
  }
  stats?: {
    byType: Record<string, number>
    bySeverity: Record<string, number>
    total: number
  }
  activeFilters?: {
    eventType: string
    agentId: string
    severity: string
    timeRange: string
  }
  connectedAgent?: {
    hostname: string
    lastEventReceived?: string
    ingestionStatus?: 'healthy' | 'degraded' | 'offline'
    ipcStatus?: 'healthy' | 'degraded' | 'offline'
    mtlsStatus?: { valid: boolean; daysToRenewal: number }
  }
  eventsUnavailable?: boolean
  eventsError?: string
}

const eventTypeIcons: Record<string, React.ElementType> = {
  // Process events
  process_create: Terminal,
  process_start: Terminal,
  process_terminate: Terminal,
  process_end: Terminal,
  process: Terminal,
  // File events
  file_create: FileText,
  file_modify: FileText,
  file_delete: FileText,
  file_rename: FileText,
  file: FileText,
  // Network events
  network_connect: Network,
  network_listen: Network,
  network: Network,
  dns_query: Globe,
  dns: Globe,
  // Registry events
  registry_modify: HardDrive,
  registry_write: HardDrive,
  registry_create: HardDrive,
  registry_delete: HardDrive,
  registry: HardDrive,
  // Security events
  injection_detected: Syringe,
  process_hollowing: Syringe,
  credential_access: Key,
  lsass_access: Key,
  amsi_scan: Shield,
  defense_evasion: Shield,
  security: Shield,
  // Auth events
  auth: Lock,
  login: Lock,
  logout: Lock,
  // Device & I/O
  usb_connect: Usb,
  usb_disconnect: Usb,
  clipboard_access: Clipboard,
  input_capture: Eye,
  // Lateral movement & persistence
  lateral_movement: Wifi,
  persistence: Lock,
  scheduled_task: Clock,
  wmi_event: Cpu,
  // Detection
  honeyfile_access: AlertTriangle,
  ransomware_canary: AlertTriangle,
  exploit_attempt: AlertTriangle,
  named_pipe: Network,
  etw_event: Activity,
  cloud_event: Globe,
}

// Event type color categories using CSS variables
type EventColorCategory = 'success' | 'danger' | 'warning' | 'info' | 'purple' | 'cyan' | 'muted'

const eventTypeColorCategory: Record<string, EventColorCategory> = {
  // Process events
  process_create: 'success',
  process_start: 'success',
  process_terminate: 'danger',
  process_end: 'danger',
  process: 'success',
  // File events
  file_create: 'info',
  file_modify: 'warning',
  file_delete: 'danger',
  file_rename: 'info',
  file: 'info',
  // Network events
  network_connect: 'purple',
  network_listen: 'purple',
  network: 'purple',
  dns_query: 'cyan',
  dns: 'cyan',
  // Registry events
  registry_modify: 'warning',
  registry_write: 'warning',
  registry_create: 'warning',
  registry_delete: 'danger',
  registry: 'warning',
  // Security events (high visibility)
  injection_detected: 'danger',
  process_hollowing: 'danger',
  credential_access: 'danger',
  lsass_access: 'danger',
  amsi_scan: 'warning',
  defense_evasion: 'danger',
  security: 'danger',
  // Auth events
  auth: 'info',
  login: 'success',
  logout: 'warning',
  // Device & I/O
  usb_connect: 'warning',
  usb_disconnect: 'warning',
  clipboard_access: 'warning',
  input_capture: 'warning',
  // Lateral movement & persistence
  lateral_movement: 'danger',
  persistence: 'warning',
  scheduled_task: 'warning',
  wmi_event: 'warning',
  // Detection alerts
  honeyfile_access: 'danger',
  ransomware_canary: 'danger',
  exploit_attempt: 'danger',
  named_pipe: 'purple',
  etw_event: 'muted',
  cloud_event: 'cyan',
}

// Get styles for event type category
function getEventTypeStyles(eventType: string): { color: string; background: string } {
  const category = eventTypeColorCategory[eventType] || 'muted'

  const styles: Record<EventColorCategory, { color: string; background: string }> = {
    success: { color: 'var(--emerald-400)', background: 'var(--emerald-glow)' },
    danger: { color: 'var(--crit)', background: 'var(--crit-bg)' },
    warning: { color: 'var(--high)', background: 'var(--high-bg)' },
    info: { color: 'var(--med)', background: 'var(--med-bg)' },
    purple: { color: '#a78bfa', background: 'rgba(167, 139, 250, 0.12)' },
    cyan: { color: 'var(--sol-cyan)', background: 'rgba(25, 251, 155, 0.12)' },
    muted: { color: 'var(--muted)', background: 'var(--surface-2)' },
  }

  return styles[category]
}

// Type filter categories
const TYPE_TABS = [
  { value: '', label: 'All', icon: Activity },
  { value: 'process', label: 'Process', icon: Terminal },
  { value: 'file', label: 'File', icon: FileText },
  { value: 'network', label: 'Network', icon: Network },
  { value: 'dns', label: 'DNS', icon: Globe },
  { value: 'registry', label: 'Registry', icon: HardDrive },
  { value: 'security', label: 'Security', icon: Shield },
  { value: 'auth', label: 'Auth', icon: Lock },
]

const SEVERITY_PILLS = [
  { value: '', label: 'Any sev' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Med' },
  { value: 'low', label: 'Low' },
]

function snakeCase(str: string): string {
  return str.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
}

function formatNumber(n: number): string {
  return n.toLocaleString()
}

function formatTime(timestamp: string | number): string {
  const date = typeof timestamp === 'number' ? new Date(timestamp) : new Date(timestamp)
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) + '.' + String(date.getMilliseconds()).padStart(3, '0')
}

function formatTimeSince(timestamp: string | number | undefined): string {
  if (!timestamp) return 'N/A'
  const now = Date.now()
  const then = typeof timestamp === 'number' ? timestamp : new Date(timestamp).getTime()
  const diff = (now - then) / 1000
  if (diff < 1) return `${Math.round(diff * 10) / 10}s ago`
  if (diff < 60) return `${Math.round(diff)}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  return `${Math.round(diff / 3600)}h ago`
}

function truncateHash(hash?: string): string {
  if (!hash) return '-'
  if (hash.length <= 12) return hash
  return `0x${hash.slice(0, 4)}...${hash.slice(-4)}`
}

function getEventTypeCategory(eventType: string): string {
  if (eventType.startsWith('process')) return 'process'
  if (eventType.startsWith('file')) return 'file'
  if (eventType.startsWith('network')) return 'network'
  if (eventType.startsWith('dns')) return 'dns'
  if (eventType.startsWith('registry')) return 'registry'
  if (['injection_detected', 'process_hollowing', 'credential_access', 'lsass_access', 'amsi_scan', 'defense_evasion', 'honeyfile_access', 'ransomware_canary', 'exploit_attempt'].includes(eventType)) return 'security'
  if (['login', 'logout', 'auth'].includes(eventType)) return 'auth'
  return ''
}

export default function Events({
  events: initialEvents,
  filters,
  pagination,
  stats,
  activeFilters,
  connectedAgent,
  eventsUnavailable = false,
  eventsError,
}: EventsProps) {
  // Server-side filter state (driven by URL params via Inertia)
  const [selectedType, setSelectedType] = useState<string>(activeFilters?.eventType || '')
  const [selectedAgent, setSelectedAgent] = useState<string>(activeFilters?.agentId || '')
  const [selectedSeverity, setSelectedSeverity] = useState<string>(activeFilters?.severity || '')
  const [selectedTimeRange, setSelectedTimeRange] = useState<string>(activeFilters?.timeRange || '')

  // Client-side search (instant filter on current page only)
  const [searchQuery, setSearchQuery] = useState(() => {
    return new URLSearchParams(window.location.search).get('event_id') || ''
  })

  // Detail panel
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)

  // Agent dropdown
  const [agentDropdownOpen, setAgentDropdownOpen] = useState(false)

  // WebSocket event streaming
  const {
    connectionState,
    events: liveEvents,
    clearEvents,
    pauseStream,
    resumeStream,
    isPaused
  } = useEventStream(selectedAgent ? selectedAgent : undefined)

  // Merge initial events with live events
  const [allEvents, setAllEvents] = useState<Event[]>(initialEvents || [])

  // Track which live event IDs we've already merged to avoid re-processing
  const mergedIdsRef = useRef(new Set<string>())

  // Sync when initial events change (e.g. Inertia navigation)
  useEffect(() => {
    setAllEvents(initialEvents || [])
    mergedIdsRef.current.clear()
  }, [initialEvents])

  // Sync filter dropdowns when activeFilters prop changes (Inertia navigation)
  useEffect(() => {
    if (activeFilters) {
      setSelectedType(activeFilters.eventType || '')
      setSelectedAgent(activeFilters.agentId || '')
      setSelectedSeverity(activeFilters.severity || '')
      setSelectedTimeRange(activeFilters.timeRange || '')
    }
  }, [activeFilters])

  // Add live events to the list -- only merge genuinely new events
  useEffect(() => {
    if (liveEvents.length === 0) return

    // Find events we haven't merged yet
    const newEvents = liveEvents.filter(e => !mergedIdsRef.current.has(e.id))
    if (newEvents.length === 0) return

    newEvents.forEach(e => mergedIdsRef.current.add(e.id))

    setAllEvents(prev => {
      const eventMap = new Map(prev.map(e => [e.id, e]))
      newEvents.forEach(event => {
        eventMap.set(event.id, {
          id: event.id,
          eventType: event.eventType,
          timestamp: event.timestamp,
          agentId: event.agentId,
          hostname: (filters?.agents?.find(a => a.id === event.agentId)?.hostname) || event.agentId || 'Unknown',
          severity: event.severity,
          summary: event.summary,
          payload: event.payload as Record<string, any>,
        })
      })
      return Array.from(eventMap.values())
        .sort((a, b) => {
          const tsA = typeof a.timestamp === 'number' ? a.timestamp : new Date(a.timestamp).getTime()
          const tsB = typeof b.timestamp === 'number' ? b.timestamp : new Date(b.timestamp).getTime()
          return tsB - tsA
        })
        .slice(0, 500) // Keep max 500 events
    })
  }, [liveEvents])

  const agents = filters?.agents || []

  // Build current filters object from state
  const currentFilters = useMemo(() => ({
    eventType: selectedType,
    agentId: selectedAgent,
    severity: selectedSeverity,
    timeRange: selectedTimeRange,
    page: String(pagination?.page || 1),
  }), [selectedType, selectedAgent, selectedSeverity, selectedTimeRange, pagination?.page])

  // Navigate with server-side filters via Inertia
  const navigateWithFilters = useCallback((newFilters: Record<string, string>) => {
    const params = new URLSearchParams()
    const merged = { ...currentFilters, ...newFilters }
    Object.entries(merged).forEach(([key, value]) => {
      if (value) params.set(snakeCase(key), value)
    })
    // Reset to page 1 when filters change (unless it's a page change)
    if (!newFilters.page) params.set('page', '1')
    router.visit(`/app/events?${params.toString()}`, { preserveState: true })
  }, [currentFilters])

  // Handle refresh
  const handleRefresh = useCallback(() => {
    router.reload()
  }, [])

  // Client-side search filter (on top of server-filtered events)
  // Also filter by type category if using the tabs
  const filteredEvents = useMemo(() => {
    let filtered = allEvents

    // Filter by type category (tabs)
    if (selectedType && !selectedType.includes('_')) {
      filtered = filtered.filter(event => {
        const category = getEventTypeCategory(event.eventType)
        return category === selectedType || event.eventType === selectedType
      })
    }

    if (!searchQuery) return filtered

    const searchLower = searchQuery.toLowerCase()
    return filtered.filter((event) => {
      const payloadStr = JSON.stringify(event.payload).toLowerCase()
      const hostname = (event.hostname || '').toLowerCase()
      const summary = (event.summary || '').toLowerCase()
      const eventType = event.eventType.toLowerCase()
      const eventId = event.id.toLowerCase()
      return eventId.includes(searchLower) ||
        payloadStr.includes(searchLower) ||
        hostname.includes(searchLower) ||
        summary.includes(searchLower) ||
        eventType.includes(searchLower)
    })
  }, [allEvents, searchQuery, selectedType])

  // Pagination info
  const page = pagination?.page || 1
  const totalPages = pagination?.totalPages || 1
  const total = pagination?.total || 0
  const perPage = pagination?.perPage || 50

  // Stats
  const totalEvents = stats?.total || total

  // Most recent event for status bar
  const lastEvent = filteredEvents[0]
  const lastEventTime = lastEvent?.timestamp
  const selectedAgentRecord = selectedAgent
    ? agents.find((agent) => agent.id === selectedAgent)
    : undefined
  const eventScopeLabel = selectedAgentRecord?.hostname || (selectedAgent ? selectedAgent : 'Fleet event stream')
  const hasVerifiedAgentContext = Boolean(connectedAgent)
  const hasActiveFilters = Boolean(searchQuery || selectedType || selectedAgent || selectedSeverity || selectedTimeRange)
  const backendIngestionStatus: 'healthy' | 'degraded' | 'offline' = eventsUnavailable
    ? 'degraded'
    : connectedAgent?.ingestionStatus || (hasVerifiedAgentContext ? 'healthy' : 'degraded')

  return (
    <MainLayout title="Event Timeline">
      <Head title="Events - Tamandua EDR" />

      <div className="flex flex-col gap-4 h-[calc(100vh-180px)]">
        {/* Agent Status Row */}
        <div
          className="rounded-xl px-4 py-3"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--hairline)',
          }}
        >
          <div className="flex items-center gap-6 flex-wrap">
            {/* Event Scope */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                Event Scope
              </span>
              <div className="flex items-center gap-2">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{
                    background: selectedAgentRecord
                      ? (connectionState === 'connected' ? 'var(--emerald-400)' : 'var(--high)')
                      : 'var(--muted)',
                  }}
                />
                <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                  {selectedAgentRecord ? (connectedAgent?.hostname || eventScopeLabel) : eventScopeLabel}
                </span>
              </div>
            </div>

            {/* Separator */}
            <div className="h-5 w-px" style={{ background: 'var(--border)' }} />

            {/* Last Event Received */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                Last Event
              </span>
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>
                {formatTimeSince(connectedAgent?.lastEventReceived || lastEventTime)}
              </span>
            </div>

            {/* Separator */}
            <div className="h-5 w-px" style={{ background: 'var(--border)' }} />

            {/* Backend Ingestion */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                Backend Ingestion
              </span>
              <StatusBadge status={backendIngestionStatus} />
            </div>

            {/* Separator */}
            <div className="h-5 w-px" style={{ background: 'var(--border)' }} />

            {/* Local GUI IPC */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                Local GUI IPC
              </span>
              {hasVerifiedAgentContext ? (
                <StatusBadge status={connectedAgent?.ipcStatus || 'offline'} />
              ) : (
                <span className="text-sm" style={{ color: 'var(--subtle)' }}>not linked</span>
              )}
            </div>

            {/* Separator */}
            <div className="h-5 w-px" style={{ background: 'var(--border)' }} />

            {/* mTLS */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                mTLS
              </span>
              {connectedAgent?.mtlsStatus ? (
                <span className="text-sm" style={{ color: connectedAgent.mtlsStatus.valid ? 'var(--emerald-400)' : 'var(--high)' }}>
                  {connectedAgent.mtlsStatus.valid ? 'valid' : 'invalid'} &bull; {connectedAgent.mtlsStatus.daysToRenewal}d to renewal
                </span>
              ) : (
                <span className="text-sm" style={{ color: 'var(--subtle)' }}>per enrolled agent</span>
              )}
            </div>

            {/* Spacer */}
            <div className="flex-1" />

            {/* Action Buttons */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleRefresh}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors hover:opacity-80"
                style={{
                  background: 'var(--surface-2)',
                  color: 'var(--fg-2)',
                  border: '1px solid var(--border)',
                }}
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Run connection check
              </button>
              <button
                onClick={() => router.visit('/app/deploy-agent')}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors hover:opacity-80"
                style={{
                  background: 'var(--surface-2)',
                  color: 'var(--fg-2)',
                  border: '1px solid var(--border)',
                }}
              >
                <Settings className="h-3.5 w-3.5" />
                Open agent setup
              </button>
            </div>
          </div>
        </div>

        {eventsUnavailable && (
          <div className="flex items-start gap-3 rounded-xl px-4 py-3 border border-yellow-500/30 bg-yellow-500/10">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-400" />
            <div>
              <p className="text-sm font-medium text-yellow-100">Event telemetry did not load cleanly</p>
              <p className="mt-1 text-xs text-yellow-200/80">
                {eventsError || 'Stored event history is unavailable. Live events may still appear if the socket is connected.'}
              </p>
            </div>
          </div>
        )}

        {/* Filters Row */}
        <div
          className="rounded-xl px-4 py-3"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--hairline)',
          }}
        >
          <div className="flex items-center gap-4 flex-wrap">
            {/* Type Filter Tabs (Segmented Button Style) */}
            <div
              className="flex items-center rounded-lg p-0.5"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              {TYPE_TABS.map((tab) => {
                const Icon = tab.icon
                const isActive = selectedType === tab.value
                return (
                  <button
                    key={tab.value}
                    onClick={() => {
                      setSelectedType(tab.value)
                      navigateWithFilters({ eventType: tab.value })
                    }}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all',
                      isActive && 'shadow-sm'
                    )}
                    style={{
                      background: isActive ? 'var(--emerald-600)' : 'transparent',
                      color: isActive ? 'white' : 'var(--muted)',
                    }}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {tab.label}
                  </button>
                )
              })}
            </div>

            {/* Separator */}
            <div className="h-6 w-px" style={{ background: 'var(--border)' }} />

            {/* Severity Filter Pills */}
            <div className="flex items-center gap-1.5">
              {SEVERITY_PILLS.map((pill) => {
                const isActive = selectedSeverity === pill.value
                return (
                  <button
                    key={pill.value}
                    onClick={() => {
                      setSelectedSeverity(pill.value)
                      navigateWithFilters({ severity: pill.value })
                    }}
                    className={cn(
                      'px-2.5 py-1 rounded-full text-xs font-medium transition-all',
                      isActive && 'ring-1 ring-white/20'
                    )}
                    style={getSeverityPillStyle(pill.value, isActive)}
                  >
                    {pill.label}
                  </button>
                )
              })}
            </div>

            {/* Separator */}
            <div className="h-6 w-px" style={{ background: 'var(--border)' }} />

            {/* Agent Dropdown */}
            <div className="relative">
              <button
                onClick={() => setAgentDropdownOpen(!agentDropdownOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                style={{
                  background: 'var(--surface-2)',
                  color: selectedAgent ? 'var(--fg)' : 'var(--muted)',
                  border: '1px solid var(--border)',
                }}
              >
                <Server className="h-3.5 w-3.5" />
                {selectedAgent ? agents.find(a => a.id === selectedAgent)?.hostname || 'Unknown' : 'All agents'}
                <ChevronDown className="h-3.5 w-3.5" />
              </button>
              {agentDropdownOpen && (
                <div
                  className="absolute top-full left-0 mt-1 rounded-lg shadow-lg z-50 min-w-[180px] py-1"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <button
                    onClick={() => {
                      setSelectedAgent('')
                      navigateWithFilters({ agentId: '' })
                      setAgentDropdownOpen(false)
                    }}
                    className="w-full text-left px-3 py-2 text-xs hover:opacity-80"
                    style={{
                      color: !selectedAgent ? 'var(--emerald-400)' : 'var(--fg-2)',
                      background: !selectedAgent ? 'var(--emerald-glow)' : 'transparent',
                    }}
                  >
                    All agents
                  </button>
                  {agents.map((agent) => (
                    <button
                      key={agent.id}
                      onClick={() => {
                        setSelectedAgent(agent.id)
                        navigateWithFilters({ agentId: agent.id })
                        setAgentDropdownOpen(false)
                      }}
                      className="w-full text-left px-3 py-2 text-xs hover:opacity-80"
                      style={{
                        color: selectedAgent === agent.id ? 'var(--emerald-400)' : 'var(--fg-2)',
                        background: selectedAgent === agent.id ? 'var(--emerald-glow)' : 'transparent',
                      }}
                    >
                      {agent.hostname}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Spacer */}
            <div className="flex-1" />

            {/* Header Controls */}
            <div className="flex items-center gap-2">
              {/* Live/Paused Toggle */}
              <button
                onClick={() => isPaused ? resumeStream() : pauseStream()}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium text-xs transition-colors"
                style={{
                  background: !isPaused ? 'var(--emerald-600)' : 'var(--surface-2)',
                  color: !isPaused ? 'white' : 'var(--fg-2)',
                  border: isPaused ? '1px solid var(--border)' : 'none',
                }}
              >
                {isPaused ? (
                  <>
                    <Play className="h-3.5 w-3.5" />
                    Paused
                  </>
                ) : (
                  <>
                    <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                    Live
                  </>
                )}
              </button>

              {/* Filters Button */}
              <button
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors hover:opacity-80"
                style={{
                  background: 'var(--surface-2)',
                  color: 'var(--fg-2)',
                  border: '1px solid var(--border)',
                }}
              >
                <Filter className="h-3.5 w-3.5" />
                Filters
              </button>

              {/* Export */}
              <ExportDropdown
                getData={() => filteredEvents.map(e => ({
                  id: e.id,
                  event_type: e.eventType,
                  timestamp: e.timestamp,
                  agent_id: e.agentId,
                  hostname: e.hostname,
                  severity: e.severity,
                  summary: getEventSummary(e),
                  ...e.payload,
                }))}
                filenameBase="tamandua-events"
                disabled={filteredEvents.length === 0}
              />
            </div>
          </div>
        </div>

        {/* Main content */}
        <div className="flex gap-6 flex-1 min-h-0">
          {/* Event List */}
          <div
            className="flex-1 flex flex-col rounded-xl"
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--hairline)',
            }}
          >
            {/* Search Bar */}
            <div
              className="p-3"
              style={{ borderBottom: '1px solid var(--hairline)' }}
            >
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                <input
                  type="text"
                  placeholder="Search events..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                    '--tw-ring-color': 'var(--emerald-500)',
                  } as React.CSSProperties}
                />
              </div>
            </div>

            {/* Event Table */}
            <div className="flex-1 overflow-y-auto">
              {filteredEvents.length === 0 ? (
                <EmptyState agents={agents} hasActiveFilters={hasActiveFilters} eventsUnavailable={eventsUnavailable} />
              ) : (
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Timestamp
                      </th>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Type
                      </th>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Sev
                      </th>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Event
                      </th>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Agent
                      </th>
                      <th className="text-left text-xs font-medium uppercase tracking-wider px-4 py-3" style={{ color: 'var(--muted)' }}>
                        Hash
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((event) => {
                      const Icon = eventTypeIcons[event.eventType] || Activity
                      const styles = getEventTypeStyles(event.eventType)
                      const effectiveSeverity = event.severity || inferSeverity(event.eventType)
                      const hash = event.hash || event.payload?.sha256 || event.payload?.hash || event.payload?.md5

                      return (
                        <tr
                          key={event.id}
                          onClick={() => setSelectedEvent(event)}
                          className="cursor-pointer transition-colors"
                          style={{
                            borderBottom: '1px solid var(--hairline)',
                            background: selectedEvent?.id === event.id ? 'var(--surface-2)' : 'transparent',
                          }}
                          onMouseEnter={(e) => {
                            if (selectedEvent?.id !== event.id) {
                              e.currentTarget.style.background = 'var(--surface-2)'
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (selectedEvent?.id !== event.id) {
                              e.currentTarget.style.background = 'transparent'
                            }
                          }}
                        >
                          {/* Timestamp */}
                          <td className="px-4 py-3">
                            <span className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>
                              {formatTime(event.timestamp)}
                            </span>
                          </td>

                          {/* Type Badge */}
                          <td className="px-4 py-3">
                            <span
                              className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium"
                              style={{
                                background: styles.background,
                                color: styles.color,
                              }}
                            >
                              <Icon className="h-3.5 w-3.5" />
                              {getEventTypeCategory(event.eventType) || event.eventType.split('_')[0]}
                            </span>
                          </td>

                          {/* Severity Badge */}
                          <td className="px-4 py-3">
                            <SeverityBadgeCompact severity={effectiveSeverity} />
                          </td>

                          {/* Event Description */}
                          <td className="px-4 py-3 max-w-md">
                            <div className="truncate text-sm" style={{ color: 'var(--fg)' }}>
                              {getEventSummary(event)}
                            </div>
                            {event.sigmaRuleId && (
                              <div className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
                                {event.sigmaRuleId}
                              </div>
                            )}
                          </td>

                          {/* Agent */}
                          <td className="px-4 py-3">
                            <span className="text-sm" style={{ color: 'var(--fg-2)' }}>
                              {event.hostname || 'Unknown'}
                            </span>
                          </td>

                          {/* Hash */}
                          <td className="px-4 py-3">
                            <span className="text-xs font-mono" style={{ color: 'var(--muted)' }}>
                              {truncateHash(hash)}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Pagination Controls */}
            <div
              className="p-3 flex items-center justify-between"
              style={{ borderTop: '1px solid var(--hairline)' }}
            >
              <div className="text-sm" style={{ color: 'var(--muted)' }}>
                Showing {Math.min((page - 1) * perPage + 1, total)}--{Math.min(page * perPage, total)} of {formatNumber(total)} events
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => navigateWithFilters({ page: String(page - 1) })}
                  disabled={page <= 1}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
                  style={{
                    background: page <= 1 ? 'var(--surface)' : 'var(--surface-2)',
                    color: page <= 1 ? 'var(--dim)' : 'var(--fg-2)',
                    border: '1px solid var(--border)',
                    cursor: page <= 1 ? 'not-allowed' : 'pointer',
                    opacity: page <= 1 ? 0.5 : 1,
                  }}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Previous
                </button>

                <span className="text-sm" style={{ color: 'var(--fg-2)' }}>
                  Page <span className="font-medium" style={{ color: 'var(--fg)' }}>{page}</span> of <span className="font-medium" style={{ color: 'var(--fg)' }}>{totalPages}</span>
                </span>

                <button
                  onClick={() => navigateWithFilters({ page: String(page + 1) })}
                  disabled={page >= totalPages}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
                  style={{
                    background: page >= totalPages ? 'var(--surface)' : 'var(--surface-2)',
                    color: page >= totalPages ? 'var(--dim)' : 'var(--fg-2)',
                    border: '1px solid var(--border)',
                    cursor: page >= totalPages ? 'not-allowed' : 'pointer',
                    opacity: page >= totalPages ? 0.5 : 1,
                  }}
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </button>

                <div className="h-5 w-px" style={{ background: 'var(--border)' }} />

                <span className="text-xs" style={{ color: 'var(--subtle)' }}>{perPage} per page</span>
              </div>
            </div>
          </div>

          {/* Event Details */}
          <div
            className="w-96 rounded-xl flex flex-col"
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--hairline)',
            }}
          >
            <div
              className="p-4"
              style={{ borderBottom: '1px solid var(--hairline)' }}
            >
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Event Details</h2>
            </div>

            {selectedEvent ? (
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Event Type
                  </label>
                  <p className="text-sm mt-1" style={{ color: 'var(--fg)' }}>
                    {selectedEvent.eventType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </p>
                </div>

                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Timestamp
                  </label>
                  <p className="text-sm mt-1" style={{ color: 'var(--fg)' }}>{new Date(selectedEvent.timestamp).toLocaleString()}</p>
                </div>

                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Agent
                  </label>
                  <p className="text-sm mt-1" style={{ color: 'var(--fg)' }}>{selectedEvent.hostname}</p>
                </div>

                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Payload
                  </label>
                  <pre
                    className="mt-2 p-3 rounded-lg text-xs overflow-x-auto"
                    style={{
                      background: 'var(--bg-2)',
                      color: 'var(--fg-2)',
                      border: '1px solid var(--hairline)',
                    }}
                  >
                    {JSON.stringify(selectedEvent.payload, null, 2)}
                  </pre>
                </div>

                {/* Severity Badge */}
                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Severity
                  </label>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedEvent.severity} eventType={selectedEvent.eventType} />
                  </div>
                </div>

                {/* Contextual Summary */}
                <div>
                  <label
                    className="text-xs font-medium uppercase tracking-wider"
                    style={{ color: 'var(--muted)' }}
                  >
                    Summary
                  </label>
                  <p className="text-sm mt-1" style={{ color: 'var(--fg-2)' }}>{getEventSummary(selectedEvent)}</p>
                </div>

                {/* Action Buttons */}
                <div className="pt-4 space-y-2">
                  <button
                    onClick={() => {
                      const q = buildHuntQuery(selectedEvent)
                      router.visit(`/app/hunt?q=${encodeURIComponent(q)}`)
                    }}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                    style={{
                      background: 'var(--emerald-600)',
                      color: 'white',
                    }}
                  >
                    <Search className="h-4 w-4" />
                    Investigate in Hunt
                  </button>
                  {hasProcessContext(selectedEvent) && (
                    <button
                      onClick={() => {
                        const pid = selectedEvent.payload?.pid || selectedEvent.payload?.process_pid || ''
                        router.visit(`/app/process-tree?agent_id=${selectedEvent.agentId}&pid=${pid}`)
                      }}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                      style={{
                        background: 'var(--surface-2)',
                        color: 'var(--fg)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      <Cpu className="h-4 w-4" />
                      View in Process Tree
                    </button>
                  )}
                  {hasNetworkContext(selectedEvent) && (
                    <button
                      onClick={() => {
                        const ip = selectedEvent.payload?.remote_ip || selectedEvent.payload?.destination_ip || selectedEvent.payload?.dst_ip || ''
                        router.visit(`/app/network?ip=${encodeURIComponent(ip)}`)
                      }}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                      style={{
                        background: 'rgba(167, 139, 250, 0.12)',
                        color: '#a78bfa',
                        border: '1px solid rgba(167, 139, 250, 0.3)',
                      }}
                    >
                      <Network className="h-4 w-4" />
                      View Network Activity
                    </button>
                  )}
                  {selectedEvent.agentId && (
                    <button
                      onClick={() => {
                        router.visit(`/app/agents/${selectedEvent.agentId}`)
                      }}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                      style={{
                        background: 'var(--surface-2)',
                        color: 'var(--fg-2)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      <Share2 className="h-4 w-4" />
                      View Agent
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--subtle)' }}>
                <div className="text-center">
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select an event to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

// ---------------------------------------------------------------------------
// Status Badge Component
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: 'healthy' | 'degraded' | 'offline' }) {
  const styles = {
    healthy: { bg: 'var(--emerald-glow)', color: 'var(--emerald-400)', border: 'rgba(47, 196, 113, 0.25)' },
    degraded: { bg: 'var(--high-bg)', color: 'var(--high)', border: 'rgba(245, 165, 36, 0.25)' },
    offline: { bg: 'var(--crit-bg)', color: 'var(--crit)', border: 'rgba(240, 80, 110, 0.25)' },
  }
  const style = styles[status] || styles.offline

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
      style={{
        background: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
      }}
    >
      {status}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Severity Pill Style Helper
// ---------------------------------------------------------------------------

function getSeverityPillStyle(severity: string, isActive: boolean): React.CSSProperties {
  if (!isActive) {
    return {
      background: 'var(--surface-2)',
      color: 'var(--muted)',
      border: '1px solid var(--border)',
    }
  }

  switch (severity) {
    case 'critical':
      return { background: 'var(--crit-bg)', color: 'var(--crit)', border: '1px solid rgba(240, 80, 110, 0.3)' }
    case 'high':
      return { background: 'var(--high-bg)', color: 'var(--high)', border: '1px solid rgba(245, 165, 36, 0.3)' }
    case 'medium':
      return { background: 'var(--med-bg)', color: 'var(--med)', border: '1px solid rgba(91, 156, 242, 0.3)' }
    case 'low':
      return { background: 'var(--low-bg)', color: 'var(--low)', border: '1px solid rgba(122, 138, 146, 0.3)' }
    default:
      return { background: 'var(--emerald-glow)', color: 'var(--emerald-400)', border: '1px solid rgba(47, 196, 113, 0.3)' }
  }
}

// ---------------------------------------------------------------------------
// Compact Severity Badge for Table
// ---------------------------------------------------------------------------

function SeverityBadgeCompact({ severity }: { severity: string }) {
  const styles: Record<string, { bg: string; color: string; label: string }> = {
    critical: { bg: 'var(--crit-bg)', color: 'var(--crit)', label: 'CRIT' },
    high: { bg: 'var(--high-bg)', color: 'var(--high)', label: 'HIGH' },
    medium: { bg: 'var(--med-bg)', color: 'var(--med)', label: 'MED' },
    low: { bg: 'var(--low-bg)', color: 'var(--low)', label: 'LOW' },
    info: { bg: 'var(--surface-2)', color: 'var(--muted)', label: 'INFO' },
  }

  const style = styles[severity] || styles.info

  return (
    <span
      className="inline-flex items-center justify-center w-12 py-0.5 rounded text-xs font-bold uppercase"
      style={{
        background: style.bg,
        color: style.color,
      }}
    >
      {style.label}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Empty State Component
// ---------------------------------------------------------------------------

function EmptyState({
  agents,
  hasActiveFilters,
  eventsUnavailable,
}: {
  agents: Array<{ id: string; hostname: string }>
  hasActiveFilters: boolean
  eventsUnavailable: boolean
}) {
  const title = eventsUnavailable
    ? 'Event history unavailable'
    : agents.length === 0
    ? 'No enrolled agents'
    : hasActiveFilters
      ? 'No events match the current filters'
      : 'No telemetry events received yet'
  const description = eventsUnavailable
    ? 'The backend could not load stored telemetry for this view. Refresh after the telemetry store recovers; live socket events can still arrive independently.'
    : agents.length === 0
    ? 'Enroll an agent before event telemetry can appear in this workspace.'
    : hasActiveFilters
      ? 'Relax the search, severity, type, agent, or time filters to inspect the stored event history.'
      : 'Events will appear here once an enrolled agent sends telemetry through the backend ingestion pipeline.'

  return (
    <div className="flex flex-col items-center justify-center h-full py-16" style={{ color: 'var(--subtle)' }}>
      {/* Large Icon */}
      <div
        className="p-6 rounded-2xl mb-6"
        style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
      >
        <Activity className="h-16 w-16" style={{ color: 'var(--muted)' }} />
      </div>

      {/* Title */}
      <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>
        {title}
      </h3>

      {/* Description */}
      <p className="text-sm text-center max-w-md mb-8" style={{ color: 'var(--muted)' }}>
        {description}
      </p>

      {/* Primary CTA */}
      <button
        onClick={() => router.visit(agents.length === 0 && !eventsUnavailable ? '/app/deploy-agent' : '/app/events')}
        className="flex items-center gap-2 px-6 py-3 rounded-lg font-medium text-sm mb-4"
        style={{
          background: 'var(--emerald-600)',
          color: 'white',
        }}
      >
        {agents.length === 0 && !eventsUnavailable ? <Plus className="h-4 w-4" /> : <RefreshCw className="h-4 w-4" />}
        {agents.length === 0 && !eventsUnavailable ? 'Enroll an agent' : 'Refresh events'}
      </button>

      {/* Secondary Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => router.reload()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
          style={{
            background: 'var(--surface-2)',
            color: 'var(--fg-2)',
            border: '1px solid var(--border)',
          }}
        >
          <RefreshCw className="h-4 w-4" />
          Run connection check
        </button>
        <button
          onClick={() => window.open('https://docs.treantlab.org/agent-setup', '_blank')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
          style={{
            background: 'var(--surface-2)',
            color: 'var(--fg-2)',
            border: '1px solid var(--border)',
          }}
        >
          <BookOpen className="h-4 w-4" />
          Read agent setup docs
        </button>
      </div>

      {/* While You Wait Cards */}
      <div className="mt-12 w-full max-w-2xl">
        <p className="text-xs font-medium uppercase tracking-wider mb-4 text-center" style={{ color: 'var(--muted)' }}>
          While you wait
        </p>
        <div className="grid grid-cols-3 gap-4">
          <WhileYouWaitCard
            icon={Shield}
            title="Configure Detection Rules"
            description="Set up YARA and Sigma rules"
            onClick={() => router.visit('/app/detection-rules')}
          />
          <WhileYouWaitCard
            icon={Zap}
            title="Set Up Response Actions"
            description="Define automated responses"
            onClick={() => router.visit('/app/response')}
          />
          <WhileYouWaitCard
            icon={UserPlus}
            title="Invite Team Members"
            description="Add analysts to your workspace"
            onClick={() => router.visit('/app/users')}
          />
        </div>
      </div>
    </div>
  )
}

function WhileYouWaitCard({
  icon: Icon,
  title,
  description,
  onClick,
}: {
  icon: React.ElementType
  title: string
  description: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center p-4 rounded-xl text-center transition-colors"
      style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--border)',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'var(--emerald-500)'
        e.currentTarget.style.background = 'var(--surface-3)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--border)'
        e.currentTarget.style.background = 'var(--surface-2)'
      }}
    >
      <Icon className="h-6 w-6 mb-2" style={{ color: 'var(--emerald-400)' }} />
      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{title}</span>
      <span className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{description}</span>
    </button>
  )
}

// ---------------------------------------------------------------------------
// Helper Functions (preserved from original)
// ---------------------------------------------------------------------------

function getEventSummary(event: Event): string {
  const p = event.payload || {}

  switch (event.eventType) {
    // Process
    case 'process_create':
    case 'process_start':
      const commandLine = p.command_line || p.cmdline || p.command || p.process_command_line
      return `${p.name || p.process_name || p.image_name || 'Unknown'} (PID: ${p.pid || p.process_id || 'N/A'})${commandLine ? ' — ' + String(commandLine).slice(0, 80) : ''}`
    case 'process_terminate':
    case 'process_end':
      return `Process ${p.pid || 'N/A'} terminated (exit code: ${p.exit_code ?? 'N/A'})`
    // File
    case 'file_create':
      return `Created: ${p.path || 'Unknown path'}`
    case 'file_modify':
      return `Modified: ${p.path || 'Unknown path'}`
    case 'file_delete':
      return `Deleted: ${p.path || 'Unknown path'}`
    case 'file_rename':
      return `Renamed: ${p.old_path || '?'} → ${p.new_path || p.path || '?'}`
    // Network
    case 'network_connect':
      return `${p.remote_ip || p.destination_ip || '?'}:${p.remote_port || p.destination_port || '?'} (${(p.protocol || 'TCP').toUpperCase()})${p.process_name ? ' by ' + p.process_name : ''}`
    case 'network_listen':
      return `Listening on ${p.local_ip || '0.0.0.0'}:${p.local_port || '?'} (${(p.protocol || 'TCP').toUpperCase()})`
    case 'dns_query':
      return `${p.query || p.domain || 'Unknown'} → ${p.response || p.resolved_ip || 'pending'}`
    // Registry
    case 'registry_modify':
    case 'registry_write':
      return `${p.key_path || p.path || 'Unknown key'}${p.value_name ? '\\' + p.value_name : ''}`
    case 'registry_create':
      return `Created: ${p.key_path || p.path || 'Unknown key'}`
    case 'registry_delete':
      return `Deleted: ${p.key_path || p.path || 'Unknown key'}`
    // Security
    case 'injection_detected':
      return `${p.technique || 'Code injection'} in PID ${p.target_pid || 'N/A'} by ${p.source_process || 'Unknown'}`
    case 'process_hollowing':
      return `Process hollowing: ${p.target_process || 'Unknown'} (PID: ${p.target_pid || 'N/A'})`
    case 'credential_access':
      return `${p.method || 'Credential access'}: ${p.target || p.source || 'Unknown target'}`
    case 'lsass_access':
      return `LSASS accessed by ${p.source_process || p.process_name || 'Unknown'} (PID: ${p.source_pid || p.pid || 'N/A'})`
    case 'amsi_scan':
      return `AMSI: ${p.content_name || 'Script'} — ${p.result || 'scanned'}`
    case 'defense_evasion':
      return `${p.technique || 'Evasion'}: ${p.description || p.detail || 'detected'}`
    // Device & I/O
    case 'usb_connect':
      return `USB connected: ${p.device_name || p.description || 'Unknown device'}`
    case 'usb_disconnect':
      return `USB disconnected: ${p.device_name || p.description || 'Unknown device'}`
    case 'clipboard_access':
      return `Clipboard accessed by ${p.process_name || 'Unknown'} (PID: ${p.pid || 'N/A'})`
    case 'input_capture':
      return `Input capture by ${p.process_name || 'Unknown'}: ${p.method || 'keyboard hook'}`
    // Lateral movement & persistence
    case 'lateral_movement':
      return `${p.technique || 'Lateral movement'}: ${p.source || '?'} → ${p.destination || '?'}`
    case 'persistence':
      return `${p.mechanism || 'Persistence'}: ${p.location || p.path || 'Unknown location'}`
    case 'scheduled_task':
      return `Task: ${p.task_name || 'Unknown'} — ${p.action || p.command || 'N/A'}`
    case 'wmi_event':
      return `WMI: ${p.query || p.operation || 'Unknown operation'}`
    // Detection
    case 'honeyfile_access':
      return `Honeyfile accessed: ${p.path || p.file_name || 'Unknown'} by ${p.process_name || 'Unknown'}`
    case 'ransomware_canary':
      return `Canary triggered: ${p.path || 'Unknown'} — ${p.operation || 'modified'}`
    case 'exploit_attempt':
      return `Exploit: ${p.technique || p.cve || 'Unknown'} targeting ${p.target || 'Unknown'}`
    case 'named_pipe':
      return `Pipe: ${p.pipe_name || 'Unknown'} by ${p.process_name || 'Unknown'}`
    case 'etw_event':
      return `ETW: ${p.provider || 'Unknown provider'} — ${p.event_name || p.event_id || 'event'}`
    case 'cloud_event':
      return `Cloud: ${p.service || 'Unknown'} — ${p.action || p.operation || 'event'}`
    default:
      return JSON.stringify(p).slice(0, 120)
  }
}

function SeverityBadge({ severity, eventType }: { severity: string; eventType: string }) {
  // Infer severity from event type if not set
  const effectiveSeverity = severity || inferSeverity(eventType)

  const severityStyles: Record<string, { bg: string; border: string; color: string }> = {
    critical: {
      bg: 'var(--crit-bg)',
      border: 'rgba(240, 80, 110, 0.3)',
      color: 'var(--crit)',
    },
    high: {
      bg: 'var(--high-bg)',
      border: 'rgba(245, 165, 36, 0.3)',
      color: 'var(--high)',
    },
    medium: {
      bg: 'var(--med-bg)',
      border: 'rgba(91, 156, 242, 0.3)',
      color: 'var(--med)',
    },
    low: {
      bg: 'var(--low-bg)',
      border: 'rgba(122, 138, 146, 0.3)',
      color: 'var(--low)',
    },
    info: {
      bg: 'var(--surface-2)',
      border: 'var(--border)',
      color: 'var(--muted)',
    },
  }

  const style = severityStyles[effectiveSeverity] || severityStyles.info

  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
      style={{
        background: style.bg,
        border: `1px solid ${style.border}`,
        color: style.color,
      }}
    >
      {safeCapitalize(effectiveSeverity)}
    </span>
  )
}

function inferSeverity(eventType: string): string {
  const critical = ['injection_detected', 'process_hollowing', 'lsass_access', 'ransomware_canary', 'exploit_attempt']
  const high = ['credential_access', 'defense_evasion', 'lateral_movement', 'honeyfile_access', 'input_capture']
  const medium = ['persistence', 'amsi_scan', 'scheduled_task', 'wmi_event']
  const low = ['process_create', 'process_terminate', 'process_start', 'process_end', 'file_create', 'file_modify', 'file_delete', 'file_rename', 'registry_modify', 'registry_write', 'registry_create', 'registry_delete']

  if (critical.includes(eventType)) return 'critical'
  if (high.includes(eventType)) return 'high'
  if (medium.includes(eventType)) return 'medium'
  if (low.includes(eventType)) return 'low'
  return 'info'
}

function hasProcessContext(event: Event): boolean {
  const p = event.payload || {}
  return !!(p.pid || p.process_pid) || ['process_create', 'process_start', 'process_terminate', 'process_end'].includes(event.eventType)
}

function hasNetworkContext(event: Event): boolean {
  const p = event.payload || {}
  return !!(p.remote_ip || p.destination_ip || p.dst_ip) || ['network_connect', 'network_listen', 'dns_query'].includes(event.eventType)
}

function buildHuntQuery(event: Event): string {
  const p = event.payload || {}
  switch (event.eventType) {
    case 'process_create':
    case 'process_start':
      if (p.sha256) return `hash:${p.sha256}`
      if (p.name) return `process_name:${p.name}`
      return `event_type:${event.eventType}`
    case 'process_terminate':
    case 'process_end':
      return `pid:${p.pid || ''}`
    case 'file_create':
    case 'file_modify':
    case 'file_delete':
    case 'file_rename':
      if (p.sha256) return `hash:${p.sha256}`
      return `file_path:${p.path || p.new_path || ''}`
    case 'network_connect':
    case 'network_listen':
      return `remote_ip:${p.remote_ip || p.destination_ip || ''}`
    case 'dns_query':
      return `domain:${p.query || p.domain || ''}`
    case 'registry_modify':
    case 'registry_write':
    case 'registry_create':
    case 'registry_delete':
      return `registry_key:${p.key_path || p.path || ''}`
    case 'injection_detected':
    case 'process_hollowing':
      return `target_pid:${p.target_pid || ''}`
    case 'lsass_access':
    case 'credential_access':
      return `source_process:${p.source_process || p.process_name || ''}`
    default:
      return `event_type:${event.eventType}`
  }
}
