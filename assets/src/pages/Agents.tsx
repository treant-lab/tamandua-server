import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Monitor, Wifi, WifiOff, AlertCircle, Clock, Cpu, HardDrive,
  Search, RefreshCw, Shield, ShieldOff, RotateCcw, ExternalLink,
  Activity, Bell, ChevronDown, ChevronUp, Terminal, Eye,
  Lock, Download, LayoutGrid, LayoutList, Plus, Smartphone
} from 'lucide-react'
import { cn, formatDate, formatRelativeTime, safeCapitalize } from '@/lib/utils'
import { ExportDropdown } from '@/components/ExportDropdown'
import { NoAgentsEmptyState, NoResultsEmptyState } from '@/components/ui/EmptyState'
import { Tooltip } from '@/components/ui/baseui'
import { useState, useCallback, useEffect, useMemo } from 'react'
import type { Agent } from '@/types'

interface AgentEnriched extends Agent {
  isolated?: boolean
  eventCount?: number
  alertCount?: number
  platform_capabilities?: PlatformCapability[]
  platformCapabilities?: PlatformCapability[]
  health?: {
    cpu_usage: number
    memory_usage: number
    disk_usage: number
    uptime_seconds: number
  } | null
  health_status?: AgentHealthStatus | null
}

type DataSourceKey = 'process' | 'file' | 'dns' | 'network' | 'registry' | 'driver' | 'ai' | 'ndr'
type DataSourceStatus = 'healthy' | 'stale' | 'missing'

interface NormalizedDataSourceHealth {
  name: DataSourceKey
  status: DataSourceStatus
  count: number
  lastSeen: string | null
  missingReason: string | null
}

interface AgentDataSourceHealth {
  status: 'recent' | 'stale' | 'none'
  generatedAt?: string | null
  periods: Record<'lastHour' | 'last24h' | 'last7d', Record<DataSourceKey, number>>
  lastSeen: Record<DataSourceKey, string | null>
  sourceStates: Record<DataSourceKey, NormalizedDataSourceHealth>
  totalLast24h: number
  totalLast7d: number
}

interface DataSourceApiSource {
  name: DataSourceKey
  status: DataSourceStatus
  count: number
  lastSeen: string | null
  missingReason: string | null
}

interface AgentDataSourceApiHealth {
  agentId: string
  hostname?: string
  windowHours?: number
  lastTelemetryAt?: string | null
  lastHeartbeatAt?: string | null
  heartbeatState?: 'online' | 'offline' | string
  healthStatus?: AgentHealthStatus | null
  driverStatus?: DriverStatus | null
  platformStatus?: PlatformSensorStatus[]
  platformCapabilities?: PlatformCapability[]
  dropCounters?: Record<string, number>
  sources: DataSourceApiSource[]
  missingSources?: DataSourceKey[]
  receivingSources?: DataSourceKey[]
}

interface AgentHealthStatus {
  status: 'healthy' | 'degraded' | 'critical' | 'unknown' | string
  reasons?: string[]
  metrics?: Record<string, unknown>
}

interface PlatformSensorStatus {
  name: string
  platform?: string
  kind?: string
  state?: string
  configured?: boolean
  compiled?: boolean
  running?: boolean
  reason?: string | null
  detail?: string | null
}

type CapabilityMaturity = 'supported' | 'partial' | 'lab' | 'unavailable' | string

interface PlatformCapability {
  id: string
  name: string
  platform?: string
  maturity: CapabilityMaturity
  status?: CapabilityMaturity
  observed?: 'observed' | 'reported' | 'not_observed' | string
  detail?: string
}

interface CollectorSignal {
  name: string
  status?: string
  events_collected?: number
  last_event_at?: string | null
  error_message?: string | null
}

interface DriverStatus {
  supported?: boolean
  loaded?: boolean
  connected?: boolean
  state?: 'unsupported' | 'loaded' | 'loaded_no_telemetry' | 'not_loaded' | string
  platform?: string
  provider?: string
  service_name?: string
  entitlement_status?: string
  lab_level?: number
  feature_level?: string
  protocol_version?: number
  buffer_size?: number
  events_read?: number
  events_consumed?: number
  events_dropped?: number
  channel_drops?: number
  kernel_events_dropped?: number
  last_error?: string | null
}

interface AgentCapabilities {
  reported?: unknown
  collectors?: CollectorSignal[]
  reported_collectors?: Record<string, unknown>
  runtime?: Record<string, unknown>
  summary?: {
    capability_count?: number
    collector_count?: number
  }
}

interface MobileOverview {
  linked?: boolean
  error?: string
  device?: Record<string, unknown>
  posture?: Record<string, unknown>
  app_inventory?: Record<string, unknown>
  app_guard?: Record<string, unknown>
  commands?: Array<Record<string, unknown>>
}

interface AgentsPageProps {
  agents: AgentEnriched[]
  dataSourceHealth?: Record<string, AgentDataSourceHealth>
}

function getCsrfHeaders(): Record<string, string> {
  const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
  return token ? { 'X-CSRF-Token': token } : {}
}

type StatusFilter = 'all' | 'online' | 'offline' | 'degraded' | 'isolated'
type OsFilter = 'all' | 'windows' | 'linux' | 'macos' | 'android' | 'ios'
type SortField = 'hostname' | 'status' | 'os_type' | 'last_seen' | 'ip_address'
type SortDir = 'asc' | 'desc'
type ViewMode = 'table' | 'grid'

export default function Agents({ agents: rawAgents, dataSourceHealth = {} }: AgentsPageProps) {
  const agents = rawAgents || []
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [osFilter, setOsFilter] = useState<OsFilter>('all')
  const [sortField, setSortField] = useState<SortField>('status')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [viewMode, setViewMode] = useState<ViewMode>('table')
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null)
  const [agentDetails, setAgentDetails] = useState<Record<string, any>>({})
  const [loadingDetails, setLoadingDetails] = useState<string | null>(null)
  const [mobileOverviews, setMobileOverviews] = useState<Record<string, MobileOverview>>({})
  const [loadingMobileOverview, setLoadingMobileOverview] = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [apiSourceHealth, setApiSourceHealth] = useState<AgentDataSourceApiHealth[] | null>(null)
  const [sourceHealthError, setSourceHealthError] = useState<string | null>(null)
  const [loadingSourceHealth, setLoadingSourceHealth] = useState(false)

  // Stats
  const onlineCount = agents.filter(a => a.status === 'online').length
  const offlineCount = agents.filter(a => a.status === 'offline').length
  const degradedCount = agents.filter(a => a.status === 'degraded').length
  const isolatedCount = agents.filter(a => a.isolated).length
  const windowsCount = agents.filter(a => a.os_type?.toLowerCase().includes('windows')).length
  const linuxCount = agents.filter(a => a.os_type?.toLowerCase().includes('linux')).length
  const macCount = agents.filter(a => a.os_type?.toLowerCase().includes('mac') || a.os_type?.toLowerCase().includes('darwin')).length
  const androidCount = agents.filter(a => a.os_type?.toLowerCase().includes('android')).length
  const iosCount = agents.filter(a => {
    const os = a.os_type?.toLowerCase() || ''
    return os.includes('ios') || os.includes('iphone') || os.includes('ipad')
  }).length

  const mergedDataSourceHealth = useMemo(() => {
    const merged: Record<string, AgentDataSourceHealth> = { ...(dataSourceHealth || {}) }

    for (const row of apiSourceHealth || []) {
      if (!row.agentId) continue
      merged[row.agentId] = apiSourceHealthToCoverage(row, merged[row.agentId])
    }

    return merged
  }, [apiSourceHealth, dataSourceHealth])

  // Calculate last check-in time (most recent last_seen)
  const lastCheckIn = useMemo(() => {
    if (agents.length === 0) return null
    const timestamps = agents
      .map(a => a.last_seen)
      .filter(Boolean)
      .map(ts => new Date(ts).getTime())
    if (timestamps.length === 0) return null
    return Math.max(...timestamps)
  }, [agents])

  const fetchDataSourceHealth = useCallback(async () => {
    setLoadingSourceHealth(true)
    setSourceHealthError(null)
    try {
      const res = await fetch('/api/v1/agents/data-sources/health?hours=24', {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      })
      if (!res.ok) throw new Error(`Data source health unavailable (${res.status})`)
      const json = await res.json()
      const rows = Array.isArray(json.data) ? json.data : []
      setApiSourceHealth(rows.map(normalizeApiSourceHealth).filter(Boolean))
    } catch (error) {
      setApiSourceHealth(null)
      setSourceHealthError(error instanceof Error ? error.message : 'Data source health unavailable')
    } finally {
      setLoadingSourceHealth(false)
    }
  }, [])

  useEffect(() => {
    fetchDataSourceHealth()
  }, [fetchDataSourceHealth])

  // Filter and sort
  const filteredAgents = useMemo(() => {
    let result = [...agents]

    // Search
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(a =>
        a.hostname?.toLowerCase().includes(q) ||
        a.ip_address?.toLowerCase().includes(q) ||
        a.id?.toLowerCase().includes(q) ||
        a.os_type?.toLowerCase().includes(q)
      )
    }

    // Status filter
    if (statusFilter !== 'all') {
      if (statusFilter === 'isolated') {
        result = result.filter(a => a.isolated)
      } else {
        result = result.filter(a => a.status === statusFilter)
      }
    }

    // OS filter
    if (osFilter !== 'all') {
      result = result.filter(a => {
        const os = (a.os_type || '').toLowerCase()
        switch (osFilter) {
          case 'windows': return os.includes('windows')
          case 'linux': return os.includes('linux')
          case 'macos': return os.includes('mac') || os.includes('darwin')
          case 'android': return os.includes('android')
          case 'ios': return os.includes('ios') || os.includes('iphone') || os.includes('ipad')
          default: return true
        }
      })
    }

    // Sort
    const statusOrder: Record<string, number> = { online: 0, degraded: 1, offline: 2 }
    result.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'hostname':
          cmp = (a.hostname || '').localeCompare(b.hostname || '')
          break
        case 'status':
          cmp = (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3)
          break
        case 'os_type':
          cmp = (a.os_type || '').localeCompare(b.os_type || '')
          break
        case 'ip_address':
          cmp = (a.ip_address || '').localeCompare(b.ip_address || '')
          break
        case 'last_seen':
          cmp = (a.last_seen || '').localeCompare(b.last_seen || '')
          break
      }
      return sortDir === 'desc' ? -cmp : cmp
    })

    return result
  }, [agents, search, statusFilter, osFilter, sortField, sortDir])

  // Fetch agent details (health, events, alerts) on expand
  const fetchAgentDetails = useCallback(async (agentId: string) => {
    if (agentDetails[agentId]) return
    setLoadingDetails(agentId)
    try {
      const res = await fetch(`/api/v1/agents/${agentId}`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const json = await res.json()
        setAgentDetails(prev => ({ ...prev, [agentId]: json.data || json }))
      }
    } catch { /* ignore */ } finally {
      setLoadingDetails(null)
    }
  }, [agentDetails])

  const fetchMobileOverview = useCallback(async (agentId: string) => {
    if (mobileOverviews[agentId]) return
    setLoadingMobileOverview(agentId)
    try {
      const res = await fetch(`/api/v1/mobile/agents/${agentId}/overview`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (!res.ok) throw new Error(`Mobile endpoint overview failed (${res.status})`)
      const json = await res.json()
      setMobileOverviews(prev => ({ ...prev, [agentId]: json.data || json }))
    } catch (error) {
      setMobileOverviews(prev => ({
        ...prev,
        [agentId]: {
          linked: false,
          error: error instanceof Error ? error.message : 'Mobile endpoint overview failed',
        },
      }))
    } finally {
      setLoadingMobileOverview(null)
    }
  }, [mobileOverviews])

  const toggleExpand = useCallback((agentId: string) => {
    if (expandedAgent === agentId) {
      setExpandedAgent(null)
    } else {
      setExpandedAgent(agentId)
      fetchAgentDetails(agentId)
      const agent = agents.find(item => item.id === agentId)
      if (isMobilePlatform(agent?.os_type)) {
        fetchMobileOverview(agentId)
      }
    }
  }, [agents, expandedAgent, fetchAgentDetails, fetchMobileOverview])

  // Agent actions
  const isolateAgent = useCallback(async (agentId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Isolate this agent from the network? It will only communicate with the Tamandua server.')) return
    setActionLoading(agentId)
    setActionError(null)
    try {
      const res = await fetch(`/api/v1/agents/${agentId}/isolate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...getCsrfHeaders() },
      })
      if (!res.ok) throw new Error(`Isolation request failed (${res.status})`)
      router.reload()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Isolation request failed')
    } finally {
      setActionLoading(null)
    }
  }, [])

  const unisolateAgent = useCallback(async (agentId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setActionLoading(agentId)
    setActionError(null)
    try {
      const res = await fetch(`/api/v1/agents/${agentId}/unisolate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...getCsrfHeaders() },
      })
      if (!res.ok) throw new Error(`Remove isolation request failed (${res.status})`)
      router.reload()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Remove isolation request failed')
    } finally {
      setActionLoading(null)
    }
  }, [])

  const restartAgent = useCallback(async (agentId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Restart this agent? It will reconnect automatically.')) return
    setActionLoading(agentId)
    setActionError(null)
    try {
      const res = await fetch(`/api/v1/agents/${agentId}/restart`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...getCsrfHeaders() },
      })
      if (!res.ok) throw new Error(`Restart request failed (${res.status})`)
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Restart request failed')
    } finally {
      setActionLoading(null)
    }
  }, [])

  const handleRefresh = useCallback(() => {
    setRefreshing(true)
    fetchDataSourceHealth()
    router.reload({ onFinish: () => setRefreshing(false) })
  }, [fetchDataSourceHealth])

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }, [sortField])

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null
    return sortDir === 'asc'
      ? <ChevronUp className="h-3 w-3 inline ml-1" />
      : <ChevronDown className="h-3 w-3 inline ml-1" />
  }

  return (
    <MainLayout title="Agents">
      <Head title="Agents - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Agents</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Manage and monitor your endpoint agents
            </p>
          </div>
          <Link
            href="/app/deploy-agent"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-primary-600 rounded-lg text-white hover:bg-primary-500 transition-colors font-medium"
          >
            <Plus className="h-4 w-4" />
            Deploy Agent
          </Link>
        </div>

        {actionError && (
          <div
            className="rounded-lg border px-4 py-3 text-sm"
            style={{
              backgroundColor: 'var(--crit-bg)',
              borderColor: 'var(--crit)',
              color: 'var(--crit)',
            }}
          >
            {actionError}
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {/* Total Agents */}
          <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary-500/20">
                <Monitor className="h-5 w-5 text-primary-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{agents.length}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Agents</p>
              </div>
            </div>
          </div>

          {/* Online */}
          <div
            className={cn(
              'rounded-xl border p-4 cursor-pointer transition-all',
              statusFilter === 'online' && 'ring-2 ring-emerald-500/50'
            )}
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
            onClick={() => setStatusFilter(statusFilter === 'online' ? 'all' : 'online')}
          >
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full animate-pulse" style={{ backgroundColor: 'var(--emerald-400)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{onlineCount}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Online</p>
              </div>
            </div>
          </div>

          {/* Offline */}
          <div
            className={cn(
              'rounded-xl border p-4 cursor-pointer transition-all',
              statusFilter === 'offline' && 'ring-2 ring-red-500/50'
            )}
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
            onClick={() => setStatusFilter(statusFilter === 'offline' ? 'all' : 'offline')}
          >
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full" style={{ backgroundColor: 'var(--crit)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{offlineCount}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Offline</p>
              </div>
            </div>
          </div>

          {/* Isolated */}
          <div
            className={cn(
              'rounded-xl border p-4 cursor-pointer transition-all',
              statusFilter === 'isolated' && 'ring-2 ring-amber-500/50'
            )}
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
            onClick={() => setStatusFilter(statusFilter === 'isolated' ? 'all' : 'isolated')}
          >
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full" style={{ backgroundColor: 'var(--high)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{isolatedCount}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Isolated</p>
              </div>
            </div>
          </div>

          {/* Last Check-in */}
          <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(99, 102, 241, 0.2)' }}>
                <Clock className="h-5 w-5" style={{ color: 'var(--primary)' }} />
              </div>
              <div>
                <p className="text-lg font-bold" style={{ color: 'var(--fg)' }}>
                  {lastCheckIn ? formatRelativeTime(lastCheckIn) : '--'}
                </p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Last Check-in</p>
              </div>
            </div>
          </div>
        </div>

        <FleetDataSourceHealthPanel
          health={apiSourceHealth}
          fallbackHealth={mergedDataSourceHealth}
          loading={loadingSourceHealth}
          error={sourceHealthError}
          onRefresh={fetchDataSourceHealth}
        />

        {/* Filter Bar */}
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
          <div className="flex flex-wrap items-center gap-4">
            {/* Status Filter */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Status</span>
              <div className="flex items-center gap-1">
                {([
                  { value: 'all' as StatusFilter, label: 'All', count: agents.length },
                  { value: 'online' as StatusFilter, label: 'Online', count: onlineCount, dot: 'var(--emerald-400)' },
                  { value: 'offline' as StatusFilter, label: 'Offline', count: offlineCount, dot: 'var(--crit)' },
                  { value: 'isolated' as StatusFilter, label: 'Isolated', count: isolatedCount, dot: 'var(--high)' },
                  { value: 'degraded' as StatusFilter, label: 'Degraded', count: degradedCount, dot: 'var(--warn)' },
                ] as const).map(s => (
                  <button
                    key={s.value}
                    onClick={() => setStatusFilter(s.value)}
                    className={cn(
                      'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all',
                      statusFilter === s.value
                        ? 'bg-primary-500 text-white'
                        : 'border hover:bg-[var(--surface-2)]'
                    )}
                    style={statusFilter !== s.value ? {
                      backgroundColor: 'var(--surface-alt)',
                      borderColor: 'var(--border)',
                      color: 'var(--fg-2)'
                    } : undefined}
                  >
                    {s.dot && statusFilter !== s.value && (
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: s.dot }} />
                    )}
                    {s.label}
                    <span className={cn(
                      'px-1.5 py-0.5 rounded-full text-[10px] font-semibold',
                      statusFilter === s.value ? 'bg-white/20' : 'bg-[var(--surface-3)]'
                    )}>
                      {s.count}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Divider */}
            <div className="h-6 w-px" style={{ backgroundColor: 'var(--border)' }} />

            {/* OS Filter */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>OS</span>
              <div className="flex items-center gap-1">
                {([
                  { value: 'all' as OsFilter, label: 'All', icon: null },
                  { value: 'windows' as OsFilter, label: 'Windows', count: windowsCount, icon: 'windows' },
                  { value: 'linux' as OsFilter, label: 'Linux', count: linuxCount, icon: 'linux' },
                  { value: 'macos' as OsFilter, label: 'macOS', count: macCount, icon: 'macos' },
                  { value: 'android' as OsFilter, label: 'Android', count: androidCount, icon: 'android' },
                  { value: 'ios' as OsFilter, label: 'iOS', count: iosCount, icon: 'ios' },
                ] as const).map(o => (
                  <button
                    key={o.value}
                    onClick={() => setOsFilter(o.value)}
                    className={cn(
                      'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all',
                      osFilter === o.value
                        ? 'bg-cyan-500 text-white'
                        : 'border hover:bg-[var(--surface-2)]'
                    )}
                    style={osFilter !== o.value ? {
                      backgroundColor: 'var(--surface-alt)',
                      borderColor: 'var(--border)',
                      color: 'var(--fg-2)'
                    } : undefined}
                  >
                    {o.icon && <OsIconSmall os={o.icon} active={osFilter === o.value} />}
                    {o.label}
                    {o.count !== undefined && (
                      <span className={cn(
                        'px-1.5 py-0.5 rounded-full text-[10px] font-semibold',
                        osFilter === o.value ? 'bg-white/20' : 'bg-[var(--surface-3)]'
                      )}>
                        {o.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Divider */}
            <div className="h-6 w-px" style={{ backgroundColor: 'var(--border)' }} />

            {/* Search */}
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                placeholder="Search hostname..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                style={{
                  backgroundColor: 'var(--surface-alt)',
                  borderColor: 'var(--border)',
                  color: 'var(--fg)',
                  border: '1px solid var(--border)'
                }}
              />
            </div>

            {/* View Toggle & Actions */}
            <div className="flex items-center gap-2 ml-auto">
              {/* View Mode Toggle */}
              <div className="flex items-center rounded-lg border" style={{ borderColor: 'var(--border)' }}>
                <Tooltip content="Table view">
                  <button
                    onClick={() => setViewMode('table')}
                    className={cn(
                      'p-2 rounded-l-lg transition-colors',
                      viewMode === 'table' ? 'bg-primary-500 text-white' : 'hover:bg-[var(--surface-2)]'
                    )}
                    style={viewMode !== 'table' ? { color: 'var(--muted)' } : undefined}
                    aria-label="Table view"
                  >
                    <LayoutList className="h-4 w-4" />
                  </button>
                </Tooltip>
                <Tooltip content="Grid view">
                  <button
                    onClick={() => setViewMode('grid')}
                    className={cn(
                      'p-2 rounded-r-lg transition-colors',
                      viewMode === 'grid' ? 'bg-primary-500 text-white' : 'hover:bg-[var(--surface-2)]'
                    )}
                    style={viewMode !== 'grid' ? { color: 'var(--muted)' } : undefined}
                    aria-label="Grid view"
                  >
                    <LayoutGrid className="h-4 w-4" />
                  </button>
                </Tooltip>
              </div>

              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors disabled:opacity-50 border hover:bg-[var(--surface-2)]"
                style={{
                  backgroundColor: 'transparent',
                  borderColor: 'var(--border)',
                  color: 'var(--fg)'
                }}
              >
                <RefreshCw className={cn('h-4 w-4', refreshing && 'animate-spin')} />
              </button>

              <ExportDropdown
                getData={() => filteredAgents.map(a => ({
                  id: a.id,
                  hostname: a.hostname,
                  ip_address: a.ip_address,
                  os_type: a.os_type,
                  os_version: a.os_version,
                  agent_version: a.agent_version,
                  status: a.status,
                  isolated: a.isolated,
                  last_seen: a.last_seen,
                }))}
                filenameBase="tamandua-agents"
                disabled={filteredAgents.length === 0}
              />
            </div>
          </div>
        </div>

        {/* Empty State - No Agents at All */}
        {agents.length === 0 && (
          <div className="rounded-xl border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <NoAgentsEmptyState
              onDeploy={() => router.visit('/app/deploy-agent')}
            />
          </div>
        )}

        {/* Empty State - No Results Match Filters */}
        {agents.length > 0 && filteredAgents.length === 0 && (
          <div className="rounded-xl border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <NoResultsEmptyState
              searchQuery={search}
              onClear={() => {
                setSearch('')
                setStatusFilter('all')
                setOsFilter('all')
              }}
            />
          </div>
        )}

        {/* Grid View */}
        {viewMode === 'grid' && filteredAgents.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredAgents.map((agent) => (
              <AgentCard
                key={agent.id}
                agent={agent}
                dataSourceHealth={mergedDataSourceHealth[agent.id]}
                onIsolate={isolateAgent}
                onUnisolate={unisolateAgent}
                actionLoading={actionLoading}
              />
            ))}
          </div>
        )}

        {/* Table View */}
        {viewMode === 'table' && filteredAgents.length > 0 && (
          <div className="rounded-xl border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-4 text-sm font-medium cursor-pointer hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                      onClick={() => handleSort('status')}>
                      Status <SortIcon field="status" />
                    </th>
                    <th className="text-left p-4 text-sm font-medium cursor-pointer hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                      onClick={() => handleSort('hostname')}>
                      Hostname <SortIcon field="hostname" />
                    </th>
                    <th className="text-left p-4 text-sm font-medium cursor-pointer hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                      onClick={() => handleSort('ip_address')}>
                      IP Address <SortIcon field="ip_address" />
                    </th>
                    <th className="text-left p-4 text-sm font-medium cursor-pointer hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                      onClick={() => handleSort('os_type')}>
                      OS <SortIcon field="os_type" />
                    </th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Version</th>
                    <th className="text-left p-4 text-sm font-medium cursor-pointer hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                      onClick={() => handleSort('last_seen')}>
                      Last Seen <SortIcon field="last_seen" />
                    </th>
                    <th className="text-right p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAgents.map((agent) => {
                    const mobileAgent = isMobilePlatform(agent.os_type)
                    return (
                    <>
                      <tr
                        key={agent.id}
                        className={cn(
                          'cursor-pointer transition-colors',
                          expandedAgent === agent.id && 'opacity-90'
                        )}
                        style={{
                          borderBottom: '1px solid var(--border)',
                          backgroundColor: agent.isolated ? 'rgba(240, 80, 110, 0.05)' : undefined
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = agent.isolated ? 'rgba(240, 80, 110, 0.1)' : 'var(--surface-alt)'}
                        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = agent.isolated ? 'rgba(240, 80, 110, 0.05)' : 'transparent'}
                        onClick={() => toggleExpand(agent.id)}
                      >
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <StatusBadge status={agent.status} />
                            {agent.isolated && (
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium"
                                style={{ backgroundColor: 'rgba(240, 80, 110, 0.2)', color: 'var(--crit)' }}>
                                <Lock className="h-2.5 w-2.5" /> Isolated
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-4">
                          <Link
                            href={`/app/agents/${agent.id}`}
                            className="flex items-center gap-2 group"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <OsIcon os={agent.os_type} />
                            <span className="font-medium group-hover:text-primary-400 transition-colors" style={{ color: 'var(--fg)' }}>
                              {agent.hostname}
                            </span>
                          </Link>
                          <span className="font-mono text-[10px]" style={{ color: 'var(--muted)' }}>{agent.id?.substring(0, 12)}</span>
                          <DataSourceHealthInline health={mergedDataSourceHealth[agent.id]} />
                          <PlatformCapabilityStrip capabilities={getAgentPlatformCapabilities(agent, apiSourceHealth)} />
                        </td>
                        <td className="p-4 font-mono text-sm" style={{ color: 'var(--fg)' }}>
                          {agent.ip_address || <span style={{ color: 'var(--muted)' }}>-</span>}
                        </td>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <OsBadge os={agent.os_type} />
                            <span className="text-sm" style={{ color: 'var(--muted)' }}>{agent.os_version}</span>
                          </div>
                        </td>
                        <td className="p-4 font-mono text-xs" style={{ color: 'var(--muted)' }}>{agent.agent_version}</td>
                        <td className="p-4">
                          <div className="flex items-center gap-2" style={{ color: 'var(--muted)' }}>
                            <Clock className="h-3.5 w-3.5" />
                            <span className="text-xs">{formatRelativeTime(new Date(agent.last_seen).getTime())}</span>
                          </div>
                        </td>
                        <td className="p-4">
                          <div className="flex items-center justify-end gap-1">
                            <Tooltip content="View Details">
                              <Link
                                href={`/app/agents/${agent.id}`}
                                className="p-1.5 rounded-lg transition-colors hover:bg-[var(--surface-2)]"
                                style={{ color: 'var(--muted)' }}
                                aria-label="View Details"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <Eye className="h-4 w-4" />
                              </Link>
                            </Tooltip>
                            {agent.isolated ? (
                              <Tooltip content="Remove Isolation">
                                <button
                                  onClick={(e) => unisolateAgent(agent.id, e)}
                                  disabled={actionLoading === agent.id || mobileAgent}
                                  className="p-1.5 rounded-lg transition-colors disabled:opacity-50 hover:bg-[var(--surface-2)]"
                                  style={{ color: 'var(--emerald-400)' }}
                                  aria-label={mobileAgent ? 'Host isolation unavailable for mobile endpoint' : 'Remove Isolation'}
                                >
                                  <ShieldOff className="h-4 w-4" />
                                </button>
                              </Tooltip>
                            ) : (
                              <Tooltip content={mobileAgent ? 'Host network isolation is not available for mobile endpoints' : 'Network Isolate'}>
                                <button
                                  onClick={(e) => isolateAgent(agent.id, e)}
                                  disabled={actionLoading === agent.id || agent.status === 'offline' || mobileAgent}
                                  className="p-1.5 rounded-lg transition-colors disabled:opacity-50 hover:bg-[var(--surface-2)]"
                                  style={{ color: 'var(--high)' }}
                                  aria-label={mobileAgent ? 'Host isolation unavailable for mobile endpoint' : 'Network Isolate'}
                                >
                                  <Shield className="h-4 w-4" />
                                </button>
                              </Tooltip>
                            )}
                          </div>
                        </td>
                      </tr>
                      {/* Expanded details row */}
                      {expandedAgent === agent.id && (
                        <tr key={`${agent.id}-detail`} style={{ backgroundColor: 'var(--surface-alt)' }}>
                          <td colSpan={7} className="p-0">
                            <AgentDetailPanel
                              agentId={agent.id}
                              osType={agent.os_type}
                              details={agentDetails[agent.id]}
                              loading={loadingDetails === agent.id}
                              dataSourceHealth={mergedDataSourceHealth[agent.id]}
                              fallbackCapabilities={getAgentPlatformCapabilities(agent, apiSourceHealth)}
                              mobileOverview={mobileOverviews[agent.id] || null}
                              mobileOverviewLoading={loadingMobileOverview === agent.id}
                            />
                          </td>
                        </tr>
                      )}
                    </>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="p-3 text-sm text-center" style={{ borderTop: '1px solid var(--border)', color: 'var(--muted)' }}>
              Showing {filteredAgents.length} of {agents.length} agents
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}

function AgentDetailPanel({
  agentId,
  osType,
  details,
  loading,
  dataSourceHealth,
  fallbackCapabilities,
  mobileOverview,
  mobileOverviewLoading,
}: {
  agentId: string
  osType?: string
  details: any
  loading: boolean
  dataSourceHealth?: AgentDataSourceHealth
  fallbackCapabilities?: PlatformCapability[]
  mobileOverview?: MobileOverview | null
  mobileOverviewLoading?: boolean
}) {
  if (loading) {
    return (
      <div className="p-6 text-center" style={{ color: 'var(--muted)' }}>
        <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2" />
        Loading agent details...
      </div>
    )
  }

  if (!details) {
    return (
      <div className="p-6 text-center" style={{ color: 'var(--muted)' }}>
        Failed to load details.{' '}
        <Link href={`/app/agents/${agentId}`} className="text-primary-400 hover:underline">
          Open full detail page
        </Link>
      </div>
    )
  }

  const health = details.health
  const collectors = details.collectors || []
  const recentEvents = details.events?.slice(0, 5) || []
  const recentAlerts = details.alerts?.slice(0, 3) || []
  const observedDataSources = details.dataSourceHealth || dataSourceHealth
  const mobileAgent = isMobilePlatform(osType || details.agent?.os_type || details.os_type)
  const platformCapabilities = normalizePlatformCapabilities(
    details.platformCapabilities || details.platform_capabilities || fallbackCapabilities
  )

  return (
    <div className="p-4 space-y-4" style={{ borderTop: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {mobileAgent ? (
          <CompactMobileEndpointOverview overview={mobileOverview} loading={!!mobileOverviewLoading} />
        ) : (
          <div className="space-y-2">
            <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <Activity className="h-4 w-4" /> System Health
            </h4>
            {health ? (
              <div className="space-y-2">
                <HealthBar label="CPU" value={health.cpu_usage} />
                <HealthBar label="Memory" value={health.memory_usage} />
                <HealthBar label="Disk" value={health.disk_usage} />
                {health.uptime_seconds > 0 && (
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Uptime: {formatUptime(health.uptime_seconds)}
                  </p>
                )}
                <DriverStatusCompact status={health.driver_status} />
              </div>
            ) : (
              <p className="text-xs" style={{ color: 'var(--muted)' }}>No health data available</p>
            )}
          </div>
        )}

        {/* Collectors */}
        <div className="space-y-2">
          <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Cpu className="h-4 w-4" /> Collector Signals ({collectors.length})
          </h4>
          <p className="text-[10px]" style={{ color: 'var(--muted)' }}>
            Derived from recent events and agent config, not a live collector attestation.
          </p>
          {collectors.length > 0 ? (
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {collectors.slice(0, 8).map((c: any) => (
                <div key={c.name} className="flex items-center justify-between text-xs">
                  <span style={{ color: 'var(--fg)' }}>{c.name}</span>
                  <span style={{ color: 'var(--muted)' }}>{c.events_collected} events</span>
                </div>
              ))}
              {collectors.length > 8 && (
                <p className="text-xs" style={{ color: 'var(--muted)' }}>+{collectors.length - 8} more</p>
              )}
            </div>
          ) : (
            <p className="text-xs" style={{ color: 'var(--muted)' }}>No collector data</p>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="space-y-2">
          <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Bell className="h-4 w-4" /> Recent Alerts ({recentAlerts.length})
          </h4>
          {recentAlerts.length > 0 ? (
            <div className="space-y-1">
              {recentAlerts.map((a: any) => (
                <Link key={a.id} href={`/app/alerts/${a.id}`} className="block p-1.5 rounded transition-colors hover:opacity-80"
                  style={{ backgroundColor: 'var(--surface-alt)' }}>
                  <div className="flex items-center gap-2">
                    <span className={cn(
                      'h-1.5 w-1.5 rounded-full'
                    )} style={{
                      backgroundColor: a.severity === 'critical' ? 'var(--crit)' :
                        a.severity === 'high' ? 'var(--high)' :
                        a.severity === 'medium' ? 'var(--med)' : 'var(--low)'
                    }} />
                    <span className="text-xs truncate" style={{ color: 'var(--fg)' }}>{a.title}</span>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-xs" style={{ color: 'var(--muted)' }}>No recent alerts</p>
          )}
        </div>

        <CollectorPolicySummary details={details} collectors={collectors} />
      </div>

      <DataSourceHealthPanel health={observedDataSources} />

      <PlatformCapabilitiesPanel capabilities={platformCapabilities} compact />

      {/* Recent Events */}
      {recentEvents.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>Recent Events</h4>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-1">
            {recentEvents.map((ev: any) => (
              <div key={ev.id} className="flex items-center gap-2 text-xs p-1.5 rounded"
                style={{ backgroundColor: 'var(--surface-alt)' }}>
                <span style={{ color: 'var(--muted)' }}>{ev.event_type || ev.eventType}</span>
                <span className="truncate flex-1" style={{ color: 'var(--fg)' }}>{ev.summary}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex justify-end">
        <Link
          href={`/app/agents/${agentId}`}
          className="flex items-center gap-1.5 text-xs text-primary-400 hover:text-primary-300 transition-colors"
        >
          View Full Details <ExternalLink className="h-3 w-3" />
        </Link>
      </div>
    </div>
  )
}

function CompactMobileEndpointOverview({
  overview,
  loading,
}: {
  overview?: MobileOverview | null
  loading: boolean
}) {
  const device = overview?.device || {}
  const posture = overview?.posture || {}
  const appInventory = overview?.app_inventory || {}
  const appGuard = overview?.app_guard || {}
  const riskScore = firstDefined(device.risk_score, posture.risk_score, overview && (overview as Record<string, unknown>).risk_score)
  const lastSync = firstDefined(device.last_seen_at, posture.last_seen_at, device.last_sync_at, posture.last_sync_at)
  const appTotal = firstDefined(
    appInventory.total,
    appInventory.total_apps,
    appInventory.installed_apps,
    appInventory.app_count,
    Array.isArray(appInventory.apps) ? appInventory.apps.length : undefined
  )
  const highRiskApps = toCount(firstDefined(appInventory.high_risk, appInventory.high_risk_apps))
  const sideloadedApps = toCount(firstDefined(appInventory.sideloaded, appInventory.sideloaded_apps))
  const compliance = coerceObject(overview?.compliance)
  const complianceValue = compactComplianceValue(compliance)
  const complianceDanger =
    compliance.local_compliant === false ||
    compliance.overall_compliant === false ||
    String(device.mdm?.compliance_status || posture.mdm_compliance_status || '').toLowerCase().includes('non')
  const protectedApps = firstDefined(
    appGuard.protected_app_count,
    appGuard.protected_total,
    appGuard.protected_apps_count,
    Array.isArray(appGuard.protected_apps) ? appGuard.protected_apps.length : undefined,
    appInventory.protected_apps,
    appInventory.protected_app_count
  )
  const recentEvents = firstDefined(
    appGuard.recent_event_count,
    appGuard.total_recent_events,
    appGuard.events_last_24h,
    Array.isArray(appGuard.events) ? appGuard.events.length : undefined
  )

  return (
    <div className="space-y-2">
      <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
        <Smartphone className="h-4 w-4" /> Mobile Endpoint
      </h4>
      {loading && !overview ? (
        <p className="text-xs" style={{ color: 'var(--muted)' }}>Loading mobile endpoint overview...</p>
      ) : overview?.error ? (
        <p className="text-xs" style={{ color: 'var(--high)' }}>{overview.error}</p>
      ) : overview?.linked === false ? (
        <p className="text-xs" style={{ color: 'var(--muted)' }}>No linked mobile device record yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <CompactMobileFact label="State" value={formatCompactValue(device.status || posture.status || 'linked')} />
          <CompactMobileFact label="Risk" value={riskScore === undefined ? 'not reported' : String(riskScore)} />
          <CompactMobileFact label="Compliance" value={complianceValue} danger={complianceDanger} />
          <CompactMobileFact label="Last sync" value={lastSync ? formatDate(String(lastSync)) : 'not reported'} />
          <div className="grid grid-cols-3 gap-2">
            <PolicyMetric label="Apps" value={toCount(appTotal)} />
            <PolicyMetric label="High risk" value={highRiskApps} tone={highRiskApps > 0 ? 'high' : 'ok'} />
            <PolicyMetric label="Sideloaded" value={sideloadedApps} tone={sideloadedApps > 0 ? 'high' : 'ok'} />
            <PolicyMetric label="Guarded" value={toCount(protectedApps)} />
            <PolicyMetric label="Events" value={toCount(recentEvents)} />
          </div>
        </div>
      )}
    </div>
  )
}

function CompactMobileFact({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span style={{ color: 'var(--muted)' }}>{label}</span>
      <span className="font-medium truncate" style={{ color: danger ? 'var(--high)' : 'var(--fg)' }}>{value}</span>
    </div>
  )
}

function CollectorPolicySummary({
  details,
  collectors,
}: {
  details: any
  collectors: CollectorSignal[]
}) {
  const config = coerceObject(details?.config)
  const capabilities = coerceObject(details?.capabilities) as AgentCapabilities
  const profile = formatProfileName(String(config.profile || config.performance_profile || 'unassigned'))
  const policyCollectors = getConfiguredCollectors(config.collectors)
  const enabledCollectors = policyCollectors.filter(item => item.enabled)
  const disabledCollectors = policyCollectors.filter(item => !item.enabled)
  const reportedCapabilities = normalizeCapabilityList(capabilities.reported)
  const reportedCollectors = coerceObject(capabilities.reported_collectors)
  const runtime = coerceObject(capabilities.runtime)
  const activeCollectorNames = getActiveCollectorNames(collectors, reportedCollectors)
  const missingCollectors = enabledCollectors
    .filter(item => !activeCollectorNames.has(item.name))
    .map(item => item.name)
    .slice(0, 4)
  const runtimeSummary = [
    runtime.os || runtime.platform,
    runtime.arch || runtime.architecture,
    runtime.version || runtime.agent_version,
  ].filter(Boolean).join(' / ')

  return (
    <div className="space-y-2">
      <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
        <Shield className="h-4 w-4" /> Collector Policy
      </h4>
      <div className="space-y-2 text-xs">
        <div className="flex items-center justify-between gap-2">
          <span style={{ color: 'var(--muted)' }}>Profile</span>
          <span className="font-medium" style={{ color: 'var(--fg)' }}>{profile}</span>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <PolicyMetric label="Enabled" value={enabledCollectors.length} />
          <PolicyMetric label="Disabled" value={disabledCollectors.length} />
          <PolicyMetric
            label="Caps"
            value={capabilities.summary?.capability_count ?? reportedCapabilities.length}
          />
        </div>
        {runtimeSummary && (
          <p className="truncate" style={{ color: 'var(--muted)' }} title={runtimeSummary}>
            Runtime: {runtimeSummary}
          </p>
        )}
        <div
          className="rounded-lg border px-3 py-2"
          style={{
            borderColor: missingCollectors.length > 0 ? 'var(--high)' : 'var(--border)',
            backgroundColor: 'var(--surface-alt)',
          }}
        >
          <div className="flex items-center justify-between gap-2">
            <span style={{ color: 'var(--muted)' }}>Coverage drift</span>
            <span style={{ color: missingCollectors.length > 0 ? 'var(--high)' : 'var(--emerald-400)' }}>
              {missingCollectors.length > 0 ? `${missingCollectors.length} missing` : 'No obvious drift'}
            </span>
          </div>
          <p className="mt-1 text-[10px]" style={{ color: 'var(--muted)' }}>
            {missingCollectors.length > 0
              ? missingCollectors.join(', ')
              : enabledCollectors.length > 0
                ? 'Enabled collectors have matching signals or reports.'
                : 'No collector policy was reported for this agent.'}
          </p>
        </div>
      </div>
    </div>
  )
}

function PolicyMetric({ label, value, tone = 'neutral' }: { label: string; value: number; tone?: 'neutral' | 'ok' | 'high' }) {
  const valueColor = tone === 'high' ? 'var(--high)' : tone === 'ok' ? 'var(--emerald-400)' : 'var(--fg)'
  return (
    <div className="rounded border px-2 py-1.5" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <p className="text-[10px]" style={{ color: 'var(--muted)' }}>{label}</p>
      <p className="font-semibold" style={{ color: valueColor }}>{value}</p>
    </div>
  )
}

function firstDefined(...values: unknown[]): unknown {
  return values.find(value => value !== undefined && value !== null && value !== '')
}

function toCount(value: unknown): number {
  const count = Number(value)
  return Number.isFinite(count) && count >= 0 ? count : 0
}

function formatCompactValue(value: unknown): string {
  const text = String(value || '').trim()
  return text ? text.replace(/_/g, ' ') : 'not reported'
}

function compactComplianceValue(compliance: Record<string, any>): string {
  if (compliance.overall_compliant === true) return 'compliant'
  if (compliance.overall_compliant === false) return 'needs review'
  if (compliance.local_compliant === true) return 'local checks pass'
  if (compliance.local_compliant === false) return 'local checks failed'
  return 'not reported'
}

function coerceObject(value: unknown): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {}
}

function getConfiguredCollectors(rawCollectors: unknown): Array<{ name: string; enabled: boolean }> {
  const collectors = coerceObject(rawCollectors)

  return Object.entries(collectors)
    .map(([name, value]) => {
      const normalizedName = name.toLowerCase().replace(/-/g, '_')
      if (typeof value === 'boolean') return { name: normalizedName, enabled: value }
      const settings = coerceObject(value)
      return { name: normalizedName, enabled: settings.enabled !== false }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

function normalizeCapabilityList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(item => String(item)).filter(Boolean)
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, enabled]) => enabled !== false && enabled !== null)
      .map(([name]) => name)
  }
  return []
}

function getActiveCollectorNames(
  collectors: CollectorSignal[],
  reportedCollectors: Record<string, unknown>
): Set<string> {
  const names = new Set<string>()

  collectors.forEach(collector => {
    const status = String(collector.status || '').toLowerCase()
    if ((collector.events_collected || 0) > 0 || ['running', 'active', 'healthy', 'enabled'].includes(status)) {
      addCollectorName(names, collector.name)
    }
  })

  Object.entries(reportedCollectors).forEach(([name, value]) => {
    if (value === true) {
      addCollectorName(names, name)
      return
    }

    const settings = coerceObject(value)
    const status = String(settings.status || settings.state || '').toLowerCase()
    if (settings.enabled === true || ['running', 'active', 'healthy', 'enabled'].includes(status)) {
      addCollectorName(names, name)
    }
  })

  return names
}

function addCollectorName(names: Set<string>, rawName: string) {
  const name = rawName.toLowerCase().replace(/-/g, '_')
  names.add(name)

  const sourceFamily = DATA_SOURCE_KEYS.find(source => name === source || name.startsWith(`${source}_`))
  if (sourceFamily) names.add(sourceFamily)
}

function formatProfileName(profile: string): string {
  if (!profile || profile === 'unassigned') return 'Unassigned'
  return profile.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

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

function normalizeApiSourceHealth(row: any): AgentDataSourceApiHealth | null {
  if (!row || typeof row !== 'object') return null
  const sources = Array.isArray(row.sources) ? row.sources : []

  return {
    agentId: String(row.agentId || row.agent_id || ''),
    hostname: row.hostname ? String(row.hostname) : undefined,
    windowHours: Number(row.windowHours || row.window_hours || 24),
    lastTelemetryAt: row.lastTelemetryAt || row.last_telemetry_at || null,
    lastHeartbeatAt: row.lastHeartbeatAt || row.last_heartbeat_at || null,
    heartbeatState: row.heartbeatState || row.heartbeat_state || 'offline',
    healthStatus: row.healthStatus || row.health_status || null,
    driverStatus: row.driverStatus || row.driver_status || null,
    platformStatus: Array.isArray(row.platformStatus)
      ? row.platformStatus
      : Array.isArray(row.platform_status)
        ? row.platform_status
        : undefined,
    platformCapabilities: normalizePlatformCapabilities(row.platformCapabilities || row.platform_capabilities),
    dropCounters: row.dropCounters || row.drop_counters || undefined,
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
      .filter(Boolean) as DataSourceApiSource[],
    missingSources: Array.isArray(row.missingSources)
      ? row.missingSources.filter((source: string) => DATA_SOURCE_KEYS.includes(source as DataSourceKey))
      : Array.isArray(row.missing_sources)
      ? row.missing_sources.filter((source: string) => DATA_SOURCE_KEYS.includes(source as DataSourceKey))
      : undefined,
    receivingSources: Array.isArray(row.receivingSources)
      ? row.receivingSources.filter((source: string) => DATA_SOURCE_KEYS.includes(source as DataSourceKey))
      : Array.isArray(row.receiving_sources)
      ? row.receiving_sources.filter((source: string) => DATA_SOURCE_KEYS.includes(source as DataSourceKey))
      : undefined,
  }
}

function apiSourceHealthToCoverage(
  row: AgentDataSourceApiHealth,
  fallback?: AgentDataSourceHealth
): AgentDataSourceHealth {
  const lastHour = zeroSourceCounts()
  const last24h = zeroSourceCounts()
  const last7d = { ...zeroSourceCounts(), ...(fallback?.periods?.last7d || {}) }
  const lastSeen: Record<DataSourceKey, string | null> = {
    ...zeroSourceTimestamps(),
    ...(fallback?.lastSeen || {}),
  }
  const sourceStates = fallback?.sourceStates ? { ...fallback.sourceStates } : zeroSourceStates()

  row.sources.forEach((source) => {
    last24h[source.name] = source.count
    last7d[source.name] = Math.max(last7d[source.name] || 0, source.count)
    if (source.lastSeen || source.count > 0) {
      lastSeen[source.name] = source.lastSeen || row.lastTelemetryAt || lastSeen[source.name] || null
    }
    sourceStates[source.name] = {
      name: source.name,
      status: source.status,
      count: source.count,
      lastSeen: source.lastSeen || lastSeen[source.name],
      missingReason: source.missingReason,
    }
  })

  const totalLast24h = DATA_SOURCE_KEYS.reduce((sum, source) => sum + last24h[source], 0)
  const totalLast7d = DATA_SOURCE_KEYS.reduce((sum, source) => sum + last7d[source], 0)

  return {
    status: totalLast24h > 0 ? 'recent' : fallback?.status || 'none',
    generatedAt: row.lastTelemetryAt || fallback?.generatedAt || null,
    periods: {
      lastHour: fallback?.periods?.lastHour || lastHour,
      last24h,
      last7d,
    },
    lastSeen,
    sourceStates,
    totalLast24h,
    totalLast7d,
  }
}

function zeroSourceCounts(): Record<DataSourceKey, number> {
  return {
    process: 0,
    file: 0,
    network: 0,
    dns: 0,
    registry: 0,
    driver: 0,
    ai: 0,
    ndr: 0,
  }
}

function zeroSourceTimestamps(): Record<DataSourceKey, string | null> {
  return {
    process: null,
    file: null,
    network: null,
    dns: null,
    registry: null,
    driver: null,
    ai: null,
    ndr: null,
  }
}

function zeroSourceStates(): Record<DataSourceKey, NormalizedDataSourceHealth> {
  return DATA_SOURCE_KEYS.reduce((acc, source) => {
    acc[source] = {
      name: source,
      status: 'missing',
      count: 0,
      lastSeen: null,
      missingReason: 'not_reported',
    }
    return acc
  }, {} as Record<DataSourceKey, NormalizedDataSourceHealth>)
}

function normalizeDataSourceStatus(rawStatus: unknown, count: number): DataSourceStatus {
  const status = String(rawStatus || '').toLowerCase()
  if (status === 'healthy' || status === 'stale' || status === 'missing') return status
  if (status === 'recent' || status === 'ok' || status === 'online') return 'healthy'
  if (status === 'none' || status === 'unknown' || status === 'offline') return 'missing'
  return count > 0 ? 'healthy' : 'missing'
}

function getCoverageSourceHealth(
  health: AgentDataSourceHealth | undefined | null,
  source: DataSourceKey
): NormalizedDataSourceHealth {
  if (health?.sourceStates?.[source]) return health.sourceStates[source]

  const count1h = health?.periods?.lastHour?.[source] || 0
  const count24h = health?.periods?.last24h?.[source] || 0
  const count7d = health?.periods?.last7d?.[source] || 0
  const lastSeen = health?.lastSeen?.[source] || null
  const status = count24h > 0 || count1h > 0 ? 'healthy' : count7d > 0 ? 'stale' : 'missing'

  return {
    name: source,
    status,
    count: count24h,
    lastSeen,
    missingReason: status === 'missing' ? 'no_events_in_window' : status === 'stale' ? 'outside_24h_window' : null,
  }
}

function FleetDataSourceHealthPanel({
  health,
  fallbackHealth,
  loading,
  error,
  onRefresh,
}: {
  health: AgentDataSourceApiHealth[] | null
  fallbackHealth: Record<string, AgentDataSourceHealth>
  loading: boolean
  error: string | null
  onRefresh: () => void
}) {
  const sourceCounts = DATA_SOURCE_KEYS.map(source => {
    if (health && health.length > 0) {
      const receiving = health.filter(agent =>
        agent.sources.some(item => item.name === source && item.status === 'healthy')
      ).length
      const events = health.reduce((sum, agent) => (
        sum + (agent.sources.find(item => item.name === source)?.count || 0)
      ), 0)
      const stale = health.filter(agent =>
        agent.sources.some(item => item.name === source && item.status === 'stale')
      ).length
      const missing = Math.max(health.length - receiving - stale, 0)
      return { source, receiving, stale, missing, events }
    }

    const rows = Object.values(fallbackHealth || {})
    const sourceRows = rows.map(agent => getCoverageSourceHealth(agent, source))
    const receiving = sourceRows.filter(item => item.status === 'healthy').length
    const stale = sourceRows.filter(item => item.status === 'stale').length
    const missing = sourceRows.filter(item => item.status === 'missing').length
    const events = sourceRows.reduce((sum, item) => sum + item.count, 0)
    return { source, receiving, stale, missing, events }
  })

  const agentCount = health?.length || Object.keys(fallbackHealth || {}).length
  const sourceMode = health && health.length > 0 ? 'API-reported 24h health' : 'Inertia persisted-event coverage'

  if (agentCount === 0 && !loading && !error) return null

  return (
    <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div>
          <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Activity className="h-4 w-4" /> Data Sources Health
          </h3>
          <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
            {sourceMode}; window: 24 hours.
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border disabled:opacity-50 hover:bg-[var(--surface-2)]"
          style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-3 text-xs rounded-lg border px-3 py-2" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
          Source health API did not return data: {error}. Showing page-provided coverage when available.
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2">
        {sourceCounts.map(({ source, receiving, stale, missing, events }) => (
          <div key={source} className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium" style={{ color: 'var(--fg)' }}>{DATA_SOURCE_LABELS[source]}</span>
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: receiving > 0 ? 'var(--emerald-400)' : stale > 0 ? 'var(--high)' : 'var(--surface-3)' }}
              />
            </div>
            <div className="mt-2 text-lg font-semibold" style={{ color: 'var(--fg)' }}>{receiving}/{agentCount}</div>
            <div className="text-[10px]" style={{ color: 'var(--muted)' }}>
              healthy, {stale} stale, {missing} missing
            </div>
            <div className="text-[10px]" style={{ color: 'var(--muted)' }}>
              {events} events
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function DataSourceHealthPanel({ health }: { health?: AgentDataSourceHealth | null }) {
  return (
    <div className="space-y-2 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Activity className="h-4 w-4" /> Data Sources Health
        </h4>
        <span className="text-xs" style={{ color: 'var(--muted)' }}>
          24h window
        </span>
      </div>

      {!health ? (
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          No persisted telemetry coverage data is available for this agent.
        </p>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2">
          {DATA_SOURCE_KEYS.map(source => {
            const sourceHealth = getCoverageSourceHealth(health, source)
            const state = getDataSourceState(sourceHealth.status)
            const lastSeen = sourceHealth.lastSeen

            return (
              <div
                key={source}
                className="rounded-lg border p-2.5 space-y-1"
                style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium" style={{ color: 'var(--fg)' }}>
                    {DATA_SOURCE_LABELS[source]}
                  </span>
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: state.color }} title={state.title} />
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{sourceHealth.count}</span>
                  <span className="text-[10px]" style={{ color: 'var(--muted)' }}>24h</span>
                </div>
                <div className="flex items-center justify-between gap-2 text-[10px]" style={{ color: 'var(--muted)' }}>
                  <span className="capitalize" style={{ color: state.color }}>{sourceHealth.status}</span>
                  <span>{lastSeen ? formatRelativeTime(new Date(lastSeen).getTime()) : 'never'}</span>
                </div>
                {sourceHealth.missingReason && sourceHealth.status !== 'healthy' && (
                  <div className="text-[10px] truncate" style={{ color: 'var(--muted)' }} title={sourceHealth.missingReason}>
                    {formatMissingReason(sourceHealth.missingReason)}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function DataSourceHealthSummary({ health }: { health?: AgentDataSourceHealth }) {
  const observed24h = health
    ? DATA_SOURCE_KEYS.filter(source => getCoverageSourceHealth(health, source).status === 'healthy')
    : []
  const stale = health
    ? DATA_SOURCE_KEYS.filter(source => getCoverageSourceHealth(health, source).status === 'stale')
    : []

  return (
    <div className="space-y-1 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex items-center justify-between text-xs">
        <span style={{ color: 'var(--muted)' }}>Telemetry Sources</span>
        <span style={{ color: observed24h.length > 0 ? 'var(--emerald-400)' : 'var(--muted)' }}>
          {observed24h.length}/{DATA_SOURCE_KEYS.length} healthy
        </span>
      </div>
      <div className="flex items-center gap-1">
        {DATA_SOURCE_KEYS.map(source => {
          const sourceHealth = getCoverageSourceHealth(health, source)
          const state = getDataSourceState(sourceHealth.status)

          return (
            <span
              key={source}
              className="h-2 flex-1 rounded-full"
              style={{ backgroundColor: state.color }}
              title={`${DATA_SOURCE_LABELS[source]}: ${sourceHealth.status}; count ${sourceHealth.count}${sourceHealth.missingReason ? `; ${sourceHealth.missingReason}` : ''}`}
            />
          )
        })}
      </div>
      <p className="text-[10px]" style={{ color: 'var(--muted)' }}>
        {health
          ? stale.length > 0
            ? `${stale.length} stale source${stale.length === 1 ? '' : 's'}`
            : '24h health from source contracts'
          : 'Coverage data unavailable'}
      </p>
    </div>
  )
}

function AgentHealthReason({ health }: { health?: AgentHealthStatus | null }) {
  const status = String(health?.status || '').toLowerCase()
  const reasons = Array.isArray(health?.reasons) ? health.reasons : []

  if (!health || status === 'healthy' || reasons.length === 0) return null
  if (status === 'unknown' && reasons.every(reason => reason === 'offline')) return null

  return (
    <div className="rounded-lg border px-2.5 py-2 text-xs" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex items-center gap-1.5 font-medium" style={{ color: status === 'critical' ? 'var(--crit)' : 'var(--high)' }}>
        <AlertCircle className="h-3.5 w-3.5" />
        {safeCapitalize(status)}
      </div>
      <div className="mt-1" style={{ color: 'var(--muted)' }}>
        {reasons.map(formatHealthReason).join(', ')}
      </div>
    </div>
  )
}

function formatHealthReason(reason: string) {
  switch (reason) {
    case 'heartbeat_stale':
      return 'heartbeat stale'
    case 'heartbeat_critical':
      return 'heartbeat critical'
    case 'high_cpu':
      return 'high CPU'
    case 'high_memory':
      return 'high memory'
    case 'high_drop_rate':
      return 'high event drop rate'
    case 'platform_sensor_degraded':
      return 'platform sensor degraded'
    case 'driver_or_endpoint_sensor_degraded':
      return 'kernel/endpoint sensor degraded'
    case 'not_registered':
      return 'not in live registry'
    case 'offline':
      return 'offline'
    default:
      return reason.replace(/_/g, ' ')
  }
}

function DataSourceHealthInline({ health }: { health?: AgentDataSourceHealth }) {
  return (
    <div className="flex items-center gap-1 mt-1" title="Data source health in the last 24 hours">
      {DATA_SOURCE_KEYS.map(source => {
        const sourceHealth = getCoverageSourceHealth(health, source)
        const state = getDataSourceState(sourceHealth.status)

        return (
          <span
            key={source}
            className="h-1.5 w-5 rounded-full"
            style={{ backgroundColor: state.color }}
            title={`${DATA_SOURCE_LABELS[source]}: ${sourceHealth.status}; count ${sourceHealth.count}${sourceHealth.missingReason ? `; ${sourceHealth.missingReason}` : ''}`}
          />
        )
      })}
    </div>
  )
}

function PlatformCapabilityStrip({
  capabilities,
}: {
  capabilities?: PlatformCapability[]
}) {
  const items = normalizePlatformCapabilities(capabilities).slice(0, 3)
  if (items.length === 0) return null

  return (
    <div className="flex flex-wrap gap-1 mt-1" title="Platform capability maturity">
      {items.map(capability => {
        const style = capabilityMaturityStyle(capability.status || capability.maturity)
        return (
          <span
            key={capability.id}
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium"
            style={{ backgroundColor: style.bg, color: style.color }}
            title={`${capability.name}: ${capability.status || capability.maturity}; ${capability.detail || capability.observed || ''}`}
          >
            {shortCapabilityName(capability.id)}
            <span className="opacity-80">{capability.status || capability.maturity}</span>
          </span>
        )
      })}
    </div>
  )
}

function PlatformCapabilitiesPanel({
  capabilities,
  compact = false,
}: {
  capabilities?: PlatformCapability[]
  compact?: boolean
}) {
  const items = normalizePlatformCapabilities(capabilities)
  if (items.length === 0) return null

  return (
    <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex items-center justify-between gap-3 mb-2">
        <h4 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Platform Capability Maturity</h4>
        <span className="text-[10px]" style={{ color: 'var(--muted)' }}>supported / partial / lab / unavailable</span>
      </div>
      <div className={cn('grid gap-2', compact ? 'grid-cols-1 md:grid-cols-3' : 'grid-cols-1 md:grid-cols-2 xl:grid-cols-3')}>
        {items.map(capability => {
          const status = capability.status || capability.maturity
          const style = capabilityMaturityStyle(status)
          return (
            <div key={capability.id} className="rounded border px-2.5 py-2" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface)' }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>{capability.name}</span>
                <span className="text-[10px] font-medium rounded px-1.5 py-0.5" style={{ backgroundColor: style.bg, color: style.color }}>
                  {status}
                </span>
              </div>
              <p className="mt-1 text-[10px] truncate" style={{ color: 'var(--muted)' }} title={capability.detail}>
                {capability.observed === 'not_observed' ? 'not observed' : capability.observed || 'unknown signal'}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function getAgentPlatformCapabilities(
  agent: AgentEnriched,
  apiRows?: AgentDataSourceApiHealth[] | null
): PlatformCapability[] {
  const reported = normalizePlatformCapabilities(
    agent.platformCapabilities ||
      agent.platform_capabilities ||
      apiRows?.find(row => row.agentId === agent.id)?.platformCapabilities
  )
  if (shouldUseMobileFallbackCapabilities(agent.os_type, reported)) {
    return fallbackPlatformCapabilities(agent.os_type)
  }
  return reported.length > 0 ? reported : fallbackPlatformCapabilities(agent.os_type)
}

function normalizePlatformCapabilities(value: unknown): PlatformCapability[] {
  if (!Array.isArray(value)) return []
  return value
    .map(item => {
      if (!item || typeof item !== 'object') return null
      const raw = item as Record<string, unknown>
      const id = String(raw.id || '')
      const name = String(raw.name || id.replace(/_/g, ' '))
      const maturity = String(raw.maturity || raw.status || 'unavailable')
      if (!id) return null
      return {
        id,
        name,
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

function shortCapabilityName(id: string) {
  const labels: Record<string, string> = {
    endpoint_telemetry: 'telemetry',
    kernel_sensor: 'kernel',
    registry_telemetry: 'registry',
    mobile_posture: 'posture',
    app_inventory: 'apps',
    app_guard: 'app guard',
    commercial_spyware: 'spyware',
    live_response: 'response',
    network_isolation: 'isolate',
    prevention_policy: 'prevent',
  }
  return labels[id] || id.replace(/_/g, ' ')
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

function getDataSourceState(status: DataSourceStatus) {
  if (status === 'healthy') return { color: 'var(--emerald-400)', title: 'Healthy' }
  if (status === 'stale') return { color: 'var(--high)', title: 'Stale' }
  return { color: 'var(--surface-3)', title: 'Missing' }
}

function formatMissingReason(reason: string): string {
  return reason.replace(/_/g, ' ')
}

function HealthBar({ label, value }: { label: string; value: number }) {
  const pct = Math.min(100, Math.max(0, value))
  const getColor = () => {
    if (pct < 60) return 'var(--emerald-400)'
    if (pct < 85) return 'var(--high)'
    return 'var(--crit)'
  }
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-14" style={{ color: 'var(--muted)' }}>{label}</span>
      <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: 'var(--surface-alt)' }}>
        <div
          className="h-1.5 rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: getColor() }}
        />
      </div>
      <span className="w-10 text-right" style={{ color: getColor() }}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}

function DriverStatusCompact({ status }: { status?: DriverStatus | null }) {
  const title = status?.platform === 'macos' ? 'Endpoint Security' : 'Kernel driver'

  if (!status) {
    return (
      <div className="rounded-lg border px-3 py-2 text-xs" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
        <div className="flex items-center justify-between gap-2">
          <span style={{ color: 'var(--muted)' }}>{title}</span>
          <span style={{ color: 'var(--muted)' }}>not reported</span>
        </div>
      </div>
    )
  }

  const state = status.state || (status.connected ? 'loaded' : status.loaded ? 'loaded_no_telemetry' : 'not_loaded')
  const color =
    state === 'loaded' ? 'var(--emerald-400)' :
    state === 'loaded_no_telemetry' ? 'var(--high)' :
    state === 'unsupported' ? 'var(--muted)' :
    'var(--crit)'
  const label =
    state === 'loaded' ? 'loaded + telemetry' :
    state === 'loaded_no_telemetry' ? 'loaded, no telemetry' :
    state === 'unsupported' ? 'unsupported' :
    'not loaded'
  const eventsRead = typeof status.events_read === 'number' ? status.events_read : status.events_consumed

  return (
    <div className="rounded-lg border px-3 py-2 text-xs space-y-1" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex items-center justify-between gap-2">
        <span style={{ color: 'var(--muted)' }}>{title}</span>
        <span className="inline-flex items-center gap-1.5 font-medium" style={{ color }}>
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
          {label}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1" style={{ color: 'var(--muted)' }}>
        {typeof status.lab_level === 'number' && <span>level {status.lab_level}</span>}
        {status.feature_level && <span>{status.feature_level}</span>}
        {status.provider && <span>{status.provider}</span>}
        {status.entitlement_status && <span>{status.entitlement_status}</span>}
        {typeof eventsRead === 'number' && <span>{eventsRead} events read</span>}
        {typeof status.events_dropped === 'number' && status.events_dropped > 0 && (
          <span style={{ color: 'var(--high)' }}>{status.events_dropped} dropped</span>
        )}
        {typeof status.channel_drops === 'number' && status.channel_drops > 0 && (
          <span style={{ color: 'var(--high)' }}>{status.channel_drops} channel drops</span>
        )}
        {typeof status.kernel_events_dropped === 'number' && status.kernel_events_dropped > 0 && (
          <span style={{ color: 'var(--high)' }}>{status.kernel_events_dropped} kernel drops</span>
        )}
      </div>
      {status.last_error && (
        <div className="truncate" style={{ color: 'var(--crit)' }} title={status.last_error}>
          {status.last_error}
        </div>
      )}
    </div>
  )
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function StatusBadge({ status }: { status: Agent['status'] }) {
  const getStatusStyles = () => {
    switch (status) {
      case 'online':
        return { bg: 'rgba(47, 196, 113, 0.2)', color: 'var(--emerald-400)' }
      case 'degraded':
        return { bg: 'rgba(245, 165, 36, 0.2)', color: 'var(--high)' }
      case 'offline':
        return { bg: 'rgba(240, 80, 110, 0.2)', color: 'var(--crit)' }
      default:
        return { bg: 'var(--surface-alt)', color: 'var(--muted)' }
    }
  }
  const styles = getStatusStyles()

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium"
      style={{ backgroundColor: styles.bg, color: styles.color }}>
      <span className={cn(
        'h-2 w-2 rounded-full',
        status === 'online' && 'animate-pulse'
      )} style={{ backgroundColor: styles.color }} />
      {safeCapitalize(status)}
    </span>
  )
}

function OsIcon({ os }: { os: Agent['os_type'] }) {
  const osLower = (os || '').toLowerCase()

  if (osLower.includes('windows')) {
    return (
      <svg className="h-4 w-4" viewBox="0 0 24 24" fill="#60a5fa">
        <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
      </svg>
    )
  }

  if (osLower.includes('linux')) {
    return (
      <svg className="h-4 w-4" viewBox="0 0 24 24" fill="#fbbf24">
        <path d="M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 00-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.536.058.399.116.728.04.97-.249.68-.28 1.145-.106 1.484.174.334.535.47.94.601.81.2 1.91.135 2.774.6.926.466 1.866.67 2.616.47.526-.116.97-.464 1.208-.946.587-.003 1.23-.269 2.26-.334.699-.058 1.574.267 2.577.2.025.134.063.198.114.333l.003.003c.391.778 1.113 1.132 1.884 1.071.771-.06 1.592-.536 2.257-1.306.631-.765 1.683-1.084 2.378-1.503.348-.199.629-.469.649-.853.023-.4-.2-.811-.714-1.376v-.097l-.003-.003c-.17-.2-.25-.535-.338-.926-.085-.401-.182-.786-.492-1.046h-.003c-.059-.054-.123-.067-.188-.135a.357.357 0 00-.19-.064c.431-1.278.264-2.55-.173-3.694-.533-1.41-1.465-2.638-2.175-3.483-.796-1.005-1.576-1.957-1.56-3.368.026-2.152.236-6.133-3.544-6.139zm.529 3.405h.013c.213 0 .396.062.584.198.19.135.33.332.438.533.105.259.158.459.166.724 0-.02.006-.04.006-.06v.105a.086.086 0 01-.004-.021l-.004-.024a1.807 1.807 0 01-.15.706.953.953 0 01-.213.335.71.71 0 00-.088-.042c-.104-.045-.198-.064-.284-.133a1.312 1.312 0 00-.22-.066c.05-.06.146-.133.183-.198.053-.128.082-.264.088-.402v-.02a1.21 1.21 0 00-.061-.4c-.045-.134-.101-.2-.183-.333-.084-.066-.167-.132-.267-.132h-.016c-.093 0-.176.03-.262.132a.8.8 0 00-.205.334 1.18 1.18 0 00-.09.4v.019c.002.089.008.179.02.267-.193-.067-.438-.135-.607-.202a1.635 1.635 0 01-.018-.2v-.02a1.772 1.772 0 01.15-.768c.082-.22.232-.406.43-.533a.985.985 0 01.594-.2zm-2.962.059h.036c.142 0 .27.048.399.135.146.129.264.288.344.465.09.199.14.4.153.667v.004c.007.134.006.2-.002.266v.08c-.03.007-.056.018-.083.024-.152.055-.274.135-.393.2.012-.09.013-.18.003-.267v-.015c-.012-.133-.04-.2-.082-.333a.613.613 0 00-.166-.267.248.248 0 00-.183-.064h-.021c-.071.006-.13.04-.186.132a.552.552 0 00-.12.27.944.944 0 00-.023.33v.015c.012.135.037.2.08.334.046.134.098.2.166.268.01.009.02.018.034.024-.07.057-.117.07-.176.136a.304.304 0 01-.131.068 2.62 2.62 0 01-.275-.402 1.772 1.772 0 01-.155-.667 1.759 1.759 0 01.08-.668 1.43 1.43 0 01.283-.535c.128-.133.26-.2.418-.2zm1.37 1.706c.332 0 .733.065 1.216.399.293.2.523.269 1.052.468h.003c.255.136.405.266.478.399v-.131a.571.571 0 01.016.47c-.123.31-.516.643-1.063.842v.002c-.268.135-.501.333-.775.465-.276.135-.588.292-1.012.267a1.139 1.139 0 01-.448-.067 3.566 3.566 0 01-.322-.198c-.195-.135-.363-.332-.612-.465v-.005h-.005c-.4-.246-.616-.512-.686-.71-.07-.268-.005-.47.193-.6.224-.135.38-.271.483-.336.104-.074.143-.102.176-.131h.002v-.003c.169-.202.436-.47.839-.601.139-.036.294-.065.466-.065zm2.8 2.142c.358 1.417 1.196 3.475 1.735 4.473.286.534.855 1.659 1.102 3.024.156-.005.313.005.469.06v-.003c.623.226.823.668.772 1.202-.05.535-.336 1.135-.83 1.67-.499.535-.893 1.135-1.105 1.536a1.05 1.05 0 00-.1.2h-.003a1.986 1.986 0 00-.035.334c-.03.2-.044.465.09.865.135.4.42.798.925 1.135.063.045.191.089.3.135.005-.105.012-.21.018-.314.012-.223.018-.481.013-.772.015.036.03.075.042.109.026.1.052.2.071.333.026.135.031.265.032.4 0 .075-.001.135-.003.2v.008l.003.004c.063.045.235.098.392.134.19.054.35.065.55.065.154 0 .31-.009.465-.034.05-.032.093-.07.135-.103v-.003c.11.006.165-.034.212-.1l.003-.003c.074-.12.045-.26-.022-.4-.07-.135-.199-.27-.3-.4-.32-.4-.454-.802-.726-1.202-.27-.401-.665-.869-.891-1.336-.227-.47-.343-1.002-.296-1.502.047-.5.204-.936.35-1.335.22-.533.443-.965.66-1.27.217-.336.443-.602.68-.937.238-.334.497-.801.758-1.136l.026-.035c-.01-.038-.02-.075-.027-.112-.308-.066-.615-.065-.85.002-.074.02-.138.044-.198.07l-.012-.003a.825.825 0 00-.073-.135c-.15-.27-.35-.535-.642-.802-.58-.535-1.476-1.003-2.476-1.336-.5-.166-1.016-.266-1.524-.332zm-3.395 4.006v.002c.497.5 1.155.799 1.705.799a1.3 1.3 0 001.038-.394c.05-.068.095-.135.135-.202.037-.066.065-.134.09-.2l.003-.005a.708.708 0 00.053-.135c.044-.16.066-.334.054-.534a.963.963 0 00-.082-.335c-.022-.045-.05-.09-.08-.135.22-.09.377-.126.51-.134h.02a.676.676 0 01.267.064.92.92 0 01.245.17c.133.134.2.272.238.5.105.5.159 1.04.1 1.604-.06.535-.172 1.068-.36 1.535-.185.468-.409.869-.682 1.201a2.5 2.5 0 01-.873.6c-.192.09-.384.132-.574.132h-.004c-.29 0-.576-.072-.834-.2-.26-.135-.484-.335-.67-.6a3.16 3.16 0 01-.459-.938c-.123-.4-.186-.8-.203-1.202-.017-.4.007-.8.064-1.135.018-.135.04-.265.072-.4l.003-.006v-.003c.083-.27.189-.535.32-.735z"/>
      </svg>
    )
  }

  if (osLower.includes('mac') || osLower.includes('darwin')) {
    return (
      <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" style={{ color: 'var(--muted)' }}>
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
      </svg>
    )
  }

  return <HardDrive className="h-4 w-4" style={{ color: 'var(--muted)' }} />
}

// Small OS icon for filter buttons
function OsIconSmall({ os, active }: { os: string; active: boolean }) {
  const color = active ? 'currentColor' : undefined

  if (os === 'windows') {
    return (
      <svg className="h-3 w-3" viewBox="0 0 24 24" fill={color || '#60a5fa'}>
        <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
      </svg>
    )
  }

  if (os === 'linux') {
    return (
      <svg className="h-3 w-3" viewBox="0 0 24 24" fill={color || '#fbbf24'}>
        <path d="M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 00-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.536.058.399.116.728.04.97-.249.68-.28 1.145-.106 1.484.174.334.535.47.94.601.81.2 1.91.135 2.774.6.926.466 1.866.67 2.616.47.526-.116.97-.464 1.208-.946.587-.003 1.23-.269 2.26-.334.699-.058 1.574.267 2.577.2.025.134.063.198.114.333l.003.003c.391.778 1.113 1.132 1.884 1.071.771-.06 1.592-.536 2.257-1.306.631-.765 1.683-1.084 2.378-1.503.348-.199.629-.469.649-.853.023-.4-.2-.811-.714-1.376v-.097l-.003-.003c-.17-.2-.25-.535-.338-.926-.085-.401-.182-.786-.492-1.046h-.003c-.059-.054-.123-.067-.188-.135a.357.357 0 00-.19-.064c.431-1.278.264-2.55-.173-3.694-.533-1.41-1.465-2.638-2.175-3.483-.796-1.005-1.576-1.957-1.56-3.368.026-2.152.236-6.133-3.544-6.139z"/>
      </svg>
    )
  }

  if (os === 'macos') {
    return (
      <svg className="h-3 w-3" viewBox="0 0 24 24" fill={color || 'var(--muted)'}>
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
      </svg>
    )
  }

  if (os === 'android' || os === 'ios') {
    return <Smartphone className="h-3 w-3" style={{ color: color || 'var(--emerald-400)' }} />
  }

  return null
}

// OS Badge for table column
function OsBadge({ os }: { os: Agent['os_type'] }) {
  const osLower = (os || '').toLowerCase()

  let label = 'Unknown'
  let bgColor = 'var(--surface-2)'
  let textColor = 'var(--muted)'

  if (osLower.includes('windows')) {
    label = 'Windows'
    bgColor = 'rgba(96, 165, 250, 0.15)'
    textColor = '#60a5fa'
  } else if (osLower.includes('linux')) {
    label = 'Linux'
    bgColor = 'rgba(251, 191, 36, 0.15)'
    textColor = '#fbbf24'
  } else if (osLower.includes('mac') || osLower.includes('darwin')) {
    label = 'macOS'
    bgColor = 'rgba(148, 163, 184, 0.15)'
    textColor = '#94a3b8'
  } else if (osLower.includes('android')) {
    label = 'Android'
    bgColor = 'rgba(16, 185, 129, 0.15)'
    textColor = 'var(--emerald-400)'
  } else if (osLower.includes('ios')) {
    label = 'iOS'
    bgColor = 'rgba(20, 184, 166, 0.15)'
    textColor = 'var(--teal-400)'
  }

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium"
      style={{ backgroundColor: bgColor, color: textColor }}
    >
      <OsIcon os={os} />
      {label}
    </span>
  )
}

// Agent Card Component for Grid View
function AgentCard({
  agent,
  dataSourceHealth,
  onIsolate,
  onUnisolate,
  actionLoading,
}: {
  agent: AgentEnriched
  dataSourceHealth?: AgentDataSourceHealth
  onIsolate: (id: string, e: React.MouseEvent) => void
  onUnisolate: (id: string, e: React.MouseEvent) => void
  actionLoading: string | null
}) {
  const mobileAgent = isMobilePlatform(agent.os_type)
  const statusColor = agent.status === 'online'
    ? 'var(--emerald-400)'
    : agent.status === 'degraded'
    ? 'var(--high)'
    : 'var(--crit)'

  return (
    <div
      className="rounded-xl border overflow-hidden transition-all hover:shadow-lg group"
      style={{
        backgroundColor: 'var(--surface)',
        borderColor: agent.isolated ? 'var(--crit)' : 'var(--border)',
      }}
    >
      {/* Status indicator bar */}
      <div className="h-1" style={{ backgroundColor: statusColor }} />

      <div className="p-4 space-y-3">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <OsIcon os={agent.os_type} />
            <div>
              <Link
                href={`/app/agents/${agent.id}`}
                className="font-semibold text-sm hover:text-primary-400 transition-colors"
                style={{ color: 'var(--fg)' }}
              >
                {agent.hostname}
              </Link>
              <p className="text-xs font-mono" style={{ color: 'var(--muted)' }}>
                {agent.id?.substring(0, 8)}...
              </p>
            </div>
          </div>
          <StatusBadge status={agent.status} />
        </div>

        {/* Badges */}
        <div className="flex flex-wrap gap-2">
          <OsBadge os={agent.os_type} />
          {agent.isolated && (
            <span
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
              style={{ backgroundColor: 'rgba(240, 80, 110, 0.2)', color: 'var(--crit)' }}
            >
              <Lock className="h-3 w-3" />
              Isolated
            </span>
          )}
        </div>

        {/* Info */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span style={{ color: 'var(--muted)' }}>IP Address</span>
            <span className="font-mono" style={{ color: 'var(--fg)' }}>
              {agent.ip_address || '--'}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span style={{ color: 'var(--muted)' }}>Version</span>
            <span className="font-mono" style={{ color: 'var(--fg)' }}>
              {agent.agent_version || '--'}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span style={{ color: 'var(--muted)' }}>Last Seen</span>
            <span style={{ color: 'var(--fg)' }}>
              {formatRelativeTime(new Date(agent.last_seen).getTime())}
            </span>
          </div>
        </div>

        {/* Health Bars (if available) */}
        {agent.health && (
          <div className="space-y-1 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
            <MiniHealthBar label="CPU" value={agent.health.cpu_usage} />
            <MiniHealthBar label="RAM" value={agent.health.memory_usage} />
          </div>
        )}

        <AgentHealthReason health={agent.health_status} />

        <DataSourceHealthSummary health={dataSourceHealth} />
        <PlatformCapabilityStrip capabilities={getAgentPlatformCapabilities(agent)} />

        {/* Actions */}
        <div className="flex items-center justify-between pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <Link
            href={`/app/agents/${agent.id}`}
            className="text-xs font-medium hover:underline"
            style={{ color: 'var(--primary)' }}
          >
            View Details
          </Link>
          <div className="flex items-center gap-1">
            <Link
              href={`/app/agents/${agent.id}`}
              className="p-1.5 rounded-lg transition-colors hover:bg-[var(--surface-2)]"
              style={{ color: 'var(--muted)' }}
              title="View"
            >
              <Eye className="h-4 w-4" />
            </Link>
            {agent.isolated ? (
              <button
                onClick={(e) => onUnisolate(agent.id, e)}
                disabled={actionLoading === agent.id || mobileAgent}
                className="p-1.5 rounded-lg transition-colors disabled:opacity-50 hover:bg-[var(--surface-2)]"
                style={{ color: 'var(--emerald-400)' }}
                title={mobileAgent ? 'Host isolation unavailable for mobile endpoint' : 'Remove Isolation'}
              >
                <ShieldOff className="h-4 w-4" />
              </button>
            ) : (
              <button
                onClick={(e) => onIsolate(agent.id, e)}
                disabled={actionLoading === agent.id || agent.status === 'offline' || mobileAgent}
                className="p-1.5 rounded-lg transition-colors disabled:opacity-50 hover:bg-[var(--surface-2)]"
                style={{ color: 'var(--high)' }}
                title={mobileAgent ? 'Host network isolation is not available for mobile endpoints' : 'Network Isolate'}
              >
                <Shield className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// Mini health bar for agent cards
function MiniHealthBar({ label, value }: { label: string; value: number }) {
  const pct = Math.min(100, Math.max(0, value))
  const getColor = () => {
    if (pct < 60) return 'var(--emerald-400)'
    if (pct < 85) return 'var(--high)'
    return 'var(--crit)'
  }

  return (
    <div className="flex items-center gap-2 text-[10px]">
      <span className="w-8" style={{ color: 'var(--muted)' }}>{label}</span>
      <div className="flex-1 h-1 rounded-full" style={{ backgroundColor: 'var(--surface-alt)' }}>
        <div
          className="h-1 rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: getColor() }}
        />
      </div>
      <span className="w-8 text-right" style={{ color: getColor() }}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}
