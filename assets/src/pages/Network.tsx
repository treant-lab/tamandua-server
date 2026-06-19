import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Network as NetworkIcon, Globe, ArrowUpRight, ArrowDownLeft, Filter, RefreshCw,
  Cpu, Share2, Search, ExternalLink, Copy, ChevronDown, ChevronRight,
  Play, Pause, Shield, AlertTriangle, Clock, Wifi, WifiOff, MoreHorizontal,
  TrendingUp, TrendingDown, Activity, MonitorSmartphone
} from 'lucide-react'
import { cn, formatDate, safeRandomUUID } from '@/lib/utils'
import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useEventStream } from '@/hooks/useSocket'
import { ExportDropdown } from '@/components/ExportDropdown'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { Select, SelectItem } from '@/components/ui/baseui'
import type { WebSocketConnectionState } from '@/types'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Direction = 'inbound' | 'outbound' | 'local'
type ConnStatus = 'established' | 'closed' | 'blocked' | 'suspicious'

interface Connection {
  id: string
  src: string
  srcPort: number
  dst: string
  dstPort: number
  protocol: string
  bytes: number
  bytesIn: number
  bytesOut: number
  agent: string
  agentId: string
  timestamp: string
  pid: number
  processName: string
  direction: Direction
  status: ConnStatus
  isNew?: boolean
}

interface NetworkStats {
  totalConnections: number
  activeConnections: number
  blockedConnections: number
  suspiciousConnections: number
  uniqueDestinations: number
  totalBytes: number
  trend: number // positive = more than previous period
}

// Props from Inertia (different field names)
interface InertiaConnection {
  id: string
  agentId: string
  timestamp: string
  sourceIp: string
  sourcePort: number
  destIp: string
  destPort: number
  protocol: string
  processName: string
  processPid: number
  direction: string
  status: string
  bytesIn?: number
  bytesOut?: number
  bytes?: number
}

interface NetworkPageProps {
  connections?: InertiaConnection[]
  stats?: Partial<NetworkStats>
  agents?: Array<{ id: string; hostname: string }>
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PRIVATE_IP_PREFIXES = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
  '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
  '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '0.0.0.0', '::1', '::']

function isPrivateIp(ip: string): boolean {
  if (!ip || ip === 'N/A') return true
  return PRIVATE_IP_PREFIXES.some(prefix => ip.startsWith(prefix))
}

function parseDirection(raw: string | undefined | null): Direction {
  const val = (raw || '').toLowerCase()
  if (val === 'inbound' || val === 'in') return 'inbound'
  if (val === 'outbound' || val === 'out') return 'outbound'
  return 'local'
}

function parseStatus(raw: string | undefined | null): ConnStatus {
  const val = (raw || '').toLowerCase()
  if (val === 'blocked') return 'blocked'
  if (val === 'suspicious') return 'suspicious'
  if (val === 'closed' || val === 'close_wait' || val === 'time_wait') return 'closed'
  return 'established'
}

function formatBytes(bytes: number | undefined | null): string {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n <= 0) return '\u2014'
  if (n < 1024) return `${Math.round(n)} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function formatBytesShort(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  if (bytes < 1024) return `${Math.round(bytes)} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function formatEndpoint(ip: string | undefined | null, port: number | undefined | null): string {
  const ipStr = String(ip || '').trim()
  const portNum = Number(port) || 0
  const displayIp = ipStr && ipStr !== 'N/A' && ipStr !== 'null' && ipStr !== 'undefined' ? ipStr : ''
  const displayPort = portNum > 0 ? portNum : 0
  if (!displayIp && displayPort === 0) return 'N/A'
  if (!displayIp) return `*:${displayPort}`
  if (displayPort === 0) return displayIp
  return `${displayIp}:${displayPort}`
}

function relativeTime(timestamp: string | undefined | null): string {
  if (!timestamp) return 'N/A'
  const date = new Date(timestamp)
  if (isNaN(date.getTime())) return 'N/A'
  const now = Date.now()
  const diff = now - date.getTime()
  if (diff < 0) return 'just now'
  if (diff < 5000) return 'just now'
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

function fullTimestamp(timestamp: string | undefined | null): string {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  if (isNaN(date.getTime())) return ''
  return date.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  })
}

function getProcessDisplay(name: string | undefined | null, pid: number | undefined | null): { label: string; pid: string; isSystem: boolean } {
  const rawName = String(name || '').trim()
  const rawPid = Number(pid)
  const pidNum = Number.isFinite(rawPid) ? rawPid : -1

  // Handle PID 0, "Idle", "System Idle Process", empty names
  const isSystemIdle = pidNum === 0 || rawName.toLowerCase() === 'idle' || rawName.toLowerCase() === 'system idle process' || rawName === ''
  const isSystem = pidNum === 4 || rawName.toLowerCase() === 'system'

  if (isSystemIdle) {
    return { label: 'System Idle', pid: 'PID 0', isSystem: true }
  }
  if (isSystem) {
    return { label: 'System', pid: `PID ${pidNum}`, isSystem: true }
  }

  return {
    label: rawName || 'Unknown',
    pid: pidNum > 0 ? `PID ${pidNum}` : '',
    isSystem: false
  }
}

function transformConnection(conn: InertiaConnection): Connection {
  const bytesIn = Number(conn.bytesIn) || 0
  const bytesOut = Number(conn.bytesOut) || 0
  const totalBytes = bytesIn + bytesOut || Number(conn.bytes) || 0

  return {
    id: conn.id,
    src: conn.sourceIp || 'N/A',
    srcPort: conn.sourcePort || 0,
    dst: conn.destIp || 'N/A',
    dstPort: conn.destPort || 0,
    protocol: (conn.protocol || 'TCP').toUpperCase(),
    bytes: totalBytes,
    bytesIn,
    bytesOut,
    agent: conn.processName || 'Unknown',
    agentId: conn.agentId || '',
    timestamp: conn.timestamp || '',
    pid: Number(conn.processPid) || 0,
    processName: conn.processName || 'Unknown',
    direction: parseDirection(conn.direction),
    status: parseStatus(conn.status),
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {
    // Fallback
    const el = document.createElement('textarea')
    el.value = text
    document.body.appendChild(el)
    el.select()
    document.execCommand('copy')
    document.body.removeChild(el)
  })
}

const ITEMS_PER_PAGE = 50

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function Network({ connections: initialConnections, stats: initialStats, agents }: NetworkPageProps) {
  const transformedInitial = useMemo(() =>
    (initialConnections || []).map(transformConnection).filter(c => c.src !== 'N/A' || c.dst !== 'N/A'),
    [initialConnections]
  )

  const [connections, setConnections] = useState<Connection[]>(transformedInitial)
  const [loading, setLoading] = useState(false)
  const [protocolFilter, setProtocolFilter] = useState<string>('all')
  const [directionFilter, setDirectionFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [agentFilter, setAgentFilter] = useState<string>('all')
  const [ipFilter, setIpFilter] = useState<string>('')
  const [processFilter, setProcessFilter] = useState<string>('')
  const [showFilters, setShowFilters] = useState(false)
  const [visibleCount, setVisibleCount] = useState(ITEMS_PER_PAGE)
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [copiedIp, setCopiedIp] = useState<string | null>(null)
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const ipDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const processDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [debouncedIp, setDebouncedIp] = useState('')
  const [debouncedProcess, setDebouncedProcess] = useState('')

  // WebSocket real-time events
  const { connectionState, events: streamEvents } = useEventStream()

  // Process incoming WebSocket events into connections
  useEffect(() => {
    if (streamEvents.length === 0) return
    const networkEvents = streamEvents.filter(e =>
      e.eventType === 'network_connect' || e.eventType === 'network_listen' || e.eventType === 'network'
    )
    if (networkEvents.length === 0) return

    const newConnections: Connection[] = networkEvents.map(event => {
      const p = event.payload || {}
      const localIp = String(p.local_ip || p.source_ip || p.src_ip || '')
      const remoteIp = String(p.remote_ip || p.destination_ip || p.dst_ip || '')
      const localPort = Number(p.local_port || p.source_port || p.src_port) || 0
      const remotePort = Number(p.remote_port || p.destination_port || p.dst_port) || 0
      const bytesSent = Number(p.bytes_sent) || 0
      const bytesRecv = Number(p.bytes_received) || 0
      const totalBytes = bytesSent + bytesRecv || Number(p.bytes) || 0

      return {
        id: event.id || safeRandomUUID(),
        src: localIp || 'N/A',
        srcPort: localPort,
        dst: remoteIp || 'N/A',
        dstPort: remotePort,
        protocol: String(p.protocol || 'TCP').toUpperCase(),
        bytes: isNaN(totalBytes) ? 0 : totalBytes,
        bytesIn: bytesRecv,
        bytesOut: bytesSent,
        agent: String(p.process_name || 'Unknown'),
        agentId: event.agentId || '',
        timestamp: event.timestamp ? new Date(event.timestamp).toISOString() : new Date().toISOString(),
        pid: Number(p.process_pid || p.pid) || 0,
        processName: String(p.process_name || 'Unknown'),
        direction: parseDirection(String(p.direction || '')),
        status: parseStatus(String(p.status || 'established')),
        isNew: true,
      }
    }).filter(c => c.src !== 'N/A' || c.dst !== 'N/A')

    if (newConnections.length > 0) {
      setConnections(prev => [...newConnections, ...prev])
      // Clear isNew flag after animation
      setTimeout(() => {
        setConnections(prev => prev.map(c => c.isNew ? { ...c, isNew: false } : c))
      }, 2000)
    }
  }, [streamEvents])

  // Debounce IP filter
  useEffect(() => {
    if (ipDebounceRef.current) clearTimeout(ipDebounceRef.current)
    ipDebounceRef.current = setTimeout(() => setDebouncedIp(ipFilter), 300)
    return () => { if (ipDebounceRef.current) clearTimeout(ipDebounceRef.current) }
  }, [ipFilter])

  // Debounce process filter
  useEffect(() => {
    if (processDebounceRef.current) clearTimeout(processDebounceRef.current)
    processDebounceRef.current = setTimeout(() => setDebouncedProcess(processFilter), 300)
    return () => { if (processDebounceRef.current) clearTimeout(processDebounceRef.current) }
  }, [processFilter])

  // Fetch network data from API
  const fetchNetworkData = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (protocolFilter !== 'all') params.append('protocol', protocolFilter)
      if (agentFilter !== 'all') params.append('agent_id', agentFilter)
      if (debouncedIp) params.append('ip', debouncedIp)

      const response = await fetch(`/api/v1/events?event_type=network_connect,network_listen&${params.toString()}`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      })
      if (response.ok) {
        const data = await response.json()
        const networkConnections: Connection[] = (data.data || [])
          .map((event: any) => {
            const payload = event.payload || {}
            const localIp = payload.local_ip || payload.source_ip || payload.src_ip || ''
            const remoteIp = payload.remote_ip || payload.destination_ip || payload.dst_ip || ''
            const localPort = payload.local_port || payload.source_port || payload.src_port || 0
            const remotePort = payload.remote_port || payload.destination_port || payload.dst_port || 0
            const bytesSent = Number(payload.bytes_sent) || 0
            const bytesReceived = Number(payload.bytes_received) || 0
            const bytesTotal = bytesSent + bytesReceived || Number(payload.bytes) || 0

            return {
              id: event.id || safeRandomUUID(),
              src: localIp || 'N/A',
              srcPort: Number(localPort) || 0,
              dst: remoteIp || 'N/A',
              dstPort: Number(remotePort) || 0,
              protocol: (payload.protocol || 'TCP').toString().toUpperCase(),
              bytes: isNaN(bytesTotal) ? 0 : bytesTotal,
              bytesIn: bytesReceived,
              bytesOut: bytesSent,
              agent: event.agent_hostname || payload.process_name || 'Unknown',
              agentId: event.agent_id || '',
              timestamp: event.timestamp || new Date().toISOString(),
              pid: Number(payload.process_pid || payload.pid) || 0,
              processName: payload.process_name || 'Unknown',
              direction: parseDirection(payload.direction),
              status: parseStatus(payload.status || payload.state),
            }
          })
          .filter((conn: Connection) => conn.src !== 'N/A' || conn.dst !== 'N/A')

        setConnections(networkConnections)
      }
    } catch (error) {
      logger.error('Failed to fetch network data:', error)
    } finally {
      setLoading(false)
    }
  }, [protocolFilter, agentFilter, debouncedIp])

  // Initial load
  useEffect(() => {
    if (!transformedInitial.length) {
      fetchNetworkData()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(fetchNetworkData, 10000)
    } else {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current)
    }
    return () => { if (autoRefreshRef.current) clearInterval(autoRefreshRef.current) }
  }, [autoRefresh, fetchNetworkData])

  // Computed: filtered, deduplicated, sorted
  const filteredConnections = useMemo(() => {
    const filtered = connections.filter(conn => {
      if (protocolFilter !== 'all' && conn.protocol !== protocolFilter) return false
      if (directionFilter !== 'all' && conn.direction !== directionFilter) return false
      if (statusFilter !== 'all') {
        if (statusFilter === 'active' && conn.status !== 'established') return false
        if (statusFilter === 'blocked' && conn.status !== 'blocked') return false
        if (statusFilter === 'suspicious' && conn.status !== 'suspicious') return false
      }
      if (agentFilter !== 'all' && conn.agentId !== agentFilter) return false
      if (debouncedIp && !conn.src.includes(debouncedIp) && !conn.dst.includes(debouncedIp)) return false
      if (debouncedProcess) {
        const pLower = debouncedProcess.toLowerCase()
        const nameMatch = (conn.processName || '').toLowerCase().includes(pLower)
        const pidMatch = String(conn.pid).includes(debouncedProcess)
        if (!nameMatch && !pidMatch) return false
      }
      return true
    })

    // Deduplicate by src:port -> dst:port + protocol + process (keep newest)
    const deduped = new Map<string, Connection>()
    for (const conn of filtered) {
      const key = `${conn.src}:${conn.srcPort}-${conn.dst}:${conn.dstPort}-${conn.protocol}-${conn.processName}`
      const existing = deduped.get(key)
      if (!existing || new Date(conn.timestamp).getTime() > new Date(existing.timestamp).getTime()) {
        deduped.set(key, conn)
      }
    }

    return Array.from(deduped.values())
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }, [connections, protocolFilter, directionFilter, statusFilter, agentFilter, debouncedIp, debouncedProcess])

  // Stats computed from current data
  const stats = useMemo<NetworkStats>(() => {
    const s = initialStats || {}
    const established = connections.filter(c => c.status === 'established').length
    const blocked = connections.filter(c => c.status === 'blocked').length
    const suspicious = connections.filter(c => c.status === 'suspicious').length
    const uniqueDests = new Set(connections.map(c => c.dst).filter(d => d !== 'N/A')).size
    const totalBytes = connections.reduce((sum, c) => sum + (Number(c.bytes) || 0), 0)

    return {
      totalConnections: s.totalConnections ?? connections.length,
      activeConnections: s.activeConnections ?? established,
      blockedConnections: s.blockedConnections ?? blocked,
      suspiciousConnections: suspicious,
      uniqueDestinations: s.uniqueDestinations ?? uniqueDests,
      totalBytes,
      trend: 0,
    }
  }, [connections, initialStats])

  const visibleConnections = filteredConnections.slice(0, visibleCount)
  const hasMore = visibleCount < filteredConnections.length

  const handleCopyIp = (ip: string) => {
    copyToClipboard(ip)
    setCopiedIp(ip)
    setTimeout(() => setCopiedIp(null), 1500)
  }

  const toggleRow = (id: string) => {
    setExpandedRows(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const getExportData = useCallback(() => {
    return filteredConnections.map(c => ({
      timestamp: c.timestamp,
      direction: c.direction,
      source_ip: c.src,
      source_port: c.srcPort,
      destination_ip: c.dst,
      destination_port: c.dstPort,
      protocol: c.protocol,
      process: c.processName,
      pid: c.pid,
      bytes: c.bytes,
      bytes_in: c.bytesIn,
      bytes_out: c.bytesOut,
      status: c.status,
      agent_id: c.agentId,
    }))
  }, [filteredConnections])

  const activeFilterCount = [
    protocolFilter !== 'all',
    directionFilter !== 'all',
    statusFilter !== 'all',
    agentFilter !== 'all',
    !!debouncedIp,
    !!debouncedProcess,
  ].filter(Boolean).length

  return (
    <MainLayout title="Network">
      <Head title="Network Monitor - Tamandua EDR" />

      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="p-2 rounded-lg"
              style={{ backgroundColor: 'var(--emerald-glow)' }}
            >
              <NetworkIcon className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <h1 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>Network Monitor</h1>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Real-time network connection analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <ConnectionStatus state={connectionState as WebSocketConnectionState} size="sm" />
            <ExportDropdown getData={getExportData} filenameBase="network-connections" />
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard
            icon={NetworkIcon}
            label="Total Connections"
            value={(stats.totalConnections ?? 0).toLocaleString()}
            trend={stats.trend}
            color="emerald"
          />
          <StatCard
            icon={Activity}
            label="Established"
            value={(stats.activeConnections ?? 0).toLocaleString()}
            color="green"
          />
          <StatCard
            icon={Shield}
            label="Blocked"
            value={(stats.blockedConnections ?? 0).toLocaleString()}
            color="crit"
            alert={(stats.blockedConnections ?? 0) > 0}
          />
          <StatCard
            icon={AlertTriangle}
            label="Suspicious"
            value={(stats.suspiciousConnections ?? 0).toLocaleString()}
            color="high"
            alert={(stats.suspiciousConnections ?? 0) > 0}
          />
          <StatCard
            icon={Globe}
            label="Unique Destinations"
            value={(stats.uniqueDestinations ?? 0).toLocaleString()}
            color="med"
          />
          <StatCard
            icon={ArrowUpRight}
            label="Bytes Transferred"
            value={formatBytesShort(stats.totalBytes)}
            color="emerald"
          />
        </div>

        {/* Toolbar */}
        <div
          className="card-sentinel rounded-xl p-3"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 flex-1 min-w-0">
              {/* Quick search */}
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
                <input
                  type="text"
                  placeholder="Search IP address..."
                  value={ipFilter}
                  onChange={(e) => setIpFilter(e.target.value)}
                  className="w-full rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-1"
                  style={{
                    backgroundColor: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg-2)',
                  }}
                />
              </div>

              {/* Process search */}
              <div className="relative flex-1 max-w-xs">
                <Cpu className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
                <input
                  type="text"
                  placeholder="Search process..."
                  value={processFilter}
                  onChange={(e) => setProcessFilter(e.target.value)}
                  className="w-full rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-1"
                  style={{
                    backgroundColor: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg-2)',
                  }}
                />
              </div>

              {/* Toggle advanced filters */}
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors'
                )}
                style={{
                  backgroundColor: showFilters ? 'var(--emerald-glow)' : 'var(--surface-2)',
                  border: `1px solid ${showFilters ? 'var(--emerald-600)' : 'var(--border)'}`,
                  color: showFilters ? 'var(--emerald-400)' : 'var(--muted)',
                }}
              >
                <Filter className="h-4 w-4" />
                Filters
                {activeFilterCount > 0 && (
                  <span
                    className="ml-1 px-1.5 py-0.5 rounded-full text-xs font-bold"
                    style={{ backgroundColor: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
                  >
                    {activeFilterCount}
                  </span>
                )}
              </button>
            </div>

            <div className="flex items-center gap-2">
              {/* Auto-refresh toggle */}
              <button
                onClick={() => setAutoRefresh(!autoRefresh)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
                style={{
                  backgroundColor: autoRefresh ? 'var(--emerald-glow)' : 'var(--surface-2)',
                  border: `1px solid ${autoRefresh ? 'var(--emerald-600)' : 'var(--border)'}`,
                  color: autoRefresh ? 'var(--emerald-400)' : 'var(--muted)',
                }}
                title={autoRefresh ? 'Auto-refresh enabled (10s)' : 'Enable auto-refresh'}
              >
                {autoRefresh ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                <span className="hidden sm:inline">{autoRefresh ? 'Auto' : 'Auto'}</span>
              </button>

              {/* Manual refresh */}
              <button
                onClick={fetchNetworkData}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
                style={{
                  backgroundColor: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  color: 'var(--muted)',
                }}
              >
                <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
                <span className="hidden sm:inline">Refresh</span>
              </button>
            </div>
          </div>

          {/* Advanced filters row */}
          {showFilters && (
            <div
              className="flex flex-wrap items-center gap-3 mt-3 pt-3"
              style={{ borderTop: '1px solid var(--hairline)' }}
            >
              <FilterSelect
                label="Protocol"
                value={protocolFilter}
                onChange={setProtocolFilter}
                options={[
                  { value: 'all', label: 'All Protocols' },
                  { value: 'TCP', label: 'TCP' },
                  { value: 'UDP', label: 'UDP' },
                  { value: 'ICMP', label: 'ICMP' },
                ]}
              />
              <FilterSelect
                label="Direction"
                value={directionFilter}
                onChange={setDirectionFilter}
                options={[
                  { value: 'all', label: 'All Directions' },
                  { value: 'inbound', label: 'Inbound' },
                  { value: 'outbound', label: 'Outbound' },
                  { value: 'local', label: 'Local' },
                ]}
              />
              <FilterSelect
                label="Status"
                value={statusFilter}
                onChange={setStatusFilter}
                options={[
                  { value: 'all', label: 'All Statuses' },
                  { value: 'active', label: 'Active' },
                  { value: 'blocked', label: 'Blocked' },
                  { value: 'suspicious', label: 'Suspicious' },
                ]}
              />
              <FilterSelect
                label="Agent"
                value={agentFilter}
                onChange={setAgentFilter}
                options={[
                  { value: 'all', label: 'All Agents' },
                  ...(agents || []).map(a => ({ value: a.id, label: a.hostname })),
                ]}
              />
              {activeFilterCount > 0 && (
                <button
                  onClick={() => {
                    setProtocolFilter('all')
                    setDirectionFilter('all')
                    setStatusFilter('all')
                    setAgentFilter('all')
                    setIpFilter('')
                    setProcessFilter('')
                  }}
                  className="text-xs hover:underline transition-colors"
                  style={{ color: 'var(--subtle)' }}
                >
                  Clear all filters
                </button>
              )}
            </div>
          )}
        </div>

        {/* Connections Table */}
        <div
          className="card-sentinel rounded-xl overflow-hidden"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
        >
          {/* Table Header */}
          <div
            className="px-4 py-3 flex items-center justify-between"
            style={{ borderBottom: '1px solid var(--hairline)' }}
          >
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold" style={{ color: 'var(--fg-2)' }}>Connections</h2>
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                Showing {Math.min(visibleCount, filteredConnections.length).toLocaleString()} of {filteredConnections.length.toLocaleString()}
              </span>
            </div>
            {connectionState === 'connected' && (
              <div className="flex items-center gap-1.5 text-xs">
                <span className="relative flex h-2 w-2">
                  <span
                    className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
                    style={{ backgroundColor: 'var(--emerald-400)' }}
                  />
                  <span
                    className="relative inline-flex rounded-full h-2 w-2"
                    style={{ backgroundColor: 'var(--emerald-500)' }}
                  />
                </span>
                <span className="font-medium" style={{ color: 'var(--emerald-400)' }}>Live</span>
              </div>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <th className="w-8" />
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Time</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Dir</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Source</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Destination</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Proto</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Process</th>
                  <th className="text-right px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Bytes</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Status</th>
                  <th className="text-right px-3 py-2.5 text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleConnections.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="py-20 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <div
                          className="p-4 rounded-full"
                          style={{ backgroundColor: 'var(--surface-2)' }}
                        >
                          <NetworkIcon className="h-8 w-8" style={{ color: 'var(--subtle)' }} />
                        </div>
                        <p className="text-sm" style={{ color: 'var(--muted)' }}>
                          {loading ? 'Fetching network connections...' : 'No network connections found'}
                        </p>
                        {!loading && activeFilterCount > 0 && (
                          <button
                            onClick={() => {
                              setProtocolFilter('all')
                              setDirectionFilter('all')
                              setStatusFilter('all')
                              setAgentFilter('all')
                              setIpFilter('')
                              setProcessFilter('')
                            }}
                            className="text-xs transition-colors"
                            style={{ color: 'var(--emerald-400)' }}
                          >
                            Clear filters
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ) : (
                  visibleConnections.map((conn) => (
                    <ConnectionRow
                      key={conn.id}
                      conn={conn}
                      expanded={expandedRows.has(conn.id)}
                      onToggle={() => toggleRow(conn.id)}
                      onCopyIp={handleCopyIp}
                      copiedIp={copiedIp}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination / Load More */}
          {hasMore && (
            <div
              className="px-4 py-3 flex items-center justify-center"
              style={{ borderTop: '1px solid var(--hairline)' }}
            >
              <button
                onClick={() => setVisibleCount(prev => prev + ITEMS_PER_PAGE)}
                className="px-4 py-2 rounded-lg text-sm transition-colors"
                style={{
                  backgroundColor: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  color: 'var(--fg-2)',
                }}
              >
                Load more ({Math.min(ITEMS_PER_PAGE, filteredConnections.length - visibleCount).toLocaleString()} remaining)
              </button>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ---------------------------------------------------------------------------
// Sub-Components
// ---------------------------------------------------------------------------

function ConnectionRow({ conn, expanded, onToggle, onCopyIp, copiedIp }: {
  conn: Connection
  expanded: boolean
  onToggle: () => void
  onCopyIp: (ip: string) => void
  copiedIp: string | null
}) {
  const proc = getProcessDisplay(conn.processName, conn.pid)
  const srcEndpoint = formatEndpoint(conn.src, conn.srcPort)
  const dstEndpoint = formatEndpoint(conn.dst, conn.dstPort)

  const rowStyle: React.CSSProperties = {
    borderBottom: '1px solid var(--hairline)',
  }

  if (conn.isNew) {
    rowStyle.backgroundColor = 'var(--emerald-glow)'
  } else if (conn.status === 'blocked') {
    rowStyle.backgroundColor = 'var(--crit-bg)'
  } else if (conn.status === 'suspicious') {
    rowStyle.backgroundColor = 'var(--high-bg)'
  }

  return (
    <>
      <tr
        className={cn(
          'group transition-colors cursor-pointer hover:brightness-110',
          conn.isNew && 'animate-pulse'
        )}
        style={rowStyle}
        onClick={onToggle}
      >
        {/* Expand chevron */}
        <td className="pl-3 pr-1 py-2.5">
          <button style={{ color: 'var(--subtle)' }} className="group-hover:brightness-125 transition-colors">
            {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        </td>

        {/* Timestamp */}
        <td className="px-3 py-2.5">
          <span
            className="text-xs font-mono cursor-default"
            style={{ color: 'var(--muted)' }}
            title={fullTimestamp(conn.timestamp)}
          >
            {relativeTime(conn.timestamp)}
          </span>
        </td>

        {/* Direction */}
        <td className="px-3 py-2.5">
          <DirectionBadge direction={conn.direction} />
        </td>

        {/* Source */}
        <td className="px-3 py-2.5">
          <EndpointCell
            endpoint={srcEndpoint}
            ip={conn.src}
            isExternal={!isPrivateIp(conn.src)}
            onCopy={onCopyIp}
            isCopied={copiedIp === conn.src}
          />
        </td>

        {/* Destination */}
        <td className="px-3 py-2.5">
          <EndpointCell
            endpoint={dstEndpoint}
            ip={conn.dst}
            isExternal={!isPrivateIp(conn.dst)}
            onCopy={onCopyIp}
            isCopied={copiedIp === conn.dst}
          />
        </td>

        {/* Protocol */}
        <td className="px-3 py-2.5">
          <ProtocolBadge protocol={conn.protocol} />
        </td>

        {/* Process */}
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <div
              className="flex-shrink-0 p-1 rounded"
              style={{
                backgroundColor: proc.isSystem ? 'var(--surface-3)' : 'var(--med-bg)',
              }}
            >
              {proc.isSystem
                ? <MonitorSmartphone className="h-3.5 w-3.5" style={{ color: 'var(--muted)' }} />
                : <Cpu className="h-3.5 w-3.5" style={{ color: 'var(--med)' }} />
              }
            </div>
            <div className="min-w-0">
              <p className="text-sm truncate leading-tight" style={{ color: 'var(--fg-2)' }}>{proc.label}</p>
              {proc.pid && (
                <p className="text-[10px] leading-tight" style={{ color: 'var(--subtle)' }}>{proc.pid}</p>
              )}
            </div>
          </div>
        </td>

        {/* Bytes */}
        <td className="px-3 py-2.5 text-right">
          <span className="text-xs font-mono" style={{ color: 'var(--muted)' }}>
            {formatBytes(conn.bytes)}
          </span>
        </td>

        {/* Status */}
        <td className="px-3 py-2.5">
          <StatusBadge status={conn.status} />
        </td>

        {/* Actions */}
        <td className="px-3 py-2.5">
          <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={(e) => e.stopPropagation()}>
            {conn.dst && conn.dst !== 'N/A' && (
              <ActionButton
                icon={Search}
                title="Hunt this IP"
                color="high"
                onClick={() => router.visit(`/app/hunt?q=remote_ip:${conn.dst}`)}
              />
            )}
            {conn.pid > 0 && conn.agentId && (
              <ActionButton
                icon={Cpu}
                title="View Process Tree"
                color="med"
                onClick={() => router.visit(`/app/process-tree?agent_id=${conn.agentId}&pid=${conn.pid}`)}
              />
            )}
            {conn.pid > 0 && conn.agentId && (
              <ActionButton
                icon={Share2}
                title="Investigate"
                color="emerald"
                onClick={() => router.visit(`/app/investigation/${conn.pid}?type=process&agent_id=${conn.agentId}`)}
              />
            )}
          </div>
        </td>
      </tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr style={{ backgroundColor: 'var(--surface-2)' }}>
          <td colSpan={10} className="px-6 py-4">
            <ExpandedDetail conn={conn} />
          </td>
        </tr>
      )}
    </>
  )
}

function ExpandedDetail({ conn }: { conn: Connection }) {
  const proc = getProcessDisplay(conn.processName, conn.pid)

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
      <DetailItem label="Full Timestamp" value={fullTimestamp(conn.timestamp) || 'N/A'} mono />
      <DetailItem label="Source" value={formatEndpoint(conn.src, conn.srcPort)} mono />
      <DetailItem label="Destination" value={formatEndpoint(conn.dst, conn.dstPort)} mono />
      <DetailItem label="Protocol" value={conn.protocol} />
      <DetailItem label="Process" value={`${proc.label} (${proc.pid || 'N/A'})`} />
      <DetailItem label="Direction" value={conn.direction} />
      <DetailItem label="Status" value={conn.status} />
      <DetailItem label="Total Bytes" value={formatBytes(conn.bytes)} mono />
      <DetailItem label="Bytes In" value={formatBytes(conn.bytesIn)} mono />
      <DetailItem label="Bytes Out" value={formatBytes(conn.bytesOut)} mono />
      <DetailItem label="Agent ID" value={conn.agentId || 'N/A'} mono />
      <DetailItem
        label="Source Type"
        value={isPrivateIp(conn.src) ? 'Private / Internal' : 'External / Public'}
      />
      <DetailItem
        label="Destination Type"
        value={isPrivateIp(conn.dst) ? 'Private / Internal' : 'External / Public'}
      />
    </div>
  )
}

function DetailItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--subtle)' }}>{label}</p>
      <p className={cn(mono && 'font-mono text-xs')} style={{ color: 'var(--fg-2)' }}>{value}</p>
    </div>
  )
}

function DirectionBadge({ direction }: { direction: Direction }) {
  if (direction === 'inbound') {
    return (
      <span className="inline-flex items-center gap-1 text-xs" style={{ color: 'var(--med)' }} title="Inbound">
        <ArrowDownLeft className="h-3.5 w-3.5" />
      </span>
    )
  }
  if (direction === 'outbound') {
    return (
      <span className="inline-flex items-center gap-1 text-xs" style={{ color: 'var(--emerald-400)' }} title="Outbound">
        <ArrowUpRight className="h-3.5 w-3.5" />
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs" style={{ color: 'var(--subtle)' }} title="Local">
      <Activity className="h-3.5 w-3.5" />
    </span>
  )
}

function EndpointCell({ endpoint, ip, isExternal, onCopy, isCopied }: {
  endpoint: string
  ip: string
  isExternal: boolean
  onCopy: (ip: string) => void
  isCopied: boolean
}) {
  const isValid = ip && ip !== 'N/A'

  return (
    <div className="flex items-center gap-1.5 group/ep">
      {isExternal && isValid && (
        <Globe className="h-3 w-3 flex-shrink-0" style={{ color: 'var(--high)' }} title="External IP" />
      )}
      <span className="font-mono text-xs truncate max-w-[160px]" style={{ color: 'var(--fg-2)' }} title={endpoint}>
        {endpoint}
      </span>
      {isValid && (
        <button
          onClick={(e) => { e.stopPropagation(); onCopy(ip) }}
          className="opacity-0 group-hover/ep:opacity-100 transition-opacity"
          style={{ color: 'var(--subtle)' }}
          title={isCopied ? 'Copied!' : `Copy ${ip}`}
        >
          {isCopied ? (
            <span className="text-[10px] font-medium" style={{ color: 'var(--emerald-400)' }}>Copied</span>
          ) : (
            <Copy className="h-3 w-3" />
          )}
        </button>
      )}
    </div>
  )
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  const getStyle = (proto: string): React.CSSProperties => {
    switch (proto) {
      case 'TCP':
        return { backgroundColor: 'var(--med-bg)', color: 'var(--med)', border: '1px solid var(--med)' }
      case 'UDP':
        return { backgroundColor: 'var(--high-bg)', color: 'var(--high)', border: '1px solid var(--high)' }
      case 'ICMP':
        return { backgroundColor: 'var(--high-bg)', color: 'var(--high)', border: '1px solid var(--high)' }
      default:
        return { backgroundColor: 'var(--surface-2)', color: 'var(--muted)', border: '1px solid var(--border)' }
    }
  }

  return (
    <span
      className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={getStyle(protocol)}
    >
      {protocol || 'N/A'}
    </span>
  )
}

function StatusBadge({ status }: { status: ConnStatus }) {
  const getStyle = (s: ConnStatus): React.CSSProperties => {
    switch (s) {
      case 'established':
        return { backgroundColor: 'var(--emerald-glow)', color: 'var(--emerald-400)' }
      case 'closed':
        return { backgroundColor: 'var(--low-bg)', color: 'var(--low)' }
      case 'blocked':
        return { backgroundColor: 'var(--crit-bg)', color: 'var(--crit)' }
      case 'suspicious':
        return { backgroundColor: 'var(--high-bg)', color: 'var(--high)' }
      default:
        return { backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }
    }
  }

  const labels: Record<ConnStatus, string> = {
    established: 'Active',
    closed: 'Closed',
    blocked: 'Blocked',
    suspicious: 'Suspicious',
  }

  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase"
      style={getStyle(status)}
    >
      {status === 'blocked' && <Shield className="h-2.5 w-2.5" />}
      {status === 'suspicious' && <AlertTriangle className="h-2.5 w-2.5" />}
      {labels[status]}
    </span>
  )
}

function ActionButton({ icon: Icon, title, color, onClick }: {
  icon: React.ElementType
  title: string
  color: 'high' | 'med' | 'emerald'
  onClick: () => void
}) {
  const getStyle = (c: string): React.CSSProperties => {
    switch (c) {
      case 'high':
        return { backgroundColor: 'var(--high-bg)', border: '1px solid var(--high)', color: 'var(--high)' }
      case 'med':
        return { backgroundColor: 'var(--med-bg)', border: '1px solid var(--med)', color: 'var(--med)' }
      case 'emerald':
        return { backgroundColor: 'var(--emerald-glow)', border: '1px solid var(--emerald-600)', color: 'var(--emerald-400)' }
      default:
        return { backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--muted)' }
    }
  }

  return (
    <button
      onClick={onClick}
      className="p-1.5 rounded transition-colors hover:brightness-110"
      style={getStyle(color)}
      title={title}
    >
      <Icon className="h-3.5 w-3.5" />
    </button>
  )
}

function StatCard({ icon: Icon, label, value, color, trend, alert }: {
  icon: React.ElementType
  label: string
  value: string
  color: 'emerald' | 'green' | 'crit' | 'high' | 'med' | 'low'
  trend?: number
  alert?: boolean
}) {
  const getIconStyle = (c: string): { bg: string; icon: string } => {
    switch (c) {
      case 'emerald':
      case 'green':
        return { bg: 'var(--emerald-glow)', icon: 'var(--emerald-400)' }
      case 'crit':
        return { bg: 'var(--crit-bg)', icon: 'var(--crit)' }
      case 'high':
        return { bg: 'var(--high-bg)', icon: 'var(--high)' }
      case 'med':
        return { bg: 'var(--med-bg)', icon: 'var(--med)' }
      case 'low':
        return { bg: 'var(--low-bg)', icon: 'var(--low)' }
      default:
        return { bg: 'var(--surface-2)', icon: 'var(--muted)' }
    }
  }

  const styles = getIconStyle(color)

  return (
    <div
      className="card-sentinel rounded-xl p-3 transition-all"
      style={{
        backgroundColor: 'var(--surface)',
        border: alert ? '1px solid var(--crit)' : '1px solid var(--border)',
        boxShadow: alert ? '0 0 0 1px var(--crit-bg)' : undefined,
      }}
    >
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: styles.bg }}>
          <Icon className="h-4 w-4" style={{ color: styles.icon }} />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <p className="text-lg font-bold leading-tight" style={{ color: 'var(--fg)' }}>{value}</p>
            {trend !== undefined && trend !== 0 && (
              <span className="inline-flex items-center text-[10px] font-medium" style={{ color: trend > 0 ? 'var(--emerald-400)' : 'var(--crit)' }}>
                {trend > 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
              </span>
            )}
          </div>
          <p className="text-[11px] leading-tight truncate" style={{ color: 'var(--subtle)' }}>{label}</p>
        </div>
      </div>
    </div>
  )
}

function FilterSelect({ label, value, onChange, options }: {
  label: string
  value: string
  onChange: (v: string) => void
  options: Array<{ value: string; label: string }>
}) {
  return (
    <div className="flex items-center gap-1.5">
      <label className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>{label}</label>
      <Select
        value={value}
        onValueChange={onChange}
        className="rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 appearance-none pr-6 cursor-pointer"
      >
        {options.map(opt => (
          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
        ))}
      </Select>
    </div>
  )
}
