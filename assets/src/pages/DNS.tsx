import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Globe,
  Search,
  Filter,
  Clock,
  Shield,
  ShieldOff,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  ChevronLeft,
  Plus,
  Trash2,
  Upload,
  Play,
  RefreshCw,
  BarChart3,
  List,
  XCircle,
  CheckCircle,
  FileWarning,
  Activity,
  Eye,
} from 'lucide-react'
import { cn, formatDate, safeCapitalize } from '@/lib/utils'
import { useEventStream } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { ExportDropdown } from '@/components/ExportDropdown'
import { Select, SelectItem } from '@/components/ui/baseui'
import type { WebSocketConnectionState } from '@/types'

// ============================================================================
// Types
// ============================================================================

interface DNSQuery {
  id: string
  timestamp: string
  domain: string
  queryType: string
  response: string
  processName: string
  processPid: number
  processPath?: string
  agentId: string
  agentHostname: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'allowed' | 'blocked' | 'suspicious'
  detections?: DNSDetection[]
}

interface DNSDetection {
  type: string
  ruleName: string
  confidence: number
  description: string
}

interface DNSStats {
  totalQueries: number
  uniqueDomains: number
  blockedQueries: number
  suspiciousQueries: number
}

interface TopDomain {
  domain: string
  count: number
}

interface BlocklistEntry {
  id: string
  domain: string
  blockedAt: string
  blockedBy: string
  reason?: string
  source?: string
  selected?: boolean
}

interface DNSAlert {
  id: string
  domain: string
  detectionType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  agentId: string
  agentHostname: string
  description: string
  alertId?: string
}

interface DNSPageProps {
  stats?: DNSStats
  queries?: DNSQuery[]
  topDomains?: TopDomain[]
  blocklist?: BlocklistEntry[]
  alerts?: DNSAlert[]
  agents?: Array<{ id: string; hostname: string }>
  pagination?: {
    page: number
    perPage: number
    total: number
  }
}

function normalizeDnsQuery(raw: Record<string, unknown>): DNSQuery {
  const payload = (raw.payload as Record<string, unknown> | undefined) || {}
  const process = (payload.process as Record<string, unknown> | undefined) || {}
  const dns = (payload.dns as Record<string, unknown> | undefined) || {}

  const pick = (...values: Array<unknown>) =>
    values.find((value) => value !== undefined && value !== null && value !== '')

  const stringify = (value: unknown, fallback = ''): string => {
    if (typeof value === 'string') return value
    if (typeof value === 'number') return String(value)
    return fallback
  }

  const toNumber = (value: unknown, fallback = 0): number => {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string') {
      const parsed = Number(value)
      return Number.isFinite(parsed) ? parsed : fallback
    }
    return fallback
  }

  const joinList = (value: unknown): string => {
    if (!Array.isArray(value)) return ''
    return value.map((item) => stringify(item)).filter(Boolean).join(', ')
  }

  return {
    id: stringify(pick(raw.id), crypto.randomUUID()),
    timestamp: stringify(pick(raw.timestamp), new Date().toISOString()),
    domain: stringify(pick(raw.domain, raw.query, raw.query_name, payload.query, payload.query_name, dns.query, dns.query_name), 'Unknown'),
    queryType: stringify(pick(raw.queryType, raw.query_type, raw.record_type, raw.type, payload.query_type, payload.record_type, dns.query_type, dns.record_type), 'A'),
    response: stringify(
      pick(
        raw.response,
        raw.resolved_ip,
        raw.answer,
        payload.response,
        payload.resolved_ip,
        payload.answer,
        joinList(raw.responses),
        joinList(raw.resolved_ips),
        joinList(payload.responses),
        joinList(payload.resolved_ips),
        joinList(dns.responses),
        joinList(dns.resolved_ips),
      ),
      '',
    ),
    processName: stringify(
      pick(
        raw.processName,
        raw.process_name,
        raw.name,
        payload.process_name,
        payload.name,
        process.process_name,
        process.name,
      ),
      'Unknown',
    ),
    processPid: toNumber(pick(raw.processPid, raw.process_pid, raw.pid, payload.pid, process.pid), 0),
    processPath:
      stringify(
        pick(
          raw.processPath,
          raw.process_path,
          raw.path,
          payload.process_path,
          payload.path,
          process.process_path,
          process.path,
        ),
        '',
      ) || undefined,
    agentId: stringify(pick(raw.agentId, raw.agent_id), ''),
    agentHostname: stringify(pick(raw.agentHostname, raw.agent_hostname, raw.agentId, raw.agent_id), ''),
    severity: stringify(pick(raw.severity), 'info') as DNSQuery['severity'],
    status: stringify(pick(raw.status), 'allowed') as DNSQuery['status'],
    detections: Array.isArray(raw.detections) ? (raw.detections as DNSDetection[]) : undefined,
  }
}

// ============================================================================
// Tab definitions
// ============================================================================

type TabId = 'live-feed' | 'top-domains' | 'blocklist' | 'detections'

const tabs: { id: TabId; label: string; icon: React.ElementType }[] = [
  { id: 'live-feed', label: 'Live DNS Feed', icon: Activity },
  { id: 'top-domains', label: 'Top Domains', icon: BarChart3 },
  { id: 'blocklist', label: 'Blocklist', icon: ShieldOff },
  { id: 'detections', label: 'Detections', icon: AlertTriangle },
]

// ============================================================================
// Main Component
// ============================================================================

export default function DNS({
  stats: initialStats,
  queries: initialQueries,
  topDomains: initialTopDomains,
  blocklist: initialBlocklist,
  alerts: initialAlerts,
  agents,
  pagination: initialPagination,
}: DNSPageProps) {
  const [activeTab, setActiveTab] = useState<TabId>('live-feed')
  const [stats, setStats] = useState<DNSStats>(initialStats || {
    totalQueries: 0,
    uniqueDomains: 0,
    blockedQueries: 0,
    suspiciousQueries: 0,
  })
  const [queries, setQueries] = useState<DNSQuery[]>(initialQueries || [])
  const [topDomains, setTopDomains] = useState<TopDomain[]>(initialTopDomains || [])
  const [blocklist, setBlocklist] = useState<BlocklistEntry[]>(
    (initialBlocklist || []).map(e => ({ ...e, selected: false }))
  )
  const [alerts, setAlerts] = useState<DNSAlert[]>(initialAlerts || [])
  const [pagination, setPagination] = useState(initialPagination || { page: 1, perPage: 50, total: 0 })
  const [loading, setLoading] = useState(false)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [queryTypeFilter, setQueryTypeFilter] = useState('all')
  const [agentFilter, setAgentFilter] = useState('all')
  const [processFilter, setProcessFilter] = useState('')
  const [expandedRow, setExpandedRow] = useState<string | null>(null)

  // Blocklist state
  const [newBlockDomain, setNewBlockDomain] = useState('')
  const [bulkImportText, setBulkImportText] = useState('')
  const [showBulkImport, setShowBulkImport] = useState(false)
  const [blocklistLoading, setBlocklistLoading] = useState(false)
  const [selectAll, setSelectAll] = useState(false)

  // Live event streaming
  const {
    connectionState,
    events: liveEvents,
    clearEvents,
    pauseStream,
    resumeStream,
    isPaused,
  } = useEventStream()

  const mergedIdsRef = useRef(new Set<string>())

  // Merge DNS events from live stream
  useEffect(() => {
    if (!liveEvents || liveEvents.length === 0) return

    const dnsEvents = liveEvents.filter(
      e => e.eventType === 'dns_query' && !mergedIdsRef.current.has(e.id)
    )
    if (dnsEvents.length === 0) return

    dnsEvents.forEach(e => mergedIdsRef.current.add(e.id))

    setQueries(prev => {
      const newQueries = dnsEvents.map(e =>
        normalizeDnsQuery({
          id: e.id,
          timestamp: new Date(e.timestamp).toISOString(),
          agentId: e.agentId,
          agentHostname: e.agentHostname || e.agentId,
          severity: e.severity,
          status: inferQueryStatus(e),
          detections: e.detections?.map(d => ({
            type: d.type,
            ruleName: d.ruleName,
            confidence: d.confidence,
            description: d.description,
          })),
          payload: e.payload,
        })
      )

      return [...newQueries, ...prev].slice(0, 500)
    })

    // Update stats optimistically
    setStats(prev => ({
      ...prev,
      totalQueries: prev.totalQueries + dnsEvents.length,
    }))
  }, [liveEvents])

  // ---- Data fetching ----

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/stats', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const json = await res.json()
        const d = json.data || json
        setStats({
          totalQueries: d.total_queries_today ?? d.totalQueries ?? 0,
          uniqueDomains: d.unique_domains ?? d.uniqueDomains ?? 0,
          blockedQueries: d.blocked_count ?? d.blockedQueries ?? 0,
          suspiciousQueries: d.suspicious_count ?? d.suspiciousQueries ?? 0,
        })
      }
    } catch {
      // ignore
    }
  }, [])

  const fetchQueries = useCallback(async (page = 1) => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('per_page', '50')
      if (searchQuery) params.set('domain', searchQuery)
      if (queryTypeFilter !== 'all') params.set('query_type', queryTypeFilter)
      if (agentFilter !== 'all') params.set('agent_id', agentFilter)
      if (processFilter) params.set('process', processFilter)

      const res = await fetch(`/api/v1/dns/queries?${params.toString()}`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        const rawQueries = data.queries || data.data || []
        setQueries(Array.isArray(rawQueries) ? rawQueries.map((query: Record<string, unknown>) => normalizeDnsQuery(query)) : [])
        if (data.pagination) setPagination(data.pagination)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [searchQuery, queryTypeFilter, agentFilter, processFilter])

  const fetchTopDomains = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/top-domains', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        const rawDomains = data.domains || data.data || []
        setTopDomains(Array.isArray(rawDomains) ? rawDomains : [])
      }
    } catch {
      // ignore
    }
  }, [])

  const fetchBlocklist = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/blocklist', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        setBlocklist((data.blocklist || data.data || []).map((e: BlocklistEntry & Record<string, any>) => ({
          id: e.id || e.domain,
          domain: e.domain,
          blockedAt: e.blockedAt || e.blocked_at,
          blockedBy: e.blockedBy || e.blocked_by,
          reason: e.reason,
          source: e.source,
          selected: false,
        })))
      }
    } catch {
      // ignore
    }
  }, [])

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/alerts', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        setAlerts(data.alerts || data.data || [])
      }
    } catch {
      // ignore
    }
  }, [])

  // Fetch data on mount and tab change
  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  useEffect(() => {
    if (activeTab === 'live-feed') fetchQueries()
    if (activeTab === 'top-domains') fetchTopDomains()
    if (activeTab === 'blocklist') fetchBlocklist()
    if (activeTab === 'detections') fetchAlerts()
  }, [activeTab, fetchQueries, fetchTopDomains, fetchBlocklist, fetchAlerts])

  // ---- Blocklist actions ----

  const addToBlocklist = async (domain: string) => {
    if (!domain.trim()) return
    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      const res = await fetch('/api/v1/dns/blocklist', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
        body: JSON.stringify({ domains: [domain.trim()], reason: 'Manual block' }),
      })
      if (res.ok) {
        setNewBlockDomain('')
        fetchBlocklist()
        fetchStats()
      }
    } catch {
      // ignore
    } finally {
      setBlocklistLoading(false)
    }
  }

  const removeFromBlocklist = async (domain: string) => {
    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      await fetch(`/api/v1/dns/blocklist/${encodeURIComponent(domain)}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
      })
      fetchBlocklist()
      fetchStats()
    } catch {
      // ignore
    } finally {
      setBlocklistLoading(false)
    }
  }

  const bulkAddToBlocklist = async () => {
    const text = bulkImportText.trim()
    if (!text) return

    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      await fetch('/api/v1/dns/blocklist/import', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
        body: JSON.stringify({ text, reason: 'Bulk import' }),
      })
      setBulkImportText('')
      setShowBulkImport(false)
      fetchBlocklist()
      fetchStats()
    } catch {
      // ignore
    } finally {
      setBlocklistLoading(false)
    }
  }

  const removeSelectedFromBlocklist = async () => {
    const selectedDomains = blocklist.filter(e => e.selected).map(e => e.domain)
    if (selectedDomains.length === 0) return

    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      for (const domain of selectedDomains) {
        await fetch(`/api/v1/dns/blocklist/${encodeURIComponent(domain)}`, {
          method: 'DELETE',
          credentials: 'include',
          headers: {
            'Accept': 'application/json',
            ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
          },
        })
      }
      fetchBlocklist()
      fetchStats()
    } catch {
      // ignore
    } finally {
      setBlocklistLoading(false)
    }
  }

  const toggleBlocklistSelection = (id: string) => {
    setBlocklist(prev =>
      prev.map(e => (e.id === id ? { ...e, selected: !e.selected } : e))
    )
  }

  const toggleSelectAll = () => {
    const newVal = !selectAll
    setSelectAll(newVal)
    setBlocklist(prev => prev.map(e => ({ ...e, selected: newVal })))
  }

  // ---- Filtering ----

  const filteredQueries = useMemo(() => {
    return queries.filter(q => {
      if (searchQuery && !q.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false
      if (queryTypeFilter !== 'all' && q.queryType !== queryTypeFilter) return false
      if (agentFilter !== 'all' && q.agentId !== agentFilter) return false
      if (processFilter && !q.processName.toLowerCase().includes(processFilter.toLowerCase())) return false
      return true
    })
  }, [queries, searchQuery, queryTypeFilter, agentFilter, processFilter])

  const selectedCount = blocklist.filter(e => e.selected).length

  // ---- Pagination ----

  const totalPages = Math.max(1, Math.ceil(pagination.total / pagination.perPage))

  const goToPage = (page: number) => {
    if (page < 1 || page > totalPages) return
    setPagination(prev => ({ ...prev, page }))
    fetchQueries(page)
  }

  // ---- Export helpers ----

  const getQueryExportData = () =>
    filteredQueries.map(q => ({
      id: q.id,
      timestamp: q.timestamp,
      domain: q.domain,
      query_type: q.queryType,
      response: q.response,
      process_name: q.processName,
      process_pid: q.processPid,
      agent_id: q.agentId,
      agent_hostname: q.agentHostname,
      severity: q.severity,
      status: q.status,
    }))

  const getBlocklistExportData = () =>
    blocklist.map(e => ({
      domain: e.domain,
      blocked_at: e.blockedAt,
      blocked_by: e.blockedBy,
      reason: e.reason,
      source: e.source,
    }))

  return (
    <MainLayout title="DNS Monitoring">
      <Head title="DNS - Tamandua EDR" />

      {/* Stats Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Total Queries Today"
          value={stats.totalQueries}
          icon={Globe}
          iconColor="var(--sol-cyan)"
        />
        <StatCard
          label="Unique Domains"
          value={stats.uniqueDomains}
          icon={List}
          iconColor="var(--sol-blue)"
        />
        <StatCard
          label="Blocked Queries"
          value={stats.blockedQueries}
          icon={ShieldOff}
          iconColor="var(--crit)"
        />
        <StatCard
          label="Suspicious Queries"
          value={stats.suspiciousQueries}
          icon={AlertTriangle}
          iconColor="var(--warn)"
        />
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 border-b border-[var(--border)] pb-0">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px',
              activeTab === tab.id
                ? 'border-[var(--sol-cyan)] text-[var(--fg)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--border)]'
            )}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'live-feed' && (
        <LiveDNSFeed
          queries={filteredQueries}
          agents={agents || []}
          loading={loading}
          connectionState={connectionState}
          isPaused={isPaused}
          pauseStream={pauseStream}
          resumeStream={resumeStream}
          clearEvents={() => { clearEvents(); setQueries([]) }}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          queryTypeFilter={queryTypeFilter}
          setQueryTypeFilter={setQueryTypeFilter}
          agentFilter={agentFilter}
          setAgentFilter={setAgentFilter}
          processFilter={processFilter}
          setProcessFilter={setProcessFilter}
          expandedRow={expandedRow}
          setExpandedRow={setExpandedRow}
          pagination={pagination}
          totalPages={totalPages}
          goToPage={goToPage}
          onRefresh={() => fetchQueries(pagination.page)}
          getExportData={getQueryExportData}
        />
      )}

      {activeTab === 'top-domains' && (
        <TopDomainsPanel
          domains={topDomains}
          onRefresh={fetchTopDomains}
        />
      )}

      {activeTab === 'blocklist' && (
        <BlocklistManagement
          blocklist={blocklist}
          loading={blocklistLoading}
          newBlockDomain={newBlockDomain}
          setNewBlockDomain={setNewBlockDomain}
          addToBlocklist={addToBlocklist}
          removeFromBlocklist={removeFromBlocklist}
          bulkImportText={bulkImportText}
          setBulkImportText={setBulkImportText}
          showBulkImport={showBulkImport}
          setShowBulkImport={setShowBulkImport}
          bulkAddToBlocklist={bulkAddToBlocklist}
          toggleBlocklistSelection={toggleBlocklistSelection}
          toggleSelectAll={toggleSelectAll}
          selectAll={selectAll}
          selectedCount={selectedCount}
          removeSelectedFromBlocklist={removeSelectedFromBlocklist}
          onRefresh={fetchBlocklist}
          getExportData={getBlocklistExportData}
        />
      )}

      {activeTab === 'detections' && (
        <DNSDetections
          alerts={alerts}
          onRefresh={fetchAlerts}
        />
      )}
    </MainLayout>
  )
}

// ============================================================================
// Stat Card
// ============================================================================

function StatCard({
  label,
  value,
  icon: Icon,
  iconColor,
}: {
  label: string
  value: number
  icon: React.ElementType
  iconColor: string
}) {
  return (
    <div className="card-sentinel p-4 flex items-center gap-4">
      <div
        className="p-3 rounded-lg"
        style={{ backgroundColor: `color-mix(in srgb, ${iconColor} 15%, transparent)` }}
      >
        <Icon className="h-5 w-5" style={{ color: iconColor }} />
      </div>
      <div>
        <p className="text-2xl font-bold text-[var(--fg)]">{value.toLocaleString()}</p>
        <p className="text-xs text-[var(--muted)]">{label}</p>
      </div>
    </div>
  )
}

// ============================================================================
// Live DNS Feed Tab
// ============================================================================

interface LiveDNSFeedProps {
  queries: DNSQuery[]
  agents: Array<{ id: string; hostname: string }>
  loading: boolean
  connectionState: WebSocketConnectionState
  isPaused: boolean
  pauseStream: () => void
  resumeStream: () => void
  clearEvents: () => void
  searchQuery: string
  setSearchQuery: (v: string) => void
  queryTypeFilter: string
  setQueryTypeFilter: (v: string) => void
  agentFilter: string
  setAgentFilter: (v: string) => void
  processFilter: string
  setProcessFilter: (v: string) => void
  expandedRow: string | null
  setExpandedRow: (v: string | null) => void
  pagination: { page: number; perPage: number; total: number }
  totalPages: number
  goToPage: (page: number) => void
  onRefresh: () => void
  getExportData: () => Record<string, any>[]
}

function LiveDNSFeed({
  queries,
  agents,
  loading,
  connectionState,
  isPaused,
  pauseStream,
  resumeStream,
  clearEvents,
  searchQuery,
  setSearchQuery,
  queryTypeFilter,
  setQueryTypeFilter,
  agentFilter,
  setAgentFilter,
  processFilter,
  setProcessFilter,
  expandedRow,
  setExpandedRow,
  pagination,
  totalPages,
  goToPage,
  onRefresh,
  getExportData,
}: LiveDNSFeedProps) {
  const queryTypes = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'SOA', 'SRV', 'PTR']

  return (
    <div className="card-sentinel">
      {/* Toolbar */}
      <div className="p-4 border-b border-[var(--border)] space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
            <input
              type="text"
              placeholder="Search by domain..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
          </div>

          <div className="relative min-w-[120px]">
            <input
              type="text"
              placeholder="Process..."
              value={processFilter}
              onChange={e => setProcessFilter(e.target.value)}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
          </div>

          <ConnectionStatus state={connectionState} showText={false} />

          <button
            onClick={() => (isPaused ? resumeStream() : pauseStream())}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors',
              !isPaused
                ? 'bg-[var(--ok)] text-white'
                : 'bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)]'
            )}
          >
            {isPaused ? (
              <>
                <Play className="h-4 w-4" />
                Resume
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                Live
              </>
            )}
          </button>

          <button
            onClick={clearEvents}
            className="flex items-center gap-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] px-3 py-2 rounded-lg text-sm"
            title="Clear"
          >
            <Trash2 className="h-4 w-4" />
          </button>

          <button
            onClick={onRefresh}
            className="flex items-center gap-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] px-3 py-2 rounded-lg text-sm"
            title="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </button>

          <ExportDropdown
            getData={getExportData}
            filenameBase="tamandua-dns-queries"
            disabled={queries.length === 0}
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[var(--muted)]" />
            <Select
              value={queryTypeFilter}
              onValueChange={setQueryTypeFilter}
              placeholder="All Query Types"
              className="bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--fg)] focus:ring-2 focus:ring-[var(--sol-cyan)]"
            >
              <SelectItem value="all">All Query Types</SelectItem>
              {queryTypes.map(t => (
                <SelectItem key={t} value={t}>{t}</SelectItem>
              ))}
            </Select>
          </div>

          <Select
            value={agentFilter}
            onValueChange={setAgentFilter}
            placeholder="All Agents"
            className="bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--fg)] focus:ring-2 focus:ring-[var(--sol-cyan)]"
          >
            <SelectItem value="all">All Agents</SelectItem>
            {agents.map(a => (
              <SelectItem key={a.id} value={a.id}>{a.hostname}</SelectItem>
            ))}
          </Select>

          <span className="text-sm text-[var(--muted)]">
            {queries.length} queries
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--border)] text-left">
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Timestamp</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Domain</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Type</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Response</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Process</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Agent</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Severity</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider w-8"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {queries.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-[var(--muted)]">
                  <Globe className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p>No DNS queries found</p>
                  <p className="text-sm mt-1">Adjust your filters or wait for live data</p>
                </td>
              </tr>
            ) : (
              queries.map(query => (
                <DNSQueryRow
                  key={query.id}
                  query={query}
                  expanded={expandedRow === query.id}
                  onToggle={() => setExpandedRow(expandedRow === query.id ? null : query.id)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination.total > pagination.perPage && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border)]">
          <span className="text-sm text-[var(--muted)]">
            Page {pagination.page} of {totalPages} ({pagination.total} total)
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => goToPage(pagination.page - 1)}
              disabled={pagination.page <= 1}
              className="p-2 rounded-lg bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const startPage = Math.max(1, pagination.page - 2)
              const pageNum = startPage + i
              if (pageNum > totalPages) return null
              return (
                <button
                  key={pageNum}
                  onClick={() => goToPage(pageNum)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                    pageNum === pagination.page
                      ? 'bg-[var(--sol-cyan)] text-white'
                      : 'bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)]'
                  )}
                >
                  {pageNum}
                </button>
              )
            })}
            <button
              onClick={() => goToPage(pagination.page + 1)}
              disabled={pagination.page >= totalPages}
              className="p-2 rounded-lg bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// DNS Query Row (with expandable details)
// ============================================================================

function DNSQueryRow({
  query,
  expanded,
  onToggle,
}: {
  query: DNSQuery
  expanded: boolean
  onToggle: () => void
}) {
  const statusColors: Record<string, { bg: string; text: string; border: string }> = {
    blocked: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    suspicious: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    allowed: { bg: 'var(--ok)', text: 'var(--ok)', border: 'var(--ok)' },
  }

  const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    high: { bg: 'var(--high)', text: 'var(--high)', border: 'var(--high)' },
    medium: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    low: { bg: 'var(--sol-blue)', text: 'var(--sol-blue)', border: 'var(--sol-blue)' },
    info: { bg: 'var(--muted)', text: 'var(--muted)', border: 'var(--muted)' },
  }

  const rowBg =
    query.status === 'blocked'
      ? 'bg-[color-mix(in_srgb,var(--crit)_5%,transparent)] hover:bg-[color-mix(in_srgb,var(--crit)_10%,transparent)]'
      : query.status === 'suspicious'
        ? 'bg-[color-mix(in_srgb,var(--warn)_5%,transparent)] hover:bg-[color-mix(in_srgb,var(--warn)_10%,transparent)]'
        : 'hover:bg-[var(--surface-alt)]'

  const currentStatus = statusColors[query.status] || statusColors.allowed
  const currentSeverity = severityStyles[query.severity] || severityStyles.info

  return (
    <>
      <tr
        className={cn('cursor-pointer transition-colors', rowBg)}
        onClick={onToggle}
      >
        <td className="px-4 py-3 text-sm text-[var(--fg)] whitespace-nowrap">
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3 text-[var(--muted)]" />
            {formatDate(query.timestamp)}
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {query.status === 'blocked' && <ShieldOff className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--crit)' }} />}
            {query.status === 'suspicious' && <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--warn)' }} />}
            <span className="text-sm font-mono truncate max-w-[280px]" style={{ color: 'var(--sol-cyan)' }} title={query.domain}>
              {query.domain}
            </span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--surface-alt)] text-[var(--fg)]">
            {query.queryType}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-[var(--muted)] font-mono truncate max-w-[160px]" title={query.response}>
          {query.response || '--'}
        </td>
        <td className="px-4 py-3">
          <span className="text-sm text-[var(--fg)]">{query.processName}</span>
          <span className="text-xs text-[var(--muted)] ml-1">({query.processPid})</span>
        </td>
        <td className="px-4 py-3 text-sm text-[var(--muted)]">
          {query.agentHostname}
        </td>
        <td className="px-4 py-3">
          <span
            className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border"
            style={{
              backgroundColor: `color-mix(in srgb, ${currentSeverity.bg} 20%, transparent)`,
              color: currentSeverity.text,
              borderColor: `color-mix(in srgb, ${currentSeverity.border} 30%, transparent)`,
            }}
          >
            {safeCapitalize(query.severity)}
          </span>
        </td>
        <td className="px-4 py-3">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-[var(--muted)]" />
          ) : (
            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
          )}
        </td>
      </tr>

      {/* Expanded details row */}
      {expanded && (
        <tr className="bg-[var(--surface-alt)]">
          <td colSpan={8} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Full Response
                </h4>
                <p className="text-sm text-[var(--fg)] font-mono break-all">
                  {query.response || 'No response data'}
                </p>
              </div>
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Process Details
                </h4>
                <div className="space-y-1 text-sm">
                  <p className="text-[var(--fg)]">
                    <span className="text-[var(--muted)]">Name:</span> {query.processName}
                  </p>
                  <p className="text-[var(--fg)]">
                    <span className="text-[var(--muted)]">PID:</span> {query.processPid}
                  </p>
                  {query.processPath && (
                    <p className="text-[var(--fg)] break-all">
                      <span className="text-[var(--muted)]">Path:</span> {query.processPath}
                    </p>
                  )}
                </div>
              </div>
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Status & Detections
                </h4>
                <div className="space-y-2">
                  <span
                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border"
                    style={{
                      backgroundColor: `color-mix(in srgb, ${currentStatus.bg} 10%, transparent)`,
                      color: currentStatus.text,
                      borderColor: `color-mix(in srgb, ${currentStatus.border} 30%, transparent)`,
                    }}
                  >
                    {query.status === 'blocked' && <ShieldOff className="h-3 w-3 mr-1" />}
                    {query.status === 'suspicious' && <AlertTriangle className="h-3 w-3 mr-1" />}
                    {query.status === 'allowed' && <CheckCircle className="h-3 w-3 mr-1" />}
                    {safeCapitalize(query.status)}
                  </span>

                  {query.detections && query.detections.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {query.detections.map((d, i) => (
                        <div key={i} className="text-xs bg-[var(--surface)] rounded p-2 border border-[var(--border)]">
                          <p style={{ color: 'var(--warn)' }} className="font-medium">{d.ruleName}</p>
                          <p className="text-[var(--muted)] mt-0.5">{d.description}</p>
                          <p className="text-[var(--muted)] mt-0.5">
                            Type: {d.type} | Confidence: {d.confidence}%
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex gap-2 mt-4 pt-3 border-t border-[var(--border)]">
              <button
                onClick={e => {
                  e.stopPropagation()
                  router.visit(`/app/hunt?q=${encodeURIComponent(`domain:${query.domain}`)}`)
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sol-cyan)] hover:bg-[color-mix(in_srgb,var(--sol-cyan)_85%,black)] text-white text-xs font-medium rounded-lg"
              >
                <Search className="h-3 w-3" />
                Hunt Domain
              </button>
              <button
                onClick={e => {
                  e.stopPropagation()
                  router.visit(`/app/agents/${query.agentId}`)
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] text-xs font-medium rounded-lg"
              >
                <Eye className="h-3 w-3" />
                View Agent
              </button>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ============================================================================
// Top Domains Panel
// ============================================================================

function TopDomainsPanel({
  domains,
  onRefresh,
}: {
  domains: TopDomain[]
  onRefresh: () => void
}) {
  const maxCount = domains.length > 0 ? Math.max(...domains.map(d => d.count)) : 1

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--fg)]">Top 20 Queried Domains</h3>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {domains.length === 0 ? (
        <div className="px-4 py-12 text-center text-[var(--muted)]">
          <BarChart3 className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No domain data available</p>
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-subtle)]">
          {domains.slice(0, 20).map((domain, idx) => (
            <div key={domain.domain} className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--surface-alt)] transition-colors">
              <span className="text-xs font-mono text-[var(--muted)] w-6 text-right">{idx + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono truncate" style={{ color: 'var(--sol-cyan)' }} title={domain.domain}>
                  {domain.domain}
                </p>
                <div className="mt-1 h-1.5 bg-[var(--surface-alt)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${(domain.count / maxCount) * 100}%`, backgroundColor: 'var(--sol-cyan)' }}
                  />
                </div>
              </div>
              <span className="text-sm font-medium text-[var(--fg)] tabular-nums">
                {domain.count.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Blocklist Management
// ============================================================================

interface BlocklistManagementProps {
  blocklist: BlocklistEntry[]
  loading: boolean
  newBlockDomain: string
  setNewBlockDomain: (v: string) => void
  addToBlocklist: (domain: string) => void
  removeFromBlocklist: (domain: string) => void
  bulkImportText: string
  setBulkImportText: (v: string) => void
  showBulkImport: boolean
  setShowBulkImport: (v: boolean) => void
  bulkAddToBlocklist: () => void
  toggleBlocklistSelection: (id: string) => void
  toggleSelectAll: () => void
  selectAll: boolean
  selectedCount: number
  removeSelectedFromBlocklist: () => void
  onRefresh: () => void
  getExportData: () => Record<string, any>[]
}

function BlocklistManagement({
  blocklist,
  loading,
  newBlockDomain,
  setNewBlockDomain,
  addToBlocklist,
  removeFromBlocklist,
  bulkImportText,
  setBulkImportText,
  showBulkImport,
  setShowBulkImport,
  bulkAddToBlocklist,
  toggleBlocklistSelection,
  toggleSelectAll,
  selectAll,
  selectedCount,
  removeSelectedFromBlocklist,
  onRefresh,
  getExportData,
}: BlocklistManagementProps) {
  return (
    <div className="space-y-4">
      {/* Add domain bar */}
      <div className="card-sentinel p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[240px] flex gap-2">
            <input
              type="text"
              placeholder="Enter domain to block (e.g. malware.example.com)"
              value={newBlockDomain}
              onChange={e => setNewBlockDomain(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addToBlocklist(newBlockDomain) }}
              className="flex-1 bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
            <button
              onClick={() => addToBlocklist(newBlockDomain)}
              disabled={!newBlockDomain.trim() || loading}
              className="flex items-center gap-2 px-4 py-2 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              <Plus className="h-4 w-4" />
              Block
            </button>
          </div>

          <button
            onClick={() => setShowBulkImport(!showBulkImport)}
            className="flex items-center gap-2 px-3 py-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] rounded-lg text-sm"
          >
            <Upload className="h-4 w-4" />
            Bulk Import
          </button>

          <button
            onClick={onRefresh}
            className="p-2 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
            title="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </button>

          <ExportDropdown
            getData={getExportData}
            filenameBase="tamandua-dns-blocklist"
            disabled={blocklist.length === 0}
          />
        </div>

        {/* Bulk import textarea */}
        {showBulkImport && (
          <div className="mt-3 space-y-2">
            <textarea
              value={bulkImportText}
              onChange={e => setBulkImportText(e.target.value)}
              placeholder="Enter domains to block, one per line..."
              rows={6}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent font-mono"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={bulkAddToBlocklist}
                disabled={!bulkImportText.trim() || loading}
                className="flex items-center gap-2 px-4 py-2 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] disabled:opacity-40 text-white rounded-lg text-sm font-medium"
              >
                <Plus className="h-4 w-4" />
                Add All ({bulkImportText.split('\n').filter(l => l.trim()).length} domains)
              </button>
              <button
                onClick={() => { setShowBulkImport(false); setBulkImportText('') }}
                className="px-3 py-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] rounded-lg text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Bulk actions */}
      {selectedCount > 0 && (
        <div
          className="flex items-center gap-3 rounded-lg px-4 py-2.5 border"
          style={{
            backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)',
            borderColor: 'color-mix(in srgb, var(--warn) 30%, transparent)',
          }}
        >
          <span className="text-sm" style={{ color: 'var(--warn)' }}>{selectedCount} selected</span>
          <button
            onClick={removeSelectedFromBlocklist}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] text-white rounded-lg text-xs font-medium"
          >
            <Trash2 className="h-3 w-3" />
            Remove Selected
          </button>
        </div>
      )}

      {/* Blocklist table */}
      <div className="card-sentinel overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--border)] text-left">
              <th className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  checked={selectAll}
                  onChange={toggleSelectAll}
                  className="rounded bg-[var(--surface-alt)] border-[var(--border)] text-[var(--sol-cyan)] focus:ring-[var(--sol-cyan)]"
                />
              </th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Domain</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Blocked At</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Source</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Blocked By</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider w-20">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {blocklist.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-[var(--muted)]">
                  <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p>No blocked domains</p>
                  <p className="text-sm mt-1">Add domains above to start blocking</p>
                </td>
              </tr>
            ) : (
              blocklist.map(entry => (
                <tr key={entry.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={entry.selected || false}
                      onChange={() => toggleBlocklistSelection(entry.id)}
                      className="rounded bg-[var(--surface-alt)] border-[var(--border)] text-[var(--sol-cyan)] focus:ring-[var(--sol-cyan)]"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="space-y-1">
                      <span className="text-sm text-[var(--fg)] font-mono">{entry.domain}</span>
                      {entry.reason && (
                        <p className="text-xs text-[var(--muted)]">{entry.reason}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    {entry.blockedAt ? formatDate(entry.blockedAt) : '--'}
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    {entry.source || 'manual'}
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    {entry.blockedBy || '--'}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => removeFromBlocklist(entry.domain)}
                      disabled={loading}
                      className="p-1.5 rounded-lg transition-colors disabled:opacity-40"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                        color: 'var(--crit)',
                      }}
                      title="Remove from blocklist"
                    >
                      <XCircle className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// DNS Detections
// ============================================================================

function DNSDetections({
  alerts,
  onRefresh,
}: {
  alerts: DNSAlert[]
  onRefresh: () => void
}) {
  const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    high: { bg: 'var(--high)', text: 'var(--high)', border: 'var(--high)' },
    medium: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    low: { bg: 'var(--sol-blue)', text: 'var(--sol-blue)', border: 'var(--sol-blue)' },
  }

  const detectionTypeLabels: Record<string, { label: string; icon: React.ElementType }> = {
    tunneling: { label: 'DNS Tunneling', icon: Shield },
    dga: { label: 'DGA Detected', icon: FileWarning },
    suspicious_domain: { label: 'Suspicious Domain', icon: AlertTriangle },
    ioc_match: { label: 'IOC Match', icon: Shield },
    exfiltration: { label: 'Data Exfiltration', icon: AlertTriangle },
  }

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--fg)]">DNS-Specific Detections</h3>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="px-4 py-12 text-center text-[var(--muted)]">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No DNS detections</p>
          <p className="text-sm mt-1">DNS-specific detections will appear here</p>
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-subtle)]">
          {alerts.map(alert => {
            const typeInfo = detectionTypeLabels[alert.detectionType] || {
              label: alert.detectionType,
              icon: AlertTriangle,
            }
            const TypeIcon = typeInfo.icon
            const severity = severityStyles[alert.severity] || severityStyles.low

            return (
              <div
                key={alert.id}
                className="px-4 py-3 hover:bg-[var(--surface-alt)] transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div
                    className="p-2 rounded-lg mt-0.5"
                    style={{
                      backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)',
                      color: 'var(--warn)',
                    }}
                  >
                    <TypeIcon className="h-4 w-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-[var(--fg)]">
                        {typeInfo.label}
                      </span>
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border"
                        style={{
                          backgroundColor: `color-mix(in srgb, ${severity.bg} 20%, transparent)`,
                          color: severity.text,
                          borderColor: `color-mix(in srgb, ${severity.border} 30%, transparent)`,
                        }}
                      >
                        {safeCapitalize(alert.severity)}
                      </span>
                    </div>
                    <p className="text-sm font-mono mt-1" style={{ color: 'var(--sol-cyan)' }}>{alert.domain}</p>
                    <p className="text-xs text-[var(--muted)] mt-0.5">{alert.description}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-[var(--muted)]">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatDate(alert.timestamp)}
                      </span>
                      <span>{alert.agentHostname}</span>
                    </div>
                  </div>
                  <div>
                    {alert.alertId && (
                      <button
                        onClick={() => router.visit(`/app/alerts/${alert.alertId}`)}
                        className="flex items-center gap-1 px-2 py-1 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] text-xs transition-colors"
                      >
                        <Eye className="h-3 w-3" />
                        Details
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Helpers
// ============================================================================

function inferQueryStatus(event: { severity: string; payload: Record<string, unknown> }): 'allowed' | 'blocked' | 'suspicious' {
  if (event.payload?.blocked) return 'blocked'
  if (event.severity === 'critical' || event.severity === 'high') return 'suspicious'
  if (event.payload?.suspicious) return 'suspicious'
  return 'allowed'
}
