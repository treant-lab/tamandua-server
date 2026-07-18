import { useState, useEffect, useCallback } from 'react'
import { Head, Link } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  AlertTriangle,
  Bug,
  Search,
  RefreshCw,
  ChevronRight,
  Calendar,
  Target,
  Zap,
  AlertCircle,
  Database,
  Server,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { Select, SelectItem } from '@/components/ui/baseui'
import { useTenantFetch } from '@/hooks/useTenantFetch'

interface VulnerabilityStats {
  total_cves: number
  by_severity: Record<string, number>
  in_kev: number
  high_epss: number
  recent_7d: number
  recent_30d: number
}

interface CVE {
  id: string
  cve_id: string
  description: string
  cvss_v3_score: number | null
  cvss_v3_severity: string | null
  calculated_severity: string
  epss_score: number | null
  epss_percentile: number | null
  in_kev: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  published_at: string
  weaknesses: string[]
  asset_evidence?: {
    source: 'agent_software_inventory'
    affected_asset_count: number | null
    status: 'matched' | 'not_observed' | 'unscoped'
  }
}

interface SyncStatus {
  nvd: {
    last_sync: string | null
    sync_in_progress?: boolean
    inProgress?: boolean
    total_cves: number
  }
  epss: {
    last_sync: string | null
    sync_in_progress?: boolean
    inProgress?: boolean
  }
  kev: {
    last_sync: string | null
    total_entries: number
    sync_in_progress?: boolean
    inProgress?: boolean
  }
}

interface VulnerabilityApiResponse<T> {
  data?: T
  error?: string
  message?: string
  meta?: {
    degraded?: boolean
    operation?: string
  }
}

export default function Vulnerabilities() {
  const { tenantGet, tenantPost } = useTenantFetch()
  const [stats, setStats] = useState<VulnerabilityStats | null>(null)
  const [cves, setCves] = useState<CVE[]>([])
  const [kevEntries, setKevEntries] = useState<CVE[]>([])
  const [topEpss, setTopEpss] = useState<CVE[]>([])
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [kevFilter, setKevFilter] = useState(false)
  const [page, setPage] = useState(1)
const [totalPages, setTotalPages] = useState(1)
const [error, setError] = useState<string | null>(null)
 const [catalogError, setCatalogError] = useState<string | null>(null)
 const [auxiliaryError, setAuxiliaryError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    try {
setLoading(true)
setError(null)
 setCatalogError(null)
 setAuxiliaryError(null)
      // Fetch stats
      const statsData = await tenantGet<VulnerabilityApiResponse<VulnerabilityStats>>('/api/v1/vulnerabilities/stats')
      assertNotDegraded(statsData)
      setStats(statsData.data ?? null)

      // Fetch vulnerabilities
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
        ...(severityFilter && { severity: severityFilter }),
        ...(kevFilter && { kev: 'true' }),
        ...(searchQuery && { search: searchQuery }),
      })

      const cvesData = await tenantGet<VulnerabilityApiResponse<CVE[]> & { pagination?: { total_pages?: number } }>(`/api/v1/vulnerabilities?${params}`)
      assertNotDegraded(cvesData)
      setCves(cvesData.data || [])
      setTotalPages(cvesData.pagination?.total_pages || 1)

 // Auxiliary context is independent from the catalog. One unavailable
 // feed must not hide CVEs that were loaded successfully.
 const auxiliary = await Promise.allSettled([
 fetchHealthy(tenantGet<VulnerabilityApiResponse<CVE[]>>('/api/v1/vulnerabilities/kev?limit=10')),
 fetchHealthy(tenantGet<VulnerabilityApiResponse<CVE[]>>('/api/v1/vulnerabilities/epss/top?limit=10')),
 fetchHealthy(tenantGet<VulnerabilityApiResponse<SyncStatus>>('/api/v1/vulnerabilities/sync/status')),
 ])

 const unavailable: string[] = []
 const [kevResult, epssResult, syncResult] = auxiliary

 if (kevResult.status === 'fulfilled') setKevEntries(kevResult.value.data || [])
 else unavailable.push('KEV')

 if (epssResult.status === 'fulfilled') setTopEpss(epssResult.value.data || [])
 else unavailable.push('EPSS')

 if (syncResult.status === 'fulfilled') setSyncStatus(syncResult.value.data ?? null)
 else unavailable.push('sync status')

 if (unavailable.length > 0) {
 const message = `Catalog loaded; auxiliary context unavailable: ${unavailable.join(', ')}`
 logger.error(message, auxiliary)
 setAuxiliaryError(message)
 }
} catch (error) {
logger.error('Failed to fetch vulnerability data:', error)
 const message = error instanceof Error ? error.message : 'Failed to load vulnerability data'
 setError(message)
 setCatalogError(message)
    } finally {
      setLoading(false)
    }
  }, [page, severityFilter, kevFilter, searchQuery, tenantGet])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const triggerSync = async (type: 'nvd' | 'epss' | 'kev') => {
    try {
      setError(null)
      await tenantPost(`/api/v1/vulnerabilities/sync/${type}`, {})
      // Refresh sync status after a delay
      setTimeout(() => {
        tenantGet<{ data: SyncStatus }>('/api/v1/vulnerabilities/sync/status')
          .then(data => setSyncStatus(data.data))
          .catch(error => {
            logger.error('Failed to refresh vulnerability sync status:', error)
            setError(error instanceof Error ? error.message : 'Failed to refresh sync status')
          })
      }, 2000)
    } catch (error) {
      logger.error(`Failed to trigger ${type} sync:`, error)
      setError(error instanceof Error ? error.message : `Failed to trigger ${type.toUpperCase()} sync`)
    }
  }

  const handleSearchChange = (value: string) => {
    setSearchQuery(value)
    setPage(1)
  }

  const handleSeverityChange = (value: string) => {
    setSeverityFilter(value)
    setPage(1)
  }

  const handleKevFilterToggle = () => {
    setKevFilter(current => !current)
    setPage(1)
  }

  const getEpssColor = (score: number | null) => {
    if (score === null) return 'var(--muted)'
    if (score >= 0.7) return 'var(--crit)'
    if (score >= 0.4) return 'var(--high)'
    if (score >= 0.1) return 'var(--med)'
    return 'var(--low)'
  }

  return (
    <MainLayout title="Vulnerability Management">
      <Head title="Vulnerabilities - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Vulnerability Management</h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              CVE catalog tracking with EPSS/KEV context; affected assets are matched from agent software inventory when available
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchData()}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                background: 'var(--surface-2)',
                color: 'var(--fg-2)',
                border: '1px solid var(--border)'
              }}
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              Refresh
            </button>
          </div>
        </div>

        {/* Stats Cards */}
{error && (
          <div
            className="rounded-lg px-4 py-3 text-sm"
            style={{
              background: 'var(--crit-bg)',
              border: '1px solid var(--crit)',
              color: 'var(--crit)'
            }}
          >
            {error}
          </div>
)}

 {auxiliaryError && !catalogError && (
 <div
 className={'rounded-lg px-4 py-3 text-sm'}
 style={{
 background: 'var(--warn-bg)',
 border: '1px solid var(--warn)',
 color: 'var(--warn)'
 }}
 >
 {auxiliaryError}
 </div>
 )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
          <StatCard
            title="Total CVEs"
            value={stats?.total_cves || 0}
            icon={Bug}
            color="primary"
          />
          <StatCard
            title="Critical"
            value={stats?.by_severity?.critical || 0}
            icon={AlertTriangle}
            color="critical"
          />
          <StatCard
            title="High"
            value={stats?.by_severity?.high || 0}
            icon={AlertCircle}
            color="high"
          />
          <StatCard
            title="In KEV"
            value={stats?.in_kev || 0}
            icon={Target}
            color="critical"
            subtitle="Known Exploited"
          />
          <StatCard
            title="High EPSS"
            value={stats?.high_epss || 0}
            icon={Zap}
            color="high"
            subtitle=">10% exploit probability"
          />
          <StatCard
            title="Last 7 Days"
            value={stats?.recent_7d || 0}
            icon={Calendar}
            color="primary"
            subtitle="New CVEs"
          />
        </div>

        {/* Sync Status */}
        <div
          className="rounded-xl p-4"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border)'
          }}
        >
          <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Data Sources</h3>
          <div className="flex flex-wrap gap-4">
            <SyncStatusCard
              name="NVD"
              lastSync={syncStatus?.nvd?.last_sync}
              inProgress={isSyncInProgress(syncStatus?.nvd)}
              count={syncStatus?.nvd?.total_cves}
              staleAfterHours={48}
              onSync={() => triggerSync('nvd')}
            />
            <SyncStatusCard
              name="EPSS"
              lastSync={syncStatus?.epss?.last_sync}
              inProgress={isSyncInProgress(syncStatus?.epss)}
              staleAfterHours={48}
              onSync={() => triggerSync('epss')}
            />
            <SyncStatusCard
              name="KEV"
              lastSync={syncStatus?.kev?.last_sync}
              inProgress={isSyncInProgress(syncStatus?.kev)}
              count={syncStatus?.kev?.total_entries}
              staleAfterHours={24}
              onSync={() => triggerSync('kev')}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main CVE List */}
          <div
            className="lg:col-span-2 rounded-xl"
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)'
            }}
          >
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Vulnerabilities</h2>
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                    Catalog and exploit-intel signals are separate from endpoint inventory evidence.
                  </p>
                </div>
              </div>

              {/* Filters */}
              <div className="flex flex-wrap gap-3">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                  <input
                    type="text"
                    placeholder="Search CVEs..."
                    value={searchQuery}
                    onChange={(e) => handleSearchChange(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 rounded-lg focus:outline-none focus:ring-2"
                    style={{
                      background: 'var(--surface-2)',
                      border: '1px solid var(--border)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <Select
                  value={severityFilter}
                  onValueChange={handleSeverityChange}
                  placeholder="All Severities"
                  className="px-3 py-2 rounded-lg focus:outline-none focus:ring-2"
                >
                  <SelectItem value="">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </Select>
                <button
                  onClick={handleKevFilterToggle}
                  className="px-3 py-2 rounded-lg transition-colors flex items-center gap-2"
                  style={{
                    background: kevFilter ? 'var(--crit-bg)' : 'var(--surface-2)',
                    border: kevFilter ? '1px solid var(--crit)' : '1px solid var(--border)',
                    color: kevFilter ? 'var(--crit)' : 'var(--fg-2)'
                  }}
                >
                  <Target className="h-4 w-4" />
                  KEV Only
                </button>
              </div>
            </div>

            {/* CVE List */}
            <div style={{ borderColor: 'var(--hairline)' }}>
              {loading ? (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2" />
                  Loading vulnerabilities...
                </div>
 ) : catalogError ? (
                <div className="p-8 text-center" style={{ color: 'var(--crit)' }}>
                  <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-80" />
                  <p>Vulnerability catalog unavailable</p>
                  <p className="text-sm mt-2" style={{ color: 'var(--muted)' }}>
 {catalogError}
                  </p>
                </div>
              ) : cves.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No CVEs found in the local vulnerability catalog for this query.</p>
                  <p className="text-sm mt-2" style={{ color: 'var(--subtle)' }}>
                    This does not prove the environment is vulnerability-free; it depends on NVD/EPSS/KEV sync and asset matching evidence.
                  </p>
                </div>
              ) : (
                cves.map((cve, idx) => (
                  <CVERow key={cve.id} cve={cve} isLast={idx === cves.length - 1} />
                ))
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div
                className="p-4 flex items-center justify-between"
                style={{ borderTop: '1px solid var(--border)' }}
              >
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 rounded disabled:opacity-50"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                >
                  Previous
                </button>
                <span style={{ color: 'var(--muted)' }}>
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1 rounded disabled:opacity-50"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                >
                  Next
                </button>
              </div>
            )}
          </div>

          {/* Side Panels */}
          <div className="space-y-6">
            {/* Top KEV Entries */}
            <div
              className="rounded-xl"
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)'
              }}
            >
              <div
                className="p-4 flex items-center justify-between"
                style={{ borderBottom: '1px solid var(--border)' }}
              >
                <div className="flex items-center gap-2">
                  <Target className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                  <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>Known Exploited</h3>
                </div>
                <span className="text-xs" style={{ color: 'var(--subtle)' }}>CISA KEV</span>
              </div>
              <div>
                {kevEntries.slice(0, 5).map((entry, idx) => (
                  <Link
                    key={entry.cve_id}
                    href={`/app/vulnerabilities/${entry.cve_id}`}
                    className="block p-3 transition-colors hover:brightness-110"
                    style={{
                      borderBottom: idx < 4 ? '1px solid var(--hairline)' : 'none',
                      background: 'transparent'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-mono" style={{ color: 'var(--emerald-400)' }}>{entry.cve_id}</span>
                      {entry.kev_due_date && (
                        <span className="text-xs" style={{ color: 'var(--crit)' }}>
                          Due: {formatDate(entry.kev_due_date)}
                        </span>
                      )}
                    </div>
                    <p className="text-xs mt-1 line-clamp-1" style={{ color: 'var(--muted)' }}>
                      {entry.description}
                    </p>
                  </Link>
                ))}
              </div>
            </div>

            {/* Top by EPSS */}
            <div
              className="rounded-xl"
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)'
              }}
            >
              <div
                className="p-4 flex items-center justify-between"
                style={{ borderBottom: '1px solid var(--border)' }}
              >
                <div className="flex items-center gap-2">
                  <Zap className="h-5 w-5" style={{ color: 'var(--high)' }} />
                  <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>Highest EPSS</h3>
                </div>
                <span className="text-xs" style={{ color: 'var(--subtle)' }}>Exploit Probability</span>
              </div>
              <div>
                {topEpss.slice(0, 5).map((cve, idx) => (
                  <Link
                    key={cve.cve_id}
                    href={`/app/vulnerabilities/${cve.cve_id}`}
                    className="block p-3 transition-colors"
                    style={{
                      borderBottom: idx < 4 ? '1px solid var(--hairline)' : 'none',
                      background: 'transparent'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-mono" style={{ color: 'var(--emerald-400)' }}>{cve.cve_id}</span>
                      <span
                        className="text-sm font-medium"
                        style={{ color: getEpssColor(cve.epss_score) }}
                      >
                        {cve.epss_score !== null ? `${(cve.epss_score * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                    <div
                      className="mt-1 h-1.5 rounded-full overflow-hidden"
                      style={{ background: 'var(--surface-3)' }}
                    >
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${(cve.epss_score || 0) * 100}%`,
                          background: getEpssColor(cve.epss_score)
                        }}
                      />
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

function assertNotDegraded<T extends { error?: string; message?: string; meta?: { degraded?: boolean; operation?: string } }>(payload: T) {
  if (payload.meta?.degraded || payload.error) {
    const operation = payload.meta?.operation ? ` (${payload.meta.operation})` : ''
    throw new Error(payload.message || `Vulnerability backend returned degraded data${operation}`)
  }
}

async function fetchHealthy<T extends { error?: string; message?: string; meta?: { degraded?: boolean; operation?: string } }>(request: Promise<T>) {
 const payload = await request
 assertNotDegraded(payload)
 return payload
}

function isSyncInProgress(source: { sync_in_progress?: boolean; inProgress?: boolean } | null | undefined) {
  return Boolean(source?.sync_in_progress || source?.inProgress)
}

interface StatCardProps {
  title: string
  value: number
  icon: React.ElementType
  color: 'primary' | 'critical' | 'high'
  subtitle?: string
}

function StatCard({ title, value, icon: Icon, color, subtitle }: StatCardProps) {
  const colorStyles = {
    primary: {
      bg: 'var(--emerald-glow)',
      fg: 'var(--emerald-400)'
    },
    critical: {
      bg: 'var(--crit-bg)',
      fg: 'var(--crit)'
    },
    high: {
      bg: 'var(--high-bg)',
      fg: 'var(--high)'
    },
  }

  const styles = colorStyles[color]

  return (
    <div
      className="rounded-xl p-4"
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)'
      }}
    >
      <div className="flex items-center justify-between">
        <div
          className="p-2 rounded-lg"
          style={{ background: styles.bg, color: styles.fg }}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-3">
        <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}</span>
        <p className="text-sm mt-0.5" style={{ color: 'var(--muted)' }}>{title}</p>
        {subtitle && (
          <p className="text-xs" style={{ color: 'var(--subtle)' }}>{subtitle}</p>
        )}
      </div>
    </div>
  )
}

interface SyncStatusCardProps {
  name: string
  lastSync: string | null | undefined
  inProgress?: boolean
  count?: number
  staleAfterHours: number
  onSync: () => void
}

function SyncStatusCard({ name, lastSync, inProgress, count, staleAfterHours, onSync }: SyncStatusCardProps) {
  const freshness = getSyncFreshness(lastSync, staleAfterHours)

  return (
    <div
      className="flex items-center gap-3 px-4 py-2 rounded-lg"
      style={{
        background: 'var(--surface-2)',
        border: freshness.state === 'fresh' ? '1px solid transparent' : '1px solid var(--high)'
      }}
    >
      <div>
        <div className="flex items-center gap-2">
          <span className="font-medium" style={{ color: 'var(--fg)' }}>{name}</span>
          {count !== undefined && (
            <span className="text-xs" style={{ color: 'var(--muted)' }}>({count.toLocaleString()})</span>
          )}
        </div>
        <div className="text-xs" style={{ color: 'var(--muted)' }}>
          {lastSync ? `Last sync: ${formatDate(lastSync)}` : 'Never synced'}
        </div>
        <div
          className="text-xs"
          style={{ color: freshness.state === 'fresh' ? 'var(--low)' : 'var(--high)' }}
        >
          {inProgress ? 'Sync in progress' : freshness.label}
        </div>
      </div>
      <button
        onClick={onSync}
        disabled={inProgress}
        className="p-1.5 rounded transition-colors disabled:opacity-50 hover:brightness-110"
        style={{ background: 'var(--surface-3)' }}
      >
        <RefreshCw className={cn("h-4 w-4", inProgress && "animate-spin")} style={{ color: 'var(--muted)' }} />
      </button>
    </div>
  )
}

function getSyncFreshness(lastSync: string | null | undefined, staleAfterHours: number) {
  if (!lastSync) {
    return { state: 'missing' as const, label: 'Freshness unknown' }
  }

  const syncedAt = new Date(lastSync).getTime()
  if (Number.isNaN(syncedAt)) {
    return { state: 'missing' as const, label: 'Freshness unknown' }
  }

  const ageMs = Date.now() - syncedAt
  if (ageMs < 0) {
    return { state: 'missing' as const, label: 'Freshness clock skew' }
  }

  const ageHours = ageMs / (1000 * 60 * 60)
  const relativeAge = formatSyncAge(ageMs)

  if (ageHours > staleAfterHours) {
    return { state: 'stale' as const, label: `Stale: ${relativeAge} old` }
  }

  return { state: 'fresh' as const, label: `Fresh: ${relativeAge} old` }
}

function formatSyncAge(ageMs: number) {
  const ageMinutes = Math.floor(ageMs / (1000 * 60))
  if (ageMinutes < 1) return 'under 1m'
  if (ageMinutes < 60) return `${ageMinutes}m`

  const ageHours = Math.floor(ageMinutes / 60)
  if (ageHours < 48) return `${ageHours}h`

  const ageDays = Math.floor(ageHours / 24)
  return `${ageDays}d`
}

function CVERow({ cve, isLast }: { cve: CVE; isLast?: boolean }) {
  const getSeverityBadgeClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'badge-sentinel badge-sentinel-critical'
      case 'high':
        return 'badge-sentinel badge-sentinel-high'
      case 'medium':
        return 'badge-sentinel badge-sentinel-medium'
      case 'low':
        return 'badge-sentinel badge-sentinel-low'
      default:
        return 'badge-sentinel badge-sentinel-default'
    }
  }

  const getCvssBadgeClass = (score: number | null) => {
    if (score === null) return 'badge-sentinel badge-sentinel-default'
    if (score >= 9.0) return 'badge-sentinel badge-sentinel-critical'
    if (score >= 7.0) return 'badge-sentinel badge-sentinel-high'
    if (score >= 4.0) return 'badge-sentinel badge-sentinel-medium'
    return 'badge-sentinel badge-sentinel-low'
  }

  return (
    <Link
      href={`/app/vulnerabilities/${cve.cve_id}`}
      className="block p-4 transition-colors"
      style={{
        borderBottom: isLast ? 'none' : '1px solid var(--hairline)',
        background: 'transparent'
      }}
      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
    >
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm" style={{ color: 'var(--emerald-400)' }}>{cve.cve_id}</span>
            <span className={getSeverityBadgeClass(cve.calculated_severity)}>
              {cve.calculated_severity?.toUpperCase() || 'UNKNOWN'}
            </span>
            {cve.in_kev && (
              <span className="badge-sentinel badge-sentinel-critical flex items-center gap-1">
                <Target className="h-3 w-3" />
                KEV
              </span>
            )}
            {cve.cvss_v3_score !== null && (
              <span className={getCvssBadgeClass(cve.cvss_v3_score)}>
                CVSS: {cve.cvss_v3_score.toFixed(1)}
              </span>
            )}
            {cve.epss_score !== null && (
              <span className="badge-sentinel badge-sentinel-default">
                EPSS: {(cve.epss_score * 100).toFixed(1)}%
              </span>
            )}
            <span className="badge-sentinel badge-sentinel-default flex items-center gap-1" title="CVE catalog record from synchronized vulnerability feeds">
              <Database className="h-3 w-3" />
              Catalog
            </span>
            <AssetEvidenceBadge evidence={cve.asset_evidence} />
          </div>
          <p className="text-sm mt-1 line-clamp-2" style={{ color: 'var(--fg-2)' }}>
            {cve.description}
          </p>
          <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--subtle)' }}>
            <span className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              {formatDate(cve.published_at)}
            </span>
            {cve.weaknesses && cve.weaknesses.length > 0 && (
              <span>CWE: {cve.weaknesses.slice(0, 2).join(', ')}</span>
            )}
          </div>
        </div>
        <ChevronRight className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
      </div>
    </Link>
  )
}

function AssetEvidenceBadge({ evidence }: { evidence?: CVE['asset_evidence'] }) {
  if (!evidence || evidence.status === 'unscoped' || evidence.affected_asset_count === null) {
    return (
      <span
        className="badge-sentinel badge-sentinel-default flex items-center gap-1"
        title="Asset evidence is unavailable without tenant-scoped inventory context"
      >
        <Server className="h-3 w-3" />
        Inventory unknown
      </span>
    )
  }

  if (evidence.status === 'matched' && evidence.affected_asset_count > 0) {
    return (
      <span
        className="badge-sentinel badge-sentinel-high flex items-center gap-1"
        title="Persisted match from agent-reported software inventory"
      >
        <Server className="h-3 w-3" />
        Inventory: {evidence.affected_asset_count} asset{evidence.affected_asset_count === 1 ? '' : 's'}
      </span>
    )
  }

  return (
    <span
      className="badge-sentinel badge-sentinel-default flex items-center gap-1"
      title="No active affected asset match is currently persisted for this tenant"
    >
      <Server className="h-3 w-3" />
      No inventory match
    </span>
  )
}
