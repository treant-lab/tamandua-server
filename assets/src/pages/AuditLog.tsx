import { useState, useEffect, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Search,
  Filter,
  Clock,
  User,
  Shield,
  Settings,
  LogIn,
  LogOut,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  FileText,
  Crosshair,
  Key,
  Globe,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { ExportDropdown } from '@/components/ExportDropdown'
import { Select, SelectItem } from '@/components/ui/baseui'
import axios from 'axios'
import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

interface AuditEntry {
  id: string
  timestamp: string
  user: string
  action: string
  action_type: AuditActionType
  target: string
  details: string
  ip_address: string
}

type AuditActionType =
  | 'login'
  | 'logout'
  | 'config_change'
  | 'response_action'
  | 'user_action'
  | 'alert_action'
  | 'agent_action'
  | 'rule_change'
  | 'api_access'

interface AuditLogPageProps {
  entries?: AuditEntry[]
  pagination?: {
    page: number
    per_page: number
    total: number
    total_pages: number
  }
}

// ============================================================================
// Constants
// ============================================================================

const ACTION_TYPE_OPTIONS: { value: AuditActionType | 'all'; label: string }[] = [
  { value: 'all', label: 'All Actions' },
  { value: 'login', label: 'Login' },
  { value: 'logout', label: 'Logout' },
  { value: 'config_change', label: 'Config Change' },
  { value: 'response_action', label: 'Response Action' },
  { value: 'user_action', label: 'User Action' },
  { value: 'alert_action', label: 'Alert Action' },
  { value: 'agent_action', label: 'Agent Action' },
  { value: 'rule_change', label: 'Rule Change' },
  { value: 'api_access', label: 'API Access' },
]

// Action type styles using design tokens
const ACTION_TYPE_STYLES: Record<AuditActionType, { icon: React.ElementType; colorVar: string; bgVar: string }> = {
  login: { icon: LogIn, colorVar: 'var(--emerald-400)', bgVar: 'var(--emerald-glow)' },
  logout: { icon: LogOut, colorVar: 'var(--muted)', bgVar: 'var(--surface-2)' },
  config_change: { icon: Settings, colorVar: 'var(--high)', bgVar: 'var(--high-bg)' },
  response_action: { icon: Crosshair, colorVar: 'var(--crit)', bgVar: 'var(--crit-bg)' },
  user_action: { icon: User, colorVar: 'var(--med)', bgVar: 'var(--med-bg)' },
  alert_action: { icon: AlertTriangle, colorVar: 'var(--high)', bgVar: 'var(--high-bg)' },
  agent_action: { icon: Shield, colorVar: 'var(--sol-magenta)', bgVar: 'rgba(217, 70, 239, 0.12)' },
  rule_change: { icon: FileText, colorVar: 'var(--sol-cyan)', bgVar: 'rgba(25, 251, 155, 0.12)' },
  api_access: { icon: Key, colorVar: 'var(--high)', bgVar: 'var(--high-bg)' },
}

// ============================================================================
// Component
// ============================================================================

export default function AuditLog({ entries: initialEntries, pagination: initialPagination }: AuditLogPageProps) {
  const [entries, setEntries] = useState<AuditEntry[]>(initialEntries || [])
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [actionTypeFilter, setActionTypeFilter] = useState<string>('all')
  const [userFilter, setUserFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [page, setPage] = useState(initialPagination?.page || 1)
  const [perPage] = useState(initialPagination?.per_page || 50)
  const [total, setTotal] = useState(initialPagination?.total || 0)
  const [totalPages, setTotalPages] = useState(initialPagination?.total_pages || 1)

  // Unique users for filter dropdown
  const uniqueUsers = Array.from(new Set(entries.map(e => e.user))).filter(Boolean).sort()

  const fetchAuditLogs = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('per_page', String(perPage))
      if (searchQuery) params.set('search', searchQuery)
      if (actionTypeFilter !== 'all') params.set('action_type', actionTypeFilter)
      if (userFilter) params.set('user', userFilter)
      if (dateFrom) params.set('date_from', dateFrom)
      if (dateTo) params.set('date_to', dateTo)

      const response = await axios.get(`/api/v1/audit/logs?${params.toString()}`)
      if (response.data?.data) {
        setEntries(response.data.data)
      }
      if (response.data?.pagination) {
        const pg = response.data.pagination
        setTotal(pg.total || 0)
        setTotalPages(pg.total_pages || 1)
        setPage(pg.page || 1)
      }
    } catch (error) {
      logger.error('Failed to fetch audit logs:', error)
    } finally {
      setLoading(false)
    }
  }, [page, perPage, searchQuery, actionTypeFilter, userFilter, dateFrom, dateTo])

  // Fetch on mount and when filters change
  useEffect(() => {
    fetchAuditLogs()
  }, [fetchAuditLogs])

  // Client-side filtering (in case server-side filtering isn't implemented yet)
  const filteredEntries = entries.filter(entry => {
    if (actionTypeFilter !== 'all' && entry.action_type !== actionTypeFilter) return false
    if (userFilter && entry.user !== userFilter) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      return (
        entry.action.toLowerCase().includes(q) ||
        entry.target.toLowerCase().includes(q) ||
        entry.details.toLowerCase().includes(q) ||
        entry.user.toLowerCase().includes(q) ||
        entry.ip_address.toLowerCase().includes(q)
      )
    }
    return true
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(1)
    fetchAuditLogs()
  }

  const goToPage = (newPage: number) => {
    if (newPage < 1 || newPage > totalPages) return
    setPage(newPage)
  }

  return (
    <MainLayout title="Audit Log">
      <Head title="Audit Log - Tamandua EDR" />

      <div className="space-y-6">
        {/* Filters */}
        <div className="card-sentinel">
          <form onSubmit={handleSearch} className="flex flex-wrap items-end gap-4">
            {/* Search */}
            <div className="flex-1 min-w-[200px]">
              <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search audit entries..."
                  className="input-sentinel w-full pl-10"
                />
              </div>
            </div>

            {/* Action Type */}
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Action Type</label>
              <Select
                value={actionTypeFilter}
                onValueChange={(value) => { setActionTypeFilter(value); setPage(1) }}
                className="input-sentinel"
              >
                {ACTION_TYPE_OPTIONS.map(opt => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </Select>
            </div>

            {/* User */}
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>User</label>
              <Select
                value={userFilter}
                onValueChange={(value) => { setUserFilter(value); setPage(1) }}
                placeholder="All Users"
                className="input-sentinel"
              >
                <SelectItem value="">All Users</SelectItem>
                {uniqueUsers.map(user => (
                  <SelectItem key={user} value={user}>{user}</SelectItem>
                ))}
              </Select>
            </div>

            {/* Date From */}
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>From</label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => { setDateFrom(e.target.value); setPage(1) }}
                className="input-sentinel"
              />
            </div>

            {/* Date To */}
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>To</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => { setDateTo(e.target.value); setPage(1) }}
                className="input-sentinel"
              />
            </div>

            {/* Search button */}
            <button
              type="submit"
              className="btn-sentinel btn-sentinel-primary"
            >
              <Filter className="h-4 w-4" />
              Apply
            </button>

            {/* Refresh */}
            <button
              type="button"
              onClick={fetchAuditLogs}
              disabled={loading}
              className="btn-sentinel btn-sentinel-secondary"
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            </button>

            {/* Export */}
            <ExportDropdown
              getData={() => filteredEntries.map(e => ({
                id: e.id,
                timestamp: e.timestamp,
                user: e.user,
                action: e.action,
                action_type: e.action_type,
                target: e.target,
                details: e.details,
                ip_address: e.ip_address,
              }))}
              filenameBase="tamandua-audit-log"
              disabled={filteredEntries.length === 0}
            />
          </form>
        </div>

        {/* Audit Log Table */}
        <div className="card-sentinel" style={{ padding: 0 }}>
          <div
            className="p-4 flex items-center justify-between"
            style={{ borderBottom: '1px solid var(--hairline)' }}
          >
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Audit Entries</h2>
              <span className="text-sm" style={{ color: 'var(--muted)' }}>
                {total > 0 ? `${total} total entries` : `${filteredEntries.length} entries`}
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <th className="text-left p-4 text-sm font-medium w-44" style={{ color: 'var(--muted)' }}>Timestamp</th>
                  <th className="text-left p-4 text-sm font-medium w-36" style={{ color: 'var(--muted)' }}>User</th>
                  <th className="text-left p-4 text-sm font-medium w-36" style={{ color: 'var(--muted)' }}>Action</th>
                  <th className="text-left p-4 text-sm font-medium w-48" style={{ color: 'var(--muted)' }}>Target</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Details</th>
                  <th className="text-left p-4 text-sm font-medium w-36" style={{ color: 'var(--muted)' }}>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={6} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                      <RefreshCw className="h-12 w-12 mx-auto mb-4 opacity-50 animate-spin" />
                      <p className="text-lg">Loading audit entries...</p>
                    </td>
                  </tr>
                ) : filteredEntries.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p className="text-lg">No audit entries found</p>
                      <p className="text-sm">
                        {entries.length === 0
                          ? 'Audit logging will capture user actions, config changes, and response executions.'
                          : 'Try adjusting your filters.'}
                      </p>
                    </td>
                  </tr>
                ) : (
                  filteredEntries.map((entry) => {
                    const style = ACTION_TYPE_STYLES[entry.action_type] || ACTION_TYPE_STYLES.user_action
                    const Icon = style.icon
                    return (
                      <tr
                        key={entry.id}
                        className="transition-colors"
                        style={{
                          borderBottom: '1px solid var(--hairline)',
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = 'var(--surface-2)'
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'transparent'
                        }}
                      >
                        <td className="p-4">
                          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
                            <Clock className="h-3 w-3 flex-shrink-0" />
                            <span className="whitespace-nowrap">{formatDate(entry.timestamp)}</span>
                          </div>
                        </td>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <User className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
                            <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{entry.user}</span>
                          </div>
                        </td>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <div
                              className="p-1.5 rounded"
                              style={{
                                background: style.bgVar,
                                color: style.colorVar,
                              }}
                            >
                              <Icon className="h-3.5 w-3.5" />
                            </div>
                            <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{formatActionName(entry.action)}</span>
                          </div>
                        </td>
                        <td className="p-4">
                          <span
                            className="text-sm font-mono truncate block max-w-[200px]"
                            style={{ color: 'var(--fg-2)' }}
                            title={entry.target}
                          >
                            {entry.target}
                          </span>
                        </td>
                        <td className="p-4">
                          <span
                            className="text-sm truncate block max-w-[350px]"
                            style={{ color: 'var(--muted)' }}
                            title={entry.details}
                          >
                            {entry.details}
                          </span>
                        </td>
                        <td className="p-4">
                          <div className="flex items-center gap-1.5 text-sm" style={{ color: 'var(--muted)' }}>
                            <Globe className="h-3 w-3 flex-shrink-0" />
                            <span className="font-mono">{entry.ip_address}</span>
                          </div>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div
              className="flex items-center justify-between p-4"
              style={{ borderTop: '1px solid var(--hairline)' }}
            >
              <span className="text-sm" style={{ color: 'var(--muted)' }}>
                Page {page} of {totalPages} ({total} total entries)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => goToPage(page - 1)}
                  disabled={page <= 1}
                  className={cn(
                    'btn-sentinel btn-sentinel-sm',
                    page <= 1 ? 'btn-sentinel-ghost opacity-50 cursor-not-allowed' : 'btn-sentinel-secondary'
                  )}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Previous
                </button>

                {/* Page numbers */}
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number
                  if (totalPages <= 5) {
                    pageNum = i + 1
                  } else if (page <= 3) {
                    pageNum = i + 1
                  } else if (page >= totalPages - 2) {
                    pageNum = totalPages - 4 + i
                  } else {
                    pageNum = page - 2 + i
                  }
                  return (
                    <button
                      key={pageNum}
                      onClick={() => goToPage(pageNum)}
                      className={cn(
                        'btn-sentinel btn-sentinel-sm btn-sentinel-icon',
                        page === pageNum ? 'btn-sentinel-primary' : 'btn-sentinel-secondary'
                      )}
                    >
                      {pageNum}
                    </button>
                  )
                })}

                <button
                  onClick={() => goToPage(page + 1)}
                  disabled={page >= totalPages}
                  className={cn(
                    'btn-sentinel btn-sentinel-sm',
                    page >= totalPages ? 'btn-sentinel-ghost opacity-50 cursor-not-allowed' : 'btn-sentinel-secondary'
                  )}
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ============================================================================
// Helpers
// ============================================================================

function formatActionName(action: string): string {
  return action
    .replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase())
}
