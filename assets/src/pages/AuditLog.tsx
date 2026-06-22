import { useState, useEffect, useCallback, useMemo } from 'react'
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
  RefreshCw,
  FileText,
  Crosshair,
  Key,
  Globe,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { ExportDropdown } from '@/components/ExportDropdown'
import {
  Select,
  SelectItem,
  DataTable,
  DataTableEmptyState,
  type TamanduaColumnDef,
} from '@/components/ui/baseui'
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
  const [perPage, setPerPage] = useState(initialPagination?.per_page || 50)
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

  const columns = useMemo<TamanduaColumnDef<AuditEntry>[]>(
    () => [
      {
        id: 'timestamp',
        header: 'Timestamp',
        accessorKey: 'timestamp',
        meta: { width: 200, truncate: true },
        cell: ({ row }) => (
          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
            <Clock className="h-3 w-3 flex-shrink-0" />
            <span className="whitespace-nowrap">{formatDate(row.original.timestamp)}</span>
          </div>
        ),
      },
      {
        id: 'user',
        header: 'User',
        accessorKey: 'user',
        meta: { width: 160, truncate: true },
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <User className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
            <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>
              {row.original.user}
            </span>
          </div>
        ),
      },
      {
        id: 'action',
        header: 'Action',
        accessorKey: 'action',
        meta: { width: 200, truncate: true },
        cell: ({ row }) => {
          const style = ACTION_TYPE_STYLES[row.original.action_type] || ACTION_TYPE_STYLES.user_action
          const Icon = style.icon
          return (
            <div className="flex items-center gap-2">
              <div
                className="p-1.5 rounded"
                style={{ background: style.bgVar, color: style.colorVar }}
              >
                <Icon className="h-3.5 w-3.5" />
              </div>
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>
                {formatActionName(row.original.action)}
              </span>
            </div>
          )
        },
      },
      {
        id: 'target',
        header: 'Target',
        accessorKey: 'target',
        meta: { width: 220, truncate: true },
        cell: ({ row }) => (
          <span
            className="text-sm font-mono truncate block"
            style={{ color: 'var(--fg-2)' }}
            title={row.original.target}
          >
            {row.original.target}
          </span>
        ),
      },
      {
        id: 'details',
        header: 'Details',
        accessorKey: 'details',
        meta: { truncate: true, maxWidth: 420 },
        cell: ({ row }) => (
          <span
            className="text-sm truncate block"
            style={{ color: 'var(--muted)' }}
            title={row.original.details}
          >
            {row.original.details}
          </span>
        ),
      },
      {
        id: 'ip_address',
        header: 'IP Address',
        accessorKey: 'ip_address',
        meta: { width: 160, truncate: true },
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5 text-sm" style={{ color: 'var(--muted)' }}>
            <Globe className="h-3 w-3 flex-shrink-0" />
            <span className="font-mono">{row.original.ip_address}</span>
          </div>
        ),
      },
    ],
    [],
  )

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

          <DataTable<AuditEntry>
            data={filteredEntries}
            columns={columns}
            getRowId={(row) => row.id}
            ariaLabel="Audit log entries"
            density="comfortable"
            loadingState={loading ? 'loading' : 'idle'}
            manualPagination
            pageCount={totalPages}
            pagination={{ pageIndex: Math.max(0, page - 1), pageSize: perPage }}
            onPaginationChange={({ pageIndex, pageSize }) => {
              if (pageSize !== perPage) {
                setPerPage(pageSize)
                setPage(1)
              } else {
                setPage(pageIndex + 1)
              }
            }}
            totalRows={total}
            pageSizeOptions={[25, 50, 100, 250]}
            emptyState={
              <DataTableEmptyState
                title="No audit entries found"
                description={
                  entries.length === 0
                    ? 'Audit logging will capture user actions, config changes, and response executions.'
                    : 'Try adjusting your filters.'
                }
              />
            }
          />
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
