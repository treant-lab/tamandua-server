import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  AlertTriangle, Clock, Shield, Filter, Search, Bell, CheckSquare, Square,
  ChevronDown, ChevronUp, X, Plus, Save, Download, Settings, Users,
  ExternalLink, History, Layers, Tag, Calendar, SlidersHorizontal,
  Ban, Eye, EyeOff, RefreshCw, FileJson, FileSpreadsheet, FileText,
  Trash2, CheckCircle, XCircle, AlertCircle, UserPlus, FolderPlus
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useAlertChannel } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import type { Alert, User } from '@/types'
import { Select, SelectItem, Menu, MenuItem, Popover } from '@/components/ui/baseui'

// ===========================================================================
// Types
// ===========================================================================

interface AlertsPageProps {
  alerts: Alert[]
  users?: User[]
  investigations?: { id: string; title: string }[]
}

interface ExclusionRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  rule_type: 'whitelist' | 'suppress' | 'tune'
  criteria: Record<string, unknown>
  hash_patterns: string[]
  path_patterns: string[]
  expires_at?: string
  match_count: number
}

interface FilterPreset {
  id: string
  name: string
  filters: Record<string, unknown>
}

interface BulkAction {
  action: string
  label: string
  icon: React.ReactNode
  requiresInput?: boolean
  inputType?: 'user' | 'investigation' | 'text' | 'status'
}

// ===========================================================================
// Constants
// ===========================================================================

const BULK_ACTIONS: BulkAction[] = [
  { action: 'acknowledge', label: 'Acknowledge', icon: <CheckCircle className="h-4 w-4" /> },
  { action: 'resolve', label: 'Resolve', icon: <CheckSquare className="h-4 w-4" />, requiresInput: true, inputType: 'text' },
  { action: 'false_positive', label: 'Mark False Positive', icon: <XCircle className="h-4 w-4" />, requiresInput: true, inputType: 'text' },
  { action: 'assign', label: 'Assign to Analyst', icon: <UserPlus className="h-4 w-4" />, requiresInput: true, inputType: 'user' },
  { action: 'add_to_investigation', label: 'Add to Investigation', icon: <FolderPlus className="h-4 w-4" />, requiresInput: true, inputType: 'investigation' },
  { action: 'close', label: 'Close', icon: <X className="h-4 w-4" /> },
]

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const STATUS_OPTIONS = ['new', 'open', 'investigating', 'resolved', 'false_positive']
const PAGE_SIZE_OPTIONS = [25, 50, 100] as const

function getCsrfHeaders(): Record<string, string> {
  const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
  return token ? { 'X-CSRF-Token': token } : {}
}

function apiRequest(url: string, options: RequestInit = {}) {
  return fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      Accept: 'application/json',
      ...getCsrfHeaders(),
      ...((options.headers || {}) as Record<string, string>),
    },
  })
}

// ===========================================================================
// Helper function for severity badge classes
// ===========================================================================

function getSeverityBadgeClass(severity: string): string {
  switch (safeSeverity(severity)) {
    case 'critical': return 'badge-sentinel badge-sentinel-critical'
    case 'high': return 'badge-sentinel badge-sentinel-high'
    case 'medium': return 'badge-sentinel badge-sentinel-medium'
    case 'low': return 'badge-sentinel badge-sentinel-low'
    case 'info': return 'badge-sentinel badge-sentinel-info'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function safeSeverity(severity: unknown): Alert['severity'] | 'info' {
  const value = String(severity || '').toLowerCase()
  return ['critical', 'high', 'medium', 'low', 'info'].includes(value)
    ? (value as Alert['severity'] | 'info')
    : 'info'
}

function safeStatus(status: unknown): Alert['status'] {
  const value = String(status || '').toLowerCase()
  return ['new', 'open', 'investigating', 'resolved', 'false_positive'].includes(value)
    ? (value as Alert['status'])
    : 'new'
}

function safeStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(item => String(item)).filter(Boolean) : []
}

// ===========================================================================
// Main Component
// ===========================================================================

export default function Alerts({ alerts: initialAlerts, users = [], investigations = [] }: AlertsPageProps) {
  // State
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [assignedFilter, setAssignedFilter] = useState<string>('')
  const [threatScoreMin, setThreatScoreMin] = useState<string>('')
  const [threatScoreMax, setThreatScoreMax] = useState<string>('')
  const [mitreTechniques, setMitreTechniques] = useState<string[]>([])

  // Selection state
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [selectAll, setSelectAll] = useState(false)

  // UI State
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false)
  const [showTuningPanel, setShowTuningPanel] = useState(false)
  const [sortBy, setSortBy] = useState<'created_at' | 'severity' | 'threat_score'>('created_at')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState<number>(50)

  // Loading/Error states
  const [loading, setLoading] = useState(false)
  const [bulkActionLoading, setBulkActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Data
  const [filterPresets, setFilterPresets] = useState<FilterPreset[]>([])
  const [exclusionRules, setExclusionRules] = useState<ExclusionRule[]>([])
  const [assignableUsers, setAssignableUsers] = useState<User[]>(users)

  // WebSocket
  const { connectionState, alerts: wsAlerts, acknowledgeAlert } = useAlertChannel()

  // Track which alert IDs arrived via WebSocket for "new alert" highlight
  const [recentWsAlertIds, setRecentWsAlertIds] = useState<Set<string>>(new Set())
  const wsAlertTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  // When new WebSocket alerts arrive, mark them as recent and auto-clear after 5s
  useEffect(() => {
    if (wsAlerts.length === 0) return
    const newIds = wsAlerts.map(a => a.id)
    setRecentWsAlertIds(prev => {
      const next = new Set(prev)
      newIds.forEach(id => next.add(id))
      return next
    })
    // Auto-clear highlight after 5 seconds per alert
    newIds.forEach(id => {
      // Clear existing timer for this ID if any
      const existing = wsAlertTimers.current.get(id)
      if (existing) clearTimeout(existing)
      const timer = setTimeout(() => {
        setRecentWsAlertIds(prev => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
        wsAlertTimers.current.delete(id)
      }, 5000)
      wsAlertTimers.current.set(id, timer)
    })
  }, [wsAlerts])

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      wsAlertTimers.current.forEach(timer => clearTimeout(timer))
    }
  }, [])

  // Merge: use WS alerts to update/add to the prop-based alerts
  const allAlerts = useMemo(() => {
    if (wsAlerts.length === 0) return initialAlerts || []
    const alertMap = new Map((initialAlerts || []).map(a => [a.id, a]))
    wsAlerts.forEach(a => alertMap.set(a.id, { ...alertMap.get(a.id), ...a } as Alert))
    return Array.from(alertMap.values()).sort((a, b) => {
      const timeA = new Date((a as Record<string, unknown>).createdAt as string || (a as Record<string, unknown>).created_at as string || 0).getTime()
      const timeB = new Date((b as Record<string, unknown>).createdAt as string || (b as Record<string, unknown>).created_at as string || 0).getTime()
      return timeB - timeA
    })
  }, [initialAlerts, wsAlerts])

  // Mutable setter for local optimistic updates (bulk actions)
  const [localOverrides, setLocalOverrides] = useState<Map<string, Partial<Alert>>>(new Map())

  // Final merged alerts with local optimistic overrides applied
  const effectiveAlerts = useMemo(() => {
    if (localOverrides.size === 0) return allAlerts
    return allAlerts.map(a => {
      const override = localOverrides.get(a.id)
      return override ? { ...a, ...override } : a
    })
  }, [allAlerts, localOverrides])

  // Load initial data
  useEffect(() => {
    loadFilterPresets()
    loadExclusionRules()
    loadAssignableUsers()
  }, [])

  // ===========================================================================
  // Data Loading
  // ===========================================================================

  const loadFilterPresets = async () => {
    try {
      const res = await apiRequest('/api/v1/alerts/filter-presets')
      if (res.ok) {
        const data = await res.json()
        setFilterPresets(data.data || [])
      }
    } catch (e) {
      logger.error('Failed to load filter presets:', e)
    }
  }

  const loadExclusionRules = async () => {
    try {
      const res = await apiRequest('/api/v1/alerts/exclusions')
      if (res.ok) {
        const data = await res.json()
        setExclusionRules(data.data || [])
      }
    } catch (e) {
      logger.error('Failed to load exclusion rules:', e)
    }
  }

  const loadAssignableUsers = async () => {
    try {
      const res = await apiRequest('/api/v1/alerts/assignable-users')
      if (res.ok) {
        const data = await res.json()
        setAssignableUsers(data.data || [])
      }
    } catch (e) {
      logger.error('Failed to load assignable users:', e)
    }
  }

  // ===========================================================================
  // Filtering
  // ===========================================================================

  const filteredAlerts = useMemo(() => {
    let result = effectiveAlerts.filter(alert => {
      // Severity filter
      const alertSeverity = safeSeverity(alert.severity)
      const alertStatus = safeStatus(alert.status)
      const alertMitreTechniques = safeStringArray(alert.mitreTechniques)

      if (severityFilter.length > 0 && !severityFilter.includes(alertSeverity)) return false

      // Status filter
      if (statusFilter.length > 0 && !statusFilter.includes(alertStatus)) return false

      // Assigned filter
      if (assignedFilter === 'unassigned' && alert.assignedToId) return false
      if (assignedFilter && assignedFilter !== 'unassigned') {
        if (alert.assignedToId !== assignedFilter) return false
      }

      // Search
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        const matches = String(alert.title || '').toLowerCase().includes(query) ||
          String(alert.description || '').toLowerCase().includes(query) ||
          alertMitreTechniques.some(t => t.toLowerCase().includes(query))
        if (!matches) return false
      }

      // Date range
      if (dateFrom) {
        const alertDate = new Date(alert.createdAt)
        const fromDate = new Date(dateFrom)
        if (alertDate < fromDate) return false
      }
      if (dateTo) {
        const alertDate = new Date(alert.createdAt)
        const toDate = new Date(dateTo)
        toDate.setDate(toDate.getDate() + 1)
        if (alertDate >= toDate) return false
      }

      // Threat score
      if (threatScoreMin && alert.threatScore < parseFloat(threatScoreMin)) return false
      if (threatScoreMax && alert.threatScore > parseFloat(threatScoreMax)) return false

      // MITRE techniques
      if (mitreTechniques.length > 0) {
        const hasMatch = mitreTechniques.some(t =>
          alertMitreTechniques.includes(t)
        )
        if (!hasMatch) return false
      }

      return true
    })

    // Sort
    result.sort((a, b) => {
      let comparison = 0
      switch (sortBy) {
        case 'severity':
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
          comparison = (severityOrder[safeSeverity(a.severity) as keyof typeof severityOrder] || 0) - (severityOrder[safeSeverity(b.severity) as keyof typeof severityOrder] || 0)
          break
        case 'threat_score':
          comparison = (a.threatScore || 0) - (b.threatScore || 0)
          break
        case 'created_at':
        default:
          comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      }
      return sortOrder === 'desc' ? -comparison : comparison
    })

    return result
  }, [effectiveAlerts, severityFilter, statusFilter, searchQuery, dateFrom, dateTo,
      threatScoreMin, threatScoreMax, mitreTechniques, assignedFilter, sortBy, sortOrder])

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [severityFilter, statusFilter, searchQuery, dateFrom, dateTo, threatScoreMin, threatScoreMax, mitreTechniques, assignedFilter])

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize))
  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredAlerts.slice(start, start + pageSize)
  }, [filteredAlerts, currentPage, pageSize])

  // ===========================================================================
  // Selection
  // ===========================================================================

  const toggleSelectAll = useCallback(() => {
    if (selectAll) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(filteredAlerts.map(a => a.id)))
    }
    setSelectAll(!selectAll)
  }, [selectAll, filteredAlerts])

  const toggleSelectAlert = useCallback((alertId: string) => {
    setSelectedAlerts(prev => {
      const next = new Set(prev)
      if (next.has(alertId)) {
        next.delete(alertId)
      } else {
        next.add(alertId)
      }
      return next
    })
  }, [])

  // Update selectAll state when selection changes
  useEffect(() => {
    setSelectAll(selectedAlerts.size === filteredAlerts.length && filteredAlerts.length > 0)
  }, [selectedAlerts.size, filteredAlerts.length])

  // ===========================================================================
  // Bulk Actions
  // ===========================================================================

  const executeBulkAction = async (action: string, params: Record<string, unknown> = {}) => {
    if (selectedAlerts.size === 0) return

    setBulkActionLoading(true)
    setError(null)

    try {
      const alertIds = Array.from(selectedAlerts)

      if (action === 'add_to_investigation') {
        const res = await apiRequest('/api/v1/alerts/bulk/add-to-investigation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            alert_ids: alertIds,
            investigation_id: params.investigation_id
          })
        })

        if (!res.ok) throw new Error('Failed to add alerts to investigation')
      } else {
        const res = await apiRequest('/api/v1/alerts/bulk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            alert_ids: alertIds,
            action,
            ...params
          })
        })

        if (!res.ok) throw new Error('Failed to execute bulk action')

        const data = await res.json()

        // Optimistic local overrides
        if (action === 'resolve' || action === 'close') {
          setLocalOverrides(prev => {
            const next = new Map(prev)
            alertIds.forEach(id => next.set(id, { ...prev.get(id), status: 'resolved' as const }))
            return next
          })
        } else if (action === 'acknowledge') {
          setLocalOverrides(prev => {
            const next = new Map(prev)
            alertIds.forEach(id => next.set(id, { ...prev.get(id), status: 'investigating' as const }))
            return next
          })
          // Also fire WebSocket acknowledge for each alert
          alertIds.forEach(id => {
            acknowledgeAlert(id).catch(err =>
              logger.error('WebSocket acknowledge failed for', id, err)
            )
          })
        } else if (action === 'false_positive') {
          setLocalOverrides(prev => {
            const next = new Map(prev)
            alertIds.forEach(id => next.set(id, { ...prev.get(id), status: 'false_positive' as const }))
            return next
          })
        }
      }

      // Clear selection
      setSelectedAlerts(new Set())
      setShowBulkActions(false)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed')
    } finally {
      setBulkActionLoading(false)
    }
  }

  // ===========================================================================
  // Export
  // ===========================================================================

  const exportAlerts = async (format: 'json' | 'csv', includeEnrichment = false) => {
    setLoading(true)
    try {
      const alertIds = selectedAlerts.size > 0 ? Array.from(selectedAlerts) : []

      const res = await apiRequest('/api/v1/alerts/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format,
          alert_ids: alertIds.length > 0 ? alertIds : undefined,
          include_enrichment: includeEnrichment,
          // Pass current filters if no selection
          ...(alertIds.length === 0 ? {
            severity: severityFilter.length > 0 ? severityFilter : undefined,
            status: statusFilter.length > 0 ? statusFilter : undefined,
            search: searchQuery || undefined,
            date_from: dateFrom || undefined,
            date_to: dateTo || undefined
          } : {})
        })
      })

      if (format === 'csv') {
        const blob = await res.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `alerts-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
      } else {
        const data = await res.json()
        const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `alerts-${new Date().toISOString().slice(0, 10)}.json`
        a.click()
      }
    } catch (e) {
      setError('Export failed')
    } finally {
      setLoading(false)
      setShowExportOptions(false)
    }
  }

  // ===========================================================================
  // Tuning / Exclusions
  // ===========================================================================

  const createExclusionFromAlert = async (alertId: string, ruleType: string = 'suppress') => {
    try {
      const res = await apiRequest(`/api/v1/alerts/${alertId}/create-exclusion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_type: ruleType,
          match_fields: ['rule_name', 'agent_id']
        })
      })

      if (res.ok) {
        const data = await res.json()
        setExclusionRules(prev => [...prev, data.data])
      }
    } catch (e) {
      setError('Failed to create exclusion rule')
    }
  }

  // ===========================================================================
  // Filter Presets
  // ===========================================================================

  const applyFilterPreset = (preset: FilterPreset) => {
    const filters = preset.filters
    if (filters.severity) {
      setSeverityFilter(Array.isArray(filters.severity) ? filters.severity : [filters.severity as string])
    }
    if (filters.status) {
      setStatusFilter(Array.isArray(filters.status) ? filters.status : [filters.status as string])
    }
    if (filters.assigned_to_id) {
      setAssignedFilter(filters.assigned_to_id as string)
    }
    setShowFilterPresets(false)
  }

  const clearFilters = () => {
    setSearchQuery('')
    setSeverityFilter([])
    setStatusFilter([])
    setDateFrom('')
    setDateTo('')
    setAssignedFilter('')
    setThreatScoreMin('')
    setThreatScoreMax('')
    setMitreTechniques([])
  }

  // ===========================================================================
  // Stats
  // ===========================================================================

  const stats = useMemo(() => ({
    total: filteredAlerts.length,
    open: filteredAlerts.filter(a => a.status === 'open' || a.status === 'new').length,
    critical: filteredAlerts.filter(a => a.severity === 'critical' && a.status !== 'resolved').length,
    high: filteredAlerts.filter(a => a.severity === 'high' && a.status !== 'resolved').length,
    filtered: filteredAlerts.length,
    selected: selectedAlerts.size
  }), [filteredAlerts, selectedAlerts])

  // An alert is "new" if it recently arrived via WebSocket (within the 5s highlight window)
  const isNewAlert = (alertId: string) => recentWsAlertIds.has(alertId)

  // ===========================================================================
  // Render
  // ===========================================================================

  return (
    <MainLayout title="Alerts">
      <Head title="Alerts - Tamandua EDR" />

      {/* Keyframe animation for new WebSocket alert flash */}
      <style>{`
        @keyframes alert-flash {
          0% { background-color: var(--emerald-glow); border-left-color: var(--emerald-400); }
          50% { background-color: rgba(47, 196, 113, 0.1); border-left-color: var(--emerald-400); }
          100% { background-color: transparent; border-left-color: var(--emerald-400); }
        }
      `}</style>

      <div className="space-y-4">
        {/* Header with Stats */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <ConnectionStatus state={connectionState} showText={true} />

            <div className="flex items-center gap-2">
              <StatBadge label="Open" value={stats.open} severity="critical" />
              <StatBadge label="Critical" value={stats.critical} severity="critical" />
              <StatBadge label="High" value={stats.high} severity="high" />
              {stats.filtered !== stats.total && (
                <StatBadge label="Filtered" value={stats.filtered} severity="info" />
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Selection info */}
            {selectedAlerts.size > 0 && (
              <div className="badge-sentinel badge-sentinel-success badge-sentinel-pill">
                {selectedAlerts.size} selected
              </div>
            )}

            {/* Bulk Actions */}
            {selectedAlerts.size > 0 && (
              <BulkActionsDropdown
                actions={BULK_ACTIONS}
                users={assignableUsers}
                investigations={investigations}
                onAction={executeBulkAction}
                loading={bulkActionLoading}
              />
            )}

            {/* Filter Presets */}
            <FilterPresetsDropdown
              presets={filterPresets}
              onApply={applyFilterPreset}
            />

            {/* Export */}
            <ExportDropdown
              onExport={exportAlerts}
              hasSelection={selectedAlerts.size > 0}
            />

            {/* Tuning */}
            <button
              onClick={() => setShowTuningPanel(!showTuningPanel)}
              className={cn(
                "btn-sentinel",
                showTuningPanel
                  ? "btn-sentinel-primary"
                  : "btn-sentinel-secondary"
              )}
            >
              <SlidersHorizontal className="h-4 w-4" />
              Tuning
              {exclusionRules.length > 0 && (
                <span className="badge-sentinel badge-sentinel-default ml-1">{exclusionRules.length}</span>
              )}
            </button>
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div
            className="px-4 py-3 rounded-lg flex items-center justify-between"
            style={{
              background: 'var(--crit-bg)',
              border: '1px solid rgba(240, 80, 110, 0.3)',
              color: 'var(--crit)',
            }}
          >
            <span>{error}</span>
            <button onClick={() => setError(null)} className="hover:opacity-70"><X className="h-4 w-4" /></button>
          </div>
        )}

        {/* Filter Bar */}
        <FilterBar
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          showAdvanced={showAdvancedFilters}
          setShowAdvanced={setShowAdvancedFilters}
          onClear={clearFilters}
          hasFilters={Boolean(searchQuery || severityFilter.length || statusFilter.length || dateFrom || dateTo)}
        />

        {/* Advanced Filters */}
        {showAdvancedFilters && (
          <AdvancedFilters
            dateFrom={dateFrom}
            setDateFrom={setDateFrom}
            dateTo={dateTo}
            setDateTo={setDateTo}
            assignedFilter={assignedFilter}
            setAssignedFilter={setAssignedFilter}
            threatScoreMin={threatScoreMin}
            setThreatScoreMin={setThreatScoreMin}
            threatScoreMax={threatScoreMax}
            setThreatScoreMax={setThreatScoreMax}
            users={assignableUsers}
          />
        )}

        {/* Tuning Panel */}
        {showTuningPanel && (
          <TuningPanel
            rules={exclusionRules}
            onClose={() => setShowTuningPanel(false)}
            onRefresh={loadExclusionRules}
          />
        )}

        {/* Alerts Table */}
        <div className="card-sentinel" style={{ padding: 0, overflow: 'hidden' }}>
          {/* Table Header */}
          <div
            className="flex items-center gap-4 px-4 py-3 text-sm"
            style={{
              background: 'var(--surface-2)',
              borderBottom: '1px solid var(--border)',
              color: 'var(--muted)',
            }}
          >
            <div className="w-8">
              <button
                onClick={toggleSelectAll}
                className="p-1 rounded transition-colors"
                style={{ color: selectAll ? 'var(--emerald-400)' : 'var(--muted)' }}
              >
                {selectAll ? (
                  <CheckSquare className="h-4 w-4" />
                ) : (
                  <Square className="h-4 w-4" />
                )}
              </button>
            </div>
            <div className="flex-1">Alert</div>
            <SortableHeader
              label="Severity"
              field="severity"
              currentSort={sortBy}
              sortOrder={sortOrder}
              onSort={(field) => {
                if (sortBy === field) {
                  setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')
                } else {
                  setSortBy(field as typeof sortBy)
                  setSortOrder('desc')
                }
              }}
              width="w-24"
            />
            <div className="w-28">Status</div>
            <SortableHeader
              label="Score"
              field="threat_score"
              currentSort={sortBy}
              sortOrder={sortOrder}
              onSort={(field) => {
                if (sortBy === field) {
                  setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')
                } else {
                  setSortBy(field as typeof sortBy)
                  setSortOrder('desc')
                }
              }}
              width="w-20"
            />
            <SortableHeader
              label="Time"
              field="created_at"
              currentSort={sortBy}
              sortOrder={sortOrder}
              onSort={(field) => {
                if (sortBy === field) {
                  setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')
                } else {
                  setSortBy(field as typeof sortBy)
                  setSortOrder('desc')
                }
              }}
              width="w-36"
            />
            <div className="w-20">Actions</div>
          </div>

          {/* Table Body */}
          {filteredAlerts.length === 0 ? (
            <div className="p-12 text-center" style={{ color: 'var(--muted)' }}>
              <Shield className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg" style={{ color: 'var(--fg-2)' }}>No alerts</p>
              <p className="text-sm">
                {effectiveAlerts.length === 0
                  ? 'All systems are operating normally'
                  : 'No alerts match your filters'}
              </p>
            </div>
          ) : (
            <div style={{ borderTop: '1px solid var(--hairline)' }}>
              {paginatedAlerts.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  isNew={isNewAlert(alert.id)}
                  isSelected={selectedAlerts.has(alert.id)}
                  onSelect={() => toggleSelectAlert(alert.id)}
                  onCreateExclusion={() => createExclusionFromAlert(alert.id)}
                  onAcknowledge={() => {
                    acknowledgeAlert(alert.id).catch(err =>
                      logger.error('WebSocket acknowledge failed:', err)
                    )
                    // Optimistic local update
                    setLocalOverrides(prev => {
                      const next = new Map(prev)
                      next.set(alert.id, { ...prev.get(alert.id), status: 'investigating' as const })
                      return next
                    })
                  }}
                />
              ))}
            </div>
          )}

          {/* Pagination */}
          {filteredAlerts.length > 0 && (
            <div
              className="flex items-center justify-between px-4 py-3"
              style={{
                borderTop: '1px solid var(--border)',
                background: 'var(--surface)',
              }}
            >
              <div className="flex items-center gap-3 text-sm" style={{ color: 'var(--muted)' }}>
                <span>
                  Showing {((currentPage - 1) * pageSize) + 1}--{Math.min(currentPage * pageSize, filteredAlerts.length)} of {filteredAlerts.length}
                  {filteredAlerts.length !== effectiveAlerts.length && ` (${effectiveAlerts.length} total)`}
                </span>
                <Select
                  value={String(pageSize)}
                  onValueChange={(v) => { setPageSize(Number(v)); setCurrentPage(1) }}
                  placeholder="Page size"
                >
                  {PAGE_SIZE_OPTIONS.map(size => (
                    <SelectItem key={size} value={String(size)}>{size} per page</SelectItem>
                  ))}
                </Select>
              </div>

              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  First
                </button>
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  Prev
                </button>

                {/* Page numbers */}
                {(() => {
                  const pages: number[] = []
                  const maxVisible = 5
                  let start = Math.max(1, currentPage - Math.floor(maxVisible / 2))
                  const end = Math.min(totalPages, start + maxVisible - 1)
                  if (end - start + 1 < maxVisible) start = Math.max(1, end - maxVisible + 1)
                  for (let i = start; i <= end; i++) pages.push(i)
                  return pages.map(page => (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={cn(
                        'btn-sentinel btn-sentinel-sm min-w-[32px]',
                        page === currentPage
                          ? 'btn-sentinel-primary'
                          : 'btn-sentinel-secondary'
                      )}
                    >
                      {page}
                    </button>
                  ))
                })()}

                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  Next
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  Last
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ===========================================================================
// Sub-Components
// ===========================================================================

function StatBadge({ label, value, severity }: { label: string; value: number; severity: 'critical' | 'high' | 'medium' | 'low' | 'info' }) {
  return (
    <div className={cn("badge-sentinel badge-sentinel-pill", getSeverityBadgeClass(severity).replace('badge-sentinel ', ''))}>
      <span className="opacity-75">{label}:</span>
      <span className="font-bold ml-1">{value}</span>
    </div>
  )
}

function SortableHeader({
  label, field, currentSort, sortOrder, onSort, width
}: {
  label: string
  field: string
  currentSort: string
  sortOrder: 'asc' | 'desc'
  onSort: (field: string) => void
  width: string
}) {
  const isActive = currentSort === field

  return (
    <button
      onClick={() => onSort(field)}
      className={cn("flex items-center gap-1 transition-colors", width)}
      style={{ color: isActive ? 'var(--fg)' : 'var(--muted)' }}
    >
      {label}
      {isActive ? (
        sortOrder === 'desc' ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
      ) : (
        <ChevronDown className="h-3 w-3 opacity-30" />
      )}
    </button>
  )
}

function FilterBar({
  searchQuery, setSearchQuery,
  severityFilter, setSeverityFilter,
  statusFilter, setStatusFilter,
  showAdvanced, setShowAdvanced,
  onClear, hasFilters
}: {
  searchQuery: string
  setSearchQuery: (v: string) => void
  severityFilter: string[]
  setSeverityFilter: (v: string[]) => void
  statusFilter: string[]
  setStatusFilter: (v: string[]) => void
  showAdvanced: boolean
  setShowAdvanced: (v: boolean) => void
  onClear: () => void
  hasFilters: boolean
}) {
  return (
    <div className="flex items-center gap-3">
      {/* Search */}
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
        <input
          type="text"
          placeholder="Search alerts..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="input-sentinel pl-10 pr-4"
        />
      </div>

      {/* Severity Filter */}
      <MultiSelect
        label="Severity"
        options={SEVERITY_OPTIONS}
        selected={severityFilter}
        onChange={setSeverityFilter}
      />

      {/* Status Filter */}
      <MultiSelect
        label="Status"
        options={STATUS_OPTIONS}
        selected={statusFilter}
        onChange={setStatusFilter}
      />

      {/* Advanced toggle */}
      <button
        onClick={() => setShowAdvanced(!showAdvanced)}
        className={cn(
          "btn-sentinel",
          showAdvanced
            ? "btn-sentinel-primary"
            : "btn-sentinel-ghost"
        )}
      >
        <Filter className="h-4 w-4" />
        Advanced
      </button>

      {/* Clear filters */}
      {hasFilters && (
        <button
          onClick={onClear}
          className="btn-sentinel btn-sentinel-ghost"
          style={{ color: 'var(--muted)' }}
        >
          <X className="h-4 w-4" />
          Clear
        </button>
      )}
    </div>
  )
}

function MultiSelect({
  label, options, selected, onChange
}: {
  label: string
  options: string[]
  selected: string[]
  onChange: (v: string[]) => void
}) {
  const [open, setOpen] = useState(false)

  const toggleOption = (opt: string) => {
    if (selected.includes(opt)) {
      onChange(selected.filter(s => s !== opt))
    } else {
      onChange([...selected, opt])
    }
  }

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      align="start"
      padded={false}
      popupStyle={{ width: '11rem', minWidth: '11rem', maxWidth: '11rem', background: 'var(--surface-2)' }}
      trigger={
        <button
          className={cn(
            "btn-sentinel",
            selected.length > 0
              ? "btn-sentinel-outline"
              : "btn-sentinel-secondary"
          )}
        >
          {label}
          {selected.length > 0 && (
            <span className="badge-sentinel badge-sentinel-success ml-1">{selected.length}</span>
          )}
          <ChevronDown className={cn("h-3 w-3 transition-transform", open && "rotate-180")} />
        </button>
      }
    >
      {options.map(opt => (
        <button
          key={opt}
          onClick={() => toggleOption(opt)}
          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors"
          style={{
            color: selected.includes(opt) ? 'var(--emerald-400)' : 'var(--fg-2)',
            background: 'transparent',
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
        >
          {selected.includes(opt) ? (
            <CheckSquare className="h-4 w-4" />
          ) : (
            <Square className="h-4 w-4" />
          )}
          <span className="capitalize">{opt.replace('_', ' ')}</span>
        </button>
      ))}
    </Popover>
  )
}

function AdvancedFilters({
  dateFrom, setDateFrom, dateTo, setDateTo,
  assignedFilter, setAssignedFilter,
  threatScoreMin, setThreatScoreMin,
  threatScoreMax, setThreatScoreMax,
  users
}: {
  dateFrom: string
  setDateFrom: (v: string) => void
  dateTo: string
  setDateTo: (v: string) => void
  assignedFilter: string
  setAssignedFilter: (v: string) => void
  threatScoreMin: string
  setThreatScoreMin: (v: string) => void
  threatScoreMax: string
  setThreatScoreMax: (v: string) => void
  users: User[]
}) {
  return (
    <div className="card-sentinel">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Date Range */}
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Date From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="input-sentinel"
          />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Date To</label>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="input-sentinel"
          />
        </div>

        {/* Threat Score */}
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Min Threat Score</label>
          <input
            type="number"
            min="0"
            max="100"
            value={threatScoreMin}
            onChange={(e) => setThreatScoreMin(e.target.value)}
            placeholder="0"
            className="input-sentinel"
          />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Max Threat Score</label>
          <input
            type="number"
            min="0"
            max="100"
            value={threatScoreMax}
            onChange={(e) => setThreatScoreMax(e.target.value)}
            placeholder="100"
            className="input-sentinel"
          />
        </div>

        {/* Assigned To */}
        <div className="col-span-2">
          <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Assigned To</label>
          <Select value={assignedFilter} onValueChange={setAssignedFilter} placeholder="All" fullWidth>
            <SelectItem value="">All</SelectItem>
            <SelectItem value="unassigned">Unassigned</SelectItem>
            {users.map(u => (
              <SelectItem key={u.id} value={u.id}>{u.name}</SelectItem>
            ))}
          </Select>
        </div>
      </div>
    </div>
  )
}

function BulkActionsDropdown({
  actions, users, investigations, onAction, loading
}: {
  actions: BulkAction[]
  users: User[]
  investigations: { id: string; title: string }[]
  onAction: (action: string, params: Record<string, unknown>) => void
  loading: boolean
}) {
  const [open, setOpen] = useState(false)
  const [selectedAction, setSelectedAction] = useState<BulkAction | null>(null)
  const [inputValue, setInputValue] = useState('')

  const handleActionClick = (action: BulkAction) => {
    if (action.requiresInput) {
      setSelectedAction(action)
    } else {
      onAction(action.action, {})
      setOpen(false)
    }
  }

  const submitAction = () => {
    if (!selectedAction) return

    const params: Record<string, unknown> = {}
    if (selectedAction.inputType === 'user') {
      params.user_id = inputValue
    } else if (selectedAction.inputType === 'investigation') {
      params.investigation_id = inputValue
    } else if (selectedAction.inputType === 'text') {
      params.notes = inputValue
    }

    onAction(selectedAction.action, params)
    setSelectedAction(null)
    setInputValue('')
    setOpen(false)
  }

  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        if (!o) { setSelectedAction(null); setInputValue('') }
      }}
      align="end"
      padded={false}
      popupStyle={{ width: '16rem', minWidth: '16rem', maxWidth: '16rem' }}
      trigger={
        <button disabled={loading} className="btn-sentinel btn-sentinel-primary">
          {loading ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Layers className="h-4 w-4" />
          )}
          Bulk Actions
          <ChevronDown className="h-3 w-3" />
        </button>
      }
    >
      {selectedAction ? (
        <div className="p-3">
          <div className="flex items-center gap-2 mb-3 text-sm" style={{ color: 'var(--fg-2)' }}>
            {selectedAction.icon}
            {selectedAction.label}
          </div>

          {selectedAction.inputType === 'user' && (
            <div className="mb-3">
              <Select value={inputValue} onValueChange={setInputValue} placeholder="Select user..." fullWidth>
                {users.map(u => (
                  <SelectItem key={u.id} value={u.id}>{u.name}</SelectItem>
                ))}
              </Select>
            </div>
          )}

          {selectedAction.inputType === 'investigation' && (
            <div className="mb-3">
              <Select value={inputValue} onValueChange={setInputValue} placeholder="Select investigation..." fullWidth>
                {investigations.map(i => (
                  <SelectItem key={i.id} value={i.id}>{i.title}</SelectItem>
                ))}
              </Select>
            </div>
          )}

          {selectedAction.inputType === 'text' && (
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Notes (optional)..."
              className="input-sentinel mb-3 resize-none"
              rows={2}
              style={{ height: 'auto' }}
            />
          )}

          <div className="flex gap-2">
            <button
              onClick={() => { setSelectedAction(null); setInputValue('') }}
              className="btn-sentinel btn-sentinel-secondary flex-1"
            >
              Cancel
            </button>
            <button
              onClick={submitAction}
              disabled={selectedAction.inputType !== 'text' && !inputValue}
              className="btn-sentinel btn-sentinel-primary flex-1"
            >
              Apply
            </button>
          </div>
        </div>
      ) : (
        actions.map(action => (
          <button
            key={action.action}
            onClick={() => handleActionClick(action)}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
            style={{ color: 'var(--fg-2)', background: 'transparent' }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            {action.icon}
            {action.label}
          </button>
        ))
      )}
    </Popover>
  )
}

function FilterPresetsDropdown({
  presets, onApply
}: {
  presets: FilterPreset[]
  onApply: (preset: FilterPreset) => void
}) {
  return (
    <Menu
      align="end"
      trigger={
        <button className="btn-sentinel btn-sentinel-secondary">
          <Save className="h-4 w-4" />
          Presets
          <ChevronDown className="h-3 w-3" />
        </button>
      }
    >
      {presets.length === 0 ? (
        <div className="px-3 py-2 text-sm" style={{ color: 'var(--muted)' }}>No saved presets</div>
      ) : (
        presets.map(preset => (
          <MenuItem key={preset.id} onSelect={() => onApply(preset)}>
            <Filter className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
            {preset.name}
          </MenuItem>
        ))
      )}
    </Menu>
  )
}

function ExportDropdown({
  onExport, hasSelection
}: {
  onExport: (format: 'json' | 'csv', includeEnrichment: boolean) => void
  hasSelection: boolean
}) {
  const [open, setOpen] = useState(false)

  const handleExport = (format: 'json' | 'csv', includeEnrichment: boolean) => {
    onExport(format, includeEnrichment)
    setOpen(false)
  }

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      align="end"
      padded={false}
      popupStyle={{ width: '14rem', minWidth: '14rem', maxWidth: '14rem' }}
      trigger={
        <button className="btn-sentinel btn-sentinel-secondary">
          <Download className="h-4 w-4" />
          Export
          <ChevronDown className="h-3 w-3" />
        </button>
      }
    >
      <div
        className="px-3 py-2 text-xs"
        style={{
          color: 'var(--muted)',
          borderBottom: '1px solid var(--hairline)',
        }}
      >
        {hasSelection ? 'Export selected alerts' : 'Export filtered alerts'}
      </div>
      <button
        onClick={() => handleExport('csv', false)}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
        style={{ color: 'var(--fg-2)', background: 'transparent' }}
        onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
      >
        <FileSpreadsheet className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
        Export as CSV
      </button>
      <button
        onClick={() => handleExport('json', false)}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
        style={{ color: 'var(--fg-2)', background: 'transparent' }}
        onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
      >
        <FileJson className="h-4 w-4" style={{ color: 'var(--med)' }} />
        Export as JSON
      </button>
      <button
        onClick={() => handleExport('json', true)}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
        style={{ color: 'var(--fg-2)', background: 'transparent' }}
        onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
      >
        <FileText className="h-4 w-4" style={{ color: 'var(--sol-magenta)' }} />
        JSON with Enrichment
      </button>
    </Popover>
  )
}

function TuningPanel({
  rules, onClose, onRefresh
}: {
  rules: ExclusionRule[]
  onClose: () => void
  onRefresh: () => void
}) {
  const [loading, setLoading] = useState(false)

  const toggleRule = async (ruleId: string) => {
    setLoading(true)
    try {
      await apiRequest(`/api/v1/alerts/exclusions/${ruleId}/toggle`, { method: 'POST' })
      onRefresh()
    } finally {
      setLoading(false)
    }
  }

  const deleteRule = async (ruleId: string) => {
    if (!confirm('Delete this exclusion rule?')) return
    setLoading(true)
    try {
      await apiRequest(`/api/v1/alerts/exclusions/${ruleId}`, { method: 'DELETE' })
      onRefresh()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>Alert Tuning & Exclusions</h3>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
            disabled={loading}
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} style={{ color: 'var(--muted)' }} />
          </button>
          <button
            onClick={onClose}
            className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          >
            <X className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          </button>
        </div>
      </div>

      {rules.length === 0 ? (
        <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
          <Ban className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No exclusion rules configured</p>
          <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Create rules from alerts to suppress similar future detections</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div
              key={rule.id}
              className={cn(
                "card-sentinel card-sentinel-interactive flex items-center justify-between p-3",
                !rule.enabled && "opacity-60"
              )}
              style={{
                background: rule.enabled ? 'var(--surface-2)' : 'var(--surface)',
              }}
            >
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className={cn(
                    "badge-sentinel",
                    rule.rule_type === 'whitelist' ? "badge-sentinel-success" :
                    rule.rule_type === 'suppress' ? "badge-sentinel-error" :
                    "badge-sentinel-warning"
                  )}>
                    {rule.rule_type}
                  </span>
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{rule.name}</span>
                </div>
                {rule.description && (
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{rule.description}</p>
                )}
                <div className="flex items-center gap-4 mt-1 text-xs" style={{ color: 'var(--subtle)' }}>
                  <span>Matched: {rule.match_count}</span>
                  {rule.expires_at && (
                    <span>Expires: {formatDate(rule.expires_at)}</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleRule(rule.id)}
                  className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
                  title={rule.enabled ? 'Disable' : 'Enable'}
                >
                  {rule.enabled ? (
                    <Eye className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                  ) : (
                    <EyeOff className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  )}
                </button>
                <button
                  onClick={() => deleteRule(rule.id)}
                  className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
                  title="Delete"
                  style={{ color: 'var(--crit)' }}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function formatAlertScore(score: number | null | undefined): string {
  if (score == null) return '--'
  const numeric = Number(score)
  if (Number.isNaN(numeric)) return '--'
  return String(numeric <= 1 ? Math.round(numeric * 100) : Math.round(numeric))
}

function getAlertScoreColor(score: number | null | undefined): string {
  const numeric = Number(score || 0)
  const normalized = numeric <= 1 ? numeric * 100 : numeric
  if (normalized >= 80) return 'var(--crit)'
  if (normalized >= 50) return 'var(--high)'
  if (normalized >= 30) return 'var(--med)'
  return 'var(--emerald-400)'
}

function getAlertScoreVersion(alert: Alert): string {
  const metadata = (alert.detectionMetadata || {}) as Record<string, unknown>
  const rawEvent = (alert.rawEvent || {}) as Record<string, unknown>
  const rawMetadata = (rawEvent.metadata || {}) as Record<string, unknown>

  return String(
    metadata.score_version ||
    metadata.scoring_version ||
    metadata.correlation_version ||
    metadata.engine_version ||
    rawMetadata.score_version ||
    rawMetadata.correlation_version ||
    'unversioned'
  )
}

function AlertRow({
  alert, isNew, isSelected, onSelect, onCreateExclusion, onAcknowledge
}: {
  alert: Alert
  isNew: boolean
  isSelected: boolean
  onSelect: () => void
  onCreateExclusion: () => void
  onAcknowledge: () => void
}) {
  const [showActions, setShowActions] = useState(false)
  const severity = safeSeverity(alert.severity)
  const status = safeStatus(alert.status)
  const mitreTechniques = safeStringArray(alert.mitreTechniques)
  const title = String(alert.title || 'Untitled alert')
  const description = String(alert.description || '')

  return (
    <div
      className={cn(
        "flex items-center gap-4 px-4 py-3 transition-all duration-300",
        isNew && "border-l-4",
        !isNew && "border-l-4 border-transparent",
      )}
      style={{
        borderBottom: '1px solid var(--hairline)',
        borderLeftColor: isNew ? 'var(--emerald-400)' : 'transparent',
        background: isNew
          ? 'var(--emerald-glow)'
          : isSelected
            ? 'rgba(47, 196, 113, 0.05)'
            : 'transparent',
        animation: isNew ? 'alert-flash 2s ease-out' : undefined,
      }}
    >
      {/* Checkbox */}
      <div className="w-8">
        <button
          onClick={onSelect}
          className="p-1 rounded transition-colors"
          style={{ color: isSelected ? 'var(--emerald-400)' : 'var(--muted)' }}
        >
          {isSelected ? (
            <CheckSquare className="h-4 w-4" />
          ) : (
            <Square className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Alert Info */}
      <div className="flex-1 min-w-0">
        <a href={`/app/alerts/${alert.id}`} className="block group">
          <div className="flex items-center gap-2 mb-0.5">
            <h3
              className="font-medium truncate transition-colors"
              style={{ color: 'var(--fg)' }}
            >
              {title}
            </h3>
            {isNew && (
              <span className="badge-sentinel badge-sentinel-success badge-sentinel-pill animate-pulse font-semibold">NEW</span>
            )}
          </div>
          <p className="text-sm truncate" style={{ color: 'var(--muted)' }}>{description}</p>
          {mitreTechniques.length > 0 && (
            <div className="flex items-center gap-1 mt-1">
              <Shield className="h-3 w-3" style={{ color: 'var(--subtle)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                {mitreTechniques.slice(0, 3).join(', ')}
                {mitreTechniques.length > 3 && ` +${mitreTechniques.length - 3}`}
              </span>
            </div>
          )}
        </a>
      </div>

      {/* Severity */}
      <div className="w-24">
        <span className={getSeverityBadgeClass(severity)}>
          {severity.toUpperCase()}
        </span>
      </div>

      {/* Status */}
      <div className="w-28">
        <StatusBadge status={status} />
      </div>

      {/* Threat Score */}
      <div className="w-20 text-center">
        <div
          className="text-lg font-bold"
          style={{ color: getAlertScoreColor(alert.threatScore) }}
          title={`Score version: ${getAlertScoreVersion(alert)}`}
        >
          {formatAlertScore(alert.threatScore)}
        </div>
        <div className="text-[10px] truncate" style={{ color: 'var(--muted)' }}>
          {getAlertScoreVersion(alert)}
        </div>
      </div>

      {/* Time */}
      <div className="w-36 text-sm" style={{ color: 'var(--muted)' }}>
        {formatDate(alert.createdAt)}
      </div>

      {/* Actions */}
      <div className="w-20">
        <Popover
          open={showActions}
          onOpenChange={setShowActions}
          align="end"
          padded={false}
          popupStyle={{ width: '12rem', minWidth: '12rem', maxWidth: '12rem', background: 'var(--surface-2)' }}
          trigger={
            <button className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon">
              <Settings className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            </button>
          }
        >
          <a
            href={`/app/alerts/${alert.id}`}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm transition-colors"
            style={{ color: 'var(--fg-2)', background: 'transparent' }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            <ExternalLink className="h-4 w-4" />
            View Details
          </a>
          <a
            href={`/app/storyline/${alert.id}`}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm transition-colors"
            style={{ color: 'var(--fg-2)', background: 'transparent' }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            <History className="h-4 w-4" />
            View Timeline
          </a>
          {status === 'new' || status === 'open' ? (
            <button
              onClick={() => { onAcknowledge(); setShowActions(false) }}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
              style={{ color: 'var(--fg-2)', background: 'transparent' }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              Acknowledge
            </button>
          ) : null}
          <button
            onClick={() => { onCreateExclusion(); setShowActions(false) }}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors"
            style={{ color: 'var(--fg-2)', background: 'transparent' }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            <Ban className="h-4 w-4" />
            Create Exclusion
          </button>
        </Popover>
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: Alert['status'] | string | null | undefined }) {
  const normalizedStatus = safeStatus(status)
  const getStatusClass = (status: string): string => {
    switch (status) {
      case 'new': return 'badge-sentinel badge-sentinel-info'
      case 'open': return 'badge-sentinel badge-sentinel-error'
      case 'investigating': return 'badge-sentinel badge-sentinel-warning'
      case 'resolved': return 'badge-sentinel badge-sentinel-success'
      case 'false_positive': return 'badge-sentinel badge-sentinel-default'
      default: return 'badge-sentinel badge-sentinel-default'
    }
  }

  return (
    <span className={cn(getStatusClass(normalizedStatus), 'capitalize')}>
      {normalizedStatus.replace(/_/g, ' ')}
    </span>
  )
}
