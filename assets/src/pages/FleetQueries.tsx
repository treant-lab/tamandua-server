import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { logger } from '@/lib/logger'
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Copy,
  Database,
  Loader2,
  Play,
  RefreshCw,
  Search,
  Server,
  Terminal,
  XCircle,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'

interface FleetQueryRun {
  id: string
  query?: string
  query_hash?: string
  query_preview?: string | null
  status: string
  target_count: number
  queued_count: number
  skipped_count: number
  completed_count: number
  failed_count: number
  requested_agent_ids?: string[]
  options?: Record<string, unknown>
  targets?: FleetQueryTarget[] | null
  started_at?: string | null
  completed_at?: string | null
  inserted_at?: string | null
}

interface FleetQueryTarget {
  id: string
  agent_id?: string | null
  hostname?: string | null
  os_type?: string | null
  status: string
  agent_command_id?: string | null
  skip_reason?: string | null
  result_summary?: {
    row_count?: number | null
    result_status?: string | null
    truncated?: boolean
  } | null
  error?: string | null
  completed_at?: string | null
}

const statusStyle: Record<string, { label: string; color: string; bg: string; icon: typeof Clock }> = {
  queued: { label: 'Queued', color: 'var(--muted)', bg: 'var(--surface-2)', icon: Clock },
  running: { label: 'Running', color: 'var(--med)', bg: 'var(--med-bg)', icon: Loader2 },
  completed: { label: 'Completed', color: 'var(--emerald-400)', bg: 'var(--emerald-glow)', icon: CheckCircle },
  completed_with_errors: { label: 'Completed with errors', color: 'var(--high)', bg: 'var(--high-bg)', icon: AlertTriangle },
  failed: { label: 'Failed', color: 'var(--crit)', bg: 'var(--crit-bg)', icon: XCircle },
  sent: { label: 'Sent', color: 'var(--med)', bg: 'var(--med-bg)', icon: Terminal },
  acknowledged: { label: 'Acknowledged', color: 'var(--sol-cyan)', bg: 'rgba(25, 251, 155, 0.12)', icon: CheckCircle },
  skipped: { label: 'Skipped', color: 'var(--muted)', bg: 'var(--surface-2)', icon: AlertTriangle },
}

const sampleQueries = [
  'select name, version from programs order by name limit 50;',
  'select pid, name, path from processes order by pid limit 100;',
  'select address, mac, interface from interface_addresses;',
  'select key, value from registry where key like "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%";',
]

function formatDate(value?: string | null): string {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function compactId(value?: string | null): string {
  if (!value) return '-'
  return value.length <= 12 ? value : `${value.slice(0, 8)}...${value.slice(-4)}`
}

function parseAgentIds(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map(item => item.trim())
    .filter(Boolean)
}

function StatusBadge({ status }: { status: string }) {
  const config = statusStyle[status] || { label: status || 'unknown', color: 'var(--muted)', bg: 'var(--surface-2)', icon: AlertTriangle }
  const Icon = config.icon

  return (
    <span className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium" style={{ color: config.color, backgroundColor: config.bg }}>
      <Icon size={12} className={status === 'running' ? 'animate-spin' : ''} />
      {config.label}
    </span>
  )
}

function ProgressBar({ run }: { run: FleetQueryRun }) {
  const total = Math.max(0, run.target_count || 0)
  const completed = Math.max(0, run.completed_count || 0)
  const failed = Math.max(0, run.failed_count || 0)
  const skipped = Math.max(0, run.skipped_count || 0)
  const terminal = completed + failed + skipped
  const percent = total > 0 ? Math.min(100, Math.round((terminal / total) * 100)) : 0

  return (
    <div className="space-y-1">
      <div className="h-2 rounded overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
        <div className="h-full transition-all" style={{ width: `${percent}%`, backgroundColor: 'var(--emerald-400)' }} />
      </div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>
        {terminal}/{total} terminal, {run.queued_count || 0} active
      </div>
    </div>
  )
}

export default function FleetQueries() {
  const [runs, setRuns] = useState<FleetQueryRun[]>([])
  const [selectedRun, setSelectedRun] = useState<FleetQueryRun | null>(null)
  const [query, setQuery] = useState(sampleQueries[0])
  const [agentIds, setAgentIds] = useState('')
  const [timeoutSeconds, setTimeoutSeconds] = useState(300)
  const [maxRows, setMaxRows] = useState(500)
  const [maxTargets, setMaxTargets] = useState(100)
  const [requireCapability, setRequireCapability] = useState(true)
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [targetStatusFilter, setTargetStatusFilter] = useState('all')
  const [targetSearch, setTargetSearch] = useState('')

  const activeRunCount = useMemo(
    () => runs.filter(run => run.status === 'queued' || run.status === 'running').length,
    [runs]
  )

  const totals = useMemo(() => {
    return runs.reduce(
      (acc, run) => ({
        targets: acc.targets + (run.target_count || 0),
        completed: acc.completed + (run.completed_count || 0),
        failed: acc.failed + (run.failed_count || 0),
        skipped: acc.skipped + (run.skipped_count || 0),
      }),
      { targets: 0, completed: 0, failed: 0, skipped: 0 }
    )
  }, [runs])

  const loadRuns = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await axios.get('/api/v1/fleet-queries', { params: { limit: 50 } })
      const data = Array.isArray(response.data?.data) ? response.data.data : []
      setRuns(data)
      setSelectedRun(current => {
        if (!current) return data[0] || null
        return data.find((run: FleetQueryRun) => run.id === current.id) || current
      })
    } catch (err) {
      logger.error('Failed to load fleet queries:', err)
      setError('Could not load fleet query runs')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadRunDetail = useCallback(async (runId: string) => {
    setDetailLoading(true)
    try {
      const response = await axios.get(`/api/v1/fleet-queries/${runId}`)
      const run = response.data?.data as FleetQueryRun
      setSelectedRun(run)
      setRuns(prev => prev.map(item => (item.id === run.id ? { ...item, ...run, targets: item.targets } : item)))
    } catch (err) {
      logger.error('Failed to load fleet query detail:', err)
      toast.error('Could not load fleet query detail')
    } finally {
      setDetailLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRuns()
  }, [loadRuns])

  useEffect(() => {
    if (activeRunCount === 0 && selectedRun?.status !== 'queued' && selectedRun?.status !== 'running') return

    const timer = window.setInterval(() => {
      loadRuns()
      if (selectedRun?.id && (selectedRun.status === 'queued' || selectedRun.status === 'running')) {
        loadRunDetail(selectedRun.id)
      }
    }, 5000)

    return () => window.clearInterval(timer)
  }, [activeRunCount, loadRunDetail, loadRuns, selectedRun?.id, selectedRun?.status])

  const createRun = async () => {
    const trimmedQuery = query.trim()
    if (!trimmedQuery) {
      toast.error('Query is required')
      return
    }

    setCreating(true)
    setError(null)
    try {
      const payload = {
        query: trimmedQuery,
        agent_ids: parseAgentIds(agentIds),
        timeout_seconds: timeoutSeconds,
        max_rows: maxRows,
        max_targets: maxTargets,
        require_capability: requireCapability,
      }
      const response = await axios.post('/api/v1/fleet-queries', payload)
      const run = response.data?.data as FleetQueryRun
      toast.success('Fleet query queued')
      await loadRuns()
      if (run?.id) await loadRunDetail(run.id)
    } catch (err: any) {
      logger.error('Failed to queue fleet query:', err)
      const message = err?.response?.data?.error || 'Could not queue fleet query'
      setError(message)
      toast.error(message)
    } finally {
      setCreating(false)
    }
  }

  const cancelRun = async () => {
    if (!selectedRun) return

    setCancelling(true)
    setError(null)
    try {
      const response = await axios.post(`/api/v1/fleet-queries/${selectedRun.id}/cancel`)
      const result = response.data?.cancel_result || {}
      const cancelled = Number(result.cancelled_count || 0)
      const alreadySent = Number(result.already_sent_count || 0)
      const notCancellable = Number(result.not_cancellable_count || 0)

      if (cancelled > 0) {
        toast.success(`Cancelled ${cancelled} pending target${cancelled === 1 ? '' : 's'}`)
      } else {
        toast.info('No pending targets were cancelled')
      }

      if (alreadySent > 0 || notCancellable > 0) {
        toast.warning(`${alreadySent + notCancellable} target${alreadySent + notCancellable === 1 ? '' : 's'} could not be cancelled`)
      }

      await loadRuns()
      await loadRunDetail(selectedRun.id)
    } catch (err: any) {
      logger.error('Failed to cancel fleet query:', err)
      const message = err?.response?.data?.error || 'Could not cancel fleet query'
      setError(message)
      toast.error(message)
    } finally {
      setCancelling(false)
    }
  }

  const selectedTargets = selectedRun?.targets || []
  const selectedRunActive = selectedRun?.status === 'queued' || selectedRun?.status === 'running'
  const filteredTargets = useMemo(() => {
    const queryText = targetSearch.trim().toLowerCase()

    return selectedTargets.filter(target => {
      if (targetStatusFilter !== 'all' && target.status !== targetStatusFilter) return false
      if (!queryText) return true

      const haystack = [
        target.hostname,
        target.agent_id,
        target.os_type,
        target.status,
        target.skip_reason,
        target.error,
        target.result_summary?.result_status,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()

      return haystack.includes(queryText)
    })
  }, [selectedTargets, targetSearch, targetStatusFilter])

  return (
    <MainLayout title="Fleet Queries">
      <Head title="Fleet Queries - Tamandua EDR" />

      <div className="p-6 space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--emerald-400)' }}>
              <Database size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Fleet Queries</h1>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                Live osquery fan-out through the existing agent command channel.
              </p>
            </div>
          </div>
          <button
            onClick={loadRuns}
            disabled={loading}
            className="btn-sentinel btn-sentinel-secondary inline-flex items-center gap-2"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="rounded-md p-3 text-sm flex items-center gap-2" style={{ color: 'var(--crit)', backgroundColor: 'var(--crit-bg)', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
            <AlertTriangle size={16} />
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <Metric label="Runs" value={runs.length} icon={Search} />
          <Metric label="Active" value={activeRunCount} icon={Loader2} />
          <Metric label="Targets" value={totals.targets} icon={Server} />
          <Metric label="Errors / skipped" value={totals.failed + totals.skipped} icon={AlertTriangle} />
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[420px_minmax(0,1fr)] gap-4">
          <section className="card-sentinel p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>New osquery run</h2>
              <StatusBadge status={requireCapability ? 'acknowledged' : 'skipped'} />
            </div>

            <div>
              <label className="text-xs font-medium" style={{ color: 'var(--muted)' }}>SQL</label>
              <textarea
                value={query}
                onChange={event => setQuery(event.target.value)}
                rows={7}
                className="mt-1 w-full rounded-md border p-3 font-mono text-sm"
                style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)', color: 'var(--fg)' }}
              />
            </div>

            <div className="space-y-2">
              <div className="text-xs font-medium" style={{ color: 'var(--muted)' }}>Examples</div>
              <div className="flex flex-wrap gap-2">
                {sampleQueries.map((sample, index) => (
                  <button
                    key={sample}
                    type="button"
                    onClick={() => setQuery(sample)}
                    className="rounded px-2 py-1 text-xs"
                    style={{ color: 'var(--fg-2)', backgroundColor: 'var(--surface-2)' }}
                  >
                    Query {index + 1}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs font-medium" style={{ color: 'var(--muted)' }}>Target agent IDs</label>
              <textarea
                value={agentIds}
                onChange={event => setAgentIds(event.target.value)}
                rows={3}
                placeholder="Leave blank for all eligible online agents"
                className="mt-1 w-full rounded-md border p-3 text-sm"
                style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)', color: 'var(--fg)' }}
              />
            </div>

            <div className="grid grid-cols-3 gap-3">
              <NumberField label="Timeout sec" value={timeoutSeconds} min={5} max={3600} onChange={setTimeoutSeconds} />
              <NumberField label="Max rows" value={maxRows} min={1} max={10000} onChange={setMaxRows} />
              <NumberField label="Max targets" value={maxTargets} min={1} max={10000} onChange={setMaxTargets} />
            </div>

            <label className="flex items-start gap-3 rounded-md p-3 cursor-pointer" style={{ backgroundColor: 'var(--bg-2)', color: 'var(--fg-2)' }}>
              <input
                type="checkbox"
                checked={requireCapability}
                onChange={event => setRequireCapability(event.target.checked)}
                className="mt-0.5"
              />
              <span className="text-sm">
                Require reported osquery capability
                <span className="block text-xs mt-1" style={{ color: 'var(--muted)' }}>
                  Agents without osquery_query or remote_query are marked skipped instead of receiving a command.
                </span>
              </span>
            </label>

            <button
              onClick={createRun}
              disabled={creating || !query.trim()}
              className="btn-sentinel btn-sentinel-primary w-full inline-flex items-center justify-center gap-2"
            >
              {creating ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
              Queue fleet query
            </button>
          </section>

          <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-4 min-w-0">
            <div className="card-sentinel p-4 min-w-0">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Recent runs</h2>
                {loading && <Loader2 size={14} className="animate-spin" style={{ color: 'var(--muted)' }} />}
              </div>

              {runs.length === 0 ? (
                <EmptyState title="No fleet queries yet" detail="Queue a query to create the first persisted run." />
              ) : (
                <div className="space-y-2">
                  {runs.map(run => (
                    <button
                      key={run.id}
                      type="button"
                      onClick={() => loadRunDetail(run.id)}
                      className="w-full text-left rounded-md p-3 transition-colors hover:brightness-105"
                      style={{
                        backgroundColor: selectedRun?.id === run.id ? 'var(--surface-2)' : 'var(--bg-2)',
                        border: selectedRun?.id === run.id ? '1px solid var(--emerald-500)' : '1px solid var(--border)',
                      }}
                    >
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <span className="font-mono text-xs" style={{ color: 'var(--fg)' }}>{compactId(run.id)}</span>
                        <StatusBadge status={run.status} />
                      </div>
                      <ProgressBar run={run} />
                      <div className="mt-2 truncate font-mono text-xs" style={{ color: 'var(--fg-2)' }}>
                        {run.query_preview || `hash ${run.query_hash || '-'}`}
                      </div>
                      <div className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
                        {formatDate(run.inserted_at || run.started_at)}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="card-sentinel p-4 min-w-0">
              <div className="flex items-center justify-between gap-3 mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Run detail</h2>
                {selectedRun && (
                  <button
                    type="button"
                    onClick={() => loadRunDetail(selectedRun.id)}
                    className="rounded p-2 hover:brightness-110"
                    style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
                    title="Refresh run detail"
                  >
                    <RefreshCw size={14} className={detailLoading ? 'animate-spin' : ''} />
                  </button>
                )}
              </div>

              {!selectedRun ? (
                <EmptyState title="Select a run" detail="Target results and skip reasons appear here." />
              ) : (
                <div className="space-y-4 min-w-0">
                  <div className="rounded-md p-3" style={{ backgroundColor: 'var(--bg-2)' }}>
                    <div className="flex items-center justify-between gap-3 mb-2">
                      <StatusBadge status={selectedRun.status} />
                      <div className="flex items-center gap-2">
                        {selectedRunActive && (
                          <button
                            type="button"
                            onClick={cancelRun}
                            disabled={cancelling}
                            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs hover:brightness-110 disabled:opacity-60"
                            style={{ color: 'var(--crit)', backgroundColor: 'var(--crit-bg)' }}
                            title="Cancel targets that have not been dispatched yet"
                          >
                            {cancelling ? <Loader2 size={12} className="animate-spin" /> : <XCircle size={12} />}
                            Cancel pending
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => navigator.clipboard.writeText(selectedRun.query || selectedRun.query_hash || selectedRun.id)}
                          className="rounded p-1 hover:brightness-110"
                          style={{ color: 'var(--muted)' }}
                          title="Copy query"
                        >
                          <Copy size={14} />
                        </button>
                      </div>
                    </div>
                    <pre className="text-xs whitespace-pre-wrap break-words font-mono" style={{ color: 'var(--fg-2)' }}>
                      {selectedRun.query || `hash ${selectedRun.query_hash || '-'}`}
                    </pre>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    <SmallCount label="Targets" value={selectedRun.target_count} />
                    <SmallCount label="Completed" value={selectedRun.completed_count} />
                    <SmallCount label="Failed" value={selectedRun.failed_count} />
                    <SmallCount label="Skipped" value={selectedRun.skipped_count} />
                  </div>

                  <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                    <div className="relative min-w-0 md:w-64">
                      <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--muted)' }} />
                      <input
                        type="search"
                        value={targetSearch}
                        onChange={event => setTargetSearch(event.target.value)}
                        placeholder="Search targets"
                        className="w-full rounded-md border py-2 pl-9 pr-3 text-sm"
                        style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)', color: 'var(--fg)' }}
                      />
                    </div>

                    <div className="flex items-center gap-2">
                      <select
                        value={targetStatusFilter}
                        onChange={event => setTargetStatusFilter(event.target.value)}
                        className="rounded-md border px-3 py-2 text-sm"
                        style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)', color: 'var(--fg)' }}
                      >
                        <option value="all">All statuses</option>
                        <option value="queued">Queued</option>
                        <option value="sent">Sent</option>
                        <option value="acknowledged">Acknowledged</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                        <option value="skipped">Skipped</option>
                      </select>
                      <span className="text-xs whitespace-nowrap" style={{ color: 'var(--muted)' }}>
                        {filteredTargets.length}/{selectedTargets.length}
                      </span>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr style={{ color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>
                          <th className="text-left py-2 pr-3 font-medium">Agent</th>
                          <th className="text-left py-2 pr-3 font-medium">OS</th>
                          <th className="text-left py-2 pr-3 font-medium">Status</th>
                          <th className="text-left py-2 pr-3 font-medium">Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedTargets.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="py-8">
                              <EmptyState title="No target rows" detail="Refresh after the run has been queued." />
                            </td>
                          </tr>
                        ) : filteredTargets.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="py-8">
                              <EmptyState title="No matching targets" detail="Adjust the target search or status filter." />
                            </td>
                          </tr>
                        ) : filteredTargets.map(target => (
                          <tr key={target.id} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td className="py-3 pr-3">
                              <div className="font-medium" style={{ color: 'var(--fg)' }}>{target.hostname || compactId(target.agent_id)}</div>
                              <div className="font-mono text-xs" style={{ color: 'var(--muted)' }}>{compactId(target.agent_id)}</div>
                            </td>
                            <td className="py-3 pr-3" style={{ color: 'var(--fg-2)' }}>{target.os_type || '-'}</td>
                            <td className="py-3 pr-3"><StatusBadge status={target.status} /></td>
                            <td className="py-3 pr-3">
                              <TargetResult target={target} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </MainLayout>
  )
}

function Metric({ label, value, icon: Icon }: { label: string; value: number; icon: typeof Search }) {
  return (
    <div className="card-sentinel p-4 flex items-center gap-3">
      <div className="p-2 rounded" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--emerald-400)' }}>
        <Icon size={18} />
      </div>
      <div>
        <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value}</div>
        <div className="text-xs" style={{ color: 'var(--muted)' }}>{label}</div>
      </div>
    </div>
  )
}

function NumberField({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  return (
    <label className="block">
      <span className="text-xs font-medium" style={{ color: 'var(--muted)' }}>{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={event => onChange(Number(event.target.value))}
        className="mt-1 w-full rounded-md border px-3 py-2 text-sm"
        style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)', color: 'var(--fg)' }}
      />
    </label>
  )
}

function SmallCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md p-3" style={{ backgroundColor: 'var(--bg-2)' }}>
      <div className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{value || 0}</div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>{label}</div>
    </div>
  )
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="text-center py-8">
      <Terminal size={28} className="mx-auto mb-2 opacity-50" style={{ color: 'var(--muted)' }} />
      <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{title}</div>
      <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{detail}</div>
    </div>
  )
}

function TargetResult({ target }: { target: FleetQueryTarget }) {
  if (target.error) {
    return <span className="text-xs" style={{ color: 'var(--crit)' }}>{target.error}</span>
  }

  if (target.skip_reason) {
    return <span className="text-xs" style={{ color: 'var(--muted)' }}>{target.skip_reason}</span>
  }

  const summary = target.result_summary
  if (!summary) {
    return <span className="text-xs" style={{ color: 'var(--muted)' }}>Pending</span>
  }

  return (
    <div className="text-xs" style={{ color: 'var(--fg-2)' }}>
      <span>{summary.row_count ?? '-'} rows</span>
      {summary.truncated ? <span style={{ color: 'var(--high)' }}> truncated</span> : null}
      {summary.result_status ? <span style={{ color: 'var(--muted)' }}> {summary.result_status}</span> : null}
    </div>
  )
}
