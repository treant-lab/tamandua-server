import { Head } from '@inertiajs/react'
import { useMemo } from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  HelpCircle,
  RefreshCw,
  ShieldAlert,
  SlidersHorizontal,
  XCircle,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'

type HealthStatus = 'healthy' | 'degraded' | 'down' | 'not_configured'

interface HealthCoverage {
  covered: number | null
  total: number | null
  percent: number | null
  label: string
}

interface HealthItem {
  id: string
  name: string
  category: string
  status: HealthStatus
  last_seen?: string | null
  coverage: HealthCoverage
  gaps: string[]
  recommended_action: string
  owner: string
  surface: string
  reason: string
  metrics?: Record<string, unknown>
}

interface HealthHubProps {
  generated_at: string
  window_hours: number
  overall_status: HealthStatus
  status_counts: Record<HealthStatus, number>
  items: HealthItem[]
  platform_visibility?: unknown
  platformVisibility?: unknown
}

type PlatformVisibilityState = 'active' | 'degraded' | 'unavailable' | 'not_reported'

interface PlatformVisibilityRecord {
  id: string
  label: string
  platform?: string | null
  state: PlatformVisibilityState
  reasons: string[]
  evidenceSource?: string | null
  lastSeen?: string | null
  reported: boolean
}

interface PlatformVisibilityFleet {
  counts: Record<PlatformVisibilityState, number>
  total: number | null
  records: PlatformVisibilityRecord[]
  reasons: string[]
  evidenceSources: string[]
  lastSeen?: string | null
  hasApiData: boolean
}

interface EvidenceSessionMetrics {
  requested: number
  completed: number
  partial: number
  failed: number
  expired: number
  cancelled: number
  inFlight: number
  terminalAttempts: number
  successfulTerminal: number
  completionPercent: number | null
  failurePercent: number | null
  averageLatencyMs: number | null
  latencySamples: number
}

const statusLabels: Record<HealthStatus, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
  not_configured: 'Not configured',
}

const statusStyles: Record<HealthStatus, { bg: string; border: string; color: string }> = {
  healthy: {
    bg: 'rgba(47, 196, 113, 0.14)',
    border: 'rgba(47, 196, 113, 0.34)',
    color: 'var(--emerald-400)',
  },
  degraded: {
    bg: 'rgba(245, 165, 36, 0.14)',
    border: 'rgba(245, 165, 36, 0.34)',
    color: 'var(--high)',
  },
  down: {
    bg: 'rgba(240, 80, 110, 0.14)',
    border: 'rgba(240, 80, 110, 0.34)',
    color: 'var(--crit)',
  },
  not_configured: {
    bg: 'var(--surface-2)',
    border: 'var(--hairline)',
    color: 'var(--muted)',
  },
}

const platformVisibilityLabels: Record<PlatformVisibilityState, string> = {
  active: 'Active',
  degraded: 'Degraded',
  unavailable: 'Unavailable',
  not_reported: 'Not reported',
}

const platformVisibilityStyles: Record<PlatformVisibilityState, { bg: string; border: string; color: string }> = {
  active: statusStyles.healthy,
  degraded: statusStyles.degraded,
  unavailable: statusStyles.down,
  not_reported: statusStyles.not_configured,
}

function StatusIcon({ status }: { status: HealthStatus }) {
  if (status === 'healthy') return <CheckCircle2 className="h-4 w-4" />
  if (status === 'down') return <XCircle className="h-4 w-4" />
  if (status === 'not_configured') return <SlidersHorizontal className="h-4 w-4" />
  return <AlertTriangle className="h-4 w-4" />
}

function StatusBadge({ status }: { status: HealthStatus }) {
  const style = statusStyles[status]

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium"
      style={{ background: style.bg, border: `1px solid ${style.border}`, color: style.color }}
    >
      <StatusIcon status={status} />
      {statusLabels[status]}
    </span>
  )
}

function formatDate(value?: string | null): string {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

function coverageLabel(coverage: HealthCoverage): string {
  if (coverage.percent === null || coverage.percent === undefined) return coverage.label || 'Unknown'
  return `${coverage.percent}% - ${coverage.label}`
}

function statusCount(counts: Record<HealthStatus, number> | undefined, status: HealthStatus): number {
  return counts?.[status] || 0
}

function coerceObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

function getAny(source: Record<string, unknown> | null | undefined, keys: string[]): unknown {
  if (!source) return undefined
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null) return source[key]
  }
  return undefined
}

function firstText(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value
  }
  return null
}

function textArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map((item) => String(item)).filter(Boolean)
}

function normalizePlatformVisibilityState(value: unknown, reported = true): PlatformVisibilityState {
  if (!reported) return 'not_reported'
  const state = String(value || '').toLowerCase().replace(/[\s-]+/g, '_')
  if (state === 'active' || state === 'healthy' || state === 'observed') return 'active'
  if (state === 'degraded' || state === 'partial' || state === 'reported') return 'degraded'
  if (state === 'unavailable' || state === 'unsupported' || state === 'down') return 'unavailable'
  if (state === 'not_reported' || state === 'not_configured' || state === 'unknown' || state === '') return 'not_reported'
  return 'not_reported'
}

function normalizeCount(value: unknown): number {
  const count = Number(value)
  return Number.isFinite(count) && count > 0 ? count : 0
}

function nullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null
  const number = Number(value)
  return Number.isFinite(number) ? number : null
}

function normalizeEvidenceMetrics(value: unknown): EvidenceSessionMetrics {
  const raw = coerceObject(value) || {}
  return {
    requested: normalizeCount(getAny(raw, ['requested'])),
    completed: normalizeCount(getAny(raw, ['completed'])),
    partial: normalizeCount(getAny(raw, ['partial'])),
    failed: normalizeCount(getAny(raw, ['failed'])),
    expired: normalizeCount(getAny(raw, ['expired'])),
    cancelled: normalizeCount(getAny(raw, ['cancelled'])),
    inFlight: normalizeCount(getAny(raw, ['in_flight', 'inFlight'])),
    terminalAttempts: normalizeCount(getAny(raw, ['terminal_attempts', 'terminalAttempts'])),
    successfulTerminal: normalizeCount(getAny(raw, ['successful_terminal', 'successfulTerminal'])),
    completionPercent: nullableNumber(getAny(raw, ['completion_percent', 'completionPercent'])),
    failurePercent: nullableNumber(getAny(raw, ['failure_percent', 'failurePercent'])),
    averageLatencyMs: nullableNumber(getAny(raw, ['average_latency_ms', 'averageLatencyMs'])),
    latencySamples: normalizeCount(getAny(raw, ['latency_samples', 'latencySamples'])),
  }
}

function formatLatency(value: number | null): string {
  if (value === null) return 'Unknown'
  if (value < 1000) return `${Math.round(value)} ms`
  if (value < 60_000) return `${(value / 1000).toFixed(1)} s`
  return `${(value / 60_000).toFixed(1)} min`
}

function visibilityCountsFromRecords(records: PlatformVisibilityRecord[]): Record<PlatformVisibilityState, number> {
  return records.reduce(
    (counts, record) => {
      counts[record.state] += 1
      return counts
    },
    { active: 0, degraded: 0, unavailable: 0, not_reported: 0 }
  )
}

function endpointAgentTotal(items: HealthItem[]): number | null {
  const endpointItem = items.find((item) => item.id === 'endpoint_agents')
  const total = endpointItem?.metrics?.total ?? endpointItem?.coverage?.total
  return typeof total === 'number' && Number.isFinite(total) ? total : null
}

function normalizePlatformVisibilityRecord(value: unknown, index: number): PlatformVisibilityRecord | null {
  const raw = coerceObject(value)
  if (!raw) return null
  const evidence = coerceObject(getAny(raw, ['evidence'])) || null
  const agentHealth = coerceObject(getAny(evidence, ['agent_health_visibility', 'agentHealthVisibility'])) || null
  const reported = getAny(raw, ['reported', 'is_reported', 'isReported']) !== false
  const state = normalizePlatformVisibilityState(getAny(raw, ['status', 'state', 'visibility', 'health']), reported)
  const label =
    firstText(
      getAny(raw, ['hostname', 'host', 'agent_name', 'agentName', 'name']),
      getAny(raw, ['agent_id', 'agentId', 'id'])
    ) || `Agent ${index + 1}`
  const reasons = [
    ...textArray(getAny(raw, ['reasons', 'reason_codes', 'reasonCodes'])),
    ...textArray(getAny(agentHealth, ['reasons'])),
    firstText(getAny(raw, ['reason', 'detail'])) || '',
  ].filter(Boolean)
  const evidenceSources = textArray(getAny(evidence, ['sources'])).join(', ')

  return {
    id: firstText(getAny(raw, ['agent_id', 'agentId', 'id']), label) || `agent-${index}`,
    label,
    platform: firstText(getAny(raw, ['platform', 'os', 'os_type', 'osType'])),
    state,
    reasons: reasons.length > 0 ? Array.from(new Set(reasons)) : ['No reason was reported.'],
    evidenceSource:
      firstText(
        getAny(raw, ['evidence_source', 'evidenceSource', 'source']),
        getAny(agentHealth, ['evidence_source', 'evidenceSource']),
        evidenceSources
      ),
    lastSeen: firstText(
      getAny(raw, ['last_seen', 'lastSeen', 'checked_at', 'checkedAt']),
      getAny(evidence, ['last_observed_at', 'lastObservedAt'])
    ),
    reported,
  }
}

function platformVisibilityRecords(input: Record<string, unknown>): PlatformVisibilityRecord[] {
  const candidates = [
    getAny(input, ['agents']),
    getAny(input, ['records']),
    getAny(input, ['items']),
    getAny(input, ['rows']),
    getAny(input, ['by_agent', 'byAgent']),
  ]
  const rows = candidates.find(Array.isArray)
  if (!Array.isArray(rows)) return []
  return rows
    .map((row, index) => normalizePlatformVisibilityRecord(row, index))
    .filter((row): row is PlatformVisibilityRecord => row !== null)
}

function normalizePlatformVisibilityFleet(
  value: unknown,
  items: HealthItem[]
): PlatformVisibilityFleet {
  const raw = coerceObject(value)
  const fallbackTotal = endpointAgentTotal(items)
  if (!raw) {
    return {
      counts: {
        active: 0,
        degraded: 0,
        unavailable: 0,
        not_reported: fallbackTotal || 0,
      },
      total: fallbackTotal,
      records: [],
      reasons: ['Health Hub API did not return platform visibility aggregation.'],
      evidenceSources: [],
      lastSeen: null,
      hasApiData: false,
    }
  }

  const records = platformVisibilityRecords(raw)
  const countSource = coerceObject(getAny(raw, ['status_counts', 'statusCounts', 'counts'])) || {}
  const counts = records.length > 0
    ? visibilityCountsFromRecords(records)
    : {
        active: normalizeCount(getAny(countSource, ['active'])),
        degraded: normalizeCount(getAny(countSource, ['degraded'])),
        unavailable: normalizeCount(getAny(countSource, ['unavailable'])),
        not_reported: normalizeCount(getAny(countSource, ['not_reported', 'notReported', 'unknown'])),
      }
  const countedTotal = counts.active + counts.degraded + counts.unavailable + counts.not_reported
  const total = normalizeCount(getAny(raw, ['total', 'total_agents', 'totalAgents'])) || countedTotal || fallbackTotal
  if (total && countedTotal < total) counts.not_reported += total - countedTotal

  const reasons = Array.from(new Set([
    ...textArray(getAny(raw, ['reasons'])),
    ...records.flatMap((record) => record.reasons),
  ])).slice(0, 8)
  const evidenceSources = Array.from(new Set([
    ...textArray(getAny(raw, ['evidence_sources', 'evidenceSources', 'sources'])),
    ...records.map((record) => record.evidenceSource).filter(Boolean),
    firstText(getAny(raw, ['evidence_source', 'evidenceSource', 'source'])) || '',
  ].filter(Boolean) as string[])).slice(0, 6)

  return {
    counts,
    total: total || null,
    records,
    reasons: reasons.length > 0 ? reasons : ['Platform visibility API returned aggregation without reasons.'],
    evidenceSources,
    lastSeen: firstText(
      getAny(raw, ['last_seen', 'lastSeen', 'generated_at', 'generatedAt', 'checked_at', 'checkedAt']),
      ...records.map((record) => record.lastSeen)
    ),
    hasApiData: true,
  }
}

function StatCard({
  label,
  value,
  status,
}: {
  label: string
  value: number | string
  status: HealthStatus
}) {
  const style = statusStyles[status]

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm" style={{ color: 'var(--muted)' }}>{label}</div>
          <div className="mt-2 text-3xl font-semibold" style={{ color: 'var(--fg)' }}>{value}</div>
        </div>
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{ background: style.bg, color: style.color, border: `1px solid ${style.border}` }}
        >
          <StatusIcon status={status} />
        </div>
      </div>
    </div>
  )
}

function PlatformVisibilityStateIcon({ state }: { state: PlatformVisibilityState }) {
  if (state === 'active') return <CheckCircle2 className="h-4 w-4" />
  if (state === 'degraded') return <AlertTriangle className="h-4 w-4" />
  if (state === 'unavailable') return <XCircle className="h-4 w-4" />
  return <HelpCircle className="h-4 w-4" />
}

function PlatformVisibilityBadge({ state }: { state: PlatformVisibilityState }) {
  const style = platformVisibilityStyles[state]

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium"
      style={{ background: style.bg, border: `1px solid ${style.border}`, color: style.color }}
    >
      <PlatformVisibilityStateIcon state={state} />
      {platformVisibilityLabels[state]}
    </span>
  )
}

function PlatformVisibilityPanel({ fleet }: { fleet: PlatformVisibilityFleet }) {
  const states: PlatformVisibilityState[] = ['active', 'degraded', 'unavailable', 'not_reported']
  const sampleRecords = fleet.records.slice(0, 5)

  return (
    <div className="card-sentinel">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Fleet platform visibility</h2>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            Aggregated endpoint platform visibility boundaries across active, degraded, unavailable, and not reported agents.
          </p>
        </div>
        <div className="text-sm" style={{ color: 'var(--muted)' }}>
          Last seen {formatDate(fleet.lastSeen)}
        </div>
      </div>

      {!fleet.hasApiData && (
        <div
          className="mt-4 rounded p-3 text-sm"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--hairline)', color: 'var(--muted)' }}
        >
          Platform visibility was not included in the Health Hub API response. Agents are counted as not reported, not unavailable.
        </div>
      )}

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {states.map((state) => {
          const style = platformVisibilityStyles[state]
          return (
            <div key={state} className="rounded p-4" style={{ background: style.bg, border: `1px solid ${style.border}` }}>
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-medium" style={{ color: style.color }}>{platformVisibilityLabels[state]}</div>
                <PlatformVisibilityStateIcon state={state} />
              </div>
              <div className="mt-2 text-3xl font-semibold" style={{ color: 'var(--fg)' }}>
                {fleet.total === null && state === 'not_reported' ? 'Unknown' : fleet.counts[state]}
              </div>
            </div>
          )
        })}
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Reasons</div>
          <div className="mt-2 space-y-1">
            {fleet.reasons.map((reason) => (
              <div key={reason} className="text-sm" style={{ color: 'var(--muted)' }}>{reason}</div>
            ))}
          </div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Evidence source</div>
          <div className="mt-2 space-y-1">
            {fleet.evidenceSources.length > 0 ? fleet.evidenceSources.map((source) => (
              <div key={source} className="text-sm" style={{ color: 'var(--fg-2)' }}>{source}</div>
            )) : (
              <div className="text-sm" style={{ color: 'var(--muted)' }}>No evidence source was reported.</div>
            )}
          </div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Agent evidence</div>
          <div className="mt-2 space-y-2">
            {sampleRecords.length > 0 ? sampleRecords.map((record) => (
              <div key={record.id} className="flex items-start justify-between gap-3 text-sm">
                <div>
                  <div style={{ color: 'var(--fg-2)' }}>{record.label}</div>
                  <div className="text-xs" style={{ color: 'var(--subtle)' }}>
                    {[record.platform, record.evidenceSource, formatDate(record.lastSeen)].filter(Boolean).join(' - ')}
                  </div>
                </div>
                <PlatformVisibilityBadge state={record.state} />
              </div>
            )) : (
              <div className="text-sm" style={{ color: 'var(--muted)' }}>No per-agent visibility evidence was reported.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function EvidenceSessionMetricsPanel({ item, windowHours }: { item?: HealthItem; windowHours: number }) {
  if (!item) return null

  const metrics = normalizeEvidenceMetrics(item.metrics)
  const raw = coerceObject(item.metrics) || {}
  const byPlatform = coerceObject(getAny(raw, ['by_platform', 'byPlatform'])) || {}
  const platforms = Object.entries(byPlatform)
    .map(([platform, value]) => ({ platform, metrics: normalizeEvidenceMetrics(value) }))
    .sort((left, right) => left.platform.localeCompare(right.platform))

  return (
    <div className="card-sentinel">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Evidence session operations</h2>
            <StatusBadge status={item.status} />
          </div>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            Persisted tenant outcomes in this {windowHours}h window. Completion excludes sessions still running and operator cancellations.
          </p>
        </div>
        <div className="text-sm" style={{ color: 'var(--muted)' }}>
          Last activity {formatDate(item.last_seen)}
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <EvidenceMetric label="Requested" value={metrics.requested} />
        <EvidenceMetric
          label="Terminal completion"
          value={metrics.completionPercent === null ? 'Unknown' : `${metrics.completionPercent}%`}
          detail={`${metrics.successfulTerminal}/${metrics.terminalAttempts} outcomes`}
        />
        <EvidenceMetric
          label="Failures"
          value={metrics.failurePercent === null ? 'Unknown' : `${metrics.failurePercent}%`}
          detail={`${metrics.failed} failed, ${metrics.expired} expired`}
        />
        <EvidenceMetric label="Average latency" value={formatLatency(metrics.averageLatencyMs)} detail={`${metrics.latencySamples} samples`} />
        <EvidenceMetric label="In flight" value={metrics.inFlight} detail={`${metrics.cancelled} cancelled`} />
      </div>

      <div className="mt-5 overflow-x-auto rounded" style={{ border: '1px solid var(--hairline)' }}>
        <table className="w-full min-w-[760px] text-left">
          <thead style={{ background: 'var(--surface-2)' }}>
            <tr>
              {['Platform', 'Requested', 'Completed / partial', 'Failed / expired', 'In flight', 'Average latency'].map((heading) => (
                <th key={heading} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {platforms.map(({ platform, metrics: platformMetrics }) => (
              <tr key={platform} style={{ borderTop: '1px solid var(--hairline)' }}>
                <td className="px-4 py-3 text-sm font-medium capitalize" style={{ color: 'var(--fg)' }}>{platform}</td>
                <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>{platformMetrics.requested}</td>
                <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>{platformMetrics.completed} / {platformMetrics.partial}</td>
                <td className="px-4 py-3 text-sm" style={{ color: platformMetrics.failed + platformMetrics.expired > 0 ? 'var(--crit)' : 'var(--fg-2)' }}>{platformMetrics.failed} / {platformMetrics.expired}</td>
                <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>{platformMetrics.inFlight}</td>
                <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>{formatLatency(platformMetrics.averageLatencyMs)}</td>
              </tr>
            ))}
            {platforms.length === 0 && (
              <tr style={{ borderTop: '1px solid var(--hairline)' }}>
                <td colSpan={6} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--muted)' }}>
                  No evidence-session platform outcomes were observed in this window.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function EvidenceMetric({ label, value, detail }: { label: string; value: number | string; detail?: string }) {
  return (
    <div className="rounded p-4" style={{ background: 'var(--surface-2)', border: '1px solid var(--hairline)' }}>
      <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>{label}</div>
      <div className="mt-2 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>{value}</div>
      {detail && <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>{detail}</div>}
    </div>
  )
}

function HealthRow({ item }: { item: HealthItem }) {
  return (
    <tr style={{ borderTop: '1px solid var(--hairline)' }}>
      <td className="p-4 align-top">
        <div className="font-medium" style={{ color: 'var(--fg)' }}>{item.name}</div>
        <div className="mt-1 text-xs uppercase" style={{ color: 'var(--subtle)' }}>{item.category}</div>
      </td>
      <td className="p-4 align-top">
        <StatusBadge status={item.status} />
      </td>
      <td className="p-4 align-top">
        <div className="text-sm" style={{ color: 'var(--fg-2)' }}>{coverageLabel(item.coverage)}</div>
        {item.coverage.percent !== null && item.coverage.percent !== undefined && (
          <div className="mt-2 h-2 w-32 overflow-hidden rounded-full" style={{ background: 'var(--surface-2)' }}>
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max(0, Math.min(100, item.coverage.percent))}%`,
                background:
                  item.status === 'healthy'
                    ? 'var(--emerald-500)'
                    : item.status === 'down'
                      ? 'var(--crit)'
                      : 'var(--high)',
              }}
            />
          </div>
        )}
      </td>
      <td className="p-4 align-top text-sm" style={{ color: 'var(--muted)' }}>
        {formatDate(item.last_seen)}
      </td>
      <td className="p-4 align-top">
        <div className="text-sm" style={{ color: 'var(--fg-2)' }}>{item.owner}</div>
        <div className="mt-1 text-xs" style={{ color: 'var(--subtle)' }}>{item.surface}</div>
      </td>
      <td className="p-4 align-top">
        <div className="max-w-sm text-sm" style={{ color: 'var(--muted)' }}>{item.reason}</div>
        {item.gaps.length > 0 && (
          <div className="mt-2 space-y-1">
            {item.gaps.map((gap) => (
              <div key={gap} className="text-xs" style={{ color: 'var(--high)' }}>{gap}</div>
            ))}
          </div>
        )}
      </td>
      <td className="p-4 align-top">
        <div className="max-w-xs text-sm" style={{ color: 'var(--fg-2)' }}>
          {item.recommended_action}
        </div>
      </td>
    </tr>
  )
}

export default function HealthHub({
  generated_at,
  window_hours = 24,
  overall_status = 'degraded',
  status_counts = {
    healthy: 0,
    degraded: 0,
    down: 0,
    not_configured: 0,
  },
  items = [],
  platform_visibility,
  platformVisibility,
}: HealthHubProps) {
  const total = items.length
  const needsAction = items.filter((item) => item.status === 'degraded' || item.status === 'down')
  const platformVisibilityFleet = useMemo(
    () => normalizePlatformVisibilityFleet(platformVisibility || platform_visibility, items),
    [items, platformVisibility, platform_visibility]
  )

  return (
    <MainLayout title="Health Hub">
      <Head title="Health Hub" />

      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold" style={{ color: 'var(--fg)' }}>Health Hub</h1>
              <StatusBadge status={overall_status} />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-4 text-sm" style={{ color: 'var(--muted)' }}>
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-4 w-4" />
                Last generated {formatDate(generated_at)}
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Activity className="h-4 w-4" />
                {window_hours}h telemetry window
              </span>
            </div>
          </div>

          <button
            className="btn-sentinel btn-sentinel-secondary"
            type="button"
            onClick={() => window.location.reload()}
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <StatCard label="Surfaces" value={total} status={overall_status} />
          <StatCard label="Healthy" value={statusCount(status_counts, 'healthy')} status="healthy" />
          <StatCard label="Degraded" value={statusCount(status_counts, 'degraded')} status="degraded" />
          <StatCard label="Down" value={statusCount(status_counts, 'down')} status="down" />
          <StatCard label="Not configured" value={statusCount(status_counts, 'not_configured')} status="not_configured" />
        </div>

        <PlatformVisibilityPanel fleet={platformVisibilityFleet} />

        <EvidenceSessionMetricsPanel
          item={items.find((item) => item.id === 'evidence_sessions')}
          windowHours={window_hours}
        />

        {needsAction.length > 0 && (
          <div
            className="rounded-lg p-4"
            style={{
              background: 'rgba(245, 165, 36, 0.10)',
              border: '1px solid rgba(245, 165, 36, 0.28)',
            }}
          >
            <div className="flex items-start gap-3">
              <ShieldAlert className="mt-0.5 h-5 w-5" style={{ color: 'var(--high)' }} />
              <div>
                <div className="font-medium" style={{ color: 'var(--fg)' }}>
                  {needsAction.length} surface(s) need attention
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                  Prioritize down controls first, then degraded telemetry sources with unknown or stale coverage.
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="card-sentinel" style={{ padding: 0 }}>
          <div className="flex items-center justify-between gap-4 p-4" style={{ borderBottom: '1px solid var(--hairline)' }}>
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Control surface health</h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                Unified health, coverage gaps, owners, and recommended operator actions.
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[1120px] text-left">
              <thead>
                <tr>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Surface</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Status</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Coverage</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Last seen</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Owner</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Gaps</th>
                  <th className="p-4 text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Recommended action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => <HealthRow key={item.id} item={item} />)}
                {items.length === 0 && (
                  <tr style={{ borderTop: '1px solid var(--hairline)' }}>
                    <td colSpan={7} className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                      No health surfaces were returned by the Health Hub API.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
