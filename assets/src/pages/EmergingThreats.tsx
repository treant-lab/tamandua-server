import { Head } from '@inertiajs/react'
import {
  AlertCircle,
  AlertTriangle,
  Archive,
  Box,
  Briefcase,
  CheckCircle2,
  Clock,
  Crosshair,
  Database,
  FileSearch,
  FlaskConical,
  Gauge,
  PackagePlus,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { MainLayout } from '@/layouts/MainLayout'
import { cn } from '@/lib/utils'

type ThreatStatus = 'active' | 'watching' | 'contained' | 'stale' | 'unknown'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type SourceStatus = 'healthy' | 'degraded' | 'offline' | 'unknown'
type ExposureState = 'exposed' | 'partial' | 'covered' | 'unknown'

interface IOC {
  type: string
  value: string
  confidence?: number
  source?: string
}

interface TTP {
  id: string
  name?: string
  tactic?: string
}

interface AffectedProduct {
  vendor?: string
  name: string
  versions?: string[]
  cves?: string[]
}

interface LocalExposure {
  state: ExposureState
  exposedAssets?: number
  matchingAgents?: number
  agentIds?: string[]
  matchedProducts?: Array<Record<string, unknown>>
  matchedCves?: Array<Record<string, unknown>>
  telemetryMatches?: Array<Record<string, unknown>>
  notes?: string[]
  gaps?: string[]
}

interface EmergingAction {
  action?: string
  integration_ref?: string
  state?: string
  payload?: Record<string, unknown>
  execution?: string
}

interface EmergingThreat {
  id: string
  title: string
  summary?: string
  status: ThreatStatus
  severity: Severity
  score: number
  confidence?: number
  source?: string
  firstSeen?: string
  lastUpdated?: string
  iocs?: IOC[]
  ttps?: TTP[]
  affectedProducts?: AffectedProduct[]
  localExposure?: LocalExposure
  recommendedHunts?: Array<Record<string, unknown>>
  recommendedActions?: EmergingAction[]
  tags?: string[]
}

interface SourceHealth {
  id: string
  name: string
  status: SourceStatus
  lastSync?: string
  itemsIngested?: number
  lagMinutes?: number
  detail?: string
}

interface ContextHealthSource {
  name: string
  capability?: string
  state: 'available' | 'degraded' | 'unknown' | string
  records?: number
}

interface ContextHealth {
  state?: 'available' | 'degraded' | 'unknown' | string
  reason?: string
  gaps?: string[]
  counts?: {
    assets?: number
    software_inventory?: number
    vulnerabilities?: number
    telemetry?: number
  }
  sources?: ContextHealthSource[]
}

interface EmergingThreatsProps {
  page_title?: string
  threats?: EmergingThreat[]
  emergingThreats?: EmergingThreat[]
  source_health?: SourceHealth[]
  sourceHealth?: SourceHealth[]
  contextHealth?: ContextHealth
  generated_at?: string
  generatedAt?: string
}

type ActionKind = 'hunt' | 'detection-pack' | 'collect-evidence' | 'create-case'

interface ActionState {
  kind: ActionKind
  status: 'idle' | 'running' | 'success' | 'error'
  message?: string
  result?: unknown
}

const severityStyles: Record<Severity, string> = {
  critical: 'border-[var(--crit)]/30 bg-[var(--crit)]/10 text-[var(--crit)]',
  high: 'border-[var(--high)]/30 bg-[var(--high)]/10 text-[var(--high)]',
  medium: 'border-[var(--med)]/30 bg-[var(--med)]/10 text-[var(--med)]',
  low: 'border-[var(--emerald-400)]/30 bg-[var(--emerald-400)]/10 text-[var(--emerald-400)]',
  info: 'border-cyan-400/30 bg-cyan-500/10 text-cyan-200',
}

const statusStyles: Record<ThreatStatus, string> = {
  active: 'border-[var(--crit)]/30 bg-[var(--crit)]/10 text-[var(--crit)]',
  watching: 'border-[var(--high)]/30 bg-[var(--high)]/10 text-[var(--high)]',
  contained: 'border-[var(--emerald-400)]/30 bg-[var(--emerald-400)]/10 text-[var(--emerald-400)]',
  stale: 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]',
  unknown: 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]',
}

const sourceStyles: Record<SourceStatus, { className: string; icon: typeof CheckCircle2; label: string }> = {
  healthy: { className: 'text-[var(--emerald-400)]', icon: CheckCircle2, label: 'Healthy' },
  degraded: { className: 'text-[var(--high)]', icon: AlertCircle, label: 'Degraded' },
  offline: { className: 'text-[var(--crit)]', icon: AlertTriangle, label: 'Offline' },
  unknown: { className: 'text-[var(--muted)]', icon: AlertCircle, label: 'Unknown' },
}

function safeArray<T>(value: T[] | undefined): T[] {
  return Array.isArray(value) ? value : []
}

function normalizeSeverity(value: string | undefined): Severity {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'info') return value
  return 'info'
}

function normalizeStatus(value: string | undefined): ThreatStatus {
  if (value === 'active' || value === 'watching' || value === 'contained' || value === 'stale') return value
  return 'unknown'
}

function normalizeSourceStatus(value: string | undefined): SourceStatus {
  if (value === 'healthy' || value === 'degraded' || value === 'offline') return value
  return 'unknown'
}

function normalizeExposureState(value: string | undefined): ExposureState {
  if (value === 'exposed' || value === 'partial' || value === 'covered') return value
  return 'unknown'
}

function formatNumber(value: number | undefined): string {
  return Number.isFinite(value) ? Number(value).toLocaleString() : '0'
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

async function postJson<T>(url: string, body: Record<string, unknown> = {}): Promise<T> {
  const token = getCsrfToken()
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-CSRF-Token': token } : {}),
    },
    body: JSON.stringify(body),
  })

  const payload = await response.json().catch(() => ({}))

  if (!response.ok) {
    const message =
      typeof payload?.error === 'string'
        ? payload.error
        : typeof payload?.message === 'string'
          ? payload.message
          : `Request failed with ${response.status}`
    throw new Error(message)
  }

  return payload as T
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { credentials: 'include' })
  const payload = await response.json().catch(() => ({}))

  if (!response.ok) {
    const message =
      typeof payload?.error === 'string'
        ? payload.error
        : typeof payload?.message === 'string'
          ? payload.message
          : `Request failed with ${response.status}`
    throw new Error(message)
  }

  return payload as T
}

function Badge({ children, className }: { children: React.ReactNode; className: string }) {
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium capitalize', className)}>
      {children}
    </span>
  )
}

function ActionButton({
  icon: Icon,
  label,
  title,
  disabled,
  busy,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  title?: string
  disabled?: boolean
  busy?: boolean
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      disabled={disabled || busy}
      title={title}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
        disabled || busy
          ? 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] opacity-70'
          : 'border-[var(--emerald-500)]/35 bg-[var(--emerald-500)]/10 text-[var(--emerald-300)] hover:bg-[var(--emerald-500)]/20'
      )}
    >
      <Icon className="h-4 w-4" />
      {busy ? 'Working...' : label}
    </button>
  )
}

function EmptyPanel({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--surface)]/35 p-5 text-sm text-[var(--muted)]">
      <span className="inline-flex items-center gap-2">
        <AlertCircle className="h-4 w-4 text-[var(--high)]" />
        {message}
      </span>
    </div>
  )
}

function ScoreRing({ score }: { score: number }) {
  const bounded = Math.max(0, Math.min(100, Number(score) || 0))
  const color = bounded >= 85 ? 'var(--crit)' : bounded >= 65 ? 'var(--high)' : bounded >= 40 ? 'var(--med)' : 'var(--emerald-400)'

  return (
    <div
      className="flex h-20 w-20 shrink-0 items-center justify-center rounded-full"
      style={{ background: `conic-gradient(${color} ${bounded * 3.6}deg, var(--surface-2) 0deg)` }}
    >
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--surface)]">
        <span className="text-xl font-bold text-[var(--fg)]">{bounded}</span>
      </div>
    </div>
  )
}

function SourceHealthRow({ source }: { source: SourceHealth }) {
  const status = normalizeSourceStatus(source.status)
  const style = sourceStyles[status]
  const Icon = style.icon

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-medium text-[var(--fg)]">{source.name}</p>
          <p className="mt-1 text-xs text-[var(--muted)]">{source.detail || 'No source detail reported.'}</p>
        </div>
        <span className={cn('inline-flex items-center gap-1.5 text-xs font-medium', style.className)}>
          <Icon className="h-3.5 w-3.5" />
          {style.label}
        </span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
        <div>
          <p className="text-[var(--subtle)]">Last sync</p>
          <p className="mt-1 truncate text-[var(--fg-2)]">{source.lastSync || 'N/A'}</p>
        </div>
        <div>
          <p className="text-[var(--subtle)]">Items</p>
          <p className="mt-1 text-[var(--fg-2)]">{formatNumber(source.itemsIngested)}</p>
        </div>
        <div>
          <p className="text-[var(--subtle)]">Lag</p>
          <p className="mt-1 text-[var(--fg-2)]">{source.lagMinutes == null ? 'N/A' : `${source.lagMinutes}m`}</p>
        </div>
      </div>
    </div>
  )
}

function ContextHealthPanel({ contextHealth }: { contextHealth?: ContextHealth }) {
  const counts = contextHealth?.counts || {}
  const gaps = safeArray(contextHealth?.gaps)
  const sources = safeArray(contextHealth?.sources)
  const state = contextHealth?.state || 'unknown'

  return (
    <div className="card-sentinel p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold text-[var(--fg)]">
            <ShieldCheck className="h-4 w-4 text-[var(--emerald-400)]" />
            Local Context Health
          </h2>
          <p className="mt-1 text-xs text-[var(--muted)]">{contextHealth?.reason || 'Tenant exposure context used for local matching.'}</p>
        </div>
        <Badge className={state === 'available' ? sourceStyles.healthy.className + ' border-[var(--emerald-400)]/30 bg-[var(--emerald-400)]/10' : sourceStyles.degraded.className + ' border-[var(--high)]/30 bg-[var(--high)]/10'}>
          {state}
        </Badge>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-lg bg-[var(--surface)]/50 p-3">
          <p className="text-[var(--subtle)]">Assets</p>
          <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(counts.assets)}</p>
        </div>
        <div className="rounded-lg bg-[var(--surface)]/50 p-3">
          <p className="text-[var(--subtle)]">Software</p>
          <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(counts.software_inventory)}</p>
        </div>
        <div className="rounded-lg bg-[var(--surface)]/50 p-3">
          <p className="text-[var(--subtle)]">Vulns</p>
          <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(counts.vulnerabilities)}</p>
        </div>
        <div className="rounded-lg bg-[var(--surface)]/50 p-3">
          <p className="text-[var(--subtle)]">Telemetry</p>
          <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(counts.telemetry)}</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {sources.map(source => (
          <div key={source.name} className="flex items-center justify-between gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface)]/35 px-3 py-2 text-xs">
            <span className="min-w-0 truncate text-[var(--fg-2)]">{source.name} / {source.capability || 'capability unknown'}</span>
            <span className={source.state === 'available' ? 'text-[var(--emerald-400)]' : 'text-[var(--high)]'}>
              {source.state} ({formatNumber(source.records)})
            </span>
          </div>
        ))}
        {gaps.map(gap => (
          <div key={gap} className="rounded-lg border border-[var(--high)]/25 bg-[var(--high)]/10 px-3 py-2 text-xs text-[var(--fg-2)]">
            {gap}
          </div>
        ))}
      </div>
    </div>
  )
}

function ThreatListItem({ threat, selected, onSelect }: { threat: EmergingThreat; selected: boolean; onSelect: () => void }) {
  const severity = normalizeSeverity(threat.severity)
  const status = normalizeStatus(threat.status)

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'w-full rounded-lg border p-4 text-left transition-colors',
        selected ? 'border-[var(--emerald-500)] bg-[var(--emerald-500)]/10' : 'border-[var(--border)] bg-[var(--surface)]/45 hover:border-[var(--fg-2)]'
      )}
    >
      <div className="flex items-start gap-3">
        <ScoreRing score={threat.score} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="truncate text-base font-semibold text-[var(--fg)]">{threat.title}</h3>
            <Badge className={severityStyles[severity]}>{severity}</Badge>
            <Badge className={statusStyles[status]}>{status}</Badge>
          </div>
          <p className="mt-2 line-clamp-2 text-sm text-[var(--muted)]">{threat.summary || 'No summary provided by threat source.'}</p>
          <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-[var(--subtle)]">
            <span className="inline-flex items-center gap-1"><Database className="h-3.5 w-3.5" />{threat.source || 'source unknown'}</span>
            <span className="inline-flex items-center gap-1"><Clock className="h-3.5 w-3.5" />{threat.lastUpdated || threat.firstSeen || 'time unknown'}</span>
            <span>{safeArray(threat.iocs).length} IOCs</span>
            <span>{safeArray(threat.ttps).length} TTPs</span>
          </div>
        </div>
      </div>
    </button>
  )
}

function agentIdsForThreat(threat: EmergingThreat): string[] {
  return safeArray(threat.localExposure?.agentIds)
    .map(String)
    .filter(Boolean)
}

function DetailPanel({ threat }: { threat: EmergingThreat | null }) {
  const [actionState, setActionState] = useState<ActionState>({ kind: 'hunt', status: 'idle' })

  useEffect(() => {
    setActionState({ kind: 'hunt', status: 'idle' })
  }, [threat?.id])

  if (!threat) {
    return (
      <div className="card-sentinel p-5">
        <EmptyPanel message="No emerging threat selected because no threat props were provided." />
      </div>
    )
  }

  const severity = normalizeSeverity(threat.severity)
  const status = normalizeStatus(threat.status)
  const exposure = threat.localExposure || { state: 'unknown' }
  const exposureState = normalizeExposureState(exposure.state)
  const iocs = safeArray(threat.iocs)
  const ttps = safeArray(threat.ttps)
  const products = safeArray(threat.affectedProducts)
  const gaps = safeArray(exposure.gaps)
  const notes = safeArray(exposure.notes)
  const agentIds = agentIdsForThreat(threat)
  const matchedProducts = safeArray(exposure.matchedProducts)
  const matchedCves = safeArray(exposure.matchedCves)
  const telemetryMatches = safeArray(exposure.telemetryMatches)
  const runningKind = actionState.status === 'running' ? actionState.kind : null

  const runAction = async (kind: ActionKind) => {
    setActionState({ kind, status: 'running' })

    try {
      if (kind === 'hunt') {
        setActionState({
          kind,
          status: 'success',
          message: `${safeArray(threat.recommendedHunts).length} hunt queries are available below.`,
          result: threat.recommendedHunts || [],
        })
        return
      }

      if (kind === 'detection-pack') {
        const result = await getJson<{ data?: unknown }>(`/api/v1/emerging-threats/${encodeURIComponent(threat.id)}/detection-pack`)
        setActionState({ kind, status: 'success', message: 'Detection pack candidate generated for review.', result: result.data || result })
        return
      }

      if (kind === 'collect-evidence') {
        if (agentIds.length === 0) {
          setActionState({
            kind,
            status: 'error',
            message: 'No exposed or matching agent was identified. Run software inventory, vulnerability scan, or telemetry collection first.',
          })
          return
        }

        const result = await postJson(`/api/v1/emerging-threats/${encodeURIComponent(threat.id)}/collect-evidence`, {
          agent_ids: agentIds,
          scope: 'ioc_context',
        })
        setActionState({ kind, status: 'success', message: `Evidence collection requested for ${agentIds.length} agent(s).`, result })
        return
      }

      const result = await postJson<{ data?: { id?: string; title?: string } }>(
        `/api/v1/emerging-threats/${encodeURIComponent(threat.id)}/create-case`,
        {}
      )
      const caseId = result.data?.id
      setActionState({
        kind,
        status: 'success',
        message: caseId ? `Case created: ${result.data?.title || caseId}` : 'Case created.',
        result,
      })
    } catch (error) {
      setActionState({
        kind,
        status: 'error',
        message: error instanceof Error ? error.message : 'Action failed',
      })
    }
  }

  return (
    <div className="space-y-5">
      <div className="card-sentinel p-5">
        <div className="flex items-start gap-4">
          <ScoreRing score={threat.score} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={severityStyles[severity]}>{severity}</Badge>
              <Badge className={statusStyles[status]}>{status}</Badge>
              {threat.confidence != null && (
                <Badge className="border-cyan-400/30 bg-cyan-500/10 text-cyan-200">{threat.confidence}% confidence</Badge>
              )}
            </div>
            <h2 className="mt-3 text-xl font-bold text-[var(--fg)]">{threat.title}</h2>
            <p className="mt-2 text-sm text-[var(--fg-2)]">{threat.summary || 'No source summary provided.'}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <ActionButton
                icon={Crosshair}
                label="Hunt related"
                busy={runningKind === 'hunt'}
                disabled={safeArray(threat.recommendedHunts).length === 0}
                title={safeArray(threat.recommendedHunts).length === 0 ? 'No recommended hunts were generated for this threat.' : 'Show recommended hunt queries.'}
                onClick={() => runAction('hunt')}
              />
              <ActionButton
                icon={PackagePlus}
                label="Create detection pack"
                busy={runningKind === 'detection-pack'}
                title="Generate a detection pack candidate for validation."
                onClick={() => runAction('detection-pack')}
              />
              <ActionButton
                icon={Archive}
                label="Collect evidence"
                busy={runningKind === 'collect-evidence'}
                disabled={agentIds.length === 0}
                title={agentIds.length === 0 ? 'Requires explicit matched/exposed agents from local exposure.' : `Queue forensic evidence collection for ${agentIds.length} agent(s).`}
                onClick={() => runAction('collect-evidence')}
              />
              <ActionButton
                icon={Briefcase}
                label="Create case"
                busy={runningKind === 'create-case'}
                title="Create an investigation case from this threat."
                onClick={() => runAction('create-case')}
              />
            </div>
            {actionState.status !== 'idle' && (
              <div
                className={cn(
                  'mt-4 rounded-lg border px-3 py-2 text-sm',
                  actionState.status === 'success'
                    ? 'border-[var(--emerald-500)]/30 bg-[var(--emerald-500)]/10 text-[var(--emerald-200)]'
                    : actionState.status === 'error'
                      ? 'border-[var(--crit)]/30 bg-[var(--crit)]/10 text-[var(--crit)]'
                      : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]'
                )}
              >
                {actionState.message || 'Action running...'}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <div className="card-sentinel p-5">
          <h3 className="mb-4 flex items-center gap-2 font-semibold text-[var(--fg)]">
            <ShieldAlert className="h-4 w-4 text-[var(--emerald-400)]" />
            IOCs
          </h3>
          <div className="space-y-2">
            {iocs.length === 0 && <EmptyPanel message="No IOCs were provided for this threat." />}
            {iocs.map((ioc, index) => (
              <div key={`${ioc.type}-${ioc.value}-${index}`} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-sm text-[var(--fg)] break-all">{ioc.value}</p>
                    <p className="mt-1 text-xs uppercase tracking-wider text-[var(--subtle)]">{ioc.type} / {ioc.source || 'source unknown'}</p>
                  </div>
                  <span className="text-xs font-medium text-[var(--muted)]">{ioc.confidence == null ? 'N/A' : `${ioc.confidence}%`}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card-sentinel p-5">
          <h3 className="mb-4 flex items-center gap-2 font-semibold text-[var(--fg)]">
            <FlaskConical className="h-4 w-4 text-[var(--emerald-400)]" />
            TTPs
          </h3>
          <div className="space-y-2">
            {ttps.length === 0 && <EmptyPanel message="No ATT&CK TTPs were provided for this threat." />}
            {ttps.map(ttp => (
              <div key={`${ttp.id}-${ttp.name || ''}`} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                <p className="font-medium text-[var(--fg)]">{ttp.id} {ttp.name ? `/ ${ttp.name}` : ''}</p>
                <p className="mt-1 text-xs text-[var(--muted)]">{ttp.tactic || 'Tactic not reported'}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <div className="card-sentinel p-5">
          <h3 className="mb-4 flex items-center gap-2 font-semibold text-[var(--fg)]">
            <Box className="h-4 w-4 text-[var(--emerald-400)]" />
            Affected Products
          </h3>
          <div className="space-y-2">
            {products.length === 0 && <EmptyPanel message="No affected products were provided for this threat." />}
            {products.map(product => (
              <div key={`${product.vendor || 'unknown'}-${product.name}`} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                <p className="font-medium text-[var(--fg)]">{product.vendor ? `${product.vendor} ` : ''}{product.name}</p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  Versions: {safeArray(product.versions).join(', ') || 'not reported'}
                </p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  CVEs: {safeArray(product.cves).join(', ') || 'not reported'}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="card-sentinel p-5">
          <h3 className="mb-4 flex items-center gap-2 font-semibold text-[var(--fg)]">
            <ShieldCheck className="h-4 w-4 text-[var(--emerald-400)]" />
            Local Exposure and Gaps
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-[var(--surface)]/50 p-3">
              <p className="text-xs text-[var(--muted)]">Exposure</p>
              <p className="mt-1 text-lg font-semibold capitalize text-[var(--fg)]">{exposureState}</p>
            </div>
            <div className="rounded-lg bg-[var(--surface)]/50 p-3">
              <p className="text-xs text-[var(--muted)]">Exposed assets</p>
              <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(exposure.exposedAssets)}</p>
            </div>
            <div className="rounded-lg bg-[var(--surface)]/50 p-3">
              <p className="text-xs text-[var(--muted)]">Matching agents</p>
              <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{formatNumber(exposure.matchingAgents)}</p>
            </div>
            <div className="rounded-lg bg-[var(--surface)]/50 p-3">
              <p className="text-xs text-[var(--muted)]">Open gaps</p>
              <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{gaps.length}</p>
            </div>
          </div>
          {(agentIds.length > 0 || matchedProducts.length > 0 || matchedCves.length > 0 || telemetryMatches.length > 0) && (
            <div className="mt-4 grid grid-cols-1 gap-3">
              {agentIds.length > 0 && (
                <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Matched agents</p>
                  <p className="break-all font-mono text-xs text-[var(--fg-2)]">{agentIds.join(', ')}</p>
                </div>
              )}
              {matchedCves.length > 0 && (
                <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Matched CVEs</p>
                  <div className="space-y-1">
                    {matchedCves.slice(0, 5).map((match, index) => (
                      <p key={`${String(match.cve_id || match.cveId || 'cve')}-${index}`} className="text-xs text-[var(--fg-2)]">
                        {String(match.cve_id || match.cveId || 'CVE not reported')} / {String(match.product || match.software_name || 'product unknown')}
                      </p>
                    ))}
                  </div>
                </div>
              )}
              {matchedProducts.length > 0 && (
                <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Matched products</p>
                  <div className="space-y-1">
                    {matchedProducts.slice(0, 5).map((match, index) => (
                      <p key={`${String(match.product || match.name || 'product')}-${index}`} className="text-xs text-[var(--fg-2)]">
                        {String(match.vendor || '')} {String(match.product || match.name || 'product unknown')} {String(match.version || '')}
                      </p>
                    ))}
                  </div>
                </div>
              )}
              {telemetryMatches.length > 0 && (
                <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Telemetry matches</p>
                  <div className="space-y-1">
                    {telemetryMatches.slice(0, 5).map((match, index) => (
                      <p key={`${String(match.type || 'telemetry')}-${String(match.value || index)}`} className="break-all text-xs text-[var(--fg-2)]">
                        {String(match.event_type || match.eventType || 'event')} / {String(match.type || 'ioc')}:{String(match.value || '')}
                      </p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          <div className="mt-4 space-y-3">
            {notes.length === 0 && gaps.length === 0 && <EmptyPanel message="No local exposure notes or detection gaps were provided." />}
            {notes.map(note => <p key={note} className="text-sm text-[var(--fg-2)]">{note}</p>)}
            {gaps.map(gap => (
              <div key={gap} className="rounded-lg border border-[var(--high)]/25 bg-[var(--high)]/10 px-3 py-2 text-sm text-[var(--fg-2)]">
                {gap}
              </div>
            ))}
          </div>
        </div>
      </div>

      {(safeArray(threat.recommendedHunts).length > 0 || safeArray(threat.recommendedActions).length > 0 || actionState.result != null) && (
        <div className="card-sentinel p-5">
          <h3 className="mb-4 flex items-center gap-2 font-semibold text-[var(--fg)]">
            <Crosshair className="h-4 w-4 text-[var(--emerald-400)]" />
            Workflow Plan and Result
          </h3>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <div>
              <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Recommended hunts</p>
              <div className="space-y-2">
                {safeArray(threat.recommendedHunts).slice(0, 4).map((hunt, index) => (
                  <div key={`${String(hunt.name || hunt.type || 'hunt')}-${index}`} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                    <p className="text-sm font-medium text-[var(--fg)]">{String(hunt.name || hunt.type || 'Hunt')}</p>
                    <p className="mt-1 break-all font-mono text-xs text-[var(--muted)]">{String(hunt.query || hunt.language || 'query not reported')}</p>
                  </div>
                ))}
                {safeArray(threat.recommendedHunts).length === 0 && <EmptyPanel message="No hunts generated for this threat." />}
              </div>
            </div>
            <div>
              <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Recommended actions</p>
              <div className="space-y-2">
                {safeArray(threat.recommendedActions).map((action, index) => (
                  <div key={`${action.action || 'action'}-${index}`} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                    <p className="text-sm font-medium text-[var(--fg)]">{action.action || 'action'}</p>
                    <p className="mt-1 text-xs text-[var(--muted)]">{action.state || action.execution || 'not_executed'}</p>
                  </div>
                ))}
                {safeArray(threat.recommendedActions).length === 0 && <EmptyPanel message="No action recommendations generated." />}
              </div>
            </div>
            <div>
              <p className="mb-2 text-xs font-medium uppercase text-[var(--subtle)]">Last action result</p>
              {actionState.result == null ? (
                <EmptyPanel message="No action has been executed from this panel yet." />
              ) : (
                <pre className="max-h-72 overflow-auto rounded-lg border border-[var(--border)] bg-[var(--surface)]/60 p-3 text-xs text-[var(--fg-2)]">
                  {JSON.stringify(actionState.result, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function EmergingThreats(props: EmergingThreatsProps) {
  const threats = safeArray(props.threats || props.emergingThreats)
  const sources = safeArray(props.source_health || props.sourceHealth)
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(threats[0]?.id || null)

  const filteredThreats = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return threats

    return threats.filter(threat => {
      const haystack = [
        threat.title,
        threat.summary,
        threat.source,
        ...safeArray(threat.tags),
        ...safeArray(threat.iocs).map(ioc => `${ioc.type} ${ioc.value}`),
        ...safeArray(threat.ttps).map(ttp => `${ttp.id} ${ttp.name || ''} ${ttp.tactic || ''}`),
        ...safeArray(threat.affectedProducts).map(product => `${product.vendor || ''} ${product.name}`),
      ].join(' ').toLowerCase()

      return haystack.includes(normalizedQuery)
    })
  }, [query, threats])

  const selectedThreat = filteredThreats.find(threat => threat.id === selectedId) || filteredThreats[0] || null
  const criticalCount = threats.filter(threat => normalizeSeverity(threat.severity) === 'critical').length
  const exposedCount = threats.filter(threat => normalizeExposureState(threat.localExposure?.state) === 'exposed').length
  const healthySources = sources.filter(source => normalizeSourceStatus(source.status) === 'healthy').length

  return (
    <MainLayout title={props.page_title || 'Emerging Threats'}>
      <Head title="Emerging Threats Center - Tamandua EDR" />

      <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-[var(--fg)]">Emerging Threats Center</h1>
            <p className="mt-1 max-w-3xl text-sm text-[var(--muted)]">
              Prioritized external threat signals mapped to local exposure, detection gaps, IOCs, TTPs, and affected products.
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--muted)]">
            Updated: {props.generated_at || props.generatedAt || 'not reported'}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="card-sentinel p-4">
            <p className="flex items-center gap-2 text-xs text-[var(--muted)]"><Sparkles className="h-4 w-4 text-cyan-300" />Tracked threats</p>
            <p className="mt-2 text-2xl font-bold text-[var(--fg)]">{threats.length}</p>
          </div>
          <div className="card-sentinel p-4">
            <p className="flex items-center gap-2 text-xs text-[var(--muted)]"><AlertTriangle className="h-4 w-4 text-[var(--crit)]" />Critical</p>
            <p className="mt-2 text-2xl font-bold text-[var(--fg)]">{criticalCount}</p>
          </div>
          <div className="card-sentinel p-4">
            <p className="flex items-center gap-2 text-xs text-[var(--muted)]"><Gauge className="h-4 w-4 text-[var(--high)]" />Local exposure</p>
            <p className="mt-2 text-2xl font-bold text-[var(--fg)]">{exposedCount}</p>
          </div>
          <div className="card-sentinel p-4">
            <p className="flex items-center gap-2 text-xs text-[var(--muted)]"><Radio className="h-4 w-4 text-[var(--emerald-400)]" />Healthy sources</p>
            <p className="mt-2 text-2xl font-bold text-[var(--fg)]">{healthySources}/{sources.length}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(420px,0.9fr)_minmax(0,1.5fr)_360px]">
          <div className="space-y-4">
            <div className="card-sentinel p-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--subtle)]" />
                <input
                  type="search"
                  value={query}
                  onChange={event => setQuery(event.target.value)}
                  placeholder="Search threats, IOCs, products, TTPs..."
                  className="input-sentinel w-full pl-10"
                />
              </div>
            </div>
            <div className="space-y-3">
              {filteredThreats.length === 0 && <EmptyPanel message="No emerging threat props matched the current filters." />}
              {filteredThreats.map(threat => (
                <ThreatListItem
                  key={threat.id}
                  threat={threat}
                  selected={selectedThreat?.id === threat.id}
                  onSelect={() => setSelectedId(threat.id)}
                />
              ))}
            </div>
          </div>

          <DetailPanel threat={selectedThreat} />

          <div className="card-sentinel h-fit p-5">
            <h2 className="mb-4 flex items-center gap-2 text-base font-semibold text-[var(--fg)]">
              <Database className="h-4 w-4 text-[var(--emerald-400)]" />
              Source Health
            </h2>
            <div className="space-y-3">
              {sources.length === 0 && <EmptyPanel message="No source health props were provided." />}
              {sources.map(source => <SourceHealthRow key={source.id} source={source} />)}
            </div>
            <div className="mt-5 rounded-lg border border-[var(--border)] bg-[var(--surface)]/50 px-3 py-2 text-xs text-[var(--muted)]">
              <span className="inline-flex items-center gap-2">
                <FileSearch className="h-4 w-4" />
                Actions use tenant-scoped APIs. Evidence collection is enabled only when local exposure produced explicit matching agent IDs.
              </span>
            </div>
          </div>
          <ContextHealthPanel contextHealth={props.contextHealth} />
        </div>
      </div>
    </MainLayout>
  )
}
