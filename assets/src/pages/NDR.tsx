import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { logger } from '@/lib/logger'
import {
  Network, Shield, AlertTriangle, Activity, Globe, Server, RefreshCw,
  Eye, Target, Lock, Key, Search, Filter,
  Wifi, Share2, BarChart3, PieChart, TrendingUp, Clock, Zap, ShieldAlert,
  Radio, History, Database, CheckCircle2, HelpCircle, AlertCircle
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useEventStream } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import type { WebSocketConnectionState } from '@/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FlowStats {
  total_flows: number
  total_bytes: number
  total_packets: number
  bytes_per_second: number
  unique_sources: number
  unique_destinations: number
  avg_flow_duration: number
}

interface NetworkFlow {
  id: string
  agent_id?: string
  src_ip: string
  src_port?: number
  dst_ip: string
  dst_port?: number
  protocol: string
  bytes_sent: number
  bytes_received: number
  total_bytes: number
  packet_count?: number
  process_name?: string
  process_pid?: number
  first_seen?: string
  last_seen?: string
}

interface TopTalker {
  ip: string
  agent_id: string
  bytes_sent: number
  bytes_received: number
  total_bytes: number
  connection_count: number
}

interface ProtocolDistribution {
  protocol: string
  flow_count: number
  total_bytes: number
  percentage: number
}

interface LateralMovement {
  type: string
  src_ip: string
  dst_ip: string
  port?: number
  ports_scanned?: number
  hosts_scanned?: number
  username?: string
  timestamp: string
}

interface JA3Stats {
  ja3_hash: string
  ja3s_hash?: string
  occurrence_count: number
  unique_agents: number
  unique_destinations: number
  is_malicious: boolean
  malware_info?: { name: string; type: string }
  destinations?: string[]
  first_seen: string
  last_seen: string
}

interface TLSSession {
  event_id?: string
  agent_id?: string
  local_ip?: string
  local_port?: number
  remote_ip?: string
  remote_port?: number
  protocol?: string
  domain?: string
  ja3?: string
  ja3s?: string
  sni?: string
  tls_version?: string
  alpn?: string
  alpn_protocols?: string[]
  cipher_suite?: string
  tls_extensions?: string[]
  ech_present?: boolean
  quic_version?: string
  is_quic?: boolean
  http_version?: string
  encrypted_dns_transport?: string
  dns_resolver?: string
  certificate_fingerprint?: string
  certificate_risk?: string
  process?: string | Record<string, unknown>
  enrichment?: Record<string, unknown>
  timestamp?: string
}

interface CertificateAnalysis {
  agent_id?: string
  remote_ip?: string
  remote_port?: number
  domain?: string
  fingerprint?: string
  subject?: string
  issuer?: string
  not_after?: string
  is_self_signed?: boolean
  risk_score?: number
  analysis?: string[]
  cached_at?: string
}

interface NDRAnomaly {
  type?: string
  confidence?: number
  description?: string
  mitre_techniques?: string[]
  flow_key?: string
  metadata?: Record<string, unknown>
}

interface TopologyNode {
  id: string
  label: string
  type: string
  total_bytes: number
  is_internal: boolean
}

interface TopologyEdge {
  source: string
  target: string
  protocol: string
  bytes: number
}

interface NDRStats {
  flow_analyzer: {
    flows_processed: number
    active_flows: number
    anomalies_detected: number
    bytes_analyzed: number
    alerts_created: number
  }
  protocol_analyzer: {
    events_analyzed: number
    http_analyzed: number
    smb_analyzed: number
    rdp_sessions: number
    ssh_sessions: number
    detections: number
  }
  lateral_detector: {
    events_analyzed: number
    port_scans_detected: number
    host_scans_detected: number
    lateral_movements_detected: number
    credential_spreads_detected: number
  }
  encrypted_traffic: {
    events_analyzed: number
    ja3_matches: number
    suspicious_certs: number
    self_signed_certs: number
  }
  summary: {
    total_flows_processed: number
    total_events_analyzed: number
    total_anomalies: number
    total_alerts: number
  }
}

type SourceHealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'empty' | 'unknown' | 'unavailable'

interface SourceHealth {
  key: string
  label: string
  status: SourceHealthStatus
  coverage?: string
  row_count?: number | null
  first_seen?: string
  last_seen?: string
  detail?: string
}

type DataMode = 'combined' | 'live' | 'historical'
type NDRTab = 'overview' | 'lateral' | 'encrypted' | 'protocols' | 'anomalies'
type EncryptedSection = 'ja3' | 'tls' | 'certificates'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number | undefined | null): string {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  if (n < 1024) return `${Math.round(n)} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function formatObservedBytes(bytes: number | undefined | null, observed: boolean): string {
  const n = Number(bytes)
  if (observed && (!Number.isFinite(n) || n <= 0)) return 'Not reported'
  return formatBytes(bytes)
}

function formatNumber(n: number | undefined | null): string {
  const num = Number(n)
  if (!Number.isFinite(num)) return '0'
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toLocaleString()
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

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

function buildQuery(params: Record<string, string | number | undefined | null>): string {
  const query = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    query.set(key, String(value))
  })

  const encoded = query.toString()
  return encoded ? `?${encoded}` : ''
}

function matchesText(value: unknown, query: string): boolean {
  if (!query.trim()) return true
  return String(value || '').toLowerCase().includes(query.trim().toLowerCase())
}

function numericFilter(value: string): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0
}

function readUrlParam(key: string): string {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get(key) || ''
}

function initialNdrTab(): NDRTab {
  const tab = readUrlParam('tab')
  return ['overview', 'lateral', 'encrypted', 'protocols', 'anomalies'].includes(tab)
    ? tab as NDRTab
    : 'overview'
}

function initialEncryptedSection(): EncryptedSection {
  const section = readUrlParam('section')
  return ['ja3', 'tls', 'certificates'].includes(section)
    ? section as EncryptedSection
    : 'ja3'
}

function coerceArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') return Object.values(value as Record<string, unknown>)
  return []
}

function coerceRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
    if (typeof value === 'boolean') return String(value)
  }
  return undefined
}

function tlsMetadata(session: TLSSession): Record<string, unknown> {
  const enrichment = coerceRecord(session.enrichment)
  return coerceRecord(enrichment.encrypted_metadata)
}

function sessionString(session: TLSSession, key: keyof TLSSession, metadataKey?: string): string | undefined {
  const metadata = tlsMetadata(session)
  return firstString(session[key], metadataKey ? metadata[metadataKey] : metadata[key as string])
}

function sessionStringList(session: TLSSession, key: keyof TLSSession, metadataKey?: string): string[] {
  const value = session[key] ?? tlsMetadata(session)[metadataKey || (key as string)]
  if (Array.isArray(value)) return value.map(item => String(item)).filter(Boolean)
  if (typeof value === 'string') return value.split(/[,\s]+/).map(item => item.trim()).filter(Boolean)
  return []
}

function formatProcess(value: TLSSession['process']): string {
  if (!value) return 'unknown'
  if (typeof value === 'string') return value
  return firstString(value.process_name, value.name, value.image_path, value.path, value.pid, value.process_pid) || 'unknown'
}

function normalizeHealthStatus(value: unknown): SourceHealthStatus {
  const normalized = String(value || '').toLowerCase()
  if (['ok', 'online', 'active', 'available', 'healthy'].includes(normalized)) return 'healthy'
  if (['warn', 'warning', 'degraded', 'partial'].includes(normalized)) return 'degraded'
  if (['err', 'error', 'failed', 'unhealthy', 'offline'].includes(normalized)) return 'unhealthy'
  if (['empty', 'no_data', 'no-telemetry'].includes(normalized)) return 'empty'
  if (['disabled', 'unavailable', 'not_available', 'not-available', 'missing'].includes(normalized)) return 'unavailable'
  return 'unknown'
}

function formatRowCount(value: unknown): string {
  if (value === undefined || value === null) return 'Rows unknown'
  const count = Number(value)
  if (!Number.isFinite(count)) return 'Rows unknown'
  return `${formatNumber(count)} ${count === 1 ? 'row' : 'rows'}`
}

function formatCoverageRange(firstSeen: unknown, lastSeen: unknown): string | undefined {
  const first = typeof firstSeen === 'string' ? firstSeen : undefined
  const last = typeof lastSeen === 'string' ? lastSeen : undefined

  if (first && last) return `Oldest ${relativeTime(first)} / newest ${relativeTime(last)}`
  if (last) return `Newest ${relativeTime(last)}`
  if (first) return `Oldest ${relativeTime(first)}`
  return undefined
}

function normalizeSourceHealth(raw: unknown): SourceHealth[] {
  const root = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {}
  const data = root.data && typeof root.data === 'object' ? root.data as Record<string, unknown> : root
  const live = data.live && typeof data.live === 'object' ? data.live as Record<string, unknown> : null
  const liveModules = live?.modules && typeof live.modules === 'object' ? live.modules as Record<string, unknown> : null
  const historical = data.historical && typeof data.historical === 'object' ? data.historical as Record<string, unknown> : null

  if (liveModules || historical) {
    const liveSources = liveModules
      ? Object.entries(liveModules).map(([key, value]) => {
          const module = value && typeof value === 'object' ? value as Record<string, unknown> : {}
          return {
            key,
            label: key.replace(/_/g, ' '),
            status: normalizeHealthStatus(module.status),
            coverage: key === 'encrypted_traffic' ? 'TLS, JA3 and certificate analyzer' : 'Live runtime analyzer',
            detail: module.reason !== undefined ? String(module.reason) : live?.retention !== undefined ? String(live.retention) : undefined,
          }
        })
      : []

    const historicalCoverage = coerceRecord(historical?.coverage)
    const historicalTables = Object.entries(historicalCoverage).map(([key, value]) => {
      const table = coerceRecord(value)
      const rowCount = table.row_count === undefined || table.row_count === null
        ? null
        : typeof table.row_count === 'number'
          ? table.row_count
          : Number.isFinite(Number(table.row_count)) ? Number(table.row_count) : null
      const retention = table.retention !== undefined ? String(table.retention) : undefined
      const range = formatCoverageRange(table.first_seen, table.last_seen)

      return {
        key: `historical-${key}`,
        label: table.label !== undefined ? String(table.label) : key.replace(/_/g, ' '),
        status: normalizeHealthStatus(table.status),
        coverage: [formatRowCount(table.row_count), retention].filter(Boolean).join(' / '),
        row_count: rowCount,
        first_seen: table.first_seen !== undefined ? String(table.first_seen) : undefined,
        last_seen: table.last_seen !== undefined ? String(table.last_seen) : undefined,
        detail: table.reason !== undefined ? String(table.reason) : range,
      }
    })

    const historicalSource = historical
      ? [{
          key: 'historical',
          label: 'Historical NDR',
          status: normalizeHealthStatus(historical.status),
          coverage: historical.retention !== undefined
            ? String(historical.retention)
            : historical.source !== undefined
              ? String(historical.source)
              : 'Persisted store',
          detail: historical.reason !== undefined
            ? String(historical.reason)
            : historicalTables.length > 0
              ? `${historicalTables.filter(source => source.status === 'healthy' || source.status === 'empty').length} Postgres tables checked`
              : historical.available ? 'Historical store is available' : 'Historical store is not available',
        }]
      : []

    return [...liveSources, ...historicalSource, ...historicalTables]
  }

  const rawSources = data.sources ?? data.coverage ?? data.health ?? data

  return coerceArray(rawSources).map((item, index) => {
    const source = item && typeof item === 'object' ? item as Record<string, unknown> : {}
    const key = String(source.key || source.id || source.name || source.source || `source-${index}`)
    const rawLabel = String(source.label || source.display_name || key)

    return {
      key,
      label: rawLabel.replace(/_/g, ' '),
      status: normalizeHealthStatus(source.status || source.health || source.state),
      coverage: source.coverage !== undefined ? String(source.coverage) : undefined,
      row_count: typeof source.row_count === 'number' ? source.row_count : undefined,
      first_seen: source.first_seen !== undefined ? String(source.first_seen) : undefined,
      last_seen: source.last_seen !== undefined ? String(source.last_seen) : undefined,
      detail: source.detail !== undefined ? String(source.detail) : source.message !== undefined ? String(source.message) : undefined,
    }
  }).filter(source => source.key && source.label)
}

function sourceStatusClasses(status: SourceHealthStatus): string {
  switch (status) {
    case 'healthy': return 'text-[var(--emerald-400)] bg-[var(--emerald-400)]/10 border-[var(--emerald-400)]/20'
    case 'degraded': return 'text-[var(--high)] bg-[var(--high)]/10 border-[var(--high)]/20'
    case 'unhealthy': return 'text-[var(--crit)] bg-[var(--crit)]/10 border-[var(--crit)]/20'
    case 'empty': return 'text-blue-400 bg-blue-500/10 border-blue-500/20'
    case 'unavailable': return 'text-[var(--subtle)] bg-[var(--surface)]/40 border-[var(--border)]'
    default: return 'text-[var(--muted)] bg-[var(--surface)]/40 border-[var(--border)]'
  }
}

function getLateralMovementIcon(type: string) {
  switch (type) {
    case 'port_scan': return Target
    case 'host_scan': return Search
    case 'credential_spread': return Key
    case 'lateral_movement': return Share2
    case 'smb_lateral_movement': return Server
    default: return Network
  }
}

function getLateralMovementColor(type: string): string {
  switch (type) {
    case 'port_scan': return 'text-[var(--high)] bg-[var(--high)]/10'
    case 'host_scan': return 'text-[var(--med)] bg-[var(--med)]/10'
    case 'credential_spread': return 'text-[var(--crit)] bg-[var(--crit)]/10'
    case 'lateral_movement': return 'text-purple-400 bg-purple-500/10'
    case 'smb_lateral_movement': return 'text-pink-400 bg-pink-500/10'
    default: return 'text-[var(--muted)] bg-[var(--muted)]/10'
  }
}

function EmptyTelemetryState({ message = 'No network telemetry received yet' }: { message?: string }) {
  return (
    <div className="py-8 text-center text-sm text-[var(--muted)]">
      {message}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function StatCard({ icon: Icon, label, value, subvalue, color, trend, alert }: {
  icon: React.ElementType
  label: string
  value: string | number
  subvalue?: string
  color: 'cyan' | 'green' | 'red' | 'amber' | 'violet' | 'blue' | 'purple' | 'pink'
  trend?: number
  alert?: boolean
}) {
  const colorMap = {
    cyan: { bg: 'bg-cyan-500/10', icon: 'text-cyan-400' },
    green: { bg: 'bg-[var(--emerald-400)]/10', icon: 'text-[var(--emerald-400)]' },
    red: { bg: 'bg-[var(--crit)]/10', icon: 'text-[var(--crit)]' },
    amber: { bg: 'bg-[var(--high)]/10', icon: 'text-[var(--high)]' },
    violet: { bg: 'bg-violet-500/10', icon: 'text-violet-400' },
    blue: { bg: 'bg-blue-500/10', icon: 'text-blue-400' },
    purple: { bg: 'bg-purple-500/10', icon: 'text-purple-400' },
    pink: { bg: 'bg-pink-500/10', icon: 'text-pink-400' },
  }
  const c = colorMap[color]

  return (
    <div className={cn(
      'card-sentinel p-4 transition-all',
      alert && 'border-[var(--crit)]/40 ring-1 ring-[var(--crit)]/10'
    )}>
      <div className="flex items-start gap-3">
        <div className={cn('p-2.5 rounded-lg', c.bg)}>
          <Icon className={cn('h-5 w-5', c.icon)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-2xl font-bold text-[var(--fg)] leading-tight">
              {typeof value === 'number' ? formatNumber(value) : value}
            </p>
            {trend !== undefined && trend !== 0 && (
              <span className={cn(
                'inline-flex items-center text-xs font-medium px-1.5 py-0.5 rounded',
                trend > 0 ? 'text-[var(--emerald-400)] bg-[var(--emerald-400)]/10' : 'text-[var(--crit)] bg-[var(--crit)]/10'
              )}>
                {trend > 0 ? '+' : ''}{trend}%
              </span>
            )}
          </div>
          <p className="text-xs text-[var(--muted)] mt-0.5">{label}</p>
          {subvalue && (
            <p className="text-xs text-[var(--muted)] mt-1">{subvalue}</p>
          )}
        </div>
      </div>
    </div>
  )
}

function DataModeCard({ icon: Icon, title, status, description, active, onClick }: {
  icon: React.ElementType
  title: string
  status: string
  description: string
  active?: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'rounded-lg border px-4 py-3 text-left transition-colors',
        active
          ? 'border-cyan-500/30 bg-cyan-500/10 ring-1 ring-cyan-500/10'
          : 'border-[var(--border)] bg-[var(--surface)]/35 hover:bg-[var(--surface)]/55'
      )}
    >
      <div className="flex items-start gap-3">
        <div className={cn('p-2 rounded-lg', active ? 'bg-cyan-500/10' : 'bg-[var(--surface)]/60')}>
          <Icon className={cn('h-4 w-4', active ? 'text-cyan-400' : 'text-[var(--muted)]')} />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold text-[var(--fg)]">{title}</h2>
            <span className={cn(
              'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
              active
                ? 'border-cyan-500/25 bg-cyan-500/10 text-cyan-400'
                : 'border-[var(--border)] bg-[var(--surface)]/50 text-[var(--muted)]'
            )}>
              {status}
            </span>
          </div>
          <p className="mt-1 text-xs leading-5 text-[var(--muted)]">{description}</p>
        </div>
      </div>
    </button>
  )
}

function SourceCoveragePanel({
  sources,
  available,
  lastUpdated,
}: {
  sources: SourceHealth[]
  available: boolean
  lastUpdated: string | null
}) {
  return (
    <div className="card-sentinel p-4">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-[var(--emerald-400)]" />
            <h2 className="text-sm font-semibold text-[var(--fg)]">Source health and coverage</h2>
          </div>
          <span className="text-xs text-[var(--muted)]">
            {available ? 'Reported by source health' : 'Derived from loaded runtime counters'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {sources.map(source => {
            const isHealthy = source.status === 'healthy'
            const Icon = isHealthy ? CheckCircle2 : source.status === 'unknown' || source.status === 'unavailable' ? HelpCircle : AlertCircle

            return (
              <div key={source.key} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/35 p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium capitalize text-[var(--fg)]">{source.label}</p>
                    <p className="mt-1 text-xs text-[var(--muted)]">{source.coverage || 'Coverage unknown'}</p>
                  </div>
                  <span className={cn(
                    'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize',
                    sourceStatusClasses(source.status)
                  )}>
                    <Icon className="h-3 w-3" />
                    {source.status.replace(/_/g, ' ')}
                  </span>
                </div>
                <p className="mt-3 text-xs text-[var(--subtle)]">
                  {source.last_seen ? `Last seen ${relativeTime(source.last_seen)}` : source.detail || (lastUpdated ? `Checked ${relativeTime(lastUpdated)}` : 'Waiting for telemetry')}
                </p>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function ProtocolPieChart({ data }: { data: ProtocolDistribution[] }) {
  const total = data.reduce((sum, d) => sum + d.total_bytes, 0)
  const colors = ['#06b6d4', '#8b5cf6', '#f59e0b', '#10b981', '#ec4899', '#6366f1']

  if (data.length === 0 || total === 0) {
    return <EmptyTelemetryState />
  }

  return (
    <div className="space-y-3">
      {data.slice(0, 6).map((item, idx) => (
        <div key={item.protocol} className="space-y-1">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: colors[idx % colors.length] }}
              />
              <span className="text-[var(--fg)] font-medium">{item.protocol}</span>
            </div>
            <span className="text-[var(--muted)] font-mono text-xs">
              {formatBytes(item.total_bytes)} ({item.percentage.toFixed(1)}%)
            </span>
          </div>
          <div className="h-2 bg-[var(--surface)]/50 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${item.percentage}%`,
                backgroundColor: colors[idx % colors.length]
              }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

function TopTalkersTable({
  talkers,
  onBlockIP,
}: {
  talkers: TopTalker[]
  onBlockIP: (talker: TopTalker) => void
}) {
  const hasObservedConnectionsWithoutBytes = talkers.some(
    talker => Number(talker.connection_count || 0) > 0 && Number(talker.total_bytes || 0) <= 0
  )

  return (
    <div className="space-y-3">
      {hasObservedConnectionsWithoutBytes && (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/30 px-3 py-2 text-xs text-[var(--muted)]">
          This agent telemetry reports connection counts, but not byte counters yet.
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--surface)]/40">
              <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">IP Address</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Sent</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Received</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Total</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Conns</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--surface)]/30">
            {talkers.map((talker, idx) => {
              const bytesUnavailable = Number(talker.connection_count || 0) > 0 && Number(talker.total_bytes || 0) <= 0

              return (
                <tr key={talker.ip + idx} className="hover:bg-[var(--surface)]/20 transition-colors">
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="p-1 bg-blue-500/10 rounded">
                        <Server className="h-3.5 w-3.5 text-blue-400" />
                      </div>
                      <span className="font-mono text-sm text-[var(--fg)]">{talker.ip}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <span className="font-mono text-xs text-[var(--emerald-400)]">{formatObservedBytes(talker.bytes_sent, bytesUnavailable)}</span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <span className="font-mono text-xs text-blue-400">{formatObservedBytes(talker.bytes_received, bytesUnavailable)}</span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <span className="font-mono text-xs text-[var(--fg)] font-medium">{formatObservedBytes(talker.total_bytes, bytesUnavailable)}</span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <span className="text-xs text-[var(--muted)]">{talker.connection_count}</span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      onClick={() => onBlockIP(talker)}
                      disabled={!talker.agent_id}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs border transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                      style={{
                        color: 'var(--crit)',
                        borderColor: 'color-mix(in srgb, var(--crit) 35%, transparent)',
                        backgroundColor: 'color-mix(in srgb, var(--crit) 8%, transparent)',
                      }}
                      title={talker.agent_id ? `Block ${talker.ip}` : 'Agent ID is required to block from endpoint'}
                    >
                      <ShieldAlert className="h-3 w-3" />
                      Block
                    </button>
                  </td>
                </tr>
              )
            })}
            {talkers.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-sm text-[var(--muted)]">
                  No network telemetry received yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RecentFlowsTable({ flows }: { flows: NetworkFlow[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[var(--surface)]/40">
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Source</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Destination</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Protocol</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Process</th>
            <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Bytes</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Last Seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--surface)]/30">
          {flows.map((flow, idx) => (
            <tr key={flow.id || `${flow.src_ip}-${flow.dst_ip}-${idx}`} className="hover:bg-[var(--surface)]/20 transition-colors">
              <td className="px-3 py-2.5">
                <div className="font-mono text-xs text-[var(--fg)]">{flow.src_ip}{flow.src_port ? `:${flow.src_port}` : ''}</div>
                {flow.agent_id && <div className="mt-0.5 truncate text-[11px] text-[var(--subtle)] max-w-[180px]">{flow.agent_id}</div>}
              </td>
              <td className="px-3 py-2.5 font-mono text-xs text-[var(--fg)]">
                {flow.dst_ip}{flow.dst_port ? `:${flow.dst_port}` : ''}
              </td>
              <td className="px-3 py-2.5">
                <span className="inline-flex items-center rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-400">
                  {flow.protocol || 'UNKNOWN'}
                </span>
              </td>
              <td className="px-3 py-2.5">
                <span className="font-mono text-xs text-[var(--muted)]">
                  {flow.process_name || 'unknown'}
                  {flow.process_pid ? ` (${flow.process_pid})` : ''}
                </span>
              </td>
              <td className="px-3 py-2.5 text-right">
                <div className="font-mono text-xs font-medium text-[var(--fg)]">{formatBytes(flow.total_bytes)}</div>
                <div className="text-[11px] text-[var(--subtle)]">
                  {formatBytes(flow.bytes_sent)} sent / {formatBytes(flow.bytes_received)} recv
                </div>
              </td>
              <td className="px-3 py-2.5 text-xs text-[var(--muted)]">
                {relativeTime(flow.last_seen)}
              </td>
            </tr>
          ))}
          {flows.length === 0 && (
            <tr>
              <td colSpan={6} className="py-8 text-center text-sm text-[var(--muted)]">
                No flows match the active filters
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function LateralMovementList({ movements }: { movements: LateralMovement[] }) {
  return (
    <div className="space-y-2">
      {movements.map((movement, idx) => {
        const Icon = getLateralMovementIcon(movement.type)
        const colorClasses = getLateralMovementColor(movement.type)

        return (
          <div
            key={idx}
            className="bg-[var(--surface)]/40 border border-[var(--surface)]/40 rounded-lg p-3 hover:border-[var(--surface)]/60 transition-colors"
          >
            <div className="flex items-start gap-3">
              <div className={cn('p-2 rounded-lg', colorClasses.split(' ')[1])}>
                <Icon className={cn('h-4 w-4', colorClasses.split(' ')[0])} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-[var(--fg)] capitalize">
                    {movement.type.replace(/_/g, ' ')}
                  </p>
                  <span className="text-xs text-[var(--muted)]">{relativeTime(movement.timestamp)}</span>
                </div>
                <p className="text-xs text-[var(--muted)] mt-1">
                  {movement.src_ip} {movement.dst_ip && `to ${movement.dst_ip}`}
                  {movement.port && ` on port ${movement.port}`}
                  {movement.ports_scanned && ` (${movement.ports_scanned} ports)`}
                  {movement.hosts_scanned && ` (${movement.hosts_scanned} hosts)`}
                  {movement.username && ` as ${movement.username}`}
                </p>
              </div>
            </div>
          </div>
        )
      })}
      {movements.length === 0 && (
        <EmptyTelemetryState message="No lateral movement activity in live telemetry" />
      )}
    </div>
  )
}

function JA3Table({ stats }: { stats: JA3Stats[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[var(--surface)]/40">
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">JA3 Hash</th>
            <th className="text-center px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Status</th>
            <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Occurrences</th>
            <th className="text-right px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Agents</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Last Seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--surface)]/30">
          {stats.map((item, idx) => (
            <tr key={item.ja3_hash + idx} className="hover:bg-[var(--surface)]/20 transition-colors">
              <td className="px-3 py-2.5">
                <span className="font-mono text-xs text-[var(--fg)] truncate max-w-[200px] block">
                  {item.ja3_hash}
                </span>
                {item.malware_info && (
                  <span className="text-xs text-[var(--crit)]">{item.malware_info.name}</span>
                )}
              </td>
              <td className="px-3 py-2.5 text-center">
                {item.is_malicious ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-[var(--crit)]/10 text-[var(--crit)] rounded-full text-xs font-medium">
                    <AlertTriangle className="h-3 w-3" />
                    Malicious
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-[var(--emerald-400)]/10 text-[var(--emerald-400)] rounded-full text-xs font-medium">
                    <Shield className="h-3 w-3" />
                    Clean
                  </span>
                )}
              </td>
              <td className="px-3 py-2.5 text-right">
                <span className="text-sm text-[var(--fg)]">{item.occurrence_count}</span>
              </td>
              <td className="px-3 py-2.5 text-right">
                <span className="text-sm text-[var(--muted)]">{item.unique_agents}</span>
              </td>
              <td className="px-3 py-2.5">
                <span className="text-xs text-[var(--muted)]">{relativeTime(item.last_seen)}</span>
              </td>
            </tr>
          ))}
          {stats.length === 0 && (
            <tr>
              <td colSpan={5} className="py-8 text-center text-sm text-[var(--muted)]">
                No JA3 fingerprints recorded in live telemetry
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function TLSSessionsTable({ sessions }: { sessions: TLSSession[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[var(--surface)]/40">
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Remote</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">SNI / Domain</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">TLS / ALPN</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Encrypted DNS</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">JA3</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Process</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Last Seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--surface)]/30">
          {sessions.map((session, idx) => {
            const alpn = sessionString(session, 'alpn')
            const alpnProtocols = sessionStringList(session, 'alpn_protocols')
            const cipherSuite = sessionString(session, 'cipher_suite')
            const quicVersion = sessionString(session, 'quic_version')
            const httpVersion = sessionString(session, 'http_version')
            const encryptedDnsTransport = sessionString(session, 'encrypted_dns_transport')
            const dnsResolver = sessionString(session, 'dns_resolver')
            const process = formatProcess(session.process)

            return (
              <tr key={`${session.event_id || session.remote_ip || 'tls'}-${idx}`} className="hover:bg-[var(--surface)]/20 transition-colors">
                <td className="px-3 py-2.5">
                  <div className="font-mono text-xs text-[var(--fg)]">{session.remote_ip || 'unknown'}</div>
                  <div className="text-[11px] text-[var(--subtle)]">{session.remote_port || '--'} / {quicVersion ? 'QUIC' : session.protocol || 'tls'}</div>
                </td>
                <td className="px-3 py-2.5">
                  <div className="text-xs text-[var(--fg)] truncate max-w-[220px]" title={session.sni || session.domain}>
                    {session.sni || session.domain || 'Not reported'}
                  </div>
                  {session.agent_id && <div className="text-[11px] text-[var(--subtle)] truncate max-w-[220px]">{session.agent_id}</div>}
                </td>
                <td className="px-3 py-2.5">
                  <div className="text-xs text-[var(--fg)]">{session.tls_version || (quicVersion ? `QUIC ${quicVersion}` : 'unknown')}</div>
                  <div className="text-[11px] text-[var(--subtle)] truncate max-w-[200px]" title={alpnProtocols.join(', ') || alpn || undefined}>
                    {[alpn || alpnProtocols[0], httpVersion ? `HTTP/${httpVersion}` : null].filter(Boolean).join(' / ') || 'ALPN not reported'}
                  </div>
                  {cipherSuite && <div className="text-[11px] text-[var(--subtle)] truncate max-w-[200px]" title={cipherSuite}>{cipherSuite}</div>}
                </td>
                <td className="px-3 py-2.5">
                  {encryptedDnsTransport ? (
                    <span className="inline-flex items-center rounded-full bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-200">
                      {encryptedDnsTransport.toUpperCase()}
                    </span>
                  ) : (
                    <span className="text-xs text-[var(--muted)]">Not classified</span>
                  )}
                  {dnsResolver && <div className="mt-1 font-mono text-[11px] text-[var(--subtle)] truncate max-w-[140px]" title={dnsResolver}>{dnsResolver}</div>}
                </td>
                <td className="px-3 py-2.5">
                  <div className="font-mono text-xs text-[var(--fg)] truncate max-w-[160px]" title={session.ja3}>{session.ja3 || 'not captured'}</div>
                  {session.ja3s && <div className="font-mono text-[11px] text-[var(--subtle)] truncate max-w-[160px]" title={session.ja3s}>S {session.ja3s}</div>}
                </td>
                <td className="px-3 py-2.5 text-xs text-[var(--muted)] truncate max-w-[160px]" title={process}>{process}</td>
                <td className="px-3 py-2.5 text-xs text-[var(--muted)]">{relativeTime(session.timestamp)}</td>
              </tr>
            )
          })}
          {sessions.length === 0 && (
            <tr>
              <td colSpan={7} className="py-8 text-center text-sm text-[var(--muted)]">
                No TLS sessions recorded. Agent telemetry must include TLS/SNI/JA3 metadata.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function CertificatesTable({ certificates }: { certificates: CertificateAnalysis[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[var(--surface)]/40">
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Domain</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Subject / Issuer</th>
            <th className="text-center px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Risk</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Fingerprint</th>
            <th className="text-left px-3 py-2 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Expires</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--surface)]/30">
          {certificates.map((cert, idx) => {
            const risk = Number(cert.risk_score || 0)
            return (
              <tr key={`${cert.fingerprint || cert.domain || 'cert'}-${idx}`} className="hover:bg-[var(--surface)]/20 transition-colors">
                <td className="px-3 py-2.5">
                  <div className="text-xs text-[var(--fg)] truncate max-w-[180px]" title={cert.domain}>{cert.domain || cert.remote_ip || 'unknown'}</div>
                  {cert.remote_port && <div className="text-[11px] text-[var(--subtle)]">{cert.remote_ip}:{cert.remote_port}</div>}
                </td>
                <td className="px-3 py-2.5">
                  <div className="text-xs text-[var(--fg)] truncate max-w-[260px]" title={cert.subject}>{cert.subject || 'No subject'}</div>
                  <div className="text-[11px] text-[var(--subtle)] truncate max-w-[260px]" title={cert.issuer}>{cert.issuer || 'No issuer'}</div>
                </td>
                <td className="px-3 py-2.5 text-center">
                  <span className={cn(
                    'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium',
                    risk >= 70 || cert.is_self_signed
                      ? 'bg-[var(--crit)]/10 text-[var(--crit)]'
                      : risk >= 30
                        ? 'bg-[var(--med)]/10 text-[var(--med)]'
                        : 'bg-[var(--emerald-400)]/10 text-[var(--emerald-400)]'
                  )}>
                    {cert.is_self_signed ? 'Self-signed' : `${risk}%`}
                  </span>
                </td>
                <td className="px-3 py-2.5 font-mono text-xs text-[var(--muted)] truncate max-w-[180px]" title={cert.fingerprint}>
                  {cert.fingerprint || 'not captured'}
                </td>
                <td className="px-3 py-2.5 text-xs text-[var(--muted)]">{relativeTime(cert.not_after)}</td>
              </tr>
            )
          })}
          {certificates.length === 0 && (
            <tr>
              <td colSpan={5} className="py-8 text-center text-sm text-[var(--muted)]">
                No certificate analysis recorded. Passive TLS 1.3 collection may not expose certificates without endpoint-side metadata.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function AnomaliesList({ anomalies }: { anomalies: NDRAnomaly[] }) {
  return (
    <div className="space-y-3">
      {anomalies.map((anomaly, idx) => (
        <div key={`${anomaly.type || 'anomaly'}-${idx}`} className="rounded-lg border border-[var(--surface)]/50 bg-[var(--surface)]/30 p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-medium text-[var(--fg)] capitalize">{String(anomaly.type || 'network anomaly').replace(/_/g, ' ')}</p>
              <p className="mt-1 text-xs text-[var(--muted)]">{anomaly.description || 'Detected by flow analysis'}</p>
            </div>
            <span className="rounded-full bg-[var(--med)]/10 px-2 py-0.5 text-xs font-medium text-[var(--med)]">
              {Math.round(Number(anomaly.confidence || 0) * 100)}%
            </span>
          </div>
          {anomaly.flow_key && <p className="mt-3 font-mono text-xs text-[var(--subtle)] truncate">{anomaly.flow_key}</p>}
        </div>
      ))}
      {anomalies.length === 0 && <EmptyTelemetryState message="No NDR anomalies match the current filters" />}
    </div>
  )
}

function NetworkTopologyMini({ nodes, edges }: { nodes: TopologyNode[]; edges: TopologyEdge[] }) {
  const internalNodes = nodes.filter(n => n.is_internal).length
  const externalNodes = nodes.length - internalNodes
  const topEdges = [...edges].sort((a, b) => (b.bytes || 0) - (a.bytes || 0)).slice(0, 6)
  const topNodes = [...nodes].sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0)).slice(0, 6)
  const byteCountersUnavailable =
    (nodes.length > 0 || edges.length > 0) &&
    nodes.every(node => Number(node.total_bytes || 0) <= 0) &&
    edges.every(edge => Number(edge.bytes || 0) <= 0)

  if (nodes.length === 0 && edges.length === 0) {
    return <EmptyTelemetryState />
  }

  return (
    <div className="space-y-4">
      {byteCountersUnavailable && (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/30 px-3 py-2 text-xs text-[var(--muted)]">
          Topology is based on observed connections. Byte counters are not reported by the current agent telemetry.
        </div>
      )}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-cyan-400">{nodes.length}</p>
          <p className="text-xs text-[var(--muted)]">Total Nodes</p>
        </div>
        <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-[var(--emerald-400)]">{internalNodes}</p>
          <p className="text-xs text-[var(--muted)]">Internal</p>
        </div>
        <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-[var(--high)]">{externalNodes}</p>
          <p className="text-xs text-[var(--muted)]">External</p>
        </div>
      </div>
      <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
        <p className="text-3xl font-bold text-purple-400">{edges.length}</p>
        <p className="text-xs text-[var(--muted)]">Network Connections</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-[var(--surface)]/30 rounded-lg p-3">
          <p className="text-xs uppercase tracking-wide text-[var(--subtle)] mb-2">Top nodes</p>
          <div className="space-y-2">
            {topNodes.map(node => (
              <div key={node.id} className="flex items-center justify-between gap-2 text-xs">
                <span className="font-mono text-[var(--fg)] truncate">{node.label}</span>
                <span className="text-[var(--muted)]">{formatObservedBytes(node.total_bytes, byteCountersUnavailable)}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[var(--surface)]/30 rounded-lg p-3">
          <p className="text-xs uppercase tracking-wide text-[var(--subtle)] mb-2">Top edges</p>
          <div className="space-y-2">
            {topEdges.map((edge, index) => (
              <div key={`${edge.source}-${edge.target}-${edge.protocol}-${index}`} className="text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[var(--fg)] truncate">{edge.source} {'->'} {edge.target}</span>
                  <span className="text-[var(--muted)]">{formatObservedBytes(edge.bytes, byteCountersUnavailable)}</span>
                </div>
                <div className="text-[var(--subtle)]">{edge.protocol}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function NDR() {
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [activeTab, setActiveTab] = useState<NDRTab>(initialNdrTab)
  const [encryptedSection, setEncryptedSection] = useState<EncryptedSection>(initialEncryptedSection)
  const [agentFilter, setAgentFilter] = useState(readUrlParam('agent_id'))
  const [ipFilter, setIpFilter] = useState(readUrlParam('ip') || readUrlParam('q') || readUrlParam('search'))
  const [protocolFilter, setProtocolFilter] = useState(readUrlParam('protocol') || 'all')
  const [scopeFilter, setScopeFilter] = useState<'all' | 'internal' | 'external'>('all')
  const [lateralTypeFilter, setLateralTypeFilter] = useState('all')
  const [ja3StatusFilter, setJa3StatusFilter] = useState<'all' | 'malicious' | 'clean'>('all')
  const [minBytesFilter, setMinBytesFilter] = useState('')
  const [limitFilter, setLimitFilter] = useState('20')
  const [dataMode, setDataMode] = useState<DataMode>('combined')

  // Data state
  const [ndrStats, setNdrStats] = useState<NDRStats | null>(null)
  const [flowStats, setFlowStats] = useState<FlowStats | null>(null)
  const [flows, setFlows] = useState<NetworkFlow[]>([])
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([])
  const [protocols, setProtocols] = useState<ProtocolDistribution[]>([])
  const [lateralMovements, setLateralMovements] = useState<LateralMovement[]>([])
  const [ja3Stats, setJa3Stats] = useState<JA3Stats[]>([])
  const [tlsSessions, setTlsSessions] = useState<TLSSession[]>([])
  const [certificates, setCertificates] = useState<CertificateAnalysis[]>([])
  const [anomalies, setAnomalies] = useState<NDRAnomaly[]>([])
  const [topology, setTopology] = useState<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>({ nodes: [], edges: [] })
  const [sourceHealth, setSourceHealth] = useState<SourceHealth[]>([])
  const [sourceHealthAvailable, setSourceHealthAvailable] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)

  // Real-time connection
  const { connectionState } = useEventStream()

  // Fetch all NDR data
  const fetchData = useCallback(async () => {
    try {
      const normalizedAgent = agentFilter.trim()
      const normalizedLimit = Math.min(Math.max(Number(limitFilter) || 20, 5), 100)
      const selectedProtocol = protocolFilter !== 'all' ? protocolFilter : undefined
      const agentQuery = buildQuery({ agent_id: normalizedAgent || undefined, mode: dataMode })
      const talkerQuery = buildQuery({ agent_id: normalizedAgent || undefined, limit: normalizedLimit, mode: dataMode })
      const protocolQuery = buildQuery({ agent_id: normalizedAgent || undefined })
      const lateralQuery = buildQuery({ agent_id: normalizedAgent || undefined, limit: normalizedLimit })
      const ja3Query = buildQuery({ agent_id: normalizedAgent || undefined, limit: normalizedLimit })
      const flowQuery = buildQuery({ agent_id: normalizedAgent || undefined, protocol: selectedProtocol, limit: normalizedLimit, mode: dataMode })

      const [statsRes, flowStatsRes, flowRowsRes, talkersRes, protocolsRes, lateralRes, ja3Res, tlsRes, certRes, anomaliesRes, topoRes, healthRes] = await Promise.all([
        fetch('/api/v1/ndr/stats', { credentials: 'include' }),
        fetch(`/api/v1/ndr/flows/stats${flowQuery}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/flows${flowQuery}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/top-talkers${talkerQuery}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/protocols${protocolQuery}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/lateral-movement${lateralQuery}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/ja3${ja3Query}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/tls-sessions${ja3Query}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/certificates${ja3Query}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/anomalies${ja3Query}`, { credentials: 'include' }),
        fetch(`/api/v1/ndr/topology${agentQuery}`, { credentials: 'include' }),
        fetch('/api/v1/ndr/data-sources', { credentials: 'include' }),
      ])

      if (statsRes.ok) {
        const data = await statsRes.json()
        setNdrStats(data.data)
      }

      if (flowStatsRes.ok) {
        const data = await flowStatsRes.json()
        setFlowStats(data.data)
      }

      if (flowRowsRes.ok) {
        const data = await flowRowsRes.json()
        setFlows(data.data || [])
      }

      if (talkersRes.ok) {
        const data = await talkersRes.json()
        setTopTalkers(data.data || [])
      }

      if (protocolsRes.ok) {
        const data = await protocolsRes.json()
        setProtocols(data.data || [])
      }

      if (lateralRes.ok) {
        const data = await lateralRes.json()
        setLateralMovements(data.data || [])
      }

      if (ja3Res.ok) {
        const data = await ja3Res.json()
        setJa3Stats(data.data || [])
      }

      if (tlsRes.ok) {
        const data = await tlsRes.json()
        setTlsSessions(data.data || [])
      }

      if (certRes.ok) {
        const data = await certRes.json()
        setCertificates(data.data || [])
      }

      if (anomaliesRes.ok) {
        const data = await anomaliesRes.json()
        setAnomalies(data.data || [])
      }

      if (topoRes.ok) {
        const data = await topoRes.json()
        setTopology(data.data || { nodes: [], edges: [] })
      }

      if (healthRes.ok) {
        const data = await healthRes.json()
        const normalized = normalizeSourceHealth(data)
        setSourceHealth(normalized)
        setSourceHealthAvailable(normalized.length > 0)
      } else if (healthRes.status === 404) {
        setSourceHealthAvailable(false)
      }

      setLastUpdated(new Date().toISOString())
    } catch (error) {
      logger.error('Failed to fetch NDR data:', error)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [agentFilter, limitFilter, protocolFilter, dataMode])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [fetchData])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const query = new URLSearchParams(window.location.search)
    query.set('tab', activeTab)
    if (activeTab === 'encrypted') query.set('section', encryptedSection)
    else query.delete('section')
    const next = `${window.location.pathname}?${query.toString()}`
    window.history.replaceState(null, '', next)
  }, [activeTab, encryptedSection])

  const handleRefresh = () => {
    setRefreshing(true)
    fetchData()
  }

  const handleBlockIP = useCallback(async (talker: TopTalker) => {
    if (!talker.agent_id || !talker.ip) return

    try {
      const res = await fetch('/api/v1/response/block-ip', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          agent_id: talker.agent_id,
          ip: talker.ip,
          direction: 'both',
          reason: 'Blocked from NDR top talkers',
        }),
      })

      if (!res.ok) {
        logger.error('Failed to block NDR top talker:', res.status)
      }
    } catch (error) {
      logger.error('Failed to block NDR top talker:', error)
    }
  }, [])

  const moduleStats = {
    total_flows_processed: ndrStats?.flow_analyzer?.flows_processed || 0,
    total_events_analyzed:
      (ndrStats?.protocol_analyzer?.events_analyzed || 0) +
      (ndrStats?.lateral_detector?.events_analyzed || 0) +
      (ndrStats?.encrypted_traffic?.events_analyzed || 0),
    total_anomalies:
      (ndrStats?.flow_analyzer?.anomalies_detected || 0) +
      (ndrStats?.lateral_detector?.lateral_movements_detected || 0) +
      (ndrStats?.encrypted_traffic?.ja3_matches || 0) +
      (ndrStats?.encrypted_traffic?.suspicious_certs || 0),
    total_alerts:
      (ndrStats?.flow_analyzer?.alerts_created || 0) +
      (ndrStats?.protocol_analyzer?.alerts_created || 0) +
      (ndrStats?.lateral_detector?.alerts_created || 0) +
      (ndrStats?.encrypted_traffic?.alerts_created || 0),
  }
  const stats = {
    total_flows_processed: Math.max(ndrStats?.summary?.total_flows_processed || 0, moduleStats.total_flows_processed),
    total_events_analyzed: Math.max(ndrStats?.summary?.total_events_analyzed || 0, moduleStats.total_events_analyzed),
    total_anomalies: Math.max(ndrStats?.summary?.total_anomalies || 0, moduleStats.total_anomalies),
    total_alerts: Math.max(ndrStats?.summary?.total_alerts || 0, moduleStats.total_alerts),
  }
  const hasNetworkTelemetry =
    stats.total_flows_processed > 0 ||
    stats.total_events_analyzed > 0 ||
    Boolean(flowStats && flowStats.total_flows > 0) ||
    flows.length > 0 ||
    topTalkers.length > 0 ||
    protocols.length > 0 ||
    lateralMovements.length > 0 ||
    ja3Stats.length > 0 ||
    tlsSessions.length > 0 ||
    certificates.length > 0 ||
    anomalies.length > 0 ||
    topology.nodes.length > 0

  const sourceCoverage = useMemo<SourceHealth[]>(() => {
    if (sourceHealth.length > 0) return sourceHealth

    const flowEvents = ndrStats?.flow_analyzer?.flows_processed || flowStats?.total_flows || 0
    const protocolEvents = ndrStats?.protocol_analyzer?.events_analyzed || 0
    const lateralEvents = ndrStats?.lateral_detector?.events_analyzed || lateralMovements.length
    const encryptedEvents = ndrStats?.encrypted_traffic?.events_analyzed || ja3Stats.length + tlsSessions.length + certificates.length

    return [
      {
        key: 'flow_analyzer',
        label: 'Flow analyzer',
        status: flowEvents > 0 ? 'healthy' : 'empty',
        coverage: `${formatNumber(flowEvents)} flows observed`,
      },
      {
        key: 'protocol_analyzer',
        label: 'Protocol analyzer',
        status: protocolEvents > 0 || protocols.length > 0 ? 'healthy' : 'empty',
        coverage: `${formatNumber(protocolEvents)} protocol events`,
      },
      {
        key: 'lateral_detector',
        label: 'Lateral detector',
        status: lateralEvents > 0 ? 'healthy' : 'empty',
        coverage: `${formatNumber(lateralEvents)} lateral inputs`,
      },
      {
        key: 'encrypted_traffic',
        label: 'Encrypted traffic',
        status: encryptedEvents > 0 ? 'healthy' : 'empty',
        coverage: `${formatNumber(encryptedEvents)} TLS/JA3 inputs`,
      },
    ]
  }, [sourceHealth, ndrStats, flowStats, protocols.length, lateralMovements.length, ja3Stats.length, tlsSessions.length, certificates.length])

  const historicalSource = sourceCoverage.find(source => source.key === 'historical')
  const historicalStatus = historicalSource?.status === 'healthy'
    ? 'Available'
    : historicalSource?.status === 'unavailable'
      ? 'Not configured'
      : 'Runtime only'
  const historicalCoverage = useMemo(() => {
    const tables = sourceCoverage.filter(source => source.key.startsWith('historical-'))
    const rows = tables.reduce((sum, source) => sum + (source.row_count || 0), 0)
    const coveredTables = tables.filter(source => (source.row_count || 0) > 0 || source.status === 'healthy').length
    const seenTimestamps = tables
      .map(source => source.last_seen)
      .filter(Boolean)
      .sort()
    const lastSeen = seenTimestamps.length > 0 ? seenTimestamps[seenTimestamps.length - 1] : undefined

    return {
      tables: tables.length,
      coveredTables,
      rows,
      lastSeen,
      available: historicalSource?.status === 'healthy' || rows > 0,
      unavailable: historicalSource?.status === 'unavailable',
    }
  }, [sourceCoverage, historicalSource?.status])

  const protocolOptions = useMemo(() => {
    const values = new Set(protocols.map(item => item.protocol).filter(Boolean))
    ;['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'TLS', 'SMB', 'RDP', 'SSH'].forEach(value => values.add(value))
    return Array.from(values).sort()
  }, [protocols])

  const lateralTypeOptions = useMemo(() => {
    return Array.from(new Set(lateralMovements.map(item => item.type).filter(Boolean))).sort()
  }, [lateralMovements])

  const minBytes = numericFilter(minBytesFilter)

  const filteredFlows = useMemo(() => {
    return flows.filter(flow => {
      if (ipFilter && !matchesText(flow.src_ip, ipFilter) && !matchesText(flow.dst_ip, ipFilter) && !matchesText(flow.process_name, ipFilter)) return false
      if (minBytes && Number(flow.total_bytes || 0) < minBytes) return false
      return true
    })
  }, [flows, ipFilter, minBytes])

  const filteredTopTalkers = useMemo(() => {
    return topTalkers.filter(talker => {
      if (!matchesText(talker.ip, ipFilter) && !matchesText(talker.agent_id, ipFilter)) return false
      if (minBytes && Number(talker.total_bytes || 0) < minBytes) return false
      return true
    })
  }, [topTalkers, ipFilter, minBytes])

  const filteredProtocols = useMemo(() => {
    return protocols.filter(item => {
      if (protocolFilter !== 'all' && item.protocol !== protocolFilter) return false
      if (minBytes && Number(item.total_bytes || 0) < minBytes) return false
      return true
    })
  }, [protocols, protocolFilter, minBytes])

  const filteredLateralMovements = useMemo(() => {
    return lateralMovements.filter(item => {
      if (lateralTypeFilter !== 'all' && item.type !== lateralTypeFilter) return false
      if (ipFilter && !matchesText(item.src_ip, ipFilter) && !matchesText(item.dst_ip, ipFilter)) return false
      return true
    })
  }, [lateralMovements, lateralTypeFilter, ipFilter])

  const filteredJa3Stats = useMemo(() => {
    return ja3Stats.filter(item => {
      if (ja3StatusFilter === 'malicious' && !item.is_malicious) return false
      if (ja3StatusFilter === 'clean' && item.is_malicious) return false
      if (ipFilter && !matchesText(item.ja3_hash, ipFilter) && !matchesText(item.ja3s_hash, ipFilter) && !matchesText(item.malware_info?.name, ipFilter)) return false
      return true
    })
  }, [ja3Stats, ja3StatusFilter, ipFilter])

  const filteredTlsSessions = useMemo(() => {
    return tlsSessions.filter(item => {
      const process = formatProcess(item.process)
      const metadata = tlsMetadata(item)
      if (
        ipFilter &&
        !matchesText(item.remote_ip, ipFilter) &&
        !matchesText(item.local_ip, ipFilter) &&
        !matchesText(item.sni, ipFilter) &&
        !matchesText(item.domain, ipFilter) &&
        !matchesText(item.ja3, ipFilter) &&
        !matchesText(item.ja3s, ipFilter) &&
        !matchesText(process, ipFilter) &&
        !matchesText(item.alpn, ipFilter) &&
        !matchesText(metadata.alpn, ipFilter) &&
        !matchesText(item.quic_version, ipFilter) &&
        !matchesText(metadata.quic_version, ipFilter) &&
        !matchesText(item.encrypted_dns_transport, ipFilter) &&
        !matchesText(metadata.encrypted_dns_transport, ipFilter) &&
        !matchesText(item.dns_resolver, ipFilter) &&
        !matchesText(metadata.dns_resolver, ipFilter)
      ) return false
      if (protocolFilter !== 'all' && item.protocol && item.protocol.toUpperCase() !== protocolFilter.toUpperCase()) return false
      return true
    })
  }, [tlsSessions, ipFilter, protocolFilter])

  const filteredCertificates = useMemo(() => {
    return certificates.filter(item => {
      if (ipFilter && !matchesText(item.remote_ip, ipFilter) && !matchesText(item.domain, ipFilter) && !matchesText(item.subject, ipFilter) && !matchesText(item.issuer, ipFilter) && !matchesText(item.fingerprint, ipFilter)) return false
      return true
    })
  }, [certificates, ipFilter])

  const filteredAnomalies = useMemo(() => {
    return anomalies.filter(item => {
      if (ipFilter && !matchesText(item.type, ipFilter) && !matchesText(item.description, ipFilter) && !matchesText(item.flow_key, ipFilter)) return false
      return true
    })
  }, [anomalies, ipFilter])

  const filteredTopology = useMemo(() => {
    const nodes = topology.nodes.filter(node => {
      if (scopeFilter === 'internal' && !node.is_internal) return false
      if (scopeFilter === 'external' && node.is_internal) return false
      if (ipFilter && !matchesText(node.id, ipFilter) && !matchesText(node.label, ipFilter)) return false
      if (minBytes && Number(node.total_bytes || 0) < minBytes) return false
      return true
    })
    const nodeIds = new Set(nodes.map(node => node.id))
    const edges = topology.edges.filter(edge => {
      if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return false
      if (protocolFilter !== 'all' && edge.protocol !== protocolFilter) return false
      if (minBytes && Number(edge.bytes || 0) < minBytes) return false
      return true
    })
    return { nodes, edges }
  }, [topology, scopeFilter, ipFilter, protocolFilter, minBytes])

  const hasFilteredTelemetry =
    filteredFlows.length > 0 ||
    filteredTopTalkers.length > 0 ||
    filteredProtocols.length > 0 ||
    filteredLateralMovements.length > 0 ||
    filteredJa3Stats.length > 0 ||
    filteredTlsSessions.length > 0 ||
    filteredCertificates.length > 0 ||
    filteredAnomalies.length > 0 ||
    filteredTopology.nodes.length > 0

  const activeFilterSummary = [
    agentFilter.trim() ? `agent=${agentFilter.trim()}` : null,
    ipFilter.trim() ? `search=${ipFilter.trim()}` : null,
    protocolFilter !== 'all' ? `protocol=${protocolFilter}` : null,
    scopeFilter !== 'all' ? `scope=${scopeFilter}` : null,
    lateralTypeFilter !== 'all' ? `lateral=${lateralTypeFilter}` : null,
    ja3StatusFilter !== 'all' ? `ja3=${ja3StatusFilter}` : null,
    minBytes ? `min_bytes=${minBytes}` : null,
  ].filter(Boolean)

  const resetFilters = () => {
    setAgentFilter('')
    setIpFilter('')
    setProtocolFilter('all')
    setScopeFilter('all')
    setLateralTypeFilter('all')
    setJa3StatusFilter('all')
    setMinBytesFilter('')
    setLimitFilter('20')
  }

  return (
    <MainLayout title="Network Detection & Response">
      <Head title="NDR - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-500/10 rounded-lg">
              <Network className="h-6 w-6 text-purple-400" />
            </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--fg)]">Network Detection & Response</h1>
            <p className="text-sm text-[var(--muted)]">
                Live runtime analyzers with 30s auto-refresh from active agent network telemetry
            </p>
          </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden md:inline-flex items-center gap-1.5 text-xs text-[var(--muted)]">
              <Clock className="h-3.5 w-3.5" />
              {lastUpdated ? `Updated ${relativeTime(lastUpdated)}` : 'Not loaded yet'}
            </span>
            <ConnectionStatus state={connectionState as WebSocketConnectionState} size="sm" />
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-2 px-4 py-2 bg-[var(--surface)]/50 hover:bg-[var(--surface)] border border-[var(--surface)]/50 rounded-lg text-sm text-[var(--fg)] transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn('h-4 w-4', refreshing && 'animate-spin')} />
              Refresh
            </button>
          </div>
        </div>

        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 px-4 py-3 text-xs text-[var(--muted)] flex items-center gap-2">
          <Zap className="h-3.5 w-3.5 text-cyan-400" />
          Select whether flow, top talker, and topology views use live runtime state, persisted history, or both. Protocol, JA3, and lateral detector panels remain live analyzer views.
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <DataModeCard
            icon={Database}
            title="Combined"
            status={dataMode === 'combined' ? 'Selected' : 'Live + historical'}
            description="Merges runtime flow state with persisted NDR rows for the broadest operational view."
            active={dataMode === 'combined'}
            onClick={() => setDataMode('combined')}
          />
          <DataModeCard
            icon={Radio}
            title="Live data"
            status={connectionState === 'connected' ? 'Streaming' : 'REST snapshots'}
            description="Runtime flow, protocol, topology, JA3, and lateral-movement counters from active agent telemetry."
            active={dataMode === 'live'}
            onClick={() => setDataMode('live')}
          />
          <DataModeCard
            icon={History}
            title="Historical data"
            status={historicalCoverage.rows > 0 ? `${formatNumber(historicalCoverage.rows)} rows` : historicalStatus}
            description="Queries persisted NDR flow rows for investigation, refresh, and audit workflows; live-only analyzers keep using runtime counters."
            active={dataMode === 'historical'}
            onClick={() => setDataMode('historical')}
          />
        </div>

        {(historicalSource || historicalCoverage.tables > 0 || dataMode === 'historical') && (
          <div
            className={cn(
              'rounded-lg border px-4 py-3 text-xs flex flex-col gap-1',
              historicalCoverage.available
                ? 'border-[var(--emerald-400)]/20 bg-[var(--emerald-400)]/10 text-[var(--fg)]'
                : dataMode === 'historical' || historicalCoverage.unavailable
                  ? 'border-[var(--high)]/25 bg-[var(--high)]/10 text-[var(--fg)]'
                  : 'border-[var(--border)] bg-[var(--surface)]/40 text-[var(--muted)]'
            )}
          >
            <div className="flex flex-wrap items-center gap-2">
              <History className="h-3.5 w-3.5" />
              <span className="font-medium">
                Historical coverage: {historicalCoverage.coveredTables}/{historicalCoverage.tables || 1} tables, {formatNumber(historicalCoverage.rows)} rows
              </span>
              {historicalCoverage.lastSeen && (
                <span className="text-[var(--muted)]">newest {relativeTime(historicalCoverage.lastSeen)}</span>
              )}
            </div>
            <p className="text-[var(--muted)]">
              {historicalCoverage.available
                ? 'Historical mode applies to flow rows, top talkers, and topology. Protocol, JA3, and lateral movement panels are still live analyzer views until those stores report historical coverage.'
                : 'No persisted NDR flow history is reporting coverage yet. Historical mode may return empty flow, talker, and topology views while live telemetry remains visible in runtime panels.'}
            </p>
          </div>
        )}

        <SourceCoveragePanel
          sources={sourceCoverage}
          available={sourceHealthAvailable}
          lastUpdated={lastUpdated}
        />

        <div className="card-sentinel p-4">
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-purple-400" />
                <h2 className="text-sm font-semibold text-[var(--fg)]">NDR filters</h2>
              </div>
              <button
                type="button"
                onClick={resetFilters}
                className="text-xs text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
              >
                Clear filters
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Agent ID</span>
                <input
                  value={agentFilter}
                  onChange={event => setAgentFilter(event.target.value)}
                  placeholder="Filter backend queries by agent"
                  className="input-sentinel"
                />
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">IP, JA3, host or malware</span>
                <input
                  value={ipFilter}
                  onChange={event => setIpFilter(event.target.value)}
                  placeholder="Search loaded NDR data"
                  className="input-sentinel"
                />
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Protocol</span>
                <select value={protocolFilter} onChange={event => setProtocolFilter(event.target.value)} className="input-sentinel">
                  <option value="all">All protocols</option>
                  {protocolOptions.map(protocol => (
                    <option key={protocol} value={protocol}>{protocol}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Topology scope</span>
                <select value={scopeFilter} onChange={event => setScopeFilter(event.target.value as typeof scopeFilter)} className="input-sentinel">
                  <option value="all">Internal and external</option>
                  <option value="internal">Internal only</option>
                  <option value="external">External only</option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Lateral activity</span>
                <select value={lateralTypeFilter} onChange={event => setLateralTypeFilter(event.target.value)} className="input-sentinel">
                  <option value="all">All lateral detections</option>
                  {lateralTypeOptions.map(type => (
                    <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">JA3 status</span>
                <select value={ja3StatusFilter} onChange={event => setJa3StatusFilter(event.target.value as typeof ja3StatusFilter)} className="input-sentinel">
                  <option value="all">All JA3 fingerprints</option>
                  <option value="malicious">Malicious only</option>
                  <option value="clean">Clean only</option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Minimum bytes</span>
                <input
                  value={minBytesFilter}
                  onChange={event => setMinBytesFilter(event.target.value)}
                  placeholder="0"
                  inputMode="numeric"
                  className="input-sentinel"
                />
              </label>
              <label className="space-y-1">
                <span className="text-xs text-[var(--muted)]">Result limit</span>
                <select value={limitFilter} onChange={event => setLimitFilter(event.target.value)} className="input-sentinel">
                  <option value="10">10</option>
                  <option value="20">20</option>
                  <option value="50">50</option>
                  <option value="100">100</option>
                </select>
              </label>
            </div>
          </div>
        </div>

        {!loading && !hasNetworkTelemetry && (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 px-4 py-6">
            <EmptyTelemetryState />
          </div>
        )}

        {!loading && hasNetworkTelemetry && !hasFilteredTelemetry && (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 px-4 py-6">
            <EmptyTelemetryState
              message={
                activeFilterSummary.length > 0
                  ? `NDR telemetry exists, but no rows match: ${activeFilterSummary.join(', ')}`
                  : 'NDR telemetry exists, but no rows match the active filters'
              }
            />
          </div>
        )}

        {!loading && hasNetworkTelemetry && activeFilterSummary.length > 0 && hasFilteredTelemetry && (
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-xs text-cyan-200">
            Showing filtered NDR telemetry for {activeFilterSummary.join(', ')}. Top counters remain global module totals; table rows and flow statistics follow the active filters.
          </div>
        )}

        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            icon={Activity}
            label="Flows Processed"
            value={stats.total_flows_processed}
            color="cyan"
          />
          <StatCard
            icon={Eye}
            label="Events Analyzed"
            value={stats.total_events_analyzed}
            color="blue"
          />
          <StatCard
            icon={AlertTriangle}
            label="Anomalies Detected"
            value={stats.total_anomalies}
            color="amber"
            alert={stats.total_anomalies > 0}
          />
          <StatCard
            icon={ShieldAlert}
            label="Alerts Created"
            value={stats.total_alerts}
            color="red"
            alert={stats.total_alerts > 0}
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 bg-[var(--surface)]/50 p-1 rounded-lg w-fit">
          {([
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'lateral', label: 'Lateral Movement', icon: Share2 },
            { id: 'encrypted', label: 'Encrypted Traffic', icon: Lock },
            { id: 'protocols', label: 'Protocols', icon: Wifi },
            { id: 'anomalies', label: 'Anomalies', icon: AlertTriangle },
          ] as const).map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                activeTab === tab.id
                  ? 'bg-purple-500/20 text-purple-400'
                  : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface)]/50'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content Panels */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="lg:col-span-2 card-sentinel p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <h3 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Network className="h-5 w-5 text-cyan-400" />
                  Recent Flows
                </h3>
                <span className="text-xs text-[var(--muted)]">
                  {filteredFlows.length} of {flows.length} loaded flows
                </span>
              </div>
              <RecentFlowsTable flows={filteredFlows} />
            </div>

            {/* Flow Stats */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <Activity className="h-5 w-5 text-cyan-400" />
                Traffic Statistics
              </h3>
              {flowStats ? (
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Active Flows</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{formatNumber(flowStats.total_flows)}</p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Total Bytes</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{formatBytes(flowStats.total_bytes)}</p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Packets</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{formatNumber(flowStats.total_packets)}</p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Throughput</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{formatBytes(flowStats.bytes_per_second)}/s</p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Unique Sources</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{flowStats.unique_sources}</p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3">
                    <p className="text-xs text-[var(--muted)] mb-1">Unique Destinations</p>
                    <p className="text-2xl font-bold text-[var(--fg)]">{flowStats.unique_destinations}</p>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-[var(--muted)]">Loading flow statistics...</div>
              )}
            </div>

            {/* Protocol Distribution */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <PieChart className="h-5 w-5 text-purple-400" />
                Protocol Distribution
              </h3>
              <ProtocolPieChart data={filteredProtocols} />
            </div>

            {/* Top Talkers */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-[var(--emerald-400)]" />
                Top Talkers
              </h3>
              <TopTalkersTable talkers={filteredTopTalkers} onBlockIP={handleBlockIP} />
            </div>

            {/* Network Topology Mini */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <Globe className="h-5 w-5 text-blue-400" />
                Network Topology
              </h3>
              <NetworkTopologyMini nodes={filteredTopology.nodes} edges={filteredTopology.edges} />
            </div>
          </div>
        )}

        {activeTab === 'lateral' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Lateral Movement Stats */}
            <div className="lg:col-span-1 space-y-4">
              <div className="card-sentinel p-5">
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Detection Summary</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Port Scans</span>
                    <span className="text-lg font-bold text-[var(--high)]">
                      {ndrStats?.lateral_detector?.port_scans_detected || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Host Scans</span>
                    <span className="text-lg font-bold text-[var(--med)]">
                      {ndrStats?.lateral_detector?.host_scans_detected || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Lateral Movements</span>
                    <span className="text-lg font-bold text-purple-400">
                      {ndrStats?.lateral_detector?.lateral_movements_detected || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Credential Spreads</span>
                    <span className="text-lg font-bold text-[var(--crit)]">
                      {ndrStats?.lateral_detector?.credential_spreads_detected || 0}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Lateral Movement List */}
            <div className="lg:col-span-2">
              <div className="card-sentinel p-5">
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                  <Share2 className="h-5 w-5 text-purple-400" />
                  Recent Lateral Movement Activity
                </h3>
                <LateralMovementList movements={filteredLateralMovements} />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'encrypted' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Encrypted Traffic Stats */}
            <div className="lg:col-span-1 space-y-4">
              <div className="card-sentinel p-5">
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">TLS Analysis</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Events Analyzed</span>
                    <span className="text-lg font-bold text-cyan-400">
                      {ndrStats?.encrypted_traffic?.events_analyzed || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">JA3 Matches</span>
                    <span className="text-lg font-bold text-[var(--crit)]">
                      {ndrStats?.encrypted_traffic?.ja3_matches || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Suspicious Certs</span>
                    <span className="text-lg font-bold text-[var(--med)]">
                      {ndrStats?.encrypted_traffic?.suspicious_certs || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Self-Signed Certs</span>
                    <span className="text-lg font-bold text-[var(--high)]">
                      {ndrStats?.encrypted_traffic?.self_signed_certs || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">TLS Sessions</span>
                    <span className="text-lg font-bold text-cyan-400">{tlsSessions.length}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-[var(--surface)]/40 rounded-lg">
                    <span className="text-sm text-[var(--muted)]">Certificates</span>
                    <span className="text-lg font-bold text-purple-400">{certificates.length}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="lg:col-span-2">
              <div className="card-sentinel p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <h3 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                    <Key className="h-5 w-5 text-[var(--med)]" />
                    Encrypted Metadata
                  </h3>
                  <div className="flex items-center gap-1 rounded-lg bg-[var(--surface)]/50 p-1">
                    {([
                      { id: 'ja3', label: 'JA3' },
                      { id: 'tls', label: 'TLS Sessions' },
                      { id: 'certificates', label: 'Certificates' },
                    ] as const).map(section => (
                      <button
                        key={section.id}
                        onClick={() => setEncryptedSection(section.id)}
                        className={cn(
                          'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                          encryptedSection === section.id
                            ? 'bg-purple-500/20 text-purple-300'
                            : 'text-[var(--muted)] hover:bg-[var(--surface)]/50 hover:text-[var(--fg)]'
                        )}
                      >
                        {section.label}
                      </button>
                    ))}
                  </div>
                </div>
                {encryptedSection === 'ja3' && <JA3Table stats={filteredJa3Stats} />}
                {encryptedSection === 'tls' && <TLSSessionsTable sessions={filteredTlsSessions} />}
                {encryptedSection === 'certificates' && <CertificatesTable certificates={filteredCertificates} />}
              </div>
            </div>
            </div>

            <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-xs text-cyan-100">
              Encrypted traffic analysis is metadata-based. Tamandua uses SNI, JA3/JA3S, TLS version, certificate fields, flow context, and DNS resolver signals when the agent reports them; it does not decrypt payloads or perform implicit MITM.
            </div>
          </div>
        )}

        {activeTab === 'anomalies' && (
          <div className="card-sentinel p-5">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-[var(--med)]" />
                NDR Anomalies
              </h3>
              <span className="text-xs text-[var(--muted)]">
                {filteredAnomalies.length} of {anomalies.length} loaded anomalies
              </span>
            </div>
            <AnomaliesList anomalies={filteredAnomalies} />
          </div>
        )}

        {activeTab === 'protocols' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Protocol Stats */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <Wifi className="h-5 w-5 text-blue-400" />
                Protocol Analysis
              </h3>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
                    <p className="text-xs text-[var(--muted)] mb-1">HTTP Analyzed</p>
                    <p className="text-xl font-bold text-blue-400">
                      {ndrStats?.protocol_analyzer?.http_analyzed || 0}
                    </p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
                    <p className="text-xs text-[var(--muted)] mb-1">SMB Analyzed</p>
                    <p className="text-xl font-bold text-purple-400">
                      {ndrStats?.protocol_analyzer?.smb_analyzed || 0}
                    </p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
                    <p className="text-xs text-[var(--muted)] mb-1">RDP Sessions</p>
                    <p className="text-xl font-bold text-[var(--emerald-400)]">
                      {ndrStats?.protocol_analyzer?.rdp_sessions || 0}
                    </p>
                  </div>
                  <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
                    <p className="text-xs text-[var(--muted)] mb-1">SSH Sessions</p>
                    <p className="text-xl font-bold text-cyan-400">
                      {ndrStats?.protocol_analyzer?.ssh_sessions || 0}
                    </p>
                  </div>
                </div>
                <div className="bg-[var(--surface)]/40 rounded-lg p-3 text-center">
                  <p className="text-xs text-[var(--muted)] mb-1">Protocol Detections</p>
                  <p className="text-2xl font-bold text-[var(--med)]">
                    {ndrStats?.protocol_analyzer?.detections || 0}
                  </p>
                </div>
              </div>
            </div>

            {/* Protocol Distribution (larger view) */}
            <div className="card-sentinel p-5">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <BarChart3 className="h-5 w-5 text-purple-400" />
                Traffic by Protocol
              </h3>
              <ProtocolPieChart data={filteredProtocols} />
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
