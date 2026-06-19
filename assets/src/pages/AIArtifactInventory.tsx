import { Head, router } from '@inertiajs/react'
import { useMemo, useState } from 'react'
import {
  AlertTriangle,
  Bot,
  Database,
  FileCode,
  Fingerprint,
  RefreshCw,
  Search,
  ShieldCheck,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'
import { EmptyState } from '@/components/ui/EmptyState'
import { Select, SelectItem } from '@/components/ui/baseui'
import { cn, formatDate, safeCapitalize } from '@/lib/utils'

interface AIArtifact {
  id: string
  source: 'Codex' | 'Claude' | 'Cursor' | 'Windsurf' | 'MCP' | 'Skills' | 'AI' | string
  name: string
  component_type?: string
  artifact_type?: string
  file_hash?: string | null
  redacted_preview?: string | null
  matched_patterns: string[]
  risk_score: number
  risk_level: 'critical' | 'high' | 'medium' | 'low' | string
  severity: 'critical' | 'high' | 'medium' | 'low' | string
  policy_status: string
  is_shadow: boolean
  agent_id?: string | null
  agent_hostname?: string | null
  organization_id?: string | null
  organization_name?: string | null
  version?: string | null
  install_path?: string | null
  config_path?: string | null
  discovered_at?: string | null
  inserted_at?: string | null
  updated_at?: string | null
}

interface Stats {
  total: number
  with_hash: number
  high_or_critical: number
  matched_patterns: number
  by_source: Array<{ source: string; count: number }>
}

interface DataSource {
  table: string
  collector: string
  emptyState: boolean
}

interface Props {
  artifacts: AIArtifact[]
  stats: Stats
  dataSource: DataSource
}

const SOURCE_OPTIONS = ['all', 'Codex', 'Claude', 'Cursor', 'Windsurf', 'MCP', 'Skills']

export default function AIArtifactInventory({ artifacts = [], stats, dataSource }: Props) {
  const [query, setQuery] = useState('')
  const [source, setSource] = useState('all')
  const [severity, setSeverity] = useState('all')

  const filteredArtifacts = useMemo(() => {
    const q = query.trim().toLowerCase()

    return artifacts.filter((artifact) => {
      const matchesSource = source === 'all' || artifact.source === source
      const matchesSeverity = severity === 'all' || artifact.severity === severity
      const haystack = [
        artifact.source,
        artifact.name,
        artifact.artifact_type,
        artifact.component_type,
        artifact.file_hash,
        artifact.agent_hostname,
        artifact.organization_name,
        artifact.install_path,
        artifact.config_path,
        artifact.matched_patterns.join(' '),
      ].filter(Boolean).join(' ').toLowerCase()

      return matchesSource && matchesSeverity && (!q || haystack.includes(q))
    })
  }, [artifacts, query, severity, source])

  const hasFilters = query !== '' || source !== 'all' || severity !== 'all'

  return (
    <MainLayout title="AI Artifact Inventory">
      <Head title="AI Artifact Inventory - Tamandua EDR" />

      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard title="Artifacts" value={stats.total} icon={Database} tone="primary" />
          <StatCard title="With File Hash" value={stats.with_hash} icon={Fingerprint} tone="neutral" />
          <StatCard title="High or Critical" value={stats.high_or_critical} icon={AlertTriangle} tone="danger" />
          <StatCard title="Pattern Categories" value={stats.matched_patterns} icon={FileCode} tone="warning" />
        </div>

        <div className="card-sentinel rounded-xl p-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" style={{ color: 'var(--muted)' }} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search artifacts, hashes, agents, paths, or patterns..."
                className="w-full rounded-lg pl-10 pr-4 py-2 placeholder-[var(--subtle)] focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
              />
            </div>

            <Select
              value={source}
              onValueChange={setSource}
              placeholder="All Sources"
              className="rounded-lg px-3 py-2 text-sm"
            >
              {SOURCE_OPTIONS.map((option) => (
                <SelectItem key={option} value={option}>{option === 'all' ? 'All Sources' : option}</SelectItem>
              ))}
            </Select>

            <Select
              value={severity}
              onValueChange={setSeverity}
              placeholder="All Severity"
              className="rounded-lg px-3 py-2 text-sm"
            >
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </Select>

            <button
              onClick={() => router.reload()}
              className="inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors hover:bg-[var(--surface-3)]"
              style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>

        {artifacts.length === 0 ? (
          <div className="card-sentinel rounded-xl">
            <EmptyState
              icon={Bot}
              title="No AI artifacts reported"
              description={`No Codex, Claude, Cursor, Windsurf, MCP, or skill artifacts are present in ${dataSource.table}. The ${dataSource.collector} collector will populate this page when agents report artifact telemetry.`}
            />
          </div>
        ) : filteredArtifacts.length === 0 ? (
          <div className="card-sentinel rounded-xl">
            <EmptyState
              icon={Search}
              title="No matching artifacts"
              description="No artifact rows match the current search and filters."
              actions={hasFilters ? [{ label: 'Clear filters', onClick: () => { setQuery(''); setSource('all'); setSeverity('all') } }] : undefined}
            />
          </div>
        ) : (
          <ArtifactTable artifacts={filteredArtifacts} />
        )}
      </div>
    </MainLayout>
  )
}

function ArtifactTable({ artifacts }: { artifacts: AIArtifact[] }) {
  return (
    <div className="card-sentinel rounded-xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1180px]">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <Th>Source</Th>
              <Th>Artifact</Th>
              <Th>Hash</Th>
              <Th>Preview</Th>
              <Th>Patterns</Th>
              <Th>Risk</Th>
              <Th>Agent / Org</Th>
              <Th>Timestamps</Th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map((artifact) => (
              <tr key={artifact.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 align-top">
                  <div className="flex items-center gap-2">
                    <SourceIcon source={artifact.source} />
                    <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{artifact.source}</span>
                  </div>
                  <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>{artifact.component_type || 'unknown'}</div>
                </td>
                <td className="p-4 align-top">
                  <div className="max-w-[220px]">
                    <div className="text-sm font-medium truncate" title={artifact.name} style={{ color: 'var(--fg)' }}>{artifact.name}</div>
                    <div className="mt-1 text-xs font-mono truncate" title={artifact.install_path || artifact.config_path || undefined} style={{ color: 'var(--muted)' }}>
                      {artifact.artifact_type || 'artifact'} {artifact.version ? `v${artifact.version}` : ''}
                    </div>
                  </div>
                </td>
                <td className="p-4 align-top">
                  {artifact.file_hash ? (
                    <code className="block max-w-[190px] truncate rounded px-2 py-1 text-xs" title={artifact.file_hash} style={{ background: 'var(--bg)', color: 'var(--fg-2)' }}>
                      {artifact.file_hash}
                    </code>
                  ) : (
                    <span className="text-xs" style={{ color: 'var(--subtle)' }}>Not reported</span>
                  )}
                </td>
                <td className="p-4 align-top">
                  <p className="max-w-[280px] whitespace-pre-wrap text-xs leading-5" style={{ color: artifact.redacted_preview ? 'var(--fg-2)' : 'var(--subtle)' }}>
                    {artifact.redacted_preview || 'No redacted preview available'}
                  </p>
                </td>
                <td className="p-4 align-top">
                  <div className="flex max-w-[240px] flex-wrap gap-1.5">
                    {artifact.matched_patterns.length === 0 ? (
                      <span className="text-xs" style={{ color: 'var(--subtle)' }}>None</span>
                    ) : artifact.matched_patterns.map((pattern) => (
                      <span key={pattern} className="rounded px-2 py-0.5 text-xs" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                        {pattern.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="p-4 align-top">
                  <SeverityBadge severity={artifact.severity} />
                  <div className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
                    Score {artifact.risk_score} / {safeCapitalize(artifact.policy_status)}
                  </div>
                </td>
                <td className="p-4 align-top">
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>{artifact.agent_hostname || artifact.agent_id || 'Unknown agent'}</div>
                  <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>{artifact.organization_name || artifact.organization_id || 'Unknown org'}</div>
                </td>
                <td className="p-4 align-top text-xs" style={{ color: 'var(--muted)' }}>
                  <div>Seen: {formatDate(artifact.discovered_at || artifact.updated_at)}</div>
                  <div className="mt-1">Stored: {formatDate(artifact.inserted_at)}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>{children}</th>
}

function SourceIcon({ source }: { source: string }) {
  const className = 'h-4 w-4'
  if (source === 'MCP') return <Database className={className} style={{ color: 'var(--muted)' }} />
  if (source === 'Skills') return <FileCode className={className} style={{ color: 'var(--muted)' }} />
  return <Bot className={className} style={{ color: 'var(--muted)' }} />
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium uppercase',
      severity === 'critical' && 'bg-red-500/20 text-red-400',
      severity === 'high' && 'bg-orange-500/20 text-orange-400',
      severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
      severity === 'low' && 'bg-green-500/20 text-green-400'
    )}>
      {severity === 'low' ? <ShieldCheck className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
      {severity}
    </span>
  )
}

function StatCard({
  title,
  value,
  icon: Icon,
  tone,
}: {
  title: string
  value: number
  icon: React.ElementType
  tone: 'primary' | 'neutral' | 'danger' | 'warning'
}) {
  const toneClass = {
    primary: 'bg-primary-600/20 text-primary-400',
    neutral: 'bg-slate-500/20 text-slate-300',
    danger: 'bg-red-500/20 text-red-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
  }[tone]

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className={cn('inline-flex rounded-lg p-2', toneClass)}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="mt-4 text-3xl font-bold" style={{ color: 'var(--fg)' }}>{value}</div>
      <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>{title}</p>
    </div>
  )
}
