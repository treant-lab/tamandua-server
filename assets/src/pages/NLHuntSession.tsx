import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Terminal,
  Clock,
  Search,
  XCircle,
  Send,
  Code,
  FileSearch,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Loader2,
  Database,
  Hash,
  Target,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HuntQuery {
  id: string
  originalQuery: string
  parsedQuery: string
  generatedSql: string
  executedAt: string
  resultCount: number
}

interface HuntFinding {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  evidence: Record<string, unknown>[]
  mitreTechniques: string[]
  discoveredAt: string
}

interface HuntSession {
  id: string
  name: string
  status: 'active' | 'completed' | 'archived'
  createdAt: string
  updatedAt: string
  queryCount: number
  findingsCount: number
}

interface NLHuntSessionProps {
  sessionId: string
  session: HuntSession | null
  queries: HuntQuery[]
  results: Record<string, unknown>[]
  findings: HuntFinding[]
  error?: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getSessionStatusColor(status: string) {
  switch (status) {
    case 'active': return 'bg-green-500/20 text-green-400 border-green-500/30'
    case 'completed': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    case 'archived': return 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/30'
    default: return 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/30'
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30'
    default: return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
  }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

export default function NLHuntSession({
  sessionId,
  session,
  queries,
  results,
  findings,
  error,
}: NLHuntSessionProps) {
  const [queryInput, setQueryInput] = useState('')
  const [isQuerying, setIsQuerying] = useState(false)
  const [expandedQueries, setExpandedQueries] = useState<Record<string, boolean>>({})

  const toggleQuery = (id: string) => {
    setExpandedQueries(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const handleSubmitQuery = async () => {
    if (!queryInput.trim() || !session) return
    setIsQuerying(true)
    try {
      const res = await fetch(`/api/v1/nl-hunt/sessions/${session.id}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(getCsrfToken() ? { 'X-CSRF-Token': getCsrfToken() } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({ query: queryInput }),
      })
      if (!res.ok) {
        logger.error('Failed to execute query:', res.status)
      }
      setQueryInput('')
      router.reload()
    } catch (err) {
      logger.error('Failed to execute query:', err)
    } finally {
      setIsQuerying(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmitQuery()
    }
  }

  // Error state
  if (error) {
    return (
      <MainLayout title="">
        <Head title="Hunt Session Error - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/nl-hunt')}
                className="p-2 hover:bg-[var(--surface-hover)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <XCircle className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-[var(--fg)]">Session Error</h1>
                  <p className="text-sm text-[var(--muted)] mt-1">{error}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </MainLayout>
    )
  }

  // Not found state
  if (!session) {
    return (
      <MainLayout title="">
        <Head title="Hunt Session Not Found - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/nl-hunt')}
                className="p-2 hover:bg-[var(--surface-hover)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--muted)]/20">
                  <Search className="h-6 w-6 text-[var(--muted)]" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-[var(--fg)]">Session Not Found</h1>
                  <p className="text-sm text-[var(--muted)] mt-1">
                    Hunt session {sessionId} could not be found.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </MainLayout>
    )
  }

  return (
    <MainLayout title="">
      <Head title={`${session.name} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Header */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/nl-hunt')}
                className="p-2 hover:bg-[var(--surface-hover)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="p-3 rounded-xl bg-emerald-600/20">
                <Terminal className="h-8 w-8 text-emerald-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold text-[var(--fg)]">{session.name}</h1>
                  <span className={cn('px-2.5 py-1 rounded text-xs font-medium border', getSessionStatusColor(session.status))}>
                    {session.status.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-4 mt-1 text-sm text-[var(--muted)]">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Created: {formatDate(session.createdAt)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Hash className="h-3.5 w-3.5" />
                    {session.queryCount} queries
                  </span>
                  <span className="flex items-center gap-1">
                    <Target className="h-3.5 w-3.5" />
                    {session.findingsCount} findings
                  </span>
                </div>
              </div>
            </div>

            <button
              onClick={() => router.reload()}
              className="p-2 bg-[var(--surface-hover)] hover:bg-[var(--surface-active)] rounded-lg transition-colors"
              title="Refresh"
            >
              <RefreshCw className="h-5 w-5 text-[var(--muted)]" />
            </button>
          </div>
        </div>

        {/* Query Input */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-4">
          <div className="flex items-center gap-3">
            <Terminal className="h-5 w-5 text-emerald-400 shrink-0" />
            <input
              type="text"
              value={queryInput}
              onChange={e => setQueryInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask a natural language question about your telemetry data..."
              className="flex-1 bg-[var(--surface-inset)] border border-[var(--surface-border)] rounded-lg px-4 py-2.5 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
              disabled={isQuerying || session.status === 'archived'}
            />
            <button
              onClick={handleSubmitQuery}
              disabled={!queryInput.trim() || isQuerying || session.status === 'archived'}
              className={cn(
                'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors',
                !queryInput.trim() || isQuerying || session.status === 'archived'
                  ? 'bg-[var(--surface-hover)] text-[var(--muted)] cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white'
              )}
            >
              {isQuerying ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
              Query
            </button>
          </div>
        </div>

        {/* Query History */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)]">
          <div className="p-4 border-b border-[var(--surface-border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Database className="h-5 w-5 text-[var(--muted)]" />
              Query History
            </h2>
          </div>

          {queries.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Terminal className="h-10 w-10 mx-auto mb-2 opacity-50" />
              <p>No queries executed yet</p>
              <p className="text-xs mt-1">Ask a question above to get started</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--surface-border)]/50">
              {queries.map(query => {
                const isExpanded = expandedQueries[query.id]
                return (
                  <div key={query.id} className="p-4 hover:bg-[var(--surface-hover)]/20 transition-colors">
                    <button
                      onClick={() => toggleQuery(query.id)}
                      className="w-full text-left"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3 flex-1 min-w-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-[var(--muted)] mt-0.5 shrink-0" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-[var(--muted)] mt-0.5 shrink-0" />
                          )}
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-[var(--fg)] font-medium">{query.originalQuery}</p>
                            <div className="flex items-center gap-3 mt-1 text-xs text-[var(--muted)]">
                              <span>{formatDate(query.executedAt)}</span>
                              <span className="flex items-center gap-1">
                                <Database className="h-3 w-3" />
                                {query.resultCount} results
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="mt-3 ml-7 space-y-3">
                        {query.parsedQuery && (
                          <div>
                            <span className="text-xs text-[var(--muted)] uppercase tracking-wider">Parsed Query</span>
                            <p className="mt-1 text-xs text-[var(--fg-secondary)] bg-[var(--surface-inset)] rounded p-2">{query.parsedQuery}</p>
                          </div>
                        )}
                        <div>
                          <span className="text-xs text-[var(--muted)] uppercase tracking-wider">Generated SQL</span>
                          <pre className="mt-1 text-xs text-emerald-300 bg-[var(--surface-inset)] rounded p-3 overflow-x-auto font-mono">
                            {query.generatedSql}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Results Table */}
        {results.length > 0 && (
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)]">
            <div className="p-4 border-b border-[var(--surface-border)] flex items-center justify-between">
              <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                <FileSearch className="h-5 w-5 text-[var(--muted)]" />
                Latest Query Results
              </h2>
              <span className="text-xs text-[var(--muted)]">{results.length} rows</span>
            </div>
            <div className="overflow-x-auto">
              {results.length > 0 && typeof results[0] === 'object' && results[0] !== null && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[var(--surface-border)]">
                      {Object.keys(results[0]).map(key => (
                        <th key={key} className="text-left py-3 px-4 text-[var(--muted)] font-medium text-xs whitespace-nowrap">
                          {key}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--surface-border)]/50">
                    {results.slice(0, 100).map((row, idx) => (
                      <tr key={idx} className="hover:bg-[var(--surface-hover)]/30 transition-colors">
                        {Object.values(row as Record<string, unknown>).map((val, vIdx) => (
                          <td key={vIdx} className="py-2 px-4 text-[var(--fg-secondary)] text-xs font-mono max-w-[300px] truncate">
                            {val === null ? <span className="text-[var(--muted)]/60">null</span> : String(val)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {results.length > 100 && (
                <div className="p-3 text-center text-xs text-[var(--muted)] border-t border-[var(--surface-border)]">
                  Showing first 100 of {results.length} results
                </div>
              )}
            </div>
          </div>
        )}

        {/* Findings */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)]">
          <div className="p-4 border-b border-[var(--surface-border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Target className="h-5 w-5 text-[var(--muted)]" />
              Findings
            </h2>
          </div>

          {findings.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Shield className="h-10 w-10 mx-auto mb-2 opacity-50" />
              <p>No findings discovered</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--surface-border)]/50">
              {findings.map(finding => (
                <div key={finding.id} className="p-4 hover:bg-[var(--surface-hover)]/20 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getSeverityColor(finding.severity))}>
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-[var(--surface-hover)] text-[var(--fg-secondary)]">
                          {finding.type}
                        </span>
                      </div>
                      <p className="text-sm text-[var(--fg)] mt-1">{finding.description}</p>
                      <div className="flex items-center gap-3 mt-2">
                        {/* MITRE Techniques */}
                        {finding.mitreTechniques.length > 0 && (
                          <div className="flex items-center gap-1">
                            <Shield className="h-3.5 w-3.5 text-[var(--muted)]" />
                            <div className="flex gap-1">
                              {finding.mitreTechniques.map(tech => (
                                <a
                                  key={tech}
                                  href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs font-medium hover:bg-purple-500/30 transition-colors"
                                >
                                  {tech}
                                </a>
                              ))}
                            </div>
                          </div>
                        )}
                        <span className="text-xs text-[var(--muted)]">
                          {formatDate(finding.discoveredAt)}
                        </span>
                      </div>
                      {finding.evidence.length > 0 && (
                        <details className="mt-2">
                          <summary className="text-xs text-[var(--muted)] cursor-pointer hover:text-[var(--fg-secondary)]">
                            View evidence ({finding.evidence.length})
                          </summary>
                          <div className="mt-2 space-y-1">
                            {finding.evidence.map((ev, idx) => (
                              <pre key={idx} className="text-xs text-[var(--fg-secondary)] bg-[var(--surface-inset)] rounded p-2 overflow-x-auto">
                                {JSON.stringify(ev, null, 2)}
                              </pre>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
