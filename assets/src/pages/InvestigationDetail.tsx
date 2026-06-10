import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Brain,
  Clock,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  FileSearch,
  Activity,
  ChevronDown,
  ChevronRight,
  Target,
  Lightbulb,
  ListChecks,
  Play,
  RefreshCw,
  Loader2,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Finding {
  id: string
  type: string
  title: string
  status: string
  confidence: number
  evidence: Record<string, unknown>[]
  mitreTechniques: string[]
}

interface TimelineEntry {
  timestamp: string
  event: string
  state: string
}

interface Recommendation {
  id: string
  action: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  rationale: string
  parameters: Record<string, unknown>
}

interface Investigation {
  id: string
  alertId: string
  state: string
  confidence: number
  triageResult: Record<string, unknown> | null
  startedAt: string
  updatedAt: string
  hypotheses: string[]
  evidence: Record<string, unknown>[]
  correlations: Record<string, unknown>[]
  explanation: string | null
}

interface InvestigationDetailProps {
  investigationId: string
  investigation: Investigation | null
  findings: Finding[]
  timeline: TimelineEntry[]
  recommendations: Recommendation[]
  error?: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getStateColor(state: string) {
  switch (state) {
    case 'completed': return 'bg-green-500/20 text-green-400 border-green-500/30'
    case 'in_progress': case 'active': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'pending': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    default: return 'bg-[var(--surface-alt)]/20 text-[var(--muted)] border-[var(--border)]'
  }
}

function getPriorityColor(priority: string) {
  switch (priority) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30'
    default: return 'bg-[var(--surface-alt)]/20 text-[var(--muted)] border-[var(--border)]'
  }
}

function getConfidenceColor(confidence: number) {
  if (confidence >= 80) return 'text-green-400 bg-green-500'
  if (confidence >= 60) return 'text-yellow-400 bg-yellow-500'
  if (confidence >= 40) return 'text-orange-400 bg-orange-500'
  return 'text-red-400 bg-red-500'
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function InvestigationDetail({
  investigationId,
  investigation,
  findings,
  timeline,
  recommendations,
  error,
}: InvestigationDetailProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'evidence' | 'timeline' | 'recommendations'>('findings')
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({})

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }))
  }

  // Error state
  if (error) {
    return (
      <MainLayout title="">
        <Head title="Investigation Error - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel rounded-xl p-6">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/analyst')}
                className="p-2 hover:bg-[var(--surface-alt)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <XCircle className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-[var(--fg)]">Investigation Error</h1>
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
  if (!investigation) {
    return (
      <MainLayout title="">
        <Head title="Investigation Not Found - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel rounded-xl p-6">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/analyst')}
                className="p-2 hover:bg-[var(--surface-alt)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--surface-alt)]">
                  <Search className="h-6 w-6 text-[var(--muted)]" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-[var(--fg)]">Investigation Not Found</h1>
                  <p className="text-sm text-[var(--muted)] mt-1">
                    Investigation {investigationId} could not be found.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </MainLayout>
    )
  }

  const confidenceColors = getConfidenceColor(investigation.confidence)

  return (
    <MainLayout title="">
      <Head title={`Investigation ${investigation.id} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Header */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/analyst')}
                className="p-2 hover:bg-[var(--surface-alt)] rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-[var(--muted)]" />
              </button>
              <div className="p-3 rounded-xl bg-blue-600/20">
                <Brain className="h-8 w-8 text-blue-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold text-[var(--fg)]">
                    Investigation {investigation.id.slice(0, 8)}
                  </h1>
                  <span className={cn('px-2.5 py-1 rounded text-xs font-medium border', getStateColor(investigation.state))}>
                    {investigation.state.replace(/_/g, ' ').toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-4 mt-1 text-sm text-[var(--muted)]">
                  <span className="flex items-center gap-1">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Alert: {investigation.alertId.slice(0, 8)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Started: {formatDate(investigation.startedAt)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Updated: {formatDate(investigation.updatedAt)}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* Confidence Score */}
              <div className="text-center">
                <div className="text-xs text-[var(--muted)]">Confidence</div>
                <div className={cn('text-3xl font-bold', confidenceColors.split(' ')[0])}>
                  {investigation.confidence}%
                </div>
                <div className="w-24 h-1.5 bg-[var(--surface-alt)] rounded-full mt-1">
                  <div
                    className={cn('h-full rounded-full', confidenceColors.split(' ')[1])}
                    style={{ width: `${investigation.confidence}%` }}
                  />
                </div>
              </div>

              <button
                onClick={() => router.reload()}
                className="p-2 bg-[var(--surface-alt)] hover:bg-[var(--surface)] rounded-lg transition-colors"
                title="Refresh"
              >
                <RefreshCw className="h-5 w-5 text-[var(--muted)]" />
              </button>
            </div>
          </div>
        </div>

        {/* AI Explanation */}
        {investigation.explanation && (
          <div className="card-sentinel rounded-xl border-blue-500/30 p-6">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-blue-500/20 mt-0.5">
                <Brain className="h-5 w-5 text-blue-400" />
              </div>
              <div className="flex-1">
                <h2 className="text-sm font-semibold text-blue-400 mb-2">AI Reasoning</h2>
                <p className="text-sm text-[var(--fg)] leading-relaxed whitespace-pre-wrap">
                  {investigation.explanation}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Hypotheses */}
        {investigation.hypotheses.length > 0 && (
          <div className="card-sentinel rounded-xl p-6">
            <h2 className="text-lg font-semibold text-[var(--fg)] mb-3 flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-yellow-400" />
              Hypotheses
            </h2>
            <div className="space-y-2">
              {investigation.hypotheses.map((hypothesis, idx) => (
                <div key={idx} className="flex items-start gap-3 bg-[var(--surface)] rounded-lg p-3">
                  <span className="text-xs font-mono text-[var(--muted)] mt-0.5">{idx + 1}</span>
                  <p className="text-sm text-[var(--fg)]">{hypothesis}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="card-sentinel rounded-xl">
          <div className="border-b border-[var(--border)] px-4">
            <div className="flex gap-1">
              {([
                { id: 'findings', label: 'Findings', icon: Target, count: findings.length },
                { id: 'evidence', label: 'Evidence', icon: FileSearch, count: investigation.evidence.length },
                { id: 'timeline', label: 'Timeline', icon: Clock, count: timeline.length },
                { id: 'recommendations', label: 'Recommendations', icon: ListChecks, count: recommendations.length },
              ] as const).map(tab => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    {tab.label}
                    {tab.count > 0 && (
                      <span className="px-1.5 py-0.5 bg-[var(--surface-alt)] rounded text-xs">{tab.count}</span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="p-4">
            {/* Findings Tab */}
            {activeTab === 'findings' && (
              <div className="space-y-3">
                {findings.length === 0 ? (
                  <div className="text-center py-12 text-[var(--muted)]">
                    <Target className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No findings yet</p>
                  </div>
                ) : (
                  findings.map(finding => (
                    <div key={finding.id} className="bg-[var(--surface)] rounded-lg border border-[var(--border)]">
                      <button
                        onClick={() => toggleFinding(finding.id)}
                        className="w-full p-4 flex items-center justify-between hover:bg-[var(--surface-alt)] transition-colors rounded-lg"
                      >
                        <div className="flex items-center gap-3">
                          {expandedFindings[finding.id] ? (
                            <ChevronDown className="h-4 w-4 text-[var(--muted)]" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
                          )}
                          <div className="text-left">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-[var(--fg)]">{finding.title}</span>
                              <span className={cn(
                                'px-2 py-0.5 rounded text-xs font-medium border',
                                getStateColor(finding.status)
                              )}>
                                {finding.status}
                              </span>
                              <span className="px-2 py-0.5 rounded text-xs font-medium bg-[var(--surface-alt)] text-[var(--fg)]">
                                {finding.type}
                              </span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {/* MITRE badges */}
                          <div className="flex gap-1">
                            {finding.mitreTechniques.slice(0, 3).map(tech => (
                              <a
                                key={tech}
                                href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={e => e.stopPropagation()}
                                className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs font-medium hover:bg-purple-500/30 transition-colors"
                              >
                                {tech}
                              </a>
                            ))}
                            {finding.mitreTechniques.length > 3 && (
                              <span className="px-2 py-0.5 bg-[var(--surface-alt)] text-[var(--muted)] rounded text-xs">
                                +{finding.mitreTechniques.length - 3}
                              </span>
                            )}
                          </div>
                          {/* Confidence bar */}
                          <div className="flex items-center gap-2 min-w-[100px]">
                            <div className="flex-1 h-1.5 bg-[var(--surface-alt)] rounded-full">
                              <div
                                className={cn('h-full rounded-full', getConfidenceColor(finding.confidence).split(' ')[1])}
                                style={{ width: `${finding.confidence}%` }}
                              />
                            </div>
                            <span className={cn('text-xs font-medium', getConfidenceColor(finding.confidence).split(' ')[0])}>
                              {finding.confidence}%
                            </span>
                          </div>
                        </div>
                      </button>

                      {expandedFindings[finding.id] && (
                        <div className="px-4 pb-4 border-t border-[var(--border)]">
                          <div className="mt-3">
                            <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">Evidence</h4>
                            {finding.evidence.length === 0 ? (
                              <p className="text-sm text-[var(--muted)]">No evidence collected</p>
                            ) : (
                              <div className="space-y-2">
                                {finding.evidence.map((ev, idx) => (
                                  <pre key={idx} className="text-xs text-[var(--fg)] bg-[var(--surface-alt)] rounded p-3 overflow-x-auto">
                                    {JSON.stringify(ev, null, 2)}
                                  </pre>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="space-y-3">
                {investigation.evidence.length === 0 ? (
                  <div className="text-center py-12 text-[var(--muted)]">
                    <FileSearch className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No evidence collected</p>
                  </div>
                ) : (
                  investigation.evidence.map((ev, idx) => (
                    <div key={idx} className="bg-[var(--surface)] rounded-lg border border-[var(--border)] p-4">
                      <pre className="text-xs text-[var(--fg)] overflow-x-auto">
                        {JSON.stringify(ev, null, 2)}
                      </pre>
                    </div>
                  ))
                )}

                {investigation.correlations.length > 0 && (
                  <div className="mt-6">
                    <h3 className="text-sm font-semibold text-[var(--fg)] mb-3">Correlations</h3>
                    {investigation.correlations.map((corr, idx) => (
                      <div key={idx} className="bg-[var(--surface)] rounded-lg border border-[var(--border)] p-4 mb-2">
                        <pre className="text-xs text-[var(--fg)] overflow-x-auto">
                          {JSON.stringify(corr, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Timeline Tab */}
            {activeTab === 'timeline' && (
              <div>
                {timeline.length === 0 ? (
                  <div className="text-center py-12 text-[var(--muted)]">
                    <Clock className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No timeline events</p>
                  </div>
                ) : (
                  <div className="relative">
                    <div className="absolute left-6 top-0 bottom-0 w-px bg-[var(--border)]" />
                    <div className="space-y-4">
                      {timeline.map((entry, idx) => (
                        <div key={idx} className="relative flex gap-4 pl-4">
                          <div className={cn(
                            'absolute left-4 w-5 h-5 rounded-full flex items-center justify-center -translate-x-1/2 z-10',
                            getStateColor(entry.state).split(' ')[0].replace('/20', '')
                          )}>
                            <Activity className="h-3 w-3 text-white" />
                          </div>
                          <div className="flex-1 ml-8 bg-[var(--surface)] rounded-lg p-4 hover:bg-[var(--surface-alt)] transition-colors">
                            <div className="flex items-start justify-between">
                              <div>
                                <p className="text-sm text-[var(--fg)] font-medium">{entry.event}</p>
                                <div className="flex items-center gap-2 mt-1">
                                  <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getStateColor(entry.state))}>
                                    {entry.state}
                                  </span>
                                  <span className="text-xs text-[var(--muted)]">{formatDate(entry.timestamp)}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Recommendations Tab */}
            {activeTab === 'recommendations' && (
              <div className="space-y-3">
                {recommendations.length === 0 ? (
                  <div className="text-center py-12 text-[var(--muted)]">
                    <ListChecks className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No recommendations</p>
                  </div>
                ) : (
                  recommendations.map(rec => (
                    <div key={rec.id} className="bg-[var(--surface)] rounded-lg border border-[var(--border)] p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getPriorityColor(rec.priority))}>
                              {rec.priority.toUpperCase()}
                            </span>
                            <span className="text-sm font-medium text-[var(--fg)]">{rec.action}</span>
                          </div>
                          <p className="text-sm text-[var(--muted)]">{rec.rationale}</p>
                          {Object.keys(rec.parameters).length > 0 && (
                            <details className="mt-2">
                              <summary className="text-xs text-[var(--muted)] cursor-pointer hover:text-[var(--fg)]">
                                View parameters
                              </summary>
                              <pre className="mt-2 text-xs text-[var(--fg)] bg-[var(--surface-alt)] rounded p-2 overflow-x-auto">
                                {JSON.stringify(rec.parameters, null, 2)}
                              </pre>
                            </details>
                          )}
                        </div>
                        <button
                          className="flex items-center gap-2 px-3 py-2 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 rounded-lg text-sm text-blue-400 transition-colors ml-4 shrink-0"
                        >
                          <Play className="h-4 w-4" />
                          Execute
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
