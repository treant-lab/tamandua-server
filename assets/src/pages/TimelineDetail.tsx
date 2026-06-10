import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Clock,
  AlertTriangle,
  Activity,
  Shield,
  Network,
  FileText,
  GitBranch,
  Target,
  ChevronRight,
  Cpu,
  Globe,
  Lightbulb,
  BarChart3,
  Layers,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface TimelineEvent {
  type: string
  timestamp: string
  data: Record<string, unknown>
}

interface Incident {
  alertId?: string
  alertIds?: string[]
  agentId?: string
  timestampStart?: string
  timestampEnd?: string
  summary?: string
  metrics?: Record<string, unknown>
  severity?: string
  eventCount?: number
  affectedAssets?: string[]
  mitreCoverage?: string[]
  rootCause?: string
  attackChain?: Array<{ step: string; description?: string; technique?: string }>
  recommendations?: string[]
}

interface TimelineData {
  processTree?: unknown[]
  networkTimeline?: unknown[]
  fileTimeline?: unknown[]
  mitreProgression?: unknown[]
}

interface TimelineDetailPageProps {
  incidentId: string
  incident: Incident | null
  events: TimelineEvent[]
  timeline: TimelineData | unknown[]
  error?: string
}

const EVENT_TYPE_ICONS: Record<string, typeof Activity> = {
  process: Cpu,
  network: Globe,
  file: FileText,
  dns: Globe,
  registry: Layers,
  alert: AlertTriangle,
}

const getSeverityColor = (severity?: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    default: return 'bg-[var(--surface-alt)]/20 text-[var(--muted)] border-[var(--border)]'
  }
}

const getSeverityDotColor = (severity?: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-500'
    case 'high': return 'bg-orange-500'
    case 'medium': return 'bg-yellow-500'
    case 'low': return 'bg-blue-500'
    default: return 'bg-[var(--muted)]'
  }
}

export default function TimelineDetail({
  incidentId,
  incident,
  events,
  timeline,
  error,
}: TimelineDetailPageProps) {
  const [activeTab, setActiveTab] = useState<'process' | 'network' | 'files' | 'mitre'>('process')

  const timelineData: TimelineData = Array.isArray(timeline) ? {} : (timeline || {})

  if (error || !incident) {
    return (
      <MainLayout title="Timeline Detail">
        <Head title="Timeline Detail - Tamandua EDR" />
        <div className="space-y-6">
          <button
            onClick={() => router.visit('/app/timeline')}
            className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Timeline
          </button>
          <div className="card-sentinel rounded-xl p-12 text-center">
            <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-[var(--muted)]" />
            <p className="text-lg text-[var(--muted)]">{error || 'Incident not found'}</p>
            <p className="text-sm text-[var(--muted)] mt-1">
              The requested incident could not be loaded.
            </p>
          </div>
        </div>
      </MainLayout>
    )
  }

  const formatTimestamp = (ts?: string) => {
    if (!ts) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(ts))
  }

  return (
    <MainLayout title="Timeline Detail">
      <Head title={`Incident ${incidentId} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Back link */}
        <button
          onClick={() => router.visit('/app/timeline')}
          className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Timeline
        </button>

        {/* Incident Header */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={cn('p-2 rounded-lg', getSeverityColor(incident.severity).split(' ')[0])}>
                <AlertTriangle className={cn('h-6 w-6', getSeverityColor(incident.severity).split(' ')[1])} />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-[var(--fg)]">
                  Incident {incidentId}
                </h1>
                <div className="flex items-center gap-3 text-sm text-[var(--muted)] mt-1">
                  {incident.severity && (
                    <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getSeverityColor(incident.severity))}>
                      {incident.severity.toUpperCase()}
                    </span>
                  )}
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    {formatTimestamp(incident.timestampStart)}
                  </span>
                  {incident.timestampEnd && (
                    <span className="text-[var(--muted)]">
                      to {formatTimestamp(incident.timestampEnd)}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {incident.summary && (
            <p className="text-sm text-[var(--fg)] mb-4">{incident.summary}</p>
          )}

          {/* Metrics row */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[var(--surface-alt)] rounded-lg p-3">
              <p className="text-xs text-[var(--muted)]">Event Count</p>
              <p className="text-xl font-bold text-[var(--fg)] mt-0.5">{incident.eventCount ?? 0}</p>
            </div>
            <div className="bg-[var(--surface-alt)] rounded-lg p-3">
              <p className="text-xs text-[var(--muted)]">Affected Assets</p>
              <p className="text-xl font-bold text-[var(--fg)] mt-0.5">{incident.affectedAssets?.length ?? 0}</p>
            </div>
            <div className="bg-[var(--surface-alt)] rounded-lg p-3">
              <p className="text-xs text-[var(--muted)]">MITRE Techniques</p>
              <p className="text-xl font-bold text-[var(--fg)] mt-0.5">{incident.mitreCoverage?.length ?? 0}</p>
            </div>
          </div>

          {/* Affected Assets */}
          {incident.affectedAssets && incident.affectedAssets.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wide mb-2">Affected Assets</p>
              <div className="flex flex-wrap gap-2">
                {incident.affectedAssets.map((asset, i) => (
                  <span key={i} className="px-2 py-1 bg-[var(--surface-alt)] rounded text-xs text-[var(--fg)]">
                    {asset}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* MITRE Techniques */}
          {incident.mitreCoverage && incident.mitreCoverage.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wide mb-2">MITRE Coverage</p>
              <div className="flex flex-wrap gap-1">
                {incident.mitreCoverage.map((technique) => (
                  <a
                    key={technique}
                    href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs font-medium hover:bg-purple-500/30 transition-colors"
                  >
                    {technique}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Root Cause */}
        {incident.rootCause && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-2">Root Cause</h2>
            <p className="text-sm text-[var(--fg)]">{incident.rootCause}</p>
          </div>
        )}

        {/* Tabs */}
        <div className="card-sentinel rounded-xl">
          <div className="border-b border-[var(--border)] px-4">
            <div className="flex gap-1">
              {[
                { id: 'process' as const, label: 'Process Tree', icon: GitBranch },
                { id: 'network' as const, label: 'Network', icon: Network },
                { id: 'files' as const, label: 'Files', icon: FileText },
                { id: 'mitre' as const, label: 'MITRE Progression', icon: Shield },
              ].map(tab => {
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
                  </button>
                )
              })}
            </div>
          </div>

          <div className="p-6 min-h-[300px]">
            {activeTab === 'process' && (
              <div>
                {timelineData.processTree && Array.isArray(timelineData.processTree) && timelineData.processTree.length > 0 ? (
                  <div className="space-y-2">
                    {timelineData.processTree.map((proc: any, i: number) => (
                      <div key={i} className="bg-[var(--surface-alt)] rounded-lg p-3 flex items-center gap-3">
                        <Cpu className="h-4 w-4 text-blue-400" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[var(--fg)] font-medium">{proc.name || proc.process_name || `Process ${i + 1}`}</p>
                          <p className="text-xs text-[var(--muted)]">
                            PID: {proc.pid || 'N/A'} | PPID: {proc.ppid || proc.parent_pid || 'N/A'}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-[var(--muted)]">
                    <GitBranch className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <p>No process tree data available</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'network' && (
              <div>
                {timelineData.networkTimeline && Array.isArray(timelineData.networkTimeline) && timelineData.networkTimeline.length > 0 ? (
                  <div className="space-y-2">
                    {timelineData.networkTimeline.map((conn: any, i: number) => (
                      <div key={i} className="bg-[var(--surface-alt)] rounded-lg p-3 flex items-center gap-3">
                        <Globe className="h-4 w-4 text-green-400" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[var(--fg)] font-medium">
                            {conn.remote_ip || conn.destination || `Connection ${i + 1}`}
                          </p>
                          <p className="text-xs text-[var(--muted)]">
                            {conn.protocol || 'TCP'} | Port: {conn.port || conn.remote_port || 'N/A'}
                          </p>
                        </div>
                        <span className="text-xs text-[var(--muted)]">{conn.timestamp || ''}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-[var(--muted)]">
                    <Network className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <p>No network timeline data available</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'files' && (
              <div>
                {timelineData.fileTimeline && Array.isArray(timelineData.fileTimeline) && timelineData.fileTimeline.length > 0 ? (
                  <div className="space-y-2">
                    {timelineData.fileTimeline.map((file: any, i: number) => (
                      <div key={i} className="bg-[var(--surface-alt)] rounded-lg p-3 flex items-center gap-3">
                        <FileText className="h-4 w-4 text-amber-400" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[var(--fg)] font-medium truncate">
                            {file.path || file.name || `File ${i + 1}`}
                          </p>
                          <p className="text-xs text-[var(--muted)]">
                            {file.action || file.operation || 'Unknown'} | {file.timestamp || ''}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-[var(--muted)]">
                    <FileText className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <p>No file timeline data available</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'mitre' && (
              <div>
                {timelineData.mitreProgression && Array.isArray(timelineData.mitreProgression) && timelineData.mitreProgression.length > 0 ? (
                  <div className="space-y-2">
                    {timelineData.mitreProgression.map((entry: any, i: number) => (
                      <div key={i} className="bg-[var(--surface-alt)] rounded-lg p-3 flex items-center gap-3">
                        <Shield className="h-4 w-4 text-purple-400" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[var(--fg)] font-medium">
                            {entry.technique || entry.id || `Technique ${i + 1}`}
                          </p>
                          <p className="text-xs text-[var(--muted)]">
                            {entry.tactic || ''} {entry.description ? `- ${entry.description}` : ''}
                          </p>
                        </div>
                        <span className="text-xs text-[var(--muted)]">{entry.timestamp || ''}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-[var(--muted)]">
                    <Shield className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <p>No MITRE progression data available</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Events List */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Activity className="h-5 w-5 text-[var(--muted)]" />
              Events ({events.length})
            </h2>
          </div>
          <div className="divide-y divide-[var(--border)] max-h-[500px] overflow-y-auto">
            {events.length === 0 ? (
              <div className="p-8 text-center text-[var(--muted)]">
                <Activity className="h-10 w-10 mx-auto mb-3 opacity-50" />
                <p>No events found</p>
              </div>
            ) : (
              events.map((event, idx) => {
                const Icon = EVENT_TYPE_ICONS[event.type] || Activity
                return (
                  <div key={idx} className="p-4 hover:bg-[var(--surface-alt)] transition-colors">
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-[var(--surface-alt)] rounded">
                        <Icon className="h-4 w-4 text-[var(--muted)]" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium text-[var(--fg)] capitalize">{event.type}</span>
                          <span className="text-xs text-[var(--muted)]">{formatTimestamp(event.timestamp)}</span>
                        </div>
                        {event.data && (
                          <details>
                            <summary className="text-xs text-[var(--muted)] cursor-pointer hover:text-[var(--fg)]">
                              View details
                            </summary>
                            <pre className="mt-2 text-xs text-[var(--fg)] bg-[var(--surface)] rounded p-2 overflow-x-auto">
                              {JSON.stringify(event.data, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Attack Chain */}
        {incident.attackChain && incident.attackChain.length > 0 && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-4 flex items-center gap-2">
              <Target className="h-4 w-4" />
              Attack Chain
            </h2>
            <div className="space-y-1">
              {incident.attackChain.map((step, i) => (
                <div key={i}>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center justify-center h-7 w-7 rounded-full bg-red-500/20 text-red-400 text-xs font-bold border border-red-500/30">
                      {i + 1}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm text-[var(--fg)] font-medium">
                        {typeof step === 'string' ? step : step.step}
                      </p>
                      {typeof step !== 'string' && step.description && (
                        <p className="text-xs text-[var(--muted)] mt-0.5">{step.description}</p>
                      )}
                      {typeof step !== 'string' && step.technique && (
                        <span className="text-xs text-purple-400">{step.technique}</span>
                      )}
                    </div>
                  </div>
                  {i < incident.attackChain!.length - 1 && (
                    <div className="ml-3.5 border-l border-[var(--border)] h-3" />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {incident.recommendations && incident.recommendations.length > 0 && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-3 flex items-center gap-2">
              <Lightbulb className="h-4 w-4" />
              Recommendations
            </h2>
            <div className="space-y-2">
              {incident.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-3 bg-[var(--surface-alt)] rounded-lg p-3">
                  <ChevronRight className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-[var(--fg)]">{rec}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
