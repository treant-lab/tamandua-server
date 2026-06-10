import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  AlertTriangle,
  BookOpen,
  Play,
  Clock,
  CheckCircle,
  XCircle,
  Pause,
  Zap,
  GitBranch,
  Timer,
  Repeat,
  ToggleRight,
  ToggleLeft,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

interface PlaybookStep {
  name: string
  type: string
  action: string
  timeout: number
  params?: Record<string, unknown>
}

interface Playbook {
  id: string
  name: string
  description: string
  triggerType: string
  severity: string
  enabled: boolean
  steps: PlaybookStep[]
  createdAt: string
  updatedAt: string
}

interface ExecutionRecord {
  id: string
  playbookId: string
  triggeredBy: string
  alertId: string
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  startedAt: string
  completedAt: string | null
  stepResults: unknown[]
  error: string | null
}

interface PlaybookDetailPageProps {
  playbookId: string
  playbook: Playbook | null
  executionHistory: ExecutionRecord[]
  error?: string
}

const stepTypeConfig: Record<string, { icon: typeof Zap; color: string; label: string }> = {
  action: { icon: Zap, color: 'text-blue-400 bg-blue-400/10 border-blue-500/30', label: 'Action' },
  condition: { icon: GitBranch, color: 'text-amber-400 bg-amber-400/10 border-amber-500/30', label: 'Condition' },
  wait: { icon: Timer, color: 'text-[var(--muted)] bg-[var(--surface-alt)] border-[var(--border)]', label: 'Wait' },
  loop: { icon: Repeat, color: 'text-purple-400 bg-purple-400/10 border-purple-500/30', label: 'Loop' },
}

const executionStatusConfig: Record<string, { color: string; icon: typeof CheckCircle }> = {
  running: { color: 'text-blue-400 bg-blue-400/10', icon: Play },
  completed: { color: 'text-green-400 bg-green-400/10', icon: CheckCircle },
  failed: { color: 'text-red-400 bg-red-400/10', icon: XCircle },
  cancelled: { color: 'text-[var(--muted)] bg-[var(--surface-alt)]', icon: Pause },
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

export default function PlaybookDetail({
  playbookId,
  playbook,
  executionHistory,
  error,
}: PlaybookDetailPageProps) {
  const [executing, setExecuting] = useState(false)

  const formatDate = (dateString?: string | null) => {
    if (!dateString) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(dateString))
  }

  const handleRunPlaybook = async () => {
    setExecuting(true)
    try {
      const res = await fetch(`/api/v1/playbooks/${playbookId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      })
      if (!res.ok) {
        logger.error('Failed to execute playbook:', res.status)
      }
      router.reload()
    } catch (err) {
      logger.error('Failed to execute playbook:', err)
    } finally {
      setExecuting(false)
    }
  }

  if (error || !playbook) {
    return (
      <MainLayout title="Playbook Detail">
        <Head title="Playbook Detail - Tamandua EDR" />
        <div className="space-y-6">
          <button
            onClick={() => router.visit('/app/playbooks')}
            className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Playbooks
          </button>
          <div className="card-sentinel rounded-xl p-12 text-center">
            <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-[var(--muted)]" />
            <p className="text-lg text-[var(--muted)]">{error || 'Playbook not found'}</p>
            <p className="text-sm text-[var(--muted)] mt-1">
              The requested playbook could not be loaded.
            </p>
          </div>
        </div>
      </MainLayout>
    )
  }

  return (
    <MainLayout title="Playbook Detail">
      <Head title={`${playbook.name} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Back link */}
        <button
          onClick={() => router.visit('/app/playbooks')}
          className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Playbooks
        </button>

        {/* Playbook Header */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-primary-500/10">
                <BookOpen className="h-6 w-6 text-primary-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-xl font-semibold text-[var(--fg)]">{playbook.name}</h1>
                  {playbook.enabled ? (
                    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium text-green-400 bg-green-400/10 border border-green-500/30">
                      <ToggleRight className="h-3.5 w-3.5" />
                      Enabled
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium text-[var(--muted)] bg-[var(--surface-alt)] border border-[var(--border)]">
                      <ToggleLeft className="h-3.5 w-3.5" />
                      Disabled
                    </span>
                  )}
                  {playbook.severity && (
                    <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getSeverityColor(playbook.severity))}>
                      {playbook.severity.toUpperCase()}
                    </span>
                  )}
                </div>
                <p className="text-sm text-[var(--muted)] mt-1">{playbook.description}</p>
                <div className="flex items-center gap-4 text-xs text-[var(--muted)] mt-2">
                  <span>Trigger: {playbook.triggerType}</span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Created: {formatDate(playbook.createdAt)}
                  </span>
                  <span>Updated: {formatDate(playbook.updatedAt)}</span>
                </div>
              </div>
            </div>

            <button
              onClick={handleRunPlaybook}
              disabled={executing || !playbook.enabled}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors',
                playbook.enabled
                  ? 'bg-primary-600 hover:bg-primary-500'
                  : 'bg-[var(--surface-alt)] cursor-not-allowed',
                executing && 'opacity-50 cursor-not-allowed'
              )}
            >
              {executing ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Run Playbook
            </button>
          </div>
        </div>

        {/* Steps */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Zap className="h-5 w-5 text-[var(--muted)]" />
              Steps ({playbook.steps.length})
            </h2>
          </div>
          <div className="p-4">
            {playbook.steps.length === 0 ? (
              <div className="text-center py-8 text-[var(--muted)]">
                <Zap className="h-10 w-10 mx-auto mb-3 opacity-50" />
                <p>No steps defined</p>
              </div>
            ) : (
              <div className="space-y-1">
                {playbook.steps.map((step, index) => {
                  const stConf = stepTypeConfig[step.type] || stepTypeConfig.action
                  const StIcon = stConf.icon

                  return (
                    <div key={index}>
                      <div className="flex items-center gap-3 bg-[var(--surface-alt)] rounded-lg p-4">
                        <div className={cn('flex items-center justify-center h-8 w-8 rounded-lg border', stConf.color)}>
                          <StIcon className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-[var(--fg)]">{step.name}</span>
                            <span className={cn('px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border', stConf.color)}>
                              {stConf.label}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-[var(--muted)] mt-1">
                            <span>Action: {step.action}</span>
                            <span>Timeout: {step.timeout}s</span>
                            {step.params && Object.keys(step.params).length > 0 && (
                              <span>{Object.keys(step.params).length} param(s)</span>
                            )}
                          </div>
                        </div>
                        <span className="text-xs text-[var(--muted)] font-mono">#{index + 1}</span>
                      </div>
                      {index < playbook.steps.length - 1 && (
                        <div className="flex items-center justify-center py-1">
                          <div className="w-px h-3 bg-[var(--border)]" />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Execution History */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Clock className="h-5 w-5 text-[var(--muted)]" />
              Execution History ({executionHistory.length})
            </h2>
          </div>
          {executionHistory.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Play className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No executions recorded</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Status</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Triggered By</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Alert ID</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Started</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Completed</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Error</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {executionHistory.map((exec) => {
                    const statusConf = executionStatusConfig[exec.status] || executionStatusConfig.cancelled
                    const StatusIcon = statusConf.icon
                    return (
                      <tr key={exec.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className={cn('p-1.5 rounded', statusConf.color)}>
                              <StatusIcon className="h-3.5 w-3.5" />
                            </div>
                            <span className={cn('text-sm font-medium capitalize', statusConf.color.split(' ')[0])}>
                              {exec.status}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-[var(--fg)]">{exec.triggeredBy}</td>
                        <td className="px-4 py-3">
                          {exec.alertId ? (
                            <button
                              onClick={() => router.visit(`/app/alerts/${exec.alertId}`)}
                              className="text-sm text-blue-400 hover:text-blue-300 font-mono"
                            >
                              {exec.alertId.substring(0, 8)}...
                            </button>
                          ) : (
                            <span className="text-sm text-[var(--muted)]">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-[var(--muted)] font-mono">{formatDate(exec.startedAt)}</td>
                        <td className="px-4 py-3 text-sm text-[var(--muted)] font-mono">{formatDate(exec.completedAt)}</td>
                        <td className="px-4 py-3">
                          {exec.error ? (
                            <span className="text-sm text-red-400 truncate max-w-[200px] block">{exec.error}</span>
                          ) : (
                            <span className="text-sm text-[var(--muted)]">-</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
