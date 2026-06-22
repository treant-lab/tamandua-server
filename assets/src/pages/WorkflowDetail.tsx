import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Workflow,
  Clock,
  Play,
  CheckCircle,
  XCircle,
  Search,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronRight,
  Zap,
  Settings,
  AlertTriangle,
  ArrowRight,
  ToggleLeft,
  ToggleRight,
  Timer,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface WorkflowStep {
  id: string
  name: string
  type: string
  action: string
  parameters: Record<string, unknown>
  onSuccess?: string
  onFailure?: string
}

interface WorkflowData {
  id: string
  name: string
  description: string
  triggerType: string
  triggerConditions: Record<string, unknown>
  steps: WorkflowStep[]
  enabled: boolean
  createdAt: string
  updatedAt: string
}

interface ExecutionRecord {
  id: string
  workflowId: string
  triggeredBy: string
  triggerData: Record<string, unknown>
  status: 'success' | 'failed' | 'running' | 'pending'
  startedAt: string
  completedAt: string | null
  stepResults: Record<string, unknown>[]
  error: string | null
  duration_ms: number | null
}

interface WorkflowDetailProps {
  workflowId: string
  workflow: WorkflowData | null
  executionHistory: ExecutionRecord[]
  availableActions: string[]
  error?: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getStatusColor(status: string) {
  switch (status) {
    case 'success': return 'bg-green-500/20 text-green-400 border-green-500/30'
    case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'running': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    case 'pending': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    default: return 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/30'
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'success': return CheckCircle
    case 'failed': return XCircle
    case 'running': return Loader2
    case 'pending': return Clock
    default: return Clock
  }
}

function formatDuration(ms: number | null) {
  if (ms === null) return '-'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function WorkflowDetail({
  workflowId,
  workflow,
  executionHistory,
  availableActions,
  error,
}: WorkflowDetailProps) {
  const [expandedExecution, setExpandedExecution] = useState<string | null>(null)
  const [isRunning, setIsRunning] = useState(false)

  const handleRunWorkflow = async () => {
    if (!workflow) return
    setIsRunning(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      const res = await fetch(`/api/v1/automation/workflows/${workflow.id}/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
        credentials: 'include',
      })
      if (!res.ok) {
        logger.error('Failed to run workflow:', res.status)
      }
      router.reload()
    } catch (err) {
      logger.error('Failed to run workflow:', err)
    } finally {
      setIsRunning(false)
    }
  }

  // Error state
  if (error) {
    return (
      <MainLayout title="">
        <Head title="Workflow Error - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/automation')}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)' }}
              >
                <ArrowLeft className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <XCircle className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>Workflow Error</h1>
                  <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{error}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </MainLayout>
    )
  }

  // Not found state
  if (!workflow) {
    return (
      <MainLayout title="">
        <Head title="Workflow Not Found - Tamandua EDR" />
        <div className="space-y-6">
          <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/automation')}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)' }}
              >
                <ArrowLeft className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--muted)]/20">
                  <Search className="h-6 w-6" style={{ color: 'var(--muted)' }} />
                </div>
                <div>
                  <h1 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>Workflow Not Found</h1>
                  <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                    Workflow {workflowId} could not be found.
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
      <Head title={`${workflow.name} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Header */}
        <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/automation')}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)' }}
              >
                <ArrowLeft className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
              <div className="p-3 rounded-xl bg-purple-600/20">
                <Workflow className="h-8 w-8 text-purple-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{workflow.name}</h1>
                  <span className={cn(
                    'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium',
                    workflow.enabled
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-[var(--muted)]/20 text-[var(--muted)]'
                  )}>
                    <span className={cn('h-2 w-2 rounded-full', workflow.enabled ? 'bg-green-400' : 'bg-[var(--muted)]')} />
                    {workflow.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{workflow.description}</p>
                <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--muted)' }}>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Created: {formatDate(workflow.createdAt)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Updated: {formatDate(workflow.updatedAt)}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleRunWorkflow}
                disabled={isRunning || !workflow.enabled}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors',
                  isRunning || !workflow.enabled
                    ? 'cursor-not-allowed opacity-50'
                    : 'bg-green-600 hover:bg-green-500 text-white'
                )}
                style={isRunning || !workflow.enabled ? { backgroundColor: 'var(--surface)', color: 'var(--muted)' } : undefined}
              >
                {isRunning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                Run Workflow
              </button>
              <button
                onClick={() => router.reload()}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}
                title="Refresh"
              >
                <RefreshCw className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
            </div>
          </div>
        </div>

        {/* Trigger Configuration */}
        <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Zap className="h-5 w-5 text-yellow-400" />
            Trigger Configuration
          </h2>
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
            <div className="flex items-center gap-3 mb-3">
              <span className="text-sm" style={{ color: 'var(--muted)' }}>Trigger Type:</span>
              <span className="px-2.5 py-1 rounded text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                {workflow.triggerType}
              </span>
            </div>
            {Object.keys(workflow.triggerConditions).length > 0 && (
              <div>
                <span className="text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Conditions</span>
                <pre className="mt-2 text-xs rounded p-3 overflow-x-auto" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                  {JSON.stringify(workflow.triggerConditions, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Steps Flowchart */}
        <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Settings className="h-5 w-5" style={{ color: 'var(--muted)' }} />
            Workflow Steps
          </h2>
          {workflow.steps.length === 0 ? (
            <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
              <Settings className="h-10 w-10 mx-auto mb-2 opacity-50" />
              <p>No steps defined</p>
            </div>
          ) : (
            <div className="space-y-0">
              {workflow.steps.map((step, idx) => (
                <div key={step.id || idx}>
                  {/* Step card */}
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center justify-center h-8 w-8 rounded-full bg-blue-500/20 text-blue-400 text-sm font-bold shrink-0">
                        {idx + 1}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{step.name}</span>
                          <span className="px-2 py-0.5 rounded text-xs font-medium" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                            {step.type}
                          </span>
                        </div>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
                          Action: <span className="font-mono" style={{ color: 'var(--muted)' }}>{step.action}</span>
                        </p>
                      </div>
                      <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
                        {step.onSuccess && (
                          <span className="flex items-center gap-1">
                            <CheckCircle className="h-3 w-3 text-green-500" />
                            {step.onSuccess}
                          </span>
                        )}
                        {step.onFailure && (
                          <span className="flex items-center gap-1">
                            <XCircle className="h-3 w-3 text-red-500" />
                            {step.onFailure}
                          </span>
                        )}
                      </div>
                    </div>
                    {Object.keys(step.parameters).length > 0 && (
                      <details className="mt-3">
                        <summary className="text-xs cursor-pointer hover:opacity-80" style={{ color: 'var(--muted)' }}>
                          View parameters
                        </summary>
                        <pre className="mt-2 text-xs rounded p-2 overflow-x-auto" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                          {JSON.stringify(step.parameters, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                  {/* Arrow connector */}
                  {idx < workflow.steps.length - 1 && (
                    <div className="flex justify-center py-1">
                      <ArrowRight className="h-4 w-4 rotate-90" style={{ color: 'var(--muted)' }} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Execution History */}
        <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--muted)' }}>
            <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <Timer className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              Execution History
            </h2>
            <span className="text-xs" style={{ color: 'var(--muted)' }}>{executionHistory.length} executions</span>
          </div>

          {executionHistory.length === 0 ? (
            <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
              <Clock className="h-10 w-10 mx-auto mb-2 opacity-50" />
              <p>No executions yet</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b" style={{ borderColor: 'var(--muted)' }}>
                    <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Triggered By</th>
                    <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Started</th>
                    <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Duration</th>
                    <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--muted)' }}>
                  {executionHistory.map(exec => {
                    const StatusIcon = getStatusIcon(exec.status)
                    const isExpanded = expandedExecution === exec.id
                    return (
                      <tr key={exec.id} className="group" style={{ borderColor: 'var(--muted)' }}>
                        <td className="py-3 px-4">
                          <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border', getStatusColor(exec.status))}>
                            <StatusIcon className={cn('h-3 w-3', exec.status === 'running' && 'animate-spin')} />
                            {exec.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs" style={{ color: 'var(--fg)' }}>{exec.triggeredBy}</td>
                        <td className="py-3 px-4 text-xs" style={{ color: 'var(--muted)' }}>{formatDate(exec.startedAt)}</td>
                        <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--muted)' }}>{formatDuration(exec.duration_ms)}</td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => setExpandedExecution(isExpanded ? null : exec.id)}
                            className="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1"
                          >
                            {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                            {isExpanded ? 'Hide' : 'View'}
                          </button>
                          {isExpanded && (
                            <div className="mt-2 space-y-2">
                              {exec.error && (
                                <div className="text-xs text-red-400 bg-red-500/10 rounded p-2">
                                  {exec.error}
                                </div>
                              )}
                              {exec.stepResults.length > 0 && (
                                <pre className="text-xs rounded p-2 overflow-x-auto" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                                  {JSON.stringify(exec.stepResults, null, 2)}
                                </pre>
                              )}
                              {Object.keys(exec.triggerData).length > 0 && (
                                <div>
                                  <span className="text-xs" style={{ color: 'var(--muted)' }}>Trigger Data:</span>
                                  <pre className="mt-1 text-xs rounded p-2 overflow-x-auto" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                                    {JSON.stringify(exec.triggerData, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
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
