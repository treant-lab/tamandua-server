import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Workflow,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Search,
  Plus,
  MoreVertical,
  Zap,
  ArrowRight,
  RefreshCw,
  Settings,
  TrendingUp,
  TrendingDown,
  Activity,
  Target,
  GitBranch,
  Box,
  Eye,
  Edit,
  Copy,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'
import { useState } from 'react'

// Types
interface WorkflowStep {
  id: string
  type: 'trigger' | 'condition' | 'action' | 'delay'
  name: string
  config: Record<string, any>
}

interface WorkflowExecution {
  id: string
  workflowId: string
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  startedAt: string
  completedAt: string | null
  triggeredBy: string
  duration: number | null
}

interface AutomationWorkflow {
  id: string
  name: string
  description: string
  isEnabled: boolean
  triggerType: 'alert' | 'schedule' | 'webhook' | 'event' | 'manual'
  triggerConditions: string[]
  steps: WorkflowStep[]
  executions: {
    total: number
    successful: number
    failed: number
    avgDuration: number
  }
  lastExecuted: string | null
  createdAt: string
  updatedAt: string
  createdBy: string
}

interface ActionMetric {
  action: string
  total: number
  successful: number
  failed: number
  avgDuration: number
}

interface ExecutionStats {
  totalWorkflows: number
  enabledWorkflows: number
  totalExecutions: number
  totalSuccessful: number
  runningNow: number
}

interface HyperautomationPageProps {
  workflows?: AutomationWorkflow[]
  availableActions?: ActionMetric[]
  templates?: { id: string; name: string; description: string }[]
  executionStats?: ExecutionStats
  recentExecutions?: WorkflowExecution[]
}

const triggerTypeConfig: Record<AutomationWorkflow['triggerType'], { icon: typeof Zap; color: string; label: string }> = {
  alert: { icon: AlertTriangle, color: 'text-orange-400 bg-orange-400/10', label: 'Alert' },
  schedule: { icon: Clock, color: 'text-blue-400 bg-blue-400/10', label: 'Schedule' },
  webhook: { icon: GitBranch, color: 'text-purple-400 bg-purple-400/10', label: 'Webhook' },
  event: { icon: Zap, color: 'text-yellow-400 bg-yellow-400/10', label: 'Event' },
  manual: { icon: Play, color: 'text-[var(--muted)] bg-[var(--surface-2)]', label: 'Manual' },
}

const stepTypeConfig: Record<WorkflowStep['type'], { color: string; icon: typeof Box }> = {
  trigger: { color: 'bg-blue-500', icon: Zap },
  condition: { color: 'bg-yellow-500', icon: GitBranch },
  action: { color: 'bg-green-500', icon: Play },
  delay: { color: 'bg-[var(--muted)]', icon: Clock },
}

const executionStatusConfig: Record<WorkflowExecution['status'], { color: string; icon: typeof CheckCircle }> = {
  running: { color: 'text-blue-400 bg-blue-400/10', icon: RefreshCw },
  completed: { color: 'text-green-400 bg-green-400/10', icon: CheckCircle },
  failed: { color: 'text-red-400 bg-red-400/10', icon: XCircle },
  cancelled: { color: 'text-[var(--muted)] bg-[var(--surface-2)]', icon: Pause },
}

export default function Automation({
  workflows = [],
  availableActions = [],
  templates = [],
  executionStats,
  recentExecutions = []
}: HyperautomationPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTrigger, setSelectedTrigger] = useState<AutomationWorkflow['triggerType'] | 'all'>('all')
  const [showEnabledOnly, setShowEnabledOnly] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState<AutomationWorkflow | null>(null)

  const filteredWorkflows = workflows.filter((workflow) => {
    const matchesSearch = workflow.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      workflow.description.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesTrigger = selectedTrigger === 'all' || workflow.triggerType === selectedTrigger
    const matchesEnabled = !showEnabledOnly || workflow.isEnabled
    return matchesSearch && matchesTrigger && matchesEnabled
  })

  // Calculate stats from props or use executionStats if provided
  const totalWorkflows = executionStats?.totalWorkflows ?? workflows.length
  const enabledWorkflows = executionStats?.enabledWorkflows ?? workflows.filter((w) => w.isEnabled).length
  const totalExecutions = executionStats?.totalExecutions ?? workflows.reduce((acc, w) => acc + w.executions.total, 0)
  const totalSuccessful = executionStats?.totalSuccessful ?? workflows.reduce((acc, w) => acc + w.executions.successful, 0)
  const overallSuccessRate = totalExecutions > 0 ? ((totalSuccessful / totalExecutions) * 100).toFixed(1) : '0'
  const runningNow = executionStats?.runningNow ?? recentExecutions.filter((e) => e.status === 'running').length

  const formatDate = (dateString: string) => {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(dateString))
  }

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}m ${secs.toFixed(0)}s`
  }

  return (
    <MainLayout title="Hyperautomation Engine">
      <Head title="Automation - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-5 gap-4">
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary-500/10">
                <Workflow className="h-5 w-5 text-primary-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{totalWorkflows}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Workflows</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <CheckCircle className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{enabledWorkflows}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Active Workflows</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Activity className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{totalExecutions}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Executions</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <Target className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{overallSuccessRate}%</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Success Rate</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Zap className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                  {runningNow}
                </p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Running Now</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters and Actions */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                placeholder="Search workflows..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-sentinel rounded-lg pl-10 pr-4 py-2 text-sm w-64"
              />
            </div>

            <Select
              value={selectedTrigger}
              onValueChange={(value) => setSelectedTrigger(value as AutomationWorkflow['triggerType'] | 'all')}
              placeholder="All Triggers"
              className="input-sentinel rounded-lg px-3 py-2 text-sm"
            >
              <SelectItem value="all">All Triggers</SelectItem>
              {Object.entries(triggerTypeConfig).map(([key, config]) => (
                <SelectItem key={key} value={key}>{config.label}</SelectItem>
              ))}
            </Select>

            <button
              onClick={() => setShowEnabledOnly(!showEnabledOnly)}
              className={cn(
                'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                showEnabledOnly
                  ? 'bg-green-600/20 text-green-400 border border-green-500/30'
                  : 'card-sentinel hover:bg-[var(--surface-2)]'
              )}
              style={!showEnabledOnly ? { color: 'var(--fg-2)' } : undefined}
            >
              {showEnabledOnly ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
              Enabled Only
            </button>
          </div>

          <button className="btn-sentinel-primary rounded-lg px-4 py-2 text-sm font-medium flex items-center gap-2">
            <Plus className="h-4 w-4" />
            New Workflow
          </button>
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* Workflows List */}
          <div className="col-span-2 space-y-4">
            {filteredWorkflows.length === 0 ? (
              <div className="card-sentinel rounded-xl p-12 text-center">
                <Workflow className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--dim)' }} />
                <p className="text-lg" style={{ color: 'var(--muted)' }}>No workflows found</p>
                <p className="text-sm mt-1" style={{ color: 'var(--subtle)' }}>Try adjusting your filters</p>
              </div>
            ) : (
              filteredWorkflows.map((workflow) => {
                const triggerConf = triggerTypeConfig[workflow.triggerType]
                const TriggerIcon = triggerConf.icon
                const successRate = workflow.executions.total > 0
                  ? ((workflow.executions.successful / workflow.executions.total) * 100).toFixed(1)
                  : '0'

                return (
                  <div
                    key={workflow.id}
                    onClick={() => setSelectedWorkflow(workflow)}
                    className={cn(
                      'card-sentinel card-sentinel-interactive rounded-xl p-5 cursor-pointer',
                      selectedWorkflow?.id === workflow.id && 'ring-2 ring-primary-500 border-primary-500'
                    )}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-start gap-4">
                        <div className={cn('p-2.5 rounded-lg', triggerConf.color)}>
                          <TriggerIcon className="h-5 w-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>{workflow.name}</h3>
                            <span className={cn(
                              'px-2 py-0.5 rounded-full text-xs font-medium',
                              workflow.isEnabled
                                ? 'bg-green-500/10 text-green-400'
                                : 'bg-[var(--surface-2)] text-[var(--muted)]'
                            )}>
                              {workflow.isEnabled ? 'Enabled' : 'Disabled'}
                            </span>
                          </div>
                          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{workflow.description}</p>
                        </div>
                      </div>
                      <button className="p-1 rounded hover:bg-[var(--surface-2)]" style={{ color: 'var(--muted)' }}>
                        <MoreVertical className="h-5 w-5" />
                      </button>
                    </div>

                    {/* Workflow Steps Preview */}
                    <div className="flex items-center gap-1 mb-4 overflow-x-auto pb-2">
                      {workflow.steps.map((step, index) => {
                        const stepConf = stepTypeConfig[step.type]

                        return (
                          <div key={step.id} className="flex items-center">
                            <div className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5" style={{ background: 'var(--surface-2)' }}>
                              <div className={cn('h-2 w-2 rounded-full', stepConf.color)} />
                              <span className="text-xs whitespace-nowrap" style={{ color: 'var(--fg-2)' }}>{step.name}</span>
                            </div>
                            {index < workflow.steps.length - 1 && (
                              <ArrowRight className="h-3 w-3 mx-1 flex-shrink-0" style={{ color: 'var(--dim)' }} />
                            )}
                          </div>
                        )
                      })}
                    </div>

                    {/* Metrics */}
                    <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--border)' }}>
                      <div className="flex items-center gap-6 text-sm">
                        <div className="flex items-center gap-2">
                          <Activity className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                          <span style={{ color: 'var(--muted)' }}>{workflow.executions.total} executions</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {parseFloat(successRate) >= 90 ? (
                            <TrendingUp className="h-4 w-4 text-green-400" />
                          ) : parseFloat(successRate) >= 70 ? (
                            <Activity className="h-4 w-4 text-yellow-400" />
                          ) : (
                            <TrendingDown className="h-4 w-4 text-red-400" />
                          )}
                          <span className={cn(
                            parseFloat(successRate) >= 90 ? 'text-green-400' :
                            parseFloat(successRate) >= 70 ? 'text-yellow-400' : 'text-red-400'
                          )}>
                            {successRate}% success
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                          <span style={{ color: 'var(--muted)' }}>Avg: {formatDuration(workflow.executions.avgDuration)}</span>
                        </div>
                      </div>
                      {workflow.lastExecuted && (
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                          Last run: {formatDate(workflow.lastExecuted)}
                        </span>
                      )}
                    </div>
                  </div>
                )
              })
            )}
          </div>

          {/* Right Sidebar */}
          <div className="space-y-6">
            {/* Workflow Builder Preview */}
            {selectedWorkflow ? (
              <div className="card-sentinel rounded-xl">
                <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Workflow Builder</h2>
                  <div className="flex items-center gap-1">
                    <button className="p-1.5 rounded hover:bg-[var(--surface-2)]" style={{ color: 'var(--muted)' }}>
                      <Eye className="h-4 w-4" />
                    </button>
                    <button className="p-1.5 rounded hover:bg-[var(--surface-2)]" style={{ color: 'var(--muted)' }}>
                      <Edit className="h-4 w-4" />
                    </button>
                    <button className="p-1.5 rounded hover:bg-[var(--surface-2)]" style={{ color: 'var(--muted)' }}>
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                <div className="p-4">
                  <h3 className="font-medium mb-2" style={{ color: 'var(--fg)' }}>{selectedWorkflow.name}</h3>

                  {/* Visual Step Flow */}
                  <div className="space-y-2 mb-4">
                    {selectedWorkflow.steps.map((step, index) => {
                      const stepConf = stepTypeConfig[step.type]
                      const StepIcon = stepConf.icon

                      return (
                        <div key={step.id} className="relative">
                          <div className="flex items-center gap-3 rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                            <div className={cn(
                              'flex items-center justify-center h-8 w-8 rounded-lg',
                              step.type === 'trigger' ? 'bg-blue-500/20 text-blue-400' :
                              step.type === 'condition' ? 'bg-yellow-500/20 text-yellow-400' :
                              step.type === 'action' ? 'bg-green-500/20 text-green-400' :
                              'bg-[var(--surface-3)] text-[var(--muted)]'
                            )}>
                              <StepIcon className="h-4 w-4" />
                            </div>
                            <div className="flex-1">
                              <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{step.name}</p>
                              <p className="text-xs capitalize" style={{ color: 'var(--subtle)' }}>{step.type}</p>
                            </div>
                            <span className="text-xs" style={{ color: 'var(--subtle)' }}>#{index + 1}</span>
                          </div>
                          {index < selectedWorkflow.steps.length - 1 && (
                            <div className="absolute left-6 top-full h-2 w-0.5" style={{ background: 'var(--border)' }} />
                          )}
                        </div>
                      )
                    })}
                  </div>

                  <div className="mb-4">
                    <h4 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Trigger Conditions</h4>
                    <div className="flex flex-wrap gap-1">
                      {selectedWorkflow.triggerConditions.map((condition, index) => (
                        <span key={index} className="px-2 py-1 rounded text-xs" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                          {condition}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                    <button className="flex-1 btn-sentinel-primary rounded-lg px-3 py-2 text-sm font-medium flex items-center justify-center gap-2">
                      <Play className="h-4 w-4" />
                      Run Now
                    </button>
                    <button className="btn-sentinel-secondary rounded-lg px-3 py-2 text-sm font-medium flex items-center justify-center gap-2">
                      <Settings className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="card-sentinel rounded-xl p-8 text-center">
                <Workflow className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--dim)' }} />
                <p style={{ color: 'var(--muted)' }}>Select a workflow to preview</p>
              </div>
            )}

            {/* Execution Metrics */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Action Success Rates</h2>
              </div>
              <div className="p-4 space-y-3">
                {availableActions.slice(0, 5).map((metric) => {
                  const successRate = metric.total > 0 ? ((metric.successful / metric.total) * 100).toFixed(1) : '0'

                  return (
                    <div key={metric.action}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{metric.action}</span>
                        <span className={cn(
                          'text-xs font-medium',
                          parseFloat(successRate) >= 95 ? 'text-green-400' :
                          parseFloat(successRate) >= 85 ? 'text-yellow-400' : 'text-red-400'
                        )}>
                          {successRate}%
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
                        <div
                          className={cn(
                            'h-full rounded-full',
                            parseFloat(successRate) >= 95 ? 'bg-green-500' :
                            parseFloat(successRate) >= 85 ? 'bg-yellow-500' : 'bg-red-500'
                          )}
                          style={{ width: `${successRate}%` }}
                        />
                      </div>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>{metric.total} total</span>
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>Avg: {metric.avgDuration.toFixed(1)}s</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Recent Executions */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recent Executions</h2>
              </div>
              <div className="max-h-[300px] overflow-auto" style={{ borderColor: 'var(--border)' }}>
                {recentExecutions.map((execution) => {
                  const workflow = workflows.find((w) => w.id === execution.workflowId)
                  const statusConf = executionStatusConfig[execution.status]
                  const StatusIcon = statusConf.icon

                  return (
                    <div key={execution.id} className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                      <div className="flex items-start gap-3">
                        <div className={cn('p-2 rounded-lg', statusConf.color)}>
                          <StatusIcon className={cn(
                            'h-4 w-4',
                            execution.status === 'running' && 'animate-spin'
                          )} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{workflow?.name}</p>
                          <p className="text-xs truncate mt-0.5" style={{ color: 'var(--muted)' }}>{execution.triggeredBy}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-xs" style={{ color: 'var(--subtle)' }}>{formatDate(execution.startedAt)}</span>
                            {execution.duration && (
                              <span className="text-xs" style={{ color: 'var(--subtle)' }}>({formatDuration(execution.duration)})</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Workflow Templates */}
            {templates.length > 0 && (
              <div className="card-sentinel rounded-xl">
                <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Quick Templates</h2>
                </div>
                <div className="p-4 space-y-2">
                  {templates.slice(0, 4).map((template) => (
                    <button
                      key={template.id}
                      className="w-full text-left p-3 rounded-lg transition-colors hover:bg-[var(--surface-2)]"
                      style={{ background: 'var(--surface-2)' }}
                    >
                      <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{template.name}</p>
                      <p className="text-xs mt-0.5 line-clamp-1" style={{ color: 'var(--muted)' }}>{template.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
