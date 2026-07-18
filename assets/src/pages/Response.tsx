import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Crosshair,
  Shield,
  Network,
  Search,
  Package,
  Play,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  Monitor,
  ChevronDown,
  AlertTriangle,
  RotateCcw,
  RefreshCw,
  Undo2,
  HardDrive,
  FileWarning,
  RotateCw,
  Trash2,
  Plus,
  Calendar,
  Bot,
  Brain,
  Zap,
  Settings,
  ToggleLeft,
  ToggleRight,
  TrendingUp,
  ThumbsUp,
  ThumbsDown,
  Eye,
  Edit,
  Copy,
  FileText,
  Activity,
} from 'lucide-react'
import { cn, formatDate, formatBytes } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useCallback, useRef, useEffect } from 'react'
import { Checkbox } from '@/components/ui/baseui'
import axios from 'axios'
import { toast } from 'sonner'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Agent {
  id: string
  hostname: string
  status: string
}

interface ResponseAction {
  id: string
  agentId: string
  actionType: string
  parameters: Record<string, any>
  status: string
  result: Record<string, any> | null
  errorMessage: string | null
  executedAt: string | null
  createdAt: string
}

interface ResponseProps {
  agents: Agent[]
  recentActions: ResponseAction[]
}

// Autonomous Response Types
interface AutonomousRecommendation {
  id: string
  alert_id: string
  agent_id: string
  severity: string
  confidence_score: number
  criticality_level: string
  criticality_score: number
  suggested_actions: Array<{
    type: string
    params: Record<string, any>
    risk_score: number
  }>
  auto_execute_eligible: boolean
  justification: string
  status: string
  created_at: string
  expires_at: string
}

interface AutonomousRule {
  id: string
  name: string
  description: string
  conditions: any[]
  actions: Array<{ type: string; params: Record<string, any> }>
  priority: number
  enabled: boolean
  auto_execute: boolean
  mode: string
  match_count: number
  execution_count: number
}

interface AutonomousSettings {
  autonomous_enabled: boolean
  max_actions_per_minute: number
  max_actions_per_hour: number
  critical_asset_protection: boolean
  min_confidence_for_auto: number
}

interface LearningStats {
  total_decisions: number
  approval_rate: number
  model_trained: boolean
  last_model_update: string | null
  unique_analysts: number
}

interface ActionParam {
  name: string
  label: string
  type: string
  required?: boolean
  default?: boolean | number | string
  options?: string[]
}

interface VssSnapshot {
  id: string
  volume: string
  created_at: number
  device_name: string
  accessible: boolean
  size_bytes: number
}

interface EncryptedFile {
  path: string
  original_extension: string | null
  ransomware_extension: string
  entropy: number
  size: number
}

interface ActionType {
  id: string
  name: string
  icon: React.ComponentType<{ className?: string }>
  description: string
  destructive: boolean
  undoAction?: string
  params: ActionParam[]
}

// Track in-flight action state locally for optimistic UI
interface TrackedAction {
  id: string
  actionType: string
  agentId: string
  agentHostname: string
  status: 'pending' | 'executing' | 'success' | 'failed'
  errorMessage: string | null
  retryCount: number
  maxRetries: number
  createdAt: string
  executedAt: string | null
  parameters: Record<string, any>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const UNDO_MAP: Record<string, string> = {
  isolate_network: 'unisolate_network',
  block_ip: 'unblock_ip',
  block_domain: 'unblock_domain',
}

const ACTION_ROUTE_MAP: Record<string, string> = {
  'kill_process': '/api/v1/response/kill',
  'quarantine_file': '/api/v1/response/quarantine',
  'isolate_network': '/api/v1/agents/{agent_id}/isolate',
  'unisolate_network': '/api/v1/agents/{agent_id}/unisolate',
  'block_ip': '/api/v1/response/block-ip',
  'unblock_ip': '/api/v1/response/unblock-ip',
  'block_domain': '/api/v1/response/block-domain',
  'unblock_domain': '/api/v1/response/unblock-domain',
  'scan_path': '/api/v1/response/scan',
  'collect_artifact': '/api/v1/response/collect',
}

const actionTypes: ActionType[] = [
  {
    id: 'kill_process',
    name: 'Kill Process',
    icon: Crosshair,
    description: 'Terminate a running process by PID',
    destructive: true,
    params: [
      { name: 'pid', label: 'Process ID', type: 'number', required: true },
      { name: 'force', label: 'Force Kill', type: 'boolean', default: false },
    ],
  },
  {
    id: 'quarantine_file',
    name: 'Quarantine File',
    icon: Shield,
    description: 'Move a file to quarantine storage',
    destructive: true,
    params: [
      { name: 'path', label: 'File Path', type: 'string', required: true },
      { name: 'delete_after', label: 'Delete After Quarantine', type: 'boolean', default: false },
    ],
  },
  {
    id: 'isolate_network',
    name: 'Isolate Network',
    icon: Network,
    description: 'Isolate endpoint from network',
    destructive: true,
    undoAction: 'unisolate_network',
    params: [
      { name: 'allowed_ips', label: 'Allowed IPs (comma-separated)', type: 'string', required: false },
      { name: 'duration', label: 'Duration (seconds, 0=permanent)', type: 'number', default: 0 },
    ],
  },
  {
    id: 'unisolate_network',
    name: 'Remove Isolation',
    icon: Network,
    description: 'Remove network isolation from endpoint',
    destructive: false,
    params: [],
  },
  {
    id: 'block_ip',
    name: 'Block IP',
    icon: Shield,
    description: 'Block an IP address at the endpoint firewall',
    destructive: true,
    undoAction: 'unblock_ip',
    params: [
      { name: 'ip', label: 'IP Address', type: 'string', required: true },
      { name: 'direction', label: 'Direction', type: 'select', options: ['both', 'inbound', 'outbound'], default: 'both' },
      { name: 'reason', label: 'Reason', type: 'string', default: 'manual_block' },
    ],
  },
  {
    id: 'unblock_ip',
    name: 'Unblock IP',
    icon: Shield,
    description: 'Remove an endpoint firewall IP block',
    destructive: false,
    params: [
      { name: 'ip', label: 'IP Address', type: 'string', required: true },
    ],
  },
  {
    id: 'block_domain',
    name: 'Block Domain',
    icon: Shield,
    description: 'Block a domain on the endpoint and add it to DNS blocklist',
    destructive: true,
    undoAction: 'unblock_domain',
    params: [
      { name: 'domain', label: 'Domain', type: 'string', required: true },
      { name: 'reason', label: 'Reason', type: 'string', default: 'manual_block' },
    ],
  },
  {
    id: 'unblock_domain',
    name: 'Unblock Domain',
    icon: Shield,
    description: 'Remove an endpoint domain block',
    destructive: false,
    params: [
      { name: 'domain', label: 'Domain', type: 'string', required: true },
    ],
  },
  {
    id: 'scan_path',
    name: 'Scan Path',
    icon: Search,
    description: 'Scan a file or directory for threats',
    destructive: false,
    params: [
      { name: 'path', label: 'Path', type: 'string', required: true },
      { name: 'recursive', label: 'Recursive Scan', type: 'boolean', default: true },
      { name: 'max_depth', label: 'Max Depth', type: 'number', default: 5 },
    ],
  },
  {
    id: 'collect_artifact',
    name: 'Collect Artifact',
    icon: Package,
    description: 'Collect a file for forensic analysis',
    destructive: false,
    params: [
      { name: 'path', label: 'File Path', type: 'string', required: true },
      { name: 'artifact_type', label: 'Artifact Type', type: 'select', options: ['file', 'memory', 'registry'], default: 'file' },
    ],
  },
]

const statusColors: Record<string, string> = {
  pending: 'text-[var(--high)] bg-[var(--high-bg)]',
  executing: 'text-[var(--med)] bg-[var(--med-bg)]',
  success: 'text-[var(--emerald-400)] bg-[var(--emerald-glow)]',
  failed: 'text-[var(--crit)] bg-[var(--crit-bg)]',
  cancelled: 'text-[var(--muted)] bg-[var(--surface-2)]',
}

// ---------------------------------------------------------------------------
// Helper: exponential backoff delay
// ---------------------------------------------------------------------------

function backoffDelay(attempt: number, base = 1000, max = 30000): number {
  const delay = Math.min(base * Math.pow(2, attempt), max)
  // Add jitter: +/- 25%
  return delay * (0.75 + Math.random() * 0.5)
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'pending':
      return <Clock className="h-4 w-4" />
    case 'executing':
      return <Loader2 className="h-4 w-4 animate-spin" />
    case 'success':
      return <CheckCircle className="h-4 w-4" />
    case 'failed':
      return <XCircle className="h-4 w-4" />
    default:
      return <Clock className="h-4 w-4" />
  }
}

function ConfirmDialog({ title, message, onConfirm, onCancel }: {
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-xl max-w-md w-full mx-4 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg bg-[var(--crit-bg)]">
            <AlertTriangle className="h-5 w-5 text-[var(--crit)]" />
          </div>
          <h3 className="text-lg font-semibold text-[var(--fg)]">{title}</h3>
        </div>
        <p className="text-sm text-[var(--muted)] mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="btn-sentinel btn-sentinel-secondary"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="btn-sentinel btn-sentinel-danger"
          >
            Confirm Action
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

type TabId = 'actions' | 'snapshots' | 'recovery' | 'autonomous' | 'metrics'

// Response metrics types
interface ResponseMetrics {
  total_responses: number
  successful_responses: number
  failed_responses: number
  rollbacks: number
  avg_response_time_ms: number
  min_response_time_ms: number | null
  max_response_time_ms: number
  responses_by_type: Record<string, number>
  mttr_minutes: number
  current_hour: {
    responses: number
    automated: number
    manual: number
    avg_time_ms: number
  }
}

interface ResponseTimelineEvent {
  id: string
  type: string
  agent_id: string
  agent_hostname: string
  alert_id: string | null
  actions: Array<{
    action: string
    result: string
    duration_ms: number
  }>
  duration_ms: number
  success: boolean
  executed_at: string
  automated: boolean
}

export default function Response({ agents, recentActions }: ResponseProps) {
  const [activeTab, setActiveTab] = useState<TabId>('actions')
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [selectedAction, setSelectedAction] = useState(actionTypes[0])
  const [params, setParams] = useState<Record<string, any>>({})
  const [isExecuting, setIsExecuting] = useState(false)
  const [showAgentDropdown, setShowAgentDropdown] = useState(false)

  // VSS Snapshots state
  const [snapshots, setSnapshots] = useState<VssSnapshot[]>([])
  const [loadingSnapshots, setLoadingSnapshots] = useState(false)
  const [creatingSnapshot, setCreatingSnapshot] = useState(false)
  const [selectedVolume, setSelectedVolume] = useState('C:')

  // Ransomware recovery state
  const [encryptedFiles, setEncryptedFiles] = useState<EncryptedFile[]>([])
  const [scanningFiles, setScanningFiles] = useState(false)
  const [scanPath, setScanPath] = useState('C:\\Users')
  const [remediating, setRemediating] = useState(false)
  const [remediationResult, setRemediationResult] = useState<any>(null)

  // Confirmation dialog state
  const [showConfirm, setShowConfirm] = useState<{
    title: string
    message: string
    onConfirm: () => void
  } | null>(null)

  // Tracked actions for status tracking and retry
  const [trackedActions, setTrackedActions] = useState<TrackedAction[]>([])

  // Autonomous response state
  const [autonomousSettings, setAutonomousSettings] = useState<AutonomousSettings | null>(null)
  const [pendingRecommendations, setPendingRecommendations] = useState<AutonomousRecommendation[]>([])
  const [processingRecommendationIds, setProcessingRecommendationIds] = useState<Set<string>>(new Set())
  const processingRecommendationIdsRef = useRef<Set<string>>(new Set())
  const recommendationPollControllersRef = useRef<Map<string, AbortController>>(new Map())
  const [activeRecommendationExecutionIds, setActiveRecommendationExecutionIds] = useState<Set<string>>(new Set())
  const [pausedRecommendationExecutionIds, setPausedRecommendationExecutionIds] = useState<Set<string>>(new Set())
  const [autonomousRules, setAutonomousRules] = useState<AutonomousRule[]>([])
  const [learningStats, setLearningStats] = useState<LearningStats | null>(null)
  const [loadingAutonomous, setLoadingAutonomous] = useState(false)
  const [autonomousSubTab, setAutonomousSubTab] = useState<'recommendations' | 'rules' | 'learning' | 'settings'>('recommendations')
  const [, setEditingRule] = useState<AutonomousRule | null>(null)
  const [, setShowRuleEditor] = useState(false)
  const [ruleTemplates, setRuleTemplates] = useState<any[]>([])

  // Response metrics state
  const [responseMetrics, setResponseMetrics] = useState<ResponseMetrics | null>(null)
  const [responseTimeline, setResponseTimeline] = useState<ResponseTimelineEvent[]>([])
  const [loadingMetrics, setLoadingMetrics] = useState(false)
  const [metricsTimeRange, setMetricsTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')

  const agentList = agents || []
  const actionList = recentActions || []

  // Polling for tracked action status updates
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const pendingActions = trackedActions.filter(a => a.status === 'pending' || a.status === 'executing')
    if (pendingActions.length === 0) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      return
    }

    if (!pollIntervalRef.current) {
      pollIntervalRef.current = setInterval(() => {
        // Reload page data to get updated action statuses
        router.reload({ only: ['recentActions'] })
      }, 3000)
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [trackedActions])

  // Sync tracked actions with server data
  useEffect(() => {
    if (!recentActions) return

    setTrackedActions(prev => {
      return prev.map(tracked => {
        const serverAction = recentActions.find(a => a.id === tracked.id)
        if (serverAction) {
          const newStatus = serverAction.status as TrackedAction['status']
          if (newStatus !== tracked.status) {
            if (newStatus === 'success') {
              toast.success(`Action completed: ${tracked.actionType}`)
            } else if (newStatus === 'failed' && tracked.retryCount < tracked.maxRetries) {
              // Auto-retry with backoff
              scheduleRetry(tracked)
            }
            return {
              ...tracked,
              status: newStatus,
              errorMessage: serverAction.errorMessage,
              executedAt: serverAction.executedAt,
            }
          }
        }
        return tracked
      })
    })
  }, [recentActions])

  // -------------------------------------------------------------------
  // Execute with retry logic
  // -------------------------------------------------------------------

  const executeAction = useCallback(async (
    actionId: string,
    actionParams: Record<string, any>,
    agentTarget: Agent,
    retryCount = 0,
    maxRetries = 3,
  ): Promise<void> => {
    setIsExecuting(true)

    try {
      // Map action ID to correct backend route
      let url = ACTION_ROUTE_MAP[actionId] || `/api/v1/response/${actionId}`
      // Replace {agent_id} placeholder for agent-specific routes
      url = url.replace('{agent_id}', agentTarget.id)

      const response = await axios.post(url, {
        agent_id: agentTarget.id,
        ...actionParams,
      })

      const actionData = response.data

      // Track the action
      const tracked: TrackedAction = {
        id: actionData?.id || `local-${Date.now()}`,
        actionType: actionId,
        agentId: agentTarget.id,
        agentHostname: agentTarget.hostname,
        status: 'pending',
        errorMessage: null,
        retryCount,
        maxRetries,
        createdAt: new Date().toISOString(),
        executedAt: null,
        parameters: actionParams,
      }

      setTrackedActions(prev => [tracked, ...prev])
      toast.success(`Action dispatched: ${actionId}`)
      router.reload({ only: ['recentActions'] })
    } catch (error: any) {
      const errorMsg = error.response?.data?.error || 'Failed to execute action'

      if (retryCount < maxRetries) {
        const delay = backoffDelay(retryCount)
        toast.error(`Action failed. Retrying in ${Math.round(delay / 1000)}s... (attempt ${retryCount + 1}/${maxRetries})`)

        setTimeout(() => {
          executeAction(actionId, actionParams, agentTarget, retryCount + 1, maxRetries)
        }, delay)
      } else {
        toast.error(`Action failed after ${maxRetries} retries: ${errorMsg}`)

        // Record failure in tracked actions
        setTrackedActions(prev => [{
          id: `failed-${Date.now()}`,
          actionType: actionId,
          agentId: agentTarget.id,
          agentHostname: agentTarget.hostname,
          status: 'failed',
          errorMessage: errorMsg,
          retryCount,
          maxRetries,
          createdAt: new Date().toISOString(),
          executedAt: null,
          parameters: actionParams,
        }, ...prev])
      }
    } finally {
      setIsExecuting(false)
    }
  }, [])

  // Schedule retry for a tracked action that failed on the server side
  const scheduleRetry = useCallback((tracked: TrackedAction) => {
    const delay = backoffDelay(tracked.retryCount)
    const agent = agentList.find(a => a.id === tracked.agentId)
    if (!agent) return

    toast.info(`Auto-retrying "${tracked.actionType}" in ${Math.round(delay / 1000)}s...`)
    setTimeout(() => {
      executeAction(tracked.actionType, tracked.parameters, agent, tracked.retryCount + 1, tracked.maxRetries)
    }, delay)
  }, [agentList, executeAction])

  // Manual retry
  const handleRetry = useCallback((tracked: TrackedAction) => {
    const agent = agentList.find(a => a.id === tracked.agentId)
    if (!agent) {
      toast.error('Agent not found for retry')
      return
    }
    executeAction(tracked.actionType, tracked.parameters, agent, 0, tracked.maxRetries)
  }, [agentList, executeAction])

  // Undo action (e.g., un-isolate after isolate)
  const handleUndo = useCallback(async (tracked: TrackedAction) => {
    const undoActionId = UNDO_MAP[tracked.actionType]
    if (!undoActionId) {
      toast.error('No undo action available for this action type')
      return
    }

    const agent = agentList.find(a => a.id === tracked.agentId)
    if (!agent) {
      toast.error('Agent not found')
      return
    }

    executeAction(undoActionId, {}, agent, 0, 3)
  }, [agentList, executeAction])

  // -------------------------------------------------------------------
  // VSS Snapshot functions
  // -------------------------------------------------------------------

  const loadSnapshots = useCallback(async () => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    setLoadingSnapshots(true)
    try {
      const response = await axios.get(`/api/v1/agents/${selectedAgent.id}/snapshots`, {
        params: { volume: selectedVolume }
      })
      setSnapshots(response.data.snapshots || [])
    } catch (error: any) {
      toast.error(`Failed to load snapshots: ${error.response?.data?.error || error.message}`)
      setSnapshots([])
    } finally {
      setLoadingSnapshots(false)
    }
  }, [selectedAgent, selectedVolume])

  const createSnapshot = useCallback(async () => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    setCreatingSnapshot(true)
    try {
      await axios.post(`/api/v1/agents/${selectedAgent.id}/snapshots`, {
        volume: selectedVolume
      })
      toast.success('Snapshot created successfully')
      loadSnapshots()
    } catch (error: any) {
      toast.error(`Failed to create snapshot: ${error.response?.data?.error || error.message}`)
    } finally {
      setCreatingSnapshot(false)
    }
  }, [selectedAgent, selectedVolume, loadSnapshots])

  const deleteSnapshot = useCallback(async (snapshotId: string) => {
    if (!selectedAgent) return

    try {
      await axios.delete(`/api/v1/agents/${selectedAgent.id}/snapshots/${snapshotId}`)
      toast.success('Snapshot deleted')
      loadSnapshots()
    } catch (error: any) {
      toast.error(`Failed to delete snapshot: ${error.response?.data?.error || error.message}`)
    }
  }, [selectedAgent, loadSnapshots])

  // -------------------------------------------------------------------
  // Ransomware recovery functions
  // -------------------------------------------------------------------

  const scanForEncryptedFiles = useCallback(async () => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    setScanningFiles(true)
    setEncryptedFiles([])
    try {
      const response = await axios.get(`/api/v1/agents/${selectedAgent.id}/encrypted-files`, {
        params: { path: scanPath }
      })
      setEncryptedFiles(response.data.encrypted_files || [])
      if (response.data.count === 0) {
        toast.success('No encrypted files found')
      } else {
        toast.warning(`Found ${response.data.count} encrypted files`)
      }
    } catch (error: any) {
      toast.error(`Failed to scan: ${error.response?.data?.error || error.message}`)
    } finally {
      setScanningFiles(false)
    }
  }, [selectedAgent, scanPath])

  const startRemediation = useCallback(async () => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    setRemediating(true)
    setRemediationResult(null)
    try {
      const response = await axios.post(`/api/v1/agents/${selectedAgent.id}/remediate`, {
        path: scanPath,
        encrypted_files: encryptedFiles.length > 0 ? encryptedFiles : undefined
      })
      setRemediationResult(response.data.result)
      toast.success(`Remediation complete: ${response.data.restored_count} files restored`)
    } catch (error: any) {
      toast.error(`Remediation failed: ${error.response?.data?.error || error.message}`)
    } finally {
      setRemediating(false)
    }
  }, [selectedAgent, scanPath, encryptedFiles])

  // Load snapshots when agent changes and tab is snapshots
  useEffect(() => {
    if (activeTab === 'snapshots' && selectedAgent) {
      loadSnapshots()
    }
  }, [activeTab, selectedAgent])

  // -------------------------------------------------------------------
  // Autonomous Response Functions
  // -------------------------------------------------------------------

  const loadAutonomousData = useCallback(async () => {
    setLoadingAutonomous(true)
    try {
      const [settingsRes, recommendationsRes, rulesRes, statsRes, templatesRes] = await Promise.all([
        axios.get('/api/v1/autonomous/settings'),
        axios.get('/api/v1/autonomous/recommendations'),
        axios.get('/api/v1/autonomous/rules'),
        axios.get('/api/v1/autonomous/learning/stats'),
        axios.get('/api/v1/autonomous/rules/templates'),
      ])

      setAutonomousSettings(settingsRes.data.settings)
      setPendingRecommendations(recommendationsRes.data.recommendations || [])
      setAutonomousRules(rulesRes.data.rules || [])
      setLearningStats(statsRes.data)
      setRuleTemplates(templatesRes.data.templates || [])
    } catch (error: any) {
      logger.error('Failed to load autonomous data:', error)
      toast.error('Failed to load autonomous response data')
    } finally {
      setLoadingAutonomous(false)
    }
  }, [])

  const pollRecommendationStatus = useCallback(async (
    statusUrl: string,
    retryAfterMs = 2000,
    signal?: AbortSignal,
  ) => {
    const terminalStatuses = new Set([
      'approved',
      'auto_executed',
      'failed',
      'execution_unknown',
      'rejected',
      'expired',
    ])
    const deadline = Date.now() + 5 * 60 * 1000
    let delayMs = retryAfterMs

    while (Date.now() < deadline) {
      if (signal?.aborted) throw new DOMException('Recommendation polling cancelled', 'AbortError')

      try {
        const response = await axios.get(statusUrl, { signal })
        const recommendation = response.data.recommendation

        if (
          !recommendation ||
          typeof recommendation !== 'object' ||
          typeof recommendation.status !== 'string' ||
          recommendation.status.trim() === ''
        ) {
          const contractError = new Error(
            'Recommendation status response is missing recommendation/status'
          )
          contractError.name = 'RecommendationStatusContractError'
          throw contractError
        }

        if (terminalStatuses.has(recommendation.status)) {
          return recommendation
        }
      } catch (error: any) {
        if (error?.name === 'RecommendationStatusContractError') throw error
        const status = error.response?.status
        if (status && status < 500) throw error
      }

      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) {
          reject(new DOMException('Recommendation polling cancelled', 'AbortError'))
          return
        }

        const onAbort = () => {
          window.clearTimeout(timer)
          reject(new DOMException('Recommendation polling cancelled', 'AbortError'))
        }
        const timer = window.setTimeout(() => {
          signal?.removeEventListener('abort', onAbort)
          resolve()
        }, delayMs)
        signal?.addEventListener('abort', onAbort, { once: true })
      })
      delayMs = Math.min(Math.round(delayMs * 1.5), 10_000)
    }

    throw new Error('Recommendation execution is still running; check history for status')
  }, [])

  const startRecommendationPoll = useCallback((
    storageKey: string,
    statusUrl: string,
    retryAfterMs = 2000,
  ) => {
    recommendationPollControllersRef.current.get(storageKey)?.abort()

    const controller = new AbortController()
    recommendationPollControllersRef.current.set(storageKey, controller)

    return pollRecommendationStatus(statusUrl, retryAfterMs, controller.signal)
      .finally(() => {
        if (recommendationPollControllersRef.current.get(storageKey) === controller) {
          recommendationPollControllersRef.current.delete(storageKey)
        }
      })
  }, [pollRecommendationStatus])

  const notifyRecommendationTerminal = useCallback((terminal: any) => {
    if (terminal.status === 'approved' || terminal.status === 'auto_executed') {
      toast.success('Recommendation executed successfully')
    } else if (terminal.status === 'failed') {
      toast.warning('Recommendation approved, but one or more response actions failed')
    } else if (terminal.status === 'execution_unknown') {
      toast.error('Execution state is unknown; manual reconciliation is required')
    } else {
      toast.warning(`Recommendation finished with status: ${terminal.status}`)
    }
  }, [])

  const markRecommendationExecutionActive = useCallback((recommendationId: string) => {
    setActiveRecommendationExecutionIds(current => {
      const next = new Set(current)
      next.add(recommendationId)
      return next
    })
    setPausedRecommendationExecutionIds(current => {
      if (!current.has(recommendationId)) return current
      const next = new Set(current)
      next.delete(recommendationId)
      return next
    })
  }, [])

  const clearRecommendationExecutionActive = useCallback((recommendationId: string) => {
    setActiveRecommendationExecutionIds(current => {
      if (!current.has(recommendationId)) return current
      const next = new Set(current)
      next.delete(recommendationId)
      return next
    })
  }, [])

  const markRecommendationExecutionPaused = useCallback((recommendationId: string) => {
    clearRecommendationExecutionActive(recommendationId)
    setPausedRecommendationExecutionIds(current => {
      const next = new Set(current)
      next.add(recommendationId)
      return next
    })
  }, [clearRecommendationExecutionActive])

  const clearRecommendationExecutionTracking = useCallback((recommendationId: string) => {
    clearRecommendationExecutionActive(recommendationId)
    setPausedRecommendationExecutionIds(current => {
      if (!current.has(recommendationId)) return current
      const next = new Set(current)
      next.delete(recommendationId)
      return next
    })
  }, [clearRecommendationExecutionActive])

  useEffect(() => {
    if (activeTab !== 'autonomous') return

    const prefix = 'tamandua:autonomous-execution:'
    const pollControllers = recommendationPollControllersRef.current
    const stored = Object.keys(sessionStorage).filter(key => key.startsWith(prefix))

    for (const key of stored) {
      const statusUrl = sessionStorage.getItem(key)
      if (!statusUrl) continue
      const recommendationId = key.slice(prefix.length)
      if (!recommendationId) continue

      markRecommendationExecutionActive(recommendationId)

      void startRecommendationPoll(key, statusUrl)
        .then(terminal => {
          sessionStorage.removeItem(key)
          clearRecommendationExecutionTracking(recommendationId)
          notifyRecommendationTerminal(terminal)
          void loadAutonomousData()
        })
        .catch(error => {
          if (axios.isCancel(error) || error?.name === 'AbortError') return

          if (error.response?.status === 403 || error.response?.status === 404) {
            sessionStorage.removeItem(key)
            clearRecommendationExecutionTracking(recommendationId)
          } else {
            markRecommendationExecutionPaused(recommendationId)
          }
          logger.error('Failed to resume recommendation polling:', error)
        })
    }

    return () => {
      for (const controller of pollControllers.values()) {
        controller.abort()
      }
      pollControllers.clear()
    }
  }, [activeTab, clearRecommendationExecutionTracking, loadAutonomousData, markRecommendationExecutionActive, markRecommendationExecutionPaused, notifyRecommendationTerminal, startRecommendationPoll])

  const approveRecommendation = useCallback(async (recId: string) => {
    if (processingRecommendationIdsRef.current.has(recId)) return
    processingRecommendationIdsRef.current.add(recId)
    setProcessingRecommendationIds(new Set(processingRecommendationIdsRef.current))
    const storageKey = `tamandua:autonomous-execution:${recId}`

    try {
      const response = await axios.post(
        `/api/v1/autonomous/recommendations/${recId}/approve`,
        undefined,
        { headers: { Prefer: 'respond-async' } }
      )

      if (response.status === 202 && response.data.status_url) {
        toast.info(response.data.message || 'Recommendation execution queued')
        setPendingRecommendations(current => current.filter(rec => rec.id !== recId))
        sessionStorage.setItem(storageKey, response.data.status_url)
        markRecommendationExecutionActive(recId)

        const terminal = await startRecommendationPoll(
          storageKey,
          response.data.status_url,
          response.data.retry_after_ms || 2000
        )

        sessionStorage.removeItem(storageKey)
        clearRecommendationExecutionTracking(recId)
        notifyRecommendationTerminal(terminal)
      } else if (response.data.result?.status === 'execution_failed') {
        toast.warning(response.data.message || 'Recommendation approved, but execution failed')
      } else {
        toast.success(response.data.message || 'Recommendation approved')
      }
      await loadAutonomousData()
    } catch (error: any) {
      if (axios.isCancel(error) || error?.name === 'AbortError') return

      const payload = error.response?.data
      toast.error(`Failed to approve: ${payload?.error || error.message}`)

      if (error.response?.status === 403 || error.response?.status === 404) {
        sessionStorage.removeItem(storageKey)
        clearRecommendationExecutionTracking(recId)
      } else if (sessionStorage.getItem(storageKey)) {
        markRecommendationExecutionPaused(recId)
      }

      if (
        error.response?.status === 404 ||
        payload?.code === 'already_processed' ||
        payload?.code === 'execution_state_unknown'
      ) {
        await loadAutonomousData()
      }
    } finally {
      processingRecommendationIdsRef.current.delete(recId)
      setProcessingRecommendationIds(new Set(processingRecommendationIdsRef.current))
    }
  }, [clearRecommendationExecutionTracking, loadAutonomousData, markRecommendationExecutionActive, markRecommendationExecutionPaused, notifyRecommendationTerminal, startRecommendationPoll])

  const rejectRecommendation = useCallback(async (recId: string, reason: string) => {
    if (processingRecommendationIdsRef.current.has(recId)) return
    processingRecommendationIdsRef.current.add(recId)
    setProcessingRecommendationIds(new Set(processingRecommendationIdsRef.current))

    try {
      await axios.post(`/api/v1/autonomous/recommendations/${recId}/reject`, { reason })
      toast.success('Recommendation rejected')
      await loadAutonomousData()
    } catch (error: any) {
      const payload = error.response?.data
      toast.error(`Failed to reject: ${payload?.error || error.message}`)

      if (error.response?.status === 404 || payload?.code === 'already_processed') {
        await loadAutonomousData()
      }
    } finally {
      processingRecommendationIdsRef.current.delete(recId)
      setProcessingRecommendationIds(new Set(processingRecommendationIdsRef.current))
    }
  }, [loadAutonomousData])

  const toggleRule = useCallback(async (ruleId: string, enabled: boolean) => {
    try {
      await axios.post(`/api/v1/autonomous/rules/${ruleId}/toggle`, { enabled })
      toast.success(enabled ? 'Rule enabled' : 'Rule disabled')
      loadAutonomousData()
    } catch (error: any) {
      toast.error(`Failed to toggle rule: ${error.response?.data?.error || error.message}`)
    }
  }, [loadAutonomousData])

  const updateSettings = useCallback(async (newSettings: Partial<AutonomousSettings>) => {
    try {
      await axios.put('/api/v1/autonomous/settings', { settings: newSettings })
      toast.success('Settings updated')
      loadAutonomousData()
    } catch (error: any) {
      toast.error(`Failed to update settings: ${error.response?.data?.error || error.message}`)
    }
  }, [loadAutonomousData])

  const cloneTemplate = useCallback(async (templateId: string) => {
    try {
      await axios.post('/api/v1/autonomous/rules/clone-template', { template_id: templateId })
      toast.success('Rule created from template')
      loadAutonomousData()
    } catch (error: any) {
      toast.error(`Failed to clone template: ${error.response?.data?.error || error.message}`)
    }
  }, [loadAutonomousData])

  const emergencyDisable = useCallback(async (reason: string) => {
    try {
      await axios.post('/api/v1/autonomous/emergency-disable', { reason })
      toast.warning('Autonomous responses disabled')
      loadAutonomousData()
    } catch (error: any) {
      toast.error(`Failed to disable: ${error.response?.data?.error || error.message}`)
    }
  }, [loadAutonomousData])

  const emergencyEnable = useCallback(async () => {
    try {
      await axios.post('/api/v1/autonomous/emergency-enable')
      toast.success('Autonomous responses re-enabled')
      loadAutonomousData()
    } catch (error: any) {
      toast.error(`Failed to enable: ${error.response?.data?.error || error.message}`)
    }
  }, [loadAutonomousData])

  // Load autonomous data when tab changes
  useEffect(() => {
    if (activeTab === 'autonomous') {
      loadAutonomousData()
    }
  }, [activeTab, loadAutonomousData])

  // Load metrics when metrics tab is active
  useEffect(() => {
    if (activeTab === 'metrics') {
      setLoadingMetrics(true)
      axios.get('/api/v1/response/metrics', {
        params: { time_range: metricsTimeRange }
      }).then(res => {
        setResponseMetrics(res.data.metrics)
        setResponseTimeline(res.data.timeline || [])
      }).catch(() => {
        toast.error('Failed to load response metrics')
      }).finally(() => {
        setLoadingMetrics(false)
      })
    }
  }, [activeTab, metricsTimeRange])

  // -------------------------------------------------------------------
  // Handle execution with confirmation for destructive actions
  // -------------------------------------------------------------------

  const handleExecute = () => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    // Validate required params
    for (const param of selectedAction.params) {
      if (param.required && !params[param.name]) {
        toast.error(`${param.label} is required`)
        return
      }
    }

    const doExecute = () => {
      executeAction(selectedAction.id, params, selectedAgent, 0, 3)
    }

    // Require confirmation for destructive actions
    if (selectedAction.destructive) {
      setShowConfirm({
        title: `Confirm: ${selectedAction.name}`,
        message: `You are about to execute "${selectedAction.name}" on agent "${selectedAgent.hostname}". This is a destructive action and may impact the endpoint. Are you sure you want to proceed?`,
        onConfirm: () => {
          setShowConfirm(null)
          doExecute()
        },
      })
    } else {
      doExecute()
    }
  }

  // Merge tracked actions with server actions for display
  const allActions = (() => {
    const serverIds = new Set(actionList.map(a => a.id))
    const localOnly = trackedActions.filter(t => !serverIds.has(t.id))
    const merged = [
      ...localOnly.map(t => ({
        id: t.id,
        agentId: t.agentId,
        agentHostname: t.agentHostname,
        actionType: t.actionType,
        parameters: t.parameters,
        status: t.status,
        result: null as Record<string, any> | null,
        errorMessage: t.errorMessage,
        executedAt: t.executedAt,
        createdAt: t.createdAt,
        retryCount: t.retryCount,
        maxRetries: t.maxRetries,
        isTracked: true,
      })),
      ...actionList.map(a => {
        const tracked = trackedActions.find(t => t.id === a.id)
        return {
          ...a,
          agentHostname: tracked?.agentHostname || agentList.find(ag => ag.id === a.agentId)?.hostname || a.agentId,
          retryCount: tracked?.retryCount || 0,
          maxRetries: tracked?.maxRetries || 3,
          isTracked: !!tracked,
        }
      }),
    ]
    return merged
  })()

  // Tab definitions
  const tabs = [
    { id: 'actions' as const, label: 'Response Actions', icon: Shield },
    { id: 'autonomous' as const, label: 'Autonomous Response', icon: Bot },
    { id: 'metrics' as const, label: 'Metrics & Timeline', icon: Activity },
    { id: 'snapshots' as const, label: 'VSS Snapshots', icon: HardDrive },
    { id: 'recovery' as const, label: 'Ransomware Recovery', icon: FileWarning },
  ]

  return (
    <MainLayout title="Response Actions">
      <Head title="Response - Tamandua EDR" />

      {/* Confirmation Dialog */}
      {showConfirm && (
        <ConfirmDialog
          title={showConfirm.title}
          message={showConfirm.message}
          onConfirm={showConfirm.onConfirm}
          onCancel={() => setShowConfirm(null)}
        />
      )}

      {/* Tabs */}
      <div className="mb-6 border-b border-[var(--border)]">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-3 font-medium text-sm transition-colors border-b-2 -mb-px',
                activeTab === tab.id
                  ? 'text-[var(--emerald-400)] border-[var(--emerald-400)]'
                  : 'text-[var(--muted)] border-transparent hover:text-[var(--fg-2)] hover:border-[var(--border)]'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Agent Selection - shared across tabs */}
      <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6 mb-6">
        <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Target Agent</h2>

        <div className="relative">
          <button
            onClick={() => setShowAgentDropdown(!showAgentDropdown)}
            className="w-full flex items-center justify-between bg-[var(--surface-2)] hover:bg-[var(--surface-3)] border border-[var(--border)] rounded-lg px-4 py-3 text-left transition-colors"
          >
            <div className="flex items-center gap-3">
              <Monitor className="h-5 w-5 text-[var(--muted)]" />
              {selectedAgent ? (
                <div>
                  <p className="text-[var(--fg)] font-medium">{selectedAgent.hostname}</p>
                  <p className="text-xs text-[var(--muted)]">{selectedAgent.id}</p>
                </div>
              ) : (
                <span className="text-[var(--muted)]">Select an agent...</span>
              )}
            </div>
            <ChevronDown className={cn(
              'h-5 w-5 text-[var(--muted)] transition-transform',
              showAgentDropdown && 'rotate-180'
            )} />
          </button>

          {showAgentDropdown && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg shadow-xl z-10 max-h-64 overflow-auto">
              {agentList.length === 0 ? (
                <p className="px-4 py-3 text-[var(--muted)]">No agents available</p>
              ) : (
                agentList.map((agent) => (
                  <button
                    key={agent.id}
                    onClick={() => {
                      setSelectedAgent(agent)
                      setShowAgentDropdown(false)
                    }}
                    className={cn(
                      'w-full flex items-center gap-3 px-4 py-3 hover:bg-[var(--surface-3)] transition-colors',
                      selectedAgent?.id === agent.id && 'bg-[var(--surface-3)]'
                    )}
                  >
                    <div className={cn(
                      'h-2.5 w-2.5 rounded-full',
                      agent.status === 'online' ? 'bg-[var(--emerald-400)]' : 'bg-[var(--muted)]'
                    )} />
                    <div className="text-left">
                      <p className="text-[var(--fg)]">{agent.hostname}</p>
                      <p className="text-xs text-[var(--muted)]">{agent.status}</p>
                    </div>
                  </button>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'actions' && (
      <div className="grid grid-cols-3 gap-6">
        {/* Action Form */}
        <div className="col-span-2 space-y-6">
          {/* Action Selection */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Action Type</h2>

            <div className="grid grid-cols-3 gap-3">
              {actionTypes.map((action) => (
                <button
                  key={action.id}
                  onClick={() => {
                    setSelectedAction(action)
                    setParams({})
                  }}
                  className={cn(
                    'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors relative',
                    selectedAction.id === action.id
                      ? 'bg-[var(--emerald-glow)] border-[var(--emerald-500)] text-[var(--emerald-400)]'
                      : 'bg-[var(--surface-2)] border-[var(--border)] text-[var(--fg-2)] hover:bg-[var(--surface-3)]'
                  )}
                >
                  {action.destructive && (
                    <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-[var(--crit)]" title="Destructive action" />
                  )}
                  <action.icon className="h-6 w-6" />
                  <span className="text-sm font-medium">{action.name}</span>
                </button>
              ))}
            </div>

            <div className="mt-4 flex items-center gap-2">
              <p className="text-sm text-[var(--muted)]">{selectedAction.description}</p>
              {selectedAction.destructive && (
                <span className="badge-sentinel badge-sentinel-error">
                  Destructive
                </span>
              )}
            </div>
          </div>

          {/* Action Parameters */}
          {selectedAction.params.length > 0 && (
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
              <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Parameters</h2>

              <div className="space-y-4">
                {selectedAction.params.map((param) => (
                  <div key={param.name}>
                    <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">
                      {param.label}
                      {param.required && <span className="text-[var(--crit)] ml-1">*</span>}
                    </label>

                    {param.type === 'boolean' ? (
                      <label className="flex items-center gap-2 cursor-pointer">
                        <Checkbox
                          checked={params[param.name] ?? param.default ?? false}
                          onCheckedChange={(checked) => setParams({ ...params, [param.name]: checked })}
                        />
                        <span className="text-sm text-[var(--muted)]">Enable</span>
                      </label>
                    ) : param.type === 'select' ? (
                      <select
                        value={params[param.name] ?? param.default ?? ''}
                        onChange={(e) => setParams({ ...params, [param.name]: e.target.value })}
                        className="input-sentinel"
                      >
                        {param.options?.map((opt) => (
                          <option key={opt} value={opt}>{opt}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type={param.type === 'number' ? 'number' : 'text'}
                        value={params[param.name] ?? ''}
                        onChange={(e) => setParams({
                          ...params,
                          [param.name]: param.type === 'number' ? parseInt(e.target.value) || 0 : e.target.value
                        })}
                        placeholder={`Enter ${param.label.toLowerCase()}`}
                        className="input-sentinel"
                      />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Execute Button */}
          <button
            onClick={handleExecute}
            disabled={!selectedAgent || isExecuting}
            className={cn(
              'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium transition-colors',
              selectedAgent && !isExecuting
                ? selectedAction.destructive
                  ? 'btn-sentinel btn-sentinel-danger'
                  : 'btn-sentinel btn-sentinel-primary'
                : 'bg-[var(--surface-2)] text-[var(--muted)] cursor-not-allowed'
            )}
          >
            {isExecuting ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                Executing...
              </>
            ) : (
              <>
                <Play className="h-5 w-5" />
                {selectedAction.destructive ? 'Execute (Requires Confirmation)' : 'Execute Action'}
              </>
            )}
          </button>
        </div>

        {/* Action History */}
        <div className="space-y-6">
          {/* Active/Tracked Actions */}
          {trackedActions.filter(a => a.status === 'pending' || a.status === 'executing').length > 0 && (
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--med)]/30">
              <div className="p-4 border-b border-[var(--border)]">
                <div className="flex items-center gap-2">
                  <Loader2 className="h-4 w-4 text-[var(--med)] animate-spin" />
                  <h2 className="text-lg font-semibold text-[var(--fg)]">In Progress</h2>
                </div>
              </div>
              <div className="divide-y divide-[var(--border)]">
                {trackedActions
                  .filter(a => a.status === 'pending' || a.status === 'executing')
                  .map((action) => {
                    const actionType = actionTypes.find(a => a.id === action.actionType)
                    const Icon = actionType?.icon || Shield

                    return (
                      <div key={action.id} className="p-4">
                        <div className="flex items-start gap-3">
                          <div className={cn('p-2 rounded-lg', statusColors[action.status])}>
                            <Icon className="h-4 w-4" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium text-[var(--fg)]">
                                {actionType?.name || action.actionType}
                              </p>
                              <Loader2 className="h-3 w-3 text-[var(--med)] animate-spin" />
                            </div>
                            <p className="text-xs text-[var(--muted)] truncate mt-0.5">
                              {action.agentHostname}
                            </p>
                            <div className="flex items-center gap-2 mt-1">
                              <span className={cn('px-1.5 py-0.5 rounded text-xs', statusColors[action.status])}>
                                {action.status}
                              </span>
                              {action.retryCount > 0 && (
                                <span className="text-xs text-[var(--subtle)]">
                                  Retry {action.retryCount}/{action.maxRetries}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })}
              </div>
            </div>
          )}

          {/* Recent Actions History */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Action History</h2>
              <button
                onClick={() => router.reload({ only: ['recentActions'] })}
                className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                title="Refresh"
              >
                <RefreshCw className="h-4 w-4 text-[var(--muted)]" />
              </button>
            </div>

            <div className="divide-y divide-[var(--border)] max-h-[700px] overflow-auto">
              {allActions.length === 0 ? (
                <div className="p-8 text-center text-[var(--subtle)]">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No recent actions</p>
                </div>
              ) : (
                allActions.map((action) => {
                  const actionType = actionTypes.find((a) => a.id === action.actionType)
                  const Icon = actionType?.icon || Shield
                  const canUndo = action.status === 'success' && UNDO_MAP[action.actionType]
                  const canRetry = action.status === 'failed'

                  return (
                    <div key={action.id} className="p-4">
                      <div className="flex items-start gap-3">
                        <div className={cn('p-2 rounded-lg', statusColors[action.status] || statusColors.pending)}>
                          <Icon className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-medium text-[var(--fg)]">
                              {actionType?.name || action.actionType}
                            </p>
                            <span className={cn(
                              'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs',
                              statusColors[action.status] || statusColors.pending
                            )}>
                              <StatusIcon status={action.status} />
                              {action.status}
                            </span>
                          </div>
                          <p className="text-xs text-[var(--muted)] truncate mt-0.5">
                            {action.agentHostname || `Agent: ${action.agentId}`}
                          </p>
                          <div className="flex items-center gap-3 mt-1">
                            <p className="text-xs text-[var(--subtle)]">
                              {formatDate(action.createdAt)}
                            </p>
                            {action.executedAt && (
                              <p className="text-xs text-[var(--subtle)]">
                                Completed: {formatDate(action.executedAt)}
                              </p>
                            )}
                          </div>
                          {action.retryCount > 0 && (
                            <p className="text-xs text-[var(--high)] mt-0.5">
                              Retried {action.retryCount} time{action.retryCount > 1 ? 's' : ''}
                            </p>
                          )}
                          {action.errorMessage && (
                            <p className="text-xs text-[var(--crit)] mt-1 bg-[var(--crit-bg)] rounded px-2 py-1">
                              {action.errorMessage}
                            </p>
                          )}

                          {/* Action buttons: Retry / Undo */}
                          {(canRetry || canUndo) && (
                            <div className="flex items-center gap-2 mt-2">
                              {canRetry && (
                                <button
                                  onClick={() => handleRetry({
                                    id: action.id,
                                    actionType: action.actionType,
                                    agentId: action.agentId,
                                    agentHostname: action.agentHostname || '',
                                    status: 'failed',
                                    errorMessage: action.errorMessage,
                                    retryCount: 0,
                                    maxRetries: action.maxRetries,
                                    createdAt: action.createdAt,
                                    executedAt: action.executedAt,
                                    parameters: action.parameters || {},
                                  })}
                                  className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-[var(--high-bg)] text-[var(--high)] hover:opacity-80 transition-colors"
                                >
                                  <RotateCcw className="h-3 w-3" />
                                  Retry
                                </button>
                              )}
                              {canUndo && (
                                <button
                                  onClick={() => handleUndo({
                                    id: action.id,
                                    actionType: action.actionType,
                                    agentId: action.agentId,
                                    agentHostname: action.agentHostname || '',
                                    status: 'success',
                                    errorMessage: null,
                                    retryCount: 0,
                                    maxRetries: 3,
                                    createdAt: action.createdAt,
                                    executedAt: action.executedAt,
                                    parameters: action.parameters || {},
                                  })}
                                  className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-[var(--med-bg)] text-[var(--med)] hover:opacity-80 transition-colors"
                                >
                                  <Undo2 className="h-3 w-3" />
                                  Undo
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>
      )}

      {/* Autonomous Response Tab */}
      {activeTab === 'autonomous' && (
        <div className="space-y-6">
          {/* Sub-tabs for autonomous response */}
          <div className="flex items-center gap-2 border-b border-[var(--border)] pb-4">
            {[
              { id: 'recommendations' as const, label: 'Recommendations', icon: Zap },
              { id: 'rules' as const, label: 'Rules', icon: FileText },
              { id: 'learning' as const, label: 'Learning', icon: Brain },
              { id: 'settings' as const, label: 'Settings', icon: Settings },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setAutonomousSubTab(tab.id)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  autonomousSubTab === tab.id
                    ? 'btn-sentinel btn-sentinel-primary'
                    : 'btn-sentinel btn-sentinel-secondary'
                )}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}

            {/* Emergency Controls */}
            <div className="ml-auto flex items-center gap-2">
              {autonomousSettings?.autonomous_enabled ? (
                <button
                  onClick={() => {
                    setShowConfirm({
                      title: 'Emergency Disable',
                      message: 'This will immediately disable all autonomous responses. Are you sure?',
                      onConfirm: () => {
                        setShowConfirm(null)
                        emergencyDisable('Manual emergency disable')
                      }
                    })
                  }}
                  className="flex items-center gap-2 px-3 py-2 bg-[var(--crit-bg)] hover:opacity-80 text-[var(--crit)] rounded-lg text-sm font-medium"
                >
                  <AlertTriangle className="h-4 w-4" />
                  Emergency Disable
                </button>
              ) : (
                <button
                  onClick={emergencyEnable}
                  className="flex items-center gap-2 px-3 py-2 bg-[var(--emerald-glow)] hover:opacity-80 text-[var(--emerald-400)] rounded-lg text-sm font-medium"
                >
                  <CheckCircle className="h-4 w-4" />
                  Re-enable
                </button>
              )}
            </div>
          </div>

          {loadingAutonomous ? (
            <div className="text-center py-12">
              <Loader2 className="h-8 w-8 mx-auto mb-4 text-[var(--emerald-400)] animate-spin" />
              <p className="text-[var(--muted)]">Loading autonomous response data...</p>
            </div>
          ) : (
            <>
              {/* Recommendations Sub-tab */}
              {autonomousSubTab === 'recommendations' && (
                <div className="grid grid-cols-3 gap-6">
                  {/* Stats Cards */}
                  <div className="col-span-3 grid grid-cols-4 gap-4">
                    <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[var(--high-bg)]">
                          <Clock className="h-5 w-5 text-[var(--high)]" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-[var(--fg)]">{pendingRecommendations.length}</p>
                          <p className="text-sm text-[var(--muted)]">Pending</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                          <CheckCircle className="h-5 w-5 text-[var(--emerald-400)]" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-[var(--fg)]">{learningStats?.total_decisions || 0}</p>
                          <p className="text-sm text-[var(--muted)]">Total Decisions</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[var(--med-bg)]">
                          <TrendingUp className="h-5 w-5 text-[var(--med)]" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-[var(--fg)]">{((learningStats?.approval_rate || 0) * 100).toFixed(0)}%</p>
                          <p className="text-sm text-[var(--muted)]">Approval Rate</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                          <Activity className="h-5 w-5 text-[var(--emerald-400)]" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-[var(--fg)]">{autonomousRules.filter(r => r.enabled).length}</p>
                          <p className="text-sm text-[var(--muted)]">Active Rules</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {activeRecommendationExecutionIds.size > 0 && (
                    <div className="col-span-3 rounded-xl border border-[var(--med)]/40 bg-[var(--med-bg)] p-4">
                      <div className="flex items-start gap-3">
                        <Loader2 className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-[var(--med)]" />
                        <div className="min-w-0 flex-1">
                          <h2 className="text-sm font-semibold text-[var(--fg)]">
                            Response executions in progress
                          </h2>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            Queued or executing — status is being monitored and will resume after navigation.
                          </p>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {Array.from(activeRecommendationExecutionIds).map(recommendationId => (
                              <span
                                key={recommendationId}
                                className="rounded-md border border-[var(--med)]/30 bg-[var(--surface)] px-2 py-1 font-mono text-xs text-[var(--fg-2)]"
                                title={recommendationId}
                              >
                                {recommendationId.slice(0, 12)}{recommendationId.length > 12 ? '…' : ''}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {pausedRecommendationExecutionIds.size > 0 && (
                    <div className="col-span-3 rounded-xl border border-[var(--warn)]/40 bg-[var(--warn-bg)] p-4">
                      <div className="flex items-start gap-3">
                        <Clock className="mt-0.5 h-5 w-5 shrink-0 text-[var(--warn)]" />
                        <div className="min-w-0 flex-1">
                          <h2 className="text-sm font-semibold text-[var(--fg)]">
                            Response execution monitoring paused
                          </h2>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            Status URL is still stored locally. Refresh or revisit this page to resume polling.
                          </p>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {Array.from(pausedRecommendationExecutionIds).map(recommendationId => (
                              <span
                                key={recommendationId}
                                className="rounded-md border border-[var(--warn)]/30 bg-[var(--surface)] px-2 py-1 font-mono text-xs text-[var(--fg-2)]"
                                title={recommendationId}
                              >
                                {recommendationId.slice(0, 12)}{recommendationId.length > 12 ? '…' : ''}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Pending Recommendations */}
                  <div className="col-span-3 bg-[var(--surface)] rounded-xl border border-[var(--border)]">
                    <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
                      <h2 className="text-lg font-semibold text-[var(--fg)]">Pending Recommendations</h2>
                      <button
                        onClick={loadAutonomousData}
                        className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                      >
                        <RefreshCw className="h-4 w-4 text-[var(--muted)]" />
                      </button>
                    </div>

                    {pendingRecommendations.length === 0 ? (
                      <div className="p-8 text-center text-[var(--muted)]">
                        <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No pending recommendations</p>
                        <p className="text-sm mt-2">All response recommendations have been reviewed</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-[var(--border)]">
                        {pendingRecommendations.map((rec) => (
                          <div key={rec.id} className="p-4">
                            <div className="flex items-start gap-4">
                              <div className={cn(
                                'p-2 rounded-lg',
                                rec.severity === 'critical' ? 'bg-[var(--crit-bg)]' :
                                rec.severity === 'high' ? 'bg-[var(--high-bg)]' :
                                'bg-[var(--high-bg)]'
                              )}>
                                <AlertTriangle className={cn(
                                  'h-5 w-5',
                                  rec.severity === 'critical' ? 'text-[var(--crit)]' :
                                  rec.severity === 'high' ? 'text-[var(--high)]' :
                                  'text-[var(--high)]'
                                )} />
                              </div>
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className={cn(
                                    'badge-sentinel',
                                    rec.severity === 'critical' ? 'badge-sentinel-critical' :
                                    rec.severity === 'high' ? 'badge-sentinel-high' :
                                    'badge-sentinel-warning'
                                  )}>
                                    {rec.severity}
                                  </span>
                                  <span className="text-sm text-[var(--muted)]">
                                    Confidence: {rec.confidence_score.toFixed(0)}%
                                  </span>
                                  <span className="text-sm text-[var(--muted)]">
                                    Asset: {rec.criticality_level}
                                  </span>
                                  {rec.auto_execute_eligible && (
                                    <span className="badge-sentinel badge-sentinel-success">
                                      Auto-execute eligible
                                    </span>
                                  )}
                                </div>

                                <p className="text-sm text-[var(--fg-2)] mb-2">Alert: {rec.alert_id.slice(0, 8)}...</p>

                                <div className="flex flex-wrap gap-2 mb-3">
                                  {rec.suggested_actions.map((action, idx) => (
                                    <span key={idx} className="px-2 py-1 rounded text-xs bg-[var(--surface-2)] text-[var(--fg-2)]">
                                      {action.type.replace(/_/g, ' ')}
                                      {action.risk_score > 0.5 && (
                                        <span className="ml-1 text-[var(--crit)]">High risk</span>
                                      )}
                                    </span>
                                  ))}
                                </div>

                                <p className="text-xs text-[var(--subtle)] mb-3">{rec.justification}</p>

                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => approveRecommendation(rec.id)}
                                    disabled={processingRecommendationIds.has(rec.id)}
                                    className="btn-sentinel btn-sentinel-primary btn-sentinel-sm"
                                  >
                                    {processingRecommendationIds.has(rec.id) ? (
                                      <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                      <ThumbsUp className="h-4 w-4" />
                                    )}
                                    Approve
                                  </button>
                                  <button
                                    onClick={() => {
                                      const reason = prompt('Rejection reason:')
                                      if (reason) rejectRecommendation(rec.id, reason)
                                    }}
                                    disabled={processingRecommendationIds.has(rec.id)}
                                    className="flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-[var(--crit-bg)] text-[var(--crit)] hover:opacity-80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                  >
                                    {processingRecommendationIds.has(rec.id) ? (
                                      <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                      <ThumbsDown className="h-4 w-4" />
                                    )}
                                    Reject
                                  </button>
                                  <button
                                    className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                                  >
                                    <Eye className="h-4 w-4" />
                                    View Alert
                                  </button>
                                </div>
                              </div>
                              <div className="text-right text-xs text-[var(--subtle)]">
                                <p>{formatDate(rec.created_at)}</p>
                                <p className="text-[var(--high)]">Expires: {formatDate(rec.expires_at)}</p>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Rules Sub-tab */}
              {autonomousSubTab === 'rules' && (
                <div className="grid grid-cols-3 gap-6">
                  {/* Rules List */}
                  <div className="col-span-2 bg-[var(--surface)] rounded-xl border border-[var(--border)]">
                    <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
                      <h2 className="text-lg font-semibold text-[var(--fg)]">Response Rules</h2>
                      <button
                        onClick={() => setShowRuleEditor(true)}
                        className="btn-sentinel btn-sentinel-primary btn-sentinel-sm"
                      >
                        <Plus className="h-4 w-4" />
                        New Rule
                      </button>
                    </div>

                    {autonomousRules.length === 0 ? (
                      <div className="p-8 text-center text-[var(--muted)]">
                        <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No rules configured</p>
                        <p className="text-sm mt-2">Create a rule or use a template to get started</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-[var(--border)]">
                        {autonomousRules.map((rule) => (
                          <div key={rule.id} className="p-4">
                            <div className="flex items-start gap-4">
                              <button
                                onClick={() => toggleRule(rule.id, !rule.enabled)}
                                className="mt-1"
                              >
                                {rule.enabled ? (
                                  <ToggleRight className="h-6 w-6 text-[var(--emerald-400)]" />
                                ) : (
                                  <ToggleLeft className="h-6 w-6 text-[var(--muted)]" />
                                )}
                              </button>
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-1">
                                  <h3 className="font-medium text-[var(--fg)]">{rule.name}</h3>
                                  <span className="badge-sentinel badge-sentinel-default">
                                    Priority: {rule.priority}
                                  </span>
                                  {rule.auto_execute && (
                                    <span className="badge-sentinel badge-sentinel-warning">
                                      Auto-execute
                                    </span>
                                  )}
                                </div>
                                <p className="text-sm text-[var(--muted)] mb-2">{rule.description}</p>
                                <div className="flex flex-wrap gap-2 mb-2">
                                  {rule.actions.map((action, idx) => (
                                    <span key={idx} className="badge-sentinel badge-sentinel-success">
                                      {action.type.replace(/_/g, ' ')}
                                    </span>
                                  ))}
                                </div>
                                <div className="flex items-center gap-4 text-xs text-[var(--subtle)]">
                                  <span>Matches: {rule.match_count}</span>
                                  <span>Executions: {rule.execution_count}</span>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => {
                                    setEditingRule(rule)
                                    setShowRuleEditor(true)
                                  }}
                                  className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                                >
                                  <Edit className="h-4 w-4 text-[var(--muted)]" />
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Templates */}
                  <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)]">
                    <div className="p-4 border-b border-[var(--border)]">
                      <h2 className="text-lg font-semibold text-[var(--fg)]">Rule Templates</h2>
                    </div>
                    <div className="p-4 space-y-3">
                      {ruleTemplates.map((template) => (
                        <div key={template.id} className="p-3 bg-[var(--surface-2)] rounded-lg border border-[var(--border)]">
                          <h4 className="font-medium text-[var(--fg)] text-sm mb-1">{template.name}</h4>
                          <p className="text-xs text-[var(--muted)] mb-2">{template.description}</p>
                          <button
                            onClick={() => cloneTemplate(template.id)}
                            className="btn-sentinel btn-sentinel-outline btn-sentinel-sm"
                          >
                            <Copy className="h-3 w-3" />
                            Use Template
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Learning Sub-tab */}
              {autonomousSubTab === 'learning' && (
                <div className="grid grid-cols-2 gap-6">
                  {/* Learning Stats */}
                  <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
                    <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Learning Statistics</h2>
                    {learningStats ? (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--muted)]">Total Analyst Decisions</span>
                          <span className="text-[var(--fg)] font-medium">{learningStats.total_decisions}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--muted)]">Approval Rate</span>
                          <span className="text-[var(--fg)] font-medium">{(learningStats.approval_rate * 100).toFixed(1)}%</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--muted)]">Unique Analysts</span>
                          <span className="text-[var(--fg)] font-medium">{learningStats.unique_analysts}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--muted)]">Model Trained</span>
                          <span className={cn(
                            'font-medium',
                            learningStats.model_trained ? 'text-[var(--emerald-400)]' : 'text-[var(--high)]'
                          )}>
                            {learningStats.model_trained ? 'Yes' : 'Not Yet'}
                          </span>
                        </div>
                        {learningStats.last_model_update && (
                          <div className="flex items-center justify-between">
                            <span className="text-[var(--muted)]">Last Model Update</span>
                            <span className="text-[var(--fg)] font-medium text-sm">
                              {formatDate(learningStats.last_model_update)}
                            </span>
                          </div>
                        )}
                        <div className="pt-4 border-t border-[var(--border)]">
                          <p className="text-sm text-[var(--muted)] mb-2">
                            The system learns from analyst decisions to improve future recommendations.
                            More decisions lead to better predictions.
                          </p>
                          <div className="w-full bg-[var(--surface-2)] rounded-full h-2">
                            <div
                              className="bg-[var(--emerald-500)] h-2 rounded-full"
                              style={{ width: `${Math.min((learningStats.total_decisions / 100) * 100, 100)}%` }}
                            />
                          </div>
                          <p className="text-xs text-[var(--subtle)] mt-1">
                            {learningStats.total_decisions}/100 decisions for optimal learning
                          </p>
                        </div>
                      </div>
                    ) : (
                      <p className="text-[var(--muted)]">No learning data available</p>
                    )}
                  </div>

                  {/* Model Info */}
                  <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
                    <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">ML Model</h2>
                    <div className="space-y-4">
                      <div className="p-4 bg-[var(--surface-2)] rounded-lg">
                        <div className="flex items-center gap-3 mb-2">
                          <Brain className="h-5 w-5 text-[var(--emerald-400)]" />
                          <h3 className="font-medium text-[var(--fg)]">Response Recommendation Model</h3>
                        </div>
                        <p className="text-sm text-[var(--muted)]">
                          Learns from analyst approvals/rejections to predict which response actions
                          are most likely to be appropriate for different alert types.
                        </p>
                      </div>

                      <div className="space-y-2">
                        <h4 className="text-sm font-medium text-[var(--fg-2)]">Features Used:</h4>
                        <ul className="text-sm text-[var(--muted)] space-y-1">
                          <li>- Alert severity</li>
                          <li>- Detection confidence</li>
                          <li>- Asset criticality</li>
                          <li>- MITRE ATT&CK techniques</li>
                          <li>- Historical approval patterns</li>
                          <li>- Time of day / business hours</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Settings Sub-tab */}
              {autonomousSubTab === 'settings' && autonomousSettings && (
                <div className="grid grid-cols-2 gap-6">
                  <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
                    <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">General Settings</h2>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium text-[var(--fg)]">Autonomous Responses</h4>
                          <p className="text-sm text-[var(--muted)]">Enable automatic response execution</p>
                        </div>
                        <button
                          onClick={() => updateSettings({ autonomous_enabled: !autonomousSettings.autonomous_enabled })}
                        >
                          {autonomousSettings.autonomous_enabled ? (
                            <ToggleRight className="h-8 w-8 text-[var(--emerald-400)]" />
                          ) : (
                            <ToggleLeft className="h-8 w-8 text-[var(--muted)]" />
                          )}
                        </button>
                      </div>

                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium text-[var(--fg)]">Critical Asset Protection</h4>
                          <p className="text-sm text-[var(--muted)]">Require approval for critical assets</p>
                        </div>
                        <button
                          onClick={() => updateSettings({ critical_asset_protection: !autonomousSettings.critical_asset_protection })}
                        >
                          {autonomousSettings.critical_asset_protection ? (
                            <ToggleRight className="h-8 w-8 text-[var(--emerald-400)]" />
                          ) : (
                            <ToggleLeft className="h-8 w-8 text-[var(--muted)]" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
                    <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Rate Limits</h2>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-[var(--fg-2)] mb-2">
                          Max Actions per Minute
                        </label>
                        <input
                          type="number"
                          value={autonomousSettings.max_actions_per_minute}
                          onChange={(e) => updateSettings({ max_actions_per_minute: parseInt(e.target.value) })}
                          className="input-sentinel"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-[var(--fg-2)] mb-2">
                          Max Actions per Hour
                        </label>
                        <input
                          type="number"
                          value={autonomousSettings.max_actions_per_hour}
                          onChange={(e) => updateSettings({ max_actions_per_hour: parseInt(e.target.value) })}
                          className="input-sentinel"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-[var(--fg-2)] mb-2">
                          Minimum Confidence for Auto-execute (%)
                        </label>
                        <input
                          type="number"
                          min="50"
                          max="100"
                          value={autonomousSettings.min_confidence_for_auto}
                          onChange={(e) => updateSettings({ min_confidence_for_auto: parseInt(e.target.value) })}
                          className="input-sentinel"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Snapshots Tab */}
      {activeTab === 'snapshots' && (
        <div className="space-y-6">
          {/* Volume Selection & Actions */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Volume Shadow Copy Snapshots</h2>
              <div className="flex items-center gap-3">
                <select
                  value={selectedVolume}
                  onChange={(e) => setSelectedVolume(e.target.value)}
                  className="input-sentinel w-auto"
                >
                  <option value="C:">C: Drive</option>
                  <option value="D:">D: Drive</option>
                  <option value="E:">E: Drive</option>
                </select>
                <button
                  onClick={loadSnapshots}
                  disabled={!selectedAgent || loadingSnapshots}
                  className="btn-sentinel btn-sentinel-secondary"
                >
                  {loadingSnapshots ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}
                  Refresh
                </button>
                <button
                  onClick={createSnapshot}
                  disabled={!selectedAgent || creatingSnapshot}
                  className="btn-sentinel btn-sentinel-primary"
                >
                  {creatingSnapshot ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4" />
                  )}
                  Create Snapshot
                </button>
              </div>
            </div>

            {!selectedAgent ? (
              <div className="text-center py-12 text-[var(--muted)]">
                <HardDrive className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Select an agent to view snapshots</p>
              </div>
            ) : loadingSnapshots ? (
              <div className="text-center py-12">
                <Loader2 className="h-8 w-8 mx-auto mb-4 text-[var(--emerald-400)] animate-spin" />
                <p className="text-[var(--muted)]">Loading snapshots...</p>
              </div>
            ) : snapshots.length === 0 ? (
              <div className="text-center py-12 text-[var(--muted)]">
                <HardDrive className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No snapshots found for volume {selectedVolume}</p>
                <p className="text-sm mt-2">Create a snapshot to enable file rollback capabilities</p>
              </div>
            ) : (
              <div className="space-y-3">
                {snapshots.map((snapshot) => (
                  <div
                    key={snapshot.id}
                    className="flex items-center justify-between p-4 bg-[var(--surface-2)] rounded-lg border border-[var(--border)]"
                  >
                    <div className="flex items-center gap-4">
                      <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                        <HardDrive className="h-5 w-5 text-[var(--emerald-400)]" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-[var(--fg)] truncate max-w-md" title={snapshot.id}>
                          {snapshot.id.slice(0, 8)}...{snapshot.id.slice(-8)}
                        </p>
                        <div className="flex items-center gap-4 mt-1 text-xs text-[var(--muted)]">
                          <span className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {snapshot.created_at ? new Date(snapshot.created_at * 1000).toLocaleString() : 'Unknown'}
                          </span>
                          <span>{snapshot.volume}</span>
                          {snapshot.accessible && (
                            <span className="text-[var(--emerald-400)]">Accessible</span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setShowConfirm({
                            title: 'Delete Snapshot',
                            message: `Are you sure you want to delete this snapshot? This action cannot be undone.`,
                            onConfirm: () => {
                              setShowConfirm(null)
                              deleteSnapshot(snapshot.id)
                            }
                          })
                        }}
                        className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon text-[var(--crit)] hover:bg-[var(--crit-bg)]"
                        title="Delete snapshot"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Ransomware Recovery Tab */}
      {activeTab === 'recovery' && (
        <div className="grid grid-cols-2 gap-6">
          {/* Scan Configuration */}
          <div className="space-y-6">
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
              <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Scan for Encrypted Files</h2>
              <p className="text-sm text-[var(--muted)] mb-4">
                Scan the agent for files that appear to be encrypted by ransomware, based on file extensions and entropy analysis.
              </p>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">
                    Scan Path
                  </label>
                  <input
                    type="text"
                    value={scanPath}
                    onChange={(e) => setScanPath(e.target.value)}
                    placeholder="C:\Users"
                    className="input-sentinel"
                  />
                </div>

                <button
                  onClick={scanForEncryptedFiles}
                  disabled={!selectedAgent || scanningFiles}
                  className="btn-sentinel btn-sentinel-primary w-full"
                >
                  {scanningFiles ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4" />
                      Scan for Encrypted Files
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Remediation */}
            {encryptedFiles.length > 0 && (
              <div className="bg-[var(--surface)] rounded-xl border border-[var(--crit)]/30 p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 rounded-lg bg-[var(--crit-bg)]">
                    <AlertTriangle className="h-5 w-5 text-[var(--crit)]" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-[var(--fg)]">Ransomware Recovery</h2>
                    <p className="text-sm text-[var(--crit)]">{encryptedFiles.length} encrypted files detected</p>
                  </div>
                </div>

                <p className="text-sm text-[var(--muted)] mb-4">
                  Attempt to restore encrypted files from VSS snapshots. This will find the most recent unencrypted version of each file and restore it.
                </p>

                <button
                  onClick={() => {
                    setShowConfirm({
                      title: 'Start Ransomware Remediation',
                      message: `This will attempt to restore ${encryptedFiles.length} encrypted files from VSS snapshots. Original encrypted files will be backed up. Are you sure you want to proceed?`,
                      onConfirm: () => {
                        setShowConfirm(null)
                        startRemediation()
                      }
                    })
                  }}
                  disabled={!selectedAgent || remediating}
                  className="btn-sentinel btn-sentinel-danger w-full"
                >
                  {remediating ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Remediating...
                    </>
                  ) : (
                    <>
                      <RotateCw className="h-4 w-4" />
                      Start Recovery
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Remediation Result */}
            {remediationResult && (
              <div className="bg-[var(--surface)] rounded-xl border border-[var(--emerald-500)]/30 p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                    <CheckCircle className="h-5 w-5 text-[var(--emerald-400)]" />
                  </div>
                  <h2 className="text-lg font-semibold text-[var(--fg)]">Remediation Complete</h2>
                </div>

                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div className="bg-[var(--surface-2)] rounded-lg p-3">
                    <p className="text-2xl font-bold text-[var(--emerald-400)]">{remediationResult.restored_count || 0}</p>
                    <p className="text-sm text-[var(--muted)]">Files Restored</p>
                  </div>
                  <div className="bg-[var(--surface-2)] rounded-lg p-3">
                    <p className="text-2xl font-bold text-[var(--crit)]">{remediationResult.failed_count || 0}</p>
                    <p className="text-sm text-[var(--muted)]">Failed</p>
                  </div>
                  <div className="bg-[var(--surface-2)] rounded-lg p-3">
                    <p className="text-2xl font-bold text-[var(--muted)]">{remediationResult.skipped_count || 0}</p>
                    <p className="text-sm text-[var(--muted)]">Skipped</p>
                  </div>
                </div>

                <div className="text-sm text-[var(--muted)]">
                  <p>Bytes restored: {formatBytes(remediationResult.bytes_restored || 0)}</p>
                  <p>Duration: {remediationResult.duration_ms}ms</p>
                </div>
              </div>
            )}
          </div>

          {/* Encrypted Files List */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-4 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Detected Encrypted Files</h2>
            </div>

            <div className="max-h-[600px] overflow-auto">
              {!selectedAgent ? (
                <div className="p-8 text-center text-[var(--muted)]">
                  <FileWarning className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select an agent to scan</p>
                </div>
              ) : encryptedFiles.length === 0 ? (
                <div className="p-8 text-center text-[var(--muted)]">
                  <FileWarning className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No encrypted files detected</p>
                  <p className="text-sm mt-2">Run a scan to detect ransomware-encrypted files</p>
                </div>
              ) : (
                <div className="divide-y divide-[var(--border)]">
                  {encryptedFiles.map((file, index) => (
                    <div key={index} className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-[var(--crit-bg)]">
                          <FileWarning className="h-4 w-4 text-[var(--crit)]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-[var(--fg)] truncate" title={file.path}>
                            {file.path.split('\\').pop() || file.path}
                          </p>
                          <p className="text-xs text-[var(--subtle)] truncate mt-0.5" title={file.path}>
                            {file.path}
                          </p>
                          <div className="flex items-center gap-3 mt-1 text-xs">
                            <span className="text-[var(--crit)]">
                              {file.ransomware_extension}
                            </span>
                            {file.original_extension && (
                              <span className="text-[var(--muted)]">
                                Original: {file.original_extension}
                              </span>
                            )}
                            <span className="text-[var(--subtle)]">
                              Entropy: {file.entropy.toFixed(2)}
                            </span>
                            <span className="text-[var(--subtle)]">
                              {formatBytes(file.size)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Response Metrics Tab */}
      {activeTab === 'metrics' && (
        <div className="space-y-6">
          {/* Time Range Selector */}
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-[var(--fg)]">Response Metrics & Timeline</h2>
            <div className="flex items-center gap-2">
              {(['1h', '24h', '7d', '30d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setMetricsTimeRange(range)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                    metricsTimeRange === range
                      ? 'btn-sentinel btn-sentinel-primary'
                      : 'btn-sentinel btn-sentinel-secondary'
                  )}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>

          {/* Metrics Overview Cards */}
          <div className="grid grid-cols-5 gap-4">
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                  <Zap className="h-5 w-5 text-[var(--emerald-400)]" />
                </div>
                <span className="text-sm text-[var(--muted)]">Total Responses</span>
              </div>
              <p className="text-2xl font-bold text-[var(--fg)]">
                {responseMetrics?.total_responses || 0}
              </p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                This hour: {responseMetrics?.current_hour?.responses || 0}
              </p>
            </div>

            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-[var(--emerald-glow)]">
                  <CheckCircle className="h-5 w-5 text-[var(--emerald-400)]" />
                </div>
                <span className="text-sm text-[var(--muted)]">Success Rate</span>
              </div>
              <p className="text-2xl font-bold text-[var(--emerald-400)]">
                {responseMetrics?.total_responses
                  ? ((responseMetrics.successful_responses / responseMetrics.total_responses) * 100).toFixed(1)
                  : 0}%
              </p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                {responseMetrics?.successful_responses || 0} successful
              </p>
            </div>

            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-[var(--high-bg)]">
                  <Clock className="h-5 w-5 text-[var(--high)]" />
                </div>
                <span className="text-sm text-[var(--muted)]">Avg Response Time</span>
              </div>
              <p className="text-2xl font-bold text-[var(--high)]">
                {responseMetrics?.avg_response_time_ms?.toFixed(0) || 0}ms
              </p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                Min: {responseMetrics?.min_response_time_ms || 0}ms / Max: {responseMetrics?.max_response_time_ms || 0}ms
              </p>
            </div>

            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-[var(--med-bg)]">
                  <TrendingUp className="h-5 w-5 text-[var(--med)]" />
                </div>
                <span className="text-sm text-[var(--muted)]">MTTR</span>
              </div>
              <p className="text-2xl font-bold text-[var(--med)]">
                {responseMetrics?.mttr_minutes?.toFixed(2) || 0} min
              </p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                Mean Time To Respond
              </p>
            </div>

            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(168, 85, 247, 0.2)' }}>
                  <Bot className="h-5 w-5 text-purple-400" />
                </div>
                <span className="text-sm text-[var(--muted)]">Automated</span>
              </div>
              <p className="text-2xl font-bold text-purple-400">
                {responseMetrics?.current_hour?.automated || 0}
              </p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                Autonomous responses
              </p>
            </div>
          </div>

          {/* Response Type Breakdown */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
              <h3 className="text-sm font-semibold text-[var(--fg)] mb-4">Response Actions by Type</h3>
              <div className="space-y-3">
                {responseMetrics?.responses_by_type && Object.entries(responseMetrics.responses_by_type).length > 0 ? (
                  Object.entries(responseMetrics.responses_by_type)
                    .sort(([, a], [, b]) => b - a)
                    .map(([action, count]) => {
                      const total = Object.values(responseMetrics.responses_by_type).reduce((a, b) => a + b, 0)
                      const percentage = ((count / total) * 100).toFixed(1)
                      return (
                        <div key={action} className="flex items-center gap-3">
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm text-[var(--fg-2)]">{action.replace(/_/g, ' ')}</span>
                              <span className="text-sm text-[var(--muted)]">{count} ({percentage}%)</span>
                            </div>
                            <div className="h-2 bg-[var(--surface-2)] rounded-full overflow-hidden">
                              <div
                                className="h-full bg-[var(--emerald-500)] rounded-full transition-all"
                                style={{ width: `${percentage}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      )
                    })
                ) : (
                  <p className="text-sm text-[var(--muted)]">No response data available</p>
                )}
              </div>
            </div>

            {/* Sub-second Response Indicator */}
            <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
              <h3 className="text-sm font-semibold text-[var(--fg)] mb-4">Sub-Second Response Performance</h3>
              <div className="flex items-center justify-center py-8">
                <div className="relative">
                  <svg className="w-32 h-32 transform -rotate-90">
                    <circle
                      cx="64"
                      cy="64"
                      r="56"
                      stroke="var(--surface-3)"
                      strokeWidth="8"
                      fill="none"
                    />
                    <circle
                      cx="64"
                      cy="64"
                      r="56"
                      stroke={responseMetrics?.avg_response_time_ms && responseMetrics.avg_response_time_ms < 1000 ? 'var(--emerald-400)' : 'var(--high)'}
                      strokeWidth="8"
                      fill="none"
                      strokeDasharray={`${(responseMetrics?.avg_response_time_ms || 0) < 1000 ? 352 : Math.max(0, 352 - (responseMetrics?.avg_response_time_ms || 0) / 10)} 352`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="text-center">
                      <p className={cn(
                        'text-2xl font-bold',
                        responseMetrics?.avg_response_time_ms && responseMetrics.avg_response_time_ms < 1000
                          ? 'text-[var(--emerald-400)]'
                          : 'text-[var(--high)]'
                      )}>
                        {responseMetrics?.avg_response_time_ms?.toFixed(0) || 0}ms
                      </p>
                      <p className="text-xs text-[var(--muted)]">avg response</p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                <div className="text-center p-3 bg-[var(--surface-2)] rounded-lg">
                  <p className="text-lg font-semibold text-[var(--emerald-400)]">
                    {responseMetrics?.min_response_time_ms || 0}ms
                  </p>
                  <p className="text-xs text-[var(--muted)]">Fastest</p>
                </div>
                <div className="text-center p-3 bg-[var(--surface-2)] rounded-lg">
                  <p className="text-lg font-semibold text-[var(--crit)]">
                    {responseMetrics?.max_response_time_ms || 0}ms
                  </p>
                  <p className="text-xs text-[var(--muted)]">Slowest</p>
                </div>
              </div>
            </div>
          </div>

          {/* Response Timeline */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[var(--fg)]">Response Timeline</h3>
              <button
                onClick={() => {
                  // Refresh timeline data
                  setLoadingMetrics(true)
                  axios.get('/api/v1/response/metrics').then(res => {
                    setResponseMetrics(res.data.metrics)
                    setResponseTimeline(res.data.timeline || [])
                  }).catch(() => {
                    toast.error('Failed to load metrics')
                  }).finally(() => {
                    setLoadingMetrics(false)
                  })
                }}
                className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
              >
                <RefreshCw className={cn('h-4 w-4 text-[var(--muted)]', loadingMetrics && 'animate-spin')} />
              </button>
            </div>
            <div className="max-h-[400px] overflow-auto">
              {loadingMetrics ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-8 w-8 text-[var(--emerald-400)] animate-spin" />
                </div>
              ) : responseTimeline.length > 0 ? (
                <div className="divide-y divide-[var(--border)]">
                  {responseTimeline.map((event) => (
                    <div key={event.id} className="p-4 hover:bg-[var(--surface-2)] transition-colors">
                      <div className="flex items-start gap-4">
                        <div className={cn(
                          'p-2 rounded-lg',
                          event.success ? 'bg-[var(--emerald-glow)]' : 'bg-[var(--crit-bg)]'
                        )}>
                          {event.success ? (
                            <CheckCircle className="h-4 w-4 text-[var(--emerald-400)]" />
                          ) : (
                            <XCircle className="h-4 w-4 text-[var(--crit)]" />
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-[var(--fg)]">{event.type}</span>
                            {event.automated && (
                              <span className="badge-sentinel badge-sentinel-sol-magenta">
                                Automated
                              </span>
                            )}
                            <span className={cn(
                              'badge-sentinel',
                              event.duration_ms < 500
                                ? 'badge-sentinel-success'
                                : event.duration_ms < 1000
                                ? 'badge-sentinel-warning'
                                : 'badge-sentinel-error'
                            )}>
                              {event.duration_ms}ms
                            </span>
                          </div>
                          <div className="flex items-center gap-4 mt-1 text-xs text-[var(--muted)]">
                            <span className="flex items-center gap-1">
                              <Monitor className="h-3 w-3" />
                              {event.agent_hostname}
                            </span>
                            <span>{formatDate(event.executed_at)}</span>
                          </div>
                          {event.actions.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {event.actions.map((action, idx) => (
                                <span
                                  key={idx}
                                  className={cn(
                                    'px-2 py-1 text-xs rounded',
                                    action.result === 'ok' || action.result === 'success'
                                      ? 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]'
                                      : 'bg-[var(--crit-bg)] text-[var(--crit)]'
                                  )}
                                >
                                  {action.action} ({action.duration_ms}ms)
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-[var(--muted)]">
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No response events yet</p>
                  <p className="text-sm mt-2">Response events will appear here as they occur</p>
                </div>
              )}
            </div>
          </div>

          {/* Rollback Stats */}
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-[var(--high-bg)]">
                <Undo2 className="h-5 w-5 text-[var(--high)]" />
              </div>
              <h3 className="text-sm font-semibold text-[var(--fg)]">Rollback Statistics</h3>
            </div>
            <div className="grid grid-cols-4 gap-4">
              <div className="text-center p-4 bg-[var(--surface-2)] rounded-lg">
                <p className="text-2xl font-bold text-[var(--high)]">
                  {responseMetrics?.rollbacks || 0}
                </p>
                <p className="text-xs text-[var(--muted)]">Total Rollbacks</p>
              </div>
              <div className="text-center p-4 bg-[var(--surface-2)] rounded-lg">
                <p className="text-2xl font-bold text-[var(--emerald-400)]">
                  {responseMetrics?.total_responses && responseMetrics.rollbacks
                    ? ((1 - (responseMetrics.rollbacks / responseMetrics.total_responses)) * 100).toFixed(1)
                    : 100}%
                </p>
                <p className="text-xs text-[var(--muted)]">First-Time Success</p>
              </div>
              <div className="text-center p-4 bg-[var(--surface-2)] rounded-lg">
                <p className="text-2xl font-bold text-[var(--med)]">
                  {responseMetrics?.failed_responses || 0}
                </p>
                <p className="text-xs text-[var(--muted)]">Failed Responses</p>
              </div>
              <div className="text-center p-4 bg-[var(--surface-2)] rounded-lg">
                <p className="text-2xl font-bold text-[var(--fg-2)]">
                  {responseMetrics?.total_responses
                    ? Math.round((responseMetrics.successful_responses + (responseMetrics.rollbacks || 0) * 0.5) / responseMetrics.total_responses * 100)
                    : 0}%
                </p>
                <p className="text-xs text-[var(--muted)]">Recovery Rate</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  )
}
