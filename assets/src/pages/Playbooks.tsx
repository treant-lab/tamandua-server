import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { logger } from '@/lib/logger'
import {
  BookOpen,
  Play,
  Pause,
  Edit,
  Clock,
  CheckCircle,
  XCircle,
  Search,
  Plus,
  MoreVertical,
  Shield,
  Bug,
  Mail,
  Lock,
  Server,
  FileWarning,
  Grid,
  List,
  ChevronRight,
  ChevronDown,
  Copy,
  Eye,
  Trash2,
  Save,
  X,
  AlertTriangle,
  RefreshCw,
  Loader2,
  ArrowUp,
  ArrowDown,
  GripVertical,
  GitBranch,
  Repeat,
  Timer,
  Zap,
  Filter,
  ToggleLeft,
  ToggleRight,
  Activity,
  Target,
  Hash,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'
import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'

// Types
type StepType = 'action' | 'condition' | 'wait' | 'loop'

interface PlaybookStep {
  id: string
  name: string
  stepType: StepType
  action: string
  actionType: 'isolate' | 'kill_process' | 'quarantine_file' | 'block_ip' | 'notify' | 'scan' | 'custom'
  condition?: string
  conditionTrueBranch?: string
  conditionFalseBranch?: string
  timeout: number
  waitDuration?: number
  loopCount?: number
  loopCondition?: string
  params?: Record<string, unknown>
}

interface TriggerCondition {
  id: string
  field: 'alert_severity' | 'event_type' | 'threat_score' | 'mitre_technique' | 'custom'
  operator: 'equals' | 'greater_than' | 'less_than' | 'contains' | 'in'
  value: string
}

interface PlaybookExecution {
  id: string
  playbookId: string
  triggeredBy: string
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'dry_run'
  startedAt: string
  completedAt: string | null
  stepsCompleted: number
  totalSteps: number
  dryRun?: boolean
  log?: string[]
}

interface Playbook {
  id: string
  name: string
  description: string
  category: 'malware' | 'phishing' | 'ransomware' | 'lateral_movement' | 'data_exfiltration' | 'custom'
  status: 'active' | 'draft' | 'disabled'
  enabled: boolean
  steps: PlaybookStep[]
  triggerConditions: string[]
  trigger?: {
    type: string
    conditions: TriggerCondition[]
  }
  lastExecuted: string | null
  executionCount: number
  successRate: number
  createdAt: string
  updatedAt: string
  createdBy: string
}

interface PlaybookTemplate {
  id: string
  name: string
  description: string
  category: Playbook['category']
  steps: PlaybookStep[]
}

interface PlaybooksPageProps {
  playbooks?: Playbook[]
  templates?: PlaybookTemplate[]
  executions?: PlaybookExecution[]
}

const categoryConfig: Record<Playbook['category'], { icon: typeof Shield; color: string; bgColor: string; label: string }> = {
  malware: { icon: Bug, color: 'var(--crit)', bgColor: 'var(--crit-bg)', label: 'Malware' },
  phishing: { icon: Mail, color: 'var(--high)', bgColor: 'var(--high-bg)', label: 'Phishing' },
  ransomware: { icon: Lock, color: 'var(--sol-magenta)', bgColor: 'rgba(217, 70, 239, 0.12)', label: 'Ransomware' },
  lateral_movement: { icon: Server, color: 'var(--med)', bgColor: 'var(--med-bg)', label: 'Lateral Movement' },
  data_exfiltration: { icon: FileWarning, color: 'var(--high)', bgColor: 'var(--high-bg)', label: 'Data Exfiltration' },
  custom: { icon: BookOpen, color: 'var(--muted)', bgColor: 'var(--surface-2)', label: 'Custom' },
}

const statusConfig: Record<Playbook['status'], { color: string; bgColor: string; borderColor: string; icon: typeof CheckCircle; label: string }> = {
  active: { color: 'var(--emerald-400)', bgColor: 'var(--emerald-glow)', borderColor: 'rgba(47, 196, 113, 0.3)', icon: CheckCircle, label: 'Active' },
  draft: { color: 'var(--high)', bgColor: 'var(--high-bg)', borderColor: 'rgba(245, 165, 36, 0.3)', icon: Edit, label: 'Draft' },
  disabled: { color: 'var(--muted)', bgColor: 'var(--surface-2)', borderColor: 'var(--border)', icon: Pause, label: 'Disabled' },
}

const executionStatusConfig: Record<PlaybookExecution['status'], { color: string; bgColor: string; icon: typeof CheckCircle }> = {
  running: { color: 'var(--med)', bgColor: 'var(--med-bg)', icon: Play },
  completed: { color: 'var(--emerald-400)', bgColor: 'var(--emerald-glow)', icon: CheckCircle },
  failed: { color: 'var(--crit)', bgColor: 'var(--crit-bg)', icon: XCircle },
  cancelled: { color: 'var(--muted)', bgColor: 'var(--surface-2)', icon: Pause },
  dry_run: { color: 'var(--sol-cyan)', bgColor: 'rgba(25, 251, 155, 0.12)', icon: Eye },
}

const normalizeCategory = (category: unknown): Playbook['category'] => {
  if (category === 'data_exfil' || category === 'exfiltration') return 'data_exfiltration'
  if (typeof category === 'string' && category in categoryConfig) return category as Playbook['category']
  return 'custom'
}

const getCategoryConfig = (category: unknown) => categoryConfig[normalizeCategory(category)]

const getStatusConfig = (status: unknown) => {
  if (typeof status === 'string' && status in statusConfig) return statusConfig[status as Playbook['status']]
  return statusConfig.draft
}

const getExecutionStatusConfig = (status: unknown) => {
  if (typeof status === 'string' && status in executionStatusConfig) {
    return executionStatusConfig[status as PlaybookExecution['status']]
  }
  return executionStatusConfig.cancelled
}

const actionTypes = [
  { value: 'isolate', label: 'Isolate Host', description: 'Isolate the agent from the network' },
  { value: 'kill_process', label: 'Kill Process', description: 'Terminate the suspicious process' },
  { value: 'quarantine_file', label: 'Quarantine File', description: 'Move file to quarantine' },
  { value: 'block_ip', label: 'Block IP', description: 'Block network communication to/from IP' },
  { value: 'notify', label: 'Send Notification', description: 'Send alert notification' },
  { value: 'scan', label: 'Run Scan', description: 'Trigger a full or targeted scan on the endpoint' },
  { value: 'custom', label: 'Custom Script', description: 'Execute custom response script' },
]

const stepTypeConfig: Record<StepType, { icon: typeof Zap; color: string; bgColor: string; borderColor: string; label: string }> = {
  action: { icon: Zap, color: 'var(--med)', bgColor: 'var(--med-bg)', borderColor: 'rgba(91, 156, 242, 0.3)', label: 'Action' },
  condition: { icon: GitBranch, color: 'var(--high)', bgColor: 'var(--high-bg)', borderColor: 'rgba(245, 165, 36, 0.3)', label: 'Condition' },
  wait: { icon: Timer, color: 'var(--muted)', bgColor: 'var(--surface-2)', borderColor: 'var(--border)', label: 'Wait / Delay' },
  loop: { icon: Repeat, color: 'var(--sol-magenta)', bgColor: 'rgba(217, 70, 239, 0.12)', borderColor: 'rgba(217, 70, 239, 0.3)', label: 'Loop' },
}

const getStepTypeConfig = (stepType: unknown) => {
  if (typeof stepType === 'string' && stepType in stepTypeConfig) return stepTypeConfig[stepType as StepType]
  return stepTypeConfig.action
}

const triggerFieldOptions = [
  { value: 'alert_severity', label: 'Alert Severity' },
  { value: 'event_type', label: 'Event Type' },
  { value: 'threat_score', label: 'Threat Score' },
  { value: 'mitre_technique', label: 'MITRE Technique' },
  { value: 'custom', label: 'Custom Field' },
]

const triggerOperatorOptions = [
  { value: 'equals', label: '==' },
  { value: 'greater_than', label: '>' },
  { value: 'less_than', label: '<' },
  { value: 'contains', label: 'contains' },
  { value: 'in', label: 'in' },
]

export default function Playbooks({ playbooks: initialPlaybooks = [], executions: initialExecutions = [] }: PlaybooksPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<Playbook['category'] | 'all'>('all')
  const [selectedStatus, setSelectedStatus] = useState<Playbook['status'] | 'all'>('all')
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [templates, setTemplates] = useState<PlaybookTemplate[]>([])

  // API state
  const [playbooks, setPlaybooks] = useState<Playbook[]>(initialPlaybooks)
  const [executions, setExecutions] = useState<PlaybookExecution[]>(initialExecutions)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [templatesError, setTemplatesError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [executing, setExecuting] = useState<string | null>(null)

  // Editor state
  const [showEditor, setShowEditor] = useState(false)
  const [editingPlaybook, setEditingPlaybook] = useState<Partial<Playbook> | null>(null)
  const [saving, setSaving] = useState(false)

  // Execution history panel
  const [showExecutionLog, setShowExecutionLog] = useState<PlaybookExecution | null>(null)

  // Fetch playbooks from API
  const fetchPlaybooks = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    setTemplatesError(null)
    try {
      const [playbooksRes, executionsRes, templatesRes] = await Promise.all([
        axios.get('/api/v1/playbooks').catch((error) => {
          logger.error('Failed to fetch playbooks:', error)
          return { data: { data: initialPlaybooks } }
        }),
        axios.get('/api/v1/playbooks/recent-executions').catch(() => ({ data: { data: [] } })),
        axios.get('/api/v1/playbooks/templates').catch((error) => {
          logger.error('Failed to fetch playbook templates:', error)
          setTemplatesError('Template library is unavailable')
          return { data: { data: [] } }
        }),
      ])

      if (playbooksRes.data?.data) {
        setPlaybooks(playbooksRes.data.data)
      }
      if (executionsRes.data?.data) {
        setExecutions(executionsRes.data.data)
      }
      if (templatesRes.data?.data) {
        // Convert backend template format to frontend format
        const backendTemplates = templatesRes.data.data.map((t: any) => ({
          id: t.id || `template_${t.name?.toLowerCase().replace(/\s+/g, '_')}`,
          name: t.name,
          description: t.description,
          category: t.category || 'custom',
          steps: (t.steps || []).map((s: any, i: number) => ({
            id: s.id || `${i + 1}`,
            name: s.name || s.action || `Step ${i + 1}`,
            stepType: s.action === 'conditional' ? 'condition' : s.action === 'wait' ? 'wait' : 'action',
            action: s.action,
            actionType: mapActionType(s.action),
            timeout: s.timeout || 30,
            params: s.params,
          })),
        }))
        setTemplates(backendTemplates)
      }
    } catch (error) {
      logger.error('Failed to refresh playbook data:', error)
      setLoadError('Failed to refresh playbook data')
    } finally {
      setLoading(false)
    }
  }, [])

  // Map backend action names to frontend action types
  const mapActionType = (action: string): PlaybookStep['actionType'] => {
    const mapping: Record<string, PlaybookStep['actionType']> = {
      'isolate_host': 'isolate',
      'kill_process': 'kill_process',
      'quarantine_file': 'quarantine_file',
      'block_ip': 'block_ip',
      'block_domain': 'block_ip',
      'send_notification': 'notify',
      'trigger_scan': 'scan',
    }
    return mapping[action] || 'custom'
  }

  // Clear action error after 5 seconds
  useEffect(() => {
    if (actionError) {
      const timer = setTimeout(() => setActionError(null), 5000)
      return () => clearTimeout(timer)
    }
  }, [actionError])

  // Execute playbook
  const executePlaybook = async (playbookId: string, dryRun = false) => {
    setExecuting(playbookId)
    setActionError(null)
    try {
      const response = await axios.post(`/api/v1/playbooks/${playbookId}/execute`, {
        dry_run: dryRun,
      })
      if (response.data?.data) {
        if (dryRun) {
          setShowExecutionLog(response.data.data)
        }
        fetchPlaybooks()
      }
    } catch (error) {
      logger.error('Failed to execute playbook:', error)
      setActionError(error instanceof Error ? error.message : 'Failed to execute playbook')
    } finally {
      setExecuting(null)
    }
  }

  // Toggle playbook enabled/disabled
  const togglePlaybook = async (playbookId: string, enabled: boolean) => {
    setActionError(null)
    try {
      await axios.patch(`/api/v1/playbooks/${playbookId}`, {
        enabled,
        status: enabled ? 'active' : 'disabled',
      })
      setPlaybooks(prev => prev.map(p =>
        p.id === playbookId ? { ...p, enabled, status: enabled ? 'active' : 'disabled' } : p
      ))
      if (selectedPlaybook?.id === playbookId) {
        setSelectedPlaybook(prev => prev ? { ...prev, enabled, status: enabled ? 'active' : 'disabled' } : null)
      }
    } catch (error) {
      logger.error('Failed to toggle playbook:', error)
      setActionError(error instanceof Error ? error.message : 'Failed to toggle playbook')
    }
  }

  // Clone playbook
  const clonePlaybook = async (playbookId: string) => {
    setActionError(null)
    try {
      const playbook = playbooks.find(p => p.id === playbookId)
      const response = await axios.post(`/api/v1/playbooks/${playbookId}/clone`, {
        name: `${playbook?.name} (Copy)`,
      })
      if (response.data?.data) {
        fetchPlaybooks()
      }
    } catch (error) {
      logger.error('Failed to clone playbook:', error)
      setActionError(error instanceof Error ? error.message : 'Failed to clone playbook')
    }
  }

  // Delete playbook
  const deletePlaybook = async (playbookId: string) => {
    if (!confirm('Are you sure you want to delete this playbook?')) return

    setActionError(null)
    try {
      await axios.delete(`/api/v1/playbooks/${playbookId}`)
      setPlaybooks(prev => prev.filter(p => p.id !== playbookId))
      if (selectedPlaybook?.id === playbookId) {
        setSelectedPlaybook(null)
      }
    } catch (error) {
      logger.error('Failed to delete playbook:', error)
      setActionError(error instanceof Error ? error.message : 'Failed to delete playbook')
    }
  }

  // Save playbook (create or update)
  const savePlaybook = async () => {
    if (!editingPlaybook) return

    setSaving(true)
    setActionError(null)
    try {
      if (editingPlaybook.id) {
        await axios.put(`/api/v1/playbooks/${editingPlaybook.id}`, editingPlaybook)
      } else {
        await axios.post('/api/v1/playbooks', editingPlaybook)
      }
      setShowEditor(false)
      setEditingPlaybook(null)
      fetchPlaybooks()
    } catch (error) {
      logger.error('Failed to save playbook:', error)
      setActionError(error instanceof Error ? error.message : 'Failed to save playbook')
    } finally {
      setSaving(false)
    }
  }

  // Open editor for new playbook
  const openNewPlaybook = (template?: PlaybookTemplate) => {
    setEditingPlaybook({
      name: template?.name || '',
      description: template?.description || '',
      category: template?.category || 'custom',
      status: 'draft',
      enabled: false,
      steps: template?.steps || [],
      triggerConditions: [],
      trigger: { type: 'manual', conditions: [] },
    })
    setShowEditor(true)
  }

  // Open editor for existing playbook
  const openEditPlaybook = (playbook: Playbook) => {
    setEditingPlaybook({
      ...playbook,
      trigger: playbook.trigger || { type: 'manual', conditions: [] },
    })
    setShowEditor(true)
  }

  // Initial fetch
  useEffect(() => {
    if (initialPlaybooks.length === 0) {
      fetchPlaybooks()
    }
  }, [])

  const filteredPlaybooks = playbooks.filter((playbook) => {
    const matchesSearch = playbook.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      playbook.description.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesCategory = selectedCategory === 'all' || playbook.category === selectedCategory
    const matchesStatus = selectedStatus === 'all' || playbook.status === selectedStatus
    return matchesSearch && matchesCategory && matchesStatus
  })

  const activePlaybooks = playbooks.filter((p) => p.status === 'active').length
  const totalExecutions = playbooks.reduce((acc, p) => acc + (p.executionCount || 0), 0)
  const avgSuccessRate = playbooks.filter((p) => (p.executionCount || 0) > 0)
    .reduce((acc, p, _, arr) => acc + (p.successRate || 0) / arr.length, 0)

  const formatDate = (dateString: string) => {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(dateString))
  }

  return (
    <MainLayout title="Response Playbooks">
      <Head title="Playbooks - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-4 gap-4">
          <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
                <BookOpen className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{playbooks.length}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Playbooks</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
                <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{activePlaybooks}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Active Playbooks</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--med-bg)' }}>
                <Play className="h-5 w-5" style={{ color: 'var(--med)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{totalExecutions}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Executions</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
                <Shield className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{avgSuccessRate.toFixed(1)}%</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Avg Success Rate</p>
              </div>
            </div>
          </div>
        </div>

        {/* Loading State */}
        {loading && playbooks.length === 0 && !loadError && (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: 'var(--emerald-500)' }} />
          </div>
        )}

        {/* Load Error State */}
        {loadError && (
          <div className="flex flex-col items-center justify-center h-64" style={{ color: 'var(--muted)' }}>
            <AlertTriangle className="w-12 h-12 mb-3" style={{ color: 'var(--crit)' }} />
            <p className="text-sm">{loadError}</p>
            <button
              onClick={fetchPlaybooks}
              className="btn-sentinel btn-sentinel-secondary mt-3"
            >
              Retry
            </button>
          </div>
        )}

        {/* Action Error Banner */}
        {actionError && (
          <div
            className="rounded-xl p-4 flex items-center justify-between"
            style={{ backgroundColor: 'var(--crit-bg)', border: '1px solid rgba(240, 80, 110, 0.2)' }}
          >
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--crit)' }} />
              <p className="text-sm" style={{ color: 'var(--crit)' }}>{actionError}</p>
            </div>
            <button
              onClick={() => setActionError(null)}
              style={{ color: 'var(--muted)' }}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Filters and Actions */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                placeholder="Search playbooks..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-sentinel pl-10 pr-4 w-64"
              />
            </div>

            <Select
              value={selectedCategory}
              onValueChange={(value) => setSelectedCategory(value as Playbook['category'] | 'all')}
              className="min-w-44"
            >
              <SelectItem value="all">All Categories</SelectItem>
              {Object.entries(categoryConfig).map(([key, config]) => (
                <SelectItem key={key} value={key}>{config.label}</SelectItem>
              ))}
            </Select>

            <Select
              value={selectedStatus}
              onValueChange={(value) => setSelectedStatus(value as Playbook['status'] | 'all')}
              className="min-w-36"
            >
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="draft">Draft</SelectItem>
              <SelectItem value="disabled">Disabled</SelectItem>
            </Select>

            <button
              onClick={fetchPlaybooks}
              disabled={loading}
              className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            </button>
          </div>

          <div className="flex items-center gap-2">
            <div
              className="flex items-center rounded-lg p-1"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <button
                onClick={() => setViewMode('grid')}
                className="p-1.5 rounded transition-colors"
                style={{
                  backgroundColor: viewMode === 'grid' ? 'var(--surface-2)' : 'transparent',
                  color: viewMode === 'grid' ? 'var(--fg)' : 'var(--muted)'
                }}
              >
                <Grid className="h-4 w-4" />
              </button>
              <button
                onClick={() => setViewMode('list')}
                className="p-1.5 rounded transition-colors"
                style={{
                  backgroundColor: viewMode === 'list' ? 'var(--surface-2)' : 'transparent',
                  color: viewMode === 'list' ? 'var(--fg)' : 'var(--muted)'
                }}
              >
                <List className="h-4 w-4" />
              </button>
            </div>
            <button
              onClick={() => openNewPlaybook()}
              className="btn-sentinel btn-sentinel-primary"
            >
              <Plus className="h-4 w-4" />
              New Playbook
            </button>
          </div>
        </div>

        {/* Templates Quick Start */}
        <div
          className="card-sentinel rounded-xl p-4"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', opacity: 0.9 }}
        >
          <h3 className="text-sm font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--muted)' }}>Quick Start Templates</h3>
          {templates.length === 0 ? (
            <div className="rounded-lg border px-3 py-3 text-sm" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
              {templatesError || 'No playbook templates available'}
            </div>
          ) : (
          <div className="flex gap-3">
            {templates.map((template) => {
              const category = getCategoryConfig(template.category)
              const CategoryIcon = category.icon
              return (
                <button
                  key={template.id}
                  onClick={() => openNewPlaybook(template)}
                  className="flex items-center gap-3 rounded-lg p-3 transition-colors"
                  style={{
                    backgroundColor: 'var(--surface-2)',
                    border: '1px solid var(--border)'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'var(--surface-3)'
                    e.currentTarget.style.borderColor = 'var(--border-strong)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                    e.currentTarget.style.borderColor = 'var(--border)'
                  }}
                >
                  <div className="p-2 rounded-lg" style={{ backgroundColor: category.bgColor }}>
                    <CategoryIcon className="h-4 w-4" style={{ color: category.color }} />
                  </div>
                  <div className="text-left">
                    <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{template.name}</p>
                    <p className="text-xs" style={{ color: 'var(--muted)' }}>{template.steps.length} steps</p>
                  </div>
                </button>
              )
            })}
          </div>
          )}
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* Playbooks Grid/List */}
          <div className="col-span-2">
            {filteredPlaybooks.length === 0 ? (
              <div
                className="card-sentinel rounded-xl p-12 text-center"
                style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
              >
                <BookOpen className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--dim)' }} />
                <p className="text-lg" style={{ color: 'var(--muted)' }}>No playbooks found</p>
                <p className="text-sm mt-1" style={{ color: 'var(--subtle)' }}>Create your first playbook to automate responses</p>
                <button
                  onClick={() => openNewPlaybook()}
                  className="btn-sentinel btn-sentinel-primary mt-4"
                >
                  <Plus className="h-4 w-4" />
                  Create Playbook
                </button>
              </div>
            ) : viewMode === 'grid' ? (
              <div className="grid grid-cols-2 gap-4">
                {filteredPlaybooks.map((playbook) => {
                  const category = getCategoryConfig(playbook.category)
                  const status = getStatusConfig(playbook.status)
                  const CategoryIcon = category.icon

                  return (
                    <div
                      key={playbook.id}
                      onClick={() => setSelectedPlaybook(playbook)}
                      className={cn(
                        'card-sentinel rounded-xl p-5 cursor-pointer transition-all',
                        selectedPlaybook?.id === playbook.id && 'ring-2'
                      )}
                      style={{
                        backgroundColor: 'var(--surface)',
                        border: selectedPlaybook?.id === playbook.id ? '1px solid var(--emerald-500)' : '1px solid var(--border)',
                        ...(selectedPlaybook?.id === playbook.id && { boxShadow: '0 0 0 2px var(--emerald-glow)' })
                      }}
                      onMouseEnter={(e) => {
                        if (selectedPlaybook?.id !== playbook.id) {
                          e.currentTarget.style.borderColor = 'var(--border-strong)'
                          e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (selectedPlaybook?.id !== playbook.id) {
                          e.currentTarget.style.borderColor = 'var(--border)'
                          e.currentTarget.style.backgroundColor = 'var(--surface)'
                        }
                      }}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="p-2 rounded-lg" style={{ backgroundColor: category.bgColor }}>
                          <CategoryIcon className="h-5 w-5" style={{ color: category.color }} />
                        </div>
                        <div className="flex items-center gap-2">
                          <span
                            className="px-2 py-1 rounded-full text-xs font-medium"
                            style={{
                              backgroundColor: status.bgColor,
                              color: status.color,
                              border: `1px solid ${status.borderColor}`
                            }}
                          >
                            {status.label}
                          </span>
                          {/* Enable/Disable toggle */}
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              togglePlaybook(playbook.id, !playbook.enabled)
                            }}
                            title={playbook.enabled ? 'Disable playbook' : 'Enable playbook'}
                          >
                            {playbook.enabled ? (
                              <ToggleRight className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                            ) : (
                              <ToggleLeft className="h-5 w-5" style={{ color: 'var(--subtle)' }} />
                            )}
                          </button>
                        </div>
                      </div>

                      <h3 className="font-semibold mb-1" style={{ color: 'var(--fg)' }}>{playbook.name}</h3>
                      <p className="text-sm mb-3 line-clamp-2" style={{ color: 'var(--muted)' }}>{playbook.description}</p>

                      {/* Step type summary */}
                      <div className="flex items-center gap-2 mb-3">
                        {playbook.steps.map((step, i) => {
                          const stConf = getStepTypeConfig(step.stepType)
                          const StIcon = stConf.icon
                          return (
                            <div key={step.id} className="flex items-center">
                              <div
                                className="p-1 rounded"
                                style={{ backgroundColor: stConf.bgColor }}
                                title={step.name}
                              >
                                <StIcon className="h-3 w-3" style={{ color: stConf.color }} />
                              </div>
                              {i < playbook.steps.length - 1 && (
                                <ChevronRight className="h-3 w-3 mx-0.5" style={{ color: 'var(--dim)' }} />
                              )}
                            </div>
                          )
                        })}
                      </div>

                      <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                        <span className="flex items-center gap-1">
                          <Play className="h-3 w-3" />
                          {playbook.executionCount || 0} runs
                        </span>
                        {(playbook.executionCount || 0) > 0 && (
                          <span className="flex items-center gap-1">
                            <CheckCircle className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
                            {playbook.successRate || 0}% success
                          </span>
                        )}
                      </div>

                      {playbook.lastExecuted && (
                        <div
                          className="mt-3 pt-3 flex items-center gap-1 text-xs"
                          style={{ borderTop: '1px solid var(--hairline)', color: 'var(--subtle)' }}
                        >
                          <Clock className="h-3 w-3" />
                          Last run: {formatDate(playbook.lastExecuted)}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <div
                className="card-sentinel rounded-xl divide-y"
                style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', '--tw-divide-color': 'var(--hairline)' } as React.CSSProperties}
              >
                {filteredPlaybooks.map((playbook) => {
                  const category = getCategoryConfig(playbook.category)
                  const status = getStatusConfig(playbook.status)
                  const CategoryIcon = category.icon

                  return (
                    <div
                      key={playbook.id}
                      onClick={() => setSelectedPlaybook(playbook)}
                      className="flex items-center gap-4 p-4 cursor-pointer transition-colors"
                      style={{
                        backgroundColor: selectedPlaybook?.id === playbook.id ? 'var(--surface-2)' : 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        if (selectedPlaybook?.id !== playbook.id) {
                          e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (selectedPlaybook?.id !== playbook.id) {
                          e.currentTarget.style.backgroundColor = 'transparent'
                        }
                      }}
                    >
                      <div className="p-2 rounded-lg" style={{ backgroundColor: category.bgColor }}>
                        <CategoryIcon className="h-5 w-5" style={{ color: category.color }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{playbook.name}</h3>
                          <span
                            className="px-2 py-0.5 rounded-full text-xs"
                            style={{
                              backgroundColor: status.bgColor,
                              color: status.color,
                              border: `1px solid ${status.borderColor}`
                            }}
                          >
                            {status.label}
                          </span>
                        </div>
                        <p className="text-sm truncate" style={{ color: 'var(--muted)' }}>{playbook.description}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            togglePlaybook(playbook.id, !playbook.enabled)
                          }}
                          title={playbook.enabled ? 'Disable' : 'Enable'}
                        >
                          {playbook.enabled ? (
                            <ToggleRight className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                          ) : (
                            <ToggleLeft className="h-5 w-5" style={{ color: 'var(--subtle)' }} />
                          )}
                        </button>
                        <div className="text-right text-sm">
                          <p style={{ color: 'var(--fg)' }}>{playbook.executionCount || 0} runs</p>
                          {(playbook.executionCount || 0) > 0 && (
                            <p style={{ color: 'var(--emerald-400)' }}>{playbook.successRate || 0}% success</p>
                          )}
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5" style={{ color: 'var(--subtle)' }} />
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Playbook Preview / Execution History */}
          <div className="space-y-6">
            {/* Playbook Preview */}
            {selectedPlaybook ? (
              <div
                className="card-sentinel rounded-xl"
                style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
              >
                <div
                  className="p-4 flex items-center justify-between"
                  style={{ borderBottom: '1px solid var(--hairline)' }}
                >
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Playbook Preview</h2>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => openEditPlaybook(selectedPlaybook)}
                      className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                      title="Edit"
                    >
                      <Edit className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => clonePlaybook(selectedPlaybook.id)}
                      className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                      title="Clone"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => deletePlaybook(selectedPlaybook.id)}
                      className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
                      style={{ color: 'var(--crit)' }}
                      title="Delete"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                <div className="p-4">
                  <h3 className="font-medium mb-2" style={{ color: 'var(--fg)' }}>{selectedPlaybook.name}</h3>
                  <p className="text-sm mb-4" style={{ color: 'var(--muted)' }}>{selectedPlaybook.description}</p>

                  {/* Visual Step Flow */}
                  <div className="mb-4">
                    <h4 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Step Flow</h4>
                    <div className="space-y-1">
                      {selectedPlaybook.steps.map((step, index) => {
                        const stConf = getStepTypeConfig(step.stepType)
                        const StIcon = stConf.icon
                        return (
                          <div key={step.id}>
                            <div className="flex items-center gap-3 text-sm">
                              <div
                                className="flex items-center justify-center h-7 w-7 rounded-lg"
                                style={{
                                  backgroundColor: stConf.bgColor,
                                  border: `1px solid ${stConf.borderColor}`
                                }}
                              >
                                <StIcon className="h-3.5 w-3.5" style={{ color: stConf.color }} />
                              </div>
                              <div className="flex-1">
                                <span style={{ color: 'var(--fg-2)' }}>{step.name}</span>
                                {step.stepType === 'condition' && step.condition && (
                                  <span className="text-xs ml-2" style={{ color: 'var(--high)' }}>if {step.condition}</span>
                                )}
                                {step.stepType === 'wait' && step.waitDuration && (
                                  <span className="text-xs ml-2" style={{ color: 'var(--subtle)' }}>{step.waitDuration}s</span>
                                )}
                                {step.stepType === 'loop' && (
                                  <span className="text-xs ml-2" style={{ color: 'var(--sol-magenta)' }}>
                                    {step.loopCount ? `${step.loopCount}x` : step.loopCondition || ''}
                                  </span>
                                )}
                              </div>
                              <span
                                className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                                style={{
                                  backgroundColor: stConf.bgColor,
                                  color: stConf.color,
                                  border: `1px solid ${stConf.borderColor}`
                                }}
                              >
                                {stConf.label}
                              </span>
                            </div>
                            {index < selectedPlaybook.steps.length - 1 && (
                              <div className="ml-3.5 h-2" style={{ borderLeft: '1px solid var(--hairline)' }} />
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Trigger Conditions */}
                  {selectedPlaybook.trigger?.conditions && selectedPlaybook.trigger.conditions.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Trigger Conditions</h4>
                      <div className="space-y-1">
                        {selectedPlaybook.trigger.conditions.map((cond: TriggerCondition, index: number) => (
                          <div
                            key={index}
                            className="flex items-center gap-2 text-xs rounded px-2 py-1.5"
                            style={{ backgroundColor: 'var(--surface-2)' }}
                          >
                            <Target className="h-3 w-3" style={{ color: 'var(--high)' }} />
                            <span style={{ color: 'var(--fg-2)' }}>{cond.field}</span>
                            <span style={{ color: 'var(--subtle)' }}>{cond.operator}</span>
                            <span className="font-mono" style={{ color: 'var(--fg)' }}>{cond.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedPlaybook.triggerConditions.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Triggers</h4>
                      <div className="flex flex-wrap gap-1">
                        {selectedPlaybook.triggerConditions.map((condition, index) => (
                          <span
                            key={index}
                            className="px-2 py-1 rounded text-xs"
                            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                          >
                            {condition}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center gap-2 pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
                    <button
                      onClick={() => executePlaybook(selectedPlaybook.id)}
                      disabled={executing === selectedPlaybook.id || selectedPlaybook.status === 'disabled'}
                      className="btn-sentinel btn-sentinel-primary flex-1"
                    >
                      {executing === selectedPlaybook.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      Run Now
                    </button>
                    <button
                      onClick={() => executePlaybook(selectedPlaybook.id, true)}
                      disabled={executing === selectedPlaybook.id}
                      className="btn-sentinel btn-sentinel-secondary"
                      title="Test / Dry Run - validate logic without executing"
                    >
                      <Eye className="h-4 w-4" />
                      Test
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div
                className="card-sentinel rounded-xl p-8 text-center"
                style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
              >
                <BookOpen className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--dim)' }} />
                <p style={{ color: 'var(--muted)' }}>Select a playbook to preview</p>
              </div>
            )}

            {/* Execution History */}
            <div
              className="card-sentinel rounded-xl"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <div className="p-4" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recent Executions</h2>
              </div>
              <div className="divide-y max-h-[400px] overflow-auto" style={{ '--tw-divide-color': 'var(--hairline)' } as React.CSSProperties}>
                {executions.length === 0 ? (
                  <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                    <Play className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No executions yet</p>
                  </div>
                ) : (
                  executions.map((execution) => {
                    const playbook = playbooks.find((p) => p.id === execution.playbookId)
                    const statusConf = getExecutionStatusConfig(execution.status)
                    const StatusIcon = statusConf.icon

                    return (
                      <div
                        key={execution.id}
                        className="p-4 cursor-pointer transition-colors"
                        onClick={() => setShowExecutionLog(execution)}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                      >
                        <div className="flex items-start gap-3">
                          <div className="p-2 rounded-lg" style={{ backgroundColor: statusConf.bgColor }}>
                            <StatusIcon className="h-4 w-4" style={{ color: statusConf.color }} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{playbook?.name || 'Unknown'}</p>
                              {execution.dryRun && (
                                <span
                                  className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                                  style={{
                                    color: 'var(--sol-cyan)',
                                    backgroundColor: 'rgba(25, 251, 155, 0.12)',
                                    border: '1px solid rgba(25, 251, 155, 0.3)'
                                  }}
                                >
                                  DRY RUN
                                </span>
                              )}
                            </div>
                            <p className="text-xs truncate mt-0.5" style={{ color: 'var(--muted)' }}>{execution.triggeredBy}</p>
                            <div className="flex items-center gap-2 mt-2">
                              <div
                                className="flex-1 h-1.5 rounded-full overflow-hidden"
                                style={{ backgroundColor: 'var(--surface-3)' }}
                              >
                                <div
                                  className="h-full rounded-full"
                                  style={{
                                    backgroundColor: execution.status === 'completed' ? 'var(--emerald-500)' :
                                    execution.status === 'running' ? 'var(--med)' :
                                    execution.status === 'failed' ? 'var(--crit)' :
                                    execution.status === 'dry_run' ? 'var(--sol-cyan)' : 'var(--muted)',
                                    width: `${(execution.stepsCompleted / execution.totalSteps) * 100}%`
                                  }}
                                />
                              </div>
                              <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                                {execution.stepsCompleted}/{execution.totalSteps}
                              </span>
                            </div>
                            <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>{formatDate(execution.startedAt)}</p>
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
      </div>

      {/* Playbook Editor Modal */}
      {showEditor && editingPlaybook && (
        <PlaybookEditor
          playbook={editingPlaybook}
          onSave={savePlaybook}
          onClose={() => { setShowEditor(false); setEditingPlaybook(null) }}
          onChange={setEditingPlaybook}
          saving={saving}
          onDryRun={async () => {
            if (editingPlaybook.id) {
              await executePlaybook(editingPlaybook.id, true)
            }
          }}
        />
      )}

      {/* Execution Log Modal */}
      {showExecutionLog && (
        <ExecutionLogModal
          execution={showExecutionLog}
          playbookName={playbooks.find(p => p.id === showExecutionLog.playbookId)?.name || 'Unknown'}
          onClose={() => setShowExecutionLog(null)}
        />
      )}
    </MainLayout>
  )
}

// Playbook Editor Component - Visual Builder
function PlaybookEditor({
  playbook,
  onSave,
  onClose,
  onChange,
  saving,
  onDryRun,
}: {
  playbook: Partial<Playbook>
  onSave: () => void
  onClose: () => void
  onChange: (playbook: Partial<Playbook>) => void
  saving: boolean
  onDryRun: () => void
}) {
  const [activeTab, setActiveTab] = useState<'steps' | 'triggers' | 'settings'>('steps')
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [showValidation, setShowValidation] = useState(false)

  const addStep = (stepType: StepType = 'action') => {
    const newStep: PlaybookStep = {
      id: `step_${Date.now()}`,
      name: stepType === 'action' ? 'New Action' :
            stepType === 'condition' ? 'New Condition' :
            stepType === 'wait' ? 'Wait' :
            'Loop',
      stepType,
      action: '',
      actionType: 'notify',
      timeout: 30,
      ...(stepType === 'wait' ? { waitDuration: 10 } : {}),
      ...(stepType === 'loop' ? { loopCount: 3 } : {}),
      ...(stepType === 'condition' ? { condition: '', conditionTrueBranch: '', conditionFalseBranch: '' } : {}),
    }
    onChange({
      ...playbook,
      steps: [...(playbook.steps || []), newStep],
    })
  }

  const updateStep = (index: number, updates: Partial<PlaybookStep>) => {
    const newSteps = [...(playbook.steps || [])]
    newSteps[index] = { ...newSteps[index], ...updates }
    onChange({ ...playbook, steps: newSteps })
  }

  const removeStep = (index: number) => {
    const newSteps = [...(playbook.steps || [])]
    newSteps.splice(index, 1)
    onChange({ ...playbook, steps: newSteps })
  }

  const moveStep = (index: number, direction: 'up' | 'down') => {
    const newSteps = [...(playbook.steps || [])]
    const newIndex = direction === 'up' ? index - 1 : index + 1
    if (newIndex < 0 || newIndex >= newSteps.length) return
    ;[newSteps[index], newSteps[newIndex]] = [newSteps[newIndex], newSteps[index]]
    onChange({ ...playbook, steps: newSteps })
  }

  // Trigger conditions management
  const addTriggerCondition = () => {
    const newCondition: TriggerCondition = {
      id: `trig_${Date.now()}`,
      field: 'alert_severity',
      operator: 'equals',
      value: '',
    }
    const currentTrigger = playbook.trigger || { type: 'auto', conditions: [] }
    onChange({
      ...playbook,
      trigger: {
        ...currentTrigger,
        conditions: [...(currentTrigger.conditions || []), newCondition],
      },
    })
  }

  const updateTriggerCondition = (index: number, updates: Partial<TriggerCondition>) => {
    const currentTrigger = playbook.trigger || { type: 'auto', conditions: [] }
    const newConditions = [...(currentTrigger.conditions || [])]
    newConditions[index] = { ...newConditions[index], ...updates } as TriggerCondition
    onChange({
      ...playbook,
      trigger: { ...currentTrigger, conditions: newConditions },
    })
  }

  const removeTriggerCondition = (index: number) => {
    const currentTrigger = playbook.trigger || { type: 'auto', conditions: [] }
    const newConditions = [...(currentTrigger.conditions || [])]
    newConditions.splice(index, 1)
    onChange({
      ...playbook,
      trigger: { ...currentTrigger, conditions: newConditions },
    })
  }

  // Validate playbook
  const validatePlaybook = () => {
    const errors: string[] = []

    if (!playbook.name || playbook.name.trim() === '') {
      errors.push('Playbook name is required')
    }
    if (!playbook.steps || playbook.steps.length === 0) {
      errors.push('At least one step is required')
    }

    playbook.steps?.forEach((step, i) => {
      if (!step.name || step.name.trim() === '') {
        errors.push(`Step ${i + 1}: Name is required`)
      }
      if (step.stepType === 'action' && !step.actionType) {
        errors.push(`Step ${i + 1} "${step.name}": Action type is required`)
      }
      if (step.stepType === 'condition' && (!step.condition || step.condition.trim() === '')) {
        errors.push(`Step ${i + 1} "${step.name}": Condition expression is required`)
      }
      if (step.stepType === 'wait' && (!step.waitDuration || step.waitDuration <= 0)) {
        errors.push(`Step ${i + 1} "${step.name}": Wait duration must be positive`)
      }
      if (step.stepType === 'loop' && !step.loopCount && !step.loopCondition) {
        errors.push(`Step ${i + 1} "${step.name}": Loop count or condition is required`)
      }
    })

    setValidationErrors(errors)
    setShowValidation(true)
    return errors.length === 0
  }

  const handleDryRun = () => {
    if (validatePlaybook()) {
      onDryRun()
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ backgroundColor: 'rgba(0, 0, 0, 0.6)' }}>
      <div
        className="card-sentinel rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        {/* Header */}
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--hairline)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {playbook.id ? 'Edit Playbook' : 'Create Playbook'}
          </h2>
          <button
            onClick={onClose}
            style={{ color: 'var(--muted)' }}
            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="px-6" style={{ borderBottom: '1px solid var(--hairline)' }}>
          <div className="flex gap-6">
            {([
              { key: 'steps', label: 'Visual Builder', icon: Activity },
              { key: 'triggers', label: 'Trigger Conditions', icon: Target },
              { key: 'settings', label: 'Settings', icon: Filter },
            ] as const).map(tab => {
              const TabIcon = tab.icon
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className="flex items-center gap-2 py-3 border-b-2 text-sm font-medium transition-colors"
                  style={{
                    borderColor: activeTab === tab.key ? 'var(--emerald-500)' : 'transparent',
                    color: activeTab === tab.key ? 'var(--emerald-400)' : 'var(--muted)'
                  }}
                >
                  <TabIcon className="h-4 w-4" />
                  {tab.label}
                </button>
              )
            })}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'settings' && (
            <>
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: 'var(--muted)' }}>Name</label>
                  <input
                    type="text"
                    value={playbook.name || ''}
                    onChange={(e) => onChange({ ...playbook, name: e.target.value })}
                    className="input-sentinel w-full"
                    placeholder="Playbook name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: 'var(--muted)' }}>Category</label>
                  <Select
                    value={playbook.category || 'custom'}
                    onValueChange={(value) => onChange({ ...playbook, category: value as Playbook['category'] })}
                    className="w-full"
                  >
                    {Object.entries(categoryConfig).map(([key, config]) => (
                      <SelectItem key={key} value={key}>{config.label}</SelectItem>
                    ))}
                  </Select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--muted)' }}>Description</label>
                <textarea
                  value={playbook.description || ''}
                  onChange={(e) => onChange({ ...playbook, description: e.target.value })}
                  className="input-sentinel w-full h-20 resize-none"
                  placeholder="Describe what this playbook does..."
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--muted)' }}>Status</label>
                <Select
                  value={playbook.status || 'draft'}
                  onValueChange={(value) => onChange({ ...playbook, status: value as Playbook['status'] })}
                  className="w-full"
                >
                  <SelectItem value="draft">Draft</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="disabled">Disabled</SelectItem>
                </Select>
              </div>
            </>
          )}

          {activeTab === 'triggers' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>Trigger Conditions</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>Define what events automatically trigger this playbook</p>
                </div>
                <button
                  onClick={addTriggerCondition}
                  className="flex items-center gap-1 text-sm"
                  style={{ color: 'var(--emerald-400)' }}
                >
                  <Plus className="h-4 w-4" />
                  Add Condition
                </button>
              </div>

              <div className="space-y-3">
                {(playbook.trigger?.conditions || []).map((cond, index) => (
                  <div
                    key={cond.id || index}
                    className="rounded-lg p-4"
                    style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
                  >
                    <div className="flex items-center gap-3">
                      {index > 0 && (
                        <span
                          className="text-xs font-medium px-2 py-0.5 rounded"
                          style={{ color: 'var(--high)', backgroundColor: 'var(--high-bg)' }}
                        >
                          AND
                        </span>
                      )}
                      <div className="flex-1 grid grid-cols-3 gap-3">
                        <div>
                          <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Field</label>
                          <Select
                            value={cond.field}
                            onValueChange={(value) => updateTriggerCondition(index, { field: value as TriggerCondition['field'] })}
                            className="w-full"
                          >
                            {triggerFieldOptions.map(opt => (
                              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                            ))}
                          </Select>
                        </div>
                        <div>
                          <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Operator</label>
                          <Select
                            value={cond.operator}
                            onValueChange={(value) => updateTriggerCondition(index, { operator: value as TriggerCondition['operator'] })}
                            className="w-full"
                          >
                            {triggerOperatorOptions.map(opt => (
                              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                            ))}
                          </Select>
                        </div>
                        <div>
                          <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Value</label>
                          <input
                            type="text"
                            value={cond.value}
                            onChange={(e) => updateTriggerCondition(index, { value: e.target.value })}
                            className="input-sentinel w-full text-sm"
                            placeholder={
                              cond.field === 'alert_severity' ? 'critical, high, medium, low' :
                              cond.field === 'threat_score' ? '80' :
                              cond.field === 'mitre_technique' ? 'T1059' :
                              cond.field === 'event_type' ? 'process_create' :
                              'value'
                            }
                          />
                        </div>
                      </div>
                      <button
                        onClick={() => removeTriggerCondition(index)}
                        className="p-1 mt-4"
                        style={{ color: 'var(--subtle)' }}
                        onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--crit)' }}
                        onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--subtle)' }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}

                {(playbook.trigger?.conditions || []).length === 0 && (
                  <div
                    className="text-center py-8 rounded-lg"
                    style={{ color: 'var(--subtle)', border: '1px dashed var(--border)' }}
                  >
                    <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No trigger conditions defined</p>
                    <p className="text-sm">This playbook can only be run manually</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'steps' && (
            <div>
              {/* Step Type Picker */}
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>Response Steps</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>Build the playbook flow by adding steps</p>
                </div>
                <div className="flex items-center gap-2">
                  {(Object.entries(stepTypeConfig) as [StepType, typeof stepTypeConfig[StepType]][]).map(([type, conf]) => {
                    const StIcon = conf.icon
                    return (
                      <button
                        key={type}
                        onClick={() => addStep(type)}
                        className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg transition-colors"
                        style={{
                          backgroundColor: conf.bgColor,
                          color: conf.color,
                          border: `1px solid ${conf.borderColor}`
                        }}
                        title={`Add ${conf.label} step`}
                      >
                        <StIcon className="h-3.5 w-3.5" />
                        {conf.label}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Visual Flow Builder */}
              <div className="space-y-1">
                {(playbook.steps || []).map((step, index) => {
                  const stConf = getStepTypeConfig(step.stepType)
                  const StIcon = stConf.icon

                  return (
                    <div key={step.id}>
                      {/* Connector line */}
                      {index > 0 && (
                        <div className="flex items-center justify-center py-1">
                          <div className="w-px h-4" style={{ backgroundColor: 'var(--border)' }} />
                        </div>
                      )}

                      <div
                        className="rounded-lg p-4 transition-colors"
                        style={{
                          backgroundColor: step.stepType === 'condition' ? 'rgba(245, 165, 36, 0.05)' :
                          step.stepType === 'wait' ? 'var(--surface-2)' :
                          step.stepType === 'loop' ? 'rgba(217, 70, 239, 0.05)' :
                          'var(--surface-2)',
                          border: `1px solid ${step.stepType === 'condition' ? 'rgba(245, 165, 36, 0.3)' :
                          step.stepType === 'loop' ? 'rgba(217, 70, 239, 0.3)' : 'var(--border)'}`
                        }}
                      >
                        <div className="flex items-start gap-3">
                          {/* Reorder controls */}
                          <div className="flex flex-col items-center gap-1 pt-1">
                            <button
                              onClick={() => moveStep(index, 'up')}
                              disabled={index === 0}
                              className="p-0.5 disabled:opacity-30"
                              style={{ color: 'var(--subtle)' }}
                            >
                              <ArrowUp className="h-3 w-3" />
                            </button>
                            <div
                              className="flex items-center justify-center h-6 w-6 rounded-lg text-xs font-mono"
                              style={{
                                backgroundColor: stConf.bgColor,
                                color: stConf.color,
                                border: `1px solid ${stConf.borderColor}`
                              }}
                            >
                              <StIcon className="h-3 w-3" />
                            </div>
                            <button
                              onClick={() => moveStep(index, 'down')}
                              disabled={index === (playbook.steps?.length || 0) - 1}
                              className="p-0.5 disabled:opacity-30"
                              style={{ color: 'var(--subtle)' }}
                            >
                              <ArrowDown className="h-3 w-3" />
                            </button>
                          </div>

                          <div className="flex-1">
                            {/* Step type badge */}
                            <div className="flex items-center gap-2 mb-2">
                              <span
                                className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
                                style={{
                                  backgroundColor: stConf.bgColor,
                                  color: stConf.color,
                                  border: `1px solid ${stConf.borderColor}`
                                }}
                              >
                                {stConf.label}
                              </span>
                              <span className="text-xs font-mono" style={{ color: 'var(--subtle)' }}>#{index + 1}</span>
                            </div>

                            {/* Common: Step Name */}
                            <div className="mb-3">
                              <input
                                type="text"
                                value={step.name}
                                onChange={(e) => updateStep(index, { name: e.target.value })}
                                className="input-sentinel w-full font-medium"
                                placeholder="Step name"
                              />
                            </div>

                            {/* Action Step Fields */}
                            {step.stepType === 'action' && (
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Action Type</label>
                                  <Select
                                    value={step.actionType}
                                    onValueChange={(value) => updateStep(index, { actionType: value as PlaybookStep['actionType'], action: value })}
                                    className="w-full"
                                  >
                                    {actionTypes.map((action) => (
                                      <SelectItem key={action.value} value={action.value}>{action.label}</SelectItem>
                                    ))}
                                  </Select>
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Timeout (sec)</label>
                                  <input
                                    type="number"
                                    value={step.timeout}
                                    onChange={(e) => updateStep(index, { timeout: parseInt(e.target.value) || 30 })}
                                    className="input-sentinel w-full text-sm"
                                    min="5"
                                    max="300"
                                  />
                                </div>
                              </div>
                            )}

                            {/* Condition Step Fields */}
                            {step.stepType === 'condition' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Condition Expression</label>
                                  <input
                                    type="text"
                                    value={step.condition || ''}
                                    onChange={(e) => updateStep(index, { condition: e.target.value })}
                                    className="input-sentinel w-full text-sm font-mono"
                                    placeholder="e.g., threat_score > 80 OR severity == 'critical'"
                                  />
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                  <div>
                                    <label className="block text-xs mb-1" style={{ color: 'var(--emerald-400)' }}>True Branch (then)</label>
                                    <input
                                      type="text"
                                      value={step.conditionTrueBranch || ''}
                                      onChange={(e) => updateStep(index, { conditionTrueBranch: e.target.value })}
                                      className="input-sentinel w-full text-sm"
                                      style={{ borderColor: 'rgba(47, 196, 113, 0.3)' }}
                                      placeholder="Description of true path"
                                    />
                                  </div>
                                  <div>
                                    <label className="block text-xs mb-1" style={{ color: 'var(--crit)' }}>False Branch (else)</label>
                                    <input
                                      type="text"
                                      value={step.conditionFalseBranch || ''}
                                      onChange={(e) => updateStep(index, { conditionFalseBranch: e.target.value })}
                                      className="input-sentinel w-full text-sm"
                                      style={{ borderColor: 'rgba(240, 80, 110, 0.3)' }}
                                      placeholder="Description of false path"
                                    />
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Wait Step Fields */}
                            {step.stepType === 'wait' && (
                              <div>
                                <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Wait Duration (seconds)</label>
                                <input
                                  type="number"
                                  value={step.waitDuration || 10}
                                  onChange={(e) => updateStep(index, { waitDuration: parseInt(e.target.value) || 10 })}
                                  className="input-sentinel w-full text-sm"
                                  min="1"
                                  max="3600"
                                />
                              </div>
                            )}

                            {/* Loop Step Fields */}
                            {step.stepType === 'loop' && (
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Loop Count</label>
                                  <input
                                    type="number"
                                    value={step.loopCount || ''}
                                    onChange={(e) => updateStep(index, { loopCount: parseInt(e.target.value) || undefined })}
                                    className="input-sentinel w-full text-sm"
                                    placeholder="Number of iterations"
                                    min="1"
                                    max="100"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--subtle)' }}>Or Condition</label>
                                  <input
                                    type="text"
                                    value={step.loopCondition || ''}
                                    onChange={(e) => updateStep(index, { loopCondition: e.target.value })}
                                    className="input-sentinel w-full text-sm font-mono"
                                    placeholder="e.g., until process_stopped"
                                  />
                                </div>
                              </div>
                            )}
                          </div>

                          <button
                            onClick={() => removeStep(index)}
                            className="p-1 mt-1"
                            style={{ color: 'var(--subtle)' }}
                            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--crit)' }}
                            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--subtle)' }}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  )
                })}

                {(playbook.steps?.length || 0) === 0 && (
                  <div
                    className="text-center py-12 rounded-lg"
                    style={{ color: 'var(--subtle)', border: '1px dashed var(--border)' }}
                  >
                    <Activity className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <p className="text-sm font-medium">No steps defined</p>
                    <p className="text-xs mt-1">Use the buttons above to add Action, Condition, Wait, or Loop steps</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Validation Results */}
          {showValidation && validationErrors.length > 0 && (
            <div
              className="rounded-lg p-4"
              style={{ backgroundColor: 'var(--crit-bg)', border: '1px solid rgba(240, 80, 110, 0.3)' }}
            >
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                <span className="text-sm font-medium" style={{ color: 'var(--crit)' }}>Validation Errors</span>
              </div>
              <ul className="space-y-1">
                {validationErrors.map((err, i) => (
                  <li key={i} className="text-xs flex items-center gap-1.5" style={{ color: 'var(--crit)' }}>
                    <XCircle className="h-3 w-3 flex-shrink-0" />
                    {err}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {showValidation && validationErrors.length === 0 && (
            <div
              className="rounded-lg p-4"
              style={{ backgroundColor: 'var(--emerald-glow)', border: '1px solid rgba(47, 196, 113, 0.3)' }}
            >
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                <span className="text-sm font-medium" style={{ color: 'var(--emerald-400)' }}>Playbook is valid</span>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 flex items-center justify-between" style={{ borderTop: '1px solid var(--hairline)' }}>
          <button
            onClick={handleDryRun}
            className="btn-sentinel btn-sentinel-outline"
            style={{
              backgroundColor: 'rgba(25, 251, 155, 0.1)',
              borderColor: 'var(--sol-cyan)',
              color: 'var(--sol-cyan)'
            }}
            title="Validate playbook logic without executing"
          >
            <Eye className="h-4 w-4" />
            Test / Dry Run
          </button>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2"
              style={{ color: 'var(--muted)' }}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
            >
              Cancel
            </button>
            <button
              onClick={() => {
                if (validatePlaybook()) {
                  onSave()
                }
              }}
              disabled={saving || !playbook.name || (playbook.steps?.length || 0) === 0}
              className="btn-sentinel btn-sentinel-primary"
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save Playbook
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// Execution Log Modal
function ExecutionLogModal({
  execution,
  playbookName,
  onClose,
}: {
  execution: PlaybookExecution
  playbookName: string
  onClose: () => void
}) {
  const statusConf = getExecutionStatusConfig(execution.status)
  const StatusIcon = statusConf.icon

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ backgroundColor: 'rgba(0, 0, 0, 0.6)' }}>
      <div
        className="card-sentinel rounded-xl w-full max-w-lg max-h-[80vh] overflow-hidden flex flex-col"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--hairline)' }}>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: statusConf.bgColor }}>
              <StatusIcon className="h-4 w-4" style={{ color: statusConf.color }} />
            </div>
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--fg)' }}>{playbookName}</h2>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>Execution Log</p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ color: 'var(--muted)' }}
            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Execution Summary */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Status</span>
              <div className="font-medium capitalize mt-0.5" style={{ color: statusConf.color }}>
                {execution.status.replace('_', ' ')}
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Progress</span>
              <div className="font-medium mt-0.5" style={{ color: 'var(--fg)' }}>
                {execution.stepsCompleted} / {execution.totalSteps} steps
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Started</span>
              <div className="font-medium mt-0.5 text-xs font-mono" style={{ color: 'var(--fg)' }}>
                {execution.startedAt}
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Completed</span>
              <div className="font-medium mt-0.5 text-xs font-mono" style={{ color: 'var(--fg)' }}>
                {execution.completedAt || 'In progress'}
              </div>
            </div>
          </div>

          {/* Triggered By */}
          <div className="rounded-lg p-3 text-sm" style={{ backgroundColor: 'var(--surface-2)' }}>
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>Triggered By</span>
            <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{execution.triggeredBy}</div>
          </div>

          {/* Execution Log */}
          {execution.log && execution.log.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Execution Log</h3>
              <div
                className="rounded-lg p-3 font-mono text-xs space-y-1 max-h-48 overflow-y-auto"
                style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)' }}
              >
                {execution.log.map((line, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="select-none" style={{ color: 'var(--dim)' }}>{String(i + 1).padStart(3, ' ')}</span>
                    <span>{line}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Progress bar */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1" style={{ color: 'var(--subtle)' }}>
              <span>Completion</span>
              <span>{Math.round((execution.stepsCompleted / execution.totalSteps) * 100)}%</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-3)' }}>
              <div
                className={cn(
                  'h-full rounded-full transition-all',
                  execution.status === 'running' && 'animate-pulse'
                )}
                style={{
                  backgroundColor: execution.status === 'completed' ? 'var(--emerald-500)' :
                  execution.status === 'running' ? 'var(--med)' :
                  execution.status === 'failed' ? 'var(--crit)' :
                  execution.status === 'dry_run' ? 'var(--sol-cyan)' : 'var(--muted)',
                  width: `${(execution.stepsCompleted / execution.totalSteps) * 100}%`
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
