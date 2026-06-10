import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState, useCallback, useMemo } from 'react'
import {
  Plus,
  Trash2,
  Play,
  Save,
  Copy,
  Eye,
  EyeOff,
  AlertTriangle,
  CheckCircle,
  XCircle,
  GripVertical,
  ChevronDown,
  ChevronUp,
  Code,
  FileCode,
  Target,
  Settings,
  History,
  BarChart3,
  Zap,
  Shield,
  Network,
  FileText,
  Terminal,
  Clock,
  Filter,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

// Types
interface RuleCondition {
  id: string
  field: string
  operator: string
  value: string
  modifier?: string
  negated?: boolean
}

interface ConditionGroup {
  id: string
  logic: 'and' | 'or'
  conditions: (RuleCondition | ConditionGroup)[]
}

interface DetectionRule {
  id: string
  name: string
  description: string
  enabled: boolean
  severity: 'critical' | 'high' | 'medium' | 'low'
  ruleType: 'sigma' | 'behavioral' | 'yara' | 'custom'
  logsource: {
    category?: string
    product?: string
    service?: string
  }
  detection: ConditionGroup
  mitreTechniques: string[]
  tags: string[]
  falsePositiveNotes: string[]
  author: string
  createdAt: string
  updatedAt: string
}

interface TestResult {
  matchCount: number
  sampleMatches: Array<{
    eventId: string
    timestamp: string
    matchedFields: Record<string, string>
    agentId: string
  }>
  falsePositiveEstimate: number
  executionTimeMs: number
}

interface RulePerformance {
  triggeredCount: number
  falsePositiveRate: number
  avgProcessingTimeMs: number
  lastTriggered: string | null
}

// Field definitions for different event types
const EVENT_FIELDS: Record<string, Array<{ value: string; label: string; type: string }>> = {
  process: [
    { value: 'process_name', label: 'Process Name', type: 'string' },
    { value: 'cmdline', label: 'Command Line', type: 'string' },
    { value: 'parent_process_name', label: 'Parent Process', type: 'string' },
    { value: 'parent_cmdline', label: 'Parent Command Line', type: 'string' },
    { value: 'user', label: 'User', type: 'string' },
    { value: 'pid', label: 'PID', type: 'number' },
    { value: 'ppid', label: 'Parent PID', type: 'number' },
    { value: 'is_elevated', label: 'Is Elevated', type: 'boolean' },
    { value: 'original_filename', label: 'Original Filename', type: 'string' },
    { value: 'file_hash', label: 'File Hash (SHA256)', type: 'string' },
    { value: 'working_directory', label: 'Working Directory', type: 'string' },
    { value: 'integrity_level', label: 'Integrity Level', type: 'string' },
  ],
  network: [
    { value: 'remote_ip', label: 'Remote IP', type: 'string' },
    { value: 'remote_port', label: 'Remote Port', type: 'number' },
    { value: 'local_port', label: 'Local Port', type: 'number' },
    { value: 'protocol', label: 'Protocol', type: 'string' },
    { value: 'direction', label: 'Direction', type: 'string' },
    { value: 'domain', label: 'Domain', type: 'string' },
    { value: 'bytes_sent', label: 'Bytes Sent', type: 'number' },
    { value: 'bytes_received', label: 'Bytes Received', type: 'number' },
  ],
  file: [
    { value: 'path', label: 'File Path', type: 'string' },
    { value: 'filename', label: 'Filename', type: 'string' },
    { value: 'extension', label: 'Extension', type: 'string' },
    { value: 'operation', label: 'Operation', type: 'string' },
    { value: 'file_hash', label: 'File Hash (SHA256)', type: 'string' },
    { value: 'file_size', label: 'File Size', type: 'number' },
    { value: 'entropy', label: 'Entropy', type: 'number' },
  ],
  dns: [
    { value: 'query', label: 'DNS Query', type: 'string' },
    { value: 'query_type', label: 'Query Type', type: 'string' },
    { value: 'response', label: 'Response', type: 'string' },
    { value: 'response_code', label: 'Response Code', type: 'string' },
  ],
  registry: [
    { value: 'key', label: 'Registry Key', type: 'string' },
    { value: 'value_name', label: 'Value Name', type: 'string' },
    { value: 'value_data', label: 'Value Data', type: 'string' },
    { value: 'operation', label: 'Operation', type: 'string' },
  ],
}

const OPERATORS = [
  { value: 'equals', label: 'Equals', types: ['string', 'number', 'boolean'] },
  { value: 'contains', label: 'Contains', types: ['string'] },
  { value: 'startswith', label: 'Starts With', types: ['string'] },
  { value: 'endswith', label: 'Ends With', types: ['string'] },
  { value: 'regex', label: 'Regex Match', types: ['string'] },
  { value: 'gt', label: 'Greater Than', types: ['number'] },
  { value: 'gte', label: 'Greater Than or Equal', types: ['number'] },
  { value: 'lt', label: 'Less Than', types: ['number'] },
  { value: 'lte', label: 'Less Than or Equal', types: ['number'] },
  { value: 'in', label: 'In List', types: ['string', 'number'] },
  { value: 'cidr', label: 'CIDR Match', types: ['string'] },
]

const MODIFIERS = [
  { value: 'none', label: 'None' },
  { value: 'base64', label: 'Base64 Decode' },
  { value: 'base64offset', label: 'Base64 Offset' },
  { value: 'wide', label: 'Wide String' },
  { value: 'utf16', label: 'UTF-16' },
  { value: 'lowercase', label: 'Lowercase' },
]

const MITRE_TECHNIQUES = [
  { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
  { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'Persistence' },
  { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'Lateral Movement' },
]

const SEVERITY_COLORS = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
}

// Generate unique ID
const generateId = () => Math.random().toString(36).substring(2, 11)

// Default empty rule
const createEmptyRule = (): DetectionRule => ({
  id: generateId(),
  name: 'New Detection Rule',
  description: '',
  enabled: true,
  severity: 'medium',
  ruleType: 'sigma',
  logsource: { category: 'process' },
  detection: {
    id: generateId(),
    logic: 'and',
    conditions: [],
  },
  mitreTechniques: [],
  tags: [],
  falsePositiveNotes: [],
  author: '',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
})

// Create empty condition
const createEmptyCondition = (): RuleCondition => ({
  id: generateId(),
  field: '',
  operator: 'contains',
  value: '',
})

export default function DetectionBuilder() {
  const [rule, setRule] = useState<DetectionRule>(createEmptyRule())
  const [selectedTab, setSelectedTab] = useState<'builder' | 'yaml' | 'test' | 'performance'>('builder')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [isTesting, setIsTesting] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set([rule.detection.id]))
  const [showMitreModal, setShowMitreModal] = useState(false)

  // Get fields for current category
  const availableFields = useMemo(() => {
    return EVENT_FIELDS[rule.logsource.category || 'process'] || EVENT_FIELDS.process
  }, [rule.logsource.category])

  // Convert rule to Sigma YAML
  const ruleYaml = useMemo(() => {
    const convertConditions = (group: ConditionGroup): string => {
      const items = group.conditions.map((c) => {
        if ('conditions' in c) {
          return `(${convertConditions(c)})`
        }
        const cond = c as RuleCondition
        const neg = cond.negated ? 'not ' : ''
        return `${neg}${cond.field}|${cond.operator}:"${cond.value}"`
      })
      return items.join(group.logic === 'and' ? ' and ' : ' or ')
    }

    return `title: ${rule.name}
id: ${rule.id}
status: ${rule.enabled ? 'experimental' : 'disabled'}
description: ${rule.description || 'No description'}
author: ${rule.author || 'Unknown'}
date: ${rule.createdAt.split('T')[0]}
modified: ${rule.updatedAt.split('T')[0]}

logsource:
    category: ${rule.logsource.category || 'process_creation'}
    ${rule.logsource.product ? `product: ${rule.logsource.product}` : ''}
    ${rule.logsource.service ? `service: ${rule.logsource.service}` : ''}

detection:
    selection:
        ${convertConditions(rule.detection).split(' and ').map((c) => `- ${c}`).join('\n        ')}
    condition: selection

falsepositives:
    ${rule.falsePositiveNotes.length > 0 ? rule.falsePositiveNotes.map((n) => `- ${n}`).join('\n    ') : '- Unknown'}

level: ${rule.severity}

tags:
    ${rule.mitreTechniques.map((t) => `- attack.${t.toLowerCase()}`).join('\n    ')}
    ${rule.tags.map((t) => `- ${t}`).join('\n    ')}
`
  }, [rule])

  // Add condition to a group
  const addCondition = useCallback((groupId: string) => {
    const addToGroup = (group: ConditionGroup): ConditionGroup => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: [...group.conditions, createEmptyCondition()],
        }
      }
      return {
        ...group,
        conditions: group.conditions.map((c) =>
          'conditions' in c ? addToGroup(c) : c
        ),
      }
    }

    setRule((prev) => ({
      ...prev,
      detection: addToGroup(prev.detection),
      updatedAt: new Date().toISOString(),
    }))
  }, [])

  // Add nested group
  const addGroup = useCallback((parentId: string) => {
    const newGroup: ConditionGroup = {
      id: generateId(),
      logic: 'and',
      conditions: [createEmptyCondition()],
    }

    const addToGroup = (group: ConditionGroup): ConditionGroup => {
      if (group.id === parentId) {
        return {
          ...group,
          conditions: [...group.conditions, newGroup],
        }
      }
      return {
        ...group,
        conditions: group.conditions.map((c) =>
          'conditions' in c ? addToGroup(c) : c
        ),
      }
    }

    setRule((prev) => ({
      ...prev,
      detection: addToGroup(prev.detection),
      updatedAt: new Date().toISOString(),
    }))

    setExpandedGroups((prev) => new Set([...prev, newGroup.id]))
  }, [])

  // Update condition
  const updateCondition = useCallback((conditionId: string, updates: Partial<RuleCondition>) => {
    const updateInGroup = (group: ConditionGroup): ConditionGroup => ({
      ...group,
      conditions: group.conditions.map((c) => {
        if ('conditions' in c) {
          return updateInGroup(c)
        }
        if (c.id === conditionId) {
          return { ...c, ...updates }
        }
        return c
      }),
    })

    setRule((prev) => ({
      ...prev,
      detection: updateInGroup(prev.detection),
      updatedAt: new Date().toISOString(),
    }))
  }, [])

  // Remove condition or group
  const removeItem = useCallback((itemId: string) => {
    const removeFromGroup = (group: ConditionGroup): ConditionGroup => ({
      ...group,
      conditions: group.conditions
        .filter((c) => {
          if ('conditions' in c) {
            return c.id !== itemId
          }
          return c.id !== itemId
        })
        .map((c) => ('conditions' in c ? removeFromGroup(c) : c)),
    })

    setRule((prev) => ({
      ...prev,
      detection: removeFromGroup(prev.detection),
      updatedAt: new Date().toISOString(),
    }))
  }, [])

  // Toggle group logic
  const toggleGroupLogic = useCallback((groupId: string) => {
    const toggleInGroup = (group: ConditionGroup): ConditionGroup => {
      if (group.id === groupId) {
        return { ...group, logic: group.logic === 'and' ? 'or' : 'and' }
      }
      return {
        ...group,
        conditions: group.conditions.map((c) =>
          'conditions' in c ? toggleInGroup(c) : c
        ),
      }
    }

    setRule((prev) => ({
      ...prev,
      detection: toggleInGroup(prev.detection),
      updatedAt: new Date().toISOString(),
    }))
  }, [])

  // Test rule against historical data
  const testRule = async () => {
    setIsTesting(true)
    setTestResult(null)

    try {
      const response = await fetch('/api/v1/detection/test-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule }),
      })

      if (response.ok) {
        const result = await response.json()
        setTestResult(result)
      }
    } catch (error) {
      logger.error('Rule test failed:', error)
    } finally {
      setIsTesting(false)
    }
  }

  // Save rule
  const saveRule = async () => {
    setIsSaving(true)

    try {
      const response = await fetch('/api/v1/detection/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule }),
      })

      if (response.ok) {
        // Show success notification
      }
    } catch (error) {
      logger.error('Save failed:', error)
    } finally {
      setIsSaving(false)
    }
  }

  // Toggle MITRE technique
  const toggleMitreTechnique = (techniqueId: string) => {
    setRule((prev) => ({
      ...prev,
      mitreTechniques: prev.mitreTechniques.includes(techniqueId)
        ? prev.mitreTechniques.filter((t) => t !== techniqueId)
        : [...prev.mitreTechniques, techniqueId],
      updatedAt: new Date().toISOString(),
    }))
  }

  // Render condition input
  const renderCondition = (condition: RuleCondition, depth: number = 0) => {
    const fieldDef = availableFields.find((f) => f.value === condition.field)
    const applicableOperators = OPERATORS.filter(
      (op) => !fieldDef || op.types.includes(fieldDef.type)
    )

    return (
      <div
        key={condition.id}
        className="flex items-center gap-2 p-3 rounded-lg"
        style={{
          marginLeft: depth * 16,
          backgroundColor: 'var(--surface)',
        }}
      >
        <GripVertical className="h-4 w-4 cursor-grab" style={{ color: 'var(--muted)' }} />

        <button
          onClick={() => updateCondition(condition.id, { negated: !condition.negated })}
          className={cn(
            'px-2 py-1 rounded text-xs font-medium',
            condition.negated
              ? 'bg-red-500/20 text-red-400'
              : 'text-[var(--muted)]'
          )}
          style={!condition.negated ? { backgroundColor: 'var(--surface)' } : undefined}
        >
          {condition.negated ? 'NOT' : 'IS'}
        </button>

        <select
          value={condition.field}
          onChange={(e) => updateCondition(condition.id, { field: e.target.value })}
          className="input-sentinel px-3 py-1.5 rounded text-sm"
        >
          <option value="">Select Field</option>
          {availableFields.map((field) => (
            <option key={field.value} value={field.value}>
              {field.label}
            </option>
          ))}
        </select>

        <select
          value={condition.operator}
          onChange={(e) => updateCondition(condition.id, { operator: e.target.value })}
          className="input-sentinel px-3 py-1.5 rounded text-sm"
        >
          {applicableOperators.map((op) => (
            <option key={op.value} value={op.value}>
              {op.label}
            </option>
          ))}
        </select>

        <input
          type="text"
          value={condition.value}
          onChange={(e) => updateCondition(condition.id, { value: e.target.value })}
          placeholder="Value"
          className="input-sentinel flex-1 px-3 py-1.5 rounded text-sm"
        />

        <select
          value={condition.modifier || 'none'}
          onChange={(e) =>
            updateCondition(condition.id, {
              modifier: e.target.value === 'none' ? undefined : e.target.value,
            })
          }
          className="input-sentinel px-2 py-1.5 rounded text-sm"
        >
          {MODIFIERS.map((mod) => (
            <option key={mod.value} value={mod.value}>
              {mod.label}
            </option>
          ))}
        </select>

        <button
          onClick={() => removeItem(condition.id)}
          className="p-1.5 transition-colors hover:text-red-400"
          style={{ color: 'var(--muted)' }}
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    )
  }

  // Render condition group
  const renderGroup = (group: ConditionGroup, depth: number = 0) => {
    const isExpanded = expandedGroups.has(group.id)

    return (
      <div
        key={group.id}
        className={cn(
          'border rounded-lg',
          depth > 0 && 'ml-4'
        )}
        style={{ borderColor: depth === 0 ? 'var(--border)' : 'var(--border-subtle)' }}
      >
        <div
          className="flex items-center gap-2 p-3"
          style={{ backgroundColor: 'var(--surface)' }}
        >
          <button
            onClick={() =>
              setExpandedGroups((prev) => {
                const next = new Set(prev)
                if (next.has(group.id)) {
                  next.delete(group.id)
                } else {
                  next.add(group.id)
                }
                return next
              })
            }
            className="p-1"
          >
            {isExpanded ? (
              <ChevronDown className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            ) : (
              <ChevronUp className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            )}
          </button>

          <button
            onClick={() => toggleGroupLogic(group.id)}
            className={cn(
              'px-3 py-1 rounded-lg text-xs font-bold',
              group.logic === 'and'
                ? 'bg-blue-500/20 text-blue-400'
                : 'bg-purple-500/20 text-purple-400'
            )}
          >
            {group.logic.toUpperCase()}
          </button>

          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {group.conditions.length} condition{group.conditions.length !== 1 ? 's' : ''}
          </span>

          <div className="flex-1" />

          <button
            onClick={() => addCondition(group.id)}
            className="flex items-center gap-1 px-2 py-1 text-xs hover:opacity-80"
            style={{ color: 'var(--emerald-400)' }}
          >
            <Plus className="h-3 w-3" />
            Condition
          </button>

          <button
            onClick={() => addGroup(group.id)}
            className="flex items-center gap-1 px-2 py-1 text-xs text-blue-400 hover:text-blue-300"
          >
            <Plus className="h-3 w-3" />
            Group
          </button>

          {depth > 0 && (
            <button
              onClick={() => removeItem(group.id)}
              className="p-1 hover:text-red-400"
              style={{ color: 'var(--muted)' }}
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>

        {isExpanded && (
          <div className="p-3 space-y-2">
            {group.conditions.length === 0 ? (
              <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
                <Filter className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No conditions yet</p>
                <button
                  onClick={() => addCondition(group.id)}
                  className="mt-2 text-sm hover:opacity-80"
                  style={{ color: 'var(--emerald-400)' }}
                >
                  Add first condition
                </button>
              </div>
            ) : (
              group.conditions.map((item, idx) => (
                <div key={'conditions' in item ? item.id : item.id}>
                  {idx > 0 && (
                    <div className="flex items-center justify-center my-2">
                      <div className="h-px flex-1" style={{ backgroundColor: 'var(--border-subtle)' }} />
                      <span className="px-2 text-xs uppercase" style={{ color: 'var(--muted)' }}>
                        {group.logic}
                      </span>
                      <div className="h-px flex-1" style={{ backgroundColor: 'var(--border-subtle)' }} />
                    </div>
                  )}
                  {'conditions' in item
                    ? renderGroup(item, depth + 1)
                    : renderCondition(item, depth)}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <MainLayout title="Detection Rule Builder">
      <Head title="Detection Builder - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Detection Rule Builder</h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              Create and test custom detection rules with visual builder
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={testRule}
              disabled={isTesting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: 'var(--surface)',
                color: 'var(--fg)',
              }}
            >
              {isTesting ? (
                <Activity className="h-4 w-4 animate-pulse" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Test Rule
            </button>
            <button
              onClick={saveRule}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg transition-colors"
            >
              <Save className="h-4 w-4" />
              Save Rule
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 pb-2" style={{ borderBottom: '1px solid var(--border)' }}>
          {[
            { id: 'builder', label: 'Visual Builder', icon: Settings },
            { id: 'yaml', label: 'YAML View', icon: Code },
            { id: 'test', label: 'Test Results', icon: Target },
            { id: 'performance', label: 'Performance', icon: BarChart3 },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedTab(tab.id as typeof selectedTab)}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
                selectedTab === tab.id
                  ? 'border'
                  : 'hover:opacity-80'
              )}
              style={
                selectedTab === tab.id
                  ? {
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      borderColor: 'var(--border)',
                      borderBottomColor: 'var(--surface)',
                    }
                  : { color: 'var(--muted)' }
              }
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {selectedTab === 'builder' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Main Editor */}
            <div className="lg:col-span-2 space-y-6">
              {/* Rule Metadata */}
              <div className="card-sentinel rounded-xl p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <FileCode className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Rule Metadata
                </h2>

                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2">
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Rule Name</label>
                    <input
                      type="text"
                      value={rule.name}
                      onChange={(e) => setRule((prev) => ({ ...prev, name: e.target.value }))}
                      className="input-sentinel w-full px-4 py-2 rounded-lg"
                    />
                  </div>

                  <div className="col-span-2">
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Description</label>
                    <textarea
                      value={rule.description}
                      onChange={(e) =>
                        setRule((prev) => ({ ...prev, description: e.target.value }))
                      }
                      rows={2}
                      className="input-sentinel w-full px-4 py-2 rounded-lg resize-none"
                    />
                  </div>

                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Severity</label>
                    <select
                      value={rule.severity}
                      onChange={(e) =>
                        setRule((prev) => ({
                          ...prev,
                          severity: e.target.value as DetectionRule['severity'],
                        }))
                      }
                      className="input-sentinel w-full px-4 py-2 rounded-lg"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Event Category</label>
                    <select
                      value={rule.logsource.category || 'process'}
                      onChange={(e) =>
                        setRule((prev) => ({
                          ...prev,
                          logsource: { ...prev.logsource, category: e.target.value },
                        }))
                      }
                      className="input-sentinel w-full px-4 py-2 rounded-lg"
                    >
                      <option value="process">Process</option>
                      <option value="network">Network</option>
                      <option value="file">File</option>
                      <option value="dns">DNS</option>
                      <option value="registry">Registry</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Author</label>
                    <input
                      type="text"
                      value={rule.author}
                      onChange={(e) => setRule((prev) => ({ ...prev, author: e.target.value }))}
                      className="input-sentinel w-full px-4 py-2 rounded-lg"
                    />
                  </div>

                  <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={(e) =>
                          setRule((prev) => ({ ...prev, enabled: e.target.checked }))
                        }
                        className="w-4 h-4 rounded"
                        style={{
                          borderColor: 'var(--border)',
                          backgroundColor: 'var(--surface)',
                        }}
                      />
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>Rule Enabled</span>
                    </label>
                  </div>
                </div>
              </div>

              {/* Detection Conditions */}
              <div className="card-sentinel rounded-xl p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Filter className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Detection Conditions
                </h2>

                {renderGroup(rule.detection)}
              </div>
            </div>

            {/* Sidebar */}
            <div className="space-y-6">
              {/* MITRE ATT&CK Mapping */}
              <div className="card-sentinel rounded-xl p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Shield className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  MITRE ATT&CK
                </h2>

                <div className="space-y-2">
                  {rule.mitreTechniques.length === 0 ? (
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>No techniques selected</p>
                  ) : (
                    rule.mitreTechniques.map((t) => {
                      const tech = MITRE_TECHNIQUES.find((m) => m.id === t)
                      return (
                        <div
                          key={t}
                          className="flex items-center justify-between p-2 rounded"
                          style={{ backgroundColor: 'var(--surface)' }}
                        >
                          <div>
                            <span className="text-xs font-mono" style={{ color: 'var(--emerald-400)' }}>{t}</span>
                            <p className="text-sm truncate max-w-[200px]" style={{ color: 'var(--fg)' }}>
                              {tech?.name || t}
                            </p>
                          </div>
                          <button
                            onClick={() => toggleMitreTechnique(t)}
                            className="p-1 hover:text-red-400"
                            style={{ color: 'var(--muted)' }}
                          >
                            <XCircle className="h-4 w-4" />
                          </button>
                        </div>
                      )
                    })
                  )}

                  <button
                    onClick={() => setShowMitreModal(true)}
                    className="w-full flex items-center justify-center gap-2 py-2 text-sm border border-dashed rounded"
                    style={{
                      color: 'var(--emerald-400)',
                      borderColor: 'var(--border)',
                    }}
                  >
                    <Plus className="h-4 w-4" />
                    Add Technique
                  </button>
                </div>
              </div>

              {/* Tags */}
              <div className="card-sentinel rounded-xl p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Zap className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Tags
                </h2>

                <div className="flex flex-wrap gap-2">
                  {rule.tags.map((tag, idx) => (
                    <span
                      key={idx}
                      className="flex items-center gap-1 px-2 py-1 rounded text-sm"
                      style={{
                        backgroundColor: 'var(--surface)',
                        color: 'var(--fg)',
                      }}
                    >
                      {tag}
                      <button
                        onClick={() =>
                          setRule((prev) => ({
                            ...prev,
                            tags: prev.tags.filter((_, i) => i !== idx),
                          }))
                        }
                        className="ml-1 hover:text-red-400"
                        style={{ color: 'var(--muted)' }}
                      >
                        <XCircle className="h-3 w-3" />
                      </button>
                    </span>
                  ))}

                  <input
                    type="text"
                    placeholder="Add tag..."
                    className="input-sentinel px-2 py-1 border border-dashed rounded text-sm w-24"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && e.currentTarget.value) {
                        setRule((prev) => ({
                          ...prev,
                          tags: [...prev.tags, e.currentTarget.value],
                        }))
                        e.currentTarget.value = ''
                      }
                    }}
                  />
                </div>
              </div>

              {/* False Positives */}
              <div className="card-sentinel rounded-xl p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  False Positive Notes
                </h2>

                <div className="space-y-2">
                  {rule.falsePositiveNotes.map((note, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2 p-2 rounded"
                      style={{ backgroundColor: 'var(--surface)' }}
                    >
                      <p className="flex-1 text-sm" style={{ color: 'var(--fg)' }}>{note}</p>
                      <button
                        onClick={() =>
                          setRule((prev) => ({
                            ...prev,
                            falsePositiveNotes: prev.falsePositiveNotes.filter(
                              (_, i) => i !== idx
                            ),
                          }))
                        }
                        className="p-1 hover:text-red-400"
                        style={{ color: 'var(--muted)' }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  ))}

                  <textarea
                    placeholder="Add false positive scenario..."
                    rows={2}
                    className="input-sentinel w-full px-3 py-2 rounded text-sm resize-none"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey && e.currentTarget.value) {
                        e.preventDefault()
                        setRule((prev) => ({
                          ...prev,
                          falsePositiveNotes: [
                            ...prev.falsePositiveNotes,
                            e.currentTarget.value,
                          ],
                        }))
                        e.currentTarget.value = ''
                      }
                    }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'yaml' && (
          <div className="card-sentinel rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Code className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Sigma YAML Output
              </h2>
              <button
                onClick={() => navigator.clipboard.writeText(ruleYaml)}
                className="flex items-center gap-2 px-3 py-1.5 rounded text-sm"
                style={{
                  backgroundColor: 'var(--surface)',
                  color: 'var(--fg)',
                }}
              >
                <Copy className="h-4 w-4" />
                Copy
              </button>
            </div>

            <pre
              className="p-4 rounded-lg overflow-x-auto"
              style={{ backgroundColor: 'var(--bg)' }}
            >
              <code
                className="text-sm font-mono whitespace-pre"
                style={{ color: 'var(--emerald-400)' }}
              >
                {ruleYaml}
              </code>
            </pre>
          </div>
        )}

        {selectedTab === 'test' && (
          <div className="card-sentinel rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              Test Results
            </h2>

            {testResult ? (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-4 gap-4">
                  <div
                    className="p-4 rounded-lg"
                    style={{ backgroundColor: 'var(--surface)' }}
                  >
                    <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{testResult.matchCount}</p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Matches</p>
                  </div>
                  <div
                    className="p-4 rounded-lg"
                    style={{ backgroundColor: 'var(--surface)' }}
                  >
                    <p className="text-2xl font-bold text-yellow-400">
                      {testResult.falsePositiveEstimate}%
                    </p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Est. False Positive Rate</p>
                  </div>
                  <div
                    className="p-4 rounded-lg"
                    style={{ backgroundColor: 'var(--surface)' }}
                  >
                    <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{testResult.executionTimeMs}ms</p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Execution Time</p>
                  </div>
                  <div
                    className="p-4 rounded-lg"
                    style={{ backgroundColor: 'var(--surface)' }}
                  >
                    <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                      {testResult.sampleMatches.length}
                    </p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Sample Matches</p>
                  </div>
                </div>

                {/* Sample Matches */}
                <div>
                  <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Sample Matches</h3>
                  <div className="space-y-2">
                    {testResult.sampleMatches.map((match, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg"
                        style={{ backgroundColor: 'var(--surface)' }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs font-mono" style={{ color: 'var(--muted)' }}>
                            {match.eventId}
                          </span>
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>
                            {new Date(match.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(match.matchedFields).map(([field, value]) => (
                            <span
                              key={field}
                              className="px-2 py-0.5 rounded text-xs"
                              style={{ backgroundColor: 'var(--bg)' }}
                            >
                              <span style={{ color: 'var(--muted)' }}>{field}:</span>{' '}
                              <span style={{ color: 'var(--emerald-400)' }}>{value}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
                <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Click "Test Rule" to validate against historical data</p>
              </div>
            )}
          </div>
        )}

        {selectedTab === 'performance' && (
          <div className="card-sentinel rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <BarChart3 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              Rule Performance Metrics
            </h2>

            <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
              <BarChart3 className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Performance metrics available after rule is deployed</p>
            </div>
          </div>
        )}
      </div>

      {/* MITRE Technique Selection Modal */}
      {showMitreModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div
            className="card-sentinel rounded-xl w-full max-w-2xl max-h-[80vh] overflow-hidden"
          >
            <div
              className="p-4 flex items-center justify-between"
              style={{ borderBottom: '1px solid var(--border)' }}
            >
              <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Select MITRE ATT&CK Techniques</h3>
              <button
                onClick={() => setShowMitreModal(false)}
                className="p-1 hover:opacity-80"
                style={{ color: 'var(--muted)' }}
              >
                <XCircle className="h-5 w-5" />
              </button>
            </div>
            <div className="p-4 overflow-y-auto max-h-[60vh]">
              <div className="space-y-2">
                {MITRE_TECHNIQUES.map((tech) => (
                  <label
                    key={tech.id}
                    className="flex items-center gap-3 p-3 rounded-lg cursor-pointer hover:opacity-90"
                    style={{ backgroundColor: 'var(--surface)' }}
                  >
                    <input
                      type="checkbox"
                      checked={rule.mitreTechniques.includes(tech.id)}
                      onChange={() => toggleMitreTechnique(tech.id)}
                      className="w-4 h-4 rounded"
                      style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg)',
                      }}
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono" style={{ color: 'var(--emerald-400)' }}>{tech.id}</span>
                        <span
                          className="text-xs px-2 py-0.5 rounded"
                          style={{
                            backgroundColor: 'var(--bg)',
                            color: 'var(--fg)',
                          }}
                        >
                          {tech.tactic}
                        </span>
                      </div>
                      <p className="text-sm mt-1" style={{ color: 'var(--fg)' }}>{tech.name}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>
            <div
              className="p-4 flex justify-end"
              style={{ borderTop: '1px solid var(--border)' }}
            >
              <button
                onClick={() => setShowMitreModal(false)}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  )
}
