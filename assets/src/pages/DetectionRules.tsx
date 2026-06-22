import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  FileCode, Shield, Search, RefreshCw, Plus, Upload, Download,
  ToggleLeft, ToggleRight, ChevronDown, ChevronRight, AlertTriangle,
  Check, X, Copy, Trash2, Edit3, Play, Filter, Loader2,
  Eye, EyeOff, Clock, Tag, Zap, Info, CheckCircle, XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { Select, SelectItem } from '@/components/ui/baseui'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SigmaRule {
  id: string
  name: string
  title?: string
  description: string
  status: 'stable' | 'test' | 'experimental' | 'deprecated'
  level: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  enabled: boolean
  author?: string
  date?: string
  modified?: string
  tags?: string[]
  logsource?: {
    category?: string
    product?: string
    service?: string
  }
  detection?: Record<string, unknown>
  falsepositives?: string[]
  content?: string
  match_count?: number
  last_match?: string
  mitre_attack?: string[]
  inserted_at?: string
  updated_at?: string
}

interface YaraRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  readonly?: boolean
  source_type?: 'database' | 'builtin_file'
  file_name?: string
  rule_count?: number
  author?: string
  category?: string
  content?: string
  tags?: string[]
  match_count?: number
  last_match?: string
  mitre_techniques?: string[]
  severity?: string
  inserted_at?: string
  updated_at?: string
  meta?: Record<string, string>
}

interface YaraStatus {
  loaded_rules: number
  total_rules: number
  last_compiled?: string
  scan_count?: number
}

interface DryRunResult {
  matches: number
  matched_events: Array<{
    event_id: string
    event_type: string
    timestamp: string
    agent_id: string
    hostname: string
  }>
  errors: string[]
}

// MITRE ATT&CK Tactics for coverage matrix
const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0040', name: 'Impact' },
]

type ActiveTab = 'sigma' | 'yara' | 'coverage'

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

const API_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const csrfToken = getCsrfToken()
  const res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...API_HEADERS,
      ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      ...(options?.headers || {}),
    },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`HTTP ${res.status}: ${body || res.statusText}`)
  }
  return res.json()
}

function normalizeArrayPayload<T>(payload: unknown, nestedKey?: string): T[] {
  const data = (payload as any)?.data ?? payload
  if (Array.isArray(data)) return data as T[]
  if (nestedKey && Array.isArray(data?.[nestedKey])) return data[nestedKey] as T[]
  if (Array.isArray(data?.rules)) return data.rules as T[]
  return []
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function DetectionRules() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('sigma')

  // Sigma rules state
  const [sigmaRules, setSigmaRules] = useState<SigmaRule[]>([])
  const [sigmaLoading, setSigmaLoading] = useState(true)
  const [sigmaError, setSigmaError] = useState<string | null>(null)
  const [sigmaSearch, setSigmaSearch] = useState('')
  const [sigmaLevelFilter, setSigmaLevelFilter] = useState<string>('all')
  const [sigmaStatusFilter, setSigmaStatusFilter] = useState<string>('all')

  // YARA rules state
  const [yaraRules, setYaraRules] = useState<YaraRule[]>([])
  const [yaraLoading, setYaraLoading] = useState(true)
  const [yaraError, setYaraError] = useState<string | null>(null)
  const [yaraSearch, setYaraSearch] = useState('')
  const [yaraSeverityFilter, setYaraSeverityFilter] = useState<string>('all')
  const [yaraCategoryFilter, setYaraCategoryFilter] = useState<string>('all')
  const [yaraSourceFilter, setYaraSourceFilter] = useState<string>('all')
  const [yaraStatusFilter, setYaraStatusFilter] = useState<string>('all')
  const [yaraStatus, setYaraStatus] = useState<YaraStatus | null>(null)

  // Editor state
  const [editingRule, setEditingRule] = useState<{ type: 'sigma' | 'yara'; rule: SigmaRule | YaraRule } | null>(null)
  const [editorContent, setEditorContent] = useState('')
  const [editorSaving, setEditorSaving] = useState(false)

  // Dry run state
  const [dryRunning, setDryRunning] = useState(false)
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null)

  // Action loading
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  // Import state
  const [showImportModal, setShowImportModal] = useState(false)
  const [importText, setImportText] = useState('')
  const [importType, setImportType] = useState<'sigma' | 'yara'>('sigma')

  // =========================================================================
  // Data Fetching
  // =========================================================================

  const fetchSigmaRules = useCallback(async () => {
    setSigmaLoading(true)
    setSigmaError(null)
    try {
      const data = await apiFetch<unknown>('/api/v1/rules/sigma')
      setSigmaRules(normalizeArrayPayload<SigmaRule>(data, 'rules'))
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch Sigma rules'
      setSigmaError(msg)
    } finally {
      setSigmaLoading(false)
    }
  }, [])

  const fetchYaraRules = useCallback(async () => {
    setYaraLoading(true)
    setYaraError(null)
    try {
      const [rulesData, statusData] = await Promise.all([
        apiFetch<unknown>('/api/v1/rules/yara'),
        apiFetch<YaraStatus>('/api/v1/rules/yara/status').catch(() => null),
      ])
      setYaraRules(normalizeArrayPayload<YaraRule>(rulesData, 'rules'))
      if (statusData) setYaraStatus(statusData)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch YARA rules'
      setYaraError(msg)
    } finally {
      setYaraLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSigmaRules()
    fetchYaraRules()
  }, [fetchSigmaRules, fetchYaraRules])

  // =========================================================================
  // Actions
  // =========================================================================

  const toggleSigmaRule = useCallback(async (ruleId: string, enabled: boolean) => {
    setActionLoading(ruleId)
    try {
      await apiFetch(`/api/v1/rules/sigma/${ruleId}`, {
        method: 'PUT',
        body: JSON.stringify({ sigma_rule: { enabled } }),
      })
      setSigmaRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled } : r))
    } catch (err) {
      logger.error('Failed to toggle Sigma rule:', err)
    } finally {
      setActionLoading(null)
    }
  }, [])

  const toggleYaraRule = useCallback(async (ruleId: string, enabled: boolean) => {
    setActionLoading(ruleId)
    try {
      await apiFetch(`/api/v1/rules/yara/${ruleId}`, {
        method: 'PUT',
        body: JSON.stringify({ yara_rule: { enabled } }),
      })
      setYaraRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled } : r))
    } catch (err) {
      logger.error('Failed to toggle YARA rule:', err)
    } finally {
      setActionLoading(null)
    }
  }, [])

  const deleteSigmaRule = useCallback(async (ruleId: string) => {
    if (!confirm('Delete this Sigma rule? This cannot be undone.')) return
    setActionLoading(ruleId)
    try {
      await apiFetch(`/api/v1/rules/sigma/${ruleId}`, { method: 'DELETE' })
      setSigmaRules(prev => prev.filter(r => r.id !== ruleId))
    } catch (err) {
      logger.error('Failed to delete Sigma rule:', err)
    } finally {
      setActionLoading(null)
    }
  }, [])

  const deleteYaraRule = useCallback(async (ruleId: string) => {
    if (!confirm('Delete this YARA rule? This cannot be undone.')) return
    setActionLoading(ruleId)
    try {
      await apiFetch(`/api/v1/rules/yara/${ruleId}`, { method: 'DELETE' })
      setYaraRules(prev => prev.filter(r => r.id !== ruleId))
    } catch (err) {
      logger.error('Failed to delete YARA rule:', err)
    } finally {
      setActionLoading(null)
    }
  }, [])

  const handleSaveRule = useCallback(async () => {
    if (!editingRule) return
    setEditorSaving(true)
    try {
      const { type, rule } = editingRule
      const endpoint = type === 'sigma' ? `/api/v1/rules/sigma/${rule.id}` : `/api/v1/rules/yara/${rule.id}`
      const bodyKey = type === 'sigma' ? 'sigma_rule' : 'yara_rule'
      if (type === 'yara' && 'readonly' in rule && rule.readonly) {
        setEditingRule(null)
        return
      }
      await apiFetch(endpoint, {
        method: 'PUT',
        body: JSON.stringify({ [bodyKey]: { content: editorContent } }),
      })
      // Refresh rules
      if (type === 'sigma') await fetchSigmaRules()
      else await fetchYaraRules()
      setEditingRule(null)
      toast.success(`${type === 'sigma' ? 'Sigma' : 'YARA'} rule saved`)
    } catch (err) {
      logger.error('Failed to save rule:', err)
      toast.error('Failed to save rule: ' + (err instanceof Error ? err.message : 'Unknown error'))
    } finally {
      setEditorSaving(false)
    }
  }, [editingRule, editorContent, fetchSigmaRules, fetchYaraRules])

  const handleDryRun = useCallback(async () => {
    if (!editingRule) return
    setDryRunning(true)
    setDryRunResult(null)
    try {
      const result = await apiFetch<DryRunResult>('/api/v1/rules/yara/scan', {
        method: 'POST',
        body: JSON.stringify({ content: editorContent, dry_run: true }),
      })
      setDryRunResult(result)
    } catch (err) {
      setDryRunResult({
        matches: 0,
        matched_events: [],
        errors: [err instanceof Error ? err.message : 'Dry run failed'],
      })
    } finally {
      setDryRunning(false)
    }
  }, [editingRule, editorContent])

  const handleImportRules = useCallback(async () => {
    if (!importText.trim()) return
    try {
      const endpoint = importType === 'sigma' ? '/api/v1/rules/sigma' : '/api/v1/rules/yara'
      const bodyKey = importType === 'sigma' ? 'sigma_rule' : 'yara_rule'
      await apiFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({ [bodyKey]: { content: importText } }),
      })
      setShowImportModal(false)
      setImportText('')
      if (importType === 'sigma') await fetchSigmaRules()
      else await fetchYaraRules()
      toast.success(`${importType === 'sigma' ? 'Sigma' : 'YARA'} rule imported`)
    } catch (err) {
      logger.error('Failed to import rule:', err)
      toast.error('Import failed: ' + (err instanceof Error ? err.message : 'Unknown error'))
    }
  }, [importText, importType, fetchSigmaRules, fetchYaraRules])

  const handleExportRules = useCallback(() => {
    const rules = activeTab === 'sigma' ? sigmaRules : yaraRules
    const content = JSON.stringify(rules, null, 2)
    const blob = new Blob([content], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `tamandua-${activeTab}-rules-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [activeTab, sigmaRules, yaraRules])

  // =========================================================================
  // Filtered data
  // =========================================================================

  const filteredSigmaRules = useMemo(() => {
    let result = sigmaRules
    if (sigmaSearch) {
      const q = sigmaSearch.toLowerCase()
      result = result.filter(r =>
        (r.name || '').toLowerCase().includes(q) ||
        (r.title || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q) ||
        (r.tags || []).some(t => t.toLowerCase().includes(q)) ||
        (r.mitre_attack || []).some(m => m.toLowerCase().includes(q))
      )
    }
    if (sigmaLevelFilter !== 'all') {
      result = result.filter(r => r.level === sigmaLevelFilter)
    }
    if (sigmaStatusFilter !== 'all') {
      if (sigmaStatusFilter === 'enabled') {
        result = result.filter(r => r.enabled)
      } else if (sigmaStatusFilter === 'disabled') {
        result = result.filter(r => !r.enabled)
      } else {
        result = result.filter(r => r.status === sigmaStatusFilter)
      }
    }
    return result
  }, [sigmaRules, sigmaSearch, sigmaLevelFilter, sigmaStatusFilter])

  const filteredYaraRules = useMemo(() => {
    let result = yaraRules
    if (yaraSearch) {
      const q = yaraSearch.toLowerCase()
      result = result.filter(r =>
        (r.name || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q) ||
        (r.category || '').toLowerCase().includes(q) ||
        (r.tags || []).some(t => t.toLowerCase().includes(q))
      )
    }
    if (yaraSeverityFilter !== 'all') {
      result = result.filter(r => (r.severity || 'unknown') === yaraSeverityFilter)
    }
    if (yaraCategoryFilter !== 'all') {
      result = result.filter(r => (r.category || 'uncategorized') === yaraCategoryFilter)
    }
    if (yaraSourceFilter !== 'all') {
      result = result.filter(r => (r.source_type || 'database') === yaraSourceFilter)
    }
    if (yaraStatusFilter !== 'all') {
      if (yaraStatusFilter === 'enabled') {
        result = result.filter(r => r.enabled)
      } else if (yaraStatusFilter === 'disabled') {
        result = result.filter(r => !r.enabled)
      } else if (yaraStatusFilter === 'readonly') {
        result = result.filter(r => r.readonly || r.source_type === 'builtin_file')
      } else if (yaraStatusFilter === 'editable') {
        result = result.filter(r => !r.readonly && r.source_type !== 'builtin_file')
      }
    }
    return result
  }, [yaraRules, yaraSearch, yaraSeverityFilter, yaraCategoryFilter, yaraSourceFilter, yaraStatusFilter])

  const yaraCategories = useMemo(() => {
    return Array.from(new Set(yaraRules.map(rule => rule.category || 'uncategorized'))).sort()
  }, [yaraRules])

  const yaraSeverities = useMemo(() => {
    return Array.from(new Set(yaraRules.map(rule => rule.severity || 'unknown'))).sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'informational', 'unknown']
      return order.indexOf(a) - order.indexOf(b)
    })
  }, [yaraRules])

  // MITRE coverage calculation
  const mitreCoverage = useMemo(() => {
    const coverageMap: Record<string, { sigma: number; yara: number; techniques: Set<string> }> = {}

    MITRE_TACTICS.forEach(tactic => {
      coverageMap[tactic.id] = { sigma: 0, yara: 0, techniques: new Set() }
    })

    // Map technique prefixes to tactics
    const techToTactic: Record<string, string> = {
      'T1190': 'TA0001', 'T1566': 'TA0001', 'T1133': 'TA0001', 'T1078': 'TA0001',
      'T1059': 'TA0002', 'T1204': 'TA0002', 'T1569': 'TA0002', 'T1047': 'TA0002',
      'T1547': 'TA0003', 'T1053': 'TA0003', 'T1543': 'TA0003', 'T1136': 'TA0003',
      'T1548': 'TA0004', 'T1134': 'TA0004', 'T1068': 'TA0004',
      'T1055': 'TA0005', 'T1027': 'TA0005', 'T1562': 'TA0005', 'T1070': 'TA0005', 'T1036': 'TA0005',
      'T1003': 'TA0006', 'T1558': 'TA0006', 'T1552': 'TA0006', 'T1110': 'TA0006',
      'T1087': 'TA0007', 'T1082': 'TA0007', 'T1083': 'TA0007', 'T1046': 'TA0007',
      'T1021': 'TA0008', 'T1570': 'TA0008', 'T1080': 'TA0008',
      'T1560': 'TA0009', 'T1005': 'TA0009', 'T1074': 'TA0009',
      'T1041': 'TA0010', 'T1048': 'TA0010', 'T1567': 'TA0010',
      'T1071': 'TA0011', 'T1105': 'TA0011', 'T1573': 'TA0011', 'T1572': 'TA0011',
      'T1486': 'TA0040', 'T1489': 'TA0040', 'T1490': 'TA0040',
    }

    sigmaRules.forEach(rule => {
      if (!rule.enabled) return
      const techniques = rule.mitre_attack || rule.tags?.filter(t => t.startsWith('attack.t') || t.match(/^T\d{4}/)) || []
      techniques.forEach(tech => {
        const normalized = tech.replace('attack.', '').toUpperCase()
        const baseT = normalized.split('.')[0]
        const tacticId = techToTactic[baseT]
        if (tacticId && coverageMap[tacticId]) {
          coverageMap[tacticId].sigma++
          coverageMap[tacticId].techniques.add(normalized)
        }
      })
    })

    yaraRules.forEach(rule => {
      if (!rule.enabled) return
      const techniques = rule.mitre_techniques || []
      techniques.forEach(tech => {
        const baseT = tech.split('.')[0]
        const tacticId = techToTactic[baseT]
        if (tacticId && coverageMap[tacticId]) {
          coverageMap[tacticId].yara++
          coverageMap[tacticId].techniques.add(tech)
        }
      })
    })

    return coverageMap
  }, [sigmaRules, yaraRules])

  const totalCoveredTactics = Object.values(mitreCoverage).filter(v => v.techniques.size > 0).length

  // =========================================================================
  // Stats
  // =========================================================================

  const sigmaStats = useMemo(() => ({
    total: sigmaRules.length,
    enabled: sigmaRules.filter(r => r.enabled).length,
    disabled: sigmaRules.filter(r => !r.enabled).length,
    critical: sigmaRules.filter(r => r.level === 'critical' && r.enabled).length,
    high: sigmaRules.filter(r => r.level === 'high' && r.enabled).length,
  }), [sigmaRules])

  const yaraStats = useMemo(() => ({
    total: yaraRules.length,
    enabled: yaraRules.filter(r => r.enabled).length,
    disabled: yaraRules.filter(r => !r.enabled).length,
  }), [yaraRules])

  // =========================================================================
  // Render
  // =========================================================================

  return (
    <MainLayout title="Detection Rules">
      <Head title="Detection Rules - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard
            icon={FileCode}
            iconColor="text-[var(--med)]"
            iconBg="bg-[var(--med-bg)]"
            value={sigmaStats.total}
            label="Sigma Rules"
            subValue={`${sigmaStats.enabled} active`}
          />
          <StatCard
            icon={Shield}
            iconColor="text-[var(--sol-magenta)]"
            iconBg="bg-[rgba(217,70,239,0.12)]"
            value={yaraStats.total}
            label="YARA Rules"
            subValue={yaraStatus ? `${yaraStatus.loaded_rules} loaded` : `${yaraStats.enabled} active`}
          />
          <StatCard
            icon={AlertTriangle}
            iconColor="text-[var(--crit)]"
            iconBg="bg-[var(--crit-bg)]"
            value={sigmaStats.critical}
            label="Critical Rules"
            subValue={`${sigmaStats.high} high`}
          />
          <StatCard
            icon={Zap}
            iconColor="text-[var(--high)]"
            iconBg="bg-[var(--high-bg)]"
            value={sigmaStats.enabled + yaraStats.enabled}
            label="Active Rules"
            subValue="across all types"
          />
          <StatCard
            icon={Shield}
            iconColor="text-[var(--emerald-400)]"
            iconBg="bg-[var(--emerald-glow)]"
            value={totalCoveredTactics}
            label="ATT&CK Tactics"
            subValue={`of ${MITRE_TACTICS.length} covered`}
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 border-b border-[var(--border)] pb-2">
            {([
              { id: 'sigma' as ActiveTab, label: 'Sigma Rules', icon: FileCode, count: sigmaStats.total },
              { id: 'yara' as ActiveTab, label: 'YARA Rules', icon: Shield, count: yaraStats.total },
              { id: 'coverage' as ActiveTab, label: 'ATT&CK Coverage', icon: Shield, count: totalCoveredTactics },
            ]).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-t-[var(--r-md)] text-sm font-medium transition-colors',
                  activeTab === tab.id
                    ? 'bg-[var(--surface)] text-[var(--fg)] border border-[var(--border)] border-b-[var(--surface)]'
                    : 'text-[var(--muted)] hover:text-[var(--fg)]'
                )}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
                <span className="text-xs bg-[var(--surface-2)] px-1.5 py-0.5 rounded-[var(--r-sm)]">{tab.count}</span>
              </button>
            ))}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setImportType(activeTab === 'yara' ? 'yara' : 'sigma'); setShowImportModal(true) }}
              className="flex items-center gap-2 px-3 py-2 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] rounded-[var(--r-md)] text-sm text-[var(--muted)] transition-colors"
            >
              <Upload className="h-4 w-4" />
              Import
            </button>
            <button
              onClick={handleExportRules}
              disabled={activeTab === 'coverage'}
              className="flex items-center gap-2 px-3 py-2 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] rounded-[var(--r-md)] text-sm text-[var(--muted)] transition-colors disabled:opacity-50"
            >
              <Download className="h-4 w-4" />
              Export
            </button>
            <button
              onClick={() => activeTab === 'sigma' ? fetchSigmaRules() : fetchYaraRules()}
              className="flex items-center gap-2 px-3 py-2 bg-[var(--emerald-600)] hover:bg-[var(--emerald-500)] rounded-[var(--r-md)] text-sm text-white font-medium transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>

        {/* ================================================================= */}
        {/* SIGMA RULES TAB */}
        {/* ================================================================= */}
        {activeTab === 'sigma' && (
          <div className="bg-[var(--surface)] rounded-[var(--r-lg)] border border-[var(--border)]">
            {/* Toolbar */}
            <div className="p-4 border-b border-[var(--border)] flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                <input
                  type="text"
                  placeholder="Search Sigma rules by name, description, MITRE technique, tags..."
                  value={sigmaSearch}
                  onChange={e => setSigmaSearch(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-[var(--emerald-500)] text-sm"
                />
              </div>

              <Select
                value={sigmaLevelFilter}
                onValueChange={setSigmaLevelFilter}
                className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] px-3 py-2 text-sm text-[var(--muted)] focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Levels</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="informational">Informational</SelectItem>
              </Select>

              <Select
                value={sigmaStatusFilter}
                onValueChange={setSigmaStatusFilter}
                className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] px-3 py-2 text-sm text-[var(--muted)] focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="enabled">Enabled</SelectItem>
                <SelectItem value="disabled">Disabled</SelectItem>
                <SelectItem value="stable">Stable</SelectItem>
                <SelectItem value="test">Test</SelectItem>
                <SelectItem value="experimental">Experimental</SelectItem>
              </Select>

              <span className="text-xs text-[var(--subtle)]">
                {filteredSigmaRules.length} of {sigmaRules.length} rules
              </span>
            </div>

            {/* Rules List */}
            {sigmaLoading ? (
              <LoadingState message="Loading Sigma rules..." />
            ) : sigmaError ? (
              <ErrorState message={sigmaError} onRetry={fetchSigmaRules} />
            ) : filteredSigmaRules.length === 0 ? (
              <EmptyState
                icon={FileCode}
                message={sigmaRules.length === 0 ? 'No Sigma rules configured' : 'No rules match your filters'}
                submessage={sigmaRules.length === 0 ? 'Import Sigma rules or create new ones to get started' : undefined}
              />
            ) : (
              <div className="divide-y divide-[var(--hairline)] max-h-[600px] overflow-y-auto">
                {filteredSigmaRules.map(rule => (
                  <SigmaRuleRow
                    key={rule.id}
                    rule={rule}
                    loading={actionLoading === rule.id}
                    onToggle={(enabled) => toggleSigmaRule(rule.id, enabled)}
                    onEdit={() => { setEditingRule({ type: 'sigma', rule }); setEditorContent(rule.content || '') }}
                    onDelete={() => deleteSigmaRule(rule.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* YARA RULES TAB */}
        {/* ================================================================= */}
        {activeTab === 'yara' && (
          <div className="bg-[var(--surface)] rounded-[var(--r-lg)] border border-[var(--border)]">
            {/* YARA Status Bar */}
            {yaraStatus && (
              <div className="px-4 py-2 border-b border-[var(--border)] bg-[var(--surface-2)] flex items-center gap-4 text-xs text-[var(--muted)]">
                <span className="flex items-center gap-1.5">
                  <CheckCircle className="h-3.5 w-3.5 text-[var(--emerald-400)]" />
                  {yaraStatus.loaded_rules} rules compiled
                </span>
                {yaraStatus.scan_count != null && (
                  <span>{yaraStatus.scan_count} scans performed</span>
                )}
                {yaraStatus.last_compiled && (
                  <span>Last compiled: {formatDate(yaraStatus.last_compiled)}</span>
                )}
              </div>
            )}

            {/* Toolbar */}
            <div className="p-4 border-b border-[var(--border)] flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                <input
                  type="text"
                  placeholder="Search YARA rules by name, description, category, tags..."
                  value={yaraSearch}
                  onChange={e => setYaraSearch(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-[var(--emerald-500)] text-sm"
                />
              </div>

              <Select
                value={yaraSeverityFilter}
                onValueChange={setYaraSeverityFilter}
                className="px-3 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] text-sm focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Severities</SelectItem>
                {yaraSeverities.map(severity => (
                  <SelectItem key={severity} value={severity}>{severity}</SelectItem>
                ))}
              </Select>

              <Select
                value={yaraCategoryFilter}
                onValueChange={setYaraCategoryFilter}
                className="px-3 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] text-sm focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Categories</SelectItem>
                {yaraCategories.map(category => (
                  <SelectItem key={category} value={category}>{category}</SelectItem>
                ))}
              </Select>

              <Select
                value={yaraSourceFilter}
                onValueChange={setYaraSourceFilter}
                className="px-3 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] text-sm focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Sources</SelectItem>
                <SelectItem value="builtin_file">Built-in files</SelectItem>
                <SelectItem value="database">Database rules</SelectItem>
              </Select>

              <Select
                value={yaraStatusFilter}
                onValueChange={setYaraStatusFilter}
                className="px-3 py-2 bg-[var(--surface-2)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg)] text-sm focus:outline-none focus:border-[var(--emerald-500)]"
              >
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="enabled">Enabled</SelectItem>
                <SelectItem value="disabled">Disabled</SelectItem>
                <SelectItem value="readonly">Built-in/Read-only</SelectItem>
                <SelectItem value="editable">Editable</SelectItem>
              </Select>

              <span className="text-xs text-[var(--subtle)]">
                {filteredYaraRules.length} of {yaraRules.length} rules
              </span>
            </div>

            {/* Rules List */}
            {yaraLoading ? (
              <LoadingState message="Loading YARA rules..." />
            ) : yaraError ? (
              <ErrorState message={yaraError} onRetry={fetchYaraRules} />
            ) : filteredYaraRules.length === 0 ? (
              <EmptyState
                icon={Shield}
                message={yaraRules.length === 0 ? 'No YARA rules configured' : 'No rules match your filters'}
                submessage={yaraRules.length === 0 ? 'Import YARA rules to enable file scanning capabilities' : undefined}
              />
            ) : (
              <div className="divide-y divide-[var(--hairline)] max-h-[600px] overflow-y-auto">
                {filteredYaraRules.map(rule => (
                  <YaraRuleRow
                    key={rule.id}
                    rule={rule}
                    loading={actionLoading === rule.id}
                    onToggle={(enabled) => !rule.readonly && toggleYaraRule(rule.id, enabled)}
                    onEdit={() => { setEditingRule({ type: 'yara', rule }); setEditorContent(rule.content || '') }}
                    onDelete={() => !rule.readonly && deleteYaraRule(rule.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* ATT&CK COVERAGE TAB */}
        {/* ================================================================= */}
        {activeTab === 'coverage' && (
          <div className="bg-[var(--surface)] rounded-[var(--r-lg)] border border-[var(--border)] p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Shield className="h-5 w-5 text-[var(--emerald-400)]" />
                  MITRE ATT&CK Coverage Matrix
                </h2>
                <p className="text-sm text-[var(--muted)] mt-1">
                  Detection coverage across {MITRE_TACTICS.length} ATT&CK tactics based on enabled rules
                </p>
              </div>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-[var(--r-sm)] bg-[var(--med-bg)] border border-[var(--med)]"></span>
                  Sigma
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-[var(--r-sm)] bg-[rgba(217,70,239,0.12)] border border-[var(--sol-magenta)]"></span>
                  YARA
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
              {MITRE_TACTICS.map(tactic => {
                const coverage = mitreCoverage[tactic.id]
                const techniqueCount = coverage?.techniques.size || 0
                const hasCoverage = techniqueCount > 0
                const coverageLevel = techniqueCount >= 5 ? 'high' : techniqueCount >= 2 ? 'medium' : techniqueCount >= 1 ? 'low' : 'none'

                return (
                  <div
                    key={tactic.id}
                    className={cn(
                      'p-4 rounded-[var(--r-md)] border transition-colors',
                      coverageLevel === 'high' ? 'bg-[var(--emerald-glow)] border-[var(--emerald-700)]' :
                      coverageLevel === 'medium' ? 'bg-[var(--high-bg)] border-[rgba(245,165,36,0.3)]' :
                      coverageLevel === 'low' ? 'bg-[var(--crit-bg)] border-[rgba(240,80,110,0.3)]' :
                      'bg-[var(--surface-2)] border-[var(--hairline)]'
                    )}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-[var(--subtle)]">{tactic.id}</span>
                      {hasCoverage ? (
                        <CheckCircle className={cn(
                          'h-3.5 w-3.5',
                          coverageLevel === 'high' ? 'text-[var(--emerald-400)]' :
                          coverageLevel === 'medium' ? 'text-[var(--high)]' : 'text-[var(--crit)]'
                        )} />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 text-[var(--dim)]" />
                      )}
                    </div>
                    <h3 className={cn(
                      'text-sm font-medium mb-2',
                      hasCoverage ? 'text-[var(--fg)]' : 'text-[var(--subtle)]'
                    )}>
                      {tactic.name}
                    </h3>
                    <div className="flex items-center gap-2 text-xs">
                      {coverage?.sigma > 0 && (
                        <span className="px-1.5 py-0.5 bg-[var(--med-bg)] text-[var(--med)] rounded-[var(--r-sm)]">
                          {coverage.sigma} Sigma
                        </span>
                      )}
                      {coverage?.yara > 0 && (
                        <span className="px-1.5 py-0.5 bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)] rounded-[var(--r-sm)]">
                          {coverage.yara} YARA
                        </span>
                      )}
                      {!hasCoverage && (
                        <span className="text-[var(--dim)]">No coverage</span>
                      )}
                    </div>
                    {hasCoverage && (
                      <div className="mt-2 text-[10px] text-[var(--subtle)]">
                        {techniqueCount} technique{techniqueCount !== 1 ? 's' : ''} covered
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Summary bar */}
            <div className="mt-6 p-4 bg-[var(--surface-2)] rounded-[var(--r-md)]">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-[var(--muted)] font-medium">Overall Coverage</span>
                <span className="text-sm text-[var(--fg)] font-bold">
                  {totalCoveredTactics} / {MITRE_TACTICS.length} tactics ({Math.round((totalCoveredTactics / MITRE_TACTICS.length) * 100)}%)
                </span>
              </div>
              <div className="h-2.5 bg-[var(--surface-3)] rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-[var(--emerald-600)] to-[var(--emerald-400)] rounded-full transition-all"
                  style={{ width: `${(totalCoveredTactics / MITRE_TACTICS.length) * 100}%` }}
                />
              </div>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* RULE EDITOR MODAL */}
        {/* ================================================================= */}
        {editingRule && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[var(--r-lg)] shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col">
              {/* Header */}
              <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
                <div className="flex items-center gap-3">
                  <div className={cn(
                    'p-2 rounded-[var(--r-md)]',
                    editingRule.type === 'sigma' ? 'bg-[var(--med-bg)]' : 'bg-[rgba(217,70,239,0.12)]'
                  )}>
                    {editingRule.type === 'sigma' ? (
                      <FileCode className="h-5 w-5 text-[var(--med)]" />
                    ) : (
                      <Shield className="h-5 w-5 text-[var(--sol-magenta)]" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-[var(--fg)] font-semibold">
                      Edit {editingRule.type === 'sigma' ? 'Sigma' : 'YARA'} Rule
                    </h3>
                    <p className="text-xs text-[var(--muted)]">{editingRule.rule.name}</p>
                  </div>
                </div>
                <button
                  onClick={() => { setEditingRule(null); setDryRunResult(null) }}
                  className="p-2 hover:bg-[var(--surface-2)] rounded-[var(--r-md)] transition-colors"
                >
                  <X className="h-5 w-5 text-[var(--muted)]" />
                </button>
              </div>

              {/* Editor */}
              <div className="flex-1 overflow-hidden flex flex-col">
                <textarea
                  value={editorContent}
                  onChange={e => setEditorContent(e.target.value)}
                  spellCheck={false}
                  className="flex-1 w-full p-4 bg-[var(--bg)] text-[var(--fg-2)] font-mono text-sm resize-none focus:outline-none border-0 min-h-[400px]"
                  placeholder={editingRule.type === 'sigma'
                    ? 'title: My Rule\nstatus: test\nlevel: medium\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: suspicious\n  condition: selection'
                    : 'rule my_rule {\n  meta:\n    description = "My YARA rule"\n    severity = "high"\n  strings:\n    $s1 = "malicious_string"\n  condition:\n    $s1\n}'
                  }
                />

                {/* Dry run results */}
                {dryRunResult && (
                  <div className="p-3 border-t border-[var(--border)] bg-[var(--surface-2)] max-h-48 overflow-y-auto">
                    <div className="flex items-center gap-2 mb-2">
                      <Play className="h-3.5 w-3.5 text-[var(--emerald-400)]" />
                      <span className="text-xs font-medium text-[var(--muted)]">Dry Run Results</span>
                    </div>
                    {dryRunResult.errors.length > 0 ? (
                      <div className="space-y-1">
                        {dryRunResult.errors.map((err, i) => (
                          <div key={i} className="text-xs text-[var(--crit)] bg-[var(--crit-bg)] rounded-[var(--r-sm)] px-2 py-1">
                            {err}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>
                        <p className="text-xs text-[var(--muted)] mb-2">
                          {dryRunResult.matches} match{dryRunResult.matches !== 1 ? 'es' : ''} against recent events
                        </p>
                        {dryRunResult.matched_events.length > 0 && (
                          <div className="space-y-1">
                            {dryRunResult.matched_events.slice(0, 5).map((evt, i) => (
                              <div key={i} className="text-xs bg-[var(--surface-3)] rounded-[var(--r-sm)] px-2 py-1 flex items-center gap-3 text-[var(--muted)]">
                                <span className="font-mono">{evt.event_type}</span>
                                <span>{evt.hostname}</span>
                                <span className="text-[var(--subtle)]">{evt.timestamp}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between p-4 border-t border-[var(--border)]">
                <button
                  onClick={handleDryRun}
                  disabled={dryRunning || !editorContent.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] rounded-[var(--r-md)] text-sm text-[var(--muted)] transition-colors disabled:opacity-50"
                >
                  {dryRunning ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  Test Rule (Dry Run)
                </button>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => { setEditingRule(null); setDryRunResult(null) }}
                    className="px-4 py-2 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] rounded-[var(--r-md)] text-sm text-[var(--muted)] transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveRule}
                    disabled={
                      editorSaving ||
                      !editorContent.trim() ||
                      (editingRule.type === 'yara' && 'readonly' in editingRule.rule && editingRule.rule.readonly)
                    }
                    className="flex items-center gap-2 px-4 py-2 bg-[var(--emerald-600)] hover:bg-[var(--emerald-500)] rounded-[var(--r-md)] text-sm text-white font-medium transition-colors disabled:opacity-50"
                  >
                    {editorSaving ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Check className="h-4 w-4" />
                    )}
                    {editingRule.type === 'yara' && 'readonly' in editingRule.rule && editingRule.rule.readonly ? 'Read-only Built-in Rule' : 'Save Rule'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* IMPORT MODAL */}
        {/* ================================================================= */}
        {showImportModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[var(--r-lg)] shadow-2xl w-full max-w-2xl">
              {/* Header */}
              <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
                <h3 className="text-[var(--fg)] font-semibold flex items-center gap-2">
                  <Upload className="h-5 w-5 text-[var(--emerald-400)]" />
                  Import {importType === 'sigma' ? 'Sigma' : 'YARA'} Rule
                </h3>
                <button
                  onClick={() => { setShowImportModal(false); setImportText('') }}
                  className="p-2 hover:bg-[var(--surface-2)] rounded-[var(--r-md)] transition-colors"
                >
                  <X className="h-5 w-5 text-[var(--muted)]" />
                </button>
              </div>

              {/* Type selector */}
              <div className="px-4 pt-4 flex items-center gap-2">
                <button
                  onClick={() => setImportType('sigma')}
                  className={cn(
                    'px-3 py-1.5 rounded-[var(--r-md)] text-sm font-medium transition-colors',
                    importType === 'sigma'
                      ? 'bg-[var(--med-bg)] text-[var(--med)] border border-[var(--med)]'
                      : 'bg-[var(--surface-2)] text-[var(--muted)] border border-[var(--border)]'
                  )}
                >
                  Sigma Rule
                </button>
                <button
                  onClick={() => setImportType('yara')}
                  className={cn(
                    'px-3 py-1.5 rounded-[var(--r-md)] text-sm font-medium transition-colors',
                    importType === 'yara'
                      ? 'bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)] border border-[var(--sol-magenta)]'
                      : 'bg-[var(--surface-2)] text-[var(--muted)] border border-[var(--border)]'
                  )}
                >
                  YARA Rule
                </button>
              </div>

              {/* Content */}
              <div className="p-4">
                <textarea
                  value={importText}
                  onChange={e => setImportText(e.target.value)}
                  spellCheck={false}
                  rows={15}
                  className="w-full p-3 bg-[var(--bg)] border border-[var(--border)] rounded-[var(--r-md)] text-[var(--fg-2)] font-mono text-sm resize-none focus:outline-none focus:border-[var(--emerald-500)]"
                  placeholder={importType === 'sigma'
                    ? 'Paste your Sigma rule in YAML format here...\n\ntitle: My Detection Rule\nstatus: test\nlevel: high\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: suspicious\n  condition: selection'
                    : 'Paste your YARA rule here...\n\nrule my_rule {\n  meta:\n    description = "My detection"\n  strings:\n    $s1 = "pattern"\n  condition:\n    $s1\n}'
                  }
                />
              </div>

              {/* Footer */}
              <div className="flex items-center justify-end gap-2 p-4 border-t border-[var(--border)]">
                <button
                  onClick={() => { setShowImportModal(false); setImportText('') }}
                  className="px-4 py-2 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] rounded-[var(--r-md)] text-sm text-[var(--muted)] transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleImportRules}
                  disabled={!importText.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-[var(--emerald-600)] hover:bg-[var(--emerald-500)] rounded-[var(--r-md)] text-sm text-white font-medium transition-colors disabled:opacity-50"
                >
                  <Upload className="h-4 w-4" />
                  Import Rule
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}

// ===========================================================================
// Sub-components
// ===========================================================================

function StatCard({ icon: Icon, iconColor, iconBg, value, label, subValue }: {
  icon: React.ElementType
  iconColor: string
  iconBg: string
  value: number
  label: string
  subValue?: string
}) {
  return (
    <div className="bg-[var(--surface)] rounded-[var(--r-lg)] border border-[var(--border)] p-4">
      <div className="flex items-center gap-3">
        <div className={cn('p-2 rounded-[var(--r-md)]', iconBg)}>
          <Icon className={cn('h-5 w-5', iconColor)} />
        </div>
        <div>
          <p className="text-2xl font-bold text-[var(--fg)]">{value}</p>
          <p className="text-sm text-[var(--muted)]">{label}</p>
          {subValue && <p className="text-xs text-[var(--subtle)]">{subValue}</p>}
        </div>
      </div>
    </div>
  )
}

function LoadingState({ message }: { message: string }) {
  return (
    <div className="p-12 text-center text-[var(--subtle)]">
      <Loader2 className="h-12 w-12 mx-auto mb-4 opacity-50 animate-spin" />
      <p>{message}</p>
    </div>
  )
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="p-12 text-center">
      <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-[var(--crit)] opacity-60" />
      <p className="text-[var(--muted)] mb-2">Failed to load rules</p>
      <p className="text-sm text-[var(--subtle)] mb-4">{message}</p>
      <button
        onClick={onRetry}
        className="text-sm text-[var(--emerald-400)] hover:text-[var(--emerald-200)] underline"
      >
        Try Again
      </button>
    </div>
  )
}

function EmptyState({ icon: Icon, message, submessage }: {
  icon: React.ElementType
  message: string
  submessage?: string
}) {
  return (
    <div className="p-12 text-center text-[var(--subtle)]">
      <Icon className="h-12 w-12 mx-auto mb-4 opacity-40" />
      <p className="text-lg">{message}</p>
      {submessage && <p className="text-sm mt-2">{submessage}</p>}
    </div>
  )
}

// Sigma Rule Row
function SigmaRuleRow({ rule, loading, onToggle, onEdit, onDelete }: {
  rule: SigmaRule
  loading: boolean
  onToggle: (enabled: boolean) => void
  onEdit: () => void
  onDelete: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  // Severity badges with design tokens
  const levelStyles: Record<string, string> = {
    critical: 'bg-[var(--crit-bg)] text-[var(--crit)] border-[rgba(240,80,110,0.3)]',
    high: 'bg-[var(--high-bg)] text-[var(--high)] border-[rgba(245,165,36,0.3)]',
    medium: 'bg-[var(--med-bg)] text-[var(--med)] border-[rgba(91,156,242,0.3)]',
    low: 'bg-[var(--low-bg)] text-[var(--low)] border-[rgba(122,138,146,0.3)]',
    informational: 'bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]',
  }

  const statusStyles: Record<string, string> = {
    stable: 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]',
    test: 'bg-[var(--high-bg)] text-[var(--high)]',
    experimental: 'bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)]',
    deprecated: 'bg-[var(--surface-2)] text-[var(--subtle)]',
  }

  return (
    <div className={cn('transition-colors', !rule.enabled && 'opacity-60')}>
      <div
        className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--surface-2)] cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Expand arrow */}
        <button className="shrink-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-[var(--muted)]" />
          ) : (
            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
          )}
        </button>

        {/* Toggle */}
        <button
          onClick={(e) => { e.stopPropagation(); onToggle(!rule.enabled) }}
          disabled={loading}
          className="shrink-0"
          title={rule.enabled ? 'Disable rule' : 'Enable rule'}
        >
          {loading ? (
            <Loader2 className="h-5 w-5 text-[var(--muted)] animate-spin" />
          ) : rule.enabled ? (
            <ToggleRight className="h-5 w-5 text-[var(--emerald-400)]" />
          ) : (
            <ToggleLeft className="h-5 w-5 text-[var(--subtle)]" />
          )}
        </button>

        {/* Level badge */}
        <span className={cn('text-[10px] px-1.5 py-0.5 rounded-[var(--r-sm)] border font-medium shrink-0 w-20 text-center uppercase', levelStyles[rule.level] || levelStyles.medium)}>
          {rule.level}
        </span>

        {/* Rule info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--fg)] truncate">
              {rule.title || rule.name}
            </span>
            <span className={cn('text-[10px] px-1.5 py-0.5 rounded-[var(--r-sm)]', statusStyles[rule.status] || statusStyles.test)}>
              {rule.status}
            </span>
          </div>
          <p className="text-xs text-[var(--subtle)] truncate mt-0.5">{rule.description}</p>
        </div>

        {/* Tags/MITRE */}
        <div className="hidden lg:flex items-center gap-1 shrink-0">
          {(rule.mitre_attack || []).slice(0, 3).map(tech => (
            <span key={tech} className="text-[10px] bg-[var(--surface-2)] text-[var(--emerald-400)] px-1.5 py-0.5 rounded-[var(--r-sm)] font-mono">
              {tech}
            </span>
          ))}
          {(rule.mitre_attack || []).length > 3 && (
            <span className="text-[10px] text-[var(--subtle)]">+{(rule.mitre_attack || []).length - 3}</span>
          )}
        </div>

        {/* Match count */}
        {rule.match_count != null && rule.match_count > 0 && (
          <span className="text-xs text-[var(--muted)] font-mono shrink-0 w-16 text-right" title="Total matches">
            {rule.match_count} hits
          </span>
        )}

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0" onClick={e => e.stopPropagation()}>
          <button
            onClick={onEdit}
            className="p-1.5 rounded-[var(--r-md)] text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-3)] transition-colors"
            title="Edit rule"
          >
            <Edit3 className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onDelete}
            disabled={loading}
            className="p-1.5 rounded-[var(--r-md)] text-[var(--muted)] hover:text-[var(--crit)] hover:bg-[var(--crit-bg)] transition-colors disabled:opacity-50"
            title="Delete rule"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 ml-12 space-y-3">
          {/* Description */}
          <p className="text-sm text-[var(--muted)]">{rule.description}</p>

          {/* Metadata */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            {rule.author && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Author:</span>
                <span className="text-[var(--muted)] ml-1">{rule.author}</span>
              </div>
            )}
            {rule.date && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Created:</span>
                <span className="text-[var(--muted)] ml-1">{rule.date}</span>
              </div>
            )}
            {rule.logsource && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Log source:</span>
                <span className="text-[var(--muted)] ml-1">
                  {[rule.logsource.product, rule.logsource.category, rule.logsource.service].filter(Boolean).join(' / ')}
                </span>
              </div>
            )}
            {rule.last_match && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Last match:</span>
                <span className="text-[var(--muted)] ml-1">{formatDate(rule.last_match)}</span>
              </div>
            )}
          </div>

          {/* MITRE techniques */}
          {(rule.mitre_attack || []).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">MITRE ATT&CK:</span>
              <div className="flex flex-wrap gap-1">
                {(rule.mitre_attack || []).map(tech => (
                  <a
                    key={tech}
                    href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)] px-2 py-0.5 rounded-[var(--r-sm)] hover:bg-[rgba(217,70,239,0.2)] transition-colors"
                  >
                    {tech}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {(rule.tags || []).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">Tags:</span>
              <div className="flex flex-wrap gap-1">
                {(rule.tags || []).map(tag => (
                  <span key={tag} className="text-xs bg-[var(--surface-2)] text-[var(--muted)] px-2 py-0.5 rounded-[var(--r-sm)]">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* False positives */}
          {(rule.falsepositives || []).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">Known false positives:</span>
              <ul className="list-disc list-inside text-xs text-[var(--muted)] space-y-0.5">
                {(rule.falsepositives || []).map((fp, i) => (
                  <li key={i}>{fp}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// YARA Rule Row
function YaraRuleRow({ rule, loading, onToggle, onEdit, onDelete }: {
  rule: YaraRule
  loading: boolean
  onToggle: (enabled: boolean) => void
  onEdit: () => void
  onDelete: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const isReadOnly = rule.readonly || rule.source_type === 'builtin_file'

  // Severity badges with design tokens
  const severityStyles: Record<string, string> = {
    critical: 'bg-[var(--crit-bg)] text-[var(--crit)] border-[rgba(240,80,110,0.3)]',
    high: 'bg-[var(--high-bg)] text-[var(--high)] border-[rgba(245,165,36,0.3)]',
    medium: 'bg-[var(--med-bg)] text-[var(--med)] border-[rgba(91,156,242,0.3)]',
    low: 'bg-[var(--low-bg)] text-[var(--low)] border-[rgba(122,138,146,0.3)]',
  }

  return (
    <div className={cn('transition-colors', !rule.enabled && 'opacity-60')}>
      <div
        className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--surface-2)] cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Expand arrow */}
        <button className="shrink-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-[var(--muted)]" />
          ) : (
            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
          )}
        </button>

        {/* Toggle */}
        <button
          onClick={(e) => { e.stopPropagation(); onToggle(!rule.enabled) }}
          disabled={loading || isReadOnly}
          className="shrink-0"
          title={isReadOnly ? 'Built-in YARA files are managed on disk' : rule.enabled ? 'Disable rule' : 'Enable rule'}
        >
          {loading ? (
            <Loader2 className="h-5 w-5 text-[var(--muted)] animate-spin" />
          ) : rule.enabled ? (
            <ToggleRight className="h-5 w-5 text-[var(--emerald-400)]" />
          ) : (
            <ToggleLeft className="h-5 w-5 text-[var(--subtle)]" />
          )}
        </button>

        {/* Severity badge */}
        {rule.severity && (
          <span className={cn(
            'text-[10px] px-1.5 py-0.5 rounded-[var(--r-sm)] border font-medium shrink-0 w-20 text-center uppercase',
            severityStyles[rule.severity] || 'bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]'
          )}>
            {rule.severity}
          </span>
        )}

        {/* Rule info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--fg)] truncate">{rule.name}</span>
            {rule.category && (
              <span className="text-[10px] bg-[var(--surface-2)] text-[var(--muted)] px-1.5 py-0.5 rounded-[var(--r-sm)]">
            {rule.category}
              </span>
            )}
            {isReadOnly && (
              <span className="text-[10px] bg-[var(--emerald-glow)] text-[var(--emerald-400)] px-1.5 py-0.5 rounded-[var(--r-sm)]">
                built-in
              </span>
            )}
            {rule.rule_count != null && rule.rule_count > 0 && (
              <span className="text-[10px] bg-[var(--surface-2)] text-[var(--subtle)] px-1.5 py-0.5 rounded-[var(--r-sm)]">
                {rule.rule_count} rules
              </span>
            )}
          </div>
          {rule.description && (
            <p className="text-xs text-[var(--subtle)] truncate mt-0.5">{rule.description}</p>
          )}
        </div>

        {/* MITRE techniques */}
        <div className="hidden lg:flex items-center gap-1 shrink-0">
          {(rule.mitre_techniques || []).slice(0, 3).map(tech => (
            <span key={tech} className="text-[10px] bg-[var(--surface-2)] text-[var(--emerald-400)] px-1.5 py-0.5 rounded-[var(--r-sm)] font-mono">
              {tech}
            </span>
          ))}
        </div>

        {/* Match count */}
        {rule.match_count != null && rule.match_count > 0 && (
          <span className="text-xs text-[var(--muted)] font-mono shrink-0 w-16 text-right" title="Total matches">
            {rule.match_count} hits
          </span>
        )}

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0" onClick={e => e.stopPropagation()}>
          <button
            onClick={onEdit}
            className="p-1.5 rounded-[var(--r-md)] text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-3)] transition-colors"
            title={isReadOnly ? 'View rule' : 'Edit rule'}
          >
            {isReadOnly ? <Eye className="h-3.5 w-3.5" /> : <Edit3 className="h-3.5 w-3.5" />}
          </button>
          {!isReadOnly && (
            <button
              onClick={onDelete}
              disabled={loading}
              className="p-1.5 rounded-[var(--r-md)] text-[var(--muted)] hover:text-[var(--crit)] hover:bg-[var(--crit-bg)] transition-colors disabled:opacity-50"
              title="Delete rule"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 ml-12 space-y-3">
          {rule.description && (
            <p className="text-sm text-[var(--muted)]">{rule.description}</p>
          )}

          {/* Metadata */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            {rule.author && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Author:</span>
                <span className="text-[var(--muted)] ml-1">{rule.author}</span>
              </div>
            )}
            {rule.category && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Category:</span>
                <span className="text-[var(--muted)] ml-1">{rule.category}</span>
              </div>
            )}
            {rule.last_match && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Last match:</span>
                <span className="text-[var(--muted)] ml-1">{formatDate(rule.last_match)}</span>
              </div>
            )}
            {rule.inserted_at && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">Added:</span>
                <span className="text-[var(--muted)] ml-1">{formatDate(rule.inserted_at)}</span>
              </div>
            )}
            {rule.file_name && (
              <div className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                <span className="text-[var(--subtle)]">File:</span>
                <span className="text-[var(--muted)] ml-1">{rule.file_name}</span>
              </div>
            )}
          </div>

          {/* MITRE techniques */}
          {(rule.mitre_techniques || []).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">MITRE ATT&CK:</span>
              <div className="flex flex-wrap gap-1">
                {(rule.mitre_techniques || []).map(tech => (
                  <a
                    key={tech}
                    href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)] px-2 py-0.5 rounded-[var(--r-sm)] hover:bg-[rgba(217,70,239,0.2)] transition-colors"
                  >
                    {tech}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {(rule.tags || []).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">Tags:</span>
              <div className="flex flex-wrap gap-1">
                {(rule.tags || []).map(tag => (
                  <span key={tag} className="text-xs bg-[var(--surface-2)] text-[var(--muted)] px-2 py-0.5 rounded-[var(--r-sm)]">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Rule content preview */}
          {rule.content && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">Rule content:</span>
              <pre className="text-xs text-[var(--muted)] bg-[var(--bg)] rounded-[var(--r-md)] p-3 overflow-x-auto max-h-48 font-mono border border-[var(--hairline)]">
                {rule.content}
              </pre>
            </div>
          )}

          {/* Meta fields */}
          {rule.meta && Object.keys(rule.meta).length > 0 && (
            <div>
              <span className="text-xs text-[var(--subtle)] mb-1 block">Metadata:</span>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(rule.meta).map(([key, value]) => (
                  <div key={key} className="bg-[var(--surface-2)] rounded-[var(--r-sm)] px-2 py-1.5">
                    <span className="text-[var(--subtle)]">{key}:</span>
                    <span className="text-[var(--muted)] ml-1">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
