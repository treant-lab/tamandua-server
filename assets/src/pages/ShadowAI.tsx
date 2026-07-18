import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { Select, SelectItem, Checkbox } from '@/components/ui/baseui'
import {
  Eye,
  AlertTriangle,
  Upload,
  Clock,
  User,
  Globe,
  FileText,
  MessageSquare,
  Code,
  Image,
  Search,
  Filter,
  XCircle,
  CheckCircle,
  TrendingUp,
  AlertOctagon,
  Activity,
  Database,
  Radar,
  Shield,
} from 'lucide-react'
import { cn, safeCapitalize } from '@/lib/utils'
import { useCallback, useEffect, useState } from 'react'
import { ModelObservationsPanel, type ModelObservation } from '@/components/ModelObservationsPanel'

// Types
interface ShadowAIUsage {
  id: string
  userId: string
  userName: string
  department: string
  tool: string
  toolCategory: 'chat' | 'code' | 'image' | 'document' | 'other'
  accessMethod: 'browser' | 'api' | 'extension' | 'app' | 'network' | 'gateway' | 'proxy'
  lastUsed: string
  usageCount: number
  dataExfiltrationRisk: 'high' | 'medium' | 'low'
  policyStatus: 'approved' | 'pending' | 'blocked' | 'unknown' | 'allow' | 'monitor' | 'review' | 'block'
  dataTypesShared: string[]
  policyReasons?: string[]
  policyEnforced?: boolean
  enforcementRequested?: boolean
  enforcementStatus?: 'decision_only' | 'requested' | 'pending' | 'succeeded' | 'failed'
  enforcementActionId?: string
  enforcementReason?: string
  enforcementMode?: string
  effectiveRiskScore?: number
  provider?: string
  domain?: string
  processName?: string
  hostname?: string
}

interface PolicyViolation {
  id: string
  userId: string
  userName: string
  tool: string
  violationType: 'data_leak' | 'unauthorized_use' | 'pii_exposure' | 'code_leak' | 'policy_bypass'
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  description: string
  resolved: boolean
}

interface AIToolDiscovery {
  tool: string
  category: string
  uniqueUsers: number
  totalRequests: number
  dataVolume: string
  riskLevel: 'high' | 'medium' | 'low'
  status: 'blocked' | 'monitored' | 'allowed'
}

interface UnapprovedModel {
  id: string
  name: string
  provider?: string
  vendor?: string
  type?: string
  riskLevel: 'high' | 'medium' | 'low'
  riskScore?: number
  usageCount: number
  lastUsed?: string
  status?: string
  modelGuard?: ModelGuardSummary
  model_guard?: ModelGuardSummary
}

interface ModelGuardSummary {
  status?: 'decision_only' | 'enforced' | 'failed' | 'unsupported' | 'pending' | 'scanning' | string
  decision?: 'allow' | 'review' | 'block' | 'unknown' | string
  enforcement?: 'decision_only' | 'enforced' | 'failed' | 'unsupported' | 'degraded' | string
  action?: string
  evidence?: {
    model_id?: string
    registry?: string
    risk_score?: number
    findings_count?: number
    highest_severity?: string
    error?: string
    requested_enforcement?: string
    reason?: string
    package_scanner?: string
    package_findings?: unknown[] | Record<string, unknown>
    package_findings_count?: number
    external_model_scores?: unknown[] | Record<string, unknown>
    external_model_scores_count?: number
    model_consensus?: Record<string, unknown>
    model_consensus_state?: string
    enforcement_note?: string
    [key: string]: unknown
  }
  package_findings?: unknown[] | Record<string, unknown>
  package_findings_count?: number
  package_scanner?: string
  external_model_scores?: unknown[] | Record<string, unknown>
  external_model_scores_count?: number
  model_consensus?: Record<string, unknown>
  model_consensus_state?: string
  enforcement_note?: string
  fp_rationale?: string
}

interface ShadowAIStats {
  totalUsers?: number
  activeAITools?: number
  highRiskUsers?: number
  openViolations?: number
  totalServices?: number
  unapprovedCount?: number
  highRiskCount?: number
  dataExfiltrationByCategory: {
    label?: string
    value?: number
    color?: string
    category?: string
    count?: number
    percentage?: number
  }[]
}

interface DataSourceHealth {
  aiDiscovery?: {
    status: 'active' | 'stale' | 'no_data' | 'unsupported'
    componentCount?: number
    lastSeen?: string | null
    coverage?: string
  }
  aiUsage?: {
    status: 'active' | 'stale' | 'no_data' | 'unsupported'
    eventCount?: number
    lastSeen?: string | null
    coverage?: string
  }
  aiGateway?: {
    status: 'active' | 'stale' | 'no_data' | 'unsupported'
    eventCount?: number
    lastSeen?: string | null
    coverage?: string
    persistenceStatus?: string | null
    persistenceRetention?: string | null
    enforcementAvailable?: boolean
    enforcementMode?: string | null
    enforcementNote?: string | null
    inlineProxy?: boolean
    decisionSimulationAvailable?: boolean
    dryRunAvailable?: boolean
  }
  llmInterception?: {
    status: 'active' | 'stale' | 'no_data' | 'unsupported'
    coverage?: string
  }
}

interface ShadowAIProps {
  discoveredServices: AIToolDiscovery[]
  unapprovedModels: UnapprovedModel[]
  stats: ShadowAIStats
  usage?: ShadowAIUsage[]
  violations?: PolicyViolation[]
  dataSourceHealth?: DataSourceHealth
  gatewayPolicy?: AIGatewayPolicy
  modelObservations?: ModelObservation[]
}

type EnforcementStatus = NonNullable<ShadowAIUsage['enforcementStatus']>

interface AIGatewayPolicy {
  policy_id?: string
  default_decision?: 'allow' | 'monitor' | 'review' | 'block'
  enforce_block?: boolean
  allowlist_providers?: string[]
  blocklist_providers?: string[]
  allowlist_domains?: string[]
  blocklist_domains?: string[]
  blocked_data_categories?: string[]
  high_risk_data_categories?: string[]
  max_risk_score_allow?: number
  max_risk_score_monitor?: number
  updated_at?: string
  updated_by?: string
}

export default function ShadowAI({ discoveredServices, unapprovedModels, stats, usage = [], violations = [], dataSourceHealth, gatewayPolicy, modelObservations = [] }: ShadowAIProps) {
  const [activeTab, setActiveTab] = useState<'inventory' | 'activity' | 'policy' | 'prompts'>('inventory')
  const [searchQuery, setSearchQuery] = useState('')
  const [scanningModelId, setScanningModelId] = useState<string | null>(null)
  const [scanResults, setScanResults] = useState<Record<string, ModelGuardSummary>>({})
  const [guardModels, setGuardModels] = useState<UnapprovedModel[]>([])
  const [guardModelsLoading, setGuardModelsLoading] = useState(false)
  const normalizedStats = {
    totalUsers: stats.totalUsers ?? usage.length,
    activeAITools: stats.activeAITools ?? stats.totalServices ?? discoveredServices.length,
    highRiskUsers: stats.highRiskUsers ?? stats.highRiskCount ?? 0,
    openViolations: stats.openViolations ?? violations.length,
    dataExfiltrationByCategory: (stats.dataExfiltrationByCategory || []).map((item) => ({
      label: item.label || item.category || 'unknown',
      value: item.value ?? item.count ?? 0,
      color: item.color || 'blue',
    })),
  }
  const normalizedUsage = usage.map(normalizeUsage)
  const normalizedViolations = violations.map(normalizeViolation)
  const normalizedServices = discoveredServices.map(normalizeDiscovery)
  const normalizedModels = uniqueModels([...guardModels, ...unapprovedModels])
    .map((model) => ({
      ...model,
      modelGuard: scanResults[model.id] || model.modelGuard,
    }))
    .map(normalizeModelGuardModel)
  const query = searchQuery.trim().toLowerCase()
  const filteredUsage = normalizedUsage.filter((item) => matchesQuery(query, [item.userName, item.department, item.tool, item.accessMethod, item.policyStatus, ...item.dataTypesShared]))
  const filteredViolations = normalizedViolations.filter((item) => matchesQuery(query, [item.userName, item.tool, item.violationType, item.severity, item.description]))
  const filteredServices = normalizedServices.filter((item) => matchesQuery(query, [item.tool, item.category, item.status, item.riskLevel]))
  const filteredModels = normalizedModels.filter((item) =>
    matchesQuery(query, [item.name, item.provider || item.vendor, item.riskLevel, item.modelGuard?.status, item.modelGuard?.decision, item.modelGuard?.enforcement]),
  )
  const loadGuardModels = useCallback(async () => {
    setGuardModelsLoading(true)
    try {
      const response = await fetch('/api/v1/ai-security/models?type=model_file&limit=100', {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      })
      const payload = await response.json().catch(() => ({}))
      const models = Array.isArray(payload?.data) ? payload.data : []
      setGuardModels(models.map(modelFromApi))
    } finally {
      setGuardModelsLoading(false)
    }
  }, [])
  const scanModel = async (modelId: string) => {
    setScanningModelId(modelId)
    try {
      const response = await fetch(`/api/v1/ai-security/models/${encodeURIComponent(modelId)}/scan`, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders({
          'Content-Type': 'application/json',
          Accept: 'application/json',
        }),
        body: JSON.stringify({}),
      })
      const payload = await response.json().catch(() => ({}))
      const guard = modelGuardFromScanPayload(payload, response.ok)
      setScanResults((current) => ({ ...current, [modelId]: guard }))
      await loadGuardModels()
      router.reload({
        only: ['unapprovedModels', 'discoveredServices', 'stats', 'dataSourceHealth'],
      })
    } finally {
      setScanningModelId(null)
    }
  }
  useEffect(() => {
    void loadGuardModels()
  }, [loadGuardModels])

  return (
    <MainLayout title="Shadow AI Detection">
      <Head title="Shadow AI Detection - Tamandua EDR" />

      <div className="space-y-6">
        <DataSourceHealthPanel health={dataSourceHealth} />

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard title="Users with AI Activity" value={normalizedStats.totalUsers} icon={User} color="primary" />
          <StatCard title="AI Tools Detected" value={normalizedStats.activeAITools} icon={Eye} color="primary" />
          <StatCard title="High Risk Users" value={normalizedStats.highRiskUsers} icon={AlertTriangle} color="danger" />
          <StatCard title="Open Violations" value={normalizedStats.openViolations} icon={AlertOctagon} color="warning" />
        </div>

        {/* Data Exfiltration Risk Summary */}
        <div className="card-sentinel rounded-xl p-4">
          <h3 className="text-sm font-medium mb-1" style={{ color: 'var(--fg)' }}>
            Potential Data Exposure Signals
          </h3>
          <p className="text-xs mb-4" style={{ color: 'var(--muted)' }}>
            Derived from available metadata. Prompt and response bodies are not captured here.
          </p>
          {normalizedStats.dataExfiltrationByCategory.length > 0 ? (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {normalizedStats.dataExfiltrationByCategory.map((item) => (
                <div key={item.label} className="text-center">
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {item.value}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>
                    {formatLabel(item.label)}
                  </div>
                  <div
                    className={cn('mt-2 h-1 rounded-full', item.color === 'red' ? 'bg-red-500' : item.color === 'orange' ? 'bg-orange-500' : item.color === 'yellow' ? 'bg-yellow-500' : 'bg-blue-500')}
                    style={{
                      width: `${Math.min(item.value * 2, 100)}%`,
                      margin: '0 auto',
                    }}
                  />
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg p-4 text-sm" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
              No exposure categories reported.
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="flex gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
          {[
            { id: 'inventory', label: 'Inventory', icon: Database },
            { id: 'activity', label: 'Observed Activity', icon: Activity },
            { id: 'policy', label: 'Policy Decisions', icon: CheckCircle },
            { id: 'prompts', label: 'Prompt Interception', icon: Radar },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={cn(
                'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                activeTab === tab.id ? 'border-primary-500 text-primary-400' : 'border-transparent hover:text-[var(--fg)]',
              )}
              style={activeTab !== tab.id ? { color: 'var(--muted)' } : undefined}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
            <input
              type="text"
              placeholder="Search users, tools, or departments..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg pl-10 pr-4 py-2 placeholder-[var(--subtle)] focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                color: 'var(--fg)',
              }}
            />
          </div>
          <button onClick={() => router.reload()} className="flex items-center gap-2 px-4 py-2 rounded-lg" style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}>
            <Filter className="h-4 w-4" />
            Refresh
          </button>
        </div>

        {/* Content based on active tab */}
        {activeTab === 'inventory' && (
          <div className="space-y-4">
            <ModelObservationsPanel observations={modelObservations} />
            <ModelGuardTable data={filteredModels} hasSearch={query.length > 0} scanningModelId={scanningModelId} loading={guardModelsLoading} onScan={scanModel} />
            <DiscoveryTable data={filteredServices} hasSearch={query.length > 0} />
          </div>
        )}
        {activeTab === 'activity' && (
          <div className="space-y-4">
            <UsageTable data={filteredUsage} hasSearch={query.length > 0} />
            <ViolationsTable data={filteredViolations} hasSearch={query.length > 0} />
          </div>
        )}
        {activeTab === 'policy' && <PolicyDecisionPanel usage={filteredUsage} gateway={dataSourceHealth?.aiGateway} gatewayPolicy={gatewayPolicy} hasSearch={query.length > 0} />}
        {activeTab === 'prompts' && <PromptInterceptionPanel health={dataSourceHealth?.llmInterception} />}
      </div>
    </MainLayout>
  )
}

// Helper Components
function normalizeUsage(usage: ShadowAIUsage): ShadowAIUsage {
  const raw = usage as ShadowAIUsage & {
    agentId?: string
    service?: string
    requestCount?: number
    dataTransferred?: number
    lastActivity?: string
    policy_enforced?: boolean
    enforcement?: {
      requested?: boolean
      status?: string
      action_id?: string
      actionId?: string
      reason?: string
      error?: string
      mode?: string
    }
    enforcement_status?: string
    enforcementStatus?: string
    enforcement_requested?: boolean
    enforcementRequested?: boolean
    enforcement_action_id?: string
    enforcementActionId?: string
    enforcement_reason?: string
    enforcementReason?: string
    enforcement_error?: string
    enforcement_mode?: string
    enforcementMode?: string
    reason?: string
  }
  const policyEnforced = usage.policyEnforced === true || raw.policy_enforced === true
  const enforcementRequested = usage.enforcementRequested === true || raw.enforcementRequested === true || raw.enforcement_requested === true || raw.enforcement?.requested === true || policyEnforced
  const enforcementStatus = normalizeEnforcementStatus(usage.enforcementStatus || raw.enforcementStatus || raw.enforcement_status || raw.enforcement?.status, enforcementRequested)
  const enforcementActionId = usage.enforcementActionId || raw.enforcementActionId || raw.enforcement_action_id || raw.enforcement?.actionId || raw.enforcement?.action_id
  const enforcementReason = usage.enforcementReason || raw.enforcementReason || raw.enforcement_reason || raw.enforcement_error || raw.enforcement?.reason || raw.enforcement?.error || raw.reason
  const enforcementMode = usage.enforcementMode || raw.enforcementMode || raw.enforcement_mode || raw.enforcement?.mode

  return {
    ...usage,
    id: usage.id || `${raw.agentId || 'unknown'}-${raw.service || 'service'}`,
    userId: usage.userId || raw.agentId || 'unknown',
    userName: usage.userName || raw.agentId || 'Unknown user',
    department: usage.department || 'Unassigned',
    tool: usage.tool || raw.service || 'Unknown AI service',
    toolCategory: usage.toolCategory || 'other',
    accessMethod: usage.accessMethod || 'browser',
    lastUsed: usage.lastUsed || raw.lastActivity || '',
    usageCount: usage.usageCount ?? raw.requestCount ?? 0,
    dataExfiltrationRisk: usage.dataExfiltrationRisk || (raw.dataTransferred && raw.dataTransferred > 0 ? 'medium' : 'low'),
    policyStatus: usage.policyStatus || 'unknown',
    dataTypesShared: usage.dataTypesShared || [],
    policyReasons: usage.policyReasons || [],
    policyEnforced,
    enforcementRequested,
    enforcementStatus,
    enforcementActionId,
    enforcementReason,
    enforcementMode,
    effectiveRiskScore: usage.effectiveRiskScore ?? 0,
    provider: usage.provider,
    domain: usage.domain,
    processName: usage.processName,
    hostname: usage.hostname,
  }
}

function normalizeViolation(violation: PolicyViolation): PolicyViolation {
  const raw = violation as PolicyViolation & {
    type?: string
    status?: string
    agentId?: string
  }
  return {
    ...violation,
    userId: violation.userId || raw.agentId || 'unknown',
    userName: violation.userName || raw.agentId || 'Unknown user',
    tool: violation.tool || 'AI service',
    violationType: violation.violationType || (raw.type as PolicyViolation['violationType']) || 'data_leak',
    severity: violation.severity || 'medium',
    timestamp: violation.timestamp || '',
    description: violation.description || '',
    resolved: violation.resolved ?? raw.status === 'resolved',
  }
}

function normalizeDiscovery(service: AIToolDiscovery): AIToolDiscovery {
  const raw = service as AIToolDiscovery & {
    name?: string
    domain?: string
    riskLevel?: 'high' | 'medium' | 'low'
    requestCount?: number
    dataVolume?: number | string
    source?: string
    policyStatus?: string
  }
  return {
    ...service,
    tool: service.tool || raw.name || raw.domain || 'Unknown AI service',
    category: service.category || 'generative_ai',
    uniqueUsers: service.uniqueUsers ?? 0,
    totalRequests: service.totalRequests ?? raw.requestCount ?? 0,
    dataVolume: service.dataVolume ?? String(raw.dataVolume ?? 0),
    riskLevel: service.riskLevel || raw.riskLevel || 'medium',
    status: service.status || 'monitored',
  }
}

function normalizeModelGuardModel(model: UnapprovedModel): UnapprovedModel {
  const guard = model.modelGuard ||
    model.model_guard || {
      status: 'unsupported',
      decision: 'unknown',
      enforcement: 'unsupported',
      action: 'none',
    }
  const riskScore = model.riskScore ?? Number(guard.evidence?.risk_score ?? 0)
  return {
    ...model,
    provider: model.provider || model.vendor || guard.evidence?.registry || 'unknown',
    riskLevel: model.riskLevel || riskLevelFromScore(riskScore),
    riskScore,
    usageCount: model.usageCount ?? 0,
    modelGuard: guard,
  }
}

function modelFromApi(model: Record<string, unknown>): UnapprovedModel {
  const guard = (model.model_guard || model.modelGuard) as ModelGuardSummary | undefined
  const riskScore = Number(model.risk_score ?? guard?.evidence?.risk_score ?? 0)
  return {
    id: String(model.id || model.model_id || model.name || guard?.evidence?.model_id || 'unknown-model'),
    name: String(model.name || model.model_id || guard?.evidence?.model_id || 'Unknown model'),
    provider: String(model.registry || guard?.evidence?.registry || model.component_type || 'local'),
    type: String(model.component_type || model.type || 'model_file'),
    riskLevel: normalizeRiskLevel(model.risk_level, riskScore),
    riskScore,
    usageCount: Number(model.usage_count || model.usageCount || 0),
    lastUsed: String(model.last_seen_at || model.lastSeen || ''),
    status: String(model.policy_status || model.status || 'unknown'),
    modelGuard: guard,
  }
}

function modelGuardFromScanPayload(payload: Record<string, unknown>, ok: boolean): ModelGuardSummary {
  const guard = (payload.model_guard || payload.modelGuard) as ModelGuardSummary | undefined
  if (guard) return guard

  const reason = String(payload.reason || payload.error || (ok ? 'scan_started' : 'scan_failed'))
  return {
    status: ok ? 'scanning' : 'failed',
    decision: 'unknown',
    enforcement: ok ? 'decision_only' : 'failed',
    action: 'none',
    evidence: { reason },
  }
}

function riskLevelFromScore(score: number): UnapprovedModel['riskLevel'] {
  if (score >= 75 || score >= 0.75) return 'high'
  if (score >= 25 || score >= 0.25) return 'medium'
  return 'low'
}

function normalizeRiskLevel(value: unknown, score: number): UnapprovedModel['riskLevel'] {
  const normalized = String(value || '').toLowerCase()
  if (normalized === 'critical' || normalized === 'high') return 'high'
  if (normalized === 'medium') return 'medium'
  if (normalized === 'low') return 'low'
  return riskLevelFromScore(score)
}

function uniqueModels(models: UnapprovedModel[]) {
  return Array.from(new Map(models.map((model) => [model.id, model])).values())
}

function matchesQuery(query: string, values: Array<string | number | undefined | null>) {
  if (!query) return true
  return values.some((value) =>
    String(value ?? '')
      .toLowerCase()
      .includes(query),
  )
}

function objectSize(value: unknown): number {
  if (Array.isArray(value)) return value.length
  if (value && typeof value === 'object') return Object.keys(value as Record<string, unknown>).length
  return 0
}

function modelGuardEvidenceSummary(guard: ModelGuardSummary) {
  const evidence = guard.evidence || {}
  const packageFindings = evidence.package_findings || guard.package_findings
  const packageFindingCount = Number(evidence.package_findings_count ?? guard.package_findings_count ?? objectSize(packageFindings))
  const packageScanner = String(evidence.package_scanner || guard.package_scanner || (packageFindingCount > 0 ? 'collected' : 'not_collected'))
  const externalScores = evidence.external_model_scores || guard.external_model_scores
  const externalScoreCount = Number(evidence.external_model_scores_count ?? guard.external_model_scores_count ?? objectSize(externalScores))
  const consensus = evidence.model_consensus || guard.model_consensus || {}
  const consensusState = String(evidence.model_consensus_state || guard.model_consensus_state || (objectSize(consensus) > 0 ? 'collected' : 'not_collected'))
  const enforcementNote = String(evidence.enforcement_note || guard.enforcement_note || '')
  const source = packageFindingCount > 0 ? 'package scanner' : packageScanner === 'not_collected' ? 'package scanner not collected' : packageScanner.replace(/_/g, ' ')

  return {
    packageFindingCount,
    packageScanner,
    externalScoreCount,
    consensusState,
    enforcementNote,
    source,
  }
}

function formatLabel(value?: string) {
  return safeCapitalize((value || 'unknown').replace(/_/g, ' '))
}

function splitPolicyList(value: string) {
  return value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .filter((item, index, list) => list.indexOf(item) === index)
}

function csrfHeaders(extra: Record<string, string> = {}) {
  const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
  return token ? { ...extra, 'X-CSRF-Token': token } : extra
}

function normalizeEnforcementStatus(value: string | undefined, requested: boolean): EnforcementStatus {
  const normalized = String(value || '')
    .toLowerCase()
    .replace(/-/g, '_')

  if (['succeeded', 'success', 'completed', 'applied'].includes(normalized)) return 'succeeded'
  if (['failed', 'error', 'rejected'].includes(normalized)) return 'failed'
  if (['pending', 'running', 'in_progress', 'queued', 'acknowledged'].includes(normalized)) return 'pending'
  if (['requested', 'endpoint_action', 'endpoint_action_bridge'].includes(normalized)) return 'requested'
  if (['decision_only', 'not_requested', 'skipped'].includes(normalized)) return 'decision_only'

  return requested ? 'pending' : 'decision_only'
}

function gatewayDetail(gateway?: DataSourceHealth['aiGateway']) {
  if (!gateway) return 'No gateway/browser/proxy metadata received'

  const lastSeen = gateway.lastSeen ? `Last seen ${formatDisplayTime(gateway.lastSeen)}` : 'No events yet'
  const persistence = gateway.persistenceStatus ? `persistence ${gateway.persistenceStatus}` : 'persistence unknown'
  const enforcement = gateway.inlineProxy ? gateway.enforcementMode || 'inline' : gateway.enforcementMode || 'decision_only'

  return `${lastSeen} / ${persistence} / ${enforcement}`
}

function PolicyDecisionPanel({
  usage,
  gateway,
  gatewayPolicy,
  hasSearch = false,
}: {
  usage: ShadowAIUsage[]
  gateway?: DataSourceHealth['aiGateway']
  gatewayPolicy?: AIGatewayPolicy
  hasSearch?: boolean
}) {
  const [policy, setPolicy] = useState<AIGatewayPolicy>(gatewayPolicy || {})
  const [simulationStatus, setSimulationStatus] = useState('')
  const [simulationError, setSimulationError] = useState('')
  const [simulationResult, setSimulationResult] = useState<{
    policy_decision?: string
    policy_reasons?: string[]
    policy_enforced?: boolean
    effective_risk_score?: number
  } | null>(null)

  const counts = usage.reduce(
    (acc, item) => {
      const key = item.policyStatus || 'unknown'
      acc[key] = (acc[key] || 0) + 1
      const enforcementStatus: EnforcementStatus = item.enforcementStatus || normalizeEnforcementStatus(undefined, item.policyEnforced === true)
      acc[enforcementStatus] = (acc[enforcementStatus] || 0) + 1
      return acc
    },
    {
      allow: 0,
      monitor: 0,
      review: 0,
      block: 0,
      unknown: 0,
      decision_only: 0,
      requested: 0,
      pending: 0,
      succeeded: 0,
      failed: 0,
    } as Record<string, number>,
  )

  const runDecisionSimulation = () => {
    setSimulationStatus('')
    setSimulationError('Tenant-scoped decision simulation is unavailable')
    setSimulationResult(null)
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <DecisionMetric title="Allow" value={counts.allow || 0} tone="green" />
        <DecisionMetric title="Monitor" value={counts.monitor || 0} tone="yellow" />
        <DecisionMetric title="Review" value={counts.review || 0} tone="orange" />
        <DecisionMetric title="Block" value={counts.block || 0} tone="red" />
      </div>

      <EnforcementReadinessPanel
        gateway={gateway}
        counts={counts}
        onRunSimulation={runDecisionSimulation}
        simulationStatus={simulationStatus}
        simulationError={simulationError}
        simulationResult={simulationResult}
      />

      <GatewayPolicyEditor policy={policy} setPolicy={setPolicy} />

      <PolicyDecisionTable data={usage} hasSearch={hasSearch} />
    </div>
  )
}

function EnforcementReadinessPanel({
  gateway,
  counts,
  onRunSimulation,
  simulationStatus,
  simulationError,
  simulationResult,
}: {
  gateway?: DataSourceHealth['aiGateway']
  counts: Record<string, number>
  onRunSimulation: () => void
  simulationStatus: string
  simulationError: string
  simulationResult: {
    policy_decision?: string
    policy_reasons?: string[]
    policy_enforced?: boolean
    effective_risk_score?: number
  } | null
}) {
  const sourceStatus = gateway?.status || 'no_data'
  const decisionSimulationAvailable = gateway?.decisionSimulationAvailable !== false
  const dryRunAvailable = gateway?.dryRunAvailable === true

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-5">
        <div className="min-w-0">
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            Enforcement Readiness
          </h3>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            {gateway?.enforcementNote || 'Endpoint bridge readiness is reported by gateway health. Inline proxy blocking is not enabled unless source health says so.'}
          </p>
          <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
            <ReadinessItem label="Endpoint bridge" value={gateway?.enforcementMode || 'not reported'} status={gateway?.enforcementAvailable === true ? 'ready' : 'unavailable'} />
            <ReadinessItem label="Inline proxy" value={gateway?.inlineProxy ? 'inline enforcement' : 'not enabled'} status={gateway?.inlineProxy === true ? 'ready' : 'unavailable'} />
            <ReadinessItem label="Source health" value={`${gateway?.eventCount ?? 0} events`} status={sourceStatus === 'active' ? 'ready' : sourceStatus === 'stale' ? 'pending' : 'unavailable'} />
          </div>
        </div>
        <div className="w-full xl:max-w-md rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
          <div className="flex flex-wrap gap-2 mb-3">
            <CapabilityPill label="Decision simulation" enabled={decisionSimulationAvailable} />
            <CapabilityPill label="Enforcement dry-run" enabled={dryRunAvailable} />
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <EnforcementCount label="Decision-only" value={counts.decision_only || 0} />
            <EnforcementCount label="Requested" value={(counts.requested || 0) + (counts.pending || 0)} />
            <EnforcementCount label="Succeeded" value={counts.succeeded || 0} />
            <EnforcementCount label="Failed" value={counts.failed || 0} />
          </div>
          <button
            onClick={onRunSimulation}
            disabled={!decisionSimulationAvailable || simulationStatus === 'Running decision simulation'}
            className="mt-3 inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium disabled:opacity-60"
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              color: 'var(--fg)',
            }}
          >
            <Radar className="h-4 w-4" />
            {simulationStatus === 'Running decision simulation' ? 'Running' : 'Run Decision Simulation'}
          </button>
          <div className="mt-3 text-xs" style={{ color: 'var(--muted)' }}>
            {dryRunAvailable
              ? 'Dry-run enforcement is reported available by health metadata.'
              : 'No Shadow AI enforcement dry-run API is exposed. This simulation evaluates policy only and does not queue actions.'}
          </div>
          {simulationStatus && simulationStatus !== 'Running decision simulation' && <div className="mt-2 text-xs text-green-400">{simulationStatus}</div>}
          {simulationError && <div className="mt-2 text-xs text-red-400">{simulationError}</div>}
          {simulationResult && (
            <div className="mt-2 text-xs" style={{ color: 'var(--fg-2)' }}>
              Decision: {simulationResult.policy_decision || 'unknown'} / Risk: {simulationResult.effective_risk_score ?? 0} / Enforcement requested: {simulationResult.policy_enforced ? 'yes' : 'no'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function DecisionMetric({ title, value, tone }: { title: string; value: number; tone: 'green' | 'yellow' | 'orange' | 'red' | 'blue' }) {
  const tones = {
    green: 'text-green-400',
    yellow: 'text-yellow-400',
    orange: 'text-orange-400',
    red: 'text-red-400',
    blue: 'text-blue-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className={cn('text-2xl font-semibold', tones[tone])}>{value}</div>
      <div className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
        {title}
      </div>
    </div>
  )
}

function ReadinessItem({ label, value, status }: { label: string; value: string; status: 'ready' | 'pending' | 'unavailable' }) {
  return (
    <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs font-medium" style={{ color: 'var(--fg)' }}>
          {label}
        </div>
        <span className={cn('h-2 w-2 rounded-full', status === 'ready' && 'bg-green-400', status === 'pending' && 'bg-yellow-400', status === 'unavailable' && 'bg-[var(--muted)]')} />
      </div>
      <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
        {value}
      </div>
    </div>
  )
}

function EnforcementCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded p-2" style={{ background: 'var(--surface)' }}>
      <div className="text-base font-semibold" style={{ color: 'var(--fg)' }}>
        {value}
      </div>
      <div style={{ color: 'var(--muted)' }}>{label}</div>
    </div>
  )
}

function CapabilityPill({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium', enabled ? 'bg-green-500/15 text-green-400' : 'bg-[var(--surface-2)] text-[var(--muted)]')}>
      {enabled ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
      {label}
    </span>
  )
}

function GatewayPolicyEditor({
  policy,
  setPolicy,
}: {
  policy: AIGatewayPolicy
  setPolicy: (policy: AIGatewayPolicy) => void
}) {
  return (
    <div className="card-sentinel rounded-xl p-6">
      <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 mb-5">
        <div>
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            AI Gateway Policy
          </h3>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            Metadata-only decisions for browser extension, proxy, SDK, gateway, and endpoint telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--muted)]">Tenant-scoped policy mutation is unavailable</span>
          <button
            disabled
            className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-60"
            style={{ background: 'var(--primary)', color: 'white' }}
          >
            <CheckCircle className="h-4 w-4" />
            Save unavailable
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <label className="space-y-2 text-sm">
          <span style={{ color: 'var(--fg)' }}>Default Decision</span>
          <Select
            value={policy.default_decision || 'monitor'}
            onValueChange={(value) =>
              setPolicy({
                ...policy,
                default_decision: value as AIGatewayPolicy['default_decision'],
              })
            }
            placeholder="monitor"
            className="rounded-lg px-3 py-2"
            fullWidth
          >
            <SelectItem value="allow">allow</SelectItem>
            <SelectItem value="monitor">monitor</SelectItem>
            <SelectItem value="review">review</SelectItem>
            <SelectItem value="block">block</SelectItem>
          </Select>
        </label>
        <NumberPolicyInput label="Allow Threshold" value={policy.max_risk_score_allow ?? 25} onChange={(value) => setPolicy({ ...policy, max_risk_score_allow: value })} />
        <NumberPolicyInput label="Review Threshold" value={policy.max_risk_score_monitor ?? 70} onChange={(value) => setPolicy({ ...policy, max_risk_score_monitor: value })} />
      </div>

      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ListPolicyInput label="Allowed Providers" value={policy.allowlist_providers || []} onChange={(value) => setPolicy({ ...policy, allowlist_providers: value })} />
        <ListPolicyInput label="Blocked Providers" value={policy.blocklist_providers || []} onChange={(value) => setPolicy({ ...policy, blocklist_providers: value })} />
        <ListPolicyInput label="Allowed Domains" value={policy.allowlist_domains || []} onChange={(value) => setPolicy({ ...policy, allowlist_domains: value })} />
        <ListPolicyInput label="Blocked Domains" value={policy.blocklist_domains || []} onChange={(value) => setPolicy({ ...policy, blocklist_domains: value })} />
        <ListPolicyInput
          label="Blocked Data Categories"
          value={policy.blocked_data_categories || ['credentials', 'secrets']}
          onChange={(value) => setPolicy({ ...policy, blocked_data_categories: value })}
        />
        <ListPolicyInput
          label="Review Data Categories"
          value={policy.high_risk_data_categories || ['pii', 'source_code', 'customer_data', 'financial_data']}
          onChange={(value) => setPolicy({ ...policy, high_risk_data_categories: value })}
        />
      </div>

      <div className="mt-4">
        <Checkbox
          checked={policy.enforce_block === true}
          onCheckedChange={(checked) => setPolicy({ ...policy, enforce_block: checked })}
          label="Queue endpoint enforcement for block decisions when an agent target is present"
        />
      </div>
    </div>
  )
}

function DataSourceHealthPanel({ health }: { health?: DataSourceHealth }) {
  const discovery = health?.aiDiscovery
  const usage = health?.aiUsage
  const gateway = health?.aiGateway
  const llm = health?.llmInterception

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
      <SourceStatusCard
        title="AI Discovery"
        icon={Database}
        status={discovery?.status || 'no_data'}
        metric={`${discovery?.componentCount ?? 0} components`}
        detail={discovery?.lastSeen ? `Last seen ${formatDisplayTime(discovery.lastSeen)}` : 'No inventory telemetry received'}
        coverage={discovery?.coverage || 'Processes, packages, extensions, model files'}
      />
      <SourceStatusCard
        title="Observed Activity"
        icon={Activity}
        status={usage?.status || 'no_data'}
        metric={`${usage?.eventCount ?? 0} events`}
        detail={usage?.lastSeen ? `Last seen ${formatDisplayTime(usage.lastSeen)}` : 'No AI network/DNS activity received'}
        coverage={usage?.coverage || 'DNS/network metadata only'}
      />
      <SourceStatusCard
        title="AI Gateway"
        icon={Globe}
        status={gateway?.status || 'no_data'}
        metric={`${gateway?.eventCount ?? 0} events`}
        detail={gatewayDetail(gateway)}
        coverage={gateway?.coverage || 'Gateway metadata only'}
      />
      <SourceStatusCard
        title="Prompt Interception"
        icon={Radar}
        status={llm?.status || 'unsupported'}
        metric={statusLabel(llm?.status || 'unsupported')}
        detail="Prompt and response content are not captured from endpoint browsers"
        coverage={llm?.coverage || 'Unsupported on endpoint agents'}
      />
    </div>
  )
}

function PromptInterceptionPanel({ health }: { health?: DataSourceHealth['llmInterception'] }) {
  const status = health?.status || 'unsupported'

  return (
    <div className="card-sentinel rounded-xl p-8">
      <div className="flex flex-col md:flex-row md:items-start gap-4">
        <div className="p-3 rounded-lg bg-blue-500/15 text-blue-400 w-fit">
          <Radar className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
              Prompt Interception
            </h3>
            <span
              className={cn(
                'px-2 py-1 rounded text-xs font-medium',
                status === 'active' && 'bg-green-500/15 text-green-400',
                status === 'stale' && 'bg-yellow-500/15 text-yellow-400',
                status === 'no_data' && 'bg-[var(--surface-2)] text-[var(--muted)]',
                status === 'unsupported' && 'bg-blue-500/15 text-blue-400',
              )}
            >
              {statusLabel(status)}
            </span>
          </div>
          <p className="mt-2 text-sm" style={{ color: 'var(--fg-2)' }}>
            No prompt or response content is shown because endpoint browser prompt interception is not reported by this data source.
          </p>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
              <div className="font-medium" style={{ color: 'var(--fg)' }}>
                Coverage
              </div>
              <div className="mt-1" style={{ color: 'var(--muted)' }}>
                {health?.coverage || 'Unsupported on endpoint agents'}
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
              <div className="font-medium" style={{ color: 'var(--fg)' }}>
                Displayed Data
              </div>
              <div className="mt-1" style={{ color: 'var(--muted)' }}>
                None. Use Observed Activity for network/DNS metadata.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function NumberPolicyInput({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <label className="space-y-2 text-sm">
      <span style={{ color: 'var(--fg)' }}>{label}</span>
      <input
        type="number"
        min={0}
        max={100}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="w-full rounded-lg px-3 py-2"
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          color: 'var(--fg)',
        }}
      />
    </label>
  )
}

function ListPolicyInput({ label, value, onChange }: { label: string; value: string[]; onChange: (value: string[]) => void }) {
  return (
    <label className="space-y-2 text-sm">
      <span style={{ color: 'var(--fg)' }}>{label}</span>
      <input
        value={value.join(', ')}
        onChange={(event) => onChange(splitPolicyList(event.target.value))}
        className="w-full rounded-lg px-3 py-2"
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          color: 'var(--fg)',
        }}
      />
    </label>
  )
}

function SourceStatusCard({
  title,
  icon: Icon,
  status,
  metric,
  detail,
  coverage,
}: {
  title: string
  icon: React.ElementType
  status: 'active' | 'stale' | 'no_data' | 'unsupported'
  metric: string
  detail: string
  coverage: string
}) {
  const statusClasses = {
    active: 'bg-green-500/15 text-green-400',
    stale: 'bg-yellow-500/15 text-yellow-400',
    no_data: 'bg-[var(--surface-2)] text-[var(--muted)]',
    unsupported: 'bg-blue-500/15 text-blue-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-primary-600/15 text-primary-400">
            <Icon className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
              {title}
            </div>
            <div className="text-xs truncate" style={{ color: 'var(--muted)' }}>
              {coverage}
            </div>
          </div>
        </div>
        <span className={cn('shrink-0 px-2 py-1 rounded text-xs font-medium', statusClasses[status])}>{statusLabel(status)}</span>
      </div>
      <div className="mt-4 text-xl font-semibold" style={{ color: 'var(--fg)' }}>
        {metric}
      </div>
      <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
        {detail}
      </div>
    </div>
  )
}

function PolicyDecisionTable({ data, hasSearch = false }: { data: ShadowAIUsage[]; hasSearch?: boolean }) {
  if (data.length === 0) {
    return (
      <div className="card-sentinel rounded-xl p-12 text-center" style={{ color: 'var(--subtle)' }}>
        <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium mb-1">{hasSearch ? 'No matching policy decisions' : 'No AI policy decisions yet'}</p>
        <p className="text-sm">{hasSearch ? 'Try a different search term.' : 'AI Gateway and endpoint usage decisions will appear here after telemetry arrives.'}</p>
      </div>
    )
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
          Policy Decision Timeline
        </h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
          Decisions are based on metadata only. Enforcement status is shown only when the event reports an endpoint action request or result.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Time
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Provider / Domain
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Endpoint
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Risk
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Decision
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Enforcement
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Reason
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((item) => {
              const enforcementStatus = item.enforcementStatus || normalizeEnforcementStatus(undefined, item.policyEnforced === true)

              return (
                <tr key={item.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="p-4 text-sm whitespace-nowrap" style={{ color: 'var(--muted)' }}>
                    {formatDisplayTime(item.lastUsed)}
                  </td>
                  <td className="p-4">
                    <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                      {item.provider || item.tool}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>
                      {item.domain || item.tool}
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="text-sm" style={{ color: 'var(--fg-2)' }}>
                      {item.hostname || item.userName || 'Unknown endpoint'}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>
                      {item.processName || item.accessMethod}
                    </div>
                  </td>
                  <td className="p-4">
                    <span className="text-sm" style={{ color: 'var(--fg)' }}>
                      {item.effectiveRiskScore ?? 0}
                    </span>
                  </td>
                  <td className="p-4">
                    <PolicyBadge status={item.policyStatus} />
                  </td>
                  <td className="p-4">
                    <EnforcementBadge status={enforcementStatus} actionId={item.enforcementActionId} mode={item.enforcementMode} />
                  </td>
                  <td className="p-4">
                    <div className="flex flex-col gap-1">
                      <div className="flex flex-wrap gap-1">
                        {(item.policyReasons || ['default_policy']).slice(0, 3).map((reason) => (
                          <span
                            key={reason}
                            className="text-xs px-2 py-0.5 rounded"
                            style={{
                              background: 'var(--surface-2)',
                              color: 'var(--fg-2)',
                            }}
                          >
                            {reason.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                      {item.enforcementReason && (
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>
                          Enforcement: {item.enforcementReason.replace(/_/g, ' ')}
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function EnforcementBadge({ status, actionId, mode }: { status: EnforcementStatus; actionId?: string; mode?: string }) {
  const label = status === 'decision_only' ? 'Decision only' : status === 'requested' ? 'Requested' : status === 'pending' ? 'Pending' : status === 'succeeded' ? 'Succeeded' : 'Failed'

  return (
    <div className="space-y-1">
      <span
        className={cn(
          'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
          status === 'decision_only' && 'bg-[var(--surface-2)] text-[var(--muted)]',
          status === 'requested' && 'bg-blue-500/15 text-blue-400',
          status === 'pending' && 'bg-yellow-500/15 text-yellow-400',
          status === 'succeeded' && 'bg-green-500/15 text-green-400',
          status === 'failed' && 'bg-red-500/15 text-red-400',
        )}
      >
        {status === 'succeeded' && <CheckCircle className="h-3 w-3" />}
        {status === 'failed' && <XCircle className="h-3 w-3" />}
        {(status === 'requested' || status === 'pending') && <Clock className="h-3 w-3" />}
        {status === 'decision_only' && <Eye className="h-3 w-3" />}
        {label}
      </span>
      {(actionId || mode) && (
        <div className="text-xs" style={{ color: 'var(--muted)' }}>
          {actionId ? `Action ${actionId}` : mode}
        </div>
      )}
    </div>
  )
}

function statusLabel(status: 'active' | 'stale' | 'no_data' | 'unsupported') {
  if (status === 'no_data') return 'No data'
  return safeCapitalize(status)
}

function formatDisplayTime(value?: string | null) {
  if (!value) return 'Not reported'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

interface StatCardProps {
  title: string
  value: number
  icon: React.ElementType
  color: 'primary' | 'danger' | 'warning'
}

function StatCard({ title, value, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-primary-600/20 text-primary-400',
    danger: 'bg-red-500/20 text-red-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div className={cn('p-2 rounded-lg', colorClasses[color])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-4">
        <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>
          {value}
        </span>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
          {title}
        </p>
      </div>
    </div>
  )
}

function UsageTable({ data, hasSearch = false }: { data: ShadowAIUsage[]; hasSearch?: boolean }) {
  const categoryIcons = {
    chat: MessageSquare,
    code: Code,
    image: Image,
    document: FileText,
    other: Globe,
  }

  if (data.length === 0) {
    return (
      <div className="card-sentinel rounded-xl p-12 text-center" style={{ color: 'var(--subtle)' }}>
        <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium mb-1">{hasSearch ? 'No matching observed activity' : 'No observed AI activity'}</p>
        <p className="text-sm">{hasSearch ? 'Try a different search term.' : 'DNS/network metadata activity will appear here when the agent reports matching domains.'}</p>
      </div>
    )
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
          Observed AI Activity
        </h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
          Network/DNS metadata and policy state. Prompt contents are not included.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                User
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                AI Tool
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Access Method
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Usage
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Risk Level
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Policy Status
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Data Types
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((usage) => {
              const CategoryIcon = categoryIcons[usage.toolCategory]
              return (
                <tr key={usage.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="p-4">
                    <div>
                      <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                        {usage.userName}
                      </div>
                      <div className="text-xs" style={{ color: 'var(--muted)' }}>
                        {usage.department}
                      </div>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <CategoryIcon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>
                        {usage.tool}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>
                      {usage.accessMethod}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>
                        {usage.usageCount}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <RiskBadge level={usage.dataExfiltrationRisk} />
                  </td>
                  <td className="p-4">
                    <PolicyBadge status={usage.policyStatus} />
                  </td>
                  <td className="p-4">
                    <div className="flex flex-wrap gap-1">
                      {usage.dataTypesShared.slice(0, 2).map((dt) => (
                        <span
                          key={dt}
                          className="text-xs px-2 py-0.5 rounded"
                          style={{
                            background: 'var(--surface-2)',
                            color: 'var(--fg-2)',
                          }}
                        >
                          {dt.replace(/_/g, ' ')}
                        </span>
                      ))}
                      {usage.dataTypesShared.length > 2 && (
                        <span className="text-xs" style={{ color: 'var(--muted)' }}>
                          +{usage.dataTypesShared.length - 2}
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ViolationsTable({ data, hasSearch = false }: { data: PolicyViolation[]; hasSearch?: boolean }) {
  if (data.length === 0) {
    return (
      <div className="card-sentinel rounded-xl p-12 text-center" style={{ color: 'var(--subtle)' }}>
        <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50 text-green-500/50" />
        <p className="text-lg font-medium mb-1">{hasSearch ? 'No matching policy violations' : 'No policy violations reported'}</p>
        <p className="text-sm">{hasSearch ? 'Try a different search term.' : 'Reported policy violations will appear here.'}</p>
      </div>
    )
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
          Policy Violations
        </h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
          Events reported by policy evaluation, separate from raw observed activity.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                User
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Tool
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Violation Type
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Severity
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Time
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((violation) => (
              <tr key={violation.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 text-sm" style={{ color: 'var(--fg)' }}>
                  {violation.userName}
                </td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                  {violation.tool}
                </td>
                <td className="p-4">
                  <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>
                    {violation.violationType.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="p-4">
                  <SeverityBadge severity={violation.severity} />
                </td>
                <td className="p-4">
                  <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
                    <Clock className="h-3 w-3" />
                    {formatDisplayTime(violation.timestamp)}
                  </div>
                </td>
                <td className="p-4">
                  {violation.resolved ? (
                    <span className="inline-flex items-center gap-1 text-xs text-green-400">
                      <CheckCircle className="h-3 w-3" /> Resolved
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-yellow-400">
                      <AlertTriangle className="h-3 w-3" /> Open
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ModelGuardTable({
  data,
  hasSearch = false,
  scanningModelId,
  loading = false,
  onScan,
}: {
  data: UnapprovedModel[]
  hasSearch?: boolean
  scanningModelId: string | null
  loading?: boolean
  onScan: (modelId: string) => void
}) {
  if (data.length === 0) {
    return (
      <div className="card-sentinel rounded-xl p-8 text-center" style={{ color: 'var(--subtle)' }}>
        <Shield className="h-10 w-10 mx-auto mb-3 opacity-50" />
        <p className="text-sm">{loading ? 'Loading Model Guard records' : hasSearch ? 'No matching Model Guard records' : 'No Model Guard model evidence reported'}</p>
      </div>
    )
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
          AI Model Guard
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Model
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Risk
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Decision
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Guard Status
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Evidence
              </th>
              <th className="text-right p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((model) => {
              const guard = model.modelGuard || {}
              const evidence = guard.evidence || {}
              const guardEvidence = modelGuardEvidenceSummary(guard)
              return (
                <tr key={model.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="p-4">
                    <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                      {model.name}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>
                      {model.provider || model.vendor || model.type || 'unknown'}
                    </div>
                  </td>
                  <td className="p-4">
                    <RiskBadge level={model.riskLevel} />
                  </td>
                  <td className="p-4">
                    <ModelGuardDecisionBadge decision={guard.decision || 'unknown'} />
                  </td>
                  <td className="p-4">
                    <ModelGuardStatusBadge status={guard.status || guard.enforcement || 'unsupported'} />
                  </td>
                  <td className="p-4 text-xs" style={{ color: 'var(--muted)' }}>
                    <div>
                      {evidence.findings_count ?? 0} findings
                      {evidence.highest_severity ? ` / ${evidence.highest_severity}` : ''}
                    </div>
                    <div className="truncate max-w-xs">
                      {guardEvidence.source}
                      {guardEvidence.packageFindingCount > 0 ? ` / ${guardEvidence.packageFindingCount} package finding${guardEvidence.packageFindingCount === 1 ? '' : 's'}` : ''}
                    </div>
                    <div className="truncate max-w-xs">
                      {guardEvidence.externalScoreCount > 0 ? `${guardEvidence.externalScoreCount} external score${guardEvidence.externalScoreCount === 1 ? '' : 's'}` : 'external scores not collected'}
                      {guardEvidence.consensusState !== 'not_collected' ? ` / consensus ${formatLabel(guardEvidence.consensusState)}` : ''}
                    </div>
                    <div className="truncate max-w-xs">
                      {guardEvidence.enforcementNote || evidence.reason || evidence.error || guard.fp_rationale || guard.action || 'No enforcement evidence recorded'}
                    </div>
                  </td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => onScan(model.id)}
                      disabled={scanningModelId === model.id}
                      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs disabled:opacity-60"
                      style={{
                        background: 'var(--surface-2)',
                        color: 'var(--fg)',
                      }}
                    >
                      <Shield className="h-3 w-3" />
                      {scanningModelId === model.id ? 'Scanning' : 'Scan'}
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function DiscoveryTable({ data, hasSearch = false }: { data: AIToolDiscovery[]; hasSearch?: boolean }) {
  if (data.length === 0) {
    return (
      <div className="card-sentinel rounded-xl p-12 text-center" style={{ color: 'var(--subtle)' }}>
        <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium mb-1">{hasSearch ? 'No matching inventory records' : 'No AI inventory reported'}</p>
        <p className="text-sm">{hasSearch ? 'Try a different search term.' : 'Processes, packages, extensions, model files, or service inventory will appear here when reported.'}</p>
      </div>
    )
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
          Inventory
        </h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
          Discovered AI-related components and services. This is inventory, not proof of prompt usage.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Tool
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Category
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Unique Users
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Total Requests
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Data Volume
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Risk Level
              </th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((tool) => (
              <tr key={tool.tool} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 text-sm font-medium" style={{ color: 'var(--fg)' }}>
                  {tool.tool}
                </td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                  {tool.category}
                </td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                  {tool.uniqueUsers}
                </td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                  {tool.totalRequests.toLocaleString()}
                </td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                  {tool.dataVolume}
                </td>
                <td className="p-4">
                  <RiskBadge level={tool.riskLevel} />
                </td>
                <td className="p-4">
                  <span
                    className={cn(
                      'text-xs px-2 py-1 rounded',
                      tool.status === 'allowed' && 'bg-green-500/20 text-green-400',
                      tool.status === 'monitored' && 'bg-yellow-500/20 text-yellow-400',
                      tool.status === 'blocked' && 'bg-red-500/20 text-red-400',
                    )}
                  >
                    {safeCapitalize(tool.status)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RiskBadge({ level }: { level: 'high' | 'medium' | 'low' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
        level === 'high' && 'bg-red-500/20 text-red-400',
        level === 'medium' && 'bg-yellow-500/20 text-yellow-400',
        level === 'low' && 'bg-green-500/20 text-green-400',
      )}
    >
      {level === 'high' && <Upload className="h-3 w-3" />}
      {safeCapitalize(level)}
    </span>
  )
}

function ModelGuardDecisionBadge({ decision }: { decision: string }) {
  const normalized = decision.toLowerCase()
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
        normalized === 'allow' && 'bg-green-500/20 text-green-400',
        normalized === 'review' && 'bg-yellow-500/20 text-yellow-400',
        normalized === 'block' && 'bg-red-500/20 text-red-400',
        normalized === 'unknown' && 'bg-blue-500/15 text-blue-400',
      )}
    >
      {normalized === 'allow' && <CheckCircle className="h-3 w-3" />}
      {normalized === 'review' && <Eye className="h-3 w-3" />}
      {normalized === 'block' && <XCircle className="h-3 w-3" />}
      {normalized === 'unknown' && <AlertTriangle className="h-3 w-3" />}
      {formatLabel(normalized)}
    </span>
  )
}

function ModelGuardStatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase()
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
        normalized === 'enforced' && 'bg-green-500/20 text-green-400',
        normalized === 'decision_only' && 'bg-yellow-500/20 text-yellow-400',
        normalized === 'degraded' && 'bg-orange-500/20 text-orange-400',
        normalized === 'failed' && 'bg-red-500/20 text-red-400',
        normalized === 'unsupported' && 'bg-blue-500/15 text-blue-400',
        ['pending', 'scanning'].includes(normalized) && 'bg-[var(--surface-2)] text-[var(--muted)]',
      )}
    >
      {normalized === 'enforced' && <CheckCircle className="h-3 w-3" />}
      {normalized === 'decision_only' && <Eye className="h-3 w-3" />}
      {normalized === 'degraded' && <AlertTriangle className="h-3 w-3" />}
      {normalized === 'failed' && <XCircle className="h-3 w-3" />}
      {normalized === 'unsupported' && <AlertTriangle className="h-3 w-3" />}
      {['pending', 'scanning'].includes(normalized) && <Clock className="h-3 w-3" />}
      {formatLabel(normalized)}
    </span>
  )
}

function PolicyBadge({ status }: { status: ShadowAIUsage['policyStatus'] }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
        status === 'approved' && 'bg-green-500/20 text-green-400',
        status === 'allow' && 'bg-green-500/20 text-green-400',
        status === 'pending' && 'bg-yellow-500/20 text-yellow-400',
        status === 'monitor' && 'bg-yellow-500/20 text-yellow-400',
        status === 'review' && 'bg-orange-500/20 text-orange-400',
        status === 'blocked' && 'bg-red-500/20 text-red-400',
        status === 'block' && 'bg-red-500/20 text-red-400',
        status === 'unknown' && 'bg-[var(--surface-2)] text-[var(--muted)]',
      )}
    >
      {status === 'approved' && <CheckCircle className="h-3 w-3" />}
      {(status === 'blocked' || status === 'block') && <XCircle className="h-3 w-3" />}
      {safeCapitalize(status)}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: PolicyViolation['severity'] }) {
  return (
    <span
      className={cn(
        'px-2 py-1 rounded text-xs font-medium uppercase',
        severity === 'critical' && 'bg-red-500/20 text-red-400',
        severity === 'high' && 'bg-orange-500/20 text-orange-400',
        severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
        severity === 'low' && 'bg-blue-500/20 text-blue-400',
      )}
    >
      {severity}
    </span>
  )
}
