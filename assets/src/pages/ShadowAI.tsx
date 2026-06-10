import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
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
} from 'lucide-react'
import { cn, safeCapitalize } from '@/lib/utils'
import { useState } from 'react'

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
  provider: string
  riskLevel: 'high' | 'medium' | 'low'
  usageCount: number
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
}

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

export default function ShadowAI({ discoveredServices, unapprovedModels: _unapprovedModels, stats, usage = [], violations = [], dataSourceHealth, gatewayPolicy }: ShadowAIProps) {
  const [activeTab, setActiveTab] = useState<'inventory' | 'activity' | 'policy' | 'prompts'>('inventory')
  const [searchQuery, setSearchQuery] = useState('')
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
  const query = searchQuery.trim().toLowerCase()
  const filteredUsage = normalizedUsage.filter((item) => matchesQuery(query, [
    item.userName,
    item.department,
    item.tool,
    item.accessMethod,
    item.policyStatus,
    ...item.dataTypesShared,
  ]))
  const filteredViolations = normalizedViolations.filter((item) => matchesQuery(query, [
    item.userName,
    item.tool,
    item.violationType,
    item.severity,
    item.description,
  ]))
  const filteredServices = normalizedServices.filter((item) => matchesQuery(query, [
    item.tool,
    item.category,
    item.status,
    item.riskLevel,
  ]))

  return (
    <MainLayout title="Shadow AI Detection">
      <Head title="Shadow AI Detection - Tamandua EDR" />

      <div className="space-y-6">
        <DataSourceHealthPanel health={dataSourceHealth} />

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Users with AI Activity"
            value={normalizedStats.totalUsers}
            icon={User}
            color="primary"
          />
          <StatCard
            title="AI Tools Detected"
            value={normalizedStats.activeAITools}
            icon={Eye}
            color="primary"
          />
          <StatCard
            title="High Risk Users"
            value={normalizedStats.highRiskUsers}
            icon={AlertTriangle}
            color="danger"
          />
          <StatCard
            title="Open Violations"
            value={normalizedStats.openViolations}
            icon={AlertOctagon}
            color="warning"
          />
        </div>

        {/* Data Exfiltration Risk Summary */}
        <div className="card-sentinel rounded-xl p-4">
          <h3 className="text-sm font-medium mb-1" style={{ color: 'var(--fg)' }}>Potential Data Exposure Signals</h3>
          <p className="text-xs mb-4" style={{ color: 'var(--muted)' }}>Derived from available metadata. Prompt and response bodies are not captured here.</p>
          {normalizedStats.dataExfiltrationByCategory.length > 0 ? (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {normalizedStats.dataExfiltrationByCategory.map((item) => (
                <div key={item.label} className="text-center">
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{item.value}</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>{formatLabel(item.label)}</div>
                  <div className={cn(
                    'mt-2 h-1 rounded-full',
                    item.color === 'red' ? 'bg-red-500' :
                    item.color === 'orange' ? 'bg-orange-500' :
                    item.color === 'yellow' ? 'bg-yellow-500' : 'bg-blue-500'
                  )} style={{ width: `${Math.min(item.value * 2, 100)}%`, margin: '0 auto' }} />
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
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-400'
                  : 'border-transparent hover:text-[var(--fg)]'
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
              style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            />
          </div>
          <button onClick={() => router.reload()} className="flex items-center gap-2 px-4 py-2 rounded-lg" style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}>
            <Filter className="h-4 w-4" />
            Refresh
          </button>
        </div>

        {/* Content based on active tab */}
        {activeTab === 'inventory' && <DiscoveryTable data={filteredServices} hasSearch={query.length > 0} />}
        {activeTab === 'activity' && (
          <div className="space-y-4">
            <UsageTable data={filteredUsage} hasSearch={query.length > 0} />
            <ViolationsTable data={filteredViolations} hasSearch={query.length > 0} />
          </div>
        )}
        {activeTab === 'policy' && (
          <PolicyDecisionPanel
            usage={filteredUsage}
            gateway={dataSourceHealth?.aiGateway}
            gatewayPolicy={gatewayPolicy}
            hasSearch={query.length > 0}
          />
        )}
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
  }
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
    policyEnforced: usage.policyEnforced === true,
    effectiveRiskScore: usage.effectiveRiskScore ?? 0,
    provider: usage.provider,
    domain: usage.domain,
    processName: usage.processName,
    hostname: usage.hostname,
  }
}

function normalizeViolation(violation: PolicyViolation): PolicyViolation {
  const raw = violation as PolicyViolation & { type?: string; status?: string; agentId?: string }
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

function matchesQuery(query: string, values: Array<string | number | undefined | null>) {
  if (!query) return true
  return values.some((value) => String(value ?? '').toLowerCase().includes(query))
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

function gatewayDetail(gateway?: DataSourceHealth['aiGateway']) {
  if (!gateway) return 'No gateway/browser/proxy metadata received'

  const lastSeen = gateway.lastSeen ? `Last seen ${formatDisplayTime(gateway.lastSeen)}` : 'No events yet'
  const persistence = gateway.persistenceStatus ? `persistence ${gateway.persistenceStatus}` : 'persistence unknown'
  const enforcement = gateway.inlineProxy
    ? gateway.enforcementMode || 'inline'
    : gateway.enforcementMode || 'decision_only'

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
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [saveStatus, setSaveStatus] = useState('')

  const counts = usage.reduce(
    (acc, item) => {
      const key = item.policyStatus || 'unknown'
      acc[key] = (acc[key] || 0) + 1
      if (item.policyEnforced) acc.enforced += 1
      return acc
    },
    { allow: 0, monitor: 0, review: 0, block: 0, unknown: 0, enforced: 0 } as Record<string, number>
  )

  const savePolicy = async () => {
    setSaving(true)
    setSaveError('')
    setSaveStatus('')

    try {
      const response = await fetch('/api/v1/ai-security/gateway/policy', {
        method: 'PUT',
        credentials: 'same-origin',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(policy),
      })

      const payload = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(payload?.message || 'Failed to save gateway policy')
      }

      setPolicy(payload?.data || policy)
      setSaveStatus('Policy saved')
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : 'Failed to save gateway policy')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <DecisionMetric title="Allow" value={counts.allow || 0} tone="green" />
        <DecisionMetric title="Monitor" value={counts.monitor || 0} tone="yellow" />
        <DecisionMetric title="Review" value={counts.review || 0} tone="orange" />
        <DecisionMetric title="Block" value={counts.block || 0} tone="red" />
        <DecisionMetric title="Enforced" value={counts.enforced || 0} tone="blue" />
      </div>

      <div className="card-sentinel rounded-xl p-4">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Enforcement Readiness</h3>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              {gateway?.enforcementNote || 'Endpoint bridge can queue conservative block actions. Inline proxy is not enabled.'}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <CapabilityPill label="Endpoint bridge" enabled={gateway?.enforcementAvailable === true} />
            <CapabilityPill label="Inline proxy" enabled={gateway?.inlineProxy === true} />
            <CapabilityPill label="Prompt capture" enabled={false} />
          </div>
        </div>
      </div>

      <GatewayPolicyEditor
        policy={policy}
        setPolicy={setPolicy}
        onSave={savePolicy}
        saving={saving}
        saveStatus={saveStatus}
        saveError={saveError}
      />

      <PolicyDecisionTable data={usage} hasSearch={hasSearch} />
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
      <div className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>{title}</div>
    </div>
  )
}

function CapabilityPill({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium',
      enabled ? 'bg-green-500/15 text-green-400' : 'bg-[var(--surface-2)] text-[var(--muted)]'
    )}>
      {enabled ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
      {label}
    </span>
  )
}

function GatewayPolicyEditor({
  policy,
  setPolicy,
  onSave,
  saving,
  saveStatus,
  saveError,
}: {
  policy: AIGatewayPolicy
  setPolicy: (policy: AIGatewayPolicy) => void
  onSave: () => void
  saving: boolean
  saveStatus: string
  saveError: string
}) {
  return (
    <div className="card-sentinel rounded-xl p-6">
      <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 mb-5">
        <div>
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>AI Gateway Policy</h3>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            Metadata-only decisions for browser extension, proxy, SDK, gateway, and endpoint telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saveStatus && <span className="text-xs text-green-400">{saveStatus}</span>}
          {saveError && <span className="text-xs text-red-400">{saveError}</span>}
          <button
            onClick={onSave}
            disabled={saving}
            className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-60"
            style={{ background: 'var(--primary)', color: 'white' }}
          >
            <CheckCircle className="h-4 w-4" />
            {saving ? 'Saving' : 'Save Policy'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <label className="space-y-2 text-sm">
          <span style={{ color: 'var(--fg)' }}>Default Decision</span>
          <select
            value={policy.default_decision || 'monitor'}
            onChange={(event) => setPolicy({ ...policy, default_decision: event.target.value as AIGatewayPolicy['default_decision'] })}
            className="w-full rounded-lg px-3 py-2"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
          >
            <option value="allow">allow</option>
            <option value="monitor">monitor</option>
            <option value="review">review</option>
            <option value="block">block</option>
          </select>
        </label>
        <NumberPolicyInput label="Allow Threshold" value={policy.max_risk_score_allow ?? 25} onChange={(value) => setPolicy({ ...policy, max_risk_score_allow: value })} />
        <NumberPolicyInput label="Review Threshold" value={policy.max_risk_score_monitor ?? 70} onChange={(value) => setPolicy({ ...policy, max_risk_score_monitor: value })} />
      </div>

      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ListPolicyInput label="Allowed Providers" value={policy.allowlist_providers || []} onChange={(value) => setPolicy({ ...policy, allowlist_providers: value })} />
        <ListPolicyInput label="Blocked Providers" value={policy.blocklist_providers || []} onChange={(value) => setPolicy({ ...policy, blocklist_providers: value })} />
        <ListPolicyInput label="Allowed Domains" value={policy.allowlist_domains || []} onChange={(value) => setPolicy({ ...policy, allowlist_domains: value })} />
        <ListPolicyInput label="Blocked Domains" value={policy.blocklist_domains || []} onChange={(value) => setPolicy({ ...policy, blocklist_domains: value })} />
        <ListPolicyInput label="Blocked Data Categories" value={policy.blocked_data_categories || ['credentials', 'secrets']} onChange={(value) => setPolicy({ ...policy, blocked_data_categories: value })} />
        <ListPolicyInput label="Review Data Categories" value={policy.high_risk_data_categories || ['pii', 'source_code', 'customer_data', 'financial_data']} onChange={(value) => setPolicy({ ...policy, high_risk_data_categories: value })} />
      </div>

      <label className="mt-4 flex items-center gap-3 text-sm" style={{ color: 'var(--fg)' }}>
        <input
          type="checkbox"
          checked={policy.enforce_block === true}
          onChange={(event) => setPolicy({ ...policy, enforce_block: event.target.checked })}
        />
        Queue endpoint enforcement for block decisions when an agent target is present
      </label>
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
            <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Prompt Interception</h3>
            <span className={cn(
              'px-2 py-1 rounded text-xs font-medium',
              status === 'active' && 'bg-green-500/15 text-green-400',
              status === 'stale' && 'bg-yellow-500/15 text-yellow-400',
              status === 'no_data' && 'bg-[var(--surface-2)] text-[var(--muted)]',
              status === 'unsupported' && 'bg-blue-500/15 text-blue-400'
            )}>
              {statusLabel(status)}
            </span>
          </div>
          <p className="mt-2 text-sm" style={{ color: 'var(--fg-2)' }}>
            No prompt or response content is shown because endpoint browser prompt interception is not reported by this data source.
          </p>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
              <div className="font-medium" style={{ color: 'var(--fg)' }}>Coverage</div>
              <div className="mt-1" style={{ color: 'var(--muted)' }}>{health?.coverage || 'Unsupported on endpoint agents'}</div>
            </div>
            <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
              <div className="font-medium" style={{ color: 'var(--fg)' }}>Displayed Data</div>
              <div className="mt-1" style={{ color: 'var(--muted)' }}>None. Use Observed Activity for network/DNS metadata.</div>
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
        style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
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
        style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
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
            <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{title}</div>
            <div className="text-xs truncate" style={{ color: 'var(--muted)' }}>{coverage}</div>
          </div>
        </div>
        <span className={cn('shrink-0 px-2 py-1 rounded text-xs font-medium', statusClasses[status])}>
          {statusLabel(status)}
        </span>
      </div>
      <div className="mt-4 text-xl font-semibold" style={{ color: 'var(--fg)' }}>{metric}</div>
      <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>{detail}</div>
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
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Policy Decision Timeline</h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
          Decisions are based on metadata only. Enforced means an endpoint action was requested or eligible, not that an inline proxy blocked the request.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Time</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Provider / Domain</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Endpoint</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Decision</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Enforcement</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Reason</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item) => (
              <tr key={item.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 text-sm whitespace-nowrap" style={{ color: 'var(--muted)' }}>{formatDisplayTime(item.lastUsed)}</td>
                <td className="p-4">
                  <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{item.provider || item.tool}</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>{item.domain || item.tool}</div>
                </td>
                <td className="p-4">
                  <div className="text-sm" style={{ color: 'var(--fg-2)' }}>{item.hostname || item.userName || 'Unknown endpoint'}</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>{item.processName || item.accessMethod}</div>
                </td>
                <td className="p-4">
                  <span className="text-sm" style={{ color: 'var(--fg)' }}>{item.effectiveRiskScore ?? 0}</span>
                </td>
                <td className="p-4">
                  <PolicyBadge status={item.policyStatus} />
                </td>
                <td className="p-4">
                  <span className={cn(
                    'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
                    item.policyEnforced ? 'bg-blue-500/15 text-blue-400' : 'bg-[var(--surface-2)] text-[var(--muted)]'
                  )}>
                    {item.policyEnforced ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                    {item.policyEnforced ? 'Endpoint action' : 'Decision only'}
                  </span>
                </td>
                <td className="p-4">
                  <div className="flex flex-wrap gap-1">
                    {(item.policyReasons || ['default_policy']).slice(0, 3).map((reason) => (
                      <span key={reason} className="text-xs px-2 py-0.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                        {reason.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
        <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
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
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Observed AI Activity</h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Network/DNS metadata and policy state. Prompt contents are not included.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>User</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>AI Tool</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Access Method</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Usage</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk Level</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Policy Status</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Data Types</th>
            </tr>
          </thead>
          <tbody>
            {data.map((usage) => {
              const CategoryIcon = categoryIcons[usage.toolCategory]
              return (
                <tr key={usage.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="p-4">
                    <div>
                      <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{usage.userName}</div>
                      <div className="text-xs" style={{ color: 'var(--muted)' }}>{usage.department}</div>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <CategoryIcon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>{usage.tool}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>{usage.accessMethod}</span>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>{usage.usageCount}</span>
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
                        <span key={dt} className="text-xs px-2 py-0.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                          {dt.replace(/_/g, ' ')}
                        </span>
                      ))}
                      {usage.dataTypesShared.length > 2 && (
                        <span className="text-xs" style={{ color: 'var(--muted)' }}>+{usage.dataTypesShared.length - 2}</span>
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
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Policy Violations</h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Events reported by policy evaluation, separate from raw observed activity.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>User</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Tool</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Violation Type</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Severity</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Time</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((violation) => (
              <tr key={violation.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 text-sm" style={{ color: 'var(--fg)' }}>{violation.userName}</td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{violation.tool}</td>
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
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Inventory</h3>
        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Discovered AI-related components and services. This is inventory, not proof of prompt usage.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Tool</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Category</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Unique Users</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Total Requests</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Data Volume</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk Level</th>
              <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((tool) => (
              <tr key={tool.tool} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                <td className="p-4 text-sm font-medium" style={{ color: 'var(--fg)' }}>{tool.tool}</td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{tool.category}</td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{tool.uniqueUsers}</td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{tool.totalRequests.toLocaleString()}</td>
                <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{tool.dataVolume}</td>
                <td className="p-4">
                  <RiskBadge level={tool.riskLevel} />
                </td>
                <td className="p-4">
                  <span className={cn(
                    'text-xs px-2 py-1 rounded',
                    tool.status === 'allowed' && 'bg-green-500/20 text-green-400',
                    tool.status === 'monitored' && 'bg-yellow-500/20 text-yellow-400',
                    tool.status === 'blocked' && 'bg-red-500/20 text-red-400'
                  )}>
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
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
      level === 'high' && 'bg-red-500/20 text-red-400',
      level === 'medium' && 'bg-yellow-500/20 text-yellow-400',
      level === 'low' && 'bg-green-500/20 text-green-400'
    )}>
      {level === 'high' && <Upload className="h-3 w-3" />}
      {safeCapitalize(level)}
    </span>
  )
}

function PolicyBadge({ status }: { status: ShadowAIUsage['policyStatus'] }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
      status === 'approved' && 'bg-green-500/20 text-green-400',
      status === 'allow' && 'bg-green-500/20 text-green-400',
      status === 'pending' && 'bg-yellow-500/20 text-yellow-400',
      status === 'monitor' && 'bg-yellow-500/20 text-yellow-400',
      status === 'review' && 'bg-orange-500/20 text-orange-400',
      status === 'blocked' && 'bg-red-500/20 text-red-400',
      status === 'block' && 'bg-red-500/20 text-red-400',
      status === 'unknown' && 'bg-[var(--surface-2)] text-[var(--muted)]'
    )}>
      {status === 'approved' && <CheckCircle className="h-3 w-3" />}
      {(status === 'blocked' || status === 'block') && <XCircle className="h-3 w-3" />}
      {safeCapitalize(status)}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: PolicyViolation['severity'] }) {
  return (
    <span className={cn(
      'px-2 py-1 rounded text-xs font-medium uppercase',
      severity === 'critical' && 'bg-red-500/20 text-red-400',
      severity === 'high' && 'bg-orange-500/20 text-orange-400',
      severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
      severity === 'low' && 'bg-blue-500/20 text-blue-400'
    )}>
      {severity}
    </span>
  )
}
