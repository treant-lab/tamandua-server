import { useState, useEffect, useCallback, useMemo } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  BarChart2,
  Shield,
  AlertTriangle,
  Target,
  Activity,
  Zap,
  TrendingUp,
  TrendingDown,
  Clock,
  CheckCircle,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RefreshCw,
  ChevronRight,
  Lightbulb,
  EyeOff,
  Layers,
  Cpu,
  Search,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// =========================================================================
// Types
// =========================================================================

interface Summary {
  totalRules: number
  activeRules: number
  totalDetections: number
  avgEffectiveness: number
  falsePositiveRate: number
  truePositiveRate: number
  detectionRate: number
  totalEventsProcessed: number
  avgPipelineLatencyMs: number
  totalRecommendations: number
  totalBlindSpots: number
}

interface RuleMetric {
  ruleId: string
  ruleName: string
  ruleType: string
  totalHits: number
  truePositives: number
  falsePositives: number
  benignCount: number
  avgConfidence: number
  fpRate: number
  tpRate: number
  effectivenessScore: number
  meanTriageSeconds: number | null
  detectionToAlertRatio: number
  mitreTechniques: string[]
  firstHitAt: string | null
  lastHitAt: string | null
}

interface PipelineStage {
  stage: string
  totalEvents: number
  avgLatencyMs: number
  p95LatencyMs: number
  errorCount: number
  errorRate: number
}

interface BlindSpots {
  mitre: {
    totalTechniques: number
    coveredTechniques: number
    coveragePercent: number
    uncoveredTechniques: string[]
  }
  eventTypes: {
    totalEventTypes: number
    coveredEventTypes: number
    uncoveredEventTypes: string[]
  }
  timeOfDay: {
    hourlyDistribution: { hour: number; count: number }[]
    gapHours: number[]
  }
}

interface Recommendation {
  id: string
  type: string
  priority: string
  ruleId?: string
  ruleName?: string
  title: string
  description: string
  impact?: string
  action?: string
  metrics?: Record<string, number>
}

interface TrendData {
  alertTrend: { date: string; count: number }[]
  fpTrend: { date: string; count: number }[]
  severityTrend: Record<string, string | number>[]
}

interface RuntimeMetricSummary {
  events_received?: number
  events_analyzed?: number
  events_observed?: number
  detections?: number
  detection_rate?: number
  latency?: {
    avg_ms?: number
    max_ms?: number
    count?: number
  }
  alerts?: {
    total?: number
    true_positives?: number
    false_positives?: number
    precision?: number
    false_positive_rate?: number
  }
  event_loss?: {
    expected?: number
    received?: number
    lost?: number
    loss_rate?: number
  }
  collector_health?: {
    samples?: number
    degraded_samples?: number
    degraded_rate?: number
    avg_score?: number
    avg_degradation_impact?: number
  }
}

interface PrecisionMetrics {
  totals?: RuntimeMetricSummary
  by_collector?: Record<string, RuntimeMetricSummary>
  by_profile?: Record<string, RuntimeMetricSummary>
  by_family?: Record<string, RuntimeMetricSummary>
}

interface EffectiveCoverage {
  summary?: {
    declared_collectors?: number
    active_collectors?: number
    configured_collectors?: number
    declared_techniques?: number
    active_techniques?: number
    configured_techniques?: number
    effective_coverage_percent?: number
    configured_coverage_percent?: number
    runtime_events_analyzed?: number
    runtime_detections?: number
    runtime_false_positive_rate?: number
    runtime_precision?: number
    runtime_event_loss_rate?: number
  }
  collectors?: {
    collector: string
    status: 'active' | 'configured' | 'possible' | string
    profiles: string[]
    tactics: string[]
    techniques: string[]
    technique_count: number
    coverage_levels?: Record<string, number>
    runtime?: RuntimeMetricSummary
  }[]
  techniques?: {
    technique_id: string
    technique: string
    tactic_id: string
    tactic: string
    status: 'active' | 'configured' | 'possible' | string
    collectors: string[]
    telemetry_requirements: string[]
  }[]
}

interface DetectionAnalyticsProps {
  summary?: Summary
  ruleMetrics?: RuleMetric[]
  pipeline?: PipelineStage[]
  blindSpots?: BlindSpots
  recommendations?: Recommendation[]
  trends?: TrendData
  precisionMetrics?: PrecisionMetrics
  effectiveCoverage?: EffectiveCoverage
}

// =========================================================================
// Default Values
// =========================================================================

const defaultSummary: Summary = {
  totalRules: 0,
  activeRules: 0,
  totalDetections: 0,
  avgEffectiveness: 0,
  falsePositiveRate: 0,
  truePositiveRate: 0,
  detectionRate: 0,
  totalEventsProcessed: 0,
  avgPipelineLatencyMs: 0,
  totalRecommendations: 0,
  totalBlindSpots: 0,
}

const defaultBlindSpots: BlindSpots = {
  mitre: { totalTechniques: 0, coveredTechniques: 0, coveragePercent: 0, uncoveredTechniques: [] },
  eventTypes: { totalEventTypes: 0, coveredEventTypes: 0, uncoveredEventTypes: [] },
  timeOfDay: { hourlyDistribution: [], gapHours: [] },
}

const defaultTrends: TrendData = {
  alertTrend: [],
  fpTrend: [],
  severityTrend: [],
}

// =========================================================================
// Main Component
// =========================================================================

export default function DetectionAnalytics({
  summary = defaultSummary,
  ruleMetrics = [],
  pipeline = [],
  blindSpots = defaultBlindSpots,
  recommendations = [],
  trends = defaultTrends,
  precisionMetrics = {},
  effectiveCoverage = {},
}: DetectionAnalyticsProps) {
  const [selectedTab, setSelectedTab] = useState<'overview' | 'rules' | 'pipeline' | 'collectors' | 'blindspots' | 'recommendations' | 'trends'>('overview')
  const [ruleSearch, setRuleSearch] = useState('')
  const [ruleSortBy, setRuleSortBy] = useState<keyof RuleMetric>('effectivenessScore')
  const [ruleSortOrder, setRuleSortOrder] = useState<'asc' | 'desc'>('desc')
  const [apiOverview, setApiOverview] = useState<Summary | null>(null)
  const [apiPrecisionMetrics, setApiPrecisionMetrics] = useState<PrecisionMetrics | null>(null)
  const [apiEffectiveCoverage, setApiEffectiveCoverage] = useState<EffectiveCoverage | null>(null)
  const [loading, setLoading] = useState(false)

  // Poll API for live updates every 30s
  const fetchOverview = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/detection-analytics/overview')
      if (res.ok) {
        const json = await res.json()
        setApiOverview(json.data)
      }

      const [precisionRes, coverageRes] = await Promise.all([
        fetch('/api/v1/detection-analytics/precision-metrics'),
        fetch('/api/v1/detection-analytics/effective-coverage'),
      ])

      if (precisionRes.ok) {
        const json = await precisionRes.json()
        setApiPrecisionMetrics(json.data)
      }

      if (coverageRes.ok) {
        const json = await coverageRes.json()
        setApiEffectiveCoverage(json.data)
      }
    } catch {
      // Silently fail, use server-side props
    }
  }, [])

  useEffect(() => {
    fetchOverview()
    const interval = setInterval(fetchOverview, 30_000)
    return () => clearInterval(interval)
  }, [fetchOverview])

  const currentSummary = apiOverview || summary
  const currentPrecisionMetrics = apiPrecisionMetrics || precisionMetrics
  const currentEffectiveCoverage = apiEffectiveCoverage || effectiveCoverage

  // Sorted and filtered rules
  const filteredRules = useMemo(() => {
    let rules = [...ruleMetrics]

    if (ruleSearch) {
      const search = ruleSearch.toLowerCase()
      rules = rules.filter(r =>
        r.ruleName.toLowerCase().includes(search) ||
        r.ruleType.toLowerCase().includes(search) ||
        r.ruleId.toLowerCase().includes(search)
      )
    }

    rules.sort((a, b) => {
      const aVal = a[ruleSortBy] ?? 0
      const bVal = b[ruleSortBy] ?? 0
      if (ruleSortOrder === 'asc') return aVal < bVal ? -1 : aVal > bVal ? 1 : 0
      return aVal > bVal ? -1 : aVal < bVal ? 1 : 0
    })

    return rules
  }, [ruleMetrics, ruleSearch, ruleSortBy, ruleSortOrder])

  const handleRuleSort = (field: keyof RuleMetric) => {
    if (ruleSortBy === field) {
      setRuleSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setRuleSortBy(field)
      setRuleSortOrder('desc')
    }
  }

  const tabs = [
    { id: 'overview' as const, label: 'Overview', icon: BarChart2 },
    { id: 'rules' as const, label: 'Rule Performance', icon: Shield },
    { id: 'pipeline' as const, label: 'Pipeline', icon: Cpu },
    { id: 'collectors' as const, label: 'Collectors', icon: Activity },
    { id: 'blindspots' as const, label: 'Blind Spots', icon: EyeOff },
    { id: 'recommendations' as const, label: 'Recommendations', icon: Lightbulb },
    { id: 'trends' as const, label: 'Trends', icon: TrendingUp },
  ]

  return (
    <MainLayout title="Detection Analytics & Tuning">
      <Head title="Detection Analytics - Tamandua EDR" />

      <div className="space-y-6">
        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <OverviewCard
            title="Total Rules"
            value={currentSummary.totalRules}
            subtitle={`${currentSummary.activeRules} active`}
            icon={Shield}
            color="primary"
          />
          <OverviewCard
            title="Avg Effectiveness"
            value={`${currentSummary.avgEffectiveness.toFixed(1)}%`}
            subtitle="weighted TP/FP/volume"
            icon={Target}
            color={currentSummary.avgEffectiveness >= 70 ? 'success' : currentSummary.avgEffectiveness >= 40 ? 'warning' : 'danger'}
          />
          <OverviewCard
            title="False Positive Rate"
            value={`${currentSummary.falsePositiveRate.toFixed(1)}%`}
            subtitle={`${currentSummary.truePositiveRate.toFixed(1)}% TP rate`}
            icon={AlertTriangle}
            color={currentSummary.falsePositiveRate <= 10 ? 'success' : currentSummary.falsePositiveRate <= 30 ? 'warning' : 'danger'}
          />
          <OverviewCard
            title="Detection Rate"
            value={`${currentSummary.detectionRate.toFixed(1)}%`}
            subtitle={`${currentSummary.totalDetections.toLocaleString()} total`}
            icon={Activity}
            color="primary"
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 pb-0 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setSelectedTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
                selectedTab === tab.id
                  ? 'border-b-2'
                  : 'border-transparent'
              )}
              style={{
                color: selectedTab === tab.id ? 'var(--fg)' : 'var(--muted)',
                borderBottomColor: selectedTab === tab.id ? 'var(--emerald-500)' : 'transparent',
                background: selectedTab === tab.id ? 'var(--surface-2)' : 'transparent',
              }}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
              {tab.id === 'recommendations' && recommendations.length > 0 && (
                <span
                  className="ml-1 px-1.5 py-0.5 text-xs rounded-full"
                  style={{ background: 'var(--high-bg)', color: 'var(--high)' }}
                >
                  {recommendations.length}
                </span>
              )}
            </button>
          ))}

          <div className="flex-1" />

          <button
            onClick={() => { setLoading(true); fetchOverview().finally(() => setLoading(false)) }}
            className="flex items-center gap-2 px-3 py-1.5 text-sm transition-colors"
            style={{ color: 'var(--muted)' }}
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            Refresh
          </button>
        </div>

        {/* Tab Content */}
        {selectedTab === 'overview' && (
          <OverviewTab
            summary={currentSummary}
            pipeline={pipeline}
            blindSpots={blindSpots}
            recommendations={recommendations}
            ruleMetrics={ruleMetrics}
          />
        )}

        {selectedTab === 'rules' && (
          <RulesTab
            rules={filteredRules}
            search={ruleSearch}
            onSearchChange={setRuleSearch}
            sortBy={ruleSortBy}
            sortOrder={ruleSortOrder}
            onSort={handleRuleSort}
          />
        )}

        {selectedTab === 'pipeline' && (
          <PipelineTab stages={pipeline} summary={currentSummary} />
        )}

        {selectedTab === 'collectors' && (
          <CollectorRuntimeTab
            precisionMetrics={currentPrecisionMetrics}
            effectiveCoverage={currentEffectiveCoverage}
          />
        )}

        {selectedTab === 'blindspots' && (
          <BlindSpotsTab blindSpots={blindSpots} />
        )}

        {selectedTab === 'recommendations' && (
          <RecommendationsTab recommendations={recommendations} />
        )}

        {selectedTab === 'trends' && (
          <TrendsTab trends={trends} />
        )}
      </div>
    </MainLayout>
  )
}

// =========================================================================
// Overview Card
// =========================================================================

interface OverviewCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: React.ElementType
  color: 'primary' | 'success' | 'warning' | 'danger'
}

function OverviewCard({ title, value, subtitle, icon: Icon, color }: OverviewCardProps) {
  const colorStyles = {
    primary: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    success: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    warning: { bg: 'var(--high-bg)', text: 'var(--high)' },
    danger: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
  }

  const styles = colorStyles[color]

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between mb-3">
        <div className="p-2 rounded-lg" style={{ background: styles.bg }}>
          <Icon className="h-5 w-5" style={{ color: styles.text }} />
        </div>
      </div>
      <div>
        <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
        {subtitle && <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>{subtitle}</p>}
      </div>
    </div>
  )
}

// =========================================================================
// Overview Tab
// =========================================================================

interface OverviewTabProps {
  summary: Summary
  pipeline: PipelineStage[]
  blindSpots: BlindSpots
  recommendations: Recommendation[]
  ruleMetrics: RuleMetric[]
}

function OverviewTab({ summary, pipeline, blindSpots, recommendations, ruleMetrics }: OverviewTabProps) {
  const topRules = ruleMetrics.slice(0, 5)
  const worstRules = [...ruleMetrics].sort((a, b) => b.fpRate - a.fpRate).slice(0, 5)
  const criticalRecs = recommendations.filter(r => r.priority === 'critical' || r.priority === 'high')

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Pipeline Summary */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Cpu className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Pipeline Performance
        </h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
            <span style={{ color: 'var(--muted)' }}>Total Events Processed</span>
            <span className="font-mono" style={{ color: 'var(--fg)' }}>{summary.totalEventsProcessed.toLocaleString()}</span>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
            <span style={{ color: 'var(--muted)' }}>Avg Pipeline Latency</span>
            <span className="font-mono" style={{ color: 'var(--fg)' }}>{summary.avgPipelineLatencyMs.toFixed(2)} ms</span>
          </div>
          {pipeline.slice(0, 4).map(stage => (
            <div key={stage.stage} className="flex items-center justify-between p-2 rounded">
              <span className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{stage.stage.replace(/_/g, ' ')}</span>
              <div className="flex items-center gap-3 text-xs">
                <span style={{ color: 'var(--fg-2)' }}>{stage.avgLatencyMs.toFixed(1)} ms avg</span>
                {stage.errorCount > 0 && (
                  <span style={{ color: 'var(--crit)' }}>{stage.errorCount} errors</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* MITRE Coverage */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          MITRE ATT&CK Coverage
        </h3>
        <div className="text-center mb-4">
          <div className="text-4xl font-bold" style={{ color: 'var(--fg)' }}>
            {(blindSpots.mitre?.coveragePercent ?? 0).toFixed(1)}%
          </div>
          <div className="text-sm" style={{ color: 'var(--muted)' }}>
            {blindSpots.mitre?.coveredTechniques ?? 0} of {blindSpots.mitre?.totalTechniques ?? 0} techniques covered
          </div>
        </div>
        <div className="h-3 rounded-full overflow-hidden mb-4" style={{ background: 'var(--surface-3)' }}>
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${blindSpots.mitre?.coveragePercent ?? 0}%`, background: 'var(--emerald-500)' }}
          />
        </div>
        <div className="flex items-center justify-between text-sm">
          <span style={{ color: 'var(--muted)' }}>{summary.totalBlindSpots} blind spots identified</span>
          <span className="text-xs" style={{ color: 'var(--emerald-400)' }}>{(blindSpots.mitre?.uncoveredTechniques ?? []).length} uncovered techniques</span>
        </div>
      </div>

      {/* Top Performing Rules */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <TrendingUp className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Top Performing Rules
        </h3>
        {topRules.length === 0 ? (
          <div className="text-center py-6" style={{ color: 'var(--subtle)' }}>
            <Shield className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No rule metrics available yet</p>
          </div>
        ) : (
          <div className="space-y-2">
            {topRules.map((rule, idx) => (
              <div key={rule.ruleId} className="flex items-center gap-3 p-2 rounded hover:opacity-80 transition-opacity" style={{ background: 'var(--surface-2)' }}>
                <span className="text-xs font-mono w-5" style={{ color: 'var(--subtle)' }}>{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm truncate" style={{ color: 'var(--fg)' }}>{rule.ruleName}</p>
                  <p className="text-xs" style={{ color: 'var(--subtle)' }}>{rule.ruleType} -- {rule.totalHits} hits</p>
                </div>
                <EffectivenessBar value={rule.effectivenessScore} />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* High FP Rules */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <TrendingDown className="h-5 w-5" style={{ color: 'var(--crit)' }} />
          Highest False Positive Rates
        </h3>
        {worstRules.length === 0 || worstRules[0].fpRate === 0 ? (
          <div className="text-center py-6" style={{ color: 'var(--subtle)' }}>
            <CheckCircle className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No false positives detected</p>
          </div>
        ) : (
          <div className="space-y-2">
            {worstRules.filter(r => r.fpRate > 0).map((rule, idx) => (
              <div key={rule.ruleId} className="flex items-center gap-3 p-2 rounded hover:opacity-80 transition-opacity" style={{ background: 'var(--surface-2)' }}>
                <span className="text-xs font-mono w-5" style={{ color: 'var(--subtle)' }}>{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm truncate" style={{ color: 'var(--fg)' }}>{rule.ruleName}</p>
                  <p className="text-xs" style={{ color: 'var(--subtle)' }}>{rule.falsePositives} FPs / {rule.truePositives} TPs</p>
                </div>
                <span
                  className="text-xs font-mono px-2 py-0.5 rounded"
                  style={{
                    background: rule.fpRate > 0.3 ? 'var(--crit-bg)' : rule.fpRate > 0.1 ? 'var(--high-bg)' : 'var(--emerald-glow)',
                    color: rule.fpRate > 0.3 ? 'var(--crit)' : rule.fpRate > 0.1 ? 'var(--high)' : 'var(--emerald-400)',
                  }}
                >
                  {(rule.fpRate * 100).toFixed(1)}% FP
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Critical Recommendations */}
      {criticalRecs.length > 0 && (
        <div className="lg:col-span-2 card-sentinel" style={{ borderColor: 'var(--high)' }}>
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Lightbulb className="h-5 w-5" style={{ color: 'var(--high)' }} />
            Priority Recommendations
            <span
              className="text-xs px-2 py-0.5 rounded-full"
              style={{ background: 'var(--high-bg)', color: 'var(--high)' }}
            >
              {criticalRecs.length}
            </span>
          </h3>
          <div className="space-y-3">
            {criticalRecs.slice(0, 5).map(rec => (
              <RecommendationCard key={rec.id} rec={rec} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// =========================================================================
// Rules Tab
// =========================================================================

interface RulesTabProps {
  rules: RuleMetric[]
  search: string
  onSearchChange: (v: string) => void
  sortBy: keyof RuleMetric
  sortOrder: 'asc' | 'desc'
  onSort: (field: keyof RuleMetric) => void
}

function RulesTab({ rules, search, onSearchChange, sortBy, sortOrder, onSort }: RulesTabProps) {
  return (
    <div className="card-sentinel p-0">
      <div className="p-4 flex items-center justify-between flex-wrap gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Shield className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Rule Performance ({rules.length} rules)
        </h3>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder="Search rules..."
            className="input-sentinel pl-9 pr-4 py-1.5 text-sm"
            style={{ width: '200px' }}
          />
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <SortableHeader label="Rule Name" field="ruleName" current={sortBy} order={sortOrder} onSort={onSort} />
              <SortableHeader label="Type" field="ruleType" current={sortBy} order={sortOrder} onSort={onSort} />
              <SortableHeader label="Hits" field="totalHits" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <SortableHeader label="TP" field="truePositives" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <SortableHeader label="FP" field="falsePositives" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <SortableHeader label="FP Rate" field="fpRate" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <SortableHeader label="Confidence" field="avgConfidence" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <SortableHeader label="Effectiveness" field="effectivenessScore" current={sortBy} order={sortOrder} onSort={onSort} className="text-right" />
              <th className="px-4 py-3 text-left font-medium" style={{ color: 'var(--muted)' }}>MITRE</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Shield className="h-10 w-10 mx-auto mb-2 opacity-30" />
                  <p>No rule metrics available{search ? ' matching your search' : ' yet'}</p>
                </td>
              </tr>
            ) : (
              rules.map(rule => (
                <tr key={rule.ruleId} className="transition-colors hover:opacity-80" style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="px-4 py-3">
                    <div className="max-w-xs truncate" style={{ color: 'var(--fg)' }}>{rule.ruleName}</div>
                    {rule.lastHitAt && (
                      <div className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>
                        Last hit: {new Date(rule.lastHitAt).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <RuleTypeBadge type={rule.ruleType} />
                  </td>
                  <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>{rule.totalHits.toLocaleString()}</td>
                  <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--emerald-400)' }}>{rule.truePositives}</td>
                  <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--crit)' }}>{rule.falsePositives}</td>
                  <td className="px-4 py-3 text-right">
                    <span
                      className="font-mono"
                      style={{
                        color: rule.fpRate > 0.3 ? 'var(--crit)' : rule.fpRate > 0.1 ? 'var(--high)' : 'var(--emerald-400)',
                      }}
                    >
                      {(rule.fpRate * 100).toFixed(1)}%
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>
                    {(rule.avgConfidence * 100).toFixed(0)}%
                  </td>
                  <td className="px-4 py-3 text-right">
                    <EffectivenessBar value={rule.effectivenessScore} showValue />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[200px]">
                      {rule.mitreTechniques.slice(0, 3).map(t => (
                        <span
                          key={t}
                          className="text-xs px-1.5 py-0.5 rounded font-mono"
                          style={{ background: 'var(--surface-3)', color: 'var(--emerald-400)' }}
                        >
                          {t}
                        </span>
                      ))}
                      {rule.mitreTechniques.length > 3 && (
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>+{rule.mitreTechniques.length - 3}</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// =========================================================================
// Pipeline Tab
// =========================================================================

function PipelineTab({ stages, summary }: { stages: PipelineStage[]; summary: Summary }) {
  const maxLatency = Math.max(...stages.map(s => s.avgLatencyMs), 1)

  return (
    <div className="space-y-6">
      {/* Pipeline Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
              <Zap className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{summary.totalEventsProcessed.toLocaleString()}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Events Processed</p>
            </div>
          </div>
        </div>
        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'var(--med-bg)' }}>
              <Clock className="h-5 w-5" style={{ color: 'var(--med)' }} />
            </div>
            <div>
              <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{summary.avgPipelineLatencyMs.toFixed(2)} ms</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Avg Pipeline Latency</p>
            </div>
          </div>
        </div>
        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
              <Layers className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{stages.length}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Pipeline Stages</p>
            </div>
          </div>
        </div>
      </div>

      {/* Latency per Stage - Bar Chart */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-6 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <BarChart2 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Latency per Stage
        </h3>
        {stages.length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
            <Cpu className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No pipeline data available yet</p>
          </div>
        ) : (
          <div className="space-y-4">
            {stages.map(stage => (
              <div key={stage.stage} className="flex items-center gap-4">
                <div className="w-32 text-sm capitalize text-right flex-shrink-0" style={{ color: 'var(--fg-2)' }}>
                  {stage.stage.replace(/_/g, ' ')}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-6 rounded overflow-hidden relative" style={{ background: 'var(--surface-3)' }}>
                      {/* Avg latency bar */}
                      <div
                        className="h-full rounded transition-all"
                        style={{ width: `${(stage.avgLatencyMs / maxLatency) * 100}%`, background: 'var(--emerald-500)', opacity: 0.8 }}
                      />
                      {/* P95 latency marker */}
                      {stage.p95LatencyMs > 0 && (
                        <div
                          className="absolute top-0 h-full w-0.5"
                          style={{ left: `${Math.min((stage.p95LatencyMs / maxLatency) * 100, 100)}%`, background: 'var(--high)' }}
                          title={`P95: ${stage.p95LatencyMs.toFixed(1)} ms`}
                        />
                      )}
                    </div>
                    <div className="w-32 flex-shrink-0 text-right">
                      <span className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>{stage.avgLatencyMs.toFixed(1)} ms</span>
                      {stage.p95LatencyMs > 0 && (
                        <span className="text-xs ml-2" style={{ color: 'var(--high)' }}>p95: {stage.p95LatencyMs.toFixed(1)}</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="w-24 text-right flex-shrink-0">
                  <span className="text-xs" style={{ color: 'var(--subtle)' }}>{stage.totalEvents.toLocaleString()} events</span>
                  {stage.errorCount > 0 && (
                    <div className="text-xs" style={{ color: 'var(--crit)' }}>{stage.errorCount} errors</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Legend */}
        {stages.length > 0 && (
          <div className="flex items-center gap-6 mt-6 pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted)' }}>
              <div className="w-4 h-2 rounded" style={{ background: 'var(--emerald-500)', opacity: 0.8 }} />
              Average Latency
            </div>
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted)' }}>
              <div className="w-0.5 h-4" style={{ background: 'var(--high)' }} />
              P95 Latency
            </div>
          </div>
        )}
      </div>

      {/* Stage Details Table */}
      <div className="card-sentinel p-0">
        <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Stage Details</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="px-4 py-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Stage</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Events</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Avg Latency</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>P95 Latency</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Errors</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Error Rate</th>
              </tr>
            </thead>
            <tbody>
              {stages.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--subtle)' }}>
                    No pipeline stage data available
                  </td>
                </tr>
              ) : (
                stages.map(stage => (
                  <tr key={stage.stage} className="hover:opacity-80 transition-opacity" style={{ borderBottom: '1px solid var(--hairline)' }}>
                    <td className="px-4 py-3 capitalize" style={{ color: 'var(--fg)' }}>{stage.stage.replace(/_/g, ' ')}</td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>{stage.totalEvents.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>{stage.avgLatencyMs.toFixed(2)} ms</td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--high)' }}>{stage.p95LatencyMs.toFixed(2)} ms</td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--crit)' }}>{stage.errorCount}</td>
                    <td className="px-4 py-3 text-right font-mono">
                      <span style={{
                        color: stage.errorRate > 0.05 ? 'var(--crit)' : stage.errorRate > 0.01 ? 'var(--high)' : 'var(--emerald-400)',
                      }}>
                        {(stage.errorRate * 100).toFixed(2)}%
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// =========================================================================
// Collector Runtime Tab
// =========================================================================

function CollectorRuntimeTab({
  precisionMetrics,
  effectiveCoverage,
}: {
  precisionMetrics: PrecisionMetrics
  effectiveCoverage: EffectiveCoverage
}) {
  const totals = precisionMetrics.totals || {}
  const coverageSummary = effectiveCoverage.summary || {}
  const collectors = effectiveCoverage.collectors || []
  const activeCollectors = collectors.filter(c => c.status === 'active')
  const visibleCollectors = collectors.slice(0, 20)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <OverviewCard
          title="Active Collectors"
          value={coverageSummary.active_collectors || activeCollectors.length}
          subtitle={`${coverageSummary.declared_collectors || collectors.length} declared`}
          icon={Activity}
          color="primary"
        />
        <OverviewCard
          title="Effective MITRE Coverage"
          value={`${(coverageSummary.effective_coverage_percent || 0).toFixed(1)}%`}
          subtitle={`${coverageSummary.active_techniques || 0} active techniques`}
          icon={Target}
          color={(coverageSummary.effective_coverage_percent || 0) >= 70 ? 'success' : (coverageSummary.effective_coverage_percent || 0) >= 40 ? 'warning' : 'danger'}
        />
        <OverviewCard
          title="Runtime Precision"
          value={`${((totals.alerts?.precision || coverageSummary.runtime_precision || 0) * 100).toFixed(1)}%`}
          subtitle={`${totals.alerts?.false_positives || 0} false positives`}
          icon={CheckCircle}
          color={(totals.alerts?.precision || 0) >= 0.8 ? 'success' : (totals.alerts?.precision || 0) >= 0.5 ? 'warning' : 'danger'}
        />
        <OverviewCard
          title="Event Loss"
          value={`${((totals.event_loss?.loss_rate || coverageSummary.runtime_event_loss_rate || 0) * 100).toFixed(2)}%`}
          subtitle={`${totals.event_loss?.lost || 0} lost events`}
          icon={AlertTriangle}
          color={(totals.event_loss?.loss_rate || 0) <= 0.01 ? 'success' : (totals.event_loss?.loss_rate || 0) <= 0.05 ? 'warning' : 'danger'}
        />
      </div>

      <div className="card-sentinel p-0">
        <div className="p-4 flex items-center justify-between gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
          <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Cpu className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            Collector Precision and Coverage
          </h3>
          <span className="text-xs" style={{ color: 'var(--subtle)' }}>
            {visibleCollectors.length} of {collectors.length} collectors
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="px-4 py-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Collector</th>
                <th className="px-4 py-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Events</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Detections</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Latency</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>FP Rate</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>Loss</th>
                <th className="px-4 py-3 text-right font-medium" style={{ color: 'var(--muted)' }}>MITRE</th>
              </tr>
            </thead>
            <tbody>
              {visibleCollectors.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center" style={{ color: 'var(--subtle)' }}>
                    <Cpu className="h-10 w-10 mx-auto mb-2 opacity-30" />
                    <p>No collector coverage loaded yet</p>
                  </td>
                </tr>
              ) : (
                visibleCollectors.map(collector => {
                  const runtime = collector.runtime || {}

                  return (
                    <tr key={collector.collector} className="hover:opacity-80 transition-opacity" style={{ borderBottom: '1px solid var(--hairline)' }}>
                      <td className="px-4 py-3">
                        <div className="font-mono" style={{ color: 'var(--fg)' }}>{collector.collector}</div>
                        <div className="text-xs truncate max-w-xs" style={{ color: 'var(--subtle)' }}>
                          {(collector.profiles || []).join(', ')}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <CollectorStatusBadge status={collector.status} />
                      </td>
                      <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>
                        {(runtime.events_analyzed || runtime.events_received || 0).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--emerald-400)' }}>
                        {(runtime.detections || 0).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right font-mono" style={{ color: 'var(--fg-2)' }}>
                        {(runtime.latency?.avg_ms || 0).toFixed(2)} ms
                      </td>
                      <td className="px-4 py-3 text-right font-mono" style={{ color: (runtime.alerts?.false_positive_rate || 0) > 0.1 ? 'var(--crit)' : 'var(--fg-2)' }}>
                        {formatPercent(runtime.alerts?.false_positive_rate)}
                      </td>
                      <td className="px-4 py-3 text-right font-mono" style={{ color: (runtime.event_loss?.loss_rate || 0) > 0.01 ? 'var(--high)' : 'var(--fg-2)' }}>
                        {formatPercent(runtime.event_loss?.loss_rate)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className="text-xs font-mono" style={{ color: 'var(--fg-2)' }}>{collector.technique_count}</span>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Active MITRE Techniques by Collector
        </h3>
        <div className="flex flex-wrap gap-2">
          {(effectiveCoverage.techniques || []).slice(0, 40).map(technique => (
            <span
              key={technique.technique_id}
              className="text-xs px-2 py-1 rounded font-mono"
              title={`${technique.technique} - ${technique.collectors.join(', ')}`}
              style={{
                background: technique.status === 'active' ? 'var(--emerald-glow)' : technique.status === 'configured' ? 'var(--high-bg)' : 'var(--surface-2)',
                color: technique.status === 'active' ? 'var(--emerald-400)' : technique.status === 'configured' ? 'var(--high)' : 'var(--muted)',
                border: '1px solid var(--hairline)',
              }}
            >
              {technique.technique_id}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

function CollectorStatusBadge({ status }: { status: string }) {
  const styles =
    status === 'active'
      ? { background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }
      : status === 'configured'
        ? { background: 'var(--high-bg)', color: 'var(--high)' }
        : { background: 'var(--surface-3)', color: 'var(--muted)' }

  return (
    <span className="text-xs px-2 py-0.5 rounded uppercase" style={styles}>
      {status}
    </span>
  )
}

function formatPercent(value?: number) {
  return `${((value || 0) * 100).toFixed(2)}%`
}

// =========================================================================
// Blind Spots Tab
// =========================================================================

function BlindSpotsTab({ blindSpots }: { blindSpots: BlindSpots }) {
  const mitre = blindSpots.mitre || { totalTechniques: 0, coveredTechniques: 0, coveragePercent: 0, uncoveredTechniques: [] }
  const eventTypes = blindSpots.eventTypes || { totalEventTypes: 0, coveredEventTypes: 0, uncoveredEventTypes: [] }
  const timeGaps = blindSpots.timeOfDay || { hourlyDistribution: [], gapHours: [] }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* MITRE Coverage */}
      <div className="lg:col-span-2 card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          MITRE ATT&CK Coverage Matrix
        </h3>
        <div className="flex items-center gap-6 mb-6">
          <div>
            <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{mitre.coveragePercent.toFixed(1)}%</span>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>Overall coverage</p>
          </div>
          <div>
            <span className="text-3xl font-bold" style={{ color: 'var(--emerald-400)' }}>{mitre.coveredTechniques}</span>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>Covered</p>
          </div>
          <div>
            <span className="text-3xl font-bold" style={{ color: 'var(--crit)' }}>{mitre.uncoveredTechniques.length}</span>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>Uncovered</p>
          </div>
        </div>

        {/* MITRE technique grid */}
        {mitre.uncoveredTechniques.length > 0 ? (
          <div>
            <p className="text-sm mb-3" style={{ color: 'var(--muted)' }}>Uncovered techniques requiring rules:</p>
            <div className="flex flex-wrap gap-2">
              {mitre.uncoveredTechniques.map(tech => (
                <span
                  key={tech}
                  className="text-xs px-2 py-1 rounded font-mono"
                  style={{ background: 'var(--crit-bg)', color: 'var(--crit)', border: '1px solid var(--crit)' }}
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-center py-4" style={{ color: 'var(--subtle)' }}>
            <CheckCircle className="h-8 w-8 mx-auto mb-2 opacity-50" style={{ color: 'var(--emerald-400)' }} />
            <p className="text-sm">All tracked techniques have detection coverage</p>
          </div>
        )}
      </div>

      {/* Event Type Coverage */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Layers className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Event Type Coverage
        </h3>
        <div className="mb-4">
          <div className="text-center mb-3">
            <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>
              {eventTypes.coveredEventTypes} / {eventTypes.totalEventTypes}
            </span>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>event types covered</p>
          </div>
          <div className="h-3 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
            <div
              className="h-full rounded-full"
              style={{ width: `${eventTypes.totalEventTypes > 0 ? (eventTypes.coveredEventTypes / eventTypes.totalEventTypes * 100) : 0}%`, background: 'var(--emerald-500)' }}
            />
          </div>
        </div>

        {eventTypes.uncoveredEventTypes.length > 0 ? (
          <div>
            <p className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>Uncovered event types:</p>
            <div className="space-y-1">
              {eventTypes.uncoveredEventTypes.map(et => (
                <div key={et} className="flex items-center gap-2 p-1.5 rounded text-xs" style={{ background: 'var(--surface-2)' }}>
                  <EyeOff className="h-3 w-3 flex-shrink-0" style={{ color: 'var(--high)' }} />
                  <span className="font-mono" style={{ color: 'var(--fg-2)' }}>{et}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-center py-4" style={{ color: 'var(--subtle)' }}>
            <CheckCircle className="h-6 w-6 mx-auto mb-1 opacity-50" style={{ color: 'var(--emerald-400)' }} />
            <p className="text-xs">All event types covered</p>
          </div>
        )}
      </div>

      {/* Time of Day Coverage */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Clock className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Time-of-Day Coverage
        </h3>
        <p className="text-xs mb-4" style={{ color: 'var(--subtle)' }}>
          Detection volume per hour (last 7 days). Red bars indicate coverage gaps.
        </p>

        {timeGaps.hourlyDistribution.length > 0 ? (
          <div className="flex items-end gap-0.5 h-32">
            {timeGaps.hourlyDistribution.map(({ hour, count }) => {
              const maxCount = Math.max(...timeGaps.hourlyDistribution.map(h => h.count), 1)
              const height = (count / maxCount) * 100
              const isGap = timeGaps.gapHours.includes(hour)

              return (
                <div key={hour} className="flex-1 flex flex-col items-center gap-1" title={`${hour}:00 - ${count} detections`}>
                  <div
                    className="w-full rounded-t transition-all min-h-[2px]"
                    style={{
                      height: `${Math.max(height, 2)}%`,
                      background: isGap ? 'var(--crit)' : 'var(--emerald-500)',
                      opacity: isGap ? 0.5 : 0.7,
                    }}
                  />
                  {hour % 6 === 0 && (
                    <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{hour}h</span>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
            <Clock className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No hourly data available yet</p>
          </div>
        )}

        {timeGaps.gapHours.length > 0 && (
          <div className="mt-4 p-3 rounded-lg" style={{ background: 'var(--crit-bg)', border: '1px solid var(--crit)' }}>
            <p className="text-xs flex items-center gap-2" style={{ color: 'var(--crit)' }}>
              <AlertTriangle className="h-3 w-3 flex-shrink-0" />
              Low coverage hours: {timeGaps.gapHours.map(h => `${h}:00`).join(', ')}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// =========================================================================
// Recommendations Tab
// =========================================================================

function RecommendationsTab({ recommendations }: { recommendations: Recommendation[] }) {
  const grouped = {
    critical: recommendations.filter(r => r.priority === 'critical'),
    high: recommendations.filter(r => r.priority === 'high'),
    medium: recommendations.filter(r => r.priority === 'medium'),
    low: recommendations.filter(r => r.priority === 'low'),
  }

  return (
    <div className="space-y-6">
      {recommendations.length === 0 ? (
        <div className="card-sentinel p-12 text-center">
          <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" style={{ color: 'var(--emerald-400)' }} />
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>All Clear</h3>
          <p style={{ color: 'var(--muted)' }}>No tuning recommendations at this time. Detection rules are performing well.</p>
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <PriorityCard label="Critical" count={grouped.critical.length} color="crit" />
            <PriorityCard label="High" count={grouped.high.length} color="high" />
            <PriorityCard label="Medium" count={grouped.medium.length} color="med" />
            <PriorityCard label="Low" count={grouped.low.length} color="low" />
          </div>

          {/* Recommendation List */}
          <div className="card-sentinel p-0">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Lightbulb className="h-5 w-5" style={{ color: 'var(--high)' }} />
                All Recommendations ({recommendations.length})
              </h3>
            </div>
            <div style={{ borderTop: '1px solid transparent' }}>
              {recommendations.map(rec => (
                <div key={rec.id} style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <RecommendationCard rec={rec} detailed />
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// =========================================================================
// Trends Tab
// =========================================================================

function TrendsTab({ trends }: { trends: TrendData }) {
  const alertTrend = trends.alertTrend || []
  const fpTrend = trends.fpTrend || []

  const maxAlerts = Math.max(...alertTrend.map(t => t.count), 1)
  const maxFp = Math.max(...fpTrend.map(t => t.count), 1)

  return (
    <div className="space-y-6">
      {/* Alert Volume Trend */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <TrendingUp className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Alert Volume Trend (7 days)
        </h3>
        {alertTrend.length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
            <Activity className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No alert data available for trend analysis</p>
          </div>
        ) : (
          <div className="flex items-end gap-1 h-40">
            {alertTrend.map(point => {
              const height = (point.count / maxAlerts) * 100
              return (
                <div key={point.date} className="flex-1 flex flex-col items-center gap-1" title={`${point.date}: ${point.count} alerts`}>
                  <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{point.count}</span>
                  <div
                    className="w-full rounded-t transition-all hover:opacity-100"
                    style={{ height: `${Math.max(height, 2)}%`, background: 'var(--emerald-500)', opacity: 0.7 }}
                  />
                  <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{point.date.slice(5)}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* False Positive Trend */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <TrendingDown className="h-5 w-5" style={{ color: 'var(--crit)' }} />
          False Positive Trend (7 days)
        </h3>
        {fpTrend.length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
            <CheckCircle className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No false positive data available</p>
          </div>
        ) : (
          <div className="flex items-end gap-1 h-32">
            {fpTrend.map(point => {
              const height = (point.count / maxFp) * 100
              return (
                <div key={point.date} className="flex-1 flex flex-col items-center gap-1" title={`${point.date}: ${point.count} FPs`}>
                  <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{point.count}</span>
                  <div
                    className="w-full rounded-t transition-all hover:opacity-80"
                    style={{ height: `${Math.max(height, 2)}%`, background: 'var(--crit)', opacity: 0.5 }}
                  />
                  <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{point.date.slice(5)}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Severity Distribution Trend */}
      <div className="card-sentinel">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <BarChart2 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          Severity Distribution Trend
        </h3>
        {(trends.severityTrend || []).length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
            <BarChart2 className="h-10 w-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No severity trend data available</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th className="px-4 py-2 text-left" style={{ color: 'var(--muted)' }}>Date</th>
                  <th className="px-4 py-2 text-right" style={{ color: 'var(--crit)' }}>Critical</th>
                  <th className="px-4 py-2 text-right" style={{ color: 'var(--high)' }}>High</th>
                  <th className="px-4 py-2 text-right" style={{ color: 'var(--med)' }}>Medium</th>
                  <th className="px-4 py-2 text-right" style={{ color: 'var(--low)' }}>Low</th>
                  <th className="px-4 py-2 text-right" style={{ color: 'var(--muted)' }}>Info</th>
                </tr>
              </thead>
              <tbody>
                {(trends.severityTrend || []).map((row, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--hairline)' }}>
                    <td className="px-4 py-2" style={{ color: 'var(--fg-2)' }}>{row.date}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: 'var(--crit)' }}>{row.critical || 0}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: 'var(--high)' }}>{row.high || 0}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: 'var(--med)' }}>{row.medium || 0}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: 'var(--low)' }}>{row.low || 0}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: 'var(--muted)' }}>{row.info || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// =========================================================================
// Shared Sub-Components
// =========================================================================

function EffectivenessBar({ value, showValue = false }: { value: number; showValue?: boolean }) {
  const percent = value * 100
  const getColor = () => {
    if (percent >= 70) return { bg: 'var(--emerald-500)', text: 'var(--emerald-400)' }
    if (percent >= 40) return { bg: 'var(--high)', text: 'var(--high)' }
    return { bg: 'var(--crit)', text: 'var(--crit)' }
  }
  const colors = getColor()

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${percent}%`, background: colors.bg }}
        />
      </div>
      {showValue && (
        <span className="text-xs font-mono w-12 text-right" style={{ color: colors.text }}>
          {percent.toFixed(0)}%
        </span>
      )}
    </div>
  )
}

function RuleTypeBadge({ type }: { type: string }) {
  const getColors = () => {
    switch (type) {
      case 'sigma': return { bg: 'rgba(168, 85, 247, 0.2)', text: '#a855f7' }
      case 'yara': return { bg: 'var(--high-bg)', text: 'var(--high)' }
      case 'ml':
      case 'ml_malware': return { bg: 'var(--med-bg)', text: 'var(--med)' }
      case 'ioc': return { bg: 'rgba(59, 130, 246, 0.2)', text: '#3b82f6' }
      case 'behavioral': return { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' }
      case 'c2': return { bg: 'var(--crit-bg)', text: 'var(--crit)' }
      case 'dns': return { bg: 'rgba(20, 184, 166, 0.2)', text: '#14b8a6' }
      case 'threat_intel_feed': return { bg: 'var(--high-bg)', text: 'var(--high)' }
      default: return { bg: 'var(--low-bg)', text: 'var(--low)' }
    }
  }
  const colors = getColors()

  return (
    <span
      className="text-xs px-2 py-0.5 rounded"
      style={{ background: colors.bg, color: colors.text }}
    >
      {type.toUpperCase().replace(/_/g, ' ')}
    </span>
  )
}

function SortableHeader({
  label,
  field,
  current,
  order,
  onSort,
  className = '',
}: {
  label: string
  field: keyof RuleMetric
  current: keyof RuleMetric
  order: 'asc' | 'desc'
  onSort: (field: keyof RuleMetric) => void
  className?: string
}) {
  const isActive = current === field

  return (
    <th
      className={cn('px-4 py-3 font-medium cursor-pointer select-none', className)}
      style={{ color: 'var(--muted)' }}
      onClick={() => onSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {isActive ? (
          order === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-30" />
        )}
      </span>
    </th>
  )
}

function RecommendationCard({ rec, detailed = false }: { rec: Recommendation; detailed?: boolean }) {
  const getPriorityStyles = () => {
    switch (rec.priority) {
      case 'critical': return { border: 'var(--crit)', bg: 'var(--crit-bg)', badge: { bg: 'var(--crit-bg)', text: 'var(--crit)' } }
      case 'high': return { border: 'var(--high)', bg: 'var(--high-bg)', badge: { bg: 'var(--high-bg)', text: 'var(--high)' } }
      case 'medium': return { border: 'var(--med)', bg: 'var(--med-bg)', badge: { bg: 'var(--med-bg)', text: 'var(--med)' } }
      case 'low': return { border: 'var(--low)', bg: 'var(--low-bg)', badge: { bg: 'var(--low-bg)', text: 'var(--low)' } }
      default: return { border: 'var(--border)', bg: 'var(--surface-2)', badge: { bg: 'var(--surface-3)', text: 'var(--muted)' } }
    }
  }
  const styles = getPriorityStyles()

  const typeLabels: Record<string, string> = {
    high_false_positive: 'High FP Rate',
    dormant_rule: 'Dormant Rule',
    correlated_rules: 'Correlated Rules',
    ml_threshold_adjustment: 'ML Threshold',
    low_effectiveness: 'Low Effectiveness',
  }

  return (
    <div
      className="p-4 rounded-r-lg"
      style={{ borderLeft: `2px solid ${styles.border}`, background: styles.bg }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className="text-xs px-2 py-0.5 rounded"
            style={{ background: styles.badge.bg, color: styles.badge.text }}
          >
            {rec.priority.toUpperCase()}
          </span>
          <span
            className="text-xs px-2 py-0.5 rounded"
            style={{ background: 'var(--surface-3)', color: 'var(--fg-2)' }}
          >
            {typeLabels[rec.type] || rec.type}
          </span>
          <h4 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{rec.title}</h4>
        </div>
        {rec.action && (
          <span
            className="text-xs px-2 py-0.5 rounded whitespace-nowrap"
            style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
          >
            {rec.action.replace(/_/g, ' ')}
          </span>
        )}
      </div>
      <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{rec.description}</p>
      {detailed && rec.impact && (
        <p className="text-xs flex items-center gap-1" style={{ color: 'var(--subtle)' }}>
          <ChevronRight className="h-3 w-3 flex-shrink-0" />
          {rec.impact}
        </p>
      )}
    </div>
  )
}

function PriorityCard({ label, count, color }: { label: string; count: number; color: string }) {
  const getColors = () => {
    switch (color) {
      case 'crit': return { bg: 'var(--crit-bg)', text: 'var(--crit)' }
      case 'high': return { bg: 'var(--high-bg)', text: 'var(--high)' }
      case 'med': return { bg: 'var(--med-bg)', text: 'var(--med)' }
      case 'low': return { bg: 'var(--low-bg)', text: 'var(--low)' }
      default: return { bg: 'var(--surface-2)', text: 'var(--muted)' }
    }
  }
  const colors = getColors()

  return (
    <div
      className="card-sentinel text-center"
      style={{ background: colors.bg }}
    >
      <p
        className="text-3xl font-bold"
        style={{ color: count > 0 ? colors.text : 'var(--dim)' }}
      >
        {count}
      </p>
      <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{label}</p>
    </div>
  )
}
