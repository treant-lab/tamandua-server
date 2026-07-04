import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  BarChart3,
  Bell,
  BellOff,
  Calendar,
  ChevronDown,
  ChevronRight,
  Clock,
  Database,
  Download,
  ExternalLink,
  Eye,
  Filter,
  GitBranch,
  Info,
  Key,
  Layers,
  MapPin,
  Minus,
  Monitor,
  MoveHorizontal,
  Network,
  Pause,
  Play,
  Plus,
  PlugZap,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Target,
  TrendingDown,
  TrendingUp,
  User,
  Users,
  XCircle,
  Zap,
} from 'lucide-react'
import { Tooltip } from '@/components/ui/baseui/Tooltip'
import { cn, formatDate } from '@/lib/utils'
import { useState, useEffect, useCallback, useRef } from 'react'
import { useDashboardChannel, getConnectionStatusColor, getConnectionStatusText } from '@/hooks/useSocket'
import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

interface BehavioralEntity {
  id: string
  name: string
  type: 'user' | 'host' | 'process'
  userRiskScore: number
  hostRiskScore: number
  lastSeen: string
}

interface BehavioralAnomaly {
  id: string
  type: string
  entityId: string
  entityType: 'user' | 'host' | 'process' | 'network'
  description: string
  riskScore: number
  deviationScore: number
  baselineValue: string | null
  observedValue: string | null
  mitreTechniques: string[]
  detectedAt: string
  ruleId?: string
}

interface DetectionCategory {
  name: string
  description: string
  mitre_techniques: string[]
  anomalies: BehavioralAnomaly[]
  count: number
  severity_distribution: Record<string, number>
}

interface EntityProfile {
  entity_type: string
  entity_id: string
  profile: Record<string, unknown>
  risk_score: number
  risk_level: string
  last_updated: string | null
  total_events: number
  recent_anomalies: BehavioralAnomaly[]
  peer_comparison: {
    risk_score_percentile: number
    event_volume_percentile: number
    anomaly_rate_percentile: number
    peer_group_size: number
  }
}

interface RiskTrendPoint {
  timestamp: string
  avg_risk_score: number
  max_risk_score: number
  anomaly_count: number
  entity_count: number
}

interface SuppressionRule {
  id: string
  pattern_type: string
  pattern: string
  reason: string
  created_by: string
  created_at: string
  expires_at: string | null
  enabled: boolean
}

interface HeatmapBucket {
  timestamp: string
  bucket_index: number
  total_count: number
  avg_risk: number
  entities: Array<{
    entity_type: string
    entity_id: string
    count: number
    max_risk: number
  }>
}

interface BehavioralStats {
  entities: {
    total_users: number
    total_processes: number
    total_hosts: number
  }
  anomalies: {
    total_24h: number
    total_7d: number
    by_severity: Record<string, number>
    by_type: Record<string, number>
  }
  risk_distribution: Record<string, number>
  trending: {
    risk_increasing: number
    risk_decreasing: number
    risk_stable: number
    new_entities_24h: number
  }
  top_mitre_techniques: Array<{
    technique: string
    name: string
    count: number
  }>
}

interface BehavioralPageProps {
  page_title: string
  entities: BehavioralEntity[]
  anomalies: BehavioralAnomaly[]
  baselines: {
    updateInterval: string
    lastUpdate: string
    profileCount: number
  }
  stats: {
    totalEntities: number
    highRiskEntities: number
    anomaliesDetected: number
    riskScoreThreshold: number
  }
}

// ============================================================================
// Constants
// ============================================================================

const API_BASE = '/api/v1/behavioral'

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

const severityConfig: Record<string, { color: string; bg: string; border: string; cssColor: string; cssBg: string }> = {
  critical: { color: 'text-sentinel-crit', bg: 'bg-[var(--crit-bg)]', border: 'border-[var(--crit)]', cssColor: 'var(--crit)', cssBg: 'var(--crit-bg)' },
  high: { color: 'text-sentinel-high', bg: 'bg-[var(--high-bg)]', border: 'border-[var(--high)]', cssColor: 'var(--high)', cssBg: 'var(--high-bg)' },
  medium: { color: 'text-sentinel-med', bg: 'bg-[var(--med-bg)]', border: 'border-[var(--med)]', cssColor: 'var(--med)', cssBg: 'var(--med-bg)' },
  low: { color: 'text-sentinel-low', bg: 'bg-[var(--low-bg)]', border: 'border-[var(--low)]', cssColor: 'var(--low)', cssBg: 'var(--low-bg)' },
  minimal: { color: 'text-sentinel-muted', bg: 'bg-[var(--surface-2)]', border: 'border-[var(--border)]', cssColor: 'var(--muted)', cssBg: 'var(--surface-2)' },
}

const entityTypeIcons: Record<string, React.ElementType> = {
  user: User,
  host: Monitor,
  process: Activity,
  network: Zap,
  service: Target,
}

const categoryIcons: Record<string, React.ElementType> = {
  unusual_process: Activity,
  abnormal_network: Network,
  credential_access: Key,
  lateral_movement: MoveHorizontal,
  data_exfiltration: Database,
  privilege_escalation: ShieldAlert,
  impossible_travel: MapPin,
  unusual_login: Clock,
}

// ============================================================================
// API Functions
// ============================================================================

async function fetchStatistics(): Promise<BehavioralStats | null> {
  const res = await fetch(`${API_BASE}/statistics`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data
}

async function fetchCategories(since?: string): Promise<Record<string, DetectionCategory> | null> {
  const params = new URLSearchParams()
  if (since) params.set('since', since)
  const res = await fetch(`${API_BASE}/categories?${params}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data
}

async function fetchRiskTrends(
  period: string = '24h',
  entityType?: string,
  entityId?: string
): Promise<RiskTrendPoint[]> {
  const params = new URLSearchParams({ period })
  if (entityType) params.set('entity_type', entityType)
  if (entityId) params.set('entity_id', entityId)
  const res = await fetch(`${API_BASE}/risk-trends?${params}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data || []
}

async function fetchHeatmap(
  period: string = '7d',
  entityType?: string
): Promise<{ heatmap: HeatmapBucket[]; entities: Array<{ type: string; id: string }> } | null> {
  const params = new URLSearchParams({ period })
  if (entityType) params.set('entity_type', entityType)
  const res = await fetch(`${API_BASE}/heatmap?${params}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data
}

async function fetchEntityProfile(entityType: string, entityId: string): Promise<EntityProfile | null> {
  const res = await fetch(`${API_BASE}/entities/${entityType}/${encodeURIComponent(entityId)}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data
}

async function fetchAnomalies(
  filters: {
    entity_type?: string
    entity_id?: string
    min_risk_score?: number
    since?: string
    limit?: number
  } = {}
): Promise<BehavioralAnomaly[]> {
  const params = new URLSearchParams()
  if (filters.entity_type) params.set('entity_type', filters.entity_type)
  if (filters.entity_id) params.set('entity_id', filters.entity_id)
  if (filters.min_risk_score !== undefined) params.set('min_risk_score', String(filters.min_risk_score))
  if (filters.since) params.set('since', filters.since)
  if (filters.limit !== undefined) params.set('limit', String(filters.limit))
  const res = await fetch(`${API_BASE}/anomalies?${params}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data || []
}

async function fetchHighRiskEntities(
  minRisk: number = 70,
  limit: number = 20
): Promise<BehavioralEntity[]> {
  const res = await fetch(`${API_BASE}/high-risk?min_risk=${minRisk}&limit=${limit}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data || []
}

async function fetchSuppressions(): Promise<SuppressionRule[]> {
  const res = await fetch(`${API_BASE}/suppressions`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data || []
}

async function createSuppression(rule: Partial<SuppressionRule>): Promise<SuppressionRule | null> {
  const res = await fetch(`${API_BASE}/suppressions`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(getCsrfToken() ? { 'X-CSRF-Token': getCsrfToken() } : {}),
    },
    body: JSON.stringify(rule),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.data
}

async function deleteSuppression(id: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/suppressions/${id}`, {
    method: 'DELETE',
    credentials: 'include',
    headers: {
      ...(getCsrfToken() ? { 'X-CSRF-Token': getCsrfToken() } : {}),
    },
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return true
}

// ============================================================================
// Main Component
// ============================================================================

type TabType = 'overview' | 'categories' | 'entities' | 'heatmap' | 'investigation' | 'settings'

export default function BehavioralAnalytics({
  page_title,
  entities: initialEntities = [],
  anomalies: initialAnomalies = [],
  baselines,
  stats: initialStats,
}: BehavioralPageProps) {
  // State
  const [activeTab, setActiveTab] = useState<TabType>('overview')
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')
  const [isLiveUpdates, setIsLiveUpdates] = useState(true)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Data state
  const [statistics, setStatistics] = useState<BehavioralStats | null>(null)
  const [categories, setCategories] = useState<Record<string, DetectionCategory> | null>(null)
  const [riskTrends, setRiskTrends] = useState<RiskTrendPoint[]>([])
  const [heatmapData, setHeatmapData] = useState<{
    heatmap: HeatmapBucket[]
    entities: Array<{ type: string; id: string }>
  } | null>(null)
  const [highRiskEntities, setHighRiskEntities] = useState<BehavioralEntity[]>([])
  const [anomalies, setAnomalies] = useState<BehavioralAnomaly[]>(initialAnomalies)
  const [suppressions, setSuppressions] = useState<SuppressionRule[]>([])

  // Selected entity for drill-down
  const [selectedEntity, setSelectedEntity] = useState<{
    type: string
    id: string
    profile: EntityProfile | null
  } | null>(null)

  // WebSocket for real-time updates
  const { connectionState, recentAlerts } = useDashboardChannel()

  // Poll interval ref
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // ============================================================================
  // Data Loading
  // ============================================================================

  const loadData = useCallback(async () => {
    setIsLoading(true)
    setLoadError(null)
    try {
      const [statsData, categoriesData, trendsData, heatData, highRisk, anomalyData] = await Promise.all([
        fetchStatistics(),
        fetchCategories(),
        fetchRiskTrends(timeRange),
        activeTab === 'heatmap' ? fetchHeatmap(timeRange === '1h' ? '24h' : timeRange) : Promise.resolve(null),
        fetchHighRiskEntities(),
        fetchAnomalies({ limit: 100 }),
      ])

      if (statsData) setStatistics(statsData)
      if (categoriesData) setCategories(categoriesData)
      setRiskTrends(trendsData)
      if (heatData) setHeatmapData(heatData)
      setHighRiskEntities(highRisk)
      setAnomalies(anomalyData)
    } catch (err) {
      logger.error('Failed to load behavioral analytics data:', err)
      setLoadError(err instanceof Error ? err.message : 'Failed to load behavioral analytics data')
    } finally {
      setIsLoading(false)
    }
  }, [timeRange, activeTab])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Live updates polling
  useEffect(() => {
    if (isLiveUpdates && activeTab !== 'settings') {
      pollIntervalRef.current = setInterval(() => {
        loadData()
      }, 30000) // 30 seconds

      return () => {
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current)
        }
      }
    }
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
      }
    }
  }, [isLiveUpdates, activeTab, loadData])

  // Load suppressions when settings tab is active
  useEffect(() => {
    if (activeTab === 'settings') {
      fetchSuppressions()
        .then(setSuppressions)
        .catch((err) => {
          logger.error('Failed to load suppressions:', err)
        })
    }
  }, [activeTab])

  // Load entity profile when selected
  const handleEntitySelect = async (type: string, id: string) => {
    try {
      const profile = await fetchEntityProfile(type, id)
      setSelectedEntity({ type, id, profile })
      setActiveTab('investigation')
    } catch (err) {
      logger.error('Failed to load entity profile:', err)
      // Still navigate to the investigation tab with a null profile
      setSelectedEntity({ type, id, profile: null })
      setActiveTab('investigation')
    }
  }

  // ============================================================================
  // Render Helpers
  // ============================================================================

  const getRiskLevel = (score: number): string => {
    if (score >= 90) return 'critical'
    if (score >= 75) return 'high'
    if (score >= 50) return 'medium'
    if (score >= 25) return 'low'
    return 'minimal'
  }

  const getSeverityFromRisk = (riskScore: number) => severityConfig[getRiskLevel(riskScore)] || severityConfig.minimal

  // ============================================================================
  // Computed Stats
  // ============================================================================

  const displayStats = statistics
    ? {
        totalEntities:
          statistics.entities.total_users +
          statistics.entities.total_processes +
          statistics.entities.total_hosts,
        anomalies24h: statistics.anomalies.total_24h,
        criticalCount: statistics.anomalies.by_severity.critical || 0,
        highCount: statistics.anomalies.by_severity.high || 0,
        avgRiskScore:
          riskTrends.length > 0
            ? Math.round(riskTrends.reduce((sum, t) => sum + t.avg_risk_score, 0) / riskTrends.length)
            : 0,
      }
    : {
        totalEntities: initialStats.totalEntities,
        anomalies24h: initialStats.anomaliesDetected,
        criticalCount: 0,
        highCount: 0,
        avgRiskScore: 0,
      }

  // Derived honest-empty-state signal: when every UEBA metric is 0 the page is
  // not broken, it is simply waiting for connected agents to emit telemetry that
  // crosses the deterministic baselines. We use this to swap zeros for honest
  // "Awaiting telemetry" badges rather than presenting raw 0s as live data.
  const awaitingTelemetry =
    !loadError &&
    displayStats.totalEntities === 0 &&
    displayStats.anomalies24h === 0 &&
    displayStats.criticalCount === 0 &&
    displayStats.highCount === 0 &&
    highRiskEntities.length === 0 &&
    anomalies.length === 0

  // ============================================================================
  // Render
  // ============================================================================

  return (
    <MainLayout title={page_title || 'Behavioral Analytics'}>
      <Head title="Behavioral Analytics - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header with Connection Status */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Behavioral Analytics (UEBA)</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              User and Entity Behavior Analytics - Detect anomalies through baseline profiling
            </p>
          </div>
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <div className="flex items-center gap-2 text-sm">
              <div className={cn('h-2 w-2 rounded-full', getConnectionStatusColor(connectionState))} />
              <span style={{ color: 'var(--muted)' }}>{getConnectionStatusText(connectionState)}</span>
            </div>

            {/* Live Updates Toggle */}
            <button
              onClick={() => setIsLiveUpdates(!isLiveUpdates)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
              style={{
                backgroundColor: isLiveUpdates ? 'var(--emerald-glow)' : 'var(--surface-2)',
                color: isLiveUpdates ? 'var(--emerald-400)' : 'var(--muted)',
                border: `1px solid ${isLiveUpdates ? 'var(--emerald-500)' : 'var(--border)'}`
              }}
            >
              {isLiveUpdates ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
              {isLiveUpdates ? 'Live' : 'Paused'}
            </button>

            {/* Refresh Button */}
            <button
              onClick={loadData}
              disabled={isLoading}
              className="btn-sentinel btn-sentinel-secondary flex items-center gap-2"
            >
              <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
              Refresh
            </button>
          </div>
        </div>

        {/* Load Error Banner — surfaced at top so operators do not interpret a
            silent backend failure as "no telemetry yet". */}
        {loadError && (
          <div
            className="flex items-start gap-3 p-3 rounded-lg"
            style={{
              backgroundColor: 'var(--crit-bg)',
              border: '1px solid var(--crit)',
              color: 'var(--fg)',
            }}
            role="alert"
          >
            <AlertTriangle className="h-5 w-5 mt-0.5 flex-shrink-0" style={{ color: 'var(--crit)' }} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold" style={{ color: 'var(--crit)' }}>
                Failed to load behavioral analytics
              </p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
                {loadError}
              </p>
            </div>
            <button
              onClick={loadData}
              className="px-3 py-1.5 rounded text-xs font-medium"
              style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg)', border: '1px solid var(--border)' }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Connection State Banner — when the live socket is not connected, the
            page is still functional via polling but real-time updates are
            paused. Surface this so the operator does not assume the dashboard
            is hung. */}
        {connectionState !== 'connected' && (
          <div
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
            style={{
              backgroundColor: 'var(--surface-2)',
              border: '1px solid var(--border)',
              color: 'var(--muted)',
            }}
          >
            <PlugZap className="h-4 w-4" style={{ color: 'var(--high)' }} />
            <span>
              Live updates paused — {getConnectionStatusText(connectionState).toLowerCase()}. Polling fallback is active.
            </span>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          <StatCard
            icon={Users}
            label="Monitored Entities"
            value={displayStats.totalEntities}
            color="primary"
            awaitingTelemetry={awaitingTelemetry}
          />
          <StatCard
            icon={AlertTriangle}
            label="Anomalies (24h)"
            value={displayStats.anomalies24h}
            color="yellow"
            trend={statistics?.trending.risk_increasing || 0}
            awaitingTelemetry={awaitingTelemetry}
          />
          <StatCard
            icon={Shield}
            label="Critical"
            value={displayStats.criticalCount}
            color="red"
            awaitingTelemetry={awaitingTelemetry}
          />
          <StatCard
            icon={ShieldAlert}
            label="High Risk"
            value={displayStats.highCount}
            color="orange"
            awaitingTelemetry={awaitingTelemetry}
          />
          <StatCard
            icon={Target}
            label="Avg Risk Score"
            value={displayStats.avgRiskScore}
            color="blue"
            awaitingTelemetry={awaitingTelemetry}
          />
        </div>

        {/* Tabs and Time Range */}
        <div className="flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-1">
            {(
              [
                { key: 'overview', label: 'Overview', icon: BarChart3 },
                { key: 'categories', label: 'Detection Categories', icon: Layers },
                { key: 'entities', label: 'Entity Profiles', icon: Users },
                { key: 'heatmap', label: 'Heat Map', icon: Activity },
                { key: 'investigation', label: 'Investigation', icon: GitBranch },
                { key: 'settings', label: 'Settings', icon: Settings },
              ] as { key: TabType; label: string; icon: React.ElementType }[]
            ).map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className="flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors"
                style={{
                  borderColor: activeTab === key ? 'var(--emerald-500)' : 'transparent',
                  color: activeTab === key ? 'var(--emerald-400)' : 'var(--muted)'
                }}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            ))}
          </div>

          <div
            className="flex items-center gap-1 rounded-lg p-1 mb-2"
            style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
          >
            {(['1h', '24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
                style={{
                  backgroundColor: timeRange === range ? 'var(--emerald-500)' : 'transparent',
                  color: timeRange === range ? 'white' : 'var(--muted)'
                }}
              >
                {range}
              </button>
            ))}
          </div>
        </div>

        {/* Loading State */}
        {isLoading && !statistics && !loadError && (
          <div className="flex items-center justify-center h-64">
            <div
              className="animate-spin rounded-full h-8 w-8 border-b-2"
              style={{ borderColor: 'var(--emerald-500)' }}
            />
          </div>
        )}

        {/* Error State — see top banner; intentionally not duplicated here. */}

        {/* Tab Content */}
        {!loadError && activeTab === 'overview' && (
          <OverviewTab
            statistics={statistics}
            riskTrends={riskTrends}
            highRiskEntities={highRiskEntities}
            anomalies={anomalies}
            onEntitySelect={handleEntitySelect}
          />
        )}

        {!loadError && activeTab === 'categories' && (
          <CategoriesTab categories={categories} onEntitySelect={handleEntitySelect} />
        )}

        {!loadError && activeTab === 'entities' && (
          <EntitiesTab
            entities={initialEntities}
            highRiskEntities={highRiskEntities}
            onEntitySelect={handleEntitySelect}
          />
        )}

        {!loadError && activeTab === 'heatmap' && (
          <HeatmapTab heatmapData={heatmapData} timeRange={timeRange} onEntitySelect={handleEntitySelect} />
        )}

        {!loadError && activeTab === 'investigation' && (
          <InvestigationTab
            selectedEntity={selectedEntity}
            anomalies={anomalies}
            onEntitySelect={handleEntitySelect}
          />
        )}

        {!loadError && activeTab === 'settings' && (
          <SettingsTab
            suppressions={suppressions}
            baselines={baselines}
            onSuppressionCreate={async (rule) => {
              try {
                const created = await createSuppression(rule)
                if (created) {
                  setSuppressions((prev) => [...prev, created])
                }
              } catch (err) {
                logger.error('Failed to create suppression:', err)
              }
            }}
            onSuppressionDelete={async (id) => {
              try {
                await deleteSuppression(id)
                setSuppressions((prev) => prev.filter((s) => s.id !== id))
              } catch (err) {
                logger.error('Failed to delete suppression:', err)
              }
            }}
          />
        )}
      </div>
    </MainLayout>
  )
}

// ============================================================================
// Stat Card Component
// ============================================================================

interface StatCardProps {
  icon: React.ElementType
  label: string
  value: number
  color: 'primary' | 'yellow' | 'red' | 'purple' | 'blue' | 'orange' | 'green'
  trend?: number
  /**
   * When true and value === 0, render a subtle "Awaiting telemetry" badge under
   * the number with a tooltip explaining why the metric is zero. UEBA baselines
   * only populate once connected agents emit enough events to cross the
   * deterministic z-score thresholds in `Detection.Baseline`, so a fresh
   * tenant legitimately sees zeros — the badge differentiates that from a bug.
   */
  awaitingTelemetry?: boolean
}

function StatCard({ icon: Icon, label, value, color, trend, awaitingTelemetry }: StatCardProps) {
  const colorStyles: Record<string, { bg: string; text: string }> = {
    primary: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    yellow: { bg: 'var(--high-bg)', text: 'var(--high)' },
    red: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    purple: { bg: 'rgba(168, 85, 247, 0.12)', text: '#a855f7' },
    blue: { bg: 'var(--med-bg)', text: 'var(--med)' },
    orange: { bg: 'var(--high-bg)', text: 'var(--high)' },
    green: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
  }

  const styles = colorStyles[color]
  const showAwaiting = awaitingTelemetry && value === 0

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between">
        <div
          className="p-2 rounded-lg w-fit"
          style={{ backgroundColor: styles.bg, color: styles.text }}
        >
          <Icon className="h-5 w-5" />
        </div>
        {trend !== undefined && trend !== 0 && (
          <div
            className="flex items-center gap-1 text-xs"
            style={{ color: trend > 0 ? 'var(--crit)' : 'var(--emerald-400)' }}
          >
            {trend > 0 ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />}
            {Math.abs(trend)}
          </div>
        )}
      </div>
      <div className="mt-3">
        <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}</span>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{label}</p>
        {showAwaiting && (
          <Tooltip
            content="UEBA baselines populate once connected agents emit enough telemetry to cross the deterministic z-score thresholds. Without agents reporting, this stays at 0."
            side="bottom"
          >
            <span
              className="inline-flex items-center gap-1 mt-2 px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider"
              style={{
                backgroundColor: 'var(--surface-2)',
                border: '1px solid var(--border)',
                color: 'var(--subtle)',
              }}
            >
              <Info className="h-3 w-3" />
              Awaiting telemetry
            </span>
          </Tooltip>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Empty State Helper
// ============================================================================

interface EmptyStateProps {
  icon: React.ElementType
  title: string
  description: string
  ctaLabel?: string
  ctaHref?: string
  compact?: boolean
}

/**
 * Honest empty-state card used when a UEBA section has no data because no
 * agents are emitting telemetry yet (rather than because the query failed).
 * Differentiates "fresh tenant, working as intended" from "broken backend".
 */
function EmptyState({ icon: Icon, title, description, ctaLabel, ctaHref, compact }: EmptyStateProps) {
  return (
    <div
      className={cn('flex flex-col items-center justify-center text-center', compact ? 'p-6' : 'p-8')}
      style={{ color: 'var(--muted)' }}
    >
      <div
        className="p-3 rounded-full mb-3"
        style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
      >
        <Icon className={cn(compact ? 'h-6 w-6' : 'h-8 w-8')} style={{ color: 'var(--subtle)' }} />
      </div>
      <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--fg)' }}>
        {title}
      </h3>
      <p className="text-xs max-w-md" style={{ color: 'var(--subtle)' }}>
        {description}
      </p>
      {ctaLabel && ctaHref && (
        <a
          href={ctaHref}
          className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors"
          style={{
            backgroundColor: 'var(--surface-2)',
            border: '1px solid var(--border)',
            color: 'var(--emerald-400)',
          }}
        >
          {ctaLabel}
          <ChevronRight className="h-3 w-3" />
        </a>
      )}
    </div>
  )
}

// ============================================================================
// Overview Tab
// ============================================================================

interface OverviewTabProps {
  statistics: BehavioralStats | null
  riskTrends: RiskTrendPoint[]
  highRiskEntities: BehavioralEntity[]
  anomalies: BehavioralAnomaly[]
  onEntitySelect: (type: string, id: string) => void
}

function OverviewTab({ statistics, riskTrends, highRiskEntities, anomalies, onEntitySelect }: OverviewTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Risk Trend Chart */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">Risk Score Trends</h2>
            <p className="card-sentinel-subtitle">Anomaly risk scores over time</p>
          </div>
        </div>
        <div className="p-4">
          {(() => {
            const hasTrendSignal = riskTrends.length > 0 && riskTrends.some((p) => p.max_risk_score > 0 || p.avg_risk_score > 0)
            if (hasTrendSignal) {
              return (
                <div className="space-y-4">
                  {/* Simple bar chart visualization */}
                  <div className="flex items-end gap-1 h-32">
                    {riskTrends.slice(-24).map((point, idx) => {
                      const maxHeight = Math.max(4, (point.max_risk_score / 100) * 100)
                      const barColor = point.max_risk_score >= 90
                        ? 'var(--crit)'
                        : point.max_risk_score >= 75
                        ? 'var(--high)'
                        : point.max_risk_score >= 50
                        ? 'var(--med)'
                        : 'var(--emerald-400)'
                      return (
                        <div
                          key={idx}
                          className="flex-1 flex flex-col items-center gap-1"
                          title={`${point.avg_risk_score.toFixed(1)} avg, ${point.max_risk_score} max`}
                        >
                          <div
                            className="w-full rounded-t transition-all"
                            style={{ height: `${maxHeight}%`, backgroundColor: barColor }}
                          />
                        </div>
                      )
                    })}
                  </div>
                  <div className="flex items-center justify-between text-xs" style={{ color: 'var(--subtle)' }}>
                    <span>Older</span>
                    <span>Recent</span>
                  </div>
                </div>
              )
            }
            return (
              <EmptyState
                icon={TrendingUp}
                title="No risk trend data"
                description="Risk trends accumulate once agents stream telemetry and the baseline learner has enough samples to score deviations. Connect an agent to start populating this chart."
                compact
              />
            )
          })()}
        </div>
      </div>

      {/* Top MITRE Techniques */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">Top MITRE Techniques</h2>
            <p className="card-sentinel-subtitle">Most frequently detected techniques</p>
          </div>
        </div>
        <div className="p-4 space-y-3">
          {statistics?.top_mitre_techniques?.slice(0, 6).map((tech) => (
            <div key={tech.technique} className="flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{tech.technique}</span>
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>{tech.count}</span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.min(100, (tech.count / (statistics.top_mitre_techniques[0]?.count || 1)) * 100)}%`,
                      backgroundColor: 'var(--emerald-500)'
                    }}
                  />
                </div>
                <span className="text-xs" style={{ color: 'var(--subtle)' }}>{tech.name}</span>
              </div>
            </div>
          )) || (
            <div className="text-sm text-center py-4" style={{ color: 'var(--subtle)' }}>No techniques detected</div>
          )}
        </div>
      </div>

      {/* High Risk Entities */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">High Risk Entities</h2>
            <p className="card-sentinel-subtitle">Entities requiring attention</p>
          </div>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {highRiskEntities.slice(0, 8).map((entity) => {
            const risk = (entity.userRiskScore || 0) + (entity.hostRiskScore || 0)
            const severity = severityConfig[risk >= 90 ? 'critical' : risk >= 75 ? 'high' : risk >= 50 ? 'medium' : 'low']
            const Icon = entityTypeIcons[entity.type] || User

            return (
              <button
                key={entity.id}
                onClick={() => onEntitySelect(entity.type, entity.id)}
                className="w-full flex items-center gap-3 p-3 transition-colors text-left"
                style={{ borderBottom: '1px solid var(--hairline)' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
              >
                <div className="p-2 rounded-lg" style={{ backgroundColor: severity.cssBg }}>
                  <Icon className="h-4 w-4" style={{ color: severity.cssColor }} />
                </div>
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium truncate block" style={{ color: 'var(--fg)' }}>{entity.name}</span>
                  <span className="text-xs capitalize" style={{ color: 'var(--subtle)' }}>{entity.type}</span>
                </div>
                <div className="text-lg font-bold" style={{ color: severity.cssColor }}>{risk}</div>
                <ChevronRight className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
              </button>
            )
          })}
          {highRiskEntities.length === 0 && (
            <EmptyState
              icon={Shield}
              title="No high-risk entities detected"
              description="Behavioral baselines learn from agent telemetry. Without connected agents emitting events, this view stays empty."
              ctaLabel="Manage agents"
              ctaHref="/app/agents"
              compact
            />
          )}
        </div>
      </div>

      {/* Recent Anomalies */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">Recent Anomalies</h2>
            <p className="card-sentinel-subtitle">Latest behavioral detections</p>
          </div>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {anomalies.slice(0, 8).map((anomaly) => {
            const severity = severityConfig[anomaly.riskScore >= 90 ? 'critical' : anomaly.riskScore >= 75 ? 'high' : anomaly.riskScore >= 50 ? 'medium' : 'low']
            const Icon = entityTypeIcons[anomaly.entityType] || AlertTriangle

            return (
              <button
                key={anomaly.id}
                onClick={() => onEntitySelect(anomaly.entityType, anomaly.entityId)}
                className="w-full flex items-start gap-3 p-3 transition-colors text-left"
                style={{ borderBottom: '1px solid var(--hairline)' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
              >
                <div className="p-2 rounded-lg mt-0.5" style={{ backgroundColor: severity.cssBg }}>
                  <Icon className="h-4 w-4" style={{ color: severity.cssColor }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{anomaly.type.replace(/_/g, ' ')}</span>
                    <span
                      className="text-xs px-1.5 py-0.5 rounded"
                      style={{ backgroundColor: severity.cssBg, color: severity.cssColor }}
                    >
                      {anomaly.riskScore}
                    </span>
                  </div>
                  <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>{anomaly.description}</p>
                  <span className="text-xs" style={{ color: 'var(--subtle)' }}>{formatDate(anomaly.detectedAt)}</span>
                </div>
              </button>
            )
          })}
          {anomalies.length === 0 && (
            <EmptyState
              icon={AlertTriangle}
              title="No anomalies detected yet"
              description="Behavioral analysis requires a baseline of events per entity before deviations are scored. Check the Agents page to verify telemetry flow."
              ctaLabel="Check agents"
              ctaHref="/app/agents"
              compact
            />
          )}
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Categories Tab
// ============================================================================

interface CategoriesTabProps {
  categories: Record<string, DetectionCategory> | null
  onEntitySelect: (type: string, id: string) => void
}

function CategoriesTab({ categories, onEntitySelect }: CategoriesTabProps) {
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null)

  if (!categories) {
    return (
      <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
        <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>Loading detection categories...</p>
      </div>
    )
  }

  const totalCategoryDetections = Object.values(categories).reduce((sum, c) => sum + (c.count || 0), 0)
  if (totalCategoryDetections === 0) {
    return (
      <div className="card-sentinel">
        <EmptyState
          icon={Layers}
          title="No detection categories populated"
          description="Detection categories aggregate behavioral anomalies by MITRE ATT&CK technique. Once agents emit telemetry and baselines learn what's normal, deviations will show up here grouped by category."
          ctaLabel="Manage agents"
          ctaHref="/app/agents"
        />
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {Object.entries(categories).map(([key, category]) => {
        const Icon = categoryIcons[key] || AlertTriangle
        const isExpanded = expandedCategory === key
        const totalCount = category.count
        const criticalCount = category.severity_distribution.critical || 0
        const highCount = category.severity_distribution.high || 0

        const borderColor = criticalCount > 0 ? 'var(--crit)' : highCount > 0 ? 'var(--high)' : 'var(--border)'
        const iconBg = criticalCount > 0 ? 'var(--crit-bg)' : highCount > 0 ? 'var(--high-bg)' : 'var(--surface-2)'
        const iconColor = criticalCount > 0 ? 'var(--crit)' : highCount > 0 ? 'var(--high)' : 'var(--muted)'

        return (
          <div
            key={key}
            className="card-sentinel transition-colors"
            style={{ borderColor: borderColor }}
          >
            <button
              onClick={() => setExpandedCategory(isExpanded ? null : key)}
              className="w-full p-4 flex items-center gap-4 text-left"
            >
              <div className="p-3 rounded-lg" style={{ backgroundColor: iconBg }}>
                <Icon className="h-6 w-6" style={{ color: iconColor }} />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{category.name}</h3>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>{category.description}</p>
                <div className="flex items-center gap-3 mt-2">
                  <span className="text-xs" style={{ color: 'var(--subtle)' }}>{totalCount} detections</span>
                  {criticalCount > 0 && (
                    <span className="text-xs" style={{ color: 'var(--crit)' }}>{criticalCount} critical</span>
                  )}
                  {highCount > 0 && (
                    <span className="text-xs" style={{ color: 'var(--high)' }}>{highCount} high</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-right">
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{totalCount}</div>
                </div>
                {isExpanded ? (
                  <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                ) : (
                  <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                )}
              </div>
            </button>

            {isExpanded && category.anomalies.length > 0 && (
              <div className="p-4 space-y-2" style={{ borderTop: '1px solid var(--hairline)' }}>
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xs" style={{ color: 'var(--subtle)' }}>MITRE Techniques:</span>
                  {category.mitre_techniques.map((tech) => (
                    <span
                      key={tech}
                      className="text-xs px-2 py-0.5 rounded"
                      style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                    >
                      {tech}
                    </span>
                  ))}
                </div>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {category.anomalies.map((anomaly: BehavioralAnomaly, idx: number) => {
                    const severity = severityConfig[anomaly.riskScore >= 90 ? 'critical' : anomaly.riskScore >= 75 ? 'high' : anomaly.riskScore >= 50 ? 'medium' : 'low']
                    return (
                      <button
                        key={idx}
                        onClick={() => onEntitySelect(anomaly.entityType, anomaly.entityId)}
                        className="w-full flex items-center gap-3 p-2 rounded-lg text-left transition-colors"
                        style={{ backgroundColor: 'var(--bg-2)' }}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--bg-2)' }}
                      >
                        <div
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: severity.cssColor }}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm truncate" style={{ color: 'var(--fg)' }}>{anomaly.description}</p>
                          <p className="text-xs" style={{ color: 'var(--subtle)' }}>
                            {anomaly.entityType}: {anomaly.entityId}
                          </p>
                        </div>
                        <span className="text-sm font-medium" style={{ color: severity.cssColor }}>{anomaly.riskScore}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ============================================================================
// Entities Tab
// ============================================================================

interface EntitiesTabProps {
  entities: BehavioralEntity[]
  highRiskEntities: BehavioralEntity[]
  onEntitySelect: (type: string, id: string) => void
}

function EntitiesTab({ entities, highRiskEntities, onEntitySelect }: EntitiesTabProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')

  const allEntities = [...entities, ...highRiskEntities.filter((e) => !entities.find((x) => x.id === e.id))]

  const filteredEntities = allEntities.filter((entity) => {
    const matchesSearch =
      entity.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entity.id.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesType = typeFilter === 'all' || entity.type === typeFilter
    return matchesSearch && matchesType
  })

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--hairline)' }}>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Entity Profiles</h2>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
            <input
              type="text"
              placeholder="Search entities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-sentinel w-48 pl-10 pr-4"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="input-sentinel px-3 py-1.5 text-sm"
            style={{ width: 'auto' }}
          >
            <option value="all">All Types</option>
            <option value="user">Users</option>
            <option value="host">Hosts</option>
            <option value="process">Processes</option>
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead style={{ backgroundColor: 'var(--bg-2)' }}>
            <tr>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Entity</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Type</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>User Risk</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Host Risk</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Combined</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Last Seen</th>
              <th className="text-left px-4 py-3 text-xs uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredEntities.map((entity) => {
              const combinedRisk = (entity.userRiskScore || 0) + (entity.hostRiskScore || 0)
              const severity = severityConfig[combinedRisk >= 90 ? 'critical' : combinedRisk >= 75 ? 'high' : combinedRisk >= 50 ? 'medium' : 'low']
              const Icon = entityTypeIcons[entity.type] || User

              return (
                <tr
                  key={entity.id}
                  className="transition-colors"
                  style={{ borderBottom: '1px solid var(--hairline)' }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 rounded-lg" style={{ backgroundColor: severity.cssBg }}>
                        <Icon className="h-4 w-4" style={{ color: severity.cssColor }} />
                      </div>
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{entity.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>{entity.type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge score={entity.userRiskScore || 0} />
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge score={entity.hostRiskScore || 0} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-lg font-bold" style={{ color: severity.cssColor }}>{combinedRisk}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm" style={{ color: 'var(--muted)' }}>{formatDate(entity.lastSeen)}</span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => onEntitySelect(entity.type, entity.id)}
                      className="flex items-center gap-1 text-sm transition-colors"
                      style={{ color: 'var(--emerald-400)' }}
                      onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--emerald-200)' }}
                      onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--emerald-400)' }}
                    >
                      <Eye className="h-4 w-4" />
                      View
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {filteredEntities.length === 0 && (
          <EmptyState
            icon={Users}
            title={allEntities.length === 0 ? 'No entity profiles yet' : 'No entities match your filters'}
            description={
              allEntities.length === 0
                ? 'Entity profiles are built from user, host, and process activity reported by connected agents. Once agents emit telemetry, profiles will appear here.'
                : 'Try clearing the search box or switching the type filter to "All Types".'
            }
            ctaLabel={allEntities.length === 0 ? 'Manage agents' : undefined}
            ctaHref={allEntities.length === 0 ? '/app/agents' : undefined}
          />
        )}
      </div>
    </div>
  )
}

function RiskBadge({ score }: { score: number }) {
  const severity = severityConfig[score >= 90 ? 'critical' : score >= 75 ? 'high' : score >= 50 ? 'medium' : score >= 25 ? 'low' : 'minimal']
  return <span className="text-sm font-medium" style={{ color: severity.cssColor }}>{score}</span>
}

// ============================================================================
// Heatmap Tab
// ============================================================================

interface HeatmapTabProps {
  heatmapData: { heatmap: HeatmapBucket[]; entities: Array<{ type: string; id: string }> } | null
  timeRange: string
  onEntitySelect: (type: string, id: string) => void
}

function HeatmapTab({ heatmapData, timeRange, onEntitySelect }: HeatmapTabProps) {
  if (!heatmapData || heatmapData.heatmap.length === 0) {
    return (
      <div className="card-sentinel">
        <EmptyState
          icon={Activity}
          title="No heatmap data for this time range"
          description="The heatmap renders anomaly density per entity per time bucket. Without agent telemetry crossing the baseline thresholds in this window, there are no cells to draw."
          ctaLabel="Manage agents"
          ctaHref="/app/agents"
        />
      </div>
    )
  }

  const { heatmap, entities } = heatmapData
  const maxCount = Math.max(...heatmap.flatMap((b) => b.entities.map((e) => e.count)), 1)

  const getHeatColor = (count: number, maxRisk: number): string => {
    if (count === 0) return 'var(--surface-2)'
    const intensity = count / maxCount
    if (maxRisk >= 90) return intensity > 0.5 ? 'var(--crit)' : 'rgba(240, 80, 110, 0.5)'
    if (maxRisk >= 75) return intensity > 0.5 ? 'var(--high)' : 'rgba(245, 165, 36, 0.5)'
    if (maxRisk >= 50) return intensity > 0.5 ? 'var(--med)' : 'rgba(91, 156, 242, 0.5)'
    return intensity > 0.5 ? 'var(--emerald-400)' : 'rgba(47, 196, 113, 0.5)'
  }

  return (
    <div className="card-sentinel">
      <div className="card-sentinel-header">
        <div>
          <h2 className="card-sentinel-title">Anomaly Heat Map</h2>
          <p className="card-sentinel-subtitle">
            Anomaly distribution by entity and time ({timeRange} view)
          </p>
        </div>
      </div>
      <div className="p-4 overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Column headers (time buckets) */}
          <div className="flex items-center mb-2 pl-32">
            {heatmap.slice(0, 24).map((bucket, idx) => (
              <div
                key={idx}
                className="flex-1 text-xs text-center"
                style={{ color: 'var(--subtle)' }}
                title={bucket.timestamp}
              >
                {new Date(bucket.timestamp).getHours()}:00
              </div>
            ))}
          </div>

          {/* Rows (entities) */}
          {entities.slice(0, 20).map((entity, entityIdx) => (
            <div key={entityIdx} className="flex items-center gap-2 mb-1">
              <button
                onClick={() => onEntitySelect(entity.type, entity.id)}
                className="w-32 text-xs truncate text-left transition-colors"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
                onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
                title={`${entity.type}: ${entity.id}`}
              >
                {entity.id}
              </button>
              <div className="flex-1 flex gap-0.5">
                {heatmap.slice(0, 24).map((bucket, bucketIdx) => {
                  const entityData = bucket.entities.find(
                    (e) => e.entity_type === entity.type && e.entity_id === entity.id
                  )
                  const count = entityData?.count || 0
                  const maxRisk = entityData?.max_risk || 0

                  return (
                    <div
                      key={bucketIdx}
                      className="flex-1 h-6 rounded-sm cursor-pointer transition-opacity hover:opacity-80"
                      style={{ backgroundColor: getHeatColor(count, maxRisk) }}
                      title={`${count} anomalies, max risk: ${maxRisk}`}
                    />
                  )
                })}
              </div>
            </div>
          ))}

          {/* Legend */}
          <div className="flex items-center gap-4 mt-4 pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>Risk Level:</span>
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded" style={{ backgroundColor: 'var(--surface-2)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>None</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded" style={{ backgroundColor: 'var(--emerald-400)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Low</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded" style={{ backgroundColor: 'var(--med)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded" style={{ backgroundColor: 'var(--high)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>High</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded" style={{ backgroundColor: 'var(--crit)' }} />
              <span className="text-xs" style={{ color: 'var(--subtle)' }}>Critical</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Investigation Tab
// ============================================================================

interface InvestigationTabProps {
  selectedEntity: { type: string; id: string; profile: EntityProfile | null } | null
  anomalies: BehavioralAnomaly[]
  onEntitySelect: (type: string, id: string) => void
}

function InvestigationTab({ selectedEntity, anomalies, onEntitySelect }: InvestigationTabProps) {
  if (!selectedEntity) {
    return (
      <div className="card-sentinel p-8 text-center">
        <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-50" style={{ color: 'var(--subtle)' }} />
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>Select an Entity to Investigate</h3>
        <p className="mb-4" style={{ color: 'var(--muted)' }}>
          Click on an entity from the Overview, Categories, or Entities tab to start an investigation
        </p>

        {/* Quick select from recent anomalies */}
        {anomalies.length > 0 && (
          <div className="mt-6">
            <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Or investigate recent anomalies:</h4>
            <div className="flex flex-wrap gap-2 justify-center">
              {anomalies.slice(0, 5).map((anomaly) => (
                <button
                  key={anomaly.id}
                  onClick={() => onEntitySelect(anomaly.entityType, anomaly.entityId)}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-3)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                >
                  <span style={{ color: 'var(--fg)' }}>{anomaly.entityId}</span>
                  <span style={{ color: 'var(--muted)' }}>({anomaly.entityType})</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  const { type, id, profile } = selectedEntity
  const entityAnomalies = anomalies.filter((a) => a.entityType === type && a.entityId === id)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Entity Profile Card */}
      <div className="lg:col-span-1 card-sentinel">
        <div className="card-sentinel-header">
          <h2 className="card-sentinel-title">Entity Profile</h2>
        </div>
        <div className="p-4 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
              {(() => {
                const Icon = entityTypeIcons[type] || User
                return <Icon className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
              })()}
            </div>
            <div>
              <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{id}</h3>
              <p className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{type}</p>
            </div>
          </div>

          {profile && (
            <>
              <div className="grid grid-cols-2 gap-4 pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
                <div>
                  <label className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Risk Score</label>
                  <div
                    className="text-2xl font-bold"
                    style={{
                      color: profile.risk_score >= 90
                        ? 'var(--crit)'
                        : profile.risk_score >= 75
                        ? 'var(--high)'
                        : profile.risk_score >= 50
                        ? 'var(--med)'
                        : 'var(--emerald-400)'
                    }}
                  >
                    {profile.risk_score}
                  </div>
                  <span className="text-xs capitalize" style={{ color: 'var(--subtle)' }}>{profile.risk_level}</span>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Total Events</label>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{profile.total_events.toLocaleString()}</div>
                </div>
              </div>

              {profile.peer_comparison && (
                <div className="pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
                  <label className="text-xs uppercase tracking-wider mb-2 block" style={{ color: 'var(--subtle)' }}>
                    Peer Comparison
                  </label>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm" style={{ color: 'var(--muted)' }}>Risk Percentile</span>
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>{profile.peer_comparison.risk_score_percentile}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm" style={{ color: 'var(--muted)' }}>Activity Percentile</span>
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>{profile.peer_comparison.event_volume_percentile}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm" style={{ color: 'var(--muted)' }}>Peer Group Size</span>
                      <span className="text-sm" style={{ color: 'var(--fg)' }}>{profile.peer_comparison.peer_group_size}</span>
                    </div>
                  </div>
                </div>
              )}

              {profile.last_updated && (
                <div className="text-xs pt-4" style={{ borderTop: '1px solid var(--hairline)', color: 'var(--subtle)' }}>
                  Last updated: {formatDate(profile.last_updated)}
                </div>
              )}
            </>
          )}

          <div className="pt-4 space-y-2">
            <a
              href={`/app/hunt?q=${encodeURIComponent(`entity_type:${type} entity_id:${id}`)}`}
              className="btn-sentinel btn-sentinel-primary w-full flex items-center justify-center gap-2"
            >
              <GitBranch className="h-4 w-4" />
              Hunt Entity
            </a>
            <a
              href={`/app/timeline?entity=${type}:${id}`}
              className="btn-sentinel btn-sentinel-secondary w-full flex items-center justify-center gap-2"
            >
              <Clock className="h-4 w-4" />
              View Timeline
            </a>
          </div>
        </div>
      </div>

      {/* Anomaly History */}
      <div className="lg:col-span-2 card-sentinel">
        <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--hairline)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Anomaly History</h2>
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{entityAnomalies.length} anomalies</span>
        </div>
        <div className="max-h-[500px] overflow-y-auto">
          {entityAnomalies.length > 0 ? (
            entityAnomalies.map((anomaly) => {
              const severity = severityConfig[anomaly.riskScore >= 90 ? 'critical' : anomaly.riskScore >= 75 ? 'high' : anomaly.riskScore >= 50 ? 'medium' : 'low']

              return (
                <div
                  key={anomaly.id}
                  className="p-4 transition-colors"
                  style={{ borderBottom: '1px solid var(--hairline)' }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                >
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg mt-0.5" style={{ backgroundColor: severity.cssBg }}>
                      <AlertTriangle className="h-4 w-4" style={{ color: severity.cssColor }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                          {anomaly.type.replace(/_/g, ' ')}
                        </span>
                        <span
                          className="text-xs px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: severity.cssBg, color: severity.cssColor }}
                        >
                          {anomaly.riskScore}
                        </span>
                      </div>
                      <p className="text-sm" style={{ color: 'var(--muted)' }}>{anomaly.description}</p>
                      <div className="flex items-center gap-4 mt-2">
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>{formatDate(anomaly.detectedAt)}</span>
                        {anomaly.mitreTechniques.length > 0 && (
                          <div className="flex items-center gap-1">
                            {anomaly.mitreTechniques.slice(0, 3).map((tech) => (
                              <span
                                key={tech}
                                className="text-xs px-1.5 py-0.5 rounded"
                                style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                              >
                                {tech}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      {anomaly.baselineValue && (
                        <div className="mt-2 text-xs" style={{ color: 'var(--subtle)' }}>
                          Baseline: {anomaly.baselineValue}
                          {anomaly.observedValue && ` | Observed: ${anomaly.observedValue}`}
                        </div>
                      )}
                    </div>
                    <button style={{ color: 'var(--emerald-400)' }}>
                      <ExternalLink className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              )
            })
          ) : (
            <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
              No anomalies recorded for this entity
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Settings Tab
// ============================================================================

interface SettingsTabProps {
  suppressions: SuppressionRule[]
  baselines: {
    updateInterval: string
    lastUpdate: string
    profileCount: number
  }
  onSuppressionCreate: (rule: Partial<SuppressionRule>) => Promise<void>
  onSuppressionDelete: (id: string) => Promise<void>
}

function SettingsTab({ suppressions, baselines, onSuppressionCreate, onSuppressionDelete }: SettingsTabProps) {
  const [newSuppression, setNewSuppression] = useState({
    pattern_type: 'process_name',
    pattern: '',
    reason: '',
  })
  const [isCreating, setIsCreating] = useState(false)

  const handleCreate = async () => {
    if (!newSuppression.pattern || !newSuppression.reason) return
    setIsCreating(true)
    await onSuppressionCreate(newSuppression)
    setNewSuppression({ pattern_type: 'process_name', pattern: '', reason: '' })
    setIsCreating(false)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Baseline Information */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <h2 className="card-sentinel-title">Baseline Configuration</h2>
        </div>
        <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Update Interval</label>
              <p className="mt-1" style={{ color: 'var(--fg)' }}>{baselines.updateInterval}</p>
            </div>
            <div>
              <label className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Last Update</label>
              <p className="mt-1" style={{ color: 'var(--fg)' }}>{formatDate(baselines.lastUpdate)}</p>
            </div>
            <div>
              <label className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Profiles Tracked</label>
              <p className="mt-1" style={{ color: 'var(--fg)' }}>{baselines.profileCount}</p>
            </div>
          </div>

          <div className="pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
            <button className="btn-sentinel btn-sentinel-primary flex items-center gap-2">
              <RefreshCw className="h-4 w-4" />
              Force Baseline Update
            </button>
          </div>
        </div>
      </div>

      {/* Suppression Rules */}
      <div className="card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">Suppression Rules (Whitelist)</h2>
            <p className="card-sentinel-subtitle">Patterns that won't generate alerts</p>
          </div>
        </div>
        <div className="p-4">
          {/* Add new suppression form */}
          <div className="space-y-3 mb-4 pb-4" style={{ borderBottom: '1px solid var(--hairline)' }}>
            <div className="grid grid-cols-2 gap-3">
              <select
                value={newSuppression.pattern_type}
                onChange={(e) => setNewSuppression((p) => ({ ...p, pattern_type: e.target.value }))}
                className="input-sentinel"
              >
                <option value="process_name">Process Name</option>
                <option value="command_line">Command Line</option>
                <option value="entity_id">Entity ID</option>
                <option value="rule_id">Rule ID</option>
              </select>
              <input
                type="text"
                placeholder="Pattern (regex supported)"
                value={newSuppression.pattern}
                onChange={(e) => setNewSuppression((p) => ({ ...p, pattern: e.target.value }))}
                className="input-sentinel"
              />
            </div>
            <div className="flex items-center gap-3">
              <input
                type="text"
                placeholder="Reason for suppression"
                value={newSuppression.reason}
                onChange={(e) => setNewSuppression((p) => ({ ...p, reason: e.target.value }))}
                className="input-sentinel flex-1"
              />
              <button
                onClick={handleCreate}
                disabled={isCreating || !newSuppression.pattern || !newSuppression.reason}
                className="btn-sentinel btn-sentinel-primary flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Add
              </button>
            </div>
          </div>

          {/* Existing suppressions */}
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {suppressions.length > 0 ? (
              suppressions.map((rule) => (
                <div
                  key={rule.id}
                  className="flex items-center gap-3 p-3 rounded-lg"
                  style={{ backgroundColor: 'var(--bg-2)' }}
                >
                  <BellOff className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className="text-xs px-1.5 py-0.5 rounded"
                        style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                      >
                        {rule.pattern_type}
                      </span>
                      <span className="text-sm font-mono truncate" style={{ color: 'var(--fg)' }}>{rule.pattern}</span>
                    </div>
                    <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>{rule.reason}</p>
                  </div>
                  <button
                    onClick={() => onSuppressionDelete(rule.id)}
                    className="p-1.5 rounded transition-colors"
                    style={{ color: 'var(--muted)' }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.color = 'var(--crit)'
                      e.currentTarget.style.backgroundColor = 'var(--crit-bg)'
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.color = 'var(--muted)'
                      e.currentTarget.style.backgroundColor = 'transparent'
                    }}
                  >
                    <XCircle className="h-4 w-4" />
                  </button>
                </div>
              ))
            ) : (
              <div className="text-sm text-center py-4" style={{ color: 'var(--subtle)' }}>
                No suppression rules configured
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Detection Thresholds */}
      <div className="lg:col-span-2 card-sentinel">
        <div className="card-sentinel-header">
          <div>
            <h2 className="card-sentinel-title">Detection Thresholds</h2>
            <p className="card-sentinel-subtitle">Configure sensitivity of behavioral detection</p>
          </div>
        </div>
        <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="text-sm font-medium block mb-2" style={{ color: 'var(--fg)' }}>Z-Score Threshold</label>
            <input
              type="number"
              defaultValue={3.0}
              step={0.1}
              className="input-sentinel w-full"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
              Standard deviations from baseline to trigger anomaly
            </p>
          </div>
          <div>
            <label className="text-sm font-medium block mb-2" style={{ color: 'var(--fg)' }}>Risk Score Alert Threshold</label>
            <input
              type="number"
              defaultValue={75}
              min={0}
              max={100}
              className="input-sentinel w-full"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Minimum risk score to generate alert</p>
          </div>
          <div>
            <label className="text-sm font-medium block mb-2" style={{ color: 'var(--fg)' }}>Large Transfer Threshold (MB)</label>
            <input
              type="number"
              defaultValue={100}
              min={1}
              className="input-sentinel w-full"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Data transfer size to flag as anomalous</p>
          </div>
        </div>
        <div className="p-4 flex justify-end" style={{ borderTop: '1px solid var(--hairline)' }}>
          <button className="btn-sentinel btn-sentinel-primary">
            Save Thresholds
          </button>
        </div>
      </div>
    </div>
  )
}
