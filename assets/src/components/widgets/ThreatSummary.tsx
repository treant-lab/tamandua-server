/**
 * ThreatSummary Widget
 *
 * Executive-level threat summary showing key security metrics,
 * current threat level, and actionable insights. Designed for
 * quick situational awareness.
 */

import { useState, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  Shield,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Minus,
  AlertCircle,
  CheckCircle,
  Clock,
  Target,
  Zap,
  Activity,
  ArrowUpRight,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export type ThreatLevel = 'critical' | 'elevated' | 'moderate' | 'low'

export interface ThreatMetric {
  label: string
  value: number
  previousValue?: number
  trend?: 'up' | 'down' | 'stable'
  trendPercent?: number
  format?: 'number' | 'percent' | 'duration'
}

export interface ActiveThreat {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  type: string
  affectedAssets: number
  firstSeen: number
  mitreTechnique?: string
}

export interface ThreatSummaryData {
  threatLevel: ThreatLevel
  threatScore: number
  metrics: {
    activeThreats: ThreatMetric
    blockedAttacks: ThreatMetric
    compromisedAssets: ThreatMetric
    meanTimeToDetect: ThreatMetric
    meanTimeToRespond: ThreatMetric
  }
  topThreats: ActiveThreat[]
  recommendations: string[]
  lastUpdated: number
}

export interface ThreatSummaryProps {
  data?: ThreatSummaryData
  isLoading?: boolean
  onViewThreats?: () => void
  onThreatClick?: (threat: ActiveThreat) => void
  className?: string
  compact?: boolean
}

const EMPTY_METRIC = (label: string, format: ThreatMetric['format'] = 'number'): ThreatMetric => ({
  label,
  value: 0,
  trend: 'stable',
  trendPercent: 0,
  format,
})

function normalizeThreatSummaryData(data?: ThreatSummaryData | null): ThreatSummaryData | null {
  if (!data) return null

  return {
    threatLevel: data.threatLevel ?? 'low',
    threatScore: data.threatScore ?? 0,
    metrics: {
      activeThreats: data.metrics?.activeThreats ?? EMPTY_METRIC('Active Threats'),
      blockedAttacks: data.metrics?.blockedAttacks ?? EMPTY_METRIC('Blocked Attacks'),
      compromisedAssets: data.metrics?.compromisedAssets ?? EMPTY_METRIC('Compromised Assets'),
      meanTimeToDetect: data.metrics?.meanTimeToDetect ?? EMPTY_METRIC('Mean Time to Detect', 'duration'),
      meanTimeToRespond: data.metrics?.meanTimeToRespond ?? EMPTY_METRIC('Mean Time to Respond', 'duration'),
    },
    topThreats: data.topThreats ?? [],
    recommendations: data.recommendations ?? [],
    lastUpdated: data.lastUpdated ?? Date.now(),
  }
}

// ============================================================================
// Constants
// ============================================================================

const THREAT_LEVEL_CONFIG: Record<ThreatLevel, {
  label: string
  color: string
  bgColor: string
  borderColor: string
  icon: React.ElementType
  description: string
}> = {
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bgColor: 'bg-red-500/20',
    borderColor: 'border-red-500',
    icon: AlertTriangle,
    description: 'Immediate action required. Active threats detected.',
  },
  elevated: {
    label: 'Elevated',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/20',
    borderColor: 'border-orange-500',
    icon: AlertCircle,
    description: 'Increased threat activity. Enhanced monitoring active.',
  },
  moderate: {
    label: 'Moderate',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/20',
    borderColor: 'border-yellow-500',
    icon: Activity,
    description: 'Normal operations. Standard monitoring in place.',
  },
  low: {
    label: 'Low',
    color: 'text-green-400',
    bgColor: 'bg-green-500/20',
    borderColor: 'border-green-500',
    icon: CheckCircle,
    description: 'All systems secure. No active threats detected.',
  },
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatMetricValue(value: number, format?: string): string {
  const safeValue = value ?? 0
  switch (format) {
    case 'percent':
      return `${safeValue.toFixed(1)}%`
    case 'duration':
      if (safeValue < 60) return `${Math.round(safeValue)}s`
      if (safeValue < 3600) return `${Math.round(safeValue / 60)}m`
      return `${(safeValue / 3600).toFixed(1)}h`
    default:
      return safeValue.toLocaleString()
  }
}

function formatTimeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

// ============================================================================
// Subcomponents
// ============================================================================

interface MetricCardProps {
  metric: ThreatMetric
  icon: React.ElementType
  accentColor: string
}

function MetricCard({ metric, icon: Icon, accentColor }: MetricCardProps) {
  const showTrend = metric.trend && metric.trend !== 'stable' && metric.trendPercent

  return (
    <div className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-lg">
      <div className={cn('p-2 rounded-lg', `bg-${accentColor}-500/20`)}>
        <Icon className={cn('h-4 w-4', `text-${accentColor}-400`)} style={{ color: `var(--${accentColor}-400, #60a5fa)` }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold text-white">
            {formatMetricValue(metric.value, metric.format)}
          </span>
          {showTrend && (
            <span
              className={cn(
                'flex items-center gap-0.5 text-xs font-medium',
                metric.trend === 'up' ? 'text-red-400' : 'text-green-400'
              )}
            >
              {metric.trend === 'up' ? (
                <TrendingUp className="h-3 w-3" />
              ) : (
                <TrendingDown className="h-3 w-3" />
              )}
              {metric.trendPercent}%
            </span>
          )}
        </div>
        <p className="text-xs text-slate-400 truncate">{metric.label}</p>
      </div>
    </div>
  )
}

interface ThreatItemProps {
  threat: ActiveThreat
  onClick?: () => void
}

function ThreatItem({ threat, onClick }: ThreatItemProps) {
  const severityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 w-full p-2 rounded-lg hover:bg-slate-700/50 transition-colors text-left"
    >
      <div className={cn('p-1.5 rounded border', severityColors[threat.severity])}>
        <Target className="h-3.5 w-3.5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-white truncate">{threat.title}</span>
          {threat.mitreTechnique && (
            <span className="text-xs text-primary-400 font-mono">{threat.mitreTechnique}</span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>{threat.type}</span>
          <span className="text-slate-600">|</span>
          <span>{threat.affectedAssets} affected</span>
          <span className="text-slate-600">|</span>
          <span>{formatTimeAgo(threat.firstSeen)}</span>
        </div>
      </div>
      <ArrowUpRight className="h-4 w-4 text-slate-500" />
    </button>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatSummary({
  data,
  isLoading = false,
  onViewThreats,
  onThreatClick,
  className,
  compact = false,
}: ThreatSummaryProps) {
  const safeData = normalizeThreatSummaryData(data)
  const levelConfig = safeData ? THREAT_LEVEL_CONFIG[safeData.threatLevel] : THREAT_LEVEL_CONFIG.low
  const LevelIcon = levelConfig.icon

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-700 rounded w-1/2" />
          <div className="h-24 bg-slate-700 rounded" />
          <div className="grid grid-cols-3 gap-3">
            <div className="h-16 bg-slate-700 rounded" />
            <div className="h-16 bg-slate-700 rounded" />
            <div className="h-16 bg-slate-700 rounded" />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Threat Level Banner */}
      <div className={cn('px-4 py-3 border-b', levelConfig.bgColor, levelConfig.borderColor)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-lg bg-slate-900/50')}>
              <LevelIcon className={cn('h-5 w-5', levelConfig.color)} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={cn('font-bold text-lg', levelConfig.color)}>
                  {levelConfig.label}
                </span>
                <span className="text-sm text-slate-300">Threat Level</span>
              </div>
              <p className="text-xs text-slate-400">{levelConfig.description}</p>
            </div>
          </div>

          {safeData && (
            <div className="text-right">
              <div className="text-2xl font-bold text-white">{safeData.threatScore}</div>
              <div className="text-xs text-slate-400">Risk Score</div>
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="p-4">
        {/* Key Metrics */}
        {safeData?.metrics && (
          <div className={cn('grid gap-3', compact ? 'grid-cols-2' : 'grid-cols-2 lg:grid-cols-3')}>
            <MetricCard
              metric={safeData.metrics.activeThreats}
              icon={AlertTriangle}
              accentColor="red"
            />
            <MetricCard
              metric={safeData.metrics.blockedAttacks}
              icon={Shield}
              accentColor="green"
            />
            <MetricCard
              metric={safeData.metrics.compromisedAssets}
              icon={Target}
              accentColor="orange"
            />
            {!compact && (
              <>
                <MetricCard
                  metric={safeData.metrics.meanTimeToDetect}
                  icon={Clock}
                  accentColor="blue"
                />
                <MetricCard
                  metric={safeData.metrics.meanTimeToRespond}
                  icon={Zap}
                  accentColor="purple"
                />
              </>
            )}
          </div>
        )}

        {/* Top Active Threats */}
        {!compact && safeData?.topThreats && safeData.topThreats.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-700">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-semibold text-white">Active Threats</h4>
              <button
                onClick={onViewThreats}
                className="text-xs text-primary-400 hover:text-primary-300"
              >
                View All
              </button>
            </div>
            <div className="space-y-1">
              {safeData.topThreats.slice(0, 3).map(threat => (
                <ThreatItem
                  key={threat.id}
                  threat={threat}
                  onClick={() => onThreatClick?.(threat)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {!compact && safeData?.recommendations && safeData.recommendations.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-700">
            <h4 className="text-sm font-semibold text-white mb-2">Recommended Actions</h4>
            <ul className="space-y-1.5">
              {safeData.recommendations.slice(0, 3).map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                  <div className="w-4 h-4 rounded-full bg-primary-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <span className="text-primary-400 text-[10px] font-bold">{i + 1}</span>
                  </div>
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-slate-700 bg-slate-900/30 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          Last updated {safeData ? formatTimeAgo(safeData.lastUpdated) : 'never'}
        </span>
        <button
          onClick={onViewThreats}
          className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
        >
          View Details
          <ArrowUpRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  )
}

// ============================================================================
// Hook for fetching threat summary
// ============================================================================

export function useThreatSummary(timeRange: string = '7d') {
  const [data, setData] = useState<ThreatSummaryData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/v1/stats/overview?range=${timeRange}`)
      if (!response.ok) throw new Error('Failed to fetch threat summary')
      const result = await response.json()
      setData(result.data)
    } catch (err) {
      // Fall back to Inertia shared page props if API call fails
      try {
        const pageEl = document.getElementById('app')
        if (pageEl) {
          const pageData = pageEl.dataset.page
          if (pageData) {
            const parsed = JSON.parse(pageData)
            if (parsed.props?.threatSummary) {
              setData(parsed.props.threatSummary)
              return
            }
          }
        }
      } catch (_fallbackErr) {
        // Fallback also failed, use original error
      }
      setError(err instanceof Error ? err : new Error('Unknown error'))
    } finally {
      setIsLoading(false)
    }
  }, [timeRange])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return {
    data,
    isLoading,
    error,
    refresh: fetchData,
  }
}

export default ThreatSummary
