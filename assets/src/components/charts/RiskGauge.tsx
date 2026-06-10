/**
 * RiskGauge Component
 *
 * An animated risk score gauge visualization with severity zones,
 * historical comparison, and trend indicators. Inspired by enterprise
 * security dashboards from CrowdStrike and SentinelOne.
 */

import { useState, useEffect, useMemo, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  Shield,
  Info,
  History,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface RiskBreakdown {
  category: string
  score: number
  maxScore: number
  trend: 'up' | 'down' | 'stable'
  issues: number
}

export interface RiskHistory {
  timestamp: number
  score: number
}

export interface RiskGaugeData {
  currentScore: number
  previousScore: number
  maxScore: number
  trend: 'up' | 'down' | 'stable'
  trendPercent: number
  breakdown?: RiskBreakdown[]
  history?: RiskHistory[]
  lastUpdated: number
}

export interface RiskGaugeProps {
  data?: RiskGaugeData
  isLoading?: boolean
  onBreakdownClick?: (category: string) => void
  className?: string
  size?: 'sm' | 'md' | 'lg'
  showBreakdown?: boolean
  showHistory?: boolean
  animated?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const SIZE_CONFIG = {
  sm: { width: 180, height: 100, strokeWidth: 12, fontSize: 24 },
  md: { width: 240, height: 130, strokeWidth: 16, fontSize: 32 },
  lg: { width: 320, height: 170, strokeWidth: 20, fontSize: 42 },
}

const SEVERITY_ZONES = [
  { min: 0, max: 25, label: 'Low', color: '#22c55e', bgColor: 'bg-green-500/20', textColor: 'text-green-400' },
  { min: 25, max: 50, label: 'Medium', color: '#eab308', bgColor: 'bg-yellow-500/20', textColor: 'text-yellow-400' },
  { min: 50, max: 75, label: 'High', color: '#f97316', bgColor: 'bg-orange-500/20', textColor: 'text-orange-400' },
  { min: 75, max: 100, label: 'Critical', color: '#ef4444', bgColor: 'bg-red-500/20', textColor: 'text-red-400' },
]

// ============================================================================
// Utility Functions
// ============================================================================

function getSeverityZone(score: number) {
  return SEVERITY_ZONES.find(z => score >= z.min && score < z.max) || SEVERITY_ZONES[3]
}

function getScoreColor(score: number): string {
  if (score < 25) return '#22c55e'
  if (score < 50) return '#eab308'
  if (score < 75) return '#f97316'
  return '#ef4444'
}

function formatScore(score: number): string {
  return Math.round(score).toString()
}

// ============================================================================
// Subcomponents
// ============================================================================

interface GaugeSVGProps {
  score: number
  maxScore: number
  size: 'sm' | 'md' | 'lg'
  animated: boolean
}

function GaugeSVG({ score, maxScore, size, animated }: GaugeSVGProps) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const config = SIZE_CONFIG[size]

  // Animate score on mount and changes
  useEffect(() => {
    if (!animated) {
      setAnimatedScore(score)
      return
    }

    const duration = 1500
    const startTime = Date.now()
    const startScore = animatedScore

    const animate = () => {
      const elapsed = Date.now() - startTime
      const progress = Math.min(elapsed / duration, 1)
      // Easing function for smooth animation
      const easeOutExpo = 1 - Math.pow(2, -10 * progress)
      const current = startScore + (score - startScore) * easeOutExpo

      setAnimatedScore(current)

      if (progress < 1) {
        requestAnimationFrame(animate)
      }
    }

    requestAnimationFrame(animate)
  }, [score, animated])

  const normalizedScore = (animatedScore / maxScore) * 100
  const color = getScoreColor(normalizedScore)

  // Arc parameters
  const centerX = config.width / 2
  const centerY = config.height - 10
  const radius = config.width / 2 - config.strokeWidth / 2 - 10
  const startAngle = Math.PI
  const endAngle = 0
  const scoreAngle = startAngle - (normalizedScore / 100) * Math.PI

  // Path for background arc
  const bgPath = describeArc(centerX, centerY, radius, startAngle, endAngle)

  // Path for score arc
  const scorePath = describeArc(centerX, centerY, radius, startAngle, scoreAngle)

  // Needle position
  const needleAngle = startAngle - (normalizedScore / 100) * Math.PI
  const needleLength = radius - 15
  const needleX = centerX + Math.cos(needleAngle) * needleLength
  const needleY = centerY - Math.sin(needleAngle) * needleLength

  return (
    <svg
      width={config.width}
      height={config.height}
      viewBox={`0 0 ${config.width} ${config.height}`}
      className="overflow-visible"
    >
      {/* Glow filter */}
      <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#22c55e" />
          <stop offset="33%" stopColor="#eab308" />
          <stop offset="66%" stopColor="#f97316" />
          <stop offset="100%" stopColor="#ef4444" />
        </linearGradient>
      </defs>

      {/* Severity zone markers */}
      {SEVERITY_ZONES.map((zone, i) => {
        const zoneStartAngle = startAngle - (zone.min / 100) * Math.PI
        const zoneEndAngle = startAngle - (zone.max / 100) * Math.PI
        const zonePath = describeArc(centerX, centerY, radius + config.strokeWidth / 2 + 2, zoneStartAngle, zoneEndAngle)

        return (
          <path
            key={i}
            d={zonePath}
            fill="none"
            stroke={zone.color}
            strokeWidth={2}
            opacity={0.3}
          />
        )
      })}

      {/* Background arc */}
      <path
        d={bgPath}
        fill="none"
        stroke="#334155"
        strokeWidth={config.strokeWidth}
        strokeLinecap="round"
      />

      {/* Score arc */}
      <path
        d={scorePath}
        fill="none"
        stroke={color}
        strokeWidth={config.strokeWidth}
        strokeLinecap="round"
        filter="url(#glow)"
        style={{
          transition: animated ? 'none' : 'stroke 0.5s ease',
        }}
      />

      {/* Tick marks */}
      {[0, 25, 50, 75, 100].map((tick) => {
        const tickAngle = startAngle - (tick / 100) * Math.PI
        const innerRadius = radius - config.strokeWidth / 2 - 5
        const outerRadius = radius + config.strokeWidth / 2 + 5
        const x1 = centerX + Math.cos(tickAngle) * innerRadius
        const y1 = centerY - Math.sin(tickAngle) * innerRadius
        const x2 = centerX + Math.cos(tickAngle) * outerRadius
        const y2 = centerY - Math.sin(tickAngle) * outerRadius

        return (
          <g key={tick}>
            <line
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="#64748b"
              strokeWidth={2}
            />
            <text
              x={centerX + Math.cos(tickAngle) * (outerRadius + 12)}
              y={centerY - Math.sin(tickAngle) * (outerRadius + 12)}
              textAnchor="middle"
              dominantBaseline="middle"
              fill="#64748b"
              fontSize={10}
            >
              {tick}
            </text>
          </g>
        )
      })}

      {/* Needle */}
      <g filter="url(#glow)">
        <line
          x1={centerX}
          y1={centerY}
          x2={needleX}
          y2={needleY}
          stroke={color}
          strokeWidth={3}
          strokeLinecap="round"
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={8}
          fill={color}
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={4}
          fill="#0f172a"
        />
      </g>

      {/* Score text */}
      <text
        x={centerX}
        y={centerY - 25}
        textAnchor="middle"
        dominantBaseline="middle"
        fill="white"
        fontSize={config.fontSize}
        fontWeight="bold"
      >
        {formatScore(animatedScore)}
      </text>

      {/* Label */}
      <text
        x={centerX}
        y={centerY - 5}
        textAnchor="middle"
        dominantBaseline="middle"
        fill="#94a3b8"
        fontSize={12}
      >
        Risk Score
      </text>
    </svg>
  )
}

// Helper function to describe an arc path
function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number): string {
  const start = {
    x: cx + Math.cos(startAngle) * r,
    y: cy - Math.sin(startAngle) * r,
  }
  const end = {
    x: cx + Math.cos(endAngle) * r,
    y: cy - Math.sin(endAngle) * r,
  }

  const largeArcFlag = Math.abs(startAngle - endAngle) > Math.PI ? 1 : 0
  const sweepFlag = startAngle > endAngle ? 1 : 0

  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArcFlag} ${sweepFlag} ${end.x} ${end.y}`
}

interface BreakdownItemProps {
  item: RiskBreakdown
  onClick?: () => void
}

function BreakdownItem({ item, onClick }: BreakdownItemProps) {
  const percentage = (item.score / item.maxScore) * 100
  const color = getScoreColor(percentage)

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-700/50 transition-colors w-full text-left"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-sm font-medium text-slate-200 truncate">{item.category}</span>
          <div className="flex items-center gap-1">
            <span className="text-sm font-semibold" style={{ color }}>
              {Math.round(item.score)}
            </span>
            <span className="text-xs text-slate-500">/{item.maxScore}</span>
          </div>
        </div>
        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${percentage}%`,
              backgroundColor: color,
            }}
          />
        </div>
      </div>
      {item.trend !== 'stable' && (
        <div className={cn(
          'flex items-center gap-0.5 text-xs',
          item.trend === 'up' ? 'text-red-400' : 'text-green-400'
        )}>
          {item.trend === 'up' ? (
            <TrendingUp className="h-3 w-3" />
          ) : (
            <TrendingDown className="h-3 w-3" />
          )}
        </div>
      )}
    </button>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function RiskGauge({
  data,
  isLoading = false,
  onBreakdownClick,
  className,
  size = 'md',
  showBreakdown = true,
  showHistory = false,
  animated = true,
}: RiskGaugeProps) {
  const normalizedScore = data ? (data.currentScore / data.maxScore) * 100 : 0
  const zone = getSeverityZone(normalizedScore)

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-32 bg-slate-700 rounded" />
          <div className="h-4 bg-slate-700 rounded w-1/2 mx-auto" />
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-slate-700 rounded-lg">
            <Shield className="h-5 w-5 text-slate-400" />
          </div>
          <h3 className="font-semibold text-white">Security Risk Score</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Shield className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">Risk score unavailable</p>
          <p className="text-slate-500 text-xs mt-1">Risk data will appear once analytics are running</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', zone.bgColor)}>
            {normalizedScore >= 75 ? (
              <AlertTriangle className={cn('h-5 w-5', zone.textColor)} />
            ) : (
              <Shield className={cn('h-5 w-5', zone.textColor)} />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-white">Security Risk Score</h3>
            <p className={cn('text-xs', zone.textColor)}>{zone.label} Risk</p>
          </div>
        </div>

        {data && (
          <div className="flex items-center gap-2">
            {data.trend === 'up' && (
              <div className="flex items-center gap-1 text-red-400 text-sm">
                <TrendingUp className="h-4 w-4" />
                <span>+{data.trendPercent}%</span>
              </div>
            )}
            {data.trend === 'down' && (
              <div className="flex items-center gap-1 text-green-400 text-sm">
                <TrendingDown className="h-4 w-4" />
                <span>-{data.trendPercent}%</span>
              </div>
            )}
            {data.trend === 'stable' && (
              <div className="flex items-center gap-1 text-slate-400 text-sm">
                <Minus className="h-4 w-4" />
                <span>Stable</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Gauge */}
      <div className="flex justify-center py-6">
        <GaugeSVG
          score={data?.currentScore || 0}
          maxScore={data?.maxScore || 100}
          size={size}
          animated={animated}
        />
      </div>

      {/* Severity Legend */}
      <div className="flex justify-center gap-4 px-4 pb-4">
        {SEVERITY_ZONES.map((z) => (
          <div key={z.label} className="flex items-center gap-1.5">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: z.color }}
            />
            <span className="text-xs text-slate-400">{z.label}</span>
          </div>
        ))}
      </div>

      {/* Breakdown */}
      {showBreakdown && data?.breakdown && data.breakdown.length > 0 && (
        <div className="border-t border-slate-700 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Info className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">Risk Breakdown</span>
          </div>
          <div className="space-y-1">
            {data.breakdown.map((item) => (
              <BreakdownItem
                key={item.category}
                item={item}
                onClick={() => onBreakdownClick?.(item.category)}
              />
            ))}
          </div>
        </div>
      )}

      {/* History Mini Chart */}
      {showHistory && data?.history && data.history.length > 0 && (
        <div className="border-t border-slate-700 p-4">
          <div className="flex items-center gap-2 mb-3">
            <History className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">7-Day Trend</span>
          </div>
          <div className="h-12">
            <MiniSparkline data={data.history} />
          </div>
        </div>
      )}

      {/* Footer */}
      {data && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700 bg-slate-900/30 text-xs text-slate-500">
          <span>
            Previous: {Math.round(data.previousScore)}/100
          </span>
          <span>
            Updated {new Date(data.lastUpdated).toLocaleTimeString()}
          </span>
        </div>
      )}
    </div>
  )
}

// Mini sparkline component for history
function MiniSparkline({ data }: { data: RiskHistory[] }) {
  const points = useMemo(() => {
    if (data.length === 0) return ''

    const minScore = Math.min(...data.map(d => d.score))
    const maxScore = Math.max(...data.map(d => d.score))
    const range = maxScore - minScore || 1

    return data
      .map((d, i) => {
        const x = (i / (data.length - 1)) * 100
        const y = 100 - ((d.score - minScore) / range) * 100
        return `${x},${y}`
      })
      .join(' ')
  }, [data])

  const lastScore = data[data.length - 1]?.score || 0
  const color = getScoreColor(lastScore)

  return (
    <svg viewBox="0 0 100 100" className="w-full h-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id="sparklineGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.3} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>

      {/* Area fill */}
      <polygon
        points={`0,100 ${points} 100,100`}
        fill="url(#sparklineGradient)"
      />

      {/* Line */}
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={2}
        vectorEffect="non-scaling-stroke"
      />

      {/* End dot */}
      {data.length > 0 && (
        <circle
          cx={100}
          cy={100 - (lastScore / 100) * 100}
          r={3}
          fill={color}
          className="animate-pulse"
        />
      )}
    </svg>
  )
}

// ============================================================================
// Hook for fetching risk data
// ============================================================================

export function useRiskGauge(timeRange: string = '7d') {
  const [data, setData] = useState<RiskGaugeData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/analytics/risk-score?range=${timeRange}`)
      if (!response.ok) throw new Error('Failed to fetch risk data')
      const result = await response.json()
      setData(result.data)
    } catch (err) {
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

export default RiskGauge
