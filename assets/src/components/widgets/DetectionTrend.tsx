/**
 * DetectionTrend Widget
 *
 * Detection trend visualization showing security detection patterns
 * over time with sparklines, category breakdowns, and trend indicators.
 */

import { useState, useMemo, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Popover } from '@/components/ui/baseui'
import {
  TrendingUp,
  TrendingDown,
  Minus,
  Shield,
  AlertTriangle,
  Activity,
  Eye,
  ChevronDown,
  BarChart3,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface TrendDataPoint {
  timestamp: number
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface DetectionCategory {
  name: string
  count: number
  change: number
  trend: 'up' | 'down' | 'stable'
  color: string
}

export interface DetectionTrendData {
  dataPoints: TrendDataPoint[]
  totalDetections: number
  change: number
  trend: 'up' | 'down' | 'stable'
  categories: DetectionCategory[]
  averagePerDay: number
  peakHour: number
  lastUpdated: number
}

export interface DetectionTrendProps {
  data?: DetectionTrendData
  isLoading?: boolean
  onCategoryClick?: (category: string) => void
  onPeriodChange?: (period: string) => void
  period?: string
  className?: string
  showCategories?: boolean
  showSparkline?: boolean
}

// ============================================================================
// Subcomponents
// ============================================================================

interface SparklineProps {
  data: TrendDataPoint[]
  height?: number
  showArea?: boolean
  color?: string
  animated?: boolean
}

function Sparkline({
  data,
  height = 60,
  showArea = true,
  color = '#6366f1',
  animated = true,
}: SparklineProps) {
  const width = 200

  const { points, areaPoints, minY, maxY } = useMemo(() => {
    if (data.length === 0) return { points: '', areaPoints: '', minY: 0, maxY: 0 }

    const values = data.map(d => d.total)
    const min = Math.min(...values)
    const max = Math.max(...values)
    const range = max - min || 1

    const pts = data.map((d, i) => {
      const x = (i / (data.length - 1)) * width
      const y = height - ((d.total - min) / range) * (height - 10) - 5
      return `${x},${y}`
    }).join(' ')

    const areaPts = `0,${height} ${pts} ${width},${height}`

    return { points: pts, areaPoints: areaPts, minY: min, maxY: max }
  }, [data, height, width])

  if (data.length === 0) return null

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full">
      <defs>
        <linearGradient id="sparklineGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.3} />
          <stop offset="100%" stopColor={color} stopOpacity={0.05} />
        </linearGradient>
      </defs>

      {/* Area fill */}
      {showArea && (
        <polygon
          points={areaPoints}
          fill="url(#sparklineGradient)"
          className={animated ? 'animate-fade-in' : ''}
        />
      )}

      {/* Line */}
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        className={animated ? 'animate-draw' : ''}
      />

      {/* End point indicator */}
      {data.length > 0 && (
        <circle
          cx={width}
          cy={height - ((data[data.length - 1].total - minY) / (maxY - minY || 1)) * (height - 10) - 5}
          r={4}
          fill={color}
          className="animate-pulse"
        />
      )}

      {/* CSS for animations */}
      <style>{`
        @keyframes draw {
          from { stroke-dasharray: 1000; stroke-dashoffset: 1000; }
          to { stroke-dasharray: 1000; stroke-dashoffset: 0; }
        }
        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .animate-draw {
          animation: draw 1.5s ease-out forwards;
        }
        .animate-fade-in {
          animation: fade-in 0.5s ease-out forwards;
        }
      `}</style>
    </svg>
  )
}

interface SeverityBarProps {
  data: TrendDataPoint[]
}

function SeverityBar({ data }: SeverityBarProps) {
  const totals = useMemo(() => {
    const result = { critical: 0, high: 0, medium: 0, low: 0 }
    data.forEach(d => {
      result.critical += d.critical
      result.high += d.high
      result.medium += d.medium
      result.low += d.low
    })
    return result
  }, [data])

  const total = totals.critical + totals.high + totals.medium + totals.low

  if (total === 0) return null

  const segments = [
    { key: 'critical', value: totals.critical, color: '#ef4444' },
    { key: 'high', value: totals.high, color: '#f97316' },
    { key: 'medium', value: totals.medium, color: '#eab308' },
    { key: 'low', value: totals.low, color: '#3b82f6' },
  ]

  return (
    <div className="space-y-2">
      <div className="h-2 flex rounded-full overflow-hidden bg-slate-700">
        {segments.map(seg => (
          <div
            key={seg.key}
            className="h-full transition-all duration-500"
            style={{
              width: `${(seg.value / total) * 100}%`,
              backgroundColor: seg.color,
            }}
          />
        ))}
      </div>
      <div className="flex justify-between text-xs">
        {segments.map(seg => (
          <div key={seg.key} className="flex items-center gap-1">
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: seg.color }}
            />
            <span className="text-slate-400 capitalize">{seg.key}</span>
            <span className="text-white font-medium">{seg.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

interface CategoryRowProps {
  category: DetectionCategory
  onClick?: () => void
  maxCount: number
}

function CategoryRow({ category, onClick, maxCount }: CategoryRowProps) {
  const percentage = (category.count / maxCount) * 100

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 w-full p-2 rounded-lg hover:bg-slate-700/50 transition-colors"
    >
      <div
        className="w-1 h-8 rounded-full"
        style={{ backgroundColor: category.color }}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-sm font-medium text-slate-200">{category.name}</span>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-white">{category.count}</span>
            {category.trend !== 'stable' && (
              <span
                className={cn(
                  'flex items-center gap-0.5 text-xs',
                  category.trend === 'up' ? 'text-red-400' : 'text-green-400'
                )}
              >
                {category.trend === 'up' ? (
                  <TrendingUp className="h-3 w-3" />
                ) : (
                  <TrendingDown className="h-3 w-3" />
                )}
                {Math.abs(category.change)}%
              </span>
            )}
          </div>
        </div>
        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${percentage}%`,
              backgroundColor: category.color,
            }}
          />
        </div>
      </div>
    </button>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function DetectionTrend({
  data,
  isLoading = false,
  onCategoryClick,
  onPeriodChange,
  period = '7d',
  className,
  showCategories = true,
  showSparkline = true,
}: DetectionTrendProps) {
  const [showDropdown, setShowDropdown] = useState(false)

  const periodOptions = [
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' },
  ]

  const maxCategoryCount = useMemo(() => {
    if (!data?.categories) return 0
    return Math.max(...data.categories.map(c => c.count))
  }, [data?.categories])

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/3" />
          <div className="h-16 bg-slate-700 rounded" />
          <div className="space-y-2">
            <div className="h-10 bg-slate-700 rounded" />
            <div className="h-10 bg-slate-700 rounded" />
          </div>
        </div>
      </div>
    )
  }

  if (!data || !data.dataPoints || data.dataPoints.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <BarChart3 className="h-5 w-5 text-primary-400" />
          </div>
          <h3 className="font-semibold text-white">Detection Trend</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <BarChart3 className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No detection data available</p>
          <p className="text-slate-500 text-xs mt-1">Detection trends will appear as events are processed</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <BarChart3 className="h-5 w-5 text-primary-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Detection Trend</h3>
            <p className="text-xs text-slate-400">Security detections over time</p>
          </div>
        </div>

        {/* Period selector */}
        <Popover
          open={showDropdown}
          onOpenChange={setShowDropdown}
          trigger={
            <button
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
            >
              {periodOptions.find(o => o.value === period)?.label}
              <ChevronDown className={cn('h-4 w-4 transition-transform', showDropdown && 'rotate-180')} />
            </button>
          }
        >
          <div className="flex flex-col gap-1 min-w-[8rem]">
            {periodOptions.map(opt => (
              <button
                key={opt.value}
                className={cn(
                  'w-full px-3 py-2 text-sm text-left rounded hover:bg-slate-600',
                  period === opt.value && 'bg-primary-600/20 text-primary-400'
                )}
                onClick={() => {
                  onPeriodChange?.(opt.value)
                  setShowDropdown(false)
                }}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </Popover>
      </div>

      {/* Stats Summary */}
      {data && (
        <div className="grid grid-cols-3 gap-4 p-4 border-b border-slate-700 bg-slate-900/30">
          <div className="text-center">
            <div className="flex items-center justify-center gap-1">
              <span className="text-2xl font-bold text-white">{data.totalDetections.toLocaleString()}</span>
              {data.trend !== 'stable' && (
                <span
                  className={cn(
                    'flex items-center text-sm',
                    data.trend === 'up' ? 'text-red-400' : 'text-green-400'
                  )}
                >
                  {data.trend === 'up' ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">Total Detections</p>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{data.averagePerDay.toLocaleString()}</div>
            <p className="text-xs text-slate-400">Avg per Day</p>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{data.peakHour}:00</div>
            <p className="text-xs text-slate-400">Peak Hour</p>
          </div>
        </div>
      )}

      {/* Sparkline */}
      {showSparkline && data?.dataPoints && (
        <div className="p-4 border-b border-slate-700">
          <div className="h-16">
            <Sparkline data={data.dataPoints} animated />
          </div>
          <SeverityBar data={data.dataPoints} />
        </div>
      )}

      {/* Categories */}
      {showCategories && data?.categories && data.categories.length > 0 && (
        <div className="p-4">
          <h4 className="text-sm font-medium text-slate-400 mb-3">Detection Categories</h4>
          <div className="space-y-1">
            {data.categories.slice(0, 5).map(cat => (
              <CategoryRow
                key={cat.name}
                category={cat}
                onClick={() => onCategoryClick?.(cat.name)}
                maxCount={maxCategoryCount}
              />
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      {data && (
        <div className="px-4 py-2 border-t border-slate-700 bg-slate-900/30">
          <span className="text-xs text-slate-500">
            Updated {new Date(data.lastUpdated).toLocaleTimeString()}
          </span>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching detection trend data
// ============================================================================

export function useDetectionTrend(period: string = '7d') {
  const [data, setData] = useState<DetectionTrendData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/v1/stats/detections?period=${period}`)
      if (!response.ok) throw new Error('Failed to fetch detection trend')
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
            if (parsed.props?.detectionTrend) {
              setData(parsed.props.detectionTrend)
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
  }, [period])

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

export default DetectionTrend
