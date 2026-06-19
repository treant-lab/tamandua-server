/**
 * ThreatHeatmap Component
 *
 * A time-based heatmap visualization showing threat activity patterns
 * by hour of day and day of week. Inspired by GitHub contribution graphs
 * and CrowdStrike's threat density visualizations.
 */

import { useState, useMemo, useEffect, useCallback } from 'react'
import { cn, safeCapitalize } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'
import {
  Calendar,
  Clock,
  AlertTriangle,
  TrendingUp,
  Filter,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface HeatmapCell {
  hour: number
  day: number
  count: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface ThreatHeatmapData {
  cells: HeatmapCell[]
  maxCount: number
  totalThreats: number
  peakHour: number
  peakDay: number
  trend: 'up' | 'down' | 'stable'
  trendPercent: number
}

export interface ThreatHeatmapProps {
  data?: ThreatHeatmapData
  isLoading?: boolean
  onCellClick?: (cell: HeatmapCell) => void
  onTimeRangeChange?: (range: string) => void
  timeRange?: string
  className?: string
  showLegend?: boolean
  showStats?: boolean
  animated?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const HOURS = Array.from({ length: 24 }, (_, i) => i)

const SEVERITY_COLORS = {
  critical: { bg: '#dc2626', glow: 'rgba(220, 38, 38, 0.6)' },
  high: { bg: '#ea580c', glow: 'rgba(234, 88, 12, 0.5)' },
  medium: { bg: '#ca8a04', glow: 'rgba(202, 138, 4, 0.4)' },
  low: { bg: '#2563eb', glow: 'rgba(37, 99, 235, 0.3)' },
  none: { bg: '#1e293b', glow: 'none' },
}

// ============================================================================
// Utility Functions
// ============================================================================

function getIntensityColor(count: number, maxCount: number, critical: number): string {
  if (count === 0) return SEVERITY_COLORS.none.bg

  const intensity = Math.min(count / Math.max(maxCount, 1), 1)

  // If has critical threats, use critical color gradient
  if (critical > 0) {
    const alpha = 0.3 + intensity * 0.7
    return `rgba(220, 38, 38, ${alpha})`
  }

  // Otherwise use primary color gradient
  const alpha = 0.2 + intensity * 0.8
  return `rgba(99, 102, 241, ${alpha})`
}

function formatHour(hour: number): string {
  if (hour === 0) return '12 AM'
  if (hour === 12) return '12 PM'
  if (hour < 12) return `${hour} AM`
  return `${hour - 12} PM`
}

// ============================================================================
// Subcomponents
// ============================================================================

interface HeatmapCellComponentProps {
  cell: HeatmapCell
  maxCount: number
  onClick?: () => void
  isHovered: boolean
  onHover: (isHovered: boolean) => void
  animated: boolean
}

function HeatmapCellComponent({
  cell,
  maxCount,
  onClick,
  isHovered,
  onHover,
  animated,
}: HeatmapCellComponentProps) {
  const color = getIntensityColor(cell.count, maxCount, cell.critical)
  const hasCritical = cell.critical > 0

  return (
    <div
      className={cn(
        'w-5 h-5 rounded-sm cursor-pointer transition-all duration-200',
        isHovered && 'ring-2 ring-white ring-offset-1 ring-offset-slate-900 scale-125 z-10',
        animated && cell.count > 0 && 'animate-pulse-subtle'
      )}
      style={{
        backgroundColor: color,
        boxShadow: hasCritical && cell.count > 0
          ? `0 0 ${8 + (cell.critical / Math.max(maxCount, 1)) * 12}px ${SEVERITY_COLORS.critical.glow}`
          : 'none',
      }}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      role="button"
      aria-label={`${DAYS[cell.day]} ${formatHour(cell.hour)}: ${cell.count} threats`}
    />
  )
}

interface TooltipProps {
  cell: HeatmapCell
  position: { x: number; y: number }
}

function Tooltip({ cell, position }: TooltipProps) {
  return (
    <div
      className="fixed z-50 pointer-events-none"
      style={{
        left: position.x,
        top: position.y,
        transform: 'translate(-50%, -100%) translateY(-8px)',
      }}
    >
      <div className="bg-slate-800 border border-slate-600 rounded-lg shadow-xl p-3 min-w-48">
        <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-700">
          <Clock className="h-4 w-4 text-slate-400" />
          <span className="font-medium text-white">
            {DAYS[cell.day]} {formatHour(cell.hour)}
          </span>
        </div>

        <div className="space-y-1.5 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-400">Total Threats:</span>
            <span className="font-semibold text-white">{cell.count}</span>
          </div>
          {cell.critical > 0 && (
            <div className="flex justify-between">
              <span className="text-red-400">Critical:</span>
              <span className="font-semibold text-red-400">{cell.critical}</span>
            </div>
          )}
          {cell.high > 0 && (
            <div className="flex justify-between">
              <span className="text-orange-400">High:</span>
              <span className="font-semibold text-orange-400">{cell.high}</span>
            </div>
          )}
          {cell.medium > 0 && (
            <div className="flex justify-between">
              <span className="text-yellow-400">Medium:</span>
              <span className="font-semibold text-yellow-400">{cell.medium}</span>
            </div>
          )}
          {cell.low > 0 && (
            <div className="flex justify-between">
              <span className="text-blue-400">Low:</span>
              <span className="font-semibold text-blue-400">{cell.low}</span>
            </div>
          )}
        </div>
      </div>
      <div className="absolute left-1/2 -translate-x-1/2 -bottom-1.5 w-3 h-3 bg-slate-800 border-b border-r border-slate-600 rotate-45" />
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatHeatmap({
  data,
  isLoading = false,
  onCellClick,
  onTimeRangeChange,
  timeRange = '7d',
  className,
  showLegend = true,
  showStats = true,
  animated = true,
}: ThreatHeatmapProps) {
  const [hoveredCell, setHoveredCell] = useState<HeatmapCell | null>(null)
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 })
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)

  // Generate cell grid from data
  const cellGrid = useMemo(() => {
    if (!data?.cells) {
      // Generate empty grid
      return DAYS.map((_, day) =>
        HOURS.map((hour) => ({
          hour,
          day,
          count: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
        }))
      )
    }

    // Create a map for quick lookup
    const cellMap = new Map<string, HeatmapCell>()
    data.cells.forEach((cell) => {
      cellMap.set(`${cell.day}-${cell.hour}`, cell)
    })

    // Generate grid with data
    return DAYS.map((_, day) =>
      HOURS.map((hour) => {
        const cell = cellMap.get(`${day}-${hour}`)
        return cell || { hour, day, count: 0, critical: 0, high: 0, medium: 0, low: 0 }
      })
    )
  }, [data?.cells])

  // Filter cells based on severity
  const filteredMaxCount = useMemo(() => {
    if (!data || !severityFilter) return data?.maxCount || 0

    let max = 0
    cellGrid.flat().forEach((cell) => {
      const count = cell[severityFilter as keyof HeatmapCell] as number
      if (count > max) max = count
    })
    return max
  }, [data, severityFilter, cellGrid])

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    setTooltipPosition({ x: e.clientX, y: e.clientY })
  }, [])

  const timeRangeOptions = [
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' },
  ]

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/3" />
          <div className="h-40 bg-slate-700 rounded" />
        </div>
      </div>
    )
  }

  if (!data || !data.cells || data.cells.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Calendar className="h-5 w-5 text-primary-400" />
          </div>
          <h3 className="font-semibold text-white">Threat Activity Heatmap</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Calendar className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No heatmap data available</p>
          <p className="text-slate-500 text-xs mt-1">Activity patterns will appear as threats are detected</p>
        </div>
      </div>
    )
  }

  return (
    <div
      className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}
      onMouseMove={handleMouseMove}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Calendar className="h-5 w-5 text-primary-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Threat Activity Heatmap</h3>
            <p className="text-xs text-slate-400">Detection patterns by time</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Severity Filter */}
          <div className="flex items-center gap-1 mr-2">
            <Filter className="h-4 w-4 text-slate-400" />
            {['critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                className={cn(
                  'px-2 py-0.5 text-xs rounded transition-all',
                  severityFilter === sev
                    ? sev === 'critical'
                      ? 'bg-red-500/30 text-red-300 ring-1 ring-red-500/50'
                      : sev === 'high'
                      ? 'bg-orange-500/30 text-orange-300 ring-1 ring-orange-500/50'
                      : sev === 'medium'
                      ? 'bg-yellow-500/30 text-yellow-300 ring-1 ring-yellow-500/50'
                      : 'bg-blue-500/30 text-blue-300 ring-1 ring-blue-500/50'
                    : 'text-slate-400 hover:text-slate-300'
                )}
                onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
              >
                {safeCapitalize(sev)}
              </button>
            ))}
          </div>

          {/* Time Range Selector */}
          <Select
            value={timeRange}
            onValueChange={(value) => onTimeRangeChange?.(value)}
            className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            {timeRangeOptions.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </Select>
        </div>
      </div>

      {/* Stats Bar */}
      {showStats && data && (
        <div className="flex items-center gap-6 px-4 py-3 bg-slate-900/50 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <span className="text-sm text-slate-400">Total:</span>
            <span className="font-semibold text-white">{data.totalThreats.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-primary-400" />
            <span className="text-sm text-slate-400">Peak:</span>
            <span className="font-semibold text-white">
              {DAYS[data.peakDay]} {formatHour(data.peakHour)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <TrendingUp
              className={cn(
                'h-4 w-4',
                data.trend === 'up' ? 'text-red-400' : data.trend === 'down' ? 'text-green-400' : 'text-slate-400'
              )}
            />
            <span className="text-sm text-slate-400">Trend:</span>
            <span
              className={cn(
                'font-semibold',
                data.trend === 'up' ? 'text-red-400' : data.trend === 'down' ? 'text-green-400' : 'text-slate-400'
              )}
            >
              {data.trend === 'up' ? '+' : data.trend === 'down' ? '-' : ''}{data.trendPercent}%
            </span>
          </div>
        </div>
      )}

      {/* Heatmap Grid */}
      <div className="p-4 overflow-x-auto">
        <div className="inline-block">
          {/* Hour labels */}
          <div className="flex ml-12 mb-1">
            {HOURS.filter((h) => h % 3 === 0).map((hour) => (
              <div
                key={hour}
                className="text-xs text-slate-500 text-center"
                style={{ width: '60px', marginLeft: hour === 0 ? 0 : '0px' }}
              >
                {formatHour(hour)}
              </div>
            ))}
          </div>

          {/* Grid rows */}
          <div className="space-y-1">
            {cellGrid.map((row, dayIndex) => (
              <div key={dayIndex} className="flex items-center gap-1">
                {/* Day label */}
                <div className="w-10 text-xs text-slate-500 text-right pr-2">
                  {DAYS[dayIndex]}
                </div>

                {/* Cells */}
                <div className="flex gap-0.5">
                  {row.map((cell, hourIndex) => (
                    <HeatmapCellComponent
                      key={`${dayIndex}-${hourIndex}`}
                      cell={cell}
                      maxCount={filteredMaxCount}
                      onClick={() => onCellClick?.(cell)}
                      isHovered={hoveredCell?.day === dayIndex && hoveredCell?.hour === hourIndex}
                      onHover={(isHovered) => setHoveredCell(isHovered ? cell : null)}
                      animated={animated}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Legend */}
      {showLegend && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700 bg-slate-900/30">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Less</span>
            <div className="flex gap-0.5">
              {[0, 0.25, 0.5, 0.75, 1].map((intensity, i) => (
                <div
                  key={i}
                  className="w-4 h-4 rounded-sm"
                  style={{
                    backgroundColor: `rgba(99, 102, 241, ${0.2 + intensity * 0.8})`,
                  }}
                />
              ))}
            </div>
            <span>More</span>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm bg-red-500" />
              <span className="text-slate-400">Critical</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm bg-orange-500" />
              <span className="text-slate-400">High</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm bg-yellow-500" />
              <span className="text-slate-400">Medium</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm bg-blue-500" />
              <span className="text-slate-400">Low</span>
            </div>
          </div>
        </div>
      )}

      {/* Tooltip */}
      {hoveredCell && hoveredCell.count > 0 && (
        <Tooltip cell={hoveredCell} position={tooltipPosition} />
      )}

      {/* CSS for subtle pulse animation */}
      <style>{`
        @keyframes pulse-subtle {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
        .animate-pulse-subtle {
          animation: pulse-subtle 3s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}

// ============================================================================
// Hook for fetching heatmap data
// ============================================================================

export function useThreatHeatmap(timeRange: string = '7d') {
  const [data, setData] = useState<ThreatHeatmapData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/analytics/heatmap?range=${timeRange}`)
      if (!response.ok) throw new Error('Failed to fetch heatmap data')
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

export default ThreatHeatmap
