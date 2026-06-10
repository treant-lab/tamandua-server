/**
 * RecentIncidents Widget
 *
 * A carousel/list of recent security incidents with severity indicators,
 * timeline, and quick action capabilities.
 */

import { useState, useMemo, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  AlertTriangle,
  Shield,
  Clock,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Activity,
  Target,
  Users,
  FileText,
  ArrowUpRight,
  Circle,
  Play,
  Pause,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export type IncidentStatus = 'active' | 'investigating' | 'contained' | 'resolved'
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface Incident {
  id: string
  title: string
  description: string
  severity: IncidentSeverity
  status: IncidentStatus
  createdAt: number
  updatedAt: number
  affectedAssets: number
  affectedUsers: number
  mitreTactics: string[]
  mitreTechniques: string[]
  assignee?: string
  alertCount: number
  timeline: Array<{
    timestamp: number
    action: string
    actor?: string
  }>
}

export interface RecentIncidentsData {
  incidents: Incident[]
  totalActive: number
  totalToday: number
  averageResolutionTime: number
  lastUpdated: number
}

export interface RecentIncidentsProps {
  data?: RecentIncidentsData
  isLoading?: boolean
  onIncidentClick?: (incident: Incident) => void
  onViewAll?: () => void
  className?: string
  autoPlay?: boolean
  autoPlayInterval?: number
  showCarousel?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_CONFIG: Record<IncidentSeverity, {
  label: string
  color: string
  bgColor: string
  borderColor: string
  dotColor: string
}> = {
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bgColor: 'bg-red-500/20',
    borderColor: 'border-red-500',
    dotColor: 'bg-red-500',
  },
  high: {
    label: 'High',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/20',
    borderColor: 'border-orange-500',
    dotColor: 'bg-orange-500',
  },
  medium: {
    label: 'Medium',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/20',
    borderColor: 'border-yellow-500',
    dotColor: 'bg-yellow-500',
  },
  low: {
    label: 'Low',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/20',
    borderColor: 'border-blue-500',
    dotColor: 'bg-blue-500',
  },
}

const STATUS_CONFIG: Record<IncidentStatus, { label: string; color: string; icon: React.ElementType }> = {
  active: { label: 'Active', color: 'text-red-400', icon: Activity },
  investigating: { label: 'Investigating', color: 'text-yellow-400', icon: Target },
  contained: { label: 'Contained', color: 'text-blue-400', icon: Shield },
  resolved: { label: 'Resolved', color: 'text-green-400', icon: Shield },
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatTimeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

function formatDuration(ms: number): string {
  const hours = Math.floor(ms / 3600000)
  const minutes = Math.floor((ms % 3600000) / 60000)
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

// ============================================================================
// Subcomponents
// ============================================================================

interface IncidentCardProps {
  incident: Incident
  onClick?: () => void
  isActive: boolean
}

function IncidentCard({ incident, onClick, isActive }: IncidentCardProps) {
  const severityConfig = SEVERITY_CONFIG[incident.severity]
  const statusConfig = STATUS_CONFIG[incident.status]
  const StatusIcon = statusConfig.icon

  return (
    <div
      className={cn(
        'flex-shrink-0 w-full p-4 rounded-lg border transition-all cursor-pointer',
        isActive && incident.status === 'active' && 'animate-pulse-border',
        severityConfig.borderColor,
        'bg-slate-900/50 hover:bg-slate-800/80'
      )}
      onClick={onClick}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <div className={cn('p-1.5 rounded', severityConfig.bgColor)}>
            <AlertTriangle className={cn('h-4 w-4', severityConfig.color)} />
          </div>
          <div>
            <h4 className="font-medium text-white text-sm line-clamp-1">{incident.title}</h4>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={cn('text-xs font-medium', severityConfig.color)}>
                {severityConfig.label}
              </span>
              <span className="text-slate-600">|</span>
              <span className={cn('flex items-center gap-1 text-xs', statusConfig.color)}>
                <StatusIcon className="h-3 w-3" />
                {statusConfig.label}
              </span>
            </div>
          </div>
        </div>

        <button className="p-1 text-slate-400 hover:text-white">
          <ArrowUpRight className="h-4 w-4" />
        </button>
      </div>

      {/* Description */}
      <p className="text-xs text-slate-400 line-clamp-2 mb-3">
        {incident.description}
      </p>

      {/* Metrics */}
      <div className="flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1 text-slate-400">
          <Target className="h-3 w-3" />
          <span>{incident.affectedAssets} assets</span>
        </div>
        <div className="flex items-center gap-1 text-slate-400">
          <Users className="h-3 w-3" />
          <span>{incident.affectedUsers} users</span>
        </div>
        <div className="flex items-center gap-1 text-slate-400">
          <AlertTriangle className="h-3 w-3" />
          <span>{incident.alertCount} alerts</span>
        </div>
      </div>

      {/* MITRE Tags */}
      {incident.mitreTechniques.length > 0 && (
        <div className="flex items-center gap-1 mt-3 flex-wrap">
          {incident.mitreTechniques.slice(0, 3).map((tech, i) => (
            <span
              key={i}
              className="text-xs px-1.5 py-0.5 bg-primary-600/20 text-primary-400 rounded font-mono"
            >
              {tech}
            </span>
          ))}
          {incident.mitreTechniques.length > 3 && (
            <span className="text-xs text-slate-500">+{incident.mitreTechniques.length - 3}</span>
          )}
        </div>
      )}

      {/* Timeline preview */}
      <div className="mt-3 pt-3 border-t border-slate-700/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1 text-xs text-slate-500">
            <Clock className="h-3 w-3" />
            <span>Created {formatTimeAgo(incident.createdAt)}</span>
          </div>
          {incident.assignee && (
            <div className="text-xs text-slate-400">
              Assigned to <span className="text-white">{incident.assignee}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

interface IncidentRowProps {
  incident: Incident
  onClick?: () => void
}

function IncidentRow({ incident, onClick }: IncidentRowProps) {
  const severityConfig = SEVERITY_CONFIG[incident.severity]
  const statusConfig = STATUS_CONFIG[incident.status]

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 w-full p-3 hover:bg-slate-700/30 transition-colors rounded-lg text-left"
    >
      {/* Severity indicator */}
      <div className={cn('w-1 h-10 rounded-full', severityConfig.dotColor)} />

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-white text-sm truncate">{incident.title}</span>
          <span className={cn('text-xs px-1.5 py-0.5 rounded', severityConfig.bgColor, severityConfig.color)}>
            {severityConfig.label}
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
          <span className={statusConfig.color}>{statusConfig.label}</span>
          <span className="text-slate-600">|</span>
          <span>{incident.affectedAssets} assets</span>
          <span className="text-slate-600">|</span>
          <span>{formatTimeAgo(incident.createdAt)}</span>
        </div>
      </div>

      {/* Arrow */}
      <ExternalLink className="h-4 w-4 text-slate-500" />
    </button>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function RecentIncidents({
  data,
  isLoading = false,
  onIncidentClick,
  onViewAll,
  className,
  autoPlay = true,
  autoPlayInterval = 5000,
  showCarousel = true,
}: RecentIncidentsProps) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isPlaying, setIsPlaying] = useState(autoPlay)

  const activeIncidents = useMemo(() => {
    if (!data?.incidents) return []
    return data.incidents.filter(i => i.status !== 'resolved')
  }, [data?.incidents])

  // Auto-play carousel
  useEffect(() => {
    if (!isPlaying || !showCarousel || activeIncidents.length <= 1) return

    const interval = setInterval(() => {
      setCurrentIndex(prev => (prev + 1) % activeIncidents.length)
    }, autoPlayInterval)

    return () => clearInterval(interval)
  }, [isPlaying, showCarousel, activeIncidents.length, autoPlayInterval])

  const handlePrev = useCallback(() => {
    setCurrentIndex(prev =>
      prev === 0 ? activeIncidents.length - 1 : prev - 1
    )
  }, [activeIncidents.length])

  const handleNext = useCallback(() => {
    setCurrentIndex(prev => (prev + 1) % activeIncidents.length)
  }, [activeIncidents.length])

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

  if (!data || !data.incidents || data.incidents.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-red-600/20 rounded-lg">
            <AlertTriangle className="h-5 w-5 text-red-400" />
          </div>
          <h3 className="font-semibold text-white">Recent Incidents</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Shield className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No recent incidents</p>
          <p className="text-slate-500 text-xs mt-1">All clear for the selected time range</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-600/20 rounded-lg relative">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            {data && data.totalActive > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-[10px] text-white flex items-center justify-center font-bold">
                {data.totalActive > 9 ? '9+' : data.totalActive}
              </span>
            )}
          </div>
          <div>
            <h3 className="font-semibold text-white">Recent Incidents</h3>
            <p className="text-xs text-slate-400">
              {data?.totalActive || 0} active, {data?.totalToday || 0} today
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {showCarousel && activeIncidents.length > 1 && (
            <>
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className={cn(
                  'p-1.5 rounded transition-colors',
                  isPlaying ? 'bg-primary-600/20 text-primary-400' : 'bg-slate-700 text-slate-400'
                )}
              >
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              </button>
              <button
                onClick={handlePrev}
                className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                onClick={handleNext}
                className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </>
          )}
          <button
            onClick={onViewAll}
            className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
          >
            View All
            <ExternalLink className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      {data && (
        <div className="grid grid-cols-3 gap-4 p-4 bg-slate-900/30 border-b border-slate-700">
          <div className="text-center">
            <div className="text-xl font-bold text-red-400">{data.totalActive}</div>
            <div className="text-xs text-slate-500">Active</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold text-white">{data.totalToday}</div>
            <div className="text-xs text-slate-500">Today</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold text-green-400">
              {formatDuration(data.averageResolutionTime)}
            </div>
            <div className="text-xs text-slate-500">Avg Resolution</div>
          </div>
        </div>
      )}

      {/* Content */}
      {activeIncidents.length === 0 ? (
        <div className="p-8 text-center text-slate-500">
          <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>No active incidents</p>
        </div>
      ) : showCarousel ? (
        <div className="p-4">
          {/* Carousel */}
          <div className="relative overflow-hidden">
            <div
              className="flex transition-transform duration-300 ease-out"
              style={{ transform: `translateX(-${currentIndex * 100}%)` }}
            >
              {activeIncidents.map((incident, index) => (
                <div key={incident.id} className="w-full flex-shrink-0 px-1">
                  <IncidentCard
                    incident={incident}
                    onClick={() => onIncidentClick?.(incident)}
                    isActive={index === currentIndex}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Carousel indicators */}
          {activeIncidents.length > 1 && (
            <div className="flex items-center justify-center gap-1.5 mt-4">
              {activeIncidents.map((_, index) => (
                <button
                  key={index}
                  onClick={() => setCurrentIndex(index)}
                  className={cn(
                    'transition-all rounded-full',
                    index === currentIndex
                      ? 'w-6 h-1.5 bg-primary-500'
                      : 'w-1.5 h-1.5 bg-slate-600 hover:bg-slate-500'
                  )}
                />
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="divide-y divide-slate-700">
          {activeIncidents.slice(0, 5).map(incident => (
            <IncidentRow
              key={incident.id}
              incident={incident}
              onClick={() => onIncidentClick?.(incident)}
            />
          ))}
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

      {/* CSS for pulsing border animation */}
      <style>{`
        @keyframes pulse-border {
          0%, 100% { border-color: rgba(239, 68, 68, 0.5); }
          50% { border-color: rgba(239, 68, 68, 1); }
        }
        .animate-pulse-border {
          animation: pulse-border 2s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}

// ============================================================================
// Hook for fetching recent incidents data
// ============================================================================

export function useRecentIncidents(timeRange: string = '7d') {
  const [data, setData] = useState<RecentIncidentsData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/v1/alerts?status=open&limit=10&range=${timeRange}`)
      if (!response.ok) throw new Error('Failed to fetch recent incidents')
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
            if (parsed.props?.recentAlerts) {
              setData(parsed.props.recentAlerts)
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

export default RecentIncidents
