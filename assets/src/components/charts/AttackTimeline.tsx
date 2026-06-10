/**
 * AttackTimeline Component
 *
 * An interactive attack timeline visualization showing security events
 * over time with zoom, pan, and drill-down capabilities.
 * Inspired by SentinelOne's timeline view and CrowdStrike's incident timeline.
 */

import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  Clock,
  ZoomIn,
  ZoomOut,
  ChevronLeft,
  ChevronRight,
  Filter,
  Play,
  Pause,
  AlertTriangle,
  Shield,
  Globe,
  FileText,
  Terminal,
  Network,
  Key,
  Maximize2,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export type TimelineEventType =
  | 'process'
  | 'file'
  | 'network'
  | 'registry'
  | 'dns'
  | 'alert'
  | 'detection'
  | 'response'

export type TimelineSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface TimelineEvent {
  id: string
  timestamp: number
  type: TimelineEventType
  severity: TimelineSeverity
  title: string
  description: string
  agentId?: string
  hostname?: string
  details?: Record<string, unknown>
  relatedEvents?: string[]
  mitreTechnique?: string
}

export interface TimelineCluster {
  startTime: number
  endTime: number
  events: TimelineEvent[]
  severity: TimelineSeverity
}

export interface AttackTimelineProps {
  events?: TimelineEvent[]
  isLoading?: boolean
  onEventClick?: (event: TimelineEvent) => void
  onTimeRangeChange?: (start: number, end: number) => void
  className?: string
  showControls?: boolean
  autoPlay?: boolean
  playbackSpeed?: number
}

// ============================================================================
// Constants
// ============================================================================

const EVENT_TYPE_CONFIG: Record<TimelineEventType, { icon: React.ElementType; color: string; bgColor: string }> = {
  process: { icon: Terminal, color: 'text-purple-400', bgColor: 'bg-purple-500/20' },
  file: { icon: FileText, color: 'text-blue-400', bgColor: 'bg-blue-500/20' },
  network: { icon: Network, color: 'text-cyan-400', bgColor: 'bg-cyan-500/20' },
  registry: { icon: Key, color: 'text-amber-400', bgColor: 'bg-amber-500/20' },
  dns: { icon: Globe, color: 'text-teal-400', bgColor: 'bg-teal-500/20' },
  alert: { icon: AlertTriangle, color: 'text-red-400', bgColor: 'bg-red-500/20' },
  detection: { icon: Shield, color: 'text-orange-400', bgColor: 'bg-orange-500/20' },
  response: { icon: Play, color: 'text-green-400', bgColor: 'bg-green-500/20' },
}

const SEVERITY_COLORS: Record<TimelineSeverity, { border: string; bg: string; text: string; glow: string }> = {
  critical: { border: 'border-red-500', bg: 'bg-red-500', text: 'text-red-400', glow: 'shadow-red-500/50' },
  high: { border: 'border-orange-500', bg: 'bg-orange-500', text: 'text-orange-400', glow: 'shadow-orange-500/50' },
  medium: { border: 'border-yellow-500', bg: 'bg-yellow-500', text: 'text-yellow-400', glow: 'shadow-yellow-500/50' },
  low: { border: 'border-blue-500', bg: 'bg-blue-500', text: 'text-blue-400', glow: 'shadow-blue-500/50' },
  info: { border: 'border-slate-500', bg: 'bg-slate-500', text: 'text-slate-400', glow: 'shadow-slate-500/50' },
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`
}

function getHighestSeverity(events: TimelineEvent[]): TimelineSeverity {
  const severityOrder: TimelineSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
  for (const severity of severityOrder) {
    if (events.some(e => e.severity === severity)) return severity
  }
  return 'info'
}

// ============================================================================
// Subcomponents
// ============================================================================

interface TimelineMarkerProps {
  event: TimelineEvent
  position: number
  isSelected: boolean
  isHovered: boolean
  onClick: () => void
  onHover: (hovered: boolean) => void
}

function TimelineMarker({
  event,
  position,
  isSelected,
  isHovered,
  onClick,
  onHover,
}: TimelineMarkerProps) {
  const config = EVENT_TYPE_CONFIG[event.type]
  const severity = SEVERITY_COLORS[event.severity]
  const Icon = config.icon

  return (
    <div
      className="absolute top-1/2 -translate-y-1/2 transition-all duration-200 cursor-pointer"
      style={{ left: `${position}%` }}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      {/* Connection line to timeline */}
      <div
        className={cn(
          'absolute left-1/2 -translate-x-1/2 w-0.5 h-4 transition-all',
          severity.bg,
          isSelected || isHovered ? 'opacity-100' : 'opacity-50'
        )}
        style={{ top: '100%' }}
      />

      {/* Event marker */}
      <div
        className={cn(
          'relative z-10 flex items-center justify-center transition-all duration-200',
          isSelected || isHovered ? 'scale-125' : 'scale-100',
          isSelected && 'ring-2 ring-white ring-offset-2 ring-offset-slate-900'
        )}
      >
        <div
          className={cn(
            'w-8 h-8 rounded-full flex items-center justify-center border-2 transition-all',
            config.bgColor,
            severity.border,
            isSelected || isHovered ? `shadow-lg ${severity.glow}` : ''
          )}
        >
          <Icon className={cn('h-4 w-4', config.color)} />
        </div>

        {/* Pulse animation for critical events */}
        {event.severity === 'critical' && (
          <div
            className={cn(
              'absolute inset-0 rounded-full animate-ping',
              severity.bg,
              'opacity-30'
            )}
          />
        )}
      </div>
    </div>
  )
}

interface EventDetailsPanelProps {
  event: TimelineEvent
  onClose: () => void
}

function EventDetailsPanel({ event, onClose }: EventDetailsPanelProps) {
  const config = EVENT_TYPE_CONFIG[event.type]
  const severity = SEVERITY_COLORS[event.severity]
  const Icon = config.icon

  return (
    <div className="absolute left-0 right-0 bottom-full mb-2 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-4 z-20 animate-fade-in">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', config.bgColor)}>
            <Icon className={cn('h-5 w-5', config.color)} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-semibold text-white">{event.title}</h4>
              <span className={cn('text-xs px-2 py-0.5 rounded-full capitalize', severity.bg, 'text-white')}>
                {event.severity}
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-0.5">{event.description}</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white transition-colors"
        >
          <Maximize2 className="h-4 w-4" />
        </button>
      </div>

      <div className="mt-4 pt-4 border-t border-slate-700 grid grid-cols-3 gap-4 text-sm">
        <div>
          <span className="text-slate-500">Time</span>
          <p className="text-white font-mono">{formatTimestamp(event.timestamp)}</p>
        </div>
        <div>
          <span className="text-slate-500">Type</span>
          <p className="text-white capitalize">{event.type}</p>
        </div>
        {event.hostname && (
          <div>
            <span className="text-slate-500">Host</span>
            <p className="text-white">{event.hostname}</p>
          </div>
        )}
        {event.mitreTechnique && (
          <div>
            <span className="text-slate-500">MITRE ATT&CK</span>
            <p className="text-primary-400 font-mono">{event.mitreTechnique}</p>
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function AttackTimeline({
  events = [],
  isLoading = false,
  onEventClick,
  onTimeRangeChange,
  className,
  showControls = true,
  autoPlay = false,
  playbackSpeed = 1,
}: AttackTimelineProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null)
  const [hoveredEvent, setHoveredEvent] = useState<TimelineEvent | null>(null)
  const [zoomLevel, setZoomLevel] = useState(1)
  const [panOffset, setPanOffset] = useState(0)
  const [isPlaying, setIsPlaying] = useState(autoPlay)
  const [playbackPosition, setPlaybackPosition] = useState(0)
  const [typeFilter, setTypeFilter] = useState<TimelineEventType[]>([])
  const [severityFilter, setSeverityFilter] = useState<TimelineSeverity[]>([])

  // Calculate time range
  const timeRange = useMemo(() => {
    if (events.length === 0) return { start: Date.now() - 86400000, end: Date.now() }
    const timestamps = events.map(e => e.timestamp)
    return {
      start: Math.min(...timestamps),
      end: Math.max(...timestamps),
    }
  }, [events])

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      if (typeFilter.length > 0 && !typeFilter.includes(e.type)) return false
      if (severityFilter.length > 0 && !severityFilter.includes(e.severity)) return false
      return true
    })
  }, [events, typeFilter, severityFilter])

  // Calculate event positions
  const eventPositions = useMemo(() => {
    const duration = timeRange.end - timeRange.start
    if (duration === 0) return new Map<string, number>()

    const positions = new Map<string, number>()
    filteredEvents.forEach(event => {
      const position = ((event.timestamp - timeRange.start) / duration) * 100
      positions.set(event.id, position)
    })
    return positions
  }, [filteredEvents, timeRange])

  // Handle zoom
  const handleZoom = useCallback((direction: 'in' | 'out') => {
    setZoomLevel(prev => {
      const newZoom = direction === 'in' ? prev * 1.5 : prev / 1.5
      return Math.max(1, Math.min(10, newZoom))
    })
  }, [])

  // Handle pan
  const handlePan = useCallback((direction: 'left' | 'right') => {
    const step = 10 / zoomLevel
    setPanOffset(prev => {
      const newOffset = direction === 'left' ? prev - step : prev + step
      return Math.max(0, Math.min(100 - 100 / zoomLevel, newOffset))
    })
  }, [zoomLevel])

  // Playback animation
  useEffect(() => {
    if (!isPlaying || filteredEvents.length === 0) return

    const duration = timeRange.end - timeRange.start
    const interval = setInterval(() => {
      setPlaybackPosition(prev => {
        const next = prev + (playbackSpeed * 100) / 60 // Complete in ~60 frames at speed 1
        if (next >= 100) {
          setIsPlaying(false)
          return 100
        }
        return next
      })
    }, 50)

    return () => clearInterval(interval)
  }, [isPlaying, playbackSpeed, filteredEvents.length, timeRange])

  // Generate time markers
  const timeMarkers = useMemo(() => {
    const markers: { position: number; label: string }[] = []
    const duration = timeRange.end - timeRange.start
    const interval = duration / 5

    for (let i = 0; i <= 5; i++) {
      const time = timeRange.start + interval * i
      markers.push({
        position: (i / 5) * 100,
        label: formatTimestamp(time),
      })
    }

    return markers
  }, [timeRange])

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/4" />
          <div className="h-32 bg-slate-700 rounded" />
        </div>
      </div>
    )
  }

  if (!events || events.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Clock className="h-5 w-5 text-primary-400" />
          </div>
          <h3 className="font-semibold text-white">Attack Timeline</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Clock className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No timeline events</p>
          <p className="text-slate-500 text-xs mt-1">Events will appear here as attacks are detected</p>
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
            <Clock className="h-5 w-5 text-primary-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Attack Timeline</h3>
            <p className="text-xs text-slate-400">
              {filteredEvents.length} events over {formatDuration(timeRange.end - timeRange.start)}
            </p>
          </div>
        </div>

        {showControls && (
          <div className="flex items-center gap-2">
            {/* Type Filter */}
            <div className="flex items-center gap-1">
              {Object.entries(EVENT_TYPE_CONFIG).slice(0, 4).map(([type, config]) => {
                const Icon = config.icon
                const isActive = typeFilter.length === 0 || typeFilter.includes(type as TimelineEventType)
                return (
                  <button
                    key={type}
                    className={cn(
                      'p-1.5 rounded transition-all',
                      isActive ? config.bgColor : 'opacity-30 hover:opacity-60'
                    )}
                    onClick={() => {
                      setTypeFilter(prev =>
                        prev.includes(type as TimelineEventType)
                          ? prev.filter(t => t !== type)
                          : [...prev, type as TimelineEventType]
                      )
                    }}
                    title={type}
                  >
                    <Icon className={cn('h-4 w-4', config.color)} />
                  </button>
                )
              })}
            </div>

            <div className="w-px h-6 bg-slate-700" />

            {/* Playback Controls */}
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className={cn(
                'p-1.5 rounded transition-colors',
                isPlaying ? 'bg-primary-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              )}
            >
              {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </button>

            <div className="w-px h-6 bg-slate-700" />

            {/* Zoom Controls */}
            <button
              onClick={() => handleZoom('out')}
              disabled={zoomLevel <= 1}
              className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ZoomOut className="h-4 w-4" />
            </button>
            <span className="text-xs text-slate-400 w-12 text-center">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => handleZoom('in')}
              disabled={zoomLevel >= 10}
              className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ZoomIn className="h-4 w-4" />
            </button>

            {/* Pan Controls */}
            <button
              onClick={() => handlePan('left')}
              disabled={panOffset <= 0}
              className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => handlePan('right')}
              disabled={panOffset >= 100 - 100 / zoomLevel}
              className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>

      {/* Timeline Container */}
      <div ref={containerRef} className="relative p-4 overflow-hidden">
        {/* Event Details Panel */}
        {selectedEvent && (
          <EventDetailsPanel
            event={selectedEvent}
            onClose={() => setSelectedEvent(null)}
          />
        )}

        {/* Timeline Track */}
        <div
          className="relative h-24"
          style={{
            width: `${100 * zoomLevel}%`,
            transform: `translateX(-${panOffset}%)`,
            transition: 'transform 0.2s ease-out',
          }}
        >
          {/* Background track */}
          <div className="absolute top-1/2 left-0 right-0 h-1 bg-slate-700 rounded-full" />

          {/* Playback progress */}
          {isPlaying && (
            <div
              className="absolute top-1/2 left-0 h-1 bg-primary-500 rounded-full transition-all"
              style={{ width: `${playbackPosition}%` }}
            />
          )}

          {/* Time markers */}
          {timeMarkers.map((marker, idx) => (
            <div
              key={idx}
              className="absolute bottom-0 transform -translate-x-1/2"
              style={{ left: `${marker.position}%` }}
            >
              <div className="w-px h-3 bg-slate-600 mb-1" />
              <span className="text-xs text-slate-500 whitespace-nowrap">
                {marker.label}
              </span>
            </div>
          ))}

          {/* Event markers */}
          {filteredEvents.map(event => {
            const position = eventPositions.get(event.id) || 0
            const isVisible = !isPlaying || position <= playbackPosition

            return isVisible ? (
              <TimelineMarker
                key={event.id}
                event={event}
                position={position}
                isSelected={selectedEvent?.id === event.id}
                isHovered={hoveredEvent?.id === event.id}
                onClick={() => {
                  setSelectedEvent(event)
                  onEventClick?.(event)
                }}
                onHover={(hovered) => setHoveredEvent(hovered ? event : null)}
              />
            ) : null
          })}

          {/* Playback cursor */}
          {isPlaying && (
            <div
              className="absolute top-0 bottom-0 w-0.5 bg-primary-400 z-30"
              style={{
                left: `${playbackPosition}%`,
                boxShadow: '0 0 10px rgba(99, 102, 241, 0.5)',
              }}
            >
              <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-3 bg-primary-400 rounded-full" />
            </div>
          )}
        </div>
      </div>

      {/* Event Summary */}
      <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700 bg-slate-900/30">
        <div className="flex items-center gap-4 text-xs">
          {(['critical', 'high', 'medium', 'low'] as TimelineSeverity[]).map(severity => {
            const count = filteredEvents.filter(e => e.severity === severity).length
            const colors = SEVERITY_COLORS[severity]
            return count > 0 ? (
              <div key={severity} className="flex items-center gap-1.5">
                <div className={cn('w-2.5 h-2.5 rounded-full', colors.bg)} />
                <span className={colors.text}>{count} {severity}</span>
              </div>
            ) : null
          })}
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>
            {formatTimestamp(timeRange.start)} - {formatTimestamp(timeRange.end)}
          </span>
        </div>
      </div>

      {/* CSS for fade-in animation */}
      <style>{`
        @keyframes fade-in {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
          animation: fade-in 0.2s ease-out;
        }
      `}</style>
    </div>
  )
}

// ============================================================================
// Hook for fetching timeline data
// ============================================================================

export function useAttackTimeline(timeWindow: number = 86400000) {
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/analytics/timeline?window=${timeWindow}`)
      if (!response.ok) throw new Error('Failed to fetch timeline data')
      const result = await response.json()
      setEvents(result.data)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Unknown error'))
    } finally {
      setIsLoading(false)
    }
  }, [timeWindow])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return {
    events,
    isLoading,
    error,
    refresh: fetchData,
  }
}

export default AttackTimeline
