/**
 * GeoThreatMap Component
 *
 * An enhanced world map visualization with animated attack flows,
 * threat hotspots, and geographic threat intelligence. This is an
 * upgraded version with additional animations and features.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { cn } from '@/lib/utils'
import {
  Globe,
  Activity,
  AlertTriangle,
  Server,
  RefreshCw,
  Clock,
  ChevronDown,
  Target,
  Zap,
  Shield,
} from 'lucide-react'
import { getWorldMapPaths } from './worldMapData'

// ============================================================================
// Types
// ============================================================================

export interface ThreatOrigin {
  id: string
  lat: number
  lon: number
  country: string
  countryName: string
  city?: string
  threatType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  lastSeen: number
  attackTypes?: string[]
}

export interface AgentLocation {
  id: string
  lat: number
  lon: number
  hostname: string
  status: 'online' | 'offline' | 'isolated'
  country?: string
  city?: string
  osType?: string
  alertCount?: number
}

export interface AttackFlow {
  id: string
  source: { lat: number; lon: number; label: string }
  target: { lat: number; lon: number; label: string }
  threatType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  active: boolean
}

export interface GeoMapSummary {
  totalThreats: number
  uniqueSources: number
  topCountries: Array<{
    country: string
    countryName: string
    count: number
    severity: string
  }>
  severityCounts: Record<string, number>
  activeFlows: number
}

export interface GeoThreatMapProps {
  threats?: ThreatOrigin[]
  agents?: AgentLocation[]
  flows?: AttackFlow[]
  summary?: GeoMapSummary
  isLoading?: boolean
  onThreatClick?: (threat: ThreatOrigin) => void
  onAgentClick?: (agent: AgentLocation) => void
  onRefresh?: () => void
  timeframe?: string
  onTimeframeChange?: (timeframe: string) => void
  className?: string
  showStats?: boolean
  showLegend?: boolean
  animated?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const MAP_WIDTH = 1000
const MAP_HEIGHT = 500
const MAP_PADDING = 30

const SEVERITY_COLORS = {
  critical: { fill: 'var(--crit)', glow: 'var(--crit-bg)', pulse: true },
  high: { fill: 'var(--high)', glow: 'var(--high-bg)', pulse: true },
  medium: { fill: 'var(--med)', glow: 'var(--med-bg)', pulse: false },
  low: { fill: 'var(--low)', glow: 'var(--low-bg)', pulse: false },
}

const AGENT_STATUS_COLORS = {
  online: 'var(--emerald-400)',
  offline: 'var(--dim)',
  isolated: 'var(--crit)',
}

// World map paths computed from real lat/lon coordinates via Mercator projection
const WORLD_PATHS = getWorldMapPaths(MAP_WIDTH, MAP_HEIGHT, MAP_PADDING, 0.5)

// ============================================================================
// Utility Functions
// ============================================================================

function latLonToSvg(lat: number, lon: number): { x: number; y: number } {
  const clampedLat = Math.max(-85, Math.min(85, lat))

  const x = ((lon + 180) / 360) * (MAP_WIDTH - 2 * MAP_PADDING) + MAP_PADDING
  const latRad = (clampedLat * Math.PI) / 180
  const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2))
  const y = MAP_HEIGHT / 2 - (MAP_WIDTH / (2 * Math.PI)) * mercN * 0.5

  return {
    x: Math.max(MAP_PADDING, Math.min(MAP_WIDTH - MAP_PADDING, x)),
    y: Math.max(MAP_PADDING, Math.min(MAP_HEIGHT - MAP_PADDING, y)),
  }
}

// ============================================================================
// Subcomponents
// ============================================================================

interface ThreatMarkerProps {
  threat: ThreatOrigin
  isSelected: boolean
  isHovered: boolean
  onClick: () => void
  onHover: (hovered: boolean) => void
  animated: boolean
}

function ThreatMarker({
  threat,
  isSelected,
  isHovered,
  onClick,
  onHover,
  animated,
}: ThreatMarkerProps) {
  const { x, y } = latLonToSvg(threat.lat, threat.lon)
  const config = SEVERITY_COLORS[threat.severity]
  const size = Math.max(8, Math.min(24, Math.log2(threat.count + 1) * 5))

  return (
    <g
      transform={`translate(${x}, ${y})`}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      className="cursor-pointer"
    >
      {/* Outer pulse ring */}
      {animated && config.pulse && (
        <circle
          r={size * 2}
          fill="none"
          stroke={config.fill}
          strokeWidth={2}
          opacity={0.3}
          className="animate-ping"
        />
      )}

      {/* Glow effect */}
      <circle
        r={size * 1.5}
        fill={config.glow}
        opacity={isSelected || isHovered ? 0.6 : 0.3}
        className="transition-all duration-200"
      />

      {/* Main marker */}
      <circle
        r={size}
        fill={config.fill}
        stroke={isSelected ? 'var(--fg)' : 'none'}
        strokeWidth={isSelected ? 2 : 0}
        opacity={isHovered || isSelected ? 1 : 0.8}
        className="transition-all duration-200"
      />

      {/* Count badge */}
      {threat.count > 1 && size > 10 && (
        <text
          textAnchor="middle"
          dominantBaseline="central"
          fill="var(--fg)"
          fontSize={10}
          fontWeight="bold"
        >
          {threat.count > 99 ? '99+' : threat.count}
        </text>
      )}

      {/* Highlight ring */}
      {(isSelected || isHovered) && (
        <circle
          r={size + 4}
          fill="none"
          stroke="var(--fg)"
          strokeWidth={2}
          opacity={0.5}
        />
      )}
    </g>
  )
}

interface AgentMarkerProps {
  agent: AgentLocation
  isSelected: boolean
  isHovered: boolean
  onClick: () => void
  onHover: (hovered: boolean) => void
}

function AgentMarker({
  agent,
  isSelected,
  isHovered,
  onClick,
  onHover,
}: AgentMarkerProps) {
  const { x, y } = latLonToSvg(agent.lat, agent.lon)
  const color = AGENT_STATUS_COLORS[agent.status]

  return (
    <g
      transform={`translate(${x}, ${y})`}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      className="cursor-pointer"
    >
      {/* Shield shape for agents */}
      <path
        d="M 0,-12 L 8,-6 L 8,6 L 0,12 L -8,6 L -8,-6 Z"
        fill={color}
        stroke={isSelected ? 'var(--fg)' : 'var(--hairline)'}
        strokeWidth={isSelected ? 2 : 1}
        opacity={isHovered || isSelected ? 1 : 0.8}
        className="transition-all duration-200"
      />

      {/* Online pulse */}
      {agent.status === 'online' && (
        <circle
          cy={-6}
          r={2}
          fill="var(--fg)"
          className="animate-pulse"
        />
      )}

      {/* Alert badge */}
      {agent.alertCount && agent.alertCount > 0 && (
        <g transform="translate(10, -10)">
          <circle r={8} fill="var(--crit)" />
          <text
            textAnchor="middle"
            dominantBaseline="central"
            fill="var(--fg)"
            fontSize={8}
            fontWeight="bold"
          >
            {agent.alertCount > 9 ? '9+' : agent.alertCount}
          </text>
        </g>
      )}
    </g>
  )
}

interface FlowLineProps {
  flow: AttackFlow
  index: number
  animated: boolean
}

function FlowLine({ flow, index, animated }: FlowLineProps) {
  const source = latLonToSvg(flow.source.lat, flow.source.lon)
  const target = latLonToSvg(flow.target.lat, flow.target.lon)
  const config = SEVERITY_COLORS[flow.severity]

  // Calculate bezier curve with arc
  const midX = (source.x + target.x) / 2
  const midY = Math.min(source.y, target.y) - 50 // Arc upward
  const pathD = `M ${source.x},${source.y} Q ${midX},${midY} ${target.x},${target.y}`

  return (
    <g>
      {/* Glow trail */}
      <path
        d={pathD}
        fill="none"
        stroke={config.glow}
        strokeWidth={4}
        opacity={0.3}
      />

      {/* Main line */}
      <path
        d={pathD}
        fill="none"
        stroke={config.fill}
        strokeWidth={2}
        strokeDasharray={flow.active ? '8,4' : 'none'}
        opacity={flow.active ? 1 : 0.5}
        className={animated && flow.active ? 'animate-dash' : ''}
        style={{ animationDelay: `${index * 0.2}s` }}
      />

      {/* Animated particle */}
      {animated && flow.active && (
        <circle r={4} fill={config.fill}>
          <animateMotion
            dur={`${1.5 + index * 0.2}s`}
            repeatCount="indefinite"
            path={pathD}
          />
        </circle>
      )}

      {/* Impact marker at target */}
      {flow.active && (
        <circle
          cx={target.x}
          cy={target.y}
          r={6}
          fill="none"
          stroke={config.fill}
          strokeWidth={2}
          className="animate-ping"
        />
      )}
    </g>
  )
}

interface TooltipProps {
  content: React.ReactNode
  x: number
  y: number
}

function Tooltip({ content, x, y }: TooltipProps) {
  return (
    <div
      className="absolute z-50 pointer-events-none"
      style={{
        left: x,
        top: y,
        transform: 'translate(-50%, -100%) translateY(-12px)',
      }}
    >
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xl p-3 text-sm min-w-56">
        {content}
      </div>
      <div className="absolute left-1/2 -translate-x-1/2 -bottom-1.5 w-3 h-3 bg-[var(--surface)] border-b border-r border-[var(--border)] rotate-45" />
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function GeoThreatMap({
  threats = [],
  agents = [],
  flows = [],
  summary,
  isLoading = false,
  onThreatClick,
  onAgentClick,
  onRefresh,
  timeframe = '24h',
  onTimeframeChange,
  className,
  showStats = true,
  showLegend = true,
  animated = true,
}: GeoThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [selectedThreat, setSelectedThreat] = useState<ThreatOrigin | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<AgentLocation | null>(null)
  const [hoveredThreat, setHoveredThreat] = useState<ThreatOrigin | null>(null)
  const [hoveredAgent, setHoveredAgent] = useState<AgentLocation | null>(null)
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
  const [showFilters, setShowFilters] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string[]>(['critical', 'high', 'medium', 'low'])

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect()
      setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top })
    }
  }, [])

  // Filter threats
  const filteredThreats = useMemo(() => {
    return (threats || []).filter(t => severityFilter.includes(t.severity))
  }, [threats, severityFilter])

  // Filter flows
  const filteredFlows = useMemo(() => {
    return (flows || []).filter(f => severityFilter.includes(f.severity))
  }, [flows, severityFilter])

  const timeframeOptions = [
    { value: '1h', label: 'Last Hour' },
    { value: '6h', label: 'Last 6 Hours' },
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
  ]

  if (isLoading) {
    return (
      <div className={cn('bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-[var(--surface-2)] rounded w-1/4" />
          <div className="h-64 bg-[var(--surface-2)] rounded" />
        </div>
      </div>
    )
  }

  if ((!threats || threats.length === 0) && (!agents || agents.length === 0)) {
    return (
      <div className={cn('bg-[var(--surface)] rounded-xl border border-[var(--border)] overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4" style={{ background: 'linear-gradient(to bottom, var(--surface), transparent)' }}>
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
            <Globe className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          </div>
          <h3 className="font-semibold text-[var(--fg)]">Global Threat Map</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Globe className="h-12 w-12 mb-3" style={{ color: 'var(--dim)' }} />
          <p className="text-[var(--muted)] text-sm">No geographic threat data available</p>
          <p className="text-[var(--subtle)] text-xs mt-1">Threat origins and agent locations will appear on the map</p>
        </div>
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className={cn('relative bg-[var(--surface)] rounded-xl border border-[var(--border)] overflow-hidden', className)}
      onMouseMove={handleMouseMove}
    >
      {/* Header */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between p-4" style={{ background: 'linear-gradient(to bottom, var(--surface), rgba(17, 24, 29, 0.92), transparent)' }}>
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)' }}>
            <Globe className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          </div>
          <div>
            <h3 className="font-semibold text-[var(--fg)]">Global Threat Map</h3>
            {summary && (
              <p className="text-xs text-[var(--muted)]">
                {summary.totalThreats} threats from {summary.uniqueSources} sources
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Severity filter pills */}
          <div className="flex items-center gap-1">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
              <button
                key={sev}
                className={cn(
                  'w-4 h-4 rounded-full border-2 transition-all',
                  severityFilter.includes(sev) ? 'opacity-100 scale-100' : 'opacity-30 scale-75'
                )}
                style={{
                  backgroundColor: SEVERITY_COLORS[sev].fill,
                  borderColor: SEVERITY_COLORS[sev].fill,
                }}
                onClick={() => {
                  setSeverityFilter(prev =>
                    prev.includes(sev)
                      ? prev.filter(s => s !== sev)
                      : [...prev, sev]
                  )
                }}
                title={`Toggle ${sev}`}
              />
            ))}
          </div>

          {/* Timeframe dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[var(--surface-2)] text-[var(--fg-2)] rounded-lg border border-[var(--border)] hover:bg-[var(--surface-3)]"
            >
              <Clock className="h-3.5 w-3.5" />
              {timeframeOptions.find(o => o.value === timeframe)?.label}
              <ChevronDown className={cn('h-3 w-3 transition-transform', showFilters && 'rotate-180')} />
            </button>

            {showFilters && (
              <div className="absolute right-0 mt-1 w-40 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xl z-20">
                {timeframeOptions.map(opt => (
                  <button
                    key={opt.value}
                    className={cn(
                      'w-full px-3 py-2 text-xs text-left text-[var(--fg-2)] hover:bg-[var(--surface-2)]',
                      timeframe === opt.value && 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]'
                    )}
                    onClick={() => {
                      onTimeframeChange?.(opt.value)
                      setShowFilters(false)
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            className="p-1.5 text-[var(--muted)] hover:text-[var(--fg)] rounded transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Map SVG */}
      <svg
        viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
        className="w-full h-full"
        style={{ minHeight: '400px' }}
      >
        {/* Definitions */}
        <defs>
          <radialGradient id="mapBgGradient" cx="50%" cy="40%" r="70%">
            <stop offset="0%" stopColor="var(--surface-2)" />
            <stop offset="60%" stopColor="var(--bg-2)" />
            <stop offset="100%" stopColor="var(--bg)" />
          </radialGradient>

          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="softGlow">
            <feGaussianBlur stdDeviation="1.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <radialGradient id="hotspotGradient">
            <stop offset="0%" stopColor="var(--crit)" stopOpacity="0.45" />
            <stop offset="50%" stopColor="var(--crit)" stopOpacity="0.14" />
            <stop offset="100%" stopColor="var(--crit)" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="oceanGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--emerald-400)" stopOpacity="0.045" />
            <stop offset="100%" stopColor="var(--emerald-400)" stopOpacity="0" />
          </radialGradient>

          {/* Animated dash pattern */}
          <style>
            {`
              @keyframes dash {
                to { stroke-dashoffset: -24; }
              }
              .animate-dash {
                animation: dash 0.8s linear infinite;
              }
              @keyframes float-particle {
                0%, 100% { opacity: 0.3; }
                50% { opacity: 0.8; }
              }
            `}
          </style>
        </defs>

        {/* Background - deep ocean */}
        <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#mapBgGradient)" />

        {/* Subtle ocean glow in center */}
        <ellipse
          cx={MAP_WIDTH / 2}
          cy={MAP_HEIGHT / 2}
          rx={MAP_WIDTH * 0.4}
          ry={MAP_HEIGHT * 0.35}
          fill="url(#oceanGlow)"
        />

        {/* Grid lines - longitude */}
        <g stroke="var(--border)" strokeWidth={0.4} opacity={0.45}>
          {[-150, -120, -90, -60, -30, 30, 60, 90, 120, 150].map(lon => {
            const { x } = latLonToSvg(0, lon)
            return <line key={`lon-${lon}`} x1={x} y1={MAP_PADDING} x2={x} y2={MAP_HEIGHT - MAP_PADDING} />
          })}
          {[-60, -45, -30, -15, 15, 30, 45, 60].map(lat => {
            const { y } = latLonToSvg(lat, 0)
            return <line key={`lat-${lat}`} x1={MAP_PADDING} y1={y} x2={MAP_WIDTH - MAP_PADDING} y2={y} />
          })}
        </g>
        {/* Equator and prime meridian */}
        <g stroke="var(--border-strong)" strokeWidth={0.8} opacity={0.45} strokeDasharray="4,4">
          <line x1={MAP_PADDING} y1={latLonToSvg(0, 0).y} x2={MAP_WIDTH - MAP_PADDING} y2={latLonToSvg(0, 0).y} />
          <line x1={latLonToSvg(0, 0).x} y1={MAP_PADDING} x2={latLonToSvg(0, 0).x} y2={MAP_HEIGHT - MAP_PADDING} />
        </g>

        {/* Continent & landmass shapes */}
        <g>
          {WORLD_PATHS.map((lm, i) => {
            const isMajor = ['North America', 'South America', 'Europe', 'Africa', 'Asia', 'Australia'].includes(lm.name)
            return (
              <path
                key={i}
                d={lm.d}
                fill={isMajor ? 'var(--surface-3)' : 'var(--surface-2)'}
                stroke="var(--emerald-700)"
                strokeWidth={isMajor ? 0.8 : 0.5}
                opacity={0.6}
                className="transition-colors duration-300"
              />
            )
          })}
        </g>

        {/* Hotspot overlays for top threat countries */}
        {summary?.topCountries?.slice(0, 8).map((country, i) => {
          const countryPositions: Record<string, { lat: number; lon: number }> = {
            CN: { lat: 35, lon: 105 }, RU: { lat: 55, lon: 100 },
            US: { lat: 38, lon: -97 }, KR: { lat: 35, lon: 127 },
            IR: { lat: 32, lon: 53 }, KP: { lat: 40, lon: 127 },
            BR: { lat: -14, lon: -51 }, IN: { lat: 20, lon: 78 },
            UA: { lat: 48, lon: 31 }, DE: { lat: 51, lon: 10 },
            GB: { lat: 54, lon: -2 }, JP: { lat: 36, lon: 138 },
            FR: { lat: 46, lon: 2 }, NL: { lat: 52, lon: 5 },
            CA: { lat: 56, lon: -106 }, AU: { lat: -25, lon: 134 },
            VN: { lat: 16, lon: 108 }, NG: { lat: 10, lon: 8 },
          }
          const pos = countryPositions[country.country]
          if (!pos) return null
          const { x, y } = latLonToSvg(pos.lat, pos.lon)
          const radius = Math.min(60, 20 + Math.sqrt(country.count) * 4)

          return (
            <circle
              key={`hotspot-${i}`}
              cx={x}
              cy={y}
              r={radius}
              fill="url(#hotspotGradient)"
              opacity={0.5}
              className="animate-pulse"
              style={{ animationDelay: `${i * 0.3}s`, animationDuration: '3s' }}
            />
          )
        })}

        {/* Attack flows */}
        <g filter="url(#glow)">
          {filteredFlows.map((flow, idx) => (
            <FlowLine
              key={flow.id}
              flow={flow}
              index={idx}
              animated={animated}
            />
          ))}
        </g>

        {/* Threat markers */}
        <g>
          {filteredThreats.map(threat => (
            <ThreatMarker
              key={threat.id}
              threat={threat}
              isSelected={selectedThreat?.id === threat.id}
              isHovered={hoveredThreat?.id === threat.id}
              onClick={() => {
                setSelectedThreat(threat)
                onThreatClick?.(threat)
              }}
              onHover={h => setHoveredThreat(h ? threat : null)}
              animated={animated}
            />
          ))}
        </g>

        {/* Agent markers */}
        <g>
          {agents.map(agent => (
            <AgentMarker
              key={agent.id}
              agent={agent}
              isSelected={selectedAgent?.id === agent.id}
              isHovered={hoveredAgent?.id === agent.id}
              onClick={() => {
                setSelectedAgent(agent)
                onAgentClick?.(agent)
              }}
              onHover={h => setHoveredAgent(h ? agent : null)}
            />
          ))}
        </g>
      </svg>

      {/* Threat tooltip */}
      {hoveredThreat && (
        <Tooltip x={mousePos.x} y={mousePos.y} content={
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Target className="h-4 w-4" style={{ color: 'var(--crit)' }} />
              <span className="font-semibold text-[var(--fg)]">
                {hoveredThreat.countryName || hoveredThreat.country}
              </span>
            </div>
            <div className="space-y-1 text-[var(--fg-2)]">
              <div className="flex justify-between gap-4">
                <span>Threat Type:</span>
                <span className="text-[var(--fg)] font-medium">{hoveredThreat.threatType}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span>Count:</span>
                <span className="text-[var(--fg)] font-semibold">{hoveredThreat.count}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span>Severity:</span>
                <span
                  className="capitalize font-medium"
                  style={{ color: SEVERITY_COLORS[hoveredThreat.severity].fill }}
                >
                  {hoveredThreat.severity}
                </span>
              </div>
            </div>
          </div>
        } />
      )}

      {/* Agent tooltip */}
      {hoveredAgent && (
        <Tooltip x={mousePos.x} y={mousePos.y} content={
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Server className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              <span className="font-semibold text-[var(--fg)]">{hoveredAgent.hostname}</span>
            </div>
            <div className="space-y-1 text-[var(--fg-2)]">
              <div className="flex justify-between gap-4">
                <span>Status:</span>
                <span
                  className="capitalize font-medium"
                  style={{ color: AGENT_STATUS_COLORS[hoveredAgent.status] }}
                >
                  {hoveredAgent.status}
                </span>
              </div>
              {hoveredAgent.city && (
                <div className="flex justify-between gap-4">
                  <span>Location:</span>
                  <span className="text-[var(--fg)]">{hoveredAgent.city}</span>
                </div>
              )}
              {hoveredAgent.osType && (
                <div className="flex justify-between gap-4">
                  <span>OS:</span>
                  <span className="text-[var(--fg)] capitalize">{hoveredAgent.osType}</span>
                </div>
              )}
            </div>
          </div>
        } />
      )}

      {/* Stats bar */}
      {showStats && summary && (
        <div className="absolute bottom-16 left-4 bg-[var(--surface)]/90 backdrop-blur-sm rounded-lg p-3 border border-[var(--border)]">
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
              <span className="text-[var(--muted)]">Critical:</span>
              <span className="font-semibold" style={{ color: 'var(--crit)' }}>{summary.severityCounts?.critical || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4" style={{ color: 'var(--high)' }} />
              <span className="text-[var(--muted)]">High:</span>
              <span className="font-semibold" style={{ color: 'var(--high)' }}>{summary.severityCounts?.high || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4" style={{ color: 'var(--sol-cyan)' }} />
              <span className="text-[var(--muted)]">Active Flows:</span>
              <span className="font-semibold" style={{ color: 'var(--sol-cyan)' }}>{summary.activeFlows}</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              <span className="text-[var(--muted)]">Agents:</span>
              <span className="font-semibold" style={{ color: 'var(--emerald-400)' }}>{agents.filter(a => a.status === 'online').length}/{agents.length}</span>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      {showLegend && (
        <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between bg-[var(--surface)]/80 backdrop-blur-sm rounded-lg px-4 py-2 border border-[var(--border)]">
          <div className="flex items-center gap-4 text-xs">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
              <div key={sev} className="flex items-center gap-1.5">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLORS[sev].fill }}
                />
                <span className="text-[var(--muted)] capitalize">{sev}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5">
              <svg width="16" height="16" viewBox="-10 -14 20 28">
                <path
                  d="M 0,-12 L 8,-6 L 8,6 L 0,12 L -8,6 L -8,-6 Z"
                  fill={AGENT_STATUS_COLORS.online}
                />
              </svg>
              <span className="text-[var(--muted)]">Agent</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-8 h-0.5 rounded" style={{ backgroundColor: SEVERITY_COLORS.critical.fill }} />
              <span className="text-[var(--muted)]">Attack Flow</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching map data
// ============================================================================

export function useGeoThreatMap(timeframe: string = '24h') {
  const [threats, setThreats] = useState<ThreatOrigin[]>([])
  const [agents, setAgents] = useState<AgentLocation[]>([])
  const [flows, setFlows] = useState<AttackFlow[]>([])
  const [summary, setSummary] = useState<GeoMapSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/geo/map?timeframe=${timeframe}`)
      if (!response.ok) throw new Error('Failed to fetch map data')
      const result = await response.json()
      setThreats(result.data.threats || [])
      setAgents(result.data.agents || [])
      setFlows(result.data.flows || [])
      setSummary(result.data.summary || null)
      setError(null)
    } catch (err) {
      setThreats([])
      setAgents([])
      setFlows([])
      setSummary(null)
      setError(err instanceof Error ? err : new Error('Unknown error'))
    } finally {
      setIsLoading(false)
    }
  }, [timeframe])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return {
    threats,
    agents,
    flows,
    summary,
    isLoading,
    error,
    refresh: fetchData,
  }
}

export default GeoThreatMap
