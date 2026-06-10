/**
 * ThreatMap Component
 *
 * A geographic visualization of threat origins and agent locations.
 * Uses SVG-based world map with animated threat flows.
 *
 * Features:
 * - World map with country boundaries
 * - Animated lines from threat source to target
 * - Agent markers with status colors
 * - Heatmap overlay for threat density
 * - Tooltip on hover
 * - Click to filter by country
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { cn } from '@/lib/utils'
import {
  Globe,
  Activity,
  AlertTriangle,
  Server,
  RefreshCw,
  Filter,
  ChevronDown,
  MapPin,
  Crosshair,
  Clock,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface ThreatOrigin {
  source_lat: number
  source_lon: number
  source_country: string
  source_country_name: string
  threat_type: string
  count: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  last_seen?: string
}

export interface AgentLocation {
  agent_id: string
  lat: number
  lon: number
  hostname: string
  status: 'online' | 'offline' | 'isolated'
  country_code?: string
  city?: string
  os_type?: string
  last_seen?: string
}

export interface ThreatFlow {
  id: string
  source: {
    lat: number
    lon: number
    country: string
  }
  target: {
    lat: number
    lon: number
    hostname: string
  }
  threat_type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
}

export interface ThreatMapSummary {
  top_countries: Array<{
    country_code: string
    country_name: string
    threat_count: number
    threat_types: string[]
  }>
  total_threats: number
  unique_sources: number
  unique_threat_types: number
  agents_online: number
  agents_total: number
  severity_counts: Record<string, number>
  timeframe: string
}

export interface ThreatMapProps {
  threats?: ThreatOrigin[]
  agents?: AgentLocation[]
  flows?: ThreatFlow[]
  summary?: ThreatMapSummary
  onCountryClick?: (countryCode: string) => void
  onAgentClick?: (agentId: string) => void
  onRefresh?: () => void
  isLoading?: boolean
  className?: string
  timeframe?: string
  onTimeframeChange?: (timeframe: string) => void
}

// ============================================================================
// Map Projection Utilities
// ============================================================================

// Mercator projection bounds
const MAP_WIDTH = 800
const MAP_HEIGHT = 450
const MAP_PADDING = 20

// Convert lat/lon to SVG coordinates using Mercator projection
function latLonToSvg(lat: number, lon: number): { x: number; y: number } {
  // Clamp latitude to avoid infinity at poles
  const clampedLat = Math.max(-85, Math.min(85, lat))

  // Mercator projection
  const x = ((lon + 180) / 360) * (MAP_WIDTH - 2 * MAP_PADDING) + MAP_PADDING
  const latRad = (clampedLat * Math.PI) / 180
  const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2))
  const y = MAP_HEIGHT / 2 - (MAP_WIDTH / (2 * Math.PI)) * mercN

  return { x, y: Math.max(MAP_PADDING, Math.min(MAP_HEIGHT - MAP_PADDING, y)) }
}

// ============================================================================
// Simplified World Map Path (110m resolution equivalent)
// ============================================================================

const WORLD_MAP_PATH = `
M 400,225
m -350,0
a 350,200 0 1,0 700,0
a 350,200 0 1,0 -700,0
`

// Simplified continent outlines for better visualization
const CONTINENTS = {
  northAmerica: `M 50,80 L 120,60 L 200,70 L 230,120 L 210,180 L 180,200 L 120,210 L 80,180 L 50,120 Z`,
  southAmerica: `M 150,220 L 190,240 L 210,300 L 180,380 L 140,400 L 130,350 L 140,280 Z`,
  europe: `M 400,70 L 480,60 L 520,80 L 530,130 L 490,140 L 440,130 L 400,110 Z`,
  africa: `M 400,150 L 470,160 L 500,220 L 490,320 L 440,360 L 390,320 L 380,240 L 390,180 Z`,
  asia: `M 530,60 L 750,50 L 780,120 L 760,200 L 700,220 L 600,210 L 550,180 L 530,120 Z`,
  oceania: `M 680,280 L 750,260 L 780,300 L 770,350 L 720,380 L 680,340 Z`,
}

// Country approximate centroids for marker placement
const COUNTRY_MARKERS: Record<string, { lat: number; lon: number }> = {
  US: { lat: 37.0902, lon: -95.7129 },
  CN: { lat: 35.8617, lon: 104.1954 },
  RU: { lat: 61.5240, lon: 105.3188 },
  DE: { lat: 51.1657, lon: 10.4515 },
  GB: { lat: 55.3781, lon: -3.4360 },
  FR: { lat: 46.2276, lon: 2.2137 },
  JP: { lat: 36.2048, lon: 138.2529 },
  KR: { lat: 35.9078, lon: 127.7669 },
  BR: { lat: -14.2350, lon: -51.9253 },
  IN: { lat: 20.5937, lon: 78.9629 },
  AU: { lat: -25.2744, lon: 133.7751 },
  CA: { lat: 56.1304, lon: -106.3468 },
  NL: { lat: 52.1326, lon: 5.2913 },
  UA: { lat: 48.3794, lon: 31.1656 },
  IR: { lat: 32.4279, lon: 53.6880 },
  KP: { lat: 40.3399, lon: 127.5101 },
}

// ============================================================================
// Subcomponents
// ============================================================================

function SeverityDot({ severity, size = 8 }: { severity: string; size?: number }) {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  }
  return (
    <circle
      r={size}
      fill={colors[severity] || colors.low}
      opacity={0.8}
      className="animate-pulse"
    />
  )
}

function ThreatMarker({
  threat,
  onClick,
  isSelected,
}: {
  threat: ThreatOrigin
  onClick?: () => void
  isSelected?: boolean
}) {
  const { x, y } = latLonToSvg(threat.source_lat, threat.source_lon)
  const size = Math.min(20, Math.max(6, Math.log2(threat.count + 1) * 4))

  const severityColors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  }

  return (
    <g
      transform={`translate(${x}, ${y})`}
      onClick={onClick}
      className="cursor-pointer"
    >
      {/* Pulse animation ring */}
      <circle
        r={size * 1.5}
        fill="none"
        stroke={severityColors[threat.severity]}
        strokeWidth={1}
        opacity={0.3}
        className="animate-ping"
      />
      {/* Main marker */}
      <circle
        r={size}
        fill={severityColors[threat.severity]}
        opacity={isSelected ? 1 : 0.7}
        stroke={isSelected ? '#fff' : 'none'}
        strokeWidth={isSelected ? 2 : 0}
      />
      {/* Count label for larger markers */}
      {size > 10 && (
        <text
          y={1}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#fff"
          fontSize={8}
          fontWeight="bold"
        >
          {threat.count > 99 ? '99+' : threat.count}
        </text>
      )}
    </g>
  )
}

function AgentMarker({
  agent,
  onClick,
  isSelected,
}: {
  agent: AgentLocation
  onClick?: () => void
  isSelected?: boolean
}) {
  const { x, y } = latLonToSvg(agent.lat, agent.lon)

  const statusColors: Record<string, string> = {
    online: '#22c55e',
    offline: '#64748b',
    isolated: '#ef4444',
  }

  return (
    <g
      transform={`translate(${x}, ${y})`}
      onClick={onClick}
      className="cursor-pointer"
    >
      {/* Agent marker (shield shape) */}
      <path
        d="M 0,-8 L 6,-4 L 6,4 L 0,8 L -6,4 L -6,-4 Z"
        fill={statusColors[agent.status]}
        opacity={isSelected ? 1 : 0.8}
        stroke={isSelected ? '#fff' : '#1e293b'}
        strokeWidth={isSelected ? 2 : 1}
      />
      {/* Status indicator dot */}
      {agent.status === 'online' && (
        <circle
          cy={-4}
          r={2}
          fill="#fff"
          className="animate-pulse"
        />
      )}
    </g>
  )
}

function AnimatedFlowLine({
  flow,
  index,
}: {
  flow: ThreatFlow
  index: number
}) {
  const source = latLonToSvg(flow.source.lat, flow.source.lon)
  const target = latLonToSvg(flow.target.lat, flow.target.lon)

  // Calculate control point for curved line
  const midX = (source.x + target.x) / 2
  const midY = (source.y + target.y) / 2 - 30 // Curve upward

  const severityColors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  }

  const pathD = `M ${source.x},${source.y} Q ${midX},${midY} ${target.x},${target.y}`

  return (
    <g>
      {/* Shadow/glow effect */}
      <path
        d={pathD}
        fill="none"
        stroke={severityColors[flow.severity]}
        strokeWidth={3}
        opacity={0.2}
        strokeLinecap="round"
      />
      {/* Main line */}
      <path
        d={pathD}
        fill="none"
        stroke={severityColors[flow.severity]}
        strokeWidth={1.5}
        opacity={0.6}
        strokeLinecap="round"
        strokeDasharray="8,4"
        className="animate-dash"
        style={{
          animationDelay: `${index * 200}ms`,
        }}
      />
      {/* Animated particle along path */}
      <circle r={3} fill={severityColors[flow.severity]}>
        <animateMotion
          dur={`${2 + index * 0.3}s`}
          repeatCount="indefinite"
          path={pathD}
        />
      </circle>
    </g>
  )
}

function Tooltip({
  content,
  x,
  y,
}: {
  content: React.ReactNode
  x: number
  y: number
}) {
  return (
    <div
      className="absolute z-50 pointer-events-none"
      style={{
        left: x,
        top: y,
        transform: 'translate(-50%, -100%) translateY(-10px)',
      }}
    >
      <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm min-w-48">
        {content}
      </div>
      {/* Arrow */}
      <div className="absolute left-1/2 -translate-x-1/2 -bottom-1.5 w-3 h-3 bg-slate-800 border-b border-r border-slate-700 rotate-45" />
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatMap({
  threats = [],
  agents = [],
  flows = [],
  summary,
  onCountryClick,
  onAgentClick,
  onRefresh,
  isLoading = false,
  className,
  timeframe = '24h',
  onTimeframeChange,
}: ThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [hoveredThreat, setHoveredThreat] = useState<ThreatOrigin | null>(null)
  const [hoveredAgent, setHoveredAgent] = useState<AgentLocation | null>(null)
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null)
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
  const [showFilters, setShowFilters] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string[]>(['critical', 'high', 'medium', 'low'])

  // Track mouse position for tooltips
  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect()
      setMousePos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      })
    }
  }, [])

  // Filter threats by severity
  const filteredThreats = useMemo(() => {
    return (threats || []).filter(t => severityFilter.includes(t.severity))
  }, [threats, severityFilter])

  // Filter flows by severity
  const filteredFlows = useMemo(() => {
    return (flows || []).filter(f => severityFilter.includes(f.severity))
  }, [flows, severityFilter])

  // Handle country click
  const handleCountryClick = useCallback((countryCode: string) => {
    setSelectedCountry(prev => prev === countryCode ? null : countryCode)
    onCountryClick?.(countryCode)
  }, [onCountryClick])

  // Timeframe options
  const timeframeOptions = [
    { value: '1h', label: 'Last Hour' },
    { value: '6h', label: 'Last 6 Hours' },
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
  ]

  return (
    <div
      ref={containerRef}
      className={cn('relative bg-slate-900 rounded-lg overflow-hidden', className)}
      onMouseMove={handleMouseMove}
    >
      {/* Header with controls */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between p-3 bg-gradient-to-b from-slate-900/90 to-transparent">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-primary-400" />
          <span className="font-semibold text-white">Threat Map</span>
          {summary && (
            <span className="text-xs text-slate-400 ml-2">
              {summary.total_threats} threats from {summary.unique_sources} sources
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Timeframe selector */}
          <div className="relative">
            <button
              className="flex items-center gap-1.5 px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded border border-slate-700 hover:bg-slate-700"
              onClick={() => setShowFilters(!showFilters)}
            >
              <Clock className="h-3.5 w-3.5" />
              {timeframeOptions.find(o => o.value === timeframe)?.label || timeframe}
              <ChevronDown className="h-3 w-3" />
            </button>

            {showFilters && (
              <div className="absolute right-0 mt-1 w-40 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-20">
                {timeframeOptions.map(option => (
                  <button
                    key={option.value}
                    className={cn(
                      'w-full px-3 py-1.5 text-xs text-left hover:bg-slate-700',
                      timeframe === option.value && 'bg-primary-600/20 text-primary-400'
                    )}
                    onClick={() => {
                      onTimeframeChange?.(option.value)
                      setShowFilters(false)
                    }}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Severity filters */}
          <div className="flex items-center gap-1">
            {['critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                className={cn(
                  'w-3 h-3 rounded-full border-2 transition-all',
                  severityFilter.includes(sev) ? 'opacity-100 scale-100' : 'opacity-30 scale-75',
                  sev === 'critical' && 'bg-red-500 border-red-400',
                  sev === 'high' && 'bg-orange-500 border-orange-400',
                  sev === 'medium' && 'bg-yellow-500 border-yellow-400',
                  sev === 'low' && 'bg-blue-500 border-blue-400'
                )}
                onClick={() => {
                  setSeverityFilter(prev =>
                    prev.includes(sev)
                      ? prev.filter(s => s !== sev)
                      : [...prev, sev]
                  )
                }}
                title={`Toggle ${sev} severity`}
              />
            ))}
          </div>

          {/* Refresh button */}
          <button
            className={cn(
              'p-1.5 text-slate-400 hover:text-white rounded transition-colors',
              isLoading && 'animate-spin'
            )}
            onClick={onRefresh}
            disabled={isLoading}
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Map SVG */}
      <svg
        viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
        className="w-full h-full"
        style={{ minHeight: '300px' }}
      >
        {/* Background gradient */}
        <defs>
          <linearGradient id="mapGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="100%" stopColor="#1e293b" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Animated dash pattern */}
          <style>
            {`
              @keyframes dash {
                to {
                  stroke-dashoffset: -24;
                }
              }
              .animate-dash {
                animation: dash 1s linear infinite;
              }
            `}
          </style>
        </defs>

        {/* Background */}
        <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#mapGradient)" />

        {/* Grid lines (graticule) */}
        <g stroke="#334155" strokeWidth={0.5} opacity={0.3}>
          {/* Longitude lines */}
          {[-180, -120, -60, 0, 60, 120, 180].map(lon => {
            const { x: x1 } = latLonToSvg(85, lon)
            const { x: x2 } = latLonToSvg(-85, lon)
            return (
              <line
                key={`lon-${lon}`}
                x1={x1}
                y1={MAP_PADDING}
                x2={x2}
                y2={MAP_HEIGHT - MAP_PADDING}
              />
            )
          })}
          {/* Latitude lines */}
          {[-60, -30, 0, 30, 60].map(lat => {
            const { y } = latLonToSvg(lat, 0)
            return (
              <line
                key={`lat-${lat}`}
                x1={MAP_PADDING}
                y1={y}
                x2={MAP_WIDTH - MAP_PADDING}
                y2={y}
              />
            )
          })}
        </g>

        {/* Continent outlines */}
        <g fill="#1e3a5f" stroke="#2563eb" strokeWidth={0.5} opacity={0.4}>
          {Object.values(CONTINENTS).map((path, i) => (
            <path key={i} d={path} />
          ))}
        </g>

        {/* Threat flow lines */}
        <g filter="url(#glow)">
          {filteredFlows.map((flow, index) => (
            <AnimatedFlowLine key={flow.id} flow={flow} index={index} />
          ))}
        </g>

        {/* Threat markers */}
        <g>
          {filteredThreats.map((threat, index) => (
            <ThreatMarker
              key={`${threat.source_country}-${threat.threat_type}-${index}`}
              threat={threat}
              isSelected={selectedCountry === threat.source_country}
              onClick={() => {
                handleCountryClick(threat.source_country)
                setHoveredThreat(threat)
              }}
            />
          ))}
        </g>

        {/* Agent markers */}
        <g>
          {agents.map((agent) => (
            <AgentMarker
              key={agent.agent_id}
              agent={agent}
              onClick={() => onAgentClick?.(agent.agent_id)}
            />
          ))}
        </g>

        {/* Loading overlay */}
        {isLoading && (
          <rect
            width={MAP_WIDTH}
            height={MAP_HEIGHT}
            fill="rgba(0,0,0,0.5)"
          />
        )}
      </svg>

      {/* Tooltip for threats */}
      {hoveredThreat && (
        <Tooltip x={mousePos.x} y={mousePos.y} content={
          <div>
            <div className="flex items-center gap-2 mb-2">
              <MapPin className="h-4 w-4 text-red-400" />
              <span className="font-semibold text-white">
                {hoveredThreat.source_country_name || hoveredThreat.source_country}
              </span>
            </div>
            <div className="space-y-1 text-slate-300">
              <div className="flex justify-between">
                <span>Threat Type:</span>
                <span className="text-white">{hoveredThreat.threat_type}</span>
              </div>
              <div className="flex justify-between">
                <span>Count:</span>
                <span className="text-white">{hoveredThreat.count}</span>
              </div>
              <div className="flex justify-between">
                <span>Severity:</span>
                <span className={cn(
                  'capitalize font-medium',
                  hoveredThreat.severity === 'critical' && 'text-red-400',
                  hoveredThreat.severity === 'high' && 'text-orange-400',
                  hoveredThreat.severity === 'medium' && 'text-yellow-400',
                  hoveredThreat.severity === 'low' && 'text-blue-400'
                )}>
                  {hoveredThreat.severity}
                </span>
              </div>
            </div>
          </div>
        } />
      )}

      {/* Tooltip for agents */}
      {hoveredAgent && (
        <Tooltip x={mousePos.x} y={mousePos.y} content={
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Server className="h-4 w-4 text-primary-400" />
              <span className="font-semibold text-white">{hoveredAgent.hostname}</span>
            </div>
            <div className="space-y-1 text-slate-300">
              <div className="flex justify-between">
                <span>Status:</span>
                <span className={cn(
                  'capitalize font-medium',
                  hoveredAgent.status === 'online' && 'text-green-400',
                  hoveredAgent.status === 'offline' && 'text-slate-400',
                  hoveredAgent.status === 'isolated' && 'text-red-400'
                )}>
                  {hoveredAgent.status}
                </span>
              </div>
              {hoveredAgent.city && (
                <div className="flex justify-between">
                  <span>Location:</span>
                  <span className="text-white">{hoveredAgent.city}</span>
                </div>
              )}
              {hoveredAgent.os_type && (
                <div className="flex justify-between">
                  <span>OS:</span>
                  <span className="text-white capitalize">{hoveredAgent.os_type}</span>
                </div>
              )}
            </div>
          </div>
        } />
      )}

      {/* Legend */}
      <div className="absolute bottom-3 left-3 bg-slate-800/80 backdrop-blur-sm rounded-lg p-2 text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span className="text-slate-400">Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-orange-500" />
            <span className="text-slate-400">High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
            <span className="text-slate-400">Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <svg width="12" height="12" viewBox="-6 -8 12 16">
              <path
                d="M 0,-8 L 6,-4 L 6,4 L 0,8 L -6,4 L -6,-4 Z"
                fill="#22c55e"
                stroke="#1e293b"
                strokeWidth={1}
              />
            </svg>
            <span className="text-slate-400">Agent</span>
          </div>
        </div>
      </div>

      {/* Stats panel */}
      {summary && (
        <div className="absolute bottom-3 right-3 bg-slate-800/80 backdrop-blur-sm rounded-lg p-2 text-xs">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
              <span className="text-white font-medium">{summary.severity_counts?.critical || 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-orange-400" />
              <span className="text-white font-medium">{summary.severity_counts?.high || 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Server className="h-3.5 w-3.5 text-green-400" />
              <span className="text-white font-medium">{summary.agents_online}/{summary.agents_total}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching threat map data
// ============================================================================

export interface UseThreatMapOptions {
  timeframe?: string
  autoRefresh?: boolean
  refreshInterval?: number
}

export interface UseThreatMapReturn {
  threats: ThreatOrigin[]
  agents: AgentLocation[]
  flows: ThreatFlow[]
  summary: ThreatMapSummary | null
  isLoading: boolean
  error: Error | null
  refresh: () => Promise<void>
  setTimeframe: (timeframe: string) => void
  timeframe: string
}

export function useThreatMap(options: UseThreatMapOptions = {}): UseThreatMapReturn {
  const {
    timeframe: initialTimeframe = '24h',
    autoRefresh = true,
    refreshInterval = 60000, // 1 minute
  } = options

  const [threats, setThreats] = useState<ThreatOrigin[]>([])
  const [agents, setAgents] = useState<AgentLocation[]>([])
  const [flows, setFlows] = useState<ThreatFlow[]>([])
  const [summary, setSummary] = useState<ThreatMapSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [timeframe, setTimeframe] = useState(initialTimeframe)

  const fetchData = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch(`/api/v1/geo/map?timeframe=${timeframe}`)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      const data = result.data

      setThreats(data.threats || [])
      setAgents(data.agents || [])
      setFlows(data.flows || [])
      setSummary(data.summary || null)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch threat map data'))
    } finally {
      setIsLoading(false)
    }
  }, [timeframe])

  // Initial fetch
  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return

    const interval = setInterval(fetchData, refreshInterval)
    return () => clearInterval(interval)
  }, [autoRefresh, refreshInterval, fetchData])

  return {
    threats,
    agents,
    flows,
    summary,
    isLoading,
    error,
    refresh: fetchData,
    setTimeframe,
    timeframe,
  }
}

export default ThreatMap
