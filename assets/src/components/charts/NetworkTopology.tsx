/**
 * NetworkTopology Component
 *
 * An interactive network topology graph visualization showing asset
 * connections, traffic flows, and threat indicators. Uses force-directed
 * layout for organic positioning.
 */

import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { cn } from '@/lib/utils'
import {
  Network,
  Server,
  Monitor,
  Globe,
  Database,
  Cloud,
  Smartphone,
  Router,
  Shield,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Filter,
  Eye,
  EyeOff,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export type NodeType = 'server' | 'endpoint' | 'network' | 'database' | 'cloud' | 'mobile' | 'router' | 'external'
export type NodeStatus = 'healthy' | 'warning' | 'critical' | 'offline' | 'unknown'

export interface TopologyNode {
  id: string
  label: string
  type: NodeType
  status: NodeStatus
  ip?: string
  hostname?: string
  group?: string
  metadata?: Record<string, unknown>
  threatCount?: number
  x?: number
  y?: number
  vx?: number
  vy?: number
}

export interface TopologyEdge {
  id: string
  source: string
  target: string
  type: 'normal' | 'suspicious' | 'blocked' | 'encrypted'
  bandwidth?: number
  latency?: number
  protocol?: string
  port?: number
  threatIndicators?: string[]
}

export interface NetworkTopologyData {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  stats: {
    totalNodes: number
    healthyNodes: number
    warningNodes: number
    criticalNodes: number
    totalConnections: number
    suspiciousConnections: number
  }
}

export interface NetworkTopologyProps {
  data?: NetworkTopologyData
  isLoading?: boolean
  onNodeClick?: (node: TopologyNode) => void
  onEdgeClick?: (edge: TopologyEdge) => void
  className?: string
  showLegend?: boolean
  showStats?: boolean
  animated?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const NODE_TYPE_CONFIG: Record<NodeType, { icon: React.ElementType; color: string; bgColor: string }> = {
  server: { icon: Server, color: '#8b5cf6', bgColor: 'bg-purple-500/20' },
  endpoint: { icon: Monitor, color: '#3b82f6', bgColor: 'bg-blue-500/20' },
  network: { icon: Network, color: '#06b6d4', bgColor: 'bg-cyan-500/20' },
  database: { icon: Database, color: '#f59e0b', bgColor: 'bg-amber-500/20' },
  cloud: { icon: Cloud, color: '#10b981', bgColor: 'bg-emerald-500/20' },
  mobile: { icon: Smartphone, color: '#ec4899', bgColor: 'bg-pink-500/20' },
  router: { icon: Router, color: '#6366f1', bgColor: 'bg-indigo-500/20' },
  external: { icon: Globe, color: '#64748b', bgColor: 'bg-slate-500/20' },
}

const STATUS_CONFIG: Record<NodeStatus, { color: string; ring: string; pulse: boolean }> = {
  healthy: { color: '#22c55e', ring: 'ring-green-500', pulse: false },
  warning: { color: '#eab308', ring: 'ring-yellow-500', pulse: true },
  critical: { color: '#ef4444', ring: 'ring-red-500', pulse: true },
  offline: { color: '#64748b', ring: 'ring-slate-500', pulse: false },
  unknown: { color: '#94a3b8', ring: 'ring-slate-400', pulse: false },
}

const EDGE_STYLES: Record<string, { color: string; dash: string; width: number }> = {
  normal: { color: '#475569', dash: 'none', width: 1.5 },
  suspicious: { color: '#f97316', dash: '5,5', width: 2 },
  blocked: { color: '#ef4444', dash: '3,3', width: 2 },
  encrypted: { color: '#22c55e', dash: 'none', width: 2 },
}

// ============================================================================
// Force Simulation
// ============================================================================

function useForceSimulation(
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  width: number,
  height: number,
  animated: boolean
) {
  const [positions, setPositions] = useState<Map<string, { x: number; y: number }>>(new Map())
  const animationRef = useRef<number>()

  useEffect(() => {
    if (nodes.length === 0) return

    // Initialize positions
    const nodeMap = new Map<string, TopologyNode>()
    nodes.forEach(node => {
      nodeMap.set(node.id, {
        ...node,
        x: node.x ?? width / 2 + (Math.random() - 0.5) * 200,
        y: node.y ?? height / 2 + (Math.random() - 0.5) * 200,
        vx: 0,
        vy: 0,
      })
    })

    if (!animated) {
      // Simple static layout
      const newPositions = new Map<string, { x: number; y: number }>()
      const groupedNodes = new Map<string, TopologyNode[]>()

      // Group nodes
      nodes.forEach(node => {
        const group = node.group || 'default'
        if (!groupedNodes.has(group)) groupedNodes.set(group, [])
        groupedNodes.get(group)!.push(node)
      })

      // Arrange in concentric circles by group
      let groupIndex = 0
      groupedNodes.forEach((groupNodes, _group) => {
        const angleStep = (2 * Math.PI) / groupNodes.length
        const radius = 100 + groupIndex * 80

        groupNodes.forEach((node, i) => {
          const angle = i * angleStep
          newPositions.set(node.id, {
            x: width / 2 + Math.cos(angle) * radius,
            y: height / 2 + Math.sin(angle) * radius,
          })
        })
        groupIndex++
      })

      setPositions(newPositions)
      return
    }

    // Force-directed simulation
    const simulate = () => {
      const alpha = 0.1
      const centerForce = 0.01
      const repulsion = 1000
      const linkForce = 0.1
      const damping = 0.9

      // Apply forces
      nodeMap.forEach((node, id) => {
        // Center attraction
        node.vx! += (width / 2 - node.x!) * centerForce
        node.vy! += (height / 2 - node.y!) * centerForce

        // Node repulsion
        nodeMap.forEach((other, otherId) => {
          if (id === otherId) return
          const dx = node.x! - other.x!
          const dy = node.y! - other.y!
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const force = repulsion / (dist * dist)
          node.vx! += (dx / dist) * force
          node.vy! += (dy / dist) * force
        })
      })

      // Link attraction
      edges.forEach(edge => {
        const source = nodeMap.get(edge.source)
        const target = nodeMap.get(edge.target)
        if (!source || !target) return

        const dx = target.x! - source.x!
        const dy = target.y! - source.y!
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (dist - 150) * linkForce

        source.vx! += (dx / dist) * force
        source.vy! += (dy / dist) * force
        target.vx! -= (dx / dist) * force
        target.vy! -= (dy / dist) * force
      })

      // Update positions
      const newPositions = new Map<string, { x: number; y: number }>()
      nodeMap.forEach((node, id) => {
        node.vx! *= damping
        node.vy! *= damping
        node.x! += node.vx! * alpha
        node.y! += node.vy! * alpha

        // Boundary constraints
        node.x = Math.max(50, Math.min(width - 50, node.x!))
        node.y = Math.max(50, Math.min(height - 50, node.y!))

        newPositions.set(id, { x: node.x!, y: node.y! })
      })

      setPositions(newPositions)
      animationRef.current = requestAnimationFrame(simulate)
    }

    // Run simulation for limited iterations
    let iterations = 0
    const maxIterations = 100

    const runSimulation = () => {
      simulate()
      iterations++
      if (iterations < maxIterations) {
        animationRef.current = requestAnimationFrame(runSimulation)
      }
    }

    runSimulation()

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [nodes, edges, width, height, animated])

  return positions
}

// ============================================================================
// Subcomponents
// ============================================================================

interface TopologyNodeComponentProps {
  node: TopologyNode
  x: number
  y: number
  isSelected: boolean
  isHovered: boolean
  onClick: () => void
  onHover: (hovered: boolean) => void
}

function TopologyNodeComponent({
  node,
  x,
  y,
  isSelected,
  isHovered,
  onClick,
  onHover,
}: TopologyNodeComponentProps) {
  const config = NODE_TYPE_CONFIG[node.type]
  const status = STATUS_CONFIG[node.status]
  const Icon = config.icon

  return (
    <g
      transform={`translate(${x}, ${y})`}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      className="cursor-pointer"
    >
      {/* Status ring */}
      <circle
        r={isSelected || isHovered ? 32 : 28}
        fill="none"
        stroke={status.color}
        strokeWidth={2}
        opacity={isSelected || isHovered ? 1 : 0.5}
        className={cn(status.pulse && 'animate-pulse')}
      />

      {/* Node background */}
      <circle
        r={24}
        fill={`${config.color}20`}
        stroke={config.color}
        strokeWidth={isSelected ? 3 : 1.5}
        className="transition-all duration-200"
      />

      {/* Icon */}
      <foreignObject x={-12} y={-12} width={24} height={24}>
        <Icon
          className="h-6 w-6"
          style={{ color: config.color }}
        />
      </foreignObject>

      {/* Threat indicator */}
      {node.threatCount && node.threatCount > 0 && (
        <g transform="translate(16, -16)">
          <circle r={10} fill="#ef4444" />
          <text
            textAnchor="middle"
            dominantBaseline="middle"
            fill="white"
            fontSize={10}
            fontWeight="bold"
          >
            {node.threatCount > 9 ? '9+' : node.threatCount}
          </text>
        </g>
      )}

      {/* Label */}
      <text
        y={38}
        textAnchor="middle"
        fill="#e2e8f0"
        fontSize={11}
        fontWeight={500}
        className="select-none"
      >
        {node.label.length > 15 ? node.label.slice(0, 15) + '...' : node.label}
      </text>

      {/* Status indicator */}
      <circle
        cx={18}
        cy={18}
        r={6}
        fill={status.color}
        stroke="#1e293b"
        strokeWidth={2}
      />
    </g>
  )
}

interface EdgeComponentProps {
  edge: TopologyEdge
  sourcePos: { x: number; y: number }
  targetPos: { x: number; y: number }
  isSelected: boolean
  isHovered: boolean
  onClick: () => void
  onHover: (hovered: boolean) => void
  animated: boolean
}

function EdgeComponent({
  edge,
  sourcePos,
  targetPos,
  isSelected,
  isHovered,
  onClick,
  onHover,
  animated,
}: EdgeComponentProps) {
  const style = EDGE_STYLES[edge.type]

  // Calculate curve control point
  const midX = (sourcePos.x + targetPos.x) / 2
  const midY = (sourcePos.y + targetPos.y) / 2
  const dx = targetPos.x - sourcePos.x
  const dy = targetPos.y - sourcePos.y
  const perpX = -dy * 0.1
  const perpY = dx * 0.1
  const ctrlX = midX + perpX
  const ctrlY = midY + perpY

  const path = `M ${sourcePos.x} ${sourcePos.y} Q ${ctrlX} ${ctrlY} ${targetPos.x} ${targetPos.y}`

  return (
    <g
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      className="cursor-pointer"
    >
      {/* Hit area */}
      <path
        d={path}
        fill="none"
        stroke="transparent"
        strokeWidth={10}
      />

      {/* Edge line */}
      <path
        d={path}
        fill="none"
        stroke={isSelected || isHovered ? '#fff' : style.color}
        strokeWidth={isSelected || isHovered ? style.width * 1.5 : style.width}
        strokeDasharray={style.dash}
        opacity={isSelected || isHovered ? 1 : 0.6}
        className="transition-all duration-200"
      />

      {/* Animated particles for suspicious connections */}
      {animated && (edge.type === 'suspicious' || edge.type === 'blocked') && (
        <circle r={3} fill={EDGE_STYLES[edge.type].color}>
          <animateMotion
            dur="2s"
            repeatCount="indefinite"
            path={path}
          />
        </circle>
      )}

      {/* Flow indicator arrow */}
      <defs>
        <marker
          id={`arrow-${edge.id}`}
          markerWidth="8"
          markerHeight="8"
          refX="6"
          refY="3"
          orient="auto"
        >
          <path
            d="M0,0 L0,6 L9,3 z"
            fill={style.color}
            opacity={0.8}
          />
        </marker>
      </defs>
      <path
        d={path}
        fill="none"
        stroke="transparent"
        markerEnd={`url(#arrow-${edge.id})`}
      />
    </g>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function NetworkTopology({
  data,
  isLoading = false,
  onNodeClick,
  onEdgeClick,
  className,
  showLegend = true,
  showStats = true,
  animated = true,
}: NetworkTopologyProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 })
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<TopologyEdge | null>(null)
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null)
  const [hoveredEdge, setHoveredEdge] = useState<TopologyEdge | null>(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [showLabels, setShowLabels] = useState(true)
  const [typeFilter, setTypeFilter] = useState<NodeType[]>([])

  // Measure container
  useEffect(() => {
    if (!containerRef.current) return
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0]
      setDimensions({
        width: entry.contentRect.width,
        height: Math.max(400, entry.contentRect.height),
      })
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  // Filter nodes
  const filteredNodes = useMemo(() => {
    if (!data?.nodes || typeFilter.length === 0) return data?.nodes || []
    return data.nodes.filter(n => typeFilter.includes(n.type))
  }, [data?.nodes, typeFilter])

  // Filter edges to only include filtered nodes
  const filteredEdges = useMemo(() => {
    if (!data?.edges) return []
    const nodeIds = new Set(filteredNodes.map(n => n.id))
    return data.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
  }, [data?.edges, filteredNodes])

  // Force simulation
  const positions = useForceSimulation(
    filteredNodes,
    filteredEdges,
    dimensions.width,
    dimensions.height,
    animated
  )

  const handleZoom = useCallback((direction: 'in' | 'out') => {
    setZoom(prev => {
      const newZoom = direction === 'in' ? prev * 1.2 : prev / 1.2
      return Math.max(0.5, Math.min(3, newZoom))
    })
  }, [])

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/4" />
          <div className="h-80 bg-slate-700 rounded" />
        </div>
      </div>
    )
  }

  if (!data || !data.nodes || data.nodes.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-cyan-600/20 rounded-lg">
            <Network className="h-5 w-5 text-cyan-400" />
          </div>
          <h3 className="font-semibold text-white">Network Topology</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Network className="h-12 w-12 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No network topology data available</p>
          <p className="text-slate-500 text-xs mt-1">Network nodes and connections will appear here once agents report data</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-600/20 rounded-lg">
            <Network className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Network Topology</h3>
            <p className="text-xs text-slate-400">
              {filteredNodes.length} nodes, {filteredEdges.length} connections
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Type filters */}
          <div className="flex items-center gap-1">
            {Object.entries(NODE_TYPE_CONFIG).slice(0, 4).map(([type, config]) => {
              const Icon = config.icon
              const isActive = typeFilter.length === 0 || typeFilter.includes(type as NodeType)
              return (
                <button
                  key={type}
                  className={cn(
                    'p-1.5 rounded transition-all',
                    isActive ? 'opacity-100' : 'opacity-30 hover:opacity-60'
                  )}
                  style={{ backgroundColor: isActive ? `${config.color}20` : 'transparent' }}
                  onClick={() => {
                    setTypeFilter(prev =>
                      prev.includes(type as NodeType)
                        ? prev.filter(t => t !== type)
                        : [...prev, type as NodeType]
                    )
                  }}
                  title={type}
                >
                  <Icon className="h-4 w-4" style={{ color: config.color }} />
                </button>
              )
            })}
          </div>

          <div className="w-px h-6 bg-slate-700" />

          {/* Label toggle */}
          <button
            onClick={() => setShowLabels(!showLabels)}
            className={cn(
              'p-1.5 rounded transition-colors',
              showLabels ? 'bg-primary-600/20 text-primary-400' : 'bg-slate-700 text-slate-400'
            )}
            title={showLabels ? 'Hide labels' : 'Show labels'}
          >
            {showLabels ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
          </button>

          {/* Zoom controls */}
          <button
            onClick={() => handleZoom('out')}
            className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <span className="text-xs text-slate-400 w-12 text-center">
            {Math.round(zoom * 100)}%
          </span>
          <button
            onClick={() => handleZoom('in')}
            className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
          >
            <ZoomIn className="h-4 w-4" />
          </button>

          {/* Reset */}
          <button
            onClick={() => {
              setZoom(1)
              setPan({ x: 0, y: 0 })
            }}
            className="p-1.5 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
          >
            <Maximize2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {showStats && data?.stats && (
        <div className="flex items-center gap-6 px-4 py-2 bg-slate-900/50 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
            <span className="text-xs text-slate-400">Healthy:</span>
            <span className="text-xs font-semibold text-white">{data.stats.healthyNodes}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
            <span className="text-xs text-slate-400">Warning:</span>
            <span className="text-xs font-semibold text-white">{data.stats.warningNodes}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span className="text-xs text-slate-400">Critical:</span>
            <span className="text-xs font-semibold text-white">{data.stats.criticalNodes}</span>
          </div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <span className="text-xs text-slate-400">Suspicious:</span>
            <span className="text-xs font-semibold text-orange-400">{data.stats.suspiciousConnections}</span>
          </div>
        </div>
      )}

      {/* Graph container */}
      <div ref={containerRef} className="relative" style={{ height: '400px' }}>
        <svg
          width="100%"
          height="100%"
          viewBox={`${-pan.x} ${-pan.y} ${dimensions.width / zoom} ${dimensions.height / zoom}`}
          className="select-none"
        >
          {/* Background grid */}
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path
                d="M 40 0 L 0 0 0 40"
                fill="none"
                stroke="#1e293b"
                strokeWidth="1"
              />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />

          {/* Edges */}
          <g>
            {filteredEdges.map(edge => {
              const sourcePos = positions.get(edge.source)
              const targetPos = positions.get(edge.target)
              if (!sourcePos || !targetPos) return null

              return (
                <EdgeComponent
                  key={edge.id}
                  edge={edge}
                  sourcePos={sourcePos}
                  targetPos={targetPos}
                  isSelected={selectedEdge?.id === edge.id}
                  isHovered={hoveredEdge?.id === edge.id}
                  onClick={() => {
                    setSelectedEdge(edge)
                    onEdgeClick?.(edge)
                  }}
                  onHover={(h) => setHoveredEdge(h ? edge : null)}
                  animated={animated}
                />
              )
            })}
          </g>

          {/* Nodes */}
          <g>
            {filteredNodes.map(node => {
              const pos = positions.get(node.id)
              if (!pos) return null

              return (
                <TopologyNodeComponent
                  key={node.id}
                  node={node}
                  x={pos.x}
                  y={pos.y}
                  isSelected={selectedNode?.id === node.id}
                  isHovered={hoveredNode?.id === node.id}
                  onClick={() => {
                    setSelectedNode(node)
                    onNodeClick?.(node)
                  }}
                  onHover={(h) => setHoveredNode(h ? node : null)}
                />
              )
            })}
          </g>
        </svg>

        {/* Node details panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-64 bg-slate-900 border border-slate-700 rounded-lg shadow-xl p-4 z-10">
            <div className="flex items-center gap-3 mb-3">
              {(() => {
                const config = NODE_TYPE_CONFIG[selectedNode.type]
                const Icon = config.icon
                return (
                  <div className="p-2 rounded-lg" style={{ backgroundColor: `${config.color}20` }}>
                    <Icon className="h-5 w-5" style={{ color: config.color }} />
                  </div>
                )
              })()}
              <div>
                <h4 className="font-semibold text-white">{selectedNode.label}</h4>
                <p className="text-xs text-slate-400 capitalize">{selectedNode.type}</p>
              </div>
            </div>
            <div className="space-y-2 text-sm">
              {selectedNode.ip && (
                <div className="flex justify-between">
                  <span className="text-slate-400">IP:</span>
                  <span className="text-white font-mono">{selectedNode.ip}</span>
                </div>
              )}
              {selectedNode.hostname && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Hostname:</span>
                  <span className="text-white">{selectedNode.hostname}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <span className={cn(
                  'capitalize font-medium',
                  selectedNode.status === 'healthy' && 'text-green-400',
                  selectedNode.status === 'warning' && 'text-yellow-400',
                  selectedNode.status === 'critical' && 'text-red-400',
                  selectedNode.status === 'offline' && 'text-slate-400'
                )}>
                  {selectedNode.status}
                </span>
              </div>
              {selectedNode.threatCount && selectedNode.threatCount > 0 && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Threats:</span>
                  <span className="text-red-400 font-semibold">{selectedNode.threatCount}</span>
                </div>
              )}
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="mt-3 w-full py-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 rounded transition-colors"
            >
              Close
            </button>
          </div>
        )}
      </div>

      {/* Legend */}
      {showLegend && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700 bg-slate-900/30">
          <div className="flex items-center gap-4">
            {Object.entries(NODE_TYPE_CONFIG).slice(0, 5).map(([type, config]) => {
              const Icon = config.icon
              return (
                <div key={type} className="flex items-center gap-1.5">
                  <Icon className="h-4 w-4" style={{ color: config.color }} />
                  <span className="text-xs text-slate-400 capitalize">{type}</span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <div className="w-6 h-0.5" style={{ backgroundColor: EDGE_STYLES.normal.color }} />
              <span className="text-xs text-slate-400">Normal</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div
                className="w-6 h-0.5"
                style={{
                  backgroundColor: EDGE_STYLES.suspicious.color,
                  backgroundImage: `repeating-linear-gradient(90deg, ${EDGE_STYLES.suspicious.color}, ${EDGE_STYLES.suspicious.color} 5px, transparent 5px, transparent 10px)`,
                }}
              />
              <span className="text-xs text-slate-400">Suspicious</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching topology data
// ============================================================================

export function useNetworkTopology() {
  const [data, setData] = useState<NetworkTopologyData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch('/api/v1/ndr/topology')
      if (!response.ok) throw new Error('Failed to fetch topology data')
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
            if (parsed.props?.networkTopology) {
              setData(parsed.props.networkTopology)
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
  }, [])

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

export default NetworkTopology
