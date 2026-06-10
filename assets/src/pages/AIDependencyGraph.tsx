import { useState, useEffect, useCallback, useRef } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Search, RefreshCw, Download, AlertTriangle, Cpu, FileCode,
  GitBranch, Shield, Layers, ZoomIn, ZoomOut, Maximize2, Target,
  Filter, ChevronRight, X, Eye, Activity, AlertCircle, Info
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AIDependencyGraphProps {
  // Initial data can be passed from server
}

type NodeType = 'process' | 'model'
type DependencyType = 'loads' | 'derived_from' | 'distilled_from'
type ViewMode = 'full' | 'consumers' | 'lineage' | 'risk'

interface GraphNode {
  id: string
  type: NodeType
  label?: string
  created_at?: string
  risk_score?: number
  depth?: number
}

interface GraphEdge {
  source: string
  target: string
  type: DependencyType
  created_at?: string
}

interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  metadata?: {
    node_count: number
    edge_count: number
    exported_at: string
  }
}

interface CriticalModel {
  id: string
  type: string
  direct_loads: number
  derivative_count: number
  total_consumers: number
  total_dependents: number
  criticality_score: number
}

interface Anomaly {
  type: string
  severity: 'high' | 'medium' | 'low'
  model_id?: string
  chain_length?: number
  load_count?: number
  description: string
}

interface RiskPropagationResult {
  source_model: string
  initial_risk: number
  affected_models: Array<{
    id: string
    propagated_risk: number
    distance: number
    path: string[]
  }>
  affected_processes: Array<{
    id: string
    propagated_risk: number
    distance: number
  }>
  total_impact_score: number
  model_count: number
  process_count: number
  critical_paths: Array<{
    path: string[]
    risk: number
    length: number
  }>
}

interface GraphStats {
  node_count: number
  edge_count: number
  model_count: number
  process_count: number
  counters: {
    dependencies_added: number
    queries_executed: number
    risk_propagations: number
  }
  memory_bytes: number
}

// Internal layout positions
interface LayoutNode extends GraphNode {
  x: number
  y: number
  vx: number
  vy: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_COLORS: Record<NodeType, string> = {
  process: '#3b82f6',  // blue
  model: '#22c55e',    // green
}

const NODE_BG_CLASSES: Record<NodeType, string> = {
  process: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  model: 'bg-green-500/20 text-green-400 border-green-500/30',
}

const EDGE_COLORS: Record<DependencyType, string> = {
  loads: '#94a3b8',
  derived_from: '#f97316',
  distilled_from: '#a855f7',
}

const NODE_RADIUS = 20
const ARROW_SIZE = 8

// ---------------------------------------------------------------------------
// Force-directed layout simulation
// ---------------------------------------------------------------------------

function initializePositions(nodes: GraphNode[], width: number, height: number): LayoutNode[] {
  const cx = width / 2
  const cy = height / 2
  return nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length
    const r = Math.min(width, height) * 0.3
    return {
      ...node,
      x: cx + r * Math.cos(angle) + (Math.random() - 0.5) * 40,
      y: cy + r * Math.sin(angle) + (Math.random() - 0.5) * 40,
      vx: 0,
      vy: 0,
    }
  })
}

function simulateForces(
  layoutNodes: LayoutNode[],
  edges: GraphEdge[],
  width: number,
  height: number,
  iterations: number = 150
): LayoutNode[] {
  const nodes = layoutNodes.map(n => ({ ...n }))
  const nodeMap = new Map<string, number>()
  nodes.forEach((n, i) => nodeMap.set(n.id, i))

  const repulsionStrength = 5000
  const attractionStrength = 0.005
  const idealLength = 120
  const centerGravity = 0.01
  const damping = 0.9

  const cx = width / 2
  const cy = height / 2

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 1 - iter / iterations

    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x
        const dy = nodes[j].y - nodes[i].y
        const distSq = dx * dx + dy * dy + 1
        const dist = Math.sqrt(distSq)
        const force = (repulsionStrength / distSq) * temp
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        nodes[i].vx -= fx
        nodes[i].vy -= fy
        nodes[j].vx += fx
        nodes[j].vy += fy
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const si = nodeMap.get(edge.source)
      const ti = nodeMap.get(edge.target)
      if (si === undefined || ti === undefined) continue
      const dx = nodes[ti].x - nodes[si].x
      const dy = nodes[ti].y - nodes[si].y
      const dist = Math.sqrt(dx * dx + dy * dy) + 1
      const force = (dist - idealLength) * attractionStrength * temp
      const fx = (dx / dist) * force
      const fy = (dy / dist) * force
      nodes[si].vx += fx
      nodes[si].vy += fy
      nodes[ti].vx -= fx
      nodes[ti].vy -= fy
    }

    // Center gravity
    for (const node of nodes) {
      node.vx += (cx - node.x) * centerGravity
      node.vy += (cy - node.y) * centerGravity
    }

    // Apply velocities
    for (const node of nodes) {
      node.vx *= damping
      node.vy *= damping
      node.x += node.vx
      node.y += node.vy
      node.x = Math.max(NODE_RADIUS + 10, Math.min(width - NODE_RADIUS - 10, node.x))
      node.y = Math.max(NODE_RADIUS + 10, Math.min(height - NODE_RADIUS - 10, node.y))
    }
  }

  return nodes
}

// ---------------------------------------------------------------------------
// Canvas rendering
// ---------------------------------------------------------------------------

function drawGraph(
  ctx: CanvasRenderingContext2D,
  nodes: LayoutNode[],
  edges: GraphEdge[],
  selectedNodeId: string | null,
  hoveredNodeId: string | null,
  zoom: number,
  pan: { x: number; y: number },
  width: number,
  height: number,
  nodeTypeFilter: Set<NodeType>
) {
  ctx.clearRect(0, 0, width, height)
  ctx.save()
  ctx.translate(pan.x, pan.y)
  ctx.scale(zoom, zoom)

  const nodeMap = new Map<string, LayoutNode>()
  nodes.forEach(n => nodeMap.set(n.id, n))

  const visibleNodes = nodes.filter(n => nodeTypeFilter.size === 0 || nodeTypeFilter.has(n.type))
  const visibleIds = new Set(visibleNodes.map(n => n.id))

  // Draw edges
  for (const edge of edges) {
    const source = nodeMap.get(edge.source)
    const target = nodeMap.get(edge.target)
    if (!source || !target) continue
    if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue

    const dx = target.x - source.x
    const dy = target.y - source.y
    const dist = Math.sqrt(dx * dx + dy * dy)
    if (dist === 0) continue

    const nx = dx / dist
    const ny = dy / dist

    const startX = source.x + nx * (NODE_RADIUS + 2)
    const startY = source.y + ny * (NODE_RADIUS + 2)
    const endX = target.x - nx * (NODE_RADIUS + ARROW_SIZE + 2)
    const endY = target.y - ny * (NODE_RADIUS + ARROW_SIZE + 2)

    const isHighlighted = selectedNodeId === edge.source || selectedNodeId === edge.target
    const edgeColor = EDGE_COLORS[edge.type] || '#475569'

    // Edge line
    ctx.beginPath()
    ctx.moveTo(startX, startY)
    ctx.lineTo(endX, endY)
    ctx.strokeStyle = isHighlighted ? edgeColor : '#475569'
    ctx.lineWidth = isHighlighted ? 2.5 : 1.5
    if (edge.type === 'derived_from') {
      ctx.setLineDash([5, 3])
    } else if (edge.type === 'distilled_from') {
      ctx.setLineDash([2, 2])
    } else {
      ctx.setLineDash([])
    }
    ctx.stroke()
    ctx.setLineDash([])

    // Arrowhead
    const arrowX = target.x - nx * (NODE_RADIUS + 2)
    const arrowY = target.y - ny * (NODE_RADIUS + 2)
    ctx.beginPath()
    ctx.moveTo(arrowX, arrowY)
    ctx.lineTo(
      arrowX - ARROW_SIZE * nx + (ARROW_SIZE / 2) * ny,
      arrowY - ARROW_SIZE * ny - (ARROW_SIZE / 2) * nx
    )
    ctx.lineTo(
      arrowX - ARROW_SIZE * nx - (ARROW_SIZE / 2) * ny,
      arrowY - ARROW_SIZE * ny + (ARROW_SIZE / 2) * nx
    )
    ctx.closePath()
    ctx.fillStyle = isHighlighted ? edgeColor : '#475569'
    ctx.fill()

    // Edge label
    if (isHighlighted) {
      const midX = (startX + endX) / 2
      const midY = (startY + endY) / 2
      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.fillStyle = '#94a3b8'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'bottom'
      ctx.fillText(edge.type.replace('_', ' '), midX, midY - 4)
    }
  }

  // Draw nodes
  for (const node of visibleNodes) {
    const isSelected = node.id === selectedNodeId
    const isHovered = node.id === hoveredNodeId
    const color = NODE_COLORS[node.type] || '#64748b'

    // Glow for selected/hovered
    if (isSelected || isHovered) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, NODE_RADIUS + 6, 0, Math.PI * 2)
      ctx.fillStyle = color + '33'
      ctx.fill()
    }

    // Risk score ring
    if (node.risk_score != null && node.risk_score > 0.3) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, NODE_RADIUS + 3, 0, Math.PI * 2)
      ctx.strokeStyle = node.risk_score > 0.7 ? '#ef4444' : node.risk_score > 0.5 ? '#f97316' : '#eab308'
      ctx.lineWidth = 2
      ctx.stroke()
    }

    // Node circle
    ctx.beginPath()
    ctx.arc(node.x, node.y, NODE_RADIUS, 0, Math.PI * 2)
    ctx.fillStyle = isSelected ? color : color + 'cc'
    ctx.fill()
    ctx.strokeStyle = isSelected ? '#ffffff' : color
    ctx.lineWidth = isSelected ? 2.5 : 1.5
    ctx.stroke()

    // Icon
    ctx.font = 'bold 14px Inter, system-ui, sans-serif'
    ctx.fillStyle = '#ffffff'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    const letter = node.type === 'process' ? 'P' : 'M'
    ctx.fillText(letter, node.x, node.y)

    // Label
    ctx.font = '11px Inter, system-ui, sans-serif'
    ctx.fillStyle = isSelected ? '#ffffff' : '#cbd5e1'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    const label = (node.label || node.id).length > 20 ? (node.label || node.id).substring(0, 18) + '..' : (node.label || node.id)
    ctx.fillText(label, node.x, node.y + NODE_RADIUS + 4)
  }

  ctx.restore()
}

// ---------------------------------------------------------------------------
// Hit test
// ---------------------------------------------------------------------------

function hitTestNode(
  nodes: LayoutNode[],
  mx: number,
  my: number,
  zoom: number,
  pan: { x: number; y: number },
  nodeTypeFilter: Set<NodeType>
): LayoutNode | null {
  const gx = (mx - pan.x) / zoom
  const gy = (my - pan.y) / zoom

  for (let i = nodes.length - 1; i >= 0; i--) {
    const node = nodes[i]
    if (nodeTypeFilter.size > 0 && !nodeTypeFilter.has(node.type)) continue
    const dx = gx - node.x
    const dy = gy - node.y
    if (dx * dx + dy * dy <= (NODE_RADIUS + 4) * (NODE_RADIUS + 4)) {
      return node
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function AIDependencyGraph(_props: AIDependencyGraphProps) {
  // State
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState<ViewMode>('full')
  const [nodeTypeFilter, setNodeTypeFilter] = useState<Set<NodeType>>(new Set())

  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [layoutNodes, setLayoutNodes] = useState<LayoutNode[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null)

  const [stats, setStats] = useState<GraphStats | null>(null)
  const [criticalModels, setCriticalModels] = useState<CriticalModel[]>([])
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [riskResult, setRiskResult] = useState<RiskPropagationResult | null>(null)
  const [riskLoading, setRiskLoading] = useState(false)

  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })

  const [showSidebar, setShowSidebar] = useState(true)
  const [sidebarTab, setSidebarTab] = useState<'details' | 'critical' | 'anomalies' | 'risk'>('critical')
  const [showFilters, setShowFilters] = useState(false)

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 })

  // Resize observer
  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        setCanvasSize({ width: Math.floor(width), height: Math.floor(height) })
      }
    })
    observer.observe(container)
    return () => observer.disconnect()
  }, [])

  // Fetch stats on mount
  useEffect(() => {
    fetchStats()
    fetchCriticalModels()
    fetchAnomalies()
  }, [])

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/v1/ai/dependency-graph/stats', { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data) {
        setStats(result.data)
      }
    } catch (err) {
      logger.error('Stats fetch error:', err)
    }
  }

  const fetchCriticalModels = async () => {
    try {
      const response = await fetch('/api/v1/ai/dependency-graph/critical-models?limit=10&min_dependents=2', { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data?.critical_models) {
        setCriticalModels(result.data.critical_models)
      }
    } catch (err) {
      logger.error('Critical models fetch error:', err)
    }
  }

  const fetchAnomalies = async () => {
    try {
      const response = await fetch('/api/v1/ai/dependency-graph/unusual-chains', { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data?.anomalies) {
        setAnomalies(result.data.anomalies)
      }
    } catch (err) {
      logger.error('Anomalies fetch error:', err)
    }
  }

  const fetchSubgraph = useCallback(async (nodeId: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/v1/ai/dependency-graph/subgraph/${encodeURIComponent(nodeId)}?depth=3`, { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()

      if (result.data) {
        const data: GraphData = {
          nodes: result.data.nodes || [],
          edges: result.data.edges || [],
        }
        setGraphData(data)

        const positioned = initializePositions(data.nodes, canvasSize.width, canvasSize.height)
        const simulated = simulateForces(positioned, data.edges, canvasSize.width, canvasSize.height)
        setLayoutNodes(simulated)
        resetView()
      }
    } catch (err) {
      logger.error('Subgraph fetch error:', err)
      setError('Failed to load dependency graph')
    } finally {
      setLoading(false)
    }
  }, [canvasSize])

  const fetchFullGraph = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/v1/ai/dependency-graph/export/json', { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data: GraphData = await response.json()

      setGraphData(data)

      // Limit nodes for performance
      const limitedNodes = data.nodes.slice(0, 200)
      const nodeIds = new Set(limitedNodes.map(n => n.id))
      const limitedEdges = data.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))

      const positioned = initializePositions(limitedNodes, canvasSize.width, canvasSize.height)
      const simulated = simulateForces(positioned, limitedEdges, canvasSize.width, canvasSize.height)
      setLayoutNodes(simulated)
      resetView()
    } catch (err) {
      logger.error('Full graph fetch error:', err)
      setError('Failed to load dependency graph')
    } finally {
      setLoading(false)
    }
  }, [canvasSize])

  const propagateRisk = useCallback(async (modelId: string, riskScore: number = 0.9) => {
    setRiskLoading(true)
    setRiskResult(null)

    try {
      const response = await fetch('/api/v1/ai/dependency-graph/propagate-risk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ model_id: modelId, risk_score: riskScore })
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data) {
        setRiskResult(result.data)
        setSidebarTab('risk')
      }
    } catch (err) {
      logger.error('Risk propagation error:', err)
    } finally {
      setRiskLoading(false)
    }
  }, [])

  // Canvas rendering
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    canvas.width = canvasSize.width * dpr
    canvas.height = canvasSize.height * dpr
    canvas.style.width = `${canvasSize.width}px`
    canvas.style.height = `${canvasSize.height}px`
    ctx.scale(dpr, dpr)

    drawGraph(
      ctx,
      layoutNodes,
      graphData?.edges || [],
      selectedNode?.id || null,
      hoveredNodeId,
      zoom,
      pan,
      canvasSize.width,
      canvasSize.height,
      nodeTypeFilter
    )
  }, [layoutNodes, graphData, selectedNode, hoveredNodeId, zoom, pan, canvasSize, nodeTypeFilter])

  // Mouse handlers
  const handleCanvasMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top

    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, nodeTypeFilter)
    if (hit) {
      setSelectedNode(hit)
      setSidebarTab('details')
      setShowSidebar(true)
    } else {
      setIsPanning(true)
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
    }
  }, [layoutNodes, zoom, pan, nodeTypeFilter])

  const handleCanvasMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isPanning) {
      setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y })
      return
    }

    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, nodeTypeFilter)
    setHoveredNodeId(hit?.id || null)

    if (canvasRef.current) {
      canvasRef.current.style.cursor = hit ? 'pointer' : isPanning ? 'grabbing' : 'grab'
    }
  }, [isPanning, panStart, layoutNodes, zoom, pan, nodeTypeFilter])

  const handleCanvasMouseUp = useCallback(() => {
    setIsPanning(false)
  }, [])

  const handleCanvasWheel = useCallback((e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.9 : 1.1
    setZoom(z => Math.max(0.1, Math.min(5, z * delta)))
  }, [])

  const handleCanvasDoubleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, nodeTypeFilter)
    if (hit) {
      fetchSubgraph(hit.id)
    }
  }, [layoutNodes, zoom, pan, nodeTypeFilter, fetchSubgraph])

  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
  }, [])

  const toggleNodeFilter = useCallback((type: NodeType) => {
    setNodeTypeFilter(prev => {
      const next = new Set(prev)
      if (next.has(type)) {
        next.delete(type)
      } else {
        next.add(type)
      }
      return next
    })
  }, [])

  const exportGraph = useCallback(async (format: 'dot' | 'json') => {
    try {
      const response = await fetch(`/api/v1/ai/dependency-graph/export/${format}`, { credentials: 'include' })
      const blob = await response.blob()
      const link = document.createElement('a')
      link.download = `ai-dependencies.${format === 'dot' ? 'dot' : 'json'}`
      link.href = URL.createObjectURL(blob)
      link.click()
      URL.revokeObjectURL(link.href)
    } catch (err) {
      logger.error('Export error:', err)
    }
  }, [])

  const handleSearch = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      fetchSubgraph(searchQuery.trim())
    } else {
      fetchFullGraph()
    }
  }, [searchQuery, fetchSubgraph, fetchFullGraph])

  const nodeCount = graphData?.nodes.length || 0
  const edgeCount = graphData?.edges.length || 0

  return (
    <MainLayout title="AI Model Dependencies">
      <Head title="AI Model Dependencies - Tamandua EDR" />

      <div className="flex flex-col h-[calc(100vh-64px)]">
        {/* Top Control Bar */}
        <div className="px-4 py-3" style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-4 flex-wrap">
            {/* Search */}
            <form onSubmit={handleSearch} className="flex items-center gap-2 flex-1 max-w-md">
              <div className="relative flex-1">
                <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--subtle)' }} />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Model or process ID..."
                  className="w-full rounded pl-8 pr-3 py-1.5 text-sm placeholder-[var(--subtle)]"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg)' }}
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded font-medium transition-colors disabled:opacity-50"
              >
                {loading ? <RefreshCw size={14} className="animate-spin" /> : 'Search'}
              </button>
            </form>

            {/* View mode */}
            <div className="flex items-center rounded overflow-hidden" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
              <button
                onClick={() => fetchFullGraph()}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  viewMode === 'full' ? 'bg-blue-600 text-white' : 'hover:bg-[var(--surface-3)]'
                )}
                style={viewMode !== 'full' ? { color: 'var(--muted)' } : undefined}
              >
                <GitBranch size={12} />
                Full Graph
              </button>
            </div>

            {/* Filter button */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                'p-1.5 rounded transition-colors',
                showFilters ? 'bg-blue-600 text-white' : ''
              )}
              style={!showFilters ? { background: 'var(--surface-2)', color: 'var(--muted)' } : undefined}
              title="Filter by node type"
            >
              <Filter size={16} />
            </button>

            {/* Actions */}
            <div className="flex items-center gap-1 ml-auto">
              <button
                onClick={() => {
                  fetchCriticalModels()
                  fetchAnomalies()
                  fetchStats()
                }}
                className="px-3 py-1.5 text-xs font-medium rounded transition-colors flex items-center gap-1.5 hover:bg-[var(--surface-3)]"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
              >
                <RefreshCw size={12} />
                Refresh
              </button>
              <button
                onClick={() => setShowSidebar(!showSidebar)}
                className={cn(
                  'p-1.5 rounded transition-colors',
                  showSidebar ? 'bg-blue-600 text-white' : ''
                )}
                style={!showSidebar ? { background: 'var(--surface-2)', color: 'var(--muted)' } : undefined}
                title="Toggle sidebar"
              >
                <Layers size={16} />
              </button>
            </div>
          </div>

          {/* Filter row */}
          {showFilters && (
            <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
              <span className="text-xs mr-1" style={{ color: 'var(--subtle)' }}>Filter types:</span>
              {(['process', 'model'] as NodeType[]).map(type => {
                const active = nodeTypeFilter.size === 0 || nodeTypeFilter.has(type)
                return (
                  <button
                    key={type}
                    onClick={() => toggleNodeFilter(type)}
                    className={cn(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors',
                      active ? NODE_BG_CLASSES[type] : ''
                    )}
                    style={!active ? { background: 'var(--surface-2)', color: 'var(--subtle)', borderColor: 'var(--border)' } : undefined}
                  >
                    {type === 'process' ? <Cpu size={12} /> : <FileCode size={12} />}
                    {type === 'process' ? 'Processes' : 'Models'}
                  </button>
                )
              })}
              {nodeTypeFilter.size > 0 && (
                <button
                  onClick={() => setNodeTypeFilter(new Set())}
                  className="text-xs ml-2 hover:text-[var(--fg-2)]"
                  style={{ color: 'var(--subtle)' }}
                >
                  Clear filters
                </button>
              )}
            </div>
          )}
        </div>

        {/* Main content */}
        <div className="flex flex-1 overflow-hidden">
          {/* Canvas */}
          <div ref={containerRef} className="flex-1 relative" style={{ background: 'var(--bg)' }}>
            {loading ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center">
                  <RefreshCw size={32} className="text-blue-400 animate-spin mx-auto mb-4" />
                  <p style={{ color: 'var(--muted)' }}>Loading dependency graph...</p>
                </div>
              </div>
            ) : error ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center rounded-lg p-6 max-w-sm" style={{ background: 'var(--surface)' }}>
                  <AlertTriangle size={32} className="text-red-400 mx-auto mb-3" />
                  <p className="mb-3" style={{ color: 'var(--fg-2)' }}>{error}</p>
                  <button
                    onClick={() => fetchFullGraph()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm text-white transition-colors"
                  >
                    Retry
                  </button>
                </div>
              </div>
            ) : !graphData ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center max-w-md">
                  <GitBranch size={48} className="mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                  <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg-2)' }}>AI Model Dependency Graph</h3>
                  <p className="text-sm mb-4" style={{ color: 'var(--subtle)' }}>
                    Visualize dependencies between processes and AI models.
                    Track model lineage and analyze supply chain risks.
                  </p>
                  <button
                    onClick={() => fetchFullGraph()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
                  >
                    Load Full Graph
                  </button>

                  {stats && (
                    <div className="card-sentinel rounded-lg p-4 text-left mt-4">
                      <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--fg-2)' }}>Graph Statistics</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <span style={{ color: 'var(--subtle)' }}>Total Nodes:</span>
                        <span className="font-mono" style={{ color: 'var(--fg)' }}>{stats.node_count}</span>
                        <span style={{ color: 'var(--subtle)' }}>Total Edges:</span>
                        <span className="font-mono" style={{ color: 'var(--fg)' }}>{stats.edge_count}</span>
                        <span style={{ color: 'var(--subtle)' }}>Models:</span>
                        <span className="text-green-400 font-mono">{stats.model_count}</span>
                        <span style={{ color: 'var(--subtle)' }}>Processes:</span>
                        <span className="text-blue-400 font-mono">{stats.process_count}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            <canvas
              ref={canvasRef}
              className="w-full h-full"
              onMouseDown={handleCanvasMouseDown}
              onMouseMove={handleCanvasMouseMove}
              onMouseUp={handleCanvasMouseUp}
              onMouseLeave={handleCanvasMouseUp}
              onWheel={handleCanvasWheel}
              onDoubleClick={handleCanvasDoubleClick}
            />

            {/* Zoom controls */}
            <div className="absolute top-4 left-4 flex flex-col gap-1 z-10">
              <button onClick={() => setZoom(z => Math.min(5, z * 1.2))} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                <ZoomIn size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
              <button onClick={() => setZoom(z => Math.max(0.1, z / 1.2))} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                <ZoomOut size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
              <button onClick={resetView} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                <Maximize2 size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
            </div>

            {/* Export controls */}
            <div className="absolute top-4 right-4 flex gap-1 z-10">
              <button
                onClick={() => exportGraph('json')}
                className="px-2.5 py-1.5 rounded text-xs transition-colors flex items-center gap-1 hover:bg-[var(--surface-2)]"
                style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
              >
                <Download size={12} />
                JSON
              </button>
              <button
                onClick={() => exportGraph('dot')}
                className="px-2.5 py-1.5 rounded text-xs transition-colors flex items-center gap-1 hover:bg-[var(--surface-2)]"
                style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
              >
                <Download size={12} />
                DOT
              </button>
            </div>

            {/* Stats overlay */}
            {graphData && graphData.nodes.length > 0 && (
              <div className="absolute bottom-4 left-4 rounded-lg p-3 text-xs z-10" style={{ background: 'var(--surface)', border: '1px solid var(--hairline)' }}>
                <div className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--subtle)' }}>Graph Stats</div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                  <span style={{ color: 'var(--subtle)' }}>Nodes:</span>
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{nodeCount}</span>
                  <span style={{ color: 'var(--subtle)' }}>Edges:</span>
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{edgeCount}</span>
                  <span style={{ color: 'var(--subtle)' }}>Zoom:</span>
                  <span className="font-medium" style={{ color: 'var(--fg-2)' }}>{(zoom * 100).toFixed(0)}%</span>
                </div>
                <div className="mt-2 pt-2 flex flex-wrap gap-1.5" style={{ borderTop: '1px solid var(--border)' }}>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.process }} />
                    <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>Process</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.model }} />
                    <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>Model</span>
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          {showSidebar && (
            <div className="w-96 flex flex-col overflow-hidden" style={{ background: 'var(--surface)', borderLeft: '1px solid var(--border)' }}>
              {/* Tab bar */}
              <div className="flex" style={{ borderBottom: '1px solid var(--border)' }}>
                <button
                  onClick={() => setSidebarTab('details')}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors',
                    sidebarTab === 'details' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'details' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Details
                </button>
                <button
                  onClick={() => setSidebarTab('critical')}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors relative',
                    sidebarTab === 'critical' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'critical' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Critical
                  {criticalModels.length > 0 && (
                    <span className="ml-1 bg-orange-500/20 text-orange-400 text-[10px] px-1.5 py-0.5 rounded-full">
                      {criticalModels.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setSidebarTab('anomalies')}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors relative',
                    sidebarTab === 'anomalies' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'anomalies' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Anomalies
                  {anomalies.length > 0 && (
                    <span className="ml-1 bg-red-500/20 text-red-400 text-[10px] px-1.5 py-0.5 rounded-full">
                      {anomalies.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setSidebarTab('risk')}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors',
                    sidebarTab === 'risk' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'risk' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Risk
                </button>
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-y-auto">
                {sidebarTab === 'details' && (
                  <NodeDetailsPanel
                    node={selectedNode}
                    onClose={() => setSelectedNode(null)}
                    onExplore={(id) => fetchSubgraph(id)}
                    onPropagateRisk={(id) => propagateRisk(id)}
                  />
                )}

                {sidebarTab === 'critical' && (
                  <CriticalModelsPanel
                    models={criticalModels}
                    onRefresh={fetchCriticalModels}
                    onSelect={(id) => fetchSubgraph(id)}
                    onPropagateRisk={(id) => propagateRisk(id)}
                  />
                )}

                {sidebarTab === 'anomalies' && (
                  <AnomaliesPanel
                    anomalies={anomalies}
                    onRefresh={fetchAnomalies}
                    onSelect={(id) => fetchSubgraph(id)}
                  />
                )}

                {sidebarTab === 'risk' && (
                  <RiskPanel
                    result={riskResult}
                    loading={riskLoading}
                    selectedNode={selectedNode}
                    onPropagateRisk={(id) => propagateRisk(id)}
                    onSelect={(id) => fetchSubgraph(id)}
                  />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function NodeDetailsPanel({
  node,
  onClose,
  onExplore,
  onPropagateRisk,
}: {
  node: GraphNode | null
  onClose: () => void
  onExplore: (id: string) => void
  onPropagateRisk: (id: string) => void
}) {
  if (!node) {
    return (
      <div className="p-6 text-center">
        <Eye size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
        <p className="text-sm" style={{ color: 'var(--subtle)' }}>Click a node on the graph to see its details.</p>
      </div>
    )
  }

  const Icon = node.type === 'process' ? Cpu : FileCode

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className={cn('p-2 rounded-lg border', NODE_BG_CLASSES[node.type])}>
            <Icon size={16} />
          </div>
          <div>
            <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{node.label || node.id}</div>
            <div className="text-xs capitalize" style={{ color: 'var(--subtle)' }}>{node.type}</div>
          </div>
        </div>
        <button onClick={onClose} className="p-1 hover:bg-[var(--surface-2)] rounded transition-colors">
          <X size={16} style={{ color: 'var(--subtle)' }} />
        </button>
      </div>

      <div className="mb-4">
        <div className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--muted)' }}>ID</div>
        <code className="text-xs px-2 py-1 rounded block truncate font-mono" style={{ background: 'var(--bg)', color: 'var(--fg-2)' }}>
          {node.id}
        </code>
      </div>

      {node.created_at && (
        <div className="mb-4">
          <div className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--muted)' }}>Created</div>
          <p className="text-xs" style={{ color: 'var(--fg-2)' }}>{formatDate(node.created_at)}</p>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <button
          onClick={() => onExplore(node.id)}
          className="w-full px-3 py-2 bg-blue-600/20 border border-blue-500/30 rounded text-xs text-blue-400 hover:bg-blue-600/30 transition-colors flex items-center justify-center gap-2"
        >
          <GitBranch size={12} />
          Explore Subgraph
        </button>
        {node.type === 'model' && (
          <button
            onClick={() => onPropagateRisk(node.id)}
            className="w-full px-3 py-2 bg-red-600/20 border border-red-500/30 rounded text-xs text-red-400 hover:bg-red-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <Target size={12} />
            Propagate Risk
          </button>
        )}
      </div>
    </div>
  )
}

function CriticalModelsPanel({
  models,
  onRefresh,
  onSelect,
  onPropagateRisk,
}: {
  models: CriticalModel[]
  onRefresh: () => void
  onSelect: (id: string) => void
  onPropagateRisk: (id: string) => void
}) {
  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Critical Models</h3>
        <button onClick={onRefresh} className="p-1 hover:bg-[var(--surface-2)] rounded transition-colors">
          <RefreshCw size={14} style={{ color: 'var(--muted)' }} />
        </button>
      </div>

      <p className="text-xs mb-4" style={{ color: 'var(--subtle)' }}>
        Models with the most dependents - single points of failure.
      </p>

      {models.length === 0 ? (
        <div className="text-center py-8">
          <Shield size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>No critical models detected.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {models.map((model, idx) => (
            <div key={model.id} className="card-sentinel rounded-lg p-3">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <div className="text-sm font-medium truncate max-w-[200px]" style={{ color: 'var(--fg)' }} title={model.id}>
                    {model.id}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--subtle)' }}>Criticality: {model.criticality_score.toFixed(1)}</div>
                </div>
                <span className={cn(
                  'text-xs px-2 py-0.5 rounded font-mono',
                  idx === 0 ? 'bg-red-500/20 text-red-400' : idx < 3 ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'
                )}>
                  #{idx + 1}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                <span style={{ color: 'var(--subtle)' }}>Direct loads:</span>
                <span className="text-blue-400 font-mono">{model.direct_loads}</span>
                <span style={{ color: 'var(--subtle)' }}>Derivatives:</span>
                <span className="text-green-400 font-mono">{model.derivative_count}</span>
                <span style={{ color: 'var(--subtle)' }}>Total consumers:</span>
                <span className="font-mono" style={{ color: 'var(--fg)' }}>{model.total_consumers}</span>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => onSelect(model.id)}
                  className="flex-1 px-2 py-1 rounded text-xs transition-colors hover:bg-[var(--surface-3)]"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                >
                  Explore
                </button>
                <button
                  onClick={() => onPropagateRisk(model.id)}
                  className="px-2 py-1 bg-red-600/20 rounded text-xs text-red-400 hover:bg-red-600/30 transition-colors"
                >
                  Risk
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function AnomaliesPanel({
  anomalies,
  onRefresh,
  onSelect,
}: {
  anomalies: Anomaly[]
  onRefresh: () => void
  onSelect: (id: string) => void
}) {
  const severityColors = {
    high: 'bg-red-500/20 text-red-400 border-red-500/30',
    medium: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    low: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  }

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Unusual Chains</h3>
        <button onClick={onRefresh} className="p-1 hover:bg-[var(--surface-2)] rounded transition-colors">
          <RefreshCw size={14} style={{ color: 'var(--muted)' }} />
        </button>
      </div>

      <p className="text-xs mb-4" style={{ color: 'var(--subtle)' }}>
        Potential supply chain attack indicators.
      </p>

      {anomalies.length === 0 ? (
        <div className="text-center py-8">
          <AlertCircle size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>No anomalies detected.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {anomalies.map((anomaly, idx) => (
            <div key={idx} className={cn('rounded-lg border p-3', severityColors[anomaly.severity])}>
              <div className="flex items-start justify-between mb-2">
                <span className="text-xs font-medium uppercase">{anomaly.type.replace(/_/g, ' ')}</span>
                <span className="text-xs font-medium uppercase">{anomaly.severity}</span>
              </div>
              <p className="text-xs mb-2">{anomaly.description}</p>
              {anomaly.model_id && (
                <button
                  onClick={() => onSelect(anomaly.model_id!)}
                  className="text-xs hover:underline"
                >
                  View: {anomaly.model_id}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RiskPanel({
  result,
  loading,
  selectedNode,
  onPropagateRisk,
  onSelect,
}: {
  result: RiskPropagationResult | null
  loading: boolean
  selectedNode: GraphNode | null
  onPropagateRisk: (id: string) => void
  onSelect: (id: string) => void
}) {
  return (
    <div className="p-4">
      <h3 className="text-sm font-medium mb-4" style={{ color: 'var(--fg)' }}>Risk Propagation</h3>

      {loading ? (
        <div className="text-center py-8">
          <RefreshCw size={24} className="text-red-400 animate-spin mx-auto mb-3" />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>Propagating risk...</p>
        </div>
      ) : !result ? (
        <div className="text-center py-8">
          <Target size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
          <p className="text-sm mb-3" style={{ color: 'var(--subtle)' }}>
            Select a model and click "Propagate Risk" to analyze impact.
          </p>
          {selectedNode && selectedNode.type === 'model' && (
            <button
              onClick={() => onPropagateRisk(selectedNode.id)}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
            >
              Analyze: {selectedNode.label || selectedNode.id}
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Summary */}
          <div className="rounded-lg border border-red-500/30 p-3" style={{ background: 'var(--bg)' }}>
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={14} className="text-red-400" />
              <span className="text-xs font-medium text-red-400 uppercase tracking-wider">Impact Summary</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <span style={{ color: 'var(--subtle)' }}>Source Model:</span>
              <span className="font-mono text-xs truncate" style={{ color: 'var(--fg)' }} title={result.source_model}>{result.source_model}</span>
              <span style={{ color: 'var(--subtle)' }}>Initial Risk:</span>
              <span className="text-red-400 font-mono">{(result.initial_risk * 100).toFixed(0)}%</span>
              <span style={{ color: 'var(--subtle)' }}>Affected Models:</span>
              <span className="text-green-400 font-mono">{result.model_count}</span>
              <span style={{ color: 'var(--subtle)' }}>Affected Processes:</span>
              <span className="text-blue-400 font-mono">{result.process_count}</span>
              <span style={{ color: 'var(--subtle)' }}>Total Impact:</span>
              <span className="text-orange-400 font-mono">{result.total_impact_score.toFixed(2)}</span>
            </div>
          </div>

          {/* Critical paths */}
          {result.critical_paths.length > 0 && (
            <div>
              <div className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--muted)' }}>Critical Paths</div>
              <div className="space-y-2">
                {result.critical_paths.map((path, idx) => (
                  <div key={idx} className="rounded border p-2" style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span style={{ color: 'var(--subtle)' }}>Risk: {(path.risk * 100).toFixed(0)}%</span>
                      <span style={{ color: 'var(--subtle)' }}>{path.length} hops</span>
                    </div>
                    <div className="flex items-center flex-wrap gap-1">
                      {path.path.slice(0, 5).map((id, i) => (
                        <span key={i} className="flex items-center">
                          {i > 0 && <ChevronRight size={10} className="mx-0.5" style={{ color: 'var(--subtle)' }} />}
                          <button
                            onClick={() => onSelect(id)}
                            className="text-[10px] px-1.5 py-0.5 rounded font-mono truncate max-w-[80px] hover:text-[var(--fg)]"
                            style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
                            title={id}
                          >
                            {id}
                          </button>
                        </span>
                      ))}
                      {path.path.length > 5 && (
                        <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>+{path.path.length - 5}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Affected models */}
          {result.affected_models.length > 0 && (
            <div>
              <div className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--muted)' }}>
                Affected Models ({result.affected_models.length})
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {result.affected_models.slice(0, 10).map((model, idx) => (
                  <button
                    key={idx}
                    onClick={() => onSelect(model.id)}
                    className="w-full flex items-center justify-between p-2 rounded border text-xs hover:border-[var(--border-strong)]"
                    style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}
                  >
                    <span className="truncate max-w-[180px]" style={{ color: 'var(--fg-2)' }}>{model.id}</span>
                    <span className={cn(
                      'font-mono',
                      model.propagated_risk > 0.5 ? 'text-red-400' : model.propagated_risk > 0.3 ? 'text-orange-400' : 'text-yellow-400'
                    )}>
                      {(model.propagated_risk * 100).toFixed(0)}%
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
