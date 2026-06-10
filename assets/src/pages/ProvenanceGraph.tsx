import { useState, useEffect, useCallback, useRef } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Search, RefreshCw, Download, AlertTriangle, Activity, Cpu,
  Globe, File, Settings, Users, Server, ChevronRight,
  X, ZoomIn, ZoomOut, Maximize2, Eye, GitBranch, Target,
  Shield, Layers, ArrowLeft, ArrowRight, Crosshair,
  Info, Filter, Clock
} from 'lucide-react'
import { cn, formatDate, safeInitial } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ProvenanceGraphProps {
  agents: AgentSummary[]
}

interface AgentSummary {
  id: string
  hostname: string
  status: string
}

type EntityType = 'process' | 'file' | 'network' | 'registry' | 'user' | 'domain'
type ViewMode = 'chain' | 'impact' | 'context'

interface ProvenanceNode {
  id: string
  entity_type: EntityType
  label: string
  properties: Record<string, unknown>
  timestamp?: string
  risk_score?: number
}

interface ProvenanceEdge {
  source: string
  target: string
  relationship: string
  timestamp?: string
  properties?: Record<string, unknown>
}

interface GraphData {
  nodes: ProvenanceNode[]
  edges: ProvenanceEdge[]
}

interface AttackChain {
  id: string
  pattern: string
  technique_id: string
  technique_name: string
  confidence: number
  entities: string[]
  description: string
}

interface BlameResult {
  root_cause: ProvenanceNode
  confidence: number
  chain: ProvenanceNode[]
  explanation: string
}

interface GraphStats {
  total_nodes: number
  total_edges: number
  connected_components: number
  node_types: Record<string, number>
  edge_types: Record<string, number>
}

// Internal layout positions
interface LayoutNode extends ProvenanceNode {
  x: number
  y: number
  vx: number
  vy: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ENTITY_COLORS: Record<EntityType, string> = {
  process: '#3b82f6',   // blue
  file: '#22c55e',      // green
  network: '#f97316',   // orange
  registry: '#a855f7',  // purple
  user: '#eab308',      // yellow
  domain: '#06b6d4',    // cyan
}

const ENTITY_BG_CLASSES: Record<EntityType, string> = {
  process: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  file: 'bg-green-500/20 text-green-400 border-green-500/30',
  network: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  registry: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  user: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  domain: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
}

const ENTITY_ICONS: Record<EntityType, React.ElementType> = {
  process: Cpu,
  file: File,
  network: Globe,
  registry: Settings,
  user: Users,
  domain: Server,
}

const ENTITY_LABELS: Record<EntityType, string> = {
  process: 'Process',
  file: 'File',
  network: 'Network',
  registry: 'Registry',
  user: 'User',
  domain: 'Domain',
}

const NODE_RADIUS = 20
const ARROW_SIZE = 8

// ---------------------------------------------------------------------------
// Force-directed layout simulation
// ---------------------------------------------------------------------------

function initializePositions(nodes: ProvenanceNode[], width: number, height: number): LayoutNode[] {
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
  edges: ProvenanceEdge[],
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
      // Clamp within bounds
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
  edges: ProvenanceEdge[],
  selectedNodeId: string | null,
  hoveredNodeId: string | null,
  zoom: number,
  pan: { x: number; y: number },
  width: number,
  height: number,
  entityTypeFilter: Set<EntityType>
) {
  ctx.clearRect(0, 0, width, height)
  ctx.save()
  ctx.translate(pan.x, pan.y)
  ctx.scale(zoom, zoom)

  const nodeMap = new Map<string, LayoutNode>()
  nodes.forEach(n => nodeMap.set(n.id, n))

  // Filter visible nodes
  const visibleNodes = nodes.filter(n => entityTypeFilter.size === 0 || entityTypeFilter.has(n.entity_type))
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

    // Edge line
    ctx.beginPath()
    ctx.moveTo(startX, startY)
    ctx.lineTo(endX, endY)
    ctx.strokeStyle = isHighlighted ? '#94a3b8' : '#475569'
    ctx.lineWidth = isHighlighted ? 2 : 1
    ctx.stroke()

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
    ctx.fillStyle = isHighlighted ? '#94a3b8' : '#475569'
    ctx.fill()

    // Edge label
    if (isHighlighted && edge.relationship) {
      const midX = (startX + endX) / 2
      const midY = (startY + endY) / 2
      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.fillStyle = '#94a3b8'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'bottom'
      ctx.fillText(edge.relationship, midX, midY - 4)
    }
  }

  // Draw nodes
  for (const node of visibleNodes) {
    const isSelected = node.id === selectedNodeId
    const isHovered = node.id === hoveredNodeId
    const color = ENTITY_COLORS[node.entity_type] || '#64748b'

    // Glow for selected/hovered
    if (isSelected || isHovered) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, NODE_RADIUS + 6, 0, Math.PI * 2)
      ctx.fillStyle = color + '33'
      ctx.fill()
    }

    // Risk score ring
    if (node.risk_score != null && node.risk_score > 50) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, NODE_RADIUS + 3, 0, Math.PI * 2)
      ctx.strokeStyle = node.risk_score > 80 ? '#ef4444' : node.risk_score > 60 ? '#f97316' : '#eab308'
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

    // Icon letter (first char of type)
    ctx.font = 'bold 14px Inter, system-ui, sans-serif'
    ctx.fillStyle = '#ffffff'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    const letter = safeInitial(node.entity_type)
    ctx.fillText(letter, node.x, node.y)

    // Label
    ctx.font = '11px Inter, system-ui, sans-serif'
    ctx.fillStyle = isSelected ? '#ffffff' : '#cbd5e1'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    const label = node.label.length > 20 ? node.label.substring(0, 18) + '..' : node.label
    ctx.fillText(label, node.x, node.y + NODE_RADIUS + 4)
  }

  ctx.restore()
}

// ---------------------------------------------------------------------------
// Helper: hit test for mouse interaction
// ---------------------------------------------------------------------------

function hitTestNode(
  nodes: LayoutNode[],
  mx: number,
  my: number,
  zoom: number,
  pan: { x: number; y: number },
  entityTypeFilter: Set<EntityType>
): LayoutNode | null {
  // Transform mouse coords to graph space
  const gx = (mx - pan.x) / zoom
  const gy = (my - pan.y) / zoom

  for (let i = nodes.length - 1; i >= 0; i--) {
    const node = nodes[i]
    if (entityTypeFilter.size > 0 && !entityTypeFilter.has(node.entity_type)) continue
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

export default function ProvenanceGraph({ agents }: ProvenanceGraphProps) {
  // --- State ---
  const [selectedAgentId, setSelectedAgentId] = useState<string>(agents[0]?.id || '')
  const [entitySearch, setEntitySearch] = useState('')
  const [viewMode, setViewMode] = useState<ViewMode>('context')
  const [maxHops, setMaxHops] = useState(3)
  const [entityTypeFilter, setEntityTypeFilter] = useState<Set<EntityType>>(new Set())

  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [layoutNodes, setLayoutNodes] = useState<LayoutNode[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [selectedNode, setSelectedNode] = useState<ProvenanceNode | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null)

  const [attackChains, setAttackChains] = useState<AttackChain[]>([])
  const [attackChainsLoading, setAttackChainsLoading] = useState(false)
  const [attackChainsError, setAttackChainsError] = useState<string | null>(null)
  const [blameResult, setBlameResult] = useState<BlameResult | null>(null)
  const [blameLoading, setBlameLoading] = useState(false)
  const [blameError, setBlameError] = useState<string | null>(null)
  const [graphStats, setGraphStats] = useState<GraphStats | null>(null)

  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })

  const [showSidebar, setShowSidebar] = useState(true)
  const [sidebarTab, setSidebarTab] = useState<'details' | 'attacks' | 'blame'>('details')
  const [showFilters, setShowFilters] = useState(false)

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 })

  // --- Resize observer ---
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

  // --- Fetch graph data ---
  const fetchGraphData = useCallback(async (entityId?: string) => {
    if (!selectedAgentId) return
    const searchId = entityId || entitySearch.trim()
    if (!searchId && viewMode !== 'context') return

    setLoading(true)
    setError(null)

    try {
      let url: string
      const params = new URLSearchParams()
      if (maxHops > 0) params.set('max_hops', String(maxHops))

      switch (viewMode) {
        case 'chain':
          url = `/api/v1/provenance/${selectedAgentId}/chain/${encodeURIComponent(searchId)}`
          break
        case 'impact':
          url = `/api/v1/provenance/${selectedAgentId}/impact/${encodeURIComponent(searchId)}`
          break
        case 'context':
        default:
          if (searchId) {
            url = `/api/v1/provenance/${selectedAgentId}/context/${encodeURIComponent(searchId)}`
          } else {
            // Without a specific entity, get stats to show summary
            url = `/api/v1/provenance/${selectedAgentId}/stats`
            const response = await fetch(url, { credentials: 'include' })
            if (!response.ok) throw new Error(`HTTP ${response.status}`)
            const result = await response.json()
            if (result.data) {
              setGraphStats(result.data)
            }
            setLoading(false)
            return
          }
          break
      }

      const qs = params.toString()
      if (qs) url += `?${qs}`

      const response = await fetch(url, { credentials: 'include' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()

      if (result.data) {
        const data: GraphData = {
          nodes: result.data.nodes || [],
          edges: result.data.edges || [],
        }
        setGraphData(data)

        // Run layout
        const positioned = initializePositions(data.nodes, canvasSize.width, canvasSize.height)
        const simulated = simulateForces(positioned, data.edges, canvasSize.width, canvasSize.height)
        setLayoutNodes(simulated)
        resetView()
      } else {
        setError(result.error || 'Failed to load provenance data')
      }
    } catch (err) {
      logger.error('Provenance fetch error:', err)
      setError('Failed to load provenance data')
    } finally {
      setLoading(false)
    }
  }, [selectedAgentId, entitySearch, viewMode, maxHops, canvasSize])

  // --- Fetch attack chains ---
  const fetchAttackChains = useCallback(async () => {
    if (!selectedAgentId) return
    setAttackChainsLoading(true)
    setAttackChainsError(null)
    try {
      const response = await fetch(
        `/api/v1/provenance/${selectedAgentId}/attack-chains`,
        { credentials: 'include' }
      )
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data) {
        setAttackChains(result.data.chains || [])
      }
    } catch (err) {
      logger.error('Attack chains fetch error:', err)
      setAttackChainsError(err instanceof Error ? err.message : 'Failed to load attack chains')
    } finally {
      setAttackChainsLoading(false)
    }
  }, [selectedAgentId])

  // --- Fetch blame ---
  const fetchBlame = useCallback(async (entityId: string) => {
    if (!selectedAgentId || !entityId) return
    setBlameLoading(true)
    setBlameResult(null)
    setBlameError(null)
    try {
      const response = await fetch(
        `/api/v1/provenance/${selectedAgentId}/blame/${encodeURIComponent(entityId)}`,
        { credentials: 'include' }
      )
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data) {
        setBlameResult(result.data)
      }
    } catch (err) {
      logger.error('Blame fetch error:', err)
      setBlameError(err instanceof Error ? err.message : 'Failed to run blame analysis')
    } finally {
      setBlameLoading(false)
    }
  }, [selectedAgentId])

  // --- Fetch stats ---
  const fetchStats = useCallback(async () => {
    if (!selectedAgentId) return
    try {
      const response = await fetch(
        `/api/v1/provenance/${selectedAgentId}/stats`,
        { credentials: 'include' }
      )
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.data) {
        setGraphStats(result.data)
      }
    } catch (err) {
      logger.error('Stats fetch error:', err)
      // Stats are supplementary -- do not block the UI for a stats fetch failure
    }
  }, [selectedAgentId])

  // --- Load stats on agent change ---
  useEffect(() => {
    if (selectedAgentId) {
      fetchStats()
    }
  }, [selectedAgentId, fetchStats])

  // --- Canvas rendering ---
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Set canvas resolution for HiDPI
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
      entityTypeFilter
    )
  }, [layoutNodes, graphData, selectedNode, hoveredNodeId, zoom, pan, canvasSize, entityTypeFilter])

  // --- Mouse handlers ---
  const handleCanvasMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top

    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, entityTypeFilter)
    if (hit) {
      setSelectedNode(hit)
      setSidebarTab('details')
      setShowSidebar(true)
    } else {
      setIsPanning(true)
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
    }
  }, [layoutNodes, zoom, pan, entityTypeFilter])

  const handleCanvasMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isPanning) {
      setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y })
      return
    }

    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, entityTypeFilter)
    setHoveredNodeId(hit?.id || null)

    if (canvasRef.current) {
      canvasRef.current.style.cursor = hit ? 'pointer' : isPanning ? 'grabbing' : 'grab'
    }
  }, [isPanning, panStart, layoutNodes, zoom, pan, entityTypeFilter])

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
    const hit = hitTestNode(layoutNodes, mx, my, zoom, pan, entityTypeFilter)
    if (hit) {
      // Navigate into this entity
      setEntitySearch(hit.id)
      fetchGraphData(hit.id)
    }
  }, [layoutNodes, zoom, pan, entityTypeFilter, fetchGraphData])

  // --- View controls ---
  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
  }, [])

  const zoomIn = useCallback(() => {
    setZoom(z => Math.min(5, z * 1.2))
  }, [])

  const zoomOut = useCallback(() => {
    setZoom(z => Math.max(0.1, z / 1.2))
  }, [])

  // --- Entity type filter toggle ---
  const toggleEntityFilter = useCallback((type: EntityType) => {
    setEntityTypeFilter(prev => {
      const next = new Set(prev)
      if (next.has(type)) {
        next.delete(type)
      } else {
        next.add(type)
      }
      return next
    })
  }, [])

  // --- Export ---
  const exportGraph = useCallback((format: 'svg' | 'png') => {
    const canvas = canvasRef.current
    if (!canvas) return

    if (format === 'png') {
      const link = document.createElement('a')
      link.download = `provenance-graph-${selectedAgentId}.png`
      link.href = canvas.toDataURL('image/png')
      link.click()
    } else {
      // SVG export: generate an SVG string from current state
      const svgParts: string[] = []
      svgParts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${canvasSize.width}" height="${canvasSize.height}" viewBox="0 0 ${canvasSize.width} ${canvasSize.height}">`)
      svgParts.push(`<rect width="100%" height="100%" fill="#0f172a"/>`)

      const nodeMap = new Map<string, LayoutNode>()
      layoutNodes.forEach(n => nodeMap.set(n.id, n))

      // Edges
      if (graphData) {
        for (const edge of graphData.edges) {
          const s = nodeMap.get(edge.source)
          const t = nodeMap.get(edge.target)
          if (!s || !t) continue
          svgParts.push(`<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="#475569" stroke-width="1" marker-end="url(#arrow)"/>`)
        }
      }

      // Arrow marker
      svgParts.push(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#475569"/></marker></defs>`)

      // Nodes
      for (const node of layoutNodes) {
        const color = ENTITY_COLORS[node.entity_type] || '#64748b'
        svgParts.push(`<circle cx="${node.x}" cy="${node.y}" r="${NODE_RADIUS}" fill="${color}" stroke="${color}" stroke-width="1.5"/>`)
        svgParts.push(`<text x="${node.x}" y="${node.y + 4}" text-anchor="middle" fill="white" font-size="14" font-weight="bold">${safeInitial(node.entity_type)}</text>`)
        svgParts.push(`<text x="${node.x}" y="${node.y + NODE_RADIUS + 14}" text-anchor="middle" fill="#cbd5e1" font-size="11">${escapeXml(node.label.substring(0, 20))}</text>`)
      }

      svgParts.push('</svg>')

      const blob = new Blob([svgParts.join('')], { type: 'image/svg+xml' })
      const link = document.createElement('a')
      link.download = `provenance-graph-${selectedAgentId}.svg`
      link.href = URL.createObjectURL(blob)
      link.click()
      URL.revokeObjectURL(link.href)
    }
  }, [canvasSize, layoutNodes, graphData, selectedAgentId])

  // --- Search submit ---
  const handleSearch = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    fetchGraphData()
  }, [fetchGraphData])

  // --- Computed stats ---
  const nodeCount = graphData?.nodes.length || 0
  const edgeCount = graphData?.edges.length || 0

  return (
    <MainLayout title="Provenance Graph">
      <Head title="Provenance Graph - Tamandua EDR" />

      <div className="flex flex-col h-[calc(100vh-64px)]">
        {/* Top Control Bar */}
        <div className="px-4 py-3" style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-4 flex-wrap">
            {/* Agent selector */}
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium" style={{ color: 'var(--muted)' }}>Agent</label>
              <select
                value={selectedAgentId}
                onChange={e => setSelectedAgentId(e.target.value)}
                className="rounded px-3 py-1.5 text-sm min-w-[180px]"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg)' }}
              >
                {agents.length === 0 && <option value="">No agents</option>}
                {agents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.hostname} ({a.status})
                  </option>
                ))}
              </select>
            </div>

            {/* Entity search */}
            <form onSubmit={handleSearch} className="flex items-center gap-2 flex-1 max-w-md">
              <div className="relative flex-1">
                <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--subtle)' }} />
                <input
                  type="text"
                  value={entitySearch}
                  onChange={e => setEntitySearch(e.target.value)}
                  placeholder="Entity ID or name..."
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

            {/* View mode toggle */}
            <div className="flex items-center rounded overflow-hidden" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
              <button
                onClick={() => setViewMode('chain')}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  viewMode === 'chain' ? 'bg-blue-600 text-white' : 'hover:bg-[var(--surface-3)]'
                )}
                style={viewMode !== 'chain' ? { color: 'var(--muted)' } : undefined}
                title="Backward provenance chain"
              >
                <ArrowLeft size={12} />
                Chain
              </button>
              <button
                onClick={() => setViewMode('impact')}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  viewMode === 'impact' ? 'bg-blue-600 text-white' : 'hover:bg-[var(--surface-3)]'
                )}
                style={viewMode !== 'impact' ? { color: 'var(--muted)' } : undefined}
                title="Forward impact graph"
              >
                <ArrowRight size={12} />
                Impact
              </button>
              <button
                onClick={() => setViewMode('context')}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  viewMode === 'context' ? 'bg-blue-600 text-white' : 'hover:bg-[var(--surface-3)]'
                )}
                style={viewMode !== 'context' ? { color: 'var(--muted)' } : undefined}
                title="N-hop neighborhood"
              >
                <Crosshair size={12} />
                Context
              </button>
            </div>

            {/* Max hops slider */}
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium whitespace-nowrap" style={{ color: 'var(--muted)' }}>Hops: {maxHops}</label>
              <input
                type="range"
                min={1}
                max={10}
                value={maxHops}
                onChange={e => setMaxHops(Number(e.target.value))}
                className="w-24 accent-blue-500"
              />
            </div>

            {/* Filter button */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                'p-1.5 rounded transition-colors',
                showFilters ? 'bg-blue-600 text-white' : ''
              )}
              style={!showFilters ? { background: 'var(--surface-2)', color: 'var(--muted)' } : undefined}
              title="Filter by entity type"
            >
              <Filter size={16} />
            </button>

            {/* Actions */}
            <div className="flex items-center gap-1 ml-auto">
              <button
                onClick={() => fetchAttackChains()}
                className="px-3 py-1.5 text-xs font-medium rounded transition-colors flex items-center gap-1.5 hover:bg-[var(--surface-3)]"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                disabled={attackChainsLoading}
                title="Detect attack chains"
              >
                <Shield size={12} />
                Attack Chains
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

          {/* Entity type filter row */}
          {showFilters && (
            <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
              <span className="text-xs mr-1" style={{ color: 'var(--subtle)' }}>Filter types:</span>
              {(Object.keys(ENTITY_COLORS) as EntityType[]).map(type => {
                const Icon = ENTITY_ICONS[type]
                const active = entityTypeFilter.size === 0 || entityTypeFilter.has(type)
                return (
                  <button
                    key={type}
                    onClick={() => toggleEntityFilter(type)}
                    className={cn(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors',
                      active ? ENTITY_BG_CLASSES[type] : ''
                    )}
                    style={!active ? { background: 'var(--surface-2)', color: 'var(--subtle)', borderColor: 'var(--border)' } : undefined}
                  >
                    <Icon size={12} />
                    {ENTITY_LABELS[type]}
                  </button>
                )
              })}
              {entityTypeFilter.size > 0 && (
                <button
                  onClick={() => setEntityTypeFilter(new Set())}
                  className="text-xs ml-2 hover:text-[var(--fg-2)]"
                  style={{ color: 'var(--subtle)' }}
                >
                  Clear filters
                </button>
              )}
            </div>
          )}
        </div>

        {/* Main content area */}
        <div className="flex flex-1 overflow-hidden">
          {/* Graph canvas */}
          <div ref={containerRef} className="flex-1 relative" style={{ background: 'var(--bg)' }}>
            {loading ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center">
                  <RefreshCw size={32} className="text-blue-400 animate-spin mx-auto mb-4" />
                  <p style={{ color: 'var(--muted)' }}>Loading provenance graph...</p>
                </div>
              </div>
            ) : error ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center rounded-lg p-6 max-w-sm" style={{ background: 'var(--surface)' }}>
                  <AlertTriangle size={32} className="text-red-400 mx-auto mb-3" />
                  <p className="mb-3" style={{ color: 'var(--fg-2)' }}>{error}</p>
                  <button
                    onClick={() => fetchGraphData()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm text-white transition-colors"
                  >
                    Retry
                  </button>
                </div>
              </div>
            ) : graphData && graphData.nodes.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center">
                  <GitBranch size={48} className="mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                  <p style={{ color: 'var(--subtle)' }}>No provenance data found.</p>
                  <p className="text-sm mt-1" style={{ color: 'var(--dim)' }}>Search for an entity to explore the provenance graph.</p>
                </div>
              </div>
            ) : !graphData ? (
              <div className="absolute inset-0 flex items-center justify-center z-10">
                <div className="text-center max-w-md">
                  <GitBranch size={48} className="mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                  <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg-2)' }}>Provenance Graph</h3>
                  <p className="text-sm mb-4" style={{ color: 'var(--subtle)' }}>
                    Search for an entity (process PID, file path, IP address) to visualize
                    causal relationships and trace attack provenance.
                  </p>
                  {graphStats && (
                    <div className="card-sentinel rounded-lg p-4 text-left">
                      <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--fg-2)' }}>Graph Statistics</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <span style={{ color: 'var(--subtle)' }}>Total Nodes:</span>
                        <span className="font-mono" style={{ color: 'var(--fg)' }}>{graphStats.total_nodes?.toLocaleString() || 0}</span>
                        <span style={{ color: 'var(--subtle)' }}>Total Edges:</span>
                        <span className="font-mono" style={{ color: 'var(--fg)' }}>{graphStats.total_edges?.toLocaleString() || 0}</span>
                        <span style={{ color: 'var(--subtle)' }}>Components:</span>
                        <span className="font-mono" style={{ color: 'var(--fg)' }}>{graphStats.connected_components?.toLocaleString() || 0}</span>
                      </div>
                      {graphStats.node_types && Object.keys(graphStats.node_types).length > 0 && (
                        <div className="mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                          <div className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>Node Types</div>
                          <div className="flex flex-wrap gap-2">
                            {Object.entries(graphStats.node_types).map(([type, count]) => {
                              const color = ENTITY_COLORS[type as EntityType] || '#64748b'
                              return (
                                <span
                                  key={type}
                                  className="text-xs px-2 py-0.5 rounded border"
                                  style={{ borderColor: color + '66', color, backgroundColor: color + '1a' }}
                                >
                                  {type}: {(count as number).toLocaleString()}
                                </span>
                              )
                            })}
                          </div>
                        </div>
                      )}
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
              <button onClick={zoomIn} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }} title="Zoom in">
                <ZoomIn size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
              <button onClick={zoomOut} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }} title="Zoom out">
                <ZoomOut size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
              <button onClick={resetView} className="p-2 rounded hover:bg-[var(--surface-2)] transition-colors" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }} title="Reset view">
                <Maximize2 size={16} style={{ color: 'var(--fg-2)' }} />
              </button>
            </div>

            {/* Export controls */}
            <div className="absolute top-4 right-4 flex gap-1 z-10">
              <button
                onClick={() => exportGraph('png')}
                className="px-2.5 py-1.5 rounded text-xs transition-colors flex items-center gap-1 hover:bg-[var(--surface-2)]"
                style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
              >
                <Download size={12} />
                PNG
              </button>
              <button
                onClick={() => exportGraph('svg')}
                className="px-2.5 py-1.5 rounded text-xs transition-colors flex items-center gap-1 hover:bg-[var(--surface-2)]"
                style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
              >
                <Download size={12} />
                SVG
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
                  <span style={{ color: 'var(--subtle)' }}>View:</span>
                  <span className="text-blue-400 font-medium capitalize">{viewMode}</span>
                  <span style={{ color: 'var(--subtle)' }}>Zoom:</span>
                  <span className="font-medium" style={{ color: 'var(--fg-2)' }}>{(zoom * 100).toFixed(0)}%</span>
                </div>
                {/* Mini legend */}
                <div className="mt-2 pt-2 flex flex-wrap gap-1.5" style={{ borderTop: '1px solid var(--border)' }}>
                  {(Object.keys(ENTITY_COLORS) as EntityType[]).map(type => (
                    <span key={type} className="flex items-center gap-1">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: ENTITY_COLORS[type] }}
                      />
                      <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{ENTITY_LABELS[type]}</span>
                    </span>
                  ))}
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
                  Node Details
                </button>
                <button
                  onClick={() => { setSidebarTab('attacks'); if (attackChains.length === 0) fetchAttackChains() }}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors relative',
                    sidebarTab === 'attacks' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'attacks' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Attack Chains
                  {attackChains.length > 0 && (
                    <span className="ml-1.5 bg-red-500/20 text-red-400 text-[10px] px-1.5 py-0.5 rounded-full">
                      {attackChains.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setSidebarTab('blame')}
                  className={cn(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors',
                    sidebarTab === 'blame' ? 'border-b-2 border-blue-500' : 'hover:text-[var(--fg-2)]'
                  )}
                  style={{ color: sidebarTab === 'blame' ? 'var(--fg)' : 'var(--subtle)' }}
                >
                  Blame
                </button>
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-y-auto">
                {sidebarTab === 'details' && (
                  <NodeDetailsPanel
                    node={selectedNode}
                    onClose={() => setSelectedNode(null)}
                    onExploreEntity={(entityId) => {
                      setEntitySearch(entityId)
                      fetchGraphData(entityId)
                    }}
                    onBlame={(entityId) => {
                      fetchBlame(entityId)
                      setSidebarTab('blame')
                    }}
                  />
                )}

                {sidebarTab === 'attacks' && (
                  <AttackChainsPanel
                    chains={attackChains}
                    loading={attackChainsLoading}
                    error={attackChainsError}
                    onRefresh={fetchAttackChains}
                    onSelectEntity={(entityId) => {
                      setEntitySearch(entityId)
                      fetchGraphData(entityId)
                    }}
                  />
                )}

                {sidebarTab === 'blame' && (
                  <BlamePanel
                    result={blameResult}
                    loading={blameLoading}
                    error={blameError}
                    selectedNode={selectedNode}
                    onBlame={(entityId) => fetchBlame(entityId)}
                    onSelectEntity={(entityId) => {
                      setEntitySearch(entityId)
                      fetchGraphData(entityId)
                    }}
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
  onExploreEntity,
  onBlame,
}: {
  node: ProvenanceNode | null
  onClose: () => void
  onExploreEntity: (entityId: string) => void
  onBlame: (entityId: string) => void
}) {
  if (!node) {
    return (
      <div className="p-6 text-center">
        <Eye size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
        <p className="text-sm" style={{ color: 'var(--subtle)' }}>Click a node on the graph to see its details.</p>
      </div>
    )
  }

  const Icon = ENTITY_ICONS[node.entity_type] || Activity
  const riskColor = !node.risk_score ? 'var(--subtle)'
    : node.risk_score > 80 ? '#ef4444'
    : node.risk_score > 60 ? '#f97316'
    : node.risk_score > 40 ? '#eab308'
    : '#22c55e'

  return (
    <div className="p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className={cn('p-2 rounded-lg border', ENTITY_BG_CLASSES[node.entity_type])}>
            <Icon size={16} />
          </div>
          <div>
            <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{node.label}</div>
            <div className="text-xs capitalize" style={{ color: 'var(--subtle)' }}>{node.entity_type}</div>
          </div>
        </div>
        <button onClick={onClose} className="p-1 hover:bg-[var(--surface-2)] rounded transition-colors">
          <X size={16} style={{ color: 'var(--subtle)' }} />
        </button>
      </div>

      {/* Risk score */}
      {node.risk_score != null && (
        <div className="card-sentinel rounded-lg p-3 mb-4">
          <div className="flex items-center justify-between">
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>Risk Score</span>
            <span className="text-lg font-bold font-mono" style={{ color: riskColor }}>{node.risk_score}</span>
          </div>
          <div className="mt-2 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
            <div
              className={cn(
                'h-full rounded-full transition-all',
                node.risk_score > 80 ? 'bg-red-500' : node.risk_score > 60 ? 'bg-orange-500' : node.risk_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
              )}
              style={{ width: `${Math.min(100, node.risk_score)}%` }}
            />
          </div>
        </div>
      )}

      {/* Timestamp */}
      {node.timestamp && (
        <div className="flex items-center gap-2 text-xs mb-4" style={{ color: 'var(--subtle)' }}>
          <Clock size={12} />
          {formatDate(node.timestamp)}
        </div>
      )}

      {/* Properties */}
      <div className="space-y-2 mb-4">
        <div className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Properties</div>
        {Object.entries(node.properties).map(([key, value]) => (
          <div key={key} className="flex justify-between text-sm py-1" style={{ borderBottom: '1px solid var(--hairline)' }}>
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>{key}</span>
            <span className="text-xs font-mono truncate max-w-[200px]" style={{ color: 'var(--fg-2)' }} title={String(value)}>
              {String(value)}
            </span>
          </div>
        ))}
        {Object.keys(node.properties).length === 0 && (
          <p className="text-xs" style={{ color: 'var(--dim)' }}>No properties available</p>
        )}
      </div>

      {/* Entity ID */}
      <div className="mb-4">
        <div className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--muted)' }}>Entity ID</div>
        <code className="text-xs px-2 py-1 rounded block truncate font-mono" style={{ background: 'var(--bg)', color: 'var(--fg-2)' }}>
          {node.id}
        </code>
      </div>

      {/* Actions */}
      <div className="flex flex-col gap-2">
        <button
          onClick={() => onExploreEntity(node.id)}
          className="w-full px-3 py-2 bg-blue-600/20 border border-blue-500/30 rounded text-xs text-blue-400 hover:bg-blue-600/30 transition-colors flex items-center justify-center gap-2"
        >
          <Crosshair size={12} />
          Explore Context
        </button>
        <button
          onClick={() => onBlame(node.id)}
          className="w-full px-3 py-2 bg-orange-600/20 border border-orange-500/30 rounded text-xs text-orange-400 hover:bg-orange-600/30 transition-colors flex items-center justify-center gap-2"
        >
          <Target size={12} />
          Run Blame Analysis
        </button>
      </div>
    </div>
  )
}

function AttackChainsPanel({
  chains,
  loading,
  error,
  onRefresh,
  onSelectEntity,
}: {
  chains: AttackChain[]
  loading: boolean
  error: string | null
  onRefresh: () => void
  onSelectEntity: (entityId: string) => void
}) {
  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Attack Chain Detection</h3>
        <button
          onClick={onRefresh}
          className="p-1 hover:bg-[var(--surface-2)] rounded transition-colors"
          disabled={loading}
        >
          <RefreshCw size={14} className={cn(loading && 'animate-spin')} style={{ color: 'var(--muted)' }} />
        </button>
      </div>

      {loading ? (
        <div className="text-center py-8">
          <RefreshCw size={24} className="text-blue-400 animate-spin mx-auto mb-3" />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>Analyzing attack chains...</p>
        </div>
      ) : error ? (
        <div className="text-center py-8">
          <AlertTriangle size={32} className="text-red-400 mx-auto mb-3" />
          <p className="text-sm text-red-400 mb-3">{error}</p>
          <button
            onClick={onRefresh}
            className="px-3 py-1.5 rounded text-xs transition-colors hover:bg-[var(--surface-3)]"
            style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
          >
            Retry
          </button>
        </div>
      ) : chains.length === 0 ? (
        <div className="text-center py-8">
          <Shield size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>No attack chains detected.</p>
          <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>Click refresh to re-analyze.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {chains.map((chain, idx) => (
            <div
              key={chain.id || idx}
              className="card-sentinel rounded-lg p-3"
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{chain.pattern}</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>{chain.description}</div>
                </div>
              </div>

              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded border border-red-500/30 font-mono">
                  {chain.technique_id}
                </span>
                <span className="text-xs" style={{ color: 'var(--muted)' }}>{chain.technique_name}</span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1">
                  <span style={{ color: 'var(--subtle)' }}>Confidence:</span>
                  <span className={cn(
                    'font-mono font-medium',
                    chain.confidence > 0.8 ? 'text-red-400' : chain.confidence > 0.5 ? 'text-orange-400' : 'text-yellow-400'
                  )}>
                    {(chain.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <span style={{ color: 'var(--dim)' }}>{chain.entities.length} entities</span>
              </div>

              {chain.entities.length > 0 && (
                <div className="mt-2 pt-2 flex flex-wrap gap-1" style={{ borderTop: '1px solid var(--border)' }}>
                  {chain.entities.slice(0, 5).map((eid, i) => (
                    <button
                      key={i}
                      onClick={() => onSelectEntity(eid)}
                      className="text-[10px] px-1.5 py-0.5 rounded transition-colors font-mono truncate max-w-[120px] hover:text-blue-400 hover:bg-[var(--surface-3)]"
                      style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
                      title={eid}
                    >
                      {eid}
                    </button>
                  ))}
                  {chain.entities.length > 5 && (
                    <span className="text-[10px] px-1.5 py-0.5" style={{ color: 'var(--dim)' }}>
                      +{chain.entities.length - 5} more
                    </span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function BlamePanel({
  result,
  loading,
  error,
  selectedNode,
  onBlame,
  onSelectEntity,
}: {
  result: BlameResult | null
  loading: boolean
  error: string | null
  selectedNode: ProvenanceNode | null
  onBlame: (entityId: string) => void
  onSelectEntity: (entityId: string) => void
}) {
  return (
    <div className="p-4">
      <h3 className="text-sm font-medium mb-4" style={{ color: 'var(--fg)' }}>Root Cause Analysis</h3>

      {!result && !loading && !error && (
        <div className="text-center py-8">
          <Target size={32} className="mx-auto mb-3" style={{ color: 'var(--subtle)' }} />
          <p className="text-sm mb-3" style={{ color: 'var(--subtle)' }}>
            Select a node and click "Run Blame Analysis" to trace root cause.
          </p>
          {selectedNode && (
            <button
              onClick={() => onBlame(selectedNode.id)}
              className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white text-sm rounded transition-colors"
            >
              Analyze: {selectedNode.label}
            </button>
          )}
        </div>
      )}

      {loading && (
        <div className="text-center py-8">
          <RefreshCw size={24} className="text-orange-400 animate-spin mx-auto mb-3" />
          <p className="text-sm" style={{ color: 'var(--subtle)' }}>Tracing root cause...</p>
        </div>
      )}

      {error && !loading && (
        <div className="text-center py-8">
          <AlertTriangle size={32} className="text-red-400 mx-auto mb-3" />
          <p className="text-sm text-red-400 mb-3">{error}</p>
          {selectedNode && (
            <button
              onClick={() => onBlame(selectedNode.id)}
              className="px-3 py-1.5 rounded text-xs transition-colors hover:bg-[var(--surface-3)]"
              style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
            >
              Retry
            </button>
          )}
        </div>
      )}

      {result && !loading && (
        <div className="space-y-4">
          {/* Root cause */}
          <div className="rounded-lg border border-orange-500/30 p-3" style={{ background: 'var(--bg)' }}>
            <div className="flex items-center gap-2 mb-2">
              <Target size={14} className="text-orange-400" />
              <span className="text-xs font-medium text-orange-400 uppercase tracking-wider">Root Cause</span>
            </div>
            <div className="text-sm font-medium mb-1" style={{ color: 'var(--fg)' }}>{result.root_cause.label}</div>
            <div className="text-xs capitalize mb-2" style={{ color: 'var(--subtle)' }}>{result.root_cause.entity_type}</div>

            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1">
                <span style={{ color: 'var(--subtle)' }}>Confidence:</span>
                <span className={cn(
                  'font-mono font-medium',
                  result.confidence > 0.8 ? 'text-green-400' : result.confidence > 0.5 ? 'text-yellow-400' : 'text-orange-400'
                )}>
                  {(result.confidence * 100).toFixed(0)}%
                </span>
              </div>
            </div>

            <button
              onClick={() => onSelectEntity(result.root_cause.id)}
              className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Explore entity
            </button>
          </div>

          {/* Explanation */}
          {result.explanation && (
            <div className="card-sentinel rounded-lg p-3">
              <div className="flex items-center gap-2 mb-2">
                <Info size={14} style={{ color: 'var(--muted)' }} />
                <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--muted)' }}>Analysis</span>
              </div>
              <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{result.explanation}</p>
            </div>
          )}

          {/* Causal chain */}
          {result.chain && result.chain.length > 0 && (
            <div>
              <div className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--muted)' }}>Causal Chain</div>
              <div className="space-y-1">
                {result.chain.map((node, idx) => {
                  const Icon = ENTITY_ICONS[node.entity_type] || Activity
                  return (
                    <div key={node.id} className="flex items-center gap-2">
                      {idx > 0 && (
                        <div className="w-4 flex justify-center">
                          <ChevronRight size={10} style={{ color: 'var(--subtle)' }} />
                        </div>
                      )}
                      <button
                        onClick={() => onSelectEntity(node.id)}
                        className={cn(
                          'flex items-center gap-2 px-2 py-1.5 rounded text-xs w-full text-left border transition-colors',
                          idx === 0 ? 'bg-orange-500/10 border-orange-500/30 text-orange-300' : 'hover:border-[var(--border-strong)]'
                        )}
                        style={idx !== 0 ? { background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg-2)' } : undefined}
                      >
                        <Icon size={12} />
                        <span className="truncate">{node.label}</span>
                        <span className="text-[10px] ml-auto capitalize" style={{ color: 'var(--dim)' }}>{node.entity_type}</span>
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}
