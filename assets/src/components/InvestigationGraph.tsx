import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Cpu, Globe, File, Server, Settings,
  ZoomIn, ZoomOut, Maximize2, RefreshCw,
  AlertTriangle, X, Filter, Play, Pause, SkipBack, SkipForward, Activity
} from 'lucide-react';
import { GraphNode, GraphEdge, GraphNodeType, GraphSeverity } from '@/types';

interface InvestigationGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNodeId?: string;
  onNodeClick?: (node: GraphNode) => void;
  onNodeDoubleClick?: (node: GraphNode) => void;
  className?: string;
}

interface NodePosition {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

type GraphPhase = 'active' | 'entering' | 'future';

const NODE_COLORS: Record<GraphNodeType, string> = {
  process: '#3b82f6',  // blue
  network: '#22c55e',  // green
  file: '#f59e0b',     // amber
  dns: '#8b5cf6',      // violet
  registry: '#ef4444', // red
};

const NODE_COLOR_CLASSES: Record<GraphNodeType, string> = {
  process: 'text-blue-400 bg-blue-400/10 border-blue-500/30',
  network: 'text-green-400 bg-green-400/10 border-green-500/30',
  file: 'text-amber-400 bg-amber-400/10 border-amber-500/30',
  dns: 'text-violet-400 bg-violet-400/10 border-violet-500/30',
  registry: 'text-red-400 bg-red-400/10 border-red-500/30',
};

const SEVERITY_COLORS: Record<GraphSeverity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
};

const NODE_ICONS: Record<GraphNodeType, typeof Cpu> = {
  process: Cpu,
  network: Globe,
  file: File,
  dns: Server,
  registry: Settings,
};

const NODE_SHAPES: Record<GraphNodeType, 'circle' | 'diamond' | 'hexagon' | 'square' | 'triangle'> = {
  process: 'circle',
  network: 'diamond',
  file: 'square',
  dns: 'hexagon',
  registry: 'triangle',
};

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function timestampToMs(value: unknown): number | null {
  if (!value) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const parsed = new Date(String(value)).getTime();
  return Number.isNaN(parsed) ? null : parsed;
}

function nodeTimestamp(node: GraphNode): number | null {
  return timestampToMs(node.data?.timestamp || node.data?.start_time || node.data?.created_at);
}

function edgeTimestamp(edge: GraphEdge, source?: GraphNode, target?: GraphNode): number | null {
  return timestampToMs(edge.timestamp) || (source ? nodeTimestamp(source) : null) || (target ? nodeTimestamp(target) : null);
}

function compactTime(ms: number | null): string {
  if (!ms) return 'unknown';
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function InvestigationGraph({
  nodes,
  edges,
  selectedNodeId,
  onNodeClick,
  onNodeDoubleClick,
  className = '',
}: InvestigationGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [positions, setPositions] = useState<Map<string, NodePosition>>(new Map());
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const animationRef = useRef<number>();

  // Filtering state
  const [typeFilters, setTypeFilters] = useState<Set<GraphNodeType>>(
    new Set(['process', 'network', 'file', 'dns', 'registry'])
  );
  const [showFilterPanel, setShowFilterPanel] = useState(false);

  // Timeline slider state
  const [timelineEnabled, setTimelineEnabled] = useState(false);
  const [timelineValue, setTimelineValue] = useState(100); // 0-100 percentage
  const [timelinePlaying, setTimelinePlaying] = useState(false);

  // Detail panel state
  const [detailNode, setDetailNode] = useState<GraphNode | null>(null);

  // Compute time range from nodes and edges
  const timeRange = useMemo(() => {
    const timestamps: number[] = [];
    nodes.forEach(node => {
      const num = nodeTimestamp(node);
      if (num) timestamps.push(num);
    });
    edges.forEach(edge => {
      const num = timestampToMs(edge.timestamp);
      if (num) timestamps.push(num);
    });
    if (timestamps.length === 0) return { min: 0, max: Date.now() };
    return { min: Math.min(...timestamps), max: Math.max(...timestamps) };
  }, [nodes, edges]);

  const timelineCutoff = useMemo(() => {
    if (!timelineEnabled) return timeRange.max;
    return timeRange.min + ((timeRange.max - timeRange.min) * timelineValue / 100);
  }, [timelineEnabled, timelineValue, timeRange]);

  const typeFilteredNodes = useMemo(() => {
    return nodes.filter(node => typeFilters.has(node.type));
  }, [nodes, typeFilters]);

  const typeFilteredNodeIds = useMemo(
    () => new Set(typeFilteredNodes.map(n => n.id)),
    [typeFilteredNodes]
  );

  // Count active nodes based on type and timeline. Future nodes are still rendered
  // as low-opacity ghosts so timeline playback has a clear appear/disappear model.
  const filteredNodes = useMemo(() => {
    if (!timelineEnabled) return typeFilteredNodes;

    return typeFilteredNodes.filter(node => {
      const num = nodeTimestamp(node);
      return !num || num <= timelineCutoff;
    });
  }, [typeFilteredNodes, timelineEnabled, timelineCutoff]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const visibleGraphNodes = useMemo(() => {
    return timelineEnabled ? typeFilteredNodes : filteredNodes;
  }, [timelineEnabled, typeFilteredNodes, filteredNodes]);

  const filteredEdges = useMemo(() => {
    return edges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));
  }, [edges, filteredNodeIds]);

  const visibleEdges = useMemo(() => {
    return edges.filter(e => typeFilteredNodeIds.has(e.source) && typeFilteredNodeIds.has(e.target));
  }, [edges, typeFilteredNodeIds]);

  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    nodes.forEach(node => map.set(node.id, node));
    return map;
  }, [nodes]);

  const timelineStepWindow = useMemo(() => {
    const span = Math.max(timeRange.max - timeRange.min, 1);
    return Math.max(span * 0.035, 2_000);
  }, [timeRange]);

  const getNodePhase = useCallback((node: GraphNode): GraphPhase => {
    if (!timelineEnabled) return 'active';
    const ts = nodeTimestamp(node);
    if (!ts || ts <= timelineCutoff - timelineStepWindow) return 'active';
    if (ts <= timelineCutoff) return 'entering';
    return 'future';
  }, [timelineEnabled, timelineCutoff, timelineStepWindow]);

  const currentStep = useMemo(() => {
    if (!timelineEnabled || visibleGraphNodes.length === 0) return null;

    const activeCandidates = visibleGraphNodes
      .map(node => ({ node, ts: nodeTimestamp(node) }))
      .filter((item): item is { node: GraphNode; ts: number } => Boolean(item.ts) && item.ts <= timelineCutoff)
      .sort((a, b) => Math.abs(a.ts - timelineCutoff) - Math.abs(b.ts - timelineCutoff));

    const current = activeCandidates[0];
    if (!current) return null;

    const incoming = visibleEdges
      .filter(edge => edge.target === current.node.id && filteredNodeIds.has(edge.source))
      .map(edge => ({ edge, source: nodeById.get(edge.source), ts: edgeTimestamp(edge, nodeById.get(edge.source), current.node) }))
      .sort((a, b) => (b.ts || 0) - (a.ts || 0))[0];

    const outgoingCount = visibleEdges.filter(edge => edge.source === current.node.id && filteredNodeIds.has(edge.target)).length;
    const detectionsCount = current.node.detections?.length || 0;

    return {
      node: current.node,
      timestamp: current.ts,
      incoming,
      outgoingCount,
      detectionsCount,
    };
  }, [timelineEnabled, visibleGraphNodes, visibleEdges, filteredNodeIds, nodeById, timelineCutoff]);

  useEffect(() => {
    if (!timelinePlaying) return;

    const interval = window.setInterval(() => {
      setTimelineValue(value => {
        if (value >= 100) {
          setTimelinePlaying(false);
          return 100;
        }
        return Math.min(100, value + 2);
      });
    }, 220);

    return () => window.clearInterval(interval);
  }, [timelinePlaying]);

  // Toggle type filter
  const toggleTypeFilter = (type: GraphNodeType) => {
    setTypeFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        // Don't allow removing all filters
        if (next.size > 1) next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  // Initialize positions using force-directed layout
  useEffect(() => {
    if (visibleGraphNodes.length === 0) return;

    const width = 800;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;

    // Create initial positions
    const newPositions = new Map<string, NodePosition>();

    // Group nodes by type for initial layout
    const typeGroups: Record<string, GraphNode[]> = {};
    visibleGraphNodes.forEach(node => {
      if (!typeGroups[node.type]) typeGroups[node.type] = [];
      typeGroups[node.type].push(node);
    });

    const typeOrder: GraphNodeType[] = ['process', 'network', 'dns', 'file', 'registry'];
    let yOffset = 100;

    typeOrder.forEach(type => {
      const group = typeGroups[type] || [];
      const xSpacing = width / (group.length + 1);

      group.forEach((node, i) => {
        // Highlighted nodes start at center
        const x = node.highlighted ? centerX : xSpacing * (i + 1);
        const y = node.highlighted ? centerY : yOffset;

        newPositions.set(node.id, {
          x: x + (Math.random() - 0.5) * 50,
          y: y + (Math.random() - 0.5) * 30,
          vx: 0,
          vy: 0,
        });
      });

      if ((typeGroups[type] || []).length > 0) {
        yOffset += 120;
      }
    });

    setPositions(newPositions);

    // Run force simulation
    let iterations = 0;
    const maxIterations = 100;

    const simulate = () => {
      if (iterations >= maxIterations) return;
      iterations++;

      setPositions(prevPositions => {
        const newPos = new Map(prevPositions);

        // Apply forces
        visibleGraphNodes.forEach(node => {
          const pos = newPos.get(node.id);
          if (!pos) return;

          let fx = 0, fy = 0;

          // Repulsion between all nodes
          visibleGraphNodes.forEach(other => {
            if (node.id === other.id) return;
            const otherPos = newPos.get(other.id);
            if (!otherPos) return;

            const dx = pos.x - otherPos.x;
            const dy = pos.y - otherPos.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = 5000 / (dist * dist);

            fx += (dx / dist) * force;
            fy += (dy / dist) * force;
          });

          // Attraction along edges
          visibleEdges.forEach(edge => {
            let otherId: string | null = null;
            if (edge.source === node.id) otherId = edge.target;
            if (edge.target === node.id) otherId = edge.source;
            if (!otherId) return;

            const otherPos = newPos.get(otherId);
            if (!otherPos) return;

            const dx = otherPos.x - pos.x;
            const dy = otherPos.y - pos.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = dist * 0.01;

            fx += (dx / dist) * force * dist;
            fy += (dy / dist) * force * dist;
          });

          // Center gravity
          fx += (centerX - pos.x) * 0.001;
          fy += (centerY - pos.y) * 0.001;

          // Update velocity with damping
          const damping = 0.8;
          pos.vx = (pos.vx + fx) * damping;
          pos.vy = (pos.vy + fy) * damping;

          // Update position
          pos.x += pos.vx;
          pos.y += pos.vy;

          // Boundary constraints
          pos.x = Math.max(50, Math.min(width - 50, pos.x));
          pos.y = Math.max(50, Math.min(height - 50, pos.y));
        });

        return newPos;
      });

      animationRef.current = requestAnimationFrame(simulate);
    };

    simulate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [visibleGraphNodes, visibleEdges]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isDragging && !draggedNode) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    } else if (draggedNode) {
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect) return;

      const x = (e.clientX - rect.left - pan.x) / zoom;
      const y = (e.clientY - rect.top - pan.y) / zoom;

      setPositions(prev => {
        const newPos = new Map(prev);
        const pos = newPos.get(draggedNode);
        if (pos) {
          pos.x = x;
          pos.y = y;
          pos.vx = 0;
          pos.vy = 0;
        }
        return newPos;
      });
    }
  }, [isDragging, draggedNode, dragStart, pan, zoom]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
    setDraggedNode(null);
  }, []);

  const handleNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setDraggedNode(nodeId);
  }, []);

  // Scroll to zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom(z => Math.max(0.3, Math.min(2, z + delta)));
  }, []);

  const handleZoomIn = () => setZoom(z => Math.min(2, z + 0.2));
  const handleZoomOut = () => setZoom(z => Math.max(0.3, z - 0.2));
  const handleFitView = () => {
    if (visibleGraphNodes.length === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    visibleGraphNodes.forEach(node => {
      const pos = positions.get(node.id);
      if (pos) {
        minX = Math.min(minX, pos.x);
        minY = Math.min(minY, pos.y);
        maxX = Math.max(maxX, pos.x);
        maxY = Math.max(maxY, pos.y);
      }
    });

    if (minX === Infinity) return;

    const container = containerRef.current;
    if (!container) return;

    const padding = 80;
    const graphWidth = maxX - minX + padding * 2;
    const graphHeight = maxY - minY + padding * 2;
    const containerWidth = container.clientWidth;
    const containerHeight = container.clientHeight;

    const fitZoom = Math.min(
      containerWidth / graphWidth,
      containerHeight / graphHeight,
      1.5
    );

    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    setZoom(Math.max(0.3, fitZoom));
    setPan({
      x: containerWidth / 2 - centerX * fitZoom,
      y: containerHeight / 2 - centerY * fitZoom,
    });
  };

  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const jumpTimeline = (direction: 'prev' | 'next') => {
    const timestamps = typeFilteredNodes
      .map(nodeTimestamp)
      .filter((ts): ts is number => Boolean(ts))
      .sort((a, b) => a - b);

    if (timestamps.length === 0 || timeRange.max <= timeRange.min) return;

    const nextTimestamp =
      direction === 'next'
        ? timestamps.find(ts => ts > timelineCutoff + 1) || timeRange.max
        : [...timestamps].reverse().find(ts => ts < timelineCutoff - 1) || timeRange.min;

    const nextValue = ((nextTimestamp - timeRange.min) / (timeRange.max - timeRange.min)) * 100;
    setTimelineValue(Math.max(0, Math.min(100, Math.round(nextValue))));
  };

  const handleNodeClick = (node: GraphNode) => {
    setDetailNode(node);
    onNodeClick?.(node);
  };

  const getNodeColor = (node: GraphNode) => {
    if (node.detections && node.detections.length > 0) {
      return SEVERITY_COLORS[node.severity] || SEVERITY_COLORS.info;
    }
    return NODE_COLORS[node.type] || NODE_COLORS.process;
  };

  // Render node shape
  const renderNodeShape = (node: GraphNode, color: string, isSelected: boolean) => {
    const shape = NODE_SHAPES[node.type];
    const size = 24;

    switch (shape) {
      case 'diamond':
        return (
          <polygon
            points={`0,-${size} ${size},0 0,${size} -${size},0`}
            fill={color}
            stroke={isSelected ? '#fff' : 'transparent'}
            strokeWidth={2}
            opacity={0.9}
          />
        );
      case 'hexagon': {
        const s = size;
        const h = s * Math.sin(Math.PI / 3);
        return (
          <polygon
            points={`-${s},0 -${s/2},-${h} ${s/2},-${h} ${s},0 ${s/2},${h} -${s/2},${h}`}
            fill={color}
            stroke={isSelected ? '#fff' : 'transparent'}
            strokeWidth={2}
            opacity={0.9}
          />
        );
      }
      case 'square':
        return (
          <rect
            x={-size + 4}
            y={-size + 4}
            width={(size - 4) * 2}
            height={(size - 4) * 2}
            rx={4}
            fill={color}
            stroke={isSelected ? '#fff' : 'transparent'}
            strokeWidth={2}
            opacity={0.9}
          />
        );
      case 'triangle':
        return (
          <polygon
            points={`0,-${size} ${size},${size * 0.7} -${size},${size * 0.7}`}
            fill={color}
            stroke={isSelected ? '#fff' : 'transparent'}
            strokeWidth={2}
            opacity={0.9}
          />
        );
      default: // circle
        return (
          <circle
            r={size}
            fill={color}
            stroke={isSelected ? '#fff' : 'transparent'}
            strokeWidth={2}
            opacity={0.9}
          />
        );
    }
  };

  const renderNode = (node: GraphNode) => {
    const pos = positions.get(node.id);
    if (!pos) return null;

    const Icon = NODE_ICONS[node.type] || Cpu;
    const color = getNodeColor(node);
    const isSelected = node.id === selectedNodeId || node.id === detailNode?.id;
    const isHovered = node.id === hoveredNode;
    const hasDetections = node.detections && node.detections.length > 0;
    const phase = getNodePhase(node);
    const nodeOpacity = phase === 'future' ? 0.18 : phase === 'entering' ? 1 : 0.88;
    const nodeScale = phase === 'entering' ? 1.08 : 1;

    return (
      <g
        key={node.id}
        transform={`translate(${pos.x}, ${pos.y}) scale(${nodeScale})`}
        onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
        onMouseEnter={() => setHoveredNode(node.id)}
        onMouseLeave={() => setHoveredNode(null)}
        onClick={() => handleNodeClick(node)}
        onDoubleClick={() => onNodeDoubleClick?.(node)}
        style={{
          cursor: phase === 'future' ? 'default' : 'pointer',
          transition: 'opacity 180ms ease, transform 180ms ease',
          pointerEvents: phase === 'future' ? 'none' : 'auto',
        }}
        opacity={nodeOpacity}
      >
        {phase === 'entering' && (
          <>
            <circle r={38} fill="none" stroke={color} strokeWidth={1.5} opacity={0.45}>
              <animate attributeName="r" from="28" to="48" dur="1.2s" repeatCount="indefinite" />
              <animate attributeName="opacity" from="0.55" to="0" dur="1.2s" repeatCount="indefinite" />
            </circle>
            <circle r={31} fill={color} opacity={0.08} />
          </>
        )}

        {/* Selection/hover ring */}
        {(isSelected || isHovered || node.highlighted) && (
          <circle
            r={32}
            fill="none"
            stroke={isSelected ? '#3b82f6' : node.highlighted ? '#f59e0b' : '#64748b'}
            strokeWidth={2}
            strokeDasharray={node.highlighted ? '5,5' : 'none'}
            opacity={0.5}
          />
        )}

        {/* Node shape */}
        {renderNodeShape(node, color, isSelected)}

        {/* Icon */}
        <foreignObject x={-12} y={-12} width={24} height={24}>
          <div className="flex items-center justify-center w-full h-full">
            <Icon size={16} className="text-white" />
          </div>
        </foreignObject>

        {/* Detection badge */}
        {hasDetections && phase !== 'future' && (
          <g transform="translate(16, -16)">
            <circle r={10} fill="#ef4444" />
            <foreignObject x={-6} y={-6} width={12} height={12}>
              <div className="flex items-center justify-center w-full h-full">
                <AlertTriangle size={10} className="text-white" />
              </div>
            </foreignObject>
          </g>
        )}

        {/* Label */}
        <text
          y={36}
          textAnchor="middle"
          fill="#e2e8f0"
          fontSize={11}
          fontWeight={isSelected ? 600 : 400}
        >
          {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
        </text>

        {/* Data volume badge for network nodes */}
        {node.type === 'network' && (() => {
          const totalBytes = Number(node.data?.total_bytes || 0);
          if (totalBytes <= 0) return null;
          const label = formatBytes(totalBytes);
          return (
            <g transform="translate(0, -30)">
              <rect
                x={-label.length * 3.5 - 6}
                y={-8}
                width={label.length * 7 + 12}
                height={16}
                rx={8}
                fill="#065f46"
                stroke="#10b981"
                strokeWidth={0.5}
                opacity={0.9}
              />
              <text textAnchor="middle" y={3} fill="#6ee7b7" fontSize={9} fontWeight={600}>
                {label}
              </text>
            </g>
          );
        })()}

        {/* Hover tooltip showing type and details */}
        {isHovered && !isSelected && (
          <g transform={`translate(0, ${node.type === 'network' && Number(node.data?.total_bytes || 0) > 0 ? -52 : -38})`}>
            {node.type === 'network' ? (() => {
              const ip = String(node.data?.remote_ip || '');
              const port = String(node.data?.remote_port || '');
              const proto = String(node.data?.protocol || 'TCP');
              const dir = String(node.data?.direction || 'outbound');
              const procName = String(node.data?.process_name || '');
              const lines = [
                `${proto} ${dir}`,
                ip && port ? `${ip}:${port}` : '',
                procName ? `via ${procName}` : '',
              ].filter(Boolean);
              const maxLen = Math.max(...lines.map(l => l.length));
              const boxW = maxLen * 6 + 16;
              const boxH = lines.length * 14 + 8;
              return (
                <>
                  <rect x={-boxW / 2} y={-boxH} width={boxW} height={boxH} rx={4} fill="#1e293b" stroke="#334155" strokeWidth={1} />
                  {lines.map((line, i) => (
                    <text key={i} textAnchor="middle" y={-boxH + 12 + i * 14} fill="#94a3b8" fontSize={10}>{line}</text>
                  ))}
                </>
              );
            })() : (
              <>
                <rect x={-40} y={-14} width={80} height={20} rx={4} fill="#1e293b" stroke="#334155" strokeWidth={1} />
                <text textAnchor="middle" y={-1} fill="#94a3b8" fontSize={10}>
                  {node.type} {node.pid ? `(PID: ${node.pid})` : ''}
                </text>
              </>
            )}
          </g>
        )}
      </g>
    );
  };

  const renderEdge = (edge: GraphEdge) => {
    const sourcePos = positions.get(edge.source);
    const targetPos = positions.get(edge.target);
    if (!sourcePos || !targetPos) return null;

    const dx = targetPos.x - sourcePos.x;
    const dy = targetPos.y - sourcePos.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist === 0) return null;

    // Offset start/end to not overlap with nodes
    const nodeRadius = 24;
    const startX = sourcePos.x + (dx / dist) * nodeRadius;
    const startY = sourcePos.y + (dy / dist) * nodeRadius;
    const endX = targetPos.x - (dx / dist) * (nodeRadius + 8);
    const endY = targetPos.y - (dy / dist) * (nodeRadius + 8);

    const isHighlighted = edge.source === selectedNodeId || edge.target === selectedNodeId ||
                          edge.source === detailNode?.id || edge.target === detailNode?.id;
    const edgeId = `${edge.source}-${edge.target}-${edge.type}`;
    const isEdgeHovered = hoveredEdge === edgeId;
    const sourceNode = nodeById.get(edge.source);
    const targetNode = nodeById.get(edge.target);
    const sourcePhase = sourceNode ? getNodePhase(sourceNode) : 'active';
    const targetPhase = targetNode ? getNodePhase(targetNode) : 'active';
    const edgeTs = edgeTimestamp(edge, sourceNode, targetNode);
    const isFutureEdge =
      timelineEnabled &&
      (sourcePhase === 'future' || targetPhase === 'future' || Boolean(edgeTs && edgeTs > timelineCutoff));
    const isEnteringEdge =
      timelineEnabled &&
      !isFutureEdge &&
      Boolean(edgeTs && edgeTs >= timelineCutoff - timelineStepWindow);

    // Edge color based on type
    const getEdgeColor = () => {
      if (isHighlighted) return '#60a5fa';
      if (isEdgeHovered) return '#94a3b8';
      switch (edge.type) {
        case 'spawned': return '#3b82f6';
        case 'connected': return '#22c55e';
        case 'wrote': case 'read': case 'modified': return '#f59e0b';
        case 'resolved': return '#8b5cf6';
        default: return '#475569';
      }
    };

    const edgeColor = getEdgeColor();

    // Compute midpoint for label
    const midX = (startX + endX) / 2;
    const midY = (startY + endY) / 2;

    // Label background width estimate
    const labelText = edge.label || edge.type || '';
    const labelWidth = labelText.length * 6 + 12;

    return (
      <g
        key={edgeId}
        onMouseEnter={() => setHoveredEdge(edgeId)}
        onMouseLeave={() => setHoveredEdge(null)}
      >
        <defs>
          <marker
            id={`arrowhead-${edge.source}-${edge.target}`}
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon
              points="0 0, 10 3.5, 0 7"
              fill={edgeColor}
            />
          </marker>
        </defs>
        {/* Wider invisible line for easier hover */}
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke="transparent"
          strokeWidth={12}
          style={{ cursor: 'pointer' }}
        />
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke={edgeColor}
          strokeWidth={isHighlighted || isEdgeHovered || isEnteringEdge ? 2.4 : 1}
          strokeDasharray={edge.type === 'resolved' ? '4,2' : 'none'}
          markerEnd={`url(#arrowhead-${edge.source}-${edge.target})`}
          opacity={isFutureEdge ? 0.14 : isHighlighted || isEdgeHovered || isEnteringEdge ? 1 : 0.55}
        >
          {isEnteringEdge && (
            <animate attributeName="stroke-dashoffset" from="16" to="0" dur="0.8s" repeatCount="indefinite" />
          )}
        </line>
        {!isFutureEdge && (isEnteringEdge || isHighlighted || isEdgeHovered) && (
          <circle r={3.5} fill={edgeColor} opacity={0.9}>
            <animateMotion dur={isEnteringEdge ? '1s' : '1.6s'} repeatCount="indefinite" path={`M ${startX} ${startY} L ${endX} ${endY}`} />
          </circle>
        )}
        {/* Edge label with background */}
        {labelText && !isFutureEdge && (isHighlighted || isEdgeHovered || isEnteringEdge || dist > 100) && (
          <g>
            <rect
              x={midX - labelWidth / 2}
              y={midY - 10}
              width={labelWidth}
              height={16}
              rx={3}
              fill="#1e293b"
              stroke="#334155"
              strokeWidth={0.5}
              opacity={isHighlighted || isEdgeHovered ? 0.95 : 0.7}
            />
            <text
              x={midX}
              y={midY + 2}
              textAnchor="middle"
              fill={isHighlighted || isEdgeHovered ? '#e2e8f0' : '#94a3b8'}
              fontSize={9}
              fontWeight={isHighlighted ? 600 : 400}
            >
              {labelText}
            </text>
          </g>
        )}
        {/* Data volume badge on connection edges */}
        {isEdgeHovered && edge.type === 'connection' && (edge.bytes_sent || edge.bytes_received) && (
          <g>
            {(() => {
              const sent = edge.bytes_sent || 0;
              const recv = edge.bytes_received || 0;
              const volText = `${formatBytes(sent)} sent / ${formatBytes(recv)} recv`;
              const volW = volText.length * 5.5 + 16;
              return (
                <>
                  <rect
                    x={midX - volW / 2}
                    y={midY + 8}
                    width={volW}
                    height={16}
                    rx={3}
                    fill="#14532d"
                    stroke="#22c55e"
                    strokeWidth={0.5}
                    opacity={0.9}
                  />
                  <text
                    x={midX}
                    y={midY + 19}
                    textAnchor="middle"
                    fill="#86efac"
                    fontSize={8}
                    fontWeight={500}
                  >
                    {volText}
                  </text>
                </>
              );
            })()}
          </g>
        )}
      </g>
    );
  };

  // Count nodes by type
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    nodes.forEach(n => {
      counts[n.type] = (counts[n.type] || 0) + 1;
    });
    return counts;
  }, [nodes]);

  return (
    <div ref={containerRef} className={`relative bg-gray-900 rounded-lg overflow-hidden ${className}`}>
      {/* Top Left: Stats + Filter Toggle */}
      <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
        <div className="bg-gray-800/90 rounded-lg p-3 backdrop-blur-sm border border-gray-700/50">
          <div className="text-xs text-gray-400 mb-1">
            {filteredNodes.length} active of {typeFilteredNodes.length} visible nodes, {filteredEdges.length} active edges
          </div>
          <div className="text-xs text-gray-500">
            Drag to pan, scroll to zoom, click nodes for evidence
          </div>
        </div>

        {/* Filter toggle */}
        <button
          onClick={() => setShowFilterPanel(!showFilterPanel)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
            showFilterPanel
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800/90 text-gray-300 hover:bg-gray-700 border border-gray-700/50'
          }`}
        >
          <Filter size={14} />
          Filters
          {typeFilters.size < 5 && (
            <span className="bg-blue-500 text-white rounded-full px-1.5 py-0 text-[10px]">
              {typeFilters.size}
            </span>
          )}
        </button>
      </div>

      {/* Filter Panel */}
      {showFilterPanel && (
        <div className="absolute top-28 left-4 z-20 bg-gray-800 rounded-lg p-4 border border-gray-700 shadow-xl w-56">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Filter by Type</h4>
            <button
              onClick={() => setShowFilterPanel(false)}
              className="text-gray-500 hover:text-gray-300"
            >
              <X size={14} />
            </button>
          </div>
          <div className="space-y-1.5">
            {(Object.entries(NODE_COLORS) as [GraphNodeType, string][]).map(([type, color]) => {
              const Icon = NODE_ICONS[type];
              const isActive = typeFilters.has(type);
              const count = typeCounts[type] || 0;
              return (
                <button
                  key={type}
                  onClick={() => toggleTypeFilter(type)}
                  className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-colors ${
                    isActive
                      ? 'bg-gray-700/80 text-gray-200'
                      : 'bg-gray-800 text-gray-500 opacity-50'
                  }`}
                >
                  <div
                    className="w-3 h-3 rounded-sm flex-shrink-0"
                    style={{ backgroundColor: isActive ? color : '#475569' }}
                  />
                  <Icon size={14} />
                  <span className="flex-1 text-left capitalize">{type}</span>
                  <span className="text-xs text-gray-500">{count}</span>
                </button>
              );
            })}
          </div>

          {/* Timeline slider */}
          <div className="mt-4 pt-3 border-t border-gray-700">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-gray-400 font-medium">Timeline Filter</label>
              <button
                onClick={() => {
                  const next = !timelineEnabled;
                  setTimelineEnabled(next);
                  setTimelinePlaying(false);
                  if (next) setTimelineValue(0);
                }}
                className={`text-xs px-2 py-0.5 rounded ${
                  timelineEnabled ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'
                }`}
              >
                {timelineEnabled ? 'On' : 'Off'}
              </button>
            </div>
            {timelineEnabled && (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setTimelineValue(0)}
                    className="p-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
                    title="Jump to first event"
                  >
                    <SkipBack size={12} />
                  </button>
                  <button
                    type="button"
                    onClick={() => jumpTimeline('prev')}
                    className="px-1.5 py-1 rounded bg-gray-700 text-[10px] text-gray-300 hover:bg-gray-600"
                  >
                    Prev
                  </button>
                  <button
                    type="button"
                    onClick={() => setTimelinePlaying(value => !value)}
                    className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium ${
                      timelinePlaying ? 'bg-amber-500/20 text-amber-300' : 'bg-blue-600 text-white'
                    }`}
                  >
                    {timelinePlaying ? <Pause size={12} /> : <Play size={12} />}
                    {timelinePlaying ? 'Pause' : 'Play'}
                  </button>
                  <button
                    type="button"
                    onClick={() => jumpTimeline('next')}
                    className="px-1.5 py-1 rounded bg-gray-700 text-[10px] text-gray-300 hover:bg-gray-600"
                  >
                    Next
                  </button>
                  <button
                    type="button"
                    onClick={() => setTimelineValue(100)}
                    className="p-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
                    title="Jump to latest event"
                  >
                    <SkipForward size={12} />
                  </button>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={timelineValue}
                  onChange={(e) => setTimelineValue(parseInt(e.target.value))}
                  className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
                />
                <div className="flex justify-between text-[10px] text-gray-500">
                  <span>{timeRange.min ? new Date(timeRange.min).toLocaleTimeString() : 'Start'}</span>
                  <span className="text-blue-400 font-medium">
                    {compactTime(timelineCutoff)}
                  </span>
                  <span>{timeRange.max ? new Date(timeRange.max).toLocaleTimeString() : 'Now'}</span>
                </div>
                <div className="text-[10px] text-center text-gray-600">
                  {filteredNodes.length} active / {typeFilteredNodes.length} visible nodes
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {timelineEnabled && currentStep && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-10 w-[360px] bg-gray-800/95 rounded-lg border border-blue-500/30 shadow-xl backdrop-blur-sm">
          <div className="p-3 border-b border-gray-700/70 flex items-center gap-2">
            <Activity size={15} className="text-blue-300" />
            <div className="min-w-0">
              <div className="text-xs text-blue-300 font-semibold">Current timeline step</div>
              <div className="text-[10px] text-gray-500">{compactTime(currentStep.timestamp)}</div>
            </div>
          </div>
          <div className="p-3 space-y-2">
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${NODE_COLOR_CLASSES[currentStep.node.type]}`}>
                {currentStep.node.type}
              </span>
              <span className="text-sm text-gray-100 truncate">{currentStep.node.label}</span>
            </div>

            {currentStep.incoming?.source ? (
              <div className="text-xs text-gray-400 leading-relaxed">
                <span className="text-gray-500">Triggered by </span>
                <button
                  type="button"
                  onClick={() => {
                    if (currentStep.incoming?.source) {
                      setDetailNode(currentStep.incoming.source);
                      onNodeClick?.(currentStep.incoming.source);
                    }
                  }}
                  className="text-blue-300 hover:text-blue-200"
                >
                  {currentStep.incoming.source.label}
                </button>
                <span className="text-gray-500"> via </span>
                <span className="text-amber-300">{currentStep.incoming.edge.label || currentStep.incoming.edge.type}</span>
              </div>
            ) : (
              <div className="text-xs text-gray-500">First visible entity in this investigation window.</div>
            )}

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded bg-gray-900/70 px-2 py-1.5">
                <div className="text-[10px] text-gray-500">Next interactions</div>
                <div className="text-sm font-semibold text-gray-200">{currentStep.outgoingCount}</div>
              </div>
              <div className="rounded bg-gray-900/70 px-2 py-1.5">
                <div className="text-[10px] text-gray-500">Detections</div>
                <div className={`text-sm font-semibold ${currentStep.detectionsCount > 0 ? 'text-red-300' : 'text-gray-300'}`}>
                  {currentStep.detectionsCount}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top Right: Zoom Controls */}
      <div className="absolute top-4 right-4 flex flex-col gap-1 z-10">
        <button
          onClick={handleZoomIn}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors border border-gray-700/50"
          title="Zoom In"
        >
          <ZoomIn size={16} className="text-gray-300" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors border border-gray-700/50"
          title="Zoom Out"
        >
          <ZoomOut size={16} className="text-gray-300" />
        </button>
        <button
          onClick={handleFitView}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors border border-gray-700/50"
          title="Fit to View"
        >
          <Maximize2 size={16} className="text-gray-300" />
        </button>
        <button
          onClick={handleReset}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors border border-gray-700/50"
          title="Reset View"
        >
          <RefreshCw size={16} className="text-gray-300" />
        </button>

        {/* Zoom indicator */}
        <div className="text-center text-[10px] text-gray-500 mt-0.5">
          {Math.round(zoom * 100)}%
        </div>
      </div>

      {/* Bottom Left: Legend */}
      <div className="absolute bottom-4 left-4 bg-gray-800/90 rounded-lg p-3 z-10 border border-gray-700/50 backdrop-blur-sm">
        <div className="text-xs text-gray-400 mb-2 font-semibold">Legend</div>

        {/* Node Types */}
        <div className="mb-2.5">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Node Types</div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            {(Object.entries(NODE_COLORS) as [GraphNodeType, string][]).map(([type, color]) => {
              const shape = NODE_SHAPES[type];
              return (
                <div key={type} className="flex items-center gap-1.5">
                  {shape === 'circle' && (
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                  )}
                  {shape === 'diamond' && (
                    <div className="w-3 h-3 rotate-45 rounded-[1px]" style={{ backgroundColor: color }} />
                  )}
                  {shape === 'square' && (
                    <div className="w-3 h-3 rounded-[2px]" style={{ backgroundColor: color }} />
                  )}
                  {shape === 'hexagon' && (
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color, clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)' }} />
                  )}
                  {shape === 'triangle' && (
                    <div className="w-3 h-3" style={{ backgroundColor: color, clipPath: 'polygon(50% 0%, 100% 100%, 0% 100%)' }} />
                  )}
                  <span className="text-xs text-gray-300 capitalize">{type}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity */}
        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Severity</div>
          <div className="flex gap-2">
            {(['critical', 'high', 'medium', 'low'] as GraphSeverity[]).map(sev => (
              <div key={sev} className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                <span className="text-[10px] text-gray-400 capitalize">{sev}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Edge Types */}
        <div className="mt-2">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Relationships</div>
          <div className="flex flex-wrap gap-2">
            {[
              { label: 'spawned', color: '#3b82f6', dash: false },
              { label: 'connected', color: '#22c55e', dash: false },
              { label: 'file op', color: '#f59e0b', dash: false },
              { label: 'resolved', color: '#8b5cf6', dash: true },
            ].map(rel => (
              <div key={rel.label} className="flex items-center gap-1">
                <svg width="16" height="8">
                  <line
                    x1="0" y1="4" x2="16" y2="4"
                    stroke={rel.color}
                    strokeWidth={1.5}
                    strokeDasharray={rel.dash ? '3,2' : 'none'}
                  />
                </svg>
                <span className="text-[10px] text-gray-400">{rel.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detail Panel (right side) */}
      {detailNode && (
        <div className="absolute top-4 right-16 z-20 w-72 bg-gray-800 rounded-lg border border-gray-700 shadow-xl overflow-hidden">
          <div className="p-3 border-b border-gray-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              {(() => {
                const Icon = NODE_ICONS[detailNode.type];
                return <Icon size={16} style={{ color: NODE_COLORS[detailNode.type] }} />;
              })()}
              <h4 className="text-sm font-semibold text-white truncate">{detailNode.label}</h4>
            </div>
            <button
              onClick={() => setDetailNode(null)}
              className="p-1 hover:bg-gray-700 rounded text-gray-500 hover:text-gray-300"
            >
              <X size={14} />
            </button>
          </div>

          <div className="p-3 max-h-80 overflow-y-auto">
            {/* Type and severity */}
            <div className="flex items-center gap-2 mb-3">
              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${NODE_COLOR_CLASSES[detailNode.type]}`}>
                {detailNode.type}
              </span>
              <span
                className="px-2 py-0.5 rounded text-xs font-medium"
                style={{
                  color: SEVERITY_COLORS[detailNode.severity],
                  backgroundColor: `${SEVERITY_COLORS[detailNode.severity]}20`,
                }}
              >
                {detailNode.severity}
              </span>
              {detailNode.pid && (
                <span className="text-xs text-gray-500 font-mono">PID: {detailNode.pid}</span>
              )}
            </div>

            {/* Network flow summary for network nodes */}
            {detailNode.type === 'network' && (() => {
              const d = detailNode.data;
              const dir = String(d?.direction || 'outbound');
              const proto = String(d?.protocol || 'TCP');
              const remoteIp = String(d?.remote_ip || '');
              const remotePort = String(d?.remote_port || '');
              const procName = String(d?.process_name || '');
              const bytesSent = Number(d?.bytes_sent || 0);
              const bytesRecv = Number(d?.bytes_received || 0);
              return (
                <div className="bg-gray-900/50 rounded-lg p-2.5 mb-3 space-y-2">
                  <div className="flex items-center gap-2 text-xs">
                    <span className={`px-1.5 py-0.5 rounded font-medium ${dir === 'inbound' ? 'bg-orange-500/20 text-orange-400' : 'bg-green-500/20 text-green-400'}`}>
                      {dir === 'inbound' ? 'INBOUND' : 'OUTBOUND'}
                    </span>
                    <span className="px-1.5 py-0.5 bg-gray-700 rounded text-gray-300">{proto}</span>
                  </div>
                  {procName && (
                    <div className="text-xs text-gray-400">
                      <span className="text-gray-500">Process: </span>
                      <span className="text-blue-400 font-medium">{procName}</span>
                    </div>
                  )}
                  <div className="text-xs text-gray-400">
                    <span className="text-gray-500">Remote: </span>
                    <span className="font-mono text-green-400">{remoteIp}:{remotePort}</span>
                  </div>
                  {(bytesSent > 0 || bytesRecv > 0) && (
                    <div className="grid grid-cols-2 gap-2 pt-1 border-t border-gray-800">
                      <div className="text-center">
                        <div className="text-[10px] text-gray-500">Sent</div>
                        <div className="text-xs font-medium text-orange-400">{formatBytes(bytesSent)}</div>
                      </div>
                      <div className="text-center">
                        <div className="text-[10px] text-gray-500">Received</div>
                        <div className="text-xs font-medium text-green-400">{formatBytes(bytesRecv)}</div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Entity Data */}
            <div className="space-y-1.5">
              {Object.entries(detailNode.data)
                .filter(([key]) => detailNode.type !== 'network' || !['remote_ip', 'remote_port', 'protocol', 'direction', 'bytes_sent', 'bytes_received', 'total_bytes', 'process_name'].includes(key))
                .slice(0, 10).map(([key, value]) => (
                <div key={key} className="flex justify-between text-xs group">
                  <span className="text-gray-500 flex-shrink-0">{key}:</span>
                  <span className="text-gray-300 truncate max-w-[170px] font-mono text-[11px] ml-2 text-right">
                    {String(value)}
                  </span>
                </div>
              ))}
            </div>

            {/* Detections */}
            {detailNode.detections && detailNode.detections.length > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-700">
                <div className="flex items-center gap-1.5 mb-2">
                  <AlertTriangle size={12} className="text-red-400" />
                  <span className="text-xs font-semibold text-red-400">
                    {detailNode.detections.length} Detection(s)
                  </span>
                </div>
                {detailNode.detections.map((det, i) => (
                  <div key={i} className="text-xs text-gray-400 bg-red-500/10 border border-red-500/20 rounded p-2 mb-1.5">
                    <div className="font-medium text-red-300 mb-0.5">{det.ruleName}</div>
                    <div>{det.description}</div>
                    {det.mitreTechniques && det.mitreTechniques.length > 0 && (
                      <div className="flex gap-1 mt-1">
                        {det.mitreTechniques.map((t, j) => (
                          <span key={j} className="px-1 py-0.5 bg-red-500/10 rounded text-[10px] text-red-300 font-mono">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Connected edges */}
            <div className="mt-3 pt-3 border-t border-gray-700">
              <div className="text-xs font-medium text-gray-400 mb-1.5">Connections</div>
              {filteredEdges
                .filter(e => e.source === detailNode.id || e.target === detailNode.id)
                .slice(0, 8)
                .map((edge, i) => {
                  const otherId = edge.source === detailNode.id ? edge.target : edge.source;
                  const otherNode = filteredNodes.find(n => n.id === otherId);
                  const isOutgoing = edge.source === detailNode.id;
                  return (
                    <div
                      key={i}
                      className="flex items-center gap-1.5 text-[11px] py-1 hover:bg-gray-700/50 rounded px-1 cursor-pointer"
                      onClick={() => {
                        if (otherNode) {
                          setDetailNode(otherNode);
                          onNodeClick?.(otherNode);
                        }
                      }}
                    >
                      <span className="text-gray-500">{isOutgoing ? '->' : '<-'}</span>
                      <span className="text-gray-400">{edge.label || edge.type}</span>
                      <span className="text-gray-300 truncate">{otherNode?.label || otherId}</span>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}

      {/* SVG Canvas */}
      <svg
        ref={svgRef}
        className="w-full h-full"
        style={{ minHeight: '500px', cursor: isDragging ? 'grabbing' : 'grab' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {/* Render edges first (below nodes) */}
          {visibleEdges.map(renderEdge)}

          {/* Render nodes */}
          {visibleGraphNodes.map(renderNode)}
        </g>
      </svg>
    </div>
  );
}
