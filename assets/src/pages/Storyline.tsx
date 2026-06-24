import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Head, Link, router } from '@inertiajs/react';
import { MainLayout } from '@/layouts/MainLayout';
import {
  AlertTriangle, Cpu, File, Globe, Server, Settings,
  ZoomIn, ZoomOut, Maximize2, RefreshCw, ChevronRight,
  Clock, Shield, Target, Activity, Download, Share2,
  Filter, Eye, EyeOff, Play, Pause, ChevronDown,
  ArrowLeft, Copy, ExternalLink, AlertCircle, Info,
  Crosshair, GitBranch, Layers, User, Lock, Trash2,
  FileText, Network, Database, Terminal, ChevronUp,
  SkipBack, SkipForward, Volume2, Square, Circle,
  Minus, Plus, Move, MousePointer, X, Check, Search
} from 'lucide-react';
import { toast } from 'sonner';
import { PageProps, Detection } from '@/types';
import { logger } from '@/lib/logger';
import { safeCapitalize } from '@/lib/utils';
import { Checkbox, Dialog, DialogFooter } from '@/components/ui/baseui';

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

function jsonApiHeaders(): HeadersInit {
  const token = getCsrfToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'X-CSRF-Token': token } : {}),
  };
}

function LongTextPreview({
  value,
  copyLabel = 'Copy',
  collapsedLines = 5,
}: {
  value?: string | null;
  copyLabel?: string;
  collapsedLines?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const text = asText(value).trim();
  const isLong = text.length > 260 || text.split(/\r?\n/).length > collapsedLines;

  if (!text) {
    return (
      <div className="rounded p-2 text-xs" style={{ backgroundColor: 'var(--bg-2)', color: 'var(--muted)' }}>
        Not captured
      </div>
    );
  }

  return (
    <div className="rounded p-2 min-w-0 max-w-full overflow-hidden" style={{ backgroundColor: 'var(--bg-2)' }}>
      <pre
        className="text-xs font-mono max-w-full"
        style={{
          color: 'var(--fg-2)',
          whiteSpace: 'pre-wrap',
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
          maxHeight: !expanded && isLong ? `${collapsedLines * 1.45}rem` : undefined,
          overflow: !expanded && isLong ? 'hidden' : 'auto',
        }}
      >
        {text}
      </pre>
      <div className="mt-2 flex items-center justify-end gap-2">
        {isLong && (
          <button
            type="button"
            onClick={() => setExpanded((current) => !current)}
            className="text-xs hover:opacity-80"
            style={{ color: 'var(--muted)' }}
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(text)}
          className="inline-flex items-center gap-1 text-xs hover:opacity-80"
          style={{ color: 'var(--muted)' }}
        >
          <Copy size={12} />
          {copyLabel}
        </button>
      </div>
    </div>
  );
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function asText(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : value == null ? fallback : String(value);
}

function asNumber(value: unknown, fallback = 0): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function mitreTechniqueHref(value: unknown): string {
  const id = asText(value).trim();
  return id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}` : 'https://attack.mitre.org/';
}

// ============================================================================
// Type Definitions
// ============================================================================

interface StorylineNode {
  id: string;
  type: 'process' | 'file' | 'network' | 'dns' | 'registry' | 'user';
  label: string;
  full_label?: string;
  pid?: number;
  timestamp?: string;
  timestamp_raw?: string;
  x: number;
  y: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  highlighted: boolean;
  suspicious: boolean;
  data: Record<string, unknown>;
  detections: Array<{
    ruleName: string;
    description: string;
    severity: string;
    mitreTechniques: string[];
  }>;
  // Process-specific fields
  cmdline?: string;
  path?: string;
  user?: string;
  ppid?: number;
  sha256?: string;
  is_elevated?: boolean;
  is_signed?: boolean;
  signer?: string;
}

interface StorylineEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  timestamp?: string;
  animated: boolean;
  color: string;
}

interface RootCause {
  node_id: string;
  type: string;
  entity_name: string;
  process_name?: string;
  cmdline?: string;
  path?: string;
  pid?: number;
  ppid?: number;
  user?: string;
  timestamp?: string;
  confidence_score: number;
  reasoning: string;
}

interface TimelineEntry {
  id: string;
  timestamp: string;
  event_type: string;
  summary: string;
  severity: string;
  payload: Record<string, unknown>;
  detections: Detection[];
}

interface ThreatIndicator {
  type: string;
  value: string;
  source: string;
}

interface ThreatAssessment {
  severity: string;
  confidence: number;
  phase: string;
  indicators_count: number;
  techniques_count: number;
  risk_level: string;
}

interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

interface RecommendedAction {
  priority: string;
  action: string;
  reason: string;
}

interface StorylineData {
  id: string;
  alert_id: string | null;
  agent_id: string;
  title: string;
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  root_cause: RootCause | null;
  nodes: StorylineNode[];
  edges: StorylineEdge[];
  timeline: TimelineEntry[];
  threat_indicators: ThreatIndicator[];
  mitre_techniques: string[];
  attack_phase: string;
  confidence_score: number;
  generated_at: string;
  time_range: {
    start: string | null;
    end: string | null;
  };
}

interface Analysis {
  threat_assessment: ThreatAssessment;
  attack_techniques: AttackTechnique[];
  recommended_actions: RecommendedAction[];
  confidence: number;
  attack_narrative: string;
}

interface StorylinePageProps extends PageProps {
  page_title: string;
  alert_id?: string;
  agent_id?: string;
  pid?: number;
  storyline: StorylineData | null;
  analysis: Analysis | null;
  layout: string;
  error?: string;
}

// ============================================================================
// Constants - Using CSS Variables
// ============================================================================

const NODE_COLORS: Record<string, string> = {
  process: 'var(--med)',           // Blue
  file: 'var(--high)',             // Amber/Orange
  network: 'var(--emerald-400)',   // Green
  dns: 'var(--sol-magenta)',       // Purple
  registry: 'var(--crit)',         // Red
  user: 'var(--sol-cyan)',         // Cyan
};

const NODE_ICONS: Record<string, typeof Cpu> = {
  process: Cpu,
  file: File,
  network: Globe,
  dns: Server,
  registry: Settings,
  user: User,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  info: 'var(--muted)',
};

const SEVERITY_BG_COLORS: Record<string, string> = {
  critical: 'var(--crit-bg)',
  high: 'var(--high-bg)',
  medium: 'var(--med-bg)',
  low: 'var(--low-bg)',
  info: 'rgba(138, 154, 161, 0.12)',
};

const ATTACK_PHASE_LABELS: Record<string, string> = {
  initial_access: 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  privilege_escalation: 'Privilege Escalation',
  defense_evasion: 'Defense Evasion',
  credential_access: 'Credential Access',
  discovery: 'Discovery',
  lateral_movement: 'Lateral Movement',
  collection: 'Collection',
  command_and_control: 'Command & Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
  unknown: 'Unknown',
};

const ATTACK_PHASE_ORDER = [
  'initial_access', 'execution', 'persistence', 'privilege_escalation',
  'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
  'collection', 'command_and_control', 'exfiltration', 'impact'
];

const ATTACK_PHASE_COLORS: Record<string, string> = {
  initial_access: 'var(--high)',
  execution: 'var(--crit)',
  persistence: 'var(--sol-magenta)',
  privilege_escalation: '#ec4899',
  defense_evasion: '#6366f1',
  credential_access: 'var(--high)',
  discovery: 'var(--sol-cyan)',
  lateral_movement: 'var(--sol-cyan)',
  collection: 'var(--emerald-400)',
  command_and_control: 'var(--emerald-500)',
  exfiltration: 'var(--med)',
  impact: 'var(--crit)',
  unknown: 'var(--muted)',
};

const EDGE_PRIORITY: Record<string, number> = {
  spawned: 0,
  executed: 1,
  contacted: 2,
  resolved: 2,
  modified: 3,
  accessed: 3,
};

function nodeTime(node: StorylineNode): number {
  const raw = node.timestamp_raw || node.timestamp || asText(node.data.timestamp);
  const parsed = raw ? Date.parse(raw) : NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function computeStorylineLayout(nodes: StorylineNode[], edges: StorylineEdge[], mode = 'timeline'): Map<string, { x: number; y: number }> {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const incoming = new Map<string, StorylineEdge[]>();
  const outgoing = new Map<string, StorylineEdge[]>();
  const undirected = new Map<string, Set<string>>();

  edges.forEach((edge) => {
    if (!byId.has(edge.source) || !byId.has(edge.target)) return;
    incoming.set(edge.target, [...(incoming.get(edge.target) || []), edge]);
    outgoing.set(edge.source, [...(outgoing.get(edge.source) || []), edge]);
    undirected.set(edge.source, (undirected.get(edge.source) || new Set()).add(edge.target));
    undirected.set(edge.target, (undirected.get(edge.target) || new Set()).add(edge.source));
  });

  const componentById = new Map<string, number>();
  const components: StorylineNode[][] = [];
  const visited = new Set<string>();

  nodes.forEach((node) => {
    if (visited.has(node.id)) return;

    const stack = [node.id];
    const component: StorylineNode[] = [];
    visited.add(node.id);

    while (stack.length) {
      const id = stack.pop()!;
      const current = byId.get(id);
      if (current) component.push(current);

      for (const next of undirected.get(id) || []) {
        if (visited.has(next)) continue;
        visited.add(next);
        stack.push(next);
      }
    }

    components.push(component);
  });

  components
    .sort((a, b) =>
      Number(b.some((node) => node.highlighted)) - Number(a.some((node) => node.highlighted)) ||
      Math.min(...a.map(nodeTime)) - Math.min(...b.map(nodeTime)) ||
      b.length - a.length
    )
    .forEach((component, index) => {
      component.forEach((node) => componentById.set(node.id, index));
    });

  const roots = nodes
    .filter((node) => !incoming.has(node.id) || node.highlighted)
    .sort((a, b) => Number(b.highlighted) - Number(a.highlighted) || nodeTime(a) - nodeTime(b));

  const level = new Map<string, number>();
  const queue = [...(roots.length ? roots : nodes.slice(0, 1))];
  queue.forEach((node) => level.set(node.id, 0));

  while (queue.length) {
    const node = queue.shift()!;
    const currentLevel = level.get(node.id) || 0;
    const nextEdges = [...(outgoing.get(node.id) || [])].sort((a, b) => (EDGE_PRIORITY[a.type] ?? 9) - (EDGE_PRIORITY[b.type] ?? 9));

    nextEdges.forEach((edge) => {
      const nextLevel = currentLevel + 1;
      if (!level.has(edge.target) || nextLevel > (level.get(edge.target) || 0)) {
        level.set(edge.target, nextLevel);
        const target = byId.get(edge.target);
        if (target) queue.push(target);
      }
    });
  }

  [...nodes]
    .sort((a, b) => (componentById.get(a.id) || 0) - (componentById.get(b.id) || 0) || nodeTime(a) - nodeTime(b))
    .forEach((node, index) => {
      if (level.has(node.id)) return;

      const neighborLevels = Array.from(undirected.get(node.id) || [])
        .map((id) => level.get(id))
        .filter((value): value is number => typeof value === 'number');

      level.set(node.id, neighborLevels.length ? Math.min(...neighborLevels) + 1 : 1 + Math.floor(index / 6));
    });

  const lanes: Record<StorylineNode['type'], number> = {
    process: 0,
    user: 1,
    file: 2,
    registry: 3,
    dns: 4,
    network: 5,
  };

  const grouped = new Map<number, StorylineNode[]>();
  nodes.forEach((node) => {
    const key = level.get(node.id) || 0;
    grouped.set(key, [...(grouped.get(key) || []), node]);
  });

  const positions = new Map<string, { x: number; y: number }>();

  if (mode === 'force') {
    const centerX = 560;
    const centerY = 430;
    const rootsSet = new Set(roots.map((node) => node.id));
    const ordered = [...nodes].sort((a, b) => Number(rootsSet.has(b.id)) - Number(rootsSet.has(a.id)) || nodeTime(a) - nodeTime(b));
    const radiusBase = Math.max(210, Math.min(520, nodes.length * 18));
    const highlighted = ordered.filter((node) => node.highlighted);
    const highlightSet = new Set(highlighted.map((node) => node.id));

    highlighted.forEach((node, index) => {
      if (highlighted.length === 1) {
        positions.set(node.id, { x: centerX, y: centerY });
        return;
      }

      const angle = (index / highlighted.length) * Math.PI * 2 - Math.PI / 2;
      const radius = Math.max(90, Math.min(190, highlighted.length * 28));
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
      });
    });

    ordered.forEach((node, index) => {
      if (highlightSet.has(node.id)) return;

      if (positions.size === 0 && index === 0) {
        positions.set(node.id, { x: centerX, y: centerY });
        return;
      }
      const placedIndex = positions.size;
      const ring = 1 + Math.floor(placedIndex / 10);
      const angle = ((placedIndex % 10) / 10) * Math.PI * 2 - Math.PI / 2;
      const radius = radiusBase + (ring - 1) * 150;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
      });
    });

    return positions;
  }

  const xSpacing = 300;
  const ySpacing = 118;
  const laneHeight = 155;

  Array.from(grouped.entries())
    .sort(([a], [b]) => a - b)
    .forEach(([lvl, group]) => {
      const ordered = [...group].sort((a, b) => {
        const typeDelta = (lanes[a.type] ?? 9) - (lanes[b.type] ?? 9);
        return typeDelta || Number(b.highlighted || b.suspicious) - Number(a.highlighted || a.suspicious) || nodeTime(a) - nodeTime(b);
      });
      const laneCounts = new Map<number, number>();

      ordered.forEach((node) => {
        const lane = lanes[node.type] ?? 0;
        const index = laneCounts.get(lane) || 0;
        const componentIndex = componentById.get(node.id) || 0;
        laneCounts.set(lane, index + 1);
        if (mode === 'hierarchical') {
          positions.set(node.id, {
            x: 160 + componentIndex * 720 + lane * 250 + index * 80,
            y: 110 + lvl * 175,
          });
        } else {
          positions.set(node.id, {
            x: 140 + lvl * xSpacing,
            y: 110 + componentIndex * 780 + lane * laneHeight + index * ySpacing,
          });
        }
      });
    });

  return positions;
}

function formatNodeValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return 'Not captured';
  if (Array.isArray(value)) return value.length ? value.map((item) => asText(item)).join(', ') : 'None';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function firstNodeData(node: StorylineNode, keys: string[], fallback = 'Not captured'): string {
  for (const key of keys) {
    const value = node.data[key] ?? (node as unknown as Record<string, unknown>)[key];
    const formatted = formatNodeValue(value);
    if (formatted !== 'Not captured') return formatted;
  }
  return fallback;
}

function summarizeStorylineNode(node: StorylineNode, edges: StorylineEdge[], allNodes: StorylineNode[]): string {
  const incoming = edges.filter((edge) => edge.target === node.id);
  const outgoing = edges.filter((edge) => edge.source === node.id);
  const parent = incoming[0] ? allNodes.find((candidate) => candidate.id === incoming[0].source) : null;

  if (node.type === 'process') {
    const cmd = firstNodeData(node, ['cmdline', 'command_line'], '');
    const path = firstNodeData(node, ['path', 'process_path', 'image_path'], '');
    return `${node.label}${node.pid ? ` PID ${node.pid}` : ''}${parent ? ` was reached from ${parent.label}` : ''}${cmd ? ` and ran ${cmd}` : path ? ` from ${path}` : ''}.`;
  }

  if (node.type === 'network') {
    const host = firstNodeData(node, ['remote_ip', 'destination_ip', 'ip', 'host'], node.label);
    const port = firstNodeData(node, ['remote_port', 'destination_port', 'port'], '');
    const proto = firstNodeData(node, ['protocol'], 'tcp');
    return `${parent?.label || 'A process'} contacted ${host}${port ? `:${port}` : ''} over ${proto}.`;
  }

  if (node.type === 'dns') {
    return `${parent?.label || 'A process'} resolved ${firstNodeData(node, ['query', 'query_name', 'domain', 'dns_query'], node.label)}.`;
  }

  if (node.type === 'file') {
    return `${parent?.label || 'A process'} ${firstNodeData(node, ['operation', 'action', 'event_type'], 'touched')} ${firstNodeData(node, ['path', 'file_path'], node.full_label || node.label)}.`;
  }

  if (node.type === 'registry') {
    return `${parent?.label || 'A process'} ${firstNodeData(node, ['operation', 'action', 'event_type'], 'modified')} registry key ${firstNodeData(node, ['key', 'registry_key', 'path'], node.full_label || node.label)}.`;
  }

  return `${node.label} has ${incoming.length} inbound and ${outgoing.length} outbound relationship(s).`;
}

function countConnected(edges: StorylineEdge[], nodeId: string, direction: 'in' | 'out' | 'all' = 'all') {
  return edges.filter((edge) =>
    direction === 'in' ? edge.target === nodeId : direction === 'out' ? edge.source === nodeId : edge.source === nodeId || edge.target === nodeId
  ).length;
}

// ============================================================================
// Helper Components
// ============================================================================

interface CollapsibleSectionProps {
  title: string;
  icon?: typeof Cpu;
  defaultOpen?: boolean;
  badge?: string | number;
  badgeColor?: string;
  children: React.ReactNode;
}

function CollapsibleSection({ title, icon: Icon, defaultOpen = true, badge, badgeColor, children }: CollapsibleSectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="card-sentinel">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-3 hover:bg-[var(--surface-2)] transition-colors rounded-t-md -m-4 mb-0 p-4"
      >
        <div className="flex items-center gap-2">
          {Icon && <Icon size={14} style={{ color: 'var(--muted)' }} />}
          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{title}</span>
          {badge !== undefined && (
            <span
              className="px-1.5 py-0.5 rounded text-xs font-medium"
              style={{
                color: badgeColor || 'var(--muted)',
                backgroundColor: badgeColor ? `${badgeColor}20` : 'var(--surface-2)'
              }}
            >
              {badge}
            </span>
          )}
        </div>
        <ChevronDown
          size={14}
          className={`transition-transform ${isOpen ? 'rotate-180' : ''}`}
          style={{ color: 'var(--muted)' }}
        />
      </button>
      {isOpen && <div className="pt-3">{children}</div>}
    </div>
  );
}

// Kill Chain Progress Indicator
interface KillChainProgressProps {
  currentPhase: string;
  detectedPhases: string[];
}

function KillChainProgress({ currentPhase, detectedPhases }: KillChainProgressProps) {
  const currentIndex = ATTACK_PHASE_ORDER.indexOf(currentPhase);

  return (
    <div className="card-sentinel">
      <div className="flex items-center gap-2 mb-4">
        <Target size={14} style={{ color: 'var(--sol-magenta)' }} />
        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>MITRE ATT&CK Kill Chain</span>
      </div>

      <div className="relative">
        {/* Progress line */}
        <div className="absolute top-3 left-4 right-4 h-0.5" style={{ backgroundColor: 'var(--border)' }} />
        <div
          className="absolute top-3 left-4 h-0.5 transition-all duration-500"
          style={{
            width: `${Math.max(0, ((currentIndex + 1) / ATTACK_PHASE_ORDER.length) * 100 - 5)}%`,
            background: 'linear-gradient(to right, var(--high), var(--crit), var(--sol-magenta))'
          }}
        />

        {/* Phase markers */}
        <div className="flex justify-between relative">
          {ATTACK_PHASE_ORDER.map((phase, index) => {
            const isActive = index <= currentIndex;
            const isDetected = detectedPhases.includes(phase);
            const isCurrent = phase === currentPhase;

            return (
              <div key={phase} className="flex flex-col items-center" style={{ width: `${100 / ATTACK_PHASE_ORDER.length}%` }}>
                <div
                  className="w-6 h-6 rounded-full border-2 flex items-center justify-center transition-all"
                  style={{
                    borderColor: isCurrent ? 'var(--crit)' : isDetected ? 'var(--high)' : isActive ? 'var(--muted)' : 'var(--border)',
                    backgroundColor: isCurrent ? 'var(--crit)' : isDetected ? 'var(--high)' : isActive ? 'var(--surface-2)' : 'var(--surface)',
                    transform: isCurrent ? 'scale(1.1)' : 'scale(1)'
                  }}
                >
                  {isDetected && <Check size={12} style={{ color: 'var(--fg)' }} />}
                </div>
                <span
                  className="text-[9px] mt-2 text-center leading-tight"
                  style={{
                    maxWidth: '60px',
                    color: isCurrent ? 'var(--crit)' : isDetected ? 'var(--high)' : 'var(--muted)',
                    fontWeight: isCurrent ? 500 : 400
                  }}
                >
                  {ATTACK_PHASE_LABELS[phase]?.split(' ').map((word, i) => (
                    <span key={i}>{word}<br /></span>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// Action Button Component
interface ActionButtonProps {
  icon: typeof Cpu;
  label: string;
  onClick: () => void;
  variant?: 'danger' | 'warning' | 'primary' | 'secondary';
  disabled?: boolean;
  loading?: boolean;
}

function ActionButton({ icon: Icon, label, onClick, variant = 'secondary', disabled, loading }: ActionButtonProps) {
  const getButtonClass = () => {
    switch (variant) {
      case 'danger':
        return 'btn-sentinel btn-sentinel-danger';
      case 'warning':
        return 'btn-sentinel btn-sentinel-outline';
      case 'primary':
        return 'btn-sentinel btn-sentinel-primary';
      default:
        return 'btn-sentinel btn-sentinel-secondary';
    }
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`${getButtonClass()} w-full justify-start`}
    >
      {loading ? (
        <RefreshCw size={14} className="animate-spin" />
      ) : (
        <Icon size={14} />
      )}
      {label}
    </button>
  );
}

function NodeIntelligenceCards({
  node,
  edges,
  allNodes,
}: {
  node: StorylineNode;
  edges: StorylineEdge[];
  allNodes: StorylineNode[];
}) {
  const inbound = countConnected(edges, node.id, 'in');
  const outbound = countConnected(edges, node.id, 'out');
  const connectedTypes = edges
    .filter((edge) => edge.source === node.id || edge.target === node.id)
    .map((edge) => allNodes.find((candidate) => candidate.id === (edge.source === node.id ? edge.target : edge.source))?.type)
    .filter(Boolean);
  const uniqueConnectedTypes = Array.from(new Set(connectedTypes)).join(', ') || 'None';

  const common = [
    { label: 'Inbound links', value: inbound },
    { label: 'Outbound links', value: outbound },
    { label: 'Related entity types', value: uniqueConnectedTypes },
  ];

  const typed =
    node.type === 'process'
      ? [
          { label: 'Executable path', value: firstNodeData(node, ['path', 'process_path', 'image_path']) },
          { label: 'User context', value: firstNodeData(node, ['user', 'username', 'account']) },
          { label: 'Parent PID', value: firstNodeData(node, ['ppid', 'parent_pid']) },
          { label: 'Signer', value: firstNodeData(node, ['signer', 'company_name', 'publisher']) },
          { label: 'SHA-256', value: firstNodeData(node, ['sha256', 'hash', 'file_hash']) },
        ]
      : node.type === 'network'
        ? [
            { label: 'Destination', value: firstNodeData(node, ['remote_ip', 'destination_ip', 'ip', 'host']) },
            { label: 'Port / protocol', value: `${firstNodeData(node, ['remote_port', 'destination_port', 'port'], '?')} / ${firstNodeData(node, ['protocol'], 'tcp')}` },
            { label: 'Direction', value: firstNodeData(node, ['direction'], 'outbound') },
            { label: 'Bytes', value: firstNodeData(node, ['total_bytes', 'bytes', 'bytes_sent']) },
            { label: 'Owning process', value: firstNodeData(node, ['process_name', 'process']) },
          ]
        : node.type === 'dns'
          ? [
              { label: 'Domain', value: firstNodeData(node, ['query', 'query_name', 'domain', 'dns_query'], node.label) },
              { label: 'Record type', value: firstNodeData(node, ['query_type', 'record_type'], 'A') },
              { label: 'Response', value: firstNodeData(node, ['response', 'answer', 'resolved_ip', 'resolved_ips']) },
              { label: 'Resolver/process', value: firstNodeData(node, ['process_name', 'resolver', 'process']) },
            ]
          : node.type === 'file'
            ? [
                { label: 'Path', value: firstNodeData(node, ['path', 'file_path'], node.full_label || node.label) },
                { label: 'Operation', value: firstNodeData(node, ['operation', 'action', 'event_type']) },
                { label: 'Hash', value: firstNodeData(node, ['sha256', 'hash', 'file_hash']) },
                { label: 'Size', value: firstNodeData(node, ['size', 'file_size']) },
              ]
            : node.type === 'registry'
              ? [
                  { label: 'Key', value: firstNodeData(node, ['key', 'registry_key', 'path'], node.full_label || node.label) },
                  { label: 'Value', value: firstNodeData(node, ['value_name', 'value']) },
                  { label: 'Operation', value: firstNodeData(node, ['operation', 'action', 'event_type']) },
                ]
              : [
                  { label: 'Identity', value: firstNodeData(node, ['user', 'username', 'account'], node.label) },
                  { label: 'Session', value: firstNodeData(node, ['session_id', 'logon_id']) },
                  { label: 'Domain', value: firstNodeData(node, ['domain', 'realm']) },
                ];

  return (
    <div className="grid grid-cols-1 gap-2">
      <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--bg-2)', border: '1px solid var(--border)' }}>
        <div className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>
          Node Intelligence
        </div>
        <div className="grid grid-cols-3 gap-2">
          {common.map((item) => (
            <div key={item.label} className="min-w-0">
              <div className="text-[10px]" style={{ color: 'var(--subtle)' }}>{item.label}</div>
              <div className="text-xs truncate" title={String(item.value)} style={{ color: 'var(--fg)' }}>{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
        <div className="space-y-2">
          {typed.map((item) => (
            <div key={item.label} className="min-w-0">
              <div className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>{item.label}</div>
              <div className="text-xs font-mono break-words" style={{ color: 'var(--fg-2)' }}>{formatNodeValue(item.value)}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function Storyline({
  page_title,
  alert_id,
  agent_id,
  pid,
  storyline: rawStoryline,
  analysis: rawAnalysis,
  layout: initialLayout,
  error
}: StorylinePageProps) {
  const storyline = useMemo<StorylineData | null>(() => {
    if (!rawStoryline) return null;

    return {
      ...rawStoryline,
      id: asText(rawStoryline.id, 'storyline'),
      alert_id: rawStoryline.alert_id ? asText(rawStoryline.alert_id) : null,
      agent_id: asText(rawStoryline.agent_id),
      title: asText(rawStoryline.title, 'Investigation storyline'),
      summary: asText(rawStoryline.summary, 'No storyline summary was provided.'),
      severity: (asText(rawStoryline.severity, 'info') as StorylineData['severity']),
      root_cause: rawStoryline.root_cause ? {
        ...rawStoryline.root_cause,
        node_id: asText(rawStoryline.root_cause.node_id),
        type: asText(rawStoryline.root_cause.type, 'process'),
        entity_name: asText(rawStoryline.root_cause.entity_name, 'unknown'),
        process_name: rawStoryline.root_cause.process_name ? asText(rawStoryline.root_cause.process_name) : undefined,
        cmdline: rawStoryline.root_cause.cmdline ? asText(rawStoryline.root_cause.cmdline) : undefined,
        path: rawStoryline.root_cause.path ? asText(rawStoryline.root_cause.path) : undefined,
        pid: rawStoryline.root_cause.pid ? asNumber(rawStoryline.root_cause.pid) : undefined,
        ppid: rawStoryline.root_cause.ppid ? asNumber(rawStoryline.root_cause.ppid) : undefined,
        user: rawStoryline.root_cause.user ? asText(rawStoryline.root_cause.user) : undefined,
        timestamp: rawStoryline.root_cause.timestamp ? asText(rawStoryline.root_cause.timestamp) : undefined,
        confidence_score: asNumber(rawStoryline.root_cause.confidence_score),
        reasoning: asText(rawStoryline.root_cause.reasoning),
      } : null,
      nodes: asArray(rawStoryline.nodes).map((node) => {
        const data = node.data && typeof node.data === 'object' ? node.data : {};

        return {
          ...node,
          id: asText(node.id),
          type: (asText(node.type, 'process') as StorylineNode['type']),
          label: asText(node.label, 'Unknown'),
          full_label: node.full_label ? asText(node.full_label) : undefined,
          x: asNumber(node.x),
          y: asNumber(node.y),
          severity: (asText(node.severity, 'info') as StorylineNode['severity']),
          highlighted: Boolean(node.highlighted),
          suspicious: Boolean(node.suspicious),
          data: {
            ...data,
            cmdline: data.cmdline ?? node.cmdline,
            path: data.path ?? node.path,
            user: data.user ?? node.user,
            ppid: data.ppid ?? node.ppid,
            sha256: data.sha256 ?? node.sha256,
            is_elevated: data.is_elevated ?? node.is_elevated,
            is_signed: data.is_signed ?? node.is_signed,
            signer: data.signer ?? node.signer,
          },
          detections: asArray(node.detections).map((det) => ({
            ruleName: asText(det.ruleName, 'Unknown'),
            description: asText(det.description),
            severity: asText(det.severity, 'info'),
            mitreTechniques: asArray(det.mitreTechniques).map((tech) => asText(tech)).filter(Boolean),
          })),
        };
      }),
      edges: asArray(rawStoryline.edges).map((edge) => ({
        ...edge,
        id: asText(edge.id),
        source: asText(edge.source),
        target: asText(edge.target),
        type: asText(edge.type, 'related'),
        label: asText(edge.label),
      })),
      timeline: asArray(rawStoryline.timeline).map((entry) => ({
        ...entry,
        id: asText(entry.id),
        timestamp: asText(entry.timestamp),
        event_type: asText(entry.event_type, 'event'),
        summary: asText(entry.summary, 'Event'),
        severity: asText(entry.severity, 'info'),
        payload: entry.payload && typeof entry.payload === 'object' ? entry.payload : {},
        detections: asArray(entry.detections),
      })),
      threat_indicators: asArray(rawStoryline.threat_indicators).map((indicator) => ({
        type: asText(indicator.type, 'indicator'),
        value: asText(indicator.value),
        source: asText(indicator.source),
      })),
      mitre_techniques: asArray(rawStoryline.mitre_techniques).map((tech) => asText(tech)).filter(Boolean),
      attack_phase: asText(rawStoryline.attack_phase, 'unknown'),
      confidence_score: asNumber(rawStoryline.confidence_score),
      generated_at: asText(rawStoryline.generated_at),
      time_range: {
        start: rawStoryline.time_range?.start ? asText(rawStoryline.time_range.start) : null,
        end: rawStoryline.time_range?.end ? asText(rawStoryline.time_range.end) : null,
      },
    };
  }, [rawStoryline]);

  const analysis = useMemo<Analysis | null>(() => {
    if (!rawAnalysis) return null;

    return {
      ...rawAnalysis,
      threat_assessment: {
        severity: asText(rawAnalysis.threat_assessment?.severity, 'info'),
        confidence: Number(rawAnalysis.threat_assessment?.confidence ?? 0),
        phase: asText(rawAnalysis.threat_assessment?.phase, 'unknown'),
        indicators_count: Number(rawAnalysis.threat_assessment?.indicators_count ?? 0),
        techniques_count: Number(rawAnalysis.threat_assessment?.techniques_count ?? 0),
        risk_level: asText(rawAnalysis.threat_assessment?.risk_level, 'unknown'),
      },
      attack_techniques: asArray(rawAnalysis.attack_techniques).map((tech) => ({
        id: asText(tech.id),
        name: asText(tech.name, 'Unknown technique'),
        tactic: asText(tech.tactic),
        description: asText(tech.description),
      })).filter((tech) => tech.id || tech.name !== 'Unknown technique'),
      recommended_actions: asArray(rawAnalysis.recommended_actions).map((action) => ({
        priority: asText(action.priority, 'medium'),
        action: asText(action.action, 'Review related evidence'),
        reason: asText(action.reason),
      })),
      attack_narrative: asText(rawAnalysis.attack_narrative),
    };
  }, [rawAnalysis]);

  // SVG canvas state
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<string | null>(null);

  // Node positions (for force-directed layout adjustments)
  const [nodePositions, setNodePositions] = useState<Map<string, { x: number; y: number }>>(new Map());

  // Collapsed nodes (for tree view)
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(new Set());

  // Selection state
  const [selectedNode, setSelectedNode] = useState<StorylineNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);

  // View state
  const [activePanel, setActivePanel] = useState<'details' | 'timeline' | 'analysis' | 'actions' | null>('analysis');
  const [showFilters, setShowFilters] = useState(false);
  const [layoutType, setLayoutType] = useState(initialLayout || 'timeline');
  const [typeFilters, setTypeFilters] = useState<Set<string>>(
    new Set(['process', 'file', 'network', 'dns', 'registry', 'user'])
  );
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);
  const [showLabels, setShowLabels] = useState(true);

  // Timeline playback state
  const [isPlaying, setIsPlaying] = useState(false);
  const [timelineProgress, setTimelineProgress] = useState(100);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const playIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Action states
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [pendingKill, setPendingKill] = useState<{ pid: number } | null>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [shareLink, setShareLink] = useState('');

  // Animation state for attack flow
  const [animationProgress, setAnimationProgress] = useState(0);
  const animationRef = useRef<number>();

  // Initialize node positions from storyline data
  useEffect(() => {
    if (storyline?.nodes) {
      const positions = computeStorylineLayout(storyline.nodes, storyline.edges || [], layoutType);
      setNodePositions(positions);
      requestAnimationFrame(() => handleFitView(positions));
    }
  }, [storyline?.nodes, storyline?.edges, layoutType]);

  // Run attack flow animation
  useEffect(() => {
    if (isPlaying && storyline?.edges) {
      const animate = () => {
        setAnimationProgress(prev => {
          const next = prev + 0.5 * playbackSpeed;
          if (next >= 100) {
            return 0;
          }
          return next;
        });
        animationRef.current = requestAnimationFrame(animate);
      };
      animationRef.current = requestAnimationFrame(animate);
    } else {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    }

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [isPlaying, playbackSpeed, storyline?.edges]);

  // Get children of a node
  const getNodeChildren = useCallback((nodeId: string): string[] => {
    if (!storyline?.edges) return [];
    return storyline.edges
      .filter(e => e.source === nodeId && e.type === 'spawned')
      .map(e => e.target);
  }, [storyline?.edges]);

  // Check if node has children
  const hasChildren = useCallback((nodeId: string): boolean => {
    return getNodeChildren(nodeId).length > 0;
  }, [getNodeChildren]);

  // Check if node is visible (considering collapsed parents)
  const isNodeVisible = useCallback((nodeId: string): boolean => {
    if (!storyline?.edges) return true;

    // Find all ancestors
    const findParent = (id: string): string | null => {
      const parentEdge = storyline.edges.find(e => e.target === id && e.type === 'spawned');
      return parentEdge?.source || null;
    };

    let current = findParent(nodeId);
    while (current) {
      if (collapsedNodes.has(current)) return false;
      current = findParent(current);
    }
    return true;
  }, [storyline?.edges, collapsedNodes]);

  // Filter nodes based on type, timeline, and collapse state
  const filteredNodes = useMemo(() => {
    if (!storyline?.nodes) return [];

    return storyline.nodes.filter(node => {
      if (!typeFilters.has(node.type)) return false;
      if (showSuspiciousOnly && !node.suspicious && !node.highlighted) return false;
      if (!isNodeVisible(node.id)) return false;

      // Timeline filter
      if (timelineProgress < 100 && storyline.timeline.length > 0) {
        const timelineIndex = Math.floor((timelineProgress / 100) * storyline.timeline.length);
        const cutoffTime = storyline.timeline[timelineIndex]?.timestamp;
        const cutoffMs = cutoffTime ? Date.parse(cutoffTime) : NaN;
        const nodeMs = Date.parse(node.timestamp_raw || node.timestamp || asText(node.data.timestamp));
        if (Number.isFinite(cutoffMs) && Number.isFinite(nodeMs) && nodeMs > cutoffMs) return false;
      }

      return true;
    });
  }, [storyline?.nodes, storyline?.timeline, typeFilters, showSuspiciousOnly, timelineProgress, isNodeVisible]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    if (!storyline?.edges) return [];
    return storyline.edges.filter(
      e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
    );
  }, [storyline?.edges, filteredNodeIds]);

  // Detected MITRE phases based on techniques
  const detectedPhases = useMemo(() => {
    if (!storyline?.mitre_techniques) return [];

    const phases = new Set<string>();
    const techniqueToPhase: Record<string, string> = {
      'T1566': 'initial_access',
      'T1190': 'initial_access',
      'T1059': 'execution',
      'T1053': 'persistence',
      'T1547': 'persistence',
      'T1548': 'privilege_escalation',
      'T1134': 'privilege_escalation',
      'T1070': 'defense_evasion',
      'T1036': 'defense_evasion',
      'T1003': 'credential_access',
      'T1082': 'discovery',
      'T1021': 'lateral_movement',
      'T1560': 'collection',
      'T1071': 'command_and_control',
      'T1041': 'exfiltration',
      'T1486': 'impact',
    };

    storyline.mitre_techniques.forEach(tech => {
      const baseTech = asText(tech).split('.')[0];
      const phase = techniqueToPhase[baseTech];
      if (phase) phases.add(phase);
    });

    return Array.from(phases);
  }, [storyline?.mitre_techniques]);

  // Timeline playback
  useEffect(() => {
    if (isPlaying) {
      playIntervalRef.current = setInterval(() => {
        setTimelineProgress(prev => {
          if (prev >= 100) {
            setIsPlaying(false);
            return 100;
          }
          return prev + (0.5 * playbackSpeed);
        });
      }, 50);
    } else {
      if (playIntervalRef.current) {
        clearInterval(playIntervalRef.current);
      }
    }

    return () => {
      if (playIntervalRef.current) {
        clearInterval(playIntervalRef.current);
      }
    };
  }, [isPlaying, playbackSpeed]);

  // Canvas interaction handlers
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

      setNodePositions(prev => {
        const newPos = new Map(prev);
        newPos.set(draggedNode, { x, y });
        return newPos;
      });
    }
  }, [isDragging, draggedNode, dragStart, pan, zoom]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
    setDraggedNode(null);
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom(z => Math.max(0.2, Math.min(3, z + delta)));
  }, []);

  const handleZoomIn = () => setZoom(z => Math.min(3, z + 0.2));
  const handleZoomOut = () => setZoom(z => Math.max(0.2, z - 0.2));

  const handleFitView = (positions = nodePositions) => {
    if (filteredNodes.length === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    filteredNodes.forEach(node => {
      const pos = positions.get(node.id) || { x: node.x, y: node.y };
      minX = Math.min(minX, pos.x);
      minY = Math.min(minY, pos.y);
      maxX = Math.max(maxX, pos.x);
      maxY = Math.max(maxY, pos.y);
    });

    const container = containerRef.current;
    if (!container || minX === Infinity) return;

    const padding = 100;
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

    setZoom(Math.max(0.2, fitZoom));
    setPan({
      x: containerWidth / 2 - centerX * fitZoom,
      y: containerHeight / 2 - centerY * fitZoom,
    });
  };

  const handleResetView = () => {
    if (storyline?.nodes) {
      const positions = computeStorylineLayout(storyline.nodes, storyline.edges || [], layoutType);
      setNodePositions(positions);
      requestAnimationFrame(() => handleFitView(positions));
    } else {
      setZoom(1);
      setPan({ x: 0, y: 0 });
    }
  };

  // Node interactions
  const handleNodeClick = (node: StorylineNode) => {
    setSelectedNode(node);
    setActivePanel('details');
  };

  const handleNodeDoubleClick = (node: StorylineNode) => {
    if (node.type === 'process' && hasChildren(node.id)) {
      setCollapsedNodes(prev => {
        const next = new Set(prev);
        if (next.has(node.id)) {
          next.delete(node.id);
        } else {
          next.add(node.id);
        }
        return next;
      });
    }
  };

  // Toggle type filter
  const toggleTypeFilter = (type: string) => {
    setTypeFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  // Action handlers
  const handleIsolateEndpoint = async () => {
    if (!storyline?.agent_id) return;
    setActionLoading('isolate');
    try {
      const response = await fetch(`/api/v1/agents/${storyline.agent_id}/isolate`, {
        method: 'POST',
        credentials: 'include',
        headers: jsonApiHeaders(),
      });
      if (response.ok) {
        toast.success('Endpoint isolated');
      } else {
        toast.error(`Failed to isolate endpoint: ${response.status} ${response.statusText}`);
      }
    } catch (err) {
      logger.error('Failed to isolate:', err);
      toast.error(`Failed to isolate endpoint: ${(err as Error).message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const performKillProcess = async (pid: number) => {
    if (!storyline?.agent_id) return;
    setActionLoading('kill');
    try {
      const response = await fetch('/api/v1/response/kill', {
        method: 'POST',
        credentials: 'include',
        headers: jsonApiHeaders(),
        body: JSON.stringify({
          agent_id: storyline.agent_id,
          pid,
          force: true,
        }),
      });
      if (response.ok) {
        toast.success('Process kill command sent');
      } else {
        toast.error(`Failed to kill process: ${response.status} ${response.statusText}`);
      }
    } catch (err) {
      logger.error('Failed to kill process:', err);
      toast.error(`Failed to kill process: ${(err as Error).message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleKillProcess = () => {
    if (!storyline?.agent_id || !selectedNode?.pid) return;
    setPendingKill({ pid: selectedNode.pid });
  };

  const confirmKillProcess = async () => {
    const pending = pendingKill;
    setPendingKill(null);
    if (!pending) return;
    await performKillProcess(pending.pid);
  };

  const handleQuarantineFile = async () => {
    if (!storyline?.agent_id || !selectedNode || selectedNode.type !== 'file') return;

    setActionLoading('quarantine');
    try {
      const response = await fetch('/api/v1/response/quarantine', {
        method: 'POST',
        credentials: 'include',
        headers: jsonApiHeaders(),
        body: JSON.stringify({
          agent_id: storyline.agent_id,
          path: selectedNode.data.path || selectedNode.full_label,
        }),
      });
      if (response.ok) {
        toast.success('File quarantined');
      } else {
        toast.error(`Failed to quarantine file: ${response.status} ${response.statusText}`);
      }
    } catch (err) {
      logger.error('Failed to quarantine:', err);
      toast.error(`Failed to quarantine file: ${(err as Error).message}`);
    } finally {
      setActionLoading(null);
    }
  };

  // Export handlers
  const handleExportJSON = () => {
    if (!storyline) return;
    const dataStr = JSON.stringify({ storyline, analysis }, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `storyline-${storyline.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setShowExportMenu(false);
  };

  const handleExportImage = async () => {
    if (!svgRef.current) return;

    // Clone the SVG
    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();

    img.onload = () => {
      canvas.width = img.width;
      canvas.height = img.height;
      ctx?.drawImage(img, 0, 0);

      const a = document.createElement('a');
      a.download = `storyline-${storyline?.id || 'export'}.png`;
      a.href = canvas.toDataURL('image/png');
      a.click();
    };

    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
    setShowExportMenu(false);
  };

  const handleShareInvestigation = () => {
    const url = window.location.href;
    setShareLink(url);
    setShowShareModal(true);
  };

  const copyShareLink = () => {
    navigator.clipboard.writeText(shareLink);
  };

  // Render error state
  if (error) {
    return (
      <MainLayout>
        <Head title={page_title} />
        <div className="flex items-center justify-center min-h-[600px]">
          <div className="text-center">
            <AlertCircle size={48} style={{ color: 'var(--crit)' }} className="mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>Failed to Load Storyline</h2>
            <p className="mb-4" style={{ color: 'var(--muted)' }}>{error}</p>
            <Link
              href={alert_id ? `/app/alerts/${alert_id}` : '/app/alerts'}
              className="btn-sentinel btn-sentinel-primary"
            >
              <ArrowLeft className="inline-block mr-2" size={16} />
              Back to {alert_id ? 'Alert' : 'Alerts'}
            </Link>
          </div>
        </div>
      </MainLayout>
    );
  }

  // Render empty state
  if (!storyline) {
    return (
      <MainLayout>
        <Head title={page_title} />
        <div className="flex items-center justify-center min-h-[600px]">
          <div className="text-center">
            <Info size={48} style={{ color: 'var(--muted)' }} className="mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Storyline Data</h2>
            <p style={{ color: 'var(--muted)' }}>No events found to build a storyline.</p>
          </div>
        </div>
      </MainLayout>
    );
  }

  // Render node shape based on type
  const renderNodeShape = (node: StorylineNode, color: string, isSelected: boolean, isCollapsed: boolean) => {
    const size = 24;
    const strokeColor = isSelected ? 'var(--fg)' : 'transparent';
    const strokeWidth = isSelected ? 3 : 0;

    switch (node.type) {
      case 'network':
        return (
          <polygon
            points={`0,-${size} ${size},0 0,${size} -${size},0`}
            fill={color}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
          />
        );
      case 'dns':
        const s = size;
        const h = s * Math.sin(Math.PI / 3);
        return (
          <polygon
            points={`-${s},0 -${s/2},-${h} ${s/2},-${h} ${s},0 ${s/2},${h} -${s/2},${h}`}
            fill={color}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
          />
        );
      case 'file':
        return (
          <rect
            x={-size + 4}
            y={-size + 4}
            width={(size - 4) * 2}
            height={(size - 4) * 2}
            rx={4}
            fill={color}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
          />
        );
      case 'registry':
        return (
          <polygon
            points={`0,-${size} ${size},${size * 0.7} -${size},${size * 0.7}`}
            fill={color}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
          />
        );
      default: // process, user
        return (
          <>
            <circle
              r={size}
              fill={color}
              stroke={strokeColor}
              strokeWidth={strokeWidth}
            />
            {/* Collapse indicator for process nodes */}
            {node.type === 'process' && hasChildren(node.id) && (
              <g transform={`translate(${size - 4}, ${size - 4})`}>
                <circle r={8} fill="var(--surface)" stroke="var(--border)" strokeWidth={1} />
                {isCollapsed ? (
                  <Plus size={10} style={{ color: 'var(--muted)' }} x={-5} y={-5} />
                ) : (
                  <Minus size={10} style={{ color: 'var(--muted)' }} x={-5} y={-5} />
                )}
              </g>
            )}
          </>
        );
    }
  };

  // Render a single node
  const renderNode = (node: StorylineNode) => {
    const pos = nodePositions.get(node.id) || { x: node.x, y: node.y };
    const Icon = NODE_ICONS[node.type] || Cpu;

    // Color based on severity if it has detections, otherwise use type color
    const hasDetections = node.detections && node.detections.length > 0;
    const color = hasDetections
      ? SEVERITY_COLORS[node.severity] || SEVERITY_COLORS.info
      : NODE_COLORS[node.type] || NODE_COLORS.process;

    const isSelected = selectedNode?.id === node.id;
    const isHovered = hoveredNode === node.id;
    const isHighlighted = Boolean(node.highlighted || node.suspicious);
    const isRootCause = storyline?.root_cause?.node_id === node.id;
    const isCollapsed = collapsedNodes.has(node.id);

    return (
      <g
        key={node.id}
        transform={`translate(${pos.x}, ${pos.y})`}
        onMouseDown={(e) => {
          e.stopPropagation();
          setDraggedNode(node.id);
        }}
        onMouseEnter={() => setHoveredNode(node.id)}
        onMouseLeave={() => setHoveredNode(null)}
        onClick={() => handleNodeClick(node)}
        onDoubleClick={() => handleNodeDoubleClick(node)}
        style={{ cursor: 'pointer' }}
      >
        {/* Root cause indicator */}
        {isRootCause && (
          <circle
            r={44}
            fill="none"
            stroke="var(--crit)"
            strokeWidth={2}
            strokeDasharray="6,3"
            className="animate-pulse"
          />
        )}

        {/* Highlight ring */}
        {(isSelected || isHovered || isHighlighted) && (
          <circle
            r={36}
            fill="none"
            stroke={isSelected ? 'var(--med)' : isHighlighted ? 'var(--high)' : 'var(--muted)'}
            strokeWidth={2}
            strokeDasharray={isHighlighted && !isSelected ? '5,5' : 'none'}
            opacity={0.6}
          />
        )}

        {/* Pulse animation for suspicious nodes */}
        {isHighlighted && !isSelected ? (
          <circle
            r={36}
            fill="none"
            stroke={node.suspicious ? 'var(--crit)' : 'var(--high)'}
            strokeWidth={1}
            opacity={0.4}
            className="animate-ping"
          />
        ) : null}

        {/* Node shape */}
        {renderNodeShape(node, color, isSelected, isCollapsed)}

        {/* Icon */}
        <foreignObject x={-12} y={-12} width={24} height={24}>
          <div className="flex items-center justify-center w-full h-full">
            <Icon size={16} style={{ color: 'var(--fg)' }} />
          </div>
        </foreignObject>

        {/* Elevated badge for process nodes */}
        {node.type === 'process' && node.data.is_elevated && (
          <g transform="translate(-18, -18)">
            <circle r={8} fill="var(--high)" />
            <foreignObject x={-5} y={-5} width={10} height={10}>
              <div className="flex items-center justify-center w-full h-full">
                <Shield size={8} style={{ color: 'var(--fg)' }} />
              </div>
            </foreignObject>
          </g>
        )}

        {/* Detection badge */}
        {hasDetections && (
          <g transform="translate(18, -18)">
            <circle r={10} fill="var(--crit)" />
            <foreignObject x={-6} y={-6} width={12} height={12}>
              <div className="flex items-center justify-center w-full h-full">
                <AlertTriangle size={10} style={{ color: 'var(--fg)' }} />
              </div>
            </foreignObject>
          </g>
        )}

        {/* Label */}
        {showLabels && (
          <>
            <text
              y={40}
              textAnchor="middle"
              fill="var(--fg-2)"
              fontSize={11}
              fontWeight={isSelected ? 600 : 400}
              className="select-none"
            >
              {node.label}
            </text>

            {/* PID badge for process nodes */}
            {node.type === 'process' && node.pid && (
              <text
                y={52}
                textAnchor="middle"
                fill="var(--muted)"
                fontSize={9}
                className="select-none"
              >
                PID: {node.pid}
              </text>
            )}
          </>
        )}
      </g>
    );
  };

  // Render an edge with animation
  const renderEdge = (edge: StorylineEdge) => {
    const sourcePos = nodePositions.get(edge.source);
    const targetPos = nodePositions.get(edge.target);

    const sourceNode = storyline?.nodes.find(n => n.id === edge.source);
    const targetNode = storyline?.nodes.find(n => n.id === edge.target);

    const source = sourcePos || (sourceNode ? { x: sourceNode.x, y: sourceNode.y } : null);
    const target = targetPos || (targetNode ? { x: targetNode.x, y: targetNode.y } : null);

    if (!source || !target) return null;

    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist === 0) return null;

    // Offset for node radius
    const nodeRadius = 28;
    const startX = source.x + (dx / dist) * nodeRadius;
    const startY = source.y + (dy / dist) * nodeRadius;
    const endX = target.x - (dx / dist) * (nodeRadius + 8);
    const endY = target.y - (dy / dist) * (nodeRadius + 8);

    const isHovered = hoveredEdge === edge.id;
    const isConnectedToSelected = selectedNode &&
      (edge.source === selectedNode.id || edge.target === selectedNode.id);

    // Edge color
    const edgeColor = edge.animated ? 'var(--crit)' :
                      isConnectedToSelected ? 'var(--med)' :
                      isHovered ? 'var(--muted)' :
                      (edge.color || 'var(--border)');

    // Midpoint for label
    const midX = (startX + endX) / 2;
    const midY = (startY + endY) / 2;

    // Calculate animation offset for flowing effect
    const dashOffset = edge.animated ? (animationProgress * 3) % 20 : 0;

    return (
      <g
        key={edge.id}
        onMouseEnter={() => setHoveredEdge(edge.id)}
        onMouseLeave={() => setHoveredEdge(null)}
      >
        <defs>
          <marker
            id={`arrow-${edge.id}`}
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill={edgeColor} />
          </marker>

          {/* Gradient for animated edges */}
          {edge.animated && (
            <linearGradient id={`gradient-${edge.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--crit)" stopOpacity="0.3" />
              <stop offset="50%" stopColor="var(--crit)" stopOpacity="1" />
              <stop offset="100%" stopColor="var(--crit)" stopOpacity="0.3" />
            </linearGradient>
          )}
        </defs>

        {/* Invisible wider line for hover target */}
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke="transparent"
          strokeWidth={12}
          style={{ cursor: 'pointer' }}
        />

        {/* Glow effect for animated edges */}
        {edge.animated && (
          <line
            x1={startX}
            y1={startY}
            x2={endX}
            y2={endY}
            stroke="var(--crit)"
            strokeWidth={4}
            opacity={0.3}
            filter="blur(4px)"
          />
        )}

        {/* Visible edge line */}
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke={edgeColor}
          strokeWidth={edge.animated || isConnectedToSelected ? 2 : 1}
          strokeDasharray={edge.animated ? '8,4' : edge.type === 'resolved' ? '4,2' : 'none'}
          strokeDashoffset={-dashOffset}
          markerEnd={`url(#arrow-${edge.id})`}
          opacity={isConnectedToSelected || isHovered ? 1 : 0.6}
          className={edge.animated ? 'transition-all' : ''}
        />

        {/* Edge label */}
        {(isHovered || isConnectedToSelected || dist > 120) && edge.label && (
          <g>
            <rect
              x={midX - 30}
              y={midY - 10}
              width={60}
              height={16}
              rx={3}
              fill="var(--surface)"
              stroke="var(--border)"
              strokeWidth={0.5}
            />
            <text
              x={midX}
              y={midY + 3}
              textAnchor="middle"
              fill="var(--muted)"
              fontSize={9}
              className="select-none"
            >
              {edge.label}
            </text>
          </g>
        )}
      </g>
    );
  };

  return (
    <MainLayout>
      <Head title={page_title} />

      <div className="flex flex-col h-[calc(100vh-64px)]">
        {/* Header */}
        <div className="flex-shrink-0 px-6 py-4" style={{ backgroundColor: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link
                href={alert_id ? `/app/alerts/${alert_id}` : '/app/alerts'}
                className="p-2 rounded-lg transition-colors"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--surface-2)'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <ArrowLeft size={20} />
              </Link>

              <div>
                <h1 className="text-xl font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <GitBranch style={{ color: 'var(--med)' }} size={24} />
                  {storyline.title}
                </h1>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{storyline.summary}</p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {/* Severity badge */}
              <span
                className="badge-sentinel badge-sentinel-pill"
                style={{
                  color: SEVERITY_COLORS[storyline.severity] || SEVERITY_COLORS.info,
                  backgroundColor: SEVERITY_BG_COLORS[storyline.severity] || SEVERITY_BG_COLORS.info,
                  border: `1px solid ${SEVERITY_COLORS[storyline.severity] || SEVERITY_COLORS.info}25`
                }}
              >
                {storyline.severity.toUpperCase()}
              </span>

              {/* Attack phase badge */}
              <span
                className="badge-sentinel badge-sentinel-pill"
                style={{
                  color: ATTACK_PHASE_COLORS[storyline.attack_phase] || 'var(--muted)',
                  backgroundColor: `${ATTACK_PHASE_COLORS[storyline.attack_phase] || 'var(--muted)'}20`,
                  border: `1px solid ${ATTACK_PHASE_COLORS[storyline.attack_phase] || 'var(--muted)'}25`
                }}
              >
                {ATTACK_PHASE_LABELS[storyline.attack_phase] || storyline.attack_phase}
              </span>

              {/* Confidence */}
              <span className="badge-sentinel badge-sentinel-default badge-sentinel-pill">
                {Math.round(storyline.confidence_score * 100)}% confidence
              </span>

              {/* Share button */}
              <button
                onClick={handleShareInvestigation}
                className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
                title="Share Investigation"
              >
                <Share2 size={18} />
              </button>

              {/* Export */}
              <div className="relative">
                <button
                  onClick={() => setShowExportMenu(!showExportMenu)}
                  className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
                >
                  <Download size={18} />
                </button>
                {showExportMenu && (
                  <div
                    className="absolute right-0 top-full mt-1 rounded-lg shadow-xl py-1 z-50 min-w-[160px]"
                    style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
                  >
                    <button
                      onClick={handleExportImage}
                      className="w-full px-4 py-2 text-left text-sm flex items-center gap-2 hover:bg-[var(--surface-3)]"
                      style={{ color: 'var(--fg-2)' }}
                    >
                      <FileText size={14} />
                      Export as PNG
                    </button>
                    <button
                      onClick={handleExportJSON}
                      className="w-full px-4 py-2 text-left text-sm flex items-center gap-2 hover:bg-[var(--surface-3)]"
                      style={{ color: 'var(--fg-2)' }}
                    >
                      <Database size={14} />
                      Export as JSON
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Quick stats */}
          <div className="flex items-center gap-6 mt-4">
            <div className="flex items-center gap-2 text-sm">
              <Layers size={14} style={{ color: 'var(--muted)' }} />
              <span style={{ color: 'var(--muted)' }}>{filteredNodes.length} nodes</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <GitBranch size={14} style={{ color: 'var(--muted)' }} />
              <span style={{ color: 'var(--muted)' }}>{filteredEdges.length} edges</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <AlertTriangle size={14} style={{ color: 'var(--muted)' }} />
              <span style={{ color: 'var(--muted)' }}>
                {storyline.nodes.filter(n => n.detections.length > 0).length} detections
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Target size={14} style={{ color: 'var(--muted)' }} />
              <span style={{ color: 'var(--muted)' }}>{storyline.mitre_techniques.length} MITRE techniques</span>
            </div>
            {storyline.time_range.start && storyline.time_range.end && (
              <div className="flex items-center gap-2 text-sm">
                <Clock size={14} style={{ color: 'var(--muted)' }} />
                <span style={{ color: 'var(--muted)' }}>
                  {storyline.time_range.start} - {storyline.time_range.end}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Main content area */}
        <div className="flex-1 flex overflow-hidden">
          {/* Graph canvas */}
          <div
            ref={containerRef}
            className="flex-1 relative overflow-hidden"
            style={{ backgroundColor: 'var(--bg)' }}
          >
            {/* Filter panel (top left) */}
            <div className="absolute top-4 left-4 z-10">
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  showFilters
                    ? 'btn-sentinel-primary'
                    : 'btn-sentinel btn-sentinel-secondary'
                }`}
              >
                <Filter size={14} />
                Filters
                {typeFilters.size < 6 && (
                  <span
                    className="rounded-full px-1.5 text-xs"
                    style={{ backgroundColor: 'var(--emerald-500)', color: 'white' }}
                  >
                    {typeFilters.size}
                  </span>
                )}
              </button>

              {showFilters && (
                <div
                  className="mt-2 rounded-lg p-4 shadow-xl w-56"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
                >
                  <h4
                    className="text-xs font-semibold uppercase tracking-wide mb-3"
                    style={{ color: 'var(--muted)' }}
                  >
                    Node Types
                  </h4>
                  <div className="space-y-1.5">
                    {Object.entries(NODE_COLORS).map(([type, color]) => {
                      const Icon = NODE_ICONS[type] || Cpu;
                      const isActive = typeFilters.has(type);
                      const count = storyline?.nodes.filter(n => n.type === type).length || 0;
                      return (
                        <button
                          key={type}
                          onClick={() => toggleTypeFilter(type)}
                          className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-colors"
                          style={{
                            backgroundColor: isActive ? 'var(--surface-3)' : 'var(--surface-2)',
                            color: isActive ? 'var(--fg-2)' : 'var(--muted)',
                            opacity: isActive ? 1 : 0.5
                          }}
                        >
                          <div
                            className="w-3 h-3 rounded-sm flex-shrink-0"
                            style={{ backgroundColor: isActive ? color : 'var(--border)' }}
                          />
                          <Icon size={14} />
                          <span className="flex-1 text-left capitalize">{type}</span>
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>{count}</span>
                        </button>
                      );
                    })}
                  </div>

                  <div className="mt-4 pt-3 space-y-2" style={{ borderTop: '1px solid var(--border)' }}>
                    <Checkbox
                      checked={showSuspiciousOnly}
                      onCheckedChange={(checked) => setShowSuspiciousOnly(checked)}
                      label="Show suspicious only"
                    />
                    <Checkbox
                      checked={showLabels}
                      onCheckedChange={(checked) => setShowLabels(checked)}
                      label="Show labels"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Layout selector (top center-left) */}
            <div
              className="absolute top-4 left-72 z-10 flex gap-1 rounded-lg p-1"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              {['timeline', 'hierarchical', 'force'].map((layout) => (
                <button
                  key={layout}
                  onClick={() => setLayoutType(layout)}
                  className="px-3 py-1.5 rounded text-xs font-medium transition-colors"
                  style={{
                    backgroundColor: layoutType === layout ? 'var(--emerald-500)' : 'transparent',
                    color: layoutType === layout ? 'white' : 'var(--muted)'
                  }}
                >
                  {safeCapitalize(layout)}
                </button>
              ))}
            </div>

            {/* Zoom controls (top right) */}
            <div className="absolute top-4 right-4 flex flex-col gap-1 z-10">
              <button
                onClick={handleZoomIn}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-icon"
                title="Zoom In"
              >
                <ZoomIn size={16} />
              </button>
              <button
                onClick={handleZoomOut}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-icon"
                title="Zoom Out"
              >
                <ZoomOut size={16} />
              </button>
              <button
                onClick={handleFitView}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-icon"
                title="Fit to View"
              >
                <Maximize2 size={16} />
              </button>
              <button
                onClick={handleResetView}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-icon"
                title="Reset View"
              >
                <RefreshCw size={16} />
              </button>
              <div className="text-center text-xs mt-1" style={{ color: 'var(--muted)' }}>
                {Math.round(zoom * 100)}%
              </div>
            </div>

            {/* Legend (bottom left) */}
            <div
              className="absolute bottom-20 left-4 rounded-lg p-3 z-10 backdrop-blur-sm"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              <div className="text-xs mb-2 font-semibold" style={{ color: 'var(--muted)' }}>Legend</div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 mb-2">
                {Object.entries(NODE_COLORS).map(([type, color]) => (
                  <div key={type} className="flex items-center gap-1.5">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                    <span className="text-xs capitalize" style={{ color: 'var(--fg-2)' }}>{type}</span>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-3 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <div className="flex items-center gap-1">
                  <div className="w-6 h-0.5" style={{ backgroundColor: 'var(--crit)' }} />
                  <span className="text-xs" style={{ color: 'var(--muted)' }}>Malicious</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-6 h-0.5 border-dashed border-t" style={{ borderColor: 'var(--muted)' }} />
                  <span className="text-xs" style={{ color: 'var(--muted)' }}>DNS</span>
                </div>
              </div>
              <div className="flex items-center gap-1 mt-1">
                <div className="w-4 h-4 rounded-full border-2 border-dashed" style={{ borderColor: 'var(--crit)' }} />
                <span className="text-xs ml-1" style={{ color: 'var(--muted)' }}>Root Cause</span>
              </div>
            </div>

            {/* Timeline playback (bottom center) */}
            <div
              className="absolute bottom-4 left-1/2 -translate-x-1/2 rounded-lg px-4 py-3 z-10 flex items-center gap-4"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              <button
                onClick={() => setTimelineProgress(0)}
                className="p-1.5 rounded hover:bg-[var(--surface-3)]"
                title="Go to start"
              >
                <SkipBack size={14} style={{ color: 'var(--muted)' }} />
              </button>
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className="btn-sentinel btn-sentinel-primary btn-sentinel-icon"
              >
                {isPlaying ? <Pause size={14} /> : <Play size={14} />}
              </button>
              <button
                onClick={() => setTimelineProgress(100)}
                className="p-1.5 rounded hover:bg-[var(--surface-3)]"
                title="Go to end"
              >
                <SkipForward size={14} style={{ color: 'var(--muted)' }} />
              </button>

              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={timelineProgress}
                  onChange={(e) => setTimelineProgress(parseInt(e.target.value))}
                  className="w-48 h-1 rounded-lg appearance-none cursor-pointer"
                  style={{ backgroundColor: 'var(--border)', accentColor: 'var(--emerald-500)' }}
                />
                <span className="text-xs w-10 text-right" style={{ color: 'var(--muted)' }}>{Math.round(timelineProgress)}%</span>
              </div>

              <div className="flex items-center gap-1 pl-3" style={{ borderLeft: '1px solid var(--border)' }}>
                <span className="text-xs" style={{ color: 'var(--muted)' }}>Speed:</span>
                {[0.5, 1, 2].map((speed) => (
                  <button
                    key={speed}
                    onClick={() => setPlaybackSpeed(speed)}
                    className="px-2 py-0.5 rounded text-xs"
                    style={{
                      backgroundColor: playbackSpeed === speed ? 'var(--emerald-500)' : 'transparent',
                      color: playbackSpeed === speed ? 'white' : 'var(--muted)'
                    }}
                  >
                    {speed}x
                  </button>
                ))}
              </div>
            </div>

            {/* SVG Canvas */}
            <svg
              ref={svgRef}
              className="w-full h-full"
              style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
            >
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Render edges first (below nodes) */}
                {filteredEdges.map(renderEdge)}

                {/* Render nodes */}
                {filteredNodes.map(renderNode)}
              </g>
            </svg>
          </div>

          {/* Right panel */}
          <div
            className="w-[420px] flex flex-col overflow-hidden"
            style={{ backgroundColor: 'var(--surface)', borderLeft: '1px solid var(--border)' }}
          >
            {/* Panel tabs */}
            <div className="flex" style={{ borderBottom: '1px solid var(--border)' }}>
              {(['analysis', 'details', 'timeline', 'actions'] as const).map((panel) => (
                <button
                  key={panel}
                  onClick={() => setActivePanel(activePanel === panel ? null : panel)}
                  className="flex-1 px-3 py-3 text-sm font-medium transition-colors"
                  style={{
                    backgroundColor: activePanel === panel ? 'var(--surface-2)' : 'transparent',
                    color: activePanel === panel ? 'var(--fg)' : 'var(--muted)',
                    borderBottom: activePanel === panel ? '2px solid var(--emerald-500)' : '2px solid transparent'
                  }}
                >
                  {panel === 'analysis' && 'Analysis'}
                  {panel === 'details' && 'Details'}
                  {panel === 'timeline' && 'Timeline'}
                  {panel === 'actions' && 'Actions'}
                </button>
              ))}
            </div>

            {/* Panel content */}
            <div className="flex-1 overflow-y-auto p-4">
              {/* Analysis Panel */}
              {activePanel === 'analysis' && analysis && (
                <div className="space-y-4">
                  {/* Kill Chain Progress */}
                  <KillChainProgress
                    currentPhase={storyline.attack_phase}
                    detectedPhases={detectedPhases}
                  />

                  {/* Root Cause */}
                  {storyline.root_cause && (
                    <CollapsibleSection title="Root Cause" icon={Crosshair} badge={`${Math.round(storyline.root_cause.confidence_score * 100)}%`} badgeColor="var(--crit)">
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Cpu size={14} style={{ color: 'var(--med)' }} />
                          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                            {storyline.root_cause.process_name || storyline.root_cause.entity_name}
                          </span>
                          {storyline.root_cause.pid && (
                            <span className="text-xs" style={{ color: 'var(--muted)' }}>PID: {storyline.root_cause.pid}</span>
                          )}
                        </div>
                        {storyline.root_cause.cmdline && (
                          <LongTextPreview value={storyline.root_cause.cmdline} copyLabel="Copy command" />
                        )}
                        {storyline.root_cause.reasoning && (
                          <div className="text-xs mt-2" style={{ color: 'var(--muted)' }}>
                            {storyline.root_cause.reasoning}
                          </div>
                        )}
                      </div>
                    </CollapsibleSection>
                  )}

                  {/* Threat Assessment */}
                  <CollapsibleSection title="Threat Assessment" icon={Shield}>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>Risk Level</div>
                        <div
                          className="text-sm font-medium capitalize"
                          style={{ color: SEVERITY_COLORS[analysis.threat_assessment.risk_level] }}
                        >
                          {analysis.threat_assessment.risk_level}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>Attack Phase</div>
                        <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                          {ATTACK_PHASE_LABELS[analysis.threat_assessment.phase] || analysis.threat_assessment.phase}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>Indicators</div>
                        <div className="text-sm" style={{ color: 'var(--fg)' }}>{analysis.threat_assessment.indicators_count}</div>
                      </div>
                      <div>
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>Techniques</div>
                        <div className="text-sm" style={{ color: 'var(--fg)' }}>{analysis.threat_assessment.techniques_count}</div>
                      </div>
                    </div>
                  </CollapsibleSection>

                  {/* Attack Narrative */}
                  <CollapsibleSection title="Attack Narrative" icon={FileText}>
                    <p className="text-sm leading-relaxed" style={{ color: 'var(--fg-2)' }}>{analysis.attack_narrative}</p>
                  </CollapsibleSection>

                  {/* MITRE Techniques */}
                  {analysis.attack_techniques.length > 0 && (
                    <CollapsibleSection
                      title="MITRE ATT&CK Techniques"
                      icon={Target}
                      badge={analysis.attack_techniques.length}
                      badgeColor="var(--sol-magenta)"
                    >
                      <div className="space-y-2">
                        {analysis.attack_techniques.map((tech) => (
                          <div key={tech.id} className="rounded-lg p-3" style={{ backgroundColor: 'var(--bg-2)' }}>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{tech.name}</span>
                              <a
                                href={mitreTechniqueHref(tech.id)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs font-mono flex items-center gap-1 hover:opacity-80"
                                style={{ color: 'var(--sol-magenta)' }}
                              >
                                {tech.id}
                                <ExternalLink size={10} />
                              </a>
                            </div>
                            <div className="text-xs mb-1" style={{ color: 'var(--muted)' }}>{tech.tactic}</div>
                            <div className="text-xs" style={{ color: 'var(--muted)' }}>{tech.description}</div>
                          </div>
                        ))}
                      </div>
                    </CollapsibleSection>
                  )}

                  {/* Recommended Actions */}
                  {analysis.recommended_actions.length > 0 && (
                    <CollapsibleSection
                      title="Recommended Actions"
                      icon={Activity}
                      badge={analysis.recommended_actions.length}
                      badgeColor="var(--emerald-400)"
                    >
                      <div className="space-y-2">
                        {analysis.recommended_actions.map((action, i) => (
                          <div key={i} className="rounded-lg p-3" style={{ backgroundColor: 'var(--bg-2)' }}>
                            <div className="flex items-center gap-2 mb-1">
                              <span
                                className="badge-sentinel"
                                style={{
                                  backgroundColor: action.priority === 'immediate' ? 'var(--crit-bg)' : action.priority === 'high' ? 'var(--high-bg)' : 'var(--med-bg)',
                                  color: action.priority === 'immediate' ? 'var(--crit)' : action.priority === 'high' ? 'var(--high)' : 'var(--med)'
                                }}
                              >
                                {action.priority}
                              </span>
                            </div>
                            <div className="text-sm" style={{ color: 'var(--fg)' }}>{action.action}</div>
                            <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{action.reason}</div>
                          </div>
                        ))}
                      </div>
                    </CollapsibleSection>
                  )}

                  {/* Threat Indicators */}
                  {storyline.threat_indicators.length > 0 && (
                    <CollapsibleSection
                      title="Threat Indicators"
                      icon={AlertTriangle}
                      badge={storyline.threat_indicators.length}
                      defaultOpen={false}
                    >
                      <div className="space-y-1 max-h-40 overflow-y-auto">
                        {storyline.threat_indicators.map((indicator, i) => (
                          <div key={i} className="flex items-center justify-between text-xs py-1">
                            <span className="uppercase" style={{ color: 'var(--muted)' }}>{indicator.type}</span>
                            <span className="font-mono truncate max-w-[200px]" style={{ color: 'var(--fg-2)' }} title={indicator.value}>
                              {indicator.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </CollapsibleSection>
                  )}
                </div>
              )}

              {/* Node Details Panel */}
              {activePanel === 'details' && (
                <div>
                  {selectedNode ? (
                    <div className="space-y-4">
                      {/* Node header */}
                      <div className="flex items-center gap-3">
                        <div
                          className="w-12 h-12 rounded-lg flex items-center justify-center"
                          style={{ backgroundColor: `${NODE_COLORS[selectedNode.type] || NODE_COLORS.process}20` }}
                        >
                          {(() => {
                            const Icon = NODE_ICONS[selectedNode.type] || Cpu;
                            return <Icon size={24} style={{ color: NODE_COLORS[selectedNode.type] || NODE_COLORS.process }} />;
                          })()}
                        </div>
                        <div className="flex-1 min-w-0">
                          <h3 className="text-sm font-semibold truncate" style={{ color: 'var(--fg)' }}>{selectedNode.full_label || selectedNode.label}</h3>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{selectedNode.type}</span>
                            {selectedNode.pid && (
                              <span className="text-xs" style={{ color: 'var(--muted)' }}>PID: {selectedNode.pid}</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Status badges */}
                      <div className="flex flex-wrap gap-2">
                        <span
                          className="badge-sentinel"
                          style={{
                            color: SEVERITY_COLORS[selectedNode.severity] || SEVERITY_COLORS.info,
                            backgroundColor: SEVERITY_BG_COLORS[selectedNode.severity] || SEVERITY_BG_COLORS.info,
                          }}
                        >
                          {selectedNode.severity}
                        </span>
                        {selectedNode.suspicious ? (
                          <span className="badge-sentinel badge-sentinel-critical">
                            Suspicious
                          </span>
                        ) : null}
                        {selectedNode.highlighted ? (
                          <span className="badge-sentinel badge-sentinel-high">
                            Highlighted
                          </span>
                        ) : null}
                        {Boolean(selectedNode.data.is_elevated) ? (
                          <span className="badge-sentinel badge-sentinel-high flex items-center gap-1">
                            <Shield size={10} /> Elevated
                          </span>
                        ) : null}
                        {selectedNode.data.is_signed === false ? (
                          <span className="badge-sentinel badge-sentinel-warning">
                            Unsigned
                          </span>
                        ) : null}
                      </div>

                      {/* Timestamp */}
                      {selectedNode.timestamp && (
                        <div className="text-xs flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                          <Clock size={12} />
                          {selectedNode.timestamp}
                        </div>
                      )}

                      <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                        <div className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                          Summary
                        </div>
                        <div className="text-sm leading-relaxed" style={{ color: 'var(--fg-2)' }}>
                          {summarizeStorylineNode(selectedNode, filteredEdges, storyline.nodes)}
                        </div>
                      </div>

                      <NodeIntelligenceCards
                        node={selectedNode}
                        edges={filteredEdges}
                        allNodes={storyline.nodes}
                      />

                      {/* Command line for process nodes */}
                      {selectedNode.type === 'process' && selectedNode.data.cmdline && (
                        <div className="card-sentinel">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium" style={{ color: 'var(--muted)' }}>Command Line</span>
                            <button
                              onClick={() => navigator.clipboard.writeText(String(selectedNode.data.cmdline))}
                              className="hover:opacity-80"
                              style={{ color: 'var(--muted)' }}
                            >
                              <Copy size={12} />
                            </button>
                          </div>
                          <LongTextPreview value={String(selectedNode.data.cmdline)} copyLabel="Copy command" />
                        </div>
                      )}

                      {/* Detections */}
                      {selectedNode.detections.length > 0 && (
                        <div className="card-sentinel card-sentinel-critical">
                          <h4 className="text-xs font-semibold flex items-center gap-1 mb-2" style={{ color: 'var(--crit)' }}>
                            <AlertTriangle size={12} />
                            {selectedNode.detections.length} Detection(s)
                          </h4>
                          <div className="space-y-2">
                            {selectedNode.detections.map((det, i) => (
                              <div key={i} className="rounded p-2" style={{ backgroundColor: 'var(--bg-2)' }}>
                                <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{det.ruleName}</div>
                                <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{det.description}</div>
                                {det.mitreTechniques.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-2">
                                    {det.mitreTechniques.map((tech, j) => (
                                      <span
                                        key={j}
                                        className="px-1.5 py-0.5 rounded text-xs font-mono"
                                        style={{ backgroundColor: 'rgba(217, 70, 239, 0.2)', color: 'var(--sol-magenta)' }}
                                      >
                                        {tech}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Node data */}
                      <CollapsibleSection title="Properties" icon={Database} defaultOpen={false}>
                        <div className="space-y-1">
                          {Object.entries(selectedNode.data).slice(0, 15).map(([key, value]) => (
                            <div key={key} className="flex justify-between text-xs py-1">
                              <span style={{ color: 'var(--muted)' }}>{key}</span>
                              <span className="truncate max-w-[200px] font-mono" style={{ color: 'var(--fg-2)' }} title={String(value)}>
                                {String(value)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </CollapsibleSection>

                      {/* Connected edges */}
                      <CollapsibleSection title="Connections" icon={Network}>
                        <div className="space-y-1 max-h-40 overflow-y-auto">
                          {filteredEdges
                            .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                            .map((edge) => {
                              const otherId = edge.source === selectedNode.id ? edge.target : edge.source;
                              const otherNode = storyline?.nodes.find(n => n.id === otherId);
                              const isOutgoing = edge.source === selectedNode.id;
                              return (
                                <div
                                  key={edge.id}
                                  className="flex items-center gap-2 text-xs py-1.5 rounded px-2 cursor-pointer hover:bg-[var(--surface-2)]"
                                  onClick={() => {
                                    if (otherNode) {
                                      setSelectedNode(otherNode);
                                    }
                                  }}
                                >
                                  <span className="w-4" style={{ color: 'var(--muted)' }}>{isOutgoing ? '->' : '<-'}</span>
                                  <span className="w-16 truncate" style={{ color: 'var(--muted)' }}>{edge.label}</span>
                                  <span className="truncate flex-1" style={{ color: 'var(--fg-2)' }}>{otherNode?.label || otherId}</span>
                                </div>
                              );
                            })}
                        </div>
                      </CollapsibleSection>
                    </div>
                  ) : (
                    <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
                      <Eye size={32} className="mx-auto mb-2 opacity-50" />
                      <p>Click a node to view details</p>
                    </div>
                  )}
                </div>
              )}

              {/* Timeline Panel */}
              {activePanel === 'timeline' && (
                <div className="space-y-2">
                  {storyline.timeline.length > 0 ? (
                    storyline.timeline.map((entry, i) => {
                      const isVisible = (i / storyline.timeline.length) * 100 <= timelineProgress;
                      return (
                        <div
                          key={entry.id || i}
                          className="card-sentinel cursor-pointer transition-opacity"
                          style={{ opacity: isVisible ? 1 : 0.3 }}
                          onClick={() => setTimelineProgress((i / storyline.timeline.length) * 100)}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span
                              className="badge-sentinel"
                              style={{
                                color: SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || 'var(--muted)',
                                backgroundColor: SEVERITY_BG_COLORS[entry.severity as keyof typeof SEVERITY_BG_COLORS] || 'var(--low-bg)',
                              }}
                            >
                              {entry.event_type}
                            </span>
                            <span className="text-xs" style={{ color: 'var(--muted)' }}>{entry.timestamp}</span>
                          </div>
                          <div className="text-sm" style={{ color: 'var(--fg)' }}>{entry.summary}</div>
                          {entry.detections.length > 0 && (
                            <div className="flex items-center gap-1 mt-2">
                              <AlertTriangle size={12} style={{ color: 'var(--crit)' }} />
                              <span className="text-xs" style={{ color: 'var(--crit)' }}>{entry.detections.length} detection(s)</span>
                            </div>
                          )}
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
                      <Clock size={32} className="mx-auto mb-2 opacity-50" />
                      <p>No timeline events</p>
                    </div>
                  )}
                </div>
              )}

              {/* Actions Panel */}
              {activePanel === 'actions' && (
                <div className="space-y-4">
                  {/* Response Actions */}
                  <CollapsibleSection title="Response Actions" icon={Shield}>
                    <div className="space-y-2">
                      <ActionButton
                        icon={Lock}
                        label="Isolate Endpoint"
                        onClick={handleIsolateEndpoint}
                        variant="danger"
                        loading={actionLoading === 'isolate'}
                      />

                      {selectedNode?.type === 'process' && (
                        <ActionButton
                          icon={Square}
                          label="Kill Process"
                          onClick={handleKillProcess}
                          variant="danger"
                          loading={actionLoading === 'kill'}
                        />
                      )}

                      {selectedNode?.type === 'file' && (
                        <ActionButton
                          icon={Trash2}
                          label="Quarantine File"
                          onClick={handleQuarantineFile}
                          variant="warning"
                          loading={actionLoading === 'quarantine'}
                        />
                      )}

                      <ActionButton
                        icon={Terminal}
                        label="Open Live Response"
                        onClick={() => router.visit(`/app/live-response/${storyline?.agent_id}`)}
                        variant="primary"
                      />
                    </div>
                  </CollapsibleSection>

                  {/* Investigation Actions */}
                  <CollapsibleSection title="Investigation" icon={Search}>
                    <div className="space-y-2">
                      <ActionButton
                        icon={Search}
                        label="Hunt Related Events"
                        onClick={() => {
                          const query = selectedNode?.pid
                            ? `pid:${selectedNode.pid}`
                            : storyline.alert_id
                              ? `alert:${storyline.alert_id}`
                              : '';
                          router.visit(`/app/hunt?q=${encodeURIComponent(query)}`);
                        }}
                        variant="secondary"
                      />

                      <ActionButton
                        icon={Globe}
                        label="View Network Activity"
                        onClick={() => router.visit(`/app/network?agent_id=${storyline?.agent_id}`)}
                        variant="secondary"
                      />

                      <ActionButton
                        icon={FileText}
                        label="Export Report"
                        onClick={() => {
                          if (alert_id) {
                            window.location.assign(`/api/v1/storyline/export/${alert_id}?format=json`);
                          }
                        }}
                        variant="secondary"
                        disabled={!alert_id}
                      />
                    </div>
                  </CollapsibleSection>

                  {/* Quick Links */}
                  <CollapsibleSection title="Quick Links" icon={ExternalLink}>
                    <div className="space-y-1">
                      {storyline.mitre_techniques.slice(0, 5).map((tech) => (
                        <a
                          key={tech}
                          href={mitreTechniqueHref(tech)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center justify-between text-sm py-1.5 px-2 rounded hover:bg-[var(--surface-2)]"
                          style={{ color: 'var(--muted)' }}
                        >
                          <span className="font-mono">{tech}</span>
                          <ExternalLink size={12} />
                        </a>
                      ))}
                    </div>
                  </CollapsibleSection>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Share Modal */}
      {showShareModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="rounded-lg p-6 w-96" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Share Investigation</h3>
              <button onClick={() => setShowShareModal(false)} className="hover:opacity-80" style={{ color: 'var(--muted)' }}>
                <X size={20} />
              </button>
            </div>
            <p className="text-sm mb-4" style={{ color: 'var(--muted)' }}>
              Share this investigation link with your team members.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={shareLink}
                readOnly
                className="input-sentinel flex-1"
              />
              <button
                onClick={copyShareLink}
                className="btn-sentinel btn-sentinel-primary flex items-center gap-2"
              >
                <Copy size={14} />
                Copy
              </button>
            </div>
          </div>
        </div>
      )}

      <Dialog
        open={!!pendingKill}
        onOpenChange={(o) => !o && setPendingKill(null)}
        title="Kill process"
        description={pendingKill ? `Kill PID ${pendingKill.pid}? This sends a force kill command for the selected process.` : ''}
      >
        <DialogFooter>
          <button
            type="button"
            className="btn-sentinel btn-sentinel-secondary"
            onClick={() => setPendingKill(null)}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn-sentinel btn-sentinel-danger"
            onClick={confirmKillProcess}
          >
            Kill process
          </button>
        </DialogFooter>
      </Dialog>
    </MainLayout>
  );
}
