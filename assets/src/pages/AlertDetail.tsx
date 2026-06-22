import { useState, useEffect } from 'react';
import { Head, router } from '@inertiajs/react';
import {
  ArrowLeft, Clock, AlertTriangle, Activity, Cpu, Shield, RefreshCw,
  Globe, File, Server, Settings, ChevronDown, ChevronUp, X, Play, Check, XCircle,
  Share2, Search, ExternalLink, Copy, Trash2, Eye, Crosshair, GitBranch,
  FileText, Terminal, ArrowRight, Database, Wifi, ShieldCheck, ShieldAlert,
  Lock, FileCheck, Hash, Link2, Layers
} from 'lucide-react';
import InvestigationGraph from '@/components/InvestigationGraph';
import EntityPivot from '@/components/EntityPivot';
import EvidencePanel from '@/components/EvidencePanel';
import ProcessChainView from '@/components/ProcessChainView';
import { Menu, MenuItem, Tooltip } from '@/components/ui/baseui';
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger';
import type { Alert, Agent, GraphNode, GraphEdge, TimelineEntry, GraphNodeType, Evidence, ProcessChainNode } from '@/types';

// Proof attestation data from Solana blockchain
interface ProofAttestation {
  attested: boolean;
  alert_id: string;
  tx_id?: string;
  attested_at?: string;
  solscan_url?: string;
  manifest_hash?: string;
  incident_hash?: string;
  slot?: number;
  included_fields?: string[];
  eligible?: boolean;
  severity?: string;
  tlp?: string;
  ioc_count?: number;
  ioc_types?: string[];
  redacted_ioc_count?: number;
  confidence?: number;
  threat_class?: string;
  malware_family?: string;
  public_manifest?: Record<string, unknown>;
  bounty?: {
    tx_id: string;
    amount_lamports: number;
    amount_sol: number;
    paid_at?: string;
  } | null;
}

// IOC (Indicator of Compromise) type
interface IOC {
  type: 'ip' | 'hash' | 'domain' | 'url' | 'email' | 'file_path';
  value: string;
  source?: string;
  confidence?: number;
  tlp?: string;
  blockable?: boolean;
  redacted?: boolean;
}

// Workflow step for timeline
interface WorkflowStep {
  id: string;
  label: string;
  status: 'completed' | 'current' | 'pending';
  timestamp?: string;
  icon: React.ComponentType<{ className?: string; size?: number }>;
}

interface RelatedEvent {
  id: string;
  event_type: string;
  timestamp: string;
  summary: string;
  pid?: number;
  process_name?: string;
  severity: string;
  payload: Record<string, any>;
  correlation_score?: number;
  correlation_reason?: string;
  correlation_kind?: 'engine' | 'context_only' | 'fallback';
  score_explanation?: string;
  score_version?: string;
  correlation_version?: string;
  evidence_count?: number;
  telemetry_gaps?: string[];
}

interface ResponseActionRecord {
  id: string;
  action_type: string;
  status: string;
  parameters?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error_message?: string | null;
  executed_at?: string | null;
  created_at?: string | null;
  executed_by_id?: string | null;
}

type AlertTab = 'graph' | 'timeline' | 'events' | 'related' | 'evidence' | 'process-chain';
const ALERT_TABS: AlertTab[] = ['graph', 'evidence', 'process-chain', 'timeline', 'events', 'related'];

interface StoryStep {
  id: string;
  label: string;
  title: string;
  detail: string;
  icon: React.ComponentType<{ className?: string; size?: number }>;
  tone: 'critical' | 'high' | 'medium' | 'low' | 'accent' | 'muted';
  tab?: AlertTab;
}

interface AlertDetailPageProps {
  alert: Alert;
  agent: Agent | null;
  relatedEvents: RelatedEvent[];
  relatedAlerts: Alert[];
  responseActions?: ResponseActionRecord[];
  graphData: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    stats: {
      process_count: number;
      network_count: number;
      file_count: number;
      dns_count: number;
    };
  } | null;
  timeline: TimelineEntry[];
}

const NODE_ICONS: Record<GraphNodeType, typeof Cpu> = {
  process: Cpu,
  network: Globe,
  file: File,
  dns: Server,
  registry: Settings,
};

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

function firstPresent(...values: unknown[]): unknown {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function parsePid(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function normalizeCorrelationScore(value: unknown): number {
  const score = Number(value || 0);
  if (!Number.isFinite(score) || score <= 0) return 0;
  return Math.min(100, Math.round(score <= 1 ? score * 100 : score));
}

function basename(path?: string): string | undefined {
  if (!path) return undefined;
  return path.split(/[\\/]/).filter(Boolean).pop();
}

function shortValue(value?: string | null, start = 16, end = 10): string {
  if (!value) return 'not available';
  return value.length > start + end + 3 ? `${value.slice(0, start)}...${value.slice(-end)}` : value;
}

function asText(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : value == null ? fallback : String(value);
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(item => asText(item).trim()).filter(Boolean) : [];
}

function humanizeValue(value: unknown, fallback = 'not recorded'): string {
  const text = asText(value).trim();
  return text ? text.replace(/_/g, ' ') : fallback;
}

function mitreTechniqueHref(value: unknown): string {
  const id = asText(value).trim();
  return id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}` : 'https://attack.mitre.org/';
}

function decodePowerShellEncodedCommand(cmdline?: string | null): string | null {
  if (!cmdline) return null;
  const match = cmdline.match(/(?:-|\/)(?:enc|encodedcommand)\s+([A-Za-z0-9+/=_-]+)/i);
  if (!match?.[1]) return null;

  try {
    const normalized = match[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
    const decoded = new TextDecoder('utf-16le', { fatal: false }).decode(bytes).replace(/\0/g, '').trim();
    return decoded || null;
  } catch (_error) {
    return null;
  }
}

function extractUrls(text?: string | null): string[] {
  if (!text) return [];
  return Array.from(text.matchAll(/\bhttps?:\/\/[^\s'"`<>]+/gi), match => match[0]);
}

function inferDetectionType(ruleType?: string, ruleName?: string): string | null {
  const type = ruleType?.trim().toLowerCase();
  if (type && type !== 'unknown') return type;

  const normalizedRule = ruleName?.trim().toLowerCase() || '';

  if (
    normalizedRule.startsWith('kernel_syscall_') ||
    normalizedRule.includes('powershell') ||
    normalizedRule.includes('execution_policy') ||
    normalizedRule.includes('defense_evasion')
  ) {
    return 'defense_evasion';
  }

  if (normalizedRule.startsWith('registry_') || normalizedRule.includes('persistence')) return 'persistence';
  if (normalizedRule.includes('credential')) return 'credential_theft';
  if (normalizedRule.includes('ransomware')) return 'ransomware';
  if (normalizedRule.includes('lateral')) return 'lateral_movement';

  return type || null;
}

function humanizeDetectionType(type: string): string {
  return asText(type, 'unknown')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function processFromPayload(
  payload: Record<string, any> = {},
  fallback: Partial<ProcessChainNode> = {}
): (ProcessChainNode & { ppid?: number }) | null {
  const pid = parsePid(firstPresent(
    fallback.pid,
    payload.pid,
    payload.process_id,
    payload.target_pid,
    payload.ProcessId
  ));

  if (!pid) return null;

  const path = firstPresent(
    fallback.path,
    payload.path,
    payload.image_path,
    payload.process_path,
    payload.exe,
    payload.image
  ) as string | undefined;

  const name = firstPresent(
    fallback.name,
    payload.name,
    payload.process_name,
    payload.image_name,
    basename(path),
    `PID ${pid}`
  ) as string;

  return {
    pid,
    name,
    path,
    cmdline: firstPresent(
      fallback.cmdline,
      payload.cmdline,
      payload.command_line,
      payload.command
    ) as string | undefined,
    sha256: firstPresent(fallback.sha256, payload.sha256, payload.hash) as string | undefined,
    user: firstPresent(fallback.user, payload.user, payload.username) as string | undefined,
    start_time: firstPresent(fallback.start_time, payload.start_time, payload.timestamp) as string | undefined,
    level: 0,
    is_malicious: fallback.is_malicious ?? false,
    ppid: parsePid(firstPresent(payload.ppid, payload.parent_pid, payload.ParentProcessId)),
  };
}

function buildFallbackProcessChain(
  alert: Alert,
  relatedEvents: RelatedEvent[],
  timeline: TimelineEntry[]
): ProcessChainNode[] {
  if (alert.processChain && alert.processChain.length > 0) return alert.processChain;

  const candidates: Array<ProcessChainNode & { ppid?: number }> = [];
  const evidence = alert.evidence || {};

  const evidenceProcess = processFromPayload(evidence.process || {}, { is_malicious: true });
  if (evidenceProcess) candidates.push(evidenceProcess);

  relatedEvents.forEach(event => {
    const correlationScore = normalizeCorrelationScore(event.correlation_score);
    const process = processFromPayload(event.payload || {}, {
      pid: event.pid,
      name: event.process_name,
      start_time: event.timestamp,
      is_malicious: event.id === alert.sourceEventId || correlationScore >= 80,
    });
    if (process) candidates.push(process);
  });

  timeline.forEach(entry => {
    const process = processFromPayload(entry as unknown as Record<string, any>, {
      pid: entry.pid,
      name: entry.summary?.match(/Process(?: created)?:\s*([^(]+)/i)?.[1]?.trim(),
      start_time: entry.timestamp,
    });
    if (process) candidates.push(process);
  });

  const byPid = new Map<number, ProcessChainNode & { ppid?: number }>();
  candidates.forEach(process => {
    const existing = byPid.get(process.pid);
    byPid.set(process.pid, {
      ...process,
      ...existing,
      ...Object.fromEntries(
        Object.entries(process).filter(([, value]) => value !== undefined && value !== null && value !== '')
      ),
      is_malicious: Boolean(existing?.is_malicious || process.is_malicious),
    });
  });

  const unique = Array.from(byPid.values());
  if (unique.length === 0) return [];

  const childPids = new Set(unique.map(process => process.pid));
  const rootPid =
    unique.find(process => process.ppid && !childPids.has(process.ppid))?.pid ||
    unique.find(process => !process.ppid)?.pid ||
    unique[0].pid;

  const ordered: Array<ProcessChainNode & { ppid?: number }> = [];
  const visited = new Set<number>();

  const appendChain = (pid: number, level: number) => {
    const process = byPid.get(pid);
    if (!process || visited.has(pid)) return;
    visited.add(pid);
    ordered.push({ ...process, level });

    unique
      .filter(candidate => candidate.ppid === pid)
      .sort((a, b) => a.pid - b.pid)
      .forEach(child => appendChain(child.pid, level + 1));
  };

  appendChain(rootPid, 0);
  unique
    .filter(process => !visited.has(process.pid))
    .sort((a, b) => a.pid - b.pid)
    .forEach(process => ordered.push({ ...process, level: ordered.length ? 1 : 0 }));

  return ordered.map(({ ppid: _ppid, ...process }) => process);
}

export default function AlertDetail({
  alert,
  agent,
  relatedEvents: initialRelatedEvents,
  relatedAlerts,
  responseActions = [],
  graphData,
  timeline,
}: AlertDetailPageProps) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeTab, setActiveTab] = useState<AlertTab>(() => {
    if (typeof window === 'undefined') return 'graph';
    const tab = new URLSearchParams(window.location.search).get('tab') as AlertTab | null;
    return tab && ALERT_TABS.includes(tab) ? tab : 'graph';
  });
  const [isUpdating, setIsUpdating] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // State for dynamically fetched related events
  const [relatedEvents, setRelatedEvents] = useState<RelatedEvent[]>(
    initialRelatedEvents.map(event => ({
      ...event,
      correlation_score: normalizeCorrelationScore(event.correlation_score),
    }))
  );
  const [isLoadingRelatedEvents, setIsLoadingRelatedEvents] = useState(false);
  const [relatedEventsError, setRelatedEventsError] = useState<string | null>(null);

  // Proof attestation state
  const [proofData, setProofData] = useState<ProofAttestation | null>(null);
  const [isLoadingProof, setIsLoadingProof] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  // IOCs section state
  const [iocsExpanded, setIocsExpanded] = useState(true);

  // Fetch related events dynamically using the Correlator API
  const fetchRelatedEvents = async () => {
    if (!alert.sourceEventId || !agent?.id) {
      // If no source event ID, use the initial server-side rendered events
      setRelatedEvents(initialRelatedEvents);
      return;
    }

    setIsLoadingRelatedEvents(true);
    setRelatedEventsError(null);

    try {
      const response = await fetch(
        `/api/v1/events/${alert.sourceEventId}/related?agent_id=${agent.id}&time_window=60&limit=50`,
        { credentials: 'include' }
      );

      if (!response.ok) {
        throw new Error(`Failed to fetch related events: ${response.status}`);
      }

      const data = await response.json();
      const events = (data.related_events || []).map((event: any) => ({
        id: event.event_id || event.id,
        event_type: event.event_type,
        timestamp: event.timestamp,
        summary: event.summary,
        pid: event.pid,
        process_name: event.process_name,
        severity: event.severity || 'info',
        payload: event.payload || {},
        correlation_score: normalizeCorrelationScore(event.correlation_score),
        correlation_reason: event.correlation_reason || '',
        correlation_kind: event.correlation_kind || (event.correlation_score > 0 ? 'engine' : 'context_only'),
        score_explanation: event.score_explanation || '',
        score_version: event.score_version || event.scoring_version || event.correlation_version,
        correlation_version: event.correlation_version,
        evidence_count: event.evidence_count,
        telemetry_gaps: Array.isArray(event.telemetry_gaps) ? event.telemetry_gaps : [],
      }));

      setRelatedEvents(events);
    } catch (err) {
      logger.error('Error fetching related events:', err);
      setRelatedEventsError(err instanceof Error ? err.message : 'Failed to fetch related events');
      // Keep showing the initial events on error
    } finally {
      setIsLoadingRelatedEvents(false);
    }
  };

  const selectTab = (tab: AlertTab) => {
    setActiveTab(tab);
    if (typeof window === 'undefined') return;

    const url = new URL(window.location.href);
    url.searchParams.set('tab', tab);
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
  };

  // Auto-fetch related events when component mounts or when switching to events tab
  useEffect(() => {
    if (activeTab === 'events' && alert.sourceEventId && agent?.id) {
      fetchRelatedEvents();
    }
  }, [activeTab, alert.sourceEventId, agent?.id]);

  // Fetch proof attestation data
  const fetchProofData = async () => {
    setIsLoadingProof(true);
    setProofError(null);
    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/attestation`, {
        credentials: 'include'
      });
      if (response.ok) {
        const data = await response.json();
        setProofData(data.data);
      } else {
        setProofError(`Proof lookup failed with HTTP ${response.status}`);
      }
    } catch (err) {
      logger.error('Failed to fetch proof data:', err);
      setProofError(err instanceof Error ? err.message : 'Failed to fetch proof data');
    } finally {
      setIsLoadingProof(false);
    }
  };

  // Auto-fetch proof data on mount
  useEffect(() => {
    fetchProofData();
  }, [alert.id]);

  // Extract IOCs from evidence
  const extractIOCs = (): IOC[] => {
    const normalized = (alert as Alert & { iocs?: IOC[] }).iocs || [];
    if (normalized.length > 0) {
      return normalized;
    }

    const iocs: IOC[] = [];
    const evidence = alert.evidence || {};

    // Extract file hashes
    if (evidence.file_hashes) {
      evidence.file_hashes.forEach((hash: any) => {
        if (hash.sha256) iocs.push({ type: 'hash', value: hash.sha256, source: 'SHA256' });
        if (hash.sha1) iocs.push({ type: 'hash', value: hash.sha1, source: 'SHA1' });
        if (hash.md5) iocs.push({ type: 'hash', value: hash.md5, source: 'MD5' });
        if (hash.path) iocs.push({ type: 'file_path', value: hash.path, source: 'File' });
      });
    }

    // Extract network indicators
    if (evidence.network) {
      evidence.network.forEach((net: any) => {
        if (net.type === 'ip' || net.type === 'IP') {
          iocs.push({ type: 'ip', value: net.value, source: net.direction || 'Network' });
        } else if (net.type === 'domain' || net.type === 'Domain') {
          iocs.push({ type: 'domain', value: net.value, source: 'DNS' });
        } else if (net.type === 'url' || net.type === 'URL') {
          iocs.push({ type: 'url', value: net.value, source: 'HTTP' });
        }
      });
    }

    // Extract process hash if available
    if (evidence.process?.sha256) {
      iocs.push({ type: 'hash', value: evidence.process.sha256, source: 'Process' });
    }

    return dedupeIOCs(iocs);
  };

  const dedupeIOCs = (iocs: IOC[]): IOC[] => {
    const seen = new Set<string>();
    return iocs.filter(ioc => {
      if (!ioc.value) return false;
      const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };

  // Compute workflow steps based on alert state
  const getWorkflowSteps = (): WorkflowStep[] => {
    // Determine step statuses based on alert status
    const isTriageStarted = ['investigating', 'resolved', 'false_positive'].includes(alert.status);
    const isResolved = ['resolved', 'false_positive'].includes(alert.status);
    const isInvestigating = alert.status === 'investigating';

    const steps: WorkflowStep[] = [
      {
        id: 'created',
        label: 'Alert Created',
        status: 'completed',
        timestamp: alert.createdAt,
        icon: AlertTriangle
      },
      {
        id: 'detection',
        label: 'Detection Triggered',
        status: 'completed',
        timestamp: alert.createdAt,
        icon: Shield
      },
      {
        id: 'triage',
        label: 'Triage Started',
        status: isTriageStarted ? 'completed' : (alert.status === 'new' ? 'current' : 'pending'),
        timestamp: isTriageStarted ? alert.createdAt : undefined,
        icon: Eye
      },
      {
        id: 'remediation',
        label: 'Remediation',
        status: isResolved ? 'completed' : (isInvestigating ? 'current' : 'pending'),
        timestamp: isResolved ? alert.createdAt : undefined,
        icon: Terminal
      },
      {
        id: 'proof',
        label: 'Proof Anchored',
        status: proofData?.attested ? 'completed' : 'pending',
        timestamp: proofData?.attested_at,
        icon: ShieldCheck
      }
    ];

    return steps;
  };

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      logger.error('Failed to copy:', err);
    }
  };

  const handleStatusChange = async (newStatus: Alert['status']) => {
    setIsUpdating(true);
    try {
      const res = await fetch(`/api/v1/alerts/${alert.id}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'include',
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) {
        setActionNotice({ type: 'error', message: `Status update failed with HTTP ${res.status}` });
        logger.error('Failed to update alert status:', res.status);
        return;
      }
      setActionNotice({ type: 'success', message: `Alert status updated to ${newStatus.replace(/_/g, ' ')}` });
      router.reload();
    } catch (err) {
      logger.error('Failed to update status:', err);
      setActionNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to update status' });
    } finally {
      setIsUpdating(false);
    }
  };

  const getActionUrl = (action: string, agentId: string) => {
    if (action === 'isolate') {
      return `/api/v1/agents/${agentId}/isolate`;
    }
    return `/api/v1/response/${action}`;
  };

  const handleResponseAction = async (action: string) => {
    if (!agent?.id) return;
    if (action === 'kill' && !alert.evidence?.process?.pid) {
      setActionNotice({ type: 'error', message: 'Cannot kill process: this alert has no process PID.' });
      return;
    }
    if (action === 'quarantine' && !alert.evidence?.file?.path) {
      setActionNotice({ type: 'error', message: 'Cannot quarantine file: this alert has no file path.' });
      return;
    }

    setIsUpdating(true);
    try {
      const payload: Record<string, any> = { agent_id: agent.id };
      if (action === 'kill' && alert.evidence?.process?.pid) {
        payload.pid = alert.evidence.process.pid;
      } else if (action === 'quarantine' && alert.evidence?.file?.path) {
        payload.path = alert.evidence.file.path;
      } else if (action === 'scan') {
        const path = alert.evidence?.file?.path || alert.evidence?.process?.path;
        if (!path) {
          setActionNotice({ type: 'error', message: 'Cannot scan: this alert has no file or process path.' });
          setIsUpdating(false);
          return;
        }
        payload.scan_type = 'full';
        payload.path = path;
      }
      payload.alert_id = alert.id;
      const res = await fetch(getActionUrl(action, agent.id), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        setActionNotice({ type: 'error', message: `${action} failed with HTTP ${res.status}` });
        logger.error(`Response action ${action} failed:`, res.status);
        return;
      }
      setActionNotice({ type: 'success', message: `${action} request accepted. Check response history for execution status.` });
      router.reload();
    } catch (err) {
      logger.error(`Response action ${action} error:`, err);
      setActionNotice({ type: 'error', message: err instanceof Error ? err.message : `${action} request failed` });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleBlockIOC = async (ioc: IOC) => {
    if (!agent?.id || !['ip', 'domain'].includes(ioc.type)) return;

    setIsUpdating(true);
    try {
      const endpoint = ioc.type === 'ip' ? '/api/v1/response/block-ip' : '/api/v1/response/block-domain';
      const payload =
        ioc.type === 'ip'
          ? { agent_id: agent.id, alert_id: alert.id, ip: ioc.value, direction: 'both', reason: `Blocked from alert ${alert.id}` }
          : { agent_id: agent.id, alert_id: alert.id, domain: ioc.value, reason: `Blocked from alert ${alert.id}` };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'include',
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        setActionNotice({ type: 'error', message: `Failed to block ${ioc.type} with HTTP ${res.status}` });
        logger.error(`Failed to block IOC ${ioc.type}:${ioc.value}`, res.status);
        return;
      }

      setActionNotice({ type: 'success', message: `Block request queued for ${ioc.type}: ${ioc.value}` });
      router.reload();
    } catch (err) {
      logger.error(`Failed to block IOC ${ioc.type}:${ioc.value}`, err);
      setActionNotice({ type: 'error', message: err instanceof Error ? err.message : `Failed to block ${ioc.value}` });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
  };

  const handleNodeDoubleClick = (node: GraphNode) => {
    if (node.type === 'process' && node.pid && agent) {
      router.visit(`/app/investigation/${node.pid}?type=process&agent_id=${agent.id}`);
    }
  };

  const handlePivot = (pivotType: string, entityData: Record<string, unknown>) => {
    if (!agent) return;

    switch (pivotType) {
      case 'process-tree':
        if (entityData.pid) router.visit(`/app/process-tree?agent_id=${agent.id}&pid=${entityData.pid}`);
        break;
      case 'network':
        if (entityData.pid) router.visit(`/app/network?agent_id=${agent.id}&pid=${entityData.pid}`);
        break;
      case 'hunt-hash':
        if (entityData.sha256) router.visit(`/app/hunt?q=${encodeURIComponent(`sha256:${entityData.sha256}`)}`);
        break;
      case 'hunt-ip':
        if (entityData.remote_ip) router.visit(`/app/hunt?q=${encodeURIComponent(`network.remote_ip:${entityData.remote_ip}`)}`);
        break;
      case 'hunt-domain':
        if (entityData.domain) router.visit(`/app/hunt?q=${encodeURIComponent(`dns.query:${entityData.domain}`)}`);
        break;
      case 'graph':
        if (entityData.pid && agent) {
          router.visit(`/app/investigation/${entityData.pid}?type=process&agent_id=${agent.id}`);
        }
        break;
    }
  };

  // Compute event flow summary stats
  const eventFlowStats = (() => {
    const networkEvents = relatedEvents.filter(e => e.event_type?.includes('network'));
    const processEvents = relatedEvents.filter(e => e.event_type?.includes('process'));
    const fileEvents = relatedEvents.filter(e => e.event_type?.includes('file'));
    const dnsEvents = relatedEvents.filter(e => e.event_type?.includes('dns'));

    let totalBytesSent = 0;
    let totalBytesRecv = 0;
    const uniqueIPs = new Set<string>();
    const uniqueDomains = new Set<string>();

    networkEvents.forEach(e => {
      const p = e.payload || {};
      totalBytesSent += Number(p.bytes_sent || p.sent_bytes || 0);
      totalBytesRecv += Number(p.bytes_received || p.recv_bytes || 0);
      const ip = p.remote_ip;
      if (ip) uniqueIPs.add(String(ip));
    });

    dnsEvents.forEach(e => {
      const p = e.payload || {};
      const domain = p.query || p.domain;
      if (domain) uniqueDomains.add(String(domain));
    });

    return {
      networkCount: networkEvents.length,
      processCount: processEvents.length,
      fileCount: fileEvents.length,
      dnsCount: dnsEvents.length,
      totalBytesSent,
      totalBytesRecv,
      uniqueIPs: uniqueIPs.size,
      uniqueDomains: uniqueDomains.size,
    };
  })();

  const formatBytes = (bytes: number): string => {
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-crit';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-med';
      case 'low': return 'severity-low';
      default: return 'severity-info';
    }
  };

  const getSeverityBgStyle = (severity: string): React.CSSProperties => {
    switch (severity) {
      case 'critical': return { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)' };
      case 'high': return { backgroundColor: 'color-mix(in srgb, var(--high) 20%, transparent)' };
      case 'medium': return { backgroundColor: 'color-mix(in srgb, var(--med) 20%, transparent)' };
      case 'low': return { backgroundColor: 'color-mix(in srgb, var(--low) 20%, transparent)' };
      default: return { backgroundColor: 'color-mix(in srgb, var(--accent) 20%, transparent)' };
    }
  };

  const getThreatScoreColor = (score: number) => {
    if (score >= 0.80) return 'text-[var(--crit)]';
    if (score >= 0.50) return 'text-[var(--high)]';
    if (score >= 0.30) return 'text-[var(--med)]';
    return 'text-[var(--low)]';
  };

  const displayThreatScore = (score: number | null | undefined) => {
    if (score == null) return 'N/A';
    const numericScore = Number(score);
    if (Number.isNaN(numericScore)) return 'N/A';
    if (numericScore <= 1) return Math.round(numericScore * 100).toString();
    if (numericScore <= 100) return Math.round(numericScore).toString();
    return Math.round(numericScore).toLocaleString();
  };

  const getStatusActions = () => {
    switch (alert.status) {
      case 'open':
        return [
          { status: 'investigating', label: 'Start Investigation', icon: Eye, color: 'bg-[var(--med)] hover:brightness-110' },
          { status: 'false_positive', label: 'Mark False Positive', icon: XCircle, color: 'bg-[var(--muted)] hover:brightness-110' },
        ];
      case 'investigating':
        return [
          { status: 'resolved', label: 'Mark Resolved', icon: Check, color: 'bg-[var(--low)] hover:brightness-110' },
          { status: 'false_positive', label: 'Mark False Positive', icon: XCircle, color: 'bg-[var(--muted)] hover:brightness-110' },
        ];
      default:
        return [
          { status: 'open', label: 'Reopen Alert', icon: AlertTriangle, color: 'bg-[var(--crit)] hover:brightness-110' },
        ];
    }
  };

  const rawPolicyDecision = alert.detectionMetadata?.policy_decision || alert.detectionMetadata?.policyDecision;
  const policyDecision = rawPolicyDecision
    ? {
        action: rawPolicyDecision.action,
        reason: rawPolicyDecision.reason,
        policy_name: 'policy_name' in rawPolicyDecision ? rawPolicyDecision.policy_name : rawPolicyDecision.policyName,
        mode: rawPolicyDecision.mode,
        alert_threshold: 'alert_threshold' in rawPolicyDecision ? rawPolicyDecision.alert_threshold : rawPolicyDecision.alertThreshold,
        block_threshold: 'block_threshold' in rawPolicyDecision ? rawPolicyDecision.block_threshold : rawPolicyDecision.blockThreshold,
      }
    : null;
  const policyActionLabel = humanizeValue(policyDecision?.action);
  const alertIocs = extractIOCs();
  const displayProcessChain = buildFallbackProcessChain(alert, relatedEvents, timeline);
  const primaryProcess = alert.evidence?.process || displayProcessChain.find(p => p.is_malicious) || displayProcessChain[displayProcessChain.length - 1];
  const primaryProcessLevel = primaryProcess && 'level' in primaryProcess ? primaryProcess.level : 99;
  const parentProcess = displayProcessChain.find(p => primaryProcess?.pid && p.pid !== primaryProcess.pid && p.level < primaryProcessLevel);
  const primaryNetwork = alert.evidence?.network?.[0] || relatedEvents.find(e => e.event_type?.includes('network'))?.payload;
  const primaryFile = alert.evidence?.file_hashes?.[0] || (alert.evidence?.process?.path ? { path: alert.evidence.process.path, sha256: alert.evidence.process.sha256 } : null);
  const ruleName = alert.evidence?.detection?.rule_name || alert.detectionMetadata?.rule_name || 'Detection rule';
  const detectionType = inferDetectionType(alert.evidence?.detection?.rule_type || alert.detectionMetadata?.rule_type, ruleName);
  const alertMitreTechniques = asStringArray(alert.mitreTechniques);
  const detectionTechniques = asStringArray(alert.evidence?.detection?.mitre_techniques).length
    ? asStringArray(alert.evidence?.detection?.mitre_techniques)
    : alertMitreTechniques;
  const attestationState = proofData?.attested ? 'Anchored on Solana' : proofError ? 'Proof lookup failed' : 'Waiting for attestation';
  const completedResponses = responseActions.filter(a => a.status === 'success').length;
  const failedResponses = responseActions.filter(a => ['failed', 'timeout'].includes(a.status)).length;
  const pendingResponses = responseActions.filter(a => ['pending', 'executing'].includes(a.status)).length;
  const storySteps: StoryStep[] = [
    {
      id: 'process',
      label: 'Process',
      title: primaryProcess?.name || 'Process context unavailable',
      detail: primaryProcess?.pid ? `PID ${primaryProcess.pid}${parentProcess?.name ? ` spawned from ${parentProcess.name}` : ''}` : 'No PID was attached to this alert',
      icon: Cpu,
      tone: alert.severity === 'critical' ? 'critical' : 'accent',
      tab: 'process-chain'
    },
    {
      id: 'evidence',
      label: 'Evidence',
      title: ruleName,
      detail: alertMitreTechniques.length ? `${alertMitreTechniques.slice(0, 3).join(', ')} mapped to this alert` : 'Detection metadata and evidence bundle',
      icon: Crosshair,
      tone: 'high',
      tab: 'evidence'
    },
    {
      id: 'ioc',
      label: 'IOCs',
      title: `${alertIocs.length} indicator${alertIocs.length === 1 ? '' : 's'} extracted`,
      detail: alertIocs.length ? alertIocs.slice(0, 3).map(i => i.type).join(' / ') : 'No public-safe indicators extracted yet',
      icon: Hash,
      tone: 'medium',
      tab: 'events'
    },
    {
      id: 'response',
      label: 'Response',
      title: responseActions.length ? `${responseActions.length} action${responseActions.length === 1 ? '' : 's'} recorded` : 'No response action yet',
      detail: responseActions.length ? `${completedResponses} succeeded, ${pendingResponses} pending, ${failedResponses} failed` : 'Use Respond to contain the endpoint, process, file, IP or domain',
      icon: Terminal,
      tone: completedResponses > 0 ? 'low' : failedResponses > 0 ? 'critical' : 'muted',
      tab: 'timeline'
    },
    {
      id: 'proof',
      label: 'Proof',
      title: attestationState,
      detail: proofData?.attested ? `${proofData.ioc_count ?? alertIocs.length} public-safe IOCs, TLP:${(proofData.tlp || 'clear').toUpperCase()}` : 'Sensitive endpoint context stays private',
      icon: ShieldCheck,
      tone: proofData?.attested ? 'low' : proofError ? 'critical' : 'muted',
      tab: 'timeline'
    }
  ];

  const getEventCorrelationDetails = (event: RelatedEvent | TimelineEntry, index = 0) => {
    const payload = (event.payload || {}) as Record<string, any>;
    const score = 'correlation_score' in event ? normalizeCorrelationScore(event.correlation_score) : 0;
    const kind = 'correlation_kind' in event ? event.correlation_kind : undefined;
    const processName = 'process_name' in event ? event.process_name : payload.process_name || payload.name;
    const pid = event.pid || payload.pid;
    const signals: Array<{ label: string; value: string }> = [];

    if ('score_explanation' in event && event.score_explanation) {
      signals.push({ label: 'score basis', value: event.score_explanation });
    }

    if ('correlation_reason' in event && event.correlation_reason) {
      signals.push({
        label: kind === 'fallback' ? 'fallback' : score > 0 ? 'engine reason' : 'context only',
        value: event.correlation_reason,
      });
    }

    if (agent?.hostname) {
      signals.push({ label: 'same endpoint', value: agent.hostname });
    }

    if (event.id && event.id === alert.sourceEventId) {
      signals.push({ label: 'source event', value: 'triggered this alert' });
    }

    if (primaryProcess?.pid && pid && Number(pid) === Number(primaryProcess.pid)) {
      signals.push({ label: 'same process', value: `PID ${pid}` });
    } else if (pid) {
      signals.push({ label: 'process context', value: `PID ${pid}` });
    }

    if (primaryProcess?.name && processName && String(processName).toLowerCase() === String(primaryProcess.name).toLowerCase()) {
      signals.push({ label: 'process name', value: String(processName) });
    } else if (processName) {
      signals.push({ label: 'process name', value: String(processName) });
    }

    const remote = payload.remote_ip || payload.dst_ip || payload.resolved_ip || payload.domain || payload.query;
    if (remote) {
      signals.push({ label: 'network pivot', value: String(remote) });
    }

    const filePath = payload.path || payload.file_path || payload.target_path || payload.image_path;
    if (filePath) {
      signals.push({ label: 'file pivot', value: String(filePath).split(/[\\/]/).pop() || String(filePath) });
    }

    if (alert.createdAt && event.timestamp) {
      const diffMs = Math.abs(new Date(event.timestamp).getTime() - new Date(alert.createdAt).getTime());
      if (!Number.isNaN(diffMs)) {
        const diffSeconds = Math.round(diffMs / 1000);
        signals.push({
          label: 'time proximity',
          value: diffSeconds < 90 ? `${diffSeconds}s from alert` : `${Math.round(diffSeconds / 60)}m from alert`
        });
      }
    }

    if (score > 0) {
      signals.push({ label: 'score', value: `${score}/100` });
    }

    if (signals.length === 0) {
      signals.push({ label: 'sequence', value: index === 0 ? 'first observed activity' : 'same incident window' });
    }

    const uniqueSignals = signals.filter((signal, signalIndex, arr) =>
      arr.findIndex(item => item.label === signal.label && item.value === signal.value) === signalIndex
    );
    const strongest =
      kind === 'fallback'
        ? 'context only - fallback telemetry'
        : kind === 'engine' && score >= 80
          ? 'high-confidence correlation'
          : kind === 'engine' && score >= 40
            ? 'medium-confidence correlation'
            : 'context only';
    const summary = uniqueSignals.slice(0, 3).map(signal => `${signal.label}: ${signal.value}`).join(' | ');

    return { strongest, summary, signals: uniqueSignals.slice(0, 6) };
  };

  const getRelatedEventScoreVersion = (event: RelatedEvent) => {
    return event.score_version || event.correlation_version || 'unversioned';
  };

  const getRelatedEventGapLabel = (event: RelatedEvent) => {
    const gaps = event.telemetry_gaps || [];
    if (gaps.length > 0) return `${gaps.length} telemetry gap${gaps.length === 1 ? '' : 's'}`;
    return 'no gaps returned';
  };

  const strongestCorrelationScore = relatedEvents.reduce((max, event) => Math.max(max, normalizeCorrelationScore(event.correlation_score)), 0);
  const correlationOverview = [
    agent?.hostname ? `same endpoint ${agent.hostname}` : null,
    primaryProcess?.name ? `primary process ${primaryProcess.name}${primaryProcess.pid ? ` PID ${primaryProcess.pid}` : ''}` : null,
    relatedEvents.length ? `${relatedEvents.length} related events` : null,
    strongestCorrelationScore ? `top score ${strongestCorrelationScore}/100` : null,
    alert.sourceEventId ? 'source event anchored' : null
  ].filter(Boolean).join(' | ') || 'Correlation is based on the alert source event, endpoint context and nearby telemetry.';
  const evidenceCount = [
    alert.evidence?.detection,
    alert.evidence?.process,
    ...(alert.evidence?.network || []),
    ...(alert.evidence?.file_hashes || []),
    ...(alert.evidence?.registry || []),
  ].filter(Boolean).length;
  const graphNodeCount = graphData?.nodes.length || 0;
  const graphEdgeCount = graphData?.edges.length || 0;
  const tabInsights: Array<{
    id: AlertTab;
    label: string;
    icon: typeof Activity;
    count?: number;
    description: string;
    metric: string;
    state: 'ready' | 'partial' | 'empty';
  }> = [
    {
      id: 'graph',
      label: 'Correlation Graph',
      icon: Share2,
      count: graphNodeCount,
      description: 'Entity graph across process, network, file and DNS pivots',
      metric: graphNodeCount > 0 ? `${graphNodeCount} nodes / ${graphEdgeCount} edges` : 'No graph built',
      state: graphNodeCount > 0 ? 'ready' : relatedEvents.length > 0 ? 'partial' : 'empty',
    },
    {
      id: 'evidence',
      label: 'Evidence',
      icon: FileText,
      count: evidenceCount,
      description: 'Raw detection context, command lines, hashes and policy metadata',
      metric: evidenceCount > 0 ? `${evidenceCount} evidence fields` : 'Evidence bundle empty',
      state: evidenceCount > 0 ? 'ready' : 'empty',
    },
    {
      id: 'process-chain',
      label: 'Process Chain',
      icon: Terminal,
      count: displayProcessChain.length,
      description: 'Parent/child process ancestry and suspicious execution markers',
      metric: displayProcessChain.length > 0 ? `${displayProcessChain.length} processes` : 'No process chain',
      state: displayProcessChain.length > 1 ? 'ready' : displayProcessChain.length === 1 ? 'partial' : 'empty',
    },
    {
      id: 'timeline',
      label: 'Timeline',
      icon: Clock,
      count: timeline.length,
      description: 'Chronological attack narrative around the source alert',
      metric: timeline.length > 0 ? `${timeline.length} timeline events` : 'No timeline events',
      state: timeline.length > 0 ? 'ready' : relatedEvents.length > 0 ? 'partial' : 'empty',
    },
    {
      id: 'events',
      label: 'Related Events',
      icon: Activity,
      count: relatedEvents.length,
      description: 'Nearby telemetry scored by endpoint, process and time proximity',
      metric: relatedEvents.length > 0 ? `${relatedEvents.length} events / top ${strongestCorrelationScore || 0}` : 'No related events',
      state: relatedEvents.length > 0 ? 'ready' : 'empty',
    },
    {
      id: 'related',
      label: 'Related Alerts',
      icon: AlertTriangle,
      count: relatedAlerts.length,
      description: 'Other detections sharing endpoint, technique or time window',
      metric: relatedAlerts.length > 0 ? `${relatedAlerts.length} related alerts` : 'No related alerts',
      state: relatedAlerts.length > 0 ? 'ready' : 'empty',
    },
  ];

  return (
    <>
      <Head title={`Alert: ${alert.title}`} />

      <div className="min-h-screen" style={{ backgroundColor: 'var(--bg)', color: 'var(--fg)' }}>
        {/* Enhanced Header */}
        <div className="border-b" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => router.visit('/app/alerts')}
                  className="p-2 rounded transition-colors hover:brightness-110"
                  style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 80%, var(--fg) 20%)' }}
                >
                  <ArrowLeft size={20} style={{ color: 'var(--muted)' }} />
                </button>

                {/* Large Severity Badge */}
                <div
                  className={cn('flex items-center justify-center w-14 h-14 rounded-xl', getSeverityColor(alert.severity))}
                  style={getSeverityBgStyle(alert.severity)}
                >
                  <AlertTriangle className={cn('h-8 w-8', getSeverityColor(alert.severity))} />
                </div>

                <div className="flex-1">
                  {/* Title Row */}
                  <div className="flex items-center gap-3 flex-wrap">
                    <h1 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>{alert.title}</h1>
                    <span
                      className={cn('badge-sentinel text-sm px-3 py-1 rounded-full font-semibold', getSeverityColor(alert.severity))}
                      style={getSeverityBgStyle(alert.severity)}
                    >
                      {alert.severity.toUpperCase()}
                    </span>
                    <StatusBadge status={alert.status} />
                    {proofData?.attested && (
                      <span
                        className="badge-sentinel badge-sentinel-sol-cyan text-xs px-2 py-0.5 rounded-full flex items-center gap-1"
                      >
                        <ShieldCheck size={12} />
                        On-Chain
                      </span>
                    )}
                  </div>
                  {/* Metadata Row */}
                  <div className="flex items-center gap-4 text-sm mt-1.5" style={{ color: 'var(--muted)' }}>
                    {agent && (
                      <span className="flex items-center gap-1">
                        <Server size={14} />
                        {agent.hostname}
                      </span>
                    )}
                    <span className="flex items-center gap-1">
                      <Clock size={14} />
                      {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '---'}
                    </span>
                    {alert.id && (
                      <span className="font-mono text-xs" style={{ color: 'var(--subtle)' }}>
                        ID: {alert.id.slice(0, 8)}...
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {/* Threat Score */}
                <div className="text-center mr-4">
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Threat Score /100</div>
                  <div className={cn('text-3xl font-bold', getThreatScoreColor(alert.threatScore))}>
                    {displayThreatScore(alert.threatScore)}
                  </div>
                </div>

                {/* Status Actions */}
                <div className="flex items-center gap-2">
                  {getStatusActions().map(action => {
                    const Icon = action.icon;
                    return (
                      <button
                        key={action.status}
                        onClick={() => handleStatusChange(action.status as Alert['status'])}
                        disabled={isUpdating}
                        className={cn(
                          'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-white transition-colors',
                          action.color,
                          isUpdating && 'opacity-50 cursor-not-allowed'
                        )}
                      >
                        <Icon size={16} />
                        {action.label}
                      </button>
                    );
                  })}
                </div>

                {/* Response Actions */}
                {agent && (
                  <Menu
                    align="end"
                    className="w-56"
                    trigger={
                      <button
                        type="button"
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
                        style={{
                          backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)',
                          borderColor: 'color-mix(in srgb, var(--crit) 30%, transparent)',
                          color: 'var(--crit)',
                          border: '1px solid'
                        }}
                      >
                        <Terminal size={16} />
                        Respond
                        <ChevronDown size={14} />
                      </button>
                    }
                  >
                    <MenuItem onSelect={() => handleResponseAction('isolate')} disabled={isUpdating} tone="danger">
                      <>
                        <Globe size={14} />
                        Isolate Endpoint
                      </>
                    </MenuItem>
                    {alert.evidence?.process?.pid && (
                      <MenuItem onSelect={() => handleResponseAction('kill')} disabled={isUpdating} tone="warning">
                        <>
                          <XCircle size={14} />
                          Kill Process (PID {alert.evidence.process.pid})
                        </>
                      </MenuItem>
                    )}
                    {alert.evidence?.file?.path && (
                      <MenuItem onSelect={() => handleResponseAction('quarantine')} disabled={isUpdating} tone="warning">
                        <>
                          <File size={14} />
                          Quarantine File
                        </>
                      </MenuItem>
                    )}
                    <MenuItem onSelect={() => handleResponseAction('scan')} disabled={isUpdating}>
                      <>
                        <Search size={14} />
                        Full Scan
                      </>
                    </MenuItem>
                  </Menu>
                )}

                <button
                  onClick={() => router.reload()}
                  className="p-2 rounded transition-colors hover:brightness-110"
                  style={{ backgroundColor: 'var(--surface-alt, var(--surface))' }}
                >
                  <RefreshCw size={18} style={{ color: 'var(--muted)' }} />
                </button>
              </div>
            </div>
          </div>
        </div>

        {agent && (
          <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 35%, var(--bg))', borderColor: 'var(--border)' }}>
            <div className="max-w-full mx-auto px-4 py-2">
              <div className="flex items-center gap-3 text-xs flex-wrap" style={{ color: 'var(--muted)' }}>
                <span
                  className="px-2 py-0.5 rounded-full font-medium"
                  style={{
                    backgroundColor: agent.status === 'online' ? 'color-mix(in srgb, var(--low) 16%, transparent)' : 'var(--surface-2)',
                    color: agent.status === 'online' ? 'var(--low)' : 'var(--muted)'
                  }}
                >
                  Agent {agent.status}
                </span>
                <span>Version {agent.agent_version || 'unknown'}</span>
                <span>OS {agent.os_type} {agent.os_version}</span>
                <span>Last seen {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'unknown'}</span>
                {(agent as Agent & { certificate_fingerprint?: string }).certificate_fingerprint && (
                  <span className="font-mono">
                    mTLS {(agent as Agent & { certificate_fingerprint?: string }).certificate_fingerprint?.slice(0, 12)}...
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {actionNotice && (
          <div
            className="border-b px-4 py-2 text-sm flex items-center justify-between"
            style={{
              backgroundColor:
                actionNotice.type === 'error'
                  ? 'color-mix(in srgb, var(--crit) 14%, var(--bg))'
                  : actionNotice.type === 'success'
                    ? 'color-mix(in srgb, var(--low) 14%, var(--bg))'
                    : 'color-mix(in srgb, var(--accent) 14%, var(--bg))',
              borderColor: 'var(--border)',
              color:
                actionNotice.type === 'error'
                  ? 'var(--crit)'
                  : actionNotice.type === 'success'
                    ? 'var(--low)'
                    : 'var(--accent)'
            }}
          >
            <span>{actionNotice.message}</span>
            <button
              onClick={() => setActionNotice(null)}
              className="p-1 rounded hover:brightness-110"
              aria-label="Dismiss action notice"
            >
              <X size={14} />
            </button>
          </div>
        )}

        {/* Alert Info Bar */}
        <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, var(--bg))', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                {/* MITRE Techniques */}
                {alertMitreTechniques.length > 0 && (
                  <div className="flex items-center gap-2">
                    <Shield size={16} style={{ color: 'var(--muted)' }} />
                    <div className="flex flex-wrap gap-1">
                      {alertMitreTechniques.map(technique => (
                        <a
                          key={technique}
                          href={mitreTechniqueHref(technique)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="badge-sentinel px-2 py-0.5 rounded text-xs font-medium transition-colors hover:brightness-110"
                          style={{
                            backgroundColor: 'color-mix(in srgb, var(--accent-secondary, #a855f7) 20%, transparent)',
                            color: 'var(--accent-secondary, #a855f7)'
                          }}
                        >
                          {technique}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Description */}
                <div className="max-w-2xl min-w-0">
                  <LongTextPreview
                    value={alert.description}
                    maxChars={260}
                    maxLines={4}
                    onCopy={(text) => copyToClipboard(text, 'alert_description')}
                    copied={copiedField === 'alert_description'}
                    mono={/encodedcommand|-[Ee]nc\b|[A-Za-z0-9+/=]{120,}/.test(alert.description || '')}
                  />
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => router.visit(`/app/storyline/${alert.id}`)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors hover:brightness-110"
                  style={{
                    backgroundColor: 'color-mix(in srgb, var(--accent-secondary, #a855f7) 20%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--accent-secondary, #a855f7) 30%, transparent)',
                    color: 'var(--accent-secondary, #a855f7)'
                  }}
                >
                  <Crosshair size={14} />
                  View Storyline
                </button>
                <button
                  onClick={() => router.visit(`/app/investigation/${alert.id}?type=alert`)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors hover:brightness-110"
                  style={{
                    backgroundColor: 'color-mix(in srgb, var(--accent) 20%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)',
                    color: 'var(--accent)'
                  }}
                >
                  <GitBranch size={14} />
                  Full Investigation
                </button>
                <button
                  onClick={() => router.visit(`/app/hunt?q=${encodeURIComponent(`alert.id:${alert.id}`)}`)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors hover:brightness-110"
                  style={{
                    backgroundColor: 'color-mix(in srgb, var(--high) 20%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--high) 30%, transparent)',
                    color: 'var(--high)'
                  }}
                >
                  <Search size={14} />
                  Hunt Related
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Workflow Timeline - Horizontal */}
        <div className="border-b" style={{ backgroundColor: 'var(--bg-2)', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-4">
            <WorkflowTimeline steps={getWorkflowSteps()} />
          </div>
        </div>

        <IncidentStorylinePanel
          alert={alert}
          agent={agent}
          storySteps={storySteps}
          primaryProcess={primaryProcess}
          primaryNetwork={primaryNetwork}
          primaryFile={primaryFile}
          iocs={alertIocs}
          responseActions={responseActions}
          proofData={proofData}
          graphStats={graphData?.stats}
          eventFlowStats={eventFlowStats}
          relatedEventsCount={relatedEvents.length}
          correlationOverview={correlationOverview}
          onOpenTab={setActiveTab}
          onCopy={copyToClipboard}
          copiedField={copiedField}
        />

        {/* Policy Decision Trace */}
        <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 45%, var(--bg))', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-4">
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Policy</p>
                <p className="mt-1 text-sm font-semibold truncate" style={{ color: 'var(--fg)' }}>
                  {policyDecision?.policy_name || 'Not recorded'}
                </p>
              </div>
              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Mode</p>
                <p className="mt-1 text-sm font-semibold" style={{ color: policyDecision?.mode === 'detect_and_prevent' ? 'var(--emerald-400)' : 'var(--med)' }}>
                  {policyDecision?.mode === 'detect_and_prevent' ? 'Detect & Prevent' : policyDecision?.mode === 'detect_only' ? 'Detect Only' : 'Unknown'}
                </p>
              </div>
              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Decision</p>
                <p className="mt-1 text-sm font-semibold capitalize" style={{ color: policyDecision?.action === 'alert_and_block' ? 'var(--crit)' : 'var(--fg)' }}>
                  {policyActionLabel}
                </p>
              </div>
              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Thresholds</p>
                <p className="mt-1 text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                  A {policyDecision?.alert_threshold ?? '-'} / B {policyDecision?.block_threshold ?? '-'}
                </p>
              </div>
              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Reason</p>
                {policyDecision?.reason ? (
                  <Tooltip content={policyDecision.reason}>
                    <p className="mt-1 text-sm truncate" style={{ color: 'var(--fg)' }}>
                      {policyDecision.reason}
                    </p>
                  </Tooltip>
                ) : (
                  <p className="mt-1 text-sm truncate" style={{ color: 'var(--fg)' }}>
                    Decision trace not available for this alert
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 38%, var(--bg))', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-3">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-2" role="tablist" aria-label="Alert investigation sections">
              {tabInsights.map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                const stateColor =
                  tab.state === 'ready' ? 'var(--low)' :
                  tab.state === 'partial' ? 'var(--high)' :
                  'var(--muted)';
                return (
                  <button
                    key={tab.id}
                    id={`alert-tab-${tab.id}`}
                    role="tab"
                    type="button"
                    aria-selected={isActive}
                    aria-controls={`alert-panel-${tab.id}`}
                    tabIndex={isActive ? 0 : -1}
                    onClick={() => selectTab(tab.id)}
                    onKeyDown={(event) => {
                      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
                      event.preventDefault();
                      const currentIndex = ALERT_TABS.indexOf(tab.id);
                      const direction = event.key === 'ArrowRight' ? 1 : -1;
                      const nextTab = ALERT_TABS[(currentIndex + direction + ALERT_TABS.length) % ALERT_TABS.length];
                      selectTab(nextTab);
                      window.requestAnimationFrame(() => document.getElementById(`alert-tab-${nextTab}`)?.focus());
                    }}
                    className={cn(
                      'group min-h-[92px] rounded-lg border p-3 text-left transition-all',
                      isActive && 'ring-2 ring-[var(--accent)]'
                    )}
                    style={{
                      backgroundColor: isActive ? 'color-mix(in srgb, var(--accent) 10%, var(--surface))' : 'var(--surface)',
                      borderColor: isActive ? 'color-mix(in srgb, var(--accent) 45%, var(--border))' : 'var(--border)',
                      color: isActive ? 'var(--fg)' : 'var(--fg-2)'
                    }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md"
                          style={{
                            backgroundColor: isActive ? 'color-mix(in srgb, var(--accent) 18%, transparent)' : 'var(--surface-2)',
                            color: isActive ? 'var(--accent)' : 'var(--muted)'
                          }}
                        >
                          <Icon size={16} />
                        </span>
                        <span className="truncate text-sm font-semibold">{tab.label}</span>
                      </div>
                      <span
                        className="shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold"
                        style={{
                          backgroundColor: 'color-mix(in srgb, var(--surface-3) 75%, transparent)',
                          color: tab.count && tab.count > 0 ? 'var(--fg)' : 'var(--muted)'
                        }}
                      >
                        {tab.count ?? 0}
                      </span>
                    </div>
                    <p className="mt-2 line-clamp-2 text-xs leading-snug" style={{ color: 'var(--muted)' }}>
                      {tab.description}
                    </p>
                    <div className="mt-3 flex items-center gap-2 text-xs">
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: stateColor }} />
                      <span className="truncate" style={{ color: stateColor }}>{tab.metric}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex h-[calc(100vh-280px)]">
          {/* Graph / Content Area */}
          <div className="flex-1 relative overflow-hidden">
            {activeTab === 'graph' && (
              <>
                {graphData && graphData.nodes.length > 0 ? (
                  <InvestigationGraph
                    nodes={graphData.nodes}
                    edges={graphData.edges}
                    selectedNodeId={selectedNode?.id}
                    onNodeClick={handleNodeClick}
                    onNodeDoubleClick={handleNodeDoubleClick}
                    className="w-full h-full"
                  />
                ) : (
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="text-center">
                      <Share2 size={48} className="mx-auto mb-4" style={{ color: 'var(--muted)' }} />
                      <p style={{ color: 'var(--muted)' }}>No correlation data available</p>
                      <p className="text-sm mt-1" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                        Related events will appear here as a graph
                      </p>
                    </div>
                  </div>
                )}

                {/* Stats Overlay */}
                {graphData?.stats && (
                  <div
                    className="card-sentinel absolute top-4 right-4 rounded-lg p-3 text-xs"
                    style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 90%, transparent)' }}
                  >
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                      <span style={{ color: 'var(--muted)' }}>Processes:</span>
                      <span className="font-medium" style={{ color: 'var(--accent)' }}>{graphData.stats.process_count}</span>
                      <span style={{ color: 'var(--muted)' }}>Network:</span>
                      <span className="font-medium" style={{ color: 'var(--low)' }}>{graphData.stats.network_count}</span>
                      <span style={{ color: 'var(--muted)' }}>Files:</span>
                      <span className="font-medium" style={{ color: 'var(--med)' }}>{graphData.stats.file_count}</span>
                      <span style={{ color: 'var(--muted)' }}>DNS:</span>
                      <span className="font-medium" style={{ color: 'var(--accent-secondary, #a855f7)' }}>{graphData.stats.dns_count}</span>
                    </div>
                  </div>
                )}
              </>
            )}

            {activeTab === 'timeline' && (
              <div className="p-4 overflow-y-auto h-full">
                {timeline.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full" style={{ color: 'var(--muted)' }}>
                    <Clock size={48} className="mb-4 opacity-50" />
                    <p>No timeline events</p>
                  </div>
                ) : (
                  <div className="relative">
                    {/* Timeline line */}
                    <div className="absolute left-6 top-0 bottom-0 w-px" style={{ backgroundColor: 'var(--border)' }} />

                    <div className="space-y-4">
                      {timeline.map((entry, idx) => {
                        const Icon = NODE_ICONS[entry.event_type as GraphNodeType] || Activity;
                        const dotColor = entry.severity === 'critical' ? 'var(--crit)' :
                          entry.severity === 'high' ? 'var(--high)' :
                          entry.severity === 'medium' ? 'var(--med)' : 'var(--accent)';
                        const correlation = getEventCorrelationDetails(entry, idx);
                        return (
                          <div key={entry.id || idx} className="relative flex gap-4 pl-4">
                            {/* Timeline dot */}
                            <div
                              className="absolute left-4 w-5 h-5 rounded-full flex items-center justify-center -translate-x-1/2 z-10"
                              style={{ backgroundColor: dotColor }}
                            >
                              <Icon size={12} className="text-white" />
                            </div>

                            {/* Content */}
                            <div
                              className="card-sentinel flex-1 ml-8 rounded-lg p-4 transition-colors hover:brightness-105"
                              style={{ backgroundColor: 'var(--surface)' }}
                            >
                              <div className="flex items-start justify-between mb-2">
                                <div>
                                  <div className="font-medium" style={{ color: 'var(--fg)' }}>{entry.summary}</div>
                                  <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                                    {entry.event_type} • {entry.timestamp}
                                    {entry.pid && ` • PID: ${entry.pid}`}
                                  </div>
                                </div>
                                {entry.detections && entry.detections.length > 0 && (
                                  <AlertTriangle size={16} style={{ color: 'var(--crit)' }} />
                                )}
                              </div>
                              <div
                                className="mb-2 rounded-lg px-3 py-2 text-xs"
                                style={{
                                  backgroundColor: 'color-mix(in srgb, var(--accent) 8%, transparent)',
                                  border: '1px solid color-mix(in srgb, var(--accent) 20%, transparent)',
                                  color: 'var(--fg-2)'
                                }}
                              >
                                <div className="flex items-center gap-2 mb-1" style={{ color: 'var(--accent)' }}>
                                  <Crosshair size={12} />
                                  <span className="font-semibold">{correlation.strongest}</span>
                                </div>
                                <div style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>{correlation.summary}</div>
                              </div>
                              {entry.detections && entry.detections.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  {entry.detections.map((det, i) => (
                                    <div
                                      key={i}
                                      className="text-xs rounded p-2"
                                      style={{
                                        backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                                        color: 'var(--crit)'
                                      }}
                                    >
                                      <span style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                                        {det.ruleName}: {det.description}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'evidence' && (
              <div className="p-4 overflow-y-auto h-full">
                <EvidencePanel evidence={alert.evidence || {}} />
              </div>
            )}

            {activeTab === 'process-chain' && (
              <div className="p-4 overflow-y-auto h-full">
                <ProcessChainView chain={displayProcessChain} />
              </div>
            )}

            {activeTab === 'events' && (
              <div className="p-4 overflow-y-auto h-full">
                {/* Header with refresh button */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Related Events</h3>
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>
                      ({relatedEvents.length} events correlated)
                    </span>
                  </div>
                  <button
                    onClick={fetchRelatedEvents}
                    disabled={isLoadingRelatedEvents}
                    className={cn(
                      'flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg transition-colors',
                      isLoadingRelatedEvents && 'opacity-50 cursor-not-allowed'
                    )}
                    style={{
                      backgroundColor: 'var(--surface-alt, var(--surface))',
                      color: isLoadingRelatedEvents ? 'var(--muted)' : 'var(--fg)'
                    }}
                  >
                    <RefreshCw size={14} className={isLoadingRelatedEvents ? 'animate-spin' : ''} />
                    {isLoadingRelatedEvents ? 'Loading...' : 'Refresh'}
                  </button>
                </div>

                {/* Error message */}
                {relatedEventsError && (
                  <div
                    className="mb-4 p-3 rounded-lg text-sm"
                    style={{
                      backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--crit) 30%, transparent)',
                      color: 'var(--crit)'
                    }}
                  >
                    {relatedEventsError}
                  </div>
                )}

                {/* Loading state */}
                {isLoadingRelatedEvents && relatedEvents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-64" style={{ color: 'var(--muted)' }}>
                    <RefreshCw size={32} className="animate-spin mb-4" />
                    <p>Loading related events...</p>
                  </div>
                ) : relatedEvents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full" style={{ color: 'var(--muted)' }}>
                    <Activity size={48} className="mb-4 opacity-50" />
                    <p>No related events found</p>
                    {alert.sourceEventId && agent?.id && (
                      <p className="text-sm mt-2">Try refreshing or expanding the time window</p>
                    )}
                  </div>
                ) : (
                  <div className="space-y-3">
                    {/* Flow Summary Cards */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 pb-3 border-b" style={{ borderColor: 'var(--border)' }}>
                      <div className="card-sentinel rounded-lg p-3" style={{ backgroundColor: 'var(--surface)' }}>
                        <div className="flex items-center gap-2 mb-1">
                          <Wifi size={14} style={{ color: 'var(--low)' }} />
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>Network</span>
                        </div>
                        <div className="text-xl font-bold" style={{ color: 'var(--low)' }}>{eventFlowStats.networkCount}</div>
                        <div className="text-[10px]" style={{ color: 'var(--muted)' }}>{eventFlowStats.uniqueIPs} unique IPs</div>
                      </div>
                      <div className="card-sentinel rounded-lg p-3" style={{ backgroundColor: 'var(--surface)' }}>
                        <div className="flex items-center gap-2 mb-1">
                          <ArrowRight size={14} style={{ color: 'var(--high)' }} />
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>Data Sent</span>
                        </div>
                        <div className="text-xl font-bold" style={{ color: 'var(--high)' }}>{formatBytes(eventFlowStats.totalBytesSent)}</div>
                        <div className="text-[10px]" style={{ color: 'var(--muted)' }}>{formatBytes(eventFlowStats.totalBytesRecv)} received</div>
                      </div>
                      <div className="card-sentinel rounded-lg p-3" style={{ backgroundColor: 'var(--surface)' }}>
                        <div className="flex items-center gap-2 mb-1">
                          <Cpu size={14} style={{ color: 'var(--accent)' }} />
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>Processes</span>
                        </div>
                        <div className="text-xl font-bold" style={{ color: 'var(--accent)' }}>{eventFlowStats.processCount}</div>
                        <div className="text-[10px]" style={{ color: 'var(--muted)' }}>{eventFlowStats.fileCount} file ops</div>
                      </div>
                      <div className="card-sentinel rounded-lg p-3" style={{ backgroundColor: 'var(--surface)' }}>
                        <div className="flex items-center gap-2 mb-1">
                          <Server size={14} style={{ color: 'var(--accent-secondary, #a855f7)' }} />
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>DNS</span>
                        </div>
                        <div className="text-xl font-bold" style={{ color: 'var(--accent-secondary, #a855f7)' }}>{eventFlowStats.dnsCount}</div>
                        <div className="text-[10px]" style={{ color: 'var(--muted)' }}>{eventFlowStats.uniqueDomains} domains</div>
                      </div>
                    </div>

                    <div
                      className="rounded-lg p-3 text-sm"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--accent) 7%, var(--surface))',
                        border: '1px solid color-mix(in srgb, var(--accent) 22%, var(--border))'
                      }}
                    >
                      <div className="flex items-center gap-2 mb-1" style={{ color: 'var(--accent)' }}>
                        <GitBranch size={14} />
                        <span className="font-semibold">Correlation basis</span>
                      </div>
                      <p className="text-xs leading-relaxed" style={{ color: 'var(--fg-2)' }}>
                        {correlationOverview}
                      </p>
                    </div>

                    {/* Correlation Legend */}
                    <div className="flex items-center gap-4 text-xs pb-2 border-b" style={{ color: 'var(--muted)', borderColor: 'var(--border)' }}>
                      <span className="font-medium">Correlation Score:</span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--low)' }}></span> High (80+)
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--med)' }}></span> Medium (40-79)
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--muted)' }}></span> Low (&lt;40)
                      </span>
                    </div>

                    {/* Related Events Timeline */}
                    <div className="relative">
                      {/* Timeline line */}
                      <div className="absolute left-6 top-0 bottom-0 w-px" style={{ backgroundColor: 'var(--border)' }} />

                      <div className="space-y-3">
                        {relatedEvents.map((event, index) => {
                          const Icon = NODE_ICONS[event.event_type as GraphNodeType] || Activity;
                          const score = normalizeCorrelationScore(event.correlation_score);
                          const scoreColor = score >= 80 ? 'var(--low)' : score >= 40 ? 'var(--med)' : 'var(--muted)';
                          const isNetwork = event.event_type?.includes('network');
                          const payload = event.payload || {};
                          const correlation = getEventCorrelationDetails(event, index);

                          return (
                            <div
                              key={event.id}
                              className="relative flex gap-4 pl-4"
                            >
                              {/* Timeline dot with correlation score indicator */}
                              <div
                                className="absolute left-4 w-5 h-5 rounded-full flex items-center justify-center -translate-x-1/2 z-10"
                                style={{ backgroundColor: scoreColor, border: '2px solid var(--surface)' }}
                              >
                                <Icon size={10} className="text-white" />
                              </div>

                              {/* Event Card */}
                              <div
                                className="card-sentinel flex-1 ml-8 rounded-lg p-4 transition-colors hover:brightness-105"
                                style={{ backgroundColor: 'var(--surface)' }}
                              >
                                <div className="flex items-start gap-3">
                                  <div className="flex-1 min-w-0">
                                    {/* Header with summary and severity */}
                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{event.summary}</span>
                                      <span className={cn('badge-sentinel', getSeverityColor(event.severity))}>
                                        {event.severity}
                                      </span>
                                      {score > 0 && (
                                        <span
                                          className="badge-sentinel px-2 py-0.5 rounded text-xs font-medium"
                                          style={{
                                            backgroundColor: `color-mix(in srgb, ${scoreColor} 20%, transparent)`,
                                            color: scoreColor
                                          }}
                                        >
                                          Score: {score}
                                        </span>
                                      )}
                                      <span
                                        className="badge-sentinel px-2 py-0.5 rounded text-xs"
                                        style={{ backgroundColor: 'var(--surface-alt, var(--surface))', color: 'var(--muted)' }}
                                      >
                                        score {getRelatedEventScoreVersion(event)}
                                      </span>
                                      <span
                                        className="badge-sentinel px-2 py-0.5 rounded text-xs"
                                        style={{
                                          backgroundColor: (event.telemetry_gaps || []).length > 0
                                            ? 'color-mix(in srgb, var(--med) 14%, transparent)'
                                            : 'var(--surface-alt, var(--surface))',
                                          color: (event.telemetry_gaps || []).length > 0 ? 'var(--med)' : 'var(--muted)'
                                        }}
                                      >
                                        {getRelatedEventGapLabel(event)}
                                      </span>
                                    </div>

                                    {/* Network Connection Flow - enhanced visualization */}
                                    {isNetwork && (() => {
                                      const remoteIp = payload.remote_ip || payload.dst_ip;
                                      const remotePort = payload.remote_port || payload.dst_port;
                                      const localPort = payload.local_port || payload.src_port;
                                      const protocol = payload.protocol || 'TCP';
                                      const direction = payload.direction || 'outbound';
                                      const bytesSent = Number(payload.bytes_sent || payload.sent_bytes || 0);
                                      const bytesRecv = Number(payload.bytes_received || payload.recv_bytes || 0);
                                      const procName = event.process_name || payload.name || payload.process_name;

                                      return (
                                        <div
                                          className="rounded-lg p-3 my-2 space-y-2"
                                          style={{ backgroundColor: 'color-mix(in srgb, var(--bg) 60%, var(--surface))' }}
                                        >
                                          {/* Connection flow arrow */}
                                          <div className="flex items-center gap-2 text-xs">
                                            <div className="flex items-center gap-1.5">
                                              <Cpu size={12} style={{ color: 'var(--accent)' }} />
                                              <span className="font-medium" style={{ color: 'var(--accent)' }}>{procName || `PID ${event.pid || '?'}`}</span>
                                              {localPort && <span style={{ color: 'var(--muted)' }}>:{String(localPort)}</span>}
                                            </div>
                                            <div className="flex items-center gap-1 px-2">
                                              {direction === 'inbound' ? (
                                                <>
                                                  <span className="text-[10px]" style={{ color: 'var(--high)' }}>INBOUND</span>
                                                  <ArrowLeft size={14} style={{ color: 'var(--high)' }} />
                                                </>
                                              ) : (
                                                <>
                                                  <ArrowRight size={14} style={{ color: 'var(--low)' }} />
                                                  <span className="text-[10px]" style={{ color: 'var(--low)' }}>OUTBOUND</span>
                                                </>
                                              )}
                                            </div>
                                            <div className="flex items-center gap-1.5">
                                              <Globe size={12} style={{ color: 'var(--low)' }} />
                                              <span className="font-mono" style={{ color: 'var(--low)' }}>{remoteIp ? `${remoteIp}:${remotePort || '?'}` : 'unknown'}</span>
                                            </div>
                                            <span
                                              className="px-1.5 py-0.5 rounded text-[10px]"
                                              style={{ backgroundColor: 'var(--surface-alt, var(--surface))', color: 'var(--muted)' }}
                                            >
                                              {String(protocol)}
                                            </span>
                                          </div>
                                          {/* Data volume */}
                                          {(bytesSent > 0 || bytesRecv > 0) && (
                                            <div className="flex items-center gap-4 text-[11px] pt-1 border-t" style={{ borderColor: 'var(--border)' }}>
                                              <span style={{ color: 'var(--muted)' }}>Data:</span>
                                              <span style={{ color: 'var(--high)' }}>{formatBytes(bytesSent)} sent</span>
                                              <span style={{ color: 'var(--low)' }}>{formatBytes(bytesRecv)} received</span>
                                              <span className="font-medium" style={{ color: 'var(--muted)' }}>{formatBytes(bytesSent + bytesRecv)} total</span>
                                            </div>
                                          )}
                                        </div>
                                      );
                                    })()}

                                    <div
                                      className="rounded-lg px-3 py-2 mb-2"
                                      style={{
                                        backgroundColor: 'color-mix(in srgb, var(--accent) 8%, transparent)',
                                        border: '1px solid color-mix(in srgb, var(--accent) 20%, transparent)'
                                      }}
                                    >
                                      <div className="flex items-center gap-2 text-xs font-semibold mb-2" style={{ color: 'var(--accent)' }}>
                                        <Crosshair size={12} />
                                        <span>Why this event is correlated</span>
                                        <span className="font-normal" style={{ color: 'var(--muted)' }}>({correlation.strongest})</span>
                                        {event.evidence_count !== undefined && (
                                          <span className="font-normal" style={{ color: 'var(--muted)' }}>
                                            {event.evidence_count} evidence item{event.evidence_count === 1 ? '' : 's'}
                                          </span>
                                        )}
                                      </div>
                                      <div className="flex flex-wrap gap-1.5">
                                        {correlation.signals.map((signal) => (
                                          <Tooltip key={`${event.id}-${signal.label}-${signal.value}`} content={`${signal.label}: ${signal.value}`}>
                                            <span
                                              className="text-[11px] px-2 py-1 rounded"
                                              style={{ backgroundColor: 'var(--surface-alt, var(--surface))', color: 'var(--fg-2)' }}
                                            >
                                              <span style={{ color: 'var(--muted)' }}>{signal.label}:</span> {signal.value}
                                            </span>
                                          </Tooltip>
                                        ))}
                                      </div>
                                    </div>

                                    {/* Event metadata */}
                                    <div className="text-xs flex items-center gap-3 flex-wrap" style={{ color: 'var(--muted)' }}>
                                      <span
                                        className="font-mono px-1.5 py-0.5 rounded"
                                        style={{ backgroundColor: 'var(--bg)' }}
                                      >
                                        {event.event_type}
                                      </span>
                                      <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}</span>
                                      {event.pid && <span>PID: {event.pid}</span>}
                                      {event.process_name && <span className="truncate max-w-[150px]">{event.process_name}</span>}
                                    </div>

                                    {/* Payload expandable */}
                                    <details className="mt-2">
                                      <summary className="text-xs cursor-pointer hover:brightness-110" style={{ color: 'var(--muted)' }}>
                                        View payload
                                      </summary>
                                      <pre
                                        className="mt-2 text-xs rounded p-2 max-h-64 max-w-full overflow-auto whitespace-pre-wrap"
                                        style={{
                                          backgroundColor: 'var(--bg)',
                                          color: 'var(--fg)',
                                          overflowWrap: 'anywhere',
                                          wordBreak: 'break-word'
                                        }}
                                      >
                                        {JSON.stringify(event.payload, null, 2)}
                                      </pre>
                                    </details>
                                  </div>

                                  {/* Action buttons */}
                                  <div className="flex flex-col items-center gap-1">
                                    {event.pid && agent && (
                                      <Tooltip content="View in Graph">
                                        <button
                                          onClick={() => router.visit(`/app/investigation/${event.pid}?type=process&agent_id=${agent.id}`)}
                                          className="p-2 rounded transition-colors hover:brightness-110"
                                          style={{ color: 'var(--muted)' }}
                                        >
                                          <Share2 size={16} />
                                        </button>
                                      </Tooltip>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'related' && (
              <div className="p-4 overflow-y-auto h-full">
                {relatedAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full" style={{ color: 'var(--muted)' }}>
                    <AlertTriangle size={48} className="mb-4 opacity-50" />
                    <p>No related alerts found</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {relatedAlerts.map(relAlert => (
                      <a
                        key={relAlert.id}
                        href={`/app/alerts/${relAlert.id}`}
                        className="card-sentinel block rounded-lg p-4 transition-colors hover:brightness-105"
                        style={{ backgroundColor: 'var(--surface)' }}
                      >
                        <div className="flex items-start gap-3">
                          <div className={cn('p-2 rounded', getSeverityColor(relAlert.severity))} style={getSeverityBgStyle(relAlert.severity)}>
                            <AlertTriangle className={cn('h-4 w-4', getSeverityColor(relAlert.severity))} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-medium" style={{ color: 'var(--fg)' }}>{relAlert.title}</span>
                              <span className={cn('badge-sentinel', getSeverityColor(relAlert.severity))}>
                                {relAlert.severity}
                              </span>
                              <StatusBadge status={relAlert.status} />
                            </div>
                            <p
                              className="text-sm min-w-0"
                              style={{ color: 'var(--muted)', overflowWrap: 'anywhere', wordBreak: 'break-word' }}
                            >
                              {relAlert.description}
                            </p>
                            <div className="text-xs mt-2" style={{ color: 'var(--muted)' }}>
                              {relAlert.createdAt ? new Date(relAlert.createdAt).toLocaleString() : '—'}
                            </div>
                          </div>
                          <div className={cn('text-xl font-bold', getThreatScoreColor(relAlert.threatScore))}>
                            {displayThreatScore(relAlert.threatScore)}
                          </div>
                        </div>
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Sidebar */}
          {selectedNode && activeTab === 'graph' && (
            <div
              className="w-96 border-l overflow-y-auto"
              style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
            >
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Selected Entity</h3>
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="p-1 rounded hover:brightness-110"
                    style={{ backgroundColor: 'var(--surface-alt, var(--surface))' }}
                  >
                    <X size={16} style={{ color: 'var(--muted)' }} />
                  </button>
                </div>

                <EntityPivot
                  entityType={selectedNode.type}
                  entityId={selectedNode.id}
                  entityLabel={selectedNode.label}
                  entityData={selectedNode.data}
                  onPivot={handlePivot}
                  position="bottom-left"
                />

                <div className="mt-4 space-y-2">
                  {Object.entries(selectedNode.data).slice(0, 8).map(([key, value]) => (
                    <div key={key} className="flex justify-between items-start text-sm">
                      <span style={{ color: 'var(--muted)' }}>{key}:</span>
                      <div className="flex items-center gap-1">
                        <span className="truncate max-w-[180px] font-mono text-xs" style={{ color: 'var(--fg)' }}>
                          {String(value)}
                        </span>
                        <Tooltip content="Copy">
                          <button
                            onClick={() => copyToClipboard(String(value), key)}
                            className="p-1 rounded hover:brightness-110"
                          >
                            <Copy
                              size={12}
                              style={{ color: copiedField === key ? 'var(--low)' : 'var(--muted)' }}
                            />
                          </button>
                        </Tooltip>
                      </div>
                    </div>
                  ))}
                </div>

                {selectedNode.detections && selectedNode.detections.length > 0 && (
                  <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                    <div className="text-sm font-medium mb-2" style={{ color: 'var(--crit)' }}>
                      {selectedNode.detections.length} Detection(s)
                    </div>
                    {selectedNode.detections.map((det, i) => (
                      <div
                        key={i}
                        className="text-xs rounded p-2 mb-1"
                        style={{
                          backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                          color: 'var(--muted)'
                        }}
                      >
                        <span style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                          {det.ruleName}: {det.description}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Right Sidebar - Proof Card & IOCs */}
          <div
            className="w-80 border-l overflow-y-auto flex-shrink-0"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            {/* Proof of Incident Card */}
            <ProofCardSection
              proofData={proofData}
              isLoading={isLoadingProof}
              error={proofError}
              alertId={alert.id}
              mitreTechniques={alert.mitreTechniques}
              onCopyToClipboard={copyToClipboard}
              copiedField={copiedField}
            />

            {/* IOCs Section */}
            <IOCsSection
              iocs={extractIOCs()}
              expanded={iocsExpanded}
              onToggle={() => setIocsExpanded(!iocsExpanded)}
              onCopyToClipboard={copyToClipboard}
              copiedField={copiedField}
              canBlock={Boolean(agent?.id)}
              onBlockIOC={handleBlockIOC}
            />

            <ResponseActionsSection actions={responseActions} />
          </div>
        </div>
      </div>
    </>
  );
}

function IncidentStorylinePanel({
  alert,
  agent,
  storySteps,
  primaryProcess,
  primaryNetwork,
  primaryFile,
  iocs,
  responseActions,
  proofData,
  graphStats,
  eventFlowStats,
  relatedEventsCount,
  correlationOverview,
  onOpenTab,
  onCopy,
  copiedField
}: {
  alert: Alert;
  agent: Agent | null;
  storySteps: StoryStep[];
  primaryProcess?: Evidence['process'] | ProcessChainNode;
  primaryNetwork?: Record<string, any> | null;
  primaryFile?: { path?: string; sha256?: string } | null;
  iocs: IOC[];
  responseActions: ResponseActionRecord[];
  proofData: ProofAttestation | null;
  graphStats?: AlertDetailPageProps['graphData']['stats'];
  eventFlowStats: {
    networkCount: number;
    processCount: number;
    fileCount: number;
    dnsCount: number;
    totalBytesSent: number;
    totalBytesRecv: number;
    uniqueIPs: number;
    uniqueDomains: number;
  };
  relatedEventsCount: number;
  correlationOverview: string;
  onOpenTab: (tab: AlertTab) => void;
  onCopy: (text: string, field: string) => void;
  copiedField: string | null;
}) {
  const ruleName = alert.evidence?.detection?.rule_name || alert.detectionMetadata?.rule_name || 'Detection rule';
  const detectionType = inferDetectionType(alert.evidence?.detection?.rule_type || alert.detectionMetadata?.rule_type, ruleName);
  const detectionTechniques = alert.evidence?.detection?.mitre_techniques || alert.mitreTechniques || [];

  const toneStyle = (tone: StoryStep['tone']): React.CSSProperties => {
    const colors = {
      critical: 'var(--crit)',
      high: 'var(--high)',
      medium: 'var(--med)',
      low: 'var(--low)',
      accent: 'var(--accent)',
      muted: 'var(--muted)'
    };
    const color = colors[tone];
    return {
      color,
      backgroundColor: `color-mix(in srgb, ${color} 12%, var(--surface))`,
      borderColor: `color-mix(in srgb, ${color} 35%, var(--border))`
    };
  };

  const remote = primaryNetwork?.remote_ip || primaryNetwork?.dst_ip || primaryNetwork?.resolved_ip || primaryNetwork?.value;
  const remotePort = primaryNetwork?.remote_port || primaryNetwork?.dst_port || primaryNetwork?.port;
  const highestConfidence = iocs.reduce((acc, ioc) => Math.max(acc, Number(ioc.confidence || 0)), 0);
  const publicSafeCount = iocs.filter(ioc => !ioc.redacted).length;
  const decodedCommand = decodePowerShellEncodedCommand(primaryProcess?.cmdline);
  const decodedUrls = extractUrls(decodedCommand);

  return (
    <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--bg) 78%, var(--surface))', borderColor: 'var(--border)' }}>
      <div className="max-w-full mx-auto px-4 py-4">
        <div className="grid grid-cols-1 2xl:grid-cols-[1.15fr_0.85fr] gap-4">
          <div
            className="rounded-xl overflow-hidden"
            style={{
              backgroundColor: 'var(--surface)',
              border: '1px solid var(--border)',
              boxShadow: '0 18px 48px rgba(0,0,0,0.18)'
            }}
          >
            <div className="px-4 py-3 border-b flex items-center justify-between gap-3" style={{ borderColor: 'var(--border)' }}>
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: 'color-mix(in srgb, var(--accent) 14%, transparent)', color: 'var(--accent)' }}
                >
                  <GitBranch size={18} />
                </div>
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Incident Storyline</h3>
                  <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>
                    Endpoint activity, detection evidence, containment and public proof in one flow.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs shrink-0" style={{ color: 'var(--muted)' }}>
                <span>{graphStats?.process_count ?? eventFlowStats.processCount} processes</span>
                <span>•</span>
                <span>{eventFlowStats.networkCount || graphStats?.network_count || 0} network events</span>
                <span>•</span>
                <span>{iocs.length} IOCs</span>
              </div>
            </div>

            <div className="p-4">
              <div className="grid grid-cols-1 xl:grid-cols-5 gap-3">
                {storySteps.map((step, index) => {
                  const Icon = step.icon;
                  return (
                    <button
                      key={step.id}
                      onClick={() => step.tab && onOpenTab(step.tab)}
                      className="group relative text-left rounded-xl p-3 border transition-all hover:-translate-y-0.5 hover:brightness-110"
                      style={toneStyle(step.tone)}
                    >
                      {index < storySteps.length - 1 && (
                        <div className="hidden xl:block absolute top-1/2 -right-3 w-3 h-px" style={{ backgroundColor: 'var(--border)' }} />
                      )}
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] uppercase tracking-wide font-semibold opacity-80">{step.label}</span>
                        <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
                          <Icon size={15} />
                        </div>
                      </div>
                      <Tooltip content={step.title}>
                        <div className="text-sm font-semibold truncate" style={{ color: 'var(--fg)' }}>
                          {step.title}
                        </div>
                      </Tooltip>
                      <Tooltip content={step.detail}>
                        <p className="mt-1 text-xs leading-relaxed line-clamp-2" style={{ color: 'var(--muted)' }}>
                          {step.detail}
                        </p>
                      </Tooltip>
                    </button>
                  );
                })}
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-4 gap-3 mt-4">
                <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--hairline)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu size={14} style={{ color: 'var(--accent)' }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>Primary Process</span>
                  </div>
                  <div className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{primaryProcess?.name || 'unknown'}</div>
                  <LongTextPreview
                    value={primaryProcess?.cmdline || primaryProcess?.path || 'command line not captured'}
                    maxChars={125}
                    maxLines={2}
                    onCopy={(text) => onCopy(text, 'primary_cmdline')}
                    copied={copiedField === 'primary_cmdline'}
                    mono
                    compact
                  />
                  {decodedCommand && (
                    <LongTextPreview
                      value={decodedCommand}
                      maxChars={280}
                      maxLines={6}
                      onCopy={(text) => onCopy(text, 'decoded_powershell')}
                      copied={copiedField === 'decoded_powershell'}
                      mono
                    />
                  )}
                  <div className="mt-2 flex gap-2 flex-wrap text-[10px]" style={{ color: 'var(--subtle)' }}>
                    {primaryProcess?.pid && <span>PID {primaryProcess.pid}</span>}
                    {primaryProcess && 'is_signed' in primaryProcess && <span>{primaryProcess.is_signed ? 'signed' : 'unsigned'}</span>}
                    {primaryProcess?.user && <span>{primaryProcess.user}</span>}
                  </div>
                </div>

                <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--hairline)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <GitBranch size={14} style={{ color: 'var(--accent)' }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>Correlation Basis</span>
                  </div>
                  <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                    {relatedEventsCount} event{relatedEventsCount === 1 ? '' : 's'} grouped
                  </div>
                  <Tooltip content={correlationOverview}>
                    <div className="mt-1 text-xs leading-relaxed line-clamp-2" style={{ color: 'var(--muted)' }}>
                      {correlationOverview}
                    </div>
                  </Tooltip>
                </div>

                <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--hairline)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Wifi size={14} style={{ color: 'var(--low)' }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>External Touchpoint</span>
                  </div>
                  {remote ? (
                    <Tooltip content={String(remote)}>
                      <div className="text-sm font-mono truncate" style={{ color: 'var(--low)' }}>
                        {`${remote}${remotePort ? `:${remotePort}` : ''}`}
                      </div>
                    </Tooltip>
                  ) : (
                    <div className="text-sm font-mono truncate" style={{ color: 'var(--muted)' }}>
                      no remote endpoint captured
                    </div>
                  )}
                  <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                    {eventFlowStats.uniqueIPs} unique IPs, {eventFlowStats.uniqueDomains} DNS names, {formatBytesLocal(eventFlowStats.totalBytesSent)} sent
                  </div>
                </div>

                <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--hairline)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldCheck size={14} style={{ color: proofData?.attested ? 'var(--low)' : 'var(--muted)' }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>Public-Safe Proof</span>
                  </div>
                  <div className="text-sm font-medium truncate" style={{ color: proofData?.attested ? 'var(--low)' : 'var(--muted)' }}>
                    {proofData?.attested ? 'Verified on Solana' : 'Not anchored yet'}
                  </div>
                  <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                    {publicSafeCount} publishable IOCs, {highestConfidence ? `${Math.round(highestConfidence <= 1 ? highestConfidence * 100 : highestConfidence)}% max confidence` : 'confidence pending'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-1 gap-4">
            <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileText size={16} style={{ color: 'var(--med)' }} />
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Evidence Snapshot</h3>
                </div>
                <button onClick={() => onOpenTab('evidence')} className="text-xs hover:brightness-110" style={{ color: 'var(--accent)' }}>
                  Open evidence
                </button>
              </div>
              <div className="space-y-2 text-xs">
                <EvidenceRow label="Rule" value={alert.evidence?.detection?.rule_name || alert.detectionMetadata?.rule_name || 'not recorded'} />
                <EvidenceRow label="Type" value={detectionType ? humanizeDetectionType(detectionType) : 'not classified'} />
                <EvidenceRow label="Technique" value={detectionTechniques[0] || alert.evidence?.detection?.mitre_attack_id || 'not mapped'} />
                <EvidenceRow label="File" value={primaryFile?.path || 'not captured'} />
                <EvidenceRow label="Hash" value={shortValue(primaryFile?.sha256 || (primaryProcess && 'sha256' in primaryProcess ? primaryProcess.sha256 : undefined))} />
                <EvidenceRow label="Decoded PS" value={decodedCommand ? shortValue(decodedCommand, 60, 20) : 'not present'} />
                <EvidenceRow label="URL" value={decodedUrls[0] ? shortValue(decodedUrls[0], 44, 18) : 'not captured'} />
                <EvidenceRow label="Agent" value={agent?.hostname || 'unknown endpoint'} />
              </div>
            </div>

            <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Hash size={16} style={{ color: 'var(--high)' }} />
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Top Indicators</h3>
                </div>
                <span className="text-xs" style={{ color: 'var(--muted)' }}>{iocs.length} total</span>
              </div>
              {iocs.length === 0 ? (
                <p className="text-xs" style={{ color: 'var(--muted)' }}>No normalized IOCs are available for this alert yet.</p>
              ) : (
                <div className="space-y-2">
                  {iocs.slice(0, 4).map((ioc, index) => (
                    <div key={`${ioc.type}-${ioc.value}-${index}`} className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                        {ioc.type}
                      </span>
                      <Tooltip content={ioc.value}>
                        <button
                          onClick={() => onCopy(ioc.value, `story_ioc_${index}`)}
                          className="text-xs font-mono truncate text-left hover:brightness-125"
                          style={{ color: copiedField === `story_ioc_${index}` ? 'var(--low)' : 'var(--fg-2)' }}
                        >
                          {shortValue(ioc.value, 20, 12)}
                        </button>
                      </Tooltip>
                    </div>
                  ))}
                </div>
              )}
              {responseActions.length > 0 && (
                <div className="mt-3 pt-3 border-t text-xs" style={{ borderColor: 'var(--hairline)', color: 'var(--muted)' }}>
                  Last response: {humanizeValue(responseActions[0].action_type)} · {asText(responseActions[0].status, 'unknown')}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function EvidenceRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b last:border-b-0" style={{ borderColor: 'var(--hairline)' }}>
      <span className="uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>{label}</span>
      <Tooltip content={value}>
        <span
          className="font-mono text-right max-w-[280px] min-w-0"
          style={{ color: 'var(--fg-2)', overflowWrap: 'anywhere', wordBreak: 'break-word' }}
        >
          {shortValue(value, 44, 14)}
        </span>
      </Tooltip>
    </div>
  );
}

function LongTextPreview({
  value,
  maxChars = 240,
  maxLines = 3,
  onCopy,
  copied = false,
  mono = false,
  compact = false
}: {
  value?: string | null;
  maxChars?: number;
  maxLines?: number;
  onCopy?: (text: string) => void;
  copied?: boolean;
  mono?: boolean;
  compact?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const text = value || '';
  const normalized = text.trim();
  const shouldCollapse = normalized.length > maxChars || normalized.split('\n').length > maxLines;
  const visibleText = !shouldCollapse || expanded
    ? normalized
    : `${normalized.slice(0, maxChars).trimEnd()}...`;

  if (!normalized) {
    return (
      <span className="text-xs" style={{ color: 'var(--muted)' }}>
        not captured
      </span>
    );
  }

  return (
    <div className={compact ? 'mt-1' : 'mt-2'}>
      <Tooltip content={normalized}>
        <div
          className={cn(
            'rounded-md border min-w-0',
            compact ? 'px-0 py-0 border-transparent bg-transparent' : 'p-2',
            mono ? 'font-mono text-[11px]' : 'text-sm'
          )}
          style={{
            backgroundColor: compact ? 'transparent' : 'var(--bg)',
            borderColor: compact ? 'transparent' : 'var(--hairline)',
            color: compact ? 'var(--muted)' : 'var(--fg-2)',
            overflowWrap: 'anywhere',
            wordBreak: 'break-word',
            whiteSpace: 'pre-wrap',
            maxHeight: expanded ? '18rem' : undefined,
            overflowY: expanded ? 'auto' : undefined
          }}
        >
          {visibleText}
        </div>
      </Tooltip>
      {(shouldCollapse || onCopy) && (
        <div className="mt-1 flex items-center gap-2">
          {shouldCollapse && (
            <button
              type="button"
              onClick={() => setExpanded((current) => !current)}
              className="inline-flex items-center gap-1 text-[11px] rounded px-1.5 py-0.5 hover:brightness-125"
              style={{ color: 'var(--accent)' }}
            >
              {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              {expanded ? 'View less' : 'View more'}
            </button>
          )}
          {onCopy && (
            <button
              type="button"
              onClick={() => onCopy(normalized)}
              className="inline-flex items-center gap-1 text-[11px] rounded px-1.5 py-0.5 hover:brightness-125"
              style={{ color: copied ? 'var(--low)' : 'var(--muted)' }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function formatBytesLocal(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function StatusBadge({ status }: { status: Alert['status'] }) {
  const getStatusStyle = (status: string): React.CSSProperties => {
    switch (status) {
      case 'new':
        return {
          backgroundColor: 'color-mix(in srgb, var(--accent) 20%, transparent)',
          color: 'var(--accent)',
          borderColor: 'color-mix(in srgb, var(--accent) 30%, transparent)'
        };
      case 'open':
        return {
          backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)',
          color: 'var(--crit)',
          borderColor: 'color-mix(in srgb, var(--crit) 30%, transparent)'
        };
      case 'acknowledged':
        return {
          backgroundColor: 'color-mix(in srgb, var(--accent-secondary, #a855f7) 20%, transparent)',
          color: 'var(--accent-secondary, #a855f7)',
          borderColor: 'color-mix(in srgb, var(--accent-secondary, #a855f7) 30%, transparent)'
        };
      case 'investigating':
        return {
          backgroundColor: 'color-mix(in srgb, var(--med) 20%, transparent)',
          color: 'var(--med)',
          borderColor: 'color-mix(in srgb, var(--med) 30%, transparent)'
        };
      case 'resolved':
        return {
          backgroundColor: 'color-mix(in srgb, var(--low) 20%, transparent)',
          color: 'var(--low)',
          borderColor: 'color-mix(in srgb, var(--low) 30%, transparent)'
        };
      case 'false_positive':
        return {
          backgroundColor: 'color-mix(in srgb, var(--muted) 20%, transparent)',
          color: 'var(--muted)',
          borderColor: 'color-mix(in srgb, var(--muted) 30%, transparent)'
        };
      default:
        return {
          backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)',
          color: 'var(--crit)',
          borderColor: 'color-mix(in srgb, var(--crit) 30%, transparent)'
        };
    }
  };

  const labels: Record<string, string> = {
    new: 'New',
    open: 'Open',
    acknowledged: 'Acknowledged',
    investigating: 'Investigating',
    resolved: 'Resolved',
    false_positive: 'False Positive',
  };

  return (
    <span
      className="badge-sentinel text-xs px-2 py-0.5 rounded border"
      style={getStatusStyle(status)}
    >
      {labels[status] || humanizeValue(status, 'unknown')}
    </span>
  );
}

// Workflow Timeline Component (Horizontal)
function WorkflowTimeline({ steps }: { steps: WorkflowStep[] }) {
  const formatTime = (timestamp?: string) => {
    if (!timestamp) return '---';
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="flex items-center justify-between w-full">
      {steps.map((step, index) => {
        const Icon = step.icon;
        const isLast = index === steps.length - 1;

        return (
          <div key={step.id} className="flex items-center flex-1">
            {/* Step */}
            <div className="flex flex-col items-center">
              {/* Icon Circle */}
              <div
                className={cn(
                  'w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all',
                  step.status === 'completed' && 'border-[var(--emerald-500)] bg-[var(--emerald-glow)]',
                  step.status === 'current' && 'border-[var(--med)] bg-[var(--med-bg)] animate-pulse',
                  step.status === 'pending' && 'border-[var(--border)] bg-[var(--surface-2)]'
                )}
              >
                <Icon
                  size={18}
                  className={cn(
                    step.status === 'completed' && 'text-[var(--emerald-400)]',
                    step.status === 'current' && 'text-[var(--med)]',
                    step.status === 'pending' && 'text-[var(--muted)]'
                  )}
                />
              </div>
              {/* Label */}
              <span
                className={cn(
                  'text-xs mt-1.5 font-medium whitespace-nowrap',
                  step.status === 'completed' && 'text-[var(--emerald-400)]',
                  step.status === 'current' && 'text-[var(--med)]',
                  step.status === 'pending' && 'text-[var(--muted)]'
                )}
              >
                {step.label}
              </span>
              {/* Timestamp */}
              <span className="text-[10px] mt-0.5" style={{ color: 'var(--subtle)' }}>
                {formatTime(step.timestamp)}
              </span>
            </div>

            {/* Connector */}
            {!isLast && (
              <div
                className={cn(
                  'flex-1 h-0.5 mx-2 rounded',
                  step.status === 'completed' ? 'bg-[var(--emerald-500)]' : 'bg-[var(--border)]'
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// Proof Card Section Component
function ProofCardSection({
  proofData,
  isLoading,
  error,
  alertId,
  mitreTechniques,
  onCopyToClipboard,
  copiedField
}: {
  proofData: ProofAttestation | null;
  isLoading: boolean;
  error: string | null;
  alertId: string;
  mitreTechniques?: string[];
  onCopyToClipboard: (text: string, field: string) => void;
  copiedField: string | null;
}) {
  const [showVerifyCommand, setShowVerifyCommand] = useState(false);

  if (isLoading) {
    return (
      <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-2)] animate-pulse" />
          <div className="flex-1">
            <div className="h-4 w-24 bg-[var(--surface-2)] rounded animate-pulse" />
            <div className="h-3 w-16 bg-[var(--surface-2)] rounded mt-1 animate-pulse" />
          </div>
        </div>
      </div>
    );
  }

  if (!proofData || !proofData.attested) {
    return (
      <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
            <ShieldAlert size={20} style={{ color: 'var(--muted)' }} />
          </div>
          <div>
            <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Proof of Incident</h4>
            <p className="text-xs" style={{ color: 'var(--muted)' }}>Not yet anchored</p>
          </div>
        </div>
        <div
          className="rounded-lg p-3 text-xs"
          style={{
            backgroundColor: error ? 'color-mix(in srgb, var(--crit) 12%, var(--surface-2))' : 'var(--surface-2)',
            color: error ? 'var(--crit)' : 'var(--muted)'
          }}
        >
          {error ||
          (proofData?.eligible !== false
            ? 'This alert will be anchored to Solana automatically within 60 seconds.'
            : 'This alert severity is not eligible for on-chain attestation.')}
        </div>
      </div>
    );
  }

  const truncateHash = (hash: string, chars: number = 8) => {
    if (!hash || hash.length <= chars * 2) return hash;
    return `${hash.slice(0, chars)}...${hash.slice(-chars)}`;
  };

  const relativeTime = (timestamp?: string) => {
    if (!timestamp) return '---';
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now.getTime() - then.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const includedFields = proofData.included_fields || [
    'incident_hash',
    'manifest_hash',
    'severity_u8',
    'mitre_ids[]',
    'ioc_count'
  ];

  const verifyCommand = `curl -s "https://api.solscan.io/transaction?tx=${proofData.tx_id}&cluster=devnet" | jq '.result.memo'`;

  return (
    <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(25, 251, 155, 0.12)' }}>
            <ShieldCheck size={18} style={{ color: 'var(--sol-cyan)' }} />
          </div>
          <div>
            <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Proof of Incident</h4>
            <span
              className="badge-sentinel badge-sentinel-sol-cyan text-[10px] px-1.5 py-0.5 rounded-full"
            >
              Verified
            </span>
          </div>
        </div>
      </div>

      {/* Fields */}
      <div className="space-y-2">
        {/* Manifest Hash */}
        {proofData.manifest_hash && (
          <ProofField
            label="MANIFEST HASH"
            value={truncateHash(proofData.manifest_hash)}
            fullValue={proofData.manifest_hash}
            onCopy={() => onCopyToClipboard(proofData.manifest_hash!, 'manifest_hash')}
            copied={copiedField === 'manifest_hash'}
          />
        )}

        {/* TX Hash */}
        <ProofField
          label="TX"
          value={truncateHash(proofData.tx_id || '')}
          fullValue={proofData.tx_id || ''}
          onCopy={() => onCopyToClipboard(proofData.tx_id!, 'tx_id')}
          copied={copiedField === 'tx_id'}
          linkUrl={proofData.solscan_url}
        />

        {/* Slot */}
        {proofData.slot && (
          <ProofField
            label="SLOT"
            value={proofData.slot.toLocaleString()}
            fullValue={String(proofData.slot)}
            onCopy={() => onCopyToClipboard(String(proofData.slot), 'slot')}
            copied={copiedField === 'slot'}
          />
        )}

        {/* Anchored Time */}
        <ProofField
          label="ANCHORED"
          value={relativeTime(proofData.attested_at)}
          fullValue={proofData.attested_at || ''}
          onCopy={() => onCopyToClipboard(proofData.attested_at || '', 'attested_at')}
          copied={copiedField === 'attested_at'}
        />
      </div>

      {/* What's Included */}
      <div className="mt-4 pt-3 border-t" style={{ borderColor: 'var(--hairline)' }}>
        <h5 className="text-[10px] uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>
          What's included
        </h5>
        <div className="grid grid-cols-2 gap-1">
          {includedFields.map(field => (
            <div key={field} className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--fg-2)' }}>
              <FileCheck size={12} style={{ color: 'var(--emerald-400)' }} />
              <span>{field}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Public manifest summary */}
      <div className="mt-4 pt-3 border-t" style={{ borderColor: 'var(--hairline)' }}>
        <h5 className="text-[10px] uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>
          Public proof summary
        </h5>
        <div className="grid grid-cols-2 gap-2">
          <ProofMiniStat label="TLP" value={(proofData.tlp || 'clear').toUpperCase()} />
          <ProofMiniStat label="IOCs" value={String(proofData.ioc_count ?? proofData.public_manifest?.['ioc_count'] ?? '0')} />
          <ProofMiniStat label="Redacted" value={String(proofData.redacted_ioc_count ?? proofData.public_manifest?.['redacted_ioc_count'] ?? '0')} />
          <ProofMiniStat
            label="Confidence"
            value={
              proofData.confidence != null
                ? `${Math.round(Number(proofData.confidence) <= 1 ? Number(proofData.confidence) * 100 : Number(proofData.confidence))}%`
                : 'N/A'
            }
          />
          <ProofMiniStat label="Class" value={proofData.threat_class || 'incident'} />
          <ProofMiniStat label="Family" value={proofData.malware_family || 'unknown'} />
        </div>
        {proofData.ioc_types && proofData.ioc_types.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {proofData.ioc_types.map(type => (
              <span
                key={type}
                className="px-1.5 py-0.5 rounded text-[10px]"
                style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
              >
                {type}
              </span>
            ))}
          </div>
        )}
        {proofData.bounty && (
          <div
            className="mt-2 rounded p-2 text-xs"
            style={{ backgroundColor: 'color-mix(in srgb, var(--low) 12%, var(--surface-2))', color: 'var(--low)' }}
          >
            Bounty paid: {proofData.bounty.amount_sol} SOL
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-2 mt-4">
        <a
          href={proofData.solscan_url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors hover:brightness-110"
          style={{
            backgroundColor: 'var(--surface-2)',
            color: 'var(--fg)'
          }}
        >
          <ExternalLink size={14} />
          Solscan
        </a>
        <button
          onClick={() => onCopyToClipboard(JSON.stringify(proofData, null, 2), 'proof_bundle')}
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors hover:brightness-110"
          style={{
            backgroundColor: 'var(--surface-2)',
            color: copiedField === 'proof_bundle' ? 'var(--emerald-400)' : 'var(--fg)'
          }}
        >
          {copiedField === 'proof_bundle' ? <Check size={14} /> : <Copy size={14} />}
          {copiedField === 'proof_bundle' ? 'Copied' : 'Copy Proof'}
        </button>
      </div>

      {/* Verify Yourself */}
      <div className="mt-3">
        <button
          onClick={() => setShowVerifyCommand(!showVerifyCommand)}
          className="flex items-center gap-1 text-[10px] uppercase tracking-wide hover:brightness-110"
          style={{ color: 'var(--muted)' }}
        >
          <Lock size={10} />
          Verify yourself
          {showVerifyCommand ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
        {showVerifyCommand && (
          <div className="mt-2">
            <pre
              className="text-[10px] p-2 rounded overflow-x-auto"
              style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)', fontFamily: 'var(--mono)' }}
            >
              {verifyCommand}
            </pre>
            <button
              onClick={() => onCopyToClipboard(verifyCommand, 'verify_cmd')}
              className="mt-1 text-[10px] flex items-center gap-1 hover:brightness-110"
              style={{ color: copiedField === 'verify_cmd' ? 'var(--emerald-400)' : 'var(--muted)' }}
            >
              {copiedField === 'verify_cmd' ? <Check size={10} /> : <Copy size={10} />}
              {copiedField === 'verify_cmd' ? 'Copied' : 'Copy command'}
            </button>
          </div>
        )}
      </div>

      {/* Privacy Notice */}
      <div className="mt-3 flex items-center gap-1.5 text-[10px]" style={{ color: 'var(--subtle)' }}>
        <Lock size={10} />
        No customer-identifying data left this server
      </div>
    </div>
  );
}

function ProofMiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded p-2" style={{ backgroundColor: 'var(--surface-2)' }}>
      <div className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>{label}</div>
      <Tooltip content={value}>
        <div className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>{value}</div>
      </Tooltip>
    </div>
  );
}

// Individual Proof Field Component
function ProofField({
  label,
  value,
  fullValue,
  onCopy,
  copied,
  linkUrl
}: {
  label: string;
  value: string;
  fullValue: string;
  onCopy: () => void;
  copied: boolean;
  linkUrl?: string;
}) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b" style={{ borderColor: 'var(--hairline)' }}>
      <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>
        {label}
      </span>
      <div className="flex items-center gap-1.5">
        <Tooltip content={fullValue}>
          <span
            className="font-mono text-xs"
            style={{ color: 'var(--fg-2)' }}
          >
            {value}
          </span>
        </Tooltip>
        {linkUrl && (
          <a
            href={linkUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="p-1 rounded hover:brightness-110"
            style={{ color: 'var(--sol-cyan)' }}
          >
            <ExternalLink size={12} />
          </a>
        )}
        <button
          onClick={onCopy}
          className="p-1 rounded hover:brightness-110"
          style={{ color: copied ? 'var(--emerald-400)' : 'var(--muted)' }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
        </button>
      </div>
    </div>
  );
}

function ResponseActionsSection({ actions }: { actions: ResponseActionRecord[] }) {
  const statusStyle = (status: string): React.CSSProperties => {
    switch (status) {
      case 'success':
        return { backgroundColor: 'color-mix(in srgb, var(--low) 14%, transparent)', color: 'var(--low)' };
      case 'failed':
      case 'timeout':
        return { backgroundColor: 'color-mix(in srgb, var(--crit) 14%, transparent)', color: 'var(--crit)' };
      case 'executing':
      case 'pending':
        return { backgroundColor: 'color-mix(in srgb, var(--med) 14%, transparent)', color: 'var(--med)' };
      default:
        return { backgroundColor: 'var(--surface-2)', color: 'var(--muted)' };
    }
  };

  return (
    <div className="p-4 border-t" style={{ borderColor: 'var(--border)' }}>
      <div className="flex items-center gap-2 mb-3">
        <Terminal size={16} style={{ color: 'var(--muted)' }} />
        <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Response History</h4>
        <span className="px-1.5 py-0.5 text-xs rounded" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
          {actions.length}
        </span>
      </div>

      {actions.length === 0 ? (
        <p className="text-xs text-center py-3" style={{ color: 'var(--muted)' }}>
          No response actions recorded for this alert
        </p>
      ) : (
        <div className="space-y-2">
          {actions.slice(0, 8).map(action => (
            <div key={action.id} className="rounded-lg p-2" style={{ backgroundColor: 'var(--surface-2)' }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>
                  {humanizeValue(action.action_type, 'action')}
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] uppercase" style={statusStyle(action.status)}>
                  {action.status}
                </span>
              </div>
              <div className="mt-1 text-[10px]" style={{ color: 'var(--subtle)' }}>
                {action.executed_at || action.created_at ? new Date(action.executed_at || action.created_at || '').toLocaleString() : 'time not recorded'}
              </div>
              {action.error_message && (
                <Tooltip content={action.error_message}>
                  <div className="mt-1 text-[10px] truncate" style={{ color: 'var(--crit)' }}>
                    {action.error_message}
                  </div>
                </Tooltip>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// IOCs Section Component
function IOCsSection({
  iocs,
  expanded,
  onToggle,
  onCopyToClipboard,
  copiedField,
  canBlock,
  onBlockIOC
}: {
  iocs: IOC[];
  expanded: boolean;
  onToggle: () => void;
  onCopyToClipboard: (text: string, field: string) => void;
  copiedField: string | null;
  canBlock: boolean;
  onBlockIOC: (ioc: IOC) => void;
}) {
  const getIOCTypeBadge = (type: IOC['type']) => {
    const configs = {
      ip: { label: 'IP', color: 'var(--med)', bg: 'var(--med-bg)' },
      hash: { label: 'Hash', color: 'var(--high)', bg: 'var(--high-bg)' },
      domain: { label: 'Domain', color: 'var(--accent-secondary, #a855f7)', bg: 'rgba(168, 85, 247, 0.12)' },
      url: { label: 'URL', color: 'var(--crit)', bg: 'var(--crit-bg)' },
      email: { label: 'Email', color: 'var(--emerald-400)', bg: 'var(--emerald-glow)' },
      file_path: { label: 'Path', color: 'var(--muted)', bg: 'var(--surface-2)' }
    };
    return configs[type] || configs.file_path;
  };

  return (
    <div className="p-4">
      {/* Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between mb-3"
      >
        <div className="flex items-center gap-2">
          <Layers size={16} style={{ color: 'var(--muted)' }} />
          <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
            IOCs
          </h4>
          <span
            className="px-1.5 py-0.5 text-xs rounded"
            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
          >
            {iocs.length}
          </span>
        </div>
        {expanded ? <ChevronUp size={16} style={{ color: 'var(--muted)' }} /> : <ChevronDown size={16} style={{ color: 'var(--muted)' }} />}
      </button>

      {/* IOC List */}
      {expanded && (
        <div className="space-y-2">
          {iocs.length === 0 ? (
            <p className="text-xs text-center py-4" style={{ color: 'var(--muted)' }}>
              No IOCs extracted from evidence
            </p>
          ) : (
            iocs.map((ioc, index) => {
              const badge = getIOCTypeBadge(ioc.type);
              const fieldKey = `ioc_${index}`;
              return (
                <div
                  key={fieldKey}
                  className="flex items-center justify-between p-2 rounded-lg"
                  style={{ backgroundColor: 'var(--surface-2)' }}
                >
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <span
                      className="text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0"
                      style={{ backgroundColor: badge.bg, color: badge.color }}
                    >
                      {badge.label}
                    </span>
                    <Tooltip content={ioc.value}>
                      <span
                        className="text-xs font-mono truncate"
                        style={{ color: 'var(--fg-2)' }}
                      >
                        {ioc.value.length > 32 ? `${ioc.value.slice(0, 16)}...${ioc.value.slice(-12)}` : ioc.value}
                      </span>
                    </Tooltip>
                  </div>
                  <div className="flex flex-col min-w-0 flex-1">
                    {(ioc.source || ioc.tlp || ioc.confidence != null || ioc.redacted) && (
                      <span className="text-[10px] truncate" style={{ color: 'var(--subtle)' }}>
                        {ioc.source || 'indicator'}
                        {ioc.tlp && ` • TLP:${ioc.tlp.toUpperCase()}`}
                        {ioc.confidence != null && ` • ${Math.round(Number(ioc.confidence) <= 1 ? Number(ioc.confidence) * 100 : Number(ioc.confidence))}%`}
                        {ioc.redacted && ' • redacted'}
                      </span>
                    )}
                  </div>
                  <Tooltip content="Copy IOC">
                    <button
                      onClick={() => onCopyToClipboard(ioc.value, fieldKey)}
                      className="p-1 rounded hover:brightness-110 shrink-0"
                      style={{ color: copiedField === fieldKey ? 'var(--emerald-400)' : 'var(--muted)' }}
                    >
                      {copiedField === fieldKey ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  </Tooltip>
                  {canBlock && (ioc.blockable ?? (ioc.type === 'ip' || ioc.type === 'domain')) && (
                    <Tooltip content={`Block ${ioc.type}`}>
                      <button
                        onClick={() => onBlockIOC(ioc)}
                        className="p-1 rounded hover:brightness-110 shrink-0"
                        style={{ color: 'var(--crit)' }}
                      >
                        <ShieldAlert size={12} />
                      </button>
                    </Tooltip>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
