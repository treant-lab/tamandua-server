import { useState, useEffect, useCallback } from 'react';
import { Head, router } from '@inertiajs/react';
import {
  ArrowLeft, Clock, AlertTriangle, Activity, Cpu, Shield, RefreshCw,
  Globe, File, Server, Settings, ChevronDown, ChevronUp, X, Check, XCircle,
  Share2, Search, ExternalLink, Copy, Eye, Crosshair, GitBranch,
  FileText, Terminal, ArrowRight, Database, Wifi, ShieldCheck, ShieldAlert,
  Lock, FileCheck, Hash, Link2, Layers, ClipboardList
} from 'lucide-react';
import InvestigationGraph from '@/components/InvestigationGraph';
import EntityPivot from '@/components/EntityPivot';
import EvidencePanel from '@/components/EvidencePanel';
import ProcessChainView from '@/components/ProcessChainView';
import { collectModelObservations, ModelObservationsPanel } from '@/components/ModelObservationsPanel';
import { Menu, MenuItem, Tooltip } from '@/components/ui/baseui';
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger';
import type { Alert, Agent, GraphNode, GraphEdge, TimelineEntry, GraphNodeType, Evidence, ProcessChainNode, AlertEvidenceQuality, AlertInvestigationPivot, AlertInvestigationStory, AlertTriageAgentContract } from '@/types';

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

interface InvestigationRunRecord {
  id: string;
  alert_id: string;
  mode: string;
  status: string;
  source: string;
  policy_version: string;
  summary?: Record<string, unknown>;
  started_at?: string | null;
  completed_at?: string | null;
  inserted_at?: string | null;
  updated_at?: string | null;
}

interface InvestigationEvidenceRecord {
  id: string;
  run_id: string;
  kind: string;
  source: string;
  source_ref?: string | null;
  payload?: Record<string, unknown>;
  observed_at?: string | null;
  inserted_at?: string | null;
}

// IOC (Indicator of Compromise) type
interface IOC {
  type: 'ip' | 'hash' | 'domain' | 'url' | 'email' | 'file_path' | 'package' | 'app' | 'indicator';
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
  icon: React.ComponentType<{ className?: string; size?: string | number }>;
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
  command?: AgentCommandRecord | null;
  rollback?: RollbackSummary | null;
}

interface RollbackSummary {
  available?: boolean;
  action_type?: string | null;
  actionType?: string | null;
  reason?: string | null;
}

interface AgentCommandRecord {
  id: string;
  agent_id?: string;
  agentId?: string;
  runtime?: string;
  runtime_kind?: string;
  runtimeKind?: string;
  command_runtime?: string;
  commandRuntime?: string;
  command_type?: string;
  commandType?: string;
  command_params?: Record<string, unknown>;
  commandParams?: Record<string, unknown>;
  status: 'pending' | 'sent' | 'acknowledged' | 'completed' | 'failed' | string;
  priority?: number | string;
  result?: Record<string, unknown> | null;
  error?: string | null;
  sent_at?: string | null;
  sentAt?: string | null;
  acknowledged_at?: string | null;
  acknowledgedAt?: string | null;
  completed_at?: string | null;
  completedAt?: string | null;
  expires_at?: string | null;
  expiresAt?: string | null;
  dispatch_count?: number;
  dispatchCount?: number;
  last_dispatched_at?: string | null;
  lastDispatchedAt?: string | null;
  inserted_at?: string | null;
  insertedAt?: string | null;
  updated_at?: string | null;
  updatedAt?: string | null;
  rollback?: RollbackSummary | null;
}

interface AgentCommandResponse {
  data?: AgentCommandRecord[];
  meta?: Record<string, unknown>;
}

interface MobileAlertCommandTarget {
  commandDeviceId?: string | null;
  legacyDeviceId?: string | null;
}

function resolveMobileCommandDeviceId(data: Record<string, any>): string | null {
  const commandIdentity = data?.command_identity || {};
  const commandDevice = data?.command_device || {};
  const value =
    commandIdentity.command_device_id ||
    commandDevice.id ||
    commandDevice.device_id ||
    commandIdentity.background_sync_device_id;
  return value ? String(value) : null;
}

interface MobileAlertCommandDraft {
  command: string;
  label: string;
  fieldLabel: string;
  value: string;
  placeholder: string;
  payloadKind: 'command' | 'domain' | 'package';
}

interface OperatorReadinessItem {
  label: string;
  status: 'supported' | 'gap' | 'degraded' | 'not_applicable';
  value: string;
  detail: string;
}

type OperationalQueueState = 'needs_triage' | 'triaged' | 'needs_evidence' | 'ready_for_response' | 'false_positive_candidate';

interface OperationalTriageState {
  state: OperationalQueueState;
  label: string;
  priority?: string;
  nextAction?: string;
  reasons: string[];
  evidenceQuality?: string;
  claimable?: boolean;
  terminal?: boolean;
}

interface TriageRecomputeResponse {
  data?: {
    triageAgent?: AlertTriageAgentContract;
    triage_agent?: AlertTriageAgentContract;
  };
}

type AlertTab = 'graph' | 'timeline' | 'events' | 'related' | 'evidence' | 'process-chain';
const ALERT_TABS: AlertTab[] = ['graph', 'evidence', 'process-chain', 'timeline', 'events', 'related'];

interface StoryStep {
  id: string;
  label: string;
  title: string;
  detail: string;
  icon: React.ComponentType<{ className?: string; size?: string | number }>;
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

const EVIDENCE_QUALITY_STYLES: Record<AlertEvidenceQuality['quality'], { color: string; bg: string; border: string; icon: typeof ShieldCheck }> = {
  direct: {
    color: 'var(--low)',
    bg: 'color-mix(in srgb, var(--low) 14%, transparent)',
    border: 'color-mix(in srgb, var(--low) 32%, transparent)',
    icon: ShieldCheck,
  },
  correlated: {
    color: 'var(--accent)',
    bg: 'color-mix(in srgb, var(--accent) 14%, transparent)',
    border: 'color-mix(in srgb, var(--accent) 30%, transparent)',
    icon: Link2,
  },
  derived: {
    color: 'var(--med)',
    bg: 'color-mix(in srgb, var(--med) 16%, transparent)',
    border: 'color-mix(in srgb, var(--med) 34%, transparent)',
    icon: Database,
  },
  synthetic: {
    color: 'var(--high)',
    bg: 'color-mix(in srgb, var(--high) 14%, transparent)',
    border: 'color-mix(in srgb, var(--high) 32%, transparent)',
    icon: AlertTriangle,
  },
  missing: {
    color: 'var(--crit)',
    bg: 'color-mix(in srgb, var(--crit) 14%, transparent)',
    border: 'color-mix(in srgb, var(--crit) 34%, transparent)',
    icon: XCircle,
  },
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

function normalizeIocType(value: unknown): IOC['type'] {
  const type = asText(value, 'indicator').trim();
  if (
    type === 'ip' ||
    type === 'hash' ||
    type === 'domain' ||
    type === 'url' ||
    type === 'email' ||
    type === 'file_path' ||
    type === 'package' ||
    type === 'app' ||
    type === 'indicator'
  ) {
    return type;
  }
  return 'indicator';
}

function asText(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : value == null ? fallback : String(value);
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(item => asText(item).trim()).filter(Boolean) : [];
}

function asTextArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(item => asText(item).trim()).filter(Boolean);
  const text = asText(value).trim();
  return text ? [text] : [];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asRecordArray(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) {
    return value.map(asRecord).filter(item => Object.keys(item).length > 0);
  }

  const record = asRecord(value);
  return Object.keys(record).length > 0 ? [record] : [];
}

function recordSize(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  const record = asRecord(value);
  return Object.keys(record).length;
}

function booleanFromUnknown(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'ok', 'ready', 'pass', 'passed', 'success'].includes(normalized)) return true;
    if (['false', 'blocked', 'fail', 'failed', 'missing'].includes(normalized)) return false;
  }
  return null;
}

function readinessToneStyle(status: OperatorReadinessItem['status']): { color: string; bg: string; border: string } {
  switch (status) {
    case 'supported':
      return {
        color: 'var(--low)',
        bg: 'color-mix(in srgb, var(--low) 12%, transparent)',
        border: 'color-mix(in srgb, var(--low) 28%, transparent)',
      };
    case 'gap':
      return {
        color: 'var(--high)',
        bg: 'color-mix(in srgb, var(--high) 12%, transparent)',
        border: 'color-mix(in srgb, var(--high) 28%, transparent)',
      };
    case 'degraded':
      return {
        color: 'var(--med)',
        bg: 'color-mix(in srgb, var(--med) 12%, transparent)',
        border: 'color-mix(in srgb, var(--med) 28%, transparent)',
      };
    default:
      return {
        color: 'var(--muted)',
        bg: 'var(--surface-2)',
        border: 'var(--border)',
      };
  }
}

function statusLabel(status: OperatorReadinessItem['status']): string {
  switch (status) {
    case 'supported':
      return 'supported';
    case 'gap':
      return 'gap';
    case 'degraded':
      return 'degraded';
    default:
      return 'n/a';
  }
}

function resolveRawEvent(alert: Alert): Record<string, unknown> {
  return asRecord(alert.rawEvent || alert.raw_event);
}

function relatedAlertContext(alert: Alert): Array<{ label: string; value: string }> {
  const rawEvent = resolveRawEvent(alert);
  const alertRecord = asRecord(alert);
  const payload = asRecord(rawEvent.payload);
  const app = asRecord(payload.app);
  const device = asRecord(payload.device);
  const evidence = asRecord(payload.evidence);
  const signals = Array.isArray(evidence.active_signals) ? evidence.active_signals : [];
  const firstSignal = asRecord(signals[0]);

  return [
    { label: 'event', value: firstText(payload.event_type, rawEvent.event_type, alert.source) },
    { label: 'app', value: firstText(app.display_name, app.package_or_bundle_id) },
    { label: 'package', value: firstText(app.package_or_bundle_id) },
    { label: 'device', value: firstText(device.model, device.device_id) },
    { label: 'managed', value: device.managed == null ? '' : String(device.managed) },
    { label: 'signal', value: firstText(firstSignal.name, firstSignal.type, firstSignal.reason) },
    { label: 'mitre', value: asTextArray(alert.mitreTechniques || alertRecord.mitre_techniques).slice(0, 3).join(', ') },
  ].filter(item => item.value);
}

function isParityTestAlert(alert: Alert): boolean {
  const alertRecord = asRecord(alert);
  const metadata = asRecord(alert.detectionMetadata || alertRecord.detection_metadata);
  const rawEvent = resolveRawEvent(alert);
  const payload = asRecord(rawEvent.payload);
  const device = asRecord(payload.device);
  const evidence = asRecord(payload.evidence);
  const eventIds = asTextArray(alertRecord.eventIds || alertRecord.event_ids);

  const markers = [
    alert.sourceEventId,
    alertRecord.source_event_id,
    ...eventIds,
    rawEvent.mobile_event_id,
    rawEvent.event_id,
    payload.event_id,
    payload.parity_run_id,
    payload.validation_run_id,
    payload.device_id,
    device.device_id,
    device.serial_number,
    evidence.source,
    evidence.parity_run_id,
    evidence.validation_run_id,
    metadata.rule_id,
    metadata.device_id,
    metadata.mobile_device_id,
  ];

  return markers.some(value => {
    const marker = asText(value).toLowerCase();
    return (
      marker.startsWith('mobile-endpoint-parity-') ||
      marker.startsWith('agent-mobile-endpoint-parity-') ||
      marker.startsWith('parity-') ||
      marker.includes('_parity_') ||
      marker.includes('-parity-')
    );
  });
}

function normalizeNetworkEvidence(evidence?: Evidence | null): Array<Record<string, unknown>> {
  return asRecordArray(evidence?.network);
}

function resolveFilePath(evidence?: Evidence | null): string | undefined {
  const file = asRecord(evidence?.file);
  const filePath = asText(file.path).trim();
  if (filePath) return filePath;

  const hashPath = (evidence?.file_hashes || [])
    .map(hash => asText(hash.path).trim())
    .find(Boolean);
  if (hashPath) return hashPath;

  const processPath = asText(evidence?.process?.path).trim();
  return processPath || undefined;
}

function resolveEvidenceQuality(alert: Alert): AlertEvidenceQuality {
  const fromServer = alert.evidenceQuality || alert.evidence_quality;
  if (fromServer?.quality) return fromServer;

  const evidence = asRecord(alert.evidence);
  const rawEvent = resolveRawEvent(alert);
  const hasSource = Boolean(alert.sourceEventId);
  const hasEvidence = Object.keys(evidence).length > 0;
  const hasRawEvent = Object.keys(rawEvent).length > 0;
  const hasDetection = Object.keys(asRecord(evidence.detection)).length > 0 || Object.keys(asRecord(alert.detectionMetadata)).length > 0;

  if (hasSource && hasEvidence && hasRawEvent) {
    return {
      quality: 'direct',
      label: 'Direct evidence',
      claimable: true,
      benchmark_eligible: true,
      summary: 'Persisted source event and evidence bundle are linked to this alert.',
      checks: { source_event: true, evidence_bundle: true, raw_event: true, detection: hasDetection },
      missing: [],
      score: 5,
    };
  }

  if (hasSource && hasEvidence) {
    return {
      quality: 'correlated',
      label: 'Correlated evidence',
      claimable: true,
      benchmark_eligible: true,
      summary: 'Alert has persisted event lineage plus evidence or related-event context.',
      checks: { source_event: true, evidence_bundle: true, raw_event: hasRawEvent, detection: hasDetection },
      missing: hasRawEvent ? [] : ['raw_event'],
      score: 4,
    };
  }

  if (hasEvidence && hasDetection) {
    return {
      quality: 'derived',
      label: 'Derived evidence',
      claimable: true,
      benchmark_eligible: false,
      summary: 'Alert is derived from detection/model evidence without a persisted source-event anchor.',
      checks: { source_event: false, evidence_bundle: true, raw_event: hasRawEvent, detection: true },
      missing: ['source_event_id'],
      score: 3,
    };
  }

  if (hasRawEvent) {
    return {
      quality: 'synthetic',
      label: 'Synthetic context',
      claimable: false,
      benchmark_eligible: false,
      summary: 'Display context was reconstructed from raw alert payload; treat as partial evidence.',
      checks: { source_event: false, evidence_bundle: hasEvidence, raw_event: true, detection: hasDetection },
      missing: ['source_event_id', 'evidence'],
      score: 2,
    };
  }

  return {
    quality: 'missing',
    label: 'Missing evidence',
    claimable: false,
    benchmark_eligible: false,
    summary: 'Minimum alert evidence provenance is missing.',
    checks: { source_event: false, evidence_bundle: false, raw_event: false, detection: hasDetection },
    missing: ['source_event_id', 'evidence', 'raw_event'],
    score: 1,
  };
}

function evidenceCheckLabel(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function resolveModelPackageEvidence(alert: Alert): Record<string, unknown> {
  const evidence = asRecord(alert.evidence);
  const metadata = asRecord(alert.detectionMetadata);
  const rawEvent = resolveRawEvent(alert);
  const payload = asRecord(rawEvent.payload);
  const enrichment = asRecord((alert as Alert & { enrichment?: unknown }).enrichment);
  const scanResult = asRecord(firstPresent(
    metadata.scan_result,
    metadata.scanResult,
    evidence.scan_result,
    evidence.scanResult,
    payload.scan_result,
    payload.scanResult,
    enrichment.scan_result,
    enrichment.scanResult
  ));
  const modelGuard = asRecord(firstPresent(
    evidence.model_guard,
    evidence.modelGuard,
    metadata.model_guard,
    metadata.modelGuard,
    scanResult.model_guard,
    scanResult.modelGuard,
    enrichment.model_guard,
    enrichment.modelGuard
  ));
  const guardEvidence = asRecord(firstPresent(modelGuard.evidence, evidence.model_guard_evidence, evidence.modelGuardEvidence));
  const packageFindings = firstPresent(
    guardEvidence.package_findings,
    guardEvidence.packageFindings,
    modelGuard.package_findings,
    modelGuard.packageFindings,
    evidence.package_findings,
    evidence.packageFindings,
    metadata.package_findings,
    metadata.packageFindings,
    scanResult.package_findings,
    scanResult.packageFindings,
    enrichment.package_findings,
    enrichment.packageFindings
  );
  const externalScores = firstPresent(
    guardEvidence.external_model_scores,
    guardEvidence.externalModelScores,
    modelGuard.external_model_scores,
    modelGuard.externalModelScores,
    evidence.external_model_scores,
    evidence.externalModelScores,
    metadata.external_model_scores,
    metadata.externalModelScores,
    scanResult.external_model_scores,
    scanResult.externalModelScores,
    enrichment.external_model_scores,
    enrichment.externalModelScores
  );
  const modelConsensus = asRecord(firstPresent(
    guardEvidence.model_consensus,
    guardEvidence.modelConsensus,
    modelGuard.model_consensus,
    modelGuard.modelConsensus,
    evidence.model_consensus,
    evidence.modelConsensus,
    metadata.model_consensus,
    metadata.modelConsensus,
    scanResult.model_consensus,
    scanResult.modelConsensus,
    enrichment.model_consensus,
    enrichment.modelConsensus
  ));
  const packageFindingCount = Number(firstPresent(
    guardEvidence.package_findings_count,
    guardEvidence.packageFindingsCount,
    modelGuard.package_findings_count,
    modelGuard.packageFindingsCount,
    recordSize(packageFindings)
  ));
  const externalScoreCount = Number(firstPresent(
    guardEvidence.external_model_scores_count,
    guardEvidence.externalModelScoresCount,
    modelGuard.external_model_scores_count,
    modelGuard.externalModelScoresCount,
    recordSize(externalScores)
  ));
  const enforcement = firstText(modelGuard.enforcement, guardEvidence.enforcement, metadata.enforcement);
  const status = firstText(modelGuard.status, guardEvidence.status, metadata.status);

  return {
    model_guard: modelGuard,
    package_findings: packageFindings,
    package_findings_count: Number.isFinite(packageFindingCount) ? packageFindingCount : 0,
    package_scanner: firstText(guardEvidence.package_scanner, modelGuard.package_scanner, packageFindingCount > 0 ? 'collected' : 'not_collected'),
    external_model_scores: externalScores,
    external_model_scores_count: Number.isFinite(externalScoreCount) ? externalScoreCount : 0,
    model_consensus: modelConsensus,
    model_consensus_state: firstText(
      guardEvidence.model_consensus_state,
      modelGuard.model_consensus_state,
      modelConsensus.state,
      modelConsensus.verdict,
      Object.keys(modelConsensus).length ? 'collected' : 'not_collected'
    ),
    decision: firstText(modelGuard.decision, guardEvidence.decision, metadata.decision, 'unknown'),
    enforcement: enforcement || 'not_collected',
    status: status || 'not_collected',
    action: firstText(modelGuard.action, guardEvidence.action, 'none'),
    enforcement_note: firstText(
      guardEvidence.enforcement_note,
      modelGuard.enforcement_note,
      modelGuard.fp_rationale,
      evidence.reason,
      metadata.reason,
      enforcement === 'decision_only' ? 'Decision-only: no endpoint or loader enforcement was attempted.' : ''
    ),
  };
}

function normalizeOperationalQueueState(value: unknown): OperationalQueueState {
  const normalized = asText(value).trim().toLowerCase();
  if (['triaged', 'needs_evidence', 'ready_for_response', 'false_positive_candidate'].includes(normalized)) {
    return normalized as OperationalQueueState;
  }
  return 'needs_triage';
}

function operationalQueueLabel(state: OperationalQueueState): string {
  switch (state) {
    case 'needs_evidence': return 'Needs evidence';
    case 'ready_for_response': return 'Ready for response';
    case 'false_positive_candidate': return 'False positive candidate';
    case 'triaged': return 'Triaged';
    case 'needs_triage':
    default: return 'Needs triage';
  }
}

function operationalQueueStyle(state: OperationalQueueState): React.CSSProperties {
  switch (state) {
    case 'needs_evidence':
      return { color: 'var(--crit)', borderColor: 'color-mix(in srgb, var(--crit) 48%, transparent)', backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)' };
    case 'ready_for_response':
      return { color: 'var(--high)', borderColor: 'color-mix(in srgb, var(--high) 48%, transparent)', backgroundColor: 'color-mix(in srgb, var(--high) 10%, transparent)' };
    case 'false_positive_candidate':
      return { color: 'var(--muted)', borderColor: 'var(--border)', backgroundColor: 'var(--surface-2)' };
    case 'triaged':
      return { color: 'var(--low)', borderColor: 'color-mix(in srgb, var(--low) 44%, transparent)', backgroundColor: 'color-mix(in srgb, var(--low) 10%, transparent)' };
    case 'needs_triage':
    default:
      return { color: 'var(--med)', borderColor: 'color-mix(in srgb, var(--med) 48%, transparent)', backgroundColor: 'color-mix(in srgb, var(--med) 10%, transparent)' };
  }
}

function resolveOperationalTriageState(alert: Alert, evidenceQuality: AlertEvidenceQuality, responseActions: ResponseActionRecord[]): OperationalTriageState {
  const alertRecord = asRecord(alert);
  const fromServer = asRecord(alertRecord.operationalTriage || alertRecord.operational_triage);
  if (fromServer.state) {
    const state = normalizeOperationalQueueState(fromServer.state);
    return {
      state,
      label: asText(fromServer.label, operationalQueueLabel(state)),
      priority: asText(fromServer.priority),
      nextAction: asText(firstPresent(fromServer.nextAction, fromServer.next_action)),
      reasons: asStringArray(fromServer.reasons),
      evidenceQuality: asText(firstPresent(fromServer.evidenceQuality, fromServer.evidence_quality)),
      claimable: typeof fromServer.claimable === 'boolean' ? fromServer.claimable : undefined,
      terminal: typeof fromServer.terminal === 'boolean' ? fromServer.terminal : undefined,
    };
  }

  const status = alert.status;
  const metadata = asRecord(alert.detectionMetadata);
  const score = Number(alert.threatScore || 0);
  const normalizedScore = score <= 1 ? score * 100 : score;
  const quality = evidenceQuality.quality;
  const missing = evidenceQuality.missing || [];
  const weakEvidence = ['missing', 'synthetic'].includes(quality) || evidenceQuality.claimable === false;
  const fpReview = Boolean(metadata.fp_review_required ?? metadata.fpReviewRequired);
  const claimStrength = asText(firstPresent(metadata.alert_claim_strength, metadata.alertClaimStrength));

  if (status === 'false_positive') {
    return {
      state: 'false_positive_candidate',
      label: operationalQueueLabel('false_positive_candidate'),
      priority: 'review',
      nextAction: 'Confirm tuning or preserve suppression evidence.',
      reasons: ['marked false positive'],
      evidenceQuality: quality,
      claimable: evidenceQuality.claimable,
      terminal: true,
    };
  }

  if ((fpReview || ['triage_only', 'weak'].includes(claimStrength)) && weakEvidence && normalizedScore < 50) {
    return {
      state: 'false_positive_candidate',
      label: operationalQueueLabel('false_positive_candidate'),
      priority: 'review',
      nextAction: 'Review telemetry before response.',
      reasons: [fpReview ? 'fp review required' : '', claimStrength ? `claim strength ${claimStrength}` : '', ...missing].filter(Boolean),
      evidenceQuality: quality,
      claimable: evidenceQuality.claimable,
    };
  }

  if (weakEvidence && ['new', 'open', 'acknowledged', 'triaged', 'investigating'].includes(status)) {
    return {
      state: 'needs_evidence',
      label: operationalQueueLabel('needs_evidence'),
      priority: 'high',
      nextAction: 'Collect missing telemetry before containment.',
      reasons: [`evidence quality ${quality}`, ...missing].slice(0, 5),
      evidenceQuality: quality,
      claimable: evidenceQuality.claimable,
    };
  }

  if (['triaged', 'investigating'].includes(status) || responseActions.length > 0) {
    return {
      state: 'ready_for_response',
      label: operationalQueueLabel('ready_for_response'),
      priority: 'high',
      nextAction: responseActions.length ? 'Review response status and rollback options.' : 'Review containment or remediation.',
      reasons: responseActions.length ? [`${responseActions.length} response action records`] : ['triage started'],
      evidenceQuality: quality,
      claimable: evidenceQuality.claimable,
    };
  }

  if (['resolved', 'closed'].includes(status)) {
    return {
      state: 'triaged',
      label: operationalQueueLabel('triaged'),
      priority: 'normal',
      nextAction: 'No queue action required.',
      reasons: ['alert closed'],
      evidenceQuality: quality,
      claimable: evidenceQuality.claimable,
      terminal: true,
    };
  }

  return {
    state: 'needs_triage',
    label: operationalQueueLabel('needs_triage'),
    priority: 'normal',
    nextAction: 'Assign an analyst and validate evidence.',
    reasons: ['new or unassigned alert'],
    evidenceQuality: quality,
    claimable: evidenceQuality.claimable,
  };
}

function resolveTriageAgent(alert: Alert): AlertTriageAgentContract | null {
  const record = asRecord(alert)
  const direct = asRecord(record.triageAgent || record.triage_agent)
  if (Object.keys(direct).length > 0) return direct as AlertTriageAgentContract

  const enrichment = asRecord(record.enrichment)
  const triage = asRecord(enrichment.triage)
  return Object.keys(triage).length > 0 ? triage as AlertTriageAgentContract : null
}

function triageAgentEvidenceStrength(triage: AlertTriageAgentContract | null): Record<string, unknown> {
  return asRecord(triage?.evidenceStrength || triage?.evidence_strength)
}

function triageAgentFp(triage: AlertTriageAgentContract | null): Record<string, unknown> {
  return asRecord(triage?.falsePositiveLikelihood || triage?.false_positive_likelihood)
}

function triageAgentPivots(triage: AlertTriageAgentContract | null): Array<Record<string, unknown>> {
  return asRecordArray(triage?.recommendedPivots || triage?.recommended_pivots)
}

function triageAgentGaps(triage: AlertTriageAgentContract | null): Array<Record<string, unknown>> {
  return asRecordArray(triage?.gaps)
}

function resolveTelemetryQuality(alert: Alert): Record<string, unknown> {
  const metadata = asRecord(alert.detectionMetadata);
  return asRecord(firstPresent(
    metadata.telemetry_quality,
    metadata.telemetryQuality,
    asRecord(alert.evidence).telemetry_quality,
    asRecord(alert.evidence).telemetryQuality
  ));
}

function telemetryQualityStyle(level: string): { color: string; bg: string; border: string } {
  switch (level) {
    case 'excellent':
    case 'good':
      return {
        color: 'var(--low)',
        bg: 'color-mix(in srgb, var(--low) 11%, transparent)',
        border: 'color-mix(in srgb, var(--low) 26%, transparent)',
      };
    case 'partial':
      return {
        color: 'var(--med)',
        bg: 'color-mix(in srgb, var(--med) 13%, transparent)',
        border: 'color-mix(in srgb, var(--med) 30%, transparent)',
      };
    default:
      return {
        color: 'var(--crit)',
        bg: 'color-mix(in srgb, var(--crit) 11%, transparent)',
        border: 'color-mix(in srgb, var(--crit) 28%, transparent)',
      };
  }
}

function buildRawEventTimeline(alert: Alert): TimelineEntry[] {
  const alertRecord = asRecord(alert);
  const rawEvent = resolveRawEvent(alert);
  const nestedPayload = asRecord(rawEvent.payload);
  const payload = Object.keys(nestedPayload).length > 0 ? nestedPayload : rawEvent;
  const payloadEvidence = asRecord(payload.evidence);
  const evidence = mergeRecords(payloadEvidence, alert.evidence);
  const snapshot = mergeRecords(
    rawEvent.evidence_snapshot,
    rawEvent.evidenceSnapshot,
    payload.evidence_snapshot,
    payload.evidenceSnapshot,
    payloadEvidence.evidence_snapshot,
    payloadEvidence.evidenceSnapshot,
    evidence.evidence_snapshot,
    evidence.evidenceSnapshot
  );

  if (Object.keys(rawEvent).length === 0 && Object.keys(payload).length === 0 && Object.keys(evidence).length === 0) return [];

  const risk = asRecord(payload.risk);
  const app = mergeRecords(payload.app, evidence.app, snapshot.app);
  const device = mergeRecords(payload.device, evidence.device, snapshot.device);
  const policy = mergeRecords(payload.policy, evidence.policy, snapshot.policy);
  const thresholds = mergeRecords(risk.thresholds, policy.thresholds, snapshot.thresholds);
  const network = mergeRecords(payload.network, evidence.network, snapshot.network);
  const inputProvenance = mergeRecords(
    payloadEvidence.input_provenance,
    evidence.input_provenance,
    snapshot.input_provenance,
    asRecord(asRecord(evidence.app_guard).input_provenance)
  );
  const appName = firstPresent(app.display_name, app.package_or_bundle_id) as string | undefined;
  const packageId = firstText(app.package_or_bundle_id, app.bundle_id, app.packageName);
  const deviceName = firstPresent(device.device_id, device.model) as string | undefined;
  const decision = firstPresent(risk.decision, policy.decision, policy.action) as string | undefined;
  const score = firstPresent(risk.score);
  const eventType = asText(firstPresent(rawEvent.event_type, payload.event_type, alertRecord.ruleName), 'alert_event');
  const timestamp = asText(firstPresent(payload.timestamp, rawEvent.timestamp, alert.createdAt), 'timestamp not captured');
  const reasons = compactTextList([
    ...asTextArray(risk.reasons),
    ...asTextArray(payload.reasons),
    ...asTextArray(evidence.reasons),
  ]);
  const signalSources = [
    payloadEvidence.active_signals,
    evidence.active_signals,
    snapshot.active_signals,
    snapshot.signals,
    payload.signals,
  ];
  const signals = compactTextList(signalSources.flatMap(source => asUnknownArray(source).map(describeSignal)));
  const iocs = normalizeSnapshotIOCs(payload.iocs, payloadEvidence.iocs, evidence.iocs, snapshot.iocs);
  const networkDetails = compactTextList([
    firstText(network.proxy_detected, network.proxyDetected) ? `proxy ${humanizeValue(firstPresent(network.proxy_detected, network.proxyDetected))}` : null,
    firstText(network.resolver) ? `resolver ${firstText(network.resolver)}` : null,
    firstText(network.request_count, network.requestCount) ? `${firstText(network.request_count, network.requestCount)} requests` : null,
    firstText(network.remote_ip, network.remoteIp, network.ip) ? `remote ${firstText(network.remote_ip, network.remoteIp, network.ip)}` : null,
    firstText(network.domain, network.host, network.sni) ? `domain ${firstText(network.domain, network.host, network.sni)}` : null,
  ]);

  const eventBase = {
    severity: asText(firstPresent(payload.severity, alert.severity), alert.severity),
    timestamp,
    detections: [],
  };
  const makeEntry = (
    suffix: string,
    type: string,
    summaryText: string,
    details: Array<{ label: string; value: unknown }>,
    extraPayload: Record<string, unknown> = {}
  ): TimelineEntry => ({
    id: `${asText(firstPresent(rawEvent.mobile_event_id, payload.event_id, alert.id), 'alert')}-${suffix}`,
    event_type: type,
    summary: summaryText,
    icon: 'activity',
    payload: {
      ...payload,
      ...extraPayload,
      timeline_details: details
        .map(detail => ({ label: detail.label, value: asText(detail.value).trim() }))
        .filter(detail => detail.value),
      synthetic: true,
      synthetic_reason: 'No persisted source_event_id/event_ids were linked to this alert',
    },
    ...eventBase,
  });

  const summary = [
    alert.description || alert.title,
    appName ? `App: ${appName}` : null,
    deviceName ? `Device: ${deviceName}` : null,
    decision ? `Decision: ${decision}` : null,
    score !== undefined && score !== null ? `Risk score: ${score}` : null,
  ].filter(Boolean).join(' | ');

  const entries: TimelineEntry[] = [
    makeEntry('alert-created', 'alert', summary || alert.title, [
      { label: 'rule', value: firstPresent(alertRecord.ruleName, alert.evidence?.detection?.rule_name, alert.title) },
      { label: 'type', value: eventType },
      { label: 'technique', value: asStringArray(alert.mitreTechniques).slice(0, 3).join(', ') },
      { label: 'source event', value: alert.sourceEventId || 'not linked' },
    ]),
  ];

  if (eventType || signals.length || reasons.length) {
    entries.push(makeEntry('signal', 'detection', humanizeValue(eventType, 'Mobile security signal'), [
      { label: 'signals', value: signals.slice(0, 4).join(' | ') },
      { label: 'reasons', value: reasons.slice(0, 4).map(reason => humanizeValue(reason)).join(' | ') },
      { label: 'collector', value: firstPresent(payload.collector, evidence.collector, rawEvent.collector) },
    ], { signals, reasons }));
  }

  if (decision || score !== undefined || Object.keys(thresholds).length > 0) {
    entries.push(makeEntry('policy-decision', 'registry', `Policy decision: ${humanizeValue(decision, 'not recorded')}`, [
      { label: 'decision', value: decision },
      { label: 'risk score', value: score },
      { label: 'alert threshold', value: firstPresent(thresholds.alert, thresholds.alert_threshold, thresholds.alertThreshold) },
      { label: 'block threshold', value: firstPresent(thresholds.block, thresholds.block_threshold, thresholds.blockThreshold) },
      { label: 'policy', value: firstPresent(policy.id, policy.policy_id, policy.name) },
    ], { policy, thresholds }));
  }

  if (appName || packageId || deviceName) {
    entries.push(makeEntry('mobile-context', 'process', 'Mobile app and device context', [
      { label: 'app', value: appName },
      { label: 'package', value: packageId },
      { label: 'device', value: deviceName },
      { label: 'model', value: firstPresent(device.model, device.device_model, device.deviceModel) },
      { label: 'platform', value: firstPresent(device.platform, payload.platform, alertRecord.platform) },
      { label: 'os', value: firstPresent(device.os_version, device.osVersion, device.os) },
    ], { app, device }));
  }

  if (networkDetails.length || iocs.length) {
    entries.push(makeEntry('network-ioc-context', 'network', 'Network and public-safe indicator context', [
      { label: 'network', value: networkDetails.join(' | ') },
      { label: 'IOCs', value: iocs.slice(0, 5).map(ioc => `${ioc.type}:${ioc.value}`).join(' | ') },
    ], { network, iocs }));
  }

  if (Object.keys(inputProvenance).length > 0) {
    entries.push(makeEntry('input-provenance', 'registry', 'Input provenance aggregate context', [
      { label: 'schema', value: inputProvenance.schema },
      { label: 'workflow', value: inputProvenance.workflow_class },
      { label: 'sample bucket', value: inputProvenance.sample_count_bucket },
      { label: 'privacy', value: inputProvenance.privacy_mode },
      { label: 'policy', value: inputProvenance.policy_mode },
      { label: 'boundary', value: inputProvenance.claim_boundary || 'observe-only aggregate input metadata; not enforcement' },
    ], { input_provenance: inputProvenance }));
  }

  return entries;
}

function timelineDetailRows(entry: TimelineEntry): Array<{ label: string; value: string }> {
  const explicit = asUnknownArray(entry.payload?.timeline_details)
    .map(item => {
      const record = asRecord(item);
      const label = firstText(record.label, record.key, record.name);
      const value = firstText(record.value, record.text, record.description);
      return label && value ? { label, value } : null;
    })
    .filter(Boolean) as Array<{ label: string; value: string }>;

  if (explicit.length > 0) return explicit.slice(0, 8);

  const payload = asRecord(entry.payload);
  return [
    { label: 'process', value: firstText(payload.process_name, payload.name, payload.image, payload.image_path) },
    { label: 'pid', value: firstText(entry.pid, payload.pid, payload.process_id) },
    { label: 'remote', value: firstText(payload.remote_ip, payload.remoteIp, payload.dst_ip, payload.domain, payload.query) },
    { label: 'port', value: firstText(payload.remote_port, payload.remotePort, payload.dst_port, payload.port) },
    { label: 'file', value: firstText(payload.path, payload.file_path, payload.target_path) },
    { label: 'command', value: firstText(payload.command_line, payload.cmdline, payload.command) },
  ].filter(detail => detail.value).slice(0, 6);
}

function humanizeValue(value: unknown, fallback = 'not recorded'): string {
  const text = asText(value).trim();
  return text ? text.replace(/_/g, ' ') : fallback;
}

function firstText(...values: unknown[]): string {
  return asText(firstPresent(...values)).trim();
}

function nestedRecord(source: Record<string, unknown>, key: string): Record<string, unknown> {
  return asRecord(source[key]);
}

function mergeRecords(...records: unknown[]): Record<string, unknown> {
  return records.reduce<Record<string, unknown>>((acc, record) => ({ ...acc, ...asRecord(record) }), {});
}

function compactTextList(values: unknown[]): string[] {
  return Array.from(new Set(values.map(value => asText(value).trim()).filter(Boolean)));
}

function asUnknownArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function dedupeIocList(iocs: IOC[]): IOC[] {
  const seen = new Set<string>();
  return iocs.filter(ioc => {
    if (!ioc.value) return false;
    const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function describeSignal(value: unknown): string {
  if (typeof value === 'string') return value;

  const signal = asRecord(value);
  const label = firstText(signal.label, signal.name, signal.type, signal.code, signal.key);
  const detail = firstText(signal.value, signal.status, signal.decision, signal.reason, signal.description, signal.observed);
  const severity = firstText(signal.severity, signal.confidence);

  return compactTextList([
    label,
    detail && label ? detail : null,
    severity && !detail?.includes(severity) ? severity : null,
  ]).join(': ');
}

function truthyFinding(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  const text = asText(value).trim().toLowerCase();
  return Boolean(text && !['false', 'none', 'no', '0', 'unknown', 'not_detected', 'not detected'].includes(text));
}

function summarizeFlags(record: Record<string, unknown>, labels: Record<string, string>): string[] {
  return Object.entries(labels)
    .map(([key, label]) => truthyFinding(record[key]) ? `${label}: ${humanizeValue(record[key], 'observed')}` : null)
    .filter(Boolean) as string[];
}

function summarizeInputProvenance(record: Record<string, unknown>): string[] {
  if (Object.keys(record).length === 0) return [];

  return compactTextList([
    firstText(record.workflow_class) ? `workflow ${humanizeValue(record.workflow_class)}` : null,
    firstText(record.sample_count_bucket) ? `samples ${humanizeValue(record.sample_count_bucket)}` : null,
    firstText(record.privacy_mode) ? `privacy ${humanizeValue(record.privacy_mode)}` : null,
    firstText(record.policy_mode) ? `policy ${humanizeValue(record.policy_mode)}` : null,
    firstText(record.assistive_technology_context)
      ? `assistive tech ${humanizeValue(record.assistive_technology_context)}`
      : null,
  ]);
}

function normalizeSnapshotIOCs(...sources: unknown[]): IOC[] {
  return sources.flatMap(source => {
    if (!Array.isArray(source)) return [];

    return source.map(item => {
      const record = asRecord(item);
      const value = asText(firstPresent(record.value, record.indicator, record.package_or_bundle_id, record.packageName, record.domain, record.url, record.ip)).trim();
      if (!value) return null;

      return {
        type: normalizeIocType(firstPresent(record.type, record.kind)),
        value,
        source: asText(firstPresent(record.source, record.origin), 'App Guard'),
        confidence: typeof record.confidence === 'number' ? record.confidence : undefined,
        tlp: asText(record.tlp).trim() || undefined,
        blockable: typeof record.blockable === 'boolean' ? record.blockable : undefined,
        redacted: typeof record.redacted === 'boolean' ? record.redacted : undefined,
      } satisfies IOC;
    }).filter(Boolean) as IOC[];
  });
}

function extractMobileContext(alert: Alert) {
  const rawEvent = resolveRawEvent(alert);
  const rawPayload = asRecord(rawEvent.payload);
  const payload = Object.keys(rawPayload).length > 0 ? rawPayload : rawEvent;
  const payloadEvidence = asRecord(payload.evidence);
  const evidence = mergeRecords(payloadEvidence, alert.evidence);
  const evidenceAppGuard = asRecord(firstPresent(evidence.app_guard, evidence.appGuard));
  const payloadAppGuard = asRecord(firstPresent(
    payload.app_guard,
    payload.appGuard,
    payloadEvidence.app_guard,
    payloadEvidence.appGuard
  ));
  const alertRecord = asRecord(alert);
  const appGuard = asRecord(firstPresent(alertRecord.app_guard, alertRecord.appGuard, evidenceAppGuard, payloadAppGuard));
  const appGuardEvidence = asRecord(appGuard.evidence);
  const protectedApp = asRecord(firstPresent(appGuard.protected_app, appGuard.protectedApp));
  const snapshot = mergeRecords(
    rawEvent.evidence_snapshot,
    rawEvent.evidenceSnapshot,
    payload.evidence_snapshot,
    payload.evidenceSnapshot,
    payloadEvidence.evidence_snapshot,
    payloadEvidence.evidenceSnapshot,
    evidence.evidence_snapshot,
    evidence.evidenceSnapshot,
    appGuard.evidence_snapshot,
    appGuard.evidenceSnapshot,
    appGuardEvidence.evidence_snapshot,
    appGuardEvidence.evidenceSnapshot,
    asRecord(appGuard.evidence).snapshot
  );
  const decisionTrace = asRecord(firstPresent(evidence.decision_trace, evidence.decisionTrace));
  const app = {
    ...nestedRecord(payload, 'app'),
    ...nestedRecord(evidence, 'app'),
    ...nestedRecord(appGuard, 'app'),
    ...nestedRecord(snapshot, 'app'),
    ...protectedApp,
  };
  const device = {
    ...nestedRecord(payload, 'device'),
    ...nestedRecord(evidence, 'device'),
    ...nestedRecord(appGuard, 'device'),
    ...nestedRecord(snapshot, 'device'),
  };
  const risk = {
    ...nestedRecord(payload, 'risk'),
    ...nestedRecord(evidence, 'risk'),
    ...nestedRecord(appGuard, 'risk'),
  };
  const riskPolicy = mergeRecords(
    nestedRecord(risk, 'policy'),
    nestedRecord(payload, 'policy'),
    nestedRecord(evidence, 'policy'),
    nestedRecord(appGuard, 'policy')
  );
  const session = {
    ...nestedRecord(payload, 'session'),
    ...nestedRecord(evidence, 'session'),
    ...nestedRecord(appGuard, 'session'),
  };
  const tamper = {
    ...nestedRecord(nestedRecord(payload, 'evidence'), 'tamper'),
    ...nestedRecord(evidence, 'tamper'),
    ...nestedRecord(nestedRecord(appGuard, 'evidence'), 'tamper'),
  };
  const metadata = asRecord(alert.detectionMetadata);
  const policy = asRecord(firstPresent(
    alert.detectionMetadata?.policy_decision,
    alert.detectionMetadata?.policyDecision,
    metadata.policy,
    evidence.policy,
    snapshot.policy,
    snapshot.decision,
    decisionTrace,
    risk.policy_decision,
    riskPolicy
  ));
  const thresholds = mergeRecords(snapshot.thresholds, policy.thresholds, risk.thresholds, riskPolicy.thresholds);
  const integrity = mergeRecords(
    snapshot.integrity,
    snapshot.device_integrity,
    snapshot.deviceIntegrity,
    evidence.integrity,
    appGuard.integrity,
    device.integrity
  );
  const runtime = mergeRecords(
    snapshot.runtime_hardening,
    snapshot.runtimeHardening,
    snapshot.runtime,
    evidence.runtime,
    evidence.runtime_hardening,
    evidence.runtimeHardening,
    appGuard.runtime
  );
  const nativeHardening = mergeRecords(
    snapshot.native_hardening,
    snapshot.nativeHardening,
    evidence.native_hardening,
    evidence.nativeHardening,
    appGuard.native_hardening,
    appGuard.nativeHardening
  );
  const networkHints = mergeRecords(
    snapshot.network,
    snapshot.network_hints,
    snapshot.networkHints,
    evidence.network_hints,
    evidence.networkHints,
    appGuard.network,
    payload.network_hints,
    payload.networkHints
  );
  const inputProvenance = mergeRecords(
    payloadEvidence.input_provenance,
    evidence.input_provenance,
    snapshot.input_provenance,
    appGuardEvidence.input_provenance
  );
  const eventType = firstText(payload.event_type, rawEvent.event_type, appGuard.event_type, alert.detectionMetadata?.rule_name);
  const eventTypeLower = eventType.toLowerCase();
  const source = asText(firstPresent(alert.source, payload.source, payload.schema, rawEvent.schema, appGuard.schema)).toLowerCase();
  const alertText = JSON.stringify({
    title: alert.title,
    description: alert.description,
    source,
    rule: alert.detectionMetadata?.rule_name,
  }).toLowerCase();
  const evidenceText = JSON.stringify({ payload, evidence, appGuard }).toLowerCase();
  const isMobileAppGuard = Boolean(
    source.includes('mobile') ||
    source.includes('app_guard') ||
    source.includes('rasp') ||
    eventTypeLower.includes('tamper') ||
    eventTypeLower.includes('policy_decision') ||
    eventTypeLower.includes('app_guard') ||
    alertText.includes('app guard') ||
    alertText.includes('app_guard') ||
    alertText.includes('webview') ||
    Object.keys(snapshot).length > 0 && evidenceText.includes('app_guard') ||
    evidenceText.includes('package_or_bundle_id') ||
    evidenceText.includes('protected-webview') ||
    evidenceText.includes('embedded_webview')
  );

  if (!isMobileAppGuard) return null;

  const appName = firstText(app.display_name, app.app_name, app.name, payload.app_name, appGuard.app_name);
  const appId = firstText(app.package_or_bundle_id, app.bundle_id, app.package_name, app.app_bundle_id, payload.package_or_bundle_id, payload.app_bundle_id);
  const deviceId = firstText(device.device_id, device.id, payload.device_id, appGuard.device_id);
  const deviceName = firstText(device.name, device.model, payload.device_name, payload.deviceName, appGuard.device_name, appGuard.deviceName, deviceId);
  const deviceDetail = [firstText(device.manufacturer), firstText(device.model), firstText(payload.platform), firstText(device.os_version)]
    .filter(Boolean)
    .join(' ');
  const decision = firstText(risk.decision, policy.action, policy.decision, decisionTrace.decision, payload.decision);
  const mode = firstText(policy.mode, decisionTrace.mode, risk.mode, payload.mode);
  const workflow = firstText(session.workflow, payload.workflow);
  const reasons = [
    ...asTextArray(risk.reasons),
    ...asTextArray(policy.reasons),
    ...asTextArray(decisionTrace.reasons),
    ...asTextArray(appGuard.reasons),
    ...asTextArray(evidence.evidence_gaps).map(gap => asText(asRecord(gap).code || gap)),
    ...asTextArray(evidence.missing_reasons),
    ...asTextArray(evidence.missingEvidenceReasons),
    ...asTextArray(evidence.missing_evidence_reasons),
  ];
  const signals = compactTextList([
    ...asUnknownArray(payload.signals).map(describeSignal),
    ...asUnknownArray(appGuard.signals).map(describeSignal),
    ...asUnknownArray(evidence.active_signals).map(describeSignal),
    ...asUnknownArray(evidence.activeSignals).map(describeSignal),
    ...asUnknownArray(snapshot.signals).map(describeSignal),
    ...asUnknownArray(snapshot.evidence_signals).map(describeSignal),
    ...asUnknownArray(snapshot.findings).map(describeSignal),
    ...asUnknownArray(risk.signals).map(describeSignal),
    ...asUnknownArray(tamper.signals).map(describeSignal),
  ]);
  const tamperSignal = [
    firstText(tamper.surface),
    firstText(tamper.indicator),
    firstText(tamper.hooked_api),
    firstText(tamper.collector, nestedRecord(payload, 'evidence').collector, asRecord(appGuard.runtime).type, appGuard.collector),
  ].filter(Boolean).join(' / ');
  const integritySignals = compactTextList([
    ...summarizeFlags(integrity, {
      rooted: 'Rooted',
      jailbreak: 'Jailbreak',
      jailbroken: 'Jailbreak',
      emulator: 'Emulator',
      debugger_attached: 'Debugger',
      debug_enabled: 'Debug enabled',
      frida_detected: 'Frida',
      magisk_detected: 'Magisk',
      play_integrity: 'Play Integrity',
      app_attest: 'App Attest',
      cert_pinning: 'Cert pinning',
    }),
    firstText(integrity.verdict, integrity.status, integrity.integrity_level),
  ]);
  const hardeningSignals = compactTextList([
    firstText(runtime.type, runtime.collector, runtime.engine),
    ...summarizeFlags(runtime, {
      native_bridge: 'Native bridge',
      embedded_webview: 'Embedded WebView',
      protected_webview: 'Protected WebView',
      hook_framework_seen: 'Hook framework',
      debugger_attached: 'Debugger',
      ptrace_denied: 'Ptrace denied',
      hook_detected: 'Runtime hook',
      instrumentation_detected: 'Instrumentation',
    }),
    ...summarizeFlags(nativeHardening, {
      enabled: 'Native hardening',
      anti_debug: 'Anti debug',
      ptrace_guard: 'Ptrace guard',
      certificate_pinning_state: 'Certificate pinning',
      code_signature: 'Code signature',
      self_check: 'Self check',
      hook_detection: 'Hook detection',
      library_integrity: 'Library integrity',
    }),
  ]);
  const networkSignals = compactTextList([
    ...summarizeFlags(networkHints, {
      proxy_detected: 'Proxy',
      proxy_configured: 'Proxy',
      vpn_active: 'VPN',
      vpn_or_tunnel_detected: 'VPN/tunnel',
      doh_detected: 'DoH',
      doh_enabled: 'DoH',
      tls_intercept_detected: 'TLS intercept',
      tls_interception_suspected: 'TLS intercept',
      cert_pinning_bypass: 'Cert pinning bypass',
    }),
    firstText(networkHints.proxy_host, networkHints.proxyHost),
    firstText(networkHints.resolver, networkHints.dns_resolver, networkHints.dnsResolver),
    firstText(networkHints.dns_mode, networkHints.dnsMode),
    firstText(networkHints.remote_host, networkHints.remoteHost, networkHints.host, networkHints.domain),
  ]);
  const inputProvenanceSignals = summarizeInputProvenance(inputProvenance);
  const snapshotIocs = normalizeSnapshotIOCs(snapshot.iocs, snapshot.indicators, evidence.iocs);
  if (appId) snapshotIocs.push({ type: 'package', value: appId, source: 'Protected app' });
  const alertThreshold = firstText(policy.alert_threshold, policy.alertThreshold, thresholds.alert, thresholds.alert_threshold);
  const blockThreshold = firstText(policy.block_threshold, policy.blockThreshold, thresholds.block, thresholds.block_threshold);
  const riskThreshold = firstText(thresholds.risk, thresholds.score, thresholds.min_score, thresholds.minimum_score);

  return {
    eventType,
    technique: firstText(alert.mitreTechniques?.[0], alert.evidence?.detection?.mitre_attack_id),
    appName: appName || appId,
    appId,
    appVersion: firstText(app.version, app.version_name, app.versionName, app.build, app.build_number),
    deviceName,
    deviceDetail,
    platform: firstText(device.platform, payload.platform, device.os, device.os_name),
    decision,
    mode,
    workflow,
    tamperSignal,
    riskScore: firstPresent(risk.score, payload.risk_score),
    reasons: Array.from(new Set(reasons)),
    signals,
    policyName: firstText(policy.policy_name, policy.policyName, policy.name, policy.id),
    thresholds: {
      alert: alertThreshold,
      block: blockThreshold,
      risk: riskThreshold,
    },
    integritySignals,
    hardeningSignals,
    networkSignals,
    inputProvenanceSignals,
    inputProvenanceBoundary: firstText(inputProvenance.claim_boundary),
    iocs: dedupeIocList(snapshotIocs),
  };
}

function resolveAppGuardReadiness(alert: Alert): Record<string, unknown> {
  const rawEvent = resolveRawEvent(alert);
  const payload = asRecord(rawEvent.payload);
  const payloadEvidence = asRecord(payload.evidence);
  const evidence = mergeRecords(payloadEvidence, alert.evidence);
  const alertRecord = asRecord(alert);
  const appGuard = asRecord(firstPresent(
    alertRecord.app_guard,
    alertRecord.appGuard,
    evidence.app_guard,
    evidence.appGuard,
    payload.app_guard,
    payload.appGuard,
    payloadEvidence.app_guard,
    payloadEvidence.appGuard
  ));

  return asRecord(firstPresent(
    appGuard.readiness,
    asRecord(appGuard.evidence).readiness,
    evidence.app_guard_readiness,
    evidence.appGuardReadiness,
    evidence.readiness,
    payload.app_guard_readiness,
    payload.appGuardReadiness,
    payloadEvidence.app_guard_readiness,
    payloadEvidence.appGuardReadiness,
    payloadEvidence.readiness,
    payload.readiness
  ));
}

function findNestedBoolean(source: unknown, keys: string[]): boolean | null {
  if (source == null || typeof source !== 'object') return null;
  const record = asRecord(source);

  for (const key of keys) {
    const direct = booleanFromUnknown(record[key]);
    if (direct !== null) return direct;
  }

  for (const value of Object.values(record)) {
    const nested = findNestedBoolean(value, keys);
    if (nested !== null) return nested;
  }

  return null;
}

function buildOperatorReadinessItems({
  alert,
  mobileContext,
  evidenceQuality,
  responseActions,
  mobileCommandTarget,
}: {
  alert: Alert;
  mobileContext: ReturnType<typeof extractMobileContext>;
  evidenceQuality: AlertEvidenceQuality;
  responseActions: ResponseActionRecord[];
  mobileCommandTarget: MobileAlertCommandTarget | null;
}): OperatorReadinessItem[] {
  const readiness = resolveAppGuardReadiness(alert);
  const readinessGaps = asStringArray(readiness.gaps);
  const appGuardStatus = asText(readiness.status).trim().toLowerCase();
  const protectedAppRegistered = booleanFromUnknown(readiness.protected_app_registered);
  const evidenceRecord = asRecord(alert.evidence);
  const telemetryQuality = resolveTelemetryQuality(alert);
  const claimStrength = firstText(
    telemetryQuality.alert_claim_strength,
    asRecord(alert.detectionMetadata).alert_claim_strength,
    asRecord(alert.detectionMetadata).alertClaimStrength
  );
  const fpReviewRequired = booleanFromUnknown(firstPresent(
    telemetryQuality.fp_review_required,
    asRecord(alert.detectionMetadata).fp_review_required,
    asRecord(alert.detectionMetadata).fpReviewRequired
  ));
  const rawEvent = resolveRawEvent(alert);
  const searchRoot = { alert, evidence: evidenceRecord, rawEvent };
  const liveSigned = findNestedBoolean(searchRoot, [
    'live_signed_ingestion_ok',
    'signed_ingestion_ok',
    'signature_verified',
    'hmac_verified',
    'signed_ingestion',
  ]);
  const antiReplay = findNestedBoolean(searchRoot, [
    'live_anti_replay_ok',
    'anti_replay_ok',
    'duplicate_rejected',
    'replay_rejected',
  ]);
  const hasResponseHistory = responseActions.length > 0;
  const responseFailures = responseActions.filter(action => ['failed', 'timeout'].includes(action.status)).length;
  const responsePending = responseActions.filter(action => ['pending', 'executing'].includes(action.status)).length;

  const items: OperatorReadinessItem[] = [
    claimStrength ? {
      label: 'Claim strength',
      status: claimStrength === 'evidence_supported' && fpReviewRequired !== true ? 'supported' : claimStrength === 'triage_only' ? 'gap' : 'degraded',
      value: humanizeValue(claimStrength),
      detail: fpReviewRequired === true
        ? 'Telemetry gaps require false-positive review before treating this alert as strong proof.'
        : claimStrength === 'evidence_supported'
          ? 'Required telemetry is present for a stronger investigation claim; this is not production readiness evidence.'
          : 'Evidence is partial; validate surrounding telemetry before escalation.',
    } : null,
    {
      label: 'Evidence boundary',
      status: evidenceQuality.claimable ? 'supported' : 'gap',
      value: evidenceQuality.label,
      detail: evidenceQuality.claimable
        ? 'Alert has enough provenance for operator triage; benchmark and production eligibility are shown separately.'
        : `Not claimable yet: ${(evidenceQuality.missing || ['source evidence']).slice(0, 3).join(', ')}`,
    },
    {
      label: 'Response audit',
      status: hasResponseHistory ? (responseFailures > 0 ? 'degraded' : 'supported') : 'gap',
      value: hasResponseHistory
        ? `${responseActions.length} recorded / ${responsePending} pending / ${responseFailures} failed`
        : 'No action recorded',
      detail: hasResponseHistory
        ? 'Operator can inspect queued/executed response history for this alert.'
        : 'No audited response command is attached to this alert yet.',
    },
  ].filter(Boolean) as OperatorReadinessItem[];

  if (mobileContext) {
    items.unshift({
      label: 'App Guard telemetry',
      status: appGuardStatus === 'ready' || readinessGaps.length === 0 && Object.keys(readiness).length > 0 ? 'supported' : 'degraded',
      value: appGuardStatus ? `Payload status: ${humanizeValue(appGuardStatus)}` : 'Event context only',
      detail: readinessGaps.length
        ? `Gaps: ${readinessGaps.slice(0, 3).join(', ')}`
        : 'Runtime event context is present, but this does not prove binary shielding, no-code hardening, or release readiness.',
    });
    items.push({
      label: 'Protected app',
      status: protectedAppRegistered === true ? 'supported' : 'gap',
      value: protectedAppRegistered === true ? 'Registered' : 'Not proven here',
      detail: protectedAppRegistered === true
        ? 'Protected-app registration is present in the payload; treat as scoped alert evidence.'
        : 'Alert payload does not prove protected-app registration.',
    });
    items.push({
      label: 'Signed ingestion',
      status: liveSigned === true ? 'supported' : 'gap',
      value: liveSigned === true ? 'Live proof present' : 'Live proof missing',
      detail: liveSigned === true
        ? 'Signed ingestion evidence is attached to this alert context.'
        : 'Local HMAC fixtures are not enough for a release claim without live signed ingestion evidence.',
    });
    items.push({
      label: 'Anti-replay',
      status: antiReplay === true ? 'supported' : 'gap',
      value: antiReplay === true ? 'Duplicate rejection proven' : 'Not proven here',
      detail: antiReplay === true
        ? 'Replay/duplicate rejection evidence is attached to this alert context.'
        : 'A release claim still needs live anti-replay proof.',
    });
    items.push({
      label: 'Mobile command target',
      status: mobileCommandTarget?.commandDeviceId ? 'supported' : 'degraded',
      value: mobileCommandTarget?.commandDeviceId ? 'v2 target linked' : 'Target unresolved',
      detail: mobileCommandTarget?.commandDeviceId
        ? 'Mobile response commands can use the v2 command device link.'
        : 'Mobile response commands may be blocked until endpoint identity resolves.',
    });
  }

  return items;
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

  const byPid = new Map<number, ProcessChainNode & { pid: number; ppid?: number }>();
  candidates.forEach(process => {
    const pid = parsePid(process.pid);
    if (pid === undefined) return;

    const ppid = parsePid(process.ppid);
    const existing = byPid.get(pid);
    byPid.set(pid, {
      ...process,
      ...existing,
      ...Object.fromEntries(
        Object.entries(process).filter(([, value]) => value !== undefined && value !== null && value !== '')
      ),
      pid,
      ppid,
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
  const [triageAgentOverride, setTriageAgentOverride] = useState<AlertTriageAgentContract | null>(null);
  const [triageAgentStatus, setTriageAgentStatus] = useState<'idle' | 'running' | 'success' | 'error'>('idle');
  const [triageAgentError, setTriageAgentError] = useState<string | null>(null);
  const [mobileCommandTarget, setMobileCommandTarget] = useState<MobileAlertCommandTarget | null>(null);
  const [mobileCommandLoading, setMobileCommandLoading] = useState<string | null>(null);
  const [mobileCommandDraft, setMobileCommandDraft] = useState<MobileAlertCommandDraft | null>(null);

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

  const buildStorylineHref = useCallback(() => {
    const params = new URLSearchParams();
    params.set('returnTab', activeTab);

    if (typeof window !== 'undefined') {
      const returnParams = new URLSearchParams(window.location.search);
      returnParams.set('tab', activeTab);
      const returnQuery = returnParams.toString();
      if (returnQuery) params.set('returnQuery', returnQuery);
    }

    const query = params.toString();
    return `/app/storyline/${alert.id}${query ? `?${query}` : ''}`;
  }, [activeTab, alert.id]);

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

  useEffect(() => {
    let cancelled = false;

    async function loadMobileCommandTarget() {
      if (!agent?.id) {
        setMobileCommandTarget(null);
        return;
      }

      try {
        const response = await fetch(`/api/v1/mobile/agents/${agent.id}/overview`, {
          credentials: 'include',
        });

        if (!response.ok) {
          if (!cancelled) setMobileCommandTarget(null);
          return;
        }

        const payload = await response.json();
        const data = payload?.data || {};

        if (!cancelled) {
          setMobileCommandTarget({
            commandDeviceId: resolveMobileCommandDeviceId(data),
            legacyDeviceId: data.device?.id || null,
          });
        }
      } catch (err) {
        logger.log('Mobile command target unavailable for alert', err);
        if (!cancelled) setMobileCommandTarget(null);
      }
    }

    loadMobileCommandTarget();

    return () => {
      cancelled = true;
    };
  }, [agent?.id]);

  // Extract IOCs from evidence
  const extractIOCs = (): IOC[] => {
    const normalized = (alert as Alert & { iocs?: IOC[] }).iocs || [];
    if (normalized.length > 0) {
      return normalized;
    }

    const iocs: IOC[] = [];
    const evidence = alert.evidence || {};

    if (Array.isArray((evidence as Record<string, unknown>).iocs)) {
      ((evidence as Record<string, unknown>).iocs as Array<Record<string, unknown>>).forEach((ioc) => {
        const value = asText(ioc.value).trim();
        const type = normalizeIocType(ioc.type);
        if (value) iocs.push({ type, value, source: asText(ioc.source, 'Evidence') });
      });
    }

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
    normalizeNetworkEvidence(evidence).forEach((net) => {
      const type = asText(net.type).toLowerCase();
      const value = asText(
        firstPresent(
          net.value,
          net.remote_ip,
          net.remoteIp,
          net.dst_ip,
          net.dstIp,
          net.destination_ip,
          net.destinationIp,
          net.domain,
          net.host,
          net.hostname,
          net.url
        )
      ).trim();
      if (!value) return;

      if (type === 'ip' || net.remote_ip || net.remoteIp || net.dst_ip || net.destination_ip) {
        iocs.push({ type: 'ip', value, source: asText(net.direction, 'Network') });
      } else if (type === 'domain' || net.domain || net.host || net.hostname) {
        iocs.push({ type: 'domain', value, source: 'DNS' });
      } else if (type === 'url' || net.url) {
        iocs.push({ type: 'url', value, source: 'HTTP' });
      }
    });

    // Extract process hash if available
    if (evidence.process?.sha256) {
      iocs.push({ type: 'hash', value: evidence.process.sha256, source: 'Process' });
    }

    return dedupeIOCs(iocs);
  };

  const dedupeIOCs = (iocs: IOC[]): IOC[] => {
    return dedupeIocList(iocs);
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

  const handleTriageRecompute = async () => {
    setTriageAgentStatus('running');
    setTriageAgentError(null);

    try {
      const res = await fetch(`/api/v1/alerts/${alert.id}/triage/recompute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'include',
        body: JSON.stringify({}),
      });
      const payload = await res.json().catch(() => ({})) as TriageRecomputeResponse & { error?: string };

      if (!res.ok) {
        const message = payload.error || `Triage recompute failed with HTTP ${res.status}`;
        setTriageAgentStatus('error');
        setTriageAgentError(message);
        setActionNotice({ type: 'error', message });
        return;
      }

      const triage = payload.data?.triageAgent || payload.data?.triage_agent;
      if (triage) setTriageAgentOverride(triage);
      setTriageAgentStatus('success');
      setActionNotice({ type: 'success', message: 'Triage agent contract recomputed.' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Triage recompute failed';
      setTriageAgentStatus('error');
      setTriageAgentError(message);
      setActionNotice({ type: 'error', message });
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
    if (action === 'quarantine' && !resolveFilePath(alert.evidence)) {
      setActionNotice({ type: 'error', message: 'Cannot quarantine file: this alert has no file path.' });
      return;
    }

    setIsUpdating(true);
    try {
      const payload: Record<string, any> = { agent_id: agent.id };
      if (action === 'kill' && alert.evidence?.process?.pid) {
        payload.pid = alert.evidence.process.pid;
      } else if (action === 'quarantine') {
        payload.path = resolveFilePath(alert.evidence);
      } else if (action === 'scan') {
        const path = resolveFilePath(alert.evidence);
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

  const createMobileAlertCommandDraft = (command: string): MobileAlertCommandDraft | null => {
    const evidence = asRecord(alert.evidence);
    const app = asRecord(evidence.app);
    const dns = asRecord(evidence.dns);
    const network = normalizeNetworkEvidence(alert.evidence)[0] || {};
    const firstDomain = extractIOCs().find(ioc => ioc.type === 'domain')?.value;

    if (command === 'managed_shell') {
      return {
        command,
        label: 'Mobile Managed Shell',
        fieldLabel: 'Managed shell command',
        value: 'posture',
        placeholder: 'posture',
        payloadKind: 'command',
      };
    }

    if (command === 'block_domain') {
      const suggestedDomain = asText(firstPresent(dns.query, dns.query_name, network.domain, firstDomain));
      return {
        command,
        label: 'Mobile Block Domain',
        fieldLabel: 'Domain to block on mobile DNS policy',
        value: suggestedDomain,
        placeholder: 'example.com',
        payloadKind: 'domain',
      };
    }

    if (command === 'inspect_package') {
      const suggestedPackage = asText(firstPresent(app.package_name, app.package_or_bundle_id, app.bundle_id));
      return {
        command,
        label: 'Mobile Inspect Package',
        fieldLabel: 'Package or bundle id to inspect',
        value: suggestedPackage,
        placeholder: 'com.example.app',
        payloadKind: 'package',
      };
    }

    return null;
  };

  const buildMobileAlertCommandPayload = (draft: MobileAlertCommandDraft): Record<string, unknown> | null => {
    const value = draft.value.trim();
    if (!value) return null;
    if (draft.payloadKind === 'domain') {
      return { domain: value, alert_id: alert.id, reason: `Blocked from alert ${alert.id}`, source: 'alert_detail' };
    }
    if (draft.payloadKind === 'package') {
      return { package_name: value, bundle_id: value, alert_id: alert.id, source: 'alert_detail' };
    }
    return { command: value, alert_id: alert.id, source: 'alert_detail' };
  };

  const mobileAlertCommandPreview = mobileCommandDraft
    ? JSON.stringify(buildMobileAlertCommandPayload(mobileCommandDraft) || { [mobileCommandDraft.payloadKind]: '<required>', alert_id: alert.id, source: 'alert_detail' })
    : '';

  const queueMobileAlertCommand = async (command: string, payload: Record<string, unknown>) => {
    const commandDeviceId = mobileCommandTarget?.commandDeviceId;
    if (!commandDeviceId) {
      setActionNotice({
        type: 'error',
        message: mobileCommandTarget?.legacyDeviceId
          ? 'Mobile command history requires a v2 command device link for this endpoint.'
          : 'Mobile command target is not available for this alert endpoint.',
      });
      return;
    }

    setMobileCommandLoading(command);
    try {
      const response = await fetch('/api/v1/mobile/v2/commands', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'include',
        body: JSON.stringify({
          device_id: commandDeviceId,
          command_type: command,
          payload,
        }),
      });

      if (!response.ok) {
        setActionNotice({ type: 'error', message: `Mobile ${command} failed with HTTP ${response.status}` });
        return;
      }

      setMobileCommandDraft(null);
      setActionNotice({ type: 'success', message: `Mobile ${command} command queued for this alert.` });
      router.reload();
    } catch (err) {
      logger.error(`Mobile response command ${command} error:`, err);
      setActionNotice({ type: 'error', message: err instanceof Error ? err.message : `Mobile ${command} command failed` });
    } finally {
      setMobileCommandLoading(null);
    }
  };

  const handleMobileAlertCommand = async (command: string) => {
    const draft = createMobileAlertCommandDraft(command);
    if (draft) {
      setMobileCommandDraft(draft);
      setActionNotice({
        type: 'info',
        message: `${draft.label} requires review before queueing. Confirm the target and payload below.`,
      });
      return;
    }
    await queueMobileAlertCommand(command, { alert_id: alert.id, source: 'alert_detail' });
  };

  const submitMobileAlertCommandDraft = () => {
    if (!mobileCommandDraft) return;
    const payload = buildMobileAlertCommandPayload(mobileCommandDraft);
    if (!payload) {
      setActionNotice({ type: 'error', message: `${mobileCommandDraft.fieldLabel} is required before queueing ${mobileCommandDraft.label}.` });
      return;
    }
    queueMobileAlertCommand(mobileCommandDraft.command, payload);
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

  const alertEvidenceRecord = asRecord(alert.evidence);
  const alertMetadataRecord = asRecord(alert.detectionMetadata);
  const modelObservations = collectModelObservations(
    alertMetadataRecord,
    alertEvidenceRecord,
    resolveRawEvent(alert),
    ...relatedEvents.map(event => event.payload),
  );
  const modelPackageEvidence = resolveModelPackageEvidence(alert);
  const rawPolicyDecision = asRecord(firstPresent(
    alert.detectionMetadata?.policy_decision,
    alert.detectionMetadata?.policyDecision,
    alertMetadataRecord.policy,
    alertEvidenceRecord.policy,
    alertEvidenceRecord.decision_trace,
    alertEvidenceRecord.decisionTrace,
    alertEvidenceRecord.risk
  ));
  const policyDecision = Object.keys(rawPolicyDecision).length > 0
    ? {
        action: asText(firstPresent(rawPolicyDecision.action, rawPolicyDecision.decision)),
        reason: asText(firstPresent(rawPolicyDecision.reason, asTextArray(rawPolicyDecision.reasons).join(', '))),
        policy_name: asText(firstPresent(
          'policy_name' in rawPolicyDecision ? rawPolicyDecision.policy_name : undefined,
          rawPolicyDecision.policyName,
          rawPolicyDecision.name,
          rawPolicyDecision.id
        )),
        mode: asText(rawPolicyDecision.mode),
        alert_threshold: asText(firstPresent(
          'alert_threshold' in rawPolicyDecision ? rawPolicyDecision.alert_threshold : undefined,
          rawPolicyDecision.alertThreshold,
          asRecord(rawPolicyDecision.thresholds).alert
        )),
        block_threshold: asText(firstPresent(
          'block_threshold' in rawPolicyDecision ? rawPolicyDecision.block_threshold : undefined,
          rawPolicyDecision.blockThreshold,
          asRecord(rawPolicyDecision.thresholds).block
        )),
      }
    : null;
  const policyActionLabel = humanizeValue(policyDecision?.action);
  const mobileContext = extractMobileContext(alert);
  const alertIocs = dedupeIocList([...extractIOCs(), ...(mobileContext?.iocs || [])]);
  const displayTimeline = timeline.length > 0 ? timeline : buildRawEventTimeline(alert);
  const displayProcessChain = buildFallbackProcessChain(alert, relatedEvents, displayTimeline);
  const evidenceQuality = resolveEvidenceQuality(alert);
  const evidenceQualityStyle = EVIDENCE_QUALITY_STYLES[evidenceQuality.quality] || EVIDENCE_QUALITY_STYLES.missing;
  const EvidenceQualityIcon = evidenceQualityStyle.icon;
  const operationalTriage = resolveOperationalTriageState(alert, evidenceQuality, responseActions);
  const operationalStyle = operationalQueueStyle(operationalTriage.state);
  const triageAgent = triageAgentOverride || resolveTriageAgent(alert);
  const triageEvidenceStrength = triageAgentEvidenceStrength(triageAgent);
  const triageFp = triageAgentFp(triageAgent);
  const triagePivots = triageAgentPivots(triageAgent);
  const triageGaps = triageAgentGaps(triageAgent);
  const triageGeneratedAt = firstText(triageAgent?.generatedAt, triageAgent?.generated_at, 'not recorded');
  const parityTestAlert = isParityTestAlert(alert);
  const evidenceChecks = Object.entries(evidenceQuality.checks || {});
  const evidenceMissing = evidenceQuality.missing || [];
  const investigationContext = evidenceQuality.investigationContext || evidenceQuality.investigation_context;
  const telemetryQuality = resolveTelemetryQuality(alert);
  const telemetryLevel = firstText(telemetryQuality.level, 'not scored');
  const telemetryScore = firstText(telemetryQuality.score);
  const telemetryCategory = firstText(telemetryQuality.category, 'unknown');
  const telemetryMissing = asStringArray(telemetryQuality.missing);
  const telemetryPresent = asStringArray(telemetryQuality.present);
  const telemetryRequired = asStringArray(telemetryQuality.required_fields);
  const telemetryReady = booleanFromUnknown(telemetryQuality.correlation_ready);
  const telemetryStyle = telemetryQualityStyle(telemetryLevel);
  const operatorReadinessItems = buildOperatorReadinessItems({
    alert,
    mobileContext,
    evidenceQuality,
    responseActions,
    mobileCommandTarget,
  });
  const networkEvidence = normalizeNetworkEvidence(alert.evidence);
  const alertFilePath = resolveFilePath(alert.evidence);
  const primaryProcess = alert.evidence?.process || displayProcessChain.find(p => p.is_malicious) || displayProcessChain[displayProcessChain.length - 1];
  const primaryProcessLevel = primaryProcess && 'level' in primaryProcess && typeof primaryProcess.level === 'number' ? primaryProcess.level : 99;
  const parentProcess = displayProcessChain.find(p => primaryProcess?.pid && p.pid !== primaryProcess.pid && p.level < primaryProcessLevel);
  const primaryNetwork = networkEvidence[0] || relatedEvents.find(e => e.event_type?.includes('network'))?.payload;
  const firstFileHash = alert.evidence?.file_hashes?.[0];
  const primaryFile = firstFileHash
    ? { ...firstFileHash, path: firstFileHash.path || alertFilePath }
    : alertFilePath
      ? { path: alertFilePath, sha256: alert.evidence?.process?.sha256 }
      : null;
  const ruleName = alert.evidence?.detection?.rule_name || alert.detectionMetadata?.rule_name || 'Detection rule';
  const alertMitreTechniques = asStringArray(alert.mitreTechniques);
  const attestationState = proofData?.attested ? 'Anchored on Solana' : proofError ? 'Proof lookup failed' : 'Waiting for attestation';
  const completedResponses = responseActions.filter(a => a.status === 'success').length;
  const failedResponses = responseActions.filter(a => ['failed', 'timeout'].includes(a.status)).length;
  const pendingResponses = responseActions.filter(a => ['pending', 'executing'].includes(a.status)).length;
  const storySteps: StoryStep[] = [
    {
      id: 'process',
      label: mobileContext && !primaryProcess?.pid ? 'App Guard' : 'Process',
      title: primaryProcess?.name || mobileContext?.appName || 'Process context unavailable',
      detail: primaryProcess?.pid
        ? `PID ${primaryProcess.pid}${parentProcess?.name ? ` spawned from ${parentProcess.name}` : ''}`
        : mobileContext
          ? [
              mobileContext.eventType ? humanizeValue(mobileContext.eventType) : null,
              mobileContext.deviceName ? `device ${mobileContext.deviceName}` : null,
              mobileContext.decision ? `decision ${humanizeValue(mobileContext.decision)}` : null,
            ].filter(Boolean).join(' | ') || 'Mobile/App Guard context attached to this alert'
          : 'No PID was attached to this alert',
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
      label: alertIocs.length > 0 || !mobileContext ? 'IOCs' : 'Signal',
      title: alertIocs.length
        ? `${alertIocs.length} indicator${alertIocs.length === 1 ? '' : 's'} extracted`
        : mobileContext?.tamperSignal || mobileContext?.eventType || 'No public-safe indicators extracted yet',
      detail: alertIocs.length
        ? alertIocs.slice(0, 3).map(i => i.type).join(' / ')
        : mobileContext?.reasons.length
          ? mobileContext.reasons.slice(0, 3).map(reason => humanizeValue(reason)).join(' / ')
          : 'No public-safe indicators extracted yet',
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
    ...networkEvidence,
    ...(alert.evidence?.file_hashes || []),
    ...(alert.evidence?.registry || []),
  ].filter(Boolean).length;
  const graphNodeCount = graphData?.nodes.length || 0;
  const graphEdgeCount = graphData?.edges.length || 0;
  const existingInvestigationStory = alert.investigationStory || alert.investigation_story;
  const evidenceConfidence = firstPresent(
    alert.evidence?.detection?.confidence,
    alert.detectionMetadata?.confidence
  ) as number | undefined;
  const fallbackMissingData = [
    !primaryProcess?.pid && !mobileContext ? { field: 'process', reason: 'No PID or process lineage was linked to this alert.', source: 'alert evidence' } : null,
    !primaryFile ? { field: 'binary', reason: 'No file path or hash was linked to this alert.', source: 'alert evidence' } : null,
    !primaryNetwork && !mobileContext?.networkSignals.length ? { field: 'network', reason: 'No network peer, DNS, or URL evidence was linked.', source: 'alert evidence' } : null,
    !networkEvidence.some(item => firstText(item.dns_question_name, item.dnsQuestionName, item.query, item.domain, item.host, item.hostname)) ? { field: 'dns', reason: 'No DNS question or domain evidence was linked.', source: 'alert evidence' } : null,
    !networkEvidence.some(item => firstText(item.tls_sni, item.tlsSni, item.server_name, item.serverName, item.sni)) ? { field: 'tls/sni', reason: 'No TLS SNI or certificate subject evidence was linked.', source: 'alert evidence' } : null,
    mobileContext && !mobileContext.appId ? { field: 'package', reason: 'No package or bundle identifier was linked to this alert.', source: 'App Guard evidence' } : null,
    { field: 'latency/ttd', reason: 'Latency and time-to-detect values were not supplied; hunt templates include placeholders.', source: 'normalizer' },
    ...evidenceMissing.map(field => ({ field: 'release evidence', reason: `${field} is missing`, source: evidenceQuality.label })),
  ].filter(Boolean) as Array<{ field: string; reason: string; source?: string }>;
  const networkPivots = networkEvidence.flatMap((item): AlertInvestigationPivot[] => {
    const remoteIp = firstText(item.remote_ip, item.remoteIp, item.dst_ip, item.dstIp, item.destination_ip, item.destinationIp);
    const remotePort = firstText(item.remote_port, item.remotePort, item.destination_port, item.destinationPort, item.dst_port, item.dstPort, item.port);
    const dnsName = firstText(item.dns_question_name, item.dnsQuestionName, item.query, item.domain, item.host, item.hostname);
    const sni = firstText(item.tls_sni, item.tlsSni, item.server_name, item.serverName, item.sni);

    const pivots: Array<AlertInvestigationPivot | null> = [
      remoteIp ? {
        type: 'remote_endpoint',
        label: remotePort ? `${remoteIp}:${remotePort}` : remoteIp,
        value: remotePort ? `${remoteIp}:${remotePort}` : remoteIp,
        remote_ip: remoteIp,
        remoteIp,
        remote_port: remotePort || undefined,
        remotePort: remotePort || undefined,
        source: 'network evidence',
        confidence: evidenceConfidence,
      } : null,
      dnsName ? { type: 'dns', label: 'dns', value: dnsName, source: 'DNS evidence', confidence: evidenceConfidence } : null,
      sni ? { type: 'tls_sni', label: 'TLS SNI', value: sni, source: 'TLS evidence', confidence: evidenceConfidence } : null,
    ];
    return pivots.filter((pivot): pivot is AlertInvestigationPivot => Boolean(pivot?.value));
  });
  const fallbackPivotCandidates: Array<AlertInvestigationPivot | null> = [
    primaryProcess?.pid ? { type: 'process', label: primaryProcess.name || `PID ${primaryProcess.pid}`, value: String(primaryProcess.pid), source: 'process evidence', confidence: evidenceConfidence } : null,
    primaryFile ? { type: primaryFile.sha256 ? 'hash' : 'binary', label: basename(asText(primaryFile.path)) || 'binary', value: asText(firstPresent(primaryFile.sha256, primaryFile.path)), source: 'file evidence', confidence: evidenceConfidence } : null,
    ...networkPivots,
    mobileContext?.appId ? { type: 'package', label: mobileContext.appName || 'package', value: mobileContext.appId, source: 'App Guard evidence', confidence: evidenceConfidence } : null,
    ...alertIocs.slice(0, 4).map((ioc): AlertInvestigationPivot => ({ type: ioc.type, label: ioc.type, value: ioc.value, source: ioc.source, confidence: ioc.confidence })),
  ];
  const fallbackPivots = fallbackPivotCandidates.filter((pivot): pivot is AlertInvestigationPivot => Boolean(pivot?.value));
  const baseInvestigationStory: AlertInvestigationStory = existingInvestigationStory || {
    summary: mobileContext
      ? `${mobileContext.appName || 'Mobile app'} alert normalized from App Guard evidence.`
      : alert.description || alert.title,
    confidence: evidenceConfidence,
    source: evidenceQuality.label,
    pivots: fallbackPivots,
    tree: [
      mobileContext ? {
        id: mobileContext.appId || mobileContext.appName || 'mobile-app',
        kind: 'package',
        label: mobileContext.appName || mobileContext.appId || 'Protected app',
        detail: mobileContext.deviceName || mobileContext.decision || undefined,
        source: 'App Guard evidence',
        confidence: evidenceConfidence,
      } : null,
      primaryProcess ? {
        id: String(primaryProcess.pid || primaryProcess.name),
        kind: 'process',
        label: primaryProcess.name || `PID ${primaryProcess.pid}`,
        detail: primaryProcess.cmdline || primaryProcess.path,
        source: 'process evidence',
        confidence: evidenceConfidence,
        children: [
          primaryFile ? {
            id: asText(firstPresent(primaryFile.sha256, primaryFile.path), 'binary'),
            kind: 'binary',
            label: basename(asText(primaryFile.path)) || primaryProcess.name || 'binary',
            detail: asText(firstPresent(primaryFile.sha256, primaryFile.path)),
            source: 'file evidence',
            confidence: evidenceConfidence,
          } : null,
          primaryNetwork ? {
            id: asText(firstPresent(primaryNetwork.remote_ip, primaryNetwork.remoteIp, primaryNetwork.dst_ip, primaryNetwork.domain, primaryNetwork.host, primaryNetwork.value), 'network'),
            kind: 'network',
            label: asText(firstPresent(primaryNetwork.domain, primaryNetwork.host, primaryNetwork.remote_ip, primaryNetwork.value), 'network endpoint'),
            detail: asText(firstPresent(primaryNetwork.port, primaryNetwork.remote_port, primaryNetwork.direction)),
            source: 'network evidence',
            confidence: evidenceConfidence,
          } : null,
        ].filter(Boolean) as AlertInvestigationStory['tree'],
      } : null,
    ].filter(Boolean) as AlertInvestigationStory['tree'],
    missing_data: fallbackMissingData,
    missingData: fallbackMissingData,
  };
  const investigationStory = enrichInvestigationStory(baseInvestigationStory);
  const huntTemplates = investigationStory.huntQueries || investigationStory.hunt_queries || [];
  const huntTemplateQueries = huntTemplates
    .map(query => asText(query.query).trim())
    .filter(Boolean);
  const huntRelatedQuery = [
    `alert.id:${quoteHuntValue(alert.id)}`,
    alert.sourceEventId ? `event.id:${quoteHuntValue(alert.sourceEventId)}` : null,
    ...huntTemplateQueries.slice(0, 3).map(query => `(${query})`),
  ].filter(Boolean).join(' or ');
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
      count: displayTimeline.length,
      description: 'Chronological attack narrative around the source alert',
      metric: displayTimeline.length > 0 ? `${displayTimeline.length} timeline events` : 'No timeline events',
      state: displayTimeline.length > 0 ? 'ready' : relatedEvents.length > 0 ? 'partial' : 'empty',
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
                    <span
                      className="badge-sentinel text-xs px-2 py-0.5 rounded-full font-semibold"
                      style={operationalStyle}
                      title={[operationalTriage.nextAction, ...operationalTriage.reasons].filter(Boolean).join(' | ')}
                    >
                      {operationalTriage.label}
                    </span>
                    {parityTestAlert && (
                      <span
                        className="badge-sentinel text-xs px-2 py-0.5 rounded-full font-semibold"
                        style={{
                          color: 'var(--muted)',
                          borderColor: 'var(--border)',
                          backgroundColor: 'var(--surface-2)',
                        }}
                        title="Synthetic mobile parity validation event, not a production security incident"
                      >
                        PARITY TEST
                      </span>
                    )}
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
                    {alertFilePath && (
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
                    {mobileCommandTarget?.commandDeviceId && (
                      <>
                        <MenuItem onSelect={() => handleMobileAlertCommand('collect_diagnostics')} disabled={isUpdating || mobileCommandLoading !== null}>
                          <>
                            <FileText size={14} />
                            Mobile Collect Diagnostics
                          </>
                        </MenuItem>
                        <MenuItem onSelect={() => handleMobileAlertCommand('managed_shell')} disabled={isUpdating || mobileCommandLoading !== null}>
                          <>
                            <Terminal size={14} />
                            Mobile Managed Shell
                          </>
                        </MenuItem>
                        <MenuItem onSelect={() => handleMobileAlertCommand('request_dns_vpn_consent')} disabled={isUpdating || mobileCommandLoading !== null}>
                          <>
                            <Wifi size={14} />
                            Mobile DNS VPN Consent
                          </>
                        </MenuItem>
                        <MenuItem onSelect={() => handleMobileAlertCommand('block_domain')} disabled={isUpdating || mobileCommandLoading !== null}>
                          <>
                            <Server size={14} />
                            Mobile Block Domain
                          </>
                        </MenuItem>
                        <MenuItem onSelect={() => handleMobileAlertCommand('inspect_package')} disabled={isUpdating || mobileCommandLoading !== null}>
                          <>
                            <Search size={14} />
                            Mobile Inspect Package
                          </>
                        </MenuItem>
                      </>
                    )}
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

        {mobileCommandDraft && (
          <div className="border-b px-4 py-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface)' }}>
            <div className="rounded-lg border p-3 space-y-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{mobileCommandDraft.label}</h3>
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                    Target {mobileCommandTarget?.commandDeviceId || 'unlinked'} / v2 mobile command / non-empty payload required.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileCommandDraft(null)}
                  className="text-xs px-2 py-1 rounded border"
                  style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}
                >
                  Cancel
                </button>
              </div>
              <label className="block text-xs font-medium" style={{ color: 'var(--muted)' }}>
                {mobileCommandDraft.fieldLabel}
              </label>
              <input
                value={mobileCommandDraft.value}
                onChange={event => setMobileCommandDraft({ ...mobileCommandDraft, value: event.target.value })}
                placeholder={mobileCommandDraft.placeholder}
                className="w-full rounded border px-3 py-2 text-sm"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface)', color: 'var(--fg)' }}
              />
              <div className="flex flex-wrap items-center justify-between gap-3">
                <code className="text-xs break-all" style={{ color: 'var(--muted)' }}>
                  {mobileAlertCommandPreview}
                </code>
                <button
                  type="button"
                  onClick={submitMobileAlertCommandDraft}
                  disabled={isUpdating || mobileCommandLoading !== null || !mobileCommandDraft.value.trim()}
                  className="inline-flex items-center gap-2 px-3 py-2 rounded text-sm border disabled:opacity-50"
                  style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}
                >
                  {mobileCommandLoading === mobileCommandDraft.command ? 'Sending...' : 'Send mobile command'}
                </button>
              </div>
            </div>
          </div>
        )}

        {modelObservations.length > 0 && (
          <div className="border-b px-4 py-3" style={{ borderColor: 'var(--border)' }}>
            <ModelObservationsPanel observations={modelObservations} />
          </div>
        )}

        {/* Evidence Quality */}
        <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 42%, var(--bg))', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-3">
            <div className="grid grid-cols-1 xl:grid-cols-[minmax(260px,1fr)_minmax(320px,1.5fr)_minmax(240px,1fr)_minmax(260px,1fr)] gap-3">
              <div
                className="rounded-lg p-3"
                style={{
                  backgroundColor: evidenceQualityStyle.bg,
                  border: `1px solid ${evidenceQualityStyle.border}`,
                  color: evidenceQualityStyle.color,
                }}
              >
                <div className="flex items-center gap-2">
                  <EvidenceQualityIcon size={16} />
                  <span className="text-sm font-semibold">{evidenceQuality.label}</span>
                </div>
                <p className="mt-2 text-xs leading-snug" style={{ color: 'var(--fg)' }}>
                  {evidenceQuality.summary}
                </p>
              </div>

              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Evidence checks</p>
                  <span
                    className="rounded-full px-2 py-0.5 text-xs font-medium"
                    style={{
                      backgroundColor: evidenceQuality.benchmark_eligible || evidenceQuality.benchmarkEligible
                        ? 'color-mix(in srgb, var(--low) 14%, transparent)'
                        : 'color-mix(in srgb, var(--high) 14%, transparent)',
                      color: evidenceQuality.benchmark_eligible || evidenceQuality.benchmarkEligible ? 'var(--low)' : 'var(--high)',
                    }}
                  >
                    {evidenceQuality.benchmark_eligible || evidenceQuality.benchmarkEligible ? 'Benchmark eligible' : 'Not benchmark eligible'}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {evidenceChecks.length > 0 ? evidenceChecks.map(([key, passed]) => (
                    <span
                      key={key}
                      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs"
                      style={{
                        backgroundColor: passed
                          ? 'color-mix(in srgb, var(--low) 12%, transparent)'
                          : 'color-mix(in srgb, var(--surface-3) 80%, transparent)',
                        color: passed ? 'var(--low)' : 'var(--muted)',
                      }}
                    >
                      {passed ? <Check size={11} /> : <X size={11} />}
                      {evidenceCheckLabel(key)}
                    </span>
                  )) : (
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>No evidence checks returned</span>
                  )}
                </div>
              </div>

              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
                <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Missing / FP context</p>
                <div className="mt-2 space-y-1 text-xs" style={{ color: 'var(--fg)' }}>
                  <div>
                    Missing: {evidenceMissing.length ? evidenceMissing.slice(0, 4).join(', ') : 'none recorded'}
                  </div>
                  <div>
                    Source event: <span className="font-mono">{alert.sourceEventId || 'not linked'}</span>
                  </div>
                  <div>
                    Claimable: {evidenceQuality.claimable ? 'yes' : 'no'}
                  </div>
                  <div>
                    Investigation context: <span className="font-medium">{investigationContext?.state || 'not reported'}</span>
                  </div>
                  {investigationContext && investigationContext.missing.length > 0 && (
                    <div>
                      Not collected: {investigationContext.missing.join(', ')}
                    </div>
                  )}
                </div>
              </div>

              <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: `1px solid ${operationalStyle.borderColor || 'var(--border)'}` }}>
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Operational triage</p>
                  <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={operationalStyle}>
                    {operationalTriage.priority || 'normal'}
                  </span>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <ClipboardList size={15} style={{ color: operationalStyle.color }} />
                  <span className="text-sm font-semibold" style={{ color: operationalStyle.color }}>
                    {operationalTriage.label}
                  </span>
                </div>
                <p className="mt-2 text-xs leading-snug" style={{ color: 'var(--fg)' }}>
                  {operationalTriage.nextAction || 'No operational next action recorded.'}
                </p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {operationalTriage.reasons.length ? operationalTriage.reasons.slice(0, 4).map(reason => (
                    <span key={reason} className="rounded px-1.5 py-0.5 text-[10px]" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                      {reason}
                    </span>
                  )) : (
                    <span className="text-[10px]" style={{ color: 'var(--muted)' }}>No queue reason returned</span>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-3 rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Triage agent</p>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                      {asText(triageAgent?.status, 'not computed')}
                    </span>
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-medium" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                      evidence {asText(triageEvidenceStrength.level, 'unknown')}
                    </span>
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-medium" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                      FP {asText(triageFp.label, 'unknown')}
                    </span>
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-medium" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                      confidence {typeof triageAgent?.confidence === 'number' ? `${Math.round(triageAgent.confidence * 100)}%` : 'unknown'}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleTriageRecompute}
                  disabled={triageAgentStatus === 'running'}
                  className="inline-flex items-center gap-2 rounded border px-2.5 py-1.5 text-xs disabled:opacity-50"
                  style={{ borderColor: 'var(--border)', color: 'var(--fg)', backgroundColor: 'var(--surface-alt)' }}
                >
                  <RefreshCw size={13} className={triageAgentStatus === 'running' ? 'animate-spin' : ''} />
                  Recompute
                </button>
              </div>

              {triageAgent ? (
                <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-[minmax(260px,1.2fr)_minmax(220px,0.8fr)_minmax(260px,1fr)]">
                  <div className="space-y-2">
                    <div>
                      <p className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Hypothesis</p>
                      <p className="mt-1 text-xs leading-relaxed" style={{ color: 'var(--fg)' }}>
                        {asText(triageAgent.hypothesis, 'No triage hypothesis generated yet.')}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Recommended response</p>
                      <p className="mt-1 text-xs leading-relaxed" style={{ color: 'var(--fg)' }}>
                        {firstText(triageAgent.recommendedResponse, triageAgent.recommended_response, 'No response recommendation recorded.')}
                      </p>
                    </div>
                    {asStringArray(triageFp.basis).length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {asStringArray(triageFp.basis).slice(0, 5).map(item => (
                          <span key={item} className="rounded px-1.5 py-0.5 text-[10px]" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                            {item}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div>
                    <p className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Evidence gaps</p>
                    <div className="mt-2 space-y-1.5">
                      {triageGaps.length > 0 ? triageGaps.slice(0, 6).map((gap, index) => (
                        <div key={`${asText(gap.source, 'gap')}-${asText(gap.field, String(index))}`} className="rounded border px-2 py-1.5 text-xs" style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}>
                          <span className="font-medium">{asText(gap.source, 'unknown')}</span>
                          <span style={{ color: 'var(--muted)' }}> / {asText(gap.field, 'field missing')}</span>
                          <span className="ml-2 text-[10px] uppercase" style={{ color: 'var(--muted)' }}>{asText(gap.severity, 'gap')}</span>
                        </div>
                      )) : (
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>No major gaps recorded.</p>
                      )}
                    </div>
                  </div>

                  <div>
                    <p className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Recommended pivots</p>
                    <div className="mt-2 space-y-1.5">
                      {triagePivots.length > 0 ? triagePivots.slice(0, 5).map((pivot, index) => (
                        <div key={`${asText(pivot.action, 'pivot')}-${index}`} className="rounded border px-2 py-1.5 text-xs" style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}>
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-medium">{asText(pivot.action, 'pivot')}</span>
                            <span className="text-[10px] uppercase" style={{ color: 'var(--muted)' }}>{asText(pivot.priority, 'normal')}</span>
                          </div>
                          <p className="mt-0.5 leading-snug" style={{ color: 'var(--muted)' }}>{asText(pivot.reason, 'No reason recorded.')}</p>
                        </div>
                      )) : (
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>No pivots recommended.</p>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="mt-3 text-xs" style={{ color: 'var(--muted)' }}>
                  No triage contract is stored for this alert yet. Recompute to generate the analyst-facing contract.
                </p>
              )}

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[10px]" style={{ color: 'var(--muted)' }}>
                <span>Generated: {triageGeneratedAt}</span>
                <span>Schema: {firstText(triageAgent?.schemaVersion, triageAgent?.schema_version, 'alert-triage/v1')}</span>
              </div>
              {triageAgentError && (
                <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{triageAgentError}</p>
              )}
            </div>
          </div>
        </div>

        {/* Operator Evidence Check */}
        <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 36%, var(--bg))', borderColor: 'var(--border)' }}>
          <div className="max-w-full mx-auto px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <ClipboardList size={16} style={{ color: 'var(--muted)' }} />
                <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Operator Evidence Check</h3>
              </div>
              <span className="text-xs" style={{ color: 'var(--muted)' }}>
                alert evidence / response audit / App Guard proof gaps
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2">
              {operatorReadinessItems.map(item => {
                const style = readinessToneStyle(item.status);
                return (
                  <div
                    key={item.label}
                    className="rounded-lg p-3"
                    style={{ backgroundColor: 'var(--surface)', border: `1px solid ${style.border}` }}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>{item.label}</p>
                      <span className="rounded-full px-2 py-0.5 text-[10px] font-medium uppercase" style={{ backgroundColor: style.bg, color: style.color }}>
                        {statusLabel(item.status)}
                      </span>
                    </div>
                    <p className="mt-2 text-xs font-medium truncate" style={{ color: style.color }} title={item.value}>
                      {item.value}
                    </p>
                    <p className="mt-1 text-[10px] leading-snug" style={{ color: 'var(--muted)' }}>
                      {item.detail}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

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
                  onClick={() => router.visit(buildStorylineHref())}
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
                  onClick={() => router.visit(`/app/hunt?q=${encodeURIComponent(huntRelatedQuery)}`)}
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
          mobileContext={mobileContext}
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

        <InvestigationCoveragePanel
          story={investigationStory}
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

        <div className="max-w-full mx-auto px-4 pb-4">
          <AutoInvestigationPanel alert={alert} />
        </div>

        {Object.keys(telemetryQuality).length > 0 && (
          <div className="max-w-full mx-auto px-4 pb-4">
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: telemetryStyle.bg,
                borderColor: telemetryStyle.border,
              }}
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <ShieldAlert size={16} style={{ color: telemetryStyle.color }} />
                    <span className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                      Telemetry quality: {humanizeValue(telemetryLevel)}
                    </span>
                    {telemetryScore && (
                      <span className="rounded-full px-2 py-0.5 text-xs font-semibold" style={{ backgroundColor: 'var(--surface)', color: telemetryStyle.color }}>
                        {telemetryScore}/100
                      </span>
                    )}
                    <span className="rounded-full px-2 py-0.5 text-xs" style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}>
                      {humanizeValue(telemetryCategory)}
                    </span>
                    <span className="rounded-full px-2 py-0.5 text-xs" style={{ backgroundColor: 'var(--surface)', color: telemetryReady === false ? 'var(--crit)' : 'var(--low)' }}>
                      {telemetryReady === false ? 'not correlation-ready' : 'correlation-ready'}
                    </span>
                  </div>
                  <p className="mt-2 text-sm" style={{ color: 'var(--fg-2)' }}>
                    {telemetryMissing.length > 0
                      ? `Missing evidence reduces FP confidence: ${telemetryMissing.slice(0, 6).join(', ')}.`
                      : 'Required telemetry fields are present for this alert category.'}
                  </p>
                </div>
                <div className="grid min-w-0 grid-cols-1 gap-2 text-xs sm:grid-cols-2 lg:w-[520px]">
                  <div className="rounded-md p-2" style={{ backgroundColor: 'var(--surface)' }}>
                    <div className="font-semibold" style={{ color: 'var(--fg)' }}>Present</div>
                    <div className="mt-1" style={{ color: 'var(--muted)', overflowWrap: 'anywhere' }}>
                      {telemetryPresent.length ? telemetryPresent.slice(0, 8).join(', ') : 'none recorded'}
                    </div>
                  </div>
                  <div className="rounded-md p-2" style={{ backgroundColor: 'var(--surface)' }}>
                    <div className="font-semibold" style={{ color: 'var(--fg)' }}>Required</div>
                    <div className="mt-1" style={{ color: 'var(--muted)', overflowWrap: 'anywhere' }}>
                      {telemetryRequired.length ? telemetryRequired.slice(0, 8).join(', ') : 'not declared'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

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
                {displayTimeline.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full" style={{ color: 'var(--muted)' }}>
                    <Clock size={48} className="mb-4 opacity-50" />
                    <p>No timeline events</p>
                  </div>
                ) : (
                  <div className="relative">
                    {/* Timeline line */}
                    <div className="absolute left-6 top-0 bottom-0 w-px" style={{ backgroundColor: 'var(--border)' }} />

                    <div className="space-y-4">
                      {displayTimeline.map((entry, idx) => {
                        const Icon = NODE_ICONS[entry.event_type as GraphNodeType] || Activity;
                        const dotColor = entry.severity === 'critical' ? 'var(--crit)' :
                          entry.severity === 'high' ? 'var(--high)' :
                          entry.severity === 'medium' ? 'var(--med)' : 'var(--accent)';
                        const correlation = getEventCorrelationDetails(entry, idx);
                        const detailRows = timelineDetailRows(entry);
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
                              {detailRows.length > 0 && (
                                <div
                                  className="mb-2 grid grid-cols-1 md:grid-cols-2 gap-2 rounded-lg p-3 text-xs"
                                  style={{
                                    backgroundColor: 'color-mix(in srgb, var(--bg) 58%, var(--surface))',
                                    border: '1px solid var(--border)'
                                  }}
                                >
                                  {detailRows.map((detail, detailIndex) => (
                                    <div key={`${detail.label}-${detailIndex}`} className="min-w-0">
                                      <div className="uppercase tracking-wide text-[10px]" style={{ color: 'var(--muted)' }}>
                                        {detail.label}
                                      </div>
                                      <div className="font-mono" style={{ color: 'var(--fg)', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                                        {detail.value}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
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
                <EvidencePanel
                  evidence={alert.evidence || {}}
                  quality={evidenceQuality}
                  contexts={[resolveRawEvent(alert), alert.detectionMetadata, modelPackageEvidence]}
                />
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

                <div
                  className="mb-4 rounded-lg border px-3 py-2 text-xs"
                  style={{
                    backgroundColor: 'color-mix(in srgb, var(--accent) 7%, var(--surface))',
                    borderColor: 'color-mix(in srgb, var(--accent) 22%, var(--border))',
                    color: 'var(--fg-2)'
                  }}
                >
                  Events shows correlated telemetry around this alert. Alert-to-alert matches are kept in Related Alerts.
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
                <div
                  className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-2"
                  style={{
                    backgroundColor: 'color-mix(in srgb, var(--high) 7%, var(--surface))',
                    borderColor: 'color-mix(in srgb, var(--high) 22%, var(--border))'
                  }}
                >
                  <div>
                    <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Related Alerts</h3>
                    <p className="mt-1 text-xs" style={{ color: 'var(--fg-2)' }}>
                      This tab lists other detections. Correlated raw telemetry lives in Events.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => selectTab('events')}
                    className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition-colors hover:brightness-110"
                    style={{
                      backgroundColor: 'var(--surface-alt, var(--surface-2))',
                      color: 'var(--fg)'
                    }}
                  >
                    <Activity size={14} />
                    Open Events
                  </button>
                </div>
                {relatedAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full" style={{ color: 'var(--muted)' }}>
                    <AlertTriangle size={48} className="mb-4 opacity-50" />
                    <p>No related alerts found</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {relatedAlerts.map(relAlert => {
                      const context = relatedAlertContext(relAlert);
                      return (
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
                            {context.length > 0 && (
                              <div className="flex flex-wrap gap-1.5 mt-3">
                                {context.slice(0, 8).map(item => (
                                  <span
                                    key={`${relAlert.id}-${item.label}-${item.value}`}
                                    className="text-[11px] px-2 py-1 rounded max-w-full"
                                    style={{
                                      backgroundColor: 'var(--surface-alt, var(--surface))',
                                      color: 'var(--fg-2)',
                                      overflowWrap: 'anywhere',
                                      wordBreak: 'break-word'
                                    }}
                                    title={`${item.label}: ${item.value}`}
                                  >
                                    <span style={{ color: 'var(--muted)' }}>{item.label}:</span> {item.value}
                                  </span>
                                ))}
                              </div>
                            )}
                            <div className="text-xs mt-2" style={{ color: 'var(--muted)' }}>
                              {relAlert.createdAt ? new Date(relAlert.createdAt).toLocaleString() : '—'}
                            </div>
                          </div>
                          <div className={cn('text-xl font-bold', getThreatScoreColor(relAlert.threatScore))}>
                            {displayThreatScore(relAlert.threatScore)}
                          </div>
                        </div>
                      </a>
                    )})}
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
            <InvestigationRunsSection alertId={alert.id} />

            {/* Proof of Incident Card */}
            <ProofCardSection
              proofData={proofData}
              isLoading={isLoadingProof}
              error={proofError}
              onCopyToClipboard={copyToClipboard}
              copiedField={copiedField}
            />

            {/* IOCs Section */}
            <IOCsSection
              iocs={alertIocs}
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
  mobileContext,
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
  mobileContext: ReturnType<typeof extractMobileContext>;
  responseActions: ResponseActionRecord[];
  proofData: ProofAttestation | null;
  graphStats?: NonNullable<AlertDetailPageProps['graphData']>['stats'];
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
  const modelPackageEvidence = resolveModelPackageEvidence(alert);
  const modelPackageFindingCount = Number(modelPackageEvidence.package_findings_count || 0);
  const modelExternalScoreCount = Number(modelPackageEvidence.external_model_scores_count || 0);
  const modelPackageScanner = asText(modelPackageEvidence.package_scanner, 'not_collected');
  const modelConsensusState = asText(modelPackageEvidence.model_consensus_state, 'not_collected');
  const modelGuardEnforcement = asText(modelPackageEvidence.enforcement, 'not_collected');
  const modelGuardStatus = asText(modelPackageEvidence.status, 'not_collected');
  const modelGuardDecision = asText(modelPackageEvidence.decision, 'unknown');
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
  const mobileSnapshotRows = mobileContext
    ? [
        {
          label: 'Policy',
          value: compactTextList([
            mobileContext.policyName,
            mobileContext.mode ? `mode ${humanizeValue(mobileContext.mode)}` : null,
            mobileContext.decision ? `decision ${humanizeValue(mobileContext.decision)}` : null,
          ]).join(' / ') || 'not recorded in snapshot',
        },
        {
          label: 'Thresholds',
          value: compactTextList([
            mobileContext.thresholds.alert ? `alert ${mobileContext.thresholds.alert}` : null,
            mobileContext.thresholds.block ? `block ${mobileContext.thresholds.block}` : null,
            mobileContext.thresholds.risk ? `risk ${mobileContext.thresholds.risk}` : null,
          ]).join(' / ') || 'not recorded in snapshot',
        },
        {
          label: 'Integrity',
          value: mobileContext.integritySignals.slice(0, 3).join(' / ') || 'no integrity verdict recorded',
        },
        {
          label: 'Hardening',
          value: mobileContext.hardeningSignals.slice(0, 3).join(' / ') || 'no runtime/native hardening signal recorded',
        },
        {
          label: 'Network',
          value: mobileContext.networkSignals.slice(0, 3).join(' / ') || 'no proxy, VPN, DoH or TLS hint recorded',
        },
        {
          label: 'Input provenance',
          value: mobileContext.inputProvenanceSignals.slice(0, 4).join(' / ') || 'not collected',
        },
        {
          label: 'Identity',
          value: compactTextList([
            mobileContext.appId,
            mobileContext.appVersion ? `v${mobileContext.appVersion}` : null,
            mobileContext.platform || mobileContext.deviceDetail,
          ]).join(' / ') || 'app or device identity not recorded',
        },
      ]
    : [];
  const processLabel = mobileContext && !primaryProcess?.pid ? 'Protected App' : 'Primary Process';
  const processTitle = primaryProcess?.name || mobileContext?.appName || 'process context unavailable';
  const processDetail = primaryProcess?.cmdline || primaryProcess?.path || mobileContext?.appId || mobileContext?.eventType || 'command line not captured';
  const processFacts = primaryProcess?.pid
    ? [
        `PID ${primaryProcess.pid}`,
        primaryProcess && 'is_signed' in primaryProcess ? (primaryProcess.is_signed ? 'signed' : 'unsigned') : null,
        primaryProcess.user,
      ].filter(Boolean)
    : [
        mobileContext?.deviceName ? `Device ${mobileContext.deviceName}` : null,
        mobileContext?.deviceDetail,
        mobileContext?.workflow ? `Workflow ${humanizeValue(mobileContext.workflow)}` : null,
      ].filter(Boolean);
  const touchpointLabel = mobileContext && !remote ? 'App Guard Signal' : 'External Touchpoint';
  const touchpointValue = remote
    ? `${remote}${remotePort ? `:${remotePort}` : ''}`
    : mobileContext?.tamperSignal || mobileContext?.eventType;
  const touchpointDetail = remote
    ? `${eventFlowStats.uniqueIPs} unique IPs, ${eventFlowStats.uniqueDomains} DNS names, ${formatBytesLocal(eventFlowStats.totalBytesSent)} sent`
    : [
        mobileContext?.decision ? `Decision ${humanizeValue(mobileContext.decision)}` : null,
        mobileContext?.mode ? `Mode ${humanizeValue(mobileContext.mode)}` : null,
        mobileContext?.riskScore !== undefined && mobileContext?.riskScore !== null ? `Risk ${mobileContext.riskScore}` : null,
      ].filter(Boolean).join(', ') || 'No network endpoint captured for this mobile alert';
  const proofDetail = iocs.length
    ? `${publicSafeCount} publishable IOCs, ${highestConfidence ? `${Math.round(highestConfidence <= 1 ? highestConfidence * 100 : highestConfidence)}% max confidence` : 'confidence pending'}`
    : mobileContext?.reasons.length
      ? `Reasons: ${mobileContext.reasons.slice(0, 3).map(reason => humanizeValue(reason)).join(', ')}`
      : `${publicSafeCount} publishable IOCs, confidence pending`;

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
                <span>{mobileContext && !primaryProcess?.pid ? 'App Guard context' : `${graphStats?.process_count ?? eventFlowStats.processCount} processes`}</span>
                <span>•</span>
                <span>{touchpointValue && !remote ? humanizeValue(mobileContext?.eventType) : `${eventFlowStats.networkCount || graphStats?.network_count || 0} network events`}</span>
                <span>•</span>
                <span>{iocs.length ? `${iocs.length} IOCs` : mobileContext?.reasons.length ? `${mobileContext.reasons.length} reasons` : '0 IOCs'}</span>
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
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>{processLabel}</span>
                  </div>
                  <div className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{processTitle}</div>
                  <LongTextPreview
                    value={processDetail}
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
                    {processFacts.map((fact, index) => <span key={`${fact}-${index}`}>{fact}</span>)}
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
                    <span className="text-xs font-semibold" style={{ color: 'var(--fg)' }}>{touchpointLabel}</span>
                  </div>
                  {touchpointValue ? (
                    <Tooltip content={String(touchpointValue)}>
                      <div className="text-sm font-mono truncate" style={{ color: 'var(--low)' }}>
                        {touchpointValue}
                      </div>
                    </Tooltip>
                  ) : (
                    <div className="text-sm font-mono truncate" style={{ color: 'var(--muted)' }}>
                      no remote endpoint captured
                    </div>
                  )}
                  <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                    {touchpointDetail}
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
                    {proofDetail}
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
                <EvidenceRow label={mobileContext && !primaryFile?.path ? 'App' : 'File'} value={primaryFile?.path || mobileContext?.appName || 'not captured'} />
                <EvidenceRow label={mobileContext && !primaryFile?.sha256 ? 'Device' : 'Hash'} value={primaryFile?.sha256 || (primaryProcess && 'sha256' in primaryProcess ? shortValue(primaryProcess.sha256) : mobileContext?.deviceName || 'not available')} />
                <EvidenceRow label="Model Guard" value={`${humanizeValue(modelGuardDecision)} / ${humanizeValue(modelGuardStatus)} / ${humanizeValue(modelGuardEnforcement)}`} />
                <EvidenceRow label="Package scanner" value={modelPackageFindingCount > 0 ? `${modelPackageFindingCount} finding${modelPackageFindingCount === 1 ? '' : 's'} from ${humanizeValue(modelPackageScanner)}` : `${humanizeValue(modelPackageScanner)} / not collected`} />
                <EvidenceRow label="Model consensus" value={modelExternalScoreCount > 0 ? `${modelExternalScoreCount} external score${modelExternalScoreCount === 1 ? '' : 's'} / ${humanizeValue(modelConsensusState)}` : 'external scores not collected'} />
                <EvidenceRow label="Enforcement" value={firstText(modelPackageEvidence.enforcement_note, modelGuardEnforcement === 'decision_only' ? 'decision-only; no block enforced' : modelGuardEnforcement === 'degraded' ? 'degraded; scanner evidence partial' : 'not recorded')} />
                <EvidenceRow label={mobileContext && !decodedCommand ? 'Decision' : 'Decoded PS'} value={decodedCommand ? shortValue(decodedCommand, 60, 20) : mobileContext?.decision ? humanizeValue(mobileContext.decision) : 'not present'} />
                <EvidenceRow label={mobileContext && !decodedUrls[0] ? 'Reason' : 'URL'} value={decodedUrls[0] ? shortValue(decodedUrls[0], 44, 18) : mobileContext?.reasons[0] ? humanizeValue(mobileContext.reasons[0]) : 'not captured'} />
                {mobileSnapshotRows.map(row => (
                  <EvidenceRow key={row.label} label={row.label} value={row.value} />
                ))}
                {mobileContext?.inputProvenanceBoundary ? (
                  <EvidenceRow label="Input boundary" value={mobileContext.inputProvenanceBoundary} />
                ) : null}
                {mobileContext?.signals.length ? (
                  <EvidenceRow label="Signals" value={mobileContext.signals.slice(0, 4).map(signal => humanizeValue(signal)).join(' / ')} />
                ) : null}
                <EvidenceRow label="Agent" value={agent?.hostname || 'unknown endpoint'} />
              </div>
            </div>

            <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Hash size={16} style={{ color: 'var(--high)' }} />
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Top Indicators</h3>
                </div>
                <span className="text-xs" style={{ color: 'var(--muted)' }}>{iocs.length || mobileContext?.reasons.length || 0} total</span>
              </div>
              {iocs.length === 0 && mobileContext ? (
                <div className="space-y-2">
                  {[mobileContext.tamperSignal || mobileContext.eventType, ...mobileContext.signals, ...mobileContext.reasons].filter(Boolean).slice(0, 4).map((signal, index) => (
                    <div key={`${signal}-${index}`} className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
                        app guard
                      </span>
                      <Tooltip content={signal}>
                        <span className="text-xs font-mono truncate" style={{ color: 'var(--fg-2)' }}>
                          {shortValue(humanizeValue(signal), 28, 12)}
                        </span>
                      </Tooltip>
                    </div>
                  ))}
                </div>
              ) : iocs.length === 0 ? (
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

const ACTIVE_AGENT_COMMAND_STATUSES = new Set(['pending', 'sent', 'acknowledged', 'running']);
const PERMANENT_COMMAND_LOOKUP_STATUSES = new Set([400, 401, 403, 404, 405, 410]);
const INVESTIGATION_COMMAND_STATUSES = new Set(['pending', 'sent', 'acknowledged', 'completed', 'failed']);

function commandType(command: AgentCommandRecord): string {
  return asText(firstPresent(command.command_type, command.commandType), 'command');
}

function normalizeCommandStatus(status: unknown): string {
  const normalized = asText(status, 'pending').trim().toLowerCase();
  if (['ack', 'acked'].includes(normalized)) return 'acknowledged';
  if (['complete', 'success', 'succeeded'].includes(normalized)) return 'completed';
  if (['error', 'timeout', 'timed_out'].includes(normalized)) return 'failed';
  return INVESTIGATION_COMMAND_STATUSES.has(normalized) ? normalized : normalized || 'pending';
}

function commandRuntime(command: AgentCommandRecord): string {
  const params = commandParams(command);
  const result = asRecord(command.result);
  const runtime = asText(firstPresent(
    command.runtime,
    command.runtime_kind,
    command.runtimeKind,
    command.command_runtime,
    command.commandRuntime,
    params.runtime,
    params.runtime_kind,
    params.runtimeKind,
    result.runtime,
    result.runtime_kind,
    result.runtimeKind
  )).trim();

  if (runtime) return runtime;
  return command.agent_id || command.agentId ? 'desktop_agent' : 'desktop_agent';
}

function runtimeLabel(runtime: string): string {
  switch (runtime) {
    case 'desktop_agent':
      return 'Desktop agent';
    case 'mobile_mdm':
      return 'Mobile MDM';
    default:
      return humanizeDetectionType(runtime);
  }
}

function commandParams(command: AgentCommandRecord): Record<string, unknown> {
  return asRecord(firstPresent(command.command_params, command.commandParams));
}

function commandTimestamp(command: AgentCommandRecord): string {
  return asText(firstPresent(
    command.completed_at,
    command.completedAt,
    command.acknowledged_at,
    command.acknowledgedAt,
    command.sent_at,
    command.sentAt,
    command.updated_at,
    command.updatedAt,
    command.inserted_at,
    command.insertedAt
  ));
}

function commandResultSummary(command: AgentCommandRecord): string | null {
  const result = asRecord(command.result);
  const direct = firstText(
    result.summary,
    result.message,
    result.reason,
    result.status,
    result.output,
    result.stdout,
    result.stderr,
    result.error
  );

  if (direct) return direct.length > 160 ? `${direct.slice(0, 157)}...` : direct;

  const counts = Object.entries(result)
    .filter(([, value]) => typeof value === 'number' || Array.isArray(value))
    .slice(0, 3)
    .map(([key, value]) => `${humanizeValue(key)}: ${Array.isArray(value) ? value.length : value}`);

  if (counts.length) return counts.join(' / ');
  return Object.keys(result).length ? 'Result payload returned' : null;
}

function rollbackLabel(rollback?: RollbackSummary | null): string {
  if (!rollback) return 'Rollback status unavailable';
  if (rollback.available) {
    return `Rollback available${asText(firstPresent(rollback.action_type, rollback.actionType)) ? `: ${humanizeDetectionType(asText(firstPresent(rollback.action_type, rollback.actionType)))}` : ''}`;
  }
  return asText(rollback.reason, 'Rollback unavailable');
}

function commandTargetSummary(command: AgentCommandRecord): string | null {
  const params = commandParams(command);
  const target = firstText(
    params.path,
    params.file_path,
    params.filePath,
    params.pid,
    params.domain,
    params.ip,
    params.host,
    params.hostname,
    params.command,
    params.artifact,
    params.artifacts
  );

  return target || null;
}

function commandStatusStyle(status: string): React.CSSProperties {
  switch (normalizeCommandStatus(status)) {
    case 'completed':
      return { backgroundColor: 'color-mix(in srgb, var(--low) 14%, transparent)', color: 'var(--low)' };
    case 'failed':
      return { backgroundColor: 'color-mix(in srgb, var(--crit) 14%, transparent)', color: 'var(--crit)' };
    case 'sent':
    case 'acknowledged':
      return { backgroundColor: 'color-mix(in srgb, var(--accent) 14%, transparent)', color: 'var(--accent)' };
    case 'pending':
      return { backgroundColor: 'color-mix(in srgb, var(--med) 14%, transparent)', color: 'var(--med)' };
    default:
      return { backgroundColor: 'var(--surface-2)', color: 'var(--muted)' };
  }
}

function commandLookupContext(meta: Record<string, unknown>, alertId: string): string | null {
 const discoveredByAlertId = firstText(meta.discovered_by_alert_id, meta.discoveredByAlertId);
 const discoveredCounts = asRecord(
 meta.discovered_command_counts ||
 meta.discoveredCommandCounts ||
 (discoveredByAlertId ? null : meta.discovered_by_alert_id || meta.discoveredByAlertId)
 );
 const discoveredTotal = ['desktop', 'mobile']
 .map((key) => Number(discoveredCounts[key] || 0))
 .filter((value) => Number.isFinite(value))
 .reduce((total, value) => total + value, 0);

 if (discoveredByAlertId) {
 return discoveredByAlertId === alertId
 ? 'Command status was discovered by this alert ID.'
 : `Command status was discovered by related alert ${discoveredByAlertId}.`;
 }
 if (discoveredTotal > 0) {
 return `${discoveredTotal} command status${discoveredTotal === 1 ? '' : 'es'} were discovered by alert lookup.`;
 }
 return null;
}

function AutoInvestigationPanel({ alert }: { alert: Alert }) {
  const plan = asRecord(alert.detectionMetadata?.investigation_enrichment);
  const auto = asRecord(alert.enrichment?.auto_investigation);
  const [commands, setCommands] = useState<AgentCommandRecord[]>([]);
  const [meta, setMeta] = useState<Record<string, unknown>>({});
  const [isLoadingCommands, setIsLoadingCommands] = useState(true);
  const [isRefreshingCommands, setIsRefreshingCommands] = useState(false);
  const [commandsError, setCommandsError] = useState<string | null>(null);
  const [commandsUnavailable, setCommandsUnavailable] = useState(false);
  const [commandsPermanentError, setCommandsPermanentError] = useState(false);
  const [shadowRuns, setShadowRuns] = useState<Record<string, unknown>[]>([]);
  const [shadowRunsUnavailable, setShadowRunsUnavailable] = useState(false);

  const loadCommands = useCallback(async (options: { signal?: AbortSignal; silent?: boolean } = {}) => {
    if (options.silent) {
      setIsRefreshingCommands(true);
    } else {
      setIsLoadingCommands(true);
    }
    setCommandsError(null);
    setCommandsUnavailable(false);
    setCommandsPermanentError(false);

    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/agent-commands`, {
        credentials: 'include',
        signal: options.signal,
      });

      if ([404, 405].includes(response.status)) {
        setCommands([]);
        setMeta({});
        setCommandsUnavailable(true);
        setCommandsPermanentError(true);
        return;
      }

      if (!response.ok) {
        setCommandsPermanentError(PERMANENT_COMMAND_LOOKUP_STATUSES.has(response.status));
        throw new Error(`Agent commands lookup failed with HTTP ${response.status}`);
      }

      const payload = await response.json() as AgentCommandResponse;
      setCommands(Array.isArray(payload.data) ? payload.data : []);
      setMeta(asRecord(payload.meta));
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      logger.error('Failed to fetch alert agent commands:', err);
      setCommandsError(err instanceof Error ? err.message : 'Failed to fetch alert agent commands');
    } finally {
      if (!options.signal?.aborted) {
        setIsLoadingCommands(false);
        setIsRefreshingCommands(false);
      }
    }
  }, [alert.id]);

  useEffect(() => {
    const controller = new AbortController();
    loadCommands({ signal: controller.signal });
    return () => controller.abort();
  }, [loadCommands]);

  useEffect(() => {
    const controller = new AbortController();
    setShadowRuns([]);
    setShadowRunsUnavailable(false);

    fetch(`/api/v1/alerts/${alert.id}/investigations`, {
      credentials: 'include',
      signal: controller.signal,
    })
      .then(async response => {
        if (!response.ok) throw new Error(`Investigation lookup failed with HTTP ${response.status}`);
        const payload = await response.json() as { data?: unknown[] };
        setShadowRuns(Array.isArray(payload.data) ? payload.data.map(asRecord) : []);
      })
      .catch(error => {
        if (error instanceof DOMException && error.name === 'AbortError') return;
        logger.error('Failed to fetch shadow investigation context:', error);
        setShadowRunsUnavailable(true);
      });

    return () => controller.abort();
  }, [alert.id]);

  useEffect(() => {
    const hasActiveCommands = commands.some(command => ACTIVE_AGENT_COMMAND_STATUSES.has(normalizeCommandStatus(command.status)));
    if (!hasActiveCommands || commandsPermanentError || commandsUnavailable) return;

    const interval = window.setInterval(() => {
      loadCommands({ silent: true });
    }, 6000);

    return () => window.clearInterval(interval);
  }, [commands, commandsPermanentError, commandsUnavailable, loadCommands]);

  const status = asText(firstPresent(plan.status, auto.status, commands.length ? 'discovered' : 'lookup'));
  const queuedCommands = Array.isArray(plan.queued_commands) ? plan.queued_commands : [];
  const artifactRequests = Array.isArray(plan.artifact_requests) ? plan.artifact_requests : [];
  const recommendedMobile = Array.isArray(plan.recommended_mobile_commands) ? plan.recommended_mobile_commands : [];
  const skippedCapabilities = Array.isArray(plan.skipped_capabilities) ? plan.skipped_capabilities : [];
  const requestedAt = asText(firstPresent(plan.requested_at, auto.requested_at, plan.generated_at));
  const collectionCommandId = asText(firstPresent(plan.collection_command_id, auto.collection_command_id));
  const error = asText(firstPresent(plan.error, plan.reason));
  const isDegraded = status === 'capability_degraded';
  const hasPlanContext = Boolean(Object.keys(plan).length || Object.keys(auto).length);
  const activeCommands = commands.filter(command => ACTIVE_AGENT_COMMAND_STATUSES.has(normalizeCommandStatus(command.status))).length;
  const completedCommands = commands.filter(command => normalizeCommandStatus(command.status) === 'completed').length;
  const failedCommands = commands.filter(command => normalizeCommandStatus(command.status) === 'failed').length;
  const requestedCommandIds = Array.isArray(meta.requested_command_ids) ? meta.requested_command_ids.length : undefined;
  const lookupContext = commandLookupContext(meta, alert.id);
  const latestShadowRun = shadowRuns[0];
  const shadowDisposition = asText(latestShadowRun?.admission_disposition);
  const shadowReason = asText(latestShadowRun?.admission_reason);
  const shadowPolicyVersion = asText(latestShadowRun?.policy_version);
  const toneColor =
    failedCommands > 0 || status === 'request_failed' ? 'var(--crit)' :
      activeCommands > 0 || status === 'requested' ? 'var(--med)' :
        completedCommands > 0 ? 'var(--low)' :
      isDegraded ? 'var(--med)' :
        'var(--accent)';

  return (
    <section className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <ClipboardList size={16} style={{ color: toneColor }} />
            <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Auto Investigation</h3>
            <span className="rounded px-2 py-0.5 text-xs font-medium" style={{ color: toneColor, backgroundColor: `color-mix(in srgb, ${toneColor} 12%, transparent)` }}>
              {commands.length ? `${completedCommands} completed / ${failedCommands} failed / ${activeCommands} active` : humanizeDetectionType(status)}
            </span>
            {isRefreshingCommands && <RefreshCw size={14} className="animate-spin" style={{ color: 'var(--muted)' }} />}
          </div>
          <p className="mt-2 text-sm leading-relaxed" style={{ color: 'var(--fg-2)' }}>
            {commands.length
              ? lookupContext || 'Investigation commands are read from the agent command queue for this alert.'
              : isLoadingCommands
                ? 'Loading investigation commands for this alert.'
                : !hasPlanContext
              ? lookupContext || 'No investigation commands were discovered for this alert yet.'
                : isDegraded
              ? asText(plan.message) || 'Mobile endpoint uses mobile command runtime; desktop live-response commands were not queued.'
              : 'Strong alert context enrichment was planned or queued for this endpoint.'}
          </p>
          {(commandsUnavailable || commandsError || error) && (
            <p className="mt-2 text-xs" style={{ color: commandsError || status === 'request_failed' ? 'var(--crit)' : 'var(--muted)' }}>
              {commandsUnavailable ? 'Command status endpoint is not available on this deployment.' : commandsError || error}
            </p>
          )}
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4 lg:min-w-[420px]">
          <AutoInvestigationMetric label="Requested" value={requestedAt || 'pending'} />
          <AutoInvestigationMetric label="Collection" value={collectionCommandId || 'none'} mono />
          <AutoInvestigationMetric label="Returned" value={String(commands.length)} />
          <AutoInvestigationMetric label="Expected" value={requestedCommandIds == null ? String(queuedCommands.length + artifactRequests.length) : String(requestedCommandIds)} />
          {lookupContext && <AutoInvestigationMetric label="Lookup" value="alert id" />}
        </div>
      </div>

      {(latestShadowRun || shadowRunsUnavailable) && (
        <div className="mt-3 rounded-lg p-3 text-xs" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="font-semibold">Automatic investigation shadow policy</span>
            {shadowDisposition && <span>Disposition: {humanizeDetectionType(shadowDisposition)}</span>}
            {shadowReason && <span>Reason: {humanizeDetectionType(shadowReason)}</span>}
            {shadowPolicyVersion && <span>Policy: {shadowPolicyVersion}</span>}
            <span>Enforcement: disabled</span>
          </div>
          <p className="mt-1" style={{ color: 'var(--muted)' }}>
            {shadowRunsUnavailable
              ? 'Shadow policy context is unavailable on this deployment.'
              : 'This is a model-agnostic admission receipt. It does not represent an automated verdict or response action.'}
          </p>
        </div>
      )}

      <div className="mt-3 flex justify-end">
        <button
          type="button"
          onClick={() => loadCommands({ silent: true })}
          className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs hover:brightness-125 disabled:opacity-60"
          style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
          disabled={isLoadingCommands || isRefreshingCommands}
        >
          <RefreshCw size={13} className={isLoadingCommands || isRefreshingCommands ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {commands.length > 0 ? (
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          {commands.map(command => {
            const target = commandTargetSummary(command);
            const resultSummary = commandResultSummary(command);
            const timestamp = commandTimestamp(command);
            const normalizedStatus = normalizeCommandStatus(command.status);
            const statusStyle = commandStatusStyle(normalizedStatus);
            const runtime = commandRuntime(command);

            return (
              <div key={command.id} className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-alt, color-mix(in srgb, var(--surface) 80%, var(--fg)))' }}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-semibold" style={{ color: 'var(--fg)' }} title={commandType(command)}>
                      {humanizeDetectionType(commandType(command))}
                    </div>
                    <div className="mt-1 truncate font-mono text-[10px]" style={{ color: 'var(--subtle)' }} title={command.id}>
                      {command.id}
                    </div>
                  </div>
                  <span className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase" style={statusStyle}>
                    {normalizedStatus}
                  </span>
                </div>

                <div className="mt-2 grid grid-cols-3 gap-2 text-[10px]">
                  <div className="truncate" style={{ color: 'var(--muted)' }} title={runtimeLabel(runtime)}>
                    Runtime: <span style={{ color: 'var(--fg-2)' }}>{runtimeLabel(runtime)}</span>
                  </div>
                  <div className="truncate" style={{ color: 'var(--muted)' }} title={target || undefined}>
                    Target: <span style={{ color: 'var(--fg-2)' }}>{target || 'not specified'}</span>
                  </div>
                  <div className="truncate" style={{ color: 'var(--muted)' }} title={timestamp || undefined}>
                    Updated: <span style={{ color: 'var(--fg-2)' }}>{timestamp ? new Date(timestamp).toLocaleString() : 'pending'}</span>
                  </div>
                </div>

                {resultSummary && (
                  <Tooltip content={resultSummary}>
                    <div className="mt-2 truncate text-xs" style={{ color: 'var(--fg-2)' }}>
                      Result: {resultSummary}
                    </div>
                  </Tooltip>
                )}

                {command.error && (
                  <Tooltip content={command.error}>
                    <div className="mt-2 truncate text-xs" style={{ color: 'var(--crit)' }}>
                      Error: {command.error}
                    </div>
                  </Tooltip>
                )}

                {command.rollback && (
                  <Tooltip content={rollbackLabel(command.rollback)}>
                    <div className="mt-2 truncate text-[10px]" style={{ color: command.rollback.available ? 'var(--low)' : 'var(--muted)' }}>
                      {command.rollback.available ? 'Rollback available' : 'Rollback unavailable'}
                    </div>
                  </Tooltip>
                )}
              </div>
            );
          })}
        </div>
      ) : isLoadingCommands ? (
        <div className="mt-4 rounded-lg p-3 text-xs" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
          Loading agent commands...
        </div>
      ) : (
        <div className="mt-4 rounded-lg p-3 text-xs" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
          {commandsUnavailable
            ? 'Command status endpoint unavailable; runtime status cannot be fetched.'
            : commandsError
              ? 'Command status lookup failed; retry when the endpoint is reachable.'
              : lookupContext
                ? `${lookupContext} No command records were returned.`
                : 'No command statuses were returned for this alert ID yet.'}
        </div>
      )}

      {(queuedCommands.length > 0 || artifactRequests.length > 0 || recommendedMobile.length > 0 || skippedCapabilities.length > 0) && (
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          {queuedCommands.length > 0 && (
            <AutoInvestigationList
              title="Queued Commands"
              items={queuedCommands.slice(0, 6).map((item: any) => {
                const record = asRecord(item);
                return `${asText(record.command_type) || 'command'} / ${asText(record.status) || asText(record.queued_status) || 'queued'}${record.command_id ? ` / ${record.command_id}` : ''}`;
              })}
            />
          )}
          {artifactRequests.length > 0 && (
            <AutoInvestigationList
              title="Artifact Requests"
              items={artifactRequests.slice(0, 6).map((item: any) => {
                const record = asRecord(item);
                return `${asText(record.command_type) || 'artifact'} / ${asText(record.status) || 'queued'}${record.path ? ` / ${record.path}` : ''}`;
              })}
            />
          )}
          {recommendedMobile.length > 0 && (
            <AutoInvestigationList title="Mobile Commands" items={recommendedMobile.map((item: any) => `Mobile MDM / ${asText(item)}`).filter(Boolean)} />
          )}
          {skippedCapabilities.length > 0 && (
            <AutoInvestigationList
              title="Degraded Capabilities"
              items={skippedCapabilities.slice(0, 6).map((item: any) => {
                const record = asRecord(item);
                return `${humanizeDetectionType(asText(record.capability) || asText(item))}${record.reason ? ` / ${asText(record.reason)}` : ''}`;
              })}
            />
          )}
        </div>
      )}
    </section>
  );
}

function AutoInvestigationMetric({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded p-2" style={{ backgroundColor: 'var(--surface-alt, color-mix(in srgb, var(--surface) 80%, var(--fg)))' }}>
      <div className="text-[10px] uppercase" style={{ color: 'var(--muted)' }}>{label}</div>
      <div className={cn('mt-1 truncate text-xs font-medium', mono && 'font-mono')} style={{ color: 'var(--fg)' }} title={value}>
        {value}
      </div>
    </div>
  );
}

function AutoInvestigationList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-alt, color-mix(in srgb, var(--surface) 80%, var(--fg)))' }}>
      <div className="mb-2 text-xs font-semibold" style={{ color: 'var(--fg)' }}>{title}</div>
      <div className="space-y-1">
        {items.map((item, index) => (
          <div key={`${title}-${index}`} className="truncate text-xs font-mono" style={{ color: 'var(--muted)' }} title={item}>
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}

function normalizeDisplayConfidence(value: unknown): string {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return 'confidence n/a';
  return `${Math.min(100, Math.round(number <= 1 ? number * 100 : number))}% confidence`;
}

function quoteHuntValue(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function normalizeDurationMs(value: unknown): number | undefined {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return undefined;
  return Math.round(number);
}

function stableHuntId(type: string, value: string): string {
  return `${type}-${value}`.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || `pivot-${type}`;
}

function latencyFieldsForPivot(pivot: NonNullable<AlertInvestigationStory['pivots']>[number]) {
  const source = pivot as unknown as Record<string, unknown>;
  const latencyMs = normalizeDurationMs(firstPresent(source.latency_ms, source.latencyMs));
  const ttdMs = normalizeDurationMs(firstPresent(source.ttd_ms, source.ttdMs));
  const latencyPlaceholder = firstText(source.latency_placeholder, source.latencyPlaceholder) || 'pending: event.ingested - @timestamp';
  const ttdPlaceholder = firstText(source.ttd_placeholder, source.ttdPlaceholder) || 'pending: alert.created_at - event.created';

  return {
    latency_ms: latencyMs,
    latencyMs,
    ttd_ms: ttdMs,
    ttdMs,
    latency_placeholder: latencyMs == null ? latencyPlaceholder : undefined,
    latencyPlaceholder: latencyMs == null ? latencyPlaceholder : undefined,
    ttd_placeholder: ttdMs == null ? ttdPlaceholder : undefined,
    ttdPlaceholder: ttdMs == null ? ttdPlaceholder : undefined,
  };
}

function networkHuntQueryForPivot(pivot: NonNullable<AlertInvestigationStory['pivots']>[number], value: string, quoted: string): string {
  const source = pivot as unknown as Record<string, unknown>;
  const remoteIp = firstText(source.remote_ip, source.remoteIp, source.ip, value.split(':')[0]);
  const remotePort = firstText(source.remote_port, source.remotePort, source.port);
  const ipQuery = `destination.ip:${quoteHuntValue(remoteIp)}`;
  return remotePort
    ? `${ipQuery} and destination.port:${remotePort}`
    : `${ipQuery} or source.ip:${quoted} or related.ip:${quoted}`;
}

function huntQueryForPivot(pivot: NonNullable<AlertInvestigationStory['pivots']>[number]): NonNullable<AlertInvestigationStory['huntQueries']>[number] | null {
  const type = asText(pivot.type, 'indicator').toLowerCase();
  const value = asText(pivot.value).trim();
  if (!value) return null;
  const quoted = quoteHuntValue(value);
  const base = {
    id: stableHuntId(type, value),
    label: `${type} hunt`,
    kind: type,
    pivot_type: type,
    pivotType: type,
    pivot_value: value,
    pivotValue: value,
    ...latencyFieldsForPivot(pivot),
  };

  if (type === 'process') {
    const numericPid = /^\d+$/.test(value);
    return {
      ...base,
      family: 'process',
      label: 'Process hunt',
      query: numericPid
        ? `process.pid:${value} or process.parent.pid:${value}`
        : `process.name:${quoted} or process.executable:${quoted} or process.command_line:${quoted}`,
      description: 'Pivot across process execution, parent process, and command-line telemetry.',
    };
  }
  if (type === 'binary' || type === 'hash') {
    return {
      ...base,
      family: 'file_hash',
      label: 'File hash hunt',
      query: `file.hash.sha256:${quoted} or file.hash.sha1:${quoted} or file.hash.md5:${quoted} or process.hash.sha256:${quoted}`,
      description: 'Pivot across file hash and process image hash telemetry.',
      missing_data_explanation: type === 'binary' ? 'File hash was missing; executable/path fallback may be lower fidelity.' : undefined,
    };
  }
  if (['dns', 'domain'].includes(type)) {
    return {
      ...base,
      family: 'dns',
      label: 'DNS hunt',
      query: `dns.question.name:${quoted} or dns.answers.data:${quoted} or destination.domain:${quoted} or url.domain:${quoted}`,
      description: 'Pivot across DNS question, answer, destination domain, and URL domain telemetry.',
    };
  }
  if (type === 'tls_sni') {
    return {
      ...base,
      family: 'tls_sni',
      label: 'TLS/SNI hunt',
      query: `tls.client.server_name:${quoted} or tls.server.subject:${quoted} or destination.domain:${quoted}`,
      description: 'Pivot across TLS SNI and certificate subject telemetry.',
    };
  }
  if (['network', 'ip', 'remote_ip', 'remote_endpoint'].includes(type)) {
    return {
      ...base,
      family: 'remote_endpoint',
      label: 'Remote IP/port hunt',
      query: networkHuntQueryForPivot(pivot, value, quoted),
      description: 'Pivot across remote IP and destination port telemetry.',
      missing_data_explanation: firstText((pivot as unknown as Record<string, unknown>).remote_port, (pivot as unknown as Record<string, unknown>).remotePort, (pivot as unknown as Record<string, unknown>).port)
        ? undefined
        : 'Remote port was not captured; hunt is IP-only.',
    };
  }
  if (type === 'url') {
    return {
      ...base,
      family: 'url',
      label: 'URL hunt',
      query: `url.full:${quoted} or url.original:${quoted}`,
      description: 'Pivot across full URL telemetry.',
    };
  }
  if (type === 'package' || type === 'app') {
    return {
      ...base,
      family: 'package',
      label: 'Package hunt',
      query: `tamandua.app.package:${quoted} or package.name:${quoted} or process.args:${quoted}`,
      description: 'Pivot across App Guard package context and endpoint process arguments.',
    };
  }
  return {
    ...base,
    family: 'indicator',
    query: `message:${quoted} or event.original:${quoted}`,
    description: 'Generic indicator pivot across raw event payloads.',
  };
}

function enrichInvestigationStory(story: AlertInvestigationStory): AlertInvestigationStory {
  const pivots = story.pivots || [];
  const tree = story.tree || [];
  const missing = story.missingData || story.missing_data || [];
  const huntQueries = story.huntQueries || story.hunt_queries || pivots.map(huntQueryForPivot).filter(Boolean) as NonNullable<AlertInvestigationStory['huntQueries']>;
  const confidenceExplanation = story.confidenceExplanation || story.confidence_explanation || {
    label: Number.isFinite(Number(story.confidence))
      ? `${normalizeDisplayConfidence(story.confidence)} from detection metadata and normalized evidence.`
      : 'Confidence was not supplied by detection metadata.',
    factors: [
      Number.isFinite(Number(story.confidence)) ? 'Detection confidence metadata was present.' : null,
      pivots.length ? `${pivots.length} pivots available for hunt expansion.` : null,
      tree.length ? 'Storyline tree includes process, binary, network, or mobile context.' : null,
      missing.length ? `${missing.length} missing-data gap(s) reduce claim strength.` : null,
    ].filter(Boolean) as string[],
  };

  return {
    ...story,
    hunt_queries: huntQueries,
    huntQueries,
    confidence_explanation: confidenceExplanation,
    confidenceExplanation,
  };
}

function InvestigationCoveragePanel({
  story,
  onCopy,
  copiedField,
}: {
  story: AlertInvestigationStory;
  onCopy: (text: string, field: string) => void;
  copiedField: string | null;
}) {
  const pivots = story.pivots || [];
  const tree = story.tree || [];
  const missing = story.missingData || story.missing_data || [];
  const huntQueries = story.huntQueries || story.hunt_queries || [];
  const confidenceExplanation = story.confidenceExplanation || story.confidence_explanation || {};
  const confidenceFactors = confidenceExplanation.factors || confidenceExplanation.reasons || confidenceExplanation.signals || [];

  const renderNode = (node: NonNullable<AlertInvestigationStory['tree']>[number], depth = 0) => (
    <div key={`${node.id}-${depth}`} className="space-y-2">
      <div
        className="rounded-lg border p-3"
        style={{
          marginLeft: depth ? 16 : 0,
          backgroundColor: 'var(--surface)',
          borderColor: 'var(--border)',
        }}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase" style={{ color: 'var(--accent)' }}>
              {humanizeValue(node.kind)}
            </div>
            <div className="mt-1 truncate text-sm font-semibold" style={{ color: 'var(--fg)' }} title={node.label}>
              {node.label}
            </div>
            {node.detail && (
              <div className="mt-1 truncate text-xs" style={{ color: 'var(--muted)' }} title={node.detail}>
                {node.detail}
              </div>
            )}
          </div>
          <div className="shrink-0 text-right text-[10px]" style={{ color: 'var(--muted)' }}>
            <div>{node.source || 'source n/a'}</div>
            <div>{normalizeDisplayConfidence(node.confidence)}</div>
          </div>
        </div>
      </div>
      {(node.children || []).map(child => renderNode(child, depth + 1))}
    </div>
  );

  return (
    <div className="border-b" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 40%, var(--bg))', borderColor: 'var(--border)' }}>
      <div className="max-w-full mx-auto px-4 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <GitBranch size={16} style={{ color: 'var(--accent)' }} />
              <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Investigation Coverage</h3>
              <span className="rounded px-2 py-0.5 text-xs" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                {normalizeDisplayConfidence(story.confidence)}
              </span>
            </div>
            <p className="mt-2 max-w-4xl text-sm leading-relaxed" style={{ color: 'var(--fg-2)' }}>
              {story.summary || 'Alert evidence was normalized into operator pivots and investigation tree context.'}
            </p>
            {(confidenceExplanation.label || confidenceExplanation.summary || confidenceFactors.length > 0) && (
              <div className="mt-3 rounded border p-2 text-xs" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg-2)' }}>
                <div>{confidenceExplanation.label || confidenceExplanation.summary || 'Confidence explanation not captured.'}</div>
                {confidenceFactors.slice(0, 4).map((factor, index) => (
                  <div key={`${factor}-${index}`} className="mt-1" style={{ color: 'var(--muted)' }}>{factor}</div>
                ))}
              </div>
            )}
          </div>
          <span className="rounded px-2 py-1 text-xs" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
            {story.source || 'source n/a'}
          </span>
        </div>

        <div className="mt-4 grid gap-3 xl:grid-cols-[1fr_1fr_1.1fr_0.9fr]">
          <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="text-xs font-semibold uppercase" style={{ color: 'var(--muted)' }}>Pivots</div>
            <div className="mt-3 space-y-2">
              {pivots.length ? pivots.slice(0, 8).map((pivot, index) => (
                <div key={`${pivot.type}-${pivot.value}-${index}`} className="rounded p-2" style={{ backgroundColor: 'var(--surface-2)' }}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-semibold uppercase" style={{ color: 'var(--accent)' }}>{humanizeValue(pivot.type)}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px]" style={{ color: 'var(--muted)' }}>{normalizeDisplayConfidence(pivot.confidence)}</span>
                      <Tooltip content="Copy pivot value">
                        <button
                          onClick={() => onCopy(pivot.value, `hunt_pivot_${index}`)}
                          className="rounded p-1"
                          style={{ color: copiedField === `hunt_pivot_${index}` ? 'var(--low)' : 'var(--muted)' }}
                        >
                          {copiedField === `hunt_pivot_${index}` ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </Tooltip>
                    </div>
                  </div>
                  <div className="mt-1 truncate font-mono text-xs" style={{ color: 'var(--fg)' }} title={pivot.value}>{pivot.value}</div>
                  <div className="mt-1 truncate text-[10px]" style={{ color: 'var(--muted)' }}>{pivot.source || pivot.label || 'source n/a'}</div>
                </div>
              )) : (
                <div className="text-xs" style={{ color: 'var(--muted)' }}>No pivots captured.</div>
              )}
            </div>
          </div>

          <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="text-xs font-semibold uppercase" style={{ color: 'var(--muted)' }}>Elastic hunt templates</div>
            <div className="mt-3 space-y-2">
              {huntQueries.length ? huntQueries.slice(0, 8).map((query, index) => (
                <div key={`${query.id || query.label}-${index}`} className="rounded p-2" style={{ backgroundColor: 'var(--surface-2)' }}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate text-xs font-semibold" style={{ color: 'var(--fg)' }}>{query.label}</div>
                      {query.description && <div className="mt-1 text-[10px]" style={{ color: 'var(--muted)' }}>{query.description}</div>}
                      {(query.latencyMs != null || query.latency_ms != null || query.latencyPlaceholder || query.latency_placeholder || query.ttdMs != null || query.ttd_ms != null || query.ttdPlaceholder || query.ttd_placeholder) && (
                        <div className="mt-1 text-[10px]" style={{ color: 'var(--muted)' }}>
                          {[
                            query.latencyMs != null || query.latency_ms != null
                              ? `${query.latencyMs ?? query.latency_ms}ms latency`
                              : query.latencyPlaceholder || query.latency_placeholder,
                            query.ttdMs != null || query.ttd_ms != null
                              ? `${query.ttdMs ?? query.ttd_ms}ms TTD`
                              : query.ttdPlaceholder || query.ttd_placeholder,
                          ].filter(Boolean).join(' / ')}
                        </div>
                      )}
                      {(query.missingDataExplanation || query.missing_data_explanation) && (
                        <div className="mt-1 text-[10px]" style={{ color: 'var(--high)' }}>
                          {query.missingDataExplanation || query.missing_data_explanation}
                        </div>
                      )}
                    </div>
                    <Tooltip content="Copy hunt query">
                      <button
                        onClick={() => onCopy(query.query, `hunt_query_${index}`)}
                        className="shrink-0 rounded p-1"
                        style={{ color: copiedField === `hunt_query_${index}` ? 'var(--low)' : 'var(--muted)' }}
                      >
                        {copiedField === `hunt_query_${index}` ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </Tooltip>
                  </div>
                  <pre className="mt-2 whitespace-pre-wrap break-words rounded p-2 text-[10px]" style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)', fontFamily: 'var(--mono)' }}>{query.query}</pre>
                </div>
              )) : (
                <div className="text-xs" style={{ color: 'var(--muted)' }}>No hunt templates captured.</div>
              )}
            </div>
          </div>

          <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="text-xs font-semibold uppercase" style={{ color: 'var(--muted)' }}>Process / binary / network tree</div>
            <div className="mt-3 space-y-2">
              {tree.length ? tree.map(node => renderNode(node)) : (
                <div className="text-xs" style={{ color: 'var(--muted)' }}>No investigation tree captured.</div>
              )}
            </div>
          </div>

          <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="text-xs font-semibold uppercase" style={{ color: 'var(--muted)' }}>Missing data explained</div>
            <div className="mt-3 space-y-2">
              {missing.length ? missing.slice(0, 8).map((item, index) => (
                <div key={`${item.field}-${index}`} className="rounded p-2 text-xs" style={{ backgroundColor: 'color-mix(in srgb, var(--high) 10%, var(--surface-2))', color: 'var(--fg)' }}>
                  <div className="font-semibold">{humanizeValue(item.field)}</div>
                  <div className="mt-1" style={{ color: 'var(--fg-2)' }}>{item.reason}</div>
                  <div className="mt-1 text-[10px]" style={{ color: 'var(--muted)' }}>{item.source || 'source n/a'}</div>
                </div>
              )) : (
                <div className="text-xs" style={{ color: 'var(--muted)' }}>No missing-data gaps recorded.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
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

function InvestigationRunsSection({ alertId }: { alertId: string }) {
  const [runs, setRuns] = useState<InvestigationRunRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [evidenceByRun, setEvidenceByRun] = useState<Record<string, {
    data: InvestigationEvidenceRecord[];
    loading: boolean;
    error: string | null;
  }>>({});

  const loadRuns = useCallback(async (signal?: AbortSignal) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/v1/alerts/${alertId}/investigations`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
        signal,
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const body = await response.json();
      setRuns(Array.isArray(body?.data) ? body.data : []);
    } catch (requestError) {
      if (requestError instanceof DOMException && requestError.name === 'AbortError') return;
      logger.error('Investigation runs unavailable:', requestError);
      setError('Investigation data is temporarily unavailable. Alert handling is unaffected.');
    } finally {
      if (!signal?.aborted) setIsLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    const controller = new AbortController();
    setRuns([]);
    setExpandedRunId(null);
    setEvidenceByRun({});
    void loadRuns(controller.signal);
    return () => controller.abort();
  }, [loadRuns]);

  const loadEvidence = async (runId: string) => {
    setEvidenceByRun(current => ({
      ...current,
      [runId]: { data: current[runId]?.data || [], loading: true, error: null },
    }));

    try {
      const response = await fetch(`/api/v1/investigation-runs/${runId}/evidence`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const body = await response.json();
      setEvidenceByRun(current => ({
        ...current,
        [runId]: { data: Array.isArray(body?.data) ? body.data : [], loading: false, error: null },
      }));
    } catch (requestError) {
      logger.error('Investigation evidence unavailable:', requestError);
      setEvidenceByRun(current => ({
        ...current,
        [runId]: {
          data: current[runId]?.data || [],
          loading: false,
          error: 'Evidence is temporarily unavailable.',
        },
      }));
    }
  };

  const toggleRun = (runId: string) => {
    const opening = expandedRunId !== runId;
    setExpandedRunId(opening ? runId : null);
    if (opening && !evidenceByRun[runId]) void loadEvidence(runId);
  };

  return (
    <section className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
            <ClipboardList size={18} style={{ color: 'var(--accent)' }} />
          </div>
          <div className="min-w-0">
            <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Investigation Runs</h4>
            <p className="text-xs" style={{ color: 'var(--muted)' }}>Governed observation history</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void loadRuns()}
          disabled={isLoading}
          className="p-1.5 rounded hover:brightness-125 disabled:opacity-50"
          style={{ color: 'var(--muted)' }}
          aria-label="Refresh investigation runs"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
        </button>
      </div>

      {isLoading && runs.length === 0 && (
        <div className="space-y-2" aria-label="Loading investigation runs">
          <div className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--surface-2)' }} />
          <div className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--surface-2)' }} />
        </div>
      )}

      {!isLoading && error && (
        <div
          className="rounded-lg border p-3 text-xs"
          style={{
            color: 'var(--med)',
            borderColor: 'color-mix(in srgb, var(--med) 35%, var(--border))',
            backgroundColor: 'color-mix(in srgb, var(--med) 10%, var(--surface-2))',
          }}
        >
          <div className="flex items-start gap-2">
            <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {!isLoading && !error && runs.length === 0 && (
        <div className="rounded-lg p-3 text-xs" style={{ color: 'var(--muted)', backgroundColor: 'var(--surface-2)' }}>
          No investigation runs have been recorded for this alert.
        </div>
      )}

      {runs.length > 0 && (
        <div className="space-y-2">
          {runs.map(run => {
            const expanded = expandedRunId === run.id;
            const evidenceState = evidenceByRun[run.id];
            const enforcement = String(run.summary?.enforcement || 'disabled');
            const degraded = ['failed', 'abstained'].includes(run.status.toLowerCase());

            return (
              <div key={run.id} className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--hairline)' }}>
                <button
                  type="button"
                  onClick={() => toggleRun(run.id)}
                  className="w-full p-3 text-left hover:brightness-110"
                  style={{ backgroundColor: 'var(--surface-2)' }}
                  aria-expanded={expanded}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className="text-[10px] uppercase tracking-wide rounded px-1.5 py-0.5"
                        style={{
                          color: degraded ? 'var(--med)' : 'var(--accent)',
                          backgroundColor: degraded
                            ? 'color-mix(in srgb, var(--med) 12%, transparent)'
                            : 'color-mix(in srgb, var(--accent) 12%, transparent)',
                        }}
                      >
                        {run.status}
                      </span>
                      <span className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>{run.mode}</span>
                    </div>
                    {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                    <InvestigationRunFact label="Source" value={run.source} />
                    <InvestigationRunFact label="Policy version" value={run.policy_version} />
                    <InvestigationRunFact label="Enforcement" value={enforcement} />
                    <InvestigationRunFact label="Created" value={formatInvestigationTimestamp(run.inserted_at)} />
                    <InvestigationRunFact label="Started" value={formatInvestigationTimestamp(run.started_at)} />
                    <InvestigationRunFact label="Completed" value={formatInvestigationTimestamp(run.completed_at)} />
                  </div>
                </button>

                {expanded && (
                  <div className="p-3 border-t" style={{ borderColor: 'var(--hairline)', backgroundColor: 'var(--bg)' }}>
                    <div className="text-[10px] uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Evidence</div>
                    {evidenceState?.loading && (
                      <div className="text-xs flex items-center gap-2" style={{ color: 'var(--muted)' }}>
                        <RefreshCw size={12} className="animate-spin" /> Loading evidence…
                      </div>
                    )}
                    {evidenceState?.error && (
                      <div className="text-xs" style={{ color: 'var(--med)' }}>{evidenceState.error}</div>
                    )}
                    {evidenceState && !evidenceState.loading && !evidenceState.error && evidenceState.data.length === 0 && (
                      <div className="text-xs" style={{ color: 'var(--muted)' }}>No evidence recorded.</div>
                    )}
                    {evidenceState?.data.map(evidence => (
                      <div key={evidence.id} className="mb-3 last:mb-0 min-w-0">
                        <div className="flex items-start justify-between gap-2 text-[11px]">
                          <div className="min-w-0">
                            <div className="font-medium truncate" style={{ color: 'var(--fg-2)' }}>{evidence.kind}</div>
                            <div className="truncate" style={{ color: 'var(--muted)' }}>{evidence.source}</div>
                          </div>
                          <span className="text-right flex-shrink-0" style={{ color: 'var(--subtle)' }}>
                            {formatInvestigationTimestamp(evidence.observed_at)}
                          </span>
                        </div>
                        {evidence.kind === 'detector_observation_consensus' ? (
                          <DetectorObservationEvidence payload={evidence.payload} />
                        ) : (
                          <InvestigationEvidenceJson payload={evidence.payload} />
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function InvestigationRunFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <span style={{ color: 'var(--subtle)' }}>{label}: </span>
      <span className="font-mono break-words" style={{ color: 'var(--fg-2)' }}>{value || '—'}</span>
    </div>
  );
}

function formatInvestigationTimestamp(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function safeInvestigationJson(payload?: Record<string, unknown>): string {
  try {
    return JSON.stringify(payload || {}, null, 2);
  } catch (_error) {
    return '{\n  "unavailable": true\n}';
  }
}

function InvestigationEvidenceJson({ payload }: { payload?: Record<string, unknown> }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={() => setExpanded(current => !current)}
        className="inline-flex items-center gap-1 text-[11px] rounded px-1.5 py-0.5 hover:brightness-125"
        style={{ color: 'var(--accent)' }}
        aria-expanded={expanded}
      >
        {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {expanded ? 'Hide payload' : 'View payload'}
      </button>
      {expanded && (
        <pre
          className="mt-1 rounded-md border p-2 font-mono text-[11px] overflow-auto max-h-72 whitespace-pre-wrap break-words"
          style={{
            color: 'var(--fg-2)',
            backgroundColor: 'var(--surface-2)',
            borderColor: 'var(--hairline)',
          }}
        >
          {safeInvestigationJson(payload)}
        </pre>
      )}
    </div>
  );
}

function detectorDecisionColor(decision: string): string {
  if (decision === 'malicious') return 'var(--crit)';
  if (decision === 'suspicious') return 'var(--med)';
  if (decision === 'benign') return 'var(--emerald-400)';
  return 'var(--muted)';
}

function detectorMetric(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : '—';
}

function DetectorObservationEvidence({ payload }: { payload?: Record<string, unknown> }) {
  const envelope = asRecord(payload?.envelope);
  const consensus = asRecord(envelope.consensus);
  const context = asRecord(envelope.validation_context);
  const observations = asRecordArray(envelope.observations);
  const producerAttestations = asRecordArray(payload?.producer_attestations);
  const decision = asText(consensus.decision, 'unknown').toLowerCase();
  const enforcement = asText(payload?.enforcement, 'disabled');
  const consensusClaim = asText(payload?.consensus_claim, 'producer_assertion');
  const contractHash = asText(payload?.contract_hash_sha256);

  return (
    <div className="mt-2 space-y-2">
      <div
        className="rounded-lg border p-2.5"
        style={{ borderColor: 'var(--hairline)', backgroundColor: 'var(--surface-2)' }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Layers size={14} style={{ color: detectorDecisionColor(decision) }} />
            <span className="text-xs font-semibold capitalize" style={{ color: detectorDecisionColor(decision) }}>
              {decision}
            </span>
            <span className="text-[10px]" style={{ color: 'var(--muted)' }}>
              {asText(consensus.strategy, 'consensus')} · {observations.length} detector{observations.length === 1 ? '' : 's'}
            </span>
          </div>
          <span
            className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide"
            style={{
              color: enforcement === 'disabled' ? 'var(--muted)' : 'var(--crit)',
              backgroundColor: 'var(--bg)',
            }}
          >
            enforcement {enforcement}
          </span>
        </div>

        <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
          <InvestigationRunFact label="Score" value={detectorMetric(consensus.score)} />
          <InvestigationRunFact label="Threshold" value={detectorMetric(consensus.threshold)} />
          <InvestigationRunFact label="Confidence" value={detectorMetric(consensus.confidence)} />
          <InvestigationRunFact label="State" value={consensus.degraded === true ? 'degraded' : 'observed'} />
        </div>

        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[10px]" style={{ color: 'var(--subtle)' }}>
          <span>Evidence: {asText(context.evidence_class, 'unknown')}</span>
          <span>Claim: {asText(context.claim_scope, 'unknown')}</span>
          <span title="Consensus was supplied by the producer and was not independently recomputed by Tamandua">
            Consensus: {consensusClaim}
          </span>
          <span>Registry: {producerAttestations.length > 0 ? `${producerAttestations.length} attested` : 'unattested'}</span>
          {contractHash && <span className="font-mono">Contract: {contractHash.slice(0, 12)}…</span>}
        </div>
      </div>

      {producerAttestations.length > 0 && (
        <div className="flex flex-wrap gap-1.5" aria-label="Attested detector producers">
          {producerAttestations.map((attestation, index) => {
            const producerId = asText(attestation.producer_id, `producer-${index + 1}`);
            const attestationHash = asText(attestation.attestation_sha256);
            return (
              <span
                key={`${producerId}-${index}`}
                className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-mono"
                style={{
                  color: 'var(--emerald-400)',
                  borderColor: 'color-mix(in srgb, var(--emerald-400) 35%, var(--hairline))',
                  backgroundColor: 'color-mix(in srgb, var(--emerald-400) 8%, transparent)',
                }}
                title={attestationHash || 'Registry attestation'}
              >
                <ShieldCheck size={11} />
                {producerId}{attestationHash ? ` · ${attestationHash.slice(0, 10)}…` : ''}
              </span>
            );
          })}
        </div>
      )}

      {observations.map((observation, index) => {
        const provenance = asRecord(observation.provenance);
        const ensembleVotes = asRecordArray(observation.ensemble_votes);
        const detectorDecision = asText(observation.decision, 'unknown').toLowerCase();
        const detectorId = asText(observation.detector_id, `detector-${index + 1}`);

        return (
          <div
            key={`${detectorId}-${index}`}
            className="rounded-md border p-2 text-[10px]"
            style={{ borderColor: 'var(--hairline)', backgroundColor: 'var(--bg)' }}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="font-mono font-medium truncate" style={{ color: 'var(--fg-2)' }}>{detectorId}</div>
                <div className="truncate" style={{ color: 'var(--muted)' }}>
                  {asText(observation.detector_type, 'detector')} · {asText(observation.detector_version, 'unknown version')}
                </div>
              </div>
              <span className="capitalize" style={{ color: detectorDecisionColor(detectorDecision) }}>
                {detectorDecision}
              </span>
            </div>
            <div className="mt-1 grid grid-cols-2 sm:grid-cols-4 gap-2">
              <InvestigationRunFact label="Status" value={asText(observation.status, 'unknown')} />
              <InvestigationRunFact label="Score" value={detectorMetric(observation.score)} />
              <InvestigationRunFact label="Confidence" value={detectorMetric(observation.confidence)} />
              <InvestigationRunFact label="Latency" value={typeof observation.latency_ms === 'number' ? `${observation.latency_ms} ms` : '—'} />
            </div>
            {(observation.runtime_lane || observation.model_contract_id || observation.decision_mode) && (
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1" style={{ color: 'var(--subtle)' }}>
                <span>Lane: {asText(observation.runtime_lane, 'not reported')}</span>
                <span>Mode: {asText(observation.decision_mode, 'not reported')}</span>
                <span className="font-mono">Contract: {asText(observation.model_contract_id, 'not reported')}</span>
              </div>
            )}
            {ensembleVotes.length > 0 && (
              <div className="mt-1.5 space-y-1" aria-label={`Ensemble votes for ${detectorId}`}>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>
                  Ensemble votes ({ensembleVotes.length})
                </div>
                {ensembleVotes.map((vote, voteIndex) => {
                  const voteDecision = asText(vote.decision, 'unknown').toLowerCase();
                  return (
                    <div
                      key={`${asText(vote.detector_id, 'engine')}-${voteIndex}`}
                      className="flex flex-wrap items-center justify-between gap-2 rounded border px-1.5 py-1"
                      style={{ borderColor: 'var(--hairline)' }}
                    >
                      <span className="font-mono" style={{ color: 'var(--fg-2)' }}>
                        {asText(vote.detector_id, `engine-${voteIndex + 1}`)}
                      </span>
                      <span style={{ color: detectorDecisionColor(voteDecision) }}>
                        {voteDecision} · {asText(vote.status, 'unknown')} · score {detectorMetric(vote.score)}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
            {(provenance.source || provenance.revision) && (
              <div className="mt-1 truncate" style={{ color: 'var(--subtle)' }}>
                Provenance: {asText(provenance.source, 'unknown')} @ {asText(provenance.revision, 'unknown')}
              </div>
            )}
          </div>
        );
      })}

      <InvestigationEvidenceJson payload={payload} />
    </div>
  );
}

// Proof Card Section Component
function ProofCardSection({
  proofData,
  isLoading,
  error,
  onCopyToClipboard,
  copiedField
}: {
  proofData: ProofAttestation | null;
  isLoading: boolean;
  error: string | null;
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
  const actionTarget = (action: ResponseActionRecord): string | null => {
    const params = asRecord(action.parameters);
    const target =
      params.device_name ||
      params.device_id ||
      params.domain ||
      params.ip ||
      params.path ||
      params.file_path ||
      params.pid ||
      params.package_name ||
      params.command;

    return target == null ? null : asText(target);
  };

  const actionResult = (action: ResponseActionRecord): string | null => {
    const result = asRecord(action.result);
    const flows = Array.isArray(result.flows) ? result.flows : [];
    const flow = asRecord(flows[0]);
    if (flow.type === 'dns_forwarder_summary') {
      const observed = Number(flow.queries_observed ?? 0);
      const blocked = Number(flow.queries_blocked ?? 0);
      const lastQuery = flow.last_query ? `, last ${asText(flow.last_query)}` : '';
      return `DNS flows: ${observed} observed, ${blocked} blocked${lastQuery}`;
    }
    if (result.coverage === 'dns_forwarder_counters_only_no_pcap') {
      return 'DNS forwarder counters only; PCAP unavailable';
    }
    const summary =
      result.summary ||
      result.message ||
      result.reason ||
      result.output ||
      result.status ||
      result.error;

    if (summary == null) return null;
    const text = asText(summary).trim();
    return text ? (text.length > 96 ? `${text.slice(0, 93)}...` : text) : null;
  };

  const actionCommand = (action: ResponseActionRecord): AgentCommandRecord | null => {
    const command = asRecord(action.command) as Partial<AgentCommandRecord>;
    return command.id ? command as AgentCommandRecord : null;
  };

  const actionCommandSummary = (action: ResponseActionRecord): string | null => {
    const command = actionCommand(action);
    if (!command) return null;
    const status = normalizeCommandStatus(command.status);
    const timestamp = commandTimestamp(command);
    const runtime = commandRuntime(command);
    const result = commandResultSummary(command);
    return [
      `${humanizeDetectionType(commandType(command))} ${status}`,
      runtimeLabel(runtime),
      timestamp ? new Date(timestamp).toLocaleString() : null,
      result,
    ].filter(Boolean).join(' / ');
  };

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
              {actionTarget(action) && (
                <div className="mt-1 text-[10px] truncate" style={{ color: 'var(--muted)' }}>
                  Target: {actionTarget(action)}
                </div>
              )}
              {actionResult(action) && (
                <Tooltip content={actionResult(action) || ''}>
                  <div className="mt-1 text-[10px] truncate" style={{ color: 'var(--subtle)' }}>
                    Result: {actionResult(action)}
                  </div>
                </Tooltip>
              )}
              {actionCommand(action) && (
                <Tooltip content={actionCommandSummary(action) || ''}>
                  <div className="mt-1 flex items-center justify-between gap-2 text-[10px]" style={{ color: 'var(--muted)' }}>
                    <span className="truncate">
                      Command: <span className="font-mono" style={{ color: 'var(--fg-2)' }}>{actionCommand(action)?.id}</span>
                    </span>
                    <span className="shrink-0 rounded px-1.5 py-0.5 uppercase" style={commandStatusStyle(normalizeCommandStatus(actionCommand(action)?.status))}>
                      {normalizeCommandStatus(actionCommand(action)?.status)}
                    </span>
                  </div>
                </Tooltip>
              )}
              {action.rollback && (
                <Tooltip content={rollbackLabel(action.rollback)}>
                  <div className="mt-1 text-[10px] truncate" style={{ color: action.rollback.available ? 'var(--low)' : 'var(--muted)' }}>
                    {action.rollback.available ? 'Rollback available' : 'Rollback unavailable'}{action.rollback.action_type || action.rollback.actionType ? ` · ${humanizeDetectionType(asText(firstPresent(action.rollback.action_type, action.rollback.actionType)))}` : ''}
                  </div>
                </Tooltip>
              )}
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
      file_path: { label: 'Path', color: 'var(--muted)', bg: 'var(--surface-2)' },
      package: { label: 'Package', color: 'var(--accent)', bg: 'rgba(59, 130, 246, 0.12)' },
      app: { label: 'App', color: 'var(--emerald-400)', bg: 'var(--emerald-glow)' },
      indicator: { label: 'Signal', color: 'var(--muted)', bg: 'var(--surface-2)' }
    };
    return configs[type] || configs.indicator;
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
