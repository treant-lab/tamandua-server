import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Clock,
  Filter,
  Search,
  Calendar,
  Monitor,
  AlertTriangle,
  Terminal,
  FileText,
  Network,
  HardDrive,
  ChevronRight,
  Download,
  ZoomIn,
  ZoomOut,
  GitBranch,
  Link2,
  Loader2,
  RefreshCw,
  CheckSquare,
  Square,
  ArrowRight,
} from 'lucide-react'
import { cn, formatDate, safeCapitalize, severityColor } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useEventStream, type StreamEvent } from '@/hooks/useSocket'
import axios from 'axios'

// Types
interface TimelineEvent {
  id: string
  timestamp: string
  eventType: 'process' | 'file' | 'network' | 'registry' | 'alert' | 'dns'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  agentId: string
  hostname: string
  details: Record<string, unknown>
  relatedEvents?: string[]
  correlationEvidence?: RelatedEvidence[]
  telemetryQuality?: TelemetryQuality
  telemetryContract?: TelemetryContract
  entities?: Record<string, Record<string, unknown>>
  mitreTechniques?: string[]
}

interface RelatedEvidence {
  id: string
  score: number
  reasons: string[]
  relationTypes: string[]
  scoring?: ScoringExplanation
}

interface ScoringExplanation {
  version?: string
  threshold?: number
  score?: number
  rawScore?: number
  decision?: string
  confidence?: string
  requirements?: string[]
  strongEvidenceCount?: number
  contextEvidenceCount?: number
  contributingEvidence?: Array<{
    type: string
    weight: number
    reason: string
    strength: string
  }>
  suppressedEvidence?: string[]
}

interface TelemetryQuality {
  score: number
  level: 'good' | 'partial' | 'poor'
  present: string[]
  missing: string[]
}

interface TelemetryContract {
  schemaVersion: string
  category: string
  requiredFields: string[]
  correlationReady: boolean
}

interface TimelineFilter {
  eventTypes: string[]
  agents: Array<{ id: string; hostname: string }>
  severities: string[]
}

interface TimelinePageProps {
  events?: TimelineEvent[]
  filters?: TimelineFilter
  incidentId?: string
}

function apiErrorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status
    const data = error.response?.data as { message?: string; error?: string } | undefined
    const detail = data?.message || data?.error || error.message
    return status ? `${fallback} (HTTP ${status}${detail ? `: ${detail}` : ''})` : `${fallback}: ${detail || 'network error'}`
  }

  return error instanceof Error ? `${fallback}: ${error.message}` : fallback
}

function timelinePartialMessage(meta: Record<string, unknown> | undefined): string | null {
  if (!meta?.partial) return null

  const reason = String(
    meta.partialReason ||
    meta.correlationPartialReason ||
    meta.queryPartialReason ||
    'partial_result'
  )

  const labels: Record<string, string> = {
    correlation_timeout: 'Correlation analysis timed out for this event window. Events are loaded, but related-event scoring is partial.',
    query_timeout: 'Timeline event query timed out. Results may be incomplete for this window.',
    partial_result: 'Timeline data loaded with partial correlation metadata.',
  }

  return labels[reason] || `Timeline data loaded with partial metadata (${reason}).`
}

interface CorrelationResult {
  id: string
  correlationId?: string
  incidentId?: string
  name: string
  events: TimelineEvent[]
  startTime: string
  endTime: string
  attackChain: string[]
  riskScore: number
  scoreVersion?: string
  scoringVersion?: string
  correlationVersion?: string
  engineVersion?: string
  modelVersion?: string
  persistedAt?: string
  correlations?: Array<{
    source: string
    target: string
    score: number
    reasons: string[]
    relationTypes: string[]
    scoring?: ScoringExplanation
  }>
  scoringPolicy?: {
    version: string
    threshold: number
    mode: string
    requirements: string[]
  }
  incidentCandidates?: Array<{
    id: string
    title: string
    score: number
    severity: string
    eventCount: number
    relationTypes: string[]
    supportingEntities: string[]
  }>
  persistedIncidentCandidates?: PersistedIncidentCandidate[]
  campaignCandidates?: Array<{
    id: string
    title: string
    score: number
    eventCount: number
    campaignSignals: string[]
  }>
  entityGraph?: {
    nodes?: unknown[]
    edges?: unknown[]
    stats?: Record<string, number>
  }
  evidenceSummary?: Array<{ type: string; count: number }>
  telemetryGaps?: Array<{ field: string; count: number }>
  analyzedEventCount?: number
}

interface Storyline {
  processId: string
  processName: string
  events: TimelineEvent[]
  childProcesses: Storyline[]
}

function normalizeProcessStoryline(raw: Record<string, unknown>, processId: string, events: TimelineEvent[]): Storyline {
  const targetPid = String(raw.target_pid ?? raw.process_id ?? processId)
  const chain = Array.isArray(raw.process_chain) ? raw.process_chain as Array<Record<string, unknown>> : []
  const timeline = Array.isArray(raw.timeline) ? raw.timeline as Array<Record<string, unknown>> : []
  const chainProcess = chain.find((entry) => String(entry.pid ?? entry.process_id ?? '') === targetPid) || chain[0]
  const timelineIds = new Set(timeline.map((entry) => String(entry.id ?? entry.event_id ?? '')).filter(Boolean))

  return {
    processId: targetPid,
    processName: String(chainProcess?.name ?? chainProcess?.process_name ?? chainProcess?.image ?? `Process ${targetPid}`),
    events: events.filter((event) => timelineIds.has(event.id)),
    childProcesses: [],
  }
}

interface ReadinessCategory {
  category: string
  eventCount: number
  status: 'good' | 'partial' | 'poor' | 'missing'
  averageQuality: number
  missingFields: Array<{ field: string; count: number }>
}

interface ReadinessAgent {
  agentId: string
  hostname: string
  totalEvents: number
  categories: ReadinessCategory[]
}

interface PersistedIncidentCandidate {
  id: string
  title: string
  status: string
  score: number
  severity: string
  eventIds: string[]
  supportingEntities: string[]
  scoringVersion: string
}

const defaultFilters: TimelineFilter = {
  eventTypes: ['process', 'file', 'network', 'registry', 'alert', 'dns'],
  agents: [],
  severities: ['critical', 'high', 'medium', 'low', 'info'],
}

const eventTypeConfig: Record<string, { icon: React.ElementType; color: string }> = {
  process: { icon: Terminal, color: 'text-[var(--emerald-400)] bg-[var(--emerald-400)]/10' },
  file: { icon: FileText, color: 'text-blue-400 bg-blue-400/10' },
  network: { icon: Network, color: 'text-purple-400 bg-purple-400/10' },
  registry: { icon: HardDrive, color: 'text-orange-400 bg-orange-400/10' },
  alert: { icon: AlertTriangle, color: 'text-red-400 bg-red-400/10' },
  dns: { icon: Network, color: 'text-cyan-400 bg-cyan-400/10' },
}

const telemetryQualityColor: Record<string, string> = {
  good: 'bg-emerald-500/15 text-emerald-300',
  partial: 'bg-yellow-500/15 text-yellow-300',
  poor: 'bg-red-500/15 text-red-300',
}

function normalizeScore100(score: number | string | undefined | null): number {
  const numeric = Number(score || 0)
  if (Number.isNaN(numeric)) return 0
  return numeric <= 1 ? Math.round(numeric * 100) : Math.round(numeric)
}

function getScoreVersionLabel(result: CorrelationResult): string {
  return result.scoringPolicy?.version || result.scoreVersion || result.scoringVersion || result.correlationVersion || result.engineVersion || result.modelVersion || 'unversioned'
}

function getCorrelationResultId(result: CorrelationResult): string | null {
  return result.correlationId || result.id || null
}

// Map DB event_type values to the frontend category names
function normalizeEventType(raw: string): TimelineEvent['eventType'] {
  if (!raw) return 'process'
  const t = raw.toLowerCase()
  if (t.startsWith('process')) return 'process'
  if (t.startsWith('file')) return 'file'
  if (t.startsWith('network')) return 'network'
  if (t.startsWith('registry')) return 'registry'
  if (t.startsWith('dns')) return 'dns'
  if (t === 'alert') return 'alert'
  return 'process'
}

// Build a human-readable title from event_type and payload
function buildEventTitle(eventType: string, payload: Record<string, unknown>): string {
  const t = (eventType || '').toLowerCase()
  if (t.startsWith('process')) {
    const name = payload?.name || payload?.process_name || 'Unknown'
    return `Process: ${name}`
  }
  if (t.startsWith('file')) {
    const path = String(payload?.path || payload?.file_path || 'Unknown')
    const basename = path.split(/[/\\]/).pop() || path
    return `File: ${basename}`
  }
  if (t.startsWith('network')) {
    const ip = payload?.remote_ip || payload?.dest_ip || 'Unknown'
    const port = payload?.remote_port || payload?.dest_port || ''
    return `Network: ${ip}:${port}`
  }
  if (t.startsWith('dns')) {
    const domain = payload?.domain || payload?.query || 'Unknown'
    return `DNS: ${domain}`
  }
  if (t.startsWith('registry')) {
    const key = payload?.key || payload?.key_path || payload?.registry_key || 'Unknown'
    return `Registry: ${key}`
  }
  if (t === 'alert') {
    return String(payload?.title || payload?.rule_name || 'Alert')
  }
  // Fallback: humanize the event_type
  return eventType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

// Build a description from event_type and payload
function buildEventDescription(eventType: string, payload: Record<string, unknown>): string {
  const t = (eventType || '').toLowerCase()
  if (t.startsWith('process')) {
    const parts = [payload?.path, payload?.command_line || payload?.cmdline]
    const user = payload?.user
    if (user) parts.push(`(${user})`)
    return parts.filter(Boolean).join(' ') || ''
  }
  if (t.startsWith('file')) {
    const op = payload?.operation || eventType
    return `${op}: ${payload?.path || payload?.file_path || ''}`
  }
  if (t.startsWith('network')) {
    const proto = payload?.protocol || 'TCP'
    const dir = payload?.direction || ''
    return `${proto} ${dir} ${payload?.local_ip || ''}:${payload?.local_port || ''} -> ${payload?.remote_ip || ''}:${payload?.remote_port || ''}`.trim()
  }
  if (t.startsWith('dns')) {
    const parts = []
    if (payload?.query_type) parts.push(`Type: ${payload.query_type}`)
    if (payload?.response) parts.push(`Response: ${payload.response}`)
    return parts.join(' | ')
  }
  if (t === 'alert') {
    return String(payload?.description || payload?.message || '')
  }
  return ''
}

function normalizeRelatedIds(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value
    .map((item) => {
      if (typeof item === 'string') return item
      if (item && typeof item === 'object' && 'id' in item) return String((item as { id: unknown }).id)
      return ''
    })
    .filter(Boolean)
}

function normalizeCorrelationEvidence(value: unknown): RelatedEvidence[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
    .map((item) => ({
      id: String(item.id || ''),
      score: Number(item.score || 0),
      reasons: Array.isArray(item.reasons) ? item.reasons.map(String) : [],
      relationTypes: Array.isArray(item.relationTypes) ? item.relationTypes.map(String) : [],
      scoring: normalizeScoringExplanation(item.scoring),
    }))
    .filter((item) => item.id)
}

function normalizeScoringExplanation(value: unknown): ScoringExplanation | undefined {
  if (!value || typeof value !== 'object') return undefined
  const scoring = value as Record<string, unknown>
  return {
    version: String(scoring.version || ''),
    threshold: Number(scoring.threshold || 0),
    score: Number(scoring.score || 0),
    rawScore: Number(scoring.rawScore || scoring.raw_score || 0),
    decision: String(scoring.decision || ''),
    confidence: String(scoring.confidence || ''),
    requirements: Array.isArray(scoring.requirements) ? scoring.requirements.map(String) : [],
    strongEvidenceCount: Number(scoring.strongEvidenceCount || scoring.strong_evidence_count || 0),
    contextEvidenceCount: Number(scoring.contextEvidenceCount || scoring.context_evidence_count || 0),
    contributingEvidence: Array.isArray(scoring.contributingEvidence)
      ? scoring.contributingEvidence.map((item) => {
          const evidence = item as Record<string, unknown>
          return {
            type: String(evidence.type || ''),
            weight: Number(evidence.weight || 0),
            reason: String(evidence.reason || ''),
            strength: String(evidence.strength || ''),
          }
        })
      : [],
    suppressedEvidence: Array.isArray(scoring.suppressedEvidence) ? scoring.suppressedEvidence.map(String) : [],
  }
}

function normalizeTelemetryQuality(value: unknown): TelemetryQuality | undefined {
  if (!value || typeof value !== 'object') return undefined
  const quality = value as Record<string, unknown>
  const level = String(quality.level || 'partial') as TelemetryQuality['level']
  return {
    score: Number(quality.score || 0),
    level: ['good', 'partial', 'poor'].includes(level) ? level : 'partial',
    present: Array.isArray(quality.present) ? quality.present.map(String) : [],
    missing: Array.isArray(quality.missing) ? quality.missing.map(String) : [],
  }
}

function normalizeTelemetryContract(value: unknown): TelemetryContract | undefined {
  if (!value || typeof value !== 'object') return undefined
  const contract = value as Record<string, unknown>
  return {
    schemaVersion: String(contract.schema_version || contract.schemaVersion || ''),
    category: String(contract.category || 'unknown'),
    requiredFields: Array.isArray(contract.required_fields)
      ? contract.required_fields.map(String)
      : Array.isArray(contract.requiredFields)
        ? contract.requiredFields.map(String)
        : [],
    correlationReady: Boolean(contract.correlation_ready ?? contract.correlationReady),
  }
}

/**
 * Normalize an event from any source (Inertia SSR, API response) into the TimelineEvent shape.
 * Handles both camelCase (API) and snake_case (raw DB) field names.
 */
function normalizeEvent(raw: Record<string, unknown>): TimelineEvent {
  // Already well-formed (from the new timeline API)
  if (raw.eventType && raw.title && raw.hostname) {
    return {
      id: String(raw.id || ''),
      timestamp: String(raw.timestamp || ''),
      eventType: raw.eventType as TimelineEvent['eventType'],
      severity: (raw.severity as TimelineEvent['severity']) || 'info',
      title: String(raw.title || ''),
      description: String(raw.description || ''),
      agentId: String(raw.agentId || raw.agent_id || ''),
      hostname: String(raw.hostname || 'Unknown'),
      details: (raw.details || raw.payload || {}) as Record<string, unknown>,
      relatedEvents: normalizeRelatedIds(raw.relatedEvents),
      correlationEvidence: normalizeCorrelationEvidence(raw.correlationEvidence),
      telemetryQuality: normalizeTelemetryQuality(raw.telemetryQuality),
      telemetryContract: normalizeTelemetryContract(raw.telemetryContract),
      entities: (raw.entities || {}) as Record<string, Record<string, unknown>>,
      mitreTechniques: (raw.mitreTechniques || []) as string[],
    }
  }

  // Legacy Inertia-provided event or raw DB shape
  const eventType = String(raw.eventType || raw.event_type || 'unknown')
  const payload = (raw.payload || raw.details || {}) as Record<string, unknown>
  const agentId = String(raw.agentId || raw.agent_id || '')
  const hostname = String(raw.hostname || raw.agent_hostname || 'Unknown')

  return {
    id: String(raw.id || ''),
    timestamp: String(raw.timestamp || ''),
    eventType: normalizeEventType(eventType),
    severity: (String(raw.severity || 'info')) as TimelineEvent['severity'],
    title: String(raw.title || raw.summary || buildEventTitle(eventType, payload)),
    description: String(raw.description || buildEventDescription(eventType, payload)),
    agentId,
    hostname,
    details: payload,
    relatedEvents: normalizeRelatedIds(raw.relatedEvents),
    correlationEvidence: normalizeCorrelationEvidence(raw.correlationEvidence),
    telemetryQuality: normalizeTelemetryQuality(raw.telemetryQuality),
    telemetryContract: normalizeTelemetryContract(raw.telemetryContract),
    entities: (raw.entities || {}) as Record<string, Record<string, unknown>>,
    mitreTechniques: (raw.mitreTechniques || []) as string[],
  }
}

/**
 * Convert a StreamEvent (from WebSocket) into the TimelineEvent shape used by the page.
 */
function streamEventToTimeline(se: StreamEvent): TimelineEvent {
  const eventType = normalizeEventType(se.eventType)
  const payload = se.payload || {}
  return {
    id: se.id,
    timestamp: typeof se.timestamp === 'number' ? new Date(se.timestamp).toISOString() : String(se.timestamp),
    eventType,
    severity: se.severity || 'info',
    title: se.summary || buildEventTitle(se.eventType, payload),
    description: buildEventDescription(se.eventType, payload),
    agentId: se.agentId || '',
    hostname: String(payload.hostname || payload.agent_hostname || 'Unknown'),
    details: payload,
    relatedEvents: [],
    correlationEvidence: [],
    mitreTechniques: se.detections?.flatMap(d => d.mitreTechniques || []) || [],
  }
}

export default function Timeline({ events = [], filters, incidentId }: TimelinePageProps) {
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTypes, setSelectedTypes] = useState<string[]>([])
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([])
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d' | 'custom'>('24h')
  const [showFilters, setShowFilters] = useState(false)
  const [zoomLevel, setZoomLevel] = useState(1)

  // API state - normalize Inertia-provided events on init
  const [eventList, setEventList] = useState<TimelineEvent[]>(() =>
    (events || []).map((e: any) => normalizeEvent(e))
  )
  const [loading, setLoading] = useState(false)
  const [correlating, setCorrelating] = useState(false)
  const [correlationResult, setCorrelationResult] = useState<CorrelationResult | null>(null)
  const [storyline, setStoryline] = useState<Storyline | null>(null)
  const [selectedEventIds, setSelectedEventIds] = useState<Set<string>>(new Set())
  const [selectionMode, setSelectionMode] = useState(false)
  const [readinessAgents, setReadinessAgents] = useState<ReadinessAgent[]>([])
  const [persistedCandidates, setPersistedCandidates] = useState<PersistedIncidentCandidate[]>([])
  const [timelineError, setTimelineError] = useState<string | null>(null)

  // Real-time WebSocket event stream (all agents)
  const {
    connectionState,
    events: streamEvents,
    clearEvents: clearStreamEvents,
    pauseStream,
    resumeStream,
    isPaused,
  } = useEventStream()

  const agentHostnameById = useMemo(() => {
    return new Map((filters?.agents || []).map(agent => [agent.id, agent.hostname]))
  }, [filters?.agents])

  // Merge API/Inertia events with real-time stream events, deduplicating by id
  const allEvents = useMemo(() => {
    const merged = [...eventList]
    streamEvents.forEach(se => {
      if (!merged.find(e => e.id === se.id)) {
        merged.unshift(streamEventToTimeline(se))
      }
    })
    return merged.slice(0, 1000).map(event => {
      const resolvedHostname = agentHostnameById.get(event.agentId)
      if (resolvedHostname && (!event.hostname || event.hostname === 'Unknown')) {
        return { ...event, hostname: resolvedHostname }
      }
      return event
    })
  }, [eventList, streamEvents, agentHostnameById])

  const filterOptions: TimelineFilter = {
    eventTypes: filters?.eventTypes || defaultFilters.eventTypes,
    agents: filters?.agents || defaultFilters.agents,
    severities: filters?.severities || defaultFilters.severities,
  }

  // Calculate time range bounds
  const getTimeRangeBounds = useCallback(() => {
    const now = new Date()
    const ranges: Record<string, number> = {
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
    }
    const ms = ranges[timeRange] || ranges['24h']
    return {
      start: new Date(now.getTime() - ms).toISOString(),
      end: now.toISOString(),
    }
  }, [timeRange])

  // Fetch timeline events from API
  const fetchEvents = useCallback(async () => {
    setLoading(true)
    try {
      const { start, end } = getTimeRangeBounds()
      const params: Record<string, string> = {
        start_time: start,
        end_time: end,
      }
      if (selectedTypes.length > 0) {
        params.event_types = selectedTypes.join(',')
      }
      if (selectedAgents.length > 0) {
        params.agent_ids = selectedAgents.join(',')
      }
      if (selectedSeverities.length > 0) {
        params.severities = selectedSeverities.join(',')
      }

      const response = await axios.get('/api/v1/timeline', { params })
      const data = response.data?.data
      if (Array.isArray(data)) {
        setEventList(data.map((e: any) => normalizeEvent(e)))
      } else {
        setEventList([])
      }
      setTimelineError(timelinePartialMessage(response.data?.correlationMeta))

      const [readinessResponse, candidatesResponse] = await Promise.allSettled([
        axios.get('/api/v1/timeline/readiness', { params: { hours: timeRange === '7d' ? '168' : '24' } }),
        axios.get('/api/v1/timeline/incident-candidates', { params: { limit: '10' } }),
      ])

      if (readinessResponse.status === 'fulfilled') {
        const readiness = readinessResponse.value.data?.data
        setReadinessAgents(Array.isArray(readiness) ? readiness : [])
      }

      if (candidatesResponse.status === 'fulfilled') {
        const candidates = candidatesResponse.value.data?.data
        setPersistedCandidates(Array.isArray(candidates) ? candidates : [])
      }
    } catch (error) {
      setTimelineError(apiErrorMessage(error, 'Timeline data did not load cleanly'))
      logger.error('Failed to fetch timeline events:', error)
    } finally {
      setLoading(false)
    }
  }, [getTimeRangeBounds, selectedTypes, selectedAgents, selectedSeverities, timeRange])

  // Correlate selected events
  const correlateEvents = useCallback(async () => {
    if (selectedEventIds.size < 2) return

    setCorrelating(true)
    try {
      const response = await axios.post('/api/v1/timeline/correlate', {
        event_ids: Array.from(selectedEventIds),
      })
      if (response.data?.data) {
        setCorrelationResult(response.data.data)
        setTimelineError(null)
        if (Array.isArray(response.data.data.persistedIncidentCandidates)) {
          setPersistedCandidates(response.data.data.persistedIncidentCandidates)
        }
      }
    } catch (error) {
      setTimelineError(apiErrorMessage(error, 'Timeline correlation failed'))
      logger.error('Failed to correlate events:', error)
    } finally {
      setCorrelating(false)
    }
  }, [selectedEventIds])

  // Build storyline for a process
  const buildStoryline = useCallback(async (processId: string, agentId: string) => {
    setLoading(true)
    try {
      const response = await axios.post('/api/v1/timeline/build', {
        pid: processId,
        agent_id: agentId,
      })
      if (response.data?.data) {
        setStoryline(normalizeProcessStoryline(response.data.data, processId, allEvents))
        setTimelineError(null)
      }
    } catch (error) {
      setTimelineError(apiErrorMessage(error, 'Process storyline build failed'))
      logger.error('Failed to build storyline:', error)
    } finally {
      setLoading(false)
    }
  }, [allEvents])

  // Toggle event selection
  const toggleEventSelection = (eventId: string) => {
    setSelectedEventIds(prev => {
      const next = new Set(prev)
      if (next.has(eventId)) {
        next.delete(eventId)
      } else {
        next.add(eventId)
      }
      return next
    })
  }

  // Clear selection
  const clearSelection = () => {
    setSelectedEventIds(new Set())
    setSelectionMode(false)
    setCorrelationResult(null)
  }

  // Fetch events on filter change
  useEffect(() => {
    if (timeRange !== 'custom') {
      fetchEvents()
    }
  }, [timeRange, selectedTypes, selectedAgents, selectedSeverities])

  // Initial fetch - always fetch from API for proper time-range filtering
  useEffect(() => {
    fetchEvents()
  }, [])

  const filteredEvents = allEvents.filter((event) => {
    if (selectedTypes.length > 0 && !selectedTypes.includes(event.eventType)) return false
    if (selectedAgents.length > 0 && !selectedAgents.includes(event.agentId)) return false
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(event.severity)) return false
    if (searchQuery) {
      const searchLower = searchQuery.toLowerCase()
      return (
        (event.title || '').toLowerCase().includes(searchLower) ||
        (event.description || '').toLowerCase().includes(searchLower) ||
        (event.hostname || '').toLowerCase().includes(searchLower)
      )
    }
    return true
  })

  const persistedEventIds = useMemo(() => new Set(eventList.map(event => event.id)), [eventList])
  const persistedFilteredCount = filteredEvents.filter(event => persistedEventIds.has(event.id)).length
  const liveFilteredCount = filteredEvents.length - persistedFilteredCount
  const eventsWithCorrelationEvidence = filteredEvents.filter(event =>
    (event.correlationEvidence?.length || 0) > 0 || (event.relatedEvents?.length || 0) > 0
  ).length
  const eventsWithTelemetryGaps = filteredEvents.filter(event =>
    Boolean(event.telemetryQuality && (
      event.telemetryQuality.missing.length > 0 ||
      event.telemetryQuality.level === 'partial' ||
      event.telemetryQuality.level === 'poor'
    ))
  ).length
  const readinessMissingOrPoor = readinessAgents.reduce((count, agent) => {
    return count + agent.categories.filter(category => category.status === 'missing' || category.status === 'poor').length
  }, 0)
  const openCandidateCount = persistedCandidates.filter(candidate =>
    candidate.status === 'candidate' || candidate.status === 'promoted'
  ).length

  const groupedEvents = filteredEvents.reduce((acc, event) => {
    const parsed = new Date(event.timestamp)
    const date = isNaN(parsed.getTime()) ? 'Unknown Date' : parsed.toDateString()
    if (!acc[date]) acc[date] = []
    acc[date].push(event)
    return acc
  }, {} as Record<string, TimelineEvent[]>)

  const toggleType = (type: string) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    )
  }

  return (
    <MainLayout title="Investigation Timeline">
      <Head title="Timeline - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {/* Time Range Selector */}
            <div className="flex items-center gap-1 bg-[var(--surface)] rounded-lg p-1 border border-[var(--hairline)]">
              {(['1h', '6h', '24h', '7d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={cn(
                    'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                    timeRange === range
                      ? 'bg-primary-600 text-white'
                      : 'text-[var(--muted)] hover:text-[var(--fg)]'
                  )}
                >
                  {range}
                </button>
              ))}
              <button
                onClick={() => setTimeRange('custom')}
                className={cn(
                  'flex items-center gap-1 px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                  timeRange === 'custom'
                    ? 'bg-primary-600 text-white'
                    : 'text-[var(--muted)] hover:text-[var(--fg)]'
                )}
              >
                <Calendar className="h-4 w-4" />
                Custom
              </button>
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center gap-1 bg-[var(--surface)] rounded-lg p-1 border border-[var(--hairline)]">
              <button
                onClick={() => setZoomLevel((prev) => Math.max(0.5, prev - 0.25))}
                className="p-1.5 text-[var(--muted)] hover:text-[var(--fg)]"
              >
                <ZoomOut className="h-4 w-4" />
              </button>
              <span className="text-sm text-[var(--muted)] px-2">{Math.round(zoomLevel * 100)}%</span>
              <button
                onClick={() => setZoomLevel((prev) => Math.min(2, prev + 0.25))}
                className="p-1.5 text-[var(--muted)] hover:text-[var(--fg)]"
              >
                <ZoomIn className="h-4 w-4" />
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Live Stream Controls */}
            <div className="flex items-center gap-3 mr-2">
              <span className={cn('inline-flex items-center gap-1.5 text-xs',
                connectionState === 'connected' ? 'text-[var(--emerald-400)]' : 'text-[var(--muted)]'
              )}>
                <span className={cn('h-1.5 w-1.5 rounded-full',
                  connectionState === 'connected' ? 'bg-[var(--emerald-400)] animate-pulse' : 'bg-[var(--muted)]'
                )} />
                {connectionState === 'connected' ? 'Live' : 'Connecting...'}
              </span>
              <button
                onClick={isPaused ? resumeStream : pauseStream}
                className="text-xs text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
              >
                {isPaused ? 'Resume' : 'Pause'}
              </button>
              <button
                onClick={clearStreamEvents}
                className="text-xs text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
              >
                Clear
              </button>
            </div>

            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
              <input
                type="text"
                placeholder="Search events..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-64 bg-[var(--surface)] border border-[var(--hairline)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>

            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                showFilters
                  ? 'bg-primary-600 text-white'
                  : 'bg-[var(--surface)] border border-[var(--hairline)] text-[var(--muted)] hover:bg-[var(--surface-hover)]'
              )}
            >
              <Filter className="h-4 w-4" />
              Filters
              {(selectedTypes.length > 0 || selectedAgents.length > 0 || selectedSeverities.length > 0) && (
                <span className="bg-primary-500 text-white text-xs px-1.5 py-0.5 rounded-full">
                  {selectedTypes.length + selectedAgents.length + selectedSeverities.length}
                </span>
              )}
            </button>

            <button className="flex items-center gap-2 bg-[var(--surface)] border border-[var(--hairline)] text-[var(--muted)] hover:bg-[var(--surface-hover)] px-3 py-2 rounded-lg text-sm">
              <Download className="h-4 w-4" />
              Export
            </button>

            <button
              onClick={fetchEvents}
              disabled={loading}
              className="flex items-center gap-2 bg-[var(--surface)] border border-[var(--hairline)] text-[var(--muted)] hover:bg-[var(--surface-hover)] px-3 py-2 rounded-lg text-sm disabled:opacity-50"
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            </button>
          </div>
        </div>

        {timelineError && (
          <div className="flex items-start justify-between gap-4 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-400" />
              <div>
                <p className="text-sm font-medium text-yellow-100">Timeline is running in degraded mode</p>
                <p className="mt-1 text-xs text-yellow-200/80">{timelineError}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setTimelineError(null)}
              className="text-xs text-yellow-200/70 hover:text-yellow-100"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="bg-[var(--surface)] border border-[var(--hairline)] rounded-xl p-3">
          <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <TimelineSignalStat
              label="Persisted events"
              value={persistedFilteredCount}
              detail={liveFilteredCount > 0 ? `${liveFilteredCount} live not yet persisted in this view` : 'Loaded from timeline API'}
            />
            <TimelineSignalStat
              label="Correlation evidence"
              value={eventsWithCorrelationEvidence}
              detail={eventsWithCorrelationEvidence > 0 ? 'Events with returned links/evidence' : 'No persisted evidence returned'}
            />
            <TimelineSignalStat
              label="Telemetry gaps"
              value={eventsWithTelemetryGaps}
              detail={eventsWithTelemetryGaps > 0 ? 'Events marked partial or missing fields' : 'No gaps returned'}
            />
            <TimelineSignalStat
              label="Scope"
              value={filteredEvents.length}
              detail={`${timeRange} window after filters`}
            />
            <TimelineSignalStat
              label="Data source gaps"
              value={readinessMissingOrPoor}
              detail={readinessAgents.length > 0 ? `${readinessAgents.length} agents with recent telemetry` : 'No readiness data returned'}
            />
            <TimelineSignalStat
              label="Incident candidates"
              value={openCandidateCount}
              detail={persistedCandidates.length > 0 ? 'Persisted from correlation runs' : 'No persisted candidates returned'}
            />
          </div>
        </div>

        {(persistedCandidates.length > 0 || readinessAgents.length > 0) && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="bg-[var(--surface)] border border-[var(--hairline)] rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-[var(--fg)]">Incident Candidates</h3>
                <span className="text-xs text-[var(--muted)]">persisted feedback loop</span>
              </div>
              <div className="space-y-2">
                {persistedCandidates.length > 0 ? (
                  persistedCandidates.slice(0, 4).map(candidate => (
                    <div key={candidate.id} className="p-2 rounded-lg bg-[var(--surface-active)]">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm text-[var(--fg)] truncate">{candidate.title}</p>
                        <span className="text-xs px-2 py-0.5 rounded bg-primary-900/50 text-primary-300">
                          {normalizeScore100(candidate.score)}
                        </span>
                      </div>
                      <p className="text-xs text-[var(--muted)] mt-1">
                        {candidate.status} - {candidate.scoringVersion} - {candidate.eventIds.length} events
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-[var(--muted)]">No incident candidates have been persisted yet.</p>
                )}
              </div>
            </div>

            <div className="bg-[var(--surface)] border border-[var(--hairline)] rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-[var(--fg)]">Data Sources Health</h3>
                <span className="text-xs text-[var(--muted)]">derived from recent events</span>
              </div>
              <div className="space-y-2">
                {readinessAgents.length > 0 ? (
                  readinessAgents.slice(0, 3).map(agent => {
                    const poor = agent.categories.filter(category => category.status === 'missing' || category.status === 'poor')
                    return (
                      <div key={agent.agentId} className="p-2 rounded-lg bg-[var(--surface-active)]">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-sm text-[var(--fg)] truncate">{agent.hostname}</p>
                          <span className="text-xs text-[var(--muted)]">{agent.totalEvents} events</span>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {poor.length > 0 ? (
                            poor.slice(0, 6).map(category => (
                              <span key={category.category} className="text-xs px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-300">
                                {category.category}: {category.status}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300">
                              no missing/poor categories
                            </span>
                          )}
                        </div>
                      </div>
                    )
                  })
                ) : (
                  <p className="text-xs text-[var(--muted)]">No recent telemetry readiness data returned.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Selection Mode Bar */}
        {selectionMode && (
          <div className="bg-primary-900/30 border border-primary-700 rounded-lg p-3 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link2 className="h-5 w-5 text-primary-400" />
              <span className="text-sm text-primary-300">
                <strong>{selectedEventIds.size}</strong> events selected for correlation
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={correlateEvents}
                disabled={selectedEventIds.size < 2 || correlating}
                className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium"
              >
                {correlating ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <GitBranch className="h-4 w-4" />
                )}
                Correlate Events
              </button>
              <button
                onClick={clearSelection}
                className="text-[var(--muted)] hover:text-[var(--fg)] px-3 py-2 text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Correlation Result */}
        {correlationResult && (
          <div className="bg-[var(--surface)] border border-[var(--hairline)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <GitBranch className="h-5 w-5 text-primary-400" />
                <h3 className="text-lg font-semibold text-[var(--fg)]">Correlation Result</h3>
                <span className={cn(
                  'px-2 py-0.5 rounded text-xs font-medium',
                  normalizeScore100(correlationResult.riskScore) >= 80 ? 'bg-red-500/20 text-red-400' :
                  normalizeScore100(correlationResult.riskScore) >= 50 ? 'bg-orange-500/20 text-orange-400' :
                  'bg-yellow-500/20 text-yellow-400'
                )}>
                  Risk Score: {normalizeScore100(correlationResult.riskScore)}
                </span>
                <span className="px-2 py-0.5 rounded text-xs bg-[var(--surface-active)] text-[var(--muted)]">
                  score {getScoreVersionLabel(correlationResult)}
                </span>
              </div>
              <button onClick={() => setCorrelationResult(null)} className="text-[var(--muted)] hover:text-[var(--fg)]">
                x
              </button>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Time Range</label>
                <p className="text-sm text-[var(--fg)] mt-1">
                  {formatDate(correlationResult.startTime)} - {formatDate(correlationResult.endTime)}
                </p>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Events Correlated</label>
                <p className="text-sm text-[var(--fg)] mt-1">{correlationResult.events.length} events</p>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Score Metadata</label>
                <p className="text-sm text-[var(--fg)] mt-1">
                  {getCorrelationResultId(correlationResult) ? `ID ${getCorrelationResultId(correlationResult)}` : 'No correlation ID returned'}
                </p>
                <p className="text-xs text-[var(--muted)] mt-0.5">
                  {correlationResult.incidentId ? `Incident ${correlationResult.incidentId}` : 'No incident link returned'}
                </p>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Scoring Policy</label>
                <p className="text-sm text-[var(--fg)] mt-1">
                  {correlationResult.scoringPolicy?.version || 'Policy metadata unavailable'}
                </p>
                <p className="text-xs text-[var(--muted)] mt-0.5">
                  {correlationResult.scoringPolicy?.requirements?.[0] || 'Conservative evidence scoring'}
                </p>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Incident Candidates</label>
                {(correlationResult.incidentCandidates || []).length > 0 ? (
                  <div className="mt-1 space-y-1">
                    {(correlationResult.incidentCandidates || []).slice(0, 3).map((candidate) => (
                      <div key={candidate.id} className="rounded bg-[var(--surface-active)] px-2 py-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs text-[var(--fg)] truncate">{candidate.title}</span>
                          <span className={cn('text-[10px] font-medium', severityColor(candidate.severity || 'info'))}>
                            {candidate.severity || 'unknown'}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center gap-2 text-[10px] text-[var(--muted)]">
                          <span>score {normalizeScore100(candidate.score)}</span>
                          <span>{candidate.eventCount} events</span>
                          {candidate.relationTypes?.length > 0 && <span className="truncate">{candidate.relationTypes.join(', ')}</span>}
                        </div>
                      </div>
                    ))}
                    {(correlationResult.incidentCandidates || []).length > 3 && (
                      <p className="text-[10px] text-[var(--muted)]">+{(correlationResult.incidentCandidates || []).length - 3} more candidates returned</p>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-[var(--muted)] mt-1">No incident candidates returned</p>
                )}
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Entity Graph</label>
                <p className="text-sm text-[var(--fg)] mt-1">
                  {correlationResult.entityGraph?.stats?.eventNodes ?? correlationResult.entityGraph?.nodes?.length ?? 0} nodes / {correlationResult.entityGraph?.stats?.totalEdges ?? correlationResult.entityGraph?.edges?.length ?? 0} edges
                </p>
                <p className="text-xs text-[var(--muted)] mt-0.5">Derived graph for investigation, not auto-alerting.</p>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Evidence Links</label>
                <p className="text-sm text-[var(--fg)] mt-1">
                  {correlationResult.correlations?.length || 0} links
                  {correlationResult.analyzedEventCount ? ` across ${correlationResult.analyzedEventCount} events` : ''}
                </p>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Top Evidence</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(correlationResult.evidenceSummary || []).length > 0 ? (
                    (correlationResult.evidenceSummary || []).slice(0, 4).map((item) => (
                      <span key={item.type} className="text-xs px-2 py-0.5 rounded bg-[var(--surface-active)] text-[var(--muted)]">
                        {item.type}: {item.count}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-[var(--muted)]">No evidence summary returned</span>
                  )}
                </div>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Telemetry Gaps</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(correlationResult.telemetryGaps || []).length > 0 ? (
                    (correlationResult.telemetryGaps || []).slice(0, 3).map((gap) => (
                      <span key={gap.field} className="text-xs px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-300">
                        {gap.field}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-[var(--muted)]">No telemetry gaps returned</span>
                  )}
                </div>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Incident / Attack Chain</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {correlationResult.attackChain.length > 0 ? (
                    correlationResult.attackChain.map((technique, idx) => (
                      <span key={idx} className="text-xs px-2 py-0.5 rounded bg-primary-900/50 text-primary-400">
                        {technique}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-[var(--muted)]">No chain phases returned</span>
                  )}
                </div>
              </div>
              <div>
                <label className="text-xs text-[var(--muted)] uppercase tracking-wider">Correlation Chain</label>
                <div className="mt-1 space-y-1">
                  {(correlationResult.correlations || []).length > 0 ? (
                    (correlationResult.correlations || []).slice(0, 4).map((link, idx) => (
                      <div key={`${link.source}-${link.target}-${idx}`} className="text-xs flex items-center gap-2 text-[var(--muted)]">
                        <span className="font-mono truncate max-w-[120px]">{link.source}</span>
                        <ArrowRight className="h-3 w-3" />
                        <span className="font-mono truncate max-w-[120px]">{link.target}</span>
                        <span className="px-1.5 py-0.5 rounded bg-[var(--surface-active)] text-[var(--fg)]">
                          {normalizeScore100(link.score)}
                        </span>
                        {link.scoring?.decision && (
                          <span className="px-1.5 py-0.5 rounded bg-[var(--surface-active)] text-[var(--muted)]">
                            {link.scoring.decision}
                          </span>
                        )}
                        {link.reasons?.[0] && <span className="truncate">{link.reasons[0]}</span>}
                      </div>
                    ))
                  ) : (
                    <span className="text-xs text-[var(--muted)]">No event-to-event links returned</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Expanded Filters */}
        {showFilters && (
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--hairline)] p-4">
            <div className="grid grid-cols-3 gap-6">
              {/* Event Types */}
              <div>
                <h3 className="text-sm font-medium text-[var(--muted)] mb-3">Event Types</h3>
                <div className="flex flex-wrap gap-2">
                  {filterOptions.eventTypes.map((type) => {
                    const config = eventTypeConfig[type]
                    const Icon = config?.icon || AlertTriangle
                    return (
                      <button
                        key={type}
                        onClick={() => toggleType(type)}
                        className={cn(
                          'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors',
                          selectedTypes.includes(type)
                            ? 'bg-primary-600 text-white'
                            : 'bg-[var(--surface-hover)] text-[var(--muted)] hover:bg-[var(--surface-active)]'
                        )}
                      >
                        <Icon className="h-4 w-4" />
                        {safeCapitalize(type)}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Agents */}
              <div>
                <h3 className="text-sm font-medium text-[var(--muted)] mb-3">Agents</h3>
                <div className="flex flex-wrap gap-2">
                  {filterOptions.agents.map((agent) => (
                    <button
                      key={agent.id}
                      onClick={() =>
                        setSelectedAgents((prev) =>
                          prev.includes(agent.id)
                            ? prev.filter((a) => a !== agent.id)
                            : [...prev, agent.id]
                        )
                      }
                      className={cn(
                        'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors',
                        selectedAgents.includes(agent.id)
                          ? 'bg-primary-600 text-white'
                          : 'bg-[var(--surface-hover)] text-[var(--muted)] hover:bg-[var(--surface-active)]'
                      )}
                    >
                      <Monitor className="h-4 w-4" />
                      {agent.hostname}
                    </button>
                  ))}
                </div>
              </div>

              {/* Severity */}
              <div>
                <h3 className="text-sm font-medium text-[var(--muted)] mb-3">Severity</h3>
                <div className="flex flex-wrap gap-2">
                  {filterOptions.severities.map((severity) => (
                    <button
                      key={severity}
                      onClick={() =>
                        setSelectedSeverities((prev) =>
                          prev.includes(severity)
                            ? prev.filter((s) => s !== severity)
                            : [...prev, severity]
                        )
                      }
                      className={cn(
                        'px-3 py-1.5 rounded-lg text-sm transition-colors',
                        selectedSeverities.includes(severity)
                          ? 'bg-primary-600 text-white'
                          : cn('bg-[var(--surface-hover)] hover:bg-[var(--surface-active)]', severityColor(severity))
                      )}
                    >
                      {safeCapitalize(severity)}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        <div className="flex gap-6">
          {/* Timeline */}
          <div className="flex-1 bg-[var(--surface)] rounded-xl border border-[var(--hairline)]">
            <div className="p-4 border-b border-[var(--hairline)] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Clock className="h-5 w-5 text-primary-400" />
                <h2 className="text-lg font-semibold text-[var(--fg)]">Event Timeline</h2>
                {loading && <Loader2 className="h-4 w-4 text-primary-400 animate-spin" />}
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-[var(--muted)]">{filteredEvents.length} events</span>
                <button
                  onClick={() => setSelectionMode(!selectionMode)}
                  className={cn(
                    'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors',
                    selectionMode
                      ? 'bg-primary-600 text-white'
                      : 'bg-[var(--surface-hover)] text-[var(--muted)] hover:bg-[var(--surface-active)]'
                  )}
                >
                  <Link2 className="h-4 w-4" />
                  {selectionMode ? 'Exit Selection' : 'Correlate'}
                </button>
              </div>
            </div>

            <div className="p-4 max-h-[calc(100vh-340px)] overflow-y-auto">
              {Object.keys(groupedEvents).length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-[var(--muted)]">
                  <Clock className="h-12 w-12 mb-4 opacity-50" />
                  <p>No events found</p>
                  <p className="text-sm mt-1">Try adjusting your filters</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {Object.entries(groupedEvents).map(([date, dayEvents]) => (
                    <div key={date}>
                      <div className="flex items-center gap-3 mb-4">
                        <div className="h-px flex-1 bg-[var(--hairline)]" />
                        <span className="text-sm font-medium text-[var(--muted)]">{date}</span>
                        <div className="h-px flex-1 bg-[var(--hairline)]" />
                      </div>

                      <div className="relative pl-8">
                        {/* Timeline line */}
                        <div className="absolute left-3 top-0 bottom-0 w-px bg-[var(--hairline)]" />

                        <div className="space-y-4">
                          {dayEvents.map((event) => {
                            const config = eventTypeConfig[event.eventType]
                            const Icon = config?.icon || AlertTriangle

                            return (
                              <div key={event.id} className="relative">
                                {/* Timeline dot */}
                                <div
                                  className={cn(
                                    'absolute -left-5 top-3 h-3 w-3 rounded-full border-2 border-[var(--surface)]',
                                    event.severity === 'critical'
                                      ? 'bg-red-500'
                                      : event.severity === 'high'
                                      ? 'bg-orange-500'
                                      : event.severity === 'medium'
                                      ? 'bg-yellow-500'
                                      : event.severity === 'low'
                                      ? 'bg-blue-500'
                                      : event.severity === 'info'
                                      ? 'bg-[var(--emerald-400)]'
                                      : 'bg-[var(--muted)]'
                                  )}
                                />

                                <div
                                  className={cn(
                                    'w-full text-left p-4 rounded-lg transition-colors cursor-pointer',
                                    selectedEvent?.id === event.id
                                      ? 'bg-[var(--surface-hover)] ring-2 ring-primary-500'
                                      : selectedEventIds.has(event.id)
                                      ? 'bg-primary-900/30 ring-1 ring-primary-600'
                                      : 'bg-[var(--surface-active)]/50 hover:bg-[var(--surface-hover)]'
                                  )}
                                  onClick={() => {
                                    if (selectionMode) {
                                      toggleEventSelection(event.id)
                                    } else {
                                      setSelectedEvent(event)
                                    }
                                  }}
                                >
                                  <div className="flex items-start gap-3">
                                    {selectionMode && (
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          toggleEventSelection(event.id)
                                        }}
                                        className="mt-1"
                                      >
                                        {selectedEventIds.has(event.id) ? (
                                          <CheckSquare className="h-5 w-5 text-primary-400" />
                                        ) : (
                                          <Square className="h-5 w-5 text-[var(--muted)]" />
                                        )}
                                      </button>
                                    )}
                                    <div className={cn('p-2 rounded-lg', config?.color)}>
                                      <Icon className="h-4 w-4" />
                                    </div>

                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2 mb-1">
                                        <h3 className="text-sm font-medium text-[var(--fg)] truncate">
                                          {event.title}
                                        </h3>
                                        <span
                                          className={cn(
                                            'text-xs px-1.5 py-0.5 rounded',
                                            severityColor(event.severity || 'info')
                                          )}
                                        >
                                          {(event.severity || 'info').toUpperCase()}
                                        </span>
                                        {event.relatedEvents && event.relatedEvents.length > 0 && (
                                          <span className="text-xs px-1.5 py-0.5 rounded bg-primary-900/50 text-primary-300">
                                            {event.relatedEvents.length} linked
                                          </span>
                                        )}
                                        {event.telemetryQuality && (
                                          <span className={cn(
                                            'text-xs px-1.5 py-0.5 rounded',
                                            telemetryQualityColor[event.telemetryQuality.level] || telemetryQualityColor.partial
                                          )}>
                                            telemetry {event.telemetryQuality.level}
                                          </span>
                                        )}
                                      </div>
                                      <p className="text-sm text-[var(--muted)] truncate">
                                        {event.description}
                                      </p>
                                      <div className="flex items-center gap-4 mt-2 text-xs text-[var(--muted)]">
                                        <span className="flex items-center gap-1">
                                          <Monitor className="h-3 w-3" />
                                          {event.hostname}
                                        </span>
                                        <span className="flex items-center gap-1">
                                          <Clock className="h-3 w-3" />
                                          {formatDate(event.timestamp)}
                                        </span>
                                        {event.mitreTechniques && event.mitreTechniques.length > 0 && (
                                          <span className="flex items-center gap-1">
                                            <Shield className="h-3 w-3" />
                                            {event.mitreTechniques.join(', ')}
                                          </span>
                                        )}
                                      </div>
                                    </div>

                                    <ChevronRight className="h-5 w-5 text-[var(--muted)]" />
                                  </div>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Event Detail Panel */}
          <div className="w-96 bg-[var(--surface)] rounded-xl border border-[var(--hairline)] flex flex-col">
            <div className="p-4 border-b border-[var(--hairline)]">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Event Details</h2>
            </div>

            {selectedEvent ? (
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                <div className="flex items-start gap-3">
                  <div
                    className={cn(
                      'p-2 rounded-lg',
                      eventTypeConfig[selectedEvent.eventType]?.color
                    )}
                  >
                    {(() => {
                      const Icon = eventTypeConfig[selectedEvent.eventType]?.icon || AlertTriangle
                      return <Icon className="h-5 w-5" />
                    })()}
                  </div>
                  <div>
                    <h3 className="text-[var(--fg)] font-medium">{selectedEvent.title}</h3>
                    <p className="text-sm text-[var(--muted)] mt-1">{selectedEvent.description}</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                      Event Type
                    </label>
                    <p className="text-sm text-[var(--fg)] mt-1 capitalize">{selectedEvent.eventType}</p>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                      Severity
                    </label>
                    <p className={cn('text-sm mt-1', severityColor(selectedEvent.severity || 'info'))}>
                      {(selectedEvent.severity || 'info').toUpperCase()}
                    </p>
                  </div>
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    Timestamp
                  </label>
                  <p className="text-sm text-[var(--fg)] mt-1">
                    {new Date(selectedEvent.timestamp).toLocaleString()}
                  </p>
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    Host
                  </label>
                  <p className="text-sm text-[var(--fg)] mt-1">{selectedEvent.hostname}</p>
                </div>

                {selectedEvent.mitreTechniques && selectedEvent.mitreTechniques.length > 0 && (
                  <div>
                    <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                      MITRE ATT&CK
                    </label>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {selectedEvent.mitreTechniques.map((tech) => (
                        <span
                          key={tech}
                          className="text-xs px-2 py-1 rounded bg-primary-900/50 text-primary-400"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    Telemetry Coverage
                  </label>
                  {selectedEvent.telemetryQuality ? (
                    <>
                      <div className="mt-2 p-3 bg-[var(--surface-active)] rounded-lg space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-[var(--fg)]">
                            {selectedEvent.telemetryQuality.score}% coverage
                          </span>
                          <span className={cn(
                            'text-xs px-2 py-0.5 rounded',
                            telemetryQualityColor[selectedEvent.telemetryQuality.level] || telemetryQualityColor.partial
                          )}>
                            {selectedEvent.telemetryQuality.level}
                          </span>
                        </div>
                        {selectedEvent.telemetryQuality.missing.length > 0 ? (
                          <div>
                            <p className="text-xs text-[var(--muted)] mb-1">Missing fields that would improve correlation</p>
                            <div className="flex flex-wrap gap-1">
                              {selectedEvent.telemetryQuality.missing.slice(0, 8).map((field) => (
                                <span key={field} className="text-xs px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-300">
                                  {field}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <p className="text-xs text-[var(--muted)]">No missing fields returned for this event.</p>
                        )}
                      </div>
                      {selectedEvent.telemetryContract && (
                        <div className="mt-2 p-3 bg-[var(--surface-active)] rounded-lg">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs text-[var(--muted)]">
                              {selectedEvent.telemetryContract.schemaVersion || 'telemetry contract'} - {selectedEvent.telemetryContract.category}
                            </span>
                            <span className={cn(
                              'text-xs px-2 py-0.5 rounded',
                              selectedEvent.telemetryContract.correlationReady
                                ? 'bg-emerald-500/15 text-emerald-300'
                                : 'bg-yellow-500/15 text-yellow-300'
                            )}>
                              {selectedEvent.telemetryContract.correlationReady ? 'correlation ready' : 'needs fields'}
                            </span>
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="mt-2 text-xs text-[var(--muted)]">
                      No telemetry quality metadata returned for this event.
                    </p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    Correlation Evidence
                  </label>
                  {selectedEvent.correlationEvidence && selectedEvent.correlationEvidence.length > 0 ? (
                    <div className="mt-2 space-y-2">
                      {selectedEvent.correlationEvidence.slice(0, 6).map((evidence) => {
                        const relatedEvent = allEvents.find((e) => e.id === evidence.id)
                        return (
                          <button
                            key={evidence.id}
                            onClick={() => relatedEvent && setSelectedEvent(relatedEvent)}
                            className="w-full text-left p-2 bg-[var(--surface-active)] rounded-lg hover:bg-[var(--surface-hover)] transition-colors"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <p className="text-sm text-[var(--fg)] truncate">
                                {relatedEvent?.title || evidence.id}
                              </p>
                              <span className="text-xs px-2 py-0.5 rounded bg-primary-900/50 text-primary-300">
                                {evidence.score}
                              </span>
                            </div>
                            <p className="text-xs text-[var(--muted)] mt-1">
                              {evidence.reasons.join(', ')}
                            </p>
                            {evidence.scoring?.decision && (
                              <p className="text-xs text-[var(--muted)] mt-1">
                                {evidence.scoring.version} - {evidence.scoring.decision}, {evidence.scoring.confidence} confidence
                              </p>
                            )}
                          </button>
                        )
                      })}
                    </div>
                  ) : (
                    <p className="mt-2 text-xs text-[var(--muted)]">
                      No persisted correlation evidence returned for this event.
                    </p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    Details
                  </label>
                  <pre className="mt-2 p-3 bg-[var(--surface-active)] rounded-lg text-xs text-[var(--muted)] overflow-x-auto">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>

                {selectedEvent.relatedEvents && selectedEvent.relatedEvents.length > 0 && (
                  <div>
                    <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                      Related Events
                    </label>
                    <div className="mt-2 space-y-2">
                      {selectedEvent.relatedEvents.map((relatedId) => {
                        const relatedEvent = allEvents.find((e) => e.id === relatedId)
                        if (!relatedEvent) return null
                        return (
                          <button
                            key={relatedId}
                            onClick={() => setSelectedEvent(relatedEvent)}
                            className="w-full text-left p-2 bg-[var(--surface-active)] rounded-lg hover:bg-[var(--surface-hover)] transition-colors"
                          >
                            <p className="text-sm text-[var(--fg)] truncate">{relatedEvent.title}</p>
                            <p className="text-xs text-[var(--muted)]">
                              {formatDate(relatedEvent.timestamp)}
                            </p>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                )}

                <div className="pt-4 space-y-2">
                  {selectedEvent.eventType === 'process' && selectedEvent.details?.pid && (
                    <button
                      onClick={() => buildStoryline(
                        String(selectedEvent.details.pid),
                        selectedEvent.agentId
                      )}
                      disabled={loading}
                      className="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium"
                    >
                      {loading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <GitBranch className="h-4 w-4" />
                      )}
                      Build Process Storyline
                    </button>
                  )}
                  <button
                    onClick={() => router.visit(`/app/hunt?q=${encodeURIComponent(`event.id:${selectedEvent.id}`)}`)}
                    className="w-full flex items-center justify-center gap-2 bg-[var(--surface-hover)] hover:bg-[var(--surface-active)] text-[var(--fg)] px-4 py-2 rounded-lg text-sm"
                  >
                    View in Hunt
                  </button>
                </div>

                {/* Storyline View */}
                {storyline && String(selectedEvent.details?.pid ?? '') === storyline.processId && (
                  <div className="pt-4 border-t border-[var(--hairline)]">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-medium text-[var(--muted)]">Process Storyline</h4>
                      <button
                        onClick={() => setStoryline(null)}
                        className="text-[var(--muted)] hover:text-[var(--fg)] text-sm"
                      >
                        x
                      </button>
                    </div>
                    <StorylineTree storyline={storyline} onSelectEvent={setSelectedEvent} events={allEvents} />
                  </div>
                )}
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center text-[var(--muted)]">
                <div className="text-center">
                  <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select an event to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

function TimelineSignalStat({
  label,
  value,
  detail,
}: {
  label: string
  value: number
  detail: string
}) {
  return (
    <div className="rounded-lg bg-[var(--surface-active)]/50 px-3 py-2">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs text-[var(--muted)] uppercase tracking-wider">{label}</span>
        <span className="text-sm font-semibold text-[var(--fg)]">{value}</span>
      </div>
      <p className="mt-1 text-xs text-[var(--muted)] truncate" title={detail}>
        {detail}
      </p>
    </div>
  )
}

// Storyline Tree Component
function StorylineTree({
  storyline,
  onSelectEvent,
  events,
  depth = 0,
}: {
  storyline: Storyline
  onSelectEvent: (event: TimelineEvent) => void
  events: TimelineEvent[]
  depth?: number
}) {
  const relatedEvents = events.filter(e =>
    storyline.events.some(se => se.id === e.id)
  )

  return (
    <div className={cn('space-y-2', depth > 0 && 'ml-4 border-l border-[var(--hairline)] pl-3')}>
      <div className="flex items-center gap-2">
        <Terminal className="h-4 w-4 text-[var(--emerald-400)]" />
        <span className="text-sm font-medium text-[var(--fg)]">{storyline.processName}</span>
        <span className="text-xs text-[var(--muted)]">PID: {storyline.processId}</span>
      </div>

      {relatedEvents.length > 0 && (
        <div className="space-y-1 ml-6">
          {relatedEvents.slice(0, 5).map((event) => (
            <button
              key={event.id}
              onClick={() => onSelectEvent(event)}
              className="w-full text-left p-2 rounded bg-[var(--surface-active)]/50 hover:bg-[var(--surface-hover)] transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className={cn(
                  'text-xs px-1.5 py-0.5 rounded',
                  event.eventType === 'file' ? 'bg-blue-500/20 text-blue-400' :
                  event.eventType === 'network' ? 'bg-purple-500/20 text-purple-400' :
                  event.eventType === 'registry' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-[var(--surface-hover)] text-[var(--muted)]'
                )}>
                  {event.eventType}
                </span>
                <span className="text-xs text-[var(--muted)] truncate">{event.title}</span>
              </div>
            </button>
          ))}
          {relatedEvents.length > 5 && (
            <span className="text-xs text-[var(--muted)] ml-2">
              +{relatedEvents.length - 5} more events
            </span>
          )}
        </div>
      )}

      {storyline.childProcesses.map((child) => (
        <StorylineTree
          key={child.processId}
          storyline={child}
          onSelectEvent={onSelectEvent}
          events={events}
          depth={depth + 1}
        />
      ))}
    </div>
  )
}
