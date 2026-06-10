import { useState, useEffect, useCallback, useMemo } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  Globe,
  Cloud,
  Mail,
  Network,
  Server,
  AlertTriangle,
  Activity,
  RefreshCw,
  Search,
  Clock,
  ChevronRight,
  ChevronDown,
  ArrowUpRight,
  CheckCircle,
  XCircle,
  AlertCircle,
  Zap,
  Link2,
  GitBranch,
  Layers,
  ExternalLink,
  Target,
  TrendingUp,
  BarChart3,
  Eye,
  Play,
  Pause,
  Users,
  HardDrive,
  Database,
  Cpu,
  Workflow,
  Brain,
  Lightbulb,
  AlertOctagon,
  ShieldAlert,
  FileWarning,
  Crosshair,
  Fingerprint,
  MapPin,
} from 'lucide-react'
import { cn, formatDate, severityColor } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { useDashboardChannel } from '@/hooks/useSocket'
import axios from 'axios'
import { toast } from 'sonner'

// Types
interface XDRSource {
  id: string
  name: string
  sourceType: 'firewall' | 'proxy' | 'email' | 'cloud' | 'network' | 'ids' | 'iam' | 'siem' | 'endpoint'
  vendor?: string
  status: 'healthy' | 'degraded' | 'offline' | 'unknown'
  lastEventAt: string | null
  eventsLastHour: number
  eventsLastDay: number
  errorCount: number
}

interface XDREvent {
  id: string
  timestamp: string
  sourceType: string
  sourceName?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category?: string
  action?: string
  outcome?: string
  sourceIp?: string
  destIp?: string
  user?: string
  url?: string
  domain?: string
  fileName?: string
  fileHash?: string
  threatName?: string
  threatCategory?: string
  mitreTechniques?: string[]
  riskScore?: number
  correlationId?: string
}

interface AttackTimeline {
  id: string
  phases: string[]
  sourceTypes: string[]
  eventCount: number
  riskScore: number
  status: 'active' | 'investigating' | 'closed'
  firstEventAt: string
  lastEventAt: string
  indicators: Record<string, string[]>
}

interface KillChainDetection {
  indicator: { type: string; value: string }
  phases: string[]
  phaseCount: number
  eventCount: number
  sourceTypes: string[]
  riskScore: number
  detectedAt: string
}

// Unified Incident Interface
interface XDRIncident {
  id: string
  title: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'new' | 'investigating' | 'contained' | 'remediated' | 'closed'
  priority: number
  assignee?: string
  eventCount: number
  alertCount: number
  affectedAssets: number
  sourceTypes: string[]
  killChainPhases: string[]
  mitreTechniques: string[]
  indicators: {
    ips: string[]
    domains: string[]
    hashes: string[]
    users: string[]
  }
  mlCorrelationScore: number
  createdAt: string
  updatedAt: string
  firstEventAt: string
  lastEventAt: string
  timeToDetect?: number
  entityGraph?: {
    nodes: number
    edges: number
    centralEntity?: string
  }
}

// Data Source Health Interface
interface DataSourceHealth {
  id: string
  name: string
  type: 'firewall' | 'proxy' | 'email' | 'cloud' | 'network' | 'ids' | 'iam' | 'siem' | 'endpoint'
  vendor: string
  status: 'healthy' | 'degraded' | 'offline' | 'error'
  lastHeartbeat: string | null
  lastEventAt: string | null
  eventsPerSecond: number
  eventsLastHour: number
  eventsLast24h: number
  errorRate: number
  latencyMs: number
  dataLakeStatus: 'hot' | 'warm' | 'cold'
  retentionDays: number
  diskUsageMb: number
  parserVersion?: string
  connectionDetails?: {
    protocol: string
    port: number
    authenticated: boolean
    tlsEnabled: boolean
  }
  healthHistory: {
    timestamp: string
    status: 'healthy' | 'degraded' | 'offline' | 'error'
    eventsPerSecond: number
  }[]
}

// Correlation Insight Interface
interface CorrelationInsight {
  id: string
  type: 'attack_pattern' | 'entity_cluster' | 'anomaly' | 'threat_campaign' | 'emerging_threat'
  title: string
  description: string
  confidence: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  relatedIncidents: string[]
  relatedIndicators: string[]
  sourcesInvolved: string[]
  mitreTechniques: string[]
  recommendation: string
  timeframe: {
    start: string
    end: string
  }
  metadata: {
    mlModelUsed?: string
    correlationRules?: string[]
    entityGraphNodes?: number
    patternFrequency?: number
  }
  createdAt: string
}

// Cross-Source Timeline Event
interface CrossSourceTimelineEvent {
  id: string
  timestamp: string
  sourceType: string
  sourceName: string
  eventType: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description?: string
  relatedEntities: {
    type: string
    value: string
  }[]
  incidentId?: string
  correlationId?: string
  mitreTechnique?: string
  killChainPhase?: string
}

interface XDRStats {
  totalSources: number
  healthySources: number
  degradedSources: number
  offlineSources: number
  eventsLast24h: number
  eventsLastHour: number
  eventsPerSecond: number
  correlationsDetected: number
  killChainsDetected: number
  alertsGenerated: number
  activeIncidents: number
  criticalIncidents: number
  mttr: number // Mean Time to Respond (minutes)
  mttd: number // Mean Time to Detect (minutes)
  bySeverity: Record<string, number>
  bySourceType: Record<string, number>
  dataLakeSize: {
    hot: number
    warm: number
    cold: number
    total: number
  }
  topMitreTechniques: { technique: string; count: number }[]
  topIndicators: { type: string; value: string; count: number }[]
}

interface XDRPageProps {
  sources?: XDRSource[]
  events?: XDREvent[]
  stats?: XDRStats
  incidents?: XDRIncident[]
  dataSourceHealth?: DataSourceHealth[]
  correlationInsights?: CorrelationInsight[]
  crossSourceTimeline?: CrossSourceTimelineEvent[]
}

const SOURCE_TYPE_ICONS: Record<string, React.ElementType> = {
  firewall: Shield,
  proxy: Globe,
  email: Mail,
  cloud: Cloud,
  network: Network,
  ids: AlertTriangle,
  iam: Server,
  siem: Activity,
  endpoint: Server,
}

const SOURCE_TYPE_COLORS: Record<string, string> = {
  firewall: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  proxy: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  email: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  cloud: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  network: 'bg-green-500/20 text-green-400 border-green-500/30',
  ids: 'bg-red-500/20 text-red-400 border-red-500/30',
  iam: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  siem: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  endpoint: 'bg-primary-500/20 text-primary-400 border-primary-500/30',
}

const KILL_CHAIN_PHASES = [
  { id: 'initial_access', name: 'Initial Access', order: 1 },
  { id: 'execution', name: 'Execution', order: 2 },
  { id: 'persistence', name: 'Persistence', order: 3 },
  { id: 'defense_evasion', name: 'Defense Evasion', order: 4 },
  { id: 'credential_access', name: 'Credential Access', order: 5 },
  { id: 'discovery', name: 'Discovery', order: 6 },
  { id: 'lateral_movement', name: 'Lateral Movement', order: 7 },
  { id: 'command_and_control', name: 'C2', order: 8 },
  { id: 'exfiltration', name: 'Exfiltration', order: 9 },
  { id: 'impact', name: 'Impact', order: 10 },
]

const TIME_RANGES = [
  { value: '1h', label: 'Last Hour' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
]

const INCIDENT_STATUS_COLORS: Record<string, string> = {
  new: 'bg-red-500/20 text-red-400 border-red-500/30',
  investigating: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  contained: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  remediated: 'bg-green-500/20 text-green-400 border-green-500/30',
  closed: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

const INSIGHT_TYPE_ICONS: Record<string, React.ElementType> = {
  attack_pattern: GitBranch,
  entity_cluster: Users,
  anomaly: AlertTriangle,
  threat_campaign: Target,
  emerging_threat: TrendingUp,
}

const INSIGHT_TYPE_COLORS: Record<string, string> = {
  attack_pattern: 'bg-red-500/20 text-red-400',
  entity_cluster: 'bg-purple-500/20 text-purple-400',
  anomaly: 'bg-yellow-500/20 text-yellow-400',
  threat_campaign: 'bg-orange-500/20 text-orange-400',
  emerging_threat: 'bg-cyan-500/20 text-cyan-400',
}

const DATA_LAKE_STATUS_COLORS: Record<string, string> = {
  hot: 'bg-red-500/20 text-red-400',
  warm: 'bg-yellow-500/20 text-yellow-400',
  cold: 'bg-blue-500/20 text-blue-400',
}

export default function XDR({
  sources: initialSources = [],
  events: initialEvents = [],
  stats: initialStats,
  incidents: initialIncidents = [],
  dataSourceHealth: initialDataSourceHealth = [],
  correlationInsights: initialInsights = [],
  crossSourceTimeline: initialCrossSourceTimeline = [],
}: XDRPageProps) {
  // State
  const [sources, setSources] = useState<XDRSource[]>(initialSources)
  const [events, setEvents] = useState<XDREvent[]>(initialEvents)
  const [stats, setStats] = useState<XDRStats>(initialStats || {
    totalSources: 0,
    healthySources: 0,
    degradedSources: 0,
    offlineSources: 0,
    eventsLast24h: 0,
    eventsLastHour: 0,
    eventsPerSecond: 0,
    correlationsDetected: 0,
    killChainsDetected: 0,
    alertsGenerated: 0,
    activeIncidents: 0,
    criticalIncidents: 0,
    mttr: 0,
    mttd: 0,
    bySeverity: {},
    bySourceType: {},
    dataLakeSize: { hot: 0, warm: 0, cold: 0, total: 0 },
    topMitreTechniques: [],
    topIndicators: [],
  })
  const [killChains, setKillChains] = useState<KillChainDetection[]>([])
  const [timelines, setTimelines] = useState<AttackTimeline[]>([])
  const [incidents, setIncidents] = useState<XDRIncident[]>(initialIncidents)
  const [dataSourceHealth, setDataSourceHealth] = useState<DataSourceHealth[]>(initialDataSourceHealth)
  const [correlationInsights, setCorrelationInsights] = useState<CorrelationInsight[]>(initialInsights)
  const [crossSourceTimeline, setCrossSourceTimeline] = useState<CrossSourceTimelineEvent[]>(initialCrossSourceTimeline)
  const [selectedIncident, setSelectedIncident] = useState<XDRIncident | null>(null)

  // Filters
  const [timeRange, setTimeRange] = useState('24h')
  const [sourceTypeFilter, setSourceTypeFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')

  // UI State
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [activeTab, setActiveTab] = useState<'incidents' | 'timeline' | 'correlations' | 'kill_chain' | 'sources' | 'health' | 'insights'>('incidents')
  const [expandedTimeline, setExpandedTimeline] = useState<string | null>(null)
  const [expandedIncident, setExpandedIncident] = useState<string | null>(null)
  const [incidentStatusFilter, setIncidentStatusFilter] = useState<string>('all')

  // WebSocket for real-time updates
  const { connectionState } = useDashboardChannel()

  // Fetch data
  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [
        eventsRes,
        sourcesRes,
        statsRes,
        killChainRes,
        timelinesRes,
        incidentsRes,
        healthRes,
        insightsRes,
        crossTimelineRes,
      ] = await Promise.all([
        axios.get(`/api/v1/xdr/events?time_range=${timeRange}&limit=100`),
        axios.get('/api/v1/xdr/sources'),
        axios.get('/api/v1/xdr/correlations/stats'),
        axios.get(`/api/v1/xdr/correlations/kill-chain?time_window_ms=${getTimeWindowMs(timeRange)}`),
        axios.get('/api/v1/xdr/timelines?status=active&limit=20'),
        axios.get(`/api/v1/xdr/incidents?time_range=${timeRange}&limit=50`).catch(() => ({ data: { data: [] } })),
        axios.get('/api/v1/xdr/sources/health').catch(() => ({ data: { data: [] } })),
        axios.get(`/api/v1/xdr/correlations/insights?time_range=${timeRange}`).catch(() => ({ data: { data: [] } })),
        axios.get(`/api/v1/xdr/timeline/cross-source?time_range=${timeRange}&limit=200`).catch(() => ({ data: { data: [] } })),
      ])

      // Transform events
      if (eventsRes.data?.data) {
        setEvents(eventsRes.data.data.map((e: Record<string, unknown>) => ({
          id: e.id as string,
          timestamp: e.timestamp as string,
          sourceType: e.source_type as string,
          sourceName: e.source_name as string | undefined,
          severity: (e.severity as string) || 'info',
          category: e.category as string | undefined,
          action: e.action as string | undefined,
          outcome: e.outcome as string | undefined,
          sourceIp: e.source_ip as string | undefined,
          destIp: e.dest_ip as string | undefined,
          user: e.user as string | undefined,
          url: e.url as string | undefined,
          domain: e.domain as string | undefined,
          fileName: e.file_name as string | undefined,
          fileHash: e.file_hash as string | undefined,
          threatName: e.threat_name as string | undefined,
          threatCategory: e.threat_category as string | undefined,
          mitreTechniques: (e.mitre_techniques as string[]) || [],
          riskScore: e.risk_score as number | undefined,
          correlationId: e.correlation_id as string | undefined,
        })))
      }

      // Transform sources
      if (sourcesRes.data?.data) {
        const transformedSources = sourcesRes.data.data.map((s: Record<string, unknown>) => ({
          id: s.id as string,
          name: s.name as string,
          sourceType: s.source_type as string,
          vendor: s.vendor as string | undefined,
          status: (s.status as string) || 'unknown',
          lastEventAt: s.last_event_at as string | null,
          eventsLastHour: (s.stats as Record<string, number>)?.events_last_hour || 0,
          eventsLastDay: (s.stats as Record<string, number>)?.events_last_day || 0,
          errorCount: (s.error_count as number) || 0,
        }))
        setSources(transformedSources)
      }

      // Stats
      if (statsRes.data?.data) {
        const s = statsRes.data.data
        setStats(prev => ({
          ...prev,
          correlationsDetected: s.events_correlated || 0,
          killChainsDetected: s.kill_chains_detected || 0,
          alertsGenerated: s.alerts_generated || 0,
        }))
      }

      // Kill chains
      if (killChainRes.data?.data) {
        setKillChains(killChainRes.data.data.map((k: Record<string, unknown>) => ({
          indicator: k.indicator as { type: string; value: string },
          phases: (k.phases as string[]) || [],
          phaseCount: (k.phase_count as number) || 0,
          eventCount: (k.event_count as number) || 0,
          sourceTypes: (k.source_types as string[]) || [],
          riskScore: (k.risk_score as number) || 0,
          detectedAt: k.detected_at as string,
        })))
      }

      // Timelines
      if (timelinesRes.data?.data) {
        setTimelines(timelinesRes.data.data.map((t: Record<string, unknown>) => ({
          id: t.id as string,
          phases: (t.kill_chain_phases as string[]) || [],
          sourceTypes: (t.source_types as string[]) || [],
          eventCount: (t.event_count as number) || 0,
          riskScore: (t.risk_score as number) || 0,
          status: (t.status as string) || 'active',
          firstEventAt: t.first_event_at as string,
          lastEventAt: t.last_event_at as string,
          indicators: (t.indicators as Record<string, string[]>) || {},
        })))
      }

      // Unified Incidents
      if (incidentsRes.data?.data) {
        setIncidents(incidentsRes.data.data.map((i: Record<string, unknown>) => ({
          id: i.id as string,
          title: (i.title as string) || 'Untitled Incident',
          description: i.description as string | undefined,
          severity: (i.severity as 'critical' | 'high' | 'medium' | 'low') || 'medium',
          status: (i.status as 'new' | 'investigating' | 'contained' | 'remediated' | 'closed') || 'new',
          priority: (i.priority as number) || 0,
          assignee: i.assignee as string | undefined,
          eventCount: (i.event_count as number) || 0,
          alertCount: (i.alert_count as number) || 0,
          affectedAssets: (i.affected_assets as number) || 0,
          sourceTypes: (i.source_types as string[]) || [],
          killChainPhases: (i.kill_chain_phases as string[]) || [],
          mitreTechniques: (i.mitre_techniques as string[]) || [],
          indicators: {
            ips: ((i.indicators as Record<string, string[]>)?.ips as string[]) || [],
            domains: ((i.indicators as Record<string, string[]>)?.domains as string[]) || [],
            hashes: ((i.indicators as Record<string, string[]>)?.hashes as string[]) || [],
            users: ((i.indicators as Record<string, string[]>)?.users as string[]) || [],
          },
          mlCorrelationScore: (i.ml_correlation_score as number) || 0,
          createdAt: i.created_at as string,
          updatedAt: i.updated_at as string,
          firstEventAt: i.first_event_at as string,
          lastEventAt: i.last_event_at as string,
          timeToDetect: i.time_to_detect as number | undefined,
          entityGraph: i.entity_graph as { nodes: number; edges: number; centralEntity?: string } | undefined,
        })))

        // Update incident stats
        const incidentData = incidentsRes.data.data
        const activeIncidents = incidentData.filter((i: Record<string, unknown>) =>
          ['new', 'investigating', 'contained'].includes(i.status as string)
        ).length
        const criticalIncidents = incidentData.filter((i: Record<string, unknown>) =>
          i.severity === 'critical' && ['new', 'investigating'].includes(i.status as string)
        ).length

        setStats(prev => ({
          ...prev,
          activeIncidents,
          criticalIncidents,
        }))
      }

      // Data Source Health
      if (healthRes.data?.data) {
        setDataSourceHealth(healthRes.data.data.map((h: Record<string, unknown>) => ({
          id: h.id as string,
          name: (h.name as string) || 'Unknown Source',
          type: (h.type as 'firewall' | 'proxy' | 'email' | 'cloud' | 'network' | 'ids' | 'iam' | 'siem' | 'endpoint') || 'endpoint',
          vendor: (h.vendor as string) || 'Unknown',
          status: (h.status as 'healthy' | 'degraded' | 'offline' | 'error') || 'unknown',
          lastHeartbeat: h.last_heartbeat as string | null,
          lastEventAt: h.last_event_at as string | null,
          eventsPerSecond: (h.events_per_second as number) || 0,
          eventsLastHour: (h.events_last_hour as number) || 0,
          eventsLast24h: (h.events_last_24h as number) || 0,
          errorRate: (h.error_rate as number) || 0,
          latencyMs: (h.latency_ms as number) || 0,
          dataLakeStatus: (h.data_lake_status as 'hot' | 'warm' | 'cold') || 'hot',
          retentionDays: (h.retention_days as number) || 30,
          diskUsageMb: (h.disk_usage_mb as number) || 0,
          parserVersion: h.parser_version as string | undefined,
          connectionDetails: h.connection_details as {
            protocol: string
            port: number
            authenticated: boolean
            tlsEnabled: boolean
          } | undefined,
          healthHistory: (h.health_history as {
            timestamp: string
            status: 'healthy' | 'degraded' | 'offline' | 'error'
            eventsPerSecond: number
          }[]) || [],
        })))

        // Update source health stats
        const healthData = healthRes.data.data
        const degradedSources = healthData.filter((h: Record<string, unknown>) => h.status === 'degraded').length
        const offlineSources = healthData.filter((h: Record<string, unknown>) =>
          h.status === 'offline' || h.status === 'error'
        ).length

        setStats(prev => ({
          ...prev,
          degradedSources,
          offlineSources,
        }))
      }

      // Correlation Insights
      if (insightsRes.data?.data) {
        setCorrelationInsights(insightsRes.data.data.map((ins: Record<string, unknown>) => ({
          id: ins.id as string,
          type: (ins.type as 'attack_pattern' | 'entity_cluster' | 'anomaly' | 'threat_campaign' | 'emerging_threat') || 'anomaly',
          title: (ins.title as string) || 'Untitled Insight',
          description: (ins.description as string) || '',
          confidence: (ins.confidence as number) || 0,
          severity: (ins.severity as 'critical' | 'high' | 'medium' | 'low') || 'medium',
          relatedIncidents: (ins.related_incidents as string[]) || [],
          relatedIndicators: (ins.related_indicators as string[]) || [],
          sourcesInvolved: (ins.sources_involved as string[]) || [],
          mitreTechniques: (ins.mitre_techniques as string[]) || [],
          recommendation: (ins.recommendation as string) || '',
          timeframe: {
            start: (ins.timeframe as Record<string, string>)?.start || '',
            end: (ins.timeframe as Record<string, string>)?.end || '',
          },
          metadata: (ins.metadata as {
            mlModelUsed?: string
            correlationRules?: string[]
            entityGraphNodes?: number
            patternFrequency?: number
          }) || {},
          createdAt: ins.created_at as string,
        })))
      }

      // Cross-Source Timeline
      if (crossTimelineRes.data?.data) {
        setCrossSourceTimeline(crossTimelineRes.data.data.map((evt: Record<string, unknown>) => ({
          id: evt.id as string,
          timestamp: evt.timestamp as string,
          sourceType: (evt.source_type as string) || 'unknown',
          sourceName: (evt.source_name as string) || 'Unknown Source',
          eventType: (evt.event_type as string) || 'event',
          severity: (evt.severity as 'critical' | 'high' | 'medium' | 'low' | 'info') || 'info',
          title: (evt.title as string) || 'Event',
          description: evt.description as string | undefined,
          relatedEntities: (evt.related_entities as { type: string; value: string }[]) || [],
          incidentId: evt.incident_id as string | undefined,
          correlationId: evt.correlation_id as string | undefined,
          mitreTechnique: evt.mitre_technique as string | undefined,
          killChainPhase: evt.kill_chain_phase as string | undefined,
        })))
      }

    } catch (error) {
      logger.error('Failed to fetch XDR data:', error)
      toast.error('Failed to load XDR data')
    } finally {
      setLoading(false)
    }
  }, [timeRange])

  // Calculate aggregate stats when sources/events change
  useEffect(() => {
    const healthySources = sources.filter(s => s.status === 'healthy').length
    const totalEvents = events.length
    const bySeverity: Record<string, number> = {}
    const bySourceType: Record<string, number> = {}

    events.forEach(e => {
      bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1
      bySourceType[e.sourceType] = (bySourceType[e.sourceType] || 0) + 1
    })

    setStats(prev => ({
      ...prev,
      totalSources: sources.length || prev.totalSources,
      healthySources,
      eventsLast24h: totalEvents,
      bySeverity,
      bySourceType,
    }))
  }, [sources, events])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchData()
    setRefreshing(false)
    toast.success('Data refreshed')
  }

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      if (sourceTypeFilter !== 'all' && event.sourceType !== sourceTypeFilter) return false
      if (severityFilter !== 'all' && event.severity !== severityFilter) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return (
          event.sourceIp?.toLowerCase().includes(query) ||
          event.destIp?.toLowerCase().includes(query) ||
          event.user?.toLowerCase().includes(query) ||
          event.domain?.toLowerCase().includes(query) ||
          event.threatName?.toLowerCase().includes(query) ||
          event.action?.toLowerCase().includes(query)
        )
      }
      return true
    })
  }, [events, sourceTypeFilter, severityFilter, searchQuery])

  // Get unique source types for filter
  const sourceTypes = useMemo(() => {
    return Array.from(new Set(events.map(e => e.sourceType))).sort()
  }, [events])

  // Filter incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter(incident => {
      if (incidentStatusFilter !== 'all' && incident.status !== incidentStatusFilter) return false
      if (severityFilter !== 'all' && incident.severity !== severityFilter) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return (
          incident.title.toLowerCase().includes(query) ||
          incident.description?.toLowerCase().includes(query) ||
          incident.indicators.ips.some(ip => ip.toLowerCase().includes(query)) ||
          incident.indicators.domains.some(d => d.toLowerCase().includes(query)) ||
          incident.indicators.users.some(u => u.toLowerCase().includes(query))
        )
      }
      return true
    })
  }, [incidents, incidentStatusFilter, severityFilter, searchQuery])

  // Filter cross-source timeline
  const filteredCrossTimeline = useMemo(() => {
    return crossSourceTimeline.filter(evt => {
      if (sourceTypeFilter !== 'all' && evt.sourceType !== sourceTypeFilter) return false
      if (severityFilter !== 'all' && evt.severity !== severityFilter) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return (
          evt.title.toLowerCase().includes(query) ||
          evt.description?.toLowerCase().includes(query) ||
          evt.sourceName.toLowerCase().includes(query) ||
          evt.relatedEntities.some(e => e.value.toLowerCase().includes(query))
        )
      }
      return true
    })
  }, [crossSourceTimeline, sourceTypeFilter, severityFilter, searchQuery])

  return (
    <MainLayout title="XDR - Extended Detection & Response">
      <Head title="XDR - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Extended Detection & Response</h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              Unified visibility across endpoint, network, email, cloud, and identity sources
            </p>
          </div>
          <div className="flex items-center gap-3">
            <ConnectionStatus state={connectionState} />
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg)' }}
            >
              {TIME_RANGES.map(tr => (
                <option key={tr.value} value={tr.value}>{tr.label}</option>
              ))}
            </select>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg transition-colors",
                "bg-primary-600 hover:bg-primary-500 text-white",
                refreshing && "opacity-50 cursor-not-allowed"
              )}
            >
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
              Refresh
            </button>
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <StatCard
            title="Active Incidents"
            value={stats.activeIncidents}
            subValue={`${stats.criticalIncidents} critical`}
            icon={AlertOctagon}
            color="danger"
          />
          <StatCard
            title="Data Sources"
            value={stats.totalSources}
            subValue={`${stats.healthySources} healthy`}
            icon={Layers}
            color="primary"
          />
          <StatCard
            title="Events (24h)"
            value={stats.eventsLast24h}
            subValue={`${stats.eventsPerSecond}/sec`}
            icon={Activity}
            color="primary"
          />
          <StatCard
            title="Correlations"
            value={stats.correlationsDetected}
            icon={Link2}
            color="warning"
          />
          <StatCard
            title="Kill Chains"
            value={stats.killChainsDetected}
            icon={GitBranch}
            color="danger"
          />
          <StatCard
            title="Alerts Generated"
            value={stats.alertsGenerated}
            icon={AlertTriangle}
            color="danger"
          />
          <StatCard
            title="MTTD"
            value={stats.mttd}
            subValue="minutes avg"
            icon={Clock}
            color="primary"
          />
          <StatCard
            title="MTTR"
            value={stats.mttr}
            subValue="minutes avg"
            icon={Zap}
            color="warning"
          />
        </div>

        {/* Source Health Cards */}
        <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Source Health</h2>
            <a href="/app/integrations" className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1">
              Manage Sources <ArrowUpRight className="h-4 w-4" />
            </a>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {sources.length === 0 && Object.keys(stats.bySourceType ?? {}).length === 0 ? (
              <div className="col-span-full text-center py-8" style={{ color: 'var(--muted)' }}>
                <Layers className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No data sources configured</p>
                <a href="/app/integrations" className="text-primary-400 hover:text-primary-300 text-sm">
                  Add data sources
                </a>
              </div>
            ) : sources.length > 0 ? (
              sources.map(source => (
                <SourceHealthCard key={source.id} source={source} />
              ))
            ) : (
              Object.entries(stats.bySourceType ?? {}).map(([type, count]) => (
                <SourceTypeCard key={type} type={type} count={count} />
              ))
            )}
          </div>
        </div>

        {/* Main Content Tabs */}
        <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)' }}>
          {/* Tab Navigation */}
          <div className="flex items-center gap-1 p-1 border-b overflow-x-auto" style={{ borderColor: 'var(--border)', backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
            <TabButton
              active={activeTab === 'incidents'}
              onClick={() => setActiveTab('incidents')}
              icon={AlertOctagon}
              label="Incidents"
              badge={filteredIncidents.filter(i => i.status === 'new').length > 0 ? filteredIncidents.filter(i => i.status === 'new').length : undefined}
            />
            <TabButton
              active={activeTab === 'timeline'}
              onClick={() => setActiveTab('timeline')}
              icon={Clock}
              label="Cross-Source Timeline"
            />
            <TabButton
              active={activeTab === 'correlations'}
              onClick={() => setActiveTab('correlations')}
              icon={Link2}
              label="Correlations"
              badge={timelines.length > 0 ? timelines.length : undefined}
            />
            <TabButton
              active={activeTab === 'kill_chain'}
              onClick={() => setActiveTab('kill_chain')}
              icon={GitBranch}
              label="Attack Chains"
              badge={killChains.length > 0 ? killChains.length : undefined}
            />
            <TabButton
              active={activeTab === 'health'}
              onClick={() => setActiveTab('health')}
              icon={Activity}
              label="Source Health"
              badge={stats.degradedSources + stats.offlineSources > 0 ? stats.degradedSources + stats.offlineSources : undefined}
            />
            <TabButton
              active={activeTab === 'insights'}
              onClick={() => setActiveTab('insights')}
              icon={Brain}
              label="ML Insights"
              badge={correlationInsights.length > 0 ? correlationInsights.length : undefined}
            />
            <TabButton
              active={activeTab === 'sources'}
              onClick={() => setActiveTab('sources')}
              icon={Layers}
              label="By Source"
            />
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 p-4 border-b flex-wrap" style={{ borderColor: 'var(--border)' }}>
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                placeholder={activeTab === 'incidents' ? "Search incidents..." : "Search events..."}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg)' }}
              />
            </div>

            {activeTab === 'incidents' && (
              <select
                value={incidentStatusFilter}
                onChange={(e) => setIncidentStatusFilter(e.target.value)}
                className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg)' }}
              >
                <option value="all">All Statuses</option>
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="remediated">Remediated</option>
                <option value="closed">Closed</option>
              </select>
            )}

            <select
              value={sourceTypeFilter}
              onChange={(e) => setSourceTypeFilter(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg)' }}
            >
              <option value="all">All Sources</option>
              {sourceTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--fg)' }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Tab Content */}
          <div className="p-4">
            {activeTab === 'incidents' && (
              <UnifiedIncidentsView
                incidents={filteredIncidents}
                expandedIncident={expandedIncident}
                onExpandIncident={setExpandedIncident}
                loading={loading}
              />
            )}

            {activeTab === 'timeline' && (
              <CrossSourceTimelineView
                events={filteredCrossTimeline}
                loading={loading}
              />
            )}

            {activeTab === 'correlations' && (
              <CorrelationsView
                timelines={timelines}
                expandedTimeline={expandedTimeline}
                onExpandTimeline={setExpandedTimeline}
              />
            )}

            {activeTab === 'kill_chain' && (
              <KillChainView killChains={killChains} />
            )}

            {activeTab === 'health' && (
              <DataSourceHealthView
                sources={dataSourceHealth}
                loading={loading}
              />
            )}

            {activeTab === 'insights' && (
              <CorrelationInsightsView
                insights={correlationInsights}
                loading={loading}
              />
            )}

            {activeTab === 'sources' && (
              <BySourceView
                events={filteredEvents}
              />
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

// Helper Components

interface StatCardProps {
  title: string
  value: number
  subValue?: string
  icon: React.ElementType
  color: 'primary' | 'warning' | 'danger'
}

function StatCard({ title, value, subValue, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-primary-600/20 text-primary-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
    danger: 'bg-red-500/20 text-red-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
      <div className="flex items-center justify-between mb-2">
        <div className={cn('p-2 rounded-lg', colorClasses[color])}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{(value ?? 0).toLocaleString()}</div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>{title}</div>
      {subValue && <div className="text-xs mt-0.5" style={{ color: 'var(--muted)', opacity: 0.7 }}>{subValue}</div>}
    </div>
  )
}

function SourceHealthCard({ source }: { source: XDRSource }) {
  const Icon = SOURCE_TYPE_ICONS[source.sourceType] || Server
  const colorClass = SOURCE_TYPE_COLORS[source.sourceType] || SOURCE_TYPE_COLORS.endpoint

  const StatusIcon = source.status === 'healthy' ? CheckCircle :
    source.status === 'degraded' ? AlertCircle : XCircle
  const statusColor = source.status === 'healthy' ? 'var(--emerald-400)' :
    source.status === 'degraded' ? 'text-yellow-400' : 'text-red-400'

  return (
    <div className={cn(
      "rounded-lg border p-3 transition-colors hover:opacity-80",
      colorClass
    )}>
      <div className="flex items-center justify-between mb-2">
        <Icon className="h-5 w-5" />
        <StatusIcon className={cn("h-4 w-4", source.status === 'healthy' ? '' : statusColor)} style={source.status === 'healthy' ? { color: 'var(--emerald-400)' } : undefined} />
      </div>
      <div className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }} title={source.name}>
        {source.name}
      </div>
      <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
        {(source.eventsLastHour ?? 0).toLocaleString()} events/hr
      </div>
    </div>
  )
}

function SourceTypeCard({ type, count }: { type: string; count: number }) {
  const Icon = SOURCE_TYPE_ICONS[type] || Server
  const colorClass = SOURCE_TYPE_COLORS[type] || SOURCE_TYPE_COLORS.endpoint

  return (
    <div className={cn(
      "rounded-lg border p-3",
      colorClass
    )}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="h-5 w-5" />
        <span className="text-sm font-medium capitalize" style={{ color: 'var(--fg)' }}>{type}</span>
      </div>
      <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{(count ?? 0).toLocaleString()}</div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>events</div>
    </div>
  )
}

interface TabButtonProps {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
  badge?: number
}

function TabButton({ active, onClick, icon: Icon, label, badge }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors",
        active
          ? "bg-primary-600 text-white"
          : "hover:bg-slate-700"
      )}
      style={!active ? { color: 'var(--muted)' } : undefined}
    >
      <Icon className="h-4 w-4" />
      {label}
      {badge !== undefined && (
        <span className={cn(
          "px-1.5 py-0.5 rounded text-xs font-medium",
          active ? "bg-white/20" : "bg-slate-600"
        )}>
          {badge}
        </span>
      )}
    </button>
  )
}

function EventTimeline({ events, loading }: { events: XDREvent[]; loading: boolean }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: 'var(--muted)' }} />
      </div>
    )
  }

  if (events.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No events found for the selected filters</p>
      </div>
    )
  }

  return (
    <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
      {events.map(event => (
        <EventRow key={event.id} event={event} />
      ))}
    </div>
  )
}

function EventRow({ event }: { event: XDREvent }) {
  const Icon = SOURCE_TYPE_ICONS[event.sourceType] || Activity
  const colorClass = SOURCE_TYPE_COLORS[event.sourceType] || SOURCE_TYPE_COLORS.endpoint

  return (
    <div className="flex items-start gap-4 p-3 rounded-lg hover:opacity-80 transition-colors" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
      <div className={cn("p-2 rounded-lg shrink-0", colorClass)}>
        <Icon className="h-4 w-4" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
            {event.action || event.category || event.threatName || 'Event'}
          </span>
          <span className={cn('text-xs px-1.5 py-0.5 rounded', severityColor(event.severity))}>
            {event.severity.toUpperCase()}
          </span>
          <span className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{event.sourceType}</span>
        </div>

        <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
          {event.sourceIp && (
            <span>Source: {event.sourceIp}</span>
          )}
          {event.destIp && (
            <span>Dest: {event.destIp}</span>
          )}
          {event.user && (
            <span>User: {event.user}</span>
          )}
          {event.domain && (
            <span>Domain: {event.domain}</span>
          )}
        </div>

        {event.mitreTechniques && event.mitreTechniques.length > 0 && (
          <div className="flex items-center gap-1 mt-1">
            {event.mitreTechniques.slice(0, 3).map(tech => (
              <span key={tech} className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">
                {tech}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="text-xs shrink-0" style={{ color: 'var(--muted)' }}>
        {formatDate(event.timestamp)}
      </div>
    </div>
  )
}

function CorrelationsView({
  timelines,
  expandedTimeline,
  onExpandTimeline,
}: {
  timelines: AttackTimeline[]
  expandedTimeline: string | null
  onExpandTimeline: (id: string | null) => void
}) {
  if (timelines.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <Link2 className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No active attack timelines detected</p>
        <p className="text-sm mt-1">Cross-source correlations will appear here</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {timelines.map(timeline => (
        <div
          key={timeline.id}
          className="rounded-lg border"
          style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}
        >
          <button
            onClick={() => onExpandTimeline(expandedTimeline === timeline.id ? null : timeline.id)}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-4">
              <div className={cn(
                "p-2 rounded-lg",
                timeline.riskScore >= 0.7 ? "bg-red-500/20 text-red-400" :
                timeline.riskScore >= 0.4 ? "bg-yellow-500/20 text-yellow-400" :
                "bg-blue-500/20 text-blue-400"
              )}>
                <GitBranch className="h-5 w-5" />
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>
                    Attack Timeline
                  </span>
                  <span className={cn(
                    "text-xs px-1.5 py-0.5 rounded",
                    timeline.status === 'active' ? "bg-red-500/20 text-red-400" :
                    timeline.status === 'investigating' ? "bg-yellow-500/20 text-yellow-400" :
                    "bg-green-500/20 text-green-400"
                  )}>
                    {timeline.status}
                  </span>
                </div>
                <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                  {timeline.eventCount} events across {timeline.sourceTypes.length} sources
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                  {Math.round(timeline.riskScore * 100)}% Risk
                </div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  {timeline.phases.length} kill chain phases
                </div>
              </div>
              {expandedTimeline === timeline.id ? (
                <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              ) : (
                <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              )}
            </div>
          </button>

          {expandedTimeline === timeline.id && (
            <div className="border-t p-4 space-y-4" style={{ borderColor: 'var(--border)' }}>
              {/* Kill Chain Visualization */}
              <div>
                <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Kill Chain Progression</h4>
                <div className="flex items-center gap-1 overflow-x-auto pb-2">
                  {KILL_CHAIN_PHASES.map((phase, idx) => {
                    const isActive = timeline.phases.includes(phase.id)
                    return (
                      <div key={phase.id} className="flex items-center">
                        <div className={cn(
                          "px-3 py-1.5 rounded text-xs font-medium whitespace-nowrap",
                          isActive
                            ? "bg-red-500/20 text-red-400 border border-red-500/30"
                            : "bg-slate-600/50 text-slate-500"
                        )}>
                          {phase.name}
                        </div>
                        {idx < KILL_CHAIN_PHASES.length - 1 && (
                          <ChevronRight className={cn(
                            "h-4 w-4 mx-0.5",
                            isActive ? "text-red-400" : "text-slate-600"
                          )} />
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Source Types */}
              <div>
                <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Sources Involved</h4>
                <div className="flex items-center gap-2 flex-wrap">
                  {timeline.sourceTypes.map(type => {
                    const TypeIcon = SOURCE_TYPE_ICONS[type] || Server
                    return (
                      <div
                        key={type}
                        className={cn(
                          "flex items-center gap-1.5 px-2 py-1 rounded text-xs",
                          SOURCE_TYPE_COLORS[type] || SOURCE_TYPE_COLORS.endpoint
                        )}
                      >
                        <TypeIcon className="h-3.5 w-3.5" />
                        <span className="capitalize">{type}</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Indicators */}
              {Object.keys(timeline.indicators ?? {}).length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Indicators</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {Object.entries(timeline.indicators ?? {}).map(([type, values]) => (
                      <div key={type} className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                        <div className="text-xs uppercase mb-1" style={{ color: 'var(--muted)' }}>{type}</div>
                        <div className="space-y-0.5">
                          {values.slice(0, 3).map((v, i) => (
                            <div key={i} className="text-xs truncate" style={{ color: 'var(--muted)' }} title={v}>
                              {v}
                            </div>
                          ))}
                          {values.length > 3 && (
                            <div className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                              +{values.length - 3} more
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  First event: {formatDate(timeline.firstEventAt)} | Last event: {formatDate(timeline.lastEventAt)}
                </div>
                <a
                  href={`/app/timeline/${timeline.id}`}
                  className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1"
                >
                  View Full Timeline <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function KillChainView({ killChains }: { killChains: KillChainDetection[] }) {
  if (killChains.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No kill chain progressions detected</p>
        <p className="text-sm mt-1">Multi-stage attack patterns will appear here</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {killChains.map((kc, idx) => (
        <div
          key={idx}
          className="rounded-lg border p-4"
          style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}
        >
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                  Kill Chain: {kc.indicator.type} - {kc.indicator.value}
                </span>
                <span className={cn(
                  "text-xs px-1.5 py-0.5 rounded",
                  kc.riskScore >= 0.7 ? "bg-red-500/20 text-red-400" :
                  kc.riskScore >= 0.4 ? "bg-yellow-500/20 text-yellow-400" :
                  "bg-blue-500/20 text-blue-400"
                )}>
                  {Math.round(kc.riskScore * 100)}% Risk
                </span>
              </div>
              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                {kc.phaseCount} phases | {kc.eventCount} events | {kc.sourceTypes.length} sources
              </div>
            </div>
            <div className="text-xs" style={{ color: 'var(--muted)' }}>
              Detected: {formatDate(kc.detectedAt)}
            </div>
          </div>

          {/* Kill Chain Visualization */}
          <div className="flex items-center gap-1 overflow-x-auto pb-2">
            {KILL_CHAIN_PHASES.map((phase, phaseIdx) => {
              const isActive = kc.phases.includes(phase.id)
              return (
                <div key={phase.id} className="flex items-center">
                  <div className={cn(
                    "px-3 py-1.5 rounded text-xs font-medium whitespace-nowrap",
                    isActive
                      ? "bg-red-500/20 text-red-400 border border-red-500/30"
                      : "bg-slate-600/50 text-slate-500"
                  )}>
                    {phase.name}
                  </div>
                  {phaseIdx < KILL_CHAIN_PHASES.length - 1 && (
                    <ChevronRight className={cn(
                      "h-4 w-4 mx-0.5",
                      isActive ? "text-red-400" : "text-slate-600"
                    )} />
                  )}
                </div>
              )
            })}
          </div>

          {/* Source Types */}
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            {kc.sourceTypes.map(type => {
              const TypeIcon = SOURCE_TYPE_ICONS[type] || Server
              return (
                <div
                  key={type}
                  className={cn(
                    "flex items-center gap-1.5 px-2 py-1 rounded text-xs",
                    SOURCE_TYPE_COLORS[type] || SOURCE_TYPE_COLORS.endpoint
                  )}
                >
                  <TypeIcon className="h-3.5 w-3.5" />
                  <span className="capitalize">{type}</span>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

function BySourceView({ events }: { events: XDREvent[] }) {
  const bySource = useMemo(() => {
    const grouped: Record<string, XDREvent[]> = {}
    events.forEach(e => {
      if (!grouped[e.sourceType]) grouped[e.sourceType] = []
      grouped[e.sourceType].push(e)
    })
    return grouped
  }, [events])

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {Object.entries(bySource).map(([sourceType, sourceEvents]) => {
        const Icon = SOURCE_TYPE_ICONS[sourceType] || Server
        const colorClass = SOURCE_TYPE_COLORS[sourceType] || SOURCE_TYPE_COLORS.endpoint

        // Count by severity
        const bySeverity: Record<string, number> = {}
        sourceEvents.forEach(e => {
          bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1
        })

        return (
          <div
            key={sourceType}
            className="rounded-lg border p-4"
            style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}
          >
            <div className="flex items-center gap-3 mb-4">
              <div className={cn("p-2 rounded-lg", colorClass)}>
                <Icon className="h-5 w-5" />
              </div>
              <div>
                <div className="text-lg font-medium capitalize" style={{ color: 'var(--fg)' }}>{sourceType}</div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>{sourceEvents.length} events</div>
              </div>
            </div>

            {/* Severity breakdown */}
            <div className="grid grid-cols-5 gap-2 mb-4">
              {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <div key={sev} className="text-center">
                  <div className={cn(
                    "text-lg font-bold",
                    sev === 'critical' ? 'text-red-400' :
                    sev === 'high' ? 'text-orange-400' :
                    sev === 'medium' ? 'text-yellow-400' :
                    sev === 'low' ? 'text-blue-400' : 'text-slate-400'
                  )}>
                    {bySeverity[sev] || 0}
                  </div>
                  <div className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{sev}</div>
                </div>
              ))}
            </div>

            {/* Recent events */}
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {sourceEvents.slice(0, 5).map(event => (
                <div key={event.id} className="flex items-center gap-2 text-xs p-1.5 rounded" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                  <span className={cn(
                    "w-1.5 h-1.5 rounded-full shrink-0",
                    event.severity === 'critical' ? 'bg-red-400' :
                    event.severity === 'high' ? 'bg-orange-400' :
                    event.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                  )} />
                  <span className="truncate flex-1" style={{ color: 'var(--muted)' }}>
                    {event.action || event.category || event.threatName || 'Event'}
                  </span>
                  <span className="shrink-0" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                    {formatDate(event.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )
      })}

      {Object.keys(bySource).length === 0 && (
        <div className="col-span-full text-center py-12" style={{ color: 'var(--muted)' }}>
          <Layers className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>No events to display by source</p>
        </div>
      )}
    </div>
  )
}

// Utility function
function getTimeWindowMs(timeRange: string): number {
  switch (timeRange) {
    case '1h': return 60 * 60 * 1000
    case '24h': return 24 * 60 * 60 * 1000
    case '7d': return 7 * 24 * 60 * 60 * 1000
    case '30d': return 30 * 24 * 60 * 60 * 1000
    default: return 24 * 60 * 60 * 1000
  }
}

// ============================================================================
// Unified Incidents View
// ============================================================================

function UnifiedIncidentsView({
  incidents,
  expandedIncident,
  onExpandIncident,
  loading,
}: {
  incidents: XDRIncident[]
  expandedIncident: string | null
  onExpandIncident: (id: string | null) => void
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: 'var(--muted)' }} />
      </div>
    )
  }

  if (incidents.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <AlertOctagon className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No incidents found</p>
        <p className="text-sm mt-1">Incidents are automatically created from correlated events</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {incidents.map(incident => (
        <div
          key={incident.id}
          className="rounded-lg border"
          style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}
        >
          <button
            onClick={() => onExpandIncident(expandedIncident === incident.id ? null : incident.id)}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-4">
              <div className={cn(
                "p-2 rounded-lg",
                incident.severity === 'critical' ? "bg-red-500/20 text-red-400" :
                incident.severity === 'high' ? "bg-orange-500/20 text-orange-400" :
                incident.severity === 'medium' ? "bg-yellow-500/20 text-yellow-400" :
                "bg-blue-500/20 text-blue-400"
              )}>
                <ShieldAlert className="h-5 w-5" />
              </div>

              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{incident.title}</span>
                  <span className={cn(
                    "text-xs px-1.5 py-0.5 rounded border",
                    INCIDENT_STATUS_COLORS[incident.status]
                  )}>
                    {incident.status}
                  </span>
                  <span className={cn(
                    "text-xs px-1.5 py-0.5 rounded",
                    severityColor(incident.severity)
                  )}>
                    {incident.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-xs mt-1 flex items-center gap-3" style={{ color: 'var(--muted)' }}>
                  <span>{incident.eventCount} events</span>
                  <span>{incident.alertCount} alerts</span>
                  <span>{incident.affectedAssets} assets</span>
                  <span>{incident.sourceTypes.length} sources</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-sm font-medium flex items-center gap-1" style={{ color: 'var(--fg)' }}>
                  <Brain className="h-4 w-4 text-purple-400" />
                  {Math.round(incident.mlCorrelationScore * 100)}% ML Score
                </div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  {incident.killChainPhases.length} kill chain phases
                </div>
              </div>
              {expandedIncident === incident.id ? (
                <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              ) : (
                <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              )}
            </div>
          </button>

          {expandedIncident === incident.id && (
            <div className="border-t p-4 space-y-4" style={{ borderColor: 'var(--border)' }}>
              {/* Description */}
              {incident.description && (
                <p className="text-sm" style={{ color: 'var(--muted)' }}>{incident.description}</p>
              )}

              {/* Kill Chain Progression */}
              <div>
                <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Kill Chain Progression</h4>
                <div className="flex items-center gap-1 overflow-x-auto pb-2">
                  {KILL_CHAIN_PHASES.map((phase, idx) => {
                    const isActive = incident.killChainPhases.includes(phase.id)
                    return (
                      <div key={phase.id} className="flex items-center">
                        <div className={cn(
                          "px-3 py-1.5 rounded text-xs font-medium whitespace-nowrap",
                          isActive
                            ? "bg-red-500/20 text-red-400 border border-red-500/30"
                            : "bg-slate-600/50 text-slate-500"
                        )}>
                          {phase.name}
                        </div>
                        {idx < KILL_CHAIN_PHASES.length - 1 && (
                          <ChevronRight className={cn(
                            "h-4 w-4 mx-0.5",
                            isActive ? "text-red-400" : "text-slate-600"
                          )} />
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* MITRE Techniques */}
              {incident.mitreTechniques.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>MITRE ATT&CK Techniques</h4>
                  <div className="flex items-center gap-2 flex-wrap">
                    {incident.mitreTechniques.map(tech => (
                      <span
                        key={tech}
                        className="text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded border border-red-500/30"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Source Types */}
              <div>
                <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Sources Involved</h4>
                <div className="flex items-center gap-2 flex-wrap">
                  {incident.sourceTypes.map(type => {
                    const TypeIcon = SOURCE_TYPE_ICONS[type] || Server
                    return (
                      <div
                        key={type}
                        className={cn(
                          "flex items-center gap-1.5 px-2 py-1 rounded text-xs",
                          SOURCE_TYPE_COLORS[type] || SOURCE_TYPE_COLORS.endpoint
                        )}
                      >
                        <TypeIcon className="h-3.5 w-3.5" />
                        <span className="capitalize">{type}</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Indicators Grid */}
              <div>
                <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Indicators of Compromise</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {incident.indicators.ips.length > 0 && (
                    <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                      <div className="text-xs uppercase mb-1 flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                        <MapPin className="h-3 w-3" /> IPs ({incident.indicators.ips.length})
                      </div>
                      <div className="space-y-0.5">
                        {incident.indicators.ips.slice(0, 3).map((ip, i) => (
                          <div key={i} className="text-xs truncate" style={{ color: 'var(--muted)' }} title={ip}>
                            {ip}
                          </div>
                        ))}
                        {incident.indicators.ips.length > 3 && (
                          <div className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>+{incident.indicators.ips.length - 3} more</div>
                        )}
                      </div>
                    </div>
                  )}
                  {incident.indicators.domains.length > 0 && (
                    <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                      <div className="text-xs uppercase mb-1 flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                        <Globe className="h-3 w-3" /> Domains ({incident.indicators.domains.length})
                      </div>
                      <div className="space-y-0.5">
                        {incident.indicators.domains.slice(0, 3).map((domain, i) => (
                          <div key={i} className="text-xs truncate" style={{ color: 'var(--muted)' }} title={domain}>
                            {domain}
                          </div>
                        ))}
                        {incident.indicators.domains.length > 3 && (
                          <div className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>+{incident.indicators.domains.length - 3} more</div>
                        )}
                      </div>
                    </div>
                  )}
                  {incident.indicators.hashes.length > 0 && (
                    <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                      <div className="text-xs uppercase mb-1 flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                        <Fingerprint className="h-3 w-3" /> Hashes ({incident.indicators.hashes.length})
                      </div>
                      <div className="space-y-0.5">
                        {incident.indicators.hashes.slice(0, 3).map((hash, i) => (
                          <div key={i} className="text-xs truncate font-mono" style={{ color: 'var(--muted)' }} title={hash}>
                            {hash.substring(0, 16)}...
                          </div>
                        ))}
                        {incident.indicators.hashes.length > 3 && (
                          <div className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>+{incident.indicators.hashes.length - 3} more</div>
                        )}
                      </div>
                    </div>
                  )}
                  {incident.indicators.users.length > 0 && (
                    <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                      <div className="text-xs uppercase mb-1 flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                        <Users className="h-3 w-3" /> Users ({incident.indicators.users.length})
                      </div>
                      <div className="space-y-0.5">
                        {incident.indicators.users.slice(0, 3).map((user, i) => (
                          <div key={i} className="text-xs truncate" style={{ color: 'var(--muted)' }} title={user}>
                            {user}
                          </div>
                        ))}
                        {incident.indicators.users.length > 3 && (
                          <div className="text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>+{incident.indicators.users.length - 3} more</div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Entity Graph Info */}
              {incident.entityGraph && (
                <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
                  <span className="flex items-center gap-1">
                    <Workflow className="h-3 w-3" />
                    Entity Graph: {incident.entityGraph.nodes} nodes, {incident.entityGraph.edges} edges
                  </span>
                  {incident.entityGraph.centralEntity && (
                    <span>Central: {incident.entityGraph.centralEntity}</span>
                  )}
                </div>
              )}

              {/* Footer */}
              <div className="flex items-center justify-between pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  Created: {formatDate(incident.createdAt)} | First event: {formatDate(incident.firstEventAt)}
                  {incident.timeToDetect && ` | TTD: ${incident.timeToDetect}min`}
                </div>
                <div className="flex items-center gap-2">
                  <a
                    href={`/app/incidents/${incident.id}`}
                    className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1"
                  >
                    View Details <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                  <button className="text-sm flex items-center gap-1 px-2 py-1 rounded bg-green-500/10" style={{ color: 'var(--emerald-400)' }}>
                    <Play className="h-3.5 w-3.5" /> Run Playbook
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ============================================================================
// Cross-Source Timeline View
// ============================================================================

function CrossSourceTimelineView({
  events,
  loading,
}: {
  events: CrossSourceTimelineEvent[]
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: 'var(--muted)' }} />
      </div>
    )
  }

  if (events.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No cross-source events found</p>
        <p className="text-sm mt-1">Events from multiple data sources will appear here</p>
      </div>
    )
  }

  // Group events by time buckets for visual timeline
  const groupedEvents = events.reduce((acc, event) => {
    const date = new Date(event.timestamp)
    const hour = date.toISOString().substring(0, 13) // Group by hour
    if (!acc[hour]) acc[hour] = []
    acc[hour].push(event)
    return acc
  }, {} as Record<string, CrossSourceTimelineEvent[]>)

  return (
    <div className="space-y-6 max-h-[600px] overflow-y-auto pr-2">
      {Object.entries(groupedEvents).map(([hour, hourEvents]) => (
        <div key={hour} className="relative">
          {/* Time marker */}
          <div className="sticky top-0 z-10 py-2 flex items-center gap-2" style={{ backgroundColor: 'var(--surface)' }}>
            <div className="w-24 text-xs font-medium" style={{ color: 'var(--muted)' }}>
              {new Date(hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </div>
            <div className="flex-1 h-px" style={{ backgroundColor: 'var(--border)' }} />
            <span className="text-xs" style={{ color: 'var(--muted)' }}>{hourEvents.length} events</span>
          </div>

          {/* Events in this hour */}
          <div className="space-y-2 pl-8 border-l-2 ml-2" style={{ borderColor: 'var(--border)' }}>
            {hourEvents.map(event => {
              const Icon = SOURCE_TYPE_ICONS[event.sourceType] || Activity
              const colorClass = SOURCE_TYPE_COLORS[event.sourceType] || SOURCE_TYPE_COLORS.endpoint

              return (
                <div
                  key={event.id}
                  className="flex items-start gap-3 p-3 rounded-lg hover:opacity-80 transition-colors relative"
                  style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}
                >
                  {/* Timeline dot */}
                  <div className="absolute -left-[1.35rem] top-4 w-3 h-3 rounded-full border-2" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface)' }}>
                    <div className={cn(
                      "w-1.5 h-1.5 rounded-full mx-auto mt-0.5",
                      event.severity === 'critical' ? 'bg-red-400' :
                      event.severity === 'high' ? 'bg-orange-400' :
                      event.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                    )} />
                  </div>

                  <div className={cn("p-2 rounded-lg shrink-0", colorClass)}>
                    <Icon className="h-4 w-4" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{event.title}</span>
                      <span className={cn('text-xs px-1.5 py-0.5 rounded', severityColor(event.severity))}>
                        {event.severity.toUpperCase()}
                      </span>
                      <span className="text-xs" style={{ color: 'var(--muted)' }}>{event.sourceName}</span>
                    </div>

                    {event.description && (
                      <p className="text-xs mb-1" style={{ color: 'var(--muted)' }}>{event.description}</p>
                    )}

                    <div className="flex items-center gap-3 text-xs flex-wrap" style={{ color: 'var(--muted)' }}>
                      {event.killChainPhase && (
                        <span className="bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">
                          {event.killChainPhase}
                        </span>
                      )}
                      {event.mitreTechnique && (
                        <span className="bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">
                          {event.mitreTechnique}
                        </span>
                      )}
                      {event.relatedEntities.slice(0, 3).map((entity, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <span style={{ color: 'var(--muted)', opacity: 0.7 }}>{entity.type}:</span>
                          <span style={{ color: 'var(--muted)' }}>{entity.value}</span>
                        </span>
                      ))}
                    </div>

                    {event.incidentId && (
                      <a
                        href={`/app/incidents/${event.incidentId}`}
                        className="text-xs text-primary-400 hover:text-primary-300 mt-1 inline-flex items-center gap-1"
                      >
                        <Link2 className="h-3 w-3" /> Linked to incident
                      </a>
                    )}
                  </div>

                  <div className="text-xs shrink-0" style={{ color: 'var(--muted)' }}>
                    {formatDate(event.timestamp)}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

// ============================================================================
// Data Source Health View
// ============================================================================

function DataSourceHealthView({
  sources,
  loading,
}: {
  sources: DataSourceHealth[]
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: 'var(--muted)' }} />
      </div>
    )
  }

  if (sources.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No data sources configured</p>
        <a href="/app/integrations" className="text-primary-400 hover:text-primary-300 text-sm">
          Configure data sources
        </a>
      </div>
    )
  }

  // Group by status
  const byStatus = {
    healthy: sources.filter(s => s.status === 'healthy'),
    degraded: sources.filter(s => s.status === 'degraded'),
    offline: sources.filter(s => s.status === 'offline' || s.status === 'error'),
  }

  return (
    <div className="space-y-6">
      {/* Health Summary */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg p-4" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            <span className="font-medium" style={{ color: 'var(--emerald-400)' }}>Healthy</span>
          </div>
          <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{byStatus.healthy.length}</div>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="h-5 w-5 text-yellow-400" />
            <span className="text-yellow-400 font-medium">Degraded</span>
          </div>
          <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{byStatus.degraded.length}</div>
        </div>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <XCircle className="h-5 w-5 text-red-400" />
            <span className="text-red-400 font-medium">Offline/Error</span>
          </div>
          <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{byStatus.offline.length}</div>
        </div>
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-5 w-5" style={{ color: 'var(--muted)' }} />
            <span className="font-medium" style={{ color: 'var(--muted)' }}>Events/sec</span>
          </div>
          <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
            {sources.reduce((acc, s) => acc + s.eventsPerSecond, 0).toFixed(1)}
          </div>
        </div>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {sources.map(source => {
          const Icon = SOURCE_TYPE_ICONS[source.type] || Server
          const colorClass = SOURCE_TYPE_COLORS[source.type] || SOURCE_TYPE_COLORS.endpoint
          const StatusIcon = source.status === 'healthy' ? CheckCircle :
            source.status === 'degraded' ? AlertCircle : XCircle
          const statusColor = source.status === 'healthy' ? 'var(--emerald-400)' :
            source.status === 'degraded' ? 'text-yellow-400' : 'text-red-400'

          return (
            <div key={source.id} className="rounded-lg border p-4" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={cn("p-2 rounded-lg", colorClass)}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="font-medium" style={{ color: 'var(--fg)' }}>{source.name}</div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>{source.vendor} - {source.type}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <StatusIcon className={cn("h-5 w-5", source.status !== 'healthy' && statusColor)} style={source.status === 'healthy' ? { color: statusColor } : undefined} />
                  <span className={cn("text-sm font-medium capitalize", source.status !== 'healthy' && statusColor)} style={source.status === 'healthy' ? { color: statusColor } : undefined}>
                    {source.status}
                  </span>
                </div>
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-4 gap-3 mb-4">
                <div className="text-center">
                  <div className="text-lg font-bold" style={{ color: 'var(--fg)' }}>{source.eventsPerSecond.toFixed(1)}</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Events/sec</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold" style={{ color: 'var(--fg)' }}>{(source.eventsLastHour ?? 0).toLocaleString()}</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Events/hr</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold" style={{ color: 'var(--fg)' }}>{source.latencyMs}ms</div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Latency</div>
                </div>
                <div className="text-center">
                  <div className={cn(
                    "text-lg font-bold",
                    source.errorRate > 5 ? "text-red-400" :
                    source.errorRate > 1 ? "text-yellow-400" : ""
                  )} style={source.errorRate <= 1 ? { color: 'var(--emerald-400)' } : undefined}>
                    {source.errorRate.toFixed(1)}%
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Error Rate</div>
                </div>
              </div>

              {/* Data Lake Status */}
              <div className="flex items-center justify-between text-xs rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                <div className="flex items-center gap-2">
                  <HardDrive className="h-3.5 w-3.5" style={{ color: 'var(--muted)' }} />
                  <span style={{ color: 'var(--muted)' }}>Data Lake:</span>
                  <span className={cn("px-1.5 py-0.5 rounded", DATA_LAKE_STATUS_COLORS[source.dataLakeStatus])}>
                    {source.dataLakeStatus} tier
                  </span>
                </div>
                <div style={{ color: 'var(--muted)' }}>
                  {(source.diskUsageMb / 1024).toFixed(2)} GB | {source.retentionDays}d retention
                </div>
              </div>

              {/* Last Activity */}
              <div className="flex items-center justify-between mt-3 text-xs" style={{ color: 'var(--muted)' }}>
                <span>Last heartbeat: {source.lastHeartbeat ? formatDate(source.lastHeartbeat) : 'N/A'}</span>
                <span>Last event: {source.lastEventAt ? formatDate(source.lastEventAt) : 'N/A'}</span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ============================================================================
// Correlation Insights View
// ============================================================================

function CorrelationInsightsView({
  insights,
  loading,
}: {
  insights: CorrelationInsight[]
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: 'var(--muted)' }} />
      </div>
    )
  }

  if (insights.length === 0) {
    return (
      <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
        <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No correlation insights available</p>
        <p className="text-sm mt-1">ML-powered insights will appear as patterns are detected</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {insights.map(insight => {
        const Icon = INSIGHT_TYPE_ICONS[insight.type] || Lightbulb
        const colorClass = INSIGHT_TYPE_COLORS[insight.type] || 'bg-purple-500/20 text-purple-400'

        return (
          <div key={insight.id} className="rounded-lg border p-4" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}>
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <div className={cn("p-2 rounded-lg", colorClass)}>
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium" style={{ color: 'var(--fg)' }}>{insight.title}</span>
                    <span className={cn('text-xs px-1.5 py-0.5 rounded', severityColor(insight.severity))}>
                      {insight.severity.toUpperCase()}
                    </span>
                    <span className="text-xs bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded capitalize">
                      {insight.type.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                    {Math.round(insight.confidence * 100)}% confidence
                    {insight.metadata.mlModelUsed && ` | Model: ${insight.metadata.mlModelUsed}`}
                  </div>
                </div>
              </div>
              <div className="text-xs" style={{ color: 'var(--muted)' }}>
                {formatDate(insight.createdAt)}
              </div>
            </div>

            <p className="text-sm mb-3" style={{ color: 'var(--muted)' }}>{insight.description}</p>

            {/* Recommendation */}
            {insight.recommendation && (
              <div className="bg-primary-500/10 border border-primary-500/30 rounded p-3 mb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Lightbulb className="h-4 w-4 text-primary-400" />
                  <span className="text-sm font-medium text-primary-400">Recommendation</span>
                </div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>{insight.recommendation}</p>
              </div>
            )}

            {/* Details Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {/* MITRE Techniques */}
              {insight.mitreTechniques.length > 0 && (
                <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                  <div className="text-xs uppercase mb-1" style={{ color: 'var(--muted)' }}>MITRE Techniques</div>
                  <div className="flex flex-wrap gap-1">
                    {insight.mitreTechniques.slice(0, 3).map(tech => (
                      <span key={tech} className="text-xs bg-red-500/20 text-red-400 px-1 py-0.5 rounded">
                        {tech}
                      </span>
                    ))}
                    {insight.mitreTechniques.length > 3 && (
                      <span className="text-xs" style={{ color: 'var(--muted)' }}>+{insight.mitreTechniques.length - 3}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Sources Involved */}
              {insight.sourcesInvolved.length > 0 && (
                <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                  <div className="text-xs uppercase mb-1" style={{ color: 'var(--muted)' }}>Sources</div>
                  <div className="flex flex-wrap gap-1">
                    {insight.sourcesInvolved.slice(0, 3).map(src => (
                      <span key={src} className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{src}</span>
                    ))}
                    {insight.sourcesInvolved.length > 3 && (
                      <span className="text-xs" style={{ color: 'var(--muted)' }}>+{insight.sourcesInvolved.length - 3}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Related Incidents */}
              {insight.relatedIncidents.length > 0 && (
                <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                  <div className="text-xs uppercase mb-1" style={{ color: 'var(--muted)' }}>Related Incidents</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>{insight.relatedIncidents.length} incidents</div>
                </div>
              )}

              {/* Metadata */}
              {insight.metadata.entityGraphNodes && (
                <div className="rounded p-2" style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                  <div className="text-xs uppercase mb-1" style={{ color: 'var(--muted)' }}>Entity Graph</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>{insight.metadata.entityGraphNodes} nodes</div>
                </div>
              )}
            </div>

            {/* Timeframe */}
            <div className="flex items-center justify-between mt-3 pt-3 border-t text-xs" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
              <span>Timeframe: {formatDate(insight.timeframe.start)} - {formatDate(insight.timeframe.end)}</span>
              {insight.relatedIndicators.length > 0 && (
                <span>{insight.relatedIndicators.length} indicators involved</span>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
