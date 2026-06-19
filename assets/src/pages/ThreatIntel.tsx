import { useState, useEffect, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Search,
  Filter,
  RefreshCw,
  Globe,
  Users,
  Target,
  Database,
  CheckCircle,
  XCircle,
  Clock,
  Plus,
  Settings,
  AlertCircle,
  FileText,
  Server,
  Link2,
  Shield,
  TrendingUp,
  ChevronDown,
  ChevronRight,
  Eye,
  Upload,
  BarChart3,
  Calendar,
  MapPin,
  Crosshair,
  Activity,
  AlertTriangle,
  Info,
  Edit,
  Trash2,
  TestTube,
  Zap,
  ShieldAlert,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { ExportDropdown } from '@/components/ExportDropdown'
import { Select, SelectItem } from '@/components/ui/baseui'
import axios from 'axios'
import { toast } from 'sonner'

// Types
interface IOC {
  id: string
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email'
  value: string
  threatType: string
  confidence: number
  source: string
  firstSeen: string
  lastSeen: string
  tags: string[]
  score?: number
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

function apiDataArray(payload: any, nestedKeys: string[] = []): any[] {
  if (Array.isArray(payload)) return payload
  if (Array.isArray(payload?.data)) return payload.data

  const data = payload?.data
  if (data && typeof data === 'object') {
    for (const key of nestedKeys) {
      if (Array.isArray(data[key])) return data[key]
    }
  }

  if (payload && typeof payload === 'object') {
    for (const key of nestedKeys) {
      if (Array.isArray(payload[key])) return payload[key]
    }
  }

  return []
}

function apiDataObject<T extends Record<string, any>>(payload: any): Partial<T> {
  const data = payload?.data
  if (data && typeof data === 'object' && !Array.isArray(data)) return data
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) return payload
  return {}
}

function numericStat(value: unknown): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function domainFromIOC(ioc: IOC): string | null {
  if (ioc.type === 'domain') return ioc.value

  if (ioc.type === 'url') {
    try {
      return new URL(ioc.value).hostname
    } catch {
      return null
    }
  }

  return null
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  motivation: 'financial' | 'espionage' | 'hacktivism' | 'sabotage' | 'unknown'
  targetSectors: string[]
  originCountry: string
  activeSince: string
  lastActivity: string
  ttps: string[]
  description?: string
  sophistication?: string
  resourceLevel?: string
  knownMalware?: string[]
  knownTools?: string[]
  iocCount?: number
  confidence?: number
}

interface Campaign {
  id: string
  name: string
  actor: string
  status: 'active' | 'dormant' | 'concluded'
  startDate: string
  endDate?: string
  targetRegions: string[]
  description: string
}

interface IntelSource {
  id: string
  name: string
  type: 'feed' | 'osint' | 'commercial' | 'internal'
  status: 'online' | 'offline' | 'degraded' | 'configured'
  lastSync: string | null
  iocCount: number
}

interface MISPInstance {
  id: string
  name: string
  url: string
  enabled: boolean
  verifySSL: boolean
  pullEnabled: boolean
  pushEnabled: boolean
  trustLevel: number
  syncIntervalHours: number
  lastSync: string | null
  lastSyncStatus: string | null
  eventsSynced: number
  iocsImported: number
  serverVersion?: string
  canPublish: boolean
  canSighting: boolean
  tagsFilter: string[]
  threatLevelFilter: number[]
}

interface MISPEvent {
  id: string
  mispEventId: string
  uuid: string
  info: string
  threatLevelId: number
  threatLevel: string
  analysis: number
  analysisStatus: string
  date: string
  published: boolean
  orgName: string
  orgcName: string
  tags: string[]
  galaxies: any[]
  attributeCount: number
  tlp: string
  threatActorName?: string
  campaignName?: string
  malwareFamily?: string
  syncedAt: string
}

interface FeedStatus {
  enabled: boolean
  lastSync: string | null
  syncIntervalHours: number
  totalIocs: number
  iocsBySource: Record<string, number>
  apiKeysConfigured: {
    misp: boolean
    otx: boolean
    virustotal: boolean
    shodan: boolean
    recordedFuture: boolean
    mandiant: boolean
    crowdstrike: boolean
    proofpoint: boolean
  }
  feedHealth?: Record<string, {
    status: 'healthy' | 'stale' | 'error' | 'unknown'
    lastSeen: string | null
    iocsLastBatch: number
  }>
  aggregatorStats?: {
    totalIngested: number
    totalDeduplicated: number
    hotCacheSize: number
    cacheHitRate: number
    multiSourceCount: number
  }
}

interface IOCScoringConfig {
  halfLifeDays: number
  minScoreThreshold: number
  maxSightingBoost: number
  fpWeight: number
  correlationBoost: number
  sourceReputation: Record<string, number>
  typeWeights: Record<string, number>
}

interface ThreatIntelPageProps {
  iocs?: IOC[]
  actors?: ThreatActor[]
  campaigns?: Campaign[]
  sources?: IntelSource[]
}

interface TenantBlocklistEntry {
  domain: string
  blocked_at?: string | null
  blocked_by?: string | null
  reason?: string | null
  source?: string | null
}

interface DNSPolicyStats {
  total_queries_today: number
  unique_domains: number
  blocked_count: number
  suspicious_count: number
}

interface DetectionContentCoverage {
  sigmaTotal: number
  sigmaEnabled: number
  yaraTotal: number
  yaraLoaded: number
  yaraScans: number
}

type AlertSourceKind = 'behavioral' | 'sigma' | 'yara' | 'ioc' | 'dns_policy' | 'ai_runtime' | 'evasion'

const ALERT_SOURCE_CATALOG: Array<{
  id: AlertSourceKind
  label: string
  description: string
  visibility: 'open' | 'tenant' | 'managed'
}> = [
  {
    id: 'behavioral',
    label: 'Behavioral detection',
    description: 'Process, file, memory, network, persistence and response correlations from endpoint telemetry.',
    visibility: 'tenant',
  },
  {
    id: 'sigma',
    label: 'Sigma rules',
    description: 'Process, auth, network and system event rules mapped to ATT&CK where metadata is available.',
    visibility: 'open',
  },
  {
    id: 'yara',
    label: 'YARA rules',
    description: 'File and memory scanning rules, including built-in packs and tenant-imported rules.',
    visibility: 'open',
  },
  {
    id: 'ioc',
    label: 'IOC match',
    description: 'Hash, domain, IP, URL and email indicators enriched by feeds, MISP, manual entries and validated contributions.',
    visibility: 'managed',
  },
  {
    id: 'dns_policy',
    label: 'DNS/IP policy',
    description: 'Tenant blocklists, allowlists and promoted high-confidence IOCs with audit trail and rollback.',
    visibility: 'tenant',
  },
  {
    id: 'ai_runtime',
    label: 'AI runtime security',
    description: 'Prompt injection, tool abuse, data exfiltration and model/runtime posture signals.',
    visibility: 'tenant',
  },
  {
    id: 'evasion',
    label: 'Memory and evasion',
    description: 'RWX/private executable memory, shellcode, syscall evasion, sleep masking and tamper behavior.',
    visibility: 'tenant',
  },
]

// ===========================================================================
// Helper function for IOC type badge classes
// ===========================================================================

function getIOCTypeBadgeClass(type: string): string {
  switch (type) {
    case 'ip': return 'badge-sentinel badge-sentinel-info'
    case 'domain': return 'badge-sentinel badge-sentinel-sol-magenta'
    case 'hash': return 'badge-sentinel badge-sentinel-high'
    case 'url': return 'badge-sentinel badge-sentinel-success'
    case 'email': return 'badge-sentinel badge-sentinel-sol-cyan'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function getScoreBadgeClass(score: number): string {
  if (score >= 90) return 'badge-sentinel badge-sentinel-critical'
  if (score >= 70) return 'badge-sentinel badge-sentinel-high'
  if (score >= 50) return 'badge-sentinel badge-sentinel-medium'
  return 'badge-sentinel badge-sentinel-low'
}

function getMotivationBadgeClass(motivation: string): string {
  switch (motivation) {
    case 'financial': return 'badge-sentinel badge-sentinel-success'
    case 'espionage': return 'badge-sentinel badge-sentinel-critical'
    case 'hacktivism': return 'badge-sentinel badge-sentinel-sol-magenta'
    case 'sabotage': return 'badge-sentinel badge-sentinel-high'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function getCampaignStatusBadgeClass(status: string): string {
  switch (status) {
    case 'active': return 'badge-sentinel badge-sentinel-critical'
    case 'dormant': return 'badge-sentinel badge-sentinel-warning'
    case 'concluded': return 'badge-sentinel badge-sentinel-success'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function getThreatLevelBadgeClass(level: number): string {
  switch (level) {
    case 1: return 'badge-sentinel badge-sentinel-critical'
    case 2: return 'badge-sentinel badge-sentinel-high'
    case 3: return 'badge-sentinel badge-sentinel-medium'
    case 4: return 'badge-sentinel badge-sentinel-low'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function getTLPBadgeClass(tlp: string): string {
  switch (tlp) {
    case 'RED': return 'badge-sentinel badge-sentinel-critical'
    case 'AMBER': return 'badge-sentinel badge-sentinel-high'
    case 'GREEN': return 'badge-sentinel badge-sentinel-success'
    case 'WHITE': return 'badge-sentinel badge-sentinel-default'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

export default function ThreatIntel({
  iocs: initialIOCs = [],
  actors: initialActors = [],
  campaigns: initialCampaigns = [],
  sources: initialSources = []
}: ThreatIntelPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'coverage' | 'iocs' | 'actors' | 'campaigns' | 'misp'>('coverage')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [iocSourceFilter, setIocSourceFilter] = useState<string>('all')
  const [scoreFilter, setScoreFilter] = useState<string>('all')
  const [blockableFilter, setBlockableFilter] = useState<string>('all')
  const [sourceStatusFilter, setSourceStatusFilter] = useState<string>('all')
  const [sourceTypeFilter, setSourceTypeFilter] = useState<string>('all')
  const [visibilityFilter, setVisibilityFilter] = useState<string>('all')
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)

  // State for data from API
  const [iocs, setIOCs] = useState<IOC[]>(initialIOCs)
  const [actors, setActors] = useState<ThreatActor[]>(initialActors)
  const [campaigns, setCampaigns] = useState<Campaign[]>(initialCampaigns)
  const [sources, setSources] = useState<IntelSource[]>(initialSources)
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null)
  const [totalIOCCount, setTotalIOCCount] = useState(0)
  const [tenantBlocklist, setTenantBlocklist] = useState<TenantBlocklistEntry[]>([])
  const [dnsPolicyStats, setDnsPolicyStats] = useState<DNSPolicyStats | null>(null)
  const [detectionCoverage, setDetectionCoverage] = useState<DetectionContentCoverage>({
    sigmaTotal: 0,
    sigmaEnabled: 0,
    yaraTotal: 0,
    yaraLoaded: 0,
    yaraScans: 0,
  })

  // MISP-specific state
  const [mispInstances, setMispInstances] = useState<MISPInstance[]>([])
  const [mispEvents, setMispEvents] = useState<MISPEvent[]>([])
  const [mispSyncStatus, setMispSyncStatus] = useState<Record<string, any>>({})
  const [scoringConfig, setScoringConfig] = useState<IOCScoringConfig | null>(null)

  // Modals
  const [showAddIOCModal, setShowAddIOCModal] = useState(false)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showMISPModal, setShowMISPModal] = useState(false)
  const [showActorModal, setShowActorModal] = useState(false)
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null)

  // Fetch data from API
  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [iocRes, actorsRes, campaignsRes, sourcesRes, statusRes, summaryRes] = await Promise.all([
        axios.get('/api/v1/iocs?limit=100'),
        axios.get('/api/v1/threat-intel/actors/db'),
        axios.get('/api/v1/threat-intel/campaigns'),
        axios.get('/api/v1/threat-intel/sources'),
        axios.get('/api/v1/threat-intel/status'),
        axios.get('/api/v1/threat-intel/summary')
      ])

      // Transform IOC data
      if (iocRes.data?.data) {
        setIOCs(iocRes.data.data.map((ioc: any) => ({
          id: ioc.id,
          type: ioc.type,
          value: ioc.value,
          threatType: ioc.description || 'Unknown',
          confidence: ioc.severity === 'high' ? 90 : ioc.severity === 'medium' ? 70 : 50,
          source: ioc.source || 'Manual',
          firstSeen: ioc.created_at,
          lastSeen: ioc.updated_at,
          tags: ioc.tags || [],
          score: ioc.score
        })))
      }

      // Transform actors data
      if (actorsRes.data?.data) {
        setActors(actorsRes.data.data.map((a: any) => ({
          id: a.id,
          name: a.name,
          description: a.description,
          aliases: a.aliases || [],
          motivation: a.motivation || 'unknown',
          sophistication: a.sophistication,
          resourceLevel: a.resource_level,
          targetSectors: a.target_sectors || [],
          originCountry: a.origin_country || 'Unknown',
          activeSince: a.first_seen || 'Unknown',
          lastActivity: a.last_seen || 'Unknown',
          ttps: a.ttps || [],
          knownMalware: a.known_malware || [],
          knownTools: a.known_tools || [],
          iocCount: a.ioc_count || 0,
          confidence: a.confidence
        })))
      }

      // Transform campaigns data
      if (campaignsRes.data?.data) {
        setCampaigns(campaignsRes.data.data.map((c: any) => ({
          id: c.id,
          name: c.name,
          actor: c.actor,
          status: c.status,
          startDate: c.start_date,
          endDate: c.end_date,
          targetRegions: c.target_regions || [],
          description: c.description
        })))
      }

      // Transform sources data
      if (sourcesRes.data?.data) {
        setSources(sourcesRes.data.data.map((s: any) => ({
          id: s.id,
          name: s.name,
          type: s.type,
          status: s.status,
          lastSync: s.last_sync,
          iocCount: s.ioc_count || 0
        })))
      }

      // Feed status
      if (statusRes.data?.data) {
        setFeedStatus({
          enabled: statusRes.data.data.enabled,
          lastSync: statusRes.data.data.last_sync,
          syncIntervalHours: statusRes.data.data.sync_interval_hours,
          totalIocs: statusRes.data.data.total_iocs || 0,
          iocsBySource: statusRes.data.data.iocs_by_source || {},
          apiKeysConfigured: statusRes.data.data.api_keys_configured
        })
        if (statusRes.data.data.total_iocs) {
          setTotalIOCCount(statusRes.data.data.total_iocs)
        }
      }

      // Summary
      if (summaryRes.data?.data) {
        setTotalIOCCount(summaryRes.data.data.total_iocs || 0)
      }
    } catch (error) {
      logger.error('Error fetching threat intel data:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchCoverageData = useCallback(async () => {
    try {
      const [sigmaRes, yaraRes, dnsBlocklistRes, dnsStatsRes] = await Promise.allSettled([
        axios.get('/api/v1/rules/sigma'),
        axios.get('/api/v1/rules/yara/status'),
        axios.get('/api/v1/dns/blocklist'),
        axios.get('/api/v1/dns/stats'),
      ])

      if (sigmaRes.status === 'fulfilled') {
        const sigmaRules = apiDataArray(sigmaRes.value.data, ['rules', 'items'])
        setDetectionCoverage(prev => ({
          ...prev,
          sigmaTotal: sigmaRules.length,
          sigmaEnabled: sigmaRules.filter((rule: any) => rule.enabled !== false).length,
        }))
      }

      if (yaraRes.status === 'fulfilled') {
        const payload = apiDataObject(yaraRes.value.data)
        setDetectionCoverage(prev => ({
          ...prev,
          yaraTotal: numericStat(payload.total_rules ?? payload.rule_count ?? payload.loaded_rules),
          yaraLoaded: numericStat(payload.loaded_rules ?? payload.rule_count),
          yaraScans: numericStat(payload.scan_count),
        }))
      }

      if (dnsBlocklistRes.status === 'fulfilled') {
        const entries = apiDataArray(dnsBlocklistRes.value.data, ['blocklist', 'entries', 'items'])
        setTenantBlocklist(entries)
      }

      if (dnsStatsRes.status === 'fulfilled') {
        const stats = apiDataObject<DNSPolicyStats>(dnsStatsRes.value.data)
        setDnsPolicyStats({
          total_queries_today: numericStat(stats.total_queries_today),
          unique_domains: numericStat(stats.unique_domains),
          blocked_count: numericStat(stats.blocked_count),
          suspicious_count: numericStat(stats.suspicious_count),
        })
      }
    } catch (error) {
      logger.error('Error fetching coverage and policy data:', error)
    }
  }, [])

  // Fetch MISP data
  const fetchMISPData = useCallback(async () => {
    try {
      const [instancesRes, eventsRes, syncStatusRes, scoringRes] = await Promise.all([
        axios.get('/api/v1/threat-intel/misp/instances'),
        axios.get('/api/v1/threat-intel/misp/events?limit=50'),
        axios.get('/api/v1/threat-intel/misp/sync-status'),
        axios.get('/api/v1/threat-intel/ioc-scoring/config')
      ])

      if (instancesRes.data?.data) {
        setMispInstances(instancesRes.data.data.map((i: any) => ({
          id: i.id,
          name: i.name,
          url: i.url,
          enabled: i.enabled,
          verifySSL: i.verify_ssl,
          pullEnabled: i.pull_enabled,
          pushEnabled: i.push_enabled,
          trustLevel: i.trust_level,
          syncIntervalHours: i.sync_interval_hours,
          lastSync: i.last_sync,
          lastSyncStatus: i.last_sync_status,
          eventsSynced: i.events_synced,
          iocsImported: i.iocs_imported,
          serverVersion: i.server_version,
          canPublish: i.can_publish,
          canSighting: i.can_sighting,
          tagsFilter: i.tags_filter || [],
          threatLevelFilter: i.threat_level_filter || []
        })))
      }

      if (eventsRes.data?.data) {
        setMispEvents(eventsRes.data.data.map((e: any) => ({
          id: e.id,
          mispEventId: e.misp_event_id,
          uuid: e.uuid,
          info: e.info,
          threatLevelId: e.threat_level_id,
          threatLevel: e.threat_level,
          analysis: e.analysis,
          analysisStatus: e.analysis_status,
          date: e.date,
          published: e.published,
          orgName: e.org_name,
          orgcName: e.orgc_name,
          tags: e.tags || [],
          galaxies: e.galaxies || [],
          attributeCount: e.attribute_count,
          tlp: e.tlp,
          threatActorName: e.threat_actor_name,
          campaignName: e.campaign_name,
          malwareFamily: e.malware_family,
          syncedAt: e.synced_at
        })))
      }

      if (syncStatusRes.data?.data) {
        const statusMap: Record<string, any> = {}
        syncStatusRes.data.data.forEach((s: any) => {
          statusMap[s.instance_id] = s
        })
        setMispSyncStatus(statusMap)
      }

      if (scoringRes.data?.data) {
        setScoringConfig({
          halfLifeDays: scoringRes.data.data.half_life_days,
          minScoreThreshold: scoringRes.data.data.min_score_threshold,
          maxSightingBoost: scoringRes.data.data.max_sighting_boost,
          fpWeight: scoringRes.data.data.fp_weight,
          correlationBoost: scoringRes.data.data.correlation_boost,
          sourceReputation: scoringRes.data.data.source_reputation || {},
          typeWeights: scoringRes.data.data.type_weights || {}
        })
      }
    } catch (error) {
      logger.error('Error fetching MISP data:', error)
    }
  }, [])

  // Initial data fetch
  useEffect(() => {
    fetchData()
    fetchMISPData()
    fetchCoverageData()
  }, [fetchData, fetchMISPData, fetchCoverageData])

  const handleSyncAll = async () => {
    setSyncing(true)
    try {
      await axios.post('/api/v1/threat-intel/sync')
      toast.success('Feed sync started')
      setTimeout(() => fetchData(), 3000)
    } catch (error) {
      toast.error('Failed to start feed sync')
    } finally {
      setSyncing(false)
    }
  }

  const handleSyncMISP = async (instanceId: string) => {
    try {
      await axios.post(`/api/v1/threat-intel/misp/instances/${instanceId}/sync`)
      toast.success('MISP sync started')
      setTimeout(() => fetchMISPData(), 3000)
    } catch (error) {
      toast.error('Failed to start MISP sync')
    }
  }

  const handleTestMISPConnection = async (instanceId: string) => {
    try {
      const res = await axios.post(`/api/v1/threat-intel/misp/instances/${instanceId}/test`)
      if (res.data?.data?.connected) {
        toast.success(`Connected! MISP v${res.data.data.version}`)
      } else {
        toast.error('Connection failed')
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Connection failed')
    }
  }

  const handleAddIOC = async (data: { type: string; value: string; description: string; tags: string[] }) => {
    try {
      await axios.post('/api/v1/iocs', {
        type: data.type,
        value: data.value,
        description: data.description,
        tags: data.tags,
        enabled: true,
        source: 'Manual'
      })
      toast.success('IOC added successfully')
      setShowAddIOCModal(false)
      fetchData()
    } catch (error) {
      toast.error('Failed to add IOC')
    }
  }

  const handleBlockIOC = async (ioc: IOC) => {
    const domain = domainFromIOC(ioc)

    if (!domain) {
      toast.error('Only domain and URL IOCs can be promoted to DNS blocklist from this view')
      return
    }

    try {
      await axios.post('/api/v1/dns/blocklist', {
        domains: [domain],
        reason: `Promoted from threat intel IOC ${ioc.id}`,
      }, {
        headers: { 'X-CSRF-Token': getCsrfToken() },
      })

      toast.success(`Domain blocked: ${domain}`)
    } catch (error) {
      logger.error('Failed to promote IOC to DNS blocklist:', error)
      toast.error('Failed to block domain')
    }
  }

  const filteredIOCs = iocs.filter(ioc => {
    if (typeFilter !== 'all' && ioc.type !== typeFilter) return false
    if (iocSourceFilter !== 'all' && ioc.source !== iocSourceFilter) return false
    if (scoreFilter !== 'all' && Number(ioc.score || ioc.confidence || 0) < Number(scoreFilter)) return false
    if (blockableFilter === 'blockable' && !domainFromIOC(ioc)) return false
    if (blockableFilter === 'not_blockable' && domainFromIOC(ioc)) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      const haystack = [
        ioc.value,
        ioc.threatType,
        ioc.source,
        ...(ioc.tags || []),
      ].join(' ').toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })

  const iocSourceOptions = Array.from(new Set(iocs.map(ioc => ioc.source).filter(Boolean))).sort()
  const filteredSources = sources.filter(source => {
    if (sourceStatusFilter !== 'all' && source.status !== sourceStatusFilter) return false
    if (sourceTypeFilter !== 'all' && source.type !== sourceTypeFilter) return false
    return true
  })
  const filteredAlertSources = ALERT_SOURCE_CATALOG.filter(source =>
    visibilityFilter === 'all' || source.visibility === visibilityFilter
  )
  const onlineSources = sources.filter(s => s.status === 'online').length
  const totalIOCs = totalIOCCount || sources.reduce((acc, s) => acc + s.iocCount, 0)
  const activeMISPInstances = mispInstances.filter(i => i.enabled).length
  const iocTypes = iocs.reduce<Record<string, number>>((acc, ioc) => {
    acc[ioc.type] = (acc[ioc.type] || 0) + 1
    return acc
  }, {})
  const promotedBlocklistCount = tenantBlocklist.filter(entry =>
    String(entry.source || entry.reason || '').toLowerCase().includes('ioc') ||
    String(entry.source || entry.reason || '').toLowerCase().includes('threat')
  ).length

  return (
    <MainLayout title="Threat Intelligence">
      <Head title="Threat Intel - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <StatCard
            icon={Database}
            label="Total IOCs"
            value={totalIOCs.toLocaleString()}
            color="primary"
          />
          <StatCard
            icon={Users}
            label="Threat Actors"
            value={actors.length.toString()}
            color="critical"
          />
          <StatCard
            icon={Target}
            label="Active Campaigns"
            value={campaigns.filter(c => c.status === 'active').length.toString()}
            color="high"
          />
          <StatCard
            icon={Server}
            label="MISP Instances"
            value={`${activeMISPInstances}/${mispInstances.length}`}
            color="medium"
          />
          <StatCard
            icon={Globe}
            label="Intel Sources"
            value={`${onlineSources}/${sources.length}`}
            color="success"
          />
        </div>

        {/* Intelligence Sources & MISP Status */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Intel Sources */}
          <div className="card-sentinel">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Intelligence Sources</h2>
                {feedStatus && (
                  <span className={cn(
                    'badge-sentinel',
                    feedStatus.enabled ? 'badge-sentinel-success' : 'badge-sentinel-critical'
                  )}>
                    {feedStatus.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowConfigModal(true)}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  <Settings className="h-4 w-4" />
                </button>
                <button
                  onClick={handleSyncAll}
                  disabled={syncing || loading}
                  className="btn-sentinel btn-sentinel-primary btn-sentinel-sm"
                >
                  <RefreshCw className={cn('h-4 w-4', syncing && 'animate-spin')} />
                  Sync
                </button>
              </div>
            </div>
            {sources.length === 0 && !loading ? (
              <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
                <Globe className="h-10 w-10 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No sources configured</p>
              </div>
            ) : (
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {filteredSources.slice(0, 6).map((source) => (
                  <SourceCard key={source.id} source={source} compact />
                ))}
              </div>
            )}
          </div>

          {/* MISP Instances */}
          <div className="card-sentinel">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>MISP Servers</h2>
                <span className="text-xs" style={{ color: 'var(--muted)' }}>
                  {mispEvents.length} events synced
                </span>
              </div>
              <button
                onClick={() => setShowMISPModal(true)}
                className="btn-sentinel btn-sentinel-outline btn-sentinel-sm"
                style={{ borderColor: 'var(--sol-magenta)', color: 'var(--sol-magenta)' }}
              >
                <Plus className="h-4 w-4" />
                Add MISP
              </button>
            </div>
            {mispInstances.length === 0 ? (
              <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
                <Server className="h-10 w-10 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No MISP instances configured</p>
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Connect to MISP for threat intelligence sharing</p>
              </div>
            ) : (
              <div className="space-y-2">
                {mispInstances.map((instance) => (
                  <MISPInstanceCard
                    key={instance.id}
                    instance={instance}
                    syncStatus={mispSyncStatus[instance.id]}
                    onSync={() => handleSyncMISP(instance.id)}
                    onTest={() => handleTestMISPConnection(instance.id)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Feed Health & Aggregator Stats */}
        {feedStatus && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Feed Health Status */}
            {feedStatus.feedHealth && Object.keys(feedStatus.feedHealth).length > 0 && (
              <div className="card-sentinel">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Activity className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Feed Health
                </h2>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {Object.entries(feedStatus.feedHealth)
                    .sort(([, a], [, b]) => {
                      const order = { healthy: 0, stale: 1, error: 2, unknown: 3 }
                      return order[a.status] - order[b.status]
                    })
                    .map(([feedName, health]) => (
                      <div key={feedName} className="flex items-center justify-between p-2 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                        <div className="flex items-center gap-2">
                          {health.status === 'healthy' ? (
                            <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                          ) : health.status === 'stale' ? (
                            <Clock className="h-4 w-4" style={{ color: 'var(--high)' }} />
                          ) : health.status === 'error' ? (
                            <XCircle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                          ) : (
                            <AlertCircle className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          )}
                          <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>{feedName.replace(/_/g, ' ')}</span>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <span style={{ color: 'var(--muted)' }}>{health.iocsLastBatch} IOCs</span>
                          {health.lastSeen && (
                            <span style={{ color: 'var(--subtle)' }}>
                              {new Date(health.lastSeen).toLocaleString()}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Aggregator Stats */}
            {feedStatus.aggregatorStats && (
              <div className="card-sentinel">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <BarChart3 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Aggregator Statistics
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="text-2xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                      {feedStatus.aggregatorStats.totalIngested.toLocaleString()}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>Total Ingested</div>
                  </div>
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="text-2xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                      {feedStatus.aggregatorStats.totalDeduplicated.toLocaleString()}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>Deduplicated</div>
                  </div>
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="text-2xl font-bold" style={{ color: 'var(--sol-magenta)' }}>
                      {feedStatus.aggregatorStats.multiSourceCount.toLocaleString()}
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>Multi-Source IOCs</div>
                  </div>
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="text-2xl font-bold" style={{ color: 'var(--high)' }}>
                      {(feedStatus.aggregatorStats.cacheHitRate * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs" style={{ color: 'var(--muted)' }}>Cache Hit Rate</div>
                  </div>
                </div>
                <div className="mt-4 flex items-center justify-between text-xs pt-3" style={{ color: 'var(--muted)', borderTop: '1px solid var(--hairline)' }}>
                  <span>Hot Cache: {feedStatus.aggregatorStats.hotCacheSize.toLocaleString()} entries</span>
                  <span>Dedup Rate: {((feedStatus.aggregatorStats.totalDeduplicated / Math.max(feedStatus.aggregatorStats.totalIngested, 1)) * 100).toFixed(1)}%</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* IOC Source Breakdown */}
        {feedStatus && Object.keys(feedStatus.iocsBySource).length > 0 && (
          <div className="card-sentinel">
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>IOC Source Breakdown</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
              {Object.entries(feedStatus.iocsBySource)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 18)
                .map(([source, count]) => {
                  const health = feedStatus.feedHealth?.[source]
                  return (
                    <div key={source} className="rounded-lg p-3 relative" style={{ background: 'var(--surface-2)' }}>
                      {health && (
                        <div className={cn(
                          'absolute top-2 right-2 w-2 h-2 rounded-full'
                        )} style={{
                          background: health.status === 'healthy' ? 'var(--emerald-400)' :
                          health.status === 'stale' ? 'var(--high)' :
                          health.status === 'error' ? 'var(--crit)' : 'var(--muted)'
                        }} title={`Status: ${health.status}`} />
                      )}
                      <div className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }} title={source}>
                        {source.replace(/_/g, ' ')}
                      </div>
                      <div className="text-xl font-bold" style={{ color: 'var(--emerald-400)' }}>{count.toLocaleString()}</div>
                      <div className="text-xs" style={{ color: 'var(--muted)' }}>IOCs</div>
                    </div>
                  )
                })}
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="card-sentinel" style={{ padding: 0 }}>
          <div className="flex overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            <TabButton
              active={activeTab === 'coverage'}
              onClick={() => setActiveTab('coverage')}
              icon={Shield}
              label="Coverage & Policy"
            />
            <TabButton
              active={activeTab === 'iocs'}
              onClick={() => setActiveTab('iocs')}
              icon={Database}
              label="IOC Feed"
            />
            <TabButton
              active={activeTab === 'actors'}
              onClick={() => setActiveTab('actors')}
              icon={Users}
              label="Threat Actors"
            />
            <TabButton
              active={activeTab === 'campaigns'}
              onClick={() => setActiveTab('campaigns')}
              icon={Target}
              label="Campaigns"
            />
            <TabButton
              active={activeTab === 'misp'}
              onClick={() => setActiveTab('misp')}
              icon={Link2}
              label="MISP Events"
            />
          </div>

          {/* Coverage & Policy Tab */}
          {activeTab === 'coverage' && (
            <div className="p-4 space-y-4">
              <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                <div className="flex items-start gap-3">
                  <Info className="h-5 w-5 mt-0.5" style={{ color: 'var(--emerald-400)' }} />
                  <div>
                    <h3 className="text-base font-semibold" style={{ color: 'var(--fg)' }}>Effective detection surface</h3>
                    <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                      This view explains what can generate alerts or blocks without exposing the complete enriched Tamandua feed.
                      Tenant blocklists and audit decisions are visible to the tenant; managed feed internals stay summarized.
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
                <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                  <div className="text-xs uppercase tracking-wide mb-1" style={{ color: 'var(--subtle)' }}>Open content</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>Sigma/YARA metadata, rule counts, source health and public ATT&CK coverage.</div>
                </div>
                <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                  <div className="text-xs uppercase tracking-wide mb-1" style={{ color: 'var(--subtle)' }}>Tenant context</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>Endpoint events, host names, users, raw paths, DNS logs and block decisions remain tenant-scoped.</div>
                </div>
                <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                  <div className="text-xs uppercase tracking-wide mb-1" style={{ color: 'var(--subtle)' }}>Managed intel</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>Commercial/API feeds expose health, counts and confidence; feed internals are summarized.</div>
                </div>
                <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                  <div className="text-xs uppercase tracking-wide mb-1" style={{ color: 'var(--subtle)' }}>Public proof</div>
                  <div className="text-sm" style={{ color: 'var(--fg)' }}>Only redacted hashes, IOC counts, types, severity and ATT&CK mappings should be attested on-chain.</div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                <PolicyMetricCard
                  icon={FileText}
                  label="Sigma rules"
                  value={detectionCoverage.sigmaTotal.toLocaleString()}
                  detail={`${detectionCoverage.sigmaEnabled.toLocaleString()} active`}
                />
                <PolicyMetricCard
                  icon={Shield}
                  label="YARA rules"
                  value={detectionCoverage.yaraTotal.toLocaleString()}
                  detail={`${detectionCoverage.yaraLoaded.toLocaleString()} files loaded / ${detectionCoverage.yaraScans.toLocaleString()} scans`}
                />
                <PolicyMetricCard
                  icon={Database}
                  label="Intel IOCs"
                  value={totalIOCs.toLocaleString()}
                  detail={`${Object.keys(iocTypes).length} indicator types`}
                />
                <PolicyMetricCard
                  icon={ShieldAlert}
                  label="Tenant blocklist"
                  value={tenantBlocklist.length.toLocaleString()}
                  detail={`${promotedBlocklistCount.toLocaleString()} promoted from intel`}
                />
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <div className="xl:col-span-2 rounded-lg border" style={{ borderColor: 'var(--border)' }}>
                  <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                      <div>
                        <h3 className="text-base font-semibold" style={{ color: 'var(--fg)' }}>What can generate alerts</h3>
                        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                          Alert sources are evaluated with confidence, policy and tenant scope before enforcement.
                        </p>
                      </div>
                      <Select
                        value={visibilityFilter}
                        onValueChange={setVisibilityFilter}
                        className="input-sentinel"
                      >
                        <SelectItem value="all">All visibility</SelectItem>
                        <SelectItem value="open">Open</SelectItem>
                        <SelectItem value="tenant">Tenant-scoped</SelectItem>
                        <SelectItem value="managed">Managed</SelectItem>
                      </Select>
                    </div>
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--hairline)' }}>
                    {filteredAlertSources.map(source => (
                      <div key={source.id} className="p-4 flex items-start justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium" style={{ color: 'var(--fg)' }}>{source.label}</span>
                            <VisibilityBadge visibility={source.visibility} />
                          </div>
                          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{source.description}</p>
                        </div>
                        <CheckCircle className="h-5 w-5 flex-shrink-0 mt-0.5" style={{ color: 'var(--emerald-400)' }} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-lg border" style={{ borderColor: 'var(--border)' }}>
                  <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                    <h3 className="text-base font-semibold" style={{ color: 'var(--fg)' }}>DNS/block policy</h3>
                    <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Current tenant enforcement summary.</p>
                  </div>
                  <div className="p-4 space-y-3">
                    <PolicyLine label="DNS queries today" value={(dnsPolicyStats?.total_queries_today || 0).toLocaleString()} />
                    <PolicyLine label="Unique domains" value={(dnsPolicyStats?.unique_domains || 0).toLocaleString()} />
                    <PolicyLine label="Blocks today" value={(dnsPolicyStats?.blocked_count || 0).toLocaleString()} tone="critical" />
                    <PolicyLine label="Suspicious DNS" value={(dnsPolicyStats?.suspicious_count || 0).toLocaleString()} tone="warning" />
                    <div className="pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
                      <p className="text-xs uppercase tracking-wide mb-2" style={{ color: 'var(--subtle)' }}>Recent tenant blocklist</p>
                      {tenantBlocklist.length === 0 ? (
                        <p className="text-sm" style={{ color: 'var(--muted)' }}>No tenant DNS blocks configured.</p>
                      ) : (
                        <div className="space-y-2 max-h-56 overflow-y-auto">
                          {tenantBlocklist.slice(0, 8).map(entry => (
                            <div key={entry.domain} className="rounded p-2" style={{ background: 'var(--surface-2)' }}>
                              <div className="font-mono text-xs truncate" style={{ color: 'var(--fg)' }}>{entry.domain}</div>
                              <div className="text-xs truncate mt-1" style={{ color: 'var(--muted)' }}>
                                {entry.reason || entry.source || 'Tenant policy'}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)' }}>
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-3">
                    <h3 className="text-base font-semibold" style={{ color: 'var(--fg)' }}>Intel source summary</h3>
                    <div className="flex items-center gap-2">
                      <Select
                        value={sourceStatusFilter}
                        onValueChange={setSourceStatusFilter}
                        className="input-sentinel"
                      >
                        <SelectItem value="all">All status</SelectItem>
                        <SelectItem value="online">Online</SelectItem>
                        <SelectItem value="configured">Configured</SelectItem>
                        <SelectItem value="degraded">Degraded</SelectItem>
                        <SelectItem value="offline">Offline</SelectItem>
                      </Select>
                      <Select
                        value={sourceTypeFilter}
                        onValueChange={setSourceTypeFilter}
                        className="input-sentinel"
                      >
                        <SelectItem value="all">All types</SelectItem>
                        <SelectItem value="feed">Feed</SelectItem>
                        <SelectItem value="osint">OSINT</SelectItem>
                        <SelectItem value="commercial">Commercial</SelectItem>
                        <SelectItem value="internal">Internal</SelectItem>
                      </Select>
                    </div>
                  </div>
                  {sources.length === 0 ? (
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>No feed source status available.</p>
                  ) : filteredSources.length === 0 ? (
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>No intelligence sources match the active filters.</p>
                  ) : (
                    <div className="space-y-2">
                      {filteredSources.slice(0, 10).map(source => (
                        <div key={source.id} className="flex items-center justify-between gap-3 text-sm">
                          <div className="flex items-center gap-2 min-w-0">
                            <span
                              className="h-2 w-2 rounded-full flex-shrink-0"
                              style={{
                                background:
                                  source.status === 'online' ? 'var(--emerald-400)' :
                                  source.status === 'degraded' ? 'var(--high)' :
                                  source.status === 'configured' ? 'var(--med)' : 'var(--muted)'
                              }}
                            />
                            <span className="truncate" style={{ color: 'var(--fg-2)' }}>{source.name}</span>
                          </div>
                          <span style={{ color: 'var(--muted)' }}>{source.iocCount.toLocaleString()} IOCs</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)' }}>
                  <h3 className="text-base font-semibold mb-3" style={{ color: 'var(--fg)' }}>Promotion rules</h3>
                  <div className="space-y-3 text-sm" style={{ color: 'var(--muted)' }}>
                    <p><span style={{ color: 'var(--fg)' }}>Alert:</span> IOC matches can alert when enabled by rule, feed confidence, or behavioral correlation.</p>
                    <p><span style={{ color: 'var(--fg)' }}>Block:</span> DNS/IP enforcement requires tenant policy, analyst action, or high-confidence promotion with audit trail.</p>
                    <p><span style={{ color: 'var(--fg)' }}>Allow:</span> tenant allowlists and rollback controls should override noisy feed matches.</p>
                    <p><span style={{ color: 'var(--fg)' }}>Public proof:</span> only redacted counts, types and hashes should be attested, never raw tenant context.</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div>
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex flex-wrap items-center gap-3">
                  <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search IOCs..."
                      className="input-sentinel pl-10"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                    <Select
                      value={typeFilter}
                      onValueChange={setTypeFilter}
                      className="input-sentinel"
                    >
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="ip">IP Address</SelectItem>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="hash">Hash</SelectItem>
                      <SelectItem value="url">URL</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                    </Select>
                    <Select
                      value={iocSourceFilter}
                      onValueChange={setIocSourceFilter}
                      className="input-sentinel"
                    >
                      <SelectItem value="all">All Sources</SelectItem>
                      {iocSourceOptions.map(source => (
                        <SelectItem key={source} value={source}>{source}</SelectItem>
                      ))}
                    </Select>
                    <Select
                      value={scoreFilter}
                      onValueChange={setScoreFilter}
                      className="input-sentinel"
                    >
                      <SelectItem value="all">All Scores</SelectItem>
                      <SelectItem value="50">Score &gt;= 50</SelectItem>
                      <SelectItem value="70">Score &gt;= 70</SelectItem>
                      <SelectItem value="90">Score &gt;= 90</SelectItem>
                    </Select>
                    <Select
                      value={blockableFilter}
                      onValueChange={setBlockableFilter}
                      className="input-sentinel"
                    >
                      <SelectItem value="all">All Enforcement</SelectItem>
                      <SelectItem value="blockable">DNS-blockable</SelectItem>
                      <SelectItem value="not_blockable">Not DNS-blockable</SelectItem>
                    </Select>
                  </div>
                  <button
                    onClick={() => setShowAddIOCModal(true)}
                    className="btn-sentinel btn-sentinel-primary btn-sentinel-sm"
                  >
                    <Plus className="h-4 w-4" />
                    Add IOC
                  </button>
                  <ExportDropdown
                    getData={() => filteredIOCs.map(ioc => ({
                      id: ioc.id,
                      type: ioc.type,
                      value: ioc.value,
                      threat_type: ioc.threatType,
                      confidence: ioc.confidence,
                      score: ioc.score,
                      source: ioc.source,
                      first_seen: ioc.firstSeen,
                      last_seen: ioc.lastSeen,
                      tags: ioc.tags.join('; '),
                    }))}
                    filenameBase="tamandua-iocs"
                    disabled={filteredIOCs.length === 0}
                  />
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Value</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Threat Type</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Score</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Source</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Tags</th>
                      <th className="text-right p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIOCs.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                          <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No IOCs found</p>
                        </td>
                      </tr>
                    ) : (
                      filteredIOCs.map((ioc) => (
                        <IOCRow key={ioc.id} ioc={ioc} onBlockIOC={handleBlockIOC} />
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Actors Tab */}
          {activeTab === 'actors' && (
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="text-sm" style={{ color: 'var(--muted)' }}>
                  {actors.length} threat actors tracked
                </div>
                <button
                  onClick={() => {
                    setSelectedActor(null)
                    setShowActorModal(true)
                  }}
                  className="btn-sentinel btn-sentinel-danger btn-sentinel-sm"
                >
                  <Plus className="h-4 w-4" />
                  Add Actor
                </button>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {actors.map((actor) => (
                  <ThreatActorCard
                    key={actor.id}
                    actor={actor}
                    onClick={() => {
                      setSelectedActor(actor)
                      setShowActorModal(true)
                    }}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <div className="p-4">
              <CampaignTimeline campaigns={campaigns} />
            </div>
          )}

          {/* MISP Events Tab */}
          {activeTab === 'misp' && (
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="text-sm" style={{ color: 'var(--muted)' }}>
                  {mispEvents.length} events from MISP
                </div>
                <button
                  onClick={() => fetchMISPData()}
                  className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh
                </button>
              </div>
              <div className="space-y-3">
                {mispEvents.length === 0 ? (
                  <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
                    <Link2 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No MISP events synced</p>
                    <p className="text-sm mt-1" style={{ color: 'var(--subtle)' }}>Configure and sync a MISP instance to see events</p>
                  </div>
                ) : (
                  mispEvents.map((event) => (
                    <MISPEventCard key={event.id} event={event} />
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modals */}
      <AddIOCModal
        isOpen={showAddIOCModal}
        onClose={() => setShowAddIOCModal(false)}
        onSubmit={handleAddIOC}
      />

      <ConfigureModal
        isOpen={showConfigModal}
        onClose={() => setShowConfigModal(false)}
        feedStatus={feedStatus}
        scoringConfig={scoringConfig}
        onConfigureKey={async (provider, key) => {
          await axios.post('/api/v1/threat-intel/configure', {
            provider,
            api_key: key
          })
          fetchData()
        }}
      />

      <MISPConfigModal
        isOpen={showMISPModal}
        onClose={() => setShowMISPModal(false)}
        onSave={async (data) => {
          try {
            await axios.post('/api/v1/threat-intel/misp/instances', data)
            toast.success('MISP instance added')
            fetchMISPData()
            setShowMISPModal(false)
          } catch (error: any) {
            toast.error(error.response?.data?.error || 'Failed to add MISP instance')
          }
        }}
      />

      <ThreatActorModal
        isOpen={showActorModal}
        onClose={() => setShowActorModal(false)}
        actor={selectedActor}
        onSave={async (data) => {
          try {
            if (selectedActor) {
              await axios.put(`/api/v1/threat-intel/actors/db/${selectedActor.id}`, data)
              toast.success('Threat actor updated')
            } else {
              await axios.post('/api/v1/threat-intel/actors/db', data)
              toast.success('Threat actor created')
            }
            fetchData()
            setShowActorModal(false)
          } catch (error: any) {
            toast.error(error.response?.data?.error || 'Failed to save threat actor')
          }
        }}
      />
    </MainLayout>
  )
}

// ============================================================================
// Component Definitions
// ============================================================================

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType
  label: string
  value: string
  color: 'primary' | 'success' | 'critical' | 'high' | 'medium'
}) {
  const colors = {
    primary: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    success: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)' }
  }

  return (
    <div className="card-sentinel">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ background: colors[color].bg }}>
          <Icon className="h-5 w-5" style={{ color: colors[color].text }} />
        </div>
        <div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
        </div>
      </div>
    </div>
  )
}

function SourceCard({ source, compact }: { source: IntelSource; compact?: boolean }) {
  const statusStyles = {
    online: { bg: 'var(--emerald-glow)', color: 'var(--emerald-400)' },
    offline: { bg: 'var(--crit-bg)', color: 'var(--crit)' },
    degraded: { bg: 'var(--high-bg)', color: 'var(--high)' },
    configured: { bg: 'var(--med-bg)', color: 'var(--med)' }
  }

  const StatusIcon = source.status === 'online' ? CheckCircle :
                     source.status === 'configured' ? CheckCircle :
                     source.status === 'offline' ? XCircle : Clock

  const style = statusStyles[source.status as keyof typeof statusStyles] || statusStyles.offline

  return (
    <div className="rounded-lg p-2" style={{ background: style.bg }}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }} title={source.name}>
          {source.name.length > 15 ? source.name.substring(0, 15) + '...' : source.name}
        </span>
        <StatusIcon className="h-3 w-3 flex-shrink-0" style={{ color: style.color }} />
      </div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>
        {source.iocCount.toLocaleString()} IOCs
      </div>
    </div>
  )
}

function MISPInstanceCard({ instance, syncStatus, onSync, onTest }: {
  instance: MISPInstance
  syncStatus?: any
  onSync: () => void
  onTest: () => void
}) {
  return (
    <div className="rounded-lg p-3" style={{
      background: instance.enabled ? 'rgba(217, 70, 239, 0.1)' : 'var(--surface-2)',
      border: instance.enabled ? '1px solid rgba(217, 70, 239, 0.3)' : '1px solid var(--border)'
    }}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4" style={{ color: instance.enabled ? 'var(--sol-magenta)' : 'var(--muted)' }} />
          <span className="font-medium" style={{ color: 'var(--fg)' }}>{instance.name}</span>
          {instance.pushEnabled && (
            <span className="badge-sentinel badge-sentinel-success" style={{ fontSize: '10px', padding: '2px 6px' }}>PUSH</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={onTest}
            className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
            title="Test connection"
          >
            <TestTube className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onSync}
            className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
            title="Sync now"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      <div className="text-xs mb-1 truncate" style={{ color: 'var(--muted)' }}>{instance.url}</div>
      <div className="flex items-center justify-between text-xs" style={{ color: 'var(--subtle)' }}>
        <span>
          {instance.eventsSynced} events / {instance.iocsImported} IOCs
        </span>
        {instance.lastSync && (
          <span>
            {formatRelativeTime(instance.lastSync)}
          </span>
        )}
      </div>
      {instance.trustLevel && (
        <div className="mt-2 flex items-center gap-2">
          <span className="text-xs" style={{ color: 'var(--muted)' }}>Trust:</span>
          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
            <div
              className="h-full rounded-full"
              style={{ width: `${instance.trustLevel}%`, background: 'var(--sol-magenta)' }}
            />
          </div>
          <span className="text-xs" style={{ color: 'var(--fg-2)' }}>{instance.trustLevel}%</span>
        </div>
      )}
    </div>
  )
}

function TabButton({ active, onClick, icon: Icon, label }: {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap"
      style={{
        color: active ? 'var(--emerald-400)' : 'var(--muted)',
        borderBottom: active ? '2px solid var(--emerald-400)' : '2px solid transparent',
        background: active ? 'var(--surface-2)' : 'transparent'
      }}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  )
}

function PolicyMetricCard({ icon: Icon, label, value, detail }: {
  icon: React.ElementType
  label: string
  value: string
  detail: string
}) {
  return (
    <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', background: 'var(--surface)' }}>
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
          <Icon className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
        </div>
        <div className="min-w-0">
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
          <p className="text-xs truncate" style={{ color: 'var(--subtle)' }}>{detail}</p>
        </div>
      </div>
    </div>
  )
}

function VisibilityBadge({ visibility }: { visibility: 'open' | 'tenant' | 'managed' }) {
  const config = {
    open: { label: 'Open content', className: 'badge-sentinel-success' },
    tenant: { label: 'Tenant scoped', className: 'badge-sentinel-info' },
    managed: { label: 'Managed summary', className: 'badge-sentinel-high' },
  }[visibility]

  return (
    <span className={cn('badge-sentinel', config.className)} style={{ fontSize: '10px', padding: '2px 6px' }}>
      {config.label}
    </span>
  )
}

function PolicyLine({ label, value, tone = 'default' }: {
  label: string
  value: string
  tone?: 'default' | 'critical' | 'warning'
}) {
  const color =
    tone === 'critical' ? 'var(--crit)' :
    tone === 'warning' ? 'var(--high)' :
    'var(--fg)'

  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-sm" style={{ color: 'var(--muted)' }}>{label}</span>
      <span className="text-sm font-semibold" style={{ color }}>{value}</span>
    </div>
  )
}

function IOCRow({ ioc, onBlockIOC }: { ioc: IOC; onBlockIOC: (ioc: IOC) => void }) {
  const score = ioc.score ?? ioc.confidence
  const blockable = ioc.type === 'domain' || ioc.type === 'url'

  return (
    <tr className="hover:bg-[var(--surface-2)] transition-colors" style={{ borderBottom: '1px solid var(--hairline)' }}>
      <td className="p-4">
        <span className={getIOCTypeBadgeClass(ioc.type)} style={{ textTransform: 'uppercase' }}>
          {ioc.type}
        </span>
      </td>
      <td className="p-4">
        <span className="font-mono text-sm" style={{ color: 'var(--fg-2)' }}>{ioc.value}</span>
      </td>
      <td className="p-4">
        <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{ioc.threatType}</span>
      </td>
      <td className="p-4">
        <div className="flex items-center gap-2">
          <div className="w-16 h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
            <div
              className="h-full rounded-full"
              style={{
                width: `${score}%`,
                background: score >= 90 ? 'var(--crit)' :
                  score >= 70 ? 'var(--high)' :
                  score >= 50 ? 'var(--med)' : 'var(--emerald-400)'
              }}
            />
          </div>
          <span className="text-xs" style={{ color: 'var(--muted)' }}>{score}</span>
        </div>
      </td>
      <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>{ioc.source}</td>
      <td className="p-4">
        <div className="flex flex-wrap gap-1">
          {ioc.tags.slice(0, 3).map((tag, idx) => (
            <span key={idx} className="badge-sentinel badge-sentinel-default">
              {tag}
            </span>
          ))}
        </div>
      </td>
      <td className="p-4 text-right">
        <button
          onClick={() => onBlockIOC(ioc)}
          disabled={!blockable}
          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs border transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            color: 'var(--crit)',
            borderColor: 'color-mix(in srgb, var(--crit) 35%, transparent)',
            backgroundColor: 'color-mix(in srgb, var(--crit) 8%, transparent)',
          }}
          title={blockable ? 'Promote to DNS blocklist' : 'Only domain and URL IOCs can be DNS-blocked here'}
        >
          <ShieldAlert className="h-3 w-3" />
          Block
        </button>
      </td>
    </tr>
  )
}

function ThreatActorCard({ actor, onClick }: { actor: ThreatActor; onClick: () => void }) {
  return (
    <div
      className="card-sentinel card-sentinel-interactive"
      onClick={onClick}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            {actor.name}
            {actor.confidence && actor.confidence >= 0.8 && (
              <Shield className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} title="High confidence" />
            )}
          </h3>
          {actor.aliases && actor.aliases.length > 0 && (
            <p className="text-sm" style={{ color: 'var(--muted)' }}>
              AKA: {actor.aliases.slice(0, 3).join(', ')}
              {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
            </p>
          )}
        </div>
        <span className={getMotivationBadgeClass(actor.motivation)} style={{ textTransform: 'capitalize' }}>
          {actor.motivation}
        </span>
      </div>

      {actor.description && (
        <p className="text-sm mb-3 line-clamp-2" style={{ color: 'var(--muted)' }}>{actor.description}</p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm mb-3">
        <div>
          <p className="text-xs mb-0.5" style={{ color: 'var(--subtle)' }}>Origin</p>
          <p className="flex items-center gap-1" style={{ color: 'var(--fg-2)' }}>
            <MapPin className="h-3 w-3" />
            {actor.originCountry}
          </p>
        </div>
        <div>
          <p className="text-xs mb-0.5" style={{ color: 'var(--subtle)' }}>First Seen</p>
          <p style={{ color: 'var(--fg-2)' }}>{formatDate(actor.activeSince)}</p>
        </div>
        <div>
          <p className="text-xs mb-0.5" style={{ color: 'var(--subtle)' }}>Last Activity</p>
          <p style={{ color: 'var(--fg-2)' }}>{formatDate(actor.lastActivity)}</p>
        </div>
        <div>
          <p className="text-xs mb-0.5" style={{ color: 'var(--subtle)' }}>Linked IOCs</p>
          <p style={{ color: 'var(--fg-2)' }}>{actor.iocCount || 0}</p>
        </div>
      </div>

      <div className="pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
        <p className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>MITRE ATT&CK TTPs:</p>
        <div className="flex flex-wrap gap-1">
          {actor.ttps.slice(0, 6).map((ttp, idx) => (
            <span key={idx} className="badge-sentinel badge-sentinel-critical font-mono">
              {ttp}
            </span>
          ))}
          {actor.ttps.length > 6 && (
            <span className="badge-sentinel badge-sentinel-default">
              +{actor.ttps.length - 6}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function CampaignTimeline({ campaigns }: { campaigns: Campaign[] }) {
  const sortedCampaigns = [...campaigns].sort((a, b) => {
    return new Date(b.startDate).getTime() - new Date(a.startDate).getTime()
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Campaign Timeline</h3>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ background: 'var(--crit)' }} />
            <span style={{ color: 'var(--muted)' }}>Active</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ background: 'var(--high)' }} />
            <span style={{ color: 'var(--muted)' }}>Dormant</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ background: 'var(--emerald-400)' }} />
            <span style={{ color: 'var(--muted)' }}>Concluded</span>
          </div>
        </div>
      </div>

      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-0.5" style={{ background: 'var(--border)' }} />

        {sortedCampaigns.map((campaign, idx) => (
          <div key={campaign.id} className="relative pl-10 pb-6">
            {/* Timeline dot */}
            <div className="absolute left-2.5 top-1.5 w-3 h-3 rounded-full" style={{
              background: campaign.status === 'active' ? 'var(--crit)' :
                campaign.status === 'dormant' ? 'var(--high)' : 'var(--emerald-400)',
              border: '2px solid var(--surface)'
            }} />

            <div className="card-sentinel">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg" style={{ background: 'var(--crit-bg)' }}>
                    <Target className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                  </div>
                  <div>
                    <h4 className="font-semibold" style={{ color: 'var(--fg)' }}>{campaign.name}</h4>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>By {campaign.actor}</p>
                  </div>
                </div>
                <span className={getCampaignStatusBadgeClass(campaign.status)} style={{ textTransform: 'capitalize' }}>
                  {campaign.status}
                </span>
              </div>

              <p className="text-sm mb-3" style={{ color: 'var(--fg-2)' }}>{campaign.description}</p>

              <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
                <div className="flex items-center gap-1">
                  <Calendar className="h-3.5 w-3.5" />
                  <span>{campaign.startDate} - {campaign.endDate || 'Present'}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Globe className="h-3.5 w-3.5" />
                  <span>{campaign.targetRegions.join(', ')}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function MISPEventCard({ event }: { event: MISPEvent }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="card-sentinel" style={{ padding: 0, overflow: 'hidden' }}>
      <div
        className="p-4 cursor-pointer hover:bg-[var(--surface-2)] transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1 mr-4">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-medium line-clamp-1" style={{ color: 'var(--fg)' }}>{event.info}</h4>
              {event.published && (
                <CheckCircle className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--emerald-400)' }} title="Published" />
              )}
            </div>
            <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--muted)' }}>
              <span>#{event.mispEventId}</span>
              <span>{event.orgcName || event.orgName}</span>
              <span>{event.date}</span>
              <span>{event.attributeCount} attributes</span>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={getThreatLevelBadgeClass(event.threatLevelId)}>
              {event.threatLevel}
            </span>
            <span className={getTLPBadgeClass(event.tlp)}>
              TLP:{event.tlp}
            </span>
            {expanded ? <ChevronDown className="h-4 w-4" style={{ color: 'var(--muted)' }} /> : <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />}
          </div>
        </div>

        {event.tags && event.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {event.tags.slice(0, 5).map((tag, idx) => (
              <span key={idx} className="badge-sentinel badge-sentinel-default">
                {tag}
              </span>
            ))}
            {event.tags.length > 5 && (
              <span className="badge-sentinel badge-sentinel-default">
                +{event.tags.length - 5}
              </span>
            )}
          </div>
        )}
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-3">
            <div>
              <p className="text-xs" style={{ color: 'var(--subtle)' }}>Analysis</p>
              <p style={{ color: 'var(--fg-2)' }}>{event.analysisStatus}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--subtle)' }}>UUID</p>
              <p className="font-mono text-xs truncate" style={{ color: 'var(--fg-2)' }} title={event.uuid}>{event.uuid}</p>
            </div>
            {event.threatActorName && (
              <div>
                <p className="text-xs" style={{ color: 'var(--subtle)' }}>Threat Actor</p>
                <p style={{ color: 'var(--fg-2)' }}>{event.threatActorName}</p>
              </div>
            )}
            {event.malwareFamily && (
              <div>
                <p className="text-xs" style={{ color: 'var(--subtle)' }}>Malware Family</p>
                <p style={{ color: 'var(--fg-2)' }}>{event.malwareFamily}</p>
              </div>
            )}
          </div>

          {event.galaxies && event.galaxies.length > 0 && (
            <div>
              <p className="text-xs mb-1" style={{ color: 'var(--subtle)' }}>Galaxies</p>
              <div className="flex flex-wrap gap-1">
                {event.galaxies.map((galaxy: any, idx: number) => (
                  <span key={idx} className="badge-sentinel badge-sentinel-sol-magenta">
                    {galaxy.name || galaxy.type}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Modal Components
// ============================================================================

function AddIOCModal({
  isOpen,
  onClose,
  onSubmit
}: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: { type: string; value: string; description: string; tags: string[] }) => void
}) {
  const [formData, setFormData] = useState({
    type: 'ip',
    value: '',
    description: '',
    tags: ''
  })

  if (!isOpen) return null

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      type: formData.type,
      value: formData.value,
      description: formData.description,
      tags: formData.tags.split(',').map(t => t.trim()).filter(Boolean)
    })
    setFormData({ type: 'ip', value: '', description: '', tags: '' })
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="card-sentinel w-full max-w-md">
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Add IOC</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Type</label>
            <Select
              value={formData.type}
              onValueChange={(value) => setFormData({ ...formData, type: value })}
              className="input-sentinel"
            >
              <SelectItem value="ip">IP Address</SelectItem>
              <SelectItem value="domain">Domain</SelectItem>
              <SelectItem value="hash">Hash (SHA256)</SelectItem>
              <SelectItem value="url">URL</SelectItem>
              <SelectItem value="email">Email</SelectItem>
            </Select>
          </div>
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Value</label>
            <input
              type="text"
              value={formData.value}
              onChange={(e) => setFormData({ ...formData, value: e.target.value })}
              placeholder="Enter IOC value..."
              className="input-sentinel"
              required
            />
          </div>
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Description</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Malware family, threat type..."
              className="input-sentinel"
            />
          </div>
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Tags (comma-separated)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              placeholder="malware, c2, phishing"
              className="input-sentinel"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-sentinel btn-sentinel-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-sentinel btn-sentinel-primary"
            >
              Add IOC
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ConfigureModal({
  isOpen,
  onClose,
  feedStatus,
  scoringConfig,
  onConfigureKey
}: {
  isOpen: boolean
  onClose: () => void
  feedStatus: FeedStatus | null
  scoringConfig: IOCScoringConfig | null
  onConfigureKey: (provider: string, key: string) => Promise<void>
}) {
  const [selectedProvider, setSelectedProvider] = useState<string>('')
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [activeConfigTab, setActiveConfigTab] = useState<'keys' | 'scoring'>('keys')

  if (!isOpen) return null

  const handleSave = async () => {
    if (!selectedProvider || !apiKey) return
    setSaving(true)
    try {
      await onConfigureKey(selectedProvider, apiKey)
      setSelectedProvider('')
      setApiKey('')
      toast.success('API key configured')
    } catch (error) {
      toast.error('Failed to configure API key')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="card-sentinel w-full max-w-lg">
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Threat Intel Configuration</h2>

        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setActiveConfigTab('keys')}
            className={cn(
              'btn-sentinel btn-sentinel-sm',
              activeConfigTab === 'keys' ? 'btn-sentinel-primary' : 'btn-sentinel-secondary'
            )}
          >
            API Keys
          </button>
          <button
            onClick={() => setActiveConfigTab('scoring')}
            className={cn(
              'btn-sentinel btn-sentinel-sm',
              activeConfigTab === 'scoring' ? 'btn-sentinel-primary' : 'btn-sentinel-secondary'
            )}
          >
            IOC Scoring
          </button>
        </div>

        {activeConfigTab === 'keys' && (
          <div className="space-y-4">
            <div className="rounded-lg p-4" style={{ background: 'var(--surface-2)' }}>
              <h3 className="text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>Current Configuration</h3>
              <div className="grid grid-cols-2 gap-2 text-sm">
                {feedStatus && Object.entries(feedStatus.apiKeysConfigured).map(([provider, configured]) => (
                  <div key={provider} className="flex items-center gap-2">
                    {configured ? (
                      <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                    ) : (
                      <XCircle className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                    )}
                    <span style={{ color: configured ? 'var(--emerald-400)' : 'var(--muted)' }}>
                      {provider.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Provider</label>
                <Select
                  value={selectedProvider}
                  onValueChange={setSelectedProvider}
                  placeholder="Select provider..."
                  className="input-sentinel"
                >
                  <SelectItem value="">Select provider...</SelectItem>
                  <SelectItem value="misp">MISP</SelectItem>
                  <SelectItem value="otx">AlienVault OTX</SelectItem>
                  <SelectItem value="virustotal">VirusTotal</SelectItem>
                  <SelectItem value="shodan">Shodan</SelectItem>
                </Select>
              </div>
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter API key..."
                  className="input-sentinel"
                />
              </div>
            </div>
          </div>
        )}

        {activeConfigTab === 'scoring' && scoringConfig && (
          <div className="space-y-4">
            <div className="rounded-lg p-4" style={{ background: 'var(--surface-2)' }}>
              <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--fg)' }}>Scoring Parameters</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span style={{ color: 'var(--subtle)' }}>Half-life (days)</span>
                  <p className="font-medium" style={{ color: 'var(--fg)' }}>{scoringConfig.halfLifeDays}</p>
                </div>
                <div>
                  <span style={{ color: 'var(--subtle)' }}>Min Score Threshold</span>
                  <p className="font-medium" style={{ color: 'var(--fg)' }}>{scoringConfig.minScoreThreshold}</p>
                </div>
                <div>
                  <span style={{ color: 'var(--subtle)' }}>Max Sighting Boost</span>
                  <p className="font-medium" style={{ color: 'var(--fg)' }}>{scoringConfig.maxSightingBoost}</p>
                </div>
                <div>
                  <span style={{ color: 'var(--subtle)' }}>FP Weight</span>
                  <p className="font-medium" style={{ color: 'var(--fg)' }}>{scoringConfig.fpWeight}</p>
                </div>
              </div>
            </div>

            <div className="rounded-lg p-4" style={{ background: 'var(--surface-2)' }}>
              <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--fg)' }}>Source Reputation</h3>
              <div className="max-h-40 overflow-y-auto space-y-1">
                {Object.entries(scoringConfig.sourceReputation)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 10)
                  .map(([source, score]) => (
                    <div key={source} className="flex items-center justify-between text-sm">
                      <span style={{ color: 'var(--muted)' }}>{source}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                          <div
                            className="h-full rounded-full"
                            style={{ width: `${score}%`, background: 'var(--emerald-500)' }}
                          />
                        </div>
                        <span className="w-8 text-right" style={{ color: 'var(--fg)' }}>{score}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-6">
          <button
            type="button"
            onClick={onClose}
            className="btn-sentinel btn-sentinel-secondary"
          >
            Close
          </button>
          {activeConfigTab === 'keys' && (
            <button
              onClick={handleSave}
              disabled={!selectedProvider || !apiKey || saving}
              className="btn-sentinel btn-sentinel-primary"
            >
              {saving ? 'Saving...' : 'Save Key'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function MISPConfigModal({
  isOpen,
  onClose,
  onSave
}: {
  isOpen: boolean
  onClose: () => void
  onSave: (data: any) => Promise<void>
}) {
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    api_key: '',
    verify_ssl: true,
    pull_enabled: true,
    push_enabled: false,
    trust_level: 50,
    sync_interval_hours: 4
  })
  const [saving, setSaving] = useState(false)

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await onSave(formData)
      setFormData({
        name: '',
        url: '',
        api_key: '',
        verify_ssl: true,
        pull_enabled: true,
        push_enabled: false,
        trust_level: 50,
        sync_interval_hours: 4
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="card-sentinel w-full max-w-lg">
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Add MISP Instance</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Instance Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="My MISP Server"
                className="input-sentinel"
                required
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>URL</label>
              <input
                type="url"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                placeholder="https://misp.example.com"
                className="input-sentinel"
                required
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>API Key</label>
              <input
                type="password"
                value={formData.api_key}
                onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
                placeholder="Your MISP API key"
                className="input-sentinel"
                required
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Trust Level</label>
              <input
                type="number"
                min={0}
                max={100}
                value={formData.trust_level}
                onChange={(e) => setFormData({ ...formData, trust_level: parseInt(e.target.value) })}
                className="input-sentinel"
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Sync Interval (hours)</label>
              <input
                type="number"
                min={1}
                max={168}
                value={formData.sync_interval_hours}
                onChange={(e) => setFormData({ ...formData, sync_interval_hours: parseInt(e.target.value) })}
                className="input-sentinel"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg-2)' }}>
              <input
                type="checkbox"
                checked={formData.verify_ssl}
                onChange={(e) => setFormData({ ...formData, verify_ssl: e.target.checked })}
                className="rounded"
                style={{ background: 'var(--surface-2)', borderColor: 'var(--border)' }}
              />
              Verify SSL
            </label>
            <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg-2)' }}>
              <input
                type="checkbox"
                checked={formData.pull_enabled}
                onChange={(e) => setFormData({ ...formData, pull_enabled: e.target.checked })}
                className="rounded"
                style={{ background: 'var(--surface-2)', borderColor: 'var(--border)' }}
              />
              Pull Events
            </label>
            <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg-2)' }}>
              <input
                type="checkbox"
                checked={formData.push_enabled}
                onChange={(e) => setFormData({ ...formData, push_enabled: e.target.checked })}
                className="rounded"
                style={{ background: 'var(--surface-2)', borderColor: 'var(--border)' }}
              />
              Push Events
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-sentinel btn-sentinel-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="btn-sentinel btn-sentinel-outline"
              style={{ borderColor: 'var(--sol-magenta)', color: 'var(--sol-magenta)' }}
            >
              {saving ? 'Adding...' : 'Add Instance'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ThreatActorModal({
  isOpen,
  onClose,
  actor,
  onSave
}: {
  isOpen: boolean
  onClose: () => void
  actor: ThreatActor | null
  onSave: (data: any) => Promise<void>
}) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    aliases: '',
    motivation: 'unknown',
    sophistication: '',
    resource_level: '',
    origin_country: '',
    target_sectors: '',
    ttps: '',
    known_malware: '',
    known_tools: ''
  })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (actor) {
      setFormData({
        name: actor.name,
        description: actor.description || '',
        aliases: actor.aliases.join(', '),
        motivation: actor.motivation || 'unknown',
        sophistication: actor.sophistication || '',
        resource_level: actor.resourceLevel || '',
        origin_country: actor.originCountry || '',
        target_sectors: actor.targetSectors.join(', '),
        ttps: actor.ttps.join(', '),
        known_malware: actor.knownMalware?.join(', ') || '',
        known_tools: actor.knownTools?.join(', ') || ''
      })
    } else {
      setFormData({
        name: '',
        description: '',
        aliases: '',
        motivation: 'unknown',
        sophistication: '',
        resource_level: '',
        origin_country: '',
        target_sectors: '',
        ttps: '',
        known_malware: '',
        known_tools: ''
      })
    }
  }, [actor])

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await onSave({
        name: formData.name,
        description: formData.description,
        aliases: formData.aliases.split(',').map(s => s.trim()).filter(Boolean),
        motivation: formData.motivation,
        sophistication: formData.sophistication || null,
        resource_level: formData.resource_level || null,
        origin_country: formData.origin_country,
        target_sectors: formData.target_sectors.split(',').map(s => s.trim()).filter(Boolean),
        ttps: formData.ttps.split(',').map(s => s.trim()).filter(Boolean),
        known_malware: formData.known_malware.split(',').map(s => s.trim()).filter(Boolean),
        known_tools: formData.known_tools.split(',').map(s => s.trim()).filter(Boolean)
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="card-sentinel w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>
          {actor ? 'Edit Threat Actor' : 'Add Threat Actor'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="APT29"
                className="input-sentinel"
                required
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Origin Country</label>
              <input
                type="text"
                value={formData.origin_country}
                onChange={(e) => setFormData({ ...formData, origin_country: e.target.value })}
                placeholder="Russia"
                className="input-sentinel"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Aliases (comma-separated)</label>
              <input
                type="text"
                value={formData.aliases}
                onChange={(e) => setFormData({ ...formData, aliases: e.target.value })}
                placeholder="Cozy Bear, The Dukes, YTTRIUM"
                className="input-sentinel"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder="Describe the threat actor..."
                rows={3}
                className="input-sentinel"
                style={{ height: 'auto' }}
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Motivation</label>
              <Select
                value={formData.motivation}
                onValueChange={(value) => setFormData({ ...formData, motivation: value })}
                className="input-sentinel"
              >
                <SelectItem value="unknown">Unknown</SelectItem>
                <SelectItem value="financial">Financial</SelectItem>
                <SelectItem value="espionage">Espionage</SelectItem>
                <SelectItem value="hacktivism">Hacktivism</SelectItem>
                <SelectItem value="sabotage">Sabotage</SelectItem>
              </Select>
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Sophistication</label>
              <Select
                value={formData.sophistication}
                onValueChange={(value) => setFormData({ ...formData, sophistication: value })}
                placeholder="Not specified"
                className="input-sentinel"
              >
                <SelectItem value="">Not specified</SelectItem>
                <SelectItem value="novice">Novice</SelectItem>
                <SelectItem value="intermediate">Intermediate</SelectItem>
                <SelectItem value="advanced">Advanced</SelectItem>
                <SelectItem value="expert">Expert</SelectItem>
              </Select>
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Target Sectors (comma-separated)</label>
              <input
                type="text"
                value={formData.target_sectors}
                onChange={(e) => setFormData({ ...formData, target_sectors: e.target.value })}
                placeholder="Government, Defense, Finance"
                className="input-sentinel"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>MITRE ATT&CK TTPs (comma-separated)</label>
              <input
                type="text"
                value={formData.ttps}
                onChange={(e) => setFormData({ ...formData, ttps: e.target.value })}
                placeholder="T1566.001, T1204.002, T1059.001"
                className="input-sentinel"
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Known Malware (comma-separated)</label>
              <input
                type="text"
                value={formData.known_malware}
                onChange={(e) => setFormData({ ...formData, known_malware: e.target.value })}
                placeholder="WellMess, WellMail"
                className="input-sentinel"
              />
            </div>
            <div>
              <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Known Tools (comma-separated)</label>
              <input
                type="text"
                value={formData.known_tools}
                onChange={(e) => setFormData({ ...formData, known_tools: e.target.value })}
                placeholder="Mimikatz, Cobalt Strike"
                className="input-sentinel"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-sentinel btn-sentinel-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="btn-sentinel btn-sentinel-danger"
            >
              {saving ? 'Saving...' : actor ? 'Update Actor' : 'Create Actor'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ============================================================================
// Helper Functions
// ============================================================================

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

function formatDate(dateStr: string): string {
  if (!dateStr || dateStr === 'Unknown') return 'Unknown'
  try {
    const date = new Date(dateStr)
    return date.toLocaleDateString()
  } catch {
    return dateStr
  }
}
