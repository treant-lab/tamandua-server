import { useState, useEffect, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  Target,
  AlertTriangle,
  Eye,
  FileKey,
  Database,
  Cloud,
  Key,
  Globe,
  Server,
  Activity,
  Users,
  TrendingUp,
  Clock,
  MapPin,
  RefreshCw,
  Plus,
  Settings,
  Play,
  Pause,
  RotateCcw,
  Download,
  ChevronRight,
  Crosshair,
  Fingerprint,
} from 'lucide-react'
import { cn, formatDate, severityColor } from '@/lib/utils'
import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

interface DeceptionStats {
  totalDecoys: number
  activeDecoys: number
  accessedDecoys: number
  uniqueAttackers: number
  totalInteractions: number
  interactionsToday: number
  ttpsExtracted: number
  indicatorsGenerated: number
  agentsWithDecoys: number
  detectionRate: number
}

interface Breadcrumb {
  id: string
  type: string
  agentId: string
  agentHostname: string
  path: string
  canaryToken: string
  status: 'active' | 'accessed' | 'rotated' | 'removed'
  deployedAt: string
  lastRotatedAt: string | null
  accessCount: number
}

interface AttackerProfile {
  id: string
  riskScore: number
  firstSeen: string
  lastSeen: string
  sourceIps: string[]
  agentsTargeted: string[]
  interactions: number
  ttps: TTP[]
  status: 'active' | 'dormant' | 'neutralized'
}

interface TTP {
  tactic: string
  techniqueId: string
  techniqueName: string
  evidenceCount: number
}

interface Indicator {
  type: 'ip' | 'username' | 'credential' | 'user_agent'
  value: string
  confidence: number
  firstSeen: string
  context: Record<string, unknown>
}

interface DeploymentProfile {
  id: string
  name: string
  description: string
  decoyTypes: string[]
  osTypes: string[]
  density: 'low' | 'medium' | 'high'
  enabled: boolean
}

interface Recommendation {
  type: 'add_decoy' | 'rotate' | 'investigate'
  priority: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  agentId?: string
  decoyType?: string
}

interface TimelineEvent {
  timestamp: string
  eventType: string
  agentId: string
  agentHostname: string
  decoyType: string
  sourceIp: string | null
  mitreTechnique: string | null
}

interface DecoyService {
  type: string
  port: number
  status: 'running' | 'stopped'
  connections: number
  lastActivity: string | null
}

interface DeceptionPageProps {
  stats: DeceptionStats
  breadcrumbs: Breadcrumb[]
  attackers: AttackerProfile[]
  indicators: Indicator[]
  profiles: DeploymentProfile[]
  recommendations: Recommendation[]
  timeline: TimelineEvent[]
  decoyServices: DecoyService[]
}

// ============================================================================
// Component
// ============================================================================

export default function Deception({
  stats: initialStats,
  breadcrumbs: initialBreadcrumbs,
  attackers: initialAttackers,
  indicators: initialIndicators,
  profiles: initialProfiles,
  recommendations: initialRecommendations,
  timeline: initialTimeline,
  decoyServices: initialServices,
}: DeceptionPageProps) {
  const [stats, setStats] = useState(initialStats)
  const [breadcrumbs, setBreadcrumbs] = useState(initialBreadcrumbs)
  const [attackers, setAttackers] = useState(initialAttackers)
  const [indicators, setIndicators] = useState(initialIndicators)
  const [profiles, setProfiles] = useState(initialProfiles)
  const [recommendations, setRecommendations] = useState(initialRecommendations)
  const [timeline, setTimeline] = useState(initialTimeline)
  const [decoyServices, setDecoyServices] = useState(initialServices)
  const [activeTab, setActiveTab] = useState<'overview' | 'decoys' | 'attackers' | 'intel' | 'services'>('overview')
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [selectedAttacker, setSelectedAttacker] = useState<AttackerProfile | null>(null)

  const refresh = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const response = await fetch('/api/v1/deception/stats')
      if (response.ok) {
        const data = await response.json()
        setStats(data.stats)
        setBreadcrumbs(data.breadcrumbs || breadcrumbs)
        setAttackers(data.attackers || attackers)
        setIndicators(data.indicators || indicators)
        setTimeline(data.timeline || timeline)
      }
    } catch (error) {
      logger.error('Failed to refresh deception data:', error)
    } finally {
      setIsRefreshing(false)
    }
  }, [breadcrumbs, attackers, indicators, timeline])

  const deployDecoys = async (profileId: string) => {
    try {
      const response = await fetch(`/api/v1/deception/deploy/${profileId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      if (response.ok) {
        refresh()
      }
    } catch (error) {
      logger.error('Failed to deploy decoys:', error)
    }
  }

  const rotateDecoys = async (agentId: string) => {
    try {
      const response = await fetch(`/api/v1/deception/rotate/${agentId}`, {
        method: 'POST',
      })
      if (response.ok) {
        refresh()
      }
    } catch (error) {
      logger.error('Failed to rotate decoys:', error)
    }
  }

  // Poll for updates every 30 seconds
  useEffect(() => {
    const interval = setInterval(refresh, 30000)
    return () => clearInterval(interval)
  }, [refresh])

  return (
    <MainLayout title="Deception Technology">
      <Head title="Deception - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3" style={{ color: 'var(--fg)' }}>
              <Target className="h-7 w-7" style={{ color: 'var(--purple-400)' }} />
              Deception Technology
            </h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              Honey tokens, decoy services, and attacker behavior analysis
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={refresh}
              disabled={isRefreshing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors hover:opacity-80"
              style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)' }}
            >
              <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
              Refresh
            </button>
            <button
              onClick={() => deployDecoys('default-windows')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors hover:opacity-90"
              style={{ backgroundColor: 'var(--purple-600)', color: 'var(--fg)' }}
            >
              <Plus className="h-4 w-4" />
              Deploy Decoys
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <StatCard
            title="Active Decoys"
            value={stats.activeDecoys}
            total={stats.totalDecoys}
            icon={Shield}
            color="purple"
          />
          <StatCard
            title="Accessed"
            value={stats.accessedDecoys}
            icon={Eye}
            color="red"
          />
          <StatCard
            title="Attackers"
            value={stats.uniqueAttackers}
            icon={Users}
            color="orange"
          />
          <StatCard
            title="Interactions Today"
            value={stats.interactionsToday}
            icon={Activity}
            color="yellow"
          />
          <StatCard
            title="TTPs Extracted"
            value={stats.ttpsExtracted}
            icon={Fingerprint}
            color="blue"
          />
          <StatCard
            title="Detection Rate"
            value={`${stats.detectionRate}%`}
            icon={TrendingUp}
            color="green"
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-1 p-1 rounded-lg w-fit" style={{ backgroundColor: 'var(--surface)' }}>
          {['overview', 'decoys', 'attackers', 'intel', 'services'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={cn(
                "px-4 py-2 rounded-md text-sm font-medium transition-colors capitalize",
                activeTab === tab
                  ? ""
                  : "hover:opacity-80"
              )}
              style={{
                backgroundColor: activeTab === tab ? 'var(--purple-600)' : 'transparent',
                color: activeTab === tab ? 'var(--fg)' : 'var(--muted)',
              }}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Recent Activity */}
            <div className="lg:col-span-2 card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Activity className="h-5 w-5" style={{ color: 'var(--purple-400)' }} />
                  Recent Activity
                </h2>
              </div>
              <div className="divide-y max-h-[400px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                {timeline.length === 0 ? (
                  <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                    <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No deception activity detected yet</p>
                  </div>
                ) : (
                  timeline.slice(0, 10).map((event, idx) => (
                    <TimelineRow key={idx} event={event} />
                  ))
                )}
              </div>
            </div>

            {/* Recommendations */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <AlertTriangle className="h-5 w-5" style={{ color: 'var(--warn)' }} />
                  Recommendations
                </h2>
              </div>
              <div className="p-4 space-y-3">
                {recommendations.length === 0 ? (
                  <p className="text-center py-4" style={{ color: 'var(--muted)' }}>
                    No recommendations at this time
                  </p>
                ) : (
                  recommendations.slice(0, 5).map((rec, idx) => (
                    <RecommendationCard key={idx} recommendation={rec} />
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'decoys' && (
          <div className="space-y-6">
            {/* Deployment Profiles */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Settings className="h-5 w-5" style={{ color: 'var(--purple-400)' }} />
                  Deployment Profiles
                </h2>
              </div>
              <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {profiles.map((profile) => (
                  <ProfileCard
                    key={profile.id}
                    profile={profile}
                    onDeploy={() => deployDecoys(profile.id)}
                  />
                ))}
              </div>
            </div>

            {/* Decoy Inventory */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <FileKey className="h-5 w-5" style={{ color: 'var(--purple-400)' }} />
                  Decoy Inventory ({breadcrumbs.length})
                </h2>
                <div className="flex items-center gap-2">
                  <button className="text-sm flex items-center gap-1 hover:opacity-80" style={{ color: 'var(--muted)' }}>
                    <Download className="h-4 w-4" />
                    Export
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}>
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Type</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Agent</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Path</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Status</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Deployed</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Access Count</th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {breadcrumbs.map((bc) => (
                      <BreadcrumbRow
                        key={bc.id}
                        breadcrumb={bc}
                        onRotate={() => rotateDecoys(bc.agentId)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'attackers' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Attacker List */}
            <div className="lg:col-span-2 card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Crosshair className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                  Attacker Profiles ({attackers.length})
                </h2>
              </div>
              <div className="divide-y max-h-[600px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                {attackers.length === 0 ? (
                  <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                    <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No attackers detected yet</p>
                  </div>
                ) : (
                  attackers.map((attacker) => (
                    <AttackerRow
                      key={attacker.id}
                      attacker={attacker}
                      isSelected={selectedAttacker?.id === attacker.id}
                      onSelect={() => setSelectedAttacker(attacker)}
                    />
                  ))
                )}
              </div>
            </div>

            {/* Attacker Detail */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                  {selectedAttacker ? 'Attacker Details' : 'Select an Attacker'}
                </h2>
              </div>
              {selectedAttacker ? (
                <AttackerDetail attacker={selectedAttacker} />
              ) : (
                <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                  <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Click on an attacker to view details</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'intel' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Extracted TTPs */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Fingerprint className="h-5 w-5" style={{ color: 'var(--info)' }} />
                  Extracted TTPs
                </h2>
              </div>
              <div className="p-4 space-y-3 max-h-[400px] overflow-y-auto">
                {attackers
                  .flatMap((a) => a.ttps)
                  .reduce((acc, ttp) => {
                    const existing = acc.find((t) => t.techniqueId === ttp.techniqueId)
                    if (existing) {
                      existing.evidenceCount += ttp.evidenceCount
                    } else {
                      acc.push({ ...ttp })
                    }
                    return acc
                  }, [] as TTP[])
                  .sort((a, b) => b.evidenceCount - a.evidenceCount)
                  .map((ttp, idx) => (
                    <TTPCard key={idx} ttp={ttp} />
                  ))}
              </div>
            </div>

            {/* Indicators of Compromise */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Globe className="h-5 w-5" style={{ color: 'var(--warn)' }} />
                  Indicators of Compromise ({indicators.length})
                </h2>
                <button className="text-sm flex items-center gap-1 hover:opacity-80" style={{ color: 'var(--muted)' }}>
                  <Download className="h-4 w-4" />
                  Export STIX
                </button>
              </div>
              <div className="divide-y max-h-[400px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                {indicators.map((ioc, idx) => (
                  <IndicatorRow key={idx} indicator={ioc} />
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'services' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {decoyServices.map((service) => (
              <DecoyServiceCard key={service.type} service={service} />
            ))}
            {decoyServices.length === 0 && (
              <div className="col-span-full card-sentinel rounded-xl p-8 text-center">
                <Server className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--muted)' }} />
                <p style={{ color: 'var(--muted)' }}>No decoy services configured</p>
                <button
                  className="mt-4 px-4 py-2 rounded-lg transition-colors hover:opacity-90"
                  style={{ backgroundColor: 'var(--purple-600)', color: 'var(--fg)' }}
                >
                  Configure Services
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </MainLayout>
  )
}

// ============================================================================
// Sub-components
// ============================================================================

function StatCard({
  title,
  value,
  total,
  icon: Icon,
  color,
}: {
  title: string
  value: number | string
  total?: number
  icon: React.ElementType
  color: 'purple' | 'red' | 'orange' | 'yellow' | 'blue' | 'green'
}) {
  const colorStyles = {
    purple: { backgroundColor: 'color-mix(in srgb, var(--purple-600) 20%, transparent)', color: 'var(--purple-400)' },
    red: { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)', color: 'var(--crit)' },
    orange: { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)', color: 'var(--warn)' },
    yellow: { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)', color: 'var(--warn)' },
    blue: { backgroundColor: 'color-mix(in srgb, var(--info) 20%, transparent)', color: 'var(--info)' },
    green: { backgroundColor: 'color-mix(in srgb, var(--emerald-400) 20%, transparent)', color: 'var(--emerald-400)' },
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="p-2 rounded-lg w-fit" style={colorStyles[color]}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="mt-3">
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
          {total !== undefined && (
            <span className="text-sm" style={{ color: 'var(--muted)' }}>/ {total}</span>
          )}
        </div>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
      </div>
    </div>
  )
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  const typeIcons: Record<string, React.ElementType> = {
    ssh_auth_attempt: Key,
    file_access: FileKey,
    http_request: Globe,
    credential_capture: Shield,
  }
  const Icon = typeIcons[event.eventType] || Activity

  return (
    <div className="flex items-center gap-4 p-4 hover:opacity-80 transition-opacity">
      <div
        className="p-2 rounded-lg"
        style={{ backgroundColor: 'color-mix(in srgb, var(--purple-600) 20%, transparent)' }}
      >
        <Icon className="h-5 w-5" style={{ color: 'var(--purple-400)' }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{event.eventType}</span>
          {event.mitreTechnique && (
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{ backgroundColor: 'color-mix(in srgb, var(--info) 20%, transparent)', color: 'var(--info)' }}
            >
              {event.mitreTechnique}
            </span>
          )}
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
          {event.decoyType} on {event.agentHostname}
          {event.sourceIp && ` from ${event.sourceIp}`}
        </p>
      </div>
      <div className="flex items-center gap-1 text-xs" style={{ color: 'var(--muted)' }}>
        <Clock className="h-3 w-3" />
        {formatDate(event.timestamp)}
      </div>
    </div>
  )
}

function RecommendationCard({ recommendation }: { recommendation: Recommendation }) {
  const priorityStyles: Record<string, { borderColor: string; backgroundColor: string }> = {
    critical: { borderColor: 'var(--crit)', backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)' },
    high: { borderColor: 'var(--warn)', backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)' },
    medium: { borderColor: 'var(--warn)', backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)' },
    low: { borderColor: 'var(--info)', backgroundColor: 'color-mix(in srgb, var(--info) 10%, transparent)' },
  }

  const style = priorityStyles[recommendation.priority]

  return (
    <div
      className="p-3 rounded-lg border-l-4"
      style={{ borderColor: style.borderColor, backgroundColor: style.backgroundColor }}
    >
      <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{recommendation.title}</p>
      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{recommendation.description}</p>
    </div>
  )
}

function ProfileCard({
  profile,
  onDeploy,
}: {
  profile: DeploymentProfile
  onDeploy: () => void
}) {
  return (
    <div
      className="p-4 rounded-lg border"
      style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)', borderColor: 'var(--border)' }}
    >
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{profile.name}</h3>
        <span
          className="px-2 py-0.5 rounded text-xs"
          style={{
            backgroundColor: profile.enabled
              ? 'color-mix(in srgb, var(--emerald-400) 20%, transparent)'
              : 'color-mix(in srgb, var(--muted) 20%, transparent)',
            color: profile.enabled ? 'var(--emerald-400)' : 'var(--muted)',
          }}
        >
          {profile.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>
      <p className="text-xs mb-3" style={{ color: 'var(--muted)' }}>{profile.description}</p>
      <div className="flex flex-wrap gap-1 mb-3">
        {profile.decoyTypes.slice(0, 3).map((type) => (
          <span
            key={type}
            className="text-xs px-2 py-0.5 rounded"
            style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
          >
            {type}
          </span>
        ))}
        {profile.decoyTypes.length > 3 && (
          <span className="text-xs" style={{ color: 'var(--muted)' }}>+{profile.decoyTypes.length - 3}</span>
        )}
      </div>
      <button
        onClick={onDeploy}
        disabled={!profile.enabled}
        className="w-full px-3 py-1.5 text-sm rounded transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        style={{
          backgroundColor: profile.enabled ? 'var(--purple-600)' : 'var(--surface)',
          color: 'var(--fg)',
        }}
      >
        Deploy
      </button>
    </div>
  )
}

function BreadcrumbRow({
  breadcrumb,
  onRotate,
}: {
  breadcrumb: Breadcrumb
  onRotate: () => void
}) {
  const statusStyles: Record<string, { backgroundColor: string; color: string }> = {
    active: { backgroundColor: 'color-mix(in srgb, var(--emerald-400) 20%, transparent)', color: 'var(--emerald-400)' },
    accessed: { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)', color: 'var(--crit)' },
    rotated: { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)', color: 'var(--warn)' },
    removed: { backgroundColor: 'color-mix(in srgb, var(--muted) 20%, transparent)', color: 'var(--muted)' },
  }

  const typeIcons: Record<string, React.ElementType> = {
    ssh_key: Key,
    cloud_credential: Cloud,
    api_token: FileKey,
    database: Database,
    credential: Shield,
  }
  const Icon = typeIcons[breadcrumb.type] || FileKey

  return (
    <tr className="hover:opacity-80 transition-opacity">
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4" style={{ color: 'var(--purple-400)' }} />
          <span className="text-sm" style={{ color: 'var(--fg)' }}>{breadcrumb.type}</span>
        </div>
      </td>
      <td className="px-4 py-3 text-sm" style={{ color: 'var(--muted)' }}>{breadcrumb.agentHostname}</td>
      <td className="px-4 py-3">
        <span className="text-sm font-mono truncate block max-w-[200px]" style={{ color: 'var(--muted)' }}>
          {breadcrumb.path}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs px-2 py-0.5 rounded" style={statusStyles[breadcrumb.status]}>
          {breadcrumb.status}
        </span>
      </td>
      <td className="px-4 py-3 text-sm" style={{ color: 'var(--muted)' }}>{formatDate(breadcrumb.deployedAt)}</td>
      <td className="px-4 py-3">
        <span
          className="text-sm"
          style={{
            color: breadcrumb.accessCount > 0 ? 'var(--crit)' : 'var(--muted)',
            fontWeight: breadcrumb.accessCount > 0 ? 500 : 400,
          }}
        >
          {breadcrumb.accessCount}
        </span>
      </td>
      <td className="px-4 py-3">
        <button
          onClick={onRotate}
          className="p-1 transition-colors hover:opacity-80"
          style={{ color: 'var(--muted)' }}
          title="Rotate"
        >
          <RotateCcw className="h-4 w-4" />
        </button>
      </td>
    </tr>
  )
}

function AttackerRow({
  attacker,
  isSelected,
  onSelect,
}: {
  attacker: AttackerProfile
  isSelected: boolean
  onSelect: () => void
}) {
  const statusStyles: Record<string, { backgroundColor: string; color: string }> = {
    active: { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)', color: 'var(--crit)' },
    dormant: { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)', color: 'var(--warn)' },
    neutralized: { backgroundColor: 'color-mix(in srgb, var(--emerald-400) 20%, transparent)', color: 'var(--emerald-400)' },
  }

  return (
    <div
      onClick={onSelect}
      className={cn(
        'flex items-center gap-4 p-4 cursor-pointer transition-colors',
        isSelected ? 'border-l-2' : 'hover:opacity-80'
      )}
      style={{
        backgroundColor: isSelected ? 'color-mix(in srgb, var(--purple-600) 30%, transparent)' : 'transparent',
        borderColor: isSelected ? 'var(--purple-400)' : 'transparent',
      }}
    >
      <div className="relative">
        <div
          className="w-10 h-10 rounded-full flex items-center justify-center"
          style={{ backgroundColor: 'var(--surface)' }}
        >
          <Users className="h-5 w-5" style={{ color: 'var(--muted)' }} />
        </div>
        <div
          className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full border-2"
          style={{
            backgroundColor: attacker.status === 'active' ? 'var(--crit)' : 'var(--muted)',
            borderColor: 'var(--surface)',
          }}
        />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{attacker.id}</span>
          <span className="text-xs px-2 py-0.5 rounded" style={statusStyles[attacker.status]}>
            {attacker.status}
          </span>
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
          {attacker.interactions} interactions | {attacker.agentsTargeted.length} agents targeted
        </p>
      </div>
      <div className="text-right">
        <div className="flex items-center gap-1">
          <span
            className="text-lg font-bold"
            style={{
              color:
                attacker.riskScore >= 80
                  ? 'var(--crit)'
                  : attacker.riskScore >= 50
                    ? 'var(--warn)'
                    : 'var(--emerald-400)',
            }}
          >
            {attacker.riskScore}
          </span>
        </div>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>Risk Score</p>
      </div>
      <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
    </div>
  )
}

function AttackerDetail({ attacker }: { attacker: AttackerProfile }) {
  const riskColor =
    attacker.riskScore >= 80
      ? 'var(--crit)'
      : attacker.riskScore >= 50
        ? 'var(--warn)'
        : 'var(--emerald-400)'

  return (
    <div className="p-4 space-y-4">
      {/* Risk Score */}
      <div className="text-center py-4">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-full text-3xl font-bold"
          style={{
            backgroundColor: `color-mix(in srgb, ${riskColor} 20%, transparent)`,
            color: riskColor,
          }}
        >
          {attacker.riskScore}
        </div>
        <p className="text-sm mt-2" style={{ color: 'var(--muted)' }}>Risk Score</p>
      </div>

      {/* Details */}
      <div className="space-y-3">
        <div>
          <p className="text-xs uppercase" style={{ color: 'var(--muted)' }}>Source IPs</p>
          <div className="flex flex-wrap gap-1 mt-1">
            {attacker.sourceIps.map((ip) => (
              <span
                key={ip}
                className="text-xs px-2 py-0.5 rounded"
                style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
              >
                {ip}
              </span>
            ))}
          </div>
        </div>

        <div>
          <p className="text-xs uppercase" style={{ color: 'var(--muted)' }}>Agents Targeted</p>
          <p className="text-sm" style={{ color: 'var(--fg)' }}>{attacker.agentsTargeted.length} endpoints</p>
        </div>

        <div>
          <p className="text-xs uppercase" style={{ color: 'var(--muted)' }}>First Seen</p>
          <p className="text-sm" style={{ color: 'var(--fg)' }}>{formatDate(attacker.firstSeen)}</p>
        </div>

        <div>
          <p className="text-xs uppercase" style={{ color: 'var(--muted)' }}>Last Seen</p>
          <p className="text-sm" style={{ color: 'var(--fg)' }}>{formatDate(attacker.lastSeen)}</p>
        </div>

        <div>
          <p className="text-xs uppercase" style={{ color: 'var(--muted)' }}>TTPs ({attacker.ttps.length})</p>
          <div className="space-y-1 mt-1">
            {attacker.ttps.slice(0, 5).map((ttp, idx) => (
              <div key={idx} className="text-xs">
                <span style={{ color: 'var(--info)' }}>{ttp.techniqueId}</span>
                <span className="ml-2" style={{ color: 'var(--muted)' }}>{ttp.techniqueName}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function TTPCard({ ttp }: { ttp: TTP }) {
  const tacticStyles: Record<string, { backgroundColor: string; color: string }> = {
    'credential-access': { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)', color: 'var(--crit)' },
    'lateral-movement': { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)', color: 'var(--warn)' },
    discovery: { backgroundColor: 'color-mix(in srgb, var(--info) 20%, transparent)', color: 'var(--info)' },
    collection: { backgroundColor: 'color-mix(in srgb, var(--purple-400) 20%, transparent)', color: 'var(--purple-400)' },
    impact: { backgroundColor: 'color-mix(in srgb, var(--crit) 20%, transparent)', color: 'var(--crit)' },
  }

  const style = tacticStyles[ttp.tactic] || { backgroundColor: 'var(--surface)', color: 'var(--muted)' }

  return (
    <div
      className="p-3 rounded-lg"
      style={{ backgroundColor: 'color-mix(in srgb, var(--surface) 50%, transparent)' }}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{ttp.techniqueId}</span>
        <span className="text-xs px-2 py-0.5 rounded" style={style}>
          {ttp.tactic}
        </span>
      </div>
      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{ttp.techniqueName}</p>
      <p className="text-xs mt-2" style={{ color: 'var(--muted)' }}>
        {ttp.evidenceCount} evidence{ttp.evidenceCount !== 1 ? 's' : ''}
      </p>
    </div>
  )
}

function IndicatorRow({ indicator }: { indicator: Indicator }) {
  const typeIcons: Record<string, React.ElementType> = {
    ip: MapPin,
    username: Users,
    credential: Key,
    user_agent: Globe,
  }
  const Icon = typeIcons[indicator.type] || Globe

  return (
    <div className="flex items-center gap-4 p-3 hover:opacity-80 transition-opacity">
      <div
        className="p-2 rounded-lg"
        style={{ backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)' }}
      >
        <Icon className="h-4 w-4" style={{ color: 'var(--warn)' }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase" style={{ color: 'var(--muted)' }}>{indicator.type}</span>
        </div>
        <p className="text-sm font-mono truncate" style={{ color: 'var(--fg)' }}>{indicator.value}</p>
      </div>
      <div className="text-right">
        <span className="text-sm" style={{ color: 'var(--muted)' }}>{Math.round(indicator.confidence * 100)}%</span>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>confidence</p>
      </div>
    </div>
  )
}

function DecoyServiceCard({ service }: { service: DecoyService }) {
  const serviceIcons: Record<string, React.ElementType> = {
    SSH: Key,
    HTTP: Globe,
    FTP: FileKey,
    Redis: Database,
    SMB: Server,
    RDP: Server,
  }
  const Icon = serviceIcons[service.type] || Server

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div
            className="p-2 rounded-lg"
            style={{ backgroundColor: 'color-mix(in srgb, var(--purple-600) 20%, transparent)' }}
          >
            <Icon className="h-5 w-5" style={{ color: 'var(--purple-400)' }} />
          </div>
          <div>
            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{service.type} Honeypot</h3>
            <p className="text-xs" style={{ color: 'var(--muted)' }}>Port {service.port}</p>
          </div>
        </div>
        <span
          className="px-2 py-0.5 rounded text-xs"
          style={{
            backgroundColor:
              service.status === 'running'
                ? 'color-mix(in srgb, var(--emerald-400) 20%, transparent)'
                : 'color-mix(in srgb, var(--muted) 20%, transparent)',
            color: service.status === 'running' ? 'var(--emerald-400)' : 'var(--muted)',
          }}
        >
          {service.status}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>Connections</p>
          <p className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{service.connections}</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>Last Activity</p>
          <p className="text-sm" style={{ color: 'var(--fg)' }}>
            {service.lastActivity ? formatDate(service.lastActivity) : 'Never'}
          </p>
        </div>
      </div>

      <div className="flex gap-2">
        <button
          className="flex-1 flex items-center justify-center gap-2 px-3 py-1.5 rounded text-sm transition-colors"
          style={{
            backgroundColor:
              service.status === 'running'
                ? 'var(--surface)'
                : 'var(--emerald-400)',
            color: 'var(--fg)',
          }}
        >
          {service.status === 'running' ? (
            <>
              <Pause className="h-4 w-4" />
              Stop
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Start
            </>
          )}
        </button>
        <button
          className="p-1.5 rounded transition-colors"
          style={{ backgroundColor: 'var(--surface)' }}
        >
          <Settings className="h-4 w-4" style={{ color: 'var(--muted)' }} />
        </button>
      </div>
    </div>
  )
}
