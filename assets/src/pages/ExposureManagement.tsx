import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  AlertOctagon,
  Search,
  Filter,
  RefreshCw,
  Globe,
  Shield,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  TrendingDown,
  ExternalLink,
  Server,
  Lock,
  Unlock,
  FileText,
  Minus
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState } from 'react'

// Types
interface ExposedService {
  id: string
  host: string
  port: number
  protocol: string
  service: string
  version?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  exposure: 'internet' | 'vpn' | 'internal'
  vulnerabilities: number
  lastScanned: string
  findings: string[]
}

interface VulnerabilityItem {
  id: string
  cve: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss: number
  affectedAssets: number
  exploitable: boolean
  patchAvailable: boolean
  firstSeen: string
  recommendation: string
}

interface ExposureTrend {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

interface Recommendation {
  id: string
  priority: 'urgent' | 'high' | 'medium' | 'low'
  title: string
  description: string
  impact: string
  effort: 'minimal' | 'moderate' | 'significant'
  affectedAssets: number
  status: 'open' | 'in_progress' | 'completed'
}

interface ExposureStats {
  totalExposures: number
  criticalExposures: number
  exposedServices: number
  attackSurface: number
  riskScore: number
  trend: 'up' | 'down' | 'stable'
  trendValue: number
}

interface AttackSurfaceAsset {
  id: string
  name: string
  type: 'service' | 'endpoint' | 'cloud' | 'external'
  riskScore: number
  exposures: number
}

interface CrownJewel {
  id: string
  name: string
  type: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  protectionStatus: 'protected' | 'partial' | 'unprotected'
  lastAssessed: string
}

interface ExposurePageProps {
  attackSurfaceMap?: {
    assets: AttackSurfaceAsset[]
    totalRiskScore: number
    exposedAssets: number
  }
  prioritizedVulnerabilities?: VulnerabilityItem[]
  crownJewels?: CrownJewel[]
  services?: ExposedService[]
  trends?: ExposureTrend[]
  recommendations?: Recommendation[]
  stats?: ExposureStats
}

const defaultStats: ExposureStats = {
  totalExposures: 0,
  criticalExposures: 0,
  exposedServices: 0,
  attackSurface: 0,
  riskScore: 0,
  trend: 'stable',
  trendValue: 0
}

export default function Exposure({
  attackSurfaceMap,
  prioritizedVulnerabilities = [],
  crownJewels = [],
  services = [],
  trends = [],
  recommendations = [],
  stats = defaultStats
}: ExposurePageProps) {
  const [activeTab, setActiveTab] = useState<'services' | 'vulnerabilities' | 'recommendations' | 'crown-jewels' | 'attack-surface'>('services')
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [loading, setLoading] = useState(false)

  const filteredServices = services.filter(service => {
    if (severityFilter !== 'all' && service.severity !== severityFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        service.host.toLowerCase().includes(query) ||
        service.service.toLowerCase().includes(query)
      )
    }
    return true
  })

  const filteredVulnerabilities = prioritizedVulnerabilities.filter(vuln => {
    if (severityFilter !== 'all' && vuln.severity !== severityFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        vuln.cve.toLowerCase().includes(query) ||
        vuln.title.toLowerCase().includes(query)
      )
    }
    return true
  })

  const handleRefresh = () => {
    setLoading(true)
    setTimeout(() => setLoading(false), 1500)
  }

  return (
    <MainLayout title="Exposure Management">
      <Head title="Exposure - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <StatCard
            icon={AlertOctagon}
            label="Total Exposures"
            value={stats.totalExposures}
            color="primary"
          />
          <StatCard
            icon={AlertTriangle}
            label="Critical"
            value={stats.criticalExposures}
            color="crit"
          />
          <StatCard
            icon={Globe}
            label="Exposed Services"
            value={stats.exposedServices}
            color="high"
          />
          <StatCard
            icon={Server}
            label="Attack Surface"
            value={stats.attackSurface}
            color="med"
            suffix=" assets"
          />
          <RiskScoreCard score={stats.riskScore} trend={stats.trend} trendValue={stats.trendValue} />
        </div>

        {/* Exposure Trends Chart */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Exposure Trends (Last 7 Days)</h2>
            <button
              onClick={handleRefresh}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition-colors"
              style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-3)'
                e.currentTarget.style.color = 'var(--fg)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                e.currentTarget.style.color = 'var(--muted)'
              }}
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
              Refresh
            </button>
          </div>
          <TrendChart trends={trends} />
        </div>

        {/* Tabs */}
        <div className="card-sentinel rounded-xl">
          <div className="flex" style={{ borderBottom: '1px solid var(--border)' }}>
            <TabButton
              active={activeTab === 'services'}
              onClick={() => setActiveTab('services')}
              icon={Globe}
              label="Exposed Services"
              count={services.length}
            />
            <TabButton
              active={activeTab === 'vulnerabilities'}
              onClick={() => setActiveTab('vulnerabilities')}
              icon={Shield}
              label="Vulnerabilities"
              count={prioritizedVulnerabilities.length}
            />
            <TabButton
              active={activeTab === 'recommendations'}
              onClick={() => setActiveTab('recommendations')}
              icon={FileText}
              label="Recommendations"
              count={recommendations.filter(r => r.status !== 'completed').length}
            />
            <TabButton
              active={activeTab === 'crown-jewels'}
              onClick={() => setActiveTab('crown-jewels')}
              icon={Lock}
              label="Crown Jewels"
              count={crownJewels.length}
            />
            <TabButton
              active={activeTab === 'attack-surface'}
              onClick={() => setActiveTab('attack-surface')}
              icon={Server}
              label="Attack Surface"
              count={attackSurfaceMap?.assets.length ?? 0}
            />
          </div>

          {/* Filters */}
          <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={
                    activeTab === 'services' ? 'Search hosts or services...' :
                    activeTab === 'vulnerabilities' ? 'Search CVE or title...' :
                    'Search recommendations...'
                  }
                  className="input-sentinel w-full pl-10 pr-4"
                />
              </div>
              {activeTab !== 'recommendations' && (
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="input-sentinel px-3 py-2 text-sm"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              )}
            </div>
          </div>

          {/* Services Tab */}
          {activeTab === 'services' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Host</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Service</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Port</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Exposure</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Severity</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Vulnerabilities</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredServices.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                        <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No exposed services found</p>
                      </td>
                    </tr>
                  ) : (
                    filteredServices.map((service) => (
                      <ServiceRow key={service.id} service={service} />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>CVE</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Title</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>CVSS</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Assets</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Exploitable</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Patch</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredVulnerabilities.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                        <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No vulnerabilities found</p>
                      </td>
                    </tr>
                  ) : (
                    filteredVulnerabilities.map((vuln) => (
                      <VulnerabilityRow key={vuln.id} vulnerability={vuln} />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* Recommendations Tab */}
          {activeTab === 'recommendations' && (
            <div className="p-4 space-y-4">
              {recommendations.map((rec) => (
                <RecommendationCard key={rec.id} recommendation={rec} />
              ))}
            </div>
          )}

          {/* Crown Jewels Tab */}
          {activeTab === 'crown-jewels' && (
            <div className="p-4">
              {crownJewels.length === 0 ? (
                <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
                  <Lock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No crown jewels identified</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {crownJewels.map((jewel) => (
                    <CrownJewelCard key={jewel.id} jewel={jewel} />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Attack Surface Tab */}
          {activeTab === 'attack-surface' && (
            <div className="p-4">
              {!attackSurfaceMap || attackSurfaceMap.assets.length === 0 ? (
                <div className="text-center py-12" style={{ color: 'var(--muted)' }}>
                  <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No attack surface data available</p>
                </div>
              ) : (
                <div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{attackSurfaceMap.totalRiskScore}</p>
                      <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Risk Score</p>
                    </div>
                    <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{attackSurfaceMap.assets.length}</p>
                      <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Assets</p>
                    </div>
                    <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
                      <p className="text-2xl font-bold" style={{ color: 'var(--crit)' }}>{attackSurfaceMap.exposedAssets}</p>
                      <p className="text-sm" style={{ color: 'var(--muted)' }}>Exposed Assets</p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    {attackSurfaceMap.assets.map((asset) => (
                      <AttackSurfaceAssetRow key={asset.id} asset={asset} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

function StatCard({ icon: Icon, label, value, color, suffix = '' }: {
  icon: React.ElementType
  label: string
  value: number
  color: 'primary' | 'crit' | 'high' | 'med' | 'low'
  suffix?: string
}) {
  const colorStyles: Record<typeof color, { bg: string; text: string }> = {
    primary: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    crit: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    med: { bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)' }
  }

  const style = colorStyles[color]

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: style.bg }}>
          <Icon className="h-5 w-5" style={{ color: style.text }} />
        </div>
        <div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}{suffix}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
        </div>
      </div>
    </div>
  )
}

function RiskScoreCard({ score, trend, trendValue }: { score: number; trend: 'up' | 'down' | 'stable'; trendValue: number }) {
  const scoreColor = score >= 80 ? 'var(--crit)' : score >= 60 ? 'var(--high)' : score >= 40 ? 'var(--med)' : 'var(--emerald-400)'
  const TrendIcon = trend === 'up' ? TrendingUp : trend === 'down' ? TrendingDown : Minus
  const trendColor = trend === 'up' ? 'var(--crit)' : trend === 'down' ? 'var(--emerald-400)' : 'var(--muted)'

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-3xl font-bold" style={{ color: scoreColor }}>{score}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>Risk Score</p>
        </div>
        <div className="flex items-center gap-1" style={{ color: trendColor }}>
          <TrendIcon className="h-5 w-5" />
          <span className="text-sm font-medium">{trendValue}%</span>
        </div>
      </div>
      <div className="mt-3 h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: `${score}%`,
            backgroundColor: scoreColor
          }}
        />
      </div>
    </div>
  )
}

function TrendChart({ trends }: { trends: ExposureTrend[] }) {
  const maxValue = Math.max(...trends.flatMap(t => [t.critical, t.high, t.medium, t.low]), 1)

  return (
    <div className="space-y-4">
      {/* Legend */}
      <div className="flex items-center gap-6 text-sm">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ backgroundColor: 'var(--crit)' }} />
          <span style={{ color: 'var(--muted)' }}>Critical</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ backgroundColor: 'var(--high)' }} />
          <span style={{ color: 'var(--muted)' }}>High</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ backgroundColor: 'var(--med)' }} />
          <span style={{ color: 'var(--muted)' }}>Medium</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ backgroundColor: 'var(--low)' }} />
          <span style={{ color: 'var(--muted)' }}>Low</span>
        </div>
      </div>

      {/* Chart */}
      <div className="flex items-end gap-2 h-40">
        {trends.map((trend, idx) => (
          <div key={idx} className="flex-1 flex flex-col gap-1">
            <div className="flex-1 flex flex-col-reverse gap-0.5">
              <div
                className="rounded-t"
                style={{ height: `${(trend.critical / maxValue) * 100}%`, backgroundColor: 'var(--crit)', opacity: 0.8 }}
              />
              <div
                style={{ height: `${(trend.high / maxValue) * 100}%`, backgroundColor: 'var(--high)', opacity: 0.8 }}
              />
              <div
                style={{ height: `${(trend.medium / maxValue) * 100}%`, backgroundColor: 'var(--med)', opacity: 0.8 }}
              />
              <div
                className="rounded-b"
                style={{ height: `${(trend.low / maxValue) * 100}%`, backgroundColor: 'var(--low)', opacity: 0.8 }}
              />
            </div>
            <span className="text-xs text-center" style={{ color: 'var(--subtle)' }}>
              {new Date(trend.date).toLocaleDateString('en-US', { weekday: 'short' })}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TabButton({ active, onClick, icon: Icon, label, count }: {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
  count?: number
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-6 py-4 text-sm font-medium transition-colors border-b-2"
      style={{
        color: active ? 'var(--emerald-400)' : 'var(--muted)',
        borderColor: active ? 'var(--emerald-400)' : 'transparent',
        backgroundColor: active ? 'var(--surface-2)' : 'transparent'
      }}
      onMouseEnter={(e) => {
        if (!active) {
          e.currentTarget.style.color = 'var(--fg)'
          e.currentTarget.style.backgroundColor = 'var(--surface-2)'
        }
      }}
      onMouseLeave={(e) => {
        if (!active) {
          e.currentTarget.style.color = 'var(--muted)'
          e.currentTarget.style.backgroundColor = 'transparent'
        }
      }}
    >
      <Icon className="h-4 w-4" />
      {label}
      {count !== undefined && (
        <span
          className="px-2 py-0.5 rounded-full text-xs"
          style={{
            backgroundColor: active ? 'var(--emerald-glow)' : 'var(--surface-2)',
            color: active ? 'var(--emerald-400)' : 'var(--muted)'
          }}
        >
          {count}
        </span>
      )}
    </button>
  )
}

function ServiceRow({ service }: { service: ExposedService }) {
  const severityStyles: Record<ExposedService['severity'], { bg: string; text: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)' }
  }

  const exposureStyles: Record<ExposedService['exposure'], { bg: string; text: string }> = {
    internet: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    vpn: { bg: 'var(--high-bg)', text: 'var(--high)' },
    internal: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' }
  }

  const sevStyle = severityStyles[service.severity]
  const expStyle = exposureStyles[service.exposure]

  return (
    <tr
      className="transition-colors"
      style={{ borderBottom: '1px solid var(--hairline)' }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = 'transparent'
      }}
    >
      <td className="p-4">
        <span className="font-mono text-sm" style={{ color: 'var(--fg-2)' }}>{service.host}</span>
      </td>
      <td className="p-4">
        <div>
          <p className="text-sm" style={{ color: 'var(--fg)' }}>{service.service}</p>
          {service.version && (
            <p className="text-xs" style={{ color: 'var(--subtle)' }}>{service.version}</p>
          )}
        </div>
      </td>
      <td className="p-4">
        <span className="font-mono text-sm" style={{ color: 'var(--fg-2)' }}>
          {service.port}/{service.protocol}
        </span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-medium capitalize"
          style={{ backgroundColor: expStyle.bg, color: expStyle.text }}
        >
          {service.exposure}
        </span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-medium capitalize"
          style={{ backgroundColor: sevStyle.bg, color: sevStyle.text }}
        >
          {service.severity}
        </span>
      </td>
      <td className="p-4">
        <span
          className="text-sm font-medium"
          style={{ color: service.vulnerabilities > 0 ? 'var(--crit)' : 'var(--emerald-400)' }}
        >
          {service.vulnerabilities}
        </span>
      </td>
      <td className="p-4">
        <div className="flex flex-wrap gap-1 max-w-[200px]">
          {service.findings.slice(0, 2).map((finding, idx) => (
            <span
              key={idx}
              className="px-2 py-0.5 rounded text-xs truncate max-w-[150px]"
              style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
            >
              {finding}
            </span>
          ))}
          {service.findings.length > 2 && (
            <span
              className="px-2 py-0.5 rounded text-xs"
              style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
            >
              +{service.findings.length - 2}
            </span>
          )}
        </div>
      </td>
    </tr>
  )
}

function VulnerabilityRow({ vulnerability }: { vulnerability: VulnerabilityItem }) {
  const getCvssStyle = (cvss: number) => {
    if (cvss >= 9) return { bg: 'var(--crit-bg)', text: 'var(--crit)' }
    if (cvss >= 7) return { bg: 'var(--high-bg)', text: 'var(--high)' }
    if (cvss >= 4) return { bg: 'var(--med-bg)', text: 'var(--med)' }
    return { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' }
  }

  const cvssStyle = getCvssStyle(vulnerability.cvss)

  return (
    <tr
      className="transition-colors"
      style={{ borderBottom: '1px solid var(--hairline)' }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = 'transparent'
      }}
    >
      <td className="p-4">
        <a
          href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cve}`}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-sm flex items-center gap-1 transition-colors"
          style={{ color: 'var(--emerald-400)' }}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--emerald-200)' }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--emerald-400)' }}
        >
          {vulnerability.cve}
          <ExternalLink className="h-3 w-3" />
        </a>
      </td>
      <td className="p-4">
        <span className="text-sm" style={{ color: 'var(--fg)' }}>{vulnerability.title}</span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-bold"
          style={{ backgroundColor: cvssStyle.bg, color: cvssStyle.text }}
        >
          {vulnerability.cvss.toFixed(1)}
        </span>
      </td>
      <td className="p-4">
        <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{vulnerability.affectedAssets}</span>
      </td>
      <td className="p-4">
        {vulnerability.exploitable ? (
          <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--crit)' }}>
            <Unlock className="h-4 w-4" />
            Yes
          </span>
        ) : (
          <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--emerald-400)' }}>
            <Lock className="h-4 w-4" />
            No
          </span>
        )}
      </td>
      <td className="p-4">
        {vulnerability.patchAvailable ? (
          <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--emerald-400)' }}>
            <CheckCircle className="h-4 w-4" />
            Available
          </span>
        ) : (
          <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--high)' }}>
            <AlertTriangle className="h-4 w-4" />
            Pending
          </span>
        )}
      </td>
      <td className="p-4">
        <span className="text-xs max-w-[200px] truncate block" style={{ color: 'var(--muted)' }}>
          {vulnerability.recommendation}
        </span>
      </td>
    </tr>
  )
}

function RecommendationCard({ recommendation }: { recommendation: Recommendation }) {
  const priorityStyles: Record<Recommendation['priority'], { border: string; bg: string; text: string }> = {
    urgent: { border: 'var(--crit)', bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { border: 'var(--high)', bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { border: 'var(--med)', bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { border: 'var(--low)', bg: 'var(--low-bg)', text: 'var(--low)' }
  }

  const statusStyles: Record<Recommendation['status'], { bg: string; text: string }> = {
    open: { bg: 'var(--surface-2)', text: 'var(--muted)' },
    in_progress: { bg: 'var(--high-bg)', text: 'var(--high)' },
    completed: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' }
  }

  const effortLabels: Record<Recommendation['effort'], string> = {
    minimal: 'Quick Fix',
    moderate: 'Moderate Effort',
    significant: 'Major Project'
  }

  const pStyle = priorityStyles[recommendation.priority]
  const sStyle = statusStyles[recommendation.status]

  return (
    <div
      className="rounded-lg p-4"
      style={{
        borderLeft: `4px solid ${pStyle.border}`,
        backgroundColor: pStyle.bg
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{recommendation.title}</h3>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{recommendation.description}</p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="px-2 py-1 rounded text-xs font-medium capitalize"
            style={{ backgroundColor: sStyle.bg, color: sStyle.text }}
          >
            {recommendation.status.replace('_', ' ')}
          </span>
          <span
            className="px-2 py-1 rounded text-xs font-medium uppercase"
            style={{ backgroundColor: pStyle.bg, color: pStyle.text }}
          >
            {recommendation.priority}
          </span>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4 text-sm">
        <div>
          <p style={{ color: 'var(--subtle)' }} className="mb-1">Impact</p>
          <p style={{ color: 'var(--fg-2)' }}>{recommendation.impact}</p>
        </div>
        <div>
          <p style={{ color: 'var(--subtle)' }} className="mb-1">Effort</p>
          <p style={{ color: 'var(--fg-2)' }}>{effortLabels[recommendation.effort]}</p>
        </div>
        <div>
          <p style={{ color: 'var(--subtle)' }} className="mb-1">Affected Assets</p>
          <p style={{ color: 'var(--fg-2)' }}>{recommendation.affectedAssets}</p>
        </div>
      </div>
    </div>
  )
}

function CrownJewelCard({ jewel }: { jewel: CrownJewel }) {
  const criticalityStyles: Record<CrownJewel['criticality'], { bg: string; border: string; text: string }> = {
    critical: { bg: 'var(--crit-bg)', border: 'var(--crit)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', border: 'var(--high)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', border: 'var(--med)', text: 'var(--med)' },
    low: { bg: 'var(--low-bg)', border: 'var(--low)', text: 'var(--low)' }
  }

  const protectionStyles: Record<CrownJewel['protectionStatus'], { bg: string; text: string }> = {
    protected: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    partial: { bg: 'var(--high-bg)', text: 'var(--high)' },
    unprotected: { bg: 'var(--crit-bg)', text: 'var(--crit)' }
  }

  const cStyle = criticalityStyles[jewel.criticality]
  const pStyle = protectionStyles[jewel.protectionStatus]

  return (
    <div
      className="p-4 rounded-lg"
      style={{
        backgroundColor: cStyle.bg,
        border: `1px solid ${cStyle.border}`,
        borderLeftWidth: '3px'
      }}
    >
      <div className="flex items-start justify-between mb-2">
        <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{jewel.name}</h3>
        <span
          className="text-xs px-2 py-0.5 rounded capitalize"
          style={{ backgroundColor: pStyle.bg, color: pStyle.text }}
        >
          {jewel.protectionStatus}
        </span>
      </div>
      <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{jewel.type}</p>
      <div className="flex items-center justify-between text-xs" style={{ color: 'var(--subtle)' }}>
        <span className="capitalize" style={{ color: cStyle.text }}>
          {jewel.criticality} criticality
        </span>
        <span>Assessed: {new Date(jewel.lastAssessed).toLocaleDateString()}</span>
      </div>
    </div>
  )
}

function AttackSurfaceAssetRow({ asset }: { asset: AttackSurfaceAsset }) {
  const typeStyles: Record<AttackSurfaceAsset['type'], { bg: string; text: string }> = {
    service: { bg: 'var(--med-bg)', text: 'var(--med)' },
    endpoint: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    cloud: { bg: 'var(--high-bg)', text: 'var(--high)' },
    external: { bg: 'var(--crit-bg)', text: 'var(--crit)' }
  }

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'var(--crit)'
    if (score >= 50) return 'var(--high)'
    if (score >= 25) return 'var(--med)'
    return 'var(--emerald-400)'
  }

  const tStyle = typeStyles[asset.type]

  return (
    <div
      className="flex items-center justify-between p-3 rounded-lg transition-colors"
      style={{ backgroundColor: 'var(--surface-2)' }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = 'var(--surface-3)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
      }}
    >
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: tStyle.bg }}>
          <Server className="h-4 w-4" style={{ color: tStyle.text }} />
        </div>
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{asset.name}</p>
          <p className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{asset.type}</p>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-right">
          <p className="text-sm font-medium" style={{ color: getRiskColor(asset.riskScore) }}>
            Risk: {asset.riskScore}
          </p>
          <p className="text-xs" style={{ color: 'var(--subtle)' }}>{asset.exposures} exposures</p>
        </div>
      </div>
    </div>
  )
}
