import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Globe,
  Shield,
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  Plus,
  Trash2,
  Eye,
  Server,
  Lock,
  Unlock,
  ExternalLink,
  TrendingUp,
  TrendingDown,
  Minus,
  Activity,
  Target,
  Radar,
  Cloud,
  Network,
  CheckCircle,
  XCircle,
  Clock,
  ChevronRight,
  BarChart3,
  PieChart,
  AlertCircle,
  FileText,
  Settings,
  Play,
  Download
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useEffect } from 'react'
import { logger } from '@/lib/logger'
import { Checkbox, Dialog } from '@/components/ui/baseui'

// Types
interface Asset {
  id: string
  type: 'subdomain' | 'ip' | 'cloud' | 'external'
  value: string
  domain?: string
  ip_addresses: string[]
  ports: number[]
  services: string[]
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'minimal'
  risk_score: number
  first_seen: string
  last_seen: string
  status: 'active' | 'inactive' | 'removed'
  exposures: Exposure[]
  vulnerabilities: Vulnerability[]
}

interface Exposure {
  id: string
  type: 'open_port' | 'tls_issue' | 'missing_header' | 'certificate' | 'outdated_software'
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  port?: number
  service?: string
  remediation: string
}

interface Vulnerability {
  cve_id: string
  title: string
  cvss_score: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  epss_score?: number
  in_kev?: boolean
}

interface MonitoredDomain {
  domain: string
  added_at: string
  last_scan?: string
  auto_discover: boolean
  notify_changes: boolean
  status: 'active' | 'pending' | 'error'
  asset_count?: number
}

interface Change {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title?: string
  asset_id?: string
  detected_at: string
  diff?: Record<string, unknown>
}

interface RiskMetrics {
  total_assets: number
  average_risk_score: number
  total_critical: number
  total_high: number
  total_medium: number
  total_low: number
  trend_summary: {
    increasing: number
    stable: number
    decreasing: number
  }
}

interface ExposureMetrics {
  total_assets_analyzed: number
  total_exposures: number
  exposures_by_severity: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

interface DashboardData {
  summary: {
    total_assets: number
    domains_monitored: number
    total_exposures: number
    average_risk_score: number
    critical_assets: number
    high_risk_assets: number
    changes_this_week: number
  }
  assets_by_type: Record<string, number>
  exposures_by_severity: Record<string, number>
  top_risks: Asset[]
  recent_changes: Change[]
}

interface AttackSurfacePageProps {
  dashboard?: DashboardData
  assets?: Asset[]
  domains?: MonitoredDomain[]
  riskMetrics?: RiskMetrics
  exposureMetrics?: ExposureMetrics
}

const defaultDashboard: DashboardData = {
  summary: {
    total_assets: 0,
    domains_monitored: 0,
    total_exposures: 0,
    average_risk_score: 0,
    critical_assets: 0,
    high_risk_assets: 0,
    changes_this_week: 0
  },
  assets_by_type: {},
  exposures_by_severity: {},
  top_risks: [],
  recent_changes: []
}

export default function AttackSurface({
  dashboard = defaultDashboard,
  assets = [],
  domains = [],
  riskMetrics,
  exposureMetrics
}: AttackSurfacePageProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'assets' | 'domains' | 'exposures' | 'changes'>('overview')
  const [searchQuery, setSearchQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [loading, setLoading] = useState(false)
  const [showAddDomain, setShowAddDomain] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)

  const filteredAssets = assets.filter(asset => {
    if (riskFilter !== 'all' && asset.risk_level !== riskFilter) return false
    if (typeFilter !== 'all' && asset.type !== typeFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        asset.value.toLowerCase().includes(query) ||
        asset.ip_addresses.some(ip => ip.includes(query))
      )
    }
    return true
  })

  const handleRefresh = async () => {
    setLoading(true)
    // In production, this would call the API to refresh data
    setTimeout(() => setLoading(false), 1500)
  }

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return
    // In production, this would call the API
    logger.log('Adding domain:', newDomain)
    setNewDomain('')
    setShowAddDomain(false)
  }

  const handleStartDiscovery = async (domain: string) => {
    // In production, this would call the API to start discovery
    logger.log('Starting discovery for:', domain)
  }

  return (
    <MainLayout title="Attack Surface Management">
      <Head title="Attack Surface - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
          <StatCard
            icon={Globe}
            label="Total Assets"
            value={dashboard.summary.total_assets}
            color="primary"
          />
          <StatCard
            icon={Radar}
            label="Domains Monitored"
            value={dashboard.summary.domains_monitored}
            color="blue"
          />
          <StatCard
            icon={AlertTriangle}
            label="Exposures"
            value={dashboard.summary.total_exposures}
            color="yellow"
          />
          <StatCard
            icon={AlertCircle}
            label="Critical Assets"
            value={dashboard.summary.critical_assets}
            color="red"
          />
          <StatCard
            icon={Shield}
            label="High Risk"
            value={dashboard.summary.high_risk_assets}
            color="orange"
          />
          <RiskScoreCard
            score={dashboard.summary.average_risk_score}
            label="Avg Risk Score"
          />
          <StatCard
            icon={Activity}
            label="Changes (7d)"
            value={dashboard.summary.changes_this_week}
            color="purple"
          />
        </div>

        {/* Main Content */}
        <div className="card-sentinel">
          {/* Tabs */}
          <div className="flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex">
              <TabButton
                active={activeTab === 'overview'}
                onClick={() => setActiveTab('overview')}
                icon={BarChart3}
                label="Overview"
              />
              <TabButton
                active={activeTab === 'assets'}
                onClick={() => setActiveTab('assets')}
                icon={Server}
                label="Assets"
                count={assets.length}
              />
              <TabButton
                active={activeTab === 'domains'}
                onClick={() => setActiveTab('domains')}
                icon={Globe}
                label="Domains"
                count={domains.length}
              />
              <TabButton
                active={activeTab === 'exposures'}
                onClick={() => setActiveTab('exposures')}
                icon={Shield}
                label="Exposures"
              />
              <TabButton
                active={activeTab === 'changes'}
                onClick={() => setActiveTab('changes')}
                icon={Activity}
                label="Changes"
              />
            </div>
            <div className="flex items-center gap-2 pr-4">
              <button
                onClick={handleRefresh}
                disabled={loading}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
              >
                <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
                Refresh
              </button>
              {activeTab === 'domains' && (
                <button
                  onClick={() => setShowAddDomain(true)}
                  className="btn-sentinel btn-sentinel-primary btn-sentinel-sm"
                >
                  <Plus className="h-4 w-4" />
                  Add Domain
                </button>
              )}
            </div>
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution */}
                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Risk Distribution</h3>
                  <RiskDistributionChart
                    critical={riskMetrics?.total_critical || 0}
                    high={riskMetrics?.total_high || 0}
                    medium={riskMetrics?.total_medium || 0}
                    low={riskMetrics?.total_low || 0}
                  />
                </div>

                {/* Exposure Summary */}
                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Exposures by Severity</h3>
                  <ExposureChart exposures={exposureMetrics?.exposures_by_severity || {}} />
                </div>

                {/* Asset Types */}
                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Assets by Type</h3>
                  <AssetTypeChart types={dashboard.assets_by_type} />
                </div>

                {/* Trend Summary */}
                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Risk Trends</h3>
                  <TrendSummary trends={riskMetrics?.trend_summary || { increasing: 0, stable: 0, decreasing: 0 }} />
                </div>
              </div>

              {/* Top Risks and Recent Changes */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Top Risk Assets</h3>
                  <div className="space-y-3">
                    {dashboard.top_risks.length === 0 ? (
                      <p className="text-sm text-center py-4" style={{ color: 'var(--muted)' }}>No high-risk assets detected</p>
                    ) : (
                      dashboard.top_risks.map((asset) => (
                        <TopRiskItem key={asset.id} asset={asset} onClick={() => setSelectedAsset(asset)} />
                      ))
                    )}
                  </div>
                </div>

                <div className="card-sentinel-inset p-4">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Recent Changes</h3>
                  <div className="space-y-3">
                    {dashboard.recent_changes.length === 0 ? (
                      <p className="text-sm text-center py-4" style={{ color: 'var(--muted)' }}>No recent changes</p>
                    ) : (
                      dashboard.recent_changes.map((change) => (
                        <ChangeItem key={change.id} change={change} />
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Assets Tab */}
          {activeTab === 'assets' && (
            <div>
              {/* Filters */}
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex items-center gap-4">
                  <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search assets by domain, IP..."
                      className="input-sentinel pl-10"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                    <select
                      value={riskFilter}
                      onChange={(e) => setRiskFilter(e.target.value)}
                      className="input-sentinel"
                      style={{ width: 'auto' }}
                    >
                      <option value="all">All Risk Levels</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                    <select
                      value={typeFilter}
                      onChange={(e) => setTypeFilter(e.target.value)}
                      className="input-sentinel"
                      style={{ width: 'auto' }}
                    >
                      <option value="all">All Types</option>
                      <option value="subdomain">Subdomains</option>
                      <option value="ip">IP Addresses</option>
                      <option value="cloud">Cloud Resources</option>
                      <option value="external">External</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Assets Table */}
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Asset</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>IP Addresses</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Open Ports</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Exposures</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Last Seen</th>
                      <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                          <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No assets found</p>
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((asset) => (
                        <AssetRow key={asset.id} asset={asset} onSelect={() => setSelectedAsset(asset)} />
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Domains Tab */}
          {activeTab === 'domains' && (
            <div className="p-6">
              {domains.length === 0 ? (
                <div className="text-center py-12">
                  <Globe className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                  <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Domains Monitored</h3>
                  <p className="mb-4" style={{ color: 'var(--muted)' }}>Add a domain to start discovering your attack surface</p>
                  <button
                    onClick={() => setShowAddDomain(true)}
                    className="btn-sentinel btn-sentinel-primary"
                  >
                    <Plus className="h-4 w-4" />
                    Add Domain
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {domains.map((domain) => (
                    <DomainCard
                      key={domain.domain}
                      domain={domain}
                      onStartDiscovery={() => handleStartDiscovery(domain.domain)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Exposures Tab */}
          {activeTab === 'exposures' && (
            <div className="p-6">
              <ExposuresList assets={assets} />
            </div>
          )}

          {/* Changes Tab */}
          {activeTab === 'changes' && (
            <div className="p-6">
              <ChangesList changes={dashboard.recent_changes} />
            </div>
          )}
        </div>

        {/* Add Domain Modal */}
        <Dialog open={showAddDomain} onOpenChange={setShowAddDomain} title="Add Domain to Monitor">
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="example.com"
            className="input-sentinel mb-4"
          />
          <div className="flex items-center gap-3">
            <Checkbox defaultChecked label="Auto-discover subdomains" />
          </div>
          <div className="flex items-center gap-3 mt-2">
            <Checkbox defaultChecked label="Notify on changes" />
          </div>
          <div className="flex justify-end gap-3 mt-6">
            <button
              onClick={() => setShowAddDomain(false)}
              className="btn-sentinel btn-sentinel-ghost"
            >
              Cancel
            </button>
            <button
              onClick={handleAddDomain}
              className="btn-sentinel btn-sentinel-primary"
            >
              Add Domain
            </button>
          </div>
        </Dialog>

        {/* Asset Detail Modal */}
        {selectedAsset && (
          <AssetDetailModal asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
        )}
      </div>
    </MainLayout>
  )
}

// Components

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType
  label: string
  value: number
  color: 'primary' | 'blue' | 'green' | 'red' | 'yellow' | 'orange' | 'purple'
}) {
  const colorStyles: Record<string, { bg: string; text: string }> = {
    primary: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    blue: { bg: 'var(--med-bg)', text: 'var(--med)' },
    green: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    red: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    yellow: { bg: 'var(--high-bg)', text: 'var(--high)' },
    orange: { bg: 'var(--high-bg)', text: 'var(--high)' },
    purple: { bg: 'rgba(217, 70, 239, 0.12)', text: 'var(--sol-magenta)' }
  }

  const style = colorStyles[color]

  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: style.bg }}>
          <Icon className="h-5 w-5" style={{ color: style.text }} />
        </div>
        <div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
        </div>
      </div>
    </div>
  )
}

function RiskScoreCard({ score, label }: { score: number; label: string }) {
  const getScoreColor = () => {
    if (score >= 80) return 'var(--crit)'
    if (score >= 60) return 'var(--high)'
    if (score >= 40) return 'var(--med)'
    return 'var(--emerald-400)'
  }

  const getBarColor = () => {
    if (score >= 80) return 'var(--crit)'
    if (score >= 60) return 'var(--high)'
    if (score >= 40) return 'var(--med)'
    return 'var(--emerald-400)'
  }

  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
          <Target className="h-5 w-5" style={{ color: 'var(--muted)' }} />
        </div>
        <div>
          <p className="text-2xl font-bold" style={{ color: getScoreColor() }}>{score}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
        </div>
      </div>
      <div className="mt-2 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${score}%`, backgroundColor: getBarColor() }}
        />
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
      className="flex items-center gap-2 px-6 py-4 text-sm font-medium transition-colors"
      style={{
        color: active ? 'var(--emerald-400)' : 'var(--muted)',
        borderBottom: active ? '2px solid var(--emerald-400)' : '2px solid transparent',
        backgroundColor: active ? 'var(--surface-2)' : 'transparent'
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

function RiskDistributionChart({ critical, high, medium, low }: {
  critical: number
  high: number
  medium: number
  low: number
}) {
  const total = critical + high + medium + low || 1
  const data = [
    { label: 'Critical', value: critical, color: 'var(--crit)', textColor: 'var(--crit)' },
    { label: 'High', value: high, color: 'var(--high)', textColor: 'var(--high)' },
    { label: 'Medium', value: medium, color: 'var(--med)', textColor: 'var(--med)' },
    { label: 'Low', value: low, color: 'var(--emerald-400)', textColor: 'var(--emerald-400)' }
  ]

  return (
    <div className="space-y-3">
      {data.map((item) => (
        <div key={item.label}>
          <div className="flex items-center justify-between text-sm mb-1">
            <span style={{ color: item.textColor }}>{item.label}</span>
            <span style={{ color: 'var(--muted)' }}>{item.value} ({Math.round(item.value / total * 100)}%)</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
            <div
              className="h-full rounded-full"
              style={{ width: `${(item.value / total) * 100}%`, backgroundColor: item.color }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

function ExposureChart({ exposures }: { exposures: Record<string, number> }) {
  const data = [
    { label: 'Critical', value: exposures.critical || 0, color: 'var(--crit)' },
    { label: 'High', value: exposures.high || 0, color: 'var(--high)' },
    { label: 'Medium', value: exposures.medium || 0, color: 'var(--med)' },
    { label: 'Low', value: exposures.low || 0, color: 'var(--low)' }
  ]
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-32 h-32">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
          {data.reduce((acc, item, index) => {
            const prevOffset = acc.offset
            const percentage = (item.value / total) * 100
            acc.elements.push(
              <circle
                key={item.label}
                cx="18"
                cy="18"
                r="15.9"
                fill="none"
                strokeWidth="3"
                stroke={item.color}
                strokeDasharray={`${percentage} ${100 - percentage}`}
                strokeDashoffset={-prevOffset}
              />
            )
            acc.offset += percentage
            return acc
          }, { elements: [] as JSX.Element[], offset: 0 }).elements}
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{total}</span>
        </div>
      </div>
      <div className="space-y-2">
        {data.map((item) => (
          <div key={item.label} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded" style={{ backgroundColor: item.color }} />
            <span className="text-sm" style={{ color: 'var(--muted)' }}>{item.label}: {item.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function AssetTypeChart({ types }: { types: Record<string, number> }) {
  const typeLabels: Record<string, string> = {
    subdomain: 'Subdomains',
    ip: 'IP Addresses',
    cloud: 'Cloud Resources',
    external: 'External Assets'
  }

  const typeColors: Record<string, string> = {
    subdomain: 'var(--med)',
    ip: 'var(--emerald-400)',
    cloud: 'var(--sol-magenta)',
    external: 'var(--high)'
  }

  const total = Object.values(types).reduce((sum, v) => sum + v, 0) || 1

  return (
    <div className="grid grid-cols-2 gap-4">
      {Object.entries(types).map(([type, count]) => (
        <div key={type} className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-2 rounded" style={{ backgroundColor: typeColors[type] || 'var(--subtle)' }} />
            <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{typeLabels[type] || type}</span>
          </div>
          <p className="text-xl font-bold" style={{ color: 'var(--fg)' }}>{count}</p>
          <p className="text-xs" style={{ color: 'var(--subtle)' }}>{Math.round(count / total * 100)}% of total</p>
        </div>
      ))}
    </div>
  )
}

function TrendSummary({ trends }: { trends: { increasing: number; stable: number; decreasing: number } }) {
  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="text-center p-4 rounded-lg" style={{ backgroundColor: 'var(--crit-bg)', border: '1px solid rgba(240, 80, 110, 0.3)' }}>
        <TrendingUp className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--crit)' }} />
        <p className="text-2xl font-bold" style={{ color: 'var(--crit)' }}>{trends.increasing}</p>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>Increasing Risk</p>
      </div>
      <div className="text-center p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
        <Minus className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--muted)' }} />
        <p className="text-2xl font-bold" style={{ color: 'var(--fg-2)' }}>{trends.stable}</p>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>Stable</p>
      </div>
      <div className="text-center p-4 rounded-lg" style={{ backgroundColor: 'var(--emerald-glow)', border: '1px solid rgba(47, 196, 113, 0.3)' }}>
        <TrendingDown className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--emerald-400)' }} />
        <p className="text-2xl font-bold" style={{ color: 'var(--emerald-400)' }}>{trends.decreasing}</p>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>Decreasing Risk</p>
      </div>
    </div>
  )
}

function TopRiskItem({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const riskStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)', border: 'rgba(240, 80, 110, 0.5)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)', border: 'rgba(245, 165, 36, 0.5)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)', border: 'rgba(91, 156, 242, 0.5)' },
    low: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)', border: 'rgba(47, 196, 113, 0.5)' },
    minimal: { bg: 'var(--surface-2)', text: 'var(--muted)', border: 'var(--border)' }
  }

  const style = riskStyles[asset.risk_level]

  return (
    <button
      onClick={onClick}
      className="w-full flex items-center justify-between p-3 rounded-lg transition-colors text-left"
      style={{ backgroundColor: 'var(--surface-2)' }}
      onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'var(--surface-3)'}
      onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'var(--surface-2)'}
    >
      <div className="flex items-center gap-3">
        <div
          className="px-2 py-1 rounded text-xs font-medium"
          style={{ backgroundColor: style.bg, color: style.text, border: `1px solid ${style.border}` }}
        >
          {asset.risk_score}
        </div>
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{asset.value}</p>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{asset.exposures.length} exposures</p>
        </div>
      </div>
      <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
    </button>
  )
}

function ChangeItem({ change }: { change: Change }) {
  const severityColors: Record<string, string> = {
    critical: 'var(--crit)',
    high: 'var(--high)',
    medium: 'var(--med)',
    low: 'var(--low)',
    info: 'var(--muted)'
  }

  const typeIcons: Record<string, React.ElementType> = {
    asset_discovered: Plus,
    risk_threshold_crossed: AlertTriangle,
    vulnerability_found: Shield,
    port_opened: Network,
    certificate_expired: Lock
  }

  const Icon = typeIcons[change.type] || Activity

  return (
    <div className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
      <div className="p-1.5 rounded" style={{ color: severityColors[change.severity] }}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm truncate" style={{ color: 'var(--fg)' }}>{change.title || change.type.replace(/_/g, ' ')}</p>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          {new Date(change.detected_at).toLocaleString()}
        </p>
      </div>
    </div>
  )
}

function AssetRow({ asset, onSelect }: { asset: Asset; onSelect: () => void }) {
  const riskStyles: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    minimal: { bg: 'var(--surface-2)', text: 'var(--muted)' }
  }

  const typeIcons = {
    subdomain: Globe,
    ip: Network,
    cloud: Cloud,
    external: ExternalLink
  }

  const TypeIcon = typeIcons[asset.type] || Server
  const style = riskStyles[asset.risk_level]

  return (
    <tr style={{ borderBottom: '1px solid var(--hairline)' }} className="hover:bg-[var(--surface-2)]">
      <td className="p-4">
        <div className="flex items-center gap-3">
          <TypeIcon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          <span className="font-mono text-sm" style={{ color: 'var(--fg-2)' }}>{asset.value}</span>
        </div>
      </td>
      <td className="p-4">
        <span className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{asset.type}</span>
      </td>
      <td className="p-4">
        <div className="flex flex-wrap gap-1 max-w-[150px]">
          {asset.ip_addresses.slice(0, 2).map((ip, idx) => (
            <span
              key={idx}
              className="font-mono text-xs px-1.5 py-0.5 rounded"
              style={{ color: 'var(--muted)', backgroundColor: 'var(--surface-2)' }}
            >
              {ip}
            </span>
          ))}
          {asset.ip_addresses.length > 2 && (
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>+{asset.ip_addresses.length - 2}</span>
          )}
        </div>
      </td>
      <td className="p-4">
        <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{asset.ports.length}</span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-medium capitalize"
          style={{ backgroundColor: style.bg, color: style.text }}
        >
          {asset.risk_level} ({asset.risk_score})
        </span>
      </td>
      <td className="p-4">
        <span className="text-sm" style={{ color: asset.exposures.length > 0 ? 'var(--high)' : 'var(--emerald-400)' }}>
          {asset.exposures.length}
        </span>
      </td>
      <td className="p-4">
        <span className="text-xs" style={{ color: 'var(--muted)' }}>
          {new Date(asset.last_seen).toLocaleDateString()}
        </span>
      </td>
      <td className="p-4">
        <button
          onClick={onSelect}
          className="p-1.5 rounded transition-colors"
          style={{ color: 'var(--muted)' }}
          onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-3)'; e.currentTarget.style.color = 'var(--fg)' }}
          onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--muted)' }}
        >
          <Eye className="h-4 w-4" />
        </button>
      </td>
    </tr>
  )
}

function DomainCard({ domain, onStartDiscovery }: { domain: MonitoredDomain; onStartDiscovery: () => void }) {
  const statusStyles: Record<string, { bg: string; text: string }> = {
    active: { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' },
    pending: { bg: 'var(--high-bg)', text: 'var(--high)' },
    error: { bg: 'var(--crit-bg)', text: 'var(--crit)' }
  }

  const style = statusStyles[domain.status]

  return (
    <div className="card-sentinel-inset p-4" style={{ border: '1px solid var(--border)' }}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          <h4 className="font-semibold" style={{ color: 'var(--fg)' }}>{domain.domain}</h4>
        </div>
        <span
          className="px-2 py-0.5 rounded text-xs capitalize"
          style={{ backgroundColor: style.bg, color: style.text }}
        >
          {domain.status}
        </span>
      </div>
      <div className="space-y-2 text-sm" style={{ color: 'var(--muted)' }}>
        <div className="flex items-center justify-between">
          <span>Added</span>
          <span>{new Date(domain.added_at).toLocaleDateString()}</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Last Scan</span>
          <span>{domain.last_scan ? new Date(domain.last_scan).toLocaleDateString() : 'Never'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Assets</span>
          <span>{domain.asset_count || 0}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 mt-4">
        <button
          onClick={onStartDiscovery}
          className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm flex-1"
        >
          <Play className="h-4 w-4" />
          Scan
        </button>
        <button
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
        >
          <Settings className="h-4 w-4" />
        </button>
        <button
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
          style={{ color: 'var(--crit)' }}
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

function ExposuresList({ assets }: { assets: Asset[] }) {
  const allExposures = assets.flatMap(asset =>
    asset.exposures.map(exp => ({ ...exp, asset_value: asset.value, asset_id: asset.id }))
  )

  const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)', border: 'rgba(240, 80, 110, 0.5)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)', border: 'rgba(245, 165, 36, 0.5)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)', border: 'rgba(91, 156, 242, 0.5)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)', border: 'rgba(122, 138, 146, 0.5)' }
  }

  if (allExposures.length === 0) {
    return (
      <div className="text-center py-12">
        <Shield className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--emerald-400)', opacity: 0.5 }} />
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Exposures Detected</h3>
        <p style={{ color: 'var(--muted)' }}>Your attack surface appears to be well-configured</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {allExposures.map((exposure, idx) => {
        const style = severityStyles[exposure.severity]
        return (
          <div
            key={`${exposure.id}-${idx}`}
            className="p-4 rounded-lg"
            style={{ backgroundColor: style.bg, borderLeft: `4px solid ${style.text}` }}
          >
            <div className="flex items-start justify-between mb-2">
              <div>
                <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{exposure.title}</h4>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>{exposure.asset_value}</p>
              </div>
              <span
                className="px-2 py-1 rounded text-xs font-medium capitalize"
                style={{ backgroundColor: style.bg, color: style.text, border: `1px solid ${style.border}` }}
              >
                {exposure.severity}
              </span>
            </div>
            <p className="text-sm mb-3" style={{ color: 'var(--muted)' }}>{exposure.description}</p>
            <div className="rounded p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-xs mb-1" style={{ color: 'var(--subtle)' }}>Remediation</p>
              <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{exposure.remediation}</p>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function ChangesList({ changes }: { changes: Change[] }) {
  if (changes.length === 0) {
    return (
      <div className="text-center py-12">
        <Activity className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Recent Changes</h3>
        <p style={{ color: 'var(--muted)' }}>Your attack surface has been stable</p>
      </div>
    )
  }

  const severityStyles: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)' },
    info: { bg: 'var(--surface-2)', text: 'var(--muted)' }
  }

  return (
    <div className="space-y-3">
      {changes.map((change) => {
        const style = severityStyles[change.severity]
        return (
          <div
            key={change.id}
            className="flex items-start gap-4 p-4 rounded-lg"
            style={{ backgroundColor: 'var(--surface-2)' }}
          >
            <div className="p-2 rounded-lg" style={{ backgroundColor: style.bg }}>
              <Activity className="h-5 w-5" style={{ color: style.text }} />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{change.title || change.type.replace(/_/g, ' ')}</h4>
                <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                  {new Date(change.detected_at).toLocaleString()}
                </span>
              </div>
              <p className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{change.type.replace(/_/g, ' ')}</p>
              {change.asset_id && (
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Asset: {change.asset_id}</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function AssetDetailModal({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const riskColors: Record<string, string> = {
    critical: 'var(--crit)',
    high: 'var(--high)',
    medium: 'var(--med)',
    low: 'var(--emerald-400)',
    minimal: 'var(--muted)'
  }

  const severityStyles: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'var(--crit-bg)', text: 'var(--crit)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--med-bg)', text: 'var(--med)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)' }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}>
      <div className="card-sentinel-elevated w-full max-w-3xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>{asset.value}</h2>
            <p className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{asset.type}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg transition-colors"
            style={{ color: 'var(--muted)' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface-2)'; e.currentTarget.style.color = 'var(--fg)' }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--muted)' }}
          >
            <XCircle className="h-5 w-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          {/* Risk Score */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-3xl font-bold" style={{ color: riskColors[asset.risk_level] }}>{asset.risk_score}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Risk Score</p>
            </div>
            <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{asset.ports.length}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Open Ports</p>
            </div>
            <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-3xl font-bold" style={{ color: 'var(--high)' }}>{asset.exposures.length}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Exposures</p>
            </div>
            <div className="rounded-lg p-4 text-center" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-3xl font-bold" style={{ color: 'var(--crit)' }}>{asset.vulnerabilities.length}</p>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Vulnerabilities</p>
            </div>
          </div>

          {/* IP Addresses */}
          {asset.ip_addresses.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>IP Addresses</h3>
              <div className="flex flex-wrap gap-2">
                {asset.ip_addresses.map((ip, idx) => (
                  <span
                    key={idx}
                    className="font-mono text-sm px-3 py-1 rounded"
                    style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                  >
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Exposures */}
          {asset.exposures.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Exposures</h3>
              <div className="space-y-2">
                {asset.exposures.map((exp, idx) => {
                  const style = severityStyles[exp.severity]
                  return (
                    <div key={idx} className="rounded p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm" style={{ color: 'var(--fg)' }}>{exp.title}</span>
                        <span
                          className="px-2 py-0.5 rounded text-xs capitalize"
                          style={{ backgroundColor: style.bg, color: style.text }}
                        >
                          {exp.severity}
                        </span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>{exp.description}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {asset.vulnerabilities.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>Vulnerabilities</h3>
              <div className="space-y-2">
                {asset.vulnerabilities.map((vuln, idx) => {
                  const cvssStyle = vuln.cvss_score >= 9
                    ? { bg: 'var(--crit-bg)', text: 'var(--crit)' }
                    : vuln.cvss_score >= 7
                    ? { bg: 'var(--high-bg)', text: 'var(--high)' }
                    : vuln.cvss_score >= 4
                    ? { bg: 'var(--med-bg)', text: 'var(--med)' }
                    : { bg: 'var(--emerald-glow)', text: 'var(--emerald-400)' }

                  return (
                    <div key={idx} className="rounded p-3" style={{ backgroundColor: 'var(--surface-2)' }}>
                      <div className="flex items-center justify-between mb-1">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm flex items-center gap-1 hover:underline"
                          style={{ color: 'var(--emerald-400)' }}
                        >
                          {vuln.cve_id}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        <div className="flex items-center gap-2">
                          {vuln.in_kev && (
                            <span
                              className="px-2 py-0.5 rounded text-xs"
                              style={{ backgroundColor: 'var(--crit-bg)', color: 'var(--crit)' }}
                            >
                              KEV
                            </span>
                          )}
                          <span
                            className="px-2 py-0.5 rounded text-xs font-bold"
                            style={{ backgroundColor: cvssStyle.bg, color: cvssStyle.text }}
                          >
                            CVSS {vuln.cvss_score.toFixed(1)}
                          </span>
                        </div>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>{vuln.title}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p style={{ color: 'var(--subtle)' }}>First Seen</p>
              <p style={{ color: 'var(--fg-2)' }}>{new Date(asset.first_seen).toLocaleString()}</p>
            </div>
            <div>
              <p style={{ color: 'var(--subtle)' }}>Last Seen</p>
              <p style={{ color: 'var(--fg-2)' }}>{new Date(asset.last_seen).toLocaleString()}</p>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 p-6" style={{ borderTop: '1px solid var(--border)' }}>
          <button
            onClick={onClose}
            className="btn-sentinel btn-sentinel-ghost"
          >
            Close
          </button>
          <button className="btn-sentinel btn-sentinel-primary">
            <Download className="h-4 w-4" />
            Export Report
          </button>
        </div>
      </div>
    </div>
  )
}
