import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Server,
  Search,
  Filter,
  RefreshCw,
  Monitor,
  Database,
  Shield,
  AlertTriangle,
  CheckCircle,
  Plus,
  Eye,
  Settings,
  Laptop,
  Network,
  Cloud
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState } from 'react'
import { Select, SelectItem } from '@/components/ui/baseui'

// Types
interface Asset {
  id: string
  hostname: string
  type: 'server' | 'workstation' | 'laptop' | 'network' | 'cloud' | 'database'
  os: string
  ip: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  owner: string
  department: string
  location: string
  discoveryStatus: 'managed' | 'unmanaged' | 'discovered' | 'decommissioned'
  agentStatus: 'installed' | 'not_installed' | 'outdated'
  vulnerabilities: {
    critical: number
    high: number
    medium: number
    low: number
  }
  lastSeen: string
  tags: string[]
}

interface AssetGroup {
  id: string
  name: string
  description: string
  assetCount: number
  color: string
}

interface AssetStats {
  totalAssets: number
  managedAssets: number
  unmanagedAssets: number
  criticalAssets: number
  vulnerableAssets: number
}

interface AssetsPageProps {
  assets?: Array<Partial<Asset> & Record<string, any>>
  groups?: AssetGroup[]
  stats?: Partial<AssetStats> & Record<string, any>
}

export default function Assets({
  assets = [],
  groups = [],
  stats
}: AssetsPageProps) {
  const normalizedAssets = assets.map(normalizeAsset)
  const assetStats = normalizeStats(stats, normalizedAssets)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [criticalityFilter, setCriticalityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [loading, setLoading] = useState(false)

  const filteredAssets = normalizedAssets.filter(asset => {
    if (typeFilter !== 'all' && asset.type !== typeFilter) return false
    if (criticalityFilter !== 'all' && asset.criticality !== criticalityFilter) return false
    if (statusFilter !== 'all' && asset.discoveryStatus !== statusFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        asset.hostname.toLowerCase().includes(query) ||
        asset.ip.toLowerCase().includes(query) ||
        asset.owner.toLowerCase().includes(query)
      )
    }
    return true
  })

  const handleRefresh = () => {
    setLoading(true)
    router.reload({
      only: ['assets', 'groups', 'stats'],
      onFinish: () => setLoading(false),
    })
  }

  return (
    <MainLayout title="Asset Management">
      <Head title="Assets - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <StatCard
            icon={Server}
            label="Total Assets"
            value={assetStats.totalAssets}
            color="primary"
          />
          <StatCard
            icon={CheckCircle}
            label="Managed"
            value={assetStats.managedAssets}
            color="green"
          />
          <StatCard
            icon={AlertTriangle}
            label="Unmanaged"
            value={assetStats.unmanagedAssets}
            color="yellow"
          />
          <StatCard
            icon={Shield}
            label="Critical Assets"
            value={assetStats.criticalAssets}
            color="red"
          />
          <StatCard
            icon={AlertTriangle}
            label="Inventory Matches"
            value={assetStats.vulnerableAssets}
            color="orange"
          />
        </div>

        {/* Asset Groups */}
        <div className="card-sentinel rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Asset Groups</h2>
            <button
              disabled
              title="Asset group creation needs a backend workflow before it can be enabled."
              className="flex items-center gap-2 bg-primary-600/50 rounded-lg px-3 py-1.5 text-sm text-white cursor-not-allowed"
            >
              <Plus className="h-4 w-4" />
              New Group
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {groups.length === 0 ? (
              <div className="md:col-span-5 rounded-lg border border-dashed p-6 text-center" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
                Asset groups will appear after assets are tagged or assigned to groups.
              </div>
            ) : (
              groups.map((group) => (
                <GroupCard key={group.id} group={group} />
              ))
            )}
          </div>
        </div>

        {/* Filters & Search */}
        <div className="card-sentinel rounded-xl p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by hostname, IP, or owner..."
                className="w-full rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border)',
                  color: 'var(--fg)'
                }}
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
              <Select
                value={typeFilter}
                onValueChange={setTypeFilter}
                placeholder="All Types"
                className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="server">Server</SelectItem>
                <SelectItem value="workstation">Workstation</SelectItem>
                <SelectItem value="laptop">Laptop</SelectItem>
                <SelectItem value="network">Network</SelectItem>
                <SelectItem value="cloud">Cloud</SelectItem>
                <SelectItem value="database">Database</SelectItem>
              </Select>
              <Select
                value={criticalityFilter}
                onValueChange={setCriticalityFilter}
                placeholder="All Criticality"
                className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <SelectItem value="all">All Criticality</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </Select>
              <Select
                value={statusFilter}
                onValueChange={setStatusFilter}
                placeholder="All Status"
                className="rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="managed">Managed</SelectItem>
                <SelectItem value="unmanaged">Unmanaged</SelectItem>
                <SelectItem value="discovered">Discovered</SelectItem>
                <SelectItem value="decommissioned">Decommissioned</SelectItem>
              </Select>
            </div>
            <button
              onClick={handleRefresh}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors"
              style={{
                backgroundColor: 'var(--surface)',
                color: 'var(--fg)'
              }}
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
              Refresh
            </button>
          </div>
        </div>

        {/* Asset Table */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Asset Inventory</h2>
            <span className="text-sm" style={{ color: 'var(--muted)' }}>{filteredAssets.length} assets</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Asset</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>IP Address</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Criticality</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Vulnerability Matches</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Tags</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                      <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No assets found</p>
                    </td>
                  </tr>
                ) : (
                  filteredAssets.map((asset) => (
                    <AssetRow key={asset.id} asset={asset} />
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType
  label: string
  value?: number
  color: 'primary' | 'green' | 'red' | 'yellow' | 'orange'
}) {
  const getColorStyles = () => {
    switch (color) {
      case 'primary':
        return { backgroundColor: 'rgba(99, 102, 241, 0.2)', color: 'var(--primary)' }
      case 'green':
        return { backgroundColor: 'rgba(52, 211, 153, 0.2)', color: 'var(--emerald-400)' }
      case 'red':
        return { backgroundColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--crit)' }
      case 'yellow':
        return { backgroundColor: 'rgba(234, 179, 8, 0.2)', color: 'var(--warn)' }
      case 'orange':
        return { backgroundColor: 'rgba(249, 115, 22, 0.2)', color: 'var(--high)' }
    }
  }

  const iconStyles = getColorStyles()
  const displayValue = Number.isFinite(value) ? value : 0

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg" style={iconStyles}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{displayValue.toLocaleString()}</p>
          <p className="text-sm" style={{ color: 'var(--muted)' }}>{label}</p>
        </div>
      </div>
    </div>
  )
}

function GroupCard({ group }: { group: AssetGroup }) {
  const getColorStyles = () => {
    switch (group.color) {
      case 'red':
        return { borderLeftColor: 'var(--crit)', backgroundColor: 'rgba(239, 68, 68, 0.1)' }
      case 'blue':
        return { borderLeftColor: 'var(--info)', backgroundColor: 'rgba(59, 130, 246, 0.1)' }
      case 'purple':
        return { borderLeftColor: 'var(--primary)', backgroundColor: 'rgba(139, 92, 246, 0.1)' }
      case 'yellow':
        return { borderLeftColor: 'var(--warn)', backgroundColor: 'rgba(234, 179, 8, 0.1)' }
      case 'green':
        return { borderLeftColor: 'var(--emerald-400)', backgroundColor: 'rgba(52, 211, 153, 0.1)' }
      default:
        return { borderLeftColor: 'var(--muted)', backgroundColor: 'rgba(100, 116, 139, 0.1)' }
    }
  }

  const colorStyles = getColorStyles()

  return (
    <div
      className="rounded-lg p-3 border-l-4 cursor-pointer transition-colors hover:opacity-80"
      style={colorStyles}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{group.name || 'Group'}</span>
        <span className="text-xs" style={{ color: 'var(--muted)' }}>{group.assetCount ?? 0}</span>
      </div>
      <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>{group.description}</p>
    </div>
  )
}

function AssetRow({ asset }: { asset: Asset }) {
  const typeIcons: Record<Asset['type'], React.ElementType> = {
    server: Server,
    workstation: Monitor,
    laptop: Laptop,
    network: Network,
    cloud: Cloud,
    database: Database
  }

  const getCriticalityStyles = () => {
    switch (asset.criticality) {
      case 'critical':
        return { backgroundColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--crit)' }
      case 'high':
        return { backgroundColor: 'rgba(249, 115, 22, 0.2)', color: 'var(--high)' }
      case 'medium':
        return { backgroundColor: 'rgba(234, 179, 8, 0.2)', color: 'var(--warn)' }
      case 'low':
        return { backgroundColor: 'rgba(52, 211, 153, 0.2)', color: 'var(--emerald-400)' }
    }
  }

  const getStatusStyles = () => {
    switch (asset.discoveryStatus) {
      case 'managed':
        return { backgroundColor: 'rgba(52, 211, 153, 0.2)', color: 'var(--emerald-400)' }
      case 'unmanaged':
        return { backgroundColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--crit)' }
      case 'discovered':
        return { backgroundColor: 'rgba(234, 179, 8, 0.2)', color: 'var(--warn)' }
      case 'decommissioned':
        return { backgroundColor: 'rgba(100, 116, 139, 0.2)', color: 'var(--muted)' }
    }
  }

  const TypeIcon = typeIcons[asset.type] || Server

  return (
    <tr className="hover:opacity-80 transition-opacity" style={{ borderBottom: '1px solid var(--border)' }}>
      <td className="p-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface)' }}>
            <TypeIcon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          </div>
          <div>
            <p className="font-medium" style={{ color: 'var(--fg)' }}>{asset.hostname}</p>
            <p className="text-xs" style={{ color: 'var(--muted)' }}>{asset.os}</p>
          </div>
        </div>
      </td>
      <td className="p-4">
        <span className="text-sm capitalize" style={{ color: 'var(--fg)' }}>{asset.type}</span>
      </td>
      <td className="p-4">
        <span className="font-mono text-sm" style={{ color: 'var(--fg)' }}>{asset.ip}</span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-medium capitalize"
          style={getCriticalityStyles()}
        >
          {asset.criticality}
        </span>
      </td>
      <td className="p-4">
        <span
          className="px-2 py-1 rounded text-xs font-medium capitalize"
          style={getStatusStyles()}
        >
          {asset.discoveryStatus}
        </span>
      </td>
      <td className="p-4">
        <VulnerabilityBadges vulnerabilities={asset.vulnerabilities} />
      </td>
      <td className="p-4">
        <div className="flex flex-wrap gap-1 max-w-[150px]">
          {asset.tags.slice(0, 2).map((tag, idx) => (
            <span
              key={idx}
              className="px-2 py-0.5 rounded text-xs"
              style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)' }}
            >
              {tag}
            </span>
          ))}
          {asset.tags.length > 2 && (
            <span
              className="px-2 py-0.5 rounded text-xs"
              style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
            >
              +{asset.tags.length - 2}
            </span>
          )}
        </div>
      </td>
      <td className="p-4">
        <div className="flex items-center gap-1">
          <button
            onClick={() => router.visit(`/app/assets/${asset.id}`)}
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--muted)' }}
            title="Open asset details"
          >
            <Eye className="h-4 w-4" />
          </button>
          <button
            disabled
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--muted)' }}
            title="Asset settings are not enabled yet"
          >
            <Settings className="h-4 w-4" />
          </button>
        </div>
      </td>
    </tr>
  )
}

function VulnerabilityBadges({ vulnerabilities }: { vulnerabilities: Asset['vulnerabilities'] }) {
  const counts = normalizeVulnerabilities(vulnerabilities)
  const total = counts.critical + counts.high + counts.medium + counts.low

  if (total === 0) {
    return <span className="text-sm" style={{ color: 'var(--muted)' }}>None</span>
  }

  return (
    <div className="flex items-center gap-1" title="CVE matches from agent software inventory when available">
      {counts.critical > 0 && (
        <span
          className="px-1.5 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--crit)' }}
        >
          C:{counts.critical}
        </span>
      )}
      {counts.high > 0 && (
        <span
          className="px-1.5 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: 'rgba(249, 115, 22, 0.2)', color: 'var(--high)' }}
        >
          H:{counts.high}
        </span>
      )}
      {counts.medium > 0 && (
        <span
          className="px-1.5 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: 'rgba(234, 179, 8, 0.2)', color: 'var(--warn)' }}
        >
          M:{counts.medium}
        </span>
      )}
      {counts.low > 0 && (
        <span
          className="px-1.5 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: 'rgba(59, 130, 246, 0.2)', color: 'var(--info)' }}
        >
          L:{counts.low}
        </span>
      )}
    </div>
  )
}

function normalizeStats(
  stats: AssetsPageProps['stats'],
  assets: Asset[]
): AssetStats {
  const totalAssets = toNumber(stats?.totalAssets, assets.length)
  const managedAssets = toNumber(
    stats?.managedAssets,
    assets.filter((asset) => asset.discoveryStatus === 'managed').length
  )

  return {
    totalAssets,
    managedAssets,
    unmanagedAssets: toNumber(stats?.unmanagedAssets, Math.max(totalAssets - managedAssets, 0)),
    criticalAssets: toNumber(stats?.criticalAssets, assets.filter((asset) => asset.criticality === 'critical').length),
    vulnerableAssets: toNumber(stats?.vulnerableAssets, assets.filter((asset) => {
      const vulns = normalizeVulnerabilities(asset.vulnerabilities)
      return vulns.critical + vulns.high + vulns.medium + vulns.low > 0
    }).length),
  }
}

function normalizeAsset(asset: Partial<Asset> & Record<string, any>): Asset {
  const vulnerabilityCount = toNumber(asset.vulnerabilityCount, 0)
  const criticalVulnCount = toNumber(asset.criticalVulnCount, 0)
  const vulnerabilities = normalizeVulnerabilities(asset.vulnerabilities)

  if (vulnerabilityCount > 0 && vulnerabilities.critical + vulnerabilities.high + vulnerabilities.medium + vulnerabilities.low === 0) {
    vulnerabilities.critical = criticalVulnCount
    vulnerabilities.high = Math.max(vulnerabilityCount - criticalVulnCount, 0)
  }

  return {
    id: String(asset.id || asset.agentId || asset.hostname || 'unknown'),
    hostname: String(asset.hostname || asset.fqdn || 'Unknown asset'),
    type: normalizeAssetType(asset.type || asset.assetType),
    os: String(asset.os || [asset.osType, asset.osVersion].filter(Boolean).join(' ') || 'Unknown OS'),
    ip: String(asset.ip || asset.ipAddress || asset.ipAddresses?.[0] || '-'),
    criticality: normalizeCriticality(asset.criticality),
    owner: String(asset.owner || asset.businessUnit || '-'),
    department: String(asset.department || asset.businessUnit || '-'),
    location: String(asset.location || asset.cloudRegion || '-'),
    discoveryStatus: normalizeDiscoveryStatus(asset.discoveryStatus, asset.agentId),
    agentStatus: normalizeAgentStatus(asset.agentStatus, asset.agentId),
    vulnerabilities,
    lastSeen: String(asset.lastSeen || '-'),
    tags: Array.isArray(asset.tags) ? asset.tags.map(String) : [],
  }
}

function normalizeVulnerabilities(vulnerabilities: Partial<Asset['vulnerabilities']> | undefined): Asset['vulnerabilities'] {
  return {
    critical: toNumber(vulnerabilities?.critical, 0),
    high: toNumber(vulnerabilities?.high, 0),
    medium: toNumber(vulnerabilities?.medium, 0),
    low: toNumber(vulnerabilities?.low, 0),
  }
}

function normalizeAssetType(type: unknown): Asset['type'] {
  const value = String(type || '').toLowerCase()
  if (['server', 'workstation', 'laptop', 'network', 'cloud', 'database'].includes(value)) {
    return value as Asset['type']
  }
  return 'server'
}

function normalizeCriticality(criticality: unknown): Asset['criticality'] {
  const value = String(criticality || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low'].includes(value)) {
    return value as Asset['criticality']
  }
  return 'medium'
}

function normalizeDiscoveryStatus(status: unknown, agentId: unknown): Asset['discoveryStatus'] {
  const value = String(status || '').toLowerCase()
  if (['managed', 'unmanaged', 'discovered', 'decommissioned'].includes(value)) {
    return value as Asset['discoveryStatus']
  }
  return agentId ? 'managed' : 'discovered'
}

function normalizeAgentStatus(status: unknown, agentId: unknown): Asset['agentStatus'] {
  const value = String(status || '').toLowerCase()
  if (['installed', 'not_installed', 'outdated'].includes(value)) {
    return value as Asset['agentStatus']
  }
  return agentId ? 'installed' : 'not_installed'
}

function toNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}
