import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Cloud as CloudIcon,
  Server,
  AlertTriangle,
  Shield,
  Activity,
  CheckCircle,
  XCircle,
  Filter,
  RefreshCw,
  ExternalLink,
  Clock,
  Database,
  Lock,
  Globe,
  Loader2,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'
import { Select, SelectItem } from '@/components/ui/baseui'

// Types
interface CloudProvider {
  id: string
  name: 'aws' | 'azure' | 'gcp'
  accountId: string
  region: string
  status: 'connected' | 'disconnected' | 'error'
  lastSync: string
  assetsCount: number
  misconfigurationsCount: number
}

interface CloudAsset {
  id: string
  provider: 'aws' | 'azure' | 'gcp'
  resourceType: string
  name: string
  region: string
  status: 'running' | 'stopped' | 'terminated'
  publiclyAccessible: boolean
  tags: Record<string, string>
  createdAt: string
}

interface Misconfiguration {
  id: string
  provider: 'aws' | 'azure' | 'gcp'
  resourceId: string
  resourceName: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  recommendation: string
  complianceFrameworks: string[]
  detectedAt: string
}

interface CloudTrailEvent {
  id: string
  provider: 'aws' | 'azure' | 'gcp'
  eventName: string
  eventSource: string
  sourceIp: string
  userAgent: string
  userName: string
  region: string
  timestamp: string
  isAnomaly: boolean
}

interface ComplianceStatus {
  framework: string
  passedControls: number
  failedControls: number
  totalControls: number
  percentage: number
}

interface CloudWorkloadsPageProps {
  providers?: CloudProvider[]
  assets?: CloudAsset[]
  misconfigurations?: Misconfiguration[]
  trailEvents?: CloudTrailEvent[]
  complianceStatus?: ComplianceStatus[]
}

export default function CloudWorkloads({
  providers = [],
  assets = [],
  misconfigurations = [],
  trailEvents = [],
  complianceStatus = [],
}: CloudWorkloadsPageProps) {
  const [providerFilter, setProviderFilter] = useState<string>('all')
  const [activeTab, setActiveTab] = useState<'assets' | 'misconfigurations' | 'events'>('assets')
  const [loading, setLoading] = useState<string | null>(null)
  const [selectedMisconfiguration, setSelectedMisconfiguration] = useState<Misconfiguration | null>(null)

  const handleSync = async (providerId?: string) => {
    const key = providerId ? `sync-${providerId}` : 'sync-all'
    setLoading(key)
    try {
      if (providerId) {
        await axios.post(`/api/v1/cloud/accounts/${providerId}/sync`)
        toast.success('Sync started')
      } else {
        for (const provider of providers) {
          await axios.post(`/api/v1/cloud/accounts/${provider.id}/sync`)
        }
        toast.success('All providers syncing')
      }
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to sync')
    } finally {
      setLoading(null)
    }
  }

  const filteredAssets = assets.filter(
    (asset) => providerFilter === 'all' || asset.provider === providerFilter
  )

  const filteredMisconfigurations = misconfigurations.filter(
    (mc) => providerFilter === 'all' || mc.provider === providerFilter
  )

  const filteredEvents = trailEvents.filter(
    (evt) => providerFilter === 'all' || evt.provider === providerFilter
  )

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'aws':
        return <span className="text-orange-400 font-bold text-xs">AWS</span>
      case 'azure':
        return <span className="text-blue-400 font-bold text-xs">Azure</span>
      case 'gcp':
        return <span className="text-red-400 font-bold text-xs">GCP</span>
      default:
        return <CloudIcon className="h-4 w-4" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
      case 'running':
        return 'text-green-400 bg-green-500/20'
      case 'disconnected':
      case 'stopped':
        return 'text-yellow-400 bg-yellow-500/20'
      case 'error':
      case 'terminated':
        return 'text-red-400 bg-red-500/20'
      default:
        return 'bg-[var(--surface-2)]' + ' ' + 'text-[var(--muted)]'
    }
  }

  return (
    <MainLayout title="Cloud Security">
      <Head title="Cloud Security - Tamandua EDR" />

      <div className="space-y-6">
        {/* Multi-cloud Overview */}
        {providers.length === 0 ? (
          <div className="card-sentinel rounded-xl p-12 text-center">
            <CloudIcon className="h-12 w-12 mx-auto mb-4 opacity-50" style={{ color: 'var(--subtle)' }} />
            <p style={{ color: 'var(--subtle)' }}>No cloud providers configured</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {providers.map((provider) => (
              <div
                key={provider.id}
                className="card-sentinel rounded-xl p-4"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg flex items-center justify-center" style={{ background: 'var(--surface-2)' }}>
                      {getProviderIcon(provider.name)}
                    </div>
                    <div>
                      <h3 className="font-medium capitalize" style={{ color: 'var(--fg)' }}>{provider.name.toUpperCase()}</h3>
                      <p className="text-xs font-mono" style={{ color: 'var(--muted)' }}>{provider.accountId}</p>
                    </div>
                  </div>
                  <span
                    className={cn(
                      'px-2 py-1 rounded text-xs font-medium',
                      getStatusColor(provider.status)
                    )}
                  >
                    {provider.status}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="flex items-center gap-2 text-xs mb-1" style={{ color: 'var(--muted)' }}>
                      <Server className="h-3 w-3" />
                      Assets
                    </div>
                    <p className="text-xl font-bold" style={{ color: 'var(--fg)' }}>{provider.assetsCount}</p>
                  </div>
                  <div className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                    <div className="flex items-center gap-2 text-xs mb-1" style={{ color: 'var(--muted)' }}>
                      <AlertTriangle className="h-3 w-3" />
                      Issues
                    </div>
                    <p className="text-xl font-bold text-orange-400">{provider.misconfigurationsCount}</p>
                  </div>
                </div>
                <div className="mt-4 flex items-center gap-2 text-xs" style={{ color: 'var(--subtle)' }}>
                  <Clock className="h-3 w-3" />
                  Last sync: {formatDate(provider.lastSync)}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Compliance Status */}
        <div className="card-sentinel rounded-xl p-4">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Shield className="h-5 w-5 text-primary-400" />
            Compliance Status
          </h2>
          {complianceStatus.length === 0 ? (
            <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
              <Shield className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No compliance data available</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              {complianceStatus.map((status) => (
                <div key={status.framework} className="rounded-lg p-3" style={{ background: 'var(--surface-2)' }}>
                  <p className="text-xs mb-2 truncate" style={{ color: 'var(--muted)' }} title={status.framework}>
                    {status.framework}
                  </p>
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className={cn(
                        'text-2xl font-bold',
                        status.percentage >= 90
                          ? 'text-green-400'
                          : status.percentage >= 70
                          ? 'text-yellow-400'
                          : 'text-red-400'
                      )}
                    >
                      {status.percentage}%
                    </span>
                    <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                      {status.passedControls}/{status.totalControls}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                    <div
                      className={cn(
                        'h-full rounded-full',
                        status.percentage >= 90
                          ? 'bg-green-500'
                          : status.percentage >= 70
                          ? 'bg-yellow-500'
                          : 'bg-red-500'
                      )}
                      style={{ width: `${status.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Filters and Tabs */}
        <div className="card-sentinel rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('assets')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'assets'
                    ? 'bg-primary-600 text-white'
                    : 'hover:bg-[var(--surface-2)]'
                )}
                style={activeTab !== 'assets' ? { color: 'var(--muted)' } : undefined}
              >
                <Server className="h-4 w-4 inline-block mr-2" />
                Assets ({filteredAssets.length})
              </button>
              <button
                onClick={() => setActiveTab('misconfigurations')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'misconfigurations'
                    ? 'bg-primary-600 text-white'
                    : 'hover:bg-[var(--surface-2)]'
                )}
                style={activeTab !== 'misconfigurations' ? { color: 'var(--muted)' } : undefined}
              >
                <AlertTriangle className="h-4 w-4 inline-block mr-2" />
                Misconfigurations ({filteredMisconfigurations.length})
              </button>
              <button
                onClick={() => setActiveTab('events')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'events'
                    ? 'bg-primary-600 text-white'
                    : 'hover:bg-[var(--surface-2)]'
                )}
                style={activeTab !== 'events' ? { color: 'var(--muted)' } : undefined}
              >
                <Activity className="h-4 w-4 inline-block mr-2" />
                Trail Events ({filteredEvents.length})
              </button>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
              <Select
                value={providerFilter}
                onValueChange={setProviderFilter}
                placeholder="All Providers"
                className="rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <SelectItem value="all">All Providers</SelectItem>
                <SelectItem value="aws">AWS</SelectItem>
                <SelectItem value="azure">Azure</SelectItem>
                <SelectItem value="gcp">GCP</SelectItem>
              </Select>
              <button
                onClick={() => handleSync()}
                disabled={loading === 'sync-all'}
                className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm disabled:opacity-50"
                style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
              >
                {loading === 'sync-all' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Sync
              </button>
            </div>
          </div>

          {/* Assets Tab */}
          {activeTab === 'assets' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Provider</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Resource</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Region</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Exposure</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                        <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No cloud assets found</p>
                      </td>
                    </tr>
                  ) : (
                    filteredAssets.map((asset) => (
                      <tr
                        key={asset.id}
                        className="hover:bg-[var(--surface-2)]"
                        style={{ borderBottom: '1px solid var(--hairline)' }}
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            {getProviderIcon(asset.provider)}
                          </div>
                        </td>
                        <td className="p-3">
                          <div>
                            <p className="font-medium" style={{ color: 'var(--fg)' }}>{asset.name}</p>
                            <p className="text-xs font-mono" style={{ color: 'var(--subtle)' }}>{asset.id}</p>
                          </div>
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-1 rounded text-xs" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                            {asset.resourceType}
                          </span>
                        </td>
                        <td className="p-3 text-sm" style={{ color: 'var(--muted)' }}>{asset.region}</td>
                        <td className="p-3">
                          <span
                            className={cn(
                              'px-2 py-1 rounded text-xs font-medium',
                              getStatusColor(asset.status)
                            )}
                          >
                            {asset.status}
                          </span>
                        </td>
                        <td className="p-3">
                          {asset.publiclyAccessible ? (
                            <span className="flex items-center gap-1 text-red-400 text-sm">
                              <Globe className="h-4 w-4" />
                              Public
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-green-400 text-sm">
                              <Lock className="h-4 w-4" />
                              Private
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* Misconfigurations Tab */}
          {activeTab === 'misconfigurations' && (
            <div className="space-y-3">
              {filteredMisconfigurations.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No misconfigurations found</p>
                </div>
              ) : (
                filteredMisconfigurations.map((mc) => (
                  <div
                    key={mc.id}
                    className="rounded-lg p-4 border-l-4"
                    style={{
                      background: 'var(--surface-2)',
                      borderLeftColor:
                        mc.severity === 'critical'
                          ? '#ef4444'
                          : mc.severity === 'high'
                          ? '#f97316'
                          : mc.severity === 'medium'
                          ? '#eab308'
                          : '#3b82f6',
                    }}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div
                          className={cn(
                            'p-2 rounded-lg mt-0.5',
                            mc.severity === 'critical'
                              ? 'bg-red-500/20'
                              : mc.severity === 'high'
                              ? 'bg-orange-500/20'
                              : mc.severity === 'medium'
                              ? 'bg-yellow-500/20'
                              : 'bg-blue-500/20'
                          )}
                        >
                          <AlertTriangle
                            className={cn(
                              'h-4 w-4',
                              mc.severity === 'critical'
                                ? 'text-red-400'
                                : mc.severity === 'high'
                                ? 'text-orange-400'
                                : mc.severity === 'medium'
                                ? 'text-yellow-400'
                                : 'text-blue-400'
                            )}
                          />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            {getProviderIcon(mc.provider)}
                            <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{mc.title}</h4>
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-xs font-medium',
                                mc.severity === 'critical'
                                  ? 'bg-red-500/20 text-red-400'
                                  : mc.severity === 'high'
                                  ? 'bg-orange-500/20 text-orange-400'
                                  : mc.severity === 'medium'
                                  ? 'bg-yellow-500/20 text-yellow-400'
                                  : 'bg-blue-500/20 text-blue-400'
                              )}
                            >
                              {mc.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{mc.description}</p>
                          <p className="text-sm mb-2" style={{ color: 'var(--fg-2)' }}>
                            <span style={{ color: 'var(--subtle)' }}>Resource:</span>{' '}
                            <span className="font-mono">{mc.resourceName}</span>
                          </p>
                          <div className="flex items-center gap-2 flex-wrap">
                            {mc.complianceFrameworks.map((fw) => (
                              <span
                                key={fw}
                                className="px-2 py-0.5 rounded text-xs"
                                style={{ background: 'var(--surface-3)', color: 'var(--fg-2)' }}
                              >
                                {fw}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => setSelectedMisconfiguration(selectedMisconfiguration?.id === mc.id ? null : mc)}
                        className="flex items-center gap-1 text-primary-400 text-sm hover:text-primary-300"
                      >
                        <ExternalLink className="h-4 w-4" />
                        View
                      </button>
                    </div>
                  </div>
                ))
              )}

              {selectedMisconfiguration && (
                <div className="mt-4 rounded-lg p-4" style={{ background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                  <h4 className="font-medium mb-2" style={{ color: 'var(--fg)' }}>Recommendation</h4>
                  <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{selectedMisconfiguration.recommendation}</p>
                  <p className="text-xs mt-2" style={{ color: 'var(--subtle)' }}>
                    Detected: {new Date(selectedMisconfiguration.detectedAt).toLocaleString()}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Trail Events Tab */}
          {activeTab === 'events' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Time</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Provider</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Event</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>User</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Source IP</th>
                    <th className="text-left p-3 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                        <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No trail events found</p>
                      </td>
                    </tr>
                  ) : (
                    filteredEvents.map((event) => (
                      <tr
                        key={event.id}
                        className={cn(
                          'hover:bg-[var(--surface-2)]',
                          event.isAnomaly && 'bg-red-900/10'
                        )}
                        style={{ borderBottom: '1px solid var(--hairline)' }}
                      >
                        <td className="p-3 text-sm" style={{ color: 'var(--muted)' }}>
                          {formatDate(event.timestamp)}
                        </td>
                        <td className="p-3">{getProviderIcon(event.provider)}</td>
                        <td className="p-3">
                          <div>
                            <p className="font-medium" style={{ color: 'var(--fg)' }}>{event.eventName}</p>
                            <p className="text-xs" style={{ color: 'var(--subtle)' }}>{event.eventSource}</p>
                          </div>
                        </td>
                        <td className="p-3 text-sm" style={{ color: 'var(--fg-2)' }}>{event.userName}</td>
                        <td className="p-3 font-mono text-sm" style={{ color: 'var(--muted)' }}>{event.sourceIp}</td>
                        <td className="p-3">
                          {event.isAnomaly ? (
                            <span className="flex items-center gap-1 text-red-400 text-sm">
                              <XCircle className="h-4 w-4" />
                              Anomaly
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-green-400 text-sm">
                              <CheckCircle className="h-4 w-4" />
                              Normal
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
