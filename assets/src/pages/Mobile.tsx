import { useState, useEffect, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { logger } from '@/lib/logger'
import {
  Smartphone,
  Tablet,
  Shield,
  AlertTriangle,
  Clock,
  RefreshCw,
  Apple,
  Lock,
  Unlock,
  MapPin,
  Trash2,
  Volume2,
  Send,
  Settings,
  Download,
  QrCode,
  ChevronRight,
  AlertCircle,
  CheckCircle,
  XCircle,
  Wifi,
  WifiOff,
  Server,
  Package,
  Activity,
  TrendingUp,
  Eye,
  FileWarning,
  Construction,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'

// Android icon component since lucide doesn't have one
function AndroidIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M6 18c0 .55.45 1 1 1h1v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h2v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h1c.55 0 1-.45 1-1V8H6v10zM3.5 8C2.67 8 2 8.67 2 9.5v7c0 .83.67 1.5 1.5 1.5S5 17.33 5 16.5v-7C5 8.67 4.33 8 3.5 8zm17 0c-.83 0-1.5.67-1.5 1.5v7c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5v-7c0-.83-.67-1.5-1.5-1.5zm-4.97-5.84l1.3-1.3c.2-.2.2-.51 0-.71-.2-.2-.51-.2-.71 0l-1.48 1.48C13.85 1.23 12.95 1 12 1c-.96 0-1.86.23-2.66.63L7.85.15c-.2-.2-.51-.2-.71 0-.2.2-.2.51 0 .71l1.31 1.31C6.97 3.26 6 5.01 6 7h12c0-1.99-.97-3.75-2.47-4.84zM10 5H9V4h1v1zm5 0h-1V4h1v1z"/>
    </svg>
  )
}

// ============================================================================
// Shared fetch helper
// ============================================================================
async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Accept': 'application/json' },
  })
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`)
  }
  const json = await res.json()
  return json.data ?? json
}

// ============================================================================
// Types
// ============================================================================
interface MobileStats {
  total: number
  ios: number
  android: number
  active: number
  compromised: number
  high_risk: number
  mdm_enrolled: number
  stale_24h: number
}

interface SecurityPosture {
  score: number
  devices: MobileStats
  events_24h: {
    total: number
    critical: number
    high: number
    by_severity: Record<string, number>
    by_type: Array<[string, number]>
  }
  risks: Array<{
    level: string
    type: string
    count: number
    message: string
  }>
  recommendations: Array<{
    priority: string
    action: string
    message: string
  }>
}

interface MDMIntegration {
  provider: string
  display_name?: string
  status: 'connected' | 'configured' | 'available' | 'not_configured' | 'error'
  message: string
}

interface MobileDevice {
  id: string
  device_id: string
  platform: string
  model: string | null
  manufacturer?: string | null
  os_version: string | null
  agent_version?: string | null
  status: string
  risk_score: number
  is_compromised: boolean
  mdm_enrolled: boolean
  mdm_provider: string | null
  last_seen_at: string | null
  enrolled_at: string | null
}

// ============================================================================
// Main component
// ============================================================================
export default function Mobile() {
  const [stats, setStats] = useState<MobileStats | null>(null)
  const [posture, setPosture] = useState<SecurityPosture | null>(null)
  const [mdmStatus, setMdmStatus] = useState<MDMIntegration[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'overview' | 'devices' | 'apps' | 'events' | 'setup'>('overview')

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      // Fetch all three endpoints in parallel
      const [statsData, postureData, mdmData] = await Promise.all([
        apiFetch<MobileStats>('/api/v1/mobile/stats'),
        apiFetch<SecurityPosture>('/api/v1/mobile/posture'),
        apiFetch<{ integrations: MDMIntegration[] }>('/api/v1/mobile/mdm/status').catch(() => null),
      ])

      setStats(statsData)
      setPosture(postureData)

      if (mdmData && mdmData.integrations) {
        setMdmStatus(mdmData.integrations)
      }
    } catch (err) {
      logger.error('Failed to fetch mobile data:', err)
      setError(err instanceof Error ? err.message : 'Failed to load mobile data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const tabs: { id: typeof activeTab; label: string; icon: React.ElementType }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'devices', label: 'Devices', icon: Smartphone },
    { id: 'apps', label: 'Apps', icon: Package },
    { id: 'events', label: 'Events', icon: AlertTriangle },
    { id: 'setup', label: 'Setup Guide', icon: Settings },
  ]

  return (
    <MainLayout title="Mobile Security">
      <Head title="Mobile Security - Tamandua EDR" />

      <div className="space-y-6">
        {/* Mobile roadmap banner */}
        <div
          className="rounded-xl p-6"
          style={{
            background: 'linear-gradient(to right, rgba(47, 196, 113, 0.12), rgba(168, 85, 247, 0.12))',
            border: '1px solid rgba(47, 196, 113, 0.3)',
          }}
        >
          <div className="flex items-start gap-4">
            <div
              className="p-3 rounded-lg"
              style={{ background: 'var(--emerald-glow)' }}
            >
              <Construction className="h-8 w-8" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div className="flex-1">
              <h2 className="text-xl font-bold mb-2" style={{ color: 'var(--fg)' }}>Mobile Agent Support - Roadmap</h2>
              <p className="mb-4" style={{ color: 'var(--muted)' }}>
                We are building native iOS and Android agents to extend Tamandua EDR protection to mobile devices.
                The foundation architecture is complete - see our detailed design document for the roadmap.
              </p>
              <div className="flex flex-wrap gap-3">
                <a
                  href="/docs/MOBILE_AGENT_ARCHITECTURE.md"
                  className="btn-sentinel btn-sentinel-primary"
                >
                  <Eye className="h-4 w-4" />
                  View Architecture Doc
                </a>
                <button
                  onClick={() => setActiveTab('setup')}
                  className="btn-sentinel btn-sentinel-secondary"
                >
                  <Settings className="h-4 w-4" />
                  Setup Guide
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Error banner */}
        {error && (
          <div
            className="rounded-lg p-4 flex items-center gap-3"
            style={{
              background: 'var(--crit-bg)',
              border: '1px solid rgba(240, 80, 110, 0.3)',
            }}
          >
            <AlertCircle className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--crit)' }} />
            <span className="text-sm flex-1" style={{ color: 'var(--crit)' }}>{error}</span>
            <button onClick={() => setError(null)} style={{ color: 'var(--crit)' }} className="hover:opacity-80">
              <XCircle className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Tabs */}
        <div className="flex items-center justify-between pb-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex gap-2">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-t-lg transition-colors",
                    activeTab === tab.id
                      ? "border-b-2"
                      : "hover:opacity-80"
                  )}
                  style={{
                    background: activeTab === tab.id ? 'var(--surface)' : 'transparent',
                    color: activeTab === tab.id ? 'var(--fg)' : 'var(--muted)',
                    borderBottomColor: activeTab === tab.id ? 'var(--emerald-500)' : 'transparent',
                  }}
                >
                  <Icon className="h-4 w-4" />
                  {tab.label}
                </button>
              )
            })}
          </div>
          <button
            onClick={fetchData}
            disabled={loading}
            className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            Refresh
          </button>
        </div>

        {/* Loading state */}
        {loading && !stats && (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin" style={{ color: 'var(--emerald-400)' }} />
            <span className="ml-3" style={{ color: 'var(--muted)' }}>Loading mobile security data...</span>
          </div>
        )}

        {/* Tab Content */}
        {(!loading || stats) && (
          <>
            {activeTab === 'overview' && (
              <OverviewTab stats={stats} posture={posture} mdmStatus={mdmStatus} />
            )}

            {activeTab === 'devices' && (
              <DevicesTab />
            )}

            {activeTab === 'apps' && (
              <AppsTab />
            )}

            {activeTab === 'events' && (
              <EventsTab />
            )}

            {activeTab === 'setup' && (
              <SetupGuideTab />
            )}
          </>
        )}
      </div>
    </MainLayout>
  )
}

// ============================================================================
// Overview tab
// ============================================================================
function OverviewTab({ stats, posture, mdmStatus }: {
  stats: MobileStats | null
  posture: SecurityPosture | null
  mdmStatus: MDMIntegration[]
}) {
  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Devices"
          value={stats?.total || 0}
          subtitle={`${stats?.ios || 0} iOS, ${stats?.android || 0} Android`}
          icon={Smartphone}
          color="primary"
        />
        <StatCard
          title="Active Devices"
          value={stats?.active || 0}
          subtitle={`${stats?.stale_24h || 0} stale (>24h)`}
          icon={Activity}
          color="success"
        />
        <StatCard
          title="Security Score"
          value={posture?.score || 100}
          subtitle="Based on device posture"
          icon={Shield}
          color={posture && posture.score < 70 ? 'danger' : posture && posture.score < 85 ? 'warning' : 'success'}
          isScore
        />
        <StatCard
          title="MDM Enrolled"
          value={stats?.mdm_enrolled || 0}
          subtitle={`${(stats?.total || 0) - (stats?.mdm_enrolled || 0)} not enrolled`}
          icon={Server}
          color="primary"
        />
      </div>

      {/* Platform Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card-sentinel p-6">
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Platform Distribution</h3>
          <div className="flex items-center justify-center gap-8 py-8">
            <div className="text-center">
              <div
                className="p-4 rounded-full mb-3 inline-block"
                style={{ background: 'var(--surface-2)' }}
              >
                <Apple className="h-12 w-12" style={{ color: 'var(--muted)' }} />
              </div>
              <div className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{stats?.ios || 0}</div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>iOS Devices</div>
            </div>
            <div className="h-24 w-px" style={{ background: 'var(--border)' }} />
            <div className="text-center">
              <div
                className="p-4 rounded-full mb-3 inline-block"
                style={{ background: 'var(--surface-2)' }}
              >
                <AndroidIcon className="h-12 w-12" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{stats?.android || 0}</div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Android Devices</div>
            </div>
          </div>
          {(stats?.total || 0) === 0 && (
            <p className="text-center text-sm" style={{ color: 'var(--subtle)' }}>
              No devices registered yet. Deploy mobile agents to start monitoring.
            </p>
          )}
        </div>

        {/* Risk Overview */}
        <div className="card-sentinel p-6">
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Security Risks</h3>
          {posture?.risks && posture.risks.length > 0 ? (
            <div className="space-y-3">
              {posture.risks.map((risk, idx) => (
                <div
                  key={idx}
                  className={cn(
                    "flex items-center gap-3 p-3 rounded-lg",
                    risk.level === 'critical' ? 'card-sentinel-critical' :
                    risk.level === 'high' ? 'card-sentinel-high' :
                    'card-sentinel-medium'
                  )}
                >
                  <AlertTriangle
                    className="h-5 w-5"
                    style={{
                      color: risk.level === 'critical' ? 'var(--crit)' :
                             risk.level === 'high' ? 'var(--high)' : 'var(--med)'
                    }}
                  />
                  <div className="flex-1">
                    <p className="text-sm" style={{ color: 'var(--fg)' }}>{risk.message}</p>
                  </div>
                  <span className="text-sm font-medium" style={{ color: 'var(--muted)' }}>{risk.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center">
              <CheckCircle className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--emerald-400)' }} />
              <p style={{ color: 'var(--muted)' }}>No security risks detected</p>
            </div>
          )}
        </div>
      </div>

      {/* MDM Integrations */}
      <div className="card-sentinel p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>MDM Integrations</h3>
          <a
            href="/app/integrations"
            className="text-sm flex items-center gap-1 hover:opacity-80"
            style={{ color: 'var(--emerald-400)' }}
          >
            Configure
            <ChevronRight className="h-4 w-4" />
          </a>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {mdmStatus.length > 0 ? mdmStatus.map((mdm, idx) => (
            <div
              key={idx}
              className="card-sentinel-inset rounded-lg p-4"
              style={{ border: '1px solid var(--border)' }}
            >
              <div className="flex items-center gap-3 mb-2">
                {mdm.status === 'connected' || mdm.status === 'configured' ? (
                  <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                ) : mdm.status === 'error' ? (
                  <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                ) : (
                  <AlertCircle className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                )}
                <span className="font-medium" style={{ color: 'var(--fg)' }}>{mdm.display_name || mdm.provider}</span>
              </div>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>{mdm.message}</p>
            </div>
          )) : (
            <div className="col-span-4 text-center py-6 text-sm" style={{ color: 'var(--subtle)' }}>
              No MDM providers configured. Set up an integration in Settings.
            </div>
          )}
        </div>
      </div>

      {/* Supported Features */}
      <div className="card-sentinel p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Planned Capabilities</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { icon: Shield, title: 'Jailbreak/Root Detection', desc: 'Detect compromised devices instantly' },
            { icon: Package, title: 'App Inventory', desc: 'Track all installed applications' },
            { icon: AlertTriangle, title: 'Malware Detection', desc: 'Identify malicious apps and behaviors' },
            { icon: Wifi, title: 'Network Monitoring', desc: 'DNS and traffic analysis' },
            { icon: Lock, title: 'Remote Lock', desc: 'Lock devices on security breach' },
            { icon: Trash2, title: 'Remote Wipe', desc: 'Enterprise or full device wipe' },
            { icon: MapPin, title: 'Device Location', desc: 'Track lost or stolen devices' },
            { icon: Server, title: 'MDM Integration', desc: 'Intune, WS1, Jamf, Google' },
            { icon: FileWarning, title: 'SMS Phishing', desc: 'Detect phishing attempts via SMS' },
          ].map((feature, idx) => {
            const Icon = feature.icon
            return (
              <div
                key={idx}
                className="flex items-start gap-3 p-3 rounded-lg"
                style={{ background: 'var(--bg-2)' }}
              >
                <div
                  className="p-2 rounded-lg"
                  style={{ background: 'var(--emerald-glow)' }}
                >
                  <Icon className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div>
                  <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{feature.title}</h4>
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>{feature.desc}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Devices tab - fetches from GET /api/v1/mobile/devices
// ============================================================================
function DevicesTab() {
  const [devices, setDevices] = useState<MobileDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [total, setTotal] = useState(0)

  const fetchDevices = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/mobile/devices?limit=200', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (!res.ok) throw new Error(`Failed to load devices (${res.status})`)
      const json = await res.json()
      setDevices(json.data || [])
      setTotal(json.meta?.total ?? (json.data || []).length)
    } catch (err) {
      logger.error('Failed to fetch devices:', err)
      setError(err instanceof Error ? err.message : 'Failed to load devices')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDevices()
  }, [fetchDevices])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin" style={{ color: 'var(--emerald-400)' }} />
        <span className="ml-3" style={{ color: 'var(--muted)' }}>Loading devices...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card-sentinel p-8 text-center">
        <AlertCircle className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--crit)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>Error Loading Devices</h3>
        <p className="mb-4" style={{ color: 'var(--muted)' }}>{error}</p>
        <button
          onClick={fetchDevices}
          className="btn-sentinel btn-sentinel-primary"
        >
          <RefreshCw className="h-4 w-4" />
          Retry
        </button>
      </div>
    )
  }

  if (devices.length === 0) {
    return (
      <div className="card-sentinel p-8 text-center">
        <Smartphone className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Devices Registered</h3>
        <p className="mb-6 max-w-md mx-auto" style={{ color: 'var(--muted)' }}>
          Deploy the Tamandua mobile agent to your iOS and Android devices to start monitoring.
          Devices can also be synced from your MDM solution.
        </p>
        <div className="flex justify-center gap-3">
          <button className="btn-sentinel btn-sentinel-secondary cursor-not-allowed opacity-50" disabled>
            <Download className="h-4 w-4" />
            Download iOS Agent
          </button>
          <button className="btn-sentinel btn-sentinel-secondary cursor-not-allowed opacity-50" disabled>
            <Download className="h-4 w-4" />
            Download Android Agent
          </button>
        </div>
        <p className="text-xs mt-4" style={{ color: 'var(--subtle)' }}>Agents are in development and will be available soon</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm" style={{ color: 'var(--muted)' }}>{total} device{total !== 1 ? 's' : ''} registered</p>
        <button
          onClick={fetchDevices}
          className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      <div className="card-sentinel overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Device</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Platform</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Status</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Risk</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>MDM</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => (
              <tr
                key={device.id}
                className="hover:bg-[var(--surface-2)]"
                style={{ borderBottom: '1px solid var(--hairline)' }}
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    {device.platform === 'ios' ? (
                      <Apple className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                    ) : (
                      <AndroidIcon className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                    )}
                    <div>
                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{device.model || device.device_id}</span>
                      {device.os_version && (
                        <span className="text-xs ml-2" style={{ color: 'var(--subtle)' }}>{device.os_version}</span>
                      )}
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 capitalize" style={{ color: 'var(--fg-2)' }}>{device.platform}</td>
                <td className="px-4 py-3">
                  <span className={cn(
                    "badge-sentinel badge-sentinel-pill",
                    device.status === 'active' ? 'badge-sentinel-success' :
                    device.status === 'lost' ? 'badge-sentinel-critical' :
                    device.status === 'wiped' ? 'badge-sentinel-high' :
                    'badge-sentinel-default'
                  )}>
                    {device.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span
                    className="text-sm font-medium"
                    style={{
                      color: device.risk_score >= 50 ? 'var(--crit)' :
                             device.risk_score >= 25 ? 'var(--high)' : 'var(--emerald-400)'
                    }}
                  >
                    {device.risk_score}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {device.mdm_enrolled ? (
                    <span className="inline-flex items-center gap-1 text-xs" style={{ color: 'var(--emerald-400)' }}>
                      <CheckCircle className="h-3 w-3" />
                      {device.mdm_provider || 'Enrolled'}
                    </span>
                  ) : (
                    <span className="text-xs" style={{ color: 'var(--subtle)' }}>Not enrolled</span>
                  )}
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--muted)' }}>
                  {device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// Apps tab
// ============================================================================
function AppsTab() {
  const [apps, setApps] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchApps = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/mobile/apps/high-risk?limit=100', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (!res.ok) throw new Error(`Failed to load apps (${res.status})`)
      const json = await res.json()
      setApps(json.data || [])
    } catch (err) {
      logger.error('Failed to fetch apps:', err)
      setError(err instanceof Error ? err.message : 'Failed to load app data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchApps()
  }, [fetchApps])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin" style={{ color: 'var(--emerald-400)' }} />
        <span className="ml-3" style={{ color: 'var(--muted)' }}>Loading app inventory...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card-sentinel p-8 text-center">
        <AlertCircle className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--crit)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>Error Loading Apps</h3>
        <p className="mb-4" style={{ color: 'var(--muted)' }}>{error}</p>
        <button
          onClick={fetchApps}
          className="btn-sentinel btn-sentinel-primary"
        >
          <RefreshCw className="h-4 w-4" />
          Retry
        </button>
      </div>
    )
  }

  if (apps.length === 0) {
    return (
      <div className="card-sentinel p-8 text-center">
        <Package className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>No App Data Available</h3>
        <p className="mb-6 max-w-md mx-auto" style={{ color: 'var(--muted)' }}>
          App inventory will be collected automatically once mobile agents are deployed.
          You will be able to see all installed apps, identify risky apps, and detect sideloading.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--muted)' }}>{apps.length} high-risk app{apps.length !== 1 ? 's' : ''} found</p>
      <div className="card-sentinel overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>App Name</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Bundle ID</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Risk Level</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Installer</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Device</th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app: any) => (
              <tr
                key={app.id}
                className="hover:bg-[var(--surface-2)]"
                style={{ borderBottom: '1px solid var(--hairline)' }}
              >
                <td className="px-4 py-3" style={{ color: 'var(--fg)' }}>{app.app_name || 'Unknown'}</td>
                <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--muted)' }}>{app.bundle_id}</td>
                <td className="px-4 py-3">
                  <span className={cn(
                    "badge-sentinel badge-sentinel-pill",
                    app.risk_level === 'critical' ? 'badge-sentinel-critical' :
                    app.risk_level === 'high' ? 'badge-sentinel-high' :
                    app.risk_level === 'medium' ? 'badge-sentinel-medium' :
                    'badge-sentinel-default'
                  )}>
                    {app.risk_level}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs capitalize" style={{ color: 'var(--muted)' }}>{app.installer}</td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--muted)' }}>
                  {app.device ? `${app.device.platform} - ${app.device.model || app.device.device_id}` : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// Events tab
// ============================================================================
function EventsTab() {
  const [events, setEvents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchEvents = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/mobile/events?limit=100&hours=72', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (!res.ok) throw new Error(`Failed to load events (${res.status})`)
      const json = await res.json()
      setEvents(json.data || [])
    } catch (err) {
      logger.error('Failed to fetch events:', err)
      setError(err instanceof Error ? err.message : 'Failed to load events')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchEvents()
  }, [fetchEvents])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin" style={{ color: 'var(--emerald-400)' }} />
        <span className="ml-3" style={{ color: 'var(--muted)' }}>Loading security events...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card-sentinel p-8 text-center">
        <AlertCircle className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--crit)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>Error Loading Events</h3>
        <p className="mb-4" style={{ color: 'var(--muted)' }}>{error}</p>
        <button
          onClick={fetchEvents}
          className="btn-sentinel btn-sentinel-primary"
        >
          <RefreshCw className="h-4 w-4" />
          Retry
        </button>
      </div>
    )
  }

  if (events.length === 0) {
    return (
      <div className="card-sentinel p-8 text-center">
        <AlertTriangle className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
        <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Security Events</h3>
        <p className="mb-6 max-w-md mx-auto" style={{ color: 'var(--muted)' }}>
          Security events from mobile devices will appear here once agents are deployed.
          Events include jailbreak detection, malware alerts, network threats, and more.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--muted)' }}>{events.length} event{events.length !== 1 ? 's' : ''} in the last 72 hours</p>
      <div className="card-sentinel overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Severity</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Type</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Title</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Device</th>
              <th className="px-4 py-3 font-medium text-left" style={{ color: 'var(--muted)' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event: any) => (
              <tr
                key={event.id}
                className="hover:bg-[var(--surface-2)]"
                style={{ borderBottom: '1px solid var(--hairline)' }}
              >
                <td className="px-4 py-3">
                  <span className={cn(
                    "badge-sentinel badge-sentinel-pill",
                    event.severity === 'critical' ? 'badge-sentinel-critical' :
                    event.severity === 'high' ? 'badge-sentinel-high' :
                    event.severity === 'medium' ? 'badge-sentinel-medium' :
                    event.severity === 'low' ? 'badge-sentinel-low' :
                    'badge-sentinel-default'
                  )}>
                    {event.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--muted)' }}>{event.event_type}</td>
                <td className="px-4 py-3" style={{ color: 'var(--fg)' }}>{event.title || event.event_type}</td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--muted)' }}>
                  {event.device ? `${event.device.platform} - ${event.device.model || event.device.device_id}` : '-'}
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--muted)' }}>
                  {event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// Setup Guide tab
// ============================================================================
function SetupGuideTab() {
  return (
    <div className="space-y-6">
      {/* QR Code Generator Stub */}
      <div className="card-sentinel p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Device Enrollment QR Code</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <p className="mb-4" style={{ color: 'var(--muted)' }}>
              Generate a QR code for easy device enrollment. Users can scan this code with
              the Tamandua mobile app to register their device automatically.
            </p>
            <div className="space-y-3">
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Enrollment Profile</label>
                <Select defaultValue="default" className="input-sentinel w-full" fullWidth>
                  <SelectItem value="default">Default - Standard Security</SelectItem>
                  <SelectItem value="high">High Security - Executive Devices</SelectItem>
                  <SelectItem value="byod">BYOD - Personal Devices</SelectItem>
                </Select>
              </div>
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Expiration</label>
                <Select defaultValue="1h" className="input-sentinel w-full" fullWidth>
                  <SelectItem value="1h">1 hour</SelectItem>
                  <SelectItem value="24h">24 hours</SelectItem>
                  <SelectItem value="7d">7 days</SelectItem>
                  <SelectItem value="never">Never</SelectItem>
                </Select>
              </div>
              <button
                className="btn-sentinel btn-sentinel-primary w-full cursor-not-allowed opacity-50"
                disabled
              >
                <QrCode className="h-4 w-4" />
                Generate QR Code
              </button>
              <p className="text-xs text-center" style={{ color: 'var(--subtle)' }}>
                QR code generation will be available when mobile agents are released
              </p>
            </div>
          </div>
          <div className="flex items-center justify-center">
            <div
              className="w-48 h-48 rounded-lg flex items-center justify-center"
              style={{
                background: 'var(--bg-2)',
                border: '2px dashed var(--border)',
              }}
            >
              <QrCode className="h-16 w-16" style={{ color: 'var(--subtle)' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Setup Steps */}
      <div className="card-sentinel p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Setup Guide</h3>
        <div className="space-y-4">
          {[
            {
              step: 1,
              title: 'Configure MDM Integration (Optional)',
              description: 'Connect your MDM solution (Intune, Workspace ONE, Jamf, or Google Workspace) for centralized device management.',
              status: 'available'
            },
            {
              step: 2,
              title: 'Download Mobile Agents',
              description: 'Download the Tamandua agent for iOS (App Store) or Android (Play Store / APK).',
              status: 'coming_soon'
            },
            {
              step: 3,
              title: 'Deploy to Devices',
              description: 'Push the agent via MDM or have users install manually by scanning the enrollment QR code.',
              status: 'coming_soon'
            },
            {
              step: 4,
              title: 'Configure Policies',
              description: 'Set security policies, configure detection rules, and define response actions.',
              status: 'coming_soon'
            },
          ].map((item) => (
            <div
              key={item.step}
              className="flex items-start gap-4 p-4 rounded-lg"
              style={{ background: 'var(--bg-2)' }}
            >
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold"
                style={{
                  background: item.status === 'available' ? 'var(--emerald-500)' : 'var(--surface-2)',
                  color: item.status === 'available' ? 'white' : 'var(--muted)',
                }}
              >
                {item.step}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{item.title}</h4>
                  {item.status === 'coming_soon' && (
                    <span className="badge-sentinel badge-sentinel-warning badge-sentinel-pill">
                      Roadmap
                    </span>
                  )}
                </div>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{item.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Architecture Overview */}
      <div className="card-sentinel p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Architecture Overview</h3>
        <div
          className="rounded-lg p-6 text-sm"
          style={{
            background: 'var(--bg-2)',
            fontFamily: 'var(--mono)',
            color: 'var(--fg-2)',
          }}
        >
          <pre className="whitespace-pre-wrap">{`
                           +-------------------+
                           |  Tamandua Server  |
                           |   (This Backend)  |
                           +---------+---------+
                                     |
          +----------------------+---+---+----------------------+
          |                      |       |                      |
+---------v---------+  +---------v-------v---------+  +---------v---------+
|   iOS Agent       |  |  Android Agent    |  |   MDM Gateway     |
|   (Swift/ObjC)    |  |  (Kotlin/Java)    |  |   (REST API)      |
|   Roadmap         |  |  Roadmap          |  |   Available Now   |
+-------------------+  +-------------------+  +-------------------+
          |                      |                      |
+---------v---------+  +---------v---------+  +---------v---------+
| Device Management |  | Device Admin API  |  | Intune / WS1 /    |
|    Framework      |  | Knox (Samsung)    |  | Jamf / Google WS  |
+-------------------+  +-------------------+  +-------------------+
          `}</pre>
        </div>
        <div className="mt-4 flex justify-end">
          <a
            href="/docs/MOBILE_AGENT_ARCHITECTURE.md"
            className="text-sm flex items-center gap-1 hover:opacity-80"
            style={{ color: 'var(--emerald-400)' }}
          >
            View Full Architecture Document
            <ChevronRight className="h-4 w-4" />
          </a>
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Stat card component
// ============================================================================
interface StatCardProps {
  title: string
  value: number
  subtitle: string
  icon: React.ElementType
  color: 'primary' | 'success' | 'warning' | 'danger'
  isScore?: boolean
}

function StatCard({ title, value, subtitle, icon: Icon, color, isScore }: StatCardProps) {
  const colorStyles = {
    primary: {
      bg: 'var(--emerald-glow)',
      text: 'var(--emerald-400)',
    },
    success: {
      bg: 'var(--emerald-glow)',
      text: 'var(--emerald-400)',
    },
    warning: {
      bg: 'var(--high-bg)',
      text: 'var(--high)',
    },
    danger: {
      bg: 'var(--crit-bg)',
      text: 'var(--crit)',
    },
  }

  const styles = colorStyles[color]

  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center justify-between mb-3">
        <div
          className="p-2 rounded-lg"
          style={{ background: styles.bg }}
        >
          <Icon className="h-5 w-5" style={{ color: styles.text }} />
        </div>
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
        {isScore && <span className="text-lg" style={{ color: 'var(--muted)' }}>/100</span>}
      </div>
      <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
      <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>{subtitle}</p>
    </div>
  )
}
