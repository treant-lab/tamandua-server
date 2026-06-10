import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Plug,
  Plus,
  Settings,
  Trash2,
  Play,
  Pause,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  ExternalLink,
  Copy,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronRight,
  Server,
  Shield,
  Bell,
  Ticket,
  Webhook,
  Activity,
  Heart,
  Clock,
  TrendingUp,
  TrendingDown,
  Zap,
  Database,
  BarChart3,
  Search,
  FileText,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useCallback, useEffect } from 'react'

interface IntegrationHealthMetrics {
  latencyMs: number
  latencyTrend: 'up' | 'down' | 'stable'
  errorRate: number
  errorRateTrend: 'up' | 'down' | 'stable'
  eventsPerMinute: number
  alertsPerMinute: number
  lastHealthCheck?: string
  uptime: number
  queueDepth: number
}

interface Integration {
  id: string
  type: string
  name: string
  description?: string
  enabled: boolean
  config: Record<string, unknown>
  lastSyncAt?: string
  lastError?: string
  stats?: {
    eventsSent?: number
    alertsSent?: number
    lastActivity?: string
  }
  health?: IntegrationHealthMetrics
}

interface RoutingRule {
  id: string
  name: string
  description?: string
  conditions: Array<{
    field: string
    operator: string
    value: unknown
  }>
  destinations: string[]
  enabled: boolean
  priority: number
}

interface IntegrationType {
  type: string
  name: string
  category: string
  description: string
  requiredFields: string[]
  optionalFields: string[]
}

interface HealthSummary {
  healthy: number
  degraded: number
  unhealthy: number
  averageLatencyMs: number
  totalEventsPerMinute: number
  totalErrorRate: number
  lastUpdated?: string
}

interface EnrichmentIntegration {
  id: string
  type: 'virustotal' | 'shodan' | 'passivetotal' | 'urlscan' | 'hybrid_analysis'
  name: string
  enabled: boolean
  stats: {
    queriesTotal: number
    queriesPerMinute: number
    cacheHitRate: number
    errors: number
    lastActivity?: string
  }
  health?: IntegrationHealthMetrics
}

interface CaseManagementIntegration {
  id: string
  type: 'thehive' | 'servicenow_secops' | 'jira_sm'
  name: string
  enabled: boolean
  stats: {
    casesCreated: number
    casesUpdated: number
    errors: number
    lastActivity?: string
  }
  health?: IntegrationHealthMetrics
}

interface IntegrationsProps {
  integrations: Integration[]
  routingRules: RoutingRule[]
  availableTypes: IntegrationType[]
  enrichmentIntegrations?: EnrichmentIntegration[]
  caseManagementIntegrations?: CaseManagementIntegration[]
  healthSummary?: HealthSummary
  stats?: {
    totalIntegrations: number
    enabledIntegrations: number
    totalAlertsSent: number
    totalEventsSent: number
  }
}

const categoryIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  siem: Server,
  soar: Shield,
  ticketing: Ticket,
  generic: Webhook,
  enrichment: Search,
  case_management: FileText,
}

const categoryLabels: Record<string, string> = {
  siem: 'SIEM',
  soar: 'SOAR',
  ticketing: 'Ticketing',
  generic: 'Generic',
  enrichment: 'Enrichment',
  case_management: 'Case Management',
}

const enrichmentTypeLabels: Record<string, string> = {
  virustotal: 'VirusTotal',
  shodan: 'Shodan',
  passivetotal: 'PassiveTotal',
  urlscan: 'URLScan.io',
  hybrid_analysis: 'Hybrid Analysis',
}

const caseManagementTypeLabels: Record<string, string> = {
  thehive: 'TheHive',
  servicenow_secops: 'ServiceNow SecOps',
  jira_sm: 'Jira Service Management',
}

function StatusBadge({ enabled, hasError }: { enabled: boolean; hasError: boolean }) {
  if (!enabled) {
    return (
      <span className="badge-sentinel badge-sentinel-default badge-sentinel-dot">
        <Pause className="h-3 w-3" />
        Disabled
      </span>
    )
  }

  if (hasError) {
    return (
      <span className="badge-sentinel badge-sentinel-error badge-sentinel-dot">
        <AlertTriangle className="h-3 w-3" />
        Error
      </span>
    )
  }

  return (
    <span className="badge-sentinel badge-sentinel-success badge-sentinel-dot">
      <CheckCircle className="h-3 w-3" />
      Active
    </span>
  )
}

function HealthStatusBadge({ healthy, degraded, enabled }: { healthy: boolean; degraded: boolean; enabled: boolean }) {
  if (!enabled) {
    return (
      <span className="badge-sentinel badge-sentinel-default badge-sentinel-dot">
        <Pause className="h-3 w-3" />
        Disabled
      </span>
    )
  }

  if (healthy) {
    return (
      <span className="badge-sentinel badge-sentinel-success badge-sentinel-dot">
        <CheckCircle className="h-3 w-3" />
        Healthy
      </span>
    )
  }

  if (degraded) {
    return (
      <span className="badge-sentinel badge-sentinel-warning badge-sentinel-dot">
        <AlertTriangle className="h-3 w-3" />
        Degraded
      </span>
    )
  }

  return (
    <span className="badge-sentinel badge-sentinel-error badge-sentinel-dot">
      <XCircle className="h-3 w-3" />
      Unhealthy
    </span>
  )
}

function TrendIndicator({ trend }: { trend: 'up' | 'down' | 'stable' }) {
  if (trend === 'up') {
    return <TrendingUp className="h-4 w-4" style={{ color: 'var(--crit)' }} />
  }
  if (trend === 'down') {
    return <TrendingDown className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
  }
  return <span className="h-4 w-4" style={{ color: 'var(--subtle)' }}>-</span>
}

function IntegrationHealthRow({ integration }: { integration: Integration }) {
  const health = integration.health
  const errorRate = health?.errorRate || 0
  const latency = health?.latencyMs || 0
  const isHealthy = errorRate < 0.01 && latency < 1000
  const isDegraded = errorRate >= 0.01 && errorRate < 0.05

  return (
    <tr>
      <td className="p-4">
        <div className="flex items-center gap-3">
          <div
            className="h-8 w-8 rounded-lg flex items-center justify-center"
            style={{ background: 'var(--surface-2)' }}
          >
            <Plug className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          </div>
          <div>
            <div className="font-medium" style={{ color: 'var(--fg)' }}>{integration.name}</div>
            <div className="text-xs" style={{ color: 'var(--subtle)' }}>{integration.type}</div>
          </div>
        </div>
      </td>
      <td className="p-4">
        <HealthStatusBadge healthy={isHealthy} degraded={isDegraded} enabled={integration.enabled} />
      </td>
      <td className="p-4">
        <div className="flex items-center gap-2">
          <span
            className="text-sm font-medium"
            style={{
              color: latency > 2000 ? 'var(--crit)' : latency > 1000 ? 'var(--high)' : 'var(--emerald-400)'
            }}
          >
            {latency.toFixed(0)}ms
          </span>
          {health?.latencyTrend && <TrendIndicator trend={health.latencyTrend} />}
        </div>
      </td>
      <td className="p-4">
        <div className="flex items-center gap-2">
          <span
            className="text-sm font-medium"
            style={{
              color: errorRate > 0.05 ? 'var(--crit)' : errorRate > 0.01 ? 'var(--high)' : 'var(--emerald-400)'
            }}
          >
            {(errorRate * 100).toFixed(2)}%
          </span>
          {health?.errorRateTrend && <TrendIndicator trend={health.errorRateTrend} />}
        </div>
      </td>
      <td className="p-4" style={{ color: 'var(--fg)' }}>{health?.eventsPerMinute?.toFixed(1) || 0}</td>
      <td className="p-4">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          <span
            className="text-sm"
            style={{ color: (health?.queueDepth || 0) > 1000 ? 'var(--high)' : 'var(--fg-2)' }}
          >
            {health?.queueDepth?.toLocaleString() || 0}
          </span>
        </div>
      </td>
      <td className="p-4">
        <div className="flex items-center gap-2">
          <div
            className="flex-1 h-2 rounded-full overflow-hidden max-w-[80px]"
            style={{ background: 'var(--surface-2)' }}
          >
            <div
              className="h-full rounded-full"
              style={{
                background: (health?.uptime || 0) > 99 ? 'var(--emerald-500)' : (health?.uptime || 0) > 95 ? 'var(--high)' : 'var(--crit)',
                width: `${health?.uptime || 0}%`
              }}
            />
          </div>
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{(health?.uptime || 0).toFixed(1)}%</span>
        </div>
      </td>
      <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>
        {health?.lastHealthCheck
          ? new Date(health.lastHealthCheck).toLocaleString()
          : 'Never'}
      </td>
    </tr>
  )
}

interface Toast {
  id: number
  type: 'success' | 'error'
  message: string
}

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={cn(
            'flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg border min-w-[320px]',
            toast.type === 'success'
              ? 'badge-sentinel-success'
              : 'badge-sentinel-error'
          )}
          style={{
            background: toast.type === 'success' ? 'var(--emerald-glow)' : 'var(--crit-bg)',
            borderColor: toast.type === 'success' ? 'var(--emerald-500)' : 'var(--crit)'
          }}
        >
          {toast.type === 'success' ? (
            <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
          ) : (
            <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
          )}
          <span className="text-sm flex-1" style={{ color: 'var(--fg)' }}>{toast.message}</span>
          <button onClick={() => onDismiss(toast.id)} style={{ color: 'var(--muted)' }} className="hover:opacity-80">
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  )
}

function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((type: 'success' | 'error', message: string) => {
    const id = Date.now() + Math.random()
    setToasts((prev) => [...prev, { id, type, message }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return { toasts, addToast, dismissToast }
}

export default function Integrations({
  integrations = [],
  routingRules = [],
  availableTypes = [],
  enrichmentIntegrations = [],
  caseManagementIntegrations = [],
  healthSummary,
  stats,
}: IntegrationsProps) {
  const [activeTab, setActiveTab] = useState<'integrations' | 'health' | 'routing' | 'logs'>('integrations')
  const [showAddModal, setShowAddModal] = useState(false)
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null)
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({
    siem: true,
    soar: true,
    ticketing: true,
    generic: true,
    enrichment: true,
    case_management: true,
  })
  const [healthData, setHealthData] = useState<HealthSummary | null>(healthSummary || null)
  const [refreshingHealth, setRefreshingHealth] = useState(false)
  const { toasts, addToast, dismissToast } = useToast()

  // Auto-refresh health data every 30 seconds when on health tab
  useEffect(() => {
    if (activeTab !== 'health') return

    const fetchHealth = async () => {
      try {
        const response = await fetch('/api/v1/integrations/health', {
          headers: { Accept: 'application/json' },
        })
        if (response.ok) {
          const data = await response.json()
          setHealthData(data)
        }
      } catch {
        // Silent fail for auto-refresh
      }
    }

    fetchHealth()
    const interval = setInterval(fetchHealth, 30000)
    return () => clearInterval(interval)
  }, [activeTab])

  const refreshHealthData = async () => {
    setRefreshingHealth(true)
    try {
      const response = await fetch('/api/v1/integrations/health', {
        headers: { Accept: 'application/json' },
      })
      if (response.ok) {
        const data = await response.json()
        setHealthData(data)
        addToast('success', 'Health data refreshed')
      } else {
        addToast('error', 'Failed to refresh health data')
      }
    } catch {
      addToast('error', 'Failed to refresh health data')
    } finally {
      setRefreshingHealth(false)
    }
  }

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => ({ ...prev, [category]: !prev[category] }))
  }

  // Group integrations by category
  const integrationsByCategory = integrations.reduce<Record<string, Integration[]>>((acc, integration) => {
    const typeInfo = availableTypes.find((t) => t.type === integration.type)
    const category = typeInfo?.category || 'generic'
    if (!acc[category]) acc[category] = []
    acc[category].push(integration)
    return acc
  }, {})

  const handleTestConnection = async (integrationId: string) => {
    try {
      const response = await fetch(`/api/v1/integrations/${integrationId}/test`, {
        method: 'POST',
        headers: { Accept: 'application/json' },
      })

      if (response.ok) {
        addToast('success', 'Connection test successful')
      } else {
        const data = await response.json()
        addToast('error', data.error || 'Connection test failed')
      }
    } catch {
      addToast('error', 'Failed to test connection')
    }
  }

  const handleToggleEnabled = async (integration: Integration) => {
    try {
      const response = await fetch(`/api/v1/integrations/${integration.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ enabled: !integration.enabled }),
      })

      if (response.ok) {
        addToast('success', `Integration ${integration.enabled ? 'disabled' : 'enabled'}`)
        // Reload page to reflect changes
        window.location.reload()
      } else {
        addToast('error', 'Failed to update integration')
      }
    } catch {
      addToast('error', 'Failed to update integration')
    }
  }

  const handleDelete = async (integrationId: string) => {
    if (!confirm('Are you sure you want to delete this integration?')) return

    try {
      const response = await fetch(`/api/v1/integrations/${integrationId}`, {
        method: 'DELETE',
        headers: { Accept: 'application/json' },
      })

      if (response.ok) {
        addToast('success', 'Integration deleted')
        window.location.reload()
      } else {
        addToast('error', 'Failed to delete integration')
      }
    } catch {
      addToast('error', 'Failed to delete integration')
    }
  }

  const defaultStats = stats || {
    totalIntegrations: integrations.length,
    enabledIntegrations: integrations.filter((i) => i.enabled).length,
    totalAlertsSent: 0,
    totalEventsSent: 0,
  }

  return (
    <MainLayout title="Integrations">
      <Head title="Integrations - Tamandua EDR" />
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center"
              style={{ background: 'var(--emerald-glow)' }}
            >
              <Plug className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.totalIntegrations}</div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Total Integrations</div>
            </div>
          </div>
        </div>

        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center"
              style={{ background: 'var(--emerald-glow)' }}
            >
              <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.enabledIntegrations}</div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Active</div>
            </div>
          </div>
        </div>

        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center"
              style={{ background: 'var(--med-bg)' }}
            >
              <Bell className="h-5 w-5" style={{ color: 'var(--med)' }} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                {(defaultStats.totalAlertsSent ?? 0).toLocaleString()}
              </div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Alerts Sent</div>
            </div>
          </div>
        </div>

        <div className="card-sentinel">
          <div className="flex items-center gap-3">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center"
              style={{ background: 'rgba(217, 70, 239, 0.12)' }}
            >
              <Activity className="h-5 w-5" style={{ color: 'var(--sol-magenta)' }} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                {(defaultStats.totalEventsSent ?? 0).toLocaleString()}
              </div>
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Events Sent</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-6">
        <div className="flex p-1 rounded-lg" style={{ background: 'var(--surface)' }}>
          <button
            onClick={() => setActiveTab('integrations')}
            className={cn(
              'px-4 py-2 rounded-md text-sm font-medium transition-colors',
              activeTab === 'integrations'
                ? 'btn-sentinel-primary'
                : ''
            )}
            style={activeTab !== 'integrations' ? { color: 'var(--muted)' } : {}}
          >
            Integrations
          </button>
          <button
            onClick={() => setActiveTab('health')}
            className={cn(
              'px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-2',
              activeTab === 'health'
                ? 'btn-sentinel-primary'
                : ''
            )}
            style={activeTab !== 'health' ? { color: 'var(--muted)' } : {}}
          >
            <Heart className="h-4 w-4" />
            Health
          </button>
          <button
            onClick={() => setActiveTab('routing')}
            className={cn(
              'px-4 py-2 rounded-md text-sm font-medium transition-colors',
              activeTab === 'routing'
                ? 'btn-sentinel-primary'
                : ''
            )}
            style={activeTab !== 'routing' ? { color: 'var(--muted)' } : {}}
          >
            Routing Rules
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            className={cn(
              'px-4 py-2 rounded-md text-sm font-medium transition-colors',
              activeTab === 'logs' ? 'btn-sentinel-primary' : ''
            )}
            style={activeTab !== 'logs' ? { color: 'var(--muted)' } : {}}
          >
            Logs
          </button>
        </div>

        <div className="flex-1" />

        <button
          onClick={() => setShowAddModal(true)}
          className="btn-sentinel btn-sentinel-primary"
        >
          <Plus className="h-4 w-4" />
          Add Integration
        </button>
      </div>

      {/* Integrations Tab */}
      {activeTab === 'integrations' && (
        <div className="space-y-4">
          {Object.entries(categoryLabels).map(([category, label]) => {
            const categoryIntegrations = integrationsByCategory[category] || []
            const CategoryIcon = categoryIcons[category] || Plug

            return (
              <div key={category} className="card-sentinel" style={{ padding: 0 }}>
                <button
                  onClick={() => toggleCategory(category)}
                  className="flex items-center gap-3 w-full p-4 text-left transition-colors rounded-t-lg"
                  style={{ background: 'transparent' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <CategoryIcon className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                  <span className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{label}</span>
                  <span className="text-sm" style={{ color: 'var(--subtle)' }}>({categoryIntegrations.length})</span>
                  <div className="flex-1" />
                  {expandedCategories[category] ? (
                    <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                  ) : (
                    <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                  )}
                </button>

                {expandedCategories[category] && (
                  <div style={{ borderTop: '1px solid var(--border)' }}>
                    {categoryIntegrations.length === 0 ? (
                      <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                        No {label} integrations configured
                      </div>
                    ) : (
                      <div style={{ borderColor: 'var(--border)' }}>
                        {categoryIntegrations.map((integration, index) => (
                          <div key={integration.id} style={index > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
                            <IntegrationRow
                              integration={integration}
                              onTest={() => handleTestConnection(integration.id)}
                              onToggle={() => handleToggleEnabled(integration)}
                              onEdit={() => setSelectedIntegration(integration)}
                              onDelete={() => handleDelete(integration.id)}
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Health Dashboard Tab */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          {/* Health Summary Cards */}
          <div className="grid grid-cols-6 gap-4">
            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'var(--emerald-glow)' }}
                >
                  <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{healthData?.healthy || 0}</div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Healthy</div>
                </div>
              </div>
            </div>

            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'var(--high-bg)' }}
                >
                  <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{healthData?.degraded || 0}</div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Degraded</div>
                </div>
              </div>
            </div>

            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'var(--crit-bg)' }}
                >
                  <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{healthData?.unhealthy || 0}</div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Unhealthy</div>
                </div>
              </div>
            </div>

            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'var(--med-bg)' }}
                >
                  <Clock className="h-5 w-5" style={{ color: 'var(--med)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {healthData?.averageLatencyMs?.toFixed(0) || 0}ms
                  </div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Avg Latency</div>
                </div>
              </div>
            </div>

            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'rgba(217, 70, 239, 0.12)' }}
                >
                  <Zap className="h-5 w-5" style={{ color: 'var(--sol-magenta)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {healthData?.totalEventsPerMinute?.toFixed(1) || 0}
                  </div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Events/min</div>
                </div>
              </div>
            </div>

            <div className="card-sentinel">
              <div className="flex items-center gap-3">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'var(--high-bg)' }}
                >
                  <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {((healthData?.totalErrorRate || 0) * 100).toFixed(2)}%
                  </div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>Error Rate</div>
                </div>
              </div>
            </div>
          </div>

          {/* SOAR & SIEM Health */}
          <div className="card-sentinel" style={{ padding: 0 }}>
            <div
              className="p-4 flex items-center justify-between"
              style={{ borderBottom: '1px solid var(--border)' }}
            >
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>SOAR & SIEM Integrations</h2>
              </div>
              <button
                onClick={refreshHealthData}
                disabled={refreshingHealth}
                className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
              >
                <RefreshCw className={cn('h-4 w-4', refreshingHealth && 'animate-spin')} />
                Refresh
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Integration</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Latency</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Error Rate</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Events/min</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Queue</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Uptime</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Last Check</th>
                  </tr>
                </thead>
                <tbody>
                  {integrations.filter(i => i.enabled).map((integration, index) => (
                    <tr key={integration.id} style={index > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
                      <IntegrationHealthRow integration={integration} />
                    </tr>
                  ))}
                  {integrations.filter(i => i.enabled).length === 0 && (
                    <tr>
                      <td colSpan={8} className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                        No active integrations
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Enrichment Services Health */}
          <div className="card-sentinel" style={{ padding: 0 }}>
            <div className="p-4 flex items-center gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
              <Search className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Enrichment Services</h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Service</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Queries Total</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Queries/min</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Cache Hit Rate</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Errors</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Last Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {enrichmentIntegrations.map((enrichment, index) => (
                    <tr key={enrichment.id} style={index > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div
                            className="h-8 w-8 rounded-lg flex items-center justify-center"
                            style={{ background: 'var(--surface-2)' }}
                          >
                            <Search className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          </div>
                          <div>
                            <div className="font-medium" style={{ color: 'var(--fg)' }}>
                              {enrichmentTypeLabels[enrichment.type] || enrichment.name}
                            </div>
                            <div className="text-xs" style={{ color: 'var(--subtle)' }}>{enrichment.type}</div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <HealthStatusBadge
                          healthy={enrichment.enabled && (enrichment.stats?.errors || 0) === 0}
                          degraded={enrichment.enabled && (enrichment.stats?.errors || 0) > 0}
                          enabled={enrichment.enabled}
                        />
                      </td>
                      <td className="p-4" style={{ color: 'var(--fg)' }}>{enrichment.stats?.queriesTotal?.toLocaleString() || 0}</td>
                      <td className="p-4" style={{ color: 'var(--fg)' }}>{enrichment.stats?.queriesPerMinute?.toFixed(1) || 0}</td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <div
                            className="flex-1 h-2 rounded-full overflow-hidden"
                            style={{ background: 'var(--surface-2)' }}
                          >
                            <div
                              className="h-full rounded-full"
                              style={{
                                background: 'var(--emerald-500)',
                                width: `${(enrichment.stats?.cacheHitRate || 0) * 100}%`
                              }}
                            />
                          </div>
                          <span className="text-sm" style={{ color: 'var(--muted)' }}>
                            {((enrichment.stats?.cacheHitRate || 0) * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="p-4">
                        <span
                          className="text-sm"
                          style={{ color: (enrichment.stats?.errors || 0) > 0 ? 'var(--crit)' : 'var(--muted)' }}
                        >
                          {enrichment.stats?.errors || 0}
                        </span>
                      </td>
                      <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>
                        {enrichment.stats?.lastActivity
                          ? new Date(enrichment.stats.lastActivity).toLocaleString()
                          : 'Never'}
                      </td>
                    </tr>
                  ))}
                  {enrichmentIntegrations.length === 0 && (
                    <tr>
                      <td colSpan={7} className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                        No enrichment services configured
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Case Management Health */}
          <div className="card-sentinel" style={{ padding: 0 }}>
            <div className="p-4 flex items-center gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
              <FileText className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Case Management</h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Service</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Cases Created</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Cases Updated</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Errors</th>
                    <th className="text-left text-sm font-medium p-4" style={{ color: 'var(--muted)' }}>Last Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {caseManagementIntegrations.map((cm, index) => (
                    <tr key={cm.id} style={index > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div
                            className="h-8 w-8 rounded-lg flex items-center justify-center"
                            style={{ background: 'var(--surface-2)' }}
                          >
                            <FileText className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          </div>
                          <div>
                            <div className="font-medium" style={{ color: 'var(--fg)' }}>
                              {caseManagementTypeLabels[cm.type] || cm.name}
                            </div>
                            <div className="text-xs" style={{ color: 'var(--subtle)' }}>{cm.type}</div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <HealthStatusBadge
                          healthy={cm.enabled && (cm.stats?.errors || 0) === 0}
                          degraded={cm.enabled && (cm.stats?.errors || 0) > 0}
                          enabled={cm.enabled}
                        />
                      </td>
                      <td className="p-4" style={{ color: 'var(--fg)' }}>{cm.stats?.casesCreated?.toLocaleString() || 0}</td>
                      <td className="p-4" style={{ color: 'var(--fg)' }}>{cm.stats?.casesUpdated?.toLocaleString() || 0}</td>
                      <td className="p-4">
                        <span
                          className="text-sm"
                          style={{ color: (cm.stats?.errors || 0) > 0 ? 'var(--crit)' : 'var(--muted)' }}
                        >
                          {cm.stats?.errors || 0}
                        </span>
                      </td>
                      <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>
                        {cm.stats?.lastActivity
                          ? new Date(cm.stats.lastActivity).toLocaleString()
                          : 'Never'}
                      </td>
                    </tr>
                  ))}
                  {caseManagementIntegrations.length === 0 && (
                    <tr>
                      <td colSpan={6} className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                        No case management integrations configured
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Last Updated */}
          {healthData?.lastUpdated && (
            <div className="text-center text-sm" style={{ color: 'var(--subtle)' }}>
              Last updated: {new Date(healthData.lastUpdated).toLocaleString()}
            </div>
          )}
        </div>
      )}

      {/* Routing Rules Tab */}
      {activeTab === 'routing' && (
        <div className="card-sentinel" style={{ padding: 0 }}>
          <div
            className="p-4 flex items-center justify-between"
            style={{ borderBottom: '1px solid var(--border)' }}
          >
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Routing Rules</h2>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                Configure which alerts are sent to which integrations
              </p>
            </div>
            <button className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm">
              <Plus className="h-4 w-4" />
              Add Rule
            </button>
          </div>

          {routingRules.length === 0 ? (
            <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
              No routing rules configured. Default routing will be used.
            </div>
          ) : (
            <div>
              {routingRules.map((rule, index) => (
                <div
                  key={rule.id}
                  className="p-4 flex items-center gap-4"
                  style={index > 0 ? { borderTop: '1px solid var(--border)' } : {}}
                >
                  <div
                    className="h-3 w-3 rounded-full"
                    style={{ background: rule.enabled ? 'var(--emerald-500)' : 'var(--subtle)' }}
                  />
                  <div className="flex-1">
                    <div className="font-medium" style={{ color: 'var(--fg)' }}>{rule.name}</div>
                    <div className="text-sm" style={{ color: 'var(--muted)' }}>
                      {rule.conditions.length} condition(s) | {rule.destinations.length} destination(s)
                    </div>
                  </div>
                  <div className="text-sm" style={{ color: 'var(--subtle)' }}>Priority: {rule.priority}</div>
                  <button
                    className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
                  >
                    <Settings className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <div className="card-sentinel" style={{ padding: 0 }}>
          <div
            className="p-4 flex items-center justify-between"
            style={{ borderBottom: '1px solid var(--border)' }}
          >
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Integration Logs</h2>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Recent activity and errors from integrations</p>
            </div>
            <button className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>

          <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
            Integration logs will appear here
          </div>
        </div>
      )}

      {/* Add Integration Modal */}
      {showAddModal && (
        <AddIntegrationModal
          availableTypes={availableTypes}
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false)
            addToast('success', 'Integration added successfully')
            window.location.reload()
          }}
        />
      )}

      {/* Edit Integration Modal */}
      {selectedIntegration && (
        <EditIntegrationModal
          integration={selectedIntegration}
          onClose={() => setSelectedIntegration(null)}
          onSuccess={() => {
            setSelectedIntegration(null)
            addToast('success', 'Integration updated successfully')
            window.location.reload()
          }}
        />
      )}
    </MainLayout>
  )
}

function IntegrationRow({
  integration,
  onTest,
  onToggle,
  onEdit,
  onDelete,
}: {
  integration: Integration
  onTest: () => void
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const [testing, setTesting] = useState(false)

  const handleTest = async () => {
    setTesting(true)
    await onTest()
    setTesting(false)
  }

  return (
    <div className="p-4 flex items-center gap-4">
      <div
        className="h-10 w-10 rounded-lg flex items-center justify-center"
        style={{ background: 'var(--surface-2)' }}
      >
        <Plug className="h-5 w-5" style={{ color: 'var(--muted)' }} />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium" style={{ color: 'var(--fg)' }}>{integration.name}</span>
          <span className="text-xs uppercase" style={{ color: 'var(--subtle)' }}>{integration.type}</span>
        </div>
        {integration.description && (
          <div className="text-sm truncate" style={{ color: 'var(--muted)' }}>{integration.description}</div>
        )}
        {integration.lastError && (
          <div className="text-sm truncate" style={{ color: 'var(--crit)' }}>Error: {integration.lastError}</div>
        )}
      </div>

      <StatusBadge enabled={integration.enabled} hasError={!!integration.lastError} />

      {integration.stats?.lastActivity && (
        <div className="text-sm" style={{ color: 'var(--subtle)' }}>
          Last activity: {new Date(integration.stats.lastActivity).toLocaleString()}
        </div>
      )}

      <div className="flex items-center gap-1">
        <button
          onClick={handleTest}
          disabled={testing}
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          title="Test Connection"
        >
          {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
        </button>
        <button
          onClick={onToggle}
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          title={integration.enabled ? 'Disable' : 'Enable'}
        >
          {integration.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </button>
        <button
          onClick={onEdit}
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          title="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
        <button
          onClick={onDelete}
          className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          style={{ color: 'var(--crit)' }}
          title="Delete"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

function AddIntegrationModal({
  availableTypes,
  onClose,
  onSuccess,
}: {
  availableTypes: IntegrationType[]
  onClose: () => void
  onSuccess: () => void
}) {
  const [selectedType, setSelectedType] = useState<IntegrationType | null>(null)
  const [formData, setFormData] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedType) return

    setSaving(true)
    try {
      const response = await fetch('/api/v1/integrations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          type: selectedType.type,
          name: formData.name || selectedType.name,
          config: formData,
        }),
      })

      if (response.ok) {
        onSuccess()
      } else {
        alert('Failed to create integration')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0, 0, 0, 0.5)' }}>
      <div
        className="card-sentinel w-full max-w-2xl max-h-[80vh] overflow-hidden"
        style={{ padding: 0 }}
      >
        <div
          className="p-4 flex items-center justify-between"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Add Integration</h2>
          <button onClick={onClose} className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon">
            <XCircle className="h-5 w-5" />
          </button>
        </div>

        <div className="p-4 overflow-y-auto max-h-[60vh]">
          {!selectedType ? (
            <div className="grid grid-cols-2 gap-4">
              {availableTypes.map((type) => {
                const CategoryIcon = categoryIcons[type.category] || Plug
                return (
                  <button
                    key={type.type}
                    onClick={() => setSelectedType(type)}
                    className="card-sentinel card-sentinel-interactive text-left"
                  >
                    <div className="flex items-center gap-3 mb-2">
                      <CategoryIcon className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{type.name}</span>
                    </div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>{type.description}</p>
                    <div className="mt-2 text-xs uppercase" style={{ color: 'var(--subtle)' }}>
                      {categoryLabels[type.category] || type.category}
                    </div>
                  </button>
                )
              })}
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <button
                  type="button"
                  onClick={() => setSelectedType(null)}
                  style={{ color: 'var(--muted)' }}
                  className="hover:opacity-80"
                >
                  &larr; Back
                </button>
                <span className="font-medium" style={{ color: 'var(--fg)' }}>{selectedType.name}</span>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>Name</label>
                <input
                  type="text"
                  value={formData.name || ''}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder={selectedType.name}
                  className="input-sentinel"
                />
              </div>

              {selectedType.requiredFields.map((field) => (
                <div key={field}>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    {field.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                    <span style={{ color: 'var(--crit)' }} className="ml-1">*</span>
                  </label>
                  <input
                    type={field.includes('password') || field.includes('secret') || field.includes('token') || field.includes('key') ? 'password' : 'text'}
                    value={formData[field] || ''}
                    onChange={(e) => setFormData({ ...formData, [field]: e.target.value })}
                    required
                    className="input-sentinel"
                  />
                </div>
              ))}

              {selectedType.optionalFields.map((field) => (
                <div key={field}>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    {field.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                  </label>
                  <input
                    type={field.includes('password') || field.includes('secret') || field.includes('token') || field.includes('key') ? 'password' : 'text'}
                    value={formData[field] || ''}
                    onChange={(e) => setFormData({ ...formData, [field]: e.target.value })}
                    className="input-sentinel"
                  />
                </div>
              ))}

              <div className="flex justify-end gap-3 pt-4">
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
                  className="btn-sentinel btn-sentinel-primary"
                >
                  {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                  Add Integration
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}

function EditIntegrationModal({
  integration,
  onClose,
  onSuccess,
}: {
  integration: Integration
  onClose: () => void
  onSuccess: () => void
}) {
  const [formData, setFormData] = useState<Record<string, unknown>>(integration.config || {})
  const [saving, setSaving] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    try {
      const response = await fetch(`/api/v1/integrations/${integration.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ config: formData }),
      })

      if (response.ok) {
        onSuccess()
      } else {
        alert('Failed to update integration')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0, 0, 0, 0.5)' }}>
      <div className="card-sentinel w-full max-w-lg" style={{ padding: 0 }}>
        <div
          className="p-4 flex items-center justify-between"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Edit {integration.name}</h2>
          <button onClick={onClose} className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon">
            <XCircle className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {Object.entries(integration.config || {}).map(([key, value]) => (
            <div key={key}>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                {key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
              </label>
              <input
                type={key.includes('password') || key.includes('secret') || key.includes('token') || key.includes('key') ? 'password' : 'text'}
                value={String(formData[key] || '')}
                onChange={(e) => setFormData({ ...formData, [key]: e.target.value })}
                className="input-sentinel"
              />
            </div>
          ))}

          <div className="flex justify-end gap-3 pt-4">
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
              className="btn-sentinel btn-sentinel-primary"
            >
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
