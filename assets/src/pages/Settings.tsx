import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Settings as SettingsIcon,
  Shield,
  Bell,
  Database,
  Globe,
  Server,
  Save,
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react'
import { Checkbox } from '@/components/ui/baseui'
import { cn } from '@/lib/utils'
import { useState, useCallback } from 'react'

interface NotificationsConfig {
  emailEnabled: boolean
  emailRecipients: string[]
  slackEnabled: boolean
  slackWebhook: string | null
  webhookEnabled: boolean
  webhookUrl: string | null
  criticalAlerts: boolean
  highAlerts: boolean
  mediumAlerts: boolean
}

interface UserInfo {
  id: string
  email: string
  name: string | null
  role: string
}

interface SettingsProps {
  config: {
    agentHeartbeatInterval: number
    telemetryBatchSize: number
    telemetryBatchTimeout: number
    mlEnabled: boolean
    mlThreshold: number
    autoResponseEnabled: boolean
    alertRetentionDays: number
    eventRetentionDays: number
  }
  notifications?: NotificationsConfig
  integrations: Array<{
    id: string
    name: string
    type: string
    enabled: boolean
    lastSync?: string
  }>
  system?: {
    version: string
    uptime: number
    hostname: string
    erlangVersion: string
    memoryUsed: number
    processCount: number
  }
  stats?: {
    totalAgents: number
    totalEvents: number
    totalAlerts: number
    dbSize: string
  }
  user?: UserInfo | null
}

const tabs = [
  { id: 'general', name: 'General', icon: SettingsIcon },
  { id: 'detection', name: 'Detection', icon: Shield },
  { id: 'notifications', name: 'Notifications', icon: Bell },
  { id: 'integrations', name: 'Integrations', icon: Globe },
  { id: 'system', name: 'System', icon: Server },
]

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
            'flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg border min-w-[320px] animate-in slide-in-from-right',
            toast.type === 'success'
              ? 'bg-green-900/90 border-green-700 text-green-100'
              : 'bg-red-900/90 border-red-700 text-red-100'
          )}
        >
          {toast.type === 'success' ? (
            <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
          ) : (
            <XCircle className="h-5 w-5 text-red-400 flex-shrink-0" />
          )}
          <span className="text-sm flex-1">{toast.message}</span>
          <button
            onClick={() => onDismiss(toast.id)}
            className="hover:text-white ml-2 flex-shrink-0"
            style={{ color: 'var(--muted)' }}
          >
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

async function postSettings(section: string, data: Record<string, unknown>): Promise<void> {
  const response = await fetch(`/api/v1/settings/${section}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    let errorMessage = `Failed to save settings (status ${response.status})`
    try {
      const errorData = await response.json()
      if (errorData.error) {
        errorMessage = errorData.error
      } else if (errorData.message) {
        errorMessage = errorData.message
      }
    } catch {
      // Use default error message
    }
    throw new Error(errorMessage)
  }
}

export default function Settings({ config, notifications, integrations, system, stats, user }: SettingsProps) {
  const [activeTab, setActiveTab] = useState('general')
  const { toasts, addToast, dismissToast } = useToast()

  // Support both 'system' (from backend) and 'stats' (legacy) props
  const systemStats = stats || (system ? {
    totalAgents: system.processCount || 0,
    totalEvents: 0,
    totalAlerts: 0,
    dbSize: `${system.memoryUsed} MB`,
  } : undefined)

  return (
    <MainLayout title="Settings">
      <Head title="Settings - Tamandua EDR" />
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="flex gap-6">
        {/* Sidebar Tabs */}
        <div className="w-48 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-3 w-full px-3 py-2 text-sm font-medium rounded-lg transition-colors',
                  activeTab === tab.id
                    ? 'text-white'
                    : 'hover:text-white'
                )}
                style={{
                  backgroundColor: activeTab === tab.id ? 'var(--emerald-400)' : 'transparent',
                  color: activeTab === tab.id ? 'white' : 'var(--muted)',
                }}
              >
                <tab.icon className="h-5 w-5" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'general' && <GeneralSettings config={config} addToast={addToast} />}
          {activeTab === 'detection' && <DetectionSettings config={config} addToast={addToast} />}
          {activeTab === 'notifications' && <NotificationSettings notifications={notifications} user={user} addToast={addToast} />}
          {activeTab === 'integrations' && <IntegrationSettings integrations={integrations} addToast={addToast} />}
          {activeTab === 'system' && <SystemSettings stats={systemStats} config={config} addToast={addToast} />}
        </div>
      </div>
    </MainLayout>
  )
}

interface SectionProps {
  addToast: (type: 'success' | 'error', message: string) => void
}

function GeneralSettings({ config, addToast }: { config: SettingsProps['config'] } & SectionProps) {
  const [data, setData] = useState({
    agentHeartbeatInterval: config?.agentHeartbeatInterval || 30,
    telemetryBatchSize: config?.telemetryBatchSize || 100,
    telemetryBatchTimeout: config?.telemetryBatchTimeout || 5,
  })
  const [saving, setSaving] = useState(false)

  const handleChange = <K extends keyof typeof data>(key: K, value: typeof data[K]) => {
    setData((prev) => ({ ...prev, [key]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await postSettings('general', data)
      addToast('success', 'General settings saved successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save general settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="rounded-xl"
      style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
    >
      <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>General Settings</h2>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Configure basic agent and telemetry settings</p>
      </div>

      <form onSubmit={handleSubmit} className="p-6 space-y-6">
        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
              Agent Heartbeat Interval (seconds)
            </label>
            <input
              type="number"
              value={data.agentHeartbeatInterval}
              onChange={(e) => handleChange('agentHeartbeatInterval', parseInt(e.target.value) || 0)}
              disabled={saving}
              className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 focus:border-transparent disabled:opacity-50"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>How often agents send heartbeat signals</p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
              Telemetry Batch Size
            </label>
            <input
              type="number"
              value={data.telemetryBatchSize}
              onChange={(e) => handleChange('telemetryBatchSize', parseInt(e.target.value) || 0)}
              disabled={saving}
              className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 focus:border-transparent disabled:opacity-50"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Max events per batch</p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
              Batch Timeout (seconds)
            </label>
            <input
              type="number"
              value={data.telemetryBatchTimeout}
              onChange={(e) => handleChange('telemetryBatchTimeout', parseInt(e.target.value) || 0)}
              disabled={saving}
              className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 focus:border-transparent disabled:opacity-50"
            />
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Max time before sending partial batch</p>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </form>
    </div>
  )
}

function DetectionSettings({ config, addToast }: { config: SettingsProps['config'] } & SectionProps) {
  const [mlEnabled, setMlEnabled] = useState(config?.mlEnabled ?? true)
  const [autoResponse, setAutoResponse] = useState(config?.autoResponseEnabled ?? false)
  const [mlThreshold, setMlThreshold] = useState(config?.mlThreshold ?? 0.7)
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    try {
      await postSettings('detection', {
        mlEnabled,
        mlThreshold,
        autoResponseEnabled: autoResponse,
      })
      addToast('success', 'Detection settings saved successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save detection settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>ML Detection</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Configure machine learning detection settings</p>
        </div>

        <div className="p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Enable ML Detection</h3>
              <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>Use Malware-SMELL for zero-shot malware detection</p>
            </div>
            <button
              type="button"
              onClick={() => setMlEnabled(!mlEnabled)}
              disabled={saving}
              className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors disabled:opacity-50"
              style={{ backgroundColor: mlEnabled ? 'var(--emerald-400)' : 'var(--border)' }}
            >
              <span
                className={cn(
                  'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                  mlEnabled ? 'translate-x-6' : 'translate-x-1'
                )}
              />
            </button>
          </div>

          {mlEnabled && (
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
                ML Confidence Threshold: {mlThreshold}
              </label>
              <input
                type="range"
                min="0.1"
                max="0.99"
                step="0.01"
                value={mlThreshold}
                onChange={(e) => setMlThreshold(parseFloat(e.target.value))}
                disabled={saving}
                className="w-full disabled:opacity-50"
              />
              <div className="flex justify-between text-xs mt-1" style={{ color: 'var(--muted)' }}>
                <span>More alerts</span>
                <span>Fewer false positives</span>
              </div>
            </div>
          )}
        </div>
      </div>

      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Automated Response</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            Global preference only. Endpoint blocking is governed by Prevention Policies and per-alert approvals.
          </p>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Enable Auto-Response Recommendations</h3>
              <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
                Allows the response engine to recommend or execute actions only when the active prevention policy permits it.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setAutoResponse(!autoResponse)}
              disabled={saving}
              className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors disabled:opacity-50"
              style={{ backgroundColor: autoResponse ? 'var(--emerald-400)' : 'var(--border)' }}
            >
              <span
                className={cn(
                  'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                  autoResponse ? 'translate-x-6' : 'translate-x-1'
                )}
              />
            </button>
          </div>

          {autoResponse && (
            <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
              <p className="text-sm text-yellow-300">
                <strong>Warning:</strong> Automatic execution still depends on the effective prevention policy,
                thresholds, exclusions, and approval rules. Review policies before enabling this globally.
              </p>
              <button
                type="button"
                onClick={() => router.visit('/app/prevention-policies')}
                className="mt-3 text-sm font-medium underline"
                style={{ color: 'var(--med)' }}
              >
                Open Prevention Policies
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function NotificationSettings({ notifications, user, addToast }: { notifications?: NotificationsConfig; user?: UserInfo | null } & SectionProps) {
  const [emailNotifications, setEmailNotifications] = useState<Record<string, boolean>>({
    'Critical alerts': notifications?.criticalAlerts ?? true,
    'High severity alerts': notifications?.highAlerts ?? false,
    'Daily digest': false,
    'Weekly report': false,
  })
  const [slackWebhookUrl, setSlackWebhookUrl] = useState(
    notifications?.slackWebhook === '***configured***' ? '' : (notifications?.slackWebhook || '')
  )
  const [saving, setSaving] = useState(false)

  const toggleEmailNotification = (item: string) => {
    setEmailNotifications((prev) => ({ ...prev, [item]: !prev[item] }))
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await postSettings('notifications', {
        emailNotifications,
        slackWebhookUrl,
      })
      addToast('success', 'Notification settings saved successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save notification settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Notification Settings</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Configure alert notifications and integrations</p>
        </div>

        <div className="p-6 space-y-6">
          <div className="space-y-4">
            <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Email Notifications</h3>
            <div className="space-y-3">
              {Object.keys(emailNotifications).map((item) => (
                <Checkbox
                  key={item}
                  checked={emailNotifications[item]}
                  onCheckedChange={() => toggleEmailNotification(item)}
                  disabled={saving}
                  label={item}
                />
              ))}
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Slack Integration</h3>
            <div>
              <label className="block text-sm mb-2" style={{ color: 'var(--fg)' }}>Webhook URL</label>
              <input
                type="text"
                value={slackWebhookUrl}
                onChange={(e) => setSlackWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                disabled={saving}
                className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 focus:border-transparent disabled:opacity-50"
              />
              {notifications?.slackEnabled && notifications?.slackWebhook === '***configured***' && (
                <p className="text-xs mt-1" style={{ color: 'var(--emerald-400)' }}>Slack webhook is configured</p>
              )}
            </div>
          </div>

          {user && (
            <div className="space-y-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
              <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Notification Recipient</h3>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                Notifications will be sent to: <span style={{ color: 'var(--fg)' }}>{user.email}</span>
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function IntegrationSettings({ integrations, addToast }: { integrations: SettingsProps['integrations'] } & SectionProps) {
  const defaultIntegrations = integrations || [
    { id: '1', name: 'VirusTotal', type: 'threat-intel', enabled: false },
    { id: '2', name: 'AbuseIPDB', type: 'threat-intel', enabled: false },
    { id: '3', name: 'MISP', type: 'threat-intel', enabled: false },
    { id: '4', name: 'Splunk', type: 'siem', enabled: false },
    { id: '5', name: 'Elasticsearch', type: 'siem', enabled: false },
  ]

  const [integrationStates, setIntegrationStates] = useState(
    defaultIntegrations.map((i) => ({ ...i }))
  )
  const [saving, setSaving] = useState(false)

  const toggleIntegration = (id: string) => {
    setIntegrationStates((prev) =>
      prev.map((i) => (i.id === id ? { ...i, enabled: !i.enabled } : i))
    )
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await postSettings('integrations', {
        integrations: integrationStates.map(({ id, enabled }) => ({ id, enabled })),
      })
      addToast('success', 'Integration settings saved successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save integration settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Integrations</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Connect external services and threat intelligence feeds</p>
        </div>

        <div>
          {integrationStates.map((integration, index) => (
            <div
              key={integration.id}
              className="flex items-center justify-between p-4"
              style={{ borderTop: index > 0 ? '1px solid var(--border)' : undefined }}
            >
              <div className="flex items-center gap-4">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: 'var(--border)' }}
                >
                  <Globe className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                </div>
                <div>
                  <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{integration.name}</h3>
                  <p className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{integration.type.replace('-', ' ')}</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                {integration.lastSync && (
                  <span className="text-xs" style={{ color: 'var(--muted)' }}>Last sync: {integration.lastSync}</span>
                )}
                <button
                  type="button"
                  onClick={() => toggleIntegration(integration.id)}
                  disabled={saving}
                  className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors disabled:opacity-50"
                  style={{ backgroundColor: integration.enabled ? 'var(--emerald-400)' : 'var(--border)' }}
                >
                  <span
                    className={cn(
                      'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                      integration.enabled ? 'translate-x-6' : 'translate-x-1'
                    )}
                  />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function SystemSettings({ stats, config, addToast }: { stats: SettingsProps['stats']; config: SettingsProps['config'] } & SectionProps) {
  const defaultStats = stats || {
    totalAgents: 0,
    totalEvents: 0,
    totalAlerts: 0,
    dbSize: '0 MB',
  }

  const [eventRetentionDays, setEventRetentionDays] = useState(config?.eventRetentionDays || 30)
  const [alertRetentionDays, setAlertRetentionDays] = useState(config?.alertRetentionDays || 90)
  const [saving, setSaving] = useState(false)
  const [reloadingRules, setReloadingRules] = useState(false)
  const [clearingCache, setClearingCache] = useState(false)

  const handleSaveRetention = async () => {
    setSaving(true)
    try {
      await postSettings('system', {
        eventRetentionDays,
        alertRetentionDays,
      })
      addToast('success', 'System settings saved successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save system settings.')
    } finally {
      setSaving(false)
    }
  }

  const handleReloadRules = async () => {
    setReloadingRules(true)
    try {
      const response = await fetch('/api/v1/settings/reload-rules', {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
      })
      if (!response.ok) {
        throw new Error(`Failed to reload rules (status ${response.status})`)
      }
      addToast('success', 'Detection rules reloaded successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to reload detection rules.')
    } finally {
      setReloadingRules(false)
    }
  }

  const handleClearCache = async () => {
    setClearingCache(true)
    try {
      const response = await fetch('/api/v1/settings/clear-cache', {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
      })
      if (!response.ok) {
        throw new Error(`Failed to clear cache (status ${response.status})`)
      }
      addToast('success', 'Event cache cleared successfully.')
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to clear event cache.')
    } finally {
      setClearingCache(false)
    }
  }

  return (
    <div className="space-y-6">
      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>System Status</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>View system statistics and health</p>
        </div>

        <div className="p-6 grid grid-cols-2 gap-4">
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--border)' }}>
            <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.totalAgents}</div>
            <div className="text-sm" style={{ color: 'var(--muted)' }}>Total Agents</div>
          </div>
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--border)' }}>
            <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.totalEvents.toLocaleString()}</div>
            <div className="text-sm" style={{ color: 'var(--muted)' }}>Total Events</div>
          </div>
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--border)' }}>
            <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.totalAlerts}</div>
            <div className="text-sm" style={{ color: 'var(--muted)' }}>Total Alerts</div>
          </div>
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--border)' }}>
            <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{defaultStats.dbSize}</div>
            <div className="text-sm" style={{ color: 'var(--muted)' }}>Database Size</div>
          </div>
        </div>
      </div>

      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Data Retention</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Configure how long data is kept</p>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
                Event Retention (days)
              </label>
              <input
                type="number"
                value={eventRetentionDays}
                onChange={(e) => setEventRetentionDays(parseInt(e.target.value) || 0)}
                disabled={saving}
                className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>
                Alert Retention (days)
              </label>
              <input
                type="number"
                value={alertRetentionDays}
                onChange={(e) => setAlertRetentionDays(parseInt(e.target.value) || 0)}
                disabled={saving}
                className="input-sentinel w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={handleSaveRetention}
              disabled={saving}
              className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>

      <div
        className="rounded-xl"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="p-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Maintenance</h2>
        </div>

        <div className="p-6 space-y-4">
          <button
            type="button"
            onClick={handleReloadRules}
            disabled={reloadingRules}
            className="flex items-center gap-2 px-4 py-2 rounded-lg disabled:opacity-50 transition-colors"
            style={{
              backgroundColor: 'var(--border)',
              color: 'var(--fg)',
            }}
          >
            {reloadingRules ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            {reloadingRules ? 'Reloading...' : 'Reload Detection Rules'}
          </button>
          <button
            type="button"
            onClick={handleClearCache}
            disabled={clearingCache}
            className="flex items-center gap-2 px-4 py-2 rounded-lg disabled:opacity-50 transition-colors"
            style={{
              backgroundColor: 'var(--border)',
              color: 'var(--fg)',
            }}
          >
            {clearingCache ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
            {clearingCache ? 'Clearing...' : 'Clear Event Cache'}
          </button>
        </div>
      </div>
    </div>
  )
}
