import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  MessageSquare,
  Shield,
  AlertTriangle,
  Eye,
  Clock,
  TrendingUp,
  Lock,
  Search,
  Download,
} from 'lucide-react'
import { useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'

interface DLPAlert {
  id: string
  platform: 'slack' | 'teams' | 'discord'
  channel: string
  user: string
  timestamp: string
  alertType: 'pii' | 'credential' | 'ip' | 'sensitive_file' | 'malicious_link'
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  content_preview: string
  status: 'open' | 'resolved' | 'false_positive'
}

interface PolicyViolation {
  id: string
  policy: string
  violations: number
  lastViolation: string
  trend: 'up' | 'down' | 'stable'
}

interface SecurityEvent {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  platform: string
  user: string
  timestamp: string
  description: string
  status: 'open' | 'resolved' | 'investigating'
}

interface SharingRisk {
  id: string
  type: 'external_share' | 'public_link' | 'guest_access'
  platform: string
  resource: string
  sharedWith: string
  createdAt: string
  riskLevel: 'high' | 'medium' | 'low'
}

interface ExternalSharing {
  id: string
  resource: string
  sharedWith: string
  platform: string
  accessLevel: 'view' | 'edit' | 'admin'
  expiresAt: string | null
}

interface CollaborationPolicy {
  id: string
  name: string
  description: string
  enabled: boolean
  violationCount: number
  lastViolation: string | null
}

interface CollaborationStats {
  totalMessages: number
  scannedToday: number
  dlpAlerts: number
  blockedMessages: number
}

interface CollaborationPageProps {
  events?: SecurityEvent[]
  risks?: SharingRisk[]
  externalSharing?: ExternalSharing[]
  policies?: CollaborationPolicy[]
  stats?: CollaborationStats
  // Legacy support - DLP alerts
  alerts?: DLPAlert[]
}

const defaultStats: CollaborationStats = {
  totalMessages: 0,
  scannedToday: 0,
  dlpAlerts: 0,
  blockedMessages: 0,
}

export default function Collaboration({
  events = [],
  risks = [],
  externalSharing = [],
  policies = [],
  stats = defaultStats,
  alerts = []
}: CollaborationPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedPlatform, setSelectedPlatform] = useState<string>('all')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [loading, setLoading] = useState<string | null>(null)

  const handleExport = async () => {
    setLoading('export')
    try {
      const response = await axios.get('/api/v1/collaboration/export', { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `collaboration-export-${new Date().toISOString().split('T')[0]}.csv`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      toast.success('Export downloaded')
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to export')
    } finally {
      setLoading(null)
    }
  }

  const handleConfigurePolicies = () => {
    router.visit('/app/collaboration')
  }

  // Use events prop if available, otherwise fall back to alerts for backwards compatibility
  const displayAlerts = events.length > 0
    ? events.map(e => ({
        id: e.id,
        platform: e.platform as DLPAlert['platform'],
        channel: '',
        user: e.user,
        timestamp: e.timestamp,
        alertType: 'pii' as DLPAlert['alertType'],
        severity: e.severity,
        description: e.description,
        content_preview: '',
        status: e.status === 'investigating' ? 'open' : e.status,
      } as DLPAlert))
    : alerts

  // Convert policies to PolicyViolation format for display
  const displayPolicies: PolicyViolation[] = policies.map(p => ({
    id: p.id,
    policy: p.name,
    violations: p.violationCount,
    lastViolation: p.lastViolation || 'Never',
    trend: 'stable' as const,
  }))

  const displayStats = stats

  const filteredAlerts = displayAlerts.filter((alert) => {
    const matchesSearch = alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.user.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesPlatform = selectedPlatform === 'all' || alert.platform === selectedPlatform
    const matchesSeverity = selectedSeverity === 'all' || alert.severity === selectedSeverity
    return matchesSearch && matchesPlatform && matchesSeverity
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20'
      case 'high': return 'text-orange-400 bg-orange-500/20'
      case 'medium': return 'text-yellow-400 bg-yellow-500/20'
      case 'low': return 'text-blue-400 bg-blue-500/20'
      default: return 'text-[var(--muted)] bg-[var(--surface-raised)]'
    }
  }

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'slack': return 'S'
      case 'teams': return 'T'
      case 'discord': return 'D'
      default: return '?'
    }
  }

  const getAlertTypeLabel = (type: string) => {
    switch (type) {
      case 'pii': return 'PII Detected'
      case 'credential': return 'Credential Exposure'
      case 'ip': return 'IP Protection'
      case 'sensitive_file': return 'Sensitive File'
      case 'malicious_link': return 'Malicious Link'
      default: return type
    }
  }

  return (
    <MainLayout title="Collaboration Security">
      <Head title="Collaboration Security - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Total Messages Monitored</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{displayStats.totalMessages.toLocaleString()}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                <MessageSquare className="h-6 w-6 text-blue-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Scanned Today</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{displayStats.scannedToday.toLocaleString()}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-green-500/20 flex items-center justify-center">
                <Eye className="h-6 w-6 text-green-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">DLP Alerts</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{displayStats.dlpAlerts}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-yellow-500/20 flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-yellow-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Blocked Messages</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{displayStats.blockedMessages}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-red-500/20 flex items-center justify-center">
                <Lock className="h-6 w-6 text-red-400" />
              </div>
            </div>
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* DLP Alerts */}
          <div className="lg:col-span-2 card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-6 border-b border-[var(--border)]">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-[var(--fg)]">DLP Alerts</h2>
                <button
                  onClick={handleExport}
                  disabled={loading === 'export'}
                  className="flex items-center gap-2 text-sm text-[var(--muted)] hover:text-[var(--fg)] disabled:opacity-50"
                >
                  <Download className="h-4 w-4" />
                  {loading === 'export' ? 'Exporting...' : 'Export'}
                </button>
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-4">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                  <input
                    type="text"
                    placeholder="Search alerts..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                </div>

                <Select
                  value={selectedPlatform}
                  onValueChange={setSelectedPlatform}
                  placeholder="All Platforms"
                  className="bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                >
                  <SelectItem value="all">All Platforms</SelectItem>
                  <SelectItem value="slack">Slack</SelectItem>
                  <SelectItem value="teams">Teams</SelectItem>
                  <SelectItem value="discord">Discord</SelectItem>
                </Select>

                <Select
                  value={selectedSeverity}
                  onValueChange={setSelectedSeverity}
                  placeholder="All Severities"
                  className="bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                >
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </Select>
              </div>
            </div>

            <div className="divide-y divide-[var(--border)]/50 max-h-[500px] overflow-y-auto">
              {filteredAlerts.map((alert) => (
                <div key={alert.id} className="p-4 hover:bg-[var(--surface-raised)]/30 transition-colors">
                  <div className="flex items-start gap-4">
                    <div className={cn(
                      'h-10 w-10 rounded-lg flex items-center justify-center font-bold text-sm',
                      alert.platform === 'slack' ? 'bg-purple-500/20 text-purple-400' :
                      alert.platform === 'teams' ? 'bg-blue-500/20 text-blue-400' :
                      'bg-indigo-500/20 text-indigo-400'
                    )}>
                      {getPlatformIcon(alert.platform)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getSeverityColor(alert.severity))}>
                          {alert.severity}
                        </span>
                        <span className="text-sm font-medium text-[var(--fg)]">{getAlertTypeLabel(alert.alertType)}</span>
                        <span className={cn(
                          'px-2 py-0.5 rounded text-xs',
                          alert.status === 'open' ? 'bg-red-500/20 text-red-400' :
                          alert.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                          'bg-[var(--surface-raised)] text-[var(--muted)]'
                        )}>
                          {alert.status}
                        </span>
                      </div>
                      <p className="text-sm text-[var(--muted)]">{alert.description}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-[var(--muted)]">
                        <span>{alert.channel}</span>
                        <span>{alert.user}</span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="mt-2 p-2 bg-[var(--surface-inset)] rounded text-xs text-[var(--muted)] font-mono truncate">
                        {alert.content_preview}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Policy Violations */}
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-6 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Policy Violations</h2>
              <p className="text-sm text-[var(--muted)] mt-1">Last 30 days</p>
            </div>

            <div className="divide-y divide-[var(--border)]/50">
              {displayPolicies.map((policy) => (
                <div key={policy.id} className="p-4 hover:bg-[var(--surface-raised)]/30 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-[var(--fg)]">{policy.policy}</span>
                    <div className="flex items-center gap-1">
                      <TrendingUp className={cn(
                        'h-4 w-4',
                        policy.trend === 'up' ? 'text-red-400' :
                        policy.trend === 'down' ? 'text-green-400' :
                        'text-[var(--muted)]'
                      )} />
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-2xl font-bold text-[var(--fg)]">{policy.violations}</span>
                    <span className="text-xs text-[var(--muted)]">{policy.lastViolation}</span>
                  </div>
                  <div className="mt-2 h-1 bg-[var(--surface-raised)] rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full',
                        policy.violations > 40 ? 'bg-red-500' :
                        policy.violations > 20 ? 'bg-yellow-500' :
                        'bg-green-500'
                      )}
                      style={{ width: `${Math.min(policy.violations * 2, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="p-4 border-t border-[var(--border)]">
              <button
                onClick={handleConfigurePolicies}
                className="w-full flex items-center justify-center gap-2 bg-[var(--surface-raised)] hover:bg-[var(--surface-elevated)] rounded-lg px-4 py-2 text-sm text-[var(--muted)] transition-colors"
              >
                <Shield className="h-4 w-4" />
                Configure Policies
              </button>
            </div>
          </div>
        </div>

        {/* External Sharing & Sharing Risks */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* External Sharing */}
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-6 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--fg)]">External Sharing</h2>
              <p className="text-sm text-[var(--muted)] mt-1">Resources shared with external parties</p>
            </div>
            <div className="divide-y divide-[var(--border)]/50 max-h-[300px] overflow-y-auto">
              {externalSharing.length === 0 ? (
                <div className="p-8 text-center text-[var(--muted)]">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No external sharing detected</p>
                </div>
              ) : (
                externalSharing.map((share) => (
                  <div key={share.id} className="p-4 hover:bg-[var(--surface-raised)]/30 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-[var(--fg)]">{share.resource}</span>
                      <span className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        share.accessLevel === 'admin' ? 'bg-red-500/20 text-red-400' :
                        share.accessLevel === 'edit' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      )}>
                        {share.accessLevel}
                      </span>
                    </div>
                    <p className="text-sm text-[var(--muted)]">Shared with: {share.sharedWith}</p>
                    <div className="flex items-center gap-4 mt-1 text-xs text-[var(--muted)]">
                      <span>{share.platform}</span>
                      {share.expiresAt && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Expires: {new Date(share.expiresAt).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Sharing Risks */}
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
            <div className="p-6 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Sharing Risks</h2>
              <p className="text-sm text-[var(--muted)] mt-1">Potential security risks from sharing</p>
            </div>
            <div className="divide-y divide-[var(--border)]/50 max-h-[300px] overflow-y-auto">
              {risks.length === 0 ? (
                <div className="p-8 text-center text-[var(--muted)]">
                  <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No sharing risks detected</p>
                </div>
              ) : (
                risks.map((risk) => (
                  <div key={risk.id} className="p-4 hover:bg-[var(--surface-raised)]/30 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-[var(--fg)]">{risk.resource}</span>
                      <span className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        risk.riskLevel === 'high' ? 'bg-red-500/20 text-red-400' :
                        risk.riskLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      )}>
                        {risk.riskLevel} risk
                      </span>
                    </div>
                    <p className="text-sm text-[var(--muted)]">{risk.type.replace('_', ' ')}</p>
                    <div className="flex items-center gap-4 mt-1 text-xs text-[var(--muted)]">
                      <span>{risk.platform}</span>
                      <span>Shared with: {risk.sharedWith}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Sensitive Data Detection */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
          <h2 className="text-lg font-semibold text-[var(--fg)] mb-4">Sensitive Data Detection Patterns</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            {[
              { name: 'Credit Cards', count: 12, icon: '****' },
              { name: 'SSN/ID Numbers', count: 8, icon: '###' },
              { name: 'API Keys', count: 23, icon: 'KEY' },
              { name: 'Passwords', count: 45, icon: '***' },
              { name: 'Email Addresses', count: 156, icon: '@' },
              { name: 'Phone Numbers', count: 34, icon: '#' },
            ].map((pattern) => (
              <div key={pattern.name} className="bg-[var(--surface-raised)]/50 rounded-lg p-4 text-center">
                <div className="text-2xl font-mono text-primary-400 mb-2">{pattern.icon}</div>
                <div className="text-sm font-medium text-[var(--fg)]">{pattern.name}</div>
                <div className="text-xs text-[var(--muted)] mt-1">{pattern.count} detections</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
