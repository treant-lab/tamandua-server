import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Mail,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Link as LinkIcon,
  Paperclip,
  Users,
  Activity,
  Target,
  ChevronRight,
  RefreshCw,
  Settings,
  Search,
  Filter,
  Cloud,
  FileWarning,
  Zap,
  ShieldAlert,
  Eye,
  Ban,
  ChevronDown,
  BarChart3,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useState } from 'react'

// Types
interface EmailIntegration {
  connected: boolean
  enabled: boolean
  tenantId?: string
  adminEmail?: string
  lastPoll?: string
  stats?: {
    emails_collected?: number
    threats_detected?: number
    api_calls?: number
    errors?: number
  }
}

interface AttackChainEmail {
  sender?: string
  recipient?: string
  subject?: string
  timestamp?: string
  verdict?: string
  threatType?: string
}

interface AttackChainTimelineEvent {
  stage: string
  timestamp?: string
  description: string
}

interface AttackChain {
  id: string
  emailId: string
  email: AttackChainEmail
  stagesCompleted: number
  riskScore: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  builtAt?: string
  timeline: AttackChainTimelineEvent[]
}

interface EmailSecurityPageProps {
  integrations?: {
    microsoft365?: EmailIntegration
    googleWorkspace?: EmailIntegration
  }
  stats?: {
    emailsAnalyzed: number
    phishingDetected: number
    suspiciousFlagged: number
    attackChainsBuilt: number
    attachmentsTracked: number
    payloadsExecuted: number
  }
  attackChains?: AttackChain[]
}

// Default values
const defaultStats = {
  emailsAnalyzed: 0,
  phishingDetected: 0,
  suspiciousFlagged: 0,
  attackChainsBuilt: 0,
  attachmentsTracked: 0,
  payloadsExecuted: 0,
}

const defaultIntegrations = {
  microsoft365: { connected: false, enabled: false },
  googleWorkspace: { connected: false, enabled: false },
}

// Stat Card Component
function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  trendDirection,
  color = 'blue',
}: {
  title: string
  value: number | string
  icon: React.ElementType
  trend?: string
  trendDirection?: 'up' | 'down' | 'neutral'
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'orange'
}) {
  const colorStyles = {
    blue: { bg: 'var(--med-bg)', color: 'var(--med)' },
    green: { bg: 'var(--emerald-glow)', color: 'var(--emerald-400)' },
    yellow: { bg: 'var(--high-bg)', color: 'var(--high)' },
    red: { bg: 'var(--crit-bg)', color: 'var(--crit)' },
    purple: { bg: 'rgba(217, 70, 239, 0.12)', color: 'var(--sol-magenta)' },
    orange: { bg: 'var(--high-bg)', color: 'var(--high)' },
  }

  const style = colorStyles[color]

  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm" style={{ color: 'var(--muted)' }}>{title}</span>
        <div className="p-2 rounded-lg" style={{ background: style.bg }}>
          <Icon className="h-4 w-4" style={{ color: style.color }} />
        </div>
      </div>
      <div className="flex items-end gap-2">
        <span className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}</span>
        {trend && (
          <span
            className={cn(
              'text-xs px-1.5 py-0.5 rounded',
              trendDirection === 'up' && 'text-[var(--emerald-400)]',
              trendDirection === 'down' && 'text-[var(--crit)]',
              trendDirection === 'neutral' && 'text-[var(--muted)]'
            )}
            style={{
              background: trendDirection === 'up' ? 'var(--emerald-glow)' :
                trendDirection === 'down' ? 'var(--crit-bg)' : 'var(--surface-2)'
            }}
          >
            {trend}
          </span>
        )}
      </div>
    </div>
  )
}

// Integration Status Card
function IntegrationCard({
  name,
  provider,
  integration,
  icon: Icon,
  onConfigure,
}: {
  name: string
  provider: string
  integration: EmailIntegration
  icon: React.ElementType
  onConfigure: () => void
}) {
  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div
            className="p-2 rounded-lg"
            style={{
              background: integration.connected ? 'var(--emerald-glow)' : 'var(--surface-2)',
            }}
          >
            <Icon
              className="h-5 w-5"
              style={{ color: integration.connected ? 'var(--emerald-400)' : 'var(--muted)' }}
            />
          </div>
          <div>
            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{name}</h3>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>{provider}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {integration.connected ? (
            <span
              className="flex items-center gap-1.5 text-xs px-2 py-1 rounded"
              style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
            >
              <CheckCircle className="h-3 w-3" />
              Connected
            </span>
          ) : (
            <span
              className="flex items-center gap-1.5 text-xs px-2 py-1 rounded"
              style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
            >
              <Clock className="h-3 w-3" />
              Not Connected
            </span>
          )}
        </div>
      </div>

      <div className="space-y-2 text-sm">
        {integration.tenantId && (
          <div className="flex justify-between">
            <span style={{ color: 'var(--muted)' }}>Tenant ID</span>
            <span className="font-mono" style={{ color: 'var(--fg-2)' }}>{integration.tenantId}</span>
          </div>
        )}
        {integration.adminEmail && (
          <div className="flex justify-between">
            <span style={{ color: 'var(--muted)' }}>Admin</span>
            <span style={{ color: 'var(--fg-2)' }}>{integration.adminEmail}</span>
          </div>
        )}
        {integration.lastPoll && (
          <div className="flex justify-between">
            <span style={{ color: 'var(--muted)' }}>Last Poll</span>
            <span style={{ color: 'var(--fg-2)' }}>{formatDate(integration.lastPoll)}</span>
          </div>
        )}
        {integration.stats && (
          <>
            <div className="flex justify-between">
              <span style={{ color: 'var(--muted)' }}>Emails Collected</span>
              <span style={{ color: 'var(--fg-2)' }}>
                {(integration.stats.emails_collected || 0).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span style={{ color: 'var(--muted)' }}>Threats Detected</span>
              <span style={{ color: 'var(--crit)' }}>
                {(integration.stats.threats_detected || 0).toLocaleString()}
              </span>
            </div>
          </>
        )}
      </div>

      <div className="mt-4 pt-4 flex gap-2" style={{ borderTop: '1px solid var(--hairline)' }}>
        <button
          onClick={onConfigure}
          className="flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
          style={{ background: 'var(--med-bg)', color: 'var(--med)' }}
          onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(91, 156, 242, 0.2)')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--med-bg)')}
        >
          <Settings className="h-4 w-4" />
          Configure
        </button>
        {integration.connected && (
          <button
            className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
            style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-3)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
          >
            <RefreshCw className="h-4 w-4" />
            Sync
          </button>
        )}
      </div>
    </div>
  )
}

// Attack Chain Card
function AttackChainCard({ chain }: { chain: AttackChain }) {
  const [expanded, setExpanded] = useState(false)

  const severityStyles = {
    critical: { bg: 'var(--crit-bg)', color: 'var(--crit)', border: 'rgba(240, 80, 110, 0.3)' },
    high: { bg: 'var(--high-bg)', color: 'var(--high)', border: 'rgba(245, 165, 36, 0.3)' },
    medium: { bg: 'var(--med-bg)', color: 'var(--med)', border: 'rgba(91, 156, 242, 0.3)' },
    low: { bg: 'var(--low-bg)', color: 'var(--low)', border: 'rgba(122, 138, 146, 0.3)' },
  }

  const stageIcons: Record<string, React.ElementType> = {
    email_received: Mail,
    attachment_saved: Paperclip,
    payload_executed: Zap,
  }

  const style = severityStyles[chain.severity]

  return (
    <div className="card-sentinel overflow-hidden">
      <div
        className="p-4 cursor-pointer transition-colors"
        onClick={() => setExpanded(!expanded)}
        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
        onMouseLeave={(e) => (e.currentTarget.style.background = '')}
      >
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'var(--crit-bg)' }}>
              <Target className="h-5 w-5" style={{ color: 'var(--crit)' }} />
            </div>
            <div>
              <h4 className="font-medium text-sm" style={{ color: 'var(--fg)' }}>
                {chain.email?.subject || 'Unknown Subject'}
              </h4>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>
                From: {chain.email?.sender || 'Unknown'} &rarr;{' '}
                {chain.email?.recipient || 'Unknown'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="text-xs px-2 py-1 rounded"
              style={{ background: style.bg, color: style.color, border: `1px solid ${style.border}` }}
            >
              {chain.severity.toUpperCase()}
            </span>
            <ChevronDown
              className={cn('h-5 w-5 transition-transform', expanded && 'rotate-180')}
              style={{ color: 'var(--muted)' }}
            />
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
          <span className="flex items-center gap-1">
            <Activity className="h-3 w-3" />
            {chain.stagesCompleted} stages
          </span>
          <span className="flex items-center gap-1">
            <ShieldAlert className="h-3 w-3" />
            Risk: {Math.round((chain.riskScore || 0) * 100)}%
          </span>
          {chain.builtAt && (
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatDate(chain.builtAt)}
            </span>
          )}
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-4" style={{ borderTop: '1px solid var(--hairline)' }}>
          <h5 className="text-xs font-medium mb-3" style={{ color: 'var(--muted)' }}>Attack Timeline</h5>
          <div className="space-y-3">
            {chain.timeline.map((event, idx) => {
              const StageIcon = stageIcons[event.stage] || Activity
              return (
                <div key={idx} className="flex items-start gap-3">
                  <div className="relative">
                    <div className="p-1.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
                      <StageIcon className="h-4 w-4" />
                    </div>
                    {idx < chain.timeline.length - 1 && (
                      <div
                        className="absolute top-8 left-1/2 -translate-x-1/2 w-0.5 h-full"
                        style={{ background: 'var(--border)' }}
                      />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm" style={{ color: 'var(--fg)' }}>{event.description}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>
                      {event.timestamp && formatDate(event.timestamp)}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>

          <div className="mt-4 flex gap-2">
            <button
              className="flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors"
              style={{ background: 'var(--med-bg)', color: 'var(--med)' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(91, 156, 242, 0.2)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--med-bg)')}
            >
              <Eye className="h-3 w-3" />
              View Details
            </button>
            <button
              className="flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors"
              style={{ background: 'var(--crit-bg)', color: 'var(--crit)' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(240, 80, 110, 0.2)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--crit-bg)')}
            >
              <Ban className="h-3 w-3" />
              Block Sender
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Quick Action Button
function QuickAction({
  icon: Icon,
  label,
  description,
  onClick,
  color = 'blue',
}: {
  icon: React.ElementType
  label: string
  description: string
  onClick?: () => void
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple'
}) {
  const colorStyles = {
    blue: { bg: 'var(--med-bg)', color: 'var(--med)', hover: 'rgba(91, 156, 242, 0.2)' },
    green: { bg: 'var(--emerald-glow)', color: 'var(--emerald-400)', hover: 'rgba(47, 196, 113, 0.25)' },
    yellow: { bg: 'var(--high-bg)', color: 'var(--high)', hover: 'rgba(245, 165, 36, 0.2)' },
    red: { bg: 'var(--crit-bg)', color: 'var(--crit)', hover: 'rgba(240, 80, 110, 0.2)' },
    purple: { bg: 'rgba(217, 70, 239, 0.12)', color: 'var(--sol-magenta)', hover: 'rgba(217, 70, 239, 0.2)' },
  }

  const style = colorStyles[color]

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 p-3 rounded-lg transition-colors text-left w-full"
      style={{ background: style.bg, color: style.color }}
      onMouseEnter={(e) => (e.currentTarget.style.background = style.hover)}
      onMouseLeave={(e) => (e.currentTarget.style.background = style.bg)}
    >
      <Icon className="h-5 w-5 flex-shrink-0" />
      <div>
        <p className="font-medium text-sm">{label}</p>
        <p className="text-xs opacity-70">{description}</p>
      </div>
      <ChevronRight className="h-4 w-4 ml-auto flex-shrink-0" />
    </button>
  )
}

export default function EmailSecurity({
  integrations = defaultIntegrations,
  stats = defaultStats,
  attackChains = [],
}: EmailSecurityPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [showConfigModal, setShowConfigModal] = useState<'m365' | 'google' | null>(null)

  const m365 = integrations?.microsoft365 || { connected: false, enabled: false }
  const google = integrations?.googleWorkspace || { connected: false, enabled: false }

  return (
    <MainLayout>
      <Head title="Email Security" />

      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Email Security</h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              Phishing detection, email-to-endpoint correlation, and attack chain analysis
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
              style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-3)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
            >
              <RefreshCw className="h-4 w-4" />
              Sync All
            </button>
            <button
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
              style={{ background: 'var(--emerald-600)', color: 'var(--fg)' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--emerald-500)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--emerald-600)')}
            >
              <Search className="h-4 w-4" />
              Search Emails
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-6 gap-4 mb-6">
          <StatCard
            title="Emails Analyzed"
            value={stats?.emailsAnalyzed || 0}
            icon={Mail}
            color="blue"
          />
          <StatCard
            title="Phishing Detected"
            value={stats?.phishingDetected || 0}
            icon={ShieldAlert}
            color="red"
          />
          <StatCard
            title="Suspicious Flagged"
            value={stats?.suspiciousFlagged || 0}
            icon={AlertTriangle}
            color="yellow"
          />
          <StatCard
            title="Attack Chains"
            value={stats?.attackChainsBuilt || 0}
            icon={Target}
            color="purple"
          />
          <StatCard
            title="Attachments Tracked"
            value={stats?.attachmentsTracked || 0}
            icon={Paperclip}
            color="orange"
          />
          <StatCard
            title="Payloads Executed"
            value={stats?.payloadsExecuted || 0}
            icon={Zap}
            color="red"
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-3 gap-6">
          {/* Left Column - Integrations & Quick Actions */}
          <div className="space-y-6">
            {/* Integrations */}
            <div>
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Cloud className="h-5 w-5" style={{ color: 'var(--med)' }} />
                Email Integrations
              </h2>
              <div className="space-y-4">
                <IntegrationCard
                  name="Microsoft 365"
                  provider="Exchange Online, Defender for O365"
                  integration={m365}
                  icon={Mail}
                  onConfigure={() => setShowConfigModal('m365')}
                />
                <IntegrationCard
                  name="Google Workspace"
                  provider="Gmail, Admin SDK"
                  integration={google}
                  icon={Mail}
                  onConfigure={() => setShowConfigModal('google')}
                />
              </div>
            </div>

            {/* Quick Actions */}
            <div>
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Zap className="h-5 w-5" style={{ color: 'var(--high)' }} />
                Quick Actions
              </h2>
              <div className="card-sentinel p-4 space-y-2">
                <QuickAction
                  icon={Search}
                  label="Analyze URL"
                  description="Deep URL analysis with sandbox detonation"
                  color="blue"
                />
                <QuickAction
                  icon={FileWarning}
                  label="Submit Sample"
                  description="Analyze suspicious email or attachment"
                  color="yellow"
                />
                <QuickAction
                  icon={Users}
                  label="User Risk Report"
                  description="View users at risk from email threats"
                  color="purple"
                />
                <QuickAction
                  icon={BarChart3}
                  label="Phishing Campaign"
                  description="Analyze phishing campaign patterns"
                  color="red"
                />
              </div>
            </div>
          </div>

          {/* Right Column - Attack Chains */}
          <div className="col-span-2">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Target className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                Email-to-Endpoint Attack Chains
              </h2>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search
                    className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
                    style={{ color: 'var(--muted)' }}
                  />
                  <input
                    type="text"
                    placeholder="Search chains..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9 pr-4 py-2 rounded-lg text-sm focus:outline-none"
                    style={{
                      background: 'var(--surface)',
                      border: '1px solid var(--border)',
                      color: 'var(--fg)',
                    }}
                  />
                </div>
                <button
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-3)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
                >
                  <Filter className="h-4 w-4" />
                  Filter
                </button>
              </div>
            </div>

            {attackChains.length > 0 ? (
              <div className="space-y-3">
                {attackChains
                  .filter(
                    (chain) =>
                      !searchQuery ||
                      chain.email?.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      chain.email?.sender?.toLowerCase().includes(searchQuery.toLowerCase())
                  )
                  .map((chain) => (
                    <AttackChainCard key={chain.id} chain={chain} />
                  ))}
              </div>
            ) : (
              <div className="card-sentinel p-12 text-center">
                <Target className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--fg)' }}>No Attack Chains Detected</h3>
                <p className="text-sm max-w-md mx-auto" style={{ color: 'var(--muted)' }}>
                  Attack chains are automatically built when email attachments are correlated with
                  endpoint file and process events. Configure your email integrations to start
                  tracking email-to-endpoint activity.
                </p>
              </div>
            )}

            {/* Detection Capabilities */}
            <div className="mt-6">
              <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Detection Capabilities</h3>
              <div className="grid grid-cols-4 gap-3">
                {[
                  { icon: LinkIcon, label: 'URL Analysis', active: true },
                  { icon: Paperclip, label: 'Attachment Scan', active: true },
                  { icon: Users, label: 'Sender Reputation', active: true },
                  { icon: Shield, label: 'Domain Spoofing', active: true },
                ].map(({ icon: Icon, label, active }) => (
                  <div
                    key={label}
                    className="flex items-center gap-2 p-3 rounded-lg"
                    style={{
                      background: active ? 'var(--emerald-glow)' : 'var(--surface)',
                      border: `1px solid ${active ? 'rgba(47, 196, 113, 0.3)' : 'var(--border)'}`,
                      color: active ? 'var(--emerald-400)' : 'var(--muted)',
                    }}
                  >
                    <Icon className="h-4 w-4" />
                    <span className="text-sm">{label}</span>
                    {active && <CheckCircle className="h-3 w-3 ml-auto" />}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0, 0, 0, 0.5)' }}>
          <div
            className="rounded-lg p-6 max-w-md w-full mx-4"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
          >
            <h2 className="text-xl font-bold mb-4" style={{ color: 'var(--fg)' }}>
              Configure {showConfigModal === 'm365' ? 'Microsoft 365' : 'Google Workspace'}
            </h2>
            <p className="mb-4" style={{ color: 'var(--muted)' }}>
              {showConfigModal === 'm365'
                ? 'Enter your Azure AD app registration details to connect Microsoft 365.'
                : 'Upload your service account key to connect Google Workspace.'}
            </p>
            <div className="space-y-4">
              {showConfigModal === 'm365' ? (
                <>
                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Tenant ID</label>
                    <input
                      type="text"
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                      className="w-full px-3 py-2 rounded"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        color: 'var(--fg)',
                      }}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Client ID</label>
                    <input
                      type="text"
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                      className="w-full px-3 py-2 rounded"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        color: 'var(--fg)',
                      }}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Client Secret</label>
                    <input
                      type="password"
                      placeholder="Enter client secret"
                      className="w-full px-3 py-2 rounded"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        color: 'var(--fg)',
                      }}
                    />
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Admin Email</label>
                    <input
                      type="email"
                      placeholder="admin@yourdomain.com"
                      className="w-full px-3 py-2 rounded"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        color: 'var(--fg)',
                      }}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Service Account Key (JSON)</label>
                    <textarea
                      placeholder="Paste service account JSON here..."
                      rows={5}
                      className="w-full px-3 py-2 rounded font-mono text-sm"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        color: 'var(--fg)',
                      }}
                    />
                  </div>
                </>
              )}
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowConfigModal(null)}
                className="flex-1 px-4 py-2 rounded transition-colors"
                style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-3)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
              >
                Cancel
              </button>
              <button
                className="flex-1 px-4 py-2 rounded transition-colors"
                style={{ background: 'var(--emerald-600)', color: 'var(--fg)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--emerald-500)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--emerald-600)')}
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  )
}
