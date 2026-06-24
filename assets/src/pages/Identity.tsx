import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  User,
  Users,
  Key,
  Lock,
  Unlock,
  Clock,
  MapPin,
  Monitor,
  AlertTriangle,
  Activity,
  TrendingUp,
  TrendingDown,
  Minus,
  Search,
  Filter,
  RefreshCw,
  ChevronRight,
  Eye,
  Globe,
  Laptop,
  Server,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'
import { useState, useEffect } from 'react'

// Types
interface RiskFactor {
  name: string
  contribution: number
  details: string
}

interface UserRisk {
  userId: string
  userPrincipalName: string
  displayName: string
  department?: string
  score: number
  level: 'low' | 'medium' | 'high' | 'critical'
  factors: RiskFactor[]
  trend: 'increasing' | 'decreasing' | 'stable'
  lastUpdated: string
  azureAdRiskLevel?: string
  azureAdRiskState?: string
}

interface RiskySignIn {
  id: string
  userPrincipalName: string
  userId: string
  timestamp: string
  ipAddress: string
  location: {
    city?: string
    state?: string
    country?: string
  }
  appDisplayName: string
  clientAppUsed: string
  riskLevelDuringSignIn: 'low' | 'medium' | 'high' | 'none'
  riskState: string
  riskDetail?: string
  statusErrorCode: number
  statusFailureReason?: string
  deviceDetail?: {
    browser?: string
    operatingSystem?: string
    deviceId?: string
  }
  conditionalAccessStatus: string
  isInteractive: boolean
}

interface PrivilegeChange {
  id: string
  timestamp: string
  activity: string
  category: string
  initiatedBy: {
    user?: {
      displayName?: string
      userPrincipalName?: string
    }
    app?: {
      displayName?: string
    }
  }
  targetResources: Array<{
    displayName?: string
    type?: string
    userPrincipalName?: string
  }>
  result: string
}

interface ServiceAccount {
  id: string
  displayName: string
  appId: string
  servicePrincipalType: string
  accountEnabled: boolean
  createdDateTime: string
  signInActivity?: {
    lastSignInDateTime?: string
    lastSignInRequestId?: string
  }
  riskLevel?: string
  permissionGrantsCount?: number
}

interface IdentityStats {
  totalUsers: number
  highRiskUsers: number
  mediumRiskUsers: number
  riskySignInsToday: number
  privilegeChangesToday: number
  serviceAccounts: number
  averageRiskScore: number
  impossibleTravelDetected: number
}

type IdentitySourceStatus = 'available' | 'disabled' | 'unavailable'

interface IdentityAvailability {
  riskScoring?: IdentitySourceStatus
  highRiskUsers?: IdentitySourceStatus
  azureAd?: IdentitySourceStatus
  riskySignIns?: IdentitySourceStatus
  privilegeChanges?: IdentitySourceStatus
  serviceAccounts?: IdentitySourceStatus
}

interface IdentityPageProps {
  stats?: IdentityStats
  highRiskUsers?: UserRisk[]
  riskySignIns?: RiskySignIn[]
  privilegeChanges?: PrivilegeChange[]
  serviceAccounts?: ServiceAccount[]
  identityAvailability?: IdentityAvailability
}

const defaultStats: IdentityStats = {
  totalUsers: 0,
  highRiskUsers: 0,
  mediumRiskUsers: 0,
  riskySignInsToday: 0,
  privilegeChangesToday: 0,
  serviceAccounts: 0,
  averageRiskScore: 0,
  impossibleTravelDetected: 0,
}

const riskLevelConfig: Record<string, { color: string; bg: string; icon: React.ElementType; badgeClass: string }> = {
  critical: { color: 'text-[var(--crit)]', bg: 'bg-[var(--crit-bg)]', icon: ShieldX, badgeClass: 'badge-sentinel badge-sentinel-critical' },
  high: { color: 'text-[var(--high)]', bg: 'bg-[var(--high-bg)]', icon: ShieldAlert, badgeClass: 'badge-sentinel badge-sentinel-high' },
  medium: { color: 'text-[var(--med)]', bg: 'bg-[var(--med-bg)]', icon: Shield, badgeClass: 'badge-sentinel badge-sentinel-medium' },
  low: { color: 'text-[var(--emerald-400)]', bg: 'bg-[var(--emerald-glow)]', icon: ShieldCheck, badgeClass: 'badge-sentinel badge-sentinel-success' },
  none: { color: 'text-[var(--muted)]', bg: 'bg-[var(--surface-2)]', icon: Shield, badgeClass: 'badge-sentinel badge-sentinel-default' },
}

export default function Identity({
  stats,
  highRiskUsers = [],
  riskySignIns = [],
  privilegeChanges = [],
  serviceAccounts = [],
  identityAvailability = {},
}: IdentityPageProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'signins' | 'privileges' | 'service_accounts'>('overview')
  const [selectedUser, setSelectedUser] = useState<UserRisk | null>(null)
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')
  const [searchTerm, setSearchTerm] = useState('')
  const [riskFilter, setRiskFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')

  const identityStats = stats || defaultStats
  const sourceStatus = (source: keyof IdentityAvailability) => identityAvailability[source] || 'available'
  const sourceUnavailable = (source: keyof IdentityAvailability) => sourceStatus(source) === 'unavailable'
  const sourceDisabled = (source: keyof IdentityAvailability) => sourceStatus(source) === 'disabled'
  const metricValue = (value: number, sources: Array<keyof IdentityAvailability>) =>
    sources.some(sourceUnavailable) ? '--' : value
  const riskScoringUnavailable = sourceUnavailable('riskScoring') || sourceUnavailable('highRiskUsers')
  const azureAdUnavailable = sourceUnavailable('azureAd')
  const azureAdDisabled = sourceDisabled('azureAd')
  const unavailableSources = [
    riskScoringUnavailable ? 'Risk scoring' : null,
    azureAdUnavailable ? 'Azure AD identity data' : null,
    sourceUnavailable('riskySignIns') ? 'Risky sign-ins' : null,
    sourceUnavailable('privilegeChanges') ? 'Privilege changes' : null,
    sourceUnavailable('serviceAccounts') ? 'Service accounts' : null,
  ].filter(Boolean)

  // Filter users based on search and risk level
  const filteredUsers = highRiskUsers.filter((user) => {
    const matchesSearch =
      user.displayName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.userPrincipalName?.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRisk = riskFilter === 'all' || user.level === riskFilter
    return matchesSearch && matchesRisk
  })

  // Filter sign-ins based on search
  const filteredSignIns = riskySignIns.filter((signIn) => {
    return signIn.userPrincipalName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
           signIn.ipAddress?.includes(searchTerm) ||
           signIn.appDisplayName?.toLowerCase().includes(searchTerm.toLowerCase())
  })

  return (
    <MainLayout title="Identity Protection">
      <Head title="Identity Protection - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <StatCard
            icon={Users}
            label="Total Users"
            value={metricValue(identityStats.totalUsers, ['riskScoring'])}
            color="primary"
          />
          <StatCard
            icon={ShieldX}
            label="Critical Risk"
            value={metricValue(identityStats.highRiskUsers, ['riskScoring', 'highRiskUsers'])}
            color="critical"
          />
          <StatCard
            icon={ShieldAlert}
            label="High Risk"
            value={metricValue(identityStats.mediumRiskUsers, ['riskScoring'])}
            color="high"
          />
          <StatCard
            icon={AlertTriangle}
            label="Risky Sign-ins"
            value={metricValue(identityStats.riskySignInsToday, ['azureAd', 'riskySignIns'])}
            color="medium"
            subtext="Today"
          />
          <StatCard
            icon={Key}
            label="Privilege Changes"
            value={metricValue(identityStats.privilegeChangesToday, ['azureAd', 'privilegeChanges'])}
            color="sol-magenta"
            subtext="Today"
          />
          <StatCard
            icon={Server}
            label="Service Accounts"
            value={metricValue(identityStats.serviceAccounts, ['azureAd', 'serviceAccounts'])}
            color="sol-cyan"
          />
          <StatCard
            icon={Globe}
            label="Impossible Travel"
            value={metricValue(identityStats.impossibleTravelDetected, ['azureAd'])}
            color="critical"
          />
          <StatCard
            icon={Activity}
            label="Avg Risk Score"
            value={metricValue(Math.round(identityStats.averageRiskScore), ['riskScoring'])}
            color="emerald"
          />
        </div>

        {(unavailableSources.length > 0 || azureAdDisabled) && (
          <div className="flex items-start gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-400" />
            <div>
              <p className="text-sm font-medium text-yellow-100">Identity data is partially available</p>
              <p className="mt-1 text-xs text-yellow-200/80">
                {unavailableSources.length > 0
                  ? `${unavailableSources.join(', ')} unavailable. Empty lists and zero values may be fallback values.`
                  : 'Azure AD is not configured; cloud sign-in, privilege-change, and service-account views are disabled.'}
              </p>
            </div>
          </div>
        )}

        {/* Tabs & Filters */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-4 border-b border-[var(--border)] overflow-x-auto">
            <TabButton
              active={activeTab === 'overview'}
              onClick={() => setActiveTab('overview')}
              icon={Activity}
              label="Overview"
            />
            <TabButton
              active={activeTab === 'users'}
              onClick={() => setActiveTab('users')}
              icon={Users}
              label="User Risk"
              badge={identityStats.highRiskUsers}
            />
            <TabButton
              active={activeTab === 'signins'}
              onClick={() => setActiveTab('signins')}
              icon={Key}
              label="Risky Sign-ins"
              badge={identityStats.riskySignInsToday}
            />
            <TabButton
              active={activeTab === 'privileges'}
              onClick={() => setActiveTab('privileges')}
              icon={Lock}
              label="Privilege Changes"
            />
            <TabButton
              active={activeTab === 'service_accounts'}
              onClick={() => setActiveTab('service_accounts')}
              icon={Server}
              label="Service Accounts"
            />
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-[var(--surface)] rounded-lg p-1 border border-[var(--border)]">
              {(['1h', '24h', '7d', '30d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={cn(
                    'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                    timeRange === range
                      ? 'bg-[var(--emerald-500)] text-white'
                      : 'text-[var(--muted)] hover:text-[var(--fg)]'
                  )}
                >
                  {range}
                </button>
              ))}
            </div>
            <button
              onClick={() => router.reload({ preserveScroll: true })}
              className="p-2 text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-2)] rounded-lg transition-colors"
              title="Refresh identity data"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* High Risk Users */}
            <div className="card-sentinel">
              <div className="card-sentinel-header">
                <h2 className="card-sentinel-title">High Risk Users</h2>
                <button
                  onClick={() => setActiveTab('users')}
                  className="text-sm text-[var(--emerald-400)] hover:text-[var(--emerald-200)]"
                >
                  View all
                </button>
              </div>
              <div className="divide-y divide-[var(--hairline)] max-h-96 overflow-y-auto">
                {highRiskUsers.slice(0, 5).map((user) => (
                  <UserRiskRow
                    key={user.userId}
                    user={user}
                    onClick={() => setSelectedUser(user)}
                  />
                ))}
                {highRiskUsers.length === 0 && (
                  <div className="p-8 text-center text-[var(--muted)]">
                    <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>{riskScoringUnavailable ? 'Risk scoring data unavailable' : 'No high risk users detected'}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Recent Risky Sign-ins */}
            <div className="card-sentinel">
              <div className="card-sentinel-header">
                <h2 className="card-sentinel-title">Recent Risky Sign-ins</h2>
                <button
                  onClick={() => setActiveTab('signins')}
                  className="text-sm text-[var(--emerald-400)] hover:text-[var(--emerald-200)]"
                >
                  View all
                </button>
              </div>
              <div className="divide-y divide-[var(--hairline)] max-h-96 overflow-y-auto">
                {riskySignIns.slice(0, 5).map((signIn) => (
                  <SignInRow key={signIn.id} signIn={signIn} />
                ))}
                {riskySignIns.length === 0 && (
                  <div className="p-8 text-center text-[var(--muted)]">
                    <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>{sourceUnavailable('riskySignIns') ? 'Risky sign-in data unavailable' : azureAdDisabled ? 'Azure AD sign-in collection disabled' : 'No risky sign-ins detected'}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Privilege Changes Timeline */}
            <div className="lg:col-span-2 card-sentinel">
              <div className="card-sentinel-header">
                <h2 className="card-sentinel-title">Privilege Changes Timeline</h2>
                <button
                  onClick={() => setActiveTab('privileges')}
                  className="text-sm text-[var(--emerald-400)] hover:text-[var(--emerald-200)]"
                >
                  View all
                </button>
              </div>
              <div className="p-4">
                <div className="space-y-4">
                  {privilegeChanges.slice(0, 5).map((change) => (
                    <PrivilegeChangeRow key={change.id} change={change} />
                  ))}
                  {privilegeChanges.length === 0 && (
                    <div className="py-8 text-center text-[var(--muted)]">
                      <Lock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>{sourceUnavailable('privilegeChanges') ? 'Privilege change data unavailable' : azureAdDisabled ? 'Azure AD audit collection disabled' : 'No privilege changes detected'}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Users Tab */}
        {activeTab === 'users' && (
          <div className="flex gap-6">
            <div className="flex-1 card-sentinel">
              <div className="card-sentinel-header">
                <h2 className="card-sentinel-title">User Risk Scores</h2>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                    <input
                      type="text"
                      placeholder="Search users..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="input-sentinel w-48 pl-10"
                    />
                  </div>
                  <Select
                    value={riskFilter}
                    onValueChange={(value) => setRiskFilter(value as typeof riskFilter)}
                    placeholder="All Risks"
                    className="input-sentinel px-3 py-1.5"
                  >
                    <SelectItem value="all">All Risks</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </Select>
                </div>
              </div>
              <div className="divide-y divide-[var(--hairline)] max-h-[600px] overflow-y-auto">
                {filteredUsers.map((user) => (
                  <UserRiskRow
                    key={user.userId}
                    user={user}
                    onClick={() => setSelectedUser(user)}
                    selected={selectedUser?.userId === user.userId}
                  />
                ))}
                {filteredUsers.length === 0 && (
                  <div className="p-8 text-center text-[var(--muted)]">
                    <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>{riskScoringUnavailable ? 'Risk scoring data unavailable' : 'No users match the current filters'}</p>
                  </div>
                )}
              </div>
            </div>

            {/* User Detail Panel */}
            <div className="w-96 card-sentinel flex flex-col">
              <div className="card-sentinel-header">
                <h2 className="card-sentinel-title">User Details</h2>
              </div>
              {selectedUser ? (
                <UserDetailPanel
                  user={selectedUser}
                  onViewActivity={() => {
                    setSearchTerm(selectedUser.userPrincipalName)
                    setActiveTab('signins')
                  }}
                />
              ) : (
                <div className="flex-1 flex items-center justify-center text-[var(--muted)]">
                  <div className="text-center">
                    <User className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a user to view details</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Sign-ins Tab */}
        {activeTab === 'signins' && (
          <div className="card-sentinel">
            <div className="card-sentinel-header">
              <h2 className="card-sentinel-title">Risky Sign-ins</h2>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                  <input
                    type="text"
                    placeholder="Search sign-ins..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="input-sentinel w-48 pl-10"
                  />
                </div>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[var(--bg-2)] text-[var(--muted)] text-xs uppercase tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-3">User</th>
                    <th className="text-left px-4 py-3">Time</th>
                    <th className="text-left px-4 py-3">Risk</th>
                    <th className="text-left px-4 py-3">Location</th>
                    <th className="text-left px-4 py-3">IP Address</th>
                    <th className="text-left px-4 py-3">Application</th>
                    <th className="text-left px-4 py-3">Device</th>
                    <th className="text-left px-4 py-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--hairline)]">
                  {filteredSignIns.map((signIn) => (
                    <SignInTableRow key={signIn.id} signIn={signIn} />
                  ))}
                </tbody>
              </table>
              {filteredSignIns.length === 0 && (
                <div className="p-8 text-center text-[var(--muted)]">
                  <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{sourceUnavailable('riskySignIns') ? 'Risky sign-in data unavailable' : azureAdDisabled ? 'Azure AD sign-in collection disabled' : 'No risky sign-ins found'}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Privileges Tab */}
        {activeTab === 'privileges' && (
          <div className="card-sentinel">
            <div className="card-sentinel-header">
              <h2 className="card-sentinel-title">Privilege Changes</h2>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                  <input
                    type="text"
                    placeholder="Search..."
                    className="input-sentinel w-48 pl-10"
                  />
                </div>
              </div>
            </div>
            <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
              {privilegeChanges.map((change) => (
                <PrivilegeChangeRow key={change.id} change={change} expanded />
              ))}
              {privilegeChanges.length === 0 && (
                <div className="py-8 text-center text-[var(--muted)]">
                  <Lock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{sourceUnavailable('privilegeChanges') ? 'Privilege change data unavailable' : azureAdDisabled ? 'Azure AD audit collection disabled' : 'No privilege changes found'}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Service Accounts Tab */}
        {activeTab === 'service_accounts' && (
          <div className="card-sentinel">
            <div className="card-sentinel-header">
              <h2 className="card-sentinel-title">Service Account Monitoring</h2>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                  <input
                    type="text"
                    placeholder="Search service accounts..."
                    className="input-sentinel w-48 pl-10"
                  />
                </div>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[var(--bg-2)] text-[var(--muted)] text-xs uppercase tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-3">Name</th>
                    <th className="text-left px-4 py-3">App ID</th>
                    <th className="text-left px-4 py-3">Type</th>
                    <th className="text-left px-4 py-3">Status</th>
                    <th className="text-left px-4 py-3">Last Sign-in</th>
                    <th className="text-left px-4 py-3">Permissions</th>
                    <th className="text-left px-4 py-3">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--hairline)]">
                  {serviceAccounts.map((account) => (
                    <ServiceAccountRow key={account.id} account={account} />
                  ))}
                </tbody>
              </table>
              {serviceAccounts.length === 0 && (
                <div className="p-8 text-center text-[var(--muted)]">
                  <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{sourceUnavailable('serviceAccounts') ? 'Service account data unavailable' : azureAdDisabled ? 'Azure AD service-principal collection disabled' : 'No service accounts found'}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}

// Stat Card Component
interface StatCardProps {
  icon: React.ElementType
  label: string
  value: number | string
  color: 'primary' | 'critical' | 'high' | 'medium' | 'sol-magenta' | 'sol-cyan' | 'emerald'
  subtext?: string
}

function StatCard({ icon: Icon, label, value, color, subtext }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]',
    critical: 'bg-[var(--crit-bg)] text-[var(--crit)]',
    high: 'bg-[var(--high-bg)] text-[var(--high)]',
    medium: 'bg-[var(--med-bg)] text-[var(--med)]',
    'sol-magenta': 'bg-[rgba(217,70,239,0.12)] text-[var(--sol-magenta)]',
    'sol-cyan': 'bg-[rgba(25,251,155,0.12)] text-[var(--sol-cyan)]',
    emerald: 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]',
  }

  return (
    <div className="card-sentinel">
      <div className={cn('p-2 rounded-lg w-fit', colorClasses[color])}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="mt-2">
        <span className="text-xl font-bold text-[var(--fg)]">{value}</span>
        <p className="text-xs text-[var(--muted)] mt-0.5">
          {label}
          {subtext && <span className="text-[var(--subtle)]"> ({subtext})</span>}
        </p>
      </div>
    </div>
  )
}

// Tab Button Component
interface TabButtonProps {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
  badge?: number
}

function TabButton({ active, onClick, icon: Icon, label, badge }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
        active
          ? 'border-[var(--emerald-500)] text-[var(--emerald-400)]'
          : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
      )}
    >
      <Icon className="h-4 w-4" />
      {label}
      {badge !== undefined && badge > 0 && (
        <span className="badge-sentinel badge-sentinel-critical">
          {badge}
        </span>
      )}
    </button>
  )
}

// User Risk Row Component
interface UserRiskRowProps {
  user: UserRisk
  onClick: () => void
  selected?: boolean
}

function UserRiskRow({ user, onClick, selected }: UserRiskRowProps) {
  const config = riskLevelConfig[user.level] || riskLevelConfig.low
  const Icon = config.icon

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-4 p-4 hover:bg-[var(--surface-2)] transition-colors text-left',
        selected && 'bg-[var(--surface-2)]'
      )}
    >
      <div className={cn('p-2 rounded-lg', config.bg)}>
        <Icon className={cn('h-5 w-5', config.color)} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-[var(--fg)] truncate">{user.displayName || user.userPrincipalName}</span>
          <span className={cn(config.badgeClass, 'capitalize')}>
            {user.level}
          </span>
        </div>
        <div className="flex items-center gap-2 mt-1 text-xs text-[var(--muted)]">
          <span>{user.userPrincipalName}</span>
          {user.department && (
            <>
              <span>-</span>
              <span>{user.department}</span>
            </>
          )}
        </div>
      </div>
      <div className="text-right">
        <div className={cn('text-2xl font-bold', config.color)}>{user.score}</div>
        <div className="flex items-center gap-1 justify-end text-xs text-[var(--subtle)]">
          {user.trend === 'increasing' ? (
            <TrendingUp className="h-3 w-3 text-[var(--crit)]" />
          ) : user.trend === 'decreasing' ? (
            <TrendingDown className="h-3 w-3 text-[var(--emerald-400)]" />
          ) : (
            <Minus className="h-3 w-3" />
          )}
          <span>{user.trend}</span>
        </div>
      </div>
      <ChevronRight className="h-5 w-5 text-[var(--subtle)]" />
    </button>
  )
}

// User Detail Panel Component
interface UserDetailPanelProps {
  user: UserRisk
  onViewActivity: () => void
}

function UserDetailPanel({ user, onViewActivity }: UserDetailPanelProps) {
  const config = riskLevelConfig[user.level] || riskLevelConfig.low

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-4">
      <div className="flex items-start gap-3">
        <div className={cn('p-3 rounded-lg', config.bg)}>
          <User className={cn('h-6 w-6', config.color)} />
        </div>
        <div>
          <h3 className="text-[var(--fg)] font-medium">{user.displayName || user.userPrincipalName}</h3>
          <p className="text-sm text-[var(--muted)]">{user.userPrincipalName}</p>
          {user.department && (
            <p className="text-sm text-[var(--subtle)]">{user.department}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Risk Score</label>
          <p className={cn('text-3xl font-bold mt-1', config.color)}>{user.score}</p>
        </div>
        <div>
          <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Risk Level</label>
          <p className={cn('text-lg font-semibold mt-1 capitalize', config.color)}>{user.level}</p>
        </div>
      </div>

      {user.azureAdRiskLevel && (
        <div className="p-3 bg-[var(--bg-2)] rounded-lg">
          <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Azure AD Identity Protection</label>
          <div className="flex items-center gap-2 mt-2">
            <span className={cn(
              user.azureAdRiskLevel === 'high' ? 'badge-sentinel badge-sentinel-critical' :
              user.azureAdRiskLevel === 'medium' ? 'badge-sentinel badge-sentinel-high' :
              'badge-sentinel badge-sentinel-success',
              'capitalize'
            )}>
              {user.azureAdRiskLevel}
            </span>
            <span className="text-xs text-[var(--subtle)]">{user.azureAdRiskState}</span>
          </div>
        </div>
      )}

      <div>
        <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Risk Factors</label>
        <div className="space-y-3 mt-2">
          {user.factors.map((factor, idx) => (
            <div key={idx}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-[var(--fg-2)]">{factor.name}</span>
                <span className="text-sm text-[var(--muted)]">+{factor.contribution}</span>
              </div>
              <div className="h-2 bg-[var(--surface-2)] rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    factor.contribution >= 20 ? 'bg-[var(--crit)]' :
                    factor.contribution >= 15 ? 'bg-[var(--high)]' :
                    factor.contribution >= 10 ? 'bg-[var(--med)]' :
                    'bg-[var(--emerald-500)]'
                  )}
                  style={{ width: `${Math.min(factor.contribution * 5, 100)}%` }}
                />
              </div>
              <p className="text-xs text-[var(--subtle)] mt-1">{factor.details}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Last Updated</label>
        <p className="text-sm text-[var(--fg)] mt-1">{formatDate(user.lastUpdated)}</p>
      </div>

      <div className="pt-4">
        <button onClick={onViewActivity} className="btn-sentinel btn-sentinel-secondary w-full">
          <Eye className="h-4 w-4" />
          View Activity
        </button>
      </div>
    </div>
  )
}

// Sign-in Row Component
interface SignInRowProps {
  signIn: RiskySignIn
}

function SignInRow({ signIn }: SignInRowProps) {
  const riskConfig = riskLevelConfig[signIn.riskLevelDuringSignIn] || riskLevelConfig.none
  const Icon = riskConfig.icon

  return (
    <div className="p-4 hover:bg-[var(--surface-2)] transition-colors">
      <div className="flex items-start gap-4">
        <div className={cn('p-2 rounded-lg', riskConfig.bg)}>
          <Icon className={cn('h-5 w-5', riskConfig.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium text-[var(--fg)]">{signIn.userPrincipalName}</span>
            <span className={cn(riskConfig.badgeClass, 'capitalize')}>
              {signIn.riskLevelDuringSignIn}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-[var(--muted)]">
            <span className="flex items-center gap-1">
              <MapPin className="h-3 w-3" />
              {signIn.location.city}, {signIn.location.country}
            </span>
            <span className="flex items-center gap-1">
              <Globe className="h-3 w-3" />
              {signIn.ipAddress}
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatDate(signIn.timestamp)}
            </span>
          </div>
        </div>
        <div className="text-right">
          {signIn.statusErrorCode === 0 ? (
            <span className="badge-sentinel badge-sentinel-success">Success</span>
          ) : (
            <span className="badge-sentinel badge-sentinel-critical">Failed</span>
          )}
        </div>
      </div>
    </div>
  )
}

// Sign-in Table Row Component
function SignInTableRow({ signIn }: SignInRowProps) {
  const riskConfig = riskLevelConfig[signIn.riskLevelDuringSignIn] || riskLevelConfig.none

  return (
    <tr className="hover:bg-[var(--surface-2)]">
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg)]">{signIn.userPrincipalName}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)]">{formatDate(signIn.timestamp)}</span>
      </td>
      <td className="px-4 py-3">
        <span className={cn(riskConfig.badgeClass, 'capitalize')}>
          {signIn.riskLevelDuringSignIn}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)]">
          {signIn.location.city && `${signIn.location.city}, `}
          {signIn.location.country || 'Unknown'}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)] font-[var(--mono)]">{signIn.ipAddress}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)]">{signIn.appDisplayName}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--muted)]">
          {signIn.deviceDetail?.browser || 'Unknown'} / {signIn.deviceDetail?.operatingSystem || 'Unknown'}
        </span>
      </td>
      <td className="px-4 py-3">
        {signIn.statusErrorCode === 0 ? (
          <span className="badge-sentinel badge-sentinel-success">Success</span>
        ) : (
          <span className="badge-sentinel badge-sentinel-critical">
            Failed ({signIn.statusErrorCode})
          </span>
        )}
      </td>
    </tr>
  )
}

// Privilege Change Row Component
interface PrivilegeChangeRowProps {
  change: PrivilegeChange
  expanded?: boolean
}

function PrivilegeChangeRow({ change, expanded }: PrivilegeChangeRowProps) {
  const initiator = change.initiatedBy?.user?.displayName ||
                    change.initiatedBy?.app?.displayName ||
                    'Unknown'
  const target = change.targetResources?.[0]?.displayName ||
                 change.targetResources?.[0]?.userPrincipalName ||
                 'Unknown'

  return (
    <div className="flex items-start gap-4 p-4 bg-[var(--bg-2)] rounded-lg">
      <div className="p-2 rounded-lg bg-[rgba(217,70,239,0.12)]">
        <Key className="h-5 w-5 text-[var(--sol-magenta)]" />
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium text-[var(--fg)]">{change.activity}</span>
          <span className={cn(
            change.result === 'success' ? 'badge-sentinel badge-sentinel-success' : 'badge-sentinel badge-sentinel-critical'
          )}>
            {change.result}
          </span>
        </div>
        <div className="text-xs text-[var(--muted)] space-y-1">
          <p>
            <span className="text-[var(--subtle)]">Initiated by:</span> {initiator}
          </p>
          <p>
            <span className="text-[var(--subtle)]">Target:</span> {target}
          </p>
          {expanded && change.category && (
            <p>
              <span className="text-[var(--subtle)]">Category:</span> {change.category}
            </p>
          )}
        </div>
      </div>
      <div className="text-right text-xs text-[var(--subtle)]">
        <Clock className="h-3 w-3 inline mr-1" />
        {formatDate(change.timestamp)}
      </div>
    </div>
  )
}

// Service Account Row Component
interface ServiceAccountRowProps {
  account: ServiceAccount
}

function ServiceAccountRow({ account }: ServiceAccountRowProps) {
  const riskConfig = riskLevelConfig[account.riskLevel || 'none'] || riskLevelConfig.none

  return (
    <tr className="hover:bg-[var(--surface-2)]">
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg)]">{account.displayName}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)] font-[var(--mono)] text-xs">{account.appId}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)]">{account.servicePrincipalType}</span>
      </td>
      <td className="px-4 py-3">
        {account.accountEnabled ? (
          <span className="badge-sentinel badge-sentinel-success">Enabled</span>
        ) : (
          <span className="badge-sentinel badge-sentinel-critical">Disabled</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--muted)]">
          {account.signInActivity?.lastSignInDateTime
            ? formatDate(account.signInActivity.lastSignInDateTime)
            : 'Never'}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--fg-2)]">{account.permissionGrantsCount || 0}</span>
      </td>
      <td className="px-4 py-3">
        {account.riskLevel && (
          <span className={cn(riskConfig.badgeClass, 'capitalize')}>
            {account.riskLevel}
          </span>
        )}
      </td>
    </tr>
  )
}
