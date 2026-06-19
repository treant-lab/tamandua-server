import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Building2,
  ArrowLeft,
  Users,
  Monitor,
  Activity,
  Key,
  Settings,
  Mail,
  UserPlus,
  MoreVertical,
  Trash2,
  RefreshCw,
  Shield,
  Clock,
  AlertCircle,
  CheckCircle,
  XCircle,
  Copy,
  Eye,
  EyeOff,
  Crown,
  Briefcase,
  Rocket,
  Sparkles,
  Ban,
  HardDrive,
  Calendar,
  TrendingUp,
  TrendingDown,
  Minus,
} from 'lucide-react'
import { cn, safeInitial } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useRef, useEffect } from 'react'
import { Dialog, Select, SelectItem } from '@/components/ui/baseui'
import type {
  TenantDetailPageProps,
  TenantUser,
  TenantInvitation,
  APIKey,
  TenantPlan,
  TenantStatus,
  TenantUsageStats,
} from '@/types'

const planIcons: Record<TenantPlan, React.ComponentType<{ className?: string }>> = {
  trial: Sparkles,
  starter: Rocket,
  professional: Briefcase,
  enterprise: Crown,
}

const planColors: Record<TenantPlan, string> = {
  trial: 'text-purple-400 bg-purple-400/10',
  starter: 'text-blue-400 bg-blue-400/10',
  professional: 'text-emerald-400 bg-emerald-400/10',
  enterprise: 'text-amber-400 bg-amber-400/10',
}

const statusColors: Record<TenantStatus, string> = {
  active: 'text-green-400 bg-green-400/10',
  suspended: 'text-red-400 bg-red-400/10',
  pending: 'text-yellow-400 bg-yellow-400/10',
  deactivated: 'text-slate-400 bg-slate-400/10',
}

function TenantLogo({ tenant, className }: { tenant: TenantDetailPageProps['tenant']; className?: string }) {
  if (tenant.logo_url) {
    return (
      <img
        src={tenant.logo_url}
        alt={`${tenant.name} logo`}
        className={cn('rounded-lg object-contain bg-white', className)}
      />
    )
  }

  const initials = tenant.name
    .split(' ')
    .map(word => word[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  const bgColor = tenant.primary_color || '#6366f1'

  return (
    <div
      className={cn('rounded-xl flex items-center justify-center font-bold text-white', className)}
      style={{ backgroundColor: bgColor }}
    >
      {initials}
    </div>
  )
}

function UsersTab({ users, invitations, tenantId }: { users: TenantUser[]; invitations: TenantInvitation[]; tenantId: string }) {
  const [showInviteModal, setShowInviteModal] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<TenantUser['role']>('analyst')
  const [inviting, setInviting] = useState(false)

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault()
    setInviting(true)
    try {
      await fetch(`/api/v1/admin/tenants/${tenantId}/invitations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      })
      setShowInviteModal(false)
      setInviteEmail('')
      router.reload()
    } catch (err) {
      logger.error('Failed to invite user:', err)
    } finally {
      setInviting(false)
    }
  }

  const handleRemoveUser = async (userId: string) => {
    if (!confirm('Are you sure you want to remove this user from the tenant?')) return
    try {
      await fetch(`/api/v1/admin/tenants/${tenantId}/users/${userId}`, {
        method: 'DELETE',
      })
      router.reload()
    } catch (err) {
      logger.error('Failed to remove user:', err)
    }
  }

  const handleRevokeInvitation = async (invitationId: string) => {
    try {
      await fetch(`/api/v1/admin/tenants/${tenantId}/invitations/${invitationId}`, {
        method: 'DELETE',
      })
      router.reload()
    } catch (err) {
      logger.error('Failed to revoke invitation:', err)
    }
  }

  const roleColors: Record<TenantUser['role'], string> = {
    tenant_admin: 'text-purple-400 bg-purple-400/10',
    analyst: 'text-blue-400 bg-blue-400/10',
    viewer: 'text-slate-400 bg-slate-400/10',
    api_only: 'text-amber-400 bg-amber-400/10',
  }

  return (
    <div className="space-y-6">
      {/* Users List */}
      <div className="bg-slate-800 rounded-xl border border-slate-700">
        <div className="p-4 border-b border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Users ({users.length})</h3>
          <button
            onClick={() => setShowInviteModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium"
          >
            <UserPlus className="h-4 w-4" />
            Invite User
          </button>
        </div>

        <div className="divide-y divide-slate-700">
          {users.length > 0 ? users.map((tu) => (
            <div key={tu.id} className="flex items-center justify-between p-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-full bg-slate-600 flex items-center justify-center">
                  <span className="text-white font-medium">
                    {safeInitial(tu.user.name)}
                  </span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">{tu.user.name}</span>
                    {tu.is_primary_contact && (
                      <span className="text-xs bg-primary-500/20 text-primary-400 px-1.5 py-0.5 rounded">
                        Primary
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400">{tu.user.email}</div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <span className={cn(
                  'text-xs px-2 py-1 rounded capitalize',
                  roleColors[tu.role]
                )}>
                  {tu.role.replace('_', ' ')}
                </span>
                <div className="text-xs text-slate-500">
                  Joined {new Date(tu.joined_at).toLocaleDateString()}
                </div>
                <button
                  onClick={() => handleRemoveUser(tu.id)}
                  className="p-1 text-slate-400 hover:text-red-400 rounded"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          )) : (
            <div className="p-8 text-center text-slate-400">
              No users in this tenant
            </div>
          )}
        </div>
      </div>

      {/* Pending Invitations */}
      {invitations.filter(i => i.status === 'pending').length > 0 && (
        <div className="bg-slate-800 rounded-xl border border-slate-700">
          <div className="p-4 border-b border-slate-700">
            <h3 className="text-lg font-semibold text-white">
              Pending Invitations ({invitations.filter(i => i.status === 'pending').length})
            </h3>
          </div>

          <div className="divide-y divide-slate-700">
            {invitations.filter(i => i.status === 'pending').map((inv) => (
              <div key={inv.id} className="flex items-center justify-between p-4">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-full bg-slate-600 flex items-center justify-center">
                    <Mail className="h-5 w-5 text-slate-400" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-white">{inv.email}</div>
                    <div className="text-xs text-slate-400">
                      Invited {new Date(inv.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <span className={cn('text-xs px-2 py-1 rounded capitalize', roleColors[inv.role])}>
                    {inv.role.replace('_', ' ')}
                  </span>
                  <span className="text-xs text-yellow-400 bg-yellow-400/10 px-2 py-1 rounded">
                    Pending
                  </span>
                  <button
                    onClick={() => handleRevokeInvitation(inv.id)}
                    className="p-1 text-slate-400 hover:text-red-400 rounded"
                  >
                    <XCircle className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Invite Modal */}
      <Dialog open={showInviteModal} onOpenChange={setShowInviteModal} title="Invite User">
        <form onSubmit={handleInvite} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Email</label>
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              required
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500"
              placeholder="user@example.com"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Role</label>
            <Select
              value={inviteRole}
              onValueChange={(value) => setInviteRole(value as TenantUser['role'])}
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500"
              fullWidth
            >
              <SelectItem value="tenant_admin">Tenant Admin</SelectItem>
              <SelectItem value="analyst">Analyst</SelectItem>
              <SelectItem value="viewer">Viewer</SelectItem>
              <SelectItem value="api_only">API Only</SelectItem>
            </Select>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setShowInviteModal(false)}
              className="px-4 py-2 text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={inviting}
              className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium disabled:opacity-50"
            >
              {inviting ? 'Sending...' : 'Send Invitation'}
            </button>
          </div>
        </form>
      </Dialog>
    </div>
  )
}

function APIKeysTab({ apiKeys, tenantId }: { apiKeys: APIKey[]; tenantId: string }) {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['read:events', 'read:alerts'])
  const [creating, setCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set())

  const availableScopes = [
    'read:events',
    'read:alerts',
    'write:alerts',
    'read:agents',
    'write:agents',
    'read:settings',
    'write:settings',
    'execute:response',
  ]

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreating(true)
    try {
      const response = await fetch(`/api/v1/admin/tenants/${tenantId}/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName, scopes: newKeyScopes }),
      })
      const data = await response.json()
      setCreatedKey(data.key)
    } catch (err) {
      logger.error('Failed to create API key:', err)
    } finally {
      setCreating(false)
    }
  }

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) return
    try {
      await fetch(`/api/v1/admin/tenants/${tenantId}/api-keys/${keyId}`, {
        method: 'DELETE',
      })
      router.reload()
    } catch (err) {
      logger.error('Failed to revoke API key:', err)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const toggleKeyVisibility = (keyId: string) => {
    setVisibleKeys(prev => {
      const next = new Set(prev)
      if (next.has(keyId)) {
        next.delete(keyId)
      } else {
        next.add(keyId)
      }
      return next
    })
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-800 rounded-xl border border-slate-700">
        <div className="p-4 border-b border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">API Keys ({apiKeys.length})</h3>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium"
          >
            <Key className="h-4 w-4" />
            Create API Key
          </button>
        </div>

        <div className="divide-y divide-slate-700">
          {apiKeys.length > 0 ? apiKeys.map((key) => (
            <div key={key.id} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <Key className={cn('h-5 w-5', key.is_active ? 'text-green-400' : 'text-slate-500')} />
                  <span className="text-sm font-medium text-white">{key.name}</span>
                  {!key.is_active && (
                    <span className="text-xs bg-red-400/10 text-red-400 px-2 py-0.5 rounded">Revoked</span>
                  )}
                </div>
                {key.is_active && (
                  <button
                    onClick={() => handleRevokeKey(key.id)}
                    className="text-xs text-red-400 hover:text-red-300"
                  >
                    Revoke
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2 mb-2">
                <code className="text-sm bg-slate-700 px-2 py-1 rounded text-slate-300 font-mono">
                  {key.key_prefix}...
                </code>
                <button
                  onClick={() => copyToClipboard(key.key_prefix)}
                  className="p-1 text-slate-400 hover:text-white"
                >
                  <Copy className="h-4 w-4" />
                </button>
              </div>

              <div className="flex flex-wrap gap-1 mb-2">
                {key.scopes.map(scope => (
                  <span key={scope} className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">
                    {scope}
                  </span>
                ))}
              </div>

              <div className="text-xs text-slate-500">
                Created {new Date(key.created_at).toLocaleDateString()}
                {key.last_used_at && ` | Last used ${new Date(key.last_used_at).toLocaleDateString()}`}
                {key.expires_at && ` | Expires ${new Date(key.expires_at).toLocaleDateString()}`}
              </div>
            </div>
          )) : (
            <div className="p-8 text-center text-slate-400">
              No API keys created yet
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      <Dialog
        open={showCreateModal}
        onOpenChange={(open) => {
          if (!open) {
            const hadCreatedKey = !!createdKey
            setShowCreateModal(false)
            setCreatedKey(null)
            setNewKeyName('')
            if (hadCreatedKey) router.reload()
          }
        }}
        title={createdKey ? 'API Key Created' : 'Create API Key'}
      >
        {createdKey ? (
          <>
            <div className="bg-green-900/30 border border-green-700 rounded-lg p-4 mb-4">
              <p className="text-sm text-green-300 mb-2">
                Copy this key now. You won't be able to see it again.
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-sm bg-slate-900 px-3 py-2 rounded text-white font-mono break-all">
                  {createdKey}
                </code>
                <button
                  onClick={() => copyToClipboard(createdKey)}
                  className="p-2 bg-slate-700 hover:bg-slate-600 rounded"
                >
                  <Copy className="h-4 w-4 text-white" />
                </button>
              </div>
            </div>
            <button
              onClick={() => {
                setShowCreateModal(false)
                setCreatedKey(null)
                setNewKeyName('')
                router.reload()
              }}
              className="w-full bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium"
            >
              Done
            </button>
          </>
        ) : (
          <form onSubmit={handleCreateKey} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                required
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500"
                placeholder="My API Key"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Scopes</label>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {availableScopes.map(scope => (
                  <label key={scope} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={newKeyScopes.includes(scope)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setNewKeyScopes([...newKeyScopes, scope])
                        } else {
                          setNewKeyScopes(newKeyScopes.filter(s => s !== scope))
                        }
                      }}
                      className="h-4 w-4 rounded border-slate-600 bg-slate-700 text-primary-600"
                    />
                    <span className="text-sm text-slate-300 font-mono">{scope}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={creating || !newKeyName || newKeyScopes.length === 0}
                className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium disabled:opacity-50"
              >
                {creating ? 'Creating...' : 'Create Key'}
              </button>
            </div>
          </form>
        )}
      </Dialog>
    </div>
  )
}

function UsageTab({ usageStats, license }: { usageStats: TenantUsageStats[]; license: TenantDetailPageProps['license'] }) {
  // Calculate trends
  const latestStats = usageStats[usageStats.length - 1]
  const previousStats = usageStats[usageStats.length - 2]

  const getTrend = (current: number, previous: number | undefined) => {
    if (!previous) return { direction: 'stable' as const, value: 0 }
    const change = ((current - previous) / previous) * 100
    if (change > 5) return { direction: 'up' as const, value: Math.round(change) }
    if (change < -5) return { direction: 'down' as const, value: Math.round(Math.abs(change)) }
    return { direction: 'stable' as const, value: 0 }
  }

  const TrendIcon = ({ direction }: { direction: 'up' | 'down' | 'stable' }) => {
    if (direction === 'up') return <TrendingUp className="h-4 w-4 text-green-400" />
    if (direction === 'down') return <TrendingDown className="h-4 w-4 text-red-400" />
    return <Minus className="h-4 w-4 text-slate-400" />
  }

  return (
    <div className="space-y-6">
      {/* License Info */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">License</h3>
        <div className="grid grid-cols-2 gap-6">
          <div>
            <div className="text-sm text-slate-400 mb-1">Plan</div>
            <div className="text-lg font-semibold text-white capitalize">{license.plan}</div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Status</div>
            <div className={cn(
              'text-lg font-semibold capitalize',
              license.status === 'active' ? 'text-green-400' :
              license.status === 'grace_period' ? 'text-yellow-400' : 'text-red-400'
            )}>
              {license.status.replace('_', ' ')}
            </div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Started</div>
            <div className="text-white">{new Date(license.started_at).toLocaleDateString()}</div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Expires</div>
            <div className="text-white">{new Date(license.expires_at).toLocaleDateString()}</div>
          </div>
        </div>
      </div>

      {/* Usage Limits */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Usage vs Limits</h3>
        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-slate-400">Agents</span>
              <span className="text-white">
                {license.usage.agents} / {license.limits.max_agents}
              </span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  (license.usage.agents / license.limits.max_agents) > 0.9
                    ? 'bg-red-500'
                    : (license.usage.agents / license.limits.max_agents) > 0.7
                    ? 'bg-yellow-500'
                    : 'bg-primary-500'
                )}
                style={{ width: `${Math.min(100, (license.usage.agents / license.limits.max_agents) * 100)}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-slate-400">Users</span>
              <span className="text-white">
                {license.usage.users} / {license.limits.max_users}
              </span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  (license.usage.users / license.limits.max_users) > 0.9
                    ? 'bg-red-500'
                    : (license.usage.users / license.limits.max_users) > 0.7
                    ? 'bg-yellow-500'
                    : 'bg-primary-500'
                )}
                style={{ width: `${Math.min(100, (license.usage.users / license.limits.max_users) * 100)}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-slate-400">Events Today</span>
              <span className="text-white">
                {license.usage.events_today.toLocaleString()} / {license.limits.max_events_per_day.toLocaleString()}
              </span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  (license.usage.events_today / license.limits.max_events_per_day) > 0.9
                    ? 'bg-red-500'
                    : (license.usage.events_today / license.limits.max_events_per_day) > 0.7
                    ? 'bg-yellow-500'
                    : 'bg-primary-500'
                )}
                style={{ width: `${Math.min(100, (license.usage.events_today / license.limits.max_events_per_day) * 100)}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Usage Stats Grid */}
      {latestStats && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
            <div className="flex items-center justify-between mb-2">
              <Monitor className="h-5 w-5 text-blue-400" />
              <TrendIcon direction={getTrend(latestStats.agents_active, previousStats?.agents_active).direction} />
            </div>
            <div className="text-2xl font-bold text-white">{latestStats.agents_active}</div>
            <div className="text-sm text-slate-400">Active Agents</div>
          </div>

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
            <div className="flex items-center justify-between mb-2">
              <Activity className="h-5 w-5 text-green-400" />
              <TrendIcon direction={getTrend(latestStats.events_ingested, previousStats?.events_ingested).direction} />
            </div>
            <div className="text-2xl font-bold text-white">{latestStats.events_ingested.toLocaleString()}</div>
            <div className="text-sm text-slate-400">Events Ingested</div>
          </div>

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
            <div className="flex items-center justify-between mb-2">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <TrendIcon direction={getTrend(latestStats.alerts_generated, previousStats?.alerts_generated).direction} />
            </div>
            <div className="text-2xl font-bold text-white">{latestStats.alerts_generated}</div>
            <div className="text-sm text-slate-400">Alerts Generated</div>
          </div>

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
            <div className="flex items-center justify-between mb-2">
              <HardDrive className="h-5 w-5 text-amber-400" />
              <TrendIcon direction={getTrend(latestStats.storage_used_mb, previousStats?.storage_used_mb).direction} />
            </div>
            <div className="text-2xl font-bold text-white">{(latestStats.storage_used_mb / 1024).toFixed(1)} GB</div>
            <div className="text-sm text-slate-400">Storage Used</div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function TenantDetail({ tenant, users, invitations, api_keys, usage_stats, license }: TenantDetailPageProps) {
  const [activeTab, setActiveTab] = useState<'users' | 'api_keys' | 'usage'>('users')
  const PlanIcon = planIcons[tenant.plan]

  const handleStatusChange = async (newStatus: 'activate' | 'suspend' | 'deactivate') => {
    const confirmMsg = newStatus === 'suspend'
      ? `Are you sure you want to suspend "${tenant.name}"? Users will lose access.`
      : newStatus === 'deactivate'
      ? `Are you sure you want to deactivate "${tenant.name}"? This will disable all services.`
      : `Are you sure you want to activate "${tenant.name}"?`

    if (!confirm(confirmMsg)) return

    try {
      await fetch(`/api/v1/admin/tenants/${tenant.id}/${newStatus}`, {
        method: 'POST',
      })
      router.reload()
    } catch (err) {
      logger.error(`Failed to ${newStatus} tenant:`, err)
    }
  }

  return (
    <MainLayout title="Tenant Details">
      <Head title={`${tenant.name} - Admin - Tamandua EDR`} />

      {/* Header */}
      <div className="mb-6">
        <Link
          href="/app/admin/tenants"
          className="flex items-center gap-2 text-sm text-slate-400 hover:text-white mb-4"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Tenants
        </Link>

        <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <TenantLogo tenant={tenant} className="h-16 w-16 text-xl" />
              <div>
                <h1 className="text-2xl font-bold text-white">{tenant.name}</h1>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-slate-400">{tenant.slug}</span>
                  {tenant.domain && (
                    <>
                      <span className="text-slate-600">|</span>
                      <span className="text-slate-400">{tenant.domain}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <span className={cn(
                    'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium capitalize',
                    planColors[tenant.plan]
                  )}>
                    <PlanIcon className="h-3 w-3" />
                    {tenant.plan}
                  </span>
                  <span className={cn(
                    'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium capitalize',
                    statusColors[tenant.status]
                  )}>
                    {tenant.status}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Link
                href={`/app/admin/tenants/${tenant.id}/settings`}
                className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-medium"
              >
                <Settings className="h-4 w-4" />
                Settings
              </Link>
              {tenant.status === 'active' ? (
                <button
                  onClick={() => handleStatusChange('suspend')}
                  className="flex items-center gap-2 bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
                >
                  <Ban className="h-4 w-4" />
                  Suspend
                </button>
              ) : (
                <button
                  onClick={() => handleStatusChange('activate')}
                  className="flex items-center gap-2 bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
                >
                  <CheckCircle className="h-4 w-4" />
                  Activate
                </button>
              )}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-700">
            <div className="flex items-center gap-3">
              <Monitor className="h-5 w-5 text-slate-400" />
              <div>
                <div className="text-lg font-semibold text-white">{tenant.agent_count ?? 0}</div>
                <div className="text-xs text-slate-400">Agents</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Users className="h-5 w-5 text-slate-400" />
              <div>
                <div className="text-lg font-semibold text-white">{tenant.user_count ?? 0}</div>
                <div className="text-xs text-slate-400">Users</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Activity className="h-5 w-5 text-slate-400" />
              <div>
                <div className="text-lg font-semibold text-white">{(tenant.event_count_30d ?? 0).toLocaleString()}</div>
                <div className="text-xs text-slate-400">Events (30d)</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Calendar className="h-5 w-5 text-slate-400" />
              <div>
                <div className="text-lg font-semibold text-white">{new Date(tenant.created_at).toLocaleDateString()}</div>
                <div className="text-xs text-slate-400">Created</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-700 mb-6">
        <nav className="flex gap-6">
          {[
            { id: 'users', label: 'Users', icon: Users },
            { id: 'api_keys', label: 'API Keys', icon: Key },
            { id: 'usage', label: 'Usage', icon: Activity },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={cn(
                'flex items-center gap-2 px-1 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-400'
                  : 'border-transparent text-slate-400 hover:text-white'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'users' && (
        <UsersTab users={users} invitations={invitations} tenantId={tenant.id} />
      )}
      {activeTab === 'api_keys' && (
        <APIKeysTab apiKeys={api_keys} tenantId={tenant.id} />
      )}
      {activeTab === 'usage' && (
        <UsageTab usageStats={usage_stats} license={license} />
      )}
    </MainLayout>
  )
}
