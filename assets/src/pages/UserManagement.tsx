import { useState, useMemo, useCallback, useEffect } from 'react'
import { Head, router, Link } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Users,
  Search,
  UserPlus,
  Shield,
  ShieldOff,
  MoreVertical,
  Clock,
  CheckCircle,
  XCircle,
  X,
  Trash2,
  Eye,
  ArrowUpCircle,
  History,
  AlertTriangle,
  Filter
} from 'lucide-react'
import { Checkbox, Dialog, DialogFooter, Menu, MenuItem, MenuSeparator, Select, SelectItem } from '@/components/ui/baseui'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'

interface UserRole {
  slug: string
  name: string
  id: string
  expiresAt?: string | null
  grantedBy?: string | null
}

interface Role {
  id: string
  name: string
  slug: string
  priority: number
  color?: string
}

interface User {
  id: string
  email: string
  name: string
  role: string
  mfaEnabled: boolean
  isActive?: boolean
  lastLoginAt: string | null
  roles: UserRole[]
}

interface EffectivePermissions {
  permissions: string[]
  count: number
  byCategory: Array<{
    category: string
    granted_count: number
    total_count: number
  }>
}

interface UserManagementProps {
  users: User[]
  availableRoles?: Role[]
}

export default function UserManagement({ users: rawUsers, availableRoles: rawRoles }: UserManagementProps) {
  const users = rawUsers || []
  const [availableRoles, setAvailableRoles] = useState<Role[]>(rawRoles || [])
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isLoading, setIsLoading] = useState<string | null>(null)

  // Modals
  const [editRoleModal, setEditRoleModal] = useState<{ user: User } | null>(null)
  const [permissionsModal, setPermissionsModal] = useState<{ user: User; permissions: EffectivePermissions | null } | null>(null)
  const [elevateModal, setElevateModal] = useState<{ user: User } | null>(null)
  const [auditModal, setAuditModal] = useState<{ user: User; entries: AuditEntry[] } | null>(null)

  // Form state
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(new Set())
  const [elevateRoleId, setElevateRoleId] = useState<string>('')
  const [elevateDuration, setElevateDuration] = useState<number>(4)
  const [elevateReason, setElevateReason] = useState<string>('')

  interface AuditEntry {
    id: string
    action: string
    changes: Record<string, unknown>
    actor: { id: string; email: string } | null
    timestamp: string
  }

  // Fetch roles if not provided
  useEffect(() => {
    if (!rawRoles || rawRoles.length === 0) {
      fetch('/api/v1/rbac/roles')
        .then((res) => res.json())
        .then((data) => setAvailableRoles(data.data || []))
        .catch(console.error)
    }
  }, [rawRoles])

  // Toggle MFA for a user
  const handleToggleMFA = useCallback(async (user: User) => {
    setIsLoading(user.id)
    try {
      const response = await fetch(`/api/v1/users/${user.id}/mfa`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ enabled: !user.mfaEnabled })
      })
      if (response.ok) {
        router.reload({ only: ['users'] })
      }
    } catch (error) {
      logger.error('Failed to toggle MFA:', error)
    } finally {
      setIsLoading(null)
    }
  }, [])

  // Toggle user status (activate/deactivate)
  const handleToggleStatus = useCallback(async (user: User) => {
    setIsLoading(user.id)
    const newStatus = user.isActive === false ? 'active' : 'inactive'
    try {
      const response = await fetch(`/api/v1/users/${user.id}/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      })
      if (response.ok) {
        router.reload({ only: ['users'] })
      }
    } catch (error) {
      logger.error('Failed to toggle status:', error)
    } finally {
      setIsLoading(null)
    }
  }, [])

  // Open edit role modal
  const handleOpenEditRole = useCallback((user: User) => {
    setSelectedRoles(new Set(user.roles.map((r) => r.id)))
    setEditRoleModal({ user })
  }, [])

  // Update user roles (multi-role)
  const handleUpdateRoles = useCallback(async () => {
    if (!editRoleModal) return
    setIsLoading(editRoleModal.user.id)
    try {
      // First, remove all existing roles
      for (const role of editRoleModal.user.roles) {
        await fetch(`/api/v1/rbac/users/${editRoleModal.user.id}/roles/${role.id}`, {
          method: 'DELETE',
          headers: { Accept: 'application/json' }
        })
      }

      // Then add selected roles
      for (const roleId of selectedRoles) {
        await fetch(`/api/v1/rbac/users/${editRoleModal.user.id}/roles`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json'
          },
          body: JSON.stringify({ role_id: roleId })
        })
      }

      router.reload({ only: ['users'] })
      setEditRoleModal(null)
    } catch (error) {
      logger.error('Failed to update roles:', error)
    } finally {
      setIsLoading(null)
    }
  }, [editRoleModal, selectedRoles])

  // View effective permissions
  const handleViewPermissions = useCallback(async (user: User) => {
    setPermissionsModal({ user, permissions: null })

    try {
      const response = await fetch(`/api/v1/rbac/users/${user.id}/effective-permissions`)
      if (response.ok) {
        const data = await response.json()
        setPermissionsModal({
          user,
          permissions: {
            permissions: data.data.effective_permissions || [],
            count: data.data.permission_count || 0,
            byCategory: data.data.breakdown_by_category || []
          }
        })
      }
    } catch (error) {
      logger.error('Failed to fetch permissions:', error)
    }
  }, [])

  // Open elevate modal
  const handleOpenElevate = useCallback((user: User) => {
    setElevateRoleId('')
    setElevateDuration(4)
    setElevateReason('')
    setElevateModal({ user })
  }, [])

  // Temporary role elevation
  const handleElevateRole = useCallback(async () => {
    if (!elevateModal || !elevateRoleId) return
    setIsLoading(elevateModal.user.id)

    try {
      const response = await fetch(`/api/v1/rbac/users/${elevateModal.user.id}/elevate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({
          role_id: elevateRoleId,
          duration_hours: elevateDuration,
          reason: elevateReason
        })
      })

      if (response.ok) {
        router.reload({ only: ['users'] })
        setElevateModal(null)
      }
    } catch (error) {
      logger.error('Failed to elevate role:', error)
    } finally {
      setIsLoading(null)
    }
  }, [elevateModal, elevateRoleId, elevateDuration, elevateReason])

  // View user audit log
  const handleViewAudit = useCallback(async (user: User) => {
    setAuditModal({ user, entries: [] })

    try {
      const response = await fetch(`/api/v1/rbac/users/${user.id}/audit-log?limit=50`)
      if (response.ok) {
        const data = await response.json()
        setAuditModal({ user, entries: data.data?.entries || [] })
      }
    } catch (error) {
      logger.error('Failed to fetch audit log:', error)
    }
  }, [])

  // Remove a specific role from user
  const handleRemoveRole = useCallback(async (user: User, roleId: string) => {
    if (!confirm('Remove this role from the user?')) return
    setIsLoading(user.id)

    try {
      const response = await fetch(`/api/v1/rbac/users/${user.id}/roles/${roleId}`, {
        method: 'DELETE',
        headers: { Accept: 'application/json' }
      })

      if (response.ok) {
        router.reload({ only: ['users'] })
      }
    } catch (error) {
      logger.error('Failed to remove role:', error)
    } finally {
      setIsLoading(null)
    }
  }, [])

  const filteredUsers = useMemo(() => {
    let result = users

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      result = result.filter(
        (u) =>
          u.email.toLowerCase().includes(query) ||
          u.name.toLowerCase().includes(query) ||
          u.roles.some((r) => r.name.toLowerCase().includes(query))
      )
    }

    // Role filter
    if (roleFilter) {
      result = result.filter((u) => u.roles.some((r) => r.id === roleFilter))
    }

    // Status filter
    if (statusFilter !== 'all') {
      result = result.filter((u) =>
        statusFilter === 'active' ? u.isActive !== false : u.isActive === false
      )
    }

    return result
  }, [users, searchQuery, roleFilter, statusFilter])

  const toggleRoleSelection = (roleId: string) => {
    setSelectedRoles((prev) => {
      const next = new Set(prev)
      if (next.has(roleId)) {
        next.delete(roleId)
      } else {
        next.add(roleId)
      }
      return next
    })
  }

  return (
    <MainLayout title="User Management">
      <Head title="User Management - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>User Management</h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              Manage users, roles, and access permissions
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/app/settings/roles"
              className="btn-sentinel flex items-center gap-2 rounded-lg px-4 py-2 font-medium transition-colors"
            >
              <Shield className="h-4 w-4" />
              Manage Roles
            </Link>
            <button
              type="button"
              className="btn-sentinel-primary flex items-center gap-2 rounded-lg px-4 py-2 font-medium transition-colors"
            >
              <UserPlus className="h-4 w-4" />
              Invite User
            </button>
          </div>
        </div>

        {/* Search/Filter Bar */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="relative min-w-[300px] flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" style={{ color: 'var(--muted)' }} />
            <input
              type="text"
              placeholder="Search by name, email, or role..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border py-2 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              style={{
                backgroundColor: 'var(--surface)',
                borderColor: 'var(--border)',
                color: 'var(--fg)'
              }}
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            <Select
              value={roleFilter}
              onValueChange={setRoleFilter}
              placeholder="All Roles"
              className="rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <SelectItem value="">All Roles</SelectItem>
              {availableRoles.map((role) => (
                <SelectItem key={role.id} value={role.id}>
                  {role.name}
                </SelectItem>
              ))}
            </Select>
            <Select
              value={statusFilter}
              onValueChange={setStatusFilter}
              placeholder="All Status"
              className="rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="inactive">Inactive</SelectItem>
            </Select>
          </div>
        </div>

        {/* Users Table */}
        <div className="card-sentinel rounded-xl">
          <div className="border-b p-4" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
              All Users
              <span className="ml-2 text-sm font-normal" style={{ color: 'var(--muted)' }}>({filteredUsers.length})</span>
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border)' }}>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>User</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Roles</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>MFA</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Last Login</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                      <Users className="mx-auto mb-4 h-12 w-12 opacity-50" />
                      <p>{users.length === 0 ? 'No users found' : 'No users match your search'}</p>
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((user) => (
                    <tr
                      key={user.id}
                      className="border-b transition-colors hover:bg-white/5"
                      style={{ borderColor: 'var(--border)' }}
                    >
                      <td className="p-4">
                        <div>
                          <span className="font-medium" style={{ color: 'var(--fg)' }}>{user.name || user.email}</span>
                          {user.name && (
                            <p className="text-sm" style={{ color: 'var(--muted)' }}>{user.email}</p>
                          )}
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {(user.roles || []).map((role) => (
                            <div
                              key={role.id}
                              className="group relative inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium"
                              style={{
                                backgroundColor: `${availableRoles.find((r) => r.id === role.id)?.color || '#6366f1'}20`,
                                color: availableRoles.find((r) => r.id === role.id)?.color || '#6366f1'
                              }}
                            >
                              <Shield className="h-3 w-3" />
                              {role.name}
                              {role.expiresAt && (
                                <span className="ml-1" style={{ color: 'var(--amber-400)' }} title={`Expires: ${role.expiresAt}`}>
                                  <Clock className="h-3 w-3" />
                                </span>
                              )}
                              <button
                                type="button"
                                onClick={() => handleRemoveRole(user, role.id)}
                                className="ml-1 hidden group-hover:inline-block"
                                style={{ color: 'var(--rose-400)' }}
                                title="Remove role"
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </div>
                          ))}
                          {user.roles.length === 0 && (
                            <span className="text-sm" style={{ color: 'var(--subtle)' }}>No roles assigned</span>
                          )}
                        </div>
                      </td>
                      <td className="p-4">
                        <span
                          className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium"
                          style={{
                            backgroundColor: user.isActive === false ? 'rgba(var(--rose-400-rgb), 0.2)' : 'rgba(var(--emerald-400-rgb), 0.2)',
                            color: user.isActive === false ? 'var(--rose-400)' : 'var(--emerald-400)'
                          }}
                        >
                          {user.isActive === false ? 'Inactive' : 'Active'}
                        </span>
                      </td>
                      <td className="p-4">
                        {user.mfaEnabled ? (
                          <span className="inline-flex items-center gap-1 text-sm" style={{ color: 'var(--emerald-400)' }}>
                            <CheckCircle className="h-4 w-4" />
                            Enabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-sm" style={{ color: 'var(--subtle)' }}>
                            <XCircle className="h-4 w-4" />
                            Disabled
                          </span>
                        )}
                      </td>
                      <td className="p-4">
                        {user.lastLoginAt ? (
                          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
                            <Clock className="h-4 w-4" />
                            {formatDate(user.lastLoginAt)}
                          </div>
                        ) : (
                          <span className="text-sm" style={{ color: 'var(--subtle)' }}>Never</span>
                        )}
                      </td>
                      <td className="p-4">
                        <Menu
                          align="end"
                          className="w-52"
                          trigger={
                            <button
                              type="button"
                              aria-label={`Open actions for ${user.email}`}
                              className="rounded-lg p-1.5 transition-colors hover:bg-white/10"
                              style={{ color: 'var(--muted)' }}
                            >
                              <MoreVertical className="h-4 w-4" />
                            </button>
                          }
                        >
                          <MenuItem onSelect={() => handleOpenEditRole(user)} disabled={isLoading === user.id}>
                            <Shield className="h-4 w-4" />
                            Manage Roles
                          </MenuItem>
                          <MenuItem onSelect={() => handleViewPermissions(user)} disabled={isLoading === user.id}>
                            <Eye className="h-4 w-4" />
                            View Permissions
                          </MenuItem>
                          <MenuItem onSelect={() => handleOpenElevate(user)} disabled={isLoading === user.id}>
                            <ArrowUpCircle className="h-4 w-4" />
                            Temporary Elevation
                          </MenuItem>
                          <MenuItem onSelect={() => handleViewAudit(user)} disabled={isLoading === user.id}>
                            <History className="h-4 w-4" />
                            View Audit Log
                          </MenuItem>
                          <MenuSeparator />
                          <MenuItem onSelect={() => handleToggleMFA(user)} disabled={isLoading === user.id}>
                            {user.mfaEnabled ? (
                              <>
                                <ShieldOff className="h-4 w-4" />
                                Disable MFA
                              </>
                            ) : (
                              <>
                                <Shield className="h-4 w-4" />
                                Enable MFA
                              </>
                            )}
                          </MenuItem>
                          <MenuItem
                            onSelect={() => handleToggleStatus(user)}
                            disabled={isLoading === user.id}
                            destructive={user.isActive !== false}
                          >
                            {user.isActive === false ? 'Activate User' : 'Deactivate User'}
                          </MenuItem>
                        </Menu>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Edit Roles Modal (Multi-role) */}
        <Dialog
          open={Boolean(editRoleModal)}
          onOpenChange={(open) => !open && setEditRoleModal(null)}
          title="Manage User Roles"
          maxWidth="34rem"
        >
          {editRoleModal && (
            <>
              <div className="mb-4">
                <p className="mb-1 text-sm" style={{ color: 'var(--muted)' }}>User</p>
                <p className="font-medium" style={{ color: 'var(--fg)' }}>{editRoleModal.user.email}</p>
              </div>
              <div className="mb-6">
                <label className="mb-2 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                  Assigned Roles
                </label>
                <p className="mb-3 text-xs" style={{ color: 'var(--subtle)' }}>
                  Select one or more roles to assign. Users inherit permissions from all assigned roles.
                </p>
                <div
                  className="max-h-64 space-y-2 overflow-y-auto rounded-lg border p-3"
                  style={{
                    backgroundColor: 'var(--surface)',
                    borderColor: 'var(--border)'
                  }}
                >
                  {availableRoles.map((role) => (
                    <label
                      key={role.id}
                      className={cn(
                        'flex cursor-pointer items-center gap-3 rounded-lg border p-3 transition-all',
                        selectedRoles.has(role.id)
                          ? 'border-primary-500 bg-primary-500/10'
                          : 'hover:border-white/20'
                      )}
                      style={{
                        borderColor: selectedRoles.has(role.id) ? undefined : 'var(--border)'
                      }}
                    >
                      <Checkbox
                        checked={selectedRoles.has(role.id)}
                        onCheckedChange={() => toggleRoleSelection(role.id)}
                        aria-label={`Assign ${role.name}`}
                      />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <div
                            className="h-3 w-3 rounded-full"
                            style={{ backgroundColor: role.color || '#6366f1' }}
                          />
                          <span className="font-medium" style={{ color: 'var(--fg)' }}>{role.name}</span>
                          <span className="text-xs" style={{ color: 'var(--subtle)' }}>Priority: {role.priority}</span>
                        </div>
                        <p className="mt-0.5 font-mono text-xs" style={{ color: 'var(--muted)' }}>{role.slug}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
              <DialogFooter className="-mx-6 -mb-5">
                <button
                  type="button"
                  onClick={() => setEditRoleModal(null)}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleUpdateRoles}
                  disabled={isLoading === editRoleModal.user.id}
                  className="btn-sentinel-primary rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isLoading === editRoleModal.user.id ? 'Updating...' : 'Update Roles'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* View Permissions Modal */}
        <Dialog
          open={Boolean(permissionsModal)}
          onOpenChange={(open) => !open && setPermissionsModal(null)}
          title="Effective Permissions"
          maxWidth="42rem"
        >
          {permissionsModal && (
            <>
              <div className="mb-4">
                <p className="mb-1 text-sm" style={{ color: 'var(--muted)' }}>User</p>
                <p className="font-medium" style={{ color: 'var(--fg)' }}>{permissionsModal.user.email}</p>
                <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                  Roles: {permissionsModal.user.roles.map((r) => r.name).join(', ') || 'None'}
                </p>
              </div>
              {permissionsModal.permissions === null ? (
                <div className="py-8 text-center" style={{ color: 'var(--subtle)' }}>Loading permissions...</div>
              ) : (
                <>
                  <div
                    className="mb-4 rounded-lg border p-4"
                    style={{
                      backgroundColor: 'var(--surface)',
                      borderColor: 'var(--border)'
                    }}
                  >
                    <p className="text-lg font-medium" style={{ color: 'var(--fg)' }}>
                      {permissionsModal.permissions.count} permissions granted
                    </p>
                  </div>
                  <div className="max-h-80 space-y-3 overflow-y-auto">
                    {permissionsModal.permissions.byCategory.map((cat) => (
                      <div
                        key={cat.category}
                        className="rounded-lg border p-3"
                        style={{
                          borderColor: cat.granted_count === cat.total_count
                            ? 'rgba(var(--emerald-400-rgb), 0.5)'
                            : cat.granted_count > 0
                              ? 'rgba(var(--amber-400-rgb), 0.5)'
                              : 'var(--border)',
                          backgroundColor: cat.granted_count === cat.total_count
                            ? 'rgba(var(--emerald-400-rgb), 0.1)'
                            : cat.granted_count > 0
                              ? 'rgba(var(--amber-400-rgb), 0.1)'
                              : 'var(--surface)'
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium capitalize" style={{ color: 'var(--fg)' }}>{cat.category}</span>
                          <span className="text-sm" style={{ color: 'var(--muted)' }}>
                            {cat.granted_count} / {cat.total_count}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => setPermissionsModal(null)}
                  className="btn-sentinel rounded-lg px-4 py-2 text-sm font-medium transition-colors"
                >
                  Close
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* Temporary Elevation Modal */}
        <Dialog
          open={Boolean(elevateModal)}
          onOpenChange={(open) => !open && setElevateModal(null)}
          title={
            <span className="flex items-center gap-2">
              <ArrowUpCircle className="h-5 w-5" style={{ color: 'var(--amber-400)' }} />
              Temporary Role Elevation
            </span>
          }
          maxWidth="30rem"
        >
          {elevateModal && (
            <>
              <div
                className="mb-4 rounded-lg border p-3"
                style={{
                  borderColor: 'rgba(var(--amber-400-rgb), 0.5)',
                  backgroundColor: 'rgba(var(--amber-400-rgb), 0.1)'
                }}
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-4 w-4" style={{ color: 'var(--amber-400)' }} />
                  <p className="text-sm" style={{ color: 'var(--amber-200)' }}>
                    Temporarily grant elevated permissions to this user. The elevation will automatically
                    expire after the specified duration.
                  </p>
                </div>
              </div>
              <div className="mb-4">
                <p className="mb-1 text-sm" style={{ color: 'var(--muted)' }}>User</p>
                <p className="font-medium" style={{ color: 'var(--fg)' }}>{elevateModal.user.email}</p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="mb-2 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Elevated Role
                  </label>
                  <Select
                    value={elevateRoleId}
                    onValueChange={setElevateRoleId}
                    placeholder="Select a role..."
                    fullWidth
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500"
                  >
                    <SelectItem value="">Select a role...</SelectItem>
                    {availableRoles
                      .filter((r) => !elevateModal.user.roles.some((ur) => ur.id === r.id))
                      .map((role) => (
                        <SelectItem key={role.id} value={role.id}>
                          {role.name} (Priority: {role.priority})
                        </SelectItem>
                      ))}
                  </Select>
                </div>
                <div>
                  <label className="mb-2 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Duration (hours)
                  </label>
                  <Select
                    value={String(elevateDuration)}
                    onValueChange={(value) => setElevateDuration(parseInt(value, 10))}
                    fullWidth
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500"
                  >
                    <SelectItem value="1">1 hour</SelectItem>
                    <SelectItem value="4">4 hours</SelectItem>
                    <SelectItem value="8">8 hours</SelectItem>
                    <SelectItem value="24">24 hours</SelectItem>
                    <SelectItem value="48">48 hours</SelectItem>
                    <SelectItem value="72">72 hours (max)</SelectItem>
                  </Select>
                </div>
                <div>
                  <label className="mb-2 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Reason (required)
                  </label>
                  <textarea
                    value={elevateReason}
                    onChange={(e) => setElevateReason(e.target.value)}
                    placeholder="Explain why this elevation is needed..."
                    rows={2}
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    style={{
                      backgroundColor: 'var(--surface)',
                      borderColor: 'var(--border)',
                      color: 'var(--fg)'
                    }}
                  />
                </div>
              </div>
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => setElevateModal(null)}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleElevateRole}
                  disabled={!elevateRoleId || !elevateReason || isLoading === elevateModal.user.id}
                  className="rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                  style={{
                    backgroundColor: 'var(--amber-600)',
                    color: 'white'
                  }}
                >
                  {isLoading === elevateModal.user.id ? 'Granting...' : 'Grant Elevation'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* Audit Log Modal */}
        <Dialog
          open={Boolean(auditModal)}
          onOpenChange={(open) => !open && setAuditModal(null)}
          title="User Permission Audit Log"
          maxWidth="42rem"
        >
          {auditModal && (
            <>
              <div className="mb-4">
                <p className="mb-1 text-sm" style={{ color: 'var(--muted)' }}>User</p>
                <p className="font-medium" style={{ color: 'var(--fg)' }}>{auditModal.user.email}</p>
              </div>
              <div className="max-h-96 overflow-y-auto">
                {auditModal.entries.length === 0 ? (
                  <div className="py-8 text-center" style={{ color: 'var(--subtle)' }}>No audit entries found</div>
                ) : (
                  <div className="space-y-3">
                    {auditModal.entries.map((entry) => (
                      <div
                        key={entry.id}
                        className="flex items-start gap-4 rounded-lg border p-4"
                        style={{
                          backgroundColor: 'var(--surface)',
                          borderColor: 'var(--border)'
                        }}
                      >
                        <div className="mt-1 h-2 w-2 rounded-full" style={{ backgroundColor: 'var(--sky-400)' }} />
                        <div className="flex-1">
                          <p className="text-sm" style={{ color: 'var(--fg)' }}>
                            <span className="font-medium capitalize">
                              {entry.action.replace(/_/g, ' ')}
                            </span>
                            {entry.actor && (
                              <span style={{ color: 'var(--muted)' }}> by {entry.actor.email}</span>
                            )}
                          </p>
                          {entry.changes && Object.keys(entry.changes).length > 0 && (
                            <div
                              className="mt-2 rounded p-2 font-mono text-xs"
                              style={{
                                backgroundColor: 'var(--bg)',
                                color: 'var(--muted)'
                              }}
                            >
                              {JSON.stringify(entry.changes, null, 2)}
                            </div>
                          )}
                          <p className="mt-2 text-xs" style={{ color: 'var(--subtle)' }}>
                            {new Date(entry.timestamp).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => setAuditModal(null)}
                  className="btn-sentinel rounded-lg px-4 py-2 text-sm font-medium transition-colors"
                >
                  Close
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>
      </div>
    </MainLayout>
  )
}
