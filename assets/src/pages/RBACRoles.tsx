import { useState, useCallback, useEffect } from 'react'
import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  Lock,
  Plus,
  ChevronDown,
  ChevronRight,
  Pencil,
  Trash2,
  Copy,
  FileText,
  Users,
  AlertTriangle,
  Check,
  Info
} from 'lucide-react'
import { Dialog, DialogFooter } from '@/components/ui/baseui'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

interface Role {
  id: string
  name: string
  slug: string
  description: string
  builtin: boolean
  priority: number
  color?: string
  userCount?: number
}

interface RoleTemplate {
  key: string
  name: string
  description: string
  permissions: string[]
}

interface PermissionCategory {
  category: string
  permissions: Array<{ slug: string; description: string }>
}

interface RoleHierarchy {
  [slug: string]: number
}

interface RBACRolesProps {
  roles: Role[]
  permissionCategories: PermissionCategory[]
  builtinRoles: Role[]
  templates?: RoleTemplate[]
  hierarchy?: RoleHierarchy
}

export default function RBACRoles({
  roles: rawRoles,
  permissionCategories: rawCategories,
  builtinRoles,
  templates: rawTemplates,
  hierarchy: rawHierarchy
}: RBACRolesProps) {
  const roles = rawRoles || []
  const permissionCategories = rawCategories || []
  const [templates, setTemplates] = useState<RoleTemplate[]>(rawTemplates || [])
  const [hierarchy, setHierarchy] = useState<RoleHierarchy>(rawHierarchy || {})
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showTemplateModal, setShowTemplateModal] = useState(false)
  const [showCloneModal, setShowCloneModal] = useState(false)
  const [cloneSource, setCloneSource] = useState<Role | null>(null)
  const [newRole, setNewRole] = useState({
    name: '',
    slug: '',
    description: '',
    priority: 50,
    color: '#6366f1'
  })
  const [deleteConfirm, setDeleteConfirm] = useState<Role | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)

  // Fetch templates and hierarchy on mount
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [templatesRes, hierarchyRes] = await Promise.all([
          fetch('/api/v1/rbac/templates'),
          fetch('/api/v1/rbac/hierarchy')
        ])

        if (templatesRes.ok) {
          const templatesData = await templatesRes.json()
          setTemplates(templatesData.data || [])
        }

        if (hierarchyRes.ok) {
          const hierarchyData = await hierarchyRes.json()
          setHierarchy(hierarchyData.data?.hierarchy || {})
        }
      } catch (error) {
        logger.error('Failed to fetch RBAC data:', error)
      }
    }

    if (!rawTemplates || !rawHierarchy) {
      fetchData()
    }
  }, [rawTemplates, rawHierarchy])

  const toggleCategory = (category: string) => {
    setExpandedCategory((prev) => (prev === category ? null : category))
  }

  // Create a new custom role
  const handleCreateRole = useCallback(async () => {
    if (!newRole.name || !newRole.slug) return
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/rbac/roles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify(newRole)
      })
      if (response.ok) {
        setShowCreateModal(false)
        setNewRole({ name: '', slug: '', description: '', priority: 50, color: '#6366f1' })
        router.reload({ only: ['roles'] })
      }
    } catch (error) {
      logger.error('Failed to create role:', error)
    } finally {
      setIsLoading(false)
    }
  }, [newRole])

  // Create role from template
  const handleCreateFromTemplate = useCallback(async () => {
    if (!selectedTemplate) return
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/rbac/templates/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({
          template: selectedTemplate,
          name: newRole.name || undefined,
          slug: newRole.slug || undefined,
          description: newRole.description || undefined,
          color: newRole.color
        })
      })
      if (response.ok) {
        setShowTemplateModal(false)
        setSelectedTemplate(null)
        setNewRole({ name: '', slug: '', description: '', priority: 50, color: '#6366f1' })
        router.reload({ only: ['roles'] })
      }
    } catch (error) {
      logger.error('Failed to create role from template:', error)
    } finally {
      setIsLoading(false)
    }
  }, [selectedTemplate, newRole])

  // Clone existing role
  const handleCloneRole = useCallback(async () => {
    if (!cloneSource || !newRole.name || !newRole.slug) return
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/rbac/roles/${cloneSource.id}/clone`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({
          name: newRole.name,
          slug: newRole.slug,
          description: newRole.description,
          color: newRole.color
        })
      })
      if (response.ok) {
        setShowCloneModal(false)
        setCloneSource(null)
        setNewRole({ name: '', slug: '', description: '', priority: 50, color: '#6366f1' })
        router.reload({ only: ['roles'] })
      }
    } catch (error) {
      logger.error('Failed to clone role:', error)
    } finally {
      setIsLoading(false)
    }
  }, [cloneSource, newRole])

  // Delete a custom role
  const handleDeleteRole = useCallback(async (role: Role) => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/v1/rbac/roles/${role.id}`, {
        method: 'DELETE',
        headers: { Accept: 'application/json' }
      })
      if (response.ok) {
        setDeleteConfirm(null)
        router.reload({ only: ['roles'] })
      }
    } catch (error) {
      logger.error('Failed to delete role:', error)
    } finally {
      setIsLoading(false)
    }
  }, [])

  const openCloneModal = (role: Role) => {
    setCloneSource(role)
    setNewRole({
      name: `${role.name} (Copy)`,
      slug: `${role.slug}_copy`,
      description: role.description || '',
      priority: role.priority,
      color: role.color || '#6366f1'
    })
    setShowCloneModal(true)
  }

  const getPriorityBadgeColor = (priority: number) => {
    if (priority >= 90) return 'bg-red-500/20 text-red-400 border-red-500/30'
    if (priority >= 70) return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    if (priority >= 50) return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    if (priority >= 30) return 'bg-green-500/20 text-green-400 border-green-500/30'
    return 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/30'
  }

  return (
    <MainLayout title="Role Management">
      <Head title="Role Management - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Role Management</h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              Manage roles and permissions for users in your organization
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setShowTemplateModal(true)}
              className="flex items-center gap-2 rounded-lg border px-4 py-2 font-medium transition-colors hover:opacity-80"
              style={{
                borderColor: 'var(--muted)',
                backgroundColor: 'var(--surface)',
                color: 'var(--fg)'
              }}
            >
              <FileText className="h-4 w-4" />
              From Template
            </button>
            <button
              type="button"
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 rounded-lg px-4 py-2 font-medium text-white transition-colors hover:opacity-90"
              style={{ backgroundColor: 'var(--emerald-400)' }}
            >
              <Plus className="h-4 w-4" />
              Create Custom Role
            </button>
          </div>
        </div>

        {/* Role Hierarchy Indicator */}
        <div className="card-sentinel rounded-xl border p-4" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="mb-3 flex items-center gap-2">
            <Info className="h-4 w-4 text-blue-400" />
            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Role Hierarchy</h3>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {Object.entries(hierarchy)
              .sort(([, a], [, b]) => b - a)
              .map(([slug, level]) => (
                <div
                  key={slug}
                  className={cn(
                    'flex items-center gap-1.5 rounded-lg border px-3 py-1.5',
                    getPriorityBadgeColor(level)
                  )}
                >
                  <span className="text-xs font-medium">{slug}</span>
                  <span className="text-xs opacity-60">({level})</span>
                </div>
              ))}
          </div>
          <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
            Higher priority roles inherit permissions from lower priority roles in the hierarchy.
          </p>
        </div>

        {/* Roles Table */}
        <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="border-b p-4" style={{ borderColor: 'var(--muted)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>All Roles</h2>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              {roles.filter((r) => r.builtin).length} built-in, {roles.filter((r) => !r.builtin).length}{' '}
              custom
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--muted)' }}>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Role</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Slug</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Description</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Priority</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Users</th>
                  <th className="p-4 text-left text-sm font-medium" style={{ color: 'var(--muted)' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {roles.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                      <Shield className="mx-auto mb-4 h-12 w-12 opacity-50" />
                      <p>No roles configured</p>
                    </td>
                  </tr>
                ) : (
                  roles.map((role) => (
                    <tr
                      key={role.id}
                      className="border-b transition-colors hover:opacity-80"
                      style={{ borderColor: 'var(--muted)' }}
                    >
                      <td className="p-4">
                        <Link
                          href={`/app/settings/roles/${role.id}`}
                          className="flex items-center gap-2 transition-colors"
                          style={{ color: 'var(--emerald-400)' }}
                        >
                          <div
                            className="h-3 w-3 rounded-full"
                            style={{ backgroundColor: role.color || '#6366f1' }}
                          />
                          {role.builtin && <Lock className="h-4 w-4" style={{ color: 'var(--muted)' }} />}
                          <span className="font-medium" style={{ color: 'var(--fg)' }}>{role.name}</span>
                        </Link>
                      </td>
                      <td className="p-4">
                        <span className="font-mono text-sm" style={{ color: 'var(--muted)' }}>{role.slug}</span>
                      </td>
                      <td className="max-w-xs truncate p-4 text-sm" style={{ color: 'var(--fg)' }}>
                        {role.description || '-'}
                      </td>
                      <td className="p-4">
                        <span
                          className={cn(
                            'inline-flex items-center rounded px-2 py-0.5 text-xs font-medium',
                            role.builtin
                              ? 'bg-[var(--muted)]/20 text-[var(--muted)]'
                              : 'bg-[var(--emerald-400)]/20 text-[var(--emerald-400)]'
                          )}
                        >
                          {role.builtin ? 'Built-in' : 'Custom'}
                        </span>
                      </td>
                      <td className="p-4">
                        <span
                          className={cn(
                            'inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium',
                            getPriorityBadgeColor(role.priority)
                          )}
                        >
                          {role.priority}
                        </span>
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-1.5" style={{ color: 'var(--muted)' }}>
                          <Users className="h-4 w-4" />
                          <span className="text-sm">{role.userCount ?? '-'}</span>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-1">
                          <Link
                            href={`/app/settings/roles/${role.id}`}
                            className="rounded-lg p-1.5 transition-colors hover:opacity-80"
                            style={{ color: 'var(--muted)' }}
                            title="Edit"
                          >
                            <Pencil className="h-4 w-4" />
                          </Link>
                          <button
                            type="button"
                            onClick={() => openCloneModal(role)}
                            className="rounded-lg p-1.5 transition-colors hover:opacity-80"
                            style={{ color: 'var(--muted)' }}
                            title="Clone"
                          >
                            <Copy className="h-4 w-4" />
                          </button>
                          {!role.builtin && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation()
                                setDeleteConfirm(role)
                              }}
                              className="rounded-lg p-1.5 transition-colors hover:text-red-400"
                              style={{ color: 'var(--muted)' }}
                              title="Delete"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Permission Categories Reference */}
        <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="border-b p-4" style={{ borderColor: 'var(--muted)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Permission Categories</h2>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              Reference of all {permissionCategories.reduce((acc, cat) => acc + cat.permissions.length, 0)}{' '}
              available permissions
            </p>
          </div>
          <div className="divide-y" style={{ borderColor: 'var(--muted)' }}>
            {permissionCategories.map((cat) => (
              <div key={cat.category} style={{ borderColor: 'var(--muted)' }}>
                <button
                  type="button"
                  onClick={() => toggleCategory(cat.category)}
                  className="flex w-full items-center justify-between p-4 transition-colors hover:opacity-80"
                >
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                    <span className="font-medium capitalize" style={{ color: 'var(--fg)' }}>{cat.category}</span>
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>
                      {cat.permissions.length} permission{cat.permissions.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  {expandedCategory === cat.category ? (
                    <ChevronDown className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  ) : (
                    <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  )}
                </button>
                {expandedCategory === cat.category && (
                  <div className="space-y-2 px-4 pb-4">
                    {cat.permissions.map((perm) => (
                      <div key={perm.slug} className="flex items-start gap-3 py-1 pl-7">
                        <span className="shrink-0 font-mono text-sm" style={{ color: 'var(--emerald-400)' }}>{perm.slug}</span>
                        <span className="text-sm" style={{ color: 'var(--muted)' }}>{perm.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Create Role Modal */}
        <Dialog
          open={showCreateModal}
          onOpenChange={setShowCreateModal}
          title="Create Custom Role"
          maxWidth="30rem"
        >
          {showCreateModal && (
            <>
              <div className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>Role Name</label>
                  <input
                    type="text"
                    value={newRole.name}
                    onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                    placeholder="e.g., Security Analyst"
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Slug (unique identifier)
                  </label>
                  <input
                    type="text"
                    value={newRole.slug}
                    onChange={(e) =>
                      setNewRole({ ...newRole, slug: e.target.value.toLowerCase().replace(/\s+/g, '_') })
                    }
                    placeholder="e.g., security_analyst"
                    className="w-full rounded-lg border px-3 py-2 font-mono focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>Description</label>
                  <textarea
                    value={newRole.description}
                    onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                    placeholder="Describe the role's responsibilities..."
                    rows={3}
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>Priority (1-100)</label>
                    <input
                      type="number"
                      value={newRole.priority}
                      onChange={(e) => setNewRole({ ...newRole, priority: parseInt(e.target.value) || 50 })}
                      min={1}
                      max={100}
                      className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                      style={{
                        borderColor: 'var(--muted)',
                        backgroundColor: 'var(--surface)',
                        color: 'var(--fg)',
                        '--tw-ring-color': 'var(--emerald-400)'
                      } as React.CSSProperties}
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>Color</label>
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        value={newRole.color}
                        onChange={(e) => setNewRole({ ...newRole, color: e.target.value })}
                        className="h-10 w-10 cursor-pointer rounded border"
                        style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}
                      />
                      <input
                        type="text"
                        value={newRole.color}
                        onChange={(e) => setNewRole({ ...newRole, color: e.target.value })}
                        className="flex-1 rounded-lg border px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2"
                        style={{
                          borderColor: 'var(--muted)',
                          backgroundColor: 'var(--surface)',
                          color: 'var(--fg)',
                          '--tw-ring-color': 'var(--emerald-400)'
                        } as React.CSSProperties}
                      />
                    </div>
                  </div>
                </div>
              </div>
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCreateRole}
                  disabled={!newRole.name || !newRole.slug || isLoading}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  style={{ backgroundColor: 'var(--emerald-400)' }}
                >
                  {isLoading ? 'Creating...' : 'Create Role'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* Template Selection Modal */}
        <Dialog
          open={showTemplateModal}
          onOpenChange={(open) => {
            setShowTemplateModal(open)
            if (!open) setSelectedTemplate(null)
          }}
          title="Create Role from Template"
          maxWidth="42rem"
        >
          {showTemplateModal && (
            <>
              <div className="mb-4">
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Select a template to quickly create a role with pre-configured permissions.
                </p>
              </div>
              <div className="grid max-h-80 grid-cols-1 gap-3 overflow-y-auto md:grid-cols-2">
                {templates.map((template) => (
                  <button
                    key={template.key}
                    type="button"
                    onClick={() => setSelectedTemplate(template.key)}
                    className={cn(
                      'rounded-lg border p-4 text-left transition-all',
                      selectedTemplate === template.key
                        ? 'border-[var(--emerald-400)] bg-[var(--emerald-400)]/10'
                        : 'hover:opacity-80'
                    )}
                    style={{
                      borderColor: selectedTemplate === template.key ? 'var(--emerald-400)' : 'var(--muted)',
                      backgroundColor: selectedTemplate === template.key ? undefined : 'var(--surface)'
                    }}
                  >
                    <div className="mb-2 flex items-center justify-between">
                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{template.name}</span>
                      {selectedTemplate === template.key && <Check className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />}
                    </div>
                    <p className="mb-2 text-sm" style={{ color: 'var(--muted)' }}>{template.description}</p>
                    <p className="text-xs" style={{ color: 'var(--muted)' }}>{template.permissions?.length || 0} permissions</p>
                  </button>
                ))}
              </div>
              {selectedTemplate && (
                <div className="mt-4 space-y-4 border-t pt-4" style={{ borderColor: 'var(--muted)' }}>
                  <p className="text-sm" style={{ color: 'var(--muted)' }}>Optionally customize the role:</p>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                        Custom Name (optional)
                      </label>
                      <input
                        type="text"
                        value={newRole.name}
                        onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                        placeholder="Leave empty for default"
                        className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                        style={{
                          borderColor: 'var(--muted)',
                          backgroundColor: 'var(--surface)',
                          color: 'var(--fg)',
                          '--tw-ring-color': 'var(--emerald-400)'
                        } as React.CSSProperties}
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>
                        Custom Slug (optional)
                      </label>
                      <input
                        type="text"
                        value={newRole.slug}
                        onChange={(e) =>
                          setNewRole({ ...newRole, slug: e.target.value.toLowerCase().replace(/\s+/g, '_') })
                        }
                        placeholder="Leave empty for default"
                        className="w-full rounded-lg border px-3 py-2 font-mono focus:outline-none focus:ring-2"
                        style={{
                          borderColor: 'var(--muted)',
                          backgroundColor: 'var(--surface)',
                          color: 'var(--fg)',
                          '--tw-ring-color': 'var(--emerald-400)'
                        } as React.CSSProperties}
                      />
                    </div>
                  </div>
                </div>
              )}
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setShowTemplateModal(false)
                    setSelectedTemplate(null)
                  }}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCreateFromTemplate}
                  disabled={!selectedTemplate || isLoading}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  style={{ backgroundColor: 'var(--emerald-400)' }}
                >
                  {isLoading ? 'Creating...' : 'Create from Template'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* Clone Role Modal */}
        <Dialog
          open={showCloneModal && Boolean(cloneSource)}
          onOpenChange={(open) => {
            setShowCloneModal(open)
            if (!open) setCloneSource(null)
          }}
          title="Clone Role"
          maxWidth="30rem"
        >
          {showCloneModal && cloneSource && (
            <>
              <div className="mb-4 rounded-lg border p-3" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Cloning from:{' '}
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{cloneSource.name}</span>
                </p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>New Role Name</label>
                  <input
                    type="text"
                    value={newRole.name}
                    onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>New Slug</label>
                  <input
                    type="text"
                    value={newRole.slug}
                    onChange={(e) =>
                      setNewRole({ ...newRole, slug: e.target.value.toLowerCase().replace(/\s+/g, '_') })
                    }
                    className="w-full rounded-lg border px-3 py-2 font-mono focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium" style={{ color: 'var(--muted)' }}>Description</label>
                  <textarea
                    value={newRole.description}
                    onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                    rows={2}
                    className="w-full rounded-lg border px-3 py-2 focus:outline-none focus:ring-2"
                    style={{
                      borderColor: 'var(--muted)',
                      backgroundColor: 'var(--surface)',
                      color: 'var(--fg)',
                      '--tw-ring-color': 'var(--emerald-400)'
                    } as React.CSSProperties}
                  />
                </div>
              </div>
              <DialogFooter className="-mx-6 -mb-5 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setShowCloneModal(false)
                    setCloneSource(null)
                  }}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCloneRole}
                  disabled={!newRole.name || !newRole.slug || isLoading}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  style={{ backgroundColor: 'var(--emerald-400)' }}
                >
                  {isLoading ? 'Cloning...' : 'Clone Role'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>

        {/* Delete Confirmation Modal */}
        <Dialog
          open={Boolean(deleteConfirm)}
          onOpenChange={(open) => !open && setDeleteConfirm(null)}
          title={
            <span className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              Delete Role
            </span>
          }
          maxWidth="30rem"
        >
          {deleteConfirm && (
            <>
              <p className="mb-6" style={{ color: 'var(--fg)' }}>
                Are you sure you want to delete the role{' '}
                <span className="font-semibold" style={{ color: 'var(--fg)' }}>{deleteConfirm.name}</span>? This will remove the
                role from all users who currently have it assigned. This action cannot be undone.
              </p>
              <DialogFooter className="-mx-6 -mb-5">
                <button
                  type="button"
                  onClick={() => setDeleteConfirm(null)}
                  className="px-4 py-2 text-sm font-medium transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => handleDeleteRole(deleteConfirm)}
                  disabled={isLoading}
                  className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isLoading ? 'Deleting...' : 'Delete Role'}
                </button>
              </DialogFooter>
            </>
          )}
        </Dialog>
      </div>
    </MainLayout>
  )
}
