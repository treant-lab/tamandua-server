import { useState, useCallback, useMemo } from 'react'
import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Lock,
  Users,
  Save,
  Trash2,
  AlertTriangle,
  Check,
  X,
  ChevronDown,
  ChevronRight,
  Grid3X3,
  List,
  History,
  AlertCircle,
  Info
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { Checkbox } from '@/components/ui/baseui'

interface Permission {
  slug: string
  description: string
}

interface AuditEntry {
  id: string
  action: string
  changes: Record<string, unknown>
  actor: { id: string; email: string } | null
  timestamp: string
}

interface RBACRoleDetailProps {
  role: {
    id: string
    name: string
    slug: string
    description: string
    builtin: boolean
    priority: number
    color?: string
  }
  permissions: string[]
  userCount: number
  allPermissions: Record<string, Permission[]>
  auditLog?: AuditEntry[]
  error?: string
}

type ViewMode = 'grid' | 'list'

export default function RBACRoleDetail({
  role,
  permissions: initialPermissions,
  userCount,
  allPermissions,
  auditLog: initialAuditLog,
  error
}: RBACRoleDetailProps) {
  const [selectedPermissions, setSelectedPermissions] = useState<Set<string>>(
    new Set(initialPermissions || [])
  )
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<ViewMode>('grid')
  const [isSaving, setIsSaving] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [showAuditLog, setShowAuditLog] = useState(false)
  const [auditLog, setAuditLog] = useState<AuditEntry[]>(initialAuditLog || [])
  const [conflicts, setConflicts] = useState<Array<{ permission: string; risk: string }>>([])

  const isBuiltin = role?.builtin ?? false
  const categories = allPermissions || {}

  // Calculate permission stats
  const permissionStats = useMemo(() => {
    const total = Object.values(categories).reduce((acc, perms) => acc + perms.length, 0)
    const granted = selectedPermissions.size
    const byCategory = Object.entries(categories).map(([cat, perms]) => ({
      category: cat,
      total: perms.length,
      granted: perms.filter((p) => selectedPermissions.has(p.slug)).length
    }))
    return { total, granted, byCategory }
  }, [categories, selectedPermissions])

  // Check if permissions have changed
  const hasChanges = useMemo(() => {
    const initial = new Set(initialPermissions || [])
    if (initial.size !== selectedPermissions.size) return true
    for (const perm of selectedPermissions) {
      if (!initial.has(perm)) return true
    }
    return false
  }, [initialPermissions, selectedPermissions])

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(category)) {
        next.delete(category)
      } else {
        next.add(category)
      }
      return next
    })
  }

  const togglePermission = (slug: string) => {
    if (isBuiltin) return
    setSelectedPermissions((prev) => {
      const next = new Set(prev)
      if (next.has(slug)) {
        next.delete(slug)
      } else {
        next.add(slug)
      }
      return next
    })
  }

  const toggleAllInCategory = (category: string) => {
    if (isBuiltin) return
    const perms = categories[category] || []
    const allSelected = perms.every((p) => selectedPermissions.has(p.slug))

    setSelectedPermissions((prev) => {
      const next = new Set(prev)
      if (allSelected) {
        perms.forEach((p) => next.delete(p.slug))
      } else {
        perms.forEach((p) => next.add(p.slug))
      }
      return next
    })
  }

  const checkConflicts = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/rbac/permissions/detect-conflicts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ permissions: Array.from(selectedPermissions) })
      })
      if (response.ok) {
        const data = await response.json()
        setConflicts(data.data?.escalation_risks || [])
      }
    } catch (error) {
      logger.error('Failed to check conflicts:', error)
    }
  }, [selectedPermissions])

  const handleSave = async () => {
    setIsSaving(true)
    setSaveMessage(null)
    try {
      const response = await fetch(`/api/v1/rbac/roles/${role.id}/permissions`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ permissions: Array.from(selectedPermissions) })
      })
      if (response.ok) {
        setSaveMessage({ type: 'success', text: 'Permissions saved successfully' })
        router.reload({ only: ['permissions'] })
      } else {
        const data = await response.json()
        setSaveMessage({ type: 'error', text: data.error || 'Failed to save permissions' })
      }
    } catch {
      setSaveMessage({ type: 'error', text: 'An error occurred while saving' })
    } finally {
      setIsSaving(false)
      setTimeout(() => setSaveMessage(null), 3000)
    }
  }

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to delete this role? This will remove it from all assigned users.'))
      return
    try {
      const response = await fetch(`/api/v1/rbac/roles/${role.id}`, {
        method: 'DELETE',
        headers: { Accept: 'application/json' }
      })
      if (response.ok) {
        window.location.href = '/app/settings/roles'
      }
    } catch (err) {
      logger.error('Failed to delete role:', err)
      setSaveMessage({ type: 'error', text: 'Failed to delete role' })
    }
  }

  const fetchAuditLog = async () => {
    try {
      const response = await fetch(`/api/v1/rbac/audit-log?target_id=${role.id}&target_type=role&limit=20`)
      if (response.ok) {
        const data = await response.json()
        setAuditLog(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch audit log:', error)
    }
  }

  if (!role) {
    return (
      <MainLayout title="Role Not Found">
        <Head title="Role Not Found - Tamandua EDR" />
        <div className="p-12 text-center" style={{ color: 'var(--muted)' }}>
          <p className="text-lg">Role not found</p>
          <Link
            href="/app/settings/roles"
            className="mt-2 inline-block text-primary-400 hover:text-primary-300"
          >
            Back to roles
          </Link>
        </div>
      </MainLayout>
    )
  }

  return (
    <MainLayout title={role.name}>
      <Head title={`${role.name} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Back link */}
        <Link
          href="/app/settings/roles"
          className="inline-flex items-center gap-2 transition-colors hover:opacity-80"
          style={{ color: 'var(--muted)' }}
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Roles
        </Link>

        {/* Error banner */}
        {error && (
          <div className="flex items-center gap-3 rounded-lg border border-red-700 bg-red-900/30 p-4">
            <AlertTriangle className="h-5 w-5 flex-shrink-0 text-red-400" />
            <p className="text-sm text-red-300">{error}</p>
          </div>
        )}

        {/* Save message */}
        {saveMessage && (
          <div
            className={cn(
              'flex items-center gap-3 rounded-lg border p-4',
              saveMessage.type === 'success'
                ? 'border-green-700 bg-green-900/30'
                : 'border-red-700 bg-red-900/30'
            )}
          >
            {saveMessage.type === 'success' ? (
              <Check className="h-5 w-5 flex-shrink-0 text-green-400" />
            ) : (
              <AlertCircle className="h-5 w-5 flex-shrink-0 text-red-400" />
            )}
            <p
              className={cn('text-sm', saveMessage.type === 'success' ? 'text-green-300' : 'text-red-300')}
            >
              {saveMessage.text}
            </p>
          </div>
        )}

        {/* Role Header */}
        <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-4">
              <div
                className="mt-1 h-4 w-4 rounded-full"
                style={{ backgroundColor: role.color || '#6366f1' }}
              />
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{role.name}</h1>
                  {isBuiltin && (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-[var(--muted)]/20 px-2.5 py-1 text-xs font-medium" style={{ color: 'var(--muted)' }}>
                      <Lock className="h-3 w-3" />
                      Built-in
                    </span>
                  )}
                </div>
                <p className="mt-1 font-mono text-sm" style={{ color: 'var(--muted)' }}>{role.slug}</p>
                <p className="mt-2 text-sm" style={{ color: 'var(--fg)' }}>{role.description || 'No description'}</p>
                <div className="mt-3 flex items-center gap-4 text-sm" style={{ color: 'var(--muted)' }}>
                  <span>Priority: {role.priority}</span>
                  <span style={{ color: 'var(--muted)' }}>|</span>
                  <span>
                    {permissionStats.granted} / {permissionStats.total} permissions
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 rounded-lg px-4 py-2" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                <Users className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                <span className="font-medium" style={{ color: 'var(--fg)' }}>{userCount}</span>
                <span className="text-sm" style={{ color: 'var(--muted)' }}>user{userCount !== 1 ? 's' : ''}</span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowAuditLog(!showAuditLog)
                  if (!showAuditLog) fetchAuditLog()
                }}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  showAuditLog
                    ? 'bg-primary-600 text-white'
                    : 'hover:opacity-80'
                )}
                style={!showAuditLog ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' } : undefined}
              >
                <History className="h-4 w-4" />
                Audit Log
              </button>
            </div>
          </div>
        </div>

        {/* Audit Log Panel */}
        {showAuditLog && (
          <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
            <div className="border-b p-4" style={{ borderColor: 'var(--muted)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Role Audit Log</h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>Recent changes to this role</p>
            </div>
            <div className="max-h-64 overflow-y-auto">
              {auditLog.length === 0 ? (
                <div className="p-6 text-center" style={{ color: 'var(--muted)' }}>No audit entries found</div>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--muted)' }}>
                  {auditLog.map((entry) => (
                    <div key={entry.id} className="flex items-start gap-4 p-4" style={{ borderColor: 'var(--muted)' }}>
                      <div className="mt-1 h-2 w-2 rounded-full bg-blue-400" />
                      <div className="flex-1">
                        <p className="text-sm" style={{ color: 'var(--fg)' }}>
                          <span className="font-medium">{entry.action.replace(/_/g, ' ')}</span>
                          {entry.actor && (
                            <span style={{ color: 'var(--muted)' }}> by {entry.actor.email}</span>
                          )}
                        </p>
                        {entry.changes && Object.keys(entry.changes).length > 0 && (
                          <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                            {JSON.stringify(entry.changes).slice(0, 100)}...
                          </p>
                        )}
                        <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                          {new Date(entry.timestamp).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Conflict Warnings */}
        {conflicts.length > 0 && (
          <div className="rounded-xl border border-yellow-700/50 bg-yellow-900/20 p-4">
            <div className="mb-2 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
              <h3 className="font-medium text-yellow-300">Permission Warnings</h3>
            </div>
            <ul className="space-y-1 text-sm text-yellow-200/80">
              {conflicts.map((c, i) => (
                <li key={i}>
                  <span className="font-mono text-yellow-300">{String(c.permission)}</span>: {c.risk}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Permission Matrix */}
        <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="flex items-center justify-between border-b p-4" style={{ borderColor: 'var(--muted)' }}>
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Permission Matrix</h2>
              {isBuiltin ? (
                <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                  Built-in role permissions cannot be modified
                </p>
              ) : (
                <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
                  Toggle permissions to configure what this role can access
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={checkConflicts}
                className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
              >
                <AlertCircle className="h-4 w-4" />
                Check Conflicts
              </button>
              <div className="flex items-center rounded-lg border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('grid')}
                  className={cn(
                    'rounded-l-lg p-2 transition-colors',
                    viewMode === 'grid' ? 'bg-primary-600 text-white' : 'hover:opacity-80'
                  )}
                  style={viewMode !== 'grid' ? { color: 'var(--muted)' } : undefined}
                >
                  <Grid3X3 className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('list')}
                  className={cn(
                    'rounded-r-lg p-2 transition-colors',
                    viewMode === 'list' ? 'bg-primary-600 text-white' : 'hover:opacity-80'
                  )}
                  style={viewMode !== 'list' ? { color: 'var(--muted)' } : undefined}
                >
                  <List className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          {viewMode === 'grid' ? (
            // Grid View - Permission Matrix
            <div className="p-4">
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {Object.entries(categories).map(([category, perms]) => {
                  const grantedCount = perms.filter((p) => selectedPermissions.has(p.slug)).length
                  const allSelected = grantedCount === perms.length
                  const someSelected = grantedCount > 0 && grantedCount < perms.length

                  return (
                    <div key={category} className="rounded-lg border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
                      <div
                        className="flex cursor-pointer items-center justify-between p-3"
                        onClick={() => toggleCategory(category)}
                      >
                        <div className="flex items-center gap-2">
                          {!isBuiltin && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleAllInCategory(category)
                              }}
                              className={cn(
                                'flex h-5 w-5 items-center justify-center rounded border transition-colors',
                                allSelected
                                  ? 'border-primary-500 bg-primary-600 text-white'
                                  : someSelected
                                    ? 'border-primary-500 bg-primary-600/50 text-white'
                                    : ''
                              )}
                              style={!allSelected && !someSelected ? { borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' } : undefined}
                            >
                              {(allSelected || someSelected) && <Check className="h-3 w-3" />}
                            </button>
                          )}
                          <span className="font-medium capitalize" style={{ color: 'var(--fg)' }}>{category}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>
                            {grantedCount}/{perms.length}
                          </span>
                          {expandedCategories.has(category) ? (
                            <ChevronDown className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          ) : (
                            <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          )}
                        </div>
                      </div>
                      {expandedCategories.has(category) && (
                        <div className="space-y-1 border-t p-3" style={{ borderColor: 'var(--muted)' }}>
                          {perms.map((perm) => (
                            <div
                              key={perm.slug}
                              role={isBuiltin ? undefined : 'button'}
                              tabIndex={isBuiltin ? undefined : 0}
                              onClick={() => {
                                if (!isBuiltin) togglePermission(perm.slug)
                              }}
                              onKeyDown={(event) => {
                                if (!isBuiltin && (event.key === 'Enter' || event.key === ' ')) {
                                  event.preventDefault()
                                  togglePermission(perm.slug)
                                }
                              }}
                              className={cn(
                                'flex items-center gap-2 rounded p-1.5',
                                isBuiltin ? 'cursor-default' : 'cursor-pointer hover:opacity-80'
                              )}
                            >
                              <div onClick={(event) => event.stopPropagation()}>
                                <Checkbox
                                  checked={selectedPermissions.has(perm.slug)}
                                  onCheckedChange={() => togglePermission(perm.slug)}
                                  disabled={isBuiltin}
                                  aria-label={perm.slug}
                                />
                              </div>
                              <div className="min-w-0 flex-1">
                                <span className="block truncate font-mono text-xs" style={{ color: 'var(--fg)' }}>
                                  {perm.slug}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ) : (
            // List View
            <div className="divide-y" style={{ borderColor: 'var(--muted)' }}>
              {Object.entries(categories).map(([category, perms]) => {
                const grantedCount = perms.filter((p) => selectedPermissions.has(p.slug)).length

                return (
                  <div key={category} className="p-4" style={{ borderColor: 'var(--muted)' }}>
                    <div className="mb-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <h3 className="font-semibold capitalize" style={{ color: 'var(--fg)' }}>{category}</h3>
                        <span className="rounded px-2 py-0.5 text-xs" style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}>
                          {grantedCount} / {perms.length}
                        </span>
                      </div>
                      {!isBuiltin && (
                        <button
                          type="button"
                          onClick={() => toggleAllInCategory(category)}
                          className="text-xs text-primary-400 hover:text-primary-300"
                        >
                          {grantedCount === perms.length ? 'Deselect All' : 'Select All'}
                        </button>
                      )}
                    </div>
                    <div className="space-y-2">
                      {perms.map((perm) => (
                        <div
                          key={perm.slug}
                          role={isBuiltin ? undefined : 'button'}
                          tabIndex={isBuiltin ? undefined : 0}
                          onClick={() => {
                            if (!isBuiltin) togglePermission(perm.slug)
                          }}
                          onKeyDown={(event) => {
                            if (!isBuiltin && (event.key === 'Enter' || event.key === ' ')) {
                              event.preventDefault()
                              togglePermission(perm.slug)
                            }
                          }}
                          className={cn(
                            'flex items-start gap-3 rounded-lg p-2',
                            isBuiltin ? 'cursor-default' : 'cursor-pointer hover:opacity-80'
                          )}
                        >
                          <div className="mt-0.5" onClick={(event) => event.stopPropagation()}>
                            <Checkbox
                              checked={selectedPermissions.has(perm.slug)}
                              onCheckedChange={() => togglePermission(perm.slug)}
                              disabled={isBuiltin}
                              aria-label={perm.slug}
                            />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="font-mono text-sm" style={{ color: 'var(--fg)' }}>{perm.slug}</span>
                            <p className="mt-0.5 text-sm" style={{ color: 'var(--muted)' }}>{perm.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Permission Summary */}
        <div className="card-sentinel rounded-xl border p-4" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="mb-3 flex items-center gap-2">
            <Info className="h-4 w-4 text-blue-400" />
            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Permission Summary</h3>
          </div>
          <div className="flex flex-wrap gap-3">
            {permissionStats.byCategory.map(({ category, total, granted }) => (
              <div
                key={category}
                className={cn(
                  'rounded-lg border px-3 py-2',
                  granted === total
                    ? 'border-green-600/50 bg-green-900/20'
                    : granted > 0
                      ? 'border-yellow-600/50 bg-yellow-900/20'
                      : ''
                )}
                style={granted === 0 ? { borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' } : undefined}
              >
                <span className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{category}</span>
                <div className="font-medium" style={{ color: 'var(--fg)' }}>
                  {granted}/{total}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        {!isBuiltin && (
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={handleDelete}
              className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 font-medium text-white transition-colors hover:bg-red-700"
            >
              <Trash2 className="h-4 w-4" />
              Delete Role
            </button>
            <div className="flex items-center gap-3">
              {hasChanges && (
                <span className="text-sm text-yellow-400">You have unsaved changes</span>
              )}
              <button
                type="button"
                onClick={handleSave}
                disabled={isSaving || !hasChanges}
                className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSaving ? (
                  <>
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Save className="h-4 w-4" />
                    Save Changes
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
