import { Head, Link } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { Shield, Plus, Usb, Bluetooth, Wifi, HardDrive, ArrowLeft, FileX, Loader2, Pencil, Trash2, X, Check, Printer, Camera, Mic } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useEffect, useCallback, Fragment } from 'react'
import { logger } from '@/lib/logger'
import { toast } from 'sonner'
import { Dialog } from '@/components/ui/baseui'

interface DeviceControlPoliciesProps {
  page_title: string
}

interface DevicePolicy {
  group: string
  allowed_classes: string[]
  blocked_classes: string[]
  allowed_devices: string[]
  blocked_devices: string[]
  write_protection: string
  require_encryption: boolean
  max_storage_size_gb: number
  allow_network_adapters: boolean
  allow_wireless: boolean
  audit_all: boolean
  updated_at?: string
}

interface CategoryStats {
  name: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  bgColor: string
  count: number
  deviceClasses: string[]
}

interface PolicyFormData {
  group: string
  allowed_classes: string[]
  blocked_classes: string[]
  write_protection: string
  require_encryption: boolean
  max_storage_size_gb: number
  audit_all: boolean
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

const deviceClasses = [
  { id: 'mass_storage', name: 'Mass Storage', description: 'USB drives, external HDDs' },
  { id: 'hid', name: 'HID', description: 'Keyboards, mice' },
  { id: 'hub', name: 'Hub', description: 'USB hubs' },
  { id: 'audio', name: 'Audio', description: 'Audio devices, microphones' },
  { id: 'video', name: 'Video', description: 'Cameras, webcams' },
  { id: 'network_adapter', name: 'Network Adapter', description: 'Ethernet adapters' },
  { id: 'wireless_controller', name: 'Wireless', description: 'Wi-Fi, Bluetooth adapters' },
  { id: 'printer', name: 'Printer', description: 'Printers, scanners' },
  { id: 'smart_card', name: 'Smart Card', description: 'Smart card readers' },
  { id: 'communications', name: 'Communications', description: 'Modems, serial ports' },
]

const writeProtectionModes = [
  { id: 'none', name: 'None', description: 'No write protection' },
  { id: 'audit_only', name: 'Audit Only', description: 'Log writes but allow them' },
  { id: 'read_only', name: 'Read Only', description: 'Block all write operations' },
  { id: 'block_executables', name: 'Block Executables', description: 'Allow data but block executable files' },
]

export default function DeviceControlPolicies({ page_title }: DeviceControlPoliciesProps) {
  const [policies, setPolicies] = useState<DevicePolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<DevicePolicy | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Form state
  const [formData, setFormData] = useState<PolicyFormData>({
    group: '',
    allowed_classes: [],
    blocked_classes: [],
    write_protection: 'none',
    require_encryption: false,
    max_storage_size_gb: 0,
    audit_all: true,
  })

  const fetchPolicies = useCallback(async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/v1/device-control/policies', {
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
      })
      if (!res.ok) {
        throw new Error(`Failed to fetch policies: ${res.status}`)
      }
      const data = await res.json()
      setPolicies(data.policies || [])
      setError(null)
    } catch (err) {
      logger.error('Error fetching policies:', err)
      setError(err instanceof Error ? err.message : 'Failed to load policies')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchPolicies()
  }, [fetchPolicies])

  const policyCategories: CategoryStats[] = [
    {
      name: 'USB Storage',
      icon: Usb,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/20',
      deviceClasses: ['mass_storage'],
      count: policies.filter(p =>
        p.allowed_classes.includes('mass_storage') || p.blocked_classes.includes('mass_storage')
      ).length,
    },
    {
      name: 'Bluetooth',
      icon: Bluetooth,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/20',
      deviceClasses: ['wireless_controller'],
      count: policies.filter(p =>
        p.allowed_classes.includes('wireless_controller') || p.blocked_classes.includes('wireless_controller')
      ).length,
    },
    {
      name: 'Wireless',
      icon: Wifi,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/20',
      deviceClasses: ['network_adapter', 'wireless_controller'],
      count: policies.filter(p =>
        p.allowed_classes.includes('network_adapter') || p.blocked_classes.includes('network_adapter')
      ).length,
    },
    {
      name: 'External Drives',
      icon: HardDrive,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/20',
      deviceClasses: ['mass_storage'],
      count: policies.filter(p => p.write_protection !== 'none').length,
    },
  ]

  const openCreateModal = () => {
    setEditingPolicy(null)
    setFormData({
      group: '',
      allowed_classes: [],
      blocked_classes: [],
      write_protection: 'none',
      require_encryption: false,
      max_storage_size_gb: 0,
      audit_all: true,
    })
    setShowModal(true)
  }

  const openEditModal = (policy: DevicePolicy) => {
    setEditingPolicy(policy)
    setFormData({
      group: policy.group,
      allowed_classes: policy.allowed_classes || [],
      blocked_classes: policy.blocked_classes || [],
      write_protection: policy.write_protection || 'none',
      require_encryption: policy.require_encryption || false,
      max_storage_size_gb: policy.max_storage_size_gb || 0,
      audit_all: policy.audit_all !== false,
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingPolicy(null)
  }

  const handleSave = async () => {
    if (!formData.group.trim()) {
      toast.error('Policy group name is required')
      return
    }

    setSaving(true)
    try {
      const url = `/api/v1/device-control/policies/${encodeURIComponent(formData.group)}`
      const res = await fetch(url, {
        method: 'PUT',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          group: formData.group,
          allowed_classes: formData.allowed_classes,
          blocked_classes: formData.blocked_classes,
          write_protection: formData.write_protection,
          require_encryption: formData.require_encryption,
          max_storage_size_gb: formData.max_storage_size_gb,
          audit_all: formData.audit_all,
        }),
      })

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}))
        throw new Error(errorData.error || `Failed to save policy: ${res.status}`)
      }

      await fetchPolicies()
      closeModal()
      toast.success(`Policy "${formData.group}" saved`)
    } catch (err) {
      logger.error('Error saving policy:', err)
      toast.error('Failed to save policy: ' + (err instanceof Error ? err.message : 'Unknown error'))
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (group: string) => {
    if (!confirm(`Are you sure you want to delete the "${group}" policy?`)) {
      return
    }

    setDeleting(group)
    try {
      const res = await fetch(`/api/v1/device-control/policies/${encodeURIComponent(group)}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
      })

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}))
        throw new Error(errorData.error || `Failed to delete policy: ${res.status}`)
      }

      await fetchPolicies()
      toast.success(`Policy "${group}" deleted`)
    } catch (err) {
      logger.error('Error deleting policy:', err)
      toast.error('Failed to delete policy: ' + (err instanceof Error ? err.message : 'Unknown error'))
    } finally {
      setDeleting(null)
    }
  }

  const toggleDeviceClass = (classId: string, type: 'allowed' | 'blocked') => {
    setFormData(prev => {
      const otherType = type === 'allowed' ? 'blocked_classes' : 'allowed_classes'
      const currentType = type === 'allowed' ? 'allowed_classes' : 'blocked_classes'

      // Remove from the other list if present
      const otherList = prev[otherType].filter(c => c !== classId)

      // Toggle in current list
      const currentList = prev[currentType].includes(classId)
        ? prev[currentType].filter(c => c !== classId)
        : [...prev[currentType], classId]

      return {
        ...prev,
        [currentType]: currentList,
        [otherType]: otherList,
      }
    })
  }

  const isDefaultPolicy = (group: string) => {
    return ['it_admin', 'developer', 'standard', 'kiosk', 'executive'].includes(group)
  }

  return (
    <MainLayout title={page_title || 'Device Control Policies'}>
      <Head title="Device Control Policies - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              href="/app/device-control"
              className="p-2 rounded-lg hover:bg-[var(--surface-hover)] transition-colors text-[var(--muted)] hover:text-[var(--fg)]"
            >
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-[var(--fg)]">Device Control Policies</h1>
              <p className="text-sm text-[var(--muted)] mt-1">Create and manage device access control rules</p>
            </div>
          </div>
          <button
            type="button"
            onClick={openCreateModal}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Plus className="h-4 w-4" />
            Create Policy
          </button>
        </div>

        {/* Policy Categories */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {policyCategories.map((category) => (
            <div
              key={category.name}
              className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-4"
            >
              <div className="flex items-center gap-3">
                <div className={cn('p-2 rounded-lg', category.bgColor)}>
                  <category.icon className={cn('h-5 w-5', category.color)} />
                </div>
                <div>
                  <p className="text-sm font-medium text-[var(--fg)]">{category.name}</p>
                  <p className="text-xs text-[var(--muted)]">{category.count} policies</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 text-primary-400 animate-spin" />
            <span className="ml-3 text-[var(--muted)]">Loading policies...</span>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
            <p className="text-red-400">{error}</p>
            <button
              onClick={fetchPolicies}
              className="mt-2 text-sm text-red-300 hover:text-red-200 underline"
            >
              Retry
            </button>
          </div>
        )}

        {/* Policies Table */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)]">
          <div className="p-4 border-b border-[var(--surface-border)] flex items-center justify-between">
            <h2 className="text-lg font-semibold text-[var(--fg)]">All Policies ({policies.length})</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--surface-border)]">
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Name</th>
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Allowed Classes</th>
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Blocked Classes</th>
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Write Protection</th>
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Encryption</th>
                  <th className="text-left p-4 text-sm font-medium text-[var(--muted)]">Actions</th>
                </tr>
              </thead>
              <tbody>
                {!loading && policies.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-12 text-center text-[var(--muted)]">
                      <FileX className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p className="text-lg">No policies configured</p>
                      <p className="text-sm mt-1">
                        Create your first device control policy to manage peripheral access
                      </p>
                      <button
                        type="button"
                        onClick={openCreateModal}
                        className="mt-4 inline-flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
                      >
                        <Plus className="h-4 w-4" />
                        Create Policy
                      </button>
                    </td>
                  </tr>
                )}
                {policies.map((policy) => (
                  <tr key={policy.group} className="border-b border-[var(--surface-border)]/50 hover:bg-[var(--surface-hover)]/20">
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-[var(--muted)]" />
                        <span className="text-[var(--fg)] font-medium">{policy.group}</span>
                        {isDefaultPolicy(policy.group) && (
                          <span className="text-xs bg-[var(--surface-hover)] text-[var(--muted)] px-2 py-0.5 rounded">
                            Default
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex flex-wrap gap-1">
                        {policy.allowed_classes.length > 0 ? (
                          policy.allowed_classes.slice(0, 3).map(cls => (
                            <span key={cls} className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">
                              {cls}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-[var(--muted)]">None</span>
                        )}
                        {policy.allowed_classes.length > 3 && (
                          <span className="text-xs text-[var(--muted)]">
                            +{policy.allowed_classes.length - 3} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex flex-wrap gap-1">
                        {policy.blocked_classes.length > 0 ? (
                          policy.blocked_classes.slice(0, 3).map(cls => (
                            <span key={cls} className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">
                              {cls}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-[var(--muted)]">None</span>
                        )}
                        {policy.blocked_classes.length > 3 && (
                          <span className="text-xs text-[var(--muted)]">
                            +{policy.blocked_classes.length - 3} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        policy.write_protection === 'none' ? 'bg-[var(--surface-hover)] text-[var(--muted)]' :
                        policy.write_protection === 'read_only' ? 'bg-red-500/20 text-red-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      )}>
                        {policy.write_protection}
                      </span>
                    </td>
                    <td className="p-4">
                      {policy.require_encryption ? (
                        <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                          Required
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--muted)]">Not required</span>
                      )}
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEditModal(policy)}
                          className="p-1.5 rounded hover:bg-[var(--surface-hover)] text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
                          title="Edit policy"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        {!isDefaultPolicy(policy.group) && (
                          <button
                            onClick={() => handleDelete(policy.group)}
                            disabled={deleting === policy.group}
                            className="p-1.5 rounded hover:bg-red-500/20 text-[var(--muted)] hover:text-red-400 transition-colors disabled:opacity-50"
                            title="Delete policy"
                          >
                            {deleting === policy.group ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Trash2 className="h-4 w-4" />
                            )}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Create/Edit Modal */}
      <Dialog
        open={showModal}
        onOpenChange={(open) => { if (!open) closeModal() }}
        title={editingPolicy ? 'Edit Policy' : 'Create Policy'}
        maxWidth="42rem"
      >
        <div className="space-y-6">
              {/* Policy Name */}
              <div>
                <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">
                  Policy Name (Group)
                </label>
                <input
                  type="text"
                  value={formData.group}
                  onChange={(e) => setFormData(prev => ({ ...prev, group: e.target.value }))}
                  disabled={!!editingPolicy}
                  placeholder="e.g., finance_team, developers"
                  className="w-full px-4 py-2 bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:opacity-50"
                />
                {editingPolicy && (
                  <p className="text-xs text-[var(--muted)] mt-1">Policy name cannot be changed after creation</p>
                )}
              </div>

              {/* Device Classes */}
              <div>
                <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">
                  Device Classes
                </label>
                <p className="text-xs text-[var(--muted)] mb-3">
                  Click to allow (green) or block (red) each device class. Click again to remove.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {deviceClasses.map(cls => {
                    const isAllowed = formData.allowed_classes.includes(cls.id)
                    const isBlocked = formData.blocked_classes.includes(cls.id)

                    return (
                      <div
                        key={cls.id}
                        className="flex items-center gap-2 p-2 bg-[var(--surface-hover)]/50 rounded-lg"
                      >
                        <button
                          type="button"
                          onClick={() => toggleDeviceClass(cls.id, 'allowed')}
                          className={cn(
                            'p-1.5 rounded transition-colors',
                            isAllowed ? 'bg-green-500/30 text-green-400' : 'bg-[var(--surface-active)] text-[var(--muted)] hover:bg-[var(--surface-hover)]'
                          )}
                          title="Allow"
                        >
                          <Check className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          onClick={() => toggleDeviceClass(cls.id, 'blocked')}
                          className={cn(
                            'p-1.5 rounded transition-colors',
                            isBlocked ? 'bg-red-500/30 text-red-400' : 'bg-[var(--surface-active)] text-[var(--muted)] hover:bg-[var(--surface-hover)]'
                          )}
                          title="Block"
                        >
                          <X className="h-4 w-4" />
                        </button>
                        <div className="flex-1">
                          <p className="text-sm text-[var(--fg)]">{cls.name}</p>
                          <p className="text-xs text-[var(--muted)]">{cls.description}</p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Write Protection */}
              <div>
                <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">
                  Write Protection
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {writeProtectionModes.map(mode => (
                    <button
                      key={mode.id}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, write_protection: mode.id }))}
                      className={cn(
                        'p-3 rounded-lg border text-left transition-colors',
                        formData.write_protection === mode.id
                          ? 'border-primary-500 bg-primary-500/10'
                          : 'border-[var(--surface-border)] bg-[var(--surface-hover)]/50 hover:border-[var(--muted)]'
                      )}
                    >
                      <p className="text-sm font-medium text-[var(--fg)]">{mode.name}</p>
                      <p className="text-xs text-[var(--muted)]">{mode.description}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Additional Options */}
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-[var(--surface-hover)]/50 rounded-lg">
                  <div>
                    <p className="text-sm font-medium text-[var(--fg)]">Require Encryption</p>
                    <p className="text-xs text-[var(--muted)]">Only allow encrypted storage devices</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, require_encryption: !prev.require_encryption }))}
                    className={cn(
                      'relative w-12 h-6 rounded-full transition-colors',
                      formData.require_encryption ? 'bg-primary-500' : 'bg-[var(--surface-active)]'
                    )}
                  >
                    <span
                      className={cn(
                        'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform',
                        formData.require_encryption ? 'left-7' : 'left-1'
                      )}
                    />
                  </button>
                </div>

                <div className="flex items-center justify-between p-3 bg-[var(--surface-hover)]/50 rounded-lg">
                  <div>
                    <p className="text-sm font-medium text-[var(--fg)]">Audit All Events</p>
                    <p className="text-xs text-[var(--muted)]">Log all device connection events</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, audit_all: !prev.audit_all }))}
                    className={cn(
                      'relative w-12 h-6 rounded-full transition-colors',
                      formData.audit_all ? 'bg-primary-500' : 'bg-[var(--surface-active)]'
                    )}
                  >
                    <span
                      className={cn(
                        'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform',
                        formData.audit_all ? 'left-7' : 'left-1'
                      )}
                    />
                  </button>
                </div>

                <div className="p-3 bg-[var(--surface-hover)]/50 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <p className="text-sm font-medium text-[var(--fg)]">Max Storage Size (GB)</p>
                      <p className="text-xs text-[var(--muted)]">0 = no limit</p>
                    </div>
                  </div>
                  <input
                    type="number"
                    min="0"
                    value={formData.max_storage_size_gb}
                    onChange={(e) => setFormData(prev => ({ ...prev, max_storage_size_gb: parseInt(e.target.value) || 0 }))}
                    className="w-full px-4 py-2 bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg text-[var(--fg)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                </div>
              </div>
        </div>

        <div className="flex items-center justify-end gap-3 mt-6 pt-4 border-t border-[var(--surface-border)]">
          <button
            type="button"
            onClick={closeModal}
            className="px-4 py-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || !formData.group.trim()}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {editingPolicy ? 'Save Changes' : 'Create Policy'}
          </button>
        </div>
      </Dialog>
    </MainLayout>
  )
}
