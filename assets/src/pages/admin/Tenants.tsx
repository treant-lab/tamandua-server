import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Building2,
  Plus,
  Search,
  Filter,
  MoreVertical,
  Users,
  Monitor,
  Activity,
  Crown,
  Briefcase,
  Rocket,
  Sparkles,
  CheckCircle,
  XCircle,
  Clock,
  AlertCircle,
  ChevronDown,
  ExternalLink,
  Settings,
  Trash2,
  Eye,
  Ban,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useRef, useEffect } from 'react'
import type { TenantsPageProps, Tenant, TenantPlan, TenantStatus } from '@/types'

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

const statusIcons: Record<TenantStatus, React.ComponentType<{ className?: string }>> = {
  active: CheckCircle,
  suspended: Ban,
  pending: Clock,
  deactivated: XCircle,
}

const statusColors: Record<TenantStatus, string> = {
  active: 'text-green-400 bg-green-400/10',
  suspended: 'text-red-400 bg-red-400/10',
  pending: 'text-yellow-400 bg-yellow-400/10',
  deactivated: 'text-slate-400 bg-slate-400/10',
}

function TenantLogo({ tenant, className }: { tenant: Tenant; className?: string }) {
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
      className={cn('rounded-lg flex items-center justify-center font-semibold text-white', className)}
      style={{ backgroundColor: bgColor }}
    >
      {initials}
    </div>
  )
}

function TenantRowMenu({ tenant }: { tenant: Tenant }) {
  const [isOpen, setIsOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleAction = (action: string) => {
    setIsOpen(false)
    switch (action) {
      case 'view':
        router.visit(`/app/admin/tenants/${tenant.id}`)
        break
      case 'settings':
        router.visit(`/app/admin/tenants/${tenant.id}/settings`)
        break
      case 'suspend':
        if (confirm(`Are you sure you want to suspend tenant "${tenant.name}"?`)) {
          router.post(`/api/v1/admin/tenants/${tenant.id}/suspend`)
        }
        break
      case 'activate':
        router.post(`/api/v1/admin/tenants/${tenant.id}/activate`)
        break
      case 'delete':
        if (confirm(`Are you sure you want to delete tenant "${tenant.name}"? This action cannot be undone.`)) {
          router.delete(`/api/v1/admin/tenants/${tenant.id}`)
        }
        break
    }
  }

  return (
    <div ref={menuRef} className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="p-1 rounded hover:bg-slate-600 text-slate-400 hover:text-white"
      >
        <MoreVertical className="h-4 w-4" />
      </button>

      {isOpen && (
        <div className="absolute right-0 top-full mt-1 w-48 bg-slate-700 border border-slate-600 rounded-lg shadow-xl z-10 py-1">
          <button
            onClick={() => handleAction('view')}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-300 hover:bg-slate-600 hover:text-white"
          >
            <Eye className="h-4 w-4" />
            View Details
          </button>
          <button
            onClick={() => handleAction('settings')}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-300 hover:bg-slate-600 hover:text-white"
          >
            <Settings className="h-4 w-4" />
            Settings
          </button>
          <div className="border-t border-slate-600 my-1" />
          {tenant.status === 'active' ? (
            <button
              onClick={() => handleAction('suspend')}
              className="flex items-center gap-2 w-full px-3 py-2 text-sm text-yellow-400 hover:bg-slate-600"
            >
              <Ban className="h-4 w-4" />
              Suspend Tenant
            </button>
          ) : tenant.status === 'suspended' ? (
            <button
              onClick={() => handleAction('activate')}
              className="flex items-center gap-2 w-full px-3 py-2 text-sm text-green-400 hover:bg-slate-600"
            >
              <CheckCircle className="h-4 w-4" />
              Activate Tenant
            </button>
          ) : null}
          <button
            onClick={() => handleAction('delete')}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-400 hover:bg-slate-600"
          >
            <Trash2 className="h-4 w-4" />
            Delete Tenant
          </button>
        </div>
      )}
    </div>
  )
}

export default function Tenants({ tenants, stats, filters }: TenantsPageProps) {
  const [searchQuery, setSearchQuery] = useState(filters?.search || '')
  const [selectedPlan, setSelectedPlan] = useState<TenantPlan | ''>(filters?.plan || '')
  const [selectedStatus, setSelectedStatus] = useState<TenantStatus | ''>(filters?.status || '')
  const [showFilters, setShowFilters] = useState(false)

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    applyFilters()
  }

  const applyFilters = () => {
    const params = new URLSearchParams()
    if (searchQuery) params.set('search', searchQuery)
    if (selectedPlan) params.set('plan', selectedPlan)
    if (selectedStatus) params.set('status', selectedStatus)
    router.visit(`/app/admin/tenants?${params.toString()}`)
  }

  const clearFilters = () => {
    setSearchQuery('')
    setSelectedPlan('')
    setSelectedStatus('')
    router.visit('/app/admin/tenants')
  }

  const hasFilters = searchQuery || selectedPlan || selectedStatus

  return (
    <MainLayout title="Tenant Management">
      <Head title="Tenants - Admin - Tamandua EDR" />

      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary-600/20 rounded-lg">
              <Building2 className="h-5 w-5 text-primary-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_tenants || 0}</div>
              <div className="text-sm text-slate-400">Total Tenants</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-600/20 rounded-lg">
              <CheckCircle className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.active_tenants || 0}</div>
              <div className="text-sm text-slate-400">Active</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-600/20 rounded-lg">
              <Sparkles className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.trial_tenants || 0}</div>
              <div className="text-sm text-slate-400">Trials</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600/20 rounded-lg">
              <Monitor className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_agents || 0}</div>
              <div className="text-sm text-slate-400">Total Agents</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-600/20 rounded-lg">
              <Users className="h-5 w-5 text-amber-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_users || 0}</div>
              <div className="text-sm text-slate-400">Total Users</div>
            </div>
          </div>
        </div>
      </div>

      {/* Header with Search and Actions */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 mb-6">
        <div className="p-4 flex items-center justify-between border-b border-slate-700">
          <div className="flex items-center gap-4 flex-1">
            <form onSubmit={handleSearch} className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search tenants..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </form>

            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                'flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors',
                hasFilters
                  ? 'border-primary-500 bg-primary-500/10 text-primary-400'
                  : 'border-slate-600 bg-slate-700 text-slate-300 hover:bg-slate-600'
              )}
            >
              <Filter className="h-4 w-4" />
              Filters
              {hasFilters && (
                <span className="bg-primary-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {[searchQuery, selectedPlan, selectedStatus].filter(Boolean).length}
                </span>
              )}
            </button>
          </div>

          <Link
            href="/app/admin/tenants/new"
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium"
          >
            <Plus className="h-4 w-4" />
            New Tenant
          </Link>
        </div>

        {/* Filters Panel */}
        {showFilters && (
          <div className="p-4 border-b border-slate-700 bg-slate-800/50">
            <div className="flex items-center gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Plan</label>
                <select
                  value={selectedPlan}
                  onChange={(e) => setSelectedPlan(e.target.value as TenantPlan | '')}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white focus:ring-2 focus:ring-primary-500"
                >
                  <option value="">All Plans</option>
                  <option value="trial">Trial</option>
                  <option value="starter">Starter</option>
                  <option value="professional">Professional</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Status</label>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value as TenantStatus | '')}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white focus:ring-2 focus:ring-primary-500"
                >
                  <option value="">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                  <option value="pending">Pending</option>
                  <option value="deactivated">Deactivated</option>
                </select>
              </div>

              <div className="flex items-end gap-2">
                <button
                  onClick={applyFilters}
                  className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium"
                >
                  Apply
                </button>
                {hasFilters && (
                  <button
                    onClick={clearFilters}
                    className="text-slate-400 hover:text-white px-3 py-1.5 text-sm"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tenant Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Tenant
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Plan
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Status
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Agents
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Users
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Events (30d)
                </th>
                <th className="text-left text-xs font-medium text-slate-400 uppercase tracking-wider px-4 py-3">
                  Created
                </th>
                <th className="w-12"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {tenants && tenants.length > 0 ? (
                tenants.map((tenant) => {
                  const PlanIcon = planIcons[tenant.plan]
                  const StatusIcon = statusIcons[tenant.status]

                  return (
                    <tr key={tenant.id} className="hover:bg-slate-700/50">
                      <td className="px-4 py-3">
                        <Link
                          href={`/app/admin/tenants/${tenant.id}`}
                          className="flex items-center gap-3 group"
                        >
                          <TenantLogo tenant={tenant} className="h-10 w-10 text-sm" />
                          <div>
                            <div className="text-sm font-medium text-white group-hover:text-primary-400 transition-colors">
                              {tenant.name}
                            </div>
                            <div className="text-xs text-slate-500">{tenant.slug}</div>
                          </div>
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium capitalize',
                          planColors[tenant.plan]
                        )}>
                          <PlanIcon className="h-3 w-3" />
                          {tenant.plan}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium capitalize',
                          statusColors[tenant.status]
                        )}>
                          <StatusIcon className="h-3 w-3" />
                          {tenant.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-sm text-slate-300">
                          <Monitor className="h-4 w-4 text-slate-500" />
                          {tenant.agent_count ?? 0}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-sm text-slate-300">
                          <Users className="h-4 w-4 text-slate-500" />
                          {tenant.user_count ?? 0}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-sm text-slate-300">
                          <Activity className="h-4 w-4 text-slate-500" />
                          {(tenant.event_count_30d ?? 0).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-400">
                        {new Date(tenant.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <TenantRowMenu tenant={tenant} />
                      </td>
                    </tr>
                  )
                })
              ) : (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center">
                    <Building2 className="h-12 w-12 text-slate-600 mx-auto mb-3" />
                    <div className="text-slate-400 mb-2">No tenants found</div>
                    <Link
                      href="/app/admin/tenants/new"
                      className="text-primary-400 hover:text-primary-300 text-sm"
                    >
                      Create your first tenant
                    </Link>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </MainLayout>
  )
}
