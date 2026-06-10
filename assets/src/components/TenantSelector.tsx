import { useState, useRef, useEffect } from 'react'
import { useTenant } from '@/contexts/TenantContext'
import {
  Building2,
  ChevronDown,
  Check,
  Search,
  Loader2,
  AlertCircle,
  Crown,
  Briefcase,
  Rocket,
  Sparkles,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Tenant, TenantPlan } from '@/types'

interface TenantSelectorProps {
  className?: string
  compact?: boolean
}

const planIcons: Record<TenantPlan, React.ComponentType<{ className?: string }>> = {
  trial: Sparkles,
  starter: Rocket,
  professional: Briefcase,
  enterprise: Crown,
}

const planColors: Record<TenantPlan, string> = {
  trial: 'text-purple-400',
  starter: 'text-blue-400',
  professional: 'text-emerald-400',
  enterprise: 'text-amber-400',
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

  // Generate initials from tenant name
  const initials = tenant.name
    .split(' ')
    .map(word => word[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  // Use tenant primary color or default
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

export function TenantSelector({ className, compact = false }: TenantSelectorProps) {
  const {
    currentTenant,
    availableTenants,
    isMultiTenant,
    isLoading,
    error,
    switchTenant,
  } = useTenant()

  const [isOpen, setIsOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const dropdownRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Focus search input when dropdown opens
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus()
    }
  }, [isOpen])

  // Don't render if user only has access to one tenant
  if (!isMultiTenant || availableTenants.length === 0) {
    return null
  }

  const filteredTenants = searchQuery
    ? availableTenants.filter(tenant =>
        tenant.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tenant.slug.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : availableTenants

  const handleTenantSelect = async (tenant: Tenant) => {
    if (tenant.id === currentTenant?.id) {
      setIsOpen(false)
      return
    }

    await switchTenant(tenant.id)
    setIsOpen(false)
    setSearchQuery('')
  }

  const PlanIcon = currentTenant ? planIcons[currentTenant.plan] : Building2

  return (
    <div ref={dropdownRef} className={cn('relative', className)}>
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        disabled={isLoading}
        className={cn(
          'flex items-center gap-3 rounded-lg transition-colors',
          'border border-slate-600 bg-slate-700/50 hover:bg-slate-700',
          compact ? 'px-2 py-1.5' : 'px-3 py-2',
          isLoading && 'opacity-50 cursor-not-allowed'
        )}
      >
        {isLoading ? (
          <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
        ) : currentTenant ? (
          <>
            <TenantLogo tenant={currentTenant} className={compact ? 'h-6 w-6 text-xs' : 'h-8 w-8 text-sm'} />
            {!compact && (
              <div className="flex-1 min-w-0 text-left">
                <div className="text-sm font-medium text-white truncate max-w-[120px]">
                  {currentTenant.name}
                </div>
                <div className="flex items-center gap-1">
                  <PlanIcon className={cn('h-3 w-3', planColors[currentTenant.plan])} />
                  <span className={cn('text-xs capitalize', planColors[currentTenant.plan])}>
                    {currentTenant.plan}
                  </span>
                </div>
              </div>
            )}
            <ChevronDown className={cn(
              'h-4 w-4 text-slate-400 transition-transform',
              isOpen && 'rotate-180'
            )} />
          </>
        ) : (
          <>
            <Building2 className="h-5 w-5 text-slate-400" />
            {!compact && <span className="text-sm text-slate-400">Select tenant</span>}
            <ChevronDown className="h-4 w-4 text-slate-400" />
          </>
        )}
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-72 bg-slate-800 border border-slate-600 rounded-lg shadow-xl z-50 overflow-hidden">
          {/* Search */}
          <div className="p-2 border-b border-slate-700">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search tenants..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Error message */}
          {error && (
            <div className="p-3 bg-red-900/30 border-b border-red-700 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
              <span className="text-sm text-red-300">{error}</span>
            </div>
          )}

          {/* Tenant list */}
          <div className="max-h-64 overflow-y-auto">
            {filteredTenants.length === 0 ? (
              <div className="p-4 text-center text-sm text-slate-400">
                {searchQuery ? 'No tenants match your search' : 'No tenants available'}
              </div>
            ) : (
              <div className="py-1">
                {filteredTenants.map((tenant) => {
                  const isSelected = tenant.id === currentTenant?.id
                  const TenantPlanIcon = planIcons[tenant.plan]

                  return (
                    <button
                      key={tenant.id}
                      onClick={() => handleTenantSelect(tenant)}
                      disabled={isLoading}
                      className={cn(
                        'flex items-center gap-3 w-full px-3 py-2 text-left transition-colors',
                        isSelected
                          ? 'bg-primary-600/20 text-white'
                          : 'text-slate-300 hover:bg-slate-700 hover:text-white',
                        tenant.status !== 'active' && 'opacity-60'
                      )}
                    >
                      <TenantLogo tenant={tenant} className="h-8 w-8 text-sm flex-shrink-0" />

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">{tenant.name}</span>
                          {tenant.status !== 'active' && (
                            <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-900/50 text-yellow-400 capitalize">
                              {tenant.status}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <TenantPlanIcon className={cn('h-3 w-3', planColors[tenant.plan])} />
                          <span className={cn('text-xs capitalize', planColors[tenant.plan])}>
                            {tenant.plan}
                          </span>
                          {tenant.agent_count !== undefined && (
                            <>
                              <span className="text-slate-600">|</span>
                              <span className="text-xs text-slate-500">
                                {tenant.agent_count} agent{tenant.agent_count !== 1 ? 's' : ''}
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      {isSelected && (
                        <Check className="h-4 w-4 text-primary-400 flex-shrink-0" />
                      )}
                    </button>
                  )
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-2 border-t border-slate-700 bg-slate-800/50">
            <div className="text-xs text-slate-500 text-center">
              {availableTenants.length} tenant{availableTenants.length !== 1 ? 's' : ''} available
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Compact version for mobile or tight spaces
export function TenantSelectorCompact({ className }: { className?: string }) {
  return <TenantSelector className={className} compact />
}
