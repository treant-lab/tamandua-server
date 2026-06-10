import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import type { Tenant } from '@/types'
import { logger } from '@/lib/logger'

interface TenantContextValue {
  // Current tenant
  currentTenant: Tenant | null
  // List of tenants the user has access to
  availableTenants: Tenant[]
  // Whether the user has access to multiple tenants
  isMultiTenant: boolean
  // Loading state
  isLoading: boolean
  // Error state
  error: string | null
  // Switch to a different tenant
  switchTenant: (tenantId: string) => Promise<void>
  // Refresh tenant data
  refreshTenants: () => Promise<void>
  // Set available tenants (used by Inertia props)
  setAvailableTenants: (tenants: Tenant[]) => void
  // Set current tenant (used by Inertia props)
  setCurrentTenant: (tenant: Tenant | null) => void
}

const TenantContext = createContext<TenantContextValue | undefined>(undefined)

const TENANT_STORAGE_KEY = 'tamandua_current_tenant_id'

interface TenantProviderProps {
  children: ReactNode
  initialTenant?: Tenant | null
  initialTenants?: Tenant[]
}

export function TenantProvider({
  children,
  initialTenant = null,
  initialTenants = []
}: TenantProviderProps) {
  const [currentTenant, setCurrentTenant] = useState<Tenant | null>(initialTenant)
  const [availableTenants, setAvailableTenants] = useState<Tenant[]>(initialTenants)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isMultiTenant = availableTenants.length > 1

  // Persist tenant selection to localStorage
  useEffect(() => {
    if (currentTenant) {
      localStorage.setItem(TENANT_STORAGE_KEY, currentTenant.id)
    }
  }, [currentTenant])

  // Restore tenant selection from localStorage on mount
  useEffect(() => {
    const storedTenantId = localStorage.getItem(TENANT_STORAGE_KEY)
    if (storedTenantId && availableTenants.length > 0 && !currentTenant) {
      const storedTenant = availableTenants.find(t => t.id === storedTenantId)
      if (storedTenant) {
        setCurrentTenant(storedTenant)
      } else if (availableTenants.length > 0) {
        // Fallback to first available tenant
        setCurrentTenant(availableTenants[0])
      }
    } else if (availableTenants.length > 0 && !currentTenant) {
      // Default to first tenant if none selected
      setCurrentTenant(availableTenants[0])
    }
  }, [availableTenants, currentTenant])

  const switchTenant = useCallback(async (tenantId: string) => {
    const tenant = availableTenants.find(t => t.id === tenantId)
    if (!tenant) {
      setError('Tenant not found')
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      // Tenant switch is a client-side state change only
      setCurrentTenant(tenant)
      localStorage.setItem(TENANT_STORAGE_KEY, tenant.id)

      // Reload the page to refresh data for new tenant context
      window.location.reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch tenant')
      logger.error('Tenant switch error:', err)
    } finally {
      setIsLoading(false)
    }
  }, [availableTenants])

  const refreshTenants = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/v1/organizations', {
        headers: {
          'Accept': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch tenants (status ${response.status})`)
      }

      const data = await response.json()
      setAvailableTenants(data.data || data.tenants || [])

      // Update current tenant if it's still in the list
      const tenantsList = data.data || data.tenants || []
      if (currentTenant) {
        const updatedTenant = tenantsList.find((t: Tenant) => t.id === currentTenant.id)
        if (updatedTenant) {
          setCurrentTenant(updatedTenant)
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh tenants')
      logger.error('Tenant refresh error:', err)
    } finally {
      setIsLoading(false)
    }
  }, [currentTenant])

  const value: TenantContextValue = {
    currentTenant,
    availableTenants,
    isMultiTenant,
    isLoading,
    error,
    switchTenant,
    refreshTenants,
    setAvailableTenants,
    setCurrentTenant,
  }

  return (
    <TenantContext.Provider value={value}>
      {children}
    </TenantContext.Provider>
  )
}

export function useTenant(): TenantContextValue {
  const context = useContext(TenantContext)
  if (context === undefined) {
    throw new Error('useTenant must be used within a TenantProvider')
  }
  return context
}

// Hook for getting tenant-scoped API headers
export function useTenantHeaders(): Record<string, string> {
  const { currentTenant } = useTenant()

  if (!currentTenant) {
    return {}
  }

  return {
    'X-Tenant-ID': currentTenant.id,
  }
}

// Utility function for making tenant-scoped API calls
export async function fetchWithTenant(
  url: string,
  tenantId: string | null,
  options: RequestInit = {}
): Promise<Response> {
  const headers = new Headers(options.headers)

  if (tenantId) {
    headers.set('X-Tenant-ID', tenantId)
  }

  return fetch(url, {
    ...options,
    headers,
  })
}
