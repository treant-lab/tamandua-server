import { useCallback } from 'react'
import { useTenant } from '@/contexts/TenantContext'

interface FetchOptions extends RequestInit {
  // Additional options can be added here
}

interface UseTenantFetchResult {
  /**
   * Make a tenant-scoped fetch request.
   * Automatically includes the X-Tenant-ID header.
   */
  tenantFetch: (url: string, options?: FetchOptions) => Promise<Response>
  /**
   * Make a tenant-scoped GET request and parse JSON response.
   */
  tenantGet: <T = unknown>(url: string) => Promise<T>
  /**
   * Make a tenant-scoped POST request with JSON body.
   */
  tenantPost: <T = unknown>(url: string, data: unknown) => Promise<T>
  /**
   * Make a tenant-scoped PATCH request with JSON body.
   */
  tenantPatch: <T = unknown>(url: string, data: unknown) => Promise<T>
  /**
   * Make a tenant-scoped DELETE request.
   */
  tenantDelete: <T = unknown>(url: string) => Promise<T>
  /**
   * Current tenant ID (for manual use if needed).
   */
  tenantId: string | null
}

/**
 * Hook for making tenant-scoped API requests.
 * All requests automatically include the X-Tenant-ID header.
 */
export function useTenantFetch(): UseTenantFetchResult {
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null

  const tenantFetch = useCallback(
    async (url: string, options: FetchOptions = {}): Promise<Response> => {
      const headers = new Headers(options.headers)

      // Add tenant ID header
      if (tenantId) {
        headers.set('X-Tenant-ID', tenantId)
      }

      // Add default Accept header if not set
      if (!headers.has('Accept')) {
        headers.set('Accept', 'application/json')
      }

      return fetch(url, {
        ...options,
        headers,
      })
    },
    [tenantId]
  )

  const tenantGet = useCallback(
    async <T = unknown>(url: string): Promise<T> => {
      const response = await tenantFetch(url, {
        method: 'GET',
      })

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Request failed' }))
        throw new Error(error.error || error.message || `Request failed: ${response.status}`)
      }

      return response.json()
    },
    [tenantFetch]
  )

  const tenantPost = useCallback(
    async <T = unknown>(url: string, data: unknown): Promise<T> => {
      const response = await tenantFetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      })

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Request failed' }))
        throw new Error(error.error || error.message || `Request failed: ${response.status}`)
      }

      return response.json()
    },
    [tenantFetch]
  )

  const tenantPatch = useCallback(
    async <T = unknown>(url: string, data: unknown): Promise<T> => {
      const response = await tenantFetch(url, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      })

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Request failed' }))
        throw new Error(error.error || error.message || `Request failed: ${response.status}`)
      }

      return response.json()
    },
    [tenantFetch]
  )

  const tenantDelete = useCallback(
    async <T = unknown>(url: string): Promise<T> => {
      const response = await tenantFetch(url, {
        method: 'DELETE',
      })

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Request failed' }))
        throw new Error(error.error || error.message || `Request failed: ${response.status}`)
      }

      return response.json()
    },
    [tenantFetch]
  )

  return {
    tenantFetch,
    tenantGet,
    tenantPost,
    tenantPatch,
    tenantDelete,
    tenantId,
  }
}
