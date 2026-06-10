import { createInertiaApp } from '@inertiajs/react'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import axios from 'axios'
import { TenantProvider } from '@/contexts/TenantContext'
import { generateFallbackUUID } from '@/lib/utils'
import type { Tenant } from '@/types'
import './xterm.css'
import './index.css'

// Configure axios for CSRF with Phoenix
axios.defaults.xsrfCookieName = 'XSRF-TOKEN'
axios.defaults.xsrfHeaderName = 'x-csrf-token'

const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
if (token) {
  axios.defaults.headers.common['x-csrf-token'] = token
}

if (globalThis.crypto && !globalThis.crypto.randomUUID) {
  globalThis.crypto.randomUUID = () => generateFallbackUUID(globalThis.crypto)
}

// Add tenant ID to all axios requests if available
axios.interceptors.request.use((config) => {
  const tenantId = localStorage.getItem('tamandua_current_tenant_id')
  if (tenantId) {
    config.headers['X-Tenant-ID'] = tenantId
  }
  return config
})

// Handle 403 errors for cross-tenant access attempts
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 403 && error.response?.data?.error === 'cross_tenant_access') {
      // Clear cached tenant and redirect to dashboard
      localStorage.removeItem('tamandua_current_tenant_id')
      window.location.href = '/app/dashboard'
    }
    return Promise.reject(error)
  }
)

interface PageProps {
  current_tenant?: Tenant | null
  available_tenants?: Tenant[]
  [key: string]: unknown
}

createInertiaApp({
  resolve: (name) => {
    const pages = import.meta.glob('./pages/**/*.tsx', { eager: true })
    const page = pages[`./pages/${name}.tsx`]
    if (!page) {
      throw new Error(`Page not found: ${name}`)
    }
    return page
  },
  setup({ el, App, props }) {
    // Extract tenant info from initial page props
    const pageProps = props.initialPage.props as PageProps
    const initialTenant = pageProps.current_tenant || null
    const initialTenants = pageProps.available_tenants || []

    createRoot(el).render(
      <TenantProvider
        initialTenant={initialTenant}
        initialTenants={initialTenants}
      >
        <Toaster
          richColors
          position="top-right"
          theme="dark"
        />
        <App {...props} />
      </TenantProvider>
    )
  },
})
