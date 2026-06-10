import { Head, Link } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { Usb, Bluetooth, HardDrive, Wifi, Shield, ChevronRight, Info, Printer, Camera, Mic, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useEffect, useCallback } from 'react'
import { logger } from '@/lib/logger'

interface DeviceControlProps {
  page_title: string
}

interface DeviceCategory {
  id: string
  name: string
  description: string
  icon: string
  status: 'allowed' | 'blocked'
  event_count: number
  blocked_count: number
  connected_count: number
  policy_count: number
}

interface DeviceControlStats {
  time_range: string
  total_events: number
  blocked_events: number
  storage_events: number
  connected_devices: number
  policies_count: number
  whitelist_count: number
  blocklist_count: number
  categories: DeviceCategory[]
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  usb: Usb,
  bluetooth: Bluetooth,
  'hard-drive': HardDrive,
  wifi: Wifi,
  printer: Printer,
  camera: Camera,
  mic: Mic,
}

export default function DeviceControl({ page_title }: DeviceControlProps) {
  const [stats, setStats] = useState<DeviceControlStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchStats = useCallback(async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/v1/device-control/stats', {
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
      })
      if (!res.ok) {
        throw new Error(`Failed to fetch stats: ${res.status}`)
      }
      const data = await res.json()
      setStats(data)
      setError(null)
    } catch (err) {
      logger.error('Error fetching device control stats:', err)
      setError(err instanceof Error ? err.message : 'Failed to load device control stats')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStats()
    // Refresh stats every 30 seconds
    const interval = setInterval(fetchStats, 30000)
    return () => clearInterval(interval)
  }, [fetchStats])

  const getIcon = (iconName: string) => {
    const IconComponent = iconMap[iconName] || Usb
    return IconComponent
  }

  const getStatusColors = (status: string) => {
    if (status === 'allowed') {
      return {
        iconStyle: { color: 'var(--emerald-400)' },
        bgStyle: { backgroundColor: 'rgba(52, 211, 153, 0.2)' },
        dotStyle: { backgroundColor: 'var(--emerald-400)' },
        badgeClass: 'badge-sentinel',
      }
    }
    return {
      iconStyle: { color: 'var(--crit)' },
      bgStyle: { backgroundColor: 'rgba(239, 68, 68, 0.2)' },
      dotStyle: { backgroundColor: 'var(--crit)' },
      badgeClass: 'badge-sentinel',
    }
  }

  return (
    <MainLayout title={page_title || 'Device Control'}>
      <Head title="Device Control - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Device Control</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Monitor and manage peripheral device access across endpoints</p>
          </div>
          <Link
            href="/app/device-control/policies"
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Shield className="h-4 w-4" />
            Manage Policies
          </Link>
        </div>

        {/* Info Banner */}
        <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-primary-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                Device control policies can be configured to allow, block, or audit peripheral device connections.
                Visit the{' '}
                <Link href="/app/device-control/policies" className="text-primary-400 hover:text-primary-300 underline">
                  policies page
                </Link>{' '}
                to create and manage device control rules.
              </p>
            </div>
          </div>
        </div>

        {/* Stats Summary */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Connected Devices</p>
              <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{stats.connected_devices}</p>
            </div>
            <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Active Policies</p>
              <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{stats.policies_count}</p>
            </div>
            <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Blocked Events (24h)</p>
              <p className="text-2xl font-bold mt-1" style={{ color: 'var(--crit)' }}>{stats.blocked_events}</p>
            </div>
            <div className="card-sentinel rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Events (24h)</p>
              <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{stats.total_events}</p>
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading && !stats && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 text-primary-400 animate-spin" />
            <span className="ml-3" style={{ color: 'var(--muted)' }}>Loading device categories...</span>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="rounded-xl p-4" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
            <p style={{ color: 'var(--crit)' }}>{error}</p>
            <button
              onClick={fetchStats}
              className="mt-2 text-sm underline"
              style={{ color: 'var(--crit)', opacity: 0.8 }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Empty State */}
        {stats && (!stats.categories || stats.categories.length === 0) && (
          <div className="flex flex-col items-center justify-center h-64" style={{ color: 'var(--muted)' }}>
            <Usb className="w-12 h-12 mb-3" style={{ opacity: 0.5 }} />
            <p className="text-sm font-medium">No device categories found</p>
            <p className="text-xs mt-1" style={{ opacity: 0.7 }}>Device categories will appear once agents report peripheral activity</p>
          </div>
        )}

        {/* Device Categories */}
        {stats && stats.categories && stats.categories.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {stats.categories.map((category) => {
              const IconComponent = getIcon(category.icon)
              const colors = getStatusColors(category.status)

              return (
                <div
                  key={category.id}
                  className="card-sentinel rounded-xl p-6 hover:opacity-90 transition-opacity"
                  style={{ backgroundColor: 'var(--surface)' }}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className="p-3 rounded-lg" style={colors.bgStyle}>
                        <IconComponent className="h-6 w-6" style={colors.iconStyle} />
                      </div>
                      <div>
                        <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>{category.name}</h3>
                        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{category.description}</p>
                        <div className="flex gap-4 mt-2 text-xs" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                          <span>{category.connected_count} connected</span>
                          <span>{category.event_count} events</span>
                          {category.blocked_count > 0 && (
                            <span style={{ color: 'var(--crit)' }}>{category.blocked_count} blocked</span>
                          )}
                        </div>
                      </div>
                    </div>
                    <span
                      className={cn(
                        'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium',
                        colors.badgeClass
                      )}
                      style={{
                        backgroundColor: category.status === 'allowed' ? 'rgba(52, 211, 153, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                        color: category.status === 'allowed' ? 'var(--emerald-400)' : 'var(--crit)',
                      }}
                    >
                      <span className="h-2 w-2 rounded-full" style={colors.dotStyle} />
                      {category.status === 'allowed' ? 'Allowed' : 'Blocked'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* Link to policies */}
        <div className="card-sentinel rounded-xl" style={{ backgroundColor: 'var(--surface)' }}>
          <Link
            href="/app/device-control/policies"
            className="flex items-center justify-between p-6 hover:opacity-80 transition-opacity rounded-xl"
          >
            <div className="flex items-center gap-3">
              <Shield className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              <div>
                <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Device Control Policies</h3>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Configure rules for each device category
                  {stats && ` (${stats.policies_count} policies)`}
                </p>
              </div>
            </div>
            <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
          </Link>
        </div>
      </div>
    </MainLayout>
  )
}
