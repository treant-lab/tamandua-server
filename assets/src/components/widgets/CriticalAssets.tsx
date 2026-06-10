/**
 * CriticalAssets Widget
 *
 * Displays critical asset health status with real-time monitoring,
 * risk indicators, and quick action capabilities.
 */

import { useState, useMemo, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  Server,
  Database,
  Cloud,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Activity,
  ExternalLink,
  MoreVertical,
  Eye,
  Lock,
  Unlock,
  RefreshCw,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export type AssetType = 'server' | 'database' | 'cloud' | 'endpoint' | 'network' | 'application'
export type AssetStatus = 'healthy' | 'warning' | 'critical' | 'offline' | 'unknown'
export type ProtectionStatus = 'protected' | 'partial' | 'unprotected'

export interface CriticalAsset {
  id: string
  name: string
  type: AssetType
  status: AssetStatus
  protection: ProtectionStatus
  riskScore: number
  lastScan: number
  alerts: number
  vulnerabilities: number
  compliance: number // percentage
  uptime: number // percentage
  tags?: string[]
  ip?: string
  location?: string
}

export interface CriticalAssetsData {
  assets: CriticalAsset[]
  summary: {
    total: number
    healthy: number
    warning: number
    critical: number
    offline: number
    averageRisk: number
    averageCompliance: number
  }
  lastUpdated: number
}

export interface CriticalAssetsProps {
  data?: CriticalAssetsData
  isLoading?: boolean
  onAssetClick?: (asset: CriticalAsset) => void
  onAction?: (asset: CriticalAsset, action: string) => void
  onViewAll?: () => void
  className?: string
  limit?: number
  showActions?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const ASSET_TYPE_CONFIG: Record<AssetType, { icon: React.ElementType; color: string; bgColor: string }> = {
  server: { icon: Server, color: 'text-purple-400', bgColor: 'bg-purple-500/20' },
  database: { icon: Database, color: 'text-amber-400', bgColor: 'bg-amber-500/20' },
  cloud: { icon: Cloud, color: 'text-cyan-400', bgColor: 'bg-cyan-500/20' },
  endpoint: { icon: Server, color: 'text-blue-400', bgColor: 'bg-blue-500/20' },
  network: { icon: Activity, color: 'text-green-400', bgColor: 'bg-green-500/20' },
  application: { icon: Server, color: 'text-pink-400', bgColor: 'bg-pink-500/20' },
}

const STATUS_CONFIG: Record<AssetStatus, { label: string; color: string; bgColor: string; icon: React.ElementType }> = {
  healthy: { label: 'Healthy', color: 'text-green-400', bgColor: 'bg-green-500/20', icon: CheckCircle },
  warning: { label: 'Warning', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', icon: AlertTriangle },
  critical: { label: 'Critical', color: 'text-red-400', bgColor: 'bg-red-500/20', icon: XCircle },
  offline: { label: 'Offline', color: 'text-slate-400', bgColor: 'bg-slate-500/20', icon: XCircle },
  unknown: { label: 'Unknown', color: 'text-slate-400', bgColor: 'bg-slate-500/20', icon: AlertTriangle },
}

const PROTECTION_CONFIG: Record<ProtectionStatus, { label: string; color: string; icon: React.ElementType }> = {
  protected: { label: 'Protected', color: 'text-green-400', icon: Shield },
  partial: { label: 'Partial', color: 'text-yellow-400', icon: Shield },
  unprotected: { label: 'Unprotected', color: 'text-red-400', icon: Unlock },
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatTimeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

function getRiskColor(score: number): string {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBgColor(score: number): string {
  if (score >= 75) return 'bg-red-500'
  if (score >= 50) return 'bg-orange-500'
  if (score >= 25) return 'bg-yellow-500'
  return 'bg-green-500'
}

// ============================================================================
// Subcomponents
// ============================================================================

interface AssetCardProps {
  asset: CriticalAsset
  onClick?: () => void
  onAction?: (action: string) => void
  showActions: boolean
}

function AssetCard({ asset, onClick, onAction, showActions }: AssetCardProps) {
  const [showMenu, setShowMenu] = useState(false)
  const typeConfig = ASSET_TYPE_CONFIG[asset.type]
  const statusConfig = STATUS_CONFIG[asset.status]
  const protectionConfig = PROTECTION_CONFIG[asset.protection]
  const TypeIcon = typeConfig.icon
  const StatusIcon = statusConfig.icon
  const ProtectionIcon = protectionConfig.icon

  return (
    <div
      className={cn(
        'relative p-4 rounded-lg border transition-all hover:bg-slate-700/30',
        asset.status === 'critical' ? 'border-red-500/50 bg-red-500/5' :
        asset.status === 'warning' ? 'border-yellow-500/30 bg-yellow-500/5' :
        'border-slate-700'
      )}
    >
      <div className="flex items-start gap-3">
        {/* Type Icon */}
        <div className={cn('p-2 rounded-lg flex-shrink-0', typeConfig.bgColor)}>
          <TypeIcon className={cn('h-5 w-5', typeConfig.color)} />
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <button
              onClick={onClick}
              className="font-medium text-white hover:text-primary-400 truncate"
            >
              {asset.name}
            </button>
            <div className={cn('flex items-center gap-1 px-1.5 py-0.5 rounded text-xs', statusConfig.bgColor)}>
              <StatusIcon className={cn('h-3 w-3', statusConfig.color)} />
              <span className={statusConfig.color}>{statusConfig.label}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
            <span className="capitalize">{asset.type}</span>
            {asset.ip && (
              <>
                <span className="text-slate-600">|</span>
                <span className="font-mono">{asset.ip}</span>
              </>
            )}
            {asset.location && (
              <>
                <span className="text-slate-600">|</span>
                <span>{asset.location}</span>
              </>
            )}
          </div>

          {/* Metrics row */}
          <div className="flex items-center gap-4 mt-3">
            {/* Risk Score */}
            <div className="flex items-center gap-2">
              <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={cn('h-full rounded-full', getRiskBgColor(asset.riskScore))}
                  style={{ width: `${asset.riskScore}%` }}
                />
              </div>
              <span className={cn('text-xs font-medium', getRiskColor(asset.riskScore))}>
                {asset.riskScore}
              </span>
            </div>

            {/* Alerts */}
            {asset.alerts > 0 && (
              <div className="flex items-center gap-1 text-xs">
                <AlertTriangle className="h-3 w-3 text-orange-400" />
                <span className="text-orange-400">{asset.alerts}</span>
              </div>
            )}

            {/* Vulnerabilities */}
            {asset.vulnerabilities > 0 && (
              <div className="flex items-center gap-1 text-xs">
                <Shield className="h-3 w-3 text-red-400" />
                <span className="text-red-400">{asset.vulnerabilities}</span>
              </div>
            )}

            {/* Protection */}
            <div className="flex items-center gap-1 text-xs">
              <ProtectionIcon className={cn('h-3 w-3', protectionConfig.color)} />
              <span className={protectionConfig.color}>{protectionConfig.label}</span>
            </div>
          </div>

          {/* Tags */}
          {asset.tags && asset.tags.length > 0 && (
            <div className="flex items-center gap-1 mt-2">
              {asset.tags.slice(0, 3).map((tag, i) => (
                <span
                  key={i}
                  className="text-xs px-1.5 py-0.5 bg-slate-700 text-slate-300 rounded"
                >
                  {tag}
                </span>
              ))}
              {asset.tags.length > 3 && (
                <span className="text-xs text-slate-500">+{asset.tags.length - 3}</span>
              )}
            </div>
          )}
        </div>

        {/* Actions */}
        {showActions && (
          <div className="relative">
            <button
              onClick={() => setShowMenu(!showMenu)}
              className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-slate-600"
            >
              <MoreVertical className="h-4 w-4" />
            </button>

            {showMenu && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setShowMenu(false)}
                />
                <div className="absolute right-0 mt-1 w-40 bg-slate-700 border border-slate-600 rounded-lg shadow-xl z-20">
                  <button
                    onClick={() => {
                      onAction?.('view')
                      setShowMenu(false)
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-300 hover:bg-slate-600 rounded-t-lg"
                  >
                    <Eye className="h-4 w-4" />
                    View Details
                  </button>
                  <button
                    onClick={() => {
                      onAction?.('scan')
                      setShowMenu(false)
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-300 hover:bg-slate-600"
                  >
                    <RefreshCw className="h-4 w-4" />
                    Rescan
                  </button>
                  <button
                    onClick={() => {
                      onAction?.('isolate')
                      setShowMenu(false)
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-400 hover:bg-slate-600 rounded-b-lg"
                  >
                    <Lock className="h-4 w-4" />
                    Isolate
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Last scan indicator */}
      <div className="absolute bottom-2 right-3 flex items-center gap-1 text-xs text-slate-500">
        <Clock className="h-3 w-3" />
        {formatTimeAgo(asset.lastScan)}
      </div>
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function CriticalAssets({
  data,
  isLoading = false,
  onAssetClick,
  onAction,
  onViewAll,
  className,
  limit = 5,
  showActions = true,
}: CriticalAssetsProps) {
  const displayedAssets = useMemo(() => {
    if (!data?.assets) return []
    // Sort by risk score descending, then by status severity
    return [...data.assets]
      .sort((a, b) => {
        const statusOrder = { critical: 0, warning: 1, offline: 2, unknown: 3, healthy: 4 }
        if (a.status !== b.status) {
          return statusOrder[a.status] - statusOrder[b.status]
        }
        return b.riskScore - a.riskScore
      })
      .slice(0, limit)
  }, [data?.assets, limit])

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/3" />
          <div className="space-y-3">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-24 bg-slate-700 rounded" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (!data || !data.assets || data.assets.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-amber-600/20 rounded-lg">
            <Server className="h-5 w-5 text-amber-400" />
          </div>
          <h3 className="font-semibold text-white">Critical Assets</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Server className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No critical assets found</p>
          <p className="text-slate-500 text-xs mt-1">Asset data will appear once agents are deployed</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-600/20 rounded-lg">
            <Server className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Critical Assets</h3>
            <p className="text-xs text-slate-400">
              {data?.summary.total || 0} assets monitored
            </p>
          </div>
        </div>

        <button
          onClick={onViewAll}
          className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
        >
          View All
          <ExternalLink className="h-3 w-3" />
        </button>
      </div>

      {/* Summary Stats */}
      {data?.summary && (
        <div className="grid grid-cols-4 gap-4 p-4 bg-slate-900/30 border-b border-slate-700">
          <div className="text-center">
            <div className="flex items-center justify-center gap-1">
              <CheckCircle className="h-4 w-4 text-green-400" />
              <span className="text-lg font-bold text-green-400">{data.summary.healthy}</span>
            </div>
            <div className="text-xs text-slate-500">Healthy</div>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center gap-1">
              <AlertTriangle className="h-4 w-4 text-yellow-400" />
              <span className="text-lg font-bold text-yellow-400">{data.summary.warning}</span>
            </div>
            <div className="text-xs text-slate-500">Warning</div>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center gap-1">
              <XCircle className="h-4 w-4 text-red-400" />
              <span className="text-lg font-bold text-red-400">{data.summary.critical}</span>
            </div>
            <div className="text-xs text-slate-500">Critical</div>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center gap-1">
              <Shield className="h-4 w-4 text-primary-400" />
              <span className="text-lg font-bold text-white">{data.summary.averageCompliance}%</span>
            </div>
            <div className="text-xs text-slate-500">Compliance</div>
          </div>
        </div>
      )}

      {/* Asset List */}
      <div className="p-4 space-y-3">
        {displayedAssets.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No critical assets configured</p>
          </div>
        ) : (
          displayedAssets.map(asset => (
            <AssetCard
              key={asset.id}
              asset={asset}
              onClick={() => onAssetClick?.(asset)}
              onAction={(action) => onAction?.(asset, action)}
              showActions={showActions}
            />
          ))
        )}
      </div>

      {/* Footer */}
      {data && (
        <div className="px-4 py-2 border-t border-slate-700 bg-slate-900/30 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Avg Risk: <span className={getRiskColor(data.summary.averageRisk)}>{data.summary.averageRisk}</span>
          </span>
          <span className="text-xs text-slate-500">
            Updated {new Date(data.lastUpdated).toLocaleTimeString()}
          </span>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching critical assets data
// ============================================================================

export function useCriticalAssets(timeRange: string = '7d') {
  const [data, setData] = useState<CriticalAssetsData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/v1/assets?range=${timeRange}&sort=risk_score`)
      if (!response.ok) throw new Error('Failed to fetch critical assets')
      const result = await response.json()
      setData(result.data)
    } catch (err) {
      // Fall back to Inertia shared page props if API call fails
      try {
        const pageEl = document.getElementById('app')
        if (pageEl) {
          const pageData = pageEl.dataset.page
          if (pageData) {
            const parsed = JSON.parse(pageData)
            if (parsed.props?.criticalAssets) {
              setData(parsed.props.criticalAssets)
              return
            }
          }
        }
      } catch (_fallbackErr) {
        // Fallback also failed, use original error
      }
      setError(err instanceof Error ? err : new Error('Unknown error'))
    } finally {
      setIsLoading(false)
    }
  }, [timeRange])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return {
    data,
    isLoading,
    error,
    refresh: fetchData,
  }
}

export default CriticalAssets
