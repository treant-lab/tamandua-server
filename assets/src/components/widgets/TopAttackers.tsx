/**
 * TopAttackers Widget
 *
 * Displays top threat actors and attack sources with geographic context,
 * attack patterns, and threat intelligence enrichment.
 */

import { useState, useMemo, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  Globe,
  Target,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  MapPin,
  Activity,
  Clock,
  Crosshair,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface Attacker {
  id: string
  name: string
  type: 'nation_state' | 'criminal' | 'hacktivist' | 'insider' | 'unknown'
  country?: string
  countryCode?: string
  attackCount: number
  targetedAssets: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  firstSeen: number
  lastSeen: number
  tactics: string[]
  techniques: string[]
  confidence: number
  trend: 'up' | 'down' | 'stable'
  change: number
  blocked: number
  iocCount?: number
}

export interface TopAttackersData {
  attackers: Attacker[]
  totalAttacks: number
  uniqueSources: number
  topCountry: string
  topTactic: string
  lastUpdated: number
}

export interface TopAttackersProps {
  data?: TopAttackersData
  isLoading?: boolean
  onAttackerClick?: (attacker: Attacker) => void
  onViewAll?: () => void
  className?: string
  limit?: number
  showDetails?: boolean
}

// ============================================================================
// Constants
// ============================================================================

const ATTACKER_TYPE_CONFIG: Record<Attacker['type'], { label: string; color: string; bgColor: string }> = {
  nation_state: { label: 'Nation State', color: 'text-red-400', bgColor: 'bg-red-500/20' },
  criminal: { label: 'Criminal', color: 'text-orange-400', bgColor: 'bg-orange-500/20' },
  hacktivist: { label: 'Hacktivist', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20' },
  insider: { label: 'Insider', color: 'text-purple-400', bgColor: 'bg-purple-500/20' },
  unknown: { label: 'Unknown', color: 'text-slate-400', bgColor: 'bg-slate-500/20' },
}

const SEVERITY_COLORS = {
  critical: 'text-red-400 bg-red-500/20 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/20 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-500/20 border-blue-500/30',
}

// Country flag emojis (sample - in production would use a proper flag library)
const COUNTRY_FLAGS: Record<string, string> = {
  CN: '\u{1F1E8}\u{1F1F3}',
  RU: '\u{1F1F7}\u{1F1FA}',
  KP: '\u{1F1F0}\u{1F1F5}',
  IR: '\u{1F1EE}\u{1F1F7}',
  US: '\u{1F1FA}\u{1F1F8}',
  UA: '\u{1F1FA}\u{1F1E6}',
  IN: '\u{1F1EE}\u{1F1F3}',
  BR: '\u{1F1E7}\u{1F1F7}',
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatTimeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

// ============================================================================
// Subcomponents
// ============================================================================

interface AttackerRowProps {
  attacker: Attacker
  rank: number
  onClick?: () => void
  expanded: boolean
  onToggle: () => void
  showDetails: boolean
}

function AttackerRow({
  attacker,
  rank,
  onClick,
  expanded,
  onToggle,
  showDetails,
}: AttackerRowProps) {
  const typeConfig = ATTACKER_TYPE_CONFIG[attacker.type]
  const flag = attacker.countryCode ? COUNTRY_FLAGS[attacker.countryCode] : null

  return (
    <div className="border-b border-slate-700 last:border-0">
      <button
        onClick={showDetails ? onToggle : onClick}
        className="flex items-center gap-3 w-full p-3 hover:bg-slate-700/30 transition-colors text-left"
      >
        {/* Rank */}
        <div className="flex-shrink-0 w-6 text-center">
          <span
            className={cn(
              'text-sm font-bold',
              rank === 1 ? 'text-red-400' : rank === 2 ? 'text-orange-400' : rank === 3 ? 'text-yellow-400' : 'text-slate-500'
            )}
          >
            #{rank}
          </span>
        </div>

        {/* Avatar/Flag */}
        <div className={cn('flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center', typeConfig.bgColor)}>
          {flag ? (
            <span className="text-xl">{flag}</span>
          ) : (
            <Globe className={cn('h-5 w-5', typeConfig.color)} />
          )}
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-white truncate">{attacker.name}</span>
            <span className={cn('text-xs px-1.5 py-0.5 rounded', typeConfig.bgColor, typeConfig.color)}>
              {typeConfig.label}
            </span>
            {attacker.confidence >= 80 && (
              <Shield className="h-3.5 w-3.5 text-green-400" title="High confidence attribution" />
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
            {attacker.country && (
              <span className="flex items-center gap-1">
                <MapPin className="h-3 w-3" />
                {attacker.country}
              </span>
            )}
            <span className="flex items-center gap-1">
              <Activity className="h-3 w-3" />
              {attacker.attackCount} attacks
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatTimeAgo(attacker.lastSeen)}
            </span>
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4">
          {/* Severity badge */}
          <div className={cn('px-2 py-1 rounded border text-xs font-medium', SEVERITY_COLORS[attacker.severity])}>
            {attacker.severity.toUpperCase()}
          </div>

          {/* Trend */}
          {attacker.trend !== 'stable' && (
            <div
              className={cn(
                'flex items-center gap-1 text-sm font-medium',
                attacker.trend === 'up' ? 'text-red-400' : 'text-green-400'
              )}
            >
              {attacker.trend === 'up' ? (
                <TrendingUp className="h-4 w-4" />
              ) : (
                <TrendingDown className="h-4 w-4" />
              )}
              {attacker.change}%
            </div>
          )}

          {/* Blocked count */}
          <div className="text-right">
            <div className="text-sm font-semibold text-green-400">{attacker.blocked}</div>
            <div className="text-xs text-slate-500">blocked</div>
          </div>

          {/* Expand toggle */}
          {showDetails && (
            <div className="text-slate-400">
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </div>
          )}
        </div>
      </button>

      {/* Expanded details */}
      {showDetails && expanded && (
        <div className="px-4 pb-4 bg-slate-900/50">
          <div className="grid grid-cols-2 gap-4 pt-3 border-t border-slate-700">
            {/* Tactics */}
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-2">MITRE Tactics</h5>
              <div className="flex flex-wrap gap-1">
                {attacker.tactics.map((tactic, i) => (
                  <span
                    key={i}
                    className="text-xs px-2 py-0.5 bg-slate-700 text-slate-300 rounded"
                  >
                    {tactic}
                  </span>
                ))}
              </div>
            </div>

            {/* Techniques */}
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-2">Techniques</h5>
              <div className="flex flex-wrap gap-1">
                {attacker.techniques.slice(0, 5).map((tech, i) => (
                  <span
                    key={i}
                    className="text-xs px-2 py-0.5 bg-primary-600/20 text-primary-400 rounded font-mono"
                  >
                    {tech}
                  </span>
                ))}
                {attacker.techniques.length > 5 && (
                  <span className="text-xs text-slate-500">+{attacker.techniques.length - 5} more</span>
                )}
              </div>
            </div>

            {/* Additional stats */}
            <div className="col-span-2 flex items-center gap-6 pt-3 border-t border-slate-700/50">
              <div className="text-center">
                <div className="text-lg font-bold text-white">{attacker.targetedAssets}</div>
                <div className="text-xs text-slate-500">Targeted Assets</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-white">{attacker.confidence}%</div>
                <div className="text-xs text-slate-500">Confidence</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-white">{attacker.iocCount || 0}</div>
                <div className="text-xs text-slate-500">IOCs</div>
              </div>
              <div className="flex-1" />
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onClick?.()
                }}
                className="flex items-center gap-1 text-xs text-primary-400 hover:text-primary-300"
              >
                View Details
                <ExternalLink className="h-3 w-3" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function TopAttackers({
  data,
  isLoading = false,
  onAttackerClick,
  onViewAll,
  className,
  limit = 5,
  showDetails = true,
}: TopAttackersProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const displayedAttackers = useMemo(() => {
    if (!data?.attackers) return []
    return data.attackers.slice(0, limit)
  }, [data?.attackers, limit])

  if (isLoading) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-slate-700 rounded w-1/3" />
          <div className="space-y-3">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-16 bg-slate-700 rounded" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (!data || !data.attackers || data.attackers.length === 0) {
    return (
      <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <div className="p-2 bg-red-600/20 rounded-lg">
            <Crosshair className="h-5 w-5 text-red-400" />
          </div>
          <h3 className="font-semibold text-white">Top Threat Actors</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Globe className="h-10 w-10 text-slate-600 mb-3" />
          <p className="text-slate-400 text-sm">No threat actor data available</p>
          <p className="text-slate-500 text-xs mt-1">Threat intelligence data will appear here when available</p>
        </div>
      </div>
    )
  }

  return (
    <div className={cn('bg-slate-800 rounded-xl border border-slate-700 overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-600/20 rounded-lg">
            <Crosshair className="h-5 w-5 text-red-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Top Threat Actors</h3>
            <p className="text-xs text-slate-400">
              {data?.uniqueSources || 0} unique sources detected
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
      {data && (
        <div className="grid grid-cols-3 gap-4 p-4 bg-slate-900/30 border-b border-slate-700">
          <div className="text-center">
            <div className="text-xl font-bold text-white">{data.totalAttacks.toLocaleString()}</div>
            <div className="text-xs text-slate-400">Total Attacks</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold text-white">{data.topCountry}</div>
            <div className="text-xs text-slate-400">Top Source</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold text-white">{data.topTactic}</div>
            <div className="text-xs text-slate-400">Top Tactic</div>
          </div>
        </div>
      )}

      {/* Attacker List */}
      <div className="divide-y divide-slate-700">
        {displayedAttackers.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No threat actors detected</p>
          </div>
        ) : (
          displayedAttackers.map((attacker, index) => (
            <AttackerRow
              key={attacker.id}
              attacker={attacker}
              rank={index + 1}
              onClick={() => onAttackerClick?.(attacker)}
              expanded={expandedId === attacker.id}
              onToggle={() => setExpandedId(expandedId === attacker.id ? null : attacker.id)}
              showDetails={showDetails}
            />
          ))
        )}
      </div>

      {/* Footer */}
      {data && (
        <div className="px-4 py-2 border-t border-slate-700 bg-slate-900/30">
          <span className="text-xs text-slate-500">
            Updated {new Date(data.lastUpdated).toLocaleTimeString()}
          </span>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Hook for fetching top attackers data
// ============================================================================

export function useTopAttackers(timeRange: string = '7d') {
  const [data, setData] = useState<TopAttackersData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/v1/threat-intel/attackers?range=${timeRange}`)
      if (!response.ok) throw new Error('Failed to fetch top attackers')
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
            if (parsed.props?.topAttackers) {
              setData(parsed.props.topAttackers)
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

export default TopAttackers
