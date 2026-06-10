import { Head } from '@inertiajs/react'
import axios from 'axios'
import { useState, useMemo } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  Eye,
  Package,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Star,
  Upload,
  Users,
  Zap,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'
import { cn } from '@/lib/utils'

// MITRE ATT&CK Tactics mapping
const MITRE_TACTICS = [
  'RECONNAISSANCE',
  'RESOURCE DEVELOPMENT',
  'INITIAL ACCESS',
  'EXECUTION',
  'PERSISTENCE',
  'PRIVILEGE ESCALATION',
  'DEFENSE EVASION',
  'CREDENTIAL ACCESS',
  'DISCOVERY',
  'LATERAL MOVEMENT',
  'COLLECTION',
  'COMMAND AND CONTROL',
  'EXFILTRATION',
  'IMPACT',
] as const

type MitreTactic = typeof MITRE_TACTICS[number]

interface Maintainer {
  wallet: string
  name: string
  avatar?: string
  pack_count: number
  reviewer_score: number
}

interface Pack {
  id: string
  name: string
  description: string
  version: string
  type: 'sigma' | 'yara' | 'config' | 'mixed'
  tier: 'free' | 'paid'
  price_sol?: number
  creator_wallet: string | null
  maintainer: Maintainer
  mitre_techniques: string[]
  mitre_tactics: MitreTactic[]
  rules_count: number
  tags: string[]
  install_count: number
  rating: number
  verified: boolean
  signed: boolean
  fp_risk: number // 0.00 - 1.00
  validation_score: number // 0 - 100
  tactics_coverage: number // out of 14
  installed?: {
    enabled: boolean
    installed_at: string
  }
  enabled?: boolean
  featured?: boolean
  changelog_url?: string
}

interface DetectionPacksProps {
  availablePacks?: Pack[]
  installedPacks?: Pack[]
  stats?: {
    total_available: number
    total_installed: number
    enabled_count: number
    techniques_covered: number
    rules_active: number
  }
}

const TYPE_COLORS: Record<string, string> = {
  sigma: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  yara: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  config: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  mixed: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
}

const TYPE_LABELS: Record<string, string> = {
  sigma: 'Sigma',
  yara: 'YARA',
  config: 'Config',
  mixed: 'Sigma + YARA',
}

const FALLBACK_MAINTAINER: Maintainer = {
  wallet: '',
  name: 'Tamandua Labs',
  pack_count: 0,
  reviewer_score: 0,
}

function maintainerFor(pack: Partial<Pack>): Maintainer {
  const maintainer = pack.maintainer || FALLBACK_MAINTAINER

  return {
    wallet: maintainer.wallet || '',
    name: maintainer.name || FALLBACK_MAINTAINER.name,
    avatar: maintainer.avatar,
    pack_count: maintainer.pack_count || 0,
    reviewer_score: maintainer.reviewer_score || 0,
  }
}

function safePack(pack: Partial<Pack> | null | undefined): Pack {
  const source = pack || {}

  return {
    ...source,
    id: source.id || `pack-${source.name || 'unknown'}`,
    name: source.name || 'Untitled pack',
    description: source.description || 'No description provided.',
    version: source.version || '0.0.0',
    type: ['sigma', 'yara', 'config', 'mixed'].includes(source.type || '') ? source.type! : 'mixed',
    tier: ['free', 'paid'].includes(source.tier || '') ? source.tier! : 'free',
    creator_wallet: source.creator_wallet || null,
    maintainer: maintainerFor(source),
    mitre_techniques: Array.isArray(source.mitre_techniques) ? source.mitre_techniques : [],
    mitre_tactics: Array.isArray(source.mitre_tactics) ? source.mitre_tactics : [],
    tags: Array.isArray(source.tags) ? source.tags : [],
    rules_count: source.rules_count || 0,
    install_count: source.install_count || 0,
    rating: source.rating || 0,
    verified: source.verified ?? false,
    signed: source.signed ?? false,
    fp_risk: source.fp_risk ?? 0,
    validation_score: source.validation_score ?? 0,
    tactics_coverage: source.tactics_coverage || 0,
  }
}

function ProgressBar({ value, max = 1, color = 'emerald' }: { value: number; max?: number; color?: string }) {
  const percent = Math.min(100, (value / max) * 100)
  const colorClass = color === 'emerald' ? 'bg-emerald-500' : color === 'amber' ? 'bg-amber-500' : 'bg-red-500'

  return (
    <div className="h-1.5 w-16 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
      <div className={cn('h-full rounded-full transition-all', colorClass)} style={{ width: `${percent}%` }} />
    </div>
  )
}

function TacticBadge({ tactic }: { tactic: MitreTactic }) {
  return (
    <span
      className="rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wider"
      style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
    >
      {tactic}
    </span>
  )
}

function FeaturedPackCard({
  pack,
  onInstall,
  installing,
}: {
  pack: Pack
  onInstall: (id: string) => void
  installing: string | null
}) {
  const maintainer = maintainerFor(pack)

  return (
    <div
      className="rounded-xl border p-6 mb-8"
      style={{
        backgroundColor: 'var(--surface)',
        borderColor: 'var(--emerald-600)',
        boxShadow: '0 0 24px rgba(16, 185, 129, 0.1)',
      }}
    >
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left side - main content */}
        <div className="flex-1">
          {/* Badges row */}
          <div className="flex items-center gap-2 mb-4">
            <span
              className="rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider"
              style={{ backgroundColor: 'var(--emerald-500)', color: 'white' }}
            >
              Featured
            </span>
            <span
              className="rounded-full px-2.5 py-1 text-xs font-medium border"
              style={{
                backgroundColor: 'var(--surface-2)',
                borderColor: 'var(--border)',
                color: 'var(--fg-2)',
              }}
            >
              v{pack.version}
            </span>
            {pack.signed && (
              <span
                className="flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium"
                style={{ backgroundColor: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
              >
                <ShieldCheck className="h-3 w-3" />
                Signed
              </span>
            )}
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold mb-2" style={{ color: 'var(--fg)' }}>
            {pack.name} <span style={{ color: 'var(--muted)' }}>·</span>{' '}
            <span style={{ color: 'var(--muted)' }}>{TYPE_LABELS[pack.type]} pack</span>
          </h2>

          {/* Description */}
          <p className="text-sm mb-6" style={{ color: 'var(--fg-2)' }}>
            {pack.description}
          </p>

          {/* Stats row */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <div>
              <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Coverage</p>
              <p className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                {pack.tactics_coverage} / 14 <span className="text-sm font-normal" style={{ color: 'var(--muted)' }}>tactics</span>
              </p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Detections</p>
              <p className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                {pack.rules_count} <span className="text-sm font-normal" style={{ color: 'var(--muted)' }}>rules</span>
              </p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>FP Risk</p>
              <div className="flex items-center gap-2">
                <span className="text-lg font-semibold" style={{ color: pack.fp_risk <= 0.1 ? 'var(--emerald-400)' : pack.fp_risk <= 0.2 ? 'var(--amber-400)' : 'var(--crit)' }}>
                  {pack.fp_risk.toFixed(2)}
                </span>
                <div className="h-2 w-2 rounded-full" style={{ backgroundColor: pack.fp_risk <= 0.1 ? 'var(--emerald-500)' : pack.fp_risk <= 0.2 ? 'var(--amber-500)' : 'var(--crit)' }} />
              </div>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Validation</p>
              <div className="flex items-center gap-2">
                <span className="text-lg font-semibold" style={{ color: pack.validation_score >= 90 ? 'var(--emerald-400)' : pack.validation_score >= 80 ? 'var(--amber-400)' : 'var(--crit)' }}>
                  {pack.validation_score} / 100
                </span>
                <div className="h-2 w-2 rounded-full" style={{ backgroundColor: pack.validation_score >= 90 ? 'var(--emerald-500)' : pack.validation_score >= 80 ? 'var(--amber-500)' : 'var(--crit)' }} />
              </div>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Installed by</p>
              <p className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                {pack.install_count.toLocaleString()} <span className="text-sm font-normal" style={{ color: 'var(--muted)' }}>fleets</span>
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => onInstall(pack.id)}
              disabled={installing === pack.id}
              className="flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold transition-colors"
              style={{
                backgroundColor: 'var(--emerald-500)',
                color: 'white',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--emerald-400)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--emerald-500)'
              }}
            >
              {installing === pack.id ? (
                'Installing...'
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  Install pack
                </>
              )}
            </button>
            <button
              disabled
              title="Rule preview is not wired to a pack detail API in this build."
              className="flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium transition-colors"
              style={{
                backgroundColor: 'transparent',
                borderColor: 'var(--border)',
                color: 'var(--fg-2)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                e.currentTarget.style.borderColor = 'var(--fg-2)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent'
                e.currentTarget.style.borderColor = 'var(--border)'
              }}
            >
              <Eye className="h-4 w-4" />
              Preview rules
            </button>
            {pack.changelog_url && (
              <a
                href={pack.changelog_url}
                className="text-sm font-medium transition-colors"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--fg)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--muted)'
                }}
              >
                Read changelog →
              </a>
            )}
          </div>
        </div>

        {/* Right side - maintainer info */}
        <div
          className="lg:w-64 lg:border-l lg:pl-6 pt-4 lg:pt-0"
          style={{ borderColor: 'var(--border)' }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div
              className="h-10 w-10 rounded-full flex items-center justify-center text-white font-semibold"
              style={{ backgroundColor: 'var(--emerald-600)' }}
            >
              {maintainer.name.charAt(0)}
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-medium truncate" style={{ color: 'var(--fg)' }}>{maintainer.name}</p>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>
                {maintainer.pack_count} packs · {maintainer.reviewer_score} reviewer score
              </p>
            </div>
          </div>
          <button
            className="w-full rounded-lg border px-4 py-2 text-sm font-medium transition-colors"
            style={{
              backgroundColor: 'transparent',
              borderColor: 'var(--border)',
              color: 'var(--fg-2)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--surface-2)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent'
            }}
          >
            + Follow
          </button>
        </div>
      </div>
    </div>
  )
}

function PackCard({
  pack,
  onInstall,
  installing,
}: {
  pack: Pack
  onInstall: (id: string) => void
  installing: string | null
}) {
  const isInstalled = !!pack.installed
  const maintainer = maintainerFor(pack)

  return (
    <div
      className={cn(
        'rounded-xl border p-5 transition-all',
        isInstalled
          ? 'border-emerald-500/30 bg-emerald-500/5'
          : 'hover:border-[var(--fg-2)]'
      )}
      style={{
        backgroundColor: isInstalled ? undefined : 'var(--surface)',
        borderColor: isInstalled ? undefined : 'var(--border)',
      }}
    >
      {/* Header with badges */}
      <div className="flex items-center gap-2 mb-3">
        <span className={cn('rounded px-2 py-0.5 text-xs font-medium border', TYPE_COLORS[pack.type])}>
          {TYPE_LABELS[pack.type]}
        </span>
        <span
          className="rounded px-2 py-0.5 text-xs"
          style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
        >
          v{pack.version}
        </span>
        <div className="flex-1" />
        {pack.tier === 'paid' && pack.price_sol ? (
          <span className="text-sm font-medium" style={{ color: 'var(--amber-400)' }}>
            {pack.price_sol} SOL
          </span>
        ) : (
          <span className="text-sm font-medium" style={{ color: 'var(--emerald-400)' }}>Free</span>
        )}
      </div>

      {/* Title */}
      <h3 className="text-base font-semibold mb-2" style={{ color: 'var(--fg)' }}>
        {pack.name}
      </h3>

      {/* Description */}
      <p className="text-sm line-clamp-2 mb-3" style={{ color: 'var(--fg-2)' }}>
        {pack.description}
      </p>

      {/* Author */}
      <div className="flex items-center gap-2 mb-3">
        <div
          className="h-5 w-5 rounded-full flex items-center justify-center text-[10px] text-white font-medium"
          style={{ backgroundColor: 'var(--surface-3)' }}
        >
          {maintainer.name.charAt(0)}
        </div>
        <span className="text-xs font-mono truncate" style={{ color: 'var(--muted)' }}>
          {maintainer.wallet ? `${maintainer.wallet.slice(0, 4)}...${maintainer.wallet.slice(-4)}` : 'tamandua'}
        </span>
      </div>

      {/* Coverage tags */}
      <div className="flex flex-wrap gap-1 mb-4">
        {pack.mitre_tactics.slice(0, 3).map(tactic => (
          <TacticBadge key={tactic} tactic={tactic} />
        ))}
        {pack.mitre_tactics.length > 3 && (
          <span className="text-xs" style={{ color: 'var(--muted)' }}>
            +{pack.mitre_tactics.length - 3}
          </span>
        )}
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>FP Risk</span>
          <ProgressBar
            value={1 - pack.fp_risk}
            color={pack.fp_risk <= 0.1 ? 'emerald' : pack.fp_risk <= 0.2 ? 'amber' : 'red'}
          />
          <span className="text-xs font-medium" style={{ color: pack.fp_risk <= 0.1 ? 'var(--emerald-400)' : pack.fp_risk <= 0.2 ? 'var(--amber-400)' : 'var(--crit)' }}>
            {pack.fp_risk.toFixed(2)}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Validation</span>
          <ProgressBar
            value={pack.validation_score}
            max={100}
            color={pack.validation_score >= 90 ? 'emerald' : pack.validation_score >= 80 ? 'amber' : 'red'}
          />
          <span className="text-xs font-medium" style={{ color: pack.validation_score >= 90 ? 'var(--emerald-400)' : pack.validation_score >= 80 ? 'var(--amber-400)' : 'var(--crit)' }}>
            {pack.validation_score}
          </span>
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-2">
        <button
          disabled
          title="Rule preview is not wired to a pack detail API in this build."
          className="flex-1 flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors"
          style={{
            backgroundColor: 'transparent',
            borderColor: 'var(--border)',
            color: 'var(--fg-2)',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--surface-2)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent'
          }}
        >
          <Eye className="h-4 w-4" />
          Preview
        </button>
        <button
          onClick={() => onInstall(pack.id)}
          disabled={installing === pack.id || isInstalled}
          className={cn(
            'flex-1 flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
            isInstalled ? 'opacity-50 cursor-not-allowed' : ''
          )}
          style={{
            backgroundColor: isInstalled ? 'var(--surface-2)' : 'var(--emerald-500)',
            color: isInstalled ? 'var(--muted)' : 'white',
          }}
          onMouseEnter={(e) => {
            if (!isInstalled) {
              e.currentTarget.style.backgroundColor = 'var(--emerald-400)'
            }
          }}
          onMouseLeave={(e) => {
            if (!isInstalled) {
              e.currentTarget.style.backgroundColor = 'var(--emerald-500)'
            }
          }}
        >
          {installing === pack.id ? (
            'Installing...'
          ) : isInstalled ? (
            <>
              <CheckCircle2 className="h-4 w-4" />
              Installed
            </>
          ) : (
            <>
              <Plus className="h-4 w-4" />
              Install
            </>
          )}
        </button>
      </div>
    </div>
  )
}

type FilterType = 'all' | 'sigma' | 'yara' | 'config'
type PriceFilter = 'all' | 'free' | 'paid'
type SortBy = 'reputation' | 'coverage' | 'recency'

export default function DetectionPacks({
  availablePacks = [],
  installedPacks = [],
  stats = { total_available: 0, total_installed: 0, enabled_count: 0, techniques_covered: 0, rules_active: 0 },
}: DetectionPacksProps) {
  const [installing, setInstalling] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<FilterType>('all')
  const [priceFilter, setPriceFilter] = useState<PriceFilter>('all')
  const [sortBy, setSortBy] = useState<SortBy>('reputation')

  const allPacks = (availablePacks || []).map(safePack)
  const installedPackList = (installedPacks || []).map(safePack)
  const safeStats = {
    total_available: stats.total_available || allPacks.length,
    total_installed: stats.total_installed || installedPackList.length,
    enabled_count: stats.enabled_count || installedPackList.filter(p => p.enabled || p.installed?.enabled).length,
    techniques_covered: stats.techniques_covered || 0,
    rules_active: stats.rules_active || 0,
  }

  // Separate featured pack
  const featuredPack = allPacks.find(p => p.featured)
  const regularPacks = allPacks.filter(p => !p.featured)

  // Count by type
  const typeCounts = useMemo(() => {
    const counts = { all: allPacks.length, sigma: 0, yara: 0, config: 0 }
    allPacks.forEach(p => {
      if (p.type === 'sigma' || p.type === 'mixed') counts.sigma++
      if (p.type === 'yara' || p.type === 'mixed') counts.yara++
      if (p.type === 'config') counts.config++
    })
    return counts
  }, [allPacks])

  // Filter and sort packs
  const filteredPacks = useMemo(() => {
    let result = regularPacks

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      result = result.filter(p =>
        p.name.toLowerCase().includes(query) ||
        p.description.toLowerCase().includes(query) ||
        p.tags.some(t => t.toLowerCase().includes(query))
      )
    }

    // Type filter
    if (typeFilter !== 'all') {
      result = result.filter(p => p.type === typeFilter || (typeFilter === 'sigma' && p.type === 'mixed') || (typeFilter === 'yara' && p.type === 'mixed'))
    }

    // Price filter
    if (priceFilter === 'free') {
      result = result.filter(p => p.tier === 'free')
    } else if (priceFilter === 'paid') {
      result = result.filter(p => p.tier === 'paid')
    }

    // Sort
    switch (sortBy) {
      case 'reputation':
        result = [...result].sort((a, b) => b.rating - a.rating)
        break
      case 'coverage':
        result = [...result].sort((a, b) => b.tactics_coverage - a.tactics_coverage)
        break
      case 'recency':
        result = [...result].sort((a, b) => {
          const vA = a.version.split('.').map(Number)
          const vB = b.version.split('.').map(Number)
          for (let i = 0; i < Math.max(vA.length, vB.length); i++) {
            if ((vA[i] || 0) !== (vB[i] || 0)) return (vB[i] || 0) - (vA[i] || 0)
          }
          return 0
        })
        break
    }

    return result
  }, [regularPacks, searchQuery, typeFilter, priceFilter, sortBy])

  const handleInstall = async (packId: string) => {
    setInstalling(packId)
    try {
      await axios.post(`/api/v1/detection-packs/${packId}/install`)
      window.location.reload()
    } catch (error) {
      console.error('Failed to install pack:', error)
    } finally {
      setInstalling(null)
    }
  }

  const installedCount = installedPackList.length || safeStats.total_installed

  return (
    <MainLayout>
      <Head title="Detection Marketplace" />

      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold mb-2" style={{ color: 'var(--fg)' }}>
              Detection marketplace
            </h1>
            <p className="text-base" style={{ color: 'var(--muted)' }}>
              Curated Sigma, YARA and config packs. Reviewed for false-positive risk before install.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              disabled
              title="Pack submission is handled from Contributions after review metadata is available."
              className="flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium transition-colors"
              style={{
                backgroundColor: 'transparent',
                borderColor: 'var(--border)',
                color: 'var(--fg-2)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-2)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent'
              }}
            >
              <Upload className="h-4 w-4" />
              Submit a pack
            </button>
            <button
              disabled
              title="Installed pack management needs enable/disable and uninstall endpoints in this build."
              className="flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors"
              style={{
                backgroundColor: 'var(--surface-2)',
                color: 'var(--fg)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-3)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--surface-2)'
              }}
            >
              <Settings className="h-4 w-4" />
              Manage installed ({installedCount})
            </button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex flex-col lg:flex-row gap-4 mb-6">
          {/* Search */}
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
            <input
              type="text"
              placeholder="Search detection packs..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border pl-10 pr-4 py-2.5 text-sm focus:outline-none focus:ring-2"
              style={{
                backgroundColor: 'var(--surface)',
                borderColor: 'var(--border)',
                color: 'var(--fg)',
              }}
            />
          </div>

          {/* Type tabs */}
          <div className="flex items-center gap-1 rounded-lg p-1" style={{ backgroundColor: 'var(--surface)' }}>
            {(['all', 'sigma', 'yara', 'config'] as FilterType[]).map(type => (
              <button
                key={type}
                onClick={() => setTypeFilter(type)}
                className={cn(
                  'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
                  typeFilter === type ? 'text-white' : ''
                )}
                style={{
                  backgroundColor: typeFilter === type ? 'var(--emerald-500)' : 'transparent',
                  color: typeFilter === type ? 'white' : 'var(--muted)',
                }}
              >
                {type === 'all' ? 'All' : type === 'sigma' ? 'Sigma' : type === 'yara' ? 'YARA' : 'Config'}{' '}
                <span style={{ opacity: 0.7 }}>({typeCounts[type]})</span>
              </button>
            ))}
          </div>

          {/* Price filter */}
          <div className="flex items-center gap-2">
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Price:</span>
            <select
              value={priceFilter}
              onChange={e => setPriceFilter(e.target.value as PriceFilter)}
              className="rounded-lg border px-3 py-2 text-sm"
              style={{
                backgroundColor: 'var(--surface)',
                borderColor: 'var(--border)',
                color: 'var(--fg)',
              }}
            >
              <option value="all">All</option>
              <option value="free">Free</option>
              <option value="paid">Paid</option>
            </select>
          </div>

          {/* Sort */}
          <div className="flex items-center gap-2">
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Sort:</span>
            <select
              value={sortBy}
              onChange={e => setSortBy(e.target.value as SortBy)}
              className="rounded-lg border px-3 py-2 text-sm"
              style={{
                backgroundColor: 'var(--surface)',
                borderColor: 'var(--border)',
                color: 'var(--fg)',
              }}
            >
              <option value="reputation">By reputation</option>
              <option value="coverage">By coverage</option>
              <option value="recency">By recency</option>
            </select>
          </div>
        </div>

        {/* Featured Pack */}
        {featuredPack && (
          <FeaturedPackCard
            pack={featuredPack}
            onInstall={handleInstall}
            installing={installing}
          />
        )}

        {/* Pack Grid */}
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {filteredPacks.map(pack => (
            <PackCard
              key={pack.id}
              pack={pack}
              onInstall={handleInstall}
              installing={installing}
            />
          ))}

          {filteredPacks.length === 0 && (
            <div className="col-span-full py-16 text-center" style={{ color: 'var(--muted)' }}>
              <Package className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium mb-1">No packs found</p>
              <p className="text-sm">Try adjusting your search or filters</p>
            </div>
          )}
        </div>

        {/* Bottom Banner */}
        <div
          className="mt-12 rounded-xl border p-6"
          style={{
            backgroundColor: 'var(--surface)',
            borderColor: 'var(--emerald-700)',
          }}
        >
          <div className="flex items-start gap-4">
            <div
              className="rounded-lg p-3"
              style={{ backgroundColor: 'var(--emerald-glow)' }}
            >
              <Shield className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
            </div>
            <div>
              <p className="text-base" style={{ color: 'var(--fg-2)' }}>
                Every pack is signed, reproducibly built, and tested against the public benchmark suite before listing.
                This is a marketplace of defense, not a token store.
              </p>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
