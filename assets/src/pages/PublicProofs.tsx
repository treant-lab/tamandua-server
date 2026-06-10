import { useState, useMemo } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  AlertTriangle,
  HeartPulse,
  Wrench,
  ExternalLink,
  Lock,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  Check,
  Hash,
  FileText,
  Clock,
  User,
  Building2,
  Network,
  Terminal,
  Database,
  Key,
  Wallet,
  CheckCircle2,
  XCircle,
  Loader2,
} from 'lucide-react'
import { cn, formatRelativeTime } from '@/lib/utils'

// ============================================================================
// Types
// ============================================================================

type AttestationType = 'incident' | 'health' | 'remediation'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type AttestationStatus = 'verified' | 'pending' | 'failed'

interface Attestation {
  id: string
  type: AttestationType
  severity: Severity | null
  manifest_hash: string
  mitre_id: string | null
  family: string | null
  ioc_count: number
  slot: number
  tx_hash: string
  status: AttestationStatus
  timestamp: number
}

interface PublicProofsProps {
  attestations?: Attestation[]
  pagination?: {
    page: number
    per_page: number
    total: number
    total_pages: number
  }
}

// ============================================================================
// Constants
// ============================================================================

const TYPE_STYLES: Record<AttestationType, { icon: React.ElementType; label: string; colorVar: string; bgVar: string }> = {
  incident: { icon: AlertTriangle, label: 'Incident', colorVar: 'var(--crit)', bgVar: 'var(--crit-bg)' },
  health: { icon: HeartPulse, label: 'Health', colorVar: 'var(--emerald-400)', bgVar: 'var(--emerald-glow)' },
  remediation: { icon: Wrench, label: 'Remediation', colorVar: 'var(--med)', bgVar: 'var(--med-bg)' },
}

const SEVERITY_STYLES: Record<Severity, { label: string; colorVar: string; bgVar: string }> = {
  critical: { label: 'Critical', colorVar: 'var(--crit)', bgVar: 'var(--crit-bg)' },
  high: { label: 'High', colorVar: 'var(--high)', bgVar: 'var(--high-bg)' },
  medium: { label: 'Medium', colorVar: 'var(--med)', bgVar: 'var(--med-bg)' },
  low: { label: 'Low', colorVar: 'var(--low)', bgVar: 'var(--low-bg)' },
}

const STATUS_STYLES: Record<AttestationStatus, { label: string; colorVar: string; bgVar: string }> = {
  verified: { label: 'Verified', colorVar: 'var(--emerald-400)', bgVar: 'var(--emerald-glow)' },
  pending: { label: 'Pending', colorVar: 'var(--high)', bgVar: 'var(--high-bg)' },
  failed: { label: 'Failed', colorVar: 'var(--crit)', bgVar: 'var(--crit-bg)' },
}

const TIME_RANGES = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: 'all', label: 'All time' },
]

// On-chain fields (with checkmarks)
const ON_CHAIN_FIELDS = [
  'incident_hash',
  'manifest_hash',
  'severity_u8',
  'mitre_ids[]',
  'ioc_count',
  'ioc_types_bitmap',
  'ts_unix',
  'tenant_pubkey',
  'manifest_signature',
]

// Private fields (with lock icons)
const PRIVATE_FIELDS = [
  'hostname',
  'username',
  'domain_membership',
  'private_ipv4',
  'file_paths',
  'process_command_lines',
  'registry_values',
  'raw_pcap',
  'wallet_addresses',
  'customer_identity',
]

// ============================================================================
// Component
// ============================================================================

export default function PublicProofs({ attestations: initialAttestations, pagination: initialPagination }: PublicProofsProps) {
  const [attestations] = useState<Attestation[]>(initialAttestations || [])
  const [typeFilter, setTypeFilter] = useState<AttestationType | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [timeRange, setTimeRange] = useState('all')
  const [page, setPage] = useState(initialPagination?.page || 1)
  const [perPage] = useState(initialPagination?.per_page || 10)

  // Compute counts
  const typeCounts = useMemo(() => {
    const counts = { all: 0, incident: 0, health: 0, remediation: 0 }
    attestations.forEach(a => {
      counts.all++
      counts[a.type]++
    })
    return counts
  }, [attestations])

  // Filter attestations
  const filteredAttestations = useMemo(() => {
    let filtered = attestations

    if (typeFilter !== 'all') {
      filtered = filtered.filter(a => a.type === typeFilter)
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(a => a.severity === severityFilter)
    }

    if (timeRange !== 'all') {
      const now = Date.now()
      const ranges: Record<string, number> = {
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000,
      }
      const cutoff = now - (ranges[timeRange] || 0)
      filtered = filtered.filter(a => a.timestamp >= cutoff)
    }

    return filtered
  }, [attestations, typeFilter, severityFilter, timeRange])

  // Pagination
  const totalFiltered = filteredAttestations.length
  const totalPages = Math.ceil(totalFiltered / perPage)
  const paginatedAttestations = filteredAttestations.slice((page - 1) * perPage, page * perPage)

  const goToPage = (newPage: number) => {
    if (newPage < 1 || newPage > totalPages) return
    setPage(newPage)
  }

  const handleExportCSV = () => {
    const headers = ['Type', 'Severity', 'Manifest Hash', 'MITRE', 'Family', 'IOCs', 'Slot', 'TX Hash', 'Status', 'Timestamp']
    const rows = filteredAttestations.map(a => [
      a.type,
      a.severity || '',
      a.manifest_hash,
      a.mitre_id || '',
      a.family || '',
      a.ioc_count.toString(),
      a.slot.toString(),
      a.tx_hash,
      a.status,
      new Date(a.timestamp).toISOString(),
    ])
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `tamandua-public-proofs-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <MainLayout title="Public Proofs">
      <Head title="Public Proofs - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                <Shield className="h-8 w-8" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <h1 className="text-2xl font-semibold" style={{ color: 'var(--fg)' }}>Public proofs</h1>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Privacy-safe attestations anchored to Solana. Anyone can verify.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Anchored count badge */}
            <div className="badge-sentinel badge-sentinel-pill badge-sentinel-sol-cyan">
              <Database className="h-4 w-4" />
              {filteredAttestations.length} anchored
            </div>

            {/* Filters button */}
            <button className="btn-sentinel btn-sentinel-secondary">
              <Filter className="h-4 w-4" />
              Filters
            </button>

            {/* Export CSV button */}
            <button
              onClick={handleExportCSV}
              className="btn-sentinel btn-sentinel-secondary"
            >
              <Download className="h-4 w-4" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Main Grid */}
        <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
          {/* Left: Filters + Table */}
          <div className="space-y-4">
            {/* Type Tabs */}
            <div className="card-sentinel">
              <div className="flex flex-wrap items-center gap-4">
                {/* Type tabs */}
                <div className="flex items-center gap-2">
                  {(['all', 'incident', 'health', 'remediation'] as const).map(type => {
                    const isActive = typeFilter === type
                    const count = typeCounts[type]
                    const style = type !== 'all' ? TYPE_STYLES[type] : null

                    return (
                      <button
                        key={type}
                        onClick={() => { setTypeFilter(type); setPage(1) }}
                        className={cn(
                          'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                          isActive ? 'ring-1' : ''
                        )}
                        style={{
                          backgroundColor: isActive ? (style?.bgVar || 'var(--surface-2)') : 'transparent',
                          color: isActive ? (style?.colorVar || 'var(--fg)') : 'var(--muted)',
                          ringColor: isActive ? (style?.colorVar || 'var(--emerald-500)') : undefined,
                        }}
                      >
                        {style && <style.icon className="h-3.5 w-3.5" />}
                        {type === 'all' ? 'All' : style?.label}
                        <span
                          className="px-1.5 py-0.5 rounded text-xs"
                          style={{
                            backgroundColor: isActive ? 'rgba(255,255,255,0.15)' : 'var(--surface-2)',
                            color: isActive ? 'inherit' : 'var(--subtle)',
                          }}
                        >
                          {count}
                        </span>
                      </button>
                    )
                  })}
                </div>

                <div className="w-px h-6" style={{ backgroundColor: 'var(--hairline)' }} />

                {/* Severity tabs */}
                <div className="flex items-center gap-2">
                  {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => {
                    const isActive = severityFilter === sev
                    const style = sev !== 'all' ? SEVERITY_STYLES[sev] : null

                    return (
                      <button
                        key={sev}
                        onClick={() => { setSeverityFilter(sev); setPage(1) }}
                        className={cn(
                          'px-2.5 py-1 rounded text-xs font-medium transition-colors',
                          isActive ? 'ring-1' : ''
                        )}
                        style={{
                          backgroundColor: isActive ? (style?.bgVar || 'var(--surface-2)') : 'transparent',
                          color: isActive ? (style?.colorVar || 'var(--fg)') : 'var(--muted)',
                          ringColor: isActive ? (style?.colorVar || 'var(--emerald-500)') : undefined,
                        }}
                      >
                        {sev === 'all' ? 'All severity' : style?.label}
                      </button>
                    )
                  })}
                </div>

                <div className="w-px h-6" style={{ backgroundColor: 'var(--hairline)' }} />

                {/* Time range */}
                <div className="flex items-center gap-1">
                  {TIME_RANGES.map(range => {
                    const isActive = timeRange === range.value
                    return (
                      <button
                        key={range.value}
                        onClick={() => { setTimeRange(range.value); setPage(1) }}
                        className={cn(
                          'px-2.5 py-1 rounded text-xs font-medium transition-colors'
                        )}
                        style={{
                          backgroundColor: isActive ? 'var(--surface-2)' : 'transparent',
                          color: isActive ? 'var(--fg)' : 'var(--muted)',
                        }}
                      >
                        {range.label}
                      </button>
                    )
                  })}
                </div>

                <div className="flex-1" />

                {/* Privacy badge */}
                <div
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium"
                  style={{
                    backgroundColor: 'var(--emerald-glow)',
                    color: 'var(--emerald-400)',
                  }}
                >
                  <Lock className="h-3.5 w-3.5" />
                  No sensitive data exposed
                </div>
              </div>
            </div>

            {/* Table */}
            <div className="card-sentinel" style={{ padding: 0 }}>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Type</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Severity</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Manifest Hash</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>MITRE / Family</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>IOCs</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Slot</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>TX</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Status</th>
                      <th className="text-left p-4 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--muted)' }}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedAttestations.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="p-12 text-center" style={{ color: 'var(--muted)' }}>
                          <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p className="text-lg">No attestations found</p>
                          <p className="text-sm">Try adjusting your filters.</p>
                        </td>
                      </tr>
                    ) : (
                      paginatedAttestations.map(attestation => {
                        const typeStyle = TYPE_STYLES[attestation.type]
                        const TypeIcon = typeStyle.icon
                        const sevStyle = attestation.severity ? SEVERITY_STYLES[attestation.severity] : null
                        const statusStyle = STATUS_STYLES[attestation.status]

                        return (
                          <tr
                            key={attestation.id}
                            className="transition-colors"
                            style={{ borderBottom: '1px solid var(--hairline)' }}
                            onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--surface-2)' }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
                          >
                            {/* Type */}
                            <td className="p-4">
                              <div
                                className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium"
                                style={{
                                  backgroundColor: typeStyle.bgVar,
                                  color: typeStyle.colorVar,
                                }}
                              >
                                <TypeIcon className="h-3 w-3" />
                                {typeStyle.label}
                              </div>
                            </td>

                            {/* Severity */}
                            <td className="p-4">
                              {sevStyle ? (
                                <div
                                  className="inline-flex items-center px-2 py-1 rounded text-xs font-medium"
                                  style={{
                                    backgroundColor: sevStyle.bgVar,
                                    color: sevStyle.colorVar,
                                  }}
                                >
                                  {sevStyle.label}
                                </div>
                              ) : (
                                <span style={{ color: 'var(--subtle)' }}>-</span>
                              )}
                            </td>

                            {/* Manifest Hash */}
                            <td className="p-4">
                              <code
                                className="text-xs font-mono"
                                style={{ color: 'var(--fg-2)' }}
                                title={attestation.manifest_hash}
                              >
                                {attestation.manifest_hash.slice(0, 14)}...
                              </code>
                            </td>

                            {/* MITRE / Family */}
                            <td className="p-4">
                              {attestation.mitre_id || attestation.family ? (
                                <div className="text-sm" style={{ color: 'var(--fg-2)' }}>
                                  {attestation.mitre_id && (
                                    <span className="font-mono" style={{ color: 'var(--sol-cyan)' }}>
                                      {attestation.mitre_id}
                                    </span>
                                  )}
                                  {attestation.mitre_id && attestation.family && ' '}
                                  {attestation.family && (
                                    <span>{attestation.family}</span>
                                  )}
                                </div>
                              ) : (
                                <span style={{ color: 'var(--subtle)' }}>-</span>
                              )}
                            </td>

                            {/* IOCs */}
                            <td className="p-4">
                              <span className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>
                                {attestation.ioc_count}
                              </span>
                            </td>

                            {/* Slot */}
                            <td className="p-4">
                              <span className="text-sm font-mono" style={{ color: 'var(--muted)' }}>
                                {attestation.slot.toLocaleString()}
                              </span>
                            </td>

                            {/* TX */}
                            <td className="p-4">
                              <a
                                href={`https://solscan.io/tx/${attestation.tx_hash}?cluster=devnet`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-xs font-mono transition-colors"
                                style={{ color: 'var(--sol-cyan)' }}
                                onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--emerald-200)' }}
                                onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--sol-cyan)' }}
                              >
                                {attestation.tx_hash.slice(0, 8)}...
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            </td>

                            {/* Status */}
                            <td className="p-4">
                              <div
                                className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium"
                                style={{
                                  backgroundColor: statusStyle.bgVar,
                                  color: statusStyle.colorVar,
                                }}
                              >
                                <span
                                  className="h-1.5 w-1.5 rounded-full"
                                  style={{ backgroundColor: statusStyle.colorVar }}
                                />
                                {statusStyle.label}
                              </div>
                            </td>

                            {/* Time */}
                            <td className="p-4">
                              <span className="text-sm" style={{ color: 'var(--muted)' }}>
                                {formatRelativeTime(attestation.timestamp)}
                              </span>
                            </td>
                          </tr>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div
                className="flex items-center justify-between p-4"
                style={{ borderTop: '1px solid var(--hairline)' }}
              >
                <span className="text-sm" style={{ color: 'var(--muted)' }}>
                  {paginatedAttestations.length} of {totalFiltered.toLocaleString()} attestations
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => goToPage(page - 1)}
                    disabled={page <= 1}
                    className={cn(
                      'btn-sentinel btn-sentinel-sm',
                      page <= 1 ? 'btn-sentinel-ghost opacity-50 cursor-not-allowed' : 'btn-sentinel-secondary'
                    )}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Prev
                  </button>
                  <button
                    onClick={() => goToPage(page + 1)}
                    disabled={page >= totalPages}
                    className={cn(
                      'btn-sentinel btn-sentinel-sm',
                      page >= totalPages ? 'btn-sentinel-ghost opacity-50 cursor-not-allowed' : 'btn-sentinel-secondary'
                    )}
                  >
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Right Sidebar */}
          <div className="space-y-4">
            {/* What goes on-chain */}
            <div className="card-sentinel">
              <div className="card-sentinel-header">
                <h3 className="card-sentinel-title">What goes on-chain</h3>
              </div>
              <div className="mt-3 space-y-2">
                {ON_CHAIN_FIELDS.map(field => (
                  <div key={field} className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--emerald-400)' }} />
                    <code className="text-xs font-mono" style={{ color: 'var(--fg-2)' }}>{field}</code>
                  </div>
                ))}
              </div>
            </div>

            {/* What never leaves your server */}
            <div className="card-sentinel">
              <div className="card-sentinel-header">
                <h3 className="card-sentinel-title">What never leaves your server</h3>
              </div>
              <div className="mt-3 space-y-2">
                {PRIVATE_FIELDS.map(field => (
                  <div key={field} className="flex items-center gap-2">
                    <Lock className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--crit)' }} />
                    <code className="text-xs font-mono" style={{ color: 'var(--muted)' }}>{field}</code>
                  </div>
                ))}
              </div>
            </div>

            {/* Verifying yourself */}
            <div className="card-sentinel">
              <div className="card-sentinel-header">
                <h3 className="card-sentinel-title">Verifying yourself</h3>
              </div>
              <p className="mt-3 text-sm" style={{ color: 'var(--muted)' }}>
                Download the incident bundle and verify the on-chain attestation matches your local data.
              </p>
              <div
                className="mt-4 p-3 rounded-lg overflow-x-auto"
                style={{
                  backgroundColor: 'var(--bg)',
                  border: '1px solid var(--hairline)',
                }}
              >
                <pre className="text-xs font-mono" style={{ color: 'var(--fg-2)' }}>
                  <code>{`$ tamandua verify \\
    --bundle ./incident.json \\
    --tx 4m23pK...aNw9`}</code>
                </pre>
                <pre className="mt-2 text-xs font-mono" style={{ color: 'var(--emerald-400)' }}>
                  <code>{`✓ manifest matches
✓ tenant signature valid
✓ slot 287,401,933`}</code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

