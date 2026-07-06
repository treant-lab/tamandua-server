import { Head, router } from '@inertiajs/react'
import { useEffect, useState } from 'react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  AlertTriangle,
  Server,
  Shield,
  Monitor,
  Clock,
  ChevronRight,
  Activity,
  Bug,
  Lightbulb,
  Tag,
  Wifi,
  WifiOff,
  CheckCircle,
  XCircle,
  FileText,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useTenantFetch } from '@/hooks/useTenantFetch'

interface Asset {
  id: string
  hostname: string
  ipAddress: string
  os: string
  osVersion: string
  platform: string
  agentId: string
  agentStatus: 'online' | 'offline' | 'degraded'
  riskScore: number
  criticality: string
  tags: string[]
  lastSeen: string
  enrolledAt: string
  securityPosture?: Record<string, unknown>
}

interface Vulnerability {
  id: string
  cveId: string
  cve_id?: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvssScore: number
  cvss_score?: number
  status: string
  discoveredAt: string
  remediation: string
  affectedComponent: string
  affected_component?: string
  affectedSoftwareName?: string
  affected_software_name?: string
  affectedSoftwareVersion?: string
  affected_software_version?: string
  confidence?: number
}

interface LicenseCompliance {
  asset_id: string
  hostname: string
  generated_at: string
  summary?: {
    total_software?: number
    with_license_metadata?: number
    without_license_metadata?: number
    non_permissive_count?: number
    by_license_risk?: Record<string, number>
    data_quality?: {
      license_metadata_coverage?: number
      note?: string
    }
  }
  findings?: Array<{
    type: string
    severity: string
    license_risk: string
    message: string
    software?: {
      name?: string
      version?: string
      vendor?: string
      license?: string
    }
  }>
  caveat?: string
}

interface AssetDetailPageProps {
  assetId: string
  asset: Asset | null
  vulnerabilities: Vulnerability[]
  riskScore: number
  riskFactors?: string[]
  recommendations?: string[]
  securityPosture?: Record<string, unknown>
  error?: string
}

const getSeverityColor = (severity?: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    default: return 'bg-[var(--surface-alt)]/20 text-[var(--muted)] border-[var(--border)]'
  }
}

const getRiskScoreColor = (score: number) => {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

const getRiskScoreBg = (score: number) => {
  if (score >= 80) return 'bg-red-500/20 border-red-500/30'
  if (score >= 60) return 'bg-orange-500/20 border-orange-500/30'
  if (score >= 40) return 'bg-yellow-500/20 border-yellow-500/30'
  return 'bg-green-500/20 border-green-500/30'
}

const getAgentStatusConfig = (status?: string) => {
  switch (status) {
    case 'online': return { icon: Wifi, color: 'text-green-400 bg-green-400/10', label: 'Online' }
    case 'offline': return { icon: WifiOff, color: 'text-red-400 bg-red-400/10', label: 'Offline' }
    case 'degraded': return { icon: Activity, color: 'text-yellow-400 bg-yellow-400/10', label: 'Degraded' }
    default: return { icon: WifiOff, color: 'text-[var(--muted)] bg-[var(--surface-alt)]', label: 'Unknown' }
  }
}

const getLicenseRiskColor = (risk?: string) => {
  switch (risk) {
    case 'restricted':
    case 'unlicensed':
      return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
    case 'commercial':
    case 'copyleft':
      return 'bg-blue-500/20 text-blue-300 border-blue-500/30'
    case 'permissive':
      return 'bg-green-500/20 text-green-300 border-green-500/30'
    case 'unknown':
    default:
      return 'bg-[var(--surface-alt)] text-[var(--muted)] border-[var(--border)]'
  }
}

const formatPercent = (value?: number) => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '0%'
  return `${Math.round(value * 100)}%`
}

function LicenseStat({ label, value }: { label: string; value?: number | string }) {
  return (
    <div className="rounded-lg bg-[var(--surface-alt)] p-3">
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p className="mt-1 text-xl font-semibold text-[var(--fg)]">
        {typeof value === 'number' ? value.toLocaleString() : value || '0'}
      </p>
    </div>
  )
}

export default function AssetDetail({
  assetId,
  asset,
  vulnerabilities,
  riskScore,
  riskFactors,
  recommendations,
  securityPosture,
  error,
}: AssetDetailPageProps) {
  const { tenantGet } = useTenantFetch()
  const [licenseCompliance, setLicenseCompliance] = useState<LicenseCompliance | null>(null)
  const [licenseLoading, setLicenseLoading] = useState(false)
  const [licenseError, setLicenseError] = useState<string | null>(null)

  const formatDate = (dateString?: string | null) => {
    if (!dateString) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(dateString))
  }

  useEffect(() => {
    if (!assetId || !asset) return

    let cancelled = false
    const fetchLicenseCompliance = async () => {
      setLicenseLoading(true)
      setLicenseError(null)
      try {
        const response = await tenantGet<{ data: LicenseCompliance }>(`/api/v1/assets/${assetId}/license-compliance`)
        if (!cancelled) {
          setLicenseCompliance(response.data)
        }
      } catch (error) {
        logger.error('Failed to fetch asset license compliance metadata:', error)
        if (!cancelled) {
          setLicenseError(error instanceof Error ? error.message : 'Failed to load license metadata')
          setLicenseCompliance(null)
        }
      } finally {
        if (!cancelled) setLicenseLoading(false)
      }
    }

    fetchLicenseCompliance()

    return () => {
      cancelled = true
    }
  }, [assetId, asset, tenantGet])

  if (error || !asset) {
    return (
      <MainLayout title="Asset Detail">
        <Head title="Asset Detail - Tamandua EDR" />
        <div className="space-y-6">
          <button
            onClick={() => router.visit('/app/assets')}
            className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Assets
          </button>
          <div className="card-sentinel rounded-xl p-12 text-center">
            <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-[var(--muted)]" />
            <p className="text-lg text-[var(--muted)]">{error || 'Asset not found'}</p>
            <p className="text-sm text-[var(--muted)] mt-1">
              The requested asset could not be loaded.
            </p>
          </div>
        </div>
      </MainLayout>
    )
  }

  const agentStatus = getAgentStatusConfig(asset.agentStatus)
  const AgentStatusIcon = agentStatus.icon
  const posture = securityPosture || asset.securityPosture

  return (
    <MainLayout title="Asset Detail">
      <Head title={`${asset.hostname} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Back link */}
        <button
          onClick={() => router.visit('/app/assets')}
          className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Assets
        </button>

        {/* Asset Header */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-[var(--surface-alt)]">
                <Server className="h-6 w-6 text-[var(--fg)]" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-xl font-semibold text-[var(--fg)]">{asset.hostname}</h1>
                  <span className={cn('flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium', agentStatus.color)}>
                    <AgentStatusIcon className="h-3.5 w-3.5" />
                    {agentStatus.label}
                  </span>
                  {asset.criticality && (
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400 border border-purple-500/30">
                      {asset.criticality}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4 text-sm text-[var(--muted)] mt-1">
                  <span>{asset.ipAddress}</span>
                  <span>{asset.os} {asset.osVersion}</span>
                  <span>{asset.platform}</span>
                </div>
                <div className="flex items-center gap-4 text-xs text-[var(--muted)] mt-2">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Last seen: {formatDate(asset.lastSeen)}
                  </span>
                  <span>Enrolled: {formatDate(asset.enrolledAt)}</span>
                  <span className="font-mono">Agent: {asset.agentId.substring(0, 8)}...</span>
                </div>
              </div>
            </div>

            {/* Risk Score */}
            <div className={cn('p-4 rounded-xl border text-center', getRiskScoreBg(riskScore))}>
              <p className="text-xs text-[var(--muted)]">Risk Score</p>
              <p className={cn('text-3xl font-bold', getRiskScoreColor(riskScore))}>{riskScore}</p>
            </div>
          </div>

          {/* Tags */}
          {asset.tags && asset.tags.length > 0 && (
            <div className="mt-4 flex items-center gap-2">
              <Tag className="h-4 w-4 text-[var(--muted)]" />
              <div className="flex flex-wrap gap-1">
                {asset.tags.map((tag, i) => (
                  <span key={i} className="px-2 py-0.5 bg-[var(--surface-alt)] rounded text-xs text-[var(--fg)]">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Security Posture */}
        {posture && Object.keys(posture).length > 0 && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Security Posture
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(posture).map(([key, value]) => (
                <div key={key} className="bg-[var(--surface-alt)] rounded-lg p-3">
                  <p className="text-xs text-[var(--muted)] capitalize">{key.replace(/_/g, ' ')}</p>
                  <p className="text-sm font-medium text-[var(--fg)] mt-0.5">
                    {typeof value === 'boolean' ? (
                      value ? (
                        <span className="flex items-center gap-1 text-green-400">
                          <CheckCircle className="h-3.5 w-3.5" /> Yes
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-red-400">
                          <XCircle className="h-3.5 w-3.5" /> No
                        </span>
                      )
                    ) : (
                      String(value)
                    )}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Vulnerabilities */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Bug className="h-5 w-5 text-[var(--muted)]" />
                  Vulnerabilities ({vulnerabilities.length})
                </h2>
                <p className="text-xs mt-1 text-[var(--muted)]">
                  CVE catalog entries are shown here when matched to this asset through agent software inventory.
                </p>
              </div>
              {vulnerabilities.length > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-blue-500/10 text-blue-300 border border-blue-500/30">
                  <Monitor className="h-3.5 w-3.5" />
                  Inventory matched
                </span>
              )}
            </div>
          </div>
          {vulnerabilities.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Shield className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No inventory-matched CVEs for this asset</p>
              <p className="text-xs mt-2">
                Coverage depends on catalog sync, agent software inventory, and matcher confidence.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">CVE ID</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Title</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Severity</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">CVSS</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Status</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Component</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Remediation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {vulnerabilities.map((vuln) => {
                    const cveId = vuln.cveId || vuln.cve_id || vuln.id
                    const cvssScore = Number(vuln.cvssScore ?? vuln.cvss_score ?? 0)
                    const softwareName = vuln.affectedSoftwareName || vuln.affected_software_name
                    const softwareVersion = vuln.affectedSoftwareVersion || vuln.affected_software_version
                    const component = softwareName
                      ? `${softwareName}${softwareVersion ? ` ${softwareVersion}` : ''}`
                      : vuln.affectedComponent || vuln.affected_component || '-'

                    return (
                    <tr key={vuln.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                      <td className="px-4 py-3">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-blue-400 hover:text-blue-300 font-mono"
                        >
                          {cveId}
                        </a>
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--fg)] max-w-[250px] truncate">{vuln.title}</td>
                      <td className="px-4 py-3">
                        <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getSeverityColor(vuln.severity))}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn('text-sm font-bold', getRiskScoreColor(cvssScore * 10))}>
                          {cvssScore ? cvssScore.toFixed(1) : 'N/A'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          'px-2 py-0.5 rounded text-xs font-medium',
                          vuln.status === 'patched' || vuln.status === 'resolved'
                            ? 'bg-green-500/20 text-green-400'
                            : vuln.status === 'in_progress'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-red-500/20 text-red-400'
                        )}>
                          {vuln.status.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-sm text-[var(--fg)]">{component}</div>
                        {softwareName && (
                          <div className="text-xs text-[var(--muted)]">from software inventory</div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--muted)] max-w-[200px] truncate">{vuln.remediation}</td>
                    </tr>
                  )})}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* License Compliance Metadata */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <FileText className="h-5 w-5 text-[var(--muted)]" />
                  License Metadata
                </h2>
                <p className="text-xs mt-1 text-[var(--muted)]">
                  Metadata-only review from installed software inventory. This is not a legal compliance determination.
                </p>
              </div>
              {licenseCompliance?.generated_at && (
                <span className="text-xs text-[var(--muted)]">Generated {formatDate(licenseCompliance.generated_at)}</span>
              )}
            </div>
          </div>
          {licenseLoading ? (
            <div className="p-6 text-sm text-[var(--muted)]">Loading license metadata...</div>
          ) : licenseError ? (
            <div className="p-6 text-sm text-[var(--muted)]">
              License metadata is unavailable: {licenseError}
            </div>
          ) : !licenseCompliance ? (
            <div className="p-6 text-sm text-[var(--muted)]">
              No license metadata analysis is available for this asset yet.
            </div>
          ) : (
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <LicenseStat label="Software" value={licenseCompliance.summary?.total_software} />
                <LicenseStat label="With metadata" value={licenseCompliance.summary?.with_license_metadata} />
                <LicenseStat label="Needs review" value={licenseCompliance.summary?.non_permissive_count} />
                <LicenseStat
                  label="Coverage"
                  value={formatPercent(licenseCompliance.summary?.data_quality?.license_metadata_coverage)}
                />
              </div>

              <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-alt)] p-3 text-xs text-[var(--muted)]">
                {licenseCompliance.caveat || licenseCompliance.summary?.data_quality?.note ||
                  'License risk is classified only from inventory-provided license metadata.'}
              </div>

              {licenseCompliance.findings && licenseCompliance.findings.length > 0 ? (
                <div className="space-y-2">
                  {licenseCompliance.findings.slice(0, 8).map((finding, index) => (
                    <div key={`${finding.software?.name || 'software'}-${index}`} className="flex items-start justify-between gap-3 rounded-lg bg-[var(--surface-alt)] p-3">
                      <div>
                        <div className="text-sm text-[var(--fg)]">
                          {finding.software?.name || 'Unknown software'}
                          {finding.software?.version && (
                            <span className="text-[var(--muted)]"> {finding.software.version}</span>
                          )}
                        </div>
                        <p className="text-xs mt-1 text-[var(--muted)]">{finding.message}</p>
                      </div>
                      <span className={cn('px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap', getLicenseRiskColor(finding.license_risk))}>
                        {finding.license_risk.replace(/_/g, ' ')}
                      </span>
                    </div>
                  ))}
                  {licenseCompliance.findings.length > 8 && (
                    <p className="text-xs text-[var(--muted)]">+{licenseCompliance.findings.length - 8} more metadata findings</p>
                  )}
                </div>
              ) : (
                <div className="p-4 text-center text-sm text-[var(--muted)]">
                  No non-permissive findings in available license metadata.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Risk Factors */}
        {riskFactors && riskFactors.length > 0 && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-3 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Risk Factors
            </h2>
            <div className="space-y-2">
              {riskFactors.map((factor, i) => (
                <div key={i} className="flex items-start gap-3 bg-[var(--surface-alt)] rounded-lg p-3">
                  <AlertTriangle className="h-4 w-4 text-orange-400 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-[var(--fg)]">{typeof factor === 'string' ? factor : JSON.stringify(factor)}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {recommendations && recommendations.length > 0 && (
          <div className="card-sentinel rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide mb-3 flex items-center gap-2">
              <Lightbulb className="h-4 w-4" />
              Recommendations
            </h2>
            <div className="space-y-2">
              {recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-3 bg-[var(--surface-alt)] rounded-lg p-3">
                  <ChevronRight className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-[var(--fg)]">{typeof rec === 'string' ? rec : JSON.stringify(rec)}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
