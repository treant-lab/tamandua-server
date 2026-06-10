import { Head, router } from '@inertiajs/react'
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
} from 'lucide-react'
import { cn } from '@/lib/utils'

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
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvssScore: number
  status: string
  discoveredAt: string
  remediation: string
  affectedComponent: string
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
  const formatDate = (dateString?: string | null) => {
    if (!dateString) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(dateString))
  }

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
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Bug className="h-5 w-5 text-[var(--muted)]" />
              Vulnerabilities ({vulnerabilities.length})
            </h2>
          </div>
          {vulnerabilities.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Shield className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No vulnerabilities detected</p>
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
                  {vulnerabilities.map((vuln) => (
                    <tr key={vuln.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                      <td className="px-4 py-3">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-blue-400 hover:text-blue-300 font-mono"
                        >
                          {vuln.cveId}
                        </a>
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--fg)] max-w-[250px] truncate">{vuln.title}</td>
                      <td className="px-4 py-3">
                        <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', getSeverityColor(vuln.severity))}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn('text-sm font-bold', getRiskScoreColor(vuln.cvssScore * 10))}>
                          {vuln.cvssScore.toFixed(1)}
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
                      <td className="px-4 py-3 text-sm text-[var(--muted)]">{vuln.affectedComponent}</td>
                      <td className="px-4 py-3 text-sm text-[var(--muted)] max-w-[200px] truncate">{vuln.remediation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
