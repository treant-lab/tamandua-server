import { useState } from 'react'
import { Head, router } from '@inertiajs/react'
import axios from 'axios'
import { toast } from 'sonner'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Target,
  Brain,
  AlertTriangle,
  Server,
  Database,
  MessageSquare,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink,
  Loader2,
} from 'lucide-react'
import { cn, safeCapitalize } from '@/lib/utils'

// Types
interface AIAsset {
  id: string
  name: string
  type: 'llm' | 'ml_model' | 'ai_agent' | 'vector_db' | 'embedding_service'
  status: 'healthy' | 'at_risk' | 'compromised'
  riskScore: number
  owner: string
  department: string
  lastAssessed: string
  vulnerabilities: number
}

interface AttackVector {
  id: string
  name: string
  category: 'prompt_injection' | 'model_theft' | 'data_poisoning' | 'jailbreak' | 'extraction'
  severity: 'critical' | 'high' | 'medium' | 'low'
  affectedAssets: number
  mitigationStatus: 'mitigated' | 'partial' | 'unmitigated'
  description: string
}

interface VulnerabilityAssessment {
  id: string
  assetName: string
  assessmentDate: string
  status: 'completed' | 'in_progress' | 'scheduled' | 'overdue'
  findings: number
  criticalFindings: number
}

interface Recommendation {
  id: string
  title: string
  description: string
  priority: 'critical' | 'high' | 'medium' | 'low'
}

interface AttackSurfaceData {
  assets: AIAsset[]
  attackVectors: AttackVector[]
  assessments: VulnerabilityAssessment[]
}

interface AIAttackSurfaceProps {
  attackSurface?: Partial<AttackSurfaceData> & { isExampleData?: boolean }
  recommendations?: Recommendation[]
}

export default function AttackSurface({ attackSurface, recommendations: _recommendations = [] }: AIAttackSurfaceProps) {
  const assets = attackSurface?.assets || []
  const attackVectors = attackSurface?.attackVectors || []
  const assessments = attackSurface?.assessments || []
  const hasObservedAIAssets = assets.length > 0 || attackVectors.length > 0 || assessments.length > 0

  const totalAssets = assets.length
  const atRiskAssets = assets.filter(a => a.status === 'at_risk').length
  const compromisedAssets = assets.filter(a => a.status === 'compromised').length
  const avgRiskScore = totalAssets > 0
    ? Math.round(assets.reduce((acc, a) => acc + a.riskScore, 0) / totalAssets)
    : 0

  const [loading, setLoading] = useState<string | null>(null)

  const handleScheduleAssessment = async () => {
    if (!hasObservedAIAssets) {
      toast.info('No AI telemetry available', {
        description: 'Assessment runs after AI assets or runtime events are observed.',
      })
      return
    }

    setLoading('schedule')
    try {
      await axios.post('/api/v1/ai-security/attack-surface/assess')
      toast.success('Assessment completed', {
        description: 'Attack surface analysis ran against the current observed AI telemetry.',
      })
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to schedule assessment')
    } finally {
      setLoading(null)
    }
  }

  return (
    <MainLayout title="AI Attack Surface">
      <Head title="AI Attack Surface - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total AI Assets"
            value={totalAssets}
            icon={Brain}
            color="primary"
          />
          <StatCard
            title="At Risk"
            value={atRiskAssets}
            icon={AlertTriangle}
            color="warning"
          />
          <StatCard
            title="Compromised"
            value={compromisedAssets}
            icon={XCircle}
            color="danger"
          />
          <StatCard
            title="Avg Risk Score"
            value={avgRiskScore}
            subtitle="/100"
            icon={Target}
            color={avgRiskScore > 60 ? 'danger' : avgRiskScore > 40 ? 'warning' : 'primary'}
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* AI Assets Table */}
          <div className="lg:col-span-2 card-sentinel rounded-xl">
            <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>AI/ML Assets</h2>
              <button
                onClick={() => router.visit('/app/assets')}
                className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1"
              >
                View All <ExternalLink className="h-3 w-3" />
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Asset</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Type</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk Score</th>
                    <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Vulns</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <AssetTypeIcon type={asset.type} />
                          <div>
                            <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{asset.name}</div>
                            <div className="text-xs" style={{ color: 'var(--muted)' }}>{asset.department}</div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className="text-sm capitalize" style={{ color: 'var(--fg-2)' }}>
                          {asset.type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="p-4">
                        <StatusBadge status={asset.status} />
                      </td>
                      <td className="p-4">
                        <RiskScoreBadge score={asset.riskScore} />
                      </td>
                      <td className="p-4">
                        <span className={cn(
                          'text-sm font-medium',
                          asset.vulnerabilities > 5 ? 'text-red-400' :
                          asset.vulnerabilities > 2 ? 'text-yellow-400' : ''
                        )} style={asset.vulnerabilities <= 2 ? { color: 'var(--muted)' } : undefined}>
                          {asset.vulnerabilities}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {assets.length === 0 && (
                <EmptyTableState
                  title="No AI/ML assets observed"
                  description="Assets will appear here after agents report AI runtime, model, vector database, or embedding service activity."
                />
              )}
            </div>
          </div>

          {/* Attack Vectors */}
          <div className="card-sentinel rounded-xl">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Attack Vectors</h2>
            </div>
            <div className="p-4 space-y-3">
              {attackVectors.map((vector) => (
                <AttackVectorCard key={vector.id} vector={vector} />
              ))}
              {attackVectors.length === 0 && (
                <EmptyInlineState
                  title="No attack vectors detected"
                  description="Prompt injection, model theft, data poisoning, jailbreak, and extraction findings will appear here when observed."
                />
              )}
            </div>
          </div>
        </div>

        {!hasObservedAIAssets && (
          <div className="card-sentinel rounded-xl p-5">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 mt-0.5" style={{ color: 'var(--med)' }} />
              <div>
                <p className="font-medium" style={{ color: 'var(--fg)' }}>Waiting for real AI security telemetry</p>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                  This page stays empty until real AI asset or runtime telemetry is collected.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerability Assessments */}
        <div className="card-sentinel rounded-xl">
          <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Vulnerability Assessments</h2>
            <button
              onClick={handleScheduleAssessment}
              disabled={loading === 'schedule' || !hasObservedAIAssets}
              className="text-sm bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
              title={!hasObservedAIAssets ? 'Waiting for real AI runtime telemetry' : undefined}
            >
              {loading === 'schedule' ? 'Running...' : hasObservedAIAssets ? 'Run Assessment' : 'Waiting for telemetry'}
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Asset</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Date</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Findings</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Critical</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((assessment) => (
                  <tr key={assessment.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                    <td className="p-4 text-sm" style={{ color: 'var(--fg)' }}>{assessment.assetName}</td>
                    <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                      {new Date(assessment.assessmentDate).toLocaleDateString()}
                    </td>
                    <td className="p-4">
                      <AssessmentStatusBadge status={assessment.status} />
                    </td>
                    <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{assessment.findings}</td>
                    <td className="p-4">
                      <span className={cn(
                        'text-sm font-medium',
                        assessment.criticalFindings > 0 ? 'text-red-400' : ''
                      )} style={assessment.criticalFindings === 0 ? { color: 'var(--muted)' } : undefined}>
                        {assessment.criticalFindings}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {assessments.length === 0 && (
              <EmptyTableState
                title="No assessments recorded"
                description="Run an assessment after AI assets are observed to populate findings and report history."
              />
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

function EmptyTableState({ title, description }: { title: string; description: string }) {
  return (
    <div className="px-6 py-10 text-center" style={{ color: 'var(--muted)' }}>
      <p className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>{title}</p>
      <p className="text-xs mt-1 max-w-md mx-auto" style={{ color: 'var(--subtle)' }}>{description}</p>
    </div>
  )
}

function EmptyInlineState({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-lg border p-4 text-sm" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-2)' }}>
      <p className="font-medium" style={{ color: 'var(--fg-2)' }}>{title}</p>
      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{description}</p>
    </div>
  )
}

// Helper Components
interface StatCardProps {
  title: string
  value: number
  subtitle?: string
  icon: React.ElementType
  color: 'primary' | 'danger' | 'warning'
}

function StatCard({ title, value, subtitle, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-primary-600/20 text-primary-400',
    danger: 'bg-red-500/20 text-red-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div className={cn('p-2 rounded-lg', colorClasses[color])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-4">
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
          {subtitle && <span className="text-sm" style={{ color: 'var(--subtle)' }}>{subtitle}</span>}
        </div>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
      </div>
    </div>
  )
}

function AssetTypeIcon({ type }: { type: AIAsset['type'] }) {
  const iconMap = {
    llm: MessageSquare,
    ml_model: Brain,
    ai_agent: Target,
    vector_db: Database,
    embedding_service: Server,
  }
  const Icon = iconMap[type]
  return (
    <div className="p-2 rounded-lg" style={{ background: 'var(--surface-2)' }}>
      <Icon className="h-4 w-4 text-primary-400" />
    </div>
  )
}

function StatusBadge({ status }: { status: AIAsset['status'] }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium',
      status === 'healthy' && 'bg-green-500/20 text-green-400',
      status === 'at_risk' && 'bg-yellow-500/20 text-yellow-400',
      status === 'compromised' && 'bg-red-500/20 text-red-400'
    )}>
      <span className={cn(
        'h-1.5 w-1.5 rounded-full',
        status === 'healthy' && 'bg-green-400',
        status === 'at_risk' && 'bg-yellow-400',
        status === 'compromised' && 'bg-red-400'
      )} />
      {status === 'healthy' ? 'Healthy' : status === 'at_risk' ? 'At Risk' : 'Compromised'}
    </span>
  )
}

function RiskScoreBadge({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
        <div
          className={cn(
            'h-full rounded-full',
            score > 70 ? 'bg-red-500' : score > 40 ? 'bg-yellow-500' : 'bg-green-500'
          )}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={cn(
        'text-sm font-medium',
        score > 70 ? 'text-red-400' : score > 40 ? 'text-yellow-400' : 'text-green-400'
      )}>
        {score}
      </span>
    </div>
  )
}

function AttackVectorCard({ vector }: { vector: AttackVector }) {
  const severityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  const mitigationIcons = {
    mitigated: <CheckCircle className="h-4 w-4 text-green-400" />,
    partial: <Clock className="h-4 w-4 text-yellow-400" />,
    unmitigated: <XCircle className="h-4 w-4 text-red-400" />,
  }

  return (
    <div className={cn(
      'p-3 rounded-lg border',
      severityColors[vector.severity]
    )}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{vector.name}</span>
            <span className="text-xs uppercase px-1.5 py-0.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
              {vector.severity}
            </span>
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{vector.description}</p>
        </div>
        {mitigationIcons[vector.mitigationStatus]}
      </div>
      <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--muted)' }}>
        <span>{vector.affectedAssets} affected assets</span>
        <span className="capitalize">{vector.mitigationStatus.replace('_', ' ')}</span>
      </div>
    </div>
  )
}

function AssessmentStatusBadge({ status }: { status: VulnerabilityAssessment['status'] }) {
  const statusConfig = {
    completed: { color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
    in_progress: { color: 'bg-blue-500/20 text-blue-400', icon: Clock },
    scheduled: { color: 'bg-[var(--surface-2)] text-[var(--muted)]', icon: Clock },
    overdue: { color: 'bg-red-500/20 text-red-400', icon: AlertTriangle },
  }
  const config = statusConfig[status]
  const Icon = config.icon

  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium',
      config.color
    )}>
      <Icon className="h-3 w-3" />
      {safeCapitalize(status?.replace('_', ' '))}
    </span>
  )
}
