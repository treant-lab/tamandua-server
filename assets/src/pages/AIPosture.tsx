import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  RefreshCw,
  ChevronRight,
  Info,
  Loader2,
  Shield,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState } from 'react'

// Types
interface ComplianceFramework {
  id: string
  name: string
  description?: string
  totalControls?: number
  passedControls?: number
  failedControls?: number
  inProgressControls?: number
  controlsTotal?: number
  controlsPassed?: number
  score?: number
  status?: string
  lastAssessed?: string
}

interface SecurityControl {
  id: string
  name: string
  category: string
  status: 'passed' | 'failed' | 'in_progress' | 'not_applicable' | 'not_implemented'
  priority?: 'critical' | 'high' | 'medium' | 'low'
  severity?: 'critical' | 'high' | 'medium' | 'low'
  framework?: string
  description: string
  lastChecked: string
  remediationSteps?: string[]
}

interface Recommendation {
  id: string
  title: string
  description: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  effort: 'low' | 'medium' | 'high'
  impact: 'low' | 'medium' | 'high'
  category: string
}

interface AIAgent {
  id: string
  name: string
  status: 'active' | 'inactive' | 'error'
  lastActive: string
}

interface ComplianceStatus {
  frameworks: ComplianceFramework[]
  controls: SecurityControl[]
}

interface PostureMetrics {
  postureScore?: number
  scoreTrend?: number
  passedControls?: number
  failedControls?: number
  inProgressControls?: number
  totalAgents?: number
  approvedAgents?: number
  unapprovedAgents?: number
  shadowAIAlerts?: number
}

interface AIPostureProps {
  agents: AIAgent[]
  complianceStatus: ComplianceStatus
  riskScore: number
  metrics: PostureMetrics
  recommendations?: Recommendation[]
}

export default function Posture({ agents: _agents, complianceStatus, riskScore: _riskScore, metrics, recommendations = [] }: AIPostureProps) {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [loading, setLoading] = useState<string | null>(null)

  const handleRefreshAll = () => {
    setLoading('refresh')
    router.reload({ onFinish: () => setLoading(null) })
  }

  const { frameworks = [], controls = [] } = complianceStatus || { frameworks: [], controls: [] }
  const passedControls = metrics?.passedControls ?? controls.filter(c => c.status === 'passed').length
  const failedControls = metrics?.failedControls ?? controls.filter(c => c.status === 'failed' || c.status === 'not_implemented').length
  const inProgressControls = metrics?.inProgressControls ?? controls.filter(c => c.status === 'in_progress').length
  const postureScore = metrics?.postureScore ?? Math.round((complianceStatus as ComplianceStatus & { overallScore?: number })?.overallScore ?? _riskScore ?? 0)
  const scoreTrend = metrics?.scoreTrend ?? 0

  const filteredControls = selectedFramework
    ? controls.filter(c => c.framework === selectedFramework)
    : controls

  return (
    <MainLayout title="AI Security Posture">
      <Head title="AI Security Posture - Tamandua EDR" />

      <div className="space-y-6">
        {/* Posture Score */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 card-sentinel rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Security Posture Score</h2>
            <div className="flex items-center justify-center">
              <div className="relative">
                <svg className="w-40 h-40 transform -rotate-90">
                  <circle
                    cx="80"
                    cy="80"
                    r="70"
                    stroke="currentColor"
                    strokeWidth="12"
                    fill="none"
                    style={{ color: 'var(--surface-3)' }}
                  />
                  <circle
                    cx="80"
                    cy="80"
                    r="70"
                    stroke="currentColor"
                    strokeWidth="12"
                    fill="none"
                    strokeDasharray={`${postureScore * 4.4} 440`}
                    className={cn(
                      postureScore >= 70 ? 'text-green-500' :
                      postureScore >= 50 ? 'text-yellow-500' : 'text-red-500'
                    )}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={cn(
                    'text-4xl font-bold',
                    postureScore >= 70 ? 'text-green-400' :
                    postureScore >= 50 ? 'text-yellow-400' : 'text-red-400'
                  )}>
                    {postureScore}
                  </span>
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>out of 100</span>
                </div>
              </div>
            </div>
            <div className="mt-6 grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold text-green-400">{passedControls}</div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>Passed</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-red-400">{failedControls}</div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>Failed</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-yellow-400">{inProgressControls}</div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>In Progress</div>
              </div>
            </div>
            <div className="mt-6 flex items-center justify-center gap-2 text-sm">
              <TrendingUp className="h-4 w-4 text-green-400" />
              <span className={scoreTrend >= 0 ? 'text-green-400' : 'text-yellow-400'}>{scoreTrend >= 0 ? '+' : ''}{scoreTrend} points</span>
              <span style={{ color: 'var(--muted)' }}>latest observed trend</span>
            </div>
          </div>

          {/* Compliance Frameworks */}
          <div className="lg:col-span-2 card-sentinel rounded-xl">
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Compliance Frameworks</h2>
              <button
                onClick={handleRefreshAll}
                disabled={loading === 'refresh'}
                className="flex items-center gap-2 text-sm text-primary-400 hover:text-primary-300 disabled:opacity-50"
              >
                {loading === 'refresh' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Refresh
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
              {frameworks.length === 0 ? (
                <div className="col-span-2 p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No compliance frameworks configured</p>
                  <p className="text-sm mt-1">Configure frameworks to track security compliance</p>
                </div>
              ) : (
                frameworks.map((framework) => (
                  <FrameworkCard
                    key={framework.id}
                    framework={framework}
                    isSelected={selectedFramework === framework.name}
                    onSelect={() => setSelectedFramework(
                      selectedFramework === framework.name ? null : framework.name
                    )}
                  />
                ))
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Security Controls */}
          <div className="lg:col-span-2 card-sentinel rounded-xl">
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Security Controls</h2>
                {selectedFramework && (
                  <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                    Filtered by: {selectedFramework}
                    <button
                      onClick={() => setSelectedFramework(null)}
                      className="ml-2 text-primary-400 hover:text-primary-300"
                    >
                      Clear
                    </button>
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                <button className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded">
                  {filteredControls.filter(c => c.status === 'failed').length} Failed
                </button>
                <button className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded">
                  {filteredControls.filter(c => c.status === 'in_progress').length} In Progress
                </button>
              </div>
            </div>
            <div style={{ borderColor: 'var(--border)' }}>
              {filteredControls.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No security controls configured</p>
                  <p className="text-sm mt-1">Add compliance frameworks to see security controls</p>
                </div>
              ) : (
                filteredControls.map((control) => (
                  <ControlRow key={control.id} control={control} />
                ))
              )}
            </div>
          </div>

          {/* Recommendations */}
          <div className="card-sentinel rounded-xl">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recommendations</h2>
            </div>
            <div className="p-4 space-y-4">
              {recommendations.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No recommendations available</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>Recommendations will appear based on your security posture</p>
                </div>
              ) : (
                recommendations.map((rec) => (
                  <RecommendationCard key={rec.id} recommendation={rec} />
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

// Helper Components
function FrameworkCard({
  framework,
  isSelected,
  onSelect,
}: {
  framework: ComplianceFramework
  isSelected: boolean
  onSelect: () => void
}) {
  const totalControls = framework.totalControls ?? framework.controlsTotal ?? 0
  const passedControls = framework.passedControls ?? framework.controlsPassed ?? 0
  const failedControls = framework.failedControls ?? Math.max(totalControls - passedControls - (framework.inProgressControls ?? 0), 0)
  const inProgressControls = framework.inProgressControls ?? 0
  const score = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : Math.round(framework.score ?? 0)

  return (
    <button
      onClick={onSelect}
      className={cn(
        'p-4 rounded-lg border text-left transition-all',
        isSelected
          ? 'border-primary-500 bg-primary-500/10'
          : 'hover:border-[var(--border-strong)]'
      )}
      style={!isSelected ? { borderColor: 'var(--border)', background: 'var(--surface-2)' } : undefined}
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{framework.name}</h3>
        <span className={cn(
          'text-lg font-bold',
          score >= 70 ? 'text-green-400' :
          score >= 50 ? 'text-yellow-400' : 'text-red-400'
        )}>
          {score}%
        </span>
      </div>
      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{framework.description || framework.status || 'Compliance posture from observed AI controls'}</p>
      <div className="mt-3 flex gap-3 text-xs">
        <span className="text-green-400">{passedControls} passed</span>
        <span className="text-red-400">{failedControls} failed</span>
        <span className="text-yellow-400">{inProgressControls} in progress</span>
      </div>
      <div className="mt-2 h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
        <div className="h-full flex">
          <div
            className="bg-green-500"
            style={{ width: `${totalControls > 0 ? (passedControls / totalControls) * 100 : 0}%` }}
          />
          <div
            className="bg-yellow-500"
            style={{ width: `${totalControls > 0 ? (inProgressControls / totalControls) * 100 : 0}%` }}
          />
          <div
            className="bg-red-500"
            style={{ width: `${totalControls > 0 ? (failedControls / totalControls) * 100 : 0}%` }}
          />
        </div>
      </div>
    </button>
  )
}

function ControlRow({ control }: { control: SecurityControl }) {
  const [expanded, setExpanded] = useState(false)

  const statusIcon = {
    passed: <CheckCircle className="h-5 w-5 text-green-400" />,
    failed: <XCircle className="h-5 w-5 text-red-400" />,
    in_progress: <Clock className="h-5 w-5 text-yellow-400" />,
    not_applicable: <Info className="h-5 w-5" style={{ color: 'var(--muted)' }} />,
    not_implemented: <XCircle className="h-5 w-5 text-red-400" />,
  }

  const priorityColors = {
    critical: 'bg-red-500/20 text-red-400',
    high: 'bg-orange-500/20 text-orange-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    low: 'bg-blue-500/20 text-blue-400',
  }

  const priority = control.priority || control.severity || 'medium'

  return (
    <div style={{ borderBottom: '1px solid var(--hairline)' }}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-center gap-4 hover:bg-[var(--surface-2)] transition-colors"
      >
        {statusIcon[control.status]}
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{control.name}</span>
            <span className={cn('text-xs px-1.5 py-0.5 rounded uppercase', priorityColors[priority])}>
              {priority}
            </span>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{control.category}{control.framework ? ` - ${control.framework}` : ''}</p>
        </div>
        <ChevronRight className={cn(
          'h-4 w-4 transition-transform',
          expanded && 'rotate-90'
        )} style={{ color: 'var(--muted)' }} />
      </button>
      {expanded && (
        <div className="px-4 pb-4 pl-14">
          <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{control.description}</p>
          {control.remediationSteps && control.status === 'failed' && (
            <div className="mt-3">
              <h4 className="text-xs font-medium uppercase mb-2" style={{ color: 'var(--muted)' }}>Remediation Steps</h4>
              <ul className="space-y-1">
                {control.remediationSteps.map((step, idx) => (
                  <li key={idx} className="text-sm flex items-start gap-2" style={{ color: 'var(--fg-2)' }}>
                    <span className="text-primary-400">{idx + 1}.</span>
                    {step}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function RecommendationCard({ recommendation }: { recommendation: Recommendation }) {
  const priorityColors = {
    critical: 'border-red-500/30 bg-red-500/10',
    high: 'border-orange-500/30 bg-orange-500/10',
    medium: 'border-yellow-500/30 bg-yellow-500/10',
    low: 'border-blue-500/30 bg-blue-500/10',
  }

  const impactColors = {
    high: 'text-green-400',
    medium: 'text-yellow-400',
    low: 'text-[var(--muted)]',
  }

  return (
    <div className={cn('p-3 rounded-lg border', priorityColors[recommendation.priority])}>
      <div className="flex items-start justify-between">
        <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{recommendation.title}</h3>
        <span className="text-xs uppercase px-1.5 py-0.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
          {recommendation.priority}
        </span>
      </div>
      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{recommendation.description}</p>
      <div className="mt-2 flex items-center gap-4 text-xs">
        <span style={{ color: 'var(--muted)' }}>
          Effort: <span className="capitalize" style={{ color: 'var(--fg-2)' }}>{recommendation.effort}</span>
        </span>
        <span style={{ color: 'var(--muted)' }}>
          Impact: <span className={cn('capitalize', impactColors[recommendation.impact])}>
            {recommendation.impact}
          </span>
        </span>
      </div>
      <div className="mt-2">
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
          {recommendation.category}
        </span>
      </div>
    </div>
  )
}
