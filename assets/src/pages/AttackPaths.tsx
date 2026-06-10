import { useState } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Route,
  Shield,
  AlertTriangle,
  Target,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  CheckCircle,
  Clock,
  Lightbulb,
  Zap,
  Server,
  TrendingUp,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AttackPathStep {
  name: string
  description: string
  technique: string
  severity: string
}

interface AttackPath {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  likelihood: number
  impactScore: number
  steps: AttackPathStep[]
  affectedAssets: string[]
  mitigations: string[]
  entryPoints: string[]
  targetAssets: string[]
}

interface Recommendation {
  id: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  category: string
  title: string
  description: string
  effort: 'low' | 'medium' | 'high'
  impact: 'low' | 'medium' | 'high'
  status: 'pending' | 'in_progress' | 'completed' | 'dismissed'
  relatedPaths: string[]
}

interface Stats {
  totalPaths: number
  criticalPaths: number
  pendingRecommendations: number
}

interface AttackPathsProps {
  paths: AttackPath[]
  criticalPaths: AttackPath[]
  recommendations: Recommendation[]
  stats: Stats
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getSeverityBadgeClass(severity: string) {
  switch (severity) {
    case 'critical': return 'badge-sentinel badge-sentinel-critical'
    case 'high': return 'badge-sentinel badge-sentinel-high'
    case 'medium': return 'badge-sentinel badge-sentinel-medium'
    case 'low': return 'badge-sentinel badge-sentinel-low'
    default: return 'badge-sentinel badge-sentinel-default'
  }
}

function getSeverityColor(severity: string): { icon: string; bg: string } {
  switch (severity) {
    case 'critical': return { icon: 'var(--crit)', bg: 'var(--crit-bg)' }
    case 'high': return { icon: 'var(--high)', bg: 'var(--high-bg)' }
    case 'medium': return { icon: 'var(--med)', bg: 'var(--med-bg)' }
    case 'low': return { icon: 'var(--low)', bg: 'var(--low-bg)' }
    default: return { icon: 'var(--subtle)', bg: 'var(--surface-2)' }
  }
}

function getEffortStyle(effort: string): { color: string; bg: string } {
  switch (effort) {
    case 'low': return { color: 'var(--emerald-400)', bg: 'rgba(47, 196, 113, 0.15)' }
    case 'medium': return { color: 'var(--high)', bg: 'var(--high-bg)' }
    case 'high': return { color: 'var(--crit)', bg: 'var(--crit-bg)' }
    default: return { color: 'var(--subtle)', bg: 'var(--surface-2)' }
  }
}

function getImpactStyle(impact: string): { color: string; bg: string } {
  switch (impact) {
    case 'low': return { color: 'var(--med)', bg: 'var(--med-bg)' }
    case 'medium': return { color: 'var(--high)', bg: 'var(--high-bg)' }
    case 'high': return { color: 'var(--emerald-400)', bg: 'rgba(47, 196, 113, 0.15)' }
    default: return { color: 'var(--subtle)', bg: 'var(--surface-2)' }
  }
}

function getStatusStyle(status: string): { color: string; bg: string; border: string } {
  switch (status) {
    case 'completed': return { color: 'var(--emerald-400)', bg: 'rgba(47, 196, 113, 0.15)', border: 'rgba(47, 196, 113, 0.3)' }
    case 'in_progress': return { color: 'var(--med)', bg: 'var(--med-bg)', border: 'rgba(91, 156, 242, 0.3)' }
    case 'pending': return { color: 'var(--high)', bg: 'var(--high-bg)', border: 'rgba(245, 165, 36, 0.3)' }
    case 'dismissed': return { color: 'var(--subtle)', bg: 'var(--surface-2)', border: 'var(--border)' }
    default: return { color: 'var(--subtle)', bg: 'var(--surface-2)', border: 'var(--border)' }
  }
}

function getLikelihoodColor(likelihood: number): string {
  if (likelihood >= 80) return 'var(--crit)'
  if (likelihood >= 60) return 'var(--high)'
  if (likelihood >= 40) return 'var(--med)'
  return 'var(--emerald-400)'
}

// ---------------------------------------------------------------------------
// Attack Path Card Component
// ---------------------------------------------------------------------------

function AttackPathCard({ path }: { path: AttackPath }) {
  const [expanded, setExpanded] = useState(false)
  const severityStyle = getSeverityColor(path.severity)

  return (
    <div className="card-sentinel overflow-hidden p-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 text-left transition-colors rounded-lg"
        style={{ background: expanded ? 'var(--surface-2)' : undefined }}
        onMouseEnter={(e) => { if (!expanded) e.currentTarget.style.background = 'var(--surface-2)' }}
        onMouseLeave={(e) => { if (!expanded) e.currentTarget.style.background = '' }}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3 flex-1">
            {expanded ? (
              <ChevronDown className="h-4 w-4 mt-1 shrink-0" style={{ color: 'var(--subtle)' }} />
            ) : (
              <ChevronRight className="h-4 w-4 mt-1 shrink-0" style={{ color: 'var(--subtle)' }} />
            )}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{path.name}</span>
                <span className={getSeverityBadgeClass(path.severity)}>
                  {path.severity.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-4 mt-1.5 text-xs" style={{ color: 'var(--subtle)' }}>
                <span className="flex items-center gap-1">
                  <TrendingUp className="h-3 w-3" />
                  Likelihood: <span style={{ color: getLikelihoodColor(path.likelihood) }}>{path.likelihood}%</span>
                </span>
                <span className="flex items-center gap-1">
                  <Zap className="h-3 w-3" />
                  Impact: <span style={{ color: 'var(--fg-2)' }}>{path.impactScore}/100</span>
                </span>
                <span className="flex items-center gap-1">
                  <Route className="h-3 w-3" />
                  {path.steps.length} steps
                </span>
                <span className="flex items-center gap-1">
                  <Server className="h-3 w-3" />
                  {path.affectedAssets.length} assets
                </span>
              </div>
            </div>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t space-y-4" style={{ borderColor: 'var(--hairline)' }}>
          {/* Entry Points and Targets */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>Entry Points</h4>
              <div className="space-y-1">
                {path.entryPoints.map((entry, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 text-xs rounded p-2"
                    style={{ color: 'var(--fg-2)', background: 'var(--surface-2)' }}
                  >
                    <Target className="h-3 w-3 shrink-0" style={{ color: 'var(--crit)' }} />
                    {entry}
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>Target Assets</h4>
              <div className="space-y-1">
                {path.targetAssets.map((asset, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 text-xs rounded p-2"
                    style={{ color: 'var(--fg-2)', background: 'var(--surface-2)' }}
                  >
                    <Server className="h-3 w-3 shrink-0" style={{ color: 'var(--high)' }} />
                    {asset}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Steps Flow */}
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>Attack Steps</h4>
            <div className="space-y-0">
              {path.steps.map((step, idx) => (
                <div key={idx}>
                  <div
                    className="rounded-lg p-3 flex items-center gap-3"
                    style={{ background: 'var(--surface-2)' }}
                  >
                    <div
                      className="flex items-center justify-center h-7 w-7 rounded-full text-xs font-bold shrink-0"
                      style={{ background: 'var(--crit-bg)', color: 'var(--crit)' }}
                    >
                      {idx + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium" style={{ color: 'var(--fg)' }}>{step.name}</span>
                        {step.technique && (
                          <a
                            href={`https://attack.mitre.org/techniques/${step.technique.replace('.', '/')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-2 py-0.5 rounded text-[10px] font-medium transition-colors"
                            style={{
                              background: 'rgba(139, 92, 246, 0.2)',
                              color: '#a78bfa',
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(139, 92, 246, 0.3)'}
                            onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(139, 92, 246, 0.2)'}
                          >
                            {step.technique}
                          </a>
                        )}
                      </div>
                      <p className="text-[11px] mt-0.5" style={{ color: 'var(--subtle)' }}>{step.description}</p>
                    </div>
                  </div>
                  {idx < path.steps.length - 1 && (
                    <div className="flex justify-center py-0.5">
                      <ArrowRight className="h-3.5 w-3.5 rotate-90" style={{ color: 'var(--dim)' }} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Affected Assets */}
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>Affected Assets</h4>
            <div className="flex flex-wrap gap-1">
              {path.affectedAssets.map((asset, idx) => (
                <span
                  key={idx}
                  className="px-2 py-1 rounded text-xs"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                >
                  {asset}
                </span>
              ))}
            </div>
          </div>

          {/* Mitigations */}
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider mb-2" style={{ color: 'var(--subtle)' }}>Mitigations</h4>
            <div className="space-y-1">
              {path.mitigations.map((mitigation, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2 text-xs rounded p-2"
                  style={{ color: 'var(--fg-2)', background: 'var(--surface-2)' }}
                >
                  <Shield className="h-3 w-3 mt-0.5 shrink-0" style={{ color: 'var(--emerald-400)' }} />
                  {mitigation}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function AttackPaths({
  paths,
  criticalPaths,
  recommendations,
  stats,
}: AttackPathsProps) {
  const [activeSection, setActiveSection] = useState<'paths' | 'recommendations'>('paths')

  return (
    <MainLayout title="">
      <Head title="Attack Paths - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="card-sentinel p-6">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl" style={{ background: 'var(--med-bg)' }}>
                <Route className="h-6 w-6" style={{ color: 'var(--med)' }} />
              </div>
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Paths</p>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{stats.totalPaths}</p>
              </div>
            </div>
          </div>
          <div
            className="card-sentinel p-6"
            style={{ borderColor: 'rgba(240, 80, 110, 0.3)' }}
          >
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl" style={{ background: 'var(--crit-bg)' }}>
                <AlertTriangle className="h-6 w-6" style={{ color: 'var(--crit)' }} />
              </div>
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Critical Paths</p>
                <p className="text-2xl font-bold" style={{ color: 'var(--crit)' }}>{stats.criticalPaths}</p>
              </div>
            </div>
          </div>
          <div
            className="card-sentinel p-6"
            style={{ borderColor: 'rgba(245, 165, 36, 0.3)' }}
          >
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl" style={{ background: 'var(--high-bg)' }}>
                <Lightbulb className="h-6 w-6" style={{ color: 'var(--high)' }} />
              </div>
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Pending Recommendations</p>
                <p className="text-2xl font-bold" style={{ color: 'var(--high)' }}>{stats.pendingRecommendations}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Critical Paths Highlight */}
        {criticalPaths.length > 0 && (
          <div
            className="card-sentinel overflow-hidden p-0"
            style={{ borderColor: 'rgba(240, 80, 110, 0.3)' }}
          >
            <div className="p-4 border-b" style={{ borderColor: 'rgba(240, 80, 110, 0.2)' }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--crit)' }}>
                <AlertTriangle className="h-5 w-5" />
                Critical Attack Paths
              </h2>
              <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                These paths represent the highest risk to your environment and should be prioritized.
              </p>
            </div>
            <div className="p-4 space-y-3">
              {criticalPaths.map(path => (
                <AttackPathCard key={path.id} path={path} />
              ))}
            </div>
          </div>
        )}

        {/* Section Toggle */}
        <div className="card-sentinel overflow-hidden p-0">
          <div className="border-b px-4" style={{ borderColor: 'var(--hairline)' }}>
            <div className="flex gap-1">
              {([
                { id: 'paths', label: 'All Attack Paths', icon: Route, count: paths.length },
                { id: 'recommendations', label: 'Recommendations', icon: Lightbulb, count: recommendations.length },
              ] as const).map(tab => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveSection(tab.id)}
                    className="flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors"
                    style={{
                      borderColor: activeSection === tab.id ? 'var(--emerald-400)' : 'transparent',
                      color: activeSection === tab.id ? 'var(--emerald-400)' : 'var(--muted)',
                    }}
                    onMouseEnter={(e) => {
                      if (activeSection !== tab.id) e.currentTarget.style.color = 'var(--fg-2)'
                    }}
                    onMouseLeave={(e) => {
                      if (activeSection !== tab.id) e.currentTarget.style.color = 'var(--muted)'
                    }}
                  >
                    <Icon className="h-4 w-4" />
                    {tab.label}
                    {tab.count > 0 && (
                      <span
                        className="px-1.5 py-0.5 rounded text-xs"
                        style={{ background: 'var(--surface-2)' }}
                      >
                        {tab.count}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="p-4">
            {/* All Paths */}
            {activeSection === 'paths' && (
              <div className="space-y-3">
                {paths.length === 0 ? (
                  <div className="text-center py-12" style={{ color: 'var(--subtle)' }}>
                    <Route className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No attack paths identified</p>
                  </div>
                ) : (
                  paths.map(path => (
                    <AttackPathCard key={path.id} path={path} />
                  ))
                )}
              </div>
            )}

            {/* Recommendations */}
            {activeSection === 'recommendations' && (
              <div className="space-y-3">
                {recommendations.length === 0 ? (
                  <div className="text-center py-12" style={{ color: 'var(--subtle)' }}>
                    <Lightbulb className="h-10 w-10 mx-auto mb-2 opacity-50" />
                    <p>No recommendations available</p>
                  </div>
                ) : (
                  recommendations.map(rec => {
                    const effortStyle = getEffortStyle(rec.effort)
                    const impactStyle = getImpactStyle(rec.impact)
                    const statusStyle = getStatusStyle(rec.status)

                    return (
                      <div key={rec.id} className="card-sentinel p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 flex-wrap mb-2">
                              <span className={getSeverityBadgeClass(rec.priority)}>
                                {rec.priority.toUpperCase()}
                              </span>
                              <span
                                className="px-2 py-0.5 rounded text-xs font-medium"
                                style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                              >
                                {rec.category}
                              </span>
                              <span
                                className="px-2 py-0.5 rounded text-xs font-medium border"
                                style={{
                                  background: statusStyle.bg,
                                  color: statusStyle.color,
                                  borderColor: statusStyle.border,
                                }}
                              >
                                {rec.status.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <h3 className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{rec.title}</h3>
                            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{rec.description}</p>
                            <div className="flex items-center gap-3 mt-3">
                              <span
                                className="px-2 py-0.5 rounded text-[10px] font-medium"
                                style={{ background: effortStyle.bg, color: effortStyle.color }}
                              >
                                Effort: {rec.effort}
                              </span>
                              <span
                                className="px-2 py-0.5 rounded text-[10px] font-medium"
                                style={{ background: impactStyle.bg, color: impactStyle.color }}
                              >
                                Impact: {rec.impact}
                              </span>
                              {rec.relatedPaths.length > 0 && (
                                <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>
                                  {rec.relatedPaths.length} related path(s)
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
