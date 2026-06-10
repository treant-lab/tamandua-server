import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState } from 'react'
import {
  LineChart,
  Shield,
  AlertTriangle,
  TrendingUp,
  Target,
  Clock,
  CheckCircle,
  XCircle,
  ArrowUpRight,
  ArrowDownRight,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// Types
interface ThreatPrediction {
  id: string
  vector: string
  description: string
  probability: number
  trend: 'increasing' | 'decreasing' | 'stable'
  timeframe: string
  affectedAssets: string[]
  mitreTechniques: string[]
  lastUpdated: string
}

interface DefenseRecommendation {
  id: string
  title: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  status: 'pending' | 'implemented' | 'in_progress'
  description: string
  expectedRiskReduction: number
  relatedThreats: string[]
  implementationSteps: string[]
}

interface AccuracyMetric {
  period: string
  predictions: number
  accurate: number
  falsePositives: number
  falseNegatives: number
  accuracy: number
}

interface AttackForecast {
  category: string
  currentRisk: number
  predictedRisk: number
  timeline: string
  factors: string[]
}

interface AttackPath {
  id: string
  name: string
  likelihood: number
  impact: string
  stages: string[]
}

interface PredictiveStats {
  highRiskPredictions: number
  defensesImplemented: number
  predictionAccuracy: number
  risingThreats: number
}

interface PredictiveShieldingPageProps {
  riskForecast?: AttackForecast[]
  attackPaths?: AttackPath[]
  recommendations?: DefenseRecommendation[]
  stats?: PredictiveStats
  predictions?: ThreatPrediction[]
  accuracyHistory?: AccuracyMetric[]
}

// Default values
const defaultStats: PredictiveStats = {
  highRiskPredictions: 0,
  defensesImplemented: 0,
  predictionAccuracy: 0,
  risingThreats: 0,
}

export default function Predictive({
  riskForecast = [],
  attackPaths = [],
  recommendations = [],
  stats = defaultStats,
  predictions = [],
  accuracyHistory = [],
}: PredictiveShieldingPageProps) {
  const [selectedPrediction, setSelectedPrediction] = useState<ThreatPrediction | null>(null)
  const [showAttackPaths, setShowAttackPaths] = useState(false)

  const priorityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  const statusColors = {
    pending: 'bg-yellow-500/20 text-yellow-400',
    implemented: 'bg-green-500/20 text-green-400',
    in_progress: 'bg-blue-500/20 text-blue-400',
  }

  const getTrendIcon = (trend: 'increasing' | 'decreasing' | 'stable') => {
    switch (trend) {
      case 'increasing':
        return <ArrowUpRight className="h-4 w-4 text-red-400" />
      case 'decreasing':
        return <ArrowDownRight className="h-4 w-4 text-green-400" />
      default:
        return <Activity className="h-4 w-4 text-yellow-400" />
    }
  }

  const getProbabilityColor = (probability: number) => {
    if (probability >= 75) return 'text-red-400'
    if (probability >= 50) return 'text-orange-400'
    if (probability >= 25) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getProbabilityBgColor = (probability: number) => {
    if (probability >= 75) return 'bg-red-500'
    if (probability >= 50) return 'bg-orange-500'
    if (probability >= 25) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  const overallAccuracy = accuracyHistory.length > 0
    ? accuracyHistory.reduce((acc, m) => acc + (m.accuracy || 0), 0) / accuracyHistory.length
    : (stats.predictionAccuracy || 0)

  return (
    <MainLayout title="Predictive Shielding">
      <Head title="Predictive Shield - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/20 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                  {stats.highRiskPredictions || predictions.filter(p => p.probability >= 75).length}
                </p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>High Risk Predictions</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <Shield className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                  {stats.defensesImplemented || recommendations.filter(r => r.status === 'implemented').length}
                </p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Defenses Implemented</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <Target className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{(overallAccuracy || 0).toFixed(1)}%</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Prediction Accuracy</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <TrendingUp className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                  {stats.risingThreats || predictions.filter(p => p.trend === 'increasing').length}
                </p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Rising Threats</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Attack Prediction Dashboard */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card-sentinel rounded-xl">
              <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <LineChart className="h-5 w-5 text-primary-400" />
                  {showAttackPaths ? 'Attack Paths' : 'Attack Predictions'}
                </h2>
                <button
                  onClick={() => setShowAttackPaths(!showAttackPaths)}
                  className="text-sm text-primary-400 hover:text-primary-300"
                >
                  {showAttackPaths ? 'View Predictions' : 'View Attack Paths'}
                </button>
              </div>
              <div style={{ borderColor: 'var(--border)' }}>
                {showAttackPaths ? (
                  attackPaths.length === 0 ? (
                    <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                      <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No attack paths identified</p>
                    </div>
                  ) : (
                    attackPaths.map((path) => (
                      <div key={path.id} className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{path.name}</h3>
                            <div className="flex items-center gap-3 mt-1">
                              <span className={cn(
                                'text-xs px-2 py-0.5 rounded',
                                path.likelihood >= 75 ? 'bg-red-500/20 text-red-400' :
                                path.likelihood >= 50 ? 'bg-orange-500/20 text-orange-400' :
                                path.likelihood >= 25 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                              )}>
                                {path.likelihood}% likelihood
                              </span>
                              <span className="text-xs" style={{ color: 'var(--muted)' }}>Impact: {path.impact}</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {(path.stages || []).map((stage, idx) => (
                            <div key={idx} className="flex items-center">
                              <span className="text-xs px-2 py-1 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>{stage}</span>
                              {idx < (path.stages || []).length - 1 && (
                                <ArrowUpRight className="h-3 w-3 mx-1" style={{ color: 'var(--subtle)' }} />
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                  )
                ) : predictions.length === 0 ? (
                  <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                    <LineChart className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No predictions available</p>
                  </div>
                ) : (
                  predictions.map((prediction) => (
                    <button
                      key={prediction.id}
                      onClick={() => setSelectedPrediction(prediction)}
                      className={cn(
                        'w-full p-4 text-left transition-colors hover:bg-[var(--surface-2)]',
                        selectedPrediction?.id === prediction.id && 'bg-[var(--surface-2)]'
                      )}
                      style={{ borderBottom: '1px solid var(--border)' }}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{ background: 'var(--surface-2)' }}>
                              <span className={cn('text-2xl font-bold', getProbabilityColor(prediction.probability))}>
                                {prediction.probability}%
                              </span>
                            </div>
                            <div
                              className={cn(
                                'absolute inset-0 rounded-full',
                                getProbabilityBgColor(prediction.probability)
                              )}
                              style={{
                                clipPath: `polygon(50% 50%, 50% 0%, ${50 + 50 * Math.sin(2 * Math.PI * prediction.probability / 100)}% ${50 - 50 * Math.cos(2 * Math.PI * prediction.probability / 100)}%, 50% 50%)`,
                                opacity: 0.3,
                              }}
                            />
                          </div>
                          <div>
                            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{prediction.vector}</h3>
                            <div className="flex items-center gap-2 mt-1">
                              {getTrendIcon(prediction.trend)}
                              <span className="text-xs" style={{ color: 'var(--muted)' }}>{prediction.trend}</span>
                              <span className="text-xs" style={{ color: 'var(--subtle)' }}>|</span>
                              <Clock className="h-3 w-3" style={{ color: 'var(--muted)' }} />
                              <span className="text-xs" style={{ color: 'var(--muted)' }}>{prediction.timeframe}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{prediction.description}</p>
                      <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                        <span>{(prediction.affectedAssets || []).length} assets at risk</span>
                        <div className="flex gap-1">
                          {(prediction.mitreTechniques || []).slice(0, 3).map((tech) => (
                            <span key={tech} className="px-1.5 py-0.5 rounded font-mono text-primary-400" style={{ background: 'var(--surface-2)' }}>
                              {tech}
                            </span>
                          ))}
                          {prediction.mitreTechniques.length > 3 && (
                            <span style={{ color: 'var(--muted)' }}>+{prediction.mitreTechniques.length - 3}</span>
                          )}
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>

            {/* Preemptive Defense Recommendations */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Shield className="h-5 w-5 text-primary-400" />
                  Preemptive Defense Recommendations
                </h2>
              </div>
              <div style={{ borderColor: 'var(--border)' }}>
                {recommendations.length === 0 ? (
                  <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No recommendations available</p>
                  </div>
                ) : (
                  recommendations.map((rec) => (
                    <div key={rec.id} className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{rec.title}</h3>
                            <span className={cn('text-xs px-2 py-0.5 rounded border', priorityColors[rec.priority])}>
                              {rec.priority.toUpperCase()}
                            </span>
                            <span className={cn('text-xs px-2 py-0.5 rounded', statusColors[rec.status])}>
                              {rec.status.replace('_', ' ')}
                            </span>
                          </div>
                          <p className="text-sm" style={{ color: 'var(--muted)' }}>{rec.description}</p>
                        </div>
                        <div className="text-right">
                          <div className="text-xs" style={{ color: 'var(--subtle)' }}>Risk Reduction</div>
                          <div className="text-lg font-bold text-green-400">-{rec.expectedRiskReduction}%</div>
                        </div>
                      </div>
                      {rec.status === 'pending' && (
                        <div className="mt-3">
                          <p className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>Implementation Steps:</p>
                          <div className="flex flex-wrap gap-2">
                            {(rec.implementationSteps || []).map((step, idx) => (
                              <span key={idx} className="text-xs px-2 py-1 rounded" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                                {idx + 1}. {step}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Right Column - Forecasts and Accuracy */}
          <div className="space-y-6">
            {/* Attack Forecasts */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <TrendingUp className="h-5 w-5 text-primary-400" />
                  Risk Forecast (48h)
                </h2>
              </div>
              <div className="p-4 space-y-4">
                {riskForecast.length === 0 ? (
                  <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                    <TrendingUp className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No forecasts available</p>
                  </div>
                ) : (
                  riskForecast.map((forecast, idx) => (
                    <div key={idx} className="p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm" style={{ color: 'var(--fg)' }}>{forecast.category}</span>
                        <span className={cn(
                          'text-xs font-medium',
                          forecast.predictedRisk > forecast.currentRisk ? 'text-red-400' : 'text-green-400'
                        )}>
                          {forecast.timeline}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mb-2">
                        <div className="flex-1">
                          <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                            <div
                              className="h-full bg-yellow-500 rounded-full transition-all"
                              style={{ width: `${forecast.currentRisk}%` }}
                            />
                          </div>
                        </div>
                        <span className="text-xs w-12" style={{ color: 'var(--muted)' }}>{forecast.currentRisk}%</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="flex-1">
                          <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                            <div
                              className={cn(
                                'h-full rounded-full transition-all',
                                forecast.predictedRisk >= 75 ? 'bg-red-500' :
                                forecast.predictedRisk >= 50 ? 'bg-orange-500' : 'bg-yellow-500'
                              )}
                              style={{ width: `${forecast.predictedRisk}%` }}
                            />
                          </div>
                        </div>
                        <span className={cn(
                          'text-xs w-12',
                          forecast.predictedRisk >= 75 ? 'text-red-400' :
                          forecast.predictedRisk >= 50 ? 'text-orange-400' : 'text-yellow-400'
                        )}>
                          {forecast.predictedRisk}%
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {(forecast.factors || []).map((factor, fidx) => (
                          <span key={fidx} className="text-xs" style={{ color: 'var(--subtle)' }}>{factor}{fidx < (forecast.factors || []).length - 1 ? ',' : ''}</span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Historical Accuracy */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Target className="h-5 w-5 text-primary-400" />
                  Prediction Accuracy
                </h2>
              </div>
              <div className="p-4">
                <div className="mb-4 text-center">
                  <div className="text-4xl font-bold" style={{ color: 'var(--fg)' }}>{(overallAccuracy || 0).toFixed(1)}%</div>
                  <div className="text-sm" style={{ color: 'var(--muted)' }}>7-day average accuracy</div>
                </div>
                <div className="space-y-2">
                  {accuracyHistory.length === 0 ? (
                    <div className="p-4 text-center" style={{ color: 'var(--subtle)' }}>
                      <p className="text-sm">No accuracy history available</p>
                    </div>
                  ) : (
                    accuracyHistory.slice(-5).map((metric, idx) => (
                      <div key={idx} className="flex items-center justify-between text-sm">
                        <span style={{ color: 'var(--muted)' }}>{metric.period}</span>
                        <div className="flex items-center gap-3">
                          <div className="flex items-center gap-1">
                            <CheckCircle className="h-3 w-3 text-green-400" />
                            <span style={{ color: 'var(--fg-2)' }}>{metric.accurate}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <XCircle className="h-3 w-3 text-red-400" />
                            <span style={{ color: 'var(--fg-2)' }}>{metric.falsePositives + metric.falseNegatives}</span>
                          </div>
                          <span className={cn(
                            'font-medium w-14 text-right',
                            metric.accuracy >= 90 ? 'text-green-400' :
                            metric.accuracy >= 80 ? 'text-yellow-400' : 'text-red-400'
                          )}>
                            {(metric.accuracy || 0).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="card-sentinel rounded-xl p-4">
              <h3 className="text-sm font-medium mb-4" style={{ color: 'var(--muted)' }}>This Week</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                  <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {accuracyHistory.reduce((acc, m) => acc + m.predictions, 0)}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Total Predictions</div>
                </div>
                <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                  <div className="text-2xl font-bold text-green-400">
                    {accuracyHistory.reduce((acc, m) => acc + m.accurate, 0)}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>Accurate</div>
                </div>
                <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                  <div className="text-2xl font-bold text-yellow-400">
                    {accuracyHistory.reduce((acc, m) => acc + m.falsePositives, 0)}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>False Positives</div>
                </div>
                <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
                  <div className="text-2xl font-bold text-red-400">
                    {accuracyHistory.reduce((acc, m) => acc + m.falseNegatives, 0)}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>False Negatives</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
