import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState, useEffect, useCallback, useRef } from 'react'
import { logger } from '@/lib/logger'
import {
  Zap,
  Activity,
  AlertTriangle,
  Clock,
  Target,
  RefreshCw,
  CheckCircle,
  XCircle,
  Brain,
  FileCode,
  BarChart2,
  AlertOctagon,
  Wifi,
  WifiOff,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  useSocket,
  ConnectionState,
  getConnectionStatusColor,
  getConnectionStatusText,
} from '../hooks/useSocket'

// Types
interface DetectionEvent {
  id: string
  timestamp: string
  ruleName: string
  ruleType: 'dynamic' | 'static' | 'ml'
  severity: 'critical' | 'high' | 'medium' | 'low'
  agentId: string
  hostname: string
  description: string
  confidence: number
  mitreTechniques: string[]
}

interface DynamicRule {
  id: string
  name: string
  status: 'active' | 'testing' | 'disabled'
  generatedAt: string
  triggeredCount: number
  falsePositiveRate: number
  basedOn: string
  description: string
}

interface MLModelMetrics {
  modelName: string
  version: string
  accuracy: number
  precision: number
  recall: number
  f1Score: number
  lastTrained: string
  samplesProcessed: number
  inferenceLatency: number
}

interface MLMetricsResponse {
  status?: string
  message?: string
  metrics?: {
    accuracy?: number
    precision?: number
    recall?: number
    f1_score?: number
    f1Score?: number
    samples_processed?: number
    samplesProcessed?: number
    inference_latency?: number
    inferenceLatency?: number
  }
  model_name?: string
  modelName?: string
  version?: string
  accuracy?: number
  precision?: number
  recall?: number
  f1_score?: number
  f1Score?: number
  last_trained?: string
  lastTrained?: string
  samples_processed?: number
  samplesProcessed?: number
  inference_latency?: number
  inferenceLatency?: number
}

interface EmergingThreat {
  id: string
  name: string
  firstSeen: string
  occurrences: number
  affectedHosts: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  mitreMapping: string[]
  indicators: string[]
}

interface ProactiveHunt {
  id: string
  name: string
  status: string
  lastRun: string
  findings: number
}

interface BlindSpot {
  id: string
  area: string
  risk: string
  recommendation: string
}

interface Recommendation {
  id: string
  title: string
  priority: string
  description: string
}

interface Coverage {
  total: number
  covered: number
  percentage: number
}

interface DynamicDetectionPageProps {
  status?: {
    detectionFeed?: DetectionEvent[]
    dynamicRules?: DynamicRule[]
    mlMetrics?: MLModelMetrics
    emergingThreats?: EmergingThreat[]
  }
  proactiveHunts?: ProactiveHunt[]
  blindSpots?: BlindSpot[]
  recommendations?: Recommendation[]
  coverage?: Coverage
}

// Default values
const defaultMLMetrics: MLModelMetrics = {
  modelName: 'Malware-SMELL',
  version: '1.0.0',
  accuracy: 0,
  precision: 0,
  recall: 0,
  f1Score: 0,
  lastTrained: new Date().toISOString(),
  samplesProcessed: 0,
  inferenceLatency: 0,
}

const ML_METRICS_ENDPOINT = '/api/v1/ml/metrics'
const ML_METRICS_POLL_INTERVAL = 30_000

// Skeleton component for loading states
function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn('animate-pulse rounded', className)} style={{ backgroundColor: 'var(--surface-2)' }} />
  )
}

// Connection status indicator
function ConnectionStatusIndicator({ state }: { state: ConnectionState }) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
      style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
    >
      <span className={cn('h-2 w-2 rounded-full', getConnectionStatusColor(state))} />
      <span style={{ color: 'var(--muted)' }}>{getConnectionStatusText(state)}</span>
      {state === 'errored' && (
        <WifiOff className="h-3 w-3 text-red-400" />
      )}
      {state === 'connected' && (
        <Wifi className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
      )}
    </div>
  )
}

export default function DynamicDetection({
  status = {},
  proactiveHunts = [],
  blindSpots = [],
  recommendations = [],
  coverage = { total: 0, covered: 0, percentage: 0 },
}: DynamicDetectionPageProps) {
  const detectionFeed = status.detectionFeed || []
  const dynamicRules = status.dynamicRules || []
  const emergingThreats = status.emergingThreats || []

  const [localDetectionFeed, setLocalDetectionFeed] = useState<DetectionEvent[]>(detectionFeed)
  const [isLive, setIsLive] = useState(true)
  const [selectedTab, setSelectedTab] = useState<'feed' | 'rules' | 'model' | 'threats' | 'gaps'>('feed')

  // ML metrics state
  const [mlMetrics, setMlMetrics] = useState<MLModelMetrics>(status.mlMetrics || defaultMLMetrics)
  const [mlMetricsLoading, setMlMetricsLoading] = useState(true)
  const [mlMetricsError, setMlMetricsError] = useState<string | null>(null)

  // WebSocket connection
  const { socket, connectionState, joinChannel, leaveChannel } = useSocket()
  const isLiveRef = useRef(isLive)
  isLiveRef.current = isLive

  // Channel error state
  const [channelError, setChannelError] = useState<string | null>(null)

  // Update local state when props change
  useEffect(() => {
    setLocalDetectionFeed(detectionFeed)
  }, [detectionFeed])

  // Fetch ML metrics from API
  const fetchMLMetrics = useCallback(async () => {
    try {
      const response = await fetch(ML_METRICS_ENDPOINT)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      const data: MLMetricsResponse = await response.json()
      if (data.status === 'unavailable') {
        throw new Error(data.message || 'ML service unavailable')
      }
      const metricSource = data.metrics || data
      // Map snake_case API response to camelCase interface
      const metrics: MLModelMetrics = {
        modelName: data.model_name ?? data.modelName ?? defaultMLMetrics.modelName,
        version: data.version ?? defaultMLMetrics.version,
        accuracy: metricSource.accuracy ?? 0,
        precision: metricSource.precision ?? 0,
        recall: metricSource.recall ?? 0,
        f1Score: metricSource.f1_score ?? metricSource.f1Score ?? 0,
        lastTrained: data.last_trained ?? data.lastTrained ?? defaultMLMetrics.lastTrained,
        samplesProcessed: metricSource.samples_processed ?? metricSource.samplesProcessed ?? 0,
        inferenceLatency: metricSource.inference_latency ?? metricSource.inferenceLatency ?? 0,
      }
      setMlMetrics(metrics)
      setMlMetricsError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch ML metrics'
      setMlMetricsError(message)
      logger.error('[MLMetrics] Fetch error:', message)
    } finally {
      setMlMetricsLoading(false)
    }
  }, [])

  // Fetch ML metrics on mount and poll every 30s
  useEffect(() => {
    fetchMLMetrics()
    const interval = setInterval(fetchMLMetrics, ML_METRICS_POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchMLMetrics])

  // WebSocket subscription for real-time detection updates
  useEffect(() => {
    if (connectionState !== 'connected') return

    const channel = joinChannel({
      topic: 'detection:feed',
      onJoin: () => {
        logger.log('[Detection] Joined detection:feed')
        setChannelError(null)
      },
      onError: (error) => {
        logger.error('[Detection] Failed to join detection:feed:', error)
        setChannelError('Failed to join detection channel')
      },
      onClose: () => {
        logger.log('[Detection] Left detection:feed')
      },
    })

    if (!channel) return

    // New detection events
    channel.on('new_detection', (payload) => {
      if (!isLiveRef.current) return
      const detection = payload as DetectionEvent
      setLocalDetectionFeed(prev => [detection, ...prev].slice(0, 50))
    })

    // Rule match events (update dynamic rules feed as detections)
    channel.on('rule_match', (payload) => {
      if (!isLiveRef.current) return
      const detection = payload as DetectionEvent
      setLocalDetectionFeed(prev => [detection, ...prev].slice(0, 50))
    })

    // Coverage changes can update ML metrics
    channel.on('coverage_update', (payload) => {
      const data = payload as { mlMetrics?: Partial<MLModelMetrics> }
      if (data.mlMetrics) {
        setMlMetrics(prev => ({ ...prev, ...data.mlMetrics }))
      }
    })

    return () => {
      leaveChannel('detection:feed')
    }
  }, [connectionState, joinChannel, leaveChannel])

  const severityColors = {
    critical: 'badge-sentinel-critical',
    high: 'badge-sentinel-high',
    medium: 'badge-sentinel-medium',
    low: 'badge-sentinel-low',
  }

  const ruleTypeColors = {
    dynamic: 'bg-purple-500/20 text-purple-400',
    static: 'bg-slate-500/20 text-slate-400',
    ml: 'bg-cyan-500/20 text-cyan-400',
  }

  const statusColors = {
    active: 'badge-sentinel-success',
    testing: 'badge-sentinel-warning',
    disabled: 'badge-sentinel-default',
  }

  return (
    <MainLayout title="Dynamic Threat Detection">
      <Head title="Dynamic Detection - Tamandua EDR" />

      <div className="space-y-6">
        {/* Connection Status & Error Banners */}
        <div className="flex items-center justify-between">
          <ConnectionStatusIndicator state={connectionState} />
          {channelError && (
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
              style={{ backgroundColor: 'var(--crit-bg)', border: '1px solid rgba(240, 80, 110, 0.3)', color: 'var(--crit)' }}
            >
              <AlertTriangle className="h-3 w-3" />
              {channelError}
            </div>
          )}
          {mlMetricsError && (
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
              style={{ backgroundColor: 'var(--high-bg)', border: '1px solid rgba(245, 165, 36, 0.3)', color: 'var(--high)' }}
            >
              <AlertTriangle className="h-3 w-3" />
              ML metrics unavailable: {mlMetricsError}
            </div>
          )}
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Zap className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{dynamicRules.filter(r => r.status === 'active').length}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Active Dynamic Rules</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--crit-bg)' }}>
                <AlertTriangle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{localDetectionFeed.filter(d => d.severity === 'critical').length}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Critical Detections</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <Brain className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                {mlMetricsLoading ? (
                  <Skeleton className="h-8 w-16 mb-1" />
                ) : (
                  <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                    {mlMetricsError ? '--' : `${mlMetrics.accuracy.toFixed(1)}%`}
                  </p>
                )}
                <p className="text-sm" style={{ color: 'var(--muted)' }}>ML Model Accuracy</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--high-bg)' }}>
                <Target className="h-5 w-5" style={{ color: 'var(--high)' }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{emergingThreats.length}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Emerging Threats</p>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 pb-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <button
            onClick={() => setSelectedTab('feed')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
              selectedTab === 'feed'
                ? 'border border-b-0'
                : 'hover:opacity-80'
            )}
            style={selectedTab === 'feed'
              ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', borderColor: 'var(--border)' }
              : { color: 'var(--muted)' }
            }
          >
            <Activity className="h-4 w-4" />
            Real-time Feed
          </button>
          <button
            onClick={() => setSelectedTab('rules')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
              selectedTab === 'rules'
                ? 'border border-b-0'
                : 'hover:opacity-80'
            )}
            style={selectedTab === 'rules'
              ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', borderColor: 'var(--border)' }
              : { color: 'var(--muted)' }
            }
          >
            <FileCode className="h-4 w-4" />
            Dynamic Rules
          </button>
          <button
            onClick={() => setSelectedTab('model')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
              selectedTab === 'model'
                ? 'border border-b-0'
                : 'hover:opacity-80'
            )}
            style={selectedTab === 'model'
              ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', borderColor: 'var(--border)' }
              : { color: 'var(--muted)' }
            }
          >
            <BarChart2 className="h-4 w-4" />
            ML Metrics
          </button>
          <button
            onClick={() => setSelectedTab('threats')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
              selectedTab === 'threats'
                ? 'border border-b-0'
                : 'hover:opacity-80'
            )}
            style={selectedTab === 'threats'
              ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', borderColor: 'var(--border)' }
              : { color: 'var(--muted)' }
            }
          >
            <AlertOctagon className="h-4 w-4" />
            Emerging Threats
          </button>
          <button
            onClick={() => setSelectedTab('gaps')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors',
              selectedTab === 'gaps'
                ? 'border border-b-0'
                : 'hover:opacity-80'
            )}
            style={selectedTab === 'gaps'
              ? { backgroundColor: 'var(--surface)', color: 'var(--fg)', borderColor: 'var(--border)' }
              : { color: 'var(--muted)' }
            }
          >
            <Target className="h-4 w-4" />
            Coverage Gaps
          </button>

          <div className="flex-1" />

          {selectedTab === 'feed' && (
            <button
              onClick={() => setIsLive(!isLive)}
              className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors'
              )}
              style={isLive
                ? { backgroundColor: 'var(--emerald-glow)', color: 'var(--emerald-400)', border: '1px solid rgba(47, 196, 113, 0.3)' }
                : { backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }
              }
            >
              {isLive ? (
                <>
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: 'var(--emerald-400)' }} />
                    <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: 'var(--emerald-500)' }} />
                  </span>
                  Live
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4" />
                  Paused
                </>
              )}
            </button>
          )}
        </div>

        {/* Tab Content */}
        {selectedTab === 'feed' && (
          <div className="card-sentinel">
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Activity className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Detection Feed
              </h2>
              <span className="text-sm" style={{ color: 'var(--muted)' }}>{localDetectionFeed.length} events</span>
            </div>
            <div className="divide-y max-h-[600px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
              {connectionState === 'connecting' ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Loader2 className="h-12 w-12 mx-auto mb-4 opacity-50 animate-spin" />
                  <p>Connecting to detection feed...</p>
                </div>
              ) : localDetectionFeed.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No detections yet</p>
                  {connectionState !== 'connected' && (
                    <p className="text-xs mt-2" style={{ color: 'var(--dim)' }}>WebSocket not connected -- live updates unavailable</p>
                  )}
                </div>
              ) : (
                localDetectionFeed.map((detection) => (
                  <div
                    key={detection.id}
                    className="p-4 transition-colors"
                    style={{ ['--tw-bg-opacity' as string]: 1 }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={cn('text-xs px-2 py-0.5 rounded', severityColors[detection.severity])}>
                          {detection.severity.toUpperCase()}
                        </span>
                        <span className={cn('text-xs px-2 py-0.5 rounded', ruleTypeColors[detection.ruleType])}>
                          {detection.ruleType.toUpperCase()}
                        </span>
                        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{detection.ruleName}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted)' }}>
                        <Clock className="h-3 w-3" />
                        {new Date(detection.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                    <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{detection.description}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                        <span>Host: {detection.hostname}</span>
                        <span>Confidence: {detection.confidence}%</span>
                      </div>
                      <div className="flex gap-1">
                        {(detection.mitreTechniques || []).map((tech) => (
                          <span
                            key={tech}
                            className="text-xs px-2 py-0.5 rounded font-mono"
                            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--emerald-400)' }}
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {selectedTab === 'rules' && (
          <div className="card-sentinel">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <FileCode className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Dynamic Rule Generation Status
              </h2>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {dynamicRules.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <FileCode className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No dynamic rules configured</p>
                </div>
              ) : (
                dynamicRules.map((rule) => (
                  <div key={rule.id} className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{rule.name}</h3>
                        <span className={cn('text-xs px-2 py-0.5 rounded', statusColors[rule.status])}>
                          {rule.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {rule.falsePositiveRate < 5 ? (
                          <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                        ) : rule.falsePositiveRate < 10 ? (
                          <AlertTriangle className="h-4 w-4" style={{ color: 'var(--high)' }} />
                        ) : (
                          <XCircle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                        )}
                        <span className="text-sm" style={{ color: 'var(--muted)' }}>FP Rate: {rule.falsePositiveRate}%</span>
                      </div>
                    </div>
                    <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{rule.description}</p>
                    <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Generated: {new Date(rule.generatedAt).toLocaleString()}
                      </span>
                      <span>Triggered: {rule.triggeredCount} times</span>
                      <span style={{ color: 'var(--emerald-400)' }}>Based on: {rule.basedOn}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {selectedTab === 'model' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-6 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Brain className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Model Information
              </h2>
              {mlMetricsLoading ? (
                <div className="space-y-4">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between p-3 rounded-lg"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-4 w-32" />
                    </div>
                  ))}
                </div>
              ) : mlMetricsError ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <AlertTriangle className="h-10 w-10 mx-auto mb-3 opacity-60" style={{ color: 'var(--high)' }} />
                  <p className="text-sm">Could not load ML metrics</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>{mlMetricsError}</p>
                  <button
                    onClick={fetchMLMetrics}
                    className="mt-3 text-xs underline"
                    style={{ color: 'var(--emerald-400)' }}
                  >
                    Retry
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
                    <span style={{ color: 'var(--muted)' }}>Model Name</span>
                    <span className="font-medium" style={{ color: 'var(--fg)' }}>{mlMetrics.modelName}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
                    <span style={{ color: 'var(--muted)' }}>Version</span>
                    <span className="font-mono" style={{ color: 'var(--fg)' }}>{mlMetrics.version}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
                    <span style={{ color: 'var(--muted)' }}>Last Trained</span>
                    <span style={{ color: 'var(--fg)' }}>{new Date(mlMetrics.lastTrained).toLocaleDateString()}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
                    <span style={{ color: 'var(--muted)' }}>Samples Processed</span>
                    <span style={{ color: 'var(--fg)' }}>{mlMetrics.samplesProcessed.toLocaleString()}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-2)' }}>
                    <span style={{ color: 'var(--muted)' }}>Inference Latency</span>
                    <span style={{ color: 'var(--fg)' }}>{mlMetrics.inferenceLatency}ms</span>
                  </div>
                </div>
              )}
            </div>

            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-6 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <BarChart2 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Performance Metrics
              </h2>
              {mlMetricsLoading ? (
                <div className="space-y-6">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i}>
                      <div className="flex items-center justify-between mb-2">
                        <Skeleton className="h-4 w-16" />
                        <Skeleton className="h-4 w-12" />
                      </div>
                      <Skeleton className="h-3 w-full rounded-full" />
                    </div>
                  ))}
                </div>
              ) : mlMetricsError ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <BarChart2 className="h-10 w-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">Metrics unavailable</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <MetricBar label="Accuracy" value={mlMetrics.accuracy} color="emerald" />
                  <MetricBar label="Precision" value={mlMetrics.precision} color="blue" />
                  <MetricBar label="Recall" value={mlMetrics.recall} color="purple" />
                  <MetricBar label="F1 Score" value={mlMetrics.f1Score} color="cyan" />
                </div>
              )}
            </div>
          </div>
        )}

        {selectedTab === 'threats' && (
          <div className="card-sentinel">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <AlertOctagon className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Emerging Threat Patterns
              </h2>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {emergingThreats.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <AlertOctagon className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No emerging threats detected</p>
                </div>
              ) : (
                emergingThreats.map((threat) => (
                  <div key={threat.id} className="p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{threat.name}</h3>
                          <span className={cn('text-xs px-2 py-0.5 rounded', severityColors[threat.riskLevel])}>
                            {threat.riskLevel.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                          <span>First seen: {new Date(threat.firstSeen).toLocaleString()}</span>
                          <span>{threat.occurrences} occurrences</span>
                          <span>{threat.affectedHosts} hosts affected</span>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        {(threat.mitreMapping || []).map((tech) => (
                          <span
                            key={tech}
                            className="text-xs px-2 py-0.5 rounded font-mono"
                            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--emerald-400)' }}
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="mt-3">
                      <p className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>Indicators:</p>
                      <div className="flex flex-wrap gap-2">
                        {(threat.indicators || []).map((indicator, idx) => (
                          <span
                            key={idx}
                            className="text-xs px-2 py-1 rounded"
                            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
                          >
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {selectedTab === 'gaps' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Coverage Overview */}
            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Detection Coverage
              </h2>
              <div className="text-center mb-6">
                <div className="text-4xl font-bold" style={{ color: 'var(--fg)' }}>{coverage.percentage.toFixed(1)}%</div>
                <div className="text-sm" style={{ color: 'var(--muted)' }}>{coverage.covered} of {coverage.total} techniques covered</div>
              </div>
              <div className="h-3 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${coverage.percentage}%`, backgroundColor: 'var(--emerald-500)' }}
                />
              </div>
            </div>

            {/* Proactive Hunts */}
            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Activity className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Proactive Hunts
              </h2>
              {proactiveHunts.length === 0 ? (
                <div className="text-center py-4" style={{ color: 'var(--subtle)' }}>No active hunts</div>
              ) : (
                <div className="space-y-3">
                  {proactiveHunts.map((hunt) => (
                    <div
                      key={hunt.id}
                      className="flex items-center justify-between p-3 rounded-lg"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{hunt.name}</p>
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>Last run: {new Date(hunt.lastRun).toLocaleDateString()}</p>
                      </div>
                      <div className="text-right">
                        <span className={cn(
                          'text-xs px-2 py-0.5 rounded',
                          hunt.status === 'running' ? 'badge-sentinel-info' : 'badge-sentinel-success'
                        )}>
                          {hunt.status}
                        </span>
                        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{hunt.findings} findings</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Blind Spots */}
            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                Blind Spots
              </h2>
              {blindSpots.length === 0 ? (
                <div className="text-center py-4" style={{ color: 'var(--subtle)' }}>No blind spots identified</div>
              ) : (
                <div className="space-y-3">
                  {blindSpots.map((spot) => (
                    <div
                      key={spot.id}
                      className="p-3 rounded-lg"
                      style={{ backgroundColor: 'var(--surface-2)', borderLeft: '3px solid var(--high)' }}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{spot.area}</p>
                        <span className={cn(
                          'text-xs px-2 py-0.5 rounded',
                          spot.risk === 'high' ? 'badge-sentinel-critical' :
                          spot.risk === 'medium' ? 'badge-sentinel-warning' : 'badge-sentinel-info'
                        )}>
                          {spot.risk}
                        </span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>{spot.recommendation}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recommendations */}
            <div className="card-sentinel p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                Recommendations
              </h2>
              {recommendations.length === 0 ? (
                <div className="text-center py-4" style={{ color: 'var(--subtle)' }}>No recommendations</div>
              ) : (
                <div className="space-y-3">
                  {recommendations.map((rec) => (
                    <div
                      key={rec.id}
                      className="p-3 rounded-lg"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{rec.title}</p>
                        <span className={cn(
                          'text-xs px-2 py-0.5 rounded',
                          rec.priority === 'high' ? 'badge-sentinel-critical' :
                          rec.priority === 'medium' ? 'badge-sentinel-warning' : 'badge-sentinel-info'
                        )}>
                          {rec.priority}
                        </span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>{rec.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}

interface MetricBarProps {
  label: string
  value: number
  color: 'emerald' | 'blue' | 'purple' | 'cyan'
}

function MetricBar({ label, value, color }: MetricBarProps) {
  const colorMap = {
    emerald: { bar: 'var(--emerald-500)', text: 'var(--emerald-400)' },
    blue: { bar: '#3b82f6', text: '#60a5fa' },
    purple: { bar: '#a855f7', text: '#c084fc' },
    cyan: { bar: '#06b6d4', text: '#22d3ee' },
  }

  const colors = colorMap[color]

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm" style={{ color: 'var(--muted)' }}>{label}</span>
        <span className="text-sm font-bold" style={{ color: colors.text }}>{value.toFixed(1)}%</span>
      </div>
      <div className="h-3 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-2)' }}>
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${value}%`, backgroundColor: colors.bar }}
        />
      </div>
    </div>
  )
}
