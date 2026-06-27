import { useEffect, useState } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { Select, SelectItem } from '@/components/ui/baseui'
import { logger } from '@/lib/logger'
import {
  Brain,
  Activity,
  AlertTriangle,
  BarChart3,
  Clock,
  Cpu,
  Database,
  Play,
  Server,
  Loader2,
  ExternalLink,
  GitBranch,
} from 'lucide-react'
import { cn, formatDate, severityColor } from '@/lib/utils'

interface MLModel {
  version: string
  encoder: string
  latent_dim: number
  similarity_markers: number
  dissimilarity_markers: number
  training_samples: number
  accuracy: number
  zsl_recall: number
  device: string
  trained: boolean
}

interface RecentAlert {
  id: string
  title: string
  severity: string
  inserted_at?: string
  created_at?: string
}

interface RecentPrediction {
  id: string
  alert_id?: string
  agent_id?: string
  prediction?: string
  malware_family?: string
  model_version?: string
  model_runtime?: string
  source?: string
  confidence?: number | string | null
  threat_score?: number | string | null
  timestamp?: string
}

interface MLLifecycleStats {
  model_manager?: Record<string, unknown>
  feedback?: Record<string, unknown>
  training_scheduler?: Record<string, unknown>
}

interface MLLifecycleModel {
  model_type: string
  version: string
  status: string
  registered_at?: string
  promoted_at?: string | null
  retired_at?: string | null
  metadata?: Record<string, unknown>
  metrics?: {
    precision?: number
    recall?: number
    f1?: number
    fpr?: number
    total_predictions?: number
    last_updated?: string
  } | null
}

interface MLCanaryStatus {
  model_type: string
  active?: boolean
  canary_version?: string
  traffic_pct?: number
  message?: string
}

interface MLDashboardProps {
  service: {
    healthy: boolean
    url: string
  }
  model: MLModel | null
  statistics: {
    total_predictions: number
    total_detections: number
    alerts_created: number
  }
  recent_alerts: RecentAlert[]
  recent_predictions?: RecentPrediction[]
  training: {
    available_datasets: string[]
    default_epochs: number
    default_batch_size: number
  }
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

export default function MLDashboard({
  service,
  model,
  statistics,
  recent_alerts: recentAlerts,
  recent_predictions: recentPredictions = [],
  training,
}: MLDashboardProps) {
  const [trainingDataset, setTrainingDataset] = useState(
    training?.available_datasets?.[0] || ''
  )
  const [epochs, setEpochs] = useState(training?.default_epochs || 50)
  const [batchSize, setBatchSize] = useState(training?.default_batch_size || 32)
  const [isTraining, setIsTraining] = useState(false)
  const [trainingError, setTrainingError] = useState<string | null>(null)
  const [predictionHistory, setPredictionHistory] = useState<RecentPrediction[]>(recentPredictions || [])
  const [predictionHistoryError, setPredictionHistoryError] = useState<string | null>(null)
  const [lifecycleStats, setLifecycleStats] = useState<MLLifecycleStats | null>(null)
  const [lifecycleError, setLifecycleError] = useState<string | null>(null)
  const [lifecycleModels, setLifecycleModels] = useState<MLLifecycleModel[]>([])
  const [lifecycleModelsError, setLifecycleModelsError] = useState<string | null>(null)
  const [canaryStatuses, setCanaryStatuses] = useState<MLCanaryStatus[]>([])

  const stats = statistics || { total_predictions: 0, total_detections: 0, alerts_created: 0 }
  const alerts = recentAlerts || []
  const predictions = predictionHistory.length > 0 ? predictionHistory : recentPredictions || []
  const isModelTrained = model != null && model.trained

  const formatScore = (value: number | string | null | undefined) => {
    const numeric = Number(value)
    if (!Number.isFinite(numeric)) return 'n/a'
    return numeric <= 1 ? `${Math.round(numeric * 100)}%` : `${Math.round(numeric)}`
  }

  const formatCount = (value: unknown, unavailable = false) => {
    if (unavailable || value === undefined || value === null || value === '') return '--'
    const numeric = Number(value)
    return Number.isFinite(numeric) ? numeric.toLocaleString() : '--'
  }

  const metricValue = (section: keyof MLLifecycleStats, key: string) =>
    lifecycleStats?.[section]?.[key]

  const lifecycleUnavailable = Boolean(lifecycleError) || lifecycleStats === null

  const openOperationalView = (href: string) => {
    window.location.assign(href)
  }

  const formatLifecycleMetric = (value: number | null | undefined, suffix = '%') => {
    if (value === undefined || value === null || !Number.isFinite(Number(value))) return '--'
    return `${Number(value).toFixed(value < 1 ? 2 : 1)}${suffix}`
  }

  const runtimeLabel = (prediction: RecentPrediction) =>
    String(prediction.model_runtime || prediction.source || 'ml').toLowerCase() === 'onnx'
      ? 'ONNX'
      : 'ML'

  const lifecycleStatusStyle = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-500/20 text-green-400'
      case 'canary':
        return 'bg-blue-500/20 text-blue-400'
      case 'training':
      case 'validating':
        return 'bg-yellow-500/20 text-yellow-400'
      case 'retired':
        return 'bg-[var(--surface-elevated)] text-[var(--muted)]'
      default:
        return 'bg-[var(--surface-elevated)] text-[var(--fg)]'
    }
  }

  const canaryFor = (modelType: string) =>
    canaryStatuses.find((status) => status.model_type === modelType)

  const handleStartTraining = async () => {
    setIsTraining(true)
    setTrainingError(null)
    try {
      const response = await fetch('/api/v1/ml/train', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(getCsrfToken() ? { 'X-CSRF-Token': getCsrfToken() } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({
          dataset: trainingDataset,
          epochs,
          batch_size: batchSize,
        }),
      })
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || `Training request failed (status ${response.status})`)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start training'
      setTrainingError(message)
      logger.error('Training error:', err)
    } finally {
      setIsTraining(false)
    }
  }

  useEffect(() => {
    let cancelled = false

    async function loadLifecycleStats() {
      try {
        const response = await fetch('/api/v1/ml/lifecycle/stats', {
          headers: { Accept: 'application/json' },
          credentials: 'include',
        })

        if (!response.ok) {
          throw new Error(`ML lifecycle stats failed (status ${response.status})`)
        }

        const payload = await response.json()

        if (!cancelled) {
          setLifecycleStats(payload?.data || null)
          setLifecycleError(null)
        }
      } catch (err) {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : 'Failed to load ML lifecycle stats'
          setLifecycleError(message)
          logger.warn('ML lifecycle stats load failed:', err)
        }
      }
    }

    async function loadLifecycleModels() {
      try {
        const [modelsResponse, canaryResponse] = await Promise.all([
          fetch('/api/v1/ml/lifecycle/models', {
            headers: { Accept: 'application/json' },
            credentials: 'include',
          }),
          fetch('/api/v1/ml/lifecycle/canary/status', {
            headers: { Accept: 'application/json' },
            credentials: 'include',
          }),
        ])

        if (!modelsResponse.ok) {
          throw new Error(`ML lifecycle models failed (status ${modelsResponse.status})`)
        }

        const modelsPayload = await modelsResponse.json()
        const canaryPayload = canaryResponse.ok ? await canaryResponse.json() : { data: [] }

        if (!cancelled) {
          setLifecycleModels(Array.isArray(modelsPayload?.data) ? modelsPayload.data : [])
          setCanaryStatuses(Array.isArray(canaryPayload?.data) ? canaryPayload.data : [])
          setLifecycleModelsError(canaryResponse.ok ? null : `Canary status failed (status ${canaryResponse.status})`)
        }
      } catch (err) {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : 'Failed to load ML lifecycle models'
          setLifecycleModelsError(message)
          logger.warn('ML lifecycle models load failed:', err)
        }
      }
    }

    async function loadPredictionHistory() {
      try {
        const response = await fetch('/api/v1/ml/predictions/history?limit=50', {
          headers: { Accept: 'application/json' },
          credentials: 'include',
        })

        if (!response.ok) {
          throw new Error(`Prediction history failed (status ${response.status})`)
        }

        const payload = await response.json()
        const rows = Array.isArray(payload?.data) ? payload.data : []

        if (!cancelled) {
          setPredictionHistory(rows.map((row: RecentPrediction) => ({
            ...row,
            alert_id: row.alert_id || row.id,
            timestamp: row.timestamp,
          })))
          setPredictionHistoryError(null)
        }
      } catch (err) {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : 'Failed to load ML prediction history'
          setPredictionHistoryError(message)
          logger.warn('ML prediction history load failed:', err)
        }
      }
    }

    loadLifecycleStats()
    loadLifecycleModels()
    loadPredictionHistory()

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <MainLayout title="ML Dashboard">
      <Head title="ML Dashboard - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
            ML Dashboard
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            Malware-SMELL model status, statistics, and training
          </p>
        </div>

        {/* Service Health */}
        <div className="card-sentinel rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              <span className="font-medium" style={{ color: 'var(--fg)' }}>
                ML Service
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span
                className="text-sm font-mono"
                style={{ color: 'var(--muted)' }}
              >
                {service?.url}
              </span>
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium'
                )}
                style={{
                  backgroundColor: service?.healthy
                    ? 'rgba(var(--emerald-400-rgb, 52, 211, 153), 0.2)'
                    : 'rgba(var(--crit-rgb, 239, 68, 68), 0.2)',
                  color: service?.healthy ? 'var(--emerald-400)' : 'var(--crit)',
                }}
              >
                <span
                  className="h-2 w-2 rounded-full"
                  style={{
                    backgroundColor: service?.healthy
                      ? 'var(--emerald-400)'
                      : 'var(--crit)',
                  }}
                />
                {service?.healthy ? 'Healthy' : 'Unhealthy'}
              </span>
            </div>
          </div>
        </div>

        {/* Model Info + Statistics */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Model Info */}
          <div className="card-sentinel rounded-xl">
            <div
              className="p-4 border-b"
              style={{ borderColor: 'var(--border)' }}
            >
              <h2
                className="text-lg font-semibold flex items-center gap-2"
                style={{ color: 'var(--fg)' }}
              >
                <Brain className="h-5 w-5" style={{ color: 'var(--primary)' }} />
                Model Info
              </h2>
            </div>
            {isModelTrained ? (
              <div className="p-4 grid grid-cols-2 gap-4">
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Version
                  </p>
                  <p
                    className="text-sm font-medium"
                    style={{ color: 'var(--fg)' }}
                  >
                    {model.version}
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Encoder
                  </p>
                  <p
                    className="text-sm font-medium"
                    style={{ color: 'var(--fg)' }}
                  >
                    {model.encoder}
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Device
                  </p>
                  <p
                    className="text-sm font-medium flex items-center gap-1.5"
                    style={{ color: 'var(--fg)' }}
                  >
                    <Cpu className="h-3.5 w-3.5" style={{ color: 'var(--muted)' }} />
                    {model.device}
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Latent Dim
                  </p>
                  <p
                    className="text-sm font-medium"
                    style={{ color: 'var(--fg)' }}
                  >
                    {model.latent_dim}
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Accuracy
                  </p>
                  <p
                    className="text-sm font-bold"
                    style={{ color: 'var(--emerald-400)' }}
                  >
                    {(model.accuracy * 100).toFixed(1)}%
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    ZSL Recall
                  </p>
                  <p
                    className="text-sm font-bold"
                    style={{ color: 'var(--emerald-400)' }}
                  >
                    {(model.zsl_recall * 100).toFixed(1)}%
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Training Samples
                  </p>
                  <p
                    className="text-sm font-medium"
                    style={{ color: 'var(--fg)' }}
                  >
                    {model.training_samples.toLocaleString()}
                  </p>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{ backgroundColor: 'var(--surface-elevated)' }}
                >
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>
                    Markers
                  </p>
                  <p
                    className="text-sm font-medium"
                    style={{ color: 'var(--fg)' }}
                  >
                    {model.similarity_markers}S / {model.dissimilarity_markers}D
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p className="text-lg">Model not trained</p>
                <p className="text-sm mt-1">
                  Train the Malware-SMELL model using the training section below
                </p>
              </div>
            )}
          </div>

          {/* Statistics */}
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4">
              <div className="card-sentinel rounded-xl p-4">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2 rounded-lg"
                    style={{ backgroundColor: 'rgba(59, 130, 246, 0.2)' }}
                  >
                    <Activity className="h-5 w-5" style={{ color: '#60a5fa' }} />
                  </div>
                  <div>
                    <p
                      className="text-2xl font-bold"
                      style={{ color: 'var(--fg)' }}
                    >
                      {stats.total_predictions.toLocaleString()}
                    </p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>
                      Total Predictions
                    </p>
                  </div>
                </div>
              </div>
              <div className="card-sentinel rounded-xl p-4">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2 rounded-lg"
                    style={{ backgroundColor: 'rgba(var(--high-rgb, 249, 115, 22), 0.2)' }}
                  >
                    <BarChart3 className="h-5 w-5" style={{ color: 'var(--high)' }} />
                  </div>
                  <div>
                    <p
                      className="text-2xl font-bold"
                      style={{ color: 'var(--fg)' }}
                    >
                      {stats.total_detections.toLocaleString()}
                    </p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>
                      Total Detections
                    </p>
                  </div>
                </div>
              </div>
              <div className="card-sentinel rounded-xl p-4">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2 rounded-lg"
                    style={{ backgroundColor: 'rgba(var(--crit-rgb, 239, 68, 68), 0.2)' }}
                  >
                    <AlertTriangle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                  </div>
                  <div>
                    <p
                      className="text-2xl font-bold"
                      style={{ color: 'var(--fg)' }}
                    >
                      {stats.alerts_created.toLocaleString()}
                    </p>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>
                      Alerts Created
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Agent ONNX / ML Predictions */}
        <div className="card-sentinel rounded-xl">
          <div
            className="p-4 border-b"
            style={{ borderColor: 'var(--border)' }}
          >
            <h2
              className="text-lg font-semibold"
              style={{ color: 'var(--fg)' }}
            >
              Agent ONNX / ML Predictions
            </h2>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Recent detections attributed to the ML pipeline and offline agent model.
            </p>
            {predictionHistoryError && (
              <p className="text-xs mt-2" style={{ color: 'var(--amber-400)' }}>
                Live history unavailable; showing server-rendered ML alert snapshot.
              </p>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Prediction
                  </th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Confidence
                  </th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Family
                  </th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Model
                  </th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Agent
                  </th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {predictions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                      <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>{predictionHistoryError ? 'ML prediction history unavailable' : 'No ML prediction history found'}</p>
                      <p className="text-sm mt-1">
                        {predictionHistoryError
                          ? 'Prediction history could not be loaded. Server-rendered ML alert data is also empty.'
                          : 'Agent ONNX and ML service detections will appear here when alerts carry ML metadata.'}
                      </p>
                    </td>
                  </tr>
                ) : (
                  predictions.map((prediction) => (
                    <tr
                      key={prediction.id}
                      className="hover:opacity-80 cursor-pointer transition-colors"
                      style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      onClick={() => prediction.alert_id && (window.location.href = `/app/alerts/${prediction.alert_id}`)}
                    >
                      <td className="p-4">
                        <span className="badge-sentinel badge-sentinel-default">
                          {(prediction.prediction || 'ml_detection').replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-sm" style={{ color: 'var(--fg)' }}>
                        {formatScore(prediction.confidence)}
                      </td>
                      <td className="p-4 text-sm" style={{ color: 'var(--fg)' }}>
                        {prediction.malware_family || 'unknown'}
                      </td>
                      <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>
                        <div className="flex items-center gap-2">
                          <span className="font-mono">{prediction.model_version || model?.version || 'not reported'}</span>
                          <span className="badge-sentinel badge-sentinel-pill font-semibold">
                            {runtimeLabel(prediction)}
                          </span>
                        </div>
                      </td>
                      <td className="p-4 text-sm font-mono" style={{ color: 'var(--muted)' }}>
                        {prediction.agent_id || 'n/a'}
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
                          <Clock className="h-4 w-4" />
                          {formatDate(prediction.timestamp)}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent ML Alerts */}
        <div className="card-sentinel rounded-xl">
          <div
            className="p-4 border-b"
            style={{ borderColor: 'var(--border)' }}
          >
            <h2
              className="text-lg font-semibold"
              style={{ color: 'var(--fg)' }}
            >
              Recent ML Alerts
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th
                    className="text-left p-4 text-sm font-medium"
                    style={{ color: 'var(--muted)' }}
                  >
                    Title
                  </th>
                  <th
                    className="text-left p-4 text-sm font-medium"
                    style={{ color: 'var(--muted)' }}
                  >
                    Severity
                  </th>
                  <th
                    className="text-left p-4 text-sm font-medium"
                    style={{ color: 'var(--muted)' }}
                  >
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td
                      colSpan={3}
                      className="p-8 text-center"
                      style={{ color: 'var(--muted)' }}
                    >
                      <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No recent ML alerts</p>
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className="hover:opacity-80 cursor-pointer transition-colors"
                      style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      onClick={() => (window.location.href = `/app/alerts/${alert.id}`)}
                    >
                      <td className="p-4" style={{ color: 'var(--fg)' }}>
                        {alert.title}
                      </td>
                      <td className="p-4">
                        <span
                          className={cn(
                            'text-xs px-2 py-0.5 rounded',
                            severityColor(alert.severity)
                          )}
                        >
                          {alert.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-4">
                        <div
                          className="flex items-center gap-2 text-sm"
                          style={{ color: 'var(--muted)' }}
                        >
                          <Clock className="h-4 w-4" />
                          {formatDate(alert.inserted_at || alert.created_at)}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Model Operations */}
        <div className="card-sentinel rounded-xl">
          <div
            className="p-4 border-b"
            style={{ borderColor: 'var(--border)' }}
          >
            <h2
              className="text-lg font-semibold flex items-center gap-2"
              style={{ color: 'var(--fg)' }}
            >
              <GitBranch className="h-5 w-5" style={{ color: 'var(--primary)' }} />
              Model Operations
            </h2>
          </div>
          <div className="p-6 space-y-4">
            {lifecycleError && (
              <div
                className="rounded-lg px-4 py-3 text-sm"
                style={{
                  backgroundColor: 'rgba(var(--warn-rgb, 245, 158, 11), 0.1)',
                  border: '1px solid rgba(var(--warn-rgb, 245, 158, 11), 0.3)',
                  color: 'var(--warn)',
                }}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  <span>{lifecycleError}</span>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-elevated)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>Registered Models</span>
                  <Brain className="h-4 w-4" style={{ color: 'var(--primary)' }} />
                </div>
                <p className="mt-2 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
                  {formatCount(metricValue('model_manager', 'model_count'), lifecycleUnavailable)}
                </p>
              </div>
              <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-elevated)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>Predictions</span>
                  <Activity className="h-4 w-4" style={{ color: 'var(--primary)' }} />
                </div>
                <p className="mt-2 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
                  {formatCount(metricValue('model_manager', 'prediction_count'), lifecycleUnavailable)}
                </p>
              </div>
              <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-elevated)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>Feedback Items</span>
                  <BarChart3 className="h-4 w-4" style={{ color: 'var(--primary)' }} />
                </div>
                <p className="mt-2 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
                  {formatCount(metricValue('feedback', 'feedback_count'), lifecycleUnavailable)}
                </p>
              </div>
              <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-elevated)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>Active Jobs</span>
                  <Clock className="h-4 w-4" style={{ color: 'var(--primary)' }} />
                </div>
                <p className="mt-2 text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
                  {formatCount(metricValue('training_scheduler', 'active_jobs'), lifecycleUnavailable)}
                </p>
              </div>
            </div>

            <div
              className="overflow-hidden rounded-lg"
              style={{
                border: '1px solid var(--border)',
                backgroundColor: 'var(--surface-elevated)',
              }}
            >
              <div
                className="flex flex-col gap-2 p-4 md:flex-row md:items-center md:justify-between"
                style={{ borderBottom: '1px solid var(--border)' }}
              >
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                    Model Registry
                  </h3>
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                    Lifecycle state for registered ML detection models.
                  </p>
                </div>
                {lifecycleModelsError && (
                  <span className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs" style={{ color: 'var(--warn)' }}>
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {lifecycleModelsError}
                  </span>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Model</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Version</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Precision</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Recall</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>FPR</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Canary</th>
                      <th className="p-3 text-left font-medium" style={{ color: 'var(--muted)' }}>Registered</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lifecycleModels.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="p-6 text-center" style={{ color: 'var(--muted)' }}>
                          {lifecycleModelsError
                            ? 'Model lifecycle registry is unavailable.'
                            : 'No ML model versions have been registered yet.'}
                        </td>
                      </tr>
                    ) : (
                      lifecycleModels.map((registryModel) => {
                        const canary = canaryFor(registryModel.model_type)
                        return (
                          <tr
                            key={`${registryModel.model_type}:${registryModel.version}`}
                            style={{ borderBottom: '1px solid var(--border-subtle)' }}
                          >
                            <td className="p-3 font-mono" style={{ color: 'var(--fg)' }}>
                              {registryModel.model_type}
                            </td>
                            <td className="p-3 font-mono" style={{ color: 'var(--fg)' }}>
                              {registryModel.version}
                            </td>
                            <td className="p-3">
                              <span className={cn('rounded px-2 py-0.5 text-xs font-medium', lifecycleStatusStyle(registryModel.status))}>
                                {registryModel.status || 'unknown'}
                              </span>
                            </td>
                            <td className="p-3 font-mono" style={{ color: 'var(--muted)' }}>
                              {formatLifecycleMetric(registryModel.metrics?.precision)}
                            </td>
                            <td className="p-3 font-mono" style={{ color: 'var(--muted)' }}>
                              {formatLifecycleMetric(registryModel.metrics?.recall)}
                            </td>
                            <td className="p-3 font-mono" style={{ color: 'var(--muted)' }}>
                              {formatLifecycleMetric(registryModel.metrics?.fpr)}
                            </td>
                            <td className="p-3" style={{ color: 'var(--muted)' }}>
                              {canary?.active || canary?.canary_version
                                ? `${canary.canary_version || 'canary'} @ ${canary.traffic_pct ?? 10}%`
                                : 'none'}
                            </td>
                            <td className="p-3" style={{ color: 'var(--muted)' }}>
                              {formatDate(registryModel.registered_at)}
                            </td>
                          </tr>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {[
                { label: 'AI Models', href: '/live/ai-security/models', icon: Brain },
                { label: 'ML Processes', href: '/live/ml-processes', icon: Cpu },
                { label: 'AI Runtime', href: '/live/ai/runtime', icon: Activity },
                { label: 'Registries', href: '/live/registries', icon: Database },
              ].map((item) => (
                <button
                  key={item.href}
                  type="button"
                  onClick={() => openOperationalView(item.href)}
                  className="flex items-center justify-between gap-3 rounded-lg px-4 py-3 text-sm transition-colors"
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                >
                  <span className="flex items-center gap-2">
                    <item.icon className="h-4 w-4" style={{ color: 'var(--primary)' }} />
                    {item.label}
                  </span>
                  <ExternalLink className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Training Section */}
        <div className="card-sentinel rounded-xl">
          <div
            className="p-4 border-b"
            style={{ borderColor: 'var(--border)' }}
          >
            <h2
              className="text-lg font-semibold flex items-center gap-2"
              style={{ color: 'var(--fg)' }}
            >
              <Database className="h-5 w-5" style={{ color: 'var(--primary)' }} />
              Training
            </h2>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Train or retrain the Malware-SMELL model
            </p>
          </div>
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--fg)' }}
                >
                  Dataset
                </label>
                <Select
                  value={trainingDataset}
                  onValueChange={setTrainingDataset}
                  disabled={isTraining}
                  placeholder="Dataset"
                  className="rounded-lg px-4 py-2 focus:ring-2 focus:ring-offset-0"
                  fullWidth
                >
                  {(training?.available_datasets || []).length === 0 ? (
                    <SelectItem value="">No datasets available</SelectItem>
                  ) : (
                    (training?.available_datasets || []).map((ds) => (
                      <SelectItem key={ds} value={ds}>
                        {ds}
                      </SelectItem>
                    ))
                  )}
                </Select>
              </div>
              <div>
                <label
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--fg)' }}
                >
                  Epochs
                </label>
                <input
                  type="number"
                  value={epochs}
                  onChange={(e) => setEpochs(parseInt(e.target.value) || 0)}
                  disabled={isTraining}
                  className="w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-offset-0 disabled:opacity-50"
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                />
              </div>
              <div>
                <label
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--fg)' }}
                >
                  Batch Size
                </label>
                <input
                  type="number"
                  value={batchSize}
                  onChange={(e) => setBatchSize(parseInt(e.target.value) || 0)}
                  disabled={isTraining}
                  className="w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-offset-0 disabled:opacity-50"
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                />
              </div>
            </div>

            {trainingError && (
              <div
                className="rounded-lg px-4 py-3 text-sm"
                style={{
                  backgroundColor: 'rgba(var(--crit-rgb, 239, 68, 68), 0.1)',
                  border: '1px solid rgba(var(--crit-rgb, 239, 68, 68), 0.3)',
                  color: 'var(--crit)',
                }}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  <span>{trainingError}</span>
                </div>
              </div>
            )}

            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleStartTraining}
                disabled={isTraining || !trainingDataset}
                className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium disabled:opacity-50 transition-colors"
                style={{
                  backgroundColor: 'var(--primary)',
                  color: 'var(--fg)',
                }}
              >
                {isTraining ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                {isTraining ? 'Training...' : 'Start Training'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
