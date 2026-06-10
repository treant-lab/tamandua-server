import { useState } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
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
  inserted_at: string
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
  training: {
    available_datasets: string[]
    default_epochs: number
    default_batch_size: number
  }
}

export default function MLDashboard({
  service,
  model,
  statistics,
  recent_alerts: recentAlerts,
  training,
}: MLDashboardProps) {
  const [trainingDataset, setTrainingDataset] = useState(
    training?.available_datasets?.[0] || ''
  )
  const [epochs, setEpochs] = useState(training?.default_epochs || 50)
  const [batchSize, setBatchSize] = useState(training?.default_batch_size || 32)
  const [isTraining, setIsTraining] = useState(false)
  const [trainingError, setTrainingError] = useState<string | null>(null)

  const stats = statistics || { total_predictions: 0, total_detections: 0, alerts_created: 0 }
  const alerts = recentAlerts || []
  const isModelTrained = model != null && model.trained

  const handleStartTraining = async () => {
    setIsTraining(true)
    setTrainingError(null)
    try {
      const response = await fetch('/api/v1/ml/train', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
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
                          {formatDate(alert.inserted_at)}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
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
                <select
                  value={trainingDataset}
                  onChange={(e) => setTrainingDataset(e.target.value)}
                  disabled={isTraining}
                  className="w-full rounded-lg px-4 py-2 focus:ring-2 focus:ring-offset-0 disabled:opacity-50"
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                >
                  {(training?.available_datasets || []).length === 0 ? (
                    <option value="">No datasets available</option>
                  ) : (
                    (training?.available_datasets || []).map((ds) => (
                      <option key={ds} value={ds}>
                        {ds}
                      </option>
                    ))
                  )}
                </select>
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
