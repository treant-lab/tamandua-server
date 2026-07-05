import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Activity,
  ArrowRight,
  CheckCircle,
  XCircle,
  AlertTriangle,
  TrendingUp,
  Clock,
  Settings,
  RefreshCw,
  Zap,
  Brain,
  Link2,
  BarChart3,
  Server,
  Database,
} from 'lucide-react'
import { useState } from 'react'
import {
  cn,
  formatLatency,
  formatNumber,
  formatPercent,
  formatThousands,
} from '@/lib/utils'

// Backend may not yet instrument every numeric field. Optional + nullable
// fields are rendered through the formatNumber/formatPercent/formatThousands/
// formatLatency helpers, which render "—" for undefined/null/NaN instead of
// the literal string "NaN" — see src/lib/utils.ts.
interface SIEMConnection {
  id: string
  name: string
  type: 'splunk' | 'elasticsearch' | 'azure_sentinel' | 'qradar' | 'chronicle' | 'internal' | 'threat_intel'
  status: 'connected' | 'disconnected' | 'error' | 'syncing'
  lastSync?: string | null
  eventsForwarded?: number | null
  eventsPerSecond?: number | null
  latencyMs?: number | null
}

interface CorrelationRule {
  id: string
  name: string
  description: string
  enabled: boolean
  matches?: number | null
  lastTriggered?: string | null
  confidence?: number | null
}

interface EnrichmentSource {
  id: string
  name: string
  type: string
  status: 'active' | 'inactive' | 'error' | 'no_data' | 'unavailable'
  enrichmentsPerformed?: number | null
  avgLatency?: number | null
}

interface DiscoveredPattern {
  id: string
  name: string
  description: string
  occurrences?: number | null
  severity: string
}

interface AlertCorrelation {
  id: string
  alerts: string[]
  pattern: string
  confidence?: number | null
}

interface NoiseMetrics {
  totalAlerts?: number | null
  filteredAlerts?: number | null
  reductionPercentage?: number | null
}

interface IntelligentAlert {
  id: string
  title: string
  severity: string
  confidence?: number | null
  relatedEvents?: number | null
}

interface AISIEMStats {
  totalEventsForwarded?: number | null
  correlationsDetected?: number | null
  enrichedAlerts?: number | null
  avgProcessingTime?: number | null
}

interface AISIEMPageProps {
  discoveredPatterns?: DiscoveredPattern[]
  alertCorrelations?: AlertCorrelation[]
  noiseMetrics?: NoiseMetrics
  intelligentAlerts?: IntelligentAlert[]
  connections?: SIEMConnection[]
  correlationRules?: CorrelationRule[]
  enrichmentSources?: EnrichmentSource[]
  stats?: AISIEMStats
}

// Default values
const defaultStats: AISIEMStats = {
  totalEventsForwarded: 0,
  correlationsDetected: 0,
  enrichedAlerts: 0,
  avgProcessingTime: 0,
}

const defaultNoiseMetrics: NoiseMetrics = {
  totalAlerts: 0,
  filteredAlerts: 0,
  reductionPercentage: 0,
}

export default function AISIEM({
  discoveredPatterns = [],
  alertCorrelations = [],
  noiseMetrics = defaultNoiseMetrics,
  intelligentAlerts = [],
  connections = [],
  correlationRules = [],
  enrichmentSources = [],
  stats = defaultStats,
}: AISIEMPageProps) {
  const [selectedConnection, setSelectedConnection] = useState<string | null>(null)

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
      case 'active':
        return 'badge-sentinel-success'
      case 'disconnected':
      case 'inactive':
        return 'badge-sentinel-default'
      case 'error':
        return 'badge-sentinel-error'
      case 'syncing':
        return 'badge-sentinel-warning'
      default:
        return 'badge-sentinel-default'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
      case 'active':
        return <CheckCircle className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
      case 'error':
        return <XCircle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
      case 'syncing':
        return <RefreshCw className="h-4 w-4 animate-spin" style={{ color: 'var(--high)' }} />
      default:
        return <AlertTriangle className="h-4 w-4" style={{ color: 'var(--muted)' }} />
    }
  }

  const getSIEMIcon = (type: string) => {
    switch (type) {
      case 'splunk':
        return 'SPL'
      case 'elasticsearch':
        return 'ELK'
      case 'azure_sentinel':
        return 'AZR'
      case 'qradar':
        return 'QR'
      case 'chronicle':
        return 'GC'
      default:
        return '?'
    }
  }

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'badge-sentinel-critical'
      case 'high':
        return 'badge-sentinel-high'
      case 'medium':
        return 'badge-sentinel-medium'
      case 'low':
        return 'badge-sentinel-low'
      default:
        return 'badge-sentinel-info'
    }
  }

  return (
    <MainLayout title="AI SIEM Integration">
      <Head title="AI SIEM - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Events Forwarded</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{formatNumber(stats.totalEventsForwarded)}</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ background: 'var(--med-bg)' }}>
                <ArrowRight className="h-6 w-6" style={{ color: 'var(--med)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>AI Correlations</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{formatNumber(stats.correlationsDetected)}</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ background: 'rgba(217, 70, 239, 0.12)' }}>
                <Brain className="h-6 w-6" style={{ color: 'var(--sol-magenta)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Enriched Alerts</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{formatNumber(stats.enrichedAlerts)}</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ background: 'var(--emerald-glow)' }}>
                <Zap className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Avg Processing Time</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{formatLatency(stats.avgProcessingTime)}</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ background: 'var(--high-bg)' }}>
                <Clock className="h-6 w-6" style={{ color: 'var(--high)' }} />
              </div>
            </div>
          </div>
        </div>

        {/* SIEM Connections */}
        <div className="card-sentinel p-0">
          <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
            <div className="flex items-center gap-2">
              <Link2 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              <h2 className="card-sentinel-title">Connected SIEMs</h2>
            </div>
            <button
              type="button"
              onClick={() => router.visit('/app/integrations')}
              className="btn-sentinel btn-sentinel-primary btn-sentinel-sm flex items-center gap-2"
            >
              <Server className="h-4 w-4" />
              Add Connection
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
            {connections.length === 0 ? (
              <div className="col-span-2 p-12 text-center" style={{ color: 'var(--subtle)' }}>
                <Link2 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No SIEM connections configured</p>
              </div>
            ) : (
              connections.map((connection) => (
                <div
                  key={connection.id}
                  onClick={() => setSelectedConnection(selectedConnection === connection.id ? null : connection.id)}
                  className={cn(
                    'rounded-xl p-4 border transition-colors cursor-pointer',
                    selectedConnection === connection.id
                      ? 'border-emerald-500'
                      : 'hover:border-[var(--border-strong)]'
                  )}
                  style={{
                    background: 'var(--surface-2)',
                    borderColor: selectedConnection === connection.id ? 'var(--emerald-500)' : 'var(--border)',
                  }}
                >
                  <div className="flex items-start gap-4">
                    <div
                      className="h-12 w-12 rounded-lg flex items-center justify-center font-bold text-sm"
                      style={{ background: 'var(--surface-3)', color: 'var(--muted)' }}
                    >
                      {getSIEMIcon(connection.type)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium" style={{ color: 'var(--fg)' }}>{connection.name}</span>
                        <div className="flex items-center gap-1">
                          {getStatusIcon(connection.status)}
                          <span className={cn('badge-sentinel badge-sentinel-pill', getStatusColor(connection.status))}>
                            {connection.status}
                          </span>
                        </div>
                      </div>
                      <p className="text-sm capitalize" style={{ color: 'var(--muted)' }}>{connection.type.replace('_', ' ')}</p>

                      <div className="grid grid-cols-3 gap-4 mt-3 pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
                        <div>
                          <p className="text-xs" style={{ color: 'var(--subtle)' }}>Events/sec</p>
                          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{formatNumber(connection.eventsPerSecond)}</p>
                        </div>
                        <div>
                          <p className="text-xs" style={{ color: 'var(--subtle)' }}>Latency</p>
                          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{formatLatency(connection.latencyMs)}</p>
                        </div>
                        <div>
                          <p className="text-xs" style={{ color: 'var(--subtle)' }}>Total</p>
                          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{formatThousands(connection.eventsForwarded)}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {selectedConnection === connection.id && (
                    <div className="mt-4 pt-4 flex gap-2" style={{ borderTop: '1px solid var(--hairline)' }}>
                      <button
                        type="button"
                        onClick={() => router.visit('/app/integrations')}
                        className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm flex-1 flex items-center justify-center gap-2"
                      >
                        <Settings className="h-4 w-4" />
                        Configure
                      </button>
                      <button
                        type="button"
                        onClick={() => router.reload({ only: ['connections', 'stats'] })}
                        className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm flex-1 flex items-center justify-center gap-2"
                      >
                        <RefreshCw className="h-4 w-4" />
                        Test
                      </button>
                      <button
                        type="button"
                        onClick={() => router.visit('/app/detection-analytics')}
                        className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm flex-1 flex items-center justify-center gap-2"
                      >
                        <BarChart3 className="h-4 w-4" />
                        Metrics
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* AI Correlation Rules & Enrichment */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* AI Correlation Rules */}
          <div className="card-sentinel p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-2">
                <Brain className="h-5 w-5" style={{ color: 'var(--sol-magenta)' }} />
                <h2 className="card-sentinel-title">AI Correlation Rules</h2>
              </div>
              <button
                type="button"
                onClick={() => router.visit('/app/detection-rules')}
                className="text-sm font-medium"
                style={{ color: 'var(--emerald-400)' }}
              >
                Manage Rules
              </button>
            </div>

            <div className="divide-y max-h-[400px] overflow-y-auto" style={{ borderColor: 'var(--hairline)' }}>
              {correlationRules.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No correlation rules configured</p>
                </div>
              ) : (
                correlationRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-4 transition-colors"
                    style={{ background: 'transparent' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-2 h-2 rounded-full"
                          style={{ background: rule.enabled ? 'var(--emerald-400)' : 'var(--subtle)' }}
                        />
                        <span className="font-medium" style={{ color: 'var(--fg)' }}>{rule.name}</span>
                      </div>
                      <span className="badge-sentinel badge-sentinel-sol-magenta">
                        {formatPercent(rule.confidence)} confidence
                      </span>
                    </div>
                    <p className="text-sm mb-2" style={{ color: 'var(--muted)' }}>{rule.description}</p>
                    <div className="flex items-center justify-between text-xs" style={{ color: 'var(--subtle)' }}>
                      <span className="flex items-center gap-1">
                        <Activity className="h-3 w-3" />
                        {formatNumber(rule.matches)} matches
                      </span>
                      {rule.lastTriggered && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(rule.lastTriggered).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Alert Enrichment */}
          <div className="card-sentinel p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-2">
                <Zap className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                <h2 className="card-sentinel-title">Alert Enrichment Sources</h2>
              </div>
              <button
                type="button"
                onClick={() => router.visit('/app/threat-intel')}
                className="text-sm font-medium"
                style={{ color: 'var(--emerald-400)' }}
              >
                Add Source
              </button>
            </div>

            <div className="divide-y max-h-[400px] overflow-y-auto" style={{ borderColor: 'var(--hairline)' }}>
              {enrichmentSources.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No enrichment sources configured</p>
                </div>
              ) : (
                enrichmentSources.map((source) => (
                  <div
                    key={source.id}
                    className="p-4 transition-colors"
                    style={{ background: 'transparent' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <div
                          className="h-10 w-10 rounded-lg flex items-center justify-center"
                          style={{ background: 'var(--surface-2)' }}
                        >
                          <Database className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                        </div>
                        <div>
                          <span className="font-medium" style={{ color: 'var(--fg)' }}>{source.name}</span>
                          <p className="text-xs" style={{ color: 'var(--muted)' }}>{source.type}</p>
                        </div>
                      </div>
                      <span className={cn('badge-sentinel badge-sentinel-pill flex items-center gap-1', getStatusColor(source.status))}>
                        {getStatusIcon(source.status)}
                        {source.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs mt-2" style={{ color: 'var(--subtle)' }}>
                      <span className="flex items-center gap-1">
                        <TrendingUp className="h-3 w-3" />
                        {formatNumber(source.enrichmentsPerformed)} enrichments
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatLatency(source.avgLatency)} avg
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* AI Insights Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Discovered Patterns */}
          <div className="card-sentinel p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <h2 className="card-sentinel-title">Discovered Patterns</h2>
            </div>
            <div className="divide-y max-h-[300px] overflow-y-auto" style={{ borderColor: 'var(--hairline)' }}>
              {discoveredPatterns.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No patterns discovered yet</p>
                </div>
              ) : (
                discoveredPatterns.map((pattern) => (
                  <div
                    key={pattern.id}
                    className="p-4 transition-colors"
                    style={{ background: 'transparent' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{pattern.name}</span>
                      <span className={cn('badge-sentinel', getSeverityBadgeClass(pattern.severity))}>
                        {pattern.severity}
                      </span>
                    </div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>{pattern.description}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>{formatNumber(pattern.occurrences)} occurrences</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Alert Correlations */}
          <div className="card-sentinel p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <h2 className="card-sentinel-title">Alert Correlations</h2>
            </div>
            <div className="divide-y max-h-[300px] overflow-y-auto" style={{ borderColor: 'var(--hairline)' }}>
              {alertCorrelations.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Link2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No correlations detected</p>
                </div>
              ) : (
                alertCorrelations.map((correlation) => (
                  <div
                    key={correlation.id}
                    className="p-4 transition-colors"
                    style={{ background: 'transparent' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium" style={{ color: 'var(--fg)' }}>{correlation.pattern}</span>
                      <span className="badge-sentinel badge-sentinel-info">
                        {formatPercent(correlation.confidence)} confidence
                      </span>
                    </div>
                    <p className="text-xs" style={{ color: 'var(--muted)' }}>{formatNumber(correlation.alerts?.length)} related alerts</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Noise Reduction */}
          <div className="card-sentinel p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <h2 className="card-sentinel-title">Noise Reduction</h2>
            </div>
            <div className="p-4">
              <div className="text-center mb-4">
                <p className="text-4xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                  {Number.isFinite(noiseMetrics.reductionPercentage as number)
                    ? `${noiseMetrics.reductionPercentage}%`
                    : '—'}
                </p>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Alert noise reduced</p>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span style={{ color: 'var(--muted)' }}>Total Alerts</span>
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{formatNumber(noiseMetrics.totalAlerts)}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span style={{ color: 'var(--muted)' }}>Filtered Out</span>
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{formatNumber(noiseMetrics.filteredAlerts)}</span>
                </div>
              </div>
              <div className="mt-4 h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    width: Number.isFinite(noiseMetrics.reductionPercentage as number)
                      ? `${noiseMetrics.reductionPercentage}%`
                      : '0%',
                    background: 'var(--emerald-400)',
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Intelligent Alerts */}
        <div className="card-sentinel p-0">
          <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5" style={{ color: 'var(--high)' }} />
              <h2 className="card-sentinel-title">Intelligent Alerts</h2>
            </div>
          </div>
          <div className="divide-y max-h-[300px] overflow-y-auto" style={{ borderColor: 'var(--hairline)' }}>
            {intelligentAlerts.length === 0 ? (
              <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No intelligent alerts generated</p>
              </div>
            ) : (
              intelligentAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-4 transition-colors"
                  style={{ background: 'transparent' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium" style={{ color: 'var(--fg)' }}>{alert.title}</span>
                    <span className={cn('badge-sentinel', getSeverityBadgeClass(alert.severity))}>
                      {alert.severity}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--subtle)' }}>
                    <span>{formatPercent(alert.confidence)} confidence</span>
                    <span>{formatNumber(alert.relatedEvents)} related events</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Log Forwarding Metrics */}
        <div className="card-sentinel">
          <h2 className="card-sentinel-title mb-4">Log Forwarding Metrics (24h)</h2>
          <div className="h-48 flex items-end justify-between gap-1">
            {Number.isFinite(stats.totalEventsForwarded as number) && (stats.totalEventsForwarded as number) > 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center rounded-lg border border-dashed" style={{ borderColor: 'var(--border)', color: 'var(--subtle)' }}>
                <BarChart3 className="h-8 w-8 mb-2" />
                <p className="text-sm">Hourly forwarding series unavailable</p>
                <p className="text-xs mt-1">{formatNumber(stats.totalEventsForwarded)} events forwarded in the selected window</p>
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--subtle)' }}>
                <p>No forwarding data available</p>
              </div>
            )}
          </div>
          <div className="flex justify-between mt-2 text-xs" style={{ color: 'var(--subtle)' }}>
            <span>00:00</span>
            <span>06:00</span>
            <span>12:00</span>
            <span>18:00</span>
            <span>24:00</span>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
