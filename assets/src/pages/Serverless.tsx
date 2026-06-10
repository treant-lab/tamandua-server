import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Cloud,
  Server,
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  RefreshCw,
  Filter,
  ChevronDown,
  TrendingUp,
  TrendingDown,
  Zap,
  Lock,
  Unlock,
  Eye,
  Play,
  CheckCircle,
  XCircle,
  AlertCircle,
  BarChart3,
  Search,
  ExternalLink,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useEffect } from 'react'

// Types
interface ServerlessFunction {
  id: string
  name: string
  provider: 'aws' | 'azure' | 'gcp'
  runtime: string
  region: string
  status: string
  memory_size: number
  timeout: number
  security_score: number
  findings_count: number
  invocation_count_24h: number
  error_count_24h: number
  last_invoked: string
}

interface SecurityFinding {
  id: string
  function_id: string
  provider: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  evidence: string
  remediation: string
  status: string
  detected_at: string
}

interface Anomaly {
  id: string
  function_id: string
  provider: string
  anomaly_type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  z_score: number
  confidence: number
  detected_at: string
  acknowledged: boolean
}

interface ServerlessStats {
  summary: {
    total_functions: number
    total_invocations_24h: number
    total_errors_24h: number
    average_security_score: number
    open_findings: number
    critical_findings: number
    anomalies_24h: number
  }
  by_provider: {
    aws: { total_functions: number; runtime_distribution?: Record<string, number> }
    azure: { total_functions: number }
    gcp: { total_functions: number }
  }
  security: {
    findings_by_category?: Record<string, number>
  }
}

interface ServerlessPageProps {
  functions?: ServerlessFunction[]
  findings?: SecurityFinding[]
  anomalies?: Anomaly[]
  stats?: ServerlessStats
}

export default function Serverless({
  functions: initialFunctions = [],
  findings: initialFindings = [],
  anomalies: initialAnomalies = [],
  stats: initialStats,
}: ServerlessPageProps) {
  const [functions, setFunctions] = useState<ServerlessFunction[]>(initialFunctions)
  const [findings, setFindings] = useState<SecurityFinding[]>(initialFindings)
  const [anomalies, setAnomalies] = useState<Anomaly[]>(initialAnomalies)
  const [stats, setStats] = useState<ServerlessStats | undefined>(initialStats)
  const [providerFilter, setProviderFilter] = useState<string>('all')
  const [activeTab, setActiveTab] = useState<'functions' | 'findings' | 'anomalies'>('functions')
  const [isLoading, setIsLoading] = useState(false)

  // Fetch data on mount
  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setIsLoading(true)
    try {
      // Fetch stats
      const statsRes = await fetch('/api/v1/serverless/statistics')
      if (statsRes.ok) {
        const statsData = await statsRes.json()
        setStats(statsData.data)
      }

      // Fetch functions
      const funcsRes = await fetch('/api/v1/serverless/functions')
      if (funcsRes.ok) {
        const funcsData = await funcsRes.json()
        setFunctions(funcsData.data || [])
      }

      // Fetch findings
      const findingsRes = await fetch('/api/v1/serverless/findings?severity=critical&limit=50')
      if (findingsRes.ok) {
        const findingsData = await findingsRes.json()
        setFindings(findingsData.data || [])
      }

      // Fetch anomalies
      const anomaliesRes = await fetch('/api/v1/serverless/anomalies?limit=50')
      if (anomaliesRes.ok) {
        const anomaliesData = await anomaliesRes.json()
        setAnomalies(anomaliesData.data || [])
      }
    } catch (err) {
      logger.error('Failed to fetch serverless data:', err)
    }
    setIsLoading(false)
  }

  const syncProvider = async (provider: string) => {
    try {
      await fetch(`/api/v1/serverless/sync?provider=${provider}`, { method: 'POST' })
      fetchData()
    } catch (err) {
      logger.error('Sync failed:', err)
    }
  }

  const scanFunction = async (functionId: string, provider: string) => {
    try {
      await fetch(`/api/v1/serverless/${provider}/${functionId}/scan`, { method: 'POST' })
      fetchData()
    } catch (err) {
      logger.error('Scan failed:', err)
    }
  }

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'aws':
        return <span className="text-orange-400 font-bold text-xs">AWS</span>
      case 'azure':
        return <span className="text-blue-400 font-bold text-xs">Azure</span>
      case 'gcp':
        return <span className="text-red-400 font-bold text-xs">GCP</span>
      default:
        return <Cloud className="h-4 w-4" />
    }
  }

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case 'aws': return 'border-orange-500'
      case 'azure': return 'border-blue-500'
      case 'gcp': return 'border-red-500'
      default: return 'border-[var(--border)]'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20'
      case 'high': return 'text-orange-400 bg-orange-500/20'
      case 'medium': return 'text-yellow-400 bg-yellow-500/20'
      case 'low': return 'text-blue-400 bg-blue-500/20'
      default: return 'text-[var(--muted)] bg-[var(--surface-raised)]'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400'
    if (score >= 70) return 'text-yellow-400'
    if (score >= 50) return 'text-orange-400'
    return 'text-red-400'
  }

  const filteredFunctions = functions.filter(
    f => providerFilter === 'all' || f.provider === providerFilter
  )

  const filteredFindings = findings.filter(
    f => providerFilter === 'all' || f.provider === providerFilter
  )

  const filteredAnomalies = anomalies.filter(
    a => providerFilter === 'all' || a.provider === providerFilter
  )

  const summary = stats?.summary || {
    total_functions: functions.length,
    total_invocations_24h: 0,
    total_errors_24h: 0,
    average_security_score: 100,
    open_findings: findings.length,
    critical_findings: findings.filter(f => f.severity === 'critical').length,
    anomalies_24h: anomalies.length,
  }

  return (
    <MainLayout title="Serverless Security">
      <Head title="Serverless Security - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header with Actions */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[var(--fg)]">Serverless Security</h1>
            <p className="text-[var(--muted)] mt-1">
              Monitor and secure AWS Lambda, Azure Functions, and GCP Cloud Functions
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchData()}
              disabled={isLoading}
              className="flex items-center gap-2 bg-[var(--surface-raised)] hover:bg-[var(--surface-elevated)] rounded-lg px-3 py-2 text-sm text-[var(--muted)]"
            >
              <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
              Refresh
            </button>
            <div className="relative group">
              <button className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 rounded-lg px-4 py-2 text-sm text-white font-medium">
                <Cloud className="h-4 w-4" />
                Sync Provider
                <ChevronDown className="h-4 w-4" />
              </button>
              <div className="absolute right-0 top-full mt-1 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xl hidden group-hover:block z-50">
                <button
                  onClick={() => syncProvider('aws')}
                  className="w-full px-4 py-2 text-left text-sm text-[var(--muted)] hover:bg-[var(--surface-raised)] flex items-center gap-2"
                >
                  <span className="text-orange-400">AWS</span> Lambda
                </button>
                <button
                  onClick={() => syncProvider('azure')}
                  className="w-full px-4 py-2 text-left text-sm text-[var(--muted)] hover:bg-[var(--surface-raised)] flex items-center gap-2"
                >
                  <span className="text-blue-400">Azure</span> Functions
                </button>
                <button
                  onClick={() => syncProvider('gcp')}
                  className="w-full px-4 py-2 text-left text-sm text-[var(--muted)] hover:bg-[var(--surface-raised)] flex items-center gap-2"
                >
                  <span className="text-red-400">GCP</span> Cloud Functions
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-10 w-10 rounded-lg bg-primary-500/20 flex items-center justify-center">
                <Server className="h-5 w-5 text-primary-400" />
              </div>
              <div>
                <p className="text-sm text-[var(--muted)]">Total Functions</p>
                <p className="text-2xl font-bold text-[var(--fg)]">{summary.total_functions}</p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="text-orange-400">AWS: {stats?.by_provider?.aws?.total_functions || 0}</span>
              <span className="text-blue-400">Azure: {stats?.by_provider?.azure?.total_functions || 0}</span>
              <span className="text-red-400">GCP: {stats?.by_provider?.gcp?.total_functions || 0}</span>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-10 w-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                <Zap className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-sm text-[var(--muted)]">Invocations (24h)</p>
                <p className="text-2xl font-bold text-[var(--fg)]">
                  {summary.total_invocations_24h.toLocaleString()}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-red-400">
                {summary.total_errors_24h} errors
              </span>
              <span className="text-[var(--muted)]">
                ({summary.total_invocations_24h > 0
                  ? ((summary.total_errors_24h / summary.total_invocations_24h) * 100).toFixed(2)
                  : 0}% error rate)
              </span>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-10 w-10 rounded-lg bg-yellow-500/20 flex items-center justify-center">
                <Shield className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-sm text-[var(--muted)]">Security Score</p>
                <p className={cn('text-2xl font-bold', getScoreColor(summary.average_security_score))}>
                  {Math.round(summary.average_security_score)}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-red-400">{summary.critical_findings} critical</span>
              <span className="text-orange-400">{summary.open_findings} open findings</span>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-10 w-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <Activity className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-[var(--muted)]">Anomalies (24h)</p>
                <p className="text-2xl font-bold text-[var(--fg)]">{summary.anomalies_24h}</p>
              </div>
            </div>
            <div className="text-xs text-[var(--muted)]">
              Behavioral deviations detected
            </div>
          </div>
        </div>

        {/* Provider Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(['aws', 'azure', 'gcp'] as const).map((provider) => {
            const providerFunctions = functions.filter(f => f.provider === provider)
            const providerFindings = findings.filter(f => f.provider === provider)
            const criticalCount = providerFindings.filter(f => f.severity === 'critical').length
            const avgScore = providerFunctions.length > 0
              ? Math.round(providerFunctions.reduce((sum, f) => sum + (f.security_score || 100), 0) / providerFunctions.length)
              : 100

            return (
              <div
                key={provider}
                className={cn(
                  'card-sentinel bg-[var(--surface)] rounded-xl border-l-4 p-4',
                  getProviderColor(provider)
                )}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-[var(--surface-raised)] flex items-center justify-center">
                      {getProviderIcon(provider)}
                    </div>
                    <div>
                      <h3 className="text-[var(--fg)] font-medium">
                        {provider === 'aws' ? 'AWS Lambda' : provider === 'azure' ? 'Azure Functions' : 'GCP Cloud Functions'}
                      </h3>
                      <p className="text-xs text-[var(--muted)]">{providerFunctions.length} functions</p>
                    </div>
                  </div>
                  <button
                    onClick={() => syncProvider(provider)}
                    className="p-2 hover:bg-[var(--surface-raised)] rounded-lg text-[var(--muted)] hover:text-[var(--fg)]"
                    title="Sync"
                  >
                    <RefreshCw className="h-4 w-4" />
                  </button>
                </div>
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="bg-[var(--surface-raised)]/50 rounded-lg p-2">
                    <p className="text-xs text-[var(--muted)]">Score</p>
                    <p className={cn('text-lg font-bold', getScoreColor(avgScore))}>{avgScore}</p>
                  </div>
                  <div className="bg-[var(--surface-raised)]/50 rounded-lg p-2">
                    <p className="text-xs text-[var(--muted)]">Findings</p>
                    <p className="text-lg font-bold text-yellow-400">{providerFindings.length}</p>
                  </div>
                  <div className="bg-[var(--surface-raised)]/50 rounded-lg p-2">
                    <p className="text-xs text-[var(--muted)]">Critical</p>
                    <p className="text-lg font-bold text-red-400">{criticalCount}</p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Main Content Tabs */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
          <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('functions')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'functions'
                    ? 'bg-primary-600 text-white'
                    : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                )}
              >
                <Server className="h-4 w-4 inline-block mr-2" />
                Functions ({filteredFunctions.length})
              </button>
              <button
                onClick={() => setActiveTab('findings')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'findings'
                    ? 'bg-primary-600 text-white'
                    : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                )}
              >
                <AlertTriangle className="h-4 w-4 inline-block mr-2" />
                Security Findings ({filteredFindings.length})
              </button>
              <button
                onClick={() => setActiveTab('anomalies')}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === 'anomalies'
                    ? 'bg-primary-600 text-white'
                    : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                )}
              >
                <Activity className="h-4 w-4 inline-block mr-2" />
                Anomalies ({filteredAnomalies.length})
              </button>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-[var(--muted)]" />
              <select
                value={providerFilter}
                onChange={(e) => setProviderFilter(e.target.value)}
                className="bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option value="all">All Providers</option>
                <option value="aws">AWS Lambda</option>
                <option value="azure">Azure Functions</option>
                <option value="gcp">GCP Cloud Functions</option>
              </select>
            </div>
          </div>

          <div className="p-4">
            {/* Functions Tab */}
            {activeTab === 'functions' && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[var(--border)]">
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Provider</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Function</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Runtime</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Region</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Score</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Findings</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Invocations</th>
                      <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFunctions.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="p-12 text-center">
                          <Server className="h-12 w-12 mx-auto mb-4 text-[var(--muted)] opacity-50" />
                          <p className="text-[var(--muted)]">No functions found</p>
                          <p className="text-sm text-[var(--muted)] mt-1">
                            Click "Sync Provider" to import functions from your cloud accounts
                          </p>
                        </td>
                      </tr>
                    ) : (
                      filteredFunctions.map((func) => (
                        <tr
                          key={func.id}
                          className="border-b border-[var(--border)]/50 hover:bg-[var(--surface-raised)]/30"
                        >
                          <td className="p-3">{getProviderIcon(func.provider)}</td>
                          <td className="p-3">
                            <div>
                              <p className="text-[var(--fg)] font-medium">{func.name}</p>
                              <p className="text-xs text-[var(--muted)] font-mono truncate max-w-[200px]">
                                {func.id}
                              </p>
                            </div>
                          </td>
                          <td className="p-3">
                            <span className="px-2 py-1 bg-[var(--surface-raised)] rounded text-xs text-[var(--muted)]">
                              {func.runtime}
                            </span>
                          </td>
                          <td className="p-3 text-[var(--muted)] text-sm">{func.region}</td>
                          <td className="p-3">
                            <span className={cn('font-bold', getScoreColor(func.security_score || 100))}>
                              {func.security_score || 100}
                            </span>
                          </td>
                          <td className="p-3">
                            {func.findings_count > 0 ? (
                              <span className="flex items-center gap-1 text-yellow-400 text-sm">
                                <AlertTriangle className="h-4 w-4" />
                                {func.findings_count}
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-green-400 text-sm">
                                <CheckCircle className="h-4 w-4" />
                                Clean
                              </span>
                            )}
                          </td>
                          <td className="p-3">
                            <div className="text-sm">
                              <span className="text-[var(--fg)]">{func.invocation_count_24h || 0}</span>
                              {func.error_count_24h > 0 && (
                                <span className="text-red-400 ml-2">
                                  ({func.error_count_24h} errors)
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="flex items-center gap-1">
                              <button
                                onClick={() => scanFunction(func.id, func.provider)}
                                className="p-1.5 hover:bg-[var(--surface-elevated)] rounded text-[var(--muted)] hover:text-[var(--fg)]"
                                title="Scan for security issues"
                              >
                                <Shield className="h-4 w-4" />
                              </button>
                              <button
                                className="p-1.5 hover:bg-[var(--surface-elevated)] rounded text-[var(--muted)] hover:text-[var(--fg)]"
                                title="View details"
                              >
                                <Eye className="h-4 w-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Findings Tab */}
            {activeTab === 'findings' && (
              <div className="space-y-3">
                {filteredFindings.length === 0 ? (
                  <div className="p-12 text-center">
                    <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500 opacity-50" />
                    <p className="text-[var(--muted)]">No security findings</p>
                    <p className="text-sm text-[var(--muted)] mt-1">
                      Your serverless functions are clean
                    </p>
                  </div>
                ) : (
                  filteredFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className={cn(
                        'bg-[var(--surface-raised)]/30 rounded-lg p-4 border-l-4',
                        finding.severity === 'critical' ? 'border-red-500' :
                        finding.severity === 'high' ? 'border-orange-500' :
                        finding.severity === 'medium' ? 'border-yellow-500' :
                        'border-blue-500'
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            'p-2 rounded-lg mt-0.5',
                            getSeverityColor(finding.severity)
                          )}>
                            <AlertTriangle className="h-4 w-4" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getProviderIcon(finding.provider)}
                              <h4 className="text-[var(--fg)] font-medium">{finding.title}</h4>
                              <span className={cn(
                                'px-2 py-0.5 rounded text-xs font-medium uppercase',
                                getSeverityColor(finding.severity)
                              )}>
                                {finding.severity}
                              </span>
                              <span className="px-2 py-0.5 bg-[var(--surface-elevated)] rounded text-xs text-[var(--muted)]">
                                {finding.category}
                              </span>
                            </div>
                            <p className="text-sm text-[var(--muted)] mb-2">{finding.description}</p>
                            <p className="text-sm text-[var(--muted)] mb-2">
                              <span className="text-[var(--muted)]">Remediation:</span> {finding.remediation}
                            </p>
                            <div className="flex items-center gap-4 text-xs text-[var(--muted)]">
                              <span>Function: {finding.function_id}</span>
                              <span>Detected: {formatDate(finding.detected_at)}</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button className="px-3 py-1 bg-[var(--surface-elevated)] hover:bg-[var(--surface-raised)] rounded text-xs text-[var(--muted)]">
                            Acknowledge
                          </button>
                          <button className="px-3 py-1 bg-primary-600 hover:bg-primary-500 rounded text-xs text-white">
                            Fix
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Anomalies Tab */}
            {activeTab === 'anomalies' && (
              <div className="space-y-3">
                {filteredAnomalies.length === 0 ? (
                  <div className="p-12 text-center">
                    <Activity className="h-12 w-12 mx-auto mb-4 text-green-500 opacity-50" />
                    <p className="text-[var(--muted)]">No anomalies detected</p>
                    <p className="text-sm text-[var(--muted)] mt-1">
                      Functions are behaving within normal parameters
                    </p>
                  </div>
                ) : (
                  filteredAnomalies.map((anomaly) => (
                    <div
                      key={anomaly.id}
                      className={cn(
                        'bg-[var(--surface-raised)]/30 rounded-lg p-4',
                        anomaly.acknowledged && 'opacity-60'
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            'p-2 rounded-lg mt-0.5',
                            getSeverityColor(anomaly.severity)
                          )}>
                            <Activity className="h-4 w-4" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getProviderIcon(anomaly.provider)}
                              <h4 className="text-[var(--fg)] font-medium capitalize">
                                {anomaly.anomaly_type.replace(/_/g, ' ')}
                              </h4>
                              <span className={cn(
                                'px-2 py-0.5 rounded text-xs font-medium uppercase',
                                getSeverityColor(anomaly.severity)
                              )}>
                                {anomaly.severity}
                              </span>
                              {anomaly.acknowledged && (
                                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">
                                  Acknowledged
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-[var(--muted)] mb-2">{anomaly.description}</p>
                            <div className="flex items-center gap-4 text-xs text-[var(--muted)]">
                              <span>Function: {anomaly.function_id}</span>
                              <span>Z-Score: {anomaly.z_score.toFixed(2)}</span>
                              <span>Confidence: {(anomaly.confidence * 100).toFixed(0)}%</span>
                              <span>Detected: {formatDate(anomaly.detected_at)}</span>
                            </div>
                          </div>
                        </div>
                        {!anomaly.acknowledged && (
                          <button className="px-3 py-1 bg-[var(--surface-elevated)] hover:bg-[var(--surface-raised)] rounded text-xs text-[var(--muted)]">
                            Acknowledge
                          </button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
