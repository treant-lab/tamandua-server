import { useState, useEffect, useCallback } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  CheckCircle,
  AlertTriangle,
  XCircle,
  HelpCircle,
  RefreshCw,
  FileText,
  Download,
  ChevronRight,
  TrendingUp,
  TrendingDown,
  Clock,
  Link2,
  Filter,
  Search,
  BarChart3,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import axios from 'axios'
import { toast } from 'sonner'
import { logger } from '@/lib/logger'
import { Select, SelectItem } from '@/components/ui/baseui'

// ============================================================================
// Types
// ============================================================================

interface Framework {
  id: string
  name: string
  description: string
  icon: string
  category: string
}

interface CompliancePosture {
  framework: string
  name: string
  score: number
  status: 'compliant' | 'partial' | 'non_compliant'
  compliant: number
  partial: number
  non_compliant: number
  not_assessed: number
  last_assessed: string
}

interface Control {
  id: string
  control_id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_assessed'
  evidence_types: string[]
  remediation_steps: string[]
  last_assessed: string
}

interface Gap {
  control: Control
  current_status: string
  findings: string[]
  remediation_steps: string[]
  priority: number
  effort_estimate: string
}

// ============================================================================
// Constants
// ============================================================================

const FRAMEWORKS: Framework[] = [
  {
    id: 'pci_dss',
    name: 'PCI-DSS 4.0',
    description: 'Payment Card Industry Data Security Standard',
    icon: 'credit-card',
    category: 'Industry',
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
    icon: 'heart-pulse',
    category: 'Industry',
  },
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2',
    icon: 'building',
    category: 'Industry',
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'General Data Protection Regulation',
    icon: 'globe',
    category: 'Regulatory',
  },
  {
    id: 'nist_800_53',
    name: 'NIST 800-53',
    description: 'Security and Privacy Controls',
    icon: 'shield-check',
    category: 'Government',
  },
  {
    id: 'cis_benchmark',
    name: 'CIS Controls v8',
    description: 'Center for Internet Security Benchmarks',
    icon: 'list-checks',
    category: 'Best Practice',
  },
]

// ============================================================================
// Component
// ============================================================================

export default function Compliance() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [posture, setPosture] = useState<CompliancePosture | null>(null)
  const [controls, setControls] = useState<Control[]>([])
  const [gaps, setGaps] = useState<Gap[]>([])
  const [loading, setLoading] = useState(false)
  const [overallPosture, setOverallPosture] = useState<any>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [generatingReport, setGeneratingReport] = useState(false)

  // Fetch overall compliance posture on mount
  useEffect(() => {
    fetchOverallPosture()
  }, [])

  // Fetch framework-specific data when selected
  useEffect(() => {
    if (selectedFramework) {
      fetchFrameworkPosture(selectedFramework)
      fetchFrameworkControls(selectedFramework)
      fetchGapAnalysis(selectedFramework)
    }
  }, [selectedFramework])

  const fetchOverallPosture = async () => {
    try {
      const response = await axios.get('/api/v1/compliance/overview')
      if (response.data?.data) {
        setOverallPosture(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch compliance overview:', error)
    }
  }

  const fetchFrameworkPosture = async (framework: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/compliance/frameworks/${framework}`)
      if (response.data?.data) {
        setPosture(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch framework posture:', error)
      toast.error('Failed to load compliance posture')
    } finally {
      setLoading(false)
    }
  }

  const fetchFrameworkControls = async (framework: string) => {
    try {
      const response = await axios.get(`/api/v1/compliance/frameworks/${framework}/controls`)
      if (response.data?.data) {
        setControls(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch controls:', error)
    }
  }

  const fetchGapAnalysis = async (framework: string) => {
    try {
      const response = await axios.get(`/api/v1/compliance/frameworks/${framework}/gap-analysis`)
      if (response.data?.data?.gaps) {
        setGaps(response.data.data.gaps)
      }
    } catch (error) {
      logger.error('Failed to fetch gap analysis:', error)
    }
  }

  const handleGenerateReport = async () => {
    if (!selectedFramework) return
    setGeneratingReport(true)
    try {
      const response = await axios.post('/api/v1/reports/generate', {
        template_id: `compliance_${selectedFramework}`,
        date_from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        date_to: new Date().toISOString().split('T')[0],
      })
      if (response.data?.data) {
        toast.success('Compliance report generated successfully')
        // Redirect to reports page or open report
        window.location.href = '/app/reports'
      }
    } catch (error) {
      toast.error('Failed to generate report')
    } finally {
      setGeneratingReport(false)
    }
  }

  const handleExportAudit = async () => {
    if (!selectedFramework) return
    try {
      const response = await axios.get(
        `/api/v1/compliance/frameworks/${selectedFramework}/export?format=csv`,
        { responseType: 'blob' }
      )
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${selectedFramework}_audit_${new Date().toISOString().split('T')[0]}.csv`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      toast.success('Audit export downloaded')
    } catch (error) {
      toast.error('Failed to export audit data')
    }
  }

  const filteredControls = controls.filter((control) => {
    const matchesStatus = statusFilter === 'all' || control.status === statusFilter
    const matchesSearch =
      !searchQuery ||
      control.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      control.control_id.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesStatus && matchesSearch
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
      case 'partial':
        return <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
      case 'non_compliant':
        return <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
      default:
        return <HelpCircle className="h-5 w-5" style={{ color: 'var(--muted)' }} />
    }
  }

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'badge-sentinel badge-sentinel-low'
      case 'partial':
        return 'badge-sentinel badge-sentinel-high'
      case 'non_compliant':
        return 'badge-sentinel badge-sentinel-crit'
      default:
        return 'badge-sentinel badge-sentinel-info'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--emerald-400)'
    if (score >= 60) return 'var(--high)'
    return 'var(--crit)'
  }

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'badge-sentinel badge-sentinel-crit'
      case 'high':
        return 'badge-sentinel badge-sentinel-high'
      case 'medium':
        return 'badge-sentinel badge-sentinel-med'
      default:
        return 'badge-sentinel badge-sentinel-info'
    }
  }

  return (
    <MainLayout title="Compliance">
      <Head title="Compliance - Tamandua EDR" />

      <div className="space-y-6">
        {/* Overall Compliance Score (when no framework selected) */}
        {!selectedFramework && (
          <>
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Overall Compliance</p>
                    <p className="text-3xl font-bold mt-1" style={{ color: getScoreColor(overallPosture?.overall_score || 0) }}>
                      {overallPosture?.overall_score || 0}%
                    </p>
                  </div>
                  <div className="p-3 rounded-lg" style={{ backgroundColor: 'rgba(var(--primary-rgb), 0.2)' }}>
                    <Shield className="h-8 w-8" style={{ color: 'var(--primary)' }} />
                  </div>
                </div>
                <div className="mt-4 flex items-center gap-2 text-sm">
                  {overallPosture?.trend === 'up' ? (
                    <TrendingUp className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                  ) : (
                    <TrendingDown className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                  )}
                  <span style={{ color: 'var(--muted)' }}>vs previous period</span>
                </div>
              </div>

              <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Frameworks Assessed</p>
                    <p className="text-3xl font-bold mt-1" style={{ color: 'var(--fg)' }}>
                      {overallPosture?.frameworks?.length || 0}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg" style={{ backgroundColor: 'rgba(59, 130, 246, 0.2)' }}>
                    <FileText className="h-8 w-8" style={{ color: 'rgb(96, 165, 250)' }} />
                  </div>
                </div>
                <div className="mt-4 text-sm" style={{ color: 'var(--muted)' }}>
                  Active compliance frameworks
                </div>
              </div>

              <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>Last Assessment</p>
                    <p className="text-xl font-semibold mt-1" style={{ color: 'var(--fg)' }}>
                      {overallPosture?.last_assessed
                        ? formatDate(overallPosture.last_assessed)
                        : 'Never'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg" style={{ backgroundColor: 'rgba(168, 85, 247, 0.2)' }}>
                    <Clock className="h-8 w-8" style={{ color: 'rgb(192, 132, 252)' }} />
                  </div>
                </div>
              </div>
            </div>

            {/* Framework Selection */}
            <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
              <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Select Compliance Framework</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {FRAMEWORKS.map((framework) => {
                  const frameworkPosture = overallPosture?.frameworks?.find(
                    (f: any) => f.framework === framework.id
                  )
                  return (
                    <button
                      key={framework.id}
                      onClick={() => setSelectedFramework(framework.id)}
                      className="flex items-start gap-4 p-4 rounded-lg border transition-all text-left hover:opacity-90"
                      style={{
                        backgroundColor: 'var(--surface-alt)',
                        borderColor: 'var(--border)'
                      }}
                    >
                      <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(var(--primary-rgb), 0.2)' }}>
                        <Shield className="h-6 w-6" style={{ color: 'var(--primary)' }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{framework.name}</h3>
                          {frameworkPosture && (
                            <span className="text-sm font-semibold" style={{ color: getScoreColor(frameworkPosture.score) }}>
                              {frameworkPosture.score}%
                            </span>
                          )}
                        </div>
                        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{framework.description}</p>
                        <div className="flex items-center gap-2 mt-2">
                          <span className="badge-sentinel badge-sentinel-info text-xs">
                            {framework.category}
                          </span>
                          {frameworkPosture && (
                            <span className={cn('text-xs', getStatusBadgeClass(frameworkPosture.status))}>
                              {frameworkPosture.compliant || 0} compliant
                            </span>
                          )}
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                    </button>
                  )
                })}
              </div>
            </div>
          </>
        )}

        {/* Framework Detail View */}
        {selectedFramework && (
          <>
            {/* Back Button and Header */}
            <div className="flex items-center justify-between">
              <button
                onClick={() => {
                  setSelectedFramework(null)
                  setPosture(null)
                  setControls([])
                  setGaps([])
                }}
                className="flex items-center gap-2 transition-colors hover:opacity-80"
                style={{ color: 'var(--muted)' }}
              >
                <ChevronRight className="h-4 w-4 rotate-180" />
                Back to Frameworks
              </button>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleExportAudit}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                >
                  <Download className="h-4 w-4" />
                  Export Audit
                </button>
                <button
                  onClick={handleGenerateReport}
                  disabled={generatingReport}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: 'var(--primary)', color: 'var(--fg)' }}
                >
                  {generatingReport ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <FileText className="h-4 w-4" />
                  )}
                  Generate Report
                </button>
              </div>
            </div>

            {/* Framework Posture Summary */}
            {loading ? (
              <div className="rounded-xl border p-12 text-center" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4" style={{ color: 'var(--primary)' }} />
                <p style={{ color: 'var(--muted)' }}>Loading compliance data...</p>
              </div>
            ) : posture ? (
              <>
                {/* Posture Overview */}
                <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h2 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{posture.name}</h2>
                      <p className="mt-1" style={{ color: 'var(--muted)' }}>
                        Last assessed: {posture.last_assessed ? formatDate(posture.last_assessed) : 'Never'}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="text-4xl font-bold" style={{ color: getScoreColor(posture.score) }}>
                        {posture.score}%
                      </div>
                      <div className={cn('text-sm px-3 py-1 rounded mt-2', getStatusBadgeClass(posture.status))}>
                        {posture.status === 'compliant' ? 'Compliant' :
                         posture.status === 'partial' ? 'Partial Compliance' : 'Non-Compliant'}
                      </div>
                    </div>
                  </div>

                  {/* Status Distribution */}
                  <div className="grid grid-cols-4 gap-4">
                    <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'rgba(16, 185, 129, 0.2)' }}>
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                        <span className="text-sm" style={{ color: 'var(--emerald-400)' }}>Compliant</span>
                      </div>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{posture.compliant}</p>
                    </div>
                    <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(251, 146, 60, 0.1)', borderColor: 'rgba(251, 146, 60, 0.2)' }}>
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                        <span className="text-sm" style={{ color: 'var(--high)' }}>Partial</span>
                      </div>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{posture.partial}</p>
                    </div>
                    <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.2)' }}>
                      <div className="flex items-center gap-2 mb-2">
                        <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                        <span className="text-sm" style={{ color: 'var(--crit)' }}>Non-Compliant</span>
                      </div>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{posture.non_compliant}</p>
                    </div>
                    <div className="rounded-lg p-4 border" style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}>
                      <div className="flex items-center gap-2 mb-2">
                        <HelpCircle className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                        <span className="text-sm" style={{ color: 'var(--muted)' }}>Not Assessed</span>
                      </div>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{posture.not_assessed}</p>
                    </div>
                  </div>
                </div>

                {/* Gap Analysis */}
                {gaps.length > 0 && (
                  <div className="rounded-xl border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                    <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
                      <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                        <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                        Gap Analysis ({gaps.length} items)
                      </h3>
                    </div>
                    <div className="divide-y max-h-96 overflow-auto" style={{ borderColor: 'var(--border)' }}>
                      {gaps.slice(0, 10).map((gap, idx) => (
                        <div key={idx} className="p-4 hover:opacity-90" style={{ borderColor: 'var(--border)' }}>
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                {getStatusIcon(gap.current_status)}
                                <span className="font-medium" style={{ color: 'var(--fg)' }}>{gap.control.control_id}</span>
                                <span className={getSeverityBadgeClass(gap.control.severity)}>
                                  {gap.control.severity}
                                </span>
                              </div>
                              <p className="mt-1" style={{ color: 'var(--fg)' }}>{gap.control.title}</p>
                              <p className="text-sm mt-2" style={{ color: 'var(--muted)' }}>{gap.effort_estimate}</p>
                            </div>
                            <div className="text-right">
                              <span className="text-xs" style={{ color: 'var(--muted)' }}>Priority</span>
                              <p className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{gap.priority}</p>
                            </div>
                          </div>
                          {gap.remediation_steps && gap.remediation_steps.length > 0 && (
                            <div className="mt-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--surface-alt)' }}>
                              <p className="text-xs mb-1" style={{ color: 'var(--muted)' }}>Remediation</p>
                              <p className="text-sm" style={{ color: 'var(--fg)' }}>{gap.remediation_steps[0]}</p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Controls Table */}
                <div className="rounded-xl border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                  <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
                    <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Controls</h3>
                    <div className="flex items-center gap-3">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                        <input
                          type="text"
                          placeholder="Search controls..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="pl-10 pr-4 py-2 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                          style={{
                            backgroundColor: 'var(--surface-alt)',
                            borderColor: 'var(--border)',
                            color: 'var(--fg)',
                            border: '1px solid var(--border)'
                          }}
                        />
                      </div>
                      <Select
                        value={statusFilter}
                        onValueChange={setStatusFilter}
                        className="px-3 py-2 rounded-lg text-sm focus:ring-2 focus:ring-primary-500"
                      >
                        <SelectItem value="all">All Status</SelectItem>
                        <SelectItem value="compliant">Compliant</SelectItem>
                        <SelectItem value="partial">Partial</SelectItem>
                        <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                        <SelectItem value="not_assessed">Not Assessed</SelectItem>
                      </Select>
                    </div>
                  </div>
                  <div className="overflow-auto max-h-[600px]">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0" style={{ backgroundColor: 'var(--surface-alt)' }}>
                        <tr>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Control ID</th>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Title</th>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Category</th>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Severity</th>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                          <th className="text-left p-4 font-medium" style={{ color: 'var(--muted)' }}>Evidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                        {filteredControls.map((control) => (
                          <tr key={control.id} className="hover:opacity-90">
                            <td className="p-4 font-mono" style={{ color: 'var(--primary)' }}>{control.control_id}</td>
                            <td className="p-4" style={{ color: 'var(--fg)' }}>{control.title}</td>
                            <td className="p-4" style={{ color: 'var(--muted)' }}>{control.category}</td>
                            <td className="p-4">
                              <span className={getSeverityBadgeClass(control.severity)}>
                                {control.severity}
                              </span>
                            </td>
                            <td className="p-4">
                              <div className="flex items-center gap-2">
                                {getStatusIcon(control.status)}
                                <span className={getStatusBadgeClass(control.status)}>
                                  {control.status.replace('_', ' ')}
                                </span>
                              </div>
                            </td>
                            <td className="p-4">
                              {control.evidence_types && control.evidence_types.length > 0 && (
                                <button className="flex items-center gap-1" style={{ color: 'var(--primary)' }}>
                                  <Link2 className="h-4 w-4" />
                                  {control.evidence_types.length} types
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                        {filteredControls.length === 0 && (
                          <tr>
                            <td colSpan={6} className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                              No controls found matching your criteria
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            ) : (
              <div className="rounded-xl border p-12 text-center" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <Shield className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--muted)' }} />
                <p style={{ color: 'var(--muted)' }}>Select a framework to view compliance posture</p>
              </div>
            )}
          </>
        )}
      </div>
    </MainLayout>
  )
}
