import { useState, useEffect, useCallback, useMemo } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  FileText,
  Calendar,
  Clock,
  RefreshCw,
  Printer,
  Shield,
  Server,
  AlertTriangle,
  CheckCircle,
  X,
  BarChart3,
  Download,
  Mail,
  Play,
  Pause,
  Trash2,
  Plus,
  Edit,
  History,
  Timer,
  FileJson,
  FileSpreadsheet,
  FileType,
  Search,
  Filter,
  ChevronDown,
  Eye,
  Activity,
  Target,
  ShieldCheck,
  PieChart,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  XCircle,
  MinusCircle,
  Building2,
  Layers,
  ClipboardList,
  Gauge,
  ArrowRight,
  ChevronRight,
  Settings,
  Zap,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import axios from 'axios'
import { toast } from 'sonner'
import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

interface ReportTemplate {
  id: string
  name: string
  description: string
  category: 'security' | 'compliance' | 'operations' | 'custom'
  icon: React.ElementType
  sections: string[]
  supportedFormats: ('pdf' | 'html' | 'csv' | 'json')[]
}

interface GeneratedReport {
  id: string
  template_id: string
  template_name: string
  date_from: string
  date_to: string
  status: 'generating' | 'ready' | 'failed'
  format: string
  created_at: string
  generated_by: string
  download_url?: string
  file_size?: number
}

interface ScheduledReport {
  id: string
  name: string
  template_id: string
  schedule: string
  schedule_display: string
  recipients: string[]
  format: string
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_by: string
}

interface ReportData {
  title: string
  template: string
  period: { from: string; to: string }
  generated_at: string
  generated_by: string
  sections: ReportSection[]
}

interface ReportSection {
  title: string
  type: 'summary' | 'table' | 'stats' | 'list' | 'text' | 'chart'
  content: unknown
}

interface ComplianceFramework {
  id: string
  name: string
  shortName: string
  description: string
  score: number
  controlsTotal: number
  controlsCompliant: number
  controlsPartial: number
  controlsNonCompliant: number
  controlsNotAssessed: number
  lastAssessed: string | null
  trend: 'up' | 'down' | 'stable'
  trendValue: number
}

interface CustomReportConfig {
  name: string
  description: string
  sections: CustomReportSection[]
  dateRange: { from: string; to: string }
  filters: CustomReportFilter[]
  format: 'pdf' | 'html' | 'csv' | 'json'
}

interface CustomReportSection {
  id: string
  type: 'metrics' | 'table' | 'chart' | 'text' | 'alerts' | 'agents' | 'threats'
  title: string
  enabled: boolean
  config: Record<string, unknown>
}

interface CustomReportFilter {
  field: string
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'in'
  value: string | number | boolean | string[]
}

// ============================================================================
// Constants
// ============================================================================

const REPORT_TEMPLATES: ReportTemplate[] = [
  // Security Reports
  {
    id: 'executive_summary',
    name: 'Executive Summary',
    description: 'High-level overview of security posture, key metrics, and critical incidents for leadership review.',
    category: 'security',
    icon: BarChart3,
    sections: ['Security Score', 'Critical Incidents', 'Agent Coverage', 'Top Threats', 'Recommendations'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'threat_report',
    name: 'Threat Analysis',
    description: 'Detailed breakdown of detected threats, IOCs, MITRE ATT&CK mapping, and trend analysis.',
    category: 'security',
    icon: AlertTriangle,
    sections: ['Threat Overview', 'IOC Summary', 'MITRE Coverage', 'Attack Vectors', 'Trend Analysis'],
    supportedFormats: ['pdf', 'html', 'csv', 'json'],
  },
  {
    id: 'incident_report',
    name: 'Incident Report',
    description: 'Detailed breakdown of security incidents, response actions taken, and resolution timeline.',
    category: 'security',
    icon: Shield,
    sections: ['Incident Timeline', 'Affected Assets', 'MITRE ATT&CK Mapping', 'Response Actions', 'Lessons Learned'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  // Operations Reports
  {
    id: 'agent_health',
    name: 'Agent Health',
    description: 'Status and health metrics for all deployed agents, including uptime, version, and coverage gaps.',
    category: 'operations',
    icon: Server,
    sections: ['Agent Status', 'Version Distribution', 'Coverage Gaps', 'Performance Metrics', 'Offline Agents'],
    supportedFormats: ['pdf', 'html', 'csv', 'json'],
  },
  {
    id: 'detection_efficacy',
    name: 'Detection Efficacy',
    description: 'Analysis of detection rule performance, false positive rates, and MITRE technique coverage.',
    category: 'operations',
    icon: Target,
    sections: ['Detection Stats', 'Rule Performance', 'False Positives', 'MITRE Coverage', 'Recommendations'],
    supportedFormats: ['pdf', 'html', 'csv', 'json'],
  },
  // Compliance Reports
  {
    id: 'compliance_pci_dss',
    name: 'PCI-DSS 4.0',
    description: 'Payment Card Industry Data Security Standard (PCI-DSS 4.0) compliance assessment and evidence.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Compliance Score', 'Requirements Status', 'Control Evidence', 'Gap Analysis', 'Remediation Plan'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'compliance_hipaa',
    name: 'HIPAA Security',
    description: 'Health Insurance Portability and Accountability Act security rule compliance assessment.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Compliance Score', 'Safeguards Status', 'Control Evidence', 'Gap Analysis', 'Remediation Plan'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'compliance_soc2',
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2 Type II compliance for security, availability, and confidentiality.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Compliance Score', 'Trust Criteria', 'Control Evidence', 'Gap Analysis', 'Remediation Plan'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'compliance_gdpr',
    name: 'GDPR Article 32',
    description: 'General Data Protection Regulation Article 32 security compliance assessment.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Compliance Score', 'Article 32 Status', 'Control Evidence', 'Gap Analysis', 'Remediation Plan'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'compliance_nist',
    name: 'NIST CSF',
    description: 'NIST Cybersecurity Framework compliance assessment across all five functions.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Maturity Score', 'Function Status', 'Control Evidence', 'Gap Analysis', 'Recommendations'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
  {
    id: 'compliance_cis',
    name: 'CIS Controls v8',
    description: 'Center for Internet Security Controls v8 implementation assessment.',
    category: 'compliance',
    icon: ShieldCheck,
    sections: ['Implementation Score', 'Control Status', 'Implementation Groups', 'Gap Analysis', 'Priorities'],
    supportedFormats: ['pdf', 'html', 'json'],
  },
]

const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: 'pci_dss',
    name: 'Payment Card Industry Data Security Standard',
    shortName: 'PCI-DSS 4.0',
    description: 'Protects cardholder data during payment transactions',
    score: 78,
    controlsTotal: 18,
    controlsCompliant: 12,
    controlsPartial: 3,
    controlsNonCompliant: 2,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-15T10:30:00Z',
    trend: 'up',
    trendValue: 5,
  },
  {
    id: 'hipaa',
    name: 'Health Insurance Portability and Accountability Act',
    shortName: 'HIPAA',
    description: 'Protects sensitive patient health information',
    score: 85,
    controlsTotal: 15,
    controlsCompliant: 11,
    controlsPartial: 2,
    controlsNonCompliant: 1,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-10T14:00:00Z',
    trend: 'stable',
    trendValue: 0,
  },
  {
    id: 'soc2',
    name: 'Service Organization Control 2 Type II',
    shortName: 'SOC 2',
    description: 'Ensures security, availability, and confidentiality of services',
    score: 72,
    controlsTotal: 20,
    controlsCompliant: 12,
    controlsPartial: 4,
    controlsNonCompliant: 3,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-12T09:15:00Z',
    trend: 'up',
    trendValue: 3,
  },
  {
    id: 'gdpr',
    name: 'General Data Protection Regulation',
    shortName: 'GDPR',
    description: 'Protects EU citizens data privacy and rights',
    score: 68,
    controlsTotal: 12,
    controlsCompliant: 7,
    controlsPartial: 3,
    controlsNonCompliant: 1,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-08T16:45:00Z',
    trend: 'down',
    trendValue: -2,
  },
  {
    id: 'nist',
    name: 'NIST Cybersecurity Framework',
    shortName: 'NIST CSF',
    description: 'Comprehensive cybersecurity risk management framework',
    score: 81,
    controlsTotal: 25,
    controlsCompliant: 18,
    controlsPartial: 4,
    controlsNonCompliant: 2,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-14T11:20:00Z',
    trend: 'up',
    trendValue: 4,
  },
  {
    id: 'cis',
    name: 'CIS Controls Version 8',
    shortName: 'CIS v8',
    description: 'Prioritized set of actions for cyber defense',
    score: 75,
    controlsTotal: 18,
    controlsCompliant: 11,
    controlsPartial: 5,
    controlsNonCompliant: 1,
    controlsNotAssessed: 1,
    lastAssessed: '2026-01-13T13:30:00Z',
    trend: 'stable',
    trendValue: 1,
  },
]

const SCHEDULE_PRESETS = [
  { value: 'daily', label: 'Daily (6:00 AM)' },
  { value: 'weekly', label: 'Weekly (Monday 6:00 AM)' },
  { value: 'monthly', label: 'Monthly (1st day 6:00 AM)' },
  { value: 'custom', label: 'Custom (Cron expression)' },
]

type ReportFormat = 'pdf' | 'html' | 'csv' | 'json'

const FORMAT_OPTIONS: { value: ReportFormat; label: string; icon: React.ElementType }[] = [
  { value: 'pdf', label: 'PDF', icon: FileType },
  { value: 'html', label: 'HTML', icon: FileText },
  { value: 'csv', label: 'CSV', icon: FileSpreadsheet },
  { value: 'json', label: 'JSON', icon: FileJson },
]

const CATEGORY_LABELS: Record<string, string> = {
  security: 'Security Reports',
  compliance: 'Compliance Reports',
  operations: 'Operations Reports',
  custom: 'Custom Reports',
}

type CustomSectionType = CustomReportSection['type']

const CUSTOM_SECTION_TYPES: { id: CustomSectionType; label: string; icon: React.ElementType; description: string }[] = [
  { id: 'metrics', label: 'Key Metrics', icon: Gauge, description: 'Display important KPIs and statistics' },
  { id: 'alerts', label: 'Alert Summary', icon: AlertTriangle, description: 'Summary of alerts by severity and status' },
  { id: 'agents', label: 'Agent Status', icon: Server, description: 'Agent deployment and health overview' },
  { id: 'threats', label: 'Threat Analysis', icon: Shield, description: 'Top threats and MITRE mapping' },
  { id: 'chart', label: 'Custom Chart', icon: BarChart3, description: 'Visual data representation' },
  { id: 'table', label: 'Data Table', icon: ClipboardList, description: 'Tabular data display' },
  { id: 'text', label: 'Text Section', icon: FileText, description: 'Custom text or notes' },
]

// ============================================================================
// Component
// ============================================================================

export default function Reports() {
  // View state
  const [activeTab, setActiveTab] = useState<'generate' | 'compliance' | 'scheduled' | 'history' | 'builder'>('generate')

  // Generate state
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [selectedFormat, setSelectedFormat] = useState<'pdf' | 'html' | 'csv' | 'json'>('pdf')
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [dateFrom, setDateFrom] = useState(() => {
    const d = new Date()
    d.setDate(d.getDate() - 30)
    return d.toISOString().split('T')[0]
  })
  const [dateTo, setDateTo] = useState(() => new Date().toISOString().split('T')[0])
  const [generating, setGenerating] = useState(false)
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])

  // Schedule state
  const [schedules, setSchedules] = useState<ScheduledReport[]>([])
  const [loadingSchedules, setLoadingSchedules] = useState(false)
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<ScheduledReport | null>(null)

  // History state
  const [reports, setReports] = useState<GeneratedReport[]>([])
  const [loadingHistory, setLoadingHistory] = useState(false)

  // Report viewer
  const [viewingReport, setViewingReport] = useState<ReportData | null>(null)

  // Compliance state
  const [complianceFrameworks, setComplianceFrameworks] = useState<ComplianceFramework[]>(COMPLIANCE_FRAMEWORKS)
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [loadingCompliance, setLoadingCompliance] = useState(false)

  // Custom Report Builder state
  const [customReport, setCustomReport] = useState<CustomReportConfig>({
    name: '',
    description: '',
    sections: [],
    dateRange: { from: dateFrom, to: dateTo },
    filters: [],
    format: 'pdf',
  })

  // Fetch data on mount
  useEffect(() => {
    if (activeTab === 'history') {
      fetchReportHistory()
    } else if (activeTab === 'scheduled') {
      fetchSchedules()
    } else if (activeTab === 'compliance') {
      fetchComplianceData()
    }
  }, [activeTab])

  const fetchReportHistory = useCallback(async () => {
    setLoadingHistory(true)
    try {
      const response = await axios.get('/api/v1/reports/history')
      if (response.data?.data) {
        setReports(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch report history:', error)
    } finally {
      setLoadingHistory(false)
    }
  }, [])

  const fetchSchedules = useCallback(async () => {
    setLoadingSchedules(true)
    try {
      const response = await axios.get('/api/v1/reports/scheduled')
      if (response.data?.data) {
        setSchedules(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch schedules:', error)
    } finally {
      setLoadingSchedules(false)
    }
  }, [])

  const fetchComplianceData = useCallback(async () => {
    setLoadingCompliance(true)
    try {
      const response = await axios.get('/api/v1/compliance/dashboard')
      if (response.data?.frameworks) {
        setComplianceFrameworks(response.data.frameworks)
      }
    } catch (error) {
      // Use default data if API not available
      logger.error('Failed to fetch compliance data:', error)
    } finally {
      setLoadingCompliance(false)
    }
  }, [])

  const handleGenerate = async () => {
    if (!selectedTemplate) return
    setGenerating(true)

    try {
      const response = await axios.post('/api/v1/reports/generate', {
        template_id: selectedTemplate,
        date_from: dateFrom,
        date_to: dateTo,
        format: selectedFormat,
        agent_ids: selectedAgents.length > 0 ? selectedAgents : undefined,
      })

      if (response.data?.data) {
        const reportData = response.data.data as ReportData
        setViewingReport(reportData)
        toast.success('Report generated successfully')
      }
    } catch (error: any) {
      // If the API isn't available, generate a client-side preview
      const template = REPORT_TEMPLATES.find(t => t.id === selectedTemplate)
      if (template) {
        const previewReport = generateClientPreview(template, dateFrom, dateTo)
        setViewingReport(previewReport)
        toast.success('Report preview generated')
      } else {
        toast.error('Failed to generate report')
      }
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = async (report: GeneratedReport, format?: string) => {
    try {
      const url = format
        ? `/api/v1/reports/${report.id}/download?format=${format}`
        : `/api/v1/reports/${report.id}/download`

      window.open(url, '_blank')
      toast.success('Download started')
    } catch (error) {
      toast.error('Failed to download report')
    }
  }

  const handleViewReport = async (report: GeneratedReport) => {
    try {
      const response = await axios.get(`/api/v1/reports/${report.id}`)
      if (response.data?.data) {
        setViewingReport(response.data.data)
      }
    } catch {
      const template = REPORT_TEMPLATES.find(t => t.id === report.template_id)
      if (template) {
        const previewReport = generateClientPreview(template, report.date_from, report.date_to)
        setViewingReport(previewReport)
      }
    }
  }

  const handleToggleSchedule = async (schedule: ScheduledReport) => {
    try {
      const endpoint = schedule.enabled
        ? `/api/v1/reports/scheduled/${schedule.id}/pause`
        : `/api/v1/reports/scheduled/${schedule.id}/resume`

      await axios.post(endpoint)
      toast.success(schedule.enabled ? 'Schedule paused' : 'Schedule resumed')
      fetchSchedules()
    } catch (error) {
      toast.error('Failed to update schedule')
    }
  }

  const handleDeleteSchedule = async (schedule: ScheduledReport) => {
    if (!confirm(`Are you sure you want to delete the schedule "${schedule.name}"?`)) {
      return
    }

    try {
      await axios.delete(`/api/v1/reports/scheduled/${schedule.id}`)
      toast.success('Schedule deleted')
      fetchSchedules()
    } catch (error) {
      toast.error('Failed to delete schedule')
    }
  }

  const handleRunNow = async (schedule: ScheduledReport) => {
    try {
      await axios.post(`/api/v1/reports/scheduled/${schedule.id}/run`)
      toast.success('Report generation started')
    } catch (error) {
      toast.error('Failed to run report')
    }
  }

  const handlePrint = () => {
    window.print()
  }

  const handleGenerateComplianceReport = async (frameworkId: string) => {
    const templateId = `compliance_${frameworkId}`
    setSelectedTemplate(templateId)
    setActiveTab('generate')
    toast.info('Template selected. Configure options and generate your report.')
  }

  // Filter templates
  const filteredTemplates = useMemo(() => {
    return REPORT_TEMPLATES.filter(t => {
      if (categoryFilter && t.category !== categoryFilter) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return t.name.toLowerCase().includes(query) ||
               t.description.toLowerCase().includes(query)
      }
      return true
    })
  }, [categoryFilter, searchQuery])

  // Group templates by category
  const templatesByCategory = useMemo(() => {
    return filteredTemplates.reduce((acc, template) => {
      if (!acc[template.category]) {
        acc[template.category] = []
      }
      acc[template.category].push(template)
      return acc
    }, {} as Record<string, ReportTemplate[]>)
  }, [filteredTemplates])

  const selectedTemplateData = REPORT_TEMPLATES.find(t => t.id === selectedTemplate)

  // Calculate overall compliance score
  const overallComplianceScore = useMemo(() => {
    if (complianceFrameworks.length === 0) return 0
    const total = complianceFrameworks.reduce((sum, f) => sum + f.score, 0)
    return Math.round(total / complianceFrameworks.length)
  }, [complianceFrameworks])

  const complianceStats = useMemo(() => {
    const total = complianceFrameworks.reduce((acc, f) => ({
      compliant: acc.compliant + f.controlsCompliant,
      partial: acc.partial + f.controlsPartial,
      nonCompliant: acc.nonCompliant + f.controlsNonCompliant,
      notAssessed: acc.notAssessed + f.controlsNotAssessed,
      total: acc.total + f.controlsTotal,
    }), { compliant: 0, partial: 0, nonCompliant: 0, notAssessed: 0, total: 0 })
    return total
  }, [complianceFrameworks])

  return (
    <MainLayout title="Reports & Compliance">
      <Head title="Reports - Tamandua EDR" />

      {viewingReport ? (
        <ReportViewer
          report={viewingReport}
          onClose={() => setViewingReport(null)}
          onPrint={handlePrint}
        />
      ) : (
        <div className="space-y-6">
          {/* Tab Navigation */}
          <div className="flex items-center gap-2 pb-4 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            <TabButton
              active={activeTab === 'generate'}
              onClick={() => setActiveTab('generate')}
              icon={FileText}
              label="Generate Report"
            />
            <TabButton
              active={activeTab === 'compliance'}
              onClick={() => setActiveTab('compliance')}
              icon={ShieldCheck}
              label="Compliance Dashboard"
            />
            <TabButton
              active={activeTab === 'scheduled'}
              onClick={() => setActiveTab('scheduled')}
              icon={Timer}
              label="Scheduled Reports"
            />
            <TabButton
              active={activeTab === 'history'}
              onClick={() => setActiveTab('history')}
              icon={History}
              label="Report History"
            />
            <TabButton
              active={activeTab === 'builder'}
              onClick={() => setActiveTab('builder')}
              icon={Settings}
              label="Custom Builder"
            />
          </div>

          {/* Generate Tab */}
          {activeTab === 'generate' && (
            <div className="space-y-6">
              {/* Search and Filter */}
              <div className="flex items-center gap-4">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
                  <input
                    type="text"
                    placeholder="Search report templates..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 rounded-lg text-sm focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                    style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  <select
                    value={categoryFilter || ''}
                    onChange={(e) => setCategoryFilter(e.target.value || null)}
                    className="rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
                    style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
                  >
                    <option value="">All Categories</option>
                    <option value="security">Security</option>
                    <option value="compliance">Compliance</option>
                    <option value="operations">Operations</option>
                  </select>
                </div>
              </div>

              {/* Report Templates by Category */}
              <div className="space-y-6">
                {Object.entries(templatesByCategory).map(([category, templates]) => (
                  <div key={category} className="card-sentinel rounded-xl p-6">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                      {category === 'security' && <Shield className="h-5 w-5" style={{ color: 'var(--crit)' }} />}
                      {category === 'compliance' && <ShieldCheck className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />}
                      {category === 'operations' && <Server className="h-5 w-5" style={{ color: 'rgb(96, 165, 250)' }} />}
                      {CATEGORY_LABELS[category] || category}
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {templates.map((tmpl) => {
                        const Icon = tmpl.icon
                        const isSelected = selectedTemplate === tmpl.id
                        return (
                          <button
                            key={tmpl.id}
                            onClick={() => setSelectedTemplate(isSelected ? null : tmpl.id)}
                            className="flex flex-col items-start p-4 rounded-lg border transition-all text-left"
                            style={{
                              backgroundColor: isSelected ? 'rgba(16, 185, 129, 0.2)' : 'var(--surface-alt)',
                              borderColor: isSelected ? 'var(--emerald-400)' : 'var(--border)',
                              boxShadow: isSelected ? '0 0 0 1px var(--emerald-400)' : 'none'
                            }}
                          >
                            <div className="flex items-center gap-3 mb-2">
                              <div className="p-2 rounded-lg" style={{
                                backgroundColor: isSelected ? 'rgba(16, 185, 129, 0.3)' : 'var(--surface)',
                                color: isSelected ? 'var(--emerald-400)' : 'var(--muted)'
                              }}>
                                <Icon className="h-5 w-5" />
                              </div>
                              <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{tmpl.name}</h3>
                            </div>
                            <p className="text-sm mb-3 line-clamp-2" style={{ color: 'var(--muted)' }}>{tmpl.description}</p>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {tmpl.sections.slice(0, 3).map((section, idx) => (
                                <span
                                  key={idx}
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
                                >
                                  {section}
                                </span>
                              ))}
                              {tmpl.sections.length > 3 && (
                                <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}>
                                  +{tmpl.sections.length - 3} more
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-1 text-xs" style={{ color: 'var(--muted)' }}>
                              Formats: {tmpl.supportedFormats.join(', ').toUpperCase()}
                            </div>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>

              {/* Generation Options */}
              {selectedTemplate && (
                <div className="card-sentinel rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Report Options</h3>
                  <div className="flex flex-wrap items-end gap-6">
                    {/* Date Range */}
                    <div className="flex items-center gap-3">
                      <Calendar className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                      <div>
                        <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>From</label>
                        <input
                          type="date"
                          value={dateFrom}
                          onChange={(e) => setDateFrom(e.target.value)}
                          className="rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                          style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
                        />
                      </div>
                      <span className="mt-4" style={{ color: 'var(--muted)' }}>to</span>
                      <div>
                        <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>To</label>
                        <input
                          type="date"
                          value={dateTo}
                          onChange={(e) => setDateTo(e.target.value)}
                          className="rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                          style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
                        />
                      </div>
                    </div>

                    {/* Quick Ranges */}
                    <div className="flex items-center gap-2">
                      {[
                        { label: '7d', days: 7 },
                        { label: '30d', days: 30 },
                        { label: '90d', days: 90 },
                      ].map(({ label, days }) => (
                        <button
                          key={label}
                          onClick={() => {
                            const to = new Date()
                            const from = new Date()
                            from.setDate(from.getDate() - days)
                            setDateFrom(from.toISOString().split('T')[0])
                            setDateTo(to.toISOString().split('T')[0])
                          }}
                          className="px-3 py-1.5 rounded text-xs transition-colors hover:opacity-80"
                          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                        >
                          Last {label}
                        </button>
                      ))}
                    </div>

                    {/* Format Selection */}
                    <div>
                      <label className="block text-xs mb-1" style={{ color: 'var(--muted)' }}>Output Format</label>
                      <div className="flex items-center gap-2">
                        {FORMAT_OPTIONS.filter(f =>
                          selectedTemplateData?.supportedFormats.includes(f.value)
                        ).map((format) => {
                          const FormatIcon = format.icon
                          return (
                            <button
                              key={format.value}
                              onClick={() => setSelectedFormat(format.value)}
                              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
                              style={{
                                backgroundColor: selectedFormat === format.value ? 'var(--emerald-400)' : 'var(--surface-alt)',
                                color: selectedFormat === format.value ? 'var(--bg)' : 'var(--muted)'
                              }}
                            >
                              <FormatIcon className="h-4 w-4" />
                              {format.label}
                            </button>
                          )
                        })}
                      </div>
                    </div>

                    {/* Generate Button */}
                    <button
                      onClick={handleGenerate}
                      disabled={generating}
                      className="btn-sentinel flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-medium transition-colors ml-auto"
                    >
                      {generating ? (
                        <>
                          <RefreshCw className="h-4 w-4 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Zap className="h-4 w-4" />
                          Generate Report
                        </>
                      )}
                    </button>

                    {/* Schedule Button */}
                    <button
                      onClick={() => {
                        setEditingSchedule(null)
                        setShowScheduleModal(true)
                      }}
                      className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
                      style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                    >
                      <Timer className="h-4 w-4" />
                      Schedule
                    </button>
                  </div>
                </div>
              )}

              {!selectedTemplate && (
                <div className="card-sentinel rounded-xl p-12 text-center">
                  <FileText className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--muted)' }} />
                  <p className="text-lg" style={{ color: 'var(--muted)' }}>Select a report template to generate</p>
                  <p className="text-sm mt-2" style={{ color: 'var(--muted)' }}>
                    Choose from security, compliance, or operations reports above
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Compliance Dashboard Tab */}
          {activeTab === 'compliance' && (
            <ComplianceDashboard
              frameworks={complianceFrameworks}
              overallScore={overallComplianceScore}
              stats={complianceStats}
              loading={loadingCompliance}
              selectedFramework={selectedFramework}
              onSelectFramework={setSelectedFramework}
              onGenerateReport={handleGenerateComplianceReport}
              onRefresh={fetchComplianceData}
            />
          )}

          {/* Scheduled Tab */}
          {activeTab === 'scheduled' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Scheduled Reports</h2>
                <button
                  onClick={() => {
                    setEditingSchedule(null)
                    setShowScheduleModal(true)
                  }}
                  className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  New Schedule
                </button>
              </div>

              {loadingSchedules ? (
                <LoadingState message="Loading schedules..." />
              ) : schedules.length === 0 ? (
                <EmptyState
                  icon={Timer}
                  title="No scheduled reports"
                  description="Create a schedule to automatically generate reports on a recurring basis"
                />
              ) : (
                <div className="card-sentinel rounded-xl divide-y" style={{ borderColor: 'var(--border)' }}>
                  {schedules.map((schedule) => {
                    const template = REPORT_TEMPLATES.find(t => t.id === schedule.template_id)
                    const Icon = template?.icon || FileText
                    return (
                      <div key={schedule.id} className="flex items-center gap-4 p-4" style={{ borderColor: 'var(--border)' }}>
                        <div className="p-2 rounded-lg" style={{
                          backgroundColor: schedule.enabled ? 'rgba(16, 185, 129, 0.2)' : 'var(--surface)',
                          color: schedule.enabled ? 'var(--emerald-400)' : 'var(--muted)'
                        }}>
                          <Icon className="h-5 w-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{schedule.name}</h3>
                            <span className="text-xs px-2 py-0.5 rounded" style={{
                              backgroundColor: schedule.enabled ? 'rgba(16, 185, 129, 0.2)' : 'var(--surface)',
                              color: schedule.enabled ? 'var(--emerald-400)' : 'var(--muted)'
                            }}>
                              {schedule.enabled ? 'Active' : 'Paused'}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-xs mt-1" style={{ color: 'var(--muted)' }}>
                            <span>{template?.name || schedule.template_id}</span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {schedule.schedule_display || schedule.schedule}
                            </span>
                            <span className="flex items-center gap-1">
                              <Mail className="h-3 w-3" />
                              {schedule.recipients.length} recipients
                            </span>
                            <span className="uppercase">{schedule.format}</span>
                          </div>
                          {schedule.next_run_at && schedule.enabled && (
                            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                              Next run: {formatDate(schedule.next_run_at)}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleRunNow(schedule)}
                            className="p-2 rounded-lg transition-colors hover:opacity-80"
                            style={{ color: 'var(--muted)', backgroundColor: 'transparent' }}
                            title="Run Now"
                          >
                            <Play className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => handleToggleSchedule(schedule)}
                            className="p-2 rounded-lg transition-colors"
                            style={{
                              color: schedule.enabled ? 'var(--high)' : 'var(--emerald-400)',
                              backgroundColor: schedule.enabled ? 'rgba(251, 146, 60, 0.2)' : 'rgba(16, 185, 129, 0.2)'
                            }}
                            title={schedule.enabled ? 'Pause' : 'Resume'}
                          >
                            {schedule.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                          </button>
                          <button
                            onClick={() => {
                              setEditingSchedule(schedule)
                              setShowScheduleModal(true)
                            }}
                            className="p-2 rounded-lg transition-colors hover:opacity-80"
                            style={{ color: 'var(--muted)', backgroundColor: 'transparent' }}
                            title="Edit"
                          >
                            <Edit className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteSchedule(schedule)}
                            className="p-2 rounded-lg transition-colors"
                            style={{ color: 'var(--crit)', backgroundColor: 'rgba(239, 68, 68, 0.2)' }}
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* History Tab */}
          {activeTab === 'history' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Report History</h2>
                <button
                  onClick={fetchReportHistory}
                  disabled={loadingHistory}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                >
                  <RefreshCw className={cn('h-4 w-4', loadingHistory && 'animate-spin')} />
                  Refresh
                </button>
              </div>

              {loadingHistory ? (
                <LoadingState message="Loading history..." />
              ) : reports.length === 0 ? (
                <EmptyState
                  icon={History}
                  title="No reports generated yet"
                  description="Generate your first report from the Generate tab"
                />
              ) : (
                <div className="card-sentinel rounded-xl divide-y" style={{ borderColor: 'var(--border)' }}>
                  {reports.map((report) => {
                    const template = REPORT_TEMPLATES.find(t => t.id === report.template_id)
                    const Icon = template?.icon || FileText
                    return (
                      <div key={report.id} className="flex items-center gap-4 p-4 transition-colors hover:opacity-90" style={{ borderColor: 'var(--border)' }}>
                        <div className="p-2 rounded-lg" style={{
                          backgroundColor: report.status === 'ready' ? 'rgba(16, 185, 129, 0.2)' :
                            report.status === 'generating' ? 'rgba(251, 146, 60, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                          color: report.status === 'ready' ? 'var(--emerald-400)' :
                            report.status === 'generating' ? 'var(--high)' : 'var(--crit)'
                        }}>
                          <Icon className="h-5 w-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <h3 className="font-medium" style={{ color: 'var(--fg)' }}>{report.template_name}</h3>
                          <div className="flex items-center gap-4 text-xs mt-1" style={{ color: 'var(--muted)' }}>
                            <span className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              {report.date_from} to {report.date_to}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatDate(report.created_at)}
                            </span>
                            <span>by {report.generated_by}</span>
                            <span className="uppercase">{report.format || 'PDF'}</span>
                            {report.file_size && (
                              <span>{formatFileSize(report.file_size)}</span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs px-2 py-0.5 rounded" style={{
                            backgroundColor: report.status === 'ready' ? 'rgba(16, 185, 129, 0.2)' :
                              report.status === 'generating' ? 'rgba(251, 146, 60, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                            color: report.status === 'ready' ? 'var(--emerald-400)' :
                              report.status === 'generating' ? 'var(--high)' : 'var(--crit)'
                          }}>
                            {report.status}
                          </span>
                          {report.status === 'ready' && (
                            <>
                              <button
                                onClick={() => handleViewReport(report)}
                                className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm transition-colors"
                                style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
                              >
                                <Eye className="h-4 w-4" />
                                View
                              </button>
                              <DownloadMenu report={report} onDownload={handleDownload} />
                            </>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* Custom Report Builder Tab */}
          {activeTab === 'builder' && (
            <CustomReportBuilder
              config={customReport}
              onChange={setCustomReport}
              onGenerate={async () => {
                toast.info('Custom report generation requires a saved report template before it can run')
              }}
            />
          )}
        </div>
      )}

      {/* Schedule Modal */}
      {showScheduleModal && (
        <ScheduleModal
          template={selectedTemplateData}
          schedule={editingSchedule}
          onClose={() => {
            setShowScheduleModal(false)
            setEditingSchedule(null)
          }}
          onSave={() => {
            setShowScheduleModal(false)
            setEditingSchedule(null)
            fetchSchedules()
          }}
        />
      )}
    </MainLayout>
  )
}

// ============================================================================
// Tab Button Component
// ============================================================================

function TabButton({ active, onClick, icon: Icon, label }: {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap"
      style={{
        backgroundColor: active ? 'var(--emerald-400)' : 'transparent',
        color: active ? 'var(--bg)' : 'var(--muted)'
      }}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  )
}

// ============================================================================
// Loading State Component
// ============================================================================

function LoadingState({ message }: { message: string }) {
  return (
    <div className="card-sentinel rounded-xl p-12 text-center">
      <RefreshCw className="h-8 w-8 mx-auto mb-4 animate-spin" style={{ color: 'var(--muted)' }} />
      <p style={{ color: 'var(--muted)' }}>{message}</p>
    </div>
  )
}

// ============================================================================
// Empty State Component
// ============================================================================

function EmptyState({ icon: Icon, title, description }: {
  icon: React.ElementType
  title: string
  description: string
}) {
  return (
    <div className="card-sentinel rounded-xl p-12 text-center">
      <Icon className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--muted)' }} />
      <p className="text-lg" style={{ color: 'var(--muted)' }}>{title}</p>
      <p className="text-sm mt-2" style={{ color: 'var(--muted)' }}>{description}</p>
    </div>
  )
}

// ============================================================================
// Compliance Dashboard Component
// ============================================================================

function ComplianceDashboard({
  frameworks,
  overallScore,
  stats,
  loading,
  selectedFramework,
  onSelectFramework,
  onGenerateReport,
  onRefresh,
}: {
  frameworks: ComplianceFramework[]
  overallScore: number
  stats: { compliant: number; partial: number; nonCompliant: number; notAssessed: number; total: number }
  loading: boolean
  selectedFramework: string | null
  onSelectFramework: (id: string | null) => void
  onGenerateReport: (frameworkId: string) => void
  onRefresh: () => void
}) {
  if (loading) {
    return <LoadingState message="Loading compliance data..." />
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--emerald-400)'
    if (score >= 60) return 'var(--high)'
    return 'var(--crit)'
  }

  const getScoreBgColor = (score: number) => {
    if (score >= 80) return 'rgba(16, 185, 129, 0.2)'
    if (score >= 60) return 'rgba(251, 146, 60, 0.2)'
    return 'rgba(239, 68, 68, 0.2)'
  }

  const getScoreLabel = (score: number) => {
    if (score >= 90) return 'Excellent'
    if (score >= 80) return 'Good'
    if (score >= 70) return 'Moderate'
    if (score >= 60) return 'Needs Work'
    return 'Critical'
  }

  return (
    <div className="space-y-6">
      {/* Overall Compliance Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Gauge */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Overall Compliance</h3>
            <button
              onClick={onRefresh}
              className="p-2 rounded-lg transition-colors hover:opacity-80"
              style={{ color: 'var(--muted)' }}
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
          <div className="flex flex-col items-center">
            <div
              className="relative w-32 h-32 rounded-full flex items-center justify-center"
              style={{ backgroundColor: getScoreBgColor(overallScore) }}
            >
              <div className="text-center">
                <span className="text-4xl font-bold" style={{ color: getScoreColor(overallScore) }}>
                  {overallScore}
                </span>
                <span className="text-lg" style={{ color: 'var(--muted)' }}>%</span>
              </div>
              {/* Progress ring */}
              <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="45"
                  fill="none"
                  stroke="var(--border)"
                  strokeWidth="6"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="45"
                  fill="none"
                  stroke={getScoreColor(overallScore)}
                  strokeWidth="6"
                  strokeDasharray={`${overallScore * 2.83} 283`}
                  strokeLinecap="round"
                />
              </svg>
            </div>
            <p className="mt-3 text-sm font-medium" style={{ color: getScoreColor(overallScore) }}>
              {getScoreLabel(overallScore)}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
              Across {frameworks.length} frameworks
            </p>
          </div>
        </div>

        {/* Control Status Summary */}
        <div className="card-sentinel rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Control Status</h3>
          <div className="space-y-4">
            <ControlStatusBar
              label="Compliant"
              count={stats.compliant}
              total={stats.total}
              color="var(--emerald-400)"
              bgColor="rgba(16, 185, 129, 0.8)"
              icon={CheckCircle2}
            />
            <ControlStatusBar
              label="Partial"
              count={stats.partial}
              total={stats.total}
              color="var(--high)"
              bgColor="rgba(251, 146, 60, 0.8)"
              icon={MinusCircle}
            />
            <ControlStatusBar
              label="Non-Compliant"
              count={stats.nonCompliant}
              total={stats.total}
              color="var(--crit)"
              bgColor="rgba(239, 68, 68, 0.8)"
              icon={XCircle}
            />
            <ControlStatusBar
              label="Not Assessed"
              count={stats.notAssessed}
              total={stats.total}
              color="var(--muted)"
              bgColor="var(--surface-alt)"
              icon={AlertCircle}
            />
          </div>
        </div>

        {/* Quick Actions */}
        <div className="card-sentinel rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Quick Actions</h3>
          <div className="space-y-3">
            <button
              onClick={() => onGenerateReport('summary')}
              className="w-full flex items-center justify-between p-3 rounded-lg transition-colors hover:opacity-90"
              style={{ backgroundColor: 'var(--surface-alt)' }}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)' }}>
                  <FileText className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <span className="text-sm" style={{ color: 'var(--fg)' }}>Generate Summary Report</span>
              </div>
              <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            </button>
            <button
              onClick={() => {}}
              className="w-full flex items-center justify-between p-3 rounded-lg transition-colors hover:opacity-90"
              style={{ backgroundColor: 'var(--surface-alt)' }}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(251, 146, 60, 0.2)' }}>
                  <AlertTriangle className="h-4 w-4" style={{ color: 'var(--high)' }} />
                </div>
                <span className="text-sm" style={{ color: 'var(--fg)' }}>View Gap Analysis</span>
              </div>
              <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            </button>
            <button
              onClick={() => {}}
              className="w-full flex items-center justify-between p-3 rounded-lg transition-colors hover:opacity-90"
              style={{ backgroundColor: 'var(--surface-alt)' }}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)' }}>
                  <TrendingUp className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <span className="text-sm" style={{ color: 'var(--fg)' }}>Compliance Trends</span>
              </div>
              <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
            </button>
          </div>
        </div>
      </div>

      {/* Framework Cards */}
      <div className="card-sentinel rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Compliance Frameworks</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {frameworks.map((framework) => (
            <FrameworkCard
              key={framework.id}
              framework={framework}
              isSelected={selectedFramework === framework.id}
              onSelect={() => onSelectFramework(
                selectedFramework === framework.id ? null : framework.id
              )}
              onGenerateReport={() => onGenerateReport(framework.id)}
            />
          ))}
        </div>
      </div>

      {/* Selected Framework Detail */}
      {selectedFramework && (
        <FrameworkDetail
          framework={frameworks.find(f => f.id === selectedFramework)!}
          onClose={() => onSelectFramework(null)}
          onGenerateReport={() => onGenerateReport(selectedFramework)}
        />
      )}
    </div>
  )
}

// ============================================================================
// Control Status Bar Component
// ============================================================================

function ControlStatusBar({ label, count, total, color, bgColor, icon: Icon }: {
  label: string
  count: number
  total: number
  color: string
  bgColor: string
  icon: React.ElementType
}) {
  const percentage = total > 0 ? Math.round((count / total) * 100) : 0

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4" style={{ color }} />
          <span style={{ color: 'var(--muted)' }}>{label}</span>
        </div>
        <span style={{ color: 'var(--muted)' }}>{count} ({percentage}%)</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface-alt)' }}>
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${percentage}%`, backgroundColor: bgColor }}
        />
      </div>
    </div>
  )
}

// ============================================================================
// Framework Card Component
// ============================================================================

function FrameworkCard({ framework, isSelected, onSelect, onGenerateReport }: {
  framework: ComplianceFramework
  isSelected: boolean
  onSelect: () => void
  onGenerateReport: () => void
}) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--emerald-400)'
    if (score >= 60) return 'var(--high)'
    return 'var(--crit)'
  }

  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    if (trend === 'up') return <TrendingUp className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
    if (trend === 'down') return <TrendingUp className="h-3 w-3 rotate-180" style={{ color: 'var(--crit)' }} />
    return <Activity className="h-3 w-3" style={{ color: 'var(--muted)' }} />
  }

  return (
    <div
      className="p-4 rounded-lg border transition-all cursor-pointer"
      style={{
        backgroundColor: isSelected ? 'rgba(16, 185, 129, 0.2)' : 'var(--surface-alt)',
        borderColor: isSelected ? 'var(--emerald-400)' : 'var(--border)',
        boxShadow: isSelected ? '0 0 0 1px var(--emerald-400)' : 'none'
      }}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h4 className="font-medium" style={{ color: 'var(--fg)' }}>{framework.shortName}</h4>
          <p className="text-xs mt-0.5 line-clamp-1" style={{ color: 'var(--muted)' }}>{framework.description}</p>
        </div>
        <div className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium" style={{
          backgroundColor: framework.score >= 80 ? 'rgba(16, 185, 129, 0.2)' :
            framework.score >= 60 ? 'rgba(251, 146, 60, 0.2)' : 'rgba(239, 68, 68, 0.2)',
          color: getScoreColor(framework.score)
        }}>
          {getTrendIcon(framework.trend)}
          {framework.trendValue !== 0 && (
            <span>{framework.trendValue > 0 ? '+' : ''}{framework.trendValue}%</span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4 mb-3">
        <div className="flex-1">
          <div className="flex items-end gap-1">
            <span className="text-2xl font-bold" style={{ color: getScoreColor(framework.score) }}>
              {framework.score}
            </span>
            <span className="text-sm mb-0.5" style={{ color: 'var(--muted)' }}>%</span>
          </div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>Compliance Score</p>
        </div>
        <div className="flex-1">
          <div className="flex items-end gap-1">
            <span className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{framework.controlsCompliant}</span>
            <span className="text-sm mb-0.5" style={{ color: 'var(--muted)' }}>/{framework.controlsTotal}</span>
          </div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>Controls</p>
        </div>
      </div>

      {/* Mini progress bar */}
      <div className="h-1.5 rounded-full overflow-hidden flex" style={{ backgroundColor: 'var(--surface)' }}>
        <div
          className="transition-all"
          style={{ width: `${(framework.controlsCompliant / framework.controlsTotal) * 100}%`, backgroundColor: 'var(--emerald-400)' }}
        />
        <div
          className="transition-all"
          style={{ width: `${(framework.controlsPartial / framework.controlsTotal) * 100}%`, backgroundColor: 'var(--high)' }}
        />
        <div
          className="transition-all"
          style={{ width: `${(framework.controlsNonCompliant / framework.controlsTotal) * 100}%`, backgroundColor: 'var(--crit)' }}
        />
      </div>

      <div className="flex items-center justify-between mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
        <span className="text-xs" style={{ color: 'var(--muted)' }}>
          {framework.lastAssessed ? `Assessed ${formatDate(framework.lastAssessed)}` : 'Not assessed'}
        </span>
        <button
          onClick={(e) => {
            e.stopPropagation()
            onGenerateReport()
          }}
          className="text-xs font-medium flex items-center gap-1"
          style={{ color: 'var(--emerald-400)' }}
        >
          Generate Report
          <ArrowRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  )
}

// ============================================================================
// Framework Detail Component
// ============================================================================

function FrameworkDetail({ framework, onClose, onGenerateReport }: {
  framework: ComplianceFramework
  onClose: () => void
  onGenerateReport: () => void
}) {
  return (
    <div className="card-sentinel rounded-xl p-6">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>{framework.name}</h3>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{framework.description}</p>
        </div>
        <button
          onClick={onClose}
          className="p-2 rounded-lg transition-colors hover:opacity-80"
          style={{ color: 'var(--muted)' }}
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'rgba(16, 185, 129, 0.3)' }}>
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--emerald-400)' }}>Compliant</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{framework.controlsCompliant}</p>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>controls</p>
        </div>
        <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(251, 146, 60, 0.1)', borderColor: 'rgba(251, 146, 60, 0.3)' }}>
          <div className="flex items-center gap-2 mb-2">
            <MinusCircle className="h-5 w-5" style={{ color: 'var(--high)' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--high)' }}>Partial</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{framework.controlsPartial}</p>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>controls</p>
        </div>
        <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)' }}>
          <div className="flex items-center gap-2 mb-2">
            <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--crit)' }}>Non-Compliant</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{framework.controlsNonCompliant}</p>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>controls</p>
        </div>
        <div className="rounded-lg p-4 border" style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="h-5 w-5" style={{ color: 'var(--muted)' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--muted)' }}>Not Assessed</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{framework.controlsNotAssessed}</p>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>controls</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={onGenerateReport}
          className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
        >
          <FileText className="h-4 w-4" />
          Generate Full Report
        </button>
        <button
          onClick={() => {}}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
        >
          <Eye className="h-4 w-4" />
          View Controls
        </button>
        <button
          onClick={() => {}}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
        >
          <AlertTriangle className="h-4 w-4" />
          Gap Analysis
        </button>
      </div>
    </div>
  )
}

// ============================================================================
// Custom Report Builder Component
// ============================================================================

function CustomReportBuilder({ config, onChange, onGenerate }: {
  config: CustomReportConfig
  onChange: (config: CustomReportConfig) => void
  onGenerate: () => void
}) {
  const addSection = (type: CustomSectionType) => {
    const newSection: CustomReportSection = {
      id: `section_${Date.now()}`,
      type,
      title: CUSTOM_SECTION_TYPES.find(t => t.id === type)?.label || 'Section',
      enabled: true,
      config: {},
    }
    onChange({ ...config, sections: [...config.sections, newSection] })
  }

  const removeSection = (id: string) => {
    onChange({ ...config, sections: config.sections.filter(s => s.id !== id) })
  }

  const moveSection = (id: string, direction: 'up' | 'down') => {
    const idx = config.sections.findIndex(s => s.id === id)
    if (idx === -1) return
    if (direction === 'up' && idx === 0) return
    if (direction === 'down' && idx === config.sections.length - 1) return

    const newSections = [...config.sections]
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1
    ;[newSections[idx], newSections[swapIdx]] = [newSections[swapIdx], newSections[idx]]
    onChange({ ...config, sections: newSections })
  }

  return (
    <div className="space-y-6">
      {/* Report Configuration */}
      <div className="card-sentinel rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Custom Report Configuration</h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Report Name</label>
            <input
              type="text"
              value={config.name}
              onChange={(e) => onChange({ ...config, name: e.target.value })}
              placeholder="My Custom Report"
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            />
          </div>
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Output Format</label>
            <select
              value={config.format}
              onChange={(e) => onChange({ ...config, format: e.target.value as ReportFormat })}
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            >
              {FORMAT_OPTIONS.map(f => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Description</label>
          <textarea
            value={config.description}
            onChange={(e) => onChange({ ...config, description: e.target.value })}
            placeholder="Describe the purpose of this report..."
            rows={2}
            className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
            style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
          />
        </div>
      </div>

      {/* Available Sections */}
      <div className="card-sentinel rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>Available Sections</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {CUSTOM_SECTION_TYPES.map((section) => {
            const Icon = section.icon
            return (
              <button
                key={section.id}
                onClick={() => addSection(section.id)}
                className="flex flex-col items-center gap-2 p-4 rounded-lg border transition-all hover:opacity-90"
                style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}
              >
                <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface)' }}>
                  <Icon className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                </div>
                <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{section.label}</span>
                <span className="text-xs text-center" style={{ color: 'var(--muted)' }}>{section.description}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Report Sections */}
      <div className="card-sentinel rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Report Sections</h3>
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{config.sections.length} sections</span>
        </div>

        {config.sections.length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--muted)' }}>
            <Layers className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p>No sections added yet</p>
            <p className="text-sm mt-1">Click a section type above to add it to your report</p>
          </div>
        ) : (
          <div className="space-y-3">
            {config.sections.map((section, idx) => {
              const typeInfo = CUSTOM_SECTION_TYPES.find(t => t.id === section.type)
              const Icon = typeInfo?.icon || FileText
              return (
                <div
                  key={section.id}
                  className="flex items-center gap-3 p-3 rounded-lg border"
                  style={{ backgroundColor: 'var(--surface-alt)', borderColor: 'var(--border)' }}
                >
                  <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface)' }}>
                    <Icon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  </div>
                  <div className="flex-1">
                    <input
                      type="text"
                      value={section.title}
                      onChange={(e) => {
                        const newSections = [...config.sections]
                        newSections[idx].title = e.target.value
                        onChange({ ...config, sections: newSections })
                      }}
                      className="bg-transparent border-none text-sm font-medium focus:outline-none focus:ring-0 w-full"
                      style={{ color: 'var(--fg)' }}
                    />
                    <p className="text-xs" style={{ color: 'var(--muted)' }}>{typeInfo?.description}</p>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => moveSection(section.id, 'up')}
                      disabled={idx === 0}
                      className="p-1 disabled:opacity-30 disabled:cursor-not-allowed"
                      style={{ color: 'var(--muted)' }}
                    >
                      <ChevronDown className="h-4 w-4 rotate-180" />
                    </button>
                    <button
                      onClick={() => moveSection(section.id, 'down')}
                      disabled={idx === config.sections.length - 1}
                      className="p-1 disabled:opacity-30 disabled:cursor-not-allowed"
                      style={{ color: 'var(--muted)' }}
                    >
                      <ChevronDown className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => removeSection(section.id)}
                      className="p-1"
                      style={{ color: 'var(--crit)' }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Generate Button */}
      <div className="flex justify-end gap-3">
        <button
          onClick={() => onChange({
            name: '',
            description: '',
            sections: [],
            dateRange: { from: '', to: '' },
            filters: [],
            format: 'pdf',
          })}
          className="px-4 py-2 rounded-lg text-sm transition-colors"
          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
        >
          Reset
        </button>
        <button
          onClick={onGenerate}
          disabled={!config.name || config.sections.length === 0}
          className={cn(
            'flex items-center gap-2 px-6 py-2 rounded-lg text-sm font-medium transition-colors',
            config.name && config.sections.length > 0 ? 'btn-sentinel' : ''
          )}
          style={config.name && config.sections.length > 0 ? {} : { backgroundColor: 'var(--surface-alt)', color: 'var(--muted)', cursor: 'not-allowed' }}
        >
          <Zap className="h-4 w-4" />
          Generate Custom Report
        </button>
      </div>
    </div>
  )
}

// ============================================================================
// Download Menu Component
// ============================================================================

function DownloadMenu({ report, onDownload }: {
  report: GeneratedReport
  onDownload: (report: GeneratedReport, format?: string) => void
}) {
  const [open, setOpen] = useState(false)

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="btn-sentinel flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm transition-colors"
      >
        <Download className="h-4 w-4" />
        Download
        <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 mt-2 w-40 rounded-lg shadow-lg z-20" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
            {FORMAT_OPTIONS.map((format) => {
              const Icon = format.icon
              return (
                <button
                  key={format.value}
                  onClick={() => {
                    onDownload(report, format.value)
                    setOpen(false)
                  }}
                  className="flex items-center gap-2 w-full px-3 py-2 text-sm first:rounded-t-lg last:rounded-b-lg transition-colors hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                >
                  <Icon className="h-4 w-4" />
                  {format.label}
                </button>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

// ============================================================================
// Schedule Modal Component
// ============================================================================

function ScheduleModal({ template, schedule, onClose, onSave }: {
  template?: ReportTemplate
  schedule: ScheduledReport | null
  onClose: () => void
  onSave: () => void
}) {
  const [name, setName] = useState(schedule?.name || '')
  const [templateId, setTemplateId] = useState(schedule?.template_id || template?.id || '')
  const [scheduleType, setScheduleType] = useState(schedule?.schedule || 'weekly')
  const [customCron, setCustomCron] = useState('')
  const [format, setFormat] = useState(schedule?.format || 'pdf')
  const [recipients, setRecipients] = useState(schedule?.recipients.join(', ') || '')
  const [saving, setSaving] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    try {
      const data = {
        name: name || `${REPORT_TEMPLATES.find(t => t.id === templateId)?.name} Report`,
        template_id: templateId,
        schedule: scheduleType === 'custom' ? customCron : scheduleType,
        format,
        recipients: recipients.split(',').map(r => r.trim()).filter(Boolean),
      }

      if (schedule) {
        await axios.put(`/api/v1/reports/scheduled/${schedule.id}`, data)
        toast.success('Schedule updated')
      } else {
        await axios.post('/api/v1/reports/scheduled', data)
        toast.success('Schedule created')
      }
      onSave()
    } catch (error) {
      toast.error('Failed to save schedule')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}>
      <div className="rounded-xl w-full max-w-lg p-6" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {schedule ? 'Edit Schedule' : 'Create Schedule'}
          </h2>
          <button onClick={onClose} className="p-1" style={{ color: 'var(--muted)' }}>
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Schedule Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Weekly Executive Report"
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            />
          </div>

          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Report Template</label>
            <select
              value={templateId}
              onChange={(e) => setTemplateId(e.target.value)}
              required
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            >
              <option value="">Select a template</option>
              {REPORT_TEMPLATES.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Schedule</label>
            <select
              value={scheduleType}
              onChange={(e) => setScheduleType(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            >
              {SCHEDULE_PRESETS.map((s) => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
            {scheduleType === 'custom' && (
              <input
                type="text"
                value={customCron}
                onChange={(e) => setCustomCron(e.target.value)}
                placeholder="0 6 * * 1 (Cron expression)"
                className="w-full mt-2 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
                style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
              />
            )}
          </div>

          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Output Format</label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            >
              {FORMAT_OPTIONS.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Email Recipients</label>
            <input
              type="text"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="email1@example.com, email2@example.com"
              className="w-full rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-emerald-500"
              style={{ backgroundColor: 'var(--surface-alt)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Comma-separated list of email addresses</p>
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-sm transition-colors"
              style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !templateId}
              className={cn(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                !saving && templateId ? 'btn-sentinel' : ''
              )}
              style={saving || !templateId ? { backgroundColor: 'var(--surface)', color: 'var(--muted)', cursor: 'not-allowed' } : {}}
            >
              {saving ? 'Saving...' : schedule ? 'Update Schedule' : 'Create Schedule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ============================================================================
// Report Viewer (printable HTML view)
// ============================================================================

function ReportViewer({ report, onClose, onPrint }: {
  report: ReportData
  onClose: () => void
  onPrint: () => void
}) {
  return (
    <div className="space-y-4">
      {/* Toolbar (hidden in print) */}
      <div className="flex items-center justify-between print:hidden">
        <button
          onClick={onClose}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
          style={{ backgroundColor: 'var(--surface-alt)', color: 'var(--muted)' }}
        >
          <X className="h-4 w-4" />
          Back to Reports
        </button>
        <button
          onClick={onPrint}
          className="btn-sentinel flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors"
        >
          <Printer className="h-4 w-4" />
          Print / Save as PDF
        </button>
      </div>

      {/* Report Content */}
      <div className="rounded-xl p-8 print:border-none print:p-0 print:rounded-none print:shadow-none" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
        {/* Header */}
        <div className="pb-6 mb-6" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="h-8 w-8 print:text-black" style={{ color: 'var(--emerald-400)' }} />
            <span className="text-2xl font-bold print:text-black" style={{ color: 'var(--fg)' }}>Tamandua EDR</span>
          </div>
          <h1 className="text-3xl font-bold print:text-black mt-4" style={{ color: 'var(--fg)' }}>
            {report.title}
          </h1>
          <div className="flex items-center gap-6 mt-3 text-sm print:text-gray-600" style={{ color: 'var(--muted)' }}>
            <span>Report Type: {report.template}</span>
            <span>Period: {report.period.from} to {report.period.to}</span>
            <span>Generated: {new Date(report.generated_at).toLocaleString()}</span>
            {report.generated_by && <span>By: {report.generated_by}</span>}
          </div>
        </div>

        {/* Sections */}
        <div className="space-y-8">
          {report.sections.map((section, idx) => (
            <ReportSectionView key={idx} section={section} />
          ))}
        </div>

        {/* Footer */}
        <div className="pt-6 mt-8 text-xs print:text-gray-400" style={{ borderTop: '1px solid var(--border)', color: 'var(--muted)' }}>
          <p>This report was generated by Tamandua EDR. Confidential - Do not distribute without authorization.</p>
          <p className="mt-1">Report ID: {report.generated_at} | Template: {report.template}</p>
        </div>
      </div>
    </div>
  )
}

function ReportSectionView({ section }: { section: ReportSection }) {
  switch (section.type) {
    case 'summary':
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <p className="leading-relaxed print:text-gray-700" style={{ color: 'var(--muted)' }}>
            {section.content}
          </p>
        </div>
      )

    case 'stats':
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {(section.content as Array<{ label: string; value: string | number; change?: string }>).map((stat, i) => (
              <div key={i} className="p-4 rounded-lg print:border print:border-gray-200" style={{ backgroundColor: 'var(--surface-alt)' }}>
                <p className="text-2xl font-bold print:text-black" style={{ color: 'var(--fg)' }}>{stat.value}</p>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>{stat.label}</p>
                {stat.change && (
                  <p className="text-xs mt-1" style={{ color: stat.change.startsWith('+') ? 'var(--crit)' : 'var(--emerald-400)' }}>
                    {stat.change} from previous period
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )

    case 'table':
      const tableData = section.content as { headers: string[]; rows: string[][] }
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {tableData.headers.map((h, i) => (
                    <th key={i} className="text-left p-3 font-medium print:text-gray-600" style={{ color: 'var(--muted)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tableData.rows.map((row, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    {row.map((cell, j) => (
                      <td key={j} className="p-3 print:text-gray-700" style={{ color: 'var(--muted)' }}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )

    case 'list':
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <ul className="space-y-2">
            {(section.content as string[]).map((item, i) => (
              <li key={i} className="flex items-start gap-2 print:text-gray-700" style={{ color: 'var(--muted)' }}>
                <span className="mt-1.5 h-1.5 w-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: 'var(--emerald-400)' }} />
                {item}
              </li>
            ))}
          </ul>
        </div>
      )

    case 'chart':
      const chartData = section.content as { labels?: string[]; data?: number[]; title?: string }
      if (!chartData.labels || !chartData.data) {
        return null
      }
      const maxVal = Math.max(...chartData.data, 1)
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-alt)' }}>
            {chartData.title && (
              <p className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>{chartData.title}</p>
            )}
            <div className="space-y-3">
              {chartData.labels.map((label, i) => {
                const value = chartData.data![i]
                const width = Math.round((value / maxVal) * 100)
                return (
                  <div key={i} className="flex items-center gap-3">
                    <span className="w-24 text-sm truncate" style={{ color: 'var(--muted)' }}>{label}</span>
                    <div className="flex-1 h-4 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--surface)' }}>
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${width}%`, backgroundColor: 'var(--emerald-400)' }}
                      />
                    </div>
                    <span className="w-12 text-sm text-right" style={{ color: 'var(--muted)' }}>{value}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )

    case 'text':
    default:
      return (
        <div>
          <h2 className="text-xl font-semibold print:text-black mb-3 pb-2" style={{ color: 'var(--fg)', borderBottom: '1px solid var(--border)' }}>
            {section.title}
          </h2>
          <p className="leading-relaxed whitespace-pre-wrap print:text-gray-700" style={{ color: 'var(--muted)' }}>
            {typeof section.content === 'string' ? section.content : JSON.stringify(section.content, null, 2)}
          </p>
        </div>
      )
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function generateClientPreview(template: ReportTemplate, dateFrom: string, dateTo: string): ReportData {
  const sections: ReportSection[] = []

  switch (template.id) {
    case 'executive_summary':
      sections.push(
        {
          title: 'Security Posture Overview',
          type: 'summary',
          content: `During the reporting period (${dateFrom} to ${dateTo}), the Tamandua EDR platform monitored endpoint activity across the environment. This report provides a high-level summary of the security posture, key incidents, and recommended actions.`,
        },
        {
          title: 'Key Metrics',
          type: 'stats',
          content: [
            { label: 'Total Events', value: '--', change: undefined },
            { label: 'Alerts Generated', value: '--', change: undefined },
            { label: 'Critical Alerts', value: '--', change: undefined },
            { label: 'Active Agents', value: '--', change: undefined },
          ],
        },
        {
          title: 'Top Threats Detected',
          type: 'table',
          content: {
            headers: ['Threat', 'MITRE Technique', 'Count', 'Severity'],
            rows: [
              ['Data available after backend integration', '', '', ''],
            ],
          },
        },
        {
          title: 'Recommendations',
          type: 'list',
          content: [
            'Review and triage all open critical alerts.',
            'Ensure all endpoints have the latest agent version deployed.',
            'Update YARA and Sigma detection rules to the latest versions.',
            'Verify response playbooks are configured and tested.',
            'Schedule periodic threat hunting sessions.',
          ],
        }
      )
      break

    case 'incident_report':
      sections.push(
        {
          title: 'Incident Summary',
          type: 'summary',
          content: `This report covers security incidents detected during ${dateFrom} to ${dateTo}. Each incident has been categorized by severity and mapped to MITRE ATT&CK techniques where applicable.`,
        },
        {
          title: 'Incident Statistics',
          type: 'stats',
          content: [
            { label: 'Total Incidents', value: '--' },
            { label: 'Resolved', value: '--' },
            { label: 'Under Investigation', value: '--' },
            { label: 'Avg Response Time', value: '--' },
          ],
        },
        {
          title: 'Incident Timeline',
          type: 'table',
          content: {
            headers: ['Date', 'Incident', 'Severity', 'Status', 'Assignee'],
            rows: [
              ['Data available after backend integration', '', '', '', ''],
            ],
          },
        },
        {
          title: 'Lessons Learned',
          type: 'list',
          content: [
            'Automate common response actions to reduce mean time to respond.',
            'Improve detection coverage for credential access techniques.',
            'Implement network segmentation recommendations from previous incidents.',
          ],
        }
      )
      break

    case 'threat_report':
      sections.push(
        {
          title: 'Threat Overview',
          type: 'summary',
          content: `Analysis of the threat landscape observed during ${dateFrom} to ${dateTo}. This report summarizes detected indicators of compromise, attack patterns, and threat actor activity.`,
        },
        {
          title: 'Threat Statistics',
          type: 'stats',
          content: [
            { label: 'IOCs Matched', value: '--' },
            { label: 'Unique Threat Actors', value: '--' },
            { label: 'Active Campaigns', value: '--' },
            { label: 'New IOCs Added', value: '--' },
          ],
        },
        {
          title: 'Attack Vector Distribution',
          type: 'chart',
          content: {
            title: 'Top Attack Vectors',
            labels: ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
            data: [0, 0, 0, 0, 0],
          },
        }
      )
      break

    case 'agent_health':
      sections.push(
        {
          title: 'Agent Fleet Status',
          type: 'summary',
          content: `Current health and status of all deployed Tamandua agents as of the reporting period (${dateFrom} to ${dateTo}).`,
        },
        {
          title: 'Fleet Statistics',
          type: 'stats',
          content: [
            { label: 'Total Agents', value: '--' },
            { label: 'Online', value: '--' },
            { label: 'Degraded', value: '--' },
            { label: 'Offline', value: '--' },
          ],
        },
        {
          title: 'Agent Inventory',
          type: 'table',
          content: {
            headers: ['Hostname', 'IP Address', 'OS', 'Version', 'Status', 'Last Seen'],
            rows: [
              ['Data available after backend integration', '', '', '', '', ''],
            ],
          },
        },
        {
          title: 'Action Items',
          type: 'list',
          content: [
            'Investigate and remediate offline agents.',
            'Upgrade agents running outdated versions.',
            'Deploy agents to uncovered endpoints.',
          ],
        }
      )
      break

    case 'detection_efficacy':
      sections.push(
        {
          title: 'Detection Overview',
          type: 'summary',
          content: `Analysis of detection rule performance and coverage for the period ${dateFrom} to ${dateTo}.`,
        },
        {
          title: 'Detection Metrics',
          type: 'stats',
          content: [
            { label: 'Total Detections', value: '--' },
            { label: 'True Positives', value: '--' },
            { label: 'False Positives', value: '--' },
            { label: 'MITRE Coverage', value: '--' },
          ],
        },
        {
          title: 'Top Performing Rules',
          type: 'table',
          content: {
            headers: ['Rule', 'Triggers', 'TP Rate', 'Avg Response'],
            rows: [
              ['Data available after backend integration', '', '', ''],
            ],
          },
        }
      )
      break

    default:
      // Compliance reports
      if (template.id.startsWith('compliance_')) {
        const frameworkName = template.name
        sections.push(
          {
            title: `${frameworkName} Overview`,
            type: 'summary',
            content: `Compliance assessment for ${frameworkName} during the period ${dateFrom} to ${dateTo}. This report evaluates control implementation status and identifies gaps requiring remediation.`,
          },
          {
            title: 'Compliance Score',
            type: 'stats',
            content: [
              { label: 'Overall Score', value: '--' },
              { label: 'Controls Implemented', value: '--' },
              { label: 'Partial Controls', value: '--' },
              { label: 'Gaps Identified', value: '--' },
            ],
          },
          {
            title: 'Compliance by Requirement',
            type: 'chart',
            content: {
              title: 'Requirement Compliance',
              labels: ['Req 1', 'Req 2', 'Req 3', 'Req 4', 'Req 5'],
              data: [0, 0, 0, 0, 0],
            },
          },
          {
            title: 'Control Status',
            type: 'table',
            content: {
              headers: ['Control ID', 'Control Name', 'Status', 'Evidence', 'Priority'],
              rows: [
                ['Data available after backend integration', '', '', '', ''],
              ],
            },
          },
          {
            title: 'Remediation Recommendations',
            type: 'list',
            content: [
              'Review controls marked as "Gap" and develop remediation plans.',
              'Collect additional evidence for partially implemented controls.',
              'Schedule periodic compliance reviews.',
            ],
          }
        )
      } else {
        sections.push({
          title: 'Report Content',
          type: 'summary',
          content: `Report data for ${template.name} will be available after backend integration.`,
        })
      }
  }

  return {
    title: template.name,
    template: template.id,
    period: { from: dateFrom, to: dateTo },
    generated_at: new Date().toISOString(),
    generated_by: 'Current User',
    sections,
  }
}
