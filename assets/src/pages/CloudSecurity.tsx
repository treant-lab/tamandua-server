import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Cloud,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Server,
  Lock,
  Unlock,
  RefreshCw,
  Plus,
  Settings,
  Eye,
  Play,
  Search,
  Filter,
  ChevronRight,
  Clock,
  Target,
  FileText,
  BarChart3,
  PieChart,
  Activity,
  ExternalLink,
  Trash2,
  Edit,
  Key,
  Users,
  Box,
  Layers,
  GitBranch,
  Network,
  Container,
  Cpu,
  HardDrive,
  Gauge,
  Zap,
  Bug,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  FileCode,
  Globe,
  Database,
  Boxes,
  ChevronDown,
  Download,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  AlertCircle,
  Info,
  DollarSign,
  TrendingDown,
  Map,
  LayoutGrid,
  Wrench,
  Copy,
  Check,
  X,
  Maximize2,
  MinusCircle,
  CircleDot,
  Link2,
  Unlink,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useEffect, useCallback } from 'react'

// Types
interface CloudAccount {
  id: string
  name: string
  provider: 'aws' | 'azure' | 'gcp'
  account_id: string
  alias?: string
  status: 'active' | 'inactive' | 'error'
  connection_status: 'connected' | 'disconnected' | 'error' | 'pending'
  compliance_score: number
  findings_count: number
  critical_findings_count: number
  resources_count: number
  last_scan_at?: string
  monthly_cost?: number
  security_score?: number
  identity_risk_score?: number
  runtime_events?: number
}

interface CloudFinding {
  id: string
  provider: 'aws' | 'azure' | 'gcp'
  account_id: string
  resource_id: string
  resource_name: string
  resource_type: string
  region?: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  title: string
  description: string
  recommendation?: string
  compliance: string[]
  status: 'open' | 'acknowledged' | 'resolved' | 'exception' | 'false_positive'
  first_seen_at: string
  last_seen_at: string
  remediation_terraform?: string
  remediation_cloudformation?: string
  remediation_arm?: string
}

interface CloudAsset {
  id: string
  provider: 'aws' | 'azure' | 'gcp'
  account_id: string
  type: string
  name: string
  region: string
  status: string
  created_at: string
  tags: Record<string, string>
  security_status: 'secure' | 'at_risk' | 'critical' | 'unknown'
  vulnerability_count: number
  compliance_status: 'compliant' | 'non_compliant' | 'partial'
}

interface CloudPolicy {
  id: string
  name: string
  description: string
  provider: string
  resource_type: string
  severity: string
  category: string
  enabled: boolean
  compliance: string[]
  source: 'builtin' | 'custom'
}

interface IdentityRisk {
  id: string
  provider: string
  name: string
  type: 'user' | 'role' | 'service_account'
  risk_score: number
  risk_factors: string[]
  permissions_count: number
  has_admin_access: boolean
  last_activity?: string
  escalation_paths: number
}

interface RuntimeEvent {
  id: string
  workload_id: string
  workload_name: string
  event_type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  description: string
  mitre_technique?: string
}

interface VulnerabilitySummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  by_package: { package: string; count: number }[]
}

interface ComplianceFramework {
  name: string
  scores: {
    aws: number
    azure: number
    gcp: number
  }
  passing_checks: number
  total_checks: number
  last_assessed: string
}

interface DashboardStats {
  total_accounts: number
  connected_accounts: number
  total_resources: number
  total_findings: number
  open_findings: number
  critical_findings: number
  high_findings: number
  average_compliance_score: number
  total_identities?: number
  high_risk_identities?: number
  monitored_workloads?: number
  runtime_threats?: number
  vulnerabilities?: VulnerabilitySummary
  cost_optimization_potential?: number
}

// Resource relationship for topology graph
interface ResourceRelationship {
  source_id: string
  source_type: string
  target_id: string
  target_type: string
  relationship_type: 'uses' | 'connects_to' | 'attached_to' | 'belongs_to' | 'exposes'
}

// Cloud topology node
interface TopologyNode {
  id: string
  name: string
  type: string
  provider: 'aws' | 'azure' | 'gcp'
  region: string
  security_status: 'secure' | 'at_risk' | 'critical' | 'unknown'
  findings_count: number
  public_exposure: boolean
  tags: Record<string, string>
}

// Risk heat map data
interface RiskHeatMapData {
  provider: string
  region: string
  resource_type: string
  risk_score: number
  findings_count: number
  critical_count: number
  high_count: number
}

// Remediation action
interface RemediationAction {
  id: string
  finding_id: string
  type: 'auto' | 'manual' | 'iac'
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  terraform_code?: string
  cloudformation_code?: string
  arm_code?: string
  cli_command?: string
  estimated_risk_reduction: number
  requires_approval: boolean
}

// Security group analysis
interface SecurityGroupAnalysis {
  id: string
  name: string
  provider: 'aws' | 'azure' | 'gcp'
  vpc_id?: string
  inbound_rules: SecurityRule[]
  outbound_rules: SecurityRule[]
  attached_resources: number
  risk_level: 'critical' | 'high' | 'medium' | 'low'
  issues: string[]
}

interface SecurityRule {
  protocol: string
  port_range: string
  source: string
  description?: string
  is_risky: boolean
  risk_reason?: string
}

interface CloudSecurityPageProps {
  accounts?: CloudAccount[]
  findings?: CloudFinding[]
  policies?: CloudPolicy[]
  stats?: DashboardStats
  assets?: CloudAsset[]
  identities?: IdentityRisk[]
  runtimeEvents?: RuntimeEvent[]
  complianceFrameworks?: ComplianceFramework[]
  topologyNodes?: TopologyNode[]
  relationships?: ResourceRelationship[]
  riskHeatMap?: RiskHeatMapData[]
  securityGroups?: SecurityGroupAnalysis[]
}

export default function CloudSecurity({
  accounts: initialAccounts = [],
  findings: initialFindings = [],
  policies: initialPolicies = [],
  stats: initialStats,
  assets: initialAssets = [],
  identities: initialIdentities = [],
  runtimeEvents: initialRuntimeEvents = [],
  complianceFrameworks: initialFrameworks = [],
  topologyNodes: initialTopologyNodes = [],
  relationships: initialRelationships = [],
  riskHeatMap: initialRiskHeatMap = [],
  securityGroups: initialSecurityGroups = [],
}: CloudSecurityPageProps) {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'accounts' | 'assets' | 'findings' | 'identity' | 'runtime' | 'compliance' | 'iac' | 'policies' | 'topology' | 'remediation' | 'security-groups'
  >('overview')
  const [accounts, setAccounts] = useState<CloudAccount[]>(initialAccounts)
  const [findings, setFindings] = useState<CloudFinding[]>(initialFindings)
  const [policies, setPolicies] = useState<CloudPolicy[]>(initialPolicies)
  const [assets, setAssets] = useState<CloudAsset[]>(initialAssets)
  const [identities, setIdentities] = useState<IdentityRisk[]>(initialIdentities)
  const [runtimeEvents, setRuntimeEvents] = useState<RuntimeEvent[]>(initialRuntimeEvents)
  const [_complianceFrameworks, setComplianceFrameworks] = useState<ComplianceFramework[]>(initialFrameworks)
  const [topologyNodes, setTopologyNodes] = useState<TopologyNode[]>(initialTopologyNodes)
  const [_relationships, setRelationships] = useState<ResourceRelationship[]>(initialRelationships)
  const [riskHeatMap, setRiskHeatMap] = useState<RiskHeatMapData[]>(initialRiskHeatMap)
  const [securityGroups, setSecurityGroups] = useState<SecurityGroupAnalysis[]>(initialSecurityGroups)
  const [stats, setStats] = useState<DashboardStats>(
    initialStats || {
      total_accounts: 0,
      connected_accounts: 0,
      total_resources: 0,
      total_findings: 0,
      open_findings: 0,
      critical_findings: 0,
      high_findings: 0,
      average_compliance_score: 100,
      total_identities: 0,
      high_risk_identities: 0,
      monitored_workloads: 0,
      runtime_threats: 0,
    }
  )
  const [isLoading, setIsLoading] = useState(false)
  const [providerFilter, setProviderFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('open')
  const [searchQuery, setSearchQuery] = useState('')
  const [showAddAccountModal, setShowAddAccountModal] = useState(false)
  const [selectedAssetType, setSelectedAssetType] = useState<string>('all')
  const [iacContent, setIacContent] = useState('')
  const [iacScanResults, setIacScanResults] = useState<any>(null)
  const [selectedFinding, setSelectedFinding] = useState<CloudFinding | null>(null)
  const [showRemediationModal, setShowRemediationModal] = useState(false)
  const [copiedCode, setCopiedCode] = useState<string | null>(null)
  const [remediationInProgress, setRemediationInProgress] = useState<Set<string>>(new Set())
  const [topologyViewMode, setTopologyViewMode] = useState<'graph' | 'heatmap' | 'regions'>('graph')

  // Fetch dashboard data
  useEffect(() => {
    fetchDashboard()
  }, [])

  const fetchDashboard = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/cspm/dashboard', {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setStats(data.data.summary || data.data)
        setAccounts(data.data.accounts || [])
        if (data.data.compliance_frameworks) {
          setComplianceFrameworks(data.data.compliance_frameworks)
        }
      }
    } catch (error) {
      logger.error('Failed to fetch dashboard:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchFindings = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)
      if (severityFilter !== 'all') params.set('severity', severityFilter)
      if (statusFilter !== 'all') params.set('status', statusFilter)
      if (searchQuery) params.set('search', searchQuery)

      const response = await fetch(`/api/v1/cspm/findings?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setFindings(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch findings:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchAssets = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)
      if (selectedAssetType !== 'all') params.set('type', selectedAssetType)
      if (searchQuery) params.set('search', searchQuery)

      const response = await fetch(`/api/v1/cspm/assets?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setAssets(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch assets:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchIdentities = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)

      const response = await fetch(`/api/v1/cspm/identities?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setIdentities(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch identities:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchRuntimeEvents = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/cspm/runtime/events', {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setRuntimeEvents(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch runtime events:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchPolicies = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)

      const response = await fetch(`/api/v1/cspm/policies?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setPolicies(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch policies:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const scanIaC = async () => {
    if (!iacContent.trim()) return

    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/cspm/iac/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ content: iacContent }),
      })
      if (response.ok) {
        const data = await response.json()
        setIacScanResults(data.data)
      }
    } catch (error) {
      logger.error('Failed to scan IaC:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchTopology = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)

      const response = await fetch(`/api/v1/cspm/topology?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setTopologyNodes(data.data.nodes || [])
        setRelationships(data.data.relationships || [])
      }
    } catch (error) {
      logger.error('Failed to fetch topology:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchRiskHeatMap = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/cspm/risk-heatmap', {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setRiskHeatMap(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch risk heatmap:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchSecurityGroups = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams()
      if (providerFilter !== 'all') params.set('provider', providerFilter)

      const response = await fetch(`/api/v1/cspm/security-groups?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setSecurityGroups(data.data || [])
      }
    } catch (error) {
      logger.error('Failed to fetch security groups:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const applyRemediation = async (findingId: string, remediationType: 'auto' | 'manual') => {
    setRemediationInProgress(prev => new Set(prev).add(findingId))
    try {
      const response = await fetch(`/api/v1/cspm/findings/${findingId}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ type: remediationType }),
      })
      if (response.ok) {
        // Refresh findings
        fetchFindings()
      }
    } catch (error) {
      logger.error('Failed to apply remediation:', error)
    } finally {
      setRemediationInProgress(prev => {
        const next = new Set(prev)
        next.delete(findingId)
        return next
      })
    }
  }

  const copyToClipboard = async (code: string, id: string) => {
    try {
      await navigator.clipboard.writeText(code)
      setCopiedCode(id)
      setTimeout(() => setCopiedCode(null), 2000)
    } catch (error) {
      logger.error('Failed to copy:', error)
    }
  }

  const exportFindings = async (format: 'csv' | 'json') => {
    try {
      const params = new URLSearchParams()
      params.set('format', format)
      if (providerFilter !== 'all') params.set('provider', providerFilter)
      if (severityFilter !== 'all') params.set('severity', severityFilter)
      if (statusFilter !== 'all') params.set('status', statusFilter)

      const response = await fetch(`/api/v1/cspm/findings/export?${params}`, {
        credentials: 'include',
      })
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `cloud-findings-${new Date().toISOString().split('T')[0]}.${format}`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        a.remove()
      }
    } catch (error) {
      logger.error('Failed to export findings:', error)
    }
  }

  // Topology, heat map, and security groups are loaded via real API data only.

  // Load data when tab changes
  useEffect(() => {
    if (activeTab === 'findings' || activeTab === 'remediation') {
      fetchFindings()
    } else if (activeTab === 'policies') {
      fetchPolicies()
    } else if (activeTab === 'assets') {
      fetchAssets()
    } else if (activeTab === 'identity') {
      fetchIdentities()
    } else if (activeTab === 'runtime') {
      fetchRuntimeEvents()
    } else if (activeTab === 'topology') {
      fetchTopology()
    } else if (activeTab === 'security-groups') {
      fetchSecurityGroups()
    }
  }, [activeTab, providerFilter, severityFilter, statusFilter, selectedAssetType])

  const getProviderIcon = (provider: string) => {
    const colors = {
      aws: 'text-orange-400',
      azure: 'text-blue-400',
      gcp: 'text-red-400',
    }
    return (
      <span className={cn('font-bold text-xs', colors[provider as keyof typeof colors] || 'text-slate-400')}>
        {provider.toUpperCase()}
      </span>
    )
  }

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case 'aws':
        return 'border-orange-500 bg-orange-500/10'
      case 'azure':
        return 'border-blue-500 bg-blue-500/10'
      case 'gcp':
        return 'border-red-500 bg-red-500/10'
      default:
        return 'border-slate-500 bg-slate-500/10'
    }
  }

  const getSeverityColor = (severity: string) => {
    // Returns inline styles for severity colors using design tokens
    switch (severity) {
      case 'critical':
        return { color: 'var(--crit)', backgroundColor: 'var(--crit-bg)' }
      case 'high':
        return { color: 'var(--high)', backgroundColor: 'var(--high-bg)' }
      case 'medium':
        return { color: 'var(--med)', backgroundColor: 'var(--med-bg)' }
      case 'low':
        return { color: 'var(--low)', backgroundColor: 'var(--low-bg)' }
      default:
        return { color: 'var(--muted)', backgroundColor: 'var(--surface-2)' }
    }
  }

  const getSeverityColorClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-500/20'
      case 'high':
        return 'text-orange-400 bg-orange-500/20'
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/20'
      case 'low':
        return 'text-blue-400 bg-blue-500/20'
      default:
        return 'text-slate-400 bg-slate-500/20'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return { color: 'var(--crit)', backgroundColor: 'var(--crit-bg)' }
      case 'acknowledged':
        return { color: 'var(--high)', backgroundColor: 'var(--high-bg)' }
      case 'resolved':
        return { color: 'var(--emerald-400)', backgroundColor: 'var(--emerald-glow)' }
      case 'exception':
        return { color: 'var(--sol-magenta)', backgroundColor: 'rgba(217, 70, 239, 0.12)' }
      case 'false_positive':
        return { color: 'var(--muted)', backgroundColor: 'var(--surface-2)' }
      default:
        return { color: 'var(--muted)', backgroundColor: 'var(--surface-2)' }
    }
  }

  const getStatusColorClass = (status: string) => {
    switch (status) {
      case 'open':
        return 'text-red-400 bg-red-500/20'
      case 'acknowledged':
        return 'text-yellow-400 bg-yellow-500/20'
      case 'resolved':
        return 'text-green-400 bg-green-500/20'
      case 'exception':
        return 'text-purple-400 bg-purple-500/20'
      case 'false_positive':
        return 'text-slate-400 bg-slate-500/20'
      default:
        return 'text-slate-400 bg-slate-500/20'
    }
  }

  const getComplianceScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400'
    if (score >= 70) return 'text-yellow-400'
    if (score >= 50) return 'text-orange-400'
    return 'text-red-400'
  }

  const getComplianceScoreStyle = (score: number) => {
    if (score >= 90) return { color: 'var(--emerald-400)' }
    if (score >= 70) return { color: 'var(--high)' }
    if (score >= 50) return { color: 'var(--high)' }
    return { color: 'var(--crit)' }
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/20'
    if (score >= 60) return 'text-orange-400 bg-orange-500/20'
    if (score >= 40) return 'text-yellow-400 bg-yellow-500/20'
    return 'text-green-400 bg-green-500/20'
  }

  const getRiskScoreStyle = (score: number) => {
    if (score >= 80) return { color: 'var(--crit)', backgroundColor: 'var(--crit-bg)' }
    if (score >= 60) return { color: 'var(--high)', backgroundColor: 'var(--high-bg)' }
    if (score >= 40) return { color: 'var(--med)', backgroundColor: 'var(--med-bg)' }
    return { color: 'var(--emerald-400)', backgroundColor: 'var(--emerald-glow)' }
  }

  const getHeatMapColor = (score: number) => {
    if (score >= 80) return 'bg-red-500'
    if (score >= 60) return 'bg-orange-500'
    if (score >= 40) return 'bg-yellow-500'
    if (score >= 20) return 'bg-blue-500'
    return 'bg-green-500'
  }

  const getHeatMapStyle = (score: number) => {
    if (score >= 80) return { backgroundColor: 'var(--crit)' }
    if (score >= 60) return { backgroundColor: 'var(--high)' }
    if (score >= 40) return { backgroundColor: 'var(--med)' }
    if (score >= 20) return { backgroundColor: 'var(--med)' }
    return { backgroundColor: 'var(--emerald-500)' }
  }

  const getResourceIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ec2':
      case 'vm':
      case 'compute':
        return Cpu
      case 's3':
      case 'blob':
      case 'storage':
        return HardDrive
      case 'rds':
      case 'sql':
      case 'database':
        return Database
      case 'vpc':
      case 'vnet':
      case 'network':
        return Network
      case 'lambda':
      case 'function':
        return Zap
      case 'iam':
      case 'role':
        return Key
      case 'container':
      case 'ecs':
      case 'kubernetes':
        return Container
      default:
        return Box
    }
  }

  const getSecurityStatusColor = (status: string) => {
    switch (status) {
      case 'secure':
        return 'text-green-400 border-green-500'
      case 'at_risk':
        return 'text-yellow-400 border-yellow-500'
      case 'critical':
        return 'text-red-400 border-red-500'
      default:
        return 'text-slate-400 border-slate-500'
    }
  }

  const getSecurityStatusStyle = (status: string) => {
    switch (status) {
      case 'secure':
        return { color: 'var(--emerald-400)', borderColor: 'var(--emerald-500)' }
      case 'at_risk':
        return { color: 'var(--high)', borderColor: 'var(--high)' }
      case 'critical':
        return { color: 'var(--crit)', borderColor: 'var(--crit)' }
      default:
        return { color: 'var(--muted)', borderColor: 'var(--border)' }
    }
  }

  const startScan = async (accountId: string) => {
    try {
      const response = await fetch(`/api/v1/cspm/accounts/${accountId}/scan`, {
        method: 'POST',
        credentials: 'include',
      })
      if (response.ok) {
        fetchDashboard()
      }
    } catch (error) {
      logger.error('Failed to start scan:', error)
    }
  }

  const assetTypes = [
    { value: 'all', label: 'All Types' },
    { value: 'compute', label: 'Compute (EC2, VMs)' },
    { value: 'storage', label: 'Storage (S3, Blob)' },
    { value: 'database', label: 'Databases (RDS, SQL)' },
    { value: 'network', label: 'Networking' },
    { value: 'container', label: 'Containers' },
    { value: 'serverless', label: 'Serverless' },
    { value: 'iam', label: 'IAM Resources' },
  ]

  return (
    <MainLayout title="Cloud Security">
      <Head title="Cloud Security - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3" style={{ color: 'var(--fg)' }}>
              <Cloud className="h-7 w-7" style={{ color: 'var(--emerald-400)' }} />
              Cloud Security Platform
            </h1>
            <p className="mt-1" style={{ color: 'var(--muted)' }}>
              Comprehensive cloud security: CSPM, CWPP, CIEM, and Runtime Protection across AWS, Azure, and GCP
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => fetchDashboard()}
              className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm transition-colors"
              style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)', border: '1px solid var(--border)' }}
            >
              <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
              Refresh
            </button>
            <button
              onClick={() => setShowAddAccountModal(true)}
              className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm text-white transition-colors"
              style={{ backgroundColor: 'var(--emerald-600)' }}
            >
              <Plus className="h-4 w-4" />
              Add Account
            </button>
          </div>
        </div>

        {/* Multi-Cloud Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Cloud Accounts</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>
                  {stats.connected_accounts}/{stats.total_accounts}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-orange-400">AWS</span>
                  <span className="text-xs text-blue-400">Azure</span>
                  <span className="text-xs text-red-400">GCP</span>
                </div>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--emerald-glow)' }}>
                <Cloud className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Cloud Assets</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{(stats.total_resources ?? 0).toLocaleString()}</p>
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Monitored resources</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--med-bg)' }}>
                <Boxes className="h-6 w-6" style={{ color: 'var(--med)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Security Findings</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{(stats.open_findings ?? 0).toLocaleString()}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs" style={{ color: 'var(--crit)' }}>{stats.critical_findings} Critical</span>
                  <span className="text-xs" style={{ color: 'var(--high)' }}>{stats.high_findings} High</span>
                </div>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--crit-bg)' }}>
                <AlertTriangle className="h-6 w-6" style={{ color: 'var(--crit)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Identity Risk</p>
                <p className="text-2xl font-bold mt-1" style={{ color: 'var(--fg)' }}>{stats.high_risk_identities || 0}</p>
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>of {stats.total_identities || 0} identities</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--high-bg)' }}>
                <UserCheck className="h-6 w-6" style={{ color: 'var(--high)' }} />
              </div>
            </div>
          </div>

          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>Compliance Score</p>
                <p className={cn('text-2xl font-bold mt-1', getComplianceScoreColor(stats.average_compliance_score))}>
                  {stats.average_compliance_score.toFixed(1)}%
                </p>
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Across all frameworks</p>
              </div>
              <div className="h-12 w-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--emerald-glow)' }}>
                <Shield className="h-6 w-6" style={{ color: 'var(--emerald-400)' }} />
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="card-sentinel rounded-xl">
          <div className="px-4 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            <nav className="flex gap-1">
              {[
                { id: 'overview', label: 'Overview', icon: BarChart3 },
                { id: 'accounts', label: 'Accounts', icon: Cloud },
                { id: 'assets', label: 'Asset Inventory', icon: Boxes },
                { id: 'findings', label: 'Findings', icon: AlertTriangle },
                { id: 'topology', label: 'Topology & Risk', icon: Map },
                { id: 'security-groups', label: 'Security Groups', icon: Shield },
                { id: 'identity', label: 'Identity Security', icon: Key },
                { id: 'runtime', label: 'Runtime Protection', icon: Zap },
                { id: 'remediation', label: 'Remediation', icon: Wrench },
                { id: 'compliance', label: 'Compliance', icon: Shield },
                { id: 'iac', label: 'IaC Security', icon: FileCode },
                { id: 'policies', label: 'Policies', icon: FileText },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className="flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap"
                  style={{
                    borderColor: activeTab === tab.id ? 'var(--emerald-400)' : 'transparent',
                    color: activeTab === tab.id ? 'var(--emerald-400)' : 'var(--muted)',
                  }}
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-4">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Multi-Cloud Provider Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {['aws', 'azure', 'gcp'].map((provider) => {
                    const providerAccounts = accounts.filter((a) => a.provider === provider)
                    const totalFindings = providerAccounts.reduce((sum, a) => sum + a.findings_count, 0)
                    const totalResources = providerAccounts.reduce((sum, a) => sum + a.resources_count, 0)
                    const avgCompliance =
                      providerAccounts.length > 0
                        ? providerAccounts.reduce((sum, a) => sum + a.compliance_score, 0) / providerAccounts.length
                        : 100

                    return (
                      <div key={provider} className={cn('rounded-lg p-4 border-l-4', getProviderColor(provider))}>
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-3">
                            <div className="h-10 w-10 rounded-lg bg-slate-600 flex items-center justify-center">
                              {getProviderIcon(provider)}
                            </div>
                            <div>
                              <h3 className="text-white font-medium">{provider.toUpperCase()}</h3>
                              <p className="text-xs text-slate-400">
                                {providerAccounts.length} account{providerAccounts.length !== 1 ? 's' : ''}
                              </p>
                            </div>
                          </div>
                          <div className={cn('text-lg font-bold', getComplianceScoreColor(avgCompliance))}>
                            {avgCompliance.toFixed(0)}%
                          </div>
                        </div>
                        <div className="grid grid-cols-3 gap-3 text-center">
                          <div className="bg-slate-700/50 rounded-lg p-2">
                            <p className="text-lg font-semibold text-white">{(totalResources ?? 0).toLocaleString()}</p>
                            <p className="text-xs text-slate-400">Resources</p>
                          </div>
                          <div className="bg-slate-700/50 rounded-lg p-2">
                            <p className="text-lg font-semibold text-orange-400">{totalFindings}</p>
                            <p className="text-xs text-slate-400">Findings</p>
                          </div>
                          <div className="bg-slate-700/50 rounded-lg p-2">
                            <p className="text-lg font-semibold text-red-400">
                              {providerAccounts.reduce((sum, a) => sum + a.critical_findings_count, 0)}
                            </p>
                            <p className="text-xs text-slate-400">Critical</p>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>

                {/* Security Posture Overview */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Security Score Trend */}
                  <div className="card-sentinel-inset rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                      <Gauge className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                      Security Posture Summary
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
                        <div className="flex items-center justify-between mb-2">
                          <span style={{ color: 'var(--muted)' }}>CSPM Score</span>
                          <span className="font-bold" style={getComplianceScoreStyle(stats.average_compliance_score)}>
                            {stats.average_compliance_score.toFixed(0)}%
                          </span>
                        </div>
                        <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${stats.average_compliance_score}%`,
                              backgroundColor: stats.average_compliance_score >= 80
                                ? 'var(--emerald-500)'
                                : stats.average_compliance_score >= 60
                                ? 'var(--high)'
                                : 'var(--crit)'
                            }}
                          />
                        </div>
                      </div>
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
                        <div className="flex items-center justify-between mb-2">
                          <span style={{ color: 'var(--muted)' }}>Identity Risk</span>
                          <span className="font-bold" style={{ color: 'var(--high)' }}>
                            {stats.high_risk_identities || 0} at risk
                          </span>
                        </div>
                        <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
                          <div
                            className="h-full rounded-full"
                            style={{
                              backgroundColor: 'var(--high)',
                              width: `${
                                stats.total_identities
                                  ? ((stats.high_risk_identities || 0) / stats.total_identities) * 100
                                  : 0
                              }%`,
                            }}
                          />
                        </div>
                      </div>
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
                        <div className="flex items-center justify-between mb-2">
                          <span style={{ color: 'var(--muted)' }}>Workload Protection</span>
                          <span className="font-bold" style={{ color: 'var(--emerald-400)' }}>{stats.monitored_workloads || 0} monitored</span>
                        </div>
                        <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
                          <div className="h-full rounded-full w-full" style={{ backgroundColor: 'var(--emerald-500)' }} />
                        </div>
                      </div>
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
                        <div className="flex items-center justify-between mb-2">
                          <span style={{ color: 'var(--muted)' }}>Runtime Threats</span>
                          <span className="font-bold" style={{ color: 'var(--crit)' }}>{stats.runtime_threats || 0}</span>
                        </div>
                        <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
                          <div
                            className="h-full rounded-full"
                            style={{ backgroundColor: 'var(--crit)', width: stats.runtime_threats ? '100%' : '0%' }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Top Findings by Category */}
                  <div className="card-sentinel-inset rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                      <AlertTriangle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                      Findings by Category
                    </h3>
                    <div className="space-y-3">
                      {[
                        { category: 'Network Security', count: 45, icon: Network, tokenColor: 'var(--med)' },
                        { category: 'Identity & Access', count: 32, icon: Key, tokenColor: 'var(--sol-magenta)' },
                        { category: 'Data Protection', count: 28, icon: Lock, tokenColor: 'var(--emerald-400)' },
                        { category: 'Encryption', count: 21, icon: Shield, tokenColor: 'var(--high)' },
                        { category: 'Logging & Monitoring', count: 15, icon: Activity, tokenColor: 'var(--sol-cyan)' },
                      ].map((item) => (
                        <div key={item.category} className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <item.icon className="h-4 w-4" style={{ color: item.tokenColor }} />
                            <span style={{ color: 'var(--fg-2)' }}>{item.category}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-24 h-2 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
                              <div
                                className="h-full rounded-full"
                                style={{ backgroundColor: 'var(--high)', width: `${(item.count / 45) * 100}%` }}
                              />
                            </div>
                            <span className="text-sm w-8 text-right" style={{ color: 'var(--muted)' }}>{item.count}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Recent Critical Findings */}
                <div className="card-sentinel-inset rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                      <ShieldAlert className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                      Critical & High Severity Findings
                    </h3>
                    <button
                      onClick={() => setActiveTab('findings')}
                      className="text-sm flex items-center gap-1"
                      style={{ color: 'var(--emerald-400)' }}
                    >
                      View All <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="space-y-2">
                    {findings
                      .filter((f) => f.severity === 'critical' || f.severity === 'high')
                      .slice(0, 5)
                      .map((finding) => (
                        <div
                          key={finding.id}
                          className="flex items-center justify-between p-3 rounded-lg"
                          style={{ backgroundColor: 'var(--surface-2)' }}
                        >
                          <div className="flex items-center gap-3">
                            {finding.severity === 'critical' ? (
                              <XCircle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                            ) : (
                              <AlertCircle className="h-5 w-5" style={{ color: 'var(--high)' }} />
                            )}
                            <div>
                              <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{finding.title}</p>
                              <p className="text-xs" style={{ color: 'var(--muted)' }}>
                                {finding.resource_name} - {finding.provider.toUpperCase()}
                              </p>
                            </div>
                          </div>
                          <span className="px-2 py-1 rounded text-xs" style={getSeverityColor(finding.severity)}>
                            {finding.severity.toUpperCase()}
                          </span>
                        </div>
                      ))}
                    {findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0 && (
                      <div className="text-center py-8" style={{ color: 'var(--subtle)' }}>
                        <CheckCircle className="h-10 w-10 mx-auto mb-2 opacity-50" style={{ color: 'var(--emerald-400)' }} />
                        <p>No critical or high severity findings</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Accounts Tab */}
            {activeTab === 'accounts' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <select
                      value={providerFilter}
                      onChange={(e) => setProviderFilter(e.target.value)}
                      className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                    >
                      <option value="all">All Providers</option>
                      <option value="aws">AWS</option>
                      <option value="azure">Azure</option>
                      <option value="gcp">GCP</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {accounts
                    .filter((a) => providerFilter === 'all' || a.provider === providerFilter)
                    .map((account) => (
                      <div key={account.id} className={cn('rounded-lg p-4 border', getProviderColor(account.provider))}>
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-3">
                            <div className="h-10 w-10 rounded-lg bg-slate-600 flex items-center justify-center">
                              {getProviderIcon(account.provider)}
                            </div>
                            <div>
                              <h4 className="text-white font-medium">{account.name}</h4>
                              <p className="text-xs text-slate-400 font-mono">{account.account_id}</p>
                            </div>
                          </div>
                          <span
                            className={cn(
                              'px-2 py-1 rounded text-xs font-medium',
                              account.connection_status === 'connected'
                                ? 'text-green-400 bg-green-500/20'
                                : 'text-red-400 bg-red-500/20'
                            )}
                          >
                            {account.connection_status}
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-2 mb-4">
                          <div className="text-center">
                            <p className="text-lg font-semibold text-white">{account.resources_count}</p>
                            <p className="text-xs text-slate-400">Resources</p>
                          </div>
                          <div className="text-center">
                            <p className="text-lg font-semibold text-orange-400">{account.findings_count}</p>
                            <p className="text-xs text-slate-400">Findings</p>
                          </div>
                          <div className="text-center">
                            <p className={cn('text-lg font-semibold', getComplianceScoreColor(account.compliance_score))}>
                              {account.compliance_score.toFixed(0)}%
                            </p>
                            <p className="text-xs text-slate-400">Score</p>
                          </div>
                          <div className="text-center">
                            <p className="text-lg font-semibold text-red-400">{account.critical_findings_count}</p>
                            <p className="text-xs text-slate-400">Critical</p>
                          </div>
                        </div>

                        <div className="flex items-center justify-between text-xs text-slate-500">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {account.last_scan_at ? `Scanned: ${formatDate(account.last_scan_at)}` : 'Never scanned'}
                          </span>
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => startScan(account.id)}
                              className="p-1 hover:bg-slate-600 rounded"
                              title="Start Scan"
                            >
                              <Play className="h-4 w-4" />
                            </button>
                            <button className="p-1 hover:bg-slate-600 rounded" title="View Details">
                              <Eye className="h-4 w-4" />
                            </button>
                            <button className="p-1 hover:bg-slate-600 rounded" title="Settings">
                              <Settings className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Asset Inventory Tab */}
            {activeTab === 'assets' && (
              <div className="space-y-4">
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search assets..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-slate-700 border border-slate-600 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-300 placeholder-slate-500"
                    />
                  </div>
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <select
                    value={selectedAssetType}
                    onChange={(e) => setSelectedAssetType(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    {assetTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                  <button className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-4 py-2 text-sm text-slate-300">
                    <Download className="h-4 w-4" />
                    Export
                  </button>
                </div>

                {/* Asset Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                  {[
                    { type: 'Compute', count: 156, icon: Cpu, color: 'text-blue-400' },
                    { type: 'Storage', count: 89, icon: HardDrive, color: 'text-green-400' },
                    { type: 'Database', count: 34, icon: Database, color: 'text-purple-400' },
                    { type: 'Network', count: 78, icon: Network, color: 'text-cyan-400' },
                    { type: 'Container', count: 45, icon: Container, color: 'text-orange-400' },
                    { type: 'Serverless', count: 67, icon: Zap, color: 'text-yellow-400' },
                  ].map((item) => (
                    <div
                      key={item.type}
                      className="bg-slate-700/50 rounded-lg p-3 border border-slate-600 cursor-pointer hover:border-slate-500"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <item.icon className={cn('h-4 w-4', item.color)} />
                        <span className="text-sm text-slate-300">{item.type}</span>
                      </div>
                      <p className="text-xl font-bold text-white">{item.count}</p>
                    </div>
                  ))}
                </div>

                {/* Asset Table */}
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Asset</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Type</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Provider</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Region</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Security</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Vulnerabilities</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Compliance</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assets.length > 0 ? (
                        assets.map((asset) => (
                          <tr key={asset.id} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                            <td className="p-3">
                              <div>
                                <p className="text-white font-medium">{asset.name}</p>
                                <p className="text-xs text-slate-500 font-mono">{asset.id}</p>
                              </div>
                            </td>
                            <td className="p-3">
                              <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">{asset.type}</span>
                            </td>
                            <td className="p-3">{getProviderIcon(asset.provider)}</td>
                            <td className="p-3 text-sm text-slate-400">{asset.region}</td>
                            <td className="p-3">
                              <span
                                className={cn(
                                  'px-2 py-1 rounded text-xs',
                                  asset.security_status === 'secure'
                                    ? 'text-green-400 bg-green-500/20'
                                    : asset.security_status === 'at_risk'
                                    ? 'text-yellow-400 bg-yellow-500/20'
                                    : 'text-red-400 bg-red-500/20'
                                )}
                              >
                                {asset.security_status}
                              </span>
                            </td>
                            <td className="p-3">
                              <span
                                className={cn(
                                  'font-medium',
                                  asset.vulnerability_count > 0 ? 'text-orange-400' : 'text-green-400'
                                )}
                              >
                                {asset.vulnerability_count}
                              </span>
                            </td>
                            <td className="p-3">
                              <span
                                className={cn(
                                  'px-2 py-1 rounded text-xs',
                                  asset.compliance_status === 'compliant'
                                    ? 'text-green-400 bg-green-500/20'
                                    : asset.compliance_status === 'partial'
                                    ? 'text-yellow-400 bg-yellow-500/20'
                                    : 'text-red-400 bg-red-500/20'
                                )}
                              >
                                {asset.compliance_status}
                              </span>
                            </td>
                            <td className="p-3">
                              <button className="p-1 hover:bg-slate-600 rounded text-slate-400 hover:text-white">
                                <Eye className="h-4 w-4" />
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={8} className="text-center py-12 text-slate-500">
                            <Boxes className="h-12 w-12 mx-auto mb-4 opacity-50" />
                            <p>No assets found</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Identity Security Tab */}
            {activeTab === 'identity' && (
              <div className="space-y-6">
                {/* Identity Overview */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Users className="h-5 w-5 text-blue-400" />
                      <span className="text-slate-400">Total Identities</span>
                    </div>
                    <p className="text-2xl font-bold text-white">{stats.total_identities || identities.length}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <ShieldAlert className="h-5 w-5 text-red-400" />
                      <span className="text-slate-400">High Risk</span>
                    </div>
                    <p className="text-2xl font-bold text-red-400">{stats.high_risk_identities || 0}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Key className="h-5 w-5 text-yellow-400" />
                      <span className="text-slate-400">Admin Access</span>
                    </div>
                    <p className="text-2xl font-bold text-yellow-400">
                      {identities.filter((i) => i.has_admin_access).length}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <GitBranch className="h-5 w-5 text-purple-400" />
                      <span className="text-slate-400">Escalation Paths</span>
                    </div>
                    <p className="text-2xl font-bold text-purple-400">
                      {identities.reduce((sum, i) => sum + i.escalation_paths, 0)}
                    </p>
                  </div>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-4">
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <button className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 rounded-lg px-4 py-2 text-sm text-white">
                    <RefreshCw className="h-4 w-4" />
                    Analyze IAM
                  </button>
                </div>

                {/* Identity Risk Table */}
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Identity</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Provider</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Type</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Risk Score</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Permissions</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Escalation Paths</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Risk Factors</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {identities.length > 0 ? (
                        identities
                          .sort((a, b) => b.risk_score - a.risk_score)
                          .map((identity) => (
                            <tr key={identity.id} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                              <td className="p-3">
                                <div className="flex items-center gap-2">
                                  {identity.has_admin_access && <ShieldAlert className="h-4 w-4 text-red-400" />}
                                  <div>
                                    <p className="text-white font-medium">{identity.name}</p>
                                    <p className="text-xs text-slate-500">{identity.id}</p>
                                  </div>
                                </div>
                              </td>
                              <td className="p-3">{getProviderIcon(identity.provider)}</td>
                              <td className="p-3">
                                <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">
                                  {identity.type}
                                </span>
                              </td>
                              <td className="p-3">
                                <span className={cn('px-2 py-1 rounded text-sm font-bold', getRiskScoreColor(identity.risk_score))}>
                                  {identity.risk_score}
                                </span>
                              </td>
                              <td className="p-3 text-slate-300">{identity.permissions_count}</td>
                              <td className="p-3">
                                {identity.escalation_paths > 0 ? (
                                  <span className="text-purple-400 font-medium">{identity.escalation_paths}</span>
                                ) : (
                                  <span className="text-slate-500">None</span>
                                )}
                              </td>
                              <td className="p-3">
                                <div className="flex flex-wrap gap-1">
                                  {identity.risk_factors.slice(0, 2).map((factor, idx) => (
                                    <span key={idx} className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                                      {factor}
                                    </span>
                                  ))}
                                  {identity.risk_factors.length > 2 && (
                                    <span className="text-xs text-slate-500">+{identity.risk_factors.length - 2}</span>
                                  )}
                                </div>
                              </td>
                              <td className="p-3">
                                <button className="p-1 hover:bg-slate-600 rounded text-slate-400 hover:text-white">
                                  <Eye className="h-4 w-4" />
                                </button>
                              </td>
                            </tr>
                          ))
                      ) : (
                        <tr>
                          <td colSpan={8} className="text-center py-12 text-slate-500">
                            <UserCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
                            <p>No identities analyzed yet</p>
                            <button
                              onClick={() => fetchIdentities()}
                              className="mt-4 text-primary-400 hover:text-primary-300"
                            >
                              Run identity analysis
                            </button>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Runtime Protection Tab */}
            {activeTab === 'runtime' && (
              <div className="space-y-6">
                {/* Runtime Overview */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Container className="h-5 w-5 text-blue-400" />
                      <span className="text-slate-400">Monitored Workloads</span>
                    </div>
                    <p className="text-2xl font-bold text-white">{stats.monitored_workloads || 0}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <ShieldAlert className="h-5 w-5 text-red-400" />
                      <span className="text-slate-400">Runtime Threats</span>
                    </div>
                    <p className="text-2xl font-bold text-red-400">{stats.runtime_threats || 0}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Activity className="h-5 w-5 text-yellow-400" />
                      <span className="text-slate-400">Drift Detected</span>
                    </div>
                    <p className="text-2xl font-bold text-yellow-400">3</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <ShieldCheck className="h-5 w-5 text-green-400" />
                      <span className="text-slate-400">Admission Policies</span>
                    </div>
                    <p className="text-2xl font-bold text-green-400">12</p>
                  </div>
                </div>

                {/* Runtime Events */}
                <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Zap className="h-5 w-5 text-yellow-400" />
                    Runtime Security Events
                  </h3>
                  <div className="space-y-2">
                    {runtimeEvents.length > 0 ? (
                      runtimeEvents.map((event) => (
                        <div
                          key={event.id}
                          className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg border-l-4"
                          style={{
                            borderLeftColor:
                              event.severity === 'critical'
                                ? '#ef4444'
                                : event.severity === 'high'
                                ? '#f97316'
                                : event.severity === 'medium'
                                ? '#eab308'
                                : '#3b82f6',
                          }}
                        >
                          <div className="flex items-center gap-3">
                            {event.event_type === 'cryptominer' ? (
                              <Bug className="h-5 w-5 text-red-400" />
                            ) : event.event_type === 'reverse_shell' ? (
                              <AlertTriangle className="h-5 w-5 text-red-400" />
                            ) : (
                              <ShieldAlert className="h-5 w-5 text-orange-400" />
                            )}
                            <div>
                              <p className="text-white font-medium">{event.description}</p>
                              <p className="text-xs text-slate-400">
                                {event.workload_name} - {event.mitre_technique && `MITRE: ${event.mitre_technique}`}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                            <span className={cn('px-2 py-1 rounded text-xs', getSeverityColor(event.severity))}>
                              {event.severity.toUpperCase()}
                            </span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8 text-slate-500">
                        <ShieldCheck className="h-10 w-10 mx-auto mb-2 opacity-50" />
                        <p>No runtime threats detected</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Findings Tab */}
            {activeTab === 'findings' && (
              <div className="space-y-4">
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-slate-700 border border-slate-600 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-300 placeholder-slate-500"
                    />
                  </div>
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="resolved">Resolved</option>
                    <option value="exception">Exception</option>
                  </select>
                  <button
                    onClick={fetchFindings}
                    className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-4 py-2 text-sm text-slate-300"
                  >
                    <Filter className="h-4 w-4" />
                    Apply
                  </button>
                </div>

                <div className="space-y-3">
                  {findings.length === 0 ? (
                    <div className="text-center py-12 text-slate-500">
                      <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No findings match your filters</p>
                    </div>
                  ) : (
                    findings.map((finding) => (
                      <div
                        key={finding.id}
                        className="bg-slate-700/30 rounded-lg p-4 border-l-4"
                        style={{
                          borderLeftColor:
                            finding.severity === 'critical'
                              ? '#ef4444'
                              : finding.severity === 'high'
                              ? '#f97316'
                              : finding.severity === 'medium'
                              ? '#eab308'
                              : '#3b82f6',
                        }}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              {getProviderIcon(finding.provider)}
                              <h4 className="text-white font-medium">{finding.title}</h4>
                              <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getSeverityColor(finding.severity))}>
                                {finding.severity.toUpperCase()}
                              </span>
                              <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getStatusColor(finding.status))}>
                                {finding.status}
                              </span>
                            </div>
                            <p className="text-sm text-slate-400 mb-2">{finding.description}</p>
                            {finding.recommendation && (
                              <p className="text-sm text-green-400 mb-2">
                                <strong>Recommendation:</strong> {finding.recommendation}
                              </p>
                            )}
                            <div className="flex items-center gap-4 text-xs text-slate-500">
                              <span>
                                <strong>Resource:</strong> {finding.resource_name}
                              </span>
                              <span>
                                <strong>Type:</strong> {finding.resource_type}
                              </span>
                              {finding.region && (
                                <span>
                                  <strong>Region:</strong> {finding.region}
                                </span>
                              )}
                            </div>
                            {finding.compliance.length > 0 && (
                              <div className="flex items-center gap-2 mt-2">
                                {finding.compliance.map((c) => (
                                  <span key={c} className="px-2 py-0.5 bg-slate-600 rounded text-xs text-slate-300">
                                    {c}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <button className="p-1.5 hover:bg-slate-600 rounded text-slate-400 hover:text-white">
                              <Eye className="h-4 w-4" />
                            </button>
                            <button className="p-1.5 hover:bg-slate-600 rounded text-slate-400 hover:text-white">
                              <ExternalLink className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Compliance Tab */}
            {activeTab === 'compliance' && (
              <div className="space-y-6">
                {_complianceFrameworks.length === 0 ? (
                  <div className="bg-slate-700/30 border border-slate-600 rounded-lg p-8 text-center">
                    <Shield className="h-10 w-10 mx-auto mb-3 text-slate-500" />
                    <h4 className="text-white font-medium">No compliance framework data available</h4>
                    <p className="text-sm text-slate-400 mt-1">
                      Connect a cloud account and run a posture scan to populate framework scores.
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {_complianceFrameworks.map((framework) => {
                      const scores = framework.scores
                      const providerScores = [scores.aws, scores.azure, scores.gcp].filter(Number.isFinite)
                      const avgScore = providerScores.length > 0
                        ? providerScores.reduce((sum, score) => sum + score, 0) / providerScores.length
                        : 0

                      return (
                      <div key={framework.name} className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h4 className="text-white font-medium">{framework.name}</h4>
                            <p className="text-xs text-slate-400">
                              {framework.passing_checks} of {framework.total_checks} checks passing
                            </p>
                          </div>
                          <span className={cn('text-2xl font-bold', getComplianceScoreColor(avgScore))}>
                            {avgScore.toFixed(0)}%
                          </span>
                        </div>
                        <div className="space-y-3">
                          {['aws', 'azure', 'gcp'].map((provider) => {
                            const score = scores[provider as keyof typeof scores]

                            return (
                              <div key={provider} className="flex items-center justify-between">
                                <span className="text-sm text-slate-400">{provider.toUpperCase()}</span>
                                <div className="flex items-center gap-2">
                                  <div className="w-24 h-1.5 bg-slate-600 rounded-full overflow-hidden">
                                    <div
                                      className={cn(
                                        'h-full rounded-full',
                                        score >= 90 ? 'bg-green-500' : score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                                      )}
                                      style={{ width: `${score}%` }}
                                    />
                                  </div>
                                  <span className={cn('text-sm font-medium', getComplianceScoreColor(score))}>
                                    {score}%
                                  </span>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                        <div className="mt-4 pt-4 border-t border-slate-600">
                          <button className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1">
                            View Details <ChevronRight className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )}

            {/* IaC Security Tab */}
            {activeTab === 'iac' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* IaC Scanner */}
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <FileCode className="h-5 w-5 text-primary-400" />
                      Infrastructure as Code Scanner
                    </h3>
                    <p className="text-sm text-slate-400 mb-4">
                      Paste Terraform, CloudFormation, Kubernetes YAML, or ARM templates to scan for security issues.
                    </p>
                    <textarea
                      value={iacContent}
                      onChange={(e) => setIacContent(e.target.value)}
                      placeholder="Paste your IaC code here..."
                      className="w-full h-64 bg-slate-900 border border-slate-600 rounded-lg p-4 text-sm text-slate-300 font-mono placeholder-slate-500"
                    />
                    <div className="flex items-center justify-between mt-4">
                      <div className="flex items-center gap-2 text-xs text-slate-500">
                        <span>Supports: Terraform, CloudFormation, K8s, ARM</span>
                      </div>
                      <button
                        onClick={scanIaC}
                        disabled={!iacContent.trim() || isLoading}
                        className={cn(
                          'flex items-center gap-2 px-4 py-2 rounded-lg text-sm',
                          iacContent.trim()
                            ? 'bg-primary-600 hover:bg-primary-500 text-white'
                            : 'bg-slate-600 text-slate-400 cursor-not-allowed'
                        )}
                      >
                        {isLoading ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Shield className="h-4 w-4" />
                        )}
                        Scan
                      </button>
                    </div>
                  </div>

                  {/* Scan Results */}
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-orange-400" />
                      Scan Results
                    </h3>
                    {iacScanResults ? (
                      <div className="space-y-4">
                        {/* Summary */}
                        <div className="grid grid-cols-4 gap-2">
                          <div className="bg-slate-700/50 rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-red-400">
                              {iacScanResults.severity_summary?.critical || 0}
                            </p>
                            <p className="text-xs text-slate-400">Critical</p>
                          </div>
                          <div className="bg-slate-700/50 rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-orange-400">
                              {iacScanResults.severity_summary?.high || 0}
                            </p>
                            <p className="text-xs text-slate-400">High</p>
                          </div>
                          <div className="bg-slate-700/50 rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-yellow-400">
                              {iacScanResults.severity_summary?.medium || 0}
                            </p>
                            <p className="text-xs text-slate-400">Medium</p>
                          </div>
                          <div className="bg-slate-700/50 rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-blue-400">
                              {iacScanResults.severity_summary?.low || 0}
                            </p>
                            <p className="text-xs text-slate-400">Low</p>
                          </div>
                        </div>

                        {/* Findings */}
                        <div className="space-y-2 max-h-96 overflow-y-auto">
                          {iacScanResults.findings?.map((finding: any, idx: number) => (
                            <div
                              key={idx}
                              className="bg-slate-700/50 rounded-lg p-3 border-l-4"
                              style={{
                                borderLeftColor:
                                  finding.severity === 'critical'
                                    ? '#ef4444'
                                    : finding.severity === 'high'
                                    ? '#f97316'
                                    : finding.severity === 'medium'
                                    ? '#eab308'
                                    : '#3b82f6',
                              }}
                            >
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-white font-medium text-sm">{finding.rule_name}</span>
                                <span
                                  className={cn('px-2 py-0.5 rounded text-xs', getSeverityColor(finding.severity))}
                                >
                                  {finding.severity.toUpperCase()}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400">{finding.description}</p>
                              <p className="text-xs text-slate-500 mt-1">Resource: {finding.resource_name}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-12 text-slate-500">
                        <FileCode className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>Paste IaC code and click Scan to check for security issues</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <button className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 rounded-lg px-4 py-2 text-sm text-white">
                    <Plus className="h-4 w-4" />
                    Create Custom Policy
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Policy</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Provider</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Category</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Severity</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Source</th>
                        <th className="text-left p-3 text-sm font-medium text-slate-400">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policies.map((policy) => (
                        <tr key={policy.id} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                          <td className="p-3">
                            <div>
                              <p className="text-white font-medium">{policy.name}</p>
                              <p className="text-xs text-slate-500 line-clamp-1">{policy.description}</p>
                            </div>
                          </td>
                          <td className="p-3">{getProviderIcon(policy.provider)}</td>
                          <td className="p-3">
                            <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">
                              {policy.category.replace(/_/g, ' ')}
                            </span>
                          </td>
                          <td className="p-3">
                            <span className={cn('px-2 py-1 rounded text-xs font-medium', getSeverityColor(policy.severity))}>
                              {policy.severity}
                            </span>
                          </td>
                          <td className="p-3">
                            <span
                              className={cn(
                                'px-2 py-1 rounded text-xs',
                                policy.source === 'builtin'
                                  ? 'bg-blue-500/20 text-blue-400'
                                  : 'bg-purple-500/20 text-purple-400'
                              )}
                            >
                              {policy.source}
                            </span>
                          </td>
                          <td className="p-3">
                            <span
                              className={cn(
                                'px-2 py-1 rounded text-xs',
                                policy.enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-500/20 text-slate-400'
                              )}
                            >
                              {policy.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Topology & Risk Tab */}
            {activeTab === 'topology' && (
              <div className="space-y-6">
                {/* View Mode Toggle */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setTopologyViewMode('graph')}
                      className={cn(
                        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        topologyViewMode === 'graph'
                          ? 'bg-primary-600 text-white'
                          : 'text-slate-400 hover:text-white hover:bg-slate-700'
                      )}
                    >
                      <Network className="h-4 w-4" />
                      Resource Graph
                    </button>
                    <button
                      onClick={() => setTopologyViewMode('heatmap')}
                      className={cn(
                        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        topologyViewMode === 'heatmap'
                          ? 'bg-primary-600 text-white'
                          : 'text-slate-400 hover:text-white hover:bg-slate-700'
                      )}
                    >
                      <LayoutGrid className="h-4 w-4" />
                      Risk Heat Map
                    </button>
                    <button
                      onClick={() => setTopologyViewMode('regions')}
                      className={cn(
                        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        topologyViewMode === 'regions'
                          ? 'bg-primary-600 text-white'
                          : 'text-slate-400 hover:text-white hover:bg-slate-700'
                      )}
                    >
                      <Globe className="h-4 w-4" />
                      Regional View
                    </button>
                  </div>
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                </div>

                {/* Resource Graph View */}
                {topologyViewMode === 'graph' && (
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <Network className="h-5 w-5 text-primary-400" />
                      Cloud Resource Topology
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
                      <div className="col-span-2">
                        {/* Resource Graph Visualization */}
                        <div className="bg-slate-800 rounded-lg p-4 h-[500px] relative overflow-hidden">
                          {topologyNodes.length > 0 ? (
                            <div className="absolute inset-0 p-4">
                              {/* Group by provider */}
                              {['aws', 'azure', 'gcp'].filter(p =>
                                providerFilter === 'all' || p === providerFilter
                              ).map((provider, pIdx) => {
                                const providerNodes = topologyNodes.filter(n => n.provider === provider)
                                if (providerNodes.length === 0) return null

                                return (
                                  <div
                                    key={provider}
                                    className={cn(
                                      'absolute rounded-lg border-2 p-4',
                                      getProviderColor(provider)
                                    )}
                                    style={{
                                      top: `${pIdx * 180 + 10}px`,
                                      left: '10px',
                                      right: '10px',
                                      minHeight: '160px',
                                    }}
                                  >
                                    <div className="flex items-center gap-2 mb-3">
                                      {getProviderIcon(provider)}
                                      <span className="text-sm text-slate-300 font-medium">
                                        {provider.toUpperCase()} Resources
                                      </span>
                                    </div>
                                    <div className="flex flex-wrap gap-3">
                                      {providerNodes.map((node) => {
                                        const Icon = getResourceIcon(node.type)
                                        return (
                                          <div
                                            key={node.id}
                                            className={cn(
                                              'bg-slate-700/80 rounded-lg p-3 border-2 cursor-pointer hover:bg-slate-600/80 transition-colors min-w-[120px]',
                                              getSecurityStatusColor(node.security_status)
                                            )}
                                            title={`${node.name}\nType: ${node.type}\nFindings: ${node.findings_count}`}
                                          >
                                            <div className="flex items-center gap-2 mb-1">
                                              <Icon className="h-4 w-4" />
                                              <span className="text-xs text-slate-300 truncate max-w-[80px]">
                                                {node.name}
                                              </span>
                                            </div>
                                            <div className="flex items-center gap-2 text-xs">
                                              <span className="text-slate-500">{node.type}</span>
                                              {node.public_exposure && (
                                                <Globe className="h-3 w-3 text-red-400" title="Publicly exposed" />
                                              )}
                                              {node.findings_count > 0 && (
                                                <span className="px-1 py-0.5 bg-red-500/20 text-red-400 rounded">
                                                  {node.findings_count}
                                                </span>
                                              )}
                                            </div>
                                          </div>
                                        )
                                      })}
                                    </div>
                                  </div>
                                )
                              })}
                            </div>
                          ) : (
                            <div className="flex items-center justify-center h-full text-slate-500">
                              <div className="text-center">
                                <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
                                <p>No topology data available</p>
                                <p className="text-sm">Connect cloud accounts to view resource topology</p>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      {/* Legend and Stats */}
                      <div className="space-y-4">
                        <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                          <h4 className="text-sm font-medium text-white mb-3">Security Status Legend</h4>
                          <div className="space-y-2">
                            {[
                              { status: 'secure', label: 'Secure', color: 'border-green-500' },
                              { status: 'at_risk', label: 'At Risk', color: 'border-yellow-500' },
                              { status: 'critical', label: 'Critical', color: 'border-red-500' },
                              { status: 'unknown', label: 'Unknown', color: 'border-slate-500' },
                            ].map((item) => (
                              <div key={item.status} className="flex items-center gap-2">
                                <div className={cn('w-4 h-4 rounded border-2', item.color)} />
                                <span className="text-sm text-slate-300">{item.label}</span>
                                <span className="text-xs text-slate-500 ml-auto">
                                  {topologyNodes.filter(n => n.security_status === item.status).length}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                          <h4 className="text-sm font-medium text-white mb-3">Resource Summary</h4>
                          <div className="space-y-2">
                            {Object.entries(
                              topologyNodes.reduce((acc, node) => {
                                acc[node.type] = (acc[node.type] || 0) + 1
                                return acc
                              }, {} as Record<string, number>)
                            ).map(([type, count]) => {
                              const Icon = getResourceIcon(type)
                              return (
                                <div key={type} className="flex items-center gap-2">
                                  <Icon className="h-4 w-4 text-slate-400" />
                                  <span className="text-sm text-slate-300 capitalize">{type}</span>
                                  <span className="text-sm text-slate-500 ml-auto">{count}</span>
                                </div>
                              )
                            })}
                          </div>
                        </div>
                        <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                          <h4 className="text-sm font-medium text-white mb-3">Public Exposure</h4>
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-slate-400">Exposed Resources</span>
                            <span className="text-lg font-bold text-red-400">
                              {topologyNodes.filter(n => n.public_exposure).length}
                            </span>
                          </div>
                          <div className="h-2 bg-slate-600 rounded-full mt-2">
                            <div
                              className="h-full bg-red-500 rounded-full"
                              style={{
                                width: `${topologyNodes.length > 0
                                  ? (topologyNodes.filter(n => n.public_exposure).length / topologyNodes.length) * 100
                                  : 0}%`
                              }}
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Risk Heat Map View */}
                {topologyViewMode === 'heatmap' && (
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <LayoutGrid className="h-5 w-5 text-orange-400" />
                      Risk Heat Map by Region & Resource Type
                    </h3>
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-slate-700">
                            <th className="text-left p-3 text-sm font-medium text-slate-400">Region</th>
                            {['ec2', 's3', 'rds', 'lambda', 'iam'].map((type) => {
                              const Icon = getResourceIcon(type)
                              return (
                                <th key={type} className="text-center p-3 text-sm font-medium text-slate-400">
                                  <div className="flex items-center justify-center gap-1">
                                    <Icon className="h-4 w-4" />
                                    <span className="uppercase">{type}</span>
                                  </div>
                                </th>
                              )
                            })}
                          </tr>
                        </thead>
                        <tbody>
                          {['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1'].map((region) => (
                            <tr key={region} className="border-b border-slate-700/50">
                              <td className="p-3 text-sm text-slate-300">{region}</td>
                              {['ec2', 's3', 'rds', 'lambda', 'iam'].map((type) => {
                                const data = riskHeatMap.find(
                                  (d) => d.region === region && d.resource_type === type &&
                                  (providerFilter === 'all' || d.provider === providerFilter)
                                )
                                const score = data?.risk_score || 0
                                return (
                                  <td key={type} className="p-2 text-center">
                                    <div
                                      className={cn(
                                        'rounded-lg p-2 cursor-pointer hover:opacity-80 transition-opacity',
                                        getHeatMapColor(score)
                                      )}
                                      title={`Risk Score: ${score}\nFindings: ${data?.findings_count || 0}\nCritical: ${data?.critical_count || 0}\nHigh: ${data?.high_count || 0}`}
                                    >
                                      <span className="text-white font-bold">{score}</span>
                                      {(data?.critical_count || 0) > 0 && (
                                        <div className="text-xs text-white/80 mt-1">
                                          {data?.critical_count}C / {data?.high_count}H
                                        </div>
                                      )}
                                    </div>
                                  </td>
                                )
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="flex items-center gap-4 mt-4 justify-center">
                      <span className="text-xs text-slate-400">Risk Level:</span>
                      {[
                        { label: 'Low (0-20)', color: 'bg-green-500' },
                        { label: 'Medium (21-40)', color: 'bg-blue-500' },
                        { label: 'Moderate (41-60)', color: 'bg-yellow-500' },
                        { label: 'High (61-80)', color: 'bg-orange-500' },
                        { label: 'Critical (81-100)', color: 'bg-red-500' },
                      ].map((item) => (
                        <div key={item.label} className="flex items-center gap-1">
                          <div className={cn('w-4 h-4 rounded', item.color)} />
                          <span className="text-xs text-slate-400">{item.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Regional View */}
                {topologyViewMode === 'regions' && (
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <Globe className="h-5 w-5 text-blue-400" />
                      Resources by Region
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'].map((region) => {
                        const regionNodes = topologyNodes.filter(n => n.region === region)
                        const regionRisk = riskHeatMap.filter(r => r.region === region)
                        const totalFindings = regionRisk.reduce((sum, r) => sum + r.findings_count, 0)
                        const criticalCount = regionRisk.reduce((sum, r) => sum + r.critical_count, 0)

                        return (
                          <div key={region} className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                            <div className="flex items-center justify-between mb-3">
                              <div className="flex items-center gap-2">
                                <Globe className="h-4 w-4 text-blue-400" />
                                <span className="text-white font-medium">{region}</span>
                              </div>
                              <span className={cn(
                                'px-2 py-1 rounded text-xs font-medium',
                                criticalCount > 0 ? 'bg-red-500/20 text-red-400' :
                                totalFindings > 0 ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-green-500/20 text-green-400'
                              )}>
                                {criticalCount > 0 ? `${criticalCount} Critical` :
                                 totalFindings > 0 ? `${totalFindings} Issues` : 'Healthy'}
                              </span>
                            </div>
                            <div className="grid grid-cols-3 gap-2 text-center">
                              <div className="bg-slate-600/50 rounded p-2">
                                <p className="text-lg font-bold text-white">{regionNodes.length}</p>
                                <p className="text-xs text-slate-400">Resources</p>
                              </div>
                              <div className="bg-slate-600/50 rounded p-2">
                                <p className="text-lg font-bold text-orange-400">{totalFindings}</p>
                                <p className="text-xs text-slate-400">Findings</p>
                              </div>
                              <div className="bg-slate-600/50 rounded p-2">
                                <p className="text-lg font-bold text-red-400">{criticalCount}</p>
                                <p className="text-xs text-slate-400">Critical</p>
                              </div>
                            </div>
                            {regionNodes.length > 0 && (
                              <div className="mt-3 flex flex-wrap gap-1">
                                {Object.entries(
                                  regionNodes.reduce((acc, n) => {
                                    acc[n.type] = (acc[n.type] || 0) + 1
                                    return acc
                                  }, {} as Record<string, number>)
                                ).slice(0, 4).map(([type, count]) => (
                                  <span key={type} className="px-2 py-0.5 bg-slate-600 rounded text-xs text-slate-300">
                                    {type}: {count}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Security Groups Tab */}
            {activeTab === 'security-groups' && (
              <div className="space-y-6">
                {/* Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="h-5 w-5 text-blue-400" />
                      <span className="text-slate-400">Total Security Groups</span>
                    </div>
                    <p className="text-2xl font-bold text-white">{securityGroups.length}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                      <span className="text-slate-400">Critical Risk</span>
                    </div>
                    <p className="text-2xl font-bold text-red-400">
                      {securityGroups.filter(sg => sg.risk_level === 'critical').length}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Globe className="h-5 w-5 text-orange-400" />
                      <span className="text-slate-400">Public Access Rules</span>
                    </div>
                    <p className="text-2xl font-bold text-orange-400">
                      {securityGroups.reduce((sum, sg) =>
                        sum + sg.inbound_rules.filter(r => r.source === '0.0.0.0/0').length, 0
                      )}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Server className="h-5 w-5 text-green-400" />
                      <span className="text-slate-400">Attached Resources</span>
                    </div>
                    <p className="text-2xl font-bold text-white">
                      {securityGroups.reduce((sum, sg) => sum + sg.attached_resources, 0)}
                    </p>
                  </div>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-4">
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <button
                    onClick={fetchSecurityGroups}
                    className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-4 py-2 text-sm text-slate-300"
                  >
                    <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
                    Refresh
                  </button>
                </div>

                {/* Security Groups List */}
                <div className="space-y-4">
                  {securityGroups.length === 0 ? (
                    <div className="text-center py-12 text-slate-500">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No security groups found</p>
                    </div>
                  ) : (
                    securityGroups.map((sg) => (
                      <div
                        key={sg.id}
                        className="bg-slate-700/30 rounded-lg p-4 border-l-4"
                        style={{
                          borderLeftColor:
                            sg.risk_level === 'critical' ? '#ef4444' :
                            sg.risk_level === 'high' ? '#f97316' :
                            sg.risk_level === 'medium' ? '#eab308' : '#22c55e'
                        }}
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getProviderIcon(sg.provider)}
                              <h4 className="text-white font-medium">{sg.name}</h4>
                              <span className={cn(
                                'px-2 py-0.5 rounded text-xs font-medium',
                                sg.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                                sg.risk_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                sg.risk_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-green-500/20 text-green-400'
                              )}>
                                {sg.risk_level.toUpperCase()} RISK
                              </span>
                            </div>
                            <p className="text-xs text-slate-500 font-mono">{sg.id}</p>
                            {sg.vpc_id && (
                              <p className="text-xs text-slate-500">VPC: {sg.vpc_id}</p>
                            )}
                          </div>
                          <div className="flex items-center gap-4 text-sm">
                            <div className="text-center">
                              <p className="text-lg font-bold text-white">{sg.attached_resources}</p>
                              <p className="text-xs text-slate-400">Resources</p>
                            </div>
                            <div className="text-center">
                              <p className="text-lg font-bold text-blue-400">{sg.inbound_rules.length}</p>
                              <p className="text-xs text-slate-400">Inbound</p>
                            </div>
                            <div className="text-center">
                              <p className="text-lg font-bold text-purple-400">{sg.outbound_rules.length}</p>
                              <p className="text-xs text-slate-400">Outbound</p>
                            </div>
                          </div>
                        </div>

                        {/* Issues */}
                        {sg.issues.length > 0 && (
                          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                            <p className="text-sm font-medium text-red-400 mb-2">Security Issues:</p>
                            <ul className="list-disc list-inside text-sm text-red-300 space-y-1">
                              {sg.issues.map((issue, idx) => (
                                <li key={idx}>{issue}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Rules Table */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                          {/* Inbound Rules */}
                          <div>
                            <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                              <ArrowDownRight className="h-4 w-4 text-blue-400" />
                              Inbound Rules
                            </h5>
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b border-slate-600">
                                  <th className="text-left p-2 text-slate-400">Protocol</th>
                                  <th className="text-left p-2 text-slate-400">Ports</th>
                                  <th className="text-left p-2 text-slate-400">Source</th>
                                </tr>
                              </thead>
                              <tbody>
                                {sg.inbound_rules.map((rule, idx) => (
                                  <tr
                                    key={idx}
                                    className={cn(
                                      'border-b border-slate-700/50',
                                      rule.is_risky && 'bg-red-500/10'
                                    )}
                                  >
                                    <td className="p-2 text-slate-300">{rule.protocol.toUpperCase()}</td>
                                    <td className="p-2 text-slate-300">{rule.port_range}</td>
                                    <td className="p-2">
                                      <div className="flex items-center gap-1">
                                        <span className={cn(
                                          rule.source === '0.0.0.0/0' ? 'text-red-400' : 'text-slate-300'
                                        )}>
                                          {rule.source}
                                        </span>
                                        {rule.is_risky && (
                                          <AlertTriangle className="h-3 w-3 text-red-400" title={rule.risk_reason} />
                                        )}
                                      </div>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>

                          {/* Outbound Rules */}
                          <div>
                            <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                              <ArrowUpRight className="h-4 w-4 text-purple-400" />
                              Outbound Rules
                            </h5>
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b border-slate-600">
                                  <th className="text-left p-2 text-slate-400">Protocol</th>
                                  <th className="text-left p-2 text-slate-400">Ports</th>
                                  <th className="text-left p-2 text-slate-400">Destination</th>
                                </tr>
                              </thead>
                              <tbody>
                                {sg.outbound_rules.map((rule, idx) => (
                                  <tr key={idx} className="border-b border-slate-700/50">
                                    <td className="p-2 text-slate-300">{rule.protocol.toUpperCase()}</td>
                                    <td className="p-2 text-slate-300">{rule.port_range}</td>
                                    <td className="p-2 text-slate-300">{rule.source}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Remediation Tab */}
            {activeTab === 'remediation' && (
              <div className="space-y-6">
                {/* Remediation Overview */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                      <span className="text-slate-400">Open Findings</span>
                    </div>
                    <p className="text-2xl font-bold text-red-400">
                      {findings.filter(f => f.status === 'open').length}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Wrench className="h-5 w-5 text-blue-400" />
                      <span className="text-slate-400">Auto-Fix Available</span>
                    </div>
                    <p className="text-2xl font-bold text-blue-400">
                      {findings.filter(f => f.remediation_terraform || f.remediation_cloudformation).length}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="h-5 w-5 text-green-400" />
                      <span className="text-slate-400">Resolved (30d)</span>
                    </div>
                    <p className="text-2xl font-bold text-green-400">
                      {findings.filter(f => f.status === 'resolved').length}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center gap-2 mb-2">
                      <Target className="h-5 w-5 text-purple-400" />
                      <span className="text-slate-400">Risk Reduction</span>
                    </div>
                    <p className="text-2xl font-bold text-purple-400">
                      {Math.round(
                        (findings.filter(f => f.status === 'resolved').length /
                         Math.max(1, findings.length)) * 100
                      )}%
                    </p>
                  </div>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-4 flex-wrap">
                  <select
                    value={providerFilter}
                    onChange={(e) => setProviderFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Providers</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="gcp">GCP</option>
                  </select>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-300"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => exportFindings('csv')}
                      className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-4 py-2 text-sm text-slate-300"
                    >
                      <Download className="h-4 w-4" />
                      Export CSV
                    </button>
                    <button
                      onClick={() => exportFindings('json')}
                      className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-4 py-2 text-sm text-slate-300"
                    >
                      <Download className="h-4 w-4" />
                      Export JSON
                    </button>
                  </div>
                </div>

                {/* Findings with Remediation */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                    <Wrench className="h-5 w-5 text-primary-400" />
                    Findings Requiring Remediation
                  </h3>
                  {findings.filter(f => f.status === 'open').length === 0 ? (
                    <div className="text-center py-12 text-slate-500">
                      <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No open findings requiring remediation</p>
                    </div>
                  ) : (
                    findings
                      .filter(f => f.status === 'open')
                      .filter(f => providerFilter === 'all' || f.provider === providerFilter)
                      .filter(f => severityFilter === 'all' || f.severity === severityFilter)
                      .map((finding) => (
                        <div
                          key={finding.id}
                          className="bg-slate-700/30 rounded-lg p-4 border-l-4"
                          style={{
                            borderLeftColor:
                              finding.severity === 'critical' ? '#ef4444' :
                              finding.severity === 'high' ? '#f97316' :
                              finding.severity === 'medium' ? '#eab308' : '#3b82f6'
                          }}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                {getProviderIcon(finding.provider)}
                                <h4 className="text-white font-medium">{finding.title}</h4>
                                <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getSeverityColor(finding.severity))}>
                                  {finding.severity.toUpperCase()}
                                </span>
                              </div>
                              <p className="text-sm text-slate-400 mb-2">{finding.description}</p>
                              <div className="flex items-center gap-4 text-xs text-slate-500">
                                <span><strong>Resource:</strong> {finding.resource_name}</span>
                                <span><strong>Type:</strong> {finding.resource_type}</span>
                                {finding.region && <span><strong>Region:</strong> {finding.region}</span>}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {(finding.remediation_terraform || finding.remediation_cloudformation) && (
                                <button
                                  onClick={() => {
                                    setSelectedFinding(finding)
                                    setShowRemediationModal(true)
                                  }}
                                  className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 rounded-lg px-4 py-2 text-sm text-white"
                                >
                                  <Wrench className="h-4 w-4" />
                                  View Fix
                                </button>
                              )}
                              <button
                                onClick={() => applyRemediation(finding.id, 'auto')}
                                disabled={remediationInProgress.has(finding.id)}
                                className={cn(
                                  'flex items-center gap-2 rounded-lg px-4 py-2 text-sm',
                                  remediationInProgress.has(finding.id)
                                    ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                                    : 'bg-green-600 hover:bg-green-500 text-white'
                                )}
                              >
                                {remediationInProgress.has(finding.id) ? (
                                  <RefreshCw className="h-4 w-4 animate-spin" />
                                ) : (
                                  <Play className="h-4 w-4" />
                                )}
                                Auto-Fix
                              </button>
                            </div>
                          </div>

                          {/* Recommendation */}
                          {finding.recommendation && (
                            <div className="mt-3 p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                              <p className="text-sm text-green-400">
                                <strong>Recommendation:</strong> {finding.recommendation}
                              </p>
                            </div>
                          )}

                          {/* Compliance Tags */}
                          {finding.compliance.length > 0 && (
                            <div className="flex items-center gap-2 mt-3">
                              {finding.compliance.map((c) => (
                                <span key={c} className="px-2 py-0.5 bg-slate-600 rounded text-xs text-slate-300">
                                  {c}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Add Account Modal */}
      {showAddAccountModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card-sentinel rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: 'var(--surface)' }}>
            <h2 className="text-xl font-semibold mb-4" style={{ color: 'var(--fg)' }}>Add Cloud Account</h2>
            <form className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--fg-2)' }}>Provider</label>
                <select
                  className="w-full rounded-lg px-3 py-2"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                >
                  <option value="aws">AWS</option>
                  <option value="azure">Azure</option>
                  <option value="gcp">GCP</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--fg-2)' }}>Account Name</label>
                <input
                  type="text"
                  placeholder="Production AWS"
                  className="w-full rounded-lg px-3 py-2"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--fg-2)' }}>Account ID</label>
                <input
                  type="text"
                  placeholder="123456789012"
                  className="w-full rounded-lg px-3 py-2"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                />
              </div>
              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAddAccountModal(false)}
                  className="flex-1 rounded-lg px-4 py-2 transition-colors"
                  style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)', border: '1px solid var(--border)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 rounded-lg px-4 py-2 text-white transition-colors"
                  style={{ backgroundColor: 'var(--emerald-600)' }}
                >
                  Add Account
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Remediation Code Modal */}
      {showRemediationModal && selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card-sentinel rounded-xl p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto" style={{ backgroundColor: 'var(--surface)' }}>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Wrench className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                  Remediation Code
                </h2>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{selectedFinding.title}</p>
              </div>
              <button
                onClick={() => {
                  setShowRemediationModal(false)
                  setSelectedFinding(null)
                }}
                className="p-2 rounded-lg transition-colors"
                style={{ color: 'var(--muted)' }}
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Finding Details */}
            <div className="mb-6 p-4 rounded-lg" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>Resource</p>
                  <p className="text-sm" style={{ color: 'var(--fg)' }}>{selectedFinding.resource_name}</p>
                </div>
                <div>
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>Resource Type</p>
                  <p className="text-sm" style={{ color: 'var(--fg)' }}>{selectedFinding.resource_type}</p>
                </div>
                <div>
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>Provider</p>
                  <p className="text-sm" style={{ color: 'var(--fg)' }}>{selectedFinding.provider.toUpperCase()}</p>
                </div>
                <div>
                  <p className="text-xs" style={{ color: 'var(--muted)' }}>Region</p>
                  <p className="text-sm" style={{ color: 'var(--fg)' }}>{selectedFinding.region || 'N/A'}</p>
                </div>
              </div>
              {selectedFinding.recommendation && (
                <div className="mt-4 pt-4" style={{ borderTop: '1px solid var(--border)' }}>
                  <p className="text-xs mb-1" style={{ color: 'var(--muted)' }}>Recommendation</p>
                  <p className="text-sm" style={{ color: 'var(--emerald-400)' }}>{selectedFinding.recommendation}</p>
                </div>
              )}
            </div>

            {/* Remediation Code Tabs */}
            <div className="space-y-4">
              {selectedFinding.remediation_terraform && (
                <div className="rounded-lg" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between p-3" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <FileCode className="h-4 w-4" style={{ color: 'var(--sol-magenta)' }} />
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Terraform</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(selectedFinding.remediation_terraform!, 'terraform')}
                      className="flex items-center gap-1 px-3 py-1 rounded text-xs transition-colors"
                      style={{ backgroundColor: 'var(--surface-3)', color: 'var(--fg-2)' }}
                    >
                      {copiedCode === 'terraform' ? (
                        <>
                          <Check className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 text-sm overflow-x-auto font-mono" style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)' }}>
                    {selectedFinding.remediation_terraform}
                  </pre>
                </div>
              )}

              {selectedFinding.remediation_cloudformation && (
                <div className="rounded-lg" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between p-3" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <FileCode className="h-4 w-4" style={{ color: 'var(--high)' }} />
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>CloudFormation</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(selectedFinding.remediation_cloudformation!, 'cfn')}
                      className="flex items-center gap-1 px-3 py-1 rounded text-xs transition-colors"
                      style={{ backgroundColor: 'var(--surface-3)', color: 'var(--fg-2)' }}
                    >
                      {copiedCode === 'cfn' ? (
                        <>
                          <Check className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 text-sm overflow-x-auto font-mono" style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)' }}>
                    {selectedFinding.remediation_cloudformation}
                  </pre>
                </div>
              )}

              {selectedFinding.remediation_arm && (
                <div className="rounded-lg" style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between p-3" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <FileCode className="h-4 w-4" style={{ color: 'var(--med)' }} />
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>ARM Template</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(selectedFinding.remediation_arm!, 'arm')}
                      className="flex items-center gap-1 px-3 py-1 rounded text-xs transition-colors"
                      style={{ backgroundColor: 'var(--surface-3)', color: 'var(--fg-2)' }}
                    >
                      {copiedCode === 'arm' ? (
                        <>
                          <Check className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 text-sm overflow-x-auto font-mono" style={{ backgroundColor: 'var(--bg)', color: 'var(--fg-2)' }}>
                    {selectedFinding.remediation_arm}
                  </pre>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between mt-6 pt-4" style={{ borderTop: '1px solid var(--border)' }}>
              <div className="text-xs" style={{ color: 'var(--subtle)' }}>
                Apply remediation code using your preferred IaC tool or click Auto-Fix to apply automatically.
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setShowRemediationModal(false)
                    setSelectedFinding(null)
                  }}
                  className="px-4 py-2 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)', border: '1px solid var(--border)' }}
                >
                  Close
                </button>
                <button
                  onClick={() => {
                    applyRemediation(selectedFinding.id, 'auto')
                    setShowRemediationModal(false)
                    setSelectedFinding(null)
                  }}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-white transition-colors"
                  style={{ backgroundColor: 'var(--emerald-600)' }}
                >
                  <Play className="h-4 w-4" />
                  Apply Auto-Fix
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  )
}
