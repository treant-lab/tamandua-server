// Shared props passed by Inertia
export interface SharedProps {
  auth: {
    user: User | null
  }
  flash: {
    success?: string
    error?: string
  }
  [key: string]: unknown
}

// Base PageProps for Inertia pages
export interface PageProps {
  auth?: {
    user: User | null
  }
  flash?: {
    success?: string
    error?: string
  }
}

export interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
}

// Agent types
export interface Agent {
  id: string
  hostname: string
  ip_address: string
  os_type: 'windows' | 'linux' | 'macos'
  os_version: string
  agent_version: string
  status: 'online' | 'offline' | 'degraded'
  last_seen: string
}

// Process types
export interface ProcessNode {
  pid: number
  ppid: number
  name: string
  path: string
  cmdline: string
  user: string
  startTime: number
  sha256?: string
  isElevated: boolean
  isSigned: boolean
  signer?: string
  childCount?: number
  children: ProcessNode[]
  detections?: Detection[]
  // Extended process details (PE metadata, resource usage)
  cpuUsage?: number
  memoryBytes?: number
  companyName?: string
  fileDescription?: string
  productName?: string
  fileVersion?: string
  entropy?: number
  // Lazy loading state (frontend-only, not from API)
  _loading?: boolean
  _loaded?: boolean
  _error?: string
}

export interface Detection {
  type: 'yara' | 'sigma' | 'entropy' | 'behavioral' | 'ioc' | 'honeyfile'
  ruleName: string
  confidence: number
  description: string
  mitreTactics: string[]
  mitreTechniques: string[]
}

// Evidence types for alerts
export interface Evidence {
  file_hashes?: Array<{
    sha256?: string
    sha1?: string
    md5?: string
    path?: string
  }>
  network?: Array<{
    type: string
    value: string
    direction?: string
    port?: number
    resolved_ip?: string
  }>
  process?: {
    pid: number | string
    ppid?: number | string
    name: string
    cmdline?: string
    command_line?: string
    command?: string
    user?: string
    path?: string
    sha256?: string
    is_elevated?: boolean
    is_signed?: boolean
    signer?: string
  }
  registry?: Array<{
    key: string
    value?: string
    operation?: string
  }>
  detection?: {
    rule_name?: string
    rule_type?: string
    detection_type?: string
    confidence?: number
    matched_pattern?: string
    severity?: string | number
    mitre_attack_id?: string
    mitre_tactics?: string[]
    mitre_techniques?: string[]
  }
}

export interface AlertIOC {
  type: 'ip' | 'hash' | 'domain' | 'url' | 'email' | 'file_path'
  value: string
  source?: string
  confidence?: number
  tlp?: string
  blockable?: boolean
  redacted?: boolean
}

// Process chain node for alert process ancestry
export interface ProcessChainNode {
  pid: number | string
  ppid?: number | string
  name: string
  path?: string
  cmdline?: string
  command_line?: string
  command?: string
  sha256?: string
  is_signed?: boolean
  signer?: string
  is_elevated?: boolean
  user?: string
  start_time?: string
  level: number
  is_malicious?: boolean
}

// Alert types
export interface Alert {
  id: string
  agentId: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  status: 'new' | 'open' | 'investigating' | 'resolved' | 'false_positive'
  threatScore: number
  source?: string
  mitreTactics: string[]
  mitreTechniques: string[]
  createdAt: string
  // Enhanced fields for correlation
  evidence?: Evidence
  iocs?: AlertIOC[]
  processChain?: ProcessChainNode[]
  rawEvent?: Record<string, unknown>
  detectionMetadata?: {
    rule_name?: string
    rule_type?: string
    detection_type?: string
    confidence?: number
    matched_pattern?: string
    policy_decision?: {
      action?: string
      severity?: string
      reason?: string
      policy_id?: string
      policy_name?: string
      mode?: string
      aggressiveness?: string
      threat_category?: string
      alert_threshold?: number
      block_threshold?: number
      response_intent?: string
    }
    policyDecision?: {
      action?: string
      severity?: string
      reason?: string
      policyId?: string
      policyName?: string
      mode?: string
      aggressiveness?: string
      threatCategory?: string
      alertThreshold?: number
      blockThreshold?: number
      responseIntent?: string
    }
  }
  contributingEvents?: string[]
  sourceEventId?: string
  assignedToId?: string
}

// Event types
export interface TelemetryEvent {
  eventId: string
  eventType: string
  timestamp: number
  severity: string
  payload: Record<string, unknown>
  detections: Detection[]
}

// Process tree metadata (truncation/error info from backend)
export interface TreeMeta {
  truncated: boolean
  total_processes?: number
  error?: string | null
  error_message?: string | null
}

// Process Tree page props
export interface ProcessTreePageProps {
  agents: Agent[]
  selectedAgent?: Agent
  processTree?: ProcessNode[]
  treeMeta?: TreeMeta
}

// Dashboard props
export interface DashboardProps {
  stats: {
    totalAgents: number
    onlineAgents: number
    openAlerts: number
    criticalAlerts: number
    eventsToday: number
    detectionsToday: number
  }
  recentAlerts: Alert[]
  topThreats: {
    technique: string
    name: string
    count: number
  }[]
}

// Investigation Graph types
export type GraphNodeType = 'process' | 'network' | 'file' | 'dns' | 'registry'
export type GraphSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface GraphNode {
  id: string
  type: GraphNodeType
  label: string
  pid?: number
  data: Record<string, unknown>
  severity: GraphSeverity
  highlighted?: boolean
  detections: Detection[]
}

export interface GraphEdge {
  source: string
  target: string
  type: string
  label: string
  // Network flow metadata
  bytes_sent?: number
  bytes_received?: number
  protocol?: string
  direction?: 'outbound' | 'inbound'
  timestamp?: string
  // Process context for network edges
  process_name?: string
}

export interface InvestigationGraphData {
  agent_id: string
  start_pid: number
  nodes: GraphNode[]
  edges: GraphEdge[]
  stats: {
    process_count: number
    network_count: number
    dns_count: number
    file_count: number
    registry_count: number
    total_nodes: number
    total_edges: number
  }
  time_window_minutes: number
}

export interface TimelineEntry {
  id: string
  timestamp: string
  event_type: string
  severity: string
  summary: string
  icon: string
  pid?: number
  detections: Detection[]
  payload: Record<string, unknown>
}

// ============================================================================
// Storyline Types (SentinelOne-style Attack Visualization)
// ============================================================================

export interface StorylineNode {
  id: string
  type: 'process' | 'file' | 'network' | 'dns' | 'registry' | 'user'
  label: string
  full_label?: string
  pid?: number
  timestamp?: string
  timestamp_raw?: string
  x: number
  y: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  highlighted: boolean
  suspicious: boolean
  data: Record<string, unknown>
  detections: Array<{
    ruleName: string
    description: string
    severity: string
    mitreTechniques: string[]
  }>
}

export interface StorylineEdge {
  id: string
  source: string
  target: string
  type: string
  label: string
  timestamp?: string
  animated: boolean
  color: string
}

export interface StorylineRootCause {
  node_id: string
  type: string
  entity_name: string
  process_name?: string
  cmdline?: string
  path?: string
  pid?: number
  ppid?: number
  user?: string
  timestamp?: string
  confidence_score: number
  reasoning: string
}

export interface StorylineThreatIndicator {
  type: string
  value: string
  source: string
}

export interface StorylineThreatAssessment {
  severity: string
  confidence: number
  phase: string
  indicators_count: number
  techniques_count: number
  risk_level: string
}

export interface StorylineAttackTechnique {
  id: string
  name: string
  tactic: string
  description: string
}

export interface StorylineRecommendedAction {
  priority: 'immediate' | 'high' | 'medium' | 'low'
  action: string
  reason: string
}

export interface StorylineAnalysis {
  threat_assessment: StorylineThreatAssessment
  attack_techniques: StorylineAttackTechnique[]
  recommended_actions: StorylineRecommendedAction[]
  confidence: number
  attack_narrative: string
  similar_incidents?: Array<{ id: string; title: string; similarity: number }>
}

export interface StorylineData {
  id: string
  alert_id: string | null
  agent_id: string
  title: string
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  root_cause: StorylineRootCause | null
  nodes: StorylineNode[]
  edges: StorylineEdge[]
  timeline: TimelineEntry[]
  threat_indicators: StorylineThreatIndicator[]
  mitre_techniques: string[]
  attack_phase: string
  confidence_score: number
  generated_at: string
  time_range: {
    start: string | null
    end: string | null
  }
}

export interface StorylinePageProps extends PageProps {
  page_title: string
  alert_id?: string
  agent_id?: string
  pid?: number
  storyline: StorylineData | null
  analysis: StorylineAnalysis | null
  layout: string
  error?: string
}

// Case Investigation (manual investigation cases)
export interface CaseInvestigation {
  id: string
  title: string
  description: string | null
  status: 'open' | 'in_progress' | 'closed' | 'archived'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  assignedTo: string | null
  assignedUser: {
    id: string
    name: string
    email: string
  } | null
  createdBy: string
  creator: {
    id: string
    name: string
    email: string
  } | null
  alertIds: string[]
  eventIds: string[]
  notes: string | null
  findings: string | null
  timeline: Record<string, unknown>
  tags: string[]
  mitreTactics: string[]
  mitreTechniques: string[]
  insertedAt: string
  updatedAt: string
}

// Investigation Hub page props (for case investigations listing)
export interface InvestigationHubProps extends PageProps {
  investigations: CaseInvestigation[]
  stats: {
    total: number
    by_status: Record<string, number>
    by_severity: Record<string, number>
    open: number
    in_progress: number
    closed: number
  }
  users: Array<{
    id: string
    name: string
    email: string
  }>
  filters: {
    status: string | null
    severity: string | null
    assigned_to: string | null
    search: string | null
  }
  statuses: string[]
  severities: string[]
}

// Investigation Case Detail page props
export interface InvestigationCaseDetailProps extends PageProps {
  investigation: CaseInvestigation
  linkedAlerts: Alert[]
  users: Array<{
    id: string
    name: string
    email: string
  }>
  statuses: string[]
  severities: string[]
}

// Legacy Investigation Hub props (for graph visualization - keeping for backward compatibility)
export interface InvestigationGraphHubProps extends PageProps {
  agents: Agent[]
  selectedAgentId?: string
  recentAlerts: Alert[]
  recentProcesses: {
    pid: number
    name: string
    path?: string
    cmdline?: string
  }[]
  filters: {
    timeRanges: string[]
    entityTypes: string[]
  }
}

// Investigation Graph page props
export interface InvestigationGraphPageProps extends PageProps {
  investigationType: 'alert' | 'process' | 'event' | 'error'
  investigationId: string
  alert?: Alert
  agent?: Agent
  processId?: number
  agentId?: string
  eventId?: string
  timeWindow: number
  apiEndpoint: string
  error?: string
}

// ============================================================================
// WebSocket Types
// ============================================================================

export type WebSocketConnectionState = 'disconnected' | 'connecting' | 'connected' | 'errored'

export interface LiveStats {
  totalAgents: number
  onlineAgents: number
  offlineAgents: number
  degradedAgents: number
  openAlerts: number
  criticalAlerts: number
  highAlerts: number
  eventsToday: number
  detectionsToday: number
  timestamp: number
}

export interface LiveAlert {
  id: string
  agentId: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'
  threatScore: number
  mitreTactics: string[]
  mitreTechniques: string[]
  createdAt: string
  updatedAt?: string
  acknowledgedBy?: string
  acknowledgedAt?: string
}

export interface LiveAgentStatus {
  agentId: string
  hostname: string
  status: 'online' | 'offline' | 'degraded'
  lastSeen: number
  cpuUsage?: number
  memoryUsage?: number
  eventsPerMinute?: number
}

export interface LiveEvent {
  id: string
  eventType: string
  agentId: string
  timestamp: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  summary: string
  payload: Record<string, unknown>
  detections?: Detection[]
}

// ============================================================================
// Page Props Types
// ============================================================================

// Attack Paths page
export interface AttackPath {
  id: string
  name: string
  severity: string
  likelihood: string
  impactScore: number
  steps: unknown[]
  affectedAssets: string[]
  mitigations: string[]
  entryPoints: string[]
  targetAssets: string[]
}

export interface AttackPathRecommendation {
  id: string
  priority: string
  category: string
  title: string
  description: string
  effort: string
  impact: string
  status: string
  relatedPaths: string[]
}

export interface AttackPathsPageProps extends PageProps {
  page_title: string
  paths: AttackPath[]
  criticalPaths: AttackPath[]
  recommendations: AttackPathRecommendation[]
  stats: {
    totalPaths: number
    criticalPaths: number
    pendingRecommendations: number
  }
}

// NL Hunt Session page
export interface HuntQuery {
  id: string
  originalQuery: string
  parsedQuery: string
  generatedSql: string
  executedAt: string
  resultCount: number
}

export interface HuntFinding {
  id: string
  type: string
  severity: string
  description: string
  evidence: unknown[]
  mitreTechniques: string[]
  discoveredAt: string
}

export interface HuntSession {
  id: string
  name: string
  status: string
  createdAt: string
  updatedAt: string
  queryCount: number
  findingsCount: number
}

export interface NLHuntSessionPageProps extends PageProps {
  page_title: string
  sessionId: string
  session: HuntSession | null
  queries: HuntQuery[]
  results: unknown[]
  findings: HuntFinding[]
  error?: string
}

// Workflow Detail page
export interface Workflow {
  id: string
  name: string
  description: string
  triggerType: string
  steps: unknown[]
  enabled: boolean
  createdAt: string
}

export interface WorkflowExecution {
  id: string
  workflowId: string
  triggeredBy: string
  triggerData: Record<string, unknown>
  status: string
  startedAt: string
  completedAt: string
  stepResults: unknown[]
  error?: string
  duration_ms: number
}

export interface WorkflowDetailPageProps extends PageProps {
  page_title: string
  workflowId: string
  workflow: Workflow | null
  executionHistory: WorkflowExecution[]
  availableActions: unknown[]
  error?: string
}

// Exposure Management page
export interface AttackSurfaceAsset {
  id: string
  name: string
  type: 'service' | 'endpoint' | 'cloud' | 'external'
  riskScore: number
  exposures: number
}

export interface AttackSurfaceMap {
  assets: AttackSurfaceAsset[]
  totalRiskScore: number
  exposedAssets: number
}

export interface ExposedService {
  id: string
  host: string
  port: number
  protocol: string
  service: string
  version: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  exposure: 'internet' | 'vpn' | 'internal'
  vulnerabilities: number
  lastScanned: string
  findings: string[]
}

export interface ExposureTrend {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

export interface CrownJewel {
  id: string
  name: string
  type: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  protectionStatus: 'protected' | 'partial' | 'unprotected' | 'unknown'
  lastAssessed: string
}

export interface VulnerabilityItem {
  id: string
  cve: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss: number
  affectedAssets: number
  exploitable: boolean
  patchAvailable: boolean
  firstSeen: string
  recommendation: string
}

export interface ExposureRecommendation {
  id: string
  priority: string
  title: string
  description: string
  impact: string
  effort: string
  affectedAssets: number
  status: string
}

export interface ExposureStats {
  totalExposures: number
  criticalExposures: number
  exposedServices: number
  attackSurface: number
  riskScore: number
  trend: 'up' | 'down' | 'stable'
  trendValue: number
}

export interface ExposureManagementPageProps extends PageProps {
  page_title: string
  attackSurfaceMap: AttackSurfaceMap
  prioritizedVulnerabilities: VulnerabilityItem[]
  crownJewels: CrownJewel[]
  services: ExposedService[]
  trends: ExposureTrend[]
  recommendations: ExposureRecommendation[]
  stats: ExposureStats
}

// Hyperautomation page
export interface WorkflowTemplate {
  id: string
  name: string
  description: string
}

export interface ExecutionStats {
  totalExecutions: number
  successRate: number
  avgResponseTime: number
}

export interface HyperautomationPageProps extends PageProps {
  page_title: string
  workflows: Workflow[]
  availableActions: unknown[]
  templates: WorkflowTemplate[]
  recentExecutions: WorkflowExecution[]
  executionStats: ExecutionStats
}

// ============================================================================
// Geo / Threat Map Types
// ============================================================================

export interface ThreatOrigin {
  source_lat: number
  source_lon: number
  source_country: string
  source_country_name: string
  threat_type: string
  count: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  last_seen?: string
}

export interface GeoAgentLocation {
  agent_id: string
  lat: number
  lon: number
  hostname: string
  status: 'online' | 'offline' | 'isolated'
  country_code?: string
  city?: string
  os_type?: string
  last_seen?: string
}

export interface ThreatFlow {
  id: string
  source: {
    lat: number
    lon: number
    country: string
  }
  target: {
    lat: number
    lon: number
    hostname: string
  }
  threat_type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
}

export interface ThreatMapSummary {
  top_countries: Array<{
    country_code: string
    country_name: string
    threat_count: number
    threat_types: string[]
  }>
  total_threats: number
  unique_sources: number
  unique_threat_types: number
  agents_online: number
  agents_total: number
  severity_counts: Record<string, number>
  timeframe: string
}

export interface ThreatMapData {
  threats: ThreatOrigin[]
  agents: GeoAgentLocation[]
  flows: ThreatFlow[]
  summary: ThreatMapSummary
  timestamp: string
}

// ============================================================================
// Multi-Tenancy Types
// ============================================================================

export type TenantPlan = 'trial' | 'starter' | 'professional' | 'enterprise'
export type TenantStatus = 'active' | 'suspended' | 'pending' | 'deactivated'

export interface Tenant {
  id: string
  name: string
  slug: string
  domain?: string
  status: TenantStatus
  plan: TenantPlan
  logo_url?: string
  primary_color?: string
  created_at: string
  updated_at: string
  settings?: TenantSettings
  // Usage metrics
  agent_count?: number
  user_count?: number
  event_count_30d?: number
  storage_used_mb?: number
}

export interface TenantSettings {
  // Branding
  logo_url?: string
  primary_color?: string
  secondary_color?: string
  favicon_url?: string
  custom_css?: string
  // Features
  sso_enabled: boolean
  sso_provider?: 'saml' | 'oidc' | 'azure_ad' | 'okta' | 'google'
  sso_config?: SSOConfig
  mfa_required: boolean
  // Limits
  max_agents: number
  max_users: number
  max_events_per_day: number
  retention_days: number
  // Contact
  admin_email?: string
  support_email?: string
  billing_email?: string
}

export interface SSOConfig {
  // SAML
  saml_entity_id?: string
  saml_sso_url?: string
  saml_certificate?: string
  // OIDC
  oidc_issuer?: string
  oidc_client_id?: string
  oidc_client_secret?: string
  // Azure AD / Okta specific
  azure_tenant_id?: string
  okta_domain?: string
}

export interface APIKey {
  id: string
  tenant_id: string
  name: string
  key_prefix: string
  scopes: string[]
  created_at: string
  last_used_at?: string
  expires_at?: string
  created_by: string
  is_active: boolean
}

export interface TenantUser {
  id: string
  tenant_id: string
  user_id: string
  role: 'tenant_admin' | 'analyst' | 'viewer' | 'api_only'
  user: {
    id: string
    name: string
    email: string
  }
  joined_at: string
  last_active_at?: string
  is_primary_contact: boolean
}

export interface TenantInvitation {
  id: string
  tenant_id: string
  email: string
  role: TenantUser['role']
  invited_by: string
  created_at: string
  expires_at: string
  accepted_at?: string
  status: 'pending' | 'accepted' | 'expired' | 'revoked'
}

export interface TenantUsageStats {
  tenant_id: string
  period: 'daily' | 'weekly' | 'monthly'
  agents_active: number
  agents_total: number
  events_ingested: number
  alerts_generated: number
  storage_used_mb: number
  api_calls: number
  date: string
}

export interface TenantLicense {
  tenant_id: string
  plan: TenantPlan
  status: 'active' | 'expired' | 'grace_period'
  started_at: string
  expires_at: string
  auto_renew: boolean
  limits: {
    max_agents: number
    max_users: number
    max_events_per_day: number
    retention_days: number
    features: string[]
  }
  usage: {
    agents: number
    users: number
    events_today: number
  }
}

// Page Props for tenant-related pages
export interface TenantsPageProps extends PageProps {
  tenants: Tenant[]
  stats: {
    total_tenants: number
    active_tenants: number
    trial_tenants: number
    total_agents: number
    total_users: number
  }
  filters: {
    status?: TenantStatus
    plan?: TenantPlan
    search?: string
  }
}

export interface TenantDetailPageProps extends PageProps {
  tenant: Tenant
  users: TenantUser[]
  invitations: TenantInvitation[]
  api_keys: APIKey[]
  usage_stats: TenantUsageStats[]
  license: TenantLicense
}

export interface TenantSettingsPageProps extends PageProps {
  tenant: Tenant
  settings: TenantSettings
  api_keys: APIKey[]
  license: TenantLicense
  available_sso_providers: string[]
}
