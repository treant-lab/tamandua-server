import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Box,
  Brain,
  Building2,
  Bug,
  ClipboardList,
  Clock,
  Cpu,
  Crosshair,
  Database,
  Download,
  Eye,
  FileCode,
  FileSearch,
  GitBranch,
  Globe,
  Key,
  LayoutDashboard,
  Lock,
  MessageSquare,
  Monitor,
  Network,
  Radar,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  Users,
  Workflow,
} from 'lucide-react'

export type NavigationRole = 'admin' | 'super_admin'

export interface NavigationItem {
  id: string
  name: string
  href: string
  icon: LucideIcon
  description: string
  keywords?: string[]
  external?: boolean
  requireRole?: NavigationRole
  searchOnly?: boolean
}

export interface NavigationGroup {
  id: string
  name: string
  icon: LucideIcon
  items: NavigationItem[]
  requireRole?: NavigationRole
}

export interface NavigationSearchResult extends NavigationItem {
  groupId: string
  groupName: string
  score: number
}

// One catalog drives both the side navigation and the feature finder. Keywords
// intentionally include operator language in English and Portuguese.
export const NAVIGATION_GROUPS: NavigationGroup[] = [
  {
    id: 'monitor',
    name: 'Monitor',
    icon: LayoutDashboard,
    items: [
      { id: 'dashboard', name: 'Overview', href: '/app/dashboard', icon: LayoutDashboard, description: 'SOC posture, activity and operational summary', keywords: ['dashboard', 'home', 'resumo', 'postura'] },
      { id: 'health-hub', name: 'Health Hub', href: '/app/health-hub', icon: Activity, description: 'Platform, ingestion and endpoint health', keywords: ['status', 'saude', 'ingestion', 'pipeline'] },
      { id: 'alerts', name: 'Alerts', href: '/app/alerts', icon: AlertTriangle, description: 'Triage detections and security findings', keywords: ['alertas', 'detections', 'findings', 'triage'] },
      { id: 'events', name: 'Events', href: '/app/events', icon: Activity, description: 'Explore endpoint and security telemetry', keywords: ['eventos', 'telemetry', 'logs'] },
      { id: 'timeline', name: 'Timeline', href: '/app/timeline', icon: Clock, description: 'Review activity in chronological order', keywords: ['tempo', 'history', 'historico'] },
      { id: 'agents', name: 'Agents', href: '/app/agents', icon: Monitor, description: 'Manage enrolled endpoint sensors', keywords: ['endpoints', 'hosts', 'maquinas', 'sensores'] },
      { id: 'assets', name: 'Assets', href: '/app/assets', icon: Box, description: 'Inventory devices and observed assets', keywords: ['inventario', 'devices', 'hosts'] },
    ],
  },
  {
    id: 'detect',
    name: 'Detect',
    icon: Radar,
    items: [
      { id: 'detection-rules', name: 'Detection Rules', href: '/app/detection-rules', icon: Shield, description: 'Manage detection content and rule lifecycle', keywords: ['regras', 'sigma', 'yara', 'detections'] },
      { id: 'detection-builder', name: 'Detection Builder', href: '/app/detection-builder', icon: FileCode, description: 'Create and test detection logic', keywords: ['criar regra', 'rule editor', 'authoring'] },
      { id: 'mitre', name: 'MITRE ATT&CK', href: '/app/mitre', icon: Target, description: 'Map coverage to tactics and techniques', keywords: ['tactics', 'techniques', 'cobertura', 'attack'] },
      { id: 'threat-intel', name: 'Threat Intel', href: '/app/threat-intel', icon: Eye, description: 'Investigate indicators and intelligence', keywords: ['ioc', 'indicator', 'hash', 'ip', 'domain'] },
      { id: 'emerging-threats', name: 'Emerging Threats', href: '/app/emerging-threats', icon: Sparkles, description: 'Track newly observed threats and campaigns', keywords: ['novas ameacas', 'campaigns', 'recent'] },
      { id: 'behavioral', name: 'Behavioral Analytics', href: '/app/behavioral', icon: Bug, description: 'Find anomalous endpoint behavior', keywords: ['anomalia', 'ueba', 'behavior', 'comportamento'] },
      { id: 'agent-ml-detections', name: 'Agent ML Detections', href: '/app/ml/detections', icon: Cpu, description: 'Review machine-learning detections from agents', keywords: ['modelo', 'machine learning', 'malware smell'] },
    ],
  },
  {
    id: 'investigate',
    name: 'Investigate',
    icon: FileSearch,
    items: [
      { id: 'investigations', name: 'Investigations', href: '/app/investigations', icon: FileSearch, description: 'Build cases from related evidence', keywords: ['casos', 'case management', 'incident'] },
      { id: 'nl-hunt', name: 'NL Hunting', href: '/app/nl-hunt', icon: MessageSquare, description: 'Hunt telemetry using natural language', keywords: ['hunt', 'hunting', 'buscar eventos', 'query'] },
      { id: 'provenance', name: 'Provenance Graph', href: '/app/provenance', icon: GitBranch, description: 'Trace process, file and network relationships', keywords: ['grafo', 'process tree', 'storyline', 'relations'] },
      { id: 'forensics', name: 'Forensics', href: '/app/forensics', icon: Crosshair, description: 'Analyze collected forensic artifacts', keywords: ['artefatos', 'memory', 'memoria', 'disk'] },
      { id: 'ai-assistant', name: 'AI Assistant', href: '/app/ai-assistant', icon: Brain, description: 'Investigate evidence with an AI copilot', keywords: ['analyst', 'assistente', 'copilot', 'explain'] },
      { id: 'ml', name: 'ML Dashboard', href: '/app/ml', icon: Cpu, description: 'Inspect model health and ML operations', keywords: ['machine learning', 'modelo', 'training', 'treino'] },
    ],
  },
  {
    id: 'respond',
    name: 'Respond',
    icon: Terminal,
    items: [
      { id: 'response', name: 'Response Center', href: '/app/response', icon: ShieldCheck, description: 'Coordinate containment and remediation', keywords: ['resposta', 'containment', 'remediation'] },
      { id: 'live-response', name: 'Live Response', href: '/app/live-response', icon: Terminal, description: 'Open an interactive endpoint session', keywords: ['terminal', 'shell', 'sessao remota'] },
      { id: 'fleet-queries', name: 'Fleet Queries', href: '/app/fleet-queries', icon: Database, description: 'Query endpoint state across the fleet', keywords: ['osquery', 'consulta', 'fleet', 'query hosts'] },
      { id: 'playbooks', name: 'Playbooks', href: '/app/playbooks', icon: BookOpen, description: 'Run repeatable response workflows', keywords: ['workflow', 'runbook', 'soar'] },
      { id: 'automation', name: 'Automation', href: '/app/automation', icon: Workflow, description: 'Automate security operations', keywords: ['soar', 'workflow', 'acoes'] },
      { id: 'prevention-policies', name: 'Prevention Policies', href: '/app/prevention-policies', icon: Shield, description: 'Configure endpoint prevention controls', keywords: ['bloquear', 'block', 'policy', 'politicas'] },
      { id: 'device-control', name: 'Device Control', href: '/app/device-control', icon: Box, description: 'Control removable and peripheral devices', keywords: ['usb', 'perifericos', 'removable'] },
      { id: 'device-policies', name: 'Device Policies', href: '/app/device-control/policies', icon: ClipboardList, description: 'Manage device-control policy sets', keywords: ['usb policy', 'politicas de dispositivo'] },
    ],
  },
  {
    id: 'exposure',
    name: 'Assets & Exposure',
    icon: Network,
    items: [
      { id: 'network', name: 'Network', href: '/app/network', icon: Network, description: 'Explore network activity and connections', keywords: ['rede', 'connections', 'traffic'] },
      { id: 'dns', name: 'DNS', href: '/app/dns', icon: Globe, description: 'Analyze DNS activity and resolutions', keywords: ['dominio', 'domain', 'resolver', 'doh', 'dot'] },
      { id: 'ndr', name: 'NDR', href: '/app/ndr', icon: Radar, description: 'Detect and investigate network threats', keywords: ['network detection', 'tls', 'ja3', 'certificate'] },
      { id: 'browser-guard', name: 'Browser Guard', href: '/app/browser-guard', icon: ShieldCheck, description: 'Monitor browser and web protections', keywords: ['navegador', 'web', 'extension'] },
      { id: 'vulnerabilities', name: 'Vulnerabilities', href: '/app/vulnerabilities', icon: AlertTriangle, description: 'Prioritize vulnerable assets and software', keywords: ['cve', 'exposure', 'vulnerabilidades'] },
      { id: 'dns-doh-dot', name: 'DoH / DoT DNS', href: '/app/dns?query_type=DOH', icon: Globe, description: 'Inspect encrypted DNS activity', keywords: ['dns over https', 'dns over tls'], searchOnly: true },
      { id: 'ndr-tls-sessions', name: 'TLS Sessions', href: '/app/ndr?tab=encrypted&section=tls', icon: Lock, description: 'Inspect encrypted network sessions', keywords: ['ssl', 'encrypted traffic'], searchOnly: true },
      { id: 'ndr-ja3', name: 'JA3 Fingerprints', href: '/app/ndr?tab=encrypted&section=ja3', icon: Key, description: 'Search TLS client fingerprints', keywords: ['fingerprint', 'malware tls'], searchOnly: true },
      { id: 'ndr-certificates', name: 'Certificate Analysis', href: '/app/ndr?tab=encrypted&section=certificates', icon: ShieldCheck, description: 'Inspect certificates observed on the network', keywords: ['x509', 'cert', 'tls'], searchOnly: true },
      { id: 'ndr-anomalies', name: 'NDR Anomalies', href: '/app/ndr?tab=anomalies', icon: AlertTriangle, description: 'Review anomalous network behavior', keywords: ['anomalia de rede', 'network anomaly'], searchOnly: true },
    ],
  },
  {
    id: 'platform',
    name: 'Platform',
    icon: Globe,
    items: [
      { id: 'deploy-agent', name: 'Deploy Agent', href: '/app/deploy-agent', icon: Download, description: 'Install and enroll endpoint agents', keywords: ['instalar', 'enroll', 'sensor'] },
      { id: 'integrations', name: 'Integrations', href: '/app/integrations', icon: Network, description: 'Connect external security systems', keywords: ['connector', 'webhook', 'api'] },
      { id: 'mcp-servers', name: 'MCP Servers', href: '/app/mcp-servers', icon: Key, description: 'Manage Model Context Protocol servers', keywords: ['tools', 'connector', 'ai'] },
    ],
  },
  {
    id: 'admin',
    name: 'Administration',
    icon: Settings,
    requireRole: 'admin',
    items: [
      { id: 'settings', name: 'Settings', href: '/app/settings', icon: Settings, description: 'Configure the Tamandua platform', keywords: ['configuracoes'], requireRole: 'admin' },
      { id: 'tenant-settings', name: 'Tenant Settings', href: '/app/tenant-settings', icon: Building2, description: 'Configure the current tenant', keywords: ['organizacao', 'workspace'], requireRole: 'admin' },
      { id: 'users', name: 'User Management', href: '/app/users', icon: Users, description: 'Manage platform users', keywords: ['usuarios', 'accounts'], requireRole: 'admin' },
      { id: 'roles', name: 'RBAC Roles', href: '/app/settings/roles', icon: Shield, description: 'Manage roles and permissions', keywords: ['permissoes', 'access control'], requireRole: 'admin' },
      { id: 'reports', name: 'Reports', href: '/app/reports', icon: ClipboardList, description: 'Create and review security reports', keywords: ['relatorios', 'export'], requireRole: 'admin' },
      { id: 'audit-log', name: 'Audit Log', href: '/app/audit-log', icon: FileSearch, description: 'Review administrative activity', keywords: ['auditoria', 'admin events'], requireRole: 'admin' },
      { id: 'tenants', name: 'Tenants', href: '/app/admin/tenants', icon: Building2, description: 'Manage all platform tenants', keywords: ['organizations', 'multi tenant'], requireRole: 'super_admin' },
    ],
  },
]

function hasRoleAccess(requiredRole: NavigationRole | undefined, userRole?: string, isSuperAdminProp?: boolean): boolean {
  const isSuperAdmin = Boolean(isSuperAdminProp || userRole === 'super_admin')
  if (requiredRole === 'super_admin') return isSuperAdmin
  if (requiredRole === 'admin') return userRole === 'admin' || isSuperAdmin
  return true
}

export function getVisibleNavigationGroups(userRole?: string, isSuperAdmin?: boolean, includeSearchOnly = false): NavigationGroup[] {
  return NAVIGATION_GROUPS
    .filter(group => hasRoleAccess(group.requireRole, userRole, isSuperAdmin))
    .map(group => ({
      ...group,
      items: group.items.filter(item =>
        hasRoleAccess(item.requireRole, userRole, isSuperAdmin) && (includeSearchOnly || !item.searchOnly)
      ),
    }))
    .filter(group => group.items.length > 0)
}

export function normalizeNavigationText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
}

export function searchNavigation(query: string, groups: NavigationGroup[], limit = 12): NavigationSearchResult[] {
  const normalizedQuery = normalizeNavigationText(query)
  if (!normalizedQuery) return []
  const tokens = normalizedQuery.split(/\s+/).filter(Boolean)

  return groups
    .flatMap(group => group.items.map(item => {
      const name = normalizeNavigationText(item.name)
      const description = normalizeNavigationText(item.description)
      const keywords = (item.keywords ?? []).map(normalizeNavigationText)
      const href = normalizeNavigationText(item.href)
      const groupName = normalizeNavigationText(group.name)
      const searchableFields = [name, description, href, groupName, ...keywords]

      if (!tokens.every(token => searchableFields.some(field => field.includes(token)))) return null

      let score = 0
      if (name === normalizedQuery) score += 120
      if (name.startsWith(normalizedQuery)) score += 70
      else if (name.includes(normalizedQuery)) score += 45
      for (const token of tokens) {
        if (name.startsWith(token)) score += 18
        else if (name.includes(token)) score += 12
        if (keywords.some(keyword => keyword === token)) score += 16
        else if (keywords.some(keyword => keyword.includes(token))) score += 8
        if (description.includes(token)) score += 4
        if (groupName.includes(token)) score += 3
      }

      return { ...item, groupId: group.id, groupName: group.name, score }
    }))
    .filter((item): item is NavigationSearchResult => item !== null)
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
    .slice(0, limit)
}

export function filterNavigationGroups(groups: NavigationGroup[], query: string): NavigationGroup[] {
  if (!normalizeNavigationText(query)) return groups
  const matches = new Set(searchNavigation(query, groups, Number.MAX_SAFE_INTEGER).map(item => item.id))
  return groups
    .map(group => ({ ...group, items: group.items.filter(item => matches.has(item.id)) }))
    .filter(group => group.items.length > 0)
}
