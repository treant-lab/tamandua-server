import { Link, usePage, router } from '@inertiajs/react'
import {
  LayoutDashboard,
  Monitor,
  AlertTriangle,
  FileSearch,
  Settings,
  LogOut,
  ChevronDown,
  ChevronRight,
  Bell,
  Search,
  Activity,
  Terminal,
  ShieldCheck,
  Box,
  FileCode,
  ClipboardList,
  Globe,
  Building2,
  PanelLeftClose,
  PanelLeftOpen,
  Database,
  Brain,
  Target,
  Radar,
  Crosshair,
  Shield,
  Zap,
  Network,
  Bug,
  Layers,
  Award,
  Users,
  BookOpen,
  Cpu,
  Eye,
  MessageSquare,
  Workflow,
  Clock,
  Download,
  GitBranch,
} from 'lucide-react'
import { cn, safeInitial } from '@/lib/utils'
import type { SharedProps, Tenant } from '@/types'
import { useState, useCallback, useEffect, useRef, useMemo } from 'react'
import { GlobalSearch } from '@/components/GlobalSearch'

// Navigation progress bar — shows while Inertia pages are loading
function NavigationProgress() {
  const [progress, setProgress] = useState(0)
  const [visible, setVisible] = useState(false)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const start = () => {
      setProgress(0)
      setVisible(true)
      timerRef.current = setInterval(() => {
        setProgress(prev => {
          if (prev >= 90) { clearInterval(timerRef.current!); return 90 }
          return prev + (90 - prev) * 0.1
        })
      }, 80)
    }
    const finish = () => {
      if (timerRef.current) clearInterval(timerRef.current)
      setProgress(100)
      setTimeout(() => { setVisible(false); setProgress(0) }, 200)
    }
    const removeStart = router.on('start', start)
    const removeFinish = router.on('finish', finish)
    return () => { removeStart(); removeFinish() }
  }, [])

  if (!visible) return null
  return (
    <div className="fixed top-0 left-0 right-0 z-[100] h-0.5">
      <div
        className="h-full transition-all duration-200 ease-out"
        style={{
          width: `${progress}%`,
          backgroundColor: 'var(--emerald-500)',
          boxShadow: '0 0 8px var(--emerald-glow)'
        }}
      />
    </div>
  )
}
import { TenantSelector } from '@/components/TenantSelector'
import { useTenant } from '@/contexts/TenantContext'
import { Menu, MenuItem, Tooltip } from '@/components/ui/baseui'

// --- localStorage persistence helpers ---

const SIDEBAR_STATE_KEY = 'tamandua_sidebar_state'
const SIDEBAR_COLLAPSED_KEY = 'tamandua_sidebar_collapsed'

/** Safely read a JSON value from localStorage. Returns `fallback` on any error. */
function readLocalStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    if (raw === null) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

/** Safely write a JSON value to localStorage. Silently ignores errors. */
function writeLocalStorage<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Quota exceeded or other storage error -- ignore silently
  }
}

interface MainLayoutProps {
  children: React.ReactNode
  title?: string
}

interface NavItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  external?: boolean
}

interface NavGroup {
  name: string
  icon: React.ComponentType<{ className?: string }>
  items: NavItem[]
}

// Extended NavItem with optional permission requirement
interface ExtendedNavItem extends NavItem {
  requireRole?: 'admin' | 'super_admin'
}

interface ExtendedNavGroup extends Omit<NavGroup, 'items'> {
  items: ExtendedNavItem[]
  requireRole?: 'admin' | 'super_admin'
}

const navigationGroups: ExtendedNavGroup[] = [
  {
    name: 'Operations',
    icon: LayoutDashboard,
    items: [
      { name: 'Overview', href: '/app/dashboard', icon: LayoutDashboard },
      { name: 'Executive', href: '/app/executive', icon: Activity },
      { name: 'Agents', href: '/app/agents', icon: Monitor },
      { name: 'Deploy Agent', href: '/app/deploy-agent', icon: Download },
      { name: 'Assets', href: '/app/assets', icon: Box },
      { name: 'Alerts', href: '/app/alerts', icon: AlertTriangle },
      { name: 'Events', href: '/app/events', icon: Activity },
      { name: 'Timeline', href: '/app/timeline', icon: Clock },
    ],
  },
  {
    name: 'Detection',
    icon: Radar,
    items: [
      { name: 'Detection Rules', href: '/app/detection-rules', icon: Shield },
      { name: 'Detection Builder', href: '/app/detection-builder', icon: FileCode },
      { name: 'Dynamic Detection', href: '/app/dynamic-detection', icon: Zap },
      { name: 'Detection Analytics', href: '/app/detection-analytics', icon: Activity },
      { name: 'Detection Packs', href: '/app/detection-packs', icon: Layers },
      { name: 'MITRE ATT&CK', href: '/app/mitre', icon: Target },
      { name: 'Threat Intel', href: '/app/threat-intel', icon: Eye },
      { name: 'Predictive Shielding', href: '/app/predictive', icon: ShieldCheck },
      { name: 'Validation Center', href: '/app/validation', icon: ClipboardList },
      { name: 'Benchmarks', href: '/app/validation/benchmark', icon: Activity },
    ],
  },
  {
    name: 'AI & Hunting',
    icon: Brain,
    items: [
      { name: 'Hunt', href: '/app/hunt', icon: Radar },
      { name: 'NL Hunting', href: '/app/nl-hunt', icon: MessageSquare },
      { name: 'AI Assistant', href: '/app/ai-assistant', icon: Brain },
      { name: 'AI SIEM', href: '/app/ai-siem', icon: Cpu },
      { name: 'ML Dashboard', href: '/app/ml', icon: Cpu },
      { name: 'Behavioral', href: '/app/behavioral', icon: Bug },
      { name: 'Agentic Analyst', href: '/app/analyst', icon: FileSearch },
    ],
  },
  {
    name: 'Investigation',
    icon: FileSearch,
    items: [
      { name: 'Investigations', href: '/app/investigations', icon: FileSearch },
      { name: 'Process Tree', href: '/app/process-tree', icon: Network },
      { name: 'Provenance Graph', href: '/app/provenance', icon: GitBranch },
      { name: 'Forensics', href: '/app/forensics', icon: Crosshair },
    ],
  },
  {
    name: 'Response',
    icon: Terminal,
    items: [
      { name: 'Response Center', href: '/app/response', icon: ShieldCheck },
      { name: 'Live Response', href: '/app/live-response', icon: Terminal },
      { name: 'Playbooks', href: '/app/playbooks', icon: BookOpen },
      { name: 'Automation', href: '/app/automation', icon: Workflow },
      { name: 'Prevention Policies', href: '/app/prevention-policies', icon: Shield },
      { name: 'Device Control', href: '/app/device-control', icon: Box },
      { name: 'Device Policies', href: '/app/device-control/policies', icon: ClipboardList },
    ],
  },
  {
    name: 'AI Security',
    icon: Shield,
    items: [
      { name: 'Attack Surface', href: '/app/ai-security/attack-surface', icon: Target },
      { name: 'Shadow AI', href: '/app/ai-security/shadow-ai', icon: Eye },
      { name: 'AI Posture', href: '/app/ai-security/posture', icon: ShieldCheck },
      { name: 'Agent Registry', href: '/app/ai-security/agents', icon: Users },
      { name: 'AI Models', href: '/live/ai-security/models', icon: Brain, external: true },
      { name: 'ML Processes', href: '/live/ml-processes', icon: Cpu, external: true },
      { name: 'AI Runtime', href: '/live/ai/runtime', icon: Activity, external: true },
      { name: 'Model Registries', href: '/live/registries', icon: Database, external: true },
      { name: 'AI Artifacts', href: '/app/ai-security/artifacts', icon: Database },
      { name: 'Dependency Graph', href: '/app/ai-security/dependency-graph', icon: GitBranch },
      { name: 'MCP Servers', href: '/app/mcp-servers', icon: Network },
    ],
  },
  {
    name: 'Proof',
    icon: Database,
    items: [
      { name: 'On-Chain Proof', href: '/app/public-proofs', icon: Database },
      { name: 'Security Status', href: '/app/security-status', icon: ShieldCheck },
    ],
  },
  {
    name: 'Exposure',
    icon: Network,
    items: [
      { name: 'Network', href: '/app/network', icon: Network },
      { name: 'DNS', href: '/app/dns', icon: Globe },
      { name: 'NDR', href: '/app/ndr', icon: Radar },
      { name: 'Attack Surface', href: '/app/attack-surface', icon: Target },
      { name: 'Exposure Management', href: '/app/exposure', icon: Eye },
      { name: 'Attack Paths', href: '/app/exposure/attack-paths', icon: GitBranch },
      { name: 'Vulnerabilities', href: '/app/vulnerabilities', icon: AlertTriangle },
      { name: 'Identity', href: '/app/identity', icon: Users },
      { name: 'Deception', href: '/app/deception', icon: Shield },
    ],
  },
  {
    name: 'Collaboration',
    icon: Globe,
    items: [
      { name: 'Integrations', href: '/app/integrations', icon: Network },
      { name: 'Collaboration Security', href: '/app/collaboration', icon: Users },
      { name: 'Email Security', href: '/app/email-security', icon: MessageSquare },
      { name: 'Phishing Triage', href: '/app/phishing-triage', icon: FileSearch },
    ],
  },
  {
    name: 'Ecosystem',
    icon: Globe,
    items: [
      { name: 'Contributions', href: '/app/contributions', icon: FileCode },
      { name: 'Contributor Leaderboard', href: '/app/contributions#leaderboard', icon: Award },
    ],
  },
  {
    name: 'Admin',
    icon: Settings,
    items: [
      { name: 'Settings', href: '/app/settings', icon: Settings },
      { name: 'Tenant Settings', href: '/app/tenant-settings', icon: Building2 },
      { name: 'User Management', href: '/app/users', icon: Users },
      { name: 'RBAC Roles', href: '/app/settings/roles', icon: Shield },
      { name: 'Reports', href: '/app/reports', icon: ClipboardList },
      { name: 'Audit Log', href: '/app/audit-log', icon: FileSearch },
      { name: 'Tenants', href: '/app/admin/tenants', icon: Building2, requireRole: 'super_admin' },
    ],
    requireRole: 'admin',
  },
]

// Extended SharedProps with tenant information
interface ExtendedSharedProps extends SharedProps {
  current_tenant?: Tenant | null
  available_tenants?: Tenant[]
  is_super_admin?: boolean
}

export function MainLayout({ children, title }: MainLayoutProps) {
  const pageProps = usePage<ExtendedSharedProps>().props
  const { auth, flash, current_tenant, available_tenants, is_super_admin } = pageProps
  const [isSearchOpen, setIsSearchOpen] = useState(false)

  // --- Sidebar collapsed state (icon-only mode) with localStorage persistence ---
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() =>
    readLocalStorage<boolean>(SIDEBAR_COLLAPSED_KEY, false)
  )

  // --- Expanded groups state with localStorage persistence ---
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(() => {
    // Default: only the first group ("Core") is expanded, rest collapsed
    const defaults: Record<string, boolean> = {}
    navigationGroups.forEach((g, i) => { defaults[g.name] = i === 0 })
    // Merge saved state on top of defaults so new groups get a sensible default
    const saved = readLocalStorage<Record<string, boolean>>(SIDEBAR_STATE_KEY, {})
    const merged = { ...defaults, ...saved }

    // Auto-expand the group containing the current page
    const path = typeof window !== 'undefined' ? window.location.pathname : '/'
    navigationGroups.forEach(group => {
      if (group.items.some(item =>
        path === item.href || (item.href !== '/app/dashboard' && path.startsWith(item.href))
      )) {
        merged[group.name] = true
      }
    })

    return merged
  })
  const user = auth?.user
  const userRole = user?.role

  // Try to use tenant context, but gracefully handle if not available
  let tenantContext: { currentTenant: Tenant | null; availableTenants: Tenant[]; isMultiTenant: boolean } | null = null
  try {
    tenantContext = useTenant()
  } catch {
    // TenantProvider not available, use props instead
  }

  // Use context values if available, otherwise fall back to page props
  const currentTenant = tenantContext?.currentTenant ?? current_tenant ?? null
  const tenantList = tenantContext?.availableTenants ?? available_tenants ?? []
  const isMultiTenant = tenantContext?.isMultiTenant ?? (tenantList.length > 1)

  // Determine if user can see admin sections
  const isSuperAdmin = Boolean(is_super_admin || userRole === 'super_admin')
  const isAdmin = userRole === 'admin' || isSuperAdmin

  // Filter navigation based on user role
  const filteredNavigationGroups = navigationGroups.filter(group => {
    if (group.requireRole === 'super_admin' && !isSuperAdmin) return false
    if (group.requireRole === 'admin' && !isAdmin) return false
    return true
  }).map(group => ({
    ...group,
    items: group.items.filter(item => {
      if (item.requireRole === 'super_admin' && !isSuperAdmin) return false
      if (item.requireRole === 'admin' && !isAdmin) return false
      return true
    })
  })).filter(group => group.items.length > 0)

  // Use Inertia's page URL for reactive path tracking
  const { url: inertiaUrl } = usePage()
  const currentPath = (inertiaUrl?.split('?')[0] || (typeof window !== 'undefined' ? window.location.pathname : '/')).split('#')[0]
  const visibleNavigationHrefs = useMemo(
    () => filteredNavigationGroups.flatMap(group => group.items.map(item => item.href.split('?')[0].split('#')[0])),
    [filteredNavigationGroups]
  )

  const isNavigationHrefActive = useCallback((href: string) => {
    const normalizedHref = href.split('?')[0].split('#')[0]
    if (currentPath === normalizedHref) return true
    if (normalizedHref === '/app/dashboard' || !currentPath.startsWith(`${normalizedHref}/`)) return false

    return !visibleNavigationHrefs.some(otherHref =>
      otherHref !== normalizedHref &&
      otherHref.startsWith(`${normalizedHref}/`) &&
      (currentPath === otherHref || currentPath.startsWith(`${otherHref}/`))
    )
  }, [currentPath, visibleNavigationHrefs])

  // Auto-expand group containing the active page on navigation
  const prevPathRef = useRef(currentPath)
  useEffect(() => {
    if (prevPathRef.current === currentPath) return
    prevPathRef.current = currentPath

    setExpandedGroups(prev => {
      let changed = false
      const next = { ...prev }
      navigationGroups.forEach(group => {
        const isActive = group.items.some(item => isNavigationHrefActive(item.href))
        if (isActive && !next[group.name]) {
          next[group.name] = true
          changed = true
        }
      })
      if (changed) {
        writeLocalStorage(SIDEBAR_STATE_KEY, next)
        return next
      }
      return prev
    })
  }, [currentPath, isNavigationHrefActive])

  const handleLogout = () => {
    router.delete('/logout')
  }

  // Global search keyboard shortcut (Cmd+K / Ctrl+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setIsSearchOpen(prev => !prev)
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Persist expanded groups to localStorage whenever they change
  const toggleGroup = useCallback((groupName: string) => {
    setExpandedGroups(prev => {
      const next = { ...prev, [groupName]: !prev[groupName] }
      writeLocalStorage(SIDEBAR_STATE_KEY, next)
      return next
    })
  }, [])

  // Persist sidebar collapsed state to localStorage whenever it changes
  const toggleSidebarCollapsed = useCallback(() => {
    setSidebarCollapsed(prev => {
      const next = !prev
      writeLocalStorage(SIDEBAR_COLLAPSED_KEY, next)
      return next
    })
  }, [])

  const isItemActive = (href: string) => {
    return isNavigationHrefActive(href)
  }

  const isGroupActive = (group: NavGroup) => {
    return group.items.some(item => isItemActive(item.href))
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg)' }}>
      <NavigationProgress />
      {/* Sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex flex-col transition-all duration-200',
          sidebarCollapsed ? 'w-16' : 'w-64'
        )}
        style={{
          backgroundColor: 'var(--bg-2)',
          borderRight: '1px solid var(--hairline)'
        }}
      >
        {/* Logo / Lockup */}
        <div
          className={cn(
            'lockup flex h-16 items-center flex-shrink-0',
            sidebarCollapsed ? 'justify-center px-2' : 'gap-3 px-6'
          )}
          style={{ borderBottom: '1px solid var(--hairline)' }}
        >
          <img
            src={sidebarCollapsed ? '/images/logo-icon.png' : '/images/logo.png'}
            alt="Tamandua"
            className={sidebarCollapsed ? 'h-8 w-8' : 'h-6'}
            style={{ objectFit: 'contain' }}
          />
          {!sidebarCollapsed && (
            <span
              className="text-xs font-medium px-2 py-0.5 rounded"
              style={{
                fontFamily: 'var(--mono)',
                color: 'var(--emerald-400)',
                border: '1px solid var(--emerald-700)',
                letterSpacing: '0.06em'
              }}
            >
              SENTINEL
            </span>
          )}
        </div>

        {/* Search */}
        <div className={cn('flex-shrink-0', sidebarCollapsed ? 'p-2' : 'p-4')}>
          {sidebarCollapsed ? (
            <Tooltip content="Search (Ctrl+K)" side="right">
              <button
                onClick={() => setIsSearchOpen(true)}
                className="w-full flex items-center justify-center p-2 rounded-lg transition-colors"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--fg)'
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--muted)'
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
                aria-label="Search (Ctrl+K)"
              >
                <Search className="h-4 w-4" />
              </button>
            </Tooltip>
          ) : (
            <button
              onClick={() => setIsSearchOpen(true)}
              className="relative w-full text-left"
            >
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--subtle)' }} />
              <div
                className="input-sentinel w-full pl-10 pr-4 cursor-pointer"
                style={{ color: 'var(--muted)' }}
              >
                Search... <span className="text-xs opacity-70">Ctrl+K</span>
              </div>
            </button>
          )}
        </div>

        {/* Navigation */}
        <nav className={cn('flex-1 overflow-y-auto pb-4', sidebarCollapsed ? 'px-2' : 'px-4')} style={{ scrollbarWidth: 'none' }}>
          <div className="space-y-2">
            {filteredNavigationGroups.map((group) => {
              const isExpanded = expandedGroups[group.name]
              const isActive = isGroupActive(group as NavGroup)

              // Collapsed sidebar: show only the group icon as a link to its first item
              if (sidebarCollapsed) {
                const firstItem = group.items[0]
                const groupIconClassName = "flex items-center justify-center w-full rounded-lg p-2 transition-colors"
                const groupIconStyle = { color: isActive ? 'var(--emerald-400)' : 'var(--subtle)' }
                const groupIconHoverHandlers = {
                  onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                      e.currentTarget.style.color = 'var(--fg)'
                    }
                  },
                  onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = 'transparent'
                      e.currentTarget.style.color = 'var(--subtle)'
                    }
                  },
                }

                return (
                  <div key={group.name} className="space-y-1">
                    <Tooltip content={`${group.name}: ${firstItem.name}`} side="right">
                      {firstItem.external ? (
                        <a
                          href={firstItem.href}
                          aria-label={`${group.name}: ${firstItem.name}`}
                          className={groupIconClassName}
                          style={groupIconStyle}
                          {...groupIconHoverHandlers}
                        >
                          <group.icon className="h-4 w-4" />
                        </a>
                      ) : (
                        <Link
                          href={firstItem.href}
                          aria-label={`${group.name}: ${firstItem.name}`}
                          prefetch="hover"
                          className={groupIconClassName}
                          style={groupIconStyle}
                          {...groupIconHoverHandlers}
                        >
                          <group.icon className="h-4 w-4" />
                        </Link>
                      )}
                    </Tooltip>
                    {group.items.slice(1).map((item) => {
                      const isItemActiveState = isItemActive(item.href)
                      const linkClassName = "nav-link flex items-center justify-center rounded-lg p-2 transition-colors"
                      const linkStyle = {
                        backgroundColor: isItemActiveState ? 'var(--emerald-500)' : 'transparent',
                        color: isItemActiveState ? 'white' : 'var(--fg-2)'
                      }
                      const hoverHandlers = {
                        onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
                          if (!isItemActiveState) {
                            e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                            e.currentTarget.style.color = 'var(--fg)'
                          }
                        },
                        onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
                          if (!isItemActiveState) {
                            e.currentTarget.style.backgroundColor = 'transparent'
                            e.currentTarget.style.color = 'var(--fg-2)'
                          }
                        },
                      }

                      if (item.external) {
                        return (
                          <Tooltip key={item.name} content={item.name} side="right">
                            <a
                              href={item.href}
                              aria-label={item.name}
                              className={linkClassName}
                              style={linkStyle}
                              {...hoverHandlers}
                            >
                              <item.icon className="h-4 w-4" />
                            </a>
                          </Tooltip>
                        )
                      }

                      return (
                        <Tooltip key={item.name} content={item.name} side="right">
                          <Link
                            href={item.href}
                            aria-label={item.name}
                            prefetch="hover"
                            className={linkClassName}
                            style={linkStyle}
                            {...hoverHandlers}
                          >
                            <item.icon className="h-4 w-4" />
                          </Link>
                        </Tooltip>
                      )
                    })}
                  </div>
                )
              }

              // Expanded sidebar: full group with toggle
              return (
                <div key={group.name}>
                  <button
                    onClick={() => toggleGroup(group.name)}
                    className="flex items-center gap-2 w-full rounded-lg px-3 py-2 text-xs font-semibold uppercase tracking-wider transition-colors"
                    style={{ color: isActive ? 'var(--emerald-400)' : 'var(--subtle)' }}
                    onMouseEnter={(e) => {
                      if (!isActive) e.currentTarget.style.color = 'var(--fg-2)'
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) e.currentTarget.style.color = 'var(--subtle)'
                    }}
                  >
                    <group.icon className="h-4 w-4" />
                    <span className="flex-1 text-left">{group.name}</span>
                    {isExpanded ? (
                      <ChevronDown className="h-3 w-3" />
                    ) : (
                      <ChevronRight className="h-3 w-3" />
                    )}
                  </button>

                  {isExpanded && (
                    <div className="mt-1 ml-4 space-y-1">
                      {group.items.map((item) => {
                        const isItemActiveState = isItemActive(item.href)
                        const linkClassName = "nav-link flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors"
                        const linkStyle = {
                          backgroundColor: isItemActiveState ? 'var(--emerald-500)' : 'transparent',
                          color: isItemActiveState ? 'white' : 'var(--fg-2)'
                        }
                        const hoverHandlers = {
                          onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
                            if (!isItemActiveState) {
                              e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                              e.currentTarget.style.color = 'var(--fg)'
                            }
                          },
                          onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
                            if (!isItemActiveState) {
                              e.currentTarget.style.backgroundColor = 'transparent'
                              e.currentTarget.style.color = 'var(--fg-2)'
                            }
                          },
                        }

                        if (item.external) {
                          return (
                            <a
                              key={item.name}
                              href={item.href}
                              className={linkClassName}
                              style={linkStyle}
                              {...hoverHandlers}
                            >
                              <item.icon className="h-4 w-4" />
                              {item.name}
                            </a>
                          )
                        }

                        return (
                          <Link
                            key={item.name}
                            href={item.href}
                            prefetch="hover"
                            className={linkClassName}
                            style={linkStyle}
                            {...hoverHandlers}
                          >
                            <item.icon className="h-4 w-4" />
                            {item.name}
                          </Link>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </nav>

        {/* Sidebar collapse toggle */}
        <div
          className={cn('flex-shrink-0', sidebarCollapsed ? 'p-2' : 'px-4 py-2')}
          style={{ borderTop: '1px solid var(--hairline)' }}
        >
          <Tooltip content={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} side={sidebarCollapsed ? 'right' : 'top'}>
          <button
            onClick={toggleSidebarCollapsed}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className={cn(
              'flex items-center gap-2 w-full rounded-lg p-2 text-sm transition-colors',
              sidebarCollapsed ? 'justify-center' : ''
            )}
            style={{ color: 'var(--muted)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = 'var(--fg)'
              e.currentTarget.style.backgroundColor = 'var(--surface-2)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = 'var(--muted)'
              e.currentTarget.style.backgroundColor = 'transparent'
            }}
          >
            {sidebarCollapsed ? (
              <PanelLeftOpen className="h-4 w-4" />
            ) : (
              <>
                <PanelLeftClose className="h-4 w-4" />
                <span>Collapse</span>
              </>
            )}
          </button>
          </Tooltip>
        </div>

        {/* User Section */}
        {user && (
          <div
            className={cn('flex-shrink-0', sidebarCollapsed ? 'p-2' : 'p-4')}
            style={{ borderTop: '1px solid var(--hairline)' }}
          >
            <Menu
              side={sidebarCollapsed ? 'right' : 'top'}
              align={sidebarCollapsed ? 'start' : 'center'}
              className={sidebarCollapsed ? 'w-48' : 'w-56'}
              trigger={
              <button
                type="button"
                className={cn(
                  'flex items-center w-full rounded-lg p-2 transition-colors',
                  sidebarCollapsed ? 'justify-center' : 'gap-3'
                )}
                style={{ backgroundColor: 'transparent' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
                title={sidebarCollapsed ? user.name : undefined}
              >
                <div
                  className={cn(
                    'rounded-full flex items-center justify-center flex-shrink-0',
                    sidebarCollapsed ? 'h-8 w-8' : 'h-9 w-9'
                  )}
                  style={{ backgroundColor: 'var(--emerald-500)' }}
                >
                  <span className="text-white font-medium text-sm">
                    {safeInitial(user.name)}
                  </span>
                </div>
                {!sidebarCollapsed && (
                  <>
                    <div className="flex-1 min-w-0 text-left">
                      <p className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{user.name}</p>
                      <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>{user.role}</p>
                    </div>
                    <ChevronDown
                      className="h-4 w-4"
                      style={{ color: 'var(--muted)' }}
                    />
                  </>
                )}
              </button>
              }
            >
              <MenuItem onSelect={() => router.visit('/app/settings')}>
                <>
                  <Settings className="h-4 w-4" />
                  Settings
                </>
              </MenuItem>
              <MenuItem onSelect={handleLogout} tone="danger">
                <>
                  <LogOut className="h-4 w-4" />
                  Logout
                </>
              </MenuItem>
            </Menu>
          </div>
        )}
      </aside>

      {/* Main content */}
      <div className={cn('transition-all duration-200', sidebarCollapsed ? 'pl-16' : 'pl-64')}>
        {/* Top bar */}
        <header
          className="topbar sticky top-0 z-40 flex h-16 items-center gap-4 px-8"
          style={{
            backgroundColor: 'var(--surface)',
            borderBottom: '1px solid var(--hairline)'
          }}
        >
          {/* Tenant branding / current tenant indicator */}
          {currentTenant && !isMultiTenant && (
            <div className="flex items-center gap-2">
              {currentTenant.logo_url ? (
                <img
                  src={currentTenant.logo_url}
                  alt={currentTenant.name}
                  className="h-7 w-7 rounded object-contain bg-white"
                />
              ) : (
                <div
                  className="h-7 w-7 rounded flex items-center justify-center text-white text-xs font-semibold"
                  style={{ backgroundColor: currentTenant.primary_color || 'var(--emerald-500)' }}
                >
                  {safeInitial(currentTenant.name)}
                </div>
              )}
              <span className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>{currentTenant.name}</span>
            </div>
          )}

          {/* Tenant Selector for multi-tenant users */}
          {isMultiTenant && <TenantSelector />}

          {title && (
            <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{title}</h1>
          )}
          <div className="flex-1" />

          {/* Tenant Settings Link (for tenant admins) */}
          {currentTenant && isAdmin && (
            <Tooltip content="Tenant Settings">
              <Link
                href="/app/tenant-settings"
                className="p-2 rounded-lg"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--fg)'
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--muted)'
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
                aria-label="Tenant Settings"
              >
                <Building2 className="h-5 w-5" />
              </Link>
            </Tooltip>
          )}

          {/* Devnet Badge */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
            style={{
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid var(--emerald-600)',
              color: 'var(--emerald-400)'
            }}
          >
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: 'var(--emerald-500)' }}
            />
            Devnet
          </div>

          {/* Notifications */}
          <button
            type="button"
            onClick={() => router.visit('/app/alerts')}
            aria-label="Open alerts"
            title="Open alerts"
            className="relative p-2 rounded-lg"
            style={{ color: 'var(--muted)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = 'var(--fg)'
              e.currentTarget.style.backgroundColor = 'var(--surface-2)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = 'var(--muted)'
              e.currentTarget.style.backgroundColor = 'transparent'
            }}
          >
            <Bell className="h-5 w-5" />
            <span
              className="absolute top-1 right-1 h-2 w-2 rounded-full"
              style={{ backgroundColor: 'var(--crit)' }}
            />
          </button>
        </header>

        {/* Flash Messages */}
        {flash?.success && (
          <div
            className="mx-8 mt-4 p-4 rounded-lg text-sm"
            style={{
              backgroundColor: 'var(--emerald-glow)',
              border: '1px solid var(--emerald-600)',
              color: 'var(--emerald-400)'
            }}
          >
            {flash.success}
          </div>
        )}
        {flash?.error && (
          <div
            className="mx-8 mt-4 p-4 rounded-lg text-sm"
            style={{
              backgroundColor: 'var(--crit-bg)',
              border: '1px solid var(--crit)',
              color: 'var(--crit)'
            }}
          >
            {flash.error}
          </div>
        )}

        {/* Page content */}
        <main className="p-8">
          {children}
        </main>
      </div>

      {/* Global Search Modal */}
      <GlobalSearch isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </div>
  )
}
