import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { router } from '@inertiajs/react'
import {
  Search,
  X,
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  FileCode,
  Activity,
  ArrowRight,
  Clock,
  Command,
  Box,
  Brain,
  ClipboardList,
  Database,
  Globe,
  Network,
  Radar,
  ShieldCheck,
  Terminal,
} from 'lucide-react'
import { cn } from '@/lib/utils'

export interface GlobalSearchProps {
  isOpen: boolean
  onClose: () => void
}

interface SearchResult {
  id: string
  type: 'agent' | 'alert' | 'event' | 'rule' | 'page'
  title: string
  subtitle?: string
  href: string
}

interface QuickAction {
  id: string
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
}

const quickActions: QuickAction[] = [
  { id: 'dashboard', name: 'Go to Dashboard', href: '/app/dashboard', icon: LayoutDashboard },
  { id: 'alerts', name: 'View Alerts', href: '/app/alerts', icon: AlertTriangle },
  { id: 'deploy', name: 'Deploy Agent', href: '/app/deploy-agent', icon: Monitor },
  { id: 'validation', name: 'Validation Center', href: '/app/validation', icon: ClipboardList },
  { id: 'proofs', name: 'Public Proofs', href: '/app/public-proofs', icon: Database },
  { id: 'rules', name: 'Detection Rules', href: '/app/detection-rules', icon: FileCode },
]

const searchablePages: QuickAction[] = [
  { id: 'dashboard', name: 'Dashboard', href: '/app/dashboard', icon: LayoutDashboard },
  { id: 'agents', name: 'Agents', href: '/app/agents', icon: Monitor },
  { id: 'deploy-agent', name: 'Deploy Agent', href: '/app/deploy-agent', icon: Monitor },
  { id: 'assets', name: 'Assets', href: '/app/assets', icon: Box },
  { id: 'alerts', name: 'Alerts', href: '/app/alerts', icon: AlertTriangle },
  { id: 'events', name: 'Events', href: '/app/events', icon: Activity },
  { id: 'live-response', name: 'Live Response', href: '/app/live-response', icon: Terminal },
  { id: 'timeline', name: 'Timeline', href: '/app/timeline', icon: Clock },
  { id: 'detection-rules', name: 'Detection Rules', href: '/app/detection-rules', icon: FileCode },
  { id: 'detection-packs', name: 'Detection Packs', href: '/app/detection-packs', icon: Box },
  { id: 'mitre', name: 'MITRE ATT&CK', href: '/app/mitre', icon: ShieldCheck },
  { id: 'threat-intel', name: 'Threat Intel', href: '/app/threat-intel', icon: Globe },
  { id: 'validation-center', name: 'Validation Center', href: '/app/validation', icon: ClipboardList },
  { id: 'benchmarks', name: 'Detection Benchmarks', href: '/app/validation/benchmark', icon: Activity },
  { id: 'nl-hunt', name: 'Natural Language Hunting', href: '/app/nl-hunt', icon: Brain },
  { id: 'ai-assistant', name: 'AI Assistant', href: '/app/ai-assistant', icon: Brain },
  { id: 'ml', name: 'ML Dashboard', href: '/app/ml', icon: Brain },
  { id: 'behavioral', name: 'Behavioral Analytics', href: '/app/behavioral', icon: Radar },
  { id: 'investigations', name: 'Investigations', href: '/app/investigations', icon: ClipboardList },
  { id: 'forensics', name: 'Forensics', href: '/app/forensics', icon: ClipboardList },
  { id: 'playbooks', name: 'Playbooks', href: '/app/playbooks', icon: ClipboardList },
  { id: 'automation', name: 'Automation', href: '/app/automation', icon: Activity },
  { id: 'network', name: 'Network', href: '/app/network', icon: Network },
  { id: 'dns', name: 'DNS Monitoring', href: '/app/dns', icon: Globe },
  { id: 'ndr', name: 'NDR', href: '/app/ndr', icon: Radar },
  { id: 'on-chain-proof', name: 'On-Chain Proof', href: '/live/on-chain-incidents', icon: Database },
  { id: 'security-status', name: 'Security Status', href: '/app/security-status', icon: ShieldCheck },
  { id: 'public-proofs', name: 'Public Proofs', href: '/app/public-proofs', icon: Database },
  { id: 'contributions', name: 'Contributions', href: '/live/contributions', icon: FileCode },
  { id: 'leaderboard', name: 'Leaderboard', href: '/live/leaderboard', icon: ClipboardList },
  { id: 'marketplace', name: 'Rule Marketplace', href: '/app/detection-packs', icon: Box },
  { id: 'reports', name: 'Reports', href: '/app/reports', icon: ClipboardList },
  { id: 'audit-log', name: 'Audit Log', href: '/app/audit-log', icon: ClipboardList },
]

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  agent: Monitor,
  alert: AlertTriangle,
  event: Activity,
  rule: FileCode,
  page: Search,
}

const typeLabels: Record<string, string> = {
  agent: 'Agents',
  alert: 'Alerts',
  event: 'Events',
  rule: 'Detection Rules',
  page: 'Pages',
}

const typeColors: Record<string, string> = {
  agent: 'var(--emerald-400)',
  alert: 'var(--crit)',
  event: 'var(--info)',
  rule: 'var(--warn)',
  page: 'var(--emerald-400)',
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

async function readJsonData(response: Response): Promise<any[]> {
  if (!response.ok) return []
  const body = await response.json()
  return Array.isArray(body?.data) ? body.data : []
}

async function searchLiveData(query: string): Promise<SearchResult[]> {
  const trimmed = query.trim()
  if (!trimmed) return []

  const staticResults: SearchResult[] = searchablePages
    .filter(page => {
      const haystack = `${page.name} ${page.id} ${page.href}`.toLowerCase()
      return haystack.includes(trimmed.toLowerCase())
    })
    .slice(0, 8)
    .map(page => ({
      id: `page-${page.id}`,
      type: 'page',
      title: page.name,
      subtitle: page.href,
      href: page.href,
    }))

  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken(),
  }

  const [agentsResult, alertsResult, eventsResult] = await Promise.allSettled([
    fetch(`/api/v1/agents?search=${encodeURIComponent(trimmed)}&limit=5`, {
      headers,
      credentials: 'include',
    }).then(readJsonData),
    fetch('/api/v1/alerts/search', {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ search: trimmed, limit: 5 }),
    }).then(readJsonData),
    fetch('/api/v1/events/search', {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ query: trimmed, limit: 5, time_range: '7d' }),
    }).then(readJsonData),
  ])

  const results: SearchResult[] = []

  if (agentsResult.status === 'fulfilled') {
    agentsResult.value.forEach((agent: any) => {
      const id = String(agent.id || agent.agent_id || '')
      if (!id) return
      results.push({
        id: `agent-${id}`,
        type: 'agent',
        title: agent.hostname || agent.name || id,
        subtitle: agent.status || agent.os || 'Agent',
        href: `/app/agents/${id}`,
      })
    })
  }

  if (alertsResult.status === 'fulfilled') {
    alertsResult.value.forEach((alert: any) => {
      const id = String(alert.id || '')
      if (!id) return
      results.push({
        id: `alert-${id}`,
        type: 'alert',
        title: alert.title || alert.description || id,
        subtitle: alert.severity || alert.status || 'Alert',
        href: `/app/alerts/${id}`,
      })
    })
  }

  if (eventsResult.status === 'fulfilled') {
    eventsResult.value.forEach((event: any) => {
      const id = String(event.id || '')
      if (!id) return
      results.push({
        id: `event-${id}`,
        type: 'event',
        title: event.description || event.event_type || event.action || id,
        subtitle: event.agent_hostname || event.event_type || 'Event',
        href: `/app/events/${id}`,
      })
    })
  }

  return [...staticResults, ...results].slice(0, 15)
}

// Recent searches stored in localStorage
const RECENT_SEARCHES_KEY = 'tamandua_recent_searches'
const MAX_RECENT_SEARCHES = 5

function getRecentSearches(): string[] {
  try {
    const stored = localStorage.getItem(RECENT_SEARCHES_KEY)
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

function addRecentSearch(query: string): void {
  try {
    const recent = getRecentSearches().filter(s => s !== query)
    recent.unshift(query)
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent.slice(0, MAX_RECENT_SEARCHES)))
  } catch {
    // Ignore storage errors
  }
}

export function GlobalSearch({ isOpen, onClose }: GlobalSearchProps) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [recentSearches, setRecentSearches] = useState<string[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const resultsRef = useRef<HTMLDivElement>(null)

  // Load recent searches on mount
  useEffect(() => {
    setRecentSearches(getRecentSearches())
  }, [])

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
      setQuery('')
      setSelectedIndex(0)
    }
  }, [isOpen])

  useEffect(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      setResults([])
      setIsSearching(false)
      setSearchError(null)
      return
    }

    const controller = new AbortController()
    const timeout = window.setTimeout(() => {
      setIsSearching(true)
      setSearchError(null)
      searchLiveData(trimmed)
        .then((liveResults) => {
          if (!controller.signal.aborted) {
            setResults(liveResults)
          }
        })
        .catch(() => {
          if (!controller.signal.aborted) {
            setResults([])
            setSearchError('Search is unavailable right now')
          }
        })
        .finally(() => {
          if (!controller.signal.aborted) {
            setIsSearching(false)
          }
        })
    }, 200)

    return () => {
      controller.abort()
      window.clearTimeout(timeout)
    }
  }, [query])

  // Search results

  // Group results by type
  const groupedResults = useMemo(() => {
    const groups: Record<string, SearchResult[]> = {}
    results.forEach(result => {
      if (!groups[result.type]) {
        groups[result.type] = []
      }
      groups[result.type].push(result)
    })
    return groups
  }, [results])

  // Flat list of all selectable items for keyboard navigation
  const selectableItems = useMemo(() => {
    if (query.trim()) {
      return results.map(r => ({ type: 'result' as const, data: r }))
    }
    // When no query, show recent searches then quick actions
    const items: Array<{ type: 'recent' | 'action'; data: string | QuickAction }> = []
    recentSearches.forEach(s => items.push({ type: 'recent', data: s }))
    quickActions.forEach(a => items.push({ type: 'action', data: a }))
    return items
  }, [query, results, recentSearches])

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setSelectedIndex(prev => Math.min(prev + 1, selectableItems.length - 1))
        break
      case 'ArrowUp':
        e.preventDefault()
        setSelectedIndex(prev => Math.max(prev - 1, 0))
        break
      case 'Enter':
        e.preventDefault()
        const item = selectableItems[selectedIndex]
        if (item) {
          if (item.type === 'result') {
            const result = item.data as SearchResult
            addRecentSearch(query)
            router.visit(result.href)
            onClose()
          } else if (item.type === 'action') {
            const action = item.data as QuickAction
            router.visit(action.href)
            onClose()
          } else if (item.type === 'recent') {
            setQuery(item.data as string)
            setSelectedIndex(0)
          }
        }
        break
      case 'Escape':
        e.preventDefault()
        onClose()
        break
    }
  }, [selectableItems, selectedIndex, query, onClose])

  // Scroll selected item into view
  useEffect(() => {
    if (resultsRef.current) {
      const selected = resultsRef.current.querySelector('[data-selected="true"]')
      if (selected) {
        selected.scrollIntoView({ block: 'nearest' })
      }
    }
  }, [selectedIndex])

  // Reset selection when query changes
  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  const handleResultClick = (result: SearchResult) => {
    addRecentSearch(query)
    router.visit(result.href)
    onClose()
  }

  const handleActionClick = (action: QuickAction) => {
    router.visit(action.href)
    onClose()
  }

  const handleRecentClick = (search: string) => {
    setQuery(search)
    setSelectedIndex(0)
  }

  if (!isOpen) return null

  // Calculate current index within flat list for selection highlighting
  let currentFlatIndex = 0

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[15vh]"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      {/* Overlay */}
      <div
        className="absolute inset-0"
        style={{ backgroundColor: 'rgba(0, 0, 0, 0.7)' }}
      />

      {/* Modal */}
      <div
        className="relative w-full max-w-[640px] mx-4 rounded-xl overflow-hidden shadow-2xl"
        style={{
          backgroundColor: 'var(--bg-2)',
          border: '1px solid var(--border)',
        }}
      >
        {/* Search Input */}
        <div
          className="flex items-center gap-3 px-4 py-4"
          style={{ borderBottom: '1px solid var(--hairline)' }}
        >
          <Search className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search agents, alerts, events, rules..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent text-base outline-none"
            style={{ color: 'var(--fg)' }}
          />
          <div
            className="flex items-center gap-1 px-2 py-1 rounded text-xs"
            style={{
              backgroundColor: 'var(--surface-2)',
              color: 'var(--muted)',
            }}
          >
            ESC
          </div>
        </div>

        {/* Content */}
        <div
          ref={resultsRef}
          className="max-h-[400px] overflow-y-auto"
          style={{ scrollbarWidth: 'thin' }}
        >
          {query.trim() ? (
            // Search results
            isSearching ? (
              <div className="py-12 text-center">
                <Search className="h-12 w-12 mx-auto mb-4 animate-pulse" style={{ color: 'var(--subtle)' }} />
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Searching live data...
                </p>
              </div>
            ) : results.length > 0 ? (
              <div className="py-2">
                {Object.entries(groupedResults).map(([type, items]) => {
                  const Icon = typeIcons[type]
                  return (
                    <div key={type}>
                      {/* Section header */}
                      <div
                        className="px-4 py-2 text-xs font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--subtle)' }}
                      >
                        {typeLabels[type]}
                      </div>
                      {/* Items */}
                      {items.map((result) => {
                        const itemIndex = currentFlatIndex++
                        const isSelected = itemIndex === selectedIndex
                        return (
                          <button
                            key={result.id}
                            data-selected={isSelected}
                            onClick={() => handleResultClick(result)}
                            className="flex items-center gap-3 w-full px-4 py-2.5 text-left transition-colors"
                            style={{
                              backgroundColor: isSelected ? 'var(--surface-2)' : 'transparent',
                            }}
                            onMouseEnter={() => setSelectedIndex(itemIndex)}
                          >
                            <div
                              className="flex items-center justify-center w-8 h-8 rounded-lg"
                              style={{
                                backgroundColor: `color-mix(in srgb, ${typeColors[type]} 15%, transparent)`,
                              }}
                            >
                              <Icon className="h-4 w-4" style={{ color: typeColors[type] }} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div
                                className="text-sm font-medium truncate"
                                style={{ color: 'var(--fg)' }}
                              >
                                {result.title}
                              </div>
                              {result.subtitle && (
                                <div
                                  className="text-xs truncate"
                                  style={{ color: 'var(--muted)' }}
                                >
                                  {result.subtitle}
                                </div>
                              )}
                            </div>
                            {isSelected && (
                              <ArrowRight className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
                            )}
                          </button>
                        )
                      })}
                    </div>
                  )
                })}
              </div>
            ) : (
              // No results
              <div className="py-12 text-center">
                <Search className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  {searchError || `No results found for "${query}"`}
                </p>
                <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                  {searchError ? 'Check your session and API availability' : 'Try adjusting your search terms'}
                </p>
              </div>
            )
          ) : (
            // Empty state: recent searches + quick actions
            <div className="py-2">
              {/* Recent Searches */}
              {recentSearches.length > 0 && (
                <>
                  <div
                    className="px-4 py-2 text-xs font-semibold uppercase tracking-wider"
                    style={{ color: 'var(--subtle)' }}
                  >
                    Recent Searches
                  </div>
                  {recentSearches.map((search, index) => {
                    const itemIndex = currentFlatIndex++
                    const isSelected = itemIndex === selectedIndex
                    return (
                      <button
                        key={`recent-${index}`}
                        data-selected={isSelected}
                        onClick={() => handleRecentClick(search)}
                        className="flex items-center gap-3 w-full px-4 py-2.5 text-left transition-colors"
                        style={{
                          backgroundColor: isSelected ? 'var(--surface-2)' : 'transparent',
                        }}
                        onMouseEnter={() => setSelectedIndex(itemIndex)}
                      >
                        <Clock className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                        <span className="flex-1 text-sm" style={{ color: 'var(--fg-2)' }}>
                          {search}
                        </span>
                        {isSelected && (
                          <ArrowRight className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                        )}
                      </button>
                    )
                  })}
                </>
              )}

              {/* Quick Actions */}
              <div
                className="px-4 py-2 text-xs font-semibold uppercase tracking-wider"
                style={{ color: 'var(--subtle)' }}
              >
                Quick Actions
              </div>
              {quickActions.map((action) => {
                const itemIndex = currentFlatIndex++
                const isSelected = itemIndex === selectedIndex
                return (
                  <button
                    key={action.id}
                    data-selected={isSelected}
                    onClick={() => handleActionClick(action)}
                    className="flex items-center gap-3 w-full px-4 py-2.5 text-left transition-colors"
                    style={{
                      backgroundColor: isSelected ? 'var(--surface-2)' : 'transparent',
                    }}
                    onMouseEnter={() => setSelectedIndex(itemIndex)}
                  >
                    <div
                      className="flex items-center justify-center w-8 h-8 rounded-lg"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <action.icon className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                    </div>
                    <span className="flex-1 text-sm font-medium" style={{ color: 'var(--fg)' }}>
                      {action.name}
                    </span>
                    {isSelected && (
                      <ArrowRight className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
                    )}
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-between px-4 py-3 text-xs"
          style={{
            borderTop: '1px solid var(--hairline)',
            backgroundColor: 'var(--surface)',
            color: 'var(--muted)',
          }}
        >
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <kbd
                className="px-1.5 py-0.5 rounded font-mono"
                style={{ backgroundColor: 'var(--surface-2)' }}
              >
                <span style={{ fontSize: '10px' }}>&#x2191;</span>
              </kbd>
              <kbd
                className="px-1.5 py-0.5 rounded font-mono"
                style={{ backgroundColor: 'var(--surface-2)' }}
              >
                <span style={{ fontSize: '10px' }}>&#x2193;</span>
              </kbd>
              <span className="ml-1">to navigate</span>
            </span>
            <span className="flex items-center gap-1">
              <kbd
                className="px-1.5 py-0.5 rounded font-mono"
                style={{ backgroundColor: 'var(--surface-2)' }}
              >
                Enter
              </kbd>
              <span className="ml-1">to select</span>
            </span>
          </div>
          <div className="flex items-center gap-1">
            <Command className="h-3 w-3" />
            <span>K to open</span>
          </div>
        </div>
      </div>
    </div>
  )
}
