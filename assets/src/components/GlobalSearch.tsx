import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { router, usePage } from '@inertiajs/react'
import {
  Search,
  AlertTriangle,
  Monitor,
  FileCode,
  Activity,
  ArrowRight,
  Clock,
  Command,
  type LucideIcon,
} from 'lucide-react'
import type { SharedProps } from '@/types'
import {
  getVisibleNavigationGroups,
  searchNavigation,
  type NavigationGroup,
  type NavigationItem,
} from '@/navigation/catalog'

export interface GlobalSearchProps {
  isOpen: boolean
  onClose: () => void
}

interface SearchResult {
  id: string
  type: 'agent' | 'alert' | 'event' | 'rule' | 'feature'
  title: string
  subtitle?: string
  href: string
  external?: boolean
  icon?: LucideIcon
}

type QuickAction = NavigationItem

type SearchSource = 'Agents' | 'Alerts' | 'Events'

interface SearchLiveDataResult {
  results: SearchResult[]
  failures: SearchSource[]
}

const QUICK_ACTION_IDS = ['dashboard', 'alerts', 'deploy-agent', 'response', 'detection-rules']

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  agent: Monitor,
  alert: AlertTriangle,
  event: Activity,
  rule: FileCode,
  feature: Search,
}

const typeLabels: Record<string, string> = {
  agent: 'Agents',
  alert: 'Alerts',
  event: 'Events',
  rule: 'Detection Rules',
  feature: 'Features',
}

const typeColors: Record<string, string> = {
  agent: 'var(--emerald-400)',
  alert: 'var(--crit)',
  event: 'var(--info)',
  rule: 'var(--warn)',
  feature: 'var(--emerald-400)',
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

async function readJsonData(response: Response): Promise<any[]> {
  if (!response.ok) {
    throw new Error(`Search request failed with HTTP ${response.status}`)
  }
  const body = await response.json()
  return Array.isArray(body?.data) ? body.data : []
}

function searchFeatureResults(query: string, navigationGroups: NavigationGroup[]): SearchResult[] {
  return searchNavigation(query, navigationGroups, 8)
    .map(feature => ({
      id: `feature-${feature.id}`,
      type: 'feature' as const,
      title: feature.name,
      subtitle: `${feature.groupName} · ${feature.description}`,
      href: feature.href,
      external: feature.external,
      icon: feature.icon,
    }))
}

async function searchLiveData(query: string, navigationGroups: NavigationGroup[]): Promise<SearchLiveDataResult> {
  const trimmed = query.trim()
  if (!trimmed) return { results: [], failures: [] }

  const staticResults = searchFeatureResults(trimmed, navigationGroups)

  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken(),
    ...(localStorage.getItem('tamandua_current_tenant_id')
      ? { 'X-Tenant-ID': localStorage.getItem('tamandua_current_tenant_id') as string }
      : {}),
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
  const failures: SearchSource[] = []

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
  } else {
    failures.push('Agents')
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
  } else {
    failures.push('Alerts')
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
        href: `/app/events?event_id=${encodeURIComponent(id)}`,
      })
    })
  } else {
    failures.push('Events')
  }

  return { results: [...staticResults, ...results].slice(0, 15), failures }
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
  const pageProps = usePage<SharedProps & { is_super_admin?: boolean }>().props
  const userRole = pageProps.auth?.user?.role
  const visibleNavigationGroups = useMemo(
    () => getVisibleNavigationGroups(userRole, pageProps.is_super_admin, true),
    [userRole, pageProps.is_super_admin]
  )
  const quickActions = useMemo(() => {
    const byId = new Map(visibleNavigationGroups.flatMap(group => group.items).map(item => [item.id, item]))
    return QUICK_ACTION_IDS.flatMap(id => {
      const item = byId.get(id)
      return item ? [item] : []
    })
  }, [visibleNavigationGroups])
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [sourceFailures, setSourceFailures] = useState<SearchSource[]>([])
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
      setSourceFailures([])
      return
    }

    // Feature navigation is local and must remain instant even when a live API is slow.
    setResults(searchFeatureResults(trimmed, visibleNavigationGroups))
    setIsSearching(true)
    setSearchError(null)
    setSourceFailures([])

    const controller = new AbortController()
    const timeout = window.setTimeout(() => {
      searchLiveData(trimmed, visibleNavigationGroups)
        .then(({ results: liveResults, failures }) => {
          if (!controller.signal.aborted) {
            setResults(liveResults)
            setSourceFailures(failures)
          }
        })
        .catch(() => {
          if (!controller.signal.aborted) {
            setResults([])
            setSourceFailures([])
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
  }, [query, visibleNavigationGroups])

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
  }, [query, results, recentSearches, quickActions])

  const visitResult = useCallback((href: string, external?: boolean) => {
    if (external) {
      window.location.assign(href)
    } else {
      router.visit(href)
    }
  }, [])

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
            visitResult(result.href, result.external)
            onClose()
          } else if (item.type === 'action') {
            const action = item.data as QuickAction
            visitResult(action.href, action.external)
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
  }, [selectableItems, selectedIndex, query, onClose, visitResult])

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
    visitResult(result.href, result.external)
    onClose()
  }

  const handleActionClick = (action: QuickAction) => {
    visitResult(action.href, action.external)
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
      role="dialog"
      aria-modal="true"
      aria-label="Search features and security data"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      {/* Overlay */}
      <div
        className="absolute inset-0"
        style={{ backgroundColor: 'rgba(0, 0, 0, 0.7)' }}
        onClick={onClose}
        aria-hidden="true"
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
            placeholder="Search features, agents, alerts, events..."
            aria-label="Search features and security data"
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
            isSearching && results.length === 0 ? (
              <div className="py-12 text-center">
                <Search className="h-12 w-12 mx-auto mb-4 animate-pulse" style={{ color: 'var(--subtle)' }} />
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Searching live data...
                </p>
              </div>
            ) : results.length > 0 ? (
              <div className="py-2">
                {sourceFailures.length > 0 && (
                  <div
                    className="mx-4 my-2 rounded-md px-3 py-2 text-xs"
                    style={{
                      backgroundColor: 'color-mix(in srgb, var(--warn) 12%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--warn) 26%, transparent)',
                      color: 'var(--fg-2)',
                    }}
                  >
                    Partial results. {sourceFailures.join(', ')} search did not load cleanly.
                  </div>
                )}
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
                        const ResultIcon = result.icon ?? Icon
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
                              <ResultIcon className="h-4 w-4" style={{ color: typeColors[type] }} />
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
                  {searchError
                    ? 'Check your session and API availability'
                    : sourceFailures.length > 0
                      ? `${sourceFailures.join(', ')} search did not load cleanly`
                      : 'Try adjusting your search terms'}
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
