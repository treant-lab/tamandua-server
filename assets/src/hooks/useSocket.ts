/**
 * WebSocket Hook for Phoenix Channels
 *
 * Provides real-time connectivity to Phoenix channels for:
 * - Dashboard updates (stats, agents, alerts)
 * - Alert feed
 * - Agent status updates
 * - Event streaming
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { usePage } from '@inertiajs/react'
import { Socket, Channel, Presence } from 'phoenix'
import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

export interface SocketConfig {
  url?: string
  token?: string
  autoConnect?: boolean
}

export interface ChannelConfig {
  topic: string
  params?: Record<string, unknown>
  onJoin?: (response: unknown) => void
  onError?: (error: unknown) => void
  onClose?: () => void
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'errored'

export interface UseSocketReturn {
  socket: Socket | null
  connectionState: ConnectionState
  connect: () => void
  disconnect: () => void
  joinChannel: (config: ChannelConfig) => Channel | null
  leaveChannel: (topic: string) => void
}

export interface UseDashboardChannelReturn {
  connectionState: ConnectionState
  stats: DashboardStats | null
  recentAlerts: AlertUpdate[]
  agentStatuses: Map<string, AgentStatusUpdate>
  sendPing: () => Promise<{ message: string }>
}

export interface UseAlertChannelReturn {
  connectionState: ConnectionState
  alerts: AlertUpdate[]
  acknowledgeAlert: (alertId: string) => Promise<void>
}

export interface UseEventStreamReturn {
  connectionState: ConnectionState
  events: StreamEvent[]
  clearEvents: () => void
  pauseStream: () => void
  resumeStream: () => void
  isPaused: boolean
}

// Event types from server
export interface DashboardStats {
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

export interface AlertUpdate {
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

export interface AgentStatusUpdate {
  agentId: string
  hostname: string
  status: 'online' | 'offline' | 'degraded'
  lastSeen: number
  cpuUsage?: number
  memoryUsage?: number
  eventsPerMinute?: number
}

export interface StreamEvent {
  id: string
  eventType: string
  agentId: string
  timestamp: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  summary: string
  payload: Record<string, unknown>
  detections?: Detection[]
}

interface Detection {
  type: string
  ruleName: string
  confidence: number
  description: string
  mitreTactics?: string[]
  mitreTechniques?: string[]
}

// ============================================================================
// Main Socket Hook
// ============================================================================

const DEFAULT_SOCKET_URL = '/socket/dashboard'

export function useSocket(config: SocketConfig = {}): UseSocketReturn {
  const {
    url = DEFAULT_SOCKET_URL,
    token,
    autoConnect = true
  } = config
  const { props } = usePage<any>()
  const resolvedToken = token ?? props?.auth?.socket_token ?? props?.auth?.socketToken ?? undefined

  const [socket, setSocket] = useState<Socket | null>(null)
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected')
  const channelsRef = useRef<Map<string, Channel>>(new Map())
  const socketRef = useRef<Socket | null>(null)

  const connect = useCallback(() => {
    const currentSocket = socketRef.current
    if (currentSocket?.isConnected()) return

    if (currentSocket) {
      currentSocket.disconnect()
      socketRef.current = null
      setSocket(null)
    }

    const params: Record<string, string> = {}
    if (resolvedToken) params.token = resolvedToken

    const newSocket = new Socket(url, { params })

    newSocket.onOpen(() => {
      setConnectionState('connected')
      logger.log('[WebSocket] Connected to', url)
    })

    newSocket.onClose(() => {
      setConnectionState('disconnected')
      logger.log('[WebSocket] Disconnected')
    })

    newSocket.onError((error) => {
      setConnectionState('errored')
      logger.error('[WebSocket] Error:', error)
    })

    setConnectionState('connecting')
    newSocket.connect()
    socketRef.current = newSocket
    setSocket(newSocket)
  }, [url, resolvedToken])

  const disconnect = useCallback(() => {
    const currentSocket = socketRef.current
    if (!currentSocket) return

    channelsRef.current.forEach((channel) => {
      channel.leave()
    })
    channelsRef.current.clear()
    currentSocket.disconnect()
    socketRef.current = null
    setSocket(null)
    setConnectionState('disconnected')
  }, [])

  const joinChannel = useCallback((channelConfig: ChannelConfig): Channel | null => {
    if (!socket) {
      logger.warn('[WebSocket] Cannot join channel: socket not connected')
      return null
    }

    const { topic, params = {}, onJoin, onError, onClose } = channelConfig

    // Check if already joined
    if (channelsRef.current.has(topic)) {
      return channelsRef.current.get(topic)!
    }

    const channel = socket.channel(topic, params)

    channel.join()
      .receive('ok', (response) => {
        logger.log(`[WebSocket] Joined ${topic}`, response)
        onJoin?.(response)
      })
      .receive('error', (error) => {
        logger.error(`[WebSocket] Failed to join ${topic}:`, error)
        onError?.(error)
      })

    channel.onClose(() => {
      channelsRef.current.delete(topic)
      onClose?.()
    })

    channelsRef.current.set(topic, channel)
    return channel
  }, [socket])

  const leaveChannel = useCallback((topic: string) => {
    const channel = channelsRef.current.get(topic)
    if (channel) {
      channel.leave()
      channelsRef.current.delete(topic)
    }
  }, [])

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect()
    }

    return () => {
      disconnect()
    }
  }, [autoConnect, connect, disconnect])

  return {
    socket,
    connectionState,
    connect,
    disconnect,
    joinChannel,
    leaveChannel
  }
}

// ============================================================================
// Dashboard Channel Hook
// ============================================================================

export function useDashboardChannel(): UseDashboardChannelReturn {
  const { socket, connectionState, joinChannel } = useSocket()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [recentAlerts, setRecentAlerts] = useState<AlertUpdate[]>([])
  const [agentStatuses, setAgentStatuses] = useState<Map<string, AgentStatusUpdate>>(new Map())
  const channelRef = useRef<Channel | null>(null)

  useEffect(() => {
    if (connectionState !== 'connected') return

    const channel = joinChannel({
      topic: 'dashboard:lobby',
      onJoin: (response) => {
        logger.log('[Dashboard] Joined lobby', response)
      }
    })

    if (!channel) return

    channelRef.current = channel

    // Listen for stats updates
    channel.on('stats_update', (payload) => {
      setStats(payload as DashboardStats)
    })

    // Server broadcasts a refresh notification only; fetch org-scoped stats
    // through the authenticated channel to avoid cross-tenant leakage.
    channel.on('stats_refresh', () => {
      channel.push('refresh_stats', {})
        .receive('ok', (payload) => {
          setStats(payload as DashboardStats)
        })
        .receive('error', (error) => {
          logger.error('[Dashboard] Failed to refresh stats', error)
        })
    })

    // Listen for new alerts
    channel.on('new_alert', (payload) => {
      const alert = payload as AlertUpdate
      setRecentAlerts(prev => [alert, ...prev].slice(0, 50))
    })

    // Listen for alert updates
    channel.on('alert_updated', (payload) => {
      const alert = payload as AlertUpdate
      setRecentAlerts(prev =>
        prev.map(a => a.id === alert.id ? alert : a)
      )
    })

    // Listen for agent status changes
    channel.on('agent_status', (payload) => {
      const status = payload as AgentStatusUpdate
      setAgentStatuses(prev => {
        const next = new Map(prev)
        next.set(status.agentId, status)
        return next
      })
    })

    return () => {
      channel.leave()
    }
  }, [connectionState, joinChannel])

  const sendPing = useCallback(async (): Promise<{ message: string }> => {
    return new Promise((resolve, reject) => {
      if (!channelRef.current) {
        reject(new Error('Not connected'))
        return
      }

      channelRef.current.push('ping', {})
        .receive('ok', (response) => resolve(response as { message: string }))
        .receive('error', reject)
        .receive('timeout', () => reject(new Error('Timeout')))
    })
  }, [])

  return {
    connectionState,
    stats,
    recentAlerts,
    agentStatuses,
    sendPing
  }
}

// ============================================================================
// Alert Channel Hook
// ============================================================================

export function useAlertChannel(): UseAlertChannelReturn {
  const { socket, connectionState, joinChannel } = useSocket()
  const [alerts, setAlerts] = useState<AlertUpdate[]>([])
  const channelRef = useRef<Channel | null>(null)

  useEffect(() => {
    if (connectionState !== 'connected') return

    const channel = joinChannel({
      topic: 'alerts:feed',
      onJoin: () => {
        logger.log('[Alerts] Joined feed')
      }
    })

    if (!channel) return

    channelRef.current = channel

    // Listen for new alerts
    channel.on('new_alert', (payload) => {
      const alert = payload as AlertUpdate
      setAlerts(prev => [alert, ...prev].slice(0, 100))
    })

    // Listen for alert updates
    channel.on('alert_updated', (payload) => {
      const data = payload as { alert: AlertUpdate }
      setAlerts(prev =>
        prev.map(a => a.id === data.alert.id ? data.alert : a)
      )
    })

    return () => {
      channel.leave()
    }
  }, [connectionState, joinChannel])

  const acknowledgeAlert = useCallback(async (alertId: string): Promise<void> => {
    return new Promise((resolve, reject) => {
      if (!channelRef.current) {
        reject(new Error('Not connected'))
        return
      }

      channelRef.current.push('acknowledge', { alert_id: alertId })
        .receive('ok', () => resolve())
        .receive('error', (error) => reject(new Error((error as { reason?: string })?.reason || 'Failed')))
        .receive('timeout', () => reject(new Error('Timeout')))
    })
  }, [])

  return {
    connectionState,
    alerts,
    acknowledgeAlert
  }
}

// ============================================================================
// Event Stream Hook
// ============================================================================

const MAX_EVENTS = 500

export function useEventStream(agentId?: string): UseEventStreamReturn {
  const { socket, connectionState, joinChannel, leaveChannel } = useSocket()
  const [events, setEvents] = useState<StreamEvent[]>([])
  const [isPaused, setIsPaused] = useState(false)
  const channelRef = useRef<Channel | null>(null)
  const eventQueueRef = useRef<StreamEvent[]>([])
  const isPausedRef = useRef(isPaused)

  // Keep ref in sync with state — avoids stale closure in event handlers
  // and removes isPaused from the useEffect dependency array
  isPausedRef.current = isPaused

  useEffect(() => {
    if (connectionState !== 'connected') return

    const topic = agentId ? `events:${agentId}` : 'events:all'

    const channel = joinChannel({
      topic,
      onJoin: () => {
        logger.log(`[Events] Joined ${topic}`)
      }
    })

    if (!channel) return

    channelRef.current = channel

    // Listen for events — use ref for isPaused to avoid stale closures
    channel.on('event', (payload) => {
      const event = payload as StreamEvent
      if (isPausedRef.current) {
        eventQueueRef.current.push(event)
        if (eventQueueRef.current.length > MAX_EVENTS) {
          eventQueueRef.current = eventQueueRef.current.slice(-MAX_EVENTS)
        }
      } else {
        setEvents(prev => [event, ...prev].slice(0, MAX_EVENTS))
      }
    })

    // Listen for batch events
    channel.on('events_batch', (payload) => {
      const data = payload as { events: StreamEvent[] }
      if (isPausedRef.current) {
        eventQueueRef.current.push(...data.events)
        if (eventQueueRef.current.length > MAX_EVENTS) {
          eventQueueRef.current = eventQueueRef.current.slice(-MAX_EVENTS)
        }
      } else {
        setEvents(prev => [...data.events, ...prev].slice(0, MAX_EVENTS))
      }
    })

    return () => {
      channelRef.current = null
      leaveChannel(topic)
    }
  }, [connectionState, joinChannel, leaveChannel, agentId]) // removed isPaused — use ref instead

  const clearEvents = useCallback(() => {
    setEvents([])
    eventQueueRef.current = []
  }, [])

  const pauseStream = useCallback(() => {
    setIsPaused(true)
  }, [])

  const resumeStream = useCallback(() => {
    // Merge queued events
    setEvents(prev => [...eventQueueRef.current, ...prev].slice(0, MAX_EVENTS))
    eventQueueRef.current = []
    setIsPaused(false)
  }, [])

  return {
    connectionState,
    events,
    clearEvents,
    pauseStream,
    resumeStream,
    isPaused
  }
}

// ============================================================================
// Agent Status Hook (individual agent)
// ============================================================================

export function useAgentStatus(agentId: string) {
  const { socket, connectionState, joinChannel, leaveChannel } = useSocket()
  const [status, setStatus] = useState<AgentStatusUpdate | null>(null)
  const [loading, setLoading] = useState(true)
  const channelRef = useRef<Channel | null>(null)

  useEffect(() => {
    if (connectionState !== 'connected' || !agentId) return

    const topic = `agents:${agentId}`

    const channel = joinChannel({
      topic,
      onJoin: () => {
        logger.log(`[Agent] Joined ${topic}`)
        setLoading(false)
      },
      onError: () => {
        setLoading(false)
      }
    })

    if (!channel) return

    channelRef.current = channel

    // Request initial status
    channel.push('get_status', { agent_id: agentId })
      .receive('ok', (response) => {
        const data = response as { agent: AgentStatusUpdate }
        setStatus(data.agent)
      })

    // Listen for status updates
    channel.on('status_update', (payload) => {
      const update = payload as AgentStatusUpdate
      setStatus(update)
    })

    return () => {
      leaveChannel(topic)
    }
  }, [connectionState, joinChannel, leaveChannel, agentId])

  return {
    connectionState,
    status,
    loading
  }
}

// ============================================================================
// Presence Hook (who's online)
// ============================================================================

export interface PresenceUser {
  id: string
  name: string
  role: string
  onlineAt: number
}

export function usePresence(topic: string) {
  const { socket, connectionState, joinChannel, leaveChannel } = useSocket()
  const [users, setUsers] = useState<PresenceUser[]>([])
  const presenceRef = useRef<Presence | null>(null)

  useEffect(() => {
    if (connectionState !== 'connected') return

    const channel = joinChannel({
      topic,
      onJoin: () => {
        logger.log(`[Presence] Joined ${topic}`)
      }
    })

    if (!channel) return

    const presence = new Presence(channel)

    presence.onSync(() => {
      const presenceList: PresenceUser[] = []
      presence.list((id, { metas }) => {
        const first = metas[0] as { name?: string; role?: string; online_at?: number } | undefined
        presenceList.push({
          id,
          name: first?.name || 'Unknown',
          role: first?.role || 'viewer',
          onlineAt: first?.online_at || Date.now()
        })
      })
      setUsers(presenceList)
    })

    presenceRef.current = presence

    return () => {
      leaveChannel(topic)
    }
  }, [connectionState, joinChannel, leaveChannel, topic])

  return {
    connectionState,
    users
  }
}

// ============================================================================
// Geo Channel Hook (Threat Map)
// ============================================================================

export interface GeoThreatOrigin {
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

export interface GeoThreatFlow {
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

export interface GeoMapSummary {
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

export interface UseGeoChannelReturn {
  connectionState: ConnectionState
  threats: GeoThreatOrigin[]
  agents: GeoAgentLocation[]
  flows: GeoThreatFlow[]
  summary: GeoMapSummary | null
  refresh: () => void
  setTimeframe: (timeframe: string) => void
  timeframe: string
}

export function useGeoChannel(initialTimeframe: string = '24h'): UseGeoChannelReturn {
  const { connectionState, joinChannel, leaveChannel } = useSocket()
  const [threats, setThreats] = useState<GeoThreatOrigin[]>([])
  const [agents, setAgents] = useState<GeoAgentLocation[]>([])
  const [flows, setFlows] = useState<GeoThreatFlow[]>([])
  const [summary, setSummary] = useState<GeoMapSummary | null>(null)
  const [timeframe, setTimeframeState] = useState(initialTimeframe)
  const channelRef = useRef<Channel | null>(null)

  useEffect(() => {
    if (connectionState !== 'connected') return

    const channel = joinChannel({
      topic: 'geo:map',
      params: { timeframe },
      onJoin: () => {
        logger.log('[Geo] Joined map channel')
      }
    })

    if (!channel) return

    channelRef.current = channel

    // Listen for full map data
    channel.on('map_data', (payload) => {
      const data = payload as {
        threats: GeoThreatOrigin[]
        agents: GeoAgentLocation[]
        flows: GeoThreatFlow[]
        summary: GeoMapSummary
      }
      setThreats(data.threats || [])
      setAgents(data.agents || [])
      setFlows(data.flows || [])
      setSummary(data.summary || null)
    })

    // Listen for incremental updates
    channel.on('map_update', (payload) => {
      const data = payload as { type: string }
      if (data.type === 'refresh') {
        // Request fresh data
        channel.push('refresh', { timeframe })
          .receive('ok', (response) => {
            const freshData = response as {
              threats: GeoThreatOrigin[]
              agents: GeoAgentLocation[]
              flows: GeoThreatFlow[]
              summary: GeoMapSummary
            }
            setThreats(freshData.threats || [])
            setAgents(freshData.agents || [])
            setFlows(freshData.flows || [])
            setSummary(freshData.summary || null)
          })
      }
    })

    // Listen for new threats
    channel.on('new_threat', (payload) => {
      const threat = payload as GeoThreatOrigin
      setThreats(prev => [threat, ...prev])
    })

    return () => {
      channelRef.current = null
      leaveChannel('geo:map')
    }
  }, [connectionState, joinChannel, leaveChannel, timeframe])

  const refresh = useCallback(() => {
    if (!channelRef.current) return

    channelRef.current.push('refresh', { timeframe })
      .receive('ok', (response) => {
        const data = response as {
          threats: GeoThreatOrigin[]
          agents: GeoAgentLocation[]
          flows: GeoThreatFlow[]
          summary: GeoMapSummary
        }
        setThreats(data.threats || [])
        setAgents(data.agents || [])
        setFlows(data.flows || [])
        setSummary(data.summary || null)
      })
  }, [timeframe])

  const setTimeframe = useCallback((newTimeframe: string) => {
    setTimeframeState(newTimeframe)
    if (channelRef.current) {
      channelRef.current.push('set_timeframe', { timeframe: newTimeframe })
    }
  }, [])

  return {
    connectionState,
    threats,
    agents,
    flows,
    summary,
    refresh,
    setTimeframe,
    timeframe
  }
}

// ============================================================================
// Connection Status Component Helper
// ============================================================================

export function getConnectionStatusColor(state: ConnectionState): string {
  switch (state) {
    case 'connected':
      return 'bg-green-500'
    case 'connecting':
      return 'bg-yellow-500 animate-pulse'
    case 'errored':
      return 'bg-red-500'
    default:
      return 'bg-slate-500'
  }
}

export function getConnectionStatusText(state: ConnectionState): string {
  switch (state) {
    case 'connected':
      return 'Connected'
    case 'connecting':
      return 'Connecting...'
    case 'errored':
      return 'Connection error'
    default:
      return 'Disconnected'
  }
}
