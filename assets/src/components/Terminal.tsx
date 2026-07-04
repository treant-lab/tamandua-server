/**
 * Terminal Component
 *
 * Interactive terminal emulator using xterm.js for live response shell sessions.
 *
 * Features:
 * - Full terminal emulation (xterm-256color)
 * - WebSocket connection to shell channel
 * - Copy/paste support
 * - Search in output
 * - Terminal resize handling
 * - Session recording playback
 * - Built-in command palette
 */

import { useEffect, useRef, useState, useCallback, forwardRef, useImperativeHandle } from 'react'
import { usePage } from '@inertiajs/react'
import { Socket, Channel } from 'phoenix'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

type XTermType = import('@xterm/xterm').Terminal
type FitAddonType = import('@xterm/addon-fit').FitAddon
type SearchAddonType = import('@xterm/addon-search').SearchAddon
import {
  Search,
  ChevronUp,
  ChevronDown,
  X,
  Copy,
  Clipboard,
  Terminal as TerminalIcon,
  AlertTriangle,
  Loader2,
  Clock,
  Shield,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface TerminalProps {
  /** Agent ID to connect to */
  agentId: string
  /** Session ID (if reconnecting) */
  sessionId?: string
  /** Callback when session starts */
  onSessionStart?: (sessionId: string) => void
  /** Callback when session ends */
  onSessionEnd?: (reason: string) => void
  /** Callback for command execution (for history) */
  onCommand?: (command: string) => void
  /** Callback for errors */
  onError?: (error: string) => void
  /** Callback when the socket/channel connection state changes */
  onConnectionStateChange?: (state: 'connecting' | 'connected' | 'disconnected' | 'error') => void
  /** Callback when the terminal is waiting for agent shell output */
  onWaitingForOutputChange?: (waiting: boolean) => void
  /** Custom class name */
  className?: string
  /** Socket URL override */
  socketUrl?: string
  /** Read-only mode (playback) */
  readOnly?: boolean
  /** Recording data for playback */
  recordingData?: string
  /** Channel type: 'shell' (legacy) or 'live_response' (enhanced) */
  channelType?: 'shell' | 'live_response'
  /** View-only mode (for session sharing) */
  viewOnly?: boolean
  /** Supervisor mode (bypass approval for privileged users) */
  supervisorMode?: boolean
  /** Callback when supervisor approval is required */
  onSupervisorRequired?: (commandId: string, command: string) => void
  /** Callback with active sessions for this agent */
  onActiveSessions?: (sessions: ActiveSession[]) => void
  /** Callback when a share token is created */
  onShareToken?: (token: string, targetUserId: string, viewOnly: boolean) => void
  /** Callback when rate limited */
  onRateLimited?: () => void
}

export interface ActiveSession {
  session_id: string
  user_email?: string
  view_only: boolean
  joined_at: string
}

export interface TerminalRef {
  /** Write data to terminal */
  write: (data: string) => void
  /** Clear terminal */
  clear: () => void
  /** Focus terminal */
  focus: () => void
  /** Get current session ID */
  getSessionId: () => string | null
  /** Terminate session */
  terminate: () => void
  /** Execute built-in command */
  executeBuiltin: (command: string, args?: string[]) => void
  /** Request a fresh active-session list */
  requestActiveSessions: () => void
  /** Share current session with another user */
  shareSession: (targetUserId: string, viewOnly?: boolean) => void
  /** Export current session */
  exportSession: (format: 'asciinema' | 'transcript' | 'json') => void
  /** Resize terminal */
  resize: () => void
}

interface DangerousWarning {
  commandId: string
  command: string
  warning: string
}

interface SupervisorRequired {
  commandId: string
  command: string
  reason: string
}

// ============================================================================
// Terminal Theme
// ============================================================================

const terminalTheme = {
  background: '#0f172a',
  foreground: '#e2e8f0',
  cursor: '#38bdf8',
  cursorAccent: '#0f172a',
  selectionBackground: '#38bdf833',
  selectionForeground: '#e2e8f0',
  black: '#1e293b',
  red: '#f87171',
  green: '#4ade80',
  yellow: '#fbbf24',
  blue: '#60a5fa',
  magenta: '#c084fc',
  cyan: '#22d3ee',
  white: '#f1f5f9',
  brightBlack: '#475569',
  brightRed: '#fca5a5',
  brightGreen: '#86efac',
  brightYellow: '#fcd34d',
  brightBlue: '#93c5fd',
  brightMagenta: '#d8b4fe',
  brightCyan: '#67e8f9',
  brightWhite: '#f8fafc',
}

// ============================================================================
// Component
// ============================================================================

export const Terminal = forwardRef<TerminalRef, TerminalProps>(
  (
    {
      agentId,
      sessionId: initialSessionId,
      onSessionStart,
      onSessionEnd,
      onCommand,
      onError,
      onConnectionStateChange,
      onWaitingForOutputChange,
      className,
      socketUrl = '/socket/dashboard',
      readOnly = false,
      recordingData,
      channelType = 'live_response',
      viewOnly = false,
      supervisorMode = false,
      onSupervisorRequired,
      onActiveSessions,
      onShareToken,
      onRateLimited,
    },
    ref
  ) => {
    const { props } = usePage<any>()
    const socketToken = props?.auth?.socket_token ?? props?.auth?.socketToken ?? undefined
    const containerRef = useRef<HTMLDivElement>(null)
    const terminalRef = useRef<XTermType | null>(null)
    const fitAddonRef = useRef<FitAddonType | null>(null)
    const searchAddonRef = useRef<SearchAddonType | null>(null)
    const channelRef = useRef<Channel | null>(null)
    const socketRef = useRef<Socket | null>(null)
    const connectionSeqRef = useRef(0)
    const onSessionStartRef = useRef(onSessionStart)
    const onSessionEndRef = useRef(onSessionEnd)
    const onErrorRef = useRef(onError)
    const onConnectionStateChangeRef = useRef(onConnectionStateChange)
    const onWaitingForOutputChangeRef = useRef(onWaitingForOutputChange)
    const onSupervisorRequiredRef = useRef(onSupervisorRequired)
    const onActiveSessionsRef = useRef(onActiveSessions)
    const onShareTokenRef = useRef(onShareToken)
    const onRateLimitedRef = useRef(onRateLimited)
    const waitingTimerRef = useRef<number | null>(null)
    const inputBufferRef = useRef('')
    const inputFlushTimerRef = useRef<number | null>(null)
    const pendingLocalEchoRef = useRef('')
    const pendingTerminalWritesRef = useRef<Array<{ kind: 'write' | 'writeln'; data: string }>>([])
    const reconnectSessionIdRef = useRef(initialSessionId)
    const activeSessionIdRef = useRef<string | null>(null)
    const recentFrameRef = useRef<{ key: string; seenAt: number } | null>(null)
    const recentOutputRef = useRef<{ sessionId: string; data: string; seenAt: number } | null>(null)

    const [isConnected, setIsConnected] = useState(false)
    const [isConnecting, setIsConnecting] = useState(false)
    const [isWaitingForOutput, setIsWaitingForOutput] = useState(false)
    const [sessionId, setSessionId] = useState<string | null>(initialSessionId || null)
    const [showSearch, setShowSearch] = useState(false)
    const [searchQuery, setSearchQuery] = useState('')
    const [dangerousWarning, setDangerousWarning] = useState<DangerousWarning | null>(null)
    const [supervisorRequired, setSupervisorRequired] = useState<SupervisorRequired | null>(null)
    const [error, setError] = useState<string | null>(null)

    const writeTerminal = useCallback((data: string) => {
      const terminal = terminalRef.current

      if (terminal) {
        terminal.write(data, () => terminal.scrollToBottom())
      } else {
        pendingTerminalWritesRef.current.push({ kind: 'write', data })
      }
    }, [])

    const writelnTerminal = useCallback((data = '') => {
      const terminal = terminalRef.current

      if (terminal) {
        terminal.writeln(data, () => terminal.scrollToBottom())
      } else {
        pendingTerminalWritesRef.current.push({ kind: 'writeln', data })
      }
    }, [])

    const flushPendingTerminalWrites = useCallback(() => {
      const terminal = terminalRef.current
      if (!terminal || pendingTerminalWritesRef.current.length === 0) return

      for (const entry of pendingTerminalWritesRef.current) {
        if (entry.kind === 'write') {
          terminal.write(entry.data, () => terminal.scrollToBottom())
        } else {
          terminal.writeln(entry.data, () => terminal.scrollToBottom())
        }
      }

      pendingTerminalWritesRef.current = []
    }, [])

    const shouldAcceptFrame = useCallback((payload: any, eventName: string) => {
      const payloadSessionId = typeof payload?.session_id === 'string' ? payload.session_id : null
      const activeSessionId = activeSessionIdRef.current

      if (payloadSessionId && activeSessionId && payloadSessionId !== activeSessionId) {
        return false
      }

      if (payloadSessionId && !activeSessionId) {
        activeSessionIdRef.current = payloadSessionId
      }

      if (eventName === 'output') {
        const data = typeof payload?.data === 'string' ? payload.data : ''
        const sessionId = payloadSessionId || activeSessionId || ''
        const now = Date.now()
        const recentOutput = recentOutputRef.current

        // Phoenix reconnects or duplicate live-response channels can deliver the
        // same PTY frame twice within the same tick. Suppress only immediate
        // exact duplicates; repeated user input still arrives as distinct frames.
        if (
          data &&
          recentOutput &&
          recentOutput.sessionId === sessionId &&
          recentOutput.data === data &&
          now - recentOutput.seenAt < 100
        ) {
          return false
        }

        recentOutputRef.current = { sessionId, data, seenAt: now }
        return true
      }

      const key = `${eventName}:${payloadSessionId || activeSessionId || ''}:${payload?.data || payload?.reason || payload?.message || ''}`
      const now = Date.now()
      const recent = recentFrameRef.current
      if (recent && recent.key === key && now - recent.seenAt < 750) {
        return false
      }

      recentFrameRef.current = { key, seenAt: now }
      return true
    }, [])

    useEffect(() => {
      onSessionStartRef.current = onSessionStart
      onSessionEndRef.current = onSessionEnd
      onErrorRef.current = onError
      onConnectionStateChangeRef.current = onConnectionStateChange
      onWaitingForOutputChangeRef.current = onWaitingForOutputChange
      onSupervisorRequiredRef.current = onSupervisorRequired
      onActiveSessionsRef.current = onActiveSessions
      onShareTokenRef.current = onShareToken
      onRateLimitedRef.current = onRateLimited
    }, [
      onSessionStart,
      onSessionEnd,
      onError,
      onConnectionStateChange,
      onWaitingForOutputChange,
      onSupervisorRequired,
      onActiveSessions,
      onShareToken,
      onRateLimited,
    ])

    // Command history for up/down arrow navigation
    const commandHistoryRef = useRef<string[]>([])
    const historyIndexRef = useRef(-1)
    const currentLineRef = useRef('')

    const setWaitingForOutput = useCallback((waiting: boolean, showHint = false) => {
      if (waitingTimerRef.current) {
        window.clearTimeout(waitingTimerRef.current)
        waitingTimerRef.current = null
      }

      setIsWaitingForOutput(waiting)
      onWaitingForOutputChangeRef.current?.(waiting)

      if (waiting && showHint) {
        waitingTimerRef.current = window.setTimeout(() => {
          writelnTerminal('\x1b[90mShell is connected. Press Enter if the prompt is not visible yet.\x1b[0m')
        }, 3000)
      }
    }, [writelnTerminal])

    const normalizeTerminalInput = useCallback((data: string) => {
      // xterm normally emits DEL for Backspace. Normalize Ctrl-H too so
      // shells with `erase = ^?` behave consistently across browsers/OSes.
      //
      // Keep Enter as the raw xterm carriage return. Sending CRLF to a real PTY
      // makes Unix shells process the LF as a second empty command, which shows
      // up as an extra prompt/blank line after every command.
      return data.replace(/\x08/g, '\x7f')
    }, [])

    const localEchoForInput = useCallback((data: string) => {
      return data
        .replace(/\x08|\x7f/g, '\b \b')
        .replace(/\r(?!\n)/g, '\r\n')
    }, [])

    const stripLocalEcho = useCallback((data: string) => {
      const pending = pendingLocalEchoRef.current
      if (!pending || !data) return data

      if (data.startsWith(pending)) {
        pendingLocalEchoRef.current = ''
        return data.slice(pending.length)
      }

      if (pending.startsWith(data)) {
        pendingLocalEchoRef.current = pending.slice(data.length)
        return ''
      }

      // The agent produced real output before echoing exactly what we predicted.
      // Drop the stale optimistic echo buffer rather than hiding unrelated output.
      pendingLocalEchoRef.current = ''
      return data
    }, [])

    const pushInput = useCallback((data: string) => {
      const channel = channelRef.current
      if (!channel) {
        writelnTerminal('\x1b[33mLive response channel is not ready yet\x1b[0m')
        return
      }

      channel
        .push('input', { data }, 10000)
        .receive('ok', () => {
          // PTY echo/output is the source of truth. Do not flip the whole
          // terminal into a waiting state for every keystroke.
        })
        .receive('error', (resp) => {
          const reason = resp?.reason || resp?.message || 'failed to send input'
          setWaitingForOutput(false)
          writelnTerminal(`\x1b[31mInput error: ${reason}\x1b[0m`)
          onErrorRef.current?.(reason)
        })
        .receive('timeout', () => {
          const reason = 'Timed out sending terminal input'
          setWaitingForOutput(false)
          writelnTerminal(`\x1b[31m${reason}\x1b[0m`)
          onErrorRef.current?.(reason)
        })
    }, [setWaitingForOutput, writelnTerminal])

    const flushInputBuffer = useCallback(() => {
      if (inputFlushTimerRef.current) {
        window.clearTimeout(inputFlushTimerRef.current)
        inputFlushTimerRef.current = null
      }

      const data = inputBufferRef.current
      if (!data) return

      inputBufferRef.current = ''
      pushInput(data)
    }, [pushInput])

    const queueTerminalInput = useCallback(
      (data: string) => {
        const normalized = normalizeTerminalInput(data)
        if (!normalized) return

        const localEcho = localEchoForInput(normalized)
        if (localEcho) {
          writeTerminal(localEcho)
          pendingLocalEchoRef.current = `${pendingLocalEchoRef.current}${localEcho}`.slice(-4096)
        }

        inputBufferRef.current += normalized

        if (normalized.includes('\r') || normalized.includes('\n') || normalized.length > 32) {
          flushInputBuffer()
          return
        }

        if (!inputFlushTimerRef.current) {
          inputFlushTimerRef.current = window.setTimeout(flushInputBuffer, 12)
        }
      },
      [flushInputBuffer, localEchoForInput, normalizeTerminalInput, writeTerminal]
    )

    // Initialize terminal (dynamically import xterm)
    useEffect(() => {
      if (!containerRef.current) return

      let disposed = false
      let resizeObserver: ResizeObserver | null = null

      const initTerminal = async () => {
        try {
          const [
            { Terminal: XTerm },
            { FitAddon },
            { SearchAddon },
            { WebLinksAddon },
            { Unicode11Addon },
          ] = await Promise.all([
            import('@xterm/xterm'),
            import('@xterm/addon-fit'),
            import('@xterm/addon-search'),
            import('@xterm/addon-web-links'),
            import('@xterm/addon-unicode11'),
          ])

          if (disposed || !containerRef.current) return

          // Single source of truth for the mono stack: the Sentinel --mono
          // token (css/tokens.css). xterm renders to canvas, so the CSS var
          // must be resolved to a concrete font list at init time.
          const monoFontStack =
            getComputedStyle(document.documentElement)
              .getPropertyValue('--mono')
              .trim() || '"JetBrains Mono", ui-monospace, monospace'

          const terminal = new XTerm({
            cursorBlink: true,
            cursorStyle: 'block',
            fontFamily: monoFontStack,
            fontSize: 14,
            lineHeight: 1.2,
            theme: terminalTheme,
            allowProposedApi: true,
            scrollback: 10000,
            convertEol: true,
          })

          const fitAddon = new FitAddon()
          const searchAddon = new SearchAddon()
          const webLinksAddon = new WebLinksAddon()
          const unicode11Addon = new Unicode11Addon()

          terminal.loadAddon(fitAddon)
          terminal.loadAddon(searchAddon)
          terminal.loadAddon(webLinksAddon)
          terminal.loadAddon(unicode11Addon)
          terminal.unicode.activeVersion = '11'

          terminal.open(containerRef.current)
          fitAddon.fit()

          terminalRef.current = terminal
          fitAddonRef.current = fitAddon
          searchAddonRef.current = searchAddon

          // Handle input (unless read-only)
          if (!readOnly) {
            terminal.onData((data) => {
              queueTerminalInput(data)
            })
          }

          // Handle resize
          const handleResize = () => {
            fitAddon.fit()
            if (channelRef.current && terminalRef.current) {
              channelRef.current.push('resize', {
                cols: terminalRef.current.cols,
                rows: terminalRef.current.rows,
              })
            }
          }

          resizeObserver = new ResizeObserver(handleResize)
          resizeObserver.observe(containerRef.current!)

          // Welcome message
          terminal.writeln('\x1b[1;36m=== Tamandua Live Response Shell ===\x1b[0m')
          terminal.writeln('')
          flushPendingTerminalWrites()
          terminal.focus()
        } catch (err) {
          logger.error('Failed to load terminal:', err)
        }
      }

      initTerminal()

      // Cleanup
      return () => {
        disposed = true
        resizeObserver?.disconnect()
        terminalRef.current?.dispose()
        if (channelRef.current) {
          channelRef.current.leave()
          channelRef.current = null
        }
        if (socketRef.current) {
          socketRef.current.disconnect()
          socketRef.current = null
        }
        if (waitingTimerRef.current) {
          window.clearTimeout(waitingTimerRef.current)
          waitingTimerRef.current = null
        }
        if (inputFlushTimerRef.current) {
          window.clearTimeout(inputFlushTimerRef.current)
          inputFlushTimerRef.current = null
        }
        inputBufferRef.current = ''
        pendingTerminalWritesRef.current = []
      }
    }, [flushPendingTerminalWrites, queueTerminalInput, readOnly])

    // Connect to shell/live_response channel
    useEffect(() => {
      if (readOnly || !agentId) return

      const connectionSeq = ++connectionSeqRef.current
      let active = true
      let joined = false
      let sessionsInterval: number | null = null

      setIsConnecting(true)
      onConnectionStateChangeRef.current?.('connecting')
      setError(null)

      const params: Record<string, string> = {}
      if (socketToken) {
        params.token = socketToken
      }

      const socket = new Socket(socketUrl, { params })

      socket.connect()
      socketRef.current = socket

      // Use either shell or live_response channel based on channelType
      const channelName = channelType === 'live_response'
        ? `live_response:${agentId}`
        : `shell:${agentId}`

      const channel = socket.channel(channelName, {
        view_only: viewOnly,
        supervisor_mode: supervisorMode,
        ...(reconnectSessionIdRef.current ? { session_id: reconnectSessionIdRef.current } : {}),
      })

      channelRef.current = channel

      channel.onClose(() => {
        if (!active || connectionSeq !== connectionSeqRef.current) return
        setIsConnected(false)
        setIsConnecting(false)
        onConnectionStateChangeRef.current?.('disconnected')
        setWaitingForOutput(false)
        if (!error) {
          writelnTerminal(`\x1b[33mDisconnected from live response channel\x1b[0m`)
        }
      })

      // Handle output from agent
      channel.on('output', (payload) => {
        if (!shouldAcceptFrame(payload, 'output')) return
        setWaitingForOutput(false)
        writeTerminal(stripLocalEcho(payload.data))
      })

      // Handle session started
      channel.on('session_started', (payload) => {
        if (!shouldAcceptFrame(payload, 'session_started')) return
        setWaitingForOutput(false)
        writelnTerminal(`\x1b[32mShell started: ${payload.shell}\x1b[0m`)
        writelnTerminal('\x1b[90mInteractive input is ready.\x1b[0m')
        writelnTerminal('')
      })

      // Handle session ended
      channel.on('session_ended', (payload) => {
        if (!shouldAcceptFrame(payload, 'session_ended')) return
        writelnTerminal('')
        writelnTerminal(`\x1b[33mSession ended: ${payload.reason}\x1b[0m`)
        setIsConnected(false)
        onConnectionStateChangeRef.current?.('disconnected')
        setWaitingForOutput(false)
        onSessionEndRef.current?.(payload.reason)
      })

      // Handle builtin results
      channel.on('builtin_result', (payload) => {
        if (!shouldAcceptFrame(payload, 'builtin_result')) return
        setWaitingForOutput(false)
        writelnTerminal('')
        if (payload.success) {
          writeTerminal(payload.output)
        } else {
          writelnTerminal(`\x1b[31mError: ${payload.output}\x1b[0m`)
        }
      })

      // Handle dangerous command warnings
      channel.on('dangerous_warning', (payload) => {
        setDangerousWarning({
          commandId: payload.command_id,
          command: payload.command,
          warning: payload.warning,
        })
      })

      // Handle errors
      channel.on('error', (payload) => {
        if (!shouldAcceptFrame(payload, 'error')) return
        setWaitingForOutput(false)
        writelnTerminal(`\x1b[31mError: ${payload.message}\x1b[0m`)
        onErrorRef.current?.(payload.message)
      })

      // Handle session timeout
      channel.on('session_timeout', (payload) => {
        writelnTerminal('')
        writelnTerminal(`\x1b[33m${payload.reason}\x1b[0m`)
        setIsConnected(false)
        onConnectionStateChangeRef.current?.('disconnected')
        setWaitingForOutput(false)
        onSessionEndRef.current?.(payload.reason)
      })

      // Handle supervisor approval required (live_response channel only)
      channel.on('supervisor_required', (payload) => {
        setSupervisorRequired({
          commandId: payload.command_id,
          command: payload.command,
          reason: payload.reason,
        })
        onSupervisorRequiredRef.current?.(payload.command_id, payload.command)
        writelnTerminal(`\x1b[33m[Supervisor approval required]\x1b[0m`)
      })

      // Handle supervisor approved
      channel.on('supervisor_approved', (payload) => {
        setSupervisorRequired(null)
        writelnTerminal(`\x1b[32m[Command approved by supervisor]\x1b[0m`)
      })

      // Handle supervisor rejected
      channel.on('supervisor_rejected', (payload) => {
        setSupervisorRequired(null)
        writelnTerminal(`\x1b[31m[Command rejected: ${payload.reason}]\x1b[0m`)
      })

      // Handle rate limiting
      channel.on('rate_limited', (payload) => {
        onRateLimitedRef.current?.()
        setWaitingForOutput(false)
        writelnTerminal(`\x1b[33m[Rate limited: ${payload.message}]\x1b[0m`)
      })

      channel.on('active_sessions', (payload) => {
        onActiveSessionsRef.current?.(Array.isArray(payload.sessions) ? payload.sessions : [])
      })

      channel.on('share_token', (payload) => {
        onShareTokenRef.current?.(payload.token, payload.target_user_id, Boolean(payload.view_only))
      })

      channel.on('history', (payload) => {
        const history = Array.isArray(payload.entries)
          ? payload.entries
          : Array.isArray(payload.history)
            ? payload.history
            : []
        setWaitingForOutput(false)
        writelnTerminal('')
        writelnTerminal('\x1b[36m--- Session History ---\x1b[0m')
        if (history.length === 0) {
          writelnTerminal('\x1b[90mNo commands recorded in this session.\x1b[0m')
          return
        }

        for (const entry of history.slice().reverse()) {
          const command = entry.command || entry.data || JSON.stringify(entry)
          const timestamp = entry.timestamp ? `[${entry.timestamp}] ` : ''
          writelnTerminal(`${timestamp}${command}`)
        }
      })

      channel.on('export_ready', (payload) => {
        if (payload.download_url) {
          window.open(payload.download_url, '_blank', 'noopener,noreferrer')
          return
        }

        if (payload.content) {
          const extension = payload.format === 'json' ? 'json' : 'txt'
          const type = payload.format === 'json' ? 'application/json' : 'text/plain'
          const blob = new Blob([payload.content], { type })
          const url = URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = `${sessionId || 'live-response'}.${extension}`
          link.click()
          URL.revokeObjectURL(url)
        }
      })

      channel
        .join(30000)
        .receive('ok', (response) => {
          if (!active || connectionSeq !== connectionSeqRef.current) return
          joined = true
          setIsConnected(true)
          setIsConnecting(false)
          onConnectionStateChangeRef.current?.('connected')
          setSessionId(response.session_id)
          activeSessionIdRef.current = response.session_id
          onSessionStartRef.current?.(response.session_id)
          setWaitingForOutput(true, true)

          writelnTerminal(`\x1b[32mConnected to ${response.hostname}\x1b[0m`)
          writelnTerminal(`\x1b[90mSession: ${response.session_id}\x1b[0m`)
          writelnTerminal(`\x1b[90mOS: ${response.os}\x1b[0m`)
          if (response.view_only) {
            writelnTerminal(`\x1b[33mView-only mode\x1b[0m`)
          }
          if (response.supervisor_mode) {
            writelnTerminal(`\x1b[35mSupervisor mode enabled\x1b[0m`)
          }
          writelnTerminal('')
          terminalRef.current?.focus()
          channel.push('list_sessions', {})
          sessionsInterval = window.setInterval(() => {
            if (active && channelRef.current === channel) {
              channel.push('list_sessions', {})
            }
          }, 10000)
        })
        .receive('error', (resp) => {
          if (!active || connectionSeq !== connectionSeqRef.current) return
          const reason = resp?.reason || 'Failed to connect'
          setIsConnecting(false)
          setError(reason)
          onConnectionStateChangeRef.current?.('error')
          setWaitingForOutput(false)
          onErrorRef.current?.(reason)
          writelnTerminal(`\x1b[31mError: ${reason}\x1b[0m`)
        })
        .receive('timeout', () => {
          if (!active || joined || connectionSeq !== connectionSeqRef.current) return
          const reason = 'Live response channel join timed out'
          setIsConnecting(false)
          setError(reason)
          onConnectionStateChangeRef.current?.('error')
          setWaitingForOutput(false)
          onErrorRef.current?.(reason)
          writelnTerminal(`\x1b[31mError: ${reason}\x1b[0m`)
        })

      return () => {
        active = false
        if (connectionSeq === connectionSeqRef.current) {
          connectionSeqRef.current += 1
          channelRef.current = null
          socketRef.current = null
        }
        if (sessionsInterval) {
          window.clearInterval(sessionsInterval)
          sessionsInterval = null
        }
        channel.leave()
        socket.disconnect()
        setWaitingForOutput(false)
      }
    // NOTE: Callback props (onSessionStart, onSessionEnd, etc.) are intentionally excluded
    // from deps to prevent reconnection loops. They are called via refs if needed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [
      agentId,
      socketUrl,
      readOnly,
      channelType,
      viewOnly,
      supervisorMode,
      socketToken,
      setWaitingForOutput,
      writeTerminal,
      writelnTerminal,
      shouldAcceptFrame,
    ])

    // Playback mode
    useEffect(() => {
      if (!readOnly || !recordingData) return

      const playRecording = async () => {
        const lines = recordingData.split('\n').filter((l) => l.trim())
        if (lines.length < 2) return

        // Parse header
        const header = JSON.parse(lines[0])
        writelnTerminal(`\x1b[1;36m=== Recording Playback ===\x1b[0m`)
        writelnTerminal(`\x1b[90mTitle: ${header.title || 'Shell Session'}\x1b[0m`)
        writelnTerminal('')

        // Parse and play events
        let lastTime = 0
        for (let i = 1; i < lines.length; i++) {
          try {
            const [timestamp, type, data] = JSON.parse(lines[i])
            const delay = (timestamp - lastTime) * 1000
            lastTime = timestamp

            // Cap delay at 2 seconds for smoother playback
            await new Promise((resolve) => setTimeout(resolve, Math.min(delay, 2000)))

            if (type === 'o') {
              writeTerminal(data)
            }
          } catch {
            // Skip malformed lines
          }
        }

        writelnTerminal('')
        writelnTerminal(`\x1b[1;36m=== End of Recording ===\x1b[0m`)
      }

      playRecording()
    }, [readOnly, recordingData, writeTerminal, writelnTerminal])

    // Search functionality
    const handleSearch = useCallback(
      (direction: 'next' | 'previous') => {
        if (!searchAddonRef.current || !searchQuery) return

        if (direction === 'next') {
          searchAddonRef.current.findNext(searchQuery)
        } else {
          searchAddonRef.current.findPrevious(searchQuery)
        }
      },
      [searchQuery]
    )

    // Handle dangerous command confirmation
    const handleConfirmDangerous = useCallback(() => {
      if (!dangerousWarning || !channelRef.current) return

      channelRef.current.push('confirm_dangerous', {
        command_id: dangerousWarning.commandId,
      })
      setDangerousWarning(null)
    }, [dangerousWarning])

    const handleCancelDangerous = useCallback(() => {
      if (!dangerousWarning || !channelRef.current) return

      channelRef.current.push('cancel_dangerous', {
        command_id: dangerousWarning.commandId,
      })
      setDangerousWarning(null)
    }, [dangerousWarning])

    // Expose methods via ref
    useImperativeHandle(ref, () => ({
      write: (data: string) => {
        writeTerminal(data)
      },
      clear: () => {
        terminalRef.current?.clear()
      },
      focus: () => {
        terminalRef.current?.focus()
      },
      getSessionId: () => sessionId,
      terminate: () => {
        if (channelRef.current) {
          channelRef.current.push('terminate', {})
        }
      },
      executeBuiltin: (command: string, args: string[] = []) => {
        if (channelRef.current) {
          if (command === 'history') {
            channelRef.current.push('get_history', {})
            setWaitingForOutput(true, false)
            return
          }

          channelRef.current.push('builtin', { command, args })
          setWaitingForOutput(true, true)
        }
      },
      requestActiveSessions: () => {
        channelRef.current?.push('list_sessions', {})
      },
      shareSession: (targetUserId: string, viewOnly = true) => {
        channelRef.current?.push('share_session', {
          user_id: targetUserId,
          view_only: viewOnly,
        })
      },
      exportSession: (format: 'asciinema' | 'transcript' | 'json') => {
        channelRef.current?.push('export_session', { format })
      },
      resize: () => {
        fitAddonRef.current?.fit()
      },
    }), [sessionId, setWaitingForOutput, writeTerminal])

    // Copy selection
    const handleCopy = useCallback(() => {
      const selection = terminalRef.current?.getSelection()
      if (selection) {
        navigator.clipboard.writeText(selection)
      }
    }, [])

    // Paste from clipboard
    const handlePaste = useCallback(async () => {
      if (readOnly) return
      try {
        const text = await navigator.clipboard.readText()
        if (channelRef.current) {
          flushInputBuffer()
          pushInput(normalizeTerminalInput(text))
        }
      } catch {
        // Clipboard access denied
      }
    }, [flushInputBuffer, normalizeTerminalInput, readOnly, pushInput])

    return (
      <div className={cn('flex flex-col h-full bg-slate-900 rounded-lg overflow-hidden', className)}>
        {/* Toolbar */}
        <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <TerminalIcon className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">
              {isConnected ? (
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  {isWaitingForOutput ? 'Waiting for agent output...' : 'Connected'}
                </span>
              ) : isConnecting ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="h-3 w-3 animate-spin text-blue-400" />
                  Connecting...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-slate-500" />
                  Disconnected
                </span>
              )}
            </span>
            {sessionId && (
              <span className="text-xs text-slate-500 font-mono">{sessionId.slice(0, 16)}...</span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Search toggle */}
            <button
              onClick={() => setShowSearch(!showSearch)}
              className={cn(
                'p-1.5 rounded transition-colors',
                showSearch ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'
              )}
              title="Search (Ctrl+F)"
            >
              <Search className="h-4 w-4" />
            </button>

            {/* Copy */}
            <button
              onClick={handleCopy}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              title="Copy selection"
            >
              <Copy className="h-4 w-4" />
            </button>

            {/* Paste */}
            {!readOnly && (
              <button
                onClick={handlePaste}
                className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
                title="Paste"
              >
                <Clipboard className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        {/* Search bar */}
        {showSearch && (
          <div className="flex items-center gap-2 px-4 py-2 bg-slate-800/50 border-b border-slate-700">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  handleSearch(e.shiftKey ? 'previous' : 'next')
                } else if (e.key === 'Escape') {
                  setShowSearch(false)
                }
              }}
              placeholder="Search..."
              className="flex-1 bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
              autoFocus
            />
            <button
              onClick={() => handleSearch('previous')}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              title="Previous (Shift+Enter)"
            >
              <ChevronUp className="h-4 w-4" />
            </button>
            <button
              onClick={() => handleSearch('next')}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              title="Next (Enter)"
            >
              <ChevronDown className="h-4 w-4" />
            </button>
            <button
              onClick={() => setShowSearch(false)}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              title="Close (Esc)"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Dangerous command warning */}
        {dangerousWarning && (
          <div className="px-4 py-3 bg-red-500/10 border-b border-red-500/30">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-red-400">Dangerous Command Detected</p>
                <p className="text-sm text-slate-400 mt-1">{dangerousWarning.warning}</p>
                <code className="block mt-2 px-2 py-1 bg-slate-800 rounded text-sm text-slate-300 font-mono">
                  {dangerousWarning.command}
                </code>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={handleConfirmDangerous}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded transition-colors"
                  >
                    Execute Anyway
                  </button>
                  <button
                    onClick={handleCancelDangerous}
                    className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Supervisor approval pending */}
        {supervisorRequired && (
          <div className="px-4 py-3 bg-orange-500/10 border-b border-orange-500/30">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-orange-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-orange-400">Supervisor Approval Required</p>
                <p className="text-sm text-slate-400 mt-1">{supervisorRequired.reason}</p>
                <code className="block mt-2 px-2 py-1 bg-slate-800 rounded text-sm text-slate-300 font-mono">
                  {supervisorRequired.command}
                </code>
                <div className="flex items-center gap-2 mt-3 text-sm text-slate-400">
                  <Clock className="h-4 w-4 animate-pulse" />
                  <span>Waiting for supervisor approval...</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Error message */}
        {error && (
          <div className="px-4 py-2 bg-red-500/10 border-b border-red-500/30">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Terminal container */}
        <div
          ref={containerRef}
          className="flex-1 p-2"
          onMouseDown={() => terminalRef.current?.focus()}
        />
      </div>
    )
  }
)

Terminal.displayName = 'Terminal'

export default Terminal
