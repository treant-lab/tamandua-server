/**
 * Type declarations for the Phoenix JS client
 */

declare module 'phoenix' {
  export interface SocketOptions {
    params?: Record<string, unknown> | (() => Record<string, unknown>)
    transport?: typeof WebSocket
    encode?: (payload: unknown, callback: (encoded: string) => void) => void
    decode?: (payload: string, callback: (decoded: unknown) => void) => void
    timeout?: number
    heartbeatIntervalMs?: number
    reconnectAfterMs?: (tries: number) => number
    rejoinAfterMs?: (tries: number) => number
    logger?: (kind: string, msg: string, data: unknown) => void
    longpollerTimeout?: number
    binaryType?: BinaryType
    vsn?: string
  }

  export class Socket {
    constructor(endPoint: string, opts?: SocketOptions)

    // Connection methods
    connect(): void
    disconnect(callback?: () => void, code?: number, reason?: string): void
    isConnected(): boolean

    // Event handlers
    onOpen(callback: () => void): void
    onClose(callback: (event: CloseEvent) => void): void
    onError(callback: (error: Event) => void): void
    onMessage(callback: (message: MessageEvent) => void): void

    // Channel methods
    channel(topic: string, params?: Record<string, unknown>): Channel

    // Connection info
    connectionState(): string
    protocol(): string
    endPointURL(): string

    // Internal
    makeRef(): string
    log(kind: string, msg: string, data?: unknown): void
  }

  export interface PushResponse {
    status: string
    response: unknown
  }

  export class Push {
    constructor(
      channel: Channel,
      event: string,
      payload: Record<string, unknown>,
      timeout: number
    )

    receive(
      status: 'ok' | 'error' | 'timeout',
      callback: (response: unknown) => void
    ): this
  }

  export class Channel {
    constructor(
      topic: string,
      params: Record<string, unknown>,
      socket: Socket
    )

    // Topic
    topic: string

    // State
    state: 'closed' | 'errored' | 'joined' | 'joining' | 'leaving'

    // Lifecycle
    join(timeout?: number): Push
    leave(timeout?: number): Push

    // Events
    on(event: string, callback: (payload: unknown) => void): number
    off(event: string, ref?: number): void
    onClose(callback: () => void): void
    onError(callback: (reason: unknown) => void): void

    // Push
    push(event: string, payload?: Record<string, unknown>, timeout?: number): Push

    // Internal
    canPush(): boolean
  }

  export interface PresenceOnJoin {
    (key: string, currentPresence: unknown | undefined, newPresence: unknown): void
  }

  export interface PresenceOnLeave {
    (key: string, currentPresence: unknown, leftPresence: unknown): void
  }

  export interface PresenceState {
    [key: string]: {
      metas: Array<{
        phx_ref: string
        [key: string]: unknown
      }>
    }
  }

  export interface PresenceDiff {
    joins: PresenceState
    leaves: PresenceState
  }

  export class Presence {
    constructor(channel: Channel, opts?: {
      events?: {
        state?: string
        diff?: string
      }
    })

    onJoin(callback: PresenceOnJoin): void
    onLeave(callback: PresenceOnLeave): void
    onSync(callback: () => void): void

    list<T = unknown>(
      by?: (key: string, presence: { metas: unknown[] }) => T
    ): T[]

    inPendingSyncState(): boolean
    static syncState(
      currentState: PresenceState,
      newState: PresenceState,
      onJoin?: PresenceOnJoin,
      onLeave?: PresenceOnLeave
    ): PresenceState

    static syncDiff(
      currentState: PresenceState,
      diff: PresenceDiff,
      onJoin?: PresenceOnJoin,
      onLeave?: PresenceOnLeave
    ): PresenceState

    static list<T = unknown>(
      presences: PresenceState,
      chooser?: (key: string, presence: { metas: unknown[] }) => T
    ): T[]
  }

  // Longpoll transport
  export class LongPoll {
    constructor(endPoint: string)
  }

  // Ajax helper
  export class Ajax {
    static request(
      method: string,
      endPoint: string,
      accept: string,
      body: string | null,
      timeout: number,
      ontimeout: () => void,
      callback: (response: unknown) => void
    ): void

    static xhrRequest(
      req: XMLHttpRequest,
      method: string,
      endPoint: string,
      accept: string,
      body: string | null,
      timeout: number,
      ontimeout: () => void,
      callback: (response: unknown) => void
    ): void

    static parseJSON(resp: string): unknown
    static serialize(obj: Record<string, unknown>, parentKey?: string): string
    static appendParams(url: string, params: Record<string, unknown>): string
  }

  export const Serializer: {
    encode(
      msg: { topic: string; event: string; payload: unknown; ref: string },
      callback: (encoded: string) => void
    ): void
    decode(
      rawPayload: string,
      callback: (decoded: { topic: string; event: string; payload: unknown; ref: string }) => void
    ): void
  }
}
