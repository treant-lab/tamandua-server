import { useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, AlertTriangle, Camera, CheckCircle, Clock, Film, GitCompare, Loader2, Lock, Square, X } from 'lucide-react'
import { toast } from 'sonner'
import {
  cancelEvidenceSession,
  approveEvidenceSession,
  createEvidenceExport,
  createEvidenceServerDiff,
  getEvidenceSession,
  getScreenCaptureArtifact,
  requestScreenCapture,
  startEvidenceSession,
  type EvidenceSessionContextSource,
  type EvidenceExportResult,
  type EvidenceServerDiffResult,
  type EvidenceSessionFrame,
  type EvidenceSessionResult,
  type ScreenCaptureResult,
} from '@/lib/remoteScreenCapture'

export type ScreenSessionBrokerState = 'ready' | 'no_user_session' | 'locked' | 'consent_required' | 'permission_denied' | 'portal_unavailable' | 'broker_unavailable' | 'unsupported'

export interface ScreenSessionBrokerHealth {
  schema_version?: string
  platform?: string
  state?: string
  ready?: boolean
  capabilities?: string[]
  observed_at?: string | null
  transport?: string
  consent_model?: string
  silent_supported?: boolean
  session_capture_supported?: boolean
  degraded_reason?: string | null
  unsupported_reason?: string | null
  detail_code?: string
  detail?: string
  displays?: Array<{
    id: string
    x: number
    y: number
    width: number
    height: number
    primary: boolean
  }>
}

export type ScreenCapturePolicyMode = 'silent' | 'notify' | 'consent_required' | 'disabled'

export interface ScreenCapturePolicyHealth {
  mode?: string
  notify_timing?: string | null
  allowed_scopes?: string[]
  redaction_required?: boolean
  policy?: {
    id?: string
    version?: number
    hash?: string
    source?: string
    issued_at?: string
    expires_at?: string
    issued_at_ms?: number
    expires_at_ms?: number
    allowed_scopes?: string[]
    redaction_required?: boolean
  }
}

interface ScreenCapability {
  id: string
  maturity?: string
  status?: string
  observed?: string
  detail?: string
  session_broker?: ScreenSessionBrokerHealth
  screen_capture_policy?: ScreenCapturePolicyHealth
}

interface ScreenCapturePanelProps {
  agentId: string
  hostname: string
  online: boolean
  capabilities: ScreenCapability[]
}

const CAPABILITY_IDS = new Set(['screen_capture', 'screen.snapshot', 'screen_snapshot'])
const BROKER_STATES = new Set<ScreenSessionBrokerState>(['ready', 'no_user_session', 'locked', 'consent_required', 'permission_denied', 'portal_unavailable', 'broker_unavailable', 'unsupported'])
const TERMINAL_CAPTURE_STATES = new Set(['ready', 'expired', 'failed'])
const POLL_INTERVAL_MS = 2_000
const MAX_POLL_WINDOW_MS = 15 * 60 * 1_000
const MAX_SESSION_POLL_WINDOW_MS = 30 * 60 * 1_000
const TERMINAL_SESSION_STATES = new Set(['completed', 'partial', 'cancelled', 'failed', 'expired'])

export function ScreenCapturePanel({
  agentId,
  hostname,
  online,
  capabilities,
}: ScreenCapturePanelProps) {
  const capability = useMemo(
    () => capabilities.find(item => CAPABILITY_IDS.has(item.id.toLowerCase())),
    [capabilities]
  )
  const broker = capability?.session_broker
  const brokerDisplays = useMemo(() => broker?.displays || [], [broker?.displays])
  const brokerCapabilitySet = useMemo(
    () => new Set((broker?.capabilities || []).map(item => item.toLowerCase().replaceAll('-', '_'))),
    [broker?.capabilities]
  )
  const policy = capability?.screen_capture_policy
  const policyMode = screenCapturePolicyMode(policy)
  const allowedScopes = useMemo(
    () => (policy?.allowed_scopes || policy?.policy?.allowed_scopes || ['virtual_desktop'])
      .filter(scope => scope === 'virtual_desktop' ||
        (scope === 'monitor' && brokerCapabilitySet.has('monitor_selection')) ||
        (scope === 'active_window' && brokerCapabilitySet.has('active_window_capture'))),
    [brokerCapabilitySet, policy?.allowed_scopes, policy?.policy?.allowed_scopes]
  )
  const redactionRequired = policy?.redaction_required ?? policy?.policy?.redaction_required ?? false
  const supportsWatermark = brokerCapabilitySet.has('watermark')
  const supportsRedaction = brokerCapabilitySet.has('redaction')
  const readiness = screenCaptureReadiness(capability)
  const [captureMode, setCaptureMode] = useState<'snapshot' | 'session'>('snapshot')
  const [showRequest, setShowRequest] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [reason, setReason] = useState('')
  const [ttlSeconds, setTtlSeconds] = useState(300)
  const [scope, setScope] = useState(allowedScopes[0] || 'virtual_desktop')
  const [monitorId, setMonitorId] = useState('')
  const [watermark, setWatermark] = useState(supportsWatermark)
  const [applyRedaction, setApplyRedaction] = useState(redactionRequired)
  const [redaction, setRedaction] = useState({ x: 0, y: 0, width: 2500, height: 2500 })
  const [frameCount, setFrameCount] = useState(3)
  const [intervalSeconds, setIntervalSeconds] = useState(10)
  const [alertId, setAlertId] = useState('')
  const [investigationId, setInvestigationId] = useState('')
  const [caseId, setCaseId] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<ScreenCaptureResult | null>(null)
  const [sessionResult, setSessionResult] = useState<EvidenceSessionResult | null>(null)
  const [cancellingSession, setCancellingSession] = useState(false)

  const disabledReason = !online
    ? 'Agent is offline; screenshot commands cannot be delivered.'
    : policyMode === 'disabled'
      ? 'Screen capture is disabled because the effective policy is missing, invalid, or explicitly disabled.'
      : redactionRequired && !supportsRedaction
        ? 'Policy requires redaction, but this platform broker cannot prove redaction before upload.'
        : allowedScopes.length === 0
          ? 'The platform broker does not support any capture scope allowed by policy.'
      : brokerStateMessage(readiness, capability?.detail)

  const canRequest = online && policyMode !== 'disabled' && (!redactionRequired || supportsRedaction) &&
    allowedScopes.length > 0 && ['ready', 'consent_required'].includes(readiness)
  const actionDisabledReason = disabledReason
  const trimmedReason = reason.trim()
  const redactionValid = !applyRedaction || (
    redaction.x >= 0 && redaction.y >= 0 && redaction.width > 0 && redaction.height > 0 &&
    redaction.x + redaction.width <= 10000 && redaction.y + redaction.height <= 10000
  )
  const requestValid = trimmedReason.length >= 10 && scope !== '' &&
    (scope !== 'monitor' || monitorId.trim().length > 0) && redactionValid &&
    (!redactionRequired || applyRedaction) &&
    (captureMode === 'snapshot' ||
      (frameCount >= 2 && frameCount <= 30 &&
        intervalSeconds >= 5 && intervalSeconds <= 60 &&
        (frameCount - 1) * intervalSeconds <= 1800))

  useEffect(() => {
    if (!allowedScopes.includes(scope)) setScope(allowedScopes[0] || '')
    if (redactionRequired) setApplyRedaction(true)
  }, [allowedScopes, redactionRequired, scope])

  useEffect(() => {
    if (!supportsWatermark) setWatermark(false)
  }, [supportsWatermark])

  useEffect(() => {
    if (scope === 'monitor' && brokerDisplays.length > 0 &&
        !brokerDisplays.some(display => display.id === monitorId)) {
      setMonitorId(brokerDisplays.find(display => display.primary)?.id || brokerDisplays[0].id)
    }
  }, [brokerDisplays, monitorId, scope])

  useEffect(() => {
    if (!online || !result?.artifactId || TERMINAL_CAPTURE_STATES.has(result.status.toLowerCase())) return

    const controller = new AbortController()
    const startedAt = Date.now()
    const serverExpiry = result.expiresAt ? new Date(result.expiresAt).getTime() : Number.NaN
    const stopAt = Number.isFinite(serverExpiry)
      ? Math.min(serverExpiry, startedAt + MAX_POLL_WINDOW_MS)
      : startedAt + MAX_POLL_WINDOW_MS
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      if (controller.signal.aborted || Date.now() >= stopAt) return
      try {
        const next = await getScreenCaptureArtifact(agentId, result.artifactId as string, controller.signal)
        if (!controller.signal.aborted) {
          setResult(previous => previous
            ? {
                ...previous,
                ...next,
                scope: next.scope ?? previous.scope,
                monitorId: next.monitorId ?? previous.monitorId,
                watermark: next.watermark ?? previous.watermark,
                redactionCount: next.redactionCount ?? previous.redactionCount,
                consentModel: next.consentModel ?? previous.consentModel,
                captureCoverage: next.captureCoverage ?? previous.captureCoverage,
                consentRequired: previous.consentRequired || next.consentRequired,
              }
            : next)
          if (!TERMINAL_CAPTURE_STATES.has(next.status.toLowerCase())) {
            timer = setTimeout(poll, POLL_INTERVAL_MS)
          }
        }
      } catch (error: unknown) {
        if (!controller.signal.aborted && Date.now() < stopAt) {
          timer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      }
    }

    timer = setTimeout(poll, POLL_INTERVAL_MS)
    return () => {
      controller.abort()
      if (timer) clearTimeout(timer)
    }
  }, [agentId, online, result?.artifactId, result?.expiresAt, result?.status])

  useEffect(() => {
    if (!online || !sessionResult?.sessionId ||
        TERMINAL_SESSION_STATES.has(sessionResult.status.toLowerCase())) return

    const controller = new AbortController()
    const parsedExpiry = sessionResult.expiresAt ? Date.parse(sessionResult.expiresAt) : Number.NaN
    const stopAt = Number.isFinite(parsedExpiry)
      ? Math.min(parsedExpiry, Date.now() + MAX_SESSION_POLL_WINDOW_MS)
      : Date.now() + MAX_SESSION_POLL_WINDOW_MS
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      if (controller.signal.aborted || Date.now() >= stopAt) return
      try {
        const next = await getEvidenceSession(
          agentId,
          sessionResult.sessionId as string,
          controller.signal
        )
        if (!controller.signal.aborted) {
          setSessionResult(previous => previous ? {
            ...previous,
            ...next,
            requestedFrameCount: next.requestedFrameCount ?? previous.requestedFrameCount,
            intervalSeconds: next.intervalSeconds ?? previous.intervalSeconds,
          } : next)
          if (!TERMINAL_SESSION_STATES.has(next.status.toLowerCase())) {
            timer = setTimeout(poll, POLL_INTERVAL_MS)
          }
        }
      } catch {
        if (!controller.signal.aborted && Date.now() < stopAt) {
          timer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      }
    }

    timer = setTimeout(poll, POLL_INTERVAL_MS)
    return () => {
      controller.abort()
      if (timer) clearTimeout(timer)
    }
  }, [agentId, online, sessionResult?.expiresAt, sessionResult?.sessionId, sessionResult?.status])

  const submit = async () => {
    setShowConfirmation(false)
    setSubmitting(true)
    if (captureMode === 'snapshot') setResult(null)
    else setSessionResult(null)
    try {
      const request = {
        reason: trimmedReason,
        ttl_seconds: ttlSeconds,
        scope: scope as 'virtual_desktop' | 'monitor' | 'active_window',
        monitor_id: scope === 'monitor' ? monitorId.trim() : undefined,
        watermark,
        redactions: applyRedaction ? [redaction] : [],
      }
      if (captureMode === 'session') {
        const session = await startEvidenceSession(agentId, {
          ...request,
          frame_count: frameCount,
          interval_seconds: intervalSeconds,
          long_session: frameCount > 10,
          alert_id: alertId.trim() || undefined,
          investigation_id: investigationId.trim() || undefined,
          case_id: caseId.trim() || undefined,
        })
        setSessionResult(session)
        toast.success(`Evidence Session request ${session.status}`)
      } else {
        const capture = await requestScreenCapture(agentId, request)
        setResult(capture)
        toast.success(`Screenshot request ${capture.status}`)
      }
      setShowRequest(false)
      setReason('')
    } catch (error: unknown) {
      const message =
        (error as { response?: { data?: { error?: string; message?: string } } })?.response?.data?.error ||
        (error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        'Failed to request screenshot'
      toast.error(message)
    } finally {
      setSubmitting(false)
    }
  }

  const cancelSession = async () => {
    if (!sessionResult?.sessionId) return
    setCancellingSession(true)
    try {
      const cancelled = await cancelEvidenceSession(sessionResult.sessionId)
      setSessionResult(previous => previous ? {
        ...previous,
        ...cancelled,
        frames: cancelled.frames.length > 0 ? cancelled.frames : previous.frames,
        requestedFrameCount: cancelled.requestedFrameCount ?? previous.requestedFrameCount,
        intervalSeconds: cancelled.intervalSeconds ?? previous.intervalSeconds,
      } : cancelled)
      toast.success(`Evidence Session ${cancelled.status}`)
    } catch (error: unknown) {
      const message =
        (error as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        'Failed to cancel Evidence Session'
      toast.error(message)
    } finally {
      setCancellingSession(false)
    }
  }

  return (
    <section
      className="card-sentinel rounded-xl p-6"
      style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      aria-labelledby="screen-capture-heading"
    >
      <div className="mb-5 inline-flex rounded-lg border p-1" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }} aria-label="Screen evidence mode">
        <button
          type="button"
          onClick={() => setCaptureMode('snapshot')}
          className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium ${captureMode === 'snapshot' ? 'bg-cyan-500/15 text-cyan-300' : ''}`}
          style={captureMode === 'snapshot' ? undefined : { color: 'var(--muted)' }}
          aria-pressed={captureMode === 'snapshot'}
        >
          <Camera className="h-3.5 w-3.5" /> Snapshot
        </button>
        <button
          type="button"
          onClick={() => setCaptureMode('session')}
          className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium ${captureMode === 'session' ? 'bg-cyan-500/15 text-cyan-300' : ''}`}
          style={captureMode === 'session' ? undefined : { color: 'var(--muted)' }}
          aria-pressed={captureMode === 'session'}
        >
          <Film className="h-3.5 w-3.5" /> Evidence Session
        </button>
      </div>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex gap-3">
          <div className="rounded-lg p-2.5" style={{ backgroundColor: 'var(--surface-alt)' }}>
            <Camera className="h-5 w-5" style={{ color: 'var(--fg-2)' }} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="screen-capture-heading" className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                {captureMode === 'snapshot' ? 'Remote snapshot' : 'Evidence Session'}
              </h2>
              <ReadinessBadge readiness={readiness} />
            </div>
            <p className="mt-1 max-w-2xl text-sm" style={{ color: 'var(--muted)' }}>
              {captureMode === 'snapshot'
                ? 'Request one auditable screenshot for incident investigation. This does not start screen sharing or remote control.'
                : 'Request a bounded sequence of still frames. This is not live viewing, recording, or remote control.'}
            </p>
            {readiness === 'consent_required' && (
              <p className="mt-2 flex items-center gap-1.5 text-xs text-amber-400">
                <AlertTriangle className="h-3.5 w-3.5" />
                The endpoint user must approve capture before an image is produced.
              </p>
            )}
            {actionDisabledReason && <p className="mt-2 text-xs text-amber-400">{actionDisabledReason}</p>}
            <BrokerHealth broker={broker} state={readiness} />
            <CapturePolicy policy={policy} mode={policyMode} />
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowRequest(true)}
          disabled={!canRequest || submitting}
          className="btn-sentinel-primary inline-flex min-w-fit items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
          title={actionDisabledReason || (captureMode === 'snapshot' ? 'Request a single snapshot' : 'Start a bounded Evidence Session')}
        >
          {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Camera className="h-4 w-4" />}
          {captureMode === 'snapshot' ? 'Capture snapshot' : 'Start session'}
        </button>
      </div>

      {result && <CaptureResult result={result} />}
      {sessionResult && (
        <EvidenceSessionResultView
          result={sessionResult}
          cancelling={cancellingSession}
          onCancel={cancelSession}
        />
      )}

      {showRequest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-labelledby="capture-request-title">
          <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border p-6 shadow-2xl" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 id="capture-request-title" className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                  {captureMode === 'snapshot' ? 'Capture snapshot' : 'Start Evidence Session'}
                </h3>
                <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>{hostname}</p>
              </div>
              <button type="button" onClick={() => setShowRequest(false)} className="rounded p-1" aria-label="Close screenshot request">
                <X className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
            </div>

            <label className="mt-5 block text-sm font-medium" style={{ color: 'var(--fg)' }} htmlFor="screen-capture-reason">
              Investigation reason <span className="text-red-400">*</span>
            </label>
            <textarea
              id="screen-capture-reason"
              value={reason}
              onChange={event => setReason(event.target.value)}
              maxLength={500}
              rows={4}
              autoFocus
              className="input-sentinel mt-2 w-full resize-none px-3 py-2"
              placeholder="Incident, ticket, and why visual evidence is necessary"
            />
            <div className="mt-1 flex justify-between text-xs" style={{ color: 'var(--muted)' }}>
              <span>At least 10 characters. Stored in the audit trail.</span>
              <span>{reason.length}/500</span>
            </div>

            <label className="mt-4 block text-sm font-medium" style={{ color: 'var(--fg)' }} htmlFor="screen-capture-ttl">
              Artifact retention request
            </label>
            <select id="screen-capture-ttl" value={ttlSeconds} onChange={event => setTtlSeconds(Number(event.target.value))} className="input-sentinel mt-2 w-full px-3 py-2">
              <option value={300}>5 minutes</option>
              <option value={900}>15 minutes</option>
            </select>

            {captureMode === 'session' && (
              <div className="mt-4 grid grid-cols-2 gap-3 rounded-lg border p-3" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
                <label className="text-sm font-medium" style={{ color: 'var(--fg)' }} htmlFor="evidence-frame-count">
                  Frames
                  <select id="evidence-frame-count" value={frameCount} onChange={event => setFrameCount(Number(event.target.value))} className="input-sentinel mt-2 w-full px-3 py-2">
                    {[2, 3, 5, 8, 10, 15, 20, 30].map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
                <label className="text-sm font-medium" style={{ color: 'var(--fg)' }} htmlFor="evidence-frame-interval">
                  Interval
                  <select id="evidence-frame-interval" value={intervalSeconds} onChange={event => setIntervalSeconds(Number(event.target.value))} className="input-sentinel mt-2 w-full px-3 py-2">
                    {[5, 10, 30, 60].map(value => <option key={value} value={value}>{value} seconds</option>)}
                  </select>
                </label>
                <p className="col-span-2 text-xs" style={{ color: 'var(--muted)' }}>
                  Requested duration: {(frameCount - 1) * intervalSeconds} seconds. Sessions above 10 frames require a second authorized operator's approval; hard cap 30 minutes.
                </p>
                <div className="col-span-2 grid gap-2 sm:grid-cols-3">
                  <input value={alertId} onChange={event => setAlertId(event.target.value)} maxLength={128} className="input-sentinel px-3 py-2 text-xs" placeholder="Optional alert ID" />
                  <input value={investigationId} onChange={event => setInvestigationId(event.target.value)} maxLength={128} className="input-sentinel px-3 py-2 text-xs" placeholder="Optional investigation ID" />
                  <input value={caseId} onChange={event => setCaseId(event.target.value)} maxLength={128} className="input-sentinel px-3 py-2 text-xs" placeholder="Optional case ID" />
                </div>
              </div>
            )}

            <label className="mt-4 block text-sm font-medium" style={{ color: 'var(--fg)' }} htmlFor="screen-capture-scope">
              Capture scope
            </label>
            <select id="screen-capture-scope" value={scope} onChange={event => setScope(event.target.value)} className="input-sentinel mt-2 w-full px-3 py-2">
              {allowedScopes.includes('virtual_desktop') && <option value="virtual_desktop">Full virtual desktop</option>}
              {allowedScopes.includes('monitor') && <option value="monitor">Specific monitor</option>}
              {allowedScopes.includes('active_window') && <option value="active_window">Active window</option>}
            </select>
            {scope === 'monitor' && (
              brokerDisplays.length > 0 ? (
                <select value={monitorId} onChange={event => setMonitorId(event.target.value)} className="input-sentinel mt-2 w-full px-3 py-2" aria-label="Monitor identifier">
                  {brokerDisplays.map(display => (
                    <option key={display.id} value={display.id}>
                      {display.id} — {display.width}×{display.height}{display.primary ? ' (primary)' : ''}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  value={monitorId}
                  onChange={event => setMonitorId(event.target.value)}
                  maxLength={128}
                  className="input-sentinel mt-2 w-full px-3 py-2"
                  placeholder="Native monitor identifier"
                  aria-label="Monitor identifier"
                />
              )
            )}

            <label className="mt-4 flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
              <input type="checkbox" checked={watermark} disabled={!supportsWatermark} onChange={event => setWatermark(event.target.checked)} />
              Apply fixed product and UTC timestamp watermark
            </label>

            <label className="mt-3 flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
              <input type="checkbox" checked={applyRedaction} disabled={redactionRequired || !supportsRedaction} onChange={event => setApplyRedaction(event.target.checked)} />
              Redact a screen region{redactionRequired ? ' (required by policy)' : ''}
            </label>
            {applyRedaction && (
              <div className="mt-2 grid grid-cols-2 gap-2" aria-label="Redaction rectangle in basis points">
                {(['x', 'y', 'width', 'height'] as const).map(field => (
                  <label key={field} className="text-xs" style={{ color: 'var(--muted)' }}>
                    {field} (0–10000)
                    <input
                      type="number"
                      min={field === 'width' || field === 'height' ? 1 : 0}
                      max={10000}
                      value={redaction[field]}
                      onChange={event => setRedaction(current => ({ ...current, [field]: Number(event.target.value) }))}
                      className="input-sentinel mt-1 w-full px-3 py-2"
                    />
                  </label>
                ))}
              </div>
            )}
            {!redactionValid && <p className="mt-1 text-xs text-red-400">The redaction rectangle must stay inside the 0–10000 screen coordinate space.</p>}

            <div className="mt-5 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300">
              <Lock className="mt-0.5 h-4 w-4 shrink-0" />
              Captures may contain personal or sensitive information. Use only when necessary and according to tenant policy.
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setShowRequest(false)} className="btn-sentinel-secondary rounded-lg px-4 py-2 text-sm">Cancel</button>
              <button
                type="button"
                onClick={() => setShowConfirmation(true)}
                disabled={!requestValid}
                className="btn-sentinel-primary rounded-lg px-4 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
              >
                Review request
              </button>
            </div>
          </div>
        </div>
      )}

      {showConfirmation && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/75 p-4" role="alertdialog" aria-modal="true" aria-labelledby="capture-confirm-title">
          <div className="w-full max-w-md rounded-xl border p-6 shadow-2xl" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
            <AlertTriangle className="h-8 w-8 text-amber-400" />
            <h3 id="capture-confirm-title" className="mt-3 text-lg font-semibold" style={{ color: 'var(--fg)' }}>Confirm privacy-sensitive capture</h3>
            <p className="mt-2 text-sm" style={{ color: 'var(--muted)' }}>
              {captureMode === 'snapshot'
                ? <>This requests one snapshot of the current display on <strong style={{ color: 'var(--fg)' }}>{hostname}</strong>.</>
                : <>This requests {frameCount} still frames, {intervalSeconds} seconds apart, from <strong style={{ color: 'var(--fg)' }}>{hostname}</strong>.</>}
              {' '}The reason, operator, target, and result must be audited. No live viewing or input control is started.
            </p>
            {readiness === 'consent_required' && <p className="mt-3 text-sm text-amber-400">The user will still need to approve the operating-system capture prompt.</p>}
            {captureMode === 'session' && frameCount > 10 && <p className="mt-3 text-sm text-amber-400">This long session will remain pending until a different operator with response approval permission approves it.</p>}
            <p className="mt-3 text-sm" style={{ color: 'var(--muted)' }}>
              Effective policy: <strong style={{ color: 'var(--fg)' }}>{policyModeLabel(policyMode)}</strong>
              {policyMode === 'notify' && policy?.notify_timing ? ` (${policy.notify_timing.replace(/_/g, ' ')})` : ''}.
            </p>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setShowConfirmation(false)} className="btn-sentinel-secondary rounded-lg px-4 py-2 text-sm">Back</button>
              <button type="button" onClick={submit} className="btn-sentinel-primary rounded-lg px-4 py-2 text-sm">
                {captureMode === 'snapshot' ? 'Request snapshot' : 'Start bounded session'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function screenCaptureReadiness(capability?: ScreenCapability): ScreenSessionBrokerState {
  if (!capability) return 'unsupported'
  const maturity = String(capability.maturity || '').toLowerCase()
  const observed = String(capability.observed || '').toLowerCase()
  if (['unsupported', 'disabled'].includes(maturity)) return 'unsupported'
  if (maturity === 'unavailable' && !capability.session_broker) return 'unsupported'
  if (observed === 'not_observed' && !capability.session_broker) return 'broker_unavailable'

  const brokerState = String(capability.session_broker?.state || '').toLowerCase() as ScreenSessionBrokerState
  if (!BROKER_STATES.has(brokerState)) return 'broker_unavailable'

  const brokerCapabilities = (capability.session_broker?.capabilities || []).map(value => value.toLowerCase())
  const brokerCaptureCapable = brokerCapabilities.some(value => CAPABILITY_IDS.has(value))
  if (!brokerCaptureCapable) return 'broker_unavailable'
  if (brokerState !== 'ready') return brokerState
  return capability.session_broker?.ready === true && brokerCaptureCapable
    ? 'ready'
    : 'broker_unavailable'
}

function screenCapturePolicyMode(policy?: ScreenCapturePolicyHealth): ScreenCapturePolicyMode {
  const mode = String(policy?.mode || '').toLowerCase() as ScreenCapturePolicyMode
  if (!['silent', 'notify', 'consent_required', 'disabled'].includes(mode)) return 'disabled'
  return policyEvidenceFresh(policy?.policy) ? mode : 'disabled'
}

function ReadinessBadge({ readiness }: { readiness: ScreenSessionBrokerState }) {
  const labels: Record<ScreenSessionBrokerState, string> = {
    ready: 'Ready',
    no_user_session: 'No user session',
    locked: 'Session locked',
    consent_required: 'Consent required',
    permission_denied: 'Permission denied',
    portal_unavailable: 'Portal unavailable',
    broker_unavailable: 'Broker unavailable',
    unsupported: 'Unsupported',
  }
  const classes: Record<ScreenSessionBrokerState, string> = {
    ready: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
    no_user_session: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
    locked: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
    consent_required: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
    permission_denied: 'border-red-500/30 bg-red-500/10 text-red-400',
    portal_unavailable: 'border-red-500/30 bg-red-500/10 text-red-400',
    broker_unavailable: 'border-red-500/30 bg-red-500/10 text-red-400',
    unsupported: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
  }
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${classes[readiness]}`}>{labels[readiness]}</span>
}

function BrokerHealth({ broker, state }: { broker?: ScreenSessionBrokerHealth; state: ScreenSessionBrokerState }) {
  return (
    <div className="mt-3 rounded-lg border px-3 py-2 text-xs" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-medium" style={{ color: 'var(--fg-2)' }}>Session broker</span>
        <ReadinessBadge readiness={state} />
        <span style={{ color: 'var(--muted)' }}>
          Observed {formatTimestamp(broker?.observed_at || null)}
        </span>
      </div>
      <p className="mt-1" style={{ color: 'var(--muted)' }}>
        {broker?.detail || brokerStateMessage(state) || 'Session broker health is not available.'}
      </p>
      <p className="mt-1 font-mono" style={{ color: 'var(--muted)' }}>
        Capabilities: {broker?.capabilities?.length ? broker.capabilities.join(', ') : 'none reported'}
      </p>
      <p className="mt-1 font-mono" style={{ color: 'var(--muted)' }}>
        {broker?.platform || 'unknown platform'} / {broker?.transport || 'unknown transport'} / {broker?.consent_model || 'unknown consent model'}
      </p>
      <p className="mt-1 font-mono" style={{ color: 'var(--muted)' }}>
        Silent: {broker?.silent_supported === true ? 'supported' : 'not supported'} / bounded session: {broker?.session_capture_supported === true ? 'supported' : 'not supported'}
      </p>
      {(broker?.degraded_reason || broker?.unsupported_reason) && (
        <p className="mt-1 text-amber-400">{broker.degraded_reason || broker.unsupported_reason}</p>
      )}
    </div>
  )
}

function CapturePolicy({ policy, mode }: { policy?: ScreenCapturePolicyHealth; mode: ScreenCapturePolicyMode }) {
  const styles: Record<ScreenCapturePolicyMode, string> = {
    silent: 'border-red-500/30 bg-red-500/10 text-red-300',
    notify: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
    consent_required: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    disabled: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
  }
  const evidence = policy?.policy

  return (
    <div className="mt-2 rounded-lg border px-3 py-2 text-xs" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium" style={{ color: 'var(--fg-2)' }}>Effective capture policy</span>
        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${styles[mode]}`}>{policyModeLabel(mode)}</span>
        {mode === 'notify' && policy?.notify_timing && <span style={{ color: 'var(--muted)' }}>{policy.notify_timing.replace(/_/g, ' ')}</span>}
      </div>
      <p className="mt-1 font-mono break-all" style={{ color: 'var(--muted)' }}>
        {evidence?.id || 'effective policy unavailable'} / v{evidence?.version || 1}
        {evidence?.hash ? ` / sha256 ${evidence.hash}` : ''}
      </p>
      <p className="mt-1" style={{ color: 'var(--muted)' }}>
        Evidence expires {formatTimestamp(evidenceExpiry(evidence))}
      </p>
      <p className="mt-1" style={{ color: 'var(--muted)' }}>
        Scopes: {(policy?.allowed_scopes || evidence?.allowed_scopes || ['virtual_desktop']).join(', ')}
        {(policy?.redaction_required ?? evidence?.redaction_required) ? ' / redaction required' : ''}
      </p>
    </div>
  )
}

function policyEvidenceFresh(evidence?: ScreenCapturePolicyHealth['policy']): boolean {
  if (!evidence) return false
  const now = Date.now()
  const issuedAt = typeof evidence.issued_at_ms === 'number'
    ? evidence.issued_at_ms
    : evidence.issued_at ? Date.parse(evidence.issued_at) : Number.NaN
  const expiresAt = typeof evidence.expires_at_ms === 'number'
    ? evidence.expires_at_ms
    : evidence.expires_at ? Date.parse(evidence.expires_at) : Number.NaN
  return Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && issuedAt <= now + 60_000 && expiresAt > now
}

function evidenceExpiry(evidence?: ScreenCapturePolicyHealth['policy']): string | null {
  if (!evidence) return null
  if (typeof evidence.expires_at_ms === 'number') return new Date(evidence.expires_at_ms).toISOString()
  return evidence.expires_at || null
}

function policyModeLabel(mode: ScreenCapturePolicyMode): string {
  const labels: Record<ScreenCapturePolicyMode, string> = {
    silent: 'Silent',
    notify: 'Notify',
    consent_required: 'Consent required',
    disabled: 'Disabled',
  }
  return labels[mode]
}

function brokerStateMessage(state: ScreenSessionBrokerState, fallback?: string): string | null {
  const messages: Record<ScreenSessionBrokerState, string | null> = {
    ready: null,
    no_user_session: 'No interactive user session is available for a screenshot.',
    locked: 'The interactive user session is locked; capture remains disabled.',
    consent_required: 'The operating system will ask the endpoint user to approve this one-time capture.',
    permission_denied: 'The operating-system screen capture permission was denied.',
    portal_unavailable: 'The desktop capture portal is unavailable on this endpoint.',
    broker_unavailable: 'Session broker health or screen-capture capability was not reported.',
    unsupported: fallback || 'Screen capture or its session broker is unsupported on this endpoint.',
  }
  return messages[state]
}

function CaptureResult({ result }: { result: ScreenCaptureResult }) {
  const status = result.status.toLowerCase()
  const ready = status === 'ready'
  const terminalError = status === 'expired' || status === 'failed'
  return (
    <div className="mt-5 rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex items-center gap-2">
        {ready ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : terminalError ? <AlertCircle className="h-4 w-4 text-red-400" /> : <Clock className="h-4 w-4 text-cyan-400" />}
        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Request {result.status}</span>
        {!TERMINAL_CAPTURE_STATES.has(status) && <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" aria-label="Waiting for screenshot artifact" />}
      </div>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3 lg:grid-cols-4">
        <ResultMeta label="Command" value={result.commandId || 'Pending assignment'} />
        <ResultMeta label="Artifact" value={result.artifactId || 'Pending assignment'} />
        <ResultMeta label="Requested" value={formatTimestamp(result.requestedAt)} />
        <ResultMeta label="Captured" value={formatTimestamp(result.capturedAt)} />
        <ResultMeta label="Uploaded" value={formatTimestamp(result.uploadedAt)} />
        <ResultMeta label="Artifact expires" value={formatTimestamp(result.expiresAt)} />
        <ResultMeta label="Display" value={result.display || 'Not reported'} />
        <ResultMeta label="Scope" value={result.scope || 'Not reported'} />
        <ResultMeta label="Coverage" value={result.captureCoverage || 'Platform default'} />
        <ResultMeta label="Protections" value={`${result.watermark === true ? 'watermarked' : result.watermark === false ? 'no watermark' : 'not reported'} / ${result.redactionCount ?? 'unknown'} redaction(s)`} />
        <ResultMeta label="Content" value={contentMetadata(result)} />
      </dl>
      {result.consentRequired && <p className="mt-3 text-xs text-amber-400">Waiting for endpoint user consent.</p>}
      {status === 'pending' && <p className="mt-3 text-xs text-cyan-400">Waiting for the endpoint to upload the screenshot.</p>}
      {status === 'expired' && <p className="mt-3 text-xs text-red-400">The screenshot artifact expired and is no longer available.</p>}
      {status === 'failed' && <p className="mt-3 text-xs text-red-400">The endpoint could not produce this screenshot.</p>}
      {ready && !result.artifactUrl && <p className="mt-3 text-xs text-amber-400">Artifact is ready, but no authenticated content URL was returned.</p>}
      {ready && result.artifactUrl && (
        <div className="mt-4">
          <img src={result.artifactUrl} alt={`Authenticated screenshot artifact for command ${result.commandId || ''}`} className="max-h-[32rem] w-auto max-w-full rounded-lg border object-contain" style={{ borderColor: 'var(--border)' }} />
          <a href={result.artifactUrl} target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs text-cyan-400 hover:underline">Open authenticated artifact</a>
        </div>
      )}
    </div>
  )
}

function EvidenceSessionResultView({
  result,
  cancelling,
  onCancel,
}: {
  result: EvidenceSessionResult
  cancelling: boolean
  onCancel: () => void
}) {
  const comparableFrames = result.frames.filter(frame => frame.status.toLowerCase() === 'ready' && frame.artifactUrl)
  const [leftIndex, setLeftIndex] = useState<number | null>(null)
  const [rightIndex, setRightIndex] = useState<number | null>(null)
  const [exportResult, setExportResult] = useState<EvidenceExportResult | null>(null)
  const [serverDiff, setServerDiff] = useState<EvidenceServerDiffResult | null>(null)
  const [productAction, setProductAction] = useState<'approve' | 'export' | 'diff' | null>(null)

  useEffect(() => {
    if (leftIndex === null || !comparableFrames.some(frame => frame.index === leftIndex)) {
      setLeftIndex(comparableFrames[0]?.index ?? null)
    }
    if (rightIndex === null || !comparableFrames.some(frame => frame.index === rightIndex)) {
      setRightIndex(comparableFrames[1]?.index ?? comparableFrames[0]?.index ?? null)
    }
  }, [comparableFrames, leftIndex, rightIndex])

  const left = comparableFrames.find(frame => frame.index === leftIndex)
  const right = comparableFrames.find(frame => frame.index === rightIndex)
  const terminal = TERMINAL_SESSION_STATES.has(result.status.toLowerCase())

  const runProductAction = async (action: 'approve' | 'export' | 'diff') => {
    if (!result.sessionId) return
    setProductAction(action)
    try {
      if (action === 'approve') {
        await approveEvidenceSession(result.sessionId)
        toast.success('Evidence Session approved; scheduling can begin.')
      } else if (action === 'export') {
        setExportResult(await createEvidenceExport(result.sessionId))
        toast.success('Evidence package generated.')
      } else if (left?.artifactId && right?.artifactId) {
        setServerDiff(await createEvidenceServerDiff(result.sessionId, left.artifactId, right.artifactId))
        toast.success('Server-side bounded diff recorded.')
      }
    } catch (error: unknown) {
      const message = (error as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        `Evidence ${action} failed`
      toast.error(message)
    } finally {
      setProductAction(null)
    }
  }

  return (
    <div className="mt-5 rounded-lg border p-4" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-alt)' }}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {result.status.toLowerCase() === 'completed'
            ? <CheckCircle className="h-4 w-4 text-emerald-400" />
            : result.status.toLowerCase() === 'partial'
              ? <AlertTriangle className="h-4 w-4 text-amber-400" />
            : terminal
              ? <AlertCircle className="h-4 w-4 text-red-400" />
              : <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />}
          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Evidence Session {result.status}</span>
        </div>
        {!terminal && result.cancelable && result.sessionId && (
          <button type="button" onClick={onCancel} disabled={cancelling} className="btn-sentinel-secondary inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs disabled:opacity-50">
            {cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Square className="h-3.5 w-3.5" />}
            Cancel session
          </button>
        )}
      </div>

      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3 lg:grid-cols-5">
        <ResultMeta label="Session" value={result.sessionId || 'Not reported'} />
        <ResultMeta label="Command" value={result.commandId || 'Not reported'} />
        <ResultMeta label="Requested frames" value={result.requestedFrameCount?.toString() || 'Not reported'} />
        <ResultMeta label="Observed ready" value={result.completedFrames.toString()} />
        <ResultMeta label="Interval" value={result.intervalSeconds === null ? 'Not reported' : `${result.intervalSeconds}s`} />
        <ResultMeta label="Requested" value={formatTimestamp(result.requestedAt)} />
        <ResultMeta label="Expires" value={formatTimestamp(result.expiresAt)} />
      </dl>
      {result.consentRequired && <p className="mt-3 text-xs text-amber-400">Endpoint consent is still required; no missing frame is treated as captured.</p>}
      {result.failureReason && <p className="mt-3 text-xs text-red-400">{result.failureReason}</p>}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {result.status.toLowerCase() === 'pending_approval' && (
          <button type="button" disabled={productAction !== null} onClick={() => runProductAction('approve')} className="btn-sentinel-secondary rounded-lg px-3 py-1.5 text-xs disabled:opacity-50">
            {productAction === 'approve' ? 'Approving…' : 'Approve long session'}
          </button>
        )}
        {['completed', 'partial'].includes(result.status.toLowerCase()) && (
          <button type="button" disabled={productAction !== null} onClick={() => runProductAction('export')} className="btn-sentinel-secondary rounded-lg px-3 py-1.5 text-xs disabled:opacity-50">
            {productAction === 'export' ? 'Packaging…' : 'Generate evidence package'}
          </button>
        )}
        {exportResult && (
          <a href={exportResult.downloadUrl} className="text-xs text-cyan-400 hover:underline">
            Download ZIP · {formatBytes(exportResult.size)} · SHA-256 {exportResult.sha256.slice(0, 12)}…
          </a>
        )}
      </div>
      {result.approvalStatus && result.approvalStatus !== 'not_required' && (
        <p className="mt-2 text-[11px] text-amber-400">
          Approval: {result.approvalStatus} · expires {formatTimestamp(result.approvalExpiresAt)}
        </p>
      )}
      {(result.links.alertId || result.links.investigationId || result.links.caseId) && (
        <p className="mt-2 break-all font-mono text-[10px]" style={{ color: 'var(--muted)' }}>
          Alert {result.links.alertId || '—'} · Investigation {result.links.investigationId || '—'} · Case {result.links.caseId || '—'}
        </p>
      )}

      <div className="mt-5 rounded-lg border p-3" style={{ borderColor: 'var(--border)' }}>
        <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Correlated endpoint context</h3>
        {!result.context ? (
          <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>Context has not been reported by the server.</p>
        ) : (
          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <ContextSource label="Process telemetry" source={result.context.process} />
            <ContextSource label="Network telemetry" source={result.context.network} />
          </div>
        )}
      </div>

      <div className="mt-5">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Frame timeline</h3>
        {result.frames.length === 0 ? (
          <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>No frames have been reported by the server.</p>
        ) : (
          <ol className="mt-3 space-y-2">
            {result.frames.map(frame => <EvidenceFrameRow key={`${frame.index}-${frame.artifactId || 'pending'}`} frame={frame} />)}
          </ol>
        )}
      </div>

      <div className="mt-5 rounded-lg border p-3" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-2">
          <GitCompare className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Compare two reported frames</h3>
        </div>
        {comparableFrames.length < 2 ? (
          <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>At least two ready frames with authenticated artifact URLs are required.</p>
        ) : (
          <>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <FrameSelector label="Left frame" frames={comparableFrames} value={leftIndex} onChange={setLeftIndex} />
              <FrameSelector label="Right frame" frames={comparableFrames} value={rightIndex} onChange={setRightIndex} />
            </div>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              <ComparedFrame frame={left} />
              <ComparedFrame frame={right} />
            </div>
            <AutomaticVisualDiff left={left} right={right} />
            <button
              type="button"
              disabled={productAction !== null || !left?.artifactId || !right?.artifactId || left.index === right.index}
              onClick={() => runProductAction('diff')}
              className="btn-sentinel-secondary mt-2 rounded-lg px-3 py-1.5 text-xs disabled:opacity-50"
            >
              {productAction === 'diff' ? 'Recording diff…' : 'Record bounded server diff'}
            </button>
            {serverDiff && (
              <pre className="mt-2 max-h-40 overflow-auto rounded bg-black/20 p-2 text-[10px]" style={{ color: 'var(--muted)' }}>
                {JSON.stringify(serverDiff.metrics, null, 2)}
              </pre>
            )}
          </>
        )}
      </div>
    </div>
  )
}

type VisualDiffResult = {
  changedPixels: number
  totalPixels: number
  changedPercent: number
  bounds: { x: number; y: number; width: number; height: number } | null
}

function AutomaticVisualDiff({ left, right }: { left?: EvidenceSessionFrame; right?: EvidenceSessionFrame }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [result, setResult] = useState<VisualDiffResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setResult(null)
    setError(null)

    if (!left?.artifactUrl || !right?.artifactUrl || left.index === right.index) return

    Promise.all([loadSameOriginImage(left.artifactUrl), loadSameOriginImage(right.artifactUrl)])
      .then(([leftImage, rightImage]) => {
        if (cancelled || !canvasRef.current) return
        const compared = renderVisualDiff(canvasRef.current, leftImage, rightImage)
        setResult(compared)
      })
      .catch(() => {
        if (!cancelled) setError('Authenticated frames could not be decoded for local visual comparison.')
      })

    return () => { cancelled = true }
  }, [left?.artifactUrl, left?.index, right?.artifactUrl, right?.index])

  if (!left?.artifactUrl || !right?.artifactUrl || left.index === right.index) {
    return <p className="mt-2 text-[11px]" style={{ color: 'var(--muted)' }}>Select two different ready frames to calculate a local pixel diff.</p>
  }

  return (
    <div className="mt-3 rounded-lg border p-3" style={{ borderColor: 'var(--border)' }}>
      <p className="text-xs font-medium" style={{ color: 'var(--fg-2)' }}>Automatic visual change map</p>
      {error && <p className="mt-2 text-[11px] text-red-400">{error}</p>}
      <canvas ref={canvasRef} className="mt-2 max-h-80 w-full rounded object-contain" aria-label="Local pixel difference heatmap" />
      {result && (
        <p className="mt-2 font-mono text-[11px]" style={{ color: 'var(--muted)' }}>
          Changed {result.changedPixels.toLocaleString()} / {result.totalPixels.toLocaleString()} sampled pixels ({result.changedPercent.toFixed(2)}%)
          {result.bounds ? ` · region x=${result.bounds.x}, y=${result.bounds.y}, w=${result.bounds.width}, h=${result.bounds.height}` : ' · no changed region'}
        </p>
      )}
      <p className="mt-1 text-[10px]" style={{ color: 'var(--muted)' }}>Computed locally in this browser at a bounded resolution; red pixels exceeded the RGB threshold. This is an operator aid, not a forensic equivalence claim.</p>
    </div>
  )
}

function loadSameOriginImage(url: string): Promise<HTMLImageElement> {
  const parsed = new URL(url, window.location.origin)
  if (parsed.origin !== window.location.origin) return Promise.reject(new Error('cross-origin artifact'))

  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => resolve(image)
    image.onerror = () => reject(new Error('image decode failed'))
    image.src = parsed.href
  })
}

function renderVisualDiff(canvas: HTMLCanvasElement, left: HTMLImageElement, right: HTMLImageElement): VisualDiffResult {
  const maxWidth = 1024
  const maxHeight = 768
  const scale = Math.min(maxWidth / Math.max(left.naturalWidth, right.naturalWidth), maxHeight / Math.max(left.naturalHeight, right.naturalHeight), 1)
  const width = Math.max(1, Math.floor(Math.max(left.naturalWidth, right.naturalWidth) * scale))
  const height = Math.max(1, Math.floor(Math.max(left.naturalHeight, right.naturalHeight) * scale))
  const scratch = document.createElement('canvas')
  scratch.width = width
  scratch.height = height
  const scratchContext = scratch.getContext('2d', { willReadFrequently: true })
  const output = canvas.getContext('2d')
  if (!scratchContext || !output) throw new Error('canvas unavailable')

  scratchContext.clearRect(0, 0, width, height)
  scratchContext.drawImage(left, 0, 0, width, height)
  const leftPixels = scratchContext.getImageData(0, 0, width, height)
  scratchContext.clearRect(0, 0, width, height)
  scratchContext.drawImage(right, 0, 0, width, height)
  const rightPixels = scratchContext.getImageData(0, 0, width, height)
  const heatmap = new ImageData(width, height)
  let changedPixels = 0
  let minX = width
  let minY = height
  let maxX = -1
  let maxY = -1

  for (let offset = 0; offset < leftPixels.data.length; offset += 4) {
    const delta = Math.max(
      Math.abs(leftPixels.data[offset] - rightPixels.data[offset]),
      Math.abs(leftPixels.data[offset + 1] - rightPixels.data[offset + 1]),
      Math.abs(leftPixels.data[offset + 2] - rightPixels.data[offset + 2])
    )
    const changed = delta >= 24
    const pixel = offset / 4
    const x = pixel % width
    const y = Math.floor(pixel / width)
    if (changed) {
      changedPixels += 1
      minX = Math.min(minX, x)
      minY = Math.min(minY, y)
      maxX = Math.max(maxX, x)
      maxY = Math.max(maxY, y)
    }
    heatmap.data[offset] = changed ? 255 : Math.floor(rightPixels.data[offset] * 0.2)
    heatmap.data[offset + 1] = changed ? 48 : Math.floor(rightPixels.data[offset + 1] * 0.2)
    heatmap.data[offset + 2] = changed ? 48 : Math.floor(rightPixels.data[offset + 2] * 0.2)
    heatmap.data[offset + 3] = 255
  }

  canvas.width = width
  canvas.height = height
  output.putImageData(heatmap, 0, 0)
  const totalPixels = width * height
  return {
    changedPixels,
    totalPixels,
    changedPercent: totalPixels === 0 ? 0 : (changedPixels / totalPixels) * 100,
    bounds: changedPixels === 0 ? null : { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 },
  }
}

function ContextSource({
  label,
  source,
}: {
  label: string
  source: EvidenceSessionContextSource
}) {
  return (
    <section className="rounded-lg border p-3" style={{ borderColor: 'var(--border)' }}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-xs font-medium" style={{ color: 'var(--fg-2)' }}>{label}</h4>
        <span className="font-mono text-[10px]" style={{ color: source.state === 'observed' ? 'var(--success)' : 'var(--muted)' }}>
          {source.state} · {source.observedCount ?? 'unknown'}
        </span>
      </div>
      {source.reason && <p className="mt-1 text-[11px]" style={{ color: 'var(--muted)' }}>{source.reason}</p>}
      {source.events.length > 0 && (
        <ol className="mt-2 space-y-1">
          {source.events.slice(0, 5).map((event, index) => (
            <li key={`${String(event.event_id || index)}-${String(event.timestamp || '')}`} className="truncate font-mono text-[10px]" style={{ color: 'var(--fg-2)' }}>
              {formatContextEvent(event)}
            </li>
          ))}
        </ol>
      )}
      {source.truncated && <p className="mt-1 text-[10px] text-amber-400">Additional matching events were omitted.</p>}
    </section>
  )
}

function formatContextEvent(event: Record<string, unknown>): string {
  const timestamp = typeof event.timestamp === 'string' ? formatTimestamp(event.timestamp) : 'time not reported'
  const eventType = typeof event.event_type === 'string' ? event.event_type : 'event'
  const subject = [event.process_name, event.destination_ip, event.domain]
    .find(value => typeof value === 'string' && value.length > 0)
  return `${timestamp} · ${eventType}${subject ? ` · ${String(subject)}` : ''}`
}

function EvidenceFrameRow({ frame }: { frame: EvidenceSessionFrame }) {
  return (
    <li className="flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between" style={{ borderColor: 'var(--border)' }}>
      <div>
        <p className="text-xs font-medium" style={{ color: 'var(--fg-2)' }}>Frame {frame.index + 1} · {frame.status}</p>
        <p className="mt-1 font-mono text-[11px]" style={{ color: 'var(--muted)' }}>
          {formatTimestamp(frame.capturedAt)} · {frame.artifactId || 'artifact not reported'}
        </p>
        {frame.failureReason && <p className="mt-1 text-[11px] text-red-400">{frame.failureReason}</p>}
      </div>
      {frame.artifactUrl && <a href={frame.artifactUrl} target="_blank" rel="noreferrer" className="text-xs text-cyan-400 hover:underline">Open frame</a>}
    </li>
  )
}

function FrameSelector({ label, frames, value, onChange }: { label: string; frames: EvidenceSessionFrame[]; value: number | null; onChange: (value: number) => void }) {
  return (
    <label className="text-xs" style={{ color: 'var(--muted)' }}>
      {label}
      <select value={value ?? ''} onChange={event => onChange(Number(event.target.value))} className="input-sentinel mt-1 w-full px-3 py-2">
        {frames.map(frame => <option key={frame.index} value={frame.index}>Frame {frame.index + 1} · {formatTimestamp(frame.capturedAt)}</option>)}
      </select>
    </label>
  )
}

function ComparedFrame({ frame }: { frame?: EvidenceSessionFrame }) {
  if (!frame?.artifactUrl) return null
  return (
    <figure className="rounded-lg border p-2" style={{ borderColor: 'var(--border)' }}>
      <img src={frame.artifactUrl} alt={`Evidence Session frame ${frame.index + 1}`} className="max-h-80 w-full rounded object-contain" />
      <figcaption className="mt-2 break-all font-mono text-[10px]" style={{ color: 'var(--muted)' }}>
        Frame {frame.index + 1} · {formatTimestamp(frame.capturedAt)} · {frame.sha256 ? `SHA-256 ${frame.sha256}` : 'hash not reported'}
      </figcaption>
    </figure>
  )
}

function ResultMeta({ label, value }: { label: string; value: string }) {
  return <div><dt style={{ color: 'var(--muted)' }}>{label}</dt><dd className="mt-0.5 break-all font-mono" style={{ color: 'var(--fg-2)' }}>{value}</dd></div>
}

function formatTimestamp(value: string | null): string {
  if (!value) return 'Not reported'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function contentMetadata(result: ScreenCaptureResult): string {
  const values: string[] = []
  if (result.mime) values.push(result.mime)
  if (result.size !== null) values.push(formatBytes(result.size))
  if (result.sha256) values.push(`SHA-256 ${result.sha256}`)
  return values.join(' / ') || 'Not reported'
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}
