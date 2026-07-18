import axios from 'axios'

export interface ScreenCaptureRequest {
  reason: string
  ttl_seconds?: number
  display?: string
  scope?: 'virtual_desktop' | 'monitor' | 'active_window'
  monitor_id?: string
  watermark?: boolean
  redactions?: ScreenRedaction[]
}

export interface ScreenRedaction {
  x: number
  y: number
  width: number
  height: number
}

export interface ScreenCaptureResult {
  commandId: string | null
  artifactId: string | null
  status: string
  requestedAt: string | null
  expiresAt: string | null
  artifactUrl: string | null
  mime: string | null
  size: number | null
  sha256: string | null
  capturedAt: string | null
  uploadedAt: string | null
  display: string | null
  scope: string | null
  monitorId: string | null
  watermark: boolean | null
  redactionCount: number | null
  consentRequired: boolean
  consentModel: string | null
  captureCoverage: string | null
}

export interface EvidenceSessionRequest extends ScreenCaptureRequest {
  frame_count: number
  interval_seconds: number
  long_session?: boolean
  alert_id?: string
  investigation_id?: string
  case_id?: string
}

export interface EvidenceSessionFrame {
  index: number
  status: string
  artifactId: string | null
  artifactUrl: string | null
  capturedAt: string | null
  mime: string | null
  size: number | null
  sha256: string | null
  failureReason: string | null
}

export interface EvidenceSessionResult {
  sessionId: string | null
  commandId: string | null
  status: string
  requestedAt: string | null
  expiresAt: string | null
  requestedFrameCount: number | null
  intervalSeconds: number | null
  completedFrames: number
  consentRequired: boolean
  cancelable: boolean
  failureReason: string | null
  frames: EvidenceSessionFrame[]
  context: EvidenceSessionContext | null
  approvalStatus: string | null
  approvalExpiresAt: string | null
  approvedAt: string | null
  links: { alertId: string | null; investigationId: string | null; caseId: string | null }
}

export interface EvidenceExportResult {
  id: string
  sha256: string
  size: number
  expiresAt: string | null
  downloadUrl: string
}

export interface EvidenceServerDiffResult {
  id: string
  expiresAt: string | null
  metrics: Record<string, unknown>
}

export interface EvidenceSessionContextSource {
  state: 'observed' | 'not_observed' | 'unavailable' | string
  reason: string | null
  observedCount: number | null
  truncated: boolean
  events: Record<string, unknown>[]
}

export interface EvidenceSessionContext {
  generatedAt: string | null
  process: EvidenceSessionContextSource
  network: EvidenceSessionContextSource
}

type ApiRecord = Record<string, unknown>

/**
 * Screen-capture v1 transport and response normalization, isolated so components
 * never depend on the API's snake_case envelope.
 */
export async function requestScreenCapture(
  agentId: string,
  request: ScreenCaptureRequest
): Promise<ScreenCaptureResult> {
  const response = await axios.post(
    `/api/v1/live-response/${encodeURIComponent(agentId)}/screen-capture`,
    request
  )
  const root = asRecord(response.data)
  const data = asRecord(root.data ?? root)
  return normalizeScreenCapture(data)
}

export async function getScreenCaptureArtifact(
  agentId: string,
  artifactId: string,
  signal?: AbortSignal
): Promise<ScreenCaptureResult> {
  const response = await axios.get(
    `/api/v1/live-response/${encodeURIComponent(agentId)}/screen-captures/${encodeURIComponent(artifactId)}`,
    { signal }
  )
  const root = asRecord(response.data)
  return normalizeScreenCapture(asRecord(root.data ?? root))
}

/**
 * Evidence Session API contract. Orchestration is server-side and relies on
 * the existing one-shot screen-capture capability and effective policy.
 *
 * POST /live-response/:agent_id/evidence-sessions
 * GET  /live-response/evidence-sessions/:session_id
 * POST /live-response/evidence-sessions/:session_id/cancel
 */
export async function startEvidenceSession(
  agentId: string,
  request: EvidenceSessionRequest
): Promise<EvidenceSessionResult> {
  const response = await axios.post(
    `/api/v1/live-response/${encodeURIComponent(agentId)}/evidence-sessions`,
    request
  )
  const root = asRecord(response.data)
  return normalizeEvidenceSession(asRecord(root.data ?? root), request)
}

export async function getEvidenceSession(
  agentId: string,
  sessionId: string,
  signal?: AbortSignal
): Promise<EvidenceSessionResult> {
  const response = await axios.get(
    `/api/v1/live-response/evidence-sessions/${encodeURIComponent(sessionId)}`,
    { signal }
  )
  const root = asRecord(response.data)
  return hydrateEvidenceFrames(
    agentId,
    normalizeEvidenceSession(asRecord(root.data ?? root)),
    signal
  )
}

export async function cancelEvidenceSession(
  sessionId: string
): Promise<EvidenceSessionResult> {
  const response = await axios.post(
    `/api/v1/live-response/evidence-sessions/${encodeURIComponent(sessionId)}/cancel`,
    {}
  )
  const root = asRecord(response.data)
  return normalizeEvidenceSession(asRecord(root.data ?? root))
}

export async function approveEvidenceSession(sessionId: string): Promise<EvidenceSessionResult> {
  const response = await axios.post(
    `/api/v1/live-response/evidence-sessions/${encodeURIComponent(sessionId)}/approve`,
    {}
  )
  const root = asRecord(response.data)
  return normalizeEvidenceSession(asRecord(root.data ?? root))
}

export async function createEvidenceExport(sessionId: string): Promise<EvidenceExportResult> {
  const response = await axios.post(
    `/api/v1/live-response/evidence-sessions/${encodeURIComponent(sessionId)}/export`,
    {}
  )
  const data = asRecord(asRecord(response.data).data ?? response.data)
  const id = text(data.id)
  const sha256 = text(data.sha256)
  const size = finiteNumber(data.size)
  const downloadUrl = authenticatedArtifactUrl(data.download_url)
  if (!id || !sha256 || size === null || !downloadUrl) throw new Error('Invalid evidence export response')
  return { id, sha256, size, expiresAt: text(data.expires_at), downloadUrl }
}

export async function createEvidenceServerDiff(
  sessionId: string,
  leftArtifactId: string,
  rightArtifactId: string
): Promise<EvidenceServerDiffResult> {
  const response = await axios.post(
    `/api/v1/live-response/evidence-sessions/${encodeURIComponent(sessionId)}/diffs`,
    { left_artifact_id: leftArtifactId, right_artifact_id: rightArtifactId }
  )
  const data = asRecord(asRecord(response.data).data ?? response.data)
  const id = text(data.id)
  if (!id) throw new Error('Invalid evidence diff response')
  return { id, expiresAt: text(data.expires_at), metrics: asRecord(data.metrics) }
}

async function hydrateEvidenceFrames(
  agentId: string,
  session: EvidenceSessionResult,
  signal?: AbortSignal
): Promise<EvidenceSessionResult> {
  const frames = await Promise.all(session.frames.map(async frame => {
    if (!frame.artifactId || frame.status.toLowerCase() !== 'ready') return frame
    try {
      const artifact = await getScreenCaptureArtifact(agentId, frame.artifactId, signal)
      return {
        ...frame,
        artifactUrl: artifact.artifactUrl,
        capturedAt: artifact.capturedAt ?? frame.capturedAt,
        mime: artifact.mime ?? frame.mime,
        size: artifact.size ?? frame.size,
        sha256: artifact.sha256 ?? frame.sha256,
      }
    } catch {
      return frame
    }
  }))
  return { ...session, frames }
}

function normalizeScreenCapture(data: ApiRecord): ScreenCaptureResult {
  const command = asRecord(data.command)
  const artifact = asRecord(data.artifact)
  return {
    commandId: text(data.command_id ?? command.id),
    artifactId: text(artifact.id ?? data.artifact_id),
    status: text(artifact.status ?? data.status ?? command.status) || 'pending',
    requestedAt: text(data.requested_at ?? data.inserted_at ?? command.inserted_at),
    expiresAt: text(data.expires_at ?? artifact.expires_at),
    artifactUrl: authenticatedArtifactUrl(
      artifact.content_url ?? data.artifact_url ?? data.screenshot_url
    ),
    mime: text(artifact.mime),
    size: finiteNumber(artifact.size),
    sha256: text(artifact.sha256),
    capturedAt: text(artifact.captured_at),
    uploadedAt: text(artifact.uploaded_at),
    display: text(artifact.display ?? data.display),
    scope: text(artifact.scope ?? data.scope),
    monitorId: text(artifact.monitor_id ?? data.monitor_id),
    watermark: optionalBoolean(artifact.watermark ?? data.watermark),
    redactionCount: finiteNumber(artifact.redaction_count ?? data.redaction_count),
    consentRequired: boolean(data.consent_required ?? command.consent_required),
    consentModel: text(data.consent_model ?? command.consent_model),
    captureCoverage: text(data.capture_coverage ?? command.capture_coverage),
  }
}

// Screenshot bytes/base64 are deliberately rejected. Only an authenticated,
// same-origin URL supplied by the server may be rendered by the UI.
export function authenticatedArtifactUrl(value: unknown): string | null {
  const candidate = text(value)
  if (!candidate || candidate.startsWith('data:') || candidate.startsWith('blob:')) return null

  try {
    const parsed = new URL(candidate, window.location.origin)
    if (parsed.origin !== window.location.origin) return null
    if (!['http:', 'https:'].includes(parsed.protocol)) return null
    return parsed.href
  } catch {
    return null
  }
}

function asRecord(value: unknown): ApiRecord {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as ApiRecord
    : {}
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

function boolean(value: unknown): boolean {
  return value === true || value === 'true'
}

function normalizeEvidenceSession(
  data: ApiRecord,
  request?: EvidenceSessionRequest
): EvidenceSessionResult {
  const session = asRecord(data.session)
  const rawFrames = Array.isArray(session.frames)
    ? session.frames
    : Array.isArray(data.frames) ? data.frames : []
  const frames = rawFrames.map((value, position) => normalizeEvidenceFrame(value, position))
  const status = text(session.status ?? data.status) || 'pending'
  const terminal = ['completed', 'partial', 'cancelled', 'failed', 'expired'].includes(status.toLowerCase())
  const links = asRecord(session.links ?? data.links)
  return {
    sessionId: text(session.id ?? data.id ?? data.session_id),
    commandId: text(session.command_id ?? data.command_id),
    status,
    requestedAt: text(session.requested_at ?? data.requested_at ?? session.started_at ?? data.started_at),
    expiresAt: text(session.expires_at ?? data.expires_at),
    requestedFrameCount: finiteNumber(
      session.frame_count ?? data.frame_count ?? request?.frame_count
    ),
    intervalSeconds: finiteNumber(
      session.interval_seconds ?? data.interval_seconds ?? request?.interval_seconds
    ),
    completedFrames: frames.filter(frame => frame.status.toLowerCase() === 'ready').length,
    consentRequired: boolean(session.consent_required ?? data.consent_required),
    cancelable: optionalBoolean(session.cancelable ?? data.cancelable) ?? !terminal,
    failureReason: text(session.failure_reason ?? data.failure_reason),
    frames,
    context: normalizeEvidenceContext(session.context ?? data.context),
    approvalStatus: text(session.approval_status ?? data.approval_status),
    approvalExpiresAt: text(session.approval_expires_at ?? data.approval_expires_at),
    approvedAt: text(session.approved_at ?? data.approved_at),
    links: {
      alertId: text(links.alert_id),
      investigationId: text(links.investigation_id),
      caseId: text(links.case_id),
    },
  }
}

function normalizeEvidenceContext(value: unknown): EvidenceSessionContext | null {
  const context = asRecord(value)
  if (Object.keys(context).length === 0) return null
  return {
    generatedAt: text(context.generated_at),
    process: normalizeContextSource(context.process),
    network: normalizeContextSource(context.network),
  }
}

function normalizeContextSource(value: unknown): EvidenceSessionContextSource {
  const source = asRecord(value)
  return {
    state: text(source.state) || 'unavailable',
    reason: text(source.reason),
    observedCount: finiteNumber(source.observed_count),
    truncated: boolean(source.truncated),
    events: Array.isArray(source.events)
      ? source.events.map(asRecord).filter(event => Object.keys(event).length > 0)
      : [],
  }
}

function normalizeEvidenceFrame(value: unknown, position: number): EvidenceSessionFrame {
  const frame = asRecord(value)
  const artifact = asRecord(frame.artifact)
  return {
    index: finiteNumber(frame.index ?? frame.sequence) ?? position,
    status: text(frame.status ?? artifact.status) || 'pending',
    artifactId: text(frame.artifact_id ?? artifact.id),
    artifactUrl: authenticatedArtifactUrl(
      frame.content_url ?? frame.artifact_url ?? artifact.content_url
    ),
    capturedAt: text(frame.captured_at ?? artifact.captured_at),
    mime: text(frame.mime ?? artifact.mime),
    size: finiteNumber(frame.size ?? artifact.size),
    sha256: text(frame.sha256 ?? artifact.sha256),
    failureReason: text(frame.failure_reason ?? artifact.failure_reason),
  }
}

function optionalBoolean(value: unknown): boolean | null {
  return value === true || value === 'true' ? true : value === false || value === 'false' ? false : null
}

function finiteNumber(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
}
