import { Activity, Eye, ShieldOff } from 'lucide-react'

export interface ModelObservation {
  detector_id: string
  status: string
  score: number
  threshold_met: boolean
  runtime_lane: string
  model_contract_id: string
  artifact_sha256?: string | null
  threshold?: number | null
  feature_contract_id?: string | null
  calibration_id?: string | null
  score_orientation?: string | null
  claim_boundary?: string | null
  component_name?: string | null
  agent_id?: string | null
  observed_at?: string | null
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

const CLAIM_BOUNDARY = 'shadow_observation_no_verdict'

function boundedText(value: unknown, max = 256): string | null {
  return typeof value === 'string' && value.trim() && value.length <= max ? value : null
}

function optionalNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function parseObservation(value: unknown): ModelObservation | null {
  const item = record(value)
  const detectorId = boundedText(item.detector_id)
  const status = boundedText(item.status)
  const runtimeLane = boundedText(item.runtime_lane)
  const modelContractId = boundedText(item.model_contract_id)
  const score = optionalNumber(item.score)
  if (!detectorId || !status || !runtimeLane || !modelContractId || score === null ||
      typeof item.threshold_met !== 'boolean') return null

  const artifact = boundedText(item.artifact_sha256, 64)?.toLowerCase() || null
  return {
    detector_id: detectorId,
    status,
    score,
    threshold_met: item.threshold_met,
    runtime_lane: runtimeLane,
    model_contract_id: modelContractId,
    artifact_sha256: artifact && /^[a-f0-9]{64}$/.test(artifact) ? artifact : null,
    threshold: optionalNumber(item.threshold),
    feature_contract_id: boundedText(item.feature_contract_id),
    calibration_id: boundedText(item.calibration_id),
    score_orientation: boundedText(item.score_orientation),
    claim_boundary: CLAIM_BOUNDARY,
    component_name: boundedText(item.component_name, 4096),
    agent_id: boundedText(item.agent_id),
    observed_at: boundedText(item.observed_at),
  }
}

function directObservations(value: unknown): ModelObservation[] {
  const normalize = (candidate: unknown): ModelObservation[] => Array.isArray(candidate)
    ? candidate.slice(0, 128).map(parseObservation).filter((item): item is ModelObservation => item !== null)
    : []
  if (Array.isArray(value)) return normalize(value)
  const item = record(value)
  const candidates = [item.model_observations, item.modelObservations]
  return candidates.flatMap(normalize)
}

/** Extract only the explicit model-observation fields; do not infer observations from verdicts or scores. */
export function collectModelObservations(...sources: unknown[]): ModelObservation[] {
  const observations = sources.flatMap(source => {
    const item = record(source)
    const payload = record(item.payload)
    const components = Array.isArray(payload.components) ? payload.components.slice(0, 128) : []
    return [
      ...directObservations(source),
      ...directObservations(payload),
      ...components.flatMap(directObservations),
    ]
  })

  const unique = new Map<string, ModelObservation>()
  for (const observation of observations) {
    const key = [
      observation.detector_id,
      observation.model_contract_id,
      observation.artifact_sha256,
      observation.calibration_id,
      observation.observed_at,
      observation.score,
      observation.threshold_met,
    ].join(':')
    if (!unique.has(key)) unique.set(key, observation)
    if (unique.size >= 128) break
  }
  return Array.from(unique.values())
}

function text(value: unknown, fallback = 'not reported'): string {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function metric(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(6) : 'not reported'
}

function artifactPrefix(value: unknown): string {
  return typeof value === 'string' && value ? `${value.slice(0, 12)}…` : 'not reported'
}

export function ModelObservationsPanel({ observations, compact = false }: { observations: ModelObservation[]; compact?: boolean }) {
  const safeObservations = directObservations(observations)
  if (safeObservations.length === 0) return null

  return (
    <section className="card-sentinel rounded-xl p-4" aria-label="Model observations">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Eye className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Model observations</h3>
          </div>
          <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
            Score-only detector telemetry. Threshold crossing is not an alert verdict.
          </p>
        </div>
        <span className="inline-flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium uppercase tracking-wide bg-blue-500/15 text-blue-400">
          <ShieldOff className="h-3 w-3" /> Shadow observation / no verdict
        </span>
      </div>

      <div className="mt-3 space-y-2">
        {safeObservations.map((observation, index) => (
          <article
            key={`${observation.detector_id}-${observation.model_contract_id}-${index}`}
            className="rounded-lg border p-3"
            style={{ borderColor: 'var(--hairline)', background: 'var(--surface-2)' }}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  <span className="font-mono text-xs font-semibold truncate" style={{ color: 'var(--fg)' }}>
                    {observation.detector_id}
                  </span>
                </div>
                {observation.component_name && (
                  <div className="mt-0.5 text-[10px] truncate" style={{ color: 'var(--muted)' }}>{observation.component_name}</div>
                )}
              </div>
              <span className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide" style={{ background: 'var(--bg)', color: 'var(--muted)' }}>
                {text(observation.status, 'unknown')}
              </span>
            </div>

            <dl className={`mt-2 grid gap-x-4 gap-y-2 text-[10px] ${compact ? 'grid-cols-2' : 'grid-cols-2 md:grid-cols-4'}`}>
              <Fact label="Score" value={metric(observation.score)} />
              <Fact label="Orientation" value={text(observation.score_orientation)} />
              <Fact label="Threshold met" value={observation.threshold_met ? 'yes (observation only)' : 'no'} />
              <Fact label="Threshold" value={metric(observation.threshold)} />
              <Fact label="Runtime lane" value={text(observation.runtime_lane)} />
              <Fact label="Feature contract" value={text(observation.feature_contract_id || observation.model_contract_id)} mono />
              <Fact label="Calibration" value={text(observation.calibration_id)} mono />
              <Fact label="Artifact" value={artifactPrefix(observation.artifact_sha256)} mono />
            </dl>

            <div className="mt-2 border-t pt-2 text-[10px]" style={{ borderColor: 'var(--hairline)', color: 'var(--subtle)' }}>
              Claim boundary: {text(observation.claim_boundary, 'shadow_observation_no_verdict')} · enforcement: none
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>{label}</dt>
      <dd className={`mt-0.5 break-words ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--fg-2)' }}>{value}</dd>
    </div>
  )
}
