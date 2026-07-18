export interface AIEvidenceSummary {
  aiNetworkRisk?: string
  aiEvidenceLimit?: string
  networkVisibilityState?: string
  tlsFingerprintsAvailable?: boolean
  certificateVisibility?: string
  riskIndicators: string[]
  matchedPatterns: string[]
  artifactType?: string
  redactedPreview?: string
}

const NESTED_CONTEXT_KEYS = ['metadata', 'payload', 'evidence', 'data', 'network', 'enrichment'] as const

export function summarizeAIEvidence(...sources: unknown[]): AIEvidenceSummary {
  const contexts = collectContexts(sources)

  return {
    aiNetworkRisk: firstText(contexts, ['ai_network_risk', 'aiNetworkRisk']),
    aiEvidenceLimit: firstText(contexts, ['ai_evidence_limit', 'aiEvidenceLimit', 'evidence_limit', 'evidenceLimit']),
    networkVisibilityState: firstText(contexts, ['network_visibility_state', 'networkVisibilityState']),
    tlsFingerprintsAvailable: firstBoolean(contexts, ['tls_fingerprints_available', 'tlsFingerprintsAvailable']),
    certificateVisibility: firstText(contexts, ['certificate_visibility', 'certificateVisibility']),
    riskIndicators: uniqueText(contexts, ['risk_indicators', 'riskIndicators']),
    matchedPatterns: uniqueText(contexts, ['matched_patterns', 'matchedPatterns']),
    artifactType: firstText(contexts, ['artifact_type', 'artifactType']),
    redactedPreview: firstText(contexts, ['redacted_preview', 'redactedPreview']),
  }
}

export function hasAIEvidence(summary: AIEvidenceSummary): boolean {
  return Boolean(
    summary.aiNetworkRisk ||
    summary.aiEvidenceLimit ||
    summary.networkVisibilityState ||
    summary.tlsFingerprintsAvailable !== undefined ||
    summary.certificateVisibility ||
    summary.riskIndicators.length ||
    summary.matchedPatterns.length ||
    summary.artifactType ||
    summary.redactedPreview
  )
}

export function networkVisibilityIsDegraded(summary: AIEvidenceSummary): boolean {
  const state = summary.networkVisibilityState?.toLowerCase()
  return state === 'degraded' || state === 'limited' || state === 'unavailable'
}

function collectContexts(sources: unknown[]): Record<string, unknown>[] {
  const contexts: Record<string, unknown>[] = []
  const seen = new Set<Record<string, unknown>>()

  const visit = (value: unknown, depth: number) => {
    if (depth > 4 || !value || typeof value !== 'object' || Array.isArray(value)) return
    const record = value as Record<string, unknown>
    if (seen.has(record)) return
    seen.add(record)
    contexts.push(record)

    for (const key of NESTED_CONTEXT_KEYS) visit(record[key], depth + 1)
  }

  sources.flat().forEach(source => visit(source, 0))
  return contexts
}

function firstText(contexts: Record<string, unknown>[], keys: string[]): string | undefined {
  for (const context of contexts) {
    for (const key of keys) {
      const value = context[key]
      if (typeof value === 'string' && value.trim()) return value.trim()
      if (typeof value === 'number') return String(value)
    }
  }
  return undefined
}

function firstBoolean(contexts: Record<string, unknown>[], keys: string[]): boolean | undefined {
  for (const context of contexts) {
    for (const key of keys) {
      const value = context[key]
      if (typeof value === 'boolean') return value
      if (typeof value === 'string' && value.toLowerCase() === 'true') return true
      if (typeof value === 'string' && value.toLowerCase() === 'false') return false
    }
  }
  return undefined
}

function uniqueText(contexts: Record<string, unknown>[], keys: string[]): string[] {
  const values = contexts.flatMap(context => keys.flatMap(key => {
    const value = context[key]
    if (Array.isArray(value)) return value.filter(item => typeof item === 'string') as string[]
    return typeof value === 'string' && value.trim() ? [value] : []
  }))

  return [...new Set(values.map(value => value.trim()).filter(Boolean))]
}
