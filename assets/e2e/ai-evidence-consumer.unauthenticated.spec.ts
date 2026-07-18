import { expect, test } from '@playwright/test'
import { hasAIEvidence, networkVisibilityIsDegraded, summarizeAIEvidence } from '../src/lib/aiEvidence'

test.describe('AI evidence consumer contract', () => {
  test('surfaces explicit degraded visibility and unavailability metadata', () => {
    const summary = summarizeAIEvidence({
      metadata: {
        ai_network_risk: 'proxy_or_doh_plus_ai_provider',
        ai_evidence_limit: 'metadata_only_no_payload_or_bind_proof',
        network_visibility_state: 'degraded',
        tls_fingerprints_available: 'false',
        certificate_visibility: 'unavailable',
      },
    })

    expect(hasAIEvidence(summary)).toBe(true)
    expect(networkVisibilityIsDegraded(summary)).toBe(true)
    expect(summary.tlsFingerprintsAvailable).toBe(false)
    expect(summary.certificateVisibility).toBe('unavailable')
    expect(summary).not.toHaveProperty('tlsFingerprint')
  })

  test('does not claim TLS or certificate visibility when metadata is absent', () => {
    const summary = summarizeAIEvidence({ payload: { domain: 'api.openai.com', remote_port: 443 } })

    expect(summary.tlsFingerprintsAvailable).toBeUndefined()
    expect(summary.certificateVisibility).toBeUndefined()
    expect(hasAIEvidence(summary)).toBe(false)
  })

  test('preserves artifact and risk evidence from nested consumer payloads', () => {
    const summary = summarizeAIEvidence({
      evidence: {
        artifact_type: 'mcp_config',
        redacted_preview: 'tools: [redacted]',
        matched_patterns: ['approval_bypass'],
        risk_indicators: ['unsigned_source'],
      },
    })

    expect(summary.artifactType).toBe('mcp_config')
    expect(summary.redactedPreview).toBe('tools: [redacted]')
    expect(summary.matchedPatterns).toEqual(['approval_bypass'])
    expect(summary.riskIndicators).toEqual(['unsigned_source'])
  })
})
