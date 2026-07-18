import { Head } from '@inertiajs/react'
import { ExternalLink, Key, ShieldCheck, Wallet } from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'

interface PolicyGateProps {
  coming_soon?: boolean
  feature_name?: string
  description?: string
}

const integrationExample = `const posture = await tamandua.verifySignerPosture({
  wallet: signerPublicKey,
  policy: {
    maxCriticalAlerts: 0,
    maxHealthAgeMinutes: 60,
    requireRecentHealthAttestation: true
  }
})

if (!posture.allowed) {
  throw new Error("Endpoint posture policy failed")
}

await signTransaction(tx)`

export default function PolicyGate({ feature_name, description }: PolicyGateProps) {
  return (
    <MainLayout title={feature_name || 'Policy Gate'}>
      <Head title={`${feature_name || 'Policy Gate'} - Roadmap`} />

      <div className="mx-auto max-w-6xl space-y-8 px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex items-start justify-between gap-6">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-purple-500/30 bg-purple-500/10 px-3 py-1 text-xs font-medium text-purple-300">
              <Key className="h-3.5 w-3.5" />
              Roadmap
            </div>
            <h1 className="text-3xl font-semibold" style={{ color: 'var(--fg)' }}>
              {feature_name || 'Policy Gate'}
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6" style={{ color: 'var(--fg-2)' }}>
              {description ||
                'A planned integration layer for protocols, multisigs, and operator workflows that want to verify endpoint security posture before sensitive approvals.'}
            </p>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="card-sentinel rounded-lg p-5">
            <ShieldCheck className="mb-4 h-6 w-6 text-emerald-400" />
            <h2 className="font-medium" style={{ color: 'var(--fg)' }}>
              Health Attestation
            </h2>
            <p className="mt-2 text-sm leading-6" style={{ color: 'var(--muted)' }}>
              Tamandua publishes privacy-preserving endpoint health proofs that can be checked by external systems without exposing local telemetry.
            </p>
          </div>

          <div className="card-sentinel rounded-lg p-5">
            <Wallet className="mb-4 h-6 w-6 text-cyan-400" />
            <h2 className="font-medium" style={{ color: 'var(--fg)' }}>
              Signer Policy
            </h2>
            <p className="mt-2 text-sm leading-6" style={{ color: 'var(--muted)' }}>
              Multisig or treasury operators can require recent clean posture before allowing high-risk signing workflows.
            </p>
          </div>

          <div className="card-sentinel rounded-lg p-5">
            <Key className="mb-4 h-6 w-6 text-purple-400" />
            <h2 className="font-medium" style={{ color: 'var(--fg)' }}>
              Protocol Integration
            </h2>
            <p className="mt-2 text-sm leading-6" style={{ color: 'var(--muted)' }}>
              The SDK and policy contract are planned after the hackathon MVP, once the attestation and audit primitives are stable.
            </p>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="card-sentinel rounded-lg p-6">
            <h2 className="text-lg font-medium" style={{ color: 'var(--fg)' }}>
              Integration Shape
            </h2>
            <p className="mt-2 text-sm leading-6" style={{ color: 'var(--muted)' }}>
              This is intentionally not enabled as a live transaction gate yet. The current production surface is public audit, incident proof, and health attestation. Policy gating is the next layer built on top of those proofs.
            </p>
            <div className="mt-5 rounded-lg p-4" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
              <pre className="overflow-x-auto text-sm leading-relaxed">
                <code style={{ color: 'var(--fg-2)' }}>{integrationExample}</code>
              </pre>
            </div>
          </div>

          <div className="card-sentinel rounded-lg p-6">
            <h2 className="text-lg font-medium" style={{ color: 'var(--fg)' }}>
              Available Today
            </h2>
            <div className="mt-4 space-y-3 text-sm" style={{ color: 'var(--fg-2)' }}>
              <p>Incident attestations with Solana transaction references.</p>
              <p>Health attestations generated from real endpoint/server state.</p>
              <p>Public audit pages for verification without exposing sensitive telemetry.</p>
            </div>
            <a
              href="/app/dashboard"
              className="mt-6 inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm transition"
              style={{ border: '1px solid var(--border)', color: 'var(--fg-2)' }}
            >
              Open Security Status
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
