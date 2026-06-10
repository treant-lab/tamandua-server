/**
 * ProofCard Component
 *
 * Displays blockchain attestation proof details for incidents, health checks,
 * and remediation actions. Shows verification status, transaction details,
 * and provides actions for verification and proof bundle export.
 */

import { useState } from 'react'
import { cn } from '@/lib/utils'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Copy,
  Check,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileCheck,
  Activity,
  Wrench,
  Lock,
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface ProofCardProps {
  /** Type of proof attestation */
  type: 'incident' | 'health' | 'remediation'
  /** Verification status */
  status: 'verified' | 'pending' | 'failed'
  /** SHA-256 hash of the manifest */
  manifestHash: string
  /** Solana transaction hash */
  txHash: string
  /** Solana slot number */
  slot: number
  /** ISO timestamp of the attestation */
  timestamp: string
  /** Tenant identifier (optional) */
  tenant?: string
  /** Trust score 0-100 (optional) */
  trustScore?: number
  /** Clean duration string for health proofs (optional) */
  cleanFor?: string
  /** Fields included in the attestation (optional) */
  includedFields?: string[]
  /** Callback when verify button is clicked */
  onVerify?: () => void
  /** Callback when copy proof bundle is clicked */
  onCopyBundle?: () => void
  /** Callback when Open in Solscan is clicked */
  onOpenSolscan?: () => void
  /** Additional CSS classes */
  className?: string
}

// ============================================================================
// Constants
// ============================================================================

const TYPE_CONFIG = {
  incident: {
    label: 'Incident',
    title: 'Proof of Incident',
    subtitle: 'Tamper-evident incident record',
    icon: ShieldAlert,
    badgeClass: 'bg-red-500/20 text-red-400',
    iconClass: 'text-red-400',
  },
  health: {
    label: 'Health',
    title: 'Last Health Attestation',
    subtitle: 'Auto-anchored every 60 seconds',
    icon: Activity,
    badgeClass: 'bg-emerald-500/20 text-emerald-400',
    iconClass: 'text-emerald-400',
  },
  remediation: {
    label: 'Remediation',
    title: 'Proof of Remediation',
    subtitle: 'Response action verification',
    icon: Wrench,
    badgeClass: 'bg-blue-500/20 text-blue-400',
    iconClass: 'text-blue-400',
  },
}

const STATUS_CONFIG = {
  verified: {
    label: 'Verified',
    icon: ShieldCheck,
    badgeClass: 'bg-emerald-500/20 text-emerald-400',
  },
  pending: {
    label: 'Pending',
    icon: Clock,
    badgeClass: 'bg-yellow-500/20 text-yellow-400',
  },
  failed: {
    label: 'Failed',
    icon: ShieldAlert,
    badgeClass: 'bg-red-500/20 text-red-400',
  },
}

// ============================================================================
// Helper Components
// ============================================================================

function CopyableField({
  label,
  value,
  mono = false,
  truncate = false,
}: {
  label: string
  value: string | number
  mono?: boolean
  truncate?: boolean
}) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(String(value))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="flex items-center justify-between gap-2 py-2 border-b border-slate-700/50 last:border-0">
      <span className="text-xs text-slate-500 uppercase tracking-wide">{label}</span>
      <div className="flex items-center gap-2">
        <span
          className={cn(
            'text-sm text-slate-300',
            mono && 'font-mono text-xs',
            truncate && 'max-w-[180px] truncate'
          )}
          title={truncate ? String(value) : undefined}
        >
          {value}
        </span>
        <button
          onClick={handleCopy}
          className="p-1 rounded text-slate-500 hover:text-white hover:bg-slate-700 transition-colors"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="h-3 w-3 text-emerald-400" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
        </button>
      </div>
    </div>
  )
}

function IncludedFieldsChecklist({ fields }: { fields: string[] }) {
  const [expanded, setExpanded] = useState(false)
  const displayFields = expanded ? fields : fields.slice(0, 4)
  const hasMore = fields.length > 4

  return (
    <div className="mt-4 pt-4 border-t border-slate-700/50">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between w-full text-left mb-3"
      >
        <span className="text-xs text-slate-400 uppercase tracking-wide">
          What's included
        </span>
        {hasMore && (
          <span className="text-xs text-slate-500 flex items-center gap-1">
            {expanded ? (
              <>
                Show less <ChevronUp className="h-3 w-3" />
              </>
            ) : (
              <>
                +{fields.length - 4} more <ChevronDown className="h-3 w-3" />
              </>
            )}
          </span>
        )}
      </button>
      <div className="grid grid-cols-2 gap-2">
        {displayFields.map((field) => (
          <div key={field} className="flex items-center gap-2">
            <FileCheck className="h-3 w-3 text-emerald-400" />
            <span className="text-xs text-slate-400">{field}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function ProofCard({
  type,
  status,
  manifestHash,
  txHash,
  slot,
  timestamp,
  tenant,
  trustScore,
  cleanFor,
  includedFields,
  onVerify,
  onCopyBundle,
  onOpenSolscan,
  className,
}: ProofCardProps) {
  const typeConfig = TYPE_CONFIG[type]
  const statusConfig = STATUS_CONFIG[status]
  const TypeIcon = typeConfig.icon
  const StatusIcon = statusConfig.icon

  const formattedTime = new Date(timestamp).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })

  const solscanUrl = `https://solscan.io/tx/${txHash}?cluster=devnet`

  const handleOpenSolscan = () => {
    if (onOpenSolscan) {
      onOpenSolscan()
    } else {
      window.open(solscanUrl, '_blank', 'noopener,noreferrer')
    }
  }

  return (
    <div
      className={cn(
        'bg-slate-800 rounded-xl border border-slate-700 overflow-hidden',
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', typeConfig.badgeClass)}>
            <TypeIcon className={cn('h-5 w-5', typeConfig.iconClass)} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-white">{typeConfig.title}</h3>
              <span
                className={cn(
                  'text-xs px-2 py-0.5 rounded-full font-medium',
                  typeConfig.badgeClass
                )}
              >
                {typeConfig.label}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">{typeConfig.subtitle}</p>
          </div>
        </div>

        {/* Status badge */}
        <div
          className={cn(
            'flex items-center gap-1.5 px-2.5 py-1 rounded-full',
            statusConfig.badgeClass
          )}
        >
          <StatusIcon className="h-3.5 w-3.5" />
          <span className="text-xs font-medium">{statusConfig.label}</span>
        </div>
      </div>

      {/* Content */}
      <div className="p-4">
        {/* Key fields */}
        <div className="space-y-0">
          {tenant && <CopyableField label="Tenant" value={tenant} />}
          {trustScore !== undefined && (
            <div className="flex items-center justify-between gap-2 py-2 border-b border-slate-700/50">
              <span className="text-xs text-slate-500 uppercase tracking-wide">
                Trust Score
              </span>
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5">
                  <div
                    className={cn(
                      'w-2 h-2 rounded-full',
                      trustScore >= 80
                        ? 'bg-emerald-400'
                        : trustScore >= 60
                          ? 'bg-yellow-400'
                          : 'bg-red-400'
                    )}
                  />
                  <span className="text-sm font-semibold text-white">
                    {trustScore}%
                  </span>
                </div>
              </div>
            </div>
          )}
          {cleanFor && <CopyableField label="Clean For" value={cleanFor} />}
          <CopyableField label="TX Hash" value={txHash} mono truncate />
          <CopyableField label="Slot" value={slot.toLocaleString()} />
          <CopyableField label="Timestamp" value={formattedTime} />
          <CopyableField
            label="Manifest Hash"
            value={manifestHash}
            mono
            truncate
          />
        </div>

        {/* Included fields checklist */}
        {includedFields && includedFields.length > 0 && (
          <IncludedFieldsChecklist fields={includedFields} />
        )}

        {/* Actions */}
        <div className="flex gap-2 mt-4 pt-4 border-t border-slate-700/50">
          <button
            onClick={handleOpenSolscan}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <ExternalLink className="h-4 w-4" />
            Open in Solscan
          </button>
          <button
            onClick={onCopyBundle}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Copy className="h-4 w-4" />
            Copy Proof Bundle
          </button>
        </div>

        {onVerify && (
          <button
            onClick={onVerify}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 mt-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Shield className="h-4 w-4" />
            Verify On-Chain
          </button>
        )}
      </div>

      {/* Privacy notice */}
      <div className="flex items-center gap-2 px-4 py-3 bg-slate-900/50 border-t border-slate-700/50">
        <Lock className="h-3.5 w-3.5 text-slate-500" />
        <p className="text-xs text-slate-500">
          No customer-identifying data left this server
        </p>
      </div>
    </div>
  )
}

export default ProofCard
