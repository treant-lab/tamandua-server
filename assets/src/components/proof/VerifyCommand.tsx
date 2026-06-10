/**
 * VerifyCommand Component
 *
 * Displays instructions for self-verification of Solana attestations
 * with copyable CLI commands and expected output.
 */

import { useState } from 'react'
import { cn } from '@/lib/utils'
import { Terminal, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

export interface VerifyCommandProps {
  /** Path to the proof bundle file */
  bundlePath: string
  /** Solana transaction hash */
  txHash: string
  /** Additional CSS classes */
  className?: string
}

// ============================================================================
// Helper Components
// ============================================================================

interface CommandBlockProps {
  command: string
  output?: string
  showOutput?: boolean
}

function CommandBlock({ command, output, showOutput = true }: CommandBlockProps) {
  const [copied, setCopied] = useState(false)
  const [expanded, setExpanded] = useState(true)

  const handleCopy = () => {
    navigator.clipboard.writeText(command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      {/* Command header */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-800/50 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-slate-400" />
          <span className="text-xs text-slate-400 font-medium">Command</span>
        </div>
        <button
          onClick={handleCopy}
          className={cn(
            'flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-colors',
            copied
              ? 'bg-emerald-500/20 text-emerald-400'
              : 'bg-slate-700 hover:bg-slate-600 text-slate-300'
          )}
        >
          {copied ? (
            <>
              <Check className="h-3 w-3" />
              Copied
            </>
          ) : (
            <>
              <Copy className="h-3 w-3" />
              Copy
            </>
          )}
        </button>
      </div>

      {/* Command content */}
      <div className="p-4">
        <code className="block text-sm text-emerald-400 font-mono whitespace-pre-wrap break-all">
          {command}
        </code>
      </div>

      {/* Output section */}
      {showOutput && output && (
        <>
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center justify-between w-full px-4 py-2 bg-slate-800/30 border-t border-slate-700 text-left hover:bg-slate-800/50 transition-colors"
          >
            <span className="text-xs text-slate-400 font-medium">
              Expected Output
            </span>
            {expanded ? (
              <ChevronUp className="h-4 w-4 text-slate-500" />
            ) : (
              <ChevronDown className="h-4 w-4 text-slate-500" />
            )}
          </button>

          {expanded && (
            <div className="p-4 border-t border-slate-700/50 bg-slate-950/50">
              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap overflow-x-auto">
                {output}
              </pre>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export function VerifyCommand({ bundlePath, txHash, className }: VerifyCommandProps) {
  const verifyCommand = `tamandua verify-proof \\
  --bundle ${bundlePath} \\
  --tx ${txHash} \\
  --cluster devnet`

  const expectedOutput = `Verifying proof bundle...
  Bundle hash: SHA256:a1b2c3d4e5f6...
  On-chain hash: SHA256:a1b2c3d4e5f6...

  [OK] Hashes match
  [OK] Signature valid
  [OK] Timestamp within tolerance

Verification: PASSED
Proof is cryptographically valid and anchored on Solana.`

  return (
    <div className={cn('space-y-4', className)}>
      {/* Section header */}
      <div>
        <h4 className="text-sm font-semibold text-white flex items-center gap-2">
          <Terminal className="h-4 w-4 text-slate-400" />
          Verifying Yourself
        </h4>
        <p className="text-sm text-slate-400 mt-1.5">
          You can independently verify this attestation using the Tamandua CLI.
          The proof bundle contains all data needed to reconstruct and verify
          the on-chain commitment.
        </p>
      </div>

      {/* Command block */}
      <CommandBlock command={verifyCommand} output={expectedOutput} />

      {/* Additional info */}
      <div className="flex items-start gap-2 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
        <div className="p-1 bg-blue-500/20 rounded">
          <svg
            className="h-3.5 w-3.5 text-blue-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        </div>
        <div className="flex-1">
          <p className="text-xs text-slate-400">
            Install the CLI with{' '}
            <code className="px-1 py-0.5 bg-slate-700 rounded text-emerald-400">
              cargo install tamandua-cli
            </code>{' '}
            or download from the{' '}
            <a
              href="https://github.com/treant-lab/tamandua-server/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 underline"
            >
              releases page
            </a>
            .
          </p>
        </div>
      </div>
    </div>
  )
}

export default VerifyCommand
