/**
 * CommandBlock - Displays code/command blocks with copy functionality
 *
 * Features:
 * - Dark background (#06090b)
 * - Copy button in top-right corner
 * - Syntax highlighting for bash/powershell
 * - Support for output lines with checkmark prefix
 * - Toast notification on copy
 */

import { useState, useCallback } from 'react'
import { Copy, Check, Terminal, Hash } from 'lucide-react'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'

interface CommandBlockProps {
  command: string
  language?: 'bash' | 'powershell' | 'text'
  showLineNumbers?: boolean
  output?: string[]
  className?: string
}

// Basic syntax highlighting tokens
const highlightBash = (line: string): React.ReactNode[] => {
  const tokens: React.ReactNode[] = []
  let remaining = line
  let key = 0

  // Match common bash patterns
  const patterns = [
    { regex: /^(#.*)$/, className: 'text-[var(--muted)]' }, // Comments
    { regex: /^(\$\s*)/, className: 'text-[var(--emerald-400)]' }, // Prompt
    { regex: /^(sudo\s+)/, className: 'text-[var(--crit)]' }, // sudo
    { regex: /(--[\w-]+)/, className: 'text-[var(--med)]' }, // Long flags
    { regex: /(-\w+)/, className: 'text-[var(--med)]' }, // Short flags
    { regex: /("(?:[^"\\]|\\.)*")/, className: 'text-[var(--high)]' }, // Double quoted strings
    { regex: /('(?:[^'\\]|\\.)*')/, className: 'text-[var(--high)]' }, // Single quoted strings
    { regex: /(\|)/, className: 'text-[var(--emerald-400)]' }, // Pipe
    { regex: /(&&|\|\|)/, className: 'text-[var(--emerald-400)]' }, // Logical operators
  ]

  // Simple tokenization - split by spaces and highlight keywords
  const words = line.split(/(\s+)/)
  const bashCommands = ['cd', 'ls', 'cat', 'echo', 'grep', 'awk', 'sed', 'curl', 'wget', 'npm', 'yarn', 'pnpm', 'cargo', 'mix', 'docker', 'git', 'make', 'sudo', 'chmod', 'chown', 'mkdir', 'rm', 'cp', 'mv', 'touch', 'tar', 'gzip', 'unzip', 'ssh', 'scp', 'rsync']

  words.forEach((word, i) => {
    if (/^\s+$/.test(word)) {
      tokens.push(<span key={key++}>{word}</span>)
    } else if (word.startsWith('$') && i === 0) {
      tokens.push(<span key={key++} className="text-[var(--emerald-400)]">{word}</span>)
    } else if (word.startsWith('#')) {
      tokens.push(<span key={key++} className="text-[var(--muted)]">{word}</span>)
    } else if (word.startsWith('--')) {
      tokens.push(<span key={key++} className="text-[var(--med)]">{word}</span>)
    } else if (word.startsWith('-') && word.length > 1) {
      tokens.push(<span key={key++} className="text-[var(--med)]">{word}</span>)
    } else if (word.startsWith('"') || word.startsWith("'")) {
      tokens.push(<span key={key++} className="text-[var(--high)]">{word}</span>)
    } else if (word === '|' || word === '&&' || word === '||') {
      tokens.push(<span key={key++} className="text-[var(--emerald-400)]">{word}</span>)
    } else if (bashCommands.includes(word) && (i === 0 || words[i - 1]?.trim() === '' || words[i - 2] === '$')) {
      tokens.push(<span key={key++} className="text-[var(--sol-cyan)]">{word}</span>)
    } else {
      tokens.push(<span key={key++}>{word}</span>)
    }
  })

  return tokens
}

const highlightPowershell = (line: string): React.ReactNode[] => {
  const tokens: React.ReactNode[] = []
  let key = 0

  const words = line.split(/(\s+)/)
  const psCommands = ['Get-', 'Set-', 'New-', 'Remove-', 'Add-', 'Import-', 'Export-', 'Start-', 'Stop-', 'Invoke-', 'Write-', 'Read-']

  words.forEach((word, i) => {
    if (/^\s+$/.test(word)) {
      tokens.push(<span key={key++}>{word}</span>)
    } else if (word.startsWith('PS>') || word.startsWith('PS ')) {
      tokens.push(<span key={key++} className="text-[var(--sol-magenta)]">{word}</span>)
    } else if (word.startsWith('#')) {
      tokens.push(<span key={key++} className="text-[var(--muted)]">{word}</span>)
    } else if (word.startsWith('-')) {
      tokens.push(<span key={key++} className="text-[var(--med)]">{word}</span>)
    } else if (word.startsWith('$')) {
      tokens.push(<span key={key++} className="text-[var(--emerald-400)]">{word}</span>)
    } else if (word.startsWith('"') || word.startsWith("'")) {
      tokens.push(<span key={key++} className="text-[var(--high)]">{word}</span>)
    } else if (psCommands.some(cmd => word.startsWith(cmd))) {
      tokens.push(<span key={key++} className="text-[var(--sol-cyan)]">{word}</span>)
    } else if (word === '|' || word === '-and' || word === '-or') {
      tokens.push(<span key={key++} className="text-[var(--sol-magenta)]">{word}</span>)
    } else {
      tokens.push(<span key={key++}>{word}</span>)
    }
  })

  return tokens
}

export function CommandBlock({
  command,
  language = 'bash',
  showLineNumbers = false,
  output,
  className,
}: CommandBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      toast.success('Command copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      toast.error('Failed to copy command')
    }
  }, [command])

  const lines = command.split('\n')

  const highlightLine = (line: string): React.ReactNode[] => {
    switch (language) {
      case 'bash':
        return highlightBash(line)
      case 'powershell':
        return highlightPowershell(line)
      default:
        return [<span key={0}>{line}</span>]
    }
  }

  const getLanguageIcon = () => {
    switch (language) {
      case 'bash':
        return <Terminal className="h-3.5 w-3.5" />
      case 'powershell':
        return <Hash className="h-3.5 w-3.5" />
      default:
        return <Terminal className="h-3.5 w-3.5" />
    }
  }

  return (
    <div
      className={cn(
        'relative rounded-lg overflow-hidden',
        className
      )}
      style={{ backgroundColor: '#06090b' }}
    >
      {/* Header bar */}
      <div
        className="flex items-center justify-between px-3 py-2"
        style={{
          backgroundColor: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
        }}
      >
        <div className="flex items-center gap-2">
          <span className="text-[var(--muted)]">{getLanguageIcon()}</span>
          <span className="text-xs font-medium text-[var(--muted)] uppercase">
            {language}
          </span>
        </div>
        <button
          onClick={handleCopy}
          className={cn(
            'flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-colors',
            copied
              ? 'bg-[var(--emerald-glow)] text-[var(--emerald-400)]'
              : 'hover:bg-[var(--surface-2)] text-[var(--muted)] hover:text-[var(--fg)]'
          )}
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5" />
              Copied
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              Copy
            </>
          )}
        </button>
      </div>

      {/* Code block */}
      <div className="p-4 overflow-x-auto">
        <pre
          className="font-mono text-sm leading-relaxed"
          style={{ fontFamily: 'var(--mono)', color: 'var(--fg)' }}
        >
          <code>
            {lines.map((line, index) => (
              <div key={index} className="flex">
                {showLineNumbers && (
                  <span
                    className="select-none mr-4 text-right min-w-[2ch]"
                    style={{ color: 'var(--dim)' }}
                  >
                    {index + 1}
                  </span>
                )}
                <span>{highlightLine(line)}</span>
              </div>
            ))}
          </code>
        </pre>

        {/* Output section */}
        {output && output.length > 0 && (
          <div
            className="mt-4 pt-4"
            style={{ borderTop: '1px solid var(--border)' }}
          >
            <div className="space-y-1">
              {output.map((line, index) => (
                <div
                  key={index}
                  className="flex items-center gap-2 text-sm font-mono"
                  style={{ fontFamily: 'var(--mono)' }}
                >
                  <span className="text-[var(--emerald-400)]">&#10003;</span>
                  <span style={{ color: 'var(--fg-2)' }}>{line}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default CommandBlock
