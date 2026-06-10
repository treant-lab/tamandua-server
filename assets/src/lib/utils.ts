import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return '—'
  try {
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(date))
  } catch {
    return '—'
  }
}

export function formatRelativeTime(timestamp: number): string {
  const now = Date.now()
  const diff = now - timestamp

  if (diff < 60000) return 'now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-500 bg-red-500/10'
    case 'high': return 'text-orange-500 bg-orange-500/10'
    case 'medium': return 'text-yellow-500 bg-yellow-500/10'
    case 'low': return 'text-blue-500 bg-blue-500/10'
    case 'info': return 'text-slate-400 bg-slate-500/10'
    default: return 'text-slate-500 bg-slate-500/10'
  }
}

export function severityDotColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500'
    case 'high': return 'bg-orange-500'
    case 'medium': return 'bg-yellow-500'
    case 'low': return 'bg-blue-500'
    case 'info': return 'bg-slate-400'
    default: return 'bg-slate-500'
  }
}

export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`
}

export function safeRandomUUID(): string {
  const cryptoApi = globalThis.crypto as Crypto | undefined

  if (cryptoApi?.randomUUID) {
    return cryptoApi.randomUUID()
  }

  return generateFallbackUUID(cryptoApi)
}

export function safeInitial(value: string | null | undefined, fallback: string = '?'): string {
  const normalized = value?.trim()
  return normalized ? normalized.charAt(0).toUpperCase() : fallback
}

export function safeCapitalize(value: string | null | undefined, fallback: string = 'Unknown'): string {
  const normalized = value?.trim()
  return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : fallback
}

export function generateFallbackUUID(cryptoApi?: Crypto): string {
  if (cryptoApi?.getRandomValues) {
    const bytes = new Uint8Array(16)
    cryptoApi.getRandomValues(bytes)
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80

    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'))
    return [
      hex.slice(0, 4).join(''),
      hex.slice(4, 6).join(''),
      hex.slice(6, 8).join(''),
      hex.slice(8, 10).join(''),
      hex.slice(10, 16).join(''),
    ].join('-')
  }

  const fallback = `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}`
  return `fallback-${fallback}`
}
