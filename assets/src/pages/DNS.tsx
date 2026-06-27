import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Globe,
  Search,
  Filter,
  Clock,
  Shield,
  ShieldOff,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  ChevronLeft,
  Plus,
  Trash2,
  Upload,
  Play,
  RefreshCw,
  BarChart3,
  List,
  XCircle,
  CheckCircle,
  FileWarning,
  Activity,
  Eye,
  ExternalLink,
} from 'lucide-react'
import { cn, formatDate, safeCapitalize } from '@/lib/utils'
import { useEventStream } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { ExportDropdown } from '@/components/ExportDropdown'
import { Checkbox, Select, SelectItem } from '@/components/ui/baseui'
import type { WebSocketConnectionState } from '@/types'

// ============================================================================
// Types
// ============================================================================

interface DNSQuery {
  id: string
  timestamp: string
  domain: string
  queryType: string
  response: string
  processName: string
  processPid: number
  processPath?: string
  agentId: string
  agentHostname: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'allowed' | 'blocked' | 'suspicious'
  detections?: DNSDetection[]
}

interface DNSDetection {
  type: string
  ruleName: string
  confidence: number
  description: string
}

interface DNSStats {
  totalQueries: number
  uniqueDomains: number
  blockedQueries: number
  suspiciousQueries: number
}

interface TopDomain {
  domain: string
  count: number
}

interface BlocklistEntry {
  id: string
  domain: string
  blockedAt?: string
  blockedBy: string
  reason?: string
  source?: string
  selected?: boolean
}

interface ThreatIntelFeed {
  name: string
  enabled: boolean
  health: string
  iocCount: number
  inserted: number
  lastSyncAt?: string
  description?: string
}

interface ThreatIntelFeedSummary {
  enabled: boolean
  totalIocs: number
  syncIntervalHours?: number
  lastGlobalSync?: string
  feeds: ThreatIntelFeed[]
}

interface DNSAlert {
  id: string
  domain: string
  detectionType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  agentId: string
  agentHostname: string
  description: string
  alertId?: string
}

interface DNSPageProps {
  stats?: DNSStats
  queries?: DNSQuery[]
  topDomains?: TopDomain[]
  blocklist?: BlocklistEntry[]
  alerts?: DNSAlert[]
  agents?: Array<{ id: string; hostname: string }>
  pagination?: {
    page: number
    perPage: number
    total: number
  }
}

const DNS_EVENT_TYPES = new Set(['dns_query', 'dns', 'dns_response', 'name_resolution', 'domain_lookup'])
const DNS_TRANSPORT_PORTS = new Set(['53', '5353'])
const DOT_PORTS = new Set(['853'])
const DOH_PORTS = new Set(['443', '8443'])
const KNOWN_DOH_IPS = new Set([
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '149.112.112.112',
  '94.140.14.14',
  '94.140.15.15',
  '76.76.2.0',
  '76.76.10.0',
  '185.228.168.9',
  '185.228.169.9',
])
const KNOWN_DOH_DOMAINS = new Set([
  'cloudflare-dns.com',
  'dns.google',
  'dns.quad9.net',
  'dns.adguard.com',
  'doh.opendns.com',
  'dns.nextdns.io',
  'dns.cleanbrowsing.org',
])

const DEFAULT_THREAT_FEEDS = [
  'abusech_feodo',
  'abusech_urlhaus',
  'abusech_threatfox',
  'abusech_malware_bazaar',
  'abusech_ssl_blacklist',
  'emergingthreats',
  'tor_exit_nodes',
  'phishtank',
  'openphish',
  'spamhaus_drop',
  'firehol_level1',
  'c2_intel_feeds',
]

const DNS_RECORD_TYPE_BY_CODE: Record<string, string> = {
  '1': 'A',
  '2': 'NS',
  '5': 'CNAME',
  '6': 'SOA',
  '12': 'PTR',
  '15': 'MX',
  '16': 'TXT',
  '28': 'AAAA',
  '33': 'SRV',
  '65': 'HTTPS',
  '255': 'ANY',
}

function isDnsEventType(type?: string): boolean {
  const normalized = String(type || '').toLowerCase()
  return DNS_EVENT_TYPES.has(normalized) || normalized.startsWith('dns')
}

function classifyDnsTransportEvent(eventType: unknown, payload: Record<string, unknown> = {}): 'query' | 'transport' | 'dot' | 'doh' | null {
  if (isDnsEventType(String(eventType || ''))) return 'query'
  if (!['network_connect', 'network_connection'].includes(String(eventType || '').toLowerCase())) return null

  const port = String(
    payload.remote_port ??
    payload.remotePort ??
    payload.destination_port ??
    payload.destinationPort ??
    payload.dst_port ??
    payload.dstPort ??
    payload.port ??
    payload.local_port ??
    payload.localPort ??
    payload.source_port ??
    payload.sourcePort ??
    payload.src_port ??
    payload.srcPort ??
    ''
  )
  const remoteIp = String(payload.remote_ip ?? payload.remoteIp ?? payload.dst_ip ?? payload.destination_ip ?? '')
  const targetName = String(payload.domain ?? payload.remote_domain ?? payload.sni ?? payload.tls_sni ?? payload.host ?? payload.hostname ?? '').toLowerCase()

  if (DOT_PORTS.has(port)) return 'dot'
  if (DOH_PORTS.has(port) && (KNOWN_DOH_IPS.has(remoteIp) || KNOWN_DOH_DOMAINS.has(targetName))) return 'doh'
  if (DNS_TRANSPORT_PORTS.has(port)) return 'transport'
  return null
}

function formatDnsTransportDomain(payload: Record<string, unknown>, transport: 'query' | 'transport' | 'dot' | 'doh' | null): string | undefined {
  if (!transport || transport === 'query') return undefined
  const remoteIp = String(payload.remote_ip ?? payload.remoteIp ?? payload.dst_ip ?? payload.destination_ip ?? '')
  const remotePort = String(
    payload.remote_port ??
    payload.remotePort ??
    payload.destination_port ??
    payload.destinationPort ??
    payload.dst_port ??
    payload.dstPort ??
    payload.port ??
    payload.local_port ??
    payload.localPort ??
    ''
  )
  const label = transport === 'doh' ? 'DoH resolver' : transport === 'dot' ? 'DoT resolver' : 'DNS resolver'
  return remoteIp ? `${label} ${remoteIp}${remotePort ? `:${remotePort}` : ''}` : label
}

function normalizeDnsRecordType(type: unknown): string {
  const value = String(type ?? '').trim()
  if (!value) return 'Unknown'

  const withoutPrefix = value.replace(/^type/i, '')
  if (DNS_RECORD_TYPE_BY_CODE[withoutPrefix]) return DNS_RECORD_TYPE_BY_CODE[withoutPrefix]

  const upper = value.toUpperCase()
  if (upper === 'IPV4') return 'A'
  if (upper === 'IPV6') return 'AAAA'
  return upper
}

function normalizeDnsSeverity(...values: Array<unknown>): DNSQuery['severity'] {
  for (const value of values) {
    if (value === undefined || value === null || value === '') continue

    if (typeof value === 'number' && Number.isFinite(value)) {
      if (value >= 90) return 'critical'
      if (value >= 70) return 'high'
      if (value >= 40) return 'medium'
      if (value > 0) return 'low'
      return 'info'
    }

    const normalized = String(value).trim().toLowerCase()
    if (!normalized) continue

    if (/^\d+(\.\d+)?$/.test(normalized)) {
      const score = Number(normalized)
      if (score >= 90) return 'critical'
      if (score >= 70) return 'high'
      if (score >= 40) return 'medium'
      if (score > 0) return 'low'
      return 'info'
    }

    const labels: Record<string, DNSQuery['severity']> = {
      alert: 'medium',
      crit: 'critical',
      critical: 'critical',
      emergency: 'critical',
      error: 'medium',
      fatal: 'critical',
      high: 'high',
      informational: 'info',
      info: 'info',
      low: 'low',
      medium: 'medium',
      med: 'medium',
      moderate: 'medium',
      notice: 'info',
      severe: 'critical',
      suspicious: 'medium',
      warn: 'medium',
      warning: 'medium',
    }

    if (labels[normalized]) return labels[normalized]
  }

  return 'info'
}

function normalizeDnsQuery(raw: Record<string, unknown>): DNSQuery {
  const payload = (raw.payload as Record<string, unknown> | undefined) || {}
  const process = (payload.process as Record<string, unknown> | undefined) || {}
  const dns = (payload.dns as Record<string, unknown> | undefined) || {}
  const agent = ((raw.agent || payload.agent || payload.endpoint || raw.endpoint) as Record<string, unknown> | undefined) || {}

  const pick = (...values: Array<unknown>) =>
    values.find((value) => value !== undefined && value !== null && value !== '')

  const stringify = (value: unknown, fallback = ''): string => {
    if (typeof value === 'string') return value
    if (typeof value === 'number') return String(value)
    if (typeof value === 'boolean') return String(value)
    return fallback
  }

  const toNumber = (value: unknown, fallback = 0): number => {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string') {
      const parsed = Number(value)
      return Number.isFinite(parsed) ? parsed : fallback
    }
    return fallback
  }

  const stringifyResponseItem = (value: unknown): string => {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
    if (!value || typeof value !== 'object' || Array.isArray(value)) return ''

    const item = value as Record<string, unknown>
    const responseValue = pick(
      item.data,
      item.address,
      item.ip,
      item.value,
      item.answer,
      item.response,
      item.resolved_ip,
      item.resolvedIp,
      item.host,
      item.hostname,
      item.domain,
      item.target,
      item.exchange,
      item.cname,
      item.ptr,
    )

    const text = stringify(responseValue)
    if (!text) return ''

    const type = normalizeDnsRecordType(pick(item.type, item.record_type, item.recordType, item.rrtype, item.qtype))
    const ttl = stringify(pick(item.ttl, item.time_to_live, item.timeToLive))
    const prefix = type && type !== 'Unknown' ? `${type} ` : ''
    const suffix = ttl ? ` (${ttl}s)` : ''

    return `${prefix}${text}${suffix}`
  }

  const joinList = (value: unknown): string => {
    if (!Array.isArray(value)) return ''
    return value.map((item) => stringifyResponseItem(item)).filter(Boolean).join(', ')
  }

  const normalizeDnsResponse = (...values: Array<unknown>): string => {
    for (const value of values) {
      const listValue = joinList(value)
      if (listValue) return listValue

      const scalarValue = stringify(value).trim()
      if (scalarValue) return scalarValue

      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const objectValue = stringifyResponseItem(value)
        if (objectValue) return objectValue
      }
    }

    return ''
  }

  const normalizeProcessName = (...values: Array<unknown>): string => {
    for (const value of values) {
      const text = stringify(value).trim()
      if (!text) continue

      const normalized = text.replace(/^.*[\\/]/, '')
      if (normalized) return normalized
    }

    return 'Unknown'
  }

  const formatAgentFallback = (agentId: string): string => {
    if (!agentId) return 'Unassigned agent'
    return agentId.length > 12 ? `${agentId.slice(0, 8)}...` : agentId
  }

  const agentId = stringify(
    pick(
      raw.agentId,
      raw.agent_id,
      raw.agentID,
      raw.endpoint_id,
      raw.endpointId,
      payload.agent_id,
      payload.agentId,
      payload.agentID,
      payload.endpoint_id,
      payload.endpointId,
      agent.id,
      agent.agent_id,
      agent.agentId,
      agent.endpoint_id,
      agent.endpointId,
    ),
    '',
  )

  const agentHostname = stringify(
    pick(
      raw.agentHostname,
      raw.agent_hostname,
      raw.hostname,
      raw.host,
      raw.computer_name,
      raw.computerName,
      raw.device_name,
      raw.deviceName,
      raw.endpoint_name,
      raw.endpointName,
      payload.agent_hostname,
      payload.agentHostname,
      payload.hostname,
      payload.host,
      payload.computer_name,
      payload.computerName,
      payload.device_name,
      payload.deviceName,
      payload.endpoint_name,
      payload.endpointName,
      agent.hostname,
      agent.host,
      agent.name,
      agent.computer_name,
      agent.computerName,
      agent.device_name,
      agent.deviceName,
      agent.endpoint_name,
      agent.endpointName,
    ),
    formatAgentFallback(agentId),
  )

  return {
    id: stringify(pick(raw.id), crypto.randomUUID()),
    timestamp: stringify(pick(raw.timestamp), new Date().toISOString()),
    domain: stringify(
      pick(
        raw.domain,
        raw.query,
        raw.query_name,
        raw.dns_query,
        raw.host,
        raw.hostname,
        payload.query,
        payload.query_name,
        payload.domain,
        payload.dns_query,
        payload['dns.domain'],
        payload.host,
        payload.hostname,
        dns.query,
        dns.query_name,
        dns.domain,
      ),
      'Unknown',
    ),
    queryType: normalizeDnsRecordType(
      pick(
        raw.queryType,
        raw.query_type,
        raw.queryTypeName,
        raw.query_type_name,
        raw.record_type,
        raw.recordType,
        raw.rrtype,
        raw.rr_type,
        raw.qtype,
        raw.q_type,
        raw.dns_type,
        raw.dnsType,
        raw.type,
        payload.query_type,
        payload.queryType,
        payload.query_type_name,
        payload.record_type,
        payload.recordType,
        payload.rrtype,
        payload.rr_type,
        payload.qtype,
        payload.q_type,
        payload.dns_type,
        payload.dnsType,
        payload['dns.query_type'],
        payload['dns.record_type'],
        payload['dns.qtype'],
        payload['dns.type'],
        dns.query_type,
        dns.queryType,
        dns.query_type_name,
        dns.record_type,
        dns.recordType,
        dns.rrtype,
        dns.rr_type,
        dns.qtype,
        dns.q_type,
        dns.type,
      ),
    ),
    response: normalizeDnsResponse(
      raw.response,
      raw.resolved_ip,
      raw.resolvedIp,
      raw.answer,
      raw.answers,
      raw.response_data,
      raw.responseData,
      raw.dns_response,
      raw.dnsResponse,
      raw.result,
      raw.results,
      raw.records,
      payload.response,
      payload.resolved_ip,
      payload.resolvedIp,
      payload.answer,
      payload.answers,
      payload.response_data,
      payload.responseData,
      payload.dns_response,
      payload.dnsResponse,
      payload.result,
      payload.results,
      payload.records,
      payload['dns.response'],
      payload['dns.answers'],
      payload['dns.response_data'],
      dns.response,
      dns.resolved_ip,
      dns.resolvedIp,
      dns.answer,
      dns.answers,
      dns.response_data,
      dns.responseData,
      dns.dns_response,
      dns.dnsResponse,
      dns.result,
      dns.results,
      dns.records,
      raw.responses,
      raw.resolved_ips,
      raw.resolvedIps,
      payload.responses,
      payload.resolved_ips,
      payload.resolvedIps,
      dns.responses,
      dns.resolved_ips,
      dns.resolvedIps,
      pick(raw.response_code, raw.rcode, payload.response_code, payload.rcode, dns.response_code, dns.rcode),
    ),
    processName: normalizeProcessName(
      pick(
        raw.processName,
        raw.process_name,
        raw.process,
        raw.image,
        raw.image_path,
        raw.imagePath,
        raw.executable,
        raw.exe,
        raw.command_line,
        raw.commandLine,
        raw.name,
        payload.process_name,
        payload.processName,
        payload.process,
        payload.image,
        payload.image_path,
        payload.imagePath,
        payload.executable,
        payload.exe,
        payload.command_line,
        payload.commandLine,
        payload.name,
        process.process_name,
        process.processName,
        process.image,
        process.image_path,
        process.imagePath,
        process.executable,
        process.exe,
        process.command_line,
        process.commandLine,
        process.name,
      ),
    ),
    processPid: toNumber(
      pick(
        raw.processPid,
        raw.process_pid,
        raw.pid,
        raw.process_id,
        raw.processId,
        payload.pid,
        payload.process_pid,
        payload.processPid,
        payload.process_id,
        payload.processId,
        process.pid,
        process.process_pid,
        process.processPid,
        process.process_id,
        process.processId,
      ),
      0,
    ),
    processPath:
      stringify(
        pick(
          raw.processPath,
          raw.process_path,
          raw.image_path,
          raw.imagePath,
          raw.image,
          raw.executable,
          raw.exe,
          raw.command_line,
          raw.commandLine,
          raw.path,
          payload.process_path,
          payload.processPath,
          payload.image_path,
          payload.imagePath,
          payload.image,
          payload.executable,
          payload.exe,
          payload.command_line,
          payload.commandLine,
          payload.path,
          process.process_path,
          process.processPath,
          process.image_path,
          process.imagePath,
          process.image,
          process.executable,
          process.exe,
          process.command_line,
          process.commandLine,
          process.path,
        ),
        '',
      ) || undefined,
    agentId,
    agentHostname,
    severity: normalizeDnsSeverity(
      raw.severity,
      raw.level,
      raw.priority,
      raw.risk,
      raw.risk_level,
      raw.riskLevel,
      raw.threat_level,
      raw.threatLevel,
      raw.score,
      raw.threat_score,
      raw.threatScore,
      payload.severity,
      payload.level,
      payload.priority,
      payload.risk,
      payload.risk_level,
      payload.riskLevel,
      payload.threat_level,
      payload.threatLevel,
      payload.score,
      payload.threat_score,
      payload.threatScore,
      dns.severity,
      dns.level,
      dns.risk,
      dns.score,
    ),
    status: stringify(pick(raw.status), 'allowed') as DNSQuery['status'],
    detections: Array.isArray(raw.detections) ? (raw.detections as DNSDetection[]) : undefined,
  }
}

function normalizeBlocklistEntry(raw: unknown, index = 0): BlocklistEntry {
  const entry = (typeof raw === 'object' && raw !== null ? raw : { domain: raw }) as Record<string, unknown>
  const asRecord = (value: unknown): Record<string, unknown> =>
    value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}

  const metadata = (entry.metadata && typeof entry.metadata === 'object'
    ? entry.metadata
    : {}) as Record<string, unknown>
  const payload = asRecord(entry.payload)
  const dns = asRecord(entry.dns ?? payload.dns)
  const ioc = asRecord(entry.ioc)
  const indicator = asRecord(entry.indicator)
  const observable = asRecord(entry.observable)

  const pick = (...values: Array<unknown>) =>
    values.find((value) => value !== undefined && value !== null && value !== '')

  const stringify = (value: unknown, fallback = ''): string => {
    if (typeof value === 'string') return value
    if (typeof value === 'number') return String(value)
    return fallback
  }

  const normalizeDomainValue = (value: unknown): string => {
    const rawValue = stringify(value).trim()
    if (!rawValue) return ''

    try {
      if (/^https?:\/\//i.test(rawValue)) {
        return new URL(rawValue).hostname.replace(/^\*\./, '').replace(/\.$/, '').toLowerCase()
      }
    } catch {
      // Fall through to raw domain normalization.
    }

    return rawValue
      .replace(/^\*\./, '')
      .replace(/\.$/, '')
      .toLowerCase()
  }

  const normalizeTimestamp = (value: unknown): string | undefined => {
    const rawValue = stringify(value).trim()
    if (!rawValue) return undefined

    const naiveMatch = rawValue.match(/^~N\[(.+)\]$/)
    const timestamp = naiveMatch ? naiveMatch[1] : rawValue
    return timestamp.includes('T') ? timestamp : timestamp.replace(' ', 'T')
  }

  const domain = normalizeDomainValue(
    pick(
      entry.normalized_domain,
      entry.normalizedDomain,
      entry.domain,
      entry.fqdn,
      entry.hostname,
      entry.host,
      entry.query,
      entry.query_name,
      entry.queryName,
      entry.dns_query,
      entry.dnsQuery,
      entry['dns.domain'],
      entry.value,
      entry.name,
      payload.domain,
      payload.fqdn,
      payload.hostname,
      payload.host,
      payload.query,
      payload.query_name,
      payload.queryName,
      payload.dns_query,
      payload.dnsQuery,
      payload['dns.domain'],
      dns.domain,
      dns.query,
      dns.query_name,
      dns.queryName,
      ioc.domain,
      ioc.value,
      indicator.domain,
      indicator.value,
      observable.domain,
      observable.value,
      metadata.domain,
      metadata.normalized_domain,
      metadata.normalizedDomain,
      metadata.value,
    ),
  ) || 'Unresolved domain'
  const blockedBy = stringify(
    pick(
      entry.blockedBy,
      entry.blocked_by,
      entry.blockedByUser,
      entry.blocked_by_user,
      entry.created_by,
      entry.createdBy,
      entry.created_by_user,
      entry.createdByUser,
      entry.user,
      entry.username,
      entry.actor,
      entry.principal,
      entry.owner,
      entry.email,
      metadata.blockedBy,
      metadata.blocked_by,
      metadata.created_by,
      metadata.createdBy,
      metadata.user,
      metadata.actor,
    ),
    '',
  )
  const source = stringify(
    pick(
      entry.source,
      entry.origin,
      entry.source_type,
      entry.sourceType,
      entry.feed_source,
      entry.feedSource,
      entry.feed,
      entry.provider,
      entry.import_source,
      entry.importSource,
      entry.created_by_source,
      entry.createdBySource,
      metadata.source,
      metadata.origin,
    ),
    '',
  )

  return {
    id: stringify(pick(entry.id, domain), `${domain}-${index}`),
    domain,
    blockedAt: normalizeTimestamp(
      pick(
        entry.blockedAt,
        entry.blocked_at,
        entry.blockedAtIso,
        entry.blocked_at_iso,
        entry.inserted_at,
        entry.created_at,
        entry.timestamp,
      ),
    ),
    blockedBy,
    reason: stringify(pick(entry.reason, entry.description), '') || undefined,
    source: source || undefined,
    selected: Boolean(entry.selected),
  }
}

function formatBlocklistActor(actor?: string): string {
  const normalized = String(actor || '').trim()
  if (!normalized) return 'Not recorded'

  const labels: Record<string, string> = {
    api: 'API',
    bulk_import: 'Bulk Import',
    dns_analyzer: 'DNS Analyzer',
    feed_import: 'Feed Import',
    manual: 'Manual',
    system: 'System',
    ui: 'UI',
  }

  const key = normalized.toLowerCase()
  if (labels[key]) return labels[key]
  if (normalized.includes('@')) return normalized
  return normalized.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

function formatBlocklistSource(source?: string): string {
  const normalized = String(source || '').trim()
  if (!normalized) return 'Manual'

  const labels: Record<string, string> = {
    api: 'API',
    bulk_import: 'Bulk Import',
    custom: 'Custom',
    ioc: 'IOC',
    manual: 'Manual',
    threat_feed: 'Threat Feed',
    threat_intel: 'Threat Intel',
    ui: 'Manual',
  }

  const key = normalized.toLowerCase()
  return labels[key] || normalized.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

function formatFeedName(name: string): string {
  const labels: Record<string, string> = {
    abusech_feodo: 'Abuse.ch Feodo',
    abusech_malware_bazaar: 'Abuse.ch Malware Bazaar',
    abusech_ssl_blacklist: 'Abuse.ch SSL Blacklist',
    abusech_threatfox: 'Abuse.ch ThreatFox',
    abusech_urlhaus: 'Abuse.ch URLHaus',
    c2_intel_feeds: 'C2 Intel Feeds',
    emergingthreats: 'EmergingThreats',
    firehol_level1: 'FireHOL Level 1',
    openphish: 'OpenPhish',
    phishtank: 'PhishTank',
    spamhaus_drop: 'Spamhaus DROP',
    tor_exit_nodes: 'Tor Exit Nodes',
  }

  return labels[name] || name.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

function normalizeThreatIntelFeed(raw: Record<string, unknown>): ThreatIntelFeed {
  const pick = (...values: Array<unknown>) =>
    values.find((value) => value !== undefined && value !== null && value !== '')

  const stringify = (value: unknown, fallback = ''): string => {
    if (typeof value === 'string') return value
    if (typeof value === 'number') return String(value)
    if (typeof value === 'boolean') return String(value)
    return fallback
  }

  const numberify = (value: unknown, fallback = 0): number => {
    if (typeof value === 'number') return value
    if (typeof value === 'string') {
      const parsed = Number(value)
      return Number.isFinite(parsed) ? parsed : fallback
    }
    return fallback
  }

  const name = stringify(pick(raw.name, raw.feed, raw.source), 'unknown')

  return {
    name,
    enabled: raw.enabled !== false,
    health: stringify(pick(raw.health, raw.status), raw.enabled === false ? 'disabled' : 'unknown'),
    iocCount: numberify(pick(raw.ioc_count, raw.iocCount, raw.count)),
    inserted: numberify(pick(raw.inserted, raw.inserted_count, raw.insertedCount)),
    lastSyncAt: stringify(pick(raw.last_sync_at, raw.lastSyncAt, raw.last_sync, raw.lastSync), '') || undefined,
    description: stringify(pick(raw.description), '') || undefined,
  }
}

// ============================================================================
// Tab definitions
// ============================================================================

type TabId = 'live-feed' | 'top-domains' | 'blocklist' | 'detections'

const tabs: { id: TabId; label: string; icon: React.ElementType }[] = [
  { id: 'live-feed', label: 'Live DNS Feed', icon: Activity },
  { id: 'top-domains', label: 'Top Domains', icon: BarChart3 },
  { id: 'blocklist', label: 'Blocklist', icon: ShieldOff },
  { id: 'detections', label: 'Detections', icon: AlertTriangle },
]

// ============================================================================
// Main Component
// ============================================================================

function dnsApiWarning(response: Record<string, any>, label: string): string | null {
  const meta = response?.meta
  if (!meta?.partial) return null

  if (typeof meta.message === 'string' && meta.message.trim()) {
    return meta.message
  }

  const unavailable = Array.isArray(meta.unavailable) ? meta.unavailable.filter(Boolean) : []
  return unavailable.length > 0
    ? `${label} returned partial data: ${unavailable.join('; ')}`
    : `${label} returned partial data`
}

export default function DNS({
  stats: initialStats,
  queries: initialQueries,
  topDomains: initialTopDomains,
  blocklist: initialBlocklist,
  alerts: initialAlerts,
  agents,
  pagination: initialPagination,
}: DNSPageProps) {
  const [activeTab, setActiveTab] = useState<TabId>('live-feed')
  const [stats, setStats] = useState<DNSStats>(initialStats || {
    totalQueries: 0,
    uniqueDomains: 0,
    blockedQueries: 0,
    suspiciousQueries: 0,
  })
  const [queries, setQueries] = useState<DNSQuery[]>(initialQueries || [])
  const [topDomains, setTopDomains] = useState<TopDomain[]>(initialTopDomains || [])
  const [blocklist, setBlocklist] = useState<BlocklistEntry[]>(
    (initialBlocklist || []).map((entry, index) => ({ ...normalizeBlocklistEntry(entry, index), selected: false }))
  )
  const [alerts, setAlerts] = useState<DNSAlert[]>(initialAlerts || [])
  const [pagination, setPagination] = useState(initialPagination || { page: 1, perPage: 50, total: 0 })
  const [loading, setLoading] = useState(false)
  const [apiError, setApiError] = useState<string | null>(null)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [queryTypeFilter, setQueryTypeFilter] = useState('all')
  const [agentFilter, setAgentFilter] = useState('all')
  const [processFilter, setProcessFilter] = useState('')
  const [expandedRow, setExpandedRow] = useState<string | null>(null)

  // Blocklist state
  const [newBlockDomain, setNewBlockDomain] = useState('')
  const [bulkImportText, setBulkImportText] = useState('')
  const [showBulkImport, setShowBulkImport] = useState(false)
  const [blocklistLoading, setBlocklistLoading] = useState(false)
  const [selectAll, setSelectAll] = useState(false)
  const [threatIntelFeeds, setThreatIntelFeeds] = useState<ThreatIntelFeedSummary | null>(null)
  const [threatIntelFeedsLoading, setThreatIntelFeedsLoading] = useState(false)

  // Live event streaming
  const {
    connectionState,
    events: liveEvents,
    clearEvents,
    pauseStream,
    resumeStream,
    isPaused,
  } = useEventStream()

  const mergedIdsRef = useRef(new Set<string>())

  // Merge DNS events from live stream
  useEffect(() => {
    if (!liveEvents || liveEvents.length === 0) return

    const dnsEvents = liveEvents.filter(e => {
      const payload = (e.payload || {}) as Record<string, unknown>
      return Boolean(classifyDnsTransportEvent(e.eventType, payload)) && !mergedIdsRef.current.has(e.id)
    })
    if (dnsEvents.length === 0) return

    dnsEvents.forEach(e => mergedIdsRef.current.add(e.id))

    setQueries(prev => {
      const newQueries = dnsEvents.map(e => {
        const payload = (e.payload || {}) as Record<string, unknown>
        const transport = classifyDnsTransportEvent(e.eventType, payload)

        return normalizeDnsQuery({
          id: e.id,
          timestamp: new Date(e.timestamp).toISOString(),
          agentId: e.agentId,
          agentHostname: e.agentHostname || e.agentId,
          severity: e.severity,
          status: inferQueryStatus(e, transport),
          domain: formatDnsTransportDomain(payload, transport),
          query_type: transport && transport !== 'query' ? transport.toUpperCase() : undefined,
          detections: e.detections?.map(d => ({
            type: d.type,
            ruleName: d.ruleName,
            confidence: d.confidence,
            description: d.description,
          })),
          payload,
        })
      })

      return [...newQueries, ...prev].slice(0, 500)
    })

    // Update stats optimistically
    setStats(prev => ({
      ...prev,
      totalQueries: prev.totalQueries + dnsEvents.length,
    }))
  }, [liveEvents])

  // ---- Data fetching ----

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/stats', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const json = await res.json()
        const d = json.data || json
        setApiError(dnsApiWarning(json, 'DNS stats'))
        setStats({
          totalQueries: d.total_queries_today ?? d.totalQueries ?? 0,
          uniqueDomains: d.unique_domains ?? d.uniqueDomains ?? 0,
          blockedQueries: d.blocked_count ?? d.blockedQueries ?? 0,
          suspiciousQueries: d.suspicious_count ?? d.suspiciousQueries ?? 0,
        })
      } else {
        setApiError(`DNS stats failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS stats failed: ${error instanceof Error ? error.message : 'network error'}`)
    }
  }, [])

  const fetchQueries = useCallback(async (page = 1) => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('per_page', '50')
      if (searchQuery) params.set('domain', searchQuery)
      if (queryTypeFilter !== 'all') params.set('query_type', queryTypeFilter)
      if (agentFilter !== 'all') params.set('agent_id', agentFilter)
      if (processFilter) params.set('process', processFilter)

      const res = await fetch(`/api/v1/dns/queries?${params.toString()}`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        const rawQueries = data.queries || data.data || []
        setApiError(dnsApiWarning(data, 'DNS query feed'))
        setQueries(Array.isArray(rawQueries) ? rawQueries.map((query: Record<string, unknown>) => normalizeDnsQuery(query)) : [])
        if (data.pagination) {
          setPagination(data.pagination)
        } else if (data.meta) {
          const limit = Number(data.meta.limit ?? data.meta.per_page ?? data.meta.perPage ?? 50)
          const offset = Number(data.meta.offset ?? 0)
          const total = Number(data.meta.total ?? data.meta.total_count ?? 0)
          setPagination({
            page: Math.floor(offset / Math.max(limit, 1)) + 1,
            perPage: limit,
            total,
          })
        }
      } else {
        setApiError(`DNS query feed failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS query feed failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setLoading(false)
    }
  }, [searchQuery, queryTypeFilter, agentFilter, processFilter])

  const fetchTopDomains = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/top-domains', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        const rawDomains = data.domains || data.data || []
        setApiError(dnsApiWarning(data, 'Top DNS domains'))
        setTopDomains(Array.isArray(rawDomains) ? rawDomains : [])
      } else {
        setApiError(`Top domains failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`Top domains failed: ${error instanceof Error ? error.message : 'network error'}`)
    }
  }, [])

  const fetchBlocklist = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/blocklist', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        setApiError(dnsApiWarning(data, 'DNS blocklist'))
        setBlocklist((data.blocklist || data.data || []).map((entry: unknown, index: number) => ({
          ...normalizeBlocklistEntry(entry, index),
          selected: false,
        })))
        if (Array.isArray(data.meta?.default_feeds)) {
          const fallbackFeeds = {
            enabled: true,
            totalIocs: 0,
            feeds: data.meta.default_feeds.map((feed: Record<string, unknown>) => normalizeThreatIntelFeed(feed)),
          }
          setThreatIntelFeeds(current => current ?? fallbackFeeds)
        }
      } else {
        setApiError(`DNS blocklist failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS blocklist failed: ${error instanceof Error ? error.message : 'network error'}`)
    }
  }, [])

  const fetchThreatIntelFeeds = useCallback(async () => {
    setThreatIntelFeedsLoading(true)
    try {
      const res = await fetch('/api/v1/threat-intel/feed-status', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const json = await res.json()
        const data = json.data || json
        const rawFeeds = Array.isArray(data.feeds) ? data.feeds : []
        setThreatIntelFeeds({
          enabled: Boolean(data.enabled),
          totalIocs: Number(data.total_iocs ?? data.totalIocs ?? 0),
          syncIntervalHours: Number(data.sync_interval_hours ?? data.syncIntervalHours ?? 0) || undefined,
          lastGlobalSync: data.last_global_sync ?? data.lastGlobalSync ?? undefined,
          feeds: rawFeeds.map((feed: Record<string, unknown>) => normalizeThreatIntelFeed(feed)),
        })
      } else {
        setApiError(`Threat intel feed status failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`Threat intel feed status failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setThreatIntelFeedsLoading(false)
    }
  }, [])

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/dns/alerts', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        setApiError(dnsApiWarning(data, 'DNS detections'))
        setAlerts(data.alerts || data.data || [])
      } else {
        setApiError(`DNS detections failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS detections failed: ${error instanceof Error ? error.message : 'network error'}`)
    }
  }, [])

  // Fetch data on mount and tab change
  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  useEffect(() => {
    if (activeTab === 'live-feed') fetchQueries()
    if (activeTab === 'top-domains') fetchTopDomains()
    if (activeTab === 'blocklist') {
      fetchBlocklist()
      fetchThreatIntelFeeds()
    }
    if (activeTab === 'detections') fetchAlerts()
  }, [activeTab, fetchQueries, fetchTopDomains, fetchBlocklist, fetchThreatIntelFeeds, fetchAlerts])

  // ---- Blocklist actions ----

  const addToBlocklist = async (domain: string) => {
    if (!domain.trim()) return
    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      const res = await fetch('/api/v1/dns/blocklist', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
        body: JSON.stringify({ domains: [domain.trim()], reason: 'Manual block' }),
      })
      if (res.ok) {
        setApiError(null)
        setNewBlockDomain('')
        fetchBlocklist()
        fetchStats()
      } else {
        setApiError(`DNS blocklist add failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS blocklist add failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setBlocklistLoading(false)
    }
  }

  const removeFromBlocklist = async (domain: string) => {
    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      const res = await fetch(`/api/v1/dns/blocklist/${encodeURIComponent(domain)}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
      })
      if (res.ok) {
        setApiError(null)
        fetchBlocklist()
        fetchStats()
      } else {
        setApiError(`DNS blocklist remove failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS blocklist remove failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setBlocklistLoading(false)
    }
  }

  const bulkAddToBlocklist = async () => {
    const text = bulkImportText.trim()
    if (!text) return

    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      const res = await fetch('/api/v1/dns/blocklist/import', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
        },
        body: JSON.stringify({ text, reason: 'Bulk import' }),
      })
      if (res.ok) {
        setApiError(null)
        setBulkImportText('')
        setShowBulkImport(false)
        fetchBlocklist()
        fetchStats()
      } else {
        setApiError(`DNS blocklist import failed with HTTP ${res.status}`)
      }
    } catch (error) {
      setApiError(`DNS blocklist import failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setBlocklistLoading(false)
    }
  }

  const removeSelectedFromBlocklist = async () => {
    const selectedDomains = blocklist.filter(e => e.selected).map(e => e.domain)
    if (selectedDomains.length === 0) return

    setBlocklistLoading(true)
    try {
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
      for (const domain of selectedDomains) {
        const res = await fetch(`/api/v1/dns/blocklist/${encodeURIComponent(domain)}`, {
          method: 'DELETE',
          credentials: 'include',
          headers: {
            'Accept': 'application/json',
            ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
          },
        })
        if (!res.ok) {
          throw new Error(`${domain} returned HTTP ${res.status}`)
        }
      }
      setApiError(null)
      fetchBlocklist()
      fetchStats()
    } catch (error) {
      setApiError(`DNS blocklist bulk remove failed: ${error instanceof Error ? error.message : 'network error'}`)
    } finally {
      setBlocklistLoading(false)
    }
  }

  const toggleBlocklistSelection = (id: string) => {
    setBlocklist(prev =>
      prev.map(e => (e.id === id ? { ...e, selected: !e.selected } : e))
    )
  }

  const toggleSelectAll = () => {
    const newVal = !selectAll
    setSelectAll(newVal)
    setBlocklist(prev => prev.map(e => ({ ...e, selected: newVal })))
  }

  // ---- Filtering ----

  const filteredQueries = useMemo(() => {
    return queries.filter(q => {
      if (searchQuery && !q.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false
      if (queryTypeFilter !== 'all' && q.queryType !== queryTypeFilter) return false
      if (agentFilter !== 'all' && q.agentId !== agentFilter) return false
      if (processFilter) {
        const normalizedProcessFilter = processFilter.toLowerCase()
        const processText = `${q.processName} ${q.processPid || ''} ${q.processPath || ''}`.toLowerCase()
        if (!processText.includes(normalizedProcessFilter)) return false
      }
      return true
    })
  }, [queries, searchQuery, queryTypeFilter, agentFilter, processFilter])

  const selectedCount = blocklist.filter(e => e.selected).length

  // ---- Pagination ----

  const totalPages = Math.max(1, Math.ceil(pagination.total / pagination.perPage))

  const goToPage = (page: number) => {
    if (page < 1 || page > totalPages) return
    setPagination(prev => ({ ...prev, page }))
    fetchQueries(page)
  }

  // ---- Export helpers ----

  const getQueryExportData = () =>
    filteredQueries.map(q => ({
      id: q.id,
      timestamp: q.timestamp,
      domain: q.domain,
      query_type: q.queryType,
      response: q.response,
      process_name: q.processName,
      process_pid: q.processPid,
      process_path: q.processPath || '',
      agent_id: q.agentId,
      agent_hostname: q.agentHostname,
      severity: q.severity,
      status: q.status,
    }))

  const getBlocklistExportData = () =>
    blocklist.map(e => ({
      domain: e.domain,
      blocked_at: e.blockedAt || '',
      blocked_by: e.blockedBy || 'not_recorded',
      reason: e.reason,
      source: e.source || 'manual',
    }))

  return (
    <MainLayout title="DNS Monitoring">
      <Head title="DNS - Tamandua EDR" />

      {/* Stats Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Total Queries Today"
          value={stats.totalQueries}
          icon={Globe}
          iconColor="var(--sol-cyan)"
        />
        <StatCard
          label="Unique Domains"
          value={stats.uniqueDomains}
          icon={List}
          iconColor="var(--sol-blue)"
        />
        <StatCard
          label="Blocked Queries"
          value={stats.blockedQueries}
          icon={ShieldOff}
          iconColor="var(--crit)"
        />
        <StatCard
          label="Suspicious Queries"
          value={stats.suspiciousQueries}
          icon={AlertTriangle}
          iconColor="var(--warn)"
        />
      </div>

      {apiError && (
        <div className="mb-6 flex items-start justify-between gap-3 rounded-md border border-[var(--warn)]/40 bg-[var(--warn)]/10 px-4 py-3 text-sm text-[var(--fg)]">
          <div className="flex items-start gap-2">
            <FileWarning className="mt-0.5 h-4 w-4 shrink-0 text-[var(--warn)]" />
            <div>
              <div className="font-medium">DNS data did not load cleanly</div>
              <div className="text-[var(--muted)]">{apiError}</div>
            </div>
          </div>
          <button type="button" onClick={() => setApiError(null)} className="text-[var(--muted)] hover:text-[var(--fg)]">
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 border-b border-[var(--border)] pb-0">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px',
              activeTab === tab.id
                ? 'border-[var(--sol-cyan)] text-[var(--fg)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--border)]'
            )}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'live-feed' && (
        <LiveDNSFeed
          queries={filteredQueries}
          agents={agents || []}
          loading={loading}
          apiError={apiError}
          connectionState={connectionState}
          isPaused={isPaused}
          pauseStream={pauseStream}
          resumeStream={resumeStream}
          clearEvents={() => { clearEvents(); setQueries([]) }}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          queryTypeFilter={queryTypeFilter}
          setQueryTypeFilter={setQueryTypeFilter}
          agentFilter={agentFilter}
          setAgentFilter={setAgentFilter}
          processFilter={processFilter}
          setProcessFilter={setProcessFilter}
          expandedRow={expandedRow}
          setExpandedRow={setExpandedRow}
          pagination={pagination}
          totalPages={totalPages}
          goToPage={goToPage}
          onRefresh={() => fetchQueries(pagination.page)}
          getExportData={getQueryExportData}
        />
      )}

      {activeTab === 'top-domains' && (
        <TopDomainsPanel
          domains={topDomains}
          onRefresh={fetchTopDomains}
        />
      )}

      {activeTab === 'blocklist' && (
        <BlocklistManagement
          blocklist={blocklist}
          loading={blocklistLoading}
          newBlockDomain={newBlockDomain}
          setNewBlockDomain={setNewBlockDomain}
          addToBlocklist={addToBlocklist}
          removeFromBlocklist={removeFromBlocklist}
          bulkImportText={bulkImportText}
          setBulkImportText={setBulkImportText}
          showBulkImport={showBulkImport}
          setShowBulkImport={setShowBulkImport}
          bulkAddToBlocklist={bulkAddToBlocklist}
          toggleBlocklistSelection={toggleBlocklistSelection}
          toggleSelectAll={toggleSelectAll}
          selectAll={selectAll}
          selectedCount={selectedCount}
          removeSelectedFromBlocklist={removeSelectedFromBlocklist}
          threatIntelFeeds={threatIntelFeeds}
          threatIntelFeedsLoading={threatIntelFeedsLoading}
          onRefresh={() => {
            fetchBlocklist()
            fetchThreatIntelFeeds()
          }}
          getExportData={getBlocklistExportData}
        />
      )}

      {activeTab === 'detections' && (
        <DNSDetections
          alerts={alerts}
          onRefresh={fetchAlerts}
        />
      )}
    </MainLayout>
  )
}

// ============================================================================
// Stat Card
// ============================================================================

function StatCard({
  label,
  value,
  icon: Icon,
  iconColor,
}: {
  label: string
  value: number
  icon: React.ElementType
  iconColor: string
}) {
  return (
    <div className="card-sentinel p-4 flex items-center gap-4">
      <div
        className="p-3 rounded-lg"
        style={{ backgroundColor: `color-mix(in srgb, ${iconColor} 15%, transparent)` }}
      >
        <Icon className="h-5 w-5" style={{ color: iconColor }} />
      </div>
      <div>
        <p className="text-2xl font-bold text-[var(--fg)]">{value.toLocaleString()}</p>
        <p className="text-xs text-[var(--muted)]">{label}</p>
      </div>
    </div>
  )
}

// ============================================================================
// Live DNS Feed Tab
// ============================================================================

interface LiveDNSFeedProps {
  queries: DNSQuery[]
  agents: Array<{ id: string; hostname: string }>
  loading: boolean
  apiError: string | null
  connectionState: WebSocketConnectionState
  isPaused: boolean
  pauseStream: () => void
  resumeStream: () => void
  clearEvents: () => void
  searchQuery: string
  setSearchQuery: (v: string) => void
  queryTypeFilter: string
  setQueryTypeFilter: (v: string) => void
  agentFilter: string
  setAgentFilter: (v: string) => void
  processFilter: string
  setProcessFilter: (v: string) => void
  expandedRow: string | null
  setExpandedRow: (v: string | null) => void
  pagination: { page: number; perPage: number; total: number }
  totalPages: number
  goToPage: (page: number) => void
  onRefresh: () => void
  getExportData: () => Record<string, any>[]
}

function LiveDNSFeed({
  queries,
  agents,
  loading,
  apiError,
  connectionState,
  isPaused,
  pauseStream,
  resumeStream,
  clearEvents,
  searchQuery,
  setSearchQuery,
  queryTypeFilter,
  setQueryTypeFilter,
  agentFilter,
  setAgentFilter,
  processFilter,
  setProcessFilter,
  expandedRow,
  setExpandedRow,
  pagination,
  totalPages,
  goToPage,
  onRefresh,
  getExportData,
}: LiveDNSFeedProps) {
  const queryTypes = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'TRANSPORT', 'DOH', 'DOT']

  return (
    <div className="card-sentinel">
      {/* Toolbar */}
      <div className="p-4 border-b border-[var(--border)] space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
            <input
              type="text"
              placeholder="Search by domain or resolver..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
          </div>

          <div className="relative min-w-[120px]">
            <input
              type="text"
              placeholder="Process..."
              value={processFilter}
              onChange={e => setProcessFilter(e.target.value)}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
          </div>

          <ConnectionStatus state={connectionState} showText={false} />

          <button
            onClick={() => (isPaused ? resumeStream() : pauseStream())}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors',
              !isPaused
                ? 'bg-[var(--ok)] text-white'
                : 'bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)]'
            )}
          >
            {isPaused ? (
              <>
                <Play className="h-4 w-4" />
                Resume
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                Live
              </>
            )}
          </button>

          <button
            onClick={clearEvents}
            className="flex items-center gap-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] px-3 py-2 rounded-lg text-sm"
            title="Clear"
          >
            <Trash2 className="h-4 w-4" />
          </button>

          <button
            onClick={onRefresh}
            className="flex items-center gap-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] px-3 py-2 rounded-lg text-sm"
            title="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </button>

          <ExportDropdown
            getData={getExportData}
            filenameBase="tamandua-dns-queries"
            disabled={queries.length === 0}
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[var(--muted)]" />
            <Select
              value={queryTypeFilter}
              onValueChange={setQueryTypeFilter}
              placeholder="All DNS Types"
              className="bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--fg)] focus:ring-2 focus:ring-[var(--sol-cyan)]"
            >
              <SelectItem value="all">All DNS Types</SelectItem>
              {queryTypes.map(t => (
                <SelectItem key={t} value={t}>{t}</SelectItem>
              ))}
            </Select>
          </div>

          <Select
            value={agentFilter}
            onValueChange={setAgentFilter}
            placeholder="All Agents"
            className="bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--fg)] focus:ring-2 focus:ring-[var(--sol-cyan)]"
          >
            <SelectItem value="all">All Agents</SelectItem>
            {agents.map(a => (
              <SelectItem key={a.id} value={a.id}>{a.hostname}</SelectItem>
            ))}
          </Select>

          <span className="text-sm text-[var(--muted)]">
            {loading ? 'Loading DNS records...' : `${queries.length} DNS records`}
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--border)] text-left">
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Timestamp</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Domain / Resolver</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Type</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Response</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Process</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Agent</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Severity</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider w-8"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {queries.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-[var(--muted)]">
                  <Globe className={cn('h-12 w-12 mx-auto mb-3 opacity-40', loading && 'animate-pulse')} />
                  <p>
                    {loading
                      ? 'Loading DNS telemetry...'
                      : 'No DNS records found'}
                  </p>
                  <p className="text-sm mt-1">
                    {loading
                      ? 'Fetching historical queries, resolver events, DoH, and DoT telemetry'
                      : apiError
                        ? 'DNS query feed failed. Check the API error above before treating this as an empty tenant.'
                        : 'Adjust filters or wait for DNS query, resolver, DoH, or DoT telemetry'}
                  </p>
                </td>
              </tr>
            ) : (
              queries.map(query => (
                <DNSQueryRow
                  key={query.id}
                  query={query}
                  expanded={expandedRow === query.id}
                  onToggle={() => setExpandedRow(expandedRow === query.id ? null : query.id)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination.total > pagination.perPage && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border)]">
          <span className="text-sm text-[var(--muted)]">
            Page {pagination.page} of {totalPages} ({pagination.total} total)
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => goToPage(pagination.page - 1)}
              disabled={pagination.page <= 1}
              className="p-2 rounded-lg bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const startPage = Math.max(1, pagination.page - 2)
              const pageNum = startPage + i
              if (pageNum > totalPages) return null
              return (
                <button
                  key={pageNum}
                  onClick={() => goToPage(pageNum)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                    pageNum === pagination.page
                      ? 'bg-[var(--sol-cyan)] text-white'
                      : 'bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)]'
                  )}
                >
                  {pageNum}
                </button>
              )
            })}
            <button
              onClick={() => goToPage(pagination.page + 1)}
              disabled={pagination.page >= totalPages}
              className="p-2 rounded-lg bg-[var(--surface-alt)] text-[var(--muted)] hover:bg-[var(--border)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// DNS Query Row (with expandable details)
// ============================================================================

function DNSQueryRow({
  query,
  expanded,
  onToggle,
}: {
  query: DNSQuery
  expanded: boolean
  onToggle: () => void
}) {
  const statusColors: Record<string, { bg: string; text: string; border: string }> = {
    blocked: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    suspicious: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    allowed: { bg: 'var(--ok)', text: 'var(--ok)', border: 'var(--ok)' },
  }

  const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    high: { bg: 'var(--high)', text: 'var(--high)', border: 'var(--high)' },
    medium: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    low: { bg: 'var(--sol-blue)', text: 'var(--sol-blue)', border: 'var(--sol-blue)' },
    info: { bg: 'var(--muted)', text: 'var(--muted)', border: 'var(--muted)' },
  }

  const rowBg =
    query.status === 'blocked'
      ? 'bg-[color-mix(in_srgb,var(--crit)_5%,transparent)] hover:bg-[color-mix(in_srgb,var(--crit)_10%,transparent)]'
      : query.status === 'suspicious'
        ? 'bg-[color-mix(in_srgb,var(--warn)_5%,transparent)] hover:bg-[color-mix(in_srgb,var(--warn)_10%,transparent)]'
        : 'hover:bg-[var(--surface-alt)]'

  const currentStatus = statusColors[query.status] || statusColors.allowed
  const currentSeverity = severityStyles[query.severity] || severityStyles.info

  return (
    <>
      <tr
        className={cn('cursor-pointer transition-colors', rowBg)}
        onClick={onToggle}
      >
        <td className="px-4 py-3 text-sm text-[var(--fg)] whitespace-nowrap">
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3 text-[var(--muted)]" />
            {formatDate(query.timestamp)}
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {query.status === 'blocked' && <ShieldOff className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--crit)' }} />}
            {query.status === 'suspicious' && <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--warn)' }} />}
            <span className="text-sm font-mono truncate max-w-[280px]" style={{ color: 'var(--sol-cyan)' }} title={query.domain}>
              {query.domain}
            </span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--surface-alt)] text-[var(--fg)]">
            {query.queryType}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-[var(--muted)] font-mono truncate max-w-[160px]" title={query.response}>
          {query.response || '--'}
        </td>
        <td className="px-4 py-3">
          <span className="text-sm text-[var(--fg)]" title={query.processPath || query.processName}>{query.processName}</span>
          {query.processPid > 0 && (
            <span className="text-xs text-[var(--muted)] ml-1">({query.processPid})</span>
          )}
        </td>
        <td className="px-4 py-3 text-sm text-[var(--muted)]">
          <span title={query.agentId || query.agentHostname}>
            {query.agentHostname || 'Unassigned agent'}
          </span>
        </td>
        <td className="px-4 py-3">
          <span
            className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border"
            style={{
              backgroundColor: `color-mix(in srgb, ${currentSeverity.bg} 20%, transparent)`,
              color: currentSeverity.text,
              borderColor: `color-mix(in srgb, ${currentSeverity.border} 30%, transparent)`,
            }}
          >
            {safeCapitalize(query.severity)}
          </span>
        </td>
        <td className="px-4 py-3">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-[var(--muted)]" />
          ) : (
            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
          )}
        </td>
      </tr>

      {/* Expanded details row */}
      {expanded && (
        <tr className="bg-[var(--surface-alt)]">
          <td colSpan={8} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Full Response
                </h4>
                <p className="text-sm text-[var(--fg)] font-mono break-all">
                  {query.response || 'No response data'}
                </p>
              </div>
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Process Details
                </h4>
                <div className="space-y-1 text-sm">
                  <p className="text-[var(--fg)]">
                    <span className="text-[var(--muted)]">Name:</span> {query.processName}
                  </p>
                  <p className="text-[var(--fg)]">
                    <span className="text-[var(--muted)]">PID:</span> {query.processPid > 0 ? query.processPid : 'Not recorded'}
                  </p>
                  {query.processPath && (
                    <p className="text-[var(--fg)] break-all">
                      <span className="text-[var(--muted)]">Path:</span> {query.processPath}
                    </p>
                  )}
                </div>
              </div>
              <div>
                <h4 className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider mb-2">
                  Status & Detections
                </h4>
                <div className="space-y-2">
                  <span
                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border"
                    style={{
                      backgroundColor: `color-mix(in srgb, ${currentStatus.bg} 10%, transparent)`,
                      color: currentStatus.text,
                      borderColor: `color-mix(in srgb, ${currentStatus.border} 30%, transparent)`,
                    }}
                  >
                    {query.status === 'blocked' && <ShieldOff className="h-3 w-3 mr-1" />}
                    {query.status === 'suspicious' && <AlertTriangle className="h-3 w-3 mr-1" />}
                    {query.status === 'allowed' && <CheckCircle className="h-3 w-3 mr-1" />}
                    {safeCapitalize(query.status)}
                  </span>

                  {query.detections && query.detections.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {query.detections.map((d, i) => (
                        <div key={i} className="text-xs bg-[var(--surface)] rounded p-2 border border-[var(--border)]">
                          <p style={{ color: 'var(--warn)' }} className="font-medium">{d.ruleName}</p>
                          <p className="text-[var(--muted)] mt-0.5">{d.description}</p>
                          <p className="text-[var(--muted)] mt-0.5">
                            Type: {d.type} | Confidence: {d.confidence}%
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex gap-2 mt-4 pt-3 border-t border-[var(--border)]">
              <button
                onClick={e => {
                  e.stopPropagation()
                  router.visit(`/app/hunt?q=${encodeURIComponent(`domain:${query.domain}`)}`)
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sol-cyan)] hover:bg-[color-mix(in_srgb,var(--sol-cyan)_85%,black)] text-white text-xs font-medium rounded-lg"
              >
                <Search className="h-3 w-3" />
                Hunt Indicator
              </button>
              <button
                onClick={e => {
                  e.stopPropagation()
                  if (query.agentId) router.visit(`/app/agents/${query.agentId}`)
                }}
                disabled={!query.agentId}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] text-xs font-medium rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Eye className="h-3 w-3" />
                View Agent
              </button>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ============================================================================
// Top Domains Panel
// ============================================================================

function TopDomainsPanel({
  domains,
  onRefresh,
}: {
  domains: TopDomain[]
  onRefresh: () => void
}) {
  const maxCount = domains.length > 0 ? Math.max(...domains.map(d => d.count)) : 1

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--fg)]">Top 20 Queried Domains</h3>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {domains.length === 0 ? (
        <div className="px-4 py-12 text-center text-[var(--muted)]">
          <BarChart3 className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No domain data available</p>
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-subtle)]">
          {domains.slice(0, 20).map((domain, idx) => (
            <div key={domain.domain} className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--surface-alt)] transition-colors">
              <span className="text-xs font-mono text-[var(--muted)] w-6 text-right">{idx + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono truncate" style={{ color: 'var(--sol-cyan)' }} title={domain.domain}>
                  {domain.domain}
                </p>
                <div className="mt-1 h-1.5 bg-[var(--surface-alt)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${(domain.count / maxCount) * 100}%`, backgroundColor: 'var(--sol-cyan)' }}
                  />
                </div>
              </div>
              <span className="text-sm font-medium text-[var(--fg)] tabular-nums">
                {domain.count.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Blocklist Management
// ============================================================================

interface BlocklistManagementProps {
  blocklist: BlocklistEntry[]
  loading: boolean
  newBlockDomain: string
  setNewBlockDomain: (v: string) => void
  addToBlocklist: (domain: string) => void
  removeFromBlocklist: (domain: string) => void
  bulkImportText: string
  setBulkImportText: (v: string) => void
  showBulkImport: boolean
  setShowBulkImport: (v: boolean) => void
  bulkAddToBlocklist: () => void
  toggleBlocklistSelection: (id: string) => void
  toggleSelectAll: () => void
  selectAll: boolean
  selectedCount: number
  removeSelectedFromBlocklist: () => void
  threatIntelFeeds: ThreatIntelFeedSummary | null
  threatIntelFeedsLoading: boolean
  onRefresh: () => void
  getExportData: () => Record<string, any>[]
}

function BlocklistManagement({
  blocklist,
  loading,
  newBlockDomain,
  setNewBlockDomain,
  addToBlocklist,
  removeFromBlocklist,
  bulkImportText,
  setBulkImportText,
  showBulkImport,
  setShowBulkImport,
  bulkAddToBlocklist,
  toggleBlocklistSelection,
  toggleSelectAll,
  selectAll,
  selectedCount,
  removeSelectedFromBlocklist,
  threatIntelFeeds,
  threatIntelFeedsLoading,
  onRefresh,
  getExportData,
}: BlocklistManagementProps) {
  const feedRows = threatIntelFeeds?.feeds.length
    ? threatIntelFeeds.feeds
    : DEFAULT_THREAT_FEEDS.map(name => ({
      name,
      enabled: true,
      health: 'configured',
      iocCount: 0,
      inserted: 0,
      description: undefined,
    }))

  const visibleFeeds = [...feedRows]
    .sort((a, b) => (b.iocCount - a.iocCount) || a.name.localeCompare(b.name))
    .slice(0, 6)

  const activeFeedCount = feedRows.filter(feed => feed.enabled !== false).length

  return (
    <div className="space-y-4">
      {/* Add domain bar */}
      <div className="card-sentinel p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[240px] flex gap-2">
            <input
              type="text"
              placeholder="Enter domain to block (e.g. malware.example.com)"
              value={newBlockDomain}
              onChange={e => setNewBlockDomain(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addToBlocklist(newBlockDomain) }}
              className="flex-1 bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent"
            />
            <button
              onClick={() => addToBlocklist(newBlockDomain)}
              disabled={!newBlockDomain.trim() || loading}
              className="flex items-center gap-2 px-4 py-2 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              <Plus className="h-4 w-4" />
              Block
            </button>
          </div>

          <button
            onClick={() => setShowBulkImport(!showBulkImport)}
            className="flex items-center gap-2 px-3 py-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] rounded-lg text-sm"
          >
            <Upload className="h-4 w-4" />
            Bulk Import
          </button>

          <button
            onClick={onRefresh}
            className="p-2 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
            title="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </button>

          <ExportDropdown
            getData={getExportData}
            filenameBase="tamandua-dns-blocklist"
            disabled={blocklist.length === 0}
          />
        </div>

        {/* Bulk import textarea */}
        {showBulkImport && (
          <div className="mt-3 space-y-2">
            <textarea
              value={bulkImportText}
              onChange={e => setBulkImportText(e.target.value)}
              placeholder="Enter domains to block, one per line..."
              rows={6}
              className="w-full bg-[var(--surface-alt)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--sol-cyan)] focus:border-transparent font-mono"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={bulkAddToBlocklist}
                disabled={!bulkImportText.trim() || loading}
                className="flex items-center gap-2 px-4 py-2 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] disabled:opacity-40 text-white rounded-lg text-sm font-medium"
              >
                <Plus className="h-4 w-4" />
                Add All ({bulkImportText.split('\n').filter(l => l.trim()).length} domains)
              </button>
              <button
                onClick={() => { setShowBulkImport(false); setBulkImportText('') }}
                className="px-3 py-2 bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] rounded-lg text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Bulk actions */}
      {selectedCount > 0 && (
        <div
          className="flex items-center gap-3 rounded-lg px-4 py-2.5 border"
          style={{
            backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)',
            borderColor: 'color-mix(in srgb, var(--warn) 30%, transparent)',
          }}
        >
          <span className="text-sm" style={{ color: 'var(--warn)' }}>{selectedCount} selected</span>
          <button
            onClick={removeSelectedFromBlocklist}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--crit)] hover:bg-[color-mix(in_srgb,var(--crit)_85%,black)] text-white rounded-lg text-xs font-medium"
          >
            <Trash2 className="h-3 w-3" />
            Remove Selected
          </button>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(280px,360px)]">
        <div className="card-sentinel p-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-[var(--sol-cyan)]" />
                <h3 className="text-sm font-semibold text-[var(--fg)]">DNS blocklist overrides</h3>
              </div>
              <p className="mt-2 text-sm text-[var(--muted)]">
                Tenant-specific domains added here are enforced as explicit DNS blocks. Default threat intel feeds are managed separately and matched during DNS analysis.
              </p>
            </div>
            <a
              href="/app/threat-intel"
              className="shrink-0 inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-sm text-[var(--fg)]"
            >
              Threat Intel
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>

        <div className="card-sentinel p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4 text-[var(--sol-cyan)]" />
                <h3 className="text-sm font-semibold text-[var(--fg)]">Default threat intel feeds</h3>
              </div>
              <p className="mt-1 text-xs text-[var(--muted)]">
                {threatIntelFeedsLoading
                  ? 'Loading feed status...'
                  : `${activeFeedCount} enabled feeds · ${(threatIntelFeeds?.totalIocs || 0).toLocaleString()} IOCs`}
              </p>
            </div>
            {threatIntelFeeds?.syncIntervalHours && (
              <span className="text-xs text-[var(--muted)]">
                {threatIntelFeeds.syncIntervalHours}h sync
              </span>
            )}
          </div>

          <div className="mt-3 space-y-2">
            {visibleFeeds.map(feed => (
              <div key={feed.name} className="flex items-center justify-between gap-3 rounded-lg bg-[var(--surface-alt)] px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-[var(--fg)]">{formatFeedName(feed.name)}</p>
                  <p className="truncate text-[11px] text-[var(--muted)]">{feed.description || feed.health}</p>
                </div>
                <div className="shrink-0 text-right">
                  <p className="text-xs tabular-nums text-[var(--fg)]">{feed.iocCount.toLocaleString()}</p>
                  <p className="text-[11px] capitalize text-[var(--muted)]">{feed.health}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Blocklist table */}
      <div className="card-sentinel overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--border)] text-left">
              <th className="px-4 py-3 w-10">
                <Checkbox
                  checked={selectAll}
                  onCheckedChange={toggleSelectAll}
                  aria-label="Select all blocklist entries"
                />
              </th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Domain</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Blocked At</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Source</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Blocked By</th>
              <th className="px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider w-20">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {blocklist.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-[var(--muted)]">
                  <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p className="text-[var(--fg)]">No DNS blocklist overrides</p>
                  <p className="text-sm mt-1">
                    Default threat intel feeds are visible in the panel above and in Threat Intel. Add a domain here only when you want a tenant-specific DNS block.
                  </p>
                </td>
              </tr>
            ) : (
              blocklist.map(entry => (
                <tr key={entry.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                  <td className="px-4 py-3">
                    <Checkbox
                      checked={entry.selected || false}
                      onCheckedChange={() => toggleBlocklistSelection(entry.id)}
                      aria-label={`Select ${entry.domain}`}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="space-y-1">
                      <span className="text-sm text-[var(--fg)] font-mono">{entry.domain}</span>
                      {entry.reason && (
                        <p className="text-xs text-[var(--muted)]">{entry.reason}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    {entry.blockedAt ? formatDate(entry.blockedAt) : 'Not recorded'}
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    <span title={entry.source || 'manual'}>
                      {formatBlocklistSource(entry.source)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-[var(--muted)]">
                    <span title={entry.blockedBy || 'not_recorded'}>
                      {formatBlocklistActor(entry.blockedBy)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => removeFromBlocklist(entry.domain)}
                      disabled={loading}
                      className="p-1.5 rounded-lg transition-colors disabled:opacity-40"
                      style={{
                        backgroundColor: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                        color: 'var(--crit)',
                      }}
                      title="Remove from blocklist"
                    >
                      <XCircle className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// DNS Detections
// ============================================================================

function DNSDetections({
  alerts,
  onRefresh,
}: {
  alerts: DNSAlert[]
  onRefresh: () => void
}) {
  const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--crit)', text: 'var(--crit)', border: 'var(--crit)' },
    high: { bg: 'var(--high)', text: 'var(--high)', border: 'var(--high)' },
    medium: { bg: 'var(--warn)', text: 'var(--warn)', border: 'var(--warn)' },
    low: { bg: 'var(--sol-blue)', text: 'var(--sol-blue)', border: 'var(--sol-blue)' },
  }

  const detectionTypeLabels: Record<string, { label: string; icon: React.ElementType }> = {
    tunneling: { label: 'DNS Tunneling', icon: Shield },
    dga: { label: 'DGA Detected', icon: FileWarning },
    suspicious_domain: { label: 'Suspicious Domain', icon: AlertTriangle },
    ioc_match: { label: 'IOC Match', icon: Shield },
    exfiltration: { label: 'Data Exfiltration', icon: AlertTriangle },
  }

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--fg)]">DNS-Specific Detections</h3>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)]"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="px-4 py-12 text-center text-[var(--muted)]">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No DNS detections</p>
          <p className="text-sm mt-1">DNS-specific detections will appear here</p>
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-subtle)]">
          {alerts.map(alert => {
            const typeInfo = detectionTypeLabels[alert.detectionType] || {
              label: alert.detectionType,
              icon: AlertTriangle,
            }
            const TypeIcon = typeInfo.icon
            const severity = severityStyles[alert.severity] || severityStyles.low

            return (
              <div
                key={alert.id}
                className="px-4 py-3 hover:bg-[var(--surface-alt)] transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div
                    className="p-2 rounded-lg mt-0.5"
                    style={{
                      backgroundColor: 'color-mix(in srgb, var(--warn) 10%, transparent)',
                      color: 'var(--warn)',
                    }}
                  >
                    <TypeIcon className="h-4 w-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-[var(--fg)]">
                        {typeInfo.label}
                      </span>
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border"
                        style={{
                          backgroundColor: `color-mix(in srgb, ${severity.bg} 20%, transparent)`,
                          color: severity.text,
                          borderColor: `color-mix(in srgb, ${severity.border} 30%, transparent)`,
                        }}
                      >
                        {safeCapitalize(alert.severity)}
                      </span>
                    </div>
                    <p className="text-sm font-mono mt-1" style={{ color: 'var(--sol-cyan)' }}>{alert.domain}</p>
                    <p className="text-xs text-[var(--muted)] mt-0.5">{alert.description}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-[var(--muted)]">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatDate(alert.timestamp)}
                      </span>
                      <span>{alert.agentHostname}</span>
                    </div>
                  </div>
                  <div>
                    {alert.alertId && (
                      <button
                        onClick={() => router.visit(`/app/alerts/${alert.alertId}`)}
                        className="flex items-center gap-1 px-2 py-1 rounded-lg bg-[var(--surface-alt)] hover:bg-[var(--border)] text-[var(--muted)] text-xs transition-colors"
                      >
                        <Eye className="h-3 w-3" />
                        Details
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Helpers
// ============================================================================

function inferQueryStatus(
  event: { severity: string; payload: Record<string, unknown> },
  transport?: 'query' | 'transport' | 'dot' | 'doh' | null,
): 'allowed' | 'blocked' | 'suspicious' {
  if (event.payload?.blocked) return 'blocked'
  if (transport === 'doh' || transport === 'dot') return 'suspicious'
  const severity = normalizeDnsSeverity(event.severity, event.payload?.severity, event.payload?.risk, event.payload?.score)
  if (severity === 'critical' || severity === 'high') return 'suspicious'
  if (event.payload?.suspicious) return 'suspicious'
  return 'allowed'
}
