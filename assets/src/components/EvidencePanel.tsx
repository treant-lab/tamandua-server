import { Shield, Network, File, Terminal, Database, Copy, Check } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';
import type { Evidence } from '@/types';

interface EvidencePanelProps {
  evidence?: Evidence | null;
}

export default function EvidencePanel({ evidence }: EvidencePanelProps) {
  if (!evidence || Object.keys(evidence).length === 0) {
    return (
      <div className="text-center py-8 text-slate-500">
        <Shield className="h-10 w-10 mx-auto mb-2 opacity-50" />
        <p>No evidence captured for this alert</p>
      </div>
    );
  }

  const detection = (evidence.detection || {}) as NonNullable<Evidence['detection']>;
  const process = (evidence.process || {}) as Partial<NonNullable<Evidence['process']>>;
  const fileHashes = Array.isArray(evidence.file_hashes) ? evidence.file_hashes : [];
  const network = normalizeNetworkEvidence(evidence.network);
  const registry = Array.isArray(evidence.registry) ? evidence.registry : [];
  const processCommandLine = process.cmdline || process.command_line || process.command;
  const detectionType = displayDetectionType(
    detection.rule_type || detection.detection_type,
    detection.rule_name
  );

  return (
    <div className="space-y-6">
      {/* Detection Info */}
      {detection.rule_name && (
        <Section title="Detection" icon={Shield}>
          <Field label="Rule" value={detection.rule_name} />
          {detectionType && (
            <Field label="Type" value={formatDetectionType(detectionType)} />
          )}
          {detection.detection_type && detection.detection_type !== detection.rule_type && (
            <Field label="Source" value={formatDetectionType(detection.detection_type)} />
          )}
          {detection.confidence !== undefined && (
            <Field
              label="Confidence"
              value={`${(Number(detection.confidence) * 100).toFixed(0)}%`}
              color={Number(detection.confidence) > 0.8 ? 'text-red-400' : 'text-yellow-400'}
            />
          )}
          {detection.severity !== undefined && (
            <Field label="Severity" value={String(detection.severity)} />
          )}
          {detection.mitre_attack_id && (
            <Field label="MITRE" value={detection.mitre_attack_id} />
          )}
          {Array.isArray(detection.mitre_techniques) && detection.mitre_techniques.length > 0 && (
            <Field label="Techniques" value={detection.mitre_techniques.join(', ')} />
          )}
          {Array.isArray(detection.mitre_tactics) && detection.mitre_tactics.length > 0 && (
            <Field label="Tactics" value={detection.mitre_tactics.join(', ')} />
          )}
          {detection.matched_pattern && (
            <Field label="Pattern" value={detection.matched_pattern} mono />
          )}
        </Section>
      )}

      {/* Process Info */}
      {process.pid !== undefined && process.pid !== null && (
        <Section title="Process" icon={Terminal}>
          <Field label="PID" value={process.pid} />
          {process.ppid !== undefined && process.ppid !== null && <Field label="Parent PID" value={process.ppid} />}
          <Field label="Name" value={process.name || 'unknown'} />
          {process.path && <Field label="Path" value={process.path} mono />}
          {processCommandLine && (
            <Field label="Command Line" value={processCommandLine} mono wrap copyable />
          )}
          {process.user && <Field label="User" value={process.user} />}
          <div className="flex items-center gap-2 mt-2">
            {process.is_elevated && (
              <span className="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded">Elevated</span>
            )}
            {process.is_signed && (
              <span className="text-xs px-2 py-0.5 bg-green-500/20 text-green-400 rounded">Signed</span>
            )}
          </div>
          {process.is_signed && process.signer && (
            <Field label="Signer" value={process.signer} />
          )}
        </Section>
      )}

      {/* File Hashes */}
      {fileHashes.length > 0 && (
        <Section title="File Hashes" icon={File}>
          {fileHashes.map((hash, i) => (
            <div key={i} className="space-y-1">
              {hash.path && <Field label="Path" value={hash.path} mono />}
              {hash.sha256 && <Field label="SHA256" value={hash.sha256} mono copyable />}
              {hash.sha1 && <Field label="SHA1" value={hash.sha1} mono copyable />}
              {hash.md5 && <Field label="MD5" value={hash.md5} mono copyable />}
            </div>
          ))}
        </Section>
      )}

      {/* Network Indicators */}
      {network.length > 0 && (
        <Section title="Network" icon={Network}>
          {network.map((ind, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="text-xs px-1.5 py-0.5 bg-slate-700 rounded">{ind.type}</span>
              <span className="font-mono text-sm text-white">{ind.value}</span>
              {ind.port && <span className="text-slate-500">:{ind.port}</span>}
              {ind.direction && <span className="text-xs text-slate-500">({ind.direction})</span>}
            </div>
          ))}
        </Section>
      )}

      {/* Registry */}
      {registry.length > 0 && (
        <Section title="Registry" icon={Database}>
          {registry.map((reg, i) => (
            <div key={i} className="space-y-1">
              <Field label="Key" value={reg.key} mono />
              {reg.value && <Field label="Value" value={reg.value} mono />}
              {reg.operation && <Field label="Operation" value={reg.operation} />}
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

function normalizeNetworkEvidence(network: unknown): Array<{ type?: string; value?: string; port?: string | number; direction?: string }> {
  if (Array.isArray(network)) return network;
  if (!network || typeof network !== 'object') return [];

  const item = network as Record<string, unknown>;
  const value =
    item.value ||
    item.remote_ip ||
    item.remoteIp ||
    item.destination_ip ||
    item.destinationIp ||
    item.domain ||
    item.host ||
    item.hostname;

  return [{
    type: String(item.type || item.protocol || 'network'),
    value: value ? String(value) : undefined,
    port: (item.port || item.remote_port || item.remotePort || item.destination_port || item.destinationPort) as string | number | undefined,
    direction: item.direction ? String(item.direction) : undefined,
  }].filter(ind => ind.value);
}

function displayDetectionType(ruleType?: string, ruleName?: string): string | null {
  const type = ruleType?.trim().toLowerCase();

  if (type && type !== 'unknown') {
    return type;
  }

  const normalizedRule = ruleName?.trim().toLowerCase() || '';

  if (
    normalizedRule.startsWith('kernel_syscall_') ||
    normalizedRule.includes('powershell') ||
    normalizedRule.includes('execution_policy') ||
    normalizedRule.includes('defense_evasion')
  ) {
    return 'defense_evasion';
  }

  if (normalizedRule.startsWith('registry_') || normalizedRule.includes('persistence')) {
    return 'persistence';
  }

  if (normalizedRule.includes('credential')) {
    return 'credential_theft';
  }

  if (normalizedRule.includes('ransomware')) {
    return 'ransomware';
  }

  return type || null;
}

function formatDetectionType(type?: string | null): string {
  return String(type || 'unknown')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function Section({ title, icon: Icon, children }: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-slate-800/50 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="h-4 w-4 text-blue-400" />
        <h4 className="text-sm font-medium text-white">{title}</h4>
      </div>
      <div className="space-y-2">
        {children}
      </div>
    </div>
  );
}

function Field({ label, value, mono, wrap, copyable, color }: {
  label: string;
  value: string | number;
  mono?: boolean;
  wrap?: boolean;
  copyable?: boolean;
  color?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const textValue = String(value);
  const isLongWrapped = Boolean(wrap && textValue.length > 260);

  const handleCopy = () => {
    navigator.clipboard.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={cn("flex gap-2 min-w-0", wrap ? "flex-col" : "items-start")}>
      <span className="text-xs text-slate-500 min-w-[80px]">{label}:</span>
      <span className={cn(
        "text-sm flex-1 min-w-0",
        mono ? "font-mono text-xs" : "",
        color || "text-slate-300",
        wrap ? "overflow-auto whitespace-pre-wrap" : "",
        wrap && !expanded ? "max-h-24" : "",
        wrap && expanded ? "max-h-80" : ""
      )}
        style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}
        title={textValue}
      >
        {value}
      </span>
      <div className="flex items-center gap-2 shrink-0">
      {isLongWrapped && (
        <button
          type="button"
          onClick={() => setExpanded(current => !current)}
          className="text-xs text-slate-500 hover:text-white"
        >
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
      {copyable && (
        <button
          onClick={handleCopy}
          className="text-xs text-slate-500 hover:text-white flex items-center gap-1 shrink-0"
        >
          {copied ? (
            <>
              <Check size={12} className="text-green-400" />
              <span className="text-green-400">Copied</span>
            </>
          ) : (
            <>
              <Copy size={12} />
              <span>Copy</span>
            </>
          )}
        </button>
      )}
      </div>
    </div>
  );
}
