import { Shield, Network, File, Terminal, Database, Copy, Check, AlertTriangle, Fingerprint, GitBranch, Info, ClipboardList } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';
import type { Evidence, AlertEvidenceQuality, AlertIOC } from '@/types';
import AIEvidenceSummary from '@/components/AIEvidenceSummary';
import { hasAIEvidence, summarizeAIEvidence } from '@/lib/aiEvidence';

interface EvidencePanelProps {
  evidence?: Evidence | null;
  quality?: AlertEvidenceQuality | null;
  contexts?: unknown[];
}

export default function EvidencePanel({ evidence, quality, contexts = [] }: EvidencePanelProps) {
  const aiEvidencePresent = hasAIEvidence(summarizeAIEvidence(evidence, ...contexts));
  if ((!evidence || Object.keys(evidence).length === 0) && !aiEvidencePresent) {
    return (
      <div className="space-y-4">
        {quality && <EvidenceQualityBanner quality={quality} />}
        <div className="text-center py-8 text-slate-500">
          <Shield className="h-10 w-10 mx-auto mb-2 opacity-50" />
          <p>No evidence captured for this alert</p>
        </div>
      </div>
    );
  }

  const normalizedEvidence = evidence || {};
  const detection = (normalizedEvidence.detection || {}) as NonNullable<Evidence['detection']>;
  const process = normalizeProcessEvidence(normalizedEvidence);
  const processTree = normalizeProcessTree(normalizedEvidence);
  const fileHashes = normalizeFileEvidence(normalizedEvidence);
  const network = normalizeNetworkEvidence(normalizedEvidence.network);
  const iocs = normalizeIocs(normalizedEvidence);
  const provenance = normalizeEvidenceProvenance(normalizedEvidence);
  const registry = Array.isArray(normalizedEvidence.registry) ? normalizedEvidence.registry : [];
  const processCommandLine = process.cmdline || process.command_line || process.command;
  const processName = normalizeProcessName(process, processCommandLine);
  const hasProcessEvidence = process.pid !== undefined || processName || process.path || processCommandLine || process.user || process.sha256;
  const mobileContext = normalizeMobileContext(normalizedEvidence);
  const browserContext = normalizeBrowserGuardContext(normalizedEvidence);
  const investigationGuidance = normalizeInvestigationGuidance(normalizedEvidence, {
    mobileContext,
    browserContext,
    hasProcessEvidence: Boolean(hasProcessEvidence),
    hasNetworkEvidence: network.length > 0,
    hasIocs: iocs.length > 0,
    hasFileHashes: fileHashes.some(hash => hash.sha256 || hash.sha1 || hash.md5),
  });
  const detectionType = displayDetectionType(detection.rule_type || detection.detection_type);
  const detectionConfidence = normalizeConfidence(detection.confidence);
  const renderedSections = [
    Boolean(detection.rule_name),
    Boolean(mobileContext),
    Boolean(browserContext),
    Boolean(investigationGuidance),
    Boolean(hasProcessEvidence),
    processTree.length > 0,
    fileHashes.length > 0,
    network.length > 0,
    iocs.length > 0,
    registry.length > 0,
    provenance.fields.length > 0,
    aiEvidencePresent,
  ].filter(Boolean).length;
  const missingContext = normalizeMissingEvidenceContext(normalizedEvidence, {
    hasProcessEvidence: Boolean(hasProcessEvidence),
    hasProcessTree: processTree.length > 0,
    hasFileHashes: fileHashes.some(hash => hash.sha256 || hash.sha1 || hash.md5),
    hasProvenance: provenance.fields.length > 0,
  });

  return (
    <div className="space-y-6">
      {quality && <EvidenceQualityBanner quality={quality} />}
      <AIEvidenceSummary sources={[normalizedEvidence, ...contexts]} />
      {renderedSections === 0 && (
        <DegradedEvidenceState
          title="Evidence bundle has no renderable context"
          details={missingContext.length > 0 ? missingContext : ['No process, binary hash, network, IOC, registry, or provenance fields were linked.']}
        />
      )}
      {renderedSections > 0 && missingContext.length > 0 && (
        <DegradedEvidenceState title="Evidence context incomplete" details={missingContext} compact />
      )}

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
          {detectionConfidence !== null && (
            <Field
              label="Confidence"
              value={`${detectionConfidence.toFixed(0)}%`}
              color={detectionConfidence > 80 ? 'text-red-400' : 'text-yellow-400'}
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

      {mobileContext && (
        <Section title="Mobile / App Guard" icon={Shield}>
          {mobileContext.app && <Field label="Protected App" value={mobileContext.app} />}
          {mobileContext.device && <Field label="Device" value={mobileContext.device} />}
          {mobileContext.eventType && <Field label="Event Type" value={formatDetectionType(mobileContext.eventType)} />}
          {mobileContext.tamper && <Field label="Tamper Signal" value={mobileContext.tamper} />}
          {mobileContext.policy && <Field label="Policy" value={mobileContext.policy} />}
          {mobileContext.decision && <Field label="Decision" value={formatDetectionType(mobileContext.decision)} />}
          {mobileContext.reasons.length > 0 && <Field label="Reasons" value={mobileContext.reasons.map(formatDetectionType).join(', ')} wrap />}
        </Section>
      )}

      {browserContext && (
        <Section title="Browser Guard" icon={Shield}>
          {browserContext.browser && <Field label="Browser" value={browserContext.browser} />}
          {browserContext.extension && <Field label="Extension" value={browserContext.extension} />}
          {browserContext.profile && <Field label="Profile" value={browserContext.profile} />}
          {browserContext.eventType && <Field label="Event Type" value={formatDetectionType(browserContext.eventType)} />}
          {browserContext.policy && <Field label="Policy" value={browserContext.policy} />}
          {browserContext.decision && <Field label="Decision" value={formatDetectionType(browserContext.decision)} />}
          {browserContext.nativeBridge && <Field label="Native Bridge" value={browserContext.nativeBridge} />}
          {browserContext.agentLink && <Field label="Agent Link" value={browserContext.agentLink} />}
          {browserContext.dnrRule && <Field label="DNR Rule" value={browserContext.dnrRule} mono />}
          {browserContext.target && <Field label="Target" value={browserContext.target} mono copyable />}
        </Section>
      )}

      {investigationGuidance && (
        <Section title="Investigation Guidance" icon={ClipboardList}>
          <Field label="Surface" value={investigationGuidance.surface} />
          <Field label="Confidence" value={investigationGuidance.confidenceBoundary} wrap />
          {investigationGuidance.linkStatus.length > 0 && (
            <Field label="Links" value={investigationGuidance.linkStatus.join(', ')} wrap />
          )}
          {investigationGuidance.commandCapabilities.length > 0 && (
            <Field label="Commands" value={investigationGuidance.commandCapabilities.join(', ')} wrap />
          )}
          {investigationGuidance.missing.length > 0 && (
            <Field label="Missing" value={investigationGuidance.missing.join('; ')} wrap />
          )}
          {investigationGuidance.nextPivots.length > 0 && (
            <Field label="Next Pivots" value={investigationGuidance.nextPivots.join('; ')} wrap />
          )}
        </Section>
      )}

      {/* Process Info */}
      {hasProcessEvidence && (
        <Section title="Process" icon={Terminal}>
          {process.pid !== undefined && process.pid !== null && <Field label="PID" value={process.pid} />}
          {process.ppid !== undefined && process.ppid !== null && <Field label="Parent PID" value={process.ppid} />}
          <Field label="Name" value={processName || 'not captured'} />
          {process.path && <Field label="Path" value={process.path} mono />}
          {process.sha256 && <Field label="Binary SHA256" value={process.sha256} mono copyable />}
          {processCommandLine && (
            <Field label="Command Line" value={processCommandLine} mono wrap copyable />
          )}
          {process.user && <Field label="User" value={process.user} />}
          {process.source && <Field label="Source" value={process.source} />}
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

      {/* Process Tree */}
      {processTree.length > 0 && (
        <Section title="Process Tree" icon={GitBranch}>
          {processTree.slice(0, 6).map((node, i) => (
            <div key={`${node.pid || node.name || 'process'}-${i}`} className="space-y-1">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-slate-500">{node.role || (i === 0 ? 'Observed' : 'Related')}:</span>
                <span className="font-medium text-slate-200">{node.name || 'unknown process'}</span>
                {node.pid && <span className="font-mono text-xs text-slate-500">pid {node.pid}</span>}
                {node.ppid && <span className="font-mono text-xs text-slate-500">ppid {node.ppid}</span>}
              </div>
              {node.path && <Field label="Path" value={node.path} mono />}
              {node.sha256 && <Field label="SHA256" value={node.sha256} mono copyable />}
              {node.source && <Field label="Source" value={node.source} />}
            </div>
          ))}
          {processTree.length > 6 && (
            <p className="text-xs text-slate-500">+{processTree.length - 6} more process tree nodes</p>
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
              {hash.source && <Field label="Source" value={hash.source} />}
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

      {/* Indicators of Compromise */}
      {iocs.length > 0 && (
        <Section title="IOCs" icon={Fingerprint}>
          {iocs.map((ioc, i) => (
            <div key={`${ioc.type || 'indicator'}-${ioc.value}-${i}`} className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs px-1.5 py-0.5 bg-slate-700 rounded">{formatDetectionType(ioc.type || 'indicator')}</span>
                <span className="font-mono text-sm text-white break-all">{ioc.value}</span>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                {ioc.source && <span>Source: {ioc.source}</span>}
                {ioc.confidence !== undefined && <span>Confidence: {formatIocConfidence(ioc.confidence)}</span>}
                {ioc.tlp && <span>TLP: {ioc.tlp}</span>}
                {ioc.blockable !== undefined && <span>Blockable: {ioc.blockable ? 'yes' : 'no'}</span>}
                {ioc.redacted !== undefined && <span>Redacted: {ioc.redacted ? 'yes' : 'no'}</span>}
              </div>
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

      {provenance.fields.length > 0 && (
        <Section title="Provenance" icon={Info}>
          {provenance.fields.map(field => (
            <Field key={field.label} label={field.label} value={field.value} mono={field.mono} />
          ))}
        </Section>
      )}
    </div>
  );
}

function EvidenceQualityBanner({ quality }: { quality: AlertEvidenceQuality }) {
  const tone =
    quality.quality === 'direct' || quality.quality === 'correlated'
      ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30'
      : quality.quality === 'derived'
        ? 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30'
        : 'text-red-300 bg-red-500/10 border-red-500/30';

  return (
    <div className={cn('rounded-lg border p-3', tone)}>
      <div className="flex items-center gap-2">
        {quality.claimable ? <Shield className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
        <span className="text-sm font-semibold">{quality.label}</span>
      </div>
      <p className="mt-1 text-xs text-slate-300">{quality.summary}</p>
      {quality.missing && quality.missing.length > 0 && (
        <p className="mt-2 text-xs text-slate-400">
          Missing: {quality.missing.join(', ')}
        </p>
      )}
    </div>
  );
}

function DegradedEvidenceState({ title, details, compact }: { title: string; details: string[]; compact?: boolean }) {
  return (
    <div className={cn('rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-100', compact ? 'p-3' : 'p-4')}>
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-yellow-300" />
        <span className="text-sm font-semibold">{title}</span>
      </div>
      <ul className="mt-2 space-y-1 text-xs text-slate-300">
        {details.map((detail, i) => (
          <li key={`${detail}-${i}`}>{detail}</li>
        ))}
      </ul>
    </div>
  );
}

function normalizeNetworkEvidence(network: unknown): Array<{ type?: string; value?: string; port?: string | number; direction?: string }> {
  if (Array.isArray(network)) {
    return network.map(normalizeNetworkItem).filter(ind => ind.value);
  }
  if (!network || typeof network !== 'object') return [];

  return [normalizeNetworkItem(network)].filter(ind => ind.value);
}

function normalizeNetworkItem(network: unknown): { type?: string; value?: string; port?: string | number; direction?: string } {
  const item = asRecord(network);
  const destination = asRecord(item.destination);
  const dest = asRecord(item.dest);
  const source = asRecord(item.source);
  const src = asRecord(item.src);
  const dns = asRecord(item.dns);
  const tls = asRecord(item.tls);
  const value =
    item.value ||
    item.indicator ||
    item.remote_ip ||
    item.remoteIp ||
    item.dst_ip ||
    item.dstIp ||
    item.destination_ip ||
    item.destinationIp ||
    item.dest_ip ||
    item.destIp ||
    destination.ip ||
    destination.address ||
    dest.ip ||
    dest.address ||
    item.domain ||
    item.host ||
    item.hostname ||
    item.url ||
    item.query ||
    item.dns_question_name ||
    item.dnsQuestionName ||
    dns.question_name ||
    dns.query ||
    item.tls_sni ||
    item.tlsSni ||
    tls.sni ||
    tls.server_name ||
    source.ip ||
    src.ip;

  return {
    type: text(item.type || item.protocol || item.event_type || dns.type || tls.type || 'network'),
    value: value ? String(value) : undefined,
    port: (item.port || item.remote_port || item.remotePort || item.destination_port || item.destinationPort || item.dest_port || item.destPort || destination.port || dest.port) as string | number | undefined,
    direction: text(item.direction || item.flow_direction || item.flowDirection) || undefined,
  };
}

function normalizeProcessEvidence(evidence: Evidence): Partial<NonNullable<Evidence['process']>> {
  const root = asRecord(evidence);
  const process = asRecord(root.process);
  const payload = asRecord(root.payload);
  const metadata = asRecord(root.metadata);
  const snapshot = asRecord(root.evidence_snapshot || root.evidenceSnapshot);
  const snapshotProcess = asRecord(snapshot.process);
  const parent = asRecord(process.parent || root.parent_process || root.parentProcess || payload.parent_process || payload.parentProcess);
  const parentProcess = asRecord(asRecord(root.parent || payload.parent).process);
  const contexts = [process, root, payload, metadata, snapshotProcess];

  return {
    ...process,
    pid: pickValue(contexts, ['pid', 'process_pid', 'processPid', 'process_id', 'processId', 'entity_id', 'entityId', 'process.pid']) as string | number | undefined,
    ppid: firstValue([
      pickValue([process, root, payload, metadata], ['ppid', 'parent_pid', 'parentPid', 'parent.process.pid']),
      pickValue([parent, parentProcess], ['pid', 'process_id', 'processId']),
    ]) as string | number | undefined,
    name: text(pickValue(contexts, ['name', 'process_name', 'processName', 'image', 'image_name', 'imageName', 'exe_name', 'executable', 'process.name'])),
    path: text(pickValue(contexts, ['path', 'process_path', 'processPath', 'image_path', 'imagePath', 'executable_path', 'executablePath', 'process.executable'])),
    cmdline: text(pickValue(contexts, ['cmdline', 'command_line', 'commandLine', 'command', 'process_command_line', 'processCommandLine', 'process.command_line'])),
    user: text(pickValue(contexts, ['user', 'username', 'user_name', 'userName', 'user.name'])),
    sha256: text(pickValue(contexts, ['sha256', 'hash_sha256', 'hashSha256'])),
    is_elevated: parseEvidenceBoolean(pickValue([process, root, payload], ['is_elevated', 'isElevated'])),
    is_signed: parseEvidenceBoolean(pickValue([process, root, payload], ['is_signed', 'isSigned'])),
    signer: text(pickValue([process, root, payload, metadata], ['signer', 'signature_subject'])),
    source: text(pickValue([process, root, payload, metadata], ['source', 'provenance', 'collector', 'data_source', 'dataSource'])),
  };
}

function normalizeProcessTree(evidence: Evidence): Array<{ role?: string; pid?: string | number; ppid?: string | number; name?: string; path?: string; sha256?: string; source?: string }> {
  const root = asRecord(evidence);
  const payload = asRecord(root.payload);
  const snapshot = asRecord(root.evidence_snapshot || root.evidenceSnapshot);
  const candidates = [
    ...arrayItems(root.process_tree || root.processTree),
    ...arrayItems(payload.process_tree || payload.processTree),
    ...arrayItems(snapshot.process_tree || snapshot.processTree),
  ];
  const seen = new Set<string>();

  return candidates
    .map((candidate, index) => normalizeProcessTreeNode(candidate, index))
    .filter(node => node.pid !== undefined || node.name || node.path || node.sha256)
    .filter((node) => {
      const key = `${node.pid || ''}:${node.name || ''}:${node.path || ''}:${node.sha256 || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function normalizeProcessTreeNode(value: unknown, index: number): { role?: string; pid?: string | number; ppid?: string | number; name?: string; path?: string; sha256?: string; source?: string } {
  const node = asRecord(value);
  const process = asRecord(node.process);
  const contexts = [node, process];
  const path = text(pickValue(contexts, ['path', 'process_path', 'processPath', 'image_path', 'imagePath', 'executable_path', 'executablePath', 'executable']));
  const commandLine = text(pickValue(contexts, ['cmdline', 'command_line', 'commandLine', 'command']));
  const name = text(pickValue(contexts, ['name', 'process_name', 'processName', 'image', 'image_name', 'imageName', 'exe_name'])) || basenameFromPath(path) || basenameFromPath(firstCommandToken(commandLine));

  return {
    role: text(pickValue(contexts, ['role', 'relationship', 'edge', 'kind'])) || (index === 0 ? 'Observed' : undefined),
    pid: pickValue(contexts, ['pid', 'process_pid', 'processPid', 'process_id', 'processId']) as string | number | undefined,
    ppid: pickValue(contexts, ['ppid', 'parent_pid', 'parentPid']) as string | number | undefined,
    name: name || undefined,
    path: path || undefined,
    sha256: text(pickValue(contexts, ['sha256', 'hash_sha256', 'hashSha256'])) || undefined,
    source: text(pickValue(contexts, ['source', 'provenance', 'collector', 'data_source', 'dataSource'])) || undefined,
  };
}

function normalizeProcessName(process: Partial<NonNullable<Evidence['process']>>, commandLine: unknown): string {
  const processRecord = asRecord(process);
  const explicit = text(
    process.name ||
    processRecord.process_name ||
    processRecord.processName ||
    processRecord.executable ||
    processRecord.image ||
    processRecord.image_name ||
    processRecord.imageName
  );
  if (explicit && explicit.toLowerCase() !== 'unknown') return explicit;

  const path = text(process.path || processRecord.image_path || processRecord.imagePath || processRecord.executable_path || processRecord.executablePath);
  const basename = basenameFromPath(path);
  if (basename) return basename;

  const commandName = basenameFromPath(firstCommandToken(text(commandLine)));
  return commandName || '';
}

function firstCommandToken(commandLine: string): string {
  if (!commandLine) return '';
  const trimmed = commandLine.trim();
  if (trimmed.startsWith('"')) {
    const endQuote = trimmed.indexOf('"', 1);
    return endQuote > 1 ? trimmed.slice(1, endQuote) : trimmed.slice(1);
  }
  return trimmed.split(/\s+/)[0] || '';
}

function basenameFromPath(path: string): string {
  if (!path) return '';
  return path.split(/[\\/]/).filter(Boolean).pop() || '';
}

function normalizeMobileContext(evidence: Evidence): {
  app?: string;
  device?: string;
  eventType?: string;
  tamper?: string;
  policy?: string;
  decision?: string;
  reasons: string[];
} | null {
  const root = asRecord(evidence);
  const appGuard = asRecord(root.app_guard || root.appGuard);
  const protectedApp = asRecord(appGuard.protected_app || appGuard.protectedApp);
  const app = { ...asRecord(root.app), ...asRecord(appGuard.app), ...protectedApp };
  const device = { ...asRecord(root.device), ...asRecord(appGuard.device) };
  const risk = { ...asRecord(root.risk), ...asRecord(appGuard.risk) };
  const appGuardRuntime = asRecord(appGuard.runtime);
  const decisionTrace = asRecord(root.decision_trace || root.decisionTrace || appGuard.decision);
  const tamper = {
    ...asRecord(root.tamper),
    ...asRecord(asRecord(appGuard.evidence).tamper),
    ...appGuardRuntime,
  };
  const policy = asRecord(
    root.policy_decision ||
    root.policyDecision ||
    root.policy ||
    appGuard.policy_decision ||
    appGuard.policyDecision ||
    appGuard.policy ||
    decisionTrace
  );
  const eventType = text(root.event_type || appGuard.event_type || evidence.detection?.rule_name);
  const normalizedEventType = eventType.toLowerCase();
  const sourceText = JSON.stringify({ root, appGuard }).toLowerCase();

  if (
    !sourceText.includes('app_guard') &&
    !sourceText.includes('appguard') &&
    !sourceText.includes('package_or_bundle_id') &&
    !sourceText.includes('protected-webview') &&
    !sourceText.includes('embedded_webview') &&
    !normalizedEventType.includes('tamper') &&
    !normalizedEventType.includes('policy_decision')
  ) {
    return null;
  }

  const appName = text(app.display_name || app.app_name || app.name || app.package_or_bundle_id || app.bundle_id || app.app_bundle_id);
  const deviceName = [
    text(device.device_id || device.name),
    text(device.manufacturer),
    text(device.model),
    text(device.os_version),
  ].filter(Boolean).join(' ');
  const tamperSignal = [
    text(tamper.surface),
    text(tamper.indicator),
    text(tamper.hooked_api),
    text(tamper.tamper_class),
    text(tamper.integrity_state),
    text(tamper.collector),
    text(tamper.type),
  ].filter(Boolean).join(' / ');
  const reasons = uniqueStrings([
    ...textArray(risk.reasons),
    ...textArray(policy.reasons),
    ...textArray(decisionTrace.reasons),
    ...textArray(appGuard.reasons),
    ...gapReasons(root.evidence_gaps),
    ...textArray(root.missing_reasons),
    ...textArray(root.missingEvidenceReasons),
    ...textArray(root.missing_evidence_reasons),
  ]);

  return {
    app: appName || undefined,
    device: deviceName || undefined,
    eventType: eventType || undefined,
    tamper: tamperSignal || undefined,
    policy: text(policy.policy_name || policy.policyName || policy.name || policy.policy_id || policy.policyId || policy.id) || undefined,
    decision: text(risk.decision || policy.decision || policy.action || decisionTrace.decision || root.decision) || undefined,
    reasons,
  };
}

function normalizeBrowserGuardContext(evidence: Evidence): {
  browser?: string;
  extension?: string;
  profile?: string;
  eventType?: string;
  policy?: string;
  decision?: string;
  nativeBridge?: string;
  agentLink?: string;
  dnrRule?: string;
  target?: string;
} | null {
  const root = asRecord(evidence);
  const browserGuard = asRecord(root.browser_guard || root.browserGuard);
  const extension = asRecord(browserGuard.extension || root.extension);
  const browser = asRecord(browserGuard.browser || root.browser);
  const nativeBridge = asRecord(browserGuard.native_bridge || browserGuard.nativeBridge || root.native_bridge || root.nativeBridge);
  const agentLink = asRecord(browserGuard.agent_link || browserGuard.agentLink || root.agent_link || root.agentLink);
  const policy = asRecord(browserGuard.policy || root.policy || root.policy_decision || root.policyDecision);
  const dnr = asRecord(browserGuard.dnr || browserGuard.dnr_rule || browserGuard.dnrRule || root.dnr || root.dnr_rule || root.dnrRule);
  const eventType = text(root.event_type || browserGuard.event_type || evidence.detection?.rule_name);
  const sourceText = JSON.stringify({ root, browserGuard }).toLowerCase();

  if (
    !sourceText.includes('browser_guard') &&
    !sourceText.includes('browser guard') &&
    !sourceText.includes('browser_tamper') &&
    !sourceText.includes('native_bridge') &&
    !sourceText.includes('dnr') &&
    !sourceText.includes('extension_id') &&
    !sourceText.includes('webextension') &&
    !eventType.toLowerCase().includes('browser')
  ) {
    return null;
  }

  const target = text(
    browserGuard.url ||
    browserGuard.domain ||
    browserGuard.host ||
    root.url ||
    root.domain ||
    root.host ||
    root.tls_sni ||
    root.tlsSni
  );

  return {
    browser: text(browser.name || browser.browser || browser.type || browser.family || browser.version) || undefined,
    extension: text(extension.name || extension.extension_id || extension.extensionId || extension.id || browserGuard.extension_id || browserGuard.extensionId) || undefined,
    profile: text(browser.profile || browser.profile_id || browser.profileId || browserGuard.profile || browserGuard.profile_id || browserGuard.profileId) || undefined,
    eventType: eventType || undefined,
    policy: text(policy.policy_name || policy.policyName || policy.name || policy.policy_id || policy.policyId || policy.id) || undefined,
    decision: text(policy.decision || policy.action || browserGuard.decision || root.decision) || undefined,
    nativeBridge: summarizeStatus(nativeBridge.status || nativeBridge.state || nativeBridge.health || nativeBridge.connected || nativeBridge.available),
    agentLink: summarizeStatus(agentLink.status || agentLink.state || agentLink.linked || root.agent_link_status || root.agentLinkStatus),
    dnrRule: text(dnr.rule_id || dnr.ruleId || dnr.id || dnr.name || dnr.action) || undefined,
    target: target || undefined,
  };
}

function normalizeInvestigationGuidance(evidence: Evidence, state: {
  mobileContext: ReturnType<typeof normalizeMobileContext>;
  browserContext: ReturnType<typeof normalizeBrowserGuardContext>;
  hasProcessEvidence: boolean;
  hasNetworkEvidence: boolean;
  hasIocs: boolean;
  hasFileHashes: boolean;
}): {
  surface: string;
  confidenceBoundary: string;
  missing: string[];
  linkStatus: string[];
  commandCapabilities: string[];
  nextPivots: string[];
} | null {
  if (!state.mobileContext && !state.browserContext) return null;

  const root = asRecord(evidence);
  const appGuard = asRecord(root.app_guard || root.appGuard);
  const browserGuard = asRecord(root.browser_guard || root.browserGuard);
  const capabilitySources = [
    root.command_capabilities,
    root.commandCapabilities,
    root.response_capabilities,
    root.responseCapabilities,
    appGuard.command_capabilities,
    appGuard.commandCapabilities,
    browserGuard.command_capabilities,
    browserGuard.commandCapabilities,
    asRecord(browserGuard.native_bridge || browserGuard.nativeBridge).capabilities,
  ];
  const commandCapabilities = uniqueStrings(capabilitySources.flatMap(capabilityList));
  const explicitMissing = uniqueStrings([
    ...gapReasons(root.evidence_gaps),
    ...textArray(root.missing_reasons),
    ...textArray(root.missingEvidenceReasons),
    ...textArray(root.missing_evidence_reasons),
    ...gapReasons(appGuard.evidence_gaps),
    ...gapReasons(browserGuard.evidence_gaps),
  ]);

  const missing = state.mobileContext
    ? mobileInvestigationMissing(state, explicitMissing)
    : browserInvestigationMissing(state, explicitMissing);

  const linkStatus = state.mobileContext
    ? mobileLinkStatus(root, appGuard)
    : browserLinkStatus(root, browserGuard);

  return {
    surface: state.mobileContext ? 'Mobile App Guard alert' : 'Browser Guard alert',
    confidenceBoundary: state.mobileContext
      ? 'Use protected-app telemetry, runtime signals, policy decision, and linked mobile command state before closing FP or confirmed.'
      : 'Use extension telemetry, DNR/native-bridge state, browser profile, and linked agent command state before closing FP or confirmed.',
    missing,
    linkStatus,
    commandCapabilities,
    nextPivots: state.mobileContext ? mobileNextPivots(evidence) : browserNextPivots(evidence),
  };
}

function mobileInvestigationMissing(state: {
  mobileContext: ReturnType<typeof normalizeMobileContext>;
  hasNetworkEvidence: boolean;
  hasIocs: boolean;
  hasFileHashes: boolean;
}, explicitMissing: string[]): string[] {
  const context = state.mobileContext;
  return uniqueStrings([
    ...explicitMissing,
    !context?.app ? 'Protected app identity was not captured.' : '',
    !context?.device ? 'Mobile device identity was not captured.' : '',
    !context?.eventType ? 'Mobile security event type was not captured.' : '',
    !context?.decision ? 'App Guard policy decision was not captured.' : '',
    !context?.tamper ? 'Runtime/tamper signal details were not captured.' : '',
    !state.hasNetworkEvidence ? 'Mobile network/DNS context was not linked.' : '',
    !state.hasIocs ? 'Public-safe mobile IOCs were not extracted.' : '',
    !state.hasFileHashes ? 'App/binary hash evidence was not captured.' : '',
  ]).slice(0, 10);
}

function browserInvestigationMissing(state: {
  browserContext: ReturnType<typeof normalizeBrowserGuardContext>;
  hasProcessEvidence: boolean;
  hasNetworkEvidence: boolean;
  hasIocs: boolean;
}, explicitMissing: string[]): string[] {
  const context = state.browserContext;
  return uniqueStrings([
    ...explicitMissing,
    !context?.browser ? 'Browser identity/profile was not captured.' : '',
    !context?.extension ? 'Extension identity/inventory was not captured.' : '',
    !context?.eventType ? 'Browser Guard event type was not captured.' : '',
    !context?.policy && !context?.dnrRule ? 'Policy or DNR rule decision was not captured.' : '',
    !context?.nativeBridge ? 'Native bridge health was not reported.' : '',
    !context?.agentLink ? 'Linked endpoint agent status was not reported.' : '',
    !context?.target && !state.hasNetworkEvidence ? 'URL/domain/network target was not captured.' : '',
    !state.hasProcessEvidence ? 'Owning browser process was not linked.' : '',
    !state.hasIocs ? 'Browser/domain IOCs were not extracted.' : '',
  ]).slice(0, 10);
}

function mobileLinkStatus(root: Record<string, unknown>, appGuard: Record<string, unknown>): string[] {
  const device = asRecord(root.device || appGuard.device);
  const command = asRecord(root.command || appGuard.command || appGuard.command_device || appGuard.commandDevice);
  return uniqueStrings([
    statusLine('device', device.status || device.state || device.managed),
    statusLine('command device', command.status || command.state || command.linked || command.device_id || command.deviceId),
    statusLine('agent', root.agent_link_status || root.agentLinkStatus || root.agent_status || root.agentStatus),
  ]);
}

function browserLinkStatus(root: Record<string, unknown>, browserGuard: Record<string, unknown>): string[] {
  const nativeBridge = asRecord(browserGuard.native_bridge || browserGuard.nativeBridge || root.native_bridge || root.nativeBridge);
  const agentLink = asRecord(browserGuard.agent_link || browserGuard.agentLink || root.agent_link || root.agentLink);
  return uniqueStrings([
    statusLine('native bridge', nativeBridge.status || nativeBridge.state || nativeBridge.health || nativeBridge.connected || nativeBridge.available),
    statusLine('agent link', agentLink.status || agentLink.state || agentLink.linked || root.agent_link_status || root.agentLinkStatus),
    statusLine('extension', browserGuard.extension_status || browserGuard.extensionStatus),
  ]);
}

function mobileNextPivots(evidence: Evidence): string[] {
  const root = asRecord(evidence);
  const appGuard = asRecord(root.app_guard || root.appGuard);
  const protectedApp = asRecord(appGuard.protected_app || appGuard.protectedApp || appGuard.app || root.app);
  const device = asRecord(appGuard.device || root.device);

  return uniqueStrings([
    pivotLine('package', protectedApp.package_or_bundle_id || protectedApp.packageName || protectedApp.bundle_id || protectedApp.bundleId),
    pivotLine('app', protectedApp.display_name || protectedApp.name),
    pivotLine('device', device.device_id || device.deviceId || device.serial_number || device.serialNumber),
    pivotLine('policy', asRecord(root.policy || appGuard.policy).policy_id || asRecord(root.policy || appGuard.policy).policyId),
    ...normalizeNetworkEvidence(root.network).map(item => pivotLine(item.type || 'network', item.value)).filter(Boolean),
  ]);
}

function browserNextPivots(evidence: Evidence): string[] {
  const root = asRecord(evidence);
  const browserGuard = asRecord(root.browser_guard || root.browserGuard);
  const extension = asRecord(browserGuard.extension || root.extension);
  const dnr = asRecord(browserGuard.dnr || browserGuard.dnr_rule || browserGuard.dnrRule || root.dnr || root.dnr_rule || root.dnrRule);

  return uniqueStrings([
    pivotLine('extension', extension.extension_id || extension.extensionId || extension.id || browserGuard.extension_id || browserGuard.extensionId),
    pivotLine('browser profile', browserGuard.profile || browserGuard.profile_id || browserGuard.profileId),
    pivotLine('DNR rule', dnr.rule_id || dnr.ruleId || dnr.id || dnr.name),
    pivotLine('domain', browserGuard.domain || root.domain || root.host),
    pivotLine('url', browserGuard.url || root.url),
    pivotLine('agent', root.agent_id || root.agentId),
    ...normalizeNetworkEvidence(root.network).map(item => pivotLine(item.type || 'network', item.value)).filter(Boolean),
  ]);
}

function gapReasons(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((gap) => {
      const record = asRecord(gap);
      return text(record.message || record.code || gap);
    })
    .filter(Boolean);
}

function normalizeFileEvidence(evidence: Evidence): Array<{ path?: string; sha256?: string; sha1?: string; md5?: string; source?: string }> {
  const hashes = Array.isArray(evidence.file_hashes) ? evidence.file_hashes : [];
  const file = evidence.file || {};

  if (!file.path && !file.sha256 && !file.sha1 && !file.md5) return hashes;

  return [
    {
      path: file.path,
      sha256: file.sha256,
      sha1: file.sha1,
      md5: file.md5,
      source: file.source,
    },
    ...hashes,
  ];
}

function normalizeEvidenceProvenance(evidence: Evidence): { fields: Array<{ label: string; value: string; mono?: boolean }> } {
  const root = asRecord(evidence);
  const payload = asRecord(root.payload);
  const metadata = asRecord(root.metadata);
  const snapshot = asRecord(root.evidence_snapshot || root.evidenceSnapshot);
  const contexts = [root, payload, metadata, snapshot];
  const fields = [
    { label: 'Source', value: text(pickValue(contexts, ['source', 'data_source', 'dataSource', 'source_type', 'sourceType'])) },
    { label: 'Collector', value: text(pickValue(contexts, ['collector', 'collector_name', 'collectorName'])) },
    { label: 'Provenance', value: text(pickValue(contexts, ['provenance', 'evidence_provenance', 'evidenceProvenance'])) },
    { label: 'Source Event', value: text(pickValue(contexts, ['source_event_id', 'sourceEventId', 'event_id', 'eventId', 'raw_event_id', 'rawEventId'])), mono: true },
    { label: 'Agent', value: text(pickValue(contexts, ['agent_id', 'agentId', 'endpoint_id', 'endpointId'])), mono: true },
    { label: 'Host', value: text(pickValue(contexts, ['host', 'hostname', 'endpoint', 'device_name', 'deviceName'])) },
    { label: 'Captured At', value: text(pickValue(contexts, ['captured_at', 'capturedAt', 'timestamp', 'event_time', 'eventTime'])) },
  ].filter(field => field.value);

  return { fields };
}

function normalizeMissingEvidenceContext(evidence: Evidence, state: { hasProcessEvidence: boolean; hasProcessTree: boolean; hasFileHashes: boolean; hasProvenance: boolean }): string[] {
  const root = asRecord(evidence);
  const explicitMissing = uniqueStrings([
    ...gapReasons(root.evidence_gaps),
    ...textArray(root.missing_reasons),
    ...textArray(root.missingEvidenceReasons),
    ...textArray(root.missing_evidence_reasons),
  ]);
  const inferredMissing = [
    !state.hasProcessEvidence ? 'Process context was not captured.' : '',
    state.hasProcessEvidence && !state.hasProcessTree ? 'Process tree or parent lineage was not linked.' : '',
    !state.hasFileHashes ? 'Binary hash evidence was not captured.' : '',
    !state.hasProvenance ? 'Provenance/source fields were not captured.' : '',
  ];

  return uniqueStrings([...explicitMissing, ...inferredMissing]).slice(0, 6);
}

function normalizeIocs(evidence: Evidence): Array<AlertIOC & { confidence?: number }> {
  const root = asRecord(evidence);
  const snapshot = asRecord(root.evidence_snapshot || root.evidenceSnapshot);
  const appGuard = asRecord(root.app_guard || root.appGuard);
  const appGuardSnapshot = asRecord(appGuard.evidence_snapshot || appGuard.evidenceSnapshot);
  const candidates = [
    ...arrayItems(root.iocs),
    ...arrayItems(snapshot.iocs),
    ...arrayItems(snapshot.indicators),
    ...arrayItems(appGuard.iocs),
    ...arrayItems(appGuardSnapshot.iocs),
    ...arrayItems(appGuardSnapshot.indicators),
  ];
  const seen = new Set<string>();

  return candidates
    .map(normalizeIoc)
    .filter((ioc): ioc is AlertIOC & { confidence?: number } => Boolean(ioc?.value))
    .filter((ioc) => {
      const key = `${ioc.type || 'indicator'}:${ioc.value}:${ioc.source || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function normalizeIoc(value: unknown): (AlertIOC & { confidence?: number }) | null {
  const record = asRecord(value);
  const indicatorValue = text(record.value || record.indicator || record.ioc || record.hash || record.domain || record.ip || record.url || record.package || record.app);
  if (!indicatorValue) return null;

  return {
    type: normalizeIocType(text(record.type || record.kind || record.category)),
    value: indicatorValue,
    source: text(record.source || record.provenance || record.collector) || undefined,
    confidence: normalizeConfidence(record.confidence) ?? undefined,
    tlp: text(record.tlp) || undefined,
    blockable: hasOwn(record, 'blockable') ? parseOptionalEvidenceBoolean(record.blockable) : undefined,
    redacted: hasOwn(record, 'redacted') ? parseOptionalEvidenceBoolean(record.redacted) : undefined,
  };
}

function normalizeIocType(type: string): AlertIOC['type'] {
  const normalized = type.trim().toLowerCase();
  const allowed: AlertIOC['type'][] = ['ip', 'hash', 'domain', 'url', 'email', 'file_path', 'package', 'app', 'indicator'];
  return allowed.includes(normalized as AlertIOC['type']) ? normalized as AlertIOC['type'] : 'indicator';
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function arrayItems(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value == null ? '' : String(value).trim();
}

function parseEvidenceBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  if (typeof value !== 'string') return false;

  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes'].includes(normalized)) return true;
  if (['false', '0', 'no', ''].includes(normalized)) return false;
  return false;
}

function parseOptionalEvidenceBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  if (typeof value !== 'string') return undefined;

  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes'].includes(normalized)) return true;
  if (['false', '0', 'no'].includes(normalized)) return false;
  return undefined;
}

function textArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(text).filter(Boolean);
  const single = text(value);
  return single ? [single] : [];
}

function firstValue(values: unknown[]): unknown {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function pickValue(records: Record<string, unknown>[], keys: string[]): unknown {
  for (const record of records) {
    const value = firstValue(keys.map(key => record[key]));
    if (value !== undefined) return value;
  }
  return undefined;
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map(value => value.trim()).filter(Boolean)));
}

function capabilityList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(text).filter(Boolean);
  const record = asRecord(value);
  if (Object.keys(record).length > 0) {
    return Object.entries(record)
      .filter(([, capabilityValue]) => parseOptionalEvidenceBoolean(capabilityValue) !== false)
      .map(([key, capabilityValue]) => {
        const status = parseOptionalEvidenceBoolean(capabilityValue);
        return status === true ? key : `${key}: ${text(capabilityValue)}`;
      })
      .filter(Boolean);
  }
  return textArray(value);
}

function summarizeStatus(value: unknown): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'boolean') return value ? 'available' : 'unavailable';
  return text(value) || undefined;
}

function statusLine(label: string, value: unknown): string {
  const status = summarizeStatus(value);
  return status ? `${label}: ${status}` : '';
}

function pivotLine(label: string, value: unknown): string {
  const pivot = text(value);
  return pivot ? `${label}: ${pivot}` : '';
}

function normalizeConfidence(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  return score <= 1 ? score * 100 : score;
}

function displayDetectionType(ruleType?: string): string | null {
  const type = ruleType?.trim().toLowerCase();

  if (type && type !== 'unknown') {
    return type;
  }

  return type || null;
}

function formatDetectionType(type?: string | null): string {
  return String(type || 'unknown')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function formatIocConfidence(value: number): string {
  return `${value.toFixed(0)}%`;
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
