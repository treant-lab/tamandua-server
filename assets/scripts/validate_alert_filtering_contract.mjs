import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const alertsSource = fs.readFileSync(path.join(root, 'src/pages/Alerts.tsx'), 'utf8');

function requirePattern(name, pattern) {
  assert.match(alertsSource, pattern, `${name}: Alerts.tsx is missing ${pattern}`);
}

function asRecord(value) {
  return value && typeof value === 'object' ? value : {};
}

function asString(value, fallback = '') {
  return typeof value === 'string' ? value : fallback;
}

function safeStringArray(value) {
  return Array.isArray(value) ? value.map(item => String(item)).filter(Boolean) : [];
}

function sourceMatchesAny(source, aliases) {
  return aliases.some(alias => source.includes(alias));
}

function normalizeAlertSourceValue(value) {
  return String(value || '').trim().toLowerCase().replace(/-/g, '_');
}

function normalizeAlertSource(alert) {
  const detectionMetadata = asRecord(alert.detectionMetadata);
  const rawEvent = asRecord(alert.rawEvent ?? alert.raw_event);
  const payload = asRecord(rawEvent.payload);
  const evidence = asRecord(alert.evidence);

  const explicit = [
    alert.source,
    detectionMetadata.source,
    detectionMetadata.detection_source,
    rawEvent.source,
    rawEvent.alert_source,
    payload.detection_source,
    payload.source,
    asRecord(rawEvent.metadata).detection_source,
    asRecord(rawEvent.metadata).source,
    evidence.source,
    evidence.detection_source,
    evidence.alert_source,
  ].map(normalizeAlertSourceValue).find(Boolean) || '';

  const detectionType = normalizeAlertSourceValue(detectionMetadata.detection_type || payload.detection_type || evidence.detection_type);
  const ruleType = normalizeAlertSourceValue(detectionMetadata.rule_type || payload.rule_type || evidence.rule_type);
  const ruleName = normalizeAlertSourceValue(detectionMetadata.rule_name || payload.rule_name || evidence.rule_name);

  if (sourceMatchesAny(explicit, ['sigma'])) return 'sigma';
  if (sourceMatchesAny(explicit, ['yara'])) return 'yara';
  if (sourceMatchesAny(explicit, ['mobile', 'android', 'ios', 'app_guard', 'mdm', 'tamandua_mobile'])) return 'mobile';
  if (sourceMatchesAny(explicit, ['ndr', 'network', 'dns', 'flow', 'packet', 'zeek', 'suricata', 'firewall', 'doh'])) return 'ndr';
  if (sourceMatchesAny(explicit, ['ml', 'onnx', 'model'])) return 'ml';
  if (sourceMatchesAny(explicit, ['ai_security', 'ai_runtime', 'llm', 'prompt', 'rag'])) return 'ai_security';
  if (sourceMatchesAny(explicit, ['ioc', 'threat_intel', 'indicator'])) return 'ioc';
  if (sourceMatchesAny(explicit, ['behavior', 'baseline', 'anomaly', 'rule_match', 'detection_engine'])) return 'behavioral';
  if ([detectionType, ruleType].includes('ml') || ruleName.startsWith('ml_') || ruleName.startsWith('offline_ml')) return 'ml';

  return explicit || 'behavioral';
}

function alertCategory(alert) {
  const detectionMetadata = asRecord(alert.detectionMetadata);
  const rawEvent = asRecord(alert.rawEvent ?? alert.raw_event);
  const evidence = asRecord(alert.evidence);

  return asString(
    detectionMetadata.category ??
      detectionMetadata.threat_category ??
      rawEvent.category ??
      rawEvent.event_type ??
      evidence.category
  ).toLowerCase();
}

function alertHasEvidence(alert) {
  return Object.keys(asRecord(alert.evidence)).length > 0;
}

function isParityTestAlert(alert) {
  const metadata = asRecord(alert.detectionMetadata);
  const rawEvent = asRecord(alert.rawEvent || alert.raw_event);
  const payload = asRecord(rawEvent.payload);
  const device = asRecord(payload.device);
  const evidence = asRecord(payload.evidence);
  const eventIds = safeStringArray(alert.contributingEvents || alert.eventIds || alert.event_ids);

  const markers = [
    alert.sourceEventId,
    ...eventIds,
    rawEvent.mobile_event_id,
    rawEvent.event_id,
    rawEvent.event_type,
    payload.event_id,
    payload.parity_run_id,
    payload.validation_run_id,
    payload.device_id,
    device.device_id,
    device.serial_number,
    evidence.source,
    evidence.parity_run_id,
    evidence.validation_run_id,
    metadata.rule_id,
    metadata.device_id,
    metadata.mobile_device_id,
  ];

  return markers.some(value => {
    if (typeof value !== 'string') return false;
    const normalized = value.toLowerCase();
    return (
      normalized.startsWith('mobile-endpoint-parity-') ||
      normalized.startsWith('agent-mobile-endpoint-parity-') ||
      normalized.startsWith('parity-') ||
      normalized.includes('_parity_') ||
      normalized.includes('-parity-')
    );
  });
}

function alertValidationKind(alert) {
  const explicit = asString(asRecord(alert).validationKind ?? asRecord(alert).validation_kind);
  if (explicit) return explicit;
  return isParityTestAlert(alert) ? 'parity' : '';
}

function alertIsValidation(alert) {
  const explicit = asRecord(alert).validationAlert ?? asRecord(alert).validation_alert;
  if (typeof explicit === 'boolean') return explicit;
  return alertValidationKind(alert) !== '';
}

function filterAlerts(alerts, filters = {}) {
  return alerts.filter(alert => {
    if (filters.source && normalizeAlertSource(alert) !== normalizeAlertSourceValue(filters.source)) return false;
    if (filters.category && alertCategory(alert) !== filters.category.toLowerCase()) return false;
    if (filters.has_evidence === 'true' && !alertHasEvidence(alert)) return false;
    if (filters.has_evidence === 'false' && alertHasEvidence(alert)) return false;
    if ((filters.validation ?? 'exclude') === 'exclude' && alertIsValidation(alert)) return false;
    if (filters.validation === 'only' && !alertIsValidation(alert)) return false;
    return true;
  });
}

function buildAlertUrlState(filters) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries({
    source: filters.source || '',
    category: filters.category || '',
    has_evidence: filters.has_evidence || '',
    validation: filters.validation !== 'exclude' ? filters.validation || '' : '',
  })) {
    if (value && value !== 'all') params.set(key, value);
  }
  return params.toString();
}

function buildAlertSearchBody(filters) {
  const body = {};
  if (filters.source) body.source = filters.source;
  if (filters.category) body.category = filters.category;
  if (filters.has_evidence) body.has_evidence = filters.has_evidence;
  if (filters.validation) body.validation = filters.validation;
  return body;
}

const fixtures = [
  {
    id: 'prod-ml',
    source: 'offline-onnx-model',
    title: 'ML suspicious process',
    evidence: { process: 'rundll32.exe' },
    detectionMetadata: { category: 'process', rule_name: 'OFFLINE_ML_PROCESS' },
  },
  {
    id: 'prod-ndr',
    rawEvent: { metadata: { detection_source: 'Zeek DNS' }, event_type: 'dns' },
    evidence: {},
    detectionMetadata: {},
  },
  {
    id: 'validation-parity',
    rawEvent: {
      payload: {
        parity_run_id: 'mobile-endpoint-parity-2026-07-11',
        device: { device_id: 'android-test-1' },
      },
    },
    evidence: { category: 'mobile' },
    detectionMetadata: { source: 'tamandua_mobile' },
  },
  {
    id: 'explicit-validation',
    validation_alert: true,
    source: 'sigma',
    evidence: { matched: true },
    detectionMetadata: { category: 'file' },
  },
];

const staticChecks = [
  ['search body source filter', /if \(sourceFilter\) body\.source = sourceFilter/],
  ['search body category filter', /if \(categoryFilter\) body\.category = categoryFilter/],
  ['search body evidence filter', /if \(hasEvidenceFilter\) body\.has_evidence = hasEvidenceFilter/],
  ['search body validation filter', /if \(validationFilter\) body\.validation = validationFilter/],
  ['local source filtering', /normalizeAlertSource\(alert\) !== normalizeAlertSourceValue\(sourceFilter\)/],
  ['local category filtering', /alertCategory\(alert\) !== categoryFilter\.toLowerCase\(\)/],
  ['local evidence-present filtering', /hasEvidenceFilter === 'true' && !alertHasEvidence\(alert\)/],
  ['local evidence-absent filtering', /hasEvidenceFilter === 'false' && alertHasEvidence\(alert\)/],
  ['local validation exclude filtering', /validationFilter === 'exclude' && alertIsValidation\(alert\)/],
  ['local validation only filtering', /validationFilter === 'only' && !alertIsValidation\(alert\)/],
  ['URL source state', /source: sourceFilter/],
  ['URL category state', /category: categoryFilter/],
  ['URL evidence state', /has_evidence: hasEvidenceFilter/],
  ['URL validation default omission', /validation: validationFilter !== 'exclude' \? validationFilter : ''/],
];

for (const [name, pattern] of staticChecks) {
  requirePattern(name, pattern);
}

assert.deepEqual(
  filterAlerts(fixtures, { validation: 'exclude' }).map(alert => alert.id),
  ['prod-ml', 'prod-ndr'],
  'validation=exclude should hide explicit and parity validation alerts by default'
);

assert.deepEqual(
  filterAlerts(fixtures, { validation: 'only' }).map(alert => alert.id),
  ['validation-parity', 'explicit-validation'],
  'validation=only should return only explicit and parity validation alerts'
);

assert.deepEqual(
  filterAlerts(fixtures, { source: 'ml', category: 'process', has_evidence: 'true', validation: 'include' }).map(alert => alert.id),
  ['prod-ml'],
  'combined source/category/evidence filters should narrow to the matching ML alert'
);

assert.deepEqual(
  filterAlerts(fixtures, { source: 'ndr', category: 'dns', has_evidence: 'false', validation: 'include' }).map(alert => alert.id),
  ['prod-ndr'],
  'NDR aliases, raw event category, and missing evidence filter should compose'
);

assert.equal(
  buildAlertUrlState({ source: 'ml', category: 'process', has_evidence: 'true', validation: 'exclude' }),
  'source=ml&category=process&has_evidence=true',
  'default validation=exclude should be omitted from the URL'
);

assert.equal(
  buildAlertUrlState({ source: 'mobile', validation: 'only' }),
  'source=mobile&validation=only',
  'non-default validation filter should be preserved in the URL'
);

assert.deepEqual(
  buildAlertSearchBody({ source: 'ml', category: 'process', has_evidence: 'true', validation: 'exclude' }),
  { source: 'ml', category: 'process', has_evidence: 'true', validation: 'exclude' },
  'alert search body should include all advanced filter fields'
);

console.log('ok: alert filtering contract');
