import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  HelpCircle,
  Shield,
  ShieldAlert,
  ShieldX,
} from "lucide-react";
import { useId } from "react";

export type TrustPostureState =
  "verified" | "unverified" | "degraded" | "suspected_clone" | "revoked";

type TrustSourceName =
  "device_identity" | "runtime_integrity" | "app_guard" | "offline_checkpoint";

interface TrustSourceSummary {
  status?: string;
  freshness?: string;
  collected_at?: string | null;
  assurance?: string;
  transition?: string | null;
  decision?: string | null;
  protection?: string | null;
  checkpoint_result?: string | null;
}

interface TrustCompleteness {
  complete?: boolean;
  required_sources?: string[];
  missing_sources?: string[];
  unsupported_sources?: string[];
  degraded_sources?: string[];
  stale_sources?: string[];
}

interface TrustHistory {
  previous_state?: string | null;
  recovered_sources?: string[];
  recovery_observed?: boolean;
}

export interface TrustPosturePayload {
  schema: "tamandua.trust_posture/v1";
  state: TrustPostureState;
  risk_score?: number;
  confidence?: number;
  evaluated_at?: string | null;
  reason_codes?: string[];
  evidence_completeness?: TrustCompleteness;
  provenance?: Partial<Record<TrustSourceName, TrustSourceSummary>>;
  history?: TrustHistory;
  evidence_type?: string;
}

const statePresentation: Record<
  TrustPostureState,
  {
    label: string;
    description: string;
    color: string;
    background: string;
    icon: typeof Shield;
  }
> = {
  verified: {
    label: "Verified",
    description:
      "Server verification and all required fresh evidence are present.",
    color: "var(--emerald-400)",
    background: "rgba(52, 211, 153, 0.12)",
    icon: CheckCircle2,
  },
  unverified: {
    label: "Unverified",
    description:
      "No adverse finding is asserted, but server verification is incomplete.",
    color: "var(--muted)",
    background: "var(--surface-alt)",
    icon: HelpCircle,
  },
  degraded: {
    label: "Degraded",
    description:
      "Required evidence is missing, stale, unsupported, degraded, or adverse.",
    color: "var(--high)",
    background: "var(--high-bg)",
    icon: AlertTriangle,
  },
  suspected_clone: {
    label: "Suspected clone",
    description:
      "Multiple fresh sources corroborate identity drift or tampering.",
    color: "var(--crit)",
    background: "var(--crit-bg)",
    icon: ShieldAlert,
  },
  revoked: {
    label: "Revoked",
    description: "The server projection reports a revoked device credential.",
    color: "var(--crit)",
    background: "var(--crit-bg)",
    icon: ShieldX,
  },
};

const sourceNames: TrustSourceName[] = [
  "device_identity",
  "runtime_integrity",
  "app_guard",
  "offline_checkpoint",
];

const fixedReasonCodes = new Set([
  "identity_server_verified",
  "identity_not_verified",
  "client_claimed_attestation_unverified",
  "device_credential_revoked",
  "device_identity_drift",
  "runtime_integrity_adverse",
  "app_guard_adverse",
  "offline_checkpoint_adverse",
  "corroborated_clone_or_tamper",
]);

const sourceReasonPrefixes = new Set([
  "source_missing",
  "source_unsupported",
  "source_degraded",
  "source_stale",
  "source_future_timestamp",
  "source_freshness_unknown",
]);

const sourceStatuses = new Set([
  "available",
  "missing",
  "unsupported",
  "degraded",
  "revoked",
]);
const freshnessStatuses = new Set([
  "fresh",
  "stale",
  "invalid_future",
  "unknown",
  "missing",
  "unsupported",
]);

const sourceDetails: Record<TrustSourceName, Set<string>> = {
  device_identity: new Set([
    "server_verified",
    "client_claimed",
    "unverified",
    "revoked",
  ]),
  runtime_integrity: new Set([
    "finding_detected",
    "finding_changed",
    "collector_degraded",
    "recovered",
  ]),
  app_guard: new Set([
    "allow",
    "observe",
    "warn",
    "step_up",
    "block",
    "kill_session",
  ]),
  offline_checkpoint: new Set([
    "verified",
    "mismatch",
    "rollback_detected",
    "replay_detected",
    "unavailable",
    "authenticated",
    "degraded_unkeyed",
  ]),
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function isTrustPosturePayload(
  value: unknown,
): value is TrustPosturePayload {
  if (!isRecord(value)) return false;
  return (
    value.schema === "tamandua.trust_posture/v1" &&
    Object.prototype.hasOwnProperty.call(statePresentation, String(value.state))
  );
}

function safeSourceList(value: unknown): TrustSourceName[] {
  if (!Array.isArray(value)) return [];
  return sourceNames.filter((source) => value.includes(source));
}

function safeReasonCodes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];

  const recognized = value.flatMap((candidate) => {
    if (typeof candidate !== "string") return [];
    if (fixedReasonCodes.has(candidate)) return [candidate];

    const [prefix, source, ...extra] = candidate.split(":");
    if (
      extra.length === 0 &&
      sourceReasonPrefixes.has(prefix) &&
      sourceNames.includes(source as TrustSourceName)
    ) {
      return [candidate];
    }
    return [];
  });

  return [...new Set(recognized)];
}

function humanize(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function safeToken(value: unknown, allowed: Set<string>): string | null {
  return typeof value === "string" && allowed.has(value) ? value : null;
}

function safePercent(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(100, Math.max(0, Math.round(value)))
    : null;
}

function safeTimestamp(value: unknown): { iso: string; label: string } | null {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
      value,
    )
  )
    return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return { iso: date.toISOString(), label: date.toLocaleString() };
}

function EvidenceList({
  label,
  values,
}: {
  label: string;
  values: TrustSourceName[];
}) {
  return (
    <div>
      <dt className="text-xs" style={{ color: "var(--muted)" }}>
        {label}
      </dt>
      <dd
        className="text-sm mt-1"
        style={{ color: values.length > 0 ? "var(--fg)" : "var(--muted)" }}
      >
        {values.length > 0 ? values.map(humanize).join(", ") : "None reported"}
      </dd>
    </div>
  );
}

function sourceDetail(
  source: TrustSourceName,
  summary: TrustSourceSummary,
): string | null {
  const candidates =
    source === "device_identity"
      ? [summary.assurance]
      : source === "runtime_integrity"
        ? [summary.transition]
        : source === "app_guard"
          ? [summary.decision]
          : [summary.checkpoint_result, summary.protection];
  const detail = candidates
    .map((candidate) => safeToken(candidate, sourceDetails[source]))
    .find(Boolean);
  return detail ? humanize(detail) : null;
}

function verifiedProjectionIsConsistent(posture: TrustPosturePayload): boolean {
  if (posture.state !== "verified") return true;

  const requiredSources = safeSourceList(
    posture.evidence_completeness?.required_sources,
  );
  const identity = posture.provenance?.device_identity;

  return (
    posture.evidence_completeness?.complete === true &&
    requiredSources.includes("device_identity") &&
    identity?.assurance === "server_verified" &&
    requiredSources.every((source) => {
      const summary = posture.provenance?.[source];
      return summary?.status === "available" && summary.freshness === "fresh";
    })
  );
}

function SourceProvenance({
  source,
  summary,
}: {
  source: TrustSourceName;
  summary?: TrustSourceSummary;
}) {
  const timestamp = safeTimestamp(summary?.collected_at);
  const detail = summary ? sourceDetail(source, summary) : null;
  const status = safeToken(summary?.status, sourceStatuses);
  const freshness = safeToken(summary?.freshness, freshnessStatuses);

  return (
    <li
      className="rounded-lg p-3"
      style={{ backgroundColor: "var(--surface-alt)" }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium" style={{ color: "var(--fg)" }}>
            {humanize(source)}
          </div>
          <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>
            Status: {status ? humanize(status) : "Not reported"}
            {detail ? ` · ${detail}` : ""}
          </div>
        </div>
        <span className="text-xs font-medium" style={{ color: "var(--muted)" }}>
          {freshness ? humanize(freshness) : "Freshness unavailable"}
        </span>
      </div>
      <div
        className="text-xs mt-2 flex items-center gap-1"
        style={{ color: "var(--muted)" }}
      >
        <Clock3 className="h-3 w-3" aria-hidden="true" />
        {timestamp ? (
          <time dateTime={timestamp.iso}>{timestamp.label}</time>
        ) : (
          "Collection time unavailable"
        )}
      </div>
    </li>
  );
}

function UnavailableTrustPosture({ headingId }: { headingId: string }) {
  return (
    <section
      aria-labelledby={headingId}
      className="card-sentinel rounded-xl p-6"
      style={{
        backgroundColor: "var(--surface)",
        border: "1px solid var(--border)",
      }}
    >
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Shield
              className="h-5 w-5"
              style={{ color: "var(--muted)" }}
              aria-hidden="true"
            />
            <h2
              id={headingId}
              className="text-lg font-semibold"
              style={{ color: "var(--fg)" }}
            >
              Trust Posture
            </h2>
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{
                color: "var(--muted)",
                backgroundColor: "var(--surface-alt)",
              }}
            >
              Preview
            </span>
          </div>
          <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
            Tamandua trust posture projection
          </p>
        </div>
        <span
          role="status"
          className="text-sm font-medium"
          style={{ color: "var(--muted)" }}
        >
          Not evaluated
        </span>
      </div>
      <p className="text-sm mt-4" style={{ color: "var(--muted)" }}>
        Trust posture data is unavailable. No verified state has been inferred.
      </p>
    </section>
  );
}

export function TrustPosturePanel({ posture }: { posture?: unknown }) {
  const headingId = useId();
  if (
    !isTrustPosturePayload(posture) ||
    !verifiedProjectionIsConsistent(posture)
  )
    return <UnavailableTrustPosture headingId={headingId} />;

  const presentation = statePresentation[posture.state];
  const StateIcon = presentation.icon;
  const evaluatedAt = safeTimestamp(posture.evaluated_at);
  const completeness = posture.evidence_completeness || {};
  const reasons = safeReasonCodes(posture.reason_codes);
  const confidence = safePercent(posture.confidence);
  const riskScore = safePercent(posture.risk_score);
  const synthetic = posture.evidence_type === "synthetic_contract";

  return (
    <section
      aria-labelledby={headingId}
      className="card-sentinel rounded-xl p-6"
      style={{
        backgroundColor: "var(--surface)",
        border: "1px solid var(--border)",
      }}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <Shield
              className="h-5 w-5"
              style={{ color: presentation.color }}
              aria-hidden="true"
            />
            <h2
              id={headingId}
              className="text-lg font-semibold"
              style={{ color: "var(--fg)" }}
            >
              Trust Posture
            </h2>
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{
                color: "var(--muted)",
                backgroundColor: "var(--surface-alt)",
              }}
            >
              Preview
            </span>
          </div>
          <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
            {synthetic
              ? "Synthetic contract fixture"
              : "Tamandua trust posture projection"}{" "}
            · External claims disabled or unavailable
          </p>
        </div>
        <div
          role="status"
          aria-label={`Trust posture: ${presentation.label}`}
          className="inline-flex items-center gap-2 rounded-lg px-3 py-2"
          style={{
            color: presentation.color,
            backgroundColor: presentation.background,
          }}
        >
          <StateIcon className="h-4 w-4" aria-hidden="true" />
          <span className="text-sm font-semibold">{presentation.label}</span>
        </div>
      </div>

      <p className="text-sm mt-4" style={{ color: "var(--muted)" }}>
        {presentation.description}
      </p>

      <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
        <div
          className="rounded-lg p-3"
          style={{ backgroundColor: "var(--surface-alt)" }}
        >
          <dt className="text-xs" style={{ color: "var(--muted)" }}>
            Risk score
          </dt>
          <dd
            className="text-lg font-semibold mt-1"
            style={{ color: "var(--fg)" }}
          >
            {riskScore ?? "Unavailable"}
          </dd>
        </div>
        <div
          className="rounded-lg p-3"
          style={{ backgroundColor: "var(--surface-alt)" }}
        >
          <dt className="text-xs" style={{ color: "var(--muted)" }}>
            Confidence
          </dt>
          <dd
            className="text-lg font-semibold mt-1"
            style={{ color: "var(--fg)" }}
          >
            {confidence === null ? "Unavailable" : `${confidence}%`}
          </dd>
        </div>
        <div
          className="rounded-lg p-3"
          style={{ backgroundColor: "var(--surface-alt)" }}
        >
          <dt className="text-xs" style={{ color: "var(--muted)" }}>
            Completeness
          </dt>
          <dd
            className="text-sm font-semibold mt-1"
            style={{
              color:
                completeness.complete === true
                  ? "var(--emerald-400)"
                  : "var(--high)",
            }}
          >
            {completeness.complete === true
              ? "Complete"
              : "Incomplete or unavailable"}
          </dd>
        </div>
        <div
          className="rounded-lg p-3"
          style={{ backgroundColor: "var(--surface-alt)" }}
        >
          <dt className="text-xs" style={{ color: "var(--muted)" }}>
            Evaluated
          </dt>
          <dd
            className="text-xs font-medium mt-1"
            style={{ color: "var(--fg)" }}
          >
            {evaluatedAt ? (
              <time dateTime={evaluatedAt.iso}>{evaluatedAt.label}</time>
            ) : (
              "Unavailable"
            )}
          </dd>
        </div>
      </dl>

      <div className="grid md:grid-cols-2 gap-4 mt-5">
        <div>
          <h3
            className="text-sm font-semibold mb-2"
            style={{ color: "var(--fg)" }}
          >
            Evidence provenance and freshness
          </h3>
          <ul className="space-y-2" aria-label="Trust evidence sources">
            {sourceNames.map((source) => (
              <SourceProvenance
                key={source}
                source={source}
                summary={posture.provenance?.[source]}
              />
            ))}
          </ul>
        </div>
        <div className="space-y-4">
          <div>
            <h3
              className="text-sm font-semibold mb-2"
              style={{ color: "var(--fg)" }}
            >
              Evidence completeness
            </h3>
            <dl
              className="grid grid-cols-2 gap-3 rounded-lg p-3"
              style={{ backgroundColor: "var(--surface-alt)" }}
            >
              <EvidenceList
                label="Missing"
                values={safeSourceList(completeness.missing_sources)}
              />
              <EvidenceList
                label="Unsupported"
                values={safeSourceList(completeness.unsupported_sources)}
              />
              <EvidenceList
                label="Degraded"
                values={safeSourceList(completeness.degraded_sources)}
              />
              <EvidenceList
                label="Stale"
                values={safeSourceList(completeness.stale_sources)}
              />
            </dl>
          </div>
          <div>
            <h3
              className="text-sm font-semibold mb-2"
              style={{ color: "var(--fg)" }}
            >
              Reason codes
            </h3>
            {reasons.length > 0 ? (
              <ul
                className="flex flex-wrap gap-2"
                aria-label="Trust posture reason codes"
              >
                {reasons.map((reason) => (
                  <li
                    key={reason}
                    className="font-mono text-xs rounded px-2 py-1"
                    style={{
                      color: "var(--fg-2)",
                      backgroundColor: "var(--surface-alt)",
                    }}
                  >
                    {reason}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm" style={{ color: "var(--muted)" }}>
                No recognized reason codes reported.
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export function TrustPostureTransitionSummary({
  posture,
}: {
  posture?: unknown;
}) {
  if (
    !isTrustPosturePayload(posture) ||
    !verifiedProjectionIsConsistent(posture)
  )
    return null;

  const presentation = statePresentation[posture.state];
  const StateIcon = presentation.icon;
  const previous = Object.prototype.hasOwnProperty.call(
    statePresentation,
    String(posture.history?.previous_state),
  )
    ? statePresentation[posture.history?.previous_state as TrustPostureState]
        .label
    : null;
  const recovered =
    posture.history?.recovery_observed === true
      ? safeSourceList(posture.history.recovered_sources)
      : [];
  const evaluatedAt = safeTimestamp(posture.evaluated_at);

  return (
    <section
      aria-label="Trust posture transition"
      className="rounded-lg p-3"
      style={{
        backgroundColor: "var(--bg-2)",
        border: "1px solid var(--border)",
      }}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <StateIcon
            className="h-4 w-4"
            style={{ color: presentation.color }}
            aria-hidden="true"
          />
          <span
            className="text-sm font-semibold"
            style={{ color: "var(--fg)" }}
          >
            Trust posture · Preview
          </span>
        </div>
        <span
          className="text-xs font-medium"
          style={{ color: presentation.color }}
        >
          {presentation.label}
        </span>
      </div>
      <p className="text-xs mt-2" style={{ color: "var(--muted)" }}>
        {previous && posture.history?.previous_state !== posture.state
          ? `${previous} → ${presentation.label}`
          : `Current projection: ${presentation.label}`}
        {recovered.length > 0
          ? ` · Recovered: ${recovered.map(humanize).join(", ")}`
          : ""}
      </p>
      {evaluatedAt && (
        <time
          className="text-xs mt-1 block"
          style={{ color: "var(--muted)" }}
          dateTime={evaluatedAt.iso}
        >
          Evaluated {evaluatedAt.label}
        </time>
      )}
    </section>
  );
}
