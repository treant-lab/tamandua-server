import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleOff,
  Clock3,
  HelpCircle,
  Shield,
} from "lucide-react";
import { useId } from "react";

type RuntimeIntegrityPreviewStatus =
  | "disabled"
  | "partial"
  | "clean"
  | "mismatch"
  | "degraded"
  | "unsupported";

type RuntimeIntegrityRuntimeState = "supported" | "degraded";
type RuntimeIntegrityBudgetState = "within_budget" | "exceeded";

interface RuntimeIntegrityCoverageV1 {
  eligible_pages: number;
  compared_pages: number;
  excluded_relocation_pages: number;
  unstable_pages: number;
  bytes_read: number;
  elapsed_us: number;
  budget_limit_us: 10000;
  full_sweep_completed: boolean;
  budget_state: RuntimeIntegrityBudgetState;
}

interface RuntimeIntegrityCoverageV2 {
  eligible_pages: number;
  pages_compared_this_tick: number;
  sweep_pages_compared: number;
  excluded_relocation_pages: number;
  unstable_pages_this_tick: number;
  memory_bytes_read_this_tick: number;
  elapsed_us_this_tick: number;
  budget_limit_us: 10000;
  full_sweep_completed: boolean;
  budget_state: RuntimeIntegrityBudgetState;
}

interface RuntimeIntegrityPreviewBase {
  external_claim_allowed: false;
  maturity: "preview";
  mode: "observe_only";
  enabled: boolean;
  status: RuntimeIntegrityPreviewStatus;
  runtime_state: RuntimeIntegrityRuntimeState;
  observed_at: string | null;
  finding_kinds: RuntimeIntegrityFindingKind[];
  limitations: RuntimeIntegrityLimitation[];
}

export interface RuntimeIntegrityPreviewPayloadV1 extends RuntimeIntegrityPreviewBase {
  schema: "tamandua.runtime_integrity_preview/v1";
  capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v1";
  coverage: RuntimeIntegrityCoverageV1;
}

export interface RuntimeIntegrityPreviewPayloadV2 extends RuntimeIntegrityPreviewBase {
  schema: "tamandua.runtime_integrity_preview/v2";
  capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v2";
  coverage: RuntimeIntegrityCoverageV2;
}

export type RuntimeIntegrityPreviewPayload =
  | RuntimeIntegrityPreviewPayloadV1
  | RuntimeIntegrityPreviewPayloadV2;

type RuntimeIntegrityFindingKind =
  | "writable_executable_mapping"
  | "debugger_or_tracer_attached"
  | "instrumentation_library_loaded"
  | "file_backed_executable_page_drift";

type RuntimeIntegrityLimitation =
  | "rx_page_content_anonymous_jit_out_of_scope"
  | "rx_page_content_backing_deleted"
  | "rx_page_content_backing_replaced"
  | "rx_page_content_baseline_mismatch"
  | "rx_page_content_baseline_unavailable"
  | "rx_page_content_bootstrap_budget_exceeded"
  | "rx_page_content_budget_exceeded"
  | "rx_page_content_coverage_limit_exceeded"
  | "rx_page_content_disabled"
  | "rx_page_content_elf_unsupported"
  | "rx_page_content_execute_only"
  | "rx_page_content_identity_race"
  | "rx_page_content_memory_read_unavailable"
  | "rx_page_content_no_eligible_pages"
  | "rx_page_content_relocation_unsupported";

const projectionKeys = [
  "capability_id",
  "coverage",
  "enabled",
  "external_claim_allowed",
  "finding_kinds",
  "limitations",
  "maturity",
  "mode",
  "observed_at",
  "runtime_state",
  "schema",
  "status",
] as const;

const coverageKeysV1 = [
  "budget_limit_us",
  "budget_state",
  "bytes_read",
  "compared_pages",
  "elapsed_us",
  "eligible_pages",
  "excluded_relocation_pages",
  "full_sweep_completed",
  "unstable_pages",
] as const;

const coverageKeysV2 = [
  "budget_limit_us",
  "budget_state",
  "elapsed_us_this_tick",
  "eligible_pages",
  "excluded_relocation_pages",
  "full_sweep_completed",
  "memory_bytes_read_this_tick",
  "pages_compared_this_tick",
  "sweep_pages_compared",
  "unstable_pages_this_tick",
] as const;

const findingKinds = new Set<RuntimeIntegrityFindingKind>([
  "writable_executable_mapping",
  "debugger_or_tracer_attached",
  "instrumentation_library_loaded",
  "file_backed_executable_page_drift",
]);

const findingKindLabels: Record<RuntimeIntegrityFindingKind, string> = {
  writable_executable_mapping: "W+X mapping",
  debugger_or_tracer_attached: "Debugger / tracer attached",
  instrumentation_library_loaded: "Known instrumentation marker",
  file_backed_executable_page_drift: "File-backed executable page drift",
};

const limitationLabels: Record<RuntimeIntegrityLimitation, string> = {
  rx_page_content_anonymous_jit_out_of_scope: "Anonymous and JIT mappings are out of scope",
  rx_page_content_backing_deleted: "Startup backing file was deleted",
  rx_page_content_backing_replaced: "Startup backing file identity changed",
  rx_page_content_baseline_mismatch: "Configured baseline did not match the startup artifact",
  rx_page_content_baseline_unavailable: "Protected startup baseline was unavailable",
  rx_page_content_bootstrap_budget_exceeded: "Bootstrap observation budget was exceeded",
  rx_page_content_budget_exceeded: "Tick observation budget was exceeded",
  rx_page_content_coverage_limit_exceeded: "Executable coverage exceeded the preview capacity",
  rx_page_content_disabled: "Page-content observation is disabled",
  rx_page_content_elf_unsupported: "ELF layout is unsupported by this preview",
  rx_page_content_execute_only: "Execute-only mapping could not be read",
  rx_page_content_identity_race: "Artifact identity changed during observation",
  rx_page_content_memory_read_unavailable: "Bounded memory read was unavailable",
  rx_page_content_no_eligible_pages: "No eligible file-backed executable pages were found",
  rx_page_content_relocation_unsupported: "Relocation layout could not be excluded safely",
};

const limitationIds = new Set<RuntimeIntegrityLimitation>(
  Object.keys(limitationLabels) as RuntimeIntegrityLimitation[],
);

const limitationIdsV1 = new Set<RuntimeIntegrityLimitation>([
  "rx_page_content_anonymous_jit_out_of_scope",
  "rx_page_content_backing_deleted",
  "rx_page_content_backing_replaced",
  "rx_page_content_baseline_mismatch",
  "rx_page_content_baseline_unavailable",
  "rx_page_content_budget_exceeded",
  "rx_page_content_disabled",
  "rx_page_content_elf_unsupported",
  "rx_page_content_execute_only",
  "rx_page_content_identity_race",
  "rx_page_content_memory_read_unavailable",
  "rx_page_content_no_eligible_pages",
  "rx_page_content_relocation_unsupported",
]);

const degradedLimitations = new Set<RuntimeIntegrityLimitation>([
  "rx_page_content_backing_deleted",
  "rx_page_content_backing_replaced",
  "rx_page_content_baseline_mismatch",
  "rx_page_content_baseline_unavailable",
  "rx_page_content_bootstrap_budget_exceeded",
  "rx_page_content_budget_exceeded",
  "rx_page_content_coverage_limit_exceeded",
  "rx_page_content_execute_only",
  "rx_page_content_identity_race",
  "rx_page_content_memory_read_unavailable",
  "rx_page_content_no_eligible_pages",
  "rx_page_content_relocation_unsupported",
]);

const statusPresentation: Record<
  RuntimeIntegrityPreviewStatus,
  {
    label: string;
    description: string;
    color: string;
    background: string;
    icon: typeof Shield;
  }
> = {
  disabled: {
    label: "Disabled",
    description: "Page-content observation is not enabled for this endpoint.",
    color: "var(--muted)",
    background: "var(--surface-alt)",
    icon: CircleOff,
  },
  clean: {
    label: "No page-content drift observed",
    description: "The completed bounded sweep observed no page-content drift.",
    color: "var(--emerald-400)",
    background: "rgba(52, 211, 153, 0.12)",
    icon: CheckCircle2,
  },
  partial: {
    label: "Partial observation",
    description: "A bounded subset was compared; a full sweep has not completed.",
    color: "var(--high)",
    background: "var(--high-bg)",
    icon: Activity,
  },
  mismatch: {
    label: "Drift observed",
    description: "Compared executable page content differed from the startup baseline.",
    color: "var(--high)",
    background: "var(--high-bg)",
    icon: AlertTriangle,
  },
  degraded: {
    label: "Degraded",
    description: "The bounded observation could not complete with its required evidence.",
    color: "var(--high)",
    background: "var(--high-bg)",
    icon: AlertTriangle,
  },
  unsupported: {
    label: "Unsupported",
    description: "This executable layout is outside the supported preview boundary.",
    color: "var(--muted)",
    background: "var(--surface-alt)",
    icon: HelpCircle,
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function boundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

function isSortedUniqueAllowlist<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  maximum: number,
): value is T[] {
  if (!Array.isArray(value) || value.length > maximum || !value.every((item) => typeof item === "string")) {
    return false;
  }
  const strings = value as string[];
  return (
    strings.every((item) => allowed.has(item as T)) &&
    strings.every((item, index) => index === 0 || strings[index - 1] < item)
  );
}

function isIsoTimestamp(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[10] === undefined ? 0 : Number(match[10]);
  const offsetMinute = match[11] === undefined ? 0 : Number(match[11]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1] ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return false;
  }

  return Number.isFinite(new Date(value).getTime());
}

function validCoverageV1(value: unknown): value is RuntimeIntegrityCoverageV1 {
  if (!isRecord(value) || !hasExactKeys(value, coverageKeysV1)) return false;
  const eligible = value.eligible_pages;
  const compared = value.compared_pages;
  const excluded = value.excluded_relocation_pages;
  const unstable = value.unstable_pages;
  const bytes = value.bytes_read;
  const elapsed = value.elapsed_us;
  const budget = value.budget_limit_us;
  const full = value.full_sweep_completed;
  const budgetState = value.budget_state;

  return (
    boundedInteger(eligible, 0, 1024) &&
    boundedInteger(compared, 0, 16) &&
    boundedInteger(excluded, 0, 16384) &&
    boundedInteger(unstable, 0, 16) &&
    boundedInteger(bytes, 0, 65536) &&
    boundedInteger(elapsed, 0, 60000) &&
    budget === 10000 &&
    typeof full === "boolean" &&
    (budgetState === "within_budget" || budgetState === "exceeded") &&
    compared <= eligible &&
    unstable <= compared &&
    bytes === compared * 4096 &&
    (!full || compared === eligible) &&
    ((budgetState === "within_budget" && elapsed <= budget) ||
      (budgetState === "exceeded" && elapsed > budget))
  );
}

function validCoverageV2(value: unknown): value is RuntimeIntegrityCoverageV2 {
  if (!isRecord(value) || !hasExactKeys(value, coverageKeysV2)) return false;
  const eligible = value.eligible_pages;
  const perTick = value.pages_compared_this_tick;
  const sweep = value.sweep_pages_compared;
  const excluded = value.excluded_relocation_pages;
  const unstable = value.unstable_pages_this_tick;
  const bytes = value.memory_bytes_read_this_tick;
  const elapsed = value.elapsed_us_this_tick;
  const budget = value.budget_limit_us;
  const full = value.full_sweep_completed;
  const budgetState = value.budget_state;

  return (
    boundedInteger(eligible, 0, 8192) &&
    boundedInteger(perTick, 0, 8) &&
    boundedInteger(sweep, 0, 8192) &&
    boundedInteger(excluded, 0, 16384) &&
    boundedInteger(unstable, 0, 8) &&
    boundedInteger(bytes, 0, 65536) &&
    bytes % 4096 === 0 &&
    boundedInteger(elapsed, 0, 60000) &&
    budget === 10000 &&
    typeof full === "boolean" &&
    (budgetState === "within_budget" || budgetState === "exceeded") &&
    sweep <= eligible &&
    unstable <= perTick &&
    full === (eligible > 0 && sweep === eligible) &&
    ((budgetState === "within_budget" && elapsed <= budget) ||
      (budgetState === "exceeded" && elapsed > budget))
  );
}

function validStatusRelationsV1(value: RuntimeIntegrityPreviewPayloadV1): boolean {
  const coverage = value.coverage;
  const drift = value.finding_kinds.includes("file_backed_executable_page_drift");
  const budgetLimitation = value.limitations.includes("rx_page_content_budget_exceeded");
  const anonymousJitOnly =
    value.limitations.length === 1 &&
    value.limitations[0] === "rx_page_content_anonymous_jit_out_of_scope";
  if ((coverage.budget_state === "exceeded") !== budgetLimitation) return false;

  switch (value.status) {
    case "disabled":
      return (
        value.enabled === false &&
        coverage.eligible_pages === 0 &&
        coverage.compared_pages === 0 &&
        coverage.excluded_relocation_pages === 0 &&
        coverage.unstable_pages === 0 &&
        coverage.bytes_read === 0 &&
        coverage.elapsed_us === 0 &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        !drift &&
        value.limitations.length === 1 &&
        value.limitations[0] === "rx_page_content_disabled"
      );
    case "partial":
      return (
        value.enabled === true &&
        coverage.compared_pages > 0 &&
        coverage.compared_pages < coverage.eligible_pages &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        !drift &&
        anonymousJitOnly
      );
    case "clean":
      return (
        value.enabled === true &&
        coverage.compared_pages > 0 &&
        coverage.compared_pages === coverage.eligible_pages &&
        coverage.unstable_pages === 0 &&
        coverage.full_sweep_completed === true &&
        coverage.budget_state === "within_budget" &&
        !drift &&
        anonymousJitOnly
      );
    case "mismatch":
      return (
        value.enabled === true &&
        coverage.compared_pages > 0 &&
        coverage.budget_state === "within_budget" &&
        drift &&
        anonymousJitOnly
      );
    case "degraded":
      return (
        value.enabled === true &&
        value.runtime_state === "degraded" &&
        coverage.full_sweep_completed === false &&
        !drift &&
        !value.limitations.includes("rx_page_content_disabled") &&
        value.limitations.some((limitation) => degradedLimitations.has(limitation))
      );
    case "unsupported":
      return (
        value.enabled === true &&
        value.runtime_state === "degraded" &&
        coverage.eligible_pages === 0 &&
        coverage.compared_pages === 0 &&
        coverage.excluded_relocation_pages === 0 &&
        coverage.unstable_pages === 0 &&
        coverage.bytes_read === 0 &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        !drift &&
        !value.limitations.includes("rx_page_content_disabled") &&
        value.limitations.includes("rx_page_content_elf_unsupported")
      );
  }
}

function validStatusRelationsV2(value: RuntimeIntegrityPreviewPayloadV2): boolean {
  const coverage = value.coverage;
  const drift = value.finding_kinds.includes("file_backed_executable_page_drift");
  const limitation = value.limitations.length === 1 ? value.limitations[0] : undefined;
  const budgetCause = limitation === "rx_page_content_budget_exceeded";
  const normalBytes = coverage.memory_bytes_read_this_tick === coverage.pages_compared_this_tick * 8192;
  const degradedBytes =
    normalBytes ||
    coverage.memory_bytes_read_this_tick === coverage.pages_compared_this_tick * 8192 + 4096;

  if (!limitation || (coverage.budget_state === "exceeded") !== budgetCause) return false;
  if ((coverage.unstable_pages_this_tick > 0) !== (limitation === "rx_page_content_identity_race")) {
    return false;
  }

  switch (value.status) {
    case "disabled":
      return (
        value.enabled === false &&
        value.runtime_state === "supported" &&
        limitation === "rx_page_content_disabled" &&
        coverage.eligible_pages === 0 &&
        coverage.pages_compared_this_tick === 0 &&
        coverage.sweep_pages_compared === 0 &&
        coverage.excluded_relocation_pages === 0 &&
        coverage.unstable_pages_this_tick === 0 &&
        coverage.memory_bytes_read_this_tick === 0 &&
        coverage.elapsed_us_this_tick === 0 &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        !drift
      );
    case "partial":
      return (
        value.enabled === true &&
        value.runtime_state === "supported" &&
        limitation === "rx_page_content_anonymous_jit_out_of_scope" &&
        coverage.pages_compared_this_tick > 0 &&
        coverage.sweep_pages_compared > 0 &&
        coverage.sweep_pages_compared < coverage.eligible_pages &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        normalBytes &&
        !drift
      );
    case "clean":
      return (
        value.enabled === true &&
        value.runtime_state === "supported" &&
        limitation === "rx_page_content_anonymous_jit_out_of_scope" &&
        coverage.pages_compared_this_tick > 0 &&
        coverage.full_sweep_completed === true &&
        coverage.unstable_pages_this_tick === 0 &&
        coverage.budget_state === "within_budget" &&
        normalBytes &&
        !drift
      );
    case "mismatch":
      return (
        value.enabled === true &&
        value.runtime_state === "supported" &&
        limitation === "rx_page_content_anonymous_jit_out_of_scope" &&
        coverage.pages_compared_this_tick > 0 &&
        coverage.sweep_pages_compared > 0 &&
        coverage.budget_state === "within_budget" &&
        normalBytes &&
        drift
      );
    case "degraded": {
      if (
        value.enabled !== true ||
        value.runtime_state !== "degraded" ||
        !degradedLimitations.has(limitation) ||
        limitation === "rx_page_content_elf_unsupported" ||
        !degradedBytes ||
        drift
      ) {
        return false;
      }
      if (
        limitation === "rx_page_content_coverage_limit_exceeded" ||
        limitation === "rx_page_content_bootstrap_budget_exceeded"
      ) {
        return (
          coverage.eligible_pages === 0 &&
          coverage.pages_compared_this_tick === 0 &&
          coverage.sweep_pages_compared === 0 &&
          coverage.excluded_relocation_pages === 0 &&
          coverage.unstable_pages_this_tick === 0 &&
          coverage.memory_bytes_read_this_tick === 0 &&
          coverage.elapsed_us_this_tick === 0 &&
          coverage.full_sweep_completed === false &&
          coverage.budget_state === "within_budget"
        );
      }
      return true;
    }
    case "unsupported":
      return (
        value.enabled === true &&
        value.runtime_state === "degraded" &&
        limitation === "rx_page_content_elf_unsupported" &&
        coverage.eligible_pages === 0 &&
        coverage.pages_compared_this_tick === 0 &&
        coverage.sweep_pages_compared === 0 &&
        coverage.excluded_relocation_pages === 0 &&
        coverage.unstable_pages_this_tick === 0 &&
        coverage.memory_bytes_read_this_tick === 0 &&
        coverage.full_sweep_completed === false &&
        coverage.budget_state === "within_budget" &&
        !drift
      );
  }
}

export function isRuntimeIntegrityPreviewPayload(
  value: unknown,
): value is RuntimeIntegrityPreviewPayload {
  if (!isRecord(value) || !hasExactKeys(value, projectionKeys)) return false;
  if (
    value.external_claim_allowed !== false ||
    value.maturity !== "preview" ||
    value.mode !== "observe_only" ||
    typeof value.enabled !== "boolean" ||
    !Object.prototype.hasOwnProperty.call(statusPresentation, String(value.status)) ||
    (value.runtime_state !== "supported" && value.runtime_state !== "degraded") ||
    !isIsoTimestamp(value.observed_at) ||
    !isSortedUniqueAllowlist(value.finding_kinds, findingKinds, findingKinds.size) ||
    !isSortedUniqueAllowlist(value.limitations, limitationIds, limitationIds.size)
  ) {
    return false;
  }

  if (
    value.schema === "tamandua.runtime_integrity_preview/v1" &&
    value.capability_id === "linux_self_file_backed_elf_rx_page_content_preview_v1" &&
    isSortedUniqueAllowlist(value.limitations, limitationIdsV1, limitationIdsV1.size) &&
    validCoverageV1(value.coverage)
  ) {
    return validStatusRelationsV1(value as unknown as RuntimeIntegrityPreviewPayloadV1);
  }

  if (
    value.schema === "tamandua.runtime_integrity_preview/v2" &&
    value.capability_id === "linux_self_file_backed_elf_rx_page_content_preview_v2" &&
    validCoverageV2(value.coverage)
  ) {
    return validStatusRelationsV2(value as unknown as RuntimeIntegrityPreviewPayloadV2);
  }

  return false;
}

function FixedUnavailable({ invalid }: { invalid: boolean }) {
  return (
    <div className="mt-4 rounded-lg p-4" style={{ backgroundColor: "var(--surface-alt)" }}>
      <div className="text-sm font-medium" style={{ color: "var(--muted)" }} role="status">
        {invalid ? "Unavailable / invalid" : "Not reported"}
      </div>
      <p className="text-xs mt-1" style={{ color: "var(--muted)" }}>
        {invalid
          ? "Runtime integrity preview data did not match the closed display contract."
          : "Runtime integrity preview data has not been reported for this endpoint."}
      </p>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg p-3" style={{ backgroundColor: "var(--surface-alt)" }}>
      <dt className="text-xs" style={{ color: "var(--muted)" }}>
        {label}
      </dt>
      <dd className="text-sm font-semibold mt-1" style={{ color: "var(--fg)" }}>
        {value}
      </dd>
    </div>
  );
}

export function RuntimeIntegrityPreviewPanel({ preview }: { preview?: unknown }) {
  const headingId = useId();
  const missing = preview === undefined || preview === null;
  const valid = isRuntimeIntegrityPreviewPayload(preview);

  return (
    <section
      aria-labelledby={headingId}
      className="card-sentinel rounded-xl p-6"
      style={{ backgroundColor: "var(--surface)", border: "1px solid var(--border)" }}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <Shield className="h-5 w-5" style={{ color: "var(--muted)" }} aria-hidden="true" />
            <h2 id={headingId} className="text-lg font-semibold" style={{ color: "var(--fg)" }}>
              Runtime Integrity
            </h2>
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{ color: "var(--muted)", backgroundColor: "var(--surface-alt)" }}
            >
              Preview
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{ color: "var(--muted)", backgroundColor: "var(--surface-alt)" }}
            >
              Default off
            </span>
          </div>
          <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
            Observe only · External claims disabled
          </p>
        </div>
        {valid && (
          <span
            className="text-xs font-medium"
            style={{
              color: preview.runtime_state === "degraded" ? "var(--high)" : "var(--muted)",
            }}
          >
            Collector state: {preview.runtime_state === "degraded" ? "Degraded" : "Available"}
          </span>
        )}
      </div>

      {!valid ? (
        <FixedUnavailable invalid={!missing} />
      ) : (
        <RuntimeIntegrityProjection preview={preview} />
      )}
    </section>
  );
}

function RuntimeIntegrityProjection({ preview }: { preview: RuntimeIntegrityPreviewPayload }) {
  const presentation = statusPresentation[preview.status];
  const StatusIcon = presentation.icon;
  const observed = preview.observed_at === null ? null : new Date(preview.observed_at);

  return (
    <div className="mt-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div
            role="status"
            aria-label={`Runtime integrity preview: ${presentation.label}`}
            className="inline-flex items-center gap-2 rounded-lg px-3 py-2"
            style={{ color: presentation.color, backgroundColor: presentation.background }}
          >
            <StatusIcon className="h-4 w-4" aria-hidden="true" />
            <span className="text-sm font-semibold">{presentation.label}</span>
          </div>
          <p className="text-sm mt-2" style={{ color: "var(--muted)" }}>
            {presentation.description}
          </p>
        </div>
        <div className="text-xs flex items-center gap-1" style={{ color: "var(--muted)" }}>
          <Clock3 className="h-3 w-3" aria-hidden="true" />
          {observed ? (
            <time dateTime={observed.toISOString()}>{observed.toLocaleString()}</time>
          ) : (
            "Observation time unavailable"
          )}
        </div>
      </div>

      {preview.schema === "tamandua.runtime_integrity_preview/v2" ? (
        <CoverageV2 coverage={preview.coverage} status={preview.status} />
      ) : (
        <CoverageV1 coverage={preview.coverage} status={preview.status} />
      )}

      <div className="mt-4">
        <h3 className="text-sm font-semibold" style={{ color: "var(--fg)" }}>
          Observed runtime signals
        </h3>
        {preview.finding_kinds.length === 0 ? (
          <p className="text-sm mt-2" style={{ color: "var(--muted)" }}>
            No allowlisted runtime signal reported.
          </p>
        ) : (
          <ul className="mt-2 flex flex-wrap gap-2" aria-label="Observed runtime signals">
            {preview.finding_kinds.map((finding) => (
              <li
                key={finding}
                className="text-xs rounded px-2 py-1"
                style={{ color: "var(--fg-2)", backgroundColor: "var(--surface-alt)" }}
              >
                {findingKindLabels[finding]}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="mt-4">
        <h3 className="text-sm font-semibold" style={{ color: "var(--fg)" }}>
          Known limitations
        </h3>
        {preview.limitations.length === 0 ? (
          <p className="text-sm mt-2" style={{ color: "var(--muted)" }}>
            No allowlisted limitation reported.
          </p>
        ) : (
          <ul
            className="mt-2 flex flex-wrap gap-2"
            aria-label="Runtime integrity preview limitations"
          >
            {preview.limitations.map((limitation) => (
              <li
                key={limitation}
                className="text-xs rounded px-2 py-1"
                style={{ color: "var(--fg-2)", backgroundColor: "var(--surface-alt)" }}
              >
                {limitationLabels[limitation]}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function sweepLabel(status: RuntimeIntegrityPreviewStatus, full: boolean): string {
  if (full) return "Complete";
  return status === "disabled" ? "Not run" : "Incomplete";
}

function budgetLabel(state: RuntimeIntegrityBudgetState, limit: number): string {
  return state === "within_budget" ? `Within ${limit} µs` : `Exceeded ${limit} µs`;
}

function CoverageV1({
  coverage,
  status,
}: {
  coverage: RuntimeIntegrityCoverageV1;
  status: RuntimeIntegrityPreviewStatus;
}) {
  return (
    <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
      <Metric label="Eligible pages" value={coverage.eligible_pages} />
      <Metric label="Compared pages" value={coverage.compared_pages} />
      <Metric label="Accumulated progress" value="Unavailable in v1" />
      <Metric label="Relocation exclusions" value={coverage.excluded_relocation_pages} />
      <Metric label="Unstable pages" value={coverage.unstable_pages} />
      <Metric label="Bytes read" value={coverage.bytes_read} />
      <Metric label="Sweep" value={sweepLabel(status, coverage.full_sweep_completed)} />
      <Metric label="Elapsed" value={`${coverage.elapsed_us} µs`} />
      <Metric label="Budget" value={budgetLabel(coverage.budget_state, coverage.budget_limit_us)} />
    </dl>
  );
}

function CoverageV2({
  coverage,
  status,
}: {
  coverage: RuntimeIntegrityCoverageV2;
  status: RuntimeIntegrityPreviewStatus;
}) {
  return (
    <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
      <Metric label="Eligible pages" value={coverage.eligible_pages} />
      <Metric label="Compared this tick" value={coverage.pages_compared_this_tick} />
      <Metric
        label="Accumulated sweep progress"
        value={`${coverage.sweep_pages_compared} / ${coverage.eligible_pages}`}
      />
      <Metric label="Relocation exclusions" value={coverage.excluded_relocation_pages} />
      <Metric label="Unstable this tick" value={coverage.unstable_pages_this_tick} />
      <Metric label="Memory read this tick" value={coverage.memory_bytes_read_this_tick} />
      <Metric label="Sweep" value={sweepLabel(status, coverage.full_sweep_completed)} />
      <Metric label="Elapsed this tick" value={`${coverage.elapsed_us_this_tick} µs`} />
      <Metric label="Budget" value={budgetLabel(coverage.budget_state, coverage.budget_limit_us)} />
    </dl>
  );
}
