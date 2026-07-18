import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import ts from "typescript";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const directory = path.dirname(fileURLToPath(import.meta.url));
const componentRoot = path.resolve(directory, "..");
const componentPath = path.join(componentRoot, "RuntimeIntegrityPreviewPanel.tsx");
const source = fs.readFileSync(componentPath, "utf8");
const agentDetail = fs.readFileSync(
  path.resolve(componentRoot, "..", "pages", "AgentDetail.tsx"),
  "utf8",
);
const fixture = JSON.parse(
  fs.readFileSync(
    path.resolve(componentRoot, "__fixtures__", "runtime-integrity-preview.synthetic.json"),
    "utf8",
  ),
);

const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
    jsx: ts.JsxEmit.ReactJSX,
    esModuleInterop: true,
  },
  fileName: componentPath,
}).outputText;
const require = createRequire(import.meta.url);
const sandbox = { exports: {}, module: { exports: {} }, require };
sandbox.module.exports = sandbox.exports;
vm.runInNewContext(compiled, sandbox, { filename: componentPath });
const validate = sandbox.exports.isRuntimeIntegrityPreviewPayload;
const Panel = sandbox.exports.RuntimeIntegrityPreviewPanel;
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const expectedFixtureKeys = ["evidence_class", "external_claim_allowed", "fixture_id", "scenarios"];
const expectedScenarios = [
  ["v1-compatibility-clean", "tamandua.runtime_integrity_preview/v1", "clean"],
  ["v1-compatibility-disabled", "tamandua.runtime_integrity_preview/v1", "disabled"],
  ["v1-compatibility-partial", "tamandua.runtime_integrity_preview/v1", "partial"],
  ["v1-compatibility-mismatch", "tamandua.runtime_integrity_preview/v1", "mismatch"],
  ["v1-compatibility-degraded", "tamandua.runtime_integrity_preview/v1", "degraded"],
  ["v1-compatibility-unsupported", "tamandua.runtime_integrity_preview/v1", "unsupported"],
  ["v2-default-off-disabled", "tamandua.runtime_integrity_preview/v2", "disabled"],
  ["v2-release-4964-partial", "tamandua.runtime_integrity_preview/v2", "partial"],
  ["v2-release-4964-mismatch", "tamandua.runtime_integrity_preview/v2", "mismatch"],
  ["v2-release-4964-full-clean", "tamandua.runtime_integrity_preview/v2", "clean"],
  ["v2-unstable-identity-degraded", "tamandua.runtime_integrity_preview/v2", "degraded"],
  ["v2-partial-first-read-degraded", "tamandua.runtime_integrity_preview/v2", "degraded"],
  ["v2-eligible-8192-full-clean", "tamandua.runtime_integrity_preview/v2", "clean"],
  ["v2-full-progress-tick-budget-degraded", "tamandua.runtime_integrity_preview/v2", "degraded"],
  ["v2-capacity-degraded", "tamandua.runtime_integrity_preview/v2", "degraded"],
  ["v2-bootstrap-budget-degraded", "tamandua.runtime_integrity_preview/v2", "degraded"],
  ["v2-unsupported", "tamandua.runtime_integrity_preview/v2", "unsupported"],
];

function scenario(id) {
  return fixture.scenarios.find((candidate) => candidate.id === id).projection;
}

function validFixtureIdentity(candidate) {
  return (
    candidate !== null &&
    typeof candidate === "object" &&
    !Array.isArray(candidate) &&
    JSON.stringify(Object.keys(candidate).sort()) === JSON.stringify(expectedFixtureKeys) &&
    candidate.fixture_id === "runtime-integrity-preview-ui-contract-v2" &&
    candidate.evidence_class === "synthetic_smoke" &&
    candidate.external_claim_allowed === false &&
    Array.isArray(candidate.scenarios) &&
    candidate.scenarios.every(
      (item) =>
        item !== null &&
        typeof item === "object" &&
        !Array.isArray(item) &&
        JSON.stringify(Object.keys(item).sort()) === JSON.stringify(["id", "projection"]),
    ) &&
    JSON.stringify(
      candidate.scenarios.map((item) => [item.id, item.projection?.schema, item.projection?.status]),
    ) === JSON.stringify(expectedScenarios)
  );
}

assert.equal(typeof validate, "function");
assert.deepEqual(Object.keys(fixture).sort(), expectedFixtureKeys);
assert.equal(validFixtureIdentity(fixture), true);

const renamedFixture = structuredClone(fixture);
renamedFixture.scenarios[0].id = "renamed";
assert.equal(validFixtureIdentity(renamedFixture), false);
const swappedFixture = structuredClone(fixture);
[swappedFixture.scenarios[0], swappedFixture.scenarios[1]] = [
  swappedFixture.scenarios[1],
  swappedFixture.scenarios[0],
];
assert.equal(validFixtureIdentity(swappedFixture), false);
assert.equal(validFixtureIdentity({ ...fixture, extra: true }), false);

for (const item of fixture.scenarios) {
  assert.equal(validate(item.projection), true, `fixture rejected: ${item.id}`);
}

const v1 = structuredClone(scenario("v1-compatibility-clean"));
const disabled = structuredClone(scenario("v2-default-off-disabled"));
const partial = structuredClone(scenario("v2-release-4964-partial"));
const mismatch = structuredClone(scenario("v2-release-4964-mismatch"));
const clean = structuredClone(scenario("v2-release-4964-full-clean"));
const degradedAtFull = structuredClone(scenario("v2-full-progress-tick-budget-degraded"));
const capacity = structuredClone(scenario("v2-capacity-degraded"));
const bootstrap = structuredClone(scenario("v2-bootstrap-budget-degraded"));
const unstable = structuredClone(scenario("v2-unstable-identity-degraded"));
const firstRead = structuredClone(scenario("v2-partial-first-read-degraded"));
const capacityBoundary = structuredClone(scenario("v2-eligible-8192-full-clean"));

const invalidMutations = [
  { ...clean, external_claim_allowed: true },
  { ...clean, raw_evidence: "must-not-render" },
  { ...clean, collector_observed: true },
  { ...clean, path: "/proc/self/exe" },
  { ...clean, pid: 424242 },
  { ...clean, address: "0x7fff0000" },
  { ...clean, page_hash: "a".repeat(64) },
  { ...clean, observed_at: "pid=424242" },
  { ...clean, observed_at: "2026-02-29T12:00:00Z" },
  { ...clean, observed_at: "2026-02-31T12:00:00Z" },
  { ...clean, observed_at: "2026-13-01T12:00:00Z" },
  { ...clean, observed_at: "2026-07-17T24:00:00Z" },
  { ...clean, observed_at: "2026-07-17T12:60:00Z" },
  { ...clean, observed_at: "2026-07-17T12:00:60Z" },
  { ...clean, observed_at: "2026-07-17T12:00:00+24:00" },
  { ...clean, observed_at: "2026-07-17t12:00:00z" },
  { ...clean, observed_at: " 2026-07-17T12:00:00Z" },
  { ...clean, capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v1" },
  { ...clean, finding_kinds: ["unknown_finding"] },
  { ...clean, finding_kinds: ["file_backed_executable_page_drift"] },
  { ...mismatch, finding_kinds: [] },
  { ...partial, limitations: ["rx_page_content_anonymous_jit_out_of_scope", "rx_page_content_budget_exceeded"] },
  { ...partial, coverage: { ...partial.coverage, raw_bytes: "must-not-render" } },
  { ...partial, coverage: { ...partial.coverage, eligible_pages: 8193 } },
  { ...partial, coverage: { ...partial.coverage, pages_compared_this_tick: 9 } },
  { ...partial, coverage: { ...partial.coverage, sweep_pages_compared: 4965 } },
  { ...partial, coverage: { ...partial.coverage, memory_bytes_read_this_tick: 32768 } },
  { ...partial, coverage: { ...partial.coverage, full_sweep_completed: true } },
  { ...clean, coverage: { ...clean.coverage, sweep_pages_compared: 4963 } },
  { ...clean, coverage: { ...clean.coverage, unstable_pages_this_tick: 1 } },
  { ...degradedAtFull, coverage: { ...degradedAtFull.coverage, full_sweep_completed: false } },
  { ...degradedAtFull, limitations: ["rx_page_content_memory_read_unavailable"] },
  { ...degradedAtFull, coverage: { ...degradedAtFull.coverage, budget_state: "within_budget" } },
  { ...capacity, coverage: { ...capacity.coverage, eligible_pages: 8192 } },
  { ...capacity, coverage: { ...capacity.coverage, elapsed_us_this_tick: 1 } },
  { ...bootstrap, coverage: { ...bootstrap.coverage, sweep_pages_compared: 1 } },
  { ...unstable, coverage: { ...unstable.coverage, unstable_pages_this_tick: 0 } },
  { ...unstable, limitations: ["rx_page_content_memory_read_unavailable"] },
  { ...capacityBoundary, coverage: { ...capacityBoundary.coverage, eligible_pages: 8193 } },
  { ...disabled, coverage: { ...disabled.coverage, elapsed_us_this_tick: 1 } },
  { ...v1, schema: "tamandua.runtime_integrity_preview/v2" },
  { ...v1, coverage: { ...v1.coverage, sweep_pages_compared: 8 } },
  {
    ...v1,
    status: "degraded",
    runtime_state: "degraded",
    limitations: ["rx_page_content_bootstrap_budget_exceeded"],
    coverage: { ...v1.coverage, full_sweep_completed: false },
  },
];

for (const [index, projection] of invalidMutations.entries()) {
  assert.equal(validate(projection), false, `closed-contract mutation ${index} was accepted`);
}

assert.equal(validate({ ...clean, observed_at: "2024-02-29T23:59:59.123+02:30" }), true);

for (const boundary of [
  "tamandua.runtime_integrity_preview/v1",
  "tamandua.runtime_integrity_preview/v2",
  "Observe only · External claims disabled",
  "Not reported",
  "Unavailable / invalid",
  "No page-content drift observed",
  "Partial observation",
  "Drift observed",
  "Degraded",
  "Unsupported",
  "Default off",
  "Collector state:",
  "Accumulated progress",
  "Unavailable in v1",
  "Accumulated sweep progress",
  "Compared this tick",
  "Memory read this tick",
  "Bootstrap observation budget was exceeded",
  "Executable coverage exceeded the preview capacity",
  "hasExactKeys",
  "validCoverageV1",
  "validCoverageV2",
  "validStatusRelationsV1",
  "validStatusRelationsV2",
]) {
  assert.ok(source.includes(boundary), `missing display boundary: ${boundary}`);
}

assert.doesNotMatch(source, /JSON\.stringify\(preview/);
assert.doesNotMatch(source, /\b(?:compromised|blocked|prevented|detected threat)\b/i);
assert.doesNotMatch(source, /external_claim_allowed\s*===\s*true/);
assert.doesNotMatch(source, /collector_observed/);
assert.ok(agentDetail.includes("<RuntimeIntegrityPreviewPanel"));
assert.ok(agentDetail.includes("preview={runtime_integrity_preview}"));
assert.ok(agentDetail.includes("runtime_integrity_preview?: unknown"));
assert.doesNotMatch(agentDetail, /runtime_integrity_preview\s+as\s+/);

function render(preview) {
  return renderToStaticMarkup(React.createElement(Panel, { preview }));
}

const missingMarkup = render(undefined);
assert.match(missingMarkup, /<section[^>]+aria-labelledby="[^"]+"/);
assert.match(missingMarkup, /<h2[^>]+id="[^"]+"[^>]*>Runtime Integrity<\/h2>/);
assert.match(missingMarkup, /Preview/);
assert.match(missingMarkup, /Default off/);
assert.match(missingMarkup, /Observe only · External claims disabled/);
assert.match(missingMarkup, /role="status"/);
assert.match(missingMarkup, /Not reported/);

const invalidMarkup = render({ ...clean, raw_evidence: "must-not-render" });
assert.match(invalidMarkup, /Unavailable \/ invalid/);
assert.doesNotMatch(invalidMarkup, /must-not-render/);

const v1Markup = render(v1);
assert.match(v1Markup, /No page-content drift observed/);
assert.match(v1Markup, /Accumulated progress/);
assert.match(v1Markup, /Unavailable in v1/);
assert.doesNotMatch(v1Markup, /Accumulated sweep progress/);

const partialMarkup = render(partial);
assert.match(partialMarkup, /Partial observation/);
assert.match(partialMarkup, /4964/);
assert.match(partialMarkup, /2480 \/ 4964/);
assert.match(partialMarkup, /Compared this tick/);
assert.match(partialMarkup, /Memory read this tick/);
assert.match(partialMarkup, /Incomplete/);

const cleanMarkup = render(clean);
assert.match(cleanMarkup, /No page-content drift observed/);
assert.match(cleanMarkup, /4964 \/ 4964/);
assert.match(cleanMarkup, /Complete/);

const degradedAtFullMarkup = render(degradedAtFull);
assert.match(degradedAtFullMarkup, /Runtime integrity preview: Degraded/);
assert.match(degradedAtFullMarkup, /17 \/ 17/);
assert.match(degradedAtFullMarkup, /Complete/);
assert.match(degradedAtFullMarkup, /Tick observation budget was exceeded/);

assert.match(render(capacity), /Executable coverage exceeded the preview capacity/);
assert.match(render(bootstrap), /Bootstrap observation budget was exceeded/);
assert.match(render(unstable), /Artifact identity changed during observation/);
assert.match(render(firstRead), /Bounded memory read was unavailable/);
assert.match(render(firstRead), />4096</);
assert.match(render(capacityBoundary), /8192 \/ 8192/);

const signalMarkup = render(mismatch);
assert.match(signalMarkup, /File-backed executable page drift/);
assert.doesNotMatch(signalMarkup, /raw_evidence|\/proc\/self\/exe|424242|0x7fff|[a-f0-9]{64}/i);

console.log("runtime integrity preview panel dual-contract: ok");
