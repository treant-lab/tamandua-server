import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const componentRoot = path.resolve(directory, "..");
const source = fs.readFileSync(
  path.join(componentRoot, "TrustPosturePanel.tsx"),
  "utf8",
);
const agentDetail = fs.readFileSync(
  path.resolve(componentRoot, "..", "pages", "AgentDetail.tsx"),
  "utf8",
);
const storyline = fs.readFileSync(
  path.resolve(componentRoot, "..", "pages", "Storyline.tsx"),
  "utf8",
);
const fixture = JSON.parse(
  fs.readFileSync(
    path.resolve(componentRoot, "__fixtures__", "trust-posture.synthetic.json"),
    "utf8",
  ),
);

assert.equal(fixture.schema, "tamandua.trust_posture/v1");
assert.equal(fixture.evidence_type, "synthetic_contract");
assert.equal(fixture.external_claim_allowed, false);
assert.equal(fixture.history.recovery_observed, false);
assert.match(fixture.provenance.device_identity.device_id, /must-not-render/);
assert.match(
  fixture.provenance.runtime_integrity.raw_evidence,
  /must-not-render/,
);

for (const state of [
  "verified",
  "unverified",
  "degraded",
  "suspected_clone",
  "revoked",
]) {
  assert.match(source, new RegExp(`\\b${state}\\b`), `missing state ${state}`);
}

for (const boundary of [
  "Not evaluated",
  "No verified state has been inferred",
  "tamandua.trust_posture/v1",
  "External claims disabled or unavailable",
  "safeReasonCodes",
  "verifiedProjectionIsConsistent",
  "Trust evidence sources",
  "Trust posture transition",
]) {
  assert.ok(source.includes(boundary), `missing trust boundary: ${boundary}`);
}

assert.doesNotMatch(source, /\.device_id\b/);
assert.doesNotMatch(source, /\.raw_evidence\b/);
assert.doesNotMatch(source, /JSON\.stringify\(posture/);
assert.doesNotMatch(source, /Number\(value\)/);
assert.doesNotMatch(source, /humanize\(summary\.(?:status|freshness)\)/);
assert.doesNotMatch(source, /external_claim_allowed === true/);
assert.ok(agentDetail.includes("<TrustPosturePanel"));
assert.ok(agentDetail.includes("posture={trust_posture}"));
assert.doesNotMatch(agentDetail, /agent as Agent & \{ trust_posture/);
assert.ok(storyline.includes("<TrustPostureTransitionSummary"));
assert.ok(storyline.includes("trust_posture?: unknown"));

console.log("trust posture panel contract: ok");
