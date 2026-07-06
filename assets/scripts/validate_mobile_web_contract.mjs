import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function readServer(relativePath) {
  return fs.readFileSync(path.join(root, '..', relativePath), 'utf8');
}

function requirePattern(name, content, pattern) {
  if (!pattern.test(content)) {
    return `${name}: missing ${pattern}`;
  }
  return null;
}

const agentDetail = read('src/pages/AgentDetail.tsx');
const agents = read('src/pages/Agents.tsx');
const liveResponse = read('src/pages/LiveResponse.tsx');
const mobileController = readServer(
  'lib/tamandua_server_web/controllers/api/v1/mobile_controller.ex'
);

const checks = [
  requirePattern(
    'AgentDetail',
    agentDetail,
    /const agentPlatform = resolveAgentPlatform\(agent\)/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /const mobileAgent = isMobilePlatform\(agentPlatform\)/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /fallbackPlatformCapabilities\(agentPlatform\)/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /raw\.platform[\s\S]*mobileDevice\.platform[\s\S]*device\.platform[\s\S]*posture\.platform/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /if \(!supportsHostResponse\)[\s\S]*Live response shell is not available/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /disabled=\{cliTokenLoading \|\| !supportsHostResponse\}/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /Mobile posture, app inventory, App Guard signals, and MDM-safe commands/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /command_device/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /\/api\/v1\/mobile\/v2\/commands/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /Command Sync/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /formatMobileRiskScore\(posture\.risk_score\)/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function formatMobileRiskScore[\s\S]*return 'Unknown'/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /command\.execution_scope === 'mdm_provider'/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /def get_config\(conn, _params\)[\s\S]*load_mobile_config\(organization_id\)/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /deep_merge_config\(default_mobile_config\(\), current \|\| %\{\}\)/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /execution_scope: "mobile_app_endpoint"[\s\S]*supported_by_mobile_app: true/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /execution_scope: "mdm_provider"[\s\S]*supported_by_mobile_app: false/
  ),
  requirePattern(
    'Agents',
    agents,
    /Host isolation unavailable for mobile endpoint/
  ),
  requirePattern(
    'Agents',
    agents,
    /Host network isolation is not available for mobile endpoints/
  ),
  requirePattern(
    'Agents',
    agents,
    /CompactMobileEndpointOverview/
  ),
  requirePattern(
    'Agents',
    agents,
    /appInventory\.total[\s\S]*appInventory\.high_risk[\s\S]*appInventory\.sideloaded[\s\S]*Compliance/
  ),
  requirePattern(
    'LiveResponse',
    liveResponse,
    /Live response shell is not available for mobile endpoints/
  ),
  requirePattern(
    'LiveResponse',
    liveResponse,
    /isMobileAgent\(agent\)/
  ),
].filter(Boolean);

if (checks.length) {
  console.error('Mobile web contract failed:');
  for (const check of checks) {
    console.error(`- ${check}`);
  }
  process.exit(1);
}

console.log('ok: mobile web contract');
