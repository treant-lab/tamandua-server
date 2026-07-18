import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8')
}

function readServer(relativePath) {
  return fs.readFileSync(path.join(root, '..', relativePath), 'utf8')
}

function requirePattern(name, content, pattern) {
  if (!pattern.test(content)) {
    return `${name}: missing ${pattern}`
  }
  return null
}

const agentDetail = read('src/pages/AgentDetail.tsx')
const agents = read('src/pages/Agents.tsx')
const liveResponse = read('src/pages/LiveResponse.tsx')
const alertDetail = read('src/pages/AlertDetail.tsx')
const mobile = read('src/pages/Mobile.tsx')
const mobileController = readServer('lib/tamandua_server_web/controllers/api/v1/mobile_controller.ex')
const inertiaController = readServer('lib/tamandua_server_web/controllers/inertia_controller.ex')

const checks = [
  requirePattern('AgentDetail', agentDetail, /const agentPlatform = resolveAgentPlatform\(agent\)/),
  requirePattern('AgentDetail', agentDetail, /const mobileAgent = isMobilePlatform\(agentPlatform\)/),
  requirePattern('AgentDetail', agentDetail, /fallbackPlatformCapabilities\(agentPlatform\)/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /raw\.platform[\s\S]*mobileDevice\.platform[\s\S]*device\.platform[\s\S]*posture\.platform/
  ),
  requirePattern('AgentDetail', agentDetail, /if \(!supportsHostResponse\)[\s\S]*Live response shell is not available/),
  requirePattern('AgentDetail', agentDetail, /disabled=\{cliTokenLoading \|\| !supportsHostResponse\}/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /Mobile posture,[\s\S]*app inventory,[\s\S]*App Guard signals,[\s\S]*MDM-safe[\s\S]*commands/
  ),
  requirePattern('AgentDetail', agentDetail, /command_device/),
  requirePattern('AgentDetail', agentDetail, /command_identity/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function mobileCommandTargetId[\s\S]*command_identity\?\.command_device_id[\s\S]*command_device\?\.id[\s\S]*command_device\?\.device_id/
  ),
  requirePattern('AgentDetail', agentDetail, /const commandDeviceId = mobileCommandTargetId\(mobileOverview\)/),
  requirePattern('AgentDetail', agentDetail, /const linked = hasEffectiveMobileLink\(overview, device\)/),
  requirePattern('AgentDetail', agentDetail, /\/api\/v1\/mobile\/v2\/commands/),
  requirePattern('AgentDetail', agentDetail, /Command Sync/),
  requirePattern('AgentDetail', agentDetail, /Mobile Response/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /buildMobileResponseSummary[\s\S]*appCommandCount[\s\S]*mdmCommandCount[\s\S]*unsupportedCommandCount[\s\S]*reviewCommandCount/
  ),
  requirePattern('AgentDetail', agentDetail, /formatMobileRiskScore\(posture\.risk_score\)/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /Debugger[\s\S]*formatMobileDetection\(posture\.debugger_detected\)[\s\S]*Frida[\s\S]*formatMobileDetection\(posture\.frida_detected\)[\s\S]*Hook framework[\s\S]*runtime_memory_tamper_detected[\s\S]*tampering_detected[\s\S]*commercial_spyware_suspected[\s\S]*spyware_indicator_match/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function formatMobileDetection[\s\S]*return ["']Observed["'][\s\S]*return ["']Not observed["']/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function formatMobileCodeSignatureStatus[\s\S]*code_signature_drift_detected[\s\S]*Baseline not configured[\s\S]*No drift observed/
  ),
  requirePattern('AgentDetail', agentDetail, /function formatMobileRiskScore[\s\S]*return ["']Not reported["']/),
  requirePattern('AgentDetail', agentDetail, /function formatMobileBoolean[\s\S]*return ["']Not reported["']/),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function formatMobileCommandValue[\s\S]*normalized === ["']none["'][\s\S]*normalized === ["']unknown["'][\s\S]*return ["']Not reported["']/
  ),
  requirePattern('AgentDetail', agentDetail, /formatMobileCommandScope\(command\.execution_scope\)/),
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
    'MobileController',
    mobileController,
    /id: "wipe"[\s\S]*command_risk: "destructive_device_action"[\s\S]*Auditable operator approval for destructive actions/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /id: "remove_app"[\s\S]*command_risk: "privileged_device_action"[\s\S]*Auditable operator approval for destructive actions/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /id: "inspect_package"[\s\S]*command_risk: "package_inspection"[\s\S]*Declared package visibility scope for target package/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /id: "sync_app_inventory"[\s\S]*execution_scope: "mobile_app_endpoint"[\s\S]*supported_by_mobile_app: true[\s\S]*Fallback mode reports current app or cached posture only/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /id: "inspect_package"[\s\S]*execution_scope: "mobile_app_endpoint"[\s\S]*supported_by_mobile_app: true[\s\S]*Fallback mode can only inspect current app or cached posture entries/
  ),
  requirePattern('Agents', agents, /Host isolation unavailable for mobile endpoint/),
  requirePattern('Agents', agents, /Host network isolation is not available for mobile endpoints/),
  requirePattern('Agents', agents, /mobileProjectionSummary\?: MobileProjectionSummary/),
  requirePattern('Agents', agents, /MobileProjectionGapDevice/),
  requirePattern('Agents', agents, /mobileProjectionGapCount > 0/),
  requirePattern('Agents', agents, /Mobile projection gap/),
  requirePattern('Agents', agents, /enrolled mobile device[\s\S]*without an Agent projection/),
  requirePattern('Agents', agents, /agent\?\.projection_gap[\s\S]*setAgentDetails/),
  requirePattern('Agents', agents, /Mobile endpoint awaiting Agent projection/),
  requirePattern('Agents', agents, /This row is a diagnostic fallback from DeviceV2/),
  requirePattern('Agents', agents, /function ProjectionGapField/),
  requirePattern('Agents', agents, /agent\.projection_gap \?[\s\S]*Projection gap/),
  requirePattern('Agents', agents, /CompactMobileEndpointOverview/),
  requirePattern(
    'Agents',
    agents,
    /appInventory\.total[\s\S]*appInventory\.high_risk[\s\S]*appInventory\.sideloaded[\s\S]*Compliance/
  ),
  requirePattern('Agents', agents, /Command Device[\s\S]*Response Scope[\s\S]*Last Command/),
  requirePattern('Agents', agents, /label=["']Risk["'][\s\S]*Not reported/),
  requirePattern('Agents', agents, /countMobileHardeningFindings\(posture, device\)[\s\S]*label=["']Hardening["']/),
  requirePattern('Agents', agents, /function formatCompactValue[\s\S]*return ["']Not reported["']/),
  requirePattern('Agents', agents, /label=["']Signature baseline["'][\s\S]*formatMobileSignatureBaseline\(posture, device\)/),
  requirePattern(
    'Agents',
    agents,
    /function countMobileHardeningFindings[\s\S]*debugger_detected[\s\S]*frida_detected[\s\S]*hook_framework_detected[\s\S]*native_hook_detected[\s\S]*app_integrity_violation[\s\S]*runtime_memory_tamper_detected[\s\S]*code_signature_drift_detected[\s\S]*tampering_detected[\s\S]*commercial_spyware_suspected[\s\S]*spyware_indicator_match/
  ),
  requirePattern(
    'Agents',
    agents,
    /function formatMobileSignatureBaseline[\s\S]*code_signature_drift_detected[\s\S]*code_signature_baseline_configured[\s\S]*not configured[\s\S]*configured/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /label=["']Hook framework["'][\s\S]*formatMobileDetection\(posture\.hook_framework_detected\)[\s\S]*label=["']Native hook["'][\s\S]*formatMobileDetection\(posture\.native_hook_detected\)[\s\S]*label=["']App integrity["'][\s\S]*formatMobileDetection\(posture\.app_integrity_violation\)[\s\S]*label=["']Runtime tamper["'][\s\S]*formatMobileDetection\(posture\.runtime_memory_tamper_detected\)[\s\S]*label=["']Code signature["'][\s\S]*formatMobileCodeSignatureStatus\(posture\)[\s\S]*label=["']Policy store["'][\s\S]*formatMobilePolicyStore\(posture\.policy\)/
  ),
  requirePattern(
    'AgentDetail',
    agentDetail,
    /function formatMobilePolicyStore[\s\S]*No policy reported[\s\S]*no_durable_local_policy_store[\s\S]*not_stored[\s\S]*not enforced/
  ),
  requirePattern(
    'Agents',
    agents,
    /formatMobileCommandDevice[\s\S]*formatMobileResponseScope[\s\S]*formatMobileLastCommand/
  ),
  requirePattern('Agents', agents, /command_identity/),
  requirePattern(
    'Agents',
    agents,
    /function formatMobileCommandDevice[\s\S]*commandIdentity\.command_device_id[\s\S]*commandIdentity\.background_sync_device_id[\s\S]*commandIdentity\.external_device_id/
  ),
  requirePattern(
    'Agents',
    agents,
    /const hasEffectiveLink = Boolean[\s\S]*commandIdentity\.command_device_id[\s\S]*commandDevice\.id[\s\S]*commandIdentity\.background_sync_device_id[\s\S]*overview\?\.linked === false && !hasEffectiveLink/
  ),
  requirePattern(
    'Agents',
    agents,
    /function formatMobileResponseScope[\s\S]*liveResponse[\s\S]*commandIdentity\.command_device_id/
  ),
  requirePattern('Agents', agents, /function formatMobileLastCommand[\s\S]*value !== ["']Not reported["']/),
  requirePattern(
    'Agents',
    agents,
    /android:[\s\S]*live_response: ["']partial["'][\s\S]*screen_capture: ["']partial["']/
  ),
  requirePattern('Agents', agents, /ios:[\s\S]*live_response: ["']partial["'][\s\S]*screen_capture: ["']partial["']/),
  requirePattern(
    'Agents',
    agents,
    /function formatMobileEndpointState[\s\S]*overview\?\.agent_status[\s\S]*overview\?\.agent_version/
  ),
  requirePattern(
    'LiveResponse',
    liveResponse,
    /Mobile managed shell and response commands are available from the mobile endpoint panel/
  ),
  requirePattern('LiveResponse', liveResponse, /isMobileAgent\(agent\)/),
  requirePattern(
    'LiveResponse',
    liveResponse,
    /function mobileOverviewCommandDeviceId[\s\S]*command_identity\?\.command_device_id[\s\S]*command_device\?\.id[\s\S]*command_identity\?\.background_sync_device_id/
  ),
  requirePattern(
    'LiveResponse',
    liveResponse,
    /let commandDeviceId = mobileOverviewCommandDeviceId\(currentOverview\)/
  ),
  requirePattern(
    'AlertDetail',
    alertDetail,
    /function resolveMobileCommandDeviceId[\s\S]*commandIdentity\.command_device_id[\s\S]*commandDevice\.id[\s\S]*commandIdentity\.background_sync_device_id/
  ),
  requirePattern('AlertDetail', alertDetail, /commandDeviceId: resolveMobileCommandDeviceId\(data\)/),
  requirePattern('Mobile', mobile, /apiFetchOptional<MobileV2Stats>\('\/api\/v1\/mobile\/v2\/stats'\)/),
  requirePattern('Mobile', mobile, /apiFetchOptional<MobileV2Posture>\('\/api\/v1\/mobile\/v2\/posture'\)/),
  requirePattern(
    'Mobile',
    mobile,
    /apiFetchEnvelopeOptional<MobileDevicesResponse>\('\/api\/v1\/mobile\/v2\/devices\?limit=200'\)/
  ),
  requirePattern('Mobile', mobile, /\/api\/v1\/mobile\/v2\/events\?limit=100&hours=72/),
  requirePattern(
    'Mobile',
    mobile,
    /res\.status === 404 \|\| res\.status === 501[\s\S]*\/api\/v1\/mobile\/events\?limit=100&hours=72/
  ),
  requirePattern('MobileController', mobileController, /def events_v2\(conn, params\), do: events\(conn, params\)/),
  requirePattern(
    'Mobile',
    mobile,
    /normalizeV2Stats\(v2Stats\)[\s\S]*normalizedV2Stats\.total >= \(legacyStats\?\.total \|\| 0\)/
  ),
  requirePattern('MobileController', mobileController, /jailbroken: jailbroken/),
  requirePattern(
    'MobileController',
    mobileController,
    /mobile_v2_posture_summary\(%DeviceV2\{\} = device, %Agent\{\} = agent\)[\s\S]*security_checks[\s\S]*debugger_detected[\s\S]*frida_detected[\s\S]*hook_framework_detected[\s\S]*native_hook_detected[\s\S]*app_integrity_violation[\s\S]*runtime_memory_tamper_detected[\s\S]*code_signature_drift_detected[\s\S]*code_signature_baseline_configured[\s\S]*tampering_detected/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /mobile_endpoint_posture_sync_config[\s\S]*security_checks[\s\S]*hardening[\s\S]*risk_score[\s\S]*last_assessment/
  ),
  requirePattern('MobileController', mobileController, /stale_24h: stale_24h/),
  requirePattern('Mobile', mobile, /legacyPosture \|\| normalizeV2Posture\(v2Posture, statsData\)/),
  requirePattern('Mobile', mobile, /mergeDevices\(v2Devices, legacyDevices\)/),
  requirePattern(
    'Mobile',
    mobile,
    /const stableDeviceId =[\s\S]*device\.device_id[\s\S]*device\.id[\s\S]*device\.agent_id/
  ),
  requirePattern(
    'Mobile',
    mobile,
    /const key = device\.device_id \|\| device\.id \|\| `\$\{device\.platform \|\| 'mobile'\}:\$\{device\.model \|\| 'device'\}:\$\{index\}`/
  ),
  requirePattern(
    'MobileController',
    mobileController,
    /id: "managed_shell"[\s\S]*id: "shell_execute"[\s\S]*id: "screen_capture"[\s\S]*id: "dns_status"[\s\S]*id: "block_domain"[\s\S]*id: "network_status"[\s\S]*id: "sync_app_inventory"[\s\S]*id: "inspect_package"/
  ),
  requirePattern('InertiaController', inertiaController, /mobileProjectionSummary: mobile_projection_summary\(org_id\)/),
  requirePattern('InertiaController', inertiaController, /agents \+\+ mobile_projection_gap_agents\(org_id, agents\)/),
  requirePattern('InertiaController', inertiaController, /defp mobile_projection_gap_agent\(device\)/),
  requirePattern('InertiaController', inertiaController, /projection_gap_reason: "mobile_device_v2_without_agent_projection"/),
  requirePattern('InertiaController', inertiaController, /Map\.get\(agent, :status\) in \[:degraded, "degraded"\]/),
  requirePattern(
    'InertiaController',
    inertiaController,
    /defp mobile_projection_summary\(org_id\)[\s\S]*DeviceV2[\s\S]*left_join: a in Agent[\s\S]*projection_gap_count[\s\S]*unprojected_devices/
  ),
  requirePattern(
    'InertiaController',
    inertiaController,
    /Mobile projection summary is diagnostic only[\s\S]*DeviceV2 to Agent projection exists/
  )
].filter(Boolean)

if (checks.length) {
  console.error('Mobile web contract failed:')
  for (const check of checks) {
    console.error(`- ${check}`)
  }
  process.exit(1)
}

console.log('ok: mobile web contract')
