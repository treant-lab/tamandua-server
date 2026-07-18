defmodule TamanduaServerWeb.AIModelUIEmergencyBoundarySourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "legacy AI model LiveView routes are disabled while scoped REST routes remain" do
    router = read("lib/tamandua_server_web/router.ex")

    refute router =~ "AIModelsLive"
    assert router =~ ~s|get("/ai-security/models", AIModelController, :index)|
    assert router =~ ~s|post("/ai-security/models/:id/scan", AIModelController, :scan)|
    assert router =~
             ~s|post("/ai-security/models/:id/quarantine", AIModelController, :quarantine)|

    assert router =~ ~s|post("/ai-security/models/:id/block", AIModelController, :block)|
    assert router =~ ~s|delete("/ai-security/models/:id/block", AIModelController, :unblock)|
    assert router =~ ~s|post("/ai-security/models/:id/restore", AIModelController, :restore)|
  end

  test "demonstrated model UI points to the scoped Inertia surface" do
    dashboard = read("assets/src/pages/MLDashboard.tsx")
    shadow_ai = read("assets/src/pages/ShadowAI.tsx")

    assert dashboard =~ "{ label: 'AI Models', href: '/app/shadow-ai', icon: Brain }"
    refute dashboard =~ "{ label: 'AI Models', href: '/live/ai-security/models'"
    assert shadow_ai =~ "fetch('/api/v1/ai-security/models?type=model_file&limit=100'"

    assert shadow_ai =~
             "fetch(`/api/v1/ai-security/models/${encodeURIComponent(modelId)}/scan`"
  end

  test "Shadow AI page requires exact RBAC actor and organization scope" do
    source = read("lib/tamandua_server_web/controllers/inertia_controller.ex")
    slice = function_slice(source)

    assert slice =~ "authorize_or_render_inertia_page(conn, [:ai_investigate]"
    assert slice =~ "ResponseActor.from_user_scope("
    assert slice =~ "conn.assigns[:current_user]"
    assert slice =~ "conn.assigns[:current_organization_id]"
    assert slice =~ "AIInventory.list_inventory(organization_id, limit: 250)"
    refute slice =~ "current_user.organization_id"
    refute slice =~ "AIInventory.list_inventory(organization_id: organization_id"
  end

  test "organization-less AttackSurface and AIGateway reads stay unavailable" do
    source = read("lib/tamandua_server_web/controllers/inertia_controller.ex")
    slice = function_slice(source)

    assert slice =~ "shadow_ai_detections = []"
    assert slice =~ "ai_usage_events = []"
    assert slice =~ "gateway_usage_events = []"
    assert slice =~ ~s(status: "unavailable")
    assert slice =~ ~s(reason: "organization_scope_unavailable")
    refute slice =~ "AttackSurface.get_shadow_ai_detections"
    refute slice =~ "AttackSurface.get_recent_events"
    refute slice =~ "AttackSurface.analyze"
    refute slice =~ "AttackSurface.get_stats"
    refute slice =~ "AIGateway.list_usage"
    refute slice =~ "AIGateway.health"
    refute slice =~ "AIGateway.get_policy"
  end

  test "organization-less AI gateway reads and policy mutation fail closed" do
    router = read("lib/tamandua_server_web/router.ex")
    shadow_ai = read("assets/src/pages/ShadowAI.tsx")

    refute router =~ ~s|get("/ai-security/gateway/usage", AISecurityController, :gateway_usage)|
    refute router =~ ~s|get("/ai-security/gateway/health", AISecurityController, :gateway_health)|
    refute router =~ ~s|get("/ai-security/gateway/policy", AISecurityController, :gateway_policy)|

    refute router =~
             ~s|put("/ai-security/gateway/policy", AISecurityController, :update_gateway_policy)|

    refute shadow_ai =~ "fetch('/api/v1/ai-security/gateway/policy'"
    refute shadow_ai =~ "fetch('/api/v1/ai-security/gateway/evaluate'"
    assert shadow_ai =~ "Tenant-scoped policy mutation is unavailable"
    assert shadow_ai =~ "Tenant-scoped decision simulation is unavailable"
    assert shadow_ai =~ "Save unavailable"
  end

  defp function_slice(source) do
    [_before, from_shadow_ai] =
      String.split(source, "  def shadow_ai(conn, _params) do", parts: 2)

    [slice, _after] =
      String.split(from_shadow_ai, "  defp model_observations_for_inventory", parts: 2)

    slice
  end

  defp read(relative), do: File.read!(Path.join(@root, relative))
end
