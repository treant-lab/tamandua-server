defmodule TamanduaServer.Detection.IOCConsumerTenantScopeSourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../../lib", __DIR__)

  test "runtime consumers use explicit tenant-aware IOC APIs" do
    scoped_consumers = [
      "tamandua_server/detection/dns_analyzer.ex",
      "tamandua_server/detection/phishing.ex",
      "tamandua_server/detection/phishing_triage.ex",
      "tamandua_server/telemetry/enrichment/cache.ex",
      "tamandua_server/telemetry/enrichment/threat_intel.ex",
      "tamandua_server/integrations/mcp_server.ex",
      "tamandua_server_web/controllers/api/v1/behavioral_controller.ex"
    ]

    Enum.each(scoped_consumers, fn relative_path ->
      source = File.read!(Path.join(@root, relative_path))

      refute source =~ ~r/IOCs\.lookup\s*\(/
      refute source =~ ~r/IOCs\.match\?\s*\(/
      refute source =~ ~r/IOCs\.match_batch\s*\(/
    end)
  end

  test "authenticated phishing controllers do not trust organization request parameters" do
    phishing =
      File.read!(
        Path.join(@root, "tamandua_server_web/controllers/api/v1/phishing_controller.ex")
      )

    email_security =
      File.read!(
        Path.join(
          @root,
          "tamandua_server_web/controllers/api/v1/email_security_controller.ex"
        )
      )

    refute phishing =~ ~r/organization_id:\s*params\["organization_id"\]/
    refute phishing =~ ~r/"organization_id"\s*=>\s*params\["organization_id"\]/
    refute email_security =~ ~r/organization_id:\s*params\["organization_id"\]/

    assert phishing =~ "conn.assigns[:current_organization_id]"
    assert email_security =~ "organization_id: conn.assigns[:current_organization_id]"
  end

  test "tenant-aware cache keys include organization identity" do
    cache =
      File.read!(Path.join(@root, "tamandua_server/telemetry/enrichment/cache.ex"))

    triage = File.read!(Path.join(@root, "tamandua_server/detection/phishing_triage.ex"))

    assert cache =~ "{:threat_intel, organization_id, ioc_type, ioc_value}"
    assert triage =~ "cache_key = {organization_id, url}"
  end
end
