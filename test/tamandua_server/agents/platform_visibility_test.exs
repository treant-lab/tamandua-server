defmodule TamanduaServer.Agents.PlatformVisibilityTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.{PlatformCapabilities, PlatformVisibility}

  test "active when platform capability evidence is observed from existing sources" do
    capabilities =
      PlatformCapabilities.for_agent(%{os_type: "windows"},
        data_sources: %{"process" => 4},
        last_observed_at: ~U[2026-07-15 12:00:00Z]
      )

    visibility =
      PlatformVisibility.summarize(%{os_type: "windows"},
        capabilities: capabilities,
        last_telemetry_at: ~U[2026-07-15 12:00:00Z]
      )

    assert visibility.status == "active"
    assert visibility.platform == "windows"
    assert visibility.source == "platform_capabilities"
    assert visibility.evidence.last_observed_at == "2026-07-15T12:00:00Z"
    assert "endpoint_telemetry" in visibility.evidence.observed_capabilities
    assert "observed_platform_visibility" in visibility.reasons
  end

  test "degraded when runtime only reports visibility without observed telemetry" do
    capabilities =
      PlatformCapabilities.for_agent(%{os_type: "linux"},
        status: "online",
        health: %{status: :healthy}
      )

    visibility =
      PlatformVisibility.summarize(%{os_type: "linux"},
        capabilities: capabilities,
        last_heartbeat_at: ~U[2026-07-15 12:00:00Z]
      )

    assert visibility.status == "degraded"
    assert visibility.evidence.last_observed_at == "2026-07-15T12:00:00Z"
    assert "endpoint_telemetry" in visibility.evidence.reported_capabilities
    assert "reported_without_observed_telemetry" in visibility.reasons
  end

  test "unavailable when platform capabilities are all unavailable" do
    capabilities = [
      %{
        id: "mobile_posture",
        platform: "windows",
        maturity: "unavailable",
        status: "unavailable",
        observed: "not_observed",
        signals: []
      }
    ]

    visibility = PlatformVisibility.summarize(%{os_type: "windows"}, capabilities: capabilities)

    assert visibility.status == "unavailable"
    assert visibility.evidence.last_observed_at == nil
    assert visibility.reasons == ["platform_unavailable"]
  end
end
