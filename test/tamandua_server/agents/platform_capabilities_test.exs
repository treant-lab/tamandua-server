defmodule TamanduaServer.Agents.PlatformCapabilitiesTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.PlatformCapabilities

  test "online healthy runtime is reported without claiming observed telemetry" do
    agent = %{os_type: "windows", config: %{}}

    capabilities =
      PlatformCapabilities.for_agent(agent,
        status: "online",
        health: %{status: :healthy, metrics: %{heartbeat_age_ms: 1_000}}
      )

    endpoint = Enum.find(capabilities, &(&1.id == "endpoint_telemetry"))
    live_response = Enum.find(capabilities, &(&1.id == "live_response"))
    kernel = Enum.find(capabilities, &(&1.id == "kernel_sensor"))

    assert endpoint.observed == "reported"
    assert endpoint.status == "supported"
    assert live_response.observed == "reported"
    assert live_response.status == "partial"
    assert kernel.observed == "not_observed"
  end

  test "offline runtime remains not observed without telemetry or config evidence" do
    agent = %{os_type: "linux", config: %{}}

    capabilities =
      PlatformCapabilities.for_agent(agent,
        status: "offline",
        health: %{status: :unknown, reasons: [:offline]}
      )

    endpoint = Enum.find(capabilities, &(&1.id == "endpoint_telemetry"))
    live_response = Enum.find(capabilities, &(&1.id == "live_response"))

    assert endpoint.observed == "not_observed"
    assert live_response.observed == "not_observed"
  end
end
