defmodule TamanduaServer.Agents.PlatformCapabilitiesTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.PlatformCapabilities
  alias TamanduaServer.LiveResponse.ScreenCapturePolicy

  test "RX page-content is Linux Preview/lab only and requires an observation" do
    preview = %{
      schema: "tamandua.runtime_integrity_preview/v1",
      status: "clean"
    }

    linux =
      PlatformCapabilities.for_agent(%{os_type: "linux"},
        runtime_integrity_preview: preview
      )
      |> Enum.find(&(&1.id == "runtime_rx_page_content"))

    assert linux.maturity == "lab"
    assert linux.release_stage == "preview"
    assert linux.status == "lab"
    assert linux.observed == "observed"
    assert Enum.any?(linux.signals, &(&1.type == "preview_observation" and &1.value == "clean"))

    unobserved =
      PlatformCapabilities.for_agent(%{os_type: "linux"})
      |> Enum.find(&(&1.id == "runtime_rx_page_content"))

    assert unobserved.maturity == "lab"
    assert unobserved.status == "unavailable"
    assert unobserved.observed == "not_observed"

    expected = %{
      "disabled" => {"unavailable", "reported"},
      "partial" => {"lab", "observed"},
      "clean" => {"lab", "observed"},
      "mismatch" => {"lab", "observed"},
      "degraded" => {"partial", "observed"},
      "unsupported" => {"unavailable", "reported"}
    }

    for {page_status, {status, observed}} <- expected do
      capability =
        PlatformCapabilities.for_agent(%{os_type: "linux"},
          runtime_integrity_preview: %{preview | status: page_status}
        )
        |> Enum.find(&(&1.id == "runtime_rx_page_content"))

      assert capability.status == status
      assert capability.observed == observed
      assert capability.evidence.decision == observed
    end

    from_data_sources =
      PlatformCapabilities.for_agent(%{os_type: "linux"},
        data_sources: %{runtime_integrity_preview: preview}
      )
      |> Enum.find(&(&1.id == "runtime_rx_page_content"))

    assert from_data_sources.status == "lab"
    assert from_data_sources.observed == "observed"

    for os <- ~w(windows macos android ios unknown) do
      capability =
        PlatformCapabilities.for_agent(%{os_type: os}, runtime_integrity_preview: preview)
        |> Enum.find(&(&1.id == "runtime_rx_page_content"))

      assert capability.maturity == "unavailable"
      assert capability.status == "unavailable"
      assert capability.observed == "not_observed"
    end
  end

  test "RX page-content v2 remains Linux Preview/lab only and status-conservative" do
    expected = %{
      "disabled" => {"unavailable", "reported"},
      "partial" => {"lab", "observed"},
      "clean" => {"lab", "observed"},
      "mismatch" => {"lab", "observed"},
      "degraded" => {"partial", "observed"},
      "unsupported" => {"unavailable", "reported"}
    }

    for {page_status, {status, observed}} <- expected do
      capability =
        PlatformCapabilities.for_agent(%{os_type: "linux"},
          runtime_integrity_preview: %{
            schema: "tamandua.runtime_integrity_preview/v2",
            status: page_status
          }
        )
        |> Enum.find(&(&1.id == "runtime_rx_page_content"))

      assert capability.maturity == "lab"
      assert capability.release_stage == "preview"
      assert capability.status == status
      assert capability.observed == observed
    end

    for os <- ~w(windows macos android ios unknown) do
      capability =
        PlatformCapabilities.for_agent(%{os_type: os},
          runtime_integrity_preview: %{
            schema: "tamandua.runtime_integrity_preview/v2",
            status: "clean"
          }
        )
        |> Enum.find(&(&1.id == "runtime_rx_page_content"))

      assert capability.maturity == "unavailable"
      assert capability.status == "unavailable"
      assert capability.observed == "not_observed"
    end
  end

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
    assert endpoint.evidence.decision == "reported"
    assert Enum.any?(endpoint.signals, &(&1.type == "runtime_status" and &1.signal == "reported"))
    assert live_response.observed == "reported"
    assert live_response.status == "partial"
    assert kernel.observed == "not_observed"
    assert Enum.any?(kernel.signals, &(&1.type == "fallback" and &1.signal == "not_observed"))
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
    assert Enum.any?(endpoint.signals, &(&1.type == "fallback" and &1.signal == "not_observed"))
  end

  test "osquery query capability reports live response without claiming endpoint telemetry" do
    capabilities =
      PlatformCapabilities.for_agent(%{
        os_type: "linux",
        config: %{reported_capabilities: ["osquery_query"]}
      })

    endpoint = Enum.find(capabilities, &(&1.id == "endpoint_telemetry"))
    live_response = Enum.find(capabilities, &(&1.id == "live_response"))

    assert endpoint.observed == "not_observed"
    assert live_response.observed == "reported"

    assert Enum.any?(
             live_response.signals,
             &(&1.type == "reported_capability" and &1.value == "osquery_query")
           )
  end

  test "proxmox virtualization host remains linux lab and read-only observed contract" do
    capabilities =
      PlatformCapabilities.for_agent(%{os_type: "linux"},
        collectors: [%{name: "proxmox", status: "running"}],
        data_sources: %{"proxmox" => 3}
      )

    virtualization = Enum.find(capabilities, &(&1.id == "virtualization_host"))

    assert virtualization.platform == "linux"
    assert virtualization.maturity == "lab"
    assert virtualization.status == "lab"
    assert virtualization.observed == "observed"
    assert virtualization.evidence.decision == "observed"

    assert Enum.any?(
             virtualization.signals,
             &(&1.type == "data_source" and &1.source == "data_sources.proxmox" and
                 &1.value == 3)
           )
  end

  test "linux virtualization host can be reported from runtime capabilities" do
    capabilities =
      PlatformCapabilities.for_agent(%{
        os_type: "linux",
        config: %{reported_capabilities: ["virtualization-host"]}
      })

    virtualization = Enum.find(capabilities, &(&1.id == "virtualization_host"))

    assert virtualization.platform == "linux"
    assert virtualization.maturity == "lab"
    assert virtualization.status == "lab"
    assert virtualization.observed == "reported"

    assert Enum.any?(
             virtualization.signals,
             &(&1.type == "reported_capability" and &1.value == "virtualization_host")
           )
  end

  test "virtualization host is unavailable outside linux" do
    capabilities =
      PlatformCapabilities.for_agent(%{os_type: "windows"},
        config: %{reported_capabilities: ["virtualization_host"]},
        collectors: [%{name: "proxmox", status: "running"}],
        data_sources: %{"proxmox" => 3}
      )

    virtualization = Enum.find(capabilities, &(&1.id == "virtualization_host"))

    assert virtualization.platform == "windows"
    assert virtualization.maturity == "unavailable"
    assert virtualization.status == "unavailable"
    assert virtualization.observed == "not_observed"

    assert Enum.any?(
             virtualization.signals,
             &(&1.type == "platform_default" and &1.value == "unavailable")
           )
  end

  test "mobile app guard evidence includes reported mobile source without upgrading maturity" do
    capabilities =
      PlatformCapabilities.for_agent(%{
        os_type: "android",
        config: %{source: "tamandua_mobile", reported_capabilities: ["mobile_rasp"]}
      })

    app_guard = Enum.find(capabilities, &(&1.id == "app_guard"))

    assert app_guard.maturity == "partial"
    assert app_guard.status == "partial"
    assert app_guard.observed == "reported"
    assert app_guard.evidence.decision == "reported"

    assert Enum.any?(
             app_guard.signals,
             &(&1.type == "reported_capability" and &1.source == "config.source" and
                 &1.value == "tamandua_mobile")
           )

    assert Enum.any?(
             app_guard.signals,
             &(&1.type == "reported_capability" and &1.value == "mobile_rasp")
           )
  end

  test "mobile v2 source is treated as mobile even when os type is unknown" do
    capabilities =
      PlatformCapabilities.for_agent(%{
        os_type: "unknown",
        config: %{source: "tamandua_mobile_v2", reported_capabilities: ["mobile_rasp"]}
      })

    app_guard = Enum.find(capabilities, &(&1.id == "app_guard"))
    screen_capture = Enum.find(capabilities, &(&1.id == "screen_capture"))

    assert app_guard.maturity == "partial"
    assert app_guard.status == "partial"
    assert app_guard.observed == "reported"

    assert Enum.any?(
             app_guard.signals,
             &(&1.type == "reported_capability" and &1.source == "config.source" and
                 &1.value == "tamandua_mobile_v2")
           )

    assert screen_capture.maturity == "unavailable"
    assert screen_capture.status == "unavailable"
  end

  test "screen capture is a reported windows lab capability only when the agent advertises it" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    policy =
      ScreenCapturePolicy.normalize("agent-1", %{
        response: %{screen_capture: %{mode: "silent"}}
      })

    capabilities =
      PlatformCapabilities.for_agent(
        %{
          os_type: "windows",
          config: %{
            reported_capabilities: ["screen_capture"],
            screen_session_broker: %{
              state: "ready",
              capabilities: ["screen_capture"],
              observed_at: observed_at
            }
          }
        },
        screen_capture_policy: policy
      )

    screen_capture = Enum.find(capabilities, &(&1.id == "screen_capture"))

    assert screen_capture.maturity == "lab"
    assert screen_capture.status == "lab"
    assert screen_capture.observed == "reported"
    assert screen_capture.session_broker.state == "ready"
    assert screen_capture.session_broker.ready

    assert Enum.any?(
             screen_capture.signals,
             &(&1.type == "reported_capability" and &1.value == "screen_capture")
           )
  end

  test "screen capture fails closed for a windows agent that does not advertise it" do
    capabilities = PlatformCapabilities.for_agent(%{os_type: "windows", config: %{}})
    screen_capture = Enum.find(capabilities, &(&1.id == "screen_capture"))

    assert screen_capture.maturity == "lab"
    assert screen_capture.status == "unavailable"
    assert screen_capture.observed == "not_observed"
    assert screen_capture.session_broker.state == "broker_unavailable"
  end

  test "screen capture exposes a locked session broker without upgrading readiness" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    policy =
      ScreenCapturePolicy.normalize("agent-1", %{
        response: %{screen_capture: %{mode: "silent"}}
      })

    capabilities =
      PlatformCapabilities.for_agent(
        %{
          os_type: "windows",
          config: %{
            reported_capabilities: ["screen_capture"],
            session_broker: %{
              state: "locked",
              capabilities: ["screen_capture"],
              observed_at: observed_at
            }
          }
        },
        screen_capture_policy: policy
      )

    screen_capture = Enum.find(capabilities, &(&1.id == "screen_capture"))

    assert screen_capture.status == "unavailable"
    assert screen_capture.session_broker.state == "locked"
    refute screen_capture.session_broker.ready

    assert Enum.any?(
             screen_capture.signals,
             &(&1.type == "session_broker" and &1.value == "locked" and
                 &1.signal == "not_observed")
           )
  end

  test "screen capture remains explicitly unavailable on mobile" do
    capabilities =
      PlatformCapabilities.for_agent(%{
        os_type: "android",
        config: %{reported_capabilities: ["screen_capture"]}
      })

    screen_capture = Enum.find(capabilities, &(&1.id == "screen_capture"))

    assert screen_capture.maturity == "unavailable"
    assert screen_capture.status == "unavailable"
    assert screen_capture.observed == "reported"
  end
end
