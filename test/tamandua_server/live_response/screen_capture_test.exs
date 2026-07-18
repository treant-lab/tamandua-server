defmodule TamanduaServer.LiveResponse.ScreenCaptureTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.ScreenCapture

  test "requires a bounded operator reason and normalizes the safe defaults" do
    assert {:error, :reason_required} = ScreenCapture.validate_request(%{})

    assert {:error, :invalid_ttl_seconds} =
             ScreenCapture.validate_request(%{"reason" => "incident", "ttl_seconds" => 901})

    assert {:error, :invalid_display} =
             ScreenCapture.validate_request(%{"reason" => "incident", "display" => "primary"})

    assert {:ok, request} =
             ScreenCapture.validate_request(%{
               "reason" => "  Validate active compromise  ",
               "ttl_seconds" => "120",
               "display" => "virtual_desktop"
             })

    assert request == %{
             reason: "Validate active compromise",
             ttl_seconds: 120,
             display: "all",
             scope: "virtual_desktop",
             monitor_id: nil,
             watermark: false,
             redactions: [],
             continuous: false,
             input_control: false
           }
  end

  test "validates capture scopes, monitor ids, watermark, and bounded redactions" do
    assert {:ok, request} =
             ScreenCapture.validate_request(%{
               "reason" => "capture selected display",
               "scope" => "monitor",
               "monitor_id" => "display-2",
               "watermark" => false,
               "redactions" => [
                 %{"x" => 100, "y" => 200, "width" => 3_000, "height" => 4_000}
               ]
             })

    assert request.scope == "monitor"
    assert request.monitor_id == "display-2"
    assert request.watermark == false
    assert request.redactions == [%{x: 100, y: 200, width: 3_000, height: 4_000}]

    assert {:ok, atom_keyed_request} =
             ScreenCapture.validate_request(%{
               "reason" => "capture selected display",
               "redactions" => [
                 %{x: 100, y: 200, width: 3_000, height: 4_000}
               ]
             })

    assert atom_keyed_request.redactions == [%{x: 100, y: 200, width: 3_000, height: 4_000}]

    assert {:error, :invalid_monitor_id} =
             ScreenCapture.validate_request(%{
               "reason" => "capture",
               "scope" => "monitor"
             })

    assert {:error, :invalid_redactions} =
             ScreenCapture.validate_request(%{
               "reason" => "capture",
               "redactions" => [%{"x" => 9_000, "y" => 0, "width" => 2_000, "height" => 10}]
             })
  end

  test "requires an advertised capability and exposes platform consent" do
    assert %{state: "supported", consent_required: false} =
             ScreenCapture.capability_state("windows", ["screen_capture"])

    assert %{state: "consent_required", consent_required: true} =
             ScreenCapture.capability_state("macOS", [%{"name" => "screen.snapshot"}])

    assert %{
             state: "unsupported",
             unsupported_reason: "agent_did_not_report_screen_capture_capability"
           } = ScreenCapture.capability_state("windows", [])

    assert %{
             state: "consent_required",
             consent_required: true,
             consent_model: "user_initiated",
             capture_coverage: "current_tamandua_app_screen_single_frame",
             unsupported_reason: nil
           } = ScreenCapture.capability_state("ios", ["screen_capture"])

    assert %{
             state: "unsupported",
             unsupported_reason: "agent_did_not_report_screen_capture_capability"
           } = ScreenCapture.capability_state("ios", [])
  end

  test "response contract never enables stream/control or embeds an artifact" do
    response = ScreenCapture.response(%{status: "queued", capability_state: "supported"})

    assert response.schema_version == "tamandua.screen_capture/v1"
    assert response.command_type == "screen_capture"
    assert response.display == "all"
    assert response.scope == "virtual_desktop"
    assert response.watermark == false
    assert response.redaction_count == 0
    assert response.artifact == nil
    assert response.continuous == false
    assert response.input_control == false
    assert response.consent_model == nil
    assert response.capture_coverage == nil
  end
end
