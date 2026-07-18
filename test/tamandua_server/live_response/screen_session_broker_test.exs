defmodule TamanduaServer.LiveResponse.ScreenSessionBrokerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.ScreenSessionBroker

  test "fails closed when broker health is absent or invalid" do
    assert %{state: "broker_unavailable", ready: false, capabilities: []} =
             ScreenSessionBroker.status(:windows, %{})

    assert %{state: "broker_unavailable", ready: false} =
             ScreenSessionBroker.status(:windows, %{
               screen_session_broker: %{state: "unexpected", capabilities: ["screen_capture"]}
             })
  end

  test "ready requires an explicit screen capture broker capability" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    assert %{state: "broker_unavailable", ready: false} =
             ScreenSessionBroker.status(:windows, %{
               screen_session_broker: %{state: "ready", capabilities: []}
             })

    assert %{
             schema_version: "tamandua.screen_session_broker/v1",
             state: "ready",
             ready: true,
             capabilities: ["screen_capture"],
             observed_at: ^observed_at,
             displays: [
               %{id: "display-1", x: 0, y: 0, width: 1920, height: 1080, primary: true}
             ]
           } =
             ScreenSessionBroker.status(:windows, %{
               screen_session_broker: %{
                 state: "ready",
                 capabilities: ["screen-capture"],
                 observed_at: observed_at,
                 displays: [
                   %{
                     id: "display-1",
                     x: 0,
                     y: 0,
                     width: 1920,
                     height: 1080,
                     primary: true,
                     ignored: "not persisted"
                   }
                 ]
               }
             })
  end

  test "preserves every explicit non-ready state without optimistic fallback" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    for state <-
          ~w(no_user_session locked consent_required permission_denied portal_unavailable broker_unavailable unsupported) do
      assert %{state: ^state, ready: false} =
               ScreenSessionBroker.status(:windows, %{
                 session_broker: %{
                   status: state,
                   capabilities: %{screen_capture: true},
                   observed_at: observed_at
                 }
               })
    end
  end

  test "platforms preserve their native transport and consent model" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    assert %{
             platform: "macos",
             state: "ready",
             ready: true,
             transport: "unix_socket",
             consent_model: "os_permission"
           } =
             ScreenSessionBroker.status(:macos, %{
               screen_session_broker: %{
                 state: "ready",
                 capabilities: ["screen_capture"],
                 observed_at: observed_at
               }
             })

    assert %{
             platform: "linux",
             state: "consent_required",
             ready: false,
             transport: "xdg_desktop_portal",
             consent_model: "portal_prompt"
           } =
             ScreenSessionBroker.status(:linux, %{
               screen_session_broker: %{
                 state: "consent_required",
                 capabilities: ["screen_capture"],
                 observed_at: observed_at
               }
             })

    assert %{
             platform: "ios",
             state: "consent_required",
             ready: false,
             transport: "ios_app_command",
             consent_model: "user_initiated"
           } =
             ScreenSessionBroker.status(:ios, %{
               screen_session_broker: %{
                 state: "consent_required",
                 capabilities: ["screen_capture"],
                 observed_at: observed_at,
                 transport: "ios_app_command",
                 consent_model: "user_initiated"
               }
             })

    assert %{
             platform: "android",
             state: "consent_required",
             ready: false,
             transport: "android_app_command",
             consent_model: "user_prompt"
           } =
             ScreenSessionBroker.status(:android, %{
               screen_session_broker: %{
                 state: "consent_required",
                 capabilities: ["screen_capture", "watermark", "redaction"],
                 observed_at: observed_at,
                 transport: "android_app_command",
                 consent_model: "user_prompt"
               }
             })
  end

  test "invalid, missing, future, and stale observations fail closed" do
    fresh_config = fn observed_at ->
      %{
        screen_session_broker: %{
          state: "ready",
          capabilities: ["screen_capture"],
          observed_at: observed_at
        }
      }
    end

    stale = DateTime.add(DateTime.utc_now(), -301, :second) |> DateTime.to_iso8601()
    future = DateTime.add(DateTime.utc_now(), 61, :second) |> DateTime.to_iso8601()

    for config <- [
          fresh_config.(stale),
          fresh_config.(future),
          fresh_config.("invalid"),
          fresh_config.(nil)
        ] do
      assert %{state: "broker_unavailable", ready: false} =
               ScreenSessionBroker.status(:windows, config)
    end
  end

  test "silent and bounded-session support are explicit and fail closed" do
    observed_at = DateTime.utc_now() |> DateTime.to_iso8601()

    assert %{
             silent_supported: true,
             session_capture_supported: true,
             degraded_reason: nil,
             unsupported_reason: nil
           } =
             ScreenSessionBroker.status(:windows, %{
               screen_session_broker: %{
                 state: "ready",
                 capabilities: ["screen_capture"],
                 observed_at: observed_at,
                 silent_supported: true,
                 session_capture_supported: true
               }
             })

    assert %{
             silent_supported: false,
             session_capture_supported: true,
             degraded_reason: "portal_prompt_required"
           } =
             ScreenSessionBroker.status(:linux, %{
               screen_session_broker: %{
                 state: "consent_required",
                 capabilities: ["screen_capture"],
                 observed_at: observed_at,
                 silent_supported: true,
                 session_capture_supported: true,
                 degraded_reason: "portal_prompt_required"
               }
             })
  end
end
