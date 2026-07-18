defmodule TamanduaServer.LiveResponse.ScreenCapturePolicyTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.ScreenCapturePolicy

  test "missing and malformed policy fail closed to disabled" do
    assert %{mode: "disabled", notify_timing: nil, policy: %{source: "fail_closed_default"}} =
             ScreenCapturePolicy.normalize("agent-1", %{})

    assert %{mode: "disabled", policy: %{source: "fail_closed_default"}} =
             ScreenCapturePolicy.normalize("agent-1", %{
               response: %{screen_capture: %{mode: "notify"}}
             })
  end

  test "normalizes supported modes with non-secret effective policy evidence" do
    assert %{
             mode: "notify",
             notify_timing: "before_capture",
             allowed_scopes: ["virtual_desktop"],
             redaction_required: false,
             policy: %{
               id: "effective:agent-1",
               version: 1,
               source: "effective_agent_policy",
               hash: hash
             }
           } =
             ScreenCapturePolicy.normalize("agent-1", %{
               "response" => %{
                 "screen_capture" => %{
                   "mode" => "notify",
                   "notify_timing" => "before-capture"
                 }
               }
             })

    assert byte_size(hash) == 64

    canonical =
      "mode=notify;notify_timing=before_capture;allowed_scopes=virtual_desktop;redaction_required=false"

    assert hash == :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower)
  end

  test "does not carry notify timing into silent or consent modes" do
    assert %{mode: "silent", notify_timing: nil} =
             ScreenCapturePolicy.normalize("agent-1", %{
               response: %{screen_capture: %{mode: "silent"}}
             })

    assert %{mode: "consent_required", notify_timing: nil} =
             ScreenCapturePolicy.normalize("agent-1", %{
               response: %{screen_capture: %{mode: "consent_required"}}
             })
  end

  test "command evidence uses protocol field names and expires with request TTL" do
    policy =
      ScreenCapturePolicy.normalize("agent-1", %{
        response: %{screen_capture: %{mode: "silent"}}
      })
      |> ScreenCapturePolicy.for_command(120)

    assert %{
             id: "effective:agent-1",
             version: 1,
             mode: "silent",
             allowed_scopes: ["virtual_desktop"],
             redaction_required: false,
             hash: hash,
             issued_at_ms: issued_at_ms,
             expires_at_ms: expires_at_ms
           } = policy.policy

    assert byte_size(hash) == 64
    assert expires_at_ms - issued_at_ms == 120_000
    assert ScreenCapturePolicy.usable?(policy)

    expired = put_in(policy, [:policy, :expires_at_ms], issued_at_ms - 1)
    refute ScreenCapturePolicy.usable?(expired)
  end

  test "command evidence is capped by the effective policy freshness window" do
    policy =
      ScreenCapturePolicy.normalize("agent-1", %{
        response: %{screen_capture: %{mode: "notify", notify_timing: "after_capture"}}
      })
      |> ScreenCapturePolicy.for_command(900)

    assert policy.policy.expires_at_ms - policy.policy.issued_at_ms == 300_000
    assert policy.policy.notify_timing == "after_capture"
  end

  test "scope and redaction controls are normalized, sorted, and hash-bound" do
    policy =
      ScreenCapturePolicy.normalize("agent-1", %{
        response: %{
          screen_capture: %{
            mode: "consent_required",
            allowed_scopes: ["monitor", "virtual_desktop", "monitor"],
            redaction_required: true
          }
        }
      })

    assert policy.allowed_scopes == ["monitor", "virtual_desktop"]
    assert policy.redaction_required

    command = ScreenCapturePolicy.for_command(policy, 300)
    assert command.policy.allowed_scopes == ["monitor", "virtual_desktop"]
    assert command.policy.redaction_required

    assert command.policy.hash_algorithm ==
             "screen_capture_policy_hash_sha256_lexical_v2"

    assert %{mode: "disabled", policy: %{source: "fail_closed_default"}} =
             ScreenCapturePolicy.normalize("agent-1", %{
               response: %{screen_capture: %{mode: "silent", allowed_scopes: ["unknown"]}}
             })
  end

  test "policy-v2 uses ascending ASCII wire-token order for the cross-runtime vector" do
    canonical =
      "mode=silent;notify_timing=none;allowed_scopes=active_window,virtual_desktop;redaction_required=true"

    assert byte_size(canonical) == 99

    assert :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower) ==
             "feb822dec838c6655ea791ea9b5cfb87552e5fd233e995fe8cb0578d6b798d4c"

    policies =
      for scopes <- [
            ["virtual_desktop", "active_window"],
            ["active_window", "virtual_desktop", "active_window"]
          ] do
        ScreenCapturePolicy.normalize("agent-1", %{
          response: %{
            screen_capture: %{
              mode: "silent",
              allowed_scopes: scopes,
              redaction_required: true
            }
          }
        })
      end

    for policy <- policies do
      assert policy.allowed_scopes == ["active_window", "virtual_desktop"]

      assert policy.policy.hash ==
               "feb822dec838c6655ea791ea9b5cfb87552e5fd233e995fe8cb0578d6b798d4c"

      assert policy.policy.hash_algorithm ==
               "screen_capture_policy_hash_sha256_lexical_v2"

      refute policy.policy.hash ==
               "8558dc260906d9e0e7a782fa671bf00c30bd70fdb8c3bf6508308de6bec9b1d3"

      refute policy.policy.hash ==
               "699ca90ac1bda3c2ee510b006cbf473019f693da2eb32fde68f4d51aa5e49aa9"
    end
  end
end
