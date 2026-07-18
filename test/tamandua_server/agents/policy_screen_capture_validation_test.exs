defmodule TamanduaServer.Agents.PolicyScreenCaptureValidationTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.Policy

  test "accepts screen_capture action and valid notify policy" do
    changeset =
      Policy.changeset(%Policy{}, %{
        name: "Remote assistance",
        organization_id: Ecto.UUID.generate(),
        policy_data:
          valid_policy(%{
            "mode" => "notify",
            "notify_timing" => "before_capture",
            "allowed_scopes" => ["virtual_desktop", "monitor"],
            "redaction_required" => true
          })
      })

    assert changeset.valid?
  end

  test "rejects missing, invalid, or misplaced notification modes" do
    invalid_configs = [
      %{"mode" => "unexpected"},
      %{"mode" => "notify"},
      %{"mode" => "silent", "notify_timing" => "before_capture"},
      %{"mode" => "silent", "allowed_scopes" => []},
      %{"mode" => "silent", "allowed_scopes" => ["unknown"]},
      %{"mode" => "silent", "redaction_required" => "yes"}
    ]

    for config <- invalid_configs do
      changeset =
        Policy.changeset(%Policy{}, %{
          name: "Invalid remote assistance",
          organization_id: Ecto.UUID.generate(),
          policy_data: valid_policy(config)
        })

      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :policy_data)
    end
  end

  defp valid_policy(screen_capture) do
    %{
      "response" => %{
        "allowed_actions" => ["screen_capture"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 10,
        "screen_capture" => screen_capture
      }
    }
  end
end
