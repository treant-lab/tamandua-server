defmodule TamanduaServer.Agents.PolicyCollectorValidationTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.Policy

  @org_id Ecto.UUID.generate()

  test "accepts full collector policy surface and performance profile" do
    changeset =
      Policy.changeset(%Policy{}, %{
        name: "High value asset",
        organization_id: @org_id,
        policy_data: %{
          "profile" => "high_value_asset",
          "collectors" => %{
            "process" => %{"enabled" => true, "interval_ms" => 3_000},
            "network_dpi" => %{"enabled" => true, "interval_ms" => 5_000, "sample_rate" => 0.5},
            "credential_theft" => %{"enabled" => true, "priority" => "high"},
            "kernel_events" => %{"enabled" => true, "interval_ms" => 1_000},
            "ebpf" => %{"enabled" => true, "interval_ms" => 1_000},
            "tcc_monitor" => %{"enabled" => true, "interval_ms" => 30_000}
          }
        }
      })

    assert changeset.valid?
  end

  test "rejects unknown collectors and invalid profile" do
    changeset =
      Policy.changeset(%Policy{}, %{
        name: "Bad policy",
        organization_id: @org_id,
        policy_data: %{
          "profile" => "maximum_magic",
          "collectors" => %{
            "made_up_collector" => %{"enabled" => true, "interval_ms" => 1_000}
          }
        }
      })

    refute changeset.valid?

    messages =
      changeset.errors[:policy_data]
      |> Enum.map(fn {message, _opts} -> message end)

    assert "invalid performance profile: maximum_magic" in messages
    assert "invalid collector: made_up_collector" in messages
  end
end
