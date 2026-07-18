defmodule TamanduaServer.Alerts.DeduplicationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Deduplication
  alias TamanduaServer.Repo

  setup do
    if :ets.whereis(:alert_dedup_windows) != :undefined do
      :ets.delete_all_objects(:alert_dedup_windows)
    end

    :ok
  end

  test "generated hashes include organization_id" do
    org_a = insert(:organization)
    org_b = insert(:organization)

    attrs = %{
      title: "same alert",
      severity: "high",
      agent_id: Ecto.UUID.generate(),
      evidence: %{process: %{name: "same.exe"}}
    }

    hash_a = Deduplication.compute_dedup_hash(Map.put(attrs, :organization_id, org_a.id))
    hash_b = Deduplication.compute_dedup_hash(Map.put(attrs, :organization_id, org_b.id))

    refute hash_a == hash_b
  end

  test "ETS windows never deduplicate across tenants even for a caller-supplied key" do
    org_a = insert(:organization)
    org_b = insert(:organization)
    alert = insert(:alert, organization: org_a, agent: nil, dedup_key: "shared-key")

    attrs_a = alert_attrs(org_a.id, "shared-key")
    attrs_b = alert_attrs(org_b.id, "shared-key")

    assert :ok = Deduplication.register_new_alert("shared-key", alert.id, attrs_a)
    :sys.get_state(Deduplication)

    assert {:new, scoped_b} = Deduplication.check_and_deduplicate(attrs_b)
    assert scoped_b.organization_id == org_b.id

    assert {:duplicate, duplicate_id, 2} = Deduplication.check_and_deduplicate(attrs_a)
    assert duplicate_id == alert.id
    assert Repo.get!(TamanduaServer.Alerts.Alert, alert.id).occurrence_count == 2
  end

  test "database fallback after an ETS reset remains tenant-scoped" do
    org_a = insert(:organization)
    org_b = insert(:organization)
    alert = insert(:alert, organization: org_a, agent: nil, dedup_key: "restart-key")

    :ets.delete_all_objects(:alert_dedup_windows)

    assert {:new, _attrs} =
             Deduplication.check_and_deduplicate(alert_attrs(org_b.id, "restart-key"))

    assert {:duplicate, duplicate_id, 2} =
             Deduplication.check_and_deduplicate(alert_attrs(org_a.id, "restart-key"))

    assert duplicate_id == alert.id
    assert Repo.get!(TamanduaServer.Alerts.Alert, alert.id).occurrence_count == 2
  end

  test "a stale or poisoned ETS window cannot suppress an alert in another tenant" do
    org_a = insert(:organization)
    org_b = insert(:organization)
    alert = insert(:alert, organization: org_a, agent: nil, dedup_key: "poisoned-key")

    :ets.insert(
      :alert_dedup_windows,
      {{org_b.id, "poisoned-key"},
       %{
         alert_id: alert.id,
         first_at: System.system_time(:second),
         last_at: System.system_time(:second),
         count: 1,
         severity: "high",
         title: "poisoned"
       }}
    )

    assert {:new, _attrs} =
             Deduplication.check_and_deduplicate(alert_attrs(org_b.id, "poisoned-key"))

    assert Repo.get!(TamanduaServer.Alerts.Alert, alert.id).occurrence_count == 1
    assert [] == :ets.lookup(:alert_dedup_windows, {org_b.id, "poisoned-key"})
  end

  test "organization can be resolved from a known agent before hashing" do
    org = insert(:organization)
    agent = insert(:agent, organization: org)

    assert {:new, attrs} =
             Deduplication.check_and_deduplicate(%{
               title: "agent scoped alert",
               severity: "high",
               agent_id: agent.id
             })

    assert attrs.organization_id == org.id
    assert is_binary(attrs.dedup_key)
  end

  test "unscoped checks and public alert creation fail closed" do
    attrs = %{title: "unscoped alert", severity: "high"}

    assert {:error, :organization_id_required} = Deduplication.check_and_deduplicate(attrs)
    assert {:error, :organization_id_required} = Alerts.create_alert(attrs)
  end

  defp alert_attrs(organization_id, dedup_key) do
    %{
      organization_id: organization_id,
      title: "same alert",
      severity: "high",
      dedup_key: dedup_key
    }
  end
end
