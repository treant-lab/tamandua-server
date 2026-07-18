defmodule TamanduaServer.Repo.DecisionEngineAuthorityAccessTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.DecisionEngineAuthorityAccess

  defmodule StubRepo do
    def enabled?, do: true
    def transaction(callback), do: {:ok, callback.()}
    def rollback(reason), do: throw({:rollback, reason})

    def query("SET LOCAL ROLE " <> _role), do: {:ok, %{rows: []}}
    def query(_preflight, [_role, _capability, _owner, _signatures]), do: {:ok, %{rows: [[true]]}}

    def query("SELECT organization_id FROM " <> _function, [cursor, _limit]) do
      rows = Process.get(:decision_engine_authority_rows, %{}) |> Map.get(cursor, [])
      {:ok, %{rows: Enum.map(rows, &[&1])}}
    end
  end

  setup do
    previous_repo =
      Application.get_env(:tamandua_server, :decision_engine_authority_repo)

    previous_role =
      Application.get_env(:tamandua_server, :decision_engine_authority_database_role)

    Application.put_env(:tamandua_server, :decision_engine_authority_repo, StubRepo)
    Application.put_env(:tamandua_server, :decision_engine_authority_database_role, "de_test")

    on_exit(fn ->
      restore_env(:decision_engine_authority_repo, previous_repo)
      restore_env(:decision_engine_authority_database_role, previous_role)
    end)

    :ok
  end

  test "accepts a canonical ordered UUID-only page" do
    Process.put(:decision_engine_authority_rows, %{
      nil => [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002"
      ]
    })

    assert {:ok,
            [
              "00000000-0000-4000-8000-000000000001",
              "00000000-0000-4000-8000-000000000002"
            ]} = DecisionEngineAuthorityAccess.discover_restore_organization_ids()
  end

  test "fails closed on malformed, duplicate, or out-of-order rows" do
    for rows <- [
          ["not-a-uuid"],
          [
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000001"
          ],
          [
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000001"
          ]
        ] do
      Process.put(:decision_engine_authority_rows, %{nil => rows})

      assert {:error, :persistence_unavailable} =
               DecisionEngineAuthorityAccess.discover_maintenance_organization_ids()
    end
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
