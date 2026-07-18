defmodule TamanduaServer.Repo.AgenticRestoreAuthorityAccessTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AgenticRestoreAuthorityAccess

  defmodule RepoStub do
    def enabled?, do: true

    def transaction(fun) do
      try do
        {:ok, fun.()}
      catch
        {:rollback, reason} -> {:error, reason}
      end
    end

    def rollback(reason), do: throw({:rollback, reason})

    def query("SET LOCAL ROLE " <> _role), do: {:ok, %{rows: []}}

    def query("SELECT organization_id FROM public.authority_agentic_restore_v1" <> _, [1, _limit]) do
      {:ok, %{rows: Process.get(:agentic_restore_authority_rows, [])}}
    end

    def query(_preflight, [_login, _executor, _owner, _signature]) do
      if Process.get(:agentic_restore_authority_preflight_failure, false),
        do: {:ok, %{rows: [[false]]}},
        else: {:ok, %{rows: [[true]]}}
    end
  end

  setup do
    previous_repo = Application.get_env(:tamandua_server, :agentic_restore_authority_repo)

    previous_role =
      Application.get_env(:tamandua_server, :agentic_restore_authority_database_role)

    Application.put_env(:tamandua_server, :agentic_restore_authority_repo, RepoStub)

    Application.put_env(
      :tamandua_server,
      :agentic_restore_authority_database_role,
      "agentic_restore_login"
    )

    on_exit(fn ->
      Process.delete(:agentic_restore_authority_rows)
      Process.delete(:agentic_restore_authority_preflight_failure)
      restore_env(:agentic_restore_authority_repo, previous_repo)
      restore_env(:agentic_restore_authority_database_role, previous_role)
    end)

    :ok
  end

  test "returns UUIDs only and preserves limit plus one truncation" do
    ids = for _ <- 1..3, do: Ecto.UUID.generate()
    Process.put(:agentic_restore_authority_rows, Enum.map(ids, &[&1]))

    assert {:ok, returned, %{truncated: true}} =
             AgenticRestoreAuthorityAccess.discover_non_terminal_organization_ids(1, 2)

    assert returned == Enum.take(ids, 2)
  end

  test "normalizes the raw 16-byte UUID representation returned by Postgrex" do
    uuid = Ecto.UUID.generate()
    assert {:ok, raw_uuid} = Ecto.UUID.dump(uuid)
    Process.put(:agentic_restore_authority_rows, [[raw_uuid]])

    assert {:ok, [^uuid], %{truncated: false}} =
             AgenticRestoreAuthorityAccess.discover_non_terminal_organization_ids(1, 1)
  end

  test "malformed, duplicate, and over-limit results fail closed" do
    uuid = Ecto.UUID.generate()

    for rows <- [
          [["not-a-uuid"]],
          [[uuid], [uuid]],
          Enum.map(1..3, fn _ -> [Ecto.UUID.generate()] end),
          [[uuid, "unexpected"]]
        ] do
      Process.put(:agentic_restore_authority_rows, rows)

      assert {:error, :persistence_unavailable} =
               AgenticRestoreAuthorityAccess.discover_non_terminal_organization_ids(1, 1)
    end
  end

  test "rejects unsupported snapshot versions and limits" do
    for {version, limit} <- [{2, 1}, {1, 0}, {1, 501}, {1, "10"}] do
      assert {:error, :persistence_unavailable} =
               AgenticRestoreAuthorityAccess.discover_non_terminal_organization_ids(
                 version,
                 limit
               )
    end
  end

  test "preflight failure rolls back through the configured repository" do
    Process.put(:agentic_restore_authority_preflight_failure, true)

    assert {:error, :persistence_unavailable} =
             AgenticRestoreAuthorityAccess.discover_non_terminal_organization_ids(1, 1)
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
