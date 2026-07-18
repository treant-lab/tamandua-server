defmodule TamanduaServer.IocSnapshotAuthorityAccessTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.IocSnapshotAuthorityAccess

  defmodule StubRepo do
    @access_source File.read!(
                     Path.expand(
                       "../../../lib/tamandua_server/ioc_snapshot_authority_access.ex",
                       __DIR__
                     )
                   )

    @function_source Regex.run(
                       ~r/@function_source ~S"""\r?\n(.*?)\r?\n  """/s,
                       @access_source
                     )
                     |> Enum.fetch!(1)

    def enabled?, do: true

    def transaction(callback, _opts) do
      try do
        {:ok, callback.()}
      catch
        {:rollback, reason} -> {:error, reason}
      end
    end

    def rollback(reason), do: throw({:rollback, reason})

    def query(sql), do: query(sql, [], [])
    def query(sql, params), do: query(sql, params, [])

    def query(sql, _params, _opts) do
      cond do
        String.contains?(sql, "FROM pg_catalog.pg_roles login") ->
          {:ok, %{rows: [[true, @function_source]]}}

        String.contains?(sql, "SELECT * FROM public.authority_ioc_snapshot_v1") ->
          description = Application.fetch_env!(:tamandua_server, :ioc_snapshot_test_description)

          {:ok,
           %{
             columns:
               ~w(authority_epoch is_envelope has_more row_bytes id organization_id type value severity description source),
             rows: [
               [
                 0,
                 false,
                 false,
                 512,
                 "00000000-0000-0000-0000-000000000001",
                 nil,
                 "domain",
                 "compressible.test",
                 "high",
                 description,
                 "focused-test"
               ]
             ]
           }}

        true ->
          {:ok, %{rows: []}}
      end
    end
  end

  setup do
    keys = [
      :ioc_snapshot_authority_repo,
      :ioc_snapshot_authority_database_role,
      :ioc_snapshot_test_description
    ]

    previous = Map.new(keys, &{&1, Application.fetch_env(:tamandua_server, &1)})

    Application.put_env(:tamandua_server, :ioc_snapshot_authority_repo, StubRepo)

    Application.put_env(
      :tamandua_server,
      :ioc_snapshot_authority_database_role,
      "ioc_snapshot_login"
    )

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:tamandua_server, key, value)
        {key, :error} -> Application.delete_env(:tamandua_server, key)
      end)
    end)

    :ok
  end

  test "rejects a logical payload over 64 KiB when SQL reports a small compressed row" do
    Application.put_env(:tamandua_server, :ioc_snapshot_test_description, "small")

    assert {:ok, %{row_count: 1}} = IocSnapshotAuthorityAccess.load_snapshot()

    Application.put_env(
      :tamandua_server,
      :ioc_snapshot_test_description,
      String.duplicate("x", 64 * 1024 + 1)
    )

    assert {:error, :persistence_unavailable} = IocSnapshotAuthorityAccess.load_snapshot()
  end
end
