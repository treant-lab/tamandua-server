defmodule TamanduaServer.Detection.IOCReloadReliabilityTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.{IOCGenerationOwner, IOCReload, RuleLoader}
  alias TamanduaServer.Workers.IOCReloadWorker

  setup do
    unless Process.whereis(IOCGenerationOwner) do
      start_supervised!(IOCGenerationOwner)
    end

    RuleLoader.init_tables()
    RuleLoader.reload_ioc_rules_atomic([], next_ioc_epoch())
    :ok
  end

  @tag timeout: 120_000
  test "concurrent 100k reloads publish exactly one complete snapshot" do
    batch_a = batch("a", 100_000)
    batch_b = batch("b", 100_000)

    base_epoch = next_ioc_epoch()

    tasks =
      for {batch, offset} <- Enum.with_index([batch_a, batch_b, batch_a, batch_b]) do
        Task.async(fn -> RuleLoader.reload_ioc_rules_atomic(batch, base_epoch + offset) end)
      end

    assert Enum.all?(Task.await_many(tasks, 120_000), fn
             {:ok, 100_000} -> true
             {:stale, _epoch} -> true
             _ -> false
           end)

    final = RuleLoader.read_all(:ioc) |> Map.new()

    assert map_size(final) == 100_000
    assert final == Map.new(batch_b)
  end

  test "worker returns errors for Oban retry and acknowledges a complete reload" do
    job = %Oban.Job{args: %{"scope" => "all"}, attempt: 1, max_attempts: 5}

    assert IOCReloadWorker.perform_result(job, fn -> {:error, :database_unavailable} end) ==
             {:error, :database_unavailable}

    assert IOCReloadWorker.perform_result(job, fn -> {:ok, 42} end) == :ok
  end

  test "scheduler keeps a durable receipt and refreshes synchronously without a consumer" do
    insert = fn changeset ->
      {:ok, Ecto.Changeset.apply_changes(changeset) |> Map.put(:id, 17)}
    end

    assert {:ok, %{mode: :durable_with_synchronous_refresh, job_id: 17, count: 9}} =
             IOCReload.schedule(insert, fn -> :ok end, fn -> false end, fn -> {:ok, 9} end)
  end

  test "scheduler does not hide enqueue or fallback failures" do
    assert {:error, :index_not_ready} =
             IOCReload.schedule(
               fn _ -> flunk("must not enqueue") end,
               fn -> {:error, :index_not_ready} end,
               fn -> true end,
               fn -> flunk("must not reload") end
             )

    assert {:error, {:reload_queued_but_synchronous_refresh_failed, 18, :db_down}} =
             IOCReload.schedule(
               fn changeset ->
                 {:ok, Ecto.Changeset.apply_changes(changeset) |> Map.put(:id, 18)}
               end,
               fn -> :ok end,
               fn -> false end,
               fn -> {:error, :db_down} end
             )
  end

  test "index preflight requires partial global and tenant indexes and rejects legacy index" do
    valid = fn
      "iocs_global_type_value_unique_index" ->
        {:ok,
         "CREATE UNIQUE INDEX x ON public.iocs USING btree (type, value) WHERE (organization_id IS NULL)"}

      "iocs_type_value_organization_id_index" ->
        {:ok, "CREATE UNIQUE INDEX x ON public.iocs USING btree (type, value, organization_id)"}

      "iocs_type_value_unique_index" ->
        :missing
    end

    assert :ok = IOCReload.verify_indexes(valid)

    assert {:error, {:ioc_index_preflight_failed, :missing_or_invalid_partial_global_index}} =
             IOCReload.verify_indexes(fn _ -> :missing end)

    assert {:error, {:ioc_index_preflight_failed, :legacy_global_unique_index_still_present}} =
             IOCReload.verify_indexes(fn
               "iocs_type_value_unique_index" -> {:ok, "CREATE UNIQUE INDEX legacy"}
               name -> valid.(name)
             end)
  end

  test "database authority queries are explicitly bound to canonical schemas" do
    source = File.read!("lib/tamandua_server/detection/ioc_reload.ex")

    assert source =~ "SELECT epoch FROM public.ioc_authority_epochs"
    assert source =~ ~s(prefix: "public")
    assert source =~ "FROM pg_catalog.pg_index"
    assert source =~ "pg_catalog.pg_get_triggerdef"
    assert source =~ "pg_catalog.pg_get_functiondef"
    assert source =~ "tbl_ns.nspname = 'public'"
    assert source =~ "idx_ns.nspname = 'public'"
    refute source =~ "current_schemas(false)"
    refute source =~ "SELECT epoch FROM ioc_authority_epochs"
  end

  test "all IOC mutation surfaces use the durable scheduler instead of Task.start" do
    paths = [
      "lib/tamandua_server/integrations.ex",
      "lib/tamandua_server/detection/threat_intel_feeds.ex",
      "lib/tamandua_server/threat_intel/aggregator.ex",
      "lib/tamandua_server/threat_intel/misp.ex",
      "lib/tamandua_server/threat_intel/stix_converter.ex",
      "lib/tamandua_server_web/controllers/api/v1/ioc_controller.ex",
      "lib/tamandua_server_web/controllers/webhook_controller.ex",
      "lib/tamandua_server_web/graphql/resolvers/threat_intel_resolver.ex"
    ]

    for path <- paths do
      source = path |> Path.expand(File.cwd!()) |> File.read!()
      assert source =~ "IOCReload.schedule()", "missing durable scheduler in #{path}"
      refute source =~ "Task.start(fn -> TamanduaServer.Detection.Engine.reload_iocs()"
      refute source =~ "Task.start(fn -> Engine.reload_iocs()"
    end
  end

  defp batch(prefix, size) do
    for index <- 1..size do
      key = {prefix, index}
      {key, %{id: "#{prefix}-#{index}", value: key}}
    end
  end

  defp next_ioc_epoch, do: max(RuleLoader.published_ioc_epoch(), 0) + 1
end
