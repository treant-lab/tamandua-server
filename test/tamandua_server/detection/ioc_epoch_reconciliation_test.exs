defmodule TamanduaServer.Detection.IOCEpochReconciliationTest do
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox

  alias TamanduaServer.Detection.{IOCGenerationOwner, IOCReconciler, IOCReload, RuleLoader}
  alias TamanduaServer.Repo

  setup do
    unless Process.whereis(IOCGenerationOwner) do
      start_supervised!(IOCGenerationOwner)
    end

    RuleLoader.init_tables()
    :ok
  end

  test "an old query cannot publish over a newer authority epoch" do
    base = max(RuleLoader.published_ioc_epoch(), 0)
    parent = self()

    old_query =
      Task.async(fn ->
        IOCReload.reconcile(
          fn ->
            send(parent, :old_snapshot_read)
            receive do: (:release_old_snapshot -> :ok)
            {:ok, {base + 1, [old: %{value: "old"}]}}
          end,
          &RuleLoader.reload_ioc_rules_atomic/2
        )
      end)

    assert_receive :old_snapshot_read

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic([new: %{value: "new"}], base + 2)

    send(old_query.pid, :release_old_snapshot)

    assert {:error, {:epoch_regression, authority, published}} = Task.await(old_query)
    assert authority == base + 1
    assert published == base + 2
    assert RuleLoader.get_iocs() == [%{value: "new"}]
  end

  test "startup database failure leaves the IOC subsystem unhealthy and fail closed" do
    previous_trap_exit = Process.flag(:trap_exit, true)

    result =
      try do
        IOCReconciler.start_link(
          name: :ioc_reconciler_startup_failure_test,
          reconcile_fun: fn -> {:error, :database_unavailable} end,
          epoch_fun: fn -> {:error, :database_unavailable} end,
          preflight_fun: fn -> :ok end
        )
      after
        Process.flag(:trap_exit, previous_trap_exit)
      end

    assert {:error, {:ioc_initial_snapshot_failed, :database_unavailable}} =
             result
  end

  test "authority epoch regression is unhealthy, pending, and rejected by reconcile" do
    published = max(RuleLoader.published_ioc_epoch(), 0) + 2

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic([current: %{value: "current"}], published)

    assert {:error, {:epoch_regression, authority, ^published}} =
             IOCReload.reconcile(
               fn -> {:ok, {published - 1, [old: %{value: "old"}]}} end,
               &RuleLoader.reload_ioc_rules_atomic/2
             )

    assert authority == published - 1
    assert RuleLoader.get_iocs() == [%{value: "current"}]

    {:ok, pid} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_epoch_regression_test,
        initial_reconcile: false,
        poll_interval_ms: 60_000,
        epoch_fun: fn -> {:ok, published - 1} end,
        preflight_fun: fn -> :ok end
      )

    assert %{
             healthy: false,
             pending: true,
             last_error: :epoch_regression
           } = IOCReconciler.status(:ioc_reconciler_epoch_regression_test)

    GenServer.stop(pid)
  end

  test "equal authority after a regression republishes before restoring readiness" do
    published = max(RuleLoader.published_ioc_epoch(), 0) + 2

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic([current: %{value: "current"}], published)

    {:ok, authority} = Agent.start_link(fn -> published - 1 end)
    {:ok, reconcile_count} = Agent.start_link(fn -> 0 end)

    reconcile = fn ->
      Agent.update(reconcile_count, &(&1 + 1))

      case RuleLoader.reload_ioc_rules_atomic(
             [current: %{value: "current"}],
             Agent.get(authority, & &1)
           ) do
        {:ok, count} -> {:ok, %{published_epoch: published, count: count}}
        {:error, reason} -> {:error, reason}
      end
    end

    {:ok, pid} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_equal_recovery_test,
        initial_reconcile: false,
        poll_interval_ms: 60_000,
        epoch_fun: fn -> {:ok, Agent.get(authority, & &1)} end,
        preflight_fun: fn -> :ok end,
        reconcile_fun: reconcile
      )

    send(pid, :poll)

    assert eventually(fn ->
             match?(
               %{healthy: false, last_error: :epoch_regression},
               IOCReconciler.status(:ioc_reconciler_equal_recovery_test)
             )
           end)

    Agent.update(authority, fn _ -> published end)
    send(pid, :poll)

    assert eventually(fn -> Agent.get(reconcile_count, & &1) == 1 end)

    assert %{healthy: true, pending: false, last_error: nil} =
             IOCReconciler.status(:ioc_reconciler_equal_recovery_test)

    assert RuleLoader.get_iocs() == [%{value: "current"}]
    GenServer.stop(pid)
  end

  test "reconcile wakeups are coalesced and retried locally" do
    parent = self()
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    reconcile = fn ->
      invocation = Agent.get_and_update(counter, fn value -> {value + 1, value + 1} end)

      if invocation == 1 do
        send(parent, :first_reconcile_started)
        receive do: (:release_reconcile -> :ok)
      end

      {:ok, %{published_epoch: invocation}}
    end

    {:ok, pid} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_coalescence_test,
        initial_reconcile: false,
        poll_interval_ms: 60_000,
        reconcile_fun: reconcile,
        epoch_fun: fn -> {:ok, 0} end,
        preflight_fun: fn -> :ok end
      )

    IOCReconciler.request_reconcile(:ioc_reconciler_coalescence_test)
    assert_receive :first_reconcile_started

    for _ <- 1..50, do: IOCReconciler.request_reconcile(:ioc_reconciler_coalescence_test)
    send(pid, :release_reconcile)

    assert eventually(fn -> Agent.get(counter, & &1) == 2 end)
    Process.sleep(20)
    assert Agent.get(counter, & &1) == 2
  end

  test "each reconciler instance converges independently without cluster enumeration" do
    {:ok, first_count} = Agent.start_link(fn -> 0 end)
    {:ok, second_count} = Agent.start_link(fn -> 0 end)

    {:ok, first} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_node_a_test,
        poll_interval_ms: 10,
        initial_reconcile: false,
        epoch_fun: fn -> {:ok, 100} end,
        preflight_fun: fn -> :ok end,
        reconcile_fun: fn ->
          Agent.update(first_count, &(&1 + 1))
          {:ok, %{published_epoch: 100}}
        end
      )

    {:ok, second} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_node_b_test,
        poll_interval_ms: 10,
        initial_reconcile: false,
        epoch_fun: fn -> {:ok, 200} end,
        preflight_fun: fn -> :ok end,
        reconcile_fun: fn ->
          Agent.update(second_count, &(&1 + 1))
          {:ok, %{published_epoch: 200}}
        end
      )

    assert eventually(fn -> Agent.get(first_count, & &1) > 0 end)
    assert eventually(fn -> Agent.get(second_count, & &1) > 0 end)

    source = File.read!("lib/tamandua_server/detection/ioc_reconciler.ex")
    refute source =~ "Node.list"

    readiness = File.read!("lib/tamandua_server_web/controllers/health_controller.ex")
    assert readiness =~ "ioc_snapshot"
    assert readiness =~ ~s(ioc_check == "ok")

    GenServer.stop(first)
    GenServer.stop(second)
  end

  test "index preflight rejects indexes not valid or not ready" do
    valid = fn
      "iocs_global_type_value_unique_index" ->
        {:ok,
         %{
           definition:
             "CREATE UNIQUE INDEX x ON iocs (type, value) WHERE organization_id IS NULL",
           valid: true,
           ready: true
         }}

      "iocs_type_value_organization_id_index" ->
        {:ok,
         %{
           definition: "CREATE UNIQUE INDEX x ON iocs (type, value, organization_id)",
           valid: true,
           ready: true
         }}

      "iocs_type_value_unique_index" ->
        :missing
    end

    assert :ok = IOCReload.verify_indexes(valid)

    assert {:error, {:ioc_index_preflight_failed, :missing_or_invalid_tenant_index}} =
             IOCReload.verify_indexes(fn
               "iocs_type_value_organization_id_index" ->
                 {:ok,
                  %{
                    definition: "CREATE UNIQUE INDEX x ON iocs (type, value, organization_id)",
                    valid: true,
                    ready: false
                  }}

               name ->
                 valid.(name)
             end)
  end

  test "authority trigger preflight requires four ALWAYS statement triggers on one function" do
    triggers =
      for operation <- ["insert", "update", "delete", "truncate"] do
        %{
          name: "iocs_authority_epoch_after_#{operation}",
          enabled: "A",
          internal: false,
          function_oid: 42,
          function: "public.bump_ioc_authority_epoch()",
          function_source: authority_function_source(),
          function_definition:
            "CREATE OR REPLACE FUNCTION public.bump_ioc_authority_epoch() " <>
              "RETURNS trigger LANGUAGE plpgsql AS 'body'",
          function_language: "plpgsql",
          security_definer: false,
          definition:
            "CREATE TRIGGER x AFTER #{String.upcase(operation)} ON public.iocs " <>
              "FOR EACH STATEMENT EXECUTE FUNCTION public.bump_ioc_authority_epoch()"
        }
      end

    assert :ok = IOCReload.verify_authority_triggers(fn -> {:ok, triggers} end)

    disabled =
      Enum.map(triggers, fn trigger ->
        if trigger.name == "iocs_authority_epoch_after_update",
          do: %{trigger | enabled: "D"},
          else: trigger
      end)

    assert {:error, {:ioc_trigger_preflight_failed, :invalid_definition}} =
             IOCReload.verify_authority_triggers(fn -> {:ok, disabled} end)

    assert {:error, {:ioc_trigger_preflight_failed, :missing_disabled_or_mismatched}} =
             IOCReload.verify_authority_triggers(fn -> {:ok, tl(triggers)} end)

    no_op = Enum.map(triggers, &%{&1 | function_source: "BEGIN RETURN NULL; END;"})

    assert {:error, {:ioc_trigger_preflight_failed, :invalid_definition}} =
             IOCReload.verify_authority_triggers(fn -> {:ok, no_op} end)
  end

  test "disabled or absent IOC authority feature flag fails preflight closed" do
    previous = Application.get_env(:tamandua_server, :ioc_partial_global_unique_index)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :ioc_partial_global_unique_index)
      else
        Application.put_env(:tamandua_server, :ioc_partial_global_unique_index, previous)
      end
    end)

    Application.delete_env(:tamandua_server, :ioc_partial_global_unique_index)

    assert {:error, {:ioc_authority_preflight_failed, :feature_disabled}} =
             IOCReload.preflight()

    Application.put_env(:tamandua_server, :ioc_partial_global_unique_index, false)

    assert {:error, {:ioc_authority_preflight_failed, :feature_disabled}} =
             IOCReload.preflight()
  end

  test "IOC authority remains bound to public across restricted search_path and reset" do
    Sandbox.unboxed_run(Repo, fn ->
      with_ioc_authority_enabled(fn ->
        assert {:ok, default_epoch} = IOCReload.current_epoch()
        assert :ok = IOCReload.preflight()
        assert {:ok, {^default_epoch, default_rules}} = IOCReload.load_authoritative_snapshot()

        Repo.query!("SET search_path = pg_catalog")

        assert {:ok, ^default_epoch} = IOCReload.current_epoch()
        assert :ok = IOCReload.preflight()
        assert {:ok, {^default_epoch, ^default_rules}} = IOCReload.load_authoritative_snapshot()

        Repo.query!("RESET search_path")

        assert {:ok, ^default_epoch} = IOCReload.current_epoch()
        assert :ok = IOCReload.preflight()
        assert {:ok, {^default_epoch, ^default_rules}} = IOCReload.load_authoritative_snapshot()
      end)
    end)
  end

  test "IOC authority ignores same-named relations and indexes in a shadow schema" do
    shadow_schema = "ioc_shadow_#{System.unique_integer([:positive])}"
    quoted_shadow_schema = quote_identifier(shadow_schema)

    Sandbox.unboxed_run(Repo, fn ->
      try do
        Repo.query!("CREATE SCHEMA #{quoted_shadow_schema}")

        Repo.query!("""
        CREATE TABLE #{quoted_shadow_schema}.iocs (
          type text NOT NULL,
          value text NOT NULL,
          organization_id uuid
        )
        """)

        Repo.query!("""
        CREATE UNIQUE INDEX iocs_global_type_value_unique_index
        ON #{quoted_shadow_schema}.iocs (type, value)
        WHERE organization_id IS NULL
        """)

        Repo.query!("""
        CREATE UNIQUE INDEX iocs_type_value_organization_id_index
        ON #{quoted_shadow_schema}.iocs (type, value, organization_id)
        """)

        Repo.query!("""
        CREATE UNIQUE INDEX iocs_type_value_unique_index
        ON #{quoted_shadow_schema}.iocs (type, value)
        """)

        Repo.query!("SET search_path = #{quoted_shadow_schema}, public")

        with_ioc_authority_enabled(fn ->
          assert {:ok, epoch} = IOCReload.current_epoch()
          assert :ok = IOCReload.preflight()
          assert {:ok, {^epoch, _rules}} = IOCReload.load_authoritative_snapshot()
        end)
      after
        Repo.query!("RESET search_path")
        Repo.query!("DROP SCHEMA IF EXISTS #{quoted_shadow_schema} CASCADE")
      end
    end)
  end

  test "equal epoch after transient authority failure republishes exactly once" do
    published = max(RuleLoader.published_ioc_epoch(), 0) + 1
    assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic([old: %{value: "old"}], published)
    {:ok, epoch_result} = Agent.start_link(fn -> {:error, :database_unavailable} end)
    {:ok, reconcile_count} = Agent.start_link(fn -> 0 end)

    reconcile = fn ->
      Agent.update(reconcile_count, &(&1 + 1))

      case RuleLoader.reload_ioc_rules_atomic([old: %{value: "old"}], published) do
        {:ok, count} -> {:ok, %{published_epoch: published, count: count}}
        {:error, reason} -> {:error, reason}
      end
    end

    {:ok, pid} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_epoch_error_recovery_test,
        initial_reconcile: false,
        poll_interval_ms: 60_000,
        epoch_fun: fn -> Agent.get(epoch_result, & &1) end,
        preflight_fun: fn -> :ok end,
        reconcile_fun: reconcile
      )

    send(pid, :poll)

    assert eventually(fn ->
             match?(
               %{healthy: false, last_error: :database_unavailable},
               IOCReconciler.status(:ioc_reconciler_epoch_error_recovery_test)
             )
           end)

    Agent.update(epoch_result, fn _ -> {:ok, published} end)
    for _ <- 1..20, do: send(pid, :poll)

    assert eventually(fn -> Agent.get(reconcile_count, & &1) == 1 end)
    Process.sleep(20)
    assert Agent.get(reconcile_count, & &1) == 1

    assert %{healthy: true, pending: false, last_error: nil} =
             IOCReconciler.status(:ioc_reconciler_epoch_error_recovery_test)

    assert RuleLoader.get_iocs() == [%{value: "old"}]
    GenServer.stop(pid)
  end

  test "preflight restoration republishes before readiness becomes healthy" do
    published = max(RuleLoader.published_ioc_epoch(), 0) + 1
    assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic([old: %{value: "old"}], published)
    {:ok, preflight_result} = Agent.start_link(fn -> {:error, :trigger_disabled} end)
    {:ok, reconcile_count} = Agent.start_link(fn -> 0 end)

    reconcile = fn ->
      Agent.update(reconcile_count, &(&1 + 1))

      case RuleLoader.reload_ioc_rules_atomic([old: %{value: "old"}], published) do
        {:ok, count} -> {:ok, %{published_epoch: published, count: count}}
        {:error, reason} -> {:error, reason}
      end
    end

    {:ok, pid} =
      IOCReconciler.start_link(
        name: :ioc_reconciler_preflight_recovery_test,
        initial_reconcile: false,
        poll_interval_ms: 60_000,
        epoch_fun: fn -> {:ok, published} end,
        preflight_fun: fn -> Agent.get(preflight_result, & &1) end,
        reconcile_fun: reconcile
      )

    # The health/status path itself must persist the observed catalog failure;
    # recovery cannot turn green merely because no periodic poll saw it.
    assert eventually(fn ->
             match?(
               %{healthy: false, last_error: :trigger_disabled},
               IOCReconciler.status(:ioc_reconciler_preflight_recovery_test)
             )
           end)

    Agent.update(preflight_result, fn _ -> :ok end)

    assert %{healthy: false, pending: true} =
             IOCReconciler.status(:ioc_reconciler_preflight_recovery_test)

    for _ <- 1..20, do: send(pid, :poll)

    assert eventually(fn -> Agent.get(reconcile_count, & &1) == 1 end)
    Process.sleep(20)
    assert Agent.get(reconcile_count, & &1) == 1

    assert %{healthy: true, pending: false, last_error: nil} =
             IOCReconciler.status(:ioc_reconciler_preflight_recovery_test)

    GenServer.stop(pid)
  end

  test "queue availability checks the actual threat-intel producer state" do
    assert IOCReload.queue_available?(fn queue: :threat_intel ->
             %{queue: "threat_intel", paused: false, running: []}
           end)

    refute IOCReload.queue_available?(fn queue: :threat_intel -> nil end)

    refute IOCReload.queue_available?(fn queue: :threat_intel ->
             %{queue: "threat_intel", paused: true, running: []}
           end)
  end

  test "database trigger authority covers the complete known producer inventory" do
    migration =
      File.read!("priv/repo/migrations/20260716005000_create_ioc_authority_epoch.exs")

    assert migration =~ ~s(for operation <- ["INSERT", "UPDATE", "DELETE", "TRUNCATE"])
    assert migration =~ "FOR EACH STATEMENT"
    assert migration =~ "ENABLE ALWAYS TRIGGER"

    producer_paths = [
      "lib/tamandua_server/detection/iocs.ex",
      "lib/tamandua_server/detection/rule_importer.ex",
      "lib/tamandua_server/batch_operations.ex",
      "lib/tamandua_server/workers/batch_job_worker.ex",
      "lib/tamandua_server_web/controllers/api/v1/batch_controller.ex",
      "lib/tamandua_server_web/controllers/api/v1/ioc_controller.ex",
      "lib/tamandua_server_web/graphql/mutations/batch.ex",
      "lib/tamandua_server_web/graphql/resolvers/batch_resolver.ex",
      "lib/tamandua_server_web/graphql/resolvers/threat_intel_resolver.ex",
      "lib/tamandua_server_web/live/iocs_live.ex",
      "lib/tamandua_server/integrations.ex",
      "lib/tamandua_server/detection/threat_intel_feeds.ex",
      "lib/tamandua_server/threat_intel/aggregator.ex",
      "lib/tamandua_server/threat_intel/misp.ex",
      "lib/tamandua_server/threat_intel/stix_converter.ex",
      "lib/tamandua_server_web/controllers/webhook_controller.ex"
    ]

    assert Enum.all?(producer_paths, &File.regular?/1)
  end

  defp authority_function_source do
    """
    DECLARE
      next_epoch bigint;
    BEGIN
      UPDATE public.ioc_authority_epochs
      SET epoch = epoch + 1, updated_at = NOW()
      WHERE singleton = TRUE
      RETURNING epoch INTO next_epoch;

      PERFORM pg_catalog.pg_notify('tamandua_ioc_authority_epoch', next_epoch::text);
      RETURN NULL;
    END;
    """
  end

  defp with_ioc_authority_enabled(fun) do
    previous = Application.get_env(:tamandua_server, :ioc_partial_global_unique_index)
    Application.put_env(:tamandua_server, :ioc_partial_global_unique_index, true)

    try do
      fun.()
    after
      Repo.query!("RESET search_path")

      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :ioc_partial_global_unique_index)
      else
        Application.put_env(:tamandua_server, :ioc_partial_global_unique_index, previous)
      end
    end
  end

  defp quote_identifier(identifier) when is_binary(identifier) do
    ~s("#{String.replace(identifier, "\"", "\"\"")}")
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(10)
      eventually(fun, attempts - 1)
    end
  end
end
