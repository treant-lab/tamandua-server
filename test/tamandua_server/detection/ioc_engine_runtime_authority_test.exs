defmodule TamanduaServer.Detection.IOCEngineRuntimeAuthorityTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.{EngineWorker, RuleLoader}

  @org_a "00000000-0000-0000-0000-00000000000a"
  @org_b "00000000-0000-0000-0000-00000000000b"

  setup do
    RuleLoader.init_tables()
    RuleLoader.reload_ioc_rules_atomic([], next_ioc_epoch())
    :ok
  end

  test "forged organization claim fails closed to global indicators" do
    reload([
      ioc(:global, :domain, "shared.test", "global"),
      ioc({:tenant, @org_b}, :domain, "private.test", "tenant-b")
    ])

    lookup = fn "agent-a" -> @org_a end

    assert EngineWorker.ioc_scope_for_event(event("private.test", @org_b), lookup) == :global
    assert EngineWorker.lookup_iocs(event("private.test", @org_b), lookup) == []
    assert ids(EngineWorker.lookup_iocs(event("shared.test", @org_b), lookup)) == ["global"]
  end

  test "unknown agents cannot adopt an organization from event data" do
    reload([
      ioc(:global, :domain, "shared.test", "global"),
      ioc({:tenant, @org_a}, :domain, "private.test", "tenant-a")
    ])

    unknown = fn _agent_id -> nil end

    assert EngineWorker.ioc_scope_for_event(event("private.test", @org_a), unknown) == :global
    assert EngineWorker.lookup_iocs(event("private.test", @org_a), unknown) == []
    assert ids(EngineWorker.lookup_iocs(event("shared.test", @org_a), unknown)) == ["global"]
  end

  test "organization lookup failures downgrade to global scope and emit telemetry" do
    handler_id = "ioc-scope-downgrade-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler_id,
        [:tamandua, :detection, :ioc_scope_downgrade],
        fn event, measurements, metadata, test_pid ->
          send(test_pid, {event, measurements, metadata})
        end,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert EngineWorker.ioc_scope_for_event(event("private.test", @org_a), fn _ ->
             raise "organization lookup unavailable"
           end) == :global

    assert_receive {[:tamandua, :detection, :ioc_scope_downgrade], %{count: 1},
                    %{reason: :organization_lookup_failed}}
  end

  test "worker observes the active version immediately after reload" do
    lookup = fn _agent_id -> @org_a end

    reload([ioc(:global, :domain, "old.test", "old")])
    assert ids(EngineWorker.lookup_iocs(event("old.test", @org_a), lookup)) == ["old"]

    reload([ioc(:global, :domain, "new.test", "new")])
    assert EngineWorker.lookup_iocs(event("old.test", @org_a), lookup) == []
    assert ids(EngineWorker.lookup_iocs(event("new.test", @org_a), lookup)) == ["new"]
  end

  test "private indicators never match another tenant" do
    reload([ioc({:tenant, @org_b}, :ip, "203.0.113.9", "tenant-b")])

    assert EngineWorker.lookup_iocs(ip_event("203.0.113.9"), fn _ -> @org_a end) == []

    assert ids(EngineWorker.lookup_iocs(ip_event("203.0.113.9"), fn _ -> @org_b end)) == [
             "tenant-b"
           ]
  end

  @tag timeout: 30_000
  test "event lookup remains scoped when cache contains many unrelated tenants" do
    unrelated =
      for index <- 1..10_000 do
        organization_id = "tenant-#{index}"
        ioc({:tenant, organization_id}, :domain, "ioc-#{index}.test", "ioc-#{index}")
      end

    reload([ioc(:global, :domain, "target.test", "target") | unrelated])

    assert :ets.info(RuleLoader.get_active_table(:ioc), :size) == 10_001

    assert ids(EngineWorker.lookup_iocs(event("target.test", @org_a), fn _ -> @org_a end)) == [
             "target"
           ]
  end

  defp reload(iocs) do
    rules = Enum.map(iocs, fn ioc -> {{ioc.scope, ioc.type, ioc.value}, ioc} end)
    assert {:ok, _count} = RuleLoader.reload_ioc_rules_atomic(rules, next_ioc_epoch())
  end

  defp ioc(scope, type, value, id) do
    %{
      id: id,
      scope: scope,
      organization_id: organization_id(scope),
      type: type,
      value: value,
      confidence: 90,
      description: id
    }
  end

  defp organization_id(:global), do: nil
  defp organization_id({:tenant, organization_id}), do: organization_id

  defp event(domain, organization_id) do
    %{
      "agent_id" => "agent-a",
      "organization_id" => organization_id,
      "payload" => %{"domain" => domain}
    }
  end

  defp ip_event(ip) do
    %{"agent_id" => "agent-a", "payload" => %{"remote_ip" => ip}}
  end

  defp ids(iocs), do: Enum.map(iocs, & &1.id)
  defp next_ioc_epoch, do: max(RuleLoader.published_ioc_epoch(), 0) + 1
end
