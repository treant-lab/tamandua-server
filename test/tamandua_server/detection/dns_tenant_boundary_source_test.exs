defmodule TamanduaServer.Detection.DNSTenantBoundarySourceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.DNSAnalyzer
  alias TamanduaServer.Detection.DNSBlocklist
  alias TamanduaServer.Detection.DNSCommandDispatch

  @organization_id "11111111-1111-4111-8111-111111111111"
  @other_organization_id "22222222-2222-4222-8222-222222222222"

  test "authoritative organization is canonical and mismatches fail closed" do
    event = %{agent_id: "agent-1", organization_id: String.upcase(@organization_id)}

    assert {:ok, @organization_id} =
             DNSAnalyzer.authoritative_organization_id(event, fn "agent-1" -> @organization_id end)

    assert {:error, :unauthorized_organization} =
             DNSAnalyzer.authoritative_organization_id(
               %{event | organization_id: @other_organization_id},
               fn "agent-1" -> @organization_id end
             )

    assert {:error, :unauthorized_organization} =
             DNSAnalyzer.authoritative_organization_id(event, fn _agent_id -> nil end)
  end

  test "legacy analyzer APIs fail closed without an organization" do
    assert {:error, :missing_organization} = DNSAnalyzer.get_blocklist()

    assert {:error, :missing_organization} =
             DNSAnalyzer.add_to_blocklist(["evil.test"], "test", "test")

    assert {:error, :missing_organization} = DNSAnalyzer.remove_from_blocklist("evil.test")
    assert {:error, :missing_organization} = DNSAnalyzer.import_blocklist(["evil.test"])
  end

  test "blocklist persistence has no global bypass or preload path" do
    blocklist = File.read!("lib/tamandua_server/detection/dns_blocklist.ex")
    analyzer = File.read!("lib/tamandua_server/detection/dns_analyzer.ex")

    refute blocklist =~ "with_bypass"
    refute blocklist =~ "Exception.message"
    refute blocklist =~ "list_active_entries"
    refute analyzer =~ "load_blocklist_cache"
    refute analyzer =~ "@ets_blocklist"
    refute analyzer =~ "DNSBlocklist.find_active_entry"
    refute analyzer =~ "IOCs.lookup_for_organization"
    assert blocklist =~ "MultiTenant.with_organization(organization_id"
    assert blocklist =~ "e.organization_id == ^organization_id"
    assert blocklist =~ "def find_active_entry(organization_id, domains)"
    assert blocklist =~ "{:error, :blocklist_unavailable}"
    assert blocklist =~ "{:error, reason} -> {:error, reason}"
    assert blocklist =~ "Repo.insert_all(DNSBlocklistEntry, rows"
    assert blocklist =~ "id: Ecto.UUID.generate()"
    assert blocklist =~ "Repo.rollback(:incomplete_blocklist_batch)"
    assert analyzer =~ "Task.Supervisor.async_nolink(state.blocklist_task_supervisor"
    assert analyzer =~ "def handle_info({:DOWN, ref, :process"
    assert analyzer =~ "{:dns_blocklist_refresh_timeout, organization_id, ref}"
    assert analyzer =~ ":global_refresh_budget"
    assert analyzer =~ ":mutation_outside_analyzer"

    refute analyzer =~
             "case DNSBlocklist.add_entries(organization_id, domains, reason, blocked_by) do"

    assert analyzer =~ "blocklist_refreshes"
    assert analyzer =~ "blocklist_status"
    assert analyzer =~ "RuleLoader.with_ioc_snapshot"
    assert analyzer =~ "RuleLoader.published_ioc_epoch"
    assert analyzer =~ "[:tamandua, :dns, :ioc_snapshot]"

    assert_refresh_task_crash_recovers()
  end

  test "engine propagates authoritative organization and temporal keys include tenant" do
    engine = File.read!("lib/tamandua_server/detection/engine_worker.ex")
    analyzer = File.read!("lib/tamandua_server/detection/dns_analyzer.ex")

    assert engine =~ "DNSAnalyzer.authoritative_organization_id(dns_event)"
    assert engine =~ "Map.put(:organization_id, organization_id)"
    assert analyzer =~ "{organization_id, agent_id, parent}"
    assert analyzer =~ "{:error, _reason} -> {[], state}"
  end

  test "bounded snapshots reject truncation and expose freshness" do
    entries = [blocklist_entry("evil.test"), blocklist_entry("other.test")]

    assert {:error, :capacity_exceeded} =
             DNSAnalyzer.build_blocklist_snapshot(entries, 1_000, 1)

    assert {:ok, snapshot} = DNSAnalyzer.build_blocklist_snapshot(entries, 1_000, 2)
    assert map_size(snapshot.entries) == 2
    assert snapshot.entries["evil.test"].normalized_domain == "evil.test"

    assert {:available, _entries, :fresh} =
             DNSAnalyzer.blocklist_snapshot_outcome(snapshot, 1_050, 100, 500)

    assert {:available, _entries, :stale} =
             DNSAnalyzer.blocklist_snapshot_outcome(snapshot, 1_200, 100, 500)

    degraded = %{snapshot | last_error: :blocklist_unavailable}

    assert {:available, _entries, :degraded} =
             DNSAnalyzer.blocklist_snapshot_outcome(degraded, 1_200, 100, 500)

    assert {:degraded, :expired} =
             DNSAnalyzer.blocklist_snapshot_outcome(degraded, 1_501, 100, 500)

    assert {:degraded, :missing} =
             DNSAnalyzer.blocklist_snapshot_outcome(nil, 1_000, 100, 500)
  end

  test "runtime IOC confidence is normalized to the detection contract" do
    assert DNSAnalyzer.normalize_ioc_confidence(95) == 0.95
    assert DNSAnalyzer.normalize_ioc_confidence(0.85) == 0.85
    assert DNSAnalyzer.normalize_ioc_confidence(nil) == 0.7
  end

  test "safe-domain matching requires a DNS label boundary" do
    assert DNSAnalyzer.safe_domain?("google.com", ["google.com"])
    assert DNSAnalyzer.safe_domain?("api.google.com", ["GOOGLE.COM."])
    refute DNSAnalyzer.safe_domain?("evilgoogle.com", ["google.com"])
  end

  test "mutation bounds reject the complete batch before database access" do
    limits = DNSBlocklist.mutation_limits()

    assert {:ok, ["evil.test"]} =
             DNSBlocklist.prepare_batch(
               ["EVIL.TEST."],
               "test",
               "tester",
               "manual"
             )

    too_many = Enum.map(1..(limits.max_domains + 1), &"d#{&1}.test")

    assert {:error, :too_many_domains} =
             DNSBlocklist.prepare_batch(too_many, "test", "tester", "manual")

    assert {:error, :reason_too_large} =
             DNSBlocklist.prepare_batch(
               ["evil.test"],
               String.duplicate("x", limits.max_reason_bytes + 1),
               "tester",
               "manual"
             )

    assert {:error, :invalid_domain} =
             DNSBlocklist.prepare_batch(
               [String.duplicate("a", 254)],
               "test",
               "tester",
               "manual"
             )

    for injected <- [
          "evil.test\n0.0.0.0 trusted.test",
          "evil.test\r\n127.0.0.1 trusted.test",
          "evil test",
          "*.evil.test",
          "-evil.test",
          "evil-.test",
          "evil/test"
        ] do
      assert {:error, :invalid_domain} =
               DNSBlocklist.prepare_batch([injected], "test", "tester", "manual")
    end
  end

  test "tenant IOC snapshot entry overrides global without database access" do
    table = :ets.new(:dns_tenant_ioc_test, [:set, :private])

    try do
      domain = "evil.test"
      global_key = {:global, :domain, domain}
      tenant_key = {{:tenant, @organization_id}, :domain, domain}

      :ets.insert(table, {global_key, %{id: "global", confidence: 70}})
      :ets.insert(table, {tenant_key, %{id: "tenant", confidence: 95}})

      assert %{id: "tenant"} =
               DNSAnalyzer.lookup_domain_ioc_entry(table, @organization_id, domain)

      :ets.delete(table, tenant_key)

      assert %{id: "global"} =
               DNSAnalyzer.lookup_domain_ioc_entry(table, @organization_id, domain)
    after
      :ets.delete(table)
    end
  end

  test "refresh budget is global and rejected tenants are explicitly degraded" do
    assert_refresh_global_budget()
  end

  test "refresh deadline clears an inflight task" do
    assert_refresh_timeout()
  end

  test "GET of a stale snapshot starts one background refresh" do
    assert_stale_get_refreshes()
  end

  test "DNS dispatch is tenant-local, bounded and reports partial queue failures" do
    {:ok, task_supervisor} = Task.Supervisor.start_link()
    test_pid = self()

    registry = fn @organization_id ->
      [
        %{agent_id: "agent-1", status: :online},
        %{agent_id: "agent-2", status: :online},
        %{agent_id: "agent-offline", status: :offline}
      ]
    end

    queue = fn agent_id, command, params, opts ->
      send(test_pid, {:dns_queue_attempt, agent_id, command, params, opts})

      if agent_id == "agent-1",
        do: {:ok, %{id: "command-1"}},
        else: {:error, :queue_rejected}
    end

    assert {:error,
            %{
              status: :partial,
              total_jobs: 2,
              queued: 1,
              failed: 1,
              timed_out: 0
            } = summary} =
             DNSCommandDispatch.dispatch(
               :block,
               ["evil.test"],
               @organization_id,
               "test",
               registry_fun: registry,
               queue_fun: queue,
               task_supervisor: task_supervisor,
               max_concurrency: 2,
               deadline_ms: 500,
               idempotency_key: "request-1"
             )

    assert Enum.map(summary.results, & &1.status) == [:queued, :failed]
    assert_receive {:dns_queue_attempt, "agent-1", "block_domain", params, opts}
    assert params == %{domain: "evil.test", reason: "test"}
    assert is_binary(opts[:idempotency_key])
    first_idempotency_key = opts[:idempotency_key]
    assert_receive {:dns_queue_attempt, "agent-2", "block_domain", _params, _opts}

    assert {:ok, %{status: :queued}} =
             DNSCommandDispatch.dispatch(
               :block,
               ["evil.test"],
               @organization_id,
               "test",
               registry_fun: fn @organization_id ->
                 [%{agent_id: "agent-1", status: :online}]
               end,
               queue_fun: queue,
               task_supervisor: task_supervisor,
               deadline_ms: 500,
               idempotency_key: "request-1"
             )

    assert_receive {:dns_queue_attempt, "agent-1", "block_domain", _params, replay_opts}
    assert replay_opts[:idempotency_key] == first_idempotency_key

    assert {:error, %{status: :failed, queued: 0, failed: 1}} =
             DNSCommandDispatch.dispatch(
               :unblock,
               ["evil.test"],
               @organization_id,
               "test",
               registry_fun: fn @organization_id ->
                 [%{agent_id: "agent-2", status: :online}]
               end,
               queue_fun: queue,
               task_supervisor: task_supervisor,
               deadline_ms: 500
             )

    assert_receive {:dns_queue_attempt, "agent-2", "unblock_domain", _params, _opts}

    Supervisor.stop(task_supervisor)
  end

  test "DNS dispatch rejects the full batch before exceeding the job cap" do
    {:ok, task_supervisor} = Task.Supervisor.start_link()
    test_pid = self()

    registry = fn @organization_id ->
      [
        %{agent_id: "agent-1", status: :online},
        %{agent_id: "agent-2", status: :online}
      ]
    end

    queue = fn _agent_id, _command, _params, _opts ->
      send(test_pid, :unexpected_dns_queue)
      {:ok, %{id: "unexpected"}}
    end

    assert {:error,
            %{
              status: :rejected,
              reason: :job_limit_exceeded,
              total_jobs: 4,
              max_jobs: 3,
              results: []
            }} =
             DNSCommandDispatch.dispatch(
               :block,
               ["one.test", "two.test"],
               @organization_id,
               "test",
               registry_fun: registry,
               queue_fun: queue,
               task_supervisor: task_supervisor,
               max_jobs: 3
             )

    refute_receive :unexpected_dns_queue

    assert {:error, %{reason: :invalid_domain, results: []}} =
             DNSCommandDispatch.dispatch(
               :block,
               ["evil.test\n127.0.0.1 trusted.test"],
               @organization_id,
               "test",
               registry_fun: registry,
               queue_fun: queue,
               task_supervisor: task_supervisor
             )

    refute_receive :unexpected_dns_queue
    Supervisor.stop(task_supervisor)
  end

  test "DNS dispatch distinguishes zero online agents and a global deadline" do
    {:ok, task_supervisor} = Task.Supervisor.start_link()
    test_pid = self()

    assert {:error, %{status: :no_online_agents, total_jobs: 0, results: []}} =
             DNSCommandDispatch.dispatch(
               :block,
               ["evil.test"],
               @organization_id,
               "test",
               registry_fun: fn @organization_id ->
                 [%{agent_id: "agent-offline", status: :offline}]
               end,
               task_supervisor: task_supervisor
             )

    blocking_queue = fn _agent_id, _command, _params, _opts ->
      send(test_pid, {:blocking_dns_queue_started, self()})

      receive do
        :never -> {:ok, %{id: "late"}}
      end
    end

    assert {:error,
            %{
              status: :timed_out,
              total_jobs: 2,
              queued: 0,
              failed: 0,
              timed_out: 2
            }} =
             DNSCommandDispatch.dispatch(
               :block,
               ["one.test", "two.test"],
               @organization_id,
               "test",
               registry_fun: fn @organization_id ->
                 [%{agent_id: "agent-1", status: :online}]
               end,
               queue_fun: blocking_queue,
               task_supervisor: task_supervisor,
               max_concurrency: 1,
               deadline_ms: 20
             )

    assert_receive {:blocking_dns_queue_started, _task_pid}
    refute_receive {:blocking_dns_queue_started, _second_task_pid}, 20
    assert Task.Supervisor.children(task_supervisor) == []

    admitted_queue = fn _agent_id, _command, _params, _opts ->
      send(test_pid, {:admitted_dns_queue_started, self()})

      receive do
        :release -> {:ok, %{id: "admitted"}}
      end
    end

    owner =
      Task.async(fn ->
        DNSCommandDispatch.dispatch(
          :block,
          ["one.test"],
          @organization_id,
          "test",
          registry_fun: fn @organization_id -> [%{agent_id: "agent-1", status: :online}] end,
          queue_fun: admitted_queue,
          task_supervisor: task_supervisor,
          deadline_ms: 1_000
        )
      end)

    assert_receive {:admitted_dns_queue_started, admitted_worker}, 1_000

    assert {:error, %{status: :rejected, reason: :dispatch_busy, queued: 0}} =
             DNSCommandDispatch.dispatch(
               :block,
               ["two.test"],
               @organization_id,
               "test",
               registry_fun: fn @organization_id ->
                 [%{agent_id: "agent-2", status: :online}]
               end,
               queue_fun: admitted_queue,
               task_supervisor: task_supervisor,
               deadline_ms: 1_000
             )

    send(admitted_worker, :release)
    assert {:ok, %{status: :queued}} = Task.await(owner, 1_000)

    dying_owner =
      spawn(fn ->
        DNSCommandDispatch.dispatch(
          :block,
          ["owner-death.test"],
          @organization_id,
          "test",
          registry_fun: fn @organization_id -> [%{agent_id: "agent-1", status: :online}] end,
          queue_fun: admitted_queue,
          task_supervisor: task_supervisor,
          deadline_ms: 10_000
        )
      end)

    dying_owner_ref = Process.monitor(dying_owner)
    assert_receive {:admitted_dns_queue_started, orphan_candidate}, 1_000
    Process.exit(dying_owner, :kill)
    assert_receive {:DOWN, ^dying_owner_ref, :process, ^dying_owner, :killed}, 1_000
    assert_eventually_dispatch_workers_stop(task_supervisor, orphan_candidate)

    Supervisor.stop(task_supervisor)
  end

  test "controller and response callers consume only applied domains" do
    controller = File.read!("lib/tamandua_server_web/controllers/api/v1/dns_controller.ex")
    remediation = File.read!("lib/tamandua_server/remediation/executor.ex")
    response = File.read!("lib/tamandua_server_web/controllers/api/v1/response_controller.ex")
    playbook = File.read!("lib/tamandua_server/response/playbook.ex")
    analyzer = File.read!("lib/tamandua_server/detection/dns_analyzer.ex")

    dispatch = File.read!("lib/tamandua_server/detection/dns_command_dispatch.ex")

    refute controller =~ "Registry.list_all"
    refute controller =~ "OrgLookup"

    assert controller =~
             "DNSCommandDispatch.dispatch(action, domains, organization_id, reason, opts)"

    assert controller =~ "durable_applied: true"
    assert controller =~ "partial: match?({:error, _summary}, dispatch)"
    assert controller =~ "dns_blocklist_mutation_outcome_unknown"
    assert controller =~ "reconciliation_requested: true"
    refute controller =~ "reconciliation_scheduled: true"
    assert dispatch =~ "Registry.list_for_org(organization_id)"
    assert dispatch =~ ":job_limit_exceeded"
    assert dispatch =~ ":dispatch_busy"
    assert dispatch =~ "Task.Supervisor.async_nolink"
    assert dispatch =~ "Process.monitor(owner)"
    assert dispatch =~ "[:tamandua, :dns, :command_dispatch]"
    assert dispatch =~ "idempotency_key: job.idempotency_key"
    assert controller =~ "TamanduaServerWeb.Plugs.Authorize"
    assert controller =~ ":response_execute"
    refute controller =~ "detail: Exception.message(exception)"

    refute remediation =~ "{:ok, count} ->"
    assert remediation =~ "{:ok, applied_domains} ->"
    assert response =~ "{:ok, [applied_domain] = applied_domains} ->"
    assert response =~ "payload = %{domain: applied_domain"
    assert playbook =~ "{:ok, applied_domains} ->"
    assert playbook =~ "%{domain: applied_domain}"
    assert playbook =~ "{:partial,"
    assert playbook =~ "durable_applied: true"
    assert playbook =~ "Endpoint dispatch failed after durable DNS blocklist update"
    assert analyzer =~ ":mutation_outcome_unknown"
    assert analyzer =~ ":mutation_busy"
    assert analyzer =~ "Process.monitor(owner)"
    assert analyzer =~ "reconcile_blocklist_after_mutation(organization_id)"

    assert :binary.match(response, "DNSAnalyzer.add_to_blocklist(") <
             :binary.match(response, ~s(Executor.execute_action(agent_id, "block_domain"))

    assert :binary.match(playbook, "case dns_result do") <
             :binary.match(playbook, "%{domain: applied_domain}")
  end

  defp blocklist_entry(domain) do
    %{
      normalized_domain: domain,
      domain: domain,
      updated_at: nil,
      inserted_at: nil,
      blocked_by: "test",
      reason: "test",
      source: "test",
      active: true,
      organization_id: @organization_id
    }
  end

  defp assert_eventually_dispatch_workers_stop(task_supervisor, worker, attempts \\ 50)

  defp assert_eventually_dispatch_workers_stop(_task_supervisor, _worker, 0),
    do: flunk("dispatch work survived owner death")

  defp assert_eventually_dispatch_workers_stop(task_supervisor, worker, attempts) do
    if Task.Supervisor.children(task_supervisor) == [] and not Process.alive?(worker) do
      :ok
    else
      Process.sleep(10)
      assert_eventually_dispatch_workers_stop(task_supervisor, worker, attempts - 1)
    end
  end

  defp assert_refresh_task_crash_recovers do
    test_pid = self()
    {:ok, attempts} = Agent.start_link(fn -> 0 end)
    {:ok, clock} = Agent.start_link(fn -> 1_000 end)
    {:ok, task_supervisor} = Task.Supervisor.start_link()

    loader = fn _organization_id, _limit ->
      attempt = Agent.get_and_update(attempts, &{&1 + 1, &1 + 1})
      send(test_pid, {:blocklist_load_attempt, attempt})

      if attempt == 1 do
        Process.exit(self(), :kill)
      else
        {:ok, []}
      end
    end

    {:ok, analyzer} =
      GenServer.start_link(DNSAnalyzer,
        skip_ets_setup: true,
        blocklist_loader: loader,
        blocklist_now: fn -> Agent.get(clock, & &1) end,
        blocklist_task_supervisor: task_supervisor
      )

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive {:blocklist_load_attempt, 1}, 1_000
    assert_eventually_not_refreshing(analyzer)

    Agent.update(clock, fn _ -> 20_000 end)

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive {:blocklist_load_attempt, 2}, 1_000
    assert_eventually_fresh(analyzer)

    GenServer.stop(analyzer)
    Supervisor.stop(task_supervisor)
    Agent.stop(clock)
    Agent.stop(attempts)
  end

  defp assert_eventually_not_refreshing(analyzer, attempts \\ 50)

  defp assert_eventually_not_refreshing(_analyzer, 0),
    do: flunk("crashed refresh remained permanently in flight")

  defp assert_eventually_not_refreshing(analyzer, attempts) do
    case GenServer.call(analyzer, {:blocklist_status, @organization_id}) do
      %{refreshing: false, last_error: :task_crashed} ->
        :ok

      _status ->
        Process.sleep(10)
        assert_eventually_not_refreshing(analyzer, attempts - 1)
    end
  end

  defp assert_eventually_fresh(analyzer, attempts \\ 50)

  defp assert_eventually_fresh(_analyzer, 0),
    do: flunk("replacement refresh did not publish a fresh snapshot")

  defp assert_eventually_fresh(analyzer, attempts) do
    case GenServer.call(analyzer, {:get_blocklist, @organization_id}) do
      {:ok, [], :fresh} ->
        :ok

      _outcome ->
        Process.sleep(10)
        assert_eventually_fresh(analyzer, attempts - 1)
    end
  end

  defp assert_refresh_global_budget do
    test_pid = self()
    {:ok, task_supervisor} = Task.Supervisor.start_link()

    loader = fn organization_id, _limit ->
      send(test_pid, {:budget_loader_started, organization_id, self()})

      receive do
        :release -> {:ok, []}
      end
    end

    {:ok, analyzer} =
      GenServer.start_link(DNSAnalyzer,
        skip_ets_setup: true,
        blocklist_loader: loader,
        blocklist_task_supervisor: task_supervisor,
        refresh_max_concurrency: 1,
        refresh_timeout_ms: 1_000
      )

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive {:budget_loader_started, @organization_id, loader_pid}, 1_000

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @other_organization_id})

    assert %{refreshing: false, last_error: :global_refresh_budget} =
             GenServer.call(analyzer, {:blocklist_status, @other_organization_id})

    refute_receive {:budget_loader_started, @other_organization_id, _pid}, 50
    send(loader_pid, :release)
    assert_eventually_fresh(analyzer)

    GenServer.stop(analyzer)
    Supervisor.stop(task_supervisor)
  end

  defp assert_refresh_timeout do
    test_pid = self()
    {:ok, task_supervisor} = Task.Supervisor.start_link()

    loader = fn _organization_id, _limit ->
      send(test_pid, :timeout_loader_started)
      Process.sleep(:infinity)
    end

    {:ok, analyzer} =
      GenServer.start_link(DNSAnalyzer,
        skip_ets_setup: true,
        blocklist_loader: loader,
        blocklist_task_supervisor: task_supervisor,
        refresh_timeout_ms: 20
      )

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive :timeout_loader_started, 1_000
    assert_eventually_refresh_timeout(analyzer)

    GenServer.stop(analyzer)
    Supervisor.stop(task_supervisor)
  end

  defp assert_eventually_refresh_timeout(analyzer, attempts \\ 50)

  defp assert_eventually_refresh_timeout(_analyzer, 0),
    do: flunk("refresh deadline did not clear inflight task")

  defp assert_eventually_refresh_timeout(analyzer, attempts) do
    case GenServer.call(analyzer, {:blocklist_status, @organization_id}) do
      %{refreshing: false, last_error: :refresh_timeout} ->
        :ok

      _status ->
        Process.sleep(10)
        assert_eventually_refresh_timeout(analyzer, attempts - 1)
    end
  end

  defp assert_stale_get_refreshes do
    test_pid = self()
    {:ok, clock} = Agent.start_link(fn -> 1_000 end)
    {:ok, task_supervisor} = Task.Supervisor.start_link()

    loader = fn _organization_id, _limit ->
      send(test_pid, :stale_loader_started)
      {:ok, []}
    end

    {:ok, analyzer} =
      GenServer.start_link(DNSAnalyzer,
        skip_ets_setup: true,
        blocklist_loader: loader,
        blocklist_now: fn -> Agent.get(clock, & &1) end,
        blocklist_task_supervisor: task_supervisor
      )

    assert {:error, :blocklist_unavailable} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive :stale_loader_started, 1_000
    assert_eventually_fresh(analyzer)
    Agent.update(clock, &(&1 + 60_001))

    assert {:ok, [], :stale} =
             GenServer.call(analyzer, {:get_blocklist, @organization_id})

    assert_receive :stale_loader_started, 1_000

    GenServer.stop(analyzer)
    Supervisor.stop(task_supervisor)
    Agent.stop(clock)
  end
end
