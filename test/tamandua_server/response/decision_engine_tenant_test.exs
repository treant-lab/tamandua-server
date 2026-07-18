defmodule TamanduaServer.Response.DecisionEngineTenantTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Response.DecisionEngine
  alias TamanduaServer.Workers.AutonomousResponseWorker

  setup do
    pid = Process.whereis(DecisionEngine)
    assert is_pid(pid) and Process.alive?(pid)

    original_product_lock =
      Application.get_env(:tamandua_server, :decision_engine_autonomous_response_enabled)

    Application.put_env(:tamandua_server, :decision_engine_autonomous_response_enabled, false)

    suffix = System.unique_integer([:positive, :monotonic])
    keys = %{
      org_a: "decision-test-org-a-#{suffix}",
      org_b: "decision-test-org-b-#{suffix}",
      rec_a: Ecto.UUID.generate(),
      rec_b: Ecto.UUID.generate(),
      response_a: "decision-test-response-a-#{suffix}"
    }

    on_exit(fn ->
      case Process.whereis(DecisionEngine) do
        current_pid when is_pid(current_pid) ->
          :sys.replace_state(current_pid, fn state ->
            %{state |
              response_metrics: drop_keys(state.response_metrics, [keys.org_a, keys.org_b]),
              pending_recommendations:
                drop_keys(state.pending_recommendations, [keys.rec_a, keys.rec_b]),
              action_counts: drop_keys(state.action_counts, [keys.org_a, keys.org_b]),
              rollback_registry: drop_keys(state.rollback_registry, [keys.response_a]),
              settings: drop_keys(state.settings, [keys.org_a, keys.org_b]),
              emergency_disabled:
                state.emergency_disabled
                |> MapSet.delete(keys.org_a)
                |> MapSet.delete(keys.org_b),
              autonomous_armed:
                state.autonomous_armed |> MapSet.delete(keys.org_a) |> MapSet.delete(keys.org_b)
            }
          end)

        nil ->
          :ok
      end

      if is_nil(original_product_lock) do
        Application.delete_env(:tamandua_server, :decision_engine_autonomous_response_enabled)
      else
        Application.put_env(
          :tamandua_server,
          :decision_engine_autonomous_response_enabled,
          original_product_lock
        )
      end
    end)

    {:ok, keys}
  end

  test "autonomous response is product locked and tenant disabled by default", keys do
    assert {:ok, %{autonomous_enabled: false}} = DecisionEngine.get_settings(keys.org_a)

    assert {:error, :autonomous_response_locked} =
             DecisionEngine.emergency_enable(keys.org_a, "operator")
    state = :sys.get_state(DecisionEngine)

    refute MapSet.member?(state.autonomous_armed, keys.org_a)

    assert {:error, :settings_persistence_failed} =
             DecisionEngine.update_settings(keys.org_a, %{autonomous_enabled: true})

    assert {:ok, %{autonomous_enabled: false}} = DecisionEngine.get_settings(keys.org_a)
  end

  test "restart posture requires product, tenant and explicit emergency arm", keys do
    Application.put_env(:tamandua_server, :decision_engine_autonomous_response_enabled, true)

    replace_state(fn state ->
      %{state | settings: Map.put(state.settings, keys.org_a, %{autonomous_enabled: true})}
    end)

    refute MapSet.member?(:sys.get_state(DecisionEngine).autonomous_armed, keys.org_a)

    assert :ok = DecisionEngine.emergency_enable(keys.org_a, "operator")
    assert MapSet.member?(:sys.get_state(DecisionEngine).autonomous_armed, keys.org_a)

    assert :ok = DecisionEngine.emergency_disable(keys.org_a, "incident")
    state = :sys.get_state(DecisionEngine)
    refute MapSet.member?(state.autonomous_armed, keys.org_a)
    assert MapSet.member?(state.emergency_disabled, keys.org_a)

    assert {:ok, restarted_state} = DecisionEngine.init([])
    assert restarted_state.autonomous_armed == MapSet.new()
  end

  test "metrics are tenant scoped and missing scope fails closed", keys do
    replace_state(fn state ->
      metrics =
        state.response_metrics
        |> Map.put(keys.org_a, metrics(3))
        |> Map.put(keys.org_b, metrics(9))

      %{state | response_metrics: metrics}
    end)

    assert {:ok, %{total_responses: 3}} =
             DecisionEngine.get_response_metrics({:organization, keys.org_a})

    assert {:ok, %{total_responses: 9}} =
             DecisionEngine.get_response_metrics({:organization, keys.org_b})

    assert {:error, :tenant_required} = DecisionEngine.get_response_metrics()
    assert {:error, :tenant_required} = DecisionEngine.get_response_metrics({:organization, ""})
  end

  test "pending recommendations are filtered from the id keyed map", keys do
    replace_state(fn state ->
      pending =
        state.pending_recommendations
        |> Map.put(keys.rec_a, %{
          id: keys.rec_a,
          organization_id: keys.org_a,
          created_at: DateTime.utc_now()
        })
        |> Map.put(keys.rec_b, %{
          id: keys.rec_b,
          organization_id: keys.org_b,
          created_at: DateTime.utc_now()
        })

      %{state | pending_recommendations: pending}
    end)

    assert {:ok, [%{id: rec_a}]} = DecisionEngine.get_pending_recommendations(keys.org_a)
    assert rec_a == keys.rec_a

    assert {:ok, [%{id: rec_b}]} = DecisionEngine.get_pending_recommendations(keys.org_b)
    assert rec_b == keys.rec_b
    assert {:error, :tenant_required} = DecisionEngine.get_pending_recommendations()
  end

  test "approval, rejection, history and rollback reject absent or foreign scope", keys do
    replace_state(fn state ->
      pending =
        Map.put(state.pending_recommendations, keys.rec_a, %{
          id: keys.rec_a,
          organization_id: keys.org_a,
          created_at: DateTime.utc_now()
        })

      registry =
        Map.put(state.rollback_registry, keys.response_a, %{
          response: %{response_id: keys.response_a, organization_id: keys.org_a},
          created_at: DateTime.utc_now()
        })

      %{state |
        pending_recommendations: pending,
        rollback_registry: registry
      }
    end)

    assert {:error, :not_found} =
             DecisionEngine.approve_recommendation(
               keys.rec_a,
               "user-b",
               {:organization, keys.org_b}
             )

    assert {:error, :tenant_required} =
             DecisionEngine.approve_recommendation(keys.rec_a, "user-a")

    assert {:error, :not_found} =
             DecisionEngine.reject_recommendation(
               keys.rec_a,
               "user-b",
               "foreign tenant",
               {:organization, keys.org_b}
             )

    assert {:error, :tenant_required} = DecisionEngine.get_action_history()

    assert {:error, :not_found} =
             DecisionEngine.rollback_response(keys.response_a, {:organization, keys.org_b})

    state = :sys.get_state(DecisionEngine)
    assert Map.has_key?(state.pending_recommendations, keys.rec_a)
    assert Map.has_key?(state.rollback_registry, keys.response_a)

    assert {:error, :tenant_required} = DecisionEngine.rollback_response(keys.response_a)
    assert {:error, :tenant_required} = DecisionEngine.parallel_response("agent", [], nil)
  end

  test "queue and rate counter casts update state without crashing the engine", keys do
    GenServer.cast(DecisionEngine, {
      :queue_recommendation,
      %{id: keys.rec_a, organization_id: keys.org_a, created_at: DateTime.utc_now()}
    })

    GenServer.cast(DecisionEngine, {:increment_counts, keys.org_a})

    state = :sys.get_state(DecisionEngine)
    assert state.pending_recommendations[keys.rec_a].organization_id == keys.org_a
    assert state.action_counts[keys.org_a].hour == 1
    assert state.action_counts[keys.org_a].minute in [0, 1]
  end

  test "configuration and evaluation APIs reject a missing tenant" do
    assert {:error, :tenant_required} = DecisionEngine.get_settings(nil)
    assert {:error, :tenant_required} = DecisionEngine.update_settings("", %{})
    assert {:error, :tenant_required} = DecisionEngine.rate_limit_status(nil)
    assert {:error, :tenant_required} = DecisionEngine.evaluate_alert(%Alert{})

    assert {:error, :tenant_required} =
             DecisionEngine.emergency_disable(nil, "invalid scope")

    assert {:error, :tenant_required} = DecisionEngine.emergency_enable("", "user")

    state = :sys.get_state(DecisionEngine)
    refute MapSet.member?(state.emergency_disabled, nil)
    refute MapSet.member?(state.emergency_disabled, "")
  end

  test "action idempotency key survives the JSONB atom-to-string round trip" do
    recommendation = %{alert_id: Ecto.UUID.generate()}
    atom_action = %{type: "kill_process", params: %{pid: 42, options: %{force: true}}}

    string_action = %{
      type: "kill_process",
      params: %{"pid" => 42, "options" => %{"force" => true}}
    }

    atom_key =
      DecisionEngine.recommendation_action_idempotency_key(recommendation, atom_action, 0)

    string_key =
      DecisionEngine.recommendation_action_idempotency_key(recommendation, string_action, 0)

    assert atom_key == string_key

    changed_key =
      DecisionEngine.recommendation_action_idempotency_key(
        recommendation,
        put_in(string_action.params["pid"], 43),
        0
      )

    refute changed_key == atom_key
  end

  test "persisted action results are JSON-safe" do
    persisted =
      DecisionEngine.persisted_execution_results({
        :ok,
        %{
          results: [
            %{action: :kill_process, result: {:ok, %{pid: 42, state: :terminated}}},
            %{action: :quarantine_file, result: {:error, {:io_error, :enoent}}}
          ]
        }
      })

    assert [
             %{
               action: "kill_process",
               status: "ok",
               result: %{"pid" => 42, "state" => "terminated"}
             },
             %{
               action: "quarantine_file",
               status: "error",
               error: "{:io_error, :enoent}"
             }
           ] = persisted

    assert {:ok, _json} = Jason.encode(persisted)
  end

  test "a durable claim allows one approval and rejects a stale replay", keys do
    organization = insert(:organization)
    user = insert(:user, organization: organization, organization_id: organization.id)
    agent = insert(:agent, organization: organization, organization_id: organization.id)

    alert =
      insert(:alert,
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id
      )

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    db_now = DateTime.to_naive(now)

    recommendation = %{
      id: keys.rec_a,
      alert_id: alert.id,
      agent_id: agent.id,
      organization_id: organization.id,
      severity: "high",
      confidence_score: 95.0,
      criticality_level: :low,
      suggested_actions: [],
      matching_rules: [],
      auto_execute_eligible: false,
      justification: "idempotency test",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    on_exit(fn ->
      learning = TamanduaServer.Response.AnalystLearning

      if Process.whereis(learning) do
        :sys.replace_state(learning, fn state ->
          %{state |
            decision_history:
              Enum.reject(state.decision_history, &(&1[:recommendation_id] == recommendation.id)),
            analyst_profiles: Map.delete(state.analyst_profiles, user.id),
            approval_patterns: Map.delete(state.approval_patterns, organization.id)
          }
        end)
      end
    end)

    insert_recommendation_row(recommendation, "pending", db_now)

    put_pending(recommendation)

    assert {:ok, %{status: :queued, job_id: job_id}} =
             DecisionEngine.approve_recommendation(
               recommendation.id,
               user.id,
               {:organization, organization.id}
             )

    assert is_integer(job_id)
    assert recommendation_status(recommendation.id, organization.id) == "queued"

    assert {:ok, %{status: "queued", id: status_id, result: queued_result}} =
             DecisionEngine.get_recommendation_status(
               recommendation.id,
               {:organization, organization.id}
             )

    assert status_id == recommendation.id
    assert queued_result["claim"] == "approved"

    assert %{is_limited: false} = DecisionEngine.rate_limit_status(organization.id)
    job = Repo.get!(Oban.Job, job_id)

    assert %Oban.Job{
             worker: "TamanduaServer.Workers.AutonomousResponseWorker",
             args: %{
               "recommendation_id" => recommendation_id,
               "organization_id" => job_organization_id,
               "approver_id" => job_approver_id,
               "mode" => "approved"
             }
           } = job

    assert recommendation_id == recommendation.id
    assert job_organization_id == organization.id
    assert job_approver_id == user.id

    assert :ok =
             AutonomousResponseWorker.perform(%Oban.Job{
               args: job.args
             })

    assert recommendation_status(recommendation.id, organization.id) == "approved"

    assert {:ok, %{status: "approved", approved_by: approved_by, result: approved_result}} =
             DecisionEngine.get_recommendation_status(
               recommendation.id,
               {:organization, organization.id}
             )

    assert approved_by == user.id
    assert approved_result["results"] == []

    :sys.get_state(TamanduaServer.Response.AnalystLearning)

    terminal_snapshot = recommendation_snapshot(recommendation.id, organization.id)

    # Oban may deliver the same job again after a timeout or worker restart.
    # A terminal recommendation must make that retry a no-op.
    assert :ok = AutonomousResponseWorker.perform(%Oban.Job{args: job.args})
    assert recommendation_snapshot(recommendation.id, organization.id) == terminal_snapshot

    learning_state = :sys.get_state(TamanduaServer.Response.AnalystLearning)

    assert Enum.count(
             learning_state.decision_history,
             &(&1[:recommendation_id] == recommendation.id)
           ) == 1

    assert Repo.aggregate(from(j in Oban.Job, where: j.id == ^job_id), :count, :id) == 1

    assert MultiTenant.with_organization(organization.id, fn ->
             Repo.aggregate(
               from(r in "autonomous_recommendations", where: r.id == ^recommendation.id),
               :count,
               :id
             )
           end) == 1

    # Simulate a stale cache entry or a replay from another node. The database
    # state wins, no action is dispatched again, and the stale entry is dropped.
    put_pending(recommendation)

    assert {:error, :already_processed} =
             DecisionEngine.approve_recommendation(
               recommendation.id,
               user.id,
               {:organization, organization.id}
             )

    refute Map.has_key?(:sys.get_state(DecisionEngine).pending_recommendations, recommendation.id)
  end

  test "product lock blocks a queued autonomous job before its state transition" do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization, organization_id: organization.id)

    alert =
      insert(:alert,
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id
      )

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    db_now = DateTime.to_naive(now)

    recommendation = %{
      id: Ecto.UUID.generate(),
      alert_id: alert.id,
      agent_id: agent.id,
      organization_id: organization.id,
      severity: "critical",
      confidence_score: 99.0,
      criticality_level: :low,
      suggested_actions: [],
      matching_rules: [],
      auto_execute_eligible: true,
      justification: "worker mode alias test",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    insert_recommendation_row(recommendation, "queued", db_now)

    assert {:error, :autonomous_response_locked} =
             AutonomousResponseWorker.perform(%Oban.Job{
               args: %{
                 "recommendation_id" => recommendation.id,
                 "organization_id" => organization.id,
                 "mode" => "auto"
               }
             })

    assert recommendation_status(recommendation.id, organization.id) == "queued"

    assert {:ok, %{status: "queued"}} =
             DecisionEngine.get_recommendation_status(
               recommendation.id,
               {:organization, organization.id}
             )

    assert {:error, {:invalid_mode, "unsupported"}} =
             DecisionEngine.execute_queued_recommendation(
               recommendation.id,
               organization.id,
               nil,
               "unsupported"
             )
  end

  test "maintenance preserves queued recommendations with an active job and reconciles orphans" do
    organization = insert(:organization)
    user = insert(:user, organization: organization, organization_id: organization.id)
    agent = insert(:agent, organization: organization, organization_id: organization.id)

    alert =
      insert(:alert,
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id
      )

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    stale_db_now = now |> DateTime.add(-25 * 60 * 60, :second) |> DateTime.to_naive()

    active_recommendation = %{
      id: Ecto.UUID.generate(),
      alert_id: alert.id,
      agent_id: agent.id,
      organization_id: organization.id,
      severity: "high",
      confidence_score: 90.0,
      criticality_level: :low,
      suggested_actions: [],
      matching_rules: [],
      auto_execute_eligible: false,
      justification: "queued recommendation with an active job",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    orphan_recommendation = %{
      active_recommendation
      | id: Ecto.UUID.generate(),
        justification: "orphaned queued recommendation"
    }

    insert_recommendation_row(active_recommendation, "queued", stale_db_now)
    insert_recommendation_row(orphan_recommendation, "queued", stale_db_now)

    assert {:ok, job} =
             Oban.insert(
               AutonomousResponseWorker.new(%{
                 recommendation_id: active_recommendation.id,
                 organization_id: organization.id,
                 approver_id: user.id,
                 mode: "approved"
               })
             )

    assert job.state in ["scheduled", "available", "executing", "retryable"]
    active_before = recommendation_snapshot(active_recommendation.id, organization.id)

    assert {:noreply, %DecisionEngine{pending_recommendations: %{}}} =
             DecisionEngine.handle_info(
               :cleanup_stale,
               %DecisionEngine{pending_recommendations: %{}}
             )

    assert recommendation_snapshot(active_recommendation.id, organization.id) == active_before

    orphan_after = recommendation_snapshot(orphan_recommendation.id, organization.id)
    assert orphan_after.status == "execution_unknown"
    assert orphan_after.result["reason"] == "stale_queued_without_active_oban_job"
    assert is_binary(orphan_after.result["reconciled_at"])

    assert %Oban.Job{state: job_state} = Repo.get!(Oban.Job, job.id)
    assert job_state == job.state
  end

  test "maintenance reconciles recent terminal jobs without overriding active jobs or tenants" do
    organization = insert(:organization)
    foreign_organization = insert(:organization)
    agent = insert(:agent, organization: organization, organization_id: organization.id)

    alert =
      insert(:alert,
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id
      )

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    db_now = DateTime.to_naive(now)

    base_recommendation = %{
      id: Ecto.UUID.generate(),
      alert_id: alert.id,
      agent_id: agent.id,
      organization_id: organization.id,
      severity: "high",
      confidence_score: 90.0,
      criticality_level: :low,
      suggested_actions: [],
      matching_rules: [],
      auto_execute_eligible: false,
      justification: "terminal Oban job maintenance",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    cancelled_recommendation = base_recommendation

    discarded_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "discarded Oban job maintenance"
    }

    active_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "active Oban job maintenance"
    }

    terminal_with_active_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "terminal and active Oban jobs maintenance"
    }

    foreign_job_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "foreign tenant Oban job maintenance"
    }

    recommendations = [
      cancelled_recommendation,
      discarded_recommendation,
      active_recommendation,
      terminal_with_active_recommendation,
      foreign_job_recommendation
    ]

    Enum.each(recommendations, &insert_recommendation_row(&1, "queued", db_now))

    insert_job = fn recommendation, organization_id ->
      Oban.insert!(
        AutonomousResponseWorker.new(%{
          recommendation_id: recommendation.id,
          organization_id: organization_id,
          approver_id: nil,
          mode: "approved"
        })
      )
    end

    cancelled_job = insert_job.(cancelled_recommendation, organization.id)
    discarded_job = insert_job.(discarded_recommendation, organization.id)
    active_job = insert_job.(active_recommendation, organization.id)

    terminal_with_active_job =
      insert_job.(terminal_with_active_recommendation, organization.id)

    foreign_job = insert_job.(foreign_job_recommendation, foreign_organization.id)

    Repo.update_all(
      from(j in Oban.Job, where: j.id == ^cancelled_job.id),
      set: [state: "cancelled"]
    )

    Repo.update_all(
      from(j in Oban.Job, where: j.id == ^discarded_job.id),
      set: [state: "discarded"]
    )

    Repo.update_all(
      from(j in Oban.Job, where: j.id == ^terminal_with_active_job.id),
      set: [state: "cancelled"]
    )

    Repo.update_all(
      from(j in Oban.Job, where: j.id == ^foreign_job.id),
      set: [state: "cancelled"]
    )

    second_active_job =
      insert_job.(terminal_with_active_recommendation, organization.id)

    assert Repo.get!(Oban.Job, active_job.id).state in [
             "scheduled",
             "available",
             "executing",
             "retryable"
           ]

    assert Repo.get!(Oban.Job, second_active_job.id).state in [
             "scheduled",
             "available",
             "executing",
             "retryable"
           ]

    assert {:noreply, %DecisionEngine{pending_recommendations: %{}}} =
             DecisionEngine.handle_info(
               :cleanup_stale,
               %DecisionEngine{pending_recommendations: %{}}
             )

    for recommendation <- [cancelled_recommendation, discarded_recommendation] do
      snapshot = recommendation_snapshot(recommendation.id, organization.id)
      assert snapshot.status == "execution_unknown"
      assert snapshot.result["reason"] == "oban_job_terminal_without_execution"
      assert is_binary(snapshot.result["reconciled_at"])
    end

    for recommendation <- [
          active_recommendation,
          terminal_with_active_recommendation,
          foreign_job_recommendation
        ] do
      assert recommendation_status(recommendation.id, organization.id) == "queued"
    end
  end

  test "exhausted Oban retries reconcile only queued recommendations in their tenant" do
    organization = insert(:organization)
    foreign_organization = insert(:organization)
    agent = insert(:agent, organization: organization, organization_id: organization.id)

    alert =
      insert(:alert,
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id
      )

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    db_now = DateTime.to_naive(now)

    base_recommendation = %{
      id: Ecto.UUID.generate(),
      alert_id: alert.id,
      agent_id: agent.id,
      organization_id: organization.id,
      severity: "high",
      confidence_score: 90.0,
      criticality_level: :low,
      suggested_actions: [],
      matching_rules: [],
      auto_execute_eligible: false,
      justification: "Oban retry reconciliation",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    retrying_recommendation = base_recommendation

    exhausted_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "exhausted Oban retry"
    }

    foreign_tenant_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "foreign tenant retry"
    }

    terminal_recommendation = %{
      base_recommendation
      | id: Ecto.UUID.generate(),
        justification: "terminal retry"
    }

    insert_recommendation_row(retrying_recommendation, "queued", db_now)
    insert_recommendation_row(exhausted_recommendation, "queued", db_now)
    insert_recommendation_row(foreign_tenant_recommendation, "queued", db_now)
    insert_recommendation_row(terminal_recommendation, "rejected", db_now)

    job = fn recommendation_id, organization_id, job_id, attempt ->
      %Oban.Job{
        id: job_id,
        attempt: attempt,
        max_attempts: 5,
        args: %{
          "recommendation_id" => recommendation_id,
          "organization_id" => organization_id,
          "mode" => "unsupported"
        }
      }
    end

    assert {:error, {:invalid_mode, "unsupported"}} =
             AutonomousResponseWorker.perform(
               job.(retrying_recommendation.id, organization.id, 91_001, 4)
             )

    assert recommendation_status(retrying_recommendation.id, organization.id) == "queued"

    assert {:error, {:invalid_mode, "unsupported"}} =
             AutonomousResponseWorker.perform(
               job.(exhausted_recommendation.id, organization.id, 91_002, 5)
             )

    exhausted_after =
      recommendation_snapshot(exhausted_recommendation.id, organization.id)

    assert exhausted_after.status == "execution_unknown"
    assert exhausted_after.result["reason"] == "oban_attempts_exhausted"
    assert exhausted_after.result["oban_job_id"] == 91_002
    assert exhausted_after.result["attempt"] == 5
    assert exhausted_after.result["error"] == "invalid_mode"

    foreign_before =
      recommendation_snapshot(foreign_tenant_recommendation.id, organization.id)

    assert {:error, {:invalid_mode, "unsupported"}} =
             AutonomousResponseWorker.perform(
               job.(
                 foreign_tenant_recommendation.id,
                 foreign_organization.id,
                 91_003,
                 5
               )
             )

    assert recommendation_snapshot(foreign_tenant_recommendation.id, organization.id) ==
             foreign_before

    terminal_before = recommendation_snapshot(terminal_recommendation.id, organization.id)

    assert {:error, {:invalid_mode, "unsupported"}} =
             AutonomousResponseWorker.perform(
               job.(terminal_recommendation.id, organization.id, 91_004, 5)
             )

    assert recommendation_snapshot(terminal_recommendation.id, organization.id) ==
             terminal_before
  end

  defp replace_state(fun), do: :sys.replace_state(DecisionEngine, fun)

  defp put_pending(recommendation) do
    replace_state(fn state ->
      %{state |
        pending_recommendations:
          Map.put(state.pending_recommendations, recommendation.id, recommendation)
      }
    end)
  end

  defp recommendation_status(recommendation_id, organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.one(
        from(r in "autonomous_recommendations",
          where: r.id == ^recommendation_id,
          select: r.status
        )
      )
    end)
  end

  defp recommendation_snapshot(recommendation_id, organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.one!(
        from(r in "autonomous_recommendations",
          where: r.id == ^recommendation_id,
          select: %{
            status: r.status,
            result: r.result,
            approved_by: r.approved_by,
            executed_at: r.executed_at,
            updated_at: r.updated_at
          }
        )
      )
    end)
  end

  defp insert_recommendation_row(recommendation, status, db_now) do
    MultiTenant.with_organization(recommendation.organization_id, fn ->
      Repo.insert_all("autonomous_recommendations", [
        %{
          id: recommendation.id,
          alert_id: recommendation.alert_id,
          agent_id: recommendation.agent_id,
          organization_id: recommendation.organization_id,
          severity: recommendation.severity,
          confidence_score: recommendation.confidence_score,
          criticality_level: "low",
          suggested_actions: recommendation.suggested_actions,
          matching_rules: recommendation.matching_rules,
          auto_execute_eligible: recommendation.auto_execute_eligible,
          justification: recommendation.justification,
          status: status,
          expires_at: DateTime.to_naive(recommendation.expires_at),
          inserted_at: db_now,
          updated_at: db_now
        }
      ])
    end)
  end

  defp drop_keys(map, keys), do: Enum.reduce(keys, map, &Map.delete(&2, &1))

  defp metrics(total) do
    %{
      total_responses: total,
      successful_responses: total,
      failed_responses: 0,
      rollbacks: 0,
      avg_response_time_ms: 10.0,
      min_response_time_ms: 10,
      max_response_time_ms: 10,
      responses_by_type: %{},
      responses_by_hour: [],
      mttr_samples: []
    }
  end
end
