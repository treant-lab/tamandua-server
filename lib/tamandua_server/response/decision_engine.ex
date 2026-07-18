defmodule TamanduaServer.Response.DecisionEngine do
  @moduledoc """
  ML-driven Response Decision Engine - SentinelOne-class Autonomous Response

  Achieves sub-second decision making for autonomous threat response:
  - Evaluates alert severity, confidence, and asset criticality in <100ms
  - Parallel action execution for multi-step responses
  - Automatic rollback on failure
  - Impact assessment before action
  - ML-based response recommendations

  Performance targets:
  - Decision time: <100ms
  - Single action execution: <500ms
  - Full containment (isolate + kill + quarantine): <1000ms

  The engine implements safeguards:
  - Rate limiting on autonomous actions
  - Maximum actions per hour per tenant
  - Critical asset exclusion by default
  - Emergency disable switch
  - Automatic rollback on cascading failures
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.DecisionEngineAuthorityAccess
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Response.{Executor, AutonomousRules, AnalystLearning}
  alias TamanduaServer.Workers.AutonomousResponseWorker
  alias TamanduaServer.Detection.Confidence
  alias TamanduaServer.Assets.Criticality

  # Performance thresholds (ms)
  @action_timeout 500
  @full_response_timeout 1000

  # Rate limiting defaults
  @default_max_actions_per_hour 100
  @default_max_actions_per_minute 20
  @default_critical_asset_protection true
  @default_autonomous_enabled false

  # Risk weights for different action types
  @action_risk_weights %{
    "kill_process" => 0.2,
    "quarantine_file" => 0.3,
    "block_ip" => 0.3,
    "block_domain" => 0.3,
    "isolate_network" => 0.7,
    "disable_user" => 0.8,
    "full_remediation" => 0.9,
    "collect_forensics" => 0.1,
    "trigger_scan" => 0.1
  }

  # GenServer state
  defstruct [
    :settings,
    :action_counts,
    :pending_recommendations,
    :emergency_disabled,
    :autonomous_armed,
    :restore_status,
    :response_metrics,
    :rollback_registry
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Evaluate an alert and determine if autonomous response should be taken.
  Returns a recommendation with suggested actions and risk scores.
  """
  @spec evaluate_alert(Alert.t()) :: {:ok, map()} | {:error, term()}
  def evaluate_alert(%Alert{} = alert) do
    GenServer.call(__MODULE__, {:evaluate_alert, alert})
  end

  @doc """
  Get all pending recommendations awaiting approval.
  """
  @spec get_pending_recommendations(String.t() | nil) ::
          {:ok, [map()]} | {:error, :tenant_required}
  def get_pending_recommendations(org_id \\ nil) do
    GenServer.call(__MODULE__, {:get_pending, org_id})
  end

  @doc """
  Approve a pending recommendation and execute the response.
  """
  @spec approve_recommendation(String.t(), String.t(), term()) ::
          {:ok, map()} | {:error, term()}
  def approve_recommendation(recommendation_id, approver_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:approve, recommendation_id, approver_id, scope})
  end

  @doc "Get the durable execution status for one recommendation."
  @spec get_recommendation_status(String.t(), term()) :: {:ok, map()} | {:error, term()}
  def get_recommendation_status(recommendation_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:recommendation_status, recommendation_id, scope})
  end

  @doc """
  Reject a pending recommendation.
  """
  @spec reject_recommendation(String.t(), String.t(), String.t(), term()) ::
          {:ok, map()} | {:error, term()}
  def reject_recommendation(recommendation_id, rejector_id, reason, scope \\ nil) do
    GenServer.call(__MODULE__, {:reject, recommendation_id, rejector_id, reason, scope})
  end

  @doc """
  Get autonomous action history.
  """
  @spec get_action_history(keyword()) :: {:ok, [map()]} | {:error, :tenant_required}
  def get_action_history(opts \\ []) do
    GenServer.call(__MODULE__, {:get_history, opts})
  end

  @doc """
  Update engine settings for an organization.
  """
  @spec update_settings(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def update_settings(org_id, settings) do
    GenServer.call(__MODULE__, {:update_settings, org_id, settings})
  end

  @doc """
  Get current engine settings.
  """
  @spec get_settings(String.t() | nil) :: {:ok, map()} | {:error, :tenant_required}
  def get_settings(org_id) do
    GenServer.call(__MODULE__, {:get_settings, org_id})
  end

  @doc """
  Emergency disable all autonomous responses.
  """
  @spec emergency_disable(String.t() | nil, String.t()) :: :ok | {:error, :tenant_required}
  def emergency_disable(org_id, reason) when is_binary(org_id) and org_id != "" do
    GenServer.call(__MODULE__, {:emergency_disable, org_id, reason})
  end

  def emergency_disable(_org_id, _reason), do: {:error, :tenant_required}

  @doc """
  Re-enable autonomous responses after emergency disable.
  """
  @spec emergency_enable(String.t() | nil, String.t()) ::
          :ok | {:error, :tenant_required | :autonomous_response_locked}
  def emergency_enable(org_id, approver_id) when is_binary(org_id) and org_id != "" do
    GenServer.call(__MODULE__, {:emergency_enable, org_id, approver_id})
  end

  def emergency_enable(_org_id, _approver_id), do: {:error, :tenant_required}

  @doc """
  Get current rate limit status.
  """
  @spec rate_limit_status(String.t() | nil) :: map() | {:error, :tenant_required}
  def rate_limit_status(org_id) do
    GenServer.call(__MODULE__, {:rate_limit_status, org_id})
  end

  @doc """
  Calculate risk score for a specific action on an asset.
  """
  @spec calculate_action_risk(String.t(), String.t(), map()) :: float()
  def calculate_action_risk(action_type, agent_id, context \\ %{}) do
    GenServer.call(__MODULE__, {:calculate_risk, action_type, agent_id, context})
  end

  @doc """
  Execute rapid autonomous response (sub-second containment).
  This is the fastest path for critical threats.
  """
  @spec rapid_response(Alert.t()) :: {:ok, map()} | {:error, term()}
  def rapid_response(%Alert{} = alert) do
    GenServer.call(__MODULE__, {:rapid_response, alert}, @full_response_timeout + 500)
  end

  @doc """
  Execute parallel response actions for faster containment.
  """
  @spec parallel_response(String.t(), [map()], term()) :: {:ok, map()} | {:error, term()}
  def parallel_response(agent_id, actions, scope \\ nil) do
    GenServer.call(__MODULE__, {:parallel_response, agent_id, actions, scope})
  end

  @doc """
  Get response metrics (MTTR, success rate, etc).
  """
  @spec get_response_metrics(term()) :: {:ok, map()} | {:error, :tenant_required}
  def get_response_metrics(scope \\ nil) do
    GenServer.call(__MODULE__, {:get_metrics, scope})
  end

  @doc """
  Rollback a response action.
  """
  @spec rollback_response(String.t(), term()) :: {:ok, map()} | {:error, term()}
  def rollback_response(response_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:rollback, response_id, scope})
  end

  @doc false
  def execute_queued_recommendation(
        recommendation_id,
        organization_id,
        approver_id,
        mode
      )
      when mode in ["approved", "auto_executed"] do
    with :ok <- queued_execution_interlock(mode, organization_id) do
      do_execute_queued_recommendation(recommendation_id, organization_id, approver_id, mode)
    end
  end

  def execute_queued_recommendation(_recommendation_id, _organization_id, _approver_id, mode) do
    {:error, {:invalid_mode, mode}}
  end

  defp do_execute_queued_recommendation(
         recommendation_id,
         organization_id,
         approver_id,
         mode
       ) do
    case load_recommendation_for_status(recommendation_id, organization_id, "queued") do
      nil ->
        # Oban retry after the worker crossed queued->executing must never
        # redispatch. Maintenance will reconcile an orphaned executing row.
        :ok

      {:error, reason} ->
        {:error, reason}

      recommendation ->
        with :ok <-
               transition_recommendation(
                 recommendation,
                 "queued",
                 "executing",
                 approved_by: approver_id,
                 result: %{started_at: DateTime.utc_now(), mode: mode}
               ) do
          case queued_execution_interlock(mode, organization_id) do
            :ok ->
              execute_claimed_recommendation(recommendation, approver_id, mode)

            {:error, _reason} = interlock_error ->
              case requeue_after_execution_failure(
                     recommendation,
                     approver_id,
                     mode,
                     :autonomous_response_locked_before_execution
                   ) do
                {:error, {:execution_interrupted, _failure}} -> interlock_error
                {:error, _reason} = requeue_error -> requeue_error
              end
          end
        end
    end
  end

  defp queued_execution_interlock("approved", _organization_id), do: :ok

  defp queued_execution_interlock("auto_executed", organization_id) do
    try do
      GenServer.call(__MODULE__, {:autonomous_dispatch_status, organization_id})
    catch
      :exit, _reason -> {:error, :autonomous_response_locked}
    end
  end

  @doc false
  def reconcile_exhausted_recommendation(
        recommendation_id,
        organization_id,
        job_id,
        attempt,
        error_summary
      ) do
    case load_recommendation_for_status(recommendation_id, organization_id, "queued") do
      nil ->
        :ok

      {:error, reason} ->
        {:error, reason}

      recommendation ->
        reconciliation_result = %{
          reason: "oban_attempts_exhausted",
          oban_job_id: job_id,
          attempt: attempt,
          error: error_summary,
          previous_result: recommendation.result || %{},
          reconciled_at: DateTime.utc_now()
        }

        case transition_recommendation(
               recommendation,
               "queued",
               "execution_unknown",
               result: reconciliation_result,
               executed_at: DateTime.utc_now()
             ) do
          :ok ->
            log_audit_event(recommendation.organization_id, :autonomous_execution_exhausted, %{
              recommendation_id: recommendation.id,
              alert_id: recommendation.alert_id,
              agent_id: recommendation.agent_id,
              oban_job_id: job_id,
              attempt: attempt,
              error: error_summary,
              previous_result: recommendation.result || %{}
            })

            :ok

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp execute_claimed_recommendation(recommendation, approver_id, mode) do
    try do
      result =
        if mode == "auto_executed" do
          execute_autonomous_response(recommendation, nil)
        else
          execute_recommendation(recommendation, approver_id, nil)
        end

      terminal_status = terminal_status(result, mode)

      finalization =
        finalize_recommendation(
          recommendation,
          "executing",
          terminal_status,
          approver_id,
          %{results: persisted_execution_results(result)}
        )

      reply =
        case finalization do
          :ok -> execution_reply(result)
          {:error, reason} -> {:error, {:execution_state_unknown, reason}}
        end

      if finalization == :ok and mode == "approved" do
        record_decision(recommendation, approver_id, :approved, reply)
      end

      case finalization do
        :ok ->
          :ok

        {:error, reason} ->
          requeue_after_execution_failure(
            recommendation,
            approver_id,
            mode,
            {:finalization_failed, reason}
          )
      end
    rescue
      error ->
        requeue_after_execution_failure(
          recommendation,
          approver_id,
          mode,
          {:exception, Exception.message(error)}
        )
    catch
      kind, reason ->
        requeue_after_execution_failure(
          recommendation,
          approver_id,
          mode,
          {kind, inspect(reason)}
        )
    end
  end

  defp requeue_after_execution_failure(recommendation, approver_id, mode, failure) do
    Logger.error(
      "Autonomous recommendation execution interrupted for #{recommendation.id}: " <>
        inspect(failure)
    )

    case transition_recommendation(
           recommendation,
           "executing",
           "queued",
           approved_by: approver_id,
           result: %{
             retry_reason: inspect(failure),
             retry_mode: mode,
             requeued_at: DateTime.utc_now()
           }
         ) do
      :ok -> {:error, {:execution_interrupted, failure}}
      {:error, reason} -> {:error, {:execution_state_unknown, reason, failure}}
    end
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Response Decision Engine - autonomous response starts disarmed")

    {restore_status, settings, pending_recommendations} = restore_persisted_state()

    state = %__MODULE__{
      settings: settings,
      action_counts: %{},
      pending_recommendations: pending_recommendations,
      emergency_disabled: MapSet.new(),
      autonomous_armed: MapSet.new(),
      restore_status: restore_status,
      response_metrics: %{},
      rollback_registry: %{}
    }

    # Schedule periodic cleanup
    schedule_cleanup()
    schedule_rate_limit_reset()
    schedule_metrics_aggregation()

    {:ok, state}
  end

  defp init_metrics do
    %{
      total_responses: 0,
      successful_responses: 0,
      failed_responses: 0,
      rollbacks: 0,
      avg_response_time_ms: 0,
      min_response_time_ms: nil,
      max_response_time_ms: 0,
      responses_by_type: %{},
      responses_by_hour: [],
      mttr_samples: []
    }
  end

  @impl true
  def handle_call({:evaluate_alert, %{organization_id: organization_id} = alert}, _from, state)
      when is_binary(organization_id) and organization_id != "" do
    result = do_evaluate_alert(alert, state)
    {:reply, result, state}
  end

  def handle_call({:evaluate_alert, _alert}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:get_pending, org_id}, _from, state)
      when is_binary(org_id) and org_id != "" do
    pending =
      state.pending_recommendations
      |> Map.values()
      |> Enum.filter(&(&1.organization_id == org_id))

    {:reply, {:ok, pending}, state}
  end

  def handle_call({:get_pending, _org_id}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call(
        {:approve, recommendation_id, approver_id, {:organization, organization_id}},
        _from,
        state
      )
      when is_binary(organization_id) and organization_id != "" do
    case pending_recommendation(state, recommendation_id, organization_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{organization_id: ^organization_id} = recommendation ->
        case enqueue_recommendation_execution(recommendation, approver_id, "approved") do
          {:ok, job} ->
            accepted = %{
              recommendation_id: recommendation.id,
              status: :queued,
              job_id: job.id,
              accepted_at: DateTime.utc_now()
            }

            new_state = drop_pending_recommendation(state, recommendation_id)

            {:reply, {:ok, accepted}, new_state}

          {:error, :not_pending} ->
            {:reply, {:error, :already_processed},
             drop_pending_recommendation(state, recommendation_id)}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      _other_tenant ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:approve, _recommendation_id, _approver_id, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call(
        {:reject, recommendation_id, rejector_id, reason, {:organization, organization_id}},
        _from,
        state
      )
      when is_binary(organization_id) and organization_id != "" do
    case pending_recommendation(state, recommendation_id, organization_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{organization_id: ^organization_id} = recommendation ->
        case reject_pending_recommendation(recommendation, rejector_id, reason) do
          :ok ->
            result = %{status: :rejected, reason: reason}
            record_decision(recommendation, rejector_id, :rejected, result)

            {:reply, {:ok, result}, drop_pending_recommendation(state, recommendation_id)}

          {:error, :not_pending} ->
            {:reply, {:error, :already_processed},
             drop_pending_recommendation(state, recommendation_id)}

          {:error, persistence_error} ->
            {:reply, {:error, persistence_error}, state}
        end

      {:error, persistence_error} ->
        {:reply, {:error, persistence_error}, state}

      _other_tenant ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:reject, _recommendation_id, _rejector_id, _reason, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call(
        {:recommendation_status, recommendation_id, {:organization, organization_id}},
        _from,
        state
      )
      when is_binary(organization_id) and organization_id != "" do
    {:reply, load_recommendation_status(recommendation_id, organization_id), state}
  end

  def handle_call({:recommendation_status, _recommendation_id, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:get_history, opts}, _from, state) when is_list(opts) do
    case Keyword.get(opts, :organization_id) do
      organization_id when is_binary(organization_id) and organization_id != "" ->
        {:reply, {:ok, load_action_history(opts)}, state}

      _missing_scope ->
        {:reply, {:error, :tenant_required}, state}
    end
  end

  def handle_call({:get_history, _opts}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:update_settings, org_id, new_settings}, _from, state)
      when is_binary(org_id) and org_id != "" and is_map(new_settings) do
    merged =
      state.settings
      |> get_org_settings(org_id)
      |> Map.merge(new_settings)
      |> normalize_settings()

    case save_settings(org_id, merged) do
      :ok ->
        new_state = %{
          state
          | settings: Map.put(state.settings, org_id, merged),
            autonomous_armed:
              if(merged.autonomous_enabled,
                do: state.autonomous_armed,
                else: MapSet.delete(state.autonomous_armed, org_id)
              )
        }

        {:reply, {:ok, merged}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:update_settings, _org_id, _new_settings}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:get_settings, org_id}, _from, state)
      when is_binary(org_id) and org_id != "" do
    settings = get_org_settings(state.settings, org_id)
    {:reply, {:ok, settings}, state}
  end

  def handle_call({:get_settings, _org_id}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:autonomous_dispatch_status, org_id}, _from, state)
      when is_binary(org_id) and org_id != "" do
    {:reply, autonomous_dispatch_interlock(org_id, state), state}
  end

  def handle_call({:autonomous_dispatch_status, _org_id}, _from, state),
    do: {:reply, {:error, :autonomous_response_locked}, state}

  @impl true
  def handle_call({:rate_limit_status, org_id}, _from, state)
      when is_binary(org_id) and org_id != "" do
    counts = Map.get(state.action_counts, org_id, %{minute: 0, hour: 0})
    settings = get_org_settings(state.settings, org_id)

    status = %{
      current_minute: counts.minute,
      max_per_minute: settings.max_actions_per_minute,
      current_hour: counts.hour,
      max_per_hour: settings.max_actions_per_hour,
      is_limited:
        counts.minute >= settings.max_actions_per_minute or
          counts.hour >= settings.max_actions_per_hour,
      emergency_disabled: MapSet.member?(state.emergency_disabled, org_id)
    }

    {:reply, status, state}
  end

  def handle_call({:rate_limit_status, _org_id}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:calculate_risk, action_type, agent_id, context}, _from, state) do
    risk = do_calculate_action_risk(action_type, agent_id, context)
    {:reply, risk, state}
  end

  @impl true
  def handle_call({:rapid_response, %{organization_id: organization_id} = alert}, _from, state)
      when is_binary(organization_id) and organization_id != "" do
    start_time = System.monotonic_time(:millisecond)
    response_id = generate_response_id()

    Logger.info("Rapid response initiated for alert #{alert.id}, response_id: #{response_id}")

    # Determine optimal response actions based on alert type
    actions = determine_rapid_response_actions(alert)

    # Execute all actions in parallel for speed. The actor scope is repeated at
    # the final dispatch boundary so a stale/mismatched alert cannot target a
    # different tenant's agent.
    actor = %{organization_id: organization_id, user_id: :system}
    results = execute_parallel_actions(alert.agent_id, actions, actor)

    duration_ms = System.monotonic_time(:millisecond) - start_time

    response = %{
      response_id: response_id,
      alert_id: alert.id,
      agent_id: alert.agent_id,
      organization_id: organization_id,
      actions: results,
      duration_ms: duration_ms,
      success: all_actions_successful?(results),
      executed_at: DateTime.utc_now()
    }

    # Update metrics
    new_metrics =
      state.response_metrics
      |> metrics_for(organization_id)
      |> update_metrics(response)

    response_metrics = Map.put(state.response_metrics, organization_id, new_metrics)

    # Register for potential rollback
    new_rollback =
      Map.put(state.rollback_registry, response_id, %{
        response: response,
        created_at: DateTime.utc_now()
      })

    Logger.info("Rapid response #{response_id} completed in #{duration_ms}ms")

    {:reply, {:ok, response},
     %{state | response_metrics: response_metrics, rollback_registry: new_rollback}}
  end

  def handle_call({:rapid_response, _alert}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call(
        {:parallel_response, agent_id, actions, {:organization, organization_id}},
        _from,
        state
      )
      when is_binary(organization_id) and organization_id != "" do
    if lookup_agent_organization(agent_id) != organization_id do
      {:reply, {:error, :unauthorized_agent}, state}
    else
      start_time = System.monotonic_time(:millisecond)
      response_id = generate_response_id()

      # Execute all actions in parallel
      actor = %{organization_id: organization_id, user_id: :system}
      results = execute_parallel_actions(agent_id, actions, actor)

      duration_ms = System.monotonic_time(:millisecond) - start_time

      response = %{
        response_id: response_id,
        agent_id: agent_id,
        organization_id: organization_id,
        actions: results,
        duration_ms: duration_ms,
        success: all_actions_successful?(results),
        executed_at: DateTime.utc_now()
      }

      # Update metrics
      new_metrics =
        state.response_metrics
        |> metrics_for(organization_id)
        |> update_metrics(response)

      new_rollback =
        Map.put(state.rollback_registry, response_id, %{
          response: response,
          created_at: DateTime.utc_now()
        })

      {:reply, {:ok, response},
       %{
         state
         | response_metrics: Map.put(state.response_metrics, organization_id, new_metrics),
           rollback_registry: new_rollback
       }}
    end
  end

  def handle_call({:parallel_response, _agent_id, _actions, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:get_metrics, {:organization, organization_id}}, _from, state)
      when is_binary(organization_id) and organization_id != "" do
    organization_metrics = metrics_for(state.response_metrics, organization_id)

    metrics =
      organization_metrics
      |> Map.put(:current_hour, current_hour_stats(organization_metrics))
      |> Map.put(:mttr_minutes, calculate_mttr(organization_metrics.mttr_samples))

    {:reply, {:ok, metrics}, state}
  end

  def handle_call({:get_metrics, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:rollback, response_id, {:organization, organization_id}}, _from, state)
      when is_binary(organization_id) and organization_id != "" do
    case Map.get(state.rollback_registry, response_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{response: %{organization_id: ^organization_id} = response} ->
        Logger.info("Initiating rollback for response #{response_id}")

        rollback_results = execute_rollback(response)

        organization_metrics = metrics_for(state.response_metrics, organization_id)
        new_metrics = %{organization_metrics | rollbacks: organization_metrics.rollbacks + 1}
        response_metrics = Map.put(state.response_metrics, organization_id, new_metrics)

        new_registry = Map.delete(state.rollback_registry, response_id)

        {:reply,
         {:ok,
          %{
            response_id: response_id,
            rollback_results: rollback_results
          }}, %{state | response_metrics: response_metrics, rollback_registry: new_registry}}

      _other_tenant ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:rollback, _response_id, _scope}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:emergency_disable, org_id, reason}, _from, state)
      when is_binary(org_id) and org_id != "" do
    Logger.warning("Emergency disable triggered for org #{org_id}: #{reason}")

    new_disabled = MapSet.put(state.emergency_disabled, org_id)

    # Log audit event
    log_audit_event(org_id, :emergency_disable, %{reason: reason})

    {:reply, :ok,
     %{
       state
       | emergency_disabled: new_disabled,
         autonomous_armed: MapSet.delete(state.autonomous_armed, org_id)
     }}
  end

  def handle_call({:emergency_disable, _org_id, _reason}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_call({:emergency_enable, org_id, approver_id}, _from, state)
      when is_binary(org_id) and org_id != "" do
    if state.restore_status == :ready and product_autonomous_response_enabled?() and
         get_org_settings(state.settings, org_id).autonomous_enabled == true do
      Logger.info("Emergency enable by #{approver_id} for org #{org_id}")
      log_audit_event(org_id, :emergency_enable, %{approver_id: approver_id})

      {:reply, :ok,
       %{
         state
         | emergency_disabled: MapSet.delete(state.emergency_disabled, org_id),
           autonomous_armed: MapSet.put(state.autonomous_armed, org_id)
       }}
    else
      Logger.warning("Emergency enable rejected because autonomous response is locked")
      {:reply, {:error, :autonomous_response_locked}, state}
    end
  end

  def handle_call({:emergency_enable, _org_id, _approver_id}, _from, state),
    do: {:reply, {:error, :tenant_required}, state}

  @impl true
  def handle_cast({:queue_recommendation, recommendation}, state) do
    pending = Map.put(state.pending_recommendations, recommendation.id, recommendation)
    {:noreply, %{state | pending_recommendations: pending}}
  end

  @impl true
  def handle_cast({:drop_pending_recommendation, recommendation_id}, state) do
    {:noreply, drop_pending_recommendation(state, recommendation_id)}
  end

  @impl true
  def handle_cast({:increment_counts, org_id}, state)
      when is_binary(org_id) and org_id != "" do
    counts = Map.get(state.action_counts, org_id, %{minute: 0, hour: 0})
    updated = %{minute: counts.minute + 1, hour: counts.hour + 1}

    {:noreply, %{state | action_counts: Map.put(state.action_counts, org_id, updated)}}
  end

  def handle_cast({:increment_counts, _org_id}, state), do: {:noreply, state}

  @impl true
  def handle_info(:cleanup_stale, state) do
    # Remove recommendations older than 24 hours
    cutoff = DateTime.add(DateTime.utc_now(), -24 * 3600, :second)

    new_pending =
      state.pending_recommendations
      |> Enum.reject(fn {_id, rec} ->
        DateTime.compare(rec.created_at, cutoff) == :lt
      end)
      |> Map.new()

    expired_count = map_size(state.pending_recommendations) - map_size(new_pending)

    if expired_count > 0 do
      Logger.info("Cleaned up #{expired_count} stale recommendations")
    end

    maintenance_result = maintain_persisted_recommendation_states()

    schedule_cleanup()

    case maintenance_result do
      :ok ->
        {:noreply, %{state | pending_recommendations: new_pending}}

      {:error, _reason} ->
        {:noreply,
         %{
           state
           | pending_recommendations: new_pending,
             restore_status: :degraded,
             autonomous_armed: MapSet.new()
         }}
    end
  end

  @impl true
  def handle_info(:reset_minute_counts, state) do
    # Reset minute counters
    new_counts =
      state.action_counts
      |> Enum.map(fn {org_id, counts} ->
        {org_id, %{counts | minute: 0}}
      end)
      |> Map.new()

    schedule_rate_limit_reset()
    {:noreply, %{state | action_counts: new_counts}}
  end

  @impl true
  def handle_info(:reset_hour_counts, state) do
    # Reset hour counters
    new_counts =
      state.action_counts
      |> Enum.map(fn {org_id, _counts} ->
        {org_id, %{minute: 0, hour: 0}}
      end)
      |> Map.new()

    {:noreply, %{state | action_counts: new_counts}}
  end

  @impl true
  def handle_info(:aggregate_metrics, state) do
    # Retain bounded samples per tenant. Response-time averages remain in
    # milliseconds; MTTR samples are minutes and must not overwrite them.
    updated_metrics =
      Map.new(state.response_metrics, fn {organization_id, metrics} ->
        {organization_id,
         %{
           metrics
           | mttr_samples: Enum.take(metrics.mttr_samples || [], 100),
             responses_by_hour: Enum.take(metrics.responses_by_hour || [], 168)
         }}
      end)

    schedule_metrics_aggregation()
    {:noreply, %{state | response_metrics: updated_metrics}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_evaluate_alert(alert, state) do
    org_id = alert.organization_id
    settings = get_org_settings(state.settings, org_id)

    if not product_autonomous_response_enabled?() do
      {:ok, %{status: :product_locked, reason: "Autonomous response product lock is off"}}
    else
      unless settings.autonomous_enabled do
        {:ok, %{status: :disabled, reason: "Autonomous responses disabled for organization"}}
      else
        # Check emergency disable
        if MapSet.member?(state.emergency_disabled, org_id) or
             not MapSet.member?(state.autonomous_armed, org_id) do
          {:ok, %{status: :emergency_disabled, reason: "Autonomous responses emergency disabled"}}
        else
          # Calculate confidence score
          confidence = Confidence.calculate(alert)

          # Get asset criticality
          criticality = Criticality.get_criticality(alert.agent_id)

          # Get applicable rules
          rules = AutonomousRules.get_matching_rules(alert, org_id)

          # Get ML-based recommendations from analyst learning
          ml_suggestions = AnalystLearning.get_recommendations(alert)

          # Generate response recommendation
          recommendation =
            generate_recommendation(
              alert,
              confidence,
              criticality,
              rules,
              ml_suggestions,
              settings
            )

          # Check if any rule allows automatic execution
          auto_execute? = should_auto_execute?(recommendation, settings, state)

          if auto_execute? do
            # Check rate limits
            if within_rate_limits?(org_id, state) do
              case persist_and_execute_autonomous_response(recommendation, state) do
                {:ok, result} ->
                  increment_action_counts(org_id)

                  {:ok,
                   %{
                     status: autonomous_response_status(result),
                     recommendation: recommendation,
                     result: result
                   }}

                {:error, {:execution_state_unknown, reason}} ->
                  {:ok,
                   %{
                     status: :execution_unknown,
                     recommendation: recommendation,
                     reason: reason,
                     retryable: false,
                     message:
                       "Actions may have been dispatched; manual reconciliation is required"
                   }}

                {:error, reason} ->
                  {:ok,
                   %{
                     status: :persistence_degraded,
                     recommendation: recommendation,
                     reason: reason,
                     retryable: true,
                     message: "Autonomous response was not dispatched because persistence failed"
                   }}
              end
            else
              # Queue for manual approval due to rate limiting
              queue_result(
                queue_recommendation(recommendation, state),
                :rate_limited,
                recommendation,
                "Queued for approval due to rate limiting"
              )
            end
          else
            # Queue for manual approval
            queue_result(
              queue_recommendation(recommendation, state),
              :pending_approval,
              recommendation,
              "Queued for manual approval"
            )
          end
        end
      end
    end
  end

  defp generate_recommendation(alert, confidence, criticality, rules, ml_suggestions, settings) do
    # Determine suggested actions based on rules and ML
    suggested_actions = determine_actions(alert, rules, ml_suggestions)

    # Calculate risk scores for each action
    actions_with_risk =
      Enum.map(suggested_actions, fn action ->
        risk =
          do_calculate_action_risk(action.type, alert.agent_id, %{
            alert: alert,
            confidence: confidence,
            criticality: criticality
          })

        Map.put(action, :risk_score, risk)
      end)

    # Filter actions based on risk tolerance
    filtered_actions =
      if settings.critical_asset_protection and criticality.level in [:critical, :high] do
        Enum.filter(actions_with_risk, fn action ->
          # Only low-risk actions for critical assets
          action.risk_score < 0.5
        end)
      else
        actions_with_risk
      end

    # Build recommendation
    %{
      id: Ecto.UUID.generate(),
      alert_id: alert.id,
      agent_id: alert.agent_id,
      organization_id: alert.organization_id,
      severity: alert.severity,
      confidence_score: confidence.score,
      confidence_factors: confidence.factors,
      criticality_level: criticality.level,
      criticality_score: criticality.score,
      suggested_actions: filtered_actions,
      matching_rules: Enum.map(rules, & &1.id),
      ml_confidence: ml_suggestions[:confidence] || 0.0,
      auto_execute_eligible: eligible_for_auto_execute?(alert, confidence, criticality, rules),
      justification: build_justification(alert, confidence, criticality, rules),
      created_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 24 * 3600, :second)
    }
  end

  defp determine_actions(alert, rules, ml_suggestions) do
    # Start with rule-based actions
    rule_actions =
      rules
      |> Enum.flat_map(fn rule -> rule.actions || [] end)
      |> Enum.uniq_by(& &1.type)

    # Add ML-suggested actions if not already present
    ml_actions =
      (ml_suggestions[:actions] || [])
      |> Enum.reject(fn action ->
        Enum.any?(rule_actions, fn ra -> ra.type == action.type end)
      end)

    # Combine and sort by confidence
    all_actions = rule_actions ++ ml_actions

    # Add context-specific actions based on alert type
    context_actions =
      case alert.severity do
        "critical" ->
          # For critical alerts, suggest isolation if not already present
          if not Enum.any?(all_actions, &(&1.type == "isolate_network")) do
            [%{type: "isolate_network", params: %{}, source: :severity_escalation}]
          else
            []
          end

        "high" ->
          # For high severity, suggest quarantine or kill
          if not Enum.any?(all_actions, &(&1.type in ["quarantine_file", "kill_process"])) do
            [%{type: "kill_process", params: %{}, source: :severity_escalation}]
          else
            []
          end

        _ ->
          []
      end

    (all_actions ++ context_actions)
    |> Enum.map(fn action ->
      %{
        type: action[:type] || action["type"],
        params: action[:params] || action["params"] || %{},
        source: action[:source] || :rule,
        priority: action_priority(action[:type] || action["type"])
      }
    end)
    |> Enum.sort_by(& &1.priority, :desc)
  end

  defp action_priority(action_type) do
    case action_type do
      "kill_process" -> 5
      "quarantine_file" -> 4
      "block_ip" -> 3
      "block_domain" -> 3
      "isolate_network" -> 2
      "collect_forensics" -> 1
      _ -> 0
    end
  end

  defp do_calculate_action_risk(action_type, agent_id, context) do
    # Base risk from action type
    base_risk = Map.get(@action_risk_weights, action_type, 0.5)

    # Adjust for asset criticality
    criticality =
      case context[:criticality] do
        %{score: score} -> score
        _ -> Criticality.get_criticality(agent_id).score
      end

    # Normalize to 0-1
    criticality_factor = criticality / 100

    # Adjust for confidence (higher confidence = lower risk)
    confidence =
      case context[:confidence] do
        %{score: score} -> score
        _ -> 50
      end

    # Lower confidence = higher risk
    confidence_factor = 1 - confidence / 100

    # Calculate final risk
    risk = base_risk * (1 + criticality_factor * 0.5) * (1 + confidence_factor * 0.3)

    min(risk, 1.0)
  end

  defp eligible_for_auto_execute?(alert, confidence, criticality, rules) do
    # Check if any rule explicitly allows auto-execution
    has_auto_rule =
      Enum.any?(rules, fn rule ->
        rule.auto_execute == true
      end)

    # Must meet minimum thresholds
    meets_thresholds =
      confidence.score >= 85 and
        alert.severity in ["critical", "high"] and
        criticality.level in [:low, :medium]

    has_auto_rule and meets_thresholds
  end

  defp should_auto_execute?(recommendation, settings, _state) do
    recommendation.auto_execute_eligible and
      settings.autonomous_enabled and
      recommendation.confidence_score >= settings.min_confidence_for_auto and
      (not settings.critical_asset_protection or
         recommendation.criticality_level not in [:critical, :high])
  end

  defp autonomous_dispatch_interlock(org_id, state) do
    settings = get_org_settings(state.settings, org_id)

    if state.restore_status == :ready and product_autonomous_response_enabled?() and
         settings.autonomous_enabled == true and
         MapSet.member?(state.autonomous_armed, org_id) and
         not MapSet.member?(state.emergency_disabled, org_id) do
      :ok
    else
      {:error, :autonomous_response_locked}
    end
  end

  defp product_autonomous_response_enabled? do
    Application.get_env(
      :tamandua_server,
      :decision_engine_autonomous_response_enabled,
      false
    ) == true
  end

  defp within_rate_limits?(org_id, state) do
    counts = Map.get(state.action_counts, org_id, %{minute: 0, hour: 0})
    settings = get_org_settings(state.settings, org_id)

    counts.minute < settings.max_actions_per_minute and
      counts.hour < settings.max_actions_per_hour
  end

  defp increment_action_counts(org_id) do
    GenServer.cast(__MODULE__, {:increment_counts, org_id})
  end

  defp persist_and_execute_autonomous_response(recommendation, state) do
    with :ok <- autonomous_dispatch_interlock(recommendation.organization_id, state),
         {:ok, job} <- enqueue_new_autonomous_recommendation(recommendation) do
      accepted = %{
        recommendation_id: recommendation.id,
        status: :queued,
        job_id: job.id,
        accepted_at: DateTime.utc_now()
      }

      {:ok, accepted}
    end
  end

  defp queue_result(:ok, status, recommendation, message) do
    {:ok, %{status: status, recommendation: recommendation, message: message}}
  end

  defp queue_result({:error, reason}, _status, recommendation, _message) do
    {:ok,
     %{
       status: :persistence_degraded,
       recommendation: recommendation,
       reason: reason,
       message: "Recommendation could not be persisted and was not queued"
     }}
  end

  @doc false
  def recommendation_action_idempotency_key(recommendation, action, action_index) do
    # Alert identity, rather than the random recommendation UUID, converges
    # concurrent evaluations of the same alert onto the same agent command.
    # The parameter digest still permits a deliberate re-evaluation whose
    # target or arguments materially changed.
    encoded_params = action.params |> canonicalize_params() |> :erlang.term_to_binary()

    params_digest =
      :crypto.hash(:sha256, encoded_params)
      |> Base.encode16(case: :lower)
      |> binary_part(0, 16)

    "decision:alert:#{recommendation.alert_id}:action:#{action_index}:#{action.type}:#{params_digest}"
  end

  defp canonicalize_params(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {to_string(key), canonicalize_params(nested_value)}
    end)
  end

  defp canonicalize_params(value) when is_list(value), do: Enum.map(value, &canonicalize_params/1)
  defp canonicalize_params(value), do: value

  defp execute_autonomous_response(recommendation, _state) do
    Logger.info("Executing autonomous response for alert #{recommendation.alert_id}")

    results =
      recommendation.suggested_actions
      |> Enum.with_index()
      |> Enum.map(fn {action, action_index} ->
        result =
          Executor.execute_action(
            recommendation.agent_id,
            action.type,
            Map.merge(action.params, %{
              autonomous: true,
              recommendation_id: recommendation.id
            }),
            actor: %{organization_id: recommendation.organization_id, user_id: :system},
            idempotency_key:
              recommendation_action_idempotency_key(recommendation, action, action_index)
          )

        # Log the action
        log_autonomous_action(recommendation, action, result)

        %{action: action.type, result: result}
      end)

    {:ok,
     %{
       status: response_execution_status(results),
       results: results,
       executed_at: DateTime.utc_now()
     }}
  end

  defp execute_recommendation(recommendation, approver_id, _state) do
    Logger.info("Executing approved recommendation #{recommendation.id} by #{approver_id}")

    results =
      recommendation.suggested_actions
      |> Enum.with_index()
      |> Enum.map(fn {action, action_index} ->
        result =
          Executor.execute_action(
            recommendation.agent_id,
            action.type,
            Map.merge(action.params, %{
              approved_by: approver_id,
              recommendation_id: recommendation.id
            }),
            actor: %{organization_id: recommendation.organization_id, user_id: approver_id},
            idempotency_key:
              recommendation_action_idempotency_key(recommendation, action, action_index)
          )

        # Log the action
        log_approved_action(recommendation, action, result, approver_id)

        %{action: action.type, result: result}
      end)

    {:ok,
     %{
       status: response_execution_status(results),
       results: results,
       approved_by: approver_id,
       executed_at: DateTime.utc_now()
     }}
  end

  defp queue_recommendation(recommendation, _state) do
    # Memory is only updated after durable persistence. A recommendation that
    # exists only in the singleton cannot be approved safely after a restart.
    case save_pending_recommendation(recommendation) do
      :ok ->
        GenServer.cast(__MODULE__, {:queue_recommendation, recommendation})
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_justification(alert, confidence, criticality, rules) do
    parts = []

    parts = parts ++ ["Alert severity: #{alert.severity}"]

    parts =
      parts ++ ["Confidence score: #{confidence.score}% (#{Enum.join(confidence.factors, ", ")})"]

    parts = parts ++ ["Asset criticality: #{criticality.level} (score: #{criticality.score})"]

    parts =
      if length(rules) > 0 do
        rule_names = Enum.map(rules, & &1.name) |> Enum.join(", ")
        parts ++ ["Matching rules: #{rule_names}"]
      else
        parts
      end

    Enum.join(parts, "\n")
  end

  defp get_org_settings(settings, org_id) do
    settings
    |> Map.get(org_id, %{})
    |> normalize_settings()
  end

  defp normalize_settings(settings) when is_map(settings) do
    defaults = default_settings()

    Enum.reduce(Map.keys(defaults), defaults, fn key, normalized ->
      value =
        Map.get(settings, Atom.to_string(key), Map.get(settings, key, Map.fetch!(defaults, key)))

      value = if key == :autonomous_enabled, do: value == true, else: value
      Map.put(normalized, key, value)
    end)
  end

  defp normalize_settings(_settings), do: default_settings()

  defp default_settings do
    %{
      autonomous_enabled: @default_autonomous_enabled,
      max_actions_per_minute: @default_max_actions_per_minute,
      max_actions_per_hour: @default_max_actions_per_hour,
      critical_asset_protection: @default_critical_asset_protection,
      min_confidence_for_auto: 90,
      min_severity_for_auto: "high",
      excluded_assets: [],
      notification_on_auto: true
    }
  end

  defp restore_persisted_state do
    case DecisionEngineAuthorityAccess.discover_restore_organization_ids() do
      {:ok, organization_ids} when is_list(organization_ids) ->
        Enum.reduce_while(organization_ids, {:ready, %{}, %{}}, fn organization_id,
                                                                   {:ready, settings, pending} ->
          case restore_tenant(organization_id) do
            {:ok, tenant_settings, tenant_pending} ->
              {:cont,
               {:ready, Map.put(settings, organization_id, tenant_settings),
                Map.merge(pending, tenant_pending)}}

            {:error, _reason} ->
              {:halt, {:degraded, %{}, %{}}}
          end
        end)

      {:error, :authority_repo_disabled} ->
        {:not_ready, %{}, %{}}

      {:error, _reason} ->
        {:degraded, %{}, %{}}

      _malformed ->
        {:degraded, %{}, %{}}
    end
  end

  defp restore_tenant(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.transaction(fn ->
        settings =
          Repo.one(
            from(s in "autonomous_settings",
              where: s.organization_id == ^organization_id,
              select: s.settings,
              limit: 1
            )
          )
          |> normalize_settings()

        pending = load_pending_recommendations_for_tenant(organization_id)
        {settings, pending}
      end)
    end)
    |> case do
      {:ok, {settings, pending}} when is_map(settings) and is_map(pending) ->
        {:ok, settings, pending}

      _error ->
        {:error, :tenant_restore_failed}
    end
  rescue
    _error -> {:error, :tenant_restore_failed}
  catch
    :exit, _reason -> {:error, :tenant_restore_failed}
  end

  defp save_settings(org_id, settings) do
    try do
      now = db_timestamp(DateTime.utc_now())

      result =
        MultiTenant.with_organization(org_id, fn ->
          Repo.insert_all(
            "autonomous_settings",
            [
              %{
                id: Ecto.UUID.generate(),
                organization_id: org_id,
                settings: settings,
                inserted_at: now,
                updated_at: now
              }
            ],
            on_conflict: {:replace, [:settings, :updated_at]},
            conflict_target: :organization_id
          )
        end)

      case result do
        {1, _rows} -> :ok
        _other -> {:error, :settings_persistence_failed}
      end
    rescue
      e ->
        Logger.error("Failed to save settings: #{inspect(e.__struct__)}")
        {:error, :settings_persistence_failed}
    end
  end

  defp load_pending_recommendations_for_tenant(organization_id) do
    query =
      from(r in "autonomous_recommendations",
        where: r.status == "pending",
        where: r.organization_id == ^organization_id,
        where: r.expires_at > ^db_timestamp(DateTime.utc_now()),
        select: %{
          id: r.id,
          alert_id: r.alert_id,
          agent_id: r.agent_id,
          organization_id: r.organization_id,
          severity: r.severity,
          confidence_score: r.confidence_score,
          criticality_level: r.criticality_level,
          suggested_actions: r.suggested_actions,
          matching_rules: r.matching_rules,
          auto_execute_eligible: r.auto_execute_eligible,
          justification: r.justification,
          status: r.status,
          result: r.result,
          approved_by: r.approved_by,
          rejection_reason: r.rejection_reason,
          inserted_at: r.inserted_at,
          expires_at: r.expires_at
        }
      )

    Repo.all(query)
    |> Enum.map(fn rec -> {rec.id, struct_from_row(rec)} end)
    |> Map.new()
  end

  defp pending_recommendation(state, recommendation_id, organization_id) do
    case Map.get(state.pending_recommendations, recommendation_id) do
      %{organization_id: ^organization_id} = recommendation ->
        recommendation

      nil ->
        load_recommendation_for_status(recommendation_id, organization_id, "pending")

      _foreign_tenant ->
        nil
    end
  end

  defp load_recommendation_for_status(recommendation_id, organization_id, status) do
    query =
      from(r in "autonomous_recommendations",
        where:
          r.id == ^recommendation_id and
            r.organization_id == ^organization_id and
            r.status == ^status,
        select: %{
          id: r.id,
          alert_id: r.alert_id,
          agent_id: r.agent_id,
          organization_id: r.organization_id,
          severity: r.severity,
          confidence_score: r.confidence_score,
          criticality_level: r.criticality_level,
          suggested_actions: r.suggested_actions,
          matching_rules: r.matching_rules,
          auto_execute_eligible: r.auto_execute_eligible,
          justification: r.justification,
          status: r.status,
          result: r.result,
          approved_by: r.approved_by,
          rejection_reason: r.rejection_reason,
          inserted_at: r.inserted_at,
          expires_at: r.expires_at
        }
      )

    MultiTenant.with_organization(organization_id, fn ->
      case Repo.one(query) do
        nil -> nil
        row -> struct_from_row(row)
      end
    end)
  rescue
    error ->
      Logger.error(
        "Failed to load recommendation #{recommendation_id} for tenant claim: " <>
          Exception.message(error)
      )

      {:error, :persistence_failed}
  end

  defp load_recommendation_status(recommendation_id, organization_id) do
    query =
      from(r in "autonomous_recommendations",
        where: r.id == ^recommendation_id and r.organization_id == ^organization_id,
        select: %{
          id: r.id,
          status: r.status,
          result: r.result,
          approved_by: r.approved_by,
          executed_at: r.executed_at,
          updated_at: r.updated_at
        }
      )

    MultiTenant.with_organization(organization_id, fn ->
      case Repo.one(query) do
        nil -> {:error, :not_found}
        status -> {:ok, normalize_recommendation_status(status)}
      end
    end)
  rescue
    error ->
      Logger.error(
        "Failed to load recommendation status #{recommendation_id}: #{Exception.message(error)}"
      )

      {:error, :persistence_failed}
  end

  defp normalize_recommendation_status(status) do
    %{
      status
      | executed_at: utc_datetime(status.executed_at),
        updated_at: utc_datetime(status.updated_at)
    }
  end

  defp struct_from_row(row) do
    %{
      id: row.id,
      alert_id: row.alert_id,
      agent_id: row.agent_id,
      organization_id: row.organization_id,
      severity: row.severity,
      confidence_score: row.confidence_score,
      criticality_level: row.criticality_level,
      suggested_actions:
        Enum.map(row.suggested_actions || [], &normalize_recommendation_action/1),
      matching_rules: row.matching_rules || [],
      auto_execute_eligible: row.auto_execute_eligible,
      justification: row.justification,
      status: row.status,
      result: row.result,
      approved_by: row.approved_by,
      rejection_reason: row.rejection_reason,
      created_at: utc_datetime(row.inserted_at),
      expires_at: utc_datetime(row.expires_at)
    }
  end

  defp normalize_recommendation_action(%{"type" => type} = action) do
    %{
      type: type,
      params: Map.get(action, "params", %{}),
      risk_score: Map.get(action, "risk_score")
    }
  end

  defp normalize_recommendation_action(%{type: _type} = action) do
    Map.put_new(action, :params, %{})
  end

  defp save_pending_recommendation(recommendation) do
    try do
      count =
        MultiTenant.with_organization(recommendation.organization_id, fn ->
          {count, _rows} =
            Repo.insert_all("autonomous_recommendations", [
              recommendation_insert_row(recommendation)
            ])

          count
        end)

      if count == 1, do: :ok, else: {:error, :persistence_failed}
    rescue
      error ->
        Logger.error("Failed to save recommendation: #{Exception.message(error)}")
        {:error, :persistence_failed}
    end
  end

  defp enqueue_new_autonomous_recommendation(recommendation) do
    try do
      now = DateTime.utc_now()
      db_now = db_timestamp(now)

      claim_query =
        from(r in "autonomous_recommendations",
          where:
            r.id == ^recommendation.id and
              r.organization_id == ^recommendation.organization_id and
              r.status == "pending" and
              (is_nil(r.expires_at) or r.expires_at > ^db_now)
        )

      job_changeset =
        AutonomousResponseWorker.new(%{
          recommendation_id: recommendation.id,
          organization_id: recommendation.organization_id,
          approver_id: nil,
          mode: "auto_executed"
        })

      multi =
        Ecto.Multi.new()
        |> Ecto.Multi.insert_all(
          :recommendation,
          "autonomous_recommendations",
          [recommendation_insert_row(recommendation)],
          on_conflict: :nothing,
          conflict_target: [:id]
        )
        |> Ecto.Multi.update_all(
          :claim,
          claim_query,
          set: [
            status: "queued",
            approved_by: nil,
            result: %{claim: "auto_executed", queued_at: now},
            updated_at: db_now
          ]
        )
        |> Ecto.Multi.run(:claim_verified, fn _repo, %{claim: {count, _rows}} ->
          if count == 1, do: {:ok, :claimed}, else: {:error, :not_pending}
        end)
        |> Oban.insert(:job, job_changeset)

      case MultiTenant.transaction(recommendation.organization_id, multi) do
        {:ok, %{job: job}} ->
          {:ok, job}

        {:error, :claim_verified, :not_pending, _changes} ->
          {:error, :not_pending}

        {:error, _step, reason, _changes} ->
          Logger.error(
            "Failed to persist/enqueue autonomous recommendation #{recommendation.id}: " <>
              inspect(reason)
          )

          {:error, :persistence_failed}
      end
    rescue
      error ->
        Logger.error(
          "Failed to persist/enqueue autonomous recommendation #{recommendation.id}: " <>
            Exception.message(error)
        )

        {:error, :persistence_failed}
    end
  end

  defp recommendation_insert_row(recommendation) do
    %{
      id: recommendation.id,
      alert_id: recommendation.alert_id,
      agent_id: recommendation.agent_id,
      organization_id: recommendation.organization_id,
      severity: recommendation.severity,
      confidence_score: recommendation.confidence_score,
      confidence_factors: recommendation[:confidence_factors],
      criticality_level: to_string(recommendation.criticality_level),
      criticality_score: recommendation[:criticality_score],
      suggested_actions: recommendation.suggested_actions,
      matching_rules: recommendation.matching_rules,
      ml_confidence: recommendation[:ml_confidence],
      auto_execute_eligible: recommendation.auto_execute_eligible,
      justification: recommendation.justification,
      status: "pending",
      expires_at: db_timestamp(recommendation.expires_at),
      inserted_at: db_timestamp(recommendation.created_at),
      updated_at: db_timestamp(DateTime.utc_now())
    }
  end

  defp enqueue_recommendation_execution(recommendation, approver_id, mode) do
    try do
      now = DateTime.utc_now()
      db_now = db_timestamp(now)

      claim_query =
        from(r in "autonomous_recommendations",
          where:
            r.id == ^recommendation.id and
              r.organization_id == ^recommendation.organization_id and
              r.status == "pending" and
              (is_nil(r.expires_at) or r.expires_at > ^db_now)
        )

      job_changeset =
        AutonomousResponseWorker.new(%{
          recommendation_id: recommendation.id,
          organization_id: recommendation.organization_id,
          approver_id: approver_id,
          mode: mode
        })

      multi =
        Ecto.Multi.new()
        |> Ecto.Multi.update_all(
          :claim,
          claim_query,
          set: [
            status: "queued",
            approved_by: approver_id,
            result: %{claim: mode, queued_at: now},
            updated_at: db_now
          ]
        )
        |> Ecto.Multi.run(:claim_verified, fn _repo, %{claim: {count, _rows}} ->
          if count == 1, do: {:ok, :claimed}, else: {:error, :not_pending}
        end)
        |> Oban.insert(:job, job_changeset)

      result = MultiTenant.transaction(recommendation.organization_id, multi)

      case result do
        {:ok, %{job: job}} ->
          {:ok, job}

        {:error, :claim_verified, :not_pending, _changes} ->
          {:error, :not_pending}

        {:error, _step, reason, _changes} ->
          Logger.error(
            "Failed to enqueue recommendation #{recommendation.id}: #{inspect(reason)}"
          )

          {:error, :persistence_failed}
      end
    rescue
      error ->
        Logger.error(
          "Failed to claim/enqueue recommendation #{recommendation.id}: #{Exception.message(error)}"
        )

        {:error, :persistence_failed}
    end
  end

  defp reject_pending_recommendation(recommendation, rejector_id, reason) do
    transition_recommendation(
      recommendation,
      "pending",
      "rejected",
      approved_by: rejector_id,
      rejection_reason: reason,
      result: %{reason: reason},
      executed_at: DateTime.utc_now()
    )
  end

  defp finalize_recommendation(recommendation, from_status, to_status, approver_id, result) do
    transition_recommendation(
      recommendation,
      from_status,
      to_status,
      approved_by: approver_id,
      result: result,
      executed_at: DateTime.utc_now()
    )
  end

  defp transition_recommendation(recommendation, from_status, to_status, attrs) do
    try do
      count =
        MultiTenant.with_organization(recommendation.organization_id, fn ->
          now = DateTime.utc_now()
          db_now = db_timestamp(now)

          query =
            from(r in "autonomous_recommendations",
              where:
                r.id == ^recommendation.id and
                  r.organization_id == ^recommendation.organization_id and
                  r.status == ^from_status
            )

          query =
            if from_status == "pending" do
              where(query, [r], is_nil(r.expires_at) or r.expires_at > ^db_now)
            else
              query
            end

          attrs =
            Keyword.update(attrs, :executed_at, nil, fn timestamp ->
              if timestamp, do: db_timestamp(timestamp), else: nil
            end)

          updates = Keyword.merge(attrs, status: to_status, updated_at: db_now)
          {count, _rows} = Repo.update_all(query, set: updates)
          count
        end)

      if count == 1, do: :ok, else: {:error, :not_pending}
    rescue
      error ->
        Logger.error(
          "Failed recommendation transition #{from_status}->#{to_status} " <>
            "for #{recommendation.id}: #{Exception.message(error)}"
        )

        {:error, :persistence_failed}
    end
  end

  defp drop_pending_recommendation(state, recommendation_id) do
    %{
      state
      | pending_recommendations: Map.delete(state.pending_recommendations, recommendation_id)
    }
  end

  defp execution_results({:ok, %{results: results}}) when is_list(results), do: results
  defp execution_results(_result), do: []

  @doc false
  def persisted_execution_results(result) do
    result
    |> execution_results()
    |> Enum.map(fn
      %{action: action, result: {:ok, payload}} ->
        %{action: to_string(action), status: "ok", result: json_safe_value(payload)}

      %{action: action, result: {:error, reason}} ->
        %{action: to_string(action), status: "error", error: inspect(reason)}

      %{action: action, result: payload} ->
        %{action: to_string(action), status: "unknown", result: json_safe_value(payload)}

      payload ->
        %{action: "unknown", status: "unknown", result: json_safe_value(payload)}
    end)
  end

  defp json_safe_value(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp json_safe_value(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)
  defp json_safe_value(%_struct{} = value), do: value |> Map.from_struct() |> json_safe_value()

  defp json_safe_value(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {json_safe_key(key), json_safe_value(nested_value)}
    end)
  end

  defp json_safe_value(value) when is_list(value), do: Enum.map(value, &json_safe_value/1)
  defp json_safe_value(value) when is_tuple(value), do: inspect(value)

  defp json_safe_value(value) when is_atom(value) and value not in [true, false, nil],
    do: to_string(value)

  defp json_safe_value(value) when is_binary(value) do
    if String.valid?(value), do: value, else: "base64:" <> Base.encode64(value)
  end

  defp json_safe_value(value) when is_number(value) or is_boolean(value) or is_nil(value),
    do: value

  defp json_safe_value(value), do: inspect(value)

  defp json_safe_key(key) when is_binary(key), do: key
  defp json_safe_key(key) when is_atom(key), do: Atom.to_string(key)
  defp json_safe_key(key), do: inspect(key)

  defp terminal_status(result, success_status) do
    case response_execution_status(execution_results(result)) do
      :executed -> success_status
      :execution_unknown -> "execution_unknown"
      :execution_failed -> "failed"
    end
  end

  defp response_execution_status(results) do
    cond do
      Enum.any?(results, &uncertain_action_result?/1) -> :execution_unknown
      all_actions_successful?(results) -> :executed
      true -> :execution_failed
    end
  end

  defp uncertain_action_result?(%{result: {:error, :timeout}}), do: true
  defp uncertain_action_result?(%{result: {:error, {:timeout, _reason}}}), do: true

  defp uncertain_action_result?(%{result: {:error, {:command_in_progress, _command_id}}}),
    do: true

  defp uncertain_action_result?(%{result: {:error, {:worker_call_exit, _reason}}}), do: true
  defp uncertain_action_result?(_result), do: false

  defp execution_reply({:ok, %{status: :execution_unknown, results: results}}) do
    reason =
      Enum.find_value(results, :command_timeout, fn
        %{result: {:error, reason}} = action_result ->
          if uncertain_action_result?(action_result), do: reason

        _result ->
          nil
      end)

    {:error, {:execution_state_unknown, reason}}
  end

  defp execution_reply(result), do: result

  defp autonomous_response_status(%{status: :executed}), do: :auto_executed
  defp autonomous_response_status(%{status: :queued}), do: :auto_execution_queued
  defp autonomous_response_status(%{status: status}), do: status

  defp db_timestamp(%DateTime{} = timestamp) do
    timestamp |> DateTime.to_naive() |> NaiveDateTime.truncate(:second)
  end

  defp db_timestamp(nil), do: nil
  defp db_timestamp(%NaiveDateTime{} = timestamp), do: NaiveDateTime.truncate(timestamp, :second)

  defp utc_datetime(%DateTime{} = timestamp), do: timestamp
  defp utc_datetime(nil), do: nil

  defp utc_datetime(%NaiveDateTime{} = timestamp) do
    DateTime.from_naive!(timestamp, "Etc/UTC")
  end

  defp load_action_history(opts) do
    limit = Keyword.get(opts, :limit, 50)
    org_id = Keyword.fetch!(opts, :organization_id)
    status = Keyword.get(opts, :status)

    try do
      query =
        from(r in "autonomous_recommendations",
          order_by: [desc: r.inserted_at],
          limit: ^limit,
          select: %{
            id: r.id,
            alert_id: r.alert_id,
            agent_id: r.agent_id,
            organization_id: r.organization_id,
            severity: r.severity,
            confidence_score: r.confidence_score,
            criticality_level: r.criticality_level,
            suggested_actions: r.suggested_actions,
            matching_rules: r.matching_rules,
            auto_execute_eligible: r.auto_execute_eligible,
            justification: r.justification,
            status: r.status,
            result: r.result,
            approved_by: r.approved_by,
            rejection_reason: r.rejection_reason,
            inserted_at: r.inserted_at,
            expires_at: r.expires_at
          }
        )

      query = where(query, [r], r.organization_id == ^org_id)
      query = if status, do: where(query, [r], r.status == ^status), else: query

      MultiTenant.with_organization(org_id, fn ->
        Repo.all(query)
        |> Enum.map(&struct_from_row/1)
      end)
    rescue
      _ -> []
    end
  end

  defp record_decision(recommendation, user_id, decision, result) do
    AnalystLearning.record_decision(%{
      recommendation_id: recommendation.id,
      alert_id: recommendation.alert_id,
      agent_id: recommendation.agent_id,
      organization_id: recommendation.organization_id,
      user_id: user_id,
      decision: decision,
      suggested_actions: recommendation.suggested_actions,
      result: result,
      alert_severity: recommendation.severity,
      confidence_score: recommendation.confidence_score,
      criticality_level: recommendation.criticality_level
    })
  end

  defp log_autonomous_action(recommendation, action, result) do
    Logger.info("""
    Autonomous action executed:
      Recommendation: #{recommendation.id}
      Alert: #{recommendation.alert_id}
      Agent: #{recommendation.agent_id}
      Action: #{action.type}
      Result: #{inspect(result)}
    """)

    log_audit_event(recommendation.organization_id, :autonomous_action, %{
      recommendation_id: recommendation.id,
      alert_id: recommendation.alert_id,
      action: action.type,
      result: result
    })
  end

  defp log_approved_action(recommendation, action, result, approver_id) do
    Logger.info("""
    Approved action executed:
      Recommendation: #{recommendation.id}
      Alert: #{recommendation.alert_id}
      Agent: #{recommendation.agent_id}
      Action: #{action.type}
      Approved by: #{approver_id}
      Result: #{inspect(result)}
    """)

    log_audit_event(recommendation.organization_id, :approved_action, %{
      recommendation_id: recommendation.id,
      alert_id: recommendation.alert_id,
      action: action.type,
      approver_id: approver_id,
      result: result
    })
  end

  defp log_audit_event(org_id, event_type, details) do
    try do
      result =
        MultiTenant.with_organization(org_id, fn ->
          Repo.insert_all("autonomous_audit_log", [
            %{
              id: Ecto.UUID.generate(),
              organization_id: org_id,
              event_type: to_string(event_type),
              details: json_safe_value(details),
              created_at: DateTime.utc_now()
            }
          ])
        end)

      case result do
        {1, _rows} ->
          :ok

        {count, _rows} ->
          Logger.error(
            "Autonomous audit insert failed for organization=#{org_id} " <>
              "event_type=#{event_type} inserted_count=#{count}"
          )

          :ok
      end
    rescue
      error ->
        Logger.error(
          "Autonomous audit insert failed for organization=#{org_id} " <>
            "event_type=#{event_type} error_class=#{inspect(error.__struct__)}"
        )

        :ok
    catch
      kind, _reason ->
        Logger.error(
          "Autonomous audit insert interrupted for organization=#{org_id} " <>
            "event_type=#{event_type} failure_kind=#{kind}"
        )

        :ok
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_stale, :timer.hours(1))
  end

  defp maintain_persisted_recommendation_states do
    with {:ok, organization_ids} <-
           DecisionEngineAuthorityAccess.discover_maintenance_organization_ids() do
      Enum.reduce_while(organization_ids, :ok, fn organization_id, :ok ->
        case maintain_tenant_recommendation_states(organization_id) do
          :ok -> {:cont, :ok}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
    else
      _error -> {:error, :maintenance_discovery_unavailable}
    end
  end

  defp maintain_tenant_recommendation_states(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.transaction(fn ->
        now = db_timestamp(DateTime.utc_now())
        execution_cutoff = NaiveDateTime.add(now, -2 * 60 * 60, :second)
        queued_cutoff = NaiveDateTime.add(now, -24 * 60 * 60, :second)

        {expired_count, _rows} =
          Repo.update_all(
            from(r in "autonomous_recommendations",
              where:
                r.organization_id == ^organization_id and r.status == "pending" and
                  r.expires_at <= ^now
            ),
            set: [status: "expired", updated_at: now]
          )

        {unknown_count, _rows} =
          Repo.update_all(
            from(r in "autonomous_recommendations",
              where:
                r.organization_id == ^organization_id and r.status == "executing" and
                  r.updated_at <= ^execution_cutoff
            ),
            set: [status: "execution_unknown", updated_at: now]
          )

        {terminal_job_count, _rows} =
          Repo.update_all(
            from(r in "autonomous_recommendations",
              where: r.organization_id == ^organization_id and r.status == "queued",
              where:
                fragment(
                  """
                  EXISTS (
                    SELECT 1
                    FROM oban_jobs AS terminal_job
                    WHERE terminal_job.worker = ?
                      AND terminal_job.state IN ('cancelled', 'discarded')
                      AND terminal_job.args->>'recommendation_id' = ?::text
                      AND terminal_job.args->>'organization_id' = ?::text
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM oban_jobs AS active_job
                    WHERE active_job.worker = ?
                      AND active_job.state IN ('scheduled', 'available', 'executing', 'retryable')
                      AND active_job.args->>'recommendation_id' = ?::text
                      AND active_job.args->>'organization_id' = ?::text
                  )
                  """,
                  ^inspect(AutonomousResponseWorker),
                  r.id,
                  r.organization_id,
                  ^inspect(AutonomousResponseWorker),
                  r.id,
                  r.organization_id
                )
            ),
            set: [
              status: "execution_unknown",
              result: %{
                reason: "oban_job_terminal_without_execution",
                reconciled_at: DateTime.utc_now()
              },
              updated_at: now
            ]
          )

        {stale_queued_count, _rows} =
          Repo.update_all(
            from(r in "autonomous_recommendations",
              where:
                r.organization_id == ^organization_id and r.status == "queued" and
                  r.updated_at <= ^queued_cutoff,
              where:
                fragment(
                  """
                  NOT EXISTS (
                    SELECT 1
                    FROM oban_jobs AS job
                    WHERE job.worker = ?
                      AND job.state IN ('scheduled', 'available', 'executing', 'retryable')
                      AND job.args->>'recommendation_id' = ?::text
                      AND job.args->>'organization_id' = ?::text
                  )
                  """,
                  ^inspect(AutonomousResponseWorker),
                  r.id,
                  r.organization_id
                )
            ),
            set: [
              status: "execution_unknown",
              result: %{
                reason: "stale_queued_without_active_oban_job",
                reconciled_at: DateTime.utc_now()
              },
              updated_at: now
            ]
          )

        if expired_count > 0 or unknown_count > 0 or terminal_job_count > 0 or
             stale_queued_count > 0 do
          Logger.warning(
            "Autonomous recommendation maintenance: expired=#{expired_count} " <>
              "execution_unknown=#{unknown_count} terminal_job=#{terminal_job_count} " <>
              "stale_queued=#{stale_queued_count}"
          )
        end

        :ok
      end)
    end)
    |> case do
      {:ok, :ok} -> :ok
      _error -> {:error, :tenant_maintenance_failed}
    end
  rescue
    error ->
      Logger.error("Autonomous recommendation maintenance failed: #{Exception.message(error)}")
      {:error, :tenant_maintenance_failed}
  catch
    :exit, _reason -> {:error, :tenant_maintenance_failed}
  end

  defp schedule_rate_limit_reset do
    Process.send_after(self(), :reset_minute_counts, :timer.minutes(1))
  end

  defp schedule_metrics_aggregation do
    Process.send_after(self(), :aggregate_metrics, :timer.minutes(5))
  end

  # ============================================================================
  # Rapid Response Functions
  # ============================================================================

  defp generate_response_id do
    "resp_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp determine_rapid_response_actions(alert) do
    base_actions =
      case alert.severity do
        "critical" ->
          [
            %{type: "kill_process", params: %{pid: alert.pid, force: true}},
            %{type: "quarantine_file", params: %{path: alert.file_path}},
            %{type: "isolate_network", params: %{}}
          ]

        "high" ->
          [
            %{type: "kill_process", params: %{pid: alert.pid}},
            %{type: "quarantine_file", params: %{path: alert.file_path}}
          ]

        _ ->
          [%{type: "quarantine_file", params: %{path: alert.file_path}}]
      end

    # Add threat-specific actions
    threat_actions =
      case alert.detection_type do
        "ransomware" ->
          [
            %{type: "isolate_network", params: %{}},
            %{type: "block_ip", params: %{ip: alert.remote_ip}}
          ]

        "credential_theft" ->
          [%{type: "kill_process", params: %{pid: alert.pid, force: true}}]

        "lateral_movement" ->
          [
            %{type: "block_ip", params: %{ip: alert.remote_ip}},
            %{type: "isolate_network", params: %{}}
          ]

        "c2_communication" ->
          [
            %{type: "block_ip", params: %{ip: alert.remote_ip}},
            %{type: "block_domain", params: %{domain: alert.domain}}
          ]

        _ ->
          []
      end

    (base_actions ++ threat_actions)
    |> Enum.uniq_by(& &1.type)
    |> Enum.filter(fn action -> valid_action_params?(action) end)
  end

  defp valid_action_params?(%{type: "kill_process", params: %{pid: pid}}) when not is_nil(pid),
    do: true

  defp valid_action_params?(%{type: "quarantine_file", params: %{path: path}})
       when not is_nil(path),
       do: true

  defp valid_action_params?(%{type: "isolate_network"}), do: true
  defp valid_action_params?(%{type: "block_ip", params: %{ip: ip}}) when not is_nil(ip), do: true

  defp valid_action_params?(%{type: "block_domain", params: %{domain: domain}})
       when not is_nil(domain),
       do: true

  defp valid_action_params?(_), do: false

  defp execute_parallel_actions(agent_id, actions, actor) do
    # Execute all actions in parallel using Task.async_stream
    actions
    |> Task.async_stream(
      fn action ->
        start_time = System.monotonic_time(:millisecond)

        result =
          Executor.execute_action(
            agent_id,
            action.type,
            Map.merge(action.params, %{rapid_response: true}),
            actor: actor
          )

        duration = System.monotonic_time(:millisecond) - start_time

        %{
          action: action.type,
          params: action.params,
          result: result,
          duration_ms: duration
        }
      end,
      timeout: @action_timeout,
      on_timeout: :kill_task
    )
    |> Enum.map(fn
      {:ok, result} ->
        result

      {:exit, reason} ->
        %{action: "unknown", result: {:error, {:timeout, reason}}, duration_ms: @action_timeout}
    end)
  end

  defp all_actions_successful?(results) do
    Enum.all?(results, fn
      %{result: {:ok, _}} -> true
      %{result: {:error, _}} -> false
      _ -> false
    end)
  end

  defp update_metrics(metrics, response) do
    total = metrics.total_responses + 1

    successful =
      if response.success,
        do: metrics.successful_responses + 1,
        else: metrics.successful_responses

    failed = if response.success, do: metrics.failed_responses, else: metrics.failed_responses + 1

    # Update average response time
    new_avg =
      (metrics.avg_response_time_ms * metrics.total_responses + response.duration_ms) / total

    # Update min/max
    min_time =
      case metrics.min_response_time_ms do
        nil -> response.duration_ms
        existing -> min(existing, response.duration_ms)
      end

    max_time = max(metrics.max_response_time_ms, response.duration_ms)

    # Update response type counts
    responses_by_type =
      response.actions
      |> Enum.reduce(metrics.responses_by_type, fn action, acc ->
        Map.update(acc, action.action, 1, &(&1 + 1))
      end)

    # Add MTTR sample (in minutes)
    mttr_samples =
      [response.duration_ms / 60_000 | metrics.mttr_samples]
      # Keep last 1000 samples
      |> Enum.take(1000)

    %{
      metrics
      | total_responses: total,
        successful_responses: successful,
        failed_responses: failed,
        avg_response_time_ms: Float.round(new_avg, 2),
        min_response_time_ms: min_time,
        max_response_time_ms: max_time,
        responses_by_type: responses_by_type,
        mttr_samples: mttr_samples
    }
  end

  defp metrics_for(metrics_by_organization, organization_id) do
    Map.get(metrics_by_organization, organization_id, init_metrics())
  end

  defp lookup_agent_organization(agent_id) do
    TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
  rescue
    error ->
      Logger.warning(
        "Failed to resolve organization for agent #{inspect(agent_id)}: #{Exception.message(error)}"
      )

      nil
  catch
    kind, reason ->
      Logger.warning(
        "Failed to resolve organization for agent #{inspect(agent_id)}: #{inspect({kind, reason})}"
      )

      nil
  end

  defp current_hour_stats(metrics) do
    _hour_start =
      DateTime.utc_now()
      |> DateTime.truncate(:second)
      |> Map.put(:minute, 0)
      |> Map.put(:second, 0)

    %{
      responses: metrics.total_responses,
      automated: metrics.successful_responses,
      # Would need separate tracking
      manual: 0,
      avg_time_ms: metrics.avg_response_time_ms
    }
  end

  defp calculate_mttr(samples) when length(samples) == 0, do: 0.0

  defp calculate_mttr(samples) do
    (Enum.sum(samples) / length(samples)) |> Float.round(2)
  end

  defp execute_rollback(response) do
    # Rollback actions in reverse order
    response.actions
    |> Enum.reverse()
    |> Enum.map(fn action ->
      rollback_action = get_rollback_action(action)

      case rollback_action do
        nil ->
          %{action: action.action, rollback: "not_reversible"}

        rollback ->
          result =
            Executor.execute_action(
              response.agent_id,
              rollback.type,
              rollback.params,
              actor: %{organization_id: response.organization_id, user_id: :system}
            )

          %{action: action.action, rollback: rollback.type, result: result}
      end
    end)
  end

  defp get_rollback_action(%{action: "isolate_network"}) do
    %{type: "unisolate_network", params: %{}}
  end

  defp get_rollback_action(%{action: "quarantine_file", params: %{path: path}}) do
    %{type: "restore_file", params: %{path: path}}
  end

  defp get_rollback_action(%{action: "block_ip", params: %{ip: ip}}) do
    %{type: "unblock_ip", params: %{ip: ip}}
  end

  defp get_rollback_action(%{action: "block_domain", params: %{domain: domain}}) do
    %{type: "unblock_domain", params: %{domain: domain}}
  end

  defp get_rollback_action(_) do
    # Action cannot be rolled back
    nil
  end
end
