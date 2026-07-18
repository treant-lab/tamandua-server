defmodule Tamandua.Updates.RolloutOrchestrator do
  @moduledoc """
  Phased rollout orchestration for agent updates.

  Implements progressive rollout strategies:
  - Canary: 1% → 5% → 25% → 100%
  - Manual approval gates
  - Automatic rollback on failure threshold
  - Emergency updates (bypass rollout)
  - Maintenance window scheduling

  Monitors update health and can halt/rollback automatically.
  """

  use GenServer
  require Logger
  alias Tamandua.Updates.{RolloutState, UpdateHealth}
  alias TamanduaServer.Repo
  import Ecto.Query

  @type rollout_id :: String.t()
  @type rollout_phase :: :canary_1 | :canary_5 | :canary_25 | :full | :paused | :cancelled
  @type rollout_strategy :: :automatic | :manual_approval | :emergency

  defmodule RolloutConfig do
    @moduledoc false
    defstruct [
      :rollout_id,
      :version,
      :platform,
      :arch,
      :strategy,
      :current_phase,
      :phase_configs,
      :failure_threshold,
      :health_check_window,
      :maintenance_windows,
      :started_at,
      :auto_advance,
      :emergency_mode
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start a new update rollout.

  Options:
  - strategy: :automatic | :manual_approval | :emergency
  - failure_threshold: percentage (default 0.05 = 5%)
  - auto_advance: automatically advance phases (default true for :automatic)
  - maintenance_windows: list of {day_of_week, start_hour, end_hour}
  """
  @spec start_rollout(String.t(), atom(), atom(), keyword()) :: {:ok, rollout_id()} | {:error, term()}
  def start_rollout(version, platform, arch, opts \\ []) do
    GenServer.call(__MODULE__, {:start_rollout, version, platform, arch, opts})
  end

  @doc """
  Advance to the next rollout phase.
  """
  @spec advance_phase(rollout_id()) :: :ok | {:error, term()}
  def advance_phase(rollout_id) do
    GenServer.call(__MODULE__, {:advance_phase, rollout_id})
  end

  @doc """
  Pause a rollout.
  """
  @spec pause_rollout(rollout_id()) :: :ok | {:error, term()}
  def pause_rollout(rollout_id) do
    GenServer.call(__MODULE__, {:pause_rollout, rollout_id})
  end

  @doc """
  Resume a paused rollout.
  """
  @spec resume_rollout(rollout_id()) :: :ok | {:error, term()}
  def resume_rollout(rollout_id) do
    GenServer.call(__MODULE__, {:resume_rollout, rollout_id})
  end

  @doc """
  Cancel a rollout.
  """
  @spec cancel_rollout(rollout_id()) :: :ok | {:error, term()}
  def cancel_rollout(rollout_id) do
    GenServer.call(__MODULE__, {:cancel_rollout, rollout_id})
  end

  @doc """
  Trigger emergency rollback for a rollout.
  """
  @spec emergency_rollback(rollout_id()) :: :ok | {:error, term()}
  def emergency_rollback(rollout_id) do
    GenServer.call(__MODULE__, {:emergency_rollback, rollout_id})
  end

  @doc """
  Check if an agent is eligible for an update based on current rollout phase.
  """
  @spec is_agent_eligible?(String.t(), atom(), atom()) :: boolean()
  def is_agent_eligible?(agent_id, platform, arch) do
    GenServer.call(__MODULE__, {:is_agent_eligible?, agent_id, platform, arch})
  end

  @doc """
  Report update status from an agent.
  """
  @spec report_update_status(String.t(), String.t(), atom(), map()) :: :ok
  def report_update_status(agent_id, version, status, metadata) do
    GenServer.cast(__MODULE__, {:report_update_status, agent_id, version, status, metadata})
  end

  @doc """
  Get rollout status.
  """
  @spec get_rollout_status(rollout_id()) :: {:ok, map()} | {:error, :not_found}
  def get_rollout_status(rollout_id) do
    GenServer.call(__MODULE__, {:get_rollout_status, rollout_id})
  end

  @doc """
  List active rollouts.
  """
  @spec list_active_rollouts() :: [map()]
  def list_active_rollouts do
    GenServer.call(__MODULE__, :list_active_rollouts)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Schedule health checks every minute
    schedule_health_check()

    state = %{
      active_rollouts: %{},
      agent_assignments: %{}  # agent_id -> rollout_id
    }

    Logger.info("Rollout Orchestrator started")
    {:ok, state}
  end

  @impl true
  def handle_call({:start_rollout, version, platform, arch, opts}, _from, state) do
    strategy = Keyword.get(opts, :strategy, :automatic)
    failure_threshold = Keyword.get(opts, :failure_threshold, 0.05)
    auto_advance = Keyword.get(opts, :auto_advance, strategy == :automatic)
    emergency_mode = strategy == :emergency

    rollout_id = generate_rollout_id()

    phase_configs = if emergency_mode do
      # Emergency: skip phases, go straight to full rollout
      %{full: %{percentage: 1.0, min_success_rate: 0.0}}
    else
      # Standard phased rollout
      %{
        canary_1: %{percentage: 0.01, min_success_rate: 0.95, min_duration_minutes: 30},
        canary_5: %{percentage: 0.05, min_success_rate: 0.95, min_duration_minutes: 60},
        canary_25: %{percentage: 0.25, min_success_rate: 0.97, min_duration_minutes: 120},
        full: %{percentage: 1.0, min_success_rate: 0.99, min_duration_minutes: 0}
      }
    end

    rollout_config = %RolloutConfig{
      rollout_id: rollout_id,
      version: version,
      platform: platform,
      arch: arch,
      strategy: strategy,
      current_phase: if(emergency_mode, do: :full, else: :canary_1),
      phase_configs: phase_configs,
      failure_threshold: failure_threshold,
      health_check_window: 300,  # 5 minutes
      maintenance_windows: Keyword.get(opts, :maintenance_windows, []),
      started_at: DateTime.utc_now(),
      auto_advance: auto_advance,
      emergency_mode: emergency_mode
    }

    # Persist rollout state
    case persist_rollout_state(rollout_config) do
      {:ok, _state} ->
        state = put_in(state.active_rollouts[rollout_id], rollout_config)
        Logger.info("Started #{strategy} rollout #{rollout_id} for #{version} (#{platform}/#{arch})")
        {:reply, {:ok, rollout_id}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:advance_phase, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rollout_config ->
        case get_next_phase(rollout_config.current_phase, rollout_config.emergency_mode) do
          nil ->
            # Already at full rollout
            Logger.info("Rollout #{rollout_id} already at full phase")
            {:reply, {:error, :already_at_full}, state}

          next_phase ->
            # Check if current phase meets success criteria
            case check_phase_health(rollout_config) do
              :ok ->
                rollout_config = %{rollout_config | current_phase: next_phase}
                state = put_in(state.active_rollouts[rollout_id], rollout_config)
                persist_rollout_state(rollout_config)
                Logger.info("Advanced rollout #{rollout_id} to phase #{next_phase}")
                {:reply, :ok, state}

              {:error, reason} ->
                Logger.warning("Cannot advance rollout #{rollout_id}: #{inspect(reason)}")
                {:reply, {:error, reason}, state}
            end
        end
    end
  end

  @impl true
  def handle_call({:pause_rollout, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rollout_config ->
        rollout_config = %{rollout_config | current_phase: :paused}
        state = put_in(state.active_rollouts[rollout_id], rollout_config)
        persist_rollout_state(rollout_config)
        Logger.info("Paused rollout #{rollout_id}")
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:resume_rollout, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{current_phase: :paused} = rollout_config ->
        # Resume to canary_1 or last active phase
        resume_phase = if rollout_config.emergency_mode, do: :full, else: :canary_1
        rollout_config = %{rollout_config | current_phase: resume_phase}
        state = put_in(state.active_rollouts[rollout_id], rollout_config)
        persist_rollout_state(rollout_config)
        Logger.info("Resumed rollout #{rollout_id} at phase #{resume_phase}")
        {:reply, :ok, state}

      _ ->
        {:reply, {:error, :not_paused}, state}
    end
  end

  @impl true
  def handle_call({:cancel_rollout, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rollout_config ->
        rollout_config = %{rollout_config | current_phase: :cancelled}
        persist_rollout_state(rollout_config)

        # Remove from active rollouts
        state = Map.update!(state, :active_rollouts, &Map.delete(&1, rollout_id))

        # Remove agent assignments
        state = Map.update!(state, :agent_assignments, fn assignments ->
          Enum.reject(assignments, fn {_agent_id, rid} -> rid == rollout_id end)
          |> Map.new()
        end)

        Logger.info("Cancelled rollout #{rollout_id}")
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:emergency_rollback, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rollout_config ->
        Logger.error("EMERGENCY ROLLBACK initiated for rollout #{rollout_id}")

        # Pause the rollout immediately
        rollout_config = %{rollout_config | current_phase: :paused}
        state = put_in(state.active_rollouts[rollout_id], rollout_config)
        persist_rollout_state(rollout_config)

        # TODO: Trigger rollback commands to all agents that updated
        # This would involve sending downgrade commands via the agent channel

        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:is_agent_eligible?, agent_id, platform, arch}, _from, state) do
    # Find active rollout for this platform/arch
    rollout = Enum.find_value(state.active_rollouts, fn {_id, config} ->
      if config.platform == platform and config.arch == arch and
         config.current_phase not in [:paused, :cancelled] do
        config
      end
    end)

    eligible = case rollout do
      nil ->
        false

      %{current_phase: :full} ->
        true

      %{emergency_mode: true} ->
        true

      rollout_config ->
        # Check if in maintenance window
        if not in_maintenance_window?(rollout_config.maintenance_windows) do
          false
        else
          # Deterministic assignment based on agent_id hash
          phase_percentage = get_phase_percentage(rollout_config.current_phase, rollout_config.phase_configs)
          agent_hash = hash_agent_id(agent_id)
          agent_hash < phase_percentage
        end
    end

    {:reply, eligible, state}
  end

  @impl true
  def handle_call({:get_rollout_status, rollout_id}, _from, state) do
    case Map.get(state.active_rollouts, rollout_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rollout_config ->
        health = get_rollout_health(rollout_config)
        status = %{
          rollout_id: rollout_config.rollout_id,
          version: rollout_config.version,
          platform: rollout_config.platform,
          arch: rollout_config.arch,
          strategy: rollout_config.strategy,
          current_phase: rollout_config.current_phase,
          started_at: rollout_config.started_at,
          health: health
        }
        {:reply, {:ok, status}, state}
    end
  end

  @impl true
  def handle_call(:list_active_rollouts, _from, state) do
    rollouts = Enum.map(state.active_rollouts, fn {_id, config} ->
      %{
        rollout_id: config.rollout_id,
        version: config.version,
        platform: config.platform,
        arch: config.arch,
        current_phase: config.current_phase,
        strategy: config.strategy,
        started_at: config.started_at
      }
    end)

    {:reply, rollouts, state}
  end

  @impl true
  def handle_cast({:report_update_status, agent_id, version, status, metadata}, state) do
    # Find rollout for this update
    rollout = Enum.find_value(state.active_rollouts, fn {_id, config} ->
      if config.version == version, do: config
    end)

    if rollout do
      # Record status in health tracking
      record_health_event(rollout.rollout_id, agent_id, status, metadata)

      # Update agent assignment
      state = if status in [:downloading, :installing] do
        put_in(state.agent_assignments[agent_id], rollout.rollout_id)
      else
        state
      end

      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:health_check, state) do
    # Check health of all active rollouts
    Enum.each(state.active_rollouts, fn {rollout_id, rollout_config} ->
      case check_rollout_health(rollout_config) do
        :ok ->
          # Health check passed
          if rollout_config.auto_advance and should_auto_advance?(rollout_config) do
            Logger.info("Auto-advancing rollout #{rollout_id}")
            advance_phase(rollout_id)
          end

        {:error, :failure_threshold_exceeded} ->
          Logger.error("Rollout #{rollout_id} exceeded failure threshold, triggering rollback")
          emergency_rollback(rollout_id)

        {:error, reason} ->
          Logger.warning("Rollout #{rollout_id} health check failed: #{inspect(reason)}")
      end
    end)

    schedule_health_check()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Helpers

  defp generate_rollout_id do
    "rollout_" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
  end

  defp get_next_phase(current_phase, emergency_mode) do
    if emergency_mode do
      nil  # Emergency mode has no phases
    else
      case current_phase do
        :canary_1 -> :canary_5
        :canary_5 -> :canary_25
        :canary_25 -> :full
        :full -> nil
        _ -> nil
      end
    end
  end

  defp get_phase_percentage(phase, phase_configs) do
    case Map.get(phase_configs, phase) do
      nil -> 0.0
      config -> config.percentage
    end
  end

  defp hash_agent_id(agent_id) do
    # Deterministic hash to [0.0, 1.0)
    hash = :crypto.hash(:sha256, agent_id)
    <<value::unsigned-integer-size(64), _rest::binary>> = hash
    value / 0xFFFFFFFFFFFFFFFF
  end

  defp in_maintenance_window?([]), do: true  # No restrictions
  defp in_maintenance_window?(windows) do
    now = DateTime.utc_now()
    day_of_week = Date.day_of_week(DateTime.to_date(now))
    hour = now.hour

    Enum.any?(windows, fn {day, start_hour, end_hour} ->
      day == day_of_week and hour >= start_hour and hour < end_hour
    end)
  end

  defp check_phase_health(rollout_config) do
    phase_config = Map.get(rollout_config.phase_configs, rollout_config.current_phase)
    health = get_rollout_health(rollout_config)

    cond do
      health.success_rate < phase_config.min_success_rate ->
        {:error, :success_rate_too_low}

      true ->
        :ok
    end
  end

  defp check_rollout_health(rollout_config) do
    health = get_rollout_health(rollout_config)

    if health.failure_rate > rollout_config.failure_threshold do
      {:error, :failure_threshold_exceeded}
    else
      :ok
    end
  end

  defp should_auto_advance?(rollout_config) do
    phase_config = Map.get(rollout_config.phase_configs, rollout_config.current_phase)
    health = get_rollout_health(rollout_config)

    # Check if minimum duration has passed
    now = DateTime.utc_now()
    duration_minutes = DateTime.diff(now, rollout_config.started_at, :minute)

    duration_minutes >= phase_config.min_duration_minutes and
      health.success_rate >= phase_config.min_success_rate
  end

  defp get_rollout_health(rollout_config) do
    # Query UpdateHealth records for this rollout
    query = from h in UpdateHealth,
      where: h.rollout_id == ^rollout_config.rollout_id,
      where: h.created_at > ago(^rollout_config.health_check_window, "second")

    records = Repo.all(query)

    total = length(records)
    successes = Enum.count(records, & &1.status == :success)
    failures = Enum.count(records, & &1.status == :failed)

    %{
      total_attempts: total,
      successes: successes,
      failures: failures,
      success_rate: if(total > 0, do: successes / total, else: 0.0),
      failure_rate: if(total > 0, do: failures / total, else: 0.0)
    }
  end

  defp record_health_event(rollout_id, agent_id, status, metadata) do
    attrs = %{
      rollout_id: rollout_id,
      agent_id: agent_id,
      status: status,
      metadata: metadata,
      created_at: DateTime.utc_now()
    }

    %UpdateHealth{}
    |> UpdateHealth.changeset(attrs)
    |> Repo.insert()
  end

  defp persist_rollout_state(rollout_config) do
    attrs = %{
      rollout_id: rollout_config.rollout_id,
      version: rollout_config.version,
      platform: rollout_config.platform,
      arch: rollout_config.arch,
      strategy: rollout_config.strategy,
      current_phase: rollout_config.current_phase,
      phase_configs: rollout_config.phase_configs,
      failure_threshold: rollout_config.failure_threshold,
      started_at: rollout_config.started_at,
      updated_at: DateTime.utc_now()
    }

    %RolloutState{}
    |> RolloutState.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: :rollout_id)
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, :timer.minutes(1))
  end
end
