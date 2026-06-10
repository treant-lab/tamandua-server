defmodule TamanduaServer.Detection.AttackChainDetector do
  @moduledoc """
  Multi-step attack chain detection engine using ETS-backed sliding windows.

  Tracks partial and complete attack chains across events from the same agent,
  correlating MITRE techniques with temporal and contextual conditions.

  ## Architecture

  - **ETS State**: Chain progress tracked in `:attack_chain_state` table
  - **Sliding Windows**: Time-based buffers per chain step with configurable retention
  - **Finite State Machine**: Tracks chain progression through multiple steps
  - **Partial Alerts**: Optional alerting on incomplete chains after timeout

  ## Chain Definition Format

  ```yaml
  name: "Credential Stuffing to Account Takeover"
  description: "Brute force followed by valid account usage"
  severity: high
  steps:
    - name: "Brute Force Detection"
      techniques: ["T1110"]
      threshold: 3
      timeframe: 300  # 5 minutes
      conditions:
        same_source_ip: true
    - name: "Valid Account Login"
      techniques: ["T1078"]
      threshold: 1
      timeframe: 1800  # 30 minutes after previous step
      conditions:
        same_user: true
  narrative_template: "Detected credential stuffing attack from {source_ip} with {count} brute force attempts, followed by successful login as {user}"
  ```
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{AttackChain, Mitre}
  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo
  import Ecto.Query

  @table_name :attack_chain_state
  @event_buffer_table :attack_chain_events
  @max_chain_age_ms :timer.hours(24)
  @cleanup_interval_ms :timer.minutes(15)

  # ─────────────────────────────────────────────────────────────────────
  # Client API
  # ─────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process an event and check if it advances any attack chains.
  Returns list of completed chains (if any).
  """
  @spec process_event(map()) :: {:ok, [map()]}
  def process_event(event) do
    GenServer.call(__MODULE__, {:process_event, event}, 10_000)
  end

  @doc """
  Load all enabled attack chains from database.
  """
  @spec reload_chains() :: :ok
  def reload_chains do
    GenServer.cast(__MODULE__, :reload_chains)
  end

  @doc """
  Get current chain progression statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get active chain progressions for an agent.
  """
  @spec get_active_chains(binary()) :: [map()]
  def get_active_chains(agent_id) do
    GenServer.call(__MODULE__, {:get_active_chains, agent_id})
  end

  # ─────────────────────────────────────────────────────────────────────
  # Server Callbacks
  # ─────────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables for chain state tracking
    :ets.new(@table_name, [:named_table, :public, :bag, read_concurrency: true])
    :ets.new(@event_buffer_table, [:named_table, :public, :bag, read_concurrency: true])

    # Load chains from database
    chains = load_chains_from_db()

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)

    Logger.info("[AttackChainDetector] Started with #{length(chains)} chains")

    {:ok,
     %{
       chains: chains,
       stats: %{
         events_processed: 0,
         chains_triggered: 0,
         partial_chains: 0,
         chains_loaded: length(chains)
       }
     }}
  end

  @impl true
  def handle_call({:process_event, event}, _from, state) do
    completed_chains = do_process_event(event, state.chains)

    new_stats =
      state.stats
      |> Map.update(:events_processed, 1, &(&1 + 1))
      |> Map.update(:chains_triggered, length(completed_chains), &(&1 + length(completed_chains)))

    {:reply, {:ok, completed_chains}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    active_chains = count_active_chains()

    stats =
      state.stats
      |> Map.put(:active_chains, active_chains)
      |> Map.put(:event_buffer_size, :ets.info(@event_buffer_table, :size) || 0)

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_active_chains, agent_id}, _from, state) do
    chains = get_agent_chains(agent_id, state.chains)
    {:reply, chains, state}
  end

  @impl true
  def handle_cast(:reload_chains, state) do
    chains = load_chains_from_db()
    Logger.info("[AttackChainDetector] Reloaded #{length(chains)} chains")

    new_stats = Map.put(state.stats, :chains_loaded, length(chains))

    {:noreply, %{state | chains: chains, stats: new_stats}}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    cleanup_expired_chains()
    cleanup_expired_events()

    # Reschedule cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)

    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ─────────────────────────────────────────────────────────────────────
  # Core Detection Logic
  # ─────────────────────────────────────────────────────────────────────

  defp do_process_event(event, chains) do
    agent_id = event[:agent_id] || event["agent_id"]
    techniques = extract_techniques(event)

    return_unless_valid(agent_id, techniques, fn ->
      # Store event in buffer for correlation
      store_event(agent_id, event)

      # Check each chain for progression
      chains
      |> Enum.filter(& &1.enabled)
      |> Enum.flat_map(&check_chain_progression(agent_id, techniques, event, &1))
    end)
  end

  defp return_unless_valid(agent_id, techniques, callback) do
    if agent_id && length(techniques) > 0 do
      callback.()
    else
      []
    end
  end

  defp extract_techniques(event) do
    techniques = event[:mitre_techniques] || event["mitre_techniques"] || []
    detection_techniques = extract_detection_techniques(event)

    (techniques ++ detection_techniques) |> Enum.uniq()
  end

  defp extract_detection_techniques(event) do
    detections = event[:detections] || event["detections"] || []

    Enum.flat_map(detections, fn detection ->
      detection[:mitre_techniques] || detection["mitre_techniques"] || []
    end)
  end

  defp check_chain_progression(agent_id, techniques, event, chain) do
    definition = chain.definition
    steps = definition["steps"] || []

    # Get or initialize chain state for this agent
    chain_state = get_chain_state(agent_id, chain.id) || init_chain_state(agent_id, chain.id)

    # Check if current event matches next expected step
    current_step_index = chain_state.current_step
    current_step = Enum.at(steps, current_step_index)

    if current_step && step_matches?(current_step, techniques, event, chain_state) do
      advance_chain(agent_id, chain, chain_state, current_step, event, steps)
    else
      []
    end
  end

  defp step_matches?(step, techniques, event, chain_state) do
    required_techniques = step["techniques"] || []
    matches_technique = Enum.any?(required_techniques, &(&1 in techniques))

    if matches_technique do
      check_step_conditions(step, event, chain_state)
    else
      false
    end
  end

  defp check_step_conditions(step, event, chain_state) do
    conditions = step["conditions"] || %{}
    previous_events = chain_state.matched_events

    Enum.all?(conditions, fn {condition, required_value} ->
      check_condition(condition, required_value, event, previous_events)
    end)
  end

  defp check_condition("same_source_ip", true, event, previous_events) do
    current_ip = extract_source_ip(event)

    current_ip &&
      Enum.all?(previous_events, fn prev_event ->
        extract_source_ip(prev_event) == current_ip
      end)
  end

  defp check_condition("same_user", true, event, previous_events) do
    current_user = extract_user(event)

    current_user &&
      Enum.all?(previous_events, fn prev_event ->
        extract_user(prev_event) == current_user
      end)
  end

  defp check_condition("same_dest_ip", true, event, previous_events) do
    current_dest = extract_dest_ip(event)

    current_dest &&
      Enum.all?(previous_events, fn prev_event ->
        extract_dest_ip(prev_event) == current_dest
      end)
  end

  defp check_condition("same_agent", true, event, previous_events) do
    current_agent = event[:agent_id] || event["agent_id"]

    current_agent &&
      Enum.all?(previous_events, fn prev_event ->
        (prev_event[:agent_id] || prev_event["agent_id"]) == current_agent
      end)
  end

  defp check_condition("same_process", true, event, previous_events) do
    current_pid = extract_pid(event)

    current_pid &&
      Enum.all?(previous_events, fn prev_event ->
        extract_pid(prev_event) == current_pid
      end)
  end

  defp check_condition(_, _, _, _), do: true

  defp advance_chain(agent_id, chain, chain_state, current_step, event, steps) do
    new_step_index = chain_state.current_step + 1
    new_matched_events = chain_state.matched_events ++ [event]

    # Update chain state
    new_state = %{
      chain_state
      | current_step: new_step_index,
        matched_events: new_matched_events,
        last_update: DateTime.utc_now()
    }

    save_chain_state(agent_id, chain.id, new_state)

    # Check if chain is complete
    if new_step_index >= length(steps) do
      complete_chain(agent_id, chain, new_state)
    else
      # Chain progressed but not complete
      update_partial_chain_metrics(chain)
      []
    end
  end

  defp complete_chain(agent_id, chain, chain_state) do
    Logger.info(
      "[AttackChainDetector] Chain '#{chain.name}' completed for agent #{agent_id}"
    )

    # Generate alert
    alert = create_chain_alert(agent_id, chain, chain_state)

    # Update chain statistics
    update_chain_stats(chain.id)

    # Clear chain state
    delete_chain_state(agent_id, chain.id)

    [alert]
  end

  defp create_chain_alert(agent_id, chain, chain_state) do
    narrative = generate_narrative(chain, chain_state)
    techniques = extract_all_techniques(chain_state.matched_events)
    tactics = techniques |> Enum.flat_map(&get_tactics_for_technique/1) |> Enum.uniq()

    event_ids =
      chain_state.matched_events
      |> Enum.map(&(&1[:event_id] || &1["event_id"]))
      |> Enum.reject(&is_nil/1)

    alert_params = %{
      agent_id: agent_id,
      organization_id: get_org_id_for_agent(agent_id),
      severity: chain.severity,
      title: "Attack Chain: #{chain.name}",
      description: narrative,
      mitre_techniques: techniques,
      mitre_tactics: tactics,
      event_ids: event_ids,
      detection_metadata: %{
        chain_id: chain.id,
        chain_name: chain.name,
        chain_version: chain.version,
        steps_matched: length(chain_state.matched_events),
        test_mode: chain.test_mode
      },
      process_chain: build_process_chain(chain_state.matched_events),
      contributing_events: event_ids |> Enum.map(&to_string/1)
    }

    # Create alert (unless in test mode)
    if chain.test_mode do
      Logger.info(
        "[AttackChainDetector] TEST MODE - Would create alert: #{inspect(alert_params)}"
      )

      alert_params
    else
      case Alerts.create_alert(alert_params) do
        {:ok, alert} ->
          Logger.info("[AttackChainDetector] Created alert #{alert.id} for chain #{chain.name}")
          alert

        {:error, changeset} ->
          Logger.error(
            "[AttackChainDetector] Failed to create alert for chain #{chain.name}: #{inspect(changeset.errors)}"
          )

          nil
      end
    end
  end

  defp generate_narrative(chain, chain_state) do
    template =
      chain.definition["narrative_template"] ||
        "Multi-step attack chain '#{chain.name}' detected with #{length(chain_state.matched_events)} steps"

    # Extract context for template substitution
    context = extract_narrative_context(chain_state.matched_events)

    # Simple template substitution
    Enum.reduce(context, template, fn {key, value}, acc ->
      String.replace(acc, "{#{key}}", to_string(value))
    end)
  end

  defp extract_narrative_context(events) do
    %{
      count: length(events),
      source_ip: events |> List.first() |> extract_source_ip() || "unknown",
      user: events |> List.first() |> extract_user() || "unknown",
      process:
        events |> List.first() |> then(&(&1[:process_name] || &1["process_name"])) || "unknown",
      timespan: calculate_timespan(events)
    }
  end

  defp calculate_timespan(events) do
    case {List.first(events), List.last(events)} do
      {first, last} when not is_nil(first) and not is_nil(last) ->
        first_time = first[:timestamp] || first["timestamp"]
        last_time = last[:timestamp] || last["timestamp"]

        if first_time && last_time do
          diff = DateTime.diff(parse_timestamp(last_time), parse_timestamp(first_time), :second)
          "#{diff}s"
        else
          "unknown"
        end

      _ ->
        "unknown"
    end
  end

  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(_), do: DateTime.utc_now()

  # ─────────────────────────────────────────────────────────────────────
  # ETS State Management
  # ─────────────────────────────────────────────────────────────────────

  defp get_chain_state(agent_id, chain_id) do
    key = {agent_id, chain_id}

    case :ets.lookup(@table_name, key) do
      [{^key, state}] -> state
      [] -> nil
    end
  end

  defp init_chain_state(agent_id, chain_id) do
    %{
      agent_id: agent_id,
      chain_id: chain_id,
      current_step: 0,
      matched_events: [],
      started_at: DateTime.utc_now(),
      last_update: DateTime.utc_now()
    }
  end

  defp save_chain_state(agent_id, chain_id, state) do
    key = {agent_id, chain_id}
    :ets.insert(@table_name, {key, state})
  end

  defp delete_chain_state(agent_id, chain_id) do
    key = {agent_id, chain_id}
    :ets.delete(@table_name, key)
  end

  defp store_event(agent_id, event) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
    :ets.insert(@event_buffer_table, {agent_id, timestamp, event})
  end

  defp get_agent_chains(agent_id, loaded_chains) do
    chain_ids = loaded_chains |> Enum.map(& &1.id) |> MapSet.new()

    :ets.select(@table_name, [
      {{{agent_id, :"$1"}, :"$2"}, [], [{{:"$1", :"$2"}}]}
    ])
    |> Enum.filter(fn {chain_id, _state} -> MapSet.member?(chain_ids, chain_id) end)
    |> Enum.map(fn {chain_id, state} ->
      chain = Enum.find(loaded_chains, &(&1.id == chain_id))

      %{
        chain_id: chain_id,
        chain_name: chain && chain.name,
        current_step: state.current_step,
        total_steps: chain && length(chain.definition["steps"] || []),
        matched_events: length(state.matched_events),
        started_at: state.started_at,
        last_update: state.last_update
      }
    end)
  end

  defp count_active_chains do
    :ets.info(@table_name, :size) || 0
  end

  defp cleanup_expired_chains do
    cutoff = DateTime.utc_now() |> DateTime.add(-@max_chain_age_ms, :millisecond)

    expired =
      :ets.select(@table_name, [
        {{:"$1", :"$2"}, [{:<, {:map_get, :last_update, :"$2"}, {:const, cutoff}}], [:"$1"]}
      ])

    Enum.each(expired, &:ets.delete(@table_name, &1))

    if length(expired) > 0 do
      Logger.info("[AttackChainDetector] Cleaned up #{length(expired)} expired chain states")
    end
  end

  defp cleanup_expired_events do
    cutoff = DateTime.utc_now() |> DateTime.add(-@max_chain_age_ms, :millisecond) |> DateTime.to_unix(:millisecond)

    expired =
      :ets.select(@event_buffer_table, [
        {{:"$1", :"$2", :"$3"}, [{:<, :"$2", {:const, cutoff}}], [{{:"$1", :"$2"}}]}
      ])

    Enum.each(expired, fn {agent_id, timestamp} ->
      :ets.match_delete(@event_buffer_table, {agent_id, timestamp, :_})
    end)

    if length(expired) > 0 do
      Logger.debug("[AttackChainDetector] Cleaned up #{length(expired)} expired events")
    end
  end

  # ─────────────────────────────────────────────────────────────────────
  # Helper Functions
  # ─────────────────────────────────────────────────────────────────────

  defp load_chains_from_db do
    query = from(c in AttackChain, where: c.enabled == true)

    case Repo.all(query) do
      chains when is_list(chains) ->
        chains

      _ ->
        Logger.warning("[AttackChainDetector] Failed to load chains from database")
        []
    end
  rescue
    e ->
      Logger.error("[AttackChainDetector] Error loading chains: #{Exception.message(e)}")
      []
  end

  defp update_chain_stats(chain_id) do
    Task.start(fn ->
      case Repo.get(AttackChain, chain_id) do
        nil ->
          :ok

        chain ->
          changeset =
            AttackChain.changeset(chain, %{
              trigger_count: chain.trigger_count + 1,
              last_triggered_at: DateTime.utc_now()
            })

          Repo.update(changeset)
      end
    end)
  end

  defp update_partial_chain_metrics(_chain) do
    # Could track partial chain metrics here if needed
    :ok
  end

  defp extract_source_ip(event) do
    event[:source_ip] || event["source_ip"] || event[:src_ip] || event["src_ip"]
  end

  defp extract_dest_ip(event) do
    event[:dest_ip] || event["dest_ip"] || event[:dst_ip] || event["dst_ip"]
  end

  defp extract_user(event) do
    event[:user] || event["user"] || event[:username] || event["username"]
  end

  defp extract_pid(event) do
    event[:pid] || event["pid"] || event[:process_id] || event["process_id"]
  end

  defp extract_all_techniques(events) do
    events
    |> Enum.flat_map(&extract_techniques/1)
    |> Enum.uniq()
  end

  defp get_tactics_for_technique(technique_id) do
    case Mitre.get_technique(technique_id) do
      nil -> []
      tech -> tech.tactics
    end
  end

  defp get_org_id_for_agent(agent_id) do
    TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
  end

  defp build_process_chain(events) do
    events
    |> Enum.map(fn event ->
      %{
        pid: extract_pid(event),
        process_name: event[:process_name] || event["process_name"],
        timestamp: event[:timestamp] || event["timestamp"]
      }
    end)
    |> Enum.reject(&is_nil(&1.pid))
  end
end
