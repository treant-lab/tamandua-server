defmodule TamanduaServer.AI.CostGovernor do
  @moduledoc """
  AI Workload Cost Governor for enterprise AI inference cost management.

  Tracks and governs AI inference costs across:
  - Per-model: Cost tracking per AI model (GPT-4, Claude, Llama, etc.)
  - Per-user: User-level cost tracking and limits
  - Per-process: Process-level cost tracking
  - Per-team: Team/organization cost tracking

  ## Features

  - **Real-time cost tracking**: Tokens/min, inferences/hour, estimated USD
  - **Budget management**: Set limits with alerts at thresholds
  - **Enforcement actions**: Alert, throttle, block, or kill process on exceed
  - **Integration**: Works with InferenceTracker, RateLimiter, ModelPolicy

  ## Budget Configuration

      limits = %{
        daily_usd: 100.0,
        hourly_usd: 10.0,
        tokens_per_min: 10_000,
        inferences_per_hour: 1000
      }

      CostGovernor.set_budget(:user, "user-123", limits)

  ## Cost Tracking

      # Track an inference
      CostGovernor.track_inference(
        agent_id: "agent-1",
        model_id: "gpt-4",
        tokens_in: 1500,
        tokens_out: 500,
        latency_ms: 2500
      )

  ## Budget Checking

      case CostGovernor.check_budget(:user, "user-123") do
        {:ok, remaining} ->
          # remaining.daily_usd, remaining.tokens_per_min, etc.
          proceed_with_inference()

        {:exceeded, action} ->
          # action is one of: :alert, :throttle, :block, :kill_process
          handle_exceeded(action)
      end

  ## Model Pricing

  Default pricing (per 1M tokens) is configurable:

      config :tamandua_server, TamanduaServer.AI.CostGovernor,
        model_pricing: %{
          "gpt-4" => %{input: 30.0, output: 60.0},
          "gpt-4-turbo" => %{input: 10.0, output: 30.0},
          "gpt-3.5-turbo" => %{input: 0.5, output: 1.5},
          "claude-3-opus" => %{input: 15.0, output: 75.0},
          "claude-3-sonnet" => %{input: 3.0, output: 15.0},
          "claude-3-haiku" => %{input: 0.25, output: 1.25},
          "llama-3-70b" => %{input: 0.0, output: 0.0}  # Local models
        }
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.InferenceTracker
  alias TamanduaServer.Policies.ModelPolicy
  alias TamanduaServer.Response.Executor

  @ets_budgets :ai_cost_budgets
  @ets_usage :ai_cost_usage
  @ets_inferences :ai_cost_inferences

  @cleanup_interval :timer.minutes(5)
  @usage_window_seconds 3600  # 1 hour for rolling windows

  # Default model pricing per 1M tokens (USD)
  @default_pricing %{
    # OpenAI models
    "gpt-4" => %{input: 30.0, output: 60.0},
    "gpt-4-32k" => %{input: 60.0, output: 120.0},
    "gpt-4-turbo" => %{input: 10.0, output: 30.0},
    "gpt-4o" => %{input: 5.0, output: 15.0},
    "gpt-4o-mini" => %{input: 0.15, output: 0.6},
    "gpt-3.5-turbo" => %{input: 0.5, output: 1.5},
    "o1-preview" => %{input: 15.0, output: 60.0},
    "o1-mini" => %{input: 3.0, output: 12.0},

    # Anthropic models
    "claude-3-opus" => %{input: 15.0, output: 75.0},
    "claude-3-5-sonnet" => %{input: 3.0, output: 15.0},
    "claude-3-sonnet" => %{input: 3.0, output: 15.0},
    "claude-3-haiku" => %{input: 0.25, output: 1.25},
    "claude-2" => %{input: 8.0, output: 24.0},

    # Local/Open models (no API cost, but track for GPU time)
    "llama-3-70b" => %{input: 0.0, output: 0.0},
    "llama-3-8b" => %{input: 0.0, output: 0.0},
    "mistral-7b" => %{input: 0.0, output: 0.0},
    "mixtral-8x7b" => %{input: 0.0, output: 0.0},
    "qwen-72b" => %{input: 0.0, output: 0.0},
    "deepseek-coder" => %{input: 0.0, output: 0.0},

    # Default for unknown models
    "default" => %{input: 1.0, output: 3.0}
  }

  # Default actions when budget is exceeded at different thresholds
  @default_actions %{
    50 => :alert,
    75 => :alert,
    90 => :throttle,
    100 => :block
  }

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type entity_type :: :model | :user | :process | :team | :agent
  @type entity_id :: String.t()

  @type budget_limits :: %{
    optional(:daily_usd) => float(),
    optional(:hourly_usd) => float(),
    optional(:tokens_per_min) => pos_integer(),
    optional(:inferences_per_hour) => pos_integer(),
    optional(:alert_thresholds) => [pos_integer()],  # e.g., [50, 75, 90, 100]
    optional(:actions) => %{pos_integer() => action()}
  }

  @type action :: :alert | :throttle | :block | :kill_process

  @type usage_report :: %{
    entity_type: entity_type(),
    entity_id: entity_id(),
    period_start: DateTime.t(),
    period_end: DateTime.t(),
    total_inferences: non_neg_integer(),
    total_tokens_in: non_neg_integer(),
    total_tokens_out: non_neg_integer(),
    total_cost_usd: float(),
    avg_latency_ms: float() | nil,
    models_used: [String.t()],
    cost_breakdown: %{String.t() => float()}
  }

  @type inference_record :: %{
    id: String.t(),
    agent_id: String.t(),
    model_id: String.t(),
    tokens_in: non_neg_integer(),
    tokens_out: non_neg_integer(),
    latency_ms: non_neg_integer(),
    cost_usd: float(),
    user_id: String.t() | nil,
    process_id: String.t() | nil,
    team_id: String.t() | nil,
    timestamp: DateTime.t()
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track an AI inference for cost accounting.

  ## Parameters

  - `agent_id` - Agent identifier
  - `model_id` - Model name (e.g., "gpt-4", "claude-3-opus")
  - `tokens_in` - Number of input tokens
  - `tokens_out` - Number of output tokens
  - `latency_ms` - Request latency in milliseconds

  ## Options

  - `:user_id` - User who initiated the request
  - `:process_id` - Process/session identifier
  - `:team_id` - Team/organization identifier
  - `:session_id` - InferenceTracker session ID for correlation

  ## Returns

  `{:ok, inference_record}` with calculated cost
  """
  @spec track_inference(String.t(), String.t(), non_neg_integer(), non_neg_integer(), non_neg_integer(), keyword()) ::
    {:ok, inference_record()}
  def track_inference(agent_id, model_id, tokens_in, tokens_out, latency_ms, opts \\ []) do
    GenServer.call(__MODULE__, {:track_inference, agent_id, model_id, tokens_in, tokens_out, latency_ms, opts})
  end

  @doc """
  Set budget limits for an entity.

  ## Parameters

  - `entity_type` - One of :model, :user, :process, :team, :agent
  - `entity_id` - Entity identifier
  - `limits` - Budget limits map

  ## Examples

      # Set daily budget for a user
      set_budget(:user, "user-123", %{daily_usd: 50.0, tokens_per_min: 5000})

      # Set hourly limit for a model
      set_budget(:model, "gpt-4", %{hourly_usd: 100.0, inferences_per_hour: 500})

      # Set limits with custom actions
      set_budget(:team, "engineering", %{
        daily_usd: 500.0,
        alert_thresholds: [50, 75, 90, 100],
        actions: %{50 => :alert, 90 => :throttle, 100 => :kill_process}
      })
  """
  @spec set_budget(entity_type(), entity_id(), budget_limits()) :: :ok
  def set_budget(entity_type, entity_id, limits) when is_atom(entity_type) and is_binary(entity_id) do
    GenServer.call(__MODULE__, {:set_budget, entity_type, entity_id, limits})
  end

  @doc """
  Get budget configuration for an entity.

  Returns `{:ok, limits}` or `{:error, :not_found}`.
  """
  @spec get_budget(entity_type(), entity_id()) :: {:ok, budget_limits()} | {:error, :not_found}
  def get_budget(entity_type, entity_id) do
    GenServer.call(__MODULE__, {:get_budget, entity_type, entity_id})
  end

  @doc """
  Remove budget limits for an entity.
  """
  @spec remove_budget(entity_type(), entity_id()) :: :ok
  def remove_budget(entity_type, entity_id) do
    GenServer.call(__MODULE__, {:remove_budget, entity_type, entity_id})
  end

  @doc """
  Check budget status for an entity.

  Returns:
  - `{:ok, remaining}` - Budget not exceeded, with remaining amounts
  - `{:exceeded, action}` - Budget exceeded, with recommended action

  ## Example

      case check_budget(:user, "user-123") do
        {:ok, %{daily_usd: 45.0, tokens_per_min: 3000}} ->
          # Proceed with inference

        {:exceeded, :throttle} ->
          # Apply rate limiting

        {:exceeded, :block} ->
          # Block the request
      end
  """
  @spec check_budget(entity_type(), entity_id()) :: {:ok, map()} | {:exceeded, action()}
  def check_budget(entity_type, entity_id) do
    GenServer.call(__MODULE__, {:check_budget, entity_type, entity_id})
  end

  @doc """
  Get usage report for an entity over a time period.

  ## Parameters

  - `entity_type` - Entity type
  - `entity_id` - Entity identifier
  - `period` - One of :hour, :day, :week, :month, or `{:custom, start_dt, end_dt}`

  ## Returns

  `UsageReport` struct with aggregated metrics.
  """
  @spec get_usage(entity_type(), entity_id(), atom() | tuple()) :: usage_report()
  def get_usage(entity_type, entity_id, period \\ :day) do
    GenServer.call(__MODULE__, {:get_usage, entity_type, entity_id, period})
  end

  @doc """
  Get real-time cost metrics for all entities.

  Returns aggregated metrics across all tracked entities.
  """
  @spec get_metrics() :: map()
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end

  @doc """
  Get model pricing configuration.
  """
  @spec get_pricing() :: map()
  def get_pricing do
    GenServer.call(__MODULE__, :get_pricing)
  end

  @doc """
  Update pricing for a specific model.
  """
  @spec set_model_pricing(String.t(), float(), float()) :: :ok
  def set_model_pricing(model_id, input_price, output_price) do
    GenServer.call(__MODULE__, {:set_model_pricing, model_id, input_price, output_price})
  end

  @doc """
  Enforce budget action for an entity.

  Called internally when budget is exceeded, but can also be called manually.
  """
  @spec enforce_action(entity_type(), entity_id(), action(), map()) :: :ok | {:error, term()}
  def enforce_action(entity_type, entity_id, action, context \\ %{}) do
    GenServer.cast(__MODULE__, {:enforce_action, entity_type, entity_id, action, context})
  end

  @doc """
  Get top cost consumers for a period.

  Returns list of `{entity_type, entity_id, total_cost_usd}` sorted by cost descending.
  """
  @spec get_top_consumers(atom(), pos_integer()) :: [{entity_type(), entity_id(), float()}]
  def get_top_consumers(period \\ :day, limit \\ 10) do
    GenServer.call(__MODULE__, {:get_top_consumers, period, limit})
  end

  @doc """
  Subscribe to cost alerts for real-time notifications.
  """
  @spec subscribe() :: :ok
  def subscribe do
    PubSub.subscribe(TamanduaServer.PubSub, "ai:cost_governor")
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_budgets, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@ets_usage, [:set, :named_table, :public, read_concurrency: true, write_concurrency: true])
    :ets.new(@ets_inferences, [:ordered_set, :named_table, :public, read_concurrency: true, write_concurrency: true])

    # Load pricing from config
    pricing = Application.get_env(:tamandua_server, __MODULE__, [])
    |> Keyword.get(:model_pricing, @default_pricing)

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval)

    Logger.info("[CostGovernor] Started with #{map_size(pricing)} model pricing entries")

    {:ok, %{pricing: pricing, alerts_sent: MapSet.new()}}
  end

  @impl true
  def handle_call({:track_inference, agent_id, model_id, tokens_in, tokens_out, latency_ms, opts}, _from, state) do
    now = DateTime.utc_now()
    inference_id = Ecto.UUID.generate()

    # Calculate cost
    cost_usd = calculate_cost(model_id, tokens_in, tokens_out, state.pricing)

    # Build inference record
    record = %{
      id: inference_id,
      agent_id: agent_id,
      model_id: model_id,
      tokens_in: tokens_in,
      tokens_out: tokens_out,
      latency_ms: latency_ms,
      cost_usd: cost_usd,
      user_id: Keyword.get(opts, :user_id),
      process_id: Keyword.get(opts, :process_id),
      team_id: Keyword.get(opts, :team_id),
      session_id: Keyword.get(opts, :session_id),
      timestamp: now
    }

    # Store inference record
    ts_key = {DateTime.to_unix(now, :microsecond), inference_id}
    :ets.insert(@ets_inferences, {ts_key, record})

    # Update usage counters for all relevant entities
    update_usage(:agent, agent_id, record, now)
    update_usage(:model, model_id, record, now)
    if record.user_id, do: update_usage(:user, record.user_id, record, now)
    if record.process_id, do: update_usage(:process, record.process_id, record, now)
    if record.team_id, do: update_usage(:team, record.team_id, record, now)

    # Check budgets and trigger alerts/actions
    state = check_and_enforce_budgets(record, state)

    # Broadcast the inference event
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "ai:cost_governor",
      {:inference_tracked, record}
    )

    Logger.debug("[CostGovernor] Tracked inference: model=#{model_id}, tokens=#{tokens_in + tokens_out}, cost=$#{Float.round(cost_usd, 4)}")

    {:reply, {:ok, record}, state}
  end

  @impl true
  def handle_call({:set_budget, entity_type, entity_id, limits}, _from, state) do
    key = {entity_type, entity_id}

    # Normalize limits with defaults
    normalized = %{
      daily_usd: Map.get(limits, :daily_usd),
      hourly_usd: Map.get(limits, :hourly_usd),
      tokens_per_min: Map.get(limits, :tokens_per_min),
      inferences_per_hour: Map.get(limits, :inferences_per_hour),
      alert_thresholds: Map.get(limits, :alert_thresholds, [50, 75, 90, 100]),
      actions: Map.merge(@default_actions, Map.get(limits, :actions, %{})),
      created_at: DateTime.utc_now()
    }

    :ets.insert(@ets_budgets, {key, normalized})

    Logger.info("[CostGovernor] Set budget for #{entity_type}:#{entity_id}: #{inspect(limits)}")

    # Broadcast budget change
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "ai:cost_governor",
      {:budget_set, entity_type, entity_id, normalized}
    )

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_budget, entity_type, entity_id}, _from, state) do
    key = {entity_type, entity_id}

    result = case :ets.lookup(@ets_budgets, key) do
      [{^key, limits}] -> {:ok, limits}
      [] -> {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:remove_budget, entity_type, entity_id}, _from, state) do
    key = {entity_type, entity_id}
    :ets.delete(@ets_budgets, key)

    Logger.info("[CostGovernor] Removed budget for #{entity_type}:#{entity_id}")

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:check_budget, entity_type, entity_id}, _from, state) do
    result = do_check_budget(entity_type, entity_id, state.pricing)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_usage, entity_type, entity_id, period}, _from, state) do
    report = build_usage_report(entity_type, entity_id, period)
    {:reply, report, state}
  end

  @impl true
  def handle_call(:get_metrics, _from, state) do
    metrics = %{
      total_inferences: count_inferences(:hour),
      total_cost_usd_hour: sum_cost(:hour),
      total_cost_usd_day: sum_cost(:day),
      total_tokens_hour: sum_tokens(:hour),
      active_budgets: :ets.info(@ets_budgets, :size),
      models_tracked: count_unique_models(),
      pricing_entries: map_size(state.pricing)
    }

    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:get_pricing, _from, state) do
    {:reply, state.pricing, state}
  end

  @impl true
  def handle_call({:set_model_pricing, model_id, input_price, output_price}, _from, state) do
    new_pricing = Map.put(state.pricing, model_id, %{input: input_price, output: output_price})

    Logger.info("[CostGovernor] Updated pricing for #{model_id}: input=$#{input_price}/1M, output=$#{output_price}/1M")

    {:reply, :ok, %{state | pricing: new_pricing}}
  end

  @impl true
  def handle_call({:get_top_consumers, period, limit}, _from, state) do
    {start_time, _end_time} = period_to_range(period)
    start_ts = DateTime.to_unix(start_time, :microsecond)

    # Aggregate costs by entity
    costs = :ets.foldl(fn {{ts, _id}, record}, acc ->
      if ts >= start_ts do
        # Track costs for each entity type
        acc = if record.agent_id do
          key = {:agent, record.agent_id}
          Map.update(acc, key, record.cost_usd, & &1 + record.cost_usd)
        else
          acc
        end

        acc = if record.user_id do
          key = {:user, record.user_id}
          Map.update(acc, key, record.cost_usd, & &1 + record.cost_usd)
        else
          acc
        end

        acc = if record.model_id do
          key = {:model, record.model_id}
          Map.update(acc, key, record.cost_usd, & &1 + record.cost_usd)
        else
          acc
        end

        acc
      else
        acc
      end
    end, %{}, @ets_inferences)

    # Sort and take top N
    top = costs
    |> Enum.sort_by(fn {_k, v} -> v end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {{type, id}, cost} -> {type, id, Float.round(cost, 4)} end)

    {:reply, top, state}
  end

  @impl true
  def handle_cast({:enforce_action, entity_type, entity_id, action, context}, state) do
    do_enforce_action(entity_type, entity_id, action, context)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Clean up old inference records (older than 24 hours)
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)
    cutoff_ts = DateTime.to_unix(cutoff, :microsecond)

    deleted = :ets.select_delete(@ets_inferences, [
      {{{:"$1", :_}, :_}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    if deleted > 0 do
      Logger.debug("[CostGovernor] Cleaned up #{deleted} old inference records")
    end

    # Reset daily alert tracking at midnight
    now = DateTime.utc_now()
    state = if now.hour == 0 and now.minute < 5 do
      %{state | alerts_sent: MapSet.new()}
    else
      state
    end

    # Schedule next cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval)

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp calculate_cost(model_id, tokens_in, tokens_out, pricing) do
    # Normalize model_id for lookup
    normalized = model_id
    |> String.downcase()
    |> String.replace(~r/[-_.]/, "-")

    # Find matching pricing or use default
    model_pricing = Enum.find_value(pricing, fn {key, value} ->
      if String.contains?(normalized, String.downcase(key)) do
        value
      end
    end) || Map.get(pricing, "default", %{input: 1.0, output: 3.0})

    # Calculate cost (pricing is per 1M tokens)
    input_cost = (tokens_in / 1_000_000) * model_pricing.input
    output_cost = (tokens_out / 1_000_000) * model_pricing.output

    input_cost + output_cost
  end

  defp update_usage(entity_type, entity_id, record, now) do
    key = {entity_type, entity_id}

    # Get or create usage record
    usage = case :ets.lookup(@ets_usage, key) do
      [{^key, existing}] -> existing
      [] -> %{
        total_inferences: 0,
        total_tokens_in: 0,
        total_tokens_out: 0,
        total_cost_usd: 0.0,
        total_latency_ms: 0,
        models: MapSet.new(),
        minute_tokens: [],  # [{minute_ts, tokens}]
        hour_inferences: [], # [{hour_ts, count}]
        day_cost: [],  # [{day_ts, cost}]
        last_updated: now
      }
    end

    # Calculate time buckets
    minute_ts = div(DateTime.to_unix(now), 60) * 60
    hour_ts = div(DateTime.to_unix(now), 3600) * 3600
    day_ts = Date.to_iso8601(DateTime.to_date(now))

    # Update rolling windows
    minute_tokens = update_rolling_window(usage.minute_tokens, minute_ts, record.tokens_in + record.tokens_out, 60)
    hour_inferences = update_rolling_window(usage.hour_inferences, hour_ts, 1, 24)
    day_cost = update_rolling_window(usage.day_cost, day_ts, record.cost_usd, 30)

    updated = %{
      total_inferences: usage.total_inferences + 1,
      total_tokens_in: usage.total_tokens_in + record.tokens_in,
      total_tokens_out: usage.total_tokens_out + record.tokens_out,
      total_cost_usd: usage.total_cost_usd + record.cost_usd,
      total_latency_ms: usage.total_latency_ms + record.latency_ms,
      models: MapSet.put(usage.models, record.model_id),
      minute_tokens: minute_tokens,
      hour_inferences: hour_inferences,
      day_cost: day_cost,
      last_updated: now
    }

    :ets.insert(@ets_usage, {key, updated})
  end

  defp update_rolling_window(window, bucket_key, value, max_buckets) do
    # Update or add to bucket
    window = case Enum.find_index(window, fn {k, _v} -> k == bucket_key end) do
      nil -> [{bucket_key, value} | window]
      idx ->
        List.update_at(window, idx, fn {k, v} -> {k, v + value} end)
    end

    # Keep only recent buckets
    window
    |> Enum.sort_by(fn {k, _v} -> k end, :desc)
    |> Enum.take(max_buckets)
  end

  defp do_check_budget(entity_type, entity_id, _pricing) do
    key = {entity_type, entity_id}

    case :ets.lookup(@ets_budgets, key) do
      [{^key, limits}] ->
        case :ets.lookup(@ets_usage, key) do
          [{^key, usage}] ->
            check_limits(limits, usage)
          [] ->
            # No usage yet, all limits available
            {:ok, %{
              daily_usd: limits.daily_usd,
              hourly_usd: limits.hourly_usd,
              tokens_per_min: limits.tokens_per_min,
              inferences_per_hour: limits.inferences_per_hour
            }}
        end
      [] ->
        # No budget set, allow everything
        {:ok, %{unlimited: true}}
    end
  end

  defp check_limits(limits, usage) do
    now = DateTime.utc_now()

    # Calculate current usage rates
    tokens_per_min = sum_recent_window(usage.minute_tokens, 60, now)
    inferences_per_hour = sum_recent_window(usage.hour_inferences, 3600, now)

    # Calculate today's cost
    today = Date.to_iso8601(DateTime.to_date(now))
    daily_cost = Enum.find_value(usage.day_cost, 0.0, fn {day, cost} ->
      if day == today, do: cost
    end) || 0.0

    # Calculate last hour's cost
    hour_ts = div(DateTime.to_unix(now), 3600) * 3600
    hourly_cost = Enum.reduce(usage.day_cost, 0.0, fn {_day, cost}, acc ->
      # Approximate hourly cost from daily window
      acc + cost / 24
    end)

    # Check each limit
    violations = []

    violations = if limits.daily_usd && daily_cost >= limits.daily_usd do
      [{:daily_usd, daily_cost, limits.daily_usd, 100} | violations]
    else
      if limits.daily_usd && daily_cost >= limits.daily_usd * 0.9 do
        [{:daily_usd, daily_cost, limits.daily_usd, 90} | violations]
      else
        violations
      end
    end

    violations = if limits.hourly_usd && hourly_cost >= limits.hourly_usd do
      [{:hourly_usd, hourly_cost, limits.hourly_usd, 100} | violations]
    else
      violations
    end

    violations = if limits.tokens_per_min && tokens_per_min >= limits.tokens_per_min do
      [{:tokens_per_min, tokens_per_min, limits.tokens_per_min, 100} | violations]
    else
      violations
    end

    violations = if limits.inferences_per_hour && inferences_per_hour >= limits.inferences_per_hour do
      [{:inferences_per_hour, inferences_per_hour, limits.inferences_per_hour, 100} | violations]
    else
      violations
    end

    if Enum.empty?(violations) do
      # Return remaining amounts
      remaining = %{
        daily_usd: if(limits.daily_usd, do: limits.daily_usd - daily_cost, else: nil),
        hourly_usd: if(limits.hourly_usd, do: limits.hourly_usd - hourly_cost, else: nil),
        tokens_per_min: if(limits.tokens_per_min, do: limits.tokens_per_min - tokens_per_min, else: nil),
        inferences_per_hour: if(limits.inferences_per_hour, do: limits.inferences_per_hour - inferences_per_hour, else: nil)
      }
      {:ok, remaining}
    else
      # Find the highest violation percentage and its action
      {_metric, _current, _limit, highest_pct} = Enum.max_by(violations, fn {_, _, _, pct} -> pct end)

      # Find the action for this threshold
      action = Enum.find_value(limits.actions, :block, fn {threshold, act} ->
        if highest_pct >= threshold, do: act
      end)

      {:exceeded, action}
    end
  end

  defp sum_recent_window(window, seconds_or_days, now) when is_list(window) do
    if is_integer(seconds_or_days) do
      # Numeric timestamp comparison
      cutoff = DateTime.to_unix(now) - seconds_or_days
      Enum.reduce(window, 0, fn {ts, value}, acc ->
        if is_integer(ts) and ts >= cutoff, do: acc + value, else: acc
      end)
    else
      # Just sum all (for day-based windows)
      Enum.reduce(window, 0, fn {_ts, value}, acc -> acc + value end)
    end
  end

  defp check_and_enforce_budgets(record, state) do
    # Check budgets for all relevant entities
    entities = [
      {:agent, record.agent_id},
      {:model, record.model_id}
    ]
    |> maybe_add({:user, record.user_id})
    |> maybe_add({:process, record.process_id})
    |> maybe_add({:team, record.team_id})

    Enum.reduce(entities, state, fn {entity_type, entity_id}, acc_state ->
      case do_check_budget(entity_type, entity_id, acc_state.pricing) do
        {:exceeded, action} ->
          # Check if we already sent an alert for this entity today
          alert_key = {entity_type, entity_id, Date.utc_today()}

          if not MapSet.member?(acc_state.alerts_sent, alert_key) do
            # Enforce the action
            context = %{
              record: record,
              entity_type: entity_type,
              entity_id: entity_id
            }
            do_enforce_action(entity_type, entity_id, action, context)

            %{acc_state | alerts_sent: MapSet.put(acc_state.alerts_sent, alert_key)}
          else
            acc_state
          end

        {:ok, _remaining} ->
          acc_state
      end
    end)
  end

  defp maybe_add(list, {_type, nil}), do: list
  defp maybe_add(list, item), do: [item | list]

  defp do_enforce_action(entity_type, entity_id, action, context) do
    Logger.warning("[CostGovernor] Enforcing #{action} on #{entity_type}:#{entity_id}")

    case action do
      :alert ->
        # Broadcast alert via PubSub
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ai:cost_governor",
          {:budget_alert, entity_type, entity_id, :warning, context}
        )

      :throttle ->
        # Apply rate limiting via existing rate limiter
        # This reduces the allowed requests per minute
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ai:cost_governor",
          {:budget_alert, entity_type, entity_id, :throttle, context}
        )

      :block ->
        # Block further requests via ModelPolicy if it's a model
        if entity_type == :model do
          ModelPolicy.ensure_started()
          ModelPolicy.block_model(entity_id, "budget_exceeded")
        end

        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ai:cost_governor",
          {:budget_alert, entity_type, entity_id, :blocked, context}
        )

      :kill_process ->
        # Kill the process via agent executor if we have process context
        case context do
          %{record: %{agent_id: agent_id, process_id: process_id}} when not is_nil(process_id) ->
            # Parse PID from process_id if it's numeric
            pid = parse_pid(process_id)
            if pid do
              spawn(fn ->
                Executor.kill_process(agent_id, pid, force: true)
              end)
            end

          _ ->
            :ok
        end

        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ai:cost_governor",
          {:budget_alert, entity_type, entity_id, :killed, context}
        )
    end

    :ok
  end

  defp parse_pid(process_id) when is_integer(process_id), do: process_id
  defp parse_pid(process_id) when is_binary(process_id) do
    case Integer.parse(process_id) do
      {pid, ""} -> pid
      _ -> nil
    end
  end
  defp parse_pid(_), do: nil

  defp build_usage_report(entity_type, entity_id, period) do
    {start_time, end_time} = period_to_range(period)
    key = {entity_type, entity_id}

    # Get cached usage data
    usage = case :ets.lookup(@ets_usage, key) do
      [{^key, u}] -> u
      [] -> nil
    end

    # Calculate detailed metrics from inference records
    start_ts = DateTime.to_unix(start_time, :microsecond)
    end_ts = DateTime.to_unix(end_time, :microsecond)

    {inferences, tokens_in, tokens_out, cost, latencies, models, cost_breakdown} =
      :ets.foldl(fn {{ts, _id}, record}, {count, t_in, t_out, c, lats, mods, breakdown} ->
        if ts >= start_ts and ts <= end_ts do
          # Check if this record belongs to the entity
          belongs = case entity_type do
            :agent -> record.agent_id == entity_id
            :user -> record.user_id == entity_id
            :model -> record.model_id == entity_id
            :process -> record.process_id == entity_id
            :team -> record.team_id == entity_id
          end

          if belongs do
            new_breakdown = Map.update(breakdown, record.model_id, record.cost_usd, & &1 + record.cost_usd)
            {
              count + 1,
              t_in + record.tokens_in,
              t_out + record.tokens_out,
              c + record.cost_usd,
              [record.latency_ms | lats],
              MapSet.put(mods, record.model_id),
              new_breakdown
            }
          else
            {count, t_in, t_out, c, lats, mods, breakdown}
          end
        else
          {count, t_in, t_out, c, lats, mods, breakdown}
        end
      end, {0, 0, 0, 0.0, [], MapSet.new(), %{}}, @ets_inferences)

    avg_latency = if length(latencies) > 0, do: Enum.sum(latencies) / length(latencies), else: nil

    %{
      entity_type: entity_type,
      entity_id: entity_id,
      period_start: start_time,
      period_end: end_time,
      total_inferences: inferences,
      total_tokens_in: tokens_in,
      total_tokens_out: tokens_out,
      total_cost_usd: Float.round(cost, 4),
      avg_latency_ms: if(avg_latency, do: Float.round(avg_latency, 2)),
      models_used: MapSet.to_list(models),
      cost_breakdown: Map.new(cost_breakdown, fn {k, v} -> {k, Float.round(v, 4)} end),
      cached_total_inferences: if(usage, do: usage.total_inferences, else: 0),
      cached_total_cost_usd: if(usage, do: Float.round(usage.total_cost_usd, 4), else: 0.0)
    }
  end

  defp period_to_range(:hour) do
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -3600, :second)
    {start_time, now}
  end

  defp period_to_range(:day) do
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -86400, :second)
    {start_time, now}
  end

  defp period_to_range(:week) do
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -604800, :second)
    {start_time, now}
  end

  defp period_to_range(:month) do
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -2592000, :second)
    {start_time, now}
  end

  defp period_to_range({:custom, start_time, end_time}) do
    {start_time, end_time}
  end

  defp count_inferences(period) do
    {start_time, _end_time} = period_to_range(period)
    start_ts = DateTime.to_unix(start_time, :microsecond)

    :ets.foldl(fn {{ts, _id}, _record}, acc ->
      if ts >= start_ts, do: acc + 1, else: acc
    end, 0, @ets_inferences)
  end

  defp sum_cost(period) do
    {start_time, _end_time} = period_to_range(period)
    start_ts = DateTime.to_unix(start_time, :microsecond)

    total = :ets.foldl(fn {{ts, _id}, record}, acc ->
      if ts >= start_ts, do: acc + record.cost_usd, else: acc
    end, 0.0, @ets_inferences)

    Float.round(total, 4)
  end

  defp sum_tokens(period) do
    {start_time, _end_time} = period_to_range(period)
    start_ts = DateTime.to_unix(start_time, :microsecond)

    :ets.foldl(fn {{ts, _id}, record}, acc ->
      if ts >= start_ts, do: acc + record.tokens_in + record.tokens_out, else: acc
    end, 0, @ets_inferences)
  end

  defp count_unique_models do
    :ets.foldl(fn {_key, record}, acc ->
      MapSet.put(acc, record.model_id)
    end, MapSet.new(), @ets_inferences)
    |> MapSet.size()
  end
end
