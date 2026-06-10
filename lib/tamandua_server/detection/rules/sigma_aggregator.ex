defmodule TamanduaServer.Detection.Rules.SigmaAggregator do
  @moduledoc """
  Sigma rule timeframe aggregation engine.

  Handles Sigma rules that include `timeframe` and aggregation conditions
  like `count() > N` or `count(field) > N` over a sliding time window.

  Events matching a rule's selection are buffered per (rule_id, agent_id).
  Aggregation conditions are evaluated against the buffered window.

  Uses ETS for fast lookups with automatic expiry cleanup.
  """

  use GenServer
  require Logger

  @table_name :sigma_aggregation_windows
  @cleanup_interval :timer.minutes(1)

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a selection match for a rule that has a timeframe/aggregation condition.

  Returns `{:trigger, count}` if the aggregation threshold is now exceeded,
  or `:buffered` if the event was stored but threshold not yet met.
  """
  @spec record_match(String.t(), String.t(), map(), map()) ::
          {:trigger, non_neg_integer()} | :buffered
  def record_match(rule_id, agent_id, event, aggregation_config) do
    GenServer.call(__MODULE__, {:record_match, rule_id, agent_id, event, aggregation_config})
  end

  @doc """
  Check if a rule's aggregation condition is currently met without adding a new event.
  """
  @spec check_threshold(String.t(), String.t(), map()) ::
          {:exceeded, non_neg_integer()} | {:below, non_neg_integer()}
  def check_threshold(rule_id, agent_id, aggregation_config) do
    GenServer.call(__MODULE__, {:check_threshold, rule_id, agent_id, aggregation_config})
  end

  @doc """
  Get aggregation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    :ets.new(@table_name, [:named_table, :bag, :public, read_concurrency: true])
    schedule_cleanup()

    state = %{
      stats: %{
        events_buffered: 0,
        thresholds_triggered: 0,
        windows_cleaned: 0
      }
    }

    Logger.info("Sigma Aggregator started")
    {:ok, state}
  end

  @impl true
  def handle_call({:record_match, rule_id, agent_id, event, agg_config}, _from, state) do
    now = System.system_time(:millisecond)
    key = {rule_id, agent_id}

    # Extract the field value for count(field) conditions
    field_value = extract_aggregation_field(event, agg_config)

    entry = %{
      timestamp: now,
      event_id: event[:event_id] || event["event_id"],
      field_value: field_value
    }

    :ets.insert(@table_name, {key, entry})

    # Evaluate the aggregation condition
    {result, count} = evaluate_aggregation(key, agg_config, now)

    new_stats = Map.update!(state.stats, :events_buffered, &(&1 + 1))
    new_stats = if result == :trigger do
      Map.update!(new_stats, :thresholds_triggered, &(&1 + 1))
    else
      new_stats
    end

    reply = if result == :trigger, do: {:trigger, count}, else: :buffered
    {:reply, reply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:check_threshold, rule_id, agent_id, agg_config}, _from, state) do
    now = System.system_time(:millisecond)
    key = {rule_id, agent_id}

    {result, count} = evaluate_aggregation(key, agg_config, now)

    reply = if result == :trigger, do: {:exceeded, count}, else: {:below, count}
    {:reply, reply, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleaned = cleanup_expired_windows()
    new_stats = Map.update!(state.stats, :windows_cleaned, &(&1 + cleaned))
    schedule_cleanup()
    {:noreply, %{state | stats: new_stats}}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp evaluate_aggregation(key, agg_config, now) do
    timeframe_ms = parse_timeframe(agg_config[:timeframe] || agg_config["timeframe"] || "5m")
    threshold = agg_config[:threshold] || agg_config["threshold"] || 1
    operator = agg_config[:operator] || agg_config["operator"] || ">"
    field = agg_config[:field] || agg_config["field"]

    # Get entries within the time window
    window_start = now - timeframe_ms

    entries = :ets.lookup(@table_name, key)
    |> Enum.map(fn {_key, entry} -> entry end)
    |> Enum.filter(fn entry -> entry.timestamp >= window_start end)

    # Calculate the count based on field or total
    count = if field && field != "" do
      # count(field) = count of distinct values
      entries
      |> Enum.map(& &1.field_value)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> length()
    else
      # count() = total number of matching events
      length(entries)
    end

    # Evaluate the condition
    exceeded = case operator do
      ">" -> count > threshold
      ">=" -> count >= threshold
      "<" -> count < threshold
      "<=" -> count <= threshold
      "==" -> count == threshold
      "=" -> count == threshold
      _ -> count > threshold
    end

    result = if exceeded, do: :trigger, else: :below
    {result, count}
  end

  defp extract_aggregation_field(event, agg_config) do
    field = agg_config[:field] || agg_config["field"]

    if field && field != "" do
      payload = event[:payload] || event["payload"] || %{}

      # Try payload first, then top-level event
      payload[field] || payload[String.to_atom(field)] ||
        event[field] || event[String.to_atom(field)]
    else
      nil
    end
  end

  @doc false
  def parse_timeframe(timeframe) when is_binary(timeframe) do
    case Regex.run(~r/^(\d+)(s|m|h|d)$/, timeframe) do
      [_, amount_str, unit] ->
        {amount, ""} = Integer.parse(amount_str)
        case unit do
          "s" -> amount * 1_000
          "m" -> amount * 60_000
          "h" -> amount * 3_600_000
          "d" -> amount * 86_400_000
          _ -> 300_000  # Default 5 minutes
        end
      _ ->
        # Try parsing as seconds
        case Integer.parse(timeframe) do
          {seconds, _} -> seconds * 1_000
          _ -> 300_000  # Default 5 minutes
        end
    end
  end

  def parse_timeframe(seconds) when is_integer(seconds), do: seconds * 1_000
  def parse_timeframe(_), do: 300_000

  defp cleanup_expired_windows do
    now = System.system_time(:millisecond)
    # Remove entries older than 1 hour (max reasonable timeframe)
    max_ttl = 3_600_000

    all_entries = :ets.tab2list(@table_name)
    expired = Enum.filter(all_entries, fn {_key, entry} ->
      entry.timestamp < (now - max_ttl)
    end)

    Enum.each(expired, fn entry ->
      :ets.delete_object(@table_name, entry)
    end)

    length(expired)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
