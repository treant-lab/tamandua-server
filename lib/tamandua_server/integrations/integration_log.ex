defmodule TamanduaServer.Integrations.IntegrationLog do
  @moduledoc """
  ETS-backed Integration Log for tracking all integration API calls.

  Stores log entries for every outbound API call made by integration modules
  (SOAR, Ticketing, SIEM, etc.), providing observability into integration health
  and debugging capability.

  ## Log Entry Fields

  - `id` - Unique log entry ID
  - `integration_name` - Name of the integration (e.g., "tines", "servicenow", "jira")
  - `action` - The action performed (e.g., "create_incident", "trigger_playbook")
  - `status` - Result status: "success", "error", "timeout"
  - `request_body` - Outbound request payload (truncated if large)
  - `response_body` - Response payload (truncated if large)
  - `error_message` - Error description when status is "error"
  - `duration_ms` - Request duration in milliseconds
  - `inserted_at` - Timestamp of log creation

  ## Cleanup

  Entries older than 30 days are automatically purged every hour.
  """

  use GenServer
  require Logger

  @ets_table :integration_logs
  @max_body_size 4096
  @cleanup_interval :timer.hours(1)
  @retention_seconds 30 * 24 * 60 * 60  # 30 days

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an integration API call.

  ## Parameters

  - `integration_name` - The integration identifier (e.g., "tines", "servicenow")
  - `action` - The action being performed (e.g., "create_incident")
  - `attrs` - Map with optional keys: `:status`, `:request_body`, `:response_body`,
    `:error_message`, `:duration_ms`

  ## Returns

  The created log entry map.
  """
  @spec log_call(String.t(), String.t(), map()) :: map()
  def log_call(integration_name, action, attrs \\ %{}) do
    entry = %{
      id: generate_id(),
      integration_name: to_string(integration_name),
      action: to_string(action),
      status: Map.get(attrs, :status, "success"),
      request_body: truncate_body(Map.get(attrs, :request_body)),
      response_body: truncate_body(Map.get(attrs, :response_body)),
      error_message: Map.get(attrs, :error_message),
      duration_ms: Map.get(attrs, :duration_ms),
      inserted_at: DateTime.utc_now()
    }

    :ets.insert(@ets_table, {entry.id, entry})
    entry
  end

  @doc """
  Wrap an integration API call with automatic logging.

  Executes `fun`, measures duration, and logs the result. Returns the
  original result of `fun`.

  ## Example

      IntegrationLog.log_api_call("tines", "trigger_playbook", request_body, fn ->
        Finch.request(request, TamanduaServer.Finch)
      end)
  """
  @spec log_api_call(String.t(), String.t(), term(), (-> term())) :: term()
  def log_api_call(integration_name, action, request_body, fun) when is_function(fun, 0) do
    start_time = System.monotonic_time(:millisecond)

    result = try do
      fun.()
    rescue
      e ->
        duration = System.monotonic_time(:millisecond) - start_time
        log_call(integration_name, action, %{
          status: "error",
          request_body: request_body,
          error_message: Exception.message(e),
          duration_ms: duration
        })
        reraise e, __STACKTRACE__
    end

    duration = System.monotonic_time(:millisecond) - start_time

    case result do
      {:ok, response} ->
        log_call(integration_name, action, %{
          status: "success",
          request_body: request_body,
          response_body: response,
          duration_ms: duration
        })

      {:error, reason} ->
        log_call(integration_name, action, %{
          status: "error",
          request_body: request_body,
          error_message: format_error(reason),
          duration_ms: duration
        })

      _ ->
        log_call(integration_name, action, %{
          status: "success",
          request_body: request_body,
          duration_ms: duration
        })
    end

    result
  end

  @doc """
  Retrieve integration logs with optional filtering and pagination.

  ## Options

  - `:integration_name` - Filter by integration name
  - `:status` - Filter by status ("success", "error", "timeout")
  - `:action` - Filter by action
  - `:from` - Start of date range (DateTime)
  - `:to` - End of date range (DateTime)
  - `:limit` - Maximum number of entries to return (default 100)
  - `:offset` - Number of entries to skip (default 0)

  ## Returns

  `{entries, total_count}` tuple where `entries` is the filtered and paginated
  list of log entries sorted by newest first, and `total_count` is the total
  number of matching entries before pagination.
  """
  @spec list_logs(keyword()) :: {[map()], non_neg_integer()}
  def list_logs(opts \\ []) do
    integration_name = Keyword.get(opts, :integration_name)
    status = Keyword.get(opts, :status)
    action = Keyword.get(opts, :action)
    from_dt = Keyword.get(opts, :from)
    to_dt = Keyword.get(opts, :to)
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    all_entries = :ets.tab2list(@ets_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.filter(fn entry ->
      matches_filter?(entry, :integration_name, integration_name) and
      matches_filter?(entry, :status, status) and
      matches_filter?(entry, :action, action) and
      matches_date_range?(entry, from_dt, to_dt)
    end)
    |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})

    total = length(all_entries)

    entries = all_entries
    |> Enum.drop(offset)
    |> Enum.take(limit)

    {entries, total}
  end

  @doc """
  Get a single log entry by ID.
  """
  @spec get_log(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_log(id) do
    case :ets.lookup(@ets_table, id) do
      [{_id, entry}] -> {:ok, entry}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get log counts grouped by integration name and status.
  """
  @spec get_summary() :: map()
  def get_summary do
    :ets.tab2list(@ets_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.reduce(%{}, fn entry, acc ->
      key = entry.integration_name
      status = entry.status

      integration_stats = Map.get(acc, key, %{total: 0, success: 0, error: 0, timeout: 0, avg_duration_ms: 0, durations: []})

      integration_stats = %{integration_stats |
        total: integration_stats.total + 1
      }

      integration_stats = Map.update(integration_stats, String.to_atom(status), 1, &(&1 + 1))

      integration_stats = if entry.duration_ms do
        Map.update(integration_stats, :durations, [entry.duration_ms], &[entry.duration_ms | &1])
      else
        integration_stats
      end

      Map.put(acc, key, integration_stats)
    end)
    |> Enum.map(fn {name, stats} ->
      durations = Map.get(stats, :durations, [])
      avg = if length(durations) > 0, do: Enum.sum(durations) / length(durations), else: 0

      {name, stats
        |> Map.put(:avg_duration_ms, round(avg))
        |> Map.delete(:durations)
      }
    end)
    |> Map.new()
  end

  @doc """
  Delete all log entries. Used for testing.
  """
  @spec clear_all() :: :ok
  def clear_all do
    :ets.delete_all_objects(@ets_table)
    :ok
  end

  @doc """
  Get total log count.
  """
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@ets_table, :size)
  end

  # ---------------------------------------------------------------------------
  # Server Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true, write_concurrency: true])
    Logger.info("IntegrationLog started (ETS table: #{inspect(table)})")

    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleaned = cleanup_old_entries()
    if cleaned > 0 do
      Logger.info("IntegrationLog cleanup: removed #{cleaned} entries older than 30 days")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Private Functions
  # ---------------------------------------------------------------------------

  defp generate_id do
    "ilog_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp truncate_body(nil), do: nil
  defp truncate_body(body) when is_binary(body) do
    if String.length(body) > @max_body_size do
      String.slice(body, 0, @max_body_size) <> "...[truncated]"
    else
      body
    end
  end
  defp truncate_body(body) when is_map(body) or is_list(body) do
    case Jason.encode(body) do
      {:ok, json} -> truncate_body(json)
      _ -> inspect(body) |> truncate_body()
    end
  end
  defp truncate_body(body), do: inspect(body) |> truncate_body()

  defp matches_filter?(_entry, _field, nil), do: true
  defp matches_filter?(entry, field, value) do
    Map.get(entry, field) == value
  end

  defp matches_date_range?(_entry, nil, nil), do: true
  defp matches_date_range?(entry, from_dt, nil) do
    DateTime.compare(entry.inserted_at, from_dt) in [:gt, :eq]
  end
  defp matches_date_range?(entry, nil, to_dt) do
    DateTime.compare(entry.inserted_at, to_dt) in [:lt, :eq]
  end
  defp matches_date_range?(entry, from_dt, to_dt) do
    DateTime.compare(entry.inserted_at, from_dt) in [:gt, :eq] and
    DateTime.compare(entry.inserted_at, to_dt) in [:lt, :eq]
  end

  defp cleanup_old_entries do
    cutoff = DateTime.add(DateTime.utc_now(), -@retention_seconds, :second)

    old_entries = :ets.tab2list(@ets_table)
    |> Enum.filter(fn {_id, entry} ->
      DateTime.compare(entry.inserted_at, cutoff) == :lt
    end)
    |> Enum.map(fn {id, _entry} -> id end)

    Enum.each(old_entries, fn id -> :ets.delete(@ets_table, id) end)
    length(old_entries)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason) when is_atom(reason), do: to_string(reason)
  defp format_error(%{message: msg}), do: msg
  defp format_error(reason), do: inspect(reason)
end
