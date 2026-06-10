defmodule TamanduaServer.Billing.UsageMeter do
  @moduledoc """
  Usage metering GenServer with ETS-backed counters.

  Tracks:
  - API calls per organization
  - Model scans per organization
  - Storage usage per organization

  Usage is accumulated in ETS for fast writes, then periodically
  flushed to the database and reported to Stripe.

  ## Architecture

  - ETS table for fast, concurrent counter updates
  - Periodic flush to PostgreSQL (every 5 minutes)
  - Stripe usage reporting at end of billing period

  ## Usage

      UsageMeter.record_api_call(org_id)
      UsageMeter.record_scan(org_id)
      UsageMeter.get_usage(org_id, :api_calls)

  ## Configuration

  The flush interval can be configured in config:

      config :tamandua_server, TamanduaServer.Billing.UsageMeter,
        flush_interval_ms: 300_000
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  @table_name :usage_meter
  @default_flush_interval :timer.minutes(5)

  # ===========================================================================
  # Client API
  # ===========================================================================

  @doc """
  Starts the UsageMeter GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Records an API call for an organization.

  ## Examples

      iex> UsageMeter.record_api_call("org-123")
      :ok

      iex> UsageMeter.record_api_call("org-123", 5)
      :ok
  """
  def record_api_call(org_id, count \\ 1) when is_binary(org_id) and is_integer(count) and count > 0 do
    increment_counter(org_id, :api_calls, count)
  end

  @doc """
  Records a model scan for an organization.

  ## Examples

      iex> UsageMeter.record_scan("org-123")
      :ok

      iex> UsageMeter.record_scan("org-123", 3)
      :ok
  """
  def record_scan(org_id, count \\ 1) when is_binary(org_id) and is_integer(count) and count > 0 do
    increment_counter(org_id, :model_scans, count)
  end

  @doc """
  Records storage change (delta in bytes, can be negative).

  ## Examples

      iex> UsageMeter.record_storage("org-123", 1024)
      :ok

      iex> UsageMeter.record_storage("org-123", -512)
      :ok
  """
  def record_storage(org_id, bytes_delta) when is_binary(org_id) and is_integer(bytes_delta) do
    increment_counter(org_id, :storage_bytes, bytes_delta)
  end

  @doc """
  Gets current usage for an organization and specific metric.

  ## Examples

      iex> UsageMeter.get_usage("org-123", :api_calls)
      42
  """
  def get_usage(org_id, metric) when metric in [:api_calls, :model_scans, :storage_bytes] do
    key = {org_id, metric}

    case :ets.lookup(@table_name, key) do
      [{^key, count}] -> count
      [] -> 0
    end
  rescue
    ArgumentError ->
      # Table doesn't exist yet
      0
  end

  @doc """
  Gets all usage metrics for an organization.

  ## Examples

      iex> UsageMeter.get_all_usage("org-123")
      %{api_calls: 42, model_scans: 5, storage_bytes: 1024}
  """
  def get_all_usage(org_id) when is_binary(org_id) do
    %{
      api_calls: get_usage(org_id, :api_calls),
      model_scans: get_usage(org_id, :model_scans),
      storage_bytes: get_usage(org_id, :storage_bytes)
    }
  end

  @doc """
  Manually triggers a flush of all counters to the database.

  Returns `{:ok, count}` with the number of records written.
  """
  def flush_to_db do
    GenServer.call(__MODULE__, :flush_to_db)
  end

  @doc """
  Resets all counters for an organization (primarily for testing).
  """
  def reset(org_id) when is_binary(org_id) do
    GenServer.call(__MODULE__, {:reset, org_id})
  end

  @doc """
  Gets the last flush timestamp.
  """
  def last_flush do
    GenServer.call(__MODULE__, :last_flush)
  end

  # ===========================================================================
  # Server Callbacks
  # ===========================================================================

  @impl true
  def init(opts) do
    # Create ETS table for counters
    # Using write_concurrency for high-throughput counter updates
    :ets.new(@table_name, [
      :named_table,
      :public,
      :set,
      {:write_concurrency, true},
      {:read_concurrency, true}
    ])

    # Get flush interval from options or config
    flush_interval =
      Keyword.get(opts, :flush_interval_ms) ||
        Application.get_env(:tamandua_server, __MODULE__)[:flush_interval_ms] ||
        @default_flush_interval

    # Schedule periodic flush
    schedule_flush(flush_interval)

    {:ok, %{last_flush: DateTime.utc_now(), flush_interval: flush_interval}}
  end

  @impl true
  def handle_call(:flush_to_db, _from, state) do
    result = do_flush_to_db()
    {:reply, result, %{state | last_flush: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:reset, org_id}, _from, state) do
    :ets.match_delete(@table_name, {{org_id, :_}, :_})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:last_flush, _from, state) do
    {:reply, state.last_flush, state}
  end

  @impl true
  def handle_info(:flush, state) do
    do_flush_to_db()
    schedule_flush(state.flush_interval)
    {:noreply, %{state | last_flush: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  defp increment_counter(org_id, metric, count) do
    key = {org_id, metric}

    try do
      :ets.update_counter(@table_name, key, {2, count}, {key, 0})
      :ok
    rescue
      ArgumentError ->
        # Table might not exist yet (startup race)
        Logger.warning("UsageMeter: ETS table not ready, dropping metric #{metric} for #{org_id}")
        :ok
    end
  end

  defp schedule_flush(interval) do
    Process.send_after(self(), :flush, interval)
  end

  defp do_flush_to_db do
    now = DateTime.utc_now()
    period_start = now |> DateTime.add(-300, :second) |> DateTime.truncate(:second)

    # Collect all counters by org_id
    counters =
      try do
        :ets.tab2list(@table_name)
      rescue
        ArgumentError -> []
      end

    if counters == [] do
      {:ok, 0}
    else
      by_org =
        counters
        |> Enum.group_by(fn {{org_id, _metric}, _count} -> org_id end)
        |> Enum.map(fn {org_id, entries} ->
          usage =
            Enum.reduce(entries, %{api_calls: 0, model_scans: 0, storage_bytes: 0}, fn
              {{_, :api_calls}, count}, acc -> %{acc | api_calls: count}
              {{_, :model_scans}, count}, acc -> %{acc | model_scans: count}
              {{_, :storage_bytes}, count}, acc -> %{acc | storage_bytes: count}
            end)

          {org_id, usage}
        end)

      # Insert usage records
      records =
        Enum.map(by_org, fn {org_id, usage} ->
          %{
            id: Ecto.UUID.generate(),
            organization_id: org_id,
            period_start: period_start,
            period_end: now,
            api_calls: usage.api_calls,
            model_scans: usage.model_scans,
            storage_bytes: usage.storage_bytes,
            reported_to_stripe: false,
            inserted_at: now,
            updated_at: now
          }
        end)

      if length(records) > 0 do
        case Repo.insert_all("usage_records", records, on_conflict: :nothing) do
          {count, _} ->
            Logger.info("UsageMeter: Flushed #{count} usage records to database")

            # Clear counters after successful flush
            :ets.delete_all_objects(@table_name)

            {:ok, count}
        end
      else
        {:ok, 0}
      end
    end
  rescue
    e ->
      Logger.error("UsageMeter: Failed to flush to database: #{inspect(e)}")
      {:error, e}
  end
end
