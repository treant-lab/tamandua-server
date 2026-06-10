defmodule TamanduaServer.Workers.CacheWarmingWorker do
  @moduledoc """
  Oban worker for scheduled background cache warming.

  Periodically refreshes cache data to ensure hot data is always available.
  Supports priority-based warming and failure retry logic.

  ## Examples

      # Schedule immediate warming
      %{cache_type: :yara_rules}
      |> CacheWarmingWorker.new()
      |> Oban.insert()

      # Schedule delayed warming
      %{cache_type: :threat_intel}
      |> CacheWarmingWorker.new(schedule_in: 3600)
      |> Oban.insert()
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    priority: 3

  require Logger

  alias TamanduaServer.Cache.Warmer

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"cache_type" => cache_type}}) do
    # Resolve the untrusted (Oban arg) cache type against atoms that already
    # exist as compile-time literals in Warmer's @warming_configs. Refuse
    # unknown values instead of growing the global atom table or warming the
    # wrong cache.
    case safe_cache_type(cache_type) do
      {:ok, cache_type_atom} ->
        Logger.info("[CacheWarmingWorker] Starting warming for #{cache_type}")

        case Warmer.warm_cache(cache_type_atom) do
          {:ok, stats} ->
            Logger.info("[CacheWarmingWorker] Warmed #{cache_type}: #{inspect(stats)}")
            :ok

          {:error, reason} ->
            Logger.error("[CacheWarmingWorker] Failed to warm #{cache_type}: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, :invalid_cache_type} = error ->
        Logger.error("[CacheWarmingWorker] Unknown cache type: #{inspect(cache_type)}")
        error
    end
  end

  def perform(%Oban.Job{args: %{"operation" => "warm_all"}}) do
    Logger.info("[CacheWarmingWorker] Starting full cache warming")

    case Warmer.warm_all() do
      {:ok, stats} ->
        Logger.info("[CacheWarmingWorker] Full warming completed: #{inspect(stats)}")
        :ok

      {:error, reason} ->
        Logger.error("[CacheWarmingWorker] Full warming failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def perform(%Oban.Job{args: %{"operation" => "warm_hot_data", "tenant_id" => tenant_id}}) do
    Logger.info("[CacheWarmingWorker] Warming hot data for tenant #{tenant_id}")

    Warmer.warm_hot_alerts(tenant_id)
    Warmer.warm_hot_agents(tenant_id)

    :ok
  end

  # Resolve a string cache type to an existing atom without growing the global
  # atom table. Valid cache atoms (:detection_config, :yara_rules, :sigma_rules,
  # :iocs, :threat_intel, :agent_metadata) already exist as compile-time
  # literals in Warmer's @warming_configs.
  defp safe_cache_type(cache_type) when is_atom(cache_type), do: {:ok, cache_type}

  defp safe_cache_type(cache_type) when is_binary(cache_type) do
    {:ok, String.to_existing_atom(cache_type)}
  rescue
    ArgumentError -> {:error, :invalid_cache_type}
  end

  defp safe_cache_type(_cache_type), do: {:error, :invalid_cache_type}
end
