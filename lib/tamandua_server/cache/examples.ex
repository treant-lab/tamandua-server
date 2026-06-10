defmodule TamanduaServer.Cache.Examples do
  @moduledoc """
  Examples of integrating the caching system into Tamandua contexts.

  These examples demonstrate best practices for:
  - Cache-aside pattern
  - Write-through invalidation
  - Background warming
  - HTTP caching in controllers

  Copy and adapt these patterns to your own modules.
  """

  # Example 1: Alerts Context with Redis Cache
  defmodule AlertsExample do
    @moduledoc """
    Example: Caching alerts with write-through invalidation.
    """

    import Ecto.Query
    alias TamanduaServer.{Repo, Alerts.Alert}
    alias TamanduaServer.Cache.{Strategy, Invalidator}

    @doc """
    Gets an alert by ID with caching.
    """
    def get_alert(id) do
      Strategy.fetch(:alert, id, fn ->
        case Repo.get(Alert, id) do
          nil -> {:error, :not_found}
          alert -> {:ok, alert}
        end
      end)
    end

    @doc """
    Lists recent alerts for a tenant with caching.
    """
    def list_recent_alerts(tenant_id, opts \\ []) do
      limit = Keyword.get(opts, :limit, 50)
      cache_key = "recent_alerts:#{tenant_id}:#{limit}"

      Strategy.fetch(:dashboard_stats, cache_key, fn ->
        alerts =
          Alert
          |> where(tenant_id: ^tenant_id)
          |> order_by([a], desc: a.inserted_at)
          |> limit(^limit)
          |> Repo.all()

        {:ok, alerts}
      end)
    end

    @doc """
    Updates an alert and invalidates cache.
    """
    def update_alert(alert, attrs) do
      alert
      |> Alert.changeset(attrs)
      |> Repo.update()
      |> case do
        {:ok, updated_alert} ->
          # Invalidate single alert cache
          Invalidator.invalidate_alert(updated_alert.id)

          # Invalidate related caches (dashboards, lists)
          Invalidator.invalidate_by_tag(:alert, updated_alert.tenant_id)

          {:ok, updated_alert}

        error ->
          error
      end
    end

    @doc """
    Deletes an alert and invalidates cache.
    """
    def delete_alert(alert) do
      case Repo.delete(alert) do
        {:ok, deleted_alert} ->
          # Invalidate all related caches
          Invalidator.invalidate_alert(deleted_alert.id)
          Invalidator.invalidate_by_tag(:alert, deleted_alert.tenant_id)

          {:ok, deleted_alert}

        error ->
          error
      end
    end

    @doc """
    Bulk updates with batch invalidation.
    """
    def bulk_update_alerts(alert_ids, attrs) do
      # Update in database
      query = from a in Alert, where: a.id in ^alert_ids
      {count, _} = Repo.update_all(query, set: attrs)

      # Batch invalidate
      invalidations = Enum.map(alert_ids, fn id -> {:alert, id} end)
      Invalidator.invalidate_batch(invalidations)

      {:ok, count}
    end
  end

  # Example 2: Detection Rules with ETS Cache
  defmodule DetectionExample do
    @moduledoc """
    Example: Caching detection rules in ETS.
    """

    import Ecto.Query
    alias TamanduaServer.{Repo, Detection.YaraRule}
    alias TamanduaServer.Cache.{ETSCache, Invalidator, Warmer}

    @doc """
    Gets a YARA rule by ID with ETS caching.
    """
    def get_yara_rule(id) do
      ETSCache.fetch(:yara_rules, id, fn ->
        case Repo.get(YaraRule, id) do
          nil -> {:error, :not_found}
          rule -> {:ok, rule}
        end
      end)
    end

    @doc """
    Lists all active YARA rules (cached).
    """
    def list_active_yara_rules do
      # Check ETS cache first
      case ETSCache.get(:yara_rules, :all_active) do
        {:ok, rules} ->
          rules

        :miss ->
          # Fetch from database
          rules =
            YaraRule
            |> where(enabled: true)
            |> Repo.all()

          # Cache for 1 hour
          ETSCache.put(:yara_rules, :all_active, rules)
          rules
      end
    end

    @doc """
    Updates a YARA rule and invalidates ETS cache.
    """
    def update_yara_rule(rule, attrs) do
      rule
      |> YaraRule.changeset(attrs)
      |> Repo.update()
      |> case do
        {:ok, updated_rule} ->
          # Invalidate specific rule
          ETSCache.delete(:yara_rules, updated_rule.id)

          # Invalidate "all active" cache
          ETSCache.delete(:yara_rules, :all_active)

          # Notify detection engine to reload
          Invalidator.invalidate_detection_rule(updated_rule.id)

          {:ok, updated_rule}

        error ->
          error
      end
    end

    @doc """
    Warms YARA rule cache on startup or reload.
    """
    def warm_yara_cache do
      Warmer.warm_cache(:yara_rules)
    end
  end

  # Example 3: Controller with HTTP Caching
  defmodule ControllerExample do
    @moduledoc """
    Example: HTTP caching in Phoenix controllers.
    """

    use Phoenix.Controller
    alias TamanduaServer.Cache.HTTPCache

    @doc """
    Example 1: Automatic ETag support via plug.
    """
    def index_with_plug(conn, _params) do
      # CachePlug automatically:
      # 1. Generates ETag from response
      # 2. Validates If-None-Match header
      # 3. Returns 304 if match

      alerts = list_alerts()
      json(conn, alerts)
    end

    @doc """
    Example 2: Manual ETag handling with custom logic.
    """
    def show_with_manual_etag(conn, %{"id" => id}) do
      alert = get_alert(id)
      etag = HTTPCache.generate_etag(alert)

      case HTTPCache.validate_conditional_request(conn, etag) do
        :not_modified ->
          conn
          |> put_resp_header("etag", etag)
          |> send_resp(304, "")

        :proceed ->
          conn
          |> put_resp_header("etag", etag)
          |> HTTPCache.put_cache_control(:public, max_age: 300)
          |> json(alert)
      end
    end

    @doc """
    Example 3: Last-Modified header for time-based caching.
    """
    def index_with_last_modified(conn, _params) do
      alerts = list_alerts()
      last_modified = HTTPCache.get_last_modified(alerts)

      case HTTPCache.validate_if_modified_since(conn, last_modified) do
        :not_modified ->
          send_resp(conn, 304, "")

        :proceed ->
          conn
          |> put_resp_header("last-modified", HTTPCache.format_http_date(last_modified))
          |> HTTPCache.cache_api_response(max_age: 60)
          |> json(alerts)
      end
    end

    @doc """
    Example 4: Disable caching for sensitive data.
    """
    def sensitive_data(conn, _params) do
      data = get_sensitive_data()

      conn
      |> HTTPCache.disable_cache()
      |> json(data)
    end

    # Stub functions
    defp list_alerts, do: []
    defp get_alert(_id), do: %{}
    defp get_sensitive_data, do: %{}
  end

  # Example 4: Background Cache Warming
  defmodule WarmingExample do
    @moduledoc """
    Example: Background cache warming strategies.
    """

    alias TamanduaServer.Cache.Warmer

    @doc """
    Warms all caches on deployment.
    """
    def warm_on_deploy do
      Warmer.warm_all()
    end

    @doc """
    Warms hot data for a tenant (e.g., after large data import).
    """
    def warm_tenant_data(tenant_id) do
      Warmer.warm_hot_alerts(tenant_id, 100)
      Warmer.warm_hot_agents(tenant_id, 50)
    end

    @doc """
    Schedules periodic warming for threat intel (Oban job).
    """
    def schedule_threat_intel_warming do
      # Every 6 hours
      %{cache_type: :threat_intel}
      |> TamanduaServer.Workers.CacheWarmingWorker.new(schedule_in: :timer.hours(6))
      |> Oban.insert()
    end
  end

  # Example 5: Multi-Tier Caching Strategy
  defmodule MultiTierExample do
    @moduledoc """
    Example: Using multiple cache layers for optimal performance.
    """

    alias TamanduaServer.Cache.{ETSCache, RedisCache}
    alias TamanduaServer.Repo

    @doc """
    Fetches data with multi-tier cache strategy:
    1. Check ETS (local, <1ms)
    2. Check Redis (distributed, <5ms)
    3. Fetch from database (cold, >50ms)
    """
    def get_with_multi_tier(id) do
      # Layer 1: ETS (fastest)
      case ETSCache.get(:ml_predictions, id) do
        {:ok, value} ->
          {:ok, value}

        :miss ->
          # Layer 2: Redis (fast)
          case RedisCache.get("predictions", id) do
            {:ok, value} ->
              # Promote to ETS for even faster future access
              ETSCache.put(:ml_predictions, id, value, ttl: :timer.minutes(5))
              {:ok, value}

            :miss ->
              # Layer 3: Database (slow)
              case fetch_from_database(id) do
                {:ok, value} ->
                  # Populate both caches
                  RedisCache.put("predictions", id, value, ttl: :timer.minutes(15))
                  ETSCache.put(:ml_predictions, id, value, ttl: :timer.minutes(5))
                  {:ok, value}

                error ->
                  error
              end
          end
      end
    end

    defp fetch_from_database(id) do
      # Simulated database fetch
      {:ok, %{id: id, data: "from_db"}}
    end
  end

  # Example 6: Cache Metrics in LiveView
  defmodule LiveViewExample do
    @moduledoc """
    Example: Displaying cache metrics in LiveView dashboard.
    """

    use Phoenix.LiveView
    alias TamanduaServer.Cache.{ETSCache, RedisCache, Invalidator}

    def mount(_params, _session, socket) do
      if connected?(socket) do
        # Update metrics every 5 seconds
        :timer.send_interval(5000, self(), :update_metrics)
      end

      {:ok, assign(socket, metrics: fetch_metrics())}
    end

    def handle_info(:update_metrics, socket) do
      {:noreply, assign(socket, metrics: fetch_metrics())}
    end

    def handle_info(_msg, socket), do: {:noreply, socket}

    defp fetch_metrics do
      %{
        ets: ETSCache.stats_all(),
        redis: RedisCache.stats(),
        invalidator: Invalidator.stats()
      }
    end
  end
end
