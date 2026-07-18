defmodule TamanduaServer.Detection.Engine do
  @moduledoc """
  Detection engine facade that routes events to sharded workers.

  This module preserves the same public API that existed when the engine was a
  single GenServer. Internally, it hashes `agent_id` to select one of N
  `EngineWorker` shards managed by `EngineSupervisor`. This gives 16x
  throughput improvement with zero contention on hot paths.

  **Key design decisions:**

  * `analyze_event/1` and `analyze_batch/1` route to the correct shard via
    `:erlang.phash2(agent_id, num_shards)`. Events without an `agent_id`
    are assigned to shard 0.

  * `reload_rules/0` and `reload_sigma_rules/0` write directly to the shared
    ETS tables (:detection_sigma_rules, :detection_ioc_rules). All workers
    read from ETS so rule updates are instantaneous with no message passing.

  * `get_stats/0` aggregates counters from the :detection_stats ETS table
    across all shards.

  * `handle_critical_event/2` casts to the correct shard for non-blocking
    critical event handling.

  * `status/0` reads rule counts from ETS and recent alert data from the DB.

  All existing callers (Ingestor, AgentWorker, controllers, MCP server, etc.)
  continue to call these functions unchanged.
  """

  require Logger

  alias TamanduaServer.Detection.{
    EngineSupervisor,
    EngineWorker,
    IOCSnapshotProvider,
    RuleLoader,
    YaraScanner
  }

  alias TamanduaServer.Detection.Rules.Falco

  @num_shards 16
  @default_max_async_queue 5_000
  @default_drop_log_interval_ms 10_000
  @drop_log_table :detection_async_drop_log
  @low_priorities MapSet.new(["debug", "info", "informational", "low"])

  # ── Public API (backward-compatible) ───────────────────────────────

  @doc """
  No-op start_link kept for backward compatibility with any code that
  attempts to start the engine directly. The actual processes are started
  by EngineSupervisor.
  """
  def start_link(_opts \\ []) do
    # EngineSupervisor synchronously reconciles the selected provider before it
    # starts any shard or this facade.  Requiring the published generation here
    # preserves that ordering without issuing a second authority transaction at
    # boot.
    with :ok <- ensure_ioc_snapshot_published() do
      # Register ourselves so Process.whereis(TamanduaServer.Detection.Engine)
      # still works for health checks.
      case Agent.start_link(fn -> :running end, name: __MODULE__) do
        {:ok, pid} -> {:ok, pid}
        {:error, {:already_started, pid}} -> {:ok, pid}
      end
    else
      {:error, reason} = error ->
        Logger.error("[Engine] IOC runtime preflight failed: #{inspect(reason)}")
        error
    end
  end

  defp ensure_ioc_snapshot_published do
    if RuleLoader.published_ioc_epoch() >= 0,
      do: :ok,
      else: {:error, :ioc_snapshot_unavailable}
  end

  @doc """
  Analyze a telemetry event and return detection results.
  Routes to the correct shard based on agent_id.
  """
  @spec analyze_event(map()) :: {:ok, map()} | {:error, term()}
  def analyze_event(event) do
    shard = shard_for_event(event)
    EngineWorker.analyze_event(shard, event)
  rescue
    e ->
      Logger.error("[Engine] analyze_event routing failed: #{Exception.message(e)}")
      {:error, :engine_unavailable}
  catch
    :exit, reason ->
      Logger.error("[Engine] analyze_event shard unavailable: #{inspect(reason)}")
      {:error, :shard_unavailable}
  end

  @doc """
  Analyze a batch of events.
  Groups events by shard and dispatches each sub-batch to the correct worker.
  """
  @spec analyze_batch([map()]) :: {:ok, [map()]} | {:error, term()}
  def analyze_batch(events) do
    # Group events by their target shard
    grouped = Enum.group_by(events, &shard_for_event/1)

    # Process each shard's batch and collect results in original order
    results =
      grouped
      |> Enum.flat_map(fn {shard, shard_events} ->
        case EngineWorker.analyze_batch(shard, shard_events) do
          {:ok, shard_results} ->
            shard_results

          {:error, _} ->
            Enum.map(shard_events, fn e -> %{event_id: e[:event_id], error: :shard_error} end)
        end
      end)

    {:ok, results}
  rescue
    e ->
      Logger.error("[Engine] analyze_batch failed: #{Exception.message(e)}")
      {:error, :engine_unavailable}
  end

  @doc """
  Analyze a telemetry event asynchronously (fire-and-forget).
  The worker handles all detection, alert creation, and response internally.
  Use this for extreme-scale ingestion where attaching analysis results to
  the event record is not required.
  """
  @spec analyze_event_async(map()) :: :ok
  def analyze_event_async(event) do
    shard = shard_for_event(event)

    if shed_async_event?(shard, event) do
      emit_async_drop(shard)
      :ok
    else
      EngineWorker.analyze_event_async(shard, event)
    end
  end

  @doc """
  Return per-shard async worker mailbox depth.

  This is intentionally read-only and uses `Process.info/2` directly so
  ingestion hot paths never need a GenServer call to observe backpressure.
  """
  @spec queue_stats() :: [map()]
  def queue_stats do
    for shard <- 0..(@num_shards - 1) do
      case worker_pid(shard) do
        nil ->
          %{shard: shard, pid: nil, running: false, message_queue_len: nil}

        pid ->
          queue_len =
            case Process.info(pid, :message_queue_len) do
              {:message_queue_len, value} -> value
              nil -> nil
            end

          %{shard: shard, pid: pid, running: Process.alive?(pid), message_queue_len: queue_len}
      end
    end
  end

  @doc """
  Handle critical event that needs immediate response.
  Routes to the correct shard as a cast (non-blocking).
  """
  @spec handle_critical_event(String.t(), map()) :: :ok
  def handle_critical_event(agent_id, event) do
    shard = agent_id_to_shard(agent_id)
    EngineWorker.handle_critical_event(shard, agent_id, event)
  end

  @doc """
  Submit a binary for ML analysis.
  Routes to shard based on agent_id in the sample.
  """
  @spec analyze_binary(map()) :: {:ok, map()} | {:error, term()}
  def analyze_binary(sample) do
    agent_id = sample[:agent_id] || sample["agent_id"]
    shard = agent_id_to_shard(agent_id)
    EngineWorker.analyze_binary(shard, sample)
  rescue
    e ->
      Logger.error("[Engine] analyze_binary failed: #{Exception.message(e)}")
      {:error, :engine_unavailable}
  catch
    :exit, reason ->
      Logger.error("[Engine] analyze_binary shard unavailable: #{inspect(reason)}")
      {:error, :shard_unavailable}
  end

  @doc """
  Reload detection rules into shared ETS tables using atomic double-buffering.
  All workers see the new rules immediately (no message passing needed).

  This uses the RuleLoader module which implements double-buffering to
  eliminate the race condition where workers could see an empty rule set
  during reloads.
  """
  @spec reload_rules() :: :ok
  def reload_rules do
    load_rules_into_ets()
    Logger.info("[Engine] Detection rules reloaded (visible to all #{@num_shards} shards)")
    :ok
  end

  @doc """
  Reload only Sigma rules atomically. Called by cluster state sync.

  Uses double-buffering to ensure workers never see an empty rule set.
  """
  @spec reload_sigma_rules() :: :ok
  def reload_sigma_rules do
    sigma_rules = load_sigma_rules_from_db()
    RuleLoader.reload_sigma_rules_atomic(sigma_rules)
    :ok
  rescue
    e ->
      Logger.error("[Engine] Failed to reload Sigma rules: #{Exception.message(e)}")
      :ok
  end

  @doc """
  Reload only IOCs into the shared ETS table atomically.

  Called after IOCs are added/removed/updated via the API or feed sync
  so the detection engine workers immediately see the latest indicators.

  Uses double-buffering to ensure workers never see an empty IOC set.
  """
  @spec reload_iocs() :: {:ok, non_neg_integer()} | {:error, term()}
  def reload_iocs do
    result =
      if Process.whereis(TamanduaServer.Detection.IOCReconciler) do
        TamanduaServer.Detection.IOCReconciler.reconcile_now()
      else
        IOCSnapshotProvider.reconcile()
      end

    case result do
      {:ok, %{count: count}} -> {:ok, count}
      {:ok, %{stale: true}} -> {:ok, RuleLoader.get_iocs() |> length()}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected_reconcile_result, other}}
    end
  rescue
    e ->
      Logger.error("[Engine] Failed to reload IOCs: #{Exception.message(e)}")
      {:error, e}
  catch
    :exit, reason ->
      Logger.error("[Engine] IOC reload exited: #{inspect(reason)}")
      {:error, {:reload_exit, reason}}
  end

  @doc """
  Get detection statistics aggregated across all shards.
  """
  @spec get_stats() :: map()
  def get_stats do
    EngineSupervisor.aggregate_stats()
  rescue
    _ ->
      %{
        events_analyzed: 0,
        detections: 0,
        ml_predictions: 0,
        alerts_created: 0,
        alerts_suppressed: 0,
        alerts_severity_reduced: 0,
        alerts_health_suppressed: 0,
        alerts_health_adjusted: 0,
        yara_scans: 0
      }
  end

  @doc """
  Get engine status including running state, loaded rules, and detection metrics.
  """
  @spec status() :: map()
  def status do
    yara_rule_count = get_yara_rule_count()
    yara_available = YaraScanner.available?()
    falco_rule_count = get_falco_rule_count()

    sigma_count =
      try do
        :ets.info(:detection_sigma_rules, :size) || 0
      rescue
        _ -> 0
      end

    %{
      running: true,
      architecture: :sharded,
      ioc_snapshot: ioc_reconciler_status(),
      num_shards: @num_shards,
      rules_loaded: %{
        sigma: sigma_count,
        falco: falco_rule_count,
        yara: yara_rule_count
      },
      yara_scanner: %{
        available: yara_available,
        rule_count: yara_rule_count,
        cache_stats: safe_yara_cache_stats()
      },
      stats: get_stats(),
      last_detection: get_last_detection_time(),
      detections_today: get_detection_count_today()
    }
  end

  @doc """
  Load rules from the database into shared ETS tables.
  Called during EngineSupervisor init and by reload_rules/0.
  """
  @spec load_rules_into_ets(keyword()) :: :ok
  def load_rules_into_ets(opts \\ []) do
    # Load Sigma rules
    sigma_rules = load_sigma_rules_from_db()
    # Clear and reload (atomic from readers' perspective since ETS insert
    # overwrites existing keys and new keys become visible immediately)
    :ets.delete_all_objects(:detection_sigma_rules)

    for {id, rule} <- sigma_rules do
      :ets.insert(:detection_sigma_rules, {id, rule})
    end

    safe_reload_ruleloader(:sigma, sigma_rules)

    # Load Falco rules
    falco_rules = load_falco_rules()
    # Note: Falco rules are currently loaded for reporting/status.
    # Full runtime matching would require additional integration in EngineWorker.
    # For now, they're available for inspection and conversion to Sigma format.

    # IOC loading is independently epoch-fenced. Never republish a direct DB
    # query here because an older query could otherwise overwrite a newer
    # snapshot completed by the reconciler.
    ioc_count =
      if Keyword.get(opts, :reconcile_iocs, true) do
        case IOCSnapshotProvider.reconcile() do
          {:ok, %{count: count}} ->
            count

          {:ok, %{stale: true}} ->
            active_rule_count(:ioc)

          {:error, reason} ->
            Logger.error(
              "[Engine] Keeping previous IOC snapshot after database load failure: #{inspect(reason)}"
            )

            active_rule_count(:ioc)
        end
      else
        active_rule_count(:ioc)
      end

    sigma_count = length(sigma_rules)
    falco_count = length(falco_rules)
    yara_rule_count = get_yara_rule_count()

    if YaraScanner.available?() do
      Logger.info(
        "[Engine] Loaded #{sigma_count} Sigma rules, #{falco_count} Falco rules, #{ioc_count} IOCs, #{yara_rule_count} YARA rule files into ETS"
      )
    else
      Logger.warning(
        "[Engine] Loaded #{sigma_count} Sigma rules, #{falco_count} Falco rules, #{ioc_count} IOCs into ETS (YARA scanner not available)"
      )
    end

    :ok
  rescue
    e ->
      Logger.error("[Engine] Failed to load rules into ETS: #{Exception.message(e)}")
      :ok
  end

  defp safe_reload_ruleloader(rule_type, rules) do
    RuleLoader.init_tables()

    case rule_type do
      :sigma -> RuleLoader.reload_sigma_rules_atomic(rules)
      :ioc -> {:error, :authority_epoch_required}
      :yara -> RuleLoader.reload_yara_rules_atomic(rules)
    end
  rescue
    e ->
      Logger.warning(
        "[Engine] RuleLoader reload failed for #{rule_type}: #{Exception.message(e)}"
      )

      :ok
  end

  defp ioc_reconciler_status do
    if Process.whereis(TamanduaServer.Detection.IOCReconciler) do
      TamanduaServer.Detection.IOCReconciler.status()
    else
      %{
        healthy: false,
        pending: true,
        published_epoch: RuleLoader.published_ioc_epoch(),
        last_error: :reconciler_not_running
      }
    end
  catch
    :exit, reason ->
      %{healthy: false, pending: true, last_error: {:reconciler_unavailable, reason}}
  end

  defp active_rule_count(rule_type) do
    if rule_type == :ioc do
      RuleLoader.with_ioc_snapshot(fn table -> :ets.info(table, :size) || 0 end)
    else
      rule_type
      |> RuleLoader.get_active_table()
      |> :ets.info(:size)
      |> case do
        count when is_integer(count) -> count
        _ -> 0
      end
    end
  rescue
    ArgumentError -> 0
  end

  # ── Sharding ───────────────────────────────────────────────────────

  defp shard_for_event(event) do
    agent_id = event[:agent_id] || event["agent_id"]
    agent_id_to_shard(agent_id)
  end

  defp agent_id_to_shard(nil), do: 0
  defp agent_id_to_shard(agent_id), do: :erlang.phash2(agent_id, @num_shards)

  defp shed_async_event?(shard, event) do
    case worker_queue_len(shard) do
      nil ->
        false

      queue_len ->
        queue_len >= max_async_queue() and low_priority_event?(event)
    end
  end

  defp worker_queue_len(shard) do
    with pid when is_pid(pid) <- worker_pid(shard),
         {:message_queue_len, queue_len} <- Process.info(pid, :message_queue_len) do
      queue_len
    else
      _ -> nil
    end
  end

  defp worker_pid(shard) do
    case Registry.lookup(TamanduaServer.Detection.ShardRegistry, shard) do
      [{pid, _}] -> pid
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp low_priority_event?(event) do
    priority =
      event[:priority] || event["priority"] ||
        event[:severity] || event["severity"] ||
        get_in(event, [:payload, :priority]) || get_in(event, ["payload", "priority"]) ||
        get_in(event, [:payload, :severity]) || get_in(event, ["payload", "severity"])

    cond do
      is_nil(priority) ->
        true

      is_atom(priority) ->
        MapSet.member?(@low_priorities, priority |> Atom.to_string() |> String.downcase())

      is_binary(priority) ->
        MapSet.member?(@low_priorities, String.downcase(priority))

      is_number(priority) ->
        priority <= 1

      true ->
        false
    end
  end

  defp max_async_queue do
    :tamandua_server
    |> Application.get_env(:detection_engine, [])
    |> Keyword.get(:max_async_queue, @default_max_async_queue)
  end

  defp drop_log_interval_ms do
    :tamandua_server
    |> Application.get_env(:detection_engine, [])
    |> Keyword.get(:async_drop_log_interval_ms, @default_drop_log_interval_ms)
  end

  defp emit_async_drop(shard) do
    :telemetry.execute(
      [:tamandua, :detection, :async_dropped],
      %{count: 1},
      %{shard: shard}
    )

    maybe_log_async_drop(shard)
  end

  defp maybe_log_async_drop(shard) do
    table = ensure_drop_log_table()
    now = System.monotonic_time(:millisecond)
    interval = drop_log_interval_ms()

    last_logged_at =
      case :ets.lookup(table, shard) do
        [{^shard, timestamp}] -> timestamp
        _ -> nil
      end

    if is_nil(last_logged_at) or now - last_logged_at >= interval do
      :ets.insert(table, {shard, now})

      Logger.warning(
        "[Engine] Dropping low-priority async detection events for shard #{shard}: " <>
          "worker mailbox exceeded #{max_async_queue()} messages"
      )
    end
  end

  defp ensure_drop_log_table do
    case :ets.whereis(@drop_log_table) do
      :undefined ->
        try do
          :ets.new(@drop_log_table, [:named_table, :public, read_concurrency: true])
        rescue
          ArgumentError -> @drop_log_table
        end

      _ ->
        @drop_log_table
    end
  end

  # ── Rule loading from database ─────────────────────────────────────

  defp load_sigma_rules_from_db do
    db_rules =
      case TamanduaServer.Repo.all(TamanduaServer.Detection.SigmaRule) do
        rules when is_list(rules) ->
          enabled = Enum.filter(rules, & &1.enabled)

          Logger.info(
            "[Engine] Loaded #{length(enabled)} enabled Sigma rules (#{length(rules)} total)"
          )

          enabled

        other ->
          Logger.error("[Engine] Unexpected result loading Sigma rules: #{inspect(other)}")
          []
      end

    file_rules = load_sigma_rules_from_priv()
    db_fingerprints = MapSet.new(Enum.map(db_rules, &sigma_rule_fingerprint/1))

    merged_file_rules =
      Enum.reject(file_rules, fn rule ->
        MapSet.member?(db_fingerprints, sigma_rule_fingerprint(rule))
      end)

    if length(merged_file_rules) > 0 do
      Logger.info(
        "[Engine] Loaded #{length(merged_file_rules)} additional Sigma rules from priv/sigma_rules"
      )
    end

    db_rules
    |> Kernel.++(merged_file_rules)
    |> Enum.with_index(fn rule, idx -> {idx, rule} end)
  rescue
    e ->
      Logger.error("[Engine] Failed to load Sigma rules from database: #{Exception.message(e)}")
      []
  end

  defp load_sigma_rules_from_priv do
    sigma_root = Application.app_dir(:tamandua_server, "priv/sigma_rules")

    sigma_root
    |> Path.join("**/*.{yml,yaml}")
    |> Path.wildcard()
    |> Enum.flat_map(&load_sigma_rule_file/1)
  rescue
    e ->
      Logger.warning(
        "[Engine] Failed to load Sigma rules from priv/sigma_rules: #{Exception.message(e)}"
      )

      []
  end

  defp load_sigma_rule_file(path) do
    with {:ok, source} <- File.read(path),
         {:ok, docs} <- read_sigma_yaml_documents(source) do
      docs
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&is_map/1)
      |> Enum.map(&normalize_file_sigma_rule(&1, source, path))
    else
      {:error, reason} ->
        Logger.warning("[Engine] Skipping Sigma file #{path}: #{inspect(reason)}")
        []
    end
  end

  defp read_sigma_yaml_documents(source) do
    if function_exported?(YamlElixir, :read_all_from_string, 1) do
      case YamlElixir.read_all_from_string(source) do
        {:ok, docs} when is_list(docs) -> {:ok, docs}
        docs when is_list(docs) -> {:ok, docs}
        {:ok, doc} when is_map(doc) -> {:ok, [doc]}
        {:error, reason} -> {:error, reason}
        other -> {:error, {:unexpected_yaml_result, other}}
      end
    else
      source
      |> String.split(~r/^---\s*$/m, trim: true)
      |> Enum.reduce_while({:ok, []}, fn doc, {:ok, acc} ->
        case YamlElixir.read_from_string(doc) do
          {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> case do
        {:ok, docs} -> {:ok, Enum.reverse(docs)}
        error -> error
      end
    end
  end

  defp normalize_file_sigma_rule(rule, source, path) do
    logsource = Map.get(rule, "logsource") || %{}
    tags = Map.get(rule, "tags") || []

    %{
      "name" => Map.get(rule, "title") || Path.basename(path),
      "title" => Map.get(rule, "title") || Path.basename(path),
      "description" => Map.get(rule, "description"),
      "level" => Map.get(rule, "level") || "medium",
      "status" => Map.get(rule, "status") || "experimental",
      "source" => source,
      "detection" => Map.get(rule, "detection") || %{},
      "logsource" => logsource,
      "logsource_category" => Map.get(logsource, "category"),
      "logsource_product" => Map.get(logsource, "product"),
      "logsource_service" => Map.get(logsource, "service"),
      "tags" => tags,
      "mitre_tactics" => sigma_tags_to_tactics(tags),
      "mitre_techniques" => sigma_tags_to_techniques(tags),
      "references" => Map.get(rule, "references") || [],
      "file_path" => path,
      "enabled" => true
    }
  end

  defp sigma_rule_fingerprint(rule) do
    title =
      Map.get(rule, :title) || Map.get(rule, "title") || Map.get(rule, :name) ||
        Map.get(rule, "name")

    source = Map.get(rule, :source) || Map.get(rule, "source") || ""

    {to_string(title || ""),
     :crypto.hash(:sha256, to_string(source)) |> Base.encode16(case: :lower)}
  end

  defp sigma_tags_to_tactics(tags) do
    tags
    |> List.wrap()
    |> Enum.map(&to_string/1)
    |> Enum.filter(
      &(String.starts_with?(&1, "attack.") and not String.starts_with?(&1, "attack.t"))
    )
    |> Enum.uniq()
  end

  defp sigma_tags_to_techniques(tags) do
    tags
    |> List.wrap()
    |> Enum.map(&to_string/1)
    |> Enum.filter(&String.starts_with?(&1, "attack.t"))
    |> Enum.uniq()
  end

  # ── Status helpers ─────────────────────────────────────────────────

  defp get_yara_rule_count do
    length(YaraScanner.get_rule_files())
  rescue
    _ -> 0
  end

  defp get_falco_rule_count do
    length(load_falco_rules())
  rescue
    _ -> 0
  end

  @doc """
  Load Falco rules from priv/falco_rules directory.
  Rules are parsed and converted to internal format for evaluation.
  """
  def load_falco_rules do
    falco_dir = Application.app_dir(:tamandua_server, "priv/falco_rules")

    if File.dir?(falco_dir) do
      falco_dir
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, [".yaml", ".yml"]))
      |> Enum.flat_map(fn filename ->
        path = Path.join(falco_dir, filename)

        case Falco.parse_file(path) do
          {:ok, rules} ->
            Logger.info("[Engine] Loaded #{length(rules)} Falco rules from #{filename}")
            rules

          {:error, reason} ->
            Logger.warning(
              "[Engine] Failed to load Falco rules from #{filename}: #{inspect(reason)}"
            )

            []
        end
      end)
    else
      Logger.debug("[Engine] No Falco rules directory found at #{falco_dir}")
      []
    end
  rescue
    e ->
      Logger.error("[Engine] Failed to load Falco rules: #{Exception.message(e)}")
      []
  end

  defp safe_yara_cache_stats do
    YaraScanner.cache_stats()
  rescue
    _ -> %{}
  end

  defp get_last_detection_time do
    import Ecto.Query

    case TamanduaServer.Repo.one(
           from(a in TamanduaServer.Alerts.Alert,
             order_by: [desc: a.inserted_at],
             limit: 1,
             select: a.inserted_at
           )
         ) do
      nil -> nil
      datetime -> datetime
    end
  rescue
    _ -> nil
  end

  defp get_detection_count_today do
    import Ecto.Query

    today = Date.utc_today()

    TamanduaServer.Repo.aggregate(
      from(a in TamanduaServer.Alerts.Alert,
        where: fragment("?::date", a.inserted_at) == ^today
      ),
      :count,
      :id
    )
  rescue
    _ -> 0
  end
end
