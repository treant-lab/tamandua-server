defmodule TamanduaServer.ThreatIntel.RetroactiveScanner do
  @moduledoc """
  When new IOCs arrive from threat intel feeds, automatically scans
  historical telemetry for matches. This catches threats that were
  present before the IOC was known.

  Architecture:
  - Subscribes to PubSub for real-time IOC addition notifications
  - Uses ClickHouse for high-performance historical queries when available
  - Falls back to PostgreSQL queries when ClickHouse is disabled
  - Rate-limits concurrent queries to avoid overloading backends
  - Tracks multiple scan jobs in ETS with progress and cancellation
  - Creates "Retroactive IOC Match" alerts with full evidence timelines
  - Links retroactive alerts to IOC source (feed name, STIX bundle ID)
  - Publishes scan progress and results to PubSub for dashboard visibility
  - Feeds matches into CampaignTracker for campaign correlation

  Scan strategies:
  - Hash scan:    SHA256/MD5/SHA1 against process_events + telemetry_events
  - IP scan:      src/dst IPs against network_flows
  - Domain scan:  domains against dns_queries
  - URL scan:     URLs against telemetry_events payload
  - Email scan:   email addresses against telemetry_events (identity/auth)
  - Pattern scan: regex patterns against process command lines
  """

  use GenServer
  require Logger

  alias TamanduaServer.Telemetry.ClickHouse
  alias TamanduaServer.Alerts

  @ets_jobs :retroactive_scan_jobs
  @ets_stats :retroactive_scan_stats
  @max_concurrent_queries 10
  @default_days_back 30
  @default_max_results 1000
  @batch_size 50
  @query_rate_limit_ms 100
  @pubsub TamanduaServer.PubSub
  @topic "retroactive_scanner"
  @ioc_topic "threat_intel:iocs"

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Scan historical telemetry for a list of newly arrived IOCs.

  Called by ThreatIntelFeeds after a successful feed sync or when PubSub
  notifies of new IOC additions. Groups IOCs by type and dispatches
  appropriate queries.

  Returns `{:ok, scan_id}` immediately; scanning is performed asynchronously.
  """
  @spec scan_new_iocs([map()], keyword()) :: {:ok, String.t()} | {:error, term()}
  def scan_new_iocs(iocs, opts \\ []) when is_list(iocs) do
    GenServer.call(__MODULE__, {:scan_new_iocs, iocs, opts})
  end

  @doc """
  Scan a single IOC across historical data (synchronous).

  ## Options
    - `:days_back` - How many days of history to scan (default: 30)
    - `:max_results` - Maximum results per query (default: 1000)
  """
  @spec scan_single_ioc(String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def scan_single_ioc(type, value, opts \\ []) do
    GenServer.call(__MODULE__, {:scan_single_ioc, type, value, opts}, 60_000)
  end

  @doc """
  Trigger a manual retroactive scan for all IOCs added within the last N days.

  ## Options
    - `:days` - Scan IOCs added within the last N days (default: 7)
    - `:days_back` - How far back to search telemetry (default: 30)
  """
  @spec trigger_manual_scan(keyword()) :: {:ok, String.t()} | {:error, term()}
  def trigger_manual_scan(opts \\ []) do
    GenServer.call(__MODULE__, {:manual_scan, opts})
  end

  @doc """
  Cancel a running scan job.
  """
  @spec cancel_scan(String.t()) :: :ok | {:error, :not_found}
  def cancel_scan(scan_id) do
    GenServer.call(__MODULE__, {:cancel_scan, scan_id})
  end

  @doc """
  Get the status and progress for a specific scan job.
  """
  @spec get_job(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_job(scan_id) do
    case ets_lookup(@ets_jobs, scan_id) do
      nil -> {:error, :not_found}
      job -> {:ok, job}
    end
  end

  @doc """
  List all scan jobs (active, completed, failed).

  ## Options
    - `:status` - Filter by status (:scanning, :complete, :error, :cancelled)
    - `:limit`  - Max jobs to return (default: 50)
  """
  @spec list_jobs(keyword()) :: [map()]
  def list_jobs(opts \\ []) do
    GenServer.call(__MODULE__, {:list_jobs, opts})
  end

  @doc """
  Get aggregate scanner statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get results from a specific scan job.
  """
  @spec get_results(String.t(), keyword()) :: {:ok, [map()]} | {:error, :not_found}
  def get_results(scan_id, opts \\ []) do
    case ets_lookup(@ets_jobs, scan_id) do
      nil -> {:error, :not_found}
      job ->
        results = job.results || []
        limit = Keyword.get(opts, :limit, 100)
        offset = Keyword.get(opts, :offset, 0)
        {:ok, results |> Enum.drop(offset) |> Enum.take(limit)}
    end
  end

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables for job tracking and stats
    :ets.new(@ets_jobs, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_stats, [:named_table, :set, :public, read_concurrency: true])

    # Initialize stats
    :ets.insert(@ets_stats, {:total_scans, 0})
    :ets.insert(@ets_stats, {:total_matches, 0})
    :ets.insert(@ets_stats, {:total_alerts_created, 0})
    :ets.insert(@ets_stats, {:total_iocs_scanned, 0})
    :ets.insert(@ets_stats, {:active_scans, 0})

    # Subscribe to PubSub for new IOC notifications
    subscribe_to_ioc_changes()

    Logger.info("[RetroactiveScanner] Started, subscribed to #{@ioc_topic}")
    {:ok, %{cancellations: MapSet.new()}}
  end

  @impl true
  def handle_call({:scan_new_iocs, iocs, opts}, _from, state) do
    case start_scan_job(iocs, opts, "feed_sync") do
      {:ok, scan_id} -> {:reply, {:ok, scan_id}, state}
      {:error, _} = err -> {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:manual_scan, opts}, _from, state) do
    days = Keyword.get(opts, :days, 7)
    days_back = Keyword.get(opts, :days_back, @default_days_back)

    # Fetch recent IOCs from database
    recent_iocs = try do
      TamanduaServer.Detection.IOCs.list(
        limit: 5000,
        order_by: :inserted_at,
        order_dir: :desc
      )
      |> Enum.filter(fn ioc ->
        age_days = DateTime.diff(DateTime.utc_now(), ioc.inserted_at, :second) / 86400
        age_days <= days
      end)
      |> Enum.map(fn ioc ->
        %{type: ioc.type, value: ioc.value, source: ioc.source, inserted_at: ioc.inserted_at}
      end)
    rescue
      _ -> []
    end

    Logger.info("[RetroactiveScanner] Manual scan: #{length(recent_iocs)} IOCs from last #{days} days")
    case start_scan_job(recent_iocs, [days_back: days_back], "manual") do
      {:ok, scan_id} -> {:reply, {:ok, scan_id}, state}
      {:error, _} = err -> {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:scan_single_ioc, type, value, opts}, _from, state) do
    days_back = Keyword.get(opts, :days_back, @default_days_back)
    max_results = Keyword.get(opts, :max_results, @default_max_results)

    result = do_scan_single_ioc(type, value, days_back, max_results)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:cancel_scan, scan_id}, _from, state) do
    case ets_lookup(@ets_jobs, scan_id) do
      nil ->
        {:reply, {:error, :not_found}, state}
      job when job.status == :scanning ->
        update_job(scan_id, %{status: :cancelled, completed_at: DateTime.utc_now()})
        new_state = %{state | cancellations: MapSet.put(state.cancellations, scan_id)}
        decrement_active_scans()
        broadcast_scan_update(scan_id, :cancelled)
        Logger.info("[RetroactiveScanner] Scan #{scan_id} cancelled")
        {:reply, :ok, new_state}
      _job ->
        {:reply, {:error, :not_running}, state}
    end
  end

  @impl true
  def handle_call({:list_jobs, opts}, _from, state) do
    status_filter = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 50)

    jobs = ets_all_values(@ets_jobs)

    jobs = if status_filter do
      Enum.filter(jobs, fn j -> j.status == status_filter end)
    else
      jobs
    end

    jobs =
      jobs
      |> Enum.sort_by(fn j -> j.started_at end, {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, jobs, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      total_scans: ets_counter(@ets_stats, :total_scans),
      total_matches: ets_counter(@ets_stats, :total_matches),
      total_alerts_created: ets_counter(@ets_stats, :total_alerts_created),
      total_iocs_scanned: ets_counter(@ets_stats, :total_iocs_scanned),
      active_scans: ets_counter(@ets_stats, :active_scans),
      clickhouse_enabled: ClickHouse.enabled?()
    }
    {:reply, stats, state}
  end

  # PubSub notification: new IOCs added
  @impl true
  def handle_info({:new_iocs, iocs}, state) when is_list(iocs) do
    Logger.info("[RetroactiveScanner] PubSub: received #{length(iocs)} new IOCs, queuing retro scan")
    start_scan_job(iocs, [], "pubsub")
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_iocs, ioc}, state) when is_map(ioc) do
    Logger.info("[RetroactiveScanner] PubSub: received 1 new IOC, queuing retro scan")
    start_scan_job([ioc], [], "pubsub")
    {:noreply, state}
  end

  @impl true
  def handle_info({:scan_complete, scan_id, results}, state) do
    match_count = length(results)
    Logger.info("[RetroactiveScanner] Scan #{scan_id} complete: #{match_count} matches")

    update_job(scan_id, %{
      status: :complete,
      completed_at: DateTime.utc_now(),
      results: results,
      matches_found: match_count
    })

    decrement_active_scans()
    increment_stat(:total_matches, match_count)

    # Create alerts for matches
    alerts_created = create_retroactive_alerts(results, scan_id)
    update_job(scan_id, %{alerts_created: alerts_created})
    increment_stat(:total_alerts_created, alerts_created)

    # Notify CampaignTracker of retroactive matches
    notify_campaign_tracker(results)

    broadcast_scan_update(scan_id, :complete)

    # Clean cancellation entry
    new_state = %{state | cancellations: MapSet.delete(state.cancellations, scan_id)}
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:scan_error, scan_id, reason}, state) do
    Logger.error("[RetroactiveScanner] Scan #{scan_id} failed: #{inspect(reason)}")
    update_job(scan_id, %{
      status: :error,
      completed_at: DateTime.utc_now(),
      error: inspect(reason)
    })
    decrement_active_scans()
    broadcast_scan_update(scan_id, :error)
    new_state = %{state | cancellations: MapSet.delete(state.cancellations, scan_id)}
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:scan_progress, scan_id, progress, total, matches}, state) do
    update_job(scan_id, %{
      progress: progress,
      total: total,
      matches_found: matches
    })
    broadcast_scan_update(scan_id, :progress)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: Scan Job Management ─────────────────────────────────────

  defp start_scan_job(iocs, opts, trigger) when is_list(iocs) do
    if length(iocs) == 0 do
      {:error, :no_iocs}
    else
      scan_id = generate_scan_id()
      days_back = Keyword.get(opts, :days_back, @default_days_back)
      parent = self()

      job = %{
        id: scan_id,
        status: :scanning,
        trigger: trigger,
        ioc_count: length(iocs),
        days_back: days_back,
        progress: 0,
        total: length(iocs),
        matches_found: 0,
        alerts_created: 0,
        results: [],
        error: nil,
        started_at: DateTime.utc_now(),
        completed_at: nil
      }

      :ets.insert(@ets_jobs, {scan_id, job})
      increment_stat(:total_scans, 1)
      increment_stat(:active_scans, 1)
      increment_stat(:total_iocs_scanned, length(iocs))

      Logger.info(
        "[RetroactiveScanner] Starting scan #{scan_id}: #{length(iocs)} IOCs, " <>
        "#{days_back} days back, trigger=#{trigger}"
      )

      broadcast_scan_update(scan_id, :started)

      Task.Supervisor.start_child(
        TamanduaServer.TaskSupervisor,
        fn ->
          try do
            results = do_scan_iocs(iocs, scan_id, parent, days_back)
            send(parent, {:scan_complete, scan_id, results})
          rescue
            e ->
              send(parent, {:scan_error, scan_id, Exception.message(e)})
          end
        end
      )

      {:ok, scan_id}
    end
  rescue
    e ->
      Logger.error("[RetroactiveScanner] Failed to start scan: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp do_scan_iocs(iocs, scan_id, parent, days_back) do
    total = length(iocs)

    # Group IOCs by type for efficient batched queries
    grouped = Enum.group_by(iocs, fn ioc ->
      type = ioc[:type] || ioc["type"]
      to_string(type)
    end)

    # Compute time-range partitions for ClickHouse queries
    partitions = build_time_partitions(days_back)

    {all_results, _} =
      grouped
      |> Enum.reduce({[], 0}, fn {type, type_iocs}, {acc_results, processed} ->
        # Process in batches for rate limiting
        {batch_results, new_processed} =
          type_iocs
          |> Enum.chunk_every(@batch_size)
          |> Enum.reduce({[], processed}, fn chunk, {chunk_acc, chunk_processed} ->
            # Check for cancellation
            if scan_cancelled?(scan_id) do
              {chunk_acc, chunk_processed}
            else
              results =
                chunk
                |> Task.async_stream(
                  fn ioc ->
                    value = ioc[:value] || ioc["value"]
                    source = ioc[:source] || ioc["source"]
                    confidence = ioc[:confidence] || ioc["confidence"]

                    # Rate limit queries
                    Process.sleep(@query_rate_limit_ms)

                    case scan_ioc_by_type(type, value, days_back, @default_max_results, partitions) do
                      {:ok, matches} ->
                        # Annotate matches with IOC source info
                        Enum.map(matches, fn m ->
                          Map.merge(m, %{
                            ioc_source: source,
                            ioc_confidence: confidence,
                            scan_id: scan_id
                          })
                        end)
                      {:error, _} ->
                        []
                    end
                  end,
                  max_concurrency: @max_concurrent_queries,
                  timeout: 30_000,
                  on_timeout: :kill_task
                )
                |> Enum.flat_map(fn
                  {:ok, matches} -> matches
                  {:exit, _} -> []
                end)

              new_processed = chunk_processed + length(chunk)
              total_matches = length(chunk_acc) + length(results)

              # Report progress
              send(parent, {:scan_progress, scan_id, new_processed, total, total_matches})

              {chunk_acc ++ results, new_processed}
            end
          end)

        {acc_results ++ batch_results, new_processed}
      end)

    # Report final progress
    send(parent, {:scan_progress, scan_id, total, total, length(all_results)})

    all_results
  end

  defp scan_cancelled?(scan_id) do
    case ets_lookup(@ets_jobs, scan_id) do
      %{status: :cancelled} -> true
      _ -> false
    end
  end

  defp do_scan_single_ioc(type, value, days_back, max_results) do
    partitions = build_time_partitions(days_back)
    scan_ioc_by_type(to_string(type), value, days_back, max_results, partitions)
  end

  defp scan_ioc_by_type(type, value, days_back, max_results, _partitions) do
    if ClickHouse.enabled?() do
      scan_clickhouse(type, value, days_back, max_results)
    else
      scan_postgres(type, value, days_back, max_results)
    end
  end

  # ── ClickHouse Scanning ─────────────────────────────────────────────

  defp scan_clickhouse(type, value, days_back, max_results) do
    case type do
      "ip" -> scan_clickhouse_ip(value, days_back, max_results)
      "domain" -> scan_clickhouse_domain(value, days_back, max_results)
      t when t in ["hash_sha256", "hash_sha1", "hash_md5"] ->
        scan_clickhouse_hash(value, days_back, max_results)
      "url" -> scan_clickhouse_url(value, days_back, max_results)
      "email" -> scan_clickhouse_email(value, days_back, max_results)
      "pattern" -> scan_clickhouse_pattern(value, days_back, max_results)
      "filename" -> scan_clickhouse_filename(value, days_back, max_results)
      _ -> {:ok, []}
    end
  end

  defp scan_clickhouse_ip(ip, days_back, max_results) do
    escaped = escape_clickhouse(ip)
    from_time = format_ch_datetime(days_ago(days_back))

    sql = """
    SELECT
      event_id, agent_id, source_ip, dest_ip, dest_port,
      protocol, process_name, timestamp
    FROM tamandua.network_flows
    WHERE (source_ip = '#{escaped}' OR dest_ip = '#{escaped}')
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "ip",
            ioc_value: ip,
            source_table: "network_flows",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              source_ip: row["source_ip"],
              dest_ip: row["dest_ip"],
              dest_port: row["dest_port"],
              protocol: row["protocol"],
              process_name: row["process_name"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse IP scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp scan_clickhouse_domain(domain, days_back, max_results) do
    escaped = escape_clickhouse(domain)
    from_time = format_ch_datetime(days_ago(days_back))

    # Exact match or subdomain match
    sql = """
    SELECT
      event_id, agent_id, query_name, response_data,
      process_name, process_id, timestamp
    FROM tamandua.dns_queries
    WHERE (query_name = '#{escaped}' OR query_name LIKE '%.#{escaped}')
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "domain",
            ioc_value: domain,
            source_table: "dns_queries",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              query_name: row["query_name"],
              response_data: row["response_data"],
              process_name: row["process_name"],
              process_id: row["process_id"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse domain scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp scan_clickhouse_hash(hash, days_back, max_results) do
    escaped = escape_clickhouse(hash)
    from_time = format_ch_datetime(days_ago(days_back))

    # Search process_events for matching hash
    sql_process = """
    SELECT
      event_id, agent_id, process_name, command_line,
      executable_path, file_hash, user_name, timestamp
    FROM tamandua.process_events
    WHERE file_hash = '#{escaped}'
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    # Also search telemetry_events for file hash
    sql_telemetry = """
    SELECT
      event_id, agent_id, event_type, file_hash, file_path,
      process_name, timestamp
    FROM tamandua.telemetry_events
    WHERE file_hash = '#{escaped}'
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    process_matches = case execute_ch_query(sql_process) do
      {:ok, rows} ->
        Enum.map(rows, fn row ->
          %{
            ioc_type: "hash",
            ioc_value: hash,
            source_table: "process_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              process_name: row["process_name"],
              command_line: row["command_line"],
              executable_path: row["executable_path"],
              user_name: row["user_name"]
            }
          }
        end)
      {:error, _} -> []
    end

    telemetry_matches = case execute_ch_query(sql_telemetry) do
      {:ok, rows} ->
        Enum.map(rows, fn row ->
          %{
            ioc_type: "hash",
            ioc_value: hash,
            source_table: "telemetry_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              event_type: row["event_type"],
              file_path: row["file_path"],
              process_name: row["process_name"]
            }
          }
        end)
      {:error, _} -> []
    end

    {:ok, process_matches ++ telemetry_matches}
  end

  defp scan_clickhouse_url(url, days_back, max_results) do
    escaped = escape_clickhouse(url)
    from_time = format_ch_datetime(days_ago(days_back))

    sql = """
    SELECT
      event_id, agent_id, event_type, process_name,
      payload, timestamp
    FROM tamandua.telemetry_events
    WHERE payload LIKE '%#{escaped}%'
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "url",
            ioc_value: url,
            source_table: "telemetry_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              event_type: row["event_type"],
              process_name: row["process_name"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse URL scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp scan_clickhouse_email(email, days_back, max_results) do
    escaped = escape_clickhouse(email)
    from_time = format_ch_datetime(days_ago(days_back))

    # Search telemetry_events for email in payload (identity/auth events)
    sql = """
    SELECT
      event_id, agent_id, event_type, user_name,
      process_name, payload, timestamp
    FROM tamandua.telemetry_events
    WHERE (user_name = '#{escaped}' OR payload LIKE '%#{escaped}%')
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "email",
            ioc_value: email,
            source_table: "telemetry_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              event_type: row["event_type"],
              user_name: row["user_name"],
              process_name: row["process_name"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse email scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp scan_clickhouse_pattern(pattern, days_back, max_results) do
    escaped = escape_clickhouse(pattern)
    from_time = format_ch_datetime(days_ago(days_back))

    # Search process command lines with LIKE pattern
    sql = """
    SELECT
      event_id, agent_id, process_name, command_line,
      executable_path, user_name, timestamp
    FROM tamandua.process_events
    WHERE command_line LIKE '%#{escaped}%'
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "pattern",
            ioc_value: pattern,
            source_table: "process_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              process_name: row["process_name"],
              command_line: row["command_line"],
              executable_path: row["executable_path"],
              user_name: row["user_name"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse pattern scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp scan_clickhouse_filename(filename, days_back, max_results) do
    escaped = escape_clickhouse(filename)
    from_time = format_ch_datetime(days_ago(days_back))

    sql = """
    SELECT
      event_id, agent_id, event_type, file_path,
      process_name, timestamp
    FROM tamandua.telemetry_events
    WHERE file_path LIKE '%#{escaped}%'
      AND timestamp >= '#{from_time}'
    ORDER BY timestamp DESC
    LIMIT #{max_results}
    FORMAT JSON
    """

    case execute_ch_query(sql) do
      {:ok, rows} ->
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: "filename",
            ioc_value: filename,
            source_table: "telemetry_events",
            agent_id: row["agent_id"],
            event_id: row["event_id"],
            timestamp: row["timestamp"],
            details: %{
              event_type: row["event_type"],
              file_path: row["file_path"],
              process_name: row["process_name"]
            }
          }
        end)
        {:ok, matches}

      {:error, reason} ->
        Logger.warning("[RetroactiveScanner] ClickHouse filename scan failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ── PostgreSQL Fallback ─────────────────────────────────────────────

  defp scan_postgres(type, value, days_back, max_results) do
    import Ecto.Query

    # Supported IOC types for PostgreSQL fallback
    supported = ["ip", "domain", "hash_sha256", "hash_sha1", "hash_md5",
                 "url", "email", "pattern", "filename"]

    if type in supported do
      since = days_ago(days_back)
      escaped_pattern = "%#{escape_like(value)}%"

      # The Event schema uses created_at (via timestamps(inserted_at: :created_at))
      query = from(e in TamanduaServer.Telemetry.Event,
        where: e.created_at >= ^since,
        where: fragment("?::text LIKE ?", e.payload, ^escaped_pattern),
        order_by: [desc: e.created_at],
        limit: ^max_results,
        select: %{
          id: e.id,
          agent_id: e.agent_id,
          event_type: e.event_type,
          timestamp: e.created_at,
          payload: e.payload
        }
      )

      try do
        rows = TamanduaServer.Repo.all(query)
        matches = Enum.map(rows, fn row ->
          %{
            ioc_type: type,
            ioc_value: value,
            source_table: "telemetry_events_pg",
            agent_id: row.agent_id,
            event_id: row.id,
            timestamp: row.timestamp,
            details: %{
              event_type: row.event_type,
              event_id: row.id
            }
          }
        end)
        {:ok, matches}
      rescue
        e ->
          Logger.warning("[RetroactiveScanner] PostgreSQL scan failed: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end
    else
      {:ok, []}
    end
  end

  # ── Alert Creation ──────────────────────────────────────────────────

  defp create_retroactive_alerts(matches, scan_id) when is_list(matches) do
    # Group matches by IOC value to create one alert per IOC
    grouped = Enum.group_by(matches, fn m -> {m.ioc_type, m.ioc_value} end)

    Enum.reduce(grouped, 0, fn {{ioc_type, ioc_value}, ioc_matches}, count ->
      # Deduplicate: check if a retroactive alert already exists for this IOC
      case check_existing_retroactive_alert(ioc_type, ioc_value) do
        true ->
          Logger.debug("[RetroactiveScanner] Skipping duplicate alert for #{ioc_type}:#{ioc_value}")
          count
        false ->
          case create_single_retroactive_alert(ioc_type, ioc_value, ioc_matches, scan_id) do
            {:ok, _} -> count + 1
            _ -> count
          end
      end
    end)
  end

  defp check_existing_retroactive_alert(ioc_type, ioc_value) do
    import Ecto.Query

    # Check if we already have a retroactive alert for this IOC in the last 24h.
    # We identify retroactive scanner alerts via detection_metadata->>'source'
    # and match the specific IOC via evidence->>'ioc_type' + evidence->>'ioc_value'.
    cutoff = DateTime.utc_now() |> DateTime.add(-86400, :second)

    query = from(a in TamanduaServer.Alerts.Alert,
      where: a.inserted_at >= ^cutoff,
      where: fragment("?->>'source' = 'retroactive_scanner'", a.detection_metadata),
      where: fragment("?->>'ioc_type' = ? AND ?->>'ioc_value' = ?",
        a.evidence, ^ioc_type, a.evidence, ^ioc_value),
      limit: 1
    )

    case TamanduaServer.Repo.one(query) do
      nil -> false
      _ -> true
    end
  rescue
    e ->
      Logger.warning("[RetroactiveScanner] Retroactive alert check failed: #{Exception.message(e)}")
      false
  end

  defp create_single_retroactive_alert(ioc_type, ioc_value, matches, scan_id) do
    affected_agents = matches |> Enum.map(& &1.agent_id) |> Enum.uniq()
    earliest_match = matches |> Enum.min_by(& &1.timestamp, fn -> nil end)
    latest_match = matches |> Enum.max_by(& &1.timestamp, fn -> nil end)

    # Derive severity from IOC confidence score if available
    ioc_confidence = matches
    |> Enum.find_value(fn m -> m[:ioc_confidence] end)

    severity = determine_severity(ioc_type, length(matches), length(affected_agents), ioc_confidence)

    # Gather IOC source information for linking
    ioc_source = matches
    |> Enum.find_value(fn m -> m[:ioc_source] end)

    evidence = %{
      "ioc_type" => ioc_type,
      "ioc_value" => ioc_value,
      "match_count" => length(matches),
      "affected_agents" => affected_agents,
      "earliest_match" => earliest_match && earliest_match.timestamp,
      "latest_match" => latest_match && latest_match.timestamp,
      "source_tables" => matches |> Enum.map(& &1.source_table) |> Enum.uniq(),
      "sample_matches" => Enum.take(matches, 10),
      "scan_id" => scan_id,
      "ioc_source" => ioc_source,
      "ioc_confidence" => ioc_confidence
    }

    alert_attrs = %{
      title: "Retroactive IOC Match: #{ioc_type} #{truncate(ioc_value, 60)}",
      description: """
      Historical telemetry matches found for IOC #{ioc_value} (#{ioc_type}).
      #{length(matches)} match(es) across #{length(affected_agents)} agent(s).
      This IOC was found in historical data before it was added to threat intel feeds.
      Source: #{ioc_source || "unknown"}
      """,
      severity: severity,
      status: "new",
      evidence: evidence,
      detection_metadata: %{
        "detection_type" => "retroactive_ioc_scan",
        "source" => "retroactive_scanner",
        "category" => "threat_intel",
        "ioc_type" => ioc_type,
        "ioc_value" => ioc_value,
        "scan_id" => scan_id,
        "feed_source" => ioc_source
      },
      mitre_techniques: determine_mitre_techniques(ioc_type),
      agent_id: List.first(affected_agents),
      threat_score: calculate_threat_score(severity, length(matches))
    }

    try do
      Alerts.create_alert(alert_attrs)
    rescue
      e ->
        Logger.error("[RetroactiveScanner] Failed to create alert: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  # ── Campaign Tracker Integration ────────────────────────────────────

  defp notify_campaign_tracker(matches) when length(matches) == 0, do: :ok
  defp notify_campaign_tracker(matches) do
    try do
      matches
      |> Enum.group_by(fn match ->
        TamanduaServer.Agents.OrgLookup.get_org_id(match.agent_id)
      end)
      |> Enum.each(fn
        {organization_id, agent_matches}
        when is_binary(organization_id) and organization_id != "" ->
          scoped_matches =
            Enum.filter(agent_matches, fn match ->
              claimed = match[:organization_id]
              valid = is_nil(claimed) or claimed == organization_id

              unless valid do
                :telemetry.execute(
                  [:tamandua, :campaign_tracker, :attribution_dropped],
                  %{count: 1},
                  %{source: :retroactive_scanner, reason: :organization_mismatch}
                )
              end

              valid
            end)

          if scoped_matches != [] do
            ioc_values = scoped_matches |> Enum.map(& &1.ioc_value) |> Enum.uniq()

            TamanduaServer.ThreatIntel.CampaignTracker.record_attribution(
              organization_id,
              %{
                source: "retroactive_scanner",
                ioc_values: ioc_values,
                match_count: length(scoped_matches),
                timestamp: DateTime.utc_now()
              }
            )
          end

        {_unknown, dropped} ->
          :telemetry.execute(
            [:tamandua, :campaign_tracker, :attribution_dropped],
            %{count: length(dropped)},
            %{source: :retroactive_scanner, reason: :organization_unknown}
          )
      end)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # ── PubSub ──────────────────────────────────────────────────────────

  defp subscribe_to_ioc_changes do
    try do
      Phoenix.PubSub.subscribe(@pubsub, @ioc_topic)
    rescue
      _ ->
        Logger.warning("[RetroactiveScanner] Failed to subscribe to #{@ioc_topic}")
    catch
      :exit, _ ->
        Logger.warning("[RetroactiveScanner] PubSub not available for #{@ioc_topic}")
    end
  end

  defp broadcast_scan_update(scan_id, event) do
    try do
      job = ets_lookup(@ets_jobs, scan_id)
      payload = %{
        scan_id: scan_id,
        event: event,
        job: job
      }
      Phoenix.PubSub.broadcast(@pubsub, @topic, {:scan_update, payload})
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────

  defp determine_severity(ioc_type, match_count, agent_count, ioc_confidence) do
    # Use IOC confidence to set base severity if available
    base = cond do
      is_number(ioc_confidence) and ioc_confidence >= 0.9 -> 4
      is_number(ioc_confidence) and ioc_confidence >= 0.7 -> 3
      true ->
        case ioc_type do
          t when t in ["hash_sha256", "hash_sha1", "hash_md5"] -> 3
          "ip" -> 2
          "domain" -> 2
          "url" -> 2
          "email" -> 2
          "pattern" -> 3
          _ -> 1
        end
    end

    # Boost for multiple matches or agents
    boost = cond do
      agent_count >= 5 -> 2
      agent_count >= 2 -> 1
      match_count >= 10 -> 1
      true -> 0
    end

    case min(base + boost, 4) do
      1 -> "low"
      2 -> "medium"
      3 -> "high"
      _ -> "critical"
    end
  end

  defp determine_mitre_techniques(ioc_type) do
    case ioc_type do
      "ip" -> ["T1071"]           # Application Layer Protocol
      "domain" -> ["T1071.001"]   # Web Protocols
      "url" -> ["T1071.001"]      # Web Protocols
      "email" -> ["T1566"]        # Phishing
      "pattern" -> ["T1059"]      # Command and Scripting Interpreter
      "filename" -> ["T1105"]     # Ingress Tool Transfer
      _ -> ["T1105"]              # Ingress Tool Transfer (hash matches)
    end
  end

  defp calculate_threat_score(severity, match_count) do
    base = case severity do
      "critical" -> 90
      "high" -> 70
      "medium" -> 50
      "low" -> 30
      _ -> 20
    end

    # Small boost for multiple matches (max +10)
    boost = min(match_count, 10)
    min(base + boost, 100)
  end

  defp build_time_partitions(days_back) do
    # Build date partitions for ClickHouse to enable partition pruning
    now = DateTime.utc_now()
    Enum.map(0..days_back, fn d ->
      DateTime.add(now, -d * 86400, :second)
      |> Calendar.strftime("%Y-%m-%d")
    end)
  end

  defp days_ago(days) do
    DateTime.utc_now() |> DateTime.add(-days * 86400, :second)
  end

  defp format_ch_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S.") <>
      String.pad_leading(
        to_string(rem(dt.microsecond |> elem(0), 1_000_000) |> div(1_000)),
        3,
        "0"
      )
  end

  defp escape_clickhouse(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
  end

  defp escape_clickhouse(value), do: escape_clickhouse(to_string(value))

  defp escape_like(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("%", "\\%")
    |> String.replace("_", "\\_")
  end

  defp truncate(str, max_length) when is_binary(str) do
    if String.length(str) > max_length do
      String.slice(str, 0, max_length) <> "..."
    else
      str
    end
  end

  defp truncate(val, _), do: to_string(val)

  defp generate_scan_id do
    "retro_" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
  end

  defp execute_ch_query(sql) do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry.ClickHouse, [])
    url = Keyword.get(config, :url, "http://localhost:8123")
    database = Keyword.get(config, :database, "tamandua")
    username = Keyword.get(config, :username, "default")
    password = Keyword.get(config, :password, "")

    full_url = "#{url}/?database=#{database}"

    headers =
      [{"content-type", "text/plain"}] ++
        if(username != "", do: [{"X-ClickHouse-User", username}], else: []) ++
        if(password != "", do: [{"X-ClickHouse-Key", password}], else: [])

    request = Finch.build(:post, full_url, headers, sql)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} -> {:ok, data}
          {:ok, other} -> {:ok, other}
          {:error, _} -> {:ok, body}
        end

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{String.slice(body, 0, 500)}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ── ETS Helpers ──────────────────────────────────────────────────────

  defp ets_lookup(table, key) do
    case :ets.lookup(table, key) do
      [{^key, value}] -> value
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp ets_all_values(table) do
    :ets.tab2list(table)
    |> Enum.map(fn {_, value} -> value end)
  rescue
    ArgumentError -> []
  end

  defp ets_counter(table, key) do
    case :ets.lookup(table, key) do
      [{^key, value}] when is_integer(value) -> value
      _ -> 0
    end
  rescue
    ArgumentError -> 0
  end

  defp update_job(scan_id, updates) when is_map(updates) do
    case ets_lookup(@ets_jobs, scan_id) do
      nil -> :ok
      job ->
        updated = Map.merge(job, updates)
        :ets.insert(@ets_jobs, {scan_id, updated})
    end
  rescue
    _ -> :ok
  end

  defp increment_stat(key, amount) do
    try do
      :ets.update_counter(@ets_stats, key, amount)
    rescue
      ArgumentError ->
        :ets.insert(@ets_stats, {key, amount})
    end
  end

  defp decrement_active_scans do
    try do
      current = ets_counter(@ets_stats, :active_scans)
      :ets.insert(@ets_stats, {:active_scans, max(current - 1, 0)})
    rescue
      _ -> :ok
    end
  end
end
