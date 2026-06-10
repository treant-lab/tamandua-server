defmodule TamanduaServer.Forensics.Timeline do
  @moduledoc """
  Forensic timeline reconstruction engine.

  Builds unified, chronologically-ordered timelines from multiple telemetry
  sources stored in ClickHouse. Merges process, file, network, DNS, and
  registry events from one or more agents into a single narrative.

  Features:
  - Multi-agent, multi-source timeline merging
  - Filtering by event type, process, user, and severity
  - Temporal pattern detection (rapid file creation, lateral movement)
  - Export to JSON and CSV formats
  - Notable event extraction for report summaries
  """
  require Logger

  # Event sources and their ClickHouse tables
  @event_sources %{
    process: "tamandua.process_events",
    dns: "tamandua.dns_queries",
    network: "tamandua.network_flows",
    telemetry: "tamandua.telemetry_events"
  }

  # Severity ordering for notable event selection
  @severity_order %{
    "critical" => 5,
    "high" => 4,
    "medium" => 3,
    "low" => 2,
    "info" => 1
  }

  # ── Public API ──────────────────────────────────────────────────────

  @doc """
  Builds a unified timeline from multiple telemetry sources.

  ## Options
    - `:agent_ids` (required) - List of agent IDs to query
    - `:from` - Start time (DateTime, default: 24 hours ago)
    - `:to` - End time (DateTime, default: now)
    - `:event_types` - List of event types to include (nil = all)
    - `:process_filter` - Filter by process name pattern
    - `:user_filter` - Filter by username pattern
    - `:severity_filter` - Minimum severity level
    - `:limit` - Max events per source table (default 2000)
    - `:format` - "json" or "csv" (default "json")

  ## Returns
    - `{:ok, timeline}` with merged, sorted events and metadata
    - `{:error, reason}` on failure
  """
  @spec build_unified_timeline(map()) :: {:ok, map()} | {:error, term()}
  def build_unified_timeline(opts) do
    agent_ids = Map.get(opts, :agent_ids, [])

    if agent_ids == [] do
      {:ok, empty_timeline(opts)}
    else
      do_build_timeline(agent_ids, opts)
    end
  end

  @doc """
  Queries events for a single agent within a time range from a specific table.
  """
  @spec query_source(atom(), String.t(), DateTime.t(), DateTime.t(), map()) ::
          {:ok, [map()]} | {:error, term()}
  def query_source(source, agent_id, from, to, opts \\ %{}) do
    limit = Map.get(opts, :limit, 1000)
    table = Map.get(@event_sources, source)

    if is_nil(table) do
      {:error, {:unknown_source, source}}
    else
      sql = build_source_query(source, table, agent_id, from, to, limit, opts)
      execute_ch_query(sql)
    end
  end

  @doc """
  Detects temporal patterns in a timeline.

  Currently detects:
  - Rapid file creation (>10 files in 60 seconds)
  - Lateral movement sequences (remote connections to multiple hosts)
  - Credential access patterns (lsass access, SAM reads)
  - Command shell chains (multiple nested shells)
  """
  @spec detect_patterns([map()]) :: [map()]
  def detect_patterns(events) when is_list(events) do
    patterns = []

    patterns = patterns ++ detect_rapid_file_creation(events)
    patterns = patterns ++ detect_lateral_movement(events)
    patterns = patterns ++ detect_credential_access(events)
    patterns = patterns ++ detect_shell_chains(events)

    Enum.sort_by(patterns, fn p -> p[:severity_score] || 0 end, :desc)
  end

  @doc """
  Exports a timeline to CSV format.
  """
  @spec export_csv([map()]) :: String.t()
  def export_csv(events) when is_list(events) do
    header = "timestamp,source,event_type,agent_id,process_name,pid,severity,description,details\n"

    rows = Enum.map(events, fn event ->
      [
        format_dt(event[:timestamp]),
        event[:source] || "",
        event[:event_type] || "",
        event[:agent_id] || "",
        event[:process_name] || "",
        to_string(event[:pid] || ""),
        event[:severity] || "info",
        csv_escape(event[:description] || ""),
        csv_escape(Jason.encode!(event[:details] || %{}))
      ]
      |> Enum.join(",")
    end)

    header <> Enum.join(rows, "\n")
  end

  @doc """
  Exports timeline events as JSON.
  """
  @spec export_json([map()]) :: {:ok, String.t()} | {:error, term()}
  def export_json(events) when is_list(events) do
    case Jason.encode(%{events: events, exported_at: DateTime.utc_now(), count: length(events)}) do
      {:ok, json} -> {:ok, json}
      error -> error
    end
  end

  # ── Private: Timeline Construction ─────────────────────────────────

  defp do_build_timeline(agent_ids, opts) do
    from = normalize_datetime(Map.get(opts, :from)) || DateTime.add(DateTime.utc_now(), -86_400, :second)
    to = normalize_datetime(Map.get(opts, :to)) || DateTime.utc_now()
    limit = Map.get(opts, :limit, 2000)

    # Query all sources concurrently for each agent
    tasks = for agent_id <- agent_ids, {source, _table} <- @event_sources do
      {source, agent_id}
    end

    results =
      tasks
      |> Task.async_stream(
        fn {source, agent_id} ->
          case query_source(source, agent_id, from, to, opts) do
            {:ok, events} ->
              events
              |> Enum.map(fn ev -> normalize_event(source, agent_id, ev) end)

            {:error, reason} ->
              Logger.debug("[Timeline] Query failed for #{source}/#{agent_id}: #{inspect(reason)}")
              []
          end
        end,
        max_concurrency: 8,
        timeout: 30_000,
        on_timeout: :kill_task
      )
      |> Enum.flat_map(fn
        {:ok, events} -> events
        {:exit, _} -> []
      end)

    # Apply user-level filters
    filtered = results
    |> maybe_filter_process(opts)
    |> maybe_filter_user(opts)
    |> maybe_filter_severity(opts)
    |> maybe_filter_event_types(opts)

    # Sort chronologically and limit
    sorted = filtered
    |> Enum.sort_by(fn ev -> ev[:timestamp] || "" end, :asc)
    |> Enum.take(limit)

    # Compute metadata
    event_type_dist = Enum.frequencies_by(sorted, fn ev -> ev[:event_type] || "unknown" end)
    agent_dist = Enum.frequencies_by(sorted, fn ev -> ev[:agent_id] || "unknown" end)
    source_dist = Enum.frequencies_by(sorted, fn ev -> ev[:source] || "unknown" end)

    # Extract notable events (high/critical severity or pattern matches)
    notable = sorted
    |> Enum.filter(fn ev ->
      sev = ev[:severity] || "info"
      Map.get(@severity_order, sev, 0) >= 3
    end)
    |> Enum.take(50)

    # Detect temporal patterns
    patterns = detect_patterns(sorted)

    timeline = %{
      events: sorted,
      total_events: length(sorted),
      total_unfiltered: length(results),
      from: from,
      to: to,
      agent_ids: agent_ids,
      event_type_distribution: event_type_dist,
      agent_distribution: agent_dist,
      source_distribution: source_dist,
      notable_events: notable,
      temporal_patterns: patterns,
      generated_at: DateTime.utc_now()
    }

    {:ok, timeline}
  rescue
    e ->
      Logger.error("[Timeline] Failed to build timeline: #{Exception.message(e)}")
      {:error, {:timeline_build_failed, Exception.message(e)}}
  end

  defp empty_timeline(opts) do
    from = normalize_datetime(Map.get(opts, :from)) || DateTime.add(DateTime.utc_now(), -86_400, :second)
    to = normalize_datetime(Map.get(opts, :to)) || DateTime.utc_now()

    %{
      events: [],
      total_events: 0,
      total_unfiltered: 0,
      from: from,
      to: to,
      agent_ids: [],
      event_type_distribution: %{},
      agent_distribution: %{},
      source_distribution: %{},
      notable_events: [],
      temporal_patterns: [],
      generated_at: DateTime.utc_now()
    }
  end

  # ── Private: Source Queries ─────────────────────────────────────────

  defp build_source_query(:process, table, agent_id, from, to, limit, _opts) do
    """
    SELECT
      event_id, timestamp, agent_id,
      'process' AS source,
      process_name, process_id AS pid, parent_process_id AS ppid,
      command_line, executable_path, user_name,
      is_elevated, is_signed, signer, file_hash AS hash_sha256
    FROM #{table}
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_ch_dt(from)}'
      AND timestamp <= '#{format_ch_dt(to)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """
  end

  defp build_source_query(:dns, table, agent_id, from, to, limit, _opts) do
    """
    SELECT
      event_id, timestamp, agent_id,
      'dns' AS source,
      process_name, process_id AS pid,
      query_name, query_type, response_code,
      is_suspicious
    FROM #{table}
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_ch_dt(from)}'
      AND timestamp <= '#{format_ch_dt(to)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """
  end

  defp build_source_query(:network, table, agent_id, from, to, limit, _opts) do
    """
    SELECT
      event_id, timestamp, agent_id,
      'network' AS source,
      process_name, process_id AS pid,
      source_ip, dest_ip, source_port, dest_port,
      protocol, bytes_sent, bytes_received, duration_ms
    FROM #{table}
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_ch_dt(from)}'
      AND timestamp <= '#{format_ch_dt(to)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """
  end

  defp build_source_query(:telemetry, table, agent_id, from, to, limit, _opts) do
    """
    SELECT
      event_id, timestamp, agent_id,
      'telemetry' AS source,
      event_type, severity,
      process_name, process_id AS pid,
      command_line, file_path, file_hash,
      dns_query, rule_name,
      mitre_technique, mitre_tactic, threat_score,
      payload
    FROM #{table}
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_ch_dt(from)}'
      AND timestamp <= '#{format_ch_dt(to)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """
  end

  # ── Private: Event Normalization ───────────────────────────────────

  defp normalize_event(:process, agent_id, raw) do
    %{
      event_id: raw["event_id"],
      timestamp: raw["timestamp"],
      agent_id: raw["agent_id"] || agent_id,
      source: "process",
      event_type: "process_event",
      severity: if(raw["is_elevated"] == 1, do: "medium", else: "info"),
      process_name: raw["process_name"],
      pid: parse_int(raw["pid"]),
      ppid: parse_int(raw["ppid"]),
      description: build_process_description(raw),
      details: %{
        command_line: raw["command_line"],
        executable_path: raw["executable_path"],
        user_name: raw["user_name"],
        is_elevated: raw["is_elevated"] == 1,
        is_signed: raw["is_signed"] == 1,
        signer: raw["signer"],
        hash_sha256: raw["hash_sha256"]
      }
    }
  end

  defp normalize_event(:dns, agent_id, raw) do
    %{
      event_id: raw["event_id"],
      timestamp: raw["timestamp"],
      agent_id: raw["agent_id"] || agent_id,
      source: "dns",
      event_type: "dns_query",
      severity: if(raw["is_suspicious"] == 1, do: "medium", else: "info"),
      process_name: raw["process_name"],
      pid: parse_int(raw["pid"]),
      description: "DNS query: #{raw["query_name"]} (#{raw["query_type"] || "A"})",
      details: %{
        query_name: raw["query_name"],
        query_type: raw["query_type"],
        response_code: raw["response_code"],
        is_suspicious: raw["is_suspicious"] == 1
      }
    }
  end

  defp normalize_event(:network, agent_id, raw) do
    %{
      event_id: raw["event_id"],
      timestamp: raw["timestamp"],
      agent_id: raw["agent_id"] || agent_id,
      source: "network",
      event_type: "network_connection",
      severity: "info",
      process_name: raw["process_name"],
      pid: parse_int(raw["pid"]),
      description: "#{raw["source_ip"]}:#{raw["source_port"]} -> #{raw["dest_ip"]}:#{raw["dest_port"]} (#{raw["protocol"]})",
      details: %{
        source_ip: raw["source_ip"],
        dest_ip: raw["dest_ip"],
        source_port: parse_int(raw["source_port"]),
        dest_port: parse_int(raw["dest_port"]),
        protocol: raw["protocol"],
        bytes_sent: parse_int(raw["bytes_sent"]),
        bytes_received: parse_int(raw["bytes_received"]),
        duration_ms: parse_int(raw["duration_ms"])
      }
    }
  end

  defp normalize_event(:telemetry, agent_id, raw) do
    payload = case raw["payload"] do
      p when is_binary(p) ->
        case Jason.decode(p) do
          {:ok, decoded} -> decoded
          _ -> %{}
        end
      p when is_map(p) -> p
      _ -> %{}
    end

    %{
      event_id: raw["event_id"],
      timestamp: raw["timestamp"],
      agent_id: raw["agent_id"] || agent_id,
      source: "telemetry",
      event_type: raw["event_type"] || "unknown",
      severity: raw["severity"] || "info",
      process_name: raw["process_name"],
      pid: parse_int(raw["process_id"] || raw["pid"]),
      description: build_telemetry_description(raw),
      details: %{
        command_line: raw["command_line"],
        file_path: raw["file_path"],
        file_hash: raw["file_hash"],
        dns_query: raw["dns_query"],
        rule_name: raw["rule_name"],
        mitre_technique: raw["mitre_technique"],
        mitre_tactic: raw["mitre_tactic"],
        threat_score: raw["threat_score"],
        payload: payload
      }
    }
  end

  defp build_process_description(raw) do
    name = raw["process_name"] || "unknown"
    pid = raw["pid"]
    cmd = raw["command_line"]
    user = raw["user_name"]

    parts = ["Process: #{name}"]
    parts = if pid, do: parts ++ ["PID #{pid}"], else: parts
    parts = if user && user != "", do: parts ++ ["user #{user}"], else: parts
    parts = if cmd && cmd != "", do: parts ++ ["cmd: #{String.slice(cmd, 0, 120)}"], else: parts

    Enum.join(parts, " | ")
  end

  defp build_telemetry_description(raw) do
    type = raw["event_type"] || "event"
    rule = raw["rule_name"]
    technique = raw["mitre_technique"]
    name = raw["process_name"]

    parts = [type]
    parts = if name && name != "", do: parts ++ [name], else: parts
    parts = if rule && rule != "", do: parts ++ ["rule: #{rule}"], else: parts
    parts = if technique && technique != "", do: parts ++ ["[#{technique}]"], else: parts

    Enum.join(parts, " | ")
  end

  # ── Private: Filtering ──────────────────────────────────────────────

  defp maybe_filter_process(events, opts) do
    case Map.get(opts, :process_filter) do
      nil -> events
      "" -> events
      pattern ->
        pattern_down = String.downcase(pattern)
        Enum.filter(events, fn ev ->
          name = String.downcase(ev[:process_name] || "")
          String.contains?(name, pattern_down)
        end)
    end
  end

  defp maybe_filter_user(events, opts) do
    case Map.get(opts, :user_filter) do
      nil -> events
      "" -> events
      pattern ->
        pattern_down = String.downcase(pattern)
        Enum.filter(events, fn ev ->
          user = String.downcase(get_in(ev, [:details, :user_name]) || "")
          String.contains?(user, pattern_down)
        end)
    end
  end

  defp maybe_filter_severity(events, opts) do
    case Map.get(opts, :severity_filter) do
      nil -> events
      "" -> events
      min_severity ->
        min_order = Map.get(@severity_order, min_severity, 0)
        Enum.filter(events, fn ev ->
          sev = ev[:severity] || "info"
          Map.get(@severity_order, sev, 0) >= min_order
        end)
    end
  end

  defp maybe_filter_event_types(events, opts) do
    case Map.get(opts, :event_types) do
      nil -> events
      [] -> events
      types when is_list(types) ->
        Enum.filter(events, fn ev -> ev[:event_type] in types end)
      _ -> events
    end
  end

  # ── Private: Pattern Detection ──────────────────────────────────────

  defp detect_rapid_file_creation(events) do
    file_events = Enum.filter(events, fn ev ->
      ev[:event_type] in ["file_create", "file_write", "file_modify"]
    end)

    if length(file_events) < 10 do
      []
    else
      # Sliding window of 60 seconds
      file_events
      |> Enum.chunk_every(10, 1, :discard)
      |> Enum.filter(fn chunk ->
        first_ts = parse_timestamp(List.first(chunk)[:timestamp])
        last_ts = parse_timestamp(List.last(chunk)[:timestamp])
        first_ts && last_ts && DateTime.diff(last_ts, first_ts, :second) <= 60
      end)
      |> Enum.take(5)
      |> Enum.map(fn chunk ->
        %{
          type: "rapid_file_creation",
          severity_score: 70,
          description: "#{length(chunk)} file operations within 60 seconds",
          first_event: List.first(chunk)[:timestamp],
          last_event: List.last(chunk)[:timestamp],
          event_count: length(chunk),
          sample_events: Enum.take(chunk, 3)
        }
      end)
    end
  end

  defp detect_lateral_movement(events) do
    # Look for network connections to multiple internal hosts from same process
    network_events = Enum.filter(events, fn ev ->
      ev[:source] == "network" and ev[:details][:dest_ip] != nil
    end)

    network_events
    |> Enum.group_by(fn ev -> {ev[:agent_id], ev[:process_name]} end)
    |> Enum.filter(fn {_key, evts} ->
      unique_dests = evts
      |> Enum.map(fn ev -> ev[:details][:dest_ip] end)
      |> Enum.uniq()
      |> length()

      unique_dests >= 3
    end)
    |> Enum.map(fn {{agent_id, process}, evts} ->
      dest_ips = evts |> Enum.map(fn ev -> ev[:details][:dest_ip] end) |> Enum.uniq()

      %{
        type: "lateral_movement_candidate",
        severity_score: 80,
        description: "#{process} on #{agent_id} connected to #{length(dest_ips)} unique hosts",
        agent_id: agent_id,
        process_name: process,
        destination_ips: dest_ips,
        event_count: length(evts),
        first_event: List.first(evts)[:timestamp],
        last_event: List.last(evts)[:timestamp]
      }
    end)
  end

  defp detect_credential_access(events) do
    cred_indicators = ["lsass", "sam", "security", "ntds", "mimikatz", "procdump", "comsvcs"]

    suspicious = Enum.filter(events, fn ev ->
      name = String.downcase(ev[:process_name] || "")
      cmd = String.downcase(get_in(ev, [:details, :command_line]) || "")
      desc = String.downcase(ev[:description] || "")

      Enum.any?(cred_indicators, fn indicator ->
        String.contains?(name, indicator) or
        String.contains?(cmd, indicator) or
        String.contains?(desc, indicator)
      end)
    end)

    if length(suspicious) > 0 do
      [%{
        type: "credential_access",
        severity_score: 90,
        description: "#{length(suspicious)} events suggest credential access activity",
        event_count: length(suspicious),
        sample_events: Enum.take(suspicious, 5),
        indicators: cred_indicators
      }]
    else
      []
    end
  end

  defp detect_shell_chains(events) do
    shell_names = ["cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "wscript.exe", "cscript.exe"]

    shell_events = Enum.filter(events, fn ev ->
      name = String.downcase(ev[:process_name] || "")
      Enum.any?(shell_names, &String.contains?(name, &1))
    end)

    if length(shell_events) >= 3 do
      # Group by agent and check for sequential shell spawning
      shell_events
      |> Enum.group_by(& &1[:agent_id])
      |> Enum.filter(fn {_agent, evts} -> length(evts) >= 3 end)
      |> Enum.map(fn {agent_id, evts} ->
        %{
          type: "shell_chain",
          severity_score: 60,
          description: "#{length(evts)} shell processes spawned on #{agent_id}",
          agent_id: agent_id,
          event_count: length(evts),
          shells: Enum.map(evts, fn ev -> ev[:process_name] end) |> Enum.uniq(),
          first_event: List.first(evts)[:timestamp],
          last_event: List.last(evts)[:timestamp]
        }
      end)
    else
      []
    end
  end

  # ── Private: ClickHouse Execution ───────────────────────────────────

  defp execute_ch_query(sql) do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry.ClickHouse, [])

    unless Keyword.get(config, :enabled, false) do
      # Return empty results when ClickHouse is disabled
      {:ok, []}
    else
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
            {:error, _} -> {:ok, []}
          end

        {:ok, %Finch.Response{status: status, body: body}} ->
          {:error, "ClickHouse HTTP #{status}: #{String.slice(body, 0, 500)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ── Private: Helpers ────────────────────────────────────────────────

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
    |> String.replace("\n", "")
    |> String.replace("\r", "")
  end

  defp escape(value), do: escape(to_string(value))

  defp format_ch_dt(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  end

  defp format_ch_dt(_), do: format_ch_dt(DateTime.utc_now())

  defp format_dt(nil), do: ""
  defp format_dt(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_dt(s) when is_binary(s), do: s
  defp format_dt(_), do: ""

  defp normalize_datetime(nil), do: nil
  defp normalize_datetime(%DateTime{} = dt), do: dt
  defp normalize_datetime(ms) when is_integer(ms) and ms > 1_000_000_000_000 do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end
  defp normalize_datetime(s) when is_integer(s) do
    case DateTime.from_unix(s) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end
  defp normalize_datetime(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp normalize_datetime(_), do: nil

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> dt
      _ ->
        # Try ClickHouse format
        case NaiveDateTime.from_iso8601(s) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_timestamp(_), do: nil

  defp parse_int(nil), do: nil
  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(v) when is_float(v), do: trunc(v)
  defp parse_int(_), do: nil

  defp csv_escape(nil), do: ""
  defp csv_escape(value) when is_binary(value) do
    if String.contains?(value, [",", "\"", "\n"]) do
      "\"" <> String.replace(value, "\"", "\"\"") <> "\""
    else
      value
    end
  end
  defp csv_escape(value), do: csv_escape(to_string(value))
end
