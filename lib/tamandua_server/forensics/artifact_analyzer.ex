defmodule TamanduaServer.Forensics.ArtifactAnalyzer do
  @moduledoc """
  Windows forensic artifact parser and analyzer.

  Parses common Windows artifacts and scores them for suspiciousness:

  - **Prefetch**: Execution count, timestamps, loaded DLLs, executable path
  - **Shimcache (AppCompatCache)**: Program execution evidence from registry
  - **Amcache**: Installed program history with SHA1 hashes
  - **SRUM (System Resource Usage Monitor)**: CPU/network/energy usage per app

  Each artifact is cross-referenced against known-bad indicators and assigned
  a suspiciousness score from 0 (benign) to 100 (highly suspicious).
  """
  require Logger

  # Known suspicious executable names
  @suspicious_executables [
    "mimikatz", "lazagne", "procdump", "pwdump", "wce", "gsecdump",
    "secretsdump", "sharphound", "bloodhound", "rubeus", "seatbelt",
    "covenant", "cobalt", "beacon", "meterpreter", "psexec",
    "wmiexec", "smbexec", "atexec", "dcomexec",
    "powerview", "powerup", "invoke-obfuscation",
    "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
    "nc.exe", "ncat", "netcat", "socat", "chisel", "plink"
  ]

  # Known suspicious DLLs
  @suspicious_dlls [
    "amsi.dll", "clrjit.dll", "dbghelp.dll", "dbgcore.dll",
    "mimilib.dll", "vaultcli.dll", "samlib.dll",
    "winscard.dll", "cryptdll.dll"
  ]

  # Known persistence locations in registry
  @persistence_paths [
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\explorer\\shell folders",
    "\\currentversion\\winlogon",
    "\\currentversion\\image file execution",
    "\\services\\",
    "\\currentcontrolset\\services\\",
    "\\environment\\",
    "\\policies\\explorer\\run"
  ]

  # Suspicious paths
  @suspicious_paths [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\public\\", "\\perflogs\\", "\\programdata\\",
    "\\windows\\debug\\", "\\recycler\\", "\\$recycle.bin\\"
  ]

  # ── Public API ──────────────────────────────────────────────────────

  @doc """
  Analyze a forensic artifact.

  ## Parameters
    - `artifact_type` - One of: "prefetch_files", "shimcache", "amcache", "srum_data"
    - `artifact_data` - Map containing the raw artifact data (parsed or structured)

  ## Returns
    - `{:ok, analysis}` with parsed results and suspiciousness score
    - `{:error, reason}` on failure
  """
  @spec analyze(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def analyze(artifact_type, artifact_data) when is_map(artifact_data) do
    case artifact_type do
      "prefetch_files" -> analyze_prefetch(artifact_data)
      "prefetch" -> analyze_prefetch(artifact_data)
      "shimcache" -> analyze_shimcache(artifact_data)
      "amcache" -> analyze_amcache(artifact_data)
      "srum_data" -> analyze_srum(artifact_data)
      "srum" -> analyze_srum(artifact_data)
      "event_log" <> _ -> analyze_event_log(artifact_data)
      "registry_hive" -> analyze_registry_hive(artifact_data)
      _ -> {:error, {:unsupported_artifact_type, artifact_type}}
    end
  rescue
    e ->
      Logger.error("[ArtifactAnalyzer] Error analyzing #{artifact_type}: #{Exception.message(e)}")
      {:error, {:analysis_failed, Exception.message(e)}}
  end

  def analyze(_type, _data), do: {:error, :invalid_artifact_data}

  @doc """
  Batch analyze multiple artifacts and return aggregated results.
  """
  @spec analyze_batch([{String.t(), map()}]) :: {:ok, [map()]}
  def analyze_batch(artifacts) when is_list(artifacts) do
    results = Enum.map(artifacts, fn {type, data} ->
      case analyze(type, data) do
        {:ok, analysis} -> %{type: type, status: "success", analysis: analysis}
        {:error, reason} -> %{type: type, status: "error", error: inspect(reason)}
      end
    end)

    {:ok, results}
  end

  @doc """
  Cross-reference artifact data against a list of known-bad indicators.

  ## Parameters
    - `artifact_analysis` - The analysis result from `analyze/2`
    - `indicators` - List of indicator maps with `:type` and `:value`

  ## Returns
    - List of matches with indicator details and evidence context
  """
  @spec cross_reference(map(), [map()]) :: [map()]
  def cross_reference(analysis, indicators) when is_map(analysis) and is_list(indicators) do
    # Extract all searchable values from the analysis
    searchable = extract_searchable_values(analysis)

    indicators
    |> Enum.filter(fn indicator ->
      value = indicator[:value] || indicator["value"] || ""
      value_down = String.downcase(value)

      Enum.any?(searchable, fn {_field, sv} ->
        sv_down = String.downcase(to_string(sv))
        sv_down == value_down or String.contains?(sv_down, value_down)
      end)
    end)
    |> Enum.map(fn indicator ->
      value = indicator[:value] || indicator["value"]
      %{
        indicator_type: indicator[:type] || indicator["type"],
        indicator_value: value,
        matched_in: find_matching_fields(searchable, value),
        severity: indicator[:severity] || "high"
      }
    end)
  end

  def cross_reference(_analysis, _indicators), do: []

  # ── Prefetch Analysis ──────────────────────────────────────────────

  defp analyze_prefetch(data) do
    entries = get_list(data, "entries", "prefetch_entries")
    parsed = Enum.map(entries, &parse_prefetch_entry/1)
    scored = Enum.map(parsed, &score_prefetch_entry/1)

    # Find most suspicious entries
    top_suspicious = scored
    |> Enum.sort_by(& &1.suspiciousness_score, :desc)
    |> Enum.take(20)

    # Execution frequency analysis
    frequently_executed = scored
    |> Enum.filter(fn e -> (e.execution_count || 0) > 10 end)
    |> Enum.sort_by(& &1.execution_count, :desc)

    # Recently executed (within last 24 hours based on timestamps)
    recently_executed = scored
    |> Enum.filter(fn e -> e.flags[:recently_executed] end)

    # Suspicious DLL loads
    suspicious_dll_loads = scored
    |> Enum.filter(fn e -> length(e.suspicious_dlls) > 0 end)

    max_score = if scored != [], do: Enum.max_by(scored, & &1.suspiciousness_score).suspiciousness_score, else: 0

    analysis = %{
      artifact_type: "prefetch",
      total_entries: length(parsed),
      top_suspicious: top_suspicious,
      frequently_executed: frequently_executed,
      recently_executed: recently_executed,
      suspicious_dll_loads: suspicious_dll_loads,
      suspiciousness_score: max_score,
      summary: build_prefetch_summary(scored)
    }

    {:ok, analysis}
  end

  defp parse_prefetch_entry(entry) when is_map(entry) do
    exe_name = get_str(entry, "executable_name", "name") || ""
    path = get_str(entry, "executable_path", "path") || ""
    run_count = get_int(entry, "run_count", "execution_count") || 0
    last_run = get_str(entry, "last_run_time", "last_executed") || ""
    loaded_dlls = get_list(entry, "loaded_dlls", "dlls")
    hash = get_str(entry, "hash", "prefetch_hash") || ""
    file_refs = get_list(entry, "file_references", "files_loaded")

    %{
      executable_name: exe_name,
      executable_path: path,
      execution_count: run_count,
      last_run_time: last_run,
      prefetch_hash: hash,
      loaded_dlls: loaded_dlls,
      file_references: file_refs,
      suspicious_dlls: find_suspicious_dlls(loaded_dlls),
      flags: %{
        from_suspicious_path: in_suspicious_path?(path),
        recently_executed: recently_executed?(last_run),
        is_known_tool: known_suspicious_exe?(exe_name)
      }
    }
  end

  defp parse_prefetch_entry(_), do: %{executable_name: "", execution_count: 0, loaded_dlls: [], suspicious_dlls: [], flags: %{}}

  defp score_prefetch_entry(entry) do
    score = 0

    # Known suspicious tool
    score = if entry.flags[:is_known_tool], do: score + 40, else: score

    # Executed from suspicious path
    score = if entry.flags[:from_suspicious_path], do: score + 20, else: score

    # Suspicious DLL loads
    score = score + min(length(entry.suspicious_dlls) * 15, 30)

    # Low execution count (potential one-off attack tool)
    score = if (entry.execution_count || 0) <= 2, do: score + 10, else: score

    # Recently executed
    score = if entry.flags[:recently_executed], do: score + 5, else: score

    Map.put(entry, :suspiciousness_score, min(score, 100))
  end

  defp build_prefetch_summary(entries) do
    suspicious_count = Enum.count(entries, fn e -> e.suspiciousness_score >= 50 end)
    total = length(entries)

    "Analyzed #{total} prefetch entries. #{suspicious_count} flagged as suspicious."
  end

  # ── Shimcache Analysis ─────────────────────────────────────────────

  defp analyze_shimcache(data) do
    entries = get_list(data, "entries", "shimcache_entries")
    parsed = Enum.map(entries, &parse_shimcache_entry/1)
    scored = Enum.map(parsed, &score_shimcache_entry/1)

    top_suspicious = scored
    |> Enum.sort_by(& &1.suspiciousness_score, :desc)
    |> Enum.take(20)

    # Programs not found on disk (potential deleted attack tools)
    not_found = scored
    |> Enum.filter(fn e -> e.flags[:not_found_on_disk] end)

    # Programs from temp/staging directories
    from_temp = scored
    |> Enum.filter(fn e -> e.flags[:from_suspicious_path] end)

    max_score = if scored != [], do: Enum.max_by(scored, & &1.suspiciousness_score).suspiciousness_score, else: 0

    analysis = %{
      artifact_type: "shimcache",
      total_entries: length(parsed),
      top_suspicious: top_suspicious,
      programs_not_on_disk: not_found,
      programs_from_temp: from_temp,
      suspiciousness_score: max_score,
      summary: "Analyzed #{length(parsed)} shimcache entries. #{length(top_suspicious)} suspicious, #{length(not_found)} not found on disk."
    }

    {:ok, analysis}
  end

  defp parse_shimcache_entry(entry) when is_map(entry) do
    path = get_str(entry, "path", "file_path") || ""
    name = Path.basename(path)
    modified_time = get_str(entry, "last_modified", "modified_time") || ""
    executed = get_bool(entry, "executed", "was_executed")
    size = get_int(entry, "file_size", "size")
    not_found = get_bool(entry, "not_found_on_disk", "deleted")

    %{
      executable_name: name,
      file_path: path,
      last_modified_time: modified_time,
      was_executed: executed,
      file_size: size,
      flags: %{
        not_found_on_disk: not_found,
        from_suspicious_path: in_suspicious_path?(path),
        is_known_tool: known_suspicious_exe?(name)
      }
    }
  end

  defp parse_shimcache_entry(_), do: %{executable_name: "", file_path: "", flags: %{}}

  defp score_shimcache_entry(entry) do
    score = 0

    score = if entry.flags[:is_known_tool], do: score + 45, else: score
    score = if entry.flags[:not_found_on_disk], do: score + 25, else: score
    score = if entry.flags[:from_suspicious_path], do: score + 20, else: score
    score = if entry.was_executed, do: score + 5, else: score

    Map.put(entry, :suspiciousness_score, min(score, 100))
  end

  # ── Amcache Analysis ───────────────────────────────────────────────

  defp analyze_amcache(data) do
    entries = get_list(data, "entries", "amcache_entries")
    parsed = Enum.map(entries, &parse_amcache_entry/1)
    scored = Enum.map(parsed, &score_amcache_entry/1)

    top_suspicious = scored
    |> Enum.sort_by(& &1.suspiciousness_score, :desc)
    |> Enum.take(20)

    # Unsigned programs
    unsigned = scored |> Enum.filter(fn e -> e.flags[:unsigned] end)

    # Programs installed in last 7 days
    recent_installs = scored |> Enum.filter(fn e -> e.flags[:recently_installed] end)

    max_score = if scored != [], do: Enum.max_by(scored, & &1.suspiciousness_score).suspiciousness_score, else: 0

    analysis = %{
      artifact_type: "amcache",
      total_entries: length(parsed),
      top_suspicious: top_suspicious,
      unsigned_programs: unsigned,
      recent_installs: recent_installs,
      suspiciousness_score: max_score,
      summary: "Analyzed #{length(parsed)} amcache entries. #{length(unsigned)} unsigned, #{length(recent_installs)} recently installed."
    }

    {:ok, analysis}
  end

  defp parse_amcache_entry(entry) when is_map(entry) do
    path = get_str(entry, "path", "file_path") || ""
    name = get_str(entry, "name", "product_name") || Path.basename(path)
    sha1 = get_str(entry, "sha1", "hash_sha1") || ""
    publisher = get_str(entry, "publisher", "company_name") || ""
    version = get_str(entry, "version", "file_version") || ""
    install_date = get_str(entry, "install_date", "first_run") || ""
    is_signed = get_bool(entry, "is_signed", "signed")

    %{
      name: name,
      file_path: path,
      sha1: sha1,
      publisher: publisher,
      version: version,
      install_date: install_date,
      is_signed: is_signed,
      flags: %{
        unsigned: !is_signed,
        from_suspicious_path: in_suspicious_path?(path),
        is_known_tool: known_suspicious_exe?(name) or known_suspicious_exe?(Path.basename(path)),
        recently_installed: recently_installed?(install_date),
        no_publisher: publisher == "" or is_nil(publisher)
      }
    }
  end

  defp parse_amcache_entry(_), do: %{name: "", file_path: "", sha1: "", flags: %{}}

  defp score_amcache_entry(entry) do
    score = 0

    score = if entry.flags[:is_known_tool], do: score + 45, else: score
    score = if entry.flags[:unsigned], do: score + 15, else: score
    score = if entry.flags[:from_suspicious_path], do: score + 15, else: score
    score = if entry.flags[:no_publisher], do: score + 10, else: score
    score = if entry.flags[:recently_installed], do: score + 5, else: score

    Map.put(entry, :suspiciousness_score, min(score, 100))
  end

  # ── SRUM Analysis ──────────────────────────────────────────────────

  defp analyze_srum(data) do
    entries = get_list(data, "entries", "srum_entries")
    parsed = Enum.map(entries, &parse_srum_entry/1)
    scored = Enum.map(parsed, &score_srum_entry/1)

    top_suspicious = scored
    |> Enum.sort_by(& &1.suspiciousness_score, :desc)
    |> Enum.take(20)

    # High network usage (potential exfiltration)
    high_network = scored
    |> Enum.filter(fn e -> (e.bytes_sent || 0) > 100_000_000 end)
    |> Enum.sort_by(& &1.bytes_sent, :desc)

    # High CPU usage (potential crypto mining)
    high_cpu = scored
    |> Enum.filter(fn e -> (e.cpu_time_ms || 0) > 600_000 end)
    |> Enum.sort_by(& &1.cpu_time_ms, :desc)

    # Background apps with network activity
    background_network = scored
    |> Enum.filter(fn e -> e.flags[:background_with_network] end)

    max_score = if scored != [], do: Enum.max_by(scored, & &1.suspiciousness_score).suspiciousness_score, else: 0

    analysis = %{
      artifact_type: "srum",
      total_entries: length(parsed),
      top_suspicious: top_suspicious,
      high_network_usage: high_network,
      high_cpu_usage: high_cpu,
      background_network_activity: background_network,
      suspiciousness_score: max_score,
      summary: "Analyzed #{length(parsed)} SRUM entries. #{length(high_network)} with high network, #{length(high_cpu)} with high CPU."
    }

    {:ok, analysis}
  end

  defp parse_srum_entry(entry) when is_map(entry) do
    app = get_str(entry, "application", "app_name") || ""
    user = get_str(entry, "user", "user_sid") || ""
    bytes_sent = get_int(entry, "bytes_sent", "network_bytes_sent") || 0
    bytes_received = get_int(entry, "bytes_received", "network_bytes_received") || 0
    cpu_time = get_int(entry, "cpu_time_ms", "foreground_cpu_time") || 0
    background_cpu = get_int(entry, "background_cpu_time", "background_cpu_ms") || 0
    timestamp = get_str(entry, "timestamp", "time_stamp") || ""
    is_background = get_bool(entry, "is_background", "background")

    %{
      application: app,
      user: user,
      bytes_sent: bytes_sent,
      bytes_received: bytes_received,
      cpu_time_ms: cpu_time,
      background_cpu_ms: background_cpu,
      timestamp: timestamp,
      is_background: is_background,
      flags: %{
        high_network: bytes_sent > 50_000_000 or bytes_received > 50_000_000,
        high_cpu: cpu_time > 600_000,
        background_with_network: is_background and (bytes_sent > 1_000_000 or bytes_received > 1_000_000),
        is_known_tool: known_suspicious_exe?(app),
        from_suspicious_path: in_suspicious_path?(app)
      }
    }
  end

  defp parse_srum_entry(_), do: %{application: "", bytes_sent: 0, bytes_received: 0, cpu_time_ms: 0, flags: %{}}

  defp score_srum_entry(entry) do
    score = 0

    score = if entry.flags[:is_known_tool], do: score + 40, else: score
    score = if entry.flags[:high_network], do: score + 25, else: score
    score = if entry.flags[:high_cpu], do: score + 15, else: score
    score = if entry.flags[:background_with_network], do: score + 20, else: score
    score = if entry.flags[:from_suspicious_path], do: score + 10, else: score

    Map.put(entry, :suspiciousness_score, min(score, 100))
  end

  # ── Event Log Analysis ─────────────────────────────────────────────

  defp analyze_event_log(data) do
    entries = get_list(data, "entries", "events")
    parsed = Enum.map(entries, &parse_event_log_entry/1)

    # Detect notable security events
    security_events = parsed
    |> Enum.filter(fn e -> e.event_id in notable_event_ids() end)

    # Failed logons (4625)
    failed_logons = parsed
    |> Enum.filter(fn e -> e.event_id in [4625, "4625"] end)

    # Account modifications
    account_mods = parsed
    |> Enum.filter(fn e -> e.event_id in [4720, 4722, 4724, 4728, 4732, 4756] end)

    # Audit log cleared (1102)
    log_cleared = parsed
    |> Enum.filter(fn e -> e.event_id in [1102, "1102"] end)

    score = 0
    score = if length(failed_logons) > 10, do: score + 30, else: score
    score = if length(account_mods) > 0, do: score + 20, else: score
    score = if length(log_cleared) > 0, do: score + 40, else: score
    score = if length(security_events) > 20, do: score + 10, else: score

    analysis = %{
      artifact_type: "event_log",
      total_entries: length(parsed),
      notable_security_events: security_events,
      failed_logon_attempts: failed_logons,
      account_modifications: account_mods,
      audit_log_cleared: log_cleared,
      suspiciousness_score: min(score, 100),
      summary: "Analyzed #{length(parsed)} event log entries. #{length(failed_logons)} failed logons, #{length(account_mods)} account modifications."
    }

    {:ok, analysis}
  end

  defp parse_event_log_entry(entry) when is_map(entry) do
    %{
      event_id: get_int(entry, "event_id", "EventID"),
      timestamp: get_str(entry, "timestamp", "TimeCreated") || "",
      source: get_str(entry, "source", "ProviderName") || "",
      level: get_str(entry, "level", "Level") || "",
      message: get_str(entry, "message", "Message") || "",
      user: get_str(entry, "user", "UserName") || "",
      computer: get_str(entry, "computer", "Computer") || "",
      data: entry
    }
  end

  defp parse_event_log_entry(_), do: %{event_id: 0, timestamp: "", source: "", data: %{}}

  defp notable_event_ids do
    [
      # Account logon
      4624, 4625, 4634, 4648, 4672,
      # Account management
      4720, 4722, 4724, 4728, 4732, 4756,
      # Audit policy
      1102, 4719,
      # Process creation
      4688, 4689,
      # Privilege use
      4673, 4674,
      # Object access
      4663, 4656,
      # Service install
      7045,
      # Scheduled task
      4698, 4702
    ]
  end

  # ── Registry Hive Analysis ─────────────────────────────────────────

  defp analyze_registry_hive(data) do
    entries = get_list(data, "entries", "registry_entries")
    parsed = Enum.map(entries, &parse_registry_entry/1)

    # Persistence entries
    persistence = parsed
    |> Enum.filter(fn e -> e.flags[:is_persistence_location] end)

    # Recently modified
    recent = parsed
    |> Enum.filter(fn e -> e.flags[:recently_modified] end)

    score = 0
    score = score + min(length(persistence) * 15, 60)
    score = if length(recent) > 5, do: score + 20, else: score

    analysis = %{
      artifact_type: "registry_hive",
      total_entries: length(parsed),
      persistence_entries: persistence,
      recently_modified: recent,
      suspiciousness_score: min(score, 100),
      summary: "Analyzed #{length(parsed)} registry entries. #{length(persistence)} in persistence locations."
    }

    {:ok, analysis}
  end

  defp parse_registry_entry(entry) when is_map(entry) do
    key = get_str(entry, "key", "key_path") || ""
    value_name = get_str(entry, "value_name", "name") || ""
    value_data = get_str(entry, "value_data", "data") || ""
    modified = get_str(entry, "last_modified", "timestamp") || ""

    %{
      key_path: key,
      value_name: value_name,
      value_data: value_data,
      last_modified: modified,
      flags: %{
        is_persistence_location: is_persistence_path?(key),
        recently_modified: recently_modified?(modified),
        suspicious_value: suspicious_registry_value?(value_data)
      }
    }
  end

  defp parse_registry_entry(_), do: %{key_path: "", value_name: "", flags: %{}}

  # ── Private: Indicator Matching ────────────────────────────────────

  defp known_suspicious_exe?(name) when is_binary(name) do
    name_down = String.downcase(name)
    Enum.any?(@suspicious_executables, fn s -> String.contains?(name_down, s) end)
  end

  defp known_suspicious_exe?(_), do: false

  defp find_suspicious_dlls(dlls) when is_list(dlls) do
    Enum.filter(dlls, fn dll ->
      dll_down = String.downcase(to_string(dll))
      Enum.any?(@suspicious_dlls, fn s -> String.contains?(dll_down, s) end)
    end)
  end

  defp find_suspicious_dlls(_), do: []

  defp in_suspicious_path?(path) when is_binary(path) do
    path_down = String.downcase(path)
    Enum.any?(@suspicious_paths, fn p -> String.contains?(path_down, p) end)
  end

  defp in_suspicious_path?(_), do: false

  defp is_persistence_path?(key) when is_binary(key) do
    key_down = String.downcase(key)
    Enum.any?(@persistence_paths, fn p -> String.contains?(key_down, p) end)
  end

  defp is_persistence_path?(_), do: false

  defp suspicious_registry_value?(value) when is_binary(value) do
    value_down = String.downcase(value)

    # PowerShell encoded commands, suspicious executables
    String.contains?(value_down, "powershell") and String.contains?(value_down, "-enc") or
    String.contains?(value_down, "cmd.exe /c") or
    String.contains?(value_down, "wscript") or
    String.contains?(value_down, "mshta") or
    String.contains?(value_down, "regsvr32") or
    String.contains?(value_down, "certutil -urlcache")
  end

  defp suspicious_registry_value?(_), do: false

  defp recently_executed?(timestamp_str) do
    case parse_datetime(timestamp_str) do
      {:ok, dt} -> DateTime.diff(DateTime.utc_now(), dt, :hour) <= 24
      _ -> false
    end
  end

  defp recently_installed?(timestamp_str) do
    case parse_datetime(timestamp_str) do
      {:ok, dt} -> DateTime.diff(DateTime.utc_now(), dt, :hour) <= 168
      _ -> false
    end
  end

  defp recently_modified?(timestamp_str) do
    case parse_datetime(timestamp_str) do
      {:ok, dt} -> DateTime.diff(DateTime.utc_now(), dt, :hour) <= 48
      _ -> false
    end
  end

  # ── Private: Search Helpers ─────────────────────────────────────────

  defp extract_searchable_values(analysis) when is_map(analysis) do
    analysis
    |> flatten_map([])
    |> Enum.filter(fn {_key, value} -> is_binary(value) and value != "" end)
  end

  defp flatten_map(map, prefix) when is_map(map) do
    Enum.flat_map(map, fn {k, v} ->
      key = prefix ++ [to_string(k)]
      case v do
        v when is_map(v) -> flatten_map(v, key)
        v when is_list(v) ->
          v
          |> Enum.with_index()
          |> Enum.flat_map(fn {item, idx} ->
            if is_map(item) do
              flatten_map(item, key ++ [to_string(idx)])
            else
              [{Enum.join(key ++ [to_string(idx)], "."), item}]
            end
          end)
        _ -> [{Enum.join(key, "."), v}]
      end
    end)
  end

  defp find_matching_fields(searchable, value) do
    value_down = String.downcase(to_string(value))

    searchable
    |> Enum.filter(fn {_field, sv} ->
      sv_down = String.downcase(to_string(sv))
      sv_down == value_down or String.contains?(sv_down, value_down)
    end)
    |> Enum.map(fn {field, _v} -> field end)
  end

  # ── Private: Data Access Helpers ───────────────────────────────────

  defp get_str(map, key1, key2) do
    val = Map.get(map, key1) || Map.get(map, key2)
    val = val || Map.get(map, String.to_atom(key1)) || Map.get(map, String.to_atom(key2))
    if is_binary(val), do: val, else: if(val, do: to_string(val), else: nil)
  rescue
    _ -> nil
  end

  defp get_int(map, key1, key2) do
    val = Map.get(map, key1) || Map.get(map, key2)
    val = val || Map.get(map, String.to_atom(key1)) || Map.get(map, String.to_atom(key2))

    cond do
      is_integer(val) -> val
      is_binary(val) ->
        case Integer.parse(val) do
          {n, _} -> n
          :error -> nil
        end
      is_float(val) -> trunc(val)
      true -> nil
    end
  rescue
    _ -> nil
  end

  defp get_bool(map, key1, key2) do
    val = Map.get(map, key1) || Map.get(map, key2)
    val = val || Map.get(map, String.to_atom(key1)) || Map.get(map, String.to_atom(key2))

    case val do
      true -> true
      "true" -> true
      1 -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp get_list(map, key1, key2) do
    val = Map.get(map, key1) || Map.get(map, key2)
    val = val || Map.get(map, String.to_atom(key1)) || Map.get(map, String.to_atom(key2))

    if is_list(val), do: val, else: []
  rescue
    _ -> []
  end

  defp parse_datetime(nil), do: :error
  defp parse_datetime(""), do: :error
  defp parse_datetime(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> {:ok, dt}
      _ ->
        case NaiveDateTime.from_iso8601(s) do
          {:ok, ndt} -> {:ok, DateTime.from_naive!(ndt, "Etc/UTC")}
          _ -> :error
        end
    end
  end
  defp parse_datetime(_), do: :error
end
