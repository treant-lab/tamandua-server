defmodule TamanduaServer.AI.QueryInterface do
  @moduledoc """
  AI-Powered Query Interface for Threat Hunting

  Allows security analysts to query threat data using natural language.
  This is a UNIQUE FEATURE that transforms how analysts interact with EDR data.

  Features:
  - Natural language to SQL/query translation
  - Threat hunting query suggestions
  - Automated IOC extraction from text
  - Alert summarization
  - Investigation path recommendations
  - MITRE ATT&CK mapping from descriptions

  Examples:
  - "Show me all PowerShell executions from the last 24 hours"
  - "Find processes that connected to external IPs after 6 PM"
  - "Which hosts have suspicious registry modifications?"
  - "Summarize the attack chain for alert abc123"
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  # Query templates for common threat hunting scenarios
  @query_templates %{
    "powershell" => %{
      pattern: ~r/powershell|script|encoded/i,
      query_fn: :query_powershell_activity,
      description: "PowerShell activity analysis"
    },
    "lateral_movement" => %{
      pattern: ~r/lateral|movement|spread|remote|psexec|wmi|smb/i,
      query_fn: :query_lateral_movement,
      description: "Lateral movement detection"
    },
    "persistence" => %{
      pattern: ~r/persist|startup|run\s*key|scheduled\s*task|service/i,
      query_fn: :query_persistence,
      description: "Persistence mechanism detection"
    },
    "credential_theft" => %{
      pattern: ~r/credential|mimikatz|lsass|password|dump|hash/i,
      query_fn: :query_credential_access,
      description: "Credential theft detection"
    },
    "exfiltration" => %{
      pattern: ~r/exfil|data\s*theft|upload|transfer|large\s*file/i,
      query_fn: :query_exfiltration,
      description: "Data exfiltration detection"
    },
    "ransomware" => %{
      pattern: ~r/ransom|encrypt|crypto|locky|wannacry|lockbit/i,
      query_fn: :query_ransomware,
      description: "Ransomware activity detection"
    },
    "c2" => %{
      pattern: ~r/c2|command.*control|beacon|callback|suspicious.*connection/i,
      query_fn: :query_c2_activity,
      description: "Command and control detection"
    }
  }

  # MITRE ATT&CK keyword mapping
  @mitre_keywords %{
    "T1059.001" => ~w(powershell script encoded base64 bypass),
    "T1003" => ~w(mimikatz lsass credential dump password hash),
    "T1486" => ~w(encrypt ransom ransomware crypto lock),
    "T1021" => ~w(psexec wmi remote smb lateral),
    "T1547" => ~w(run registry startup persistence autostart),
    "T1053" => ~w(scheduled task schtasks cron),
    "T1071" => ~w(http https dns c2 beacon callback),
    "T1041" => ~w(exfiltration upload transfer data theft)
  }

  @doc """
  Process a natural language query and return results.
  """
  def process_query(query_text, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    time_range = Keyword.get(opts, :time_range, "24h")

    Logger.info("Processing AI query: #{query_text}")

    # Parse the query intent
    intent = parse_query_intent(query_text)

    # Extract time constraints
    time_constraint = extract_time_constraint(query_text, time_range)

    # Execute appropriate query
    results = execute_query(intent, organization_id, time_constraint)

    # Generate response with explanation
    response = generate_response(query_text, intent, results)

    response
  end

  @doc """
  Get threat hunting query suggestions based on current alerts.
  """
  def get_hunting_suggestions(organization_id) do
    # Get recent alert patterns
    recent_alerts = get_recent_alert_patterns(organization_id)

    # Generate suggestions based on patterns
    suggestions = []

    suggestions = if Enum.any?(recent_alerts, &(&1.type == :powershell)) do
      suggestions ++ [
        %{
          query: "Show all encoded PowerShell commands in the last 48 hours",
          reason: "Recent PowerShell activity detected",
          priority: :high
        }
      ]
    else
      suggestions
    end

    suggestions = if Enum.any?(recent_alerts, &(&1.type == :credential_access)) do
      suggestions ++ [
        %{
          query: "Find all processes that accessed LSASS memory",
          reason: "Potential credential theft activity",
          priority: :critical
        },
        %{
          query: "Show authentication failures followed by successes",
          reason: "Possible credential stuffing",
          priority: :high
        }
      ]
    else
      suggestions
    end

    suggestions = if Enum.any?(recent_alerts, &(&1.type == :network_anomaly)) do
      suggestions ++ [
        %{
          query: "Find processes with unusual network destinations",
          reason: "Potential C2 activity",
          priority: :high
        },
        %{
          query: "Show large data transfers to external IPs",
          reason: "Potential data exfiltration",
          priority: :medium
        }
      ]
    else
      suggestions
    end

    # Add general hunting suggestions
    suggestions ++ [
      %{
        query: "Show newly created services in the last 7 days",
        reason: "Persistence monitoring",
        priority: :medium
      },
      %{
        query: "Find processes spawned by Office applications",
        reason: "Macro/document malware detection",
        priority: :medium
      }
    ]
  end

  @doc """
  Summarize an alert or incident for analyst review.
  """
  def summarize_alert(alert_id) do
    alert = Repo.get!(Alert, alert_id)

    # Get related events
    events = get_alert_events(alert)

    # Build summary
    %{
      alert_id: alert_id,
      title: alert.title,
      severity: alert.severity,
      summary: generate_alert_summary(alert, events),
      timeline: build_event_timeline(events),
      mitre_mapping: map_to_mitre(alert, events),
      recommended_actions: generate_recommendations(alert, events),
      investigation_queries: generate_investigation_queries(alert, events)
    }
  end

  @doc """
  Extract IOCs from free-form text (e.g., threat intel reports).
  """
  def extract_iocs_from_text(text) do
    iocs = %{
      ipv4: extract_ipv4(text),
      ipv6: extract_ipv6(text),
      domains: extract_domains(text),
      urls: extract_urls(text),
      hashes: extract_hashes(text),
      emails: extract_emails(text),
      file_paths: extract_file_paths(text)
    }

    # Filter out common false positives
    iocs
    |> Enum.map(fn {type, values} ->
      {type, filter_false_positives(type, values)}
    end)
    |> Enum.into(%{})
  end

  @doc """
  Map a description or query to MITRE ATT&CK techniques.
  """
  def map_description_to_mitre(text) do
    text_lower = String.downcase(text)

    @mitre_keywords
    |> Enum.filter(fn {_technique, keywords} ->
      Enum.any?(keywords, &String.contains?(text_lower, &1))
    end)
    |> Enum.map(fn {technique, _} -> technique end)
    |> Enum.uniq()
  end

  # ============================================================================
  # Query Intent Parsing
  # ============================================================================

  defp parse_query_intent(query_text) do
    query_lower = String.downcase(query_text)

    # Check against known patterns
    matched_template = @query_templates
    |> Enum.find(fn {_name, template} ->
      Regex.match?(template.pattern, query_lower)
    end)

    case matched_template do
      {name, template} ->
        %{
          type: name,
          query_fn: template.query_fn,
          description: template.description,
          confidence: :high
        }

      nil ->
        # Try to infer intent from keywords
        infer_intent_from_keywords(query_lower)
    end
  end

  defp infer_intent_from_keywords(query_lower) do
    cond do
      String.contains?(query_lower, ["process", "execution", "run"]) ->
        %{type: "process", query_fn: :query_processes, description: "Process activity", confidence: :medium}

      String.contains?(query_lower, ["file", "created", "modified", "deleted"]) ->
        %{type: "file", query_fn: :query_files, description: "File activity", confidence: :medium}

      String.contains?(query_lower, ["network", "connection", "ip", "port"]) ->
        %{type: "network", query_fn: :query_network, description: "Network activity", confidence: :medium}

      String.contains?(query_lower, ["alert", "detection", "threat"]) ->
        %{type: "alerts", query_fn: :query_alerts, description: "Alert search", confidence: :medium}

      true ->
        %{type: "general", query_fn: :query_general, description: "General search", confidence: :low}
    end
  end

  defp extract_time_constraint(query_text, default) do
    query_lower = String.downcase(query_text)

    cond do
      String.contains?(query_lower, "last hour") -> "1h"
      String.contains?(query_lower, "last 24 hours") or String.contains?(query_lower, "today") -> "24h"
      String.contains?(query_lower, "last 48 hours") -> "48h"
      String.contains?(query_lower, "last week") or String.contains?(query_lower, "7 days") -> "7d"
      String.contains?(query_lower, "last month") or String.contains?(query_lower, "30 days") -> "30d"
      true -> default
    end
  end

  # ============================================================================
  # Query Execution
  # ============================================================================

  defp execute_query(intent, organization_id, time_range) do
    time_threshold = calculate_time_threshold(time_range)

    case intent.query_fn do
      :query_powershell_activity -> query_powershell_activity(organization_id, time_threshold)
      :query_lateral_movement -> query_lateral_movement(organization_id, time_threshold)
      :query_persistence -> query_persistence(organization_id, time_threshold)
      :query_credential_access -> query_credential_access(organization_id, time_threshold)
      :query_exfiltration -> query_exfiltration(organization_id, time_threshold)
      :query_ransomware -> query_ransomware(organization_id, time_threshold)
      :query_c2_activity -> query_c2_activity(organization_id, time_threshold)
      :query_processes -> query_processes(organization_id, time_threshold)
      :query_files -> query_files(organization_id, time_threshold)
      :query_network -> query_network(organization_id, time_threshold)
      :query_alerts -> query_alerts(organization_id, time_threshold)
      _ -> query_general(organization_id, time_threshold)
    end
  end

  defp calculate_time_threshold(time_range) do
    now = DateTime.utc_now()

    seconds = case time_range do
      "1h" -> 3600
      "24h" -> 86400
      "48h" -> 172800
      "7d" -> 604800
      "30d" -> 2592000
      _ -> 86400
    end

    DateTime.add(now, -seconds, :second)
  end

  # Specific query implementations
  defp query_powershell_activity(organization_id, time_threshold) do
    # Query events table for PowerShell activity
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND (
        e.payload->>'name' ILIKE '%powershell%'
        OR e.payload->>'command_line' ILIKE '%-enc%'
        OR e.payload->>'command_line' ILIKE '%encodedcommand%'
        OR e.payload->>'command_line' ILIKE '%bypass%'
      )
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_lateral_movement(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND (
        e.payload->>'name' ILIKE '%psexec%'
        OR e.payload->>'name' ILIKE '%wmic%'
        OR e.payload->>'name' ILIKE '%winrm%'
        OR (e.event_type = 'network' AND e.payload->>'remote_port' IN ('445', '5985', '5986', '135'))
      )
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_persistence(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND (
        e.event_type = 'registry'
        AND (
          e.payload->>'key_path' ILIKE '%\\Run%'
          OR e.payload->>'key_path' ILIKE '%\\RunOnce%'
          OR e.payload->>'key_path' ILIKE '%\\Services%'
          OR e.payload->>'key_path' ILIKE '%Winlogon%'
        )
      )
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_credential_access(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND (
        e.payload->>'name' ILIKE '%mimikatz%'
        OR e.payload->>'name' ILIKE '%procdump%'
        OR e.payload->>'target_process' ILIKE '%lsass%'
        OR (e.event_type = 'registry' AND e.payload->>'key_path' ILIKE '%SAM%')
        OR (e.event_type = 'registry' AND e.payload->>'key_path' ILIKE '%SECURITY%')
      )
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_exfiltration(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type = 'network'
      AND (e.payload->>'bytes_sent')::bigint > 10000000
    ORDER BY (e.payload->>'bytes_sent')::bigint DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_ransomware(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND (
        e.payload->>'path' SIMILAR TO '%.encrypted|%.locked|%.crypt|%.locky%'
        OR e.payload->>'name' ILIKE '%vssadmin%'
        OR e.payload->>'command_line' ILIKE '%delete shadows%'
      )
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_c2_activity(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type = 'network'
      AND e.payload->>'remote_port' IN ('443', '8443', '4444', '8080', '53')
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_processes(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type IN ('process', 'process_create')
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_files(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type IN ('file', 'file_create', 'file_modify', 'file_delete')
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_network(organization_id, time_threshold) do
    query = """
    SELECT e.*, a.hostname
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type IN ('network', 'network_connection', 'dns')
    ORDER BY e.timestamp DESC
    LIMIT 100
    """

    execute_raw_query(query, [organization_id, time_threshold])
  end

  defp query_alerts(organization_id, time_threshold) do
    base_query = from(a in Alert,
      where: a.inserted_at >= ^time_threshold,
      order_by: [desc: a.inserted_at],
      limit: 100
    )

    query = if organization_id do
      from(a in base_query, where: a.organization_id == ^organization_id)
    else
      base_query
    end

    query
    |> Repo.all()
    |> Enum.map(&Map.from_struct/1)
  end

  defp query_general(organization_id, time_threshold) do
    query_alerts(organization_id, time_threshold)
  end

  defp execute_raw_query(query, params) do
    case Repo.query(query, normalize_raw_query_params(params)) do
      {:ok, result} ->
        columns = Enum.map(result.columns, &String.to_atom/1)
        Enum.map(result.rows, fn row ->
          Enum.zip(columns, row) |> Enum.into(%{})
        end)

      {:error, reason} ->
        Logger.warning("AI raw query failed: #{inspect(reason)}")
        []
    end
  rescue
    error ->
      Logger.warning("AI raw query crashed: #{Exception.message(error)}")
      []
  end

  defp normalize_raw_query_params(params) when is_list(params) do
    Enum.map(params, &normalize_raw_query_param/1)
  end

  defp normalize_raw_query_param(value) when is_binary(value) do
    case Ecto.UUID.dump(value) do
      {:ok, dumped} -> dumped
      :error -> value
    end
  end

  defp normalize_raw_query_param(value), do: value

  # ============================================================================
  # Response Generation
  # ============================================================================

  defp generate_response(query_text, intent, results) do
    result_count = length(results)

    %{
      query: query_text,
      intent: intent,
      result_count: result_count,
      results: results,
      summary: generate_result_summary(intent, results),
      follow_up_queries: suggest_follow_up_queries(intent, results),
      export_options: ["csv", "json", "pdf"]
    }
  end

  defp generate_result_summary(intent, results) do
    count = length(results)

    case intent.type do
      "powershell" ->
        encoded_count = Enum.count(results, fn r ->
          cmd = r[:command_line] || r["command_line"] || ""
          String.contains?(String.downcase(cmd), "-enc")
        end)
        "Found #{count} PowerShell events. #{encoded_count} contain encoded commands."

      "credential_theft" ->
        "Found #{count} potential credential access events. Review for Mimikatz or LSASS access."

      "ransomware" ->
        "Found #{count} potential ransomware indicators. Immediate investigation recommended."

      _ ->
        "Found #{count} matching events."
    end
  end

  defp suggest_follow_up_queries(intent, results) do
    base_suggestions = case intent.type do
      "powershell" ->
        [
          "Show parent processes of these PowerShell executions",
          "Find network connections from these PowerShell processes",
          "Show file operations by these processes"
        ]

      "credential_theft" ->
        [
          "Show authentication events after credential access",
          "Find lateral movement from affected hosts",
          "Show processes spawned by the accessing process"
        ]

      "ransomware" ->
        [
          "Show all file modifications on affected hosts",
          "Find processes that deleted shadow copies",
          "Show network connections before encryption started"
        ]

      _ ->
        ["Narrow search by time range", "Filter by specific host", "Add severity filter"]
    end

    # Add host-specific suggestions if results exist
    if length(results) > 0 do
      hosts = results
      |> Enum.map(fn r -> r[:hostname] || r["hostname"] end)
      |> Enum.filter(& &1)
      |> Enum.uniq()
      |> Enum.take(3)

      host_suggestions = Enum.map(hosts, fn host ->
        "Show all activity on host #{host}"
      end)

      base_suggestions ++ host_suggestions
    else
      base_suggestions
    end
  end

  # ============================================================================
  # IOC Extraction
  # ============================================================================

  # Known valid TLDs for domain validation (subset of most common)
  @valid_tlds ~w(com net org edu gov mil int io co uk us de fr jp cn ru br au ca
    in it nl es se no fi dk be at ch cz pl pt hu ro bg hr sk si lt lv ee
    info biz name pro aero coop museum jobs travel mobi cat asia tel
    xyz online site store app dev cloud tech cyber security digital
    link click top pw cc me tv fm ly ai)

  defp extract_ipv4(text) do
    # Proper IPv4 with octet validation (0-255)
    Regex.scan(~r/\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/, text)
    |> List.flatten()
    |> Enum.uniq()
  end

  defp extract_ipv6(text) do
    # Handle full, abbreviated, and mixed IPv6 forms
    full_ipv6 = Regex.scan(~r/\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/, text) |> List.flatten()

    # Abbreviated IPv6 with :: (e.g., 2001:db8::1, ::1, fe80::1%eth0)
    abbreviated_ipv6 = Regex.scan(~r/\b(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}\b/, text) |> List.flatten()

    # :: prefix forms (e.g., ::ffff:192.0.2.1, ::1)
    prefix_ipv6 = Regex.scan(~r/::(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4}\b/, text) |> List.flatten()

    # Double-colon in middle (e.g., 2001:db8::8a2e:370:7334)
    middle_ipv6 = Regex.scan(~r/\b[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*::(?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{1,4}\b/, text) |> List.flatten()

    (full_ipv6 ++ abbreviated_ipv6 ++ prefix_ipv6 ++ middle_ipv6)
    |> Enum.filter(&valid_ipv6?/1)
    |> Enum.uniq()
  end

  defp valid_ipv6?(addr) do
    case :inet.parse_address(String.to_charlist(addr)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp extract_domains(text) do
    Regex.scan(~r/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,})\b/, text)
    |> Enum.map(&List.first/1)
    |> Enum.filter(fn domain ->
      # Validate TLD and reject version-number-like strings (e.g., 1.2.3)
      parts = String.split(domain, ".")
      tld = List.last(parts) |> String.downcase()

      # TLD must be valid and domain must have at least one non-numeric label
      tld in @valid_tlds and
        Enum.any?(parts, fn part -> not Regex.match?(~r/^\d+$/, part) end) and
        # Reject patterns that look like version numbers (e.g., v1.2.3, 2.0.1)
        not Regex.match?(~r/^v?\d+\.\d+/, domain)
    end)
    |> Enum.uniq()
  end

  defp extract_urls(text) do
    # Handle various schemes: http, https, ftp, ftps
    Regex.scan(~r/(?:https?|ftps?):\/\/[^\s<>"{}|\\^`\[\]]+/, text)
    |> List.flatten()
    # Strip trailing punctuation that may be part of surrounding text
    |> Enum.map(fn url ->
      url
      |> String.replace(~r/[.,;:!?\)]+$/, "")
      |> String.replace(~r/\]+$/, "")
    end)
    |> Enum.filter(&(String.length(&1) > 10))
    |> Enum.uniq()
  end

  defp extract_hashes(text) do
    # Exact length matching with word boundaries to avoid partial matches
    # MD5: exactly 32 hex chars (exclude if it's actually part of a longer hex string)
    md5 = Regex.scan(~r/\b[a-fA-F0-9]{32}\b/, text)
      |> List.flatten()
      |> Enum.reject(fn h -> String.length(h) != 32 end)

    # SHA1: exactly 40 hex chars
    sha1 = Regex.scan(~r/\b[a-fA-F0-9]{40}\b/, text)
      |> List.flatten()
      |> Enum.reject(fn h -> String.length(h) != 40 end)

    # SHA256: exactly 64 hex chars
    sha256 = Regex.scan(~r/\b[a-fA-F0-9]{64}\b/, text)
      |> List.flatten()
      |> Enum.reject(fn h -> String.length(h) != 64 end)

    # Remove MD5 matches that are substrings of SHA1 matches, and
    # SHA1 matches that are substrings of SHA256 matches
    md5 = md5 -- (sha1 ++ sha256 |> Enum.flat_map(fn h -> for i <- 0..(String.length(h) - 32), do: String.slice(h, i, 32) end))
    sha1 = sha1 -- (sha256 |> Enum.flat_map(fn h -> for i <- 0..(String.length(h) - 40), do: String.slice(h, i, 40) end))

    %{md5: Enum.uniq(md5), sha1: Enum.uniq(sha1), sha256: Enum.uniq(sha256)}
  end

  defp extract_emails(text) do
    Regex.scan(~r/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, text)
    |> List.flatten()
    |> Enum.uniq()
  end

  defp extract_file_paths(text) do
    # Windows paths like C:\Windows\System32
    windows = Regex.scan(~r/[A-Za-z]:[\\\/][^\s:*?"<>|]+/, text)
    # Unix paths like /usr/bin/bash (must start with / followed by a word char)
    unix = Regex.scan(~r/\/[a-zA-Z][^\s:*?"<>|]*/, text)

    (List.flatten(windows) ++ List.flatten(unix))
    |> Enum.filter(&(String.length(&1) > 3))
    |> Enum.uniq()
  end

  defp filter_false_positives(type, values) do
    case type do
      :ipv4 ->
        Enum.reject(values, fn ip ->
          # Filter out private/reserved IPs (RFC 1918, loopback, link-local, etc.)
          String.starts_with?(ip, "10.") or
          String.starts_with?(ip, "192.168.") or
          String.starts_with?(ip, "127.") or
          String.starts_with?(ip, "0.") or
          String.starts_with?(ip, "169.254.") or
          String.starts_with?(ip, "255.") or
          ip == "0.0.0.0" or
          # 172.16.0.0/12 private range
          is_private_172?(ip)
        end)

      :domains ->
        Enum.reject(values, fn domain ->
          domain_lower = String.downcase(domain)
          # Filter out common benign/internal domains
          String.ends_with?(domain_lower, ".local") or
          String.ends_with?(domain_lower, ".internal") or
          String.ends_with?(domain_lower, ".localhost") or
          String.ends_with?(domain_lower, ".test") or
          String.ends_with?(domain_lower, ".example") or
          String.ends_with?(domain_lower, ".invalid") or
          domain_lower in ["example.com", "example.org", "example.net", "localhost"] or
          # Reject pure numeric domains (likely version numbers or IPs)
          Regex.match?(~r/^\d+\.\d+/, domain_lower)
        end)

      :hashes ->
        # For hash maps, filter each sub-list
        case values do
          %{md5: md5, sha1: sha1, sha256: sha256} ->
            %{
              md5: Enum.reject(md5, &trivial_hash?/1),
              sha1: Enum.reject(sha1, &trivial_hash?/1),
              sha256: Enum.reject(sha256, &trivial_hash?/1)
            }
          _ -> values
        end

      _ -> values
    end
  end

  # Check if IP is in the 172.16.0.0/12 private range (172.16.x.x - 172.31.x.x)
  defp is_private_172?(ip) do
    case String.split(ip, ".") do
      ["172", second | _] ->
        case Integer.parse(second) do
          {n, ""} when n >= 16 and n <= 31 -> true
          _ -> false
        end
      _ -> false
    end
  end

  # Reject trivially generated hashes (all zeros, all f's, etc.)
  defp trivial_hash?(hash) do
    hash_lower = String.downcase(hash)
    String.match?(hash_lower, ~r/^(.)\1+$/) or
    hash_lower == String.duplicate("0", String.length(hash))
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_recent_alert_patterns(organization_id) do
    # Get alerts from last 24 hours and categorize
    threshold = DateTime.add(DateTime.utc_now(), -86400, :second)

    base_query = from(a in Alert,
      where: a.inserted_at >= ^threshold
    )

    query = if organization_id do
      from(a in base_query, where: a.organization_id == ^organization_id)
    else
      base_query
    end

    alerts = query
    |> Repo.all()

    Enum.map(alerts, fn alert ->
      type = cond do
        Enum.any?(alert.mitre_techniques || [], &String.starts_with?(&1, "T1059")) -> :powershell
        Enum.any?(alert.mitre_techniques || [], &String.starts_with?(&1, "T1003")) -> :credential_access
        Enum.any?(alert.mitre_techniques || [], &String.starts_with?(&1, "T1071")) -> :network_anomaly
        true -> :other
      end

      %{type: type, alert: alert}
    end)
  end

  defp get_alert_events(%Alert{event_ids: event_ids}) when is_list(event_ids) and length(event_ids) > 0 do
    query = "SELECT * FROM events WHERE id = ANY($1) ORDER BY timestamp"
    case Repo.query(query, [event_ids]) do
      {:ok, result} ->
        columns = Enum.map(result.columns, &String.to_atom/1)
        Enum.map(result.rows, fn row ->
          Enum.zip(columns, row) |> Enum.into(%{})
        end)
      {:error, _} -> []
    end
  end
  defp get_alert_events(_), do: []

  defp generate_alert_summary(alert, events) do
    event_count = length(events)
    techniques = alert.mitre_techniques || []

    """
    Alert: #{alert.title}
    Severity: #{alert.severity}
    Events: #{event_count} related events
    MITRE Techniques: #{Enum.join(techniques, ", ")}
    Status: #{alert.status}
    """
  end

  defp build_event_timeline(events) do
    Enum.map(events, fn event ->
      %{
        timestamp: event[:timestamp],
        type: event[:event_type],
        summary: summarize_event(event)
      }
    end)
  end

  defp summarize_event(event) do
    case event[:event_type] do
      type when type in ["process", "process_create"] ->
        name = event[:payload]["name"] || "unknown"
        "Process: #{name}"

      "network" ->
        ip = event[:payload]["remote_ip"] || "unknown"
        "Network connection to #{ip}"

      "file" ->
        path = event[:payload]["path"] || "unknown"
        "File: #{path}"

      _ ->
        "#{event[:event_type]} event"
    end
  end

  defp map_to_mitre(alert, _events) do
    %{
      tactics: alert.mitre_tactics || [],
      techniques: alert.mitre_techniques || []
    }
  end

  defp generate_recommendations(alert, _events) do
    case alert.severity do
      "critical" ->
        [
          "Isolate affected hosts immediately",
          "Collect forensic evidence",
          "Notify incident response team",
          "Check for lateral movement"
        ]

      "high" ->
        [
          "Investigate the alert promptly",
          "Check related hosts for similar activity",
          "Review user account access"
        ]

      _ ->
        [
          "Review and triage the alert",
          "Check for additional context"
        ]
    end
  end

  defp generate_investigation_queries(alert, _events) do
    techniques = alert.mitre_techniques || []

    base_queries = [
      "Show all activity from affected host",
      "Find related alerts in the last 24 hours"
    ]

    technique_queries = Enum.flat_map(techniques, fn tech ->
      case tech do
        t when t in ["T1059", "T1059.001"] ->
          ["Show all PowerShell executions on this host"]

        t when t in ["T1003", "T1003.001"] ->
          ["Find processes accessing LSASS", "Show credential-related events"]

        _ -> []
      end
    end)

    base_queries ++ technique_queries
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Process a natural language query (alias for process_query/2).
  """
  def query(query_text, opts \\ []) do
    process_query(query_text, opts)
  end

  @doc """
  Explain a detection/alert in natural language.
  """
  def explain_detection(alert_id, opts \\ []) do
    try do
      with {:ok, alert} <- load_scoped_alert(alert_id, opts) do
        explanation = %{
          summary: "Alert: #{alert.title || alert.id}",
          severity: alert.severity,
          mitre_techniques: alert.mitre_techniques || [],
          description: generate_alert_explanation(alert),
          recommended_actions: generate_recommended_actions(alert, []),
          investigation_queries: generate_investigation_queries(alert, [])
        }

        {:ok, explanation}
      end
    rescue
      Ecto.NoResultsError ->
        Logger.warning("[QueryInterface] explain_detection: alert #{alert_id} not found")
        {:error, :not_found}

      Ecto.Query.CastError ->
        {:error, :not_found}
    end
  end

  @doc """
  Extract IOCs from natural language text or alert description.
  """
  def extract_iocs(text, opts \\ []) do
    include_private_ips = Keyword.get(opts, :include_private_ips, false)

    # Reuse the robust private extraction helpers
    raw_iocs = extract_iocs_from_text(text)

    ip_addresses = if include_private_ips do
      raw_iocs.ipv4
    else
      filter_false_positives(:ipv4, raw_iocs.ipv4)
    end

    hashes = raw_iocs.hashes
    hashes_md5 = if is_map(hashes), do: Map.get(hashes, :md5, []), else: []
    hashes_sha1 = if is_map(hashes), do: Map.get(hashes, :sha1, []), else: []
    hashes_sha256 = if is_map(hashes), do: Map.get(hashes, :sha256, []), else: []

    iocs = %{
      ip_addresses: ip_addresses,
      ipv6_addresses: raw_iocs.ipv6,
      domains: filter_false_positives(:domains, raw_iocs.domains),
      urls: raw_iocs.urls,
      hashes_md5: hashes_md5,
      hashes_sha1: hashes_sha1,
      hashes_sha256: hashes_sha256,
      emails: raw_iocs.emails,
      file_paths: raw_iocs.file_paths
    }

    {:ok, iocs}
  end

  @doc """
  Generate a hunt query from natural language description.
  """
  def generate_hunt_query(description, opts \\ []) do
    intent = parse_query_intent(description)
    time_range = Keyword.get(opts, :time_range, "24h")

    query = %{
      intent: intent,
      suggested_query: description,
      time_range: time_range,
      filters: extract_entities_from_query(description),
      mitre_techniques: map_to_mitre_techniques(description)
    }
    {:ok, query}
  end

  @doc """
  Suggest actions based on an alert or detection.
  """
  def suggest_actions(alert_id, opts \\ []) do
    try do
      with {:ok, alert} <- load_scoped_alert(alert_id, opts) do
        actions = generate_recommended_actions(alert, [])
        {:ok, %{alert_id: alert_id, suggested_actions: actions}}
      end
    rescue
      Ecto.NoResultsError ->
        Logger.warning("[QueryInterface] suggest_actions: alert #{alert_id} not found")
        {:error, :not_found}

      Ecto.Query.CastError ->
        {:error, :not_found}
    end
  end

  defp load_scoped_alert(alert_id, opts) do
    case Keyword.get(opts, :organization_id) do
      org_id when is_binary(org_id) and org_id != "" ->
        TamanduaServer.Alerts.get_alert_for_org(org_id, alert_id)

      _ ->
        {:error, :missing_tenant_context}
    end
  end

  defp extract_entities_from_query(query_text) do
    %{
      ip_addresses: Regex.scan(~r/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/, query_text) |> List.flatten(),
      processes: Regex.scan(~r/\b\w+\.exe\b/i, query_text) |> List.flatten()
    }
  end

  defp generate_alert_explanation(alert) do
    detector = alert.title || get_in(alert.detection_metadata || %{}, ["rule_name"]) || alert.id || "unknown"

    "Detection triggered by '#{detector}'. " <>
    "This alert indicates potential #{severity_description(alert.severity)} activity that requires investigation."
  end

  defp severity_description("critical"), do: "critical threat"
  defp severity_description("high"), do: "high-risk"
  defp severity_description("medium"), do: "suspicious"
  defp severity_description(_), do: "potentially malicious"

  defp generate_recommended_actions(alert, _opts) do
    # Generate recommended actions based on alert severity and type
    base_actions = [
      %{
        action: "investigate",
        description: "Review the alert details and associated events",
        priority: :high
      },
      %{
        action: "verify",
        description: "Verify if this activity is legitimate business behavior",
        priority: :medium
      }
    ]

    severity_actions = case alert_severity(alert) do
      s when s in ["critical", :critical] ->
        [%{action: "isolate", description: "Consider isolating the affected system", priority: :critical} | base_actions]
      s when s in ["high", :high] ->
        [%{action: "contain", description: "Prepare containment measures", priority: :high} | base_actions]
      _ ->
        base_actions
    end

    severity_actions
  end

  defp alert_severity(%{severity: severity}), do: severity
  defp alert_severity(alert) when is_map(alert), do: alert[:severity] || alert["severity"]
  defp alert_severity(_), do: nil

  defp map_to_mitre_techniques(description) do
    # Map description keywords to potential MITRE techniques
    technique_patterns = %{
      "powershell" => ["T1059.001"],
      "cmd" => ["T1059.003"],
      "process injection" => ["T1055"],
      "credential" => ["T1003"],
      "lateral movement" => ["T1021"],
      "persistence" => ["T1547", "T1053"],
      "exfiltration" => ["T1041"],
      "network" => ["T1071"],
      "file" => ["T1083"],
      "registry" => ["T1112"]
    }

    description_lower = String.downcase(description || "")

    technique_patterns
    |> Enum.flat_map(fn {pattern, techniques} ->
      if String.contains?(description_lower, pattern) do
        techniques
      else
        []
      end
    end)
    |> Enum.uniq()
  end
end
