defmodule TamanduaServer.Detection.BaselinePatterns do
  @moduledoc """
  Pattern storage and matching for baseline learning.

  Handles recording and matching of:
  - Process patterns (name, parent, command line patterns)
  - Network patterns (destination IP/port, protocol)
  - File patterns (path patterns, access types)
  - Schedule patterns (time of day activity)

  Patterns are stored in PostgreSQL with a pattern_hash for uniqueness.
  Matching uses fuzzy logic with confidence scoring.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.Baseline.Pattern

  # Minimum occurrences before a pattern is considered "common"
  @common_threshold 10

  # ============================================================================
  # Process Patterns
  # ============================================================================

  @doc """
  Record a process pattern from a telemetry event.
  """
  def record_process(agent_id, process_info) when is_map(process_info) do
    # Normalize the process info into a pattern
    pattern = normalize_process_pattern(process_info)

    upsert_pattern(agent_id, "process", pattern)
  end

  @doc """
  Match a process against learned patterns for this agent.
  Returns {:match, score} if pattern exists, :no_match otherwise.
  """
  def match_process(agent_id, process_info) when is_map(process_info) do
    pattern = normalize_process_pattern(process_info)
    match_pattern(agent_id, "process", pattern)
  end

  defp normalize_process_pattern(info) do
    name = get_string(info, :name) || get_string(info, "name") || ""
    parent = get_string(info, :parent_name) || get_string(info, "parent_name")
    cmdline = get_string(info, :command_line) || get_string(info, "command_line")

    # Normalize command line by removing variable parts (PIDs, timestamps, paths with UUIDs)
    normalized_cmdline = if cmdline, do: normalize_cmdline(cmdline), else: nil

    %{
      "name" => String.downcase(name),
      "parent_name" => parent && String.downcase(parent),
      "cmdline_pattern" => normalized_cmdline
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_cmdline(cmdline) do
    cmdline
    |> String.downcase()
    # Remove GUIDs/UUIDs
    |> String.replace(~r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, "<uuid>")
    # Remove numeric PIDs
    |> String.replace(~r/\b\d{4,}\b/, "<num>")
    # Remove file paths with temp directories
    |> String.replace(~r/\\temp\\[^\s]+/i, "\\temp\\<temp>")
    |> String.replace(~r/\/tmp\/[^\s]+/i, "/tmp/<temp>")
    # Truncate to reasonable length
    |> String.slice(0, 200)
    |> String.trim()
  end

  # ============================================================================
  # Network Patterns
  # ============================================================================

  @doc """
  Record a network connection pattern.
  """
  def record_network(agent_id, connection_info) when is_map(connection_info) do
    pattern = normalize_network_pattern(connection_info)
    upsert_pattern(agent_id, "network", pattern)
  end

  @doc """
  Match a network connection against learned patterns.
  """
  def match_network(agent_id, connection_info) when is_map(connection_info) do
    pattern = normalize_network_pattern(connection_info)
    match_pattern(agent_id, "network", pattern)
  end

  defp normalize_network_pattern(info) do
    remote_ip = get_string(info, :remote_ip) || get_string(info, "remote_ip")
    remote_port = info[:remote_port] || info["remote_port"]
    protocol = get_string(info, :protocol) || get_string(info, "protocol")
    process_name = get_string(info, :process_name) || get_string(info, "process_name")

    # For common ports, we track process + port
    # For uncommon ports, we track full destination
    pattern = %{
      "process_name" => process_name && String.downcase(process_name),
      "remote_port" => remote_port,
      "protocol" => protocol && String.downcase(protocol)
    }

    # Add IP for non-common ports or specific destinations
    pattern = if remote_port in [80, 443, 53] do
      pattern
    else
      Map.put(pattern, "remote_ip", remote_ip)
    end

    pattern
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  # ============================================================================
  # File Access Patterns
  # ============================================================================

  @doc """
  Record a file access pattern.
  """
  def record_file_access(agent_id, file_info) when is_map(file_info) do
    pattern = normalize_file_pattern(file_info)
    upsert_pattern(agent_id, "file", pattern)
  end

  @doc """
  Match a file access against learned patterns.
  """
  def match_file_access(agent_id, file_info) when is_map(file_info) do
    pattern = normalize_file_pattern(file_info)
    match_pattern(agent_id, "file", pattern)
  end

  defp normalize_file_pattern(info) do
    path = get_string(info, :path) || get_string(info, "path") || ""
    process_name = get_string(info, :process_name) || get_string(info, "process_name")
    operation = get_string(info, :operation) || get_string(info, "operation")

    # Normalize path to a pattern (remove variable parts like usernames, timestamps)
    normalized_path = normalize_path_pattern(path)

    %{
      "path_pattern" => normalized_path,
      "process_name" => process_name && String.downcase(process_name),
      "operation" => operation && String.downcase(operation)
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_path_pattern(path) do
    path
    |> String.downcase()
    # Replace user-specific paths
    |> String.replace(~r/\\users\\[^\\]+/i, "\\users\\<user>")
    |> String.replace(~r/\/home\/[^\/]+/i, "/home/<user>")
    # Replace timestamps in filenames
    |> String.replace(~r/\d{4}[-_]\d{2}[-_]\d{2}/, "<date>")
    |> String.replace(~r/\d{6,}/, "<num>")
    # Replace GUIDs
    |> String.replace(~r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, "<uuid>")
    # Truncate
    |> String.slice(0, 200)
  end

  # ============================================================================
  # Schedule/Time Patterns
  # ============================================================================

  @doc """
  Record activity time pattern (hour of day).
  """
  def record_schedule(agent_id, schedule_info) when is_map(schedule_info) do
    pattern = normalize_schedule_pattern(schedule_info)
    upsert_pattern(agent_id, "schedule", pattern)
  end

  @doc """
  Match activity time against learned patterns.
  """
  def match_schedule(agent_id, schedule_info) when is_map(schedule_info) do
    pattern = normalize_schedule_pattern(schedule_info)
    match_pattern(agent_id, "schedule", pattern)
  end

  defp normalize_schedule_pattern(info) do
    timestamp = info[:timestamp] || info["timestamp"] || DateTime.utc_now()

    dt = case timestamp do
      %DateTime{} = dt -> dt
      ts when is_integer(ts) ->
        case DateTime.from_unix(ts, :millisecond) do
          {:ok, dt} -> dt
          _ -> DateTime.utc_now()
        end
      _ -> DateTime.utc_now()
    end

    %{
      "hour_of_day" => dt.hour,
      "day_of_week" => Date.day_of_week(DateTime.to_date(dt))
    }
  end

  # ============================================================================
  # Common/Rare Pattern Queries
  # ============================================================================

  @doc """
  Get patterns that are common (seen more than threshold times).
  """
  def get_common_patterns(agent_id, opts \\ []) do
    baseline_type = opts[:type]
    threshold = opts[:threshold] || @common_threshold

    query = from(p in Pattern,
      where: p.agent_id == ^agent_id,
      where: p.occurrence_count >= ^threshold,
      order_by: [desc: p.occurrence_count],
      limit: 100
    )

    query = if baseline_type do
      from(p in query, where: p.baseline_type == ^baseline_type)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get patterns that are rare (seen only a few times).
  """
  def get_rare_patterns(agent_id, opts \\ []) do
    baseline_type = opts[:type]
    threshold = opts[:threshold] || 3

    query = from(p in Pattern,
      where: p.agent_id == ^agent_id,
      where: p.occurrence_count < ^threshold,
      order_by: [asc: p.occurrence_count],
      limit: 100
    )

    query = if baseline_type do
      from(p in query, where: p.baseline_type == ^baseline_type)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get all patterns for an agent.
  """
  def list_patterns(agent_id, opts \\ []) do
    baseline_type = opts[:type]
    limit = opts[:limit] || 500

    query = from(p in Pattern,
      where: p.agent_id == ^agent_id,
      order_by: [desc: p.occurrence_count],
      limit: ^limit
    )

    query = if baseline_type do
      from(p in query, where: p.baseline_type == ^baseline_type)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get pattern statistics for an agent.
  """
  def get_pattern_stats(agent_id) do
    query = from(p in Pattern,
      where: p.agent_id == ^agent_id,
      group_by: p.baseline_type,
      select: {
        p.baseline_type,
        count(p.id),
        sum(p.occurrence_count),
        avg(p.occurrence_count)
      }
    )

    Repo.all(query)
    |> Enum.map(fn {type, count, total_occurrences, avg_occurrences} ->
      %{
        type: type,
        pattern_count: count,
        total_occurrences: total_occurrences || 0,
        avg_occurrences: avg_occurrences && Decimal.to_float(avg_occurrences) || 0.0
      }
    end)
  end

  # ============================================================================
  # Internal Functions
  # ============================================================================

  defp upsert_pattern(agent_id, baseline_type, pattern) when map_size(pattern) > 0 do
    now = DateTime.utc_now()
    pattern_hash = Pattern.pattern_hash(pattern)

    # Try to find existing pattern
    existing = Repo.one(from p in Pattern,
      where: p.agent_id == ^agent_id,
      where: p.baseline_type == ^baseline_type,
      where: fragment("md5(pattern::text) = ?", ^pattern_hash)
    )

    case existing do
      nil ->
        # Insert new pattern
        %Pattern{}
        |> Pattern.changeset(%{
          agent_id: agent_id,
          baseline_type: baseline_type,
          pattern: pattern,
          occurrence_count: 1,
          first_seen: now,
          last_seen: now,
          confidence_weight: 1.0
        })
        |> Repo.insert()

      %Pattern{} = existing ->
        # Update existing pattern
        existing
        |> Pattern.changeset(%{
          occurrence_count: existing.occurrence_count + 1,
          last_seen: now,
          # Increase confidence weight based on recency and frequency
          confidence_weight: calculate_confidence_weight(existing, now)
        })
        |> Repo.update()
    end
  rescue
    e ->
      Logger.warning("Failed to upsert baseline pattern: #{inspect(e)}")
      {:error, e}
  end

  defp upsert_pattern(_agent_id, _baseline_type, _pattern), do: {:ok, nil}

  defp match_pattern(agent_id, baseline_type, pattern) when map_size(pattern) > 0 do
    pattern_hash = Pattern.pattern_hash(pattern)

    # First try exact match
    case Repo.one(from p in Pattern,
      where: p.agent_id == ^agent_id,
      where: p.baseline_type == ^baseline_type,
      where: fragment("md5(pattern::text) = ?", ^pattern_hash)
    ) do
      %Pattern{} = p ->
        score = calculate_match_score(p)
        {:match, score}

      nil ->
        # Try fuzzy match for process patterns
        if baseline_type == "process" do
          fuzzy_match_process(agent_id, pattern)
        else
          :no_match
        end
    end
  end

  defp match_pattern(_agent_id, _baseline_type, _pattern), do: :no_match

  defp fuzzy_match_process(agent_id, pattern) do
    process_name = pattern["name"]

    if process_name do
      # Look for patterns with the same process name
      matches = Repo.all(from p in Pattern,
        where: p.agent_id == ^agent_id,
        where: p.baseline_type == "process",
        where: fragment("pattern->>'name' = ?", ^process_name),
        order_by: [desc: p.occurrence_count],
        limit: 10
      )

      if Enum.empty?(matches) do
        :no_match
      else
        # Calculate partial match score based on similarity
        best_match = Enum.max_by(matches, fn m ->
          pattern_similarity(pattern, m.pattern)
        end)

        similarity = pattern_similarity(pattern, best_match.pattern)

        if similarity >= 0.5 do
          score = calculate_match_score(best_match) * similarity
          {:match, score}
        else
          :no_match
        end
      end
    else
      :no_match
    end
  end

  defp pattern_similarity(pattern1, pattern2) do
    keys = MapSet.union(
      MapSet.new(Map.keys(pattern1)),
      MapSet.new(Map.keys(pattern2))
    )

    if MapSet.size(keys) == 0 do
      0.0
    else
      matching = Enum.count(keys, fn k ->
        Map.get(pattern1, k) == Map.get(pattern2, k)
      end)

      matching / MapSet.size(keys)
    end
  end

  defp calculate_match_score(%Pattern{} = pattern) do
    # Score is based on:
    # 1. Occurrence count (more occurrences = more confident it's normal)
    # 2. Confidence weight (decay over time)
    # 3. Recency (recently seen patterns are more relevant)

    occurrence_factor = min(pattern.occurrence_count / 100.0, 1.0)
    confidence_factor = pattern.confidence_weight

    # Recency factor: patterns not seen in 30+ days get lower weight
    recency_factor = if pattern.last_seen do
      days_since = DateTime.diff(DateTime.utc_now(), pattern.last_seen, :day)
      max(1.0 - (days_since / 60.0), 0.3)
    else
      0.5
    end

    score = occurrence_factor * 0.4 + confidence_factor * 0.3 + recency_factor * 0.3
    Float.round(score, 3)
  end

  defp calculate_confidence_weight(%Pattern{} = pattern, now) do
    # Confidence increases with frequency and recency
    base_weight = pattern.confidence_weight

    # Boost for recent activity
    days_since = if pattern.last_seen do
      DateTime.diff(now, pattern.last_seen, :day)
    else
      30
    end

    recency_boost = if days_since < 1, do: 0.05, else: 0.0

    # Frequency boost (logarithmic)
    freq_boost = :math.log10(pattern.occurrence_count + 1) / 100.0

    min(base_weight + recency_boost + freq_boost, 2.0)
  end

  defp get_string(map, key) when is_atom(key) do
    case Map.get(map, key) || Map.get(map, Atom.to_string(key)) do
      nil -> nil
      val when is_binary(val) -> val
      val -> to_string(val)
    end
  end

  defp get_string(map, key) when is_binary(key) do
    case Map.get(map, key) || Map.get(map, String.to_atom(key)) do
      nil -> nil
      val when is_binary(val) -> val
      val -> to_string(val)
    end
  rescue
    # String.to_atom might fail for non-existent atoms
    ArgumentError -> Map.get(map, key)
  end
end
