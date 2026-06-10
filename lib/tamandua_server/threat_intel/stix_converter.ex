defmodule TamanduaServer.ThreatIntel.StixConverter do
  @moduledoc """
  Converts between Tamandua's internal IOC format and STIX 2.1 objects.

  Supports:
  - Internal IOC -> STIX Indicator (with pattern generation)
  - STIX Indicator -> Internal IOC (with pattern parsing)
  - Alert -> STIX Sighting
  - IOC collection -> STIX Bundle
  - Full STIX bundle import

  STIX 2.1 reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  """

  require Logger

  @stix_spec_version "2.1"
  @tamandua_identity_id "identity--tamandua-edr"

  # ── IOC to STIX Indicator ───────────────────────────────────────────

  @doc """
  Convert an internal IOC to a STIX 2.1 Indicator object.

  The IOC should have at minimum `:type` and `:value` fields.
  Optional fields: `:description`, `:tags`, `:confidence`, `:inserted_at`, `:updated_at`.
  """
  @spec to_stix_indicator(map()) :: map()
  def to_stix_indicator(ioc) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()
    created = format_stix_datetime(ioc[:inserted_at] || ioc["inserted_at"]) || now
    modified = format_stix_datetime(ioc[:updated_at] || ioc["updated_at"]) || now

    type = to_string(ioc[:type] || ioc["type"])
    value = to_string(ioc[:value] || ioc["value"])
    description = ioc[:description] || ioc["description"] || "#{type}: #{value}"
    tags = ioc[:tags] || ioc["tags"] || []
    confidence = normalize_confidence(ioc[:confidence] || ioc["confidence"])

    indicator_id = if ioc[:id] || ioc["id"] do
      "indicator--#{ioc[:id] || ioc["id"]}"
    else
      "indicator--#{UUID.uuid4()}"
    end

    %{
      "type" => "indicator",
      "spec_version" => @stix_spec_version,
      "id" => indicator_id,
      "created" => created,
      "modified" => modified,
      "name" => description,
      "description" => "IOC from Tamandua EDR: #{type} indicator",
      "pattern" => to_stix_pattern(type, value),
      "pattern_type" => "stix",
      "valid_from" => created,
      "labels" => normalize_labels(tags),
      "confidence" => confidence,
      "indicator_types" => determine_indicator_types(type, tags),
      "created_by_ref" => @tamandua_identity_id
    }
  end

  @doc """
  Convert a list of IOCs to STIX indicators.
  """
  @spec to_stix_indicators([map()]) :: [map()]
  def to_stix_indicators(iocs) when is_list(iocs) do
    Enum.map(iocs, &to_stix_indicator/1)
  end

  # ── STIX Indicator to IOC ───────────────────────────────────────────

  @doc """
  Convert a STIX 2.1 Indicator to an internal IOC map.

  Parses the STIX pattern to extract the IOC type and value.

  Returns `{:ok, ioc_map}` or `{:error, reason}`.
  """
  @spec from_stix_indicator(map()) :: {:ok, map()} | {:error, term()}
  def from_stix_indicator(%{"type" => "indicator", "pattern" => pattern} = indicator) do
    case parse_stix_pattern(pattern) do
      {:ok, ioc_type, ioc_value} ->
        confidence = (indicator["confidence"] || 50) / 100.0
        tags = indicator["labels"] || []
        description = indicator["name"] || indicator["description"] || ""

        source = case indicator["created_by_ref"] do
          nil -> "stix_import"
          ref -> "stix_#{String.slice(ref, 0, 20)}"
        end

        severity = determine_severity_from_confidence(confidence)

        ioc = %{
          type: ioc_type,
          value: String.downcase(ioc_value),
          source: source,
          severity: severity,
          confidence: confidence,
          description: description,
          tags: normalize_tags(tags ++ ["stix_import"]),
          enabled: true
        }

        {:ok, ioc}

      {:error, reason} ->
        {:error, {:pattern_parse_error, reason}}
    end
  end

  def from_stix_indicator(%{"type" => "indicator"}) do
    {:error, :missing_pattern}
  end

  def from_stix_indicator(_) do
    {:error, :not_an_indicator}
  end

  @doc """
  Convert a list of STIX indicators to internal IOC maps.
  Returns only successfully converted IOCs.
  """
  @spec from_stix_indicators([map()]) :: [map()]
  def from_stix_indicators(indicators) when is_list(indicators) do
    indicators
    |> Enum.filter(&(&1["type"] == "indicator"))
    |> Enum.flat_map(fn indicator ->
      case from_stix_indicator(indicator) do
        {:ok, ioc} -> [ioc]
        {:error, _} -> []
      end
    end)
  end

  # ── Alert to STIX Sighting ──────────────────────────────────────────

  @doc """
  Convert a Tamandua alert to a STIX 2.1 Sighting object.

  A Sighting represents the observation of an indicator in the environment.
  """
  @spec alert_to_sighting(map()) :: map()
  def alert_to_sighting(alert) do
    alert_id = alert[:id] || alert["id"] || UUID.uuid4()
    created = format_stix_datetime(alert[:inserted_at] || alert["inserted_at"]) || DateTime.to_iso8601(DateTime.utc_now())

    source_ioc_id = alert[:source_ioc_id] || alert["source_ioc_id"]
    sighting_of_ref = if source_ioc_id do
      "indicator--#{source_ioc_id}"
    else
      nil
    end

    agent_id = alert[:agent_id] || alert["agent_id"]
    observed_data_refs = if agent_id do
      ["observed-data--#{agent_id}"]
    else
      []
    end

    sighting = %{
      "type" => "sighting",
      "spec_version" => @stix_spec_version,
      "id" => "sighting--#{alert_id}",
      "created" => created,
      "modified" => created,
      "first_seen" => created,
      "last_seen" => format_stix_datetime(alert[:last_seen_at] || alert["last_seen_at"]) || created,
      "count" => alert[:occurrence_count] || alert["occurrence_count"] || 1,
      "where_sighted_refs" => [@tamandua_identity_id],
      "observed_data_refs" => observed_data_refs,
      "summary" => true,
      "created_by_ref" => @tamandua_identity_id
    }

    # Only add sighting_of_ref if we have one
    if sighting_of_ref do
      Map.put(sighting, "sighting_of_ref", sighting_of_ref)
    else
      sighting
    end
  end

  # ── STIX Bundle ──────────────────────────────────────────────────────

  @doc """
  Create a STIX 2.1 Bundle from a list of STIX objects.

  The bundle includes a Tamandua identity object for attribution.
  """
  @spec create_bundle([map()]) :: map()
  def create_bundle(objects) when is_list(objects) do
    identity = tamandua_identity()

    %{
      "type" => "bundle",
      "id" => "bundle--#{UUID.uuid4()}",
      "objects" => [identity | objects]
    }
  end

  @doc """
  Export IOCs as a STIX bundle.

  ## Options
    - `:type` - Filter by IOC type
    - `:source` - Filter by source
    - `:limit` - Maximum IOCs to include (default: 1000)
    - `:include_sightings` - Whether to include alert sightings (default: false)
  """
  @spec export_iocs_as_bundle(keyword()) :: map()
  def export_iocs_as_bundle(opts \\ []) do
    limit = Keyword.get(opts, :limit, 1000)
    include_sightings = Keyword.get(opts, :include_sightings, false)

    # Fetch IOCs
    ioc_opts = [limit: limit, enabled: true]
    ioc_opts = if type = Keyword.get(opts, :type), do: Keyword.put(ioc_opts, :type, type), else: ioc_opts
    ioc_opts = if source = Keyword.get(opts, :source), do: Keyword.put(ioc_opts, :source, source), else: ioc_opts

    iocs = TamanduaServer.Detection.IOCs.list(ioc_opts)
    indicators = Enum.map(iocs, &to_stix_indicator/1)

    objects = if include_sightings do
      # Fetch recent alerts related to these IOCs
      sightings = fetch_related_sightings(iocs)
      indicators ++ sightings
    else
      indicators
    end

    create_bundle(objects)
  end

  @doc """
  Import a STIX bundle and insert IOCs into the database.

  Returns a summary of the import results.
  """
  @spec import_bundle(map()) :: {:ok, map()} | {:error, term()}
  def import_bundle(%{"type" => "bundle", "objects" => objects}) when is_list(objects) do
    # Separate indicators from other object types
    indicators = Enum.filter(objects, &(&1["type"] == "indicator"))
    sightings = Enum.filter(objects, &(&1["type"] == "sighting"))
    other = Enum.reject(objects, &(&1["type"] in ["indicator", "sighting", "identity"]))

    # Convert STIX indicators to IOCs
    iocs = from_stix_indicators(indicators)

    # Bulk insert IOCs
    {inserted, failed} = case TamanduaServer.Detection.IOCs.bulk_add(iocs, on_conflict: :nothing) do
      {:ok, result} -> {result.successful, result.failed}
      {:error, _} -> {0, length(iocs)}
    end

    # Trigger retroactive scan and detection engine refresh for new IOCs
    if inserted > 0 do
      Task.start(fn -> TamanduaServer.Detection.Engine.reload_iocs() end)

      try do
        TamanduaServer.ThreatIntel.RetroactiveScanner.scan_new_iocs(iocs)
      rescue
        _ -> :ok
      end
    end

    {:ok, %{
      total_objects: length(objects),
      indicators_found: length(indicators),
      sightings_found: length(sightings),
      other_objects: length(other),
      iocs_converted: length(iocs),
      iocs_inserted: inserted,
      iocs_failed: failed
    }}
  end

  def import_bundle(%{"type" => "bundle"}) do
    {:error, :empty_bundle}
  end

  def import_bundle(_) do
    {:error, :invalid_bundle_format}
  end

  # ── STIX Pattern Generation ─────────────────────────────────────────

  @doc """
  Generate a STIX pattern string from an IOC type and value.

  ## Examples

      iex> to_stix_pattern("ip", "192.168.1.1")
      "[ipv4-addr:value = '192.168.1.1']"

      iex> to_stix_pattern("domain", "evil.com")
      "[domain-name:value = 'evil.com']"

      iex> to_stix_pattern("hash_sha256", "abc123...")
      "[file:hashes.'SHA-256' = 'abc123...']"
  """
  @spec to_stix_pattern(String.t(), String.t()) :: String.t()
  def to_stix_pattern(type, value) do
    escaped = escape_stix_value(value)

    case type do
      "ip" ->
        if String.contains?(value, ":") do
          "[ipv6-addr:value = '#{escaped}']"
        else
          "[ipv4-addr:value = '#{escaped}']"
        end

      "domain" ->
        "[domain-name:value = '#{escaped}']"

      "hash_sha256" ->
        "[file:hashes.'SHA-256' = '#{escaped}']"

      "hash_sha1" ->
        "[file:hashes.'SHA-1' = '#{escaped}']"

      "hash_md5" ->
        "[file:hashes.MD5 = '#{escaped}']"

      "url" ->
        "[url:value = '#{escaped}']"

      "email" ->
        "[email-addr:value = '#{escaped}']"

      "filename" ->
        "[file:name = '#{escaped}']"

      _ ->
        "[artifact:payload_bin = '#{escaped}']"
    end
  end

  # ── STIX Pattern Parsing ────────────────────────────────────────────

  @doc """
  Parse a STIX pattern to extract IOC type and value.

  Supports common patterns:
  - `[ipv4-addr:value = '...']`
  - `[ipv6-addr:value = '...']`
  - `[domain-name:value = '...']`
  - `[file:hashes.'SHA-256' = '...']`
  - `[file:hashes.'SHA-1' = '...']`
  - `[file:hashes.MD5 = '...']`
  - `[url:value = '...']`
  - `[email-addr:value = '...']`
  - `[file:name = '...']`

  Returns `{:ok, type, value}` or `{:error, :unsupported_pattern}`.
  """
  @spec parse_stix_pattern(String.t()) :: {:ok, String.t(), String.t()} | {:error, term()}
  def parse_stix_pattern(pattern) when is_binary(pattern) do
    pattern = String.trim(pattern)

    cond do
      match = Regex.run(~r/\[ipv4-addr:value\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "ip", Enum.at(match, 1)}

      match = Regex.run(~r/\[ipv6-addr:value\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "ip", Enum.at(match, 1)}

      match = Regex.run(~r/\[domain-name:value\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "domain", Enum.at(match, 1)}

      match = Regex.run(~r/\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]/i, pattern) ->
        {:ok, "hash_sha256", Enum.at(match, 1)}

      match = Regex.run(~r/\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]/i, pattern) ->
        {:ok, "hash_sha1", Enum.at(match, 1)}

      match = Regex.run(~r/\[file:hashes\.MD5\s*=\s*'([^']+)'\]/i, pattern) ->
        {:ok, "hash_md5", Enum.at(match, 1)}

      match = Regex.run(~r/\[url:value\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "url", Enum.at(match, 1)}

      match = Regex.run(~r/\[email-addr:value\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "email", Enum.at(match, 1)}

      match = Regex.run(~r/\[file:name\s*=\s*'([^']+)'\]/, pattern) ->
        {:ok, "filename", Enum.at(match, 1)}

      # Compound patterns (OR) - extract first value
      match = Regex.run(~r/\[([a-z0-9-]+):value\s*=\s*'([^']+)'\s*OR/, pattern) ->
        stix_type = Enum.at(match, 1)
        value = Enum.at(match, 2)
        {:ok, stix_type_to_internal(stix_type), value}

      true ->
        {:error, :unsupported_pattern}
    end
  end

  def parse_stix_pattern(_), do: {:error, :invalid_pattern}

  # ── Private Helpers ──────────────────────────────────────────────────

  defp tamandua_identity do
    %{
      "type" => "identity",
      "spec_version" => @stix_spec_version,
      "id" => @tamandua_identity_id,
      "created" => "2025-01-01T00:00:00.000Z",
      "modified" => "2025-01-01T00:00:00.000Z",
      "name" => "Tamandua EDR",
      "description" => "Tamandua Endpoint Detection and Response Platform",
      "identity_class" => "system",
      "sectors" => ["technology"]
    }
  end

  defp format_stix_datetime(nil), do: nil
  defp format_stix_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_stix_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt) <> "Z"
  defp format_stix_datetime(str) when is_binary(str), do: str
  defp format_stix_datetime(_), do: nil

  defp normalize_confidence(nil), do: 50
  defp normalize_confidence(c) when is_float(c) and c <= 1.0, do: round(c * 100)
  defp normalize_confidence(c) when is_integer(c) and c >= 0 and c <= 100, do: c
  defp normalize_confidence(c) when is_float(c) and c > 1.0, do: round(min(c, 100))
  defp normalize_confidence(_), do: 50

  defp normalize_labels(tags) when is_list(tags) do
    tags
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end
  defp normalize_labels(_), do: []

  defp normalize_tags(tags) when is_list(tags) do
    tags
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end
  defp normalize_tags(_), do: []

  defp determine_indicator_types(type, tags) do
    base_types = case type do
      "ip" -> ["malicious-activity"]
      "domain" -> ["malicious-activity"]
      "url" -> ["malicious-activity"]
      t when t in ["hash_sha256", "hash_sha1", "hash_md5"] -> ["malicious-activity"]
      "email" -> ["malicious-activity"]
      _ -> ["anomalous-activity"]
    end

    # Check tags for more specific types
    tag_strs = Enum.map(tags, &to_string/1)
    cond do
      Enum.any?(tag_strs, &String.contains?(&1, "c2")) -> ["malicious-activity", "command-and-control"]
      Enum.any?(tag_strs, &String.contains?(&1, "phish")) -> ["malicious-activity", "phishing"]
      Enum.any?(tag_strs, &String.contains?(&1, "ransomware")) -> ["malicious-activity"]
      true -> base_types
    end
  end

  defp determine_severity_from_confidence(confidence) when is_float(confidence) do
    cond do
      confidence >= 0.9 -> "critical"
      confidence >= 0.7 -> "high"
      confidence >= 0.4 -> "medium"
      true -> "low"
    end
  end
  defp determine_severity_from_confidence(_), do: "medium"

  defp stix_type_to_internal("ipv4-addr"), do: "ip"
  defp stix_type_to_internal("ipv6-addr"), do: "ip"
  defp stix_type_to_internal("domain-name"), do: "domain"
  defp stix_type_to_internal("url"), do: "url"
  defp stix_type_to_internal("email-addr"), do: "email"
  defp stix_type_to_internal("file"), do: "filename"
  defp stix_type_to_internal(_), do: "filename"

  defp escape_stix_value(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
  end
  defp escape_stix_value(value), do: escape_stix_value(to_string(value))

  defp fetch_related_sightings(_iocs) do
    # Future: Query alerts that match IOC values and convert to sightings
    # For now, return empty - sightings can be exported separately
    []
  end
end
