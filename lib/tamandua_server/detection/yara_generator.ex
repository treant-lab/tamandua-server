defmodule TamanduaServer.Detection.YaraGenerator do
  @moduledoc """
  GenServer that automatically generates YARA rules from high-confidence ML detections.

  When the ML engine detects malware with confidence > 0.85 and the file hash is not
  already covered by an existing YARA rule, this module generates a YARA rule from
  the event data and stores it with `staged` status for analyst review.

  ## Rule Generation

  Rules are built from the following event data:
  - PE header patterns (MZ header, compile timestamps, section names)
  - String artifacts (URLs, domains, IP addresses, registry paths)
  - Entropy characteristics (packed/encrypted indicators)
  - Import table fingerprints (suspicious DLL/API combinations)
  - File size ranges

  ## Rule Lifecycle

  - `staged`   - Auto-generated, not active (30-day TTL)
  - `reviewed` - Analyst has reviewed, still not active
  - `active`   - Promoted to active detection
  - `expired`  - TTL exceeded without promotion, auto-removed
  - `rejected` - Analyst rejected; source hash will not trigger regeneration

  ## Collision Detection

  Before inserting a new rule, the generator checks for >80% string overlap with
  existing rules to avoid duplicates.

  ## Periodic Cleanup

  Expired staged rules are automatically cleaned up every hour.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.GeneratedYaraRule

  @ml_confidence_threshold 0.85
  @default_ttl_days 30
  @cleanup_interval_ms :timer.hours(1)
  @collision_threshold 0.80

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Generate a YARA rule from an ML detection event.

  ## Parameters

  - `event` - The telemetry event map containing file/process payload data
  - `ml_result` - The ML prediction result map with `:confidence`, `:prediction`,
    and optionally `:malware_family`

  ## Returns

  - `{:ok, rule}` - Successfully generated and stored the rule
  - `{:skip, reason}` - Skipped generation (below threshold, duplicate, etc.)
  - `{:error, reason}` - Error during generation
  """
  @spec generate_rule(map(), map()) :: {:ok, map()} | {:skip, atom()} | {:error, term()}
  def generate_rule(event, ml_result) do
    GenServer.call(__MODULE__, {:generate_rule, event, ml_result}, 30_000)
  end

  @doc """
  List all staged auto-generated rules.

  ## Options

  - `:status` - Filter by status (default: all)
  - `:family` - Filter by malware family
  - `:limit` - Maximum number of results (default: 100)
  """
  @spec list_staged_rules(keyword()) :: [map()]
  def list_staged_rules(opts \\ []) do
    GenServer.call(__MODULE__, {:list_staged_rules, opts})
  end

  @doc """
  Promote a staged rule to `active` status.

  The rule will be converted to a standard YaraRule and distributed to agents.

  ## Parameters

  - `rule_id` - The generated rule ID
  - `reviewer_id` - The user ID of the reviewer (optional)
  """
  @spec promote_rule(String.t(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def promote_rule(rule_id, reviewer_id \\ nil) do
    GenServer.call(__MODULE__, {:promote_rule, rule_id, reviewer_id})
  end

  @doc """
  Reject a staged rule. The source hash will not trigger regeneration.

  ## Parameters

  - `rule_id` - The generated rule ID
  - `reviewer_id` - The user ID of the reviewer (optional)
  """
  @spec reject_rule(String.t(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def reject_rule(rule_id, reviewer_id \\ nil) do
    GenServer.call(__MODULE__, {:reject_rule, rule_id, reviewer_id})
  end

  @doc """
  Remove expired staged rules from the database.
  Returns the count of removed rules.
  """
  @spec cleanup_expired() :: {:ok, non_neg_integer()}
  def cleanup_expired do
    GenServer.call(__MODULE__, :cleanup_expired)
  end

  @doc """
  Get auto-generation statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    schedule_cleanup()

    state = %{
      rules_generated: 0,
      rules_skipped: 0,
      rules_promoted: 0,
      rules_rejected: 0,
      rules_expired: 0,
      last_generation: nil
    }

    Logger.info("YARA Auto-Generator started (threshold: #{@ml_confidence_threshold})")
    {:ok, state}
  end

  @impl true
  def handle_call({:generate_rule, event, ml_result}, _from, state) do
    case do_generate_rule(event, ml_result) do
      {:ok, rule} ->
        new_state = %{state |
          rules_generated: state.rules_generated + 1,
          last_generation: DateTime.utc_now()
        }
        {:reply, {:ok, rule}, new_state}

      {:skip, reason} = skip ->
        new_state = %{state | rules_skipped: state.rules_skipped + 1}
        {:reply, skip, new_state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_staged_rules, opts}, _from, state) do
    rules = do_list_rules(opts)
    {:reply, rules, state}
  end

  @impl true
  def handle_call({:promote_rule, rule_id, reviewer_id}, _from, state) do
    case do_promote_rule(rule_id, reviewer_id) do
      {:ok, rule} ->
        new_state = %{state | rules_promoted: state.rules_promoted + 1}
        {:reply, {:ok, rule}, new_state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:reject_rule, rule_id, reviewer_id}, _from, state) do
    case do_reject_rule(rule_id, reviewer_id) do
      {:ok, rule} ->
        new_state = %{state | rules_rejected: state.rules_rejected + 1}
        {:reply, {:ok, rule}, new_state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:cleanup_expired, _from, state) do
    {count, new_state} = do_cleanup_expired(state)
    {:reply, {:ok, count}, new_state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    db_stats = get_db_stats()

    stats = %{
      session: %{
        rules_generated: state.rules_generated,
        rules_skipped: state.rules_skipped,
        rules_promoted: state.rules_promoted,
        rules_rejected: state.rules_rejected,
        rules_expired: state.rules_expired,
        last_generation: state.last_generation
      },
      database: db_stats,
      config: %{
        ml_confidence_threshold: @ml_confidence_threshold,
        default_ttl_days: @default_ttl_days,
        collision_threshold: @collision_threshold
      }
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    {_count, new_state} = do_cleanup_expired(state)
    schedule_cleanup()
    {:noreply, new_state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # Private implementation

  defp do_generate_rule(event, ml_result) do
    confidence = ml_result[:confidence] || ml_result["confidence"] || 0.0
    prediction = ml_result[:prediction] || ml_result["prediction"]
    malware_family = ml_result[:malware_family] || ml_result["malware_family"] || "Unknown"

    payload = event[:payload] || event["payload"] || %{}
    source_hash = extract_hash(payload)

    cond do
      # Check confidence threshold
      confidence < @ml_confidence_threshold ->
        {:skip, :below_threshold}

      # Only generate for malicious predictions
      prediction not in ["malicious", :malicious] ->
        {:skip, :not_malicious}

      # Need a file hash to deduplicate
      is_nil(source_hash) or source_hash == "" ->
        {:skip, :no_hash}

      # Check if hash is already covered by existing rules
      hash_covered_by_existing_rule?(source_hash) ->
        {:skip, :already_covered}

      # Check if already generated (or rejected) for this hash
      hash_already_processed?(source_hash) ->
        {:skip, :already_processed}

      true ->
        build_and_store_rule(event, ml_result, source_hash, malware_family, confidence)
    end
  rescue
    e ->
      Logger.error("YARA rule generation failed: #{Exception.message(e)}")
      {:error, {:generation_failed, Exception.message(e)}}
  end

  defp build_and_store_rule(event, ml_result, source_hash, malware_family, confidence) do
    payload = event[:payload] || event["payload"] || %{}
    short_hash = String.slice(source_hash, 0, 8)
    sanitized_family = sanitize_identifier(malware_family)

    rule_name = "ML_AutoGen_#{sanitized_family}_#{short_hash}"
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, @default_ttl_days * 24 * 3600, :second)

    # Extract artifacts from the event payload
    artifacts = extract_artifacts(payload)

    # Check for collision with existing generated rules
    if rule_collides_with_existing?(artifacts) do
      {:skip, :collision_detected}
    else
      # Build the YARA rule content
      rule_content = build_yara_rule(rule_name, malware_family, confidence, now, expires_at, payload, artifacts)

      # Build metadata
      metadata = build_metadata(event, ml_result, artifacts)

      attrs = %{
        name: rule_name,
        rule_content: rule_content,
        source_hash: source_hash,
        malware_family: malware_family,
        ml_confidence: confidence,
        status: "staged",
        expires_at: expires_at,
        organization_id: event[:organization_id] || event["organization_id"],
        metadata: metadata
      }

      case Repo.insert(GeneratedYaraRule.changeset(%GeneratedYaraRule{}, attrs)) do
        {:ok, rule} ->
          Logger.info(
            "Auto-generated YARA rule '#{rule_name}' for #{malware_family} " <>
            "(confidence: #{Float.round(confidence * 100, 1)}%, hash: #{short_hash})"
          )
          {:ok, rule}

        {:error, changeset} ->
          Logger.warning("Failed to store generated YARA rule: #{inspect(changeset.errors)}")
          {:error, {:insert_failed, changeset.errors}}
      end
    end
  end

  # --- Artifact Extraction ---

  defp extract_artifacts(payload) do
    %{
      strings: extract_string_artifacts(payload),
      pe_sections: extract_pe_sections(payload),
      imports: extract_imports(payload),
      entropy: extract_entropy(payload),
      file_size: extract_file_size(payload),
      compile_timestamp: extract_compile_timestamp(payload)
    }
  end

  defp extract_string_artifacts(payload) do
    raw_strings = payload[:strings] || payload["strings"] || []
    cmdline = payload[:cmdline] || payload["cmdline"]
    path = payload[:path] || payload["path"]

    all_strings =
      List.wrap(raw_strings)
      |> Enum.concat(extract_urls_from_string(cmdline))
      |> Enum.concat(extract_urls_from_string(path))

    # Extract specific patterns
    urls = Enum.filter(all_strings, &is_url?/1)
    domains = Enum.filter(all_strings, &is_domain?/1)
    ips = Enum.filter(all_strings, &is_ip_address?/1)
    registry_paths = Enum.filter(all_strings, &is_registry_path?/1)
    suspicious_strings = Enum.filter(all_strings, &is_suspicious_string?/1)

    # Combine and deduplicate, take the most specific ones
    (urls ++ domains ++ ips ++ registry_paths ++ suspicious_strings)
    |> Enum.uniq()
    |> Enum.reject(&(String.length(&1) < 4))
    |> Enum.take(20)
  end

  defp extract_urls_from_string(nil), do: []
  defp extract_urls_from_string(str) when is_binary(str) do
    # Extract URLs
    url_pattern = ~r{https?://[^\s\"\'<>]+}
    urls = Regex.scan(url_pattern, str) |> List.flatten()

    # Extract IP addresses
    ip_pattern = ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/
    ips = Regex.scan(ip_pattern, str) |> List.flatten()

    # Extract domain-like patterns
    domain_pattern = ~r/\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b/
    domains = Regex.scan(domain_pattern, str) |> List.flatten()

    # Extract registry paths (Windows)
    reg_pattern = ~r{(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"]+}
    reg_paths = Regex.scan(reg_pattern, str) |> List.flatten()

    urls ++ ips ++ domains ++ reg_paths
  end
  defp extract_urls_from_string(_), do: []

  defp extract_pe_sections(payload) do
    payload[:pe_sections] || payload["pe_sections"] || []
  end

  defp extract_imports(payload) do
    payload[:imports] || payload["imports"] || payload[:import_table] || payload["import_table"] || []
  end

  defp extract_entropy(payload) do
    entropy = payload[:entropy] || payload["entropy"]
    cond do
      is_number(entropy) -> entropy
      is_binary(entropy) -> String.to_float(entropy)
      true -> nil
    end
  rescue
    _ -> nil
  end

  defp extract_file_size(payload) do
    size = payload[:file_size] || payload["file_size"] || payload[:size] || payload["size"]
    cond do
      is_integer(size) -> size
      is_binary(size) -> String.to_integer(size)
      true -> nil
    end
  rescue
    _ -> nil
  end

  defp extract_compile_timestamp(payload) do
    payload[:compile_timestamp] || payload["compile_timestamp"]
  end

  # --- Pattern Classification ---

  defp is_url?(str) when is_binary(str) do
    String.match?(str, ~r{^https?://})
  end
  defp is_url?(_), do: false

  defp is_domain?(str) when is_binary(str) do
    String.match?(str, ~r/^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\.[a-zA-Z]{2,}$/)
  end
  defp is_domain?(_), do: false

  defp is_ip_address?(str) when is_binary(str) do
    String.match?(str, ~r/^(?:\d{1,3}\.){3}\d{1,3}$/)
  end
  defp is_ip_address?(_), do: false

  defp is_registry_path?(str) when is_binary(str) do
    String.match?(str, ~r{^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\}i)
  end
  defp is_registry_path?(_), do: false

  defp is_suspicious_string?(str) when is_binary(str) do
    suspicious_patterns = [
      ~r{cmd\.exe}i,
      ~r{powershell}i,
      ~r{wscript}i,
      ~r{cscript}i,
      ~r{mshta}i,
      ~r{rundll32}i,
      ~r{regsvr32}i,
      ~r{certutil}i,
      ~r{bitsadmin}i,
      ~r{\\temp\\}i,
      ~r{\\appdata\\}i,
      ~r{VirtualAlloc}i,
      ~r{WriteProcessMemory}i,
      ~r{CreateRemoteThread}i,
      ~r{NtUnmapViewOfSection}i,
      ~r{IsDebuggerPresent}i,
      ~r{GetProcAddress}i
    ]

    Enum.any?(suspicious_patterns, &Regex.match?(&1, str))
  end
  defp is_suspicious_string?(_), do: false

  # --- YARA Rule Construction ---

  defp build_yara_rule(rule_name, family, confidence, created_at, expires_at, payload, artifacts) do
    meta_block = build_meta_block(family, confidence, created_at, expires_at)
    strings_block = build_strings_block(payload, artifacts)
    condition_block = build_condition_block(artifacts)

    """
    import "math"

    rule #{rule_name} {
      meta:
    #{meta_block}
      strings:
    #{strings_block}
      condition:
    #{condition_block}
    }
    """
    |> String.trim()
  end

  defp build_meta_block(family, confidence, created_at, expires_at) do
    lines = [
      "    description = \"Auto-generated from ML detection\"",
      "    malware_family = \"#{escape_yara_string(family)}\"",
      "    ml_confidence = \"#{Float.round(confidence * 100, 1)}\"",
      "    source = \"ml_auto_generator\"",
      "    created = \"#{DateTime.to_iso8601(created_at)}\"",
      "    status = \"staged\"",
      "    expires = \"#{DateTime.to_iso8601(expires_at)}\""
    ]

    Enum.join(lines, "\n")
  end

  defp build_strings_block(payload, artifacts) do
    string_defs = []

    # MZ header for PE files
    string_defs = if is_pe_file?(payload) do
      string_defs ++ ["    $mz = \"MZ\" at 0"]
    else
      string_defs
    end

    # Add extracted string artifacts
    artifact_strings = artifacts.strings
    |> Enum.with_index(1)
    |> Enum.map(fn {str, idx} ->
      escaped = escape_yara_string(str)
      modifiers = string_modifiers(str)
      "    $str#{idx} = \"#{escaped}\"#{modifiers}"
    end)

    string_defs = string_defs ++ artifact_strings

    # Add PE section name patterns
    section_strings = artifacts.pe_sections
    |> Enum.with_index(1)
    |> Enum.map(fn {section, idx} ->
      name = section[:name] || section["name"] || to_string(section)
      "    $sec#{idx} = \"#{escape_yara_string(name)}\" ascii"
    end)
    |> Enum.take(5)

    string_defs = string_defs ++ section_strings

    # Add import patterns
    import_strings = artifacts.imports
    |> Enum.filter(&suspicious_import?/1)
    |> Enum.with_index(1)
    |> Enum.map(fn {imp, idx} ->
      name = if is_map(imp), do: imp[:name] || imp["name"] || to_string(imp), else: to_string(imp)
      "    $imp#{idx} = \"#{escape_yara_string(name)}\" ascii"
    end)
    |> Enum.take(10)

    string_defs = string_defs ++ import_strings

    # Ensure we have at least one string definition
    if Enum.empty?(string_defs) do
      "    $mz = \"MZ\" at 0"
    else
      Enum.join(string_defs, "\n")
    end
  end

  defp build_condition_block(artifacts) do
    conditions = []

    # PE header check
    conditions = conditions ++ ["    uint16(0) == 0x5A4D"]

    # File size constraint
    conditions = case artifacts.file_size do
      size when is_integer(size) and size > 0 ->
        max_size = max(size * 2, 1_048_576)  # At least 1MB, at most 2x actual size
        size_label = format_file_size(max_size)
        conditions ++ ["    filesize < #{size_label}"]

      _ ->
        conditions ++ ["    filesize < 5MB"]
    end

    # String matching: require at least 2 of all $str* patterns
    str_count = length(artifacts.strings)
    conditions = if str_count > 0 do
      required = max(1, div(str_count, 2))
      required = min(required, str_count)
      conditions ++ ["    #{required} of ($str*)"]
    else
      conditions
    end

    # Entropy check for packed/encrypted binaries
    conditions = case artifacts.entropy do
      entropy when is_number(entropy) and entropy > 6.0 ->
        # High entropy suggests packing/encryption
        threshold = Float.round(max(entropy - 0.5, 6.0), 1)
        conditions ++ ["    math.entropy(0, filesize) > #{threshold}"]

      _ ->
        conditions
    end

    Enum.join(conditions, " and\n")
  end

  # --- Collision Detection ---

  defp rule_collides_with_existing?(artifacts) do
    new_strings = MapSet.new(artifacts.strings)

    if MapSet.size(new_strings) == 0 do
      false
    else
      existing_rules =
        from(r in GeneratedYaraRule,
          where: r.status in ["staged", "reviewed", "active"],
          select: {r.id, r.metadata}
        )
        |> Repo.all()

      Enum.any?(existing_rules, fn {_id, metadata} ->
        existing_strings =
          (metadata["artifacts"] || %{})
          |> Map.get("strings", [])
          |> MapSet.new()

        if MapSet.size(existing_strings) == 0 do
          false
        else
          intersection = MapSet.intersection(new_strings, existing_strings)
          union = MapSet.union(new_strings, existing_strings)
          overlap = MapSet.size(intersection) / max(MapSet.size(union), 1)
          overlap >= @collision_threshold
        end
      end)
    end
  rescue
    e ->
      Logger.warning("Collision check failed: #{inspect(e)}, proceeding with generation")
      false
  end

  # --- Hash Coverage Checks ---

  defp hash_covered_by_existing_rule?(source_hash) do
    # Check if any active YARA rule in the database references this hash
    query =
      from(r in TamanduaServer.Detection.YaraRule,
        where: r.enabled == true,
        where: ilike(r.source, ^"%#{source_hash}%"),
        select: count(r.id)
      )

    Repo.one(query) > 0
  rescue
    _ -> false
  end

  defp hash_already_processed?(source_hash) do
    query =
      from(r in GeneratedYaraRule,
        where: r.source_hash == ^source_hash,
        where: r.status in ["staged", "reviewed", "active", "rejected"],
        select: count(r.id)
      )

    Repo.one(query) > 0
  rescue
    _ -> false
  end

  # --- Rule Lifecycle ---

  defp do_list_rules(opts) do
    status = Keyword.get(opts, :status)
    family = Keyword.get(opts, :family)
    limit = Keyword.get(opts, :limit, 100)

    query = from(r in GeneratedYaraRule, order_by: [desc: r.inserted_at], limit: ^limit)

    query = if status do
      from(r in query, where: r.status == ^status)
    else
      query
    end

    query = if family do
      from(r in query, where: r.malware_family == ^family)
    else
      query
    end

    Repo.all(query)
  rescue
    e ->
      Logger.error("Failed to list generated rules: #{inspect(e)}")
      []
  end

  defp do_promote_rule(rule_id, reviewer_id) do
    case Repo.get(GeneratedYaraRule, rule_id) do
      nil ->
        {:error, :not_found}

      %GeneratedYaraRule{status: status} when status not in ["staged", "reviewed"] ->
        {:error, {:invalid_status, status}}

      rule ->
        attrs = %{
          status: "active",
          reviewed_by_id: reviewer_id,
          reviewed_at: DateTime.utc_now()
        }

        case Repo.update(GeneratedYaraRule.promote_changeset(rule, attrs)) do
          {:ok, updated_rule} ->
            # Also create a standard YaraRule for agent distribution
            promote_to_standard_rule(updated_rule)
            Logger.info("Generated YARA rule '#{updated_rule.name}' promoted to active")
            {:ok, updated_rule}

          {:error, changeset} ->
            {:error, {:update_failed, changeset.errors}}
        end
    end
  rescue
    e ->
      Logger.error("Failed to promote rule #{rule_id}: #{inspect(e)}")
      {:error, {:promote_failed, Exception.message(e)}}
  end

  defp do_reject_rule(rule_id, reviewer_id) do
    case Repo.get(GeneratedYaraRule, rule_id) do
      nil ->
        {:error, :not_found}

      %GeneratedYaraRule{status: "active"} ->
        {:error, :cannot_reject_active}

      rule ->
        attrs = %{
          status: "rejected",
          reviewed_by_id: reviewer_id,
          reviewed_at: DateTime.utc_now()
        }

        case Repo.update(GeneratedYaraRule.promote_changeset(rule, attrs)) do
          {:ok, updated_rule} ->
            Logger.info("Generated YARA rule '#{updated_rule.name}' rejected")
            {:ok, updated_rule}

          {:error, changeset} ->
            {:error, {:update_failed, changeset.errors}}
        end
    end
  rescue
    e ->
      Logger.error("Failed to reject rule #{rule_id}: #{inspect(e)}")
      {:error, {:reject_failed, Exception.message(e)}}
  end

  defp do_cleanup_expired(state) do
    now = DateTime.utc_now()

    {count, _} =
      from(r in GeneratedYaraRule,
        where: r.status == "staged",
        where: r.expires_at < ^now
      )
      |> Repo.update_all(set: [status: "expired", updated_at: now])

    if count > 0 do
      Logger.info("Cleaned up #{count} expired auto-generated YARA rules")
    end

    new_state = %{state | rules_expired: state.rules_expired + count}
    {count, new_state}
  rescue
    e ->
      Logger.warning("Cleanup failed: #{inspect(e)}")
      {0, state}
  end

  defp promote_to_standard_rule(%GeneratedYaraRule{} = gen_rule) do
    attrs = %{
      name: gen_rule.name,
      description: "Auto-generated from ML detection (family: #{gen_rule.malware_family})",
      author: "ml_auto_generator",
      source: gen_rule.rule_content,
      enabled: true,
      category: "malware",
      severity: severity_from_confidence(gen_rule.ml_confidence),
      malware_family: gen_rule.malware_family,
      tags: ["auto_generated", "ml_detection"],
      organization_id: gen_rule.organization_id
    }

    case TamanduaServer.Detection.create_yara_rule(attrs) do
      {:ok, yara_rule} ->
        Logger.info("Standard YARA rule created from generated rule: #{yara_rule.id}")
        {:ok, yara_rule}

      {:error, reason} ->
        Logger.warning("Failed to create standard YARA rule from generated: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Failed to promote to standard rule: #{inspect(e)}")
      {:error, {:promotion_failed, Exception.message(e)}}
  end

  # --- Helpers ---

  defp extract_hash(payload) do
    payload[:sha256] || payload["sha256"] ||
    payload[:hash] || payload["hash"]
  end

  defp sanitize_identifier(nil), do: "Unknown"
  defp sanitize_identifier(name) when is_binary(name) do
    name
    |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
    |> String.slice(0, 32)
  end

  defp escape_yara_string(str) when is_binary(str) do
    str
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
    |> String.replace("\r", "\\r")
    |> String.replace("\t", "\\t")
  end
  defp escape_yara_string(other), do: to_string(other)

  defp string_modifiers(str) do
    cond do
      is_url?(str) -> " ascii wide nocase"
      is_domain?(str) -> " ascii wide nocase"
      is_ip_address?(str) -> " ascii wide"
      is_registry_path?(str) -> " ascii nocase"
      true -> " ascii wide nocase"
    end
  end

  defp suspicious_import?(imp) when is_binary(imp) do
    suspicious_apis = [
      "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
      "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
      "NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtCreateThreadEx",
      "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
      "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
      "CreateFileW", "DeleteFileW", "MoveFileW",
      "RegSetValueExW", "RegCreateKeyExW",
      "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA",
      "URLDownloadToFileA", "URLDownloadToFileW",
      "ShellExecuteA", "ShellExecuteW", "WinExec",
      "CryptEncrypt", "CryptDecrypt", "CryptGenKey"
    ]

    Enum.any?(suspicious_apis, &String.contains?(imp, &1))
  end
  defp suspicious_import?(imp) when is_map(imp) do
    name = imp[:name] || imp["name"] || ""
    suspicious_import?(name)
  end
  defp suspicious_import?(_), do: false

  defp is_pe_file?(payload) do
    # Check if the file looks like a PE (Windows executable)
    path = payload[:path] || payload["path"] || ""
    pe_header = payload[:pe_header] || payload["pe_header"]

    has_pe_extension = String.match?(path, ~r/\.(exe|dll|sys|scr|com|ocx|drv)$/i)
    has_pe_header = pe_header != nil

    has_pe_extension or has_pe_header
  end

  defp format_file_size(bytes) when bytes >= 1_048_576 do
    mb = div(bytes, 1_048_576)
    "#{mb}MB"
  end
  defp format_file_size(bytes) when bytes >= 1024 do
    kb = div(bytes, 1024)
    "#{kb}KB"
  end
  defp format_file_size(bytes), do: "#{bytes}"

  defp severity_from_confidence(confidence) do
    cond do
      confidence >= 0.95 -> "critical"
      confidence >= 0.85 -> "high"
      confidence >= 0.70 -> "medium"
      confidence >= 0.50 -> "low"
      true -> "informational"
    end
  end

  defp build_metadata(event, ml_result, artifacts) do
    %{
      "event_type" => to_string(event[:event_type] || event["event_type"] || ""),
      "agent_id" => event[:agent_id] || event["agent_id"],
      "ml_prediction" => ml_result[:prediction] || ml_result["prediction"],
      "ml_malware_family" => ml_result[:malware_family] || ml_result["malware_family"],
      "artifacts" => %{
        "strings" => artifacts.strings,
        "pe_sections" => Enum.map(artifacts.pe_sections, &to_string/1),
        "import_count" => length(artifacts.imports),
        "entropy" => artifacts.entropy,
        "file_size" => artifacts.file_size
      }
    }
  end

  defp get_db_stats do
    counts =
      from(r in GeneratedYaraRule,
        group_by: r.status,
        select: {r.status, count(r.id)}
      )
      |> Repo.all()
      |> Enum.into(%{})

    %{
      total: Enum.reduce(counts, 0, fn {_k, v}, acc -> acc + v end),
      staged: Map.get(counts, "staged", 0),
      reviewed: Map.get(counts, "reviewed", 0),
      active: Map.get(counts, "active", 0),
      expired: Map.get(counts, "expired", 0),
      rejected: Map.get(counts, "rejected", 0)
    }
  rescue
    _ -> %{total: 0, staged: 0, reviewed: 0, active: 0, expired: 0, rejected: 0}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)
  end
end
