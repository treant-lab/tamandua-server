defmodule TamanduaServer.Detection.CrossAgentCorrelator do
  @moduledoc """
  Cross-Agent Storyline Correlation Engine.

  While the Storyline engine (`Detection.Storyline`) correlates events within a
  single agent, this module correlates across ALL endpoints. When the same
  attacker IP, file hash, domain, or URL appears on multiple agents, those
  storylines are linked into cross-agent correlations.

  This is modeled after the cross-endpoint correlation found in CrowdStrike
  Falcon and SentinelOne Singularity: if the same indicator of compromise (IOC)
  is observed on two or more distinct agents, it is likely a coordinated attack
  or campaign rather than an isolated incident.

  ## Architecture

  - **ETS IOC Index** (`:cross_agent_ioc_index`) -- Maps `{ioc_type, ioc_value}`
    to a set of `{agent_id, storyline_id, timestamp}` tuples. Public table with
    `read_concurrency: true` so query functions can read directly without going
    through the GenServer.

  - **ETS Correlation Store** (`:cross_agent_correlations`) -- Stores
    `CrossAgentCorrelation` records keyed by their UUID. Same concurrency model.

  - **Mutations through GenServer** -- All writes (IOC indexing, correlation
    creation, cleanup) go through `handle_cast`/`handle_call` to avoid races.

  - **Direct ETS reads for queries** -- `get_correlations_for_agent/1`,
    `get_correlations_for_storyline/1`, and `get_campaign_view/0` read ETS
    directly for maximum throughput.

  ## Campaign Detection

  When 3 or more distinct agents share the same IOC within a 24-hour window, a
  campaign alert is automatically created. The alert includes all involved
  agents, storylines, and shared IOCs, and is broadcast on the
  `"cross_agent:campaigns"` PubSub topic.

  ## Cleanup

  A periodic sweep (every 30 minutes) removes IOC index entries older than
  48 hours. This keeps memory bounded while retaining enough history for
  meaningful correlation across slow-moving campaigns.

  ## Thread Safety

  All mutations go through the GenServer. ETS reads are direct for performance
  (public `read_concurrency` tables).
  """

  use GenServer
  require Logger

  @ioc_index_table :cross_agent_ioc_index
  @correlation_table :cross_agent_correlations

  # Campaign alert threshold: N distinct agents sharing the same IOC
  @campaign_agent_threshold 3
  # Time window for campaign detection: 24 hours in seconds
  @campaign_window_seconds 86_400
  # IOC entry TTL: 48 hours in seconds
  @ioc_ttl_seconds 172_800
  # Cleanup interval: 30 minutes in milliseconds
  @cleanup_interval_ms 1_800_000

  # ------------------------------------------------------------------
  # Structs
  # ------------------------------------------------------------------

  defmodule CrossAgentCorrelation do
    @moduledoc false
    defstruct [
      :id,
      :ioc_type,
      :ioc_value,
      :first_seen_at,
      :last_seen_at,
      agent_storylines: [],
      confidence: 0.0
    ]
  end

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest a detection and extract IOCs for cross-agent correlation.

  Called from the EngineWorker after a detection is created. Extracts IOCs
  (sha256, source/dest IP, domain, URL) from the detection, checks if any
  already exist in the index from a DIFFERENT agent, and if so creates a
  `CrossAgentCorrelation` record and broadcasts via PubSub.
  """
  @spec ingest_detection(String.t(), map()) :: :ok
  def ingest_detection(agent_id, detection) do
    GenServer.cast(__MODULE__, {:ingest_detection, agent_id, detection})
  end

  @doc """
  Get all cross-agent correlations involving a specific agent.

  Reads directly from ETS for performance.
  """
  @spec get_correlations_for_agent(String.t()) :: {:ok, [map()]}
  def get_correlations_for_agent(agent_id) do
    correlations =
      safe_tab2list(@correlation_table)
      |> Enum.map(fn {_id, corr} -> corr end)
      |> Enum.filter(fn corr ->
        Enum.any?(corr.agent_storylines, fn entry -> entry.agent_id == agent_id end)
      end)
      |> Enum.sort_by(& &1.last_seen_at, {:desc, DateTime})
      |> Enum.map(&serialize_correlation/1)

    {:ok, correlations}
  end

  @doc """
  Get all cross-agent correlations involving a specific storyline.

  Reads directly from ETS for performance.
  """
  @spec get_correlations_for_storyline(String.t()) :: {:ok, [map()]}
  def get_correlations_for_storyline(storyline_id) do
    correlations =
      safe_tab2list(@correlation_table)
      |> Enum.map(fn {_id, corr} -> corr end)
      |> Enum.filter(fn corr ->
        Enum.any?(corr.agent_storylines, fn entry -> entry.storyline_id == storyline_id end)
      end)
      |> Enum.sort_by(& &1.last_seen_at, {:desc, DateTime})
      |> Enum.map(&serialize_correlation/1)

    {:ok, correlations}
  end

  @doc """
  Get a campaign view: correlations grouped by shared IOCs that span 3+ agents.

  Returns a list of campaign summaries, each containing the shared IOC, all
  involved agents and storylines, and a combined confidence score.
  """
  @spec get_campaign_view() :: {:ok, [map()]}
  def get_campaign_view do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@campaign_window_seconds, :second)

    campaigns =
      safe_tab2list(@correlation_table)
      |> Enum.map(fn {_id, corr} -> corr end)
      |> Enum.filter(fn corr ->
        # Only include correlations within the campaign window
        DateTime.compare(corr.last_seen_at, cutoff) != :lt
      end)
      |> Enum.filter(fn corr ->
        # Only include correlations spanning 3+ distinct agents
        corr.agent_storylines
        |> Enum.map(& &1.agent_id)
        |> Enum.uniq()
        |> length()
        |> Kernel.>=(@campaign_agent_threshold)
      end)
      |> group_into_campaigns()

    {:ok, campaigns}
  end

  @doc """
  Return summary statistics about the Cross-Agent Correlator state.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # IOC index: key = {ioc_type, ioc_value}, value = list of {agent_id, storyline_id, timestamp}
    :ets.new(@ioc_index_table, [
      :set, :public, :named_table,
      read_concurrency: true
    ])

    # Correlation store: key = correlation_id, value = %CrossAgentCorrelation{}
    :ets.new(@correlation_table, [
      :set, :public, :named_table,
      read_concurrency: true
    ])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("[CrossAgentCorrelator] Cross-Agent Correlation Engine started")

    {:ok, %{
      stats: %{
        detections_ingested: 0,
        iocs_indexed: 0,
        correlations_created: 0,
        correlations_updated: 0,
        campaigns_detected: 0,
        campaign_alerts_created: 0,
        cleanups: 0,
        iocs_cleaned: 0
      }
    }}
  end

  # -- Detection ingestion -------------------------------------------

  @impl true
  def handle_cast({:ingest_detection, agent_id, detection}, state) do
    new_stats = Map.update!(state.stats, :detections_ingested, &(&1 + 1))

    {iocs_indexed, correlations_created, correlations_updated, campaigns_detected} =
      process_detection(agent_id, detection)

    new_stats = Map.update!(new_stats, :iocs_indexed, &(&1 + iocs_indexed))
    new_stats = Map.update!(new_stats, :correlations_created, &(&1 + correlations_created))
    new_stats = Map.update!(new_stats, :correlations_updated, &(&1 + correlations_updated))
    new_stats = Map.update!(new_stats, :campaigns_detected, &(&1 + campaigns_detected))

    {:noreply, %{state | stats: new_stats}}
  end

  # -- Stats ---------------------------------------------------------

  @impl true
  def handle_call(:stats, _from, state) do
    reply = %{
      ioc_index_size: safe_ets_size(@ioc_index_table),
      correlation_count: safe_ets_size(@correlation_table),
      counters: state.stats
    }

    {:reply, reply, state}
  end

  # -- Periodic cleanup ----------------------------------------------

  @impl true
  def handle_info(:cleanup, state) do
    {iocs_removed, correlations_removed} = cleanup_expired_entries()

    new_stats = Map.update!(state.stats, :cleanups, &(&1 + 1))
    new_stats = Map.update!(new_stats, :iocs_cleaned, &(&1 + iocs_removed))

    if iocs_removed > 0 or correlations_removed > 0 do
      Logger.info(
        "[CrossAgentCorrelator] Cleanup removed #{iocs_removed} expired IOC entries " <>
          "and #{correlations_removed} stale correlations"
      )
    end

    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Detection Processing
  # ------------------------------------------------------------------

  defp process_detection(agent_id, detection) do
    storyline_id = extract_storyline_id(detection)
    iocs = extract_iocs(detection)

    now = DateTime.utc_now()
    entry = %{agent_id: agent_id, storyline_id: storyline_id, timestamp: now}

    iocs_indexed = 0
    correlations_created = 0
    correlations_updated = 0
    campaigns_detected = 0

    {iocs_indexed, correlations_created, correlations_updated, campaigns_detected} =
      Enum.reduce(iocs, {iocs_indexed, correlations_created, correlations_updated, campaigns_detected},
        fn {ioc_type, ioc_value}, {idx, created, updated, campaigns} ->
          # Normalize the IOC value
          normalized = normalize_ioc(ioc_type, ioc_value)

          if normalized do
            key = {ioc_type, normalized}

            # Check existing entries for this IOC from OTHER agents
            existing_entries = get_ioc_entries(key)
            other_agent_entries = Enum.filter(existing_entries, fn e -> e.agent_id != agent_id end)

            # Add this entry to the IOC index
            new_entries = add_ioc_entry(key, entry, existing_entries)
            :ets.insert(@ioc_index_table, {key, new_entries})

            # If we found entries from other agents, create/update a correlation
            {c, u} = if length(other_agent_entries) > 0 do
              handle_cross_agent_match(ioc_type, normalized, entry, other_agent_entries)
            else
              {0, 0}
            end

            # Check for campaign threshold (3+ distinct agents)
            all_entries_now = [entry | existing_entries] |> Enum.uniq_by(fn e -> {e.agent_id, e.storyline_id} end)
            distinct_agents =
              all_entries_now
              |> Enum.map(& &1.agent_id)
              |> Enum.uniq()
              |> length()

            camp = if distinct_agents >= @campaign_agent_threshold do
              maybe_create_campaign_alert(ioc_type, normalized, all_entries_now)
            else
              0
            end

            {idx + 1, created + c, updated + u, campaigns + camp}
          else
            {idx, created, updated, campaigns}
          end
        end
      )

    {iocs_indexed, correlations_created, correlations_updated, campaigns_detected}
  end

  # ------------------------------------------------------------------
  # IOC Index Management
  # ------------------------------------------------------------------

  defp get_ioc_entries(key) do
    case :ets.lookup(@ioc_index_table, key) do
      [{^key, entries}] when is_list(entries) -> entries
      _ -> []
    end
  end

  defp add_ioc_entry(_key, entry, existing_entries) do
    # Deduplicate: don't add the same {agent_id, storyline_id} pair twice
    already_exists = Enum.any?(existing_entries, fn e ->
      e.agent_id == entry.agent_id and e.storyline_id == entry.storyline_id
    end)

    if already_exists do
      # Update the timestamp for the existing entry
      Enum.map(existing_entries, fn e ->
        if e.agent_id == entry.agent_id and e.storyline_id == entry.storyline_id do
          %{e | timestamp: entry.timestamp}
        else
          e
        end
      end)
    else
      [entry | existing_entries]
    end
  end

  # ------------------------------------------------------------------
  # Cross-Agent Match Handling
  # ------------------------------------------------------------------

  defp handle_cross_agent_match(ioc_type, ioc_value, new_entry, other_agent_entries) do
    # Build the full list of agent_storyline pairs
    all_entries = [new_entry | other_agent_entries]
    agent_storylines = Enum.map(all_entries, fn e ->
      %{agent_id: e.agent_id, storyline_id: e.storyline_id}
    end)
    |> Enum.uniq()

    # Check if we already have a correlation for this IOC
    existing_correlation = find_correlation_by_ioc(ioc_type, ioc_value)

    case existing_correlation do
      nil ->
        # Create new correlation
        create_correlation(ioc_type, ioc_value, agent_storylines, all_entries)
        {1, 0}

      {corr_id, corr} ->
        # Update existing correlation with new agent/storyline
        update_correlation(corr_id, corr, agent_storylines)
        {0, 1}
    end
  end

  defp create_correlation(ioc_type, ioc_value, agent_storylines, entries) do
    id = Ecto.UUID.generate()
    now = DateTime.utc_now()
    first_seen = earliest_timestamp(entries)
    confidence = calculate_confidence(agent_storylines, ioc_type)

    correlation = %CrossAgentCorrelation{
      id: id,
      ioc_type: ioc_type,
      ioc_value: ioc_value,
      agent_storylines: agent_storylines,
      first_seen_at: first_seen,
      last_seen_at: now,
      confidence: confidence
    }

    :ets.insert(@correlation_table, {id, correlation})

    Logger.info(
      "[CrossAgentCorrelator] New cross-agent correlation: #{ioc_type}=#{truncate_value(ioc_value)} " <>
        "linking #{length(agent_storylines)} agent/storyline pairs " <>
        "(confidence: #{Float.round(confidence, 3)})"
    )

    broadcast_correlation(correlation)

    correlation
  end

  defp update_correlation(corr_id, corr, new_agent_storylines) do
    now = DateTime.utc_now()
    merged = Enum.uniq(corr.agent_storylines ++ new_agent_storylines)
    confidence = calculate_confidence(merged, corr.ioc_type)

    updated = %{corr |
      agent_storylines: merged,
      last_seen_at: now,
      confidence: confidence
    }

    :ets.insert(@correlation_table, {corr_id, updated})

    broadcast_correlation(updated)

    updated
  end

  defp find_correlation_by_ioc(ioc_type, ioc_value) do
    safe_tab2list(@correlation_table)
    |> Enum.find(fn {_id, corr} ->
      corr.ioc_type == ioc_type and corr.ioc_value == ioc_value
    end)
  end

  # ------------------------------------------------------------------
  # Campaign Detection
  # ------------------------------------------------------------------

  defp maybe_create_campaign_alert(ioc_type, ioc_value, entries) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@campaign_window_seconds, :second)

    # Only consider entries within the campaign time window
    recent_entries = Enum.filter(entries, fn e ->
      DateTime.compare(e.timestamp, cutoff) != :lt
    end)

    distinct_agents =
      recent_entries
      |> Enum.map(& &1.agent_id)
      |> Enum.uniq()

    if length(distinct_agents) >= @campaign_agent_threshold do
      # Build the campaign alert
      agent_ids = distinct_agents
      storyline_ids =
        recent_entries
        |> Enum.map(& &1.storyline_id)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()

      title = build_campaign_title(ioc_type, ioc_value, length(agent_ids))
      description = build_campaign_description(ioc_type, ioc_value, agent_ids, storyline_ids)

      alert_attrs = %{
        severity: "critical",
        title: title,
        description: description,
        event_ids: [],
        mitre_tactics: campaign_tactics_for_ioc_type(ioc_type),
        mitre_techniques: campaign_techniques_for_ioc_type(ioc_type),
        threat_score: 0.95,
        detection_metadata: %{
          "rule_type" => "cross_agent_campaign",
          "rule_name" => "Cross-Agent Campaign: #{ioc_type}",
          "ioc_type" => to_string(ioc_type),
          "ioc_value" => ioc_value,
          "affected_agents" => agent_ids,
          "affected_storylines" => storyline_ids,
          "agent_count" => length(agent_ids),
          "confidence" => 0.95
        },
        evidence: %{
          "campaign_indicator" => %{
            "ioc_type" => to_string(ioc_type),
            "ioc_value" => ioc_value,
            "agent_count" => length(agent_ids),
            "agents" => agent_ids,
            "storylines" => storyline_ids
          }
        }
      }

      # Try to associate with the first agent (campaign alerts span agents)
      first_agent_id = List.first(agent_ids)
      alert_attrs = Map.put(alert_attrs, :agent_id, first_agent_id)

      org_id = try do
        TamanduaServer.Agents.OrgLookup.get_org_id(first_agent_id)
      rescue
        _ -> nil
      catch
        :exit, _ -> nil
      end

      alert_attrs = if org_id do
        Map.put(alert_attrs, :organization_id, org_id)
      else
        alert_attrs
      end

      case TamanduaServer.Alerts.create_alert(alert_attrs) do
        {:ok, alert} ->
          Logger.warning(
            "[CrossAgentCorrelator] Campaign alert created: #{alert.id} -- " <>
              "#{ioc_type}=#{truncate_value(ioc_value)} across #{length(agent_ids)} agents"
          )

          broadcast_campaign(%{
            alert_id: alert.id,
            ioc_type: ioc_type,
            ioc_value: ioc_value,
            agent_ids: agent_ids,
            storyline_ids: storyline_ids,
            detected_at: now
          })

          1

        {:error, changeset} ->
          Logger.error("[CrossAgentCorrelator] Failed to create campaign alert: #{inspect(changeset)}")
          0
      end
    else
      0
    end
  end

  # ------------------------------------------------------------------
  # IOC Extraction
  # ------------------------------------------------------------------

  @doc false
  def extract_iocs(detection) do
    payload = extract_payload(detection)
    detections_list = detection[:detections] || []

    iocs = []

    # SHA256 hash
    iocs = case extract_hash(payload, detections_list) do
      nil -> iocs
      hash -> [{:hash, hash} | iocs]
    end

    # Source IP
    iocs = case extract_field(payload, ["source_ip", "src_ip", "local_ip"]) do
      nil -> iocs
      ip when ip in ["127.0.0.1", "::1", "0.0.0.0"] -> iocs
      ip -> [{:ip, ip} | iocs]
    end

    # Destination IP
    iocs = case extract_field(payload, ["remote_ip", "dest_ip", "destination_ip", "dst_ip"]) do
      nil -> iocs
      ip when ip in ["127.0.0.1", "::1", "0.0.0.0"] -> iocs
      ip ->
        if private_ip?(ip), do: iocs, else: [{:ip, ip} | iocs]
    end

    # Domain
    iocs = case extract_domain_ioc(payload) do
      nil -> iocs
      domain ->
        if trusted_domain?(domain), do: iocs, else: [{:domain, domain} | iocs]
    end

    # URL
    iocs = case extract_field(payload, ["url", "request_url"]) do
      nil -> iocs
      url -> [{:url, url} | iocs]
    end

    # Also extract IOCs from nested detection metadata
    iocs = iocs ++ extract_iocs_from_detections(detections_list)

    # Deduplicate
    Enum.uniq(iocs)
  end

  defp extract_payload(detection) do
    raw = detection[:payload] || detection["payload"] || detection[:raw_event] || %{}

    if is_map(raw), do: raw, else: %{}
  end

  defp extract_hash(payload, detections_list) do
    # Try payload first
    hash = extract_field(payload, ["sha256", "file_hash", "hash"])

    # Fall back to detection metadata
    hash = if is_nil(hash) do
      Enum.find_value(detections_list, fn d ->
        d[:sha256] || d[:file_hash] || d[:hash]
      end)
    else
      hash
    end

    normalize_hash(hash)
  end

  defp extract_domain_ioc(payload) do
    cond do
      query = extract_field(payload, ["query", "dns_query"]) -> query
      domain = extract_field(payload, ["domain", "hostname", "server_name"]) -> domain
      url = extract_field(payload, ["url"]) ->
        case URI.parse(to_string(url)) do
          %URI{host: host} when is_binary(host) and host != "" -> host
          _ -> nil
        end
      true -> nil
    end
  end

  defp extract_iocs_from_detections(detections_list) when is_list(detections_list) do
    Enum.flat_map(detections_list, fn d ->
      iocs = []

      iocs = case d[:sha256] || d[:file_hash] do
        nil -> iocs
        hash ->
          case normalize_hash(hash) do
            nil -> iocs
            h -> [{:hash, h} | iocs]
          end
      end

      iocs = case d[:remote_ip] || d[:dest_ip] do
        nil -> iocs
        ip -> [{:ip, to_string(ip)} | iocs]
      end

      iocs = case d[:domain] do
        nil -> iocs
        domain -> [{:domain, to_string(domain)} | iocs]
      end

      iocs
    end)
  end

  defp extract_iocs_from_detections(_), do: []

  defp extract_field(payload, field_names) when is_map(payload) do
    Enum.find_value(field_names, fn name ->
      value = payload[name] || payload[String.to_atom(name)]

      case value do
        nil -> nil
        v when is_binary(v) and v != "" -> v
        _ -> nil
      end
    end)
  end

  defp extract_field(_, _), do: nil

  defp extract_storyline_id(detection) do
    detection[:storyline_id] ||
      detection["storyline_id"] ||
      get_in(detection, [:detection_metadata, "storyline_id"]) ||
      get_in(detection, [:detection_metadata, :storyline_id])
  end

  # ------------------------------------------------------------------
  # IOC Normalization
  # ------------------------------------------------------------------

  defp normalize_ioc(:hash, value), do: normalize_hash(value)
  defp normalize_ioc(:ip, value) when is_binary(value), do: String.trim(value)
  defp normalize_ioc(:domain, value) when is_binary(value), do: String.downcase(String.trim(value))
  defp normalize_ioc(:url, value) when is_binary(value), do: String.trim(value)
  defp normalize_ioc(_, _), do: nil

  defp normalize_hash(nil), do: nil

  defp normalize_hash(hash) when is_binary(hash) do
    cleaned = hash |> String.trim() |> String.downcase()

    # Validate it looks like a hex hash (SHA256 = 64 chars)
    if Regex.match?(~r/^[a-f0-9]{64}$/, cleaned) do
      cleaned
    else
      # Try to encode as hex if it's raw bytes
      if byte_size(hash) == 32 do
        Base.encode16(hash, case: :lower)
      else
        nil
      end
    end
  end

  defp normalize_hash(_), do: nil

  # ------------------------------------------------------------------
  # Confidence Calculation
  # ------------------------------------------------------------------

  defp calculate_confidence(agent_storylines, ioc_type) do
    distinct_agents =
      agent_storylines
      |> Enum.map(& &1.agent_id)
      |> Enum.uniq()
      |> length()

    distinct_storylines =
      agent_storylines
      |> Enum.map(& &1.storyline_id)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> length()

    # Base confidence from number of agents
    agent_factor = min(distinct_agents / 5.0, 1.0)

    # Storyline bonus: more storylines = higher confidence
    storyline_factor = min(distinct_storylines / 8.0, 1.0)

    # IOC type weight: hashes are more specific than IPs
    type_weight = case ioc_type do
      :hash -> 0.95
      :domain -> 0.80
      :url -> 0.85
      :ip -> 0.70
    end

    # Combine: weighted average of agent spread and storyline depth
    raw = (agent_factor * 0.50 + storyline_factor * 0.25 + type_weight * 0.25)

    # Clamp to [0.1, 1.0]
    Float.round(max(0.1, min(raw, 1.0)), 4)
  end

  # ------------------------------------------------------------------
  # Campaign Grouping
  # ------------------------------------------------------------------

  defp group_into_campaigns(correlations) do
    # Group correlations that share at least one agent into campaign clusters.
    # This uses a simple union-find approach: if correlation A and correlation B
    # both involve agent X, they belong to the same campaign.

    if Enum.empty?(correlations) do
      []
    else
      # Build agent -> correlation_index mapping
      indexed = Enum.with_index(correlations)

      agent_to_indices = Enum.reduce(indexed, %{}, fn {corr, idx}, acc ->
        agents = corr.agent_storylines |> Enum.map(& &1.agent_id) |> Enum.uniq()
        Enum.reduce(agents, acc, fn agent, inner_acc ->
          Map.update(inner_acc, agent, [idx], fn existing -> [idx | existing] end)
        end)
      end)

      # Union-find: group indices that share agents
      groups = union_find_groups(agent_to_indices, length(correlations))

      # Build campaign summaries from groups
      Enum.map(groups, fn group_indices ->
        group_corrs = Enum.map(group_indices, fn idx ->
          {corr, _} = Enum.at(indexed, idx)
          corr
        end)

        build_campaign_summary(group_corrs)
      end)
      |> Enum.sort_by(fn c -> c.agent_count end, :desc)
    end
  end

  defp union_find_groups(agent_to_indices, total_count) do
    # Initialize parent array (each element is its own parent)
    parent = Enum.into(0..(total_count - 1), %{}, fn i -> {i, i} end)

    # For each agent, union all correlation indices that share that agent
    parent = Enum.reduce(agent_to_indices, parent, fn {_agent, indices}, p ->
      case indices do
        [_single] -> p
        [first | rest] ->
          Enum.reduce(rest, p, fn idx, acc ->
            union(acc, first, idx)
          end)
      end
    end)

    # Collect groups by root
    0..(total_count - 1)
    |> Enum.group_by(fn i -> find_root(parent, i) end)
    |> Map.values()
  end

  defp find_root(parent, i) do
    p = Map.get(parent, i, i)
    if p == i, do: i, else: find_root(parent, p)
  end

  defp union(parent, a, b) do
    root_a = find_root(parent, a)
    root_b = find_root(parent, b)

    if root_a == root_b do
      parent
    else
      Map.put(parent, root_b, root_a)
    end
  end

  defp build_campaign_summary(correlations) do
    all_agents =
      correlations
      |> Enum.flat_map(fn c -> Enum.map(c.agent_storylines, & &1.agent_id) end)
      |> Enum.uniq()

    all_storylines =
      correlations
      |> Enum.flat_map(fn c -> Enum.map(c.agent_storylines, & &1.storyline_id) end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    shared_iocs = Enum.map(correlations, fn c ->
      %{type: c.ioc_type, value: c.ioc_value}
    end)

    first_seen = correlations
      |> Enum.map(& &1.first_seen_at)
      |> Enum.min(DateTime)

    last_seen = correlations
      |> Enum.map(& &1.last_seen_at)
      |> Enum.max(DateTime)

    avg_confidence = correlations
      |> Enum.map(& &1.confidence)
      |> then(fn confs ->
        if length(confs) > 0, do: Enum.sum(confs) / length(confs), else: 0.0
      end)

    %{
      agent_ids: all_agents,
      agent_count: length(all_agents),
      storyline_ids: all_storylines,
      storyline_count: length(all_storylines),
      shared_iocs: shared_iocs,
      ioc_count: length(shared_iocs),
      correlation_ids: Enum.map(correlations, & &1.id),
      first_seen_at: first_seen,
      last_seen_at: last_seen,
      confidence: Float.round(avg_confidence, 4)
    }
  end

  # ------------------------------------------------------------------
  # Cleanup
  # ------------------------------------------------------------------

  defp cleanup_expired_entries do
    cutoff = DateTime.utc_now() |> DateTime.add(-@ioc_ttl_seconds, :second)

    # Clean IOC index: remove entries older than 48 hours
    iocs_removed =
      safe_tab2list(@ioc_index_table)
      |> Enum.reduce(0, fn {key, entries}, removed ->
        filtered = Enum.filter(entries, fn e ->
          DateTime.compare(e.timestamp, cutoff) != :lt
        end)

        cond do
          # All entries expired -> delete the key
          Enum.empty?(filtered) ->
            :ets.delete(@ioc_index_table, key)
            removed + length(entries)

          # Some entries expired -> update
          length(filtered) < length(entries) ->
            :ets.insert(@ioc_index_table, {key, filtered})
            removed + (length(entries) - length(filtered))

          # No entries expired
          true ->
            removed
        end
      end)

    # Clean correlations: remove those where all agent_storylines entries
    # reference IOCs that no longer exist in the index
    correlations_removed =
      safe_tab2list(@correlation_table)
      |> Enum.reduce(0, fn {id, corr}, removed ->
        key = {corr.ioc_type, corr.ioc_value}
        remaining_entries = get_ioc_entries(key)

        if Enum.empty?(remaining_entries) and
             DateTime.compare(corr.last_seen_at, cutoff) == :lt do
          :ets.delete(@correlation_table, id)
          removed + 1
        else
          removed
        end
      end)

    {iocs_removed, correlations_removed}
  end

  # ------------------------------------------------------------------
  # Campaign Alert Helpers
  # ------------------------------------------------------------------

  defp build_campaign_title(ioc_type, ioc_value, agent_count) do
    type_label = case ioc_type do
      :hash -> "File Hash"
      :ip -> "IP Address"
      :domain -> "Domain"
      :url -> "URL"
    end

    "Cross-Agent Campaign: #{type_label} #{truncate_value(ioc_value)} across #{agent_count} endpoints"
  end

  defp build_campaign_description(ioc_type, ioc_value, agent_ids, storyline_ids) do
    type_label = case ioc_type do
      :hash -> "file hash"
      :ip -> "IP address"
      :domain -> "domain"
      :url -> "URL"
    end

    """
    Cross-Agent Campaign Detection: The same #{type_label} has been observed on #{length(agent_ids)} distinct endpoints, indicating a coordinated attack or campaign.

    Indicator: #{ioc_value}
    Type: #{ioc_type}
    Affected Endpoints: #{length(agent_ids)}
    Agent IDs: #{Enum.join(agent_ids, ", ")}
    Linked Storylines: #{length(storyline_ids)}

    This correlation was automatically detected by the Cross-Agent Correlation Engine. Immediate investigation is recommended to determine the scope and impact of this campaign.
    """
    |> String.trim()
  end

  defp campaign_tactics_for_ioc_type(ioc_type) do
    case ioc_type do
      :hash -> ["execution", "lateral-movement"]
      :ip -> ["command-and-control", "lateral-movement"]
      :domain -> ["command-and-control"]
      :url -> ["command-and-control", "initial-access"]
    end
  end

  defp campaign_techniques_for_ioc_type(ioc_type) do
    case ioc_type do
      :hash -> ["T1570", "T1204"]
      :ip -> ["T1071", "T1021"]
      :domain -> ["T1071.001", "T1568"]
      :url -> ["T1071.001", "T1566.002"]
    end
  end

  # ------------------------------------------------------------------
  # PubSub Broadcasts
  # ------------------------------------------------------------------

  defp broadcast_correlation(correlation) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cross_agent:correlations",
      {:cross_agent_correlation, serialize_correlation(correlation)}
    )
  rescue
    _ -> :ok
  end

  defp broadcast_campaign(campaign_data) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cross_agent:campaigns",
      {:cross_agent_campaign, campaign_data}
    )
  rescue
    _ -> :ok
  end

  # ------------------------------------------------------------------
  # Serialization
  # ------------------------------------------------------------------

  defp serialize_correlation(c) when is_map(c) do
    %{
      id: c.id,
      ioc_type: c.ioc_type,
      ioc_value: c.ioc_value,
      agent_storylines: c.agent_storylines,
      first_seen_at: c.first_seen_at,
      last_seen_at: c.last_seen_at,
      confidence: c.confidence,
      agent_count: c.agent_storylines |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length(),
      storyline_count: c.agent_storylines |> Enum.map(& &1.storyline_id) |> Enum.reject(&is_nil/1) |> Enum.uniq() |> length()
    }
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  defp earliest_timestamp(entries) do
    entries
    |> Enum.map(& &1.timestamp)
    |> Enum.min(DateTime, fn -> DateTime.utc_now() end)
  end

  defp truncate_value(value) when is_binary(value) and byte_size(value) > 40 do
    String.slice(value, 0, 20) <> "..." <> String.slice(value, -16, 16)
  end

  defp truncate_value(value) when is_binary(value), do: value
  defp truncate_value(value), do: inspect(value)

  defp private_ip?(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      {:ok, {127, _, _, _}} -> true
      {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
      _ -> false
    end
  end

  defp private_ip?(_), do: false

  # Common trusted domains that should not trigger cross-agent correlations.
  # These are high-volume infrastructure domains that many agents will contact
  # independently, producing false-positive correlations.
  @trusted_domains [
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com",
    "live.com", "outlook.com", "azure.com", "azureedge.net", "msedge.net",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "cloudflare.com", "cloudflare-dns.com",
    "amazonaws.com", "aws.amazon.com", "cloudfront.net",
    "github.com", "githubusercontent.com",
    "akamai.net", "akamaized.net", "akadns.net",
    "apple.com", "icloud.com",
    "mozilla.org", "mozilla.net",
    "digicert.com", "letsencrypt.org", "verisign.com",
    "ubuntu.com", "debian.org",
    "docker.com", "docker.io",
    "npmjs.org", "pypi.org", "crates.io", "hex.pm"
  ]

  defp trusted_domain?(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)

    Enum.any?(@trusted_domains, fn trusted ->
      domain_lower == trusted or String.ends_with?(domain_lower, "." <> trusted)
    end)
  end

  defp trusted_domain?(_), do: false

  defp safe_tab2list(table) do
    try do
      :ets.tab2list(table)
    rescue
      ArgumentError -> []
    end
  end

  defp safe_ets_size(table) do
    try do
      :ets.info(table, :size)
    rescue
      ArgumentError -> 0
    end
  end
end
