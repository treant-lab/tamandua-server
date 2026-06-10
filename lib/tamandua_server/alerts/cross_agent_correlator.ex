defmodule TamanduaServer.Alerts.CrossAgentCorrelator do
  @moduledoc """
  Cross-agent alert correlation engine.

  Features:
  - Temporal pattern matching
  - Probabilistic alert grouping
  - Attack chain detection
  - Network graph analysis
  - Adaptive deduplication windows
  - Campaign tracking
  """
  use GenServer
  require Logger

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, AlertCorrelation, AttackCampaign, CampaignAlert, Timestamp}
  alias TamanduaServer.Agents.Agent

  @default_time_window_minutes 30
  @default_similarity_threshold 0.7
  # Run correlation every minute
  @correlation_interval_ms 60_000

  # MITRE technique rarity scores (lower = rarer, higher weight)
  @technique_rarity %{
    # Very rare techniques (high weight)
    # Process Injection
    "T1055" => 0.1,
    # Credential Dumping
    "T1003" => 0.15,
    # Obfuscated Files
    "T1027" => 0.2,
    # Data Encrypted for Impact
    "T1486" => 0.1,
    # Exfiltration Over Alternative Protocol
    "T1048" => 0.15,
    # Common techniques (low weight)
    # Command Line Interface
    "T1059" => 0.6,
    # Application Layer Protocol
    "T1071" => 0.5,
    # Ingress Tool Transfer
    "T1105" => 0.4
  }

  # Attack chain patterns (sequences of tactics)
  @attack_patterns %{
    lateral_movement: [:credential_access, :lateral_movement, :execution],
    ransomware: [:initial_access, :execution, :impact],
    exfiltration: [:collection, :exfiltration],
    full_kill_chain: [
      :initial_access,
      :execution,
      :persistence,
      :privilege_escalation,
      :defense_evasion,
      :credential_access,
      :discovery,
      :lateral_movement,
      :collection,
      :exfiltration,
      :impact
    ],
    credential_theft: [:credential_access, :collection],
    persistence_escalation: [:persistence, :privilege_escalation],
    reconnaissance: [:reconnaissance, :discovery]
  }

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Find alerts related to the given alert within a time window.

  ## Options
  - `:time_window_minutes` - Time window in minutes (default: 30)
  - `:threshold` - Minimum similarity threshold (default: 0.7)
  - `:organization_id` - Filter by organization
  """
  def find_related_alerts(alert, opts \\ []) do
    GenServer.call(__MODULE__, {:find_related, alert, opts}, 30_000)
  end

  @doc """
  Correlate a newly created alert with existing alerts.
  Returns {:ok, correlations} or {:error, reason}.
  """
  def correlate_alert(alert) do
    GenServer.cast(__MODULE__, {:correlate, alert})
  end

  @doc """
  Run full correlation analysis for all recent alerts.
  """
  def run_correlation(opts \\ []) do
    GenServer.cast(__MODULE__, {:run_correlation, opts})
  end

  @doc """
  Detect attack chains in a set of alerts.
  """
  def detect_attack_chains(alerts) when is_list(alerts) do
    GenServer.call(__MODULE__, {:detect_chains, alerts}, 30_000)
  end

  @doc """
  Build network graph for a campaign or set of alerts.
  """
  def build_network_graph(alert_ids) when is_list(alert_ids) do
    GenServer.call(__MODULE__, {:build_graph, alert_ids}, 30_000)
  end

  @doc """
  Get adaptive dedup window for a technique.
  """
  def get_dedup_window(technique, organization_id) do
    GenServer.call(__MODULE__, {:get_dedup_window, technique, organization_id})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Schedule periodic correlation
    schedule_correlation()

    state = %{
      last_correlation: nil,
      stats: %{
        correlations_created: 0,
        campaigns_detected: 0
      }
    }

    Logger.info("[CrossAgentCorrelator] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:find_related, alert, opts}, _from, state) do
    result = do_find_related_alerts(alert, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:detect_chains, alerts}, _from, state) do
    result = do_detect_attack_chains(alerts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:build_graph, alert_ids}, _from, state) do
    result = do_build_network_graph(alert_ids)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_dedup_window, technique, org_id}, _from, state) do
    result = do_get_dedup_window(technique, org_id)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:correlate, alert}, state) do
    spawn(fn -> do_correlate_alert(alert) end)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:run_correlation, opts}, state) do
    spawn(fn -> do_run_correlation(opts) end)
    {:noreply, %{state | last_correlation: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:correlate, state) do
    # Periodic correlation run
    spawn(fn -> do_run_correlation([]) end)
    schedule_correlation()
    {:noreply, %{state | last_correlation: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp schedule_correlation do
    Process.send_after(self(), :correlate, @correlation_interval_ms)
  end

  defp do_find_related_alerts(alert, opts) do
    time_window = Keyword.get(opts, :time_window_minutes, @default_time_window_minutes)
    threshold = Keyword.get(opts, :threshold, @default_similarity_threshold)
    organization_id = Keyword.get(opts, :organization_id) || alert.organization_id

    time_start = DateTime.add(alert.inserted_at, -time_window * 60, :second)
    time_end = DateTime.add(alert.inserted_at, time_window * 60, :second)

    # Query alerts in time window
    query =
      from(a in Alert,
        where: a.id != ^alert.id,
        where: a.inserted_at >= ^time_start and a.inserted_at <= ^time_end,
        where: a.organization_id == ^organization_id,
        order_by: [desc: :inserted_at],
        limit: 100,
        preload: [:agent]
      )

    candidates = Repo.all(query)

    # Score and filter candidates
    scored_alerts =
      candidates
      |> Enum.map(fn candidate ->
        score = calculate_similarity(alert, candidate)
        {candidate, score}
      end)
      |> Enum.filter(fn {_alert, score} -> score >= threshold end)
      |> Enum.filter(fn {candidate, _score} -> correlation_allowed?(alert, candidate) end)
      |> Enum.sort_by(fn {_alert, score} -> -score end)

    {:ok, scored_alerts}
  end

  defp calculate_similarity(alert1, alert2) do
    # Calculate weighted similarity score based on multiple factors

    # 1. Shared MITRE techniques (weighted by rarity)
    technique_score =
      calculate_technique_similarity(
        alert1.mitre_techniques || [],
        alert2.mitre_techniques || []
      )

    # 2. Shared IOCs (from evidence)
    ioc_score =
      calculate_ioc_similarity(
        alert1.evidence || %{},
        alert2.evidence || %{}
      )

    # 3. Network proximity
    network_score = calculate_network_proximity(alert1, alert2)

    # 4. Temporal proximity (within same hour = higher score)
    temporal_score = calculate_temporal_proximity(alert1.inserted_at, alert2.inserted_at)

    # 5. Same user or process
    entity_score =
      calculate_entity_similarity(
        alert1.evidence || %{},
        alert2.evidence || %{}
      )

    # Weighted average
    technique_weight = 0.25
    ioc_weight = 0.35
    network_weight = 0.05
    temporal_weight = 0.10
    entity_weight = 0.25

    technique_score * technique_weight +
      ioc_score * ioc_weight +
      network_score * network_weight +
      temporal_score * temporal_weight +
      entity_score * entity_weight
  end

  defp calculate_technique_similarity(techniques1, techniques2) do
    if techniques1 == [] or techniques2 == [] do
      0.0
    else
      # Find shared techniques
      shared =
        MapSet.intersection(MapSet.new(techniques1), MapSet.new(techniques2))
        |> MapSet.to_list()

      if shared == [] do
        0.0
      else
        # Weight by rarity
        weighted_score =
          Enum.reduce(shared, 0.0, fn tech, acc ->
            rarity = Map.get(@technique_rarity, tech, 0.3)
            # Lower rarity = higher weight (invert it)
            weight = 1.0 - rarity
            acc + weight
          end)

        # Normalize by total techniques
        total = max(length(techniques1), length(techniques2))
        min(weighted_score / total, 1.0)
      end
    end
  end

  defp calculate_ioc_similarity(evidence1, evidence2) do
    # Extract IOCs from evidence
    iocs1 = extract_iocs_from_evidence(evidence1)
    iocs2 = extract_iocs_from_evidence(evidence2)

    if MapSet.size(iocs1) == 0 or MapSet.size(iocs2) == 0 do
      0.0
    else
      shared = MapSet.intersection(iocs1, iocs2)
      total = MapSet.union(iocs1, iocs2)

      MapSet.size(shared) / MapSet.size(total)
    end
  end

  defp extract_iocs_from_evidence(evidence) do
    []
    |> add_file_hash_iocs(evidence["file_hashes"] || evidence[:file_hashes])
    |> add_network_iocs(evidence["network"] || evidence[:network])
    |> add_process_iocs(evidence["process"] || evidence[:process])
    |> add_dns_iocs(evidence["dns"] || evidence[:dns])
    |> MapSet.new()
  end

  defp add_file_hash_iocs(iocs, file_hashes) when is_map(file_hashes) do
    Enum.filter(Map.values(file_hashes), &present?/1) ++ iocs
  end

  defp add_file_hash_iocs(iocs, _), do: iocs

  defp add_network_iocs(iocs, network) when is_map(network) do
    iocs
    |> maybe_add_strong_ip_ioc(network["remote_ip"] || network[:remote_ip])
    |> maybe_add_strong_dns_ioc(network["domain"] || network[:domain])
  end

  defp add_network_iocs(iocs, _), do: iocs

  defp add_process_iocs(iocs, process) when is_map(process) do
    sha256 = process["sha256"] || process[:sha256]
    if present?(sha256), do: [sha256 | iocs], else: iocs
  end

  defp add_process_iocs(iocs, _), do: iocs

  defp add_dns_iocs(iocs, dns) when is_map(dns) do
    maybe_add_strong_dns_ioc(iocs, dns["query"] || dns[:query])
  end

  defp add_dns_iocs(iocs, _), do: iocs

  defp maybe_add_strong_ip_ioc(iocs, value) do
    if present?(value) and public_ip?(value), do: [value | iocs], else: iocs
  end

  defp maybe_add_strong_dns_ioc(iocs, value) do
    if strong_domain_or_public_ip?(value), do: [String.downcase(value) | iocs], else: iocs
  end

  defp calculate_network_proximity(alert1, alert2) do
    # Load agents with IP addresses
    agent1 = if alert1.agent_id, do: Repo.get(Agent, alert1.agent_id), else: nil
    agent2 = if alert2.agent_id, do: Repo.get(Agent, alert2.agent_id), else: nil

    cond do
      # Same agent
      alert1.agent_id == alert2.agent_id ->
        0.2

      # Both have IPs
      agent1 && agent2 && agent1.ip_address && agent2.ip_address ->
        cond do
          same_subnet?(agent1.ip_address, agent2.ip_address) and
            public_ip?(agent1.ip_address) and public_ip?(agent2.ip_address) ->
            0.3

          same_subnet?(agent1.ip_address, agent2.ip_address) ->
            0.1

          true ->
            0.0
        end

      # No network data
      true ->
        0.0
    end
  end

  defp same_subnet?(ip1, ip2) do
    case {parse_ipv4(ip1), parse_ipv4(ip2)} do
      {{a1, b1, c1, _}, {a2, b2, c2, _}} -> {a1, b1, c1} == {a2, b2, c2}
      _ -> false
    end
  end

  defp public_ip?(value) do
    match?({_, _, _, _}, parse_ipv4(value)) and not private_or_local_ip?(value)
  end

  defp private_or_local_ip?(value) do
    case parse_ipv4(value) do
      {10, _, _, _} -> true
      {127, _, _, _} -> true
      {169, 254, _, _} -> true
      {172, b, _, _} when b >= 16 and b <= 31 -> true
      {192, 0, 2, _} -> true
      {192, 168, _, _} -> true
      {198, b, _, _} when b >= 18 and b <= 19 -> true
      {198, 51, 100, _} -> true
      {203, 0, 113, _} -> true
      {100, b, _, _} when b >= 64 and b <= 127 -> true
      {0, _, _, _} -> true
      {a, _, _, _} when a >= 224 -> true
      {_a, _b, _c, _d} -> false
      nil -> false
    end
  end

  defp parse_ipv4(value) when is_binary(value) do
    parts = String.split(value, ".")

    with [a, b, c, d] <- parts,
         {a_int, ""} <- Integer.parse(a),
         {b_int, ""} <- Integer.parse(b),
         {c_int, ""} <- Integer.parse(c),
         {d_int, ""} <- Integer.parse(d),
         true <- Enum.all?([a_int, b_int, c_int, d_int], &(&1 >= 0 and &1 <= 255)) do
      {a_int, b_int, c_int, d_int}
    else
      _ -> nil
    end
  end

  defp parse_ipv4(_), do: nil

  defp calculate_temporal_proximity(time1, time2) do
    diff_seconds = abs(Timestamp.diff(time1, time2, :second) || 86_400)

    cond do
      # < 5 minutes
      diff_seconds < 300 -> 1.0
      # < 15 minutes
      diff_seconds < 900 -> 0.8
      # < 30 minutes
      diff_seconds < 1800 -> 0.6
      # < 1 hour
      diff_seconds < 3600 -> 0.4
      true -> 0.2
    end
  end

  defp calculate_entity_similarity(evidence1, evidence2) do
    user1 = get_in(evidence1, ["process", "user"]) || get_in(evidence1, [:process, :user])
    user2 = get_in(evidence2, ["process", "user"]) || get_in(evidence2, [:process, :user])

    # Same process name
    name1 = get_in(evidence1, ["process", "name"]) || get_in(evidence1, [:process, :name])
    name2 = get_in(evidence2, ["process", "name"]) || get_in(evidence2, [:process, :name])

    # Same file path
    path1 = get_in(evidence1, ["file", "path"]) || get_in(evidence1, [:file, :path])
    path2 = get_in(evidence2, ["file", "path"]) || get_in(evidence2, [:file, :path])

    scores =
      []
      |> maybe_add_entity_score(present?(user1) and user1 == user2, 0.5)
      |> maybe_add_entity_score(
        present?(name1) and name1 == name2 and not common_process_name?(name1),
        0.2
      )
      |> maybe_add_entity_score(
        present?(path1) and path1 == path2 and meaningful_file_path?(path1),
        0.9
      )

    if scores == [] do
      0.0
    else
      Enum.sum(scores) / length(scores)
    end
  end

  defp maybe_add_entity_score(scores, true, score), do: [score | scores]
  defp maybe_add_entity_score(scores, _, _), do: scores

  defp correlation_allowed?(alert1, alert2) do
    has_shared_iocs?(alert1, alert2) or
      same_process_hash?(alert1, alert2) or
      same_file_path?(alert1, alert2) or
      (has_shared_rare_technique?(alert1, alert2) and has_supporting_context?(alert1, alert2))
  end

  defp has_supporting_context?(alert1, alert2) do
    same_user?(alert1, alert2) or
      same_non_common_process_name?(alert1, alert2) or
      same_agent_close_in_time?(alert1, alert2)
  end

  defp same_user?(alert1, alert2) do
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}
    user1 = get_in(evidence1, ["process", "user"]) || get_in(evidence1, [:process, :user])
    user2 = get_in(evidence2, ["process", "user"]) || get_in(evidence2, [:process, :user])

    present?(user1) and user1 == user2
  end

  defp same_process_hash?(alert1, alert2) do
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}
    hash1 = get_in(evidence1, ["process", "sha256"]) || get_in(evidence1, [:process, :sha256])
    hash2 = get_in(evidence2, ["process", "sha256"]) || get_in(evidence2, [:process, :sha256])

    present?(hash1) and hash1 == hash2
  end

  defp same_file_path?(alert1, alert2) do
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}
    path1 = get_in(evidence1, ["file", "path"]) || get_in(evidence1, [:file, :path])
    path2 = get_in(evidence2, ["file", "path"]) || get_in(evidence2, [:file, :path])

    present?(path1) and path1 == path2 and meaningful_file_path?(path1)
  end

  defp same_non_common_process_name?(alert1, alert2) do
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}
    name1 = get_in(evidence1, ["process", "name"]) || get_in(evidence1, [:process, :name])
    name2 = get_in(evidence2, ["process", "name"]) || get_in(evidence2, [:process, :name])

    present?(name1) and name1 == name2 and not common_process_name?(name1)
  end

  defp same_agent_close_in_time?(alert1, alert2) do
    alert1.agent_id == alert2.agent_id and
      abs(Timestamp.diff(alert1.inserted_at, alert2.inserted_at, :second) || 86_400) < 300
  end

  defp has_shared_rare_technique?(alert1, alert2) do
    shared =
      MapSet.intersection(
        MapSet.new(alert1.mitre_techniques || []),
        MapSet.new(alert2.mitre_techniques || [])
      )

    Enum.any?(shared, fn technique ->
      Map.get(@technique_rarity, technique, 0.3) <= 0.2
    end)
  end

  defp common_process_name?(name) when is_binary(name) do
    normalized =
      name
      |> String.replace("\\", "/")
      |> Path.basename()
      |> String.downcase()

    normalized in [
      "cmd.exe",
      "powershell.exe",
      "pwsh.exe",
      "conhost.exe",
      "svchost.exe",
      "explorer.exe",
      "chrome.exe",
      "msedge.exe",
      "firefox.exe",
      "rundll32.exe",
      "regsvr32.exe",
      "wmic.exe",
      "python.exe",
      "node.exe"
    ]
  end

  defp common_process_name?(_), do: false

  defp strong_domain_or_public_ip?(value) when is_binary(value) do
    normalized =
      value
      |> String.trim()
      |> String.trim_trailing(".")
      |> String.downcase()

    cond do
      normalized == "" -> false
      public_ip?(normalized) -> true
      private_or_local_ip?(normalized) -> false
      String.ends_with?(normalized, ".local") -> false
      String.ends_with?(normalized, ".lan") -> false
      normalized in ["localhost", "broadcasthost"] -> false
      common_domain?(normalized) -> false
      true -> String.contains?(normalized, ".")
    end
  end

  defp strong_domain_or_public_ip?(_), do: false

  defp common_domain?(domain) do
    domain in [
      "apple.com",
      "icloud.com",
      "microsoft.com",
      "windows.com",
      "google.com",
      "gstatic.com",
      "googleapis.com",
      "spotify.com",
      "office.com",
      "live.com"
    ] or
      String.ends_with?(domain, ".apple.com") or
      String.ends_with?(domain, ".icloud.com") or
      String.ends_with?(domain, ".microsoft.com") or
      String.ends_with?(domain, ".windows.com") or
      String.ends_with?(domain, ".google.com") or
      String.ends_with?(domain, ".gstatic.com") or
      String.ends_with?(domain, ".googleapis.com") or
      String.ends_with?(domain, ".spotify.com") or
      String.ends_with?(domain, ".office.com") or
      String.ends_with?(domain, ".live.com")
  end

  defp meaningful_file_path?(path) when is_binary(path) do
    normalized =
      path
      |> String.replace("\\", "/")
      |> String.downcase()

    present?(Path.basename(normalized)) and
      not String.contains?(normalized, "/library/caches/") and
      not String.contains?(normalized, "/appdata/local/temp/") and
      not String.contains?(normalized, "/appdata/local/microsoft/") and
      not String.contains?(normalized, "/appdata/local/google/") and
      not String.contains?(normalized, "/appdata/local/packages/") and
      not String.contains?(normalized, "/windows/temp/") and
      not String.contains?(normalized, "/tmp/")
  end

  defp meaningful_file_path?(_), do: false

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(value), do: not is_nil(value)

  defp do_correlate_alert(alert) do
    try do
      # Find related alerts
      {:ok, related} = do_find_related_alerts(alert, [])

      eligible_related =
        Enum.filter(related, fn {related_alert, _score} ->
          correlation_allowed?(alert, related_alert)
        end)

      # Create correlation records
      Enum.each(eligible_related, fn {related_alert, score} ->
        create_correlation(alert, related_alert, score)
      end)

      # Check if this alert should be added to an existing campaign
      maybe_add_to_campaign(alert, eligible_related)

      Logger.debug(
        "[CrossAgentCorrelator] Correlated alert #{alert.id} with #{length(eligible_related)} alerts"
      )
    rescue
      e ->
        Logger.error(
          "[CrossAgentCorrelator] Failed to correlate alert #{alert.id}: #{inspect(e)}"
        )
    end
  end

  defp create_correlation(alert1, alert2, score) do
    if correlation_allowed?(alert1, alert2) do
      # Determine correlation type
      correlation_type = determine_correlation_type(alert1, alert2)

      # Build metadata
      metadata = build_correlation_metadata(alert1, alert2)

      attrs = %{
        alert_id: alert1.id,
        related_alert_id: alert2.id,
        correlation_type: correlation_type,
        confidence: score,
        similarity_score: score,
        metadata: metadata,
        organization_id: alert1.organization_id
      }

      case Repo.insert(%AlertCorrelation{} |> AlertCorrelation.changeset(attrs)) do
        {:ok, _correlation} ->
          :ok

        {:error, changeset} ->
          # Ignore duplicate constraint errors
          if changeset.errors[:alert_id] do
            :ok
          else
            Logger.warning(
              "[CrossAgentCorrelator] Failed to create correlation: #{inspect(changeset.errors)}"
            )
          end
      end
    end
  end

  defp determine_correlation_type(alert1, alert2) do
    cond do
      # Same IOCs = IOC correlation
      has_shared_iocs?(alert1, alert2) -> "ioc"
      # Same techniques = technique correlation
      has_shared_techniques?(alert1, alert2) -> "technique"
      # Network proximity = network correlation
      alert1.agent_id == alert2.agent_id -> "network"
      # Time proximity = temporal correlation
      true -> "temporal"
    end
  end

  defp has_shared_techniques?(alert1, alert2) do
    techniques1 = MapSet.new(alert1.mitre_techniques || [])
    techniques2 = MapSet.new(alert2.mitre_techniques || [])
    MapSet.size(MapSet.intersection(techniques1, techniques2)) > 0
  end

  defp has_shared_iocs?(alert1, alert2) do
    iocs1 = extract_iocs_from_evidence(alert1.evidence || %{})
    iocs2 = extract_iocs_from_evidence(alert2.evidence || %{})
    MapSet.size(MapSet.intersection(iocs1, iocs2)) > 0
  end

  defp extract_weak_iocs_from_evidence(evidence) do
    weak_iocs = []

    weak_iocs =
      case evidence["network"] || evidence[:network] do
        nil ->
          weak_iocs

        network ->
          remote_ip = network["remote_ip"] || network[:remote_ip]

          if private_or_local_ip?(remote_ip), do: [remote_ip | weak_iocs], else: weak_iocs
      end

    weak_iocs =
      case evidence["dns"] || evidence[:dns] do
        nil ->
          weak_iocs

        dns ->
          query = dns["query"] || dns[:query]

          if private_or_local_ip?(query), do: [query | weak_iocs], else: weak_iocs
      end

    MapSet.new(weak_iocs)
  end

  defp build_correlation_metadata(alert1, alert2) do
    techniques1 = MapSet.new(alert1.mitre_techniques || [])
    techniques2 = MapSet.new(alert2.mitre_techniques || [])
    shared_techniques = MapSet.intersection(techniques1, techniques2) |> MapSet.to_list()

    iocs1 = extract_iocs_from_evidence(alert1.evidence || %{})
    iocs2 = extract_iocs_from_evidence(alert2.evidence || %{})
    shared_iocs = MapSet.intersection(iocs1, iocs2) |> MapSet.to_list()
    weak_iocs1 = extract_weak_iocs_from_evidence(alert1.evidence || %{})
    weak_iocs2 = extract_weak_iocs_from_evidence(alert2.evidence || %{})
    shared_weak_iocs = MapSet.intersection(weak_iocs1, weak_iocs2) |> MapSet.to_list()

    time_delta = Timestamp.diff(alert2.inserted_at, alert1.inserted_at, :second)

    %{
      "shared_techniques" => shared_techniques,
      "shared_iocs" => shared_iocs,
      "shared_weak_iocs" => shared_weak_iocs,
      "time_delta_seconds" => time_delta,
      "technique_count" => length(shared_techniques),
      "ioc_count" => length(shared_iocs),
      "weak_ioc_count" => length(shared_weak_iocs),
      "same_agent" => alert1.agent_id == alert2.agent_id
    }
  end

  defp maybe_add_to_campaign(alert, related_alerts) do
    eligible_related =
      Enum.filter(related_alerts, fn {related_alert, _score} ->
        correlation_allowed?(alert, related_alert)
      end)

    if length(eligible_related) >= 2 do
      # Check if any related alerts are already in a campaign
      campaign = find_existing_campaign(eligible_related)

      case campaign do
        nil ->
          # Create new campaign
          create_campaign_from_alerts([alert | Enum.map(eligible_related, fn {a, _} -> a end)])

        campaign ->
          # Add to existing campaign
          add_alert_to_campaign(campaign, alert)
      end
    end
  end

  defp find_existing_campaign(related_alerts) do
    alert_ids = Enum.map(related_alerts, fn {alert, _} -> alert.id end)

    query =
      from(ca in CampaignAlert,
        where: ca.alert_id in ^alert_ids,
        preload: [:campaign],
        limit: 1
      )

    case Repo.one(query) do
      nil -> nil
      campaign_alert -> campaign_alert.campaign
    end
  end

  defp create_campaign_from_alerts(alerts) when length(alerts) >= 2 do
    try do
      # Detect attack pattern
      attack_pattern = detect_attack_pattern(alerts)

      # Calculate campaign severity (highest alert severity)
      severity =
        alerts
        |> Enum.map(& &1.severity)
        |> Enum.max_by(&severity_rank/1, fn -> "medium" end)

      # Aggregate MITRE data
      all_tactics = alerts |> Enum.flat_map(&(&1.mitre_tactics || [])) |> Enum.uniq()
      all_techniques = alerts |> Enum.flat_map(&(&1.mitre_techniques || [])) |> Enum.uniq()

      # Time bounds
      times =
        alerts
        |> Enum.map(&Timestamp.normalize(&1.inserted_at))
        |> Enum.reject(&is_nil/1)
        |> Enum.sort(DateTime)

      start_time = List.first(times) || DateTime.utc_now()
      end_time = List.last(times) || start_time

      # Agent count
      agent_ids = alerts |> Enum.map(& &1.agent_id) |> Enum.reject(&is_nil/1) |> Enum.uniq()

      # Build network graph
      network_graph = do_build_network_graph(Enum.map(alerts, & &1.id))

      # Campaign name
      name = generate_campaign_name(attack_pattern, all_tactics, start_time)

      attrs = %{
        name: name,
        description:
          "Detected #{attack_pattern} campaign with #{length(alerts)} alerts across #{length(agent_ids)} agents",
        severity: severity,
        status: "active",
        agent_count: length(agent_ids),
        alert_count: length(alerts),
        start_time: start_time,
        end_time: end_time,
        last_activity: end_time,
        mitre_tactics: all_tactics,
        mitre_techniques: all_techniques,
        attack_pattern: to_string(attack_pattern),
        confidence_score: 0.8,
        network_graph: network_graph,
        organization_id: List.first(alerts).organization_id
      }

      {:ok, campaign} = Repo.insert(%AttackCampaign{} |> AttackCampaign.changeset(attrs))

      # Link alerts to campaign
      alerts
      |> Enum.with_index()
      |> Enum.each(fn {alert, idx} ->
        role = determine_alert_role(alert, alerts)

        Repo.insert(
          %CampaignAlert{}
          |> CampaignAlert.changeset(%{
            campaign_id: campaign.id,
            alert_id: alert.id,
            role: role,
            sequence_order: idx,
            added_at: DateTime.utc_now()
          })
        )

        # Update alert with campaign_id
        Repo.update_all(
          from(a in Alert, where: a.id == ^alert.id),
          set: [campaign_id: campaign.id]
        )
      end)

      Logger.info("[CrossAgentCorrelator] Created campaign #{campaign.id}: #{name}")

      {:ok, campaign}
    rescue
      e ->
        Logger.error("[CrossAgentCorrelator] Failed to create campaign: #{inspect(e)}")
        {:error, e}
    end
  end

  defp create_campaign_from_alerts(_alerts), do: nil

  defp add_alert_to_campaign(campaign, alert) do
    try do
      # Add alert to campaign
      {:ok, _} =
        Repo.insert(
          %CampaignAlert{}
          |> CampaignAlert.changeset(%{
            campaign_id: campaign.id,
            alert_id: alert.id,
            role: "lateral",
            added_at: DateTime.utc_now()
          })
        )

      # Update campaign stats
      Repo.update_all(
        from(c in AttackCampaign, where: c.id == ^campaign.id),
        inc: [alert_count: 1],
        set: [last_activity: DateTime.utc_now()]
      )

      # Update alert with campaign_id
      Repo.update_all(
        from(a in Alert, where: a.id == ^alert.id),
        set: [campaign_id: campaign.id]
      )

      Logger.debug("[CrossAgentCorrelator] Added alert #{alert.id} to campaign #{campaign.id}")
    rescue
      e ->
        Logger.error("[CrossAgentCorrelator] Failed to add alert to campaign: #{inspect(e)}")
    end
  end

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank("info"), do: 0
  defp severity_rank(_), do: 0

  # Convert untrusted MITRE tactic strings (sourced verbatim from external
  # SigmaHQ rule tags, with no whitelist) into atoms WITHOUT growing the global
  # atom table. The 12 valid tactics already exist as compile-time literals in
  # @attack_patterns, so they resolve via to_existing_atom; any unknown string
  # could never match a pattern atom anyway, so it is safely dropped.
  defp tactic_strings_to_atoms(tactics) do
    Enum.flat_map(tactics, fn tactic ->
      try do
        [String.to_existing_atom(String.replace(tactic, "-", "_"))]
      rescue
        ArgumentError -> []
      end
    end)
  end

  defp detect_attack_pattern(alerts) do
    # Extract tactics in chronological order
    tactics =
      alerts
      |> Enum.sort_by(&Timestamp.sort_key(&1.inserted_at))
      |> Enum.flat_map(&(&1.mitre_tactics || []))
      |> tactic_strings_to_atoms()

    # Match against known patterns
    Enum.find(@attack_patterns, {:unknown, []}, fn {_pattern_name, pattern_tactics} ->
      matches_pattern?(tactics, pattern_tactics)
    end)
    |> elem(0)
  end

  defp matches_pattern?(tactics, pattern) do
    # Check if all pattern tactics appear in order (not necessarily consecutive)
    pattern
    |> Enum.all?(fn tactic ->
      tactic in tactics
    end)
  end

  defp determine_alert_role(alert, all_alerts) do
    # Determine role based on timing and tactics
    sorted = Enum.sort_by(all_alerts, &Timestamp.sort_key(&1.inserted_at))
    first = List.first(sorted)

    tactics = alert.mitre_tactics || []

    cond do
      alert.id == first.id -> "initial"
      "lateral-movement" in tactics -> "lateral"
      "impact" in tactics -> "impact"
      "credential-access" in tactics -> "credential_access"
      "persistence" in tactics -> "persistence"
      true -> "lateral"
    end
  end

  defp generate_campaign_name(pattern, tactics, start_time) do
    date = DateTime.to_date(start_time)
    pattern_str = pattern |> to_string() |> String.replace("_", " ") |> String.capitalize()

    primary_tactic = List.first(tactics) || "unknown"

    "#{pattern_str} - #{primary_tactic} - #{Date.to_iso8601(date)}"
  end

  defp do_detect_attack_chains(alerts) do
    # Group alerts and detect patterns
    patterns =
      Enum.map(@attack_patterns, fn {pattern_name, pattern_tactics} ->
        matching = filter_matching_alerts(alerts, pattern_tactics)

        if length(matching) >= 2 do
          %{
            pattern: pattern_name,
            alerts: matching,
            confidence: calculate_chain_confidence(matching, pattern_tactics),
            tactics_matched: pattern_tactics
          }
        else
          nil
        end
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.sort_by(& &1.confidence, :desc)

    {:ok, patterns}
  end

  defp filter_matching_alerts(alerts, pattern_tactics) do
    alerts
    |> Enum.filter(fn alert ->
      alert_tactics =
        (alert.mitre_tactics || [])
        |> tactic_strings_to_atoms()

      Enum.any?(pattern_tactics, fn tactic -> tactic in alert_tactics end)
    end)
  end

  defp calculate_chain_confidence(alerts, pattern_tactics) do
    if alerts == [] do
      0.0
    else
      # Calculate what percentage of pattern tactics are covered
      covered_tactics =
        alerts
        |> Enum.flat_map(&(&1.mitre_tactics || []))
        |> tactic_strings_to_atoms()
        |> MapSet.new()

      pattern_set = MapSet.new(pattern_tactics)

      coverage =
        MapSet.intersection(covered_tactics, pattern_set)
        |> MapSet.size()

      coverage / max(MapSet.size(pattern_set), 1)
    end
  end

  defp do_build_network_graph(alert_ids) do
    # Load alerts with agents
    alerts =
      from(a in Alert,
        where: a.id in ^alert_ids,
        preload: [:agent]
      )
      |> Repo.all()

    # Build nodes (agents)
    nodes =
      alerts
      |> Enum.map(& &1.agent)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq_by(& &1.id)
      |> Enum.map(fn agent ->
        %{
          "id" => agent.id,
          "hostname" => agent.hostname,
          "ip" => agent.ip_address,
          "os" => agent.os_type,
          "type" => "endpoint"
        }
      end)

    # Build edges (network connections between agents)
    edges =
      for alert <- alerts,
          evidence = alert.evidence || %{},
          network = evidence["network"] || evidence[:network],
          remote_ip = network["remote_ip"] || network[:remote_ip],
          target_agent <- find_agent_by_ip(remote_ip, alerts) do
        %{
          "source" => alert.agent_id,
          "target" => target_agent.id,
          "type" => "network",
          "alert_id" => alert.id
        }
      end
      |> Enum.uniq()

    %{
      "nodes" => nodes,
      "edges" => edges
    }
  end

  defp find_agent_by_ip(ip, alerts) do
    alerts
    |> Enum.map(& &1.agent)
    |> Enum.reject(&is_nil/1)
    |> Enum.find(fn agent -> agent.ip_address == ip end)
  end

  defp do_get_dedup_window(technique, organization_id) do
    # Check if there's a custom window configured
    query =
      from(w in "dedup_windows",
        where: w.mitre_technique == ^technique and w.organization_id == ^organization_id,
        select: w.window_seconds
      )

    case Repo.one(query) do
      # Default 5 minutes
      nil -> {:ok, 300}
      seconds -> {:ok, seconds}
    end
  rescue
    _ -> {:ok, 300}
  end

  defp do_run_correlation(opts) do
    try do
      # Get recent alerts from last hour
      since = DateTime.add(DateTime.utc_now(), -3600, :second)
      organization_id = Keyword.get(opts, :organization_id)

      query =
        from(a in Alert,
          where: a.inserted_at >= ^since,
          order_by: [desc: :inserted_at],
          limit: 500,
          preload: [:agent]
        )

      query =
        if organization_id do
          from(a in query, where: a.organization_id == ^organization_id)
        else
          query
        end

      alerts = Repo.all(query)

      Logger.info("[CrossAgentCorrelator] Running correlation on #{length(alerts)} recent alerts")

      # Correlate each alert
      Enum.each(alerts, fn alert ->
        do_correlate_alert(alert)
      end)

      Logger.info("[CrossAgentCorrelator] Correlation complete")
    rescue
      e ->
        Logger.error("[CrossAgentCorrelator] Correlation run failed: #{inspect(e)}")
    end
  end
end
