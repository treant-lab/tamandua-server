defmodule TamanduaServer.ThreatIntel.Attribution do
  @moduledoc """
  Threat Attribution Engine.

  Links IOCs to threat actors and tracks campaigns:
  - IOC-to-Actor correlation
  - Campaign tracking and clustering
  - TTP correlation using MITRE ATT&CK
  - Kill chain analysis
  - Confidence scoring for attribution
  - Historical attribution tracking

  ## Attribution Confidence

  Attribution confidence is calculated based on:
  - Number of matching IOCs
  - IOC confidence scores
  - TTP overlap with known actor TTPs
  - Historical actor behavior patterns
  - Temporal patterns (attack timing)
  - Target profile matching

  ## Usage

      # Attribute an alert to threat actors
      Attribution.attribute_alert(organization_id, alert)

      # Get campaign intelligence
      Attribution.get_campaign(organization_id, "campaign_id")

      # Link new IOCs to existing campaigns
      Attribution.correlate_iocs(organization_id, iocs)
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.ThreatActor

  @ets_campaigns :attribution_campaigns
  @ets_actor_iocs :attribution_actor_iocs
  @ets_ttp_actors :attribution_ttp_actors

  # Attribution weights
  @ioc_match_weight 30
  @ttp_match_weight 25
  @malware_match_weight 25
  @target_match_weight 10

  # Minimum confidence for attribution
  @min_attribution_confidence 0.3

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Attribute an alert to potential threat actors.

  Returns a list of potential attributions with confidence scores.
  """
  @spec attribute_alert(String.t(), map()) :: {:ok, [map()]} | {:error, term()}
  def attribute_alert(organization_id, alert) when is_map(alert) do
    with :ok <- validate_scoped_payload(organization_id, alert, :attribute_alert) do
      call_if_started(
        {:attribute_alert, organization_id, alert},
        {:error, :attribution_unavailable},
        30_000
      )
    end
  end

  def attribute_alert(_organization_id, _alert), do: organization_required(:attribute_alert)
  def attribute_alert(_legacy_alert), do: organization_required(:attribute_alert)

  @doc """
  Correlate IOCs to identify potential campaigns.
  """
  @spec correlate_iocs(String.t(), [map()]) :: {:ok, map()} | {:error, term()}
  def correlate_iocs(organization_id, iocs) when is_list(iocs) do
    with :ok <- validate_organization(organization_id, :correlate_iocs),
         :ok <- validate_scoped_iocs(organization_id, iocs, :correlate_iocs) do
      call_if_started(
        {:correlate_iocs, organization_id, iocs},
        {:error, :attribution_unavailable},
        60_000
      )
    end
  end

  def correlate_iocs(_organization_id, _iocs), do: organization_required(:correlate_iocs)
  def correlate_iocs(_legacy_iocs), do: organization_required(:correlate_iocs)

  @doc """
  Get campaign details by ID.
  """
  @spec get_campaign(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_campaign(organization_id, campaign_id) do
    with :ok <- validate_organization(organization_id, :get_campaign) do
      call_if_started({:get_campaign, organization_id, campaign_id}, {:error, :not_found})
    end
  end

  def get_campaign(_legacy_campaign_id), do: organization_required(:get_campaign)

  @doc """
  List active campaigns.
  """
  @spec list_campaigns(String.t(), keyword()) :: [map()] | {:error, term()}
  def list_campaigns(organization_id, opts) when is_list(opts) do
    with :ok <- validate_organization(organization_id, :list_campaigns) do
      call_if_started({:list_campaigns, organization_id, opts}, [])
    end
  end

  def list_campaigns(_organization_id, _opts), do: organization_required(:list_campaigns)
  def list_campaigns(_legacy_opts), do: organization_required(:list_campaigns)
  def list_campaigns, do: organization_required(:list_campaigns)

  @doc """
  Create or update a campaign.
  """
  @spec upsert_campaign(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def upsert_campaign(organization_id, campaign) when is_map(campaign) do
    with :ok <- validate_scoped_payload(organization_id, campaign, :upsert_campaign) do
      call_if_started(
        {:upsert_campaign, organization_id, campaign},
        {:error, :attribution_unavailable}
      )
    end
  end

  def upsert_campaign(_organization_id, _campaign), do: organization_required(:upsert_campaign)
  def upsert_campaign(_legacy_campaign), do: organization_required(:upsert_campaign)

  @doc """
  Link IOCs to a campaign.
  """
  @spec link_iocs_to_campaign(String.t(), String.t(), [String.t()]) :: :ok | {:error, term()}
  def link_iocs_to_campaign(organization_id, campaign_id, ioc_ids) when is_list(ioc_ids) do
    with :ok <- validate_organization(organization_id, :link_iocs_to_campaign) do
      call_if_started(
        {:link_iocs_to_campaign, organization_id, campaign_id, ioc_ids},
        {:error, :not_found}
      )
    end
  end

  def link_iocs_to_campaign(_organization_id, _campaign_id, _ioc_ids),
    do: organization_required(:link_iocs_to_campaign)

  def link_iocs_to_campaign(_campaign_id, _ioc_ids),
    do: organization_required(:link_iocs_to_campaign)

  @doc """
  Get actor profile with associated IOCs and TTPs.
  """
  @spec get_actor_profile(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_actor_profile(organization_id, actor_id) do
    with :ok <- validate_organization(organization_id, :get_actor_profile) do
      call_if_started({:get_actor_profile, organization_id, actor_id}, {:error, :not_found})
    end
  end

  def get_actor_profile(_legacy_actor_id), do: organization_required(:get_actor_profile)

  @doc """
  Find actors by TTP.
  """
  @spec find_actors_by_ttp(String.t()) :: [map()]
  def find_actors_by_ttp(technique_id) do
    call_if_started({:find_actors_by_ttp, technique_id}, [])
  end

  @doc """
  Find actors by target profile.
  """
  @spec find_actors_by_target(map()) :: [map()]
  def find_actors_by_target(target) do
    call_if_started({:find_actors_by_target, target}, [])
  end

  @doc """
  Get attribution statistics.
  """
  @spec get_stats(String.t()) :: map() | {:error, term()}
  def get_stats(organization_id) do
    with :ok <- validate_organization(organization_id, :get_stats) do
      call_if_started({:get_stats, organization_id}, %{
        status: :unavailable,
        attributions_made: 0,
        campaigns_tracked: 0,
        iocs_linked: 0,
        campaigns_in_memory: 0
      })
    end
  end

  def get_stats, do: organization_required(:get_stats)

  @doc """
  Rebuild attribution indexes.
  """
  @spec rebuild_indexes() :: :ok
  def rebuild_indexes do
    if Process.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, :rebuild_indexes)
    end

    :ok
  end

  defp call_if_started(request, default, timeout \\ 5_000) do
    case Process.whereis(__MODULE__) do
      nil ->
        default

      _pid ->
        GenServer.call(__MODULE__, request, timeout)
    end
  catch
    :exit, {:noproc, _} -> default
    :exit, {:normal, _} -> default
    :exit, {:shutdown, _} -> default
    :exit, :normal -> default
    :exit, :shutdown -> default
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_campaigns, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_actor_iocs, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ets_ttp_actors, [:named_table, :bag, :public, read_concurrency: true])

    state = %{stats: %{}}

    # Build initial indexes
    send(self(), :build_indexes)

    Logger.info("[Attribution] Initialized")
    {:ok, state}
  end

  @impl true
  def handle_call({:attribute_alert, organization_id, alert}, _from, state) do
    result = do_attribute_alert(organization_id, alert)
    {:reply, result, increment_stat(state, organization_id, :attributions_made)}
  end

  @impl true
  def handle_call({:correlate_iocs, organization_id, iocs}, _from, state) do
    result = do_correlate_iocs(organization_id, iocs)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_campaign, organization_id, campaign_id}, _from, state) do
    key = {organization_id, campaign_id}

    result =
      case :ets.lookup(@ets_campaigns, key) do
        [{^key, %{organization_id: ^organization_id} = campaign}] -> {:ok, campaign}
        _legacy_or_mismatch -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_campaigns, organization_id, opts}, _from, state) do
    campaigns = do_list_campaigns(organization_id, opts)
    {:reply, campaigns, state}
  end

  @impl true
  def handle_call({:upsert_campaign, organization_id, campaign}, _from, state) do
    result = do_upsert_campaign(organization_id, campaign)
    {:reply, result, increment_stat(state, organization_id, :campaigns_tracked)}
  end

  @impl true
  def handle_call(
        {:link_iocs_to_campaign, organization_id, campaign_id, ioc_ids},
        _from,
        state
      ) do
    case do_link_iocs_to_campaign(organization_id, campaign_id, ioc_ids) do
      :ok ->
        {:reply, :ok, increment_stat(state, organization_id, :iocs_linked, length(ioc_ids))}

      {:error, :not_found} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_actor_profile, organization_id, actor_id}, _from, state) do
    result = do_get_actor_profile(organization_id, actor_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:find_actors_by_ttp, technique_id}, _from, state) do
    actors = do_find_actors_by_ttp(technique_id)
    {:reply, actors, state}
  end

  @impl true
  def handle_call({:find_actors_by_target, target}, _from, state) do
    actors = do_find_actors_by_target(target)
    {:reply, actors, state}
  end

  @impl true
  def handle_call({:get_stats, organization_id}, _from, state) do
    stats =
      Map.put(
        organization_stats(state, organization_id),
        :campaigns_in_memory,
        count_campaigns(organization_id)
      )

    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:rebuild_indexes, state) do
    Task.start(fn -> build_indexes() end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:build_indexes, state) do
    build_indexes()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Attribution
  # ============================================================================

  defp do_attribute_alert(organization_id, alert) do
    # Extract indicators from alert
    iocs = extract_alert_iocs(alert)
    ttps = extract_alert_ttps(alert)
    malware = extract_alert_malware(alert)
    target = extract_alert_target(alert)

    # Get all actors
    actors = ThreatActor.list_for_organization(organization_id, limit: 200, active: true)

    # Score each actor
    attributions =
      Enum.map(actors, fn actor ->
        score =
          calculate_attribution_score(organization_id, actor, iocs, ttps, malware, target)

        {actor, score}
      end)
      |> Enum.filter(fn {_, score} -> score.confidence >= @min_attribution_confidence end)
      |> Enum.sort_by(fn {_, score} -> score.confidence end, :desc)
      |> Enum.take(5)
      |> Enum.map(fn {actor, score} ->
        %{
          actor_id: actor.id,
          actor_name: actor.name,
          aliases: actor.aliases,
          motivation: actor.motivation,
          confidence: Float.round(score.confidence, 3),
          matching_iocs: score.matching_iocs,
          matching_ttps: score.matching_ttps,
          matching_malware: score.matching_malware,
          evidence: build_evidence(actor, score),
          metadata: %{
            origin_country: actor.origin_country,
            target_sectors: actor.target_sectors,
            last_seen: actor.last_seen
          }
        }
      end)

    {:ok, attributions}
  end

  defp calculate_attribution_score(
         organization_id,
         actor,
         alert_iocs,
         alert_ttps,
         alert_malware,
         alert_target
       ) do
    # IOC matching
    actor_iocs = get_actor_ioc_values(organization_id, actor)

    matching_iocs =
      Enum.filter(alert_iocs, fn ioc ->
        Enum.member?(actor_iocs, normalize_ioc_value(ioc))
      end)

    ioc_score = min(length(matching_iocs) * 10, @ioc_match_weight)

    # TTP matching
    matching_ttps =
      Enum.filter(alert_ttps, fn ttp ->
        Enum.member?(actor.ttps || [], ttp)
      end)

    ttp_score = min(length(matching_ttps) * 8, @ttp_match_weight)

    # Malware matching
    matching_malware =
      Enum.filter(alert_malware, fn m ->
        m_lower = String.downcase(m)

        Enum.any?(actor.known_malware || [], fn km ->
          String.downcase(km) == m_lower
        end)
      end)

    malware_score = if length(matching_malware) > 0, do: @malware_match_weight, else: 0

    # Target matching
    target_score = calculate_target_match(actor, alert_target)

    # Calculate total score
    total_score = ioc_score + ttp_score + malware_score + target_score

    max_score =
      @ioc_match_weight + @ttp_match_weight + @malware_match_weight + @target_match_weight

    confidence = total_score / max_score

    %{
      confidence: confidence,
      matching_iocs: matching_iocs,
      matching_ttps: matching_ttps,
      matching_malware: matching_malware,
      ioc_score: ioc_score,
      ttp_score: ttp_score,
      malware_score: malware_score,
      target_score: target_score
    }
  end

  defp calculate_target_match(actor, target) do
    score = 0

    # Sector match
    score =
      if target[:sector] && Enum.member?(actor.target_sectors || [], target[:sector]) do
        score + 5
      else
        score
      end

    # Country match
    score =
      if target[:country] && Enum.member?(actor.target_countries || [], target[:country]) do
        score + 3
      else
        score
      end

    # Region match
    score =
      if target[:region] && Enum.member?(actor.target_regions || [], target[:region]) do
        score + 2
      else
        score
      end

    min(score, @target_match_weight)
  end

  defp build_evidence(actor, score) do
    evidence = []

    evidence =
      if length(score.matching_iocs) > 0 do
        [
          %{
            type: "ioc_match",
            description:
              "#{length(score.matching_iocs)} IOCs match known #{actor.name} infrastructure",
            confidence: "high"
          }
          | evidence
        ]
      else
        evidence
      end

    evidence =
      if length(score.matching_ttps) > 0 do
        [
          %{
            type: "ttp_match",
            description:
              "Attack techniques match #{actor.name} known TTPs: #{Enum.join(score.matching_ttps, ", ")}",
            confidence: "medium"
          }
          | evidence
        ]
      else
        evidence
      end

    evidence =
      if length(score.matching_malware) > 0 do
        [
          %{
            type: "malware_match",
            description:
              "Malware family #{Enum.join(score.matching_malware, ", ")} attributed to #{actor.name}",
            confidence: "high"
          }
          | evidence
        ]
      else
        evidence
      end

    evidence
  end

  # ============================================================================
  # Private Functions - Campaign Correlation
  # ============================================================================

  defp do_correlate_iocs(organization_id, iocs) do
    # Group IOCs by potential campaign indicators
    infrastructure = group_by_infrastructure(iocs)
    temporal = group_by_temporal(iocs)
    ttps = group_by_ttps(iocs)

    # Find existing campaigns that match
    matching_campaigns = find_matching_campaigns(organization_id, infrastructure, temporal)

    # Identify new potential campaigns
    new_campaigns = identify_new_campaigns(infrastructure, temporal, ttps)

    {:ok,
     %{
       matching_existing: matching_campaigns,
       potential_new: new_campaigns,
       infrastructure_clusters: infrastructure,
       temporal_clusters: temporal
     }}
  end

  defp group_by_infrastructure(iocs) do
    # Group by shared infrastructure (same AS, same domain registrar, etc.)
    iocs
    |> Enum.group_by(fn ioc ->
      metadata = ioc[:metadata] || %{}
      {metadata["asn"], metadata["registrar"]}
    end)
    |> Enum.filter(fn {_, group} -> length(group) >= 3 end)
    |> Map.new()
  end

  defp group_by_temporal(iocs) do
    # Group by temporal proximity
    iocs
    |> Enum.filter(fn ioc -> ioc[:first_seen] end)
    |> Enum.group_by(fn ioc ->
      # Group by day
      DateTime.to_date(ioc[:first_seen] || DateTime.utc_now())
    end)
    |> Enum.filter(fn {_, group} -> length(group) >= 5 end)
    |> Map.new()
  end

  defp group_by_ttps(iocs) do
    # Group by shared TTPs in metadata
    iocs
    |> Enum.filter(fn ioc ->
      ttps = get_in(ioc, [:metadata, "mitre_ttps"]) || []
      length(ttps) > 0
    end)
    |> Enum.group_by(fn ioc ->
      ttps = get_in(ioc, [:metadata, "mitre_ttps"]) || []
      Enum.sort(ttps)
    end)
    |> Enum.filter(fn {ttps, group} -> length(ttps) > 0 and length(group) >= 2 end)
    |> Map.new()
  end

  defp find_matching_campaigns(organization_id, infrastructure, _temporal) do
    # Check existing campaigns for IOC overlap
    :ets.foldl(
      fn
        {{^organization_id, _id}, campaign}, matches ->
          campaign_iocs = campaign.iocs || []

          infra_match =
            Enum.any?(infrastructure, fn {_, iocs} ->
              ioc_values = Enum.map(iocs, & &1[:value])
              overlap = length(Enum.filter(campaign_iocs, fn ci -> ci in ioc_values end))
              overlap >= 2
            end)

          if infra_match, do: [campaign | matches], else: matches

        _legacy_or_other_tenant, matches ->
          matches
      end,
      [],
      @ets_campaigns
    )
  end

  defp identify_new_campaigns(infrastructure, _temporal, _ttps) do
    # Identify clusters that could be new campaigns
    infrastructure
    |> Enum.map(fn {{asn, registrar}, iocs} ->
      %{
        type: :infrastructure_cluster,
        indicators: %{asn: asn, registrar: registrar},
        iocs: Enum.map(iocs, & &1[:value]),
        count: length(iocs),
        suggested_name: "Campaign-#{:erlang.phash2({asn, registrar}, 999_999)}"
      }
    end)
  end

  # ============================================================================
  # Private Functions - Campaign Management
  # ============================================================================

  defp do_list_campaigns(organization_id, opts) do
    limit = Keyword.get(opts, :limit, 50)
    status_filter = Keyword.get(opts, :status)

    campaigns =
      :ets.tab2list(@ets_campaigns)
      |> Enum.flat_map(fn
        {{^organization_id, _campaign_id}, %{organization_id: ^organization_id} = campaign} ->
          [campaign]

        _legacy_or_other_tenant ->
          []
      end)

    campaigns =
      if status_filter do
        Enum.filter(campaigns, fn c -> c.status == status_filter end)
      else
        campaigns
      end

    campaigns
    |> Enum.sort_by(fn c -> c.last_activity || c.start_date end, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp do_upsert_campaign(organization_id, campaign) do
    campaign_id = campaign_field(campaign, :id) || generate_campaign_id()

    campaign_data = %{
      id: campaign_id,
      organization_id: organization_id,
      name: campaign_field(campaign, :name) || "Unknown Campaign",
      description: campaign_field(campaign, :description),
      status: campaign_field(campaign, :status) || "active",
      actors: campaign_field(campaign, :actors) || [],
      malware: campaign_field(campaign, :malware) || [],
      ttps: campaign_field(campaign, :ttps) || [],
      iocs: campaign_field(campaign, :iocs) || [],
      targets: campaign_field(campaign, :targets) || [],
      start_date: campaign_field(campaign, :start_date) || DateTime.utc_now(),
      end_date: campaign_field(campaign, :end_date),
      last_activity: campaign_field(campaign, :last_activity) || DateTime.utc_now(),
      confidence: campaign_field(campaign, :confidence) || 0.7,
      metadata: campaign_field(campaign, :metadata) || %{}
    }

    :ets.insert(@ets_campaigns, {{organization_id, campaign_id}, campaign_data})

    {:ok, campaign_data}
  end

  defp do_link_iocs_to_campaign(organization_id, campaign_id, ioc_ids) do
    key = {organization_id, campaign_id}

    case :ets.lookup(@ets_campaigns, key) do
      [{^key, %{organization_id: ^organization_id} = campaign}] ->
        updated_iocs = Enum.uniq(campaign.iocs ++ ioc_ids)

        updated_campaign = %{
          campaign
          | iocs: updated_iocs,
            last_activity: DateTime.utc_now()
        }

        :ets.insert(@ets_campaigns, {key, updated_campaign})
        :ok

      _legacy_or_mismatch ->
        {:error, :not_found}
    end
  end

  # ============================================================================
  # Private Functions - Actor Profiles
  # ============================================================================

  defp do_get_actor_profile(organization_id, actor_id) do
    case ThreatActor.get_for_organization(organization_id, actor_id) do
      nil ->
        {:error, :not_found}

      actor ->
        # Get linked IOCs
        iocs = load_actor_iocs(organization_id, actor)

        # Get campaigns involving this actor
        campaigns =
          :ets.foldl(
            fn
              {{^organization_id, _campaign_id}, %{organization_id: ^organization_id} = campaign},
              acc ->
                if actor.name in (campaign.actors || []) or actor_id in (campaign.actors || []) do
                  [campaign | acc]
                else
                  acc
                end

              _legacy_or_other_tenant, acc ->
                acc
            end,
            [],
            @ets_campaigns
          )

        profile = %{
          actor: %{
            id: actor.id,
            name: actor.name,
            description: actor.description,
            aliases: actor.aliases,
            motivation: actor.motivation,
            sophistication: actor.sophistication,
            origin_country: actor.origin_country,
            target_sectors: actor.target_sectors,
            target_countries: actor.target_countries,
            ttps: actor.ttps,
            known_malware: actor.known_malware,
            known_tools: actor.known_tools,
            first_seen: actor.first_seen,
            last_seen: actor.last_seen,
            active: actor.active
          },
          iocs: Enum.take(iocs, 100),
          ioc_count: length(iocs),
          campaigns:
            Enum.map(campaigns, fn c ->
              %{id: c.id, name: c.name, status: c.status}
            end),
          related_actors: find_related_actors(organization_id, actor)
        }

        {:ok, profile}
    end
  end

  defp do_find_actors_by_ttp(technique_id) do
    :ets.lookup(@ets_ttp_actors, technique_id)
    |> Enum.map(fn {_, actor_info} -> actor_info end)
  end

  defp do_find_actors_by_target(target) do
    actors = ThreatActor.list(limit: 100, active: true)

    Enum.filter(actors, fn actor ->
      sector_match = target[:sector] && target[:sector] in (actor.target_sectors || [])
      country_match = target[:country] && target[:country] in (actor.target_countries || [])
      region_match = target[:region] && target[:region] in (actor.target_regions || [])

      sector_match or country_match or region_match
    end)
    |> Enum.map(fn actor ->
      %{
        id: actor.id,
        name: actor.name,
        motivation: actor.motivation,
        target_sectors: actor.target_sectors,
        target_countries: actor.target_countries
      }
    end)
  end

  defp find_related_actors(organization_id, actor) do
    # Find actors with overlapping TTPs or malware
    actors = ThreatActor.list_for_organization(organization_id, limit: 100, active: true)

    Enum.filter(actors, fn a ->
      a.id != actor.id and
        (length(Enum.filter(a.ttps || [], fn t -> t in (actor.ttps || []) end)) >= 3 or
           length(
             Enum.filter(a.known_malware || [], fn m -> m in (actor.known_malware || []) end)
           ) >= 1)
    end)
    |> Enum.take(5)
    |> Enum.map(fn a ->
      %{id: a.id, name: a.name, relationship: "shared_ttps"}
    end)
  end

  # ============================================================================
  # Private Functions - Indexing
  # ============================================================================

  defp build_indexes do
    Logger.info("[Attribution] Building attribution indexes...")

    # Build actor IOC index
    actors = ThreatActor.list(limit: 1000)

    Enum.each(actors, fn actor ->
      # Get IOCs linked to this actor
      iocs =
        if is_binary(actor.organization_id) do
          ThreatActor.get_linked_iocs_for_organization(actor.organization_id, actor, limit: 500)
        else
          []
        end

      Enum.each(iocs, fn ioc ->
        :ets.insert(
          @ets_actor_iocs,
          {{actor.organization_id, actor.id},
           %{
             type: ioc.type,
             value: ioc.value,
             source: ioc.source
           }}
        )
      end)

      # Index TTPs
      Enum.each(actor.ttps || [], fn ttp ->
        :ets.insert(
          @ets_ttp_actors,
          {ttp,
           %{
             id: actor.id,
             name: actor.name,
             motivation: actor.motivation
           }}
        )
      end)
    end)

    Logger.info("[Attribution] Built indexes for #{length(actors)} actors")
  rescue
    e ->
      Logger.error("[Attribution] Failed to build indexes: #{inspect(e)}")
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp extract_alert_iocs(alert) do
    enrichment = alert[:enrichment] || alert["enrichment"] || %{}

    iocs = []

    # Extract IPs
    iocs =
      case enrichment["source_ip"] || enrichment[:source_ip] do
        nil -> iocs
        ip -> [%{type: "ip", value: ip} | iocs]
      end

    iocs =
      case enrichment["dest_ip"] || enrichment[:dest_ip] do
        nil -> iocs
        ip -> [%{type: "ip", value: ip} | iocs]
      end

    # Extract domains
    iocs =
      case enrichment["domain"] || enrichment[:domain] do
        nil -> iocs
        domain -> [%{type: "domain", value: domain} | iocs]
      end

    # Extract hashes
    iocs =
      case enrichment["file_hash"] || enrichment[:file_hash] do
        nil -> iocs
        hash -> [%{type: "hash", value: hash} | iocs]
      end

    # Extract from related IOCs
    related = enrichment["related_iocs"] || enrichment[:related_iocs] || []
    iocs ++ Enum.map(related, fn i -> %{type: i["type"], value: i["value"]} end)
  end

  defp extract_alert_ttps(alert) do
    alert[:mitre_techniques] || alert["mitre_techniques"] ||
      get_in(alert, [:enrichment, "mitre_techniques"]) ||
      get_in(alert, [:enrichment, :mitre_techniques]) ||
      []
  end

  defp extract_alert_malware(alert) do
    enrichment = alert[:enrichment] || alert["enrichment"] || %{}

    malware = []

    malware =
      case enrichment["malware_family"] || enrichment[:malware_family] do
        nil -> malware
        m -> [m | malware]
      end

    malware =
      case enrichment["detected_malware"] || enrichment[:detected_malware] do
        nil -> malware
        list when is_list(list) -> malware ++ list
        m -> [m | malware]
      end

    Enum.uniq(malware)
  end

  defp extract_alert_target(alert) do
    %{
      sector: get_in(alert, [:target, :sector]) || get_in(alert, [:enrichment, "target_sector"]),
      country:
        get_in(alert, [:target, :country]) || get_in(alert, [:enrichment, "target_country"]),
      region: get_in(alert, [:target, :region])
    }
  end

  defp get_actor_ioc_values(organization_id, actor) do
    key = {organization_id, actor.id}

    case :ets.lookup(@ets_actor_iocs, key) do
      [] -> load_actor_iocs(organization_id, actor) |> Enum.map(&normalize_ioc_value/1)
      entries -> Enum.map(entries, fn {_, ioc} -> normalize_ioc_value(ioc) end)
    end
  end

  defp load_actor_iocs(organization_id, actor) do
    key = {organization_id, actor.id}

    iocs = ThreatActor.get_linked_iocs_for_organization(organization_id, actor, limit: 500)
    :ets.delete(@ets_actor_iocs, key)

    Enum.each(iocs, fn ioc ->
      :ets.insert(
        @ets_actor_iocs,
        {key, %{type: ioc.type, value: ioc.value, source: ioc.source}}
      )
    end)

    Enum.map(iocs, fn ioc -> %{type: ioc.type, value: ioc.value, source: ioc.source} end)
  end

  defp normalize_ioc_value(ioc) when is_map(ioc) do
    String.downcase(to_string(ioc[:value] || ioc["value"] || ""))
  end

  defp normalize_ioc_value(value), do: String.downcase(to_string(value))

  defp generate_campaign_id do
    "campaign_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp validate_organization(organization_id, operation) do
    if is_binary(organization_id) and match?({:ok, _}, Ecto.UUID.cast(organization_id)) do
      :ok
    else
      organization_required(operation)
    end
  end

  defp validate_scoped_payload(organization_id, payload, operation) do
    with :ok <- validate_organization(organization_id, operation) do
      case campaign_field(payload, :organization_id) do
        nil ->
          :ok

        ^organization_id ->
          :ok

        _mismatch ->
          emit_scope_rejection(operation, :organization_mismatch)
          {:error, :organization_mismatch}
      end
    end
  end

  defp validate_scoped_iocs(organization_id, iocs, operation) do
    if Enum.all?(iocs, fn
         ioc when is_map(ioc) ->
           claimed = campaign_field(ioc, :organization_id)
           is_nil(claimed) or claimed == organization_id

         _ ->
           true
       end) do
      :ok
    else
      emit_scope_rejection(operation, :organization_mismatch)
      {:error, :organization_mismatch}
    end
  end

  defp organization_required(operation) do
    emit_scope_rejection(operation, :organization_unknown)
    {:error, :organization_required}
  end

  defp emit_scope_rejection(operation, reason) do
    :telemetry.execute(
      [:tamandua, :threat_intel, :attribution_scope_rejected],
      %{count: 1},
      %{operation: operation, reason: reason}
    )
  end

  defp campaign_field(map, field) when is_map(map), do: map[field] || map[Atom.to_string(field)]

  defp organization_stats(state, organization_id) do
    Map.get(state.stats, organization_id, %{
      attributions_made: 0,
      campaigns_tracked: 0,
      iocs_linked: 0
    })
  end

  defp increment_stat(state, organization_id, stat, amount \\ 1) do
    updated_org_stats =
      Map.update!(organization_stats(state, organization_id), stat, &(&1 + amount))

    %{state | stats: Map.put(state.stats, organization_id, updated_org_stats)}
  end

  defp count_campaigns(organization_id) do
    :ets.foldl(
      fn
        {{^organization_id, _campaign_id}, %{organization_id: ^organization_id}}, count ->
          count + 1

        _legacy_or_other_tenant, count ->
          count
      end,
      0,
      @ets_campaigns
    )
  end
end
