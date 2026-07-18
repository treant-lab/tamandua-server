defmodule TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver do
  @moduledoc """
  GraphQL resolvers for Threat Intelligence queries.

  Threat actors, campaigns, feeds, and MITRE metadata are shared curated
  intelligence. Tenant-created IOCs and every alert-derived projection are
  organization-scoped and fail closed without an organization context.
  """

  require Logger

  alias TamanduaServer.{ThreatIntel, Repo}
  alias TamanduaServer.ThreatIntel.{ThreatActor, CampaignTracker}
  alias TamanduaServer.Detection.{IOC, IOCReload, IOCs}
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # Query resolvers

  def list_iocs(_parent, args, %{context: context}) do
    org_id = context[:organization_id]
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    limit = pagination[:limit] || 50
    offset = pagination[:offset] || 0

    query =
      org_id
      |> scoped_iocs()
      |> apply_ioc_filters(filter)
      |> order_by([i], desc: i.inserted_at)
      |> limit(^limit)
      |> offset(^offset)

    {:ok, Repo.all(query)}
  rescue
    error ->
      Logger.warning("list_iocs resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def get_ioc(_parent, %{id: id}, %{context: context}) do
    case get_scoped_ioc(context[:organization_id], id) do
      nil -> {:error, "IOC not found"}
      ioc -> {:ok, ioc}
    end
  rescue
    error ->
      Logger.warning("get_ioc resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:error, "Failed to retrieve IOC"}
  end

  def list_threat_actors(_parent, args, _resolution) do
    pagination = Map.get(args, :pagination, %{})
    limit = pagination[:limit] || 50

    actors = ThreatActor.list(limit: limit)
    {:ok, actors}
  rescue
    error ->
      Logger.warning("list_threat_actors resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def get_threat_actor(_parent, %{id: id}, _resolution) do
    case ThreatActor.get(id) do
      nil -> {:error, "Threat actor not found"}
      actor -> {:ok, actor}
    end
  rescue
    error ->
      Logger.warning("get_threat_actor resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:error, "Failed to retrieve threat actor"}
  end

  def list_campaigns(_parent, args, %{context: context}) do
    org_id = context[:organization_id]
    pagination = Map.get(args, :pagination, %{})
    limit = pagination[:limit] || 50

    if valid_campaign_org?(org_id) do
      campaigns =
        tracker_campaigns(org_id, [])
        |> Enum.take(limit)
        |> Enum.map(&adapt_campaign/1)

      {:ok, campaigns}
    else
      {:error, "Organization context required"}
    end
  rescue
    error ->
      Logger.warning("list_campaigns resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def threat_intel_summary(_parent, _args, %{context: context}) do
    # Composed from the real threat-intel surfaces: DB-backed IOCs and
    # actors (Detection.IOC / ThreatIntel.ThreatActor) plus the ETS-backed
    # feed cache and campaign tracker GenServers.
    org_id = context[:organization_id]
    intel_stats = safe_genserver(fn -> ThreatIntel.get_stats() end, %{})
    feeds = safe_genserver(fn -> ThreatIntel.get_feed_status() end, [])
    campaigns = tracker_campaigns(org_id, [])
    actor_stats = ThreatActor.get_stats()

    scoped_iocs = scoped_iocs(org_id)

    iocs_by_severity =
      from(i in scoped_iocs, group_by: i.severity, select: {i.severity, count(i.id)})
      |> Repo.all()
      |> Map.new()

    iocs_by_type =
      from(i in scoped_iocs, group_by: i.type, select: {i.type, count(i.id)})
      |> Repo.all()
      |> Map.new()

    recent_iocs =
      from(i in scoped_iocs, order_by: [desc: i.inserted_at], limit: 10)
      |> Repo.all()

    top_actors =
      ThreatActor.list(limit: 100)
      |> Enum.sort_by(&(&1.ioc_count || 0), :desc)
      |> Enum.take(5)

    {:ok,
     %{
       total_iocs: Repo.aggregate(scoped_iocs, :count, :id),
       active_iocs: Repo.aggregate(from(i in scoped_iocs, where: i.enabled == true), :count, :id),
       total_actors: actor_stats.total,
       active_campaigns: Enum.count(campaigns, &(to_string(&1[:status] || "") == "active")),
       feeds_count: length(feeds),
       feeds_healthy: Enum.count(feeds, &(&1[:status] == :ok)),
       last_enrichment: intel_stats[:last_update],
       iocs_by_type: iocs_by_type,
       iocs_by_severity: iocs_by_severity,
       recent_iocs: recent_iocs,
       top_actors: top_actors
     }}
  rescue
    error ->
      Logger.warning("threat_intel_summary resolver failed: #{inspect(error)}")

      {:ok,
       %{
         total_iocs: 0,
         active_iocs: 0,
         total_actors: 0,
         active_campaigns: 0,
         feeds_count: 0,
         feeds_healthy: 0,
         last_enrichment: nil,
         iocs_by_type: %{},
         iocs_by_severity: %{},
         recent_iocs: [],
         top_actors: []
       }}
  end

  def mitre_coverage(_parent, _args, _resolution) do
    coverage = TamanduaServer.Detection.Mitre.get_coverage()
    {:ok, coverage}
  rescue
    error ->
      Logger.warning("mitre_coverage resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def mitre_technique(_parent, %{id: id}, _resolution) do
    case TamanduaServer.Detection.Mitre.get_technique(id) do
      nil -> {:error, "Technique not found"}
      technique -> {:ok, technique}
    end
  rescue
    error ->
      Logger.warning("mitre_technique resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:error, "Failed to retrieve MITRE technique"}
  end

  # Field resolvers

  def related_alerts(ioc, args, %{context: context}) do
    limit = args[:limit] || 10
    ioc_value = ioc.value
    org_id = context[:organization_id]

    alerts =
      if org_id && ioc.organization_id == org_id do
        from(a in Alert,
          where:
            a.organization_id == ^org_id and
              fragment("?::text ILIKE ?", a.enrichment, ^"%#{ioc_value}%"),
          order_by: [desc: a.inserted_at],
          limit: ^limit
        )
        |> Repo.all()
      else
        []
      end

    {:ok, alerts}
  rescue
    error ->
      Logger.warning(
        "related_alerts resolver failed for ioc=#{inspect(ioc.id)}: #{inspect(error)}"
      )

      {:ok, []}
  end

  def threat_actor(ioc, _args, %{context: context}) do
    # Actor linkage on IOCs lives in metadata (see ThreatActor.get_linked_iocs/2)
    metadata = Map.get(ioc, :metadata) || %{}
    actor_id = Map.get(ioc, :threat_actor_id) || metadata["threat_actor_id"]
    organization_id = context[:organization_id]

    if actor_id && ioc.organization_id == organization_id do
      {:ok, ThreatActor.get_for_organization(organization_id, actor_id)}
    else
      {:ok, nil}
    end
  rescue
    error ->
      Logger.warning(
        "threat_actor field resolver failed for ioc=#{inspect(ioc.id)}: #{inspect(error)}"
      )

      {:ok, nil}
  end

  def actor_iocs(actor, args, %{context: context}) do
    limit = args[:limit] || 50
    org_id = context[:organization_id]

    iocs =
      from(i in scoped_iocs(org_id),
        where: fragment("?->>'threat_actor_id' = ?", i.metadata, ^actor.id),
        order_by: [desc: i.inserted_at],
        limit: ^limit
      )
      |> Repo.all()

    {:ok, iocs}
  rescue
    error ->
      Logger.warning(
        "actor_iocs resolver failed for actor=#{inspect(actor.id)}: #{inspect(error)}"
      )

      {:ok, []}
  end

  def actor_campaigns(actor, _args, %{context: context}) do
    # The campaign tracker keys campaigns by actor *name*, not actor id.
    campaigns =
      tracker_campaigns(context[:organization_id], actor: actor.name)
      |> Enum.map(&adapt_campaign/1)

    {:ok, campaigns}
  rescue
    error ->
      Logger.warning(
        "actor_campaigns resolver failed for actor=#{inspect(actor.id)}: #{inspect(error)}"
      )

      {:ok, []}
  end

  def campaign_actor(campaign, _args, %{context: context}) do
    # Tracker campaigns carry an actor *name* under :actor; DB-shaped
    # campaign maps may carry a :threat_actor_id. Support both.
    organization_id = context[:organization_id]

    cond do
      actor_id = Map.get(campaign, :threat_actor_id) ->
        {:ok, ThreatActor.get_for_organization(organization_id, actor_id)}

      actor_name = Map.get(campaign, :actor) ->
        {:ok, ThreatActor.get_by_name_for_organization(organization_id, actor_name)}

      true ->
        {:ok, nil}
    end
  rescue
    error ->
      Logger.warning(
        "campaign_actor resolver failed for campaign=#{inspect(campaign.id)}: #{inspect(error)}"
      )

      {:ok, nil}
  end

  def campaign_iocs(campaign, args, %{context: context}) do
    limit = args[:limit] || 50
    org_id = context[:organization_id]

    # Tracker campaigns carry the correlated IOC *values*; resolve them to
    # the DB-backed IOC records the :ioc GraphQL type is shaped around.
    values =
      campaign
      |> Map.get(:ioc_values)
      |> Kernel.||([])
      |> Enum.to_list()

    iocs =
      if values == [] do
        []
      else
        from(i in scoped_iocs(org_id),
          where: i.value in ^values,
          limit: ^limit
        )
        |> Repo.all()
      end

    {:ok, iocs}
  rescue
    error ->
      Logger.warning(
        "campaign_iocs resolver failed for campaign=#{inspect(campaign.id)}: #{inspect(error)}"
      )

      {:ok, []}
  end

  def technique_alert_count(technique, _args, %{context: context}) do
    org_id = context[:organization_id]

    count =
      if org_id do
        from(a in Alert,
          where: a.organization_id == ^org_id and ^technique.id in a.mitre_techniques,
          select: count(a.id)
        )
        |> Repo.one()
      else
        0
      end

    {:ok, count || 0}
  rescue
    error ->
      Logger.warning(
        "technique_alert_count resolver failed for technique=#{inspect(technique.id)}: #{inspect(error)}"
      )

      {:ok, 0}
  end

  # Mutation resolvers

  def create_ioc(_parent, %{input: input}, %{context: context}) do
    org_id = context[:organization_id]

    attrs = %{
      type: input.type,
      value: input.value,
      source: input[:source] || "manual",
      description: input[:description],
      severity: input[:severity] || "medium",
      confidence: input[:confidence] || 0.8,
      tags: input[:tags] || [],
      organization_id: org_id
    }

    if org_id do
      case insert_ioc(attrs) do
        {:ok, ioc} ->
          schedule_ioc_reload()
          {:ok, ioc}

        {:error, %Ecto.Changeset{} = changeset} ->
          {:error, "Failed to create IOC: #{inspect(changeset.errors)}"}
      end
    else
      {:error, "Not authorized"}
    end
  end

  def bulk_import_iocs(_parent, %{input: input}, %{context: context}) do
    org_id = context[:organization_id]
    source = input[:source] || "bulk_import"
    default_severity = input[:default_severity] || "medium"
    iocs = input[:iocs] || []

    cond do
      not (is_binary(org_id) and org_id != "") ->
        {:error, "Not authorized"}

      not is_list(iocs) or not Enum.all?(iocs, &is_map/1) ->
        {:error, "Every IOC entry must be an object"}

      length(iocs) > 100 ->
        {:error, "At most 100 IOCs may be imported per request"}

      true ->
        results =
          Enum.map(iocs, fn ioc_input ->
            attrs = %{
              type: ioc_input.type,
              value: ioc_input.value,
              source: ioc_input[:source] || source,
              description: ioc_input[:description],
              severity: ioc_input[:severity] || default_severity,
              confidence: ioc_input[:confidence] || 0.8,
              tags: ioc_input[:tags] || [],
              organization_id: org_id
            }

            insert_ioc(attrs)
          end)

        successful =
          Enum.count(results, fn
            {:ok, _} -> true
            _ -> false
          end)

        if successful > 0, do: schedule_ioc_reload()

        {:ok,
         %{
           success: successful > 0,
           message: "Imported #{successful} of #{length(results)} IOCs"
         }}
    end
  end

  def delete_ioc(_parent, %{id: id}, %{context: context}) do
    case get_scoped_ioc(context[:organization_id], id) do
      nil ->
        {:ok, %{success: false, id: id, message: "IOC not found"}}

      ioc ->
        case Repo.delete(ioc) do
          {:ok, _} ->
            schedule_ioc_reload()
            {:ok, %{success: true, id: id, message: "IOC deleted"}}

          {:error, _} ->
            {:ok, %{success: false, id: id, message: "Failed to delete IOC"}}
        end
    end
  rescue
    error ->
      Logger.warning("delete_ioc resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:ok, %{success: false, id: id, message: "Error deleting IOC"}}
  end

  def enrich_ioc(_parent, %{input: input}, _resolution) do
    # ThreatIntel exposes no multi-source enrichment pipeline; the honest
    # surface today is the ETS feed cache (ThreatIntel.lookup/2, exit-safe).
    # Compose the :enrichment_result shape from the cached IOC when present.
    case parse_indicator_type(input.type) do
      {:ok, type} ->
        case ThreatIntel.lookup(type, input.value) do
          {:ok, ioc} -> {:ok, enrichment_from_cached_ioc(type, input.value, ioc)}
          :not_found -> {:ok, empty_enrichment(type, input.value)}
        end

      :error ->
        {:error, "Unknown indicator type: #{inspect(input.type)}"}
    end
  rescue
    e -> {:error, "Enrichment failed: #{Exception.message(e)}"}
  end

  def create_threat_actor(_parent, %{input: input}, %{context: context}) do
    with :ok <- authorize_global_catalog_write(context),
         {:ok, actor} <- ThreatActor.create(input) do
      {:ok, actor}
    else
      {:error, :system_operator_required} ->
        {:error, "Not authorized"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, "Failed to create actor: #{inspect(changeset.errors)}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  rescue
    e -> {:error, "Failed to create actor: #{Exception.message(e)}"}
  end

  def sync_threat_feeds(_parent, _args, %{context: context}) do
    # refresh_feeds/0 is an async cast; report the trigger honestly rather
    # than fabricating a synchronous per-feed result.
    with :ok <- authorize_global_catalog_write(context) do
      :ok = ThreatIntel.refresh_feeds()
      {:ok, %{success: true, message: "Feed refresh triggered"}}
    else
      {:error, :system_operator_required} -> {:error, "Not authorized"}
    end
  catch
    :exit, reason ->
      {:ok, %{success: false, message: "Sync failed: #{inspect(reason)}"}}
  end

  # Private helpers

  defp authorize_global_catalog_write(context) do
    user =
      context[:current_user_id] &&
        TamanduaServer.Accounts.get_user(context[:current_user_id])

    if TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization.system_operator?(user),
      do: :ok,
      else: {:error, :system_operator_required}
  end

  defp scoped_iocs(nil), do: from(i in IOC, where: false)
  defp scoped_iocs(org_id), do: from(i in IOC, where: i.organization_id == ^org_id)

  defp get_scoped_ioc(nil, _id), do: nil
  defp get_scoped_ioc(org_id, id), do: Repo.get_by(IOC, id: id, organization_id: org_id)

  defp insert_ioc(attrs) do
    IOCs.create_ioc(attrs)
  end

  defp schedule_ioc_reload do
    IOCReload.schedule()
  end

  # Matches TamanduaServer.ThreatIntel @indicator_types (atoms exist there).
  @indicator_type_names ~w(ip domain hash_md5 hash_sha1 hash_sha256 url email cve)

  defp parse_indicator_type(type) when is_atom(type),
    do: parse_indicator_type(Atom.to_string(type))

  defp parse_indicator_type(type) when is_binary(type) do
    normalized = String.downcase(type)

    if normalized in @indicator_type_names do
      {:ok, String.to_existing_atom(normalized)}
    else
      :error
    end
  end

  defp parse_indicator_type(_), do: :error

  defp enrichment_from_cached_ioc(type, value, ioc) do
    confidence = severity_confidence(ioc[:severity])

    %{
      ioc_type: to_string(type),
      ioc_value: value,
      is_malicious: true,
      confidence: confidence,
      sources: [
        %{
          name: ioc[:source] || "feed_cache",
          category: "feed_cache",
          is_malicious: true,
          confidence: confidence,
          details: %{
            "description" => ioc[:description],
            "tags" => ioc[:tags] || []
          },
          last_updated: ioc[:inserted_at]
        }
      ],
      geo: nil,
      whois: nil,
      dns: nil,
      related_iocs: [],
      threat_actors: [],
      mitre_techniques: [],
      first_seen: ioc[:inserted_at],
      last_seen: ioc[:inserted_at]
    }
  end

  defp empty_enrichment(type, value) do
    %{
      ioc_type: to_string(type),
      ioc_value: value,
      is_malicious: false,
      confidence: 0.0,
      sources: [],
      geo: nil,
      whois: nil,
      dns: nil,
      related_iocs: [],
      threat_actors: [],
      mitre_techniques: [],
      first_seen: nil,
      last_seen: nil
    }
  end

  defp severity_confidence("critical"), do: 0.95
  defp severity_confidence("high"), do: 0.85
  defp severity_confidence("medium"), do: 0.7
  defp severity_confidence("low"), do: 0.5
  defp severity_confidence(_), do: 0.5

  # Call into a GenServer-backed API, falling back when it is not running.
  defp safe_genserver(fun, fallback) do
    fun.()
  catch
    :exit, _ -> fallback
  end

  defp tracker_campaigns(organization_id, opts) do
    if valid_campaign_org?(organization_id) do
      safe_genserver(fn -> CampaignTracker.list_campaigns(organization_id, opts) end, [])
    else
      []
    end
  end

  defp valid_campaign_org?(organization_id),
    do: is_binary(organization_id) and match?({:ok, _}, Ecto.UUID.cast(organization_id))

  # Tracker campaigns use :start_time/:end_time/:created_at and atom
  # :status; the :campaign GraphQL type expects :start_date/:end_date/
  # :inserted_at and string status.
  defp adapt_campaign(campaign) do
    campaign
    |> Map.put_new(:start_date, Map.get(campaign, :start_time))
    |> Map.put_new(:end_date, Map.get(campaign, :end_time))
    |> Map.put_new(:inserted_at, Map.get(campaign, :created_at))
    |> Map.update(:status, nil, fn s -> s && to_string(s) end)
  end

  defp apply_ioc_filters(query, filter) do
    query
    |> maybe_filter_type(filter[:type])
    |> maybe_filter_source(filter[:source])
    |> maybe_filter_severity(filter[:severity])
    |> maybe_filter_active(filter[:is_active])
    |> maybe_filter_search(filter[:search])
    |> maybe_filter_since(filter[:since])
    |> maybe_filter_tags(filter[:tags])
  end

  defp maybe_filter_type(query, nil), do: query

  defp maybe_filter_type(query, type) do
    where(query, [i], i.type == ^type)
  end

  defp maybe_filter_source(query, nil), do: query

  defp maybe_filter_source(query, source) do
    where(query, [i], i.source == ^source)
  end

  defp maybe_filter_severity(query, nil), do: query

  defp maybe_filter_severity(query, severity) do
    where(query, [i], i.severity == ^severity)
  end

  defp maybe_filter_active(query, nil), do: query

  defp maybe_filter_active(query, is_active) do
    where(query, [i], i.enabled == ^is_active)
  end

  defp maybe_filter_search(query, nil), do: query

  defp maybe_filter_search(query, search) do
    pattern = "%#{search}%"
    where(query, [i], ilike(i.value, ^pattern) or ilike(i.description, ^pattern))
  end

  defp maybe_filter_since(query, nil), do: query

  defp maybe_filter_since(query, since) do
    where(query, [i], i.inserted_at >= ^since)
  end

  defp maybe_filter_tags(query, nil), do: query
  defp maybe_filter_tags(query, []), do: query

  defp maybe_filter_tags(query, tags) do
    where(query, [i], fragment("? && ?", i.tags, ^tags))
  end
end
