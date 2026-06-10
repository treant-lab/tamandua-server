defmodule TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver do
  @moduledoc """
  GraphQL resolvers for Threat Intelligence queries.
  """

  require Logger

  alias TamanduaServer.{ThreatIntel, Repo}
  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # Query resolvers

  def list_iocs(_parent, args, _resolution) do
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    limit = pagination[:limit] || 50
    offset = pagination[:offset] || 0

    query = IOC
    |> apply_ioc_filters(filter)
    |> order_by([i], [desc: i.inserted_at])
    |> limit(^limit)
    |> offset(^offset)

    {:ok, Repo.all(query)}
  rescue
    error ->
      Logger.warning("list_iocs resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def get_ioc(_parent, %{id: id}, _resolution) do
    case Repo.get(IOC, id) do
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

    actors = ThreatIntel.list_actors(limit: limit)
    {:ok, actors}
  rescue
    error ->
      Logger.warning("list_threat_actors resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def get_threat_actor(_parent, %{id: id}, _resolution) do
    case ThreatIntel.get_actor(id) do
      nil -> {:error, "Threat actor not found"}
      actor -> {:ok, actor}
    end
  rescue
    error ->
      Logger.warning("get_threat_actor resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:error, "Failed to retrieve threat actor"}
  end

  def list_campaigns(_parent, args, _resolution) do
    pagination = Map.get(args, :pagination, %{})
    limit = pagination[:limit] || 50

    campaigns = ThreatIntel.list_campaigns(limit: limit)
    {:ok, campaigns}
  rescue
    error ->
      Logger.warning("list_campaigns resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  def threat_intel_summary(_parent, _args, _resolution) do
    summary = ThreatIntel.get_summary()
    {:ok, summary}
  rescue
    error ->
      Logger.warning("threat_intel_summary resolver failed: #{inspect(error)}")
      {:ok, %{
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

  def related_alerts(ioc, args, _resolution) do
    limit = args[:limit] || 10
    ioc_value = ioc.value

    # Search alerts that might contain this IOC
    alerts = from(a in Alert,
      where: fragment("?::text ILIKE ?", a.enrichment, ^"%#{ioc_value}%"),
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()

    {:ok, alerts}
  rescue
    error ->
      Logger.warning("related_alerts resolver failed for ioc=#{inspect(ioc.id)}: #{inspect(error)}")
      {:ok, []}
  end

  def threat_actor(ioc, _args, _resolution) do
    if ioc.threat_actor_id do
      {:ok, ThreatIntel.get_actor(ioc.threat_actor_id)}
    else
      {:ok, nil}
    end
  rescue
    error ->
      Logger.warning("threat_actor field resolver failed for ioc=#{inspect(ioc.id)}: #{inspect(error)}")
      {:ok, nil}
  end

  def actor_iocs(actor, args, _resolution) do
    limit = args[:limit] || 50

    iocs = ThreatIntel.get_actor_iocs(actor.id, limit: limit)
    {:ok, iocs}
  rescue
    error ->
      Logger.warning("actor_iocs resolver failed for actor=#{inspect(actor.id)}: #{inspect(error)}")
      {:ok, []}
  end

  def actor_campaigns(actor, _args, _resolution) do
    campaigns = ThreatIntel.get_actor_campaigns(actor.id)
    {:ok, campaigns}
  rescue
    error ->
      Logger.warning("actor_campaigns resolver failed for actor=#{inspect(actor.id)}: #{inspect(error)}")
      {:ok, []}
  end

  def campaign_actor(campaign, _args, _resolution) do
    if campaign.threat_actor_id do
      {:ok, ThreatIntel.get_actor(campaign.threat_actor_id)}
    else
      {:ok, nil}
    end
  rescue
    error ->
      Logger.warning("campaign_actor resolver failed for campaign=#{inspect(campaign.id)}: #{inspect(error)}")
      {:ok, nil}
  end

  def campaign_iocs(campaign, args, _resolution) do
    limit = args[:limit] || 50

    iocs = ThreatIntel.get_campaign_iocs(campaign.id, limit: limit)
    {:ok, iocs}
  rescue
    error ->
      Logger.warning("campaign_iocs resolver failed for campaign=#{inspect(campaign.id)}: #{inspect(error)}")
      {:ok, []}
  end

  def technique_alert_count(technique, _args, _resolution) do
    count = from(a in Alert,
      where: ^technique.id in a.mitre_techniques,
      select: count(a.id)
    )
    |> Repo.one()

    {:ok, count || 0}
  rescue
    error ->
      Logger.warning("technique_alert_count resolver failed for technique=#{inspect(technique.id)}: #{inspect(error)}")
      {:ok, 0}
  end

  # Mutation resolvers

  def create_ioc(_parent, %{input: input}, _resolution) do
    attrs = %{
      type: input.type,
      value: input.value,
      source: input[:source] || "manual",
      description: input[:description],
      severity: input[:severity] || "medium",
      confidence: input[:confidence] || 0.8,
      tags: input[:tags] || []
    }

    case ThreatIntel.add_ioc(attrs) do
      {:ok, ioc} -> {:ok, ioc}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def bulk_import_iocs(_parent, %{input: input}, _resolution) do
    source = input[:source] || "bulk_import"
    default_severity = input[:default_severity] || "medium"

    results = Enum.map(input.iocs, fn ioc_input ->
      attrs = %{
        type: ioc_input.type,
        value: ioc_input.value,
        source: ioc_input[:source] || source,
        description: ioc_input[:description],
        severity: ioc_input[:severity] || default_severity,
        confidence: ioc_input[:confidence] || 0.8,
        tags: ioc_input[:tags] || []
      }

      ThreatIntel.add_ioc(attrs)
    end)

    successful = Enum.count(results, fn
      {:ok, _} -> true
      _ -> false
    end)

    {:ok, %{
      success: successful > 0,
      message: "Imported #{successful} of #{length(results)} IOCs"
    }}
  end

  def delete_ioc(_parent, %{id: id}, _resolution) do
    case Repo.get(IOC, id) do
      nil ->
        {:ok, %{success: false, id: id, message: "IOC not found"}}

      ioc ->
        case Repo.delete(ioc) do
          {:ok, _} -> {:ok, %{success: true, id: id, message: "IOC deleted"}}
          {:error, _} -> {:ok, %{success: false, id: id, message: "Failed to delete IOC"}}
        end
    end
  rescue
    error ->
      Logger.warning("delete_ioc resolver failed for id=#{inspect(id)}: #{inspect(error)}")
      {:ok, %{success: false, id: id, message: "Error deleting IOC"}}
  end

  def enrich_ioc(_parent, %{input: input}, _resolution) do
    case ThreatIntel.enrich_ioc(input.type, input.value) do
      {:ok, enrichment} -> {:ok, enrichment}
      {:error, reason} -> {:error, inspect(reason)}
    end
  rescue
    e -> {:error, "Enrichment failed: #{Exception.message(e)}"}
  end

  def create_threat_actor(_parent, %{input: input}, _resolution) do
    case ThreatIntel.create_actor(input) do
      {:ok, actor} -> {:ok, actor}
      {:error, reason} -> {:error, inspect(reason)}
    end
  rescue
    e -> {:error, "Failed to create actor: #{Exception.message(e)}"}
  end

  def sync_threat_feeds(_parent, _args, _resolution) do
    case ThreatIntel.sync_all_feeds() do
      {:ok, results} ->
        {:ok, %{success: true, message: "Synced #{length(results)} feeds"}}
      {:error, reason} ->
        {:ok, %{success: false, message: "Sync failed: #{inspect(reason)}"}}
    end
  rescue
    e -> {:ok, %{success: false, message: "Sync failed: #{Exception.message(e)}"}}
  end

  # Private helpers

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
    where(query, [i], i.is_active == ^is_active)
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
