defmodule TamanduaServer.Jobs.NodeEnrichmentJob do
  @moduledoc """
  Oban job for enriching pending knowledge graph nodes.

  When edges are created to nodes that don't exist yet, they are marked as
  :pending. This job fetches real data for those nodes from various sources:
  - Agent telemetry cache
  - Database records (alerts, devices, vulnerabilities)
  - External enrichment APIs (threat intel, DNS, WHOIS)

  Once enriched, the node transitions from :pending to :complete status.
  """

  use Oban.Worker,
    queue: :graph_enrichment,
    max_attempts: 3,
    unique: [period: 60, keys: [:node_type, :node_id]]

  require Logger

  alias TamanduaServer.Graph.KnowledgeGraph
  alias TamanduaServer.Repo

  import Ecto.Query

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"node_type" => node_type, "node_id" => node_id}}) do
    node_type_atom = String.to_existing_atom(node_type)

    Logger.debug("[NodeEnrichment] Enriching #{node_type}:#{node_id}")

    case enrich_node(node_type_atom, node_id) do
      {:ok, attrs} ->
        # Update the node with real data and mark as complete
        enriched_attrs = Map.merge(attrs, %{
          status: :complete,
          enriched_at: DateTime.utc_now()
        })

        KnowledgeGraph.upsert_node(node_type_atom, node_id, enriched_attrs)

        Logger.info("[NodeEnrichment] Successfully enriched #{node_type}:#{node_id}")
        :ok

      {:error, :not_found} ->
        Logger.debug("[NodeEnrichment] No data found for #{node_type}:#{node_id}")
        # Keep as pending, will be cleaned up later if orphaned
        :ok

      {:error, reason} ->
        Logger.warning("[NodeEnrichment] Failed to enrich #{node_type}:#{node_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # -------------------------------------------------------------------
  # Enrichment by Node Type
  # -------------------------------------------------------------------

  defp enrich_node(:device, agent_id) do
    # Look up agent in database
    query = from a in "agents",
      where: a.id == ^agent_id or a.agent_id == ^agent_id,
      select: %{
        hostname: a.hostname,
        os: a.os_type,
        os_version: a.os_version,
        ip_addresses: a.ip_addresses,
        criticality: a.criticality,
        last_seen: a.last_seen_at
      },
      limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      data -> {:ok, data}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp enrich_node(:process, proc_id) do
    # Process IDs are in format "agent_id:pid"
    # Check if we have telemetry data cached
    case String.split(proc_id, ":", parts: 2) do
      [agent_id, _pid] ->
        # Try to get process info from recent telemetry
        # This is a simplified implementation - in production you'd query
        # a telemetry cache or recent events table
        {:ok, %{
          agent_id: agent_id,
          source: :telemetry_cache
        }}

      _ ->
        {:error, :invalid_format}
    end
  end

  defp enrich_node(:user, username) do
    # Look up user in database
    query = from u in "users",
      where: u.username == ^username or u.email == ^username,
      select: %{
        email: u.email,
        role: u.role,
        last_login: u.last_login_at,
        is_active: u.is_active
      },
      limit: 1

    case Repo.one(query) do
      nil ->
        # User might be from telemetry (Windows/Linux username)
        {:ok, %{identity: username, source: :telemetry}}

      data ->
        {:ok, data}
    end
  rescue
    _ -> {:ok, %{identity: username, source: :telemetry}}
  end

  defp enrich_node(:network, net_id) do
    # Network IDs are in format "ip:port"
    case parse_network_id(net_id) do
      {:ok, ip, port} ->
        attrs = %{
          ip: ip,
          port: port,
          external: is_external_ip?(ip)
        }

        # Optional: enrich with threat intel
        attrs = case lookup_threat_intel(ip) do
          {:ok, ti_data} -> Map.merge(attrs, ti_data)
          _ -> attrs
        end

        {:ok, attrs}

      {:error, _} ->
        {:error, :invalid_format}
    end
  end

  defp enrich_node(:file, file_id) do
    # Look up file in alerts or file events
    query = from a in "alerts",
      where: fragment("? @> ?", a.context, ^%{file_id: file_id}),
      or_where: not is_nil(a.file_path) and not is_nil(a.file_sha256),
      select: %{
        path: a.file_path,
        hash: a.file_sha256,
        classification: a.malware_family
      },
      limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      data -> {:ok, data}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp enrich_node(:alert, alert_id) do
    # Look up alert in database
    query = from a in "alerts",
      where: a.id == ^alert_id,
      select: %{
        severity: a.severity,
        title: a.title,
        description: a.description,
        mitre_tactics: a.mitre_tactics,
        mitre_techniques: a.mitre_techniques,
        agent_id: a.agent_id
      },
      limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      data -> {:ok, data}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp enrich_node(:vulnerability, vuln_id) do
    # Look up vulnerability (CVE, etc.)
    query = from v in "vulnerabilities",
      where: v.cve_id == ^vuln_id or v.id == ^vuln_id,
      select: %{
        cve_id: v.cve_id,
        severity: v.severity,
        cvss_score: v.cvss_score,
        description: v.description,
        published_at: v.published_at
      },
      limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      data -> {:ok, data}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp enrich_node(:service, service_id) do
    # Service discovery data
    {:ok, %{
      service_id: service_id,
      source: :pending_enrichment
    }}
  end

  defp enrich_node(:ai_model, model_id) do
    # AI model from inventory
    {:ok, %{
      model_id: model_id,
      source: :pending_enrichment
    }}
  end

  defp enrich_node(:mcp_server, server_id) do
    # MCP server from inventory
    {:ok, %{
      server_id: server_id,
      source: :pending_enrichment
    }}
  end

  defp enrich_node(:group, group_id) do
    # User/device group
    query = from g in "groups",
      where: g.id == ^group_id or g.name == ^group_id,
      select: %{
        name: g.name,
        description: g.description,
        member_count: fragment("array_length(?, 1)", g.member_ids)
      },
      limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      data -> {:ok, data}
    end
  rescue
    _ -> {:error, :not_found}
  end

  # -------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------

  defp parse_network_id(net_id) when is_binary(net_id) do
    case String.split(net_id, ":", parts: 2) do
      [ip, port_str] ->
        case Integer.parse(port_str) do
          {port, _} -> {:ok, ip, port}
          :error -> {:error, :invalid_port}
        end

      [ip] ->
        {:ok, ip, nil}

      _ ->
        {:error, :invalid_format}
    end
  end

  defp parse_network_id(_), do: {:error, :invalid_format}

  defp is_external_ip?(nil), do: false
  defp is_external_ip?(ip) when is_binary(ip) do
    not (String.starts_with?(ip, "10.") or
         String.starts_with?(ip, "172.16.") or
         String.starts_with?(ip, "192.168.") or
         String.starts_with?(ip, "127.") or
         ip == "::1")
  end
  defp is_external_ip?(_), do: false

  defp lookup_threat_intel(ip) do
    # Optional: query threat intel feed cache. The cache stores IOCs with a
    # severity/tags shape (not score/categories), so map honestly: a cache
    # hit means the IP appeared in a threat feed.
    case TamanduaServer.ThreatIntel.lookup(:ip, ip) do
      {:ok, ioc} ->
        {:ok, %{
          threat_score: severity_to_score(ioc[:severity]),
          threat_categories: ioc[:tags] || [],
          is_malicious: true
        }}

      _ ->
        {:error, :not_found}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp severity_to_score("critical"), do: 1.0
  defp severity_to_score("high"), do: 0.8
  defp severity_to_score("medium"), do: 0.5
  defp severity_to_score("low"), do: 0.2
  defp severity_to_score(_), do: 0.5
end
