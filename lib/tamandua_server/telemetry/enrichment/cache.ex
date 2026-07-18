defmodule TamanduaServer.Telemetry.Enrichment.Cache do
  @moduledoc """
  Cache for enrichment lookups to reduce external API calls and database queries.

  Provides TTL-based caching for:
  - Threat intelligence lookups (1 hour TTL)
  - GeoIP lookups (24 hour TTL)
  - Asset context lookups (5 minute TTL)

  Uses Nebulex for distributed caching support.
  """

  use Nebulex.Cache,
    otp_app: :tamandua_server,
    adapter: Nebulex.Adapters.Local

  require Logger

  # Cache TTLs
  @threat_intel_ttl :timer.hours(1)
  @geo_ip_ttl :timer.hours(24)
  @asset_context_ttl :timer.minutes(5)
  @user_context_ttl :timer.minutes(10)

  # ──────────────────────────────────────────────────────────────────
  # Threat Intel Cache
  # ──────────────────────────────────────────────────────────────────

  @doc """
  Get or lookup threat intelligence for an IOC.

  Returns cached result if available, otherwise performs lookup and caches it.
  """
  def get_or_lookup_threat_intel(ioc_type, ioc_value, organization_id \\ nil) do
    organization_id = valid_organization_id(organization_id)
    cache_key = {:threat_intel, organization_id, ioc_type, ioc_value}

    case get(cache_key) do
      nil ->
        result = lookup_threat_intel(ioc_type, ioc_value, organization_id)
        put(cache_key, result, ttl: @threat_intel_ttl)
        result

      cached ->
        cached
    end
  end

  defp lookup_threat_intel(ioc_type, ioc_value, organization_id) do
    alias TamanduaServer.Detection.IOCs
    alias TamanduaServer.ThreatIntel

    # Try IOC database first
    case IOCs.lookup_for_organization(to_string(ioc_type), ioc_value, organization_id) do
      {:ok, ioc} ->
        {:ok, ioc}

      {:error, :not_found} ->
        # Try ThreatIntel ETS cache
        ThreatIntel.lookup(ioc_type, ioc_value)
    end
  rescue
    e ->
      Logger.debug("Threat intel lookup failed for #{ioc_type}/#{ioc_value}: #{Exception.message(e)}")
      {:error, :lookup_failed}
  end

  defp valid_organization_id(organization_id)
       when is_binary(organization_id) and organization_id != "",
       do: organization_id

  defp valid_organization_id(_organization_id), do: nil

  # ──────────────────────────────────────────────────────────────────
  # GeoIP Cache
  # ──────────────────────────────────────────────────────────────────

  @doc """
  Get or lookup GeoIP information for an IP address.

  Returns cached result if available, otherwise performs lookup and caches it.
  """
  def get_or_lookup_geo(ip) do
    cache_key = {:geo_ip, ip}

    case get(cache_key) do
      nil ->
        result = lookup_geo(ip)
        put(cache_key, result, ttl: @geo_ip_ttl)
        result

      cached ->
        cached
    end
  end

  defp lookup_geo(ip) do
    alias TamanduaServer.Enrichment.GeoIP

    GeoIP.lookup(ip)
  rescue
    e ->
      Logger.debug("GeoIP lookup failed for #{ip}: #{Exception.message(e)}")
      {:error, :lookup_failed}
  end

  # ──────────────────────────────────────────────────────────────────
  # Asset Context Cache
  # ──────────────────────────────────────────────────────────────────

  @doc """
  Get or lookup asset context for an agent.

  Returns cached result if available, otherwise performs lookup and caches it.
  """
  def get_or_lookup_asset(agent_id) do
    cache_key = {:asset, agent_id}

    case get(cache_key) do
      nil ->
        result = lookup_asset(agent_id)
        put(cache_key, result, ttl: @asset_context_ttl)
        result

      cached ->
        cached
    end
  end

  defp lookup_asset(agent_id) do
    alias TamanduaServer.Agents

    case Agents.get_agent(agent_id) do
      nil ->
        {:error, :not_found}

      agent ->
        {:ok, %{
          hostname: agent.hostname,
          os_type: agent.os_type,
          os_version: agent.os_version,
          tags: agent.tags || [],
          criticality: agent.criticality,
          location: agent.location,
          organization_id: agent.organization_id
        }}
    end
  rescue
    e ->
      Logger.debug("Asset lookup failed for #{agent_id}: #{Exception.message(e)}")
      {:error, :lookup_failed}
  end

  # ──────────────────────────────────────────────────────────────────
  # User Context Cache
  # ──────────────────────────────────────────────────────────────────

  @doc """
  Get or lookup user context.

  Returns cached result if available, otherwise performs lookup and caches it.
  """
  def get_or_lookup_user(username) when is_binary(username) do
    cache_key = {:user, String.downcase(username)}

    case get(cache_key) do
      nil ->
        result = lookup_user(username)
        put(cache_key, result, ttl: @user_context_ttl)
        result

      cached ->
        cached
    end
  end

  def get_or_lookup_user(_), do: {:error, :invalid_username}

  defp lookup_user(_username) do
    # This would integrate with your user management system
    # For now, return a placeholder
    {:error, :not_implemented}
  end

  # ──────────────────────────────────────────────────────────────────
  # Cache Management
  # ──────────────────────────────────────────────────────────────────

  @doc """
  Clear all enrichment caches.
  """
  def clear_all do
    delete_all()
    :ok
  end

  @doc """
  Clear threat intel cache.
  """
  def clear_threat_intel do
    # Delete all keys matching {:threat_intel, _, _}
    all()
    |> Stream.filter(fn {key, _} ->
      case key do
        {:threat_intel, _, _, _} -> true
        _ -> false
      end
    end)
    |> Stream.each(fn {key, _} -> delete(key) end)
    |> Stream.run()

    :ok
  end

  @doc """
  Clear GeoIP cache.
  """
  def clear_geo do
    all()
    |> Stream.filter(fn {key, _} ->
      case key do
        {:geo_ip, _} -> true
        _ -> false
      end
    end)
    |> Stream.each(fn {key, _} -> delete(key) end)
    |> Stream.run()

    :ok
  end

  @doc """
  Get a per-type breakdown of cache entries.

  Named `entry_stats/0` because `use Nebulex.Cache` already generates a
  `stats/0` (adapter-level hit/miss counters), which would shadow a local
  `stats/0` clause and make it unreachable.
  """
  def entry_stats do
    entries = all() |> Enum.to_list()

    %{
      total_entries: length(entries),
      threat_intel_entries: count_by_type(entries, :threat_intel),
      geo_entries: count_by_type(entries, :geo_ip),
      asset_entries: count_by_type(entries, :asset),
      user_entries: count_by_type(entries, :user)
    }
  end

  defp count_by_type(entries, type) do
    Enum.count(entries, fn {key, _} ->
      case key do
        {^type, _} -> true
        {^type, _, _} -> true
        {^type, _, _, _} -> true
        _ -> false
      end
    end)
  end
end
