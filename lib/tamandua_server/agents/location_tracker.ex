defmodule TamanduaServer.Agents.LocationTracker do
  @moduledoc """
  Tracks agent locations using GeoIP, detects VPN usage, and maintains location history.

  Features:
  - GeoIP lookup via MaxMind GeoLite2
  - VPN detection (datacenter IPs, known VPN providers)
  - Location history (7 days retention)
  - Region matching
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{Agent, AgentLocation, GeoRegion, VpnWhitelist}

  @doc """
  Track agent location from IP address.
  Returns {:ok, location} or {:error, reason}.
  """
  def track_location(agent_id, ip_address, opts \\ []) do
    with {:ok, agent} <- get_agent(agent_id),
         {:ok, geoip_data} <- lookup_geoip(ip_address),
         {:ok, vpn_data} <- detect_vpn(ip_address, agent.organization_id),
         {:ok, region_matches} <- match_regions(geoip_data, agent.organization_id) do
      location_attrs = %{
        organization_id: agent.organization_id,
        agent_id: agent_id,
        ip_address: ip_address,
        country_code: geoip_data[:country_code],
        country_name: geoip_data[:country_name],
        city: geoip_data[:city],
        region: geoip_data[:region],
        latitude: geoip_data[:latitude],
        longitude: geoip_data[:longitude],
        accuracy_km: geoip_data[:accuracy_km],
        source: Keyword.get(opts, :source, "geoip"),
        is_vpn: vpn_data[:is_vpn],
        vpn_provider: vpn_data[:vpn_provider],
        is_proxy: vpn_data[:is_proxy],
        is_tor: vpn_data[:is_tor],
        true_location: vpn_data[:true_location],
        matched_region_ids: region_matches,
        metadata: geoip_data[:metadata] || %{},
        detected_at: DateTime.utc_now()
      }

      # Create location record
      location =
        %AgentLocation{}
        |> AgentLocation.changeset(location_attrs)
        |> Repo.insert!()

      # Update agent's current location
      agent
      |> Ecto.Changeset.change(current_location_id: location.id)
      |> Repo.update!()

      # Cleanup old locations (older than 7 days)
      cleanup_old_locations(agent_id)

      {:ok, location}
    end
  end

  @doc """
  Get agent's current location.
  """
  def get_current_location(agent_id) do
    query =
      from l in AgentLocation,
        where: l.agent_id == ^agent_id,
        order_by: [desc: l.detected_at],
        limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      location -> {:ok, location}
    end
  end

  @doc """
  Get agent's location history for the last N days.
  """
  def get_location_history(agent_id, days \\ 7) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 86400, :second)

    query =
      from l in AgentLocation,
        where: l.agent_id == ^agent_id and l.detected_at >= ^cutoff,
        order_by: [desc: l.detected_at]

    Repo.all(query)
  end

  @doc """
  Get unique locations visited by agent in the last N days.
  """
  def get_unique_locations(agent_id, days \\ 7) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 86400, :second)

    query =
      from l in AgentLocation,
        where: l.agent_id == ^agent_id and l.detected_at >= ^cutoff,
        distinct: [l.country_code, l.city],
        select: %{
          country_code: l.country_code,
          country_name: l.country_name,
          city: l.city,
          region: l.region,
          latitude: l.latitude,
          longitude: l.longitude,
          first_seen: min(l.detected_at),
          last_seen: max(l.detected_at)
        },
        group_by: [
          l.country_code,
          l.country_name,
          l.city,
          l.region,
          l.latitude,
          l.longitude
        ],
        order_by: [desc: max(l.detected_at)]

    Repo.all(query)
  end

  @doc """
  Check if agent has traveled to a new location.
  """
  def has_traveled?(agent_id, threshold_km \\ 50) do
    case get_location_history(agent_id, 1) do
      [] ->
        false

      [_single] ->
        false

      [current | previous] ->
        distance = calculate_distance(current, List.first(previous))
        distance > threshold_km
    end
  end

  ## Private Functions

  defp get_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp lookup_geoip(ip_address) do
    case lookup_geoip_service(ip_address) do
      {:ok, data} ->
        {:ok,
         [
           country_code: data["country_code"],
           country_name: data["country_name"],
           city: data["city"],
           region: data["region"],
           latitude: data["latitude"],
           longitude: data["longitude"],
           accuracy_km: data["accuracy_km"] || 50.0,
           metadata: %{
             asn: data["asn"],
             isp: data["isp"],
             organization: data["organization"],
             timezone: data["timezone"]
           }
         ]}

      {:error, reason} ->
        Logger.warning("GeoIP lookup failed for #{ip_address}: #{inspect(reason)}")
        {:ok,
         [
           country_code: nil,
           country_name: nil,
           city: nil,
           region: nil,
           latitude: nil,
           longitude: nil,
           accuracy_km: nil,
           metadata: %{
             enrichment_status: "unknown",
             enrichment_source: "geoip",
             reason: inspect(reason)
           }
         ]}
    end
  end

  defp lookup_geoip_service(ip_address) do
    Logger.debug("GeoIP lookup for #{ip_address}")

    if private_ip?(ip_address) do
      {:ok,
       %{
         "country_code" => nil,
         "country_name" => "Private Network",
         "city" => nil,
         "region" => nil,
         "latitude" => nil,
         "longitude" => nil,
         "accuracy_km" => nil,
         "asn" => nil,
         "isp" => "Private",
         "organization" => "Private Network",
         "timezone" => nil
       }}
    else
      case TamanduaServer.Enrichment.GeoIP.lookup(ip_address) do
        {:ok, geo} ->
          {:ok,
           %{
             "country_code" => geo[:country_code],
             "country_name" => geo[:country_name],
             "city" => geo[:city],
             "region" => geo[:region],
             "latitude" => geo[:latitude],
             "longitude" => geo[:longitude],
             "accuracy_km" => geo[:accuracy_km] || 50.0,
             "asn" => geo[:asn],
             "isp" => geo[:asn_org],
             "organization" => geo[:asn_org],
             "timezone" => geo[:timezone],
             "is_datacenter" => geo[:is_datacenter],
             "is_proxy" => geo[:is_proxy],
             "is_tor" => geo[:is_tor]
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp private_ip?(ip_address) do
    case :inet.parse_address(String.to_charlist(ip_address)) do
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      {:ok, {127, _, _, _}} -> true
      _ -> false
    end
  end

  defp detect_vpn(ip_address, organization_id) do
    # Check against whitelist
    whitelist_entry = get_vpn_whitelist_entry(ip_address, organization_id)

    # Check if IP is from datacenter/hosting provider (common for VPNs)
    is_datacenter = check_datacenter_ip(ip_address)

    # Check known VPN provider lists
    vpn_provider = detect_vpn_provider(ip_address)

    is_vpn = is_datacenter || vpn_provider != nil

    {:ok,
     [
       is_vpn: is_vpn,
       vpn_provider: vpn_provider,
       is_proxy: false,
       # TODO: proxy detection
       is_tor: false,
       # TODO: Tor detection
       true_location: nil,
       # Could be enhanced with VPN leak detection
       whitelisted: whitelist_entry != nil,
       trust_level: whitelist_entry && whitelist_entry.trust_level
     ]}
  end

  defp get_vpn_whitelist_entry(ip_address, organization_id) do
    query =
      from w in VpnWhitelist,
        where: w.organization_id == ^organization_id and w.is_active == true

    whitelists = Repo.all(query)

    Enum.find(whitelists, fn whitelist ->
      ip_in_ranges?(ip_address, whitelist.ip_ranges)
    end)
  end

  defp ip_in_ranges?(ip_address, ranges) do
    Enum.any?(ranges, fn range ->
      ip_in_cidr?(ip_address, range)
    end)
  end

  defp ip_in_cidr?(ip_address, cidr) do
    # Simple CIDR matching - in production, use a proper library
    case String.split(cidr, "/") do
      [network, prefix] ->
        with {:ok, ip_tuple} <- :inet.parse_address(String.to_charlist(ip_address)),
             {:ok, network_tuple} <- :inet.parse_address(String.to_charlist(network)),
             {prefix_int, ""} <- Integer.parse(prefix) do
          ip_matches_network?(ip_tuple, network_tuple, prefix_int)
        else
          _ -> false
        end

      _ ->
        false
    end
  end

  defp ip_matches_network?(ip, network, prefix) do
    # Convert IPs to binary and compare prefix bits
    ip_bits = tuple_to_bits(ip)
    network_bits = tuple_to_bits(network)

    String.slice(ip_bits, 0, prefix) == String.slice(network_bits, 0, prefix)
  end

  defp tuple_to_bits({a, b, c, d}) do
    <<a, b, c, d>>
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 2))
    |> Enum.map(&String.pad_leading(&1, 8, "0"))
    |> Enum.join()
  end

  defp tuple_to_bits({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 2))
    |> Enum.map(&String.pad_leading(&1, 8, "0"))
    |> Enum.join()
  end

  defp check_datacenter_ip(ip_address) do
    case TamanduaServer.Enrichment.GeoIP.lookup(ip_address) do
      {:ok, geo} -> geo[:is_datacenter] || false
      _ -> false
    end
  end

  defp detect_vpn_provider(_ip_address) do
    # TODO: Check against known VPN provider IP ranges
    # Common providers:
    # - NordVPN
    # - ExpressVPN
    # - Private Internet Access
    # - Surfshark
    # - ProtonVPN
    nil
  end

  defp match_regions(geoip_data, organization_id) do
    country_code = Keyword.get(geoip_data, :country_code)
    city = Keyword.get(geoip_data, :city)
    latitude = Keyword.get(geoip_data, :latitude)
    longitude = Keyword.get(geoip_data, :longitude)

    query =
      from r in GeoRegion,
        where: r.organization_id == ^organization_id and r.is_active == true

    regions = Repo.all(query)

    matched =
      Enum.filter(regions, fn region ->
        location_matches_region?(region, country_code, city, latitude, longitude)
      end)

    {:ok, Enum.map(matched, & &1.id)}
  end

  defp location_matches_region?(region, country_code, city, latitude, longitude) do
    case region.region_type do
      "country" ->
        region.definition["country_code"] == country_code

      "city" ->
        region.definition["country"] == country_code &&
          region.definition["city"] == city

      "polygon" ->
        if latitude && longitude do
          point_in_polygon?(
            {latitude, longitude},
            region.definition["coordinates"]
          )
        else
          false
        end

      "radius" ->
        if latitude && longitude do
          center = region.definition["center"]
          radius_km = region.definition["radius_km"]
          distance = haversine_distance(latitude, longitude, center["lat"], center["lon"])
          distance <= radius_km
        else
          false
        end

      _ ->
        false
    end
  end

  defp point_in_polygon?({lat, lon}, coordinates) do
    # Ray casting algorithm
    # Convert coordinates to list of {lat, lon} tuples
    points = Enum.map(coordinates, fn [lat, lon] -> {lat, lon} end)

    # Close the polygon if not already closed
    points =
      if List.first(points) != List.last(points) do
        points ++ [List.first(points)]
      else
        points
      end

    # Count intersections
    intersections =
      points
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.count(fn [{y1, x1}, {y2, x2}] ->
        ((y1 <= lat && lat < y2) || (y2 <= lat && lat < y1)) &&
          lon < (x2 - x1) * (lat - y1) / (y2 - y1) + x1
      end)

    # Odd number of intersections means inside
    rem(intersections, 2) == 1
  end

  defp haversine_distance(lat1, lon1, lat2, lon2) do
    # Haversine formula for distance between two points on Earth
    r = 6371.0
    # Earth radius in km

    d_lat = :math.pi() * (lat2 - lat1) / 180
    d_lon = :math.pi() * (lon2 - lon1) / 180

    a =
      :math.sin(d_lat / 2) * :math.sin(d_lat / 2) +
        :math.cos(:math.pi() * lat1 / 180) *
          :math.cos(:math.pi() * lat2 / 180) *
          :math.sin(d_lon / 2) * :math.sin(d_lon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))

    r * c
  end

  defp calculate_distance(loc1, loc2) do
    if loc1.latitude && loc1.longitude && loc2.latitude && loc2.longitude do
      haversine_distance(loc1.latitude, loc1.longitude, loc2.latitude, loc2.longitude)
    else
      0.0
    end
  end

  defp cleanup_old_locations(agent_id) do
    cutoff = DateTime.utc_now() |> DateTime.add(-7 * 86400, :second)

    query =
      from l in AgentLocation,
        where: l.agent_id == ^agent_id and l.detected_at < ^cutoff

    Repo.delete_all(query)
  end
end
