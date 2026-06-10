defmodule TamanduaServer.Telemetry.Enrichment.Geo do
  @moduledoc """
  Enriches telemetry events with geographic and ASN information for IP addresses.

  Uses the GeoIP service to resolve IP addresses to country, city, ASN, and
  risk indicators. Results are cached to minimize lookups.

  Enrichment is added to the event under the :enrichment.geo key.
  """

  require Logger
  alias TamanduaServer.Enrichment.GeoIP
  alias TamanduaServer.Telemetry.Enrichment.Cache

  @doc """
  Enrich an event with GeoIP data for any IP addresses in the payload.

  Supports network events (remote_ip), DNS events, and generic IP fields.

  ## Examples

      iex> enrich_event(%{event_type: "network_connect", payload: %{"remote_ip" => "8.8.8.8"}})
      %{event_type: "network_connect", enrichment: %{geo: %{"8.8.8.8" => %{country_code: "US", ...}}}}
  """
  @spec enrich_event(map()) :: map()
  def enrich_event(event) do
    ips = extract_ip_addresses(event)

    if Enum.empty?(ips) do
      event
    else
      geo_data = lookup_ips(ips)

      if geo_data != %{} do
        enrichment = Map.get(event, :enrichment, %{})
        enrichment = Map.put(enrichment, :geo, geo_data)
        Map.put(event, :enrichment, enrichment)
      else
        event
      end
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # IP Extraction
  # ──────────────────────────────────────────────────────────────────

  defp extract_ip_addresses(event) do
    payload = event[:payload] || event["payload"] || %{}
    event_type = event[:event_type] || event["event_type"]

    ips = case event_type do
      et when et in ["network_connect", "network_connection", "network", "network_anomaly", "network_listen",
                     :network_connect, :network_connection, :network, :network_anomaly, :network_listen] ->
        [
          get_in(payload, ["remote_ip"]),
          get_in(payload, [:remote_ip]),
          get_in(payload, ["source_ip"]),
          get_in(payload, [:source_ip]),
          get_in(payload, ["dest_ip"]),
          get_in(payload, [:dest_ip])
        ]

      et when et in ["dns_query", :dns_query] ->
        # DNS responses may contain resolved IPs
        answer = get_in(payload, ["answer"]) || get_in(payload, [:answer]) || []
        if is_list(answer), do: answer, else: []

      _ ->
        # Generic extraction for any field that looks like an IP
        extract_ips_from_map(payload)
    end

    ips
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(&is_ip?/1)
    |> Enum.reject(&is_private_ip?/1)
    |> Enum.uniq()
  end

  defp extract_ips_from_map(map) when is_map(map) do
    map
    |> Map.values()
    |> Enum.flat_map(fn
      value when is_binary(value) ->
        if is_ip?(value), do: [value], else: []
      value when is_map(value) ->
        extract_ips_from_map(value)
      value when is_list(value) ->
        Enum.flat_map(value, fn
          v when is_binary(v) -> if is_ip?(v), do: [v], else: []
          v when is_map(v) -> extract_ips_from_map(v)
          _ -> []
        end)
      _ ->
        []
    end)
  end

  defp extract_ips_from_map(_), do: []

  # ──────────────────────────────────────────────────────────────────
  # GeoIP Lookup
  # ──────────────────────────────────────────────────────────────────

  defp lookup_ips(ips) do
    ips
    |> Enum.map(&lookup_ip_with_cache/1)
    |> Enum.reject(fn {_ip, result} -> result == nil end)
    |> Map.new()
  end

  defp lookup_ip_with_cache(ip) do
    case Cache.get_or_lookup_geo(ip) do
      {:ok, geo_info} ->
        {ip, format_geo_info(geo_info)}

      {:error, _reason} ->
        # Fallback to direct lookup if cache fails
        case GeoIP.lookup(ip) do
          {:ok, geo_info} ->
            {ip, format_geo_info(geo_info)}
          _ ->
            {ip, nil}
        end

      nil ->
        {ip, nil}
    end
  rescue
    e ->
      Logger.debug("GeoIP lookup failed for #{ip}: #{Exception.message(e)}")
      {ip, nil}
  end

  defp format_geo_info(info) do
    %{
      country_code: info[:country_code] || info["country_code"],
      country_name: info[:country_name] || info["country_name"],
      city: info[:city] || info["city"],
      region: info[:region] || info["region"],
      latitude: info[:latitude] || info["latitude"],
      longitude: info[:longitude] || info["longitude"],
      asn: info[:asn] || info["asn"],
      asn_org: info[:asn_org] || info["asn_org"],
      is_tor: info[:is_tor] || info["is_tor"] || false,
      is_proxy: info[:is_proxy] || info["is_proxy"] || false,
      is_datacenter: info[:is_datacenter] || info["is_datacenter"] || false,
      is_high_risk_country: info[:is_high_risk_country] || info["is_high_risk_country"] || false,
      risk_score: info[:risk_score] || info["risk_score"] || 0
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  # ──────────────────────────────────────────────────────────────────
  # Validation Helpers
  # ──────────────────────────────────────────────────────────────────

  defp is_ip?(value) when is_binary(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp is_ip?(_), do: false

  defp is_private_ip?(value) when is_binary(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      {:ok, {127, _, _, _}} -> true
      {:ok, {169, 254, _, _}} -> true
      {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true  # IPv6 loopback
      {:ok, {0xfe80, _, _, _, _, _, _, _}} -> true  # IPv6 link-local
      _ -> false
    end
  end

  defp is_private_ip?(_), do: false
end
