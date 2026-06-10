defmodule TamanduaServer.Enrichment.GeoIP do
  @moduledoc """
  GeoIP lookup service for IP address enrichment.

  Uses MaxMind GeoLite2 databases for:
  - Country/City location
  - ASN (Autonomous System Number)
  - Organization/ISP information

  Supports local MaxMind-compatible MMDB databases when the optional Geolix
  runtime is available, and DB-IP Lite CSV files for keyless open-data
  deployments.
  """

  use GenServer
  require Logger

  @geoip_db_path Application.compile_env(:tamandua_server, :geoip_db_path, "/var/lib/tamandua/geoip")

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Look up GeoIP information for an IP address.

  Returns:
    {:ok, %{
      country_code: "US",
      country_name: "United States",
      city: "San Francisco",
      region: "California",
      latitude: 37.7749,
      longitude: -122.4194,
      asn: 15169,
      asn_org: "Google LLC",
      is_tor: false,
      is_proxy: false,
      is_datacenter: false
    }}
  """
  def lookup(ip) when is_binary(ip) do
    # Handler may fall back to an external HTTP API with a 5s receive_timeout;
    # use a call timeout above that so the caller degrades gracefully instead
    # of exiting at the 5s GenServer default.
    GenServer.call(__MODULE__, {:lookup, ip}, 15_000)
  end

  @doc """
  Check if an IP is from a suspicious location (high-risk country).
  """
  def is_high_risk?(ip) when is_binary(ip) do
    case lookup(ip) do
      {:ok, %{country_code: country_code}} ->
        country_code in high_risk_countries()
      _ ->
        false
    end
  end

  @doc """
  Check if an IP is a known Tor exit node or proxy.
  """
  def is_anonymous?(ip) when is_binary(ip) do
    case lookup(ip) do
      {:ok, %{is_tor: is_tor, is_proxy: is_proxy}} ->
        is_tor or is_proxy
      _ ->
        false
    end
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    state = %{
      city_db: nil,
      asn_db: nil,
      country_ranges: nil,
      loaded: false
    }

    # Load databases asynchronously
    send(self(), :load_databases)

    {:ok, state}
  end

  @impl true
  def handle_info(:load_databases, state) do
    city_path = Path.join(@geoip_db_path, "GeoLite2-City.mmdb")
    asn_path = Path.join(@geoip_db_path, "GeoLite2-ASN.mmdb")
    country_ranges = load_dbip_country_ranges()

    city_db = load_database(city_path, "City")
    asn_db = load_database(asn_path, "ASN")

    loaded = city_db != nil or asn_db != nil or country_ranges != nil

    if loaded do
      Logger.info("GeoIP databases loaded")
    else
      Logger.warning("No GeoIP databases found at #{@geoip_db_path}")
    end

    {:noreply, %{state | city_db: city_db, asn_db: asn_db, country_ranges: country_ranges, loaded: loaded}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_call({:lookup, ip}, _from, state) do
    result = do_lookup(ip, state)
    {:reply, result, state}
  end

  # Private functions

  defp do_lookup(ip, %{loaded: false}) do
    # Fallback to external API if no local database
    lookup_via_api(ip)
  end

  defp do_lookup(ip, %{city_db: city_db, asn_db: asn_db, country_ranges: country_ranges}) do
    with {:ok, parsed_ip} <- parse_ip(ip) do
      city_info = if city_db, do: lookup_city(city_db, parsed_ip), else: %{}
      asn_info = if asn_db, do: lookup_asn(asn_db, parsed_ip), else: %{}
      country_info = lookup_country_ranges(country_ranges, parsed_ip)

      result =
        country_info
        |> merge_non_nil(city_info)
        |> merge_non_nil(asn_info)

      # If the local MMDB returned no useful data, fall back to the API
      has_data = result[:country_code] != nil or result[:asn] != nil

      if has_data do
        final = result
        |> Map.put(:ip, ip)
        |> Map.put_new(:is_tor, false)
        |> Map.put_new(:is_proxy, false)
        |> Map.put_new(:is_datacenter, is_datacenter?(result[:asn_org]))
        |> add_risk_indicators()

        {:ok, final}
      else
        lookup_via_api(ip)
      end
    end
  end

  defp parse_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, addr} -> {:ok, addr}
      {:error, _} -> {:error, :invalid_ip}
    end
  end

  defp load_database(path, name) do
    if File.exists?(path) do
      Logger.info("Loading #{name} MMDB database from #{path}")
      db_id = String.to_atom("geoip_#{String.downcase(name)}")

      if Code.ensure_loaded?(Geolix) and Code.ensure_loaded?(Geolix.Adapter.MMDB2) do
        case Geolix.load_database(%{
          id: db_id,
          adapter: Geolix.Adapter.MMDB2,
          source: path
        }) do
          :ok ->
            Logger.info("#{name} MMDB database loaded successfully")
            db_id

          {:error, reason} ->
            Logger.warning("Failed to load #{name} MMDB database: #{inspect(reason)}")
            nil
        end
      else
        Logger.warning("#{name} MMDB database found, but Geolix/MMDB2 is not available at runtime")
        nil
      end
    else
      Logger.debug("#{name} MMDB database not found at #{path}")
      nil
    end
  rescue
    e ->
      Logger.warning("Error loading #{name} MMDB database: #{inspect(e)}")
      nil
  end

  defp load_dbip_country_ranges do
    paths =
      [
        Path.join(@geoip_db_path, "dbip-country-lite.csv")
      ] ++ Path.wildcard(Path.join(@geoip_db_path, "dbip-country-lite-*.csv"))

    case Enum.find(paths, &File.exists?/1) do
      nil ->
        Logger.debug("DB-IP Country Lite CSV not found at #{@geoip_db_path}")
        nil

      path ->
        ranges =
          path
          |> stream_country_csv()
          |> Stream.map(&parse_dbip_country_row/1)
          |> Stream.reject(&is_nil/1)
          |> Enum.sort_by(fn {first, _last, _code, _name} -> first end)
          |> List.to_tuple()

        Logger.info("DB-IP Country Lite CSV loaded from #{path} with #{tuple_size(ranges)} IPv4 ranges")
        ranges
    end
  rescue
    e ->
      Logger.warning("Failed to load DB-IP Country Lite CSV: #{inspect(e)}")
      nil
  end

  defp stream_country_csv(path), do: File.stream!(path)

  defp parse_dbip_country_row(line) do
    line = String.trim(line)

    case Regex.run(~r/^"?([^",]+)"?,"?([^",]+)"?,"?([A-Z]{2}|ZZ)"?,"?([^"]*)"?$/, line) do
      [_, first_ip, last_ip, country_code, country_name] ->
        with {:ok, first} <- ipv4_to_integer(first_ip),
             {:ok, last} <- ipv4_to_integer(last_ip) do
          {first, last, country_code, country_name}
        else
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp lookup_country_ranges(nil, _parsed_ip), do: %{}

  defp lookup_country_ranges(ranges, parsed_ip) do
    case ip_to_integer(parsed_ip) do
      {:ok, ip_int} ->
        case find_range(ranges, ip_int, 0, tuple_size(ranges) - 1) do
          {_first, _last, country_code, country_name} ->
            %{
              country_code: country_code,
              country_name: country_name,
              city: nil,
              region: nil,
              latitude: nil,
              longitude: nil
            }

          nil ->
            %{}
        end

      :error ->
        %{}
    end
  end

  defp find_range(_ranges, _ip_int, low, high) when low > high, do: nil

  defp find_range(ranges, ip_int, low, high) do
    mid = div(low + high, 2)
    {first, last, _country_code, _country_name} = range = elem(ranges, mid)

    cond do
      ip_int < first -> find_range(ranges, ip_int, low, mid - 1)
      ip_int > last -> find_range(ranges, ip_int, mid + 1, high)
      true -> range
    end
  end

  defp ip_to_integer({a, b, c, d}), do: {:ok, a * 16_777_216 + b * 65_536 + c * 256 + d}
  defp ip_to_integer(_ipv6), do: :error

  defp ipv4_to_integer(ip) do
    with {:ok, parsed} <- parse_ip(ip),
         {:ok, int} <- ip_to_integer(parsed) do
      {:ok, int}
    else
      _ -> :error
    end
  end

  defp merge_non_nil(left, right) do
    Enum.reduce(right, left, fn
      {_key, nil}, acc -> acc
      {key, value}, acc -> Map.put(acc, key, value)
    end)
  end

  defp lookup_city(db_id, ip) do
    case Geolix.lookup(ip, where: db_id) do
      %{country: country, city: city, location: location} ->
        %{
          country_code: get_in(country, [:iso_code]),
          country_name: get_in(country, [:name]),
          city: get_in(city, [:name]),
          region: nil,
          latitude: get_in(location, [:latitude]),
          longitude: get_in(location, [:longitude])
        }

      %{country: country} ->
        %{
          country_code: get_in(country, [:iso_code]),
          country_name: get_in(country, [:name]),
          city: nil,
          region: nil,
          latitude: nil,
          longitude: nil
        }

      _ ->
        %{
          country_code: nil,
          country_name: nil,
          city: nil,
          region: nil,
          latitude: nil,
          longitude: nil
        }
    end
  rescue
    _ ->
      %{country_code: nil, country_name: nil, city: nil, region: nil, latitude: nil, longitude: nil}
  end

  defp lookup_asn(db_id, ip) do
    case Geolix.lookup(ip, where: db_id) do
      %{autonomous_system_number: asn, autonomous_system_organization: org} ->
        %{asn: asn, asn_org: org}

      _ ->
        %{asn: nil, asn_org: nil}
    end
  rescue
    _ ->
      %{asn: nil, asn_org: nil}
  end

  defp lookup_via_api(ip) do
    # Use free ip-api.com service as fallback
    url = "http://ip-api.com/json/#{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as"

    case Req.get(url, receive_timeout: 5000) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        if body["status"] == "success" do
          {:ok, %{
            ip: ip,
            country_code: body["countryCode"],
            country_name: body["country"],
            city: body["city"],
            region: body["regionName"],
            latitude: body["lat"],
            longitude: body["lon"],
            asn: parse_asn(body["as"]),
            asn_org: body["isp"] || body["org"],
            is_tor: false,
            is_proxy: false,
            is_datacenter: is_datacenter?(body["isp"])
          }}
        else
          {:error, body["message"] || "Unknown error"}
        end

      {:ok, %{status: status}} ->
        {:error, "API returned status #{status}"}

      {:error, reason} ->
        {:error, "API request failed: #{inspect(reason)}"}
    end
  end

  defp parse_asn(nil), do: nil
  defp parse_asn(as_string) when is_binary(as_string) do
    case Regex.run(~r/AS(\d+)/, as_string) do
      [_, asn] -> String.to_integer(asn)
      _ -> nil
    end
  end

  defp is_datacenter?(nil), do: false
  defp is_datacenter?(isp) do
    datacenter_keywords = [
      "amazon", "aws", "google", "microsoft", "azure",
      "digitalocean", "linode", "vultr", "hetzner",
      "ovh", "cloudflare", "akamai", "fastly"
    ]

    isp_lower = String.downcase(isp)
    Enum.any?(datacenter_keywords, &String.contains?(isp_lower, &1))
  end

  defp add_risk_indicators(info) do
    is_high_risk = info[:country_code] in high_risk_countries()
    is_datacenter = info[:is_datacenter] || false

    Map.merge(info, %{
      is_high_risk_country: is_high_risk,
      risk_score: calculate_risk_score(info)
    })
  end

  defp calculate_risk_score(info) do
    score = 0

    score = if info[:is_tor], do: score + 40, else: score
    score = if info[:is_proxy], do: score + 30, else: score
    score = if info[:is_datacenter], do: score + 20, else: score
    score = if info[:country_code] in high_risk_countries(), do: score + 20, else: score

    min(score, 100)
  end

  defp high_risk_countries do
    # Countries commonly associated with cyber attacks
    # This list should be configurable
    ~w(RU CN KP IR SY)
  end
end
