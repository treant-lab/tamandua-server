defmodule TamanduaServer.ThreatIntel.EmergingExposure do
  @moduledoc """
  Pure "Am I exposed?" assessment for Emerging Threats items.

  The evaluator only reports explicit local matches. Missing local context is
  surfaced as coverage gaps instead of inferring exposure.
  """

  @type exposure_status :: :exposed | :not_detected | :unknown
  @type assessment :: %{
          exposure_status: exposure_status(),
          matched_assets: [map()],
          matched_products: [map()],
          matched_cves: [map()],
          telemetry_matches: [map()],
          coverage_gaps: [atom()],
          recommended_collection: [atom()]
        }

  @doc """
  Evaluate an Emerging Threats item against local endpoint, asset, and telemetry context.

  Accepted context keys are intentionally flexible so callers can pass already-loaded
  software inventory, vulnerability rows, asset/agent records, and telemetry events.
  """
  @spec assess(map(), map() | nil) :: assessment()
  def assess(threat, context \\ %{}) when is_map(threat) do
    context = context || %{}

    threat_cves = extract_cves(threat)
    threat_products = extract_products(threat)
    threat_iocs = extract_iocs(threat)

    software = context_list(context, [:software_inventory, :installed_software, :software])
    vulnerabilities = context_list(context, [:vulnerabilities, :asset_vulnerabilities])
    assets = context_list(context, [:assets, :agents])
    telemetry = telemetry_context(context)

    matched_cves = match_cves(threat_cves, vulnerabilities, software)
    matched_products = match_products(threat_products, software)
    telemetry_matches = match_telemetry(threat_iocs, telemetry)
    matched_assets = matched_assets(matched_cves, matched_products, telemetry_matches, assets)
    coverage_gaps = coverage_gaps(context, software, vulnerabilities, assets, telemetry)

    %{
      exposure_status: exposure_status(matched_assets, matched_products, matched_cves, telemetry_matches, coverage_gaps),
      matched_assets: matched_assets,
      matched_products: matched_products,
      matched_cves: matched_cves,
      telemetry_matches: telemetry_matches,
      coverage_gaps: coverage_gaps,
      recommended_collection: recommended_collection(coverage_gaps)
    }
  end

  def assess(_threat, context), do: assess(%{}, context || %{})

  defp exposure_status(matched_assets, matched_products, matched_cves, telemetry_matches, coverage_gaps) do
    cond do
      matched_assets != [] or matched_products != [] or matched_cves != [] or telemetry_matches != [] ->
        :exposed

      coverage_gaps != [] ->
        :unknown

      true ->
        :not_detected
    end
  end

  defp coverage_gaps(context, software, vulnerabilities, assets, telemetry) do
    []
    |> maybe_gap(:software_inventory_missing, context_has_any?(context, [:software_inventory, :installed_software, :software]) and software == [])
    |> maybe_gap(:vulnerability_inventory_missing, context_has_any?(context, [:vulnerabilities, :asset_vulnerabilities]) and vulnerabilities == [])
    |> maybe_gap(:asset_inventory_missing, context_has_any?(context, [:assets, :agents]) and assets == [])
    |> maybe_gap(:telemetry_missing, telemetry_context_present?(context) and telemetry == [])
    |> maybe_gap(:software_inventory_missing, not context_has_any?(context, [:software_inventory, :installed_software, :software]))
    |> maybe_gap(:vulnerability_inventory_missing, not context_has_any?(context, [:vulnerabilities, :asset_vulnerabilities]))
    |> maybe_gap(:asset_inventory_missing, not context_has_any?(context, [:assets, :agents]))
    |> maybe_gap(:telemetry_missing, not telemetry_context_present?(context))
    |> Enum.uniq()
  end

  defp maybe_gap(gaps, gap, true), do: [gap | gaps]
  defp maybe_gap(gaps, _gap, _), do: gaps

  defp recommended_collection(coverage_gaps) do
    coverage_gaps
    |> Enum.flat_map(fn
      :software_inventory_missing -> [:software_inventory]
      :vulnerability_inventory_missing -> [:vulnerability_scan]
      :asset_inventory_missing -> [:agent_inventory]
      :telemetry_missing -> [:network_telemetry, :browser_telemetry, :mobile_telemetry]
      _ -> []
    end)
    |> Enum.uniq()
  end

  defp match_cves([], _vulnerabilities, _software), do: []

  defp match_cves(threat_cves, vulnerabilities, software) do
    cve_set = MapSet.new(threat_cves)

    vulnerabilities
    |> Enum.flat_map(fn vuln ->
      vuln_cves(vuln)
      |> Enum.filter(&MapSet.member?(cve_set, &1))
      |> Enum.map(fn cve ->
        %{
          cve_id: cve,
          asset_id: first_present(vuln, [:asset_id, :agent_id, :device_id, :host_id]),
          product: first_present(vuln, [:product, :software_name, :name]) || software_name_for(vuln, software),
          evidence: compact_map(vuln, [:id, :software_id, :severity, :status, :source])
        }
      end)
    end)
    |> uniq_maps([:cve_id, :asset_id, :product])
  end

  defp match_products([], _software), do: []

  defp match_products(threat_products, software) do
    software
    |> Enum.filter(fn item ->
      Enum.any?(threat_products, &product_matches?(&1, item))
    end)
    |> Enum.map(fn item ->
      %{
        product: first_present(item, [:name, :product, :software_name, :package_name]),
        vendor: first_present(item, [:vendor, :publisher]),
        version: first_present(item, [:version, :software_version, :package_version]),
        asset_id: first_present(item, [:asset_id, :agent_id, :device_id, :host_id]),
        evidence: compact_map(item, [:id, :source, :package_manager, :platform])
      }
    end)
    |> uniq_maps([:product, :vendor, :version, :asset_id])
  end

  defp match_telemetry([], _telemetry), do: []

  defp match_telemetry(threat_iocs, telemetry) do
    threat_iocs
    |> Enum.flat_map(fn ioc ->
      telemetry
      |> Enum.filter(&telemetry_matches_ioc?(&1, ioc))
      |> Enum.map(fn event ->
        %{
          type: ioc.type,
          value: ioc.value,
          asset_id: first_present(event, [:asset_id, :agent_id, :device_id, :host_id]),
          event_type: first_present(event, [:event_type, :type, :category]),
          evidence: compact_map(event, [:id, :timestamp, :source])
        }
      end)
    end)
    |> uniq_maps([:type, :value, :asset_id, :event_type])
  end

  defp telemetry_matches_ioc?(event, %{type: type, value: value}) do
    event
    |> telemetry_values(type)
    |> Enum.any?(&(&1 == value))
  end

  defp telemetry_values(event, type) do
    keys =
      case type do
        "ip" -> [:ip, :src_ip, :source_ip, :dst_ip, :destination_ip, :remote_ip, :remote_address]
        "domain" -> [:domain, :hostname, :host, :dns_query, :remote_domain]
        "url" -> [:url, :uri, :request_url]
        "hash" -> [:hash, :sha256, :sha1, :md5, :file_hash]
        "package" -> [:package_name, :package, :bundle_id, :package_or_bundle_id]
        _ -> []
      end

    direct =
      keys
      |> Enum.map(&first_present(event, [&1]))
      |> Enum.reject(&blank?/1)

    payload_values =
      [:payload, :metadata, :evidence]
      |> Enum.flat_map(fn key ->
        case first_present(event, [key]) do
          nested when is_map(nested) -> Enum.map(keys, &first_present(nested, [&1]))
          _ -> []
        end
      end)
      |> Enum.reject(&blank?/1)

    (direct ++ payload_values)
    |> Enum.map(&normalize_ioc_value(type, &1))
    |> Enum.reject(&blank?/1)
  end

  defp matched_assets(matched_cves, matched_products, telemetry_matches, assets) do
    explicit_ids =
      (matched_cves ++ matched_products ++ telemetry_matches)
      |> Enum.map(& &1.asset_id)
      |> Enum.reject(&blank?/1)
      |> MapSet.new()

    assets
    |> Enum.filter(fn asset ->
      asset_id = first_present(asset, [:id, :asset_id, :agent_id, :device_id, :host_id])
      not blank?(asset_id) and MapSet.member?(explicit_ids, asset_id)
    end)
    |> Enum.map(fn asset ->
      %{
        asset_id: first_present(asset, [:id, :asset_id, :agent_id, :device_id, :host_id]),
        hostname: first_present(asset, [:hostname, :name, :device_name]),
        platform: first_present(asset, [:platform, :os_type, :os]),
        evidence: compact_map(asset, [:status, :last_seen, :source])
      }
    end)
    |> Kernel.++(
      explicit_ids
      |> Enum.reject(fn id -> Enum.any?(assets, &(first_present(&1, [:id, :asset_id, :agent_id, :device_id, :host_id]) == id)) end)
      |> Enum.map(&%{asset_id: &1, hostname: nil, platform: nil, evidence: %{}})
    )
    |> uniq_maps([:asset_id])
  end

  defp extract_cves(value) do
    value
    |> collect_values([:cve, :cve_id, :cve_ids, :cves, :vulnerability, :vulnerabilities])
    |> Enum.flat_map(&cves_from_value/1)
    |> Enum.uniq()
  end

  defp cves_from_value(value) when is_binary(value) do
    Regex.scan(~r/CVE-\d{4}-\d{4,}/i, value)
    |> List.flatten()
    |> Enum.map(&String.upcase/1)
  end

  defp cves_from_value(values) when is_list(values), do: Enum.flat_map(values, &cves_from_value/1)
  defp cves_from_value(value) when is_map(value), do: extract_cves(value)
  defp cves_from_value(_), do: []

  defp vuln_cves(vuln), do: extract_cves(vuln)

  defp extract_products(value) do
    value
    |> collect_values([:product, :products, :affected_product, :affected_products, :software, :package_name])
    |> Enum.flat_map(&products_from_value/1)
    |> Enum.reject(&(product_key(&1) == nil))
    |> uniq_by_key(&product_key/1)
  end

  defp products_from_value(value) when is_binary(value), do: [%{name: value}]
  defp products_from_value(values) when is_list(values), do: Enum.flat_map(values, &products_from_value/1)
  defp products_from_value(value) when is_map(value), do: [value]
  defp products_from_value(_), do: []

  defp extract_iocs(value) do
    value
    |> collect_values([:ioc, :iocs, :indicator, :indicators, :observable, :observables])
    |> Enum.flat_map(&iocs_from_value/1)
    |> Enum.reject(&blank?(&1.value))
    |> uniq_maps([:type, :value])
  end

  defp iocs_from_value(values) when is_list(values), do: Enum.flat_map(values, &iocs_from_value/1)

  defp iocs_from_value(%{} = value) do
    raw_type = first_present(value, [:type, :ioc_type, :indicator_type])
    raw_value = first_present(value, [:value, :indicator, :ioc, :observable])
    type = normalize_ioc_type(raw_type, raw_value)
    normalized = normalize_ioc_value(type, raw_value)

    if blank?(type) or blank?(normalized), do: [], else: [%{type: type, value: normalized}]
  end

  defp iocs_from_value(value) when is_binary(value) do
    type = normalize_ioc_type(nil, value)
    normalized = normalize_ioc_value(type, value)

    if blank?(type) or blank?(normalized), do: [], else: [%{type: type, value: normalized}]
  end

  defp iocs_from_value(_), do: []

  defp normalize_ioc_type(type, value) do
    type = type |> to_string_safe() |> String.downcase()

    cond do
      type in ["ip", "ipv4", "ipv6"] -> "ip"
      type in ["domain", "hostname", "dns"] -> "domain"
      type in ["url", "uri"] -> "url"
      type in ["hash", "sha256", "sha1", "md5", "file_hash"] -> "hash"
      type in ["package", "package_name", "bundle_id"] -> "package"
      valid_ip?(value) -> "ip"
      binary_like?(value) and String.starts_with?(String.downcase(to_string(value)), ["http://", "https://"]) -> "url"
      binary_like?(value) and Regex.match?(~r/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i, to_string(value)) -> "hash"
      binary_like?(value) and String.contains?(to_string(value), ".") -> "domain"
      true -> nil
    end
  end

  defp normalize_ioc_value("ip", value), do: trim_to_nil(value)
  defp normalize_ioc_value(type, value) when type in ["domain", "url", "hash", "package"], do: value |> trim_to_nil() |> downcase_or_nil()
  defp normalize_ioc_value(_, _), do: nil

  defp telemetry_context(context) do
    [:telemetry, :events, :mobile_telemetry, :browser_telemetry, :network_telemetry]
    |> Enum.flat_map(&context_list(context, [&1]))
  end

  defp telemetry_context_present?(context) do
    context_has_any?(context, [:telemetry, :events, :mobile_telemetry, :browser_telemetry, :network_telemetry])
  end

  defp context_list(context, keys) do
    keys
    |> Enum.find_value([], fn key ->
      case first_present(context, [key]) do
        list when is_list(list) -> list
        map when is_map(map) -> [map]
        _ -> nil
      end
    end)
  end

  defp context_has_any?(context, keys), do: Enum.any?(keys, &(has_key_any?(context, &1)))

  defp collect_values(value, keys) when is_map(value) do
    direct =
      keys
      |> Enum.map(&first_present(value, [&1]))
      |> Enum.reject(&is_nil/1)

    nested =
      value
      |> Map.values()
      |> Enum.flat_map(fn
        nested when is_map(nested) -> collect_values(nested, keys)
        nested when is_list(nested) -> Enum.flat_map(nested, &collect_values(&1, keys))
        _ -> []
      end)

    direct ++ nested
  end

  defp collect_values(value, keys) when is_list(value), do: Enum.flat_map(value, &collect_values(&1, keys))
  defp collect_values(_value, _keys), do: []

  defp product_key(product) when is_binary(product), do: product_key(%{name: product})

  defp product_key(product) when is_map(product) do
    name = first_present(product, [:name, :product, :software_name, :package_name])
    vendor = first_present(product, [:vendor, :publisher])
    normalized_name = normalize_product(name)
    normalized_vendor = normalize_product(vendor)

    cond do
      blank?(normalized_name) -> nil
      blank?(normalized_vendor) -> normalized_name
      true -> "#{normalized_vendor}:#{normalized_name}"
    end
  end

  defp product_key(_), do: nil

  defp product_matches?(threat_product, inventory_item) do
    threat_name = normalized_product_name(threat_product)
    item_name = normalized_product_name(inventory_item)
    threat_vendor = normalized_product_vendor(threat_product)
    item_vendor = normalized_product_vendor(inventory_item)

    not blank?(threat_name) and threat_name == item_name and
      (blank?(threat_vendor) or threat_vendor == item_vendor)
  end

  defp normalized_product_name(product) when is_binary(product), do: normalize_product(product)

  defp normalized_product_name(product) when is_map(product) do
    product
    |> first_present([:name, :product, :software_name, :package_name])
    |> normalize_product()
  end

  defp normalized_product_name(_), do: nil

  defp normalized_product_vendor(product) when is_map(product) do
    product
    |> first_present([:vendor, :publisher])
    |> normalize_product()
  end

  defp normalized_product_vendor(_), do: nil

  defp normalize_product(value) do
    case trim_to_nil(value) do
      nil ->
        nil

      string ->
        string
        |> String.downcase()
        |> String.replace(~r/[^a-z0-9]+/, " ")
        |> String.trim()
    end
  end

  defp software_name_for(vuln, software) do
    software_id = first_present(vuln, [:software_id])

    software
    |> Enum.find(&(software_id != nil and first_present(&1, [:id, :software_id]) == software_id))
    |> case do
      nil -> nil
      item -> first_present(item, [:name, :product, :software_name, :package_name])
    end
  end

  defp compact_map(map, keys) do
    keys
    |> Enum.reduce(%{}, fn key, acc ->
      value = first_present(map, [key])
      if blank?(value), do: acc, else: Map.put(acc, key, value)
    end)
  end

  defp first_present(map, keys) when is_map(map) do
    Enum.find_value(keys, fn key ->
      Map.get(map, key) || Map.get(map, Atom.to_string(key))
    end)
  end

  defp first_present(_map, _keys), do: nil

  defp has_key_any?(map, key) when is_map(map), do: Map.has_key?(map, key) or Map.has_key?(map, Atom.to_string(key))
  defp has_key_any?(_map, _key), do: false

  defp trim_to_nil(value) when is_binary(value) do
    value = String.trim(value)
    if value == "", do: nil, else: value
  end

  defp trim_to_nil(value) when is_atom(value), do: value |> Atom.to_string() |> trim_to_nil()
  defp trim_to_nil(value) when is_integer(value), do: Integer.to_string(value)
  defp trim_to_nil(_), do: nil

  defp downcase_or_nil(nil), do: nil
  defp downcase_or_nil(value), do: String.downcase(value)

  defp to_string_safe(nil), do: ""
  defp to_string_safe(value) when is_binary(value), do: value
  defp to_string_safe(value) when is_atom(value), do: Atom.to_string(value)
  defp to_string_safe(value), do: to_string(value)

  defp binary_like?(value), do: is_binary(value) or is_atom(value)

  defp valid_ip?(value) when is_binary(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp valid_ip?(_), do: false

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?([]), do: true
  defp blank?(_), do: false

  defp uniq_maps(items, keys) do
    Enum.uniq_by(items, fn item -> Enum.map(keys, &Map.get(item, &1)) end)
  end

  defp uniq_by_key(items, fun), do: Enum.uniq_by(items, fun)
end
