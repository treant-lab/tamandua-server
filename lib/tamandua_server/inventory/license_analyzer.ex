defmodule TamanduaServer.Inventory.LicenseAnalyzer do
  @moduledoc """
  Conservative license metadata analysis for asset software inventory.

  This module classifies only the license metadata already present in inventory
  payloads. It does not infer legal compliance, ownership, or entitlement.
  Missing or ambiguous metadata is reported as `unknown`.
  """

  @risk_levels ~w(unknown permissive copyleft restricted commercial unlicensed)

  defp permissive_patterns do
    [
    ~r/\bmit\b/i,
    ~r/\bapache(?:\s|-)?2(?:\.0)?\b/i,
    ~r/\bbsd(?:\s|-)?(?:2|3)?\b/i,
    ~r/\bisc\b/i,
    ~r/\bzlib\b/i,
    ~r/\bboost\b/i,
    ~r/\bmozilla public license\b/i,
    ~r/\bmpl(?:\s|-)?2(?:\.0)?\b/i,
    ~r/\bpublic domain\b/i,
    ~r/\bunlicense\b/i,
    ~r/\bcc0\b/i
    ]
  end

  defp copyleft_patterns do
    [
    ~r/\bagpl\b/i,
    ~r/\bgpl\b/i,
    ~r/\blgpl\b/i,
    ~r/\bgnu general public license\b/i,
    ~r/\bgnu lesser general public license\b/i,
    ~r/\bepl(?:\s|-)?(?:1|2)(?:\.0)?\b/i,
    ~r/\bcddl\b/i
    ]
  end

  defp restricted_patterns do
    [
    ~r/\bsspl\b/i,
    ~r/\bserver side public license\b/i,
    ~r/\bcommons clause\b/i,
    ~r/\belastic license\b/i,
    ~r/\bbusiness source license\b/i,
    ~r/\bbsl(?:\s|-)?1(?:\.1)?\b/i,
    ~r/\bnon[-\s]?commercial\b/i,
    ~r/\brestricted\b/i,
    ~r/\bsource[-\s]?available\b/i
    ]
  end

  defp commercial_patterns do
    [
    ~r/\bcommercial\b/i,
    ~r/\bproprietary\b/i,
    ~r/\bclosed source\b/i,
    ~r/\beula\b/i,
    ~r/\bsubscription\b/i,
    ~r/\bpaid\b/i,
    ~r/\btrial\b/i
    ]
  end

  @unlicensed_values [
    "none",
    "no license",
    "not licensed",
    "unlicensed",
    "all rights reserved",
    "license missing"
  ]

  @doc """
  Analyze the installed software for an asset-like map or struct.
  """
  def analyze_asset(asset) do
    software = software_items(asset)
    analyzed = Enum.map(software, &analyze_software/1)

    %{
      asset_id: field(asset, :id),
      hostname: field(asset, :hostname),
      generated_at: DateTime.utc_now(),
      summary: summarize(analyzed),
      findings: findings(analyzed),
      software: analyzed
    }
  end

  @doc """
  Normalize and classify one software inventory item.
  """
  def analyze_software(item) when is_map(item) do
    {license, source} = license_value(item)
    normalized_license = normalize_license(license)
    license_risk = classify_license(normalized_license)

    %{
      name: field(item, :name),
      version: field(item, :version),
      vendor: field(item, :vendor),
      license: normalized_license,
      license_source: source,
      license_risk: license_risk,
      metadata: metadata(item)
    }
  end

  def analyze_software(_item) do
    analyze_software(%{})
  end

  @doc """
  Classify normalized license metadata.
  """
  def classify_license(nil), do: "unknown"
  def classify_license(""), do: "unknown"

  def classify_license(license) when is_binary(license) do
    normalized = license |> String.trim() |> String.downcase()

    cond do
      normalized in @unlicensed_values -> "unlicensed"
      matches_any?(license, restricted_patterns()) -> "restricted"
      matches_any?(license, commercial_patterns()) -> "commercial"
      matches_any?(license, copyleft_patterns()) -> "copyleft"
      matches_any?(license, permissive_patterns()) -> "permissive"
      unknown_marker?(normalized) -> "unknown"
      true -> "unknown"
    end
  end

  def classify_license(_license), do: "unknown"

  def risk_levels, do: @risk_levels

  defp software_items(asset) do
    case field(asset, :installed_software) do
      items when is_list(items) -> items
      _ -> []
    end
  end

  defp summarize(items) do
    by_risk =
      @risk_levels
      |> Map.new(fn level -> {level, Enum.count(items, &(&1.license_risk == level))} end)

    total = length(items)
    with_metadata = Enum.count(items, &(&1.license_source != "default"))

    %{
      total_software: total,
      with_license_metadata: with_metadata,
      without_license_metadata: total - with_metadata,
      by_license_risk: by_risk,
      non_permissive_count:
        by_risk["copyleft"] + by_risk["restricted"] + by_risk["commercial"] +
          by_risk["unlicensed"],
      data_quality: %{
        license_metadata_coverage:
          if(total > 0, do: Float.round(with_metadata / total, 4), else: 0.0),
        note:
          "Classification is based only on inventory-provided license fields or metadata; unknown means no usable license metadata was present."
      }
    }
  end

  defp findings(items) do
    items
    |> Enum.reject(&(&1.license_risk == "permissive"))
    |> Enum.map(fn item ->
      %{
        type: "software_license_metadata",
        severity: finding_severity(item.license_risk),
        license_risk: item.license_risk,
        software: %{
          name: item.name,
          version: item.version,
          vendor: item.vendor,
          license: item.license
        },
        message: finding_message(item)
      }
    end)
  end

  defp finding_severity("restricted"), do: "medium"
  defp finding_severity("commercial"), do: "low"
  defp finding_severity("copyleft"), do: "low"
  defp finding_severity("unlicensed"), do: "medium"
  defp finding_severity(_), do: "info"

  defp finding_message(%{license_risk: "unknown", name: name}) do
    "No usable license metadata was provided for #{software_name(name)}."
  end

  defp finding_message(%{license_risk: risk, name: name, license: license}) do
    "#{software_name(name)} has #{risk} license metadata#{license_suffix(license)}; review policy fit before making compliance claims."
  end

  defp software_name(nil), do: "software item"
  defp software_name(""), do: "software item"
  defp software_name(name), do: name

  defp license_suffix(nil), do: ""
  defp license_suffix(""), do: ""
  defp license_suffix(license), do: " (#{license})"

  defp license_value(item) do
    metadata = metadata(item)

    [
      {:top_level, field(item, :license)},
      {:top_level, field(item, :licenses)},
      {:metadata, field(metadata, :license)},
      {:metadata, field(metadata, :licenses)},
      {:metadata, field(metadata, :license_expression)},
      {:metadata, field(metadata, :license_id)},
      {:metadata, field(metadata, :spdx_license_identifier)}
    ]
    |> Enum.find_value({"", "default"}, fn
      {source, value} ->
        normalized = normalize_license(value)

        if normalized == "" do
          nil
        else
          {normalized, Atom.to_string(source)}
        end
    end)
  end

  defp normalize_license(nil), do: ""
  defp normalize_license(value) when is_binary(value), do: String.trim(value)
  defp normalize_license(value) when is_atom(value), do: value |> Atom.to_string() |> String.trim()
  defp normalize_license(values) when is_list(values) do
    values
    |> Enum.map(&normalize_license/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(" OR ")
  end

  defp normalize_license(value) when is_map(value) do
    field(value, :id) || field(value, :name) || field(value, :license) || ""
  end

  defp normalize_license(_value), do: ""

  defp metadata(item) do
    case field(item, :metadata) do
      value when is_map(value) -> value
      _ -> %{}
    end
  end

  defp field(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  defp field(struct, key), do: Map.get(struct, key)

  defp matches_any?(value, patterns), do: Enum.any?(patterns, &Regex.match?(&1, value))

  defp unknown_marker?(value), do: value in ["unknown", "n/a", "na", "not available", "unspecified"]
end
