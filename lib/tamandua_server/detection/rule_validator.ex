defmodule TamanduaServer.Detection.RuleValidator do
  @moduledoc """
  Validates detection rules before import.
  Performs syntax checking, duplicate detection, and semantic validation.
  """

  alias TamanduaServer.Detection
  alias TamanduaServer.Repo

  require Logger

  @doc """
  Validate a YARA rule.
  Returns {:ok, parsed_metadata} or {:error, reason}.
  """
  def validate_yara(source) when is_binary(source) do
    with :ok <- validate_yara_syntax(source),
         {:ok, metadata} <- extract_yara_metadata(source) do
      {:ok, metadata}
    end
  end

  @doc """
  Validate a Sigma rule from YAML content.
  Returns {:ok, parsed_rule} or {:error, reason}.
  """
  def validate_sigma(yaml_content) when is_binary(yaml_content) do
    with {:ok, parsed} <- parse_sigma_yaml(yaml_content),
         :ok <- validate_sigma_structure(parsed),
         {:ok, normalized} <- normalize_sigma_rule(parsed) do
      {:ok, normalized}
    end
  end

  @doc """
  Validate IOC data.
  Returns {:ok, normalized_ioc} or {:error, reason}.
  """
  def validate_ioc(ioc_data) when is_map(ioc_data) do
    with :ok <- validate_ioc_type(ioc_data),
         :ok <- validate_ioc_value(ioc_data),
         {:ok, normalized} <- normalize_ioc(ioc_data) do
      {:ok, normalized}
    end
  end

  @doc """
  Check if a rule already exists (duplicate detection).
  Returns {:ok, nil} if no duplicate, {:ok, existing_rule} if duplicate found.
  """
  def check_duplicate(rule_type, identifier, organization_id) do
    case rule_type do
      :yara ->
        case Repo.get_by(Detection.YaraRule, name: identifier, organization_id: organization_id) do
          nil -> {:ok, nil}
          rule -> {:ok, rule}
        end

      :sigma ->
        case Repo.get_by(Detection.SigmaRule, name: identifier, organization_id: organization_id) do
          nil -> {:ok, nil}
          rule -> {:ok, rule}
        end

      :ioc ->
        {type, value} = identifier
        case Repo.get_by(Detection.IOC, type: type, value: value, organization_id: organization_id) do
          nil -> {:ok, nil}
          ioc -> {:ok, ioc}
        end
    end
  end

  # --- YARA Validation ---

  defp validate_yara_syntax(source) do
    cond do
      !String.contains?(source, "rule ") ->
        {:error, "Invalid YARA rule: must contain 'rule' keyword"}

      !Regex.match?(~r/rule\s+\w+\s*(\{|\:)/, source) ->
        {:error, "Invalid YARA rule structure: rule name must be followed by { or :"}

      !String.contains?(source, "{") || !String.contains?(source, "}") ->
        {:error, "Invalid YARA rule: missing braces"}

      true ->
        :ok
    end
  end

  defp extract_yara_metadata(source) do
    # Extract rule name
    name_regex = ~r/rule\s+(\w+)/
    name = case Regex.run(name_regex, source) do
      [_, name] -> name
      _ -> "unknown_rule"
    end

    # Extract basic metadata from meta section if present
    metadata = %{
      name: name,
      description: extract_yara_meta_field(source, "description"),
      author: extract_yara_meta_field(source, "author"),
      tags: extract_yara_tags(source)
    }

    {:ok, metadata}
  end

  defp extract_yara_meta_field(source, field) do
    regex = Regex.compile!("#{field}\\s*=\\s*\"([^\"]+)\"", "i")
    case Regex.run(regex, source) do
      [_, value] -> value
      _ -> nil
    end
  end

  defp extract_yara_tags(source) do
    case Regex.run(~r/rule\s+\w+\s*:\s*([^\{]+)/, source) do
      [_, tags_str] ->
        tags_str
        |> String.split()
        |> Enum.filter(&(&1 != ""))

      _ ->
        []
    end
  end

  # --- Sigma Validation ---

  defp parse_sigma_yaml(yaml_content) do
    case YamlElixir.read_from_string(yaml_content) do
      {:ok, parsed} when is_map(parsed) ->
        {:ok, parsed}

      {:ok, _} ->
        {:error, "Sigma rule must be a YAML map"}

      {:error, %{message: message}} ->
        {:error, "Invalid YAML: #{message}"}

      {:error, reason} ->
        {:error, "Invalid YAML: #{inspect(reason)}"}
    end
  rescue
    e ->
      {:error, "Failed to parse YAML: #{Exception.message(e)}"}
  end

  defp validate_sigma_structure(parsed) do
    required_fields = ["title", "detection"]

    missing = Enum.filter(required_fields, fn field ->
      !Map.has_key?(parsed, field) || is_nil(parsed[field])
    end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, "Missing required Sigma fields: #{Enum.join(missing, ", ")}"}
    end
  end

  defp normalize_sigma_rule(parsed) do
    # Generate name from title if not present
    name = parsed["name"] || parsed["id"] || slugify(parsed["title"])

    normalized = %{
      name: name,
      title: parsed["title"],
      description: parsed["description"],
      author: parsed["author"],
      # Solana base58 public key for bounty payments (optional)
      author_pubkey: parsed["author_pubkey"],
      level: parsed["level"] || "medium",
      status: parsed["status"] || "experimental",
      source: Jason.encode!(parsed),
      detection: parsed["detection"] || %{},
      logsource_category: get_in(parsed, ["logsource", "category"]),
      logsource_product: get_in(parsed, ["logsource", "product"]),
      logsource_service: get_in(parsed, ["logsource", "service"]),
      tags: extract_sigma_tags(parsed["tags"]),
      mitre_tactics: extract_mitre_tactics(parsed["tags"]),
      mitre_techniques: extract_mitre_techniques(parsed["tags"]),
      references: parsed["references"] || []
    }

    {:ok, normalized}
  end

  defp extract_sigma_tags(nil), do: []
  defp extract_sigma_tags(tags) when is_list(tags) do
    tags
    |> Enum.reject(&String.starts_with?(&1, "attack."))
    |> Enum.map(&String.downcase/1)
  end
  defp extract_sigma_tags(_), do: []

  defp extract_mitre_tactics(nil), do: []
  defp extract_mitre_tactics(tags) when is_list(tags) do
    tags
    |> Enum.filter(&String.starts_with?(&1, "attack.") && !String.contains?(&1, ".t"))
    |> Enum.map(&String.replace_prefix(&1, "attack.", ""))
    |> Enum.map(&String.replace(&1, "_", "-"))
  end
  defp extract_mitre_tactics(_), do: []

  defp extract_mitre_techniques(nil), do: []
  defp extract_mitre_techniques(tags) when is_list(tags) do
    tags
    |> Enum.filter(&String.contains?(&1, ".t"))
    |> Enum.map(fn tag ->
      tag
      |> String.split(".")
      |> List.last()
      |> String.upcase()
    end)
  end
  defp extract_mitre_techniques(_), do: []

  defp slugify(str) do
    str
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9\s-]/, "")
    |> String.replace(~r/\s+/, "_")
    |> String.slice(0, 100)
  end

  # --- IOC Validation ---

  defp validate_ioc_type(%{"type" => type}) when type in ["hash_md5", "hash_sha1", "hash_sha256", "ip", "domain", "url", "email", "filename"] do
    :ok
  end
  defp validate_ioc_type(%{type: type}) when type in [:hash_md5, :hash_sha1, :hash_sha256, :ip, :domain, :url, :email, :filename] do
    :ok
  end
  defp validate_ioc_type(_) do
    {:error, "Invalid IOC type. Must be one of: hash_md5, hash_sha1, hash_sha256, ip, domain, url, email, filename"}
  end

  defp validate_ioc_value(%{"value" => value}) when is_binary(value) and byte_size(value) > 0, do: :ok
  defp validate_ioc_value(%{value: value}) when is_binary(value) and byte_size(value) > 0, do: :ok
  defp validate_ioc_value(_), do: {:error, "IOC value is required and must be a non-empty string"}

  defp normalize_ioc(ioc_data) do
    normalized = %{
      type: normalize_key(ioc_data, "type"),
      value: normalize_key(ioc_data, "value") |> String.downcase(),
      description: normalize_key(ioc_data, "description"),
      source: normalize_key(ioc_data, "source"),
      source_ref: normalize_key(ioc_data, "source_ref"),
      severity: normalize_key(ioc_data, "severity") || "medium",
      confidence: parse_confidence(normalize_key(ioc_data, "confidence")),
      tags: normalize_key(ioc_data, "tags") || [],
      metadata: normalize_key(ioc_data, "metadata") || %{},
      malware_family: normalize_key(ioc_data, "malware_family"),
      threat_actor: normalize_key(ioc_data, "threat_actor"),
      campaign: normalize_key(ioc_data, "campaign"),
      mitre_tactics: normalize_key(ioc_data, "mitre_tactics") || [],
      mitre_techniques: normalize_key(ioc_data, "mitre_techniques") || []
    }

    {:ok, normalized}
  end

  defp normalize_key(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, String.to_atom(key))
  end

  defp parse_confidence(nil), do: nil
  defp parse_confidence(val) when is_float(val), do: val
  defp parse_confidence(val) when is_integer(val), do: val / 100.0
  defp parse_confidence(val) when is_binary(val) do
    case Float.parse(val) do
      {float, _} -> float
      :error -> nil
    end
  end
  defp parse_confidence(_), do: nil
end
