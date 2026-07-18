defmodule TamanduaServer.Plugins.Manifest do
  @moduledoc """
  Data-only contract for plugin marketplace manifest metadata.

  This module validates and normalizes marketplace metadata. It does not load,
  execute, authorize, or otherwise enable plugin runtime behavior.
  """

  @allowed_plugin_types ~w(collector analyzer response)
  @allowed_api_versions ~w(v1)

  @allowed_required_capabilities ~w(
    alerts:read
    artifacts:read
    detections:read
    detections:write
    endpoint:read
    events:read
    files:read
    network:read
    response:propose
    telemetry:read
  )

  @checksum_sha256_pattern ~r/\A[0-9a-f]{64}\z/
  @semver_pattern ~r/\A(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z/
  @https_url_pattern ~r/\Ahttps:\/\/(?:\[[0-9A-Fa-f:.]+\]|[^\s\/@?#:]+)(?::[0-9]+)?(?:[\/?#][^\s]*)?\z/
  @https_url_fields ~w(homepage_url repository_url documentation_url wasm_url signature_url)a
  @required_fields ~w(plugin_type api_version checksum_sha256)a
  @manifest_fields [
    :plugin_type,
    :api_version,
    :version,
    :homepage_url,
    :repository_url,
    :documentation_url,
    :wasm_url,
    :signature_url,
    :public_key,
    :license,
    :checksum_sha256,
    :required_capabilities
  ]

  @type attrs :: %{optional(atom() | String.t()) => term()}
  @type normalized_attrs :: %{optional(atom() | String.t()) => term()}
  @type error :: {atom(), String.t()}

  @doc """
  Returns the allowed plugin types for manifest metadata.
  """
  @spec allowed_plugin_types() :: [String.t()]
  def allowed_plugin_types, do: @allowed_plugin_types

  @doc """
  Returns the allowed manifest API versions.
  """
  @spec allowed_api_versions() :: [String.t()]
  def allowed_api_versions, do: @allowed_api_versions

  @doc """
  Returns the allowed marketplace capability tokens.
  """
  @spec allowed_required_capabilities() :: [String.t()]
  def allowed_required_capabilities, do: @allowed_required_capabilities

  @doc """
  Normalizes supported manifest fields while preserving unrelated marketplace
  metadata fields.
  """
  @spec normalize_attrs(attrs()) :: normalized_attrs()
  def normalize_attrs(attrs) when is_map(attrs) do
    attrs
    |> normalize_string_field(:plugin_type, &String.downcase/1)
    |> normalize_string_field(:api_version, &String.downcase/1)
    |> normalize_string_field(:version, fn value -> value end)
    |> normalize_string_field(:homepage_url, fn value -> value end)
    |> normalize_string_field(:repository_url, fn value -> value end)
    |> normalize_string_field(:documentation_url, fn value -> value end)
    |> normalize_string_field(:wasm_url, fn value -> value end)
    |> normalize_string_field(:signature_url, fn value -> value end)
    |> normalize_string_field(:public_key, fn value -> value end)
    |> normalize_string_field(:license, fn value -> value end)
    |> normalize_string_field(:checksum_sha256, &String.downcase/1)
    |> normalize_required_capabilities()
  end

  @doc """
  Returns errors for supported manifest fields provided with both atom and
  string keys.
  """
  @spec field_alias_errors(attrs()) :: [error()]
  def field_alias_errors(attrs) when is_map(attrs) do
    @manifest_fields
    |> Enum.reduce([], fn field, errors ->
      if Map.has_key?(attrs, field) and Map.has_key?(attrs, Atom.to_string(field)) do
        [{field, "must not be provided with both atom and string keys"} | errors]
      else
        errors
      end
    end)
    |> Enum.reverse()
  end

  @doc """
  Validates normalized manifest metadata and returns field-level errors.
  """
  @spec validate_attrs(attrs()) :: :ok | {:error, [error()]}
  def validate_attrs(attrs) when is_map(attrs) do
    alias_errors = field_alias_errors(attrs)
    attrs = normalize_attrs(attrs)

    alias_errors
    |> validate_required(attrs)
    |> validate_allowed(:plugin_type, field_value(attrs, :plugin_type), @allowed_plugin_types)
    |> validate_allowed(:api_version, field_value(attrs, :api_version), @allowed_api_versions)
    |> validate_semver(field_value(attrs, :version))
    |> validate_https_urls(attrs)
    |> validate_public_key(field_value(attrs, :public_key))
    |> validate_non_empty_string(:license, field_value(attrs, :license))
    |> validate_checksum(field_value(attrs, :checksum_sha256))
    |> validate_capabilities(field_value(attrs, :required_capabilities))
    |> case do
      [] -> :ok
      errors -> {:error, Enum.reverse(errors)}
    end
  end

  defp validate_required(errors, attrs) do
    Enum.reduce(@required_fields, errors, fn field, errors ->
      case field_value(attrs, field) do
        nil -> [{field, "is required"} | errors]
        _value -> errors
      end
    end)
  end

  defp normalize_string_field(attrs, field, normalizer) do
    update_field(attrs, field, fn
      value when is_binary(value) ->
        value
        |> String.trim()
        |> normalizer.()

      value ->
        value
    end)
  end

  defp normalize_required_capabilities(attrs) do
    update_field(attrs, :required_capabilities, fn
      capabilities when is_list(capabilities) ->
        capabilities
        |> Enum.map(fn
          capability when is_binary(capability) -> String.trim(capability)
          capability -> capability
        end)
        |> Enum.reject(&(&1 == ""))
        |> Enum.uniq()

      capabilities ->
        capabilities
    end)
  end

  defp validate_allowed(errors, _field, nil, _allowed), do: errors

  defp validate_allowed(errors, field, value, allowed) when is_binary(value) do
    if value in allowed do
      errors
    else
      [{field, "is not an allowed #{field}"} | errors]
    end
  end

  defp validate_allowed(errors, field, _value, _allowed) do
    [{field, "must be a string"} | errors]
  end

  defp validate_checksum(errors, nil), do: errors

  defp validate_checksum(errors, checksum) when is_binary(checksum) do
    if Regex.match?(@checksum_sha256_pattern, checksum) do
      errors
    else
      [{:checksum_sha256, "must be a lowercase 64-character SHA-256 hex digest"} | errors]
    end
  end

  defp validate_checksum(errors, _checksum) do
    [{:checksum_sha256, "must be a string"} | errors]
  end

  defp validate_semver(errors, nil), do: errors

  defp validate_semver(errors, version) when is_binary(version) do
    if Regex.match?(@semver_pattern, version) do
      errors
    else
      [{:version, "must be a semantic version"} | errors]
    end
  end

  defp validate_semver(errors, _version) do
    [{:version, "must be a string"} | errors]
  end

  defp validate_https_urls(errors, attrs) do
    Enum.reduce(@https_url_fields, errors, fn field, errors ->
      validate_https_url(errors, field, field_value(attrs, field))
    end)
  end

  defp validate_https_url(errors, _field, nil), do: errors

  defp validate_https_url(errors, field, url) when is_binary(url) do
    uri = URI.parse(url)

    if Regex.match?(@https_url_pattern, url) and uri.scheme == "https" and is_binary(uri.host) and
         uri.host != "" and is_nil(uri.userinfo) do
      errors
    else
      [{field, "must be an HTTPS URL"} | errors]
    end
  end

  defp validate_https_url(errors, field, _url) do
    [{field, "must be a string"} | errors]
  end

  defp validate_public_key(errors, nil), do: errors

  defp validate_public_key(errors, public_key) when is_binary(public_key) do
    if String.trim(public_key) == "" do
      [{:public_key, "must be a non-empty string"} | errors]
    else
      errors
    end
  end

  defp validate_public_key(errors, _public_key) do
    [{:public_key, "must be a string"} | errors]
  end

  defp validate_non_empty_string(errors, _field, nil), do: errors

  defp validate_non_empty_string(errors, field, value) when is_binary(value) do
    if value == "" do
      [{field, "must be a non-empty string"} | errors]
    else
      errors
    end
  end

  defp validate_non_empty_string(errors, field, _value) do
    [{field, "must be a string"} | errors]
  end

  defp validate_capabilities(errors, nil), do: errors

  defp validate_capabilities(errors, capabilities) when is_list(capabilities) do
    unknown =
      capabilities
      |> Enum.reject(fn capability ->
        is_binary(capability) and capability in @allowed_required_capabilities
      end)
      |> Enum.map(&inspect_capability/1)

    case unknown do
      [] -> errors
      values -> [{:required_capabilities, "contains unknown capabilities: #{Enum.join(values, ", ")}"} | errors]
    end
  end

  defp validate_capabilities(errors, _capabilities) do
    [{:required_capabilities, "must be a list of strings"} | errors]
  end

  defp inspect_capability(capability) when is_binary(capability), do: capability
  defp inspect_capability(capability), do: inspect(capability)

  defp field_value(attrs, field) do
    Map.get(attrs, field) || Map.get(attrs, Atom.to_string(field))
  end

  defp update_field(attrs, field, fun) do
    string_field = Atom.to_string(field)

    cond do
      Map.has_key?(attrs, field) -> Map.update!(attrs, field, fun)
      Map.has_key?(attrs, string_field) -> Map.update!(attrs, string_field, fun)
      true -> attrs
    end
  end
end
