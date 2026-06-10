defmodule TamanduaServer.Connectors.Helpers.Transform do
  @moduledoc """
  Event transformation utilities for connectors.

  Provides common transformations for normalizing data between
  Tamandua and external systems.
  """

  @doc """
  Transform Tamandua alert to generic format.

  ## Example output:
      %{
        id: "alert-123",
        title: "Malware detected",
        severity: "high",
        timestamp: ~U[2024-01-20 10:00:00Z],
        metadata: %{...}
      }
  """
  def alert_to_generic(%{} = alert) do
    %{
      id: Map.get(alert, :id) || Map.get(alert, "id"),
      title: Map.get(alert, :title) || Map.get(alert, "title"),
      description: Map.get(alert, :description) || Map.get(alert, "description"),
      severity: normalize_severity(Map.get(alert, :severity) || Map.get(alert, "severity")),
      status: Map.get(alert, :status) || Map.get(alert, "status"),
      timestamp: Map.get(alert, :inserted_at) || Map.get(alert, "inserted_at") || DateTime.utc_now(),
      agent_id: Map.get(alert, :agent_id) || Map.get(alert, "agent_id"),
      mitre_tactics: Map.get(alert, :mitre_tactics) || Map.get(alert, "mitre_tactics") || [],
      mitre_techniques: Map.get(alert, :mitre_techniques) || Map.get(alert, "mitre_techniques") || [],
      metadata: extract_metadata(alert)
    }
  end

  @doc """
  Transform IOC to generic format.
  """
  def ioc_to_generic(%{} = ioc) do
    %{
      id: Map.get(ioc, :id) || Map.get(ioc, "id"),
      type: normalize_ioc_type(Map.get(ioc, :type) || Map.get(ioc, "type")),
      value: Map.get(ioc, :value) || Map.get(ioc, "value"),
      description: Map.get(ioc, :description) || Map.get(ioc, "description"),
      severity: normalize_severity(Map.get(ioc, :severity) || Map.get(ioc, "severity")),
      source: Map.get(ioc, :source) || Map.get(ioc, "source"),
      tags: Map.get(ioc, :tags) || Map.get(ioc, "tags") || [],
      first_seen: Map.get(ioc, :first_seen) || Map.get(ioc, "first_seen"),
      last_seen: Map.get(ioc, :last_seen) || Map.get(ioc, "last_seen")
    }
  end

  @doc """
  Normalize severity to standard levels: low, medium, high, critical.
  """
  def normalize_severity(severity) when is_atom(severity) do
    severity |> Atom.to_string() |> normalize_severity()
  end

  def normalize_severity(severity) when is_binary(severity) do
    case String.downcase(severity) do
      s when s in ["critical", "crit", "5"] -> "critical"
      s when s in ["high", "4"] -> "high"
      s when s in ["medium", "med", "moderate", "3"] -> "medium"
      s when s in ["low", "2"] -> "low"
      s when s in ["info", "informational", "1"] -> "info"
      _ -> "medium"
    end
  end

  def normalize_severity(_), do: "medium"

  @doc """
  Normalize IOC type to standard naming.
  """
  def normalize_ioc_type(type) when is_atom(type) do
    type |> Atom.to_string() |> normalize_ioc_type()
  end

  def normalize_ioc_type(type) when is_binary(type) do
    case String.downcase(type) do
      "ip" -> "ip"
      "ipv4" -> "ip"
      "ipv6" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "url" -> "url"
      "md5" -> "hash_md5"
      "sha1" -> "hash_sha1"
      "sha256" -> "hash_sha256"
      "hash-md5" -> "hash_md5"
      "hash-sha1" -> "hash_sha1"
      "hash-sha256" -> "hash_sha256"
      "filehash-md5" -> "hash_md5"
      "filehash-sha1" -> "hash_sha1"
      "filehash-sha256" -> "hash_sha256"
      "email" -> "email"
      "filename" -> "filename"
      other -> other
    end
  end

  @doc """
  Extract metadata fields from alert/IOC.
  """
  def extract_metadata(data) do
    excluded_keys = [:id, :title, :description, :severity, :status, :timestamp,
                     :agent_id, :type, :value, :source, :tags, :first_seen, :last_seen,
                     :inserted_at, :updated_at, :__struct__, :__meta__]

    data
    |> Map.drop(excluded_keys)
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Enum.into(%{})
  end

  @doc """
  Deep merge two maps, with right map taking precedence.
  """
  def deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, fn _key, left_val, right_val ->
      if is_map(left_val) and is_map(right_val) do
        deep_merge(left_val, right_val)
      else
        right_val
      end
    end)
  end

  def deep_merge(_, right), do: right

  @doc """
  Convert string keys to atoms (safely).
  """
  def atomize_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} ->
      key = if is_binary(k), do: String.to_existing_atom(k), else: k
      value = if is_map(v), do: atomize_keys(v), else: v
      {key, value}
    end)
  rescue
    ArgumentError -> map
  end

  @doc """
  Convert atom keys to strings.
  """
  def stringify_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} ->
      key = if is_atom(k), do: Atom.to_string(k), else: k
      value = if is_map(v), do: stringify_keys(v), else: v
      {key, value}
    end)
  end
end
