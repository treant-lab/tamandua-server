defmodule TamanduaServer.Telemetry.EventContract do
  @moduledoc """
  Versioned canonical telemetry contract used by ingestion, correlation and UI.

  This module is observational. It normalizes what was received and explains
  whether enough fields exist for reliable detections/correlation; it does not
  create alerts or change severity.
  """

  alias TamanduaServer.Telemetry.CorrelationEvidence

  @schema_version "telemetry-contract/v1"

  @categories ~w(process file network dns registry driver auth module script ai_usage unknown)

  @required_fields %{
    "process" => ["process.pid", "process.name", "process.path", "process.ppid", "process.user"],
    "file" => ["file.path", "process.pid", "process.name"],
    "network" => [
      "network.remote_ip",
      "network.remote_port",
      "network.protocol",
      "process.pid",
      "process.name"
    ],
    "dns" => ["dns.domain", "process.pid", "process.name"],
    "registry" => ["process.pid", "process.name"],
    "driver" => ["process.pid", "process.name", "file.path"],
    "auth" => ["process.user"],
    "module" => ["process.pid", "process.name", "file.path"],
    "script" => ["process.pid", "process.name", "file.path"],
    "ai_usage" => ["dns.domain", "network.remote_ip", "process.pid", "process.name"],
    "unknown" => []
  }

  @doc """
  Returns a compact contract summary for an event-like map/struct.
  """
  def summarize(event) do
    category = category(event_type(event))
    quality = CorrelationEvidence.telemetry_quality(event)
    entities = CorrelationEvidence.extract_entities(event)

    %{
      "schema_version" => @schema_version,
      "category" => category,
      "required_fields" => Map.fetch!(@required_fields, category),
      "quality" => quality,
      "entity_counts" => entity_counts(entities),
      "correlation_ready" => correlation_ready?(category, quality, entities)
    }
  end

  @doc """
  Stable high-level telemetry category for an event type.
  """
  def category(event_type) do
    normalized =
      event_type
      |> to_string()
      |> String.downcase()

    cond do
      normalized in ["inference_request", "inference_response", "ai_usage"] ->
        "ai_usage"

      String.contains?(normalized, "dns") ->
        "dns"

      String.contains?(normalized, "registry") or String.starts_with?(normalized, "reg_") ->
        "registry"

      String.contains?(normalized, "driver") or String.contains?(normalized, "etw") ->
        "driver"

      String.contains?(normalized, "auth") or String.contains?(normalized, "login") ->
        "auth"

      String.contains?(normalized, "module") or String.contains?(normalized, "dll") ->
        "module"

      String.contains?(normalized, "script") or String.contains?(normalized, "powershell") ->
        "script"

      String.contains?(normalized, "network") or String.contains?(normalized, "connect") or
        String.contains?(normalized, "socket") or String.contains?(normalized, "flow") or
        String.contains?(normalized, "http") or String.contains?(normalized, "tcp") or
          String.contains?(normalized, "udp") ->
        "network"

      String.contains?(normalized, "file") or String.contains?(normalized, "fim") or
        String.contains?(normalized, "write") or String.contains?(normalized, "rename") or
          String.contains?(normalized, "delete") ->
        "file"

      String.contains?(normalized, "process") or String.contains?(normalized, "proc") or
        String.contains?(normalized, "exec") or String.contains?(normalized, "spawn") ->
        "process"

      true ->
        "unknown"
    end
  end

  def categories, do: @categories

  def required_fields(category) when is_binary(category),
    do: Map.get(@required_fields, category, [])

  defp event_type(%{event_type: event_type}), do: event_type
  defp event_type(%{"event_type" => event_type}), do: event_type
  defp event_type(_), do: "unknown"

  defp entity_counts(entities) do
    Map.new(entities, fn {key, value} ->
      count =
        case value do
          map when is_map(map) -> map_size(map)
          list when is_list(list) -> length(list)
          nil -> 0
          _ -> 1
        end

      {to_string(key), count}
    end)
  end

  defp correlation_ready?("unknown", _quality, _entities), do: false

  defp correlation_ready?(_category, %{score: score}, entities) when score >= 40 do
    has_process_identity?(entities) or has_network_identity?(entities) or
      has_file_identity?(entities)
  end

  defp correlation_ready?(_, _, _), do: false

  defp has_process_identity?(entities) do
    present?(get_in(entities, [:process, :process_guid])) or
      (present?(get_in(entities, [:process, :pid])) and
         present?(get_in(entities, [:process, :name])))
  end

  defp has_network_identity?(entities) do
    present?(get_in(entities, [:network, :remote_ip])) and
      present?(get_in(entities, [:network, :remote_port]))
  end

  defp has_file_identity?(entities) do
    present?(get_in(entities, [:file, :sha256])) or present?(get_in(entities, [:file, :path]))
  end

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(nil), do: false
  defp present?(_), do: true
end
