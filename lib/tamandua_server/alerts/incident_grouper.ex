defmodule TamanduaServer.Alerts.IncidentGrouper do
  @moduledoc """
  First-pass alert to incident grouping.

  This assigns a stable `incident_key` into `alert.correlation_data` and mirrors
  it to `storyline_id`. The grouping is deliberately conservative: alerts only
  join an existing incident when they share organization, host/agent, and either
  the same executable/file hash or the same process lineage inside the temporal
  window.
  """

  import Ecto.Query

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  @default_window_seconds 3600
  @recent_limit 100

  @doc """
  Adds incident grouping metadata to alert attrs before insertion.
  """
  def assign_incident_metadata(attrs, opts \\ []) when is_map(attrs) do
    window_seconds = Keyword.get(opts, :window_seconds, window_seconds())
    components = components(attrs)

    incident_key =
      existing_incident_key(attrs, components, window_seconds) ||
        generate_incident_key(components, attrs, window_seconds)

    correlation_data =
      attrs
      |> get_map(:correlation_data)
      |> Map.put("incident_key", incident_key)
      |> Map.put("incident_window_seconds", window_seconds)
      |> Map.put("incident_components", public_components(components))
      |> Map.put("incident_grouped_at", DateTime.utc_now() |> DateTime.to_iso8601())

    attrs
    |> Map.put(:correlation_data, correlation_data)
    |> put_storyline_id(incident_key)
  end

  @doc """
  Generates a deterministic incident key from host plus hash or process lineage.
  """
  def generate_incident_key(components, attrs \\ %{}, window_seconds \\ window_seconds())
      when is_map(components) do
    basis =
      cond do
        present?(components.hash) -> "hash:#{components.hash}"
        present?(components.lineage) -> "lineage:#{components.lineage}"
        present?(components.process_name) -> "process:#{components.process_name}"
        true -> "alert:#{Map.get(attrs, :dedup_key) || Map.get(attrs, "dedup_key") || title(attrs)}"
      end

    bucket = timestamp_bucket(attrs, window_seconds)
    material = Enum.join([components.organization_id, components.host_key, basis, bucket], "|")

    "inc_" <> (:crypto.hash(:sha256, material) |> Base.encode16(case: :lower) |> binary_part(0, 32))
  end

  @doc """
  Extracts the grouping components used by the incident key.
  """
  def components(attrs) when is_map(attrs) do
    evidence = get_map(attrs, :evidence)
    raw_event = get_map(attrs, :raw_event)
    process = get_map(evidence, :process)

    %{
      organization_id: to_string(value(attrs, :organization_id) || ""),
      agent_id: to_string(value(attrs, :agent_id) || ""),
      host_key: host_key(attrs, evidence, raw_event),
      hash: extract_hash(attrs, evidence, raw_event),
      lineage: process_lineage(attrs, evidence, raw_event),
      process_name: normalize_string(value(process, :name) || value(raw_event, :process_name)),
      timestamp: alert_timestamp(attrs)
    }
  end

  defp existing_incident_key(attrs, components, window_seconds) do
    org_id = value(attrs, :organization_id)
    agent_id = value(attrs, :agent_id)

    if org_id && agent_id && (present?(components.hash) || present?(components.lineage)) do
      cutoff =
        DateTime.utc_now()
        |> DateTime.add(-window_seconds, :second)

      Alert
      |> where([a], a.organization_id == ^org_id)
      |> where([a], a.agent_id == ^agent_id)
      |> where([a], a.inserted_at >= ^cutoff)
      |> where([a], a.status not in ["resolved", "false_positive"])
      |> order_by([a], desc: a.inserted_at)
      |> limit(^@recent_limit)
      |> Repo.all()
      |> Enum.find_value(fn alert ->
        existing_components = components(alert_to_attrs(alert))

        if same_incident_components?(components, existing_components) do
          get_in(alert.correlation_data || %{}, ["incident_key"]) || alert.storyline_id
        end
      end)
    end
  rescue
    _ -> nil
  end

  defp same_incident_components?(left, right) do
    left.host_key == right.host_key and
      ((present?(left.hash) and left.hash == right.hash) or
         (present?(left.lineage) and left.lineage == right.lineage))
  end

  defp alert_to_attrs(%Alert{} = alert) do
    %{
      organization_id: alert.organization_id,
      agent_id: alert.agent_id,
      evidence: alert.evidence || %{},
      raw_event: alert.raw_event || %{},
      process_chain: alert.process_chain || [],
      correlation_data: alert.correlation_data || %{},
      inserted_at: alert.inserted_at,
      title: alert.title,
      dedup_key: alert.dedup_key
    }
  end

  defp public_components(components) do
    %{
      "agent_id" => components.agent_id,
      "host_key" => components.host_key,
      "hash" => components.hash,
      "lineage" => components.lineage,
      "process_name" => components.process_name
    }
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Map.new()
  end

  defp put_storyline_id(attrs, incident_key) do
    case value(attrs, :storyline_id) do
      value when is_binary(value) ->
        if String.trim(value) == "", do: Map.put(attrs, :storyline_id, incident_key), else: attrs

      nil ->
        Map.put(attrs, :storyline_id, incident_key)

      _ ->
        attrs
    end
  end

  defp process_lineage(attrs, evidence, raw_event) do
    chain = value(attrs, :process_chain) || []

    lineage =
      chain
      |> List.wrap()
      |> Enum.map(fn proc ->
        [
          normalize_string(value(proc, :name) || value(proc, :process_name)),
          normalize_string(value(proc, :path) || value(proc, :image_path)),
          normalize_string(value(proc, :pid)),
          normalize_string(value(proc, :ppid) || value(proc, :parent_pid))
        ]
        |> Enum.reject(&blank?/1)
        |> Enum.join("/")
      end)
      |> Enum.reject(&blank?/1)
      |> Enum.join(">")

    if lineage != "" do
      lineage
    else
      process = get_map(evidence, :process)

      [
        normalize_string(value(process, :parent_name) || value(raw_event, :parent_process_name)),
        normalize_string(value(process, :name) || value(raw_event, :process_name)),
        normalize_string(value(process, :pid) || value(raw_event, :pid)),
        normalize_string(value(process, :ppid) || value(raw_event, :ppid) || value(raw_event, :parent_pid))
      ]
      |> Enum.reject(&blank?/1)
      |> Enum.join(">")
    end
  end

  defp extract_hash(attrs, evidence, raw_event) do
    process = get_map(evidence, :process)
    file = get_map(evidence, :file)
    hashes = value(evidence, :file_hashes)

    [
      value(process, :sha256),
      value(process, :hash_sha256),
      value(file, :sha256),
      value(raw_event, :sha256),
      value(raw_event, :hash_sha256),
      value(attrs, :sha256),
      hash_value(hashes, :sha256)
    ]
    |> Enum.find_value(&normalize_hash/1)
  end

  defp hash_value(map, key) when is_map(map), do: value(map, key)

  defp hash_value(list, _key) when is_list(list) do
    Enum.find_value(list, fn
      item when is_map(item) -> value(item, :sha256)
      item -> item
    end)
  end

  defp hash_value(_, _), do: nil

  defp host_key(attrs, evidence, raw_event) do
    agent_id = value(attrs, :agent_id)

    [
      agent_id,
      value(attrs, :host_id),
      value(attrs, :hostname),
      value(evidence, :host_id),
      value(evidence, :hostname),
      value(raw_event, :host_id),
      value(raw_event, :hostname)
    ]
    |> Enum.find_value(&normalize_string/1)
    |> case do
      nil -> "unknown-host"
      "" -> "unknown-host"
      host -> host
    end
  end

  defp timestamp_bucket(attrs, window_seconds) do
    attrs
    |> alert_timestamp()
    |> DateTime.to_unix()
    |> div(window_seconds)
  end

  defp alert_timestamp(attrs) do
    timestamp =
      value(attrs, :timestamp) ||
        value(attrs, :inserted_at) ||
        value(attrs, :last_seen_at) ||
        DateTime.utc_now()

    normalize_datetime(timestamp)
  end

  defp normalize_datetime(%DateTime{} = dt), do: dt
  defp normalize_datetime(%NaiveDateTime{} = dt), do: DateTime.from_naive!(dt, "Etc/UTC")

  defp normalize_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp normalize_datetime(_), do: DateTime.utc_now()

  defp get_map(map, key) when is_map(map) do
    case value(map, key) do
      nested when is_map(nested) -> nested
      _ -> %{}
    end
  end

  defp get_map(_, _), do: %{}

  defp value(map, key) when is_map(map) and is_atom(key) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  defp value(_, _), do: nil

  defp normalize_hash(value) when is_binary(value) do
    normalized = value |> String.trim() |> String.downcase()

    if normalized != "" do
      normalized
    end
  end

  defp normalize_hash(_), do: nil

  defp normalize_string(value) when is_binary(value), do: value |> String.trim() |> String.downcase()
  defp normalize_string(value) when is_integer(value), do: Integer.to_string(value)
  defp normalize_string(value) when is_atom(value), do: value |> Atom.to_string() |> normalize_string()
  defp normalize_string(_), do: nil

  defp present?(value), do: is_binary(value) and String.trim(value) != ""
  defp blank?(value), do: !present?(value)

  defp title(attrs), do: to_string(value(attrs, :title) || "unknown")

  defp window_seconds do
    Application.get_env(:tamandua_server, :incident_grouping_window_seconds, @default_window_seconds)
  end
end
