defmodule TamanduaServer.Telemetry.Enrichment.ThreatIntel do
  @moduledoc """
  Enriches telemetry events with threat intelligence data from IOC database.

  Extracts observables (IPs, domains, hashes, URLs) from event payloads and
  matches them against known IOCs from threat feeds.

  Enrichment is added to the event under the :enrichment.threat_intel key.
  """

  require Logger
  alias TamanduaServer.ThreatIntel
  alias TamanduaServer.Detection.IOCs

  @doc """
  Enrich an event with threat intelligence data.

  Extracts observables from the event payload, looks them up in the IOC database,
  and adds any matches to the enrichment map.

  ## Examples

      iex> enrich_event(%{event_type: "network_connect", payload: %{"remote_ip" => "192.168.1.1"}})
      %{event_type: "network_connect", enrichment: %{threat_intel: %{...}}}
  """
  @spec enrich_event(map()) :: map()
  def enrich_event(event) do
    iocs = extract_iocs_from_event(event)

    if Enum.empty?(iocs) do
      event
    else
      matches = lookup_iocs(iocs)

      if matches != %{} do
        enrichment = Map.get(event, :enrichment, %{})
        enrichment = Map.put(enrichment, :threat_intel, matches)
        Map.put(event, :enrichment, enrichment)
      else
        event
      end
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # IOC Extraction
  # ──────────────────────────────────────────────────────────────────

  defp extract_iocs_from_event(event) do
    payload = event[:payload] || event["payload"] || %{}
    event_type = event[:event_type] || event["event_type"]

    # Extract observables based on event type
    observables = case event_type do
      et when et in ["network_connect", "network_connection", "network", "network_anomaly", "network_listen",
                     :network_connect, :network_connection, :network, :network_anomaly, :network_listen] ->
        extract_network_observables(payload)

      et when et in ["process_create", "process_exec", :process_create, :process_exec] ->
        extract_process_observables(payload)

      et when et in ["file_create", "file_modify", "file_delete", :file_create, :file_modify, :file_delete] ->
        extract_file_observables(payload)

      et when et in ["dns_query", :dns_query] ->
        extract_dns_observables(payload)

      _ ->
        # Generic extraction for unknown event types
        extract_generic_observables(payload)
    end

    observables
    |> Enum.uniq()
    |> Enum.reject(fn {_type, value} -> is_nil(value) or value == "" end)
  end

  defp extract_network_observables(payload) do
    ips = [
      get_in(payload, ["remote_ip"]),
      get_in(payload, [:remote_ip]),
      get_in(payload, ["source_ip"]),
      get_in(payload, [:source_ip]),
      get_in(payload, ["dest_ip"]),
      get_in(payload, [:dest_ip])
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.reject(&is_private_ip?/1)
    |> Enum.map(&{:ip, &1})

    domains = [
      get_in(payload, ["domain"]),
      get_in(payload, [:domain]),
      get_in(payload, ["sni"]),
      get_in(payload, [:sni]),
      get_in(payload, ["tls_sni"]),
      get_in(payload, [:tls_sni]),
      get_in(payload, ["hostname"]),
      get_in(payload, [:hostname])
    ]
    |> Enum.concat(List.wrap(get_in(payload, ["domain_candidates"]) || get_in(payload, [:domain_candidates]) || []))
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&{:domain, &1})

    ips ++ domains
  end

  defp extract_process_observables(payload) do
    hashes = [
      {get_in(payload, ["md5"]), :hash_md5},
      {get_in(payload, [:md5]), :hash_md5},
      {get_in(payload, ["sha1"]), :hash_sha1},
      {get_in(payload, [:sha1]), :hash_sha1},
      {get_in(payload, ["sha256"]), :hash_sha256},
      {get_in(payload, [:sha256]), :hash_sha256}
    ]
    |> Enum.reject(fn {hash, _type} -> is_nil(hash) or hash == "" end)
    |> Enum.map(fn {hash, type} -> {type, hash} end)

    # Extract from image_path if present
    image_path = get_in(payload, ["image_path"]) || get_in(payload, [:image_path])
    filenames = if image_path, do: [{:filename, Path.basename(image_path)}], else: []

    hashes ++ filenames
  end

  defp extract_file_observables(payload) do
    hashes = [
      {get_in(payload, ["md5"]), :hash_md5},
      {get_in(payload, [:md5]), :hash_md5},
      {get_in(payload, ["sha1"]), :hash_sha1},
      {get_in(payload, [:sha1]), :hash_sha1},
      {get_in(payload, ["sha256"]), :hash_sha256},
      {get_in(payload, [:sha256]), :hash_sha256}
    ]
    |> Enum.reject(fn {hash, _type} -> is_nil(hash) or hash == "" end)
    |> Enum.map(fn {hash, type} -> {type, hash} end)

    path = get_in(payload, ["path"]) || get_in(payload, [:path])
    filenames = if path, do: [{:filename, Path.basename(path)}], else: []

    hashes ++ filenames
  end

  defp extract_dns_observables(payload) do
    query = get_in(payload, ["query"]) || get_in(payload, [:query])

    if query do
      [{:domain, query}]
    else
      []
    end
  end

  defp extract_generic_observables(payload) when is_map(payload) do
    payload
    |> Enum.flat_map(fn
      {_key, value} when is_binary(value) ->
        guess_observable_type(value)
      {_key, value} when is_map(value) ->
        extract_generic_observables(value)
      _ ->
        []
    end)
  end

  defp extract_generic_observables(_), do: []

  defp guess_observable_type(value) do
    cond do
      is_ip?(value) and not is_private_ip?(value) ->
        [{:ip, value}]

      is_domain?(value) ->
        [{:domain, value}]

      is_hash?(value) ->
        hash_type = case String.length(value) do
          32 -> :hash_md5
          40 -> :hash_sha1
          64 -> :hash_sha256
          _ -> nil
        end
        if hash_type, do: [{hash_type, value}], else: []

      true ->
        []
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # IOC Lookup
  # ──────────────────────────────────────────────────────────────────

  defp lookup_iocs(observables) do
    # Batch lookup from IOC database
    ioc_matches = observables
    |> Enum.map(fn {type, value} -> {to_string(type), value} end)
    |> IOCs.match_batch()
    |> Enum.map(&format_ioc_match/1)
    |> Enum.group_by(& &1.type)

    # Also check ThreatIntel ETS cache for additional feeds
    ti_matches = observables
    |> Enum.flat_map(fn {type, value} ->
      case ThreatIntel.lookup(type, value) do
        {:ok, ioc} -> [format_ti_match(ioc)]
        :not_found -> []
      end
    end)
    |> Enum.group_by(& &1.type)

    # Merge both sources
    Map.merge(ioc_matches, ti_matches, fn _k, v1, v2 -> v1 ++ v2 end)
  end

  defp format_ioc_match(ioc) do
    %{
      type: ioc.type,
      value: ioc.value,
      source: ioc.source || "unknown",
      severity: ioc.severity || "medium",
      confidence: ioc.confidence,
      description: ioc.description,
      tags: ioc.tags || [],
      malware_family: ioc.malware_family,
      threat_actor: ioc.threat_actor,
      first_seen: ioc.first_seen,
      last_seen: ioc.last_seen
    }
  end

  defp format_ti_match(ioc) do
    %{
      type: ioc.type,
      value: ioc.value,
      source: ioc.source || "unknown",
      severity: ioc.severity || "medium",
      confidence: ioc.confidence || 0.5,
      description: ioc.description,
      tags: ioc.tags || []
    }
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

  defp is_domain?(value) when is_binary(value) do
    # Basic domain validation
    String.match?(value, ~r/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)+$/)
  end

  defp is_domain?(_), do: false

  defp is_hash?(value) when is_binary(value) do
    # Check if value looks like a hash (hex string of appropriate length)
    String.match?(value, ~r/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/)
  end

  defp is_hash?(_), do: false
end
