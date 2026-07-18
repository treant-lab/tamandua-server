defmodule TamanduaServer.NDR.EventNormalizer do
  @moduledoc """
  Normalizes network telemetry into the server-side NDR contract.
  """

  alias TamanduaServer.NDR.IP

  @network_event_types ~w(
    network
    network_accept
    network_anomaly
    network_close
    network_connect
    network_connection
    network_flow
    network_listen
  )

  @doc "Returns true when the event type should be processed by NDR analyzers."
  def network_event?(%{} = event) do
    event
    |> get_field(:event_type)
    |> network_event?()
  end

  def network_event?(type) when is_atom(type), do: type |> Atom.to_string() |> network_event?()
  def network_event?(type) when is_binary(type), do: String.downcase(type) in @network_event_types
  def network_event?(_), do: false

  @doc """
  Normalize supported network event payload keys without dropping original data.

  Accepted payload keys include:
  remote_ip, remote_port, protocol, pid, process_name, domain,
  domain_candidates, is_encrypted, visibility_level, visibility_gaps,
  domain_source, bytes_source, tls_metadata_source, process_attribution_source,
  sni, tls_sni, tls_version, ja3, ja3s, alpn, alpn_protocols, quic_version,
  http_version, encrypted_dns_transport, certificate and certificate_risk.
  """
  def normalize_event(%{} = event) do
    if network_event?(event) do
      payload = get_field(event, :payload) || %{}
      normalized_payload = normalize_payload(payload, event)

      event
      |> put_field(:payload, normalized_payload)
      |> put_field(:event_type, normalize_event_type(get_field(event, :event_type)))
    else
      event
    end
  end

  def normalize_event(event), do: event

  def normalize_payload(payload, event \\ %{})

  def normalize_payload(payload, event) when is_map(payload) do
    enrichment = get_field(payload, :enrichment) || %{}
    metadata = get_field(event, :metadata) || %{}

    remote_port =
      payload
      |> first_present([:remote_port, :destination_port, :dest_port, :dst_port])
      |> normalize_port()

    local_port =
      payload
      |> first_present([:local_port, :source_port, :src_port])
      |> normalize_port()
    tls_sni = get_field(payload, :tls_sni)
    domain = get_field(payload, :domain)
    sni = get_field(payload, :sni) || tls_sni || domain
    alpn_protocols =
      normalize_list(first_present(payload, [:alpn_protocols, :alpn_list, :application_protocols]))

    alpn = first_present(payload, [:alpn, :application_protocol]) || List.first(alpn_protocols)
    quic_version = first_present(payload, [:quic_version, :quic])
    http_version = first_present(payload, [:http_version, :http_protocol])
    encrypted_dns_transport = normalize_encrypted_dns_transport(payload, remote_port, alpn, alpn_protocols, sni)

    protocol =
      normalize_protocol(
        get_field(payload, :protocol),
        sni,
        get_field(payload, :tls_version),
        remote_port,
        quic_version,
        alpn,
        alpn_protocols
      )

    explicit_encryption = normalize_bool(get_field(payload, :is_encrypted))

    is_encrypted =
      cond do
        is_boolean(explicit_encryption) -> explicit_encryption
        encrypted_by_metadata?(
          payload,
          sni,
          remote_port,
          quic_version,
          alpn,
          alpn_protocols,
          encrypted_dns_transport
        ) -> true

        true -> nil
      end

    process_pid = get_field(payload, :pid) || get_field(payload, :process_pid)
    domain_candidates = normalize_domain_candidates(get_field(payload, :domain_candidates), domain, sni, tls_sni)
    bytes_sent = first_present(payload, [:bytes_sent, :bytes_out, :sent_bytes, :tx_bytes])
    bytes_received = first_present(payload, [:bytes_received, :bytes_recv, :bytes_in, :received_bytes, :rx_bytes])
    visibility_level = normalize_visibility_level(first_present_any([payload, enrichment, metadata], [:visibility_level, :network_visibility_level]))
    visibility_gaps =
      normalize_visibility_gaps(
        first_present_any([payload, enrichment, metadata], [:visibility_gaps, :network_visibility_gaps]),
        enrichment,
        metadata
      )
    domain_source = first_present_any([payload, enrichment, metadata], [:domain_source, :network_domain_source])
    bytes_source = first_present_any([payload, enrichment, metadata], [:bytes_source, :network_bytes_source])
    tls_metadata_source = first_present_any([payload, enrichment, metadata], [:tls_metadata_source, :network_tls_source])
    process_attribution_source = first_present_any([payload, enrichment, metadata], [:process_attribution_source, :network_process_source])

    remote_ip = first_present(payload, [:remote_ip, :destination_ip, :dest_ip, :dst_ip, :remote_address])
    local_ip = first_present(payload, [:local_ip, :source_ip, :src_ip, :local_address])

    payload
    |> put_field(
      :remote_ip,
      normalize_ip(remote_ip)
    )
    |> put_field(:remote_port, remote_port)
    |> put_field(
      :local_ip,
      normalize_ip(local_ip)
    )
    |> put_field(:local_port, local_port)
    |> put_field(:protocol, protocol)
    |> put_field(:bytes_sent, normalize_int(bytes_sent))
    |> put_field(:bytes_received, normalize_int(bytes_received))
    |> put_field(:pid, process_pid)
    |> put_field(:process_pid, process_pid)
    |> put_field(:process_name, get_field(payload, :process_name) || get_field(payload, :name))
    |> put_field(:domain, domain || sni)
    |> put_field(:domain_candidates, domain_candidates)
    |> put_if_present(:visibility_level, visibility_level)
    |> put_if_present(:visibility_gaps, visibility_gaps)
    |> put_if_present(:domain_source, normalize_source_label(domain_source))
    |> put_if_present(:bytes_source, normalize_source_label(bytes_source))
    |> put_if_present(:tls_metadata_source, normalize_source_label(tls_metadata_source))
    |> put_if_present(
      :process_attribution_source,
      normalize_source_label(process_attribution_source)
    )
    |> put_field(:sni, sni)
    |> put_field(:tls_sni, tls_sni || sni)
    |> put_if_present(:is_encrypted, is_encrypted)
    |> put_if_present(:tls_version, get_field(payload, :tls_version))
    |> put_if_present(:ja3, get_field(payload, :ja3))
    |> put_if_present(:ja3s, get_field(payload, :ja3s))
    |> put_if_present(:alpn, alpn)
    |> put_if_present(:alpn_protocols, alpn_protocols)
    |> put_if_present(:cipher_suite, first_present(payload, [:cipher_suite, :tls_cipher_suite, :cipher]))
    |> put_if_present(:tls_extensions, normalize_list(get_field(payload, :tls_extensions)))
    |> put_if_present(:ech_present, normalize_bool(first_present(payload, [:ech_present, :encrypted_client_hello])))
    |> put_if_present(:quic_version, quic_version)
    |> put_if_present(:is_quic, normalize_bool(get_field(payload, :is_quic)) || protocol == "QUIC")
    |> put_if_present(:http_version, http_version)
    |> put_if_present(:encrypted_dns_transport, encrypted_dns_transport)
    |> put_if_present(:dns_resolver, first_present(payload, [:dns_resolver, :resolver_ip, :resolver]))
    |> put_if_present(:certificate, get_field(payload, :certificate))
    |> put_if_present(:certificate_risk, normalize_float(get_field(payload, :certificate_risk)))
  end

  def normalize_payload(payload, _event), do: payload

  @doc "Builds the network context stored in NDR alert evidence."
  def network_context(event) do
    payload = event |> get_field(:payload) |> normalize_payload()
    enrichment = get_field(event, :enrichment) || %{}
    remote_ip = get_field(payload, :remote_ip)

    %{
      local_ip: get_field(payload, :local_ip),
      local_port: get_field(payload, :local_port),
      remote_ip: remote_ip,
      remote_port: get_field(payload, :remote_port),
      protocol: get_field(payload, :protocol),
      domain: get_field(payload, :domain),
      domain_candidates: get_field(payload, :domain_candidates),
      visibility_level: get_field(payload, :visibility_level),
      visibility_gaps: get_field(payload, :visibility_gaps),
      domain_source: get_field(payload, :domain_source),
      bytes_source: get_field(payload, :bytes_source),
      tls_metadata_source: get_field(payload, :tls_metadata_source),
      process_attribution_source: get_field(payload, :process_attribution_source),
      sni: get_field(payload, :sni),
      tls_sni: get_field(payload, :tls_sni),
      tls_version: get_field(payload, :tls_version),
      ja3: get_field(payload, :ja3),
      ja3s: get_field(payload, :ja3s),
      alpn: get_field(payload, :alpn),
      alpn_protocols: get_field(payload, :alpn_protocols),
      cipher_suite: get_field(payload, :cipher_suite),
      tls_extensions: get_field(payload, :tls_extensions),
      ech_present: get_field(payload, :ech_present),
      quic_version: get_field(payload, :quic_version),
      is_quic: get_field(payload, :is_quic),
      http_version: get_field(payload, :http_version),
      encrypted_dns_transport: get_field(payload, :encrypted_dns_transport),
      dns_resolver: get_field(payload, :dns_resolver),
      is_encrypted: get_field(payload, :is_encrypted),
      certificate_risk: get_field(payload, :certificate_risk),
      certificate_fingerprint: certificate_fingerprint(get_field(payload, :certificate)),
      bytes_sent: get_field(payload, :bytes_sent),
      bytes_received: get_field(payload, :bytes_received),
      threat_intel: get_in_any(enrichment, [:threat_intel]),
      geo: geo_for_ip(enrichment, remote_ip)
    }
    |> reject_empty_values()
  end

  @doc "Builds the process context stored in NDR alert evidence."
  def process_context(event_or_payload) do
    payload =
      case get_field(event_or_payload, :payload) do
        nil -> event_or_payload
        nested -> nested
      end

    %{
      pid: get_field(payload, :pid) || get_field(payload, :process_pid),
      process_pid: get_field(payload, :process_pid) || get_field(payload, :pid),
      process_name: get_field(payload, :process_name) || get_field(payload, :name),
      name: get_field(payload, :process_name) || get_field(payload, :name),
      path: get_field(payload, :process_path) || get_field(payload, :image_path) || get_field(payload, :path),
      image_path: get_field(payload, :image_path) || get_field(payload, :process_path),
      command_line: get_field(payload, :command_line) || get_field(payload, :cmdline),
      user: get_field(payload, :user) || get_field(payload, :username),
      username: get_field(payload, :username) || get_field(payload, :user)
    }
    |> reject_empty_values()
  end

  @doc "Builds NDR alert evidence with network_context and process fields."
  def alert_evidence(event, detection, metadata_key) do
    network_context = network_context(event)
    process_context = process_context(event)

    %{
      metadata_key => get_field(detection, :metadata) || %{},
      :network => [
        %{
          type: detection |> get_field(:type) |> to_string(),
          remote_ip: network_context[:remote_ip],
          remote_port: network_context[:remote_port],
          protocol: network_context[:protocol],
          domain: network_context[:domain],
          sni: network_context[:sni]
        }
        |> reject_empty_values()
      ],
      :network_context => network_context,
      :process => process_context,
      :detection => %{
        type: detection |> get_field(:type) |> to_string(),
        confidence: get_field(detection, :confidence),
        description: get_field(detection, :description)
      }
      |> reject_empty_values()
    }
    |> reject_empty_values()
  end

  def source_event_id(event), do: get_field(event, :event_id) || get_field(event, :id)

  def source_event_uuid(event) do
    case source_event_id(event) do
      value when is_binary(value) ->
        case Ecto.UUID.cast(value) do
          {:ok, uuid} -> uuid
          :error -> nil
        end

      _ ->
        nil
    end
  end

  def source_event_ids(event) do
    event
    |> source_event_uuid()
    |> List.wrap()
    |> Enum.reject(&is_nil/1)
  end

  def get_field(map, key) when is_map(map) and is_atom(key) do
    cond do
      Map.has_key?(map, key) -> Map.get(map, key)
      Map.has_key?(map, Atom.to_string(key)) -> Map.get(map, Atom.to_string(key))
      true -> nil
    end
  end

  def get_field(_, _), do: nil

  def certificate_fingerprint(cert) when is_map(cert) do
    get_field(cert, :fingerprint_sha256) ||
      get_field(cert, :sha256) ||
      get_field(cert, :fingerprint) ||
      get_field(cert, :serial_number)
  end

  def certificate_fingerprint(_), do: nil

  defp normalize_event_type(type) when is_atom(type), do: Atom.to_string(type)
  defp normalize_event_type(type), do: type

  defp put_field(map, key, value) do
    map
    |> Map.put(key, value)
    |> maybe_put_string_key(key, value)
  end

  defp put_if_present(map, _key, nil), do: map
  defp put_if_present(map, _key, ""), do: map
  defp put_if_present(map, key, value), do: put_field(map, key, value)

  defp maybe_put_string_key(map, key, value) when is_atom(key), do: Map.put(map, Atom.to_string(key), value)
  defp maybe_put_string_key(map, _key, _value), do: map

  defp normalize_port(port) when is_integer(port), do: port
  defp normalize_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {value, _} -> value
      :error -> nil
    end
  end
  defp normalize_port(_), do: nil

  defp normalize_ip(nil), do: nil
  defp normalize_ip(value) when is_binary(value), do: IP.canonical(value)
  defp normalize_ip(value), do: value

  defp normalize_int(nil), do: 0
  defp normalize_int(value) when is_integer(value), do: value
  defp normalize_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} -> parsed
      :error -> 0
    end
  end
  defp normalize_int(value) when is_float(value), do: trunc(value)
  defp normalize_int(_), do: 0

  defp first_present(map, keys) do
    Enum.find_value(keys, fn key ->
      case get_field(map, key) do
        nil -> nil
        "" -> nil
        value -> value
      end
    end)
  end

  defp first_present_any(maps, keys) do
    maps
    |> Enum.reject(&is_nil/1)
    |> Enum.find_value(&first_present(&1, keys))
  end

  defp normalize_protocol(nil, _sni, _tls_version, _port, quic_version, _alpn, _alpn_protocols)
       when not is_nil(quic_version),
       do: "QUIC"

  defp normalize_protocol(nil, _sni, tls_version, port, _quic_version, _alpn, _alpn_protocols)
       when not is_nil(tls_version) or port in [443, 853, 8443, 9443],
       do: "TLS"

  defp normalize_protocol(nil, sni, _tls_version, _port, _quic_version, _alpn, _alpn_protocols)
       when not is_nil(sni),
       do: "TLS"

  # Final nil-protocol clause: classifies by ALPN and falls back to "TCP",
  # so no additional nil catch-all is needed after it.
  defp normalize_protocol(nil, _sni, _tls_version, _port, _quic_version, alpn, alpn_protocols) do
    cond do
      alpn_match?(alpn, alpn_protocols, ["h3", "h3-29", "h3-32"]) -> "QUIC"
      alpn_match?(alpn, alpn_protocols, ["h2", "http/1.1", "dot", "doh", "doq", "doq-i02", "doq-i03"]) ->
        "TLS"

      true -> "TCP"
    end
  end

  defp normalize_protocol(protocol, _sni, _tls_version, _port, _quic_version, _alpn, _alpn_protocols),
    do: protocol |> to_string() |> String.upcase()

  defp encrypted_by_metadata?(
         payload,
         sni,
         remote_port,
         quic_version,
         alpn,
         alpn_protocols,
         encrypted_dns_transport
       ) do
    not is_nil(sni) or
      not is_nil(get_field(payload, :tls_version)) or
      not is_nil(get_field(payload, :ja3)) or
      not is_nil(get_field(payload, :ja3s)) or
      not is_nil(get_field(payload, :certificate)) or
      not is_nil(quic_version) or
      not is_nil(alpn) or
      alpn_protocols != [] or
      not is_nil(encrypted_dns_transport) or
      remote_port in [443, 853, 784, 8853, 8443, 9443]
  end

  defp normalize_bool(value) when value in [true, false], do: value
  defp normalize_bool(value) when is_binary(value), do: String.downcase(value) in ["true", "1", "yes"]
  defp normalize_bool(_), do: nil

  defp normalize_float(nil), do: nil
  defp normalize_float(value) when is_float(value), do: value
  defp normalize_float(value) when is_integer(value), do: value / 1
  defp normalize_float(value) when is_binary(value) do
    case Float.parse(value) do
      {float, _} -> float
      :error -> nil
    end
  end
  defp normalize_float(_), do: nil

  defp normalize_list(nil), do: []

  defp normalize_list(value) when is_list(value),
    do: value |> Enum.reject(&is_nil/1) |> Enum.map(&to_string/1) |> Enum.reject(&(&1 == ""))

  defp normalize_list(value) when is_binary(value) do
    value
    |> String.split([",", " "], trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end
  defp normalize_list(value), do: [to_string(value)]

  defp normalize_visibility_level(nil), do: nil
  defp normalize_visibility_level(value) do
    value
    |> to_string()
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_source_label(nil), do: nil
  defp normalize_source_label(value) do
    value
    |> to_string()
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_visibility_gaps(value, enrichment, metadata) do
    explicit = normalize_list(value)
    derived = derived_visibility_gaps(enrichment, metadata)

    (explicit ++ derived)
    |> Enum.map(&normalize_source_label/1)
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.uniq()
  end

  defp derived_visibility_gaps(enrichment, metadata) do
    [
      degraded_gap?(metadata, :network_bytes_degraded, "bytes_not_available"),
      degraded_gap?(metadata, :network_tls_degraded, "tls_metadata_not_available"),
      degraded_gap?(metadata, :network_sni_degraded, "sni_not_available"),
      visibility_gap?(enrichment, [:visibility, :bytes, :degraded], "bytes_not_available"),
      visibility_gap?(enrichment, [:visibility, :tls, :degraded], "tls_metadata_not_available"),
      visibility_gap?(enrichment, [:visibility, :sni, :degraded], "sni_not_available")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp degraded_gap?(metadata, key, gap) do
    if normalize_bool(get_field(metadata, key)) == true, do: gap
  end

  defp visibility_gap?(map, path, gap) do
    if normalize_bool(get_path(map, path)) == true, do: gap
  end

  defp normalize_encrypted_dns_transport(payload, remote_port, alpn, alpn_protocols, sni) do
    explicit = first_present(payload, [:encrypted_dns_transport, :dns_transport])

    cond do
      explicit in [:doh, "doh", "DoH", "DOH"] -> "doh"
      explicit in [:dot, "dot", "DoT", "DOT"] -> "dot"
      explicit in [:doq, "doq", "DoQ", "DOQ"] -> "doq"
      remote_port == 853 -> "dot"
      remote_port in [784, 8853] -> "doq"
      alpn_match?(alpn, alpn_protocols, ["doq", "doq-i02", "doq-i03"]) -> "doq"
      alpn_match?(alpn, alpn_protocols, ["dot"]) -> "dot"
      resolver_sni?(sni) and remote_port in [443, 8443] -> "doh"
      true -> nil
    end
  end

  defp alpn_match?(alpn, alpn_protocols, expected) do
    values =
      [alpn | alpn_protocols]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&(String.downcase(to_string(&1))))

    Enum.any?(values, &(&1 in expected))
  end

  defp resolver_sni?(nil), do: false
  defp resolver_sni?(sni) do
    normalized = sni |> to_string() |> String.downcase()
    String.contains?(normalized, "dns.google") or
      String.contains?(normalized, "cloudflare-dns.com") or
      String.contains?(normalized, "dns.quad9.net") or
      String.contains?(normalized, "dns.nextdns.io")
  end

  defp normalize_domain_candidates(candidates, domain, sni, tls_sni) do
    candidates
    |> List.wrap()
    |> Enum.concat([domain, sni, tls_sni])
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp get_in_any(map, [key]) when is_map(map) do
    get_field(map, key)
  end

  defp get_path(map, keys) when is_map(map) and is_list(keys) do
    Enum.reduce_while(keys, map, fn key, acc ->
      case get_field(acc, key) do
        nil -> {:halt, nil}
        value -> {:cont, value}
      end
    end)
  end

  defp get_path(_, _), do: nil

  defp geo_for_ip(_enrichment, nil), do: nil
  defp geo_for_ip(enrichment, ip) do
    geo = get_in_any(enrichment, [:geo]) || %{}
    Map.get(geo, ip) || Map.get(geo, to_string(ip))
  end

  defp reject_empty_values(map) do
    map
    |> Enum.reject(fn
      {_key, nil} -> true
      {_key, ""} -> true
      {_key, []} -> true
      {_key, value} when is_map(value) -> map_size(value) == 0
      _ -> false
    end)
    |> Map.new()
  end
end
