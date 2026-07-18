defmodule TamanduaServer.NDR.EventNormalizerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.NDR.EventNormalizer

  describe "normalize_event/1 encrypted metadata" do
    test "preserves ALPN, JA3, TLS, ECH, and DNS resolver metadata" do
      event =
        EventNormalizer.normalize_event(%{
          event_type: "network_connect",
          payload: %{
            remote_ip: "8.8.8.8",
            remote_port: 443,
            process_name: "browser",
            sni: "dns.google",
            tls_version: "TLSv1.3",
            ja3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ja3s: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            alpn_protocols: "h2,http/1.1",
            cipher: "TLS_AES_128_GCM_SHA256",
            encrypted_client_hello: "true",
            resolver_ip: "8.8.8.8"
          }
        })

      payload = event.payload

      assert payload.protocol == "TLS"
      assert payload.is_encrypted == true
      assert payload.alpn == "h2"
      assert payload.alpn_protocols == ["h2", "http/1.1"]
      assert payload.cipher_suite == "TLS_AES_128_GCM_SHA256"
      assert payload.ech_present == true
      assert payload.encrypted_dns_transport == "doh"
      assert payload.dns_resolver == "8.8.8.8"
      assert payload.ja3 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      assert payload.ja3s == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    end

    test "infers DoT from port 853" do
      event =
        EventNormalizer.normalize_event(%{
          event_type: :network_connection,
          payload: %{
            remote_ip: "1.1.1.1",
            remote_port: "853",
            process_name: "resolver"
          }
        })

      assert event.payload.protocol == "TLS"
      assert event.payload.is_encrypted == true
      assert event.payload.encrypted_dns_transport == "dot"
    end

    test "infers QUIC and DoQ metadata without claiming decrypted payload visibility" do
      event =
        EventNormalizer.normalize_event(%{
          event_type: "network",
          payload: %{
            remote_ip: "9.9.9.9",
            remote_port: 8853,
            protocol: nil,
            quic_version: "1",
            alpn: "doq"
          }
        })

      assert event.payload.protocol == "QUIC"
      assert event.payload.is_quic == true
      assert event.payload.is_encrypted == true
      assert event.payload.quic_version == "1"
      assert event.payload.encrypted_dns_transport == "doq"
    end
  end

  describe "network_context/1" do
    test "normalizes visibility and source attribution fields when present" do
      event =
        EventNormalizer.normalize_event(%{
          event_type: "network_connect",
          payload: %{
            remote_ip: "203.0.113.10",
            visibility_level: "Degraded",
            visibility_gaps: ["dns_rows", :packet_dpi],
            domain_source: "TLS_SNI",
            bytes_source: "FLOW_COUNTERS",
            tls_metadata_source: "ClientHello",
            process_attribution_source: "Endpoint_PID"
          }
        })

      assert event.payload.visibility_level == "degraded"
      assert event.payload.visibility_gaps == ["dns_rows", "packet_dpi"]
      assert event.payload.domain_source == "tls_sni"
      assert event.payload.bytes_source == "flow_counters"
      assert event.payload.tls_metadata_source == "clienthello"
      assert event.payload.process_attribution_source == "endpoint_pid"
    end

    test "promotes socket-table enrichment and event metadata into visibility fields" do
      event =
        EventNormalizer.normalize_event(%{
          event_type: "network_connect",
          metadata: %{
            "network_domain_source" => "recent_dns_cache",
            "network_bytes_source" => "not_available_socket_table",
            "network_tls_source" => "not_available_socket_table"
          },
          payload: %{
            remote_ip: "203.0.113.77",
            domain_candidates: ["endpoint-enrichment.example"],
            enrichment: %{
              visibility: %{
                bytes: %{degraded: true},
                tls: %{degraded: true},
                sni: %{degraded: true}
              }
            }
          }
        })

      assert event.payload.domain_source == "recent_dns_cache"
      assert event.payload.bytes_source == "not_available_socket_table"
      assert event.payload.tls_metadata_source == "not_available_socket_table"
      assert "bytes_not_available" in event.payload.visibility_gaps
      assert "tls_metadata_not_available" in event.payload.visibility_gaps
      assert "sni_not_available" in event.payload.visibility_gaps
    end

    test "includes encrypted traffic fields used by alert evidence" do
      context =
        EventNormalizer.network_context(%{
          payload: %{
            remote_ip: "203.0.113.10",
            remote_port: 443,
            sni: "example.com",
            alpn: "h3",
            quic_version: "1",
            encrypted_dns_transport: "doh"
          }
        })

      assert context.alpn == "h3"
      assert context.quic_version == "1"
      assert context.encrypted_dns_transport == "doh"
      assert context.is_quic == true
    end

    test "includes visibility and source attribution fields used by alert evidence" do
      context =
        EventNormalizer.network_context(%{
          payload: %{
            remote_ip: "203.0.113.10",
            visibility_level: "live_only",
            visibility_gaps: ["no_persisted_flow_rows"],
            domain_source: "tls_sni",
            bytes_source: "flow_counters",
            tls_metadata_source: "clienthello",
            process_attribution_source: "endpoint_pid"
          }
        })

      assert context.visibility_level == "live_only"
      assert context.visibility_gaps == ["no_persisted_flow_rows"]
      assert context.domain_source == "tls_sni"
      assert context.bytes_source == "flow_counters"
      assert context.tls_metadata_source == "clienthello"
      assert context.process_attribution_source == "endpoint_pid"
    end
  end
end
