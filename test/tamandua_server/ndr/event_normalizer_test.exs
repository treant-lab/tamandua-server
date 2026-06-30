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
  end
end
