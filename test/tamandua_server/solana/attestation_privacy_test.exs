defmodule TamanduaServer.Solana.AttestationPrivacyTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Solana.Attestation
  alias TamanduaServer.Alerts.Alert

  @moduledoc """
  Tests for privacy-safe IOC extraction in attestation manifests.

  Verifies that PRIVACY-01 and PRIVACY-02 requirements are met:
  - No PII (hostname, username, internal IP, local paths) in manifests
  - Only safe IOCs (hashes, public domains/IPs/URLs, MITRE, rule hash) included
  """

  describe "build_public_manifest/1 - privacy stripping" do
    test "removes hostname from indicators" do
      alert = build_alert_with_iocs([
        %{type: "hostname", value: "victim-pc.local"},
        %{type: "hash_sha256", value: "abc123"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 1
      assert Enum.any?(manifest.iocs, &(&1.type == "hash_sha256"))
      refute Enum.any?(manifest.iocs, &(&1.type == "hostname"))
    end

    test "removes username from indicators" do
      alert = build_alert_with_iocs([
        %{type: "username", value: "john.doe"},
        %{type: "user", value: "admin"},
        %{type: "domain", value: "evil.com"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 2
      assert Enum.any?(manifest.iocs, &(&1.type == "domain"))
      refute Enum.any?(manifest.iocs, &(&1.type == "username"))
      refute Enum.any?(manifest.iocs, &(&1.type == "user"))
    end

    test "removes internal IPs (10.x.x.x)" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "10.0.0.1"},
        %{type: "ip", value: "8.8.8.8"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 1
      ioc = Enum.find(manifest.iocs, &(&1.type == "ip"))
      assert ioc.value == "8.8.8.8"
    end

    test "removes internal IPs (192.168.x.x)" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "192.168.1.1"},
        %{type: "ip", value: "1.1.1.1"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 1
      ioc = Enum.find(manifest.iocs, &(&1.type == "ip"))
      assert ioc.value == "1.1.1.1"
    end

    test "removes internal IPs (172.16-31.x.x)" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "172.16.0.1"},
        %{type: "ip", value: "172.31.255.255"},
        %{type: "ip", value: "172.15.0.1"},  # Not in range, should be public
        %{type: "ip", value: "172.32.0.1"}   # Not in range, should be public
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 2
      assert manifest.redacted_ioc_count == 2
      values = Enum.map(manifest.iocs, & &1.value)
      assert "172.15.0.1" in values
      assert "172.32.0.1" in values
      refute "172.16.0.1" in values
      refute "172.31.255.255" in values
    end

    test "removes localhost and link-local IPs" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "127.0.0.1"},
        %{type: "ip", value: "169.254.1.1"},
        %{type: "ip", value: "0.0.0.0"},
        %{type: "ip", value: "255.255.255.255"},
        %{type: "ip", value: "4.4.4.4"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 4
      ioc = Enum.find(manifest.iocs, &(&1.type == "ip"))
      assert ioc.value == "4.4.4.4"
    end

    test "removes .local domains" do
      alert = build_alert_with_iocs([
        %{type: "domain", value: "server.local"},
        %{type: "domain", value: "evil.com"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 1
      ioc = Enum.find(manifest.iocs, &(&1.type == "domain"))
      assert ioc.value == "evil.com"
    end

    test "removes .lan, .internal, .corp domains" do
      alert = build_alert_with_iocs([
        %{type: "domain", value: "server.lan"},
        %{type: "domain", value: "intranet.internal"},
        %{type: "domain", value: "vpn.corp"},
        %{type: "domain", value: "malware.com"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 3
      ioc = Enum.find(manifest.iocs, &(&1.type == "domain"))
      assert ioc.value == "malware.com"
    end

    test "removes file paths" do
      alert = build_alert_with_iocs([
        %{type: "path", value: "/home/user/malware.exe"},
        %{type: "file_path", value: "C:\\Users\\victim\\payload.dll"},
        %{type: "process_path", value: "/usr/bin/suspicious"},
        %{type: "image_path", value: "C:\\Windows\\System32\\evil.exe"},
        %{type: "hash_md5", value: "d41d8cd98f00b204e9800998ecf8427e"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 4
      assert Enum.any?(manifest.iocs, &(&1.type == "hash_md5"))
      refute Enum.any?(manifest.iocs, &(&1.type in ["path", "file_path", "process_path", "image_path"]))
    end

    test "removes command lines" do
      alert = build_alert_with_iocs([
        %{type: "command_line", value: "powershell -enc SGVsbG8gV29ybGQ="},
        %{type: "cmdline", value: "cmd.exe /c whoami"},
        %{type: "url", value: "https://evil.com/payload"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 2
      assert Enum.any?(manifest.iocs, &(&1.type == "url"))
      refute Enum.any?(manifest.iocs, &(&1.type in ["command_line", "cmdline"]))
    end

    test "includes safe hash IOCs (SHA256, SHA1, MD5)" do
      alert = build_alert_with_iocs([
        %{type: "sha256", value: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
        %{type: "sha1", value: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"},
        %{type: "md5", value: "D41D8CD98F00B204E9800998ECF8427E"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 3
      assert manifest.redacted_ioc_count == 0

      types = Enum.map(manifest.iocs, & &1.type) |> Enum.sort()
      assert types == ["hash_md5", "hash_sha1", "hash_sha256"]

      # Verify hashes are normalized to lowercase
      assert Enum.all?(manifest.iocs, fn ioc ->
        ioc.value == String.downcase(ioc.value)
      end)
    end

    test "includes public domain IOCs" do
      alert = build_alert_with_iocs([
        %{type: "domain", value: "malware.com"},
        %{type: "dns_query", value: "c2.evil.net"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 2
      assert manifest.redacted_ioc_count == 0
      values = Enum.map(manifest.iocs, & &1.value) |> Enum.sort()
      assert values == ["c2.evil.net", "malware.com"]
    end

    test "includes public URL IOCs" do
      alert = build_alert_with_iocs([
        %{type: "url", value: "https://evil.com/payload.exe"},
        %{type: "url", value: "http://192.168.1.1/internal"}  # Internal IP URL
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 1
      ioc = Enum.find(manifest.iocs, &(&1.type == "url"))
      assert ioc.value == "https://evil.com/payload.exe"
    end

    test "includes public IP IOCs" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "1.2.3.4"},
        %{type: "ip", value: "8.8.8.8"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 2
      assert manifest.redacted_ioc_count == 0
      values = Enum.map(manifest.iocs, & &1.value) |> Enum.sort()
      assert values == ["1.2.3.4", "8.8.8.8"]
    end

    test "handles nil and empty values" do
      alert = build_alert_with_iocs([
        %{type: "domain", value: nil},
        %{type: "ip", value: ""},
        %{type: nil, value: "something"},
        %{type: "hash_sha256", value: "abc123"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert Enum.any?(manifest.iocs, &(&1.type == "hash_sha256"))
    end

    test "handles malformed IP addresses" do
      alert = build_alert_with_iocs([
        %{type: "ip", value: "not-an-ip"},
        %{type: "ip", value: "999.999.999.999"},
        %{type: "ip", value: "1.2.3.4"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      ioc = Enum.find(manifest.iocs, &(&1.type == "ip"))
      assert ioc.value == "1.2.3.4"
    end

    test "sets TLP to amber when any IOC is redacted" do
      alert = build_alert_with_iocs([
        %{type: "hostname", value: "internal.local"},
        %{type: "hash_sha256", value: "abc123"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.tlp == "amber"
      assert manifest.redacted_ioc_count > 0
    end

    test "sets TLP to clear when no IOCs are redacted" do
      alert = build_alert_with_iocs([
        %{type: "hash_sha256", value: "abc123"},
        %{type: "domain", value: "evil.com"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.tlp == "clear"
      assert manifest.redacted_ioc_count == 0
    end

    test "rejects unknown IOC types" do
      alert = build_alert_with_iocs([
        %{type: "unknown_type", value: "some_value"},
        %{type: "custom_ioc", value: "another_value"},
        %{type: "hash_sha256", value: "abc123"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 1
      assert manifest.redacted_ioc_count == 2
      assert Enum.any?(manifest.iocs, &(&1.type == "hash_sha256"))
    end

    test "handles empty IOC list" do
      alert = build_alert_with_iocs([])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 0
      assert manifest.redacted_ioc_count == 0
      assert manifest.iocs == []
      assert manifest.tlp == "clear"
    end

    test "handles all IOCs redacted" do
      alert = build_alert_with_iocs([
        %{type: "hostname", value: "internal.local"},
        %{type: "username", value: "admin"},
        %{type: "path", value: "/home/user/file"}
      ])

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 0
      assert manifest.redacted_ioc_count == 3
      assert manifest.iocs == []
      assert manifest.tlp == "amber"
    end
  end

  describe "IOC extraction from raw_event" do
    test "extracts hashes from raw_event" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Test Alert",
        severity: "high",
        status: "open",
        organization_id: Ecto.UUID.generate(),
        agent_id: Ecto.UUID.generate(),
        inserted_at: DateTime.utc_now(),
        raw_event: %{
          sha256: "abc123def456",
          sha1: "xyz789",
          md5: "qwerty"
        },
        evidence: %{},
        enrichment: %{},
        detection_metadata: %{}
      }

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 3
      types = Enum.map(manifest.iocs, & &1.type) |> Enum.sort()
      assert types == ["hash_md5", "hash_sha1", "hash_sha256"]
    end

    test "extracts domain from raw_event" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Test Alert",
        severity: "high",
        status: "open",
        organization_id: Ecto.UUID.generate(),
        agent_id: Ecto.UUID.generate(),
        inserted_at: DateTime.utc_now(),
        raw_event: %{
          domain: "malware.com",
          query: "c2.evil.net"  # dns_query field
        },
        evidence: %{},
        enrichment: %{},
        detection_metadata: %{}
      }

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 2
      values = Enum.map(manifest.iocs, & &1.value) |> Enum.sort()
      assert values == ["c2.evil.net", "malware.com"]
    end

    test "extracts URL and IP from raw_event" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Test Alert",
        severity: "high",
        status: "open",
        organization_id: Ecto.UUID.generate(),
        agent_id: Ecto.UUID.generate(),
        inserted_at: DateTime.utc_now(),
        raw_event: %{
          url: "https://evil.com/payload",
          remote_ip: "1.2.3.4",
          dst_ip: "5.6.7.8"
        },
        evidence: %{},
        enrichment: %{},
        detection_metadata: %{}
      }

      manifest = Attestation.build_public_manifest(alert)

      assert manifest.ioc_count == 3
      types = Enum.map(manifest.iocs, & &1.type) |> Enum.sort()
      assert types == ["ip", "ip", "url"]
    end
  end

  # Helper functions

  defp build_alert_with_iocs(iocs) do
    %Alert{
      id: Ecto.UUID.generate(),
      title: "Test Alert",
      severity: "high",
      status: "open",
      organization_id: Ecto.UUID.generate(),
      agent_id: Ecto.UUID.generate(),
      inserted_at: DateTime.utc_now(),
      evidence: %{
        indicators: iocs
      },
      enrichment: %{},
      raw_event: %{},
      detection_metadata: %{}
    }
  end
end
