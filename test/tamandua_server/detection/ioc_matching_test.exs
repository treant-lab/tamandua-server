defmodule TamanduaServer.Detection.IOCMatchingTest do
  @moduledoc """
  Unit tests for IOC matching logic in the detection engine.

  Tests the observable extraction, IOC type matching (hash, IP,
  domain, URL), case sensitivity, subdomain matching, and trusted
  domain filtering that the EngineWorker performs against loaded IOCs.

  These tests exercise the pure matching functions without requiring
  the full detection pipeline to run.
  """

  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.Detection.IOCs

  # ── IOC schema changeset validation ─────────────────────────────────

  describe "IOC changeset" do
    test "valid changeset for IP IOC" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "192.168.1.100",
          severity: "high",
          source: "manual"
        })

      assert changeset.valid?
    end

    test "valid changeset for domain IOC" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "domain",
          value: "evil-domain.com",
          severity: "critical"
        })

      assert changeset.valid?
    end

    test "valid changeset for hash IOC" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "hash_sha256",
          value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          severity: "medium"
        })

      assert changeset.valid?
    end

    test "rejects missing type" do
      changeset = IOC.changeset(%IOC{}, %{value: "test"})
      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :type)
    end

    test "rejects missing value" do
      changeset = IOC.changeset(%IOC{}, %{type: "ip"})
      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :value)
    end

    test "rejects invalid type" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "invalid_type",
          value: "test"
        })

      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :type)
    end

    test "rejects invalid severity" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "1.2.3.4",
          severity: "super_critical"
        })

      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :severity)
    end

    test "confidence must be between 0.0 and 1.0" do
      changeset_too_high =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "1.2.3.4",
          confidence: 1.5
        })

      refute changeset_too_high.valid?

      changeset_negative =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "1.2.3.4",
          confidence: -0.1
        })

      refute changeset_negative.valid?

      changeset_ok =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "1.2.3.4",
          confidence: 0.85
        })

      assert changeset_ok.valid?
    end

    test "accepts all valid IOC types" do
      valid_types = ["hash_md5", "hash_sha256", "hash_sha1", "ip", "domain", "url", "email", "filename"]

      for type <- valid_types do
        changeset = IOC.changeset(%IOC{}, %{type: type, value: "test-value"})
        assert changeset.valid?, "type #{type} should be valid"
      end
    end

    test "accepts all valid severities" do
      valid_severities = ["low", "medium", "high", "critical"]

      for severity <- valid_severities do
        changeset =
          IOC.changeset(%IOC{}, %{
            type: "ip",
            value: "1.2.3.4",
            severity: severity
          })

        assert changeset.valid?, "severity #{severity} should be valid"
      end
    end

    test "default values are set correctly" do
      changeset =
        IOC.changeset(%IOC{}, %{
          type: "ip",
          value: "10.0.0.1"
        })

      assert changeset.valid?
      # The struct defaults: enabled=true, severity="medium", tags=[], metadata=%{}
      ioc = Ecto.Changeset.apply_changes(changeset)
      assert ioc.enabled == true
      assert ioc.severity == "medium"
      assert ioc.tags == []
      assert ioc.metadata == %{}
    end
  end

  # ── IOC CRUD operations ─────────────────────────────────────────────

  describe "IOCs.add/1" do
    test "creates an IP IOC" do
      {:ok, ioc} =
        IOCs.add(%{
          type: "ip",
          value: "203.0.113.50",
          severity: "high",
          source: "test"
        })

      assert ioc.type == "ip"
      # Values should be lowercased/trimmed
      assert ioc.value == "203.0.113.50"
      assert ioc.severity == "high"
      assert ioc.enabled == true
    end

    test "creates a domain IOC and normalizes value" do
      {:ok, ioc} =
        IOCs.add(%{
          type: "domain",
          value: "  www.Evil-Domain.COM  ",
          severity: "critical",
          source: "test"
        })

      assert ioc.type == "domain"
      # Should be trimmed, lowercased, www. stripped
      assert ioc.value == "evil-domain.com"
    end

    test "creates a hash IOC with lowercase normalization" do
      hash_upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

      {:ok, ioc} =
        IOCs.add(%{
          type: "hash_sha256",
          value: hash_upper,
          source: "test"
        })

      assert ioc.value == String.downcase(hash_upper)
    end

    test "rejects invalid IOC" do
      {:error, changeset} =
        IOCs.add(%{
          type: "invalid_type",
          value: "test"
        })

      assert not changeset.valid?
    end
  end

  describe "IOCs.lookup/2" do
    test "finds existing IOC by type and value" do
      {:ok, created} =
        IOCs.add(%{
          type: "ip",
          value: "198.51.100.1",
          severity: "high",
          source: "test"
        })

      {:ok, found} = IOCs.lookup("ip", "198.51.100.1")
      assert found.id == created.id
    end

    test "returns not_found for missing IOC" do
      assert {:error, :not_found} = IOCs.lookup("ip", "0.0.0.0")
    end

    test "lookup is case-insensitive for hashes" do
      hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

      {:ok, _} =
        IOCs.add(%{
          type: "hash_sha256",
          value: hash,
          source: "test"
        })

      {:ok, found} = IOCs.lookup("hash_sha256", String.upcase(hash))
      assert found.value == hash
    end

    test "lookup does not find disabled IOCs" do
      {:ok, ioc} =
        IOCs.add(%{
          type: "ip",
          value: "192.0.2.99",
          severity: "medium",
          source: "test",
          enabled: true
        })

      # Disable it
      IOCs.update_ioc(ioc, %{enabled: false})

      assert {:error, :not_found} = IOCs.lookup("ip", "192.0.2.99")
    end
  end

  # ── IOC matching ────────────────────────────────────────────────────

  describe "IOCs.match?/2" do
    test "matches an IP IOC" do
      {:ok, _} =
        IOCs.add(%{
          type: "ip",
          value: "10.20.30.40",
          severity: "high",
          source: "test"
        })

      result = IOCs.match?("10.20.30.40", "ip")
      assert result != nil
      assert result.type == "ip"
    end

    test "returns nil for non-matching value" do
      result = IOCs.match?("255.255.255.255", "ip")
      assert result == nil
    end
  end

  describe "IOCs.match_batch/1" do
    test "returns matching IOCs from a batch" do
      {:ok, _} =
        IOCs.add(%{
          type: "domain",
          value: "batch-test-evil.com",
          severity: "high",
          source: "test"
        })

      {:ok, _} =
        IOCs.add(%{
          type: "ip",
          value: "100.100.100.100",
          severity: "medium",
          source: "test"
        })

      results =
        IOCs.match_batch([
          {"domain", "batch-test-evil.com"},
          {"ip", "100.100.100.100"},
          {"ip", "9.9.9.9"}
        ])

      assert length(results) == 2

      types = Enum.map(results, & &1.type)
      assert "domain" in types
      assert "ip" in types
    end
  end

  # ── Bulk operations ─────────────────────────────────────────────────

  describe "IOCs.bulk_add/1" do
    test "inserts multiple IOCs" do
      {:ok, result} =
        IOCs.bulk_add([
          %{type: "ip", value: "1.1.1.1", source: "bulk-test"},
          %{type: "ip", value: "2.2.2.2", source: "bulk-test"},
          %{type: "domain", value: "bulk-evil.com", source: "bulk-test"}
        ])

      assert result.successful >= 2
      assert result.failed == 0
    end

    test "reports failures for invalid entries" do
      {:ok, result} =
        IOCs.bulk_add([
          %{type: "ip", value: "3.3.3.3", source: "bulk-test"},
          %{type: "invalid_no_such_type", value: "bad"}
        ])

      assert result.successful >= 1
      assert result.failed >= 1
      assert length(result.errors) >= 1
    end

    test "handles empty list" do
      {:ok, result} = IOCs.bulk_add([])
      assert result.successful == 0
      assert result.failed == 0
    end
  end

  # ── Count and stats ─────────────────────────────────────────────────

  describe "IOCs.count/1" do
    test "counts all IOCs" do
      count = IOCs.count()
      assert is_integer(count)
      assert count >= 0
    end

    test "counts by type" do
      {:ok, _} =
        IOCs.add(%{type: "email", value: "count-test@evil.com", source: "test"})

      count = IOCs.count(type: "email")
      assert count >= 1
    end
  end

  describe "IOCs.get_stats/0" do
    test "returns a stats map with expected keys" do
      stats = IOCs.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total)
      assert Map.has_key?(stats, :active)
      assert Map.has_key?(stats, :by_type)
      assert Map.has_key?(stats, :by_severity)
      assert Map.has_key?(stats, :by_source)
    end
  end

  # ── Observable matching logic (as used by EngineWorker) ─────────────

  describe "observable extraction from events" do
    # This tests the same extraction logic that EngineWorker uses.
    # We replicate the extract function here to test in isolation.

    defp extract_observables(event) do
      payload = event[:payload] || %{}

      %{
        sha256: payload[:sha256],
        sha1: payload[:sha1],
        md5: payload[:md5],
        ip: payload[:remote_ip],
        domain: extract_domain(payload),
        path: payload[:path],
        cmdline: payload[:cmdline]
      }
    end

    defp extract_domain(payload) do
      cond do
        payload[:query] -> payload[:query]
        payload[:domain] -> payload[:domain]
        payload[:url] ->
          case URI.parse(to_string(payload[:url])) do
            %URI{host: host} when is_binary(host) and host != "" -> host
            _ -> nil
          end
        payload[:hostname] -> payload[:hostname]
        payload[:remote_ip] -> nil
        true -> nil
      end
    end

    test "extracts SHA256 hash from payload" do
      obs = extract_observables(%{payload: %{sha256: <<0xDE, 0xAD>>}})
      assert obs.sha256 == <<0xDE, 0xAD>>
    end

    test "extracts IP from remote_ip" do
      obs = extract_observables(%{payload: %{remote_ip: "1.2.3.4"}})
      assert obs.ip == "1.2.3.4"
    end

    test "extracts domain from query field" do
      obs = extract_observables(%{payload: %{query: "evil.com"}})
      assert obs.domain == "evil.com"
    end

    test "extracts domain from url field" do
      obs = extract_observables(%{payload: %{url: "https://evil.com/payload"}})
      assert obs.domain == "evil.com"
    end

    test "extracts domain from hostname field" do
      obs = extract_observables(%{payload: %{hostname: "evil-host.com"}})
      assert obs.domain == "evil-host.com"
    end

    test "domain is nil when only remote_ip is present" do
      obs = extract_observables(%{payload: %{remote_ip: "1.2.3.4"}})
      assert obs.domain == nil
    end

    test "all fields nil for empty payload" do
      obs = extract_observables(%{payload: %{}})
      assert obs.sha256 == nil
      assert obs.ip == nil
      assert obs.domain == nil
    end
  end

  # ── IOC type atom matching ──────────────────────────────────────────

  describe "observable_matches_ioc? logic" do
    # Replicate the matching logic from EngineWorker for isolated testing.

    defp observable_matches_ioc?(observables, ioc) do
      case ioc.type do
        :sha256 ->
          observables.sha256 &&
            Base.encode16(observables.sha256, case: :lower) == ioc.value

        :ip ->
          observables.ip == ioc.value

        :domain ->
          domain = observables.domain
          domain != nil and
            (domain == ioc.value or String.ends_with?(domain, "." <> ioc.value))

        _ ->
          false
      end
    end

    test "matches SHA256 hash (binary to hex comparison)" do
      hash_binary = Base.decode16!("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")

      obs = %{sha256: hash_binary, ip: nil, domain: nil}

      ioc = %{
        type: :sha256,
        value: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      }

      assert observable_matches_ioc?(obs, ioc)
    end

    test "does not match SHA256 when hash differs" do
      obs = %{sha256: :crypto.strong_rand_bytes(32), ip: nil, domain: nil}
      ioc = %{type: :sha256, value: "0000000000000000000000000000000000000000000000000000000000000000"}
      refute observable_matches_ioc?(obs, ioc)
    end

    test "matches exact IP" do
      obs = %{sha256: nil, ip: "192.168.1.1", domain: nil}
      ioc = %{type: :ip, value: "192.168.1.1"}
      assert observable_matches_ioc?(obs, ioc)
    end

    test "does not match different IP" do
      obs = %{sha256: nil, ip: "192.168.1.2", domain: nil}
      ioc = %{type: :ip, value: "192.168.1.1"}
      refute observable_matches_ioc?(obs, ioc)
    end

    test "matches exact domain" do
      obs = %{sha256: nil, ip: nil, domain: "evil.com"}
      ioc = %{type: :domain, value: "evil.com"}
      assert observable_matches_ioc?(obs, ioc)
    end

    test "matches subdomain against parent domain IOC" do
      obs = %{sha256: nil, ip: nil, domain: "sub.evil.com"}
      ioc = %{type: :domain, value: "evil.com"}
      assert observable_matches_ioc?(obs, ioc)
    end

    test "does not match partial domain name" do
      # "notevil.com" should NOT match the IOC for "evil.com"
      obs = %{sha256: nil, ip: nil, domain: "notevil.com"}
      ioc = %{type: :domain, value: "evil.com"}
      refute observable_matches_ioc?(obs, ioc)
    end

    test "does not match when domain is nil" do
      obs = %{sha256: nil, ip: nil, domain: nil}
      ioc = %{type: :domain, value: "evil.com"}
      refute observable_matches_ioc?(obs, ioc)
    end
  end

  # ── Trusted domain filtering ────────────────────────────────────────

  describe "trusted domain filtering" do
    @trusted_domains [
      "microsoft.com", "google.com", "github.com", "cloudflare.com",
      "amazonaws.com", "apple.com"
    ]

    defp trusted_domain?(domain) when is_binary(domain) do
      domain_lower = String.downcase(domain)
      Enum.any?(@trusted_domains, fn trusted ->
        domain_lower == trusted or String.ends_with?(domain_lower, "." <> trusted)
      end)
    end
    defp trusted_domain?(_), do: false

    test "recognizes direct trusted domains" do
      assert trusted_domain?("microsoft.com")
      assert trusted_domain?("google.com")
      assert trusted_domain?("github.com")
    end

    test "recognizes subdomains of trusted domains" do
      assert trusted_domain?("update.microsoft.com")
      assert trusted_domain?("api.github.com")
      assert trusted_domain?("s3.amazonaws.com")
    end

    test "rejects non-trusted domains" do
      refute trusted_domain?("evil.com")
      refute trusted_domain?("notmicrosoft.com")
      refute trusted_domain?("c2-server.ru")
    end

    test "is case-insensitive" do
      assert trusted_domain?("MICROSOFT.COM")
      assert trusted_domain?("Google.Com")
      assert trusted_domain?("WWW.GITHUB.COM")
    end

    test "handles nil gracefully" do
      refute trusted_domain?(nil)
    end
  end
end
