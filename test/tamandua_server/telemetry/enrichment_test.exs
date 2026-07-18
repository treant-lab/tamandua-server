defmodule TamanduaServer.Telemetry.EnrichmentTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Telemetry.Enrichment
  alias TamanduaServer.Telemetry.Enrichment.{ThreatIntel, Geo, Asset, User, Cache}
  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.Agents

  describe "ThreatIntel.enrich_event/1" do
    setup do
      # Create test IOCs
      {:ok, _ioc} = IOCs.add(%{
        type: "ip",
        value: "192.0.2.1",
        source: "test",
        severity: "critical",
        confidence: 0.95,
        tags: ["malware", "c2"],
        malware_family: "Emotet"
      })

      {:ok, _ioc} = IOCs.add(%{
        type: "hash_sha256",
        value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source: "test",
        severity: "high",
        confidence: 0.8,
        tags: ["malware"]
      })

      :ok
    end

    test "enriches network event with IOC matches" do
      event = %{
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "192.0.2.1",
          "remote_port" => 443
        }
      }

      enriched = ThreatIntel.enrich_event(event)

      assert enriched.enrichment.threat_intel
      assert enriched.enrichment.threat_intel[:ip]
      assert length(enriched.enrichment.threat_intel[:ip]) == 1

      [match] = enriched.enrichment.threat_intel[:ip]
      assert match.value == "192.0.2.1"
      assert match.source == "test"
      assert match.severity == "critical"
      assert match.malware_family == "Emotet"
    end

    test "enriches process event with hash matches" do
      event = %{
        event_type: "process_create",
        payload: %{
          "sha256" => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "image_path" => "C:\\Windows\\System32\\malware.exe"
        }
      }

      enriched = ThreatIntel.enrich_event(event)

      assert enriched.enrichment.threat_intel
      assert enriched.enrichment.threat_intel[:hash_sha256]
      assert length(enriched.enrichment.threat_intel[:hash_sha256]) == 1
    end

    test "skips events with no matching IOCs" do
      event = %{
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "8.8.8.8",  # Google DNS, not in IOC database
          "remote_port" => 53
        }
      }

      enriched = ThreatIntel.enrich_event(event)

      # Event should be returned unchanged (or with empty enrichment)
      refute enriched[:enrichment][:threat_intel]
    end

    test "filters out private IPs" do
      event = %{
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "192.168.1.1",  # Private IP
          "remote_port" => 445
        }
      }

      enriched = ThreatIntel.enrich_event(event)

      # Private IPs should not be looked up
      refute enriched[:enrichment][:threat_intel]
    end
  end

  describe "Geo.enrich_event/1" do
    test "enriches network event with GeoIP data" do
      event = %{
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "8.8.8.8",
          "remote_port" => 53
        }
      }

      enriched = Geo.enrich_event(event)

      # Should have geo enrichment
      assert enriched.enrichment.geo
      assert enriched.enrichment.geo["8.8.8.8"]

      geo = enriched.enrichment.geo["8.8.8.8"]
      # Note: Actual values depend on GeoIP database availability
      assert is_map(geo)
    end

    test "skips events with no IPs" do
      event = %{
        event_type: "file_create",
        payload: %{
          "path" => "C:\\test.txt"
        }
      }

      enriched = Geo.enrich_event(event)

      # No IPs, so no geo enrichment
      refute enriched[:enrichment][:geo]
    end

    test "filters out private IPs from geo lookup" do
      event = %{
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "10.0.0.1",
          "remote_port" => 445
        }
      }

      enriched = Geo.enrich_event(event)

      # Private IPs should not be enriched
      refute enriched[:enrichment][:geo]
    end
  end

  describe "Asset.enrich_event/1" do
    setup do
      # Create test agent
      {:ok, agent} = Agents.create_agent(%{
        id: Ecto.UUID.generate(),
        hostname: "test-workstation",
        os_type: "windows",
        os_version: "Windows 11",
        status: "online",
        tags: ["test", "engineering"],
        criticality: "high"
      })

      %{agent: agent}
    end

    test "enriches event with asset context", %{agent: agent} do
      event = %{
        agent_id: agent.id,
        event_type: "process_create",
        payload: %{
          "image_path" => "C:\\Windows\\System32\\cmd.exe"
        }
      }

      enriched = Asset.enrich_event(event)

      assert enriched.enrichment.asset
      assert enriched.enrichment.asset.hostname == "test-workstation"
      assert enriched.enrichment.asset.os_type == "windows"
      assert enriched.enrichment.asset.criticality == "high"
    end

    test "skips events with no agent_id" do
      event = %{
        event_type: "test_event",
        payload: %{}
      }

      enriched = Asset.enrich_event(event)

      refute enriched[:enrichment][:asset]
    end
  end

  describe "User.enrich_event/1" do
    test "extracts username from event payload" do
      event = %{
        event_type: "process_create",
        payload: %{
          "user" => "jsmith",
          "image_path" => "C:\\test.exe"
        }
      }

      enriched = User.enrich_event(event)

      # Note: User enrichment currently returns :not_implemented
      # This test will need to be updated when user directory integration is added
      refute enriched[:enrichment][:user]
    end
  end

  describe "Enrichment.enrich_all/1" do
    setup do
      # Create test data
      {:ok, agent} = Agents.create_agent(%{
        id: Ecto.UUID.generate(),
        hostname: "test-host",
        os_type: "linux",
        status: "online"
      })

      {:ok, _ioc} = IOCs.add(%{
        type: "ip",
        value: "198.51.100.1",
        source: "test",
        severity: "medium"
      })

      %{agent: agent}
    end

    test "applies all enrichments", %{agent: agent} do
      event = %{
        agent_id: agent.id,
        event_type: "network_connect",
        payload: %{
          "remote_ip" => "198.51.100.1",
          "remote_port" => 80,
          "user" => "testuser"
        }
      }

      enriched = Enrichment.enrich_all(event)

      # Should have multiple enrichments
      assert enriched.enrichment
      # ThreatIntel enrichment (IOC match)
      assert enriched.enrichment.threat_intel
      # Geo enrichment
      # Note: May or may not be present depending on GeoIP availability
      # Asset enrichment
      assert enriched.enrichment.asset
    end
  end

  describe "Cache" do
    test "caches threat intel lookups" do
      {:ok, ioc} = IOCs.add(%{
        type: "ip",
        value: "203.0.113.1",
        source: "test"
      })

      # First lookup - cache miss
      result1 = Cache.get_or_lookup_threat_intel(:ip, "203.0.113.1")
      assert {:ok, ^ioc} = result1

      # Second lookup - cache hit (should be faster)
      result2 = Cache.get_or_lookup_threat_intel(:ip, "203.0.113.1")
      assert {:ok, ^ioc} = result2
    end

    test "provides cache statistics" do
      stats = Cache.entry_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_entries)
      assert Map.has_key?(stats, :threat_intel_entries)
      assert Map.has_key?(stats, :geo_entries)
    end

    test "can clear all caches" do
      # Add something to cache
      Cache.get_or_lookup_threat_intel(:ip, "203.0.113.2")

      # Clear cache
      :ok = Cache.clear_all()

      # Stats should show 0 entries
      stats = Cache.entry_stats()
      assert stats.total_entries == 0
    end
  end

  describe "AsyncWorker" do
    test "provides worker statistics" do
      stats = Enrichment.AsyncWorker.stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :queue_size)
      assert Map.has_key?(stats, :processed)
      assert Map.has_key?(stats, :failed)
      assert Map.has_key?(stats, :uptime_seconds)
    end
  end
end
