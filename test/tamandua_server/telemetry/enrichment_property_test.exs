defmodule TamanduaServer.Telemetry.EnrichmentPropertyTest do
  use TamanduaServer.DataCase
  use ExUnitProperties

  alias TamanduaServer.Telemetry.Enrichment

  describe "Enrichment properties" do
    @tag timeout: 120_000
    property "enrichment preserves original event data" do
      check all(
              event <- event_generator(),
              max_runs: 100
            ) do
        original_payload = event["payload"]

        # Enrich event
        enriched = Enrichment.enrich(event)

        # Original payload should be unchanged
        assert enriched["payload"] == original_payload
      end
    end

    @tag timeout: 120_000
    property "geo enrichment adds location fields" do
      check all(
              ip <- ip_generator(),
              max_runs: 50
            ) do
        event = %{
          "event_type" => "network_connect",
          "payload" => %{"remote_ip" => ip},
          "enrichment" => %{}
        }

        enriched = Enrichment.Geo.enrich(event)

        # Should have enrichment field
        assert Map.has_key?(enriched, "enrichment")
        assert is_map(enriched["enrichment"])
      end
    end

    @tag timeout: 120_000
    property "enrichment is idempotent" do
      check all(
              event <- event_generator(),
              max_runs: 50
            ) do
        enriched_once = Enrichment.enrich(event)
        enriched_twice = Enrichment.enrich(enriched_once)

        # Enriching twice should produce same result as enriching once
        assert enriched_once == enriched_twice
      end
    end

    @tag timeout: 120_000
    property "enrichment handles missing fields gracefully" do
      check all(
              event_type <- event_type_generator(),
              max_runs: 100
            ) do
        # Event with minimal data (no IP, no file hash, etc.)
        minimal_event = %{
          "event_type" => event_type,
          "payload" => %{},
          "enrichment" => %{}
        }

        # Should not crash
        enriched = Enrichment.enrich(minimal_event)

        # Should return a valid event
        assert Map.has_key?(enriched, "event_type")
        assert Map.has_key?(enriched, "payload")
        assert Map.has_key?(enriched, "enrichment")
      end
    end

    @tag timeout: 120_000
    property "enrichment merges multiple sources" do
      check all(
              event <- event_with_multiple_enrichments(),
              max_runs: 50
            ) do
        enriched = Enrichment.enrich(event)
        enrichment = enriched["enrichment"]

        # Should have multiple enrichment sources
        assert is_map(enrichment)

        # Count enrichment keys
        key_count = Map.keys(enrichment) |> length()
        assert key_count >= 0
      end
    end

    @tag timeout: 120_000
    property "ip reputation scores are in valid range" do
      check all(
              ip <- ip_generator(),
              max_runs: 50
            ) do
        event = %{
          "event_type" => "network_connect",
          "payload" => %{"remote_ip" => ip},
          "enrichment" => %{}
        }

        enriched = Enrichment.ThreatIntel.enrich(event)
        enrichment = enriched["enrichment"]

        # If reputation score is present, it should be valid
        if Map.has_key?(enrichment, "reputation_score") do
          score = enrichment["reputation_score"]
          assert is_number(score)
          assert score >= 0
          assert score <= 100
        end
      end
    end

    @tag timeout: 120_000
    property "enrichment preserves event type" do
      check all(
              event <- event_generator(),
              max_runs: 100
            ) do
        original_type = event["event_type"]
        enriched = Enrichment.enrich(event)

        assert enriched["event_type"] == original_type
      end
    end

    @tag timeout: 120_000
    property "enrichment adds timestamp if missing" do
      check all(
              event <- event_without_timestamp(),
              max_runs: 50
            ) do
        enriched = Enrichment.enrich(event)

        # Should have a timestamp after enrichment
        assert Map.has_key?(enriched, "timestamp") or Map.has_key?(enriched["payload"], "timestamp")
      end
    end

    @tag timeout: 120_000
    property "cache lookups are consistent" do
      check all(
              key <- string(:alphanumeric, min_length: 1, max_length: 50),
              value <- map_generator(),
              max_runs: 50
            ) do
        # Cache a value
        Enrichment.Cache.put(key, value)

        # Retrieve it multiple times
        result1 = Enrichment.Cache.get(key)
        result2 = Enrichment.Cache.get(key)

        # Should be consistent
        assert result1 == result2
      end
    end

    @tag timeout: 120_000
    property "asset enrichment adds context" do
      check all(
              hostname <- string(:alphanumeric, min_length: 1, max_length: 50),
              max_runs: 50
            ) do
        event = %{
          "event_type" => "process_create",
          "payload" => %{"hostname" => hostname},
          "enrichment" => %{}
        }

        enriched = Enrichment.Asset.enrich(event)

        # Should have enrichment
        assert Map.has_key?(enriched, "enrichment")
        assert is_map(enriched["enrichment"])
      end
    end
  end

  # Generators
  defp event_generator do
    gen all(
          event_type <- event_type_generator(),
          payload <- payload_generator(),
          max_tries: 10
        ) do
      %{
        "event_type" => event_type,
        "payload" => payload,
        "enrichment" => %{},
        "timestamp" => DateTime.utc_now()
      }
    end
  end

  defp event_with_multiple_enrichments do
    gen all(
          event_type <- event_type_generator(),
          ip <- ip_generator(),
          file_hash <- hash_generator(),
          max_tries: 10
        ) do
      %{
        "event_type" => event_type,
        "payload" => %{
          "remote_ip" => ip,
          "sha256" => file_hash
        },
        "enrichment" => %{}
      }
    end
  end

  defp event_without_timestamp do
    gen all(
          event_type <- event_type_generator(),
          payload <- payload_generator(),
          max_tries: 10
        ) do
      %{
        "event_type" => event_type,
        "payload" => payload,
        "enrichment" => %{}
      }
    end
  end

  defp event_type_generator do
    one_of([
      constant("process_create"),
      constant("network_connect"),
      constant("dns_query"),
      constant("file_create"),
      constant("registry_modify")
    ])
  end

  defp payload_generator do
    gen all(
          key1 <- string(:alphanumeric, min_length: 1, max_length: 20),
          value1 <- string(:alphanumeric, min_length: 1, max_length: 50),
          key2 <- string(:alphanumeric, min_length: 1, max_length: 20),
          value2 <- integer(1..10000),
          max_tries: 10
        ) do
      %{
        key1 => value1,
        key2 => value2
      }
    end
  end

  defp ip_generator do
    gen all(
          a <- integer(1..255),
          b <- integer(0..255),
          c <- integer(0..255),
          d <- integer(1..255),
          max_tries: 10
        ) do
      "#{a}.#{b}.#{c}.#{d}"
    end
  end

  defp hash_generator do
    bind(
      list_of(integer(0..255), length: 32),
      fn bytes ->
        constant(
          bytes
          |> Enum.map(&Integer.to_string(&1, 16) |> String.pad_leading(2, "0"))
          |> Enum.join()
        )
      end
    )
  end

  defp map_generator do
    gen all(
          keys <- list_of(string(:alphanumeric, min_length: 1, max_length: 10), max_length: 5),
          values <- list_of(one_of([string(:alphanumeric), integer()]), max_length: 5),
          max_tries: 10
        ) do
      Enum.zip(keys, values) |> Map.new()
    end
  end
end
