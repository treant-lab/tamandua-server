defmodule TamanduaServer.Telemetry.EventPropertyTest do
  use TamanduaServer.DataCase
  use ExUnitProperties

  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo

  describe "Event properties" do
    @tag timeout: 120_000
    property "events can be serialized and deserialized via JSON" do
      check all(event <- telemetry_event_generator(), max_runs: 100) do
        # Convert struct to map for JSON encoding
        event_map = %{
          "id" => event.id,
          "event_type" => event.event_type,
          "agent_id" => event.agent_id,
          "timestamp" => DateTime.to_iso8601(event.timestamp),
          "payload" => event.payload,
          "severity" => event.severity,
          "enrichment" => event.enrichment
        }

        json = Jason.encode!(event_map)
        decoded = Jason.decode!(json)

        assert decoded["event_type"] == event.event_type
        assert decoded["agent_id"] == event.agent_id
        assert decoded["severity"] == event.severity
      end
    end

    @tag timeout: 120_000
    property "event timestamps are always valid" do
      check all(event <- telemetry_event_generator(), max_runs: 100) do
        # All generated timestamps should be in the past or present
        assert DateTime.compare(event.timestamp, DateTime.utc_now()) in [:lt, :eq]
      end
    end

    @tag timeout: 120_000
    property "event payloads can contain nested structures" do
      check all(
              agent_id <- uuid_generator(),
              payload <- nested_payload_generator(3),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        # Create event with nested payload
        event_attrs = %{
          event_type: "process_create",
          agent_id: agent_id,
          timestamp: DateTime.utc_now(),
          payload: payload,
          severity: "info"
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        # Verify nested payload persisted correctly
        assert event.payload == payload
        assert is_map(event.payload) or is_list(event.payload)

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end

    @tag timeout: 120_000
    property "event types are preserved" do
      check all(
              agent_id <- uuid_generator(),
              event_type <- event_type_generator(),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        event_attrs = %{
          event_type: event_type,
          agent_id: agent_id,
          timestamp: DateTime.utc_now(),
          payload: %{"test" => "data"},
          severity: "info"
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        # Reload from database
        reloaded = Repo.get!(Event, event.id)
        assert reloaded.event_type == event_type

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end

    @tag timeout: 120_000
    property "severity levels are valid" do
      check all(
              agent_id <- uuid_generator(),
              severity <- severity_generator(),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        event_attrs = %{
          event_type: "process_create",
          agent_id: agent_id,
          timestamp: DateTime.utc_now(),
          payload: %{"test" => "data"},
          severity: severity
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        assert event.severity in ["info", "low", "medium", "high", "critical"]

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end

    @tag timeout: 120_000
    property "enrichment data preserves structure" do
      check all(
              agent_id <- uuid_generator(),
              enrichment <- enrichment_generator(),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        event_attrs = %{
          event_type: "network_connect",
          agent_id: agent_id,
          timestamp: DateTime.utc_now(),
          payload: %{"remote_ip" => "8.8.8.8"},
          enrichment: enrichment,
          severity: "info"
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        # Verify enrichment persisted correctly
        assert event.enrichment == enrichment

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end

    @tag timeout: 120_000
    property "payload field types are preserved" do
      check all(
              agent_id <- uuid_generator(),
              string_val <- string(:alphanumeric, min_length: 1, max_length: 50),
              int_val <- integer(1..10000),
              bool_val <- boolean(),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        payload = %{
          "string_field" => string_val,
          "integer_field" => int_val,
          "boolean_field" => bool_val
        }

        event_attrs = %{
          event_type: "process_create",
          agent_id: agent_id,
          timestamp: DateTime.utc_now(),
          payload: payload,
          severity: "info"
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        # Reload from database
        reloaded = Repo.get!(Event, event.id)

        assert reloaded.payload["string_field"] == string_val
        assert reloaded.payload["integer_field"] == int_val
        assert reloaded.payload["boolean_field"] == bool_val

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end

    @tag timeout: 120_000
    property "timestamps maintain microsecond precision" do
      check all(
              agent_id <- uuid_generator(),
              max_runs: 50
            ) do
        # Create agent first
        {:ok, agent} =
          %Agent{}
          |> Agent.changeset(%{
            id: agent_id,
            hostname: "test-host",
            ip_address: "192.168.1.100",
            status: "online"
          })
          |> Repo.insert()

        timestamp = DateTime.utc_now()

        event_attrs = %{
          event_type: "process_create",
          agent_id: agent_id,
          timestamp: timestamp,
          payload: %{"test" => "data"},
          severity: "info"
        }

        {:ok, event} =
          %Event{}
          |> Event.changeset(event_attrs)
          |> Repo.insert()

        # Reload from database
        reloaded = Repo.get!(Event, event.id)

        # Check microsecond precision is maintained
        assert reloaded.timestamp.microsecond != {0, 0}

        # Cleanup
        Repo.delete(event)
        Repo.delete(agent)
      end
    end
  end

  # Generators
  defp telemetry_event_generator do
    gen all(
          event_type <- event_type_generator(),
          agent_id <- uuid_generator(),
          payload <- payload_generator(event_type),
          severity <- severity_generator(),
          max_tries: 10
        ) do
      %Event{
        id: Ecto.UUID.generate(),
        event_type: event_type,
        agent_id: agent_id,
        timestamp: DateTime.utc_now(),
        payload: payload,
        severity: severity,
        enrichment: %{},
        archived: false,
        sampled: false
      }
    end
  end

  defp event_type_generator do
    one_of([
      constant("process_create"),
      constant("process_terminate"),
      constant("file_create"),
      constant("file_modify"),
      constant("file_delete"),
      constant("network_connect"),
      constant("dns_query"),
      constant("registry_create"),
      constant("registry_modify")
    ])
  end

  defp payload_generator("process_create") do
    gen all(
          pid <- integer(1..65535),
          path <- string(:alphanumeric, min_length: 1, max_length: 50),
          cmdline <- string(:alphanumeric, min_length: 1, max_length: 100),
          max_tries: 10
        ) do
      %{
        "pid" => pid,
        "path" => path,
        "cmdline" => cmdline,
        "user" => "testuser"
      }
    end
  end

  defp payload_generator("network_connect") do
    gen all(
          remote_ip <- ip_generator(),
          remote_port <- integer(1..65535),
          max_tries: 10
        ) do
      %{
        "remote_ip" => remote_ip,
        "remote_port" => remote_port,
        "protocol" => "tcp"
      }
    end
  end

  defp payload_generator(_event_type) do
    gen all(
          key <- string(:alphanumeric, min_length: 1, max_length: 20),
          value <- string(:alphanumeric, min_length: 1, max_length: 50),
          max_tries: 10
        ) do
      %{key => value}
    end
  end

  defp nested_payload_generator(0) do
    one_of([
      string(:alphanumeric, min_length: 1, max_length: 30),
      integer(1..10000),
      boolean()
    ])
  end

  defp nested_payload_generator(depth) when depth > 0 do
    one_of([
      string(:alphanumeric, min_length: 1, max_length: 30),
      integer(1..10000),
      boolean(),
      list_of(nested_payload_generator(depth - 1), max_length: 3),
      map_of(
        string(:alphanumeric, min_length: 1, max_length: 15),
        nested_payload_generator(depth - 1),
        max_length: 5
      )
    ])
  end

  defp enrichment_generator do
    gen all(
          geo <- geo_generator(),
          threat_intel <- threat_intel_generator(),
          max_tries: 10
        ) do
      %{
        "geo" => geo,
        "threat_intel" => threat_intel
      }
    end
  end

  defp geo_generator do
    gen all(
          country <- string(:alphanumeric, min_length: 2, max_length: 2),
          city <- string(:alphanumeric, min_length: 1, max_length: 30),
          max_tries: 10
        ) do
      %{
        "country" => country,
        "city" => city
      }
    end
  end

  defp threat_intel_generator do
    gen all(
          is_malicious <- boolean(),
          reputation_score <- integer(0..100),
          max_tries: 10
        ) do
      %{
        "is_malicious" => is_malicious,
        "reputation_score" => reputation_score
      }
    end
  end

  defp severity_generator do
    one_of([
      constant("info"),
      constant("low"),
      constant("medium"),
      constant("high"),
      constant("critical")
    ])
  end

  defp uuid_generator do
    bind(
      list_of(integer(0..255), length: 16),
      fn bytes ->
        constant(
          bytes
          |> Enum.map(&Integer.to_string(&1, 16) |> String.pad_leading(2, "0"))
          |> Enum.chunk_every(4)
          |> Enum.map(&Enum.join/1)
          |> Enum.join("-")
        )
      end
    )
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
end
