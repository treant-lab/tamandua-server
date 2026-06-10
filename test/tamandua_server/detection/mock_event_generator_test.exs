defmodule TamanduaServer.Detection.MockEventGeneratorTest do
  use ExUnit.Case

  alias TamanduaServer.Detection.MockEventGenerator

  describe "generate_from_template/1" do
    test "generates event from basic template" do
      template = %{
        "type" => "process_create",
        "data" => %{
          "path" => "C:\\Windows\\System32\\cmd.exe",
          "cmdline" => "cmd.exe /c whoami"
        }
      }

      event = MockEventGenerator.generate_from_template(template)

      assert event["event_type"] == "process_create"
      assert event["payload"][:path] == "C:\\Windows\\System32\\cmd.exe"
      assert event["payload"][:cmdline] == "cmd.exe /c whoami"
      assert Map.has_key?(event, "event_id")
      assert Map.has_key?(event, "timestamp")
    end

    test "merges custom data with defaults" do
      template = %{
        "type" => "process_create",
        "os_type" => "windows",
        "data" => %{
          "path" => "C:\\Tools\\mimikatz.exe"
        }
      }

      event = MockEventGenerator.generate_from_template(template)

      # Custom value
      assert event["payload"][:path] == "C:\\Tools\\mimikatz.exe"

      # Default values
      assert is_integer(event["payload"][:pid])
      assert is_integer(event["payload"][:ppid])
    end

    test "supports different event types" do
      for event_type <- ["process_create", "file_create", "network_connect", "registry_set", "dns_query"] do
        template = %{"type" => event_type, "data" => %{}}
        event = MockEventGenerator.generate_from_template(template)
        assert event["event_type"] == event_type
      end
    end
  end

  describe "generate_random/2" do
    test "generates random process event" do
      event = MockEventGenerator.generate_random(:process_create)

      assert event["event_type"] == "process_create"
      assert is_binary(event["payload"][:path])
      assert is_binary(event["payload"][:cmdline])
      assert is_integer(event["payload"][:pid])
    end

    test "generates random network event" do
      event = MockEventGenerator.generate_random(:network_connect)

      assert event["event_type"] == "network_connect"
      assert is_binary(event["payload"][:remote_ip])
      assert is_integer(event["payload"][:remote_port])
      assert is_binary(event["payload"][:protocol])
    end

    test "respects os_type option" do
      event = MockEventGenerator.generate_random(:process_create, os_type: "linux")
      assert event["os_type"] == "linux"
    end
  end

  describe "generate_bulk/3" do
    test "generates multiple events" do
      events = MockEventGenerator.generate_bulk(:process_create, 10)

      assert length(events) == 10
      assert Enum.all?(events, &(&1["event_type"] == "process_create"))

      # Each event should have unique event_id
      event_ids = Enum.map(events, & &1["event_id"])
      assert length(Enum.uniq(event_ids)) == 10
    end
  end

  describe "generate_attack_chain/1" do
    test "generates credential theft chain" do
      events = MockEventGenerator.generate_attack_chain(:credential_theft)

      assert length(events) >= 3
      assert Enum.any?(events, fn e ->
        String.contains?(e["payload"][:cmdline] || "", "mimikatz")
      end)
    end

    test "generates ransomware chain" do
      events = MockEventGenerator.generate_attack_chain(:ransomware)

      assert length(events) >= 3
      assert Enum.any?(events, fn e ->
        String.contains?(e["payload"][:cmdline] || "", "vssadmin")
      end)
    end

    test "generates lateral movement chain" do
      events = MockEventGenerator.generate_attack_chain(:lateral_movement)

      assert length(events) >= 3
      assert Enum.any?(events, fn e ->
        e["event_type"] == "network_connect"
      end)
    end
  end
end
