defmodule TamanduaServer.Investigations.GraphBuilderTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Investigations.GraphBuilder
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.Agent

  describe "build_from_alert/2" do
    setup do
      # Create test agent
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-1",
          hostname: "test-host",
          ip_address: "192.168.1.100",
          os_type: "Windows"
        })
        |> Repo.insert!()

      # Create test events
      base_time = DateTime.utc_now()

      process_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "process_start",
          timestamp: base_time,
          payload: %{
            "pid" => 1234,
            "name" => "malware.exe",
            "path" => "C:\\Temp\\malware.exe",
            "command_line" => "malware.exe --evil",
            "parent_pid" => 100,
            "user" => "SYSTEM",
            "is_elevated" => true
          },
          severity: "high"
        })
        |> Repo.insert!()

      file_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "file_create",
          timestamp: DateTime.add(base_time, 5, :second),
          payload: %{
            "path" => "C:\\Users\\victim\\ransomware.txt",
            "action" => "create",
            "hash" => "abc123",
            "pid" => 1234
          },
          severity: "critical"
        })
        |> Repo.insert!()

      network_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "network_connect",
          timestamp: DateTime.add(base_time, 10, :second),
          payload: %{
            "remote_ip" => "10.0.0.1",
            "remote_port" => 443,
            "protocol" => "tcp",
            "pid" => 1234
          },
          severity: "medium"
        })
        |> Repo.insert!()

      # Create alert
      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "critical",
          title: "Ransomware Detected",
          description: "Suspicious file encryption behavior",
          event_ids: [process_event.id, file_event.id, network_event.id],
          mitre_techniques: ["T1486", "T1059"]
        })
        |> Repo.insert!()

      %{
        agent: agent,
        alert: alert,
        process_event: process_event,
        file_event: file_event,
        network_event: network_event
      }
    end

    test "builds graph from single alert", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      assert is_map(graph)
      assert is_list(graph.nodes)
      assert is_list(graph.edges)
      assert graph.metadata.node_count > 0
      assert graph.metadata.edge_count > 0
    end

    test "includes process nodes", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      process_nodes = Enum.filter(graph.nodes, fn node -> node.type == :process end)
      assert length(process_nodes) > 0

      process_node = Enum.find(process_nodes, fn node -> node.metadata.pid == 1234 end)
      assert process_node
      assert process_node.metadata.name == "malware.exe"
      assert process_node.metadata.is_elevated == true
      assert process_node.suspicious == true
    end

    test "includes file nodes", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      file_nodes = Enum.filter(graph.nodes, fn node -> node.type == :file end)
      assert length(file_nodes) > 0

      file_node = List.first(file_nodes)
      assert file_node.metadata.path =~ "ransomware.txt"
      assert file_node.metadata.hash == "abc123"
    end

    test "includes network nodes", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      network_nodes = Enum.filter(graph.nodes, fn node -> node.type == :network end)
      assert length(network_nodes) > 0

      network_node = List.first(network_nodes)
      assert network_node.metadata.ip == "10.0.0.1"
      assert network_node.metadata.port == 443
    end

    test "includes user nodes", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      user_nodes = Enum.filter(graph.nodes, fn node -> node.type == :user end)
      assert length(user_nodes) > 0

      user_node = List.first(user_nodes)
      assert user_node.metadata.username == "SYSTEM"
    end

    test "includes alert node", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      alert_nodes = Enum.filter(graph.nodes, fn node -> node.type == :alert end)
      assert length(alert_nodes) == 1

      alert_node = List.first(alert_nodes)
      assert alert_node.label == "Ransomware Detected"
      assert alert_node.suspicious == true
      assert alert_node.metadata.severity == "critical"
      assert "T1486" in alert_node.mitre_techniques
    end

    test "creates process-to-file edges", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      file_edges =
        Enum.filter(graph.edges, fn edge ->
          edge.type in [:creates, :writes, :reads, :deletes, :accesses]
        end)

      assert length(file_edges) > 0
    end

    test "creates process-to-network edges", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      network_edges = Enum.filter(graph.edges, fn edge -> edge.type == :connects_to end)
      assert length(network_edges) > 0
    end

    test "creates user-to-process edges", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      user_edges = Enum.filter(graph.edges, fn edge -> edge.type == :executes end)
      assert length(user_edges) > 0
    end

    test "includes timeline data", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id)

      assert graph.timeline.start
      assert graph.timeline.end
      assert DateTime.compare(graph.timeline.start, graph.timeline.end) == :lt
      assert is_list(graph.timeline.buckets)
    end

    test "respects max_nodes option", %{alert: alert} do
      graph = GraphBuilder.build_from_alert(alert.id, max_nodes: 5)

      assert length(graph.nodes) <= 5
    end

    test "filters by time_window", %{alert: alert} do
      # Build with very small time window
      graph = GraphBuilder.build_from_alert(alert.id, time_window: 1)

      # Should still include alert-linked events but may filter others
      assert graph.metadata.node_count > 0
    end

    test "returns empty graph for non-existent alert" do
      graph = GraphBuilder.build_from_alert(Ecto.UUID.generate())

      assert graph.nodes == []
      assert graph.edges == []
      assert graph.metadata.node_count == 0
    end
  end

  describe "build_from_events/1" do
    setup do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-2",
          hostname: "test-host-2",
          ip_address: "192.168.1.101",
          os_type: "Linux"
        })
        |> Repo.insert!()

      start_time = DateTime.utc_now() |> DateTime.add(-3600, :second)
      end_time = DateTime.utc_now()

      # Create events
      events =
        for i <- 1..10 do
          %Event{}
          |> Event.changeset(%{
            agent_id: agent.id,
            event_type: "process_start",
            timestamp: DateTime.add(start_time, i * 60, :second),
            payload: %{
              "pid" => 1000 + i,
              "name" => "proc#{i}",
              "parent_pid" => 1000
            },
            severity: "info"
          })
          |> Repo.insert!()
        end

      %{
        agent: agent,
        events: events,
        start_time: start_time,
        end_time: end_time
      }
    end

    test "builds graph from event range", %{agent: agent, start_time: start_time, end_time: end_time} do
      graph =
        GraphBuilder.build_from_events(
          agent_id: agent.id,
          start_time: start_time,
          end_time: end_time
        )

      assert length(graph.nodes) > 0
      assert graph.metadata.node_count > 0
    end

    test "filters by event_types", %{agent: agent, start_time: start_time, end_time: end_time} do
      graph =
        GraphBuilder.build_from_events(
          agent_id: agent.id,
          start_time: start_time,
          end_time: end_time,
          event_types: ["process_start"]
        )

      # All nodes should be process-related
      process_nodes = Enum.filter(graph.nodes, fn node -> node.type == :process end)
      assert length(process_nodes) > 0
    end
  end

  describe "filter_by_time/3" do
    test "filters graph to time window" do
      # Create a graph with nodes at different times
      base_time = DateTime.utc_now()

      nodes = [
        %{
          id: "node1",
          type: :process,
          label: "proc1",
          timestamp: base_time,
          metadata: %{},
          suspicious: false,
          mitre_techniques: []
        },
        %{
          id: "node2",
          type: :process,
          label: "proc2",
          timestamp: DateTime.add(base_time, 3600, :second),
          metadata: %{},
          suspicious: false,
          mitre_techniques: []
        },
        %{
          id: "node3",
          type: :process,
          label: "proc3",
          timestamp: DateTime.add(base_time, 7200, :second),
          metadata: %{},
          suspicious: false,
          mitre_techniques: []
        }
      ]

      edges = [
        %{
          source: "node1",
          target: "node2",
          type: :spawns,
          label: "spawns",
          timestamp: DateTime.add(base_time, 1800, :second),
          metadata: %{}
        }
      ]

      graph = %{
        nodes: nodes,
        edges: edges,
        timeline: %{
          start: base_time,
          end: DateTime.add(base_time, 7200, :second),
          buckets: []
        },
        metadata: %{}
      }

      # Filter to first 2 hours
      filtered_graph =
        GraphBuilder.filter_by_time(
          graph,
          base_time,
          DateTime.add(base_time, 7200, :second)
        )

      assert length(filtered_graph.nodes) == 3
    end
  end

  describe "export_graphml/1" do
    test "exports graph to GraphML format" do
      graph = %{
        nodes: [
          %{
            id: "node1",
            type: :process,
            label: "test.exe",
            timestamp: DateTime.utc_now(),
            metadata: %{},
            suspicious: true,
            mitre_techniques: ["T1059"]
          }
        ],
        edges: [
          %{
            source: "node1",
            target: "node2",
            type: :spawns,
            label: "spawns",
            timestamp: DateTime.utc_now(),
            metadata: %{}
          }
        ],
        timeline: %{
          start: DateTime.utc_now(),
          end: DateTime.utc_now(),
          buckets: []
        },
        metadata: %{}
      }

      graphml = GraphBuilder.export_graphml(graph)

      assert is_binary(graphml)
      assert graphml =~ "<?xml version=\"1.0\""
      assert graphml =~ "<graphml"
      assert graphml =~ "<node id=\"node1\">"
      assert graphml =~ "<edge"
      assert graphml =~ "test.exe"
    end
  end

  describe "edge cases" do
    test "handles empty event list" do
      graph = GraphBuilder.build_from_alert([])

      assert graph.nodes == []
      assert graph.edges == []
      assert graph.metadata.node_count == 0
    end

    test "handles events with missing fields" do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-3",
          hostname: "test-host-3",
          ip_address: "192.168.1.102",
          os_type: "Windows"
        })
        |> Repo.insert!()

      # Event with minimal payload
      event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "process_start",
          timestamp: DateTime.utc_now(),
          payload: %{"pid" => 999},
          severity: "info"
        })
        |> Repo.insert!()

      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "low",
          title: "Test Alert",
          event_ids: [event.id]
        })
        |> Repo.insert!()

      graph = GraphBuilder.build_from_alert(alert.id)

      # Should still build graph without crashing
      assert is_map(graph)
      assert is_list(graph.nodes)
    end

    test "handles events with atom and string keys" do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-4",
          hostname: "test-host-4",
          ip_address: "192.168.1.103",
          os_type: "Windows"
        })
        |> Repo.insert!()

      # Event with atom keys (from ClickHouse)
      event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "file_create",
          timestamp: DateTime.utc_now(),
          payload: %{
            path: "C:\\test.txt",
            action: "create",
            hash: "hash123",
            pid: 1234
          },
          severity: "info"
        })
        |> Repo.insert!()

      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "low",
          title: "Test Alert",
          event_ids: [event.id]
        })
        |> Repo.insert!()

      graph = GraphBuilder.build_from_alert(alert.id)

      # Should handle both atom and string keys
      file_nodes = Enum.filter(graph.nodes, fn node -> node.type == :file end)
      assert length(file_nodes) > 0
    end
  end

  describe "registry events (Windows)" do
    test "includes registry nodes" do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-win",
          hostname: "win-host",
          ip_address: "192.168.1.200",
          os_type: "Windows"
        })
        |> Repo.insert!()

      reg_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "registry_set",
          timestamp: DateTime.utc_now(),
          payload: %{
            "key" => "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value" => "Malware",
            "action" => "set",
            "pid" => 1234
          },
          severity: "high"
        })
        |> Repo.insert!()

      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "high",
          title: "Persistence Detected",
          event_ids: [reg_event.id]
        })
        |> Repo.insert!()

      graph = GraphBuilder.build_from_alert(alert.id)

      registry_nodes = Enum.filter(graph.nodes, fn node -> node.type == :registry end)
      assert length(registry_nodes) > 0

      reg_node = List.first(registry_nodes)
      assert reg_node.metadata.key =~ "Run"
      assert reg_node.metadata.value == "Malware"
    end
  end

  describe "DNS events" do
    test "includes DNS nodes" do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-dns",
          hostname: "dns-host",
          ip_address: "192.168.1.201",
          os_type: "Linux"
        })
        |> Repo.insert!()

      dns_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "dns_query",
          timestamp: DateTime.utc_now(),
          payload: %{
            "query" => "evil.com",
            "answers" => ["1.2.3.4"],
            "pid" => 5678
          },
          severity: "medium"
        })
        |> Repo.insert!()

      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "medium",
          title: "Suspicious DNS Query",
          event_ids: [dns_event.id]
        })
        |> Repo.insert!()

      graph = GraphBuilder.build_from_alert(alert.id)

      dns_nodes = Enum.filter(graph.nodes, fn node -> node.type == :dns end)
      assert length(dns_nodes) > 0

      dns_node = List.first(dns_nodes)
      assert dns_node.metadata.query == "evil.com"
      assert dns_node.metadata.answers == ["1.2.3.4"]
    end
  end

  describe "module load events" do
    test "includes module nodes" do
      agent =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "test-agent-mod",
          hostname: "mod-host",
          ip_address: "192.168.1.202",
          os_type: "Windows"
        })
        |> Repo.insert!()

      module_event =
        %Event{}
        |> Event.changeset(%{
          agent_id: agent.id,
          event_type: "module_load",
          timestamp: DateTime.utc_now(),
          payload: %{
            "path" => "C:\\Windows\\System32\\evil.dll",
            "hash" => "dll123",
            "pid" => 9999
          },
          severity: "high"
        })
        |> Repo.insert!()

      alert =
        %Alert{}
        |> Alert.changeset(%{
          agent_id: agent.id,
          severity: "high",
          title: "Suspicious DLL Load",
          event_ids: [module_event.id]
        })
        |> Repo.insert!()

      graph = GraphBuilder.build_from_alert(alert.id)

      module_nodes = Enum.filter(graph.nodes, fn node -> node.type == :module end)
      assert length(module_nodes) > 0

      mod_node = List.first(module_nodes)
      assert mod_node.metadata.path =~ "evil.dll"
      assert mod_node.metadata.hash == "dll123"
    end
  end
end
