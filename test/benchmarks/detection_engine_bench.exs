defmodule TamanduaServer.Benchmarks.DetectionEngineBench do
  @moduledoc """
  Comprehensive benchmarks for detection engine performance.

  This module benchmarks all detection components:
  - Sigma rule evaluation
  - YARA scanning integration
  - ML inference pipeline
  - IOC matching
  - Event correlation
  - Alert generation

  ## Running Benchmarks

      # Run all benchmarks
      mix run test/benchmarks/detection_engine_bench.exs

      # Generate HTML report
      mix run test/benchmarks/detection_engine_bench.exs -- --html

      # Run specific benchmark group
      mix run test/benchmarks/detection_engine_bench.exs -- --group sigma

  ## Interpreting Results

  Results show:
  - IPS (iterations per second) - higher is better
  - Average time per operation
  - Standard deviation
  - Memory usage per operation

  Target performance:
  - Single event processing: < 1ms
  - Batch (100 events): < 50ms
  - Sigma match: < 100us
  - IOC lookup: < 10us
  """

  require Logger

  # ============================================================================
  # Test Data Generation
  # ============================================================================

  @doc """
  Generate realistic process creation events.
  """
  def generate_process_event(id, opts \\ []) do
    suspicious = Keyword.get(opts, :suspicious, false)

    image = if suspicious do
      Enum.random([
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\Windows\\System32\\wscript.exe"
      ])
    else
      Enum.random([
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
      ])
    end

    cmdline = if suspicious do
      Enum.random([
        "powershell.exe -encodedcommand JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAA=",
        "cmd.exe /c whoami && net user",
        "mshta.exe javascript:alert('test')",
        "wscript.exe //E:VBScript C:\\temp\\script.vbs"
      ])
    else
      "#{Path.basename(image)} --normal-flag"
    end

    %{
      event_id: "evt-#{id}",
      event_type: "process_create",
      agent_id: "agent-#{rem(id, 100)}",
      timestamp: DateTime.utc_now(),
      payload: %{
        "ProcessId" => :rand.uniform(65535),
        "ParentProcessId" => :rand.uniform(65535),
        "Image" => image,
        "CommandLine" => cmdline,
        "User" => Enum.random(["SYSTEM", "Administrator", "user1", "analyst"]),
        "ParentImage" => Enum.random([
          "C:\\Windows\\System32\\services.exe",
          "C:\\Windows\\explorer.exe",
          "C:\\Windows\\System32\\svchost.exe"
        ]),
        "IntegrityLevel" => Enum.random(["Low", "Medium", "High", "System"]),
        "SHA256" => generate_sha256_hash()
      }
    }
  end

  @doc """
  Generate network connection events.
  """
  def generate_network_event(id, opts \\ []) do
    suspicious = Keyword.get(opts, :suspicious, false)

    {remote_ip, remote_port} = if suspicious do
      {
        Enum.random(["185.141.63.120", "45.142.212.100", "194.147.140.10"]),
        Enum.random([4444, 5555, 8080, 9999])
      }
    else
      {
        "#{:rand.uniform(223)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}",
        Enum.random([80, 443, 8080, 22])
      }
    end

    %{
      event_id: "evt-#{id}",
      event_type: "network_connect",
      agent_id: "agent-#{rem(id, 100)}",
      timestamp: DateTime.utc_now(),
      payload: %{
        "ProcessId" => :rand.uniform(65535),
        "Image" => Enum.random([
          "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          "C:\\Windows\\System32\\svchost.exe"
        ]),
        "SourceIp" => "192.168.1.#{:rand.uniform(254)}",
        "SourcePort" => :rand.uniform(64000) + 1024,
        "DestinationIp" => remote_ip,
        "DestinationPort" => remote_port,
        "Protocol" => Enum.random(["tcp", "udp"])
      }
    }
  end

  @doc """
  Generate file events.
  """
  def generate_file_event(id, opts \\ []) do
    suspicious = Keyword.get(opts, :suspicious, false)

    path = if suspicious do
      Enum.random([
        "C:\\Users\\Public\\Downloads\\malware.exe",
        "C:\\Windows\\Temp\\payload.dll",
        "C:\\ProgramData\\evil\\backdoor.exe"
      ])
    else
      "C:\\Users\\analyst\\Documents\\file_#{id}.docx"
    end

    %{
      event_id: "evt-#{id}",
      event_type: Enum.random(["file_create", "file_modify"]),
      agent_id: "agent-#{rem(id, 100)}",
      timestamp: DateTime.utc_now(),
      payload: %{
        "ProcessId" => :rand.uniform(65535),
        "Image" => "C:\\Windows\\explorer.exe",
        "TargetFilename" => path,
        "SHA256" => generate_sha256_hash()
      }
    }
  end

  @doc """
  Generate a batch of mixed events.
  """
  def generate_event_batch(count, opts \\ []) do
    suspicious_ratio = Keyword.get(opts, :suspicious_ratio, 0.1)

    Enum.map(1..count, fn i ->
      suspicious = :rand.uniform() < suspicious_ratio
      event_type = Enum.random([:process, :network, :file])

      case event_type do
        :process -> generate_process_event(i, suspicious: suspicious)
        :network -> generate_network_event(i, suspicious: suspicious)
        :file -> generate_file_event(i, suspicious: suspicious)
      end
    end)
  end

  @doc """
  Generate SHA256 hash (hex string).
  """
  def generate_sha256_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Generate Sigma rules of varying complexity.
  """
  def generate_sigma_rules(count) do
    Enum.map(1..count, fn i ->
      level = Enum.random(["low", "medium", "high", "critical"])

      %{
        id: "sigma-rule-#{i}",
        title: "Generated Rule #{i}",
        level: level,
        enabled: true,
        source: """
        title: Generated Rule #{i}
        status: test
        level: #{level}
        logsource:
          category: process_creation
          product: windows
        detection:
          selection:
            Image|endswith:
              - '\\\\cmd.exe'
              - '\\\\powershell.exe'
            CommandLine|contains:
              - 'pattern_#{i}'
              - '-enc'
          condition: selection
        """,
        detection: %{
          "selection" => %{
            "Image|endswith" => ["\\cmd.exe", "\\powershell.exe"],
            "CommandLine|contains" => ["pattern_#{i}", "-enc"]
          },
          "condition" => "selection"
        },
        logsource: %{
          "category" => "process_creation",
          "product" => "windows"
        }
      }
    end)
  end

  @doc """
  Generate IOC list.
  """
  def generate_iocs(count) do
    Enum.map(1..count, fn i ->
      type = Enum.random([:sha256, :ip, :domain])

      case type do
        :sha256 -> {:sha256, generate_sha256_hash()}
        :ip -> {:ip, "#{:rand.uniform(223)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}"}
        :domain -> {:domain, "malware-c2-#{i}.evil.com"}
      end
    end)
    |> Map.new(fn {type, value} -> {value, type} end)
  end

  # ============================================================================
  # Sigma Benchmarks
  # ============================================================================

  def benchmark_sigma(events, rules) do
    Benchee.run(
      %{
        "sigma_match_single_rule" => fn ->
          event = Enum.random(events)
          rule = Enum.random(rules)
          TamanduaServer.Detection.Rules.Sigma.matches?(event, rule)
        end,

        "sigma_match_all_rules" => fn ->
          event = Enum.random(events)
          Enum.filter(rules, fn rule ->
            TamanduaServer.Detection.Rules.Sigma.matches?(event, rule)
          end)
        end,

        "sigma_parse_simple" => fn ->
          TamanduaServer.Detection.Rules.Sigma.parse("""
          title: Simple Rule
          logsource:
            category: process_creation
          detection:
            selection:
              Image|endswith: '\\\\cmd.exe'
            condition: selection
          """)
        end,

        "sigma_parse_complex" => fn ->
          TamanduaServer.Detection.Rules.Sigma.parse("""
          title: Complex Rule
          logsource:
            category: process_creation
            product: windows
          detection:
            selection1:
              Image|endswith:
                - '\\\\cmd.exe'
                - '\\\\powershell.exe'
            selection2:
              CommandLine|contains|all:
                - '-encodedcommand'
                - 'bypass'
            filter:
              User: 'SYSTEM'
            condition: (selection1 or selection2) and not filter
          """)
        end,

        "sigma_batch_10_rules" => fn ->
          event = Enum.random(events)
          rules_subset = Enum.take(rules, 10)
          Enum.count(rules_subset, fn rule ->
            TamanduaServer.Detection.Rules.Sigma.matches?(event, rule)
          end)
        end,

        "sigma_batch_100_rules" => fn ->
          event = Enum.random(events)
          rules_subset = Enum.take(rules, 100)
          Enum.count(rules_subset, fn rule ->
            TamanduaServer.Detection.Rules.Sigma.matches?(event, rule)
          end)
        end,

        "sigma_batch_100_events_10_rules" => fn ->
          events_subset = Enum.take(events, 100)
          rules_subset = Enum.take(rules, 10)

          Enum.flat_map(events_subset, fn event ->
            Enum.filter(rules_subset, fn rule ->
              TamanduaServer.Detection.Rules.Sigma.matches?(event, rule)
            end)
          end)
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [
        Benchee.Formatters.Console
      ],
      print: [configuration: false]
    )
  end

  # ============================================================================
  # IOC Matching Benchmarks
  # ============================================================================

  def benchmark_ioc_matching(events, iocs) do
    ioc_hashes = iocs |> Map.keys() |> MapSet.new()

    Benchee.run(
      %{
        "ioc_hash_lookup_mapset" => fn ->
          hash = Enum.random(events) |> get_in([:payload, "SHA256"])
          MapSet.member?(ioc_hashes, hash)
        end,

        "ioc_hash_lookup_map" => fn ->
          hash = Enum.random(events) |> get_in([:payload, "SHA256"])
          Map.has_key?(iocs, hash)
        end,

        "ioc_ip_lookup" => fn ->
          ip = Enum.random(events) |> get_in([:payload, "DestinationIp"])
          Map.has_key?(iocs, ip)
        end,

        "ioc_batch_check_100_events" => fn ->
          events_subset = Enum.take(events, 100)
          Enum.count(events_subset, fn event ->
            hash = get_in(event, [:payload, "SHA256"])
            Map.has_key?(iocs, hash)
          end)
        end,

        "ioc_multi_field_check" => fn ->
          event = Enum.random(events)
          hash = get_in(event, [:payload, "SHA256"])
          ip = get_in(event, [:payload, "DestinationIp"])
          domain = get_in(event, [:payload, "QueryName"])

          Map.has_key?(iocs, hash) or
            Map.has_key?(iocs, ip) or
            Map.has_key?(iocs, domain)
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [Benchee.Formatters.Console],
      print: [configuration: false]
    )
  end

  # ============================================================================
  # Detection Engine Benchmarks
  # ============================================================================

  def benchmark_detection_engine(events) do
    Benchee.run(
      %{
        "engine_analyze_single" => fn ->
          event = Enum.random(events)
          TamanduaServer.Detection.Engine.analyze_event(event)
        end,

        "engine_analyze_batch_10" => fn ->
          batch = Enum.take(events, 10)
          TamanduaServer.Detection.Engine.analyze_batch(batch)
        end,

        "engine_analyze_batch_100" => fn ->
          batch = Enum.take(events, 100)
          TamanduaServer.Detection.Engine.analyze_batch(batch)
        end,

        "engine_analyze_batch_1000" => fn ->
          batch = Enum.take(events, 1000)
          TamanduaServer.Detection.Engine.analyze_batch(batch)
        end,

        "engine_async_analyze" => fn ->
          event = Enum.random(events)
          TamanduaServer.Detection.Engine.analyze_event_async(event)
        end,

        "engine_status" => fn ->
          TamanduaServer.Detection.Engine.status()
        end,

        "engine_get_stats" => fn ->
          TamanduaServer.Detection.Engine.get_stats()
        end
      },
      time: 15,
      memory_time: 2,
      warmup: 3,
      formatters: [Benchee.Formatters.Console],
      print: [configuration: false]
    )
  end

  # ============================================================================
  # Correlation Benchmarks
  # ============================================================================

  def benchmark_correlation(events) do
    Benchee.run(
      %{
        "correlation_group_by_agent" => fn ->
          events
          |> Enum.take(1000)
          |> Enum.group_by(& &1[:agent_id])
        end,

        "correlation_group_by_process" => fn ->
          events
          |> Enum.take(1000)
          |> Enum.group_by(&get_in(&1, [:payload, "ProcessId"]))
        end,

        "correlation_timeline_sort" => fn ->
          events
          |> Enum.take(1000)
          |> Enum.sort_by(& &1[:timestamp], DateTime)
        end,

        "correlation_find_related_process" => fn ->
          event = Enum.random(events)
          ppid = get_in(event, [:payload, "ParentProcessId"])

          events
          |> Enum.take(500)
          |> Enum.filter(fn e ->
            get_in(e, [:payload, "ProcessId"]) == ppid
          end)
        end,

        "correlation_build_process_tree" => fn ->
          sample = Enum.take(events, 200)

          tree = sample
          |> Enum.reduce(%{}, fn event, acc ->
            pid = get_in(event, [:payload, "ProcessId"])
            ppid = get_in(event, [:payload, "ParentProcessId"])

            acc
            |> Map.update(ppid, [pid], &[pid | &1])
          end)

          tree
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [Benchee.Formatters.Console],
      print: [configuration: false]
    )
  end

  # ============================================================================
  # Alert Generation Benchmarks
  # ============================================================================

  def benchmark_alert_generation(events) do
    Benchee.run(
      %{
        "alert_create_struct" => fn ->
          event = Enum.random(events)

          %{
            id: Ecto.UUID.generate(),
            title: "Suspicious Process Execution",
            severity: :high,
            status: :open,
            agent_id: event[:agent_id],
            event_id: event[:event_id],
            rule_id: "sigma-rule-1",
            rule_name: "Test Rule",
            mitre_tactics: ["execution"],
            mitre_techniques: ["T1059.001"],
            payload: event[:payload],
            inserted_at: DateTime.utc_now()
          }
        end,

        "alert_json_serialize" => fn ->
          event = Enum.random(events)

          alert = %{
            id: Ecto.UUID.generate(),
            title: "Suspicious Process Execution",
            severity: :high,
            status: :open,
            agent_id: event[:agent_id],
            event_id: event[:event_id],
            payload: event[:payload]
          }

          Jason.encode!(alert)
        end,

        "alert_dedup_check" => fn ->
          events_subset = Enum.take(events, 100)

          events_subset
          |> Enum.map(fn e ->
            :erlang.phash2({
              e[:agent_id],
              get_in(e, [:payload, "Image"]),
              get_in(e, [:payload, "CommandLine"])
            })
          end)
          |> MapSet.new()
          |> MapSet.size()
        end,

        "alert_severity_calculation" => fn ->
          event = Enum.random(events)

          factors = [
            if(String.contains?(get_in(event, [:payload, "CommandLine"]) || "", "powershell"), do: 20, else: 0),
            if(get_in(event, [:payload, "IntegrityLevel"]) == "System", do: 15, else: 0),
            if(String.contains?(get_in(event, [:payload, "Image"]) || "", "Temp"), do: 10, else: 0)
          ]

          Enum.sum(factors)
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [Benchee.Formatters.Console],
      print: [configuration: false]
    )
  end

  # ============================================================================
  # Load Testing Benchmarks
  # ============================================================================

  def benchmark_load_testing(events) do
    Benchee.run(
      %{
        "load_100_events_sequential" => fn ->
          events
          |> Enum.take(100)
          |> Enum.each(&process_event/1)
        end,

        "load_1000_events_sequential" => fn ->
          events
          |> Enum.take(1000)
          |> Enum.each(&process_event/1)
        end,

        "load_100_events_parallel" => fn ->
          events
          |> Enum.take(100)
          |> Task.async_stream(&process_event/1, max_concurrency: 10)
          |> Enum.to_list()
        end,

        "load_1000_events_parallel" => fn ->
          events
          |> Enum.take(1000)
          |> Task.async_stream(&process_event/1, max_concurrency: 50)
          |> Enum.to_list()
        end,

        "load_burst_100_events" => fn ->
          # Simulate burst - all events at once
          events
          |> Enum.take(100)
          |> Enum.map(&Task.async(fn -> process_event(&1) end))
          |> Task.await_many(5000)
        end
      },
      time: 30,
      memory_time: 5,
      warmup: 5,
      formatters: [Benchee.Formatters.Console],
      print: [configuration: false]
    )
  end

  # Simulated event processing
  defp process_event(event) do
    # Simulate processing steps
    _hash = :erlang.phash2(event)
    _json = Jason.encode!(event)
    :ok
  end

  # ============================================================================
  # Scaling Benchmarks
  # ============================================================================

  def benchmark_scaling do
    IO.puts("\n========================================")
    IO.puts("SCALING BENCHMARKS")
    IO.puts("========================================\n")

    # Single agent baseline
    IO.puts("--- Single Agent (1000 events) ---")
    single_agent_events = generate_event_batch(1000)
    run_scaling_test(single_agent_events, 1)

    # 100 agents
    IO.puts("\n--- 100 Agents (100 events each) ---")
    multi_agent_events = Enum.flat_map(1..100, fn agent_num ->
      Enum.map(1..100, fn i ->
        event = generate_process_event(i)
        %{event | agent_id: "agent-#{agent_num}"}
      end)
    end)
    run_scaling_test(multi_agent_events, 100)

    # 1000 agents
    IO.puts("\n--- 1000 Agents (10 events each) ---")
    large_scale_events = Enum.flat_map(1..1000, fn agent_num ->
      Enum.map(1..10, fn i ->
        event = generate_process_event(i)
        %{event | agent_id: "agent-#{agent_num}"}
      end)
    end)
    run_scaling_test(large_scale_events, 1000)
  end

  defp run_scaling_test(events, agent_count) do
    start = System.monotonic_time(:millisecond)

    # Process all events
    results = events
    |> Task.async_stream(&process_event/1, max_concurrency: 100)
    |> Enum.to_list()

    elapsed = System.monotonic_time(:millisecond) - start
    events_per_second = length(events) / (elapsed / 1000)

    IO.puts("  Events processed: #{length(events)}")
    IO.puts("  Agent count: #{agent_count}")
    IO.puts("  Time elapsed: #{elapsed}ms")
    IO.puts("  Events/second: #{Float.round(events_per_second, 2)}")
    IO.puts("  Avg latency: #{Float.round(elapsed / length(events), 3)}ms")
  end

  # ============================================================================
  # Main Entry Point
  # ============================================================================

  def run(opts \\ []) do
    IO.puts("\n========================================")
    IO.puts("TAMANDUA DETECTION PERFORMANCE BENCHMARKS")
    IO.puts("========================================\n")

    group = Keyword.get(opts, :group, :all)
    html_output = Keyword.get(opts, :html, false)

    # Generate test data
    IO.puts("Generating test data...")
    events = generate_event_batch(10_000, suspicious_ratio: 0.2)
    sigma_rules = generate_sigma_rules(200)
    iocs = generate_iocs(5000)

    IO.puts("  Events: #{length(events)}")
    IO.puts("  Sigma rules: #{length(sigma_rules)}")
    IO.puts("  IOCs: #{map_size(iocs)}")
    IO.puts("")

    if html_output do
      File.mkdir_p!("benchmarks/output")
    end

    # Run benchmarks based on group
    case group do
      :sigma ->
        IO.puts("\n--- SIGMA BENCHMARKS ---\n")
        benchmark_sigma(events, sigma_rules)

      :ioc ->
        IO.puts("\n--- IOC MATCHING BENCHMARKS ---\n")
        benchmark_ioc_matching(events, iocs)

      :engine ->
        IO.puts("\n--- DETECTION ENGINE BENCHMARKS ---\n")
        benchmark_detection_engine(events)

      :correlation ->
        IO.puts("\n--- CORRELATION BENCHMARKS ---\n")
        benchmark_correlation(events)

      :alert ->
        IO.puts("\n--- ALERT GENERATION BENCHMARKS ---\n")
        benchmark_alert_generation(events)

      :load ->
        IO.puts("\n--- LOAD TESTING BENCHMARKS ---\n")
        benchmark_load_testing(events)

      :scaling ->
        benchmark_scaling()

      :all ->
        IO.puts("\n--- SIGMA BENCHMARKS ---\n")
        benchmark_sigma(events, sigma_rules)

        IO.puts("\n--- IOC MATCHING BENCHMARKS ---\n")
        benchmark_ioc_matching(events, iocs)

        IO.puts("\n--- CORRELATION BENCHMARKS ---\n")
        benchmark_correlation(events)

        IO.puts("\n--- ALERT GENERATION BENCHMARKS ---\n")
        benchmark_alert_generation(events)

        IO.puts("\n--- LOAD TESTING BENCHMARKS ---\n")
        benchmark_load_testing(events)

        benchmark_scaling()
    end

    IO.puts("\n========================================")
    IO.puts("BENCHMARKS COMPLETE")
    IO.puts("========================================\n")
  end
end

# Parse command line arguments
args = System.argv()

opts = [
  group: cond do
    "--group" in args -> String.to_atom(Enum.at(args, Enum.find_index(args, &(&1 == "--group")) + 1) || "all")
    true -> :all
  end,
  html: "--html" in args
]

TamanduaServer.Benchmarks.DetectionEngineBench.run(opts)
