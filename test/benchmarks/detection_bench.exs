defmodule TamanduaServer.Benchmarks.DetectionBench do
  @moduledoc """
  Benchmarks for detection engine performance.

  Run with:
    mix run test/benchmarks/detection_bench.exs
  """

  alias TamanduaServer.Detection.{Engine, Rules, Sigma, Yara}
  alias TamanduaServer.Telemetry.Event

  def run do
    events = generate_events(10_000)
    sigma_rules = load_sigma_rules(100)
    yara_rules = load_yara_rules(50)
    ioc_list = generate_iocs(1000)

    Benchee.run(
      %{
        # Single rule matching
        "sigma_match_single" => fn ->
          event = Enum.random(events)
          Sigma.matches?(Enum.random(sigma_rules), event)
        end,

        # Match against all rules
        "sigma_match_all_rules" => fn ->
          event = Enum.random(events)
          Enum.filter(sigma_rules, &Sigma.matches?(&1, event))
        end,

        # Detection engine full pipeline
        "detection_engine_process" => fn ->
          event = Enum.random(events)
          Engine.process_event(event)
        end,

        # YARA rule compilation
        "yara_compile" => fn ->
          Yara.compile(Enum.random(yara_rules).source)
        end,

        # YARA scanning
        "yara_scan_file" => fn ->
          # Simulate file scanning
          data = :crypto.strong_rand_bytes(1024 * 100)  # 100KB
          Yara.scan_bytes(data, Enum.random(yara_rules))
        end,

        # IOC matching (hash lists)
        "ioc_match_hash" => fn ->
          event = Enum.random(events)
          hash = event.payload["SHA256"]
          MapSet.member?(ioc_list, hash)
        end,

        # IOC matching (IP addresses)
        "ioc_match_ip" => fn ->
          event = Enum.random(events)
          ip = event.payload["RemoteIP"]
          MapSet.member?(ioc_list, ip)
        end,

        # Correlation: Build alert graph
        "correlation_build_graph" => fn ->
          sample_events = Enum.take(events, 100)
          TamanduaServer.Alerts.Correlator.build_graph(sample_events)
        end,

        # Correlation: Find related alerts
        "correlation_find_related" => fn ->
          alert_id = :rand.uniform(1000)
          TamanduaServer.Alerts.Correlator.find_related(alert_id, max_depth: 3)
        end,

        # Behavioral analysis
        "behavioral_analyze_process_chain" => fn ->
          sample_events = Enum.take(events, 50)
          TamanduaServer.Detection.Behavioral.analyze_process_chain(sample_events)
        end,

        # Rule reload performance
        "rules_reload_sigma" => fn ->
          Sigma.reload_rules()
        end,

        # Batch event processing
        "batch_process_100_events" => fn ->
          batch = Enum.take(events, 100)
          Enum.each(batch, &Engine.process_event/1)
        end,

        # Batch event processing (1000)
        "batch_process_1000_events" => fn ->
          batch = Enum.take(events, 1000)
          Enum.each(batch, &Engine.process_event/1)
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [
        {Benchee.Formatters.HTML, file: "benchmarks/output/detection_bench.html"},
        Benchee.Formatters.Console
      ],
      print: [
        configuration: false,
        fast_warning: false
      ]
    )
  end

  # Helper functions

  defp generate_events(count) do
    event_types = [:process_create, :file_create, :network_connect, :registry_set, :dns_query]
    images = [
      "C:\\Windows\\System32\\cmd.exe",
      "C:\\Windows\\System32\\powershell.exe",
      "C:\\Windows\\System32\\notepad.exe",
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "C:\\Users\\analyst\\AppData\\Local\\suspicious.exe"
    ]
    users = ["SYSTEM", "Administrator", "user1", "analyst"]

    Enum.map(1..count, fn i ->
      %Event{
        id: i,
        agent_id: "agent-#{rem(i, 10)}",
        type: Enum.random(event_types),
        timestamp: DateTime.utc_now(),
        payload: %{
          "EventID" => rem(i, 100),
          "Image" => Enum.random(images),
          "CommandLine" => "#{Enum.random(images)} /c #{:rand.uniform(100)}",
          "User" => Enum.random(users),
          "ProcessId" => :rand.uniform(10000),
          "ParentProcessId" => :rand.uniform(10000),
          "SHA256" => generate_hash(),
          "RemoteIP" => generate_ip(),
          "DestinationPort" => :rand.uniform(65535),
          "Protocol" => Enum.random(["tcp", "udp"]),
          "IntegrityLevel" => Enum.random(["Low", "Medium", "High", "System"]),
          "TargetFilename" => "C:\\Users\\test\\file#{i}.txt"
        }
      }
    end)
  end

  defp load_sigma_rules(count) do
    # Generate realistic Sigma rule structures
    Enum.map(1..count, fn i ->
      %{
        id: "rule-#{i}",
        title: "Test Rule #{i}",
        level: Enum.random(["low", "medium", "high", "critical"]),
        detection: %{
          selection: %{
            "Image" => ["*\\cmd.exe", "*\\powershell.exe"],
            "CommandLine" => ["*whoami*", "*net user*"]
          },
          condition: "selection"
        },
        fields: ["Image", "CommandLine", "User"]
      }
    end)
  end

  defp load_yara_rules(count) do
    # Generate YARA rule structures
    Enum.map(1..count, fn i ->
      %{
        id: "yara-rule-#{i}",
        name: "TestRule#{i}",
        source: """
        rule TestRule#{i} {
          strings:
            $s1 = "malicious_string_#{i}"
            $s2 = "suspicious_pattern_#{i}"
          condition:
            any of them
        }
        """
      }
    end)
  end

  defp generate_iocs(count) do
    hashes = Enum.map(1..count, fn _ -> generate_hash() end)
    ips = Enum.map(1..count, fn _ -> generate_ip() end)
    MapSet.new(hashes ++ ips)
  end

  defp generate_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.encode16(case: :lower)
  end

  defp generate_ip do
    "#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}"
  end
end

# Run benchmarks if called directly
if System.argv() == [] do
  TamanduaServer.Benchmarks.DetectionBench.run()
end
