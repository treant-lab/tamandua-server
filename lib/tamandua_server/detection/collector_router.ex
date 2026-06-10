defmodule TamanduaServer.Detection.CollectorRouter do
  @moduledoc """
  Collector-aware dispatch for detection-side analyzers.

  `EngineWorker` still owns the main event-type pipeline. This router adds the
  missing collector/profile dimension so high-signal collectors can feed their
  specialized analyzers even when an event arrives under a generic event type.
  """

  alias TamanduaServer.Detection.{
    CredentialDetector,
    EtwTamperingHandler,
    IdentityThreats,
    InstallScriptAnalyzer,
    LateralMovement
  }

  @ebpf_collectors ~w(ebpf auditd)
  @script_collectors ~w(amsi script_inspector command_line_dna)
  @credential_collectors ~w(credential_theft dlp clipboard_dlp)
  @identity_collectors ~w(identity ad_monitor)
  @lateral_collectors ~w(lateral_movement network_dpi)
  @endpoint_collectors ~w(endpoint_security)
  @defense_evasion_collectors ~w(etw defense_evasion ntdll_write_monitor syscall_evasion)

  @doc "Run collector-specific analyzers and side-effect engines for an event."
  @spec analyze(map(), map() | nil) :: [map()]
  def analyze(event, context) when is_map(event) do
    collector = context_value(context, :collector) |> normalize_token()
    event_type = context_value(context, :event_type) || event_type(event)

    []
    |> maybe_add(script_analyzer_detections(event), collector in @script_collectors)
    |> maybe_add(
      credential_detections(event),
      collector in @credential_collectors and not credential_event_type?(event_type)
    )
    |> maybe_add(ebpf_auditd_detections(event, collector), collector in @ebpf_collectors)
    |> maybe_add(endpoint_security_detections(event), collector in @endpoint_collectors)
    |> maybe_add(network_dpi_detections(event), collector == "network_dpi")
    |> maybe_add(identity_detections(event), collector in @identity_collectors)
    |> maybe_add(amsi_detections(event), collector == "amsi")
    |> maybe_add(etw_tampering_detection(event), collector in @defense_evasion_collectors)
    |> Enum.map(&normalize_detection(&1, collector))
    |> tap(fn _ -> maybe_route_identity(event, collector, event_type) end)
    |> tap(fn _ -> maybe_route_lateral(event, collector, event_type) end)
  end

  def analyze(_event, _context), do: []

  defp script_analyzer_detections(event) do
    event
    |> script_candidates()
    |> Enum.map(&InstallScriptAnalyzer.analyze_script/1)
    |> Enum.filter(&match?({:suspicious, _}, &1))
    |> Enum.map(fn {:suspicious, result} ->
      %{
        type: :collector_script_behavior,
        rule_name: "Collector Script Inspector: Suspicious command content",
        confidence: result.risk_score,
        description: "Script collector observed suspicious command content",
        matched_patterns: Enum.map(result.patterns, &to_string/1),
        mitre_tactics: ["execution", "defense-evasion"],
        mitre_techniques: ["T1059", "T1027"]
      }
    end)
  end

  defp credential_detections(event) do
    case CredentialDetector.detect_credentials(event) do
      {:ok, detections} -> detections
      _ -> []
    end
  end

  defp ebpf_auditd_detections(event, collector) do
    payload = payload(event)
    type = event_type(event)
    command = command_text(payload)
    path = first_string(payload, [:path, :file_path, :target_path, :exe, :process_path])
    syscall = first_string(payload, [:syscall, :syscall_name, :operation])

    []
    |> maybe_detection(
      %{
        type: :collector_kernel_module_load,
        rule_name: "Collector Kernel Telemetry: Unsigned kernel module load",
        confidence: 0.88,
        description: "#{collector} observed an unsigned or untrusted kernel module load",
        evidence: %{path: path, syscall: syscall},
        mitre_tactics: ["persistence", "privilege-escalation", "defense-evasion"],
        mitre_techniques: ["T1547.006"]
      },
      type in ["kernel_module_load", "module_load"] and suspicious_module_load?(payload, path)
    )
    |> maybe_detection(
      %{
        type: :collector_privilege_escalation,
        rule_name: "Collector Kernel Telemetry: Suspicious setuid permission change",
        confidence: 0.84,
        description: "#{collector} observed setuid permissions applied to a risky path",
        evidence: %{path: path, command_line: command},
        mitre_tactics: ["privilege-escalation"],
        mitre_techniques: ["T1548.001"]
      },
      setuid_change?(payload, command, path)
    )
    |> maybe_detection(
      %{
        type: :collector_process_injection,
        rule_name: "Collector Kernel Telemetry: Process memory access to sensitive target",
        confidence: 0.82,
        description: "#{collector} observed process memory access against a sensitive process",
        evidence: %{
          syscall: syscall,
          source_process: first_string(payload, [:process_name, :comm, :exe]),
          target_process: first_string(payload, [:target_process, :target_process_name])
        },
        mitre_tactics: ["defense-evasion", "credential-access", "privilege-escalation"],
        mitre_techniques: ["T1055", "T1003"]
      },
      memory_access_to_sensitive_process?(payload, syscall)
    )
    |> maybe_add(script_analyzer_detections(event), suspicious_command_line?(command))
  end

  defp endpoint_security_detections(event) do
    payload = payload(event)
    command = command_text(payload)
    target_process = first_string(payload, [:target_process, :target_process_name, :process_name])

    []
    |> maybe_detection(
      %{
        type: :collector_credential_dumping,
        rule_name: "Collector Endpoint Security: LSASS credential access",
        confidence: 0.93,
        description: "Endpoint security telemetry observed LSASS memory access or dump behavior",
        evidence: %{target_process: target_process, command_line: command},
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003.001"]
      },
      lsass_access?(payload, command, target_process)
    )
    |> maybe_detection(
      %{
        type: :collector_endpoint_tampering,
        rule_name: "Collector Endpoint Security: Security control tampering",
        confidence: 0.86,
        description: "Endpoint security telemetry observed tampering with a security control",
        evidence: %{command_line: command, action: first_string(payload, [:action, :operation])},
        mitre_tactics: ["defense-evasion"],
        mitre_techniques: ["T1562.001"]
      },
      security_control_tampering?(payload, command)
    )
    |> maybe_detection(
      %{
        type: :collector_ransomware_behavior,
        rule_name: "Collector Endpoint Security: Ransomware-like file impact",
        confidence: 0.8,
        description:
          "Endpoint security telemetry observed mass file modification or recovery inhibition",
        evidence: %{command_line: command, file_count: value(payload, :file_count)},
        mitre_tactics: ["impact"],
        mitre_techniques: ["T1486", "T1490"]
      },
      ransomware_behavior?(payload, command)
    )
  end

  defp network_dpi_detections(event) do
    payload = payload(event)
    text = payload_text(payload)
    protocol = first_string(payload, [:protocol, :app_protocol, :application])

    port =
      integer_value(
        value(payload, :dest_port) || value(payload, :remote_port) || value(payload, :dst_port)
      )

    []
    |> maybe_detection(
      %{
        type: :collector_lateral_movement,
        rule_name: "Collector Network DPI: Remote admin protocol execution",
        confidence: 0.84,
        description: "Network DPI observed remote administration or service-execution traffic",
        evidence: %{
          protocol: protocol,
          port: port,
          service: first_string(payload, [:service, :rpc_interface])
        },
        mitre_tactics: ["lateral-movement", "execution"],
        mitre_techniques: ["T1021", "T1569.002"]
      },
      remote_admin_traffic?(payload, protocol, port, text)
    )
    |> maybe_detection(
      %{
        type: :collector_dns_tunneling,
        rule_name: "Collector Network DPI: Suspicious DNS tunnel characteristics",
        confidence: 0.78,
        description: "Network DPI observed DNS query characteristics consistent with tunneling",
        evidence: %{query: first_string(payload, [:query, :dns_query, :fqdn])},
        mitre_tactics: ["command-and-control"],
        mitre_techniques: ["T1071.004"]
      },
      dns_tunnel?(payload, protocol)
    )
    |> maybe_detection(
      %{
        type: :collector_c2_beacon,
        rule_name: "Collector Network DPI: Suspicious HTTP beacon",
        confidence: 0.74,
        description: "Network DPI observed HTTP traffic with command-and-control beacon traits",
        evidence: %{
          user_agent: first_string(payload, [:user_agent, :http_user_agent]),
          uri: first_string(payload, [:uri, :url, :path])
        },
        mitre_tactics: ["command-and-control"],
        mitre_techniques: ["T1071.001"]
      },
      http_beacon?(payload, text)
    )
  end

  defp identity_detections(event) do
    payload = payload(event)
    event_id = value(payload, :event_id) || value(payload, :EventID)

    []
    |> maybe_detection(
      %{
        type: :collector_password_spray,
        rule_name: "Collector Identity: Password spray indicators",
        confidence: 0.86,
        description:
          "Identity collector observed clustered failed authentication across accounts",
        evidence: %{
          source_ip: first_string(payload, [:source_ip, :src_ip, :IpAddress]),
          failed_count: value(payload, :failed_count)
        },
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1110.003"]
      },
      password_spray?(payload)
    )
    |> maybe_detection(
      %{
        type: :collector_kerberoasting,
        rule_name: "Collector Identity: Kerberoasting indicators",
        confidence: 0.82,
        description:
          "Identity collector observed service ticket request traits consistent with Kerberoasting",
        evidence: %{
          event_id: event_id,
          service_name: first_string(payload, [:service_name, :ServiceName])
        },
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1558.003"]
      },
      kerberoasting?(payload, event_id)
    )
    |> maybe_detection(
      %{
        type: :collector_dcsync,
        rule_name: "Collector Identity: Directory replication abuse",
        confidence: 0.9,
        description:
          "Identity collector observed directory replication behavior from a non-domain-controller source",
        evidence: %{
          source_ip: first_string(payload, [:source_ip, :src_ip]),
          account: first_string(payload, [:username, :user, :account])
        },
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003.006"]
      },
      dcsync?(payload)
    )
  end

  defp amsi_detections(event) do
    content = command_text(payload(event))

    []
    |> maybe_detection(
      %{
        type: :collector_amsi_bypass,
        rule_name: "Collector AMSI: AMSI bypass content",
        confidence: 0.9,
        description: "AMSI telemetry observed script content attempting to bypass scanning",
        evidence: %{content_preview: String.slice(content, 0, 200)},
        mitre_tactics: ["defense-evasion"],
        mitre_techniques: ["T1562.001", "T1027"]
      },
      amsi_bypass?(content)
    )
  end

  defp etw_tampering_detection(event) do
    type = event_type(event)

    if EtwTamperingHandler.etw_tampering_event?(type) do
      details = EtwTamperingHandler.extract_details(payload(event))

      [
        %{
          type: :collector_defense_evasion,
          rule_name: "Collector Defense Evasion: ETW tampering",
          confidence: 0.92,
          description: "Defense-evasion collector observed ETW or syscall telemetry tampering",
          details: details,
          mitre_tactics: ["defense-evasion"],
          mitre_techniques: ["T1562.006"]
        }
      ]
    else
      etw_payload_detections(event)
    end
  end

  defp etw_payload_detections(event) do
    payload = payload(event)
    command = command_text(payload)

    []
    |> maybe_detection(
      %{
        type: :collector_defense_evasion,
        rule_name: "Collector Defense Evasion: ETW provider disabled",
        confidence: 0.83,
        description:
          "ETW collector observed tracing provider disablement or event session tampering",
        evidence: %{
          provider: first_string(payload, [:provider, :provider_name]),
          command_line: command
        },
        mitre_tactics: ["defense-evasion"],
        mitre_techniques: ["T1562.006"]
      },
      etw_disable?(payload, command)
    )
  end

  defp suspicious_module_load?(payload, path) do
    unsigned? = truthy?(value(payload, :unsigned)) or truthy?(value(payload, :signature_invalid))

    risky_path? =
      path &&
        String.contains?(String.downcase(path), [
          "/tmp/",
          "/dev/shm/",
          "\\temp\\",
          "\\users\\public\\"
        ])

    unsigned? or risky_path?
  end

  defp setuid_change?(payload, command, path) do
    mode = value(payload, :mode) || value(payload, :file_mode) || value(payload, :permissions)

    risky_path? =
      path && String.contains?(String.downcase(path), ["/tmp/", "/dev/shm/", "/var/tmp/"])

    mode_text = normalize_token(mode)

    String.contains?(command, ["chmod +s", "chmod 4", "setuid"]) or
      (String.contains?(mode_text, ["4000", "suid", "setuid"]) and risky_path?)
  end

  defp memory_access_to_sensitive_process?(_payload, syscall) do
    syscall = normalize_token(syscall)

    syscall in ["ptrace", "process_vm_writev", "process_vm_readv"]
  end

  defp suspicious_command_line?(command) do
    String.contains?(command, [
      "curl ",
      "wget ",
      "base64",
      "bash -c",
      "sh -c",
      "python -c",
      "perl -e"
    ])
  end

  defp lsass_access?(_payload, command, target_process) do
    target = normalize_token(target_process)

    String.contains?(target, "lsass") and
      String.contains?(command, ["procdump", "comsvcs.dll", "minidump", "sekurlsa", "rundll32"])
  end

  defp security_control_tampering?(payload, command) do
    action = first_string(payload, [:action, :operation, :event_action]) |> normalize_token()

    product =
      first_string(payload, [:product, :service, :target_service, :process_name])
      |> normalize_token()

    (String.contains?(action, ["disabled", "stopped", "tamper", "excluded"]) and
       String.contains?(product <> " " <> command, [
         "defender",
         "edr",
         "sensor",
         "antivirus",
         "securityhealth",
         "windefend"
       ])) or
      String.contains?(command, [
        "set-mppreference",
        "disableantispyware",
        "add-mppreference -exclusion"
      ])
  end

  defp ransomware_behavior?(payload, command) do
    file_count =
      integer_value(
        value(payload, :file_count) || value(payload, :modified_files) ||
          value(payload, :rename_count)
      )

    extension = first_string(payload, [:extension, :new_extension]) |> normalize_token()

    file_count >= 100 or
      String.contains?(command, [
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "bcdedit /set"
      ]) or
      String.contains?(extension, [".locked", ".encrypted", ".crypt", ".enc"])
  end

  defp remote_admin_traffic?(payload, protocol, port, text) do
    protocol = normalize_token(protocol)

    service =
      first_string(payload, [:service, :rpc_interface, :share, :named_pipe]) |> normalize_token()

    port in [135, 139, 445, 3389, 5985, 5986] or
      protocol in ["smb", "rdp", "winrm", "dcerpc", "wmi"] or
      String.contains?(service <> " " <> text, [
        "admin$",
        "ipc$",
        "svcctl",
        "psexesvc",
        "atsvc",
        "winrm",
        "wmic"
      ])
  end

  defp dns_tunnel?(payload, protocol) do
    query = first_string(payload, [:query, :dns_query, :fqdn, :domain])
    labels = if query, do: String.split(query, "."), else: []
    longest_label = labels |> Enum.map(&String.length/1) |> Enum.max(fn -> 0 end)
    query_count = integer_value(value(payload, :query_count))

    normalize_token(protocol) == "dns" and
      (longest_label >= 45 or query_count >= 50 or Enum.any?(labels, &base64ish?/1))
  end

  defp http_beacon?(payload, text) do
    method = first_string(payload, [:method, :http_method]) |> normalize_token()
    uri = first_string(payload, [:uri, :url, :path]) |> normalize_token()

    interval =
      integer_value(value(payload, :beacon_interval) || value(payload, :interval_seconds))

    (method in ["get", "post"] and
       String.contains?(uri <> " " <> text, ["/gate", "/beacon", "/task", "/checkin"])) or
      interval in 30..300
  end

  defp password_spray?(payload) do
    failed = integer_value(value(payload, :failed_count) || value(payload, :failure_count))

    users =
      integer_value(
        value(payload, :unique_users) || value(payload, :target_user_count) ||
          value(payload, :user_count)
      )

    failed >= 10 and users >= 5
  end

  defp kerberoasting?(payload, event_id) do
    encryption =
      first_string(payload, [:ticket_encryption_type, :TicketEncryptionType, :encryption_type])
      |> normalize_token()

    service = first_string(payload, [:service_name, :ServiceName])
    status = first_string(payload, [:status, :Status]) |> normalize_token()

    to_string(event_id) == "4769" and service not in [nil, "krbtgt"] and
      (String.contains?(encryption, ["0x17", "rc4"]) or status in ["0x0", "success"])
  end

  defp dcsync?(payload) do
    operation =
      first_string(payload, [:operation, :event_action, :access_mask]) |> normalize_token()

    source_role =
      first_string(payload, [:source_role, :src_role, :host_role]) |> normalize_token()

    String.contains?(operation, [
      "drsuapi",
      "replicating directory changes",
      "replication-get-changes",
      "dcsync"
    ]) and
      source_role not in ["domain_controller", "domain controller", "dc"]
  end

  defp amsi_bypass?(content) do
    content = normalize_token(content)

    String.contains?(content, [
      "amsiutils",
      "amsiscanbuffer",
      "amsiinitfailed",
      "system.management.automation.amsi",
      "amsi.dll",
      "patch amsi"
    ])
  end

  defp etw_disable?(payload, command) do
    action = first_string(payload, [:action, :operation]) |> normalize_token()

    provider =
      first_string(payload, [:provider, :provider_name, :target_provider]) |> normalize_token()

    String.contains?(action <> " " <> provider <> " " <> command, [
      "disable provider",
      "event tracing stopped",
      "etweventwrite",
      "nttraceevent",
      "logman stop",
      "wevtutil sl",
      "set-etwtraceprovider"
    ])
  end

  defp normalize_detection(detection, collector) do
    detection
    |> Map.put_new(:collector, collector)
    |> Map.put_new(:rule_name, fallback_rule_name(detection))
    |> Map.put_new(:confidence, fallback_confidence(detection))
    |> Map.put_new(:mitre_tactics, [])
    |> Map.put_new(:mitre_techniques, [])
  end

  defp fallback_rule_name(%{type: type}), do: "Collector Router: #{type}"
  defp fallback_rule_name(_), do: "Collector Router: Payload heuristic"

  defp fallback_confidence(%{severity: "critical"}), do: 0.95
  defp fallback_confidence(%{severity: "high"}), do: 0.85
  defp fallback_confidence(%{severity: "medium"}), do: 0.65
  defp fallback_confidence(_), do: 0.7

  defp maybe_route_identity(event, collector, event_type) do
    if collector in @identity_collectors and not auth_event_type?(event_type) do
      safe_call(fn -> IdentityThreats.analyze_event(event) end, :ok)
    end
  end

  defp maybe_route_lateral(event, collector, event_type) do
    if collector in @lateral_collectors and not lateral_event_type?(event_type) do
      safe_call(fn -> LateralMovement.process_event(event) end, :ok)
    end
  end

  defp script_candidates(event) do
    payload = payload(event)

    [
      value(payload, :command_line),
      value(payload, :cmdline),
      value(payload, :script),
      value(payload, :script_content),
      value(payload, :powershell),
      value(payload, :content)
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.uniq()
  end

  defp maybe_add(detections, extra, true), do: detections ++ extra
  defp maybe_add(detections, _extra, false), do: detections

  defp maybe_detection(detections, detection, true), do: detections ++ [detection]
  defp maybe_detection(detections, _detection, false), do: detections

  defp auth_event_type?(event_type) do
    event_type in ~w(authentication logon auth_event logon_event kerberos_tgt kerberos_tgs account_logon logon_failure directory_replication)
  end

  defp lateral_event_type?(event_type) do
    event_type in ~w(network_connect network_connection network service_create service_created service_install scheduled_task task_create scheduled_task_create wmi_event wmi_exec wmi_process named_pipe pipe_connect)
  end

  defp credential_event_type?(event_type) do
    event_type in ~w(process_create process_creation file_create file_modify file_access)
  end

  defp payload(event) do
    case value(event, :payload) do
      payload when is_map(payload) -> payload
      _ -> %{}
    end
  end

  defp event_type(event), do: value(event, :event_type) |> to_string() |> String.downcase()

  defp context_value(context, key) when is_map(context),
    do: Map.get(context, key) || Map.get(context, to_string(key))

  defp context_value(_context, _key), do: nil

  defp value(map, key) do
    Map.get(map, key) || Map.get(map, to_string(key))
  end

  defp first_string(map, keys) do
    keys
    |> Enum.find_value(fn key ->
      case value(map, key) do
        value when is_binary(value) -> value
        value when is_atom(value) -> Atom.to_string(value)
        value when is_integer(value) -> Integer.to_string(value)
        _ -> nil
      end
    end)
  end

  defp command_text(payload) do
    [
      first_string(payload, [:command_line, :cmdline, :process_command_line]),
      first_string(payload, [:script, :script_content, :content]),
      first_string(payload, [:args, :arguments])
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" ")
    |> String.downcase()
  end

  defp payload_text(payload) do
    payload
    |> flatten_values()
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" ")
    |> String.downcase()
  end

  defp flatten_values(map) when is_map(map),
    do: Enum.flat_map(map, fn {_key, value} -> flatten_values(value) end)

  defp flatten_values(list) when is_list(list), do: Enum.flat_map(list, &flatten_values/1)
  defp flatten_values(value) when is_binary(value), do: [value]
  defp flatten_values(value) when is_atom(value), do: [Atom.to_string(value)]
  defp flatten_values(value) when is_integer(value), do: [Integer.to_string(value)]
  defp flatten_values(_), do: []

  defp normalize_token(value) when is_binary(value),
    do: value |> String.downcase() |> String.trim()

  defp normalize_token(value) when is_atom(value),
    do: value |> Atom.to_string() |> normalize_token()

  defp normalize_token(value) when is_integer(value), do: Integer.to_string(value)
  defp normalize_token(_), do: ""

  defp integer_value(value) when is_integer(value), do: value

  defp integer_value(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, _} -> integer
      :error -> 0
    end
  end

  defp integer_value(_), do: 0

  defp truthy?(value) when value in [true, "true", "1", 1, "yes", "invalid", "unsigned"], do: true
  defp truthy?(_), do: false

  defp base64ish?(label) when is_binary(label) do
    String.length(label) >= 32 and String.match?(label, ~r/^[A-Za-z0-9+_-]+={0,2}$/)
  end

  defp base64ish?(_), do: false

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      :exit, _ -> default
    end
  end
end
