defmodule TamanduaServer.Detection.CollectorCoverage do
  @moduledoc """
  Static collector-to-MITRE ATT&CK coverage matrix.

  This module is intentionally deterministic and data-only for now. It answers
  which collectors can observe specific ATT&CK techniques, the deployment
  profiles that enable those collectors, the expected coverage level, and the
  telemetry requirements needed for that coverage to be valid.
  """

  @type collector :: atom()
  @type profile :: atom()
  @type coverage_level :: :strong | :moderate | :partial
  @type entry :: %{
          required(:collector) => collector(),
          required(:profiles) => [profile()],
          required(:tactic_id) => String.t(),
          required(:tactic) => String.t(),
          required(:technique_id) => String.t(),
          required(:technique) => String.t(),
          required(:coverage_level) => coverage_level(),
          required(:telemetry_requirements) => [atom()],
          optional(:notes) => String.t()
        }

  @profile_order [
    :core,
    :linux,
    :windows,
    :macos,
    :endpoint,
    :server,
    :network,
    :identity,
    :ai_runtime,
    :full
  ]

  @matrix [
    %{
      collector: :process,
      profiles: [:core, :endpoint, :server, :full],
      tactic_id: "TA0002",
      tactic: "Execution",
      technique_id: "T1059",
      technique: "Command and Scripting Interpreter",
      coverage_level: :strong,
      telemetry_requirements: [:process_create, :command_line, :parent_process, :user]
    },
    %{
      collector: :process,
      profiles: [:core, :endpoint, :server, :full],
      tactic_id: "TA0004",
      tactic: "Privilege Escalation",
      technique_id: "T1055",
      technique: "Process Injection",
      coverage_level: :moderate,
      telemetry_requirements: [:process_access, :image_load, :memory_operation, :process_lineage]
    },
    %{
      collector: :file,
      profiles: [:core, :endpoint, :server, :full],
      tactic_id: "TA0003",
      tactic: "Persistence",
      technique_id: "T1547.001",
      technique: "Registry Run Keys / Startup Folder",
      coverage_level: :moderate,
      telemetry_requirements: [:file_write, :path, :process_guid, :user]
    },
    %{
      collector: :registry,
      profiles: [:core, :windows, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1112",
      technique: "Modify Registry",
      coverage_level: :strong,
      telemetry_requirements: [:registry_set, :registry_key, :registry_value, :process_guid]
    },
    %{
      collector: :network,
      profiles: [:core, :endpoint, :server, :network, :full],
      tactic_id: "TA0011",
      tactic: "Command and Control",
      technique_id: "T1071",
      technique: "Application Layer Protocol",
      coverage_level: :moderate,
      telemetry_requirements: [:network_connection, :remote_ip, :remote_port, :process_guid]
    },
    %{
      collector: :dns,
      profiles: [:core, :endpoint, :server, :network, :full],
      tactic_id: "TA0011",
      tactic: "Command and Control",
      technique_id: "T1071.004",
      technique: "DNS",
      coverage_level: :strong,
      telemetry_requirements: [:dns_query, :query_name, :answer, :process_guid]
    },
    %{
      collector: :ebpf,
      profiles: [:linux, :endpoint, :server, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1562.001",
      technique: "Disable or Modify Tools",
      coverage_level: :strong,
      telemetry_requirements: [:syscall, :process_exec, :kernel_event, :capability_change]
    },
    %{
      collector: :ebpf,
      profiles: [:linux, :endpoint, :server, :full],
      tactic_id: "TA0007",
      tactic: "Discovery",
      technique_id: "T1057",
      technique: "Process Discovery",
      coverage_level: :strong,
      telemetry_requirements: [:process_enum, :syscall, :container_context, :process_lineage]
    },
    %{
      collector: :auditd,
      profiles: [:linux, :server, :endpoint, :full],
      tactic_id: "TA0006",
      tactic: "Credential Access",
      technique_id: "T1003.008",
      technique: "/etc/passwd and /etc/shadow",
      coverage_level: :moderate,
      telemetry_requirements: [:audit_rule, :file_read, :path, :auid, :process_exec]
    },
    %{
      collector: :auditd,
      profiles: [:linux, :server, :endpoint, :full],
      tactic_id: "TA0003",
      tactic: "Persistence",
      technique_id: "T1053.003",
      technique: "Cron",
      coverage_level: :moderate,
      telemetry_requirements: [:audit_rule, :file_write, :cron_path, :process_exec, :user]
    },
    %{
      collector: :endpoint_security,
      profiles: [:macos, :endpoint, :full],
      tactic_id: "TA0002",
      tactic: "Execution",
      technique_id: "T1204.002",
      technique: "Malicious File",
      coverage_level: :strong,
      telemetry_requirements: [:es_event, :process_exec, :file_quarantine, :code_signature]
    },
    %{
      collector: :endpoint_security,
      profiles: [:macos, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1553.001",
      technique: "Gatekeeper Bypass",
      coverage_level: :moderate,
      telemetry_requirements: [:es_event, :code_signature, :xattr_change, :file_path]
    },
    %{
      collector: :network_dpi,
      profiles: [:network, :server, :full],
      tactic_id: "TA0011",
      tactic: "Command and Control",
      technique_id: "T1071.001",
      technique: "Web Protocols",
      coverage_level: :strong,
      telemetry_requirements: [:flow, :http_metadata, :tls_fingerprint, :dns_context]
    },
    %{
      collector: :network_dpi,
      profiles: [:network, :server, :full],
      tactic_id: "TA0010",
      tactic: "Exfiltration",
      technique_id: "T1041",
      technique: "Exfiltration Over C2 Channel",
      coverage_level: :moderate,
      telemetry_requirements: [:flow, :bytes_out, :session_duration, :destination_reputation]
    },
    %{
      collector: :identity,
      profiles: [:identity, :windows, :full],
      tactic_id: "TA0001",
      tactic: "Initial Access",
      technique_id: "T1078",
      technique: "Valid Accounts",
      coverage_level: :strong,
      telemetry_requirements: [:authentication, :principal, :source_ip, :mfa_result, :geo_context]
    },
    %{
      collector: :identity,
      profiles: [:identity, :windows, :full],
      tactic_id: "TA0006",
      tactic: "Credential Access",
      technique_id: "T1110",
      technique: "Brute Force",
      coverage_level: :strong,
      telemetry_requirements: [:authentication_failure, :principal, :source_ip, :failure_reason]
    },
    %{
      collector: :amsi,
      profiles: [:windows, :endpoint, :full],
      tactic_id: "TA0002",
      tactic: "Execution",
      technique_id: "T1059.001",
      technique: "PowerShell",
      coverage_level: :strong,
      telemetry_requirements: [:script_content, :amsi_result, :process_guid, :user]
    },
    %{
      collector: :amsi,
      profiles: [:windows, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1027",
      technique: "Obfuscated Files or Information",
      coverage_level: :moderate,
      telemetry_requirements: [:script_content, :decode_signal, :process_guid, :parent_process]
    },
    %{
      collector: :etw,
      profiles: [:windows, :endpoint, :server, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1562.006",
      technique: "Indicator Blocking",
      coverage_level: :strong,
      telemetry_requirements: [:etw_provider, :provider_state, :process_guid, :call_stack]
    },
    %{
      collector: :etw,
      profiles: [:windows, :endpoint, :server, :full],
      tactic_id: "TA0006",
      tactic: "Credential Access",
      technique_id: "T1003.001",
      technique: "LSASS Memory",
      coverage_level: :moderate,
      telemetry_requirements: [:process_access, :target_process, :access_mask, :call_stack]
    },
    %{
      collector: :script_inspector,
      profiles: [:windows, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1140",
      technique: "Deobfuscate/Decode Files or Information",
      coverage_level: :moderate,
      telemetry_requirements: [:script_content, :decoded_payload, :process_guid]
    },
    %{
      collector: :command_line_dna,
      profiles: [:core, :endpoint, :server, :full],
      tactic_id: "TA0002",
      tactic: "Execution",
      technique_id: "T1106",
      technique: "Native API",
      coverage_level: :partial,
      telemetry_requirements: [:command_line, :process_lineage, :binary_metadata]
    },
    %{
      collector: :credential_theft,
      profiles: [:endpoint, :server, :identity, :full],
      tactic_id: "TA0006",
      tactic: "Credential Access",
      technique_id: "T1555",
      technique: "Credentials from Password Stores",
      coverage_level: :moderate,
      telemetry_requirements: [:file_access, :browser_profile_path, :process_guid, :user]
    },
    %{
      collector: :dlp,
      profiles: [:endpoint, :network, :full],
      tactic_id: "TA0009",
      tactic: "Collection",
      technique_id: "T1115",
      technique: "Clipboard Data",
      coverage_level: :partial,
      telemetry_requirements: [:clipboard_event, :sensitive_content_match, :process_guid]
    },
    %{
      collector: :clipboard_dlp,
      profiles: [:endpoint, :full],
      tactic_id: "TA0009",
      tactic: "Collection",
      technique_id: "T1115",
      technique: "Clipboard Data",
      coverage_level: :moderate,
      telemetry_requirements: [:clipboard_event, :content_hash, :process_guid, :user]
    },
    %{
      collector: :ad_monitor,
      profiles: [:identity, :windows, :full],
      tactic_id: "TA0007",
      tactic: "Discovery",
      technique_id: "T1087.002",
      technique: "Domain Account",
      coverage_level: :strong,
      telemetry_requirements: [:directory_query, :principal, :domain_controller, :source_host]
    },
    %{
      collector: :lateral_movement,
      profiles: [:windows, :network, :server, :full],
      tactic_id: "TA0008",
      tactic: "Lateral Movement",
      technique_id: "T1021.002",
      technique: "SMB/Windows Admin Shares",
      coverage_level: :strong,
      telemetry_requirements: [:network_connection, :admin_share, :logon_event, :service_create]
    },
    %{
      collector: :defense_evasion,
      profiles: [:windows, :endpoint, :server, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1562",
      technique: "Impair Defenses",
      coverage_level: :moderate,
      telemetry_requirements: [:service_change, :registry_set, :process_exec, :security_product_state]
    },
    %{
      collector: :ntdll_write_monitor,
      profiles: [:windows, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1562.001",
      technique: "Disable or Modify Tools",
      coverage_level: :strong,
      telemetry_requirements: [:memory_write, :target_module, :process_guid, :call_stack]
    },
    %{
      collector: :syscall_evasion,
      profiles: [:windows, :linux, :endpoint, :full],
      tactic_id: "TA0005",
      tactic: "Defense Evasion",
      technique_id: "T1106",
      technique: "Native API",
      coverage_level: :moderate,
      telemetry_requirements: [:syscall, :process_guid, :call_stack, :binary_metadata]
    }
  ]

  @doc "Returns the full deterministic collector coverage matrix."
  @spec matrix() :: [entry()]
  def matrix do
    Enum.sort_by(@matrix, &sort_key/1)
  end

  @doc "Returns matrix entries for a collector. Accepts atom or string names."
  @spec for_collector(atom() | String.t()) :: [entry()]
  def for_collector(collector) do
    collector = normalize(collector)

    matrix()
    |> Enum.filter(&(&1.collector == collector))
  end

  @doc "Returns matrix entries enabled by a profile. Accepts atom or string names."
  @spec for_profile(atom() | String.t()) :: [entry()]
  def for_profile(profile) do
    profile = normalize(profile)

    matrix()
    |> Enum.filter(&(profile in &1.profiles))
  end

  @doc """
  Summarizes coverage for the requested scope.

  Supported scopes:

    * `:all`
    * a collector atom or string, equivalent to `{:collector, collector}`
    * `{:collector, collector}`
    * `{:profile, profile}`
    * `%{collector: collector}` or `%{"collector" => collector}`
    * `%{profile: profile}` or `%{"profile" => profile}`
  """
  @spec summary(:all | atom() | String.t() | {:collector, term()} | {:profile, term()} | map()) :: map()
  def summary(scope \\ :all) do
    entries =
      case scope do
        :all -> matrix()
        {:collector, collector} -> for_collector(collector)
        {:profile, profile} -> for_profile(profile)
        scope when is_map(scope) -> summary_entries_from_map(scope)
        collector -> for_collector(collector)
      end

    collectors = entries |> Enum.map(& &1.collector) |> Enum.uniq() |> Enum.sort()
    profiles = entries |> Enum.flat_map(& &1.profiles) |> Enum.uniq() |> sort_profiles()
    techniques = entries |> Enum.map(& &1.technique_id) |> Enum.uniq() |> Enum.sort()
    tactics = entries |> Enum.map(& &1.tactic_id) |> Enum.uniq() |> Enum.sort()

    %{
      collectors: collectors,
      collector_count: length(collectors),
      profiles: profiles,
      profile_count: length(profiles),
      tactics: tactics,
      tactic_count: length(tactics),
      techniques: techniques,
      technique_count: length(techniques),
      entry_count: length(entries),
      by_coverage_level: coverage_counts(entries)
    }
  end

  defp summary_entries_from_map(scope) do
    cond do
      Map.has_key?(scope, :collector) -> for_collector(Map.fetch!(scope, :collector))
      Map.has_key?(scope, "collector") -> for_collector(Map.fetch!(scope, "collector"))
      Map.has_key?(scope, :profile) -> for_profile(Map.fetch!(scope, :profile))
      Map.has_key?(scope, "profile") -> for_profile(Map.fetch!(scope, "profile"))
      true -> []
    end
  end

  defp coverage_counts(entries) do
    entries
    |> Enum.frequencies_by(& &1.coverage_level)
    |> Map.merge(%{strong: 0, moderate: 0, partial: 0}, fn _key, count, _default -> count end)
  end

  defp sort_key(entry) do
    {to_string(entry.collector), entry.tactic_id, entry.technique_id}
  end

  defp sort_profiles(profiles) do
    Enum.sort_by(profiles, fn profile ->
      {Enum.find_index(@profile_order, &(&1 == profile)) || length(@profile_order), to_string(profile)}
    end)
  end

  defp normalize(value) when is_atom(value), do: value

  defp normalize(value) when is_binary(value) do
    normalized =
      value
      |> String.trim()
      |> String.downcase()
      |> String.replace("-", "_")

    try do
      String.to_existing_atom(normalized)
    rescue
      ArgumentError -> :unknown
    end
  end
end
