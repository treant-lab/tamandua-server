defmodule TamanduaServer.Agents.CollectorCatalog do
  @moduledoc """
  Central catalog of endpoint collector capabilities used by policy validation,
  templates, and UI surfaces.

  The agent remains the source of truth for OS-specific implementation details;
  this catalog is the server-side contract for safe policy authoring.
  """

  @common_collectors ~w(
    process
    file
    network
    dns
    injection
    named_pipes
    usb
    ransomware_canary
    driver_blocklist
    memory
    network_dpi
    network_anomaly
    cloud
    exploit_mitigation
    defense_evasion
    persistence
    script_inspector
    credential_theft
    lateral_movement
    container
    process_hollowing
    scheduled_tasks
    firmware
    clipboard
    browser_protection
    input_capture
    office_email
    ad_monitor
    health
    syscall_evasion
    software_inventory
    ai_discovery
    fim
    dlp
    clipboard_dlp
    network_discovery
    ntdll_write_monitor
  )

  @windows_collectors ~w(identity registry etw amsi lsass wmi clr)
  @linux_collectors ~w(ebpf auditd)
  @macos_collectors ~w(tcc_monitor xpc_monitor endpoint_security sysext_bridge)
  @legacy_aliases %{
    "kernel_events" => "etw",
    "sysmon" => "etw",
    "linux_audit" => "auditd",
    "network_flow" => "network",
    "edr_blinding" => "defense_evasion"
  }

  @profiles ~w(lightweight balanced aggressive server_safe vdi_safe high_value_asset forensic_burst)

  def common_collectors, do: @common_collectors
  def windows_collectors, do: @windows_collectors
  def linux_collectors, do: @linux_collectors
  def macos_collectors, do: @macos_collectors
  def profiles, do: @profiles

  def all_collectors do
    (@common_collectors ++ @windows_collectors ++ @linux_collectors ++ @macos_collectors)
    |> Enum.uniq()
  end

  def normalize_collector(name) do
    normalized =
      name
      |> to_string()
      |> String.trim()
      |> String.downcase()
      |> String.replace("-", "_")

    Map.get(@legacy_aliases, normalized, normalized)
  end

  def valid_collector?(name), do: normalize_collector(name) in all_collectors()

  def valid_profile?(profile) do
    profile
    |> to_string()
    |> String.trim()
    |> String.downcase()
    |> String.replace("-", "_")
    |> then(&(&1 in @profiles))
  end

  def collector_metadata do
    %{
      common: @common_collectors,
      windows: @windows_collectors,
      linux: @linux_collectors,
      macos: @macos_collectors,
      aliases: @legacy_aliases,
      profiles: @profiles
    }
  end

  def default_template("lightweight"), do: profile_template("lightweight")
  def default_template("balanced"), do: profile_template("balanced")
  def default_template("aggressive"), do: profile_template("aggressive")
  def default_template("performance"), do: profile_template("lightweight")
  def default_template("baseline"), do: profile_template("balanced")
  def default_template("high_security"), do: profile_template("high_value_asset")
  def default_template("forensics"), do: profile_template("forensic_burst")
  def default_template("server_safe"), do: profile_template("server_safe")
  def default_template("vdi_safe"), do: profile_template("vdi_safe")
  def default_template("high_value_asset"), do: profile_template("high_value_asset")
  def default_template("forensic_burst"), do: profile_template("forensic_burst")
  def default_template(_), do: profile_template("balanced")

  def profile_template(profile) do
    case profile do
      "lightweight" ->
        base_policy("lightweight", 5, %{
          process: 15_000,
          file: 30_000,
          network: 10_000,
          dns: 5_000,
          registry: 30_000,
          health: 60_000
        })

      "aggressive" ->
        base_policy("aggressive", 20, %{
          process: 3_000,
          file: 5_000,
          network: 2_000,
          dns: 1_000,
          registry: 5_000,
          memory: 60_000,
          network_dpi: 5_000,
          etw: 1_000,
          amsi: 1_000,
          health: 30_000
        })

      "server_safe" ->
        base_policy("server_safe", 10, %{
          process: 10_000,
          file: 30_000,
          network: 5_000,
          dns: 3_000,
          persistence: 60_000,
          scheduled_tasks: 60_000,
          health: 60_000
        })

      "vdi_safe" ->
        base_policy("vdi_safe", 4, %{
          process: 20_000,
          file: 60_000,
          network: 15_000,
          dns: 10_000,
          health: 60_000
        })

      "high_value_asset" ->
        base_policy("high_value_asset", 20, %{
          process: 3_000,
          file: 5_000,
          network: 2_000,
          dns: 1_000,
          registry: 5_000,
          memory: 60_000,
          injection: 10_000,
          credential_theft: 10_000,
          lateral_movement: 10_000,
          defense_evasion: 10_000,
          etw: 1_000,
          ebpf: 1_000,
          health: 30_000
        })

      "forensic_burst" ->
        base_policy("forensic_burst", 30, %{
          process: 2_000,
          file: 3_000,
          network: 1_000,
          dns: 1_000,
          memory: 30_000,
          injection: 5_000,
          network_dpi: 2_000,
          credential_theft: 5_000,
          lateral_movement: 5_000,
          defense_evasion: 5_000,
          exploit_mitigation: 5_000,
          health: 15_000
        })

      _ ->
        base_policy("balanced", 15, %{
          process: 5_000,
          file: 15_000,
          network: 3_000,
          dns: 2_000,
          registry: 10_000,
          persistence: 60_000,
          fim: 60_000,
          health: 60_000
        })
    end
  end

  defp base_policy(profile, max_cpu, collectors) do
    %{
      "profile" => profile,
      "collectors" =>
        Map.new(collectors, fn {collector, interval_ms} ->
          {Atom.to_string(collector), %{"enabled" => true, "interval_ms" => interval_ms}}
        end),
      "resource_limits" => %{
        "max_cpu_percent" => max_cpu,
        "max_memory_mb" => 768,
        "max_disk_mb" => 2_048
      },
      "detection" => %{
        "yara_enabled" => profile not in ["lightweight", "vdi_safe"],
        "sigma_enabled" => true,
        "ml_enabled" => profile in ["balanced", "aggressive", "high_value_asset", "forensic_burst"]
      },
      "response" => %{
        "allowed_actions" => ["isolate", "kill_process", "quarantine", "restore_file"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 10
      },
      "rollout" => %{
        "strategy" => "phased",
        "health_gates" => default_health_gates(profile)
      }
    }
  end

  defp default_health_gates(profile) do
    %{
      "max_failure_rate_percent" => if(profile == "forensic_burst", do: 20, else: 10),
      "max_agent_cpu_percent" => if(profile in ["aggressive", "forensic_burst"], do: 30, else: 20),
      "max_offline_rate_percent" => 5,
      "min_success_rate_percent" => if(profile == "forensic_burst", do: 80, else: 90)
    }
  end
end
