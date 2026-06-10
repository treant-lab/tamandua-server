defmodule TamanduaServer.Detection.MockEventGenerator do
  @moduledoc """
  Mock event generator for detection rule testing.

  Generates synthetic telemetry events for testing Sigma and YARA rules.
  Supports:
  - Event templates by type (process, file, network, registry, DNS)
  - Randomization (timestamps, hosts, users, IPs)
  - Bulk event generation
  - Realistic data generation

  ## Usage

      # Generate from template
      event = MockEventGenerator.generate_from_template(%{
        type: "process_create",
        data: %{
          path: "C:\\\\Windows\\\\System32\\\\cmd.exe",
          cmdline: "cmd.exe /c whoami"
        }
      })

      # Generate random event
      event = MockEventGenerator.generate_random(:process_create)

      # Generate bulk events
      events = MockEventGenerator.generate_bulk(:network_connect, 100)
  """

  @doc """
  Generate an event from a template.

  Template format:
      %{
        type: "process_create",
        os_type: "windows",
        data: %{
          path: "C:\\\\mimikatz.exe",
          cmdline: "sekurlsa::logonpasswords",
          ...
        }
      }
  """
  @spec generate_from_template(map()) :: map()
  def generate_from_template(template) do
    event_type = template["type"] || template[:type] || "process_create"
    os_type = template["os_type"] || template[:os_type] || "windows"
    data = template["data"] || template[:data] || %{}

    base_event = %{
      "event_id" => generate_uuid(),
      "event_type" => event_type,
      "timestamp" => template["timestamp"] || DateTime.utc_now() |> DateTime.to_iso8601(),
      "agent_id" => template["agent_id"] || generate_uuid(),
      "hostname" => template["hostname"] || random_hostname(),
      "os_type" => os_type,
      "payload" => merge_with_defaults(event_type, data, os_type)
    }

    base_event
  end

  @doc """
  Generate a random event of the specified type.
  """
  @spec generate_random(atom() | String.t(), keyword()) :: map()
  def generate_random(event_type, opts \\ []) do
    os_type = Keyword.get(opts, :os_type, "windows")

    template = %{
      "type" => to_string(event_type),
      "os_type" => os_type,
      "data" => random_payload(event_type, os_type)
    }

    generate_from_template(template)
  end

  @doc """
  Generate multiple random events.
  """
  @spec generate_bulk(atom() | String.t(), integer(), keyword()) :: [map()]
  def generate_bulk(event_type, count, opts \\ []) do
    Enum.map(1..count, fn _ ->
      generate_random(event_type, opts)
    end)
  end

  @doc """
  Generate events for a complete attack chain.

  ## Example

      events = MockEventGenerator.generate_attack_chain(:credential_theft)
      # Returns sequence: powershell -> mimikatz -> lsass access -> network exfil
  """
  @spec generate_attack_chain(atom()) :: [map()]
  def generate_attack_chain(chain_type) do
    case chain_type do
      :credential_theft ->
        [
          generate_random(:process_create, data: %{"path" => "C:\\Windows\\System32\\powershell.exe"}),
          generate_random(:process_create, data: %{"path" => "C:\\Tools\\mimikatz.exe", "cmdline" => "sekurlsa::logonpasswords"}),
          generate_random(:process_access, data: %{"target_path" => "C:\\Windows\\System32\\lsass.exe"}),
          generate_random(:network_connect, data: %{"remote_ip" => "10.0.0.1", "remote_port" => 443})
        ]

      :ransomware ->
        [
          generate_random(:process_create, data: %{"cmdline" => "vssadmin delete shadows /all /quiet"}),
          generate_random(:file_delete, data: %{"path" => "C:\\System Volume Information\\"}),
          generate_random(:file_create, data: %{"path" => "C:\\Users\\user\\Documents\\README_RANSOM.txt"}),
          generate_random(:network_connect, data: %{"remote_ip" => "185.220.101.1", "remote_port" => 9050})
        ]

      :lateral_movement ->
        [
          generate_random(:network_connect, data: %{"remote_ip" => "10.0.0.50", "remote_port" => 445}),
          generate_random(:process_create, data: %{"path" => "C:\\Windows\\System32\\net.exe", "cmdline" => "net use \\\\10.0.0.50\\C$"}),
          generate_random(:file_create, data: %{"path" => "\\\\10.0.0.50\\C$\\Windows\\Temp\\payload.exe"}),
          generate_random(:process_create, data: %{"cmdline" => "sc \\\\10.0.0.50 create evil binPath= C:\\Windows\\Temp\\payload.exe"})
        ]

      _ ->
        []
    end
  end

  # ── Private Functions ──────────────────────────────────────────────

  defp merge_with_defaults(event_type, custom_data, os_type) do
    defaults = default_payload(event_type, os_type)

    # Convert string keys to atom keys for merging
    custom_atom_data =
      Enum.map(custom_data, fn {k, v} ->
        {if(is_binary(k), do: String.to_atom(k), else: k), v}
      end)
      |> Map.new()

    Map.merge(defaults, custom_atom_data)
  end

  defp default_payload("process_create", "windows") do
    %{
      path: "C:\\Windows\\System32\\svchost.exe",
      cmdline: "svchost.exe -k netsvcs",
      parent_path: "C:\\Windows\\System32\\services.exe",
      parent_cmdline: "services.exe",
      user: "NT AUTHORITY\\SYSTEM",
      pid: :rand.uniform(10000),
      ppid: :rand.uniform(1000),
      integrity_level: "System",
      sha256: random_sha256(),
      is_elevated: true,
      is_signed: true,
      signer: "Microsoft Corporation"
    }
  end

  defp default_payload("process_create", "linux") do
    %{
      path: "/usr/bin/bash",
      cmdline: "bash",
      parent_path: "/usr/bin/bash",
      parent_cmdline: "bash",
      user: "root",
      pid: :rand.uniform(10000),
      ppid: :rand.uniform(1000),
      sha256: random_sha256(),
      is_elevated: true
    }
  end

  defp default_payload("file_create", "windows") do
    %{
      path: "C:\\Users\\#{random_username()}\\Documents\\document.txt",
      sha256: random_sha256(),
      size: :rand.uniform(1_000_000),
      process_path: "C:\\Windows\\System32\\notepad.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("file_modify", "windows") do
    %{
      path: "C:\\Users\\#{random_username()}\\Documents\\document.txt",
      sha256: random_sha256(),
      old_sha256: random_sha256(),
      size: :rand.uniform(1_000_000),
      process_path: "C:\\Windows\\System32\\notepad.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("file_delete", "windows") do
    %{
      path: "C:\\Users\\#{random_username()}\\Documents\\temp.txt",
      process_path: "C:\\Windows\\explorer.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("network_connect", "windows") do
    %{
      local_ip: "192.168.1.#{:rand.uniform(254)}",
      local_port: :rand.uniform(65535),
      remote_ip: random_ip(),
      remote_port: Enum.random([80, 443, 8080, 8443]),
      protocol: "tcp",
      process_path: "C:\\Windows\\System32\\svchost.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("network_listen", "windows") do
    %{
      local_ip: "0.0.0.0",
      local_port: Enum.random([80, 443, 3389, 445, 135]),
      protocol: "tcp",
      process_path: "C:\\Windows\\System32\\svchost.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("dns_query", _os_type) do
    %{
      query_name: Enum.random(["google.com", "microsoft.com", "example.com", "malicious-domain.xyz"]),
      query_type: Enum.random(["A", "AAAA", "CNAME", "MX", "TXT"]),
      response: random_ip(),
      process_path: "C:\\Windows\\System32\\svchost.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("registry_set", "windows") do
    %{
      key_path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      value_name: "Update",
      value_data: "C:\\Windows\\System32\\update.exe",
      value_type: "REG_SZ",
      process_path: "C:\\Windows\\System32\\reg.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("registry_create", "windows") do
    %{
      key_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      value_name: "Startup",
      value_data: "C:\\Users\\Public\\startup.exe",
      value_type: "REG_SZ",
      process_path: "C:\\Windows\\regedit.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload("registry_delete", "windows") do
    %{
      key_path: "HKLM\\Software\\Policies\\Microsoft\\Windows Defender",
      value_name: "DisableAntiSpyware",
      process_path: "C:\\Windows\\System32\\reg.exe",
      process_pid: :rand.uniform(10000)
    }
  end

  defp default_payload(_event_type, _os_type) do
    %{}
  end

  defp random_payload("process_create", os_type) do
    case os_type do
      "windows" ->
        %{
          path: Enum.random([
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\powershell.exe",
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
          ]),
          cmdline: Enum.random([
            "cmd.exe /c dir",
            "powershell.exe -Command Get-Process",
            "notepad.exe document.txt"
          ]),
          user: Enum.random(["NT AUTHORITY\\SYSTEM", "WORKSTATION\\Administrator", "WORKSTATION\\user"])
        }

      "linux" ->
        %{
          path: Enum.random(["/bin/bash", "/usr/bin/python3", "/usr/bin/curl", "/usr/bin/wget"]),
          cmdline: Enum.random(["bash -c ls", "python3 script.py", "curl https://example.com"]),
          user: Enum.random(["root", "user", "www-data"])
        }

      _ ->
        %{}
    end
  end

  defp random_payload("network_connect", _os_type) do
    %{
      remote_ip: random_ip(),
      remote_port: Enum.random([80, 443, 8080, 4444, 1234]),
      protocol: "tcp"
    }
  end

  defp random_payload("dns_query", _os_type) do
    %{
      query_name: Enum.random([
        "google.com",
        "facebook.com",
        "evil-c2-server.xyz",
        "malware-download.com",
        "phishing-site.net"
      ]),
      query_type: Enum.random(["A", "AAAA", "CNAME"])
    }
  end

  defp random_payload(_event_type, _os_type), do: %{}

  defp generate_uuid do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
    |> String.slice(0..35)
  end

  defp random_hostname do
    "WORKSTATION-#{:rand.uniform(9999)}"
  end

  defp random_username do
    Enum.random(["Administrator", "user", "admin", "john.doe", "jane.smith"])
  end

  defp random_ip do
    "#{:rand.uniform(254)}.#{:rand.uniform(254)}.#{:rand.uniform(254)}.#{:rand.uniform(254)}"
  end

  defp random_sha256 do
    :crypto.strong_rand_bytes(32)
    |> Base.encode16(case: :lower)
  end
end
