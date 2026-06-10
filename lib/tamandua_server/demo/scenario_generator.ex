defmodule TamanduaServer.Demo.ScenarioGenerator do
  @moduledoc """
  Generates synthetic telemetry events for demo/hackathon purposes.

  Each scenario creates a realistic detection event that will trigger
  the full detection -> alert -> attestation pipeline.

  ## Supported Scenarios

  - `browser_credential_theft` - MITRE T1555.003 (Credentials from Web Browsers)
  - `session_hijack` - MITRE T1539 (Steal Web Session Cookie)
  - `lumma_like` - Infostealer pattern with C2 callback

  ## Usage

      {:ok, event} = ScenarioGenerator.generate_event("browser_credential_theft")
      {:ok, result} = Detection.Engine.analyze_event(event)
  """

  @scenarios %{
    "browser_credential_theft" => &__MODULE__.browser_credential_theft/1,
    "session_hijack" => &__MODULE__.session_hijack/1,
    "lumma_like" => &__MODULE__.lumma_like/1
  }

  @doc """
  List all available demo scenarios.
  """
  @spec available_scenarios() :: [String.t()]
  def available_scenarios do
    Map.keys(@scenarios)
  end

  @doc """
  Generate a synthetic telemetry event for the given scenario.

  ## Options

  - `:agent_id` - Agent ID (default: generates demo UUID)
  - `:organization_id` - Organization ID (default: generates demo UUID)
  - `:severity` - Override severity (default: scenario-specific)
  - `:timestamp` - Event timestamp (default: now)

  ## Returns

  - `{:ok, event}` - Generated event map
  - `{:error, :invalid_scenario}` - Unknown scenario name
  """
  @spec generate_event(String.t(), keyword()) :: {:ok, map()} | {:error, :invalid_scenario}
  def generate_event(scenario, opts \\ []) do
    case Map.get(@scenarios, scenario) do
      nil -> {:error, :invalid_scenario}
      generator ->
        event = generator.(opts)
        {:ok, event}
    end
  end

  @doc """
  Generate an alert directly (bypasses detection engine).

  Returns attrs suitable for `Alerts.create_alert/1`.
  """
  @spec generate_alert_attrs(String.t(), keyword()) :: {:ok, map()} | {:error, :invalid_scenario}
  def generate_alert_attrs(scenario, opts \\ []) do
    case generate_event(scenario, opts) do
      {:ok, event} ->
        attrs = build_alert_attrs(scenario, event, opts)
        {:ok, attrs}

      error ->
        error
    end
  end

  # ── Scenario: Browser Credential Theft ─────────────────────────────

  @doc false
  def browser_credential_theft(opts) do
    agent_id = Keyword.get(opts, :agent_id, demo_uuid())
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    %{
      event_id: demo_uuid(),
      event_type: "process_file_access",
      agent_id: agent_id,
      organization_id: Keyword.get(opts, :organization_id, demo_uuid()),
      timestamp: timestamp,
      payload: %{
        # Process info
        process_name: "stealer.exe",
        process_path: "C:\\Users\\demo\\AppData\\Local\\Temp\\stealer.exe",
        pid: 4532 + :rand.uniform(1000),
        ppid: 1024 + :rand.uniform(500),
        parent_name: "cmd.exe",
        parent_path: "C:\\Windows\\System32\\cmd.exe",
        command_line: "stealer.exe --mode=browsers --output=c2.evil.com",
        user: "demo-user",
        is_elevated: false,

        # File access (browser credential DB)
        file_path: "C:\\Users\\demo\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        file_operation: "read",
        file_hash_sha256: generate_demo_hash("chrome_login_data"),

        # Network callback
        remote_ip: "185.220.101.42",
        remote_port: 443,
        domain: "c2.evil.com",

        # Detection context
        mitre_technique: "T1555.003",
        mitre_tactic: "credential-access",
        detection_source: "sigma",
        rule_id: "demo_browser_credential_theft_001",
        rule_name: "Browser Credential Theft via Login Data Access"
      }
    }
  end

  # ── Scenario: Session Hijack ───────────────────────────────────────

  @doc false
  def session_hijack(opts) do
    agent_id = Keyword.get(opts, :agent_id, demo_uuid())
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    %{
      event_id: demo_uuid(),
      event_type: "process_file_access",
      agent_id: agent_id,
      organization_id: Keyword.get(opts, :organization_id, demo_uuid()),
      timestamp: timestamp,
      payload: %{
        # Process info
        process_name: "cookie_stealer.exe",
        process_path: "C:\\Users\\demo\\Downloads\\cookie_stealer.exe",
        pid: 5678 + :rand.uniform(1000),
        ppid: 2048 + :rand.uniform(500),
        parent_name: "explorer.exe",
        parent_path: "C:\\Windows\\explorer.exe",
        command_line: "cookie_stealer.exe --target=all_browsers",
        user: "demo-user",
        is_elevated: false,

        # File access (browser cookies)
        file_path: "C:\\Users\\demo\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        file_operation: "read",
        file_hash_sha256: generate_demo_hash("chrome_cookies"),

        # Additional accessed files
        accessed_files: [
          "C:\\Users\\demo\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
          "C:\\Users\\demo\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\demo\\cookies.sqlite"
        ],

        # Network exfiltration
        remote_ip: "91.92.251.39",
        remote_port: 8443,
        domain: "exfil.malware-host.net",
        url: "https://exfil.malware-host.net/upload",

        # Detection context
        mitre_technique: "T1539",
        mitre_tactic: "credential-access",
        detection_source: "sigma",
        rule_id: "demo_session_hijack_001",
        rule_name: "Session Cookie Theft Detection"
      }
    }
  end

  # ── Scenario: Lumma-like Infostealer ───────────────────────────────

  @doc false
  def lumma_like(opts) do
    agent_id = Keyword.get(opts, :agent_id, demo_uuid())
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    %{
      event_id: demo_uuid(),
      event_type: "process_network_behavior",
      agent_id: agent_id,
      organization_id: Keyword.get(opts, :organization_id, demo_uuid()),
      timestamp: timestamp,
      payload: %{
        # Process info (mimics Lumma stealer behavior)
        process_name: "RuntimeBroker.exe",
        process_path: "C:\\Users\\demo\\AppData\\Roaming\\RuntimeBroker.exe",
        pid: 7890 + :rand.uniform(1000),
        ppid: 3456 + :rand.uniform(500),
        parent_name: "powershell.exe",
        parent_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line: "RuntimeBroker.exe",
        user: "demo-user",
        is_elevated: false,

        # Fake legitimate name in wrong location (common stealer technique)
        file_hash_sha256: generate_demo_hash("lumma_payload"),
        file_signed: false,

        # C2 communication pattern
        remote_ip: "45.142.212.100",
        remote_port: 443,
        domain: "lumma-c2-demo.xyz",
        url: "https://lumma-c2-demo.xyz/api/gate.php",

        # Exfiltrated data indicators
        data_exfil_size_bytes: 524_288,
        connection_count: 15,

        # Browser credential access trail
        accessed_sensitive_files: [
          %{path: "C:\\Users\\demo\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", hash: generate_demo_hash("login_data")},
          %{path: "C:\\Users\\demo\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", hash: generate_demo_hash("cookies")},
          %{path: "C:\\Users\\demo\\AppData\\Roaming\\discord\\Local Storage\\leveldb", hash: generate_demo_hash("discord")}
        ],

        # Crypto wallet access
        crypto_wallet_access: [
          "C:\\Users\\demo\\AppData\\Roaming\\Exodus\\exodus.wallet",
          "C:\\Users\\demo\\AppData\\Local\\Coinbase\\wallet"
        ],

        # Detection context
        mitre_technique: "T1555.003",
        mitre_tactic: "credential-access",
        threat_class: "infostealer",
        malware_family: "Lumma",
        detection_source: "behavioral",
        rule_id: "demo_lumma_stealer_001",
        rule_name: "Lumma Infostealer Behavioral Pattern"
      }
    }
  end

  # ── Alert Attribute Builder ────────────────────────────────────────

  defp build_alert_attrs(scenario, event, opts) do
    payload = event.payload
    severity = Keyword.get(opts, :severity) || default_severity(scenario)
    rule_author_pubkey = Keyword.get(opts, :rule_author_pubkey)

    %{
      title: alert_title(scenario),
      description: alert_description(scenario, payload),
      severity: severity,
      status: "new",
      agent_id: event.agent_id,
      organization_id: event.organization_id,
      source_event_id: event.event_id,
      mitre_techniques: [payload[:mitre_technique] || payload["mitre_technique"]],
      mitre_tactics: [payload[:mitre_tactic] || payload["mitre_tactic"]],
      threat_score: severity_to_score(severity),
      raw_event: payload,
      detection_metadata: %{
        rule_id: payload[:rule_id] || payload["rule_id"],
        rule_name: payload[:rule_name] || payload["rule_name"],
        detection_source: payload[:detection_source] || payload["detection_source"],
        mitre_technique: payload[:mitre_technique] || payload["mitre_technique"],
        threat_class: payload[:threat_class] || "endpoint_threat",
        malware_family: payload[:malware_family],
        demo: true
      },
      evidence: %{
        process: %{
          name: payload[:process_name],
          path: payload[:process_path],
          pid: payload[:pid],
          ppid: payload[:ppid],
          parent_name: payload[:parent_name],
          command_line: payload[:command_line]
        },
        file: %{
          path: payload[:file_path],
          operation: payload[:file_operation],
          hash_sha256: payload[:file_hash_sha256]
        },
        network: %{
          remote_ip: payload[:remote_ip],
          remote_port: payload[:remote_port],
          domain: payload[:domain],
          url: payload[:url]
        },
        indicators: build_indicators(payload)
      },
      enrichment: %{
        indicators: build_indicators(payload),
        threat_intel: %{
          source: "demo",
          confidence: 0.95
        }
      },
      rule_author_pubkey: rule_author_pubkey
    }
  end

  defp build_indicators(payload) do
    indicators = []

    # Add hash if present
    indicators = if hash = payload[:file_hash_sha256] do
      [%{type: "hash_sha256", value: hash, source: "demo"} | indicators]
    else
      indicators
    end

    # Add domain if present and public
    indicators = if domain = payload[:domain] do
      [%{type: "domain", value: domain, source: "demo"} | indicators]
    else
      indicators
    end

    # Add public IP if present
    indicators = if ip = payload[:remote_ip] do
      [%{type: "ip", value: ip, source: "demo"} | indicators]
    else
      indicators
    end

    # Add URL if present
    indicators = if url = payload[:url] do
      [%{type: "url", value: url, source: "demo"} | indicators]
    else
      indicators
    end

    indicators
  end

  defp alert_title("browser_credential_theft"), do: "Demo: Browser Credential Theft Detected"
  defp alert_title("session_hijack"), do: "Demo: Session Cookie Hijack Detected"
  defp alert_title("lumma_like"), do: "Demo: Lumma-like Infostealer Activity"
  defp alert_title(_), do: "Demo: Security Incident Detected"

  defp alert_description("browser_credential_theft", payload) do
    """
    Detected unauthorized access to browser credential storage.
    Process #{payload[:process_name]} (PID: #{payload[:pid]}) accessed Chrome Login Data.
    Network callback to #{payload[:domain]} observed.
    MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)
    """
  end

  defp alert_description("session_hijack", payload) do
    """
    Detected session cookie theft attempt across multiple browsers.
    Process #{payload[:process_name]} accessed browser cookie databases.
    Data exfiltration to #{payload[:domain]} detected.
    MITRE ATT&CK: T1539 (Steal Web Session Cookie)
    """
  end

  defp alert_description("lumma_like", payload) do
    """
    Behavioral pattern matches Lumma infostealer family.
    Fake system process (#{payload[:process_name]}) in user directory.
    Accessed browser credentials, Discord tokens, and crypto wallets.
    C2 communication to #{payload[:domain]}.
    MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)
    """
  end

  defp alert_description(_, _), do: "Demo security incident for hackathon demonstration."

  defp default_severity("browser_credential_theft"), do: "high"
  defp default_severity("session_hijack"), do: "high"
  defp default_severity("lumma_like"), do: "critical"
  defp default_severity(_), do: "medium"

  defp severity_to_score("critical"), do: 95.0
  defp severity_to_score("high"), do: 80.0
  defp severity_to_score("medium"), do: 60.0
  defp severity_to_score("low"), do: 40.0
  defp severity_to_score("info"), do: 20.0
  defp severity_to_score(_), do: 60.0

  # ── Helpers ────────────────────────────────────────────────────────

  defp demo_uuid do
    UUID.uuid4()
  end

  defp generate_demo_hash(seed) do
    :crypto.hash(:sha256, "demo:#{seed}:#{System.system_time(:nanosecond)}")
    |> Base.encode16(case: :lower)
  end
end
