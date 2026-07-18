defmodule TamanduaServer.Mobile.ThreatDetection do
  @moduledoc """
  Mobile-specific threat detection module.

  Provides detection rules for:
  - Jailbreak/root detection (file path indicators, known root apps, SU binary)
  - App-level threats (sideloaded apps, dangerous permissions, cloned apps)
  - Network threats (malicious WiFi, suspicious VPN, MitM indicators)
  - SMS/URL phishing detection (suspicious URLs, known phishing domains, shortened URLs)

  Results are returned as threat reports that can feed into the alert pipeline.
  """

  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Mobile.{Device, MobileApp, DeviceRegistry}

  # Known malicious WiFi SSIDs (honeypots, common attack SSIDs)
  @malicious_wifi_ssids [
    "Free WiFi",
    "Free Public WiFi",
    "XFINITY WiFi",
    "attwifi",
    "Google Starbucks",
    "WiFi Free",
    "linksys",
    "NETGEAR",
    "default",
    "hacker",
    "evil_twin"
  ]

  # Known phishing domains (sample subset)
  @known_phishing_domains [
    "secure-login-update.com",
    "account-verify-now.com",
    "signin-verification.com",
    "update-your-account.com",
    "confirm-identity.com",
    "security-alert-notice.com",
    "password-reset-required.com",
    "unusual-activity-detected.com"
  ]

  # URL shorteners that may hide phishing links
  @url_shorteners [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "rb.gy", "shorturl.at", "cutt.ly", "tiny.cc", "lnkd.in"
  ]

  # Suspicious VPN configuration indicators
  @suspicious_vpn_indicators [
    "transparent_proxy",
    "split_tunnel_disabled",
    "custom_ca_installed",
    "unknown_vpn_provider"
  ]

  # Popular apps frequently cloned by malware
  @popular_clone_targets [
    {"com.whatsapp", "WhatsApp"},
    {"com.facebook.orca", "Messenger"},
    {"com.instagram.android", "Instagram"},
    {"com.google.android.apps.banking", "Banking"},
    {"com.paypal.android.p2pmobile", "PayPal"},
    {"com.venmo", "Venmo"},
    {"com.coinbase.android", "Coinbase"},
    {"com.binance.dev", "Binance"},
    {"com.amazon.mShop.android.shopping", "Amazon"},
    {"org.telegram.messenger", "Telegram"}
  ]

  # Potentially invasive permission combinations that increase privacy risk
  @spyware_permission_combos [
    ["android.permission.CAMERA", "android.permission.INTERNET", "android.permission.SEND_SMS"],
    ["android.permission.RECORD_AUDIO", "android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
    ["android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.READ_CONTACTS"],
    ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
     "android.permission.INTERNET"]
  ]

  # ---------------------------------------------------------------------------
  # Jailbreak / Root Detection
  # ---------------------------------------------------------------------------

  @doc """
  Detects jailbreak (iOS) or root (Android) indicators on a device.

  Checks:
  - Known file paths associated with jailbreak/root tools
  - System partition writability
  - SU binary presence
  - Known root/jailbreak management apps
  """
  @spec detect_jailbreak(Device.t()) :: %{detected: boolean(), indicators: [map()], severity: String.t()}
  def detect_jailbreak(%Device{} = device) do
    indicators = []

    # Check known jailbreak/root paths (reported by agent telemetry)
    path_indicators = check_known_paths(device)
    indicators = indicators ++ path_indicators

    # Check for root/jailbreak management apps
    app_indicators = check_root_apps(device)
    indicators = indicators ++ app_indicators

    # Check device-level flags
    indicators =
      if device.is_jailbroken or device.is_rooted do
        [%{
          type: "device_flag",
          description: "Device flagged as #{if device.is_jailbroken, do: "jailbroken", else: "rooted"}",
          severity: "critical",
          indicator: "device_status_flag"
        } | indicators]
      else
        indicators
      end

    # Check developer mode / USB debugging as potential indicators
    indicators =
      if device.developer_mode_enabled do
        [%{
          type: "developer_mode",
          description: "Developer mode is enabled",
          severity: "medium",
          indicator: "developer_mode_enabled"
        } | indicators]
      else
        indicators
      end

    indicators =
      if device.usb_debugging_enabled do
        [%{
          type: "usb_debugging",
          description: "USB debugging is enabled",
          severity: "medium",
          indicator: "usb_debugging_enabled"
        } | indicators]
      else
        indicators
      end

    detected = length(indicators) > 0

    severity =
      cond do
        Enum.any?(indicators, &(&1.severity == "critical")) -> "critical"
        Enum.any?(indicators, &(&1.severity == "high")) -> "high"
        Enum.any?(indicators, &(&1.severity == "medium")) -> "medium"
        true -> "low"
      end

    %{
      detected: detected,
      indicators: indicators,
      severity: severity,
      check_type: "jailbreak_root",
      device_id: device.id,
      platform: device.platform,
      checked_at: NaiveDateTime.utc_now()
    }
  end

  defp check_known_paths(%Device{platform: "ios"} = device) do
    # Check agent-reported paths against jailbreak indicators
    reported_paths = get_reported_paths(device.id)
    jailbreak_paths = DeviceRegistry.jailbreak_indicators()

    Enum.reduce(jailbreak_paths, [], fn path, acc ->
      if path in reported_paths do
        [%{
          type: "jailbreak_path",
          description: "Known jailbreak path detected: #{path}",
          severity: "critical",
          indicator: path
        } | acc]
      else
        acc
      end
    end)
  end

  defp check_known_paths(%Device{platform: "android"} = device) do
    reported_paths = get_reported_paths(device.id)
    root_paths = DeviceRegistry.root_indicators()

    Enum.reduce(root_paths, [], fn path, acc ->
      if path in reported_paths do
        [%{
          type: "root_path",
          description: "Known root indicator path detected: #{path}",
          severity: "critical",
          indicator: path
        } | acc]
      else
        acc
      end
    end)
  end

  defp check_known_paths(_device), do: []

  defp check_root_apps(device) do
    root_packages = DeviceRegistry.root_app_packages()

    installed_root_apps =
      MobileApp
      |> MobileApp.by_device(device.id)
      |> where([a], a.bundle_id in ^root_packages)
      |> Repo.all()

    Enum.map(installed_root_apps, fn app ->
      %{
        type: "root_management_app",
        description: "Root/jailbreak management app installed: #{app.app_name || app.bundle_id}",
        severity: "critical",
        indicator: app.bundle_id
      }
    end)
  end

  defp get_reported_paths(device_id) do
    # Look for file path indicators from recent device events
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device_id,
        where: e.event_type in ["jailbreak_detected", "root_detected", "tampering_detected"],
        select: e.payload,
        order_by: [desc: e.timestamp],
        limit: 10

    Repo.all(query)
    |> Enum.flat_map(fn payload ->
      case payload do
        %{"paths" => paths} when is_list(paths) -> paths
        %{"path" => path} when is_binary(path) -> [path]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  # ---------------------------------------------------------------------------
  # App Threat Detection
  # ---------------------------------------------------------------------------

  @doc """
  Detects app-level threats on a device.

  Checks:
  - Sideloaded apps (not from official store)
  - Known malicious app signatures
  - Apps with dangerous permission combinations
  - Cloned/repackaged popular apps
  """
  @spec detect_app_threats(Device.t()) :: %{threats: [map()], risk_score: non_neg_integer(), severity: String.t()}
  def detect_app_threats(%Device{} = device) do
    apps = Repo.all(MobileApp.by_device(device.id))
    threats = []

    # Check sideloaded apps
    sideloaded = detect_sideloaded_apps(apps)
    threats = threats ++ sideloaded

    # Check blacklisted / known malicious apps
    blacklisted = detect_blacklisted_apps(apps)
    threats = threats ++ blacklisted

    # Check dangerous permission combinations
    dangerous = detect_dangerous_permissions(apps)
    threats = threats ++ dangerous

    # Check cloned / repackaged apps
    cloned = detect_cloned_apps(apps)
    threats = threats ++ cloned

    risk_score = calculate_app_threat_score(threats)

    severity =
      cond do
        risk_score >= 80 -> "critical"
        risk_score >= 60 -> "high"
        risk_score >= 30 -> "medium"
        risk_score > 0 -> "low"
        true -> "info"
      end

    %{
      threats: threats,
      risk_score: risk_score,
      severity: severity,
      check_type: "app_threats",
      device_id: device.id,
      total_apps: length(apps),
      checked_at: NaiveDateTime.utc_now()
    }
  end

  defp detect_sideloaded_apps(apps) do
    apps
    |> Enum.filter(&(&1.installer == "sideload" and not &1.is_system_app))
    |> Enum.map(fn app ->
      %{
        type: "sideloaded_app",
        description: "Sideloaded app detected: #{app.app_name || app.bundle_id}",
        severity: "medium",
        app_bundle_id: app.bundle_id,
        app_name: app.app_name
      }
    end)
  end

  defp detect_blacklisted_apps(apps) do
    blacklist = DeviceRegistry.blacklisted_apps()

    apps
    |> Enum.filter(&(&1.bundle_id in blacklist))
    |> Enum.map(fn app ->
      %{
        type: "blacklisted_app",
        description: "Known malicious app detected: #{app.app_name || app.bundle_id}",
        severity: "critical",
        app_bundle_id: app.bundle_id,
        app_name: app.app_name
      }
    end)
  end

  defp detect_dangerous_permissions(apps) do
    Enum.flat_map(apps, fn app ->
      if app.is_system_app do
        []
      else
        permissions = app.permissions || []

        matching_combos =
          Enum.filter(@spyware_permission_combos, fn combo ->
            Enum.all?(combo, &(&1 in permissions))
          end)

        if Enum.empty?(matching_combos) do
          []
        else
          [%{
            type: "dangerous_permissions",
            description: "App #{app.app_name || app.bundle_id} has a potentially invasive permission combination",
            severity: "high",
            app_bundle_id: app.bundle_id,
            app_name: app.app_name,
            matched_combos: length(matching_combos)
          }]
        end
      end
    end)
  end

  defp detect_cloned_apps(apps) do
    _bundle_ids = MapSet.new(apps, & &1.bundle_id)

    Enum.flat_map(@popular_clone_targets, fn {original_id, app_name} ->
      # Look for apps with similar bundle IDs but not the original
      clones =
        Enum.filter(apps, fn app ->
          app.bundle_id != original_id and
            not app.is_system_app and
            (String.contains?(app.bundle_id, String.split(original_id, ".") |> List.last()) or
             (app.app_name && String.jaro_distance(app.app_name || "", app_name) > 0.85))
        end)

      Enum.map(clones, fn clone ->
        %{
          type: "cloned_app",
          description: "Possible clone of #{app_name} detected: #{clone.app_name || clone.bundle_id}",
          severity: "high",
          app_bundle_id: clone.bundle_id,
          app_name: clone.app_name,
          original_bundle_id: original_id,
          original_name: app_name
        }
      end)
    end)
  end

  defp calculate_app_threat_score(threats) do
    score =
      Enum.reduce(threats, 0, fn threat, acc ->
        weight = case threat.severity do
          "critical" -> 30
          "high" -> 20
          "medium" -> 10
          "low" -> 5
          _ -> 0
        end
        acc + weight
      end)

    min(100, score)
  end

  # ---------------------------------------------------------------------------
  # Network Threat Detection
  # ---------------------------------------------------------------------------

  @doc """
  Detects network-level threats on a device.

  Checks:
  - Connected to known malicious WiFi SSID
  - VPN profile with suspicious configuration
  - Certificate pinning bypass indicators
  - Man-in-the-middle indicators
  """
  @spec detect_network_threats(Device.t()) :: %{threats: [map()], severity: String.t()}
  def detect_network_threats(%Device{} = device) do
    threats = []

    # Check WiFi threats from recent events
    wifi_threats = check_malicious_wifi(device)
    threats = threats ++ wifi_threats

    # Check VPN threats
    vpn_threats = check_suspicious_vpn(device)
    threats = threats ++ vpn_threats

    # Check certificate pinning bypass
    cert_threats = check_cert_pinning_bypass(device)
    threats = threats ++ cert_threats

    # Check MitM indicators
    mitm_threats = check_mitm_indicators(device)
    threats = threats ++ mitm_threats

    severity =
      cond do
        Enum.any?(threats, &(&1.severity == "critical")) -> "critical"
        Enum.any?(threats, &(&1.severity == "high")) -> "high"
        Enum.any?(threats, &(&1.severity == "medium")) -> "medium"
        length(threats) > 0 -> "low"
        true -> "info"
      end

    %{
      threats: threats,
      severity: severity,
      check_type: "network_threats",
      device_id: device.id,
      checked_at: NaiveDateTime.utc_now()
    }
  end

  defp check_malicious_wifi(device) do
    # Check recent network events for malicious WiFi connections
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: e.event_type in ["suspicious_connection", "malicious_dns_query"],
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: e.payload,
        limit: 50

    events = Repo.all(query)

    events
    |> Enum.flat_map(fn payload ->
      case payload do
        %{"wifi_ssid" => ssid} when is_binary(ssid) ->
          ssid_lower = String.downcase(ssid)
          if Enum.any?(@malicious_wifi_ssids, &(String.downcase(&1) == ssid_lower)) do
            [%{
              type: "malicious_wifi",
              description: "Connected to known suspicious WiFi: #{ssid}",
              severity: "high",
              wifi_ssid: ssid
            }]
          else
            []
          end
        _ -> []
      end
    end)
    |> Enum.uniq_by(& &1[:wifi_ssid])
  end

  defp check_suspicious_vpn(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: e.event_type == "vpn_changed",
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: e.payload,
        limit: 10

    events = Repo.all(query)

    Enum.flat_map(events, fn payload ->
      indicators_found =
        Enum.filter(@suspicious_vpn_indicators, fn indicator ->
          case payload do
            %{"indicators" => indicators} when is_list(indicators) -> indicator in indicators
            %{"type" => type} -> type == indicator
            _ -> false
          end
        end)

      if Enum.empty?(indicators_found) do
        []
      else
        [%{
          type: "suspicious_vpn",
          description: "VPN profile with suspicious configuration detected",
          severity: "high",
          indicators: indicators_found
        }]
      end
    end)
  end

  defp check_cert_pinning_bypass(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: e.event_type == "certificate_pinning_bypass",
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: %{payload: e.payload, app_name: e.app_name, app_bundle_id: e.app_bundle_id},
        limit: 10

    events = Repo.all(query)

    Enum.map(events, fn event ->
      %{
        type: "cert_pinning_bypass",
        description: "Certificate pinning bypass detected" <>
          if(event.app_name, do: " in #{event.app_name}", else: ""),
        severity: "critical",
        app_bundle_id: event.app_bundle_id,
        app_name: event.app_name
      }
    end)
  end

  defp check_mitm_indicators(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: e.event_type == "man_in_the_middle",
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: %{payload: e.payload, remote_address: e.remote_address, domain: e.domain},
        limit: 10

    events = Repo.all(query)

    Enum.map(events, fn event ->
      %{
        type: "mitm_detected",
        description: "Man-in-the-middle attack indicator detected" <>
          if(event.domain, do: " targeting #{event.domain}", else: ""),
        severity: "critical",
        remote_address: event.remote_address,
        domain: event.domain
      }
    end)
  end

  # ---------------------------------------------------------------------------
  # Phishing Detection
  # ---------------------------------------------------------------------------

  @doc """
  Detects SMS and URL phishing threats.

  Checks:
  - Suspicious URLs in SMS messages
  - Known phishing domains
  - Shortened URL expansion
  """
  @spec detect_phishing(Device.t()) :: %{threats: [map()], severity: String.t()}
  def detect_phishing(%Device{} = device) do
    threats = []

    # Check for reported phishing SMS/URLs
    sms_threats = check_phishing_sms(device)
    threats = threats ++ sms_threats

    # Check for known phishing domains in events
    domain_threats = check_phishing_domains(device)
    threats = threats ++ domain_threats

    # Check for shortened URLs
    shortened_threats = check_shortened_urls(device)
    threats = threats ++ shortened_threats

    severity =
      cond do
        Enum.any?(threats, &(&1.severity == "critical")) -> "critical"
        Enum.any?(threats, &(&1.severity == "high")) -> "high"
        length(threats) > 0 -> "medium"
        true -> "info"
      end

    %{
      threats: threats,
      severity: severity,
      check_type: "phishing",
      device_id: device.id,
      checked_at: NaiveDateTime.utc_now()
    }
  end

  defp check_phishing_sms(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: e.event_type in ["phishing_sms_detected", "phishing_url_blocked"],
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400 * 7),
        select: %{payload: e.payload, domain: e.domain, description: e.description},
        order_by: [desc: e.timestamp],
        limit: 50

    events = Repo.all(query)

    Enum.map(events, fn event ->
      %{
        type: "phishing_sms",
        description: event.description || "Phishing SMS/URL detected",
        severity: "high",
        domain: event.domain,
        details: event.payload
      }
    end)
  end

  defp check_phishing_domains(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: not is_nil(e.domain),
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: e.domain,
        limit: 200

    domains = Repo.all(query) |> Enum.uniq()

    Enum.flat_map(domains, fn domain ->
      domain_lower = String.downcase(domain)

      if Enum.any?(@known_phishing_domains, &(String.downcase(&1) == domain_lower)) do
        [%{
          type: "known_phishing_domain",
          description: "Connection to known phishing domain: #{domain}",
          severity: "critical",
          domain: domain
        }]
      else
        []
      end
    end)
  end

  defp check_shortened_urls(device) do
    query =
      from e in TamanduaServer.Mobile.MobileEvent,
        where: e.device_id == ^device.id,
        where: not is_nil(e.domain),
        where: e.timestamp >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -86400),
        select: %{domain: e.domain, payload: e.payload},
        limit: 200

    events = Repo.all(query)

    Enum.flat_map(events, fn event ->
      domain_lower = String.downcase(event.domain || "")

      if Enum.any?(@url_shorteners, &(String.downcase(&1) == domain_lower)) do
        [%{
          type: "shortened_url",
          description: "Shortened URL via #{event.domain} - potential phishing redirect",
          severity: "medium",
          domain: event.domain,
          details: event.payload
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(& &1.domain)
  end

  # ---------------------------------------------------------------------------
  # Full Threat Scan
  # ---------------------------------------------------------------------------

  @doc """
  Runs all threat detection checks on a device and returns a combined report.
  """
  @spec full_scan(Device.t()) :: map()
  def full_scan(%Device{} = device) do
    jailbreak = detect_jailbreak(device)
    app_threats = detect_app_threats(device)
    network_threats = detect_network_threats(device)
    phishing = detect_phishing(device)

    all_threats =
      (jailbreak.indicators |> Enum.map(&Map.put(&1, :category, "jailbreak_root"))) ++
      (app_threats.threats |> Enum.map(&Map.put(&1, :category, "app_threats"))) ++
      (network_threats.threats |> Enum.map(&Map.put(&1, :category, "network_threats"))) ++
      (phishing.threats |> Enum.map(&Map.put(&1, :category, "phishing")))

    overall_severity =
      cond do
        Enum.any?(all_threats, &(&1.severity == "critical")) -> "critical"
        Enum.any?(all_threats, &(&1.severity == "high")) -> "high"
        Enum.any?(all_threats, &(&1.severity == "medium")) -> "medium"
        length(all_threats) > 0 -> "low"
        true -> "info"
      end

    %{
      device_id: device.id,
      platform: device.platform,
      scanned_at: NaiveDateTime.utc_now(),
      overall_severity: overall_severity,
      total_threats: length(all_threats),
      threats: all_threats,
      results: %{
        jailbreak_root: jailbreak,
        app_threats: app_threats,
        network_threats: network_threats,
        phishing: phishing
      }
    }
  end
end
