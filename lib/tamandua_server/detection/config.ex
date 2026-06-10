defmodule TamanduaServer.Detection.Config do
  @moduledoc """
  Centralized detection configuration.

  All thresholds are configurable at runtime via Application env.
  Configuration is read from `:tamandua_server, :detection` keyword list
  and can be overridden at runtime without restarts.

  ## Example config

      config :tamandua_server, :detection,
        threat_threshold: 0.7,
        critical_threshold: 0.9,
        entropy_threshold: 3.5
  """

  alias TamanduaServer.Detection.ThresholdConfig

  # ============================================================================
  # Generic accessor
  # ============================================================================

  @doc "Read a detection config key with an optional default."
  @spec get(atom(), term()) :: term()
  def get(key, default \\ nil) do
    Application.get_env(:tamandua_server, :detection, [])
    |> Keyword.get(key, default)
  end

  # ============================================================================
  # Engine thresholds
  # ============================================================================

  # Prefer the preset-overlaid ETS value (ThresholdConfig); fall back to App-env.
  # Wrapped in try/rescue because ThresholdConfig's ETS table may not exist in
  # minimal/test boots — never let a threshold read crash the detection path.
  defp effective(category, key, app_env_key, default) do
    ThresholdConfig.get(category, key, get(app_env_key, default))
  rescue
    ArgumentError -> get(app_env_key, default)
  end

  @doc "Minimum threat score (0.0-1.0) to create an alert."
  def threat_threshold, do: effective(:scores, :threat_alert_threshold, :threat_threshold, 0.75)

  @doc "Minimum threat score (0.0-1.0) to trigger automatic response."
  def critical_threshold, do: effective(:scores, :threat_critical_threshold, :critical_threshold, 0.9)

  # ============================================================================
  # Behavioral thresholds
  # ============================================================================

  @doc "Shannon entropy above which a domain label is considered DGA-like."
  def entropy_threshold, do: get(:entropy_threshold, 4.0)

  @doc "Number of queries to a single parent domain before flagging beaconing."
  def beaconing_query_threshold, do: get(:beaconing_query_threshold, 100)

  @doc "Time window (ms) for beaconing frequency analysis."
  def beaconing_window_ms, do: get(:beaconing_window_ms, :timer.minutes(5))

  @doc "Number of file operations in the rapid-ops window that triggers an alert."
  def rapid_file_ops_threshold, do: get(:rapid_file_ops_threshold, 50)

  @doc "Time window (seconds) for rapid file operation detection."
  def rapid_file_ops_window_seconds, do: get(:rapid_file_ops_window_seconds, 10)

  @doc "Z-score standard deviation threshold for statistical anomaly."
  def z_score_threshold, do: get(:z_score_threshold, 3.0)

  @doc "Risk score (0-100) at or above which an anomaly generates an alert."
  def risk_score_alert_threshold, do: effective(:scores, :risk_alert_threshold, :risk_score_alert_threshold, 75)

  @doc "Baseline persistence interval (ms) for writing profiles to DB."
  def baseline_persist_interval, do: get(:baseline_persist_interval, :timer.minutes(5))

  @doc "Baseline recalculation interval (ms)."
  def baseline_update_interval, do: get(:baseline_update_interval, :timer.hours(1))

  @doc "Large data transfer threshold in bytes."
  def large_transfer_bytes, do: get(:large_transfer_bytes, 500_000_000)

  @doc "Impossible travel speed threshold in km/h."
  def impossible_travel_speed_kmh, do: get(:impossible_travel_speed_kmh, 500)

  # ============================================================================
  # Correlator thresholds
  # ============================================================================

  @doc "TTL (ms) for events in correlation ETS tables."
  def event_ttl, do: get(:event_ttl, :timer.hours(1))

  @doc "Cleanup interval (ms) for expired correlation events."
  def cleanup_interval, do: get(:cleanup_interval, :timer.minutes(5))

  @doc "Number of endpoints with same credential before flagging lateral movement."
  def lateral_movement_threshold, do: get(:lateral_movement_threshold, 3)

  # ============================================================================
  # Agent thresholds
  # ============================================================================

  @doc "Time (ms) before an agent heartbeat is considered late."
  def heartbeat_timeout, do: get(:heartbeat_timeout, :timer.seconds(60))

  @doc "Time (ms) after which a pending command is considered stale."
  def command_stale_timeout, do: get(:command_stale_timeout, :timer.seconds(45))

  @doc "Time (ms) after last heartbeat before agent is marked offline."
  def offline_threshold, do: get(:offline_threshold, :timer.seconds(90))

  # ============================================================================
  # DNS thresholds
  # ============================================================================

  @doc "TLDs commonly associated with malicious infrastructure."
  def suspicious_tlds do
    get(:suspicious_tlds, ~w(.tk .ml .ga .cf .gq .xyz .top .buzz .club))
  end

  @doc "Domain suffixes excluded from DNS analysis."
  def safe_domains do
    get(:safe_domains, [
      ".microsoft.com", ".windows.com", ".windowsupdate.com", ".msftncsi.com",
      ".office.com", ".live.com", ".bing.com", ".azure.com",
      ".googleapis.com", ".gstatic.com", ".google.com",
      ".amazon.com", ".amazonaws.com", ".cloudflare.com", ".cloudfront.net",
      ".akamaiedge.net", ".akadns.net", ".github.com", ".github.io"
    ])
  end

  @doc "Exfiltration subdomain threshold."
  def exfil_subdomain_threshold, do: get(:exfil_subdomain_threshold, 30)

  @doc "Exfiltration analysis window (ms)."
  def exfil_window_ms, do: get(:exfil_window_ms, :timer.minutes(5))

  @doc "DNS label length (chars) above which to flag."
  def long_label_threshold, do: get(:long_label_threshold, 20)

  @doc "Exfiltration label length threshold (chars)."
  def exfil_label_threshold, do: get(:exfil_label_threshold, 30)

  @doc "DNS data TTL in ETS (ms)."
  def dns_data_ttl, do: get(:dns_data_ttl, :timer.minutes(15))

  @doc "DNS cleanup interval (ms)."
  def dns_cleanup_interval, do: get(:dns_cleanup_interval, :timer.minutes(2))

  # ============================================================================
  # Suspicious network ports
  # ============================================================================

  @doc "Ports commonly used by C2 frameworks and backdoors."
  def suspicious_ports do
    get(:suspicious_ports, [4444, 5555, 6666, 31337, 8080])
  end

  # ============================================================================
  # C2 Detection thresholds
  # ============================================================================

  @doc "Entropy threshold above which a domain is considered DGA-like for HTTPS C2."
  def c2_dga_entropy_threshold, do: get(:c2_dga_entropy_threshold, 4.0)

  @doc "Minimum confidence sum to create a C2 alert."
  def c2_alert_threshold, do: get(:c2_alert_threshold, 0.7)

  @doc "Time window (ms) for connection frequency analysis."
  def c2_frequency_window_ms, do: get(:c2_frequency_window_ms, 300_000)

  @doc "Number of connections in window to flag as high frequency."
  def c2_high_frequency_threshold, do: get(:c2_high_frequency_threshold, 30)

  @doc "Cleanup interval (ms) for expired C2 patterns."
  def c2_cleanup_interval_ms, do: get(:c2_cleanup_interval_ms, :timer.minutes(5))

  @doc "TTL (seconds) for C2 pattern data in ETS."
  def c2_pattern_ttl_seconds, do: get(:c2_pattern_ttl_seconds, 3600)

  # ============================================================================
  # C2 Beaconing Detection thresholds
  # ============================================================================

  @doc "Minimum number of connections to consider for beaconing analysis."
  def c2_beacon_min_samples, do: get(:c2_beacon_min_samples, 5)

  @doc "Minimum time span (seconds) that connections must cover to trigger beacon analysis."
  def c2_beacon_min_span_seconds, do: get(:c2_beacon_min_span_seconds, 600)

  # ============================================================================
  # C2 Composite Scoring thresholds
  # ============================================================================

  @doc "Composite score threshold (0.0-1.0) to create a multi-signal C2 alert."
  def c2_composite_alert_threshold, do: get(:c2_composite_alert_threshold, 0.6)

  @doc "Weight for beaconing signal in composite C2 score."
  def c2_beacon_signal_weight, do: get(:c2_beacon_signal_weight, 0.4)

  @doc "Weight for DNS anomaly signal in composite C2 score."
  def c2_dns_signal_weight, do: get(:c2_dns_signal_weight, 0.3)

  @doc "Weight for JA3/JA4 fingerprint signal in composite C2 score."
  def c2_ja3_signal_weight, do: get(:c2_ja3_signal_weight, 0.3)

  # ============================================================================
  # DNS Tunneling Detection thresholds
  # ============================================================================

  @doc "Shannon entropy threshold (bits/char) above which DNS subdomain is flagged (normal ~2.5, suspicious >3.5)."
  def c2_dns_tunnel_entropy_threshold, do: get(:c2_dns_tunnel_entropy_threshold, 3.5)

  @doc "Subdomain label length (chars) above which to flag as potential tunneling."
  def c2_dns_tunnel_long_label_chars, do: get(:c2_dns_tunnel_long_label_chars, 24)

  @doc "Number of DNS queries per window to a single domain to flag as potential tunneling."
  def c2_dns_tunnel_volume_threshold, do: get(:c2_dns_tunnel_volume_threshold, 50)

  @doc "Time window (ms) for DNS query volume analysis."
  def c2_dns_tunnel_volume_window_ms, do: get(:c2_dns_tunnel_volume_window_ms, 60_000)

  @doc "Minimum confidence sum to create a DNS tunneling alert."
  def c2_dns_tunnel_alert_threshold, do: get(:c2_dns_tunnel_alert_threshold, 0.7)

  @doc "TTL (seconds) for DNS tunnel tracking data in ETS."
  def c2_dns_tunnel_ttl_seconds, do: get(:c2_dns_tunnel_ttl_seconds, 86_400)

  # ============================================================================
  # Severity mapping
  # ============================================================================

  @doc """
  Map a numeric threat score (0.0-1.0) to a severity string.
  Thresholds are read from config at call time.
  """
  @spec severity_from_score(number()) :: String.t()
  def severity_from_score(score) do
    cond do
      score >= critical_threshold() -> "critical"
      score >= threat_threshold() -> "high"
      score >= 0.5 -> "medium"
      true -> "low"
    end
  end

  @doc """
  Map a risk score (0-100) to a severity string.
  """
  @spec severity_from_risk(number()) :: String.t()
  def severity_from_risk(risk) do
    cond do
      risk >= 90 -> "critical"
      risk >= 75 -> "high"
      risk >= 50 -> "medium"
      true -> "low"
    end
  end
end
