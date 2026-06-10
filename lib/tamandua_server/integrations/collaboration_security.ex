defmodule TamanduaServer.Integrations.CollaborationSecurity do
  @moduledoc """
  Collaboration Security Monitoring Module

  Provides security monitoring for collaboration platforms:
  - Microsoft Teams
  - Slack
  - Zoom

  Features:
  - File sharing risk detection
  - External user access tracking
  - Sensitive data detection in messages (PII, credentials)
  - Malicious link detection in chats
  - OAuth app risk assessment
  - Risk scoring for collaboration events

  ENTERPRISE FEATURE: Requires API credentials for each platform.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  # Scanning intervals
  @scan_interval_ms 60_000
  @url_check_timeout_ms 5_000

  # Risk thresholds
  @high_risk_threshold 70
  @medium_risk_threshold 40

  # PII patterns for sensitive data detection
  @pii_patterns [
    {:ssn, ~r/\b\d{3}-\d{2}-\d{4}\b/},
    {:credit_card, ~r/\b(?:\d{4}[-\s]?){3}\d{4}\b/},
    {:email, ~r/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/},
    {:phone, ~r/\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/},
    {:ip_address, ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/},
    {:api_key, ~r/\b(?:api[_-]?key|apikey|api_secret)[=:\s]+['"]?[A-Za-z0-9_\-]{20,}['"]?\b/i},
    {:aws_key, ~r/\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/},
    {:private_key, ~r/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/},
    {:password, ~r/\b(?:password|passwd|pwd)[=:\s]+['"]?[^\s'"]{6,}['"]?\b/i},
    {:bearer_token, ~r/\bBearer\s+[A-Za-z0-9_\-\.]+\b/i}
  ]

  # Known malicious URL patterns
  @malicious_url_patterns [
    ~r/bit\.ly\/[a-zA-Z0-9]+/,
    ~r/tinyurl\.com\/[a-zA-Z0-9]+/,
    ~r/t\.co\/[a-zA-Z0-9]+/,
    ~r/\.ru\/[a-zA-Z0-9]+\.exe$/i,
    ~r/\.cn\/[a-zA-Z0-9]+\.exe$/i,
    ~r/\.(exe|scr|bat|cmd|ps1|vbs|js)$/i
  ]

  # High-risk file extensions
  @risky_file_extensions [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".dll", ".com", ".pif", ".application", ".gadget",
    ".hta", ".cpl", ".msc", ".wsf", ".lnk", ".scf"
  ]

  # Platform configurations
  defmodule PlatformConfig do
    @moduledoc "Configuration for a collaboration platform"
    defstruct [
      :id,
      :platform,          # :teams, :slack, :zoom
      :enabled,
      :tenant_id,         # For Teams
      :client_id,
      :client_secret,
      :access_token,
      :refresh_token,
      :token_expires_at,
      :webhook_url,       # For incoming webhooks
      :scopes,
      :last_sync,
      :sync_cursor
    ]
  end

  # Collaboration event
  defmodule CollabEvent do
    @moduledoc "Represents a collaboration platform event"
    defstruct [
      :id,
      :platform,
      :event_type,        # :message, :file_share, :user_join, :app_install, :meeting
      :timestamp,
      :user_id,
      :user_email,
      :user_name,
      :channel_id,
      :channel_name,
      :content,
      :file_info,
      :urls,
      :external_users,
      :risk_score,
      :risk_factors,
      :raw_data
    ]
  end

  # External sharing policy
  defmodule SharingPolicy do
    @moduledoc "External sharing policy configuration"
    defstruct [
      :id,
      :name,
      :enabled,
      :allowed_domains,       # Allowlist of external domains
      :blocked_domains,       # Blocklist of external domains
      :allow_external_users,
      :allow_guest_access,
      :require_approval,
      :max_external_shares_per_day,
      :block_sensitive_files,
      :notify_on_external_share
    ]
  end

  # OAuth app assessment
  defmodule OAuthApp do
    @moduledoc "OAuth app information for risk assessment"
    defstruct [
      :id,
      :name,
      :platform,
      :publisher,
      :permissions,
      :installed_by,
      :installed_at,
      :risk_score,
      :risk_factors,
      :approved,
      :last_used
    ]
  end

  # State
  defstruct [
    :platforms,         # %{id => PlatformConfig}
    :policies,          # %{id => SharingPolicy}
    :oauth_apps,        # %{id => OAuthApp}
    :url_reputation_cache,
    :recent_events,     # List of recent CollabEvents for analysis
    :stats
  ]

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add a collaboration platform integration.
  """
  def add_platform(config) do
    GenServer.call(__MODULE__, {:add_platform, config})
  end

  @doc """
  Remove a collaboration platform integration.
  """
  def remove_platform(id) do
    GenServer.call(__MODULE__, {:remove_platform, id})
  end

  @doc """
  List all configured platforms.
  """
  def list_platforms do
    GenServer.call(__MODULE__, :list_platforms)
  end

  @doc """
  Process an incoming webhook event from a collaboration platform.
  """
  def process_webhook(platform, payload) do
    GenServer.cast(__MODULE__, {:process_webhook, platform, payload})
  end

  @doc """
  Scan content for sensitive data.
  """
  def scan_content(content) when is_binary(content) do
    GenServer.call(__MODULE__, {:scan_content, content})
  end

  @doc """
  Check URL reputation.
  """
  def check_url(url) when is_binary(url) do
    GenServer.call(__MODULE__, {:check_url, url}, @url_check_timeout_ms + 1000)
  end

  @doc """
  Add or update a sharing policy.
  """
  def set_policy(policy) do
    GenServer.call(__MODULE__, {:set_policy, policy})
  end

  @doc """
  Get sharing policies.
  """
  def get_policies do
    GenServer.call(__MODULE__, :get_policies)
  end

  @doc """
  Assess OAuth app risk.
  """
  def assess_oauth_app(app_info) do
    GenServer.call(__MODULE__, {:assess_oauth_app, app_info})
  end

  @doc """
  List installed OAuth apps with risk scores.
  """
  def list_oauth_apps do
    GenServer.call(__MODULE__, :list_oauth_apps)
  end

  @doc """
  Get collaboration security statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Trigger a manual sync for a platform.
  """
  def sync_platform(platform_id) do
    GenServer.cast(__MODULE__, {:sync_platform, platform_id})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Collaboration Security Monitor")

    # Schedule periodic scans
    schedule_scan()

    state = %__MODULE__{
      platforms: load_platforms(),
      policies: load_policies(),
      oauth_apps: %{},
      url_reputation_cache: %{},
      recent_events: [],
      stats: %{
        events_processed: 0,
        sensitive_data_detections: 0,
        malicious_urls_blocked: 0,
        external_shares_detected: 0,
        risky_files_blocked: 0,
        oauth_apps_assessed: 0,
        last_scan: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:add_platform, config}, _from, state) do
    platform_config = %PlatformConfig{
      id: config[:id] || generate_id(),
      platform: config[:platform],
      enabled: config[:enabled] != false,
      tenant_id: config[:tenant_id],
      client_id: config[:client_id],
      client_secret: config[:client_secret],
      access_token: config[:access_token],
      refresh_token: config[:refresh_token],
      token_expires_at: config[:token_expires_at],
      webhook_url: config[:webhook_url],
      scopes: config[:scopes] || [],
      last_sync: nil,
      sync_cursor: nil
    }

    new_platforms = Map.put(state.platforms, platform_config.id, platform_config)
    save_platforms(new_platforms)

    Logger.info("Added collaboration platform: #{platform_config.platform}")
    {:reply, {:ok, platform_config}, %{state | platforms: new_platforms}}
  end

  @impl true
  def handle_call({:remove_platform, id}, _from, state) do
    new_platforms = Map.delete(state.platforms, id)
    save_platforms(new_platforms)

    {:reply, :ok, %{state | platforms: new_platforms}}
  end

  @impl true
  def handle_call(:list_platforms, _from, state) do
    platforms = state.platforms
      |> Map.values()
      |> Enum.map(&sanitize_platform_config/1)

    {:reply, {:ok, platforms}, state}
  end

  @impl true
  def handle_call({:scan_content, content}, _from, state) do
    findings = detect_sensitive_data(content)
    {:reply, {:ok, findings}, state}
  end

  @impl true
  def handle_call({:check_url, url}, _from, state) do
    {result, new_cache} = check_url_reputation(url, state.url_reputation_cache)
    {:reply, result, %{state | url_reputation_cache: new_cache}}
  end

  @impl true
  def handle_call({:set_policy, policy_attrs}, _from, state) do
    policy = %SharingPolicy{
      id: policy_attrs[:id] || generate_id(),
      name: policy_attrs[:name],
      enabled: policy_attrs[:enabled] != false,
      allowed_domains: policy_attrs[:allowed_domains] || [],
      blocked_domains: policy_attrs[:blocked_domains] || [],
      allow_external_users: policy_attrs[:allow_external_users] || false,
      allow_guest_access: policy_attrs[:allow_guest_access] || false,
      require_approval: policy_attrs[:require_approval] || true,
      max_external_shares_per_day: policy_attrs[:max_external_shares_per_day] || 10,
      block_sensitive_files: policy_attrs[:block_sensitive_files] != false,
      notify_on_external_share: policy_attrs[:notify_on_external_share] != false
    }

    new_policies = Map.put(state.policies, policy.id, policy)
    save_policies(new_policies)

    {:reply, {:ok, policy}, %{state | policies: new_policies}}
  end

  @impl true
  def handle_call(:get_policies, _from, state) do
    {:reply, {:ok, Map.values(state.policies)}, state}
  end

  @impl true
  def handle_call({:assess_oauth_app, app_info}, _from, state) do
    {app, risk_assessment} = assess_app_risk(app_info)
    new_apps = Map.put(state.oauth_apps, app.id, app)

    new_stats = %{state.stats | oauth_apps_assessed: state.stats.oauth_apps_assessed + 1}

    {:reply, {:ok, risk_assessment}, %{state | oauth_apps: new_apps, stats: new_stats}}
  end

  @impl true
  def handle_call(:list_oauth_apps, _from, state) do
    apps = Map.values(state.oauth_apps)
    {:reply, {:ok, apps}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_call({:analyze_external_sharing, opts}, _from, state) do
    # Analyze external sharing patterns across platforms
    time_range = Map.get(opts, :time_range, :last_7d)

    # Get external sharing events from recent events
    external_events = state.recent_events
    |> Enum.filter(fn event ->
      Enum.any?(event.risk_factors || [], &String.starts_with?(&1, "external_"))
    end)

    analysis = %{
      time_range: time_range,
      total_external_shares: length(external_events),
      by_platform: Enum.group_by(external_events, & &1.platform)
        |> Enum.map(fn {platform, events} -> {platform, length(events)} end)
        |> Map.new(),
      high_risk_shares: Enum.count(external_events, &(&1.risk_score >= 70)),
      blocked_shares: state.stats.external_shares_detected,
      top_external_domains: extract_top_external_domains(external_events),
      policy_violations: state.stats.external_shares_detected,
      recommendations: generate_sharing_recommendations(external_events)
    }

    {:reply, {:ok, analysis}, state}
  end

  @impl true
  def handle_call({:analyze_risks, opts}, _from, state) do
    # Comprehensive risk analysis across collaboration platforms
    analysis = %{
      overall_risk_score: calculate_overall_risk_score(state),
      platform_risks: analyze_platform_risks(state),
      top_risk_factors: extract_top_risk_factors(state.recent_events),
      sensitive_data_exposure: %{
        detections: state.stats.sensitive_data_detections,
        types: categorize_sensitive_data_types(state.recent_events)
      },
      malicious_content: %{
        urls_blocked: state.stats.malicious_urls_blocked,
        files_blocked: state.stats.risky_files_blocked
      },
      oauth_app_risks: analyze_oauth_risks(state.oauth_apps),
      policy_compliance: calculate_policy_compliance(state),
      recommendations: generate_risk_recommendations(state)
    }

    {:reply, {:ok, analysis}, state}
  end

  @impl true
  def handle_call({:list_events, opts}, _from, state) do
    # List collaboration security events with optional filters
    limit = Map.get(opts, :limit, 100)
    platform = Map.get(opts, :platform)
    min_risk = Map.get(opts, :min_risk_score, 0)

    events = state.recent_events
    |> maybe_filter_by_platform(platform)
    |> Enum.filter(&(&1.risk_score >= min_risk))
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, {:ok, events}, state}
  end

  @impl true
  def handle_cast({:process_webhook, platform, payload}, state) do
    Logger.debug("Processing #{platform} webhook event")

    case parse_webhook_event(platform, payload) do
      {:ok, event} ->
        new_state = process_collaboration_event(event, state)
        {:noreply, new_state}

      {:error, reason} ->
        Logger.warning("Failed to parse #{platform} webhook: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:sync_platform, platform_id}, state) do
    case Map.get(state.platforms, platform_id) do
      nil ->
        Logger.warning("Platform not found: #{platform_id}")
        {:noreply, state}

      platform ->
        Task.start(fn -> sync_platform_data(platform) end)
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:periodic_scan, state) do
    Logger.debug("Running periodic collaboration security scan")

    # Sync enabled platforms
    state.platforms
    |> Map.values()
    |> Enum.filter(& &1.enabled)
    |> Enum.each(fn platform ->
      Task.start(fn -> sync_platform_data(platform) end)
    end)

    # Clean up expired cache entries
    new_cache = clean_url_cache(state.url_reputation_cache)

    new_stats = %{state.stats | last_scan: DateTime.utc_now()}

    schedule_scan()
    {:noreply, %{state | url_reputation_cache: new_cache, stats: new_stats}}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions - Event Processing

  defp process_collaboration_event(%CollabEvent{} = event, state) do
    # Calculate risk score
    {risk_score, risk_factors} = calculate_event_risk(event, state)

    event = %{event | risk_score: risk_score, risk_factors: risk_factors}

    # Check policies
    policy_violations = check_policy_violations(event, state.policies)

    # Update stats
    new_stats = update_stats(state.stats, event, policy_violations)

    # Generate alerts if needed
    if risk_score >= @high_risk_threshold or length(policy_violations) > 0 do
      create_collaboration_alert(event, policy_violations)
    end

    # Store event in recent_events (keep last 1000)
    new_recent_events = [event | state.recent_events] |> Enum.take(1000)

    %{state | stats: new_stats, recent_events: new_recent_events}
  end

  defp calculate_event_risk(%CollabEvent{} = event, state) do
    risk_factors = []
    base_score = 0

    # Check for sensitive data in content
    {sensitive_score, sensitive_factors} = if event.content do
      findings = detect_sensitive_data(event.content)
      score = length(findings) * 15
      factors = Enum.map(findings, fn {type, _} -> "sensitive_data:#{type}" end)
      {min(score, 50), factors}
    else
      {0, []}
    end

    risk_factors = risk_factors ++ sensitive_factors

    # Check URLs in content
    {url_score, url_factors} = if event.urls && length(event.urls) > 0 do
      url_results = Enum.map(event.urls, fn url ->
        {result, _} = check_url_reputation(url, state.url_reputation_cache)
        result
      end)

      malicious_count = Enum.count(url_results, fn
        {:malicious, _} -> true
        _ -> false
      end)

      suspicious_count = Enum.count(url_results, fn
        {:suspicious, _} -> true
        _ -> false
      end)

      score = malicious_count * 40 + suspicious_count * 15
      factors = if malicious_count > 0, do: ["malicious_urls:#{malicious_count}"], else: []
      factors = if suspicious_count > 0, do: factors ++ ["suspicious_urls:#{suspicious_count}"], else: factors

      {min(score, 60), factors}
    else
      {0, []}
    end

    risk_factors = risk_factors ++ url_factors

    # Check for external users
    {external_score, external_factors} = if event.external_users && length(event.external_users) > 0 do
      score = length(event.external_users) * 10
      {min(score, 30), ["external_users:#{length(event.external_users)}"]}
    else
      {0, []}
    end

    risk_factors = risk_factors ++ external_factors

    # Check file sharing risk
    {file_score, file_factors} = if event.file_info do
      check_file_risk(event.file_info)
    else
      {0, []}
    end

    risk_factors = risk_factors ++ file_factors

    # Event type specific scoring
    type_score = case event.event_type do
      :app_install -> 20
      :file_share -> 10
      :user_join when event.external_users != nil -> 15
      _ -> 0
    end

    total_score = base_score + sensitive_score + url_score + external_score + file_score + type_score
    {min(total_score, 100), risk_factors}
  end

  defp check_file_risk(file_info) do
    factors = []
    score = 0

    # Check file extension
    extension = Path.extname(file_info[:name] || "") |> String.downcase()

    {score, factors} = if extension in @risky_file_extensions do
      {score + 40, factors ++ ["risky_extension:#{extension}"]}
    else
      {score, factors}
    end

    # Check file size (large files might be data exfiltration)
    {score, factors} = if file_info[:size] && file_info[:size] > 100_000_000 do
      {score + 15, factors ++ ["large_file:#{div(file_info[:size], 1_000_000)}MB"]}
    else
      {score, factors}
    end

    # Check if shared externally
    {score, factors} = if file_info[:shared_externally] do
      {score + 20, factors ++ ["external_share"]}
    else
      {score, factors}
    end

    {score, factors}
  end

  defp check_policy_violations(%CollabEvent{} = event, policies) do
    policies
    |> Map.values()
    |> Enum.filter(& &1.enabled)
    |> Enum.flat_map(fn policy ->
      violations = []

      # Check external user restrictions
      violations = if event.external_users && length(event.external_users) > 0 do
        external_domains = Enum.map(event.external_users, fn user ->
          case String.split(user[:email] || "", "@") do
            [_, domain] -> domain
            _ -> nil
          end
        end)
        |> Enum.filter(& &1)

        blocked = Enum.filter(external_domains, fn domain ->
          domain in policy.blocked_domains or
          (length(policy.allowed_domains) > 0 and domain not in policy.allowed_domains)
        end)

        if length(blocked) > 0 do
          [%{policy_id: policy.id, violation: :blocked_domain, details: blocked} | violations]
        else
          violations
        end
      else
        violations
      end

      # Check guest access
      violations = if not policy.allow_guest_access and event.event_type == :user_join do
        if event.external_users && length(event.external_users) > 0 do
          [%{policy_id: policy.id, violation: :guest_access_denied, details: event.external_users} | violations]
        else
          violations
        end
      else
        violations
      end

      # Check sensitive file sharing
      violations = if policy.block_sensitive_files and event.file_info do
        findings = detect_sensitive_data(event.file_info[:name] || "")
        if length(findings) > 0 do
          [%{policy_id: policy.id, violation: :sensitive_file_blocked, details: findings} | violations]
        else
          violations
        end
      else
        violations
      end

      violations
    end)
  end

  ## Private Functions - Sensitive Data Detection

  defp detect_sensitive_data(content) when is_binary(content) do
    @pii_patterns
    |> Enum.flat_map(fn {type, pattern} ->
      case Regex.scan(pattern, content) do
        [] -> []
        matches -> Enum.map(matches, fn [match | _] -> {type, redact_sensitive(match, type)} end)
      end
    end)
  end

  defp redact_sensitive(value, type) do
    case type do
      :ssn -> "***-**-" <> String.slice(value, -4, 4)
      :credit_card -> "**** **** **** " <> String.slice(value, -4, 4)
      :email -> redact_email(value)
      :phone -> "***-***-" <> String.slice(value, -4, 4)
      :api_key -> String.slice(value, 0, 10) <> "..." <> String.slice(value, -4, 4)
      :aws_key -> String.slice(value, 0, 8) <> "********"
      :private_key -> "[PRIVATE KEY REDACTED]"
      :password -> "[PASSWORD REDACTED]"
      :bearer_token -> "Bearer ****..."
      _ -> String.slice(value, 0, 4) <> "****"
    end
  end

  defp redact_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        redacted_local = String.slice(local, 0, 2) <> "***"
        "#{redacted_local}@#{domain}"
      _ ->
        "***@***"
    end
  end

  ## Private Functions - URL Reputation

  defp check_url_reputation(url, cache) do
    now = DateTime.utc_now()

    # Check cache first
    case Map.get(cache, url) do
      {result, expires_at} ->
        if DateTime.compare(expires_at, now) == :gt do
          {result, cache}
        else
          # Cache expired, refresh
          result = perform_url_check(url)
          new_expires_at = DateTime.add(now, 3600, :second)
          new_cache = Map.put(cache, url, {result, new_expires_at})
          {result, new_cache}
        end

      nil ->
        result = perform_url_check(url)
        expires_at = DateTime.add(now, 3600, :second)
        new_cache = Map.put(cache, url, {result, expires_at})
        {result, new_cache}
    end
  end

  defp perform_url_check(url) do
    # Check against known malicious patterns
    pattern_match = Enum.find(@malicious_url_patterns, fn pattern ->
      Regex.match?(pattern, url)
    end)

    if pattern_match do
      {:malicious, "Matches known malicious URL pattern"}
    else
      # Check URL structure for suspicious indicators
      uri = URI.parse(url)
      suspicious_indicators = []

      # Check for IP address instead of domain
      suspicious_indicators = if uri.host && Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, uri.host) do
        ["ip_address_url" | suspicious_indicators]
      else
        suspicious_indicators
      end

      # Check for suspicious TLDs
      suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"]
      suspicious_indicators = if uri.host && Enum.any?(suspicious_tlds, &String.ends_with?(uri.host, &1)) do
        ["suspicious_tld" | suspicious_indicators]
      else
        suspicious_indicators
      end

      # Check for encoded characters (possible obfuscation)
      suspicious_indicators = if String.contains?(url, "%") and String.length(url) > 100 do
        ["heavy_encoding" | suspicious_indicators]
      else
        suspicious_indicators
      end

      # Check for data URI
      suspicious_indicators = if String.starts_with?(url, "data:") do
        ["data_uri" | suspicious_indicators]
      else
        suspicious_indicators
      end

      case length(suspicious_indicators) do
        0 -> {:clean, "No issues detected"}
        n when n >= 2 -> {:suspicious, "Multiple suspicious indicators: #{Enum.join(suspicious_indicators, ", ")}"}
        _ -> {:low_risk, "Minor concern: #{hd(suspicious_indicators)}"}
      end
    end
  end

  defp clean_url_cache(cache) do
    now = DateTime.utc_now()

    cache
    |> Enum.filter(fn {_url, {_result, expires_at}} ->
      DateTime.compare(expires_at, now) == :gt
    end)
    |> Map.new()
  end

  ## Private Functions - OAuth App Assessment

  defp assess_app_risk(app_info) do
    risk_factors = []
    score = 0

    # Check permissions scope
    permissions = app_info[:permissions] || []

    high_risk_permissions = [
      "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
      "Directory.ReadWrite.All", "User.ReadWrite.All",
      "channels:write", "files:write", "admin"
    ]

    risky_perms = Enum.filter(permissions, fn perm ->
      Enum.any?(high_risk_permissions, &String.contains?(perm, &1))
    end)

    {score, risk_factors} = if length(risky_perms) > 0 do
      {score + length(risky_perms) * 15, risk_factors ++ Enum.map(risky_perms, &"high_risk_permission:#{&1}")}
    else
      {score, risk_factors}
    end

    # Check publisher reputation
    {score, risk_factors} = if app_info[:publisher] do
      trusted_publishers = ["Microsoft", "Google", "Slack", "Zoom", "Salesforce", "Adobe"]
      if app_info[:publisher] not in trusted_publishers do
        {score + 20, risk_factors ++ ["untrusted_publisher:#{app_info[:publisher]}"]}
      else
        {score, risk_factors}
      end
    else
      {score + 25, risk_factors ++ ["unknown_publisher"]}
    end

    # Check if recently installed
    {score, risk_factors} = if app_info[:installed_at] do
      days_since_install = DateTime.diff(DateTime.utc_now(), app_info[:installed_at], :day)
      if days_since_install < 7 do
        {score + 10, risk_factors ++ ["recently_installed:#{days_since_install}_days"]}
      else
        {score, risk_factors}
      end
    else
      {score, risk_factors}
    end

    total_score = min(score, 100)

    app = %OAuthApp{
      id: app_info[:id] || generate_id(),
      name: app_info[:name],
      platform: app_info[:platform],
      publisher: app_info[:publisher],
      permissions: permissions,
      installed_by: app_info[:installed_by],
      installed_at: app_info[:installed_at],
      risk_score: total_score,
      risk_factors: risk_factors,
      approved: total_score < @medium_risk_threshold,
      last_used: app_info[:last_used]
    }

    risk_level = cond do
      total_score >= @high_risk_threshold -> :high
      total_score >= @medium_risk_threshold -> :medium
      true -> :low
    end

    assessment = %{
      app_id: app.id,
      app_name: app.name,
      risk_level: risk_level,
      risk_score: total_score,
      risk_factors: risk_factors,
      recommendation: get_app_recommendation(risk_level, risk_factors),
      approved: app.approved
    }

    {app, assessment}
  end

  defp get_app_recommendation(:high, risk_factors) do
    "BLOCK: This application has high-risk characteristics. " <>
    "Risk factors: #{Enum.join(risk_factors, ", ")}. " <>
    "Review and consider removing this application."
  end

  defp get_app_recommendation(:medium, risk_factors) do
    "REVIEW: This application requires manual review. " <>
    "Concerns: #{Enum.join(risk_factors, ", ")}. " <>
    "Verify the application is necessary and from a trusted source."
  end

  defp get_app_recommendation(:low, _risk_factors) do
    "ALLOW: This application appears to be low risk. " <>
    "Continue to monitor for unusual behavior."
  end

  ## Private Functions - Webhook Parsing

  defp parse_webhook_event(:teams, payload) do
    # Microsoft Teams webhook format
    event = %CollabEvent{
      id: payload["id"] || generate_id(),
      platform: :teams,
      event_type: parse_teams_event_type(payload["@odata.type"]),
      timestamp: parse_timestamp(payload["createdDateTime"]),
      user_id: get_in(payload, ["from", "user", "id"]),
      user_email: get_in(payload, ["from", "user", "email"]),
      user_name: get_in(payload, ["from", "user", "displayName"]),
      channel_id: get_in(payload, ["channelIdentity", "channelId"]),
      channel_name: payload["channelDisplayName"],
      content: get_in(payload, ["body", "content"]),
      file_info: parse_teams_attachments(payload["attachments"]),
      urls: extract_urls(get_in(payload, ["body", "content"]) || ""),
      external_users: parse_teams_external_users(payload["mentions"]),
      raw_data: payload
    }

    {:ok, event}
  end

  defp parse_webhook_event(:slack, payload) do
    # Slack Events API format
    event_data = payload["event"] || payload

    event = %CollabEvent{
      id: event_data["client_msg_id"] || event_data["event_id"] || generate_id(),
      platform: :slack,
      event_type: parse_slack_event_type(event_data["type"]),
      timestamp: parse_slack_timestamp(event_data["ts"]),
      user_id: event_data["user"],
      user_email: nil,  # Requires additional API call
      user_name: nil,
      channel_id: event_data["channel"],
      channel_name: nil,
      content: event_data["text"],
      file_info: parse_slack_files(event_data["files"]),
      urls: extract_urls(event_data["text"] || ""),
      external_users: nil,
      raw_data: payload
    }

    {:ok, event}
  end

  defp parse_webhook_event(:zoom, payload) do
    # Zoom webhook format
    event_payload = payload["payload"] || %{}
    object = event_payload["object"] || %{}

    event = %CollabEvent{
      id: payload["event_ts"] || generate_id(),
      platform: :zoom,
      event_type: parse_zoom_event_type(payload["event"]),
      timestamp: parse_timestamp(payload["event_ts"]),
      user_id: get_in(object, ["host_id"]),
      user_email: get_in(object, ["host_email"]),
      user_name: get_in(object, ["host_name"]),
      channel_id: object["id"],
      channel_name: object["topic"],
      content: nil,
      file_info: parse_zoom_files(object["files"]),
      urls: [],
      external_users: parse_zoom_participants(object["participants"]),
      raw_data: payload
    }

    {:ok, event}
  end

  defp parse_webhook_event(platform, _payload) do
    {:error, "Unknown platform: #{platform}"}
  end

  ## Private Functions - Platform-specific Parsers

  defp parse_teams_event_type(type) do
    case type do
      "#microsoft.graph.chatMessage" -> :message
      "#microsoft.graph.driveItem" -> :file_share
      "#microsoft.graph.user" -> :user_join
      "#microsoft.graph.teamsApp" -> :app_install
      _ -> :unknown
    end
  end

  defp parse_slack_event_type(type) do
    case type do
      "message" -> :message
      "file_shared" -> :file_share
      "file_public" -> :file_share
      "member_joined_channel" -> :user_join
      "app_installed" -> :app_install
      _ -> :unknown
    end
  end

  defp parse_zoom_event_type(type) do
    case type do
      "meeting.started" -> :meeting
      "meeting.ended" -> :meeting
      "meeting.participant_joined" -> :user_join
      "chat_message.sent" -> :message
      _ -> :unknown
    end
  end

  defp parse_teams_attachments(nil), do: nil
  defp parse_teams_attachments([]), do: nil
  defp parse_teams_attachments([attachment | _]) do
    %{
      name: attachment["name"],
      size: attachment["contentBytes"] && byte_size(attachment["contentBytes"]),
      content_type: attachment["contentType"],
      shared_externally: false
    }
  end

  defp parse_slack_files(nil), do: nil
  defp parse_slack_files([]), do: nil
  defp parse_slack_files([file | _]) do
    %{
      name: file["name"],
      size: file["size"],
      content_type: file["mimetype"],
      shared_externally: file["is_external"] == true
    }
  end

  defp parse_zoom_files(nil), do: nil
  defp parse_zoom_files([]), do: nil
  defp parse_zoom_files([file | _]) do
    %{
      name: file["file_name"],
      size: file["file_size"],
      content_type: file["file_type"],
      shared_externally: false
    }
  end

  defp parse_teams_external_users(nil), do: nil
  defp parse_teams_external_users(mentions) do
    Enum.filter(mentions, fn m ->
      get_in(m, ["mentioned", "user", "userIdentityType"]) == "guest"
    end)
    |> Enum.map(fn m ->
      %{
        id: get_in(m, ["mentioned", "user", "id"]),
        email: get_in(m, ["mentioned", "user", "email"]),
        name: get_in(m, ["mentioned", "user", "displayName"])
      }
    end)
  end

  defp parse_zoom_participants(nil), do: nil
  defp parse_zoom_participants(participants) do
    Enum.filter(participants, fn p -> p["user_type"] == "external" end)
    |> Enum.map(fn p ->
      %{
        id: p["user_id"],
        email: p["email"],
        name: p["user_name"]
      }
    end)
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(ts) when is_integer(ts) do
    DateTime.from_unix!(ts)
  end

  defp parse_slack_timestamp(nil), do: DateTime.utc_now()
  defp parse_slack_timestamp(ts) when is_binary(ts) do
    case Float.parse(ts) do
      {unix_ts, _} -> DateTime.from_unix!(trunc(unix_ts))
      :error -> DateTime.utc_now()
    end
  end

  defp extract_urls(content) when is_binary(content) do
    url_pattern = ~r/https?:\/\/[^\s<>\[\]"']+/
    Regex.scan(url_pattern, content)
    |> List.flatten()
    |> Enum.uniq()
  end

  ## Private Functions - Alerting

  defp create_collaboration_alert(%CollabEvent{} = event, policy_violations) do
    severity = cond do
      event.risk_score >= @high_risk_threshold -> :high
      length(policy_violations) > 0 -> :medium
      event.risk_score >= @medium_risk_threshold -> :medium
      true -> :low
    end

    title = build_alert_title(event, policy_violations)
    description = build_alert_description(event, policy_violations)

    # Extract event_id from the collaboration event if available
    source_event_id = event.id || event[:event_id]

    # Build evidence for collaboration security alerts
    evidence = %{
      file_hashes: [],
      network: if(event.channel_name, do: [%{type: "channel", value: event.channel_name}], else: []),
      process: %{
        user: event.user_email || event.user_name
      },
      registry: [],
      detection: %{
        rule_name: "Collaboration Security: #{event.platform}",
        rule_type: "collaboration_monitoring",
        confidence: event.risk_score / 100,
        matched_pattern: Enum.join(event.risk_factors || [], ", ")
      }
    }

    alert_attrs = %{
      title: title,
      description: description,
      severity: severity,
      source_event_id: source_event_id,
      event_ids: if(source_event_id, do: [source_event_id], else: []),
      evidence: evidence,
      threat_score: event.risk_score / 100,
      detection_type: "collaboration_security",
      source: "collab_monitor:#{event.platform}",
      metadata: %{
        platform: event.platform,
        event_type: event.event_type,
        user_email: event.user_email,
        channel_name: event.channel_name,
        risk_score: event.risk_score,
        risk_factors: event.risk_factors,
        policy_violations: Enum.map(policy_violations, & &1.violation)
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info("Created collaboration security alert: #{alert.id}")
        broadcast_alert(alert)

      {:error, reason} ->
        Logger.error("Failed to create collaboration alert: #{inspect(reason)}")
    end
  end

  defp build_alert_title(event, policy_violations) do
    base = "Collaboration Security: #{String.capitalize(to_string(event.platform))}"
    risk_factors = event.risk_factors || []

    cond do
      length(policy_violations) > 0 ->
        violation = hd(policy_violations)
        "#{base} - Policy Violation: #{violation.violation}"

      event.risk_score >= @high_risk_threshold ->
        "#{base} - High Risk Activity Detected"

      length(risk_factors) > 0 ->
        factor = hd(risk_factors)
        "#{base} - #{humanize_risk_factor(factor)}"

      true ->
        "#{base} - Suspicious Activity"
    end
  end

  defp build_alert_description(event, policy_violations) do
    risk_factors = event.risk_factors || []

    parts = [
      "Platform: #{event.platform}",
      "Event Type: #{event.event_type}",
      "User: #{event.user_email || event.user_name || "Unknown"}",
      "Channel: #{event.channel_name || event.channel_id || "N/A"}",
      "Risk Score: #{event.risk_score}/100",
      ""
    ]

    parts = if length(risk_factors) > 0 do
      parts ++ ["Risk Factors:", Enum.map(risk_factors, &"  - #{humanize_risk_factor(&1)}") |> Enum.join("\n"), ""]
    else
      parts
    end

    parts = if length(policy_violations) > 0 do
      violations_text = Enum.map(policy_violations, fn v ->
        "  - #{v.violation}: #{inspect(v.details)}"
      end) |> Enum.join("\n")

      parts ++ ["Policy Violations:", violations_text]
    else
      parts
    end

    Enum.join(parts, "\n")
  end

  defp humanize_risk_factor(factor) do
    factor
    |> String.replace("_", " ")
    |> String.replace(":", ": ")
    |> String.capitalize()
  end

  defp broadcast_alert(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:new",
      {:new_alert, alert}
    )
  end

  ## Private Functions - Stats & Utilities

  defp update_stats(stats, event, policy_violations) do
    stats = %{stats | events_processed: stats.events_processed + 1}
    risk_factors = event.risk_factors || []

    stats = if length(risk_factors) > 0 do
      sensitive_count = Enum.count(risk_factors, &String.starts_with?(&1, "sensitive_data:"))
      malicious_count = Enum.count(risk_factors, &String.starts_with?(&1, "malicious_url"))
      external_count = Enum.count(risk_factors, &String.starts_with?(&1, "external_"))
      file_count = Enum.count(risk_factors, &String.starts_with?(&1, "risky_extension:"))

      %{stats |
        sensitive_data_detections: stats.sensitive_data_detections + sensitive_count,
        malicious_urls_blocked: stats.malicious_urls_blocked + malicious_count,
        external_shares_detected: stats.external_shares_detected + external_count,
        risky_files_blocked: stats.risky_files_blocked + file_count
      }
    else
      stats
    end

    if length(policy_violations) > 0 do
      %{stats | external_shares_detected: stats.external_shares_detected + 1}
    else
      stats
    end
  end

  defp sync_platform_data(%PlatformConfig{platform: :teams} = _config) do
    # Microsoft Graph API sync
    Logger.info("Syncing Microsoft Teams data")
    # Implementation would use Microsoft Graph API
    # GET /teams/{team-id}/channels/{channel-id}/messages
    :ok
  end

  defp sync_platform_data(%PlatformConfig{platform: :slack} = _config) do
    # Slack API sync
    Logger.info("Syncing Slack data")
    # Implementation would use Slack Web API
    # conversations.history, files.list, etc.
    :ok
  end

  defp sync_platform_data(%PlatformConfig{platform: :zoom} = _config) do
    # Zoom API sync
    Logger.info("Syncing Zoom data")
    # Implementation would use Zoom API
    # /users, /meetings, /chat/users/{userId}/messages
    :ok
  end

  defp sync_platform_data(_), do: :ok

  defp sanitize_platform_config(config) do
    %{config |
      client_secret: if(config.client_secret, do: "****", else: nil),
      access_token: if(config.access_token, do: "****", else: nil),
      refresh_token: if(config.refresh_token, do: "****", else: nil)
    }
  end

  defp load_platforms do
    # Load from database/config
    %{}
  end

  defp save_platforms(_platforms) do
    # Save to database/config
    :ok
  end

  defp load_policies do
    # Load from database/config - return default policy
    default_policy = %SharingPolicy{
      id: "default",
      name: "Default Sharing Policy",
      enabled: true,
      allowed_domains: [],
      blocked_domains: [],
      allow_external_users: true,
      allow_guest_access: false,
      require_approval: true,
      max_external_shares_per_day: 10,
      block_sensitive_files: true,
      notify_on_external_share: true
    }

    %{"default" => default_policy}
  end

  defp save_policies(_policies) do
    # Save to database/config
    :ok
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp schedule_scan do
    Process.send_after(self(), :periodic_scan, @scan_interval_ms)
  end

  defp extract_top_external_domains(events) do
    events
    |> Enum.flat_map(fn event ->
      (event.risk_factors || [])
      |> Enum.filter(&String.starts_with?(&1, "external_domain:"))
      |> Enum.map(&String.replace(&1, "external_domain:", ""))
    end)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_domain, count} -> count end, :desc)
    |> Enum.take(10)
    |> Map.new()
  end

  defp generate_sharing_recommendations(external_events) do
    recommendations = []

    recommendations = if length(external_events) > 50 do
      ["Review and reduce external sharing volume" | recommendations]
    else
      recommendations
    end

    high_risk_count = Enum.count(external_events, &(&1.risk_score >= 70))
    recommendations = if high_risk_count > 5 do
      ["Investigate high-risk external shares" | recommendations]
    else
      recommendations
    end

    if Enum.empty?(recommendations) do
      ["External sharing patterns are within normal parameters"]
    else
      recommendations
    end
  end

  defp calculate_overall_risk_score(state) do
    # Calculate weighted risk score
    event_risk = if length(state.recent_events) > 0 do
      Enum.map(state.recent_events, & &1.risk_score)
      |> Enum.sum()
      |> Kernel./(length(state.recent_events))
    else
      0
    end

    oauth_risk = if map_size(state.oauth_apps) > 0 do
      state.oauth_apps
      |> Map.values()
      |> Enum.map(&(&1.risk_score || 0))
      |> Enum.sum()
      |> Kernel./(map_size(state.oauth_apps))
    else
      0
    end

    Float.round((event_risk * 0.7) + (oauth_risk * 0.3), 1)
  end

  defp analyze_platform_risks(state) do
    state.platforms
    |> Map.values()
    |> Enum.map(fn platform ->
      platform_events = Enum.filter(state.recent_events, &(&1.platform == platform.platform))
      avg_risk = if length(platform_events) > 0 do
        Enum.map(platform_events, & &1.risk_score) |> Enum.sum() |> Kernel./(length(platform_events))
      else
        0
      end

      %{
        platform: platform.platform,
        event_count: length(platform_events),
        average_risk: Float.round(avg_risk, 1),
        enabled: platform.enabled
      }
    end)
  end

  defp extract_top_risk_factors(events) do
    events
    |> Enum.flat_map(&(&1.risk_factors || []))
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_factor, count} -> count end, :desc)
    |> Enum.take(10)
    |> Enum.map(fn {factor, count} -> %{factor: factor, count: count} end)
  end

  defp categorize_sensitive_data_types(events) do
    events
    |> Enum.flat_map(&(&1.risk_factors || []))
    |> Enum.filter(&String.starts_with?(&1, "sensitive_data:"))
    |> Enum.map(&String.replace(&1, "sensitive_data:", ""))
    |> Enum.frequencies()
  end

  defp analyze_oauth_risks(oauth_apps) do
    apps = Map.values(oauth_apps)

    %{
      total_apps: length(apps),
      high_risk_apps: Enum.count(apps, &((&1.risk_score || 0) >= 70)),
      apps_with_excessive_permissions: Enum.count(apps, &has_excessive_permissions?/1)
    }
  end

  defp has_excessive_permissions?(app) do
    permissions = app.permissions || []
    length(permissions) > 5
  end

  defp calculate_policy_compliance(state) do
    policies = Map.values(state.policies)
    enabled_policies = Enum.count(policies, & &1.enabled)

    %{
      total_policies: length(policies),
      enabled_policies: enabled_policies,
      compliance_rate: if(length(policies) > 0, do: Float.round(enabled_policies / length(policies) * 100, 1), else: 100.0)
    }
  end

  defp generate_risk_recommendations(state) do
    recommendations = []

    recommendations = if state.stats.malicious_urls_blocked > 0 do
      ["Review blocked malicious URLs for patterns" | recommendations]
    else
      recommendations
    end

    recommendations = if state.stats.sensitive_data_detections > 10 do
      ["Enable stricter DLP policies" | recommendations]
    else
      recommendations
    end

    high_risk_apps = state.oauth_apps
    |> Map.values()
    |> Enum.filter(&((&1.risk_score || 0) >= 70))
    |> length()

    recommendations = if high_risk_apps > 0 do
      ["Review and revoke high-risk OAuth applications" | recommendations]
    else
      recommendations
    end

    if Enum.empty?(recommendations) do
      ["No immediate actions required"]
    else
      recommendations
    end
  end

  defp maybe_filter_by_platform(events, nil), do: events
  defp maybe_filter_by_platform(events, platform) do
    Enum.filter(events, &(&1.platform == platform))
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Analyze external sharing patterns and risks.
  """
  def analyze_external_sharing(opts \\ %{}) do
    GenServer.call(__MODULE__, {:analyze_external_sharing, opts}, 30_000)
  end

  @doc """
  Analyze collaboration risks across platforms.
  """
  def analyze_risks(opts \\ %{}) do
    GenServer.call(__MODULE__, {:analyze_risks, opts}, 30_000)
  end

  @doc """
  List collaboration security events.
  """
  def list_events(opts \\ %{}) do
    GenServer.call(__MODULE__, {:list_events, opts})
  end

  @doc """
  List collaboration security alerts.
  """
  @spec list_alerts(map()) :: {:ok, [map()]}
  def list_alerts(_opts \\ %{}) do
    {:ok, []}
  end
end
