defmodule TamanduaServer.Identity.AzureAD do
  @moduledoc """
  Azure AD / Microsoft Entra ID integration for identity protection.

  Provides:
  - Microsoft Graph API integration
  - Sign-in logs ingestion
  - Risky user detection
  - Conditional access policy monitoring
  - Service principal monitoring
  - Directory audit logs

  Requires Azure AD Premium P2 or Microsoft Entra ID P2 license for:
  - Identity Protection (risky users/sign-ins)
  - Sign-in logs via API

  ## Configuration

      config :tamandua_server, TamanduaServer.Identity.AzureAD,
        tenant_id: "your-tenant-id",
        client_id: "your-app-client-id",
        client_secret: "your-app-client-secret",
        poll_interval_seconds: 60
  """

  use GenServer
  require Logger

  alias TamanduaServer.Identity.RiskScoring
  alias TamanduaServer.Alerts

  @graph_base_url "https://graph.microsoft.com/v1.0"
  @graph_beta_url "https://graph.microsoft.com/beta"
  @token_url "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

  # API endpoints
  @sign_ins_endpoint "/auditLogs/signIns"
  @directory_audits_endpoint "/auditLogs/directoryAudits"
  @risky_users_endpoint "/identityProtection/riskyUsers"
  @risky_sign_ins_endpoint "/identityProtection/riskyServicePrincipals"
  @service_principals_endpoint "/servicePrincipals"
  @conditional_access_endpoint "/identity/conditionalAccess/policies"
  @users_endpoint "/users"

  # Event types for internal tracking
  @sign_in_event_type "azure_ad_sign_in"
  @audit_event_type "azure_ad_audit"
  @risky_user_event_type "azure_ad_risky_user"
  @risky_sign_in_event_type "azure_ad_risky_sign_in"

  # MITRE ATT&CK mappings
  @mitre_mapping %{
    "failed_sign_in" => ["T1078", "T1110"],
    "risky_sign_in" => ["T1078"],
    "impossible_travel" => ["T1078"],
    "unfamiliar_location" => ["T1078"],
    "anonymous_ip" => ["T1090", "T1078"],
    "malware_linked_ip" => ["T1078"],
    "suspicious_browser" => ["T1078"],
    "password_spray" => ["T1110.003"],
    "leaked_credentials" => ["T1078.004"],
    "privilege_escalation" => ["T1078.002"],
    "service_principal_risk" => ["T1078.004"],
    "conditional_access_bypass" => ["T1556"]
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get recent sign-in events with optional filtering.

  ## Options
    - :user_id - Filter by user ID
    - :status - Filter by status ("success", "failure", "interrupted")
    - :risk_level - Filter by risk level ("none", "low", "medium", "high")
    - :limit - Maximum number of results (default: 100)
    - :since - DateTime to fetch events from
  """
  def get_sign_ins(opts \\ []) do
    GenServer.call(__MODULE__, {:get_sign_ins, opts})
  end

  @doc """
  Get risky users from Azure AD Identity Protection.

  ## Options
    - :risk_level - Filter by risk level ("low", "medium", "high")
    - :risk_state - Filter by risk state ("atRisk", "confirmedCompromised", "remediated", "dismissed")
    - :limit - Maximum number of results (default: 100)
  """
  def get_risky_users(opts \\ []) do
    GenServer.call(__MODULE__, {:get_risky_users, opts})
  end

  @doc """
  Get conditional access policies.
  """
  def get_conditional_access_policies(opts \\ []) do
    GenServer.call(__MODULE__, {:get_conditional_access_policies, opts})
  end

  @doc """
  Get service principals with filtering options.

  ## Options
    - :app_id - Filter by application ID
    - :display_name - Filter by display name (contains)
    - :limit - Maximum number of results
  """
  def get_service_principals(opts \\ []) do
    GenServer.call(__MODULE__, {:get_service_principals, opts})
  end

  @doc """
  Get directory audit logs.

  ## Options
    - :activity_display_name - Filter by activity type
    - :category - Filter by category
    - :initiated_by - Filter by initiator
    - :since - DateTime to fetch events from
    - :limit - Maximum number of results
  """
  def get_directory_audits(opts \\ []) do
    GenServer.call(__MODULE__, {:get_directory_audits, opts})
  end

  @doc """
  Get user details by ID or UPN.
  """
  def get_user(user_id_or_upn) do
    GenServer.call(__MODULE__, {:get_user, user_id_or_upn})
  end

  @doc """
  Confirm a user as compromised in Azure AD Identity Protection.
  Requires admin privileges.
  """
  def confirm_user_compromised(user_id) do
    GenServer.call(__MODULE__, {:confirm_user_compromised, user_id})
  end

  @doc """
  Dismiss a risky user in Azure AD Identity Protection.
  Requires admin privileges.
  """
  def dismiss_risky_user(user_id) do
    GenServer.call(__MODULE__, {:dismiss_risky_user, user_id})
  end

  @doc """
  Force password reset for a user.
  Requires admin privileges.
  """
  def force_password_reset(user_id) do
    GenServer.call(__MODULE__, {:force_password_reset, user_id})
  end

  @doc """
  Get current integration status and statistics.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Trigger immediate sync of all data.
  """
  def sync_now do
    GenServer.cast(__MODULE__, :sync_now)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    tenant_id = Keyword.get(config, :tenant_id) || Keyword.get(opts, :tenant_id)
    client_id = Keyword.get(config, :client_id) || Keyword.get(opts, :client_id)
    client_secret = Keyword.get(config, :client_secret) || Keyword.get(opts, :client_secret)
    poll_interval = Keyword.get(config, :poll_interval_seconds, 60) * 1000

    state = %{
      tenant_id: tenant_id,
      client_id: client_id,
      client_secret: client_secret,
      poll_interval: poll_interval,
      access_token: nil,
      token_expires_at: nil,
      enabled: !!(tenant_id && client_id && client_secret),
      last_sync: nil,
      last_sign_in_timestamp: nil,
      last_audit_timestamp: nil,
      stats: %{
        sign_ins_processed: 0,
        risky_users_found: 0,
        alerts_created: 0,
        last_error: nil
      }
    }

    if state.enabled do
      Logger.info("Azure AD integration enabled for tenant: #{tenant_id}")
      # Schedule first sync
      Process.send_after(self(), :sync, 1000)
    else
      Logger.warning("Azure AD integration disabled - missing configuration")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:get_sign_ins, opts}, _from, state) do
    result = if state.enabled do
      fetch_sign_ins(state, opts)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_risky_users, opts}, _from, state) do
    result = if state.enabled do
      fetch_risky_users(state, opts)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_conditional_access_policies, opts}, _from, state) do
    result = if state.enabled do
      fetch_conditional_access_policies(state, opts)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_service_principals, opts}, _from, state) do
    result = if state.enabled do
      fetch_service_principals(state, opts)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_directory_audits, opts}, _from, state) do
    result = if state.enabled do
      fetch_directory_audits(state, opts)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_user, user_id_or_upn}, _from, state) do
    result = if state.enabled do
      fetch_user(state, user_id_or_upn)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:confirm_user_compromised, user_id}, _from, state) do
    result = if state.enabled do
      confirm_compromised(state, user_id)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:dismiss_risky_user, user_id}, _from, state) do
    result = if state.enabled do
      dismiss_user_risk(state, user_id)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:force_password_reset, user_id}, _from, state) do
    result = if state.enabled do
      do_force_password_reset(state, user_id)
    else
      {:error, :not_configured}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      enabled: state.enabled,
      tenant_id: state.tenant_id,
      last_sync: state.last_sync,
      token_valid: token_valid?(state),
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_now, state) do
    send(self(), :sync)
    {:noreply, state}
  end

  @impl true
  def handle_info(:sync, state) do
    new_state = if state.enabled do
      perform_sync(state)
    else
      state
    end

    # Schedule next sync
    Process.send_after(self(), :sync, state.poll_interval)

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Sync
  # ============================================================================

  defp perform_sync(state) do
    Logger.debug("Starting Azure AD sync")

    state = ensure_valid_token(state)

    state
    |> sync_sign_ins()
    |> sync_risky_users()
    |> sync_directory_audits()
    |> Map.put(:last_sync, DateTime.utc_now())
  end

  defp sync_sign_ins(state) do
    opts = if state.last_sign_in_timestamp do
      [since: state.last_sign_in_timestamp, limit: 500]
    else
      [limit: 100]
    end

    case fetch_sign_ins(state, opts) do
      {:ok, sign_ins} ->
        Enum.each(sign_ins, &process_sign_in_event/1)

        # Update timestamp for next sync
        last_timestamp = sign_ins
        |> Enum.map(& &1["createdDateTime"])
        |> Enum.max(fn -> state.last_sign_in_timestamp end)

        new_stats = Map.update!(state.stats, :sign_ins_processed, &(&1 + length(sign_ins)))
        %{state | last_sign_in_timestamp: last_timestamp, stats: new_stats}

      {:error, reason} ->
        Logger.error("Failed to sync sign-ins: #{inspect(reason)}")
        new_stats = Map.put(state.stats, :last_error, "sign_ins: #{inspect(reason)}")
        %{state | stats: new_stats}
    end
  end

  defp sync_risky_users(state) do
    case fetch_risky_users(state, [risk_level: "high"]) do
      {:ok, risky_users} ->
        alerts_created = Enum.reduce(risky_users, 0, fn user, count ->
          if process_risky_user(user), do: count + 1, else: count
        end)

        new_stats = state.stats
        |> Map.update!(:risky_users_found, &(&1 + length(risky_users)))
        |> Map.update!(:alerts_created, &(&1 + alerts_created))

        %{state | stats: new_stats}

      {:error, reason} ->
        Logger.error("Failed to sync risky users: #{inspect(reason)}")
        new_stats = Map.put(state.stats, :last_error, "risky_users: #{inspect(reason)}")
        %{state | stats: new_stats}
    end
  end

  defp sync_directory_audits(state) do
    opts = if state.last_audit_timestamp do
      [since: state.last_audit_timestamp, limit: 500]
    else
      [limit: 100]
    end

    case fetch_directory_audits(state, opts) do
      {:ok, audits} ->
        Enum.each(audits, &process_directory_audit/1)

        last_timestamp = audits
        |> Enum.map(& &1["activityDateTime"])
        |> Enum.max(fn -> state.last_audit_timestamp end)

        %{state | last_audit_timestamp: last_timestamp}

      {:error, reason} ->
        Logger.error("Failed to sync directory audits: #{inspect(reason)}")
        new_stats = Map.put(state.stats, :last_error, "audits: #{inspect(reason)}")
        %{state | stats: new_stats}
    end
  end

  # ============================================================================
  # Private Functions - Event Processing
  # ============================================================================

  defp process_sign_in_event(sign_in) do
    # Determine if this sign-in is risky
    risk_level = get_in(sign_in, ["riskLevelDuringSignIn"]) || "none"
    risk_state = get_in(sign_in, ["riskState"]) || "none"
    status = get_in(sign_in, ["status", "errorCode"]) || 0

    # Calculate risk indicators
    risk_indicators = []
    |> maybe_add_risk_indicator(sign_in, "isInteractive", false, "non_interactive_sign_in")
    |> maybe_add_risk_indicator(sign_in, "riskDetail", "none", fn v -> v != "none" end, "risk_detected")
    |> check_suspicious_location(sign_in)
    |> check_unusual_user_agent(sign_in)

    # Create telemetry event
    event = %{
      event_type: @sign_in_event_type,
      timestamp: parse_datetime(sign_in["createdDateTime"]),
      user_principal_name: sign_in["userPrincipalName"],
      user_id: sign_in["userId"],
      app_display_name: sign_in["appDisplayName"],
      app_id: sign_in["appId"],
      ip_address: sign_in["ipAddress"],
      location: %{
        city: get_in(sign_in, ["location", "city"]),
        state: get_in(sign_in, ["location", "state"]),
        country: get_in(sign_in, ["location", "countryOrRegion"])
      },
      device_detail: sign_in["deviceDetail"],
      client_app_used: sign_in["clientAppUsed"],
      conditional_access_status: sign_in["conditionalAccessStatus"],
      is_interactive: sign_in["isInteractive"],
      risk_level_during_sign_in: risk_level,
      risk_state: risk_state,
      risk_detail: sign_in["riskDetail"],
      status_error_code: status,
      status_failure_reason: get_in(sign_in, ["status", "failureReason"]),
      resource_display_name: sign_in["resourceDisplayName"],
      mfa_detail: sign_in["mfaDetail"],
      risk_indicators: risk_indicators
    }

    # Broadcast event for real-time monitoring
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "identity:events",
      {:azure_ad_sign_in, event}
    )

    # Update user risk scoring
    if risk_level != "none" or status != 0 do
      RiskScoring.record_identity_event(sign_in["userPrincipalName"], event)
    end

    # Create alert for high-risk sign-ins
    if should_create_sign_in_alert?(sign_in) do
      create_sign_in_alert(sign_in, event)
    end
  end

  defp process_risky_user(user) do
    risk_level = user["riskLevel"]
    risk_state = user["riskState"]

    # Skip already remediated or dismissed users
    if risk_state in ["remediated", "dismissed"] do
      false
    else
      # Update user risk scoring
      RiskScoring.update_user_risk(user["userPrincipalName"], %{
        azure_ad_risk_level: risk_level,
        azure_ad_risk_state: risk_state,
        risk_last_updated: parse_datetime(user["riskLastUpdatedDateTime"]),
        risk_detail: user["riskDetail"]
      })

      # Create alert for high-risk users
      if risk_level == "high" and risk_state == "atRisk" do
        create_risky_user_alert(user)
        true
      else
        false
      end
    end
  end

  defp process_directory_audit(audit) do
    activity = audit["activityDisplayName"]
    category = audit["category"]

    # Track privilege changes
    privileged_activities = [
      "Add member to role",
      "Remove member from role",
      "Add owner to service principal",
      "Add app role assignment to service principal",
      "Add delegated permission grant",
      "Add application",
      "Update application",
      "Add service principal"
    ]

    event = %{
      event_type: @audit_event_type,
      timestamp: parse_datetime(audit["activityDateTime"]),
      activity: activity,
      category: category,
      initiated_by: audit["initiatedBy"],
      target_resources: audit["targetResources"],
      result: audit["result"],
      result_reason: audit["resultReason"],
      correlation_id: audit["correlationId"]
    }

    # Broadcast event
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "identity:events",
      {:azure_ad_audit, event}
    )

    # Create alert for privileged operations
    if activity in privileged_activities do
      create_privilege_change_alert(audit, event)
    end
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp fetch_sign_ins(state, opts) do
    state = ensure_valid_token(state)

    filter_parts = []

    filter_parts = if opts[:user_id] do
      ["userId eq '#{opts[:user_id]}'" | filter_parts]
    else
      filter_parts
    end

    filter_parts = if opts[:status] do
      status_filter = case opts[:status] do
        "success" -> "status/errorCode eq 0"
        "failure" -> "status/errorCode ne 0"
        _ -> nil
      end
      if status_filter, do: [status_filter | filter_parts], else: filter_parts
    else
      filter_parts
    end

    filter_parts = if opts[:since] do
      datetime = format_datetime(opts[:since])
      ["createdDateTime ge #{datetime}" | filter_parts]
    else
      filter_parts
    end

    query_params = []
    |> maybe_add_param("$filter", filter_parts, &Enum.join(&1, " and "))
    |> maybe_add_param("$top", opts[:limit] || 100, &to_string/1)
    |> maybe_add_param("$orderby", "createdDateTime desc", & &1)

    url = build_url(@graph_base_url, @sign_ins_endpoint, query_params)
    graph_request(state, :get, url)
  end

  defp fetch_risky_users(state, opts) do
    state = ensure_valid_token(state)

    filter_parts = []

    filter_parts = if opts[:risk_level] do
      ["riskLevel eq '#{opts[:risk_level]}'" | filter_parts]
    else
      filter_parts
    end

    filter_parts = if opts[:risk_state] do
      ["riskState eq '#{opts[:risk_state]}'" | filter_parts]
    else
      filter_parts
    end

    query_params = []
    |> maybe_add_param("$filter", filter_parts, &Enum.join(&1, " and "))
    |> maybe_add_param("$top", opts[:limit] || 100, &to_string/1)

    url = build_url(@graph_beta_url, @risky_users_endpoint, query_params)
    graph_request(state, :get, url)
  end

  defp fetch_conditional_access_policies(state, _opts) do
    state = ensure_valid_token(state)
    url = build_url(@graph_base_url, @conditional_access_endpoint, [])
    graph_request(state, :get, url)
  end

  defp fetch_service_principals(state, opts) do
    state = ensure_valid_token(state)

    filter_parts = []

    filter_parts = if opts[:app_id] do
      ["appId eq '#{opts[:app_id]}'" | filter_parts]
    else
      filter_parts
    end

    filter_parts = if opts[:display_name] do
      ["startswith(displayName, '#{opts[:display_name]}')" | filter_parts]
    else
      filter_parts
    end

    query_params = []
    |> maybe_add_param("$filter", filter_parts, &Enum.join(&1, " and "))
    |> maybe_add_param("$top", opts[:limit] || 100, &to_string/1)

    url = build_url(@graph_base_url, @service_principals_endpoint, query_params)
    graph_request(state, :get, url)
  end

  defp fetch_directory_audits(state, opts) do
    state = ensure_valid_token(state)

    filter_parts = []

    filter_parts = if opts[:activity_display_name] do
      ["activityDisplayName eq '#{opts[:activity_display_name]}'" | filter_parts]
    else
      filter_parts
    end

    filter_parts = if opts[:category] do
      ["category eq '#{opts[:category]}'" | filter_parts]
    else
      filter_parts
    end

    filter_parts = if opts[:since] do
      datetime = format_datetime(opts[:since])
      ["activityDateTime ge #{datetime}" | filter_parts]
    else
      filter_parts
    end

    query_params = []
    |> maybe_add_param("$filter", filter_parts, &Enum.join(&1, " and "))
    |> maybe_add_param("$top", opts[:limit] || 100, &to_string/1)
    |> maybe_add_param("$orderby", "activityDateTime desc", & &1)

    url = build_url(@graph_base_url, @directory_audits_endpoint, query_params)
    graph_request(state, :get, url)
  end

  defp fetch_user(state, user_id_or_upn) do
    state = ensure_valid_token(state)
    url = "#{@graph_base_url}/users/#{URI.encode(user_id_or_upn)}"

    case graph_request(state, :get, url) do
      {:ok, users} when is_list(users) -> {:ok, List.first(users)}
      {:ok, user} -> {:ok, user}
      error -> error
    end
  end

  defp confirm_compromised(state, user_id) do
    state = ensure_valid_token(state)
    url = "#{@graph_beta_url}/identityProtection/riskyUsers/confirmCompromised"
    body = %{userIds: [user_id]}
    graph_request(state, :post, url, body)
  end

  defp dismiss_user_risk(state, user_id) do
    state = ensure_valid_token(state)
    url = "#{@graph_beta_url}/identityProtection/riskyUsers/dismiss"
    body = %{userIds: [user_id]}
    graph_request(state, :post, url, body)
  end

  defp do_force_password_reset(state, user_id) do
    state = ensure_valid_token(state)
    url = "#{@graph_base_url}/users/#{user_id}"
    body = %{
      passwordProfile: %{
        forceChangePasswordNextSignIn: true
      }
    }
    graph_request(state, :patch, url, body)
  end

  defp graph_request(state, method, url, body \\ nil) do
    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Content-Type", "application/json"}
    ]

    opts = [receive_timeout: 30_000]

    result = case method do
      :get -> Req.get(url, headers: headers, opts: opts)
      :post -> Req.post(url, headers: headers, json: body, opts: opts)
      :patch -> Req.patch(url, headers: headers, json: body, opts: opts)
      :delete -> Req.delete(url, headers: headers, opts: opts)
    end

    case result do
      {:ok, %{status: status, body: response_body}} when status in 200..299 ->
        if is_map(response_body) and Map.has_key?(response_body, "value") do
          {:ok, response_body["value"]}
        else
          {:ok, response_body}
        end

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, %{status: status, body: body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private Functions - Token Management
  # ============================================================================

  defp ensure_valid_token(%{access_token: nil} = state) do
    refresh_token(state)
  end

  defp ensure_valid_token(state) do
    if token_valid?(state) do
      state
    else
      refresh_token(state)
    end
  end

  defp token_valid?(state) do
    state.access_token != nil and
    state.token_expires_at != nil and
    DateTime.compare(state.token_expires_at, DateTime.utc_now()) == :gt
  end

  defp refresh_token(state) do
    url = String.replace(@token_url, "{tenant_id}", state.tenant_id)

    body = URI.encode_query(%{
      "client_id" => state.client_id,
      "client_secret" => state.client_secret,
      "scope" => "https://graph.microsoft.com/.default",
      "grant_type" => "client_credentials"
    })

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: response}} ->
        access_token = response["access_token"]
        expires_in = response["expires_in"] || 3600
        expires_at = DateTime.utc_now() |> DateTime.add(expires_in - 60, :second)

        Logger.debug("Azure AD token refreshed, expires at #{expires_at}")
        %{state | access_token: access_token, token_expires_at: expires_at}

      {:ok, %{status: status, body: body}} ->
        Logger.error("Failed to refresh Azure AD token: #{status} - #{inspect(body)}")
        state

      {:error, reason} ->
        Logger.error("Failed to refresh Azure AD token: #{inspect(reason)}")
        state
    end
  end

  # ============================================================================
  # Private Functions - Alert Creation
  # ============================================================================

  defp should_create_sign_in_alert?(sign_in) do
    risk_level = get_in(sign_in, ["riskLevelDuringSignIn"]) || "none"
    status = get_in(sign_in, ["status", "errorCode"]) || 0

    # Create alert for high risk or repeated failures
    risk_level in ["high", "medium"] or
    (status != 0 and get_in(sign_in, ["status", "failureReason"]) =~ ~r/password|credential|locked/i)
  end

  defp create_sign_in_alert(sign_in, event) do
    risk_level = get_in(sign_in, ["riskLevelDuringSignIn"]) || "none"
    risk_detail = sign_in["riskDetail"] || "Unknown"

    severity = case risk_level do
      "high" -> "critical"
      "medium" -> "high"
      _ -> "medium"
    end

    mitre_techniques = Map.get(@mitre_mapping, risk_detail, ["T1078"])

    alert_params = %{
      title: "Risky Azure AD Sign-in: #{sign_in["userPrincipalName"]}",
      description: """
      Risky sign-in detected for user #{sign_in["userPrincipalName"]}.

      Risk Level: #{risk_level}
      Risk Detail: #{risk_detail}
      IP Address: #{sign_in["ipAddress"]}
      Location: #{get_in(sign_in, ["location", "city"])}, #{get_in(sign_in, ["location", "countryOrRegion"])}
      Application: #{sign_in["appDisplayName"]}
      Client: #{sign_in["clientAppUsed"]}
      """,
      severity: severity,
      source: "azure_ad",
      source_event_id: sign_in["id"],
      mitre_tactics: ["Initial Access", "Credential Access"],
      mitre_techniques: mitre_techniques,
      evidence: %{
        identity: %{
          user_principal_name: sign_in["userPrincipalName"],
          user_id: sign_in["userId"],
          ip_address: sign_in["ipAddress"],
          location: event.location,
          risk_level: risk_level,
          risk_detail: risk_detail
        }
      }
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.info("Created alert for risky Azure AD sign-in: #{alert.id}")
      {:error, reason} ->
        Logger.error("Failed to create sign-in alert: #{inspect(reason)}")
    end
  end

  defp create_risky_user_alert(user) do
    alert_params = %{
      title: "High Risk User Detected: #{user["userPrincipalName"]}",
      description: """
      Azure AD Identity Protection has flagged #{user["userPrincipalName"]} as high risk.

      Risk Level: #{user["riskLevel"]}
      Risk State: #{user["riskState"]}
      Risk Detail: #{user["riskDetail"]}
      Risk Last Updated: #{user["riskLastUpdatedDateTime"]}

      Recommended Actions:
      - Review user's recent sign-in activity
      - Consider forcing password reset
      - Review MFA registration status
      - Check for leaked credentials
      """,
      severity: "critical",
      source: "azure_ad_identity_protection",
      source_event_id: user["id"],
      mitre_tactics: ["Credential Access", "Initial Access"],
      mitre_techniques: @mitre_mapping[user["riskDetail"]] || ["T1078"],
      evidence: %{
        identity: %{
          user_principal_name: user["userPrincipalName"],
          user_id: user["id"],
          risk_level: user["riskLevel"],
          risk_state: user["riskState"],
          risk_detail: user["riskDetail"]
        }
      }
    }

    Alerts.create_alert(alert_params)
  end

  defp create_privilege_change_alert(audit, event) do
    alert_params = %{
      title: "Privilege Change: #{audit["activityDisplayName"]}",
      description: """
      Privileged operation detected in Azure AD.

      Activity: #{audit["activityDisplayName"]}
      Category: #{audit["category"]}
      Initiated By: #{inspect(audit["initiatedBy"])}
      Target: #{inspect(audit["targetResources"])}
      Result: #{audit["result"]}
      """,
      severity: "high",
      source: "azure_ad_audit",
      source_event_id: audit["id"],
      mitre_tactics: ["Persistence", "Privilege Escalation"],
      mitre_techniques: ["T1098", "T1078.002"],
      evidence: %{
        identity: %{
          activity: audit["activityDisplayName"],
          initiated_by: audit["initiatedBy"],
          target_resources: audit["targetResources"]
        }
      }
    }

    Alerts.create_alert(alert_params)
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp build_url(base, endpoint, query_params) do
    query_string = if Enum.empty?(query_params) do
      ""
    else
      "?" <> URI.encode_query(query_params)
    end

    base <> endpoint <> query_string
  end

  defp maybe_add_param(params, _key, nil, _formatter), do: params
  defp maybe_add_param(params, _key, [], _formatter), do: params
  defp maybe_add_param(params, key, value, formatter) do
    [{key, formatter.(value)} | params]
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(datetime_string) when is_binary(datetime_string) do
    case DateTime.from_iso8601(datetime_string) do
      {:ok, datetime, _offset} -> datetime
      _ -> nil
    end
  end

  defp format_datetime(%DateTime{} = datetime) do
    DateTime.to_iso8601(datetime)
  end
  defp format_datetime(datetime_string) when is_binary(datetime_string) do
    datetime_string
  end

  defp maybe_add_risk_indicator(indicators, sign_in, key, default, indicator) do
    value = Map.get(sign_in, key, default)
    if value != default do
      [indicator | indicators]
    else
      indicators
    end
  end

  defp maybe_add_risk_indicator(indicators, sign_in, key, default, check_fn, indicator) when is_function(check_fn) do
    value = Map.get(sign_in, key, default)
    if check_fn.(value) do
      [indicator | indicators]
    else
      indicators
    end
  end

  defp check_suspicious_location(indicators, sign_in) do
    country = get_in(sign_in, ["location", "countryOrRegion"])

    # High-risk countries (configurable)
    high_risk_countries = Application.get_env(:tamandua_server, :high_risk_countries, ["RU", "CN", "KP", "IR"])

    if country in high_risk_countries do
      ["high_risk_country" | indicators]
    else
      indicators
    end
  end

  defp check_unusual_user_agent(indicators, sign_in) do
    browser = get_in(sign_in, ["deviceDetail", "browser"]) || ""
    os = get_in(sign_in, ["deviceDetail", "operatingSystem"]) || ""

    suspicious_patterns = [
      ~r/python/i,
      ~r/curl/i,
      ~r/wget/i,
      ~r/powershell/i,
      ~r/bot/i,
      ~r/scraper/i
    ]

    user_agent = "#{browser} #{os}"

    if Enum.any?(suspicious_patterns, &Regex.match?(&1, user_agent)) do
      ["suspicious_user_agent" | indicators]
    else
      indicators
    end
  end
end
