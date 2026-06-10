defmodule TamanduaServer.Licensing.License do
  @moduledoc """
  Enterprise license management system.

  Supports:
  - Per-agent licensing
  - Feature licensing
  - Usage metering
  - License enforcement
  - Grace periods
  - Multi-tenant licensing for MSSPs

  ## License Types

  - `:trial` - 14-day trial, 10 agents, basic features
  - `:pro` - Annual subscription, 100 agents, advanced features
  - `:enterprise` - Custom terms, unlimited agents, all features
  - `:mssp` - MSSP partner license with sub-licensing capabilities

  ## License Key Format

  License keys are signed JWTs containing:
  - Organization ID
  - License tier
  - Feature flags
  - Agent limit
  - Expiration date
  - Signature
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Licensing.{LicenseKey, LicenseUsage, FeatureLicense}
  alias TamanduaServer.Accounts.Organization

  import Ecto.Query

  @cache_table :license_cache
  @cache_ttl_seconds 60
  @grace_period_days 7
  @license_secret Application.compile_env(:tamandua_server, :license_secret, "tamandua_license_secret_key_2026")

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get active license for an organization.
  """
  def get_license(organization_id) do
    case get_cached_license(organization_id) do
      nil -> {:error, :no_license}
      license -> {:ok, license}
    end
  end

  @doc """
  Validate a license key and activate it for an organization.
  """
  def activate_license(organization_id, license_key) do
    with {:ok, claims} <- decode_license_key(license_key),
         :ok <- validate_claims(claims, organization_id),
         {:ok, license} <- store_license(organization_id, license_key, claims) do
      invalidate_cache(organization_id)
      {:ok, license}
    end
  end

  @doc """
  Deactivate a license (e.g., for transfer).
  """
  def deactivate_license(organization_id) do
    case Repo.get_by(LicenseKey, organization_id: organization_id, is_active: true) do
      nil ->
        {:ok, :no_active_license}

      license ->
        license
        |> LicenseKey.changeset(%{is_active: false, deactivated_at: DateTime.utc_now()})
        |> Repo.update()
        |> tap(fn _ -> invalidate_cache(organization_id) end)
    end
  end

  @doc """
  Check if organization has a valid license.
  """
  def valid_license?(organization_id) do
    case get_license(organization_id) do
      {:ok, license} -> license_active?(license)
      _ -> false
    end
  end

  @doc """
  Check if license allows adding more agents.
  """
  def can_add_agent?(organization_id) do
    with {:ok, license} <- get_license(organization_id),
         true <- license_active?(license),
         current_count <- get_agent_count(organization_id) do
      current_count < license.agent_limit
    else
      _ -> false
    end
  end

  @doc """
  Check if a specific feature is licensed.
  """
  def feature_enabled?(organization_id, feature) when is_atom(feature) do
    with {:ok, license} <- get_license(organization_id),
         true <- license_active?(license) do
      feature in (license.features || [])
    else
      _ -> false
    end
  end

  @doc """
  Get all licensed features for an organization.
  """
  def get_features(organization_id) do
    case get_license(organization_id) do
      {:ok, license} ->
        if license_active?(license) do
          {:ok, license.features || []}
        else
          {:ok, []}
        end

      _ ->
        {:ok, []}
    end
  end

  @doc """
  Get license usage statistics.
  """
  def get_usage(organization_id) do
    license = case get_license(organization_id) do
      {:ok, l} -> l
      _ -> nil
    end

    agent_count = get_agent_count(organization_id)
    user_count = get_user_count(organization_id)

    %{
      organization_id: organization_id,
      license_tier: license && license.tier,
      license_status: get_license_status(license),
      agent_count: agent_count,
      agent_limit: license && license.agent_limit,
      agent_usage_percent: if(license && license.agent_limit > 0, do: round(agent_count / license.agent_limit * 100), else: 0),
      user_count: user_count,
      features: license && license.features || [],
      expires_at: license && license.expires_at,
      days_remaining: get_days_remaining(license),
      in_grace_period: in_grace_period?(license)
    }
  end

  @doc """
  Record usage metrics for billing/metering.
  """
  def record_usage(organization_id, metric_type, value, metadata \\ %{}) do
    %LicenseUsage{}
    |> LicenseUsage.changeset(%{
      organization_id: organization_id,
      metric_type: metric_type,
      value: value,
      metadata: metadata,
      recorded_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  @doc """
  Get usage metrics for billing period.
  """
  def get_usage_metrics(organization_id, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, beginning_of_month())
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    from(u in LicenseUsage,
      where: u.organization_id == ^organization_id,
      where: u.recorded_at >= ^date_from and u.recorded_at <= ^date_to,
      group_by: u.metric_type,
      select: %{
        metric_type: u.metric_type,
        total: sum(u.value),
        count: count()
      }
    )
    |> Repo.all()
  end

  @doc """
  Generate a new license key.

  This should only be called by authorized systems (licensing portal).
  """
  def generate_license_key(attrs) do
    claims = %{
      "oid" => attrs[:organization_id],
      "tier" => to_string(attrs[:tier] || :pro),
      "agent_limit" => attrs[:agent_limit] || 100,
      "features" => Enum.map(attrs[:features] || default_features(attrs[:tier]), &to_string/1),
      "iat" => System.system_time(:second),
      "exp" => DateTime.to_unix(attrs[:expires_at] || default_expiration()),
      "nonce" => :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    }

    token = encode_license_key(claims)
    {:ok, token, claims}
  end

  @doc """
  Verify a license key without activating it.
  """
  def verify_license_key(license_key) do
    decode_license_key(license_key)
  end

  @doc """
  Get license tier limits.
  """
  def tier_limits(tier) do
    case tier do
      :trial ->
        %{
          agent_limit: 10,
          user_limit: 5,
          retention_days: 7,
          features: [:detection, :dashboards, :alerts, :basic_response]
        }

      :pro ->
        %{
          agent_limit: 100,
          user_limit: 25,
          retention_days: 90,
          features: [:detection, :dashboards, :alerts, :basic_response, :hunting, :behavioral_analytics, :playbooks, :api_access]
        }

      :enterprise ->
        %{
          agent_limit: 10_000,
          user_limit: :unlimited,
          retention_days: 365,
          features: [:detection, :dashboards, :alerts, :basic_response, :hunting, :behavioral_analytics, :playbooks, :api_access, :custom_integrations, :sso, :advanced_forensics, :live_response, :compliance]
        }

      :mssp ->
        %{
          agent_limit: 100_000,
          user_limit: :unlimited,
          retention_days: 365,
          features: [:detection, :dashboards, :alerts, :basic_response, :hunting, :behavioral_analytics, :playbooks, :api_access, :custom_integrations, :sso, :advanced_forensics, :live_response, :compliance, :mssp_portal, :white_labeling, :sub_licensing]
        }

      _ ->
        tier_limits(:trial)
    end
  end

  @doc """
  Check license compliance across all tenants (for MSSP).
  """
  def check_compliance_all do
    from(o in Organization,
      where: o.is_active == true,
      select: o.id
    )
    |> Repo.all()
    |> Enum.map(fn org_id ->
      usage = get_usage(org_id)
      %{
        organization_id: org_id,
        compliant: usage.license_status == :active,
        issues: get_compliance_issues(usage)
      }
    end)
  end

  # Server Callbacks

  @notification_thresholds [30, 14, 7, 0]

  @impl true
  def init(_opts) do
    :ets.new(@cache_table, [:set, :public, :named_table, read_concurrency: true])

    # Schedule periodic license checks
    :timer.send_interval(3600_000, :check_expirations)

    Logger.info("License management service started")
    {:ok, %{sent_notifications: MapSet.new()}}
  end

  @impl true
  def handle_cast({:invalidate, org_id}, state) do
    :ets.delete(@cache_table, org_id)
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_expirations, state) do
    new_state = check_expiring_licenses(state)
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp get_cached_license(organization_id) do
    case :ets.lookup(@cache_table, organization_id) do
      [{^organization_id, license, cached_at}] ->
        if System.system_time(:second) - cached_at < @cache_ttl_seconds do
          license
        else
          load_and_cache_license(organization_id)
        end

      [] ->
        load_and_cache_license(organization_id)
    end
  end

  defp load_and_cache_license(organization_id) do
    case Repo.one(from l in LicenseKey,
      where: l.organization_id == ^organization_id,
      where: l.is_active == true,
      order_by: [desc: l.inserted_at],
      limit: 1
    ) do
      nil ->
        nil

      license ->
        :ets.insert(@cache_table, {organization_id, license, System.system_time(:second)})
        license
    end
  end

  defp invalidate_cache(organization_id) do
    GenServer.cast(__MODULE__, {:invalidate, organization_id})
  end

  defp decode_license_key(key) do
    try do
      # Split the key into parts
      [header_b64, payload_b64, signature_b64] = String.split(key, ".")

      # Decode and parse
      payload = payload_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()

      # Verify signature
      signing_input = "#{header_b64}.#{payload_b64}"
      expected_sig = :crypto.mac(:hmac, :sha256, @license_secret, signing_input)
                     |> Base.url_encode64(padding: false)

      if Plug.Crypto.secure_compare(signature_b64, expected_sig) do
        {:ok, payload}
      else
        {:error, :invalid_signature}
      end
    rescue
      _ -> {:error, :invalid_format}
    end
  end

  defp encode_license_key(claims) do
    header = %{"alg" => "HS256", "typ" => "LIC"} |> Jason.encode!() |> Base.url_encode64(padding: false)
    payload = claims |> Jason.encode!() |> Base.url_encode64(padding: false)

    signing_input = "#{header}.#{payload}"
    signature = :crypto.mac(:hmac, :sha256, @license_secret, signing_input)
                |> Base.url_encode64(padding: false)

    "#{header}.#{payload}.#{signature}"
  end

  defp validate_claims(claims, organization_id) do
    cond do
      claims["oid"] && claims["oid"] != organization_id ->
        {:error, :organization_mismatch}

      claims["exp"] && claims["exp"] < System.system_time(:second) ->
        {:error, :license_expired}

      true ->
        :ok
    end
  end

  defp store_license(organization_id, license_key, claims) do
    tier = String.to_existing_atom(claims["tier"])
    features = Enum.map(claims["features"] || [], &String.to_existing_atom/1)

    attrs = %{
      organization_id: organization_id,
      license_key: license_key,
      tier: tier,
      agent_limit: claims["agent_limit"],
      features: features,
      issued_at: DateTime.from_unix!(claims["iat"]),
      expires_at: DateTime.from_unix!(claims["exp"]),
      is_active: true
    }

    # Deactivate any existing licenses
    from(l in LicenseKey,
      where: l.organization_id == ^organization_id and l.is_active == true
    )
    |> Repo.update_all(set: [is_active: false])

    %LicenseKey{}
    |> LicenseKey.changeset(attrs)
    |> Repo.insert()
  end

  defp license_active?(nil), do: false

  defp license_active?(license) do
    now = DateTime.utc_now()
    grace_end = DateTime.add(license.expires_at, @grace_period_days, :day)

    license.is_active && DateTime.compare(now, grace_end) == :lt
  end

  defp in_grace_period?(nil), do: false

  defp in_grace_period?(license) do
    now = DateTime.utc_now()
    grace_end = DateTime.add(license.expires_at, @grace_period_days, :day)

    DateTime.compare(now, license.expires_at) == :gt &&
      DateTime.compare(now, grace_end) == :lt
  end

  defp get_license_status(nil), do: :no_license

  defp get_license_status(license) do
    now = DateTime.utc_now()
    grace_end = DateTime.add(license.expires_at, @grace_period_days, :day)

    cond do
      !license.is_active -> :inactive
      DateTime.compare(now, grace_end) == :gt -> :expired
      DateTime.compare(now, license.expires_at) == :gt -> :grace_period
      true -> :active
    end
  end

  defp get_days_remaining(nil), do: 0

  defp get_days_remaining(license) do
    now = DateTime.utc_now()
    diff = DateTime.diff(license.expires_at, now, :day)
    max(diff, 0)
  end

  defp get_agent_count(organization_id) do
    from(a in TamanduaServer.Agents.Agent,
      where: a.organization_id == ^organization_id,
      select: count()
    )
    |> Repo.one()
  end

  defp get_user_count(organization_id) do
    from(u in TamanduaServer.Accounts.User,
      where: u.organization_id == ^organization_id,
      select: count()
    )
    |> Repo.one()
  end

  defp default_features(:trial), do: [:detection, :dashboards, :alerts, :basic_response]
  defp default_features(:pro), do: [:detection, :dashboards, :alerts, :basic_response, :hunting, :behavioral_analytics, :playbooks, :api_access]
  defp default_features(:enterprise), do: [:detection, :dashboards, :alerts, :basic_response, :hunting, :behavioral_analytics, :playbooks, :api_access, :custom_integrations, :sso, :advanced_forensics, :live_response, :compliance]
  defp default_features(:mssp), do: default_features(:enterprise) ++ [:mssp_portal, :white_labeling, :sub_licensing]
  defp default_features(_), do: default_features(:trial)

  defp default_expiration do
    DateTime.add(DateTime.utc_now(), 365, :day)
  end

  defp beginning_of_month do
    now = DateTime.utc_now()
    {:ok, date} = Date.new(now.year, now.month, 1)
    DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
  end

  defp get_compliance_issues(usage) do
    issues = []

    issues = if usage.license_status != :active do
      ["License is #{usage.license_status}" | issues]
    else
      issues
    end

    issues = if usage.agent_usage_percent > 90 do
      ["Agent usage at #{usage.agent_usage_percent}% of limit" | issues]
    else
      issues
    end

    issues = if usage.days_remaining && usage.days_remaining < 30 do
      ["License expires in #{usage.days_remaining} days" | issues]
    else
      issues
    end

    issues
  end

  defp check_expiring_licenses(state) do
    # Find licenses expiring in next 30 days
    thirty_days = DateTime.add(DateTime.utc_now(), 30, :day)

    expiring = from(l in LicenseKey,
      where: l.is_active == true,
      where: l.expires_at <= ^thirty_days,
      preload: [:organization]
    )
    |> Repo.all()

    Enum.reduce(expiring, state, fn license, acc_state ->
      days = get_days_remaining(license)
      Logger.warning("License expiring: org=#{license.organization_id} days_remaining=#{days}")

      send_expiration_notifications(license, days, acc_state)
    end)
  end

  defp send_expiration_notifications(license, days_remaining, state) do
    # Determine which notification threshold applies
    threshold = Enum.find(@notification_thresholds, fn threshold ->
      days_remaining <= threshold
    end)

    case threshold do
      nil ->
        # No threshold matched (should not happen since we query <=30 days,
        # but guard defensively)
        state

      matched_threshold ->
        notification_key = {license.id, matched_threshold}

        if MapSet.member?(state.sent_notifications, notification_key) do
          # Already sent this notification, skip
          state
        else
          urgency = notification_urgency(matched_threshold)
          send_license_notification(license, days_remaining, urgency)

          %{state | sent_notifications: MapSet.put(state.sent_notifications, notification_key)}
        end
    end
  end

  defp notification_urgency(0), do: :expired
  defp notification_urgency(7), do: :critical
  defp notification_urgency(14), do: :urgent
  defp notification_urgency(30), do: :warning
  defp notification_urgency(_), do: :warning

  defp send_license_notification(license, days_remaining, urgency) do
    org_name = case license.organization do
      %{name: name} when is_binary(name) -> name
      _ -> license.organization_id
    end

    {subject, body_text, body_html} = build_notification_content(
      org_name,
      license.tier,
      license.expires_at,
      days_remaining,
      urgency
    )

    mailer_available = Code.ensure_loaded?(TamanduaServer.Mailer) and
                       function_exported?(TamanduaServer.Mailer, :deliver, 1)

    admin_emails = get_org_admin_emails(license.organization_id)

    if mailer_available and length(admin_emails) > 0 do
      send_notification_email(admin_emails, subject, body_text, body_html, urgency)
    else
      log_notification_fallback(org_name, days_remaining, urgency, admin_emails)
    end
  end

  defp build_notification_content(org_name, tier, expires_at, days_remaining, urgency) do
    expires_str = DateTime.to_iso8601(expires_at)
    tier_str = to_string(tier) |> String.capitalize()

    {subject, intro} = case urgency do
      :expired ->
        {"[Tamandua EDR] License Expired - #{org_name}",
         "Your Tamandua EDR #{tier_str} license has expired."}

      :critical ->
        {"[CRITICAL] Tamandua EDR License Expires in #{days_remaining} Days - #{org_name}",
         "Your Tamandua EDR #{tier_str} license expires in #{days_remaining} days. Immediate action required."}

      :urgent ->
        {"[URGENT] Tamandua EDR License Expires in #{days_remaining} Days - #{org_name}",
         "Your Tamandua EDR #{tier_str} license expires in #{days_remaining} days. Please renew soon."}

      :warning ->
        {"[Warning] Tamandua EDR License Expires in #{days_remaining} Days - #{org_name}",
         "Your Tamandua EDR #{tier_str} license expires in #{days_remaining} days."}
    end

    grace_note = if urgency == :expired do
      "A #{@grace_period_days}-day grace period is in effect, after which EDR protection will be disabled."
    else
      "After expiration, a #{@grace_period_days}-day grace period applies before EDR protection is disabled."
    end

    body_text = """
    #{intro}

    Organization: #{org_name}
    License Tier: #{tier_str}
    Expiration Date: #{expires_str}
    Days Remaining: #{days_remaining}

    #{grace_note}

    Please contact your account representative or visit the licensing portal to renew.

    -- Tamandua EDR Platform
    """

    body_html = """
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
      <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #{urgency_color(urgency)};">#{subject}</h2>
        <p>#{intro}</p>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Organization:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">#{org_name}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>License Tier:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">#{tier_str}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Expiration Date:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">#{expires_str}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Days Remaining:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #{urgency_color(urgency)}; font-weight: bold;">#{days_remaining}</td></tr>
        </table>
        <p style="background: #f9f9f9; padding: 12px; border-left: 4px solid #{urgency_color(urgency)};">#{grace_note}</p>
        <p>Please contact your account representative or visit the licensing portal to renew.</p>
        <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;" />
        <p style="font-size: 12px; color: #999;">Tamandua EDR Platform - Enterprise License Management</p>
      </div>
    </body>
    </html>
    """

    {subject, body_text, body_html}
  end

  defp urgency_color(:expired), do: "#dc3545"
  defp urgency_color(:critical), do: "#dc3545"
  defp urgency_color(:urgent), do: "#fd7e14"
  defp urgency_color(:warning), do: "#ffc107"

  defp send_notification_email(recipients, subject, body_text, body_html, urgency) do
    try do
      from_name = case urgency do
        u when u in [:expired, :critical] -> "Tamandua EDR (CRITICAL)"
        :urgent -> "Tamandua EDR (URGENT)"
        _ -> "Tamandua EDR"
      end

      from_addr = Application.get_env(:tamandua_server, :license_notification_from,
                    "licensing@tamandua-edr.local")

      email = Swoosh.Email.new()
      |> Swoosh.Email.from({from_name, from_addr})
      |> Swoosh.Email.subject(subject)
      |> Swoosh.Email.html_body(body_html)
      |> Swoosh.Email.text_body(body_text)

      email = Enum.reduce(recipients, email, fn recipient, acc ->
        Swoosh.Email.to(acc, recipient)
      end)

      case TamanduaServer.Mailer.deliver(email) do
        {:ok, _metadata} ->
          Logger.info("License expiration notification sent to #{Enum.join(recipients, ", ")} (#{urgency})")

        {:error, reason} ->
          Logger.error("License notification email delivery failed: #{inspect(reason)}")
          log_notification_fallback("organization", 0, urgency, recipients)
      end
    rescue
      e ->
        Logger.error("License notification email error: #{Exception.message(e)}")
        log_notification_fallback("organization", 0, urgency, recipients)
    end
  end

  defp log_notification_fallback(org_name, days_remaining, urgency, admin_emails) do
    case urgency do
      :expired ->
        Logger.error("[LICENSE EXPIRED] Organization '#{org_name}' license has expired. " <>
          "Grace period of #{@grace_period_days} days in effect. " <>
          "Admin contacts: #{inspect(admin_emails)}")

      :critical ->
        Logger.error("[LICENSE CRITICAL] Organization '#{org_name}' license expires in " <>
          "#{days_remaining} days. Immediate renewal required. " <>
          "Admin contacts: #{inspect(admin_emails)}")

      :urgent ->
        Logger.warning("[LICENSE URGENT] Organization '#{org_name}' license expires in " <>
          "#{days_remaining} days. Renewal recommended. " <>
          "Admin contacts: #{inspect(admin_emails)}")

      :warning ->
        Logger.warning("[LICENSE WARNING] Organization '#{org_name}' license expires in " <>
          "#{days_remaining} days. " <>
          "Admin contacts: #{inspect(admin_emails)}")
    end
  end

  defp get_org_admin_emails(organization_id) do
    try do
      from(u in TamanduaServer.Accounts.User,
        where: u.organization_id == ^organization_id,
        where: u.role in ["admin", "owner"],
        select: u.email
      )
      |> Repo.all()
    rescue
      _ -> []
    end
  end
end
