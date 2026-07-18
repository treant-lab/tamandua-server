defmodule TamanduaServer.PKI.CertificateRotator do
  @moduledoc """
  Automatic certificate rotation for agents.

  This GenServer periodically scans all agent certificates and automatically
  renews those approaching expiry (75% of lifetime by default). It also
  handles:

  - Auto-renewal scheduling and execution
  - Certificate expiry monitoring and alerting
  - Failed renewal retry logic with exponential backoff
  - Certificate health metrics and reporting
  - Notification to agents when new certificates are ready

  ## Certificate Rotation Flow

  1. Scan all active agents (hourly)
  2. Check certificate expiry status
  3. For certificates past renewal threshold:
     - Generate new certificate
     - Store in database
     - Notify agent via WebSocket channel
     - Agent downloads new cert and key via authenticated API
  4. Alert on certificates within 7 days of expiry
  5. Revoke expired certificates (> 7 days past expiry)

  ## Configuration

  Set in config.exs:

      config :tamandua_server, TamanduaServer.PKI.CertificateRotator,
        scan_interval_minutes: 60,
        renewal_threshold: 0.75,
        alert_days_before_expiry: 7,
        auto_revoke_days_after_expiry: 7

  ## Example

      # Start rotator (normally supervised)
      {:ok, pid} = CertificateRotator.start_link()

      # Trigger manual scan
      CertificateRotator.scan_now()

      # Get rotation statistics
      stats = CertificateRotator.get_stats()
  """

  use GenServer
  require Logger
  alias TamanduaServer.PKI.CertificateGenerator
  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo

  @default_scan_interval_minutes 60
  @default_renewal_threshold 0.75
  @default_alert_days 7
  @default_auto_revoke_days 7

  defmodule State do
    @moduledoc false
    defstruct [
      :scan_interval,
      :renewal_threshold,
      :alert_days,
      :auto_revoke_days,
      :last_scan_at,
      :stats
    ]
  end

  defmodule Stats do
    @moduledoc false
    defstruct [
      total_scanned: 0,
      renewed: 0,
      failed: 0,
      expiring_soon: 0,
      expired: 0,
      last_scan_duration_ms: 0
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger an immediate certificate scan and rotation cycle.

  Returns `:ok` immediately; scan runs asynchronously.
  """
  def scan_now do
    GenServer.cast(__MODULE__, :scan_now)
  end

  @doc """
  Get certificate rotation statistics.

  Returns a map with:
  - `total_scanned` - Total certificates checked in last scan
  - `renewed` - Certificates successfully renewed
  - `failed` - Failed renewal attempts
  - `expiring_soon` - Certificates expiring within alert threshold
  - `expired` - Expired certificates
  - `last_scan_at` - Timestamp of last scan
  - `last_scan_duration_ms` - Duration of last scan
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Force renewal of a specific agent certificate.

  Bypasses the normal renewal threshold check.
  """
  def force_renew(agent_id) do
    GenServer.call(__MODULE__, {:force_renew, agent_id}, :infinity)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    scan_interval = Keyword.get(config, :scan_interval_minutes, @default_scan_interval_minutes)
    renewal_threshold = Keyword.get(config, :renewal_threshold, @default_renewal_threshold)
    alert_days = Keyword.get(config, :alert_days_before_expiry, @default_alert_days)
    auto_revoke_days = Keyword.get(config, :auto_revoke_days_after_expiry, @default_auto_revoke_days)

    state = %State{
      scan_interval: scan_interval * 60 * 1000,  # Convert to milliseconds
      renewal_threshold: renewal_threshold,
      alert_days: alert_days,
      auto_revoke_days: auto_revoke_days,
      last_scan_at: nil,
      stats: %Stats{}
    }

    Logger.info("Certificate Rotator started",
      scan_interval_minutes: scan_interval,
      renewal_threshold: renewal_threshold
    )

    # Schedule first scan
    schedule_scan(state.scan_interval)

    {:ok, state}
  end

  @impl true
  def handle_cast(:scan_now, state) do
    Logger.info("Manual certificate scan triggered")
    new_state = perform_scan(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.put(state.stats, :last_scan_at, state.last_scan_at)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:force_renew, agent_id}, _from, state) do
    Logger.info("Force renewal triggered for agent", agent_id: agent_id)

    result = case CertificateGenerator.renew_agent_cert(agent_id) do
      {:ok, cert_pem, _key_pem} ->
        notify_agent_cert_ready(agent_id, cert_pem)
        {:ok, :renewed}

      {:error, reason} = error ->
        Logger.error("Force renewal failed", agent_id: agent_id, reason: inspect(reason))
        error
    end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:scan_certificates, state) do
    Logger.debug("Starting scheduled certificate scan")
    new_state = perform_scan(state)

    # Schedule next scan
    schedule_scan(state.scan_interval)

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:retry_renewal, agent_id, attempt}, state) do
    Logger.info("Retrying certificate renewal", agent_id: agent_id, attempt: attempt)

    case CertificateGenerator.renew_agent_cert(agent_id) do
      {:ok, cert_pem, _key_pem} ->
        Logger.info("Certificate renewed on retry", agent_id: agent_id, attempt: attempt)
        notify_agent_cert_ready(agent_id, cert_pem)

      {:error, reason} ->
        Logger.warning("Renewal retry failed",
          agent_id: agent_id,
          attempt: attempt,
          reason: inspect(reason)
        )
        # Schedule next retry
        schedule_retry(agent_id, attempt + 1)
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp perform_scan(state) do
    start_time = System.monotonic_time(:millisecond)

    # Query all active agents with certificates
    agents = list_agents_with_certificates()

    stats = %Stats{
      total_scanned: length(agents),
      renewed: 0,
      failed: 0,
      expiring_soon: 0,
      expired: 0
    }

    # Process each agent certificate
    stats = Enum.reduce(agents, stats, fn agent, acc ->
      process_agent_certificate(agent, state, acc)
    end)

    duration = System.monotonic_time(:millisecond) - start_time

    final_stats = %{stats | last_scan_duration_ms: duration}

    Logger.info("Certificate scan completed",
      total: stats.total_scanned,
      renewed: stats.renewed,
      failed: stats.failed,
      expiring_soon: stats.expiring_soon,
      expired: stats.expired,
      duration_ms: duration
    )

    # Emit metrics
    emit_metrics(final_stats)

    %{state |
      last_scan_at: DateTime.utc_now(),
      stats: final_stats
    }
  end

  defp process_agent_certificate(agent, state, stats) do
    cert_pem = agent.certificate_pem

    if cert_pem do
      case CertificateGenerator.get_certificate_info(cert_pem) do
        {:ok, cert_info} ->
          analyze_certificate(agent, cert_info, state, stats)

        {:error, reason} ->
          Logger.warning("Failed to parse certificate for agent",
            agent_id: agent.id,
            reason: inspect(reason)
          )
          stats
      end
    else
      # No certificate - skip
      stats
    end
  end

  defp analyze_certificate(agent, cert_info, state, stats) do
    now = DateTime.utc_now()

    case parse_expiry_date(cert_info.not_after) do
      {:ok, expiry} ->
        days_until_expiry = DateTime.diff(expiry, now, :day)

        cond do
          # Expired
          days_until_expiry < 0 ->
            handle_expired_certificate(agent, expiry, days_until_expiry, state, stats)

          # Expiring soon (within alert threshold)
          days_until_expiry <= state.alert_days ->
            handle_expiring_soon_certificate(agent, expiry, days_until_expiry, state, stats)

          # Check if renewal needed based on threshold
          needs_renewal?(expiry, state.renewal_threshold) ->
            handle_renewal_needed(agent, expiry, state, stats)

          # Certificate is healthy
          true ->
            stats
        end

      {:error, _} ->
        Logger.warning("Failed to parse certificate expiry", agent_id: agent.id)
        stats
    end
  end

  defp handle_expired_certificate(agent, expiry, days_past_expiry, state, stats) do
    days_past = abs(days_past_expiry)

    Logger.warning("Agent certificate expired",
      agent_id: agent.id,
      expired_days_ago: days_past
    )

    # Alert
    create_expiry_alert(agent, expiry, :expired)

    # Auto-revoke if past grace period
    if days_past > state.auto_revoke_days do
      Logger.info("Auto-revoking expired certificate", agent_id: agent.id)
      CertificateGenerator.revoke_certificate(agent.id, :cessation_of_operation)
    end

    %{stats | expired: stats.expired + 1}
  end

  defp handle_expiring_soon_certificate(agent, expiry, days_until_expiry, _state, stats) do
    Logger.info("Agent certificate expiring soon",
      agent_id: agent.id,
      days_until_expiry: days_until_expiry
    )

    # Create alert if not already alerted
    create_expiry_alert(agent, expiry, :expiring_soon)

    # Attempt renewal
    case CertificateGenerator.renew_agent_cert(agent.id) do
      {:ok, new_cert_pem, _new_key_pem} ->
        Logger.info("Certificate renewed (expiring soon)", agent_id: agent.id)
        notify_agent_cert_ready(agent.id, new_cert_pem)
        %{stats | renewed: stats.renewed + 1, expiring_soon: stats.expiring_soon + 1}

      {:error, reason} ->
        Logger.error("Failed to renew expiring certificate",
          agent_id: agent.id,
          reason: inspect(reason)
        )
        %{stats | failed: stats.failed + 1, expiring_soon: stats.expiring_soon + 1}
    end
  end

  defp handle_renewal_needed(agent, expiry, _state, stats) do
    Logger.info("Certificate renewal needed",
      agent_id: agent.id,
      expiry: expiry
    )

    case CertificateGenerator.renew_agent_cert(agent.id) do
      {:ok, new_cert_pem, _new_key_pem} ->
        Logger.info("Certificate renewed successfully", agent_id: agent.id)
        notify_agent_cert_ready(agent.id, new_cert_pem)
        %{stats | renewed: stats.renewed + 1}

      {:error, reason} ->
        Logger.error("Certificate renewal failed",
          agent_id: agent.id,
          reason: inspect(reason)
        )

        # Schedule retry with backoff
        schedule_retry(agent.id, 1)

        %{stats | failed: stats.failed + 1}
    end
  end

  defp needs_renewal?(expiry, threshold) do
    now = DateTime.utc_now()
    total_lifetime = DateTime.diff(expiry, now, :second)
    threshold_lifetime = total_lifetime * threshold

    remaining = DateTime.diff(expiry, now, :second)
    remaining <= threshold_lifetime
  end

  defp notify_agent_cert_ready(agent_id, cert_pem) do
    # Notify agent via WebSocket that a new certificate is ready
    # Agent will download it via authenticated API endpoint

    message = %{
      event: "certificate_renewal",
      certificate_pem: cert_pem,
      download_url: "/api/v1/agents/#{agent_id}/certificate",
      expires_at: extract_expiry_from_cert(cert_pem)
    }

    TamanduaServerWeb.Endpoint.broadcast(
      "agent:#{agent_id}",
      "certificate_renewal",
      message
    )

    # Also send via command channel for agents that might have missed the broadcast
    Agents.send_command(agent_id, %{
      command_type: "certificate_renewal",
      payload: message
    })
  end

  defp create_expiry_alert(agent, expiry, severity) do
    title = case severity do
      :expired -> "Agent Certificate Expired"
      :expiring_soon -> "Agent Certificate Expiring Soon"
    end

    description = """
    Agent certificate expiry detected:
    - Agent ID: #{agent.id}
    - Hostname: #{agent.hostname || "unknown"}
    - Expiry: #{expiry}
    """

    Alerts.create_alert(%{
      title: title,
      description: description,
      severity: severity,
      source: "pki_rotator",
      agent_id: agent.id,
      metadata: %{
        certificate_expiry: expiry,
        alert_type: "certificate_expiry"
      }
    })
  end

  defp schedule_retry(agent_id, attempt) do
    # Exponential backoff: 1h, 2h, 4h, 8h, then give up
    if attempt <= 4 do
      delay_ms = :timer.hours(1) * :math.pow(2, attempt - 1) |> round()

      Logger.info("Scheduling renewal retry",
        agent_id: agent_id,
        attempt: attempt,
        delay_minutes: div(delay_ms, 60_000)
      )

      Process.send_after(self(), {:retry_renewal, agent_id, attempt}, delay_ms)
    else
      Logger.error("Renewal retry limit exceeded", agent_id: agent_id)

      # Create high-severity alert
      Alerts.create_alert(%{
        title: "Certificate Renewal Failed",
        description: "Failed to renew certificate for agent #{agent_id} after #{attempt} attempts",
        severity: :high,
        source: "pki_rotator",
        agent_id: agent_id
      })
    end
  end

  defp list_agents_with_certificates do
    # Query active agents with certificates
    query = """
    SELECT a.id, a.hostname, ac.certificate_pem, ac.not_after
    FROM agents a
    INNER JOIN agent_certificates ac ON ac.agent_id = a.id
    WHERE a.status = 'active' AND ac.status = 'active'
    """

    case Repo.query(query) do
      {:ok, %{rows: rows}} ->
        Enum.map(rows, fn [id, hostname, cert_pem, not_after] ->
          %{
            id: id,
            hostname: hostname,
            certificate_pem: cert_pem,
            not_after: not_after
          }
        end)

      {:error, reason} ->
        Logger.error("Failed to query agent certificates", reason: inspect(reason))
        []
    end
  end

  defp parse_expiry_date(date_string) when is_binary(date_string) do
    case TamanduaServer.DateTimeParser.parse_utc(date_string) do
      {:ok, datetime} -> {:ok, datetime}
      {:error, _} -> {:error, :parse_failed}
    end
  end

  defp parse_expiry_date(%DateTime{} = datetime), do: {:ok, datetime}
  defp parse_expiry_date(_), do: {:error, :invalid_format}

  defp extract_expiry_from_cert(cert_pem) do
    case CertificateGenerator.get_certificate_info(cert_pem) do
      {:ok, %{not_after: expiry}} -> expiry
      _ -> nil
    end
  end

  defp emit_metrics(stats) do
    # Emit Telemetry metrics for monitoring
    :telemetry.execute(
      [:tamandua, :pki, :certificate_rotation],
      %{
        total_scanned: stats.total_scanned,
        renewed: stats.renewed,
        failed: stats.failed,
        expiring_soon: stats.expiring_soon,
        expired: stats.expired,
        duration_ms: stats.last_scan_duration_ms
      },
      %{}
    )
  end

  defp schedule_scan(interval_ms) do
    Process.send_after(self(), :scan_certificates, interval_ms)
  end
end
