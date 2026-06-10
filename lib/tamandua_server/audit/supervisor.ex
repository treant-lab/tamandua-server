defmodule TamanduaServer.Audit do
  @moduledoc """
  Audit subsystem supervisor and background worker.

  Handles:
  - Periodic hash chain integrity verification
  - Retention policy enforcement (archive, delete old entries)
  - Async audit log writing for performance
  - Tamper detection alerts
  """

  use GenServer
  require Logger

  alias TamanduaServer.AuditLog

  @verification_interval :timer.hours(1)
  @retention_interval :timer.hours(24)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger an immediate hash chain verification.
  """
  def verify_chain_now do
    GenServer.cast(__MODULE__, :verify_chain)
  end

  @doc """
  Trigger retention policy enforcement.
  """
  def enforce_retention_now do
    GenServer.cast(__MODULE__, :enforce_retention)
  end

  @doc """
  Get the current audit subsystem status.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[Audit] Starting audit subsystem")

    # Schedule periodic tasks
    schedule_verification()
    schedule_retention()

    state = %{
      last_verification: nil,
      last_retention: nil,
      verification_status: :pending,
      chain_valid: true,
      started_at: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:verify_chain, state) do
    new_state = do_verify_chain(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast(:enforce_retention, state) do
    new_state = do_enforce_retention(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      started_at: state.started_at,
      last_verification: state.last_verification,
      last_retention: state.last_retention,
      verification_status: state.verification_status,
      chain_valid: state.chain_valid
    }

    {:reply, status, state}
  end

  @impl true
  def handle_info(:verify_chain, state) do
    new_state = do_verify_chain(state)
    schedule_verification()
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:enforce_retention, state) do
    new_state = do_enforce_retention(state)
    schedule_retention()
    {:noreply, new_state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[Audit] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_verification do
    Process.send_after(self(), :verify_chain, @verification_interval)
  end

  defp schedule_retention do
    Process.send_after(self(), :enforce_retention, @retention_interval)
  end

  defp do_verify_chain(state) do
    Logger.info("[Audit] Starting hash chain verification")

    result =
      try do
        case AuditLog.verify_chain() do
          {:ok, :valid} ->
            Logger.info("[Audit] Hash chain verification passed")
            {:ok, true}

          {:error, :chain_broken, details} ->
            Logger.error("[Audit] Hash chain verification FAILED: #{inspect(details)}")
            alert_tamper_detected(details)
            {:ok, false}

          {:error, reason} ->
            Logger.warning("[Audit] Hash chain verification error: #{inspect(reason)}")
            {:error, reason}
        end
      rescue
        e ->
          Logger.error("[Audit] Hash chain verification exception: #{inspect(e)}")
          {:error, e}
      end

    case result do
      {:ok, valid} ->
        %{state |
          last_verification: DateTime.utc_now(),
          verification_status: :completed,
          chain_valid: valid
        }

      {:error, _} ->
        %{state |
          last_verification: DateTime.utc_now(),
          verification_status: :error
        }
    end
  end

  defp do_enforce_retention(state) do
    Logger.info("[Audit] Starting retention policy enforcement")

    try do
      case AuditLog.enforce_retention() do
        {:ok, stats} ->
          Logger.info("[Audit] Retention policy enforced: #{inspect(stats)}")

        {:error, reason} ->
          Logger.warning("[Audit] Retention policy error: #{inspect(reason)}")
      end
    rescue
      e ->
        Logger.error("[Audit] Retention policy exception: #{inspect(e)}")
    end

    %{state | last_retention: DateTime.utc_now()}
  end

  defp alert_tamper_detected(details) do
    # Log a critical security alert for tamper detection
    AuditLog.log(%{
      action: "audit_tamper_detected",
      action_type: "security",
      resource_type: "audit_log",
      severity: :critical,
      details: %{
        tamper_details: details,
        alert_message: "Audit log tampering detected - hash chain broken"
      },
      ip_address: "system",
      user_agent: "TamanduaServer.Audit"
    })

    # Broadcast to admin channel if available
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "admin:security_alerts",
      {:audit_tamper_detected, details}
    )
  end
end
