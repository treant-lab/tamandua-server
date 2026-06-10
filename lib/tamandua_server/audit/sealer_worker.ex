defmodule TamanduaServer.Audit.SealerWorker do
  @moduledoc """
  Background worker for automatic audit log sealing and verification.

  Runs periodically to:
  - Seal batches that meet criteria (1 hour old or 10K entries)
  - Verify integrity of sealed batches
  - Alert on tampering detection

  Scheduled via Oban or GenServer with periodic intervals.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Audit.Verifier

  @seal_interval :timer.minutes(15) # Check every 15 minutes
  @verify_interval :timer.hours(6) # Verify integrity every 6 hours

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger immediate sealing check.
  """
  def seal_now do
    GenServer.cast(__MODULE__, :seal_now)
  end

  @doc """
  Trigger immediate integrity verification.
  """
  def verify_now do
    GenServer.cast(__MODULE__, :verify_now)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    state = %{
      seal_timer: schedule_seal_check(),
      verify_timer: schedule_verify_check(),
      last_seal: nil,
      last_verify: nil
    }

    Logger.info("Audit sealer worker started")
    {:ok, state}
  end

  @impl true
  def handle_cast(:seal_now, state) do
    perform_seal_check()
    {:noreply, state}
  end

  @impl true
  def handle_cast(:verify_now, state) do
    perform_verify_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:seal_check, state) do
    perform_seal_check()

    new_state = %{state |
      seal_timer: schedule_seal_check(),
      last_seal: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:verify_check, state) do
    perform_verify_check()

    new_state = %{state |
      verify_timer: schedule_verify_check(),
      last_verify: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_seal_check do
    Process.send_after(self(), :seal_check, @seal_interval)
  end

  defp schedule_verify_check do
    Process.send_after(self(), :verify_check, @verify_interval)
  end

  defp perform_seal_check do
    Logger.debug("Running audit seal check")

    case Verifier.seal_all_pending() do
      {:ok, sealed_count} ->
        if sealed_count > 0 do
          Logger.info("Sealed #{sealed_count} audit batches")

          # Broadcast seal event
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "audit:seals",
            {:seals_created, sealed_count}
          )
        end

        :ok

      {:error, reason} ->
        Logger.error("Failed to seal audit batches: #{inspect(reason)}")
        :error
    end
  rescue
    e ->
      Logger.error("Exception during audit seal check: #{Exception.format(:error, e, __STACKTRACE__)}")
      :error
  end

  defp perform_verify_check do
    Logger.debug("Running audit integrity verification")

    # Get all organizations with sealed batches
    org_ids = get_organizations_with_seals()

    results = Enum.map(org_ids, fn org_id ->
      case Verifier.check_tampering(org_id, limit: 100) do
        {:ok, :no_tampering} ->
          {:ok, org_id}

        {:error, {:tampering_detected, errors}} ->
          # CRITICAL: Tampering detected
          Logger.error("TAMPERING DETECTED in organization #{org_id}: #{length(errors)} invalid seals")

          # Broadcast alert
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "audit:tampering",
            {:tampering_detected, org_id, errors}
          )

          # TODO: Send alert to admins
          # - Email notification
          # - Slack/Teams webhook
          # - Create high-severity alert

          {:error, org_id, errors}
      end
    end)

    errors = Enum.filter(results, &match?({:error, _, _}, &1))

    if Enum.empty?(errors) do
      Logger.info("Integrity verification complete: No tampering detected")
      :ok
    else
      Logger.error("Integrity verification found #{length(errors)} organizations with tampering")
      :error
    end
  rescue
    e ->
      Logger.error("Exception during integrity verification: #{Exception.format(:error, e, __STACKTRACE__)}")
      :error
  end

  defp get_organizations_with_seals do
    import Ecto.Query
    alias TamanduaServer.Repo
    alias TamanduaServer.Audit.Signature

    from(s in Signature,
      select: s.organization_id,
      distinct: true
    )
    |> Repo.all()
    |> Enum.reject(&is_nil/1)
  end
end
