defmodule TamanduaServer.Jobs.IsolationExpiryJob do
  @moduledoc """
  Oban job for checking and automatically de-isolating expired network isolations.

  This job runs every 5 minutes (configured in Oban cron) and:
  1. Queries agents with isolation_expires_at <= now()
  2. De-isolates each expired agent
  3. Creates alerts for auto de-isolation events
  4. Clears expiry and rollback state from the database

  The NetworkIsolation module handles the actual de-isolation logic
  and state management.
  """

  use Oban.Worker,
    queue: :isolation,
    max_attempts: 3,
    unique: [period: 60]  # Only one expiry check per minute

  require Logger

  alias TamanduaServer.Response.NetworkIsolation

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.debug("[IsolationExpiryJob] Checking for expired network isolations")

    case NetworkIsolation.check_and_expire_isolations() do
      {:ok, de_isolated} when is_list(de_isolated) ->
        if length(de_isolated) > 0 do
          Logger.info(
            "[IsolationExpiryJob] Auto de-isolated #{length(de_isolated)} agents: #{inspect(de_isolated)}"
          )
        else
          Logger.debug("[IsolationExpiryJob] No expired isolations found")
        end

        :ok

      {:error, reason} ->
        Logger.error("[IsolationExpiryJob] Failed to check expired isolations: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
