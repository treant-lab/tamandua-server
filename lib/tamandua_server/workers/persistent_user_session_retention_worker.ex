defmodule TamanduaServer.Workers.PersistentUserSessionRetentionWorker do
  @moduledoc """
  Periodically removes persistent sessions whose terminal retention window elapsed.

  The job is deliberately argument-free. Cleanup policy remains server-owned and
  no tenant, user, session, token, or binding identifier is stored in Oban args.
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 3_600]

  alias TamanduaServer.Accounts.PersistentUserSessionStore

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) when map_size(args) == 0 do
    case PersistentUserSessionStore.cleanup_terminal_sessions() do
      {:ok, %{status: :completed, deleted_count: deleted_count, batches: batches}}
      when is_integer(deleted_count) and deleted_count >= 0 and is_integer(batches) and
             batches >= 0 ->
        Logger.info(
          "[PersistentUserSessionRetentionWorker] status=completed " <>
            "deleted_count=#{deleted_count} batches=#{batches}"
        )

        :ok

      {:ok, _unexpected_result} ->
        {:error, :unexpected_cleanup_result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def perform(%Oban.Job{}), do: {:discard, :unexpected_arguments}
end
