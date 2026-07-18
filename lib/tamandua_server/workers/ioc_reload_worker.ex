defmodule TamanduaServer.Workers.IOCReloadWorker do
  @moduledoc """
  Rebuilds the detection IOC snapshot from its durable database authority.

  Uniqueness excludes executing jobs intentionally. Pending requests coalesce,
  while a mutation arriving during execution schedules one follow-up snapshot.
  """

  use Oban.Worker,
    queue: :threat_intel,
    max_attempts: 5,
    unique: [
      period: :infinity,
      fields: [:worker, :args],
      keys: [:scope],
      states: [:available, :scheduled, :retryable]
    ]

  alias TamanduaServer.Detection.Engine

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"scope" => "all"}} = job) do
    perform_result(job, &Engine.reload_iocs/0)
  end

  def perform(%Oban.Job{}), do: {:discard, :invalid_job_arguments}

  @doc false
  def perform_result(%Oban.Job{}, reload_fun) when is_function(reload_fun, 0) do
    case reload_fun.() do
      {:ok, _count} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, {:reload_exception, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:reload_exit, reason}}
  end
end
