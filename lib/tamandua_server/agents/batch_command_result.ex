defmodule TamanduaServer.Agents.BatchCommandResult do
  @moduledoc """
  Schema for individual agent results within a batch command.

  Tracks the execution status and result for each agent in a batch operation.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.BatchCommand

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "batch_command_results" do
    field :agent_id, :string
    field :status, :string, default: "pending"
    field :result, :map
    field :error, :string
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime

    belongs_to :batch_command, BatchCommand

    timestamps(type: :utc_datetime)
  end

  @valid_statuses ~w(pending running completed failed cancelled)

  @doc false
  def changeset(result, attrs) do
    result
    |> cast(attrs, [
      :agent_id,
      :batch_command_id,
      :status,
      :result,
      :error,
      :started_at,
      :completed_at
    ])
    |> validate_required([:agent_id, :batch_command_id])
    |> validate_inclusion(:status, @valid_statuses)
    |> foreign_key_constraint(:batch_command_id)
  end

  @doc """
  Mark result as running.
  """
  def mark_running(result) do
    change(result, status: "running", started_at: DateTime.utc_now())
  end

  @doc """
  Mark result as completed with result data.
  """
  def mark_completed(result, result_data) do
    change(result,
      status: "completed",
      result: result_data,
      completed_at: DateTime.utc_now()
    )
  end

  @doc """
  Mark result as failed with error message.
  """
  def mark_failed(result, error_message) do
    change(result,
      status: "failed",
      error: error_message,
      completed_at: DateTime.utc_now()
    )
  end
end
