defmodule TamanduaServer.Agents.BatchCommand do
  @moduledoc """
  Schema for batch command execution tracking.

  Tracks commands sent to multiple agents simultaneously, providing
  progress tracking and partial failure handling.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.{Group, BatchCommandResult}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "batch_commands" do
    field :command_type, :string
    field :command_params, :map, default: %{}
    field :status, :string, default: "pending"
    field :total_count, :integer, default: 0
    field :completed_count, :integer, default: 0
    field :success_count, :integer, default: 0
    field :failed_count, :integer, default: 0
    field :initiated_by, :string
    field :expires_at, :utc_datetime
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :timeout_seconds, :integer, default: 3600

    # Target selection
    field :target_type, :string  # "group", "agents", "query"
    field :target_ids, {:array, :string}, default: []

    belongs_to :organization, Organization
    belongs_to :group, Group

    has_many :results, BatchCommandResult

    timestamps(type: :utc_datetime)
  end

  @valid_statuses ~w(pending running completed partial_failure failed cancelled)
  @valid_target_types ~w(group agents query)
  @valid_command_types ~w(
    kill_process
    quarantine_file
    isolate_network
    deisolate_network
    update_config
    collect_forensics
    scan_path
    restart_agent
    update_agent
  )

  @doc false
  def changeset(batch_command, attrs) do
    batch_command
    |> cast(attrs, [
      :command_type,
      :command_params,
      :status,
      :total_count,
      :completed_count,
      :success_count,
      :failed_count,
      :initiated_by,
      :expires_at,
      :started_at,
      :completed_at,
      :timeout_seconds,
      :target_type,
      :target_ids,
      :organization_id,
      :group_id
    ])
    |> validate_required([:command_type, :target_type, :organization_id])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:target_type, @valid_target_types)
    |> validate_inclusion(:command_type, @valid_command_types)
    |> validate_number(:timeout_seconds, greater_than: 0, less_than_or_equal_to: 86400)
    |> validate_targets()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:group_id)
  end

  defp validate_targets(changeset) do
    target_type = get_field(changeset, :target_type)
    target_ids = get_field(changeset, :target_ids)
    group_id = get_field(changeset, :group_id)

    case target_type do
      "group" when is_nil(group_id) ->
        add_error(changeset, :group_id, "is required when target_type is 'group'")

      "agents" when target_ids == [] ->
        add_error(changeset, :target_ids, "must contain at least one agent ID")

      _ ->
        changeset
    end
  end

  @doc """
  Mark batch command as running.
  """
  def mark_running(batch_command) do
    change(batch_command,
      status: "running",
      started_at: DateTime.utc_now()
    )
  end

  @doc """
  Mark batch command as completed.
  """
  def mark_completed(batch_command) do
    status =
      cond do
        batch_command.failed_count == batch_command.total_count -> "failed"
        batch_command.failed_count > 0 -> "partial_failure"
        true -> "completed"
      end

    change(batch_command,
      status: status,
      completed_at: DateTime.utc_now()
    )
  end

  @doc """
  Mark batch command as cancelled.
  """
  def mark_cancelled(batch_command) do
    change(batch_command, status: "cancelled", completed_at: DateTime.utc_now())
  end

  @doc """
  Update progress counters.
  """
  def update_progress(batch_command, completed: completed, success: success, failed: failed) do
    change(batch_command,
      completed_count: completed,
      success_count: success,
      failed_count: failed
    )
  end
end
