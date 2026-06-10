defmodule TamanduaServer.Agents.AgentCommand do
  @moduledoc """
  Schema for persistent agent command queue.

  Commands are stored in the database to ensure they survive worker crashes
  and server restarts. Each command has a lifecycle:

  - pending: Command created, not yet sent to agent
  - sent: Command sent to agent, awaiting acknowledgment
  - acknowledged: Agent acknowledged receipt, processing
  - completed: Command execution completed successfully
  - failed: Command execution failed

  Commands can have expiration times and priorities for queue management.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "agent_commands" do
    field :agent_id, :string
    field :command_type, :string
    field :command_params, :map, default: %{}
    field :status, :string, default: "pending"
    field :priority, :integer, default: 0
    field :sent_at, :utc_datetime
    field :acknowledged_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :error, :string
    field :result, :map
    field :expires_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @valid_statuses ~w(pending sent acknowledged completed failed)
  @valid_command_types ~w(
    kill_process
    quarantine_file
    isolate_network
    unisolate_network
    deisolate_network
    block_ip
    unblock_ip
    block_domain
    unblock_domain
    scan_path
    collect_artifact
    update_config
    update_rules
    collect_forensics
    run_script
    restart_agent
    update_agent
    deploy_breadcrumbs
    rotate_breadcrumbs
  )

  @doc false
  def changeset(command, attrs) do
    command
    |> cast(attrs, [
      :agent_id,
      :command_type,
      :command_params,
      :status,
      :priority,
      :sent_at,
      :acknowledged_at,
      :completed_at,
      :error,
      :result,
      :expires_at
    ])
    |> validate_required([:agent_id, :command_type])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:command_type, @valid_command_types)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
  end

  @doc """
  Get pending commands for an agent, ordered by priority (descending) and insertion time.
  """
  def pending_for_agent(agent_id, limit \\ 10) do
    from(c in __MODULE__,
      where: c.agent_id == ^agent_id and c.status == "pending",
      order_by: [desc: c.priority, asc: c.inserted_at],
      limit: ^limit
    )
  end

  @doc """
  Get commands that are pending or sent (not yet completed/failed).
  """
  def active_for_agent(agent_id) do
    from(c in __MODULE__,
      where: c.agent_id == ^agent_id and c.status in ["pending", "sent", "acknowledged"],
      order_by: [desc: c.priority, asc: c.inserted_at]
    )
  end

  @doc """
  Get expired commands (past expires_at time and not completed).
  """
  def expired_commands do
    now = utc_now_second()

    from(c in __MODULE__,
      where: not is_nil(c.expires_at),
      where: c.expires_at < ^now,
      where: c.status not in ["completed", "failed"]
    )
  end

  @doc """
  Get commands older than the specified number of days that are completed or failed.
  Used for cleanup.
  """
  def completed_older_than(days) do
    cutoff = utc_now_second() |> DateTime.add(-days * 24 * 60 * 60, :second)

    from(c in __MODULE__,
      where: c.status in ["completed", "failed"],
      where: c.updated_at < ^cutoff
    )
  end

  @doc """
  Mark a command as sent.
  """
  def mark_sent(command) do
    change(command, status: "sent", sent_at: utc_now_second())
  end

  @doc """
  Mark a command as acknowledged.
  """
  def mark_acknowledged(command) do
    change(command, status: "acknowledged", acknowledged_at: utc_now_second())
  end

  @doc """
  Mark a command as completed with optional result.
  """
  def mark_completed(command, result \\ nil) do
    change(command, status: "completed", completed_at: utc_now_second(), result: result)
  end

  @doc """
  Mark a command as failed with error message.
  """
  def mark_failed(command, error) do
    change(command, status: "failed", completed_at: utc_now_second(), error: error)
  end

  def utc_now_second do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
  end
end
