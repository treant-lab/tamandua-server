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
    field :dispatch_count, :integer, default: 0
    field :last_dispatched_at, :utc_datetime
    field :idempotency_key, :string

    timestamps(type: :utc_datetime)
  end

  # Redelivery guardrails: a command is pushed at most @max_dispatch_attempts
  # times, and never re-pushed within @redispatch_cooldown_seconds of the
  # previous push (prevents tight redelivery loops across fast reconnects).
  @max_dispatch_attempts 5
  @redispatch_cooldown_seconds 30

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
    install_patches
    rollback_patches
    process_list
    process_tree_list
    process_kill
    process_suspend
    process_resume
    process_set_priority
    process_list_handles
    process_dump
    process_create_dump
    memory_scan
    memory_strings
    network_connections
    dns_cache
    list_loaded_modules
    osquery_query
    file_list
    file_download
    file_upload
    file_hash
    registry_query
    os_info
    service_list
    scheduled_tasks
    startup_items
    shell_execute
    screen_capture
  )

  # The trailing block above (file_list .. shell_execute) covers the live
  # response wire types produced by LiveResponse.CommandExecutor
  # (@command_contracts agent_command_type values) and implemented by the
  # Rust agent (transport/mod.rs CommandType: FileList, FileDownload,
  # FileUpload, FileHash, RegistryQuery, OsInfo, ServiceList, ScheduledTasks,
  # StartupItems, ShellExecute). They were previously missing from this
  # allowlist, so Worker.send_command -> AgentCommand.insert_new rejected
  # them with :command_insert_failed before any dispatch happened.

  @doc """
  Returns the allowlist of command types accepted by the persistent command
  queue (`changeset/2` and `create_changeset/2` validate inclusion in it).
  """
  @spec valid_command_types() :: [String.t()]
  def valid_command_types, do: @valid_command_types

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
      :expires_at,
      :idempotency_key
    ])
    |> validate_required([:agent_id, :command_type])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:command_type, @valid_command_types)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
    |> update_change(:command_params, &stringify_command_params/1)
    |> unique_constraint(:idempotency_key,
      name: :agent_commands_agent_id_idempotency_key_index
    )
  end

  @doc """
  Creation changeset used by command queue producers.

  Enforces the same command-type allowlist as `changeset/2`, stringifies
  command parameter keys for the agent wire contract, and supports optional
  idempotency for retry-safe queue insertion.
  """
  def create_changeset(command, attrs) do
    command
    |> cast(attrs, [
      :agent_id,
      :command_type,
      :command_params,
      :status,
      :priority,
      :expires_at,
      :idempotency_key
    ])
    |> validate_required([:agent_id, :command_type])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:command_type, @valid_command_types)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
    |> update_change(:command_params, &stringify_command_params/1)
    |> unique_constraint(:idempotency_key,
      name: :agent_commands_agent_id_idempotency_key_index
    )
  end

  defp stringify_command_params(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {to_string(key), stringify_command_params(nested_value)}
    end)
  end

  defp stringify_command_params(value) when is_list(value), do: Enum.map(value, &stringify_command_params/1)
  defp stringify_command_params(value), do: value

  @doc """
  Insert a new command, honoring the optional idempotency key.

  Returns:

  - `{:ok, command}` when a new command row was inserted
  - `{:existing, command}` when `attrs[:idempotency_key]` matched an existing
    command for the same agent (UI/API retry) — no new row is inserted
  - `{:error, changeset}` on validation or other insert errors
  """
  @spec insert_new(map()) ::
          {:ok, %__MODULE__{}} | {:existing, %__MODULE__{}} | {:error, Ecto.Changeset.t()}
  def insert_new(attrs) do
    changeset = create_changeset(%__MODULE__{}, attrs)

    case TamanduaServer.Repo.insert(changeset) do
      {:ok, command} ->
        {:ok, command}

      {:error, %Ecto.Changeset{} = failed} ->
        agent_id = Ecto.Changeset.get_field(failed, :agent_id)
        key = Ecto.Changeset.get_field(failed, :idempotency_key)

        if idempotency_conflict?(failed) and is_binary(key) do
          case TamanduaServer.Repo.get_by(__MODULE__, agent_id: agent_id, idempotency_key: key) do
            nil -> {:error, failed}
            existing -> {:existing, existing}
          end
        else
          {:error, failed}
        end
    end
  end

  defp idempotency_conflict?(%Ecto.Changeset{errors: errors}) do
    Enum.any?(errors, fn
      {:idempotency_key, {_msg, meta}} -> meta[:constraint] == :unique
      _ -> false
    end)
  end

  @doc """
  Get deliverable commands for an agent, ordered by priority (descending) and
  insertion time.

  Includes both "pending" (never pushed) and "sent" (pushed but never
  acknowledged) commands: a command marked "sent" right before the worker or
  channel died was possibly never delivered, so it must be re-offered on
  reconnect. Agent-side execution is idempotent by command id (replay guard),
  which makes re-delivering "sent" commands safe. Redelivery loop guards
  (attempt cap / cooldown) are applied by callers via `dispatch_decision/2`.
  """
  def pending_for_agent(agent_id, limit \\ 50) do
    now = utc_now_second()

    from(c in __MODULE__,
      where: c.agent_id == ^agent_id and c.status in ["pending", "sent"],
      where: is_nil(c.expires_at) or c.expires_at > ^now,
      order_by: [desc: c.priority, asc: c.inserted_at],
      limit: ^limit
    )
  end

  @doc """
  Decide whether a pending/sent command should be (re)dispatched.

  Returns:

  - `:dispatch` — push the command to the agent now
  - `:skip_recently_dispatched` — pushed less than the cooldown ago; leave it
    alone (the in-flight attempt may still be acknowledged)
  - `{:fail, reason}` — the dispatch attempt cap was reached without a terminal
    agent response; the command should be marked failed

  ## Options

  - `:max_attempts` (default #{@max_dispatch_attempts})
  - `:cooldown_seconds` (default #{@redispatch_cooldown_seconds})
  - `:now` — clock override for tests
  """
  @spec dispatch_decision(%__MODULE__{}, keyword()) ::
          :dispatch | :skip_recently_dispatched | {:fail, String.t()}
  def dispatch_decision(%__MODULE__{} = command, opts \\ []) do
    max_attempts = Keyword.get(opts, :max_attempts, @max_dispatch_attempts)
    cooldown = Keyword.get(opts, :cooldown_seconds, @redispatch_cooldown_seconds)
    now = Keyword.get(opts, :now, utc_now_second())
    attempts = command.dispatch_count || 0

    cond do
      attempts >= max_attempts ->
        {:fail,
         "Dispatch limit reached (#{attempts}/#{max_attempts} attempts without a terminal agent response)"}

      match?(%DateTime{}, command.last_dispatched_at) and
          DateTime.diff(now, command.last_dispatched_at, :second) < cooldown ->
        :skip_recently_dispatched

      true ->
        :dispatch
    end
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
  Mark a command as dispatched towards the agent.

  Like `mark_sent/1`, but also increments `dispatch_count` and stamps
  `last_dispatched_at` so redelivery guards (`dispatch_decision/2`) can cap
  attempts and enforce a cooldown. `sent_at` keeps the first dispatch time.
  """
  def mark_dispatched(command) do
    now = utc_now_second()

    change(command,
      status: "sent",
      sent_at: command.sent_at || now,
      dispatch_count: (command.dispatch_count || 0) + 1,
      last_dispatched_at: now
    )
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
