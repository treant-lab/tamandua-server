defmodule TamanduaServer.Response.Audit.AuditEntry do
  @moduledoc """
  Schema for audit trail entries of response actions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "response_audit_trail" do
    field :action_type, :string
    field :details, :map, default: %{}
    field :agent_id, :binary_id
    field :organization_id, :binary_id
    field :actor_type, :string
    field :actor_id, :binary_id
    field :performed_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(action_type agent_id actor_type performed_at)a
  @optional_fields ~w(details organization_id actor_id)a

  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:actor_type, ["system", "user"])
  end
end

defmodule TamanduaServer.Response.Audit do
  @moduledoc """
  Audit trail for automated response actions.

  This module provides comprehensive logging and querying of all automated
  response actions taken by the system, including:
  - ML-triggered quarantine and process termination
  - Playbook-executed actions
  - Manual analyst actions

  The audit trail is essential for:
  - Compliance and regulatory requirements
  - Incident investigation and forensics
  - Tuning and improving automated responses
  - Transparency in security operations
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Response.Audit.AuditEntry

  @doc """
  Log an automated response action.

  ## Parameters

  - `action_type` - The type of action (e.g., :quarantine_file, :kill_process, :isolate_host)
  - `details` - Map containing action details (file_path, pid, sha256, etc.)
  - `agent_id` - The agent ID where the action was performed
  - `user_or_system` - Either :system for automated actions or a user ID

  ## Examples

      iex> Audit.log_action(:quarantine_file, %{file_path: "C:\\malware.exe", sha256: "abc..."}, "agent-123", :system)
      {:ok, %AuditEntry{}}

      iex> Audit.log_action(:kill_process, %{pid: 1234}, "agent-123", "user-456")
      {:ok, %AuditEntry{}}
  """
  @spec log_action(atom() | String.t(), map(), String.t(), :system | String.t()) ::
          {:ok, AuditEntry.t()} | {:error, term()}
  def log_action(action_type, details, agent_id, user_or_system) do
    {actor_type, actor_id} =
      case user_or_system do
        :system -> {"system", nil}
        user_id when is_binary(user_id) -> {"user", user_id}
        _ -> {"system", nil}
      end

    attrs = %{
      action_type: to_string(action_type),
      details: details,
      agent_id: agent_id,
      actor_type: actor_type,
      actor_id: actor_id,
      performed_at: DateTime.utc_now()
    }

    case create_audit_entry(attrs) do
      {:ok, entry} ->
        Logger.info(
          "Audit: #{action_type} on agent #{agent_id} by #{actor_type}" <>
            if(actor_id, do: " (#{actor_id})", else: "")
        )

        {:ok, entry}

      {:error, reason} = error ->
        Logger.error("Failed to create audit entry: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Get all audit actions for a specific agent.

  ## Options

  - `:limit` - Maximum number of entries to return (default: 100)
  - `:offset` - Number of entries to skip (default: 0)
  - `:action_type` - Filter by action type
  - `:from` - Start datetime for filtering
  - `:to` - End datetime for filtering
  - `:actor_type` - Filter by actor type ("system" or "user")

  ## Examples

      iex> Audit.get_actions_for_agent("agent-123", limit: 50)
      [%AuditEntry{}, ...]

      iex> Audit.get_actions_for_agent("agent-123", action_type: "quarantine_file")
      [%AuditEntry{}, ...]
  """
  @spec get_actions_for_agent(String.t(), keyword()) :: [AuditEntry.t()]
  def get_actions_for_agent(agent_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      from(a in AuditEntry,
        where: a.agent_id == ^agent_id,
        order_by: [desc: a.performed_at],
        limit: ^limit,
        offset: ^offset
      )

    query = apply_filters(query, opts)

    Repo.all(query)
  rescue
    e ->
      Logger.error("Error fetching audit actions for agent #{agent_id}: #{inspect(e)}")
      []
  end

  @doc """
  Get recent audit actions across all agents.

  ## Options

  - `:limit` - Maximum number of entries to return (default: 100)
  - `:offset` - Number of entries to skip (default: 0)
  - `:action_type` - Filter by action type
  - `:agent_id` - Filter by specific agent
  - `:actor_type` - Filter by actor type ("system" or "user")
  - `:from` - Start datetime for filtering
  - `:to` - End datetime for filtering
  - `:organization_id` - Filter by organization

  ## Examples

      iex> Audit.get_recent_actions(limit: 50)
      [%AuditEntry{}, ...]

      iex> Audit.get_recent_actions(action_type: "kill_process", actor_type: "system")
      [%AuditEntry{}, ...]
  """
  @spec get_recent_actions(keyword()) :: [AuditEntry.t()]
  def get_recent_actions(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      from(a in AuditEntry,
        order_by: [desc: a.performed_at],
        limit: ^limit,
        offset: ^offset
      )

    query = apply_filters(query, opts)

    Repo.all(query)
  rescue
    e ->
      Logger.error("Error fetching recent audit actions: #{inspect(e)}")
      []
  end

  @doc """
  Get audit action counts grouped by action type for a time range.

  ## Parameters

  - `opts` - Options including :from, :to, :agent_id, :organization_id

  ## Returns

  A map of action types to counts.
  """
  @spec get_action_counts(keyword()) :: map()
  def get_action_counts(opts \\ []) do
    query =
      from(a in AuditEntry,
        group_by: a.action_type,
        select: {a.action_type, count(a.id)}
      )

    query = apply_filters(query, opts)

    query
    |> Repo.all()
    |> Map.new()
  rescue
    e ->
      Logger.error("Error fetching audit action counts: #{inspect(e)}")
      %{}
  end

  @doc """
  Get audit entries for a specific alert or related events.
  """
  @spec get_actions_for_alert(String.t()) :: [AuditEntry.t()]
  def get_actions_for_alert(alert_id) do
    from(a in AuditEntry,
      where: fragment("?->>'alert_id' = ?", a.details, ^alert_id),
      order_by: [desc: a.performed_at]
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  @doc """
  Search audit entries by details content.
  """
  @spec search_by_details(String.t(), String.t(), keyword()) :: [AuditEntry.t()]
  def search_by_details(field, value, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(a in AuditEntry,
      where: fragment("?->>? = ?", a.details, ^field, ^value),
      order_by: [desc: a.performed_at],
      limit: ^limit
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  # Private functions

  defp create_audit_entry(attrs) do
    %AuditEntry{}
    |> AuditEntry.changeset(attrs)
    |> Repo.insert()
  end

  defp apply_filters(query, opts) do
    query
    |> maybe_filter_action_type(opts[:action_type])
    |> maybe_filter_agent_id(opts[:agent_id])
    |> maybe_filter_actor_type(opts[:actor_type])
    |> maybe_filter_from(opts[:from])
    |> maybe_filter_to(opts[:to])
    |> maybe_filter_organization(opts[:organization_id])
  end

  defp maybe_filter_action_type(query, nil), do: query

  defp maybe_filter_action_type(query, action_type) do
    from(a in query, where: a.action_type == ^to_string(action_type))
  end

  defp maybe_filter_agent_id(query, nil), do: query

  defp maybe_filter_agent_id(query, agent_id) do
    from(a in query, where: a.agent_id == ^agent_id)
  end

  defp maybe_filter_actor_type(query, nil), do: query

  defp maybe_filter_actor_type(query, actor_type) do
    from(a in query, where: a.actor_type == ^to_string(actor_type))
  end

  defp maybe_filter_from(query, nil), do: query

  defp maybe_filter_from(query, from_datetime) do
    from(a in query, where: a.performed_at >= ^from_datetime)
  end

  defp maybe_filter_to(query, nil), do: query

  defp maybe_filter_to(query, to_datetime) do
    from(a in query, where: a.performed_at <= ^to_datetime)
  end

  defp maybe_filter_organization(query, nil), do: query

  defp maybe_filter_organization(query, organization_id) do
    from(a in query, where: a.organization_id == ^organization_id)
  end
end
