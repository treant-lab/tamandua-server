defmodule TamanduaServer.Remediation.AuditTrail do
  @moduledoc """
  Immutable audit trail for remediation workflow events.

  Records all workflow actions with actor information, timestamps,
  and detailed context for compliance and forensics.

  ## Event Types

  - `created` - Workflow created
  - `approved` - Workflow approved by user
  - `rejected` - Workflow rejected by user
  - `started` - Workflow execution started
  - `completed` - Workflow completed successfully
  - `failed` - Workflow failed
  - `cancelled` - Workflow cancelled
  - `escalated` - Workflow escalated to higher tier
  - `auto_rejected` - Workflow auto-rejected due to max escalation
  - `retried` - Workflow retry attempt

  ## Actor Types

  - `user` - Human user action
  - `system` - System/automated action
  - `oban_worker` - Oban job execution
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Remediation.Workflow

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @event_types ~w(created approved rejected started completed failed cancelled escalated auto_rejected retried)
  @actor_types ~w(user system oban_worker)

  schema "remediation_audit_events" do
    field :event_type, :string
    field :previous_state, :string
    field :new_state, :string

    field :actor_id, :binary_id
    field :actor_type, :string
    field :actor_email, :string

    field :details, :map, default: %{}
    field :ip_address, :string
    field :user_agent, :string

    belongs_to :workflow, Workflow
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @doc false
  def changeset(audit_event, attrs) do
    audit_event
    |> cast(attrs, [
      :event_type, :previous_state, :new_state,
      :actor_id, :actor_type, :actor_email,
      :details, :ip_address, :user_agent,
      :workflow_id, :organization_id
    ])
    |> validate_required([:event_type, :actor_type])
    |> validate_inclusion(:event_type, @event_types)
    |> validate_inclusion(:actor_type, @actor_types)
    |> foreign_key_constraint(:workflow_id)
    |> foreign_key_constraint(:organization_id)
  end

  # === Public API ===

  @doc """
  Log an audit event for a workflow action.

  ## Parameters

  - `workflow` - The workflow struct
  - `event_type` - One of: #{Enum.join(@event_types, ", ")}
  - `actor` - One of: `%User{}`, `:system`, or `{:oban, job_id}`
  - `details` - Optional map of additional context

  ## Examples

      AuditTrail.log_event(workflow, :created, :system)
      AuditTrail.log_event(workflow, :approved, user, %{notes: "Approved after investigation"})
      AuditTrail.log_event(workflow, :started, {:oban, 12345})
  """
  def log_event(workflow, event_type, actor, details \\ %{})

  def log_event(workflow, event_type, actor, details) when is_map(workflow) and is_atom(event_type) do
    log_event(workflow, Atom.to_string(event_type), actor, details)
  end

  def log_event(workflow, event_type, actor, details) when is_map(workflow) and is_binary(event_type) do
    {actor_type, actor_id, actor_email} = extract_actor(actor)

    attrs = %{
      workflow_id: workflow.id,
      organization_id: workflow.organization_id,
      event_type: event_type,
      previous_state: workflow.previous_state,
      new_state: workflow.state,
      actor_type: actor_type,
      actor_id: actor_id,
      actor_email: actor_email,
      details: details
    }

    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  List audit events for a workflow.

  ## Options

  - `:limit` - Maximum number of events to return (default: 100)
  - `:order` - Sort order, `:asc` or `:desc` (default: `:asc`)

  ## Examples

      AuditTrail.list_events(workflow_id)
      AuditTrail.list_events(workflow_id, limit: 50, order: :desc)
  """
  def list_events(workflow_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    order = Keyword.get(opts, :order, :asc)

    from(e in __MODULE__,
      where: e.workflow_id == ^workflow_id,
      order_by: [{^order, e.inserted_at}],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get the complete workflow history as a timeline.

  Returns all audit events for a workflow in chronological order,
  formatted for display in a timeline component.

  ## Examples

      AuditTrail.get_workflow_history(workflow_id)
  """
  def get_workflow_history(workflow_id) do
    from(e in __MODULE__,
      where: e.workflow_id == ^workflow_id,
      order_by: [asc: e.inserted_at]
    )
    |> Repo.all()
    |> Enum.map(&format_timeline_event/1)
  end

  @doc """
  List recent audit events for an organization.

  ## Options

  - `:limit` - Maximum number of events (default: 50)
  - `:event_type` - Filter by event type
  - `:since` - Filter events after this datetime

  ## Examples

      AuditTrail.list_recent_events(organization_id, limit: 20)
      AuditTrail.list_recent_events(organization_id, event_type: "approved")
  """
  def list_recent_events(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    event_type = Keyword.get(opts, :event_type)
    since = Keyword.get(opts, :since)

    from(e in __MODULE__,
      where: e.organization_id == ^organization_id,
      order_by: [desc: e.inserted_at],
      limit: ^limit,
      preload: [:workflow]
    )
    |> maybe_filter_event_type(event_type)
    |> maybe_filter_since(since)
    |> Repo.all()
  end

  @doc """
  Count audit events by event type for an organization.

  Returns a map of event_type => count.

  ## Examples

      AuditTrail.count_by_event_type(organization_id)
      # => %{"approved" => 15, "rejected" => 3, "completed" => 45}
  """
  def count_by_event_type(organization_id) do
    from(e in __MODULE__,
      where: e.organization_id == ^organization_id,
      group_by: e.event_type,
      select: {e.event_type, count(e.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc "Get valid event types"
  def event_types, do: @event_types

  @doc "Get valid actor types"
  def actor_types, do: @actor_types

  # === Private Functions ===

  defp extract_actor(user) when is_map(user) do
    {"user", user.id, user.email}
  end

  defp extract_actor(:system) do
    {"system", nil, "system"}
  end

  defp extract_actor({:oban, job_id}) when is_integer(job_id) do
    {"oban_worker", to_string(job_id), "Oban job ##{job_id}"}
  end

  defp extract_actor({:oban, job_id}) when is_binary(job_id) do
    {"oban_worker", job_id, "Oban job ##{job_id}"}
  end

  defp extract_actor(nil) do
    {"system", nil, "system"}
  end

  defp extract_actor(user_id) when is_binary(user_id) do
    case Repo.get(User, user_id) do
      nil -> {"user", user_id, "Unknown user"}
      user -> {"user", user.id, user.email}
    end
  end

  defp format_timeline_event(event) do
    %{
      id: event.id,
      event_type: event.event_type,
      previous_state: event.previous_state,
      new_state: event.new_state,
      actor_type: event.actor_type,
      actor_email: event.actor_email,
      details: event.details,
      timestamp: event.inserted_at,
      formatted_time: format_timestamp(event.inserted_at)
    }
  end

  defp format_timestamp(nil), do: nil
  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp maybe_filter_event_type(query, nil), do: query
  defp maybe_filter_event_type(query, event_type) do
    where(query, [e], e.event_type == ^event_type)
  end

  defp maybe_filter_since(query, nil), do: query
  defp maybe_filter_since(query, since) do
    where(query, [e], e.inserted_at >= ^since)
  end
end
