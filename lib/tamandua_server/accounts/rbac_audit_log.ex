defmodule TamanduaServer.Accounts.RBACAuditLog do
  @moduledoc """
  Schema for RBAC audit log entries.

  Tracks all changes to roles and permissions including:
  - Role assignments and revocations
  - Role creation, updates, and deletions
  - Permission changes

  This provides a complete audit trail for compliance and security review.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @actions ~w(
    role_assigned role_revoked role_created role_updated role_deleted
    permission_changed user_created user_updated user_deleted
    api_key_created api_key_revoked
  )

  @target_types ~w(user role permission api_key)

  schema "rbac_audit_log" do
    belongs_to :organization, Organization
    belongs_to :actor, User

    field :action, :string
    field :target_type, :string
    field :target_id, :binary_id
    field :target_name, :string

    field :changes, :map, default: %{}
    field :metadata, :map, default: %{}

    field :ip_address, :string
    field :user_agent, :string

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @required_fields ~w(organization_id action target_type target_id)a
  @optional_fields ~w(actor_id target_name changes metadata ip_address user_agent)a

  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:action, @actions)
    |> validate_inclusion(:target_type, @target_types)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:actor_id)
  end

  @doc """
  Log a role assignment.
  """
  def log_role_assigned(org_id, actor, user, role, opts \\ []) do
    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "role_assigned",
      target_type: "user",
      target_id: user.id,
      target_name: user.email,
      changes: %{
        role_id: role.id,
        role_slug: role.slug,
        scope_type: opts[:scope_type],
        scope_id: opts[:scope_id],
        expires_at: opts[:expires_at]
      },
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Log a role revocation.
  """
  def log_role_revoked(org_id, actor, user, role, opts \\ []) do
    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "role_revoked",
      target_type: "user",
      target_id: user.id,
      target_name: user.email,
      changes: %{
        role_id: role.id,
        role_slug: role.slug
      },
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Log role creation.
  """
  def log_role_created(org_id, actor, role, opts \\ []) do
    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "role_created",
      target_type: "role",
      target_id: role.id,
      target_name: role.name,
      changes: %{
        slug: role.slug,
        description: role.description,
        priority: role.priority
      },
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Log role update.
  """
  def log_role_updated(org_id, actor, role, changes, opts \\ []) do
    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "role_updated",
      target_type: "role",
      target_id: role.id,
      target_name: role.name,
      changes: changes,
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Log role deletion.
  """
  def log_role_deleted(org_id, actor, role, opts \\ []) do
    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "role_deleted",
      target_type: "role",
      target_id: role.id,
      target_name: role.name,
      changes: %{
        slug: role.slug
      },
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Log permission changes on a role.
  """
  def log_permission_changed(org_id, actor, role, old_permissions, new_permissions, opts \\ []) do
    added = new_permissions -- old_permissions
    removed = old_permissions -- new_permissions

    create_entry(%{
      organization_id: org_id,
      actor_id: actor && actor.id,
      action: "permission_changed",
      target_type: "role",
      target_id: role.id,
      target_name: role.name,
      changes: %{
        added: added,
        removed: removed,
        old_count: length(old_permissions),
        new_count: length(new_permissions)
      },
      metadata: extract_metadata(opts)
    })
  end

  @doc """
  Query audit log entries for an organization.
  """
  def list_for_organization(org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      from al in __MODULE__,
        where: al.organization_id == ^org_id,
        order_by: [desc: al.inserted_at],
        limit: ^limit,
        offset: ^offset,
        preload: [:actor]

    # Filter by action
    query =
      case Keyword.get(opts, :action) do
        nil -> query
        action -> from al in query, where: al.action == ^action
      end

    # Filter by target type
    query =
      case Keyword.get(opts, :target_type) do
        nil -> query
        type -> from al in query, where: al.target_type == ^type
      end

    # Filter by target ID
    query =
      case Keyword.get(opts, :target_id) do
        nil -> query
        id -> from al in query, where: al.target_id == ^id
      end

    # Filter by actor
    query =
      case Keyword.get(opts, :actor_id) do
        nil -> query
        id -> from al in query, where: al.actor_id == ^id
      end

    # Filter by date range
    query =
      case Keyword.get(opts, :from) do
        nil -> query
        from_date -> from al in query, where: al.inserted_at >= ^from_date
      end

    query =
      case Keyword.get(opts, :to) do
        nil -> query
        to_date -> from al in query, where: al.inserted_at <= ^to_date
      end

    Repo.all(query)
  end

  @doc """
  Get audit entries for a specific user.
  """
  def list_for_user(org_id, user_id, opts \\ []) do
    list_for_organization(org_id, Keyword.put(opts, :target_id, user_id))
  end

  @doc """
  Get audit entries for a specific role.
  """
  def list_for_role(org_id, role_id, opts \\ []) do
    opts = opts
           |> Keyword.put(:target_id, role_id)
           |> Keyword.put(:target_type, "role")

    list_for_organization(org_id, opts)
  end

  @doc """
  Count entries matching criteria.
  """
  def count_for_organization(org_id, opts \\ []) do
    from(al in __MODULE__,
      where: al.organization_id == ^org_id,
      select: count()
    )
    |> Repo.one()
  end

  # Private helpers

  defp create_entry(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  defp extract_metadata(opts) do
    %{
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      request_id: opts[:request_id]
    }
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end
end
