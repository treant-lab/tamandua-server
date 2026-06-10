defmodule TamanduaServer.TenantScope do
  @moduledoc """
  Tenant scoping utilities for multi-tenant data isolation.

  This module provides functions to ensure all queries are properly scoped
  to the current organization (tenant). It should be used in all context
  modules to prevent cross-tenant data access.

  ## Usage

  In context modules:

      import TamanduaServer.TenantScope

      def list_alerts(org_id) do
        Alert
        |> scope_to_tenant(org_id)
        |> Repo.all()
      end

      def get_alert(org_id, id) do
        Alert
        |> scope_to_tenant(org_id)
        |> Repo.get(id)
      end

  In Phoenix controllers:

      def index(conn, params) do
        org_id = conn.assigns[:current_organization_id]
        alerts = Alerts.list_alerts(org_id)
        # ...
      end

  ## Preloading with Tenant Scope

      Agent
      |> scope_to_tenant(org_id)
      |> preload_scoped(:alerts, org_id)
      |> Repo.all()
  """

  import Ecto.Query

  @doc """
  Scope a query to a specific organization.

  ## Parameters
  - query: An Ecto query or schema module
  - org_id: The organization ID to scope to

  ## Returns
  A query with the organization filter applied

  ## Examples

      iex> scope_to_tenant(Alert, "org-uuid")
      #Ecto.Query<from a in Alert, where: a.organization_id == ^"org-uuid">
  """
  def scope_to_tenant(query, org_id) when not is_nil(org_id) do
    from q in query, where: q.organization_id == ^org_id
  end

  def scope_to_tenant(_query, nil) do
    raise ArgumentError, "organization_id cannot be nil when scoping query"
  end

  @doc """
  Scope a query and select specific fields.

  Useful for lists where you don't need all fields.
  """
  def scope_and_select(query, org_id, fields) when is_list(fields) do
    query
    |> scope_to_tenant(org_id)
    |> select([q], map(q, ^fields))
  end

  @doc """
  Get a single record scoped to organization.

  Returns nil if not found or doesn't belong to the organization.
  """
  def get_scoped(schema, org_id, id) do
    schema
    |> scope_to_tenant(org_id)
    |> where([q], q.id == ^id)
    |> TamanduaServer.Repo.one()
  end

  @doc """
  Get a single record scoped to organization, raises if not found.
  """
  def get_scoped!(schema, org_id, id) do
    case get_scoped(schema, org_id, id) do
      nil -> raise Ecto.NoResultsError, queryable: schema
      record -> record
    end
  end

  @doc """
  Check if a record belongs to the organization.
  """
  def belongs_to_tenant?(schema, org_id, id) do
    schema
    |> scope_to_tenant(org_id)
    |> where([q], q.id == ^id)
    |> select([q], true)
    |> TamanduaServer.Repo.one()
    |> Kernel.!=(nil)
  end

  @doc """
  Count records for an organization.
  """
  def count_for_tenant(schema, org_id) do
    schema
    |> scope_to_tenant(org_id)
    |> select([q], count(q.id))
    |> TamanduaServer.Repo.one()
  end

  @doc """
  Ensure a changeset has the organization_id set.

  Use this when creating records to ensure tenant isolation.
  """
  def put_tenant(changeset, org_id) do
    Ecto.Changeset.put_change(changeset, :organization_id, org_id)
  end

  @doc """
  Validate that a referenced record belongs to the same organization.

  This prevents cross-tenant references.

  ## Example

      def changeset(alert, attrs, org_id) do
        alert
        |> cast(attrs, [:agent_id])
        |> validate_same_tenant(:agent_id, Agent, org_id)
      end
  """
  def validate_same_tenant(changeset, field, schema, org_id) do
    Ecto.Changeset.validate_change(changeset, field, fn _, value ->
      if belongs_to_tenant?(schema, org_id, value) do
        []
      else
        [{field, "does not belong to your organization"}]
      end
    end)
  end

  @doc """
  Get the organization_id from a Plug.Conn.

  Expects the organization_id to be in assigns under :current_organization_id
  or extractable from :current_user.
  """
  def get_tenant_id(%Plug.Conn{assigns: assigns}) do
    assigns[:current_organization_id] ||
      (assigns[:current_user] && assigns[:current_user].organization_id)
  end

  def get_tenant_id(%{organization_id: org_id}) when not is_nil(org_id), do: org_id
  def get_tenant_id(_), do: nil

  @doc """
  Macro for creating tenant-scoped context functions.

  Generates common CRUD functions that are automatically scoped to tenant.
  """
  defmacro tenant_scoped_crud(schema, opts \\ []) do
    singular = Keyword.get(opts, :singular, schema |> Module.split() |> List.last() |> Macro.underscore())
    plural = Keyword.get(opts, :plural, "#{singular}s")

    quote do
      import Ecto.Query
      alias TamanduaServer.TenantScope
      alias TamanduaServer.Repo

      @doc """
      List all #{unquote(plural)} for an organization.
      """
      def unquote(:"list_#{plural}")(org_id, opts \\ []) do
        limit = Keyword.get(opts, :limit, 100)
        offset = Keyword.get(opts, :offset, 0)

        unquote(schema)
        |> TenantScope.scope_to_tenant(org_id)
        |> limit(^limit)
        |> offset(^offset)
        |> Repo.all()
      end

      @doc """
      Get a single #{unquote(singular)} by ID, scoped to organization.
      """
      def unquote(:"get_#{singular}")(org_id, id) do
        TenantScope.get_scoped(unquote(schema), org_id, id)
      end

      @doc """
      Get a single #{unquote(singular)} by ID, raises if not found.
      """
      def unquote(:"get_#{singular}!")(org_id, id) do
        TenantScope.get_scoped!(unquote(schema), org_id, id)
      end

      @doc """
      Create a new #{unquote(singular)} for an organization.
      """
      def unquote(:"create_#{singular}")(org_id, attrs) do
        %unquote(schema){}
        |> unquote(schema).changeset(attrs)
        |> TenantScope.put_tenant(org_id)
        |> Repo.insert()
      end

      @doc """
      Update a #{unquote(singular)}.
      """
      def unquote(:"update_#{singular}")(%unquote(schema){} = record, attrs) do
        record
        |> unquote(schema).changeset(attrs)
        |> Repo.update()
      end

      @doc """
      Delete a #{unquote(singular)}.
      """
      def unquote(:"delete_#{singular}")(%unquote(schema){} = record) do
        Repo.delete(record)
      end

      @doc """
      Count #{unquote(plural)} for an organization.
      """
      def unquote(:"count_#{plural}")(org_id) do
        TenantScope.count_for_tenant(unquote(schema), org_id)
      end
    end
  end
end
