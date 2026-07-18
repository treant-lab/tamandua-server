defmodule TamanduaServer.Response.Audit.AuditEntry do
  @moduledoc """
  Schema for audit trail entries of response actions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "response_audit_trail" do
    field(:action_type, :string)
    field(:details, :map, default: %{})
    field(:agent_id, :binary_id)
    field(:organization_id, :binary_id)
    field(:actor_type, :string)
    field(:actor_id, :binary_id)
    field(:performed_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(action_type agent_id organization_id actor_type performed_at)a
  @optional_fields ~w(details actor_id)a

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

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Response.Audit.AuditEntry

  @default_limit 100
  @max_limit 500
  @max_offset 10_000
  @max_action_type_bytes 128
  @max_search_field_bytes 64
  @max_search_value_bytes 2_048

  @doc """
  Log an automated response action.

  ## Parameters

  - `action_type` - The type of action (e.g., :quarantine_file, :kill_process, :isolate_host)
  - `details` - Map containing action details (file_path, pid, sha256, etc.)
  - `agent_id` - The agent ID where the action was performed
  - `user_or_system` - Either :system for automated actions or a user ID

  ## Examples

      iex> Audit.log_action(:quarantine_file, %{}, "agent-123", :system)
      {:error, :organization_scope_required}
  """
  @spec log_action(atom() | String.t(), map(), String.t(), :system | String.t()) ::
          {:ok, AuditEntry.t()} | {:error, term()}
  def log_action(_action_type, _details, _agent_id, _user_or_system),
    do: {:error, :organization_scope_required}

  @doc """
  Log a response action under an authoritative organization scope.

  Callers that already authenticated an actor or resolved a target/alert must
  pass that organization explicitly. Missing ownership fails closed; audit
  rows are never inserted without a tenant.
  """
  @spec log_action(atom() | String.t(), map(), String.t(), :system | String.t(), String.t()) ::
          {:ok, AuditEntry.t()} | {:error, term()}
  def log_action(action_type, details, agent_id, user_or_system, organization_id)
      when is_binary(organization_id) and organization_id != "" do
    with {:ok, canonical_organization_id} <- canonical_uuid(organization_id),
         {:ok, canonical_agent_id} <- canonical_uuid(agent_id),
         {:ok, actor_type, actor_id} <- canonical_actor(user_or_system) do
      attrs = %{
        action_type: to_string(action_type),
        details: details,
        agent_id: canonical_agent_id,
        organization_id: canonical_organization_id,
        actor_type: actor_type,
        actor_id: actor_id,
        performed_at: DateTime.utc_now()
      }

      case create_audit_entry(attrs, canonical_organization_id, canonical_agent_id) do
        {:ok, entry} ->
          Logger.info(
            "Audit: #{action_type} on agent #{canonical_agent_id} by #{actor_type}" <>
              if(actor_id, do: " (#{actor_id})", else: "")
          )

          {:ok, entry}

        {:error, reason} = error ->
          Logger.error("Failed to create audit entry: #{inspect(reason)}")
          error
      end
    end
  end

  def log_action(_action_type, _details, _agent_id, _user_or_system, _organization_id),
    do: {:error, :organization_scope_required}

  @doc "Get audit actions for one agent under an explicit tenant scope."
  @spec get_actions_for_agent(String.t(), String.t(), keyword()) ::
          {:ok, [AuditEntry.t()]} | {:error, term()}
  def get_actions_for_agent(organization_id, agent_id, opts) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, agent_id} <- canonical_agent_id(agent_id),
         {:ok, opts} <- normalize_read_opts(opts) do
      limit = opts[:limit]
      offset = opts[:offset]

      tenant_read(organization_id, fn ->
        AuditEntry
        |> where([a], a.organization_id == ^organization_id and a.agent_id == ^agent_id)
        |> order_by([a], desc: a.performed_at)
        |> limit(^limit)
        |> offset(^offset)
        |> apply_filters(opts)
        |> Repo.all()
      end)
    end
  end

  @spec get_actions_for_agent(term(), term()) :: {:error, :organization_scope_required}
  def get_actions_for_agent(_agent_id, _opts), do: {:error, :organization_scope_required}

  @spec get_actions_for_agent(term()) :: {:error, :organization_scope_required}
  def get_actions_for_agent(_agent_id), do: {:error, :organization_scope_required}

  @doc "Get recent audit actions under an explicit tenant scope."
  @spec get_recent_actions(String.t(), keyword()) ::
          {:ok, [AuditEntry.t()]} | {:error, term()}
  def get_recent_actions(organization_id, opts) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, opts} <- normalize_read_opts(opts) do
      limit = opts[:limit]
      offset = opts[:offset]

      tenant_read(organization_id, fn ->
        AuditEntry
        |> where([a], a.organization_id == ^organization_id)
        |> order_by([a], desc: a.performed_at)
        |> limit(^limit)
        |> offset(^offset)
        |> apply_filters(opts)
        |> Repo.all()
      end)
    end
  end

  @spec get_recent_actions(term()) :: {:error, :organization_scope_required}
  def get_recent_actions(_opts), do: {:error, :organization_scope_required}

  @spec get_recent_actions() :: {:error, :organization_scope_required}
  def get_recent_actions, do: {:error, :organization_scope_required}

  @doc """
  Get audit action counts grouped by action type for a time range.

  ## Parameters

  - `organization_id` - Authoritative tenant UUID
  - `opts` - Bounded filters including :from, :to, and :agent_id

  ## Returns

  A map of action types to counts.
  """
  @spec get_action_counts(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_action_counts(organization_id, opts) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, opts} <- normalize_count_opts(opts) do
      tenant_read(organization_id, fn ->
        AuditEntry
        |> where([a], a.organization_id == ^organization_id)
        |> apply_filters(opts)
        |> group_by([a], a.action_type)
        |> select([a], {a.action_type, count(a.id)})
        |> Repo.all()
        |> Map.new()
      end)
    end
  end

  @spec get_action_counts(term()) :: {:error, :organization_scope_required}
  def get_action_counts(_opts), do: {:error, :organization_scope_required}

  @spec get_action_counts() :: {:error, :organization_scope_required}
  def get_action_counts, do: {:error, :organization_scope_required}

  @doc """
  Get audit entries for a specific alert or related events.
  """
  @spec get_actions_for_alert(String.t(), String.t(), keyword()) ::
          {:ok, [AuditEntry.t()]} | {:error, term()}
  def get_actions_for_alert(organization_id, alert_id, opts) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, alert_id} <- canonical_alert_id(alert_id),
         {:ok, opts} <- normalize_read_opts(opts) do
      limit = opts[:limit]
      offset = opts[:offset]

      tenant_read(organization_id, fn ->
        AuditEntry
        |> where(
          [a],
          a.organization_id == ^organization_id and
            fragment("?->>'alert_id' = ?", a.details, ^alert_id)
        )
        |> order_by([a], desc: a.performed_at)
        |> limit(^limit)
        |> offset(^offset)
        |> apply_filters(opts)
        |> Repo.all()
      end)
    end
  end

  @spec get_actions_for_alert(term(), term()) :: {:error, :organization_scope_required}
  def get_actions_for_alert(_alert_id, _organization_id),
    do: {:error, :organization_scope_required}

  @doc """
  Search audit entries by details content.
  """
  @spec search_by_details(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, [AuditEntry.t()]} | {:error, term()}
  def search_by_details(organization_id, field, value, opts) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, field} <- canonical_search_field(field),
         {:ok, value} <- canonical_search_value(value),
         {:ok, opts} <- normalize_read_opts(opts) do
      limit = opts[:limit]
      offset = opts[:offset]

      tenant_read(organization_id, fn ->
        AuditEntry
        |> where(
          [a],
          a.organization_id == ^organization_id and
            fragment("?->>? = ?", a.details, ^field, ^value)
        )
        |> order_by([a], desc: a.performed_at)
        |> limit(^limit)
        |> offset(^offset)
        |> apply_filters(opts)
        |> Repo.all()
      end)
    end
  end

  @spec search_by_details(term(), term(), term()) :: {:error, :organization_scope_required}
  def search_by_details(_field, _value, _opts), do: {:error, :organization_scope_required}

  @spec search_by_details(term(), term()) :: {:error, :organization_scope_required}
  def search_by_details(_field, _value), do: {:error, :organization_scope_required}

  # Private functions

  defp create_audit_entry(attrs, organization_id, agent_id) do
    TamanduaServer.Repo.MultiTenant.with_organization(organization_id, fn ->
      with {:ok, _agent} <- validate_agent_scope(organization_id, agent_id),
           :ok <- validate_actor_scope(attrs, organization_id) do
        %AuditEntry{}
        |> AuditEntry.changeset(attrs)
        |> Repo.insert()
      end
    end)
  rescue
    ArgumentError -> {:error, :invalid_organization_scope}
    error -> {:error, {:tenant_scope_failed, error}}
  end

  defp validate_agent_scope(organization_id, agent_id) do
    case TamanduaServer.Agents.get_agent_for_org(organization_id, agent_id) do
      {:ok, agent} -> {:ok, agent}
      {:error, :not_found} -> {:error, :agent_scope_mismatch}
      {:error, reason} -> {:error, {:agent_scope_validation_failed, reason}}
    end
  end

  defp validate_actor_scope(%{actor_type: "system"}, _organization_id), do: :ok

  defp validate_actor_scope(%{actor_type: "user", actor_id: actor_id}, organization_id) do
    if Repo.get_by(User, id: actor_id, organization_id: organization_id),
      do: :ok,
      else: {:error, :actor_scope_mismatch}
  end

  defp validate_actor_scope(_attrs, _organization_id), do: {:error, :invalid_actor}

  defp canonical_uuid(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :invalid_tenant_identifier}
    end
  end

  defp canonical_uuid(_value), do: {:error, :invalid_tenant_identifier}

  defp canonical_organization_id(value) do
    case canonical_uuid(value) do
      {:ok, uuid} -> {:ok, uuid}
      {:error, _reason} -> {:error, :invalid_organization_id}
    end
  end

  defp canonical_agent_id(value) do
    case canonical_uuid(value) do
      {:ok, uuid} -> {:ok, uuid}
      {:error, _reason} -> {:error, :invalid_agent_id}
    end
  end

  defp canonical_alert_id(value) do
    case canonical_uuid(value) do
      {:ok, uuid} -> {:ok, uuid}
      {:error, _reason} -> {:error, :invalid_alert_id}
    end
  end

  defp canonical_actor(:system), do: {:ok, "system", nil}

  defp canonical_actor(user_id) when is_binary(user_id) do
    case Ecto.UUID.cast(user_id) do
      {:ok, canonical_user_id} -> {:ok, "user", canonical_user_id}
      :error -> {:error, :invalid_actor}
    end
  end

  defp canonical_actor(_user_or_system), do: {:error, :invalid_actor}

  defp tenant_read(organization_id, fun) do
    {:ok, MultiTenant.with_organization(organization_id, fun)}
  rescue
    error ->
      Logger.error("Tenant-scoped response audit read failed: #{Exception.message(error)}")
      {:error, :audit_query_failed}
  end

  defp normalize_read_opts(opts) do
    with :ok <- valid_keyword_opts(opts),
         {:ok, limit} <-
           bounded_integer(Keyword.get(opts, :limit, @default_limit), 1, @max_limit),
         {:ok, offset} <- bounded_integer(Keyword.get(opts, :offset, 0), 0, @max_offset),
         {:ok, action_type} <-
           optional_bounded_string(opts[:action_type], @max_action_type_bytes),
         {:ok, agent_id} <- optional_agent_id(opts[:agent_id]),
         {:ok, actor_type} <- optional_actor_type(opts[:actor_type]),
         {:ok, from_datetime} <- optional_datetime(opts[:from]),
         {:ok, to_datetime} <- optional_datetime(opts[:to]),
         :ok <- valid_time_range(from_datetime, to_datetime) do
      {:ok,
       [
         limit: limit,
         offset: offset,
         action_type: action_type,
         agent_id: agent_id,
         actor_type: actor_type,
         from: from_datetime,
         to: to_datetime
       ]}
    end
  end

  defp normalize_count_opts(opts) do
    case normalize_read_opts(opts) do
      {:ok, normalized} -> {:ok, Keyword.drop(normalized, [:limit, :offset])}
      error -> error
    end
  end

  defp valid_keyword_opts(opts) when is_list(opts) do
    allowed = [:limit, :offset, :action_type, :agent_id, :actor_type, :from, :to]

    if Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in allowed)),
      do: :ok,
      else: {:error, :invalid_query_options}
  end

  defp valid_keyword_opts(_opts), do: {:error, :invalid_query_options}

  defp bounded_integer(value, min, max) when is_integer(value) and value >= min and value <= max,
    do: {:ok, value}

  defp bounded_integer(_value, _min, _max), do: {:error, :invalid_pagination}

  defp optional_bounded_string(nil, _max), do: {:ok, nil}

  defp optional_bounded_string(value, max) when is_binary(value) and byte_size(value) in 1..max,
    do: {:ok, value}

  defp optional_bounded_string(_value, _max), do: {:error, :invalid_filter}

  defp optional_agent_id(nil), do: {:ok, nil}
  defp optional_agent_id(value), do: canonical_agent_id(value)

  defp optional_actor_type(nil), do: {:ok, nil}
  defp optional_actor_type(value) when value in ["system", "user"], do: {:ok, value}
  defp optional_actor_type(_value), do: {:error, :invalid_actor_type}

  defp optional_datetime(nil), do: {:ok, nil}
  defp optional_datetime(%DateTime{} = value), do: {:ok, value}
  defp optional_datetime(_value), do: {:error, :invalid_datetime}

  defp valid_time_range(nil, _to), do: :ok
  defp valid_time_range(_from, nil), do: :ok

  defp valid_time_range(from_datetime, to_datetime) do
    if DateTime.compare(from_datetime, to_datetime) in [:lt, :eq],
      do: :ok,
      else: {:error, :invalid_time_range}
  end

  defp canonical_search_field(value)
       when is_binary(value) and byte_size(value) in 1..@max_search_field_bytes do
    if Regex.match?(~r/\A[A-Za-z0-9_.-]+\z/, value),
      do: {:ok, value},
      else: {:error, :invalid_search_field}
  end

  defp canonical_search_field(_value), do: {:error, :invalid_search_field}

  defp canonical_search_value(value)
       when is_binary(value) and byte_size(value) in 1..@max_search_value_bytes,
       do: {:ok, value}

  defp canonical_search_value(_value), do: {:error, :invalid_search_value}

  defp apply_filters(query, opts) do
    query
    |> maybe_filter_action_type(opts[:action_type])
    |> maybe_filter_agent_id(opts[:agent_id])
    |> maybe_filter_actor_type(opts[:actor_type])
    |> maybe_filter_from(opts[:from])
    |> maybe_filter_to(opts[:to])
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
end
