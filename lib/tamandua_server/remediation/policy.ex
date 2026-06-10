defmodule TamanduaServer.Remediation.Policy do
  @moduledoc """
  Remediation policy schema and context functions.

  Policies define automated response actions based on alert risk scores
  and conditions. Policies are evaluated in priority order (lower = higher priority).

  ## Action Types

  - `quarantine` - Quarantine the file/process triggering the alert
  - `block` - Block the IP/domain/hash via prevention policy
  - `notify` - Send notification to configured channels
  - `escalate` - Escalate to specified team/user

  ## Thresholds

  - `auto_threshold` - Minimum threat_score required for auto-remediation
  - `manual_threshold` - Threat_score at or above this requires human approval
  - Between thresholds: auto-execute only when the policy explicitly allows it
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @action_types ~w(quarantine block notify escalate)

  schema "remediation_policies" do
    field :name, :string
    field :description, :string
    field :is_enabled, :boolean, default: true
    field :is_default, :boolean, default: false
    field :priority, :integer, default: 100

    field :auto_threshold, :float
    field :manual_threshold, :float

    field :action_type, :string
    field :action_config, :map, default: %{}

    field :conditions, :map, default: %{}
    field :agent_group_ids, {:array, :binary_id}, default: []

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps()
  end

  @doc false
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :name, :description, :is_enabled, :is_default, :priority,
      :auto_threshold, :manual_threshold, :action_type, :action_config,
      :conditions, :agent_group_ids, :organization_id
    ])
    |> validate_required([:name, :action_type])
    |> validate_inclusion(:action_type, @action_types)
    |> validate_thresholds()
    |> unique_constraint([:name, :organization_id])
  end

  defp validate_thresholds(changeset) do
    auto = get_field(changeset, :auto_threshold)
    manual = get_field(changeset, :manual_threshold)

    cond do
      is_nil(auto) or is_nil(manual) -> changeset
      auto >= manual -> add_error(changeset, :auto_threshold, "must be less than manual_threshold")
      auto < 0.0 or auto > 1.0 -> add_error(changeset, :auto_threshold, "must be between 0.0 and 1.0")
      manual < 0.0 or manual > 1.0 -> add_error(changeset, :manual_threshold, "must be between 0.0 and 1.0")
      true -> changeset
    end
  end

  # === Context Functions ===

  @doc "List all policies ordered by priority"
  def list_policies(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    from(p in __MODULE__, order_by: [asc: p.priority, asc: p.inserted_at])
    |> maybe_filter_by_org(organization_id)
    |> Repo.all()
  end

  @doc "List only enabled policies for evaluation"
  def list_active_policies(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    from(p in __MODULE__,
      where: p.is_enabled == true,
      order_by: [asc: p.priority, asc: p.inserted_at]
    )
    |> maybe_filter_by_org(organization_id)
    |> Repo.all()
  end

  @doc "Get a policy by ID"
  def get_policy!(id), do: Repo.get!(__MODULE__, id)

  @doc "Get a policy by ID, returns {:ok, policy} or {:error, :not_found}"
  def get_policy(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      policy -> {:ok, policy}
    end
  end

  @doc "Create a new policy"
  def create_policy(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc "Update an existing policy"
  def update_policy(%__MODULE__{} = policy, attrs) do
    policy
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc "Delete a policy"
  def delete_policy(%__MODULE__{} = policy) do
    if policy.is_default do
      {:error, :cannot_delete_default}
    else
      Repo.delete(policy)
    end
  end

  @doc "Get action types"
  def action_types, do: @action_types

  defp maybe_filter_by_org(query, nil), do: query
  defp maybe_filter_by_org(query, org_id), do: where(query, [p], p.organization_id == ^org_id)
end
