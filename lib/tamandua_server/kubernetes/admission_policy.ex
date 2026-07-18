defmodule TamanduaServer.Kubernetes.AdmissionPolicy do
  @moduledoc """
  Ecto schema for Kubernetes admission control policies.

  This schema extends the original `Policy` schema with additional fields
  required for production multi-tenant deployments: namespace selectors,
  structured rules, labels, and organization scoping.

  ## Fields

  - `name` - Unique policy name (e.g. "block-privileged-containers")
  - `namespace_selector` - Map of label selectors to match namespaces.
    Follows Kubernetes LabelSelector format:
    `%{"matchLabels" => %{"env" => "production"}, "matchExpressions" => [...]}`
  - `rules` - Array of maps defining what to match. Each rule contains:
    - `"apiGroups"` - API groups (e.g. `["", "apps"]`)
    - `"apiVersions"` - API versions (e.g. `["v1"]`)
    - `"resources"` - Resource types (e.g. `["pods", "deployments"]`)
    - `"operations"` - Operations to match (e.g. `["CREATE", "UPDATE"]`)
  - `action` - Policy action: allow, deny, audit
  - `enabled` - Whether the policy is active
  - `priority` - Evaluation order (lower = higher priority)
  - `description` - Human-readable description
  - `labels` - Arbitrary key-value metadata labels
  - `organization_id` - Tenant scoping for multi-tenancy
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query


  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "k8s_admission_policies" do
    field :name, :string
    field :description, :string
    field :action, Ecto.Enum, values: [:allow, :deny, :audit, :warn, :mutate]
    field :namespace_selector, :map, default: %{}
    field :rules, {:array, :map}, default: []
    field :enabled, :boolean, default: true
    field :priority, :integer, default: 100
    field :labels, :map, default: %{}
    field :organization_id, :binary_id

    # Fields inherited from existing migration schema
    field :target, Ecto.Enum,
      values: [:pod, :deployment, :daemonset, :statefulset, :job, :cronjob],
      default: :pod

    field :conditions, :map, default: %{}
    field :mutation, :map, default: %{}
    field :namespaces, {:array, :string}, default: []

    timestamps()
  end

  @required_fields [:name, :action]
  @optional_fields [
    :description,
    :namespace_selector,
    :rules,
    :enabled,
    :priority,
    :labels,
    :organization_id,
    :target,
    :conditions,
    :mutation,
    :namespaces
  ]

  @doc """
  Build a changeset for creating or updating an admission policy.
  """
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 10_000)
    |> validate_inclusion(:action, [:allow, :deny, :audit, :warn, :mutate])
    |> validate_rules()
    |> validate_namespace_selector()
    |> unique_constraint(:name)
  end

  # -------------------------------------------------------------------
  # Query Helpers
  # -------------------------------------------------------------------

  @doc """
  Query for all active (enabled) policies, ordered by priority.
  """
  def list_active do
    from(p in __MODULE__,
      where: p.enabled == true,
      order_by: [asc: p.priority, asc: p.name]
    )
  end

  @doc """
  Query for policies matching a given namespace, either by the `namespaces`
  array or by a wildcard (empty namespaces list = all namespaces).
  """
  def by_namespace(query \\ __MODULE__, namespace) when is_binary(namespace) do
    from(p in query,
      where:
        fragment("? = '{}'", p.namespaces) or
          fragment("? = ANY(?)", ^namespace, p.namespaces)
    )
  end

  @doc """
  Query for policies belonging to a specific organization.
  """
  def by_organization(query \\ __MODULE__, organization_id) do
    from(p in query,
      where: p.organization_id == ^organization_id
    )
  end

  # -------------------------------------------------------------------
  # Validations
  # -------------------------------------------------------------------

  defp validate_rules(changeset) do
    case get_change(changeset, :rules) do
      nil ->
        changeset

      rules when is_list(rules) ->
        if Enum.all?(rules, &valid_rule?/1) do
          changeset
        else
          add_error(changeset, :rules, "each rule must be a map with valid keys (apiGroups, apiVersions, resources, operations)")
        end

      _ ->
        add_error(changeset, :rules, "must be a list of maps")
    end
  end

  defp valid_rule?(rule) when is_map(rule) do
    # Rules should contain at least one of the standard K8s admission rule fields
    valid_keys = ["apiGroups", "apiVersions", "resources", "operations", "scope"]
    Map.keys(rule) |> Enum.any?(&(&1 in valid_keys))
  end

  defp valid_rule?(_), do: false

  defp validate_namespace_selector(changeset) do
    case get_change(changeset, :namespace_selector) do
      nil ->
        changeset

      selector when is_map(selector) ->
        valid_keys = ["matchLabels", "matchExpressions"]

        if map_size(selector) == 0 or Enum.any?(Map.keys(selector), &(&1 in valid_keys)) do
          changeset
        else
          add_error(changeset, :namespace_selector, "must contain matchLabels and/or matchExpressions")
        end

      _ ->
        add_error(changeset, :namespace_selector, "must be a map")
    end
  end
end
