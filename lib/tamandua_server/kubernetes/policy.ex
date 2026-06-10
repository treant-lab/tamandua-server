defmodule TamanduaServer.Kubernetes.Policy do
  @moduledoc """
  Ecto schema for Kubernetes admission control policies.

  Each policy defines a rule that the admission controller evaluates against
  incoming AdmissionReview requests. Policies can deny, warn, or mutate
  pod specifications to enforce security standards.

  ## Actions
  - `:deny`   - Reject the admission request
  - `:warn`   - Allow but attach a warning to the response
  - `:mutate` - Allow and apply a JSON patch to the resource

  ## Targets
  Policies can target specific Kubernetes resource types:
  Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob.

  ## Conditions
  The `conditions` field is a JSON map that defines what to check. Examples:
  - `%{"privileged" => true}` - matches privileged containers
  - `%{"host_namespaces" => ["hostNetwork", "hostPID"]}` - matches host namespace usage
  - `%{"registries" => ["docker.io", "ghcr.io"]}` - allowlist of trusted registries
  - `%{"run_as_root" => true}` - matches containers running as root
  - `%{"missing_resource_limits" => true}` - matches pods without resource limits
  - `%{"image_tag" => "latest"}` - matches images using the latest tag
  - `%{"missing_security_context" => true}` - matches pods without security context

  ## Mutations
  The `mutation` field defines a JSON patch (RFC 6902) to apply for `:mutate` actions:
  - `%{"add_labels" => %{"tamandua.io/managed" => "true"}}` - inject labels
  - `%{"default_limits" => %{"cpu" => "500m", "memory" => "256Mi"}}` - inject defaults
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "k8s_admission_policies" do
    field :name, :string
    field :description, :string
    field :action, Ecto.Enum, values: [:allow, :deny, :audit, :warn, :mutate]
    field :target, Ecto.Enum, values: [:pod, :deployment, :daemonset, :statefulset, :job, :cronjob]
    field :conditions, :map, default: %{}
    field :mutation, :map, default: %{}
    field :enabled, :boolean, default: true
    field :priority, :integer, default: 100
    field :namespaces, {:array, :string}, default: []
    field :namespace_selector, :map, default: %{}
    field :rules, {:array, :map}, default: []
    field :labels, :map, default: %{}
    field :organization_id, :binary_id

    timestamps()
  end

  @required_fields [:name, :action, :target]
  @optional_fields [
    :description, :conditions, :mutation, :enabled, :priority, :namespaces,
    :namespace_selector, :rules, :labels, :organization_id
  ]

  def changeset(policy, attrs) do
    policy
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 10_000)
    |> unique_constraint(:name)
  end

  @doc "List all policies, ordered by priority (lower first)."
  def list_policies do
    Repo.all(from p in __MODULE__, order_by: [asc: p.priority, asc: p.name])
  end

  @doc "List only enabled policies, ordered by priority."
  def list_enabled_policies do
    Repo.all(
      from p in __MODULE__,
        where: p.enabled == true,
        order_by: [asc: p.priority, asc: p.name]
    )
  end

  @doc "Get a policy by ID."
  def get_policy(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      policy -> {:ok, policy}
    end
  end

  @doc "Get a policy by ID, raises on not found."
  def get_policy!(id), do: Repo.get!(__MODULE__, id)

  @doc "Create a new policy."
  def create_policy(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc "Update an existing policy."
  def update_policy(%__MODULE__{} = policy, attrs) do
    policy
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc "Delete a policy."
  def delete_policy(%__MODULE__{} = policy) do
    Repo.delete(policy)
  end
end
