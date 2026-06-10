defmodule TamanduaServer.Fim.Policy do
  @moduledoc """
  Schema for FIM policies with allow/block/alert actions.

  Policies are evaluated in priority order (lower = higher priority).
  First matching policy determines the action.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @actions ~w(allow alert block)
  @auto_responses ~w(none notify quarantine)
  @severities ~w(info low medium high critical)

  schema "fim_policies" do
    field :agent_id, :string  # "*" for global policy
    field :pattern, :string
    field :action, :string, default: "alert"
    field :severity_threshold, :string  # nil = all severities
    field :auto_response, :string, default: "notify"
    field :priority, :integer, default: 100
    field :expires, :integer, default: 0  # Unix timestamp ms, 0 = never
    field :reason, :string
    field :added_by, :string
    field :enabled, :boolean, default: true

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps()
  end

  @doc false
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :agent_id,
      :pattern,
      :action,
      :severity_threshold,
      :auto_response,
      :priority,
      :expires,
      :reason,
      :added_by,
      :enabled,
      :organization_id
    ])
    |> validate_required([:agent_id, :pattern, :action, :reason, :added_by])
    |> validate_inclusion(:action, @actions)
    |> validate_inclusion(:auto_response, @auto_responses)
    |> validate_severity_threshold()
    |> validate_number(:priority, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_severity_threshold(changeset) do
    case get_field(changeset, :severity_threshold) do
      nil -> changeset
      threshold when threshold in @severities -> changeset
      _ -> add_error(changeset, :severity_threshold, "must be one of: #{Enum.join(@severities, ", ")}")
    end
  end

  @doc "Get all enabled policies for an agent, sorted by priority"
  def policies_for_agent(agent_id) do
    import Ecto.Query

    from(p in __MODULE__,
      where: p.enabled == true,
      where: p.agent_id == ^agent_id or p.agent_id == "*",
      where: p.expires == 0 or p.expires > ^:os.system_time(:millisecond),
      order_by: [asc: p.priority]
    )
  end

  @doc "Serialize policy for agent sync"
  def to_agent_format(%__MODULE__{} = policy) do
    %{
      id: policy.id,
      pattern: policy.pattern,
      action: policy.action,
      severity_threshold: policy.severity_threshold,
      auto_response: policy.auto_response,
      priority: policy.priority,
      expires: policy.expires,
      reason: policy.reason,
      added_by: policy.added_by,
      enabled: policy.enabled
    }
  end
end
