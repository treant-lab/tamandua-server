defmodule TamanduaServer.Integrations.SOAR.TriggerRule do
  @moduledoc """
  Ecto schema for SOAR trigger rules.

  Rules define when and how alerts trigger SOAR playbooks based on:
  - Alert severity (critical, high, medium, low, info)
  - MITRE tactics and techniques
  - Threat score thresholds
  - Alert title/description keywords

  ## Match Criteria

  The `match_criteria` field is a JSON map with optional keys:
  - `"severity"` - List of severity levels to match
  - `"mitre_tactics"` - List of tactics (any match triggers)
  - `"mitre_techniques"` - List of technique IDs (any match triggers)
  - `"threat_score_gte"` - Minimum threat score threshold
  - `"title_contains"` - Keywords to match in alert title (case-insensitive)

  ## Example

      %TriggerRule{
        name: "Critical Alert Response",
        match_criteria: %{
          "severity" => ["critical"],
          "threat_score_gte" => 0.8
        },
        soar_platform: "both",
        playbook_name: "high_priority_incident"
      }
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "soar_trigger_rules" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true
    field :priority, :integer, default: 50

    # Match criteria as JSON map
    field :match_criteria, :map, default: %{}

    # Action configuration
    field :soar_platform, :string  # "xsoar", "tines", "both"
    field :playbook_name, :string
    field :webhook_url, :string    # For Tines webhooks
    field :params, :map, default: %{}

    # Tenant scoping
    belongs_to :organization, TamanduaServer.Accounts.Organization, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:name, :soar_platform, :playbook_name]
  @optional_fields [:description, :enabled, :priority, :match_criteria, :webhook_url, :params, :organization_id]

  @doc """
  Changeset for creating/updating trigger rules.
  """
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:soar_platform, ["xsoar", "tines", "both"])
    |> validate_number(:priority, greater_than_or_equal_to: 1, less_than_or_equal_to: 100)
    |> validate_match_criteria()
  end

  defp validate_match_criteria(changeset) do
    case get_change(changeset, :match_criteria) do
      nil -> changeset
      criteria when is_map(criteria) ->
        # Validate structure of criteria
        valid_keys = ["severity", "mitre_tactics", "mitre_techniques", "threat_score_gte", "title_contains"]
        unknown_keys = Map.keys(criteria) -- valid_keys

        if unknown_keys == [] do
          changeset
        else
          add_error(changeset, :match_criteria, "contains unknown keys: #{inspect(unknown_keys)}")
        end
      _ ->
        add_error(changeset, :match_criteria, "must be a map")
    end
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  @doc """
  List all enabled trigger rules, ordered by priority.
  """
  def list_enabled(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)

    query = from(r in __MODULE__,
      where: r.enabled == true,
      order_by: [desc: r.priority, asc: r.name]
    )

    query = if org_id do
      from(r in query, where: r.organization_id == ^org_id or is_nil(r.organization_id))
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  List all trigger rules.
  """
  def list_all(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)

    query = from(r in __MODULE__, order_by: [desc: r.priority, asc: r.name])

    query = if org_id do
      from(r in query, where: r.organization_id == ^org_id or is_nil(r.organization_id))
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get a rule by ID.
  """
  def get(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Create a new trigger rule.
  """
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a trigger rule.
  """
  def update(%__MODULE__{} = rule, attrs) do
    rule
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a trigger rule.
  """
  def delete(%__MODULE__{} = rule) do
    Repo.delete(rule)
  end

  @doc """
  Delete a trigger rule by ID.
  """
  def delete(id) when is_binary(id) do
    case get(id) do
      nil -> {:error, :not_found}
      rule -> delete(rule)
    end
  end
end
