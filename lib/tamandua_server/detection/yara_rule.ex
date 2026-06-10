defmodule TamanduaServer.Detection.YaraRule do
  @moduledoc """
  Schema for YARA detection rules.

  YARA rules are stored in their raw text format and distributed to agents
  for local binary scanning.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @severity_scores %{
    "informational" => 0.1,
    "low" => 0.3,
    "medium" => 0.5,
    "high" => 0.7,
    "critical" => 0.9
  }

  schema "yara_rules" do
    field :name, :string
    field :description, :string
    field :author, :string
    field :source, :string  # Raw YARA rule content
    field :enabled, :boolean, default: true

    # Classification
    field :category, :string
    field :severity, :string, default: "medium"
    field :tags, {:array, :string}, default: []

    # MITRE ATT&CK
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []

    # Context
    field :malware_family, :string
    field :threat_actor, :string

    # References
    field :references, {:array, :string}, default: []

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name source)a
  @optional_fields ~w(description author enabled category severity tags
                      mitre_tactics mitre_techniques malware_family
                      threat_actor references organization_id)a

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:severity, Map.keys(@severity_scores))
    |> validate_yara_syntax()
    |> unique_constraint([:name, :organization_id])
  end

  @doc """
  Get the numeric score for this rule's severity.
  """
  def severity_score(%__MODULE__{severity: severity}) do
    Map.get(@severity_scores, severity, 0.5)
  end

  @doc """
  Serialize the rule for agent distribution.
  """
  def to_agent_format(%__MODULE__{} = rule) do
    %{
      name: rule.name,
      source: rule.source,
      category: rule.category,
      severity: rule.severity,
      malware_family: rule.malware_family
    }
  end

  # Validate basic YARA syntax
  defp validate_yara_syntax(changeset) do
    source = get_field(changeset, :source)

    if source && valid_yara_structure?(source) do
      changeset
    else
      add_error(changeset, :source, "must be valid YARA rule syntax")
    end
  end

  defp valid_yara_structure?(source) do
    # Basic structure check: rule NAME { ... }
    String.match?(source, ~r/rule\s+\w+\s*(\:[\w\s]+)?\s*\{[\s\S]*\}/m)
  end
end
