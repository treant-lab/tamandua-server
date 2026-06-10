defmodule TamanduaServer.Detection.RuleVersion do
  @moduledoc """
  Schema for tracking rule version history.
  Allows rollback and change tracking for all rule types.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rule_versions" do
    field :rule_type, :string
    field :rule_id, :binary_id
    field :version, :integer, default: 1
    field :content, :string
    field :checksum, :string
    field :change_summary, :string

    belongs_to :changed_by_user, User, foreign_key: :changed_by
    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc false
  def changeset(version, attrs) do
    version
    |> cast(attrs, [
      :rule_type,
      :rule_id,
      :version,
      :content,
      :checksum,
      :change_summary,
      :changed_by,
      :organization_id
    ])
    |> validate_required([:rule_type, :rule_id, :version, :content, :organization_id])
    |> validate_inclusion(:rule_type, ["yara", "sigma", "ioc"])
    |> put_checksum()
    |> unique_constraint([:rule_type, :rule_id, :version])
  end

  defp put_checksum(changeset) do
    case get_change(changeset, :content) do
      nil ->
        changeset

      content ->
        checksum = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
        put_change(changeset, :checksum, checksum)
    end
  end

  @doc """
  Create a new version from a rule.
  """
  def from_rule(rule, rule_type, user_id, change_summary \\ nil) do
    content = serialize_rule(rule, rule_type)

    %__MODULE__{
      rule_type: to_string(rule_type),
      rule_id: rule.id,
      content: content,
      change_summary: change_summary,
      changed_by: user_id,
      organization_id: rule.organization_id
    }
  end

  defp serialize_rule(rule, :yara) do
    Jason.encode!(%{
      name: rule.name,
      source: rule.source,
      description: rule.description,
      author: rule.author,
      category: rule.category,
      severity: rule.severity,
      tags: rule.tags,
      mitre_tactics: rule.mitre_tactics,
      mitre_techniques: rule.mitre_techniques,
      malware_family: rule.malware_family,
      threat_actor: rule.threat_actor,
      references: rule.references,
      enabled: rule.enabled
    })
  end

  defp serialize_rule(rule, :sigma) do
    Jason.encode!(%{
      name: rule.name,
      title: rule.title,
      description: rule.description,
      author: rule.author,
      level: rule.level,
      status: rule.status,
      source: rule.source,
      detection: rule.detection,
      logsource_category: rule.logsource_category,
      logsource_product: rule.logsource_product,
      logsource_service: rule.logsource_service,
      mitre_tactics: rule.mitre_tactics,
      mitre_techniques: rule.mitre_techniques,
      references: rule.references,
      tags: rule.tags,
      enabled: rule.enabled
    })
  end

  defp serialize_rule(rule, :ioc) do
    Jason.encode!(%{
      type: rule.type,
      value: rule.value,
      description: rule.description,
      source: rule.source,
      source_ref: rule.source_ref,
      severity: rule.severity,
      confidence: rule.confidence,
      tags: rule.tags,
      metadata: rule.metadata,
      malware_family: rule.malware_family,
      threat_actor: rule.threat_actor,
      campaign: rule.campaign,
      mitre_tactics: rule.mitre_tactics,
      mitre_techniques: rule.mitre_techniques,
      enabled: rule.enabled
    })
  end
end
