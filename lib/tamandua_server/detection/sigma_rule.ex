defmodule TamanduaServer.Detection.SigmaRule do
  @moduledoc """
  Schema for Sigma detection rules.

  Sigma rules can be either:
  - Organization-specific rules (organization_id set, is_system_template=false)
  - System templates (organization_id=nil, is_system_template=true)
  - Copies from templates (organization_id set, copied_from_template_id set)
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "sigma_rules" do
    field :name, :string
    field :title, :string
    field :description, :string
    field :author, :string
    # Solana base58 public key for bounty payments (e.g., "TamDevBounty1111111111111111111111111111111")
    field :author_pubkey, :string
    field :level, :string, default: "medium"
    field :status, :string, default: "experimental"
    field :enabled, :boolean, default: true
    field :source, :string
    field :detection, :map, default: %{}
    field :logsource_category, :string
    field :logsource_product, :string
    field :logsource_service, :string
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :references, {:array, :string}, default: []
    field :tags, {:array, :string}, default: []

    # Template system fields
    field :is_system_template, :boolean, default: false
    field :copied_from_template_id, Ecto.UUID

    belongs_to :organization, Organization
    belongs_to :template, __MODULE__, foreign_key: :copied_from_template_id, define_field: false

    timestamps()
  end

  @castable_fields [
    :name,
    :title,
    :description,
    :author,
    :author_pubkey,
    :level,
    :status,
    :enabled,
    :source,
    :detection,
    :logsource_category,
    :logsource_product,
    :logsource_service,
    :mitre_tactics,
    :mitre_techniques,
    :references,
    :tags,
    :organization_id,
    :is_system_template,
    :copied_from_template_id
  ]

  @doc false
  def changeset(sigma_rule, attrs) do
    sigma_rule
    |> cast(attrs, @castable_fields)
    |> validate_required([:name, :source])
    |> validate_organization_or_template()
    |> validate_author_pubkey()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:copied_from_template_id)
  end

  @doc """
  Changeset for creating system templates.
  System templates have is_system_template=true and no organization_id.
  """
  def template_changeset(sigma_rule, attrs) do
    attrs =
      attrs
      |> Map.put(:is_system_template, true)
      |> Map.delete(:organization_id)
      |> Map.delete("organization_id")

    sigma_rule
    |> cast(attrs, @castable_fields)
    |> validate_required([:name, :source])
    |> put_change(:is_system_template, true)
    |> put_change(:organization_id, nil)
    |> validate_author_pubkey()
  end

  # Validates that either organization_id is set OR is_system_template is true
  defp validate_organization_or_template(changeset) do
    is_system_template = get_field(changeset, :is_system_template)
    organization_id = get_field(changeset, :organization_id)

    cond do
      is_system_template == true ->
        # System templates don't need organization_id
        changeset

      is_nil(organization_id) ->
        add_error(changeset, :organization_id, "is required for non-template rules")

      true ->
        changeset
    end
  end

  # Validate author_pubkey is a valid Solana base58 address (32-44 characters)
  # This is optional - rules without pubkey just don't receive bounties
  defp validate_author_pubkey(changeset) do
    case get_change(changeset, :author_pubkey) do
      nil ->
        changeset

      pubkey when is_binary(pubkey) ->
        # Basic Solana base58 validation: 32-44 chars, alphanumeric (no 0, O, I, l)
        if Regex.match?(~r/^[1-9A-HJ-NP-Za-km-z]{32,44}$/, pubkey) do
          changeset
        else
          add_error(changeset, :author_pubkey, "must be a valid Solana base58 public key (32-44 characters)")
        end

      _ ->
        add_error(changeset, :author_pubkey, "must be a string")
    end
  end
end