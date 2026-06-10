defmodule TamanduaServer.Detection.DNSBlocklistEntry do
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dns_blocklist_entries" do
    field :domain, :string
    field :normalized_domain, :string
    field :reason, :string
    field :blocked_by, :string
    field :source, :string, default: "manual"
    field :active, :boolean, default: true

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [
      :organization_id,
      :domain,
      :normalized_domain,
      :reason,
      :blocked_by,
      :source,
      :active
    ])
    |> validate_required([:organization_id, :domain, :normalized_domain, :source])
    |> validate_length(:domain, min: 1, max: 253)
    |> validate_length(:normalized_domain, min: 1, max: 253)
    |> unique_constraint([:organization_id, :normalized_domain],
      name: :dns_blocklist_entries_org_domain_index
    )
    |> foreign_key_constraint(:organization_id)
  end
end
