defmodule TamanduaServer.Agents.Agent do
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "agents" do
    field :hostname, :string
    field :ip_address, :string
    field :os_type, :string
    field :os_version, :string
    field :agent_version, :string
    field :machine_id, :binary
    field :status, :string, default: "offline"
    field :last_seen_at, :naive_datetime
    field :config, :map, default: %{}
    field :tags, {:array, :string}, default: []
    # Detailed isolation status from the agent (JSON blob)
    field :isolation_status, :map
    # Network isolation expiry and rollback fields
    field :isolation_expires_at, :utc_datetime
    field :previous_network_state, :map
    field :isolation_exceptions, {:array, :map}, default: []
    # mTLS certificate information
    field :certificate_fingerprint, :string
    field :certificate_subject, :string
    field :certificate_valid_until, :naive_datetime
    field :token_rotation_enabled, :boolean, default: true
    field :token_ttl_hours, :integer, default: 720
    field :token_refresh_window_percent, :integer, default: 60
    field :current_token_generation, :integer, default: 1

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(agent, attrs) do
    agent
    |> cast(attrs, [
      :hostname,
      :ip_address,
      :os_type,
      :os_version,
      :agent_version,
      :machine_id,
      :status,
      :last_seen_at,
      :config,
      :tags,
      :organization_id,
      :isolation_status,
      :isolation_expires_at,
      :previous_network_state,
      :isolation_exceptions,
      :certificate_fingerprint,
      :certificate_subject,
      :certificate_valid_until,
      :token_rotation_enabled,
      :token_ttl_hours,
      :token_refresh_window_percent,
      :current_token_generation
    ])
    |> validate_required([:organization_id, :hostname, :os_type])
    |> validate_inclusion(:status, ~w(registered online offline isolated))
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for tenant API updates.

  Runtime identity, tenant ownership, isolation state, presence and credential
  fields are intentionally excluded. Those fields are maintained by trusted
  enrollment/runtime paths through `changeset/2` and must not be mass assigned
  by an authenticated API client.
  """
  def public_update_changeset(agent, attrs) do
    agent
    |> cast(attrs, [
      :hostname,
      :ip_address,
      :os_type,
      :os_version,
      :agent_version,
      :tags
    ])
    |> validate_required([:organization_id, :hostname, :os_type])
  end
end
