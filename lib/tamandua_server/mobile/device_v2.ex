defmodule TamanduaServer.Mobile.DeviceV2 do
  @moduledoc """
  Ecto schema for mobile_devices_v2 table.

  Represents a managed mobile device (iOS, Android, etc.) with MDM enrollment,
  compliance status, and security posture fields. Each device is scoped to an
  organization and uniquely identified by its `device_id` (from the MDM or agent).
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.MDMCommand

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(ios android chromeos windows linux)
  @compliance_statuses ~w(compliant non_compliant unknown)

  schema "mobile_devices_v2" do
    field :device_id, :string
    field :device_name, :string
    field :platform, :string
    field :os_version, :string
    field :model, :string
    field :serial_number, :string
    field :owner_email, :string

    # MDM
    field :mdm_enrolled, :boolean, default: false
    field :mdm_provider, :string

    # Compliance
    field :compliance_status, :string, default: "unknown"

    # Security posture
    field :encryption_enabled, :boolean, default: false
    field :jailbroken, :boolean, default: false
    field :passcode_set, :boolean, default: true

    # Temporal
    field :last_seen_at, :utc_datetime_usec
    field :enrolled_at, :utc_datetime_usec

    belongs_to :organization, Organization
    has_many :commands, MDMCommand, foreign_key: :device_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(device_id)a
  @optional_fields ~w(
    device_name platform os_version model serial_number owner_email
    mdm_enrolled mdm_provider compliance_status
    encryption_enabled jailbroken passcode_set
    last_seen_at enrolled_at organization_id
  )a

  @doc """
  Default changeset for creating or updating a mobile device.
  """
  def changeset(device, attrs) do
    device
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:platform, @platforms)
    |> validate_inclusion(:compliance_status, @compliance_statuses)
    |> unique_constraint([:organization_id, :device_id],
      name: :mobile_devices_v2_organization_id_device_id_index
    )
    |> foreign_key_constraint(:organization_id)
  end

  # ---------------------------------------------------------------------------
  # Query helpers
  # ---------------------------------------------------------------------------

  @doc "Scope query to a single organization."
  def by_organization(query \\ __MODULE__, organization_id) do
    from d in query, where: d.organization_id == ^organization_id
  end

  @doc "Filter by platform."
  def by_platform(query \\ __MODULE__, platform) do
    from d in query, where: d.platform == ^platform
  end

  @doc "Filter by compliance status."
  def by_compliance(query \\ __MODULE__, status) do
    from d in query, where: d.compliance_status == ^status
  end

  @doc "Filter to MDM-enrolled devices only."
  def mdm_enrolled_only(query \\ __MODULE__) do
    from d in query, where: d.mdm_enrolled == true
  end

  @doc "Filter jailbroken / rooted devices."
  def jailbroken_only(query \\ __MODULE__) do
    from d in query, where: d.jailbroken == true
  end

  @doc "Filter devices without encryption."
  def unencrypted(query \\ __MODULE__) do
    from d in query, where: d.encryption_enabled == false
  end

  @doc "Filter devices without a passcode."
  def no_passcode(query \\ __MODULE__) do
    from d in query, where: d.passcode_set == false
  end
end
