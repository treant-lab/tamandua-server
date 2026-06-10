defmodule TamanduaServer.Mobile.Device do
  @moduledoc """
  Schema for mobile devices (iOS and Android).

  Mobile devices are registered through the mobile agent app or synced
  from MDM platforms (Intune, Workspace ONE, Jamf, Google Workspace).
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.{MobileApp, MobileEvent}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(ios android)
  @statuses ~w(active lost wiped retired pending)
  @mdm_providers ~w(intune workspace_one jamf google_workspace mobileiron soti none)

  schema "mobile_devices" do
    field :device_id, :string
    field :platform, :string
    field :model, :string
    field :manufacturer, :string
    field :os_version, :string
    field :agent_version, :string
    field :serial_number, :string

    # MDM Integration
    field :mdm_enrolled, :boolean, default: false
    field :mdm_provider, :string, default: "none"
    field :mdm_device_id, :string
    field :mdm_compliance_status, :string
    field :mdm_last_sync, :naive_datetime

    # Security Posture
    field :is_jailbroken, :boolean, default: false
    field :is_rooted, :boolean, default: false
    field :passcode_enabled, :boolean
    field :passcode_compliant, :boolean
    field :encryption_enabled, :boolean
    field :biometric_enabled, :boolean
    field :developer_mode_enabled, :boolean, default: false
    field :usb_debugging_enabled, :boolean, default: false

    # Network
    field :ip_address, :string
    field :mac_address, :string
    field :wifi_mac_address, :string
    field :bluetooth_mac_address, :string
    field :imei, :string
    field :phone_number, :string

    # User assignment
    field :user_email, :string
    field :user_name, :string
    field :department, :string

    # Status
    field :status, :string, default: "active"
    field :last_seen_at, :naive_datetime
    field :enrolled_at, :naive_datetime
    field :last_location, :map

    # Risk scoring
    field :risk_score, :integer, default: 0
    field :risk_factors, {:array, :string}, default: []

    # Metadata
    field :tags, {:array, :string}, default: []
    field :custom_attributes, :map, default: %{}

    belongs_to :organization, Organization

    has_many :apps, MobileApp, foreign_key: :device_id
    has_many :events, MobileEvent, foreign_key: :device_id

    timestamps()
  end

  @required_fields ~w(organization_id device_id platform)a
  @optional_fields ~w(
    model manufacturer os_version agent_version serial_number
    mdm_enrolled mdm_provider mdm_device_id mdm_compliance_status mdm_last_sync
    is_jailbroken is_rooted passcode_enabled passcode_compliant
    encryption_enabled biometric_enabled developer_mode_enabled usb_debugging_enabled
    ip_address mac_address wifi_mac_address bluetooth_mac_address imei phone_number
    user_email user_name department
    status last_seen_at enrolled_at last_location
    risk_score risk_factors tags custom_attributes
  )a

  @doc false
  def changeset(device, attrs) do
    device
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:platform, @platforms)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:mdm_provider, @mdm_providers)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> unique_constraint([:organization_id, :device_id])
    |> foreign_key_constraint(:organization_id)
    |> calculate_risk_score()
  end

  @doc """
  Changeset for registering a new mobile device from the agent.
  """
  def registration_changeset(device, attrs) do
    device
    |> cast(attrs, [
      :organization_id,
      :device_id,
      :platform,
      :model,
      :manufacturer,
      :os_version,
      :agent_version,
      :serial_number,
      :ip_address,
      :mac_address
    ])
    |> validate_required([:organization_id, :device_id, :platform])
    |> validate_inclusion(:platform, @platforms)
    |> put_change(:status, "pending")
    |> put_change(:enrolled_at, NaiveDateTime.utc_now())
    |> put_change(:last_seen_at, NaiveDateTime.utc_now())
    |> unique_constraint([:organization_id, :device_id])
  end

  @doc """
  Changeset for updating security posture from agent telemetry.
  """
  def posture_changeset(device, attrs) do
    device
    |> cast(attrs, [
      :is_jailbroken,
      :is_rooted,
      :passcode_enabled,
      :passcode_compliant,
      :encryption_enabled,
      :biometric_enabled,
      :developer_mode_enabled,
      :usb_debugging_enabled,
      :last_seen_at
    ])
    |> calculate_risk_score()
  end

  @doc """
  Changeset for MDM sync updates.
  """
  def mdm_sync_changeset(device, attrs) do
    device
    |> cast(attrs, [
      :mdm_enrolled,
      :mdm_provider,
      :mdm_device_id,
      :mdm_compliance_status,
      :mdm_last_sync,
      :user_email,
      :user_name,
      :department
    ])
    |> validate_inclusion(:mdm_provider, @mdm_providers)
  end

  # Calculate risk score based on security posture
  defp calculate_risk_score(changeset) do
    if get_change(changeset, :is_jailbroken) != nil or
       get_change(changeset, :is_rooted) != nil or
       get_change(changeset, :passcode_enabled) != nil or
       get_change(changeset, :encryption_enabled) != nil do

      jailbroken = get_field(changeset, :is_jailbroken) || false
      rooted = get_field(changeset, :is_rooted) || false
      passcode = get_field(changeset, :passcode_enabled)
      encryption = get_field(changeset, :encryption_enabled)
      dev_mode = get_field(changeset, :developer_mode_enabled) || false
      usb_debug = get_field(changeset, :usb_debugging_enabled) || false

      {score, factors} = calculate_risk(jailbroken, rooted, passcode, encryption, dev_mode, usb_debug)

      changeset
      |> put_change(:risk_score, score)
      |> put_change(:risk_factors, factors)
    else
      changeset
    end
  end

  defp calculate_risk(jailbroken, rooted, passcode, encryption, dev_mode, usb_debug) do
    factors = []
    score = 0

    # Critical: Jailbreak/Root
    {score, factors} = if jailbroken or rooted do
      {score + 40, ["jailbroken_or_rooted" | factors]}
    else
      {score, factors}
    end

    # High: No passcode
    {score, factors} = if passcode == false do
      {score + 25, ["no_passcode" | factors]}
    else
      {score, factors}
    end

    # High: No encryption
    {score, factors} = if encryption == false do
      {score + 20, ["no_encryption" | factors]}
    else
      {score, factors}
    end

    # Medium: Developer mode
    {score, factors} = if dev_mode do
      {score + 10, ["developer_mode_enabled" | factors]}
    else
      {score, factors}
    end

    # Medium: USB debugging
    {score, factors} = if usb_debug do
      {score + 10, ["usb_debugging_enabled" | factors]}
    else
      {score, factors}
    end

    {min(score, 100), factors}
  end

  # Query helpers

  @doc """
  Query devices by organization.
  """
  def by_organization(query \\ __MODULE__, organization_id) do
    from d in query, where: d.organization_id == ^organization_id
  end

  @doc """
  Query devices by platform.
  """
  def by_platform(query \\ __MODULE__, platform) do
    from d in query, where: d.platform == ^platform
  end

  @doc """
  Query devices by status.
  """
  def by_status(query \\ __MODULE__, status) do
    from d in query, where: d.status == ^status
  end

  @doc """
  Query devices that are compromised (jailbroken/rooted).
  """
  def compromised(query \\ __MODULE__) do
    from d in query, where: d.is_jailbroken == true or d.is_rooted == true
  end

  @doc """
  Query devices with high risk score.
  """
  def high_risk(query \\ __MODULE__, threshold \\ 50) do
    from d in query, where: d.risk_score >= ^threshold
  end

  @doc """
  Query devices not seen within given hours.
  """
  def stale(query \\ __MODULE__, hours \\ 24) do
    cutoff = NaiveDateTime.add(NaiveDateTime.utc_now(), -hours * 3600)
    from d in query, where: d.last_seen_at < ^cutoff
  end

  @doc """
  Query devices enrolled with MDM.
  """
  def mdm_enrolled(query \\ __MODULE__) do
    from d in query, where: d.mdm_enrolled == true
  end

  @doc """
  Query devices not compliant with MDM policies.
  """
  def non_compliant(query \\ __MODULE__) do
    from d in query, where: d.mdm_compliance_status != "compliant"
  end
end
