defmodule TamanduaServer.Mobile.MobileApp do
  @moduledoc """
  Schema for mobile app inventory.

  Tracks installed applications on mobile devices for visibility
  and threat detection (malicious apps, risky permissions, etc.).
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Mobile.Device

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @risk_levels ~w(low medium high critical)
  @installers ~w(app_store play_store enterprise sideload system unknown)

  schema "mobile_app_inventory" do
    # App identification
    field :bundle_id, :string
    field :app_name, :string
    field :version, :string
    field :version_code, :integer

    # Security info
    field :signature_hash, :string
    field :installer, :string, default: "unknown"
    field :permissions, {:array, :string}, default: []
    field :dangerous_permissions, {:array, :string}, default: []

    # Risk assessment
    field :risk_level, :string, default: "low"
    field :risk_reasons, {:array, :string}, default: []
    field :is_system_app, :boolean, default: false
    field :is_debuggable, :boolean, default: false

    # Metadata
    field :developer, :string
    field :category, :string
    field :size_bytes, :integer
    field :installed_at, :naive_datetime
    field :last_updated_at, :naive_datetime

    belongs_to :device, Device

    field :first_seen_at, :naive_datetime

    timestamps()
  end

  @required_fields ~w(device_id bundle_id)a
  @optional_fields ~w(
    app_name version version_code
    signature_hash installer permissions dangerous_permissions
    risk_level risk_reasons is_system_app is_debuggable
    developer category size_bytes installed_at last_updated_at first_seen_at
  )a

  @doc false
  def changeset(app, attrs) do
    app
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:risk_level, @risk_levels)
    |> validate_inclusion(:installer, @installers)
    |> unique_constraint([:device_id, :bundle_id])
    |> foreign_key_constraint(:device_id)
    |> assess_risk()
  end

  @doc """
  Changeset for syncing app inventory from agent.
  """
  def sync_changeset(app, attrs) do
    now = NaiveDateTime.utc_now()

    app
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> put_default(:first_seen_at, now)
    |> validate_inclusion(:installer, @installers)
    |> assess_risk()
    |> unique_constraint([:device_id, :bundle_id])
  end

  defp put_default(changeset, field, value) do
    if get_field(changeset, field) do
      changeset
    else
      put_change(changeset, field, value)
    end
  end

  # Risk assessment based on app characteristics
  defp assess_risk(changeset) do
    if get_change(changeset, :permissions) != nil or
       get_change(changeset, :installer) != nil or
       get_change(changeset, :is_debuggable) != nil do

      permissions = get_field(changeset, :permissions) || []
      installer = get_field(changeset, :installer) || "unknown"
      debuggable = get_field(changeset, :is_debuggable) || false
      is_system = get_field(changeset, :is_system_app) || false

      {level, reasons, dangerous_perms} = calculate_app_risk(permissions, installer, debuggable, is_system)

      changeset
      |> put_change(:risk_level, level)
      |> put_change(:risk_reasons, reasons)
      |> put_change(:dangerous_permissions, dangerous_perms)
    else
      changeset
    end
  end

  @dangerous_android_permissions [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES"
  ]

  @critical_permissions [
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW"
  ]

  defp calculate_app_risk(permissions, installer, debuggable, is_system) do
    reasons = []
    score = 0

    # Skip system apps from risk assessment
    if is_system do
      {"low", [], []}
    else
      dangerous_perms = Enum.filter(permissions, &(&1 in @dangerous_android_permissions))
      critical_perms = Enum.filter(permissions, &(&1 in @critical_permissions))

      # Critical permissions
      {score, reasons} = if length(critical_perms) > 0 do
        {score + 40, ["critical_permissions:#{Enum.join(critical_perms, ",")}" | reasons]}
      else
        {score, reasons}
      end

      # Many dangerous permissions
      {score, reasons} = if length(dangerous_perms) >= 5 do
        {score + 30, ["many_dangerous_permissions:#{length(dangerous_perms)}" | reasons]}
      else
        if length(dangerous_perms) >= 3 do
          {score + 15, ["dangerous_permissions:#{length(dangerous_perms)}" | reasons]}
        else
          {score, reasons}
        end
      end

      # Sideloaded
      {score, reasons} = if installer == "sideload" do
        {score + 25, ["sideloaded" | reasons]}
      else
        {score, reasons}
      end

      # Unknown installer
      {score, reasons} = if installer == "unknown" do
        {score + 10, ["unknown_installer" | reasons]}
      else
        {score, reasons}
      end

      # Debuggable
      {score, reasons} = if debuggable do
        {score + 15, ["debuggable" | reasons]}
      else
        {score, reasons}
      end

      level = cond do
        score >= 60 -> "critical"
        score >= 40 -> "high"
        score >= 20 -> "medium"
        true -> "low"
      end

      {level, reasons, dangerous_perms}
    end
  end

  # Query helpers

  @doc """
  Query apps by device.
  """
  def by_device(query \\ __MODULE__, device_id) do
    from a in query, where: a.device_id == ^device_id
  end

  @doc """
  Query apps by risk level.
  """
  def by_risk_level(query \\ __MODULE__, level) do
    from a in query, where: a.risk_level == ^level
  end

  @doc """
  Query high-risk apps.
  """
  def high_risk(query \\ __MODULE__) do
    from a in query, where: a.risk_level in ["high", "critical"]
  end

  @doc """
  Query sideloaded apps.
  """
  def sideloaded(query \\ __MODULE__) do
    from a in query, where: a.installer == "sideload"
  end

  @doc """
  Query apps with specific permission.
  """
  def with_permission(query \\ __MODULE__, permission) do
    from a in query, where: ^permission in a.permissions
  end

  @doc """
  Query apps by bundle ID pattern.
  """
  def by_bundle_pattern(query \\ __MODULE__, pattern) do
    from a in query, where: ilike(a.bundle_id, ^"%#{pattern}%")
  end
end
