defmodule TamanduaServer.Mobile.MDMCommand do
  @moduledoc """
  Ecto schema for the mdm_commands table.

  Represents an MDM command issued to a mobile device (lock, wipe,
  install_profile, remove_profile, etc.). Tracks lifecycle from
  pending -> sent -> completed/failed.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.DeviceV2

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @command_types ~w(
    lock wipe install_profile remove_profile update_policy ring locate enable_vpn remove_app push_config
    refresh_network_policy collect_diagnostics managed_shell shell_execute dns_status request_dns_vpn_consent
    enable_dns_protection disable_dns_protection clear_dns_cache block_domain unblock_domain
    network_status list_network_flows inspect_packet sync_app_inventory inspect_package screen_capture
    evidence_session cancel_evidence_session
  )
  @statuses ~w(pending sent completed failed)

  schema "mdm_commands" do
    field(:command_type, :string)
    field(:status, :string, default: "pending")
    field(:payload, :map, default: %{})
    field(:result, :map, default: %{})

    field(:sent_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    field(:requested_by, :string)

    belongs_to(:device, DeviceV2, foreign_key: :device_id)
    belongs_to(:organization, Organization)

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(command_type device_id)a
  @optional_fields ~w(
    status payload result sent_at completed_at requested_by organization_id
  )a

  @doc """
  Default changeset for creating or updating an MDM command.
  """
  def changeset(command, attrs) do
    command
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:command_type, @command_types)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:device_id)
    |> foreign_key_constraint(:organization_id)
  end

  # ---------------------------------------------------------------------------
  # Query helpers
  # ---------------------------------------------------------------------------

  @doc "Query commands by device."
  def by_device(query \\ __MODULE__, device_id) do
    from(c in query, where: c.device_id == ^device_id)
  end

  @doc "Query commands by organization."
  def by_organization(query \\ __MODULE__, organization_id) do
    from(c in query, where: c.organization_id == ^organization_id)
  end

  @doc "Query commands by status."
  def by_status(query \\ __MODULE__, status) do
    from(c in query, where: c.status == ^status)
  end

  @doc "Query commands by type."
  def by_type(query \\ __MODULE__, command_type) do
    from(c in query, where: c.command_type == ^command_type)
  end

  @doc "Order by most recent first."
  def latest_first(query \\ __MODULE__) do
    from(c in query, order_by: [desc: c.inserted_at])
  end
end
