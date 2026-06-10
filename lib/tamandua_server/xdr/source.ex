defmodule TamanduaServer.XDR.Source do
  @moduledoc """
  Ecto schema for XDR data sources.

  Represents external security data sources that feed into Tamandua's XDR pipeline.
  Each source has its own configuration, health status, and event statistics.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @source_types ~w(firewall proxy email cloud network ids iam siem custom)
  @vendors %{
    "firewall" => ~w(palo_alto fortinet cisco_asa checkpoint sophos),
    "proxy" => ~w(zscaler bluecoat squid mcafee forcepoint),
    "email" => ~w(o365 google_workspace proofpoint mimecast barracuda),
    "cloud" => ~w(aws azure gcp alibaba oracle),
    "network" => ~w(zeek suricata snort corelight darktrace),
    "ids" => ~w(suricata snort zeek),
    "iam" => ~w(okta azure_ad ping_identity cyberark),
    "siem" => ~w(splunk elastic qradar sentinel chronicle),
    "custom" => []
  }

  @status_values ~w(healthy degraded offline unknown)

  schema "xdr_sources" do
    field :name, :string
    field :source_type, :string
    field :vendor, :string
    field :enabled, :boolean, default: true
    field :status, :string, default: "unknown"

    # Configuration (connection settings, polling intervals, etc.)
    field :config, :map, default: %{}

    # Statistics
    field :last_event_at, :utc_datetime_usec
    field :event_count, :integer, default: 0
    field :error_count, :integer, default: 0
    field :last_error, :string

    belongs_to :organization, Organization

    timestamps()
  end

  @required_fields [:name, :source_type]
  @optional_fields [:vendor, :enabled, :status, :config, :last_event_at, :event_count, :error_count, :last_error, :organization_id]

  def changeset(source, attrs) do
    source
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:source_type, @source_types)
    |> validate_inclusion(:status, @status_values)
    |> validate_vendor()
    |> unique_constraint([:organization_id, :name])
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_vendor(changeset) do
    source_type = get_field(changeset, :source_type)
    vendor = get_field(changeset, :vendor)

    if vendor && source_type do
      allowed_vendors = Map.get(@vendors, source_type, [])
      if Enum.empty?(allowed_vendors) or vendor in allowed_vendors do
        changeset
      else
        add_error(changeset, :vendor, "is not valid for source type #{source_type}")
      end
    else
      changeset
    end
  end

  @doc """
  Updates statistics after processing events.
  """
  def update_stats_changeset(source, event_count, error \\ nil) do
    changes = %{
      event_count: (source.event_count || 0) + event_count,
      last_event_at: DateTime.utc_now()
    }

    changes = if error do
      Map.merge(changes, %{
        error_count: (source.error_count || 0) + 1,
        last_error: to_string(error)
      })
    else
      changes
    end

    change(source, changes)
  end

  def source_types, do: @source_types
  def vendors, do: @vendors
end
