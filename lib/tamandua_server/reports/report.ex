defmodule TamanduaServer.Reports.Report do
  @moduledoc """
  Schema for stored reports.

  Reports are generated on-demand and stored for historical reference.
  Each report contains the template used, date range, and the full
  rendered data structure.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "reports" do
    field :template_id, :string
    field :date_from, :string
    field :date_to, :string
    field :generated_by, :string
    field :status, :string, default: "ready"
    field :data, :map, default: %{}

    # Optional: link to user who generated it
    field :user_id, :binary_id

    timestamps()
  end

  @valid_templates ~w(
    executive_summary
    incident_report
    threat_report
    threat_landscape
    agent_health
    detection_efficacy
    compliance_summary
    compliance_pci_dss
    compliance_hipaa
    compliance_soc2
    compliance_gdpr
    compliance_nist
    compliance_cis
    custom
  )

  @doc false
  def changeset(report, attrs) do
    report
    |> cast(attrs, [:template_id, :date_from, :date_to, :generated_by, :status, :data, :user_id])
    |> validate_required([:template_id, :date_from, :date_to])
    |> validate_inclusion(:status, ~w(generating ready failed))
    |> validate_inclusion(:template_id, @valid_templates)
  end

  @doc """
  Returns the list of valid template IDs.
  """
  def valid_templates, do: @valid_templates
end
