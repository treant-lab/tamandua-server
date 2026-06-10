defmodule TamanduaServer.Reports.ScheduledReport do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "scheduled_reports" do
    field(:name, :string)
    field(:template_id, :string)
    field(:schedule, :string)
    field(:recipients, {:array, :string}, default: [])
    field(:format, :string, default: "pdf")
    field(:params, :map, default: %{})
    field(:enabled, :boolean, default: true)

    field(:last_run_at, :utc_datetime)
    field(:next_run_at, :utc_datetime)
    field(:created_by, :string)
    field(:organization_id, :binary_id)

    timestamps()
  end

  def changeset(scheduled_report, attrs) do
    scheduled_report
    |> cast(attrs, [
      :name,
      :template_id,
      :schedule,
      :recipients,
      :format,
      :params,
      :enabled,
      :last_run_at,
      :next_run_at,
      :created_by,
      :organization_id
    ])
    |> validate_required([:name, :template_id, :schedule])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:format, ~w(pdf html csv json))
  end
end
