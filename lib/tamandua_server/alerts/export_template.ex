defmodule TamanduaServer.Alerts.ExportTemplate do
  @moduledoc """
  Schema for saved alert export templates.

  Templates allow users to save column selections, filters, and scheduling
  preferences for reusable exports.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "alert_export_templates" do
    field :name, :string
    field :description, :string

    # Export configuration
    field :format, :string  # csv, json, pdf
    field :columns, {:array, :string}, default: []
    field :filter_json, :map, default: %{}
    field :include_evidence, :boolean, default: false
    field :include_process_chain, :boolean, default: false

    # Schedule configuration
    field :scheduled, :boolean, default: false
    field :schedule_type, :string  # daily, weekly, monthly
    field :schedule_cron, :string
    field :schedule_timezone, :string, default: "UTC"
    field :max_records, :integer

    # Delivery configuration
    field :delivery_method, :string  # download, email, s3, sftp
    field :delivery_config, :map, default: %{}  # email addresses, S3 bucket, SFTP credentials

    # Retention
    field :retention_days, :integer, default: 7

    # Sharing
    field :is_shared, :boolean, default: false
    field :last_run_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    timestamps()
  end

  @doc false
  def changeset(template, attrs) do
    template
    |> cast(attrs, [
      :name,
      :description,
      :format,
      :columns,
      :filter_json,
      :include_evidence,
      :include_process_chain,
      :scheduled,
      :schedule_type,
      :schedule_cron,
      :schedule_timezone,
      :max_records,
      :delivery_method,
      :delivery_config,
      :retention_days,
      :is_shared,
      :last_run_at,
      :organization_id,
      :created_by_id
    ])
    |> validate_required([:name, :format, :organization_id, :created_by_id])
    |> validate_inclusion(:format, ~w(csv json pdf))
    |> validate_inclusion(:schedule_type, ~w(daily weekly monthly))
    |> validate_inclusion(:delivery_method, ~w(download email s3 sftp))
    |> validate_number(:max_records, greater_than: 0, less_than_or_equal: 100_000)
    |> validate_number(:retention_days, greater_than: 0, less_than_or_equal: 365)
    |> validate_columns()
    |> validate_schedule()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  defp validate_columns(changeset) do
    case get_change(changeset, :columns) do
      nil -> changeset
      [] -> add_error(changeset, :columns, "must select at least one column")
      columns when is_list(columns) ->
        if Enum.all?(columns, &valid_column?/1) do
          changeset
        else
          add_error(changeset, :columns, "contains invalid column names")
        end
    end
  end

  defp validate_schedule(changeset) do
    scheduled = get_change(changeset, :scheduled) || get_field(changeset, :scheduled)

    if scheduled do
      changeset
      |> validate_required([:schedule_type, :delivery_method])
      |> validate_cron_expression()
    else
      changeset
    end
  end

  defp validate_cron_expression(changeset) do
    case get_change(changeset, :schedule_cron) do
      nil -> changeset
      cron ->
        case Crontab.CronExpression.Parser.parse(cron) do
          {:ok, _} -> changeset
          {:error, _} -> add_error(changeset, :schedule_cron, "invalid cron expression")
        end
    end
  end

  defp valid_column?(column) when is_binary(column) do
    column in available_columns()
  end
  defp valid_column?(_), do: false

  @doc """
  Returns list of available columns for export.
  """
  def available_columns do
    [
      "id",
      "severity",
      "title",
      "description",
      "status",
      "verdict",
      "threat_score",
      "agent_hostname",
      "agent_os",
      "assigned_to_name",
      "mitre_tactics",
      "mitre_techniques",
      "attributed_actors",
      "campaign_id",
      "occurrence_count",
      "workflow_state",
      "escalation_level",
      "sla_acknowledge_breached",
      "sla_resolve_breached",
      "inserted_at",
      "acknowledged_at",
      "resolved_at",
      "last_seen_at"
    ]
  end

  @doc """
  Returns default column set for exports.
  """
  def default_columns do
    [
      "id",
      "severity",
      "title",
      "status",
      "threat_score",
      "agent_hostname",
      "mitre_tactics",
      "inserted_at"
    ]
  end
end
