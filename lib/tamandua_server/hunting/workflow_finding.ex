defmodule TamanduaServer.Hunting.WorkflowFinding do
  @moduledoc """
  Schema for findings discovered during workflow execution.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workflow_findings" do
    field :step_index, :integer
    field :finding_type, :string
    field :severity, :string
    field :title, :string
    field :description, :string
    field :data, :map
    field :exported_to_misp, :boolean, default: false
    field :exported_at, :utc_datetime

    belongs_to :execution, TamanduaServer.Hunting.WorkflowExecution
    belongs_to :linked_alert, TamanduaServer.Alerts.Alert

    timestamps()
  end

  @doc false
  def changeset(finding, attrs) do
    finding
    |> cast(attrs, [
      :execution_id,
      :step_index,
      :finding_type,
      :severity,
      :title,
      :description,
      :data,
      :linked_alert_id,
      :exported_to_misp,
      :exported_at
    ])
    |> validate_required([:execution_id, :finding_type, :title])
    |> validate_inclusion(:severity, ["low", "medium", "high", "critical"])
    |> validate_inclusion(:finding_type, [
      "ioc",
      "suspicious_activity",
      "evidence",
      "anomaly",
      "confirmed_threat",
      "false_positive"
    ])
  end
end
