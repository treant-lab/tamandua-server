defmodule TamanduaServer.Hunting.Workflow do
  @moduledoc """
  Schema for hunting workflows (templates and custom workflows).

  A workflow is a structured, step-by-step guide for threat hunting that:
  - Defines a sequence of hunting steps
  - Includes decision trees based on findings
  - Tracks hypotheses and evidence
  - Generates final hunt reports

  Workflows can be:
  - Pre-built templates (shipped with the system)
  - Custom workflows created by analysts
  - Shared across organizations or kept private
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @categories [
    "lateral_movement",
    "credential_theft",
    "ransomware",
    "c2_communication",
    "persistence",
    "data_exfiltration",
    "privilege_escalation",
    "powershell_abuse",
    "lolbas",
    "shadow_it",
    "insider_threat",
    "malware_hunt",
    "custom"
  ]

  @step_types [
    "query",           # Execute a hunt query
    "decision",        # Make a decision based on previous results
    "manual_review",   # Analyst manual review
    "collect_evidence",# Automated evidence collection
    "notify",          # Send notification
    "export_iocs",     # Export IOCs to MISP/OpenCTI
    "create_alert"     # Create alert from findings
  ]

  schema "hunting_workflows" do
    field :name, :string
    field :description, :string
    field :category, :string
    field :steps, {:array, :map}, default: []
    field :metadata, :map, default: %{}
    field :version, :integer, default: 1
    field :is_custom, :boolean, default: false
    field :is_template, :boolean, default: true
    field :visibility, :string, default: "global"

    # The migration column is `created_by`, so keep the persisted field name
    # and expose the association under a non-conflicting name.
    belongs_to :created_by_user, TamanduaServer.Accounts.User,
      foreign_key: :created_by

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :parent_workflow, __MODULE__

    has_many :executions, TamanduaServer.Hunting.WorkflowExecution

    timestamps()
  end

  @doc false
  def changeset(workflow, attrs) do
    workflow
    |> cast(attrs, [
      :name,
      :description,
      :category,
      :steps,
      :metadata,
      :version,
      :is_custom,
      :is_template,
      :visibility,
      :created_by,
      :organization_id,
      :parent_workflow_id
    ])
    |> validate_required([:name, :category])
    |> validate_inclusion(:category, @categories)
    |> validate_inclusion(:visibility, ["global", "organization", "private"])
    |> validate_steps()
    |> validate_metadata()
  end

  defp validate_steps(changeset) do
    case get_change(changeset, :steps) do
      nil ->
        changeset

      steps when is_list(steps) ->
        if Enum.all?(steps, &valid_step?/1) do
          changeset
        else
          add_error(changeset, :steps, "contains invalid step definitions")
        end

      _ ->
        add_error(changeset, :steps, "must be a list")
    end
  end

  defp valid_step?(%{
         "type" => type,
         "name" => name,
         "description" => _desc
       })
       when type in @step_types and is_binary(name) do
    true
  end

  defp valid_step?(_), do: false

  defp validate_metadata(changeset) do
    case get_change(changeset, :metadata) do
      nil -> changeset
      meta when is_map(meta) -> changeset
      _ -> add_error(changeset, :metadata, "must be a map")
    end
  end

  @doc """
  Get all available step types.
  """
  def step_types, do: @step_types

  @doc """
  Get all available workflow categories.
  """
  def categories, do: @categories
end
