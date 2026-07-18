defmodule TamanduaServerWeb.GraphQL.Types.PlaybookTypes do
  @moduledoc """
  GraphQL types for Playbooks and Automation.
  """
  use Absinthe.Schema.Notation

  @desc "Playbook trigger type"
  enum :trigger_type do
    value :manual, description: "Manually triggered"
    value :alert, description: "Triggered by alert"
    value :detection, description: "Triggered by detection"
    value :schedule, description: "Scheduled execution"
  end

  @desc "Playbook execution status"
  enum :execution_status do
    value :pending_approval, description: "Waiting for approval"
    value :running, description: "Currently executing"
    value :completed, description: "Successfully completed"
    value :failed, description: "Execution failed"
    value :cancelled, description: "Execution cancelled"
  end

  @desc "An automated response playbook"
  object :playbook do
    field :id, non_null(:id), description: "Unique playbook identifier"
    field :name, non_null(:string), description: "Playbook name"
    field :description, :string, description: "Playbook description"
    field :trigger_type, :string, description: "Trigger type"
    field :trigger_conditions, :json, description: "Conditions for automatic trigger"
    field :steps, list_of(:playbook_step), description: "Playbook steps"
    field :enabled, :boolean, description: "Playbook is enabled"
    field :require_approval, :boolean, description: "Requires human approval"
    field :approval_timeout_minutes, :integer, description: "Approval timeout"
    field :tags, list_of(:string), description: "Tags for categorization"
    field :severity_threshold, :string, description: "Minimum severity to trigger"
    field :execution_count, :integer, description: "Total executions"
    field :success_count, :integer, description: "Successful executions"
    field :last_executed_at, :datetime, description: "Last execution timestamp"
    field :created_by, :id, description: "Creator user ID"
    field :inserted_at, :datetime
    field :updated_at, :datetime

    field :success_rate, :float do
      resolve fn playbook, _, _ ->
        if playbook.execution_count > 0 do
          {:ok, (playbook.success_count || 0) / playbook.execution_count}
        else
          {:ok, nil}
        end
      end
    end

    field :recent_executions, list_of(:playbook_execution) do
      arg :limit, :integer, default_value: 10
      resolve &TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolver.recent_executions/3
    end
  end

  @desc "A step in a playbook"
  object :playbook_step do
    field :action, non_null(:string), description: "Action type"
    field :name, :string, description: "Step name"
    field :params, :json, description: "Action parameters"
    field :timeout_seconds, :integer, description: "Step timeout"
    field :on_failure, :string, description: "Failure handling (continue, stop)"
  end

  @desc "A playbook execution record"
  object :playbook_execution do
    field :id, non_null(:id)
    field :playbook_id, :id
    field :status, :string
    field :trigger_event, :json
    field :steps_completed, list_of(:step_result)
    field :current_step, :integer
    field :error_message, :string
    field :started_at, :datetime
    field :completed_at, :datetime
    field :approved_by, :id
    field :approved_at, :datetime
    field :execution_context, :json

    field :playbook, :playbook do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolver.playbook/3
    end

    field :duration_seconds, :integer do
      resolve fn execution, _, _ ->
        if execution.completed_at && execution.started_at do
          {:ok, DateTime.diff(execution.completed_at, execution.started_at)}
        else
          {:ok, nil}
        end
      end
    end
  end

  @desc "Result of a playbook step"
  object :step_result do
    field :index, :integer
    field :action, :string
    field :status, :string
    field :result, :json
    field :error, :string
    field :completed_at, :datetime
  end

  @desc "Playbook template for common scenarios"
  object :playbook_template do
    field :id, non_null(:string)
    field :name, non_null(:string)
    field :description, :string
    field :category, :string
    field :trigger_type, :string
    field :trigger_conditions, :json
    field :steps, list_of(:playbook_step)
    field :require_approval, :boolean
    field :severity_threshold, :string
    field :tags, list_of(:string)
  end

  @desc "Pending approval request"
  object :pending_approval do
    field :execution, :playbook_execution
    field :playbook, :playbook
    field :requested_at, :datetime
    field :expires_at, :datetime
  end

  @desc "Filter input for playbooks"
  input_object :playbook_filter do
    field :enabled, :boolean, description: "Filter by enabled status"
    field :trigger_type, :string, description: "Filter by trigger type"
    field :tag, :string, description: "Filter by tag"
    field :search, :string, description: "Search in name/description"
  end

  @desc "Input for creating a playbook"
  input_object :create_playbook_input do
    field :name, non_null(:string)
    field :description, :string
    field :trigger_type, :string, default_value: "manual"
    field :trigger_conditions, :json
    field :steps, non_null(list_of(:playbook_step_input))
    field :enabled, :boolean, default_value: true
    field :require_approval, :boolean, default_value: false
    field :approval_timeout_minutes, :integer, default_value: 30
    field :tags, list_of(:string)
    field :severity_threshold, :string
  end

  @desc "Input for a playbook step"
  input_object :playbook_step_input do
    field :action, non_null(:string)
    field :name, :string
    field :params, :json
    field :timeout_seconds, :integer
    field :on_failure, :string
  end

  @desc "Input for updating a playbook"
  input_object :update_playbook_input do
    field :name, :string
    field :description, :string
    field :trigger_type, :string
    field :trigger_conditions, :json
    field :steps, list_of(:playbook_step_input)
    field :enabled, :boolean
    field :require_approval, :boolean
    field :approval_timeout_minutes, :integer
    field :tags, list_of(:string)
    field :severity_threshold, :string
  end

  @desc "Input for executing a playbook"
  input_object :execute_playbook_input do
    field :playbook_id, non_null(:id)
    field :context, :json, description: "Execution context (agent_id, alert_id, etc.)"
  end
end
