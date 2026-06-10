defmodule TamanduaServerWeb.GraphQL.Types.CommonTypes do
  @moduledoc """
  Common GraphQL types and scalars.
  """
  use Absinthe.Schema.Notation

  # Common types

  @desc "Pagination info for cursor-based pagination"
  object :page_info do
    field :has_next_page, non_null(:boolean)
    field :has_previous_page, non_null(:boolean)
    field :start_cursor, :string
    field :end_cursor, :string
    field :total_count, :integer
  end

  @desc "Sort direction"
  enum :sort_direction do
    value :asc, description: "Ascending order"
    value :desc, description: "Descending order"
  end

  @desc "Standard mutation result"
  object :mutation_result do
    field :success, non_null(:boolean)
    field :message, :string
    field :errors, list_of(:field_error)
  end

  @desc "Field-level error"
  object :field_error do
    field :field, :string
    field :message, non_null(:string)
    field :code, :string
  end

  @desc "Delete result"
  object :delete_result do
    field :success, non_null(:boolean)
    field :id, :id
    field :message, :string
  end

  @desc "Generic count result"
  object :count_result do
    field :count, non_null(:integer)
  end

  @desc "Dashboard statistics"
  object :dashboard_stats do
    field :agents, :agent_stats
    field :alerts, :alert_stats
    field :events, :event_stats
    field :threats, :threat_stats
    field :response_actions, :response_stats
    field :detections_today, :integer
    field :mttr_hours, :float, description: "Mean time to respond"
    field :mttd_minutes, :float, description: "Mean time to detect"
  end

  @desc "Threat statistics"
  object :threat_stats do
    field :active_threats, :integer
    field :blocked_today, :integer
    field :quarantined_files, :integer
    field :isolated_hosts, :integer
    field :top_mitre_techniques, list_of(:technique_stat)
  end

  @desc "Technique statistics"
  object :technique_stat do
    field :technique_id, :string
    field :technique_name, :string
    field :count, :integer
  end

  @desc "Response action statistics"
  object :response_stats do
    field :total_actions, :integer
    field :successful, :integer
    field :failed, :integer
    field :pending_approval, :integer
    field :by_type, :json
  end

  @desc "Health status"
  object :health_status do
    field :status, non_null(:string), description: "healthy, degraded, unhealthy"
    field :database, :component_status
    field :redis, :component_status
    field :rabbitmq, :component_status
    field :ml_service, :component_status
    field :uptime_seconds, :integer
    field :version, :string
  end

  @desc "Component health status"
  object :component_status do
    field :status, :string
    field :latency_ms, :integer
    field :details, :string
  end

  @desc "Pagination input"
  input_object :pagination_input do
    field :limit, :integer, default_value: 50, description: "Maximum results to return"
    field :offset, :integer, default_value: 0, description: "Offset for pagination"
    field :cursor, :string, description: "Cursor for cursor-based pagination"
  end

  @desc "Sort input"
  input_object :sort_input do
    field :field, non_null(:string), description: "Field to sort by"
    field :direction, :sort_direction, default_value: :desc
  end

  @desc "Date range input"
  input_object :date_range_input do
    field :since, :datetime, description: "Start of range"
    field :until, :datetime, description: "End of range"
  end
end
