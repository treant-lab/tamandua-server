defmodule TamanduaServer.Dashboards.Widget do
  @moduledoc """
  Schema for dashboard widgets.
  Each widget represents a visual component on a dashboard with specific configuration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @widget_types ~w(
    threat_level_gauge
    top_detections
    geo_map
    timeline_viewer
    agent_health_overview
    agent_status_overview
    recent_alerts
    detection_efficacy
    detection_performance
    system_health
    top_threats
    response_actions
    mitre_attack_heatmap
    alert_volume_trends
    alert_trend
    response_time_metrics
    sla_compliance
    ioc_trends
    network_topology
    user_activity
    compliance_score
    cost_tracking
    incident_timeline
    process_tree
    network_traffic
    file_events
    registry_events
    custom_query
  )

  schema "dashboard_widgets" do
    field :widget_type, :string
    field :title, :string
    field :position_x, :integer, default: 0
    field :position_y, :integer, default: 0
    field :width, :integer, default: 4
    field :height, :integer, default: 4
    field :config, :map, default: %{}
    field :refresh_interval, :integer, default: 30000
    field :is_visible, :boolean, default: true
    field :order, :integer, default: 0

    belongs_to :dashboard_layout, TamanduaServer.Dashboards.Layout

    has_one :data_cache, TamanduaServer.Dashboards.WidgetDataCache, on_delete: :delete_all

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(widget_type title dashboard_layout_id position_x position_y width height)a
  @optional_fields ~w(config refresh_interval is_visible order)a

  def changeset(widget, attrs) do
    widget
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:widget_type, @widget_types)
    |> validate_length(:title, min: 1, max: 255)
    |> validate_number(:position_x, greater_than_or_equal_to: 0)
    |> validate_number(:position_y, greater_than_or_equal_to: 0)
    |> validate_number(:width, greater_than: 0, less_than_or_equal_to: 12)
    |> validate_number(:height, greater_than: 0, less_than_or_equal_to: 12)
    |> validate_number(:refresh_interval, greater_than_or_equal_to: 1000)
    |> validate_widget_config()
    |> foreign_key_constraint(:dashboard_layout_id)
  end

  defp validate_widget_config(changeset) do
    widget_type = get_field(changeset, :widget_type)
    config = get_change(changeset, :config)

    if widget_type && config do
      case validate_config_for_type(widget_type, config) do
        :ok -> changeset
        {:error, message} -> add_error(changeset, :config, message)
      end
    else
      changeset
    end
  end

  defp validate_config_for_type("recent_alerts", config) do
    # Validate filters, limit, sort
    cond do
      Map.has_key?(config, "limit") && (!is_integer(config["limit"]) || config["limit"] < 1) ->
        {:error, "limit must be a positive integer"}

      true ->
        :ok
    end
  end

  defp validate_config_for_type("timeline", config) do
    # Validate time_range
    cond do
      Map.has_key?(config, "time_range") &&
          config["time_range"] not in ["1h", "6h", "24h", "7d", "30d", "custom"] ->
        {:error, "invalid time_range"}

      true ->
        :ok
    end
  end

  defp validate_config_for_type("geo_map", config) do
    # Validate zoom, center
    cond do
      Map.has_key?(config, "zoom") && (!is_integer(config["zoom"]) || config["zoom"] < 1 || config["zoom"] > 20) ->
        {:error, "zoom must be between 1 and 20"}

      true ->
        :ok
    end
  end

  defp validate_config_for_type(_type, _config), do: :ok

  @doc """
  Returns the list of available widget types.
  """
  def widget_types, do: @widget_types

  @doc """
  Returns the default configuration for a widget type.
  """
  def default_config("threat_level_gauge") do
    %{
      "show_counts" => true,
      "show_percentage" => true,
      "animate" => true
    }
  end

  def default_config("top_detections") do
    %{
      "limit" => 10,
      "group_by" => "technique",
      "time_range" => "24h",
      "show_mitre_id" => true
    }
  end

  def default_config("geo_map") do
    %{
      "zoom" => 2,
      "center" => [0, 0],
      "show_heatmap" => true,
      "show_agent_markers" => true,
      "cluster_markers" => true
    }
  end

  def default_config("timeline") do
    %{
      "time_range" => "24h",
      "chart_type" => "line",
      "group_by" => "hour",
      "show_legend" => true,
      "show_grid" => true
    }
  end

  def default_config("agent_status_overview") do
    %{
      "show_version_info" => false,
      "show_last_seen" => true,
      "group_by_os" => false
    }
  end

  def default_config("recent_alerts") do
    %{
      "limit" => 20,
      "severity_filter" => [],
      "status_filter" => [],
      "show_pagination" => true,
      "auto_refresh" => true
    }
  end

  def default_config("detection_performance") do
    %{
      "time_range" => "7d",
      "metrics" => ["precision", "recall", "f1_score"],
      "show_trend" => true
    }
  end

  def default_config("system_health") do
    %{
      "metrics" => ["cpu", "memory", "latency"],
      "show_alerts" => true,
      "threshold_cpu" => 80,
      "threshold_memory" => 85
    }
  end

  def default_config("top_threats") do
    %{
      "limit" => 10,
      "group_by" => "malware_family",
      "time_range" => "24h",
      "show_ioc_count" => true
    }
  end

  def default_config("response_actions") do
    %{
      "limit" => 15,
      "status_filter" => [],
      "show_timeline" => true
    }
  end

  def default_config("mitre_attack_heatmap") do
    %{
      "time_range" => "7d",
      "tactics" => [],
      "show_technique_count" => true
    }
  end

  def default_config("alert_trend") do
    %{
      "time_range" => "7d",
      "chart_type" => "area",
      "group_by" => "day",
      "split_by_severity" => true
    }
  end

  def default_config("custom_query") do
    %{
      "query" => "",
      "visualization" => "table",
      "refresh_interval" => 60000
    }
  end

  def default_config(_), do: %{}

  @doc """
  Returns a human-readable name for a widget type.
  """
  def widget_type_name("threat_level_gauge"), do: "Threat Level Gauge"
  def widget_type_name("top_detections"), do: "Top Detections"
  def widget_type_name("geo_map"), do: "Geographic Map"
  def widget_type_name("timeline"), do: "Event Timeline"
  def widget_type_name("timeline_viewer"), do: "Timeline Viewer"
  def widget_type_name("agent_health_overview"), do: "Agent Health Overview"
  def widget_type_name("agent_status_overview"), do: "Agent Status Overview"
  def widget_type_name("recent_alerts"), do: "Recent Alerts"
  def widget_type_name("detection_efficacy"), do: "Detection Efficacy"
  def widget_type_name("detection_performance"), do: "Detection Performance"
  def widget_type_name("system_health"), do: "System Health"
  def widget_type_name("top_threats"), do: "Top Threats"
  def widget_type_name("response_actions"), do: "Response Actions"
  def widget_type_name("mitre_attack_heatmap"), do: "MITRE ATT&CK Heatmap"
  def widget_type_name("alert_volume_trends"), do: "Alert Volume Trends"
  def widget_type_name("alert_trend"), do: "Alert Trend"
  def widget_type_name("response_time_metrics"), do: "Response Time Metrics"
  def widget_type_name("sla_compliance"), do: "SLA Compliance"
  def widget_type_name("ioc_trends"), do: "IOC Trends"
  def widget_type_name("network_topology"), do: "Network Topology"
  def widget_type_name("user_activity"), do: "User Activity"
  def widget_type_name("compliance_score"), do: "Compliance Score"
  def widget_type_name("cost_tracking"), do: "Cost Tracking"
  def widget_type_name("incident_timeline"), do: "Incident Timeline"
  def widget_type_name("process_tree"), do: "Process Tree"
  def widget_type_name("network_traffic"), do: "Network Traffic"
  def widget_type_name("file_events"), do: "File Events"
  def widget_type_name("registry_events"), do: "Registry Events"
  def widget_type_name("custom_query"), do: "Custom Query"
  def widget_type_name(_), do: "Unknown Widget"
end
