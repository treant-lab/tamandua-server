defmodule TamanduaServer.Dashboards.Manager do
  @moduledoc """
  Business logic for managing dashboards, layouts, and widgets.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Dashboards.{Layout, Widget, WidgetDataCache}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Detection.Engine

  require Logger

  # ========================
  # Layout Management
  # ========================

  @doc """
  Lists all layouts for a user.
  """
  def list_user_layouts(user_id) do
    Layout
    |> where([l], l.user_id == ^user_id)
    |> order_by([l], desc: l.is_default, asc: l.name)
    |> preload(:widgets)
    |> Repo.all()
  end

  @doc """
  Lists all template layouts.
  """
  def list_template_layouts do
    Layout
    |> where([l], l.is_template == true)
    |> order_by([l], asc: l.template_type)
    |> preload(:widgets)
    |> Repo.all()
  end

  @doc """
  Gets a layout by ID with widgets preloaded.
  """
  def get_layout(id) do
    Layout
    |> where([l], l.id == ^id)
    |> preload(:widgets)
    |> Repo.one()
  end

  @doc """
  Gets or creates a default layout for a user.
  """
  def get_or_create_default_layout(user_id, organization_id \\ nil) do
    case get_default_layout(user_id) do
      nil -> create_default_layout(user_id, organization_id)
      layout -> {:ok, layout}
    end
  end

  @doc """
  Gets the default layout for a user.
  """
  def get_default_layout(user_id) do
    Layout
    |> where([l], l.user_id == ^user_id and l.is_default == true)
    |> preload(:widgets)
    |> Repo.one()
  end

  @doc """
  Creates a new layout.
  """
  def create_layout(attrs) do
    %Layout{}
    |> Layout.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Creates a default layout for a user based on SOC analyst template.
  """
  def create_default_layout(user_id, organization_id \\ nil) do
    attrs = %{
      user_id: user_id,
      organization_id: organization_id,
      name: "Default Dashboard",
      description: "Auto-generated default dashboard",
      is_default: true,
      template_type: "soc_analyst",
      layout_config: Layout.default_template_config("soc_analyst")
    }

    case create_layout(attrs) do
      {:ok, layout} ->
        # Create widgets from template
        create_widgets_from_template(layout, "soc_analyst")
        {:ok, Repo.preload(layout, :widgets)}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Creates a layout from a template.
  """
  def create_from_template(user_id, template_type, organization_id \\ nil) do
    attrs = %{
      user_id: user_id,
      organization_id: organization_id,
      name: "#{template_type |> String.replace("_", " ") |> String.capitalize()} Dashboard",
      description: "Dashboard created from #{template_type} template",
      is_default: false,
      template_type: template_type,
      layout_config: Layout.default_template_config(template_type)
    }

    case create_layout(attrs) do
      {:ok, layout} ->
        create_widgets_from_template(layout, template_type)
        {:ok, Repo.preload(layout, :widgets)}

      {:error, _} = error ->
        error
    end
  end

  defp create_widgets_from_template(layout, template_type) do
    template_config = Layout.default_template_config(template_type)
    widgets_config = Map.get(template_config, "widgets", [])

    Enum.each(widgets_config, fn widget_config ->
      attrs = %{
        dashboard_layout_id: layout.id,
        widget_type: widget_config["type"],
        title: Widget.widget_type_name(widget_config["type"]),
        position_x: widget_config["x"],
        position_y: widget_config["y"],
        width: widget_config["w"],
        height: widget_config["h"],
        config: Widget.default_config(widget_config["type"])
      }

      create_widget(attrs)
    end)
  end

  @doc """
  Updates a layout.
  """
  def update_layout(%Layout{} = layout, attrs) do
    layout
    |> Layout.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a layout and all its widgets.
  """
  def delete_layout(%Layout{} = layout) do
    Repo.delete(layout)
  end

  @doc """
  Sets a layout as the default for a user.
  """
  def set_default_layout(layout_id, user_id) do
    Repo.transaction(fn ->
      # Unset current default
      from(l in Layout,
        where: l.user_id == ^user_id and l.is_default == true
      )
      |> Repo.update_all(set: [is_default: false])

      # Set new default
      layout = Repo.get!(Layout, layout_id)

      if layout.user_id == user_id do
        layout
        |> Layout.changeset(%{is_default: true})
        |> Repo.update!()
      else
        Repo.rollback(:unauthorized)
      end
    end)
  end

  # ========================
  # Widget Management
  # ========================

  @doc """
  Lists all widgets for a layout.
  """
  def list_layout_widgets(layout_id) do
    Widget
    |> where([w], w.dashboard_layout_id == ^layout_id)
    |> order_by([w], asc: w.order)
    |> Repo.all()
  end

  @doc """
  Gets a widget by ID.
  """
  def get_widget(id) do
    Repo.get(Widget, id)
  end

  @doc """
  Creates a new widget.
  """
  def create_widget(attrs) do
    %Widget{}
    |> Widget.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a widget.
  """
  def update_widget(%Widget{} = widget, attrs) do
    widget
    |> Widget.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates widget positions (for drag-and-drop).
  """
  def update_widget_positions(widgets_positions) when is_list(widgets_positions) do
    Repo.transaction(fn ->
      Enum.map(widgets_positions, fn %{"id" => id} = attrs ->
        widget = Repo.get!(Widget, id)

        widget
        |> Widget.changeset(attrs)
        |> Repo.update!()
      end)
    end)
  end

  @doc """
  Deletes a widget.
  """
  def delete_widget(%Widget{} = widget) do
    Repo.delete(widget)
  end

  # ========================
  # Widget Data Fetching
  # ========================

  @doc """
  Fetches data for a widget based on its type and configuration.
  Returns cached data if available and not expired.
  """
  def fetch_widget_data(%Widget{} = widget) do
    # Check cache first
    case get_cached_widget_data(widget.id) do
      {:ok, data} ->
        {:ok, data}

      :miss ->
        # Fetch fresh data
        case fetch_fresh_widget_data(widget) do
          {:ok, data} ->
            # Cache the data
            cache_widget_data(widget.id, data, widget.refresh_interval)
            {:ok, data}

          {:error, _} = error ->
            error
        end
    end
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "threat_level_gauge"} = widget) do
    time_range = get_time_range(widget.config["time_range"] || "24h")

    alert_counts =
      Alert
      |> where([a], a.inserted_at >= ^time_range)
      |> group_by([a], a.severity)
      |> select([a], {a.severity, count(a.id)})
      |> Repo.all()
      |> Map.new()

    data = %{
      critical: Map.get(alert_counts, "critical", 0),
      high: Map.get(alert_counts, "high", 0),
      medium: Map.get(alert_counts, "medium", 0),
      low: Map.get(alert_counts, "low", 0),
      total: Enum.reduce(alert_counts, 0, fn {_, count}, acc -> acc + count end)
    }

    {:ok, data}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "agent_status_overview"}) do
    total_agents = Repo.aggregate(Agent, :count)

    status_counts =
      Agent
      |> group_by([a], a.status)
      |> select([a], {a.status, count(a.id)})
      |> Repo.all()
      |> Map.new()

    data = %{
      total: total_agents,
      online: Map.get(status_counts, "online", 0),
      offline: Map.get(status_counts, "offline", 0),
      error: Map.get(status_counts, "error", 0)
    }

    {:ok, data}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "top_detections"} = widget) do
    limit = widget.config["limit"] || 10
    time_range = get_time_range(widget.config["time_range"] || "24h")

    top_detections =
      Alert
      |> where([a], a.inserted_at >= ^time_range)
      |> where([a], not is_nil(a.mitre_technique))
      |> group_by([a], a.mitre_technique)
      |> select([a], %{
        technique: a.mitre_technique,
        count: count(a.id)
      })
      |> order_by([a], desc: count(a.id))
      |> limit(^limit)
      |> Repo.all()

    {:ok, %{detections: top_detections}}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "recent_alerts"} = widget) do
    limit = widget.config["limit"] || 20
    severity_filter = widget.config["severity_filter"] || []
    status_filter = widget.config["status_filter"] || []

    query = Alert

    query =
      if severity_filter != [] do
        where(query, [a], a.severity in ^severity_filter)
      else
        query
      end

    query =
      if status_filter != [] do
        where(query, [a], a.status in ^status_filter)
      else
        query
      end

    alerts =
      query
      |> order_by([a], desc: a.inserted_at)
      |> limit(^limit)
      |> select([a], %{
        id: a.id,
        title: a.title,
        severity: a.severity,
        status: a.status,
        mitre_technique: a.mitre_technique,
        agent_id: a.agent_id,
        inserted_at: a.inserted_at
      })
      |> Repo.all()

    {:ok, %{alerts: alerts}}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "timeline"} = widget) do
    time_range = get_time_range(widget.config["time_range"] || "24h")
    group_by = widget.config["group_by"] || "hour"

    interval = case group_by do
      "minute" -> "1 minute"
      "hour" -> "1 hour"
      "day" -> "1 day"
      _ -> "1 hour"
    end

    # Use PostgreSQL's date_trunc for time bucketing
    timeline_data =
      Alert
      |> where([a], a.inserted_at >= ^time_range)
      |> group_by([a], fragment("date_trunc(?, ?)", ^interval, a.inserted_at))
      |> select([a], %{
        timestamp: fragment("date_trunc(?, ?)", ^interval, a.inserted_at),
        count: count(a.id)
      })
      |> order_by([a], asc: fragment("date_trunc(?, ?)", ^interval, a.inserted_at))
      |> Repo.all()

    {:ok, %{timeline: timeline_data}}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "system_health"}) do
    {:ok,
     %{
       status: "insufficient_data",
       insufficient_data: true,
       reason: "No real system health metrics source is configured for this widget"
     }}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "detection_performance"}) do
    verdict_counts =
      Alert
      |> where([a], a.verdict in ["true_positive", "false_positive"])
      |> group_by([a], a.verdict)
      |> select([a], {a.verdict, count(a.id)})
      |> Repo.all()
      |> Map.new()

    true_positives = Map.get(verdict_counts, "true_positive", 0)
    false_positives = Map.get(verdict_counts, "false_positive", 0)
    total = true_positives + false_positives

    if total == 0 do
      {:ok,
       %{
         status: "insufficient_data",
         insufficient_data: true,
         reason: "No true_positive/false_positive alert verdicts are available"
       }}
    else
      precision = Float.round(true_positives / total, 3)

      {:ok,
       %{
         precision: precision,
         recall: nil,
         f1_score: nil,
         source: "alert_verdicts",
         insufficient_data: true,
         reason: "Precision is based on real alert verdicts; recall/f1 require labeled false-negative data"
       }}
    end
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "top_threats"} = widget) do
    limit = widget.config["limit"] || 10
    time_range = get_time_range(widget.config["time_range"] || "24h")

    # This would query malware families from detections
    # For now, return empty
    {:ok, %{threats: []}}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "response_actions"} = widget) do
    limit = widget.config["limit"] || 15

    # This would query response actions
    # For now, return empty
    {:ok, %{actions: []}}
  end

  defp fetch_fresh_widget_data(%Widget{widget_type: "geo_map"}) do
    # Fetch agent locations
    agents =
      Agent
      |> where([a], not is_nil(a.ip_address))
      |> select([a], %{
        id: a.id,
        hostname: a.hostname,
        ip_address: a.ip_address,
        status: a.status
      })
      |> Repo.all()

    # In production, this would use a GeoIP database to convert IPs to coordinates
    {:ok, %{agents: agents, locations: []}}
  end

  defp fetch_fresh_widget_data(_widget) do
    {:ok, %{}}
  end

  # ========================
  # Widget Data Caching
  # ========================

  defp get_cached_widget_data(widget_id) do
    cache_key = "widget_data"

    case Repo.get_by(WidgetDataCache, widget_id: widget_id, cache_key: cache_key) do
      nil ->
        :miss

      cache ->
        if WidgetDataCache.expired?(cache) do
          Repo.delete(cache)
          :miss
        else
          {:ok, cache.data}
        end
    end
  end

  defp cache_widget_data(widget_id, data, ttl_ms) do
    expires_at = DateTime.add(DateTime.utc_now(), ttl_ms, :millisecond)
    cache_key = "widget_data"

    attrs = %{
      widget_id: widget_id,
      cache_key: cache_key,
      data: data,
      expires_at: expires_at
    }

    # Upsert: delete existing and insert new
    Repo.delete_all(from(c in WidgetDataCache, where: c.widget_id == ^widget_id and c.cache_key == ^cache_key))

    %WidgetDataCache{}
    |> WidgetDataCache.changeset(attrs)
    |> Repo.insert()
  end

  # ========================
  # Helpers
  # ========================

  defp get_time_range(time_range_str) do
    now = DateTime.utc_now()

    case time_range_str do
      "1h" -> DateTime.add(now, -1, :hour)
      "6h" -> DateTime.add(now, -6, :hour)
      "24h" -> DateTime.add(now, -24, :hour)
      "7d" -> DateTime.add(now, -7, :day)
      "30d" -> DateTime.add(now, -30, :day)
      _ -> DateTime.add(now, -24, :hour)
    end
  end

  @doc """
  Exports a dashboard layout to JSON for sharing.
  """
  def export_layout(%Layout{} = layout) do
    layout = Repo.preload(layout, :widgets)

    export_data = %{
      name: layout.name,
      description: layout.description,
      template_type: layout.template_type,
      layout_config: layout.layout_config,
      widgets:
        Enum.map(layout.widgets, fn widget ->
          %{
            widget_type: widget.widget_type,
            title: widget.title,
            position_x: widget.position_x,
            position_y: widget.position_y,
            width: widget.width,
            height: widget.height,
            config: widget.config
          }
        end)
    }

    Jason.encode(export_data, pretty: true)
  end

  @doc """
  Imports a dashboard layout from JSON.
  """
  def import_layout(user_id, json_data, organization_id \\ nil) do
    with {:ok, data} <- Jason.decode(json_data),
         {:ok, layout} <- create_imported_layout(user_id, data, organization_id) do
      {:ok, layout}
    else
      {:error, %Jason.DecodeError{}} -> {:error, "Invalid JSON"}
      {:error, _} = error -> error
    end
  end

  defp create_imported_layout(user_id, data, organization_id) do
    layout_attrs = %{
      user_id: user_id,
      organization_id: organization_id,
      name: data["name"] || "Imported Dashboard",
      description: data["description"],
      template_type: data["template_type"] || "custom",
      layout_config: data["layout_config"] || %{}
    }

    Repo.transaction(fn ->
      layout =
        %Layout{}
        |> Layout.changeset(layout_attrs)
        |> Repo.insert!()

      widgets = data["widgets"] || []

      Enum.each(widgets, fn widget_data ->
        widget_attrs = %{
          dashboard_layout_id: layout.id,
          widget_type: widget_data["widget_type"],
          title: widget_data["title"],
          position_x: widget_data["position_x"] || 0,
          position_y: widget_data["position_y"] || 0,
          width: widget_data["width"] || 4,
          height: widget_data["height"] || 4,
          config: widget_data["config"] || %{}
        }

        %Widget{}
        |> Widget.changeset(widget_attrs)
        |> Repo.insert!()
      end)

      Repo.preload(layout, :widgets)
    end)
  end
end
