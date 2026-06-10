defmodule TamanduaServer.Dashboards do
  @moduledoc """
  The Dashboards context.

  Provides functions for managing user dashboards, layouts, and widgets.
  """

  alias TamanduaServer.Dashboards.Manager

  # Delegate all functions to Manager for cleaner API
  defdelegate list_user_layouts(user_id), to: Manager
  defdelegate list_template_layouts(), to: Manager
  defdelegate get_layout(id), to: Manager
  defdelegate get_or_create_default_layout(user_id, organization_id \\ nil), to: Manager
  defdelegate get_default_layout(user_id), to: Manager
  defdelegate create_layout(attrs), to: Manager
  defdelegate create_default_layout(user_id, organization_id \\ nil), to: Manager
  defdelegate create_from_template(user_id, template_type, organization_id \\ nil), to: Manager
  defdelegate update_layout(layout, attrs), to: Manager
  defdelegate delete_layout(layout), to: Manager
  defdelegate set_default_layout(layout_id, user_id), to: Manager

  defdelegate list_layout_widgets(layout_id), to: Manager
  defdelegate get_widget(id), to: Manager
  defdelegate create_widget(attrs), to: Manager
  defdelegate update_widget(widget, attrs), to: Manager
  defdelegate update_widget_positions(widgets_positions), to: Manager
  defdelegate delete_widget(widget), to: Manager

  defdelegate fetch_widget_data(widget), to: Manager
  defdelegate export_layout(layout), to: Manager
  defdelegate import_layout(user_id, json_data, organization_id \\ nil), to: Manager
end
