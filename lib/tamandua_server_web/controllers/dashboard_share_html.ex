defmodule TamanduaServerWeb.DashboardShareHTML do
  @moduledoc """
  HTML views for public shared dashboards.
  """
  use TamanduaServerWeb, :html

  # Rename templates to avoid conflict with CoreComponents.show/1
  embed_templates "dashboard_share_html/*"

  def render("show.html", assigns) do
    dashboard_show(assigns)
  end

  def render("password_prompt.html", assigns) do
    password_prompt(assigns)
  end

  # Alias to avoid conflict with imported show/1
  defp dashboard_show(assigns) do
    ~H"""
    <div class="dashboard-share">
      <h1>Shared Dashboard</h1>
      <p>Dashboard content would be rendered here.</p>
    </div>
    """
  end
end
