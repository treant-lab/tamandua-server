defmodule TamanduaServerWeb.RedirectController do
  @moduledoc """
  Handles redirects from legacy LiveView routes to the new React UI.
  """
  use TamanduaServerWeb, :controller

  def to_app_dashboard(conn, _params) do
    redirect(conn, to: "/app/dashboard")
  end

  def to_app_agents(conn, _params) do
    redirect(conn, to: "/app/agents")
  end

  def to_app_alerts(conn, _params) do
    redirect(conn, to: "/app/alerts")
  end

  def to_app_events(conn, _params) do
    redirect(conn, to: "/app/events")
  end

  def to_app_hunt(conn, _params) do
    redirect(conn, to: "/app/hunt")
  end

  def to_app_mitre(conn, _params) do
    redirect(conn, to: "/app/mitre")
  end

  def to_app_settings(conn, _params) do
    redirect(conn, to: "/app/settings")
  end

  def to_agent_deployment_docs(conn, _params) do
    redirect(conn, to: "/app/deploy-agent")
  end

  def to_app_ai_attack_surface(conn, _params) do
    redirect(conn, to: "/app/ai-security/attack-surface")
  end
end
