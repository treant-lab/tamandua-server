defmodule TamanduaServerWeb.API.V1.AuditLogController do
  @moduledoc """
  Controller for audit log API endpoints.

  Provides paginated access to audit log entries with filtering capabilities.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.AuditLog

  @doc """
  List audit log entries with pagination and filtering.

  ## Query Parameters

  - `page` - Page number (default: 1)
  - `per_page` - Entries per page (default: 50, max: 500)
  - `search` - Search in action, user, details
  - `action_type` - Filter by action type (login, logout, config_change, etc.)
  - `user` - Filter by user email
  - `date_from` - Start date (YYYY-MM-DD or ISO 8601)
  - `date_to` - End date (YYYY-MM-DD or ISO 8601)
  """
  def index(conn, params) do
    page = parse_int(params["page"], 1)
    per_page = parse_int(params["per_page"], 50) |> min(500)

    # Get organization_id from current user if authenticated
    organization_id = get_organization_id(conn)

    result = AuditLog.list_entries(
      page: page,
      per_page: per_page,
      search: params["search"],
      action_type: params["action_type"],
      user: params["user"],
      date_from: params["date_from"],
      date_to: params["date_to"],
      organization_id: organization_id
    )

    entries = Enum.map(result.entries, &format_entry/1)

    json(conn, %{
      data: entries,
      pagination: %{
        page: result.page,
        per_page: result.per_page,
        total: result.total,
        total_pages: result.total_pages
      }
    })
  end

  @doc """
  Get audit statistics by action type.
  """
  def stats(conn, params) do
    organization_id = get_organization_id(conn)

    counts = AuditLog.count_by_action_type(
      organization_id: organization_id,
      date_from: params["date_from"],
      date_to: params["date_to"]
    )

    json(conn, %{
      data: counts,
      action_types: TamanduaServer.Audit.AuditLog.action_types()
    })
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp format_entry(entry) do
    # Build target string from resource_type and resource_id
    target = build_target(entry.resource_type, entry.resource_id)

    # Format details for display
    details = format_details(entry.details, entry.action)

    %{
      id: entry.id,
      timestamp: entry.inserted_at,
      user: entry.user_email || "system",
      action: entry.action,
      action_type: entry.action_type,
      target: target,
      details: details,
      ip_address: entry.ip_address || ""
    }
  end

  defp build_target(nil, nil), do: ""
  defp build_target(resource_type, nil), do: resource_type || ""
  defp build_target(nil, resource_id), do: resource_id || ""
  defp build_target(resource_type, resource_id), do: "#{resource_type}:#{resource_id}"

  defp format_details(nil, _action), do: ""
  defp format_details(details, _action) when details == %{}, do: ""

  defp format_details(details, action) when is_map(details) do
    # Try to build a human-readable summary
    cond do
      Map.has_key?(details, "changes") ->
        "Changed: #{inspect(details["changes"])}"

      Map.has_key?(details, "playbook_name") ->
        "Playbook: #{details["playbook_name"]}"

      Map.has_key?(details, "target_email") ->
        "Target: #{details["target_email"]}"

      Map.has_key?(details, "method") and action =~ "login" ->
        "Method: #{details["method"]}"

      true ->
        details
        |> Map.take(["reason", "result", "status", "message", "endpoint"])
        |> Enum.map(fn {k, v} -> "#{k}: #{v}" end)
        |> Enum.join(", ")
    end
  end

  defp format_details(details, _action) do
    to_string(details)
  end

  defp get_organization_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ -> nil
    end
  end

  defp parse_int(nil, default), do: default

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {num, _} -> num
      :error -> default
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default
end
