defmodule TamanduaServerWeb.API.V1.EmergingThreatController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.ThreatIntel.EmergingCenter

  def index(conn, params) do
    with {:ok, org_id} <- require_organization(conn) do
      limit = parse_int(params["limit"], 100, 1, 250)

      json(conn, EmergingCenter.summary(org_id, limit: limit))
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def show(conn, %{"id" => id}) do
    with {:ok, org_id} <- require_organization(conn) do
      case EmergingCenter.get_threat(org_id, id) do
        {:ok, threat} ->
          json(conn, %{data: threat})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Emerging threat not found"})
      end
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def collect_evidence(conn, %{"id" => id} = params) do
    with {:ok, org_id} <- require_organization(conn) do
      agent_ids = explicit_agent_ids(params)

      with {:ok, target_agent_ids} <- evidence_target_agent_ids(org_id, id, agent_ids) do
        result = EmergingCenter.collect_evidence(org_id, id, target_agent_ids, params)
        conn |> put_status(:accepted) |> json(result)
      else
        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Emerging threat not found"})

        {:error, :no_targets} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{
            error: "No evidence target agents",
            reason: "Evidence collection needs explicit agent_ids or local exposure with matching agentIds"
          })
      end
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def create_case(conn, %{"id" => id} = params) do
    with {:ok, org_id} <- require_organization(conn) do
      case EmergingCenter.create_case(org_id, current_user_id(conn), id, params) do
        {:ok, case_view} ->
          status = if Map.get(case_view, :action) == "already_exists", do: :ok, else: :created
          conn |> put_status(status) |> json(%{data: case_view})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Emerging threat not found"})

        {:error, :tenant_or_user_required} ->
          conn |> put_status(:forbidden) |> json(%{error: "Tenant and user context required"})

        {:error, changeset = %Ecto.Changeset{}} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "Invalid case", details: changeset_errors(changeset)})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})
      end
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def detection_pack(conn, %{"id" => id}) do
    with {:ok, org_id} <- require_organization(conn) do
      case EmergingCenter.detection_pack_candidate(org_id, id) do
        {:ok, pack} ->
          json(conn, %{data: pack})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Emerging threat not found"})
      end
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns.current_user.organization_id)
  end

  defp current_user_id(conn), do: conn.assigns[:current_user] && conn.assigns.current_user.id

  defp require_organization(conn) do
    case current_organization_id(conn) do
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> {:error, :tenant_required}
    end
  end

  defp tenant_required(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Tenant context required"})
  end

  defp explicit_agent_ids(params) do
    params
    |> Map.get("agent_ids", Map.get(params, "agents", []))
    |> List.wrap()
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp evidence_target_agent_ids(_org_id, _id, agent_ids) when agent_ids != [], do: {:ok, agent_ids}

  defp evidence_target_agent_ids(org_id, id, _agent_ids) do
    with {:ok, threat} <- EmergingCenter.get_threat(org_id, id) do
      agent_ids =
        threat
        |> get_in([:localExposure, :agentIds])
        |> List.wrap()
        |> Enum.map(&to_string/1)
        |> Enum.reject(&(&1 == ""))

      if agent_ids == [], do: {:error, :no_targets}, else: {:ok, agent_ids}
    end
  end

  defp parse_int(nil, default, _min, _max), do: default

  defp parse_int(value, _default, min, max) when is_integer(value),
    do: value |> max(min) |> min(max)

  defp parse_int(value, default, min, max) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed |> max(min) |> min(max)
      _ -> default
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
