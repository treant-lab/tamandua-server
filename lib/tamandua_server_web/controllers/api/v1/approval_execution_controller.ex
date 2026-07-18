defmodule TamanduaServerWeb.API.V1.ApprovalExecutionController do
  @moduledoc "Tenant-scoped status and human reconciliation for approved response executions."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.ApprovalExecutions

  action_fallback(TamanduaServerWeb.FallbackController)

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :response_view] when action in [:show]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :response_approve] when action in [:index, :reconcile]
  )

  def index(conn, params) do
    with :ok <- authorize(conn, :response_approve),
         {:ok, organization_id} <- current_organization_id(conn),
         {:ok, executions} <-
           ApprovalExecutions.list_reconciliation_required(
             organization_id,
             limit: parse_limit(params["limit"])
           ) do
      json(conn, %{status: "success", data: executions, meta: %{count: length(executions)}})
    end
  end

  def show(conn, %{"id" => execution_id}) do
    with :ok <- authorize(conn, :response_view),
         {:ok, organization_id} <- current_organization_id(conn),
         {:ok, status} <- ApprovalExecutions.status(organization_id, execution_id) do
      json(conn, %{status: "success", data: status})
    end
  end

  def reconcile(conn, %{
        "id" => execution_id,
        "outcome" => outcome,
        "evidence_ref" => evidence_ref
      }) do
    with :ok <- authorize(conn, :response_approve),
         {:ok, organization_id} <- current_organization_id(conn),
         {:ok, reconciler_id} <- current_user_id(conn),
         {:ok, execution} <-
           ApprovalExecutions.reconcile(
             organization_id,
             execution_id,
             reconciler_id,
             outcome,
             evidence_ref
           ),
         {:ok, status} <- ApprovalExecutions.status(organization_id, execution.id) do
      json(conn, %{status: "success", data: status})
    end
  end

  def reconcile(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      status: "error",
      message: "outcome and typed evidence_ref are required"
    })
  end

  defp authorize(conn, permission) do
    if TamanduaServer.Accounts.user_can?(conn.assigns[:current_user], permission),
      do: :ok,
      else: {:error, :unauthorized}
  rescue
    _ -> {:error, :unauthorized}
  end

  defp current_organization_id(conn) do
    value =
      conn.assigns[:current_organization_id] ||
        field(conn.assigns[:current_user], :organization_id)

    if is_binary(value) and value != "", do: {:ok, value}, else: {:error, :unauthorized}
  end

  defp current_user_id(conn) do
    value = field(conn.assigns[:current_user], :id)
    if is_binary(value) and value != "", do: {:ok, value}, else: {:error, :unauthorized}
  end

  defp field(%{} = value, key), do: Map.get(value, key) || Map.get(value, to_string(key))
  defp field(_, _), do: nil

  defp parse_limit(value) when is_integer(value), do: value

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed
      _ -> 50
    end
  end

  defp parse_limit(_value), do: 50
end
