defmodule TamanduaServerWeb.API.V1.UninstallIntentController do
  @moduledoc "HTTP boundary for online uninstall intents and offline break-glass issuance."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Agents.UninstallBreakglass
  alias TamanduaServer.Agents.UninstallIntents

  plug(:put_no_store)

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    :agents_uninstall when action in [:create, :create_breakglass]
  )

  def create(conn, %{"agent_id" => agent_id} = params) do
    with :ok <- exact_keys(params, [["agent_id", "reason"], ["agent_id", "reason", "idempotency_key"]]),
         {:ok, organization_id} <- tenant_id(conn),
         {:ok, actor_id} <- actor_id(conn),
         {:ok, intent, disposition} <-
           UninstallIntents.issue(organization_id, agent_id, actor_id, %{
             reason: params["reason"],
             idempotency_key: params["idempotency_key"]
           }) do
      conn
      |> put_status(if(disposition == :created, do: :created, else: :ok))
      |> json(%{
        data: %{
          id: intent.id,
          state: intent.state,
          expires_at: intent.expires_at
        }
      })
    else
      error -> render_issue_error(conn, error)
    end
  end

  def create(conn, _params), do: render_issue_error(conn, {:error, :request_invalid})

  def create_breakglass(conn, %{"agent_id" => agent_id} = params) do
    with :ok <-
           exact_keys(params, [
             ["agent_id", "reason", "platform", "consumer"],
             ["agent_id", "reason", "platform", "consumer", "ttl_seconds"]
           ]),
         {:ok, organization_id} <- tenant_id(conn),
         {:ok, actor_id} <- actor_id(conn),
         {:ok, envelope} <-
           UninstallBreakglass.issue(organization_id, agent_id, actor_id, %{
             reason: params["reason"],
             platform: params["platform"],
             consumer: params["consumer"],
             ttl_seconds: params["ttl_seconds"]
           }) do
      send_envelope(conn, envelope)
    else
      error -> render_breakglass_error(conn, error)
    end
  end

  def create_breakglass(conn, _params),
    do: render_breakglass_error(conn, {:error, :request_invalid})

  def consume(conn, params) do
    with :ok <- exact_keys(params, [["nonce", "verifier_version", "platform", "consumer"]]),
         {:ok, token} <- bearer_token(conn),
         {:ok, claims} <- TokenManager.validate_token(token),
         {:ok, organization_id, agent_id, generation} <- agent_identity(claims),
         {:ok, consumed} <-
           UninstallIntents.consume(organization_id, agent_id, generation, token, params) do
      json(conn, %{data: consumed})
    else
      error -> render_consume_error(conn, error)
    end
  end

  defp exact_keys(params, allowed_sets) when is_map(params) do
    keys = params |> Map.keys() |> Enum.sort()

    if Enum.any?(allowed_sets, &(Enum.sort(&1) == keys)),
      do: :ok,
      else: {:error, :request_invalid}
  end

  defp exact_keys(_params, _allowed_sets), do: {:error, :request_invalid}

  defp tenant_id(conn) do
    canonical_uuid(conn.assigns[:current_organization_id], :tenant_context_required)
  end

  defp actor_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> canonical_uuid(id, :issuer_invalid)
      _ -> {:error, :issuer_invalid}
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when byte_size(token) > 0 -> {:ok, token}
      _ -> {:error, :unauthorized}
    end
  end

  defp agent_identity(claims) when is_map(claims) do
    with {:ok, agent_id} <- canonical_uuid(claims["agent_id"], :unauthorized),
         {:ok, org_id} <- canonical_uuid(claims["org_id"], :unauthorized),
         {:ok, organization_id} <- canonical_uuid(claims["organization_id"], :unauthorized),
         true <- org_id == organization_id,
         generation when is_integer(generation) and generation > 0 <- claims["generation"] do
      {:ok, organization_id, agent_id, generation}
    else
      _ -> {:error, :unauthorized}
    end
  end

  defp agent_identity(_claims), do: {:error, :unauthorized}

  defp canonical_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, error}
    end
  end

  defp canonical_uuid(_value, error), do: {:error, error}

  defp render_issue_error(conn, {:error, :agent_not_found}),
    do: error_response(conn, :not_found, "uninstall_intent_agent_not_found")

  defp render_issue_error(conn, {:error, reason})
       when reason in [:tenant_context_required, :issuer_invalid],
       do: error_response(conn, :forbidden, "uninstall_intent_forbidden")

  defp render_issue_error(conn, {:error, :store_unavailable}),
    do: error_response(conn, :service_unavailable, "uninstall_intent_store_unavailable")

  defp render_issue_error(conn, {:error, :idempotency_conflict}),
    do: error_response(conn, :conflict, "uninstall_intent_idempotency_conflict")

  defp render_issue_error(conn, {:error, %Ecto.Changeset{}}),
    do: error_response(conn, :unprocessable_entity, "uninstall_intent_invalid")

  defp render_issue_error(conn, _error),
    do: error_response(conn, :bad_request, "uninstall_intent_invalid")

  defp render_consume_error(conn, {:error, reason})
       when reason in [:unauthorized, :invalid_token, :token_expired, :token_revoked],
       do: error_response(conn, :unauthorized, "uninstall_intent_unauthorized")

  defp render_consume_error(conn, {:error, :request_invalid}),
    do: error_response(conn, :bad_request, "uninstall_intent_request_invalid")

  defp render_consume_error(conn, {:error, :expired}),
    do: error_response(conn, :gone, "uninstall_intent_expired")

  defp render_consume_error(conn, {:error, :already_consumed}),
    do: error_response(conn, :conflict, "uninstall_intent_already_consumed")

  defp render_consume_error(conn, {:error, :store_unavailable}),
    do: error_response(conn, :service_unavailable, "uninstall_intent_store_unavailable")

  defp render_consume_error(conn, {:error, :unavailable}),
    do: error_response(conn, :conflict, "uninstall_intent_unavailable")

  defp render_consume_error(conn, _error),
    do: error_response(conn, :unauthorized, "uninstall_intent_unauthorized")

  defp render_breakglass_error(conn, {:error, :agent_not_found}),
    do: error_response(conn, :not_found, "uninstall_breakglass_agent_not_found")

  defp render_breakglass_error(conn, {:error, reason})
       when reason in [:tenant_context_required, :issuer_invalid],
       do: error_response(conn, :forbidden, "uninstall_breakglass_forbidden")

  defp render_breakglass_error(conn, {:error, :signer_unavailable}),
    do: error_response(conn, :service_unavailable, "uninstall_breakglass_signer_unavailable")

  defp render_breakglass_error(conn, {:error, :store_unavailable}),
    do: error_response(conn, :service_unavailable, "uninstall_breakglass_store_unavailable")

  defp render_breakglass_error(conn, _error),
    do: error_response(conn, :bad_request, "uninstall_breakglass_request_invalid")

  defp send_envelope(conn, %{payload: payload, signature: signature}) do
    case UninstallBreakglass.encode_envelope(%{payload: payload, signature: signature}) do
      {:ok, body} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(:created, body)

      {:error, _reason} ->
        error_response(conn, :bad_request, "uninstall_breakglass_request_invalid")
    end
  end

  defp error_response(conn, status, code) do
    conn |> put_status(status) |> json(%{error: %{code: code}})
  end

  def put_no_store(conn, _opts), do: put_resp_header(conn, "cache-control", "no-store")
end
