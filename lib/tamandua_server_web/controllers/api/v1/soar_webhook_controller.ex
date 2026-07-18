defmodule TamanduaServerWeb.API.V1.SoarWebhookController do
  @moduledoc """
  Webhook endpoint for SOAR platform callbacks.

  Receives callbacks from XSOAR and Tines when playbooks complete.

  ## Endpoints

  - `POST /api/v1/integrations/soar/callback/:platform`

  ## Authentication

  - **XSOAR**: API key in `X-XSOAR-Auth` header
  - **Tines**: HMAC signature in `X-Tines-Signature` header
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Integrations.SOAR.CallbackHandler

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Handle SOAR platform callback.

  POST /api/v1/integrations/soar/callback/:platform

  ## Path Parameters

  - `platform` - "xsoar" or "tines"

  ## Headers (platform-specific)

  - XSOAR: `X-XSOAR-Auth: <api-key>`
  - Tines: `X-Tines-Signature: sha256=<hmac>`

  ## Body

  Platform-specific callback payload (JSON).
  """
  def callback(conn, %{"platform" => platform} = params) do
    with :ok <- verify_auth(conn, platform),
         {:ok, result} <- CallbackHandler.handle_callback(platform, params) do
      Logger.info("[SoarWebhook] Processed #{platform} callback: #{inspect(result.execution_id)}")

      json(conn, %{
        status: "ok",
        execution_id: result.execution_id,
        result_status: result.status
      })
    else
      {:error, :unauthorized} ->
        Logger.warning("[SoarWebhook] Unauthorized #{platform} callback")
        conn
        |> put_status(401)
        |> json(%{error: "Unauthorized", message: "Invalid authentication"})

      {:error, :invalid_signature} ->
        Logger.warning("[SoarWebhook] Invalid signature for #{platform} callback")
        conn
        |> put_status(401)
        |> json(%{error: "Unauthorized", message: "Invalid webhook signature"})

      {:error, :no_signing_secret} ->
        Logger.error("[SoarWebhook] No signing secret configured for #{platform}")
        conn
        |> put_status(500)
        |> json(%{error: "Configuration Error", message: "Webhook verification not configured"})

      {:error, :execution_not_found} ->
        Logger.warning("[SoarWebhook] Execution not found for #{platform} callback")
        conn
        |> put_status(404)
        |> json(%{error: "Not Found", message: "Execution log not found"})

      {:error, :unknown_platform} ->
        conn
        |> put_status(400)
        |> json(%{error: "Bad Request", message: "Unknown platform: #{platform}"})

      {:error, reason} ->
        Logger.error("[SoarWebhook] Callback error: #{inspect(reason)}")
        conn
        |> put_status(400)
        |> json(%{error: "Bad Request", message: inspect(reason)})
    end
  end

  @doc """
  Health check for webhook endpoint.

  GET /api/v1/integrations/soar/callback/health
  """
  def health(conn, _params) do
    json(conn, %{
      status: "healthy",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp verify_auth(conn, "xsoar") do
    api_key = get_req_header(conn, "x-xsoar-auth") |> List.first()

    if api_key do
      CallbackHandler.verify_xsoar_auth(api_key)
    else
      # Also check standard Authorization header
      case get_req_header(conn, "authorization") |> List.first() do
        "Bearer " <> token -> CallbackHandler.verify_xsoar_auth(token)
        token when is_binary(token) -> CallbackHandler.verify_xsoar_auth(token)
        _ -> {:error, :unauthorized}
      end
    end
  end

  defp verify_auth(conn, "tines") do
    signature = get_req_header(conn, "x-tines-signature") |> List.first()

    if signature do
      # Need raw body for signature verification
      # This requires the CacheBodyReader plug to be configured
      raw_body = get_raw_body(conn)

      if raw_body do
        CallbackHandler.verify_tines_signature(raw_body, signature)
      else
        # If no raw body cached, skip verification and log warning
        Logger.warning("[SoarWebhook] No raw body available for Tines signature verification")
        :ok
      end
    else
      # No signature header - check if verification is required
      config = Application.get_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [])

      if config[:require_signature_verification] == true do
        {:error, :unauthorized}
      else
        # Signature verification not required
        :ok
      end
    end
  end

  defp verify_auth(_conn, _platform) do
    # Unknown platform, let it through for error handling
    :ok
  end

  defp get_raw_body(conn) do
    # Try to get cached raw body
    case conn.private do
      %{raw_body: body} -> body
      _ ->
        # Try reading from body_params if it's a string
        case conn.body_params do
          body when is_binary(body) -> body
          params when is_map(params) -> Jason.encode!(params)
          _ -> nil
        end
    end
  end
end
