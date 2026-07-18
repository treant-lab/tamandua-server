defmodule TamanduaServerWeb.API.V1.RelayController do
  @moduledoc """
  API endpoint for the attestation relay service.

  Self-hosted Tamandua instances send attestations here for batched
  publication to Solana. Treant pays the transaction fees.

  ## Authentication

  Relay requests are authenticated via API key (X-Tamandua-Relay-Key header).
  Keys are issued to registered self-hosted operators.

  The endpoint fails closed when no relay key is configured. Configure
  `TAMANDUA_RELAY_API_KEY` before enabling the relay.

  ## Endpoints

  - POST /api/v1/relay/attestations - Queue attestation for publication
  - GET /api/v1/relay/status - Get relay status and stats
  - GET /api/v1/relay/batch/:id - Get batch publication status
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Solana.RelayBatch

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Queue an attestation for batched publication.

  Accepts attestation data from self-hosted instances and queues
  for periodic batch publication to Solana.
  """
  def create_attestation(conn, %{"attestation" => attestation_params}) do
    # Basic validation
    with :ok <- authenticate_relay(conn),
         :ok <- validate_attestation(attestation_params),
         {:ok, result} <- RelayBatch.queue_attestation(attestation_params) do
      conn
      |> put_status(:accepted)
      |> json(%{
        status: "queued",
        batch_id: result.batch_id,
        position: result.position,
        queue_size: result.queue_size,
        message: "Attestation queued for batch publication"
      })
    else
      {:error, :queue_full} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Relay queue full, try again later"})

      {:error, :relay_disabled} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Relay service is disabled"})

      {:error, :unauthorized} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid or missing relay API key"})

      {:error, :relay_not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Relay authentication is not configured"})

      {:error, :invalid_attestation, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid attestation", reason: reason})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get relay service status and statistics.
  """
  def status(conn, _params) do
    status = RelayBatch.status()

    json(conn, %{
      status: "operational",
      relay: status,
      pricing: %{
        cost_per_attestation: "$0 (sponsored by Treant)",
        batch_size: status[:batch_size] || 50,
        publish_interval_seconds: div(status[:batch_interval_ms] || 30_000, 1000)
      },
      network: %{
        description: "Attestations are batched and published to Solana",
        benefit: "Your threat intel contributes to the global security oracle"
      }
    })
  end

  @doc """
  Get status of a specific batch.
  """
  def batch_status(conn, %{"id" => batch_id}) do
    # TODO: Implement batch tracking with persistence
    # For now, return generic info
    json(conn, %{
      batch_id: batch_id,
      status: "processing",
      message: "Batch status tracking coming soon"
    })
  end

  # Private

  defp authenticate_relay(conn) do
    expected_key = relay_api_key()

    cond do
      not (is_binary(expected_key) and byte_size(expected_key) > 0) ->
        {:error, :relay_not_configured}

      relay_key_matches?(get_req_header(conn, "x-tamandua-relay-key"), expected_key) ->
        :ok

      true ->
        {:error, :unauthorized}
    end
  end

  defp relay_key_matches?([provided_key], expected_key)
       when byte_size(provided_key) == byte_size(expected_key) do
    Plug.Crypto.secure_compare(provided_key, expected_key)
  end

 defp relay_key_matches?(_provided_keys, _expected_key), do: false

  defp validate_attestation(params) do
    required_fields = ["ih", "s", "mt"]
    missing = Enum.filter(required_fields, fn field -> is_nil(params[field]) end)

    cond do
      length(missing) > 0 ->
        {:error, :invalid_attestation, "Missing fields: #{Enum.join(missing, ", ")}"}

      not is_integer(params["s"]) and not is_binary(params["s"]) ->
        {:error, :invalid_attestation, "Invalid severity"}

      not is_binary(params["ih"]) ->
        {:error, :invalid_attestation, "Invalid incident hash"}

      true ->
        :ok
    end
  end

  defp relay_api_key do
    Application.get_env(:tamandua_server, TamanduaServer.Solana.RelayBatch, [])
    |> Keyword.get(:api_key)
    |> Kernel.||(System.get_env("TAMANDUA_RELAY_API_KEY"))
  end
end
