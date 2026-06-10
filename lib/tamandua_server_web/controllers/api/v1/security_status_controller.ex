defmodule TamanduaServerWeb.API.V1.SecurityStatusController do
  @moduledoc """
  Endpoint security posture attestation API.

  This exposes the "Security Oracle" primitive without claiming an endpoint is
  clean. It returns and optionally publishes a privacy-safe proof that an agent
  was monitored during a time window and summarizes aggregate alert posture.
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.{Agents, Alerts}
  alias TamanduaServer.Solana.{Attestation, Client}

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Return a privacy-safe endpoint security posture manifest for an agent.
  """
  def show_agent(conn, %{"id" => agent_id} = params) do
    with {:ok, agent} <- authorize_agent(conn, agent_id),
         posture <- build_posture(conn, agent, params),
         manifest <- Attestation.build_health_manifest(agent, posture) do
      json(conn, %{
        data: %{
          agent_id: agent.id,
          status: manifest.status,
          posture_hash: Attestation.compute_manifest_hash(manifest) |> Base.encode16(case: :lower),
          manifest: serialize_manifest(manifest),
          solana_enabled: Client.enabled?()
        }
      })
    end
  end

  @doc """
  Publish a privacy-safe endpoint security posture attestation to Solana.
  """
  def attest_agent(conn, %{"id" => agent_id} = params) do
    with :ok <- require_admin(conn),
         {:ok, agent} <- authorize_agent(conn, agent_id),
         posture <- build_posture(conn, agent, params),
         manifest <- Attestation.build_health_manifest(agent, posture),
         {:ok, tx_id} <- Attestation.attest_agent_health(agent, posture) do
      json(conn, %{
        success: true,
        type: "endpoint_health",
        agent_id: agent.id,
        status: manifest.status,
        posture_hash: Attestation.compute_manifest_hash(manifest) |> Base.encode16(case: :lower),
        blockchain_tx_id: tx_id,
        solscan_url: Client.solscan_url(tx_id),
        manifest: serialize_manifest(manifest)
      })
    else
      {:error, :unauthorized} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Admin access required"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, reason} ->
        Logger.warning("[SecurityStatus] Health attestation failed: #{inspect(reason)}")

        conn
        |> put_status(:bad_gateway)
        |> json(%{error: "Health attestation failed", reason: inspect(reason)})
    end
  end

  defp authorize_agent(conn, agent_id) do
    org_id = current_organization_id(conn)

    if is_nil(org_id) do
      {:error, :unauthorized}
    else
      Agents.get_agent_for_org(org_id, agent_id)
    end
  end

  defp build_posture(conn, agent, params) do
    org_id = current_organization_id(conn)
    hours = parse_window_hours(params["window_hours"] || params["window"] || "24")
    since = DateTime.add(DateTime.utc_now(), -hours * 60 * 60, :second)

    Alerts.posture_counts_for_agent(org_id, agent.id, since: since)
  end

  defp parse_window_hours(value) when is_integer(value), do: clamp_window(value)
  defp parse_window_hours(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.trim_trailing("h")
    |> Integer.parse()
    |> case do
      {hours, _} -> clamp_window(hours)
      :error -> 24
    end
  end
  defp parse_window_hours(_), do: 24

  defp clamp_window(hours), do: hours |> max(1) |> min(168)

  defp require_admin(conn) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) -> {:error, :unauthorized}
      Map.get(user, :role) in ["admin", "superadmin"] -> :ok
      Application.get_env(:tamandua_server, :demo_mode, false) -> :ok
      true -> {:error, :unauthorized}
    end
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      case conn.assigns[:current_user] do
        %{organization_id: org_id} -> org_id
        _ -> nil
      end
  end

  defp serialize_manifest(manifest) do
    manifest
    |> Map.update(:window_started_at, nil, &format_datetime/1)
    |> Map.update(:window_ended_at, nil, &format_datetime/1)
  end

  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(value), do: value
end
