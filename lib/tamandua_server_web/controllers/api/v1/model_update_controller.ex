defmodule TamanduaServerWeb.API.V1.ModelUpdateController do
  @moduledoc """
  Agent-facing backend for model/rule hot updates.

  This controller intentionally supports a safe minimal flow:

  - `POST /api/v1/updates/models/check` returns `204` when the deployment does
    not publish signed model assets yet.
  - `200` with a signed manifest only when publishable assets exist and a
    signing key is configured.
  - `GET /api/v1/updates/models/download/:asset_type/:version` serves a concrete
    asset referenced by the manifest.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Updates.ModelUpdates

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  def check(conn, params) do
    agent_id = Map.get(params, "agent_id", "")
    platform = Map.get(params, "platform", "")
    current_versions = normalize_current_versions(conn.body_params || %{})

    Logger.info(
      "[ModelUpdates] check from agent=#{agent_id} platform=#{platform} body_keys=#{inspect(Map.keys(current_versions))}"
    )

    case ModelUpdates.check_for_updates(
           current_versions,
           base_url: model_updates_base_url(conn)
         ) do
      {:ok, manifest} ->
        json(conn, manifest)

      :up_to_date ->
        send_resp(conn, 204, "")

      {:error, reason} ->
        Logger.error("[ModelUpdates] check failed for agent=#{agent_id}: #{inspect(reason)}")
        send_resp(conn, 204, "")
    end
  end

  def download(conn, %{"asset_type" => asset_type, "version" => version}) do
    case ModelUpdates.fetch_downloadable_asset(asset_type, version) do
      {:ok, asset} ->
        conn
        |> put_resp_header("content-type", "application/octet-stream")
        |> put_resp_header("content-length", Integer.to_string(asset.size))
        |> put_resp_header(
          "content-disposition",
          ~s(attachment; filename="#{asset.filename}")
        )
        |> send_file(200, asset.path)

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model update asset not found"})
    end
  end

  defp model_updates_base_url(conn) do
    uri = URI.parse(TamanduaServerWeb.Endpoint.url())
    scheme = Atom.to_string(conn.scheme)
    host = conn.host || uri.host || "localhost"
    port = conn.port || uri.port

    port_fragment =
      case {scheme, port} do
        {"http", 80} -> ""
        {"https", 443} -> ""
        {_, nil} -> ""
        _ -> ":#{port}"
      end

    "#{scheme}://#{host}#{port_fragment}/api/v1/updates/models"
  end

  defp normalize_current_versions(params) do
    keys = ~w(
      smell_sha256
      transformer_sha256
      ensemble_sha256
      features_sha256
      yara_sha256
      sigma_sha256
      ioc_sha256
    )

    Map.take(params, keys)
  end
end
