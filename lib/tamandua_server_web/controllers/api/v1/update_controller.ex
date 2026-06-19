defmodule TamanduaServerWeb.API.V1.UpdateController do
  @moduledoc """
  Handles agent self-update operations.

  ## Endpoints

  * `GET /api/v1/updates/check` - Check for available updates.
    Query params: `version`, `agent_id`.
    Returns 200 with manifest JSON if update available, 204 if up-to-date.

  * `GET /api/v1/updates/download/:version/:platform` - Download update binary.
    Returns the binary file or a redirect to a CDN URL.

  * `POST /api/v1/updates/report` - Agent reports update status.
    Body: `{ agent_id, rollout_id, status, error_message }`.

  * `GET /api/v1/updates/status` - Admin view of rollout status.

  ## Admin Endpoints

  * `GET /api/v1/updates/packages` - List update packages.
  * `POST /api/v1/updates/packages` - Create update package.
  * `GET /api/v1/updates/packages/:id` - Get a single update package.
  * `DELETE /api/v1/updates/packages/:id` - Delete an update package.
  * `GET /api/v1/updates/rollouts` - List rollouts.
  * `POST /api/v1/updates/rollouts` - Create a rollout.
  * `GET /api/v1/updates/rollouts/:id` - Get rollout with progress.
  * `POST /api/v1/updates/rollouts/:id/pause` - Pause a rollout.
  * `POST /api/v1/updates/rollouts/:id/resume` - Resume a rollout.
  * `POST /api/v1/updates/rollouts/:id/rollback` - Rollback a rollout.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Updates

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  # ===========================================================================
  # Agent-facing endpoints
  # ===========================================================================

  @doc """
  Check for available updates.

  The agent provides its current version and agent_id. The server looks up
  the latest applicable package and checks whether this agent is included
  in any active rollout.

  ## Query Parameters

  * `version` - Current agent version (e.g. "0.1.0")
  * `agent_id` - Agent UUID
  """
  def check(conn, params) do
    agent_id = Map.get(params, "agent_id", "")
    current_version = Map.get(params, "version", "0.0.0")

    Logger.info(
      "Update check from agent #{agent_id} (version=#{current_version})"
    )

    case Updates.check_for_update(agent_id, current_version) do
      {:ok, manifest} ->
        # If the package has no download_url, build one from the current conn
        manifest = maybe_build_download_url(conn, manifest)

        if macos_manifest_without_deployable_download?(manifest) do
          Logger.warning(
            "Suppressing macOS update #{manifest.version} for agent #{agent_id}; " <>
              "macOS updates require signed/notarized DMG/Cask with EndpointSecurity System Extension"
          )

          send_resp(conn, 204, "")
        else
          Logger.info(
            "Offering update #{manifest.version} to agent #{agent_id} " <>
              "(from #{current_version})"
          )

          json(conn, manifest)
        end

      :up_to_date ->
        Logger.debug("Agent #{agent_id} is up to date (#{current_version})")
        send_resp(conn, 204, "")

      {:error, :agent_not_found} ->
        Logger.warning("Update check from unknown agent #{agent_id}")
        send_resp(conn, 204, "")

      {:error, reason} ->
        Logger.error("Update check error for agent #{agent_id}: #{inspect(reason)}")
        send_resp(conn, 204, "")
    end
  end

  @doc """
  Download the update binary for the given version and platform.

  In production, this would typically redirect to a CDN. For development,
  it serves the file directly from the updates directory.
  """
  def download(conn, %{"version" => version, "platform" => platform}) do
    Logger.info("Update download request: version=#{version}, platform=#{platform}")

    if macos_update_platform?(platform) do
      Logger.warning(
        "Refusing macOS standalone update download for #{platform} v#{version}; " <>
          "macOS updates require signed/notarized DMG/Cask with EndpointSecurity System Extension"
      )

      conn
      |> put_status(:gone)
      |> json(%{
        error:
          "macOS updates require a signed/notarized DMG or Cask with EndpointSecurity System Extension"
      })
    else
      updates_dir = get_updates_dir()
      binary_name = build_binary_name(version, platform)
      file_path = Path.join(updates_dir, binary_name)

      if File.exists?(file_path) do
        conn
        |> put_resp_header("content-type", "application/octet-stream")
        |> put_resp_header(
          "content-disposition",
          ~s(attachment; filename="#{binary_name}")
        )
        |> send_file(200, file_path)
      else
        Logger.warning("Update binary not found: #{file_path}")

        conn
        |> put_status(404)
        |> json(%{error: "Update binary not found for #{platform} v#{version}"})
      end
    end
  end

  @doc """
  Receive an update status report from an agent.

  Agents report their update progress (downloading, installing, completed, failed).
  The system records the status and evaluates canary failure rates for
  automatic rollback.

  ## Request Body

  * `agent_id` - Agent UUID
  * `rollout_id` - Rollout UUID
  * `status` - One of: downloading, installing, completed, failed
  * `error_message` - Optional error details (for failed status)
  """
  def report(conn, params) do
    agent_id = Map.get(params, "agent_id", "unknown")
    rollout_id = Map.get(params, "rollout_id")
    status = Map.get(params, "status")

    # Support legacy format: convert success/failure boolean to status string
    status = normalize_report_status(status, params)

    Logger.info("Update report: agent=#{agent_id} rollout=#{rollout_id} status=#{status}")

    if rollout_id do
      case Updates.report_update_status(agent_id, rollout_id, %{
             "status" => status,
             "error_message" => Map.get(params, "error_message")
           }) do
        {:ok, _agent_update} ->
          json(conn, %{status: "ok"})

        {:error, :not_found} ->
          Logger.warning(
            "Update report for unknown agent/rollout: agent=#{agent_id} rollout=#{rollout_id}"
          )

          json(conn, %{status: "ok"})

        {:error, reason} ->
          Logger.error("Update report error: #{inspect(reason)}")
          json(conn, %{status: "ok"})
      end
    else
      # Legacy report without rollout_id -- accept but log
      Logger.info(
        "Legacy update report from agent #{agent_id} (no rollout_id): status=#{status}"
      )

      json(conn, %{status: "ok"})
    end
  end

  # ===========================================================================
  # Admin endpoints
  # ===========================================================================

  @doc """
  Admin endpoint to view overall rollout status.

  Returns all active rollouts with progress statistics.
  """
  def rollout_status(conn, _params) do
    active_rollouts = Updates.list_active_rollouts()

    rollout_data =
      Enum.map(active_rollouts, fn rollout ->
        progress = Updates.get_rollout_progress(rollout.id)

        %{
          id: rollout.id,
          strategy: rollout.strategy,
          status: rollout.status,
          current_stage: rollout.current_stage,
          started_at: rollout.started_at,
          package: %{
            version: rollout.update_package.version,
            platform: rollout.update_package.platform,
            architecture: rollout.update_package.architecture
          },
          progress: progress
        }
      end)

    json(conn, %{data: %{rollouts: rollout_data, last_updated: DateTime.utc_now()}})
  end

  @doc """
  List update packages for the current organization.
  """
  def list_packages(conn, params) do
    org_id = get_org_id(conn)
    opts = filter_opts(params, [:platform, :limit, :offset])
    packages = Updates.list_packages(org_id, opts)

    json(conn, %{data: Enum.map(packages, &serialize_package/1)})
  end

  @doc """
  Create a new update package.
  """
  def create_package(conn, %{"package" => package_params}) do
    org_id = get_org_id(conn)

    case Updates.create_package(org_id, package_params) do
      {:ok, package} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_package(package)})

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}
    end
  end

  def create_package(conn, params) do
    create_package(conn, %{"package" => params})
  end

  @doc """
  Get a single update package.
  """
  def show_package(conn, %{"id" => id}) do
    org_id = get_org_id(conn)

    case Updates.get_package(org_id, id) do
      {:ok, package} -> json(conn, %{data: serialize_package(package)})
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Delete an update package.
  """
  def delete_package(conn, %{"id" => id}) do
    org_id = get_org_id(conn)

    with {:ok, package} <- Updates.get_package(org_id, id),
         {:ok, _} <- Updates.delete_package(package) do
      send_resp(conn, :no_content, "")
    end
  end

  @doc """
  List rollouts for the current organization.
  """
  def list_rollouts(conn, params) do
    org_id = get_org_id(conn)
    opts = filter_opts(params, [:status, :limit])
    rollouts = Updates.list_rollouts(org_id, opts)

    json(conn, %{data: Enum.map(rollouts, &serialize_rollout/1)})
  end

  @doc """
  Create a new rollout.
  """
  def create_rollout(conn, %{"rollout" => rollout_params}) do
    org_id = get_org_id(conn)

    case Updates.create_rollout(org_id, rollout_params) do
      {:ok, rollout} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_rollout(rollout)})

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}
    end
  end

  def create_rollout(conn, params) do
    create_rollout(conn, %{"rollout" => params})
  end

  @doc """
  Get a single rollout with progress.
  """
  def show_rollout(conn, %{"id" => id}) do
    org_id = get_org_id(conn)

    case Updates.get_rollout(org_id, id) do
      {:ok, rollout} ->
        progress = Updates.get_rollout_progress(rollout.id)

        json(conn, %{
          data: serialize_rollout(rollout) |> Map.put(:progress, progress)
        })

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Pause an active rollout.
  """
  def pause_rollout(conn, %{"id" => id}) do
    case Updates.pause_rollout(id) do
      {:ok, rollout} -> json(conn, %{data: serialize_rollout(rollout)})
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Resume a paused rollout.
  """
  def resume_rollout(conn, %{"id" => id}) do
    case Updates.resume_rollout(id) do
      {:ok, rollout} -> json(conn, %{data: serialize_rollout(rollout)})
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Rollback a rollout.
  """
  def rollback_rollout(conn, %{"id" => id} = params) do
    reason = Map.get(params, "reason", "manual rollback via API")

    case Updates.rollback_rollout(id, reason) do
      {:ok, rollout} -> json(conn, %{data: serialize_rollout(rollout)})
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  # ===========================================================================
  # Private helpers
  # ===========================================================================

  defp maybe_build_download_url(conn, %{download_url: nil} = manifest) do
    if macos_update_platform?(manifest.platform) do
      Map.put(manifest, :download_url, nil)
    else
      platform = "#{manifest.platform}-#{manifest.architecture}"
      url = build_download_url(conn, manifest.version, platform)
      Map.put(manifest, :download_url, url)
    end
  end

  defp maybe_build_download_url(_conn, manifest), do: manifest

  defp macos_manifest_without_deployable_download?(%{download_url: nil, platform: platform}) do
    macos_update_platform?(platform)
  end

  defp macos_manifest_without_deployable_download?(_manifest), do: false

  defp macos_update_platform?(platform) when is_atom(platform) do
    platform
    |> Atom.to_string()
    |> macos_update_platform?()
  end

  defp macos_update_platform?(platform) when is_binary(platform) do
    platform = String.downcase(platform)

    String.starts_with?(platform, "macos") or
      String.starts_with?(platform, "darwin") or
      String.contains?(platform, "apple-darwin")
  end

  defp macos_update_platform?(_platform), do: false

  defp build_download_url(conn, version, platform) do
    case Application.get_env(:tamandua_server, :update_cdn_base_url) do
      nil ->
        "#{conn.scheme}://#{conn.host}:#{conn.port}/api/v1/updates/download/#{version}/#{platform}"

      cdn_base ->
        "#{cdn_base}/#{version}/#{platform}/#{build_binary_name(version, platform)}"
    end
  end

  defp build_binary_name(version, platform) do
    extension =
      if String.starts_with?(platform, "windows"), do: ".exe", else: ""

    "tamandua-agent-#{version}-#{platform}#{extension}"
  end

  defp get_updates_dir do
    Application.get_env(:tamandua_server, :updates_dir, "priv/updates")
  end

  # Normalize legacy boolean success/failure to status string
  defp normalize_report_status(nil, params) do
    case Map.get(params, "success") do
      true -> "completed"
      false -> "failed"
      _ -> "completed"
    end
  end

  defp normalize_report_status(status, _params) when is_binary(status), do: status

  defp get_org_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp filter_opts(params, allowed_keys) do
    allowed_keys
    |> Enum.flat_map(fn key ->
      str_key = to_string(key)

      case Map.get(params, str_key) do
        nil -> []
        value when key in [:limit, :offset] -> [{key, parse_integer(value)}]
        value -> [{key, value}]
      end
    end)
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
  end

  defp parse_integer(value) when is_integer(value), do: value

  defp parse_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> nil
    end
  end

  defp parse_integer(_), do: nil

  # -- Serializers -----------------------------------------------------------

  defp serialize_package(package) do
    %{
      id: package.id,
      version: package.version,
      platform: package.platform,
      architecture: package.architecture,
      download_url: package.download_url,
      sha256_hash: package.sha256_hash,
      signature: package.signature,
      release_notes: package.release_notes,
      size_bytes: package.size_bytes,
      min_agent_version: package.min_agent_version,
      is_critical: package.is_critical,
      released_at: package.released_at,
      inserted_at: package.inserted_at,
      updated_at: package.updated_at
    }
  end

  defp serialize_rollout(rollout) do
    %{
      id: rollout.id,
      strategy: rollout.strategy,
      canary_percentage: rollout.canary_percentage,
      stages: rollout.stages,
      current_stage: rollout.current_stage,
      status: rollout.status,
      started_at: rollout.started_at,
      completed_at: rollout.completed_at,
      rollback_reason: rollout.rollback_reason,
      update_package_id: rollout.update_package_id,
      inserted_at: rollout.inserted_at,
      updated_at: rollout.updated_at
    }
  end
end
