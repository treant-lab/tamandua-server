defmodule TamanduaServerWeb.API.V1.DetectionPacksController do
  @moduledoc """
  API controller for Detection Packs management.

  ## Authorization

  - `index`, `show`, `installed` - any authenticated user with org context
  - `install`, `uninstall`, `toggle` - requires admin or security_admin role

  All write operations are audit logged.
  """
  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Detection.Packs

  action_fallback TamanduaServerWeb.FallbackController

  # Admin roles that can modify detection packs
  @admin_roles ["admin", "security_admin", "owner"]

  @doc """
  Lists all available detection packs.
  """
  def index(conn, _params) do
    packs = Packs.list_available()
    json(conn, %{data: packs})
  end

  @doc """
  Shows a specific detection pack.
  """
  def show(conn, %{"id" => pack_id}) do
    case Packs.get_pack(pack_id) do
      {:ok, pack} ->
        json(conn, %{data: pack})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pack not found"})
    end
  end

  @doc """
  Lists installed packs for the current organization.
  """
  def installed(conn, _params) do
    organization_id = conn.assigns[:current_organization_id]

    if organization_id do
      installed = Packs.list_installed(organization_id)
      json(conn, %{data: installed})
    else
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Organization context required"})
    end
  end

  @doc """
  Installs a detection pack for the current organization.

  Requires admin or security_admin role.
  """
  def install(conn, %{"id" => pack_id}) do
    organization_id = conn.assigns[:current_organization_id]
    current_user = conn.assigns[:current_user]
    user_id = current_user && current_user.id

    cond do
      is_nil(organization_id) ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Organization context required"})

      not has_admin_role?(current_user) ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Admin or security_admin role required to install detection packs"})

      match?({:error, :not_found}, Packs.get_pack(pack_id)) ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pack not found"})

      true ->
        # Audit log
        audit_log("detection_pack.install", %{
          pack_id: pack_id,
          organization_id: organization_id,
          user_id: user_id,
          user_email: current_user && current_user.email
        })
        case Packs.install_pack(pack_id, organization_id, installed_by_id: user_id) do
          {:ok, installed_pack} ->
            conn
            |> put_status(:created)
            |> json(%{
              message: install_message(installed_pack),
              data: %{
                id: installed_pack.id,
                pack_id: installed_pack.pack_id,
                pack_version: installed_pack.pack_version,
                enabled: installed_pack.enabled,
                installed_at: installed_pack.inserted_at,
                config: installed_pack.config || %{}
              }
            })

          {:error, %Ecto.Changeset{} = changeset} ->
            errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
              Enum.reduce(opts, msg, fn {key, value}, acc ->
                String.replace(acc, "%{#{key}}", to_string(value))
              end)
            end)

            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to install pack", details: errors})

          {:error, :already_installed} ->
            conn
            |> put_status(:conflict)
            |> json(%{error: "Pack is already installed"})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: reason})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: inspect(reason)})
        end
    end
  end

  @doc """
  Uninstalls a detection pack from the current organization.

  Requires admin or security_admin role.
  """
  def uninstall(conn, %{"id" => pack_id}) do
    organization_id = conn.assigns[:current_organization_id]
    current_user = conn.assigns[:current_user]

    cond do
      is_nil(organization_id) ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Organization context required"})

      not has_admin_role?(current_user) ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Admin or security_admin role required to uninstall detection packs"})

      true ->
        audit_log("detection_pack.uninstall", %{
          pack_id: pack_id,
          organization_id: organization_id,
          user_id: current_user && current_user.id,
          user_email: current_user && current_user.email
        })

        case Packs.uninstall_pack(pack_id, organization_id) do
          {:ok, _} ->
            conn
            |> put_status(:ok)
            |> json(%{message: "Pack uninstalled successfully"})

          {:error, :not_installed} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Pack is not installed"})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Pack not found"})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: reason})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: inspect(reason)})
        end
    end
  end

  @doc """
  Toggles a pack's enabled status.

  Requires admin or security_admin role.
  """
  def toggle(conn, %{"id" => pack_id, "enabled" => enabled}) when is_boolean(enabled) do
    organization_id = conn.assigns[:current_organization_id]
    current_user = conn.assigns[:current_user]

    cond do
      is_nil(organization_id) ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Organization context required"})

      not has_admin_role?(current_user) ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Admin or security_admin role required to toggle detection packs"})

      true ->
        audit_log("detection_pack.toggle", %{
          pack_id: pack_id,
          organization_id: organization_id,
          enabled: enabled,
          user_id: current_user && current_user.id,
          user_email: current_user && current_user.email
        })

        case Packs.set_enabled(pack_id, organization_id, enabled) do
          {:ok, installed_pack} ->
            json(conn, %{
              message: toggle_message(enabled, installed_pack),
              data: %{
                pack_id: installed_pack.pack_id,
                enabled: installed_pack.enabled,
                config: installed_pack.config || %{}
              }
            })

          {:error, :not_installed} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Pack is not installed"})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Pack not found"})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: reason})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: inspect(reason)})
        end
    end
  end

  # Fallback for missing enabled parameter
  def toggle(conn, %{"id" => _pack_id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "enabled parameter is required (boolean)"})
  end

  @doc """
  Gets statistics about detection packs for the organization.
  """
  def stats(conn, _params) do
    organization_id = conn.assigns[:current_organization_id]

    if organization_id do
      stats = Packs.get_stats(organization_id)
      json(conn, %{data: stats})
    else
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Organization context required"})
    end
  end

  defp install_message(installed_pack) do
    config = installed_pack.config || %{}
    rules_enabled = config_get(config, :rules_enabled, 0)
    rules_available = config_get(config, :rules_available, 0)

    if installed_pack.enabled do
      "Pack installed; #{rules_enabled}/#{rules_available} rules enabled"
    else
      "Pack installed; no rules enabled"
    end
  end

  defp toggle_message(false, %{enabled: false}), do: "Pack disabled"

  defp toggle_message(false, _installed_pack) do
    "Pack remains enabled; some rules could not be disabled"
  end

  defp toggle_message(true, %{enabled: true, config: config}) do
    config = config || %{}
    rules_enabled = config_get(config, :rules_enabled, 0)
    rules_available = config_get(config, :rules_available, 0)

    "Pack enabled; #{rules_enabled}/#{rules_available} rules enabled"
  end

  defp toggle_message(true, _installed_pack), do: "Pack remains disabled; no rules were enabled"

  defp config_get(config, key, default) do
    Map.get(config, key) || Map.get(config, Atom.to_string(key), default)
  end

  # Check if user has admin/security_admin role
  defp has_admin_role?(nil), do: false
  defp has_admin_role?(%{role: role}) when role in @admin_roles, do: true
  defp has_admin_role?(%{roles: roles}) when is_list(roles) do
    Enum.any?(roles, &(&1 in @admin_roles))
  end
  defp has_admin_role?(_), do: false

  # Audit log for security-sensitive operations
  defp audit_log(event, metadata) do
    Logger.info(
      "[Audit] #{event}: #{inspect(metadata)}",
      event: event,
      audit: true,
      metadata: metadata
    )
  end
end
