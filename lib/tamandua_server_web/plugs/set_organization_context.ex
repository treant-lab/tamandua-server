defmodule TamanduaServerWeb.Plugs.SetOrganizationContext do
  @moduledoc """
  Plug to automatically set the organization context for Row-Level Security (RLS).

  This plug extracts the organization ID from the authenticated user or session
  and sets it in the Repo process dictionary, enabling automatic RLS filtering
  for all database queries in the request.

  ## Usage

  Add to your router or controller pipeline:

      pipeline :authenticated do
        plug :fetch_session
        plug :fetch_current_user
        plug TamanduaServerWeb.Plugs.SetOrganizationContext
      end

  ## Security

  - Always runs after authentication
  - Validates organization_id is a valid UUID
  - Logs any failures to set context (but doesn't halt request)
  - Automatically cleared after request completes

  ## Process Flow

  1. Extract organization_id from conn.assigns.current_user or session
  2. Validate it's a valid UUID
  3. Set in Repo process dictionary
  4. Set in MultiTenant session variable
  5. Continue with request
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @doc """
  Initializes the plug with options.

  ## Options

  - :key - Key to look for organization_id in assigns (default: :current_user)
  - :session_key - Key to look for organization_id in session (default: :organization_id)
  - :required - Whether to halt if organization_id is missing (default: false)
  """
  def init(opts) do
    %{
      key: Keyword.get(opts, :key, :current_user),
      session_key: Keyword.get(opts, :session_key, :organization_id),
      required: Keyword.get(opts, :required, false)
    }
  end

  @doc """
  Sets the organization context for the current request.

  Looks for organization_id in the following order:
  1. conn.assigns.organization_id (explicitly set)
  2. conn.assigns.current_user.organization_id (from authentication)
  3. get_session(conn, :organization_id) (from session)

  If found and valid, sets it in both:
  - Repo process dictionary (for automatic query filtering)
  - MultiTenant session variable (for manual queries)
  """
  def call(conn, opts) do
    case extract_organization_id(conn, opts) do
      {:ok, org_id} ->
        # Set in Repo process dictionary for automatic filtering
        Repo.put_organization_id(org_id)

        # Also set in database session variable for explicit queries
        case MultiTenant.put_organization_id(nil, org_id) do
          :ok ->
            Logger.debug("Set organization context to #{org_id} for request")
            assign(conn, :current_organization_id, org_id)

          {:error, reason} ->
            Logger.error("Failed to set organization context in DB: #{inspect(reason)}")

            if opts.required do
              conn
              |> put_status(:internal_server_error)
              |> Phoenix.Controller.json(%{error: "Failed to set organization context"})
              |> halt()
            else
              conn
            end
        end

      {:error, :not_found} ->
        Logger.debug("No organization_id found for request")

        if opts.required do
          conn
          |> put_status(:forbidden)
          |> Phoenix.Controller.json(%{error: "Organization context required"})
          |> halt()
        else
          conn
        end

      {:error, :invalid_uuid} ->
        Logger.warning("Invalid organization_id UUID in request")

        if opts.required do
          conn
          |> put_status(:bad_request)
          |> Phoenix.Controller.json(%{error: "Invalid organization ID"})
          |> halt()
        else
          conn
        end
    end
  end

  ## Private Functions

  defp extract_organization_id(conn, opts) do
    # Try to get organization_id from multiple sources
    org_id =
      conn.assigns[:organization_id] ||
        get_from_user(conn, opts) ||
        get_session(conn, opts.session_key)

    case org_id do
      nil ->
        {:error, :not_found}

      org_id when is_binary(org_id) ->
        validate_uuid(org_id)

      _ ->
        {:error, :invalid_uuid}
    end
  end

  defp get_from_user(conn, opts) do
    case conn.assigns[opts.key] do
      %{organization_id: org_id} when is_binary(org_id) -> org_id
      _ -> nil
    end
  end

  defp validate_uuid(uuid) do
    case Ecto.UUID.cast(uuid) do
      {:ok, uuid_string} -> {:ok, uuid_string}
      :error -> {:error, :invalid_uuid}
    end
  end
end
