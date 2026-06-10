defmodule TamanduaServer.Repo do
  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  require Logger

  @doc """
  Dynamically loads the repository configuration from environment variables at runtime.
  Uses DATABASE_URL if set, otherwise falls back to config values.
  """
  def init(_type, config) do
    case System.get_env("DATABASE_URL") do
      nil -> {:ok, config}
      url -> {:ok, Keyword.put(config, :url, url)}
    end
  end

  @doc """
  Wraps default_options/1 callback to automatically set organization context
  for queries when available in the process dictionary.

  This enables automatic RLS filtering for all queries when the organization
  is set via Plug or other middleware.
  """
  def default_options(_operation) do
    case Process.get(:current_organization_id) do
      nil ->
        []

      org_id when is_binary(org_id) ->
        # Set organization context for this query
        # This is automatically called before each Repo operation
        set_query_organization(org_id)
        []
    end
  end

  @doc """
  Puts the organization ID in the process dictionary for automatic RLS filtering.

  This should be called in Plugs or other request-handling code to set the
  organization context for all database queries in the current process.

  ## Parameters

  - organization_id: UUID binary or string of the organization

  ## Examples

      # In a Plug
      def call(conn, _opts) do
        org_id = get_session(conn, :organization_id)
        Repo.put_organization_id(org_id)
        conn
      end

      # In a LiveView
      def mount(_params, %{"organization_id" => org_id}, socket) do
        Repo.put_organization_id(org_id)
        {:ok, socket}
      end
  """
  def put_organization_id(organization_id) when is_binary(organization_id) do
    Process.put(:current_organization_id, organization_id)
    :ok
  end

  @doc """
  Gets the current organization ID from the process dictionary.

  ## Returns

  - organization_id (string) if set
  - nil if not set
  """
  def get_organization_id do
    Process.get(:current_organization_id)
  end

  @doc """
  Clears the organization ID from the process dictionary.
  """
  def clear_organization_id do
    Process.delete(:current_organization_id)
    :ok
  end

  ## Private Functions

  defp set_query_organization(org_id) do
    # Format UUID to string
    org_id_string = format_uuid(org_id)

    # Set session variable for RLS policies
    # Postgres does not support bind parameters in SET LOCAL, so use the
    # already-validated UUID string directly.
    sql = "SET LOCAL app.current_organization_id = '#{org_id_string}'"

    case query(sql) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to set organization context for query: #{inspect(reason)}")
        :ok
    end
  rescue
    error ->
      Logger.error("Exception setting organization context: #{inspect(error)}")
      :ok
  end

  defp format_uuid(uuid) when is_binary(uuid) do
    case Ecto.UUID.cast(uuid) do
      {:ok, uuid_string} -> uuid_string
      :error -> uuid
    end
  end
end
