defmodule TamanduaServer.Auth.InvitationManager do
  @moduledoc """
  Invitation Manager for tenant user provisioning.

  Manages the lifecycle of user invitations (create, list, revoke, accept, expire)
  using an ETS table for high-performance storage. Each invitation contains a
  secure random token that can be used to accept the invitation and join the
  organization.

  ## Invitation Lifecycle

      pending -> accepted   (user accepts via token)
      pending -> revoked    (admin revokes)
      pending -> expired    (past expires_at)

  ## Storage

  Uses ETS table `:tamandua_invitations` with `{id, invitation_map}` entries.
  A periodic cleanup task expires stale invitations every 5 minutes.
  """

  use GenServer
  require Logger

  @table :tamandua_invitations
  @default_expiry_days 7
  @cleanup_interval :timer.minutes(5)

  @valid_roles ~w(admin analyst viewer responder)
  @email_regex ~r/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new invitation.

  ## Attributes

  - `email` (required) - Email address of the invitee
  - `role` (optional, default: "analyst") - Role to assign: admin, analyst, viewer, responder
  - `organization_id` (required) - Organization the user is being invited to
  - `created_by` (optional) - ID of the admin creating the invitation

  Returns `{:ok, invitation}` or `{:error, reason}`.
  """
  @spec create(map()) :: {:ok, map()} | {:error, String.t()}
  def create(attrs) do
    GenServer.call(__MODULE__, {:create, attrs})
  end

  @doc """
  List all invitations for an organization.

  Returns only pending invitations by default. Pass `status: :all` to include
  accepted, revoked, and expired invitations.

  Returns `{:ok, [invitation]}`.
  """
  @spec list(String.t(), keyword()) :: {:ok, list(map())}
  def list(organization_id, opts \\ []) do
    GenServer.call(__MODULE__, {:list, organization_id, opts})
  end

  @doc """
  Get an invitation by its secure token.

  Returns `{:ok, invitation}` or `{:error, :not_found}`.
  Only returns pending (non-expired) invitations.
  """
  @spec get_by_token(String.t()) :: {:ok, map()} | {:error, :not_found | :expired}
  def get_by_token(token) do
    GenServer.call(__MODULE__, {:get_by_token, token})
  end

  @doc """
  Revoke an invitation by its ID.

  Returns `{:ok, invitation}` or `{:error, :not_found}`.
  """
  @spec revoke(String.t()) :: {:ok, map()} | {:error, :not_found | :already_accepted}
  def revoke(invitation_id) do
    GenServer.call(__MODULE__, {:revoke, invitation_id})
  end

  @doc """
  Accept an invitation by its secure token.

  Marks the invitation as accepted. The caller is responsible for actually
  creating/linking the user account.

  Returns `{:ok, invitation}` or `{:error, reason}`.
  """
  @spec accept(String.t()) :: {:ok, map()} | {:error, :not_found | :expired | :already_accepted | :revoked}
  def accept(token) do
    GenServer.call(__MODULE__, {:accept, token})
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])

    Logger.info("[InvitationManager] Started, ETS table :tamandua_invitations created")

    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_call({:create, attrs}, _from, state) do
    case validate_create_attrs(attrs) do
      :ok ->
        invitation = build_invitation(attrs)
        :ets.insert(@table, {invitation.id, invitation})

        Logger.info(
          "[InvitationManager] Created invitation #{invitation.id} for #{invitation.email} " <>
            "in org #{invitation.organization_id} with role #{invitation.role}"
        )

        {:reply, {:ok, invitation}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:list, organization_id, opts}, _from, state) do
    # First expire any stale invitations
    expire_stale_invitations()

    status_filter = Keyword.get(opts, :status, :pending)

    invitations =
      :ets.tab2list(@table)
      |> Enum.map(fn {_id, inv} -> inv end)
      |> Enum.filter(fn inv -> inv.organization_id == organization_id end)
      |> Enum.filter(fn inv ->
        case status_filter do
          :all -> true
          status -> inv.status == to_string(status)
        end
      end)
      |> Enum.sort_by(fn inv -> inv.created_at end, {:desc, DateTime})

    {:reply, {:ok, invitations}, state}
  end

  def handle_call({:get_by_token, token}, _from, state) do
    result =
      case find_by_token(token) do
        nil ->
          {:error, :not_found}

        invitation ->
          if expired?(invitation) do
            update_invitation(invitation.id, %{status: "expired"})
            {:error, :expired}
          else
            if invitation.status == "pending" do
              {:ok, invitation}
            else
              {:error, :not_found}
            end
          end
      end

    {:reply, result, state}
  end

  def handle_call({:revoke, invitation_id}, _from, state) do
    case :ets.lookup(@table, invitation_id) do
      [{^invitation_id, invitation}] ->
        cond do
          invitation.status == "accepted" ->
            {:reply, {:error, :already_accepted}, state}

          invitation.status == "revoked" ->
            {:reply, {:ok, invitation}, state}

          true ->
            updated = %{invitation | status: "revoked"}
            :ets.insert(@table, {invitation_id, updated})

            Logger.info(
              "[InvitationManager] Revoked invitation #{invitation_id} for #{invitation.email}"
            )

            {:reply, {:ok, updated}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:accept, token}, _from, state) do
    case find_by_token(token) do
      nil ->
        {:reply, {:error, :not_found}, state}

      invitation ->
        cond do
          expired?(invitation) ->
            update_invitation(invitation.id, %{status: "expired"})
            {:reply, {:error, :expired}, state}

          invitation.status == "accepted" ->
            {:reply, {:error, :already_accepted}, state}

          invitation.status == "revoked" ->
            {:reply, {:error, :revoked}, state}

          invitation.status == "pending" ->
            updated = %{invitation | status: "accepted"}
            :ets.insert(@table, {invitation.id, updated})

            Logger.info(
              "[InvitationManager] Accepted invitation #{invitation.id} for #{invitation.email} " <>
                "in org #{invitation.organization_id}"
            )

            {:reply, {:ok, updated}, state}

          true ->
            {:reply, {:error, :not_found}, state}
        end
    end
  end

  @impl true
  def handle_info(:cleanup, state) do
    count = expire_stale_invitations()

    if count > 0 do
      Logger.debug("[InvitationManager] Expired #{count} stale invitations")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp validate_create_attrs(attrs) do
    email = Map.get(attrs, :email) || Map.get(attrs, "email")
    organization_id = Map.get(attrs, :organization_id) || Map.get(attrs, "organization_id")
    role = Map.get(attrs, :role) || Map.get(attrs, "role") || "analyst"

    cond do
      is_nil(email) or email == "" ->
        {:error, "email is required"}

      not valid_email?(email) ->
        {:error, "invalid email format"}

      is_nil(organization_id) or organization_id == "" ->
        {:error, "organization_id is required"}

      role not in @valid_roles ->
        {:error, "invalid role: #{role}. Must be one of: #{Enum.join(@valid_roles, ", ")}"}

      duplicate_pending?(email, organization_id) ->
        {:error, "a pending invitation already exists for this email in this organization"}

      true ->
        :ok
    end
  end

  defp valid_email?(email) when is_binary(email) do
    Regex.match?(@email_regex, email)
  end

  defp valid_email?(_), do: false

  defp duplicate_pending?(email, organization_id) do
    :ets.tab2list(@table)
    |> Enum.any?(fn {_id, inv} ->
      inv.email == email and
        inv.organization_id == organization_id and
        inv.status == "pending" and
        not expired?(inv)
    end)
  end

  defp build_invitation(attrs) do
    email = Map.get(attrs, :email) || Map.get(attrs, "email")
    role = Map.get(attrs, :role) || Map.get(attrs, "role") || "analyst"
    organization_id = Map.get(attrs, :organization_id) || Map.get(attrs, "organization_id")
    created_by = Map.get(attrs, :created_by) || Map.get(attrs, "created_by")

    now = DateTime.utc_now()
    expires_at = DateTime.add(now, @default_expiry_days * 24 * 3600, :second)

    %{
      id: Ecto.UUID.generate(),
      email: email,
      role: role,
      organization_id: organization_id,
      token: generate_secure_token(),
      status: "pending",
      created_by: created_by,
      created_at: now,
      expires_at: expires_at
    }
  end

  defp generate_secure_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64()
  end

  defp find_by_token(token) do
    :ets.tab2list(@table)
    |> Enum.find_value(fn {_id, inv} ->
      if inv.token == token, do: inv, else: nil
    end)
  end

  defp update_invitation(id, changes) do
    case :ets.lookup(@table, id) do
      [{^id, invitation}] ->
        updated = Map.merge(invitation, changes)
        :ets.insert(@table, {id, updated})
        updated

      [] ->
        nil
    end
  end

  defp expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp expire_stale_invitations do
    now = DateTime.utc_now()

    stale =
      :ets.tab2list(@table)
      |> Enum.filter(fn {_id, inv} ->
        inv.status == "pending" and DateTime.compare(now, inv.expires_at) == :gt
      end)

    Enum.each(stale, fn {id, inv} ->
      :ets.insert(@table, {id, %{inv | status: "expired"}})
    end)

    length(stale)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
