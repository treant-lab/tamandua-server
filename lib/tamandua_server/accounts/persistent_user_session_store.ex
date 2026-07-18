defmodule TamanduaServer.Accounts.PersistentUserSessionStore do
  @moduledoc """
  Default-off first-party session store. Only SHA-256 token and binding digests
  are persisted; raw secrets remain in Phoenix's signed browser session.

  Token and binding are co-resident, so binding only mitigates partial-secret
  theft. Theft of the complete cookie remains outside this Phase A claim.
  """

  import Ecto.Query

  alias TamanduaServer.Accounts.{
    Organization,
    PersistentUserSession,
    PlatformOperatorSession,
    User
  }

  alias TamanduaServer.Repo

  @default_ttl_seconds 7 * 24 * 60 * 60
  @max_ttl_seconds 7 * 24 * 60 * 60
  @default_activity_touch_interval_seconds 5 * 60
  @default_terminal_retention_seconds 30 * 24 * 60 * 60
  @default_cleanup_batch_size 500
  @max_cleanup_batch_size 1_000

  @activity_event [:tamandua_server, :persistent_user_session, :activity]
  @retention_event [:tamandua_server, :persistent_user_session, :retention]

  def enabled? do
    Application.get_env(:tamandua_server, :persistent_user_sessions, [])
    |> Keyword.get(:enabled, false)
  end

  def create(user, opts \\ [])

  def create(%User{organization_id: organization_id} = user, opts)
      when is_binary(organization_id) do
    if enabled?() do
      now = Keyword.get(opts, :now, DateTime.utc_now())
      ttl = Keyword.get(opts, :ttl_seconds, configured_ttl())
      token = random_secret()
      binding = random_secret()

      if valid_issue_options?(now, ttl) do
        Repo.transaction(fn ->
          current_user =
            from(u in User,
              join: o in Organization,
              on: o.id == u.organization_id,
              where:
                u.id == ^user.id and u.organization_id == ^organization_id and
                  u.is_active == true and o.is_active == true,
              lock: "FOR UPDATE"
            )
            |> Repo.one()

          if current_user do
            attrs = %{
              user_id: current_user.id,
              organization_id: current_user.organization_id,
              token_digest: digest(token),
              binding_digest: digest(binding),
              auth_epoch: current_user.auth_epoch,
              auth_method: :password,
              authenticated_at: now,
              last_seen_at: now,
              expires_at: DateTime.add(now, ttl, :second)
            }

            %PersistentUserSession{}
            |> PersistentUserSession.create_changeset(attrs)
            |> Repo.insert!()
          else
            Repo.rollback(:inactive_or_unbound_principal)
          end
        end)
        |> case do
          {:ok, session} -> {:ok, %{token: token, binding: binding, session_id: session.id}}
          {:error, reason} -> {:error, reason}
        end
      else
        {:error, :invalid_session_lifetime}
      end
    else
      {:error, :persistent_sessions_disabled}
    end
  end

  def create(%User{}, _opts), do: {:error, :tenant_required}

  def authenticate(token, binding) when is_binary(token) and is_binary(binding) do
    if enabled?() do
      now = DateTime.utc_now()

      Repo.transaction(fn ->
        case active_query(digest(token)) |> Repo.one() do
          nil -> Repo.rollback(:invalid_session)
          session -> validate_and_touch!(session, binding, now)
        end
      end)
      |> case do
        {:ok, {user, session}} -> {:ok, user, session.id}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :persistent_sessions_disabled}
    end
  end

  def authenticate(_, _), do: {:error, :invalid_session}

  def revoke(token, binding) when is_binary(token) and is_binary(binding) do
    if enabled?() do
      now = DateTime.utc_now()

      Repo.transaction(fn ->
        case revocable_query(digest(token)) |> Repo.one() do
          nil ->
            :ok

          session ->
            verify_binding!(session, binding)
            session |> Ecto.Changeset.change(revoked_at: now) |> Repo.update!()
            :ok
        end
      end)
      |> case do
        {:ok, :ok} -> :ok
        {:error, reason} -> {:error, reason}
      end
    else
      :ok
    end
  end

  def revoke(_, _), do: :ok

  @doc """
  Deletes one bounded batch of expired or revoked sessions whose terminal
  timestamp is older than the configured retention window.

  Rows are locked with `SKIP LOCKED`, allowing independent workers to make
  progress without waiting on or deleting the same session.
  """
  def cleanup_terminal_sessions(opts \\ [])

  def cleanup_terminal_sessions(opts) when is_list(opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    retention_seconds =
      configured_nonnegative_integer(
        opts,
        :retention_seconds,
        @default_terminal_retention_seconds
      )

    batch_size = configured_batch_size(opts)

    try do
      if match?(%DateTime{}, now) do
        cutoff = DateTime.add(now, -retention_seconds, :second)

        Repo.transaction(fn ->
          ids =
            from(s in PersistentUserSession,
              where:
                (not is_nil(s.revoked_at) and s.revoked_at <= ^cutoff) or
                  s.expires_at <= ^cutoff,
              order_by: [asc: s.expires_at, asc: s.id],
              limit: ^batch_size,
              select: s.id,
              lock: "FOR UPDATE SKIP LOCKED"
            )
            |> Repo.all()

          {deleted_count, _} =
            from(s in PersistentUserSession, where: s.id in ^ids)
            |> Repo.delete_all()

          %{
            status: :completed,
            deleted_count: deleted_count,
            batches: if(deleted_count > 0, do: 1, else: 0)
          }
        end)
        |> case do
          {:ok, result} ->
            emit(@retention_event, result.deleted_count, :terminal_cleanup)
            {:ok, result}

          {:error, reason} ->
            emit(@retention_event, 1, :cleanup_error)
            {:error, reason}
        end
      else
        {:error, :invalid_cleanup_time}
      end
    rescue
      _error ->
        emit(@retention_event, 1, :cleanup_error)
        {:error, :cleanup_failed}
    end
  end

  def cleanup_terminal_sessions(_), do: {:error, :invalid_cleanup_options}

  def fetch_for_update(repo, session_id, binding)
      when is_binary(session_id) and is_binary(binding) do
    if enabled?() do
      now = DateTime.utc_now()

      from(s in PersistentUserSession,
        join: u in User,
        on: u.id == s.user_id and u.organization_id == s.organization_id,
        join: o in Organization,
        on: o.id == s.organization_id,
        where: s.id == ^session_id and is_nil(s.revoked_at) and o.is_active == true,
        preload: [user: u, organization: o],
        lock: "FOR UPDATE"
      )
      |> repo.one()
      |> case do
        nil -> {:error, :persistent_session_required}
        session -> project_operator_session(session, binding, now)
      end
    else
      {:error, :persistent_session_required}
    end
  end

  def fetch_for_update(_, _, _), do: {:error, :persistent_session_required}

  defp active_query(token_digest) do
    from(s in PersistentUserSession,
      join: u in User,
      on: u.id == s.user_id and u.organization_id == s.organization_id,
      join: o in Organization,
      on: o.id == s.organization_id,
      where: s.token_digest == ^token_digest and is_nil(s.revoked_at) and o.is_active == true,
      preload: [user: u, organization: o],
      lock: "FOR UPDATE"
    )
  end

  defp revocable_query(token_digest) do
    from(s in PersistentUserSession,
      where: s.token_digest == ^token_digest and is_nil(s.revoked_at),
      lock: "FOR UPDATE"
    )
  end

  defp validate_and_touch!(session, binding, now) do
    verify_binding!(session, binding)

    cond do
      not session.user.is_active ->
        Repo.rollback(:inactive_user)

      session.user.auth_epoch != session.auth_epoch ->
        Repo.rollback(:credential_epoch_changed)

      DateTime.compare(session.authenticated_at, now) == :gt ->
        Repo.rollback(:invalid_chronology)

      DateTime.compare(session.expires_at, now) != :gt ->
        Repo.rollback(:session_expired)

      true ->
        touch_activity_if_due!(session, now)
        {session.user, session}
    end
  end

  defp touch_activity_if_due!(session, now) do
    interval = configured_activity_touch_interval()

    if DateTime.diff(now, session.last_seen_at, :second) >= interval do
      session |> Ecto.Changeset.change(last_seen_at: now) |> Repo.update!()
      emit(@activity_event, 1, :touched)
    else
      emit(@activity_event, 1, :throttled)
    end
  end

  defp project_operator_session(session, binding, now) do
    with :ok <- verify_binding(session, binding) do
      cond do
        not session.user.is_active ->
          {:error, :inactive_user}

        session.user.auth_epoch != session.auth_epoch ->
          {:error, :credential_epoch_changed}

        DateTime.compare(session.authenticated_at, now) == :gt ->
          {:error, :invalid_chronology}

        DateTime.compare(session.expires_at, now) != :gt ->
          {:error, :session_expired}

        true ->
          {:ok,
           %PlatformOperatorSession{
             id: session.id,
             user_id: session.user_id,
             binding_hash: session.binding_digest,
             authenticated_at: session.authenticated_at,
             expires_at: session.expires_at,
             revoked_at: session.revoked_at,
             auth_method: :session
           }}
      end
    end
  end

  defp verify_binding!(session, binding) do
    case verify_binding(session, binding) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp verify_binding(session, binding) do
    if Plug.Crypto.secure_compare(session.binding_digest, digest(binding)),
      do: :ok,
      else: {:error, :session_binding_mismatch}
  end

  defp configured_ttl do
    Application.get_env(:tamandua_server, :persistent_user_sessions, [])
    |> Keyword.get(:ttl_seconds, @default_ttl_seconds)
  end

  defp configured_activity_touch_interval do
    configured_nonnegative_integer(
      [],
      :activity_touch_interval_seconds,
      @default_activity_touch_interval_seconds
    )
  end

  defp configured_batch_size(opts) do
    value = configured_value(opts, :cleanup_batch_size, @default_cleanup_batch_size)

    if is_integer(value) and value > 0 and value <= @max_cleanup_batch_size,
      do: value,
      else: @default_cleanup_batch_size
  end

  defp configured_nonnegative_integer(opts, key, default) do
    value = configured_value(opts, key, default)
    if is_integer(value) and value >= 0, do: value, else: default
  end

  defp configured_value(opts, key, default) do
    case Keyword.fetch(opts, key) do
      {:ok, value} ->
        value

      :error ->
        Application.get_env(:tamandua_server, :persistent_user_sessions, [])
        |> Keyword.get(key, default)
    end
  end

  defp emit(event, count, category) do
    :telemetry.execute(event, %{count: count}, %{category: category})
  end

  defp valid_issue_options?(%DateTime{} = now, ttl)
       when is_integer(ttl) and ttl > 0 and ttl <= @max_ttl_seconds do
    DateTime.compare(now, DateTime.utc_now()) != :gt
  end

  defp valid_issue_options?(_, _), do: false

  defp random_secret, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  defp digest(secret), do: :crypto.hash(:sha256, secret)
end
