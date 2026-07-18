defmodule TamanduaServer.Accounts.PersistentUserSessionTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Accounts

  alias TamanduaServer.Accounts.{
    Organization,
    PersistentUserSession,
    PersistentUserSessionStore,
    User
  }

  alias Ecto.Adapters.SQL.Sandbox

  setup do
    previous = Application.get_env(:tamandua_server, :persistent_user_sessions)
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: true)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:tamandua_server, :persistent_user_sessions, previous),
        else: Application.delete_env(:tamandua_server, :persistent_user_sessions)
    end)

    organization = insert(:organization)
    user = insert(:user, organization: organization)
    %{user: user, organization: organization}
  end

  test "persists only fixed-size token and binding digests", %{user: user} do
    assert {:ok, issued} = PersistentUserSessionStore.create(user)
    session = Repo.get!(PersistentUserSession, issued.session_id)

    assert byte_size(session.token_digest) == 32
    assert byte_size(session.binding_digest) == 32
    refute session.token_digest == issued.token
    refute session.binding_digest == issued.binding
    assert session.user_id == user.id
    assert session.organization_id == user.organization_id
    assert session.auth_epoch == user.auth_epoch
    assert session.auth_method == :password
  end

  test "password A-B-A advances auth_epoch and permanently invalidates the old session", %{
    user: user
  } do
    assert {:ok, issued} = PersistentUserSessionStore.create(user)
    session_id = issued.session_id

    assert {:ok, _user, ^session_id} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    assert {:ok, user_b} = Accounts.update_user(user, %{password: "password-B-123456"})
    assert user_b.auth_epoch == user.auth_epoch + 1

    assert {:error, :credential_epoch_changed} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    assert {:ok, user_a_again} = Accounts.update_user(user_b, %{password: "password123"})
    assert user_a_again.auth_epoch == user.auth_epoch + 2

    assert {:error, :credential_epoch_changed} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)
  end

  test "disable and re-enable cannot revive a prior session", %{user: user} do
    assert {:ok, issued} = PersistentUserSessionStore.create(user)
    assert {:ok, disabled} = Accounts.update_user(user, %{is_active: false})

    assert {:error, :inactive_user} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    assert {:ok, _enabled} = Accounts.update_user(disabled, %{is_active: true})

    assert {:error, :credential_epoch_changed} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)
  end

  test "logout revocation is durable and never unrevokes the UUID", %{user: user} do
    assert {:ok, issued} = PersistentUserSessionStore.create(user)
    assert :ok = PersistentUserSessionStore.revoke(issued.token, issued.binding)

    assert {:error, :invalid_session} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    session = Repo.get!(PersistentUserSession, issued.session_id)
    assert %DateTime{} = session.revoked_at
    assert :ok = PersistentUserSessionStore.revoke(issued.token, issued.binding)
    assert Repo.get!(PersistentUserSession, issued.session_id).revoked_at == session.revoked_at
  end

  test "wrong binding, future authentication and expiry fail closed", %{user: user} do
    assert {:ok, issued} = PersistentUserSessionStore.create(user)

    assert {:error, :session_binding_mismatch} =
             PersistentUserSessionStore.authenticate(issued.token, "wrong-binding")

    future = DateTime.add(DateTime.utc_now(), 60, :second)

    assert {:error, :invalid_session_lifetime} =
             PersistentUserSessionStore.create(user, now: future)

    assert {:error, :invalid_session_lifetime} =
             PersistentUserSessionStore.create(user, ttl_seconds: 7 * 24 * 60 * 60 + 1)

    past = DateTime.add(DateTime.utc_now(), -120, :second)
    assert {:ok, expired} = PersistentUserSessionStore.create(user, now: past, ttl_seconds: 60)

    assert {:error, :session_expired} =
             PersistentUserSessionStore.authenticate(expired.token, expired.binding)
  end

  test "successful authentication throttles activity writes at the configured boundary", %{
    user: user
  } do
    Application.put_env(:tamandua_server, :persistent_user_sessions,
      enabled: true,
      activity_touch_interval_seconds: 300
    )

    issued_at = DateTime.add(DateTime.utc_now(), -600, :second)

    assert {:ok, issued} =
             PersistentUserSessionStore.create(user, now: issued_at, ttl_seconds: 3_600)

    below_boundary = DateTime.utc_now()
    set_last_seen!(issued.session_id, below_boundary)

    assert {:ok, _user, session_id} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    assert session_id == issued.session_id
    assert Repo.get!(PersistentUserSession, issued.session_id).last_seen_at == below_boundary

    at_boundary = DateTime.add(DateTime.utc_now(), -300, :second)
    set_last_seen!(issued.session_id, at_boundary)

    assert {:ok, _user, ^session_id} =
             PersistentUserSessionStore.authenticate(issued.token, issued.binding)

    assert DateTime.compare(
             Repo.get!(PersistentUserSession, issued.session_id).last_seen_at,
             at_boundary
           ) == :gt
  end

  test "retention keeps recent and active rows and deletes one bounded terminal batch", %{
    user: user
  } do
    now = DateTime.utc_now()
    old_issue_time = DateTime.add(now, -38 * 24 * 60 * 60, :second)

    old_sessions =
      for _ <- 1..3 do
        assert {:ok, issued} =
                 PersistentUserSessionStore.create(user,
                   now: old_issue_time,
                   ttl_seconds: 7 * 24 * 60 * 60
                 )

        issued
      end

    revoked_issue_time = DateTime.add(now, -31 * 24 * 60 * 60, :second)

    assert {:ok, revoked_only} =
             PersistentUserSessionStore.create(user,
               now: revoked_issue_time,
               ttl_seconds: 7 * 24 * 60 * 60
             )

    revoked_only.session_id
    |> then(&Repo.get!(PersistentUserSession, &1))
    |> Ecto.Changeset.change(revoked_at: DateTime.add(now, -30 * 24 * 60 * 60, :second))
    |> Repo.update!()

    assert {:ok, recent} = PersistentUserSessionStore.create(user)

    assert {:ok, %{status: :completed, deleted_count: 2, batches: 1}} =
             PersistentUserSessionStore.cleanup_terminal_sessions(
               now: now,
               retention_seconds: 30 * 24 * 60 * 60,
               cleanup_batch_size: 2
             )

    assert Repo.aggregate(PersistentUserSession, :count) == 3
    assert Repo.get!(PersistentUserSession, recent.session_id)
    assert Enum.count(old_sessions, &Repo.get(PersistentUserSession, &1.session_id)) == 1

    assert {:ok, %{status: :completed, deleted_count: 2, batches: 1}} =
             PersistentUserSessionStore.cleanup_terminal_sessions(
               now: now,
               retention_seconds: 30 * 24 * 60 * 60,
               cleanup_batch_size: 2
             )

    assert {:ok, %{status: :completed, deleted_count: 0, batches: 0}} =
             PersistentUserSessionStore.cleanup_terminal_sessions(
               now: now,
               retention_seconds: 30 * 24 * 60 * 60,
               cleanup_batch_size: 2
             )
  end

  test "independent PostgreSQL sessions skip locked rows and never double-delete" do
    parent = self()
    fixture = create_unboxed_terminal_fixture!(6)

    on_exit(fn -> cleanup_unboxed_fixture!(fixture) end)

    locker =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.checkout(fn ->
            Repo.transaction(fn ->
              locked_ids =
                from(s in PersistentUserSession,
                  where: s.organization_id == ^fixture.organization_id,
                  order_by: [asc: s.id],
                  limit: 4,
                  select: s.id,
                  lock: "FOR UPDATE"
                )
                |> Repo.all()

              %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
              send(parent, {:terminal_rows_locked, self(), backend_pid, locked_ids})

              receive do
                :release_terminal_rows -> locked_ids
              after
                10_000 -> raise "terminal row lock timeout"
              end
            end)
          end)
        end)
      end)

    assert_receive {:terminal_rows_locked, locker_pid, locker_backend_pid, locked_ids}, 10_000
    assert length(locked_ids) == 4

    {cleanup_backend_pid, first_result} =
      Sandbox.unboxed_run(Repo, fn ->
        %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")

        result =
          PersistentUserSessionStore.cleanup_terminal_sessions(
            now: fixture.now,
            retention_seconds: 30 * 24 * 60 * 60,
            cleanup_batch_size: 4
          )

        {backend_pid, result}
      end)

    refute cleanup_backend_pid == locker_backend_pid
    assert {:ok, %{status: :completed, deleted_count: 2, batches: 1}} = first_result

    send(locker_pid, :release_terminal_rows)
    assert {:ok, ^locked_ids} = Task.await(locker, 10_000)

    assert {:ok, %{status: :completed, deleted_count: 4, batches: 1}} =
             Sandbox.unboxed_run(Repo, fn ->
               PersistentUserSessionStore.cleanup_terminal_sessions(
                 now: fixture.now,
                 retention_seconds: 30 * 24 * 60 * 60,
                 cleanup_batch_size: 4
               )
             end)

    Sandbox.unboxed_run(Repo, fn ->
      assert Repo.aggregate(
               from(s in PersistentUserSession,
                 where: s.organization_id == ^fixture.organization_id
               ),
               :count
             ) == 0
    end)
  end

  test "store is unavailable by default" do
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: false)
    refute PersistentUserSessionStore.enabled?()
  end

  test "auth_epoch cannot be reset through public user attrs", %{user: user} do
    assert {:ok, updated} = Accounts.update_user(user, %{auth_epoch: 999, name: "updated"})
    assert updated.auth_epoch == user.auth_epoch
  end

  test "database trigger advances epoch for direct credential and lifecycle writes", %{user: user} do
    first =
      user
      |> Ecto.Changeset.change(password_hash: Bcrypt.hash_pwd_salt("direct-B-123456"))
      |> Repo.update!()

    assert first.auth_epoch == user.auth_epoch + 1

    second = first |> Ecto.Changeset.change(is_active: false) |> Repo.update!()
    third = second |> Ecto.Changeset.change(is_active: true) |> Repo.update!()

    assert second.auth_epoch == user.auth_epoch + 2
    assert third.auth_epoch == user.auth_epoch + 3

    reset_attempt = third |> Ecto.Changeset.change(auth_epoch: 0) |> Repo.update!()
    assert reset_attempt.auth_epoch == third.auth_epoch
  end

  defp set_last_seen!(session_id, last_seen_at) do
    session_id
    |> then(&Repo.get!(PersistentUserSession, &1))
    |> Ecto.Changeset.change(last_seen_at: last_seen_at)
    |> Repo.update!()
  end

  defp create_unboxed_terminal_fixture!(count) do
    Sandbox.unboxed_run(Repo, fn ->
      organization = insert(:organization)
      user = insert(:user, organization: organization)
      now = DateTime.utc_now()
      issued_at = DateTime.add(now, -38 * 24 * 60 * 60, :second)

      sessions =
        for _ <- 1..count do
          assert {:ok, issued} =
                   PersistentUserSessionStore.create(user,
                     now: issued_at,
                     ttl_seconds: 7 * 24 * 60 * 60
                   )

          issued.session_id
        end

      %{organization_id: organization.id, user_id: user.id, session_ids: sessions, now: now}
    end)
  end

  defp cleanup_unboxed_fixture!(fixture) do
    Sandbox.unboxed_run(Repo, fn ->
      Repo.delete_all(from(s in PersistentUserSession, where: s.id in ^fixture.session_ids))
      Repo.delete_all(from(u in User, where: u.id == ^fixture.user_id))
      Repo.delete_all(from(o in Organization, where: o.id == ^fixture.organization_id))
    end)
  end
end
