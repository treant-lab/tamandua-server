defmodule TamanduaServerWeb.UserAuthPersistentSessionTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.PersistentUserSession
  alias TamanduaServerWeb.UserAuth

  setup do
    previous = Application.get_env(:tamandua_server, :persistent_user_sessions)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:tamandua_server, :persistent_user_sessions, previous),
        else: Application.delete_env(:tamandua_server, :persistent_user_sessions)
    end)

    :ok
  end

  test "default-off login preserves the existing ETS behavior", %{conn: conn} do
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: false)
    user = insert(:user)

    conn = conn |> init_test_session(%{}) |> UserAuth.log_in_user(user)

    assert is_binary(get_session(conn, :user_token))
    assert get_session(conn, :persistent_session_binding) == nil
    assert Repo.aggregate(PersistentUserSession, :count) == 0
  end

  test "opt-in login records server-derived password provenance and verified fetch assigns ref",
       %{
         conn: conn
       } do
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: true)
    user = insert(:user)

    logged_in =
      conn
      |> init_test_session(%{})
      |> UserAuth.log_in_user(user, %{"auth_method" => "mfa"})

    binding = get_session(logged_in, :persistent_session_binding)
    assert is_binary(binding)
    assert get_session(logged_in, :persistent_session_ref) == nil
    assert get_session(logged_in, :persistent_session_auth_method) == nil

    fetched = UserAuth.fetch_current_user(logged_in, [])
    session_ref = fetched.assigns.persistent_session_ref
    assert fetched.assigns.current_user.id == user.id
    assert is_binary(session_ref)
    assert Repo.get!(PersistentUserSession, session_ref).auth_method == :password
  end

  test "logout revokes the persistent row", %{conn: conn} do
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: true)
    user = insert(:user)

    logged_in = conn |> init_test_session(%{}) |> UserAuth.log_in_user(user)
    session_ref = UserAuth.fetch_current_user(logged_in, []).assigns.persistent_session_ref

    logout_conn =
      build_conn()
      |> init_test_session(%{
        user_token: get_session(logged_in, :user_token),
        persistent_session_binding: get_session(logged_in, :persistent_session_binding),
        live_socket_id: get_session(logged_in, :live_socket_id)
      })

    _logged_out = UserAuth.log_out_user(logout_conn)

    assert %DateTime{} = Repo.get!(PersistentUserSession, session_ref).revoked_at
  end

  test "feature-on refuses a legacy ETS cookie without persistent binding", %{conn: conn} do
    Application.put_env(:tamandua_server, :persistent_user_sessions, enabled: true)
    user = insert(:user)
    legacy_token = TamanduaServer.Accounts.generate_user_session_token(user)

    fetched =
      conn
      |> init_test_session(%{user_token: legacy_token})
      |> UserAuth.fetch_current_user([])

    assert fetched.assigns.current_user == nil
    assert fetched.assigns.persistent_session_ref == nil
  end
end
