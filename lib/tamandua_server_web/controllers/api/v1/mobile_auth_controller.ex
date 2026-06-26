defmodule TamanduaServerWeb.API.V1.MobileAuthController do
  @moduledoc """
  Token authentication for first-party mobile clients.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Accounts
  alias TamanduaServer.AuditLog

  def login(conn, %{"email" => email, "password" => password} = params) do
    case Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        cond do
          mfa_required_without_token?(user, params) ->
            json(conn, %{mfa_required: true})

          not valid_mfa_token?(user, params["mfa_token"]) ->
            conn
            |> put_status(:unauthorized)
            |> json(%{message: "Invalid MFA token"})

          true ->
            token = Accounts.generate_api_token(user)
            _ = Accounts.update_last_login(user)
            log_login(user, conn)

            json(conn, %{
              data: %{
                token: token,
                token_type: "Bearer",
                user: serialize_user(user)
              }
            })
        end

      {:error, :invalid_credentials} ->
        log_failed_login(email, conn, :invalid_credentials)

        conn
        |> put_status(:unauthorized)
        |> json(%{message: "Invalid email or password"})
    end
  end

  def login(conn, params) do
    log_failed_login(Map.get(params, "email"), conn, :malformed_login_request)

    conn
    |> put_status(:bad_request)
    |> json(%{message: "Missing email or password"})
  end

  def logout(conn, _params) do
    if token = bearer_token(conn) do
      Accounts.revoke_api_token(token)
    end

    if user = conn.assigns[:current_user] do
      safe_audit(fn ->
        AuditLog.log_logout(user,
          ip_address: client_ip(conn),
          user_agent: user_agent(conn)
        )
      end)
    end

    json(conn, %{data: %{ok: true}})
  end

  def refresh(conn, _params) do
    user = conn.assigns[:current_user]

    if token = bearer_token(conn) do
      Accounts.revoke_api_token(token)
    end

    new_token = Accounts.generate_api_token(user)

    json(conn, %{
      data: %{
        token: new_token,
        token_type: "Bearer",
        user: serialize_user(user)
      }
    })
  end

  defp mfa_required_without_token?(user, params) do
    mfa_enabled?(user) and blank?(params["mfa_token"])
  end

  defp mfa_enabled?(user), do: Map.get(user, :mfa_enabled) == true

  defp valid_mfa_token?(user, token) do
    not mfa_enabled?(user) or Accounts.verify_totp(Map.get(user, :mfa_secret), token)
  end

  defp blank?(value), do: value in [nil, ""]

  defp serialize_user(user) do
    %{
      id: user.id,
      email: user.email,
      name: Map.get(user, :name),
      role: Map.get(user, :role),
      organization_id: Map.get(user, :organization_id),
      mfa_enabled: Map.get(user, :mfa_enabled, false)
    }
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp log_login(user, conn) do
    safe_audit(fn ->
      AuditLog.log_login(user,
        ip_address: client_ip(conn),
        user_agent: user_agent(conn),
        method: "mobile_api"
      )
    end)
  end

  defp log_failed_login(nil, _conn, _reason), do: :ok

  defp log_failed_login(email, conn, reason) do
    safe_audit(fn ->
      AuditLog.log_failed_login(email, reason,
        ip_address: client_ip(conn),
        user_agent: user_agent(conn)
      )
    end)
  end

  defp safe_audit(fun) do
    fun.()
    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
