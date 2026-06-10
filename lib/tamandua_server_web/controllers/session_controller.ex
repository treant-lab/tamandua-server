defmodule TamanduaServerWeb.SessionController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.AuditLog
  alias TamanduaServer.WalletAuth
  alias TamanduaServerWeb.UserAuth

  # Don't use app layout for login page - it has the sidebar
  plug :put_layout, false

  def new(conn, _params) do
    render(conn, :new, error_message: nil, email: "")
  end

  def register(conn, _params) do
    changeset = User.registration_changeset(%User{}, %{})
    render(conn, :register, changeset: changeset, error_message: nil)
  end

  def create_register(conn, %{"user" => user_params} = params) do
    with :ok <- validate_password_confirmation(user_params),
         {:ok, wallet_attrs} <- verified_wallet_attrs(params),
         {:ok, user, _org} <- register_owner(user_params, wallet_attrs) do
      AuditLog.log_login(user,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn),
        method: if(wallet_attrs, do: "wallet_registration", else: "password_registration")
      )

      log_wallet_event(user, wallet_attrs, "wallet_linked", conn)

      conn
      |> put_flash(:info, "Account created.")
      |> UserAuth.log_in_user(user)
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :register, changeset: changeset, error_message: "Please check the errors below.")

      {:error, reason} ->
        changeset = User.registration_changeset(%User{}, user_params)
        render(conn, :register, changeset: changeset, error_message: humanize_wallet_error(reason))
    end
  end

  def create(conn, %{"user" => %{"email" => email, "password" => password}}) do
    case safe_authenticate_user(email, password) do
      {:ok, user} ->
        # Log successful login
        safe_audit(fn ->
          AuditLog.log_login(user,
          ip_address: get_client_ip(conn),
          user_agent: get_user_agent(conn),
          method: "password"
          )
        end)

        conn
        |> put_flash(:info, "Welcome back!")
        |> UserAuth.log_in_user(user)

      {:error, :invalid_credentials} ->
        safe_log_failed_login(email, conn, :invalid_credentials)
        render(conn, :new, error_message: "Invalid email or password", email: email)
    end
  end

  def create(conn, %{"email" => email, "password" => password}) do
    create(conn, %{"user" => %{"email" => email, "password" => password}})
  end

  def create(conn, params) do
    safe_log_failed_login(Map.get(params, "email") || get_in(params, ["user", "email"]), conn, :malformed_login_request)
    render(conn, :new, error_message: "Invalid email or password", email: "")
  end

  def wallet_challenge(conn, %{"wallet_address" => wallet_address} = params) do
    provider = params["provider"] || "unknown"

    case WalletAuth.issue_challenge(wallet_address, provider, conn.host) do
      {:ok, challenge} ->
        Accounts.log_wallet_auth_event(%{
          "wallet_address" => challenge.wallet_address,
          "provider" => challenge.provider,
          "event_type" => "challenge_issued",
          "ip_address" => get_client_ip(conn),
          "user_agent" => get_user_agent(conn)
        })

        json(conn, challenge)

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: humanize_wallet_error(reason)})
    end
  end

  def wallet_login(conn, params) do
    with {:ok, verified} <- verify_wallet_params(params),
         %User{} = user <- Accounts.get_user_by_wallet_identity(verified.chain, verified.wallet_address) do
      Accounts.touch_wallet_identity(verified.chain, verified.wallet_address)
      log_wallet_event(user, verified, "login_succeeded", conn)

      AuditLog.log_login(user,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn),
        method: "wallet"
      )

      conn
      |> put_flash(:info, "Welcome back.")
      |> UserAuth.log_in_user(user)
    else
      nil ->
        params
        |> Map.put("event_type", "login_failed")
        |> log_unlinked_wallet_event(conn)

        conn
        |> put_status(:not_found)
        |> json(%{error: "Wallet is not linked to an account.", register_url: ~p"/register"})

      {:error, reason} ->
        params
        |> Map.put("event_type", "login_failed")
        |> log_unlinked_wallet_event(conn)

        conn
        |> put_status(:unauthorized)
        |> json(%{error: humanize_wallet_error(reason)})
    end
  end

  def delete(conn, _params) do
    # Log logout if user is authenticated
    if user = conn.assigns[:current_user] do
      AuditLog.log_logout(user,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      )
    end

    conn
    |> put_flash(:info, "Logged out successfully.")
    |> UserAuth.log_out_user()
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_client_ip(conn) do
    # Check for X-Forwarded-For header (common in proxy/load balancer setups)
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        # Fall back to remote_ip
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end

  defp safe_authenticate_user(email, password) do
    Accounts.authenticate_user(email, password)
  rescue
    exception ->
      require Logger
      Logger.error("Password login failed with exception: #{Exception.format(:error, exception, __STACKTRACE__)}")
      {:error, :invalid_credentials}
  catch
    kind, reason ->
      require Logger
      Logger.error("Password login failed with #{inspect(kind)}: #{inspect(reason)}")
      {:error, :invalid_credentials}
  end

  defp safe_log_failed_login(nil, _conn, _reason), do: :ok

  defp safe_log_failed_login(email, conn, reason) do
    safe_audit(fn ->
      AuditLog.log_failed_login(email, reason,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      )
    end)
  end

  defp safe_audit(fun) when is_function(fun, 0) do
    case fun.() do
      {:ok, _} -> :ok
      {:error, reason} ->
        require Logger
        Logger.warning("Audit write skipped during auth flow: #{inspect(reason)}")
        :ok
      _ -> :ok
    end
  rescue
    exception ->
      require Logger
      Logger.warning("Audit write failed during auth flow: #{Exception.message(exception)}")
      :ok
  catch
    kind, reason ->
      require Logger
      Logger.warning("Audit write failed during auth flow with #{inspect(kind)}: #{inspect(reason)}")
      :ok
  end

  defp validate_password_confirmation(%{"password" => password, "password_confirmation" => password}) do
    :ok
  end

  defp validate_password_confirmation(_), do: {:error, :password_confirmation_mismatch}

  defp register_owner(user_params, wallet_attrs) do
    org_name = Map.get(user_params, "organization_name") || "#{Map.get(user_params, "name", "Tamandua")} Workspace"

    org_attrs = %{
      "name" => org_name,
      "slug" => unique_slug(org_name),
      "license_tier" => "trial",
      "max_agents" => 10,
      "features" => %{"wallet_onboarding" => true, "solana_attestation" => true}
    }

    Accounts.register_organization_owner(user_params, org_attrs, wallet_attrs)
  end

  defp verified_wallet_attrs(%{
         "wallet_address" => wallet_address,
         "wallet_provider" => provider,
         "wallet_message" => message,
         "wallet_signature" => signature
       })
       when wallet_address != "" and message != "" and signature != "" do
    with {:ok, verified} <- WalletAuth.verify_and_consume(wallet_address, message, signature, provider) do
      {:ok,
       %{
         "chain" => verified.chain,
         "wallet_address" => verified.wallet_address,
         "provider" => verified.provider,
         "verified_at" => DateTime.utc_now()
       }}
    end
  end

  defp verified_wallet_attrs(_), do: {:ok, nil}

  defp verify_wallet_params(params) do
    WalletAuth.verify_and_consume(
      params["wallet_address"],
      params["message"],
      params["signature"],
      params["provider"] || "unknown"
    )
  end

  defp log_wallet_event(_user, nil, _event_type, _conn), do: :ok

  defp log_wallet_event(user, wallet, event_type, conn) do
    Accounts.log_wallet_auth_event(%{
      "user_id" => user.id,
      "wallet_address" => wallet_value(wallet, :wallet_address),
      "provider" => wallet_value(wallet, :provider),
      "event_type" => event_type,
      "ip_address" => get_client_ip(conn),
      "user_agent" => get_user_agent(conn)
    })
  end

  defp wallet_value(wallet, key) when is_map(wallet) do
    Map.get(wallet, key) || Map.get(wallet, to_string(key))
  end

  defp log_unlinked_wallet_event(params, conn) do
    if params["wallet_address"] do
      Accounts.log_wallet_auth_event(%{
        "wallet_address" => params["wallet_address"],
        "provider" => params["provider"] || "unknown",
        "event_type" => params["event_type"],
        "ip_address" => get_client_ip(conn),
        "user_agent" => get_user_agent(conn)
      })
    end
  end

  defp unique_slug(name) do
    base =
      name
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")
      |> case do
        "" -> "workspace"
        slug -> String.slice(slug, 0, 40)
      end

    "#{base}-#{:crypto.strong_rand_bytes(3) |> Base.encode16(case: :lower)}"
  end

  defp humanize_wallet_error(:password_confirmation_mismatch), do: "Password confirmation does not match."
  defp humanize_wallet_error(:invalid_wallet_address), do: "Invalid Solana wallet address."
  defp humanize_wallet_error(:invalid_wallet_provider), do: "Unsupported wallet provider."
  defp humanize_wallet_error(:challenge_not_found), do: "Wallet challenge expired. Please reconnect your wallet."
  defp humanize_wallet_error(:challenge_expired), do: "Wallet challenge expired. Please reconnect your wallet."
  defp humanize_wallet_error(:invalid_signature), do: "Wallet signature could not be verified."
  defp humanize_wallet_error(:signature_verification_unavailable), do: "Wallet verification is unavailable on this server."
  defp humanize_wallet_error(reason), do: "Wallet authentication failed: #{inspect(reason)}"
end
