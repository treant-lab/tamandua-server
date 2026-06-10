defmodule TamanduaServer.AccountsHelpers do
  @moduledoc """
  Helper functions for user account management in dark web monitoring context.

  These functions are used by the BreachResponder for automated actions.
  """

  alias TamanduaServer.Accounts
  alias TamanduaServer.Repo

  @doc """
  Mark a user as requiring password reset on next login.

  This sets a flag that forces password change before the user can access the system.
  """
  def require_password_reset(user) do
    # Update user to require password reset
    user
    |> Accounts.User.changeset(%{
      # You might need to add this field to the users table
      # For now, we'll use is_active as a placeholder
      metadata: Map.put(user.metadata || %{}, "requires_password_reset", true)
    })
    |> Repo.update()
  end

  @doc """
  Disable a user account.

  This prevents the user from logging in until manually re-enabled.
  """
  def disable_user(user) do
    user
    |> Accounts.User.changeset(%{is_active: false})
    |> Repo.update()
  end

  @doc """
  Require MFA for a user on next login.

  This forces the user to set up MFA before they can access the system.
  """
  def require_mfa(user) do
    user
    |> Accounts.User.changeset(%{
      metadata: Map.put(user.metadata || %{}, "requires_mfa_setup", true)
    })
    |> Repo.update()
  end

  @doc """
  List security team users (admins and security analysts).

  Returns users who should be notified of security incidents.
  """
  def list_security_team_users do
    # Get users with security-related roles
    import Ecto.Query

    from(u in Accounts.User,
      where: u.role in ["admin", "analyst", "responder", "compliance_officer"],
      where: u.is_active == true
    )
    |> Repo.all()
  end
end
