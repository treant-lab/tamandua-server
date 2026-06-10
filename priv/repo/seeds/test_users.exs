# Test users seed for E2E tests
# Run with: mix run priv/repo/seeds/test_users.exs
#
# REQUIRED ENVIRONMENT VARIABLES:
#   TAMANDUA_ADMIN_EMAIL    - Admin user email
#   TAMANDUA_ADMIN_PASSWORD - Admin user password (min 12 chars)
#   TAMANDUA_ANALYST_EMAIL  - Analyst user email (optional)
#   TAMANDUA_ANALYST_PASSWORD - Analyst password (optional)

alias TamanduaServer.Repo
alias TamanduaServer.Accounts.User

# Only run in dev/test environments
if Mix.env() in [:dev, :test] do
  # Require admin credentials from environment
  admin_email = System.get_env("TAMANDUA_ADMIN_EMAIL")
  admin_password = System.get_env("TAMANDUA_ADMIN_PASSWORD")

  if is_nil(admin_email) or is_nil(admin_password) do
    IO.puts("""
    ERROR: Missing required environment variables.

    Please set:
      TAMANDUA_ADMIN_EMAIL=your@email.com
      TAMANDUA_ADMIN_PASSWORD=your_secure_password

    Example:
      TAMANDUA_ADMIN_EMAIL=admin@example.com \\
      TAMANDUA_ADMIN_PASSWORD=MySecurePass123! \\
      mix run priv/repo/seeds/test_users.exs
    """)
    System.halt(1)
  end

  if String.length(admin_password) < 12 do
    IO.puts("ERROR: Password must be at least 12 characters")
    System.halt(1)
  end

  IO.puts("Creating users from environment variables...")

  test_users = [
    %{
      name: "Admin User",
      email: admin_email,
      password: admin_password,
      role: "admin"
    }
  ]

  # Optional analyst user
  analyst_email = System.get_env("TAMANDUA_ANALYST_EMAIL")
  analyst_password = System.get_env("TAMANDUA_ANALYST_PASSWORD")

  test_users =
    if analyst_email && analyst_password do
      test_users ++ [%{
        name: "Security Analyst",
        email: analyst_email,
        password: analyst_password,
        role: "analyst"
      }]
    else
      test_users
    end

  for user_attrs <- test_users do
    case Repo.get_by(User, email: user_attrs.email) do
      nil ->
        %User{}
        |> User.registration_changeset(user_attrs)
        |> Repo.insert!()
        IO.puts("  Created user: #{user_attrs.email} (role: #{user_attrs.role})")

      _existing ->
        IO.puts("  User already exists: #{user_attrs.email}")
    end
  end

  IO.puts("Done!")
else
  IO.puts("Skipping test user creation - not in dev/test environment")
end
