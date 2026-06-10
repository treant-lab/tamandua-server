# Lab Light Bootstrap Script
#
# REQUIRED ENVIRONMENT VARIABLES:
#   LAB_LIGHT_ADMIN_EMAIL    - Admin user email
#   LAB_LIGHT_ADMIN_PASSWORD - Admin password (min 12 chars)
#
# OPTIONAL:
#   LAB_LIGHT_ORG_SLUG       - Organization slug (default: tamandua-lab)
#   LAB_LIGHT_ORG_NAME       - Organization name (default: Tamandua Lab)
#   LAB_LIGHT_ANALYST_EMAIL  - Analyst email
#   LAB_LIGHT_ANALYST_PASSWORD - Analyst password

alias TamanduaServer.Repo
alias TamanduaServer.Accounts
alias TamanduaServer.Accounts.{Organization, User}

# Require admin credentials
admin_email = System.get_env("LAB_LIGHT_ADMIN_EMAIL")
admin_password = System.get_env("LAB_LIGHT_ADMIN_PASSWORD")

if is_nil(admin_email) or is_nil(admin_password) do
  IO.puts("""
  ERROR: Missing required environment variables.

  Please set:
    LAB_LIGHT_ADMIN_EMAIL=your@email.com
    LAB_LIGHT_ADMIN_PASSWORD=your_secure_password

  Example:
    LAB_LIGHT_ADMIN_EMAIL=admin@mycompany.com \\
    LAB_LIGHT_ADMIN_PASSWORD=SuperSecure123! \\
    mix run priv/repo/scripts/lab_light_bootstrap.exs
  """)
  System.halt(1)
end

if String.length(admin_password) < 12 do
  IO.puts("ERROR: LAB_LIGHT_ADMIN_PASSWORD must be at least 12 characters")
  System.halt(1)
end

lab_org_slug = System.get_env("LAB_LIGHT_ORG_SLUG", "tamandua-lab")
lab_org_name = System.get_env("LAB_LIGHT_ORG_NAME", "Tamandua Lab")

# Build user list - admin is required
users = [
  %{
    email: admin_email,
    password: admin_password,
    role: "admin",
    name: "Lab Administrator"
  }
]

# Optional analyst
analyst_email = System.get_env("LAB_LIGHT_ANALYST_EMAIL")
analyst_password = System.get_env("LAB_LIGHT_ANALYST_PASSWORD")

users =
  if analyst_email && analyst_password && String.length(analyst_password) >= 12 do
    users ++ [%{
      email: analyst_email,
      password: analyst_password,
      role: "analyst",
      name: "Lab Analyst"
    }]
  else
    users
  end

# Create organization
organization =
  case Repo.get_by(Organization, slug: lab_org_slug) do
    nil ->
      {:ok, org} =
        Accounts.create_organization(%{
          name: lab_org_name,
          slug: lab_org_slug,
          license_tier: :enterprise,
          region: :us,
          features: Organization.default_features(:enterprise)
        })

      IO.puts("Created lab organization: #{org.slug}")
      org

    org ->
      IO.puts("Lab organization already exists: #{org.slug}")
      org
  end

# Create users
Enum.each(users, fn attrs ->
  case Repo.get_by(User, email: attrs.email) do
    nil ->
      %User{}
      |> User.registration_changeset(Map.put(attrs, :organization_id, organization.id))
      |> Repo.insert!()

      IO.puts("Created user: #{attrs.email} (role: #{attrs.role})")

    _user ->
      IO.puts("User already exists: #{attrs.email}")
  end
end)

IO.puts("\nLab Light bootstrap complete!")
