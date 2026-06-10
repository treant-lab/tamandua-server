# Policy management seed data
# Run with: mix run priv/repo/seeds/policy_seeds.exs

alias TamanduaServer.Repo
alias TamanduaServer.Accounts.{Organization, User}
alias TamanduaServer.Agents.PolicyManager

IO.puts("\n=== Seeding Policy Management System ===\n")

# Get or create organization
org =
  case Repo.one(from o in Organization, limit: 1) do
    nil ->
      IO.puts("Creating default organization...")

      %Organization{}
      |> Organization.changeset(%{
        name: "Demo Organization",
        slug: "demo-org"
      })
      |> Repo.insert!()

    org ->
      IO.puts("Using existing organization: #{org.name}")
      org
  end

# Get existing user (must be created first via test_users.exs)
user =
  case Repo.one(from u in User, where: u.organization_id == ^org.id, limit: 1) do
    nil ->
      IO.puts("""
      ERROR: No user found in organization.

      Please create a user first:
        TAMANDUA_ADMIN_EMAIL=your@email.com \\
        TAMANDUA_ADMIN_PASSWORD=YourSecurePass! \\
        mix run priv/repo/seeds/test_users.exs
      """)
      System.halt(1)

    user ->
      IO.puts("Using existing user: #{user.email}")
      user
  end

# Create policies from templates
templates = [
  {"baseline", "Corporate Baseline Policy",
   "Standard security policy for all corporate endpoints"},
  {"high_security", "High Security Policy",
   "Enhanced security for critical systems and sensitive data"},
  {"performance", "Performance Optimized Policy", "Lightweight policy for resource-constrained systems"},
  {"forensics", "Forensics Mode Policy", "Maximum data collection for incident response"}
]

IO.puts("\nCreating policies from templates...\n")

Enum.each(templates, fn {template_name, policy_name, description} ->
  case PolicyManager.get_policy_by_name(org.id, policy_name) do
    nil ->
      case PolicyManager.create_from_template(
             org.id,
             template_name,
             %{
               name: policy_name,
               description: description,
               scope: "organization",
               compliance_tags:
                 case template_name do
                   "baseline" -> ["standard", "baseline"]
                   "high_security" -> ["high_security", "pci_dss", "hipaa"]
                   "performance" -> ["performance", "lightweight"]
                   "forensics" -> ["forensics", "incident_response"]
                 end
             },
             user.id
           ) do
        {:ok, policy} ->
          IO.puts("  ✓ Created: #{policy.name} (#{template_name})")

          # Activate baseline policy by default
          if template_name == "baseline" do
            {:ok, _} = PolicyManager.activate_policy(policy, user.id)
            IO.puts("    → Activated as default policy")
          end

        {:error, error} ->
          IO.puts("  ✗ Failed to create #{policy_name}: #{inspect(error)}")
      end

    policy ->
      IO.puts("  ⊙ Already exists: #{policy.name}")
  end
end)

# Create custom example policy
IO.puts("\nCreating custom example policy...\n")

custom_policy_name = "Development Team Policy"

case PolicyManager.get_policy_by_name(org.id, custom_policy_name) do
  nil ->
    case PolicyManager.create_policy(
           %{
             name: custom_policy_name,
             description: "Relaxed policy for development environments",
             organization_id: org.id,
             scope: "group",
             policy_data: %{
               "collectors" => %{
                 "process" => %{"enabled" => true, "interval_ms" => 15000},
                 "file" => %{"enabled" => false, "interval_ms" => 60000},
                 "network" => %{"enabled" => true, "interval_ms" => 30000},
                 "dns" => %{"enabled" => false, "interval_ms" => 60000},
                 "registry" => %{"enabled" => false, "interval_ms" => 120000}
               },
               "resource_limits" => %{
                 "max_cpu_percent" => 5,
                 "max_memory_mb" => 256,
                 "max_disk_mb" => 500
               },
               "detection" => %{
                 "yara_enabled" => false,
                 "sigma_enabled" => true,
                 "ml_enabled" => false
               },
               "response" => %{
                 "allowed_actions" => ["isolate"],
                 "auto_response_enabled" => false,
                 "max_actions_per_hour" => 5
               }
             },
             tags: ["development", "low_priority"],
             metadata: %{
               "created_by_seed" => true,
               "environment" => "development"
             }
           },
           user.id
         ) do
      {:ok, policy} ->
        IO.puts("  ✓ Created: #{policy.name}")

      {:error, error} ->
        IO.puts("  ✗ Failed to create custom policy: #{inspect(error)}")
    end

  policy ->
    IO.puts("  ⊙ Already exists: #{policy.name}")
end

# Summary
IO.puts("\n=== Seed Complete ===\n")

policy_count = Repo.aggregate(TamanduaServer.Agents.Policy, :count)
IO.puts("Total policies: #{policy_count}")

active_count =
  Repo.aggregate(
    from(p in TamanduaServer.Agents.Policy, where: p.status == "active"),
    :count
  )

IO.puts("Active policies: #{active_count}")

IO.puts("\nNext steps:")
IO.puts("  1. Access the policy management UI at /policies")
IO.puts("  2. Review and customize the seeded policies")
IO.puts("  3. Create agent groups for targeted policy assignment")
IO.puts("  4. Deploy policies to your agents")
IO.puts("  5. See docs/POLICY_QUICK_START.md for usage guide\n")
