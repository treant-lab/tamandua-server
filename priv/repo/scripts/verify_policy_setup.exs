# Verification script for policy management setup
# Run with: mix run priv/repo/scripts/verify_policy_setup.exs

alias TamanduaServer.Repo
alias TamanduaServer.Agents.{
  Policy,
  PolicyGroupAssignment,
  PolicyAssignment,
  PolicyDeployment,
  PolicyDeploymentResult,
  PolicyHistory
}

IO.puts("\n=== Tamandua Policy Management Setup Verification ===\n")

# Check if tables exist
tables = [
  {"agent_policies", Policy},
  {"agent_policy_group_assignments", PolicyGroupAssignment},
  {"agent_policy_assignments", PolicyAssignment},
  {"agent_policy_deployments", PolicyDeployment},
  {"agent_policy_deployment_results", PolicyDeploymentResult},
  {"agent_policy_history", PolicyHistory}
]

IO.puts("Checking database tables...")
Enum.each(tables, fn {table_name, schema} ->
  try do
    count = Repo.aggregate(schema, :count)
    IO.puts("  ✓ #{table_name}: OK (#{count} records)")
  rescue
    _ ->
      IO.puts("  ✗ #{table_name}: MISSING - Run migrations!")
  end
end)

# Check templates
IO.puts("\nChecking policy templates...")
template_dir = Path.join([File.cwd!(), "priv", "policy_templates"])

if File.dir?(template_dir) do
  templates = File.ls!(template_dir)
  IO.puts("  ✓ Template directory exists")
  Enum.each(templates, fn template ->
    IO.puts("    - #{template}")
  end)
else
  IO.puts("  ✗ Template directory missing")
end

# Check if Oban queue is configured
IO.puts("\nChecking Oban configuration...")
oban_config = Application.get_env(:tamandua_server, Oban)

if oban_config do
  queues = Keyword.get(oban_config, :queues, [])

  if Keyword.has_key?(queues, :policy_deployments) do
    IO.puts("  ✓ Policy deployment queue configured")
  else
    IO.puts("  ⚠ Policy deployment queue not configured")
    IO.puts("    Add to config.exs: queues: [policy_deployments: 10]")
  end
else
  IO.puts("  ⚠ Oban not configured")
end

# Test basic operations
IO.puts("\nTesting basic operations...")

# Check if we can query organizations
try do
  org_count = Repo.aggregate(TamanduaServer.Accounts.Organization, :count)
  IO.puts("  ✓ Organizations table accessible (#{org_count} orgs)")

  if org_count == 0 do
    IO.puts("    ⚠ No organizations found - create one to use policies")
  end
rescue
  error ->
    IO.puts("  ✗ Error accessing organizations: #{inspect(error)}")
end

# Check if we can query users
try do
  user_count = Repo.aggregate(TamanduaServer.Accounts.User, :count)
  IO.puts("  ✓ Users table accessible (#{user_count} users)")

  if user_count == 0 do
    IO.puts("    ⚠ No users found - create one to manage policies")
  end
rescue
  error ->
    IO.puts("  ✗ Error accessing users: #{inspect(error)}")
end

# Check if we can query agents
try do
  agent_count = Repo.aggregate(TamanduaServer.Agents.Agent, :count)
  IO.puts("  ✓ Agents table accessible (#{agent_count} agents)")

  if agent_count == 0 do
    IO.puts("    ⚠ No agents found - connect agents to deploy policies")
  end
rescue
  error ->
    IO.puts("  ✗ Error accessing agents: #{inspect(error)}")
end

IO.puts("\n=== Verification Complete ===\n")

IO.puts("Next steps:")
IO.puts("  1. Ensure migrations are applied: mix ecto.migrate")
IO.puts("  2. Create an organization if needed")
IO.puts("  3. Create a user account")
IO.puts("  4. Connect at least one agent")
IO.puts("  5. Access policy management UI at /policies")
IO.puts("  6. See docs/POLICY_QUICK_START.md for usage guide\n")
