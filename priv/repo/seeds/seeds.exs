# Master Seed File for Tamandua EDR
# ===================================
#
# This file orchestrates the execution of all seed files in the correct order
# to populate the database with comprehensive demo data.
#
# Usage:
#   mix run priv/repo/seeds/seeds.exs
#
# Or to seed only specific components:
#   mix run priv/repo/seeds/playbooks.exs
#   mix run priv/repo/seeds/iocs.exs
#   etc.
#
# Environment:
#   These seeds are designed for development and demo environments.
#   DO NOT run in production without review.

IO.puts("""

================================================================================
  _____                               _
 |_   _|_ _ _ __ ___   __ _ _ __   __| |_   _  __ _
   | |/ _` | '_ ` _ \\ / _` | '_ \\ / _` | | | |/ _` |
   | | (_| | | | | | | (_| | | | | (_| | |_| | (_| |
   |_|\\__,_|_| |_| |_|\\__,_|_| |_|\\__,_|\\__,_|\\__,_|

                    EDR Platform Seed Data
================================================================================
""")

IO.puts("Starting comprehensive seed process...")
IO.puts("Environment: #{Mix.env()}")
IO.puts("")

# Ensure we're not in production
if Mix.env() == :prod do
  IO.puts("""
  WARNING: Running seeds in production environment!

  These seeds contain demo data and should only be used for:
  - Development environments
  - Demo/staging environments
  - Initial setup with test data

  Press Ctrl+C to abort, or wait 10 seconds to continue...
  """)
  Process.sleep(10_000)
end

# Track execution time
start_time = System.monotonic_time(:millisecond)

# Define seed files in execution order
seed_files = [
  # 1. Base data - Organizations and Users
  {"test_users.exs", "Creating organizations and test users"},

  # 2. Endpoint Agents - Required by alerts
  {"sample_agents.exs", "Creating sample endpoint agents"},

  # 3. Detection Content
  {"iocs.exs", "Loading Indicators of Compromise (IOCs)"},
  {"sigma_rules.exs", "Loading Sigma detection rules"},

  # 4. Response Automation
  {"playbooks.exs", "Creating incident response playbooks"},
  {"remediation_policies.exs", "Creating default remediation policies"},
  {"remediation_notification_templates.exs", "Creating remediation notification templates"},

  # 5. Threat Intelligence Configuration
  {"threat_intel_feeds.exs", "Configuring threat intelligence feeds"},

  # 6. MITRE ATT&CK Mapping
  {"mitre_coverage.exs", "Loading MITRE ATT&CK coverage data"},

  # 7. Hunt Query Templates
  {"hunt_templates.exs", "Loading MITRE ATT&CK hunt query templates"},

  # 8. Sample Alerts - Depends on agents and org
  {"sample_alerts.exs", "Creating sample security alerts"}
]

# Base path for seed files
base_path = Path.dirname(__ENV__.file)

# Execute each seed file
results = Enum.map(seed_files, fn {file, description} ->
  IO.puts("")
  IO.puts(String.duplicate("-", 70))
  IO.puts("#{description}...")
  IO.puts(String.duplicate("-", 70))

  file_path = Path.join(base_path, file)

  if File.exists?(file_path) do
    try do
      {time, _result} = :timer.tc(fn ->
        Code.eval_file(file_path)
      end)

      {:ok, file, time / 1_000_000}
    rescue
      e ->
        IO.puts("ERROR: Failed to execute #{file}")
        IO.puts("  #{Exception.message(e)}")
        {:error, file, Exception.message(e)}
    end
  else
    IO.puts("WARNING: Seed file not found: #{file_path}")
    {:skip, file, "File not found"}
  end
end)

# Calculate total time
end_time = System.monotonic_time(:millisecond)
total_time = (end_time - start_time) / 1000

# Print summary
IO.puts("")
IO.puts("")
IO.puts(String.duplicate("=", 70))
IO.puts("SEED EXECUTION SUMMARY")
IO.puts(String.duplicate("=", 70))

successful = Enum.filter(results, fn {status, _, _} -> status == :ok end)
failed = Enum.filter(results, fn {status, _, _} -> status == :error end)
skipped = Enum.filter(results, fn {status, _, _} -> status == :skip end)

IO.puts("")
IO.puts("Results:")
for {status, file, detail} <- results do
  case status do
    :ok ->
      IO.puts("  [OK]    #{file} (#{Float.round(detail, 2)}s)")
    :error ->
      IO.puts("  [FAIL]  #{file}: #{detail}")
    :skip ->
      IO.puts("  [SKIP]  #{file}: #{detail}")
  end
end

IO.puts("")
IO.puts("Statistics:")
IO.puts("  Successful: #{length(successful)}")
IO.puts("  Failed:     #{length(failed)}")
IO.puts("  Skipped:    #{length(skipped)}")
IO.puts("  Total Time: #{Float.round(total_time, 2)} seconds")

# Print what was seeded
IO.puts("")
IO.puts("Data Summary:")
IO.puts("  - Organizations and Users: Created demo organization with admin/analyst/viewer users")
IO.puts("  - Endpoint Agents: ~55 agents (Windows, Linux, macOS workstations and servers)")
IO.puts("  - IOCs: ~60 indicators (malware hashes, C2 IPs/domains, phishing URLs)")
IO.puts("  - Sigma Rules: ~25 detection rules covering major MITRE techniques")
IO.puts("  - Playbooks: 17 incident response playbooks (ransomware, phishing, APT, etc.)")
IO.puts("  - Remediation Policies: 4 default policies (auto-quarantine, manual approval, blocking)")
IO.puts("  - Notification Templates: 12 templates for remediation notifications (email + Slack + Discord)")
IO.puts("  - Threat Intel Feeds: 25 feed configurations (OTX, abuse.ch, CISA KEV, etc.)")
IO.puts("  - MITRE Coverage: Full ATT&CK matrix mapping with detection capabilities")
IO.puts("  - Hunt Templates: ~60 MITRE ATT&CK based query templates for threat hunting")
IO.puts("  - Sample Alerts: ~20 realistic alerts across all severity levels")

if length(failed) > 0 do
  IO.puts("")
  IO.puts("WARNING: Some seeds failed to execute. Review errors above.")
  System.halt(1)
end

IO.puts("")
IO.puts(String.duplicate("=", 70))
IO.puts("Seed execution complete!")
IO.puts(String.duplicate("=", 70))

IO.puts("""

Next Steps:
-----------
1. Create admin user (if not done):
   TAMANDUA_ADMIN_EMAIL=your@email.com \\
   TAMANDUA_ADMIN_PASSWORD=YourSecurePass123! \\
   mix run priv/repo/seeds/test_users.exs

2. Start the Phoenix server:
   cd apps/tamandua_server && mix phx.server

3. Access the dashboard:
   http://localhost:4000

4. Login with the credentials you configured above.

5. Explore the platform:
   - Dashboard: View alerts and agent status
   - Agents: Browse endpoint inventory
   - Alerts: Investigate security alerts
   - Detection: Manage Sigma rules and IOCs
   - Response: Execute and manage playbooks
   - MITRE: View ATT&CK coverage matrix
   - Threat Intel: Configure intelligence feeds

Documentation:
--------------
See CLAUDE.md for development instructions and architecture overview.

""")
