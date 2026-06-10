# Seed Hunt Query Templates
# ==========================
#
# This seeds the database with default MITRE ATT&CK based hunt query templates.
# These templates are used in the Threat Hunt page to help analysts quickly
# search for common attack patterns.
#
# Usage:
#   mix run priv/repo/seeds/hunt_templates.exs
#

IO.puts("Seeding MITRE ATT&CK hunt query templates...")

alias TamanduaServer.Hunting.SavedQueries

case SavedQueries.seed_default_templates() do
  {:ok, count} ->
    IO.puts("  Seeded #{count} hunt query templates")
    IO.puts("")

    # Show templates by category
    templates = SavedQueries.templates_by_category()
    IO.puts("Templates by MITRE Tactic:")

    for {category, items} <- templates do
      IO.puts("  - #{category}: #{length(items)} templates")
    end

  {:error, reason} ->
    IO.puts("  ERROR: Failed to seed templates - #{inspect(reason)}")
end

IO.puts("")
IO.puts("Hunt templates seeding complete!")
