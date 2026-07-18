defmodule TamanduaServer.Repo.Migrations.HardenAutonomousRecommendationClaims do
  use Ecto.Migration

  def up do
    # The table is FORCE RLS. Migrations are trusted system operations and
    # need an explicit transaction-local bypass for cross-tenant normalization.
    execute("SET LOCAL app.rls_bypass = 'true'")

    execute("""
    UPDATE autonomous_recommendations
    SET status = 'auto_executed', updated_at = NOW()
    WHERE status = 'executed'
    """)

    execute("SET LOCAL app.rls_bypass = 'false'")

    create_if_not_exists index(
                           :autonomous_recommendations,
                           [:organization_id, :status, :expires_at],
                           name: :autonomous_recommendations_org_status_expires_idx
                         )
  end

  def down do
    drop_if_exists index(
                     :autonomous_recommendations,
                     [:organization_id, :status, :expires_at],
                     name: :autonomous_recommendations_org_status_expires_idx
                   )
  end
end
