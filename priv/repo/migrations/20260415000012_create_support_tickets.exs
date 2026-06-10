defmodule TamanduaServer.Repo.Migrations.CreateSupportTickets do
  use Ecto.Migration

  def change do
    create table(:support_tickets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assigned_to_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      add :subject, :string, null: false
      add :description, :text
      add :priority, :string, null: false, default: "p3"  # p1, p2, p3, p4
      add :status, :string, null: false, default: "open"  # open, in_progress, pending_customer, resolved, closed
      add :category, :string  # license, security, performance, feature_request, other

      # SLA tracking
      add :response_deadline, :utc_datetime
      add :resolution_deadline, :utc_datetime
      add :first_response_at, :utc_datetime
      add :resolved_at, :utc_datetime
      add :response_sla_breached, :boolean, default: false
      add :resolution_sla_breached, :boolean, default: false

      # Escalation tracking
      add :escalation_level, :integer, default: 0
      add :escalated_at, :utc_datetime
      add :escalation_reason, :string

      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create index(:support_tickets, [:organization_id])
    create index(:support_tickets, [:priority, :status])
    create index(:support_tickets, [:response_deadline])
    create index(:support_tickets, [:assigned_to_id])

    # RLS policy
    execute """
    ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;
    """, """
    ALTER TABLE support_tickets DISABLE ROW LEVEL SECURITY;
    """

    execute """
    CREATE POLICY support_tickets_isolation_policy ON support_tickets
      USING (
        COALESCE(current_setting('app.rls_bypass', TRUE)::BOOLEAN, FALSE) = TRUE
        OR organization_id::text = current_setting('app.current_organization_id', TRUE)
      );
    """, """
    DROP POLICY IF EXISTS support_tickets_isolation_policy ON support_tickets;
    """
  end
end
