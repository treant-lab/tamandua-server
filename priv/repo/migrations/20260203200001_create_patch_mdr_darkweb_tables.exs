defmodule TamanduaServer.Repo.Migrations.CreatePatchMdrDarkwebTables do
  @moduledoc """
  Creates tables for:
  - Patch Management (policies, deployments)
  - Dark Web / Credential Breach Monitoring (watchlist, findings)
  - MDR Delivery Framework (customers, incidents, reports)
  """

  use Ecto.Migration

  def change do
    # ====================================================================
    # PATCH MANAGEMENT
    # ====================================================================

    # -- patch_policies: per-org patch deployment configuration -----------
    create_if_not_exists table(:patch_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :config, :map, null: false, default: %{}
      add :enabled, :boolean, null: false, default: true

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:patch_policies, [:org_id])
    create_if_not_exists index(:patch_policies, [:enabled])

    # -- patch_deployments: deployment execution tracking ------------------
    create_if_not_exists table(:patch_deployments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :status, :string, null: false, default: "pending_approval"
      add :wave, :string
      add :patches, {:array, :map}, default: []
      add :target_agent_ids, {:array, :binary_id}, default: []
      add :completed_agent_ids, {:array, :binary_id}, default: []
      add :failed_agent_ids, {:array, :binary_id}, default: []
      add :canary_agent_ids, {:array, :binary_id}, default: []
      add :canary_passed, :boolean, default: false
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :error_log, {:array, :map}, default: []

      add :policy_id,
          references(:patch_policies, type: :binary_id, on_delete: :nilify_all)

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:patch_deployments, [:org_id])
    create_if_not_exists index(:patch_deployments, [:policy_id])
    create_if_not_exists index(:patch_deployments, [:status])
    create_if_not_exists index(:patch_deployments, [:wave])
    create_if_not_exists index(:patch_deployments, [:started_at])

    # ====================================================================
    # DARK WEB / CREDENTIAL BREACH MONITORING
    # ====================================================================

    # -- dark_web_watchlist: monitored domains, emails, executives --------
    create_if_not_exists table(:dark_web_watchlist, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :watch_type, :string, null: false  # domain | email | executive
      add :identifier, :string, null: false  # email address or domain
      add :label, :string

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:dark_web_watchlist, [:org_id])
    create_if_not_exists index(:dark_web_watchlist, [:watch_type])
    create_if_not_exists unique_index(:dark_web_watchlist, [:org_id, :identifier],
             name: :dark_web_watchlist_org_identifier_idx)

    # -- dark_web_findings: discovered breach/exposure records ------------
    create_if_not_exists table(:dark_web_findings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :source, :string, null: false
      add :breach_name, :string
      add :breach_date, :date
      add :affected_emails, {:array, :string}, default: []
      add :exposed_data_types, {:array, :string}, default: []
      add :severity, :string, null: false, default: "medium"
      add :remediation_status, :string, null: false, default: "new"
      add :raw_data, :map, default: %{}

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:dark_web_findings, [:org_id])
    create_if_not_exists index(:dark_web_findings, [:severity])
    create_if_not_exists index(:dark_web_findings, [:remediation_status])
    create_if_not_exists index(:dark_web_findings, [:breach_name])
    create_if_not_exists index(:dark_web_findings, [:source])

    # ====================================================================
    # MDR (MANAGED DETECTION & RESPONSE)
    # ====================================================================

    # -- mdr_customers: organizations enrolled in MDR service -------------
    create_if_not_exists table(:mdr_customers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :tier, :string, null: false, default: "essential"
      add :config, :map, default: %{}

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists unique_index(:mdr_customers, [:org_id])
    create_if_not_exists index(:mdr_customers, [:tier])

    # -- mdr_incidents: MDR-managed security incidents --------------------
    create_if_not_exists table(:mdr_incidents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :title, :string, null: false
      add :severity, :string, null: false
      add :status, :string, null: false, default: "open"
      add :assigned_analyst, :string
      add :escalation_level, :integer, default: 0
      add :alert_ids, {:array, :binary_id}, default: []
      add :data, :map, default: %{}

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:mdr_incidents, [:org_id])
    create_if_not_exists index(:mdr_incidents, [:status])
    create_if_not_exists index(:mdr_incidents, [:severity])
    create_if_not_exists index(:mdr_incidents, [:assigned_analyst])
    create_if_not_exists index(:mdr_incidents, [:escalation_level])

    # -- mdr_reports: generated MDR executive reports ---------------------
    create_if_not_exists table(:mdr_reports, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :report_type, :string, null: false
      add :period, :string
      add :data, :map, default: %{}

      add :org_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:mdr_reports, [:org_id])
    create_if_not_exists index(:mdr_reports, [:report_type])
    create_if_not_exists index(:mdr_reports, [:period])
  end
end
