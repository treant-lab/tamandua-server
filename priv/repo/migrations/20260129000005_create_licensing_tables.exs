defmodule TamanduaServer.Repo.Migrations.CreateLicensingTables do
  use Ecto.Migration

  def change do
    # License keys table
    create_if_not_exists table(:license_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :license_key, :text  # The actual JWT token (encrypted at rest)
      add :tier, :string, null: false  # trial, pro, enterprise, mssp
      add :agent_limit, :integer, null: false
      add :features, {:array, :string}, default: []

      add :issued_at, :utc_datetime_usec
      add :expires_at, :utc_datetime_usec, null: false
      add :activated_at, :utc_datetime_usec
      add :deactivated_at, :utc_datetime_usec

      add :is_active, :boolean, default: true

      # Billing info
      add :billing_cycle, :string  # monthly, annual
      add :auto_renew, :boolean, default: true
      add :payment_method_id, :string

      # Audit
      add :activated_by, :binary_id
      add :activation_ip, :string

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:license_keys, [:organization_id])
    create_if_not_exists index(:license_keys, [:organization_id, :is_active])
    create_if_not_exists index(:license_keys, [:tier])
    create_if_not_exists index(:license_keys, [:expires_at])

    # License usage table for metering
    create_if_not_exists table(:license_usage, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :metric_type, :string, null: false  # agent_checkin, event_ingested, query_executed, etc.
      add :value, :integer, null: false
      add :metadata, :map, default: %{}
      add :recorded_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create_if_not_exists index(:license_usage, [:organization_id])
    create_if_not_exists index(:license_usage, [:organization_id, :metric_type])
    create_if_not_exists index(:license_usage, [:recorded_at])
    create_if_not_exists index(:license_usage, [:organization_id, :recorded_at])

    # Feature licenses table for granular feature control
    create_if_not_exists table(:feature_licenses, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :feature, :string, null: false
      add :enabled, :boolean, default: true
      add :expires_at, :utc_datetime_usec
      add :quota, :integer  # Optional usage quota for the feature
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:feature_licenses, [:organization_id])
    create_if_not_exists unique_index(:feature_licenses, [:organization_id, :feature])
    create_if_not_exists index(:feature_licenses, [:feature])

    # License violations/enforcement log
    create_if_not_exists table(:license_violations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :violation_type, :string, null: false  # agent_limit_exceeded, feature_not_licensed, etc.
      add :attempted_action, :string
      add :details, :map, default: %{}
      add :user_id, :binary_id
      add :resolved, :boolean, default: false
      add :resolved_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:license_violations, [:organization_id])
    create_if_not_exists index(:license_violations, [:organization_id, :resolved])
    create_if_not_exists index(:license_violations, [:violation_type])

    # License billing history
    create_if_not_exists table(:license_billing_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :license_key_id, references(:license_keys, type: :binary_id, on_delete: :nilify_all)

      add :billing_period_start, :utc_datetime_usec, null: false
      add :billing_period_end, :utc_datetime_usec, null: false
      add :amount_cents, :integer, null: false
      add :currency, :string, default: "USD"
      add :status, :string, null: false  # pending, paid, failed, refunded
      add :payment_method, :string
      add :invoice_url, :string
      add :receipt_url, :string
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:license_billing_history, [:organization_id])
    create_if_not_exists index(:license_billing_history, [:license_key_id])
    create_if_not_exists index(:license_billing_history, [:billing_period_start])
    create_if_not_exists index(:license_billing_history, [:status])

    # MSSP sub-licensing table
    create_if_not_exists table(:mssp_sub_licenses, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :parent_organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :child_organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :parent_license_id, references(:license_keys, type: :binary_id, on_delete: :delete_all), null: false

      add :allocated_agents, :integer, null: false
      add :allocated_features, {:array, :string}, default: []
      add :expires_at, :utc_datetime_usec
      add :is_active, :boolean, default: true
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:mssp_sub_licenses, [:parent_organization_id])
    create_if_not_exists index(:mssp_sub_licenses, [:child_organization_id])
    create_if_not_exists unique_index(:mssp_sub_licenses, [:parent_organization_id, :child_organization_id])
  end
end
