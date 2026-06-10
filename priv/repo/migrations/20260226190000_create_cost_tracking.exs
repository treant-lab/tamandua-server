defmodule TamanduaServer.Repo.Migrations.CreateCostTracking do
  use Ecto.Migration

  def up do
    # Cost tracking table - daily cost breakdown by resource type
    create table(:cost_entries, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :date, :date, null: false
      add :resource_type, :string, null: false # "agent", "storage", "network", "ml", "integration"
      add :resource_id, :string # agent_id, integration name, etc.
      add :cost_usd, :decimal, precision: 12, scale: 4, null: false
      add :usage_amount, :decimal, precision: 15, scale: 4 # CPU hours, GB stored, API calls, etc.
      add :usage_unit, :string # "cpu_hours", "gb_stored", "api_calls", etc.
      add :metadata, :map, default: %{} # tags, department, project, etc.

      timestamps(type: :utc_datetime)
    end

    create index(:cost_entries, [:organization_id, :date])
    create index(:cost_entries, [:organization_id, :resource_type])
    create index(:cost_entries, [:organization_id, :resource_id])
    create index(:cost_entries, [:date])

    # Cost allocation tags - for chargeback and cost center assignment
    create table(:cost_tags, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :tag_key, :string, null: false
      add :tag_value, :string, null: false
      add :description, :text

      timestamps(type: :utc_datetime)
    end

    create unique_index(:cost_tags, [:organization_id, :tag_key, :tag_value])

    # Budget configuration
    create table(:cost_budgets, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :name, :string, null: false
      add :budget_type, :string, null: false # "monthly", "quarterly", "annual"
      add :amount_usd, :decimal, precision: 12, scale: 2, null: false
      add :start_date, :date, null: false
      add :end_date, :date
      add :alert_thresholds, {:array, :integer}, default: [50, 75, 90, 100] # percentage thresholds
      add :auto_throttle_enabled, :boolean, default: false
      add :throttle_threshold, :integer, default: 95 # percentage at which to throttle
      add :tags, :map, default: %{} # filter by department, project, etc.
      add :active, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create index(:cost_budgets, [:organization_id])
    create index(:cost_budgets, [:organization_id, :active])

    # Budget alerts
    create table(:cost_budget_alerts, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :budget_id, references(:cost_budgets, type: :uuid, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :threshold_percent, :integer, null: false
      add :current_spend, :decimal, precision: 12, scale: 2, null: false
      add :budget_amount, :decimal, precision: 12, scale: 2, null: false
      add :forecast_overrun, :boolean, default: false
      add :forecast_amount, :decimal, precision: 12, scale: 2
      add :acknowledged, :boolean, default: false
      add :acknowledged_by, references(:users, type: :uuid, on_delete: :nilify_all)
      add :acknowledged_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:cost_budget_alerts, [:budget_id])
    create index(:cost_budget_alerts, [:organization_id, :acknowledged])

    # Cost optimization recommendations
    create table(:cost_recommendations, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :recommendation_type, :string, null: false # "overprovisioned_agent", "excessive_retention", "unused_integration", etc.
      add :severity, :string, null: false # "low", "medium", "high"
      add :title, :string, null: false
      add :description, :text, null: false
      add :resource_type, :string, null: false
      add :resource_id, :string
      add :current_cost_usd, :decimal, precision: 12, scale: 2, null: false
      add :estimated_savings_usd, :decimal, precision: 12, scale: 2, null: false
      add :savings_percent, :decimal, precision: 5, scale: 2
      add :implementation_effort, :string # "one_click", "easy", "moderate", "complex"
      add :action_payload, :map # data needed to implement the recommendation
      add :status, :string, default: "new" # "new", "acknowledged", "implemented", "dismissed"
      add :implemented_by, references(:users, type: :uuid, on_delete: :nilify_all)
      add :implemented_at, :utc_datetime
      add :dismissed_by, references(:users, type: :uuid, on_delete: :nilify_all)
      add :dismissed_at, :utc_datetime
      add :dismissal_reason, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create index(:cost_recommendations, [:organization_id, :status])
    create index(:cost_recommendations, [:organization_id, :recommendation_type])
    create index(:cost_recommendations, [:resource_type, :resource_id])

    # Cost forecasts - predict future costs
    create table(:cost_forecasts, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :forecast_month, :date, null: false # first day of the forecasted month
      add :base_forecast, :decimal, precision: 12, scale: 2, null: false # current trend
      add :growth_10_forecast, :decimal, precision: 12, scale: 2 # 10% growth
      add :growth_25_forecast, :decimal, precision: 12, scale: 2 # 25% growth
      add :growth_50_forecast, :decimal, precision: 12, scale: 2 # 50% growth
      add :seasonal_adjustment, :decimal, precision: 5, scale: 2, default: 0.0
      add :confidence_level, :decimal, precision: 5, scale: 2 # 0.0 to 1.0
      add :forecast_breakdown, :map # breakdown by resource type
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:cost_forecasts, [:organization_id, :forecast_month])
    create index(:cost_forecasts, [:organization_id])

    # Cost allocation rules - automated tagging rules
    create table(:cost_allocation_rules, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :name, :string, null: false
      add :description, :text
      add :priority, :integer, default: 100 # lower = higher priority
      add :match_conditions, :map, null: false # {"resource_type": "agent", "hostname_pattern": "dev-*"}
      add :tags_to_apply, :map, null: false # {"department": "Engineering", "environment": "dev"}
      add :active, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create index(:cost_allocation_rules, [:organization_id, :active])
    create index(:cost_allocation_rules, [:organization_id, :priority])
  end

  def down do
    drop table(:cost_allocation_rules)
    drop table(:cost_forecasts)
    drop table(:cost_recommendations)
    drop table(:cost_budget_alerts)
    drop table(:cost_budgets)
    drop table(:cost_tags)
    drop table(:cost_entries)
  end
end
