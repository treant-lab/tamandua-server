defmodule TamanduaServer.Repo.Migrations.CreateAICostTracking do
  use Ecto.Migration

  def up do
    # AI inference cost tracking - individual inference records
    create table(:ai_inference_costs, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all)
      add :model_id, :string, null: false
      add :tokens_in, :integer, null: false
      add :tokens_out, :integer, null: false
      add :cost_usd, :decimal, precision: 12, scale: 6, null: false
      add :latency_ms, :integer
      add :agent_id, :string, null: false
      add :user_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :process_id, :string
      add :team_id, :string
      add :session_id, :string
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Indexes for efficient querying
    create index(:ai_inference_costs, [:organization_id])
    create index(:ai_inference_costs, [:agent_id])
    create index(:ai_inference_costs, [:user_id])
    create index(:ai_inference_costs, [:model_id])
    create index(:ai_inference_costs, [:team_id])
    create index(:ai_inference_costs, [:inserted_at])
    create index(:ai_inference_costs, [:organization_id, :inserted_at])
    create index(:ai_inference_costs, [:agent_id, :inserted_at])
    create index(:ai_inference_costs, [:model_id, :inserted_at])

    # AI cost budgets - spending limits per entity
    create table(:ai_cost_budgets, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all)
      add :entity_type, :string, null: false  # "model", "user", "process", "team", "agent"
      add :entity_id, :string, null: false
      add :name, :string
      add :description, :text

      # Spending limits
      add :daily_usd, :decimal, precision: 12, scale: 2
      add :hourly_usd, :decimal, precision: 12, scale: 2
      add :tokens_per_min, :integer
      add :inferences_per_hour, :integer

      # Alert configuration
      add :alert_thresholds, {:array, :integer}, default: [50, 75, 90, 100]
      add :actions, :map, default: %{
        "50" => "alert",
        "75" => "alert",
        "90" => "throttle",
        "100" => "block"
      }

      # State
      add :active, :boolean, default: true
      add :notified_thresholds, {:array, :integer}, default: []

      add :created_by_id, references(:users, type: :uuid, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create unique_index(:ai_cost_budgets, [:entity_type, :entity_id], name: :ai_cost_budgets_entity_idx)
    create index(:ai_cost_budgets, [:organization_id])
    create index(:ai_cost_budgets, [:entity_type])
    create index(:ai_cost_budgets, [:active])

    # AI cost budget alerts - alert history
    create table(:ai_cost_budget_alerts, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :budget_id, references(:ai_cost_budgets, type: :uuid, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all)
      add :entity_type, :string, null: false
      add :entity_id, :string, null: false
      add :threshold_percent, :integer, null: false
      add :current_usage, :decimal, precision: 12, scale: 4, null: false
      add :limit_value, :decimal, precision: 12, scale: 4, null: false
      add :limit_type, :string, null: false  # "daily_usd", "hourly_usd", "tokens_per_min", "inferences_per_hour"
      add :action_taken, :string, null: false  # "alert", "throttle", "block", "kill_process"
      add :acknowledged, :boolean, default: false
      add :acknowledged_by, references(:users, type: :uuid, on_delete: :nilify_all)
      add :acknowledged_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:ai_cost_budget_alerts, [:budget_id])
    create index(:ai_cost_budget_alerts, [:organization_id])
    create index(:ai_cost_budget_alerts, [:entity_type, :entity_id])
    create index(:ai_cost_budget_alerts, [:acknowledged])
    create index(:ai_cost_budget_alerts, [:inserted_at])

    # Model pricing configuration - configurable per-model pricing
    create table(:ai_model_pricing, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all)
      add :model_id, :string, null: false
      add :model_pattern, :string  # Optional regex pattern for matching model names
      add :input_price_per_million, :decimal, precision: 12, scale: 4, null: false
      add :output_price_per_million, :decimal, precision: 12, scale: 4, null: false
      add :provider, :string  # "openai", "anthropic", "local", etc.
      add :description, :string
      add :active, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:ai_model_pricing, [:organization_id, :model_id], name: :ai_model_pricing_org_model_idx)
    create index(:ai_model_pricing, [:model_id])
    create index(:ai_model_pricing, [:provider])
    create index(:ai_model_pricing, [:active])

    # Insert default model pricing
    execute """
    INSERT INTO ai_model_pricing (id, model_id, input_price_per_million, output_price_per_million, provider, description, active, inserted_at, updated_at)
    VALUES
      (gen_random_uuid(), 'gpt-4', 30.0, 60.0, 'openai', 'OpenAI GPT-4 8K', true, NOW(), NOW()),
      (gen_random_uuid(), 'gpt-4-32k', 60.0, 120.0, 'openai', 'OpenAI GPT-4 32K', true, NOW(), NOW()),
      (gen_random_uuid(), 'gpt-4-turbo', 10.0, 30.0, 'openai', 'OpenAI GPT-4 Turbo', true, NOW(), NOW()),
      (gen_random_uuid(), 'gpt-4o', 5.0, 15.0, 'openai', 'OpenAI GPT-4o', true, NOW(), NOW()),
      (gen_random_uuid(), 'gpt-4o-mini', 0.15, 0.6, 'openai', 'OpenAI GPT-4o Mini', true, NOW(), NOW()),
      (gen_random_uuid(), 'gpt-3.5-turbo', 0.5, 1.5, 'openai', 'OpenAI GPT-3.5 Turbo', true, NOW(), NOW()),
      (gen_random_uuid(), 'o1-preview', 15.0, 60.0, 'openai', 'OpenAI o1-preview', true, NOW(), NOW()),
      (gen_random_uuid(), 'o1-mini', 3.0, 12.0, 'openai', 'OpenAI o1-mini', true, NOW(), NOW()),
      (gen_random_uuid(), 'claude-3-opus', 15.0, 75.0, 'anthropic', 'Anthropic Claude 3 Opus', true, NOW(), NOW()),
      (gen_random_uuid(), 'claude-3-5-sonnet', 3.0, 15.0, 'anthropic', 'Anthropic Claude 3.5 Sonnet', true, NOW(), NOW()),
      (gen_random_uuid(), 'claude-3-sonnet', 3.0, 15.0, 'anthropic', 'Anthropic Claude 3 Sonnet', true, NOW(), NOW()),
      (gen_random_uuid(), 'claude-3-haiku', 0.25, 1.25, 'anthropic', 'Anthropic Claude 3 Haiku', true, NOW(), NOW()),
      (gen_random_uuid(), 'claude-2', 8.0, 24.0, 'anthropic', 'Anthropic Claude 2', true, NOW(), NOW()),
      (gen_random_uuid(), 'llama-3-70b', 0.0, 0.0, 'local', 'Meta Llama 3 70B (local)', true, NOW(), NOW()),
      (gen_random_uuid(), 'llama-3-8b', 0.0, 0.0, 'local', 'Meta Llama 3 8B (local)', true, NOW(), NOW()),
      (gen_random_uuid(), 'mistral-7b', 0.0, 0.0, 'local', 'Mistral 7B (local)', true, NOW(), NOW()),
      (gen_random_uuid(), 'mixtral-8x7b', 0.0, 0.0, 'local', 'Mixtral 8x7B (local)', true, NOW(), NOW()),
      (gen_random_uuid(), 'default', 1.0, 3.0, 'unknown', 'Default pricing for unknown models', true, NOW(), NOW())
    """

    # Daily cost aggregation view for efficient dashboard queries
    execute """
    CREATE OR REPLACE VIEW ai_daily_costs AS
    SELECT
      DATE(inserted_at) AS date,
      organization_id,
      model_id,
      agent_id,
      user_id,
      team_id,
      COUNT(*) AS inference_count,
      SUM(tokens_in) AS total_tokens_in,
      SUM(tokens_out) AS total_tokens_out,
      SUM(cost_usd) AS total_cost_usd,
      AVG(latency_ms) AS avg_latency_ms
    FROM ai_inference_costs
    GROUP BY DATE(inserted_at), organization_id, model_id, agent_id, user_id, team_id
    """
  end

  def down do
    execute "DROP VIEW IF EXISTS ai_daily_costs"
    drop table(:ai_model_pricing)
    drop table(:ai_cost_budget_alerts)
    drop table(:ai_cost_budgets)
    drop table(:ai_inference_costs)
  end
end
