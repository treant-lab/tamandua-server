defmodule TamanduaServer.Repo.Migrations.CreateAIGatewayPersistence do
  use Ecto.Migration

  def change do
    create table(:ai_gateway_events, primary_key: false) do
      add(:id, :string, primary_key: true)
      add(:timestamp_ms, :bigint, null: false)
      add(:observed_at, :utc_datetime_usec, null: false)
      add(:source, :string, null: false)
      add(:integration_id, :string)
      add(:tenant_id, :string)
      add(:organization_id, :string)
      add(:user_id, :string)
      add(:username, :string)
      add(:department, :string)
      add(:app, :string)
      add(:provider, :string)
      add(:model, :string)
      add(:domain, :string)
      add(:access_method, :string)
      add(:agent_id, :string)
      add(:hostname, :string)
      add(:process_name, :string)
      add(:process_path, :text)
      add(:pid, :string)
      add(:request_count, :integer, default: 1, null: false)
      add(:input_tokens, :bigint, default: 0, null: false)
      add(:output_tokens, :bigint, default: 0, null: false)
      add(:total_tokens, :bigint)
      add(:bytes_sent, :bigint, default: 0, null: false)
      add(:bytes_received, :bigint, default: 0, null: false)
      add(:cost_usd, :float)
      add(:policy_id, :string)
      add(:policy_decision, :string)
      add(:policy_reasons, {:array, :string}, default: [], null: false)
      add(:policy_enforced, :boolean, default: false, null: false)
      add(:effective_risk_score, :integer, default: 0, null: false)
      add(:reason, :text)
      add(:risk_level, :string)
      add(:risk_score, :integer, default: 0, null: false)
      add(:data_categories, {:array, :string}, default: [], null: false)
      add(:classification, :string)
      add(:verdict, :string)
      add(:trace_id, :string)
      add(:session_id, :string)
      add(:metadata, :map, default: %{}, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:ai_gateway_events, [:observed_at]))
    create(index(:ai_gateway_events, [:organization_id, :observed_at]))
    create(index(:ai_gateway_events, [:tenant_id, :observed_at]))
    create(index(:ai_gateway_events, [:agent_id, :observed_at]))
    create(index(:ai_gateway_events, [:user_id, :observed_at]))
    create(index(:ai_gateway_events, [:provider, :observed_at]))
    create(index(:ai_gateway_events, [:domain, :observed_at]))
    create(index(:ai_gateway_events, [:policy_decision, :observed_at]))
    create(index(:ai_gateway_events, [:trace_id]))
    create(index(:ai_gateway_events, [:session_id]))

    create table(:ai_gateway_policies, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:policy_id, :string, null: false)
      add(:active, :boolean, default: true, null: false)
      add(:default_decision, :string, null: false)
      add(:enforce_block, :boolean, default: false, null: false)
      add(:allowlist_providers, {:array, :string}, default: [], null: false)
      add(:blocklist_providers, {:array, :string}, default: [], null: false)
      add(:allowlist_domains, {:array, :string}, default: [], null: false)
      add(:blocklist_domains, {:array, :string}, default: [], null: false)
      add(:blocked_data_categories, {:array, :string}, default: [], null: false)
      add(:high_risk_data_categories, {:array, :string}, default: [], null: false)
      add(:max_risk_score_allow, :integer, null: false)
      add(:max_risk_score_monitor, :integer, null: false)
      add(:updated_by, :string)
      add(:policy, :map, default: %{}, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:ai_gateway_policies, [:policy_id],
        where: "active",
        name: :ai_gateway_policies_active_policy_idx
      )
    )

    create(index(:ai_gateway_policies, [:active, :inserted_at]))
    create(index(:ai_gateway_policies, [:updated_by, :inserted_at]))
  end
end
