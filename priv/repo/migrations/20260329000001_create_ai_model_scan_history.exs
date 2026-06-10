defmodule TamanduaServer.Repo.Migrations.CreateAIModelScanHistory do
  use Ecto.Migration

  def change do
    create table(:ai_model_scan_history, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :model_id, :string, null: false
      add :agent_id, :string, null: false
      add :file_hash, :string, null: false
      add :scan_status, :string, null: false  # 'safe', 'threats', 'suspicious', 'error'
      add :threat_score, :float
      add :threats, :map, default: %{}
      add :scan_duration_ms, :integer
      add :scanner_version, :string
      add :scanned_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    create index(:ai_model_scan_history, [:model_id, :scanned_at])
    create index(:ai_model_scan_history, [:agent_id])
    create index(:ai_model_scan_history, [:organization_id])
  end
end
