defmodule TamanduaServer.Repo.Migrations.CreateModelLoads do
  use Ecto.Migration

  def change do
    create table(:model_loads, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Process context
      add :process_pid, :integer, null: false
      add :process_name, :string, null: false
      add :process_path, :string
      add :process_cmdline, :text
      add :process_user, :string

      # Model info
      add :model_path, :string, null: false
      add :model_filename, :string, null: false
      add :model_format, :string, null: false  # gguf, safetensors, pytorch, onnx, unknown
      add :model_size_bytes, :bigint
      add :model_hash_sha256, :string

      # Metadata (from GGUF/SafeTensors parsing)
      add :architecture, :string      # llama, mistral, gpt2, bert
      add :parameters, :string        # 7B, 13B, 70B
      add :quantization, :string      # Q4_K_M, Q8_0, FP16

      # Loading context
      add :loading_method, :string, default: "file_read"  # file_read, mmap, network
      add :libraries_loaded, {:array, :string}, default: []
      add :risk_indicators, {:array, :string}, default: []

      # Event timestamp (from agent)
      add :event_timestamp, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create index(:model_loads, [:agent_id])
    create index(:model_loads, [:model_hash_sha256])
    create index(:model_loads, [:model_format])
    create index(:model_loads, [:architecture])
    create index(:model_loads, [:event_timestamp])
    create index(:model_loads, [:agent_id, :model_path], name: :model_loads_agent_model_idx)
  end
end
