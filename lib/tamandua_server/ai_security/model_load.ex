defmodule TamanduaServer.AISecurity.ModelLoad do
  @moduledoc """
  Schema for AI model load detection events.

  Tracks when processes load AI/ML models, including metadata extraction
  and correlation with process context. Events are received from agents
  and persisted for analysis and alerting.

  ## Fields

  ### Process Context
  - `process_pid` - Process ID that loaded the model
  - `process_name` - Name of the process (e.g., "python", "ollama")
  - `process_path` - Full path to the executable
  - `process_cmdline` - Command line arguments
  - `process_user` - User running the process

  ### Model Info
  - `model_path` - Full path to the model file
  - `model_filename` - File name only
  - `model_format` - Detected format (gguf, safetensors, pytorch, onnx, tensorflow, unknown)
  - `model_size_bytes` - File size in bytes
  - `model_hash_sha256` - SHA-256 hash of the model file

  ### Extracted Metadata
  - `architecture` - Model architecture (llama, mistral, gpt2, bert, etc.)
  - `parameters` - Parameter count as human-readable string (7B, 13B, 70B)
  - `quantization` - Quantization type (Q4_K_M, Q8_0, FP16, BF16)

  ### Loading Context
  - `loading_method` - How the model was loaded (file_read, mmap, network)
  - `libraries_loaded` - ML libraries loaded by the process
  - `risk_indicators` - Detected risk indicators (elevated_privileges, etc.)

  ## Example

      iex> ModelLoad.changeset(%ModelLoad{}, %{
      ...>   agent_id: "uuid-here",
      ...>   process_pid: 1234,
      ...>   process_name: "python",
      ...>   model_path: "/models/llama-7b.gguf",
      ...>   model_filename: "llama-7b.gguf",
      ...>   model_format: "gguf",
      ...>   event_timestamp: DateTime.utc_now()
      ...> })
      #Ecto.Changeset<...>
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_formats ~w(gguf safetensors pytorch onnx tensorflow unknown)
  @valid_loading_methods ~w(file_read mmap network)

  schema "model_loads" do
    belongs_to :agent, Agent

    # Process context
    field :process_pid, :integer
    field :process_name, :string
    field :process_path, :string
    field :process_cmdline, :string
    field :process_user, :string

    # Model info
    field :model_path, :string
    field :model_filename, :string
    field :model_format, :string
    field :model_size_bytes, :integer
    field :model_hash_sha256, :string

    # Metadata
    field :architecture, :string
    field :parameters, :string
    field :quantization, :string

    # Loading context
    field :loading_method, :string, default: "file_read"
    field :libraries_loaded, {:array, :string}, default: []
    field :risk_indicators, {:array, :string}, default: []

    # Event timestamp
    field :event_timestamp, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(agent_id process_pid process_name model_path model_filename model_format event_timestamp)a
  @optional_fields ~w(process_path process_cmdline process_user model_size_bytes model_hash_sha256 architecture parameters quantization loading_method libraries_loaded risk_indicators)a

  @doc """
  Creates a changeset for inserting or updating a model load event.
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(model_load, attrs) do
    model_load
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:model_format, @valid_formats)
    |> validate_inclusion(:loading_method, @valid_loading_methods)
    |> validate_number(:model_size_bytes, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:agent_id)
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    agent_id: binary() | nil,
    process_pid: integer() | nil,
    process_name: String.t() | nil,
    process_path: String.t() | nil,
    process_cmdline: String.t() | nil,
    process_user: String.t() | nil,
    model_path: String.t() | nil,
    model_filename: String.t() | nil,
    model_format: String.t() | nil,
    model_size_bytes: integer() | nil,
    model_hash_sha256: String.t() | nil,
    architecture: String.t() | nil,
    parameters: String.t() | nil,
    quantization: String.t() | nil,
    loading_method: String.t() | nil,
    libraries_loaded: [String.t()],
    risk_indicators: [String.t()],
    event_timestamp: DateTime.t() | nil,
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }
end
