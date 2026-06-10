defmodule TamanduaServer.Detection.AttackChain do
  @moduledoc """
  Ecto schema for attack chain definitions.

  Attack chains define multi-step attack sequences based on MITRE ATT&CK techniques
  with temporal constraints, thresholds, and correlation conditions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "attack_chains" do
    field :name, :string
    field :description, :string
    field :severity, :string, default: "high"
    field :enabled, :boolean, default: true

    # Chain definition (YAML serialized)
    field :definition, :map

    # Metadata
    field :author, :string
    field :version, :string, default: "1.0"
    field :tags, {:array, :string}, default: []

    # Testing mode (dry run - log but don't alert)
    field :test_mode, :boolean, default: false

    # Statistics
    field :trigger_count, :integer, default: 0
    field :false_positive_count, :integer, default: 0
    field :last_triggered_at, :utc_datetime_usec

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(chain, attrs) do
    chain
    |> cast(attrs, [
      :name,
      :description,
      :severity,
      :enabled,
      :definition,
      :author,
      :version,
      :tags,
      :test_mode,
      :trigger_count,
      :false_positive_count,
      :last_triggered_at,
      :organization_id
    ])
    |> validate_required([:name, :definition])
    |> validate_inclusion(:severity, ~w(critical high medium low info))
    |> validate_definition()
    |> unique_constraint(:name, name: :attack_chains_organization_id_name_index)
  end

  defp validate_definition(changeset) do
    case get_change(changeset, :definition) do
      nil ->
        changeset

      definition ->
        case validate_definition_structure(definition) do
          :ok ->
            changeset

          {:error, reason} ->
            add_error(changeset, :definition, "Invalid chain definition: #{reason}")
        end
    end
  end

  defp validate_definition_structure(definition) when is_map(definition) do
    with :ok <- validate_has_steps(definition),
         :ok <- validate_steps_format(definition["steps"] || []) do
      :ok
    end
  end

  defp validate_definition_structure(_), do: {:error, "must be a map"}

  defp validate_has_steps(%{"steps" => steps}) when is_list(steps) and length(steps) > 0,
    do: :ok

  defp validate_has_steps(_), do: {:error, "must have at least one step"}

  defp validate_steps_format(steps) do
    Enum.reduce_while(steps, :ok, fn step, _acc ->
      case validate_step(step) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_step(step) when is_map(step) do
    cond do
      not Map.has_key?(step, "techniques") ->
        {:error, "step missing 'techniques' field"}

      not is_list(step["techniques"]) ->
        {:error, "'techniques' must be an array"}

      true ->
        :ok
    end
  end

  defp validate_step(_), do: {:error, "step must be a map"}

  @doc """
  Parse a YAML chain definition file and return a map.
  """
  def parse_yaml(yaml_content) do
    case YamlElixir.read_from_string(yaml_content) do
      {:ok, data} -> {:ok, data}
      {:error, error} -> {:error, "YAML parse error: #{inspect(error)}"}
    end
  rescue
    e -> {:error, "Failed to parse YAML: #{Exception.message(e)}"}
  end

  @doc """
  Convert chain definition to YAML format.
  """
  def to_yaml(chain) do
    Ymlr.document!(chain.definition)
  rescue
    e -> {:error, "Failed to export YAML: #{Exception.message(e)}"}
  end

  @doc """
  Increment trigger count and update last triggered time.
  """
  def record_trigger(chain) do
    chain
    |> changeset(%{
      trigger_count: chain.trigger_count + 1,
      last_triggered_at: DateTime.utc_now()
    })
  end

  @doc """
  Record a false positive.
  """
  def record_false_positive(chain) do
    chain
    |> changeset(%{false_positive_count: chain.false_positive_count + 1})
  end
end
