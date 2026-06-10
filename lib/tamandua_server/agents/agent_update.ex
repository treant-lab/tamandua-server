defmodule TamanduaServer.Agents.AgentUpdate do
  @moduledoc """
  Tracks individual agent update progress within a rollout campaign.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_updates" do
    field :status, :string
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :error_message, :string
    field :previous_version, :string
    field :new_version, :string

    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :rollout, TamanduaServer.Agents.UpgradeCampaign
    belongs_to :update_package, TamanduaServer.Agents.UpdatePackage

    timestamps()
  end

  @doc false
  def changeset(update, attrs) do
    update
    |> cast(attrs, [
      :status,
      :started_at,
      :completed_at,
      :error_message,
      :previous_version,
      :new_version,
      :agent_id,
      :rollout_id,
      :update_package_id
    ])
    |> validate_required([:agent_id, :update_package_id])
    |> validate_inclusion(:status, ["pending", "in_progress", "completed", "failed"])
    |> unique_constraint([:agent_id, :rollout_id], name: :agent_updates_agent_rollout_idx)
  end

  @doc """
  Create agent updates for a rollout.
  """
  @spec create_for_agents(list(binary()), binary(), binary(), binary()) ::
          {:ok, list(__MODULE__.t())} | {:error, any()}
  def create_for_agents(agent_ids, rollout_id, update_package_id, new_version) do
    now = DateTime.utc_now()

    updates =
      Enum.map(agent_ids, fn agent_id ->
        %{
          agent_id: agent_id,
          rollout_id: rollout_id,
          update_package_id: update_package_id,
          new_version: new_version,
          status: "pending",
          inserted_at: now,
          updated_at: now
        }
      end)

    Repo.insert_all(__MODULE__, updates, returning: true)
    |> case do
      {_count, updates} -> {:ok, updates}
      error -> {:error, error}
    end
  end

  @doc """
  Start an agent update.
  """
  @spec start(__MODULE__.t(), String.t()) :: {:ok, __MODULE__.t()} | {:error, Ecto.Changeset.t()}
  def start(%__MODULE__{} = update, previous_version) do
    update
    |> changeset(%{
      status: "in_progress",
      started_at: DateTime.utc_now(),
      previous_version: previous_version
    })
    |> Repo.update()
  end

  @doc """
  Mark update as completed.
  """
  @spec complete(__MODULE__.t()) :: {:ok, __MODULE__.t()} | {:error, Ecto.Changeset.t()}
  def complete(%__MODULE__{} = update) do
    update
    |> changeset(%{status: "completed", completed_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  Mark update as failed.
  """
  @spec fail(__MODULE__.t(), String.t()) :: {:ok, __MODULE__.t()} | {:error, Ecto.Changeset.t()}
  def fail(%__MODULE__{} = update, error_message) do
    update
    |> changeset(%{
      status: "failed",
      completed_at: DateTime.utc_now(),
      error_message: error_message
    })
    |> Repo.update()
  end

  @doc """
  Get updates for a specific rollout.
  """
  @spec get_for_rollout(binary()) :: list(__MODULE__.t())
  def get_for_rollout(rollout_id) do
    __MODULE__
    |> where([u], u.rollout_id == ^rollout_id)
    |> Repo.all()
    |> Repo.preload([:agent, :update_package])
  end

  @doc """
  Get update history for an agent.
  """
  @spec get_history(binary(), keyword()) :: list(__MODULE__.t())
  def get_history(agent_id, opts \\ []) do
    __MODULE__
    |> where([u], u.agent_id == ^agent_id)
    |> order_by([u], desc: u.inserted_at)
    |> limit(^Keyword.get(opts, :limit, 50))
    |> Repo.all()
    |> Repo.preload([:update_package, :rollout])
  end
end
