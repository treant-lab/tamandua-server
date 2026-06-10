defmodule TamanduaServer.AISecurity.AIAgent do
  @moduledoc """
  Ecto schema for AI agents inventory.

  This schema represents registered AI agents in the organization,
  tracking their metadata, permissions, risk assessment, and approval status.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "ai_agents" do
    field :name, :string
    field :vendor, :string
    field :agent_type, :string
    field :endpoint_url, :string
    field :permissions, :map, default: %{}
    field :risk_score, :float, default: 0.0
    field :approved, :boolean, default: false
    field :owner, :string

    timestamps()
  end

  @doc false
  def changeset(ai_agent, attrs) do
    ai_agent
    |> cast(attrs, [
      :name,
      :vendor,
      :agent_type,
      :endpoint_url,
      :permissions,
      :risk_score,
      :approved,
      :owner
    ])
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:vendor, max: 255)
    |> validate_length(:agent_type, max: 100)
    |> validate_length(:endpoint_url, max: 2048)
    |> validate_length(:owner, max: 255)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_inclusion(:agent_type, ~w(llm chatbot assistant copilot custom))
  end

  @doc """
  Changeset for approval status updates.
  """
  def approval_changeset(ai_agent, attrs) do
    ai_agent
    |> cast(attrs, [:approved])
    |> validate_required([:approved])
  end

  @doc """
  Changeset for updating permissions.
  """
  def permissions_changeset(ai_agent, attrs) do
    ai_agent
    |> cast(attrs, [:permissions])
    |> validate_required([:permissions])
  end

  @doc """
  Changeset for updating risk score.
  """
  def risk_changeset(ai_agent, attrs) do
    ai_agent
    |> cast(attrs, [:risk_score])
    |> validate_required([:risk_score])
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
  end
end
