defmodule TamanduaServer.NotificationCenter.EscalationPolicy do
  @moduledoc """
  Schema for escalation policies.

  Escalation chain structure:
  [
    %{"user_id" => "uuid", "delay_minutes" => 15},
    %{"user_id" => "uuid", "delay_minutes" => 30},
    ...
  ]
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "escalation_policies" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true

    field :escalation_chain, {:array, :map}, default: []
    field :trigger_conditions, :map, default: %{}

    field :schedule_enabled, :boolean, default: false
    field :schedule, :map

    belongs_to :organization, TamanduaServer.Accounts.Organization

    has_many :instances, TamanduaServer.NotificationCenter.EscalationInstance

    timestamps(type: :utc_datetime)
  end

  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :organization_id,
      :name,
      :description,
      :enabled,
      :escalation_chain,
      :trigger_conditions,
      :schedule_enabled,
      :schedule
    ])
    |> validate_required([:organization_id, :name, :escalation_chain])
    |> validate_escalation_chain()
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_escalation_chain(changeset) do
    case get_field(changeset, :escalation_chain) do
      nil ->
        add_error(changeset, :escalation_chain, "can't be blank")

      [] ->
        add_error(changeset, :escalation_chain, "must have at least one level")

      chain when is_list(chain) ->
        valid? =
          Enum.all?(chain, fn level ->
            is_map(level) and
              Map.has_key?(level, "user_id") and
              Map.has_key?(level, "delay_minutes") and
              is_integer(level["delay_minutes"]) and
              level["delay_minutes"] > 0
          end)

        if valid? do
          changeset
        else
          add_error(
            changeset,
            :escalation_chain,
            "must be a list of maps with user_id and delay_minutes"
          )
        end

      _ ->
        add_error(changeset, :escalation_chain, "must be a list")
    end
  end
end
