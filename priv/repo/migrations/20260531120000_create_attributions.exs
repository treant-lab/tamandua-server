defmodule TamanduaServer.Repo.Migrations.CreateAttributions do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:attributions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:primary_actor, :string)
      add(:confidence, :float)
      add(:alternative_actors, {:array, :map}, default: [], null: false)
      add(:explanation, :text)
      add(:feature_contributions, :map, default: %{}, null: false)
      add(:mitre_techniques, {:array, :string}, default: [], null: false)
      add(:mitre_tactics, {:array, :string}, default: [], null: false)
      add(:iocs, {:array, :map}, default: [], null: false)
      add(:campaign_id, :string)
      add(:attack_patterns, {:array, :string}, default: [], null: false)
      add(:source, :string, default: "ml")
      add(:validated, :boolean, default: false, null: false)
      add(:validated_by_id, :binary_id)
      add(:validated_at, :utc_datetime)
      add(:analyst_notes, :text)

      add(:alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all))

      # `events` is a Timescale hypertable; a standard FK is not portable there.
      # `tenants` has no backing table (the association is resolved logically).
      add(:event_id, :binary_id)
      add(:tenant_id, :binary_id)

      timestamps()
    end

    create_if_not_exists(index(:attributions, [:alert_id]))
    create_if_not_exists(index(:attributions, [:event_id]))
    create_if_not_exists(index(:attributions, [:tenant_id]))
    create_if_not_exists(index(:attributions, [:primary_actor]))
    create_if_not_exists(index(:attributions, [:campaign_id]))
  end
end
