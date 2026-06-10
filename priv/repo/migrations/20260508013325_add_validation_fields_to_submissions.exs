defmodule TamanduaServer.Repo.Migrations.AddValidationFieldsToSubmissions do
  use Ecto.Migration

  def change do
    alter table(:submissions) do
      add :validated_by_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :validated_at, :utc_datetime_usec
      add :rejection_reason, :text
    end

    create index(:submissions, [:validated_by_id])
  end
end
