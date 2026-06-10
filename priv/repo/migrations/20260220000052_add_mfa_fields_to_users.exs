defmodule TamanduaServer.Repo.Migrations.AddMfaFieldsToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :mfa_enforced_at, :utc_datetime_usec  # When MFA was enforced for this user
      add :mfa_grace_expires_at, :utc_datetime_usec  # Grace period expiration
    end

    create index(:users, [:mfa_grace_expires_at])
  end
end
