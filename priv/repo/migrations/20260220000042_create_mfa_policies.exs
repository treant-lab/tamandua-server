defmodule TamanduaServer.Repo.Migrations.CreateMfaPolicies do
  use Ecto.Migration

  def change do
    create table(:mfa_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id), null: false
      add :enforcement_mode, :string, default: "optional"  # "optional", "required_all", "required_admins", "required_roles"
      add :required_roles, {:array, :string}, default: []  # Roles that must have MFA
      add :grace_period_days, :integer, default: 7  # Days to enroll after account creation
      add :allowed_methods, {:array, :string}, default: ["totp", "sms", "email", "webauthn"]
      add :require_webauthn_for_admins, :boolean, default: false
      add :trusted_ip_ranges, {:array, :string}, default: []  # CIDR ranges that bypass MFA
      add :step_up_actions, {:array, :string}, default: []  # Actions requiring MFA even if trusted

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:mfa_policies, [:organization_id])
  end
end
