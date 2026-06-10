defmodule TamanduaServer.Repo.Migrations.AddNetworkContainmentToPreventionPolicies do
  use Ecto.Migration

  def change do
    alter table(:prevention_policies) do
      add :network_containment, :map, default: %{"allow_dns" => true, "allowed_ips" => []}
    end
  end
end
