defmodule TamanduaServer.Accounts.PlatformOperatorDBPreflightTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Accounts.PlatformOperatorDBPreflight

  defmodule SafeProbe do
    @behaviour PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo), do: {:ok, snapshot()}

    defp snapshot do
      %{
        role: "tamandua_runtime",
        superuser: false,
        bypass_rls: false,
        inherits_roles: false,
        missing_tables: 0,
        owns_table: false,
        member_of_owner: false,
        prohibited_dml: false
      }
    end
  end

  defmodule UnsafeProbe do
    @behaviour PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo) do
      {:ok,
       %{
         role: "tamandua",
         superuser: true,
         bypass_rls: true,
         inherits_roles: true,
         missing_tables: 0,
         owns_table: true,
         member_of_owner: true,
         prohibited_dml: true
       }}
    end
  end

  defmodule MissingTablesProbe do
    @behaviour PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo) do
      {:ok,
       %{
         role: "tamandua_runtime",
         superuser: false,
         bypass_rls: false,
         inherits_roles: false,
         missing_tables: 4,
         owns_table: false,
         member_of_owner: false,
         prohibited_dml: false
       }}
    end
  end

  defmodule FailedProbe do
    @behaviour PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo), do: {:error, :database_unavailable}
  end

  defmodule RaisingProbe do
    @behaviour PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo), do: raise("driver details must not escape")
  end

  test "accepts only a complete role snapshot without dangerous authority" do
    assert :ok = PlatformOperatorDBPreflight.check(:fake_repo, SafeProbe)
  end

  test "blocks superuser, bypassrls, owner membership and prohibited DML" do
    assert {:error, :unsafe_platform_operator_database_role} =
             PlatformOperatorDBPreflight.check(:fake_repo, UnsafeProbe)

    assert PlatformOperatorDBPreflight.unsafe_reasons(elem(UnsafeProbe.inspect_role(nil), 1)) == [
             :superuser,
             :bypass_rls,
             :role_inheritance_enabled,
             :table_owner,
             :member_of_table_owner,
             :prohibited_table_dml
           ]
  end

  test "missing authority tables and probe failures fail closed" do
    assert {:error, :unsafe_platform_operator_database_role} =
             PlatformOperatorDBPreflight.check(:fake_repo, MissingTablesProbe)

    assert {:error, :platform_operator_database_preflight_failed} =
             PlatformOperatorDBPreflight.check(:fake_repo, FailedProbe)

    assert {:error, :platform_operator_database_preflight_failed} =
             PlatformOperatorDBPreflight.check(:fake_repo, RaisingProbe)
  end

  test "source boundary runs preflight before every privileged database operation" do
    authority =
      File.read!(
        Path.expand(
          "../../../lib/tamandua_server/accounts/platform_operator_authority.ex",
          __DIR__
        )
      )

    assert length(Regex.scan(~r/PlatformOperatorDBPreflight\.check\(Repo\)/, authority)) == 5
    assert authority =~ "def approve_grant"
    assert authority =~ "def approve_revoke"
    assert authority =~ "def issue_elevation"
    assert authority =~ "def authorize_external_intent"
    assert authority =~ "def record_external_outcome"

    preflight =
      File.read!(
        Path.expand(
          "../../../lib/tamandua_server/accounts/platform_operator_db_preflight.ex",
          __DIR__
        )
      )

    assert preflight =~ "pg_catalog.pg_has_role"
    assert preflight =~ "pg_catalog.has_table_privilege"
    assert preflight =~ "pg_catalog.has_any_column_privilege"
    assert preflight =~ "'INSERT'"
    assert preflight =~ "'UPDATE'"
    assert preflight =~ "'DELETE'"
    assert preflight =~ "'TRUNCATE'"
    assert preflight =~ "PostgresProbe"
  end
end
