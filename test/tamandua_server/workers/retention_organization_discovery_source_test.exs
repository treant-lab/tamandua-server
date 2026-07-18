defmodule TamanduaServer.Workers.RetentionOrganizationDiscoverySourceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Workers.RetentionOrganizationDiscovery

  @discovery "lib/tamandua_server/workers/retention_organization_discovery.ex"
  @screen_worker "lib/tamandua_server/workers/screen_capture_retention_worker.ex"
  @evidence_worker "lib/tamandua_server/workers/evidence_session_retention_worker.ex"

  test "canonicalizes, sorts, deduplicates, rejects malformed IDs and enforces the bound" do
    ids =
      for number <- 1..1_005 do
        <<number::128>> |> Ecto.UUID.load!()
      end

    uppercase = ids |> hd() |> String.upcase()

    result =
      RetentionOrganizationDiscovery.normalize_organization_ids([
        "malformed",
        uppercase,
        hd(ids) | Enum.reverse(ids)
      ])

    assert length(result) == 1_000
    assert result == Enum.sort(result)
    assert Enum.uniq(result) == result
    assert hd(ids) in result
    refute "malformed" in result
  end

  test "enabled authority success and error are terminal and never fall back" do
    source = File.read!(@discovery)

    assert source =~ "if AuthorityRepo.enabled?() do"
    assert source =~ "discover_with_authority(as_of)"

    assert source =~
             "AuthorityAccess.discover_screen_evidence_retention_due_organization_ids("

    assert source =~ "organization_ids when is_list(organization_ids)"
    assert source =~ "validate_authority_organization_ids(organization_ids)"
    assert source =~ "{:error, :invalid_authority_response}"
    assert source =~ "{:error, reason} when is_atom(reason)"
    assert source =~ "{:error, reason}"
    refute source =~ "AuthorityRepo.query"
    refute source =~ "is_function"
    refute source =~ "apply("
  end

  test "disabled authority fails closed without ordinary repository discovery" do
    source = File.read!(@discovery)

    assert source =~ "@maximum_limit 1_000"
    assert source =~ "emit(:disabled, :error, :authority_repo_disabled)"
    assert source =~ "{:error, :authority_repo_disabled}"
    refute source =~ "Application.get_env"
    refute source =~ "MultiTenant.with_bypass"
    refute source =~ "Repo.all"
    refute source =~ "legacy_discover"
  end

  test "workers keep schedules and mutate only in canonical tenant loops" do
    for path <- [@screen_worker, @evidence_worker] do
      source = File.read!(path)

      assert source =~ "queue: :default"
      assert source =~ "max_attempts: 3"
      assert source =~ "unique: [period: 240]"
      assert source =~ "RetentionOrganizationDiscovery.discover"
      assert source =~ "MultiTenant.with_organization(organization_id, fn ->"
      refute source =~ "MultiTenant.with_bypass"
    end
  end

  test "shared discovery has one fixed authority capability and no arbitrary authority surface" do
    source = File.read!(@discovery)

    assert length(
             Regex.scan(
               ~r/AuthorityAccess\.discover_screen_evidence_retention_due_organization_ids/,
               source
             )
           ) == 1

    refute source =~ "AuthorityRepo.transaction"
    refute source =~ "AuthorityRepo.query"
    refute source =~ "authority_callback"
  end
end
