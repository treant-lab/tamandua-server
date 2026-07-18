defmodule TamanduaServer.Detection.IOCSnapshotProviderSourceTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.{IOCSnapshotProvider, RuleLoader}

  test "provider validation is exact and legacy remains configured by default" do
    assert {:ok, :legacy} = IOCSnapshotProvider.validate_provider(:legacy)
    assert {:ok, :authority_v1} = IOCSnapshotProvider.validate_provider(:authority_v1)

    assert {:error, :invalid_ioc_snapshot_provider} =
             IOCSnapshotProvider.validate_provider("authority_v1")

    assert Application.get_env(:tamandua_server, :ioc_snapshot_provider) == :legacy
    refute Application.get_env(:tamandua_server, :ioc_snapshot_authority_repo_enabled)

    provider_source =
      File.read!(
        Path.expand("../../../lib/tamandua_server/detection/ioc_snapshot_provider.ex", __DIR__)
      )

    assert provider_source =~ "configured == :authority_v1 and authority_enabled"
    assert provider_source =~ "configured == :legacy and not authority_enabled"
  end

  test "same epoch metadata conflict preserves the active generation" do
    RuleLoader.init_tables()
    epoch = max(RuleLoader.published_ioc_epoch(), 0) + 1
    first_digest = String.duplicate("a", 64)
    second_digest = String.duplicate("b", 64)

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic(
               [first: %{value: "first"}],
               %{authority_epoch: epoch, digest: first_digest, provider: :legacy}
             )

    first = RuleLoader.published_ioc_snapshot()

    assert {:error, :ioc_snapshot_metadata_conflict} =
             RuleLoader.reload_ioc_rules_atomic(
               [second: %{value: "second"}],
               %{authority_epoch: epoch, digest: second_digest, provider: :legacy}
             )

    assert RuleLoader.published_ioc_snapshot() == first
    assert [{:first, %{value: "first"}}] = RuleLoader.read_all(:ioc)
  end

  test "same epoch provider conflict preserves the active generation" do
    epoch = max(RuleLoader.published_ioc_epoch(), 0) + 1
    digest = String.duplicate("c", 64)

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic(
               [legacy: %{value: "legacy"}],
               %{authority_epoch: epoch, digest: digest, provider: :legacy}
             )

    first = RuleLoader.published_ioc_snapshot()

    assert {:error, :ioc_snapshot_metadata_conflict} =
             RuleLoader.reload_ioc_rules_atomic(
               [authority: %{value: "authority"}],
               %{authority_epoch: epoch, digest: digest, provider: :authority_v1}
             )

    assert RuleLoader.published_ioc_snapshot() == first
    assert [{:legacy, %{value: "legacy"}}] = RuleLoader.read_all(:ioc)
  end

  test "legacy API and facade metadata use one digest contract at an equal epoch" do
    epoch = max(RuleLoader.published_ioc_epoch(), 0) + 1
    rules = [legacy: %{value: "same"}]

    assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic(rules, epoch)

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic(rules, %{
               authority_epoch: epoch,
               digest: RuleLoader.ioc_rules_digest(rules),
               provider: :legacy
             })

    assert %{authority_epoch: ^epoch, provider: :legacy} = RuleLoader.published_ioc_snapshot()
    assert rules == RuleLoader.read_all(:ioc)
  end

  test "an unfenced legacy tuple cannot change provider at the same epoch" do
    epoch = max(RuleLoader.published_ioc_epoch(), 0) + 1

    assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic([legacy: %{value: "legacy"}], epoch)
    %{table: table} = RuleLoader.published_ioc_snapshot()
    :ets.insert(:detection_rule_versions, {:ioc, table, epoch})

    assert {:error, :ioc_snapshot_metadata_conflict} =
             RuleLoader.reload_ioc_rules_atomic(
               [authority: %{value: "authority"}],
               %{
                 authority_epoch: epoch,
                 digest: String.duplicate("a", 64),
                 provider: :authority_v1
               }
             )

    assert %{table: ^table, authority_epoch: ^epoch, digest: nil, provider: :legacy} =
             RuleLoader.published_ioc_snapshot()

    assert [{:legacy, %{value: "legacy"}}] = RuleLoader.read_all(:ioc)
  end

  test "an unfenced legacy tuple cannot replace content at the same epoch" do
    epoch = max(RuleLoader.published_ioc_epoch(), 0) + 1

    assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic([legacy: %{value: "legacy"}], epoch)
    %{table: table} = RuleLoader.published_ioc_snapshot()
    :ets.insert(:detection_rule_versions, {:ioc, table, epoch})

    replacement = [replacement: %{value: "replacement"}]

    assert {:error, :ioc_snapshot_metadata_conflict} =
             RuleLoader.reload_ioc_rules_atomic(replacement, %{
               authority_epoch: epoch,
               digest: RuleLoader.ioc_rules_digest(replacement),
               provider: :legacy
             })

    assert %{table: ^table, authority_epoch: ^epoch, digest: nil, provider: :legacy} =
             RuleLoader.published_ioc_snapshot()

    assert [{:legacy, %{value: "legacy"}}] = RuleLoader.read_all(:ioc)
  end

  test "lower epoch is stale and a higher epoch atomically replaces all metadata" do
    RuleLoader.init_tables()
    base_epoch = max(RuleLoader.published_ioc_epoch(), 0) + 2

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic(
               [base: %{value: "base"}],
               %{
                 authority_epoch: base_epoch,
                 digest: String.duplicate("f", 64),
                 provider: :legacy
               }
             )

    current = RuleLoader.published_ioc_snapshot()
    current_epoch = current.authority_epoch

    assert {:stale, ^current_epoch} =
             RuleLoader.reload_ioc_rules_atomic(
               [],
               %{
                 authority_epoch: current.authority_epoch - 1,
                 digest: String.duplicate("d", 64),
                 provider: :legacy
               }
             )

    next_epoch = current.authority_epoch + 1
    next_digest = String.duplicate("e", 64)

    assert {:ok, 1} =
             RuleLoader.reload_ioc_rules_atomic(
               [next: %{value: "next"}],
               %{
                 authority_epoch: next_epoch,
                 digest: next_digest,
                 provider: :authority_v1
               }
             )

    assert %{
             authority_epoch: ^next_epoch,
             digest: ^next_digest,
             provider: :authority_v1
           } = RuleLoader.published_ioc_snapshot()
  end

  test "production callsites use the facade and authority pool is conditional" do
    root = Path.expand("../../..", __DIR__)

    engine_supervisor =
      File.read!(Path.join(root, "lib/tamandua_server/detection/engine_supervisor.ex"))

    reconciler = File.read!(Path.join(root, "lib/tamandua_server/detection/ioc_reconciler.ex"))
    reload = File.read!(Path.join(root, "lib/tamandua_server/detection/ioc_reload.ex"))
    application = File.read!(Path.join(root, "lib/tamandua_server/application.ex"))

    refute engine_supervisor =~ "IOCSnapshotProvider.preflight()"
    assert engine_supervisor =~ "IOCSnapshotProvider.reconcile()"
    assert reconciler =~ "&IOCSnapshotProvider.reconcile/0"
    assert reconciler =~ "&IOCSnapshotProvider.probe/0"
    assert reload =~ "IOCSnapshotProvider.reconcile()"
    assert application =~ "IocSnapshotAuthorityRepo.enabled?()"
    assert application =~ "IOCSnapshotProvider.initialize!()"
    assert application =~ "initial_reconcile: false"
    assert application =~ "load_rules_into_ets(reconcile_iocs: false)"
  end
end
