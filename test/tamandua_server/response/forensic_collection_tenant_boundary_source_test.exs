defmodule TamanduaServer.Response.ForensicCollectionTenantBoundarySourceTest do
  use ExUnit.Case, async: true

  @executor Path.expand(
              "../../../lib/tamandua_server/response/executor.ex",
              __DIR__
            )
  @response_resolver Path.expand(
                       "../../../lib/tamandua_server_web/graphql/resolvers/response_resolver.ex",
                       __DIR__
                     )
  @investigation_resolver Path.expand(
                            "../../../lib/tamandua_server_web/graphql/resolvers/investigation_resolver.ex",
                            __DIR__
                          )
  @schema Path.expand("../../../lib/tamandua_server_web/graphql/schema.ex", __DIR__)

  test "forensic collection records and status are tenant bound" do
    source = File.read!(@executor)

    assert source =~ "organization_id: organization_id"
    assert source =~ "requested_by: requested_by"
    assert source =~ "def get_collection_status(organization_id, collection_id)"
    assert source =~ "%{organization_id: ^canonical_organization_id} = record"

    assert source =~
             "def get_collection_status(_collection_id), do: {:error, :organization_scope_required}"
  end

  test "the ETS table is protected and writes are owned by the collection store" do
    source = File.read!(@executor)

    assert source =~ ":protected"
    refute source =~ ":public"
    assert source =~ "CollectionStore.reserve(collection_record)"
    assert source =~ "CollectionStore.finish(collection_id"
    refute source =~ ":ets.insert(@collections_table"
  end

  test "admission is serialized, bounded and happens before task creation" do
    source = File.read!(@executor)

    assert source =~ "@max_active_global 64"
    assert source =~ "@max_active_per_tenant 8"
    assert source =~ "@max_retained_records 2_048"
    assert source =~ "{:error, :collection_admission_limited}"
    assert source =~ "System.monotonic_time(:millisecond)"
    assert source =~ "@active_ttl_ms :timer.hours(1)"
    assert source =~ "@retained_ttl_ms :timer.hours(24)"

    {reserve_offset, _} = :binary.match(source, "CollectionStore.reserve(collection_record)")
    {task_offset, _} = :binary.match(source, "case Task.start(fn ->")
    assert reserve_offset < task_offset
  end

  test "caller and retained result data are bounded and errors are categorized" do
    source = File.read!(@executor)
    [forensic_source | _rest] =
      source
      |> String.split("defp do_collect_forensics", parts: 2)
      |> List.last()
      |> String.split("def collect_artifact", parts: 2)

    assert source =~ "@max_forensic_options 16"
    assert source =~ "@max_forensic_type_bytes 32"
    assert source =~ "@max_forensic_artifacts 128"
    assert source =~ "@max_forensic_artifact_bytes 16_384"
    assert forensic_source =~ "error_message: forensic_error_category(reason)"
    refute forensic_source =~ "error_message: inspect(reason)"
  end

  test "store volatility is explicit and not overclaimed as durable" do
    source = File.read!(@executor)

    assert source =~ "This store is intentionally volatile"
    assert source =~ "Durable supervision/reconciliation is a separate P2 lane"
  end

  test "GraphQL validates investigation ownership and maps supported input honestly" do
    source = File.read!(@response_resolver)

    assert source =~ "Investigations.get_investigation_for_org("
    assert source =~ "memory_dump: input[:include_memory] || false"
    assert source =~ "supported_forensic_paths(input[:paths])"
    refute source =~ "include_memory: input[:include_memory]"
    refute source =~ "paths: input[:paths]"
  end

  test "only ResponseResolver owns the wired forensic mutation" do
    schema = File.read!(@schema)
    response_resolver = File.read!(@response_resolver)
    investigation_resolver = File.read!(@investigation_resolver)

    assert schema =~ "field :collect_forensics, :forensics_result"
    assert schema =~ "Middleware.Authentication"
    assert schema =~ "Middleware.Authorization, :forensics_collect"
    assert schema =~ "resolve(&ResponseResolver.collect_forensics/3)"
    assert response_resolver =~ "def collect_forensics("
    refute investigation_resolver =~ "def collect_forensics("
    refute investigation_resolver =~ "def get_forensic_collection("
    refute investigation_resolver =~ "defp get_collection_status("
  end
end
