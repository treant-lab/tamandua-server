defmodule TamanduaServer.ReleaseTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Release

  test "deploy smoke bearer is intentionally short lived" do
    assert Release.smoke_bearer_ttl() == {5, :minute}
  end

  test "tenant preflight covers every Evidence Session composite relationship" do
    checks = Release.evidence_tenant_checks()

    assert length(checks) == 12
    assert Enum.all?(checks, fn {label, child, parent, predicate} ->
             is_binary(label) and is_binary(child) and is_binary(parent) and
               String.contains?(predicate, "organization_id")
           end)

    assert Enum.count(checks, fn {label, _, _, _} ->
             String.contains?(label, "artifact")
           end) == 5
  end
end
