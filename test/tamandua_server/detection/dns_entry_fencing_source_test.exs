defmodule TamanduaServer.Detection.DNSEntryFencingSourceTest do
  use ExUnit.Case, async: true

  @source Path.expand(
            "../../../lib/tamandua_server/detection/dns_command_dispatch.ex",
            __DIR__
          )

  test "legacy dispatch omits the fence payload while explicit v1 is passed per domain" do
    source = File.read!(@source)
    assert {:ok, _ast} = Code.string_to_quoted(source)
    assert source =~ "Keyword.fetch(opts, :dns_policy_fence)"
    assert source =~ "defp fence_payload(nil, _domain), do: nil"
    assert source =~ "entry_version: Map.fetch!(fence.entry_versions, domain)"
    assert source =~ "defp command_params(%{dns_policy_fence: nil} = job)"
  end

  test "fenced dispatch is tenant-stream-bound and capability fail-closed" do
    source = File.read!(@source)
    assert source =~ "canonical_stream == organization_id"
    assert source =~ ~s("dns_policy_fence_v1" in capabilities)
    assert source =~ "Enum.all?(agents, &fence_capable?/1)"
    assert source =~ "versions[&1] <= 9_223_372_036_854_775_807"
    assert source =~ "{:error, :dns_policy_fence_not_ready}"
  end
end
