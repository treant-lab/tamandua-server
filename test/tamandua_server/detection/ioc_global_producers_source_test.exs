defmodule TamanduaServer.Detection.IOCGlobalProducersSourceTest do
  use ExUnit.Case, async: true

  @server_root Path.expand("../../../lib", __DIR__)

  @global_producers %{
    "tamandua_server/detection/threat_intel_feeds.ex" => 4,
    "tamandua_server/threat_intel/aggregator.ex" => 1,
    "tamandua_server/threat_intel/misp.ex" => 1,
    "tamandua_server/threat_intel/stix_converter.ex" => 1
  }

  test "all known shared-feed producers use the explicit global IOC API" do
    total_calls =
      Enum.reduce(@global_producers, 0, fn {relative_path, expected_calls}, total ->
        source = File.read!(Path.join(@server_root, relative_path))

        assert count_calls(source, "bulk_add_global(") == expected_calls,
               "expected #{expected_calls} explicit global IOC writes in #{relative_path}"

        refute Regex.match?(~r/IOCs\.bulk_add\(/, source),
               "#{relative_path} must not use tenant-inferred bulk_add for global feed data"

        total + expected_calls
      end)

    assert total_calls == 7
  end

  test "feed writes do not crash on an IOC API error tuple" do
    source =
      File.read!(Path.join(@server_root, "tamandua_server/detection/threat_intel_feeds.ex"))

    refute Regex.match?(~r/\{:ok,\s*result\}\s*=\s*IOCs\.bulk_add(?:_global)?\(/, source)
    assert count_calls(source, "case IOCs.bulk_add_global(") == 4
    assert count_calls(source, "{:error, reason} ->") >= 4
  end

  test "legacy system ingestion paths use the explicit global single-write API" do
    integrations = File.read!(Path.join(@server_root, "tamandua_server/integrations.ex"))

    webhooks =
      File.read!(Path.join(@server_root, "tamandua_server_web/controllers/webhook_controller.ex"))

    assert count_calls(integrations, "IOCs.add_global(") == 3
    assert count_calls(webhooks, "create_global_ioc(attrs)") == 4
    assert count_calls(webhooks, "IOCs.add_global(attrs)") == 1
    assert integrations =~ "IOCReload.schedule()"
    assert webhooks =~ "IOCReload.schedule()"
    refute integrations =~ "IOCs.create_ioc(ioc_attrs)"
    refute webhooks =~ "IOCs.create_ioc(attrs)"
  end

  defp count_calls(source, call),
    do: source |> String.split(call) |> length() |> Kernel.-(1)
end
