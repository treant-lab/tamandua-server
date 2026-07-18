defmodule TamanduaServer.Detection.IOCRuntimeTenantScopeTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.IOCs

  @org_a "00000000-0000-0000-0000-00000000000a"
  @org_b "00000000-0000-0000-0000-00000000000b"

  test "global rules are shared while private rules never cross tenants" do
    rules = [
      %{id: "global", scope: :global, organization_id: nil, type: :domain, value: "global.test"},
      %{
        id: "a",
        scope: {:tenant, @org_a},
        organization_id: @org_a,
        type: :domain,
        value: "a.test"
      },
      %{
        id: "b",
        scope: {:tenant, @org_b},
        organization_id: @org_b,
        type: :domain,
        value: "b.test"
      }
    ]

    assert ids(IOCs.visible_for_organization(rules, @org_a)) == ["a", "global"]
    assert ids(IOCs.visible_for_organization(rules, @org_b)) == ["b", "global"]
    assert ids(IOCs.visible_for_organization(rules, nil)) == ["global"]
  end

  test "tenant rule overrides a global rule with the same normalized key" do
    rules = [
      %{id: "global", scope: :global, organization_id: nil, type: :ip, value: "203.0.113.1"},
      %{
        id: "tenant",
        scope: {:tenant, @org_a},
        organization_id: @org_a,
        type: :ip,
        value: "203.0.113.1"
      }
    ]

    assert [%{id: "tenant"}] = IOCs.visible_for_organization(rules, @org_a)
    assert [%{id: "global"}] = IOCs.visible_for_organization(rules, @org_b)
  end

  test "inconsistent scope metadata fails closed" do
    rules = [
      %{
        id: "spoofed-global",
        scope: :global,
        organization_id: @org_b,
        type: :ip,
        value: "1.1.1.1"
      },
      %{
        id: "spoofed-tenant",
        scope: {:tenant, @org_a},
        organization_id: nil,
        type: :ip,
        value: "2.2.2.2"
      }
    ]

    assert IOCs.visible_for_organization(rules, @org_a) == []
  end

  test "organization-less and mixed private writes fail before database access" do
    assert {:error, :organization_required} =
             IOCs.add(%{type: "ip", value: "192.0.2.1"})

    assert {:error, :ioc_scope_required} =
             IOCs.bulk_add([%{type: "ip", value: "192.0.2.2"}])

    assert {:error, :mixed_ioc_scopes} =
             IOCs.bulk_add(
               [
                 %{type: "ip", value: "192.0.2.3", organization_id: @org_a},
                 %{type: "ip", value: "192.0.2.4", organization_id: @org_b}
               ],
               scope: {:tenant, @org_a}
             )
  end

  defp ids(rules), do: rules |> Enum.map(& &1.id) |> Enum.sort()
end
