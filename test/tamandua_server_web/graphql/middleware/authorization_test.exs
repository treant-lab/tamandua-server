defmodule TamanduaServerWeb.GraphQL.Middleware.AuthorizationTest do
  use ExUnit.Case, async: true

  alias TamanduaServerWeb.GraphQL.Middleware.Authorization

  test "an API key is an additional restriction, not an RBAC bypass" do
    assert Authorization.api_key_allows?(%{}, :investigations_update)

    assert Authorization.api_key_allows?(
             %{api_key_present: true, api_key_scope: "full"},
             :investigations_update
           )

    refute Authorization.api_key_allows?(
             %{api_key_present: true, api_key_scope: "read_only"},
             :investigations_update
           )

    assert Authorization.api_key_allows?(
             %{api_key_present: true, api_key_scope: "read_only"},
             :investigations_read
           )
  end

  test "custom keys require the exact investigation permission" do
    context = %{
      api_key_present: true,
      api_key_scope: "custom",
      api_key_permissions: ["investigations_read"]
    }

    assert Authorization.api_key_allows?(context, :investigations_read)
    refute Authorization.api_key_allows?(context, :investigations_create)
    refute Authorization.api_key_allows?(context, :investigations_update)
  end
end
