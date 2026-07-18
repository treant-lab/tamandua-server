defmodule TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorizationTest do
  use ExUnit.Case, async: true

  alias TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization

  test "tenant admin is not a system operator" do
    refute SystemOperatorAuthorization.system_operator?(%{role: "admin"})
    refute SystemOperatorAuthorization.system_operator?(%{role: "admin", system_all: true})
  end

  test "only explicit super-admin identity is a system operator" do
    assert SystemOperatorAuthorization.system_operator?(%{role: "super_admin"})
    assert SystemOperatorAuthorization.system_operator?(%{role: "viewer", is_super_admin: true})
  end
end
