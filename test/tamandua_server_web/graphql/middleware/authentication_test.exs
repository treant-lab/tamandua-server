defmodule TamanduaServerWeb.GraphQL.Middleware.AuthenticationTest do
  use ExUnit.Case, async: true

  alias Absinthe.Resolution
  alias TamanduaServerWeb.GraphQL.Middleware.{Authentication, Authorization}

  test "restricted API key fails closed on a field without explicit authorization" do
    resolution = %Resolution{
      context: %{current_user_id: "user-id", api_key_present: true},
      middleware: []
    }

    result = Authentication.call(resolution, [])

    assert result.state == :resolved
    assert ["API key scope is not configured for this operation"] = result.errors
  end

  test "API key may continue only when permission authorization remains in the pipeline" do
    resolution = %Resolution{
      context: %{current_user_id: "user-id", api_key_present: true},
      middleware: [{Authorization, :investigations_read}]
    }

    result = Authentication.call(resolution, [])

    assert result.state == :unresolved
    assert result.errors == []
  end

  test "authenticated actor without an API key keeps the existing RBAC pipeline" do
    resolution = %Resolution{context: %{current_user_id: "user-id"}, middleware: []}

    result = Authentication.call(resolution, [])

    assert result.state == :unresolved
    assert result.errors == []
  end
end
