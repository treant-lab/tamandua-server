defmodule TamanduaServerWeb.GraphQL.Middleware.ConditionalAuthorizationTest do
  use ExUnit.Case, async: true

  alias TamanduaServerWeb.GraphQL.Middleware.ConditionalAuthorization

  test "recognizes only populated nested arguments" do
    refute ConditionalAuthorization.argument_present?(%{input: %{}}, [
             :input,
             :assigned_to_id
           ])

    refute ConditionalAuthorization.argument_present?(%{input: %{alert_ids: []}}, [
             :input,
             :alert_ids
           ])

    assert ConditionalAuthorization.argument_present?(%{input: %{assigned_to_id: "user-1"}}, [
             :input,
             :assigned_to_id
           ])

    assert ConditionalAuthorization.argument_present?(%{input: %{assigned_to_id: nil}}, [
             :input,
             :assigned_to_id
           ])

    assert ConditionalAuthorization.argument_present?(%{input: %{alert_ids: ["alert-1"]}}, [
             :input,
             :alert_ids
           ])
  end

  test "does not invoke authorization when the guarded argument is absent" do
    resolution = %{arguments: %{input: %{status: "resolved"}}}

    assert ConditionalAuthorization.call(
             resolution,
             {:alerts_assign, [:input, :assigned_to_id]}
           ) == resolution
  end
end
