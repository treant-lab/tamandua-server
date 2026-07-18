defmodule TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolverTest do
  use ExUnit.Case, async: true

  alias TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolver

  test "list fails closed without an organization context" do
    assert {:error, error} =
             PlaybookResolver.list_playbooks(nil, %{}, %{context: %{current_user_id: "user-1"}})

    assert error =~ "tenant_required"
  end

  test "execute ignores client organization and requires authenticated tenant context" do
    input = %{
      playbook_id: Ecto.UUID.generate(),
      context: %{"organization_id" => Ecto.UUID.generate()}
    }

    assert {:error, :tenant_required} =
             PlaybookResolver.execute_playbook(nil, %{input: input}, %{
               context: %{current_user_id: "user-1"}
             })
  end
end
