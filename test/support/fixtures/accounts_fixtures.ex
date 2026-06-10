defmodule TamanduaServer.AccountsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `TamanduaServer.Accounts` context.
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Accounts.User

  def organization_fixture(attrs \\ %{}) do
    attrs =
      attrs
      |> Enum.into(%{
        name: "Test Organization #{System.unique_integer([:positive])}",
        slug: "test-org-#{System.unique_integer([:positive])}"
      })

    %Organization{}
    |> Organization.changeset(attrs)
    |> Repo.insert!()
  end

  def user_fixture(attrs \\ %{}) do
    organization_id = attrs[:organization_id] || raise "organization_id required"

    attrs =
      attrs
      |> Enum.into(%{
        email: "user#{System.unique_integer([:positive])}@test.com",
        password: "password123456",
        organization_id: organization_id
      })

    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert!()
  end
end
