defmodule TamanduaServer.Response.ResponseActorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Response.ResponseActor

  @organization_id "11111111-1111-4111-8111-111111111111"
  @user_id "22222222-2222-4222-8222-222222222222"

  test "builds the executor actor only for the authenticated user's exact tenant" do
    assert {:ok,
            %{
              organization_id: @organization_id,
              user_id: @user_id
            }} =
             ResponseActor.from_user_scope(
               %{id: @user_id, organization_id: @organization_id},
               @organization_id
             )
  end

  test "canonicalizes UUID representations before exact comparison" do
    assert {:ok, %{organization_id: @organization_id, user_id: @user_id}} =
             ResponseActor.from_user_scope(
               %{
                 "id" => String.upcase(@user_id),
                 "organization_id" => String.upcase(@organization_id)
               },
               @organization_id
             )
  end

  test "fails closed when the user identity or either tenant is missing" do
    assert {:error, :forbidden} =
             ResponseActor.from_user_scope(%{organization_id: @organization_id}, @organization_id)

    assert {:error, :forbidden} =
             ResponseActor.from_user_scope(%{id: @user_id}, @organization_id)

    assert {:error, :forbidden} =
             ResponseActor.from_user_scope(
               %{id: @user_id, organization_id: @organization_id},
               nil
             )

    assert {:error, :forbidden} = ResponseActor.from_user_scope(nil, @organization_id)
  end

  test "rejects a cross-tenant request scope" do
    assert {:error, :forbidden} =
             ResponseActor.from_user_scope(
               %{id: @user_id, organization_id: @organization_id},
               "33333333-3333-4333-8333-333333333333"
             )
  end

  test "rejects malformed identifiers" do
    assert {:error, :forbidden} =
             ResponseActor.from_user_scope(
               %{id: "not-a-uuid", organization_id: @organization_id},
               @organization_id
             )
  end
end
