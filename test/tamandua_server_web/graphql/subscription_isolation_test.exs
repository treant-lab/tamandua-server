defmodule TamanduaServerWeb.GraphQL.SubscriptionIsolationTest do
  use TamanduaServerWeb.ChannelCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServerWeb.GraphQL.{Schema, UserSocket}

  test "socket rejects anonymous and invalid-token connections" do
    assert :error = connect(UserSocket, %{})
    assert :error = connect(UserSocket, %{"token" => "invalid"})
  end

  test "socket accepts only an active user bound to an organization" do
    organization = insert(:organization)
    user = insert(:user, organization: organization, is_active: true)
    token = Accounts.generate_user_session_token(user)

    assert {:ok, socket} = connect(UserSocket, %{"token" => token})
    assert UserSocket.id(socket) == "graphql_socket:#{user.id}"

    inactive_user = insert(:user, organization: organization, is_active: false)
    inactive_token = Accounts.generate_user_session_token(inactive_user)

    assert :error = connect(UserSocket, %{"token" => inactive_token})
  end

  test "Guardian JWT must be minted explicitly for the GraphQL socket" do
    organization = insert(:organization)
    user = insert(:user, organization: organization, is_active: true)

    {:ok, generic_token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    {:ok, graphql_token, _claims} =
      TamanduaServer.Guardian.encode_and_sign(user, %{
        "aud" => "tamandua_graphql",
        "scope" => "graphql_socket"
      })

    assert :error = connect(UserSocket, %{"token" => generic_token})
    assert {:ok, _socket} = connect(UserSocket, %{"token" => graphql_token})
  end

  test "narrow Guardian capability claims are never valid GraphQL claims" do
    base = %{"aud" => "tamandua_graphql", "scope" => "graphql_socket"}

    assert UserSocket.graphql_claims?(base)
    refute UserSocket.graphql_claims?(Map.put(base, "cli", true))
    refute UserSocket.graphql_claims?(Map.put(base, "scope", "dashboard_socket"))
    refute UserSocket.graphql_claims?(Map.put(base, "scope", "live_response"))
    refute UserSocket.graphql_claims?(Map.put(base, "agent_id", Ecto.UUID.generate()))
    refute UserSocket.graphql_claims?(Map.put(base, "permissions", ["live_response:shell"]))
    refute UserSocket.graphql_claims?(Map.put(base, "aud", "another_surface"))
  end

  test "every topic is organization-qualified and no global fallback exists" do
    organization_id = Ecto.UUID.generate()
    alert_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()
    execution_id = Ecto.UUID.generate()

    topics = [
      Schema.tenant_topic(organization_id, :alerts),
      Schema.tenant_topic(organization_id, :alert_updates, %{alert_id: alert_id}),
      Schema.tenant_topic(organization_id, :agent_status, %{agent_id: agent_id}),
      Schema.tenant_topic(organization_id, :events, %{agent_id: agent_id, event_type: "process"}),
      Schema.tenant_topic(organization_id, :playbook_executions, %{execution_id: execution_id}),
      Schema.tenant_topic(organization_id, :threat_intel)
    ]

    assert Enum.all?(topics, &String.starts_with?(&1, "org:#{organization_id}:"))
    refute Enum.any?(topics, &String.contains?(&1, ":all"))
  end

  test "subscription config fails closed without tenant context" do
    assert {:error, "Subscription unavailable"} =
             Schema.subscription_topic(%{}, :alerts_read, :alerts, %{})
  end

  test "API-key scope intersects the authenticated user's permission" do
    organization = insert(:organization)
    user = insert(:user, organization: organization, is_active: true)

    context = %{
      current_user_id: user.id,
      organization_id: organization.id,
      api_key_present: true,
      api_key_scope: "custom",
      api_key_permissions: []
    }

    assert {:error, "Subscription unavailable"} =
             Schema.subscription_topic(context, :alerts_read, :alerts, %{})
  end

  test "caller-supplied alert ID must belong to the socket tenant" do
    organization = insert(:organization)
    other_organization = insert(:organization)
    user = insert(:user, organization: organization, is_active: true)
    foreign_alert = insert(:alert, organization: other_organization)

    context = %{current_user_id: user.id, organization_id: organization.id}

    assert {:error, "Subscription unavailable"} =
             Schema.subscription_topic(context, :alerts_read, :alert_updates, %{
               alert_id: foreign_alert.id
             })
  end
end
