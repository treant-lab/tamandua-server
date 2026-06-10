defmodule TamanduaServerWeb.AlertStreamChannelTest do
  use TamanduaServerWeb.ChannelCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Streaming.StreamManager

  setup do
    # Start StreamManager
    start_supervised!(StreamManager)

    # Create test organization
    {:ok, org} = Accounts.create_organization(%{
      name: "Test Org",
      slug: "test-org-#{:erlang.unique_integer([:positive])}"
    })

    # Create test user
    {:ok, user} = Accounts.create_user(%{
      email: "test-#{:erlang.unique_integer([:positive])}@example.com",
      password: "password123",
      organization_id: org.id,
      active: true
    })

    # Generate JWT token
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    # Connect to socket
    {:ok, socket} = connect(TamanduaServerWeb.StreamSocket, %{"token" => token})

    %{socket: socket, user: user, org: org, token: token}
  end

  describe "join stream:alerts" do
    test "successfully joins with valid filters", %{socket: socket} do
      {:ok, reply, _socket} = subscribe_and_join(
        socket,
        "stream:alerts",
        %{"filters" => %{"severity" => ["critical", "high"]}}
      )

      assert reply.stream_id =~ "ws_alerts"
      assert reply.filters.severity == ["critical", "high"]
    end

    test "applies default filters if none provided", %{socket: socket} do
      {:ok, reply, _socket} = subscribe_and_join(socket, "stream:alerts", %{})

      assert reply.stream_id =~ "ws_alerts"
      assert is_map(reply.filters)
    end

    test "enforces organization_id filter (RBAC)", %{socket: socket, org: org} do
      {:ok, reply, _socket} = subscribe_and_join(socket, "stream:alerts", %{})

      assert reply.filters.organization_id == org.id
    end
  end

  describe "receiving alerts" do
    test "receives matching alerts", %{socket: socket, org: org} do
      {:ok, _reply, socket} = subscribe_and_join(
        socket,
        "stream:alerts",
        %{"filters" => %{"severity" => ["critical"]}}
      )

      # Broadcast a critical alert
      alert = %{
        severity: "critical",
        title: "Test Alert",
        organization_id: org.id
      }

      StreamManager.broadcast_alert(alert)

      # Should receive the alert
      assert_push "alert", %{data: _data, id: _id}
    end

    test "does not receive non-matching alerts", %{socket: socket, org: org} do
      {:ok, _reply, socket} = subscribe_and_join(
        socket,
        "stream:alerts",
        %{"filters" => %{"severity" => ["high"]}}
      )

      # Broadcast a critical alert (should not match)
      alert = %{
        severity: "critical",
        title: "Test Alert",
        organization_id: org.id
      }

      StreamManager.broadcast_alert(alert)

      # Should NOT receive the alert
      refute_push "alert", %{}, 500
    end

    test "receives alerts from own organization only", %{socket: socket, org: org} do
      {:ok, _reply, socket} = subscribe_and_join(socket, "stream:alerts", %{})

      # Broadcast alert from different organization
      other_org_alert = %{
        severity: "critical",
        title: "Other Org Alert",
        organization_id: "other-org-id"
      }

      StreamManager.broadcast_alert(other_org_alert)

      # Should NOT receive the alert
      refute_push "alert", %{}, 500

      # Broadcast alert from same organization
      own_org_alert = %{
        severity: "critical",
        title: "Own Org Alert",
        organization_id: org.id
      }

      StreamManager.broadcast_alert(own_org_alert)

      # Should receive this alert
      assert_push "alert", %{}
    end
  end

  describe "update_filters" do
    test "updates stream filters dynamically", %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(
        socket,
        "stream:alerts",
        %{"filters" => %{"severity" => ["critical"]}}
      )

      # Update filters
      ref = push(socket, "update_filters", %{
        "filters" => %{"severity" => ["high", "medium"]}
      })

      assert_reply ref, :ok, %{filters: filters}
      assert filters.severity == ["high", "medium"]
    end
  end

  describe "ping" do
    test "responds to ping with pong", %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, "stream:alerts", %{})

      ref = push(socket, "ping", %{})
      assert_reply ref, :ok, %{pong: true}
    end
  end
end
