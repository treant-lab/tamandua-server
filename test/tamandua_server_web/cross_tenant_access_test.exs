defmodule TamanduaServerWeb.CrossTenantAccessTest do
  @moduledoc """
  Tests for BOLA/IDOR (Broken Object Level Authorization / Insecure Direct Object Reference)
  vulnerability prevention.

  These tests verify that users from one organization cannot access
  resources belonging to another organization.
  """
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts

  describe "Agents LiveView cross-tenant access prevention" do
    setup do
      # Create two organizations
      org1_id = Ecto.UUID.generate()
      org2_id = Ecto.UUID.generate()

      # Create agents for each organization
      {:ok, agent_org1} = create_agent_for_org(org1_id, %{
        hostname: "org1-server",
        os_type: "linux"
      })

      {:ok, agent_org2} = create_agent_for_org(org2_id, %{
        hostname: "org2-server",
        os_type: "windows"
      })

      %{
        org1_id: org1_id,
        org2_id: org2_id,
        agent_org1: agent_org1,
        agent_org2: agent_org2
      }
    end

    test "user cannot view agent from different organization", %{
      conn: conn,
      org1_id: org1_id,
      agent_org2: agent_org2
    } do
      # Authenticate user with org1
      conn = setup_session_with_org(conn, org1_id)

      # Try to access agent from org2 - should fail
      {:error, {:redirect, redirect}} = live(conn, ~p"/agents/#{agent_org2.id}")

      assert redirect.flash["error"] =~ "not found"
    end

    test "user can view agent from their own organization", %{
      conn: conn,
      org1_id: org1_id,
      agent_org1: agent_org1
    } do
      conn = setup_session_with_org(conn, org1_id)

      # Access agent from same org - should succeed
      {:ok, _view, html} = live(conn, ~p"/agents/#{agent_org1.id}")

      assert html =~ agent_org1.hostname
    end

    test "agent list only shows agents from user's organization", %{
      conn: conn,
      org1_id: org1_id,
      agent_org1: agent_org1,
      agent_org2: agent_org2
    } do
      conn = setup_session_with_org(conn, org1_id)

      {:ok, _view, html} = live(conn, ~p"/agents")

      # Should see org1 agent
      assert html =~ agent_org1.hostname

      # Should NOT see org2 agent
      refute html =~ agent_org2.hostname
    end
  end

  describe "Alerts cross-tenant access prevention" do
    setup do
      org1_id = Ecto.UUID.generate()
      org2_id = Ecto.UUID.generate()

      {:ok, alert_org1} = create_alert_for_org(org1_id, %{
        title: "Org1 Alert",
        severity: "high"
      })

      {:ok, alert_org2} = create_alert_for_org(org2_id, %{
        title: "Org2 Alert",
        severity: "critical"
      })

      %{
        org1_id: org1_id,
        org2_id: org2_id,
        alert_org1: alert_org1,
        alert_org2: alert_org2
      }
    end

    test "user cannot view alert from different organization", %{
      conn: conn,
      org1_id: org1_id,
      alert_org2: alert_org2
    } do
      conn = setup_session_with_org(conn, org1_id)

      # Try to access alert from org2 - should fail
      {:error, {:redirect, redirect}} = live(conn, ~p"/alerts/#{alert_org2.id}")

      assert redirect.flash["error"] =~ "not found"
    end

    test "user can view alert from their own organization", %{
      conn: conn,
      org1_id: org1_id,
      alert_org1: alert_org1
    } do
      conn = setup_session_with_org(conn, org1_id)

      {:ok, _view, html} = live(conn, ~p"/alerts/#{alert_org1.id}")

      assert html =~ alert_org1.title
    end
  end

  describe "Timeline LiveView cross-tenant access prevention" do
    setup do
      org1_id = Ecto.UUID.generate()
      org2_id = Ecto.UUID.generate()

      {:ok, alert_org1} = create_alert_for_org(org1_id, %{
        title: "Org1 Timeline Alert",
        severity: "high"
      })

      {:ok, alert_org2} = create_alert_for_org(org2_id, %{
        title: "Org2 Timeline Alert",
        severity: "critical"
      })

      %{
        org1_id: org1_id,
        org2_id: org2_id,
        alert_org1: alert_org1,
        alert_org2: alert_org2
      }
    end

    test "user cannot view timeline for alert from different organization", %{
      conn: conn,
      org1_id: org1_id,
      alert_org2: alert_org2
    } do
      conn = setup_session_with_org(conn, org1_id)

      # Try to access timeline from org2 - should fail
      {:error, {:redirect, redirect}} = live(conn, ~p"/timeline/#{alert_org2.id}")

      assert redirect.flash["error"] =~ "not found"
    end
  end

  describe "GraphQL cross-tenant access prevention" do
    setup do
      org1_id = Ecto.UUID.generate()
      org2_id = Ecto.UUID.generate()

      {:ok, agent_org1} = create_agent_for_org(org1_id, %{hostname: "gql-org1-server"})
      {:ok, agent_org2} = create_agent_for_org(org2_id, %{hostname: "gql-org2-server"})

      %{
        org1_id: org1_id,
        org2_id: org2_id,
        agent_org1: agent_org1,
        agent_org2: agent_org2
      }
    end

    test "GraphQL agent field resolver does not leak cross-tenant data", %{
      org1_id: org1_id,
      agent_org2: agent_org2
    } do
      # Create an alert that references agent_org2 but belongs to org1
      # This simulates a potential data inconsistency
      {:ok, alert} = create_alert_for_org(org1_id, %{
        title: "Test Alert",
        agent_id: agent_org2.id  # Reference to different org's agent
      })

      # When resolving the agent field, it should return nil
      # because the agent doesn't belong to org1
      context = %{organization_id: org1_id}

      result = TamanduaServerWeb.GraphQL.Resolvers.AlertResolver.agent(
        alert,
        %{},
        %{context: context}
      )

      assert result == {:ok, nil}
    end
  end

  describe "API Controller cross-tenant access prevention" do
    setup do
      org1_id = Ecto.UUID.generate()
      org2_id = Ecto.UUID.generate()

      {:ok, agent_org1} = create_agent_for_org(org1_id, %{hostname: "api-org1-server"})
      {:ok, agent_org2} = create_agent_for_org(org2_id, %{hostname: "api-org2-server"})

      %{
        org1_id: org1_id,
        org2_id: org2_id,
        agent_org1: agent_org1,
        agent_org2: agent_org2
      }
    end

    test "baseline status returns 404 for agent from different organization", %{
      conn: conn,
      org1_id: org1_id,
      agent_org2: agent_org2
    } do
      conn =
        conn
        |> setup_api_session_with_org(org1_id)
        |> get(~p"/api/v1/agents/#{agent_org2.id}/baseline/status")

      assert json_response(conn, 404)["error"] =~ "not found"
    end

    test "baseline status succeeds for agent from same organization", %{
      conn: conn,
      org1_id: org1_id,
      agent_org1: agent_org1
    } do
      conn =
        conn
        |> setup_api_session_with_org(org1_id)
        |> get(~p"/api/v1/agents/#{agent_org1.id}/baseline/status")

      assert json_response(conn, 200)["data"]["agent_id"] == agent_org1.id
    end
  end

  # Helper functions

  defp create_agent_for_org(organization_id, attrs) do
    default_attrs = %{
      id: Ecto.UUID.generate(),
      hostname: "test-server",
      os_type: "linux",
      os_version: "Ubuntu 22.04",
      agent_version: "1.0.0",
      status: "online",
      organization_id: organization_id
    }

    %Agent{}
    |> Agent.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert()
  end

  defp create_alert_for_org(organization_id, attrs) do
    default_attrs = %{
      title: "Test Alert",
      description: "Test description",
      severity: "medium",
      status: "new",
      agent_id: Ecto.UUID.generate(),
      organization_id: organization_id
    }

    %Alert{}
    |> Alert.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert()
  end

  defp setup_session_with_org(conn, organization_id) do
    user = %{
      id: Ecto.UUID.generate(),
      email: "test@example.com",
      organization_id: organization_id,
      role: :admin
    }

    conn
    |> Plug.Test.init_test_session(%{
      "organization_id" => organization_id,
      "current_user" => user
    })
    |> assign(:current_user, user)
    |> assign(:current_organization_id, organization_id)
  end

  defp setup_api_session_with_org(conn, organization_id) do
    user = %{
      id: Ecto.UUID.generate(),
      email: "api-test@example.com",
      organization_id: organization_id,
      role: :admin
    }

    conn
    |> assign(:current_user, user)
    |> assign(:current_organization_id, organization_id)
  end
end
