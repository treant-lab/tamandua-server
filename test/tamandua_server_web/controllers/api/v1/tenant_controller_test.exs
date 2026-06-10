defmodule TamanduaServerWeb.API.V1.TenantControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Repo

  import TamanduaServer.Factory

  @moduledoc """
  Tests for the Tenant Management API.

  These tests cover:
  - CRUD operations for tenants
  - Suspension and reactivation
  - Tenant provisioning
  - Authorization enforcement
  """

  setup %{conn: conn} do
    # Create system admin organization and user
    admin_org = insert(:organization, %{
      name: "System Admin Org",
      slug: "system-admin-org",
      is_active: true
    })

    admin_user = insert(:user, %{
      organization_id: admin_org.id,
      role: "admin",
      email: "admin@system.local"
    })

    # Create regular organization and user
    regular_org = insert(:organization, %{
      name: "Regular Org",
      slug: "regular-org",
      is_active: true
    })

    regular_user = insert(:user, %{
      organization_id: regular_org.id,
      role: "analyst",
      email: "analyst@regular.local"
    })

    # Generate tokens
    {:ok, admin_token, _} = TamanduaServer.Guardian.encode_and_sign(admin_user)
    {:ok, regular_token, _} = TamanduaServer.Guardian.encode_and_sign(regular_user)

    admin_conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("authorization", "Bearer #{admin_token}")

    regular_conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("authorization", "Bearer #{regular_token}")

    %{
      admin_conn: admin_conn,
      regular_conn: regular_conn,
      admin_org: admin_org,
      regular_org: regular_org,
      admin_user: admin_user,
      regular_user: regular_user
    }
  end

  describe "GET /api/v1/tenants" do
    test "lists all tenants for system admin", %{admin_conn: conn} do
      # Create additional tenants
      insert(:organization, %{name: "Tenant 1", slug: "tenant-1"})
      insert(:organization, %{name: "Tenant 2", slug: "tenant-2"})

      conn = get(conn, ~p"/api/v1/tenants")

      assert %{"data" => tenants, "meta" => meta} = json_response(conn, 200)
      assert length(tenants) >= 3  # 2 created + admin org
      assert is_map(meta)
      assert Map.has_key?(meta, "limit")
      assert Map.has_key?(meta, "offset")
    end

    test "supports pagination", %{admin_conn: conn} do
      # Create more tenants
      for i <- 1..5 do
        insert(:organization, %{name: "Tenant #{i}", slug: "tenant-page-#{i}"})
      end

      conn = get(conn, ~p"/api/v1/tenants?limit=2&offset=0")

      assert %{"data" => tenants, "meta" => meta} = json_response(conn, 200)
      assert length(tenants) == 2
      assert meta["limit"] == 2
      assert meta["offset"] == 0
    end

    test "filters by active status", %{admin_conn: conn} do
      insert(:organization, %{name: "Active Org", slug: "active-org", is_active: true})
      insert(:organization, %{name: "Inactive Org", slug: "inactive-org", is_active: false})

      conn = get(conn, ~p"/api/v1/tenants?active=true")

      assert %{"data" => tenants} = json_response(conn, 200)
      assert Enum.all?(tenants, fn t -> t["is_active"] == true end)
    end
  end

  describe "GET /api/v1/tenants/:id" do
    test "returns tenant details for system admin", %{admin_conn: conn} do
      org = insert(:organization, %{name: "Show Test", slug: "show-test"})

      conn = get(conn, ~p"/api/v1/tenants/#{org.id}")

      assert %{"data" => tenant} = json_response(conn, 200)
      assert tenant["id"] == org.id
      assert tenant["slug"] == "show-test"
      assert Map.has_key?(tenant, "usage")
    end

    test "returns own organization for regular user", %{regular_conn: conn, regular_org: org} do
      conn = get(conn, ~p"/api/v1/tenants/#{org.id}")

      assert %{"data" => tenant} = json_response(conn, 200)
      assert tenant["id"] == org.id
    end

    test "returns 404 for non-existent tenant", %{admin_conn: conn} do
      conn = get(conn, ~p"/api/v1/tenants/#{Ecto.UUID.generate()}")

      assert json_response(conn, 404)
    end
  end

  describe "POST /api/v1/tenants" do
    test "creates tenant with valid attributes", %{admin_conn: conn} do
      attrs = %{
        "name" => "New Tenant",
        "slug" => "new-tenant",
        "license_tier" => "pro"
      }

      conn = post(conn, ~p"/api/v1/tenants", attrs)

      assert %{"data" => tenant} = json_response(conn, 201)
      assert tenant["name"] == "New Tenant"
      assert tenant["slug"] == "new-tenant"
      assert tenant["license_tier"] == "pro"
    end

    test "returns error for duplicate slug", %{admin_conn: conn} do
      insert(:organization, %{name: "Existing", slug: "existing-slug"})

      conn = post(conn, ~p"/api/v1/tenants", %{
        "name" => "Duplicate",
        "slug" => "existing-slug"
      })

      assert json_response(conn, 422)
    end

    test "returns error for missing required fields", %{admin_conn: conn} do
      conn = post(conn, ~p"/api/v1/tenants", %{})

      assert json_response(conn, 422)
    end
  end

  describe "PUT /api/v1/tenants/:id" do
    test "updates tenant settings", %{admin_conn: conn} do
      org = insert(:organization, %{name: "Update Test", slug: "update-test"})

      conn = put(conn, ~p"/api/v1/tenants/#{org.id}", %{
        "name" => "Updated Name",
        "settings" => %{"theme" => "dark"}
      })

      assert %{"data" => tenant} = json_response(conn, 200)
      assert tenant["name"] == "Updated Name"
      assert tenant["settings"]["theme"] == "dark"
    end

    test "regular user can update own organization", %{regular_conn: conn, regular_org: org} do
      conn = put(conn, ~p"/api/v1/tenants/#{org.id}", %{
        "name" => "My Updated Org"
      })

      assert %{"data" => tenant} = json_response(conn, 200)
      assert tenant["name"] == "My Updated Org"
    end
  end

  describe "DELETE /api/v1/tenants/:id" do
    test "deactivates tenant (soft delete)", %{admin_conn: conn} do
      org = insert(:organization, %{name: "To Delete", slug: "to-delete", is_active: true})

      conn = delete(conn, ~p"/api/v1/tenants/#{org.id}")

      assert %{"message" => _} = json_response(conn, 200)

      # Verify organization is deactivated
      updated = Repo.get!(Organization, org.id)
      refute updated.is_active
    end
  end

  describe "POST /api/v1/tenants/:id/suspend" do
    test "suspends tenant with reason", %{admin_conn: conn} do
      org = insert(:organization, %{name: "To Suspend", slug: "to-suspend", is_active: true})

      conn = post(conn, ~p"/api/v1/tenants/#{org.id}/suspend", %{
        "reason" => "Non-payment"
      })

      assert %{"data" => tenant, "message" => "Tenant suspended"} = json_response(conn, 200)
      assert tenant["is_active"] == false
    end

    test "suspends tenant without reason", %{admin_conn: conn} do
      org = insert(:organization, %{name: "Suspend No Reason", slug: "suspend-no-reason", is_active: true})

      conn = post(conn, ~p"/api/v1/tenants/#{org.id}/suspend", %{})

      assert %{"data" => tenant} = json_response(conn, 200)
      assert tenant["is_active"] == false
    end
  end

  describe "POST /api/v1/tenants/:id/reactivate" do
    test "reactivates suspended tenant", %{admin_conn: conn} do
      org = insert(:organization, %{name: "Suspended", slug: "suspended-org", is_active: false})

      conn = post(conn, ~p"/api/v1/tenants/#{org.id}/reactivate")

      assert %{"data" => tenant, "message" => "Tenant reactivated"} = json_response(conn, 200)
      assert tenant["is_active"] == true
    end
  end

  describe "POST /api/v1/tenants/provision" do
    test "provisions tenant with admin user", %{admin_conn: conn} do
      attrs = %{
        "organization" => %{
          "name" => "Provisioned Org",
          "slug" => "provisioned-org-#{System.unique_integer([:positive])}"
        },
        "admin" => %{
          "email" => "admin-#{System.unique_integer([:positive])}@provisioned.com",
          "password" => "SecurePassword123!",
          "name" => "Admin User"
        },
        "license_tier" => "enterprise"
      }

      conn = post(conn, ~p"/api/v1/tenants/provision", attrs)

      assert %{"data" => result} = json_response(conn, 201)
      assert result["tenant"]["slug"] =~ "provisioned-org"
      assert result["admin"]["email"] =~ "provisioned.com"
      assert is_integer(result["roles_created"])
      assert result["roles_created"] > 0
    end

    test "returns error for invalid admin email", %{admin_conn: conn} do
      attrs = %{
        "organization" => %{
          "name" => "Invalid Admin Org",
          "slug" => "invalid-admin-org-#{System.unique_integer([:positive])}"
        },
        "admin" => %{
          "email" => "not-an-email",
          "password" => "SecurePassword123!",
          "name" => "Admin User"
        }
      }

      conn = post(conn, ~p"/api/v1/tenants/provision", attrs)

      assert json_response(conn, 422)
    end
  end

  describe "TenantSuspension plug" do
    setup %{conn: conn} do
      # Create a suspended organization
      suspended_org = insert(:organization, %{
        name: "Suspended Tenant",
        slug: "suspended-tenant",
        is_active: false
      })

      suspended_user = insert(:user, %{
        organization_id: suspended_org.id,
        role: "analyst",
        email: "user@suspended.local"
      })

      {:ok, suspended_token, _} = TamanduaServer.Guardian.encode_and_sign(suspended_user)

      suspended_conn =
        conn
        |> put_req_header("accept", "application/json")
        |> put_req_header("authorization", "Bearer #{suspended_token}")

      %{
        suspended_conn: suspended_conn,
        suspended_org: suspended_org,
        suspended_user: suspended_user
      }
    end

    test "blocks requests from suspended tenant", %{suspended_conn: conn} do
      # Attempt to access a protected endpoint
      conn = get(conn, ~p"/api/v1/agents")

      assert %{"error" => "tenant_suspended"} = json_response(conn, 403)
    end

    test "allows health check even for suspended tenant", %{suspended_conn: conn} do
      conn = get(conn, ~p"/api/v1/health")

      # Health check should not be blocked
      assert conn.status in [200, 404]  # 404 if no health endpoint, 200 if exists
    end
  end
end
