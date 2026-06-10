defmodule TamanduaServerWeb.RoleLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Accounts
  alias TamanduaServer.Authorization.RBAC

  setup do
    # Create organization
    {:ok, org} =
      Accounts.create_organization(%{
        name: "Test Org",
        slug: "test-org",
        license_tier: :pro
      })

    # Create admin user with permissions
    {:ok, admin_role} =
      Accounts.create_role(%{
        name: "Admin",
        slug: "admin",
        builtin: true,
        priority: 100,
        organization_id: org.id
      })

    {:ok, admin_user} =
      Accounts.create_user(%{
        email: "admin@test.com",
        password: "password123",
        organization_id: org.id,
        is_active: true
      })

    RBAC.assign_role(admin_user, admin_role)

    %{
      org: org,
      admin_user: admin_user,
      admin_role: admin_role
    }
  end

  describe "Role Management Live - Authentication" do
    test "redirects when not authenticated", %{conn: conn} do
      {:error, {:redirect, %{to: "/login"}}} = live(conn, "/roles")
    end

    test "allows access for admin user", %{conn: conn, admin_user: user} do
      conn = log_in_user(conn, user)
      {:ok, _view, html} = live(conn, "/roles")
      assert html =~ "Role Management"
    end
  end

  describe "Role Management Live - List Roles" do
    test "displays all roles", %{conn: conn, admin_user: admin_user, admin_role: admin_role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      assert has_element?(view, "h3", admin_role.name)
    end

    test "shows builtin badge for builtin roles", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      assert has_element?(view, ".badge-builtin", "Built-in")
    end

    test "displays user and permission counts", %{
      conn: conn,
      admin_user: admin_user,
      org: org
    } do
      # Create custom role
      {:ok, role} =
        RBAC.create_role(
          %{
            name: "Custom Role",
            slug: "custom",
            organization_id: org.id
          },
          [:alerts_read, :events_read]
        )

      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Should show permission count
      assert has_element?(view, ".stat-value", "2")
    end
  end

  describe "Role Management Live - Create Role" do
    test "opens create role modal", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button", "Create Role")
      |> render_click()

      assert has_element?(view, "h2", "Create Role")
    end

    test "shows template selector", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button", "Create Role")
      |> render_click()

      assert has_element?(view, "h3", "Start from a template")
      assert has_element?(view, ".template-card", "Blank Role")
    end

    test "creates role from template", %{conn: conn, admin_user: admin_user, org: org} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open modal
      view
      |> element("button", "Create Role")
      |> render_click()

      # Select template
      view
      |> element(".template-card[phx-value-template='security_analyst']")
      |> render_click()

      # Submit form
      view
      |> form(".role-form", %{
        role: %{
          name: "Security Analyst",
          slug: "security_analyst",
          description: "Security analyst role",
          priority: 50
        }
      })
      |> render_submit()

      # Verify role was created
      role = Accounts.get_role_by_slug(org.id, "security_analyst")
      assert role
      assert role.name == "Security Analyst"
    end

    test "creates blank role with selected permissions", %{
      conn: conn,
      admin_user: admin_user,
      org: org
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open modal
      view
      |> element("button", "Create Role")
      |> render_click()

      # Create blank
      view
      |> element(".template-card", "Blank Role")
      |> render_click()

      # Select some permissions
      view
      |> element("input[phx-value-permission='alerts_read']")
      |> render_click()

      view
      |> element("input[phx-value-permission='alerts_update']")
      |> render_click()

      # Submit form
      view
      |> form(".role-form", %{
        role: %{
          name: "Custom Role",
          slug: "custom_role",
          description: "Custom role",
          priority: 30
        }
      })
      |> render_submit()

      # Verify role and permissions
      role = Accounts.get_role_by_slug(org.id, "custom_role")
      assert role
      permissions = Accounts.get_role_permissions(role)
      assert :alerts_read in permissions
      assert :alerts_update in permissions
    end

    test "validates required fields", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open modal
      view
      |> element("button", "Create Role")
      |> render_click()

      # Create blank
      view
      |> element(".template-card", "Blank Role")
      |> render_click()

      # Submit without required fields
      view
      |> form(".role-form", %{
        role: %{
          name: "",
          slug: ""
        }
      })
      |> render_submit()

      assert has_element?(view, ".error")
    end
  end

  describe "Role Management Live - Edit Role" do
    setup %{org: org} do
      {:ok, role} =
        RBAC.create_role(
          %{
            name: "Test Role",
            slug: "test_role",
            organization_id: org.id
          },
          [:alerts_read]
        )

      %{role: role}
    end

    test "opens edit role modal", %{conn: conn, admin_user: admin_user, role: role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button[phx-click='edit_role'][phx-value-id='#{role.id}']")
      |> render_click()

      assert has_element?(view, "h2", "Edit Role")
      assert has_element?(view, "input[value='#{role.name}']")
    end

    test "updates role and permissions", %{conn: conn, admin_user: admin_user, role: role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open edit modal
      view
      |> element("button[phx-click='edit_role'][phx-value-id='#{role.id}']")
      |> render_click()

      # Add another permission
      view
      |> element("input[phx-value-permission='alerts_update']")
      |> render_click()

      # Update name
      view
      |> form(".role-form", %{
        role: %{
          name: "Updated Role",
          slug: role.slug,
          description: "Updated description"
        }
      })
      |> render_submit()

      # Verify updates
      updated_role = Accounts.get_role(role.id)
      assert updated_role.name == "Updated Role"
      assert updated_role.description == "Updated description"

      permissions = Accounts.get_role_permissions(updated_role)
      assert :alerts_read in permissions
      assert :alerts_update in permissions
    end

    test "prevents editing builtin roles", %{conn: conn, admin_user: admin_user, admin_role: admin_role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open edit modal for builtin role
      view
      |> element("button[phx-click='edit_role'][phx-value-id='#{admin_role.id}']")
      |> render_click()

      # Form fields should be disabled
      assert has_element?(view, "input[disabled][name='role[name]']")
    end
  end

  describe "Role Management Live - Clone Role" do
    setup %{org: org} do
      {:ok, role} =
        RBAC.create_role(
          %{
            name: "Original Role",
            slug: "original",
            organization_id: org.id,
            priority: 50
          },
          [:alerts_read, :events_read]
        )

      %{role: role}
    end

    test "clones role with permissions", %{conn: conn, admin_user: admin_user, role: role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button[phx-click='clone_role'][phx-value-id='#{role.id}']")
      |> render_click()

      assert has_element?(view, "h2", "Create Role")
      assert has_element?(view, "input[value='Original Role (Copy)']")

      # Permissions should be pre-selected
      assert has_element?(view, "input[checked][phx-value-permission='alerts_read']")
      assert has_element?(view, "input[checked][phx-value-permission='events_read']")
    end
  end

  describe "Role Management Live - Delete Role" do
    setup %{org: org} do
      {:ok, role} =
        RBAC.create_role(
          %{
            name: "Deletable Role",
            slug: "deletable",
            organization_id: org.id
          },
          []
        )

      %{role: role}
    end

    test "deletes custom role", %{conn: conn, admin_user: admin_user, role: role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button[phx-click='delete_role'][phx-value-id='#{role.id}']")
      |> render_click()

      # Role should be deleted
      refute Accounts.get_role(role.id)
      refute has_element?(view, "h3", "Deletable Role")
    end

    test "prevents deleting builtin roles", %{conn: conn, admin_user: admin_user, admin_role: admin_role} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      view
      |> element("button[phx-click='delete_role'][phx-value-id='#{admin_role.id}']")
      |> render_click()

      # Role should still exist
      assert Accounts.get_role(admin_role.id)
      assert has_element?(view, ".flash", "Cannot delete builtin roles")
    end
  end

  describe "Role Management Live - Permission Selection" do
    test "selects individual permission", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open create modal
      view
      |> element("button", "Create Role")
      |> render_click()

      view
      |> element(".template-card", "Blank Role")
      |> render_click()

      # Click permission checkbox
      view
      |> element("input[phx-value-permission='alerts_read']")
      |> render_click()

      # Should be checked
      assert has_element?(view, "input[checked][phx-value-permission='alerts_read']")
    end

    test "selects all permissions in category", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open create modal
      view
      |> element("button", "Create Role")
      |> render_click()

      view
      |> element(".template-card", "Blank Role")
      |> render_click()

      # Click category header
      view
      |> element(".category-header[phx-value-category='alerts']")
      |> render_click()

      # All alerts permissions should be checked
      assert has_element?(view, "input[checked][phx-value-permission='alerts_read']")
      assert has_element?(view, "input[checked][phx-value-permission='alerts_create']")
      assert has_element?(view, "input[checked][phx-value-permission='alerts_update']")
    end

    test "deselects all permissions in category", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/roles")

      # Open create modal
      view
      |> element("button", "Create Role")
      |> render_click()

      view
      |> element(".template-card", "Blank Role")
      |> render_click()

      # Select all in category
      view
      |> element(".category-header[phx-value-category='alerts']")
      |> render_click()

      # Deselect all in category
      view
      |> element(".category-header[phx-value-category='alerts']")
      |> render_click()

      # All should be unchecked
      refute has_element?(view, "input[checked][phx-value-permission='alerts_read']")
      refute has_element?(view, "input[checked][phx-value-permission='alerts_create']")
    end
  end

  # Helper functions

  defp log_in_user(conn, user) do
    token = Accounts.generate_user_session_token(user)

    conn
    |> init_test_session(%{})
    |> put_session(:user_token, token)
  end
end
