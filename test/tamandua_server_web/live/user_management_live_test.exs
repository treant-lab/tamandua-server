defmodule TamanduaServerWeb.UserManagementLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Accounts

  setup do
    # Create organization
    {:ok, org} =
      Accounts.create_organization(%{
        name: "Test Org",
        slug: "test-org",
        license_tier: :pro
      })

    # Create admin role and user
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

    # Assign admin role
    TamanduaServer.Authorization.RBAC.assign_role(admin_user, admin_role)

    # Create viewer role and user
    {:ok, viewer_role} =
      Accounts.create_role(%{
        name: "Viewer",
        slug: "viewer",
        builtin: true,
        priority: 10,
        organization_id: org.id
      })

    {:ok, viewer_user} =
      Accounts.create_user(%{
        email: "viewer@test.com",
        password: "password123",
        organization_id: org.id,
        is_active: true
      })

    TamanduaServer.Authorization.RBAC.assign_role(viewer_user, viewer_role)

    %{
      org: org,
      admin_user: admin_user,
      admin_role: admin_role,
      viewer_user: viewer_user,
      viewer_role: viewer_role
    }
  end

  describe "User Management Live - Authentication" do
    test "redirects when not authenticated", %{conn: conn} do
      {:error, {:redirect, %{to: "/login"}}} = live(conn, "/users")
    end

    test "redirects when user lacks permission", %{conn: conn, viewer_user: user} do
      conn = log_in_user(conn, user)
      {:error, {:redirect, %{to: "/"}}} = live(conn, "/users")
    end

    test "allows access for admin user", %{conn: conn, admin_user: user} do
      conn = log_in_user(conn, user)
      {:ok, _view, html} = live(conn, "/users")
      assert html =~ "User Management"
    end
  end

  describe "User Management Live - List Users" do
    test "displays all users in organization", %{
      conn: conn,
      admin_user: admin_user,
      viewer_user: viewer_user
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      assert has_element?(view, "td", admin_user.email)
      assert has_element?(view, "td", viewer_user.email)
    end

    test "filters users by search query", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Search for admin
      view
      |> element("input[name='query']")
      |> render_change(%{"query" => "admin"})

      assert has_element?(view, "td", "admin@test.com")
      refute has_element?(view, "td", "viewer@test.com")
    end

    test "filters users by role", %{
      conn: conn,
      admin_user: admin_user,
      admin_role: admin_role
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Filter by admin role
      view
      |> element("select[name='role']")
      |> render_change(%{"role_id" => admin_role.id})

      assert has_element?(view, "td", "admin@test.com")
      refute has_element?(view, "td", "viewer@test.com")
    end

    test "filters users by status", %{conn: conn, admin_user: admin_user} do
      # Create inactive user
      {:ok, inactive_user} =
        Accounts.create_user(%{
          email: "inactive@test.com",
          password: "password123",
          organization_id: admin_user.organization_id,
          is_active: false
        })

      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Filter by inactive status
      view
      |> element("select[name='status']")
      |> render_change(%{"status" => "inactive"})

      assert has_element?(view, "td", inactive_user.email)
      refute has_element?(view, "td", admin_user.email)
    end
  end

  describe "User Management Live - Create User" do
    test "opens create user modal", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button", "Create User")
      |> render_click()

      assert has_element?(view, "h2", "Create User")
    end

    test "creates new user with valid data", %{
      conn: conn,
      admin_user: admin_user,
      viewer_role: viewer_role
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Open modal
      view
      |> element("button", "Create User")
      |> render_click()

      # Submit form
      view
      |> form(".user-form", %{
        user: %{
          email: "newuser@test.com",
          name: "New User",
          password: "password123",
          role_ids: viewer_role.id,
          is_active: true
        }
      })
      |> render_submit()

      # Verify user was created
      assert has_element?(view, "td", "newuser@test.com")
      assert Accounts.get_user_by_email("newuser@test.com")
    end

    test "shows validation errors for invalid data", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Open modal
      view
      |> element("button", "Create User")
      |> render_click()

      # Submit with invalid email
      view
      |> form(".user-form", %{
        user: %{
          email: "invalid-email",
          password: "short"
        }
      })
      |> render_submit()

      assert has_element?(view, ".error")
    end
  end

  describe "User Management Live - Edit User" do
    test "opens edit user modal", %{conn: conn, admin_user: admin_user, viewer_user: viewer_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='edit_user'][phx-value-id='#{viewer_user.id}']")
      |> render_click()

      assert has_element?(view, "h2", "Edit User")
      assert has_element?(view, "input[value='#{viewer_user.email}']")
    end

    test "updates user with valid data", %{
      conn: conn,
      admin_user: admin_user,
      viewer_user: viewer_user
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      # Open edit modal
      view
      |> element("button[phx-click='edit_user'][phx-value-id='#{viewer_user.id}']")
      |> render_click()

      # Update name
      view
      |> form(".user-form", %{
        user: %{
          name: "Updated Name",
          email: viewer_user.email
        }
      })
      |> render_submit()

      # Verify update
      updated_user = Accounts.get_user(viewer_user.id)
      assert updated_user.name == "Updated Name"
    end
  end

  describe "User Management Live - Toggle Active Status" do
    test "deactivates active user", %{conn: conn, admin_user: admin_user, viewer_user: viewer_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='toggle_active'][phx-value-id='#{viewer_user.id}']")
      |> render_click()

      updated_user = Accounts.get_user(viewer_user.id)
      refute updated_user.is_active
      assert has_element?(view, ".status-badge.inactive")
    end

    test "activates inactive user", %{conn: conn, admin_user: admin_user} do
      {:ok, inactive_user} =
        Accounts.create_user(%{
          email: "inactive@test.com",
          password: "password123",
          organization_id: admin_user.organization_id,
          is_active: false
        })

      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='toggle_active'][phx-value-id='#{inactive_user.id}']")
      |> render_click()

      updated_user = Accounts.get_user(inactive_user.id)
      assert updated_user.is_active
    end
  end

  describe "User Management Live - Delete User" do
    test "deletes user successfully", %{conn: conn, admin_user: admin_user, viewer_user: viewer_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='delete_user'][phx-value-id='#{viewer_user.id}']")
      |> render_click()

      refute Accounts.get_user(viewer_user.id)
      refute has_element?(view, "td", viewer_user.email)
    end

    test "prevents self-deletion", %{conn: conn, admin_user: admin_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='delete_user'][phx-value-id='#{admin_user.id}']")
      |> render_click()

      # User should still exist
      assert Accounts.get_user(admin_user.id)
      assert has_element?(view, ".flash", "cannot delete your own account")
    end
  end

  describe "User Management Live - Role Assignment" do
    test "assigns role to user", %{
      conn: conn,
      admin_user: admin_user,
      viewer_user: viewer_user,
      admin_role: admin_role
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='assign_role']")
      |> render_click(%{
        "user_id" => viewer_user.id,
        "role_id" => admin_role.id
      })

      # Verify role was assigned
      user = Accounts.get_user_with_roles(viewer_user.id)
      assert Enum.any?(user.roles, &(&1.id == admin_role.id))
    end

    test "revokes role from user", %{
      conn: conn,
      admin_user: admin_user,
      viewer_user: viewer_user,
      viewer_role: viewer_role
    } do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      view
      |> element("button[phx-click='revoke_role']")
      |> render_click(%{
        "user_id" => viewer_user.id,
        "role_id" => viewer_role.id
      })

      # Verify role was revoked
      user = Accounts.get_user_with_roles(viewer_user.id)
      refute Enum.any?(user.roles, &(&1.id == viewer_role.id))
    end
  end

  describe "User Management Live - Password Reset" do
    test "resets user password", %{conn: conn, admin_user: admin_user, viewer_user: viewer_user} do
      conn = log_in_user(conn, admin_user)
      {:ok, view, _html} = live(conn, "/users")

      html =
        view
        |> element("button[phx-click='reset_password'][phx-value-id='#{viewer_user.id}']")
        |> render_click()

      # Should show temporary password in flash
      assert html =~ "Temporary password:"
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
