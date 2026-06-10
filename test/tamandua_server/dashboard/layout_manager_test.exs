defmodule TamanduaServer.Dashboard.LayoutManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Dashboard.{Layout, LayoutManager}
  alias TamanduaServer.Accounts.{User, Organization}

  setup do
    # Create test organization
    {:ok, org} = %Organization{}
    |> Organization.changeset(%{
      name: "Test Org",
      domain: "test.example.com"
    })
    |> Repo.insert()

    # Create test user
    {:ok, user} = %User{}
    |> User.registration_changeset(%{
      email: "test@example.com",
      password: "password123",
      name: "Test User",
      role: "analyst",
      organization_id: org.id
    })
    |> Repo.insert()

    %{org: org, user: user}
  end

  describe "create_layout/1" do
    test "creates a user-specific layout", %{user: user, org: org} do
      attrs = %{
        name: "My Custom Dashboard",
        description: "Custom layout for testing",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}}
        ],
        settings: %{"gridColumns" => 12},
        user_id: user.id,
        organization_id: org.id
      }

      assert {:ok, layout} = LayoutManager.create_layout(attrs)
      assert layout.name == "My Custom Dashboard"
      assert layout.user_id == user.id
      assert layout.organization_id == org.id
      assert length(layout.widgets) == 1
      assert layout.version == 1
      refute layout.is_template
      refute layout.is_public
    end

    test "creates a role-based layout", %{org: org} do
      attrs = %{
        name: "Analyst Default",
        description: "Default layout for analysts",
        widgets: [
          %{"type" => "alert_volume", "x" => 0, "y" => 0, "w" => 8, "h" => 3, "settings" => %{}}
        ],
        settings: %{"gridColumns" => 12},
        role: "analyst",
        organization_id: org.id,
        is_default: true
      }

      assert {:ok, layout} = LayoutManager.create_layout(attrs)
      assert layout.name == "Analyst Default"
      assert layout.role == "analyst"
      assert is_nil(layout.user_id)
      assert layout.is_default
    end

    test "creates a public template", %{org: org} do
      attrs = %{
        name: "SOC Analyst Template",
        description: "Template for SOC analysts",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}}
        ],
        settings: %{"gridColumns" => 12},
        organization_id: org.id,
        is_template: true,
        is_public: true,
        template_category: "soc_analyst"
      }

      assert {:ok, layout} = LayoutManager.create_layout(attrs)
      assert layout.is_template
      assert layout.is_public
      assert layout.template_category == "soc_analyst"
    end

    test "validates widget configuration", %{user: user, org: org} do
      attrs = %{
        name: "Invalid Layout",
        widgets: [
          %{"type" => "invalid_widget", "x" => 0, "y" => 0, "w" => 4, "h" => 3}
        ],
        user_id: user.id,
        organization_id: org.id
      }

      assert {:error, changeset} = LayoutManager.create_layout(attrs)
      assert "contains invalid widget configuration" in errors_on(changeset).widgets
    end

    test "prevents both user_id and role being set", %{user: user, org: org} do
      attrs = %{
        name: "Conflicting Layout",
        widgets: [],
        user_id: user.id,
        role: "analyst",
        organization_id: org.id
      }

      assert {:error, changeset} = LayoutManager.create_layout(attrs)
      assert "layout cannot be both user-specific and role-based" in errors_on(changeset).base
    end
  end

  describe "update_layout/4" do
    test "updates layout and creates version", %{user: user, org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "Original",
        widgets: [],
        user_id: user.id,
        organization_id: org.id
      })

      new_widgets = [
        %{"type" => "alert_volume", "x" => 0, "y" => 0, "w" => 8, "h" => 3, "settings" => %{}}
      ]

      assert {:ok, updated} = LayoutManager.update_layout(
        layout,
        %{widgets: new_widgets},
        user.id,
        "Added alert volume widget"
      )

      assert updated.version == 2
      assert length(updated.widgets) == 1

      # Check version was created
      versions = LayoutManager.list_versions(updated.id)
      assert length(versions) == 2
      assert Enum.at(versions, 0).change_description == "Added alert volume widget"
    end
  end

  describe "get_active_layout/3" do
    test "returns user's default layout", %{user: user, org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "User Default",
        widgets: [],
        user_id: user.id,
        organization_id: org.id,
        is_default: true
      })

      active = LayoutManager.get_active_layout(user.id, org.id, "analyst")
      assert active.id == layout.id
    end

    test "falls back to role default when user has no default", %{user: user, org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "Role Default",
        widgets: [],
        role: "analyst",
        organization_id: org.id,
        is_default: true
      })

      active = LayoutManager.get_active_layout(user.id, org.id, "analyst")
      assert active.id == layout.id
    end

    test "creates built-in template when no defaults exist", %{user: user, org: org} do
      active = LayoutManager.get_active_layout(user.id, org.id, "analyst")
      assert active.name == "SOC Analyst Dashboard"
      assert active.is_template
    end
  end

  describe "clone_layout/4" do
    test "clones a layout for a user", %{user: user, org: org} do
      {:ok, source} = LayoutManager.create_layout(%{
        name: "Original Layout",
        description: "Source layout",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}}
        ],
        settings: %{"gridColumns" => 12},
        organization_id: org.id,
        is_template: true,
        is_public: true
      })

      assert {:ok, cloned} = LayoutManager.clone_layout(source.id, user.id, org.id)
      assert cloned.name == "Original Layout (Copy)"
      assert cloned.user_id == user.id
      assert cloned.cloned_from_id == source.id
      assert cloned.widgets == source.widgets
      refute cloned.is_template
      refute cloned.is_public

      # Check clone count incremented
      source = Repo.get!(Layout, source.id)
      assert source.clone_count == 1
    end

    test "allows custom name for clone", %{user: user, org: org} do
      {:ok, source} = LayoutManager.create_layout(%{
        name: "Original",
        widgets: [],
        organization_id: org.id,
        is_template: true,
        is_public: true
      })

      assert {:ok, cloned} = LayoutManager.clone_layout(source.id, user.id, org.id, "My Custom Name")
      assert cloned.name == "My Custom Name"
    end
  end

  describe "set_user_default/3" do
    test "sets a layout as user default and clears previous default", %{user: user, org: org} do
      {:ok, layout1} = LayoutManager.create_layout(%{
        name: "Layout 1",
        widgets: [],
        user_id: user.id,
        organization_id: org.id,
        is_default: true
      })

      {:ok, layout2} = LayoutManager.create_layout(%{
        name: "Layout 2",
        widgets: [],
        user_id: user.id,
        organization_id: org.id
      })

      assert {:ok, _} = LayoutManager.set_user_default(layout2.id, user.id, org.id)

      layout1 = Repo.get!(Layout, layout1.id)
      layout2 = Repo.get!(Layout, layout2.id)

      refute layout1.is_default
      assert layout2.is_default
    end
  end

  describe "export_layout/1 and import_layout/3" do
    test "exports and imports layout successfully", %{user: user, org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "Export Test",
        description: "Test layout export",
        widgets: [
          %{"type" => "alert_volume", "x" => 0, "y" => 0, "w" => 8, "h" => 3, "settings" => %{}}
        ],
        settings: %{"gridColumns" => 12},
        user_id: user.id,
        organization_id: org.id,
        tags: ["custom", "test"]
      })

      # Export
      assert {:ok, json} = LayoutManager.export_layout(layout.id)
      assert is_binary(json)

      # Import
      assert {:ok, imported} = LayoutManager.import_layout(json, user.id, org.id)
      assert imported.name == "Export Test"
      assert imported.description == "Test layout export"
      assert length(imported.widgets) == 1
      assert imported.tags == ["custom", "test"]
    end
  end

  describe "restore_version/3" do
    test "restores layout to previous version", %{user: user, org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "Version Test",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}}
        ],
        user_id: user.id,
        organization_id: org.id
      })

      # Update to add more widgets
      {:ok, updated} = LayoutManager.update_layout(
        layout,
        %{widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}},
          %{"type" => "alert_volume", "x" => 4, "y" => 0, "w" => 8, "h" => 3, "settings" => %{}}
        ]},
        user.id,
        "Added widgets"
      )

      assert length(updated.widgets) == 2

      # Restore to version 1
      {:ok, restored} = LayoutManager.restore_version(updated.id, 1, user.id)

      assert restored.version == 3
      assert length(restored.widgets) == 1
    end
  end

  describe "list_templates_by_category/2" do
    test "returns templates in specified category", %{org: org} do
      {:ok, _template1} = LayoutManager.create_layout(%{
        name: "SOC Template",
        widgets: [],
        organization_id: org.id,
        is_template: true,
        template_category: "soc_analyst"
      })

      {:ok, _template2} = LayoutManager.create_layout(%{
        name: "Executive Template",
        widgets: [],
        organization_id: org.id,
        is_template: true,
        template_category: "executive"
      })

      soc_templates = LayoutManager.list_templates_by_category("soc_analyst", org.id)
      assert length(soc_templates) == 1
      assert Enum.at(soc_templates, 0).name == "SOC Template"
    end
  end

  describe "search_layouts/3" do
    test "searches layouts by name", %{user: user, org: org} do
      {:ok, _} = LayoutManager.create_layout(%{
        name: "Custom Dashboard",
        widgets: [],
        user_id: user.id,
        organization_id: org.id
      })

      {:ok, _} = LayoutManager.create_layout(%{
        name: "Other Layout",
        widgets: [],
        user_id: user.id,
        organization_id: org.id
      })

      results = LayoutManager.search_layouts("Dashboard", org.id, user_id: user.id)
      assert length(results) == 1
      assert Enum.at(results, 0).name == "Custom Dashboard"
    end

    test "searches layouts by tags", %{user: user, org: org} do
      {:ok, _} = LayoutManager.create_layout(%{
        name: "Tagged Layout",
        widgets: [],
        tags: ["security", "monitoring"],
        user_id: user.id,
        organization_id: org.id
      })

      results = LayoutManager.search_layouts("security", org.id, user_id: user.id)
      assert length(results) == 1
    end
  end

  describe "increment_view_count/1" do
    test "increments view count for a layout", %{org: org} do
      {:ok, layout} = LayoutManager.create_layout(%{
        name: "View Test",
        widgets: [],
        organization_id: org.id,
        is_template: true,
        is_public: true
      })

      assert layout.view_count == 0

      LayoutManager.increment_view_count(layout.id)
      LayoutManager.increment_view_count(layout.id)

      layout = Repo.get!(Layout, layout.id)
      assert layout.view_count == 2
    end
  end
end
