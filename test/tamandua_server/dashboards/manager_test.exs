defmodule TamanduaServer.Dashboards.ManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Dashboards.{Manager, Layout, Widget}
  alias TamanduaServer.Repo

  describe "list_user_layouts/1" do
    test "returns all layouts for a user" do
      user_id = Ecto.UUID.generate()

      {:ok, layout1} = Manager.create_layout(%{user_id: user_id, name: "Layout 1"})
      {:ok, layout2} = Manager.create_layout(%{user_id: user_id, name: "Layout 2"})

      layouts = Manager.list_user_layouts(user_id)

      assert length(layouts) == 2
      assert Enum.any?(layouts, &(&1.id == layout1.id))
      assert Enum.any?(layouts, &(&1.id == layout2.id))
    end

    test "does not return layouts from other users" do
      user1_id = Ecto.UUID.generate()
      user2_id = Ecto.UUID.generate()

      {:ok, _layout1} = Manager.create_layout(%{user_id: user1_id, name: "Layout 1"})
      {:ok, _layout2} = Manager.create_layout(%{user_id: user2_id, name: "Layout 2"})

      layouts = Manager.list_user_layouts(user1_id)

      assert length(layouts) == 1
    end
  end

  describe "get_or_create_default_layout/2" do
    test "creates a default layout if none exists" do
      user_id = Ecto.UUID.generate()

      {:ok, layout} = Manager.get_or_create_default_layout(user_id)

      assert layout.user_id == user_id
      assert layout.is_default == true
      assert layout.name == "Default Dashboard"
    end

    test "returns existing default layout" do
      user_id = Ecto.UUID.generate()

      {:ok, layout1} = Manager.get_or_create_default_layout(user_id)
      {:ok, layout2} = Manager.get_or_create_default_layout(user_id)

      assert layout1.id == layout2.id
    end

    test "creates default widgets from SOC analyst template" do
      user_id = Ecto.UUID.generate()

      {:ok, layout} = Manager.get_or_create_default_layout(user_id)

      widgets = Manager.list_layout_widgets(layout.id)

      assert length(widgets) > 0
    end
  end

  describe "create_from_template/3" do
    test "creates layout from SOC analyst template" do
      user_id = Ecto.UUID.generate()

      {:ok, layout} = Manager.create_from_template(user_id, "soc_analyst")

      assert layout.user_id == user_id
      assert layout.template_type == "soc_analyst"
      assert String.contains?(layout.name, "Soc analyst")

      widgets = Manager.list_layout_widgets(layout.id)
      assert length(widgets) > 0
    end

    test "creates layout from executive template" do
      user_id = Ecto.UUID.generate()

      {:ok, layout} = Manager.create_from_template(user_id, "executive")

      assert layout.template_type == "executive"

      widgets = Manager.list_layout_widgets(layout.id)
      assert length(widgets) > 0
    end
  end

  describe "set_default_layout/2" do
    test "sets a layout as default and unsets others" do
      user_id = Ecto.UUID.generate()

      {:ok, layout1} = Manager.create_layout(%{user_id: user_id, name: "Layout 1", is_default: true})
      {:ok, layout2} = Manager.create_layout(%{user_id: user_id, name: "Layout 2"})

      {:ok, _} = Manager.set_default_layout(layout2.id, user_id)

      layout1_updated = Repo.get!(Layout, layout1.id)
      layout2_updated = Repo.get!(Layout, layout2.id)

      assert layout1_updated.is_default == false
      assert layout2_updated.is_default == true
    end

    test "returns error if user does not own layout" do
      user1_id = Ecto.UUID.generate()
      user2_id = Ecto.UUID.generate()

      {:ok, layout} = Manager.create_layout(%{user_id: user1_id, name: "Layout 1"})

      {:error, :unauthorized} = Manager.set_default_layout(layout.id, user2_id)
    end
  end

  describe "create_widget/1" do
    test "creates a widget with valid attributes" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      attrs = %{
        dashboard_layout_id: layout.id,
        widget_type: "threat_level_gauge",
        title: "Threat Level",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      }

      {:ok, widget} = Manager.create_widget(attrs)

      assert widget.widget_type == "threat_level_gauge"
      assert widget.title == "Threat Level"
      assert widget.position_x == 0
      assert widget.position_y == 0
    end

    test "returns error with invalid widget type" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      attrs = %{
        dashboard_layout_id: layout.id,
        widget_type: "invalid_type",
        title: "Test Widget",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      }

      {:error, changeset} = Manager.create_widget(attrs)

      assert changeset.errors[:widget_type] != nil
    end
  end

  describe "update_widget_positions/1" do
    test "updates multiple widget positions" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      {:ok, widget1} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "threat_level_gauge",
        title: "Widget 1",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      })

      {:ok, widget2} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "top_detections",
        title: "Widget 2",
        position_x: 4,
        position_y: 0,
        width: 4,
        height: 3
      })

      positions = [
        %{"id" => widget1.id, "position_x" => 2, "position_y" => 1, "width" => 6, "height" => 4},
        %{"id" => widget2.id, "position_x" => 0, "position_y" => 5, "width" => 4, "height" => 3}
      ]

      {:ok, _} = Manager.update_widget_positions(positions)

      widget1_updated = Repo.get!(Widget, widget1.id)
      widget2_updated = Repo.get!(Widget, widget2.id)

      assert widget1_updated.position_x == 2
      assert widget1_updated.position_y == 1
      assert widget1_updated.width == 6
      assert widget1_updated.height == 4

      assert widget2_updated.position_x == 0
      assert widget2_updated.position_y == 5
    end
  end

  describe "fetch_widget_data/1" do
    test "fetches data for threat_level_gauge widget" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      {:ok, widget} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "threat_level_gauge",
        title: "Threat Level",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      })

      {:ok, data} = Manager.fetch_widget_data(widget)

      assert Map.has_key?(data, :critical)
      assert Map.has_key?(data, :high)
      assert Map.has_key?(data, :medium)
      assert Map.has_key?(data, :low)
      assert Map.has_key?(data, :total)
    end

    test "fetches data for agent_status_overview widget" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      {:ok, widget} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "agent_status_overview",
        title: "Agent Status",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      })

      {:ok, data} = Manager.fetch_widget_data(widget)

      assert Map.has_key?(data, :total)
      assert Map.has_key?(data, :online)
      assert Map.has_key?(data, :offline)
      assert Map.has_key?(data, :error)
    end
  end

  describe "export_layout/1" do
    test "exports layout to JSON" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{
        user_id: user_id,
        name: "Test Layout",
        description: "Test description",
        template_type: "custom"
      })

      {:ok, _widget} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "threat_level_gauge",
        title: "Threat Level",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      })

      {:ok, json} = Manager.export_layout(layout)

      assert is_binary(json)

      {:ok, data} = Jason.decode(json)

      assert data["name"] == "Test Layout"
      assert data["description"] == "Test description"
      assert length(data["widgets"]) == 1
    end
  end

  describe "import_layout/3" do
    test "imports layout from JSON" do
      user_id = Ecto.UUID.generate()

      json = ~s({
        "name": "Imported Dashboard",
        "description": "Imported from JSON",
        "template_type": "custom",
        "widgets": [
          {
            "widget_type": "threat_level_gauge",
            "title": "Threat Level",
            "position_x": 0,
            "position_y": 0,
            "width": 4,
            "height": 3,
            "config": {}
          }
        ]
      })

      {:ok, layout} = Manager.import_layout(user_id, json)

      assert layout.name == "Imported Dashboard"
      assert layout.description == "Imported from JSON"
      assert length(layout.widgets) == 1
      assert hd(layout.widgets).widget_type == "threat_level_gauge"
    end

    test "returns error for invalid JSON" do
      user_id = Ecto.UUID.generate()

      json = "invalid json"

      {:error, "Invalid JSON"} = Manager.import_layout(user_id, json)
    end
  end

  describe "delete_layout/1" do
    test "deletes layout and all its widgets" do
      user_id = Ecto.UUID.generate()
      {:ok, layout} = Manager.create_layout(%{user_id: user_id, name: "Test Layout"})

      {:ok, widget} = Manager.create_widget(%{
        dashboard_layout_id: layout.id,
        widget_type: "threat_level_gauge",
        title: "Widget",
        position_x: 0,
        position_y: 0,
        width: 4,
        height: 3
      })

      {:ok, _} = Manager.delete_layout(layout)

      assert Repo.get(Layout, layout.id) == nil
      assert Repo.get(Widget, widget.id) == nil
    end
  end
end
