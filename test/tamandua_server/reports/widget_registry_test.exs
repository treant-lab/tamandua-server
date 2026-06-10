defmodule TamanduaServer.Reports.WidgetRegistryTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Reports.WidgetRegistry

  describe "list_widgets/0" do
    test "returns all available widgets" do
      widgets = WidgetRegistry.list_widgets()

      assert length(widgets) > 0
      assert Enum.all?(widgets, fn w ->
        Map.has_key?(w, :type) &&
        Map.has_key?(w, :name) &&
        Map.has_key?(w, :description)
      end)
    end

    test "widgets are sorted by name" do
      widgets = WidgetRegistry.list_widgets()
      names = Enum.map(widgets, & &1.name)
      assert names == Enum.sort(names)
    end
  end

  describe "get_widget/1" do
    test "returns widget module for valid type" do
      assert {:ok, _module} = WidgetRegistry.get_widget("text")
      assert {:ok, _module} = WidgetRegistry.get_widget("chart")
      assert {:ok, _module} = WidgetRegistry.get_widget("table")
    end

    test "returns error for unknown widget type" do
      assert {:error, :unknown_widget} = WidgetRegistry.get_widget("unknown")
    end
  end

  describe "validate_widget/1" do
    test "validates widget with valid configuration" do
      config = %{
        "id" => "widget-1",
        "type" => "text",
        "title" => "Test Widget",
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 4, "height" => 2},
        "params" => %{"content" => "Hello World"}
      }

      assert {:ok, validated} = WidgetRegistry.validate_widget(config)
      assert validated["type"] == "text"
    end

    test "returns error for missing required fields" do
      config = %{"title" => "Test"}

      assert {:error, _reason} = WidgetRegistry.validate_widget(config)
    end

    test "returns error for unknown widget type" do
      config = %{
        "id" => "widget-1",
        "type" => "unknown",
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 4, "height" => 2}
      }

      assert {:error, :unknown_widget} = WidgetRegistry.validate_widget(config)
    end
  end

  describe "render_widget/2" do
    test "renders text widget" do
      config = %{
        "id" => "widget-1",
        "type" => "text",
        "title" => "Test Text",
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 4, "height" => 2},
        "params" => %{"content" => "Test content"}
      }

      context = %{
        date_from: "2024-01-01",
        date_to: "2024-01-31",
        organization_id: nil,
        user: nil
      }

      assert {:ok, rendered} = WidgetRegistry.render_widget(config, context)
      assert rendered["type"] == "text"
      assert rendered["title"] == "Test Text"
      assert is_binary(rendered["content"])
    end

    test "renders chart widget" do
      config = %{
        "id" => "widget-2",
        "type" => "chart",
        "title" => "Test Chart",
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 6, "height" => 4},
        "params" => %{
          "chart_type" => "bar",
          "data_source" => "alerts_by_severity"
        }
      }

      context = %{
        date_from: "2024-01-01",
        date_to: "2024-01-31",
        organization_id: nil,
        user: nil
      }

      assert {:ok, rendered} = WidgetRegistry.render_widget(config, context)
      assert rendered["type"] == "chart"
      assert is_map(rendered["content"])
      assert rendered["content"]["chart_type"] == "bar"
    end
  end

  describe "get_default_config/1" do
    test "returns default configuration for widget type" do
      assert {:ok, config} = WidgetRegistry.get_default_config("text")

      assert config["type"] == "text"
      assert is_binary(config["id"])
      assert is_map(config["params"])
      assert is_map(config["position"])
      assert is_map(config["size"])
    end

    test "returns error for unknown widget type" do
      assert {:error, :unknown_widget} = WidgetRegistry.get_default_config("unknown")
    end
  end
end
