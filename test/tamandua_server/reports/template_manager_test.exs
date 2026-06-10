defmodule TamanduaServer.Reports.TemplateManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Reports.TemplateManager

  @valid_attrs %{
    name: "Test Template",
    description: "A test report template",
    category: "custom",
    layout: %{
      "orientation" => "portrait",
      "page_size" => "A4",
      "columns" => 12,
      "row_height" => 50
    },
    widgets: [
      %{
        "id" => "widget-1",
        "type" => "text",
        "title" => "Test Widget",
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 4, "height" => 2},
        "params" => %{"content" => "Test"}
      }
    ],
    branding: %{
      "company_name" => "Test Corp",
      "primary_color" => "#0066cc"
    }
  }

  describe "create_template/1" do
    test "creates template with valid attributes" do
      assert {:ok, template} = TemplateManager.create_template(@valid_attrs)
      assert template.name == "Test Template"
      assert template.category == "custom"
      assert length(template.widgets) == 1
    end

    test "returns error with invalid attributes" do
      assert {:error, changeset} = TemplateManager.create_template(%{})
      assert changeset.valid? == false
    end

    test "validates layout structure" do
      attrs = Map.put(@valid_attrs, :layout, %{"invalid" => "layout"})
      assert {:error, changeset} = TemplateManager.create_template(attrs)
      assert "missing required layout keys" in errors_on(changeset).layout
    end
  end

  describe "list_templates/1" do
    setup do
      {:ok, template1} = TemplateManager.create_template(@valid_attrs)
      {:ok, template2} = TemplateManager.create_template(Map.put(@valid_attrs, :name, "Template 2"))
      {:ok, template1: template1, template2: template2}
    end

    test "lists all templates", %{template1: t1, template2: t2} do
      templates = TemplateManager.list_templates()
      assert length(templates) >= 2
      assert Enum.any?(templates, &(&1.id == t1.id))
      assert Enum.any?(templates, &(&1.id == t2.id))
    end

    test "filters by category" do
      {:ok, compliance} = TemplateManager.create_template(Map.put(@valid_attrs, :category, "compliance"))

      templates = TemplateManager.list_templates(category: "compliance")
      assert Enum.all?(templates, &(&1.category == "compliance"))
      assert Enum.any?(templates, &(&1.id == compliance.id))
    end
  end

  describe "get_template/1" do
    test "returns template by ID" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)
      assert {:ok, found} = TemplateManager.get_template(template.id)
      assert found.id == template.id
    end

    test "returns error for non-existent ID" do
      assert {:error, :not_found} = TemplateManager.get_template(Ecto.UUID.generate())
    end
  end

  describe "update_template/2" do
    test "updates template" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)

      assert {:ok, updated} = TemplateManager.update_template(template.id, %{
        name: "Updated Name"
      })

      assert updated.name == "Updated Name"
      assert updated.version > template.version
    end

    test "increments version on widget change" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)
      original_version = template.version

      new_widgets = template.widgets ++ [
        %{
          "id" => "widget-2",
          "type" => "chart",
          "title" => "New Widget",
          "position" => %{"x" => 4, "y" => 0},
          "size" => %{"width" => 4, "height" => 2},
          "params" => %{}
        }
      ]

      assert {:ok, updated} = TemplateManager.update_template(template.id, %{
        widgets: new_widgets
      })

      assert updated.version == original_version + 1
    end
  end

  describe "delete_template/1" do
    test "deletes template" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)

      assert {:ok, _} = TemplateManager.delete_template(template.id)
      assert {:error, :not_found} = TemplateManager.get_template(template.id)
    end

    test "cannot delete system template" do
      {:ok, template} = TemplateManager.create_template(Map.put(@valid_attrs, :is_system, true))

      assert {:error, :cannot_delete_system_template} = TemplateManager.delete_template(template.id)
    end
  end

  describe "export_template/1 and import_template/1" do
    test "exports and imports template" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)

      assert {:ok, json} = TemplateManager.export_template(template.id)
      assert is_binary(json)

      assert {:ok, imported} = TemplateManager.import_template(json, [])
      assert imported.name == template.name
      assert imported.widgets == template.widgets
      assert imported.id != template.id  # Should have new ID
    end
  end

  describe "generate_from_template/3" do
    test "generates report from template" do
      {:ok, template} = TemplateManager.create_template(@valid_attrs)

      assert {:ok, report_data} = TemplateManager.generate_from_template(
        template.id,
        "2024-01-01",
        "2024-01-31",
        []
      )

      assert report_data["title"] == template.name
      assert is_list(report_data["sections"])
      assert length(report_data["sections"]) > 0
    end
  end
end
