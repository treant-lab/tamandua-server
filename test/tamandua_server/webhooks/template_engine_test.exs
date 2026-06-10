defmodule TamanduaServer.Webhooks.TemplateEngineTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Webhooks.TemplateEngine

  describe "render/2" do
    test "renders simple liquid template" do
      template = "Alert: {{ alert.title }} - Severity: {{ alert.severity }}"
      data = %{"alert" => %{"title" => "Malware Detected", "severity" => "critical"}}

      assert {:ok, rendered} = TemplateEngine.render(template, data)
      assert rendered =~ "Alert: Malware Detected"
      assert rendered =~ "Severity: critical"
    end

    test "renders template with filters" do
      template = "{{ alert.severity | upcase }}"
      data = %{"alert" => %{"severity" => "high"}}

      assert {:ok, rendered} = TemplateEngine.render(template, data)
      assert rendered =~ "HIGH"
    end

    test "renders template with conditionals" do
      template = """
      {% if alert.severity == "critical" %}
      URGENT
      {% else %}
      NORMAL
      {% endif %}
      """

      data = %{"alert" => %{"severity" => "critical"}}

      assert {:ok, rendered} = TemplateEngine.render(template, data)
      assert rendered =~ "URGENT"
    end

    test "returns error for invalid template" do
      template = "{{ unclosed"
      data = %{}

      assert {:error, _reason} = TemplateEngine.render(template, data)
    end

    test "returns data when template is nil" do
      assert {:ok, %{"test" => "data"}} = TemplateEngine.render(nil, %{"test" => "data"})
    end
  end

  describe "validate_template/1" do
    test "validates correct template" do
      template = "{{ alert.id }}"
      assert :ok = TemplateEngine.validate_template(template)
    end

    test "returns error for invalid template" do
      template = "{% if unclosed"
      assert {:error, _reason} = TemplateEngine.validate_template(template)
    end

    test "validates nil template" do
      assert :ok = TemplateEngine.validate_template(nil)
    end
  end

  describe "builtin_templates/0" do
    test "returns all pre-built templates" do
      templates = TemplateEngine.builtin_templates()

      assert is_map(templates)
      assert Map.has_key?(templates, "slack")
      assert Map.has_key?(templates, "microsoft_teams")
      assert Map.has_key?(templates, "generic_json")
      assert Map.has_key?(templates, "pagerduty")
    end
  end

  describe "get_builtin_template/1" do
    test "returns slack template" do
      template = TemplateEngine.get_builtin_template("slack")
      assert is_binary(template)
      assert template =~ "blocks"
    end

    test "returns nil for unknown template" do
      assert is_nil(TemplateEngine.get_builtin_template("unknown"))
    end
  end

  describe "extract_variables/1" do
    test "extracts variable names from template" do
      template = "{{ alert.id }} {{ alert.severity }} {{ timestamp }}"
      variables = TemplateEngine.extract_variables(template)

      assert "alert.id" in variables
      assert "alert.severity" in variables
      assert "timestamp" in variables
    end

    test "handles variables with filters" do
      template = "{{ alert.severity | upcase }}"
      variables = TemplateEngine.extract_variables(template)

      assert "alert.severity" in variables
    end

    test "returns unique variables" do
      template = "{{ alert.id }} {{ alert.id }}"
      variables = TemplateEngine.extract_variables(template)

      assert length(variables) == 1
    end
  end

  describe "available_variables/0" do
    test "returns available variables for each event type" do
      variables = TemplateEngine.available_variables()

      assert is_map(variables)
      assert Map.has_key?(variables, "alert.created")
      assert Map.has_key?(variables, "agent.connected")

      alert_vars = variables["alert.created"]
      assert "data.alert.id" in alert_vars
      assert "data.alert.severity" in alert_vars
    end
  end
end
