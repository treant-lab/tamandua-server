defmodule TamanduaServer.Filtering.FilterParserTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Filtering.FilterParser

  describe "validate/1" do
    test "validates simple AND filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      assert {:ok, validated} = FilterParser.validate(filter)
      assert validated == filter
    end

    test "validates nested OR filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
          %{
            "logic" => "OR",
            "conditions" => [
              %{"field" => "status", "operator" => "eq", "value" => "new"},
              %{"field" => "assigned_to_id", "operator" => "is_null"}
            ]
          }
        ]
      }

      assert {:ok, _validated} = FilterParser.validate(filter)
    end

    test "validates NOT filter with single condition" do
      filter = %{
        "logic" => "NOT",
        "conditions" => [
          %{"field" => "status", "operator" => "eq", "value" => "resolved"}
        ]
      }

      assert {:ok, _validated} = FilterParser.validate(filter)
    end

    test "rejects NOT filter with multiple conditions" do
      filter = %{
        "logic" => "NOT",
        "conditions" => [
          %{"field" => "status", "operator" => "eq", "value" => "resolved"},
          %{"field" => "severity", "operator" => "eq", "value" => "low"}
        ]
      }

      assert {:error, "NOT logic can only have one condition"} = FilterParser.validate(filter)
    end

    test "validates all comparison operators" do
      operators = ["eq", "ne", "gt", "gte", "lt", "lte"]

      for op <- operators do
        filter = %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => op, "value" => "critical"}
          ]
        }

        assert {:ok, _} = FilterParser.validate(filter)
      end
    end

    test "validates string operators" do
      operators = ["contains", "not_contains", "starts_with", "ends_with", "regex"]

      for op <- operators do
        filter = %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "process_name", "operator" => op, "value" => "test"}
          ]
        }

        assert {:ok, _} = FilterParser.validate(filter)
      end
    end

    test "validates array operators" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{
            "field" => "mitre_tactics",
            "operator" => "array_contains_any",
            "value" => ["persistence", "privilege-escalation"]
          }
        ]
      }

      assert {:ok, _} = FilterParser.validate(filter)
    end

    test "validates date operators" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "created_at", "operator" => "last_n_days", "value" => 7}
        ]
      }

      assert {:ok, _} = FilterParser.validate(filter)
    end

    test "validates geospatial operators" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{
            "field" => "location",
            "operator" => "within_radius",
            "value" => %{"lat" => 37.7749, "lon" => -122.4194, "radius_km" => 50}
          }
        ]
      }

      assert {:ok, _} = FilterParser.validate(filter)
    end

    test "validates between operator" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{
            "field" => "threat_score",
            "operator" => "between",
            "value" => %{"min" => 0.5, "max" => 1.0}
          }
        ]
      }

      assert {:ok, _} = FilterParser.validate(filter)
    end

    test "rejects unsupported operator" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "invalid_op", "value" => "critical"}
        ]
      }

      assert {:error, "Unsupported operator: invalid_op"} = FilterParser.validate(filter)
    end

    test "rejects invalid value for operator" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "in", "value" => "not_a_list"}
        ]
      }

      assert {:error, "Invalid value for operator in"} = FilterParser.validate(filter)
    end

    test "rejects filter without logic" do
      filter = %{
        "conditions" => []
      }

      assert {:error, _} = FilterParser.validate(filter)
    end

    test "accepts null value operators without value" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "assigned_to_id", "operator" => "is_null"}
        ]
      }

      assert {:ok, _} = FilterParser.validate(filter)
    end
  end

  describe "operator_metadata/0" do
    test "returns metadata for all operators" do
      metadata = FilterParser.operator_metadata()

      assert is_map(metadata)
      assert Map.has_key?(metadata, "eq")
      assert Map.has_key?(metadata, "contains")
      assert Map.has_key?(metadata, "within_radius")

      assert %{name: "Equals", value_type: :single, symbol: "="} = metadata["eq"]
      assert %{name: "Contains", value_type: :single} = metadata["contains"]
    end
  end

  describe "to_description/1" do
    test "generates description for simple filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      description = FilterParser.to_description(filter)
      assert description =~ "severity"
      assert description =~ "equals"
      assert description =~ "critical"
    end

    test "generates description for nested filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"},
          %{
            "logic" => "OR",
            "conditions" => [
              %{"field" => "status", "operator" => "eq", "value" => "new"},
              %{"field" => "status", "operator" => "eq", "value" => "investigating"}
            ]
          }
        ]
      }

      description = FilterParser.to_description(filter)
      assert description =~ "and"
      assert description =~ "or"
    end

    test "generates description for null operator" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "assigned_to_id", "operator" => "is_null"}
        ]
      }

      description = FilterParser.to_description(filter)
      assert description =~ "assigned to id"
      assert description =~ "is empty"
    end
  end

  describe "supported_operators/0" do
    test "returns list of all supported operators" do
      operators = FilterParser.supported_operators()

      assert is_list(operators)
      assert length(operators) >= 30
      assert "eq" in operators
      assert "contains" in operators
      assert "within_radius" in operators
      assert "last_n_days" in operators
    end
  end
end
