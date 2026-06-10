defmodule TamanduaServer.Alerts.FilterBuilderTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.{Alert, FilterBuilder}
  alias TamanduaServer.Repo

  import Ecto.Query

  describe "validate_filter/1" do
    test "validates simple filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      assert {:ok, _validated} = FilterBuilder.validate_filter(filter)
    end

    test "validates nested filter groups" do
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

      assert {:ok, _validated} = FilterBuilder.validate_filter(filter)
    end

    test "validates quick filter" do
      filter = %{"quick_filter" => "high_severity"}

      assert {:ok, _validated} = FilterBuilder.validate_filter(filter)
    end

    test "rejects invalid quick filter" do
      filter = %{"quick_filter" => "invalid"}

      assert {:error, _reason} = FilterBuilder.validate_filter(filter)
    end

    test "rejects unsupported field" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "invalid_field", "operator" => "eq", "value" => "test"}
        ]
      }

      assert {:error, _reason} = FilterBuilder.validate_filter(filter)
    end

    test "rejects unsupported operator" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "invalid_op", "value" => "test"}
        ]
      }

      assert {:error, _reason} = FilterBuilder.validate_filter(filter)
    end

    test "validates is_null operator without value" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "assigned_to_id", "operator" => "is_null", "value" => nil}
        ]
      }

      assert {:ok, _validated} = FilterBuilder.validate_filter(filter)
    end

    test "validates array operators" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "mitre_technique", "operator" => "array_contains", "value" => "T1055"}
        ]
      }

      assert {:ok, _validated} = FilterBuilder.validate_filter(filter)
    end
  end

  describe "build_query/2" do
    setup do
      org = insert(:organization)
      {:ok, organization: org}
    end

    test "builds query for severity filter", %{organization: org} do
      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "low", organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 1
      assert hd(results).severity == "critical"
    end

    test "builds query for status filter", %{organization: org} do
      insert(:alert, status: "new", organization: org)
      insert(:alert, status: "resolved", organization: org)
      insert(:alert, status: "investigating", organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "status", "operator" => "in", "value" => ["new", "investigating"]}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "builds query for AND logic", %{organization: org} do
      insert(:alert, severity: "critical", status: "new", organization: org)
      insert(:alert, severity: "critical", status: "resolved", organization: org)
      insert(:alert, severity: "low", status: "new", organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"},
          %{"field" => "status", "operator" => "eq", "value" => "new"}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 1
    end

    test "builds query for OR logic", %{organization: org} do
      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "high", organization: org)
      insert(:alert, severity: "low", organization: org)

      filter = %{
        "logic" => "OR",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"},
          %{"field" => "severity", "operator" => "eq", "value" => "high"}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "builds query for nested groups", %{organization: org} do
      insert(:alert, severity: "critical", status: "new", organization: org)
      insert(:alert, severity: "critical", status: "investigating", organization: org)
      insert(:alert, severity: "high", status: "new", organization: org)
      insert(:alert, severity: "low", status: "resolved", organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{
            "logic" => "OR",
            "conditions" => [
              %{"field" => "severity", "operator" => "eq", "value" => "critical"},
              %{"field" => "severity", "operator" => "eq", "value" => "high"}
            ]
          },
          %{"field" => "status", "operator" => "eq", "value" => "new"}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "builds query for threat score comparison", %{organization: org} do
      insert(:alert, threat_score: 0.9, organization: org)
      insert(:alert, threat_score: 0.7, organization: org)
      insert(:alert, threat_score: 0.3, organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "threat_score", "operator" => "gte", "value" => 0.7}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "builds query for MITRE technique", %{organization: org} do
      insert(:alert, mitre_techniques: ["T1055", "T1059"], organization: org)
      insert(:alert, mitre_techniques: ["T1055"], organization: org)
      insert(:alert, mitre_techniques: ["T1486"], organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "mitre_technique", "operator" => "array_contains", "value" => "T1055"}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "builds query for is_null operator", %{organization: org} do
      insert(:alert, assigned_to_id: nil, organization: org)
      user = insert(:user, organization: org)
      insert(:alert, assigned_to_id: user.id, organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "assigned_to_id", "operator" => "is_null", "value" => nil}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 1
    end

    test "builds query for date range", %{organization: org} do
      now = DateTime.utc_now()
      yesterday = DateTime.add(now, -1, :day)
      week_ago = DateTime.add(now, -7, :day)

      insert(:alert, inserted_at: now, organization: org)
      insert(:alert, inserted_at: yesterday, organization: org)
      insert(:alert, inserted_at: week_ago, organization: org)

      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "created_at", "operator" => "gte", "value" => DateTime.to_iso8601(DateTime.add(now, -2, :day))}
        ]
      }

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "handles invalid filter gracefully", %{organization: org} do
      insert(:alert, organization: org)

      invalid_filter = %{"invalid" => "structure"}

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(invalid_filter)

      # Should return all results when filter is invalid
      results = Repo.all(query)
      assert length(results) == 1
    end
  end

  describe "quick filters" do
    setup do
      org = insert(:organization)
      {:ok, organization: org}
    end

    test "unresolved quick filter", %{organization: org} do
      insert(:alert, status: "new", organization: org)
      insert(:alert, status: "investigating", organization: org)
      insert(:alert, status: "resolved", organization: org)

      filter = %{"quick_filter" => "unresolved"}

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "high_severity quick filter", %{organization: org} do
      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "high", organization: org)
      insert(:alert, severity: "low", organization: org)

      filter = %{"quick_filter" => "high_severity"}

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      assert length(results) == 2
    end

    test "last_24h quick filter", %{organization: org} do
      now = DateTime.utc_now()
      yesterday = DateTime.add(now, -1, :day)
      two_days_ago = DateTime.add(now, -2, :day)

      insert(:alert, inserted_at: DateTime.add(now, -1, :hour), organization: org)
      insert(:alert, inserted_at: yesterday, organization: org)
      insert(:alert, inserted_at: two_days_ago, organization: org)

      filter = %{"quick_filter" => "last_24h"}

      query =
        Alert
        |> where([a], a.organization_id == ^org.id)
        |> FilterBuilder.build_query(filter)

      results = Repo.all(query)
      # Should include alerts from last 24 hours
      assert length(results) >= 1
    end
  end

  describe "to_url_params/1 and from_url_params/1" do
    test "encodes and decodes filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      encoded = FilterBuilder.to_url_params(filter)
      assert is_binary(encoded)

      {:ok, decoded} = FilterBuilder.from_url_params(encoded)
      assert decoded == filter
    end

    test "handles complex nested filter" do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
          %{
            "logic" => "OR",
            "conditions" => [
              %{"field" => "status", "operator" => "eq", "value" => "new"},
              %{"field" => "status", "operator" => "eq", "value" => "investigating"}
            ]
          }
        ]
      }

      encoded = FilterBuilder.to_url_params(filter)
      {:ok, decoded} = FilterBuilder.from_url_params(encoded)
      assert decoded == filter
    end

    test "handles invalid encoding" do
      assert {:error, _reason} = FilterBuilder.from_url_params("invalid-base64!")
    end
  end

  describe "supported_fields/0" do
    test "returns list of field metadata" do
      fields = FilterBuilder.supported_fields()

      assert is_list(fields)
      assert length(fields) > 0

      # Check structure of field metadata
      field = hd(fields)
      assert Map.has_key?(field, :name)
      assert Map.has_key?(field, :type)
      assert Map.has_key?(field, :operators)
    end

    test "includes all critical fields" do
      fields = FilterBuilder.supported_fields()
      field_names = Enum.map(fields, & &1.name)

      assert "severity" in field_names
      assert "status" in field_names
      assert "mitre_technique" in field_names
      assert "threat_score" in field_names
      assert "created_at" in field_names
    end
  end
end
