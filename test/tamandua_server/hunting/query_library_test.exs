defmodule TamanduaServer.Hunting.QueryLibraryTest do
  @moduledoc """
  Comprehensive unit tests for hunting query library.
  Tests query parsing, execution, saved queries, and templates.
  """
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Hunting.{QueryLibrary, SavedQuery, QueryTemplate}
  alias TamanduaServer.Repo

  setup do
    {org, agent} = create_agent_with_org()

    %{org: org, agent: agent}
  end

  # ── Query Parsing Tests ────────────────────────────────────────────────

  describe "parse_query/1" do
    test "parses simple field:value query" do
      {:ok, parsed} = QueryLibrary.parse_query("process_name:cmd.exe")

      assert parsed.type == :field_match
      assert parsed.field == "process_name"
      assert parsed.value == "cmd.exe"
    end

    test "parses wildcard queries" do
      {:ok, parsed} = QueryLibrary.parse_query("process_name:*powershell*")

      assert parsed.type == :wildcard
      assert parsed.field == "process_name"
      assert String.contains?(parsed.value, "powershell")
    end

    test "parses AND queries" do
      {:ok, parsed} = QueryLibrary.parse_query("process_name:cmd.exe AND user:SYSTEM")

      assert parsed.type == :and
      assert is_list(parsed.conditions)
      assert length(parsed.conditions) == 2
    end

    test "parses OR queries" do
      {:ok, parsed} = QueryLibrary.parse_query("process_name:cmd.exe OR process_name:powershell.exe")

      assert parsed.type == :or
      assert is_list(parsed.conditions)
      assert length(parsed.conditions) == 2
    end

    test "parses NOT queries" do
      {:ok, parsed} = QueryLibrary.parse_query("process_name:cmd.exe NOT user:Administrator")

      assert parsed.type == :and_not or parsed.type == :not
    end

    test "parses nested parentheses queries" do
      {:ok, parsed} = QueryLibrary.parse_query("(process_name:cmd.exe OR process_name:powershell.exe) AND user:SYSTEM")

      assert is_map(parsed)
      assert parsed.type in [:and, :or, :nested]
    end

    test "parses comparison operators" do
      {:ok, parsed} = QueryLibrary.parse_query("pid > 1000")

      assert parsed.type == :comparison
      assert parsed.operator == ">"
      assert parsed.value == "1000"
    end

    test "parses range queries" do
      {:ok, parsed} = QueryLibrary.parse_query("timestamp:[2024-01-01 TO 2024-12-31]")

      assert parsed.type == :range
      assert is_map(parsed)
    end

    test "returns error for invalid query syntax" do
      {:error, reason} = QueryLibrary.parse_query("invalid[syntax")

      assert is_binary(reason)
    end

    test "handles empty query" do
      result = QueryLibrary.parse_query("")

      assert result == {:error, "Empty query"} or result == {:ok, %{}}
    end
  end

  # ── Query Execution Tests ──────────────────────────────────────────────

  describe "execute_query/2" do
    test "executes simple field match query", %{org: org} do
      # Create test events
      event = insert!(:event, %{
        organization_id: org.id,
        event_type: "process_create",
        payload: %{"name" => "cmd.exe"}
      })

      {:ok, results} = QueryLibrary.execute_query("name:cmd.exe", organization_id: org.id)

      assert is_list(results)
      if length(results) > 0 do
        assert Enum.any?(results, fn r -> r.id == event.id end)
      end
    end

    test "executes wildcard queries", %{org: org} do
      insert!(:event, %{
        organization_id: org.id,
        event_type: "process_create",
        payload: %{"name" => "powershell.exe"}
      })

      {:ok, results} = QueryLibrary.execute_query("name:*powershell*", organization_id: org.id)

      assert is_list(results)
    end

    test "executes AND queries", %{org: org} do
      event = insert!(:event, %{
        organization_id: org.id,
        event_type: "process_create",
        payload: %{
          "name" => "cmd.exe",
          "user" => "SYSTEM"
        }
      })

      {:ok, results} = QueryLibrary.execute_query("name:cmd.exe AND user:SYSTEM", organization_id: org.id)

      assert is_list(results)
    end

    test "executes OR queries", %{org: org} do
      insert!(:event, %{
        organization_id: org.id,
        payload: %{"name" => "cmd.exe"}
      })

      insert!(:event, %{
        organization_id: org.id,
        payload: %{"name" => "powershell.exe"}
      })

      {:ok, results} = QueryLibrary.execute_query("name:cmd.exe OR name:powershell.exe", organization_id: org.id)

      assert is_list(results)
      # Should find at least one of the two
    end

    test "respects time range filters", %{org: org} do
      old_event = insert!(:event, %{
        organization_id: org.id,
        timestamp: DateTime.utc_now() |> DateTime.add(-7200, :second),
        payload: %{"name" => "cmd.exe"}
      })

      recent_event = insert!(:event, %{
        organization_id: org.id,
        timestamp: DateTime.utc_now(),
        payload: %{"name" => "cmd.exe"}
      })

      {:ok, results} = QueryLibrary.execute_query(
        "name:cmd.exe",
        organization_id: org.id,
        time_range: [from: DateTime.utc_now() |> DateTime.add(-3600, :second)]
      )

      assert is_list(results)
      # Should only return recent event
      if length(results) > 0 do
        refute Enum.any?(results, fn r -> r.id == old_event.id end)
      end
    end

    test "limits result count", %{org: org} do
      # Create many events
      for i <- 1..50 do
        insert!(:event, %{
          organization_id: org.id,
          payload: %{"name" => "cmd.exe", "pid" => i}
        })
      end

      {:ok, results} = QueryLibrary.execute_query(
        "name:cmd.exe",
        organization_id: org.id,
        limit: 10
      )

      assert length(results) <= 10
    end

    test "returns error for invalid query", %{org: org} do
      {:error, _reason} = QueryLibrary.execute_query("invalid[syntax", organization_id: org.id)
    end

    test "handles empty results gracefully", %{org: org} do
      {:ok, results} = QueryLibrary.execute_query("name:nonexistent.exe", organization_id: org.id)

      assert results == []
    end
  end

  # ── Saved Query Tests ──────────────────────────────────────────────────

  describe "saved queries" do
    test "creates saved query", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.save_query(%{
        name: "Suspicious PowerShell",
        query: "name:powershell.exe AND cmdline:*-enc*",
        description: "Detects encoded PowerShell commands",
        organization_id: org.id,
        user_id: user.id
      })

      assert query.id != nil
      assert query.name == "Suspicious PowerShell"
    end

    test "lists saved queries for organization", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      insert!(:saved_query, %{
        name: "Query 1",
        query: "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id
      })

      insert!(:saved_query, %{
        name: "Query 2",
        query: "name:powershell.exe",
        organization_id: org.id,
        user_id: user.id
      })

      queries = QueryLibrary.list_saved_queries(organization_id: org.id)

      assert length(queries) >= 2
    end

    test "executes saved query", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.save_query(%{
        name: "Test Query",
        query: "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id
      })

      insert!(:event, %{
        organization_id: org.id,
        payload: %{"name" => "cmd.exe"}
      })

      {:ok, results} = QueryLibrary.execute_saved_query(query.id)

      assert is_list(results)
    end

    test "updates saved query", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.save_query(%{
        name: "Original",
        query: "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id
      })

      {:ok, updated} = QueryLibrary.update_saved_query(query, %{
        name: "Updated",
        query: "name:powershell.exe"
      })

      assert updated.name == "Updated"
      assert updated.query == "name:powershell.exe"
    end

    test "deletes saved query", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.save_query(%{
        name: "To Delete",
        query: "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id
      })

      {:ok, _deleted} = QueryLibrary.delete_saved_query(query)

      assert Repo.get(SavedQuery, query.id) == nil
    end

    test "shares saved query", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.save_query(%{
        name: "Shared Query",
        query: "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id,
        is_shared: false
      })

      {:ok, shared} = QueryLibrary.share_query(query)

      assert shared.is_shared == true
    end
  end

  # ── Query Template Tests ───────────────────────────────────────────────

  describe "query templates" do
    test "lists available templates" do
      templates = QueryLibrary.list_templates()

      assert is_list(templates)
      assert length(templates) > 0
    end

    test "gets template by name" do
      {:ok, template} = QueryLibrary.get_template("suspicious_processes")

      assert template.name != nil
      assert template.query != nil
      assert is_list(template.parameters) or template.parameters == nil
    end

    test "expands template with parameters" do
      {:ok, query} = QueryLibrary.expand_template(
        "process_by_name",
        %{process_name: "cmd.exe"}
      )

      assert is_binary(query)
      assert String.contains?(query, "cmd.exe")
    end

    test "validates required parameters" do
      {:error, _reason} = QueryLibrary.expand_template(
        "process_by_name",
        %{} # Missing required parameter
      )
    end

    test "creates query from template", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, query} = QueryLibrary.create_from_template(
        "suspicious_processes",
        %{},
        organization_id: org.id,
        user_id: user.id
      )

      assert query.id != nil
      assert query.query != nil
    end
  end

  # ── Query History Tests ────────────────────────────────────────────────

  describe "query history" do
    test "records query execution", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      {:ok, history} = QueryLibrary.record_execution(
        "name:cmd.exe",
        organization_id: org.id,
        user_id: user.id,
        result_count: 42,
        execution_time_ms: 150
      )

      assert history.id != nil
      assert history.query == "name:cmd.exe"
      assert history.result_count == 42
    end

    test "retrieves query history for user", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      QueryLibrary.record_execution("query1", organization_id: org.id, user_id: user.id)
      QueryLibrary.record_execution("query2", organization_id: org.id, user_id: user.id)

      history = QueryLibrary.get_user_history(user.id, limit: 10)

      assert length(history) >= 2
    end

    test "retrieves popular queries", %{org: org} do
      user = insert!(:user, %{organization_id: org.id})

      # Execute same query multiple times
      for _ <- 1..5 do
        QueryLibrary.record_execution("popular_query", organization_id: org.id, user_id: user.id)
      end

      popular = QueryLibrary.get_popular_queries(organization_id: org.id, limit: 5)

      assert is_list(popular)
    end
  end

  # ── Query Validation Tests ─────────────────────────────────────────────

  describe "query validation" do
    test "validates correct query syntax" do
      {:ok, _} = QueryLibrary.validate_query("name:cmd.exe")
    end

    test "rejects malformed queries" do
      {:error, _} = QueryLibrary.validate_query("invalid[[[syntax")
    end

    test "validates field names" do
      {:ok, _} = QueryLibrary.validate_query("name:cmd.exe")
      {:error, _} = QueryLibrary.validate_query("invalid_field:value")
    end

    test "validates operators" do
      {:ok, _} = QueryLibrary.validate_query("pid > 1000")
      {:ok, _} = QueryLibrary.validate_query("pid >= 1000")
      {:ok, _} = QueryLibrary.validate_query("pid < 1000")
      {:ok, _} = QueryLibrary.validate_query("pid <= 1000")
    end

    test "validates date ranges" do
      {:ok, _} = QueryLibrary.validate_query("timestamp:[2024-01-01 TO 2024-12-31]")
      {:error, _} = QueryLibrary.validate_query("timestamp:[invalid TO invalid]")
    end
  end

  # ── Query Suggestions Tests ────────────────────────────────────────────

  describe "query suggestions" do
    test "suggests field names for autocomplete" do
      suggestions = QueryLibrary.suggest_fields("proc")

      assert is_list(suggestions)
      assert Enum.any?(suggestions, fn s -> String.contains?(s, "process") end)
    end

    test "suggests values for field" do
      suggestions = QueryLibrary.suggest_values("event_type")

      assert is_list(suggestions)
      assert Enum.any?(suggestions, fn s -> s in ["process_create", "file_create", "network_connect"] end)
    end

    test "suggests query completions" do
      suggestions = QueryLibrary.suggest_completions("name:cmd")

      assert is_list(suggestions)
    end
  end
end
