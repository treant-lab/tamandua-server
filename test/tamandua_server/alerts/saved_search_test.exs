defmodule TamanduaServer.Alerts.SavedSearchTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.SavedSearch

  describe "saved searches" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      {:ok, organization: org, user: user}
    end

    test "create_saved_search/1 creates a saved search", %{organization: org, user: user} do
      attrs = %{
        name: "Critical Alerts",
        description: "All critical alerts",
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "eq", "value" => "critical"}
          ]
        },
        user_id: user.id,
        organization_id: org.id
      }

      assert {:ok, search} = Alerts.create_saved_search(attrs)
      assert search.name == "Critical Alerts"
      assert search.user_id == user.id
      assert search.organization_id == org.id
      assert search.version == 1
      assert search.usage_count == 0
    end

    test "create_saved_search/1 validates required fields", %{organization: org, user: user} do
      attrs = %{
        description: "Missing name",
        user_id: user.id,
        organization_id: org.id
      }

      assert {:error, changeset} = Alerts.create_saved_search(attrs)
      assert "can't be blank" in errors_on(changeset).name
      assert "can't be blank" in errors_on(changeset).filter_json
    end

    test "create_saved_search/1 validates filter structure", %{organization: org, user: user} do
      attrs = %{
        name: "Invalid Filter",
        filter_json: %{"invalid" => "structure"},
        user_id: user.id,
        organization_id: org.id
      }

      assert {:error, changeset} = Alerts.create_saved_search(attrs)
      assert "invalid filter structure" in errors_on(changeset).filter_json
    end

    test "create_saved_search/1 accepts valid quick filter", %{organization: org, user: user} do
      attrs = %{
        name: "High Severity",
        filter_json: %{"quick_filter" => "high_severity"},
        user_id: user.id,
        organization_id: org.id
      }

      assert {:ok, search} = Alerts.create_saved_search(attrs)
      assert search.filter_json["quick_filter"] == "high_severity"
    end

    test "list_saved_searches/3 returns user's searches", %{organization: org, user: user} do
      search1 = insert(:saved_search, user: user, organization: org, name: "Search 1")
      search2 = insert(:saved_search, user: user, organization: org, name: "Search 2")
      _other_user_search = insert(:saved_search, organization: org, name: "Other")

      searches = Alerts.list_saved_searches(user.id, org.id)

      search_ids = Enum.map(searches, & &1.id)
      assert search1.id in search_ids
      assert search2.id in search_ids
    end

    test "list_saved_searches/3 includes shared searches", %{organization: org, user: user} do
      my_search = insert(:saved_search, user: user, organization: org)
      shared_search = insert(:saved_search, organization: org, is_shared: true)

      searches = Alerts.list_saved_searches(user.id, org.id)

      search_ids = Enum.map(searches, & &1.id)
      assert my_search.id in search_ids
      assert shared_search.id in search_ids
    end

    test "list_saved_searches/3 filters by starred", %{organization: org, user: user} do
      starred = insert(:saved_search, user: user, organization: org, is_starred: true)
      _not_starred = insert(:saved_search, user: user, organization: org, is_starred: false)

      searches = Alerts.list_saved_searches(user.id, org.id, starred_only: true)

      assert length(searches) == 1
      assert hd(searches).id == starred.id
    end

    test "list_saved_searches/3 filters by category", %{organization: org, user: user} do
      detection = insert(:saved_search, user: user, organization: org, category: "detection")
      _hunting = insert(:saved_search, user: user, organization: org, category: "threat_hunting")

      searches = Alerts.list_saved_searches(user.id, org.id, category: "detection")

      assert length(searches) == 1
      assert hd(searches).id == detection.id
    end

    test "update_saved_search/2 updates a search", %{organization: org, user: user} do
      search = insert(:saved_search, user: user, organization: org, name: "Old Name")

      assert {:ok, updated} = Alerts.update_saved_search(search, %{name: "New Name"})
      assert updated.name == "New Name"
    end

    test "delete_saved_search/1 deletes a search", %{organization: org, user: user} do
      search = insert(:saved_search, user: user, organization: org)

      assert {:ok, _deleted} = Alerts.delete_saved_search(search)
      assert {:error, :not_found} = Alerts.get_saved_search(search.id)
    end

    test "toggle_star_saved_search/1 stars a search", %{organization: org, user: user} do
      search = insert(:saved_search, user: user, organization: org, is_starred: false)

      assert {:ok, starred} = Alerts.toggle_star_saved_search(search)
      assert starred.is_starred == true

      assert {:ok, unstarred} = Alerts.toggle_star_saved_search(starred)
      assert unstarred.is_starred == false
    end

    test "record_search_usage/1 increments usage count", %{organization: org, user: user} do
      search = insert(:saved_search, user: user, organization: org, usage_count: 5)

      assert {:ok, updated} = Alerts.record_search_usage(search)
      assert updated.usage_count == 6
      assert updated.last_used_at != nil
    end

    test "create_search_version/2 creates a new version", %{organization: org, user: user} do
      original = insert(:saved_search, user: user, organization: org, version: 1)

      new_filter = %{
        "logic" => "OR",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "high"}
        ]
      }

      assert {:ok, version} = Alerts.create_search_version(original, %{
        name: original.name,
        filter_json: new_filter
      })

      assert version.version == 2
      assert version.parent_id == original.id
      assert version.filter_json == new_filter
    end

    test "list_search_versions/1 lists all versions", %{organization: org, user: user} do
      original = insert(:saved_search, user: user, organization: org, version: 1)

      {:ok, v2} = Alerts.create_search_version(original, %{
        name: original.name,
        filter_json: original.filter_json
      })

      {:ok, v3} = Alerts.create_search_version(original, %{
        name: original.name,
        filter_json: original.filter_json
      })

      versions = Alerts.list_search_versions(original)

      assert length(versions) == 3
      version_numbers = Enum.map(versions, & &1.version)
      assert 1 in version_numbers
      assert 2 in version_numbers
      assert 3 in version_numbers
    end

    test "list_search_templates/1 returns templates only", %{organization: org, user: user} do
      template = insert(:saved_search, user: user, organization: org, is_template: true)
      _regular = insert(:saved_search, user: user, organization: org, is_template: false)

      templates = Alerts.list_search_templates(org.id)

      assert length(templates) == 1
      assert hd(templates).id == template.id
    end

    test "create_default_templates/2 creates templates", %{organization: org, user: user} do
      assert {:ok, templates} = Alerts.create_default_templates(org.id, user.id)

      assert length(templates) > 0
      assert Enum.all?(templates, & &1.is_template)
      assert Enum.all?(templates, & &1.is_shared)
      assert Enum.all?(templates, &(&1.organization_id == org.id))
    end
  end

  describe "list_alerts_with_filter/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create test alerts
      critical_new = insert(:alert, severity: "critical", status: "new", organization: org)
      critical_resolved = insert(:alert, severity: "critical", status: "resolved", organization: org)
      high_new = insert(:alert, severity: "high", status: "new", organization: org)
      low_resolved = insert(:alert, severity: "low", status: "resolved", organization: org)

      {:ok,
       organization: org,
       user: user,
       critical_new: critical_new,
       critical_resolved: critical_resolved,
       high_new: high_new,
       low_resolved: low_resolved}
    end

    test "filters by severity", %{organization: org, critical_new: alert1, critical_resolved: alert2} do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      alerts = Alerts.list_alerts_with_filter(org.id, filter)

      alert_ids = Enum.map(alerts, & &1.id)
      assert alert1.id in alert_ids
      assert alert2.id in alert_ids
      assert length(alerts) == 2
    end

    test "filters with AND logic", %{organization: org, critical_new: alert} do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"},
          %{"field" => "status", "operator" => "eq", "value" => "new"}
        ]
      }

      alerts = Alerts.list_alerts_with_filter(org.id, filter)

      assert length(alerts) == 1
      assert hd(alerts).id == alert.id
    end

    test "filters with OR logic", %{organization: org, critical_new: alert1, high_new: alert2} do
      filter = %{
        "logic" => "OR",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"},
          %{"field" => "severity", "operator" => "eq", "value" => "high"}
        ]
      }

      alerts = Alerts.list_alerts_with_filter(org.id, filter)

      alert_ids = Enum.map(alerts, & &1.id)
      assert alert1.id in alert_ids
      assert alert2.id in alert_ids
      assert length(alerts) == 2
    end

    test "applies pagination", %{organization: org} do
      # Insert more alerts
      Enum.each(1..10, fn _ ->
        insert(:alert, organization: org)
      end)

      filter = %{"logic" => "AND", "conditions" => []}

      page1 = Alerts.list_alerts_with_filter(org.id, filter, limit: 5, offset: 0)
      page2 = Alerts.list_alerts_with_filter(org.id, filter, limit: 5, offset: 5)

      assert length(page1) == 5
      assert length(page2) == 5

      # Ensure no overlap
      page1_ids = Enum.map(page1, & &1.id)
      page2_ids = Enum.map(page2, & &1.id)
      assert Enum.empty?(page1_ids -- (page1_ids -- page2_ids))
    end
  end

  describe "count_alerts_with_filter/3" do
    setup do
      org = insert(:organization)
      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "high", organization: org)
      {:ok, organization: org}
    end

    test "counts filtered alerts", %{organization: org} do
      filter = %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      count = Alerts.count_alerts_with_filter(org.id, filter)
      assert count == 2
    end

    test "counts all alerts with empty filter", %{organization: org} do
      filter = %{"logic" => "AND", "conditions" => []}

      count = Alerts.count_alerts_with_filter(org.id, filter)
      assert count == 3
    end
  end

  describe "list_alerts_with_saved_search/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      insert(:alert, severity: "critical", organization: org)
      insert(:alert, severity: "high", organization: org)

      search = insert(:saved_search,
        user: user,
        organization: org,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "eq", "value" => "critical"}
          ]
        }
      )

      {:ok, organization: org, user: user, search: search}
    end

    test "lists alerts using saved search", %{organization: org, search: search} do
      alerts = Alerts.list_alerts_with_saved_search(org.id, search)

      assert length(alerts) == 1
      assert hd(alerts).severity == "critical"
    end

    test "increments usage count", %{organization: org, search: search} do
      initial_count = search.usage_count

      Alerts.list_alerts_with_saved_search(org.id, search)

      {:ok, updated} = Alerts.get_saved_search(search.id)
      assert updated.usage_count == initial_count + 1
    end
  end
end
