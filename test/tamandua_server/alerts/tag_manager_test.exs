defmodule TamanduaServer.Alerts.TagManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.TagManager
  alias TamanduaServer.Alerts.Tag

  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AlertsFixtures

  describe "tag management" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      %{organization: org, user: user}
    end

    test "list_tags/2 returns all tags for organization", %{organization: org, user: user} do
      {:ok, tag1} = TagManager.create_tag(org.id, %{name: "malware"}, user)
      {:ok, tag2} = TagManager.create_tag(org.id, %{name: "phishing"}, user)

      tags = TagManager.list_tags(org.id)

      assert length(tags) == 2
      assert Enum.any?(tags, &(&1.id == tag1.id))
      assert Enum.any?(tags, &(&1.id == tag2.id))
    end

    test "list_tags/2 filters by category", %{organization: org, user: user} do
      {:ok, _tag1} = TagManager.create_tag(org.id, %{name: "malware", category: "malware"}, user)
      {:ok, _tag2} = TagManager.create_tag(org.id, %{name: "phishing", category: "phishing"}, user)

      tags = TagManager.list_tags(org.id, category: "malware")

      assert length(tags) == 1
      assert hd(tags).category == "malware"
    end

    test "list_tags/2 searches by name", %{organization: org, user: user} do
      {:ok, _tag1} = TagManager.create_tag(org.id, %{name: "malware"}, user)
      {:ok, _tag2} = TagManager.create_tag(org.id, %{name: "phishing"}, user)

      tags = TagManager.list_tags(org.id, search: "mal")

      assert length(tags) == 1
      assert hd(tags).name == "malware"
    end

    test "get_tag/2 returns tag by ID", %{organization: org, user: user} do
      {:ok, tag} = TagManager.create_tag(org.id, %{name: "test"}, user)

      assert {:ok, fetched_tag} = TagManager.get_tag(org.id, tag.id)
      assert fetched_tag.id == tag.id
    end

    test "get_tag/2 returns error for non-existent tag", %{organization: org} do
      assert {:error, :not_found} = TagManager.get_tag(org.id, Ecto.UUID.generate())
    end

    test "get_tag_by_name/2 returns tag by name", %{organization: org, user: user} do
      {:ok, tag} = TagManager.create_tag(org.id, %{name: "test"}, user)

      assert {:ok, fetched_tag} = TagManager.get_tag_by_name(org.id, "test")
      assert fetched_tag.id == tag.id
    end

    test "create_tag/3 creates a tag with valid attributes", %{organization: org, user: user} do
      attrs = %{
        name: "critical-alert",
        description: "High priority alerts",
        color: "#FF0000",
        category: "malware"
      }

      assert {:ok, tag} = TagManager.create_tag(org.id, attrs, user)
      assert tag.name == "critical-alert"
      assert tag.description == "High priority alerts"
      assert tag.color == "#FF0000"
      assert tag.category == "malware"
      assert tag.organization_id == org.id
      assert tag.created_by_id == user.id
    end

    test "create_tag/3 enforces unique name per organization", %{organization: org, user: user} do
      {:ok, _tag} = TagManager.create_tag(org.id, %{name: "duplicate"}, user)

      assert {:error, changeset} = TagManager.create_tag(org.id, %{name: "duplicate"}, user)
      assert "has already been taken" in errors_on(changeset).name
    end

    test "create_tag/3 validates color format", %{organization: org, user: user} do
      assert {:error, changeset} = TagManager.create_tag(org.id, %{name: "test", color: "red"}, user)
      assert "must be a valid hex color" in errors_on(changeset).color
    end

    test "update_tag/3 updates tag attributes", %{organization: org, user: user} do
      {:ok, tag} = TagManager.create_tag(org.id, %{name: "original"}, user)

      assert {:ok, updated_tag} = TagManager.update_tag(org.id, tag.id, %{name: "updated", color: "#00FF00"})
      assert updated_tag.name == "updated"
      assert updated_tag.color == "#00FF00"
    end

    test "delete_tag/2 deletes the tag", %{organization: org, user: user} do
      {:ok, tag} = TagManager.create_tag(org.id, %{name: "to-delete"}, user)

      assert {:ok, _deleted_tag} = TagManager.delete_tag(org.id, tag.id)
      assert {:error, :not_found} = TagManager.get_tag(org.id, tag.id)
    end
  end

  describe "tag assignment" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      alert = alert_fixture(%{organization_id: org.id})
      {:ok, tag} = TagManager.create_tag(org.id, %{name: "test-tag"}, user)

      %{organization: org, user: user, alert: alert, tag: tag}
    end

    test "assign_tag/3 assigns tag to alert", %{alert: alert, tag: tag, user: user} do
      assert {:ok, assignment} = TagManager.assign_tag(alert.id, tag.id, user.id)
      assert assignment.alert_id == alert.id
      assert assignment.tag_id == tag.id
      assert assignment.assigned_by_id == user.id
    end

    test "assign_tag/3 returns ok if tag already assigned", %{alert: alert, tag: tag, user: user} do
      {:ok, _assignment} = TagManager.assign_tag(alert.id, tag.id, user.id)
      assert {:ok, :already_assigned} = TagManager.assign_tag(alert.id, tag.id, user.id)
    end

    test "unassign_tag/2 removes tag from alert", %{alert: alert, tag: tag, user: user} do
      {:ok, _assignment} = TagManager.assign_tag(alert.id, tag.id, user.id)

      assert {:ok, :deleted} = TagManager.unassign_tag(alert.id, tag.id)
      assert [] = TagManager.list_alert_tags(alert.id)
    end

    test "list_alert_tags/1 returns all tags for alert", %{organization: org, alert: alert, user: user} do
      {:ok, tag1} = TagManager.create_tag(org.id, %{name: "tag1"}, user)
      {:ok, tag2} = TagManager.create_tag(org.id, %{name: "tag2"}, user)

      TagManager.assign_tag(alert.id, tag1.id, user.id)
      TagManager.assign_tag(alert.id, tag2.id, user.id)

      tags = TagManager.list_alert_tags(alert.id)

      assert length(tags) == 2
      assert Enum.any?(tags, &(&1.id == tag1.id))
      assert Enum.any?(tags, &(&1.id == tag2.id))
    end

    test "list_alerts_by_tag/3 returns alerts with specific tag", %{organization: org, tag: tag, user: user} do
      alert1 = alert_fixture(%{organization_id: org.id})
      alert2 = alert_fixture(%{organization_id: org.id})
      _alert3 = alert_fixture(%{organization_id: org.id})

      TagManager.assign_tag(alert1.id, tag.id, user.id)
      TagManager.assign_tag(alert2.id, tag.id, user.id)

      alerts = TagManager.list_alerts_by_tag(org.id, tag.id)

      assert length(alerts) == 2
      assert Enum.any?(alerts, &(&1.id == alert1.id))
      assert Enum.any?(alerts, &(&1.id == alert2.id))
    end
  end

  describe "bulk operations" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      alert1 = alert_fixture(%{organization_id: org.id})
      alert2 = alert_fixture(%{organization_id: org.id})

      %{organization: org, user: user, alerts: [alert1, alert2]}
    end

    test "bulk_assign_tags/4 assigns tags to multiple alerts", %{organization: org, user: user, alerts: alerts} do
      alert_ids = Enum.map(alerts, & &1.id)
      tag_names = ["malware", "critical"]

      assert {:ok, count} = TagManager.bulk_assign_tags(alert_ids, tag_names, org.id, user)
      assert count == 4  # 2 alerts × 2 tags

      for alert <- alerts do
        tags = TagManager.list_alert_tags(alert.id)
        assert length(tags) == 2
        assert Enum.any?(tags, &(&1.name == "malware"))
        assert Enum.any?(tags, &(&1.name == "critical"))
      end
    end

    test "bulk_assign_tags/4 creates tags if they don't exist", %{organization: org, user: user, alerts: alerts} do
      alert_ids = Enum.map(alerts, & &1.id)

      assert {:ok, _count} = TagManager.bulk_assign_tags(alert_ids, ["new-tag"], org.id, user)

      assert {:ok, _tag} = TagManager.get_tag_by_name(org.id, "new-tag")
    end

    test "bulk_unassign_tags/3 removes tags from multiple alerts", %{organization: org, user: user, alerts: alerts} do
      alert_ids = Enum.map(alerts, & &1.id)
      TagManager.bulk_assign_tags(alert_ids, ["malware"], org.id, user)

      assert {:ok, count} = TagManager.bulk_unassign_tags(alert_ids, ["malware"], org.id)
      assert count == 2

      for alert <- alerts do
        tags = TagManager.list_alert_tags(alert.id)
        assert tags == []
      end
    end
  end

  describe "tag statistics" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      %{organization: org, user: user}
    end

    test "tag_statistics/2 returns usage counts", %{organization: org, user: user} do
      {:ok, tag1} = TagManager.create_tag(org.id, %{name: "popular"}, user)
      {:ok, tag2} = TagManager.create_tag(org.id, %{name: "rare"}, user)

      # Create alerts and assign tags
      for _ <- 1..5 do
        alert = alert_fixture(%{organization_id: org.id})
        TagManager.assign_tag(alert.id, tag1.id, user.id)
      end

      alert = alert_fixture(%{organization_id: org.id})
      TagManager.assign_tag(alert.id, tag2.id, user.id)

      stats = TagManager.tag_statistics(org.id)

      assert length(stats) == 2
      popular_stat = Enum.find(stats, &(&1.name == "popular"))
      rare_stat = Enum.find(stats, &(&1.name == "rare"))

      assert popular_stat.usage_count == 5
      assert rare_stat.usage_count == 1
    end

    test "autocomplete_tags/3 returns matching tags", %{organization: org, user: user} do
      {:ok, _tag1} = TagManager.create_tag(org.id, %{name: "malware"}, user)
      {:ok, _tag2} = TagManager.create_tag(org.id, %{name: "malicious"}, user)
      {:ok, _tag3} = TagManager.create_tag(org.id, %{name: "phishing"}, user)

      results = TagManager.autocomplete_tags(org.id, "mal")

      assert length(results) == 2
      assert Enum.all?(results, &String.contains?(&1.name, "mal"))
    end
  end
end
