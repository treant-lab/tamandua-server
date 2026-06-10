defmodule TamanduaServer.InsiderThreat.AlertTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.InsiderThreat.Alert
  alias TamanduaServer.Accounts.{Organization, User}

  setup do
    org = insert(:organization)
    user1 = insert(:user, organization: org)
    user2 = insert(:user, organization: org)

    {:ok, org: org, user1: user1, user2: user2}
  end

  describe "create/1" do
    test "creates an alert", %{org: org, user1: user} do
      attrs = %{
        user_id: user.id,
        organization_id: org.id,
        risk_score: 75.0,
        severity: "critical",
        status: "open",
        indicators: [
          %{type: "data_exfiltration", weight: 40.0},
          %{type: "privilege_escalation", weight: 30.0}
        ],
        trend: "increasing"
      }

      assert {:ok, alert} = Alert.create(attrs)
      assert alert.risk_score == 75.0
      assert alert.severity == "critical"
      assert alert.status == "open"
      assert length(alert.indicators) == 2
    end

    test "validates required fields" do
      assert {:error, changeset} = Alert.create(%{})
      errors = errors_on(changeset)
      assert "can't be blank" in errors.user_id
      assert "can't be blank" in errors.risk_score
      assert "can't be blank" in errors.severity
    end

    test "validates risk score range", %{org: org, user1: user} do
      # Below 0
      assert {:error, changeset} =
               Alert.create(%{
                 user_id: user.id,
                 organization_id: org.id,
                 risk_score: -5.0,
                 severity: "low",
                 status: "open"
               })

      assert "must be greater than or equal to 0" in errors_on(changeset).risk_score

      # Above 100
      assert {:error, changeset} =
               Alert.create(%{
                 user_id: user.id,
                 organization_id: org.id,
                 risk_score: 105.0,
                 severity: "critical",
                 status: "open"
               })

      assert "must be less than or equal to 100" in errors_on(changeset).risk_score
    end
  end

  describe "start_investigation/2" do
    test "marks alert as under investigation", %{org: org, user1: user, user2: investigator} do
      {:ok, alert} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 75.0,
          severity: "critical",
          status: "open"
        })

      assert {:ok, updated_alert} = Alert.start_investigation(alert, investigator.id)
      assert updated_alert.status == "investigating"
      assert updated_alert.investigated_by_id == investigator.id
    end
  end

  describe "resolve/4" do
    test "resolves an alert", %{org: org, user1: user, user2: resolver} do
      {:ok, alert} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 75.0,
          severity: "critical",
          status: "investigating"
        })

      assert {:ok, resolved_alert} =
               Alert.resolve(alert, resolver.id, "Investigated and cleared", false)

      assert resolved_alert.status == "resolved"
      assert resolved_alert.resolved_by_id == resolver.id
      assert resolved_alert.resolution_notes == "Investigated and cleared"
      assert resolved_alert.false_positive == false
      assert resolved_alert.resolved_at != nil
    end

    test "can mark as false positive", %{org: org, user1: user, user2: resolver} do
      {:ok, alert} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 50.0,
          severity: "high",
          status: "investigating"
        })

      assert {:ok, resolved_alert} = Alert.resolve(alert, resolver.id, "False alarm", true)

      assert resolved_alert.false_positive == true
    end
  end

  describe "suppress/1" do
    test "suppresses an alert", %{org: org, user1: user} do
      {:ok, alert} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 30.0,
          severity: "medium",
          status: "open"
        })

      assert {:ok, suppressed_alert} = Alert.suppress(alert)
      assert suppressed_alert.status == "suppressed"
      assert suppressed_alert.suppressed == true
    end
  end

  describe "top_users_by_risk/2" do
    test "returns top users sorted by risk score", %{org: org} do
      user1 = insert(:user, organization: org, name: "User 1")
      user2 = insert(:user, organization: org, name: "User 2")
      user3 = insert(:user, organization: org, name: "User 3")

      # Create alerts with different risk scores
      Alert.create(%{
        user_id: user1.id,
        organization_id: org.id,
        risk_score: 85.0,
        severity: "critical",
        status: "open"
      })

      Alert.create(%{
        user_id: user2.id,
        organization_id: org.id,
        risk_score: 60.0,
        severity: "high",
        status: "open"
      })

      Alert.create(%{
        user_id: user3.id,
        organization_id: org.id,
        risk_score: 45.0,
        severity: "medium",
        status: "open"
      })

      top_users = Alert.top_users_by_risk(org.id, 3)

      assert length(top_users) == 3
      assert Enum.at(top_users, 0).risk_score == 85.0
      assert Enum.at(top_users, 1).risk_score == 60.0
      assert Enum.at(top_users, 2).risk_score == 45.0
    end
  end

  describe "risk_distribution/1" do
    test "returns alert count by severity", %{org: org, user1: user} do
      # Create alerts with different severities
      Alert.create(%{
        user_id: user.id,
        organization_id: org.id,
        risk_score: 85.0,
        severity: "critical",
        status: "open"
      })

      Alert.create(%{
        user_id: user.id,
        organization_id: org.id,
        risk_score: 55.0,
        severity: "high",
        status: "open"
      })

      Alert.create(%{
        user_id: user.id,
        organization_id: org.id,
        risk_score: 30.0,
        severity: "medium",
        status: "open"
      })

      distribution = Alert.risk_distribution(org.id)

      assert distribution["critical"] == 1
      assert distribution["high"] == 1
      assert distribution["medium"] == 1
    end
  end

  describe "statistics/3" do
    test "returns alert statistics for time period", %{org: org, user1: user, user2: resolver} do
      start_time = DateTime.utc_now() |> DateTime.add(-7 * 24 * 3600, :second)
      end_time = DateTime.utc_now()

      # Create various alerts
      {:ok, alert1} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 85.0,
          severity: "critical",
          status: "open"
        })

      {:ok, alert2} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 55.0,
          severity: "high",
          status: "investigating"
        })

      {:ok, alert3} =
        Alert.create(%{
          user_id: user.id,
          organization_id: org.id,
          risk_score: 30.0,
          severity: "medium",
          status: "open"
        })

      Alert.resolve(alert3, resolver.id, "False alarm", true)

      stats = Alert.statistics(org.id, start_time, end_time)

      assert stats.total == 3
      assert stats.open == 1
      assert stats.investigating == 1
      assert stats.resolved == 1
      assert stats.false_positives == 1
      assert stats.avg_risk_score > 0
      assert stats.by_severity["critical"] == 1
      assert stats.by_severity["high"] == 1
    end
  end

  # Helper to insert test data
  defp insert(schema, attrs \\ %{}) do
    case schema do
      :organization ->
        %Organization{
          id: Ecto.UUID.generate(),
          name: attrs[:name] || "Test Org",
          slug: attrs[:slug] || "test-org"
        }
        |> Organization.changeset(attrs)
        |> Repo.insert!()

      :user ->
        %User{
          id: Ecto.UUID.generate(),
          email: "user-#{System.unique_integer()}@example.com",
          password_hash: Bcrypt.hash_pwd_salt("password"),
          name: attrs[:name] || "Test User",
          role: attrs[:role] || "analyst",
          is_active: true,
          organization_id: attrs[:organization] && attrs[:organization].id
        }
        |> User.changeset(Map.drop(attrs, [:organization]))
        |> Repo.insert!()
    end
  end
end
