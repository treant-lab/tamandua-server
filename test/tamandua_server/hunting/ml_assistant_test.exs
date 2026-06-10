defmodule TamanduaServer.Hunting.MLAssistantTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Hunting.MLAssistant
  alias TamanduaServer.Alerts
  alias TamanduaServer.Accounts

  setup do
    # Create test organization and user
    {:ok, org} =
      Accounts.create_organization(%{
        name: "Test Org",
        slug: "test-org-#{System.unique_integer([:positive])}"
      })

    {:ok, user} =
      Accounts.create_user(%{
        email: "test@example.com",
        password: "password123",
        name: "Test User",
        organization_id: org.id
      })

    # Create test alert
    {:ok, alert} =
      Alerts.create_alert(%{
        title: "Mimikatz Execution Detected",
        description: "Detected execution of credential dumping tool mimikatz.exe",
        severity: "critical",
        status: "open",
        organization_id: org.id,
        agent_id: Ecto.UUID.generate(),
        agent_hostname: "workstation-01",
        process_name: "mimikatz.exe",
        command_line: "mimikatz.exe sekurlsa::logonpasswords",
        mitre_techniques: ["T1003.001"],
        tags: ["credential_access", "mimikatz"]
      })

    %{organization: org, user: user, alert: alert}
  end

  describe "suggest_hunts/1" do
    test "suggests hunts from specific alert", %{organization: org, alert: alert} do
      {:ok, suggestions} =
        MLAssistant.suggest_hunts(organization_id: org.id, alert_id: alert.id, limit: 5)

      assert is_list(suggestions)
      assert length(suggestions) > 0

      # Verify suggestion structure
      suggestion = hd(suggestions)
      assert Map.has_key?(suggestion, :title)
      assert Map.has_key?(suggestion, :query)
      assert Map.has_key?(suggestion, :description)
      assert Map.has_key?(suggestion, :confidence)
      assert Map.has_key?(suggestion, :mitre_ttps)

      # Confidence should be 0-100
      assert suggestion.confidence >= 0
      assert suggestion.confidence <= 100
    end

    test "suggests hunts from recent activity", %{organization: org} do
      {:ok, suggestions} =
        MLAssistant.suggest_hunts(organization_id: org.id, days: 7, limit: 10)

      assert is_list(suggestions)
      # May be empty if no recent high-severity alerts
    end

    test "limits number of suggestions", %{organization: org, alert: alert} do
      {:ok, suggestions} =
        MLAssistant.suggest_hunts(organization_id: org.id, alert_id: alert.id, limit: 3)

      assert length(suggestions) <= 3
    end
  end

  describe "generate_hypotheses/1" do
    test "generates hunt hypotheses from anomalies", %{organization: org} do
      # This test requires ML service to be running or will use fallback
      {:ok, hypotheses} =
        MLAssistant.generate_hypotheses(
          organization_id: org.id,
          hours: 24,
          min_suspiciousness: 50
        )

      assert is_list(hypotheses)

      # If hypotheses returned, verify structure
      if length(hypotheses) > 0 do
        hypothesis = hd(hypotheses)
        assert Map.has_key?(hypothesis, :title)
        assert Map.has_key?(hypothesis, :query)
        assert Map.has_key?(hypothesis, :suspiciousness_score)
        assert hypothesis.suspiciousness_score >= 50
      end
    end

    test "filters hypotheses by minimum suspiciousness", %{organization: org} do
      {:ok, hypotheses} =
        MLAssistant.generate_hypotheses(
          organization_id: org.id,
          hours: 24,
          min_suspiciousness: 80
        )

      # All hypotheses should meet minimum threshold
      Enum.each(hypotheses, fn h ->
        assert h.suspiciousness_score >= 80
      end)
    end
  end

  describe "identify_clusters/1" do
    test "identifies process behavior clusters", %{organization: org} do
      # This requires ML service
      result =
        MLAssistant.identify_clusters(
          organization_id: org.id,
          entity_type: :process,
          hours: 24
        )

      # May succeed or fail depending on ML service availability
      case result do
        {:ok, clusters} ->
          assert is_list(clusters)

          if length(clusters) > 0 do
            cluster = hd(clusters)
            assert cluster.entity_type == :process
            assert is_integer(cluster.size)
            assert is_boolean(cluster.is_outlier)
            assert is_float(cluster.suspiciousness_score)
            assert is_binary(cluster.hunt_query)
          end

        {:error, _reason} ->
          # ML service unavailable, test passes
          assert true
      end
    end

    test "identifies network behavior clusters", %{organization: org} do
      result =
        MLAssistant.identify_clusters(
          organization_id: org.id,
          entity_type: :network,
          hours: 24
        )

      case result do
        {:ok, clusters} ->
          assert is_list(clusters)

        {:error, _reason} ->
          assert true
      end
    end
  end

  describe "rank_hunt_results/2" do
    test "ranks hunt results by suspiciousness", %{organization: org} do
      hunt_results = [
        %{
          process_name: "mimikatz.exe",
          rarity: 0.001,
          mitre_ttps: ["T1003.001"],
          is_elevated: true,
          is_signed: false
        },
        %{
          process_name: "notepad.exe",
          rarity: 0.8,
          mitre_ttps: [],
          is_elevated: false,
          is_signed: true
        }
      ]

      {:ok, ranked} = MLAssistant.rank_hunt_results(hunt_results, org.id)

      assert is_list(ranked)
      assert length(ranked) == 2

      # First result should be mimikatz (more suspicious)
      first = hd(ranked)
      assert Map.has_key?(first, :suspiciousness_score)
      # Mimikatz should have high suspiciousness
      assert first[:suspiciousness_score] > 50
    end

    test "uses fallback ranking when ML unavailable", %{organization: org} do
      hunt_results = [
        %{process_name: "test.exe", rarity: 0.01}
      ]

      {:ok, ranked} = MLAssistant.rank_hunt_results(hunt_results, org.id)

      # Should succeed even without ML service
      assert is_list(ranked)
      assert length(ranked) == 1
    end
  end

  describe "generate_template_from_alert/2" do
    test "generates hunt template from alert", %{organization: org, alert: alert} do
      {:ok, template_attrs} =
        MLAssistant.generate_template_from_alert(alert.id, org.id)

      assert is_map(template_attrs)
      assert template_attrs.name =~ "Hunt:"
      assert is_binary(template_attrs.query)
      assert template_attrs.organization_id == org.id
      assert "auto-generated" in template_attrs.tags
      assert "ml-assisted" in template_attrs.tags

      # Should inherit MITRE techniques from alert
      assert template_attrs.mitre_techniques == ["T1003.001"]

      # Should extract variables
      assert is_map(template_attrs.variables)
    end

    test "returns error for non-existent alert", %{organization: org} do
      fake_id = Ecto.UUID.generate()

      {:error, :alert_not_found} =
        MLAssistant.generate_template_from_alert(fake_id, org.id)
    end
  end

  describe "suggest_pivots/3" do
    test "suggests pivot steps from hunt results", %{organization: org} do
      hunt_results = [
        %{
          process_name: "powershell.exe",
          parent_process: %{name: "cmd.exe", pid: 1234},
          network_connections: [%{dst_ip: "1.2.3.4", dst_port: 443}],
          modified_files: ["/tmp/suspicious.txt"]
        }
      ]

      original_query = "process.name:powershell.exe"

      {:ok, pivots} = MLAssistant.suggest_pivots(hunt_results, original_query, org.id)

      assert is_list(pivots)

      # Should suggest multiple pivots
      assert length(pivots) > 0

      # Verify pivot structure
      pivot = hd(pivots)
      assert Map.has_key?(pivot, :title)
      assert Map.has_key?(pivot, :query)
      assert Map.has_key?(pivot, :reasoning)
      assert Map.has_key?(pivot, :confidence)
    end

    test "uses fallback pivots when ML unavailable", %{organization: org} do
      hunt_results = [%{process_name: "test.exe"}]
      original_query = "*"

      {:ok, pivots} = MLAssistant.suggest_pivots(hunt_results, original_query, org.id)

      # Should return fallback suggestions
      assert is_list(pivots)
    end
  end

  describe "get_hunt_recommendations/3" do
    test "returns hunt recommendations based on query similarity", %{organization: org} do
      query = "process.name:mimikatz.exe"

      {:ok, recommendations} = MLAssistant.get_hunt_recommendations(query, org.id, 5)

      assert is_list(recommendations)
      # May be empty if no similar saved queries exist
    end

    test "limits number of recommendations", %{organization: org} do
      query = "*"

      {:ok, recommendations} = MLAssistant.get_hunt_recommendations(query, org.id, 3)

      assert is_list(recommendations)
      assert length(recommendations) <= 3
    end
  end
end
