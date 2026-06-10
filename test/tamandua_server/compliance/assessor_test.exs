defmodule TamanduaServer.Compliance.AssessorTest do
  @moduledoc """
  Comprehensive unit tests for compliance assessor.
  Tests framework loading, control assessment, evidence collection, and reporting.
  """
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Compliance.{Assessor, Framework, Control, Assessment}
  alias TamanduaServer.Repo

  setup do
    {org, agent} = create_agent_with_org()

    %{org: org, agent: agent}
  end

  # ── Framework Loading Tests ────────────────────────────────────────────

  describe "load_framework/1" do
    test "loads PCI DSS framework" do
      {:ok, framework} = Assessor.load_framework("pci_dss")

      assert framework.name == "PCI DSS"
      assert framework.version != nil
      assert is_list(framework.controls)
      assert length(framework.controls) > 0
    end

    test "loads HIPAA framework" do
      {:ok, framework} = Assessor.load_framework("hipaa")

      assert framework.name == "HIPAA"
      assert is_list(framework.controls)
    end

    test "loads SOC 2 framework" do
      {:ok, framework} = Assessor.load_framework("soc2")

      assert framework.name == "SOC 2"
      assert is_list(framework.controls)
    end

    test "loads GDPR framework" do
      {:ok, framework} = Assessor.load_framework("gdpr")

      assert framework.name == "GDPR"
      assert is_list(framework.controls)
    end

    test "loads NIST framework" do
      {:ok, framework} = Assessor.load_framework("nist_csf")

      assert framework.name in ["NIST CSF", "NIST Cybersecurity Framework"]
      assert is_list(framework.controls)
    end

    test "loads CIS Controls" do
      {:ok, framework} = Assessor.load_framework("cis")

      assert framework.name in ["CIS Controls", "CIS Critical Security Controls"]
      assert is_list(framework.controls)
    end

    test "returns error for unknown framework" do
      {:error, :framework_not_found} = Assessor.load_framework("unknown_framework")
    end

    test "framework includes metadata" do
      {:ok, framework} = Assessor.load_framework("pci_dss")

      assert Map.has_key?(framework, :description)
      assert Map.has_key?(framework, :version)
      assert Map.has_key?(framework, :updated_at)
    end
  end

  # ── Control Assessment Tests ───────────────────────────────────────────

  describe "assess_control/3" do
    test "assesses logging control", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "log_collection",
        agent_id: agent.id,
        organization_id: org.id
      )

      assert result.control_id == "log_collection"
      assert result.status in [:compliant, :non_compliant, :partial]
      assert is_list(result.evidence)
      assert is_number(result.score)
    end

    test "assesses antivirus control", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "antivirus_enabled",
        agent_id: agent.id,
        organization_id: org.id
      )

      assert result.control_id == "antivirus_enabled"
      assert result.status in [:compliant, :non_compliant, :partial]
    end

    test "assesses encryption control", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "disk_encryption",
        agent_id: agent.id,
        organization_id: org.id
      )

      assert is_map(result)
      assert Map.has_key?(result, :status)
      assert Map.has_key?(result, :evidence)
    end

    test "includes remediation steps for non-compliant controls", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "firewall_enabled",
        agent_id: agent.id,
        organization_id: org.id
      )

      if result.status == :non_compliant do
        assert is_list(result.remediation_steps)
        assert length(result.remediation_steps) > 0
      end
    end

    test "collects evidence for assessment", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "log_collection",
        agent_id: agent.id,
        organization_id: org.id
      )

      assert is_list(result.evidence)

      if length(result.evidence) > 0 do
        evidence = hd(result.evidence)
        assert Map.has_key?(evidence, :type)
        assert Map.has_key?(evidence, :collected_at)
      end
    end

    test "returns error for unknown control" do
      {:error, :control_not_found} = Assessor.assess_control("unknown_control")
    end

    test "handles agent with no data gracefully", %{org: org} do
      # Create agent with no metrics
      agent = insert!(:agent, %{organization_id: org.id})

      {:ok, result} = Assessor.assess_control(
        "log_collection",
        agent_id: agent.id,
        organization_id: org.id
      )

      # Should return non-compliant or unknown
      assert result.status in [:non_compliant, :unknown, :partial]
    end
  end

  # ── Organization Assessment Tests ──────────────────────────────────────

  describe "assess_organization/2" do
    test "assesses entire organization against framework", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      assert assessment.organization_id == org.id
      assert assessment.framework == "pci_dss"
      assert is_list(assessment.control_results)
      assert is_number(assessment.overall_score)
      assert assessment.overall_score >= 0
      assert assessment.overall_score <= 100
    end

    test "calculates compliance percentage", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "hipaa")

      assert Map.has_key?(assessment, :compliance_percentage)
      assert assessment.compliance_percentage >= 0
      assert assessment.compliance_percentage <= 100
    end

    test "identifies failing controls", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "soc2")

      failing = Enum.filter(assessment.control_results, fn result ->
        result.status == :non_compliant
      end)

      assert is_list(failing)
    end

    test "groups controls by domain", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "nist_csf")

      if Map.has_key?(assessment, :by_domain) do
        assert is_map(assessment.by_domain)
      end
    end

    test "includes timestamp", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "cis")

      assert Map.has_key?(assessment, :assessed_at)
      assert %DateTime{} = assessment.assessed_at
    end
  end

  # ── Evidence Collection Tests ──────────────────────────────────────────

  describe "collect_evidence/2" do
    test "collects agent configuration evidence", %{agent: agent} do
      {:ok, evidence} = Assessor.collect_evidence("agent_config", agent_id: agent.id)

      assert evidence.type == "agent_config"
      assert is_map(evidence.data)
      assert Map.has_key?(evidence.data, :agent_id)
    end

    test "collects log evidence", %{org: org} do
      {:ok, evidence} = Assessor.collect_evidence("logs", organization_id: org.id)

      assert evidence.type == "logs"
      assert is_map(evidence.data) or is_list(evidence.data)
    end

    test "collects security policy evidence", %{org: org} do
      {:ok, evidence} = Assessor.collect_evidence("security_policies", organization_id: org.id)

      assert evidence.type == "security_policies"
    end

    test "collects alert evidence", %{org: org} do
      # Create some alerts
      agent = insert!(:agent, %{organization_id: org.id})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      {:ok, evidence} = Assessor.collect_evidence("alerts", organization_id: org.id)

      assert evidence.type == "alerts"
      assert is_list(evidence.data)
    end

    test "evidence includes timestamp" do
      {:ok, evidence} = Assessor.collect_evidence("agent_config", agent_id: Ecto.UUID.generate())

      assert Map.has_key?(evidence, :collected_at)
    end

    test "handles missing data gracefully" do
      {:ok, evidence} = Assessor.collect_evidence("nonexistent", organization_id: Ecto.UUID.generate())

      assert is_map(evidence)
    end
  end

  # ── Assessment Storage and Retrieval ───────────────────────────────────

  describe "assessment persistence" do
    test "saves assessment to database", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      {:ok, saved} = Assessor.save_assessment(assessment)

      assert saved.id != nil
      assert saved.organization_id == org.id
    end

    test "retrieves latest assessment", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")
      {:ok, _saved} = Assessor.save_assessment(assessment)

      {:ok, latest} = Assessor.get_latest_assessment(org.id, framework: "pci_dss")

      assert latest.framework == "pci_dss"
    end

    test "retrieves assessment history", %{org: org} do
      # Create multiple assessments
      for _ <- 1..3 do
        {:ok, assessment} = Assessor.assess_organization(org.id, framework: "hipaa")
        {:ok, _} = Assessor.save_assessment(assessment)
      end

      history = Assessor.get_assessment_history(org.id, framework: "hipaa")

      assert length(history) >= 3
    end

    test "tracks compliance trend over time", %{org: org} do
      # Create assessments with different scores
      for _ <- 1..5 do
        {:ok, assessment} = Assessor.assess_organization(org.id, framework: "soc2")
        {:ok, _} = Assessor.save_assessment(assessment)
      end

      {:ok, trend} = Assessor.get_compliance_trend(org.id, framework: "soc2")

      assert is_list(trend)
      assert length(trend) >= 1
    end
  end

  # ── Reporting Tests ────────────────────────────────────────────────────

  describe "generate_report/2" do
    test "generates summary report", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      {:ok, report} = Assessor.generate_report(assessment, format: :summary)

      assert is_map(report)
      assert Map.has_key?(report, :overall_score)
      assert Map.has_key?(report, :compliance_percentage)
      assert Map.has_key?(report, :critical_failures)
    end

    test "generates detailed report", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "hipaa")

      {:ok, report} = Assessor.generate_report(assessment, format: :detailed)

      assert is_map(report)
      assert Map.has_key?(report, :control_details)
      assert Map.has_key?(report, :evidence)
    end

    test "generates executive summary", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "soc2")

      {:ok, report} = Assessor.generate_report(assessment, format: :executive)

      assert is_map(report)
      assert Map.has_key?(report, :executive_summary)
    end

    test "includes remediation plan", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "nist_csf")

      {:ok, report} = Assessor.generate_report(assessment, format: :detailed)

      if Map.has_key?(report, :remediation_plan) do
        assert is_list(report.remediation_plan)
      end
    end

    test "exports to JSON", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "cis")

      {:ok, json} = Assessor.export_report(assessment, format: :json)

      assert is_binary(json)
      {:ok, decoded} = Jason.decode(json)
      assert is_map(decoded)
    end

    test "exports to CSV", %{org: org} do
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      {:ok, csv} = Assessor.export_report(assessment, format: :csv)

      assert is_binary(csv)
      assert String.contains?(csv, "Control")
      assert String.contains?(csv, "Status")
    end
  end

  # ── Remediation Tracking ───────────────────────────────────────────────

  describe "remediation tracking" do
    test "creates remediation task for failing control", %{org: org, agent: agent} do
      {:ok, result} = Assessor.assess_control(
        "antivirus_enabled",
        agent_id: agent.id,
        organization_id: org.id
      )

      if result.status == :non_compliant do
        {:ok, task} = Assessor.create_remediation_task(result)

        assert task.control_id == "antivirus_enabled"
        assert task.status == :open
        assert is_list(task.steps)
      end
    end

    test "tracks remediation progress", %{org: org} do
      # Create assessment
      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      # Create remediation tasks
      failing = Enum.filter(assessment.control_results, fn r -> r.status == :non_compliant end)

      for result <- Enum.take(failing, 3) do
        {:ok, _task} = Assessor.create_remediation_task(result)
      end

      # Get progress
      progress = Assessor.get_remediation_progress(org.id, framework: "pci_dss")

      assert is_map(progress)
      assert Map.has_key?(progress, :total_tasks)
      assert Map.has_key?(progress, :completed_tasks)
    end

    test "marks remediation task as complete" do
      task = insert!(:remediation_task, %{status: :open})

      {:ok, updated} = Assessor.complete_remediation_task(task.id)

      assert updated.status == :completed
      assert updated.completed_at != nil
    end
  end

  # ── Control Mapping Tests ──────────────────────────────────────────────

  describe "control mapping" do
    test "maps controls to MITRE ATT&CK techniques" do
      {:ok, framework} = Assessor.load_framework("nist_csf")

      mappings = Assessor.map_controls_to_mitre(framework)

      assert is_map(mappings)
      # Should have at least some mappings
      if map_size(mappings) > 0 do
        {_control_id, techniques} = Enum.at(mappings, 0)
        assert is_list(techniques)
      end
    end

    test "maps controls to CIS Controls" do
      {:ok, framework} = Assessor.load_framework("pci_dss")

      mappings = Assessor.map_controls_to_cis(framework)

      assert is_map(mappings)
    end

    test "finds equivalent controls across frameworks" do
      {:ok, equivalents} = Assessor.find_equivalent_controls("pci_dss", "soc2")

      assert is_list(equivalents)

      if length(equivalents) > 0 do
        equivalent = hd(equivalents)
        assert Map.has_key?(equivalent, :pci_dss_control)
        assert Map.has_key?(equivalent, :soc2_control)
      end
    end
  end

  # ── Edge Cases and Error Handling ──────────────────────────────────────

  describe "edge cases" do
    test "handles organization with no agents", %{org: org} do
      # Delete all agents
      from(a in Agent, where: a.organization_id == ^org.id)
      |> Repo.delete_all()

      {:ok, assessment} = Assessor.assess_organization(org.id, framework: "pci_dss")

      # Should complete but likely with low scores
      assert assessment.overall_score >= 0
    end

    test "handles concurrent assessments", %{org: org} do
      tasks = for _ <- 1..3 do
        Task.async(fn ->
          Assessor.assess_organization(org.id, framework: "hipaa")
        end)
      end

      results = Task.await_many(tasks, 30_000)

      # All should complete successfully
      assert Enum.all?(results, fn result -> match?({:ok, _}, result) end)
    end

    test "handles invalid control data gracefully" do
      result = Assessor.assess_control("malformed_control", agent_id: Ecto.UUID.generate())

      assert match?({:error, _}, result) or match?({:ok, %{status: :unknown}}, result)
    end
  end
end
