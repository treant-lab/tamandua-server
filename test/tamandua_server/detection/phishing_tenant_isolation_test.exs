defmodule TamanduaServer.Detection.PhishingTenantIsolationTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.Detection.{Phishing, PhishingTriage}

  @org_a "00000000-0000-0000-0000-00000000000a"
  @org_b "00000000-0000-0000-0000-00000000000b"

  test "the same Message-ID is deduplicated only inside one organization" do
    message_id = "<#{System.unique_integer([:positive])}@tenant.test>"

    assert {:ok, report_a} =
             Phishing.analyze_for_organization(@org_a, email(@org_b, message_id))

    assert {:ok, report_b} =
             Phishing.analyze_for_organization(@org_b, email(@org_a, message_id))

    assert report_a.organization_id == @org_a
    assert report_b.organization_id == @org_b
    refute report_a.id == report_b.id

    assert {:ok, same_a} =
             Phishing.analyze_for_organization(@org_a, email(@org_b, message_id))

    assert same_a.id == report_a.id
    assert {:error, :not_found} = Phishing.get_report(@org_b, report_a.id)
  end

  test "triage ownership protects reads feedback and tenant statistics" do
    assert {:ok, analysis_a} =
             PhishingTriage.analyze_email_for_organization(
               @org_a,
               email(@org_b, unique_message_id())
             )

    assert {:ok, stored} = PhishingTriage.get_analysis(@org_a, analysis_a.analysis_id)
    assert stored.organization_id == @org_a
    assert {:error, :not_found} = PhishingTriage.get_analysis(@org_b, analysis_a.analysis_id)

    assert {:error, :not_found} =
             PhishingTriage.submit_feedback(
               @org_b,
               analysis_a.analysis_id,
               :incorrect,
               %{}
             )

    assert :ok =
             PhishingTriage.submit_feedback(
               @org_a,
               analysis_a.analysis_id,
               :correct,
               %{}
             )

    assert {:ok, stats_a} = PhishingTriage.get_stats(@org_a)
    assert {:ok, stats_b} = PhishingTriage.get_stats(@org_b)
    assert stats_a.total_analyzed >= 1
    assert stats_b.total_analyzed == 0
  end

  test "campaign fingerprints never correlate across organizations" do
    suffix = System.unique_integer([:positive])
    org_a = "org-campaign-a-#{suffix}"
    org_b = "org-campaign-b-#{suffix}"

    for sequence <- 1..3 do
      assert {:ok, _report} =
               Phishing.analyze_for_organization(
                 org_a,
                 email(org_b, "<campaign-a-#{suffix}-#{sequence}@tenant.test>")
               )
    end

    assert {:ok, _report} =
             Phishing.analyze_for_organization(
               org_b,
               email(org_a, "<campaign-b-#{suffix}@tenant.test>")
             )

    assert {:ok, campaigns_a} = Phishing.list_campaigns(org_a)
    assert {:ok, campaigns_b} = Phishing.list_campaigns(org_b)
    assert Enum.any?(campaigns_a, &(&1.email_count >= 3))
    assert Enum.all?(campaigns_a, &(&1.organization_id == org_a))
    assert Enum.all?(campaigns_b, &(&1.organization_id == org_b))

    refute MapSet.new(Enum.map(campaigns_a, & &1.id)) ==
             MapSet.new(Enum.map(campaigns_b, & &1.id))
  end

  test "a foreign or unknown optional agent fails closed" do
    agent_id = "agent-phishing-#{System.unique_integer([:positive])}"
    :ok = OrgLookup.put(agent_id, @org_a)

    assert {:error, :forbidden} =
             Phishing.analyze_for_organization(
               @org_b,
               email(@org_b, unique_message_id(), agent_id)
             )

    assert {:error, :forbidden} =
             PhishingTriage.analyze_email_for_organization(
               @org_b,
               email(@org_b, unique_message_id(), agent_id)
             )

    assert {:error, :organization_required} = Phishing.analyze(email(@org_a, unique_message_id()))

    assert {:error, :organization_required} =
             PhishingTriage.analyze_email(email(@org_a, unique_message_id()))
  end

  test "ETS keys partition reports dedup campaigns and sender reputation" do
    phishing = File.read!("lib/tamandua_server/detection/phishing.ex")

    assert phishing =~ "{{organization_id, report_id}, report}"
    assert phishing =~ "{{:dedup, organization_id, message_id}, report}"
    assert phishing =~ "{{fingerprint.organization_id, id}, campaign}"
    assert phishing =~ "key = {organization_id, email}"
    assert phishing =~ "organization_id == fingerprint.organization_id"
  end

  test "M365 and Google Workspace pass their owned organization to triage" do
    m365 = File.read!("lib/tamandua_server/email_security/microsoft365.ex")
    google = File.read!("lib/tamandua_server/email_security/google_workspace.ex")

    assert m365 =~ "organization_id: state.organization_id"
    assert google =~ "organization_id: state.organization_id"
    assert m365 =~ "process_email_event(&1, state)"
    assert google =~ "process_email_event(&1, state)"
    assert m365 =~ "analyze_email_for_organization(state.organization_id, email_data)"
    assert google =~ "analyze_email_for_organization(state.organization_id, email_data)"
    assert m365 =~ "organization_id: Map.get(config, :organization_id, state.organization_id)"
    assert google =~ "organization_id: Map.get(config, :organization_id, state.organization_id)"
    refute m365 =~ "organization_id: nil,  # Will be looked up"
    refute google =~ "organization_id: nil,"
  end

  test "public phishing controllers derive scope from authenticated connection assigns" do
    phishing_controller =
      File.read!("lib/tamandua_server_web/controllers/api/v1/phishing_controller.ex")

    email_controller =
      File.read!("lib/tamandua_server_web/controllers/api/v1/email_security_controller.ex")

    assert phishing_controller =~ "Phishing.get_report(organization_id, report_id)"
    assert phishing_controller =~ "Phishing.analyze_for_organization(organization_id, email_data)"

    assert phishing_controller =~
             "Phishing.report_phish_for_organization(organization_id, submission)"

    assert phishing_controller =~ "Phishing.list_campaigns(organization_id, opts)"
    assert phishing_controller =~ "Phishing.get_stats(organization_id)"
    assert phishing_controller =~ "put_status(:forbidden)"
    assert email_controller =~ "PhishingTriage.get_analysis(organization_id, analysis_id)"

    assert email_controller =~
             "PhishingTriage.analyze_email_for_organization(organization_id, email_data)"

    assert email_controller =~
             "PhishingTriage.submit_feedback(organization_id, analysis_id, feedback_atom, metadata)"

    assert email_controller =~ "PhishingTriage.analyze_campaign(organization_id, email_id)"
    assert email_controller =~ "organization_id: organization_id"
  end

  defp email(organization_id, message_id, agent_id \\ nil) do
    %{
      organization_id: organization_id,
      agent_id: agent_id,
      headers: %{
        "from" => "sender@example.com",
        "to" => "recipient@example.com",
        "subject" => "Routine status update",
        "message-id" => message_id,
        "authentication-results" => "spf=pass dkim=pass dmarc=pass"
      },
      body: "Routine project status update with no links or attachments.",
      attachments: []
    }
  end

  defp unique_message_id do
    "<#{System.unique_integer([:positive])}@tenant.test>"
  end
end
