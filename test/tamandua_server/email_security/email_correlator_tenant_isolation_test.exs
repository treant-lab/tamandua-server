defmodule TamanduaServer.EmailSecurity.EmailCorrelatorTenantIsolationTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.EmailSecurity.EmailCorrelator

  @tables [:email_correlations, :email_attachments, :email_user_risk, :email_attack_chains]

  setup do
    unless Process.whereis(OrgLookup) do
      start_supervised!(OrgLookup)
    end

    unless Process.whereis(EmailCorrelator) do
      start_supervised!({EmailCorrelator, auto_create_alerts: false})
    end

    :sys.replace_state(EmailCorrelator, fn state ->
      %{state | config: Map.put(state.config, :auto_create_alerts, false), stats: %{}}
    end)

    Enum.each(@tables, &:ets.delete_all_objects/1)
    :ok
  end

  test "legacy public arities fail closed" do
    assert {:error, :organization_required} = EmailCorrelator.correlate_email(%{})
    assert {:error, :organization_required} = EmailCorrelator.track_attachment(%{})
    assert {:error, :organization_required} = EmailCorrelator.correlate_file_event(%{})
    assert {:error, :organization_required} = EmailCorrelator.correlate_process_event(%{})
    assert {:error, :organization_required} = EmailCorrelator.build_attack_chain("email")
    assert {:error, :organization_required} = EmailCorrelator.get_attack_chain("email")
    assert {:error, :organization_required} = EmailCorrelator.get_user_chains("user@test")

    assert {:error, :organization_required} =
             EmailCorrelator.get_user_chains("user@test", limit: 1)

    assert {:error, :organization_required} = EmailCorrelator.get_user_risk("user@test")
    assert {:error, :organization_required} = EmailCorrelator.list_attack_chains(limit: 1)
    assert {:error, :organization_required} = EmailCorrelator.get_stats()
    assert {:error, :organization_required} = EmailCorrelator.cleanup()
  end

  test "same email message hash and user remain isolated across organizations" do
    org_a = unique("org-a")
    org_b = unique("org-b")
    event = email_event(:malicious)

    assert {:ok, _} = EmailCorrelator.correlate_email(org_a, event)
    assert {:ok, _} = EmailCorrelator.correlate_email(org_b, event)
    assert {:ok, _} = EmailCorrelator.correlate_email(org_a, %{event | id: "email-a-2"})

    assert {:ok, risk_a} = EmailCorrelator.get_user_risk(org_a, event.recipient)
    assert {:ok, risk_b} = EmailCorrelator.get_user_risk(org_b, event.recipient)
    assert risk_a.total_emails == 2
    assert risk_b.total_emails == 1

    assert {:ok, chain_a} = EmailCorrelator.build_attack_chain(org_a, event.id)
    assert {:ok, chain_b} = EmailCorrelator.build_attack_chain(org_b, event.id)
    assert chain_a.organization_id == org_a
    assert chain_b.organization_id == org_b

    assert {:ok, [listed_a]} = EmailCorrelator.list_attack_chains(org_a, limit: 10)
    assert {:ok, [listed_b]} = EmailCorrelator.list_attack_chains(org_b, limit: 10)
    assert listed_a.organization_id == org_a
    assert listed_b.organization_id == org_b

    assert {:ok, [user_chain_a]} =
             EmailCorrelator.get_user_chains(org_a, event.recipient, limit: 10)

    assert user_chain_a.organization_id == org_a
    assert {:ok, stats_a} = EmailCorrelator.get_stats(org_a)
    assert {:ok, stats_b} = EmailCorrelator.get_stats(org_b)
    assert stats_a.emails_correlated == 2
    assert stats_b.emails_correlated == 1

    assert :ets.member(:email_correlations, {org_a, :email, event.id})
    assert :ets.member(:email_correlations, {org_b, :message, event.message_id})
    assert :ets.member(:email_attachments, {org_a, :hash, attachment_hash()})
    assert :ets.member(:email_user_risk, {org_b, event.recipient})
    assert :ets.member(:email_attack_chains, {org_a, event.id})
  end

  test "endpoint correlation uses authoritative agent organization and never crosses tenants" do
    org_a = unique("org-a")
    org_b = unique("org-b")
    agent_a = unique("agent-a")
    agent_b = unique("agent-b")
    :ok = OrgLookup.put(agent_a, org_a)
    :ok = OrgLookup.put(agent_b, org_b)
    telemetry_id = "email-correlator-test-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        telemetry_id,
        [:tamandua, :email_security, :correlation_scope_rejected],
        fn name, measurements, metadata, owner ->
          send(owner, {:scope_rejected, name, measurements, metadata})
        end,
        self()
      )

    on_exit(fn -> :telemetry.detach(telemetry_id) end)

    assert {:ok, _} = EmailCorrelator.correlate_email(org_a, email_event(:suspicious))

    assert {:ok, %{matched: false}} =
             EmailCorrelator.correlate_file_event(org_b, file_event(agent_b))

    assert {:ok, %{matched: true, email_id: "shared-email"}} =
             EmailCorrelator.correlate_file_event(org_a, file_event(agent_a))

    assert {:ok, %{matched: false}} =
             EmailCorrelator.correlate_process_event(org_b, process_event(agent_b))

    assert {:ok, %{matched: true, attack_chain: chain}} =
             EmailCorrelator.correlate_process_event(org_a, process_event(agent_a))

    assert chain.organization_id == org_a
    assert :ets.member(:email_correlations, {org_a, :file, "file-event"})
    assert :ets.member(:email_correlations, {org_a, :process, "process-event"})
    assert :ets.member(:email_correlations, {org_b, :file, "file-event"})

    assert {:error, :agent_organization_mismatch} =
             EmailCorrelator.correlate_file_event(org_b, file_event(agent_a))

    assert {:error, :organization_claim_mismatch} =
             EmailCorrelator.correlate_file_event(
               org_a,
               Map.put(file_event(agent_a), :organization_id, org_b)
             )

    assert {:error, :unknown_agent} =
             EmailCorrelator.correlate_process_event(org_a, process_event(unique("unknown")))

    assert_receive {:scope_rejected, [:tamandua, :email_security, :correlation_scope_rejected],
                    %{count: 1}, %{reason: :agent_organization_mismatch}}

    assert_receive {:scope_rejected, [:tamandua, :email_security, :correlation_scope_rejected],
                    %{count: 1}, %{reason: :organization_claim_mismatch}}

    assert_receive {:scope_rejected, [:tamandua, :email_security, :correlation_scope_rejected],
                    %{count: 1}, %{reason: :unknown_agent}}
  end

  test "cleanup and PubSub are tenant scoped" do
    org_a = unique("org-a")
    org_b = unique("org-b")
    old = DateTime.add(DateTime.utc_now(), -48, :hour)

    assert :ok =
             Phoenix.PubSub.subscribe(
               TamanduaServer.PubSub,
               "email_security_correlation:#{org_a}"
             )

    assert :ok =
             Phoenix.PubSub.subscribe(
               TamanduaServer.PubSub,
               "email_security_correlation:#{org_b}"
             )

    assert {:ok, _} =
             EmailCorrelator.correlate_email(org_a, %{email_event(:benign) | timestamp: old})

    assert {:ok, _} =
             EmailCorrelator.correlate_email(org_b, %{email_event(:benign) | timestamp: old})

    assert {:ok, chain_a} = EmailCorrelator.build_attack_chain(org_a, "shared-email")
    assert_receive {:email_attack_chain_updated, ^chain_a}
    refute_receive {:email_attack_chain_updated, %{organization_id: ^org_b}}, 20

    assert :ok = EmailCorrelator.cleanup(org_a)
    _ = :sys.get_state(EmailCorrelator)

    assert {:error, :not_found} = EmailCorrelator.build_attack_chain(org_a, "shared-email")
    assert {:ok, _} = EmailCorrelator.build_attack_chain(org_b, "shared-email")
  end

  test "cached attack-chain lookup is read-only" do
    org = unique("org-read-only")
    assert {:ok, _} = EmailCorrelator.correlate_email(org, email_event(:suspicious))
    assert {:ok, materialized} = EmailCorrelator.build_attack_chain(org, "shared-email")
    assert {:ok, stats_before} = EmailCorrelator.get_stats(org)

    assert :ok =
             Phoenix.PubSub.subscribe(
               TamanduaServer.PubSub,
               "email_security_correlation:#{org}"
             )

    assert {:ok, ^materialized} = EmailCorrelator.get_attack_chain(org, "shared-email")
    assert {:ok, stats_after} = EmailCorrelator.get_stats(org)
    assert stats_after == stats_before
    refute_receive {:email_attack_chain_updated, _}, 20

    assert {:error, :not_found} = EmailCorrelator.get_attack_chain(org, "unknown-email")
  end

  test "REST and Inertia projections pass only authenticated organization scope" do
    controller =
      File.read!("lib/tamandua_server_web/controllers/api/v1/email_security_controller.ex")

    inertia = File.read!("lib/tamandua_server_web/controllers/inertia_controller.ex")

    assert controller =~ "EmailCorrelator.list_attack_chains(organization_id, opts)"
    assert controller =~ "EmailCorrelator.get_attack_chain(organization_id, email_id)"
    assert controller =~ "EmailCorrelator.get_user_risk(organization_id, email)"
    assert controller =~ "EmailCorrelator.get_user_chains(organization_id, email, opts)"
    assert controller =~ "EmailCorrelator.get_stats(organization_id)"
    assert controller =~ "organization_id = current_organization_id(conn)"
    assert inertia =~ "EmailCorrelator.get_stats(organization_id)"
    assert inertia =~ "EmailCorrelator.list_attack_chains(organization_id,"

    refute controller =~ "EmailCorrelator.build_attack_chain(email_id)"
    refute controller =~ "EmailCorrelator.get_attack_chain(email_id)"
    refute controller =~ "EmailCorrelator.get_user_risk(email)"
    refute controller =~ "EmailCorrelator.get_user_chains(email, opts)"
    refute inertia =~ "EmailCorrelator.get_stats()"
  end

  test "full and lab-light supervision start correlator after agent organization authority" do
    application = File.read!("lib/tamandua_server/application.ex")

    assert length(:binary.matches(application, "TamanduaServer.EmailSecurity.EmailCorrelator")) ==
             2

    assert application =~
             ~r/TamanduaServer\.Agents\.OrgLookup,\s+TamanduaServer\.Agents\.Registry,\s+(?:#.*\s+)*TamanduaServer\.EmailSecurity\.EmailCorrelator/
  end

  defp email_event(verdict) do
    %{
      id: "shared-email",
      message_id: "<shared-message@example.test>",
      recipient: "victor@example.test",
      sender: "attacker@example.test",
      subject: "Shared subject",
      timestamp: DateTime.utc_now(),
      verdict: verdict,
      attachments: [
        %{
          filename: "invoice.exe",
          sha256: attachment_hash(),
          content_type: "application/x-dosexec"
        }
      ]
    }
  end

  defp file_event(agent_id) do
    %{
      event_id: "file-event",
      agent_id: agent_id,
      timestamp: DateTime.utc_now(),
      payload: %{path: "C:/Users/victor/Downloads/invoice.exe", sha256: attachment_hash()}
    }
  end

  defp process_event(agent_id) do
    %{
      event_id: "process-event",
      agent_id: agent_id,
      timestamp: DateTime.utc_now(),
      payload: %{
        path: "C:/Users/victor/Downloads/invoice.exe",
        sha256: attachment_hash(),
        pid: 4242
      }
    }
  end

  defp attachment_hash, do: String.duplicate("a", 64)

  defp unique(prefix) do
    "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
  end
end
