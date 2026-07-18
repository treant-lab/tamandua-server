defmodule TamanduaServer.EmailSecurity.TenantRuntimeTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.EmailSecurity.{
    GoogleWorkspace,
    Microsoft365,
    RuntimeConfigStore,
    RuntimeSupervisor
  }

  defmodule M365ForbiddenPollAdapter do
    def fetch_security_events(_state), do: {:error, {:api_error, 403}}
    def fetch_email_threats(_state), do: flunk("second source must not run after failure")
  end

  defmodule GoogleOutagePollAdapter do
    def fetch_gmail_activity(_state), do: {:error, {:http_error, :econnrefused}}
    def fetch_suspicious_logins(_state), do: flunk("second source must not run after failure")
  end

  defmodule AtomicityProvider do
    use GenServer

    alias TamanduaServer.EmailSecurity.{RuntimeConfigStore, RuntimeSupervisor}

    def start_link(opts) do
      organization_id = Keyword.fetch!(opts, :organization_id)

      GenServer.start_link(__MODULE__, organization_id,
        name: RuntimeSupervisor.via(__MODULE__, organization_id)
      )
    end

    @impl true
    def init(organization_id) do
      with {:ok, revision, config} <- RuntimeConfigStore.fetch(__MODULE__, organization_id) do
        if Map.get(config, :start_failure, false) do
          {:stop, :injected_start_failure}
        else
          {:ok, %{organization_id: organization_id, revision: revision, config: config}}
        end
      end
    end

    @impl true
    def handle_call({:reload_config, revision}, _from, state) do
      with {:ok, current_revision, config} when current_revision >= revision <-
             RuntimeConfigStore.fetch(__MODULE__, state.organization_id) do
        case Map.get(config, :reload_behavior, :ok) do
          :fail ->
            {:reply, {:error, :injected_reload_failure}, state}

          {:sleep, milliseconds} ->
            Process.sleep(milliseconds)
            {:reply, :ok, %{state | revision: current_revision, config: config}}

          :ok ->
            {:reply, :ok, %{state | revision: current_revision, config: config}}
        end
      else
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
  end

  setup do
    unless Process.whereis(RuntimeSupervisor) do
      start_supervised!(RuntimeSupervisor)
    end

    :ok
  end

  test "Microsoft 365 configuration and credentials are isolated per tenant" do
    org_a = unique_org("m365-a")
    org_b = unique_org("m365-b")

    assert :ok =
             Microsoft365.update_config(org_a, %{
               tenant_id: "tenant-a",
               client_id: "client-a",
               client_secret: "secret-a",
               enabled: false
             })

    assert :ok =
             Microsoft365.update_config(org_b, %{
               tenant_id: "tenant-b",
               client_id: "client-b",
               client_secret: "secret-b",
               enabled: false
             })

    assert {:ok, pid_a} = RuntimeSupervisor.lookup(Microsoft365, org_a)
    assert {:ok, pid_b} = RuntimeSupervisor.lookup(Microsoft365, org_b)
    refute pid_a == pid_b

    state_a = :sys.get_state(pid_a)
    state_b = :sys.get_state(pid_b)
    assert {state_a.organization_id, state_a.client_secret} == {org_a, "secret-a"}
    assert {state_b.organization_id, state_b.client_secret} == {org_b, "secret-b"}

    assert :ok = Microsoft365.update_config(org_a, %{client_secret: "secret-a-rotated"})
    assert :sys.get_state(pid_a).client_secret == "secret-a-rotated"
    assert :sys.get_state(pid_b).client_secret == "secret-b"
  end

  test "Google Workspace concurrent configuration remains tenant keyed" do
    org_a = unique_org("google-a")
    org_b = unique_org("google-b")

    configurations = [
      {org_a, %{admin_email: "admin-a@example.test", service_account_key: "key-a"}},
      {org_b, %{admin_email: "admin-b@example.test", service_account_key: "key-b"}}
    ]

    configurations
    |> Task.async_stream(
      fn {organization_id, config} ->
        GoogleWorkspace.update_config(organization_id, Map.put(config, :enabled, false))
      end,
      ordered: false
    )
    |> Enum.each(fn result -> assert result == {:ok, :ok} end)

    assert {:ok, pid_a} = RuntimeSupervisor.lookup(GoogleWorkspace, org_a)
    assert {:ok, pid_b} = RuntimeSupervisor.lookup(GoogleWorkspace, org_b)

    assert :sys.get_state(pid_a).admin_email == "admin-a@example.test"
    assert :sys.get_state(pid_b).admin_email == "admin-b@example.test"
    assert :sys.get_state(pid_a).organization_id == org_a
    assert :sys.get_state(pid_b).organization_id == org_b
  end

  test "a foreign or missing tenant never falls back to another tenant instance" do
    org_a = unique_org("configured")
    org_b = unique_org("foreign")

    assert :ok = Microsoft365.update_config(org_a, %{enabled: false})
    assert :ok = GoogleWorkspace.update_config(org_a, %{enabled: false})

    assert {:error, :integration_not_configured} = Microsoft365.get_status(org_b)
    assert {:error, :integration_not_configured} = Microsoft365.list_quarantine(org_b)

    assert {:error, :integration_not_configured} =
             Microsoft365.release_from_quarantine(org_b, "message-a")

    assert {:error, :integration_not_configured} =
             Microsoft365.search_emails(org_b, "subject:secret")

    assert {:error, :integration_not_configured} = GoogleWorkspace.get_status(org_b)
    assert {:error, :integration_not_configured} = GoogleWorkspace.get_email(org_b, "a@b", "id")

    assert {:error, :integration_not_configured} =
             GoogleWorkspace.search_emails(org_b, "a@b", "secret")

    assert {:error, :integration_not_configured} =
             GoogleWorkspace.move_to_spam(org_b, "a@b", "id")

    assert {:error, :organization_required} = Microsoft365.get_status(nil)
    assert {:error, :organization_required} = GoogleWorkspace.get_status("")
  end

  test "polling forwards the tenant-owned state organization to phishing triage" do
    for file <- [
          "lib/tamandua_server/email_security/microsoft365.ex",
          "lib/tamandua_server/email_security/google_workspace.ex"
        ] do
      source = File.read!(file)

      assert source =~
               "PhishingTriage.analyze_email_for_organization(state.organization_id, email_data)"

      assert source =~ "organization_id: state.organization_id"
      refute source =~ "name: __MODULE__"
    end
  end

  test "disable cancels pending authentication before it fires" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("disable")
      assert :ok = provider.update_config(org, Map.put(config, :enabled, true))
      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)

      enabled_state = :sys.get_state(pid)
      assert is_reference(enabled_state.auth_timer_ref)
      assert is_integer(Process.read_timer(enabled_state.auth_timer_ref))
      enabled_generation = enabled_state.config_generation

      assert :ok = provider.update_config(org, %{enabled: false})
      disabled_state = :sys.get_state(pid)
      refute disabled_state.enabled
      assert disabled_state.config_generation == enabled_generation + 1
      assert disabled_state.auth_timer_ref == nil
      assert disabled_state.poll_timer_ref == nil
      assert Process.read_timer(enabled_state.auth_timer_ref) == false

      send(pid, {:authenticate, enabled_generation})
      send(pid, {:poll, enabled_generation})
      assert :sys.get_state(pid) == disabled_state
    end)
  end

  test "repeated configuration updates replace rather than multiply timer loops" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("repeat")
      assert :ok = provider.update_config(org, Map.put(config, :enabled, true))
      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)
      first_state = :sys.get_state(pid)

      assert :ok = provider.update_config(org, %{enabled: true, poll_interval_ms: 123_456})
      second_state = :sys.get_state(pid)

      assert second_state.config_generation == first_state.config_generation + 1
      assert is_reference(second_state.auth_timer_ref)
      refute second_state.auth_timer_ref == first_state.auth_timer_ref
      assert Process.read_timer(first_state.auth_timer_ref) == false
      assert is_integer(Process.read_timer(second_state.auth_timer_ref))
      assert second_state.poll_timer_ref == nil
    end)
  end

  test "stale authentication and poll messages cannot act on rotated configuration" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("stale")
      assert :ok = provider.update_config(org, Map.put(config, :enabled, true))
      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)
      old_generation = :sys.get_state(pid).config_generation

      assert :ok = provider.update_config(org, %{enabled: true})
      current_state = :sys.get_state(pid)
      assert current_state.config_generation == old_generation + 1

      send(pid, {:authenticate, old_generation})
      send(pid, {:poll, old_generation})

      assert :sys.get_state(pid) == current_state
      assert Process.alive?(pid)
    end)
  end

  test "disabled integrations reject manual API lanes before authentication" do
    org = unique_org("manual-disabled")

    assert :ok =
             Microsoft365.update_config(
               org,
               Map.merge(m365_config(), %{enabled: false, poll_interval_ms: 0})
             )

    assert {:error, :integration_disabled} = Microsoft365.poll_events(org)
    assert {:error, :integration_disabled} = Microsoft365.get_threat_intel(org)
    assert {:error, :integration_disabled} = Microsoft365.list_quarantine(org)
    assert {:error, :integration_disabled} = Microsoft365.search_emails(org, "subject:test")

    assert :ok =
             GoogleWorkspace.update_config(
               org,
               Map.merge(google_config(), %{enabled: false, poll_interval_ms: "0"})
             )

    assert {:error, :integration_disabled} = GoogleWorkspace.poll_events(org)

    assert {:error, :integration_disabled} =
             GoogleWorkspace.get_gmail_logs(org, DateTime.utc_now(), DateTime.utc_now())

    assert {:error, :integration_disabled} =
             GoogleWorkspace.search_emails(org, "user@example.test", "subject:test")

    assert {:ok, m365_pid} = RuntimeSupervisor.lookup(Microsoft365, org)
    assert {:ok, google_pid} = RuntimeSupervisor.lookup(GoogleWorkspace, org)
    assert :sys.get_state(m365_pid).poll_interval == :timer.seconds(10)
    assert :sys.get_state(google_pid).poll_interval == :timer.seconds(10)
  end

  test "poll interval is bounded and invalid updates retain the last safe value" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("bounds")

      assert :ok =
               provider.update_config(
                 org,
                 Map.merge(config, %{enabled: false, poll_interval_ms: 100_000_000})
               )

      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)
      assert :sys.get_state(pid).poll_interval == :timer.hours(24)

      assert :ok = provider.update_config(org, %{poll_interval_ms: "not-an-integer"})
      assert :sys.get_state(pid).poll_interval == :timer.hours(24)
    end)
  end

  test "Google accepts an in-memory service-account map as configured credentials" do
    org = unique_org("google-map-key")

    assert :ok =
             GoogleWorkspace.update_config(org, %{
               enabled: true,
               admin_email: "admin@example.test",
               service_account_key: %{
                 "private_key" => "test",
                 "client_email" => "svc@example.test"
               }
             })

    assert {:ok, pid} = RuntimeSupervisor.lookup(GoogleWorkspace, org)
    state = :sys.get_state(pid)
    assert is_reference(state.auth_timer_ref)

    assert :ok = GoogleWorkspace.update_config(org, %{enabled: false})
  end

  test "rotated configuration survives a real provider crash and restart" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("restart")
      secret_patch = secret_patch(provider, "rotated-secret")

      assert :ok =
               provider.update_config(
                 org,
                 Map.merge(config, %{enabled: false, poll_interval_ms: 30_000})
               )

      assert {:ok, old_pid} = RuntimeSupervisor.lookup(provider, org)

      assert :ok =
               provider.update_config(
                 org,
                 Map.merge(secret_patch, %{enabled: true, poll_interval_ms: 123_456})
               )

      Process.exit(old_pid, :kill)
      assert {:ok, new_pid} = await_restarted(provider, org, old_pid)
      state = :sys.get_state(new_pid)

      assert state.enabled
      assert state.poll_interval == 123_456
      assert provider_secret(provider, state) == "rotated-secret"
      assert is_reference(state.auth_timer_ref)
    end)
  end

  test "concurrent updates converge on the serialized runtime store revision" do
    org = unique_org("concurrent")
    assert :ok = Microsoft365.update_config(org, Map.put(m365_config(), :enabled, false))

    1..20
    |> Task.async_stream(
      fn index ->
        Microsoft365.update_config(org, %{
          client_secret: "secret-#{index}",
          poll_interval_ms: 10_000 + index
        })
      end,
      max_concurrency: 10,
      ordered: false
    )
    |> Enum.each(fn result -> assert result == {:ok, :ok} end)

    assert {:ok, revision, stored} = RuntimeConfigStore.fetch(Microsoft365, org)
    assert {:ok, pid} = RuntimeSupervisor.lookup(Microsoft365, org)
    state = :sys.get_state(pid)

    assert state.config_revision == revision
    assert state.client_secret == stored.client_secret
    assert state.poll_interval == stored.poll_interval_ms
  end

  test "provider start failure rolls back the candidate revision" do
    org = unique_org("atomic-start-failure")

    assert {:error, :provider_start_failed} =
             RuntimeSupervisor.update_config(AtomicityProvider, org, %{start_failure: true})

    assert {:error, :integration_not_configured} =
             RuntimeConfigStore.fetch(AtomicityProvider, org)

    assert {:error, :integration_not_configured} =
             RuntimeSupervisor.lookup(AtomicityProvider, org)
  end

  test "provider reload failure restores the previous revision and runtime" do
    org = unique_org("atomic-reload-failure")

    assert {:ok, original_pid, :started, original_revision} =
             RuntimeSupervisor.update_config(AtomicityProvider, org, %{secret: "original"})

    assert {:error, :provider_reload_failed} =
             RuntimeSupervisor.update_config(AtomicityProvider, org, %{
               secret: "must-not-apply",
               reload_behavior: :fail
             })

    assert {:ok, ^original_revision, %{secret: "original"}} =
             RuntimeConfigStore.fetch(AtomicityProvider, org)

    assert {:ok, replacement_pid} = RuntimeSupervisor.lookup(AtomicityProvider, org)
    refute replacement_pid == original_pid
    assert :sys.get_state(replacement_pid).config == %{secret: "original"}

    assert {:ok, ^replacement_pid, :existing, accepted_revision} =
             RuntimeSupervisor.update_config(AtomicityProvider, org, %{accepted: true})

    assert accepted_revision == original_revision + 1

    assert {:ok, ^accepted_revision, %{secret: "original", accepted: true}} =
             RuntimeConfigStore.fetch(AtomicityProvider, org)
  end

  test "provider reload timeout restores the previous revision before replacement starts" do
    org = unique_org("atomic-reload-timeout")

    assert {:ok, original_pid, :started, original_revision} =
             RuntimeSupervisor.update_config(AtomicityProvider, org, %{secret: "original"})

    assert {:error, :provider_reload_failed} =
             RuntimeSupervisor.update_config(
               AtomicityProvider,
               org,
               %{secret: "must-not-apply", reload_behavior: {:sleep, 200}},
               reload_timeout: 20
             )

    assert {:ok, ^original_revision, %{secret: "original"}} =
             RuntimeConfigStore.fetch(AtomicityProvider, org)

    assert {:ok, replacement_pid} = RuntimeSupervisor.lookup(AtomicityProvider, org)
    refute replacement_pid == original_pid
    assert :sys.get_state(replacement_pid).config == %{secret: "original"}
  end

  test "runtime config store failure rejects updates without mutating provider state" do
    org = unique_org("store-failure")
    assert :ok = Microsoft365.update_config(org, Map.put(m365_config(), :enabled, false))
    assert {:ok, pid} = RuntimeSupervisor.lookup(Microsoft365, org)
    before = :sys.get_state(pid)

    :ok = :sys.suspend(RuntimeSupervisor)
    Process.exit(Process.whereis(RuntimeConfigStore), :kill)

    assert {:error, :runtime_config_unavailable} =
             Microsoft365.update_config(org, %{client_secret: "must-not-apply"})

    assert :sys.get_state(pid) == before
    :ok = :sys.resume(RuntimeSupervisor)
    assert eventually(fn -> is_pid(Process.whereis(RuntimeConfigStore)) end)
  end

  test "provider 403 and outage do not advance poll success and record sanitized errors" do
    cases = [
      {Microsoft365, M365ForbiddenPollAdapter, m365_config(), {:api_error, 403}},
      {GoogleWorkspace, GoogleOutagePollAdapter, google_config(), {:http_error, :econnrefused}}
    ]

    Enum.each(cases, fn {provider, adapter, config, expected_error} ->
      org = unique_org("poll-error")
      Application.put_env(:tamandua_server, poll_adapter_env(provider), adapter)

      assert :ok = provider.update_config(org, Map.merge(config, %{enabled: true}))
      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)

      :sys.replace_state(pid, fn state ->
        %{
          state
          | access_token: "test-token",
            token_expires_at: DateTime.add(DateTime.utc_now(), 3_600, :second)
        }
      end)

      assert {:error, ^expected_error} = provider.poll_events(org)
      state = :sys.get_state(pid)
      assert state.last_poll_time == nil
      assert state.stats.api_calls == 0
      assert state.stats.errors == 1
      assert state.stats.last_error.reason == inspect(expected_error)

      assert :ok = provider.update_config(org, %{enabled: false})
      Application.delete_env(:tamandua_server, poll_adapter_env(provider))
    end)
  end

  test "runtime state and config store inspection redact credentials" do
    org = unique_org("inspect-redaction")

    assert :ok =
             Microsoft365.update_config(org, %{
               tenant_id: "tenant",
               client_id: "client",
               client_secret: "never-print-me",
               enabled: false
             })

    assert {:ok, pid} = RuntimeSupervisor.lookup(Microsoft365, org)
    refute inspect(:sys.get_state(pid)) =~ "never-print-me"
    refute inspect(:sys.get_state(RuntimeConfigStore)) =~ "never-print-me"
  end

  test "explicit null credentials fail without changing the stored secret" do
    Enum.each(provider_cases(), fn {provider, config} ->
      org = unique_org("null-secret")
      assert :ok = provider.update_config(org, Map.put(config, :enabled, false))
      assert {:ok, pid} = RuntimeSupervisor.lookup(provider, org)
      before = :sys.get_state(pid)

      assert {:error, :secret_cannot_be_null} =
               provider.update_config(org, secret_patch(provider, nil))

      assert provider_secret(provider, :sys.get_state(pid)) == provider_secret(provider, before)
    end)
  end

  defp provider_cases do
    [
      {Microsoft365, m365_config()},
      {GoogleWorkspace, google_config()}
    ]
  end

  defp m365_config, do: %{tenant_id: "tenant", client_id: "client", client_secret: "secret"}

  defp google_config do
    %{admin_email: "admin@example.test", service_account_key: "service-account-json"}
  end

  defp secret_patch(Microsoft365, value), do: %{client_secret: value}
  defp secret_patch(GoogleWorkspace, value), do: %{service_account_key: value}
  defp provider_secret(Microsoft365, state), do: state.client_secret
  defp provider_secret(GoogleWorkspace, state), do: state.service_account_key
  defp poll_adapter_env(Microsoft365), do: :microsoft365_email_security_poll_adapter

  defp poll_adapter_env(GoogleWorkspace),
    do: :google_workspace_email_security_poll_adapter

  defp await_restarted(provider, organization_id, old_pid) do
    Enum.reduce_while(1..100, {:error, :restart_timeout}, fn _, _acc ->
      case RuntimeSupervisor.lookup(provider, organization_id) do
        {:ok, pid} when pid != old_pid ->
          {:halt, {:ok, pid}}

        _ ->
          Process.sleep(10)
          {:cont, {:error, :restart_timeout}}
      end
    end)
  end

  defp eventually(fun) do
    Enum.reduce_while(1..100, false, fn _, _acc ->
      if fun.(),
        do: {:halt, true},
        else:
          (
            Process.sleep(10)
            {:cont, false}
          )
    end)
  end

  defp unique_org(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
