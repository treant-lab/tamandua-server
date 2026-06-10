defmodule TamanduaServer.ThreatIntel.CredentialHygiene do
  @moduledoc """
  Credential Hygiene Checker for Tamandua EDR.

  Monitors the overall health of an organization's credential ecosystem:

  - **Weak Password Detection** - HIBP Passwords API (k-anonymity, never plaintext)
  - **Password Reuse Detection** - Cross-service hash comparison
  - **Certificate Expiration** - TLS/mTLS certificate monitoring
  - **API Key Rotation** - Age-based alerts for stale API keys
  - **Service Account Hygiene** - Unused/over-privileged service accounts

  ## Security Model

  All password operations use hashed representations exclusively. Plaintext
  passwords are never stored, transmitted, or logged. The HIBP Passwords API
  uses SHA-1 prefix k-anonymity so only the first 5 hex characters leave the
  system.

  Multi-tenant: all operations scoped to org_id.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.DarkWebMonitor

  # ETS tables
  @ets_cert_watch :credential_certs
  @ets_api_keys :credential_api_keys
  @ets_service_accounts :credential_service_accounts
  @ets_password_hashes :credential_password_hashes
  @ets_hygiene_scores :credential_hygiene_scores

  # Check intervals
  @cert_check_interval :timer.hours(6)
  @api_key_check_interval :timer.hours(12)
  @service_account_check_interval :timer.hours(24)
  @password_audit_interval :timer.hours(24)

  # Thresholds
  @cert_expiry_warning_days 30
  @cert_expiry_critical_days 7
  @api_key_rotation_warning_days 90
  @api_key_rotation_critical_days 180
  @service_account_unused_days 90

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if a password hash has been compromised via HIBP k-anonymity API.

  Takes a SHA-1 hex string. Returns `{:ok, count}` where count is the number
  of times the password appeared in known breaches (0 = not found).
  """
  @spec check_password(String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def check_password(sha1_hex) do
    DarkWebMonitor.check_password_hash(sha1_hex)
  end

  @doc """
  Submit a batch of password hashes for audit. Used for proactive
  credential hygiene checks across the organization.

  Each entry is `%{user_id: ..., sha1_hex: ..., service: ...}`.
  Returns a list of compromised entries with breach counts.
  """
  @spec audit_passwords(String.t(), [map()]) :: {:ok, [map()]}
  def audit_passwords(org_id, entries) do
    GenServer.call(__MODULE__, {:audit_passwords, org_id, entries}, 300_000)
  end

  @doc """
  Detect password reuse across services. Takes a list of
  `%{user_id, service, password_sha256}` entries and returns
  users with identical hashes across multiple services.
  """
  @spec detect_reuse(String.t(), [map()]) :: {:ok, [map()]}
  def detect_reuse(org_id, entries) do
    GenServer.call(__MODULE__, {:detect_reuse, org_id, entries})
  end

  @doc """
  Register a TLS certificate for expiration monitoring.
  """
  @spec watch_certificate(String.t(), map()) :: :ok
  def watch_certificate(org_id, cert_info) do
    GenServer.call(__MODULE__, {:watch_cert, org_id, cert_info})
  end

  @doc """
  Remove a certificate from monitoring.
  """
  @spec unwatch_certificate(String.t(), String.t()) :: :ok
  def unwatch_certificate(org_id, cert_id) do
    GenServer.call(__MODULE__, {:unwatch_cert, org_id, cert_id})
  end

  @doc """
  Register an API key for rotation monitoring.
  """
  @spec track_api_key(String.t(), map()) :: :ok
  def track_api_key(org_id, key_info) do
    GenServer.call(__MODULE__, {:track_api_key, org_id, key_info})
  end

  @doc """
  Mark an API key as rotated (resets the age timer).
  """
  @spec mark_key_rotated(String.t(), String.t()) :: :ok | {:error, :not_found}
  def mark_key_rotated(org_id, key_id) do
    GenServer.call(__MODULE__, {:mark_key_rotated, org_id, key_id})
  end

  @doc """
  Register a service account for hygiene monitoring.
  """
  @spec track_service_account(String.t(), map()) :: :ok
  def track_service_account(org_id, account_info) do
    GenServer.call(__MODULE__, {:track_service_account, org_id, account_info})
  end

  @doc """
  Record activity for a service account (resets unused timer).
  """
  @spec record_service_account_activity(String.t(), String.t()) :: :ok
  def record_service_account_activity(org_id, account_id) do
    GenServer.cast(__MODULE__, {:service_account_activity, org_id, account_id})
  end

  @doc """
  Get the full credential hygiene report for an organization.
  """
  @spec get_hygiene_report(String.t()) :: map()
  def get_hygiene_report(org_id) do
    GenServer.call(__MODULE__, {:get_report, org_id})
  end

  @doc """
  Get overall hygiene score (0-100) for an organization.
  """
  @spec get_hygiene_score(String.t()) :: integer()
  def get_hygiene_score(org_id) do
    GenServer.call(__MODULE__, {:get_score, org_id})
  end

  @doc """
  Get engine statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ets_cert_watch, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_api_keys, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_service_accounts, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_password_hashes, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_hygiene_scores, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      stats: %{
        passwords_checked: 0,
        compromised_found: 0,
        reuse_detected: 0,
        certs_monitored: 0,
        certs_expiring: 0,
        api_keys_tracked: 0,
        api_keys_stale: 0,
        service_accounts_tracked: 0,
        service_accounts_unused: 0,
        last_audit: nil
      }
    }

    # Schedule periodic checks
    schedule_cert_check()
    schedule_api_key_check()
    schedule_service_account_check()
    schedule_password_audit()

    Logger.info("[CredentialHygiene] Initialized")
    {:ok, state}
  end

  # -- Password audit ------------------------------------------------------

  @impl true
  def handle_call({:audit_passwords, org_id, entries}, _from, state) do
    compromised = Enum.reduce(entries, [], fn entry, acc ->
      sha1 = entry[:sha1_hex] || entry["sha1_hex"]

      if sha1 do
        case DarkWebMonitor.check_password_hash(sha1) do
          {:ok, count} when count > 0 ->
            finding = %{
              user_id: entry[:user_id] || entry["user_id"],
              service: entry[:service] || entry["service"],
              breach_count: count,
              severity: cond do
                count > 100_000 -> "critical"
                count > 10_000 -> "high"
                count > 1_000 -> "medium"
                true -> "low"
              end
            }
            [finding | acc]

          _ ->
            acc
        end
      else
        acc
      end
    end)

    # Store audit results
    :ets.insert(@ets_password_hashes, {org_id, %{
      last_audit: DateTime.utc_now(),
      compromised_count: length(compromised),
      total_checked: length(entries)
    }})

    # Generate alerts for critical findings
    Enum.each(compromised, fn finding ->
      if finding.severity in ["critical", "high"] do
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "alerts:feed",
          {:compromised_credential, %{
            org_id: org_id,
            user_id: finding.user_id,
            service: finding.service,
            severity: finding.severity,
            breach_count: finding.breach_count
          }}
        )
      end
    end)

    new_stats = %{state.stats |
      passwords_checked: state.stats.passwords_checked + length(entries),
      compromised_found: state.stats.compromised_found + length(compromised),
      last_audit: DateTime.utc_now()
    }

    {:reply, {:ok, compromised}, %{state | stats: new_stats}}
  end

  # -- Password reuse detection --------------------------------------------

  @impl true
  def handle_call({:detect_reuse, org_id, entries}, _from, state) do
    # Group by password hash (SHA-256)
    by_hash = Enum.group_by(entries, fn e ->
      e[:password_sha256] || e["password_sha256"]
    end)

    reuse_findings =
      by_hash
      |> Enum.filter(fn {_hash, group} -> length(group) > 1 end)
      |> Enum.flat_map(fn {_hash, group} ->
        user_ids = group |> Enum.map(&(&1[:user_id] || &1["user_id"])) |> Enum.uniq()
        services = group |> Enum.map(&(&1[:service] || &1["service"])) |> Enum.uniq()

        Enum.map(user_ids, fn user_id ->
          user_services = group
            |> Enum.filter(&((&1[:user_id] || &1["user_id"]) == user_id))
            |> Enum.map(&(&1[:service] || &1["service"]))

          if length(user_services) > 1 do
            %{
              user_id: user_id,
              reused_across: user_services,
              service_count: length(user_services),
              severity: if(length(user_services) > 3, do: "high", else: "medium")
            }
          end
        end)
        |> Enum.reject(&is_nil/1)
      end)

    new_stats = %{state.stats | reuse_detected: state.stats.reuse_detected + length(reuse_findings)}
    {:reply, {:ok, reuse_findings}, %{state | stats: new_stats}}
  end

  # -- Certificate monitoring ----------------------------------------------

  @impl true
  def handle_call({:watch_cert, org_id, cert_info}, _from, state) do
    cert_id = cert_info[:id] || cert_info["id"] || Ecto.UUID.generate()

    entry = %{
      id: cert_id,
      org_id: org_id,
      subject: cert_info[:subject] || cert_info["subject"],
      issuer: cert_info[:issuer] || cert_info["issuer"],
      serial_number: cert_info[:serial_number] || cert_info["serial_number"],
      not_before: parse_datetime(cert_info[:not_before] || cert_info["not_before"]),
      not_after: parse_datetime(cert_info[:not_after] || cert_info["not_after"]),
      san_domains: cert_info[:san_domains] || cert_info["san_domains"] || [],
      usage: cert_info[:usage] || cert_info["usage"] || "tls",
      added_at: DateTime.utc_now()
    }

    :ets.insert(@ets_cert_watch, {{org_id, cert_id}, entry})
    new_stats = %{state.stats | certs_monitored: state.stats.certs_monitored + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:unwatch_cert, org_id, cert_id}, _from, state) do
    :ets.delete(@ets_cert_watch, {org_id, cert_id})
    {:reply, :ok, state}
  end

  # -- API key tracking ----------------------------------------------------

  @impl true
  def handle_call({:track_api_key, org_id, key_info}, _from, state) do
    key_id = key_info[:id] || key_info["id"] || Ecto.UUID.generate()

    entry = %{
      id: key_id,
      org_id: org_id,
      name: key_info[:name] || key_info["name"],
      service: key_info[:service] || key_info["service"],
      created_at: parse_datetime(key_info[:created_at] || key_info["created_at"]) || DateTime.utc_now(),
      last_rotated: parse_datetime(key_info[:last_rotated] || key_info["last_rotated"]) || DateTime.utc_now(),
      owner: key_info[:owner] || key_info["owner"],
      permissions: key_info[:permissions] || key_info["permissions"] || [],
      tracked_at: DateTime.utc_now()
    }

    :ets.insert(@ets_api_keys, {{org_id, key_id}, entry})
    new_stats = %{state.stats | api_keys_tracked: state.stats.api_keys_tracked + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:mark_key_rotated, org_id, key_id}, _from, state) do
    case :ets.lookup(@ets_api_keys, {org_id, key_id}) do
      [{{^org_id, ^key_id}, entry}] ->
        updated = %{entry | last_rotated: DateTime.utc_now()}
        :ets.insert(@ets_api_keys, {{org_id, key_id}, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Service account tracking --------------------------------------------

  @impl true
  def handle_call({:track_service_account, org_id, account_info}, _from, state) do
    account_id = account_info[:id] || account_info["id"] || Ecto.UUID.generate()

    entry = %{
      id: account_id,
      org_id: org_id,
      name: account_info[:name] || account_info["name"],
      type: account_info[:type] || account_info["type"] || "service",
      permissions: account_info[:permissions] || account_info["permissions"] || [],
      last_activity: DateTime.utc_now(),
      created_at: parse_datetime(account_info[:created_at] || account_info["created_at"]) || DateTime.utc_now(),
      owner: account_info[:owner] || account_info["owner"],
      tracked_at: DateTime.utc_now()
    }

    :ets.insert(@ets_service_accounts, {{org_id, account_id}, entry})
    new_stats = %{state.stats | service_accounts_tracked: state.stats.service_accounts_tracked + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:service_account_activity, org_id, account_id}, state) do
    case :ets.lookup(@ets_service_accounts, {org_id, account_id}) do
      [{{^org_id, ^account_id}, entry}] ->
        updated = %{entry | last_activity: DateTime.utc_now()}
        :ets.insert(@ets_service_accounts, {{org_id, account_id}, updated})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  # -- Reports and scores --------------------------------------------------

  @impl true
  def handle_call({:get_report, org_id}, _from, state) do
    report = build_hygiene_report(org_id)
    {:reply, report, state}
  end

  @impl true
  def handle_call({:get_score, org_id}, _from, state) do
    score = calculate_hygiene_score(org_id)
    {:reply, score, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- Periodic checks -----------------------------------------------------

  @impl true
  def handle_info(:check_certs, state) do
    check_certificate_expirations(state)
    schedule_cert_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_api_keys, state) do
    new_stats = check_api_key_ages(state)
    schedule_api_key_check()
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:check_service_accounts, state) do
    new_stats = check_service_account_hygiene(state)
    schedule_service_account_check()
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:password_audit, state) do
    # Recalculate hygiene scores for all orgs
    recalculate_all_scores()
    schedule_password_audit()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private - Certificate Checks
  # ============================================================================

  defp check_certificate_expirations(state) do
    now = DateTime.utc_now()

    :ets.tab2list(@ets_cert_watch)
    |> Enum.each(fn {{org_id, _cert_id}, cert} ->
      case cert.not_after do
        %DateTime{} = expiry ->
          days_until = DateTime.diff(expiry, now, :day)

          cond do
            days_until < 0 ->
              generate_cert_alert(org_id, cert, "expired", "critical")

            days_until <= @cert_expiry_critical_days ->
              generate_cert_alert(org_id, cert, "expiring_critical", "critical")

            days_until <= @cert_expiry_warning_days ->
              generate_cert_alert(org_id, cert, "expiring_soon", "high")

            true ->
              :ok
          end

        _ ->
          :ok
      end
    end)
  end

  defp generate_cert_alert(org_id, cert, alert_type, severity) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:certificate_hygiene, %{
        org_id: org_id,
        cert_subject: cert.subject,
        cert_issuer: cert.issuer,
        expiry: cert.not_after,
        alert_type: alert_type,
        severity: severity,
        san_domains: cert.san_domains
      }}
    )
  end

  # ============================================================================
  # Private - API Key Checks
  # ============================================================================

  defp check_api_key_ages(state) do
    now = DateTime.utc_now()
    stale_count = 0

    stale_count =
      :ets.tab2list(@ets_api_keys)
      |> Enum.reduce(stale_count, fn {{org_id, _key_id}, key}, acc ->
        days_since_rotation = DateTime.diff(now, key.last_rotated, :day)

        cond do
          days_since_rotation >= @api_key_rotation_critical_days ->
            generate_api_key_alert(org_id, key, "rotation_overdue", "critical")
            acc + 1

          days_since_rotation >= @api_key_rotation_warning_days ->
            generate_api_key_alert(org_id, key, "rotation_recommended", "medium")
            acc + 1

          true ->
            acc
        end
      end)

    %{state.stats | api_keys_stale: stale_count}
  end

  defp generate_api_key_alert(org_id, key, alert_type, severity) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:api_key_hygiene, %{
        org_id: org_id,
        key_name: key.name,
        key_service: key.service,
        owner: key.owner,
        last_rotated: key.last_rotated,
        alert_type: alert_type,
        severity: severity
      }}
    )
  end

  # ============================================================================
  # Private - Service Account Checks
  # ============================================================================

  defp check_service_account_hygiene(state) do
    now = DateTime.utc_now()
    unused_count = 0

    unused_count =
      :ets.tab2list(@ets_service_accounts)
      |> Enum.reduce(unused_count, fn {{org_id, _account_id}, account}, acc ->
        days_inactive = DateTime.diff(now, account.last_activity, :day)

        cond do
          days_inactive >= @service_account_unused_days ->
            generate_service_account_alert(org_id, account, "unused", "medium")
            acc + 1

          length(account.permissions) > 10 ->
            generate_service_account_alert(org_id, account, "over_privileged", "high")
            acc

          true ->
            acc
        end
      end)

    %{state.stats | service_accounts_unused: unused_count}
  end

  defp generate_service_account_alert(org_id, account, alert_type, severity) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:service_account_hygiene, %{
        org_id: org_id,
        account_name: account.name,
        account_type: account.type,
        owner: account.owner,
        last_activity: account.last_activity,
        permissions_count: length(account.permissions),
        alert_type: alert_type,
        severity: severity
      }}
    )
  end

  # ============================================================================
  # Private - Hygiene Report & Score
  # ============================================================================

  defp build_hygiene_report(org_id) do
    now = DateTime.utc_now()

    # Certificate status
    certs = :ets.tab2list(@ets_cert_watch)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, cert} ->
        days_until = case cert.not_after do
          %DateTime{} = expiry -> DateTime.diff(expiry, now, :day)
          _ -> nil
        end

        status = cond do
          is_nil(days_until) -> "unknown"
          days_until < 0 -> "expired"
          days_until <= @cert_expiry_critical_days -> "critical"
          days_until <= @cert_expiry_warning_days -> "warning"
          true -> "ok"
        end

        Map.merge(cert, %{days_until_expiry: days_until, status: status})
      end)

    # API key status
    api_keys = :ets.tab2list(@ets_api_keys)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, key} ->
        age_days = DateTime.diff(now, key.last_rotated, :day)

        status = cond do
          age_days >= @api_key_rotation_critical_days -> "critical"
          age_days >= @api_key_rotation_warning_days -> "warning"
          true -> "ok"
        end

        Map.merge(key, %{age_days: age_days, status: status})
      end)

    # Service account status
    service_accounts = :ets.tab2list(@ets_service_accounts)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, account} ->
        inactive_days = DateTime.diff(now, account.last_activity, :day)
        is_over_privileged = length(account.permissions) > 10

        status = cond do
          inactive_days >= @service_account_unused_days -> "unused"
          is_over_privileged -> "over_privileged"
          true -> "ok"
        end

        Map.merge(account, %{inactive_days: inactive_days, is_over_privileged: is_over_privileged, status: status})
      end)

    # Password audit results
    password_status = case :ets.lookup(@ets_password_hashes, org_id) do
      [{^org_id, data}] -> data
      [] -> %{last_audit: nil, compromised_count: 0, total_checked: 0}
    end

    %{
      org_id: org_id,
      overall_score: calculate_hygiene_score(org_id),
      certificates: %{
        total: length(certs),
        expired: Enum.count(certs, &(&1.status == "expired")),
        critical: Enum.count(certs, &(&1.status == "critical")),
        warning: Enum.count(certs, &(&1.status == "warning")),
        ok: Enum.count(certs, &(&1.status == "ok")),
        details: certs
      },
      api_keys: %{
        total: length(api_keys),
        critical: Enum.count(api_keys, &(&1.status == "critical")),
        warning: Enum.count(api_keys, &(&1.status == "warning")),
        ok: Enum.count(api_keys, &(&1.status == "ok")),
        details: api_keys
      },
      service_accounts: %{
        total: length(service_accounts),
        unused: Enum.count(service_accounts, &(&1.status == "unused")),
        over_privileged: Enum.count(service_accounts, &(&1.status == "over_privileged")),
        ok: Enum.count(service_accounts, &(&1.status == "ok")),
        details: service_accounts
      },
      passwords: password_status,
      generated_at: now
    }
  end

  defp calculate_hygiene_score(org_id) do
    report = build_hygiene_report_lightweight(org_id)

    # Score components (each out of 25, total = 100)
    cert_score = calculate_cert_score(report)
    api_key_score = calculate_api_key_score(report)
    service_account_score = calculate_service_account_score(report)
    password_score = calculate_password_score(report)

    total = cert_score + api_key_score + service_account_score + password_score
    max(0, min(100, round(total)))
  end

  defp build_hygiene_report_lightweight(org_id) do
    now = DateTime.utc_now()

    certs = :ets.tab2list(@ets_cert_watch)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, cert} ->
        days_until = case cert.not_after do
          %DateTime{} = expiry -> DateTime.diff(expiry, now, :day)
          _ -> 999
        end
        %{days_until_expiry: days_until}
      end)

    api_keys = :ets.tab2list(@ets_api_keys)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, key} ->
        %{age_days: DateTime.diff(now, key.last_rotated, :day)}
      end)

    service_accounts = :ets.tab2list(@ets_service_accounts)
      |> Enum.filter(fn {{oid, _}, _} -> oid == org_id end)
      |> Enum.map(fn {_, account} ->
        %{
          inactive_days: DateTime.diff(now, account.last_activity, :day),
          permissions_count: length(account.permissions)
        }
      end)

    password_status = case :ets.lookup(@ets_password_hashes, org_id) do
      [{^org_id, data}] -> data
      [] -> %{compromised_count: 0, total_checked: 0}
    end

    %{certs: certs, api_keys: api_keys, service_accounts: service_accounts, passwords: password_status}
  end

  defp calculate_cert_score(%{certs: []}), do: 25
  defp calculate_cert_score(%{certs: certs}) do
    total = length(certs)
    expired = Enum.count(certs, &(&1.days_until_expiry < 0))
    critical = Enum.count(certs, &(&1.days_until_expiry >= 0 and &1.days_until_expiry <= @cert_expiry_critical_days))

    ok_ratio = (total - expired - critical) / total
    round(ok_ratio * 25)
  end

  defp calculate_api_key_score(%{api_keys: []}), do: 25
  defp calculate_api_key_score(%{api_keys: keys}) do
    total = length(keys)
    stale = Enum.count(keys, &(&1.age_days >= @api_key_rotation_warning_days))

    ok_ratio = (total - stale) / total
    round(ok_ratio * 25)
  end

  defp calculate_service_account_score(%{service_accounts: []}), do: 25
  defp calculate_service_account_score(%{service_accounts: accounts}) do
    total = length(accounts)
    unused = Enum.count(accounts, &(&1.inactive_days >= @service_account_unused_days))
    over_priv = Enum.count(accounts, &(&1.permissions_count > 10))

    issues = min(unused + over_priv, total)
    ok_ratio = (total - issues) / total
    round(ok_ratio * 25)
  end

  defp calculate_password_score(%{passwords: %{total_checked: 0}}), do: 25
  defp calculate_password_score(%{passwords: %{compromised_count: comp, total_checked: total}}) do
    ok_ratio = (total - comp) / max(total, 1)
    round(ok_ratio * 25)
  end
  defp calculate_password_score(_), do: 25

  defp recalculate_all_scores do
    org_ids =
      (:ets.tab2list(@ets_cert_watch) |> Enum.map(fn {{oid, _}, _} -> oid end)) ++
      (:ets.tab2list(@ets_api_keys) |> Enum.map(fn {{oid, _}, _} -> oid end)) ++
      (:ets.tab2list(@ets_service_accounts) |> Enum.map(fn {{oid, _}, _} -> oid end))

    org_ids
    |> Enum.uniq()
    |> Enum.each(fn org_id ->
      score = calculate_hygiene_score(org_id)
      :ets.insert(@ets_hygiene_scores, {org_id, %{score: score, updated_at: DateTime.utc_now()}})
    end)
  end

  # ============================================================================
  # Private - Scheduling
  # ============================================================================

  defp schedule_cert_check do
    Process.send_after(self(), :check_certs, @cert_check_interval)
  end

  defp schedule_api_key_check do
    Process.send_after(self(), :check_api_keys, @api_key_check_interval)
  end

  defp schedule_service_account_check do
    Process.send_after(self(), :check_service_accounts, @service_account_check_interval)
  end

  defp schedule_password_audit do
    Process.send_after(self(), :password_audit, @password_audit_interval)
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil
end
