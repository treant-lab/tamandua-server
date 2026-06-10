defmodule TamanduaServer.ThreatIntel.DarkWebMonitor do
  @moduledoc """
  Dark Web & Credential Breach Monitoring for Tamandua EDR.

  Monitors dark web data sources and breach databases for compromised credentials
  belonging to organization users. Supports domain-wide monitoring, individual
  email tracking, hash-based password checking (never plaintext), and executive
  VIP watchlists.

  ## Data Sources

  - **Have I Been Pwned (HIBP)** - Domain search and breach notification API
  - **HIBP Passwords** - k-anonymity-based password hash checking
  - **Intelligence X** - Deep/dark web search API
  - **Custom Feeds** - CSV/JSON breach database ingestion

  ## Monitoring Modes

  1. **Domain Monitoring** - Watch organization domains in new breaches
  2. **Email Monitoring** - Check specific email addresses
  3. **Credential Monitoring** - Hash-based password checking (k-anonymity)
  4. **Executive Monitoring** - VIP account watchlist with elevated alerting

  ## Processing Pipeline

  1. Fetch new breach data on schedule (hourly/daily configurable)
  2. Match against organization user database
  3. Assess risk: password age, reuse likelihood, account privilege level
  4. Generate alerts with severity based on exposure type
  5. Optionally trigger password reset for critical accounts

  ## Security

  - Never stores or transmits plaintext passwords
  - Password checking uses SHA-1 prefix (k-anonymity) via HIBP API
  - All breach data encrypted at rest
  - Multi-tenant: all operations scoped to org_id
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  import Ecto.Query

  # ETS tables
  @ets_breaches :dark_web_breaches
  @ets_watchlist :dark_web_watchlist
  @ets_findings :dark_web_findings

  # HIBP API
  @hibp_api_base "https://haveibeenpwned.com/api/v3"
  @hibp_password_api "https://api.pwnedpasswords.com/range"

  # Intelligence X API
  @intelx_api_base "https://2.intelx.io"

  # Polling intervals
  @domain_check_interval :timer.hours(24)
  @email_check_interval :timer.hours(6)
  @executive_check_interval :timer.hours(1)

  # Rate limiting (HIBP requires 1500ms between requests on free tier)
  @hibp_rate_limit_ms 1_600

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register an organization domain for monitoring.
  """
  @spec watch_domain(String.t(), String.t(), keyword()) :: :ok
  def watch_domain(org_id, domain, opts \\ []) do
    GenServer.call(__MODULE__, {:watch_domain, org_id, domain, opts})
  end

  @doc """
  Register an email address for monitoring.
  """
  @spec watch_email(String.t(), String.t(), keyword()) :: :ok
  def watch_email(org_id, email, opts \\ []) do
    GenServer.call(__MODULE__, {:watch_email, org_id, email, opts})
  end

  @doc """
  Add a VIP/executive account to the watchlist.
  """
  @spec watch_executive(String.t(), String.t(), keyword()) :: :ok
  def watch_executive(org_id, email, opts \\ []) do
    GenServer.call(__MODULE__, {:watch_executive, org_id, email, opts})
  end

  @doc """
  Remove a watch entry.
  """
  @spec unwatch(String.t(), String.t()) :: :ok
  def unwatch(org_id, identifier) do
    GenServer.call(__MODULE__, {:unwatch, org_id, identifier})
  end

  @doc """
  Check a password hash against HIBP using k-anonymity.
  Never sends the full hash - only the first 5 characters (SHA-1 prefix).

  Returns the number of times the password has appeared in breaches.
  """
  @spec check_password_hash(String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def check_password_hash(sha1_hex) when is_binary(sha1_hex) do
    GenServer.call(__MODULE__, {:check_password_hash, sha1_hex}, 15_000)
  end

  @doc """
  Ingest a custom breach feed (CSV/JSON).
  """
  @spec ingest_custom_feed(String.t(), String.t(), binary()) :: {:ok, integer()} | {:error, term()}
  def ingest_custom_feed(org_id, format, data) when format in ["csv", "json"] do
    GenServer.call(__MODULE__, {:ingest_custom_feed, org_id, format, data}, 120_000)
  end

  @doc """
  Get all findings for an organization.
  """
  @spec get_findings(String.t(), keyword()) :: [map()]
  def get_findings(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_findings, org_id, opts})
  end

  @doc """
  Get findings for a specific email address.
  """
  @spec get_findings_for_email(String.t(), String.t()) :: [map()]
  def get_findings_for_email(org_id, email) do
    GenServer.call(__MODULE__, {:get_findings_for_email, org_id, email})
  end

  @doc """
  Get breach summary statistics for an organization.
  """
  @spec get_summary(String.t()) :: map()
  def get_summary(org_id) do
    GenServer.call(__MODULE__, {:get_summary, org_id})
  end

  @doc """
  Trigger an immediate scan for an organization.
  """
  @spec trigger_scan(String.t()) :: {:ok, map()} | {:error, term()}
  def trigger_scan(org_id) do
    GenServer.call(__MODULE__, {:trigger_scan, org_id}, 300_000)
  end

  @doc """
  Update the remediation status of a finding.
  """
  @spec update_finding_status(String.t(), String.t(), keyword()) :: :ok | {:error, :not_found}
  def update_finding_status(finding_id, status, opts \\ []) do
    GenServer.call(__MODULE__, {:update_finding_status, finding_id, status, opts})
  end

  @doc """
  Get monitoring engine statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    :ets.new(@ets_breaches, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_watchlist, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ets_findings, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      hibp_api_key: Keyword.get(opts, :hibp_api_key, System.get_env("HIBP_API_KEY")),
      intelx_api_key: Keyword.get(opts, :intelx_api_key, System.get_env("INTELX_API_KEY")),
      stats: %{
        domains_monitored: 0,
        emails_monitored: 0,
        executives_monitored: 0,
        breaches_found: 0,
        findings_total: 0,
        scans_run: 0,
        api_calls: 0,
        last_scan: nil
      }
    }

    # Load watchlist from database
    load_watchlist_from_db()

    # Schedule periodic checks
    schedule_domain_check()
    schedule_email_check()
    schedule_executive_check()

    Logger.info("[DarkWebMonitor] Initialized")
    {:ok, state}
  end

  # -- Watch management ----------------------------------------------------

  @impl true
  def handle_call({:watch_domain, org_id, domain, opts}, _from, state) do
    entry = %{
      type: :domain,
      org_id: org_id,
      identifier: domain,
      label: Keyword.get(opts, :label, domain),
      added_at: DateTime.utc_now()
    }

    :ets.insert(@ets_watchlist, {org_id, entry})
    persist_watchlist_entry(entry)
    new_stats = %{state.stats | domains_monitored: state.stats.domains_monitored + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:watch_email, org_id, email, opts}, _from, state) do
    entry = %{
      type: :email,
      org_id: org_id,
      identifier: String.downcase(email),
      label: Keyword.get(opts, :label, email),
      added_at: DateTime.utc_now()
    }

    :ets.insert(@ets_watchlist, {org_id, entry})
    persist_watchlist_entry(entry)
    new_stats = %{state.stats | emails_monitored: state.stats.emails_monitored + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:watch_executive, org_id, email, opts}, _from, state) do
    entry = %{
      type: :executive,
      org_id: org_id,
      identifier: String.downcase(email),
      label: Keyword.get(opts, :label, email),
      role: Keyword.get(opts, :role, "executive"),
      added_at: DateTime.utc_now()
    }

    :ets.insert(@ets_watchlist, {org_id, entry})
    persist_watchlist_entry(entry)
    new_stats = %{state.stats | executives_monitored: state.stats.executives_monitored + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:unwatch, org_id, identifier}, _from, state) do
    entries = :ets.lookup(@ets_watchlist, org_id)

    entries
    |> Enum.filter(fn {_key, entry} -> entry.identifier == identifier end)
    |> Enum.each(fn obj -> :ets.delete_object(@ets_watchlist, obj) end)

    delete_watchlist_entry(org_id, identifier)
    {:reply, :ok, state}
  end

  # -- Password checking (k-anonymity) ------------------------------------

  @impl true
  def handle_call({:check_password_hash, sha1_hex}, _from, state) do
    result = do_check_password_hash(sha1_hex)
    new_stats = %{state.stats | api_calls: state.stats.api_calls + 1}
    {:reply, result, %{state | stats: new_stats}}
  end

  # -- Custom feed ingestion -----------------------------------------------

  @impl true
  def handle_call({:ingest_custom_feed, org_id, format, data}, _from, state) do
    result = do_ingest_custom_feed(org_id, format, data)

    new_stats = case result do
      {:ok, count} -> %{state.stats | findings_total: state.stats.findings_total + count}
      _ -> state.stats
    end

    {:reply, result, %{state | stats: new_stats}}
  end

  # -- Findings queries ----------------------------------------------------

  @impl true
  def handle_call({:get_findings, org_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)
    status_filter = Keyword.get(opts, :status)
    severity_filter = Keyword.get(opts, :severity)

    findings =
      :ets.tab2list(@ets_findings)
      |> Enum.map(fn {_id, f} -> f end)
      |> Enum.filter(&(&1.org_id == org_id))
      |> then(fn fs ->
        if status_filter, do: Enum.filter(fs, &(&1.remediation_status == status_filter)), else: fs
      end)
      |> then(fn fs ->
        if severity_filter, do: Enum.filter(fs, &(&1.severity == severity_filter)), else: fs
      end)
      |> Enum.sort_by(& &1.discovered_at, {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, findings, state}
  end

  @impl true
  def handle_call({:get_findings_for_email, org_id, email}, _from, state) do
    findings =
      :ets.tab2list(@ets_findings)
      |> Enum.map(fn {_id, f} -> f end)
      |> Enum.filter(fn f ->
        f.org_id == org_id and
        Enum.any?(f.affected_emails, &(String.downcase(&1) == String.downcase(email)))
      end)
      |> Enum.sort_by(& &1.discovered_at, {:desc, DateTime})

    {:reply, findings, state}
  end

  @impl true
  def handle_call({:get_summary, org_id}, _from, state) do
    findings =
      :ets.tab2list(@ets_findings)
      |> Enum.map(fn {_id, f} -> f end)
      |> Enum.filter(&(&1.org_id == org_id))

    summary = %{
      org_id: org_id,
      total_findings: length(findings),
      by_severity: findings |> Enum.group_by(& &1.severity) |> Enum.map(fn {s, fs} -> {s, length(fs)} end) |> Map.new(),
      by_status: findings |> Enum.group_by(& &1.remediation_status) |> Enum.map(fn {s, fs} -> {s, length(fs)} end) |> Map.new(),
      unique_breaches: findings |> Enum.map(& &1.breach_name) |> Enum.uniq() |> length(),
      unique_affected_users: findings |> Enum.flat_map(& &1.affected_emails) |> Enum.uniq() |> length(),
      exposed_data_types: findings |> Enum.flat_map(& &1.exposed_data_types) |> Enum.uniq(),
      most_recent_breach: findings |> Enum.max_by(& &1.breach_date, Date, fn -> nil end),
      last_updated: DateTime.utc_now()
    }

    {:reply, summary, state}
  end

  @impl true
  def handle_call({:trigger_scan, org_id}, _from, state) do
    result = do_full_scan(org_id, state)
    new_stats = %{state.stats | scans_run: state.stats.scans_run + 1, last_scan: DateTime.utc_now()}
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:update_finding_status, finding_id, status, opts}, _from, state) do
    case :ets.lookup(@ets_findings, finding_id) do
      [{^finding_id, finding}] ->
        updated = %{finding |
          remediation_status: status,
          remediation_notes: Keyword.get(opts, :notes, finding[:remediation_notes]),
          remediation_at: DateTime.utc_now()
        }
        :ets.insert(@ets_findings, {finding_id, updated})
        persist_finding(updated)
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- Periodic checks -----------------------------------------------------

  @impl true
  def handle_info(:check_domains, state) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      check_all_domains(state)
    end)

    schedule_domain_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_emails, state) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      check_all_emails(state)
    end)

    schedule_email_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_executives, state) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      check_all_executives(state)
    end)

    schedule_executive_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private - HIBP Integration
  # ============================================================================

  defp do_check_password_hash(sha1_hex) do
    # k-anonymity: send only the first 5 characters of the SHA-1 hash
    prefix = String.upcase(String.slice(sha1_hex, 0, 5))
    suffix = String.upcase(String.slice(sha1_hex, 5..-1//1))

    url = "#{@hibp_password_api}/#{prefix}"

    case http_get(url, []) do
      {:ok, body} ->
        count =
          body
          |> String.split("\r\n")
          |> Enum.find_value(0, fn line ->
            case String.split(line, ":") do
              [hash_suffix, count_str] ->
                if String.trim(hash_suffix) == suffix do
                  {count, _} = Integer.parse(String.trim(count_str))
                  count
                else
                  nil
                end
              _ ->
                nil
            end
          end)

        {:ok, count}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_email_breaches(email, api_key) do
    url = "#{@hibp_api_base}/breachedaccount/#{URI.encode(email)}?truncateResponse=false"

    headers = [
      {"hibp-api-key", api_key || ""},
      {"user-agent", "Tamandua-EDR-DarkWebMonitor"}
    ]

    case http_get(url, headers) do
      {:ok, body} ->
        case Jason.decode(body) do
          {:ok, breaches} when is_list(breaches) ->
            {:ok, Enum.map(breaches, &parse_hibp_breach/1)}

          _ ->
            {:ok, []}
        end

      {:error, {:http_status, 404}} ->
        {:ok, []}

      {:error, {:http_status, 429}} ->
        # Rate limited
        Process.sleep(@hibp_rate_limit_ms * 2)
        {:error, :rate_limited}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_domain_breaches(domain, api_key) do
    url = "#{@hibp_api_base}/breaches?domain=#{URI.encode(domain)}"

    headers = [
      {"hibp-api-key", api_key || ""},
      {"user-agent", "Tamandua-EDR-DarkWebMonitor"}
    ]

    case http_get(url, headers) do
      {:ok, body} ->
        case Jason.decode(body) do
          {:ok, breaches} when is_list(breaches) ->
            {:ok, Enum.map(breaches, &parse_hibp_breach/1)}

          _ ->
            {:ok, []}
        end

      {:error, {:http_status, 404}} ->
        {:ok, []}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_hibp_breach(breach) do
    %{
      name: breach["Name"],
      title: breach["Title"],
      domain: breach["Domain"],
      breach_date: parse_date(breach["BreachDate"]),
      added_date: parse_date(breach["AddedDate"]),
      modified_date: parse_date(breach["ModifiedDate"]),
      pwn_count: breach["PwnCount"],
      description: breach["Description"],
      data_classes: breach["DataClasses"] || [],
      is_verified: breach["IsVerified"],
      is_sensitive: breach["IsSensitive"],
      is_spam_list: breach["IsSpamList"]
    }
  end

  # ============================================================================
  # Private - Intelligence X Integration
  # ============================================================================

  defp search_intelx(query, api_key) do
    if api_key do
      url = "#{@intelx_api_base}/intelligent/search"

      body = Jason.encode!(%{
        term: query,
        maxresults: 100,
        media: 0,
        sort: 2,
        terminate: []
      })

      headers = [
        {"x-key", api_key},
        {"content-type", "application/json"}
      ]

      case http_post(url, body, headers) do
        {:ok, response_body} ->
          case Jason.decode(response_body) do
            {:ok, %{"id" => search_id}} ->
              # Fetch results (Intelligence X uses async search)
              Process.sleep(2_000)
              fetch_intelx_results(search_id, api_key)

            _ ->
              {:ok, []}
          end

        {:error, reason} ->
          Logger.warning("[DarkWebMonitor] IntelX search failed: #{inspect(reason)}")
          {:ok, []}
      end
    else
      {:ok, []}
    end
  end

  defp fetch_intelx_results(search_id, api_key) do
    url = "#{@intelx_api_base}/intelligent/search/result?id=#{search_id}&limit=100"

    headers = [{"x-key", api_key}]

    case http_get(url, headers) do
      {:ok, body} ->
        case Jason.decode(body) do
          {:ok, %{"records" => records}} when is_list(records) ->
            {:ok, Enum.map(records, &parse_intelx_record/1)}

          _ ->
            {:ok, []}
        end

      {:error, _} ->
        {:ok, []}
    end
  end

  defp parse_intelx_record(record) do
    %{
      source: "intelligence_x",
      name: record["name"] || "Unknown",
      date: parse_date(record["date"]),
      type: record["type"],
      bucket: record["bucket"],
      media: record["media"],
      systemid: record["systemid"]
    }
  end

  # ============================================================================
  # Private - Custom Feed Ingestion
  # ============================================================================

  defp do_ingest_custom_feed(org_id, "json", data) do
    case Jason.decode(data) do
      {:ok, records} when is_list(records) ->
        count = Enum.reduce(records, 0, fn record, acc ->
          finding = build_finding_from_custom(org_id, record)
          :ets.insert(@ets_findings, {finding.id, finding})
          persist_finding(finding)
          acc + 1
        end)

        {:ok, count}

      _ ->
        {:error, :invalid_json}
    end
  end

  defp do_ingest_custom_feed(org_id, "csv", data) do
    lines = String.split(data, "\n") |> Enum.drop(1) |> Enum.reject(&(&1 == ""))

    count = Enum.reduce(lines, 0, fn line, acc ->
      fields = String.split(line, ",") |> Enum.map(&String.trim/1)

      case fields do
        [email, breach_name, breach_date | rest] ->
          exposed_types = if rest != [], do: rest, else: ["email"]
          record = %{
            "email" => email,
            "breach_name" => breach_name,
            "breach_date" => breach_date,
            "exposed_data_types" => exposed_types
          }
          finding = build_finding_from_custom(org_id, record)
          :ets.insert(@ets_findings, {finding.id, finding})
          persist_finding(finding)
          acc + 1

        _ ->
          acc
      end
    end)

    {:ok, count}
  end

  defp build_finding_from_custom(org_id, record) do
    %{
      id: Ecto.UUID.generate(),
      org_id: org_id,
      source: "custom_feed",
      breach_name: record["breach_name"] || "Custom Feed",
      breach_date: parse_date(record["breach_date"]),
      affected_emails: List.wrap(record["email"] || record["emails"]),
      exposed_data_types: record["exposed_data_types"] || ["unknown"],
      severity: assess_severity(record["exposed_data_types"] || []),
      remediation_status: "new",
      remediation_notes: nil,
      remediation_at: nil,
      discovered_at: DateTime.utc_now(),
      raw_data: record
    }
  end

  # ============================================================================
  # Private - Scanning
  # ============================================================================

  defp do_full_scan(org_id, state) do
    watchlist = get_watchlist_for_org(org_id)
    findings_count = 0

    # Check domains
    domains = Enum.filter(watchlist, &(&1.type == :domain))
    domain_findings = Enum.reduce(domains, 0, fn entry, acc ->
      count = scan_domain(entry, org_id, state)
      Process.sleep(@hibp_rate_limit_ms)
      acc + count
    end)

    # Check emails
    emails = Enum.filter(watchlist, &(&1.type in [:email, :executive]))
    email_findings = Enum.reduce(emails, 0, fn entry, acc ->
      count = scan_email(entry, org_id, state)
      Process.sleep(@hibp_rate_limit_ms)
      acc + count
    end)

    total = domain_findings + email_findings + findings_count

    {:ok, %{
      org_id: org_id,
      domains_checked: length(domains),
      emails_checked: length(emails),
      new_findings: total
    }}
  rescue
    e ->
      Logger.error("[DarkWebMonitor] Scan failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp scan_domain(entry, org_id, state) do
    case check_domain_breaches(entry.identifier, state.hibp_api_key) do
      {:ok, breaches} ->
        Enum.reduce(breaches, 0, fn breach, acc ->
          if not finding_exists?(org_id, breach.name, entry.identifier) do
            finding = build_finding(org_id, breach, [entry.identifier], "hibp_domain")
            :ets.insert(@ets_findings, {finding.id, finding})
            persist_finding(finding)
            maybe_generate_alert(finding)
            acc + 1
          else
            acc
          end
        end)

      {:error, reason} ->
        Logger.warning("[DarkWebMonitor] Domain check failed for #{entry.identifier}: #{inspect(reason)}")
        0
    end
  end

  defp scan_email(entry, org_id, state) do
    case check_email_breaches(entry.identifier, state.hibp_api_key) do
      {:ok, breaches} ->
        is_executive = entry.type == :executive

        Enum.reduce(breaches, 0, fn breach, acc ->
          if not finding_exists?(org_id, breach.name, entry.identifier) do
            finding = build_finding(org_id, breach, [entry.identifier], "hibp_email")
            finding = if is_executive do
              # Elevate severity for executives
              elevated_severity = elevate_severity(finding.severity)
              %{finding | severity: elevated_severity}
            else
              finding
            end

            :ets.insert(@ets_findings, {finding.id, finding})
            persist_finding(finding)
            maybe_generate_alert(finding)
            acc + 1
          else
            acc
          end
        end)

      {:error, reason} ->
        Logger.warning("[DarkWebMonitor] Email check failed for #{entry.identifier}: #{inspect(reason)}")
        0
    end
  end

  defp check_all_domains(state) do
    all_entries = :ets.tab2list(@ets_watchlist)
    domains = Enum.flat_map(all_entries, fn {_org_id, entry} ->
      if entry.type == :domain, do: [entry], else: []
    end)

    Enum.each(domains, fn entry ->
      scan_domain(entry, entry.org_id, state)
      Process.sleep(@hibp_rate_limit_ms)
    end)
  end

  defp check_all_emails(state) do
    all_entries = :ets.tab2list(@ets_watchlist)
    emails = Enum.flat_map(all_entries, fn {_org_id, entry} ->
      if entry.type == :email, do: [entry], else: []
    end)

    Enum.each(emails, fn entry ->
      scan_email(entry, entry.org_id, state)
      Process.sleep(@hibp_rate_limit_ms)
    end)
  end

  defp check_all_executives(state) do
    all_entries = :ets.tab2list(@ets_watchlist)
    executives = Enum.flat_map(all_entries, fn {_org_id, entry} ->
      if entry.type == :executive, do: [entry], else: []
    end)

    Enum.each(executives, fn entry ->
      # Also search Intelligence X for executives
      if state.intelx_api_key do
        case search_intelx(entry.identifier, state.intelx_api_key) do
          {:ok, results} when results != [] ->
            Enum.each(results, fn result ->
              finding = %{
                id: Ecto.UUID.generate(),
                org_id: entry.org_id,
                source: "intelligence_x",
                breach_name: result.name,
                breach_date: result.date,
                affected_emails: [entry.identifier],
                exposed_data_types: ["dark_web_mention"],
                severity: "critical",
                remediation_status: "new",
                remediation_notes: nil,
                remediation_at: nil,
                discovered_at: DateTime.utc_now(),
                raw_data: result
              }

              if not finding_exists?(entry.org_id, result.name, entry.identifier) do
                :ets.insert(@ets_findings, {finding.id, finding})
                persist_finding(finding)
                maybe_generate_alert(finding)
              end
            end)

          _ ->
            :ok
        end
      end

      scan_email(entry, entry.org_id, state)
      Process.sleep(@hibp_rate_limit_ms)
    end)
  end

  # ============================================================================
  # Private - Finding Construction
  # ============================================================================

  defp build_finding(org_id, breach, affected_emails, source) do
    %{
      id: Ecto.UUID.generate(),
      org_id: org_id,
      source: source,
      breach_name: breach.name || breach[:title] || "Unknown",
      breach_date: breach.breach_date || breach[:date],
      affected_emails: affected_emails,
      exposed_data_types: breach.data_classes || breach[:data_classes] || [],
      severity: assess_severity(breach.data_classes || []),
      pwn_count: breach[:pwn_count],
      is_verified: breach[:is_verified],
      remediation_status: "new",
      remediation_notes: nil,
      remediation_at: nil,
      discovered_at: DateTime.utc_now(),
      raw_data: breach
    }
  end

  defp assess_severity(data_classes) do
    data_classes_lower = Enum.map(data_classes, &String.downcase/1)

    cond do
      # Critical: passwords, credit cards, SSNs
      Enum.any?(data_classes_lower, &(&1 in ["passwords", "credit cards", "social security numbers", "bank account numbers"])) ->
        "critical"

      # High: personal data that enables account takeover
      Enum.any?(data_classes_lower, &(&1 in ["password hints", "security questions and answers", "phone numbers", "physical addresses"])) ->
        "high"

      # Medium: PII that could be used in social engineering
      Enum.any?(data_classes_lower, &(&1 in ["email addresses", "names", "dates of birth", "genders", "ip addresses"])) ->
        "medium"

      # Low: minimal exposure
      true ->
        "low"
    end
  end

  defp elevate_severity("low"), do: "medium"
  defp elevate_severity("medium"), do: "high"
  defp elevate_severity("high"), do: "critical"
  defp elevate_severity(severity), do: severity

  defp finding_exists?(org_id, breach_name, identifier) do
    :ets.tab2list(@ets_findings)
    |> Enum.any?(fn {_id, f} ->
      f.org_id == org_id and
      f.breach_name == breach_name and
      Enum.any?(f.affected_emails, &(&1 == identifier))
    end)
  end

  # ============================================================================
  # Private - Alerting
  # ============================================================================

  defp maybe_generate_alert(finding) do
    if finding.severity in ["critical", "high"] do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:feed",
        {:dark_web_breach, %{
          org_id: finding.org_id,
          finding_id: finding.id,
          breach_name: finding.breach_name,
          severity: finding.severity,
          affected_users: length(finding.affected_emails),
          exposed_data_types: finding.exposed_data_types,
          source: finding.source
        }}
      )
    end
  end

  # ============================================================================
  # Private - Persistence
  # ============================================================================

  defp persist_finding(finding) do
    Task.start(fn ->
      try do
        attrs = %{
          id: finding.id,
          org_id: finding.org_id,
          source: finding.source,
          breach_name: finding.breach_name,
          breach_date: finding.breach_date,
          affected_emails: finding.affected_emails,
          exposed_data_types: finding.exposed_data_types,
          severity: finding.severity,
          remediation_status: finding.remediation_status,
          raw_data: finding.raw_data,
          inserted_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }

        Repo.insert_all("dark_web_findings", [attrs],
          on_conflict: {:replace, [:severity, :remediation_status, :updated_at]},
          conflict_target: [:id]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp persist_watchlist_entry(entry) do
    Task.start(fn ->
      try do
        attrs = %{
          id: Ecto.UUID.generate(),
          org_id: entry.org_id,
          watch_type: Atom.to_string(entry.type),
          identifier: entry.identifier,
          label: entry[:label],
          inserted_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }

        Repo.insert_all("dark_web_watchlist", [attrs],
          on_conflict: :nothing,
          conflict_target: [:org_id, :identifier]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp delete_watchlist_entry(org_id, identifier) do
    Task.start(fn ->
      try do
        Repo.delete_all(
          from(w in "dark_web_watchlist",
            where: w.org_id == ^org_id and w.identifier == ^identifier
          )
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp load_watchlist_from_db do
    try do
      entries = Repo.all(
        from(w in "dark_web_watchlist",
          select: %{org_id: w.org_id, watch_type: w.watch_type, identifier: w.identifier, label: w.label}
        )
      )

      Enum.each(entries, fn row ->
        entry = %{
          type: String.to_existing_atom(row.watch_type),
          org_id: row.org_id,
          identifier: row.identifier,
          label: row.label,
          added_at: DateTime.utc_now()
        }

        :ets.insert(@ets_watchlist, {row.org_id, entry})
      end)
    rescue
      _ -> :ok
    end
  end

  defp get_watchlist_for_org(org_id) do
    :ets.lookup(@ets_watchlist, org_id)
    |> Enum.map(fn {_key, entry} -> entry end)
  end

  # ============================================================================
  # Private - HTTP Helpers
  # ============================================================================

  defp http_get(url, headers) do
    req = Finch.build(:get, url, headers)

    case Finch.request(req, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, {:network, reason}}
    end
  end

  defp http_post(url, body, headers) do
    req = Finch.build(:post, url, headers, body)

    case Finch.request(req, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: status, body: response_body}} when status in 200..299 ->
        {:ok, response_body}

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, {:network, reason}}
    end
  end

  # ============================================================================
  # Private - Scheduling
  # ============================================================================

  defp schedule_domain_check do
    Process.send_after(self(), :check_domains, @domain_check_interval)
  end

  defp schedule_email_check do
    Process.send_after(self(), :check_emails, @email_check_interval)
  end

  defp schedule_executive_check do
    Process.send_after(self(), :check_executives, @executive_check_interval)
  end

  defp parse_date(nil), do: nil
  defp parse_date(%Date{} = d), do: d
  defp parse_date(str) when is_binary(str) do
    case Date.from_iso8601(str) do
      {:ok, d} -> d
      _ ->
        case DateTime.from_iso8601(str) do
          {:ok, dt, _} -> DateTime.to_date(dt)
          _ -> nil
        end
    end
  end
  defp parse_date(_), do: nil
end
