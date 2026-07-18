defmodule TamanduaServer.Detection.DNSAnalyzer do
  @moduledoc """
  Advanced DNS threat detection module.

  Provides real-time analysis of DNS query events to detect:
  - DGA (Domain Generation Algorithm) domains via Shannon entropy
  - DNS beaconing (periodic C2 communication)
  - DNS-based data exfiltration (encoded subdomain labels)
  - Suspicious TLD usage

  Called from the Detection Engine for every dns_query event.
  Maintains per-agent, per-domain state in ETS for temporal analysis.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.Config
  alias TamanduaServer.Detection.DNSBlocklist
  alias TamanduaServer.Detection.RuleLoader
  alias TamanduaServer.Agents.OrgLookup

  @ets_query_log :dns_query_log
  @ets_subdomain_tracker :dns_subdomain_tracker
  @analyze_timeout 10_000
  @read_timeout 15_000
  @cache_ttl_ms 60_000
  @cache_stale_ttl_ms 300_000
  @cache_retry_ms 15_000
  @default_blocklist_max_tenants 128
  @hard_blocklist_max_tenants 512
  @default_blocklist_max_entries_per_tenant 2_000
  @hard_blocklist_max_entries_per_tenant 10_000
  @default_refresh_max_concurrency 4
  @hard_refresh_max_concurrency 16
  @default_refresh_timeout_ms 5_000
  @hard_refresh_timeout_ms 30_000
  @default_mutation_timeout_ms 5_000
  @hard_mutation_timeout_ms 30_000

  @dns_whitelist [
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "amazonaws.com",
    "cloudfront.net",
    "akamai.net",
    "akamaized.net",
    "mozilla.org",
    "mozilla.net",
    "office.com",
    "office365.com",
    "outlook.com",
    "teams.microsoft.com",
    "skype.com",
    "github.com",
    "githubusercontent.com",
    "docker.com",
    "docker.io",
    "ubuntu.com",
    "debian.org",
    "ntp.org",
    "pool.ntp.org"
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a DNS query event and return a list of detections.

  Each detection is a map with:
  - :type - atom identifying the detection category
  - :confidence - float 0.0..1.0
  - :description - human-readable explanation
  - :mitre_techniques - list of relevant MITRE ATT&CK technique IDs
  """
  @spec analyze_dns_event(map()) :: [map()]
  def analyze_dns_event(event) do
    GenServer.call(__MODULE__, {:analyze, event}, @analyze_timeout)
  end

  @doc """
  Return the current DNS blocklist as a list of maps.
  """
  @spec get_blocklist() :: {:error, :missing_organization}
  def get_blocklist, do: {:error, :missing_organization}

  @spec get_blocklist(String.t() | nil) ::
          {:ok, [map()], :fresh | :stale | :degraded} | {:error, atom()}
  def get_blocklist(organization_id) do
    GenServer.call(__MODULE__, {:get_blocklist, organization_id}, @read_timeout)
  end

  @doc false
  def blocklist_status(organization_id) do
    GenServer.call(__MODULE__, {:blocklist_status, organization_id}, @read_timeout)
  end

  @doc """
  Add domains to the blocklist.
  Returns the normalized domains applied after the atomic persistence step commits.
  """
  @spec add_to_blocklist([String.t()], String.t(), String.t()) ::
          {:error, :missing_organization}
  def add_to_blocklist(_domains, _reason, _blocked_by), do: {:error, :missing_organization}

  @spec add_to_blocklist([String.t()], String.t(), String.t(), String.t() | nil) ::
          {:ok, [String.t()]} | {:error, atom()}
  def add_to_blocklist(domains, reason, blocked_by, organization_id) do
    persist_blocklist_mutation(organization_id, fn ->
      DNSBlocklist.add_entries(organization_id, domains, reason, blocked_by)
    end)
  end

  @doc """
  Remove a domain from the blocklist.
  Returns the normalized domain removed after persistence commits.
  """
  @spec remove_from_blocklist(String.t()) :: {:error, :missing_organization}
  def remove_from_blocklist(_domain), do: {:error, :missing_organization}

  @spec remove_from_blocklist(String.t(), String.t() | nil) ::
          {:ok, [String.t()]} | {:error, atom()}
  def remove_from_blocklist(domain, organization_id) do
    persist_blocklist_mutation(organization_id, fn ->
      case DNSBlocklist.remove_entry(organization_id, domain) do
        :ok -> {:ok, [DNSBlocklist.normalize_domain(domain)]}
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  @doc """
  Bulk import domains from a list of strings.
  """
  @spec import_blocklist([String.t()], String.t()) :: {:error, :missing_organization}
  def import_blocklist(_domains, _reason \\ "Bulk import"),
    do: {:error, :missing_organization}

  @spec import_blocklist([String.t()], String.t(), String.t() | nil) ::
          {:ok, [String.t()]} | {:error, atom()}
  def import_blocklist(domains, reason, organization_id) do
    persist_blocklist_mutation(organization_id, fn ->
      DNSBlocklist.add_entries(organization_id, domains, reason, "bulk_import", "bulk_import")
    end)
  end

  defp persist_blocklist_mutation(organization_id, fun) when is_function(fun, 0) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id) do
      with_node_mutation_admission(fn ->
        timeout =
          configured_timeout(
            :mutation_timeout_ms,
            @default_mutation_timeout_ms,
            @hard_mutation_timeout_ms
          )

        owner = self()

        task =
          Task.Supervisor.async_nolink(TamanduaServer.TaskSupervisor, fn ->
            run_mutation_with_owner(fun, owner)
          end)

        outcome = Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill)

        case outcome do
          {:ok, {:ok, applied_domains}} when is_list(applied_domains) ->
            reconcile_blocklist_after_mutation(organization_id)
            {:ok, applied_domains}

          {:ok, {:error, reason}} when is_atom(reason) ->
            {:error, reason}

          {:exit, _reason} ->
            {:error, :blocklist_unavailable}

          nil ->
            # The caller deadline expired without a commit/rollback receipt. Do
            # not claim rollback: force cache invalidation and reconciliation so
            # a late database outcome is observed before subsequent reads.
            reconcile_blocklist_after_mutation(organization_id)

            emit_blocklist_telemetry(
              :mutation_outcome_unknown,
              organization_id,
              :mutation_outcome_unknown
            )

            {:error, :mutation_outcome_unknown}

          _unexpected ->
            {:error, :invalid_mutation_result}
        end
      end)
      |> case do
        :mutation_busy -> {:error, :mutation_busy}
        result -> result
      end
    end
  catch
    :exit, _reason -> {:error, :blocklist_unavailable}
  end

  defp with_node_mutation_admission(fun) do
    lock = {{__MODULE__, :node_mutation_lane, node()}, self()}

    case :global.trans(lock, fun, [node()], 0) do
      :aborted -> :mutation_busy
      {:aborted, _reason} -> :mutation_busy
      result -> result
    end
  catch
    :exit, _reason -> :mutation_busy
  end

  defp run_mutation_with_owner(fun, owner) do
    previous_trap_exit = Process.flag(:trap_exit, true)
    owner_ref = Process.monitor(owner)
    task = self()
    worker = spawn_link(fn -> send(task, {:dns_mutation_result, self(), fun.()}) end)

    try do
      receive do
        {:dns_mutation_result, ^worker, result} ->
          result

        {:EXIT, ^worker, _reason} ->
          {:error, :blocklist_unavailable}

        {:DOWN, ^owner_ref, :process, ^owner, _reason} ->
          Process.exit(worker, :kill)
          {:error, :mutation_owner_down}
      end
    after
      Process.demonitor(owner_ref, [:flush])
      if Process.alive?(worker), do: Process.exit(worker, :kill)
      Process.flag(:trap_exit, previous_trap_exit)
    end
  end

  defp reconcile_blocklist_after_mutation(organization_id) do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) ->
        GenServer.cast(pid, {:invalidate_blocklist, organization_id})

      nil ->
        emit_blocklist_telemetry(:invalidation_deferred, organization_id, :analyzer_unavailable)
    end
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    opts = Keyword.merge(Application.get_env(:tamandua_server, :dns_blocklist_cache, []), opts)

    unless Keyword.get(opts, :skip_ets_setup, false) do
      :ets.new(@ets_query_log, [:named_table, :bag, :public, read_concurrency: true])
      :ets.new(@ets_subdomain_tracker, [:named_table, :set, :public, read_concurrency: true])
    end

    schedule_cleanup()
    Logger.info("DNS Analyzer started")

    {:ok,
     %{
       blocklist_snapshots: %{},
       blocklist_refreshes: %{},
       blocklist_loader:
         Keyword.get(opts, :blocklist_loader, fn organization_id, limit ->
           DNSBlocklist.list_entries(organization_id, limit)
         end),
       blocklist_now:
         Keyword.get(opts, :blocklist_now, fn -> System.monotonic_time(:millisecond) end),
       blocklist_task_supervisor:
         Keyword.get(opts, :blocklist_task_supervisor, TamanduaServer.TaskSupervisor),
       blocklist_max_tenants:
         bounded_cache_limit(
           opts,
           :blocklist_max_tenants,
           @default_blocklist_max_tenants,
           @hard_blocklist_max_tenants
         ),
       blocklist_max_entries_per_tenant:
         bounded_cache_limit(
           opts,
           :blocklist_max_entries_per_tenant,
           @default_blocklist_max_entries_per_tenant,
           @hard_blocklist_max_entries_per_tenant
         ),
       blocklist_refresh_max_concurrency:
         bounded_cache_limit(
           opts,
           :refresh_max_concurrency,
           @default_refresh_max_concurrency,
           @hard_refresh_max_concurrency
         ),
       blocklist_refresh_timeout_ms:
         bounded_cache_limit(
           opts,
           :refresh_timeout_ms,
           @default_refresh_timeout_ms,
           @hard_refresh_timeout_ms
         ),
       ioc_snapshot_observation: %{outcome: nil, emitted_at: nil}
     }}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    {detections, state} = do_analyze(event, state)
    {:reply, detections, state}
  end

  @impl true
  def handle_call(:get_blocklist, _from, state) do
    {:reply, {:error, :missing_organization}, state}
  end

  @impl true
  def handle_call({:get_blocklist, organization_id}, _from, state) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id) do
      now = state.blocklist_now.()
      state = touch_blocklist_snapshot(state, organization_id, now)

      case blocklist_snapshot_outcome(
             state.blocklist_snapshots[organization_id],
             now,
             @cache_ttl_ms,
             @cache_stale_ttl_ms
           ) do
        {:available, entries, freshness} ->
          state =
            if freshness == :fresh,
              do: state,
              else: maybe_start_blocklist_refresh(state, organization_id, now)

          {:reply, {:ok, Map.values(entries), freshness}, state}

        {:degraded, _reason} ->
          state = maybe_start_blocklist_refresh(state, organization_id, now)
          {:reply, {:error, :blocklist_unavailable}, state}
      end
    else
      {:error, _reason} -> {:reply, {:error, :invalid_organization}, state}
    end
  end

  @impl true
  def handle_call({:blocklist_status, organization_id}, _from, state) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id) do
      now = state.blocklist_now.()
      snapshot = state.blocklist_snapshots[organization_id]

      status =
        case blocklist_snapshot_outcome(
               snapshot,
               now,
               @cache_ttl_ms,
               @cache_stale_ttl_ms
             ) do
          {:available, _entries, freshness} -> freshness
          {:degraded, reason} -> {:degraded, reason}
        end

      {:reply,
       %{
         status: status,
         refreshing: Map.has_key?(state.blocklist_refreshes, organization_id),
         last_error: snapshot && snapshot.last_error
       }, state}
    else
      {:error, _reason} -> {:reply, %{status: {:degraded, :invalid_organization}}, state}
    end
  end

  @impl true
  def handle_call({:add_blocklist, domains, reason, blocked_by}, _from, state) do
    _ = {domains, reason, blocked_by}
    {:reply, {:error, :missing_organization}, state}
  end

  @impl true
  def handle_call({:add_blocklist, organization_id, domains, reason, blocked_by}, _from, state) do
    _ = {organization_id, domains, reason, blocked_by}
    {:reply, {:error, :mutation_outside_analyzer}, state}
  end

  @impl true
  def handle_call({:remove_blocklist, domain}, _from, state) do
    _ = domain
    {:reply, {:error, :missing_organization}, state}
  end

  @impl true
  def handle_call({:remove_blocklist, organization_id, domain}, _from, state) do
    _ = {organization_id, domain}
    {:reply, {:error, :mutation_outside_analyzer}, state}
  end

  @impl true
  def handle_call({:import_blocklist, domains, reason}, _from, state) do
    _ = {domains, reason}
    {:reply, {:error, :missing_organization}, state}
  end

  @impl true
  def handle_call({:import_blocklist, organization_id, domains, reason}, _from, state) do
    _ = {organization_id, domains, reason}
    {:reply, {:error, :mutation_outside_analyzer}, state}
  end

  @impl true
  def handle_cast({:invalidate_blocklist, organization_id}, state) do
    {:noreply, invalidate_blocklist_snapshot(state, organization_id)}
  end

  @impl true
  def handle_info(
        {ref, {:dns_blocklist_refresh, organization_id, result}},
        state
      )
      when is_reference(ref) do
    case state.blocklist_refreshes[organization_id] do
      %{task: %Task{ref: ^ref}, timer: timer} ->
        _ = Process.cancel_timer(timer)
        Process.demonitor(ref, [:flush])
        now = state.blocklist_now.()

        state =
          state
          |> Map.update!(:blocklist_refreshes, &Map.delete(&1, organization_id))
          |> apply_blocklist_refresh(organization_id, result, now)

        {:noreply, state}

      _stale_or_unknown ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) when is_reference(ref) do
    case refresh_for_ref(state.blocklist_refreshes, ref) do
      {organization_id, %{timer: timer}} ->
        _ = Process.cancel_timer(timer)
        now = state.blocklist_now.()

        emit_blocklist_telemetry(:refresh_failed, organization_id, :task_crashed)

        state =
          state
          |> Map.update!(:blocklist_refreshes, &Map.delete(&1, organization_id))
          |> note_blocklist_failure(organization_id, :task_crashed, now)

        {:noreply, state}

      nil ->
        {:noreply, state}
    end
  end

  def handle_info({:dns_blocklist_refresh_timeout, organization_id, ref}, state)
      when is_reference(ref) do
    case state.blocklist_refreshes[organization_id] do
      %{task: %Task{ref: ^ref} = task} ->
        _ = Task.shutdown(task, :brutal_kill)
        now = state.blocklist_now.()

        emit_blocklist_telemetry(:refresh_failed, organization_id, :refresh_timeout)

        state =
          state
          |> Map.update!(:blocklist_refreshes, &Map.delete(&1, organization_id))
          |> note_blocklist_failure(organization_id, :refresh_timeout, now)

        {:noreply, state}

      _stale_or_unknown ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_data()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Analysis Logic
  # ============================================================================

  defp do_analyze(event, state) do
    agent_id = event[:agent_id] || event["agent_id"]

    case authoritative_organization_id(event) do
      {:ok, organization_id} -> do_analyze(event, agent_id, organization_id, state)
      {:error, _reason} -> {[], state}
    end
  end

  defp do_analyze(event, agent_id, organization_id, state) do
    payload = event[:payload] || event["payload"] || %{}
    dns_payload = payload[:dns] || payload["dns"] || %{}
    domain = dns_domain(payload, dns_payload)
    query_type = dns_query_type(payload, dns_payload)
    timestamp = event[:timestamp] || event["timestamp"] || System.system_time(:millisecond)

    domain = String.downcase(String.trim(domain))

    if domain == "" or is_safe_domain?(domain) do
      {[], state}
    else
      # Record the query for temporal analysis
      record_query(organization_id, agent_id, domain, timestamp)
      record_subdomain(organization_id, agent_id, domain, timestamp)

      detections = []

      # 1. DGA detection via Shannon entropy
      detections = detections ++ detect_dga(domain)

      # 2. Beaconing detection (frequency analysis)
      detections = detections ++ detect_beaconing(organization_id, agent_id, domain, timestamp)

      # 3. Exfiltration detection (subdomain diversity + long labels)
      detections = detections ++ detect_exfiltration(organization_id, agent_id, domain, timestamp)

      # 4. Suspicious TLD check
      detections = detections ++ detect_suspicious_tld(domain)

      # 5. TXT record abuse
      detections = detections ++ detect_txt_abuse(domain, query_type)

      # 6. Blocklist check. The hot path reads only a bounded tenant snapshot;
      # refresh I/O is supervised and asynchronous.
      {blocklist_detections, state} = check_blocklist(domain, organization_id, state)
      detections = detections ++ blocklist_detections

      # 7. Threat Intelligence feed check
      {threat_intel_detections, state} = check_threat_intel(domain, organization_id, state)
      detections = detections ++ threat_intel_detections

      {detections, state}
    end
  end

  defp dns_domain(payload, dns_payload) do
    first_present(
      [
        payload[:query],
        payload["query"],
        payload[:query_name],
        payload["query_name"],
        payload[:domain],
        payload["domain"],
        payload[:dns_query],
        payload["dns_query"],
        payload[:"dns.domain"],
        payload["dns.domain"],
        payload[:host],
        payload["host"],
        payload[:hostname],
        payload["hostname"],
        dns_payload[:query],
        dns_payload["query"],
        dns_payload[:query_name],
        dns_payload["query_name"],
        dns_payload[:domain],
        dns_payload["domain"]
      ],
      ""
    )
  end

  @doc false
  def authoritative_organization_id(event, org_lookup \\ &OrgLookup.get_org_id/1) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]

    claimed =
      event[:organization_id] || event["organization_id"] || payload[:organization_id] ||
        payload["organization_id"]

    with {:ok, authoritative} <- canonical_organization_id(org_lookup.(agent_id)),
         {:ok, claimed} <- canonical_claimed_organization_id(claimed, authoritative),
         true <- claimed == authoritative do
      {:ok, authoritative}
    else
      _reason ->
        Logger.warning(
          "DNS analysis rejected: authoritative organization unavailable or mismatched",
          agent_id: agent_id
        )

        {:error, :unauthorized_organization}
    end
  rescue
    _ -> {:error, :unauthorized_organization}
  end

  defp canonical_claimed_organization_id(nil, authoritative), do: {:ok, authoritative}

  defp canonical_claimed_organization_id(claimed, _authoritative),
    do: canonical_organization_id(claimed)

  defp canonical_organization_id(organization_id) do
    case Ecto.UUID.cast(organization_id) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, :invalid_organization}
    end
  end

  defp dns_query_type(payload, dns_payload) do
    first_present(
      [
        payload[:query_type],
        payload["query_type"],
        payload[:record_type],
        payload["record_type"],
        payload[:"dns.query_type"],
        payload["dns.query_type"],
        payload[:"dns.record_type"],
        payload["dns.record_type"],
        dns_payload[:query_type],
        dns_payload["query_type"],
        dns_payload[:record_type],
        dns_payload["record_type"]
      ],
      "A"
    )
  end

  defp first_present(values, default) do
    Enum.find_value(values, default, fn
      nil -> nil
      "" -> nil
      value -> value
    end)
  end

  # --------------------------------------------------------------------------
  # DGA Detection
  # --------------------------------------------------------------------------

  defp detect_dga(domain) do
    # Skip DGA analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_dga(domain)
    end
  end

  defp do_detect_dga(domain) do
    # Extract the second-level domain (e.g., "abc123xyz" from "abc123xyz.evil.com")
    labels = String.split(domain, ".")
    sld = if length(labels) >= 2, do: Enum.at(labels, length(labels) - 2), else: hd(labels)

    detections = []

    # Shannon entropy of the SLD
    entropy = shannon_entropy(sld)

    detections =
      if entropy > Config.entropy_threshold() do
        [
          %{
            type: :dga_high_entropy,
            confidence: min(0.5 + (entropy - Config.entropy_threshold()) * 0.2, 0.95),
            description:
              "Domain '#{domain}' has high Shannon entropy (#{Float.round(entropy, 2)}), " <>
                "suggesting DGA-generated domain",
            mitre_techniques: ["T1568.002"]
          }
          | detections
        ]
      else
        detections
      end

    # Consonant-to-vowel ratio check on SLD
    {consonants, vowels} = count_consonants_vowels(sld)
    cv_ratio = if vowels > 0, do: consonants / vowels, else: consonants * 1.0

    detections =
      if String.length(sld) >= 8 and cv_ratio > 5.0 do
        [
          %{
            type: :dga_character_distribution,
            confidence: min(0.4 + cv_ratio * 0.05, 0.85),
            description:
              "Domain '#{domain}' has unusual consonant-to-vowel ratio (#{Float.round(cv_ratio, 1)}:1), " <>
                "suggesting DGA-generated domain",
            mitre_techniques: ["T1568.002"]
          }
          | detections
        ]
      else
        detections
      end

    # Numeric mixing check
    alpha_count = sld |> String.graphemes() |> Enum.count(&(&1 =~ ~r/[a-z]/))
    digit_count = sld |> String.graphemes() |> Enum.count(&(&1 =~ ~r/[0-9]/))

    detections =
      if String.length(sld) >= 10 and alpha_count > 0 and digit_count > 0 and
           digit_count / (alpha_count + digit_count) > 0.3 do
        [
          %{
            type: :dga_mixed_alphanum,
            confidence: 0.6,
            description:
              "Domain '#{domain}' has heavy numeric/alpha mixing " <>
                "(#{digit_count} digits in #{String.length(sld)} chars), suggesting DGA",
            mitre_techniques: ["T1568.002"]
          }
          | detections
        ]
      else
        detections
      end

    # Long label check
    longest_label =
      labels
      |> Enum.map(&String.length/1)
      |> Enum.max(fn -> 0 end)

    detections =
      if longest_label > Config.long_label_threshold() do
        [
          %{
            type: :dga_long_label,
            confidence: min(0.5 + (longest_label - Config.long_label_threshold()) * 0.02, 0.85),
            description:
              "Domain '#{domain}' contains a label with #{longest_label} characters (>#{Config.long_label_threshold()}), " <>
                "suggesting DGA or data encoding",
            mitre_techniques: ["T1568.002", "T1048"]
          }
          | detections
        ]
      else
        detections
      end

    detections
  end

  # --------------------------------------------------------------------------
  # Beaconing Detection
  # --------------------------------------------------------------------------

  defp detect_beaconing(organization_id, agent_id, domain, now) do
    # Skip beaconing analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_beaconing(organization_id, agent_id, domain, now)
    end
  end

  defp do_detect_beaconing(organization_id, agent_id, domain, now) do
    # Extract parent domain (last two labels) to group queries
    parent = extract_parent_domain(domain)

    # Count queries to this parent domain from this agent within the window
    cutoff = now - Config.beaconing_window_ms()

    count =
      :ets.lookup(@ets_query_log, {organization_id, agent_id, parent})
      |> Enum.count(fn {{_organization, _agent, _dom}, ts} -> ts >= cutoff end)

    if count > Config.beaconing_query_threshold() do
      # Calculate interval regularity
      timestamps =
        :ets.lookup(@ets_query_log, {organization_id, agent_id, parent})
        |> Enum.map(fn {_key, ts} -> ts end)
        |> Enum.filter(&(&1 >= cutoff))
        |> Enum.sort()

      regularity = calculate_interval_regularity(timestamps)

      confidence =
        cond do
          regularity > 0.9 and count > 100 -> 0.95
          regularity > 0.7 and count > 50 -> 0.85
          count > 50 -> 0.7
          true -> 0.5
        end

      [
        %{
          type: :dns_beaconing,
          confidence: confidence,
          description:
            "Domain '#{parent}' queried #{count} times in #{div(Config.beaconing_window_ms(), 60_000)} minutes " <>
              "from agent #{agent_id} (interval regularity: #{Float.round(regularity, 2)}), " <>
              "suggesting C2 beaconing",
          mitre_techniques: ["T1071.004", "T1573"]
        }
      ]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Exfiltration Detection
  # --------------------------------------------------------------------------

  defp detect_exfiltration(organization_id, agent_id, domain, now) do
    # Skip exfiltration analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_exfiltration(organization_id, agent_id, domain, now)
    end
  end

  defp do_detect_exfiltration(organization_id, agent_id, domain, now) do
    parent = extract_parent_domain(domain)
    labels = String.split(domain, ".")
    detections = []

    # Check for long encoded subdomain labels (>30 chars)
    long_labels =
      labels
      |> Enum.slice(0..(length(labels) - 3)//1)
      |> Enum.filter(&(String.length(&1) > Config.exfil_label_threshold()))

    detections =
      if length(long_labels) > 0 do
        longest = Enum.max_by(long_labels, &String.length/1)

        [
          %{
            type: :dns_exfiltration_long_label,
            confidence:
              min(0.6 + (String.length(longest) - Config.exfil_label_threshold()) * 0.01, 0.95),
            description:
              "DNS query to '#{domain}' contains encoded subdomain label " <>
                "(#{String.length(longest)} chars), suggesting data exfiltration",
            mitre_techniques: ["T1048", "T1071.004"]
          }
          | detections
        ]
      else
        detections
      end

    # Check for high unique subdomain diversity under the same parent
    tracker_key = {organization_id, agent_id, parent}
    cutoff = now - Config.exfil_window_ms()

    unique_count =
      case :ets.lookup(@ets_subdomain_tracker, tracker_key) do
        [{_key, subdomains_map}] ->
          subdomains_map
          |> Enum.count(fn {_sub, ts} -> ts >= cutoff end)

        [] ->
          0
      end

    detections =
      if unique_count > Config.exfil_subdomain_threshold() do
        [
          %{
            type: :dns_exfiltration_subdomain_volume,
            confidence: min(0.6 + unique_count * 0.005, 0.95),
            description:
              "#{unique_count} unique subdomains queried under '#{parent}' " <>
                "in #{div(Config.exfil_window_ms(), 60_000)} minutes from agent #{agent_id}, " <>
                "suggesting DNS data exfiltration",
            mitre_techniques: ["T1048", "T1071.004"]
          }
          | detections
        ]
      else
        detections
      end

    detections
  end

  # --------------------------------------------------------------------------
  # Suspicious TLD Detection
  # --------------------------------------------------------------------------

  defp detect_suspicious_tld(domain) do
    tld = "." <> (domain |> String.split(".") |> List.last())

    if tld in Config.suspicious_tlds() do
      [
        %{
          type: :suspicious_tld,
          confidence: 0.4,
          description:
            "DNS query to '#{domain}' uses TLD '#{tld}' commonly associated " <>
              "with malicious activity",
          mitre_techniques: ["T1071.004", "T1583.001"]
        }
      ]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # TXT Record Abuse
  # --------------------------------------------------------------------------

  defp detect_txt_abuse(domain, query_type) do
    query_type_str = to_string(query_type) |> String.upcase()

    if query_type_str == "TXT" do
      # TXT queries to non-standard domains are suspicious
      is_standard_txt =
        String.contains?(domain, "_domainkey.") or
          String.contains?(domain, "_dmarc.") or
          String.contains?(domain, "_spf.") or
          String.contains?(domain, "_acme-challenge.")

      if not is_standard_txt do
        [
          %{
            type: :dns_txt_query,
            confidence: 0.5,
            description:
              "DNS TXT record query to '#{domain}' may indicate C2 communication " <>
                "or data exfiltration via DNS TXT records",
            mitre_techniques: ["T1071.004", "T1048"]
          }
        ]
      else
        []
      end
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Blocklist Check
  # --------------------------------------------------------------------------

  defp check_blocklist(domain, organization_id, state) do
    # Check exact match and parent domains
    domains_to_check = [domain | parent_domains(domain)]
    now = state.blocklist_now.()
    state = touch_blocklist_snapshot(state, organization_id, now)

    case blocklist_snapshot_outcome(
           state.blocklist_snapshots[organization_id],
           now,
           @cache_ttl_ms,
           @cache_stale_ttl_ms
         ) do
      {:available, entries, freshness} ->
        state =
          if freshness == :fresh do
            state
          else
            maybe_start_blocklist_refresh(state, organization_id, now)
          end

        case Enum.find_value(domains_to_check, &Map.get(entries, &1)) do
          nil ->
            {[], state}

          entry ->
            matched_domain = Map.get(entry, :normalized_domain) || Map.get(entry, :domain)

            {[
               %{
                 type: :blocklisted_domain,
                 confidence: 1.0,
                 description:
                   "DNS query to '#{domain}' matches blocklisted domain '#{matched_domain}' " <>
                     "(reason: #{entry.reason || "N/A"})",
                 mitre_techniques: ["T1071.004"]
               }
             ], state}
        end

      {:degraded, _reason} ->
        {[], maybe_start_blocklist_refresh(state, organization_id, now)}
    end
  end

  # --------------------------------------------------------------------------
  # Threat Intelligence Check
  # --------------------------------------------------------------------------

  defp check_threat_intel(domain, organization_id, state) do
    domains_to_check = [domain | parent_domains(domain)] |> Enum.take(8)

    {ioc_matches, state} =
      case lookup_domain_ioc_snapshot(organization_id, domains_to_check) do
        {:ok, matches} -> {matches, observe_ioc_snapshot(state, :ready)}
        {:error, reason} -> {%{}, observe_ioc_snapshot(state, {:degraded, reason})}
      end

    # Check all domain variants against the global feed cache and one pinned,
    # tenant-aware IOC generation.
    Enum.reduce_while(domains_to_check, {[], state}, fn candidate, {_detections, state} ->
      case check_single_domain_intel(candidate, domain, Map.get(ioc_matches, candidate)) do
        [] -> {:cont, {[], state}}
        detections -> {:halt, {detections, state}}
      end
    end)
  end

  defp check_single_domain_intel(check_domain, original_domain, tenant_ioc) do
    detections = []

    # 1. Check ETS-based ThreatIntel cache (from automated feeds)
    detections =
      try do
        case TamanduaServer.ThreatIntel.lookup(:domain, check_domain) do
          {:ok, ioc} ->
            source = Map.get(ioc, :source, "threat_feed")
            severity = Map.get(ioc, :severity, "medium")
            tags = Map.get(ioc, :tags, [])
            tag_info = if(tags != [], do: ", tags: #{Enum.join(tags, ", ")}", else: "")

            [
              %{
                type: :threat_intel_domain,
                confidence: severity_to_confidence(severity),
                description:
                  "DNS query to '#{original_domain}' matches threat intel IOC " <>
                    "'#{check_domain}' (source: #{source}, severity: #{severity}#{tag_info})",
                mitre_techniques: ["T1071.004", "T1568"]
              }
              | detections
            ]

          :not_found ->
            detections
        end
      rescue
        _ -> detections
      end

    case tenant_ioc do
      nil ->
        detections

      ioc ->
        [
          %{
            type: :ioc_domain_match,
            confidence: normalize_ioc_confidence(Map.get(ioc, :confidence)),
            description:
              "DNS query to '#{original_domain}' matches known malicious domain " <>
                "'#{check_domain}' (scope: #{inspect(Map.get(ioc, :scope, :global))})",
            mitre_techniques: ["T1071.004"]
          }
          | detections
        ]
    end
  end

  defp severity_to_confidence("critical"), do: 0.95
  defp severity_to_confidence("high"), do: 0.85
  defp severity_to_confidence("medium"), do: 0.70
  defp severity_to_confidence("low"), do: 0.50
  defp severity_to_confidence(_), do: 0.70

  @doc false
  def normalize_ioc_confidence(value) when is_number(value) and value > 1,
    do: min(value / 100, 1.0)

  def normalize_ioc_confidence(value) when is_number(value) and value >= 0,
    do: min(value * 1.0, 1.0)

  def normalize_ioc_confidence(_value), do: 0.7

  defp lookup_domain_ioc_snapshot(organization_id, domains) do
    with epoch when is_integer(epoch) and epoch >= 0 <- RuleLoader.published_ioc_epoch(),
         {:ok, matches} <-
           RuleLoader.with_ioc_snapshot(fn pinned_table ->
             matches =
               Enum.reduce(domains, %{}, fn domain, acc ->
                 case lookup_domain_ioc_entry(pinned_table, organization_id, domain) do
                   nil -> acc
                   ioc -> Map.put(acc, domain, ioc)
                 end
               end)

             {:ok, matches}
           end) do
      {:ok, matches}
    else
      [] -> {:error, :snapshot_unavailable}
      :unavailable -> {:error, :snapshot_unavailable}
      epoch when is_integer(epoch) and epoch < 0 -> {:error, :epoch_unavailable}
      _unexpected -> {:error, :snapshot_unavailable}
    end
  rescue
    ArgumentError -> {:error, :snapshot_unavailable}
  end

  @doc false
  def lookup_domain_ioc_entry(table, organization_id, domain) do
    tenant_key = {{:tenant, organization_id}, :domain, domain}
    global_key = {:global, :domain, domain}

    case :ets.lookup(table, tenant_key) do
      [{^tenant_key, tenant_ioc}] ->
        tenant_ioc

      [] ->
        case :ets.lookup(table, global_key) do
          [{^global_key, global_ioc}] -> global_ioc
          [] -> nil
        end
    end
  end

  defp observe_ioc_snapshot(state, outcome) do
    now = state.blocklist_now.()
    previous = state.ioc_snapshot_observation

    emit? =
      previous.outcome != outcome or not is_integer(previous.emitted_at) or
        now - previous.emitted_at >= @cache_retry_ms

    if emit? do
      reason = if match?({:degraded, _}, outcome), do: elem(outcome, 1), else: :ready

      :telemetry.execute(
        [:tamandua, :dns, :ioc_snapshot],
        %{count: 1},
        %{outcome: outcome, reason: reason}
      )

      put_in(state, [:ioc_snapshot_observation], %{outcome: outcome, emitted_at: now})
    else
      state
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Calculate Shannon entropy of a string.
  Higher values indicate more randomness.
  """
  @spec shannon_entropy(String.t()) :: float()
  def shannon_entropy(""), do: 0.0

  def shannon_entropy(string) do
    len = String.length(string)

    if len == 0 do
      0.0
    else
      string
      |> String.graphemes()
      |> Enum.frequencies()
      |> Enum.reduce(0.0, fn {_char, count}, acc ->
        probability = count / len
        acc - probability * :math.log2(probability)
      end)
    end
  end

  defp count_consonants_vowels(string) do
    vowels = ~w(a e i o u)
    chars = string |> String.downcase() |> String.graphemes() |> Enum.filter(&(&1 =~ ~r/[a-z]/))

    vowel_count = Enum.count(chars, &(&1 in vowels))
    consonant_count = length(chars) - vowel_count

    {consonant_count, vowel_count}
  end

  defp extract_parent_domain(domain) do
    parts = String.split(domain, ".")

    if length(parts) >= 2 do
      parts |> Enum.take(-2) |> Enum.join(".")
    else
      domain
    end
  end

  defp parent_domains(domain) do
    parts = String.split(domain, ".")

    if length(parts) > 2 do
      # Generate all parent domains: a.b.c.d -> [b.c.d, c.d]
      2..(length(parts) - 1)
      |> Enum.map(fn i ->
        parts |> Enum.take(-i) |> Enum.join(".")
      end)
    else
      []
    end
  end

  defp is_safe_domain?(domain) do
    safe_domain?(domain, Config.safe_domains())
  end

  @doc false
  def safe_domain?(domain, safe_domains) when is_binary(domain) and is_list(safe_domains) do
    domain = DNSBlocklist.normalize_domain(domain)

    Enum.any?(safe_domains, fn safe ->
      safe = DNSBlocklist.normalize_domain(safe)
      safe != "" and (domain == safe or String.ends_with?(domain, "." <> safe))
    end)
  end

  def safe_domain?(_domain, _safe_domains), do: false

  defp whitelisted_domain?(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)

    Enum.any?(@dns_whitelist, fn trusted ->
      domain_lower == trusted or String.ends_with?(domain_lower, "." <> trusted)
    end)
  end

  defp whitelisted_domain?(_), do: false

  defp record_query(organization_id, agent_id, domain, timestamp) do
    parent = extract_parent_domain(domain)
    :ets.insert(@ets_query_log, {{organization_id, agent_id, parent}, timestamp})
  end

  defp blocklist_entry_to_map(entry) do
    %{
      normalized_domain: entry.normalized_domain,
      domain: entry.normalized_domain || entry.domain,
      blocked_at: entry.updated_at || entry.inserted_at,
      blocked_by: entry.blocked_by,
      reason: entry.reason,
      source: entry.source,
      active: entry.active,
      organization_id: entry.organization_id
    }
  end

  @doc false
  def build_blocklist_snapshot(
        entries,
        refreshed_at,
        max_entries \\ @default_blocklist_max_entries_per_tenant
      )

  def build_blocklist_snapshot(entries, refreshed_at, max_entries)
      when is_list(entries) and is_integer(max_entries) and max_entries > 0 do
    if length(entries) > max_entries do
      {:error, :capacity_exceeded}
    else
      indexed =
        Enum.reduce(entries, %{}, fn entry, acc ->
          mapped = blocklist_entry_to_map(entry)
          domain = DNSBlocklist.normalize_domain(mapped.domain)

          if domain == "" do
            acc
          else
            Map.put(acc, domain, mapped)
          end
        end)

      {:ok,
       %{
         entries: indexed,
         refreshed_at: refreshed_at,
         last_attempt_at: refreshed_at,
         last_accessed_at: refreshed_at,
         last_error: nil
       }}
    end
  end

  def build_blocklist_snapshot(_entries, _refreshed_at, _max_entries),
    do: {:error, :invalid_snapshot}

  @doc false
  def blocklist_snapshot_outcome(snapshot, now, fresh_ttl, stale_ttl)

  def blocklist_snapshot_outcome(
        %{entries: entries, refreshed_at: refreshed_at} = snapshot,
        now,
        fresh_ttl,
        stale_ttl
      )
      when is_map(entries) and is_integer(refreshed_at) and is_integer(now) do
    age = max(now - refreshed_at, 0)

    cond do
      age <= fresh_ttl and is_nil(snapshot.last_error) ->
        {:available, entries, :fresh}

      age <= stale_ttl and is_nil(snapshot.last_error) ->
        {:available, entries, :stale}

      age <= stale_ttl ->
        {:available, entries, :degraded}

      true ->
        {:degraded, :expired}
    end
  end

  def blocklist_snapshot_outcome(_snapshot, _now, _fresh_ttl, _stale_ttl),
    do: {:degraded, :missing}

  defp maybe_start_blocklist_refresh(state, organization_id, now) do
    snapshot = state.blocklist_snapshots[organization_id]
    last_attempt_at = snapshot && snapshot.last_attempt_at

    cond do
      Map.has_key?(state.blocklist_refreshes, organization_id) ->
        state

      is_integer(last_attempt_at) and now - last_attempt_at < @cache_retry_ms ->
        state

      map_size(state.blocklist_refreshes) >= state.blocklist_refresh_max_concurrency ->
        emit_blocklist_telemetry(:refresh_rejected, organization_id, :global_refresh_budget)
        note_bounded_refresh_rejection(state, organization_id, :global_refresh_budget, now)

      true ->
        state = ensure_blocklist_tenant_capacity(state, organization_id)

        if not Map.has_key?(state.blocklist_snapshots, organization_id) and
             blocklist_tenant_count(state) >= state.blocklist_max_tenants do
          emit_blocklist_telemetry(:refresh_rejected, organization_id, :tenant_capacity)
          state
        else
          loader = state.blocklist_loader
          limit = state.blocklist_max_entries_per_tenant + 1

          task = fn ->
            result = safe_load_blocklist(loader, organization_id, limit)
            {:dns_blocklist_refresh, organization_id, result}
          end

          case Task.Supervisor.async_nolink(state.blocklist_task_supervisor, task) do
            %Task{} = task ->
              timer =
                Process.send_after(
                  self(),
                  {:dns_blocklist_refresh_timeout, organization_id, task.ref},
                  state.blocklist_refresh_timeout_ms
                )

              emit_blocklist_telemetry(:refresh_started, organization_id, :scheduled)

              state
              |> Map.update!(:blocklist_refreshes, fn refreshes ->
                Map.put(refreshes, organization_id, %{task: task, timer: timer})
              end)
              |> mark_blocklist_attempt(organization_id, now)
          end
        end
    end
  catch
    :exit, _reason ->
      emit_blocklist_telemetry(:refresh_failed, organization_id, :task_unavailable)
      note_blocklist_failure(state, organization_id, :task_unavailable, now)
  end

  defp safe_load_blocklist(loader, organization_id, limit) do
    case loader.(organization_id, limit) do
      {:ok, entries} when is_list(entries) -> {:ok, entries}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _unexpected -> {:error, :invalid_loader_result}
    end
  rescue
    _ -> {:error, :blocklist_unavailable}
  catch
    :exit, _reason -> {:error, :blocklist_unavailable}
  end

  defp apply_blocklist_refresh(state, organization_id, {:ok, entries}, now) do
    case build_blocklist_snapshot(entries, now, state.blocklist_max_entries_per_tenant) do
      {:ok, snapshot} ->
        emit_blocklist_telemetry(:refresh_succeeded, organization_id, :ready)
        put_in(state, [:blocklist_snapshots, organization_id], snapshot)

      {:error, reason} ->
        emit_blocklist_telemetry(:refresh_failed, organization_id, reason)
        note_blocklist_failure(state, organization_id, reason, now)
    end
  end

  defp apply_blocklist_refresh(state, organization_id, {:error, reason}, now) do
    emit_blocklist_telemetry(:refresh_failed, organization_id, reason)
    note_blocklist_failure(state, organization_id, reason, now)
  end

  defp mark_blocklist_attempt(state, organization_id, now) do
    update_in(state, [:blocklist_snapshots], fn snapshots ->
      Map.update(
        snapshots,
        organization_id,
        %{
          entries: %{},
          refreshed_at: nil,
          last_attempt_at: now,
          last_accessed_at: now,
          last_error: :loading
        },
        &Map.put(&1, :last_attempt_at, now)
      )
    end)
  end

  defp note_blocklist_failure(state, organization_id, reason, now) do
    update_in(state, [:blocklist_snapshots], fn snapshots ->
      Map.update(
        snapshots,
        organization_id,
        %{
          entries: %{},
          refreshed_at: nil,
          last_attempt_at: now,
          last_accessed_at: now,
          last_error: reason
        },
        fn snapshot ->
          snapshot
          |> Map.put(:last_attempt_at, now)
          |> Map.put(:last_error, reason)
        end
      )
    end)
  end

  defp note_bounded_refresh_rejection(state, organization_id, reason, now) do
    state = ensure_blocklist_tenant_capacity(state, organization_id)

    if Map.has_key?(state.blocklist_snapshots, organization_id) or
         blocklist_tenant_count(state) < state.blocklist_max_tenants do
      note_blocklist_failure(state, organization_id, reason, now)
    else
      state
    end
  end

  defp invalidate_blocklist_snapshot(state, organization_id) do
    case canonical_organization_id(organization_id) do
      {:ok, organization_id} ->
        now = state.blocklist_now.()

        state
        |> cancel_blocklist_refresh(organization_id)
        |> Map.update!(:blocklist_snapshots, &Map.delete(&1, organization_id))
        |> maybe_start_blocklist_refresh(organization_id, now)

      {:error, _reason} ->
        state
    end
  end

  defp cancel_blocklist_refresh(state, organization_id) do
    case Map.pop(state.blocklist_refreshes, organization_id) do
      {nil, _refreshes} ->
        state

      {%{task: %Task{} = task, timer: timer}, refreshes} ->
        _ = Process.cancel_timer(timer)
        _ = Task.shutdown(task, :brutal_kill)
        %{state | blocklist_refreshes: refreshes}
    end
  catch
    :exit, _reason ->
      update_in(state, [:blocklist_refreshes], &Map.delete(&1, organization_id))
  end

  defp refresh_for_ref(refreshes, ref) do
    Enum.find(refreshes, fn
      {_organization_id, %{task: %Task{ref: ^ref}}} -> true
      _other -> false
    end)
  end

  defp emit_blocklist_telemetry(outcome, organization_id, reason) do
    :telemetry.execute(
      [:tamandua, :dns, :blocklist_cache],
      %{count: 1},
      %{outcome: outcome, organization_id: organization_id, reason: reason}
    )
  end

  defp touch_blocklist_snapshot(state, organization_id, now) do
    update_in(state, [:blocklist_snapshots], fn snapshots ->
      case snapshots do
        %{^organization_id => snapshot} ->
          Map.put(snapshots, organization_id, Map.put(snapshot, :last_accessed_at, now))

        _ ->
          snapshots
      end
    end)
  end

  defp ensure_blocklist_tenant_capacity(state, organization_id) do
    known? =
      Map.has_key?(state.blocklist_snapshots, organization_id) or
        Map.has_key?(state.blocklist_refreshes, organization_id)

    if known? or blocklist_tenant_count(state) < state.blocklist_max_tenants do
      state
    else
      protected = Map.keys(state.blocklist_refreshes) |> MapSet.new()

      eviction_candidate =
        state.blocklist_snapshots
        |> Enum.reject(fn {tenant_id, _snapshot} -> MapSet.member?(protected, tenant_id) end)
        |> Enum.min_by(
          fn {tenant_id, snapshot} -> {Map.get(snapshot, :last_accessed_at, 0), tenant_id} end,
          fn -> nil end
        )

      case eviction_candidate do
        {tenant_id, _snapshot} ->
          emit_blocklist_telemetry(:snapshot_evicted, tenant_id, :tenant_capacity)
          update_in(state, [:blocklist_snapshots], &Map.delete(&1, tenant_id))

        nil ->
          state
      end
    end
  end

  defp blocklist_tenant_count(state) do
    state.blocklist_snapshots
    |> Map.keys()
    |> MapSet.new()
    |> MapSet.union(Map.keys(state.blocklist_refreshes) |> MapSet.new())
    |> MapSet.size()
  end

  defp bounded_cache_limit(opts, key, default, hard_max) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> min(value, hard_max)
      _invalid -> default
    end
  end

  defp configured_timeout(key, default, hard_max) do
    :tamandua_server
    |> Application.get_env(:dns_blocklist_mutations, [])
    |> Keyword.get(key, default)
    |> case do
      value when is_integer(value) and value > 0 -> min(value, hard_max)
      _invalid -> default
    end
  end

  defp record_subdomain(organization_id, agent_id, domain, timestamp) do
    parts = String.split(domain, ".")

    if length(parts) > 2 do
      parent = extract_parent_domain(domain)
      # The subdomain portion (everything except the last two labels)
      subdomain = parts |> Enum.take(length(parts) - 2) |> Enum.join(".")
      tracker_key = {organization_id, agent_id, parent}

      existing =
        case :ets.lookup(@ets_subdomain_tracker, tracker_key) do
          [{_key, map}] -> map
          [] -> %{}
        end

      updated = Map.put(existing, subdomain, timestamp)
      :ets.insert(@ets_subdomain_tracker, {tracker_key, updated})
    end
  end

  defp calculate_interval_regularity(timestamps) when length(timestamps) < 3, do: 0.0

  defp calculate_interval_regularity(timestamps) do
    # Calculate intervals between consecutive timestamps
    intervals =
      timestamps
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [a, b] -> b - a end)
      |> Enum.filter(&(&1 > 0))

    if length(intervals) < 2 do
      0.0
    else
      mean = Enum.sum(intervals) / length(intervals)

      if mean == 0 do
        0.0
      else
        # Calculate coefficient of variation (lower = more regular)
        variance =
          intervals
          |> Enum.map(fn i -> (i - mean) * (i - mean) end)
          |> Enum.sum()
          |> Kernel./(length(intervals))

        std_dev = :math.sqrt(variance)
        cv = std_dev / mean

        # Convert CV to a 0-1 regularity score (lower CV = higher regularity)
        max(0.0, min(1.0, 1.0 - cv))
      end
    end
  end

  defp cleanup_old_data do
    now = System.system_time(:millisecond)
    cutoff = now - Config.dns_data_ttl()

    # Clean query log
    :ets.tab2list(@ets_query_log)
    |> Enum.each(fn {key, ts} ->
      if ts < cutoff do
        :ets.delete_object(@ets_query_log, {key, ts})
      end
    end)

    # Clean subdomain tracker - remove old entries from each map
    :ets.tab2list(@ets_subdomain_tracker)
    |> Enum.each(fn {key, subdomains_map} ->
      cleaned =
        subdomains_map
        |> Enum.reject(fn {_sub, ts} -> ts < cutoff end)
        |> Map.new()

      if map_size(cleaned) == 0 do
        :ets.delete(@ets_subdomain_tracker, key)
      else
        :ets.insert(@ets_subdomain_tracker, {key, cleaned})
      end
    end)

    Logger.debug("DNS Analyzer cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, Config.dns_cleanup_interval())
  end
end
