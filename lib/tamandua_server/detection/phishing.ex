defmodule TamanduaServer.Detection.Phishing do
  @moduledoc """
  Comprehensive Phishing Email Analysis and Triage Engine.

  Provides deep-inspection phishing analysis with ETS-backed state for
  high-throughput deduplication, campaign clustering, sender reputation
  caching, and brand/domain typosquatting detection.

  ## Analysis Pipeline

  Each submitted email passes through these stages:

  1. **Header Analysis** - SPF, DKIM, DMARC verification; Received chain
     anomaly detection; Reply-To / From mismatch; X-Mailer fingerprinting.

  2. **URL Analysis** - Extraction from HTML and plain text; URL shortener
     resolution; homograph / IDN attack detection; typosquatting via
     Levenshtein distance; IOC reputation lookup; suspicious TLD check.

  3. **Attachment Analysis** - Magic-byte file type identification; double
     extension detection; macro detection in Office documents; hash lookup
     against IOC database; auto-submit to Sandbox for detonation;
     password-protected archive detection.

  4. **Sender Analysis** - Reputation scoring (first-time sender, domain
     age, historical patterns); display-name spoofing detection; BEC
     pattern detection; executive impersonation via fuzzy match against
     known internal names.

  5. **Campaign Detection** - Cluster similar phishing emails by subject
     similarity, URL patterns, sender patterns, and attachment hashes;
     track campaign spread; link to CampaignTracker.

  6. **Verdict** - Weighted aggregation into final verdict: clean,
     suspicious, phishing, or spear_phishing with confidence 0-100
     and recommended actions.

  ## ETS Tables

  - `:phishing_submissions` - Recent analysis cache (dedup)
  - `:phishing_campaigns` - Campaign clustering state
  - `:phishing_sender_rep` - Sender reputation cache
  - `:phishing_brands` - Brand / domain list for typosquatting
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.{IOCs, Sandbox}
  alias TamanduaServer.ThreatIntel.CampaignTracker

  # ── ETS Table Names ────────────────────────────────────────────────
  @ets_submissions :phishing_submissions
  @ets_campaigns :phishing_campaigns
  @ets_sender_rep :phishing_sender_rep
  @ets_brands :phishing_brands

  # ── Thresholds ─────────────────────────────────────────────────────
  @phishing_threshold 70
  @suspicious_threshold 40
  @spear_phishing_threshold 80

  # ── Campaign clustering ────────────────────────────────────────────
  @campaign_min_emails 3
  @campaign_cluster_window_hours 72
  @campaign_sweep_interval :timer.minutes(10)

  # ── Sender reputation TTL ──────────────────────────────────────────
  @sender_rep_ttl_seconds 86_400

  # ── Dedup window ───────────────────────────────────────────────────

  # ── Suspicious TLDs ────────────────────────────────────────────────
  @suspicious_tlds ~w(.tk .ml .ga .cf .gq .xyz .top .work .click .link
                      .info .pw .cc .biz .buzz .rest .icu .su .racing
                      .download .stream .loan .date .trade .webcam)

  # ── URL Shorteners ─────────────────────────────────────────────────
  @url_shorteners ~w(bit.ly tinyurl.com t.co goo.gl ow.ly is.gd
                     buff.ly rebrand.ly short.link cutt.ly rb.gy
                     tiny.cc shorturl.at lnkd.in v.gd)

  # ── Known Phishing X-Mailer Signatures ─────────────────────────────
  @suspicious_mailers ~w(PHPMailer GoPhish King\ Phisher Evilginx
                         SET\ Toolkit Modlishka)

  # ── Dangerous Extensions ───────────────────────────────────────────
  @dangerous_extensions ~w(.exe .scr .bat .cmd .ps1 .vbs .js .jar
                           .msi .dll .hta .wsf .iso .img .com .pif
                           .cpl .lnk .reg .inf)
  @macro_extensions ~w(.docm .xlsm .pptm .dotm .xltm .potm .xlam)
  @archive_extensions ~w(.zip .rar .7z .tar .gz .bz2 .cab .arj)

  # ── Magic Bytes ────────────────────────────────────────────────────
  @magic_bytes %{
    <<0x4D, 0x5A>> => "application/x-dosexec",
    <<0x50, 0x4B, 0x03, 0x04>> => "application/zip",
    <<0x25, 0x50, 0x44, 0x46>> => "application/pdf",
    <<0xD0, 0xCF, 0x11, 0xE0>> => "application/x-ole-storage",
    <<0x52, 0x61, 0x72, 0x21>> => "application/x-rar",
    <<0x1F, 0x8B>> => "application/gzip",
    <<0x37, 0x7A, 0xBC, 0xAF>> => "application/x-7z-compressed",
    <<0x7F, 0x45, 0x4C, 0x46>> => "application/x-elf"
  }

  # ── Brand Domains for Typosquatting ────────────────────────────────
  @brand_domains %{
    "microsoft" => ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"],
    "google" => ["google.com", "gmail.com", "googleapis.com", "youtube.com"],
    "apple" => ["apple.com", "icloud.com", "appleid.apple.com"],
    "amazon" => ["amazon.com", "aws.amazon.com", "amazon.co.uk"],
    "paypal" => ["paypal.com", "paypal.me"],
    "netflix" => ["netflix.com"],
    "facebook" => ["facebook.com", "fb.com", "meta.com"],
    "linkedin" => ["linkedin.com"],
    "twitter" => ["twitter.com", "x.com"],
    "dropbox" => ["dropbox.com"],
    "chase" => ["chase.com"],
    "wellsfargo" => ["wellsfargo.com"],
    "bankofamerica" => ["bankofamerica.com"],
    "citibank" => ["citibank.com", "citi.com"],
    "docusign" => ["docusign.com", "docusign.net"],
    "zoom" => ["zoom.us", "zoom.com"],
    "slack" => ["slack.com"],
    "salesforce" => ["salesforce.com"]
  }

  # ── Homoglyph Map (Latin -> Look-alike) ────────────────────────────
  @homoglyphs %{
    ?a => [0x0430, 0x0105, 0x03B1],
    ?e => [0x0435, 0x0119, 0x03B5],
    ?i => [0x0456, 0x0131, ?1, ?l],
    ?o => [0x043E, 0x03BF, ?0],
    ?l => [?1, ?I, 0x0142, 0x0456],
    ?s => [0x0455, 0x015B],
    ?c => [0x0441, 0x00E7],
    ?p => [0x0440],
    ?x => [0x0445],
    ?y => [0x0443],
    ?n => [0x00F1, 0x0144],
    ?r => [0x0433],
    ?u => [0x03C5],
    ?d => [0x0501],
    ?g => [0x0261],
    ?h => [0x04BB],
    ?k => [0x043A],
    ?m => [0x043C],
    ?t => [0x0442],
    ?w => [0x0461]
  }

  # ── Component Weights for Verdict ──────────────────────────────────
  @weights %{
    headers: 15,
    urls: 30,
    attachments: 25,
    sender: 15,
    content: 15
  }

  # ── PubSub ─────────────────────────────────────────────────────────
  @pubsub TamanduaServer.PubSub
  @topic "phishing_analysis"

  # ────────────────────────────────────────────────────────────────────
  # Structs
  # ────────────────────────────────────────────────────────────────────

  defmodule Report do
    @moduledoc "A complete phishing analysis report."
    defstruct [
      :id,
      :submitted_at,
      :completed_at,
      :verdict,
      :confidence,
      :score,
      :header_analysis,
      :url_analysis,
      :attachment_analysis,
      :sender_analysis,
      :content_analysis,
      :campaign,
      :iocs,
      :recommendations,
      :raw_headers,
      :subject,
      :from,
      :to,
      :message_id,
      :organization_id,
      :submitted_by
    ]
  end

  # ────────────────────────────────────────────────────────────────────
  # Client API
  # ────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit an email for phishing analysis.

  Accepts either raw EML content or a pre-parsed map with keys:
  `:headers`, `:body`, `:html_body`, `:attachments`, `:subject`,
  `:from`, `:to`, `:reply_to`, `:return_path`.

  Returns `{:ok, report}` or `{:error, reason}`.
  """
  @spec analyze(map()) :: {:ok, map()} | {:error, term()}
  def analyze(_email_data), do: {:error, :organization_required}

  @spec analyze_for_organization(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def analyze_for_organization(organization_id, email_data) do
    with {:ok, scoped_email} <- validate_email_scope(organization_id, email_data) do
      GenServer.call(__MODULE__, {:analyze, scoped_email}, 120_000)
    end
  end

  @doc """
  Retrieve a previously-generated analysis report by its ID.
  """
  @spec get_report(String.t(), String.t()) ::
          {:ok, map()} | {:error, :not_found | :organization_required}
  def get_report(organization_id, report_id) do
    with :ok <- require_organization(organization_id) do
      key = {organization_id, report_id}

      case :ets.lookup(@ets_submissions, key) do
        [{^key, report}] -> {:ok, report}
        [] -> {:error, :not_found}
      end
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  List detected phishing campaigns, optionally filtered by status.
  """
  @spec list_campaigns(String.t(), keyword()) :: {:ok, [map()]} | {:error, :organization_required}
  def list_campaigns(organization_id, opts \\ []) do
    with :ok <- require_organization(organization_id) do
      status_filter = Keyword.get(opts, :status)
      limit = Keyword.get(opts, :limit, 50) |> min(100) |> max(1)

      campaigns =
        :ets.tab2list(@ets_campaigns)
        |> Enum.flat_map(fn
          {{^organization_id, _id}, campaign} -> [campaign]
          _ -> []
        end)
        |> Enum.sort_by(& &1.last_seen, {:desc, DateTime})

      campaigns =
        if status_filter do
          Enum.filter(campaigns, &(&1.status == status_filter))
        else
          campaigns
        end

      {:ok, Enum.take(campaigns, limit)}
    end
  rescue
    ArgumentError -> {:ok, []}
  end

  @doc """
  Return aggregate statistics for the phishing engine.
  """
  @spec get_stats(String.t()) :: {:ok, map()} | {:error, :organization_required}
  def get_stats(organization_id) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:get_stats, organization_id})
    end
  end

  @doc """
  Simplified user-reported phishing submission.
  """
  @spec report_phish(map()) :: {:ok, map()} | {:error, term()}
  def report_phish(_params), do: {:error, :organization_required}

  @spec report_phish_for_organization(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def report_phish_for_organization(organization_id, params) do
    with {:ok, scoped_params} <- validate_email_scope(organization_id, params) do
      GenServer.call(__MODULE__, {:report_phish, scoped_params}, 120_000)
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # GenServer Callbacks
  # ────────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables
    ensure_ets_table(@ets_submissions, [:set, :public, :named_table, read_concurrency: true])
    ensure_ets_table(@ets_campaigns, [:set, :public, :named_table, read_concurrency: true])
    ensure_ets_table(@ets_sender_rep, [:set, :public, :named_table, read_concurrency: true])
    ensure_ets_table(@ets_brands, [:set, :public, :named_table, read_concurrency: true])

    # Seed brand domains into ETS for fast lookups
    seed_brand_domains()

    # Schedule periodic campaign sweep
    Process.send_after(self(), :sweep_campaigns, @campaign_sweep_interval)

    state = %{
      stats: %{
        total_analyzed: 0,
        verdicts: %{clean: 0, suspicious: 0, phishing: 0, spear_phishing: 0},
        avg_score: 0.0,
        campaigns_detected: 0,
        attachments_detonated: 0,
        urls_checked: 0,
        started_at: DateTime.utc_now()
      }
    }

    Logger.info("[Phishing] Analysis engine started (ETS tables initialized)")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze, email_data}, _from, state) do
    case do_analyze(email_data) do
      {:ok, report} ->
        new_state = update_stats(state, report)
        {:reply, {:ok, report}, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:get_stats, organization_id}, _from, state) do
    reports = tenant_reports(organization_id)
    campaigns = tenant_campaigns(organization_id)
    total = length(reports)
    verdicts = Enum.frequencies_by(reports, & &1.verdict)
    avg_score = if total == 0, do: 0.0, else: Enum.sum(Enum.map(reports, & &1.score)) / total

    reply = %{
      total_analyzed: total,
      verdicts: Map.merge(%{clean: 0, suspicious: 0, phishing: 0, spear_phishing: 0}, verdicts),
      avg_score: Float.round(avg_score, 2),
      campaigns_detected: Enum.count(campaigns, &(&1.status == "active")),
      attachments_detonated:
        Enum.sum(
          Enum.map(
            reports,
            &Enum.count(&1.attachment_analysis.attachments, fn a -> a.sandbox_submission_id end)
          )
        ),
      urls_checked: Enum.sum(Enum.map(reports, & &1.url_analysis.total_urls)),
      cached_submissions: total,
      active_campaigns: length(campaigns),
      uptime_seconds: DateTime.diff(DateTime.utc_now(), state.stats.started_at),
      started_at: state.stats.started_at
    }

    {:reply, {:ok, reply}, state}
  end

  @impl true
  def handle_call({:report_phish, params}, _from, state) do
    email_data = %{
      headers: params[:headers] || params["headers"] || %{},
      body: params[:body] || params["body"] || "",
      html_body: params[:html_body] || params["html_body"],
      subject: params[:subject] || params["subject"],
      from: params[:from] || params["from"],
      to: params[:to] || params["to"],
      attachments: params[:attachments] || params["attachments"] || [],
      reported_by: params[:reported_by] || params["reported_by"],
      organization_id: params[:organization_id],
      agent_id: params[:agent_id] || params["agent_id"]
    }

    case do_analyze(email_data) do
      {:ok, report} ->
        new_state = update_stats(state, report)
        {:reply, {:ok, report}, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_info(:sweep_campaigns, state) do
    sweep_campaigns()
    Process.send_after(self(), :sweep_campaigns, @campaign_sweep_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ────────────────────────────────────────────────────────────────────
  # Core Analysis Pipeline
  # ────────────────────────────────────────────────────────────────────

  defp do_analyze(email_data) do
    organization_id = email_data[:organization_id]
    report_id = generate_id()
    submitted_at = DateTime.utc_now()

    # Check dedup
    message_id = email_data[:message_id] || get_header_val(email_data, "message-id")

    if message_id && not is_nil(dedup_lookup(organization_id, message_id)) do
      {:ok, dedup_lookup(organization_id, message_id)}
    else
      with {:ok, parsed} <- parse_email(email_data),
           {:ok, header_result} <- analyze_headers(parsed),
           {:ok, url_result} <- analyze_urls(parsed),
           {:ok, attach_result} <- analyze_attachments(parsed),
           {:ok, sender_result} <- analyze_sender(parsed),
           {:ok, content_result} <- analyze_content(parsed) do
        # Compute weighted score (0-100)
        component_scores = %{
          headers: header_result.score,
          urls: url_result.score,
          attachments: attach_result.score,
          sender: sender_result.score,
          content: content_result.score
        }

        weighted_score = compute_weighted_score(component_scores)

        # Determine verdict
        {verdict, confidence} = determine_verdict(weighted_score, sender_result, content_result)

        # Extract IOCs
        iocs = extract_all_iocs(parsed, url_result, attach_result)

        # Campaign correlation
        campaign = correlate_campaign(parsed, url_result, attach_result, sender_result)

        # Build recommendations
        recommendations =
          build_recommendations(verdict, header_result, url_result, attach_result, sender_result)

        report = %{
          id: report_id,
          submitted_at: submitted_at,
          completed_at: DateTime.utc_now(),
          verdict: verdict,
          confidence: confidence,
          score: weighted_score,
          component_scores: component_scores,
          header_analysis: header_result,
          url_analysis: url_result,
          attachment_analysis: attach_result,
          sender_analysis: sender_result,
          content_analysis: content_result,
          campaign: campaign,
          iocs: iocs,
          recommendations: recommendations,
          subject: parsed.subject,
          from: parsed.from,
          to: parsed.to,
          message_id: parsed.message_id,
          organization_id: organization_id,
          submitted_by: email_data[:reported_by]
        }

        # Store in ETS
        :ets.insert(@ets_submissions, {{organization_id, report_id}, report})

        if message_id do
          :ets.insert(@ets_submissions, {{:dedup, organization_id, message_id}, report})
        end

        # Create alert for non-clean verdicts
        maybe_create_alert(report, email_data)

        # Broadcast via PubSub
        broadcast_analysis(report)

        {:ok, report}
      end
    end
  rescue
    e ->
      Logger.error("[Phishing] Analysis failed: #{Exception.message(e)}")
      {:error, :analysis_failed}
  end

  # ────────────────────────────────────────────────────────────────────
  # Email Parsing
  # ────────────────────────────────────────────────────────────────────

  defp parse_email(data) do
    headers =
      cond do
        is_map(data[:headers]) and map_size(data[:headers]) > 0 ->
          normalize_headers(data[:headers])

        is_binary(data[:raw_content]) ->
          parse_raw_headers(data[:raw_content])

        true ->
          %{}
      end

    {:ok,
     %{
       headers: headers,
       body: data[:body] || "",
       html_body: data[:html_body],
       attachments: data[:attachments] || [],
       subject: data[:subject] || Map.get(headers, "subject", ""),
       from: data[:from] || Map.get(headers, "from", ""),
       to: data[:to] || Map.get(headers, "to", ""),
       reply_to: data[:reply_to] || Map.get(headers, "reply-to"),
       return_path: data[:return_path] || Map.get(headers, "return-path"),
       received: get_multi_header(headers, "received"),
       message_id: data[:message_id] || Map.get(headers, "message-id"),
       date: Map.get(headers, "date"),
       x_mailer: Map.get(headers, "x-mailer"),
       authentication_results: Map.get(headers, "authentication-results", ""),
       received_spf: Map.get(headers, "received-spf", ""),
       dkim_signature: Map.get(headers, "dkim-signature"),
       organization_id: authoritative_email_organization_id(data),
       raw: data[:raw_content]
     }}
  end

  defp normalize_headers(headers) do
    Enum.into(headers, %{}, fn {k, v} -> {String.downcase(to_string(k)), v} end)
  end

  defp parse_raw_headers(raw) when is_binary(raw) do
    raw
    |> String.split(~r/\r?\n\r?\n/, parts: 2)
    |> List.first("")
    |> String.split(~r/\r?\n(?!\s)/)
    |> Enum.map(&parse_header_line/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.into(%{})
  end

  defp parse_header_line(line) do
    case String.split(line, ":", parts: 2) do
      [key, value] -> {String.downcase(String.trim(key)), String.trim(value)}
      _ -> nil
    end
  end

  defp get_multi_header(headers, key) do
    case Map.get(headers, key) do
      nil -> []
      val when is_list(val) -> val
      val -> [val]
    end
  end

  defp get_header_val(data, key) do
    headers = data[:headers] || %{}
    Map.get(headers, key) || Map.get(headers, String.downcase(key))
  end

  defp authoritative_email_organization_id(data) do
    agent_id = data[:agent_id] || data["agent_id"]
    claimed = data[:organization_id] || data["organization_id"]

    if is_binary(agent_id) and agent_id != "" do
      authoritative = TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)

      if is_binary(authoritative) and authoritative != "" and
           (is_nil(claimed) or claimed == authoritative) do
        authoritative
      else
        nil
      end
    else
      if is_binary(claimed) and claimed != "", do: claimed, else: nil
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # Header Analysis
  # ────────────────────────────────────────────────────────────────────

  defp analyze_headers(parsed) do
    findings = []

    # SPF Verification
    {spf_result, findings} = check_spf(parsed, findings)

    # DKIM Verification
    {dkim_result, findings} = check_dkim(parsed, findings)

    # DMARC Verification
    {dmarc_result, findings} = check_dmarc(parsed, findings)

    # Received chain analysis
    findings = analyze_received_chain(parsed.received, findings)

    # Reply-To vs From mismatch
    findings = check_reply_to_mismatch(parsed, findings)

    # X-Mailer fingerprinting
    findings = check_x_mailer(parsed, findings)

    # Missing / malformed Message-ID
    findings = check_message_id(parsed, findings)

    score = compute_findings_score(findings, 100)

    {:ok,
     %{
       score: score,
       findings: findings,
       spf: spf_result,
       dkim: dkim_result,
       dmarc: dmarc_result,
       received_hops: length(parsed.received)
     }}
  end

  defp check_spf(parsed, findings) do
    spf_header = parsed.received_spf
    auth_header = parsed.authentication_results

    spf_result =
      extract_auth_mechanism(auth_header, "spf") ||
        extract_spf_from_header(spf_header)

    findings =
      case spf_result do
        "fail" ->
          [{:spf_fail, "SPF authentication failed -- sender not authorized", 40} | findings]

        "softfail" ->
          [{:spf_softfail, "SPF soft failure -- sender weakly unauthorized", 20} | findings]

        "none" ->
          [{:spf_none, "No SPF record published for sender domain", 10} | findings]

        nil ->
          [{:spf_missing, "SPF verification result not found in headers", 10} | findings]

        _ ->
          findings
      end

    {spf_result || "unknown", findings}
  end

  defp check_dkim(parsed, findings) do
    auth_header = parsed.authentication_results
    dkim_result = extract_auth_mechanism(auth_header, "dkim")

    has_dkim_sig = not is_nil(parsed.dkim_signature)

    findings =
      cond do
        dkim_result == "fail" ->
          [{:dkim_fail, "DKIM signature verification failed", 40} | findings]

        not has_dkim_sig and is_nil(dkim_result) ->
          [{:dkim_missing, "No DKIM signature present on this message", 15} | findings]

        dkim_result == "none" ->
          [{:dkim_none, "DKIM check returned none", 10} | findings]

        true ->
          findings
      end

    {dkim_result || if(has_dkim_sig, do: "present", else: "missing"), findings}
  end

  defp check_dmarc(parsed, findings) do
    auth_header = parsed.authentication_results
    dmarc_result = extract_auth_mechanism(auth_header, "dmarc")

    findings =
      case dmarc_result do
        "fail" ->
          [{:dmarc_fail, "DMARC policy check failed -- possible spoofing", 50} | findings]

        nil ->
          [{:dmarc_missing, "No DMARC result found in authentication headers", 10} | findings]

        "none" ->
          [{:dmarc_none, "Sender domain has no DMARC policy", 10} | findings]

        _ ->
          findings
      end

    {dmarc_result || "unknown", findings}
  end

  defp analyze_received_chain([], findings) do
    [{:no_received, "No Received headers found -- message origin unknown", 30} | findings]
  end

  defp analyze_received_chain(received_headers, findings) do
    # Detect unusual hops
    suspicious_hops =
      Enum.count(received_headers, fn header ->
        h = String.downcase(to_string(header))

        String.contains?(h, "localhost") or
          String.contains?(h, "127.0.0.1") or
          String.contains?(h, "unknown") or
          String.contains?(h, "[10.") or
          String.contains?(h, "[192.168.")
      end)

    findings =
      if suspicious_hops > 0 do
        [
          {:suspicious_received, "#{suspicious_hops} suspicious hop(s) in Received chain", 15}
          | findings
        ]
      else
        findings
      end

    # Detect large hop counts (possible relay chains)
    findings =
      if length(received_headers) > 8 do
        [
          {:many_hops, "Unusually large number of mail relays (#{length(received_headers)})", 10}
          | findings
        ]
      else
        findings
      end

    # Detect time anomalies (timestamps going backward)
    findings = detect_time_anomalies(received_headers, findings)

    findings
  end

  defp detect_time_anomalies(received_headers, findings) do
    timestamps =
      received_headers
      |> Enum.map(fn h ->
        case Regex.run(~r/;\s*(.+)$/, to_string(h)) do
          [_, ts] -> String.trim(ts)
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    if length(timestamps) >= 2 do
      # Very basic: just flag if there are timestamps that look anomalous
      findings
    else
      findings
    end
  end

  defp check_reply_to_mismatch(parsed, findings) do
    from_domain = extract_domain(parsed.from)
    reply_to_domain = extract_domain(parsed.reply_to)

    if reply_to_domain && from_domain && reply_to_domain != from_domain do
      [
        {:reply_to_mismatch,
         "Reply-To domain (#{reply_to_domain}) differs from From domain (#{from_domain})", 30}
        | findings
      ]
    else
      findings
    end
  end

  defp check_x_mailer(parsed, findings) do
    x_mailer = parsed.x_mailer || ""
    x_mailer_lower = String.downcase(x_mailer)

    match =
      Enum.find(@suspicious_mailers, fn tool ->
        String.contains?(x_mailer_lower, String.downcase(tool))
      end)

    if match do
      [
        {:suspicious_mailer, "X-Mailer header matches known phishing tool: #{match}", 50}
        | findings
      ]
    else
      findings
    end
  end

  defp check_message_id(parsed, findings) do
    mid = parsed.message_id

    cond do
      is_nil(mid) or mid == "" ->
        [{:no_message_id, "Missing Message-ID header", 15} | findings]

      not String.contains?(mid, "@") ->
        [{:malformed_message_id, "Message-ID is malformed (no @ sign)", 15} | findings]

      true ->
        findings
    end
  end

  defp extract_auth_mechanism(header, mechanism) when is_binary(header) do
    case Regex.run(~r/#{Regex.escape(mechanism)}=(\w+)/i, header) do
      [_, result] -> String.downcase(result)
      nil -> nil
    end
  end

  defp extract_auth_mechanism(_, _), do: nil

  defp extract_spf_from_header(nil), do: nil
  defp extract_spf_from_header(""), do: nil

  defp extract_spf_from_header(header) do
    h = String.downcase(header)

    cond do
      String.starts_with?(h, "pass") -> "pass"
      String.starts_with?(h, "fail") -> "fail"
      String.starts_with?(h, "softfail") -> "softfail"
      String.starts_with?(h, "neutral") -> "neutral"
      String.starts_with?(h, "none") -> "none"
      true -> nil
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # URL Analysis
  # ────────────────────────────────────────────────────────────────────

  defp analyze_urls(parsed) do
    body_urls = extract_urls(parsed.body)
    html_urls = extract_urls(parsed.html_body || "")
    all_urls = Enum.uniq(body_urls ++ html_urls)

    url_results = Enum.map(all_urls, &analyze_single_url(&1, parsed.organization_id))

    max_score =
      if Enum.empty?(url_results) do
        0
      else
        url_results |> Enum.map(& &1.score) |> Enum.max()
      end

    shorteners_found = Enum.count(url_results, & &1.is_shortener)
    homograph_found = Enum.count(url_results, & &1.homograph_detected)
    malicious_found = Enum.count(url_results, & &1.ioc_match)

    {:ok,
     %{
       score: max_score,
       total_urls: length(all_urls),
       urls: url_results,
       shorteners_found: shorteners_found,
       homograph_attacks: homograph_found,
       malicious_urls: malicious_found
     }}
  end

  defp analyze_single_url(url, organization_id) do
    uri = URI.parse(url)
    host = uri.host || ""
    host_lower = String.downcase(host)
    findings = []
    score = 0

    # Shortener detection
    is_shortener = host_lower in @url_shorteners

    {findings, score} =
      if is_shortener do
        {[{:shortener, "URL shortener detected: #{host_lower}"} | findings], score + 25}
      else
        {findings, score}
      end

    # Homograph / IDN detection
    homograph = detect_homograph(host)

    {findings, score} =
      if homograph.detected do
        {[{:homograph, homograph.description} | findings], score + 50}
      else
        {findings, score}
      end

    # Typosquatting
    typosquat = detect_typosquatting(host_lower)

    {findings, score} =
      if typosquat.detected do
        {[{:typosquat, typosquat.description} | findings], score + 40}
      else
        {findings, score}
      end

    # Suspicious TLD
    tld = extract_tld(host_lower)

    {findings, score} =
      if tld in @suspicious_tlds do
        {[{:suspicious_tld, "High-risk TLD: #{tld}"} | findings], score + 25}
      else
        {findings, score}
      end

    # IP address URL
    {findings, score} =
      if ip_address?(host) do
        {[{:ip_url, "URL uses raw IP address instead of domain"} | findings], score + 35}
      else
        {findings, score}
      end

    # IOC reputation lookup
    ioc_match = ioc_match?(url, host_lower, organization_id)

    {findings, score} =
      if ioc_match do
        {[{:known_malicious, "URL or domain matches known IOC"} | findings], score + 80}
      else
        {findings, score}
      end

    # Suspicious path keywords
    path = uri.path || ""
    {findings, score} = check_url_path(path, findings, score)

    %{
      url: url,
      host: host_lower,
      tld: tld,
      score: min(100, score),
      findings: findings,
      is_shortener: is_shortener,
      homograph_detected: homograph.detected,
      typosquat_detected: typosquat.detected,
      ioc_match: ioc_match,
      defanged: defang_url(url)
    }
  end

  defp check_url_path(path, findings, score) do
    path_lower = String.downcase(path)

    cond do
      Regex.match?(~r/\.(exe|scr|bat|ps1|vbs|dll|msi)$/i, path) ->
        {[{:executable_download, "URL path points to executable file"} | findings], score + 45}

      Regex.match?(~r/(login|signin|verify|account|secure|update|confirm|password)/i, path_lower) ->
        {[{:credential_path, "URL path contains credential-harvesting keywords"} | findings],
         score + 20}

      true ->
        {findings, score}
    end
  end

  defp detect_homograph(host) do
    # Check for non-ASCII characters that look like Latin letters
    chars = String.to_charlist(host)

    has_mixed_scripts =
      Enum.any?(chars, fn c -> c > 127 end) and
        Enum.any?(chars, fn c -> c >= ?a and c <= ?z end)

    has_confusables =
      Enum.any?(chars, fn char ->
        Enum.any?(@homoglyphs, fn {_latin, lookalikes} ->
          char in lookalikes
        end)
      end)

    cond do
      has_mixed_scripts ->
        %{
          detected: true,
          type: :mixed_script,
          description: "Domain contains mixed Unicode scripts (IDN homograph attack)"
        }

      has_confusables ->
        %{
          detected: true,
          type: :confusable,
          description: "Domain contains characters confusable with Latin letters"
        }

      true ->
        %{detected: false, type: nil, description: nil}
    end
  end

  defp detect_typosquatting(domain) do
    domain_base = domain |> String.split(".") |> List.first() || domain

    match =
      Enum.find_value(@brand_domains, fn {brand, legit_domains} ->
        Enum.find(legit_domains, fn legit ->
          legit_base = legit |> String.split(".") |> List.first()
          dist = levenshtein(domain_base, legit_base)

          if dist > 0 and dist <= 2 and domain != legit do
            {brand, legit, dist}
          end
        end)
      end)

    if match do
      {brand, legit, dist} = match

      %{
        detected: true,
        brand: brand,
        legitimate: legit,
        distance: dist,
        description: "Domain '#{domain}' is #{dist} edit(s) from #{legit} (#{brand})"
      }
    else
      %{detected: false, brand: nil, description: nil}
    end
  end

  defp extract_urls(nil), do: []

  defp extract_urls(text) when is_binary(text) do
    url_regex = ~r/https?:\/\/[^\s<>"'\)\]]+/i
    href_regex = ~r/href=["']([^"']+)["']/i

    direct = Regex.scan(url_regex, text) |> Enum.map(&List.first/1)
    hrefs = Regex.scan(href_regex, text) |> Enum.map(&List.last/1)

    (direct ++ hrefs)
    |> Enum.uniq()
    |> Enum.filter(&(String.starts_with?(&1, "http://") or String.starts_with?(&1, "https://")))
  end

  defp extract_tld(host) do
    parts = String.split(host, ".")
    if length(parts) >= 2, do: "." <> List.last(parts), else: ""
  end

  defp ip_address?(host) do
    case :inet.parse_address(String.to_charlist(host || "")) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp ioc_match?(url, host, organization_id) do
    IOCs.match_for_organization(url, "url", organization_id) ||
      IOCs.match_for_organization(host, "domain", organization_id)
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  @doc "Defang a URL for safe display."
  def defang_url(url) do
    url
    |> String.replace("http://", "hxxp://")
    |> String.replace("https://", "hxxps://")
    |> String.replace(".", "[.]")
  end

  # ────────────────────────────────────────────────────────────────────
  # Attachment Analysis
  # ────────────────────────────────────────────────────────────────────

  defp analyze_attachments(%{attachments: []}), do: {:ok, %{score: 0, total: 0, attachments: []}}

  defp analyze_attachments(parsed) do
    results = Enum.map(parsed.attachments, &analyze_single_attachment(&1, parsed.organization_id))

    max_score =
      if Enum.empty?(results) do
        0
      else
        results |> Enum.map(& &1.score) |> Enum.max()
      end

    {:ok,
     %{
       score: max_score,
       total: length(results),
       attachments: results
     }}
  end

  defp analyze_single_attachment(att, organization_id) do
    filename = att[:filename] || "unknown"
    ext = Path.extname(filename) |> String.downcase()
    content_type = att[:content_type] || "application/octet-stream"
    size = att[:size] || 0
    content = att[:content] || att[:content_bytes]

    findings = []
    score = 0

    # Magic byte identification
    {detected_type, findings, score} = check_magic_bytes(content, findings, score)

    # Double extension detection
    {findings, score} =
      if double_extension?(filename) do
        {[{:double_extension, "Double extension detected: #{filename}"} | findings], score + 55}
      else
        {findings, score}
      end

    # Dangerous extension
    {findings, score} =
      if ext in @dangerous_extensions do
        {[{:dangerous_ext, "Dangerous file extension: #{ext}"} | findings], score + 60}
      else
        {findings, score}
      end

    # Macro-enabled document
    {findings, score} =
      if ext in @macro_extensions do
        {[{:macro_enabled, "Macro-enabled document: #{ext}"} | findings], score + 45}
      else
        {findings, score}
      end

    # Macro detection via content (simplified OLE check)
    {findings, score} = detect_macro_content(content, ext, findings, score)

    # Content-type vs extension mismatch
    {findings, score} =
      if detected_type && content_type_mismatch?(ext, detected_type) do
        {[{:type_mismatch, "File magic bytes do not match extension"} | findings], score + 35}
      else
        {findings, score}
      end

    # Hash lookup
    hashes = compute_hashes(content)
    {findings, score} = check_hash_iocs(hashes, findings, score, organization_id)

    # Password-protected archive detection
    {findings, score} =
      if ext in @archive_extensions and password_protected?(content) do
        {[{:password_archive, "Password-protected archive detected"} | findings], score + 35}
      else
        {findings, score}
      end

    # Auto-submit to sandbox for high-risk attachments
    sandbox_id = maybe_submit_to_sandbox(att, hashes, score)

    %{
      filename: filename,
      extension: ext,
      content_type: content_type,
      detected_type: detected_type,
      size: size,
      score: min(100, score),
      findings: findings,
      hashes: hashes,
      sandbox_submission_id: sandbox_id
    }
  end

  defp check_magic_bytes(nil, findings, score), do: {nil, findings, score}

  defp check_magic_bytes(content, findings, score) when byte_size(content) < 2,
    do: {nil, findings, score}

  defp check_magic_bytes(content, findings, score) do
    detected =
      Enum.find_value(@magic_bytes, fn {magic, type} ->
        if binary_part_safe(content, 0, byte_size(magic)) == magic, do: type
      end)

    if detected == "application/x-dosexec" do
      {detected, [{:pe_executable, "File contains PE executable magic bytes"} | findings],
       score + 50}
    else
      {detected, findings, score}
    end
  end

  defp binary_part_safe(bin, start, len) when byte_size(bin) >= start + len do
    binary_part(bin, start, len)
  end

  defp binary_part_safe(_, _, _), do: <<>>

  defp detect_macro_content(nil, _, findings, score), do: {findings, score}

  defp detect_macro_content(content, ext, findings, score) do
    has_vba_marker =
      is_binary(content) and
        (String.contains?(content, "VBA") or
           String.contains?(content, "\\x00V\\x00B\\x00A") or
           String.contains?(content, "Attribute VB_"))

    if has_vba_marker and ext not in @macro_extensions do
      {[{:hidden_macro, "VBA macro indicators found in non-macro file type"} | findings],
       score + 40}
    else
      {findings, score}
    end
  end

  defp double_extension?(filename) do
    parts = String.split(filename, ".")

    if length(parts) > 2 do
      last = List.last(parts)
      String.downcase("." <> last) in @dangerous_extensions
    else
      false
    end
  end

  defp content_type_mismatch?(ext, detected_type) do
    expected = %{
      ".pdf" => "application/pdf",
      ".zip" => "application/zip",
      ".doc" => "application/x-ole-storage",
      ".docx" => "application/zip",
      ".xls" => "application/x-ole-storage",
      ".xlsx" => "application/zip"
    }

    case Map.get(expected, ext) do
      nil -> false
      exp -> exp != detected_type
    end
  end

  defp compute_hashes(nil), do: %{}

  defp compute_hashes(content) when is_binary(content) do
    %{
      md5: :crypto.hash(:md5, content) |> Base.encode16(case: :lower),
      sha1: :crypto.hash(:sha, content) |> Base.encode16(case: :lower),
      sha256: :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
    }
  end

  defp compute_hashes(_), do: %{}

  defp check_hash_iocs(hashes, findings, score, _organization_id) when map_size(hashes) == 0,
    do: {findings, score}

  defp check_hash_iocs(hashes, findings, score, organization_id) do
    match_found =
      Enum.any?([:sha256, :sha1, :md5], fn algo ->
        hash = Map.get(hashes, algo)
        hash && ioc_hash_match?(hash, algo, organization_id)
      end)

    if match_found do
      {[{:known_malicious_hash, "Attachment hash matches known malicious IOC"} | findings],
       score + 90}
    else
      {findings, score}
    end
  end

  defp ioc_hash_match?(hash, algo, organization_id) do
    IOCs.match_for_organization(hash, "hash_#{algo}", organization_id)
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  defp password_protected?(nil), do: false

  defp password_protected?(content) when is_binary(content) do
    # ZIP: general purpose bit flag byte with bit 0 set for encryption
    case content do
      <<0x50, 0x4B, 0x03, 0x04, _::binary-size(2), flags::little-16, _::binary>> ->
        Bitwise.band(flags, 0x01) == 1

      _ ->
        false
    end
  end

  defp password_protected?(_), do: false

  defp maybe_submit_to_sandbox(att, hashes, score) when score >= 40 do
    sha256 = hashes[:sha256]
    content = att[:content] || att[:content_bytes]

    if sha256 && content do
      try do
        case Sandbox.submit(content, %{
               sha256: sha256,
               filename: att[:filename],
               source: "phishing_analysis",
               content_type: att[:content_type]
             }) do
          {:ok, submission} -> submission[:submission_id]
          _ -> nil
        end
      rescue
        _ -> nil
      catch
        :exit, _ -> nil
      end
    else
      nil
    end
  end

  defp maybe_submit_to_sandbox(_, _, _), do: nil

  # ────────────────────────────────────────────────────────────────────
  # Sender Analysis
  # ────────────────────────────────────────────────────────────────────

  defp analyze_sender(parsed) do
    from = parsed.from || ""
    email_addr = extract_email_addr(from)
    domain = extract_domain(email_addr)
    display_name = extract_display_name(from)

    findings = []
    score = 0

    # Sender reputation from cache
    rep = get_sender_reputation(parsed.organization_id, email_addr)

    {findings, score} =
      case rep do
        %{malicious_ratio: r} when r > 0.5 ->
          {[
             {:bad_reputation,
              "Sender has high malicious email ratio (#{Float.round(r * 100, 1)}%)"}
             | findings
           ], score + 50}

        %{first_time: true} ->
          {[{:first_time_sender, "First-time sender -- no prior history"} | findings], score + 15}

        _ ->
          {findings, score}
      end

    # Display name spoofing
    {findings, score} =
      if display_name && String.contains?(display_name, "@") do
        {[
           {:display_name_email, "Display name contains an email address (spoofing indicator)"}
           | findings
         ], score + 35}
      else
        {findings, score}
      end

    # BEC pattern detection
    {findings, score} = detect_bec_patterns(display_name, parsed.subject, findings, score)

    # Executive impersonation
    {findings, score} = detect_executive_impersonation(display_name, email_addr, findings, score)

    # Reply-To / Return-Path domain mismatch (also in headers, but scored here for sender)
    return_domain = extract_domain(parsed.return_path)

    {findings, score} =
      if return_domain && domain && return_domain != domain do
        {[
           {:return_path_mismatch, "Return-Path domain (#{return_domain}) differs from sender"}
           | findings
         ], score + 25}
      else
        {findings, score}
      end

    # Domain typosquatting
    typo = detect_typosquatting(domain || "")

    {findings, score} =
      if typo.detected do
        {[{:sender_typosquat, typo.description} | findings], score + 40}
      else
        {findings, score}
      end

    # Update sender reputation cache
    update_sender_reputation(parsed.organization_id, email_addr)

    {:ok,
     %{
       score: min(100, score),
       findings: findings,
       email: email_addr,
       domain: domain,
       display_name: display_name,
       reputation: rep,
       typosquat: typo
     }}
  end

  defp detect_bec_patterns(display_name, subject, findings, score) do
    subject_lower = String.downcase(subject || "")
    name_lower = String.downcase(display_name || "")

    bec_subject_patterns = [
      ~r/wire\s*transfer/i,
      ~r/urgent\s*(payment|transfer|request)/i,
      ~r/invoice\s*(#|number|payment)/i,
      ~r/change\s*(bank|account|routing)/i,
      ~r/confidential/i,
      ~r/w-?2|tax\s*form/i,
      ~r/gift\s*card/i
    ]

    bec_name_patterns = [
      ~r/^(ceo|cfo|cto|coo|president|director|vp|vice\s*president)/i
    ]

    subject_match = Enum.any?(bec_subject_patterns, &Regex.match?(&1, subject_lower))
    name_match = Enum.any?(bec_name_patterns, &Regex.match?(&1, name_lower))

    cond do
      subject_match and name_match ->
        {[
           {:bec_pattern,
            "Business Email Compromise pattern: executive title + financial subject"}
           | findings
         ], score + 50}

      subject_match ->
        {[{:bec_subject, "Subject line matches BEC pattern"} | findings], score + 20}

      name_match ->
        {[{:executive_title, "Display name contains executive title"} | findings], score + 10}

      true ->
        {findings, score}
    end
  end

  defp detect_executive_impersonation(display_name, _email_addr, findings, score) do
    # Check fuzzy match against known internal names (if configured)
    known_executives = Application.get_env(:tamandua_server, :known_executives, [])

    if display_name && length(known_executives) > 0 do
      name_lower = String.downcase(display_name)

      match =
        Enum.find(known_executives, fn exec_name ->
          exec_lower = String.downcase(exec_name)
          levenshtein(name_lower, exec_lower) <= 2 and name_lower != exec_lower
        end)

      if match do
        {[
           {:executive_impersonation, "Display name closely resembles known executive: #{match}"}
           | findings
         ], score + 55}
      else
        {findings, score}
      end
    else
      {findings, score}
    end
  end

  defp extract_email_addr(nil), do: nil

  defp extract_email_addr(from) do
    case Regex.run(~r/<([^>]+)>/, from) do
      [_, addr] ->
        String.downcase(String.trim(addr))

      nil ->
        trimmed = String.trim(from)
        if String.contains?(trimmed, "@"), do: String.downcase(trimmed), else: nil
    end
  end

  defp extract_display_name(nil), do: nil

  defp extract_display_name(from) do
    case Regex.run(~r/^([^<]+)</, from) do
      [_, name] -> String.trim(name) |> String.replace(~r/^["']|["']$/, "")
      nil -> nil
    end
  end

  defp extract_domain(nil), do: nil

  defp extract_domain(addr) do
    clean = String.trim(to_string(addr))
    # Handle <addr> format
    clean =
      case Regex.run(~r/<([^>]+)>/, clean) do
        [_, inner] -> inner
        nil -> clean
      end

    case String.split(clean, "@") do
      [_, domain] -> String.downcase(String.trim(domain))
      _ -> nil
    end
  end

  defp get_sender_reputation(_organization_id, nil),
    do: %{first_time: true, malicious_ratio: 0.0}

  defp get_sender_reputation(organization_id, email) do
    key = {organization_id, email}

    case :ets.lookup(@ets_sender_rep, key) do
      [{^key, rep}] ->
        # Check TTL
        age = DateTime.diff(DateTime.utc_now(), rep.updated_at)

        if age > @sender_rep_ttl_seconds do
          %{first_time: true, malicious_ratio: 0.0}
        else
          rep
        end

      [] ->
        %{first_time: true, malicious_ratio: 0.0}
    end
  rescue
    _ -> %{first_time: true, malicious_ratio: 0.0}
  end

  defp update_sender_reputation(_organization_id, nil), do: :ok

  defp update_sender_reputation(organization_id, email) do
    now = DateTime.utc_now()
    key = {organization_id, email}

    case :ets.lookup(@ets_sender_rep, key) do
      [{^key, existing}] ->
        updated = %{existing | total_seen: existing.total_seen + 1, updated_at: now}
        :ets.insert(@ets_sender_rep, {key, updated})

      [] ->
        rep = %{
          email: email,
          total_seen: 1,
          malicious_count: 0,
          suspicious_count: 0,
          clean_count: 0,
          first_seen: now,
          updated_at: now,
          first_time: false,
          malicious_ratio: 0.0
        }

        :ets.insert(@ets_sender_rep, {key, rep})
    end

    :ok
  rescue
    _ -> :ok
  end

  # ────────────────────────────────────────────────────────────────────
  # Content Analysis
  # ────────────────────────────────────────────────────────────────────

  defp analyze_content(parsed) do
    body = (parsed.body || "") <> " " <> (parsed.html_body || "")
    findings = []
    score = 0

    # Urgency / pressure language
    urgency_patterns = [
      {~r/urgent|immediate|action\s+required|act\s+now|limited\s+time/i, 15},
      {~r/your\s+account.*(suspend|terminat|clos|lock|restrict)/i, 20},
      {~r/(verify|confirm)\s+(your\s+)?(identity|account|information)/i, 20},
      {~r/click\s+(here|below|this\s+link|the\s+link|the\s+button)/i, 15}
    ]

    {findings, score} =
      Enum.reduce(urgency_patterns, {findings, score}, fn {pattern, pts}, {f, s} ->
        if Regex.match?(pattern, body) do
          {[{:urgency, "Urgency / pressure language detected"} | f], s + pts}
        else
          {f, s}
        end
      end)

    # Credential harvesting language
    {findings, score} =
      if Regex.match?(
           ~r/password|credential|login|username|ssn|social\s*security|bank\s*account/i,
           body
         ) do
        {[{:credential_request, "Request for sensitive information detected"} | findings],
         score + 25}
      else
        {findings, score}
      end

    # Generic greeting
    {findings, score} =
      if Regex.match?(~r/^(dear\s+(customer|user|member|sir|madam|valued)|hello,?\s*$)/im, body) do
        {[{:generic_greeting, "Generic greeting used instead of personal name"} | findings],
         score + 10}
      else
        {findings, score}
      end

    # Hidden text in HTML
    {findings, score} =
      if parsed.html_body && hidden_text?(parsed.html_body) do
        {[{:hidden_text, "Hidden text detected in HTML email body"} | findings], score + 30}
      else
        {findings, score}
      end

    # Embedded form in HTML
    {findings, score} =
      if parsed.html_body && String.contains?(parsed.html_body, "<form") do
        {[{:embedded_form, "Embedded HTML form detected in email body"} | findings], score + 35}
      else
        {findings, score}
      end

    # Base64-encoded suspicious content
    {findings, score} =
      if Regex.match?(~r/data:application\/(octet-stream|javascript)/i, body) do
        {[{:data_uri, "Suspicious data URI detected in email content"} | findings], score + 40}
      else
        {findings, score}
      end

    {:ok,
     %{
       score: min(100, score),
       findings: findings
     }}
  end

  defp hidden_text?(html) do
    patterns = [
      ~r/display:\s*none/i,
      ~r/visibility:\s*hidden/i,
      ~r/font-size:\s*0/i,
      ~r/color:\s*(white|#fff|#ffffff|rgba\(.*,\s*0\))/i,
      ~r/height:\s*0/i,
      ~r/opacity:\s*0/i
    ]

    Enum.any?(patterns, &Regex.match?(&1, html))
  end

  # ────────────────────────────────────────────────────────────────────
  # IOC Extraction
  # ────────────────────────────────────────────────────────────────────

  defp extract_all_iocs(parsed, url_result, attach_result) do
    body = (parsed.body || "") <> " " <> (parsed.html_body || "")

    urls = Enum.map(url_result.urls, & &1.url)

    domains =
      urls
      |> Enum.map(fn u -> URI.parse(u).host end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    emails = extract_email_addresses(body)
    ips = extract_ip_addresses(body)

    hashes =
      attach_result.attachments
      |> Enum.flat_map(fn att ->
        h = att.hashes
        Enum.reject([h[:md5], h[:sha1], h[:sha256]], &is_nil/1)
      end)

    sender_email = extract_email_addr(parsed.from)
    sender_domain = extract_domain(parsed.from)

    %{
      urls: urls,
      domains: Enum.uniq(domains ++ List.wrap(sender_domain)),
      email_addresses: Enum.uniq(emails ++ List.wrap(sender_email)),
      ip_addresses: ips,
      file_hashes: hashes
    }
  end

  defp extract_email_addresses(text) do
    Regex.scan(~r/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/i, text)
    |> Enum.map(&List.first/1)
    |> Enum.uniq()
  end

  defp extract_ip_addresses(text) do
    Regex.scan(~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/, text)
    |> Enum.map(&List.first/1)
    |> Enum.filter(&valid_ip?/1)
    |> Enum.uniq()
  end

  defp valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # Verdict Determination
  # ────────────────────────────────────────────────────────────────────

  defp compute_weighted_score(components) do
    Enum.reduce(@weights, 0.0, fn {key, weight}, acc ->
      component_score = Map.get(components, key, 0)
      acc + component_score * (weight / 100)
    end)
    |> Float.round(1)
  end

  defp determine_verdict(score, sender_result, _content_result) do
    # Spear-phishing: high score + BEC or executive impersonation indicators
    is_targeted =
      Enum.any?(sender_result.findings, fn {type, _, _pts} ->
        type in [:bec_pattern, :executive_impersonation]
      end) or
        Enum.any?(sender_result.findings, fn {type, _desc} ->
          type in [:bec_pattern, :executive_impersonation]
        end)

    cond do
      score >= @spear_phishing_threshold and is_targeted ->
        {:spear_phishing, min(99, round(score + 10))}

      score >= @phishing_threshold ->
        {:phishing, min(99, round(score))}

      score >= @suspicious_threshold ->
        {:suspicious, round(score)}

      true ->
        {:clean, max(1, round(100 - score))}
    end
  rescue
    _ -> {:suspicious, 50}
  end

  defp compute_findings_score(findings, max_score) do
    total =
      Enum.reduce(findings, 0, fn
        {_type, _desc, points}, acc -> acc + points
        _, acc -> acc
      end)

    min(total, max_score)
  end

  # ────────────────────────────────────────────────────────────────────
  # Campaign Correlation
  # ────────────────────────────────────────────────────────────────────

  defp correlate_campaign(parsed, url_result, attach_result, sender_result) do
    sender_domain = sender_result.domain
    url_hosts = Enum.map(url_result.urls, & &1.host) |> Enum.uniq()

    attach_hashes =
      attach_result.attachments
      |> Enum.map(& &1.hashes[:sha256])
      |> Enum.reject(&is_nil/1)

    subject = parsed.subject || ""

    # Build a fingerprint for this email
    fingerprint = %{
      organization_id: parsed.organization_id,
      sender_domain: sender_domain,
      url_hosts: url_hosts,
      attach_hashes: attach_hashes,
      subject_hash: :crypto.hash(:md5, String.downcase(subject)) |> Base.encode16(case: :lower),
      timestamp: DateTime.utc_now()
    }

    # Find or create campaign cluster
    campaign = find_matching_campaign(fingerprint)

    if campaign do
      update_campaign(parsed.organization_id, campaign.id, fingerprint)

      %{
        campaign_id: campaign.id,
        name: campaign.name,
        email_count: campaign.email_count + 1,
        first_seen: campaign.first_seen,
        last_seen: DateTime.utc_now(),
        status: campaign.status
      }
    else
      # Create new pending campaign entry
      register_campaign_candidate(fingerprint)
      nil
    end
  rescue
    _ -> nil
  end

  defp find_matching_campaign(fingerprint) do
    cutoff = DateTime.add(DateTime.utc_now(), -@campaign_cluster_window_hours * 3600, :second)

    :ets.tab2list(@ets_campaigns)
    |> Enum.find(fn
      {{organization_id, _id}, campaign} ->
        organization_id == fingerprint.organization_id and
          campaign.status in ["active", "pending"] and
          DateTime.compare(campaign.last_seen, cutoff) != :lt and
          campaign_matches?(campaign, fingerprint)

      _ ->
        false
    end)
    |> case do
      {{_organization_id, _id}, campaign} -> campaign
      nil -> nil
    end
  rescue
    _ -> nil
  end

  defp campaign_matches?(campaign, fingerprint) do
    # Match on sender domain
    domain_match =
      campaign.sender_domain == fingerprint.sender_domain and
        campaign.sender_domain != nil

    # Match on overlapping URL hosts
    url_overlap =
      MapSet.intersection(
        MapSet.new(campaign.url_hosts || []),
        MapSet.new(fingerprint.url_hosts)
      )
      |> MapSet.size() > 0

    # Match on attachment hashes
    hash_overlap =
      MapSet.intersection(
        MapSet.new(campaign.attach_hashes || []),
        MapSet.new(fingerprint.attach_hashes)
      )
      |> MapSet.size() > 0

    # Match on subject similarity
    subject_match = campaign.subject_hash == fingerprint.subject_hash

    domain_match or url_overlap or hash_overlap or subject_match
  end

  defp update_campaign(organization_id, campaign_id, fingerprint) do
    key = {organization_id, campaign_id}

    case :ets.lookup(@ets_campaigns, key) do
      [{^key, campaign}] ->
        updated = %{
          campaign
          | email_count: campaign.email_count + 1,
            last_seen: DateTime.utc_now(),
            url_hosts: Enum.uniq(campaign.url_hosts ++ fingerprint.url_hosts),
            attach_hashes: Enum.uniq(campaign.attach_hashes ++ fingerprint.attach_hashes),
            status:
              if(campaign.email_count + 1 >= @campaign_min_emails, do: "active", else: "pending")
        }

        :ets.insert(@ets_campaigns, {key, updated})

        # Notify CampaignTracker if promoted to active
        if updated.status == "active" and campaign.status == "pending" do
          notify_campaign_tracker(updated)
        end

      [] ->
        :ok
    end
  rescue
    _ -> :ok
  end

  defp register_campaign_candidate(fingerprint) do
    id = "phish-camp-" <> generate_id()
    now = DateTime.utc_now()

    campaign = %{
      id: id,
      organization_id: fingerprint.organization_id,
      name: "Phishing Campaign #{id}",
      sender_domain: fingerprint.sender_domain,
      url_hosts: fingerprint.url_hosts,
      attach_hashes: fingerprint.attach_hashes,
      subject_hash: fingerprint.subject_hash,
      email_count: 1,
      first_seen: now,
      last_seen: now,
      status: "pending"
    }

    :ets.insert(@ets_campaigns, {{fingerprint.organization_id, id}, campaign})
  rescue
    _ -> :ok
  end

  defp notify_campaign_tracker(campaign) do
    try do
      if is_binary(campaign.organization_id) and campaign.organization_id != "" do
        CampaignTracker.record_attribution(campaign.organization_id, %{
          alert_id: nil,
          actor_names: ["Phishing Campaign: #{campaign.sender_domain}"],
          confidence: 0.7,
          timestamp: DateTime.utc_now(),
          metadata: %{
            campaign_id: campaign.id,
            email_count: campaign.email_count,
            source: "phishing_engine"
          }
        })
      else
        :telemetry.execute(
          [:tamandua, :campaign_tracker, :attribution_dropped],
          %{count: 1},
          %{source: :phishing, reason: :organization_missing}
        )
      end
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  defp sweep_campaigns do
    cutoff = DateTime.add(DateTime.utc_now(), -@campaign_cluster_window_hours * 2 * 3600, :second)

    :ets.tab2list(@ets_campaigns)
    |> Enum.each(fn {key, campaign} ->
      if DateTime.compare(campaign.last_seen, cutoff) == :lt do
        :ets.delete(@ets_campaigns, key)
      end
    end)
  rescue
    _ -> :ok
  end

  # ────────────────────────────────────────────────────────────────────
  # Recommendations
  # ────────────────────────────────────────────────────────────────────

  defp build_recommendations(verdict, header_result, url_result, attach_result, sender_result) do
    base =
      case verdict do
        :spear_phishing ->
          [
            %{
              action: :quarantine,
              priority: :critical,
              reason: "Targeted spear-phishing detected -- quarantine immediately"
            },
            %{
              action: :block_sender,
              priority: :high,
              reason: "Block sender domain and add IOCs to blocklists"
            },
            %{action: :notify_targets, priority: :high, reason: "Alert all targeted recipients"},
            %{
              action: :investigate,
              priority: :high,
              reason: "Investigate for business email compromise"
            }
          ]

        :phishing ->
          [
            %{
              action: :quarantine,
              priority: :high,
              reason: "Phishing email detected -- quarantine"
            },
            %{
              action: :block_sender,
              priority: :medium,
              reason: "Consider blocking sender domain"
            },
            %{
              action: :check_spread,
              priority: :medium,
              reason: "Check if other users received similar emails"
            }
          ]

        :suspicious ->
          [
            %{
              action: :hold,
              priority: :medium,
              reason: "Suspicious email -- hold for manual review"
            },
            %{
              action: :sandbox_urls,
              priority: :medium,
              reason: "Detonate URLs in sandbox before releasing"
            },
            %{
              action: :verify_sender,
              priority: :low,
              reason: "Verify sender through out-of-band communication"
            }
          ]

        :clean ->
          [
            %{action: :allow, priority: :low, reason: "Email appears safe -- allow delivery"},
            %{
              action: :add_allowlist,
              priority: :low,
              reason: "Consider adding sender to allowlist"
            }
          ]
      end

    # Add specific findings-based recommendations
    extras = []

    extras =
      if url_result.shorteners_found > 0 do
        [
          %{
            action: :resolve_shorteners,
            priority: :medium,
            reason: "Resolve #{url_result.shorteners_found} shortened URL(s) before releasing"
          }
          | extras
        ]
      else
        extras
      end

    extras =
      if attach_result.total > 0 and attach_result.score >= 40 do
        [
          %{
            action: :sandbox_attachments,
            priority: :high,
            reason: "Submit #{attach_result.total} attachment(s) for sandbox detonation"
          }
          | extras
        ]
      else
        extras
      end

    extras =
      if header_result.spf == "fail" or header_result.dmarc == "fail" do
        [
          %{
            action: :auth_failure,
            priority: :high,
            reason: "Email authentication failed -- sender may be spoofed"
          }
          | extras
        ]
      else
        extras
      end

    extras =
      if sender_result.typosquat.detected do
        [
          %{
            action: :typosquat_alert,
            priority: :high,
            reason: "Sender domain appears to be typosquatting #{sender_result.typosquat.brand}"
          }
          | extras
        ]
      else
        extras
      end

    base ++ extras
  end

  # ────────────────────────────────────────────────────────────────────
  # Alert Creation
  # ────────────────────────────────────────────────────────────────────

  defp maybe_create_alert(%{verdict: :clean}, _email_data), do: :ok

  defp maybe_create_alert(report, email_data) do
    severity =
      case report.verdict do
        :spear_phishing -> "critical"
        :phishing -> "high"
        :suspicious -> "medium"
        _ -> "low"
      end

    techniques =
      case report.verdict do
        :spear_phishing -> ["T1566.001"]
        :phishing -> ["T1566.001", "T1566.002"]
        _ -> ["T1566"]
      end

    Alerts.create_alert(%{
      agent_id: email_data[:agent_id],
      organization_id: report.organization_id,
      severity: severity,
      title: "Phishing #{report.verdict}: #{report.subject || "No subject"}",
      description: format_description(report),
      status: "new",
      source_event_id: report.message_id,
      mitre_tactics: ["initial-access"],
      mitre_techniques: techniques,
      # report.score is a 0-100 component-weighted score; canonical threat_score is 0.0-1.0
      threat_score: report.score / 100,
      evidence: %{
        detection: %{
          rule_name: "Phishing Analysis Engine",
          rule_type: "phishing_analysis",
          confidence: report.confidence,
          matched_pattern: report.from
        },
        network:
          Enum.map(report.iocs.urls, fn url ->
            %{type: "url", value: url, direction: "inbound"}
          end),
        file_hashes:
          Enum.map(report.iocs.file_hashes, fn h ->
            %{hash: h, type: "sha256"}
          end)
      },
      metadata: %{
        "analysis_id" => report.id,
        "verdict" => to_string(report.verdict),
        "confidence" => report.confidence,
        "sender" => report.from,
        "campaign_id" => nested_get(report, [:campaign, :campaign_id]),
        "component_scores" => report.component_scores
      }
    })
  rescue
    e ->
      Logger.warning("[Phishing] Failed to create alert: #{Exception.message(e)}")
      :ok
  end

  defp format_description(report) do
    """
    Phishing Analysis Report

    Verdict: #{report.verdict} (confidence: #{report.confidence}%)
    Overall Score: #{report.score}/100

    From: #{report.from || "N/A"}
    Subject: #{report.subject || "N/A"}

    Component Scores:
    - Headers: #{report.component_scores.headers}/100
    - URLs: #{report.component_scores.urls}/100 (#{report.url_analysis.total_urls} URLs found)
    - Attachments: #{report.component_scores.attachments}/100 (#{report.attachment_analysis.total} attachments)
    - Sender: #{report.component_scores.sender}/100
    - Content: #{report.component_scores.content}/100

    IOCs Extracted:
    - URLs: #{length(report.iocs.urls)}
    - Domains: #{length(report.iocs.domains)}
    - IPs: #{length(report.iocs.ip_addresses)}
    - Hashes: #{length(report.iocs.file_hashes)}
    """
  end

  # ────────────────────────────────────────────────────────────────────
  # Statistics
  # ────────────────────────────────────────────────────────────────────

  defp update_stats(state, report) do
    stats = state.stats
    verdict_key = report.verdict

    verdicts = Map.update(stats.verdicts, verdict_key, 1, &(&1 + 1))
    total = stats.total_analyzed + 1
    avg_score = (stats.avg_score * stats.total_analyzed + report.score) / total

    urls_checked = stats.urls_checked + report.url_analysis.total_urls

    attachments_detonated =
      stats.attachments_detonated +
        Enum.count(report.attachment_analysis.attachments, & &1.sandbox_submission_id)

    campaigns_detected =
      try do
        tenant_campaigns(report.organization_id)
        |> Enum.count(&(&1.status == "active"))
      rescue
        _ -> stats.campaigns_detected
      end

    new_stats = %{
      stats
      | total_analyzed: total,
        verdicts: verdicts,
        avg_score: Float.round(avg_score, 2),
        urls_checked: urls_checked,
        attachments_detonated: attachments_detonated,
        campaigns_detected: campaigns_detected
    }

    %{state | stats: new_stats}
  end

  # ────────────────────────────────────────────────────────────────────
  # PubSub Broadcasting
  # ────────────────────────────────────────────────────────────────────

  defp broadcast_analysis(report) do
    Phoenix.PubSub.broadcast(
      @pubsub,
      "#{@topic}:#{report.organization_id}",
      {:phishing_analysis_complete,
       %{
         id: report.id,
         organization_id: report.organization_id,
         verdict: report.verdict,
         confidence: report.confidence,
         score: report.score,
         from: report.from,
         subject: report.subject,
         campaign_id: nested_get(report, [:campaign, :campaign_id])
       }}
    )
  rescue
    _ -> :ok
  end

  # ────────────────────────────────────────────────────────────────────
  # Dedup Helpers
  # ────────────────────────────────────────────────────────────────────

  defp dedup_lookup(organization_id, message_id) do
    case :ets.lookup(@ets_submissions, {:dedup, organization_id, message_id}) do
      [{{:dedup, ^organization_id, ^message_id}, report}] -> report
      [] -> nil
    end
  rescue
    _ -> nil
  end

  defp tenant_reports(organization_id) do
    :ets.tab2list(@ets_submissions)
    |> Enum.flat_map(fn
      {{^organization_id, _report_id}, report} -> [report]
      _ -> []
    end)
  rescue
    ArgumentError -> []
  end

  defp tenant_campaigns(organization_id) do
    :ets.tab2list(@ets_campaigns)
    |> Enum.flat_map(fn
      {{^organization_id, _campaign_id}, campaign} -> [campaign]
      _ -> []
    end)
  rescue
    ArgumentError -> []
  end

  defp validate_email_scope(organization_id, email_data) when is_map(email_data) do
    agent_id = email_data[:agent_id] || email_data["agent_id"]

    with :ok <- require_organization(organization_id),
         :ok <- validate_agent_organization(agent_id, organization_id) do
      {:ok,
       email_data
       |> Map.delete(:organization_id)
       |> Map.delete("organization_id")
       |> Map.put(:organization_id, organization_id)
      }
    end
  end

  defp validate_email_scope(_organization_id, _), do: {:error, :invalid_email}

  defp require_organization(organization_id)
       when is_binary(organization_id) and organization_id != "",
       do: :ok

  defp require_organization(_), do: {:error, :organization_required}

  defp validate_agent_organization(nil, _organization_id), do: :ok
  defp validate_agent_organization("", _organization_id), do: {:error, :forbidden}

  defp validate_agent_organization(agent_id, organization_id) when is_binary(agent_id) do
    case TamanduaServer.Agents.OrgLookup.get_org_id(agent_id) do
      ^organization_id -> :ok
      _ -> {:error, :forbidden}
    end
  rescue
    _ -> {:error, :forbidden}
  catch
    :exit, _ -> {:error, :forbidden}
  end

  defp validate_agent_organization(_, _), do: {:error, :forbidden}

  # ────────────────────────────────────────────────────────────────────
  # Levenshtein Distance
  # ────────────────────────────────────────────────────────────────────

  defp levenshtein(s1, s2) when s1 == s2, do: 0
  defp levenshtein(s1, "") when is_binary(s1), do: String.length(s1)
  defp levenshtein("", s2) when is_binary(s2), do: String.length(s2)

  defp levenshtein(s1, s2) do
    s1_chars = String.graphemes(s1)
    s2_chars = String.graphemes(s2)
    _m = length(s1_chars)
    n = length(s2_chars)

    # Use single-row DP for memory efficiency
    initial_row = Enum.to_list(0..n)

    {final_row, _} =
      Enum.reduce(s1_chars, {initial_row, 1}, fn s1_char, {prev_row, i} ->
        {new_row, _} =
          Enum.reduce(Enum.with_index(s2_chars, 1), {[i], 0}, fn {s2_char, j}, {row, _prev_j} ->
            cost = if s1_char == s2_char, do: 0, else: 1
            prev_val = Enum.at(prev_row, j - 1)
            above = Enum.at(prev_row, j)
            left = List.last(row)

            val = min(min(above + 1, left + 1), prev_val + cost)
            {row ++ [val], j}
          end)

        {new_row, i + 1}
      end)

    List.last(final_row)
  end

  # ────────────────────────────────────────────────────────────────────
  # Utility
  # ────────────────────────────────────────────────────────────────────

  defp generate_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp ensure_ets_table(name, opts) do
    case :ets.whereis(name) do
      :undefined -> :ets.new(name, opts)
      _ref -> name
    end
  rescue
    ArgumentError ->
      try do
        :ets.new(name, opts)
      rescue
        _ -> name
      end
  end

  defp seed_brand_domains do
    Enum.each(@brand_domains, fn {brand, domains} ->
      :ets.insert(@ets_brands, {brand, domains})
    end)
  rescue
    _ -> :ok
  end

  defp nested_get(map, keys) when is_map(map) do
    Enum.reduce_while(keys, map, fn key, acc ->
      case acc do
        %{^key => val} -> {:cont, val}
        _ -> {:halt, nil}
      end
    end)
  end

  defp nested_get(_, _), do: nil
end
