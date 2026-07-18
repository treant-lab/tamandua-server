defmodule TamanduaServer.Detection.PhishingTriage do
  @moduledoc """
  Automated Phishing Triage Agent for email analysis and threat assessment.

  This module implements a comprehensive phishing detection system similar to
  Microsoft's Security Copilot phishing triage capabilities:

  - Autonomous phishing email analysis
  - URL reputation checking and defanging
  - Attachment analysis (hash checking, file type validation)
  - Sender reputation scoring
  - Auto-resolve false positives
  - Escalate malicious cases with confidence scoring
  - User notification and feedback integration

  ## Architecture

  The triage agent operates as a GenServer that processes email submissions
  through a multi-stage analysis pipeline:

  1. Email parsing and header extraction
  2. Sender reputation assessment
  3. URL extraction and reputation checking
  4. Attachment hash analysis
  5. IOC extraction and correlation
  6. Verdict calculation with confidence scoring
  7. Automated response (resolve/escalate)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.IOCs

  # Thresholds for verdict determination
  @malicious_threshold 0.75
  @suspicious_threshold 0.45
  @benign_threshold 0.25

  # Known malicious TLDs with high phishing rates
  @suspicious_tlds ~w(.tk .ml .ga .cf .gq .xyz .top .work .click .link .info .pw .cc .biz)

  # Common legitimate email providers for sender analysis
  @trusted_email_providers ~w(gmail.com outlook.com hotmail.com yahoo.com icloud.com protonmail.com)

  # Suspicious attachment extensions
  @dangerous_extensions ~w(.exe .scr .bat .cmd .ps1 .vbs .js .jar .msi .dll .hta .wsf .iso .img)
  @macro_extensions ~w(.docm .xlsm .pptm .dotm .xltm .potm)

  # URL shortener domains
  @url_shorteners ~w(bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly short.link)

  # State structure
  defstruct [
    :reputation_cache,
    :stats,
    :pending_analyses,
    :config
  ]

  # -----------------------------------------------------------------
  # Client API
  # -----------------------------------------------------------------

  @doc """
  Start the Phishing Triage Agent.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit an email for phishing analysis.

  ## Parameters
    - email_data: Map containing email content and metadata
      - :raw_content - Raw email content (RFC 822 format)
      - :headers - Parsed headers map
      - :body - Email body text
      - :html_body - HTML body if present
      - :attachments - List of attachment metadata
      - :reported_by - User who reported the email
      - :submission_id - Unique submission identifier

  ## Returns
    - {:ok, analysis_id} on successful submission
    - {:error, reason} on failure
  """
  @spec analyze_email(map()) :: {:ok, String.t()} | {:error, term()}
  def analyze_email(_email_data), do: {:error, :organization_required}

  @spec analyze_email_for_organization(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def analyze_email_for_organization(organization_id, email_data) do
    with {:ok, scoped_email} <- validate_email_scope(organization_id, email_data) do
      GenServer.call(__MODULE__, {:analyze_email, scoped_email}, 60_000)
    end
  end

  @doc """
  Get the analysis result for a submission.
  """
  @spec get_analysis(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_analysis(organization_id, analysis_id) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:get_analysis, organization_id, analysis_id})
    end
  end

  @doc """
  Submit user feedback on an analysis verdict.
  """
  @spec submit_feedback(String.t(), String.t(), :correct | :incorrect, map()) ::
          :ok | {:error, term()}
  def submit_feedback(organization_id, analysis_id, feedback, metadata \\ %{}) do
    with :ok <- require_organization(organization_id),
         true <- feedback in [:correct, :incorrect] do
      GenServer.call(__MODULE__, {:feedback, organization_id, analysis_id, feedback, metadata})
    else
      false -> {:error, :invalid_feedback}
      error -> error
    end
  end

  @doc """
  Get triage statistics.
  """
  @spec get_stats(String.t()) :: {:ok, map()} | {:error, term()}
  def get_stats(organization_id) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:get_stats, organization_id})
    end
  end

  @doc """
  Check URL reputation (can be called standalone).
  """
  @spec check_url_reputation(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def check_url_reputation(organization_id, url) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:check_url, organization_id, url})
    end
  end

  @doc """
  Defang a URL for safe display/sharing.
  """
  @spec defang_url(String.t()) :: String.t()
  def defang_url(url) do
    url
    |> String.replace("http://", "hxxp://")
    |> String.replace("https://", "hxxps://")
    |> String.replace(".", "[.]")
  end

  @doc """
  Re-fang a defanged URL.
  """
  @spec refang_url(String.t()) :: String.t()
  def refang_url(url) do
    url
    |> String.replace("hxxp://", "http://")
    |> String.replace("hxxps://", "https://")
    |> String.replace("[.]", ".")
  end

  # -----------------------------------------------------------------
  # Server Callbacks
  # -----------------------------------------------------------------

  @impl true
  def init(opts) do
    state = %__MODULE__{
      reputation_cache: %{},
      pending_analyses: %{},
      config: parse_config(opts),
      stats: %{
        total_analyzed: 0,
        malicious_detected: 0,
        suspicious_detected: 0,
        benign_resolved: 0,
        false_positives: 0,
        false_negatives: 0,
        avg_confidence: 0.0
      }
    }

    Logger.info("Phishing Triage Agent started")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze_email, email_data}, _from, state) do
    analysis_id = generate_analysis_id()
    organization_id = email_data[:organization_id]

    case perform_analysis(email_data, state) do
      {:ok, result} ->
        # Store result
        owned_result =
          result
          |> Map.put(:organization_id, organization_id)
          |> Map.put(:analysis_id, analysis_id)

        new_pending =
          Map.put(state.pending_analyses, {organization_id, analysis_id}, owned_result)

        # Update statistics
        new_stats = update_stats(state.stats, owned_result)

        # Execute automated response
        execute_response(owned_result, email_data)

        new_state = %{state | pending_analyses: new_pending, stats: new_stats}
        {:reply, {:ok, Map.put(owned_result, :analysis_id, analysis_id)}, new_state}

      {:error, reason} = error ->
        Logger.error("Phishing analysis failed: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_analysis, organization_id, analysis_id}, _from, state) do
    case Map.get(state.pending_analyses, {organization_id, analysis_id}) do
      nil -> {:reply, {:error, :not_found}, state}
      result -> {:reply, {:ok, result}, state}
    end
  end

  @impl true
  def handle_call({:get_stats, organization_id}, _from, state) do
    analyses = tenant_analyses(state, organization_id)
    {:reply, {:ok, stats_for_analyses(analyses)}, state}
  end

  @impl true
  def handle_call({:list_analyses, organization_id, opts}, _from, state) do
    limit = opts[:limit] || opts["limit"] || 50
    limit = if is_integer(limit), do: limit |> min(100) |> max(1), else: 50

    analyses =
      state
      |> tenant_analyses(organization_id)
      |> Enum.sort_by(& &1.analyzed_at, {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, {:ok, analyses}, state}
  end

  @impl true
  def handle_call({:check_url, organization_id, url}, _from, state) do
    {result, new_cache} = check_url_with_cache(url, state.reputation_cache, organization_id)
    {:reply, {:ok, result}, %{state | reputation_cache: new_cache}}
  end

  # Deep-analysis calls (moved up to keep handle_call/3 clauses contiguous)
  @impl true
  def handle_call({:analyze_url_deep, url, opts}, _from, state) do
    result = do_analyze_url_deep(url, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:detonate_url, url, opts}, _from, state) do
    result = do_detonate_url(url, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:check_sender_reputation, organization_id, sender_email}, _from, state) do
    result = do_check_sender_reputation(organization_id, sender_email, state)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:detect_spoofing, domain}, _from, state) do
    result = do_detect_spoofing(domain)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:analyze_attachment_ml, attachment}, _from, state) do
    result = do_analyze_attachment_ml(attachment)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:analyze_campaign, organization_id, email_id}, _from, state) do
    result = do_analyze_campaign(organization_id, email_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:feedback, organization_id, analysis_id, feedback, metadata}, _from, state) do
    key = {organization_id, analysis_id}

    case Map.get(state.pending_analyses, key) do
      nil ->
        {:reply, {:error, :not_found}, state}

      analysis ->
        new_stats = apply_feedback(state.stats, analysis, feedback)

        Logger.info(
          "Feedback received for #{analysis_id}: #{feedback}, metadata: #{inspect(metadata)}"
        )

        updated = Map.put(analysis, :feedback, feedback)
        pending = Map.put(state.pending_analyses, key, updated)
        {:reply, :ok, %{state | stats: new_stats, pending_analyses: pending}}
    end
  end

  # -----------------------------------------------------------------
  # Analysis Pipeline
  # -----------------------------------------------------------------

  defp perform_analysis(email_data, state) do
    with {:ok, parsed} <- parse_email(email_data),
         {:ok, sender_score} <- analyze_sender(parsed),
         {:ok, header_analysis} <- analyze_headers(parsed),
         {:ok, url_analysis} <- analyze_urls(parsed, state.reputation_cache),
         {:ok, attachment_analysis} <- analyze_attachments(parsed),
         {:ok, iocs} <- extract_iocs(parsed),
         {:ok, content_analysis} <- analyze_content(parsed) do
      # Calculate final verdict
      verdict =
        calculate_verdict(%{
          sender_score: sender_score,
          header_analysis: header_analysis,
          url_analysis: url_analysis,
          attachment_analysis: attachment_analysis,
          content_analysis: content_analysis
        })

      {:ok,
       %{
         verdict: verdict.verdict,
         confidence: verdict.confidence,
         threat_score: verdict.threat_score,
         sender_analysis: sender_score,
         header_analysis: header_analysis,
         url_analysis: url_analysis,
         attachment_analysis: attachment_analysis,
         content_analysis: content_analysis,
         extracted_iocs: iocs,
         recommendations: generate_recommendations(verdict),
         analyzed_at: DateTime.utc_now()
       }}
    end
  end

  defp parse_email(email_data) do
    parsed = %{
      headers: email_data[:headers] || extract_headers(email_data[:raw_content]),
      body: email_data[:body] || "",
      html_body: email_data[:html_body],
      attachments: email_data[:attachments] || [],
      subject: get_header(email_data, "subject"),
      from: get_header(email_data, "from"),
      to: get_header(email_data, "to"),
      reply_to: get_header(email_data, "reply-to"),
      return_path: get_header(email_data, "return-path"),
      received: get_all_headers(email_data, "received"),
      message_id: get_header(email_data, "message-id"),
      date: get_header(email_data, "date"),
      organization_id: authoritative_email_organization_id(email_data),
      raw: email_data[:raw_content]
    }

    {:ok, parsed}
  end

  defp extract_headers(nil), do: %{}

  defp extract_headers(raw_content) when is_binary(raw_content) do
    raw_content
    |> String.split("\r\n\r\n", parts: 2)
    |> List.first()
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

  defp get_header(email_data, header_name) do
    headers = email_data[:headers] || %{}
    Map.get(headers, header_name) || Map.get(headers, String.downcase(header_name))
  end

  defp authoritative_email_organization_id(email_data) do
    agent_id = email_data[:agent_id] || email_data["agent_id"]
    claimed = email_data[:organization_id] || email_data["organization_id"]

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

  defp get_all_headers(email_data, header_name) do
    headers = email_data[:headers] || %{}
    # For multi-value headers like Received, return as list
    case Map.get(headers, header_name) do
      nil -> []
      value when is_list(value) -> value
      value -> [value]
    end
  end

  # -----------------------------------------------------------------
  # Sender Analysis
  # -----------------------------------------------------------------

  defp analyze_sender(parsed) do
    from = parsed.from || ""
    reply_to = parsed.reply_to
    return_path = parsed.return_path

    email_address = extract_email_address(from)
    domain = extract_domain_from_email(email_address)

    score = %{
      email: email_address,
      domain: domain,
      display_name: extract_display_name(from),
      checks: [],
      risk_score: 0.0
    }

    # Check 1: Reply-To mismatch
    score =
      if reply_to && extract_domain_from_email(reply_to) != domain do
        add_sender_check(
          score,
          :reply_to_mismatch,
          "Reply-To domain differs from sender domain",
          0.3
        )
      else
        score
      end

    # Check 2: Return-Path mismatch
    score =
      if return_path && extract_domain_from_email(return_path) != domain do
        add_sender_check(
          score,
          :return_path_mismatch,
          "Return-Path domain differs from sender domain",
          0.2
        )
      else
        score
      end

    # Check 3: Display name contains email (spoofing indicator)
    display_name = score.display_name || ""

    score =
      if String.contains?(display_name, "@") do
        add_sender_check(
          score,
          :display_name_contains_email,
          "Display name contains email address (possible spoofing)",
          0.4
        )
      else
        score
      end

    # Check 4: Free email provider for business context
    score =
      if domain && domain in @trusted_email_providers do
        add_sender_check(score, :free_email_provider, "Sender using free email provider", 0.1)
      else
        score
      end

    # Check 5: Recently registered domain (if we had WHOIS data)
    # This would integrate with external threat intel

    # Check 6: Domain similarity to known brands (typosquatting)
    score = check_typosquatting(score, domain)

    {:ok, score}
  end

  defp add_sender_check(score, check_type, description, risk_delta) do
    %{
      score
      | checks: [{check_type, description} | score.checks],
        risk_score: min(1.0, score.risk_score + risk_delta)
    }
  end

  defp extract_email_address(nil), do: nil

  defp extract_email_address(from_header) do
    case Regex.run(~r/<([^>]+)>/, from_header) do
      [_, email] ->
        String.downcase(email)

      nil ->
        # Try bare email
        if String.contains?(from_header, "@") do
          String.trim(from_header) |> String.downcase()
        else
          nil
        end
    end
  end

  defp extract_display_name(nil), do: nil

  defp extract_display_name(from_header) do
    case Regex.run(~r/^([^<]+)</, from_header) do
      [_, name] -> String.trim(name) |> String.replace(~r/^["']|["']$/, "")
      nil -> nil
    end
  end

  defp extract_domain_from_email(nil), do: nil

  defp extract_domain_from_email(email) do
    case String.split(email, "@") do
      [_, domain] -> String.downcase(domain)
      _ -> nil
    end
  end

  defp check_typosquatting(score, nil), do: score

  defp check_typosquatting(score, domain) do
    known_brands = ~w(microsoft google apple amazon paypal netflix facebook linkedin twitter)

    typosquat_match =
      Enum.find(known_brands, fn brand ->
        # Check for brand name in domain but not exact match
        String.contains?(domain, brand) && domain != "#{brand}.com"
      end)

    if typosquat_match do
      add_sender_check(
        score,
        :possible_typosquatting,
        "Domain may be impersonating #{typosquat_match}",
        0.5
      )
    else
      score
    end
  end

  # -----------------------------------------------------------------
  # Header Analysis
  # -----------------------------------------------------------------

  defp analyze_headers(parsed) do
    analysis = %{
      checks: [],
      risk_score: 0.0,
      spf_result: nil,
      dkim_result: nil,
      dmarc_result: nil
    }

    # Check authentication results
    auth_results = extract_auth_results(parsed.headers)
    analysis = Map.merge(analysis, auth_results)

    # Check 1: SPF failure
    analysis =
      case auth_results.spf_result do
        "fail" -> add_header_check(analysis, :spf_fail, "SPF authentication failed", 0.4)
        "softfail" -> add_header_check(analysis, :spf_softfail, "SPF soft failure", 0.2)
        _ -> analysis
      end

    # Check 2: DKIM failure
    analysis =
      case auth_results.dkim_result do
        "fail" -> add_header_check(analysis, :dkim_fail, "DKIM authentication failed", 0.4)
        nil -> add_header_check(analysis, :dkim_missing, "No DKIM signature", 0.1)
        _ -> analysis
      end

    # Check 3: DMARC failure
    analysis =
      case auth_results.dmarc_result do
        "fail" -> add_header_check(analysis, :dmarc_fail, "DMARC authentication failed", 0.5)
        nil -> add_header_check(analysis, :dmarc_missing, "No DMARC policy", 0.1)
        _ -> analysis
      end

    # Check 4: Suspicious Received chain
    analysis = analyze_received_chain(analysis, parsed.received)

    # Check 5: Missing or suspicious Message-ID
    analysis =
      if is_nil(parsed.message_id) or not valid_message_id?(parsed.message_id) do
        add_header_check(analysis, :invalid_message_id, "Missing or malformed Message-ID", 0.2)
      else
        analysis
      end

    {:ok, analysis}
  end

  defp add_header_check(analysis, check_type, description, risk_delta) do
    %{
      analysis
      | checks: [{check_type, description} | analysis.checks],
        risk_score: min(1.0, analysis.risk_score + risk_delta)
    }
  end

  defp extract_auth_results(headers) do
    auth_header = Map.get(headers, "authentication-results", "")

    %{
      spf_result: extract_auth_value(auth_header, "spf"),
      dkim_result: extract_auth_value(auth_header, "dkim"),
      dmarc_result: extract_auth_value(auth_header, "dmarc")
    }
  end

  defp extract_auth_value(header, mechanism) do
    case Regex.run(~r/#{mechanism}=(\w+)/i, header) do
      [_, result] -> String.downcase(result)
      nil -> nil
    end
  end

  defp analyze_received_chain(analysis, received_headers) when length(received_headers) == 0 do
    add_header_check(analysis, :no_received_headers, "No Received headers present", 0.3)
  end

  defp analyze_received_chain(analysis, received_headers) do
    # Check for suspicious patterns in Received chain
    suspicious_count =
      Enum.count(received_headers, fn header ->
        String.contains?(String.downcase(header), ["localhost", "127.0.0.1", "unknown"])
      end)

    if suspicious_count > 0 do
      add_header_check(
        analysis,
        :suspicious_received,
        "#{suspicious_count} suspicious entries in Received chain",
        0.2
      )
    else
      analysis
    end
  end

  defp valid_message_id?(message_id) do
    # Basic Message-ID validation: should contain @ and be wrapped in <>
    String.contains?(message_id, "@") &&
      (String.starts_with?(message_id, "<") || not String.contains?(message_id, " "))
  end

  # -----------------------------------------------------------------
  # URL Analysis
  # -----------------------------------------------------------------

  defp analyze_urls(parsed, cache) do
    # Extract URLs from body and HTML
    body_urls = extract_urls(parsed.body)
    html_urls = extract_urls(parsed.html_body || "")
    all_urls = Enum.uniq(body_urls ++ html_urls)

    # Analyze each URL
    {url_results, _updated_cache} =
      Enum.map_reduce(all_urls, cache, fn url, acc_cache ->
        {result, new_cache} = check_url_with_cache(url, acc_cache, parsed.organization_id)
        {{url, result}, new_cache}
      end)

    # Calculate overall URL risk
    total_risk =
      if Enum.empty?(url_results) do
        0.0
      else
        url_results
        |> Enum.map(fn {_, result} -> result.risk_score end)
        |> Enum.max()
      end

    {:ok,
     %{
       urls_found: length(all_urls),
       url_details: url_results,
       highest_risk: total_risk,
       defanged_urls: Enum.map(all_urls, &defang_url/1)
     }}
  end

  defp extract_urls(nil), do: []

  defp extract_urls(text) do
    # Extract URLs including those in href attributes
    url_regex = ~r/https?:\/\/[^\s<>"'\)]+/i
    href_regex = ~r/href=["']([^"']+)["']/i

    direct_urls = Regex.scan(url_regex, text) |> Enum.map(&List.first/1)
    href_urls = Regex.scan(href_regex, text) |> Enum.map(&List.last/1)

    (direct_urls ++ href_urls)
    |> Enum.uniq()
    |> Enum.filter(&valid_url?/1)
  end

  defp valid_url?(url) do
    String.starts_with?(url, "http://") || String.starts_with?(url, "https://")
  end

  defp check_url_with_cache(url, cache, organization_id) do
    cache_key = {organization_id, url}

    case Map.get(cache, cache_key) do
      nil ->
        result = analyze_single_url(url, organization_id)
        {result, Map.put(cache, cache_key, result)}

      cached ->
        {cached, cache}
    end
  end

  defp analyze_single_url(url, organization_id) do
    uri = URI.parse(url)
    host = uri.host || ""

    checks = []
    risk_score = 0.0

    # Check 1: URL shortener
    {checks, risk_score} =
      if host in @url_shorteners do
        {[{:url_shortener, "URL shortener detected"} | checks], risk_score + 0.3}
      else
        {checks, risk_score}
      end

    # Check 2: Suspicious TLD
    tld = "." <> (String.split(host, ".") |> List.last() || "")

    {checks, risk_score} =
      if tld in @suspicious_tlds do
        {[{:suspicious_tld, "High-risk TLD: #{tld}"} | checks], risk_score + 0.3}
      else
        {checks, risk_score}
      end

    # Check 3: IP address URL
    {checks, risk_score} =
      if ip_address?(host) do
        {[{:ip_url, "URL uses IP address instead of domain"} | checks], risk_score + 0.4}
      else
        {checks, risk_score}
      end

    # Check 4: Suspicious patterns in path
    path = uri.path || ""

    {checks, risk_score} =
      cond do
        String.contains?(path, ["login", "signin", "verify", "account", "secure", "update"]) ->
          {[{:sensitive_path, "URL path contains sensitive keywords"} | checks], risk_score + 0.2}

        String.contains?(path, [".exe", ".scr", ".zip", ".rar"]) ->
          {[{:executable_download, "URL may lead to executable download"} | checks],
           risk_score + 0.5}

        true ->
          {checks, risk_score}
      end

    # Check 5: Data URI or javascript
    {checks, risk_score} =
      if String.starts_with?(url, "data:") or String.starts_with?(url, "javascript:") do
        {[{:dangerous_scheme, "Dangerous URL scheme detected"} | checks], risk_score + 0.6}
      else
        {checks, risk_score}
      end

    # Check against IOC database
    ioc_match =
      IOCs.match_for_organization(url, "url", organization_id) ||
        IOCs.match_for_organization(host, "domain", organization_id)

    {checks, risk_score} =
      if ioc_match do
        {[{:known_malicious, "URL/domain matches known IOC"} | checks], risk_score + 0.8}
      else
        {checks, risk_score}
      end

    %{
      url: url,
      host: host,
      checks: checks,
      risk_score: min(1.0, risk_score),
      defanged: defang_url(url)
    }
  end

  defp ip_address?(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  # -----------------------------------------------------------------
  # Attachment Analysis
  # -----------------------------------------------------------------

  defp analyze_attachments(parsed) do
    attachments = parsed.attachments || []

    if Enum.empty?(attachments) do
      {:ok,
       %{
         attachment_count: 0,
         attachments: [],
         highest_risk: 0.0
       }}
    else
      results = Enum.map(attachments, &analyze_single_attachment(&1, parsed.organization_id))

      highest_risk =
        results
        |> Enum.map(& &1.risk_score)
        |> Enum.max(fn -> 0.0 end)

      {:ok,
       %{
         attachment_count: length(attachments),
         attachments: results,
         highest_risk: highest_risk
       }}
    end
  end

  defp analyze_single_attachment(attachment, organization_id) do
    filename = attachment[:filename] || "unknown"
    extension = Path.extname(filename) |> String.downcase()
    content_type = attachment[:content_type] || "application/octet-stream"
    size = attachment[:size] || 0

    checks = []
    risk_score = 0.0

    # Check 1: Dangerous extension
    {checks, risk_score} =
      if extension in @dangerous_extensions do
        {[{:dangerous_extension, "Dangerous file extension: #{extension}"} | checks],
         risk_score + 0.7}
      else
        {checks, risk_score}
      end

    # Check 2: Macro-enabled document
    {checks, risk_score} =
      if extension in @macro_extensions do
        {[{:macro_enabled, "Macro-enabled document: #{extension}"} | checks], risk_score + 0.5}
      else
        {checks, risk_score}
      end

    # Check 3: Double extension
    {checks, risk_score} =
      if double_extension?(filename) do
        {[{:double_extension, "Double file extension detected"} | checks], risk_score + 0.6}
      else
        {checks, risk_score}
      end

    # Check 4: Content-type mismatch
    {checks, risk_score} =
      if content_type_mismatch?(extension, content_type) do
        {[{:content_type_mismatch, "File extension doesn't match content type"} | checks],
         risk_score + 0.4}
      else
        {checks, risk_score}
      end

    # Check 5: Hash against IOC database
    {checks, risk_score} =
      check_attachment_hash(checks, risk_score, attachment, organization_id)

    # Check 6: Suspicious filename patterns
    {checks, risk_score} =
      if suspicious_filename?(filename) do
        {[{:suspicious_filename, "Suspicious filename pattern"} | checks], risk_score + 0.3}
      else
        {checks, risk_score}
      end

    %{
      filename: filename,
      extension: extension,
      content_type: content_type,
      size: size,
      checks: checks,
      risk_score: min(1.0, risk_score),
      hashes: %{
        md5: attachment[:md5],
        sha1: attachment[:sha1],
        sha256: attachment[:sha256]
      }
    }
  end

  defp double_extension?(filename) do
    parts = String.split(filename, ".")
    length(parts) > 2 && List.last(parts) in ["exe", "scr", "bat", "cmd", "js", "vbs"]
  end

  defp content_type_mismatch?(extension, content_type) do
    expected = %{
      ".pdf" => "application/pdf",
      ".doc" => "application/msword",
      ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      ".xls" => "application/vnd.ms-excel",
      ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }

    case Map.get(expected, extension) do
      nil -> false
      expected_type -> not String.contains?(content_type, expected_type)
    end
  end

  defp check_attachment_hash(checks, risk_score, attachment, organization_id) do
    hash_checks = [
      {:sha256, attachment[:sha256]},
      {:sha1, attachment[:sha1]},
      {:md5, attachment[:md5]}
    ]

    Enum.reduce(hash_checks, {checks, risk_score}, fn {type, hash}, {acc_checks, acc_risk} ->
      if hash && IOCs.match_for_organization(hash, "hash_#{type}", organization_id) do
        {[{:known_malicious_hash, "File hash matches known malicious IOC"} | acc_checks],
         acc_risk + 0.9}
      else
        {acc_checks, acc_risk}
      end
    end)
  end

  defp suspicious_filename?(filename) do
    patterns = [
      ~r/invoice.*\d+/i,
      ~r/payment.*confirm/i,
      ~r/urgent.*action/i,
      ~r/password.*reset/i,
      ~r/account.*verif/i
    ]

    Enum.any?(patterns, &Regex.match?(&1, filename))
  end

  # -----------------------------------------------------------------
  # Content Analysis
  # -----------------------------------------------------------------

  defp analyze_content(parsed) do
    body = (parsed.body || "") <> " " <> (parsed.html_body || "")

    checks = []
    risk_score = 0.0

    # Check 1: Urgency keywords
    urgency_patterns = [
      ~r/urgent|immediate|action required|act now|limited time/i,
      ~r/your account.*suspend|verify.*account|confirm.*identity/i,
      ~r/click here|click below|click this link/i
    ]

    {checks, risk_score} =
      Enum.reduce(urgency_patterns, {checks, risk_score}, fn pattern, {acc_checks, acc_risk} ->
        if Regex.match?(pattern, body) do
          {[{:urgency_language, "Urgency/pressure language detected"} | acc_checks],
           acc_risk + 0.15}
        else
          {acc_checks, acc_risk}
        end
      end)

    # Check 2: Credential request patterns
    {checks, risk_score} =
      if Regex.match?(~r/password|credential|login|username|ssn|social security/i, body) do
        {[{:credential_request, "Request for sensitive information detected"} | checks],
         risk_score + 0.3}
      else
        {checks, risk_score}
      end

    # Check 3: Generic greeting
    {checks, risk_score} =
      if Regex.match?(~r/^(dear\s+(customer|user|member|sir|madam)|hello,?\s*$)/im, body) do
        {[{:generic_greeting, "Generic greeting used"} | checks], risk_score + 0.1}
      else
        {checks, risk_score}
      end

    # Check 4: Grammar/spelling indicators (simplified)
    {checks, risk_score} =
      if poor_grammar_indicators?(body) do
        {[{:poor_grammar, "Potential grammar/spelling issues detected"} | checks],
         risk_score + 0.1}
      else
        {checks, risk_score}
      end

    # Check 5: Hidden text (HTML only)
    {checks, risk_score} =
      if parsed.html_body && hidden_text_detected?(parsed.html_body) do
        {[{:hidden_text, "Hidden text detected in HTML"} | checks], risk_score + 0.4}
      else
        {checks, risk_score}
      end

    {:ok,
     %{
       checks: checks,
       risk_score: min(1.0, risk_score)
     }}
  end

  defp poor_grammar_indicators?(text) do
    # Simple heuristics for grammar issues
    patterns = [
      # Multiple spaces
      ~r/\s{2,}/,
      # Multiple punctuation
      ~r/[.!?]{2,}/,
      # Lowercase "i" as pronoun
      ~r/\bi\b/
    ]

    Enum.count(patterns, &Regex.match?(&1, text)) >= 2
  end

  defp hidden_text_detected?(html) do
    hidden_patterns = [
      ~r/display:\s*none/i,
      ~r/visibility:\s*hidden/i,
      ~r/font-size:\s*0/i,
      ~r/color:\s*white|color:\s*#fff/i
    ]

    Enum.any?(hidden_patterns, &Regex.match?(&1, html))
  end

  # -----------------------------------------------------------------
  # IOC Extraction
  # -----------------------------------------------------------------

  defp extract_iocs(parsed) do
    body = (parsed.body || "") <> " " <> (parsed.html_body || "")

    iocs = %{
      urls: extract_urls(body),
      email_addresses: extract_email_addresses(body),
      domains: extract_domains(body),
      ip_addresses: extract_ip_addresses(body),
      hashes: extract_hashes_from_attachments(parsed.attachments || [])
    }

    {:ok, iocs}
  end

  defp extract_email_addresses(text) do
    Regex.scan(~r/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i, text)
    |> Enum.map(&List.first/1)
    |> Enum.uniq()
  end

  defp extract_domains(text) do
    # Extract domains from URLs and email addresses
    urls = extract_urls(text)
    emails = extract_email_addresses(text)

    url_domains =
      Enum.map(urls, fn url ->
        URI.parse(url).host
      end)
      |> Enum.reject(&is_nil/1)

    email_domains =
      Enum.map(emails, &extract_domain_from_email/1)
      |> Enum.reject(&is_nil/1)

    Enum.uniq(url_domains ++ email_domains)
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
      {:error, _} -> false
    end
  end

  defp extract_hashes_from_attachments(attachments) do
    Enum.flat_map(attachments, fn att ->
      [
        att[:md5] && {:md5, att[:md5]},
        att[:sha1] && {:sha1, att[:sha1]},
        att[:sha256] && {:sha256, att[:sha256]}
      ]
      |> Enum.reject(&is_nil/1)
    end)
  end

  # -----------------------------------------------------------------
  # Verdict Calculation
  # -----------------------------------------------------------------

  defp calculate_verdict(analysis_results) do
    # Weighted scoring across all analysis dimensions
    weights = %{
      sender_score: 0.20,
      header_analysis: 0.15,
      url_analysis: 0.30,
      attachment_analysis: 0.25,
      content_analysis: 0.10
    }

    scores = %{
      sender_score: analysis_results.sender_score.risk_score,
      header_analysis: analysis_results.header_analysis.risk_score,
      url_analysis: analysis_results.url_analysis.highest_risk,
      attachment_analysis: analysis_results.attachment_analysis.highest_risk,
      content_analysis: analysis_results.content_analysis.risk_score
    }

    weighted_score =
      Enum.reduce(weights, 0.0, fn {key, weight}, acc ->
        acc + Map.get(scores, key, 0.0) * weight
      end)

    # Determine verdict and confidence
    {verdict, confidence} =
      cond do
        weighted_score >= @malicious_threshold ->
          {:malicious, calculate_confidence(weighted_score, @malicious_threshold)}

        weighted_score >= @suspicious_threshold ->
          {:suspicious, calculate_confidence(weighted_score, @suspicious_threshold)}

        weighted_score <= @benign_threshold ->
          {:benign, calculate_confidence(@benign_threshold - weighted_score, @benign_threshold)}

        true ->
          {:inconclusive, 0.5}
      end

    %{
      verdict: verdict,
      confidence: confidence,
      threat_score: weighted_score,
      component_scores: scores
    }
  end

  defp calculate_confidence(score, threshold) do
    # Higher scores above threshold = higher confidence
    base_confidence = 0.6
    additional = min(0.4, (score - threshold) * 2)
    min(1.0, base_confidence + additional)
  end

  # -----------------------------------------------------------------
  # Response Execution
  # -----------------------------------------------------------------

  defp execute_response(result, email_data) do
    case result.verdict do
      :malicious ->
        # Create high-severity alert
        create_phishing_alert(result, email_data, :high)
        # Could trigger automated quarantine, user notification, etc.
        Logger.warning("Phishing detected: confidence=#{result.confidence}")

      :suspicious ->
        # Create medium-severity alert for review
        create_phishing_alert(result, email_data, :medium)
        Logger.info("Suspicious email flagged for review")

      :benign ->
        # Auto-resolve with notification
        Logger.debug("Email classified as benign, auto-resolving")
        notify_user_safe(email_data[:reported_by])

      :inconclusive ->
        # Queue for manual review
        create_phishing_alert(result, email_data, :low)
        Logger.info("Inconclusive analysis, queued for manual review")
    end
  end

  defp create_phishing_alert(result, email_data, severity) do
    # Use email_id or event_id as the source event reference
    source_event_id = email_data[:event_id] || email_data[:email_id] || email_data[:message_id]

    # Build evidence for phishing alerts
    evidence = build_phishing_evidence(result, email_data)

    Alerts.create_alert(%{
      agent_id: email_data[:agent_id],
      organization_id: email_data[:organization_id],
      severity: severity,
      title: "Phishing: #{result.verdict} - #{email_data[:subject] || "No subject"}",
      description: format_alert_description(result, email_data),
      status: "new",
      source_event_id: source_event_id,
      event_ids: if(source_event_id, do: [source_event_id], else: []),
      evidence: evidence,
      mitre_tactics: ["initial-access"],
      # Phishing techniques
      mitre_techniques: ["T1566.001", "T1566.002"],
      threat_score: result.threat_score,
      metadata: %{
        analysis_type: "phishing_triage",
        verdict: result.verdict,
        confidence: result.confidence,
        sender: email_data[:from],
        reported_by: email_data[:reported_by]
      }
    })
  end

  defp build_phishing_evidence(result, email_data) do
    # Extract file hashes from attachments
    file_hashes =
      (result.attachment_analysis[:attachments] || [])
      |> Enum.flat_map(fn att ->
        if att[:sha256] do
          [%{sha256: att[:sha256], path: att[:filename]}]
        else
          []
        end
      end)

    # Extract network indicators (URLs and domains)
    network =
      (result.url_analysis[:urls] || [])
      |> Enum.map(fn url_info ->
        %{
          type: "url",
          value: url_info[:url] || url_info,
          direction: "inbound"
        }
      end)

    %{
      file_hashes: file_hashes,
      network: network,
      process: %{},
      registry: [],
      detection: %{
        rule_name: "Phishing Triage: #{result.verdict}",
        rule_type: "phishing_analysis",
        confidence: result.confidence,
        matched_pattern: email_data[:from]
      }
    }
  end

  defp format_alert_description(result, email_data) do
    """
    Phishing Triage Analysis

    Verdict: #{result.verdict} (#{Float.round(result.confidence * 100, 1)}% confidence)
    Threat Score: #{Float.round(result.threat_score * 100, 1)}%

    Email Details:
    - Subject: #{email_data[:subject] || "N/A"}
    - From: #{email_data[:from] || "N/A"}
    - Reported By: #{email_data[:reported_by] || "N/A"}

    Analysis Summary:
    - Sender Risk: #{Float.round(result.sender_analysis.risk_score * 100, 1)}%
    - Header Risk: #{Float.round(result.header_analysis.risk_score * 100, 1)}%
    - URL Risk: #{Float.round(result.url_analysis.highest_risk * 100, 1)}% (#{result.url_analysis.urls_found} URLs)
    - Attachment Risk: #{Float.round(result.attachment_analysis.highest_risk * 100, 1)}% (#{result.attachment_analysis.attachment_count} attachments)
    - Content Risk: #{Float.round(result.content_analysis.risk_score * 100, 1)}%

    Recommendations:
    #{Enum.join(result.recommendations, "\n")}
    """
  end

  defp notify_user_safe(_user_id) do
    # Integration point for user notification
    # Could send email, Slack message, etc.
    :ok
  end

  # -----------------------------------------------------------------
  # Recommendations
  # -----------------------------------------------------------------

  defp generate_recommendations(verdict) do
    base_recommendations =
      case verdict.verdict do
        :malicious ->
          [
            "- URGENT: Block sender domain immediately",
            "- Quarantine this email and any copies",
            "- Check if other users received similar emails",
            "- Add extracted IOCs to blocklists",
            "- Notify affected user(s) and advise not to click any links"
          ]

        :suspicious ->
          [
            "- Review this email manually before releasing",
            "- Verify sender through out-of-band communication",
            "- Check URL destinations in a sandbox",
            "- Monitor for similar emails from this sender"
          ]

        :benign ->
          [
            "- This email appears safe to release",
            "- Consider adding sender to allowlist if legitimate",
            "- Provide feedback if this was incorrectly classified"
          ]

        :inconclusive ->
          [
            "- Manual review required",
            "- Check URLs and attachments in a sandbox",
            "- Verify sender legitimacy",
            "- Consider requesting additional context from reporter"
          ]
      end

    # Add specific recommendations based on findings
    base_recommendations
  end

  # -----------------------------------------------------------------
  # Statistics and Feedback
  # -----------------------------------------------------------------

  defp update_stats(stats, result) do
    new_stats = %{
      stats
      | total_analyzed: stats.total_analyzed + 1,
        avg_confidence: update_avg_confidence(stats, result.confidence)
    }

    case result.verdict do
      :malicious -> %{new_stats | malicious_detected: new_stats.malicious_detected + 1}
      :suspicious -> %{new_stats | suspicious_detected: new_stats.suspicious_detected + 1}
      :benign -> %{new_stats | benign_resolved: new_stats.benign_resolved + 1}
      _ -> new_stats
    end
  end

  defp update_avg_confidence(stats, new_confidence) do
    total = stats.total_analyzed

    if total == 0 do
      new_confidence
    else
      (stats.avg_confidence * total + new_confidence) / (total + 1)
    end
  end

  defp apply_feedback(stats, analysis, :incorrect) do
    case analysis.verdict do
      :malicious -> %{stats | false_positives: stats.false_positives + 1}
      :benign -> %{stats | false_negatives: stats.false_negatives + 1}
      _ -> stats
    end
  end

  defp apply_feedback(stats, _analysis, :correct), do: stats

  # -----------------------------------------------------------------
  # Helpers
  # -----------------------------------------------------------------

  defp generate_analysis_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp tenant_analyses(state, organization_id) do
    state.pending_analyses
    |> Enum.flat_map(fn
      {{^organization_id, _analysis_id}, analysis} -> [analysis]
      _ -> []
    end)
  end

  defp stats_for_analyses(analyses) do
    total = length(analyses)

    avg_confidence =
      if total == 0, do: 0.0, else: Enum.sum(Enum.map(analyses, & &1.confidence)) / total

    %{
      total_analyzed: total,
      malicious_detected: Enum.count(analyses, &(&1.verdict == :malicious)),
      suspicious_detected: Enum.count(analyses, &(&1.verdict == :suspicious)),
      benign_resolved: Enum.count(analyses, &(&1.verdict == :benign)),
      false_positives:
        Enum.count(analyses, &(&1[:feedback] == :incorrect and &1.verdict == :malicious)),
      false_negatives:
        Enum.count(analyses, &(&1[:feedback] == :incorrect and &1.verdict == :benign)),
      avg_confidence: avg_confidence
    }
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

  defp parse_config(opts) do
    %{
      auto_resolve_benign: Keyword.get(opts, :auto_resolve_benign, true),
      auto_quarantine_malicious: Keyword.get(opts, :auto_quarantine_malicious, true),
      confidence_threshold: Keyword.get(opts, :confidence_threshold, 0.7),
      enable_external_lookups: Keyword.get(opts, :enable_external_lookups, false)
    }
  end

  # ============================================================================
  # Public API Stub Functions
  # ============================================================================

  @doc """
  List AI classifications for phishing analysis.
  """
  @spec list_classifications(map()) :: {:ok, [map()]}
  def list_classifications(opts \\ %{}) do
    organization_id = opts[:organization_id] || opts["organization_id"]

    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:list_analyses, organization_id, opts})
    end
  end

  @doc """
  List reported phishing emails.
  """
  @spec list_reported_emails(map()) :: {:ok, [map()]}
  def list_reported_emails(opts \\ %{}) do
    list_classifications(opts)
  end

  # ============================================================================
  # Enhanced URL Analysis and Detonation
  # ============================================================================

  @doc """
  Perform deep URL analysis including detonation in sandbox.

  Returns detailed analysis including:
  - Final destination (follows redirects)
  - Domain reputation
  - SSL certificate analysis
  - Content inspection
  - Sandbox detonation results
  """
  @spec analyze_url_deep(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def analyze_url_deep(url, opts \\ []) do
    with :ok <- require_organization(Keyword.get(opts, :organization_id)) do
      GenServer.call(__MODULE__, {:analyze_url_deep, url, opts}, 120_000)
    end
  end

  @doc """
  Detonate URL in sandbox environment.

  This submits the URL to the ML service for browser-based detonation
  and captures screenshots, network traffic, and behavior.
  """
  @spec detonate_url(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def detonate_url(url, opts \\ []) do
    GenServer.call(__MODULE__, {:detonate_url, url, opts}, 180_000)
  end

  @doc """
  Check sender reputation across multiple sources.

  Queries:
  - Internal historical data
  - Email authentication results (SPF/DKIM/DMARC)
  - Domain age and registration info
  - Known sender databases
  """
  @spec check_sender_reputation(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def check_sender_reputation(organization_id, sender_email) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:check_sender_reputation, organization_id, sender_email})
    end
  end

  @doc """
  Detect domain spoofing and lookalike domains.

  Checks for:
  - Homoglyph attacks (l vs 1, O vs 0)
  - Typosquatting (googel.com)
  - Subdomain abuse (login.microsoft.com.attacker.com)
  - Cousin domains (microsoft-login.com)
  """
  @spec detect_domain_spoofing(String.t()) :: {:ok, map()}
  def detect_domain_spoofing(domain) do
    GenServer.call(__MODULE__, {:detect_spoofing, domain})
  end

  @doc """
  Analyze attachment via ML service for malware detection.

  Submits attachment to the Malware-SMELL model for analysis.
  """
  @spec analyze_attachment_ml(map()) :: {:ok, map()} | {:error, term()}
  def analyze_attachment_ml(attachment) do
    GenServer.call(__MODULE__, {:analyze_attachment_ml, attachment}, 60_000)
  end

  @doc """
  Get phishing campaign analysis.

  Groups related phishing emails to identify campaigns based on:
  - Similar sender patterns
  - Common URLs/domains
  - Template similarity
  - Temporal clustering
  """
  @spec analyze_campaign(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def analyze_campaign(organization_id, email_id) do
    with :ok <- require_organization(organization_id) do
      GenServer.call(__MODULE__, {:analyze_campaign, organization_id, email_id})
    end
  end

  # -----------------------------------------------------------------
  # Deep URL Analysis Implementation
  # -----------------------------------------------------------------

  defp do_analyze_url_deep(url, opts, state) do
    uri = URI.parse(url)
    host = uri.host || ""

    # Basic URL checks
    organization_id = Keyword.get(opts, :organization_id)
    {basic_result, _} = check_url_with_cache(url, state.reputation_cache, organization_id)

    # Follow redirects to get final destination
    final_destination = follow_redirects(url, Keyword.get(opts, :max_redirects, 5))

    # Analyze SSL certificate
    ssl_analysis = analyze_ssl_certificate(host)

    # Check domain registration age
    domain_info = check_domain_registration(host)

    # Content inspection (if enabled)
    content_analysis =
      if Keyword.get(opts, :fetch_content, false) do
        analyze_page_content(url)
      else
        %{skipped: true}
      end

    result = %{
      url: url,
      host: host,
      basic_analysis: basic_result,
      final_destination: final_destination,
      ssl_analysis: ssl_analysis,
      domain_info: domain_info,
      content_analysis: content_analysis,
      overall_risk: calculate_deep_url_risk(basic_result, ssl_analysis, domain_info),
      analyzed_at: DateTime.utc_now()
    }

    {:ok, result}
  end

  defp follow_redirects(url, max_redirects) when max_redirects <= 0 do
    %{
      final_url: url,
      redirect_chain: [],
      error: "Max redirects exceeded"
    }
  end

  defp follow_redirects(url, max_redirects) do
    follow_redirects(url, max_redirects, [])
  end

  defp follow_redirects(url, max_redirects, chain) when max_redirects > 0 do
    try do
      # Use Req with redirect: false so we can capture each hop manually
      case Req.get(url,
             redirect: false,
             connect_options: [timeout: 5_000],
             receive_timeout: 10_000,
             retry: false
           ) do
        {:ok, %{status: status, headers: headers}} when status in [301, 302, 303, 307, 308] ->
          location =
            headers
            |> Enum.find_value(fn
              {"location", loc} -> loc
              _ -> nil
            end)

          if location do
            # Resolve relative redirects against the current URL
            resolved = resolve_redirect_url(url, location)
            hop = %{url: url, status: status, redirected_to: resolved}
            follow_redirects(resolved, max_redirects - 1, chain ++ [hop])
          else
            # Location header missing -- treat current URL as final
            %{final_url: url, redirect_chain: chain, error: nil}
          end

        {:ok, %{status: status}} ->
          # Non-redirect response -- we've reached the final destination
          hop = %{url: url, status: status, redirected_to: nil}
          %{final_url: url, redirect_chain: chain ++ [hop], error: nil}

        {:error, exception} ->
          %{
            final_url: url,
            redirect_chain: chain,
            error: "HTTP request failed: #{Exception.message(exception)}"
          }
      end
    rescue
      e ->
        %{
          final_url: url,
          redirect_chain: chain,
          error: "Exception during redirect following: #{Exception.message(e)}"
        }
    end
  end

  defp follow_redirects(url, _max_redirects, chain) do
    # max_redirects exhausted
    %{final_url: url, redirect_chain: chain, error: "Max redirects exceeded"}
  end

  # Resolve a possibly-relative Location header against the request URL
  defp resolve_redirect_url(_base_url, "http" <> _ = absolute), do: absolute

  defp resolve_redirect_url(_base_url, "//" <> _ = protocol_relative),
    do: "https:" <> protocol_relative

  defp resolve_redirect_url(base_url, relative_path) do
    base_uri = URI.parse(base_url)
    %URI{base_uri | path: relative_path, query: nil, fragment: nil} |> URI.to_string()
  end

  defp analyze_ssl_certificate(host) do
    # Strip protocol/path to get the bare hostname
    hostname =
      host
      |> String.replace(~r{^https?://}, "")
      |> String.split("/", parts: 2)
      |> List.first()
      |> String.split(":", parts: 2)
      |> List.first()

    charlist_host = String.to_charlist(hostname)

    try do
      # Connect with TLS and retrieve the peer certificate
      ssl_opts = [
        verify: :verify_none,
        depth: 3,
        server_name_indication: charlist_host,
        versions: [:"tlsv1.2", :"tlsv1.3"]
      ]

      case :ssl.connect(charlist_host, 443, ssl_opts, 8_000) do
        {:ok, ssl_socket} ->
          result =
            case :ssl.peercert(ssl_socket) do
              {:ok, der_cert} ->
                parse_certificate(der_cert, hostname)

              {:error, reason} ->
                %{
                  has_ssl: true,
                  valid: false,
                  issuer: "Unknown",
                  subject: nil,
                  expires_at: nil,
                  not_before: nil,
                  subject_alt_names: [],
                  self_signed: false,
                  weak_algorithm: false,
                  expired: false,
                  risk_score: 0.5,
                  error: "Could not retrieve peer certificate: #{inspect(reason)}"
                }
            end

          :ssl.close(ssl_socket)
          result

        {:error, reason} ->
          %{
            has_ssl: false,
            valid: false,
            issuer: "Unknown",
            subject: nil,
            expires_at: nil,
            not_before: nil,
            subject_alt_names: [],
            self_signed: false,
            weak_algorithm: false,
            expired: false,
            risk_score: 0.8,
            error: "TLS connection failed: #{inspect(reason)}"
          }
      end
    rescue
      e ->
        %{
          has_ssl: false,
          valid: false,
          issuer: "Unknown",
          subject: nil,
          expires_at: nil,
          not_before: nil,
          subject_alt_names: [],
          self_signed: false,
          weak_algorithm: false,
          expired: false,
          risk_score: 0.6,
          error: "SSL analysis exception: #{Exception.message(e)}"
        }
    end
  end

  defp parse_certificate(der_cert, _hostname) do
    # Decode the DER-encoded certificate using Erlang :public_key
    otp_cert = :public_key.pkix_decode_cert(der_cert, :otp)
    # OTPTBSCertificate
    tbs = elem(otp_cert, 2)

    # Extract validity period
    {not_before, not_after} = extract_validity(tbs)
    now = DateTime.utc_now()

    expired =
      case not_after do
        %DateTime{} -> DateTime.compare(now, not_after) == :gt
        _ -> false
      end

    not_yet_valid =
      case not_before do
        %DateTime{} -> DateTime.compare(now, not_before) == :lt
        _ -> false
      end

    # Extract issuer and subject as readable strings
    issuer = extract_rdn_string(elem(tbs, 4))
    subject = extract_rdn_string(elem(tbs, 6))

    # Detect self-signed: issuer == subject is a simple heuristic
    self_signed = issuer == subject

    # Extract Subject Alternative Names from extensions
    sans = extract_sans(tbs)

    # Check for weak signature algorithms
    sig_algo = extract_signature_algorithm(tbs)

    weak_algorithm =
      sig_algo in [
        :sha1WithRSAEncryption,
        :md5WithRSAEncryption,
        :md2WithRSAEncryption,
        "sha1WithRSAEncryption",
        "md5WithRSAEncryption"
      ]

    # Compute a risk score: 0.0 (safe) .. 1.0 (risky)
    risk_score = compute_ssl_risk(expired, not_yet_valid, self_signed, weak_algorithm)

    %{
      has_ssl: true,
      valid: not expired and not not_yet_valid and not self_signed,
      issuer: issuer,
      subject: subject,
      expires_at: not_after,
      not_before: not_before,
      subject_alt_names: sans,
      self_signed: self_signed,
      weak_algorithm: weak_algorithm,
      expired: expired,
      signature_algorithm: to_string(sig_algo),
      risk_score: risk_score,
      error: nil
    }
  rescue
    e ->
      %{
        has_ssl: true,
        valid: false,
        issuer: "Unknown",
        subject: nil,
        expires_at: nil,
        not_before: nil,
        subject_alt_names: [],
        self_signed: false,
        weak_algorithm: false,
        expired: false,
        risk_score: 0.5,
        error: "Certificate parsing error: #{Exception.message(e)}"
      }
  end

  defp extract_validity(tbs) do
    # Validity is the 5th element (index 5) of OTPTBSCertificate
    validity = elem(tbs, 5)
    not_before = asn1_time_to_datetime(elem(validity, 1))
    not_after = asn1_time_to_datetime(elem(validity, 2))
    {not_before, not_after}
  rescue
    _ -> {nil, nil}
  end

  defp asn1_time_to_datetime({:utcTime, time_charlist}) do
    time_str = to_string(time_charlist)
    # UTCTime format: YYMMDDHHMMSSZ
    case Regex.run(~r/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/, time_str) do
      [_, yy, mm, dd, hh, mi, ss] ->
        year = String.to_integer(yy)
        # RFC 5280: YY >= 50 means 19YY, otherwise 20YY
        year = if year >= 50, do: 1900 + year, else: 2000 + year

        {:ok, dt} =
          NaiveDateTime.new(
            year,
            String.to_integer(mm),
            String.to_integer(dd),
            String.to_integer(hh),
            String.to_integer(mi),
            String.to_integer(ss)
          )

        DateTime.from_naive!(dt, "Etc/UTC")

      _ ->
        nil
    end
  end

  defp asn1_time_to_datetime({:generalTime, time_charlist}) do
    time_str = to_string(time_charlist)
    # GeneralizedTime format: YYYYMMDDHHMMSSZ
    case Regex.run(~r/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/, time_str) do
      [_, yyyy, mm, dd, hh, mi, ss] ->
        {:ok, dt} =
          NaiveDateTime.new(
            String.to_integer(yyyy),
            String.to_integer(mm),
            String.to_integer(dd),
            String.to_integer(hh),
            String.to_integer(mi),
            String.to_integer(ss)
          )

        DateTime.from_naive!(dt, "Etc/UTC")

      _ ->
        nil
    end
  end

  defp asn1_time_to_datetime(_), do: nil

  defp extract_rdn_string(rdn_sequence) do
    # rdn_sequence is {:rdnSequence, list_of_attribute_sets}
    case rdn_sequence do
      {:rdnSequence, attr_sets} ->
        attr_sets
        |> List.flatten()
        |> Enum.map(fn
          {:AttributeTypeAndValue, oid, value} ->
            name = oid_to_short_name(oid)
            val = extract_attribute_value(value)
            "#{name}=#{val}"

          _ ->
            nil
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.join(", ")

      _ ->
        "Unknown"
    end
  rescue
    _ -> "Unknown"
  end

  defp oid_to_short_name({2, 5, 4, 3}), do: "CN"
  defp oid_to_short_name({2, 5, 4, 6}), do: "C"
  defp oid_to_short_name({2, 5, 4, 7}), do: "L"
  defp oid_to_short_name({2, 5, 4, 8}), do: "ST"
  defp oid_to_short_name({2, 5, 4, 10}), do: "O"
  defp oid_to_short_name({2, 5, 4, 11}), do: "OU"
  defp oid_to_short_name(oid), do: inspect(oid)

  defp extract_attribute_value({:utf8String, val}), do: to_string(val)
  defp extract_attribute_value({:printableString, val}), do: to_string(val)
  defp extract_attribute_value({:ia5String, val}), do: to_string(val)
  defp extract_attribute_value({:teletexString, val}), do: to_string(val)
  defp extract_attribute_value(val) when is_binary(val), do: val
  defp extract_attribute_value(val) when is_list(val), do: to_string(val)
  defp extract_attribute_value(val), do: inspect(val)

  defp extract_sans(tbs) do
    # Extensions are at index 8 of OTPTBSCertificate
    extensions =
      try do
        elem(tbs, 8)
      rescue
        _ -> []
      end

    case extensions do
      :asn1_NOVALUE ->
        []

      exts when is_list(exts) ->
        Enum.flat_map(exts, fn
          {:Extension, {2, 5, 29, 17}, _critical, san_value} ->
            extract_san_names(san_value)

          _ ->
            []
        end)

      _ ->
        []
    end
  rescue
    _ -> []
  end

  defp extract_san_names(san_values) when is_list(san_values) do
    Enum.flat_map(san_values, fn
      {:dNSName, name} -> [to_string(name)]
      {:iPAddress, ip} -> [format_ip(ip)]
      _ -> []
    end)
  end

  defp extract_san_names(_), do: []

  defp format_ip(ip) when is_list(ip) and length(ip) == 4 do
    Enum.join(ip, ".")
  end

  defp format_ip(ip), do: inspect(ip)

  defp extract_signature_algorithm(tbs) do
    # Signature algorithm is at index 2 of OTPTBSCertificate
    try do
      algo_record = elem(tbs, 2)
      # The algorithm OID is the second element of the record
      elem(algo_record, 1)
    rescue
      _ -> :unknown
    end
  end

  defp compute_ssl_risk(expired, not_yet_valid, self_signed, weak_algorithm) do
    base = 0.0
    base = if expired, do: base + 0.4, else: base
    base = if not_yet_valid, do: base + 0.3, else: base
    base = if self_signed, do: base + 0.3, else: base
    base = if weak_algorithm, do: base + 0.2, else: base
    min(1.0, base)
  end

  defp check_domain_registration(_host) do
    # In production, query WHOIS data
    %{
      registered: true,
      age_days: nil,
      registrar: "Unknown",
      creation_date: nil,
      analysis_note: "Domain registration requires WHOIS lookup"
    }
  end

  defp analyze_page_content(_url) do
    # In production, fetch and analyze page content
    %{
      fetched: false,
      login_form_detected: false,
      credential_fields: [],
      brand_impersonation: nil,
      analysis_note: "Content analysis requires HTTP fetch"
    }
  end

  defp calculate_deep_url_risk(basic_result, ssl_analysis, domain_info) do
    base = basic_result.risk_score

    # Increase risk for SSL issues
    base = if ssl_analysis.valid == false, do: min(1.0, base + 0.3), else: base

    # Increase risk for newly registered domains
    base =
      if domain_info[:age_days] && domain_info[:age_days] < 30 do
        min(1.0, base + 0.2)
      else
        base
      end

    base
  end

  # -----------------------------------------------------------------
  # URL Detonation Implementation
  # -----------------------------------------------------------------

  defp do_detonate_url(url, opts) do
    ml_service_url =
      Application.get_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

    # Submit to ML service for browser-based detonation
    request_body = %{
      "url" => url,
      "timeout_seconds" => Keyword.get(opts, :timeout, 30),
      "capture_screenshot" => Keyword.get(opts, :screenshot, true),
      "capture_network" => Keyword.get(opts, :network, true),
      "user_agent" => Keyword.get(opts, :user_agent, "Mozilla/5.0")
    }

    case http_post("#{ml_service_url}/api/v1/detonate/url", Jason.encode!(request_body)) do
      {:ok, response} ->
        {:ok,
         %{
           url: url,
           status: response["status"],
           final_url: response["final_url"],
           screenshot_url: response["screenshot_url"],
           network_requests: response["network_requests"] || [],
           page_title: response["page_title"],
           forms_detected: response["forms_detected"] || [],
           verdict: response["verdict"],
           confidence: response["confidence"],
           indicators: response["indicators"] || [],
           detonated_at: DateTime.utc_now()
         }}

      {:error, reason} ->
        {:error, {:detonation_failed, reason}}
    end
  end

  # -----------------------------------------------------------------
  # Sender Reputation Implementation
  # -----------------------------------------------------------------

  defp do_check_sender_reputation(organization_id, sender_email, state) do
    domain = extract_domain_from_email(sender_email)

    # Check internal history
    internal_score = check_internal_sender_history(organization_id, sender_email)

    # Check cached reputation
    cached = Map.get(state.reputation_cache, {organization_id, sender_email})

    # Build reputation profile
    %{
      email: sender_email,
      domain: domain,
      internal_score: internal_score,
      emails_seen: internal_score.emails_seen,
      malicious_emails: internal_score.malicious_count,
      suspicious_emails: internal_score.suspicious_count,
      first_seen: internal_score.first_seen,
      last_seen: internal_score.last_seen,
      is_trusted_provider: domain in @trusted_email_providers,
      reputation_score: calculate_sender_reputation_score(internal_score, domain),
      cached_analysis: cached,
      analyzed_at: DateTime.utc_now()
    }
  end

  defp check_internal_sender_history(_organization_id, _sender_email) do
    # In production, query internal database for sender history
    %{
      emails_seen: 0,
      malicious_count: 0,
      suspicious_count: 0,
      first_seen: nil,
      last_seen: nil
    }
  end

  defp calculate_sender_reputation_score(internal_score, domain) do
    # Neutral starting point
    base = 0.5

    # Adjust based on history
    base =
      if internal_score.emails_seen > 0 do
        malicious_ratio = internal_score.malicious_count / internal_score.emails_seen
        suspicious_ratio = internal_score.suspicious_count / internal_score.emails_seen

        base + malicious_ratio * -0.4 + suspicious_ratio * -0.2
      else
        base
      end

    # Boost for trusted providers
    base = if domain in @trusted_email_providers, do: base + 0.1, else: base

    max(0.0, min(1.0, base))
  end

  # -----------------------------------------------------------------
  # Domain Spoofing Detection Implementation
  # -----------------------------------------------------------------

  # Common homoglyph mappings
  @homoglyphs %{
    "a" => ["а", "ą", "α"],
    "e" => ["е", "ę", "ε"],
    "i" => ["і", "ı", "1", "l"],
    "o" => ["о", "ο", "0"],
    "l" => ["1", "I", "ł", "і"],
    "s" => ["ѕ", "ś"],
    "c" => ["с", "ç"],
    "p" => ["р"],
    "x" => ["х"],
    "y" => ["у"],
    "n" => ["ñ", "ń"]
  }

  # Known brand domains for lookalike detection
  @brand_domains %{
    "microsoft" => ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google" => ["google.com", "gmail.com", "googleapis.com"],
    "apple" => ["apple.com", "icloud.com"],
    "amazon" => ["amazon.com", "aws.com"],
    "facebook" => ["facebook.com", "fb.com"],
    "paypal" => ["paypal.com"],
    "netflix" => ["netflix.com"],
    "linkedin" => ["linkedin.com"],
    "twitter" => ["twitter.com", "x.com"],
    "dropbox" => ["dropbox.com"],
    "bank" => ["chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com"]
  }

  defp do_detect_spoofing(domain) do
    domain_lower = String.downcase(domain || "")

    # Check for homoglyph attacks
    homoglyph_check = detect_homoglyphs(domain_lower)

    # Check for typosquatting
    typosquat_check = detect_typosquatting(domain_lower)

    # Check for subdomain abuse
    subdomain_check = detect_subdomain_abuse(domain_lower)

    # Check for cousin domains
    cousin_check = detect_cousin_domains(domain_lower)

    # Overall spoofing assessment
    is_spoofing =
      homoglyph_check.detected or
        typosquat_check.detected or
        subdomain_check.detected or
        cousin_check.detected

    impersonated_brand =
      homoglyph_check.brand ||
        typosquat_check.brand ||
        subdomain_check.brand ||
        cousin_check.brand

    %{
      domain: domain,
      is_spoofing: is_spoofing,
      impersonated_brand: impersonated_brand,
      homoglyph_attack: homoglyph_check,
      typosquatting: typosquat_check,
      subdomain_abuse: subdomain_check,
      cousin_domain: cousin_check,
      risk_score:
        calculate_spoofing_risk(homoglyph_check, typosquat_check, subdomain_check, cousin_check),
      analyzed_at: DateTime.utc_now()
    }
  end

  defp detect_homoglyphs(domain) do
    # Check for Unicode homoglyphs
    has_unicode =
      not String.printable?(domain) or
        Regex.match?(~r/[^\x00-\x7F]/, domain)

    if has_unicode do
      %{
        detected: true,
        type: :unicode_homoglyph,
        description: "Domain contains non-ASCII characters that may be homoglyphs",
        brand: nil
      }
    else
      %{detected: false, type: nil, description: nil, brand: nil}
    end
  end

  defp detect_typosquatting(domain) do
    # Check against known brands with Levenshtein distance
    match =
      Enum.find_value(@brand_domains, fn {brand, legitimate_domains} ->
        Enum.find(legitimate_domains, fn legit_domain ->
          # Calculate similarity
          legit_base = legit_domain |> String.split(".") |> List.first()
          domain_base = domain |> String.split(".") |> List.first()

          # Check if similar but not exact
          distance = levenshtein_distance(domain_base, legit_base)

          if distance > 0 and distance <= 2 and domain != legit_domain do
            {brand, legit_domain, distance}
          end
        end)
      end)

    if match do
      {brand, legit_domain, distance} = match

      %{
        detected: true,
        type: :typosquatting,
        brand: brand,
        legitimate_domain: legit_domain,
        edit_distance: distance,
        description: "Domain is similar to #{legit_domain} (#{brand})"
      }
    else
      %{detected: false, type: nil, brand: nil, description: nil}
    end
  end

  defp detect_subdomain_abuse(domain) do
    # Check for patterns like login.microsoft.com.attacker.com
    Enum.find_value(@brand_domains, fn {brand, legitimate_domains} ->
      Enum.find(legitimate_domains, fn legit_domain ->
        _legit_base = String.replace(legit_domain, ".com", "")

        # Check if legitimate domain appears as subdomain
        if String.contains?(domain, legit_domain) and domain != legit_domain do
          # Verify it's actually subdomain abuse (brand.com.attacker.com)
          pattern = ~r/#{Regex.escape(legit_domain)}\.[a-z]+/

          if Regex.match?(pattern, domain) do
            %{
              detected: true,
              type: :subdomain_abuse,
              brand: brand,
              legitimate_domain: legit_domain,
              description: "Domain abuses #{legit_domain} as subdomain"
            }
          end
        end
      end)
    end) || %{detected: false, type: nil, brand: nil, description: nil}
  end

  defp detect_cousin_domains(domain) do
    # Check for patterns like microsoft-login.com, paypal-secure.com
    Enum.find_value(@brand_domains, fn {brand, _legitimate_domains} ->
      patterns = [
        ~r/^#{brand}-[a-z]+\./,
        ~r/^[a-z]+-#{brand}\./,
        ~r/^#{brand}[a-z]+\./,
        ~r/^[a-z]+#{brand}\./
      ]

      if Enum.any?(patterns, &Regex.match?(&1, domain)) do
        %{
          detected: true,
          type: :cousin_domain,
          brand: brand,
          description: "Domain appears to impersonate #{brand} brand"
        }
      end
    end) || %{detected: false, type: nil, brand: nil, description: nil}
  end

  defp levenshtein_distance(s1, s2) do
    # Simple Levenshtein distance implementation
    if s1 == s2 do
      0
    else
      m = String.length(s1)
      n = String.length(s2)

      cond do
        m == 0 ->
          n

        n == 0 ->
          m

        true ->
          s1_chars = String.graphemes(s1)
          s2_chars = String.graphemes(s2)

          matrix =
            for i <- 0..m, j <- 0..n, into: %{} do
              cond do
                i == 0 -> {{i, j}, j}
                j == 0 -> {{i, j}, i}
                true -> {{i, j}, 0}
              end
            end

          result =
            Enum.reduce(1..m, matrix, fn i, acc1 ->
              Enum.reduce(1..n, acc1, fn j, acc2 ->
                s1_char = Enum.at(s1_chars, i - 1)
                s2_char = Enum.at(s2_chars, j - 1)

                cost = if s1_char == s2_char, do: 0, else: 1

                value =
                  min(
                    min(
                      # deletion
                      Map.get(acc2, {i - 1, j}) + 1,
                      # insertion
                      Map.get(acc2, {i, j - 1}) + 1
                    ),
                    # substitution
                    Map.get(acc2, {i - 1, j - 1}) + cost
                  )

                Map.put(acc2, {i, j}, value)
              end)
            end)

          Map.get(result, {m, n})
      end
    end
  end

  defp calculate_spoofing_risk(homoglyph, typosquat, subdomain, cousin) do
    risks = [
      if(homoglyph.detected, do: 0.9, else: 0.0),
      if(typosquat.detected, do: 0.8, else: 0.0),
      if(subdomain.detected, do: 0.85, else: 0.0),
      if(cousin.detected, do: 0.7, else: 0.0)
    ]

    Enum.max(risks)
  end

  # -----------------------------------------------------------------
  # ML Attachment Analysis Implementation
  # -----------------------------------------------------------------

  defp do_analyze_attachment_ml(attachment) do
    ml_service_url =
      Application.get_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

    # Submit to ML service
    request_body = %{
      "sha256" => attachment[:sha256],
      "filename" => attachment[:filename],
      "content_type" => attachment[:content_type],
      "size" => attachment[:size],
      "content_base64" => attachment[:content_base64]
    }

    case http_post("#{ml_service_url}/api/v1/analyze/file", Jason.encode!(request_body)) do
      {:ok, response} ->
        {:ok,
         %{
           sha256: attachment[:sha256],
           filename: attachment[:filename],
           verdict: response["verdict"],
           confidence: response["confidence"],
           malware_family: response["malware_family"],
           threat_score: response["threat_score"],
           indicators: response["indicators"] || [],
           static_analysis: response["static_analysis"],
           behavioral_analysis: response["behavioral_analysis"],
           analyzed_at: DateTime.utc_now()
         }}

      {:error, reason} ->
        {:error, {:ml_analysis_failed, reason}}
    end
  end

  # -----------------------------------------------------------------
  # Campaign Analysis Implementation
  # -----------------------------------------------------------------

  defp do_analyze_campaign(organization_id, email_id, state) do
    case Map.get(state.pending_analyses, {organization_id, email_id}) do
      nil ->
        {:error, :email_not_found}

      email_analysis ->
        # Find similar emails
        similar_emails = find_similar_emails(organization_id, email_analysis, state)

        # Cluster by common attributes
        clusters = cluster_by_attributes(similar_emails)

        # Determine if this is part of a campaign
        is_campaign = length(similar_emails) >= 3

        campaign_info =
          if is_campaign do
            %{
              campaign_id: "camp-#{email_id}",
              email_count: length(similar_emails),
              common_sender_domain: find_common_attribute(similar_emails, :sender_domain),
              common_urls: find_common_urls(similar_emails),
              common_attachments: find_common_attachments(similar_emails),
              time_range: calculate_campaign_time_range(similar_emails),
              target_domains: find_target_domains(similar_emails),
              severity: :high,
              confidence: calculate_campaign_confidence(similar_emails)
            }
          end

        {:ok,
         %{
           email_id: email_id,
           is_campaign: is_campaign,
           campaign: campaign_info,
           similar_emails: similar_emails,
           clusters: clusters,
           analyzed_at: DateTime.utc_now()
         }}
    end
  end

  defp find_similar_emails(organization_id, email_analysis, state) do
    sender_domain = email_analysis.sender_analysis[:domain]

    state.pending_analyses
    |> Enum.flat_map(fn
      {{^organization_id, _analysis_id}, analysis} -> [analysis]
      _ -> []
    end)
    |> Enum.filter(fn analysis ->
      analysis_domain = analysis.sender_analysis[:domain]

      # Match by sender domain, similar URLs, or similar attachments
      analysis_domain == sender_domain or
        urls_overlap?(email_analysis, analysis) or
        attachments_overlap?(email_analysis, analysis)
    end)
    |> Enum.take(100)
  end

  defp urls_overlap?(analysis1, analysis2) do
    urls1 = MapSet.new(get_in(analysis1, [:url_analysis, :defanged_urls]) || [])
    urls2 = MapSet.new(get_in(analysis2, [:url_analysis, :defanged_urls]) || [])

    MapSet.intersection(urls1, urls2) |> MapSet.size() > 0
  end

  defp attachments_overlap?(analysis1, analysis2) do
    hashes1 = get_attachment_hashes(analysis1)
    hashes2 = get_attachment_hashes(analysis2)

    MapSet.intersection(MapSet.new(hashes1), MapSet.new(hashes2)) |> MapSet.size() > 0
  end

  defp get_attachment_hashes(analysis) do
    (get_in(analysis, [:attachment_analysis, :attachments]) || [])
    |> Enum.map(fn att -> att[:hashes][:sha256] end)
    |> Enum.reject(&is_nil/1)
  end

  defp cluster_by_attributes(emails) do
    # Simple clustering by sender domain
    Enum.group_by(emails, fn email ->
      email.sender_analysis[:domain]
    end)
    |> Enum.map(fn {domain, group} ->
      %{
        key: domain,
        count: length(group),
        emails: Enum.map(group, & &1.analysis_id)
      }
    end)
  end

  defp find_common_attribute(emails, :sender_domain) do
    emails
    |> Enum.map(fn e -> e.sender_analysis[:domain] end)
    |> Enum.frequencies()
    |> Enum.max_by(fn {_, count} -> count end, fn -> {nil, 0} end)
    |> elem(0)
  end

  defp find_common_urls(emails) do
    emails
    |> Enum.flat_map(fn e -> get_in(e, [:url_analysis, :defanged_urls]) || [] end)
    |> Enum.frequencies()
    |> Enum.filter(fn {_, count} -> count >= 2 end)
    |> Enum.map(fn {url, count} -> %{url: url, occurrences: count} end)
  end

  defp find_common_attachments(emails) do
    emails
    |> Enum.flat_map(fn e ->
      (get_in(e, [:attachment_analysis, :attachments]) || [])
      |> Enum.map(fn att -> %{filename: att[:filename], sha256: att[:hashes][:sha256]} end)
    end)
    |> Enum.frequencies()
    |> Enum.filter(fn {_, count} -> count >= 2 end)
    |> Enum.map(fn {att, count} -> Map.put(att, :occurrences, count) end)
  end

  defp calculate_campaign_time_range(emails) do
    times =
      emails
      |> Enum.map(fn e -> e[:analyzed_at] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.sort()

    %{
      first: List.first(times),
      last: List.last(times)
    }
  end

  defp find_target_domains(emails) do
    emails
    |> Enum.flat_map(fn e ->
      recipients = e[:recipients] || []

      Enum.map(recipients, fn r ->
        case String.split(r || "", "@") do
          [_, domain] -> domain
          _ -> nil
        end
      end)
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_, count} -> count end, :desc)
    |> Enum.take(10)
    |> Enum.map(fn {domain, count} -> %{domain: domain, count: count} end)
  end

  defp calculate_campaign_confidence(emails) do
    # Higher confidence with more similar emails
    count = length(emails)

    cond do
      count >= 10 -> 0.95
      count >= 5 -> 0.85
      count >= 3 -> 0.70
      true -> 0.50
    end
  end

  # HTTP helper for ML service calls
  defp http_post(url, body) do
    headers = [{"Content-Type", "application/json"}]

    if Code.ensure_loaded?(Req) do
      case Req.post(url, body: body, headers: headers, receive_timeout: 60_000) do
        {:ok, %{status: 200, body: response_body}} ->
          {:ok, response_body}

        {:ok, %{status: status, body: body}} ->
          {:error, {:api_error, status, body}}

        {:error, exception} ->
          {:error, Exception.message(exception)}
      end
    else
      # Stub for testing
      {:ok, %{"verdict" => "unknown", "confidence" => 0.5}}
    end
  end
end
