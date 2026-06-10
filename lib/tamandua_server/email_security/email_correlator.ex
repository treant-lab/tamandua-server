defmodule TamanduaServer.EmailSecurity.EmailCorrelator do
  @moduledoc """
  Email-to-Endpoint Correlation Engine.

  Correlates email security events with endpoint telemetry to build
  comprehensive attack chains. Tracks the complete lifecycle:

  1. Email received
  2. Attachment saved to disk
  3. Attachment/payload executed
  4. Malicious process behavior

  This enables detection of sophisticated attacks that span email delivery
  and endpoint execution, similar to Microsoft Defender for Office 365
  and CrowdStrike Falcon Complete.

  ## Features

  - Email to file correlation (attachment tracking)
  - File to process correlation (execution tracking)
  - Attack chain building and scoring
  - Cross-endpoint correlation for lateral movement
  - User risk scoring based on email behavior
  - Temporal correlation for time-based patterns
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{Correlator, Evidence}
  alias TamanduaServer.Alerts
  alias TamanduaServer.Telemetry

  @table_name :email_correlations
  @attachment_table :email_attachments
  @user_risk_table :email_user_risk
  @chain_table :email_attack_chains

  # Correlation time window
  @default_correlation_window :timer.hours(24)

  # State structure
  defstruct [
    :correlation_window,
    :stats,
    :config
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Start the Email Correlator.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Correlate an email event with endpoint telemetry.
  """
  @spec correlate_email(map()) :: {:ok, map()} | {:error, term()}
  def correlate_email(email_event) do
    GenServer.call(__MODULE__, {:correlate_email, email_event})
  end

  @doc """
  Track an attachment from email.
  """
  @spec track_attachment(map()) :: :ok
  def track_attachment(attachment) do
    GenServer.cast(__MODULE__, {:track_attachment, attachment})
  end

  @doc """
  Correlate a file event with tracked attachments.
  """
  @spec correlate_file_event(map()) :: {:ok, map() | nil}
  def correlate_file_event(file_event) do
    GenServer.call(__MODULE__, {:correlate_file_event, file_event})
  end

  @doc """
  Correlate a process event with email-originated files.
  """
  @spec correlate_process_event(map()) :: {:ok, map() | nil}
  def correlate_process_event(process_event) do
    GenServer.call(__MODULE__, {:correlate_process_event, process_event})
  end

  @doc """
  Build attack chain for an email.
  """
  @spec build_attack_chain(String.t()) :: {:ok, map()} | {:error, :not_found}
  def build_attack_chain(email_id) do
    GenServer.call(__MODULE__, {:build_attack_chain, email_id})
  end

  @doc """
  Get attack chains for a user.
  """
  @spec get_user_chains(String.t(), keyword()) :: {:ok, [map()]}
  def get_user_chains(user_email, opts \\ []) do
    GenServer.call(__MODULE__, {:get_user_chains, user_email, opts})
  end

  @doc """
  Get user risk score based on email activity.
  """
  @spec get_user_risk(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_user_risk(user_email) do
    GenServer.call(__MODULE__, {:get_user_risk, user_email})
  end

  @doc """
  List all active attack chains.
  """
  @spec list_attack_chains(keyword()) :: {:ok, [map()]}
  def list_attack_chains(opts \\ []) do
    GenServer.call(__MODULE__, {:list_attack_chains, opts})
  end

  @doc """
  Get correlation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Manually trigger cleanup of old correlations.
  """
  @spec cleanup() :: :ok
  def cleanup do
    GenServer.cast(__MODULE__, :cleanup)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS tables
    :ets.new(@table_name, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@attachment_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@user_risk_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@chain_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_cleanup()

    state = %__MODULE__{
      correlation_window: Keyword.get(opts, :correlation_window, @default_correlation_window),
      config: %{
        auto_create_alerts: Keyword.get(opts, :auto_create_alerts, true),
        min_chain_severity: Keyword.get(opts, :min_chain_severity, :medium)
      },
      stats: %{
        emails_correlated: 0,
        attachments_tracked: 0,
        files_correlated: 0,
        processes_correlated: 0,
        chains_built: 0,
        alerts_created: 0
      }
    }

    Logger.info("Email Correlator started")
    {:ok, state}
  end

  @impl true
  def handle_call({:correlate_email, email_event}, _from, state) do
    result = do_correlate_email(email_event, state)
    new_state = update_stats(state, :emails_correlated)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:correlate_file_event, file_event}, _from, state) do
    result = do_correlate_file_event(file_event, state)
    new_state = if match?({:ok, %{matched: true}}, result) do
      update_stats(state, :files_correlated)
    else
      state
    end
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:correlate_process_event, process_event}, _from, state) do
    result = do_correlate_process_event(process_event, state)
    new_state = if match?({:ok, %{matched: true}}, result) do
      update_stats(state, :processes_correlated)
    else
      state
    end
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:build_attack_chain, email_id}, _from, state) do
    result = do_build_attack_chain(email_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_user_chains, user_email, opts}, _from, state) do
    result = do_get_user_chains(user_email, opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:get_user_risk, user_email}, _from, state) do
    result = do_get_user_risk(user_email)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_attack_chains, opts}, _from, state) do
    result = do_list_attack_chains(opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:track_attachment, attachment}, state) do
    do_track_attachment(attachment)
    new_state = update_stats(state, :attachments_tracked)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast(:cleanup, state) do
    do_cleanup(state.correlation_window)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup(state.correlation_window)
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Email Correlation
  # ============================================================================

  defp do_correlate_email(email_event, state) do
    email_id = email_event[:id] || email_event[:message_id]
    recipient = email_event[:recipient] || email_event[:to]
    sender = email_event[:sender] || email_event[:from]
    timestamp = email_event[:timestamp] || DateTime.utc_now()

    # Store email event for correlation
    correlation_entry = %{
      email_id: email_id,
      recipient: recipient,
      sender: sender,
      subject: email_event[:subject],
      timestamp: timestamp,
      attachments: email_event[:attachments] || [],
      urls: email_event[:urls] || [],
      threat_type: email_event[:threat_type],
      verdict: email_event[:verdict],
      confidence: email_event[:confidence] || 0.5,
      source: email_event[:source],
      correlated_events: [],
      chain_stage: :email_received
    }

    :ets.insert(@table_name, {email_id, correlation_entry})

    # Track attachments for file correlation
    Enum.each(email_event[:attachments] || [], fn attachment ->
      do_track_attachment(Map.merge(attachment, %{
        email_id: email_id,
        recipient: recipient,
        timestamp: timestamp
      }))
    end)

    # Update user risk
    update_user_risk(recipient, email_event)

    # Check for existing endpoint correlations
    existing_correlations = find_endpoint_correlations(email_event, state)

    result = %{
      email_id: email_id,
      correlations_found: length(existing_correlations),
      correlations: existing_correlations,
      user_risk: do_get_user_risk(recipient)
    }

    # Create alert if chain detected
    if length(existing_correlations) > 0 and state.config.auto_create_alerts do
      create_chain_alert(email_event, existing_correlations)
    end

    {:ok, result}
  end

  defp do_track_attachment(attachment) do
    # Create multiple lookup keys
    hash = attachment[:sha256] || attachment["sha256"]
    filename = attachment[:filename] || attachment["filename"] || attachment[:name]
    email_id = attachment[:email_id]

    entry = %{
      email_id: email_id,
      filename: filename,
      sha256: hash,
      md5: attachment[:md5] || attachment["md5"],
      sha1: attachment[:sha1] || attachment["sha1"],
      content_type: attachment[:content_type] || attachment["content_type"],
      size: attachment[:size] || attachment["size"],
      recipient: attachment[:recipient],
      timestamp: attachment[:timestamp] || DateTime.utc_now(),
      file_events: [],
      process_events: []
    }

    # Store by hash if available
    if hash do
      :ets.insert(@attachment_table, {{:hash, hash}, entry})
    end

    # Store by filename
    if filename do
      :ets.insert(@attachment_table, {{:filename, filename}, entry})
    end

    # Store by email_id
    if email_id do
      :ets.insert(@attachment_table, {{:email, email_id}, entry})
    end
  end

  # ============================================================================
  # File Event Correlation
  # ============================================================================

  defp do_correlate_file_event(file_event, state) do
    payload = file_event[:payload] || file_event["payload"] || %{}
    path = payload[:path] || payload["path"]
    sha256 = payload[:sha256] || payload["sha256"]
    filename = if path, do: Path.basename(path), else: nil

    # Look up by hash first (most reliable)
    matches = if sha256 do
      case :ets.lookup(@attachment_table, {:hash, sha256}) do
        [{_, entry}] -> [entry]
        [] -> []
      end
    else
      []
    end

    # Fall back to filename matching
    matches = if Enum.empty?(matches) and filename do
      case :ets.lookup(@attachment_table, {:filename, filename}) do
        [{_, entry}] -> [entry]
        [] -> []
      end
    else
      matches
    end

    if Enum.empty?(matches) do
      {:ok, %{matched: false}}
    else
      # Found a match - update correlation
      match = List.first(matches)

      # Update the attachment entry with file event
      updated_entry = %{match |
        file_events: [file_event | match.file_events]
      }

      if sha256 do
        :ets.insert(@attachment_table, {{:hash, sha256}, updated_entry})
      end

      # Update email correlation
      if match.email_id do
        update_email_correlation(match.email_id, :file_created, file_event)
      end

      # Update attack chain
      update_attack_chain(match.email_id, :attachment_saved, file_event, state)

      {:ok, %{
        matched: true,
        email_id: match.email_id,
        attachment: match,
        chain_stage: :attachment_saved
      }}
    end
  end

  # ============================================================================
  # Process Event Correlation
  # ============================================================================

  defp do_correlate_process_event(process_event, state) do
    payload = process_event[:payload] || process_event["payload"] || %{}
    path = payload[:path] || payload["path"]
    sha256 = payload[:sha256] || payload["sha256"]

    # Try to match process with tracked attachments
    matches = []

    # Match by hash
    matches = if sha256 do
      case :ets.lookup(@attachment_table, {:hash, sha256}) do
        [{_, entry}] -> [entry]
        [] -> matches
      end
    else
      matches
    end

    # Match by path containing tracked filename
    matches = if Enum.empty?(matches) and path do
      :ets.tab2list(@attachment_table)
      |> Enum.filter(fn {{type, _}, entry} ->
        type == :filename and
        entry.filename != nil and
        String.contains?(path || "", entry.filename)
      end)
      |> Enum.map(fn {_, entry} -> entry end)
    else
      matches
    end

    if Enum.empty?(matches) do
      {:ok, %{matched: false}}
    else
      match = List.first(matches)

      # Critical correlation: attachment was executed!
      updated_entry = %{match |
        process_events: [process_event | match.process_events]
      }

      if match.sha256 do
        :ets.insert(@attachment_table, {{:hash, match.sha256}, updated_entry})
      end

      # Update email correlation with execution event
      if match.email_id do
        update_email_correlation(match.email_id, :attachment_executed, process_event)
      end

      # Critical: attachment execution detected - create alert
      update_attack_chain(match.email_id, :payload_executed, process_event, state)

      # Build complete chain. The attachment match can outlive the email entry
      # (separate ETS tables with independent TTL/cleanup), so do_build_attack_chain
      # may return {:error, :not_found}; degrade to a nil chain instead of crashing
      # this GenServer on a hot correlation path.
      chain =
        case do_build_attack_chain(match.email_id) do
          {:ok, chain} -> chain
          {:error, _reason} -> nil
        end

      # Create high-severity alert for email-to-execution chain
      if state.config.auto_create_alerts and chain do
        create_execution_alert(match, process_event, chain)
      end

      {:ok, %{
        matched: true,
        email_id: match.email_id,
        attachment: match,
        chain_stage: :payload_executed,
        attack_chain: chain
      }}
    end
  end

  # ============================================================================
  # Attack Chain Building
  # ============================================================================

  defp do_build_attack_chain(email_id) do
    case :ets.lookup(@table_name, email_id) do
      [{^email_id, email_entry}] ->
        # Get all attachments for this email
        attachments = case :ets.lookup(@attachment_table, {:email, email_id}) do
          [{_, att}] -> [att]
          [] ->
            # Try to find by hash from email entry
            (email_entry.attachments || [])
            |> Enum.flat_map(fn att ->
              hash = att[:sha256] || att["sha256"]
              if hash do
                case :ets.lookup(@attachment_table, {:hash, hash}) do
                  [{_, entry}] -> [entry]
                  [] -> []
                end
              else
                []
              end
            end)
        end

        # Build timeline of events
        timeline = build_chain_timeline(email_entry, attachments)

        # Calculate chain risk score
        risk_score = calculate_chain_risk(email_entry, attachments, timeline)

        chain = %{
          id: "chain-#{email_id}",
          email_id: email_id,
          email: %{
            sender: email_entry.sender,
            recipient: email_entry.recipient,
            subject: email_entry.subject,
            timestamp: email_entry.timestamp,
            verdict: email_entry.verdict,
            threat_type: email_entry.threat_type
          },
          attachments: Enum.map(attachments, fn att ->
            %{
              filename: att.filename,
              sha256: att.sha256,
              content_type: att.content_type,
              was_saved: length(att.file_events) > 0,
              was_executed: length(att.process_events) > 0
            }
          end),
          timeline: timeline,
          stages_completed: count_stages(timeline),
          risk_score: risk_score,
          severity: risk_to_severity(risk_score),
          built_at: DateTime.utc_now()
        }

        # Cache the chain
        :ets.insert(@chain_table, {email_id, chain})

        {:ok, chain}

      [] ->
        {:error, :not_found}
    end
  end

  defp build_chain_timeline(email_entry, attachments) do
    events = []

    # Stage 1: Email received
    events = [%{
      stage: :email_received,
      timestamp: email_entry.timestamp,
      description: "Email received from #{email_entry.sender}",
      details: %{
        subject: email_entry.subject,
        verdict: email_entry.verdict
      }
    } | events]

    # Stage 2: Attachments saved
    file_events = Enum.flat_map(attachments, fn att ->
      Enum.map(att.file_events, fn file_event ->
        payload = file_event[:payload] || file_event["payload"] || %{}
        %{
          stage: :attachment_saved,
          timestamp: file_event[:timestamp],
          description: "Attachment saved: #{att.filename}",
          details: %{
            path: payload[:path] || payload["path"],
            sha256: att.sha256
          }
        }
      end)
    end)
    events = events ++ file_events

    # Stage 3: Attachments executed
    process_events = Enum.flat_map(attachments, fn att ->
      Enum.map(att.process_events, fn proc_event ->
        payload = proc_event[:payload] || proc_event["payload"] || %{}
        %{
          stage: :payload_executed,
          timestamp: proc_event[:timestamp],
          description: "Payload executed: #{att.filename}",
          details: %{
            pid: payload[:pid] || payload["pid"],
            path: payload[:path] || payload["path"],
            cmdline: payload[:cmdline] || payload["cmdline"],
            user: payload[:user] || payload["user"]
          }
        }
      end)
    end)
    events = events ++ process_events

    # Sort by timestamp
    events
    |> Enum.sort_by(fn e -> e.timestamp end)
  end

  defp count_stages(timeline) do
    timeline
    |> Enum.map(fn e -> e.stage end)
    |> Enum.uniq()
    |> length()
  end

  defp calculate_chain_risk(email_entry, attachments, timeline) do
    base_score = case email_entry.verdict do
      :malicious -> 0.7
      :suspicious -> 0.4
      :benign -> 0.1
      _ -> 0.3
    end

    # Increase risk for each stage completed
    stage_count = count_stages(timeline)
    stage_bonus = stage_count * 0.1

    # Increase risk if attachments were executed
    execution_bonus = if Enum.any?(attachments, fn att -> length(att.process_events) > 0 end) do
      0.3
    else
      0.0
    end

    # Increase risk for dangerous attachment types
    dangerous_bonus = if Enum.any?(attachments, fn att ->
      ext = Path.extname(att.filename || "") |> String.downcase()
      ext in [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll"]
    end) do
      0.1
    else
      0.0
    end

    min(1.0, base_score + stage_bonus + execution_bonus + dangerous_bonus)
  end

  defp risk_to_severity(risk) when risk >= 0.8, do: :critical
  defp risk_to_severity(risk) when risk >= 0.6, do: :high
  defp risk_to_severity(risk) when risk >= 0.4, do: :medium
  defp risk_to_severity(_), do: :low

  # ============================================================================
  # User Risk Scoring
  # ============================================================================

  defp update_user_risk(nil, _email_event), do: :ok
  defp update_user_risk(user_email, email_event) do
    current = case :ets.lookup(@user_risk_table, user_email) do
      [{^user_email, risk}] -> risk
      [] -> %{
        email: user_email,
        total_emails: 0,
        malicious_emails: 0,
        suspicious_emails: 0,
        attachments_opened: 0,
        payloads_executed: 0,
        risk_score: 0.0,
        last_activity: nil,
        attack_chains: []
      }
    end

    verdict = email_event[:verdict]

    updated = %{current |
      total_emails: current.total_emails + 1,
      malicious_emails: if(verdict == :malicious, do: current.malicious_emails + 1, else: current.malicious_emails),
      suspicious_emails: if(verdict == :suspicious, do: current.suspicious_emails + 1, else: current.suspicious_emails),
      last_activity: DateTime.utc_now()
    }

    # Recalculate risk score
    risk_score = calculate_user_risk_score(updated)
    updated = %{updated | risk_score: risk_score}

    :ets.insert(@user_risk_table, {user_email, updated})
  end

  defp calculate_user_risk_score(user_data) do
    base = 0.0

    # Risk from malicious emails
    if user_data.total_emails > 0 do
      malicious_ratio = user_data.malicious_emails / user_data.total_emails
      suspicious_ratio = user_data.suspicious_emails / user_data.total_emails

      base = base + (malicious_ratio * 0.5) + (suspicious_ratio * 0.2)
    end

    # High risk for payload execution
    base = if user_data.payloads_executed > 0 do
      min(1.0, base + 0.3)
    else
      base
    end

    # Moderate risk for attachment opens
    base = if user_data.attachments_opened > 0 do
      min(1.0, base + 0.1)
    else
      base
    end

    min(1.0, base)
  end

  defp do_get_user_risk(nil), do: {:error, :not_found}
  defp do_get_user_risk(user_email) do
    case :ets.lookup(@user_risk_table, user_email) do
      [{^user_email, risk}] -> {:ok, risk}
      [] -> {:error, :not_found}
    end
  end

  defp do_get_user_chains(user_email, opts) do
    limit = Keyword.get(opts, :limit, 50)

    :ets.tab2list(@chain_table)
    |> Enum.filter(fn {_id, chain} ->
      chain.email.recipient == user_email
    end)
    |> Enum.map(fn {_, chain} -> chain end)
    |> Enum.sort_by(fn c -> c.built_at end, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp do_list_attack_chains(opts) do
    limit = Keyword.get(opts, :limit, 100)
    min_severity = Keyword.get(opts, :min_severity)

    chains = :ets.tab2list(@chain_table)
    |> Enum.map(fn {_, chain} -> chain end)

    chains = if min_severity do
      severity_order = %{critical: 4, high: 3, medium: 2, low: 1}
      min_order = Map.get(severity_order, min_severity, 0)
      Enum.filter(chains, fn c ->
        Map.get(severity_order, c.severity, 0) >= min_order
      end)
    else
      chains
    end

    chains
    |> Enum.sort_by(fn c -> c.risk_score end, :desc)
    |> Enum.take(limit)
  end

  # ============================================================================
  # Correlation Helpers
  # ============================================================================

  defp find_endpoint_correlations(email_event, state) do
    # Look for existing file/process events that match email attachments
    window = state.correlation_window
    now = System.system_time(:millisecond)

    attachments = email_event[:attachments] || []

    Enum.flat_map(attachments, fn attachment ->
      hash = attachment[:sha256] || attachment["sha256"]

      if hash do
        # Look up in attachment table
        case :ets.lookup(@attachment_table, {:hash, hash}) do
          [{_, entry}] ->
            correlations = []

            # Check for file events
            correlations = if length(entry.file_events) > 0 do
              [%{type: :file_correlation, events: entry.file_events} | correlations]
            else
              correlations
            end

            # Check for process events
            correlations = if length(entry.process_events) > 0 do
              [%{type: :process_correlation, events: entry.process_events} | correlations]
            else
              correlations
            end

            correlations

          [] ->
            []
        end
      else
        []
      end
    end)
  end

  defp update_email_correlation(email_id, event_type, event) do
    case :ets.lookup(@table_name, email_id) do
      [{^email_id, entry}] ->
        updated = %{entry |
          correlated_events: [{event_type, event} | entry.correlated_events],
          chain_stage: event_type
        }
        :ets.insert(@table_name, {email_id, updated})
      [] ->
        :ok
    end
  end

  defp update_attack_chain(nil, _stage, _event, _state), do: :ok
  defp update_attack_chain(email_id, stage, _event, _state) do
    # Rebuild chain with new information
    do_build_attack_chain(email_id)
    :ok
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_chain_alert(email_event, correlations) do
    file_count = Enum.count(correlations, fn c -> c.type == :file_correlation end)
    process_count = Enum.count(correlations, fn c -> c.type == :process_correlation end)

    severity = cond do
      process_count > 0 -> :critical
      file_count > 0 -> :high
      true -> :medium
    end

    title = cond do
      process_count > 0 -> "Email Attack Chain: Payload Executed"
      file_count > 0 -> "Email Attack Chain: Attachment Saved"
      true -> "Email Attack Chain: Correlation Detected"
    end

    Alerts.create_alert(%{
      severity: severity,
      title: title,
      description: """
      Attack chain detected from email:
      - From: #{email_event[:sender]}
      - To: #{email_event[:recipient]}
      - Subject: #{email_event[:subject]}

      Correlations:
      - Files saved: #{file_count}
      - Processes executed: #{process_count}

      This indicates a potential phishing attack that progressed to endpoint activity.
      """,
      event_ids:
        correlations
        |> Enum.flat_map(fn c -> c.events end)
        |> Enum.map(fn e -> e[:event_id] || e["event_id"] end)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq(),
      mitre_tactics: ["initial-access", "execution"],
      mitre_techniques: ["T1566.001", "T1204.002"],
      threat_score: 0.8,
      metadata: %{
        email_id: email_event[:id],
        sender: email_event[:sender],
        recipient: email_event[:recipient],
        chain_type: "email_to_endpoint"
      }
    })
  end

  defp create_execution_alert(attachment, process_event, chain) do
    payload = process_event[:payload] || process_event["payload"] || %{}

    Alerts.create_alert(%{
      severity: :critical,
      title: "Critical: Email Attachment Executed",
      description: """
      A file from an email attachment was executed on the endpoint.

      Email Details:
      - Recipient: #{attachment.recipient}
      - Attachment: #{attachment.filename}
      - SHA256: #{attachment.sha256}

      Execution Details:
      - Process: #{payload[:path] || payload["path"]}
      - PID: #{payload[:pid] || payload["pid"]}
      - User: #{payload[:user] || payload["user"]}
      - Command Line: #{payload[:cmdline] || payload["cmdline"]}

      Attack Chain:
      - Stages completed: #{chain.stages_completed}
      - Risk score: #{Float.round(chain.risk_score * 100, 1)}%

      This is a critical indicator of a successful phishing attack.
      Immediate investigation and remediation recommended.
      """,
      agent_id: process_event[:agent_id],
      event_ids: [process_event[:event_id]],
      evidence: %{
        file_hashes: [%{sha256: attachment.sha256, path: payload[:path] || payload["path"]}],
        process: payload,
        detection: %{
          rule_name: "Email Attachment Execution",
          rule_type: "email_correlation",
          confidence: 0.95
        }
      },
      mitre_tactics: ["initial-access", "execution"],
      mitre_techniques: ["T1566.001", "T1204.002"],
      threat_score: 0.95,
      metadata: %{
        email_id: attachment.email_id,
        attachment_filename: attachment.filename,
        chain_id: chain.id
      }
    })
  end

  # ============================================================================
  # Cleanup
  # ============================================================================

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end

  defp do_cleanup(window) do
    now = System.system_time(:millisecond)
    threshold = now - window

    # Clean old correlations
    :ets.tab2list(@table_name)
    |> Enum.each(fn {key, entry} ->
      ts = entry.timestamp
      if is_struct(ts, DateTime) do
        ts_ms = DateTime.to_unix(ts, :millisecond)
        if ts_ms < threshold do
          :ets.delete(@table_name, key)
        end
      end
    end)

    # Clean old attachments
    :ets.tab2list(@attachment_table)
    |> Enum.each(fn {key, entry} ->
      ts = entry.timestamp
      if is_struct(ts, DateTime) do
        ts_ms = DateTime.to_unix(ts, :millisecond)
        if ts_ms < threshold do
          :ets.delete(@attachment_table, key)
        end
      end
    end)

    Logger.debug("Email correlator cleanup completed")
  end

  defp update_stats(state, key) do
    new_stats = Map.update(state.stats, key, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
