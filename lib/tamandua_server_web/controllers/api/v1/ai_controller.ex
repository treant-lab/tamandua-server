defmodule TamanduaServerWeb.API.V1.AIController do
  @moduledoc """
  AI Assistant endpoints for natural language queries, detection explanations,
  action suggestions, IOC extraction, and hunt query generation.
  """
  use TamanduaServerWeb, :controller

  import Ecto.Query

  alias TamanduaServer.AI.QueryInterface
  alias TamanduaServer.Accounts
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Process a natural language query against the security data.

  ## Parameters
    - query: The natural language query string
    - context: Optional context for the query (e.g., time range, scope)
  """
  def query(conn, params) do
    with {:ok, query} <- fetch_required(params, "query"),
         result <- QueryInterface.process_query(query, query_context_opts(conn, Map.get(params, "context", %{}))) do
      json(conn, %{
        status: "success",
        data: result
      })
    end
  end

  @doc """
  Get an AI-generated explanation for a specific detection or alert.

  ## Parameters
    - detection_id: The ID of the detection to explain
    - detail_level: Optional level of detail (brief, standard, detailed)
  """
  def explain_detection(conn, %{"detection_id" => detection_id} = params) do
    detail_level = Map.get(params, "detail_level", "standard")

    case QueryInterface.explain_detection(detection_id,
           detail_level: detail_level,
           organization_id: current_organization_id(conn)
         ) do
      {:ok, explanation} ->
        json(conn, %{
          status: "success",
          data: %{
            detection_id: detection_id,
            explanation: explanation
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "Detection not found"})

      {:error, :missing_tenant_context} ->
        conn
        |> put_status(:forbidden)
        |> json(%{status: "error", message: "Tenant context is required"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: "Unable to explain detection", reason: inspect(reason)})
    end
  end

  def explain_detection(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "detection_id is required"})
  end

  @doc """
  Get AI-suggested response actions for an alert or incident.

  ## Parameters
    - alert_id: The ID of the alert
    - incident_context: Optional additional context about the incident
  """
  def suggest_actions(conn, %{"alert_id" => alert_id} = params) do
    context = Map.get(params, "incident_context", %{})

    case QueryInterface.suggest_actions(alert_id,
           context: context,
           organization_id: current_organization_id(conn)
         ) do
      {:ok, suggestions} ->
        json(conn, %{
          status: "success",
          data: %{
            alert_id: alert_id,
            suggested_actions: suggestions
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "Alert not found"})

      {:error, :missing_tenant_context} ->
        conn
        |> put_status(:forbidden)
        |> json(%{status: "error", message: "Tenant context is required"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: "Unable to suggest actions", reason: inspect(reason)})
    end
  end

  def suggest_actions(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "alert_id is required"})
  end

  @doc """
  Extract Indicators of Compromise (IOCs) from text or logs.

  ## Parameters
    - content: The text content to analyze for IOCs
    - content_type: Type of content (log, email, report, raw_text)
  """
  def extract_iocs(conn, %{"content" => content} = params) do
    content_type = Map.get(params, "content_type", "raw_text")

    with {:ok, iocs} <- QueryInterface.extract_iocs(content, content_type) do
      json(conn, %{
        status: "success",
        data: %{
          iocs: iocs,
          content_type: content_type,
          extracted_at: DateTime.utc_now()
        }
      })
    end
  end

  def extract_iocs(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "content is required"})
  end

  @doc """
  Generate a threat hunting query from natural language description.

  ## Parameters
    - description: Natural language description of what to hunt for
    - query_language: Target query language (kql, sigma, yara, splunk)
    - time_range: Optional time range for the query
  """
  def generate_hunt_query(conn, %{"description" => description} = params) do
    query_language = Map.get(params, "query_language", "kql")
    time_range = Map.get(params, "time_range")

    opts = [query_language: query_language]
    opts = if time_range, do: Keyword.put(opts, :time_range, time_range), else: opts

    with {:ok, generated_query} <- QueryInterface.generate_hunt_query(description, opts) do
      json(conn, %{
        status: "success",
        data: %{
          query: generated_query,
          language: query_language,
          description: description
        }
      })
    end
  end

  def generate_hunt_query(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "description is required"})
  end

  # ===========================================================================
  # AI Chat (conversational endpoint with server-side persistence)
  # ===========================================================================

  alias TamanduaServer.AI.ConversationStore

  @doc """
  Handle a chat message from the AI Assistant page.

  Accepts `message`, optional `conversation_id`, and optional `context`.
  Returns the assistant response and persists the conversation server-side.
  """
  def chat(conn, %{"message" => message} = params) do
    user_id = get_user_id(conn)
    conversation_id = params["conversation_id"]
    context = params["context"] || %{}
    organization_id = current_organization_id(conn)
    response_language = detect_response_language(message)

    # Handle the special welcome message
    if message == "__welcome__" do
      # Build a welcome response with environment-aware content
      env = context["environment"] || %{}
      active_agents = env["activeAgents"] || 0
      open_alerts = env["openAlerts"] || 0

      welcome_text = """
      Hello! I'm your AI Security Assistant powered by Tamandua EDR. I can help you with:

      - **Threat Analysis**: Understand current threats and attack patterns
      - **Hunting Queries**: Build and execute threat hunting queries
      - **Response Guidance**: Get recommendations for incident response
      - **Context & Learning**: Explain detections, MITRE techniques, and security concepts

      Currently monitoring #{active_agents} agent(s) with #{open_alerts} open alert(s). How can I assist you today?
      """

      json(conn, %{
        data: %{
          message: String.trim(welcome_text),
          conversation_id: nil,
          suggested_actions: [
            %{label: "Review open alerts", type: "investigation", action: "Show me all open high-severity alerts"},
            %{label: "Threat summary", type: "info", action: "Provide a current threat landscape summary"},
            %{label: "Start hunt", type: "query", action: "Help me create a threat hunting query"}
          ]
        }
      })
    else
      # Regular chat message - answer common analyst intents from real data,
      # then fall back to the broader natural-language query interface.
      result = try do
        run_chat_query(conn, message, context, conversation_id)
      rescue
        e ->
          Logger.warning("AI chat query failed: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      catch
        kind, reason ->
          Logger.warning("AI chat query crashed: #{kind} #{inspect(reason)}")
          {:error, reason}
      end

      response_message =
        case result do
          {:ok, data} when is_map(data) -> data[:message] || data[:summary] || inspect(data)
          {:ok, text} when is_binary(text) -> text
          {:error, reason} -> "I encountered an issue: #{inspect(reason)}"
          _ -> "I'm processing your request."
        end
        |> localize_assistant_message(response_language)

      # Persist conversation
      prev_messages = case conversation_id do
        nil -> []
        id ->
          try do
            case ConversationStore.get_conversation(user_id, id) do
              {:ok, conv} -> conv.messages || []
              _ -> []
            end
          catch
            kind, reason ->
              Logger.warning("AI chat conversation lookup failed: #{kind} #{inspect(reason)}")
              []
          end
      end

      now = DateTime.to_iso8601(DateTime.utc_now())
      updated_messages =
        (prev_messages ++ [
           %{role: "user", content: message, timestamp: now},
           %{role: "assistant", content: response_message, timestamp: now}
         ])
        |> compact_conversation_messages(organization_id)

      title = case Enum.find(updated_messages, fn m -> m[:role] == "user" || m["role"] == "user" end) do
        nil -> "Conversation"
        msg -> String.slice(msg[:content] || msg["content"] || "", 0, 60)
      end

      saved_conversation_id =
        try do
          case ConversationStore.save_conversation(user_id, conversation_id, title, updated_messages) do
            {:ok, conv} ->
              conv.id

            {:error, reason} ->
              Logger.warning("AI chat conversation persistence failed: #{inspect(reason)}")
              conversation_id
          end
        catch
          kind, reason ->
            Logger.warning("AI chat conversation persistence crashed: #{kind} #{inspect(reason)}")
            conversation_id
        end

      json(conn, %{
        data: %{
          message: response_message,
          conversation_id: saved_conversation_id,
          suggested_actions:
            result
            |> chat_suggestions_from_result(message)
            |> localize_suggested_actions(response_language)
        }
      })
    end
  end

  def chat(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "message is required"})
  end

  @doc """
  List saved conversations for the current user.
  """
  def list_conversations(conn, _params) do
    user_id = get_user_id(conn)
    conversations =
      try do
        ConversationStore.list_conversations(user_id)
      catch
        kind, reason ->
          Logger.warning("AI conversation list failed: #{kind} #{inspect(reason)}")
          []
      end

    json(conn, %{data: conversations})
  end

  @doc """
  Get a specific conversation by ID.
  """
  def get_conversation(conn, %{"id" => id}) do
    case ConversationStore.get_conversation(get_user_id(conn), id) do
      {:ok, conversation} ->
        json(conn, %{data: conversation})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "Conversation not found"})
    end
  end

  @doc """
  Save a conversation (create or update).
  """
  def save_conversation(conn, params) do
    user_id = get_user_id(conn)
    conversation_id = params["conversation_id"]
    title = params["title"] || "Untitled"
    messages = params["messages"] || []

    try do
      case ConversationStore.save_conversation(user_id, conversation_id, title, messages) do
        {:ok, conversation} ->
          json(conn, %{data: conversation})

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{status: "error", message: "Conversation not found"})

        {:error, reason} ->
          conn
          |> put_status(:service_unavailable)
          |> json(%{status: "error", message: "Conversation persistence failed", reason: inspect(reason)})
      end
    catch
      kind, reason ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Conversation persistence unavailable", reason: "#{kind}: #{inspect(reason)}"})
    end
  end

  @doc """
  Delete a conversation.
  """
  def delete_conversation(conn, %{"id" => id}) do
    ConversationStore.delete_conversation(get_user_id(conn), id)
    json(conn, %{status: "ok"})
  end

  @doc """
  Generate context-aware suggestions based on the current environment state.
  """
  def suggestions(conn, params) do
    context = params["context"] || %{}
    env = context["environment"] || %{}
    open_alerts = env["openAlerts"] || 0

    base_suggestions = [
      %{icon: "AlertTriangle", label: "Show critical alerts", query: "Show me all critical severity alerts from today"},
      %{icon: "Search", label: "Hunt for lateral movement", query: "Search for lateral movement indicators across all agents"},
      %{icon: "Shield", label: "Detection coverage", query: "What is our current MITRE ATT&CK detection coverage?"},
      %{icon: "Network", label: "Network anomalies", query: "Show unusual network connections in the last 24 hours"}
    ]

    # Add dynamic suggestions based on environment
    dynamic_suggestions = if open_alerts > 0 do
      [%{icon: "Zap", label: "Triage #{open_alerts} alerts", query: "Help me triage the #{open_alerts} open alerts"} | base_suggestions]
    else
      base_suggestions
    end

    recommendations = if open_alerts > 5 do
      [
        %{
          id: "rec-1",
          title: "High alert volume detected",
          description: "#{open_alerts} alerts are currently open. Consider triaging and resolving stale alerts.",
          priority: "high",
          category: "investigation",
          relatedAlerts: open_alerts
        }
      ]
    else
      []
    end

    json(conn, %{
      data: %{
        suggestions: Enum.take(dynamic_suggestions, 6),
        recommendations: recommendations,
        query_history: []
      }
    })
  end

  # ===========================================================================
  # Private helpers
  # ===========================================================================

  defp fetch_required(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when not is_nil(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_required_param, key}
    end
  end

  defp get_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> "anonymous"
      user -> user.id || user[:id] || "anonymous"
    end
  end

  @alert_id_regex ~r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i

  defp run_chat_query(conn, message, context, conversation_id) do
    organization_id = current_organization_id(conn)
    user_id = get_user_id(conn)
    lower = String.downcase(message || "")
    explicit_alert_id = extract_alert_id(message)
    messages = context_messages(context, conversation_id, user_id)
    contextual_alert_ids = contextual_alert_ids(messages, organization_id)
    alert_id = explicit_alert_id || active_alert_id_from_messages(messages, organization_id)

    cond do
      length(contextual_alert_ids) > 1 and multi_alert_summary_intent?(lower) ->
        summarize_context_alerts(contextual_alert_ids, organization_id)

      is_binary(alert_id) and create_investigation_intent?(lower) ->
        create_investigation_from_alert(conn, alert_id, organization_id)

      is_binary(alert_id) and alert_followup_intent?(lower) ->
        investigate_alert_followup(alert_id, organization_id, lower)

      is_binary(explicit_alert_id) ->
        analyze_alert(alert_id, organization_id)

      contains_any?(lower, ["affected host", "hosts affected", "host affected", "hosts afetados", "maquinas afetadas", "máquinas afetadas"]) ->
        affected_hosts_summary(organization_id)

      contains_any?(lower, ["respond", "response", "responder", "critical alerts", "alertas criticos", "alertas críticos", "remediate", "remediar"]) ->
        critical_response_plan(organization_id)

      contains_any?(lower, ["open alert", "open alerts", "critical", "high-severity", "high severity", "alertas abertos", "alertas críticos"]) ->
        open_alerts_summary(organization_id)

      true ->
        result =
          message
          |> QueryInterface.process_query(query_context_opts(conn, context))
          |> normalize_query_result()

        {:ok, result}
    end
  end

  defp context_messages(context, conversation_id, user_id) do
    frontend_messages =
      case context do
        %{} -> context["previous_messages"] || context[:previous_messages] || []
        _ -> []
      end

    stored_messages =
      case conversation_id do
        id when is_binary(id) and id != "" ->
          case ConversationStore.get_conversation(user_id, id) do
            {:ok, conv} -> conv.messages || conv[:messages] || []
            _ -> []
          end

        _ ->
          []
      end

    stored_messages ++ frontend_messages
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  defp message_content(%{"content" => content}) when is_binary(content), do: content
  defp message_content(%{content: content}) when is_binary(content), do: content
  defp message_content(content) when is_binary(content), do: content
  defp message_content(_), do: ""

  defp create_investigation_intent?(lower) do
    contains_any?(lower, [
      "create investigation",
      "open investigation",
      "abrir investigacao",
      "abrir investigação",
      "criar investigacao",
      "criar investigação",
      "start investigation",
      "investigar isso"
    ])
  end

  defp alert_followup_intent?(lower) do
    contains_any?(lower, [
      "resuma",
      "resumo",
      "summarize",
      "summary",
      "o que sao",
      "o que são",
      "what are",
      "explique",
      "detalhe",
      "detalhes",
      "o que aconteceu",
      "what happened",
      "malicioso",
      "malicious",
      "host",
      "hosts",
      "ip",
      "ioc",
      "pivots",
      "pivot",
      "correl",
      "related",
      "relacion",
      "mais",
      "acontecendo",
      "aconteceu",
      "evidence",
      "evidencia",
      "evidência",
      "timeline",
      "storyline",
      "linha do tempo",
      "realmente",
      "validar atividade",
      "atividade administrativa",
      "admin activity"
    ])
  end

  defp multi_alert_summary_intent?(lower) do
    contains_any?(lower, [
      "cada um",
      "cada alerta",
      "esses alertas",
      "estas alertas",
      "these alerts",
      "each one",
      "each alert",
      "resuma",
      "resumo",
      "summarize",
      "summary",
      "o que sao",
      "o que são",
      "what are these"
    ])
  end

  defp analyze_alert(alert_id, organization_id) do
    alert =
      Alert
      |> where([a], a.id == ^alert_id)
      |> maybe_alert_org_scope(organization_id)
      |> preload(:agent)
      |> Repo.one()

    case alert do
      nil ->
        {:ok,
         %{
           message: "I could not find alert `#{alert_id}` in your current organization scope.",
           suggested_actions: [
             %{label: "Show open alerts", type: "investigation", action: "Show me all open high-severity alerts"},
             %{label: "Affected hosts", type: "investigation", action: "Show me all hosts affected by the current alerts"}
           ]
         }}

      alert ->
        {:ok,
         %{
           message: alert_analysis_message(alert),
           suggested_actions: alert_suggested_actions(alert)
         }}
    end
  end

  defp investigate_alert_followup(alert_id, organization_id, lower) do
    case load_alert(alert_id, organization_id) do
      nil ->
        {:ok, %{message: "I could not find alert `#{alert_id}` in your current organization scope."}}

      alert ->
        events = related_events_for_alert(alert, 25)
        related_alerts = related_alerts_for_alert(alert, organization_id, 6)
        suspicious_networks = suspicious_network_indicators(alert, events)

        message =
          cond do
            contains_any?(lower, ["validar atividade", "atividade administrativa", "admin activity", "faz sentido", "realmente"]) ->
              validation_plan_for_alert_message(alert, events, suspicious_networks)

            contains_any?(lower, ["host", "hosts", "maquina", "máquina"]) ->
              affected_hosts_for_alert_message(alert, related_alerts)

            contains_any?(lower, ["malicioso", "malicious", "ip", "ioc", "pivots", "pivot"]) ->
              suspicious_indicators_message(alert, events, suspicious_networks)

            true ->
              deep_alert_explanation_message(alert, events, related_alerts, suspicious_networks)
          end

        {:ok,
         %{
           message: message,
           results: Enum.map(events, &event_result/1),
           result_count: length(events),
           suggested_actions: alert_suggested_actions(alert) ++ [
             %{label: "Create investigation", type: "investigation", action: "Create investigation for alert #{alert.id}"},
             %{label: "Find related IOCs", type: "query", action: "Which hosts and network IOCs look suspicious in this alert?"},
             %{label: "Compact summary", type: "info", action: "Summarize this investigation context so far"}
           ]
         }}
    end
  end

  defp create_investigation_from_alert(conn, alert_id, organization_id) do
    case load_alert(alert_id, organization_id) do
      nil ->
        {:ok, %{message: "I could not find alert `#{alert_id}` in your current organization scope."}}

      alert ->
        user_id = get_user_id(conn)

        attrs = %{
          title: "Investigation: #{alert.title || alert.id}",
          description: investigation_description(alert),
          severity: normalize_case_severity(alert.severity),
          created_by: user_id,
          alert_ids: [alert.id],
          event_ids: Enum.uniq([alert.source_event_id | (alert.event_ids || [])] |> Enum.reject(&is_nil/1)),
          tags: ["ai-assistant", "alert-triage", alert.title || "alert"],
          mitre_tactics: alert.mitre_tactics || [],
          mitre_techniques: alert.mitre_techniques || [],
          organization_id: organization_id
        }

        case Investigations.create_investigation(attrs) do
          {:ok, investigation} ->
            {:ok,
             %{
               message: """
               **Investigation created**

               Created case `#{investigation.id}` for alert `#{alert.id}`.

               - Title: #{investigation.title}
               - Severity: #{String.upcase(investigation.severity || "unknown")}
               - Linked alerts: #{length(investigation.alert_ids || [])}
               - Linked events: #{length(investigation.event_ids || [])}

               Links: `/app/investigations/#{investigation.id}` and `/app/alerts/#{alert.id}`
               """
               |> String.trim(),
               suggested_actions: [
                 %{label: "Open investigation", type: "investigation", kind: "navigate", url: "/app/investigations/#{investigation.id}", action: "Open /app/investigations/#{investigation.id}"},
                 %{label: "Explain alert", type: "info", action: "Explain what happened in alert #{alert.id}"},
                 %{label: "Response plan", type: "response", action: "Help me respond to alert #{alert.id}"}
               ]
             }}

          {:error, changeset} ->
            {:ok,
             %{
               message: "I could not create the investigation for alert `#{alert.id}`: #{inspect(changeset.errors)}",
               suggested_actions: alert_suggested_actions(alert)
             }}
        end
    end
  end

  defp load_alert(alert_id, organization_id) do
    Alert
    |> where([a], a.id == ^alert_id)
    |> maybe_alert_org_scope(organization_id)
    |> preload(:agent)
    |> Repo.one()
  end

  defp related_events_for_alert(alert, limit) do
    organization_id = alert.organization_id

    ids =
      [alert.source_event_id | (alert.event_ids || [])]
      |> Kernel.++(alert.contributing_events || [])
      |> Enum.filter(&valid_uuid?/1)
      |> Enum.uniq()

    by_id =
      if ids == [] do
        []
      else
        Event
        |> where([e], e.id in ^ids)
        |> maybe_event_org_scope(organization_id)
        |> preload(:agent)
        |> Repo.all()
      end

    nearby =
      case alert_time(alert) do
        nil ->
          []

        ts ->
          start_time = DateTime.add(ts, -30 * 60, :second)
          end_time = DateTime.add(ts, 30 * 60, :second)

          Event
          |> where([e], e.agent_id == ^alert.agent_id)
          |> maybe_event_org_scope(organization_id)
          |> where([e], e.timestamp >= ^start_time and e.timestamp <= ^end_time)
          |> order_by([e], desc: e.timestamp)
          |> limit(^limit)
          |> preload(:agent)
          |> Repo.all()
      end

    (by_id ++ nearby)
    |> Enum.uniq_by(& &1.id)
    |> Enum.take(limit)
  end

  defp related_alerts_for_alert(alert, organization_id, limit) do
    Alert
    |> where([a], a.id != ^alert.id)
    |> where([a], a.agent_id == ^alert.agent_id or a.source_event_id == ^alert.source_event_id)
    |> maybe_alert_org_scope(organization_id)
    |> preload(:agent)
    |> order_by([a], desc: a.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  defp deep_alert_explanation_message(alert, events, related_alerts, suspicious_networks) do
    event_lines = Enum.map(events |> Enum.take(8), &event_line/1)
    related_lines = Enum.map(related_alerts, &related_alert_line/1)

    """
    **What likely happened**

    This alert is still in context: `#{alert.id}` - **#{alert.title || "Untitled alert"}** on `#{agent_hostname(alert)}`.

    **Primary finding**
    #{alert.description || "The detector did not provide a detailed description."}

    **Most relevant evidence**
    - Endpoint: `#{agent_hostname(alert)}` (#{agent_status(alert)})
    - Process: #{process_summary(alert, alert.evidence || %{})}
    - Network pivots: #{network_summary(alert.evidence || %{})}
    - Source event: #{alert.source_event_id || "not linked"}
    - MITRE: #{join_or_none(alert.mitre_techniques)}

    **Suspicious hosts / IOCs to review**
    #{format_indicator_lines(suspicious_networks)}

    **Nearby telemetry**
    #{format_lines(event_lines, "No nearby/source events were found for this alert.")}

    **Related alerts on the same endpoint**
    #{format_lines(related_lines, "No related open alerts were found on the same endpoint.")}

    **Analyst interpretation**
    #{alert_interpretation(alert, events, suspicious_networks)}
    """
    |> String.trim()
  end

  defp suspicious_indicators_message(alert, events, suspicious_networks) do
    """
    **Suspicious hosts and network indicators for alert `#{alert.id}`**

    Endpoint: `#{agent_hostname(alert)}`.

    #{format_indicator_lines(suspicious_networks)}

    **Why these matter**
    External remote IPs/domains connected to the process or source event are the strongest pivots for this alert. Internal/private addresses are usually lower priority unless they indicate lateral movement.

    **Observed event types in scope**
    #{events |> Enum.map(& &1.event_type) |> Enum.frequencies() |> Enum.map(fn {k, v} -> "- #{k}: #{v}" end) |> format_lines("No related events available.")}
    """
    |> String.trim()
  end

  defp affected_hosts_for_alert_message(alert, related_alerts) do
    hosts =
      [alert | related_alerts]
      |> Enum.map(&agent_hostname/1)
      |> Enum.reject(&(&1 in [nil, "", "Unknown endpoint"]))
      |> Enum.uniq()

    """
    **Affected hosts for the current alert**

    Primary endpoint: `#{agent_hostname(alert)}` (#{agent_status(alert)}).

    Other hosts directly linked by current alert correlation: #{if hosts == [], do: "none found", else: Enum.map_join(hosts, ", ", &"`#{&1}`")}.

    Related alerts checked: #{length(related_alerts)}.

    I do not see enough evidence here to claim fleet-wide spread. To prove spread, pivot on the remote IP/domain/process and search across all agents.
    """
    |> String.trim()
  end

  defp validation_plan_for_alert_message(alert, events, suspicious_networks) do
    process = plain_process_name(alert, alert.evidence || %{})
    external_values = suspicious_networks |> Enum.filter(& &1.suspicious) |> Enum.map(& &1.value)
    internal_values = suspicious_networks |> Enum.reject(& &1.suspicious) |> Enum.map(& &1.value)
    event_counts = events |> Enum.map(& &1.event_type) |> Enum.frequencies()

    """
    **What we can say from the evidence**

    Alert `#{alert.id}` fired on `#{agent_hostname(alert)}` for **#{alert.title || "Untitled alert"}**.

    - Process: #{format_optional_code(process)}
    - Source event: #{alert.source_event_id || "not linked"}
    - External pivots: #{format_short_values(external_values)}
    - Internal pivots: #{format_short_values(internal_values)}
    - Nearby event mix: #{format_event_counts(event_counts)}

    **Does it make sense?**
    #{alert_interpretation(alert, events, suspicious_networks)}

    **How to validate administrative activity**
    1. Confirm whether `#{agent_hostname(alert)}` is expected to initiate this kind of connection.
    2. Confirm the destination owner and purpose: #{format_short_values(external_values ++ internal_values)}.
    3. Check the process path, signer, parent process, and command line for #{format_optional_code(process)}.
    4. Compare this host against baseline: same process, same destination, same time window in prior days.
    5. Search the same IP/domain/process across other agents before closing or suppressing.

    **Decision**
    If the destination and process are known/admin-approved, this is likely expected activity or a noisy NDR rule. If either is unknown, keep it open and create an investigation with the source event and pivots above.
    """
    |> String.trim()
  end

  defp investigation_description(alert) do
    """
    Created by AI Assistant from alert #{alert.id}.

    Alert: #{alert.title}
    Severity: #{alert.severity}
    Endpoint: #{agent_hostname(alert)}
    Description: #{alert.description}
    Source event: #{alert.source_event_id}
    """
    |> String.trim()
  end

  defp affected_hosts_summary(organization_id) do
    rows =
      Alert
      |> join(:left, [a], ag in Agent, on: ag.id == a.agent_id)
      |> where([a], a.status in ["new", "open", "investigating", "triaged"])
      |> maybe_joined_org_scope(organization_id)
      |> group_by([a, ag], [ag.id, ag.hostname, ag.status, ag.os_type, ag.ip_address])
      |> select([a, ag], %{
        agent_id: ag.id,
        hostname: ag.hostname,
        agent_status: ag.status,
        os_type: ag.os_type,
        ip_address: ag.ip_address,
        alert_count: count(a.id),
        critical_count: fragment("sum(case when ? = 'critical' then 1 else 0 end)", a.severity),
        high_count: fragment("sum(case when ? = 'high' then 1 else 0 end)", a.severity),
        latest_alert_at: max(a.inserted_at)
      })
      |> order_by([a, ag], desc: count(a.id))
      |> limit(15)
      |> Repo.all()

    total_alerts = Enum.reduce(rows, 0, &(&1.alert_count + &2))
    impacted_hosts = Enum.count(rows)

    host_lines =
      rows
      |> Enum.map(fn row ->
        sev = severity_phrase(row.critical_count, row.high_count)
        "- **#{row.hostname || "Unknown host"}** (`#{row.agent_status || "unknown"}`): #{row.alert_count} open alerts#{sev}; latest #{format_datetime(row.latest_alert_at)}"
      end)

    message =
      if rows == [] do
        "No hosts currently have open alerts in your organization scope."
      else
        """
        **Affected hosts**

        #{impacted_hosts} host(s) currently have #{total_alerts} open alert(s).

        #{Enum.join(host_lines, "\n")}

        **Recommended next step**
        - Prioritize hosts with critical/high alerts and online status.
        - Open the highest-severity alert first, review the storyline, then use live response only after evidence review.
        """
        |> String.trim()
      end

    {:ok,
     %{
       message: message,
       results: rows,
       result_count: length(rows),
       suggested_actions: [
         %{label: "Response plan", type: "response", action: "Help me respond to the critical alerts"},
         %{label: "Open critical alerts", type: "investigation", action: "Show me all open high-severity alerts"}
       ]
     }}
  end

  defp critical_response_plan(organization_id) do
    alerts =
      Alert
      |> where([a], a.status in ["new", "open", "investigating", "triaged"])
      |> where([a], a.severity in ["critical", "high"])
      |> maybe_alert_org_scope(organization_id)
      |> preload(:agent)
      |> order_by([a], desc: fragment("case ? when 'critical' then 3 when 'high' then 2 else 1 end", a.severity), desc: a.inserted_at)
      |> limit(10)
      |> Repo.all()

    message =
      if alerts == [] do
        "There are no open critical or high-severity alerts in your current organization scope."
      else
        alert_lines =
          alerts
          |> Enum.with_index(1)
          |> Enum.map(fn {alert, index} ->
            "#{index}. **#{String.upcase(alert.severity || "unknown")}** #{alert.title || "Untitled alert"} on `#{agent_hostname(alert)}` - `/app/alerts/#{alert.id}`"
          end)

        """
        **Critical response plan**

        I found #{length(alerts)} critical/high alert(s) to prioritize:

        #{Enum.join(alert_lines, "\n")}

        **Recommended sequence**
        1. Confirm the top alert evidence and storyline before destructive action.
        2. If the endpoint is online and the evidence indicates active execution, isolate the host.
        3. Kill the suspicious process only after confirming the process tree and parent process.
        4. Quarantine confirmed malicious files and block confirmed network IOCs.
        5. Collect forensic evidence before closing or suppressing recurring alerts.

        **Do not mark as false positive** until the process chain, file evidence, and network pivots are reviewed.
        """
        |> String.trim()
      end

    {:ok,
     %{
       message: message,
       results: Enum.map(alerts, &alert_result/1),
       result_count: length(alerts),
       suggested_actions: [
         %{label: "Affected hosts", type: "investigation", action: "Show me all hosts affected by the current alerts"},
         %{label: "Show alert details", type: "investigation", action: "Show me the details and evidence for these alerts"}
       ]
     }}
  end

  defp open_alerts_summary(organization_id) do
    alerts =
      Alert
      |> where([a], a.status in ["new", "open", "investigating", "triaged"])
      |> maybe_alert_org_scope(organization_id)
      |> preload(:agent)
      |> order_by([a], desc: fragment("case ? when 'critical' then 4 when 'high' then 3 when 'medium' then 2 else 1 end", a.severity), desc: a.inserted_at)
      |> limit(12)
      |> Repo.all()

    severity_counts =
      alerts
      |> Enum.group_by(&(&1.severity || "unknown"))
      |> Enum.map(fn {severity, values} -> "#{severity}: #{length(values)}" end)
      |> Enum.join(", ")

    lines =
      alerts
      |> Enum.with_index(1)
      |> Enum.map(fn {alert, index} ->
        "#{index}. **#{String.upcase(alert.severity || "unknown")}** #{alert.title || "Untitled alert"} on `#{agent_hostname(alert)}` - status `#{alert.status || "unknown"}` - `/app/alerts/#{alert.id}`"
      end)

    message =
      if alerts == [] do
        "No open alerts were found in your current organization scope."
      else
        """
        **Open alert summary**

        Showing the top #{length(alerts)} open alerts by severity and recency.

        Severity mix: #{severity_counts}

        #{Enum.join(lines, "\n")}
        """
        |> String.trim()
      end

    {:ok,
     %{
       message: message,
       results: Enum.map(alerts, &alert_result/1),
       result_count: length(alerts),
       suggested_actions: [
         %{label: "Response plan", type: "response", action: "Help me respond to the critical alerts"},
         %{label: "Affected hosts", type: "investigation", action: "Show me all hosts affected by the current alerts"}
       ]
     }}
  end

  defp summarize_context_alerts(alert_ids, organization_id) do
    alerts =
      alert_ids
      |> load_alerts_by_ids(organization_id)

    duplicate_groups =
      alerts
      |> Enum.group_by(fn alert -> {alert.title || "Untitled alert", agent_hostname(alert), alert.description || ""} end)
      |> Enum.filter(fn {_key, values} -> length(values) > 1 end)

    lines =
      alerts
      |> Enum.with_index(1)
      |> Enum.map(fn {alert, index} -> multi_alert_summary_line(alert, index) end)

    duplicate_note =
      case duplicate_groups do
        [] ->
          "No obvious duplicate cluster was found in this set."

        groups ->
          groups
          |> Enum.map(fn {{title, host, _description}, values} ->
            "- #{length(values)} alerts share the same title and endpoint: **#{title}** on `#{host}`. Treat these as a repeated detector pattern first; investigate one representative alert deeply, then confirm whether timestamps/source events differ."
          end)
          |> Enum.join("\n")
      end

    message =
      if alerts == [] do
        "I could not recover the previous alert list in your current organization scope."
      else
        """
        **Context alert summary**

        I recovered #{length(alerts)} alert(s) from the previous assistant response and loaded their details inside the current organization scope.

        #{Enum.join(lines, "\n\n")}

        **Cluster reading**
        #{duplicate_note}

        **Best next step**
        When many items share the same title, host, and description, do not treat them as independent incidents before validating deduplication. Open one representative alert, review the source event, process, file/path, and timestamp, then compare the remaining IDs to see whether they are repeated firings of the same detector.
        """
        |> String.trim()
      end

    {:ok,
     %{
       message: message,
       results: Enum.map(alerts, &alert_result/1),
       result_count: length(alerts),
       suggested_actions: [
         %{label: "Investigate representative", type: "investigation", action: representative_investigation_action(alerts)},
         %{label: "Group duplicates", type: "investigation", action: "Group these alerts by title, endpoint, source event, and timestamp"},
         %{label: "Response plan", type: "response", action: "Help me respond to this alert cluster"}
       ]
     }}
  end

  defp load_alerts_by_ids(alert_ids, organization_id) do
    ids = alert_ids |> Enum.filter(&valid_uuid?/1) |> Enum.uniq() |> Enum.take(20)

    alerts =
      Alert
      |> where([a], a.id in ^ids)
      |> maybe_alert_org_scope(organization_id)
      |> preload(:agent)
      |> Repo.all()
      |> Map.new(&{&1.id, &1})

    ids
    |> Enum.map(&Map.get(alerts, &1))
    |> Enum.reject(&is_nil/1)
  end

  defp multi_alert_summary_line(alert, index) do
    evidence = alert.evidence || %{}
    source = alert.source_event_id || "not linked"

    """
    #{index}. **#{String.upcase(alert.severity || "unknown")}** `#{alert.id}`
       - What it is: #{alert.title || "Untitled alert"}
       - Host: `#{agent_hostname(alert)}` (#{agent_status(alert)})
       - Why it fired: #{alert.description || "no detector description"}
       - Primary evidence: process #{process_summary(alert, evidence)}; network #{network_summary(evidence)}; file #{file_summary(evidence)}
       - Source event: #{source}
       - Link: `/app/alerts/#{alert.id}`
    """
    |> String.trim()
  end

  defp representative_investigation_action([alert | _]), do: "Explain alert #{alert.id} in detail and check correlated events"
  defp representative_investigation_action(_), do: "Show open alerts"

  defp alert_analysis_message(alert) do
    evidence = alert.evidence || %{}
    detection = alert.detection_metadata || %{}
    public_manifest = alert.public_manifest || %{}

    """
    **Alert analysis: #{alert.title || "Untitled alert"}**

    - Severity: **#{String.upcase(alert.severity || "unknown")}**
    - Status: `#{alert.status || "unknown"}`
    - Endpoint: `#{agent_hostname(alert)}` (#{agent_status(alert)})
    - Threat score: #{format_score(alert.threat_score)}
    - Occurrences: #{alert.occurrence_count || 1}
    - Last seen: #{format_datetime(alert.last_seen_at || alert.inserted_at)}

    **Why it fired**
    #{alert.description || map_value(detection, ["description", :description]) || "No detector description is available."}

    **Correlation and evidence**
    - Rule/detector: #{map_value(detection, ["rule_name", :rule_name, "detector", :detector, "rule_id", :rule_id]) || "not provided"}
    - Source event: #{alert.source_event_id || "not linked"}
    - Contributing events: #{length(alert.contributing_events || [])}
    - Process evidence: #{process_summary(alert, evidence)}
    - Network pivots: #{network_summary(evidence)}
    - File pivots: #{file_summary(evidence)}

    **MITRE mapping**
    - Tactics: #{join_or_none(alert.mitre_tactics)}
    - Techniques: #{join_or_none(alert.mitre_techniques)}

    **On-chain proof**
    #{attestation_summary(alert, public_manifest)}

    **Recommended analyst actions**
    #{recommended_actions_for(alert)}

    Links: `/app/alerts/#{alert.id}` and `/app/storyline/#{alert.id}`
    """
    |> String.trim()
  end

  defp alert_suggested_actions(alert) do
    [
      %{label: "Open storyline", type: "investigation", kind: "navigate", url: "/app/storyline/#{alert.id}", action: "Open /app/storyline/#{alert.id}"},
      %{label: "Create investigation", type: "investigation", kind: "prompt", action: "Create investigation for alert #{alert.id}"},
      %{label: "Find suspicious hosts", type: "query", action: "Which hosts and network IOCs look suspicious in alert #{alert.id}?"},
      %{label: "Response plan", type: "response", action: "Help me respond to alert #{alert.id}"}
    ]
  end

  defp chat_suggestions_from_result({:ok, data}, query) when is_map(data) do
    case data[:suggested_actions] || data["suggested_actions"] do
      actions when is_list(actions) and actions != [] -> actions
      _ -> build_chat_suggestions(query)
    end
  end

  defp chat_suggestions_from_result(_, query), do: build_chat_suggestions(query)

  defp detect_response_language(message) when is_binary(message) do
    lower = String.downcase(message)

    cond do
      contains_any?(lower, [
        "qué",
        "que es la alerta",
        "qué es la alerta",
        "explícame",
        "explicame",
        "detalles",
        "ocurrió",
        "ocurrio",
        "investigación",
        "investigacion",
        "hosts afectados",
        "español",
        "espanol"
      ]) ->
        :es

      contains_any?(lower, [
        "alerta",
        "o que",
        "explique",
        "detalhe",
        "detalhes",
        "aconteceu",
        "correlacion",
        "investigação",
        "investigacao",
        "malicioso",
        "máquinas",
        "maquinas",
        "quais",
        "qual",
        "resuma",
        "resumo",
        "cada um",
        "cada alerta",
        "esses alertas",
        "são",
        "sao",
        "todos os eventos",
        "faz sentido",
        "português",
        "portugues"
      ]) ->
        :pt

      true ->
        :en
    end
  end

  defp detect_response_language(_), do: :en

  defp localize_assistant_message(message, :en), do: message

  defp localize_assistant_message(message, :pt) when is_binary(message) do
    replace_many(message, [
      {"**Alert analysis:", "**Análise do alerta:"},
      {"**What likely happened**", "**O que provavelmente aconteceu**"},
      {"**Primary finding**", "**Achado principal**"},
      {"**Most relevant evidence**", "**Evidências mais relevantes**"},
      {"**Suspicious hosts / IOCs to review**", "**Hosts / IOCs suspeitos para revisar**"},
      {"**Nearby telemetry**", "**Telemetria próxima**"},
      {"**Related alerts on the same endpoint**", "**Alertas relacionados no mesmo endpoint**"},
      {"**Analyst interpretation**", "**Interpretação do analista**"},
      {"**Why it fired**", "**Por que disparou**"},
      {"**Correlation and evidence**", "**Correlação e evidências**"},
      {"**MITRE mapping**", "**Mapeamento MITRE**"},
      {"**On-chain proof**", "**Prova on-chain**"},
      {"**Recommended analyst actions**", "**Ações recomendadas para o analista**"},
      {"**Investigation created**", "**Investigação criada**"},
      {"**Affected hosts**", "**Hosts afetados**"},
      {"**Recommended next step**", "**Próximo passo recomendado**"},
      {"**Critical response plan**", "**Plano de resposta crítica**"},
      {"**Recommended sequence**", "**Sequência recomendada**"},
      {"**Open alert summary**", "**Resumo de alertas abertos**"},
      {"**Context alert summary**", "**Resumo dos alertas em contexto**"},
      {"**Cluster reading**", "**Leitura do cluster**"},
      {"**Best next step**", "**Melhor próximo passo**"},
      {"**What we can say from the evidence**", "**O que dá para afirmar pela evidência**"},
      {"**Does it make sense?**", "**Faz sentido?**"},
      {"**How to validate administrative activity**", "**Como validar se é atividade administrativa**"},
      {"**Decision**", "**Decisão**"},
      {"This alert is still in context:", "Este alerta ainda está em contexto:"},
      {"fired on", "disparou em"},
      {"for **", "para **"},
      {"- Severity:", "- Severidade:"},
      {"- Status:", "- Status:"},
      {"- Endpoint:", "- Endpoint:"},
      {"- External pivots:", "- Pivôs externos:"},
      {"- Internal pivots:", "- Pivôs internos:"},
      {"- Nearby event mix:", "- Mix de eventos próximos:"},
      {"- Threat score:", "- Score de ameaça:"},
      {"- Occurrences:", "- Ocorrências:"},
      {"- Last seen:", "- Visto por último:"},
      {"- Rule/detector:", "- Regra/detector:"},
      {"- Source event:", "- Evento de origem:"},
      {"- What it is:", "- O que é:"},
      {"- Why it fired:", "- Por que disparou:"},
      {"- Primary evidence:", "- Evidência principal:"},
      {"- Contributing events:", "- Eventos contribuintes:"},
      {"- Process evidence:", "- Evidência de processo:"},
      {"- Process:", "- Processo:"},
      {"- Network pivots:", "- Pivôs de rede:"},
      {"- File pivots:", "- Pivôs de arquivo:"},
      {"- Tactics:", "- Táticas:"},
      {"- Techniques:", "- Técnicas:"},
      {"not provided", "não informado"},
      {"not linked", "não vinculado"},
      {"none in alert evidence", "nenhum na evidência do alerta"},
      {"none mapped", "nenhum mapeado"},
      {"No on-chain attestation is linked to this alert yet.", "Nenhuma atestação on-chain está vinculada a este alerta ainda."},
      {"SSH connection from external IP:", "Conexão SSH a partir de IP externo:"},
      {"For this specific alert, treat the external endpoint(s) above as suspicious until validated against expected admin activity, VPN/bastion usage, or known cloud infrastructure.", "Para este alerta específico, trate os endpoint(s) externos acima como suspeitos até validar contra atividade administrativa esperada, uso de VPN/bastion ou infraestrutura cloud conhecida."},
      {"The next useful step is to open a case investigation, review the source event/storyline, and check whether the same remote IP/domain appears on other hosts.", "O próximo passo útil é abrir uma investigação, revisar o evento de origem/storyline e verificar se o mesmo IP/domínio remoto aparece em outros hosts."},
      {"External remote IPs/domains connected to the process or source event are the strongest pivots for this alert.", "IPs/domínios remotos externos conectados ao processo ou evento de origem são os pivôs mais fortes deste alerta."},
      {"Internal/private addresses are usually lower priority unless they indicate lateral movement.", "Endereços internos/privados normalmente têm prioridade menor, salvo quando indicam movimento lateral."},
      {"The concrete evidence points to an outbound SSH client connection from", "A evidência concreta aponta para uma conexão SSH de saída de"},
      {"The concrete evidence points to process", "A evidência concreta aponta para o processo"},
      {"using process", "usando o processo"},
      {" to `", " para `"},
      {"making repeated internal connections from", "fazendo conexões internas repetidas a partir de"},
      {"to private/local network addresses such as", "para endereços privados/locais como"},
      {"This does not prove compromise by itself: it is suspicious because it is remote administrative access from the endpoint to an external address.", "Isso não prova comprometimento por si só: é suspeito porque é acesso administrativo remoto do endpoint para um endereço externo."},
      {"Validate whether that destination is an expected admin box, cloud VM, bastion, VPN path, or developer workflow.", "Valide se esse destino é um host administrativo esperado, VM cloud, bastion, caminho de VPN ou fluxo de desenvolvimento."},
      {"If it is not expected, pivot on the destination IP, user shell history, SSH config/known_hosts, parent process, and any nearby process/file events.", "Se não for esperado, pivote pelo IP de destino, histórico de shell do usuário, configuração SSH/known_hosts, processo pai e eventos próximos de processo/arquivo."},
      {"This pattern can be benign when it matches expected LAN software, discovery, remote-control, device sync, or service retry behavior.", "Esse padrão pode ser benigno quando combina com software LAN esperado, descoberta, controle remoto, sincronização de dispositivo ou retry de serviço."},
      {"It becomes suspicious if the process is unexpected, the target IPs are unusual for this host, or the same pattern appears across several endpoints.", "Ele se torna suspeito se o processo for inesperado, se os IPs de destino forem incomuns para esse host, ou se o mesmo padrão aparecer em vários endpoints."},
      {"Validate the process owner/path/signature, whether the destination IPs are known internal assets, and whether the event volume is a normal baseline for this endpoint.", "Valide dono/caminho/assinatura do processo, se os IPs de destino são ativos internos conhecidos e se o volume de eventos é normal para a baseline desse endpoint."},
      {"The alert has nearby telemetry, but the available evidence is not enough to state confirmed compromise.", "O alerta tem telemetria próxima, mas a evidência disponível não é suficiente para afirmar comprometimento confirmado."},
      {"Treat the listed process, source event, and network indicators as pivots.", "Trate o processo listado, o evento de origem e os indicadores de rede como pivôs."},
      {"First validate whether the process and destination are expected for this host, then compare the event pattern against the endpoint baseline and search for the same IOCs on other agents.", "Primeiro valide se o processo e o destino são esperados para esse host; depois compare o padrão de eventos contra a baseline do endpoint e busque os mesmos IOCs em outros agents."},
      {"Confirm whether", "Confirme se"},
      {"is expected to initiate this kind of connection.", "deveria iniciar esse tipo de conexão."},
      {"Confirm the destination owner and purpose:", "Confirme o dono e o propósito do destino:"},
      {"Check the process path, signer, parent process, and command line for", "Verifique caminho, assinatura, processo pai e linha de comando de"},
      {"Compare this host against baseline: same process, same destination, same time window in prior days.", "Compare este host com a baseline: mesmo processo, mesmo destino e mesma janela de horário em dias anteriores."},
      {"Search the same IP/domain/process across other agents before closing or suppressing.", "Busque o mesmo IP/domínio/processo em outros agents antes de fechar ou suprimir."},
      {"If the destination and process are known/admin-approved, this is likely expected activity or a noisy NDR rule.", "Se o destino e o processo forem conhecidos/aprovados por administração, isso provavelmente é atividade esperada ou uma regra NDR ruidosa."},
      {"If either is unknown, keep it open and create an investigation with the source event and pivots above.", "Se qualquer um dos dois for desconhecido, mantenha aberto e crie uma investigação com o evento de origem e os pivôs acima."},
      {"No nearby/source events were found for this alert.", "Nenhum evento próximo/de origem foi encontrado para este alerta."},
      {"No related open alerts were found on the same endpoint.", "Nenhum alerta aberto relacionado foi encontrado no mesmo endpoint."},
      {"I could not find alert", "Não encontrei o alerta"},
      {"in your current organization scope.", "no escopo da organização atual."},
      {"I encountered an issue:", "Encontrei um problema:"},
      {"I recovered", "Recuperei"},
      {"alert(s) from the previous assistant response and loaded their details inside the current organization scope.", "alerta(s) da resposta anterior e carreguei os detalhes dentro do escopo da organização atual."},
      {"No obvious duplicate cluster was found in this set.", "Nenhum cluster duplicado óbvio foi encontrado nesse conjunto."},
      {"alerts share the same title and endpoint:", "alertas compartilham o mesmo título e endpoint:"},
      {"Treat these as a repeated detector pattern first; investigate one representative alert deeply, then confirm whether timestamps/source events differ.", "Trate isso primeiro como um padrão repetido do detector; investigue profundamente um alerta representativo e depois confirme se timestamps/eventos de origem diferem."},
      {"When many items share the same title, host, and description, do not treat them as independent incidents before validating deduplication.", "Quando muitos itens compartilham o mesmo título, host e descrição, não trate como incidentes independentes antes de validar deduplicação."},
      {"Open one representative alert, review the source event, process, file/path, and timestamp, then compare the remaining IDs to see whether they are repeated firings of the same detector.", "Abra um alerta representativo, revise evento de origem, processo, arquivo/caminho e timestamp; depois compare os IDs restantes para ver se são disparos repetidos do mesmo detector."},
      {"external/suspicious", "externo/suspeito"},
      {"internal/local", "interno/local"},
      {" process `", " processo `"},
      {" network `", " rede `"}
    ])
  end

  defp localize_assistant_message(message, :es) when is_binary(message) do
    replace_many(message, [
      {"**Alert analysis:", "**Análisis de la alerta:"},
      {"**What likely happened**", "**Lo que probablemente ocurrió**"},
      {"**Primary finding**", "**Hallazgo principal**"},
      {"**Most relevant evidence**", "**Evidencia más relevante**"},
      {"**Suspicious hosts / IOCs to review**", "**Hosts / IOCs sospechosos para revisar**"},
      {"**Nearby telemetry**", "**Telemetría cercana**"},
      {"**Related alerts on the same endpoint**", "**Alertas relacionadas en el mismo endpoint**"},
      {"**Analyst interpretation**", "**Interpretación del analista**"},
      {"**Why it fired**", "**Por qué se disparó**"},
      {"**Correlation and evidence**", "**Correlación y evidencia**"},
      {"**Context alert summary**", "**Resumen de alertas en contexto**"},
      {"**Cluster reading**", "**Lectura del cluster**"},
      {"**Best next step**", "**Mejor próximo paso**"},
      {"- Severity:", "- Severidad:"},
      {"- Source event:", "- Evento origen:"},
      {"- What it is:", "- Qué es:"},
      {"- Why it fired:", "- Por qué se disparó:"},
      {"- Primary evidence:", "- Evidencia principal:"},
      {"not provided", "no informado"},
      {"not linked", "no vinculado"},
      {"none in alert evidence", "ninguno en la evidencia de la alerta"},
      {"SSH connection from external IP:", "Conexión SSH desde IP externa:"},
      {"external/suspicious", "externo/sospechoso"},
      {"internal/local", "interno/local"},
      {"I could not find alert", "No encontré la alerta"},
      {"in your current organization scope.", "en el alcance de tu organización actual."}
    ])
  end

  defp localize_assistant_message(message, _), do: message

  defp localize_suggested_actions(actions, :en), do: actions

  defp localize_suggested_actions(actions, language) when is_list(actions) do
    Enum.map(actions, fn
      action when is_map(action) ->
        cond do
          Map.has_key?(action, :label) ->
            Map.update!(action, :label, &localize_action_label(&1, language))

          Map.has_key?(action, "label") ->
            Map.update!(action, "label", &localize_action_label(&1, language))

          true ->
            action
        end

      other ->
        other
    end)
  end

  defp localize_suggested_actions(actions, _), do: actions

  defp localize_action_label(label, :pt) do
    case label do
      "Open storyline" -> "Abrir storyline"
      "Create investigation" -> "Criar investigação"
      "Find suspicious hosts" -> "Ver hosts suspeitos"
      "Response plan" -> "Plano de resposta"
      "Find related IOCs" -> "Ver IOCs relacionados"
      "Compact summary" -> "Resumo compacto"
      "Investigate representative" -> "Investigar representante"
      "Group duplicates" -> "Agrupar duplicados"
      "Review open alerts" -> "Revisar alertas abertos"
      "Threat summary" -> "Resumo de ameaças"
      "Start hunt" -> "Iniciar hunting"
      "Learn more" -> "Ver mais"
      "Related alerts" -> "Alertas relacionados"
      value -> value
    end
  end

  defp localize_action_label(label, :es) do
    case label do
      "Open storyline" -> "Abrir storyline"
      "Create investigation" -> "Crear investigación"
      "Find suspicious hosts" -> "Ver hosts sospechosos"
      "Response plan" -> "Plan de respuesta"
      "Find related IOCs" -> "Ver IOCs relacionados"
      "Compact summary" -> "Resumen compacto"
      "Investigate representative" -> "Investigar representante"
      "Group duplicates" -> "Agrupar duplicados"
      "Review open alerts" -> "Revisar alertas abiertas"
      "Threat summary" -> "Resumen de amenazas"
      "Start hunt" -> "Iniciar hunting"
      "Learn more" -> "Ver más"
      "Related alerts" -> "Alertas relacionadas"
      value -> value
    end
  end

  defp localize_action_label(label, _), do: label

  defp replace_many(text, replacements) do
    Enum.reduce(replacements, text, fn {from, to}, acc -> String.replace(acc, from, to) end)
  end

  defp query_context_opts(conn, context) when is_map(context) do
    [
      organization_id: current_organization_id(conn),
      time_range: context["time_range"] || context[:time_range] || "24h"
    ]
  end

  defp query_context_opts(conn, _context), do: query_context_opts(conn, %{})

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      current_user_org_id(conn.assigns[:current_user]) ||
      user_org_id_from_db(get_user_id(conn))
  end

  defp current_user_org_id(%{organization_id: org_id}) when not is_nil(org_id), do: org_id
  defp current_user_org_id(user) when is_map(user), do: user[:organization_id] || user["organization_id"]
  defp current_user_org_id(_), do: nil

  defp user_org_id_from_db("anonymous"), do: nil
  defp user_org_id_from_db(user_id) do
    case Accounts.get_user(user_id) do
      %{organization_id: org_id} -> org_id
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp extract_alert_id(message) when is_binary(message) do
    case Regex.run(~r/(?:\/app\/alerts\/|alerta?\s+|alert\s+)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i, message) do
      [_match, id | _] -> id
      _ ->
        case Regex.run(@alert_id_regex, message) do
          [id | _] -> id
          _ -> nil
        end
    end
  end

  defp extract_alert_id(_), do: nil

  defp extract_alert_id_from_context(message, organization_id) when is_binary(message) do
    context_ids =
      Regex.scan(~r/(?:alerta ainda está em contexto|alert is still in context|alerta sigue en contexto):\s*`?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`?/i, message)
      |> Enum.map(fn [_match, id] -> id end)

    preferred =
      Regex.scan(~r/(?:\/app\/alerts\/|alerta?\s+|alert\s+)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i, message)
      |> Enum.map(fn [_match, id] -> id end)

    all_uuid_candidates =
      Regex.scan(@alert_id_regex, message)
      |> Enum.map(&List.first/1)

    candidates =
      (context_ids ++ preferred ++ all_uuid_candidates)
      |> Enum.uniq()

    Enum.find(candidates, &alert_exists?(&1, organization_id))
  end

  defp extract_alert_id_from_context(_, _), do: nil

  defp contextual_alert_ids(messages, organization_id) when is_list(messages) do
    messages
    |> Enum.reverse()
    |> Enum.flat_map(fn message ->
      message
      |> message_content()
      |> alert_ids_from_text()
    end)
    |> Enum.uniq()
    |> Enum.filter(&alert_exists?(&1, organization_id))
    |> Enum.take(20)
  end

  defp contextual_alert_ids(_, _), do: []

  defp alert_ids_from_text(message) when is_binary(message) do
    @alert_id_regex
    |> Regex.scan(message)
    |> Enum.map(&List.first/1)
    |> Enum.uniq()
  end

  defp alert_ids_from_text(_), do: []

  defp alert_exists?(alert_id, organization_id) do
    query =
      Alert
      |> where([a], a.id == ^alert_id)
      |> maybe_alert_org_scope(organization_id)

    Repo.exists?(query)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp active_alert_id_from_messages(messages, organization_id) do
    messages
    |> Enum.reverse()
    |> Enum.find_value(fn message ->
      message
      |> message_content()
      |> extract_alert_id_from_context(organization_id)
    end)
  end

  defp compact_conversation_messages(messages, organization_id) when is_list(messages) and length(messages) > 40 do
    alert_id = active_alert_id_from_messages(messages, organization_id)

    summary = %{
      role: "system",
      content:
        "Auto-compact summary: this conversation is an active security investigation. " <>
          "Keep using prior alert context#{if alert_id, do: " for alert #{alert_id}", else: ""}; " <>
          "prefer concrete evidence, related hosts, IOCs, storyline, and response next steps over generic search summaries.",
      timestamp: DateTime.to_iso8601(DateTime.utc_now())
    }

    [summary | Enum.take(messages, -24)]
  end

  defp compact_conversation_messages(messages, _organization_id), do: messages

  defp contains_any?(text, patterns), do: Enum.any?(patterns, &String.contains?(text, &1))

  defp maybe_alert_org_scope(query, nil), do: query
  defp maybe_alert_org_scope(query, organization_id), do: where(query, [a], a.organization_id == ^organization_id)

  defp maybe_event_org_scope(query, nil), do: query
  defp maybe_event_org_scope(query, organization_id), do: where(query, [e], e.organization_id == ^organization_id)

  defp maybe_joined_org_scope(query, nil), do: query
  defp maybe_joined_org_scope(query, organization_id), do: where(query, [a, _ag], a.organization_id == ^organization_id)

  defp normalize_query_result({:ok, result}), do: result
  defp normalize_query_result(result) when is_map(result), do: result
  defp normalize_query_result(result), do: %{message: inspect(result)}

  defp alert_result(alert) do
    %{
      id: alert.id,
      title: alert.title,
      severity: alert.severity,
      status: alert.status,
      hostname: agent_hostname(alert),
      agent_id: alert.agent_id,
      inserted_at: alert.inserted_at
    }
  end

  defp event_result(event) do
    %{
      id: event.id,
      event_type: event.event_type,
      severity: event.severity,
      timestamp: event.timestamp,
      hostname: agent_hostname(event),
      agent_id: event.agent_id,
      payload: event.payload
    }
  end

  defp agent_hostname(%{agent: %{hostname: hostname}}) when is_binary(hostname), do: hostname
  defp agent_hostname(_), do: "Unknown endpoint"

  defp agent_status(%{agent: %{status: status}}) when is_binary(status), do: status
  defp agent_status(_), do: "unknown"

  defp map_value(nil, _keys), do: nil
  defp map_value(map, keys) when is_map(map), do: Enum.find_value(keys, &Map.get(map, &1))
  defp map_value(_, _keys), do: nil

  defp valid_uuid?(value) when is_binary(value), do: Regex.match?(@alert_id_regex, value)
  defp valid_uuid?(_), do: false

  defp alert_time(%{last_seen_at: %DateTime{} = dt}), do: dt
  defp alert_time(%{inserted_at: %DateTime{} = dt}), do: dt
  defp alert_time(%{last_seen_at: %NaiveDateTime{} = dt}), do: DateTime.from_naive!(dt, "Etc/UTC")
  defp alert_time(%{inserted_at: %NaiveDateTime{} = dt}), do: DateTime.from_naive!(dt, "Etc/UTC")
  defp alert_time(_), do: nil

  defp suspicious_network_indicators(alert, events) do
    alert_values = network_values(alert.evidence || %{}) ++ network_values(alert.raw_event || %{})
    event_values = Enum.flat_map(events, &network_values(&1.payload || %{}))

    (alert_values ++ event_values)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.map(fn value ->
      %{value: value, scope: indicator_scope(value), suspicious: suspicious_network_value?(value)}
    end)
    |> Enum.sort_by(fn item -> {not item.suspicious, item.value} end)
  end

  defp network_values(map) when is_map(map) do
    [
      map_value(map, ["remote_ip", :remote_ip, "destination_ip", :destination_ip, "dst_ip", :dst_ip]),
      map_value(map, ["domain", :domain, "dns_query", :dns_query, "sni", :sni, "tls_sni", :tls_sni]),
      map_value(map, ["remote_host", :remote_host, "hostname", :hostname])
    ]
  end

  defp network_values(_), do: []

  defp suspicious_network_value?(value) when is_binary(value) do
    cond do
      String.match?(value, ~r/^\d{1,3}(\.\d{1,3}){3}$/) -> not private_ipv4?(value)
      String.contains?(value, ".") -> true
      true -> false
    end
  end

  defp suspicious_network_value?(_), do: false

  defp private_ipv4?("10." <> _), do: true
  defp private_ipv4?("192.168." <> _), do: true
  defp private_ipv4?("127." <> _), do: true
  defp private_ipv4?("169.254." <> _), do: true
  defp private_ipv4?("172." <> rest) do
    rest
    |> String.split(".", parts: 2)
    |> List.first()
    |> case do
      nil -> false
      octet -> match?({n, ""} when n >= 16 and n <= 31, Integer.parse(octet))
    end
  end
  defp private_ipv4?(_), do: false

  defp indicator_scope(value) do
    if suspicious_network_value?(value), do: "external/suspicious", else: "internal/local"
  end

  defp format_indicator_lines([]), do: "- No network indicators were present in the alert evidence I could read."
  defp format_indicator_lines(indicators) do
    indicators
    |> Enum.take(12)
    |> Enum.map(fn item -> "- `#{item.value}` - #{item.scope}" end)
    |> Enum.join("\n")
  end

  defp alert_interpretation(alert, events, suspicious_networks) do
    title = String.downcase(alert.title || "")
    description = String.downcase(alert.description || "")
    process = plain_process_name(alert, alert.evidence || %{})
    external_values = suspicious_networks |> Enum.filter(& &1.suspicious) |> Enum.map(& &1.value)
    internal_values = suspicious_networks |> Enum.reject(& &1.suspicious) |> Enum.map(& &1.value)
    event_types = events |> Enum.map(& &1.event_type) |> Enum.frequencies()

    cond do
      String.contains?(title <> " " <> description, "external ssh") ->
        """
        The concrete evidence points to an outbound SSH client connection from `#{agent_hostname(alert)}` using process #{format_optional_code(process)} to `#{List.first(external_values) || "an external IP"}`. This does not prove compromise by itself: it is suspicious because it is remote administrative access from the endpoint to an external address. Validate whether that destination is an expected admin box, cloud VM, bastion, VPN path, or developer workflow. If it is not expected, pivot on the destination IP, user shell history, SSH config/known_hosts, parent process, and any nearby process/file events.
        """
        |> String.trim()

      String.contains?(title <> " " <> description, "rapid internal connections") ->
        """
        The concrete evidence points to process #{format_optional_code(process)} making repeated internal connections from `#{agent_hostname(alert)}` to private/local network addresses such as #{format_short_values(internal_values)}. This pattern can be benign when it matches expected LAN software, discovery, remote-control, device sync, or service retry behavior. It becomes suspicious if the process is unexpected, the target IPs are unusual for this host, or the same pattern appears across several endpoints. Validate the process owner/path/signature, whether the destination IPs are known internal assets, and whether the event volume is a normal baseline for this endpoint.
        """
        |> String.trim()

      map_size(event_types) > 0 ->
        """
        The alert has nearby telemetry, but the available evidence is not enough to state confirmed compromise. Treat the listed process, source event, and network indicators as pivots. First validate whether the process and destination are expected for this host, then compare the event pattern against the endpoint baseline and search for the same IOCs on other agents.
        """
        |> String.trim()

      true ->
        "The alert exists, but the correlated telemetry available to the assistant is too thin to make a confident determination. Open the source event/storyline, validate the endpoint process and destination, and pivot across the org before deciding whether this is malicious or expected activity."
    end
  end

  defp event_line(event) do
    payload = event.payload || %{}
    network = network_values(payload) |> Enum.reject(&is_nil/1) |> Enum.map_join(", ", &"`#{&1}`")
    process = map_value(payload, ["process_name", :process_name, "process", :process, "image", :image])
    "- #{format_datetime(event.timestamp)} `#{event.event_type}` #{if process, do: "process `#{process}` ", else: ""}#{if network != "", do: "network #{network}", else: ""}"
  end

  defp plain_process_name(alert, evidence) do
    process =
      map_value(evidence, ["process", :process, "process_name", :process_name, "image", :image]) ||
        map_value(alert.raw_event || %{}, ["process", :process, "process_name", :process_name, "image", :image])

    cond do
      is_binary(process) and process != "" -> process
      is_map(process) -> map_value(process, ["name", :name, "image", :image, "path", :path])
      true -> nil
    end
  end

  defp format_optional_code(nil), do: "not provided"
  defp format_optional_code(""), do: "not provided"
  defp format_optional_code(value), do: "`#{value}`"

  defp format_short_values([]), do: "no specific values"
  defp format_short_values(values) do
    values
    |> Enum.take(4)
    |> Enum.map_join(", ", &"`#{&1}`")
  end

  defp format_event_counts(counts) when map_size(counts) == 0, do: "no nearby events"
  defp format_event_counts(counts) do
    counts
    |> Enum.sort_by(fn {_event_type, count} -> -count end)
    |> Enum.take(5)
    |> Enum.map_join(", ", fn {event_type, count} -> "#{event_type}: #{count}" end)
  end

  defp related_alert_line(alert) do
    "- #{format_datetime(alert.last_seen_at || alert.inserted_at)} **#{String.upcase(alert.severity || "unknown")}** #{alert.title || "Untitled alert"} - `/app/alerts/#{alert.id}`"
  end

  defp format_lines([], fallback), do: fallback
  defp format_lines(lines, _fallback) when is_list(lines), do: Enum.join(lines, "\n")

  defp normalize_case_severity(severity) when severity in ["critical", "high", "medium", "low", "info"], do: severity
  defp normalize_case_severity(_), do: "medium"

  defp process_summary(alert, evidence) do
    process =
      map_value(evidence, ["process", :process, "process_name", :process_name, "image", :image]) ||
        map_value(alert.raw_event || %{}, ["process", :process, "process_name", :process_name, "image", :image])

    cond do
      is_binary(process) -> "`#{process}`"
      is_map(process) -> "`#{map_value(process, ["name", :name, "image", :image, "path", :path]) || "process object"}`"
      alert.process_chain && alert.process_chain != [] -> "#{length(alert.process_chain)} process-chain node(s)"
      true -> "not provided"
    end
  end

  defp network_summary(evidence) do
    values =
      [
        map_value(evidence, ["remote_ip", :remote_ip, "destination_ip", :destination_ip]),
        map_value(evidence, ["domain", :domain, "dns_query", :dns_query])
      ]
      |> Enum.reject(&is_nil/1)

    case values do
      [] -> "none in alert evidence"
      values -> Enum.map_join(values, ", ", &"`#{&1}`")
    end
  end

  defp file_summary(evidence) do
    values =
      [
        map_value(evidence, ["file_path", :file_path, "path", :path]),
        map_value(evidence, ["sha256", :sha256, "file_hash", :file_hash])
      ]
      |> Enum.reject(&is_nil/1)

    case values do
      [] -> "none in alert evidence"
      values -> Enum.map_join(values, ", ", &"`#{&1}`")
    end
  end

  defp attestation_summary(%{blockchain_tx_id: tx_id} = alert, _manifest) when is_binary(tx_id) and tx_id != "" do
    "- Solana transaction: `#{tx_id}`\n- Incident hash: `#{alert.incident_hash || "not stored"}`\n- Public IOC count: #{alert.attestation_ioc_count || 0}"
  end

  defp attestation_summary(_alert, manifest) when is_map(manifest) and map_size(manifest) > 0 do
    "- Public manifest exists locally but no transaction id is attached to this alert."
  end

  defp attestation_summary(_alert, _manifest), do: "- No on-chain attestation is linked to this alert yet."

  defp recommended_actions_for(%{severity: severity}) when severity in ["critical", "high"] do
    """
    - Review the storyline and related events before closing the alert.
    - If active execution is confirmed, isolate the endpoint and collect evidence.
    - Kill/quarantine only confirmed malicious process/file pivots.
    - Block network IOCs after validating they are not shared infrastructure.
    """
    |> String.trim()
  end

  defp recommended_actions_for(_alert) do
    """
    - Review the evidence and related events.
    - Compare against known baseline activity for this endpoint.
    - Mark false positive only with analyst notes if the behavior is expected.
    """
    |> String.trim()
  end

  defp join_or_none(values) when is_list(values) and values != [], do: Enum.join(values, ", ")
  defp join_or_none(_), do: "none mapped"

  defp severity_phrase(critical, high) do
    parts = []
    parts = if critical && critical > 0, do: [" #{critical} critical" | parts], else: parts
    parts = if high && high > 0, do: [" #{high} high" | parts], else: parts

    case Enum.reverse(parts) do
      [] -> ""
      values -> " (#{Enum.join(values, ",")})"
    end
  end

  defp format_score(nil), do: "not scored"
  defp format_score(score) when is_float(score), do: :erlang.float_to_binary(score, decimals: 1)
  defp format_score(score), do: to_string(score)

  defp format_datetime(nil), do: "unknown"
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(dt), do: to_string(dt)

  defp build_chat_suggestions(query) do
    lower = String.downcase(query)

    cond do
      String.contains?(lower, "alert") ->
        [
          %{label: "Show affected hosts", type: "investigation", action: "Show me all hosts affected by the current alerts"},
          %{label: "Start response", type: "response", action: "Help me respond to the critical alerts"},
          %{label: "Alert trends", type: "info", action: "Show me alert trends over the past week"}
        ]

      String.contains?(lower, "hunt") or String.contains?(lower, "threat") ->
        [
          %{label: "Lateral movement", type: "query", action: "Hunt for lateral movement using PsExec or WMI"},
          %{label: "Persistence check", type: "query", action: "Search for persistence mechanisms across agents"},
          %{label: "Suspicious processes", type: "query", action: "Find processes with suspicious parent-child relationships"}
        ]

      String.contains?(lower, "process") ->
        [
          %{label: "Process tree", type: "investigation", action: "Show the full process tree for this activity"},
          %{label: "Related files", type: "investigation", action: "Show files accessed by this process"},
          %{label: "Network connections", type: "investigation", action: "Show network connections from this process"}
        ]

      true ->
        [
          %{label: "Learn more", type: "info", action: "Can you explain this in more detail?"},
          %{label: "Related alerts", type: "investigation", action: "Show me related alerts"}
        ]
    end
  end
end
