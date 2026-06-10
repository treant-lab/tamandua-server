defmodule TamanduaServerWeb.API.V1.AISecurityController do
  @moduledoc """
  AI Security Attack Surface endpoints for monitoring and assessing
  AI-related security risks in the organization.

  Includes:
  - Attack surface analysis
  - Prompt injection scanning
  - Shadow AI inventory
  - Risk assessment
  - RAG poisoning detection
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.{AIGateway, AIInventory, AttackSurface, Enforcement}
  alias TamanduaServer.Detection.RagPoisoningHandler

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get the current AI attack surface analysis.

  Returns a comprehensive view of AI-related attack vectors including:
  - Exposed AI endpoints
  - Model vulnerabilities
  - Data exposure risks
  - Integration weaknesses

  ## Parameters
    - scope: Optional scope filter (all, critical, external)
    - include_recommendations: Whether to include remediation recommendations
  """
  def attack_surface(conn, params) do
    scope = Map.get(params, "scope", "all")
    include_recommendations = Map.get(params, "include_recommendations", true)

    opts = [
      scope: scope,
      include_recommendations: include_recommendations
    ]

    with {:ok, surface_analysis} <- AttackSurface.analyze(opts) do
      json(conn, %{
        status: "success",
        data: surface_analysis
      })
    end
  end

  @doc """
  Schedule an AI attack surface assessment.

  For now this endpoint performs the same real analyzer pass used by the page
  and returns a persisted-free assessment result. It does not fabricate sample
  assets; empty results mean no AI assets have been observed yet.
  """
  def schedule_attack_surface_assessment(conn, params) do
    scope = Map.get(params, "scope", "all")

    try do
      case AttackSurface.analyze(scope: scope, include_recommendations: true) do
        {:ok, surface_analysis} ->
          json(conn, %{
            status: "success",
            data: %{
              status: "completed",
              assessment: surface_analysis,
              scheduled_at: DateTime.utc_now()
            }
          })

        {:error, reason} ->
          conn
          |> put_status(:service_unavailable)
          |> json(%{
            status: "error",
            message: "AI attack surface assessment failed",
            reason: inspect(reason)
          })
      end
    catch
      kind, reason ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          status: "error",
          message: "AI attack surface assessment is unavailable",
          reason: "#{kind}: #{inspect(reason)}"
        })
    end
  end

  @doc """
  Scan a prompt for potential security risks (prompt injection, jailbreaking, etc.).

  ## Parameters
    - prompt: The prompt text to scan
    - model_context: Optional context about the target model
    - scan_depth: Level of analysis (quick, standard, deep)
  """
  def scan_prompt(conn, %{"prompt" => prompt} = params) do
    model_context = Map.get(params, "model_context", %{})
    scan_depth = Map.get(params, "scan_depth", "standard")

    opts = %{
      context: model_context,
      scan_depth: scan_depth
    }

    with {:ok, scan_result} <- AttackSurface.scan_prompt(prompt, opts) do
      detected_threats = Map.get(scan_result, :detections, [])

      json(conn, %{
        status: "success",
        data: %{
          risk_score: scan_result.risk_score,
          detected_threats: detected_threats,
          classifications: threat_classifications(detected_threats),
          recommendations: prompt_scan_recommendations(scan_result),
          scanned_at: DateTime.utc_now()
        }
      })
    end
  end

  def scan_prompt(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "prompt is required"})
  end

  @doc """
  Get inventory of shadow AI usage across the organization.

  Discovers and catalogs unauthorized or unmanaged AI tools and services
  being used within the organization's network.

  ## Parameters
    - time_range: Time range for discovery (e.g., "24h", "7d", "30d")
    - department: Optional filter by department
    - include_approved: Whether to include approved AI tools for comparison
  """
  def shadow_ai_inventory(conn, params) do
    time_range = Map.get(params, "time_range", "7d")
    department = Map.get(params, "department")
    include_approved = Map.get(params, "include_approved", false) in [true, "true", "1", 1]

    inventory_opts = [
      limit: 500,
      shadow_only: !include_approved
    ]

    with {:ok, components} <- AIInventory.list_inventory(inventory_opts) do
      filtered_components =
        if department do
          Enum.filter(components, fn component ->
            to_string(component[:department] || component["department"] || "") == department
          end)
        else
          components
        end

      discovered_services = Enum.map(filtered_components, &shadow_ai_component_json/1)
      type_counts =
        filtered_components
        |> Enum.group_by(&(&1[:component_type] || "unknown"))
        |> Map.new(fn {type, entries} -> {type, length(entries)} end)

      json(conn, %{
        status: "success",
        data: %{
          discovered_services: discovered_services,
          usage_statistics: %{
            component_count: length(filtered_components),
            components_by_type: type_counts,
            source: "ai_inventory"
          },
          risk_assessment: %{
            high_risk_count: Enum.count(filtered_components, fn component -> component[:risk_level] in ["high", "critical"] end),
            shadow_ai_count: Enum.count(filtered_components, fn component -> component[:is_shadow] == true end),
            max_risk_score: Enum.reduce(filtered_components, 0, fn component, acc -> max(acc, component[:risk_score] || 0) end)
          },
          capabilities: %{
            content_inspection: false,
            prompt_capture: false,
            collection_mode: "inventory_and_metadata"
          },
          total_count: length(discovered_services),
          scan_period: time_range
        }
      })
    end
  end

  defp shadow_ai_component_json(component) do
    %{
      id: component[:id],
      name: component[:name],
      type: component[:component_type],
      version: component[:version],
      agent_id: component[:agent_id],
      hostname: component[:hostname],
      install_path: component[:install_path],
      policy_status: component[:policy_status],
      is_shadow: component[:is_shadow],
      risk_score: component[:risk_score],
      risk_level: component[:risk_level],
      risk_factors: component[:risk_factors] || [],
      last_seen_at: component[:last_seen_at]
    }
  end

  @doc """
  Get comprehensive AI risk assessment for the organization.

  ## Parameters
    - assessment_type: Type of assessment (full, quick, compliance)
    - frameworks: List of compliance frameworks to check against
  """
  def risk_assessment(conn, params) do
    assessment_type = Map.get(params, "assessment_type", "full")
    frameworks = Map.get(params, "frameworks", [])

    opts = [
      assessment_type: assessment_type,
      frameworks: frameworks
    ]

    with {:ok, assessment} <- AttackSurface.risk_assessment(opts) do
      normalized_assessment = normalize_risk_assessment(assessment)

      json(conn, %{
        status: "success",
        data: %{
          overall_risk_score: normalized_assessment.overall_risk_score,
          risk_categories: normalized_assessment.risk_categories,
          compliance_gaps: normalized_assessment.compliance_gaps,
          priority_actions: normalized_assessment.priority_actions,
          trend: normalized_assessment.trend,
          assessed_at: DateTime.utc_now()
        }
      })
    end
  end

  @doc """
  Ingest a metadata-only AI Gateway usage event.

  This endpoint is intended for future AI gateway, browser extension, proxy, and
  SDK integrations. It rejects prompt/response/body/authorization fields.
  """
  def gateway_event(conn, params) do
    case AIGateway.ingest_event(params) do
      {:ok, event} ->
        maybe_enforce_gateway_event(event)

        json(conn, %{
          status: "success",
          data: %{
            id: event.id,
            observed_at: event.observed_at,
            provider: event.provider,
            model: event.model,
            domain: event.domain,
            policy_decision: event.policy_decision,
            policy_reasons: event.policy_reasons,
            policy_enforced: event.policy_enforced,
            effective_risk_score: event.effective_risk_score,
            content_inspection: false,
            prompt_capture: false,
            enforcement: enforcement_summary(event)
          }
        })

      {:error, {:sensitive_fields, fields}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          status: "error",
          message: "AI Gateway events must be metadata-only",
          rejected_fields: fields
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  def gateway_events_batch(conn, %{"events" => events}) when is_list(events) do
    case AIGateway.ingest_batch(events) do
      {:ok, result} ->
        Enum.each(result.accepted, &maybe_enforce_gateway_event/1)

        json(conn, %{
          status: "success",
          data: %{
            accepted_count: result.accepted_count,
            rejected_count: result.rejected_count,
            accepted: Enum.map(result.accepted, &gateway_event_json/1),
            rejected: result.rejected,
            capabilities: %{
              collection_mode: "gateway_metadata",
              content_inspection: false,
              prompt_capture: false,
              enforcement_mode: "endpoint_action_bridge"
            }
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  def gateway_events_batch(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "events must be a list"})
  end

  def gateway_evaluate(conn, params) do
    case AIGateway.evaluate_event(params) do
      {:ok, evaluation} ->
        json(conn, %{
          status: "success",
          data: evaluation
        })

      {:error, {:sensitive_fields, fields}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          status: "error",
          message: "AI Gateway evaluation must be metadata-only",
          rejected_fields: fields
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  def gateway_usage(conn, params) do
    limit = params |> Map.get("limit", "250") |> parse_int(250) |> min(1000)
    since_ms = parse_since_ms(Map.get(params, "since_ms") || Map.get(params, "since"))

    {:ok, usage} = AIGateway.list_usage(limit: limit, since_ms: since_ms)

    json(conn, %{
      status: "success",
      data: %{
        usage: Enum.map(usage, &gateway_event_json/1),
        count: length(usage),
        capabilities: %{
          collection_mode: "gateway_metadata",
          content_inspection: false,
          prompt_capture: false,
          enforcement_mode: "endpoint_action_bridge"
        }
      }
    })
  end

  def gateway_health(conn, _params) do
    json(conn, %{status: "success", data: AIGateway.health()})
  end

  def gateway_policy(conn, _params) do
    json(conn, %{status: "success", data: AIGateway.get_policy()})
  end

  def update_gateway_policy(conn, params) do
    case AIGateway.update_policy(params) do
      {:ok, policy} ->
        json(conn, %{status: "success", data: policy})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  defp maybe_enforce_gateway_event(event) do
    Task.start(fn -> Enforcement.enforce_event(event) end)
    :ok
  rescue
    _ -> :ok
  end

  defp enforcement_summary(event) do
    %{
      requested: event.policy_enforced == true,
      mode: "endpoint_action_bridge",
      target_agent_id: event.agent_id,
      inline_proxy: false
    }
  end


  @doc """
  Scan RAG context documents for poisoning attacks.

  Detects various poisoning techniques in retrieved documents:
  - Instruction override hidden in "facts"
  - Delimiter injection (chat template tokens, markdown blocks)
  - Hidden unicode characters (zero-width, bidirectional)
  - Confidence manipulation phrases
  - Cross-document contradictions
  - Data exfiltration URLs
  - Source spoofing attempts

  ## Parameters
    - documents: List of context document strings (required)
    - query: Optional original query for alignment analysis
    - generate_alerts: Whether to create alerts for high-risk findings (default: true)

  ## Response
    - safe: Boolean indicating if documents are safe
    - risks: List of detected poisoning risks
    - risk_score: Aggregate risk score (0.0-1.0)
    - documents_scanned: Number of documents analyzed
    - high_risk_documents: Indices of high-risk documents
    - context_query_alignment: How well context matches query (0.0-1.0)
  """
  def scan_rag(conn, %{"documents" => documents} = params) when is_list(documents) do
    query = Map.get(params, "query")
    generate_alerts = Map.get(params, "generate_alerts", true)

    # Get agent_id from connection context if available
    agent_id = case conn.assigns do
      %{current_agent: %{id: id}} -> id
      %{agent_id: id} -> id
      _ -> nil
    end

    opts = [
      agent_id: agent_id,
      generate_alerts: generate_alerts
    ]

    case RagPoisoningHandler.scan_documents(documents, query, opts) do
      {:ok, scan_result} ->
        json(conn, %{
          status: "success",
          data: %{
            safe: scan_result.safe,
            risks: format_risks(scan_result.risks),
            risk_score: scan_result.risk_score,
            scan_time_ms: scan_result.scan_time_ms,
            documents_scanned: scan_result.documents_scanned,
            high_risk_documents: scan_result.high_risk_documents,
            context_query_alignment: scan_result.context_query_alignment,
            scanned_at: DateTime.utc_now()
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          status: "error",
          message: "RAG scan failed: #{inspect(reason)}"
        })
    end
  end

  def scan_rag(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      status: "error",
      message: "documents is required and must be a list of strings"
    })
  end

  @doc """
  Register a document source for integrity tracking.

  ## Parameters
    - doc_hash: SHA-256 hash of the document content
    - source: Source identifier (URL, file path, etc.)
    - trusted: Whether the source should be marked as trusted (default: true)
  """
  def register_rag_source(conn, %{"doc_hash" => doc_hash, "source" => source} = params) do
    trusted = Map.get(params, "trusted", true)

    :ok = RagPoisoningHandler.register_source(doc_hash, source, trusted)

    json(conn, %{
      status: "success",
      data: %{
        doc_hash: doc_hash,
        source: source,
        trusted: trusted,
        registered_at: DateTime.utc_now()
      }
    })
  end

  def register_rag_source(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      status: "error",
      message: "doc_hash and source are required"
    })
  end

  @doc """
  Validate a document source against the registry.

  ## Parameters
    - doc_hash: SHA-256 hash of the document content
    - source: Source identifier to validate
  """
  def validate_rag_source(conn, %{"doc_hash" => doc_hash, "source" => source}) do
    case RagPoisoningHandler.validate_source(doc_hash, source) do
      {:ok, validation} ->
        json(conn, %{
          status: "success",
          data: %{
            valid: validation.valid,
            hash_match: validation.hash_match,
            source_trusted: validation.source_trusted,
            validated_at: DateTime.utc_now()
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{
          status: "error",
          message: "Document hash not found in registry"
        })
    end
  end

  def validate_rag_source(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      status: "error",
      message: "doc_hash and source are required"
    })
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp gateway_event_json(event) do
    %{
      id: event.id,
      observed_at: event.observed_at,
      source: event.source,
      integration_id: event.integration_id,
      tenant_id: event.tenant_id,
      organization_id: event.organization_id,
      user_id: event.user_id,
      username: event.username,
      department: event.department,
      app: event.app,
      provider: event.provider,
      model: event.model,
      domain: event.domain,
      access_method: event.access_method,
      agent_id: event.agent_id,
      hostname: event.hostname,
      process_name: event.process_name,
      request_count: event.request_count,
      input_tokens: event.input_tokens,
      output_tokens: event.output_tokens,
      total_tokens: event.total_tokens,
      bytes_sent: event.bytes_sent,
      bytes_received: event.bytes_received,
      cost_usd: event.cost_usd,
      policy_id: event.policy_id,
      policy_decision: event.policy_decision,
      policy_reasons: event.policy_reasons,
      policy_enforced: event.policy_enforced,
      effective_risk_score: event.effective_risk_score,
      reason: event.reason,
      risk_level: event.risk_level,
      risk_score: event.risk_score,
      data_categories: event.data_categories,
      classification: event.classification,
      verdict: event.verdict,
      trace_id: event.trace_id,
      session_id: event.session_id
    }
  end

  defp parse_int(value, default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      _ -> default
    end
  end
  defp parse_int(_, default), do: default

  defp parse_since_ms(nil), do: nil
  defp parse_since_ms(value) when is_integer(value), do: value
  defp parse_since_ms(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} ->
        int

      _ ->
        case DateTime.from_iso8601(value) do
          {:ok, dt, _} -> DateTime.to_unix(dt, :millisecond)
          _ -> nil
        end
    end
  end
  defp parse_since_ms(_), do: nil

  defp format_risks(risks) do
    Enum.map(risks, fn risk ->
      %{
        category: risk.category,
        description: risk.description,
        confidence: risk.confidence,
        technique_id: risk.technique_id,
        matched_text: String.slice(risk.matched_text || "", 0, 200),
        document_index: risk.document_index
      }
    end)
  end

  defp threat_classifications(detections) do
    detections
    |> Enum.map(fn detection -> detection[:type] || detection["type"] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp prompt_scan_recommendations(%{is_malicious: false}) do
    ["No immediate action required"]
  end

  defp prompt_scan_recommendations(%{detections: detections}) do
    if Enum.any?(detections, fn detection -> detection[:severity] in [:high, :critical] end) do
      ["Block or require review before sending this prompt to an AI model"]
    else
      ["Review prompt before model execution"]
    end
  end

  defp prompt_scan_recommendations(_scan_result), do: ["No immediate action required"]

  defp normalize_risk_assessment(%{risk_score: %{score: score, factors: factors}} = assessment) do
    %{
      overall_risk_score: score,
      risk_categories: %{attack_surface: score, factors: factors},
      compliance_gaps: [],
      priority_actions: risk_priority_actions(factors),
      trend: "stable",
      entity_id: assessment[:entity_id]
    }
  end

  defp normalize_risk_assessment(%{risk_score: score} = assessment) when is_number(score) do
    %{
      overall_risk_score: score,
      risk_categories: %{attack_surface: score, factors: []},
      compliance_gaps: [],
      priority_actions: [],
      trend: "stable",
      entity_id: assessment[:entity_id]
    }
  end

  defp normalize_risk_assessment(assessment) do
    %{
      overall_risk_score: assessment[:overall_risk_score] || 0.0,
      risk_categories: assessment[:risk_categories] || %{},
      compliance_gaps: assessment[:compliance_gaps] || [],
      priority_actions: assessment[:priority_actions] || [],
      trend: assessment[:trend] || "stable"
    }
  end

  defp risk_priority_actions(factors) when is_list(factors) and factors != [] do
    Enum.map(factors, &"Review AI security factor: #{&1}")
  end

  defp risk_priority_actions(_factors), do: []
end
