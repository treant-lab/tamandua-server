defmodule TamanduaServer.Detection.AIRuntimeAnalyzer do
  @moduledoc """
  AI Runtime Behavior Analyzer.

  Analyzes LLM requests for security threats including:
  - Prompt injection patterns
  - MCP tool abuse
  - Data exfiltration via LLM responses
  - Jailbreak attempts

  Uses Sigma rules from priv/sigma_rules/ai_runtime/ and creates
  alerts with category "ai_runtime" for dashboard visualization.
  """

  require Logger
  alias TamanduaServer.Detection.Rules.{Sigma, SigmaAggregator}
  alias TamanduaServer.Alerts
  alias Phoenix.PubSub

  @ai_runtime_rules_path "priv/sigma_rules/ai_runtime"

  @doc """
  Analyze an LLM request event for AI-specific threats.

  Returns {:ok, detections} where detections is a list of matched rules.
  Creates alerts for any detections found.
  """
  @spec analyze_llm_request(String.t(), map()) :: {:ok, list(tuple())}
  def analyze_llm_request(agent_id, event) do
    # Load AI runtime rules
    rules = load_ai_runtime_rules()

    # Build event map with proper structure for Sigma matching
    event_map = build_event_map(agent_id, event)

    # Evaluate rules
    {instant_matches, aggregation_triggers} = evaluate_rules(event_map, rules, agent_id)

    # Create alerts for matches
    all_detections = instant_matches ++ aggregation_triggers

    Enum.each(all_detections, fn {rule, count} ->
      create_ai_runtime_alert(agent_id, rule, event_map, count)
    end)

    {:ok, all_detections}
  rescue
    e ->
      Logger.error("[AIRuntimeAnalyzer] Error analyzing LLM request: #{Exception.message(e)}")
      {:ok, []}
  end

  defp load_ai_runtime_rules do
    # Load rules from ai_runtime directory
    path = Application.app_dir(:tamandua_server, @ai_runtime_rules_path)

    if File.dir?(path) do
      path
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".yml"))
      |> Enum.flat_map(fn file ->
        File.read!(Path.join(path, file))
        |> String.split("---")
        |> Enum.reject(&(&1 == "" or &1 == "\n"))
        |> Enum.map(&parse_rule/1)
        |> Enum.reject(&is_nil/1)
      end)
    else
      Logger.warning("[AIRuntimeAnalyzer] AI runtime rules directory not found: #{path}")
      []
    end
  end

  defp parse_rule(yaml_content) do
    case Sigma.parse(yaml_content) do
      {:ok, rule} -> rule
      {:error, reason} ->
        Logger.warning("[AIRuntimeAnalyzer] Failed to parse rule: #{reason}")
        nil
    end
  end

  defp build_event_map(agent_id, event) do
    %{
      "event_type" => "llm_request",
      "agent_id" => agent_id,
      "api_provider" => to_string(event[:api_provider] || event["api_provider"] || "unknown"),
      "api_endpoint" => event[:api_endpoint] || event["api_endpoint"],
      "prompt_preview" => event[:prompt_preview] || event["prompt_preview"] || "",
      "full_prompt_hash" => event[:full_prompt_hash] || event["full_prompt_hash"],
      "model" => event[:model] || event["model"],
      "process_name" => event[:process_name] || event["process_name"],
      "process_path" => event[:process_path] || event["process_path"],
      "pid" => event[:pid] || event["pid"],
      "ml_context" => event[:ml_context] || event["ml_context"],
      "timestamp" => event[:timestamp] || event["timestamp"] || DateTime.utc_now()
    }
  end

  defp evaluate_rules(event, rules, agent_id) do
    Enum.reduce(rules, {[], []}, fn rule, {instant_acc, agg_acc} ->
      case Sigma.classify_rule(rule) do
        :instant ->
          if Sigma.matches?(event, rule) do
            {[{rule, 1} | instant_acc], agg_acc}
          else
            {instant_acc, agg_acc}
          end

        {:aggregation, agg_config} ->
          if Sigma.matches_selection_only?(event, rule) do
            rule_id = to_string(rule["id"] || rule["title"] || "unknown")

            case SigmaAggregator.record_match(rule_id, agent_id, event, agg_config) do
              {:trigger, count} ->
                {instant_acc, [{rule, count} | agg_acc]}
              :buffered ->
                {instant_acc, agg_acc}
            end
          else
            {instant_acc, agg_acc}
          end
      end
    end)
  end

  defp create_ai_runtime_alert(agent_id, {rule, count}, event, _count_param) do
    severity = rule["level"] || "medium"
    title = rule["title"] || "AI Runtime Detection"
    description = rule["description"] || "AI runtime security event detected"

    tags = (rule["tags"] || []) ++ ["ai_runtime"]

    metadata = %{
      rule_id: rule["id"],
      provider: event["api_provider"],
      model: event["model"],
      prompt_preview: String.slice(event["prompt_preview"] || "", 0..255),
      prompt_hash: event["full_prompt_hash"],
      ml_context: event["ml_context"],
      match_count: count
    }

    case Alerts.create_alert(%{
      agent_id: agent_id,
      severity: severity,
      category: "ai_runtime",
      title: title,
      description: description,
      tags: tags,
      metadata: metadata
    }) do
      {:ok, alert} ->
        # Broadcast to dashboard
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "alerts:ai_runtime",
          {:new_alert, alert}
        )
        Logger.info("[AIRuntimeAnalyzer] Created alert: #{alert.id} - #{title}")

      {:error, reason} ->
        Logger.error("[AIRuntimeAnalyzer] Failed to create alert: #{inspect(reason)}")
    end
  end
end
