defmodule TamanduaServerWeb.API.V1.AutonomousResponseController do
  @moduledoc """
  API Controller for Autonomous Response Management

  Provides endpoints for:
  - Decision engine status and configuration
  - Autonomous rules CRUD operations
  - Recommendation management (approve/reject)
  - Analyst learning statistics
  - Asset criticality management
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Response.{DecisionEngine, AutonomousRules, AnalystLearning, AutonomousEngine}
  alias TamanduaServer.Assets.Criticality
  alias TamanduaServer.Alerts

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # Decision Engine Endpoints
  # ============================================================================

  @doc """
  Get autonomous response settings for the organization.
  GET /api/v1/autonomous/settings
  """
  def settings(conn, _params) do
    org_id = get_org_id(conn)

    case DecisionEngine.get_settings(org_id) do
      {:ok, settings} ->
        rate_status = DecisionEngine.rate_limit_status(org_id)

        json(conn, %{
          settings: settings,
          rate_limit_status: rate_status
        })

      {:error, reason} ->
        conn
        |> put_status(500)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Update autonomous response settings.
  PUT /api/v1/autonomous/settings
  """
  def update_settings(conn, %{"settings" => settings_params}) do
    org_id = get_org_id(conn)

    case DecisionEngine.update_settings(org_id, atomize_keys(settings_params)) do
      {:ok, settings} ->
        json(conn, %{success: true, settings: settings})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Emergency disable autonomous responses.
  POST /api/v1/autonomous/emergency-disable
  """
  def emergency_disable(conn, %{"reason" => reason}) do
    org_id = get_org_id(conn)
    DecisionEngine.emergency_disable(org_id, reason)
    json(conn, %{success: true, message: "Autonomous responses disabled"})
  end

  @doc """
  Re-enable autonomous responses after emergency.
  POST /api/v1/autonomous/emergency-enable
  """
  def emergency_enable(conn, _params) do
    org_id = get_org_id(conn)
    user = conn.assigns[:current_user]
    approver_id = if user, do: user.id, else: "system"

    DecisionEngine.emergency_enable(org_id, approver_id)
    json(conn, %{success: true, message: "Autonomous responses re-enabled"})
  end

  # ============================================================================
  # Recommendation Endpoints
  # ============================================================================

  @doc """
  Get pending recommendations awaiting approval.
  GET /api/v1/autonomous/recommendations
  """
  def list_recommendations(conn, params) do
    org_id = get_org_id(conn)
    status = params["status"]

    case DecisionEngine.get_pending_recommendations(org_id) do
      {:ok, recommendations} ->
        filtered = if status do
          Enum.filter(recommendations, & &1.status == status)
        else
          recommendations
        end

        json(conn, %{
          recommendations: filtered,
          count: length(filtered)
        })

      {:error, reason} ->
        conn
        |> put_status(500)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Approve a pending recommendation.
  POST /api/v1/autonomous/recommendations/:id/approve
  """
  def approve_recommendation(conn, %{"id" => recommendation_id}) do
    user = conn.assigns[:current_user]
    approver_id = if user, do: user.id, else: "system"

    case DecisionEngine.approve_recommendation(recommendation_id, approver_id) do
      {:ok, result} ->
        json(conn, %{
          success: true,
          message: "Recommendation approved and executed",
          result: result
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Recommendation not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Reject a pending recommendation.
  POST /api/v1/autonomous/recommendations/:id/reject
  """
  def reject_recommendation(conn, %{"id" => recommendation_id} = params) do
    user = conn.assigns[:current_user]
    rejector_id = if user, do: user.id, else: "system"
    reason = params["reason"] || "No reason provided"

    case DecisionEngine.reject_recommendation(recommendation_id, rejector_id, reason) do
      {:ok, result} ->
        json(conn, %{
          success: true,
          message: "Recommendation rejected",
          result: result
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Recommendation not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Get action history.
  GET /api/v1/autonomous/history
  """
  def action_history(conn, params) do
    org_id = get_org_id(conn)
    limit = bounded_limit(params["limit"], 50, 500)
    status = params["status"]

    opts = [organization_id: org_id, limit: limit]
    opts = if status, do: Keyword.put(opts, :status, status), else: opts

    case DecisionEngine.get_action_history(opts) do
      {:ok, history} ->
        json(conn, %{
          history: history,
          count: length(history)
        })

      {:error, reason} ->
        conn
        |> put_status(500)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Manually evaluate an alert for autonomous response.
  POST /api/v1/autonomous/evaluate
  """
  def evaluate_alert(conn, %{"alert_id" => alert_id}) do
    org_id = get_org_id(conn)

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        case DecisionEngine.evaluate_alert(alert) do
          {:ok, result} ->
            json(conn, %{
              success: true,
              evaluation: result
            })

          {:error, reason} ->
            conn
            |> put_status(400)
            |> json(%{success: false, error: inspect(reason)})
        end

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Alert not found"})
    end
  end

  # ============================================================================
  # Rules Endpoints
  # ============================================================================

  @doc """
  List autonomous response rules.
  GET /api/v1/autonomous/rules
  """
  def list_rules(conn, params) do
    org_id = get_org_id(conn)
    enabled_only = params["enabled_only"] == "true"

    rules = AutonomousRules.list_rules(org_id, enabled_only: enabled_only)

    json(conn, %{
      rules: rules,
      count: length(rules)
    })
  end

  @doc """
  Get a specific rule.
  GET /api/v1/autonomous/rules/:id
  """
  def show_rule(conn, %{"id" => rule_id}) do
    case AutonomousRules.get_rule(rule_id) do
      {:ok, rule} ->
        stats = AutonomousRules.get_rule_stats(rule_id)
        json(conn, %{rule: rule, stats: stats})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Rule not found"})
    end
  end

  @doc """
  Create a new rule.
  POST /api/v1/autonomous/rules
  """
  def create_rule(conn, %{"rule" => rule_params}) do
    org_id = get_org_id(conn)
    params = Map.put(rule_params, "organization_id", org_id)

    case AutonomousRules.create_rule(atomize_keys(params)) do
      {:ok, rule} ->
        conn
        |> put_status(201)
        |> json(%{success: true, rule: rule})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Update a rule.
  PUT /api/v1/autonomous/rules/:id
  """
  def update_rule(conn, %{"id" => rule_id, "rule" => rule_params}) do
    case AutonomousRules.update_rule(rule_id, atomize_keys(rule_params)) do
      {:ok, rule} ->
        json(conn, %{success: true, rule: rule})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Rule not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Delete a rule.
  DELETE /api/v1/autonomous/rules/:id
  """
  def delete_rule(conn, %{"id" => rule_id}) do
    case AutonomousRules.delete_rule(rule_id) do
      :ok ->
        json(conn, %{success: true, message: "Rule deleted"})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Rule not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Enable or disable a rule.
  POST /api/v1/autonomous/rules/:id/toggle
  """
  def toggle_rule(conn, %{"id" => rule_id} = params) do
    enabled = params["enabled"] == true or params["enabled"] == "true"

    case AutonomousRules.set_rule_enabled(rule_id, enabled) do
      {:ok, rule} ->
        json(conn, %{
          success: true,
          rule: rule,
          message: if(enabled, do: "Rule enabled", else: "Rule disabled")
        })

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Test a rule against sample data.
  POST /api/v1/autonomous/rules/:id/test
  """
  def test_rule(conn, %{"id" => rule_id, "sample_data" => sample_data}) do
    case AutonomousRules.test_rule(rule_id, atomize_keys(sample_data)) do
      {:ok, result} ->
        json(conn, %{success: true, test_result: result})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Rule not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Get rule templates.
  GET /api/v1/autonomous/rules/templates
  """
  def rule_templates(conn, _params) do
    templates = AutonomousRules.get_templates()
    json(conn, %{templates: templates})
  end

  @doc """
  Clone a rule template.
  POST /api/v1/autonomous/rules/clone-template
  """
  def clone_template(conn, %{"template_id" => template_id} = params) do
    org_id = get_org_id(conn)
    overrides = atomize_keys(params["overrides"] || %{})

    case AutonomousRules.clone_template(template_id, org_id, overrides) do
      {:ok, rule} ->
        conn
        |> put_status(201)
        |> json(%{success: true, rule: rule})

      {:error, :template_not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Template not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Get rule schema (available conditions, operators, actions).
  GET /api/v1/autonomous/rules/schema
  """
  def rule_schema(conn, _params) do
    schema = AutonomousRules.get_schema()
    json(conn, schema)
  end

  # ============================================================================
  # Learning Endpoints
  # ============================================================================

  @doc """
  Get analyst learning statistics.
  GET /api/v1/autonomous/learning/stats
  """
  def learning_stats(conn, _params) do
    org_id = get_org_id(conn)
    stats = AnalystLearning.get_learning_stats(org_id)
    json(conn, stats)
  end

  @doc """
  Get learned patterns.
  GET /api/v1/autonomous/learning/patterns
  """
  def learned_patterns(conn, _params) do
    org_id = get_org_id(conn)
    patterns = AnalystLearning.get_learned_patterns(org_id)
    json(conn, %{patterns: patterns})
  end

  @doc """
  Get analyst decision history.
  GET /api/v1/autonomous/learning/history
  """
  def decision_history(conn, params) do
    org_id = get_org_id(conn)
    limit = bounded_limit(params["limit"], 100, 500)
    user_id = params["user_id"]

    opts = [organization_id: org_id, limit: limit]
    opts = if user_id, do: Keyword.put(opts, :user_id, user_id), else: opts

    history = AnalystLearning.get_decision_history(opts)

    json(conn, %{
      history: history,
      count: length(history)
    })
  end

  @doc """
  Get analyst profile.
  GET /api/v1/autonomous/learning/analysts/:id
  """
  def analyst_profile(conn, %{"id" => analyst_id}) do
    profile = AnalystLearning.get_analyst_profile(analyst_id)
    json(conn, %{profile: profile})
  end

  @doc """
  Trigger model retraining.
  POST /api/v1/autonomous/learning/retrain
  """
  def retrain_model(conn, _params) do
    org_id = get_org_id(conn)

    case AnalystLearning.retrain_model(org_id) do
      {:ok, metrics} ->
        json(conn, %{success: true, metrics: metrics})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  @doc """
  Provide feedback on a past recommendation.
  POST /api/v1/autonomous/learning/feedback
  """
  def provide_feedback(conn, %{"recommendation_id" => rec_id, "feedback" => feedback}) do
    AnalystLearning.provide_feedback(rec_id, atomize_keys(feedback))
    json(conn, %{success: true, message: "Feedback recorded"})
  end

  # ============================================================================
  # Asset Criticality Endpoints
  # ============================================================================

  @doc """
  Get asset criticality for an agent.
  GET /api/v1/autonomous/assets/:agent_id/criticality
  """
  def get_asset_criticality(conn, %{"agent_id" => agent_id}) do
    criticality = Criticality.get_criticality(agent_id)
    json(conn, criticality)
  end

  @doc """
  Set asset criticality override.
  PUT /api/v1/autonomous/assets/:agent_id/criticality
  """
  def set_asset_criticality(conn, %{"agent_id" => agent_id} = params) do
    attrs = params
    |> Map.drop(["agent_id"])
    |> atomize_keys()

    case Criticality.set_criticality(agent_id, attrs) do
      {:ok, criticality} ->
        json(conn, %{success: true, criticality: criticality})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  @doc """
  Clear asset criticality override.
  DELETE /api/v1/autonomous/assets/:agent_id/criticality
  """
  def clear_asset_criticality(conn, %{"agent_id" => agent_id}) do
    Criticality.clear_criticality(agent_id)
    json(conn, %{success: true, message: "Criticality override cleared"})
  end

  @doc """
  List all assets with criticality.
  GET /api/v1/autonomous/assets
  """
  def list_assets(conn, params) do
    org_id = get_org_id(conn)
    level = params["level"]

    opts = [organization_id: org_id]
    opts = if level do
      case safe_to_existing_atom(level, ~w(low medium high critical)) do
        nil -> opts
        level_atom -> Keyword.put(opts, :level, level_atom)
      end
    else
      opts
    end

    assets = Criticality.list_assets(opts)

    json(conn, %{
      assets: assets,
      count: length(assets)
    })
  end

  @doc """
  Get critical assets.
  GET /api/v1/autonomous/assets/critical
  """
  def critical_assets(conn, _params) do
    org_id = get_org_id(conn)
    assets = Criticality.get_critical_assets(org_id)

    json(conn, %{
      assets: assets,
      count: length(assets)
    })
  end

  @doc """
  Get asset criticality distribution.
  GET /api/v1/autonomous/assets/distribution
  """
  def criticality_distribution(conn, _params) do
    org_id = get_org_id(conn)
    distribution = Criticality.get_distribution(org_id)
    json(conn, distribution)
  end

  @doc """
  Bulk import asset criticality data.
  POST /api/v1/autonomous/assets/import
  """
  def import_criticality(conn, %{"assets" => assets}) do
    case Criticality.bulk_import(assets) do
      {:ok, count} ->
        json(conn, %{success: true, imported: count})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Refresh asset criticality.
  POST /api/v1/autonomous/assets/:agent_id/refresh
  """
  def refresh_criticality(conn, %{"agent_id" => agent_id}) do
    case Criticality.refresh_criticality(agent_id) do
      {:ok, criticality} ->
        json(conn, %{success: true, criticality: criticality})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  # ============================================================================
  # Dashboard / Stats Endpoints
  # ============================================================================

  @doc """
  Get autonomous response dashboard data.
  GET /api/v1/autonomous/dashboard
  """
  def dashboard(conn, _params) do
    org_id = get_org_id(conn)

    # Gather dashboard data
    {:ok, settings} = DecisionEngine.get_settings(org_id)
    {:ok, pending} = DecisionEngine.get_pending_recommendations(org_id)
    {:ok, history} = DecisionEngine.get_action_history(organization_id: org_id, limit: 10)
    rate_status = DecisionEngine.rate_limit_status(org_id)
    learning_stats = AnalystLearning.get_learning_stats(org_id)
    critical_assets = Criticality.get_critical_assets(org_id)
    rules = AutonomousRules.list_rules(org_id, enabled_only: true)

    # Calculate summary stats
    auto_executed_count = Enum.count(history, fn h -> h[:status] == "auto_executed" end)
    approved_count = Enum.count(history, fn h -> h[:status] == "approved" end)
    rejected_count = Enum.count(history, fn h -> h[:status] == "rejected" end)

    json(conn, %{
      settings: settings,
      rate_limit_status: rate_status,
      pending_recommendations: %{
        count: length(pending),
        items: Enum.take(pending, 5)
      },
      recent_actions: %{
        count: length(history),
        items: history
      },
      stats: %{
        auto_executed: auto_executed_count,
        approved: approved_count,
        rejected: rejected_count,
        pending: length(pending)
      },
      learning: learning_stats,
      critical_assets_count: length(critical_assets),
      active_rules_count: length(rules)
    })
  end

  # ============================================================================
  # ML Autonomous Engine Endpoints (AutonomousEngine GenServer)
  # ============================================================================

  @doc """
  Get autonomous engine aggregate statistics.
  GET /api/v1/autonomous-response/stats
  """
  def engine_stats(conn, _params) do
    {:ok, stats} = AutonomousEngine.get_stats()
    json(conn, %{stats: stats})
  end

  @doc """
  Get recent autonomous engine decisions.
  GET /api/v1/autonomous-response/decisions
  """
  def engine_decisions(conn, params) do
    limit = bounded_limit(params["limit"], 100, 500)
    {:ok, decisions} = AutonomousEngine.get_decisions(limit: limit)

    json(conn, %{
      decisions: decisions,
      count: length(decisions)
    })
  end

  @doc """
  Assess risk for an alert through the ML engine.
  POST /api/v1/autonomous-response/assess
  """
  def engine_assess(conn, %{"alert_id" => alert_id}) do
    org_id = get_org_id(conn)

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        {:ok, assessment} = AutonomousEngine.assess_risk(alert)
        json(conn, %{assessment: assessment})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Alert not found"})
    end
  end

  def engine_assess(conn, %{"alert" => alert_data}) do
    {:ok, assessment} = AutonomousEngine.assess_risk(alert_data)
    json(conn, %{assessment: assessment})
  end

  @doc """
  Record analyst feedback on a decision.
  POST /api/v1/autonomous-response/feedback
  """
  def engine_feedback(conn, %{"alert_id" => alert_id, "verdict" => verdict} = params) do
    metadata = Map.drop(params, ["alert_id", "verdict"])
    AutonomousEngine.record_outcome(alert_id, verdict, metadata)
    json(conn, %{success: true, message: "Feedback recorded"})
  end

  @doc """
  Get current ML engine confidence thresholds.
  GET /api/v1/autonomous-response/thresholds
  """
  def engine_get_thresholds(conn, _params) do
    {:ok, thresholds} = AutonomousEngine.get_thresholds()
    json(conn, %{thresholds: thresholds})
  end

  @doc """
  Update ML engine confidence thresholds.
  PUT /api/v1/autonomous-response/thresholds
  """
  def engine_update_thresholds(conn, %{"thresholds" => thresholds}) do
    {:ok, updated} = AutonomousEngine.update_thresholds(atomize_keys(thresholds))
    json(conn, %{success: true, thresholds: updated})
  end

  @doc """
  Get ML engine asset criticality for an agent.
  GET /api/v1/autonomous-response/asset-criticality/:agent_id
  """
  def engine_get_criticality(conn, %{"agent_id" => agent_id}) do
    criticality = AutonomousEngine.get_asset_criticality(agent_id)
    json(conn, %{agent_id: agent_id, criticality: criticality})
  end

  @doc """
  Set ML engine asset criticality for an agent.
  PUT /api/v1/autonomous-response/asset-criticality/:agent_id
  """
  def engine_set_criticality(conn, %{"agent_id" => agent_id} = params) do
    attrs = Map.drop(params, ["agent_id"])
    :ok = AutonomousEngine.set_asset_criticality(agent_id, atomize_keys(attrs))
    criticality = AutonomousEngine.get_asset_criticality(agent_id)
    json(conn, %{success: true, agent_id: agent_id, criticality: criticality})
  end

  @doc """
  Simulate the autonomous response pipeline (dry run).
  POST /api/v1/autonomous-response/simulate
  """
  def engine_simulate(conn, %{"alert_id" => alert_id}) do
    org_id = get_org_id(conn)

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        {:ok, result} = AutonomousEngine.simulate(alert)
        json(conn, %{simulation: result})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Alert not found"})
    end
  end

  def engine_simulate(conn, %{"alert" => alert_data}) do
    {:ok, result} = AutonomousEngine.simulate(alert_data)
    json(conn, %{simulation: result})
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_org_id(conn) do
    case conn.assigns do
      %{current_organization: org} when not is_nil(org) -> org.id
      %{current_user: user} when not is_nil(user) -> user.organization_id
      _ -> nil
    end
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) ->
        key = try do
          String.to_existing_atom(k)
        rescue
          ArgumentError -> k
        end
        {key, atomize_keys(v)}
      {k, v} -> {k, atomize_keys(v)}
    end)
  end

  defp atomize_keys(list) when is_list(list) do
    Enum.map(list, &atomize_keys/1)
  end

  defp atomize_keys(value), do: value

  defp bounded_limit(value, default, max_limit),
    do: value |> parse_int(default) |> max(1) |> min(max_limit)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

end
