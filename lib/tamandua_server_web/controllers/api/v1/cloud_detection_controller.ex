defmodule TamanduaServerWeb.API.V1.CloudDetectionController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Cloud.DetectionRules

  @doc """
  List all cloud detection rules.
  GET /api/v1/cloud/detection/rules
  """
  def index(conn, params) do
    rules = case params do
      %{"provider" => provider} ->
        case parse_provider(provider) do
          nil -> DetectionRules.all_rules()
          provider_atom -> DetectionRules.get_rules_by_provider(provider_atom)
        end
      %{"mitre" => technique} ->
        DetectionRules.get_rules_by_mitre(technique)
      %{"category" => category} ->
        rules_by_category = DetectionRules.get_rules_by_category()
        case safe_to_existing_atom(category) do
          nil -> []
          cat_atom -> Map.get(rules_by_category, cat_atom, [])
        end
      _ ->
        DetectionRules.all_rules()
    end

    json(conn, %{
      success: true,
      data: %{
        rules: Enum.map(rules, &format_rule/1),
        total: length(rules)
      }
    })
  end

  @doc """
  Get a specific cloud detection rule.
  GET /api/v1/cloud/detection/rules/:id
  """
  def show(conn, %{"id" => rule_id}) do
    case DetectionRules.get_rule(rule_id) do
      {:ok, rule} ->
        json(conn, %{success: true, data: format_rule(rule)})
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{success: false, error: "Rule not found"})
    end
  end

  @doc """
  Get detection coverage statistics.
  GET /api/v1/cloud/detection/stats
  """
  def stats(conn, _params) do
    stats = DetectionRules.get_coverage_stats()
    json(conn, %{success: true, data: stats})
  end

  @doc """
  Get rules grouped by category.
  GET /api/v1/cloud/detection/categories
  """
  def categories(conn, _params) do
    rules_by_category = DetectionRules.get_rules_by_category()

    formatted = Enum.map(rules_by_category, fn {category, rules} ->
      %{
        category: category,
        count: length(rules),
        rules: Enum.map(rules, &format_rule_summary/1)
      }
    end)

    json(conn, %{success: true, data: formatted})
  end

  @doc """
  Evaluate an event against cloud detection rules.
  POST /api/v1/cloud/detection/evaluate
  """
  def evaluate(conn, %{"event" => event}) do
    event_map = atomize_keys(event)

    case DetectionRules.evaluate_event(event_map) do
      {:ok, matches} ->
        json(conn, %{
          success: true,
          data: %{
            matched: length(matches) > 0,
            matches: Enum.map(matches, &format_rule_summary/1),
            count: length(matches)
          }
        })
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Evaluate a CloudTrail event.
  POST /api/v1/cloud/detection/evaluate/cloudtrail
  """
  def evaluate_cloudtrail(conn, %{"event" => event}) do
    event_map = atomize_keys(event)
    matches = DetectionRules.evaluate_cloudtrail(event_map)

    json(conn, %{
      success: true,
      data: %{
        matched: length(matches) > 0,
        matches: Enum.map(matches, &format_rule_summary/1),
        count: length(matches)
      }
    })
  end

  @doc """
  Evaluate an Azure Activity Log event.
  POST /api/v1/cloud/detection/evaluate/azure
  """
  def evaluate_azure(conn, %{"event" => event}) do
    event_map = atomize_keys(event)
    matches = DetectionRules.evaluate_activity_log(event_map)

    json(conn, %{
      success: true,
      data: %{
        matched: length(matches) > 0,
        matches: Enum.map(matches, &format_rule_summary/1),
        count: length(matches)
      }
    })
  end

  @doc """
  Evaluate a GCP Audit Log event.
  POST /api/v1/cloud/detection/evaluate/gcp
  """
  def evaluate_gcp(conn, %{"event" => event}) do
    event_map = atomize_keys(event)
    matches = DetectionRules.evaluate_audit_log(event_map)

    json(conn, %{
      success: true,
      data: %{
        matched: length(matches) > 0,
        matches: Enum.map(matches, &format_rule_summary/1),
        count: length(matches)
      }
    })
  end

  @doc """
  Evaluate a runtime event.
  POST /api/v1/cloud/detection/evaluate/runtime
  """
  def evaluate_runtime(conn, %{"event" => event}) do
    event_map = atomize_keys(event)
    matches = DetectionRules.evaluate_runtime(event_map)

    json(conn, %{
      success: true,
      data: %{
        matched: length(matches) > 0,
        matches: Enum.map(matches, &format_rule_summary/1),
        count: length(matches)
      }
    })
  end

  @doc """
  Evaluate a Kubernetes event.
  POST /api/v1/cloud/detection/evaluate/kubernetes
  """
  def evaluate_kubernetes(conn, %{"event" => event}) do
    event_map = atomize_keys(event)
    matches = DetectionRules.evaluate_kubernetes(event_map)

    json(conn, %{
      success: true,
      data: %{
        matched: length(matches) > 0,
        matches: Enum.map(matches, &format_rule_summary/1),
        count: length(matches)
      }
    })
  end

  # Private helpers

  defp format_rule(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      mitre: rule.mitre,
      provider: rule.provider,
      rule_type: rule.rule_type,
      condition: rule.condition,
      indicators: Map.get(rule, :indicators)
    }
  end

  defp format_rule_summary(rule) do
    %{
      id: rule.id,
      name: rule.name,
      severity: rule.severity,
      mitre: rule.mitre,
      provider: rule.provider
    }
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
  defp atomize_keys(list) when is_list(list), do: Enum.map(list, &atomize_keys/1)
  defp atomize_keys(value), do: value

  defp parse_provider("aws"), do: :aws
  defp parse_provider("azure"), do: :azure
  defp parse_provider("gcp"), do: :gcp
  defp parse_provider("all"), do: :all
  defp parse_provider(_), do: nil

  defp safe_to_existing_atom(str) when is_binary(str) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> nil
  end
end
