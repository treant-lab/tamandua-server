defmodule TamanduaServerWeb.API.V1.SigmaRuleController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.Rules

  action_fallback TamanduaServerWeb.FallbackController

  def index(conn, params) do
    filters = %{
      enabled: params["enabled"],
      category: params["category"]
    }

    rules = Rules.list_sigma_rules(filters)
    json(conn, %{data: Enum.map(rules, &serialize/1)})
  end

  def show(conn, %{"id" => id}) do
    rule = Rules.get_sigma_rule!(id)
    json(conn, %{data: serialize(rule)})
  end

  def create(conn, params) do
    attrs = normalize_rule_params(params)

    case Rules.create_sigma_rule(attrs) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize(rule)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def update(conn, %{"id" => id} = params) do
    rule = Rules.get_sigma_rule!(id)
    attrs = params |> Map.delete("id") |> normalize_rule_params()

    case Rules.update_sigma_rule(rule, attrs) do
      {:ok, rule} ->
        json(conn, %{data: serialize(rule)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def delete(conn, %{"id" => id}) do
    rule = Rules.get_sigma_rule!(id)

    case Rules.delete_sigma_rule(rule) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, _} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to delete rule"})
    end
  end

  defp serialize(rule) do
    %{
      id: rule.id,
      name: rule.name,
      title: rule.title,
      description: rule.description,
      content: rule.source,
      source: rule.source,
      enabled: rule.enabled,
      level: rule.level,
      status: rule.status,
      author: rule.author,
      tags: rule.tags || [],
      detection: rule.detection || %{},
      falsepositives: [],
      logsource_category: rule.logsource_category,
      logsource: %{
        category: rule.logsource_category,
        product: rule.logsource_product,
        service: rule.logsource_service
      },
      mitre_tactics: rule.mitre_tactics || [],
      mitre_techniques: rule.mitre_techniques || [],
      mitre_attack: rule.mitre_techniques || [],
      inserted_at: iso8601(rule.inserted_at),
      updated_at: iso8601(rule.updated_at),
      created_at: iso8601(rule.inserted_at)
    }
  end

  defp iso8601(nil), do: nil
  defp iso8601(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp iso8601(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp iso8601(value) when is_binary(value), do: value

  defp normalize_rule_params(%{"sigma_rule" => attrs}) when is_map(attrs), do: normalize_rule_params(attrs)

  defp normalize_rule_params(attrs) when is_map(attrs) do
    attrs
    |> Map.delete("id")
    |> maybe_copy_content_to_source()
  end

  defp maybe_copy_content_to_source(%{"content" => content} = attrs)
       when is_binary(content) and content != "" do
    Map.put_new(attrs, "source", content)
  end

  defp maybe_copy_content_to_source(attrs), do: attrs

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_atom(key), key) |> to_string()
      end)
    end)
  end
end
