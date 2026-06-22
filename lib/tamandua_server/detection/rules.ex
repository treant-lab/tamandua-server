defmodule TamanduaServer.Detection.Rules do
  @moduledoc """
  Facade module for rule management.
  Provides unified interface for YARA and Sigma rules.
  """

  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.{YaraRule, SigmaRule}
  alias TamanduaServer.Repo
  import Ecto.Query

  # Sigma Rules

  def list_sigma_rules(filters \\ %{}) do
    from(r in SigmaRule, order_by: [desc: r.inserted_at])
    |> apply_sigma_filters(filters)
    |> apply_pagination(filters)
    |> Repo.all()
  end

  def count_sigma_rules(filters \\ %{}) do
    SigmaRule
    |> apply_sigma_filters(filters)
    |> Repo.aggregate(:count, :id)
  end

  defp apply_sigma_filters(query, filters) do
    if filters[:enabled] != nil do
      enabled = parse_boolean(filters[:enabled])
      where(query, [r], r.enabled == ^enabled)
    else
      query
    end
  end

  def get_sigma_rule!(id), do: Repo.get!(SigmaRule, id)

  def create_sigma_rule(attrs), do: Detection.create_sigma_rule(attrs)

  def update_sigma_rule(rule, attrs), do: Detection.update_sigma_rule(rule, attrs)

  def delete_sigma_rule(rule), do: Detection.delete_sigma_rule(rule)

  # YARA Rules

  def list_yara_rules(filters \\ %{}) do
    from(r in YaraRule, order_by: [desc: r.inserted_at])
    |> apply_yara_filters(filters)
    |> apply_pagination(filters)
    |> Repo.all()
  end

  def count_yara_rules(filters \\ %{}) do
    YaraRule
    |> apply_yara_filters(filters)
    |> Repo.aggregate(:count, :id)
  end

  defp apply_yara_filters(query, filters) do
    query
    |> maybe_filter_enabled(filters)
    |> maybe_filter_category(filters)
  end

  defp maybe_filter_enabled(query, %{enabled: nil}), do: query
  defp maybe_filter_enabled(query, %{enabled: value}) when not is_nil(value) do
    enabled = parse_boolean(value)
    where(query, [r], r.enabled == ^enabled)
  end
  defp maybe_filter_enabled(query, _), do: query

  defp maybe_filter_category(query, %{category: nil}), do: query
  defp maybe_filter_category(query, %{category: ""}), do: query
  defp maybe_filter_category(query, %{category: cat}) when is_binary(cat) do
    where(query, [r], r.category == ^cat)
  end
  defp maybe_filter_category(query, _), do: query

  def get_yara_rule!(id), do: Repo.get!(YaraRule, id)

  def create_yara_rule(attrs), do: Detection.create_yara_rule(attrs)

  def update_yara_rule(rule, attrs), do: Detection.update_yara_rule(rule, attrs)

  def delete_yara_rule(rule), do: Detection.delete_yara_rule(rule)

  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(true), do: true
  defp parse_boolean(false), do: false
  defp parse_boolean(_), do: nil

  # Applies :limit and :offset from the filter map. Missing/invalid values are
  # ignored so callers can pass raw query params; clamping (defaults, ceilings)
  # is the controller's responsibility.
  defp apply_pagination(query, filters) do
    query
    |> maybe_limit(filters[:limit])
    |> maybe_offset(filters[:offset])
  end

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, n) when is_integer(n) and n > 0, do: limit(query, ^n)
  defp maybe_limit(query, _), do: query

  defp maybe_offset(query, nil), do: query
  defp maybe_offset(query, n) when is_integer(n) and n >= 0, do: offset(query, ^n)
  defp maybe_offset(query, _), do: query
end
