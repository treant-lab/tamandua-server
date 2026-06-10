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
    query = from(r in SigmaRule, order_by: [desc: r.inserted_at])

    query = if filters[:enabled] != nil do
      enabled = parse_boolean(filters[:enabled])
      where(query, [r], r.enabled == ^enabled)
    else
      query
    end

    Repo.all(query)
  end

  def get_sigma_rule!(id), do: Repo.get!(SigmaRule, id)

  def create_sigma_rule(attrs), do: Detection.create_sigma_rule(attrs)

  def update_sigma_rule(rule, attrs), do: Detection.update_sigma_rule(rule, attrs)

  def delete_sigma_rule(rule), do: Detection.delete_sigma_rule(rule)

  # YARA Rules

  def list_yara_rules(filters \\ %{}) do
    query = from(r in YaraRule, order_by: [desc: r.inserted_at])

    query = if filters[:enabled] != nil do
      enabled = parse_boolean(filters[:enabled])
      where(query, [r], r.enabled == ^enabled)
    else
      query
    end

    query = if filters[:category] do
      where(query, [r], r.category == ^filters[:category])
    else
      query
    end

    Repo.all(query)
  end

  def get_yara_rule!(id), do: Repo.get!(YaraRule, id)

  def create_yara_rule(attrs), do: Detection.create_yara_rule(attrs)

  def update_yara_rule(rule, attrs), do: Detection.update_yara_rule(rule, attrs)

  def delete_yara_rule(rule), do: Detection.delete_yara_rule(rule)

  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(true), do: true
  defp parse_boolean(false), do: false
  defp parse_boolean(_), do: nil
end
