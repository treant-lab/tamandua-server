defmodule TamanduaServer.ThreatIntel.EmergingThreats do
  @moduledoc """
  Pure context helpers for emerging threat records.
  """

  alias TamanduaServer.ThreatIntel.EmergingThreat

  @doc """
  Normalizes a list of source records into valid emerging threat structs.

  Invalid records are returned with their original index so ingestion callers can
  decide whether to drop, dead-letter, or surface validation issues.
  """
  @spec normalize_many([map()]) :: {:ok, [EmergingThreat.t()]} | {:error, [map()]}
  def normalize_many(records) when is_list(records) do
    records
    |> Enum.with_index()
    |> Enum.reduce({[], []}, fn {attrs, index}, {valid, invalid} ->
      case EmergingThreat.new(attrs) do
        {:ok, threat} -> {[threat | valid], invalid}
        {:error, errors} -> {valid, [%{index: index, errors: errors, record: attrs} | invalid]}
      end
    end)
    |> case do
      {valid, []} -> {:ok, Enum.reverse(valid)}
      {_valid, invalid} -> {:error, Enum.reverse(invalid)}
    end
  end

  @doc """
  Scores and ranks threats highest first.
  """
  @spec rank([EmergingThreat.t() | map()]) :: [map()]
  def rank(threats) when is_list(threats) do
    threats
    |> Enum.map(&normalize_or_raise/1)
    |> Enum.map(fn threat ->
      threat
      |> EmergingThreat.to_map()
      |> Map.merge(EmergingThreat.score(threat))
    end)
    |> Enum.sort_by(&{-&1.score, &1.id})
  end

  @doc """
  Groups ranked threats by severity derived from the deterministic score.
  """
  @spec grouped_by_scored_severity([EmergingThreat.t() | map()]) :: map()
  def grouped_by_scored_severity(threats) when is_list(threats) do
    threats
    |> rank()
    |> Enum.group_by(fn threat -> EmergingThreat.severity_for_score(threat.score) end)
  end

  defp normalize_or_raise(%EmergingThreat{} = threat), do: threat
  defp normalize_or_raise(attrs) when is_map(attrs), do: EmergingThreat.new!(attrs)
end
