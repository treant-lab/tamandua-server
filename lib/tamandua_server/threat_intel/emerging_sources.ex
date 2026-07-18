defmodule TamanduaServer.ThreatIntel.EmergingSources do
  @moduledoc """
  Public entry point for Emerging Threats source aggregation.
  """

  alias TamanduaServer.ThreatIntel.EmergingSources.Aggregator

  @doc """
  Aggregate available local/static sources into normalized EmergingThreat candidates.
  """
  @spec aggregate(keyword()) :: map()
  defdelegate aggregate(opts \\ []), to: Aggregator

  @doc """
  Return health and gap information for Emerging Threat source inputs.
  """
  @spec source_health(keyword()) :: map()
  defdelegate source_health(opts \\ []), to: Aggregator
end
