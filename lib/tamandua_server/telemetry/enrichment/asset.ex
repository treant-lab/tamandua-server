defmodule TamanduaServer.Telemetry.Enrichment.Asset do
  @moduledoc """
  Enriches telemetry events with asset context information.

  Adds information about the agent/endpoint such as:
  - Hostname
  - Operating system
  - Asset tags
  - Criticality level
  - Location
  - Organization

  Enrichment is added to the event under the :enrichment.asset key.
  """

  require Logger
  alias TamanduaServer.Telemetry.Enrichment.Cache

  @doc """
  Enrich an event with asset context.

  Looks up the agent's metadata and adds it to the enrichment map.

  ## Examples

      iex> enrich_event(%{agent_id: "agent-123", event_type: "process_create"})
      %{agent_id: "agent-123", enrichment: %{asset: %{hostname: "workstation-1", ...}}}
  """
  @spec enrich_event(map()) :: map()
  def enrich_event(event) do
    agent_id = event[:agent_id] || event["agent_id"]

    if agent_id do
      case Cache.get_or_lookup_asset(agent_id) do
        {:ok, asset_info} ->
          enrichment = Map.get(event, :enrichment, %{})
          enrichment = Map.put(enrichment, :asset, asset_info)
          Map.put(event, :enrichment, enrichment)

        {:error, _reason} ->
          # Asset not found or lookup failed, return event unchanged
          event
      end
    else
      event
    end
  end
end
