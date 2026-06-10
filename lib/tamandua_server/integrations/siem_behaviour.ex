defmodule TamanduaServer.Integrations.SIEMBehaviour do
  @moduledoc """
  Common behaviour for SIEM (Security Information and Event Management) integrations.

  All SIEM connectors (Splunk, Sentinel, Elastic, etc.) should implement this behaviour
  to ensure a consistent interface for sending events and alerts.
  """

  @doc """
  Send a batch of events to the SIEM.
  """
  @callback send_events(events :: [map()]) :: :ok | {:error, term()}

  @doc """
  Send alerts to the SIEM.
  """
  @callback send_alerts(alerts :: [map()]) :: :ok | {:error, term()}
end
