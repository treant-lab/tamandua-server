defmodule TamanduaServer.Integrations.WebhookParsers do
  @moduledoc """
  Router for integration-specific webhook parsers.

  Returns the appropriate parser module for each integration type.
  """

  @parsers %{
    splunk: TamanduaServer.Integrations.WebhookParsers.Splunk,
    sentinel: TamanduaServer.Integrations.WebhookParsers.Sentinel,
    qradar: TamanduaServer.Integrations.WebhookParsers.QRadar,
    jira: TamanduaServer.Integrations.WebhookParsers.Jira,
    servicenow: TamanduaServer.Integrations.WebhookParsers.ServiceNow,
    pagerduty: TamanduaServer.Integrations.WebhookParsers.PagerDuty,
    slack: TamanduaServer.Integrations.WebhookParsers.Slack,
    generic: TamanduaServer.Integrations.WebhookParsers.Generic
  }

  @doc """
  Get the parser module for an integration type.
  """
  def get_parser(integration_type) when is_atom(integration_type) do
    Map.get(@parsers, integration_type, @parsers.generic)
  end

  def get_parser(integration_type) when is_binary(integration_type) do
    integration_type
    |> String.to_existing_atom()
    |> get_parser()
  rescue
    ArgumentError -> @parsers.generic
  end

  @doc """
  List all available parsers.
  """
  def available_parsers, do: Map.keys(@parsers)
end
