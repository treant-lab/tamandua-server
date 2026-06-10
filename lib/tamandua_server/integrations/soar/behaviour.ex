defmodule TamanduaServer.Integrations.SOAR.Behaviour do
  @moduledoc """
  Common behaviour for SOAR (Security Orchestration, Automation and Response) integrations.

  All SOAR connectors should implement this behaviour to ensure a consistent interface.
  """

  @doc """
  Trigger a playbook execution.
  """
  @callback trigger_playbook(playbook_name :: String.t(), params :: map()) ::
              {:ok, run_id :: String.t()} | {:error, term()}

  @doc """
  Get the status of a playbook run.
  """
  @callback get_playbook_status(run_id :: String.t()) ::
              {:ok, status :: map()} | {:error, term()}

  @doc """
  Create an incident/case.
  """
  @callback create_incident(incident_data :: map()) ::
              {:ok, incident_id :: String.t()} | {:error, term()}

  @doc """
  Update an existing incident.
  """
  @callback update_incident(incident_id :: String.t(), updates :: map()) ::
              :ok | {:error, term()}

  @doc """
  Get incident details.
  """
  @callback get_incident(incident_id :: String.t()) ::
              {:ok, incident :: map()} | {:error, term()}

  @doc """
  Add an artifact/indicator to an incident.
  """
  @callback add_artifact(incident_id :: String.t(), artifact :: map()) ::
              {:ok, artifact_id :: String.t()} | {:error, term()}

  @doc """
  List available playbooks.
  """
  @callback list_playbooks(opts :: keyword()) ::
              {:ok, playbooks :: [map()]} | {:error, term()}

  @doc """
  Test the connection to the SOAR platform.
  """
  @callback test_connection() ::
              {:ok, message :: String.t()} | {:error, term()}

  @doc """
  Get integration statistics.
  """
  @callback get_stats() :: map()
end
