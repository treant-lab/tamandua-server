defmodule TamanduaServer.DeceptionFixtures do
  @moduledoc """
  This module defines test helpers for creating
  deception-related entities (breadcrumbs, access logs, etc.).
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Deception.{BreadcrumbDeployment, BreadcrumbAccessLog}

  @doc """
  Generate a breadcrumb deployment.
  """
  def breadcrumb_deployment_fixture(attrs \\ %{}) do
    {:ok, breadcrumb} =
      attrs
      |> Enum.into(%{
        id: Ecto.UUID.generate(),
        agent_id: "agent-#{:rand.uniform(1000)}",
        type: "credential",
        path: "/home/user/.config/credentials.txt",
        content_hash: "abc123def456",
        canary_token: "TAMANDUA-#{Ecto.UUID.generate() |> String.replace("-", "")}",
        deployed_at: DateTime.utc_now(),
        status: "active",
        access_count: 0,
        metadata: %{}
      })
      |> BreadcrumbDeployment.changeset()
      |> Repo.insert()

    breadcrumb
  end

  @doc """
  Generate a breadcrumb access log.
  """
  def breadcrumb_access_log_fixture(attrs \\ %{}) do
    breadcrumb_id =
      case attrs[:breadcrumb_id] do
        nil ->
          # Create a breadcrumb if not provided
          bc = breadcrumb_deployment_fixture()
          bc.id

        id ->
          id
      end

    {:ok, access_log} =
      attrs
      |> Enum.into(%{
        breadcrumb_id: breadcrumb_id,
        agent_id: "agent-#{:rand.uniform(1000)}",
        accessed_at: DateTime.utc_now(),
        process_name: "suspicious_process",
        pid: :rand.uniform(10000),
        user: "attacker",
        access_type: "read",
        tamper_detected: false,
        original_hash: "abc123",
        new_hash: nil,
        additional_data: %{}
      })
      |> BreadcrumbAccessLog.changeset()
      |> Repo.insert()

    access_log
  end

  @doc """
  Generate an alert with breadcrumb detection metadata.
  """
  def breadcrumb_alert_fixture(attrs \\ %{}) do
    alias TamanduaServer.Alerts.Alert

    {:ok, alert} =
      attrs
      |> Enum.into(%{
        title: "Honeyfile Accessed: Credential File",
        severity: "high",
        description: "A breadcrumb honeypot file was accessed",
        agent_id: "agent-#{:rand.uniform(1000)}",
        mitre_techniques: ["T1083"],
        mitre_tactics: ["discovery"],
        evidence: %{
          file_path: "/home/user/.config/creds.txt",
          process: "cat",
          pid: 1234,
          user: "attacker"
        },
        detection_metadata: %{
          detection_type: "honeypot",
          detection_source: "breadcrumb_monitor",
          breadcrumb_id: Ecto.UUID.generate()
        }
      })
      |> Alert.changeset()
      |> Repo.insert()

    alert
  end

  @doc """
  Generate multiple breadcrumb deployments.
  """
  def create_breadcrumb_deployments(count \\ 5) do
    types = [:credential, :ssh_key, :api_token, :cloud_credential, :document]
    statuses = ["active", "accessed", "rotated"]

    Enum.map(1..count, fn i ->
      breadcrumb_deployment_fixture(%{
        type: Enum.random(types) |> to_string(),
        status: Enum.random(statuses),
        access_count: if(Enum.random([true, false]), do: :rand.uniform(5), else: 0),
        deployed_at: DateTime.add(DateTime.utc_now(), -:rand.uniform(30), :day)
      })
    end)
  end

  @doc """
  Generate multiple breadcrumb access logs.
  """
  def create_breadcrumb_access_logs(breadcrumb_id, count \\ 3) do
    processes = ["cat", "grep", "vi", "powershell.exe", "cmd.exe"]
    users = ["attacker", "compromised_user", "root", "admin"]
    access_types = ["read", "write", "execute", "delete"]

    Enum.map(1..count, fn _i ->
      breadcrumb_access_log_fixture(%{
        breadcrumb_id: breadcrumb_id,
        process_name: Enum.random(processes),
        user: Enum.random(users),
        access_type: Enum.random(access_types),
        tamper_detected: Enum.random([true, false]),
        accessed_at: DateTime.add(DateTime.utc_now(), -:rand.uniform(24), :hour)
      })
    end)
  end
end
