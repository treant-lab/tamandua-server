defmodule TamanduaServer.AlertsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `TamanduaServer.Alerts` context.
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  def alert_fixture(attrs \\ %{}) do
    organization_id = attrs[:organization_id] || raise "organization_id required"

    attrs =
      attrs
      |> Enum.into(%{
        title: "Test Alert #{System.unique_integer([:positive])}",
        description: "Test alert description",
        severity: "high",
        status: "new",
        organization_id: organization_id,
        agent_id: attrs[:agent_id] || Ecto.UUID.generate()
      })

    %Alert{}
    |> Alert.changeset(attrs)
    |> Repo.insert!()
  end
end
