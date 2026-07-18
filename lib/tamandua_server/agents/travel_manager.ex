defmodule TamanduaServer.Agents.TravelManager do
  @moduledoc """
  Manages travel requests and temporary geofencing exceptions.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{GeoTravelRequest}

  @doc """
  Create a travel request.
  """
  def create_travel_request(attrs) do
    %GeoTravelRequest{}
    |> GeoTravelRequest.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Approve a travel request.
  """
  def approve_travel_request(request_id, approved_by_id, opts \\ []) do
    request = Repo.get!(GeoTravelRequest, request_id)

    attrs = %{
      status: "approved",
      approved_by_id: approved_by_id,
      approved_at: DateTime.utc_now(),
      auto_approved: Keyword.get(opts, :auto_approved, false)
    }

    request
    |> GeoTravelRequest.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deny a travel request.
  """
  def deny_travel_request(request_id, denied_by_id, reason) do
    request = Repo.get!(GeoTravelRequest, request_id)

    attrs = %{
      status: "denied",
      denied_by_id: denied_by_id,
      denied_at: DateTime.utc_now(),
      denial_reason: reason
    }

    request
    |> GeoTravelRequest.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get pending travel requests for an organization.
  """
  def list_pending_requests(organization_id) do
    query =
      from t in GeoTravelRequest,
        where: t.organization_id == ^organization_id and t.status == "pending",
        order_by: [asc: t.start_date],
        preload: [:agent, :requested_by, :destination_region]

    Repo.all(query)
  end

  @doc """
  Get active travel requests for an agent.
  """
  def get_active_travel(agent_id) do
    today = Date.utc_today()

    query =
      from t in GeoTravelRequest,
        where:
          t.agent_id == ^agent_id and
            t.status == "approved" and
            t.start_date <= ^today and
            t.end_date >= ^today,
        preload: [:destination_region]

    Repo.all(query)
  end

  @doc """
  Check if a location is covered by an active travel request.
  """
  def location_approved_for_travel?(agent_id, country_code, city \\ nil) do
    active_travel = get_active_travel(agent_id)

    Enum.any?(active_travel, fn request ->
      request.destination_country == country_code &&
        (is_nil(city) || is_nil(request.destination_city) ||
           request.destination_city == city)
    end)
  end

  @doc """
  Expire old travel requests.
  Should be run periodically (daily cron job).
  """
  def expire_old_requests do
    today = Date.utc_today()

    query =
      from t in GeoTravelRequest,
        where: t.status == "approved" and t.end_date < ^today

    {count, _} = Repo.update_all(query, set: [status: "expired"])

    Logger.info("Expired #{count} travel requests")
    {:ok, count}
  end

  @doc """
  Auto-approve travel requests based on policy.
  For example, auto-approve requests to allowed regions.
  """
  def auto_approve_if_eligible(request_id) do
    request = Repo.get!(GeoTravelRequest, request_id) |> Repo.preload([:agent, :destination_region])

    if eligible_for_auto_approval?(request) do
      approve_travel_request(request_id, nil, auto_approved: true)
    else
      {:ok, request}
    end
  end

  ## Private Functions

  defp eligible_for_auto_approval?(_request) do
    # Check if destination is in allowed regions for this agent
    # This would require checking geofencing rules
    # For now, return false (manual approval required)
    false
  end
end
