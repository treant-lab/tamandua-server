defmodule TamanduaServer.Agents.GeofencingAPI do
  @moduledoc """
  Public API for geofencing operations.
  Use this module for all geofencing interactions.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    GeoRegion,
    GeofencingRule,
    GeoPolicy,
    VpnWhitelist,
    GeoTravelRequest,
    LocationTracker,
    Geofencing,
    TravelManager
  }

  ## Region Management

  @doc """
  Create a geographic region.

  ## Examples

      # Country region
      iex> create_region(%{
        organization_id: org_id,
        name: "United States",
        region_type: "country",
        definition: %{"country_code" => "US"}
      })
      {:ok, %GeoRegion{}}

      # Radius region
      iex> create_region(%{
        organization_id: org_id,
        name: "Office Area",
        region_type: "radius",
        definition: %{
          "center" => %{"lat" => 40.7128, "lon" => -74.0060},
          "radius_km" => 50
        }
      })
      {:ok, %GeoRegion{}}
  """
  def create_region(attrs) do
    %GeoRegion{}
    |> GeoRegion.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a region.
  """
  def update_region(%GeoRegion{} = region, attrs) do
    region
    |> GeoRegion.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a region.
  """
  def delete_region(%GeoRegion{} = region) do
    Repo.delete(region)
  end

  @doc """
  List all regions for an organization.
  """
  def list_regions(organization_id) do
    query =
      from r in GeoRegion,
        where: r.organization_id == ^organization_id,
        order_by: [asc: r.name]

    Repo.all(query)
  end

  @doc """
  Get a region by ID.
  """
  def get_region(id) do
    Repo.get(GeoRegion, id)
  end

  ## Rule Management

  @doc """
  Create a geofencing rule.

  ## Examples

      # Rule for all agents
      iex> create_rule(%{
        organization_id: org_id,
        name: "US Only",
        scope_type: "all",
        expected_region_ids: [us_region_id],
        alert_on_unexpected: true,
        alert_severity: "high"
      })
      {:ok, %GeofencingRule{}}

      # Rule for tagged agents
      iex> create_rule(%{
        organization_id: org_id,
        name: "Executive Protection",
        scope_type: "tag",
        scope_tags: ["executive"],
        restricted_region_ids: [cn_region_id, ru_region_id],
        auto_isolate_restricted: true
      })
      {:ok, %GeofencingRule{}}
  """
  def create_rule(attrs) do
    %GeofencingRule{}
    |> GeofencingRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a rule.
  """
  def update_rule(%GeofencingRule{} = rule, attrs) do
    rule
    |> GeofencingRule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a rule.
  """
  def delete_rule(%GeofencingRule{} = rule) do
    Repo.delete(rule)
  end

  @doc """
  Enable or disable a rule.
  """
  def toggle_rule(%GeofencingRule{} = rule) do
    rule
    |> Ecto.Changeset.change(is_enabled: !rule.is_enabled)
    |> Repo.update()
  end

  @doc """
  List all rules for an organization.
  """
  def list_rules(organization_id) do
    query =
      from r in GeofencingRule,
        where: r.organization_id == ^organization_id,
        order_by: [desc: r.priority, asc: r.name]

    Repo.all(query)
  end

  @doc """
  Get a rule by ID.
  """
  def get_rule(id) do
    Repo.get(GeofencingRule, id)
  end

  ## Policy Management

  @doc """
  Create a geo policy.

  ## Examples

      iex> create_policy(%{
        organization_id: org_id,
        name: "MFA for Unexpected Locations",
        apply_to_unexpected: true,
        require_mfa: true
      })
      {:ok, %GeoPolicy{}}
  """
  def create_policy(attrs) do
    %GeoPolicy{}
    |> GeoPolicy.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a policy.
  """
  def update_policy(%GeoPolicy{} = policy, attrs) do
    policy
    |> GeoPolicy.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a policy.
  """
  def delete_policy(%GeoPolicy{} = policy) do
    Repo.delete(policy)
  end

  @doc """
  Enable or disable a policy.
  """
  def toggle_policy(%GeoPolicy{} = policy) do
    policy
    |> Ecto.Changeset.change(is_enabled: !policy.is_enabled)
    |> Repo.update()
  end

  @doc """
  List all policies for an organization.
  """
  def list_policies(organization_id) do
    query =
      from p in GeoPolicy,
        where: p.organization_id == ^organization_id,
        order_by: [desc: p.priority, asc: p.name]

    Repo.all(query)
  end

  @doc """
  Get a policy by ID.
  """
  def get_policy(id) do
    Repo.get(GeoPolicy, id)
  end

  ## Location Tracking

  @doc """
  Track agent location from IP address.

  ## Examples

      iex> track_location(agent_id, "203.0.113.42")
      {:ok, %AgentLocation{}}
  """
  defdelegate track_location(agent_id, ip_address, opts \\ []), to: LocationTracker

  @doc """
  Get agent's current location.
  """
  defdelegate get_current_location(agent_id), to: LocationTracker

  @doc """
  Get agent's location history.

  ## Examples

      iex> get_location_history(agent_id, 7)
      [%AgentLocation{}, ...]
  """
  defdelegate get_location_history(agent_id, days \\ 7), to: LocationTracker

  @doc """
  Get unique locations visited by agent.
  """
  defdelegate get_unique_locations(agent_id, days \\ 7), to: LocationTracker

  ## Geofencing Evaluation

  @doc """
  Evaluate geofencing for an agent's current location.
  Checks rules and enforces policies.

  ## Examples

      iex> evaluate_location(agent_id)
      {:ok, %{
        location: %AgentLocation{},
        rules_evaluated: 3,
        violations: 1,
        policies_enforced: 2,
        approved_travel: nil
      }}
  """
  defdelegate evaluate_location(agent_id), to: Geofencing

  @doc """
  Get applicable rules for an agent.
  """
  defdelegate get_applicable_rules(agent), to: Geofencing

  @doc """
  Check if a rule applies to an agent.
  """
  defdelegate rule_applies_to_agent?(rule, agent), to: Geofencing

  ## Travel Management

  @doc """
  Create a travel request.

  ## Examples

      iex> create_travel_request(%{
        organization_id: org_id,
        agent_id: agent_id,
        requested_by_id: user_id,
        destination_country: "JP",
        destination_city: "Tokyo",
        reason: "Business conference",
        start_date: ~D[2026-03-01],
        end_date: ~D[2026-03-07]
      })
      {:ok, %GeoTravelRequest{}}
  """
  defdelegate create_travel_request(attrs), to: TravelManager

  @doc """
  Approve a travel request.
  """
  defdelegate approve_travel_request(request_id, approved_by_id, opts \\ []), to: TravelManager

  @doc """
  Deny a travel request.
  """
  defdelegate deny_travel_request(request_id, denied_by_id, reason), to: TravelManager

  @doc """
  List pending travel requests.
  """
  defdelegate list_pending_requests(organization_id), to: TravelManager

  @doc """
  Get active travel requests for an agent.
  """
  defdelegate get_active_travel(agent_id), to: TravelManager

  @doc """
  Check if a location is covered by active travel request.
  """
  defdelegate location_approved_for_travel?(agent_id, country_code, city \\ nil),
    to: TravelManager

  @doc """
  Expire old travel requests.
  Should be run daily via cron job.
  """
  defdelegate expire_old_requests(), to: TravelManager

  ## VPN Management

  @doc """
  Create a VPN whitelist entry.

  ## Examples

      iex> create_vpn_whitelist(%{
        organization_id: org_id,
        name: "Corporate VPN",
        vpn_provider: "Cisco AnyConnect",
        ip_ranges: ["10.0.0.0/8"],
        trust_level: "trusted"
      })
      {:ok, %VpnWhitelist{}}
  """
  def create_vpn_whitelist(attrs) do
    %VpnWhitelist{}
    |> VpnWhitelist.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a VPN whitelist entry.
  """
  def update_vpn_whitelist(%VpnWhitelist{} = whitelist, attrs) do
    whitelist
    |> VpnWhitelist.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a VPN whitelist entry.
  """
  def delete_vpn_whitelist(%VpnWhitelist{} = whitelist) do
    Repo.delete(whitelist)
  end

  @doc """
  List all VPN whitelist entries for an organization.
  """
  def list_vpn_whitelist(organization_id) do
    query =
      from v in VpnWhitelist,
        where: v.organization_id == ^organization_id,
        order_by: [asc: v.name]

    Repo.all(query)
  end

  @doc """
  Get a VPN whitelist entry by ID.
  """
  def get_vpn_whitelist(id) do
    Repo.get(VpnWhitelist, id)
  end

  ## Statistics

  @doc """
  Get geofencing statistics for an organization.

  Returns:
  - total_agents: Total number of agents
  - agents_with_location: Agents with location data
  - vpn_agents: Agents using VPN
  - unexpected_agents: Agents in unexpected locations
  - restricted_agents: Agents in restricted regions
  - unique_countries: Number of unique countries
  - pending_travel_requests: Number of pending travel requests
  """
  def get_statistics(organization_id) do
    # Get agent counts
    total_agents =
      Repo.one(
        from a in TamanduaServer.Agents.Agent,
          where: a.organization_id == ^organization_id,
          select: count(a.id)
      )

    # Get location stats (last 24 hours)
    cutoff = DateTime.utc_now() |> DateTime.add(-86400, :second)

    location_stats =
      Repo.one(
        from l in TamanduaServer.Agents.AgentLocation,
          where: l.organization_id == ^organization_id and l.detected_at >= ^cutoff,
          select: %{
            total: count(l.id),
            vpn: count(l.id, :distinct) |> filter(l.is_vpn == true),
            unexpected: count(l.id, :distinct) |> filter(l.is_expected == false),
            restricted: count(l.id, :distinct) |> filter(l.is_restricted == true),
            countries: count(l.country_code, :distinct)
          }
      )

    # Get pending travel requests
    pending_travel =
      Repo.one(
        from t in GeoTravelRequest,
          where: t.organization_id == ^organization_id and t.status == "pending",
          select: count(t.id)
      )

    %{
      total_agents: total_agents,
      agents_with_location: location_stats.total || 0,
      vpn_agents: location_stats.vpn || 0,
      unexpected_agents: location_stats.unexpected || 0,
      restricted_agents: location_stats.restricted || 0,
      unique_countries: location_stats.countries || 0,
      pending_travel_requests: pending_travel || 0
    }
  end
end
