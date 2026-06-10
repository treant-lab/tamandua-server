defmodule TamanduaServer.Agents.GeofencingTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Agents.{
    Agent,
    GeoRegion,
    GeofencingRule,
    GeoPolicy,
    AgentLocation,
    VpnWhitelist,
    GeoTravelRequest,
    Geofencing,
    LocationTracker,
    TravelManager
  }

  describe "geo_regions" do
    setup do
      org = insert(:organization)
      %{org: org}
    end

    test "creates country region", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "United States",
        region_type: "country",
        definition: %{"country_code" => "US"}
      }

      changeset = GeoRegion.changeset(%GeoRegion{}, attrs)
      assert changeset.valid?

      {:ok, region} = Repo.insert(changeset)
      assert region.name == "United States"
      assert region.region_type == "country"
    end

    test "creates city region", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "New York",
        region_type: "city",
        definition: %{"country" => "US", "city" => "New York", "state" => "NY"}
      }

      changeset = GeoRegion.changeset(%GeoRegion{}, attrs)
      assert changeset.valid?

      {:ok, region} = Repo.insert(changeset)
      assert region.region_type == "city"
    end

    test "creates polygon region", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Office Campus",
        region_type: "polygon",
        definition: %{
          "coordinates" => [
            [40.7128, -74.006],
            [40.7138, -74.005],
            [40.7118, -74.004]
          ]
        }
      }

      changeset = GeoRegion.changeset(%GeoRegion{}, attrs)
      assert changeset.valid?
    end

    test "creates radius region", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "50km around office",
        region_type: "radius",
        definition: %{
          "center" => %{"lat" => 40.7128, "lon" => -74.006},
          "radius_km" => 50
        }
      }

      changeset = GeoRegion.changeset(%GeoRegion{}, attrs)
      assert changeset.valid?
    end

    test "validates country definition", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Invalid",
        region_type: "country",
        definition: %{}
      }

      changeset = GeoRegion.changeset(%GeoRegion{}, attrs)
      refute changeset.valid?
      assert "must include country_code for country type" in errors_on(changeset).definition
    end
  end

  describe "geofencing_rules" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      region = insert(:geo_region, organization: org)
      %{org: org, agent: agent, region: region}
    end

    test "creates rule for all agents", %{org: org, region: region} do
      attrs = %{
        organization_id: org.id,
        name: "US Only",
        scope_type: "all",
        expected_region_ids: [region.id],
        alert_on_unexpected: true
      }

      changeset = GeofencingRule.changeset(%GeofencingRule{}, attrs)
      assert changeset.valid?

      {:ok, rule} = Repo.insert(changeset)
      assert rule.scope_type == "all"
    end

    test "creates rule for specific agent", %{org: org, agent: agent, region: region} do
      attrs = %{
        organization_id: org.id,
        name: "Executive Protection",
        scope_type: "agent",
        scope_ids: [agent.id],
        expected_region_ids: [region.id],
        alert_severity: "critical"
      }

      changeset = GeofencingRule.changeset(%GeofencingRule{}, attrs)
      assert changeset.valid?
    end

    test "validates scope_ids for agent scope", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Invalid",
        scope_type: "agent",
        scope_ids: []
      }

      changeset = GeofencingRule.changeset(%GeofencingRule{}, attrs)
      refute changeset.valid?
    end

    test "validates scope_tags for tag scope", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Invalid",
        scope_type: "tag",
        scope_tags: []
      }

      changeset = GeofencingRule.changeset(%GeofencingRule{}, attrs)
      refute changeset.valid?
    end
  end

  describe "location_tracking" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      %{org: org, agent: agent}
    end

    test "tracks agent location", %{agent: agent} do
      {:ok, location} = LocationTracker.track_location(agent.id, "203.0.113.1")

      assert location.agent_id == agent.id
      assert location.ip_address == "203.0.113.1"
      assert location.detected_at
    end

    test "detects private IP", %{agent: agent} do
      {:ok, location} = LocationTracker.track_location(agent.id, "192.168.1.100")

      assert location.country_code == "PRIVATE"
    end

    test "gets location history", %{agent: agent} do
      LocationTracker.track_location(agent.id, "203.0.113.1")
      LocationTracker.track_location(agent.id, "203.0.113.2")

      history = LocationTracker.get_location_history(agent.id, 7)
      assert length(history) == 2
    end

    test "gets unique locations", %{agent: agent} do
      LocationTracker.track_location(agent.id, "203.0.113.1")
      LocationTracker.track_location(agent.id, "203.0.113.1")
      LocationTracker.track_location(agent.id, "203.0.113.2")

      unique = LocationTracker.get_unique_locations(agent.id, 7)
      assert length(unique) >= 1
    end
  end

  describe "vpn_detection" do
    setup do
      org = insert(:organization)
      %{org: org}
    end

    test "creates VPN whitelist entry", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Corporate VPN",
        vpn_provider: "Cisco AnyConnect",
        ip_ranges: ["10.0.0.0/8", "172.16.0.0/12"],
        trust_level: "trusted"
      }

      changeset = VpnWhitelist.changeset(%VpnWhitelist{}, attrs)
      assert changeset.valid?

      {:ok, whitelist} = Repo.insert(changeset)
      assert whitelist.trust_level == "trusted"
      assert length(whitelist.ip_ranges) == 2
    end

    test "validates CIDR notation", %{org: org} do
      attrs = %{
        organization_id: org.id,
        name: "Invalid",
        ip_ranges: ["not-a-cidr"],
        trust_level: "trusted"
      }

      changeset = VpnWhitelist.changeset(%VpnWhitelist{}, attrs)
      refute changeset.valid?
    end
  end

  describe "travel_requests" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      user = insert(:user, organization: org)
      %{org: org, agent: agent, user: user}
    end

    test "creates travel request", %{org: org, agent: agent, user: user} do
      attrs = %{
        organization_id: org.id,
        agent_id: agent.id,
        requested_by_id: user.id,
        destination_country: "JP",
        destination_city: "Tokyo",
        reason: "Business conference",
        start_date: Date.utc_today(),
        end_date: Date.add(Date.utc_today(), 7)
      }

      {:ok, request} = TravelManager.create_travel_request(attrs)
      assert request.status == "pending"
      assert request.destination_country == "JP"
    end

    test "approves travel request", %{org: org, agent: agent, user: user} do
      {:ok, request} =
        TravelManager.create_travel_request(%{
          organization_id: org.id,
          agent_id: agent.id,
          destination_country: "JP",
          start_date: Date.utc_today(),
          end_date: Date.add(Date.utc_today(), 7)
        })

      {:ok, approved} = TravelManager.approve_travel_request(request.id, user.id)
      assert approved.status == "approved"
      assert approved.approved_by_id == user.id
    end

    test "denies travel request", %{org: org, agent: agent, user: user} do
      {:ok, request} =
        TravelManager.create_travel_request(%{
          organization_id: org.id,
          agent_id: agent.id,
          destination_country: "KP",
          start_date: Date.utc_today(),
          end_date: Date.add(Date.utc_today(), 7)
        })

      {:ok, denied} = TravelManager.deny_travel_request(request.id, user.id, "Restricted country")
      assert denied.status == "denied"
      assert denied.denial_reason == "Restricted country"
    end

    test "gets active travel", %{org: org, agent: agent, user: user} do
      {:ok, request} =
        TravelManager.create_travel_request(%{
          organization_id: org.id,
          agent_id: agent.id,
          destination_country: "JP",
          start_date: Date.utc_today(),
          end_date: Date.add(Date.utc_today(), 7)
        })

      TravelManager.approve_travel_request(request.id, user.id)

      active = TravelManager.get_active_travel(agent.id)
      assert length(active) == 1
    end
  end

  describe "rule_evaluation" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org, tags: ["executive"])

      us_region =
        insert(:geo_region,
          organization: org,
          region_type: "country",
          definition: %{"country_code" => "US"}
        )

      rule =
        insert(:geofencing_rule,
          organization: org,
          scope_type: "tag",
          scope_tags: ["executive"],
          expected_region_ids: [us_region.id]
        )

      %{org: org, agent: agent, region: us_region, rule: rule}
    end

    test "rule applies to tagged agent", %{agent: agent, rule: rule} do
      assert Geofencing.rule_applies_to_agent?(rule, agent)
    end

    test "evaluates expected location", %{agent: agent, rule: rule, region: region} do
      location = %AgentLocation{
        matched_region_ids: [region.id],
        is_expected: true,
        country_name: "United States"
      }

      {_rule, result} = Geofencing.evaluate_rule(rule, location, agent)
      refute result.violation
    end

    test "evaluates unexpected location", %{agent: agent, rule: rule} do
      location = %AgentLocation{
        matched_region_ids: [],
        is_expected: false,
        country_name: "Russia",
        city: "Moscow"
      }

      {_rule, result} = Geofencing.evaluate_rule(rule, location, agent)
      assert result.violation
      assert result.type == :unexpected_location
    end

    test "evaluates restricted location", %{agent: agent, rule: rule} do
      location = %AgentLocation{
        matched_region_ids: [],
        is_restricted: true,
        country_name: "North Korea"
      }

      {_rule, result} = Geofencing.evaluate_rule(rule, location, agent)
      assert result.violation
      assert result.type == :restricted_region
    end
  end

  describe "policy_enforcement" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      region =
        insert(:geo_region,
          organization: org,
          region_type: "country",
          definition: %{"country_code" => "CN"}
        )

      policy =
        insert(:geo_policy,
          organization: org,
          region_ids: [region.id],
          require_mfa: true,
          restrict_file_downloads: true
        )

      location =
        insert(:agent_location,
          organization: org,
          agent: agent,
          matched_region_ids: [region.id],
          country_code: "CN"
        )

      %{org: org, agent: agent, region: region, policy: policy, location: location}
    end

    test "policy applies to location in region", %{policy: policy, location: location} do
      assert Geofencing.policy_applies_to_location?(policy, location)
    end

    test "enforces MFA requirement", %{policy: policy, agent: agent, location: location} do
      Geofencing.enforce_policy(policy, agent, location)

      updated_agent = Repo.get!(Agent, agent.id)
      assert updated_agent.geo_restrictions["require_mfa"] == true
    end
  end

  ## Helpers

  defp insert(schema, attrs \\ %{})

  defp insert(:organization, attrs) do
    %TamanduaServer.Accounts.Organization{}
    |> TamanduaServer.Accounts.Organization.changeset(
      Map.merge(
        %{
          name: "Test Org",
          slug: "test-org-#{System.unique_integer([:positive])}"
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:agent, attrs) do
    %Agent{}
    |> Agent.changeset(
      Map.merge(
        %{
          hostname: "test-agent",
          os_type: "linux",
          machine_id: :crypto.strong_rand_bytes(32),
          organization_id: attrs[:organization].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:geo_region, attrs) do
    %GeoRegion{}
    |> GeoRegion.changeset(
      Map.merge(
        %{
          name: "Test Region",
          region_type: "country",
          definition: %{"country_code" => "US"},
          organization_id: attrs[:organization].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:geofencing_rule, attrs) do
    %GeofencingRule{}
    |> GeofencingRule.changeset(
      Map.merge(
        %{
          name: "Test Rule",
          scope_type: "all",
          organization_id: attrs[:organization].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:geo_policy, attrs) do
    %GeoPolicy{}
    |> GeoPolicy.changeset(
      Map.merge(
        %{
          name: "Test Policy",
          organization_id: attrs[:organization].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:agent_location, attrs) do
    %AgentLocation{}
    |> AgentLocation.changeset(
      Map.merge(
        %{
          ip_address: "203.0.113.1",
          country_code: "US",
          country_name: "United States",
          detected_at: DateTime.utc_now(),
          organization_id: attrs[:organization].id,
          agent_id: attrs[:agent].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  defp insert(:user, attrs) do
    %TamanduaServer.Accounts.User{}
    |> TamanduaServer.Accounts.User.changeset(
      Map.merge(
        %{
          email: "user@example.com",
          name: "Test User",
          organization_id: attrs[:organization].id
        },
        attrs
      )
    )
    |> Repo.insert!()
  end
end
