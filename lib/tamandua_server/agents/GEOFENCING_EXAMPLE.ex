defmodule TamanduaServer.Agents.GeofencingExample do
  @moduledoc """
  Example usage of the geofencing system.

  This module demonstrates common geofencing scenarios and integrations.
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.GeofencingAPI

  @doc """
  Example 1: Basic setup for a US-based company.

  Creates:
  - US region
  - Rule to alert on non-US access
  - Policy to require MFA from unexpected locations
  """
  def example_us_company(organization_id) do
    # Create US region
    {:ok, us_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "United States",
        region_type: "country",
        definition: %{"country_code" => "US"},
        color: "#3B82F6"
      })

    # Create geofencing rule
    {:ok, rule} =
      GeofencingAPI.create_rule(%{
        organization_id: organization_id,
        name: "US Only Access",
        scope_type: "all",
        expected_region_ids: [us_region.id],
        alert_on_unexpected: true,
        alert_severity: "high"
      })

    # Create MFA policy
    {:ok, policy} =
      GeofencingAPI.create_policy(%{
        organization_id: organization_id,
        name: "MFA for Unexpected Locations",
        apply_to_unexpected: true,
        require_mfa: true,
        send_alert: true,
        alert_severity: "medium"
      })

    {:ok, %{region: us_region, rule: rule, policy: policy}}
  end

  @doc """
  Example 2: Multi-national company with offices in US, UK, and EU.

  Creates multiple regions and allows travel between them.
  """
  def example_multinational_company(organization_id) do
    # Create regions
    {:ok, us_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "United States",
        region_type: "country",
        definition: %{"country_code" => "US"}
      })

    {:ok, uk_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "United Kingdom",
        region_type: "country",
        definition: %{"country_code" => "GB"}
      })

    {:ok, de_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "Germany",
        region_type: "country",
        definition: %{"country_code" => "DE"}
      })

    # Create rule allowing US, UK, DE
    {:ok, rule} =
      GeofencingAPI.create_rule(%{
        organization_id: organization_id,
        name: "Office Locations",
        scope_type: "all",
        expected_region_ids: [us_region.id],
        allowed_region_ids: [uk_region.id, de_region.id],
        alert_on_unexpected: true,
        alert_severity: "medium"
      })

    {:ok, %{regions: [us_region, uk_region, de_region], rule: rule}}
  end

  @doc """
  Example 3: Executive protection with strict geofencing.

  Creates high-priority rules for executives with restricted countries.
  """
  def example_executive_protection(organization_id) do
    # Create allowed regions
    {:ok, us_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "United States",
        region_type: "country",
        definition: %{"country_code" => "US"}
      })

    # Create restricted regions
    {:ok, cn_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "China",
        region_type: "country",
        definition: %{"country_code" => "CN"},
        color: "#EF4444"
      })

    {:ok, ru_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "Russia",
        region_type: "country",
        definition: %{"country_code" => "RU"},
        color: "#EF4444"
      })

    # Create high-priority rule for executives
    {:ok, rule} =
      GeofencingAPI.create_rule(%{
        organization_id: organization_id,
        name: "Executive Protection",
        scope_type: "tag",
        scope_tags: ["executive"],
        expected_region_ids: [us_region.id],
        restricted_region_ids: [cn_region.id, ru_region.id],
        auto_isolate_restricted: true,
        alert_on_unexpected: true,
        alert_severity: "critical",
        priority: 100
      })

    # Create strict policy
    {:ok, policy} =
      GeofencingAPI.create_policy(%{
        organization_id: organization_id,
        name: "Restricted Region Lockdown",
        apply_to_restricted: true,
        auto_isolate: true,
        require_mfa: true,
        disable_features: ["file_download", "remote_shell", "screen_capture"],
        restrict_file_downloads: true,
        enhanced_monitoring: true,
        alert_severity: "critical",
        priority: 100
      })

    {:ok, %{rule: rule, policy: policy}}
  end

  @doc """
  Example 4: Office-only access with radius geofencing.

  Creates a 50km radius around office for on-premise contractors.
  """
  def example_office_only(organization_id, office_lat, office_lon) do
    # Create radius region around office
    {:ok, office_region} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "Office Region",
        region_type: "radius",
        definition: %{
          "center" => %{"lat" => office_lat, "lon" => office_lon},
          "radius_km" => 50
        },
        color: "#10B981"
      })

    # Create strict rule for contractors
    {:ok, rule} =
      GeofencingAPI.create_rule(%{
        organization_id: organization_id,
        name: "Office Only Access",
        scope_type: "tag",
        scope_tags: ["contractor", "on-premise"],
        expected_region_ids: [office_region.id],
        alert_on_unexpected: true,
        alert_severity: "high"
      })

    # Create policy to isolate when outside office
    {:ok, policy} =
      GeofencingAPI.create_policy(%{
        organization_id: organization_id,
        name: "Outside Office Policy",
        apply_to_unexpected: true,
        auto_isolate: true,
        send_alert: true,
        alert_severity: "high"
      })

    {:ok, %{region: office_region, rule: rule, policy: policy}}
  end

  @doc """
  Example 5: VPN whitelist for corporate network.

  Adds corporate VPN and cloud provider IPs to whitelist.
  """
  def example_vpn_whitelist(organization_id) do
    # Corporate VPN
    {:ok, corporate_vpn} =
      GeofencingAPI.create_vpn_whitelist(%{
        organization_id: organization_id,
        name: "Corporate VPN",
        vpn_provider: "Cisco AnyConnect",
        ip_ranges: [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16"
        ],
        trust_level: "trusted"
      })

    # AWS VPN
    {:ok, aws_vpn} =
      GeofencingAPI.create_vpn_whitelist(%{
        organization_id: organization_id,
        name: "AWS VPN",
        ip_ranges: [
          "52.0.0.0/8",
          "54.0.0.0/8"
        ],
        asn_numbers: [16509],
        trust_level: "monitored"
      })

    {:ok, %{corporate: corporate_vpn, aws: aws_vpn}}
  end

  @doc """
  Example 6: Travel request workflow.

  Demonstrates creating and approving travel requests.
  """
  def example_travel_workflow(organization_id, agent_id, user_id, approver_id) do
    # User submits travel request
    {:ok, request} =
      GeofencingAPI.create_travel_request(%{
        organization_id: organization_id,
        agent_id: agent_id,
        requested_by_id: user_id,
        destination_country: "JP",
        destination_city: "Tokyo",
        reason: "Attending RSA Conference",
        start_date: Date.add(Date.utc_today(), 7),
        end_date: Date.add(Date.utc_today(), 14)
      })

    # Security team reviews pending requests
    pending = GeofencingAPI.list_pending_requests(organization_id)

    # Approve the request
    {:ok, approved} = GeofencingAPI.approve_travel_request(request.id, approver_id)

    {:ok, %{request: approved, pending_count: length(pending)}}
  end

  @doc """
  Example 7: Real-time location tracking integration.

  Shows how to track location when agent connects.
  """
  def example_track_agent_connection(agent_id, ip_address) do
    # Track location
    {:ok, location} = GeofencingAPI.track_location(agent_id, ip_address)

    # Evaluate geofencing
    {:ok, result} = GeofencingAPI.evaluate_location(agent_id)

    case result do
      %{violations: 0} ->
        {:ok, :allowed}

      %{violations: count} when count > 0 ->
        # Violations detected - alerts already sent, policies enforced
        {:error, :geofencing_violation, result}
    end
  end

  @doc """
  Example 8: Dashboard statistics.

  Gets geofencing statistics for monitoring dashboard.
  """
  def example_dashboard_stats(organization_id) do
    stats = GeofencingAPI.get_statistics(organization_id)

    # Returns:
    # %{
    #   total_agents: 150,
    #   agents_with_location: 145,
    #   vpn_agents: 12,
    #   unexpected_agents: 3,
    #   restricted_agents: 0,
    #   unique_countries: 8,
    #   pending_travel_requests: 2
    # }

    {:ok, stats}
  end

  @doc """
  Example 9: Custom polygon region (campus boundary).

  Creates a precise polygon region for corporate campus.
  """
  def example_campus_polygon(organization_id) do
    {:ok, campus} =
      GeofencingAPI.create_region(%{
        organization_id: organization_id,
        name: "Corporate Campus",
        region_type: "polygon",
        definition: %{
          "coordinates" => [
            [37.4220, -122.0841],
            [37.4225, -122.0836],
            [37.4215, -122.0830],
            [37.4210, -122.0835],
            [37.4220, -122.0841]
          ]
        },
        color: "#8B5CF6"
      })

    {:ok, campus}
  end

  @doc """
  Example 10: Integration with alert system.

  Shows how geofencing alerts integrate with existing alert system.
  """
  def example_alert_integration(organization_id) do
    # Subscribe to geofencing alerts
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "geofencing:alerts:#{organization_id}")

    # When geofencing violation occurs, alerts are automatically created
    # and published to PubSub for real-time notifications
    :ok
  end
end
