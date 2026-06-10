defmodule TamanduaServer.InsiderThreat.Detector do
  @moduledoc """
  Main insider threat detection engine.
  Analyzes user activity and generates insider threat alerts.
  """

  alias TamanduaServer.InsiderThreat.{Indicator, RiskScorer, PeerGroup, Alert}
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Repo

  import Ecto.Query
  require Logger

  @doc """
  Analyze an event for insider threat indicators.
  """
  @spec analyze_event(Event.t()) :: {:ok, [Indicator.t()]} | {:error, any()}
  def analyze_event(%Event{} = event) do
    indicators =
      []
      |> detect_off_hours_activity(event)
      |> detect_data_exfiltration(event)
      |> detect_privilege_escalation(event)
      |> detect_sensitive_data_access(event)
      |> detect_lateral_movement(event)
      |> detect_credential_misuse(event)
      |> detect_policy_violation(event)
      |> detect_bulk_download(event)
      |> detect_usb_write(event)
      |> detect_cloud_upload(event)

    {:ok, indicators}
  end

  @doc """
  Analyze user activity over a time period.
  """
  @spec analyze_user(Ecto.UUID.t(), DateTime.t(), DateTime.t()) ::
          {:ok, map()} | {:error, any()}
  def analyze_user(user_id, start_time, end_time) do
    # Get events for user in time period
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        order_by: [asc: e.inserted_at]
      )

    events = Repo.all(query)

    # Collect all indicators
    indicators =
      events
      |> Enum.flat_map(fn event ->
        case analyze_event(event) do
          {:ok, inds} -> inds
          _ -> []
        end
      end)

    # Add behavioral indicators
    behavioral_indicators =
      []
      |> detect_failed_auth_spike(user_id, start_time, end_time)
      |> detect_unusual_location(user_id, start_time, end_time)
      |> detect_unusual_access(user_id, start_time, end_time)
      |> detect_peer_group_outliers(user_id, start_time, end_time)

    all_indicators = indicators ++ behavioral_indicators

    # Calculate user metrics
    user_metrics = calculate_user_metrics(user_id, start_time, end_time)

    # Get peer group
    peer_group_id = get_user_peer_group(user_id)

    # Calculate risk score
    risk_score =
      RiskScorer.calculate_score(user_id, all_indicators, %{
        peer_group_id: peer_group_id,
        user_metrics: user_metrics,
        lookback_days: 7
      })

    # Create alert if threshold exceeded
    if risk_score.threshold_exceeded do
      create_alert(user_id, risk_score, user_metrics)
    end

    {:ok, %{indicators: all_indicators, risk_score: risk_score, user_metrics: user_metrics}}
  end

  @doc """
  Batch analyze all users in organization.
  """
  @spec analyze_organization(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: {:ok, map()}
  def analyze_organization(organization_id, start_time, end_time) do
    query =
      from(u in "users",
        where: u.organization_id == ^organization_id and u.is_active == true,
        select: u.id
      )

    user_ids = Repo.all(query)

    results =
      user_ids
      |> Task.async_stream(
        fn user_id ->
          case analyze_user(user_id, start_time, end_time) do
            {:ok, result} -> {user_id, result}
            _ -> {user_id, nil}
          end
        end,
        max_concurrency: 10,
        timeout: 30_000
      )
      |> Enum.map(fn {:ok, result} -> result end)
      |> Enum.reject(fn {_user_id, result} -> is_nil(result) end)
      |> Map.new()

    {:ok, results}
  end

  # Detection rules

  defp detect_off_hours_activity(indicators, %Event{} = event) do
    hour = event.inserted_at.hour

    # Off hours: 10pm - 6am (22:00 - 06:00)
    if hour >= 22 or hour < 6 do
      indicator =
        Indicator.new(:off_hours_activity, %{
          hour: hour,
          user: event.user_id,
          event_type: event.event_type
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_data_exfiltration(indicators, %Event{event_type: event_type, payload: payload})
       when event_type in ["network_connection", "file_transfer"] do
    bytes = get_in(payload, ["bytes_sent"]) || get_in(payload, ["file_size"]) || 0

    # Flag if >1GB transfer
    if bytes > 1_073_741_824 do
      destination = get_in(payload, ["remote_ip"]) || get_in(payload, ["destination"]) || "unknown"

      indicator =
        Indicator.new(:data_exfiltration, %{
          bytes: bytes,
          destination: destination
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_data_exfiltration(indicators, _event), do: indicators

  defp detect_privilege_escalation(indicators, %Event{
         event_type: event_type,
         payload: payload
       })
       when event_type in ["process_start", "privilege_escalation"] do
    process_name = get_in(payload, ["process_name"]) || ""
    elevated = get_in(payload, ["is_elevated"]) || false

    # Check for privilege escalation patterns
    if elevated and
         (String.contains?(process_name, "sudo") or
            String.contains?(process_name, "runas") or
            event_type == "privilege_escalation") do
      indicator =
        Indicator.new(:privilege_escalation, %{
          method: process_name,
          count: 1
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_privilege_escalation(indicators, _event), do: indicators

  defp detect_sensitive_data_access(indicators, %Event{
         event_type: "file_access",
         payload: payload
       }) do
    file_path = get_in(payload, ["file_path"]) || ""

    # Check for sensitive data patterns
    sensitive_patterns = [
      "confidential",
      "secret",
      "private",
      "password",
      "credential",
      "financial",
      "payroll",
      "ssn"
    ]

    if Enum.any?(sensitive_patterns, &String.contains?(String.downcase(file_path), &1)) do
      indicator =
        Indicator.new(:sensitive_data_access, %{
          resource: file_path,
          classification: "sensitive"
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_sensitive_data_access(indicators, _event), do: indicators

  defp detect_lateral_movement(indicators, %Event{
         event_type: "network_connection",
         payload: payload
       }) do
    remote_ip = get_in(payload, ["remote_ip"])
    protocol = get_in(payload, ["protocol"]) || ""

    # Check for lateral movement patterns (RDP, SMB, SSH to internal IPs)
    internal_protocols = ["rdp", "smb", "ssh", "winrm"]

    if remote_ip && String.starts_with?(remote_ip, ["10.", "172.", "192.168."]) &&
         Enum.any?(internal_protocols, &String.contains?(String.downcase(protocol), &1)) do
      indicator =
        Indicator.new(:lateral_movement, %{
          source: "local",
          target: remote_ip
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_lateral_movement(indicators, _event), do: indicators

  defp detect_credential_misuse(indicators, %Event{
         event_type: "authentication_success",
         payload: payload
       }) do
    # Check for shared credentials or unusual authentication patterns
    auth_method = get_in(payload, ["auth_method"]) || ""
    source_ip = get_in(payload, ["source_ip"]) || ""

    # Flag if authentication from VPN or proxy (potential credential sharing)
    suspicious_patterns = ["vpn", "proxy", "tor"]

    if Enum.any?(suspicious_patterns, &String.contains?(String.downcase(source_ip), &1)) do
      indicator =
        Indicator.new(:credential_misuse, %{
          credential_type: auth_method
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_credential_misuse(indicators, _event), do: indicators

  defp detect_policy_violation(indicators, %Event{event_type: "dlp_violation", payload: payload}) do
    policy = get_in(payload, ["policy_name"]) || "unknown"

    indicator =
      Indicator.new(:policy_violation, %{
        policy: policy
      })

    [indicator | indicators]
  end

  defp detect_policy_violation(indicators, _event), do: indicators

  defp detect_bulk_download(indicators, %Event{payload: payload} = event) do
    user_id = payload["user_id"] || payload[:user_id]

    if is_nil(user_id) do
      indicators
    else
      # Look for multiple downloads in short time
      one_hour_ago = DateTime.add(event.created_at, -3600, :second)

      query =
        from(e in Event,
          where:
            fragment("payload->>'user_id' = ?", ^user_id) and
              e.event_type == "file_access" and
              e.created_at >= ^one_hour_ago and
              e.created_at <= ^event.created_at,
          select: fragment("COALESCE((payload->>'file_size')::bigint, 0)")
        )

      total_bytes = Repo.all(query) |> Enum.sum()
      file_count = Repo.aggregate(query, :count)

      # Flag if >1GB in 1 hour
      if total_bytes > 1_073_741_824 do
        indicator =
          Indicator.new(:bulk_download, %{
            bytes: total_bytes,
            files: file_count
          })

        [indicator | indicators]
      else
        indicators
      end
    end
  end

  defp detect_usb_write(indicators, %Event{event_type: "file_write", payload: payload}) do
    file_path = get_in(payload, ["file_path"]) || ""
    file_size = get_in(payload, ["file_size"]) || 0

    # Check if writing to USB device
    usb_patterns = ["/media/", "/mnt/usb", "D:\\", "E:\\", "F:\\"]

    if Enum.any?(usb_patterns, &String.starts_with?(file_path, &1)) && file_size > 1_048_576 do
      indicator =
        Indicator.new(:usb_write, %{
          bytes: file_size,
          device: file_path
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_usb_write(indicators, _event), do: indicators

  defp detect_cloud_upload(indicators, %Event{
         event_type: "network_connection",
         payload: payload
       }) do
    remote_host = get_in(payload, ["remote_host"]) || ""
    bytes = get_in(payload, ["bytes_sent"]) || 0

    # Check for cloud storage services
    cloud_services = [
      "dropbox.com",
      "drive.google.com",
      "onedrive.com",
      "box.com",
      "s3.amazonaws.com"
    ]

    if Enum.any?(cloud_services, &String.contains?(String.downcase(remote_host), &1)) &&
         bytes > 10_485_760 do
      indicator =
        Indicator.new(:cloud_upload, %{
          bytes: bytes,
          service: remote_host
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_cloud_upload(indicators, _event), do: indicators

  # Behavioral detection (requires aggregation)

  defp detect_failed_auth_spike(indicators, user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "authentication_failure" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time
      )

    failure_count = Repo.aggregate(query, :count)

    # Flag if >10 failures in time window
    if failure_count > 10 do
      window_minutes = DateTime.diff(end_time, start_time, :minute)

      indicator =
        Indicator.new(:failed_auth_spike, %{
          count: failure_count,
          window: window_minutes
        })

      [indicator | indicators]
    else
      indicators
    end
  end

  defp detect_unusual_location(indicators, user_id, start_time, end_time) do
    # Get user's typical locations
    typical_locations = get_typical_locations(user_id)

    # Get current locations
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "authentication_success" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        select: fragment("DISTINCT payload->>'location'")
      )

    current_locations = Repo.all(query) |> Enum.reject(&is_nil/1)

    unusual_locations = current_locations -- typical_locations

    Enum.reduce(unusual_locations, indicators, fn location, acc ->
      indicator =
        Indicator.new(:unusual_location, %{
          location: location,
          expected: Enum.join(typical_locations, ", ")
        })

      [indicator | acc]
    end)
  end

  defp detect_unusual_access(indicators, user_id, start_time, end_time) do
    # Get typical file shares for user
    typical_shares = get_typical_file_shares(user_id)

    # Get current file shares accessed
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "file_access" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        select: fragment("DISTINCT payload->>'share_path'")
      )

    current_shares = Repo.all(query) |> Enum.reject(&is_nil/1)

    unusual_shares = current_shares -- typical_shares

    Enum.reduce(unusual_shares, indicators, fn share, acc ->
      indicator =
        Indicator.new(:unusual_access, %{
          resource: share
        })

      [indicator | acc]
    end)
  end

  defp detect_peer_group_outliers(indicators, user_id, start_time, end_time) do
    peer_group_id = get_user_peer_group(user_id)

    case peer_group_id do
      nil ->
        indicators

      peer_group_id ->
        peer_group = PeerGroup.get(peer_group_id)
        user_metrics = calculate_user_metrics(user_id, start_time, end_time)

        user_metrics
        |> Enum.filter(fn {metric, value} ->
          PeerGroup.is_outlier?(peer_group, user_id, metric, value)
        end)
        |> Enum.reduce(indicators, fn {metric, value}, acc ->
          deviation = PeerGroup.calculate_deviation(peer_group, metric, value)

          indicator =
            Indicator.new(:peer_group_outlier, %{
              metric: metric,
              deviation: Float.round(deviation, 2)
            })

          [indicator | acc]
        end)
    end
  end

  # Helper functions

  defp create_alert(user_id, risk_score, user_metrics) do
    Alert.create(%{
      user_id: user_id,
      risk_score: risk_score.total,
      severity: risk_score.severity,
      indicators: Enum.map(risk_score.indicators, &Map.from_struct/1),
      risk_breakdown: risk_score.components,
      user_metrics: user_metrics,
      trend: risk_score.trend,
      status: "open",
      requires_investigation: true
    })
  end

  defp calculate_user_metrics(user_id, start_time, end_time) do
    %{
      data_access: calculate_data_access(user_id, start_time, end_time),
      network_activity: calculate_network_activity(user_id, start_time, end_time),
      authentication_count: calculate_auth_count(user_id, start_time, end_time),
      file_access_count: calculate_file_access_count(user_id, start_time, end_time)
    }
  end

  defp calculate_data_access(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type in ["file_access", "data_read"] and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        select: fragment("COALESCE((payload->>'bytes_read')::bigint, 0)")
      )

    Repo.all(query) |> Enum.sum() |> then(&(&1 / 1))
  end

  defp calculate_network_activity(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "network_connection" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        select: fragment("COALESCE((payload->>'bytes_sent')::bigint, 0)")
      )

    Repo.all(query) |> Enum.sum() |> then(&(&1 / 1))
  end

  defp calculate_auth_count(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "authentication_success" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time
      )

    Repo.aggregate(query, :count) |> then(&(&1 / 1))
  end

  defp calculate_file_access_count(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "file_access" and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time
      )

    Repo.aggregate(query, :count) |> then(&(&1 / 1))
  end

  defp get_typical_locations(user_id) do
    # Query historical authentication events
    thirty_days_ago = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600, :second)

    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "authentication_success" and
            e.inserted_at >= ^thirty_days_ago,
        select: fragment("payload->>'location'")
      )

    Repo.all(query)
    |> Enum.reject(&is_nil/1)
    |> Enum.frequencies()
    |> Enum.filter(fn {_loc, count} -> count > 5 end)
    |> Enum.map(fn {loc, _count} -> loc end)
  end

  defp get_typical_file_shares(user_id) do
    # Query historical file access events
    thirty_days_ago = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600, :second)

    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type == "file_access" and
            e.inserted_at >= ^thirty_days_ago,
        select: fragment("payload->>'share_path'")
      )

    Repo.all(query)
    |> Enum.reject(&is_nil/1)
    |> Enum.frequencies()
    |> Enum.filter(fn {_share, count} -> count > 3 end)
    |> Enum.map(fn {share, _count} -> share end)
  end

  defp get_user_peer_group(user_id) do
    query =
      from(m in "insider_threat_peer_group_members",
        where: m.user_id == ^user_id,
        select: m.peer_group_id,
        limit: 1
      )

    Repo.one(query)
  end
end
