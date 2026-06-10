defmodule TamanduaServer.InsiderThreat.Indicator do
  @moduledoc """
  Insider threat indicators and their risk weights.
  """

  @type indicator_type ::
          :off_hours_activity
          | :data_exfiltration
          | :privilege_escalation
          | :unusual_access
          | :lateral_movement
          | :credential_misuse
          | :policy_violation
          | :peer_group_outlier
          | :sensitive_data_access
          | :bulk_download
          | :usb_write
          | :cloud_upload
          | :failed_auth_spike
          | :unusual_location
          | :file_share_access
          | :application_anomaly

  @type t :: %__MODULE__{
          type: indicator_type(),
          severity: :critical | :high | :medium | :low,
          weight: float(),
          description: String.t(),
          evidence: map(),
          timestamp: DateTime.t()
        }

  defstruct [
    :type,
    :severity,
    :weight,
    :description,
    :evidence,
    :timestamp
  ]

  @doc """
  Get risk weight for an indicator type.
  """
  @spec get_weight(indicator_type()) :: float()
  def get_weight(:data_exfiltration), do: 40.0
  def get_weight(:privilege_escalation), do: 30.0
  def get_weight(:off_hours_activity), do: 20.0
  def get_weight(:peer_group_outlier), do: 10.0
  def get_weight(:sensitive_data_access), do: 25.0
  def get_weight(:bulk_download), do: 35.0
  def get_weight(:usb_write), do: 30.0
  def get_weight(:cloud_upload), do: 25.0
  def get_weight(:lateral_movement), do: 25.0
  def get_weight(:credential_misuse), do: 35.0
  def get_weight(:policy_violation), do: 15.0
  def get_weight(:failed_auth_spike), do: 20.0
  def get_weight(:unusual_location), do: 15.0
  def get_weight(:unusual_access), do: 20.0
  def get_weight(:file_share_access), do: 15.0
  def get_weight(:application_anomaly), do: 10.0

  @doc """
  Get severity for an indicator type.
  """
  @spec get_severity(indicator_type()) :: :critical | :high | :medium | :low
  def get_severity(:data_exfiltration), do: :critical
  def get_severity(:privilege_escalation), do: :high
  def get_severity(:bulk_download), do: :critical
  def get_severity(:credential_misuse), do: :critical
  def get_severity(:usb_write), do: :high
  def get_severity(:cloud_upload), do: :high
  def get_severity(:lateral_movement), do: :high
  def get_severity(:sensitive_data_access), do: :high
  def get_severity(:off_hours_activity), do: :medium
  def get_severity(:failed_auth_spike), do: :medium
  def get_severity(:unusual_access), do: :medium
  def get_severity(:unusual_location), do: :medium
  def get_severity(:policy_violation), do: :medium
  def get_severity(:file_share_access), do: :low
  def get_severity(:peer_group_outlier), do: :low
  def get_severity(:application_anomaly), do: :low

  @doc """
  Create a new indicator.
  """
  @spec new(indicator_type(), map()) :: t()
  def new(type, evidence) do
    %__MODULE__{
      type: type,
      severity: get_severity(type),
      weight: get_weight(type),
      description: describe(type, evidence),
      evidence: evidence,
      timestamp: DateTime.utc_now()
    }
  end

  @doc """
  Describe an indicator with context.
  """
  @spec describe(indicator_type(), map()) :: String.t()
  def describe(:off_hours_activity, %{hour: hour, user: user}) do
    "User #{user} accessed systems at #{hour}:00 (off-hours)"
  end

  def describe(:data_exfiltration, %{bytes: bytes, destination: dest}) do
    "Large data transfer detected: #{format_bytes(bytes)} to #{dest}"
  end

  def describe(:privilege_escalation, %{method: method, count: count}) do
    "#{count} privilege escalation attempts via #{method}"
  end

  def describe(:bulk_download, %{bytes: bytes, files: files}) do
    "Bulk download: #{files} files (#{format_bytes(bytes)}) in short time"
  end

  def describe(:usb_write, %{bytes: bytes, device: device}) do
    "USB write: #{format_bytes(bytes)} to #{device}"
  end

  def describe(:cloud_upload, %{bytes: bytes, service: service}) do
    "Cloud upload: #{format_bytes(bytes)} to #{service}"
  end

  def describe(:sensitive_data_access, %{resource: resource, classification: class}) do
    "Access to #{class} data: #{resource}"
  end

  def describe(:lateral_movement, %{source: src, target: tgt}) do
    "Lateral movement from #{src} to #{tgt}"
  end

  def describe(:credential_misuse, %{credential_type: type}) do
    "Suspicious credential usage: #{type}"
  end

  def describe(:policy_violation, %{policy: policy}) do
    "Policy violation: #{policy}"
  end

  def describe(:failed_auth_spike, %{count: count, window: window}) do
    "#{count} failed authentication attempts in #{window} minutes"
  end

  def describe(:unusual_location, %{location: loc, expected: exp}) do
    "Authentication from unusual location: #{loc} (expected: #{exp})"
  end

  def describe(:unusual_access, %{resource: resource}) do
    "Access to unusual resource: #{resource}"
  end

  def describe(:file_share_access, %{share: share}) do
    "Access to unusual file share: #{share}"
  end

  def describe(:application_anomaly, %{application: app}) do
    "Unusual application usage: #{app}"
  end

  def describe(:peer_group_outlier, %{metric: metric, deviation: dev}) do
    "Peer group outlier: #{metric} (#{dev}σ deviation)"
  end

  def describe(type, _evidence), do: "Indicator: #{type}"

  @doc """
  Format bytes for human readability.
  """
  @spec format_bytes(integer()) :: String.t()
  def format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  def format_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 2)} KB"
  def format_bytes(bytes) when bytes < 1_073_741_824, do: "#{Float.round(bytes / 1_048_576, 2)} MB"
  def format_bytes(bytes), do: "#{Float.round(bytes / 1_073_741_824, 2)} GB"

  @doc """
  Check if indicator is high severity.
  """
  @spec high_severity?(t()) :: boolean()
  def high_severity?(%__MODULE__{severity: severity}) do
    severity in [:critical, :high]
  end

  @doc """
  All indicator types.
  """
  @spec all_types() :: [indicator_type()]
  def all_types do
    [
      :off_hours_activity,
      :data_exfiltration,
      :privilege_escalation,
      :unusual_access,
      :lateral_movement,
      :credential_misuse,
      :policy_violation,
      :peer_group_outlier,
      :sensitive_data_access,
      :bulk_download,
      :usb_write,
      :cloud_upload,
      :failed_auth_spike,
      :unusual_location,
      :file_share_access,
      :application_anomaly
    ]
  end
end
