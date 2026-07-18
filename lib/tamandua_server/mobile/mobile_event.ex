defmodule TamanduaServer.Mobile.MobileEvent do
  @moduledoc """
  Schema for mobile security events.

  Mobile events include security posture changes, threat detections,
  network events, and compliance violations from iOS/Android devices.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Mobile.Device
  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @severities ~w(info low medium high critical)

  @event_types %{
    # Device events
    "device_boot" => "Device booted",
    "screen_lock_changed" => "Screen lock state changed",
    "passcode_changed" => "Passcode changed",
    "biometric_changed" => "Biometric enrollment changed",
    "encryption_changed" => "Encryption state changed",
    "usb_connection" => "USB connection detected",
    "developer_mode_changed" => "Developer mode state changed",

    # Security events
    "jailbreak_detected" => "Jailbreak detected",
    "root_detected" => "Root detected",
    "debugger_detected" => "Debugger attached",
    "hook_framework_detected" => "Hook framework detected",
    "emulator_detected" => "Emulator detected",
    "simulator_detected" => "Simulator detected",
    "app_integrity_violation" => "App integrity violation",
    "tampering_detected" => "Tampering detected",
    "browser_tamper_detected" => "Browser tamper detected",
    "automation_detected" => "Automation detected",
    "network_exfiltration_suspected" => "Network exfiltration suspected",
    "commercial_spyware_suspected" => "Commercial spyware suspected",
    "frida_detected" => "Frida instrumentation detected",
    "native_hook_detected" => "Native hook suspected",
    "runtime_memory_tamper_detected" => "Runtime memory tamper detected",
    "code_signature_drift_detected" => "Code signature drift detected",
    "suspicious_proxy_detected" => "Suspicious proxy detected",
    "shielding_interference_suspected" => "Shielding interference suspected",
    "webview_bridge_risk_detected" => "WebView bridge risk detected",
    "webview_ssl_error_bypass" => "WebView SSL error bypass detected",
    "spyware_indicator_match" => "Spyware indicator match",
    "integrity_snapshot_changed" => "Integrity snapshot changed",
    "behavior_anomaly_detected" => "Behavior anomaly detected",
    "suspicious_app_installed" => "Suspicious app installed",
    "malware_detected" => "Malware detected",
    "spyware_detected" => "Spyware detected",

    # Network events
    "malicious_dns_query" => "Malicious DNS query",
    "suspicious_connection" => "Suspicious network connection",
    "proxy_detected" => "Proxy detected",
    "vpn_changed" => "VPN configuration changed",
    "certificate_pinning_bypass" => "Certificate pinning bypass attempted",
    "man_in_the_middle" => "MitM attack detected",

    # App events
    "app_installed" => "App installed",
    "app_uninstalled" => "App uninstalled",
    "sideload_attempt" => "Sideload attempt",
    "dangerous_permission_granted" => "Dangerous permission granted",
    "overlay_detected" => "Screen overlay detected",
    "policy_decision" => "App Guard policy decision",

    # MDM events
    "mdm_profile_installed" => "MDM profile installed",
    "mdm_profile_removed" => "MDM profile removed",
    "compliance_violation" => "MDM compliance violation",
    "mdm_command_received" => "MDM command received",

    # SMS/Phishing events
    "phishing_sms_detected" => "Phishing SMS detected",
    "phishing_url_blocked" => "Phishing URL blocked",

    # Location events
    "geofence_breach" => "Geofence breach",
    "location_spoofing" => "Location spoofing detected"
  }

  schema "mobile_events" do
    field :event_type, :string
    field :severity, :string
    field :timestamp, :naive_datetime

    # Event details
    field :title, :string
    field :description, :string
    field :payload, :map, default: %{}

    # Detection info
    field :mitre_technique, :string
    field :mitre_tactic, :string
    field :rule_id, :string
    field :rule_name, :string

    # App context (if applicable)
    field :app_bundle_id, :string
    field :app_name, :string

    # Network context (if applicable)
    field :remote_address, :string
    field :remote_port, :integer
    field :domain, :string

    # Location context
    field :latitude, :float
    field :longitude, :float

    # Processing status
    field :processed, :boolean, default: false
    field :alerted, :boolean, default: false
    field :alert_id, :binary_id

    belongs_to :device, Device
    belongs_to :organization, Organization

    timestamps(updated_at: false)
  end

  @required_fields ~w(device_id organization_id event_type severity timestamp)a
  @optional_fields ~w(
    title description payload
    mitre_technique mitre_tactic rule_id rule_name
    app_bundle_id app_name
    remote_address remote_port domain
    latitude longitude
    processed alerted alert_id
  )a

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:severity, @severities)
    |> validate_event_type()
    |> maybe_add_title()
    |> foreign_key_constraint(:device_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for ingesting events from mobile agent.
  """
  def ingest_changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required([:device_id, :organization_id, :event_type, :severity])
    |> validate_inclusion(:severity, @severities)
    |> put_timestamp_if_missing()
    |> validate_event_type()
    |> maybe_add_title()
    |> maybe_add_mitre_mapping()
  end

  defp validate_event_type(changeset) do
    event_type = get_field(changeset, :event_type)

    if event_type && Map.has_key?(@event_types, event_type) do
      changeset
    else
      add_error(changeset, :event_type, "unknown event type: #{event_type}")
    end
  end

  defp maybe_add_title(changeset) do
    if get_field(changeset, :title) do
      changeset
    else
      event_type = get_field(changeset, :event_type)
      title = Map.get(@event_types, event_type, "Unknown event")
      put_change(changeset, :title, title)
    end
  end

  defp put_timestamp_if_missing(changeset) do
    if get_field(changeset, :timestamp) do
      changeset
    else
      put_change(changeset, :timestamp, NaiveDateTime.utc_now())
    end
  end

  # MITRE ATT&CK Mobile mappings
  @mitre_mappings %{
    "jailbreak_detected" => {"T1398", "TA0007"},
    "root_detected" => {"T1398", "TA0007"},
    "malicious_dns_query" => {"T1071.004", "TA0011"},
    "phishing_sms_detected" => {"T1660", "TA0001"},
    "phishing_url_blocked" => {"T1566.002", "TA0001"},
    "malware_detected" => {"T1544", "TA0002"},
    "spyware_detected" => {"T1429", "TA0009"},
    "overlay_detected" => {"T1411", "TA0009"},
    "debugger_detected" => {"T1622", "TA0007"},
    "sideload_attempt" => {"T1398", "TA0007"},
    "certificate_pinning_bypass" => {"T1557", "TA0006"},
    "man_in_the_middle" => {"T1557", "TA0006"},
    "location_spoofing" => {"T1430", "TA0007"},
    "tampering_detected" => {"T1398", "TA0005"},
    "browser_tamper_detected" => {"T1622", "TA0005"},
    "automation_detected" => {"T1622", "TA0007"},
    "network_exfiltration_suspected" => {"T1446", "TA0011"},
    "commercial_spyware_suspected" => {"T1639", "TA0009"},
    "integrity_snapshot_changed" => {"T1398", "TA0005"},
    "behavior_anomaly_detected" => {"T1622", "TA0007"}
  }

  defp maybe_add_mitre_mapping(changeset) do
    event_type = get_field(changeset, :event_type)

    case Map.get(@mitre_mappings, event_type) do
      {technique, tactic} ->
        changeset
        |> put_change(:mitre_technique, technique)
        |> put_change(:mitre_tactic, tactic)

      nil ->
        changeset
    end
  end

  @doc """
  Get all supported event types.
  """
  def event_types, do: @event_types

  @doc """
  Get description for event type.
  """
  def event_type_description(event_type) do
    Map.get(@event_types, event_type, "Unknown event")
  end

  # Query helpers

  @doc """
  Query events by device.
  """
  def by_device(query \\ __MODULE__, device_id) do
    from e in query, where: e.device_id == ^device_id
  end

  @doc """
  Query events by organization.
  """
  def by_organization(query \\ __MODULE__, organization_id) do
    from e in query, where: e.organization_id == ^organization_id
  end

  @doc """
  Query events by type.
  """
  def by_type(query \\ __MODULE__, event_type) do
    from e in query, where: e.event_type == ^event_type
  end

  @doc """
  Query events by severity.
  """
  def by_severity(query \\ __MODULE__, severity) when severity in @severities do
    from e in query, where: e.severity == ^severity
  end

  @doc """
  Query high-severity events (high or critical).
  """
  def high_severity(query \\ __MODULE__) do
    from e in query, where: e.severity in ["high", "critical"]
  end

  @doc """
  Query events within time range.
  """
  def in_time_range(query \\ __MODULE__, from_time, to_time) do
    from e in query, where: e.timestamp >= ^from_time and e.timestamp <= ^to_time
  end

  @doc """
  Query recent events (last N hours).
  """
  def recent(query \\ __MODULE__, hours \\ 24) do
    cutoff = NaiveDateTime.add(NaiveDateTime.utc_now(), -hours * 3600)
    from e in query, where: e.timestamp >= ^cutoff
  end

  @doc """
  Query events by MITRE technique.
  """
  def by_mitre_technique(query \\ __MODULE__, technique) do
    from e in query, where: e.mitre_technique == ^technique
  end

  @doc """
  Query unprocessed events.
  """
  def unprocessed(query \\ __MODULE__) do
    from e in query, where: e.processed == false
  end

  @doc """
  Query security events (excludes info-level).
  """
  def security_events(query \\ __MODULE__) do
    from e in query, where: e.severity != "info"
  end

  @doc """
  Order by timestamp descending.
  """
  def latest_first(query \\ __MODULE__) do
    from e in query, order_by: [desc: e.timestamp]
  end
end
