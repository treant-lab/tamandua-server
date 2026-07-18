defmodule TamanduaServer.XDR.NormalizedEvent do
  @moduledoc """
  Ecto schema for normalized XDR (Extended Detection and Response) events.

  This schema provides a unified format for events from diverse security sources:
  - Firewalls (Palo Alto, Fortinet, Cisco ASA)
  - Web Proxies (Zscaler, Bluecoat, Squid)
  - Email Security (O365, Google Workspace, Proofpoint)
  - Cloud (AWS CloudTrail, Azure Activity, GCP Audit)
  - Network Security (Zeek/Bro, Suricata)

  The schema follows Elastic Common Schema (ECS) principles for field naming
  to ensure consistency and interoperability.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.XDR.Source
  alias TamanduaServer.Telemetry.Event, as: EndpointEvent
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @source_types ~w(firewall proxy email cloud network ids iam siem custom)
  @severities ~w(critical high medium low info)
  @actions ~w(allow deny block alert drop quarantine forward redirect unknown)
  @outcomes ~w(success failure unknown)
  @log_formats ~w(cef leef json syslog csv xml)
  @network_directions ~w(inbound outbound internal external unknown)
  @email_directions ~w(inbound outbound internal)

  schema "xdr_events" do
    # Timestamp fields
    field :timestamp, :utc_datetime_usec
    field :received_at, :utc_datetime_usec
    field :ingested_at, :utc_datetime_usec

    # Source identification
    field :source_type, :string
    field :source_name, :string
    field :log_format, :string

    # Network fields
    field :source_ip, :string
    field :source_port, :integer
    field :dest_ip, :string
    field :dest_port, :integer
    field :source_hostname, :string
    field :dest_hostname, :string
    field :network_direction, :string
    field :network_protocol, :string
    field :network_transport, :string

    # User/identity fields
    field :user_name, :string
    field :user_domain, :string
    field :user_email, :string
    field :source_user, :string
    field :dest_user, :string

    # Action/outcome fields
    field :action, :string
    field :outcome, :string
    field :event_category, :string
    field :event_type, :string

    # Severity and risk
    field :severity, :string, default: "info"
    field :risk_score, :float

    # URL/domain fields
    field :url, :string
    field :url_domain, :string
    field :url_path, :string
    field :dns_query, :string

    # File fields
    field :file_name, :string
    field :file_path, :string
    field :file_hash_sha256, :string
    field :file_hash_md5, :string
    field :file_size, :integer

    # Email fields
    field :email_subject, :string
    field :email_from, :string
    field :email_to, :string
    field :email_direction, :string

    # Cloud fields
    field :cloud_provider, :string
    field :cloud_region, :string
    field :cloud_account_id, :string
    field :cloud_resource_id, :string
    field :cloud_service, :string

    # Rule/signature fields
    field :rule_name, :string
    field :rule_id, :string
    field :signature_id, :string
    field :threat_name, :string
    field :threat_category, :string

    # MITRE ATT&CK
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []

    # Raw and enriched data
    field :raw_event, :string
    field :parsed_fields, :map, default: %{}
    field :enrichment, :map, default: %{}

    # Correlation
    field :correlation_id, :binary_id

    # Relationships
    belongs_to :source, Source
    belongs_to :organization, Organization
    belongs_to :correlated_endpoint_event, EndpointEvent
    belongs_to :correlated_alert, Alert
  end

  @required_fields [:timestamp, :source_type]
  @optional_fields [
    :received_at, :ingested_at, :source_name, :source_id, :log_format,
    :source_ip, :source_port, :dest_ip, :dest_port,
    :source_hostname, :dest_hostname, :network_direction, :network_protocol, :network_transport,
    :user_name, :user_domain, :user_email, :source_user, :dest_user,
    :action, :outcome, :event_category, :event_type,
    :severity, :risk_score,
    :url, :url_domain, :url_path, :dns_query,
    :file_name, :file_path, :file_hash_sha256, :file_hash_md5, :file_size,
    :email_subject, :email_from, :email_to, :email_direction,
    :cloud_provider, :cloud_region, :cloud_account_id, :cloud_resource_id, :cloud_service,
    :rule_name, :rule_id, :signature_id, :threat_name, :threat_category,
    :mitre_tactics, :mitre_techniques,
    :raw_event, :parsed_fields, :enrichment,
    :correlation_id, :correlated_endpoint_event_id, :correlated_alert_id,
    :organization_id
  ]

  @doc """
  Creates a changeset for a normalized XDR event.
  """
  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:source_type, @source_types)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:action, @actions ++ [nil])
    |> validate_inclusion(:outcome, @outcomes ++ [nil])
    |> validate_inclusion(:log_format, @log_formats ++ [nil])
    |> validate_inclusion(:network_direction, @network_directions ++ [nil])
    |> validate_inclusion(:email_direction, @email_directions ++ [nil])
    |> validate_ip(:source_ip)
    |> validate_ip(:dest_ip)
    |> validate_number(:source_port, greater_than_or_equal_to: 0, less_than_or_equal_to: 65535)
    |> validate_number(:dest_port, greater_than_or_equal_to: 0, less_than_or_equal_to: 65535)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> foreign_key_constraint(:source_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:correlated_endpoint_event_id)
    |> foreign_key_constraint(:correlated_alert_id)
    |> set_received_at()
  end

  defp validate_ip(changeset, field) do
    case get_change(changeset, field) do
      nil -> changeset
      ip when is_binary(ip) ->
        case :inet.parse_address(String.to_charlist(ip)) do
          {:ok, _} -> changeset
          {:error, _} -> add_error(changeset, field, "must be a valid IP address")
        end
      _ -> changeset
    end
  end

  defp set_received_at(changeset) do
    if get_field(changeset, :received_at) do
      changeset
    else
      put_change(changeset, :received_at, DateTime.utc_now())
    end
  end

  # Source type definitions
  def source_types, do: @source_types
  def severities, do: @severities
  def actions, do: @actions
  def outcomes, do: @outcomes
  def log_formats, do: @log_formats

  @doc """
  Builds an in-memory `%NormalizedEvent{}` struct from a parsed event map.

  Known schema fields are set directly; vendor-specific extra keys are
  preserved under `:parsed_fields` (mirroring `normalize/3` policy).
  `source_type` atoms are stringified and `timestamp`/`received_at`
  default to now.

  This is a plain constructor for parser pipelines -- persistence must
  still go through `changeset/2`, which performs validation.
  """
  def new(attrs) when is_map(attrs) do
    {known, extras} = Map.split(attrs, __schema__(:fields))

    known =
      known
      |> Map.update(:source_type, "custom", &to_string/1)
      |> Map.put_new_lazy(:timestamp, &DateTime.utc_now/0)
      |> Map.put_new_lazy(:received_at, &DateTime.utc_now/0)
      |> Map.update(:parsed_fields, extras, &Map.merge(extras, &1))

    struct(__MODULE__, known)
  end

  @doc """
  Normalizes raw event data into a standardized format.
  Takes vendor-specific parsed fields and maps them to normalized fields.
  """
  def normalize(parsed_event, source_type, opts \\ []) do
    base = %{
      timestamp: parsed_event[:timestamp] || DateTime.utc_now(),
      source_type: to_string(source_type),
      source_name: opts[:source_name],
      log_format: opts[:log_format],
      organization_id: opts[:organization_id],
      source_id: opts[:source_id],
      received_at: DateTime.utc_now(),
      raw_event: opts[:raw_event]
    }

    # Merge normalized network fields
    normalized = base
    |> Map.merge(normalize_network_fields(parsed_event))
    |> Map.merge(normalize_user_fields(parsed_event))
    |> Map.merge(normalize_action_fields(parsed_event))
    |> Map.merge(normalize_url_fields(parsed_event))
    |> Map.merge(normalize_file_fields(parsed_event))
    |> Map.merge(normalize_email_fields(parsed_event))
    |> Map.merge(normalize_cloud_fields(parsed_event))
    |> Map.merge(normalize_threat_fields(parsed_event))
    |> Map.merge(normalize_mitre_fields(parsed_event))
    |> Map.put(:parsed_fields, Map.drop(parsed_event, Map.keys(base)))

    # Calculate severity if not provided
    if normalized[:severity] do
      normalized
    else
      Map.put(normalized, :severity, infer_severity(normalized))
    end
  end

  defp normalize_network_fields(event) do
    %{
      source_ip: event[:src_ip] || event[:source_ip] || event[:srcip] || event[:sip],
      source_port: parse_port(event[:src_port] || event[:source_port] || event[:srcport] || event[:sport]),
      dest_ip: event[:dst_ip] || event[:dest_ip] || event[:dstip] || event[:dip] || event[:destination_ip],
      dest_port: parse_port(event[:dst_port] || event[:dest_port] || event[:dstport] || event[:dport] || event[:destination_port]),
      source_hostname: event[:src_host] || event[:source_hostname] || event[:srchost],
      dest_hostname: event[:dst_host] || event[:dest_hostname] || event[:dsthost] || event[:destination_hostname],
      network_direction: normalize_direction(event[:direction] || event[:network_direction]),
      network_protocol: String.upcase(to_string(event[:protocol] || event[:proto] || event[:network_protocol] || "")),
      network_transport: event[:app] || event[:application] || event[:transport] || event[:service]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) or v == "" end)
    |> Map.new()
  end

  defp normalize_user_fields(event) do
    %{
      user_name: event[:user] || event[:username] || event[:user_name] || event[:srcuser],
      user_domain: event[:domain] || event[:user_domain] || event[:userdomain],
      user_email: event[:email] || event[:user_email] || event[:useremail],
      source_user: event[:src_user] || event[:source_user] || event[:sourceuser],
      dest_user: event[:dst_user] || event[:dest_user] || event[:destinationuser]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_action_fields(event) do
    action = event[:action] || event[:act] || event[:result]
    outcome = event[:outcome] || infer_outcome(action)

    %{
      action: normalize_action(action),
      outcome: outcome,
      event_category: event[:category] || event[:event_category] || event[:cat],
      event_type: event[:type] || event[:event_type] || event[:eventtype]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_url_fields(event) do
    url = event[:url] || event[:request_url] || event[:requesturl]
    domain = event[:domain] || event[:hostname] || event[:host] || extract_domain(url)

    %{
      url: url,
      url_domain: domain,
      url_path: event[:path] || event[:url_path] || event[:uri] || extract_path(url),
      dns_query: event[:dns_query] || event[:query] || event[:qname]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_file_fields(event) do
    %{
      file_name: event[:filename] || event[:file_name] || event[:fname],
      file_path: event[:filepath] || event[:file_path] || event[:fpath],
      file_hash_sha256: event[:sha256] || event[:filehash] || event[:hash],
      file_hash_md5: event[:md5],
      file_size: parse_int(event[:filesize] || event[:file_size] || event[:fsize])
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_email_fields(event) do
    %{
      email_subject: event[:subject] || event[:email_subject],
      email_from: event[:from] || event[:sender] || event[:email_from],
      email_to: normalize_email_recipients(event[:to] || event[:recipient] || event[:recipients] || event[:email_to]),
      email_direction: normalize_email_direction(event[:direction] || event[:email_direction])
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_cloud_fields(event) do
    %{
      cloud_provider: normalize_cloud_provider(event[:cloud_provider] || event[:provider] || event[:eventSource]),
      cloud_region: event[:region] || event[:awsRegion] || event[:cloud_region],
      cloud_account_id: event[:account_id] || event[:accountId] || event[:recipientAccountId] || event[:cloud_account_id],
      cloud_resource_id: event[:resource_id] || event[:resourceId] || event[:arn] || event[:cloud_resource_id],
      cloud_service: event[:service] || event[:eventSource] || event[:cloud_service]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_threat_fields(event) do
    %{
      rule_name: event[:rule_name] || event[:rulename] || event[:rule] || event[:signature],
      rule_id: event[:rule_id] || event[:ruleid] || event[:sid],
      signature_id: event[:signature_id] || event[:signatureid] || event[:sid],
      threat_name: event[:threat_name] || event[:threatname] || event[:malware] || event[:virus],
      threat_category: event[:threat_category] || event[:threatcategory] || event[:category],
      severity: normalize_severity(event[:severity] || event[:priority] || event[:risk])
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp normalize_mitre_fields(event) do
    tactics = event[:mitre_tactics] || event[:tactics] || []
    techniques = event[:mitre_techniques] || event[:techniques] || []

    %{
      mitre_tactics: List.wrap(tactics),
      mitre_techniques: List.wrap(techniques)
    }
  end

  # Helper functions

  defp parse_port(nil), do: nil
  defp parse_port(port) when is_integer(port), do: port
  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {p, _} when p >= 0 and p <= 65535 -> p
      _ -> nil
    end
  end
  defp parse_port(_), do: nil

  defp parse_int(nil), do: nil
  defp parse_int(i) when is_integer(i), do: i
  defp parse_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {i, _} -> i
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp normalize_direction(nil), do: nil
  defp normalize_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      d when d in ["inbound", "in", "ingress", "incoming"] -> "inbound"
      d when d in ["outbound", "out", "egress", "outgoing"] -> "outbound"
      d when d in ["internal", "lateral", "east-west"] -> "internal"
      d when d in ["external", "north-south"] -> "external"
      _ -> "unknown"
    end
  end
  defp normalize_direction(_), do: nil

  defp normalize_action(nil), do: nil
  defp normalize_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["allow", "allowed", "accept", "pass", "permit"] -> "allow"
      a when a in ["deny", "denied", "reject", "refused"] -> "deny"
      a when a in ["block", "blocked", "drop", "dropped"] -> "block"
      a when a in ["alert", "alerted", "warn", "warning"] -> "alert"
      a when a in ["quarantine", "quarantined", "isolate", "isolated"] -> "quarantine"
      a when a in ["forward", "forwarded", "redirect", "redirected"] -> "forward"
      _ -> "unknown"
    end
  end
  defp normalize_action(_), do: nil

  defp infer_outcome(nil), do: nil
  defp infer_outcome(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["allow", "allowed", "accept", "pass", "permit", "success", "ok"] -> "success"
      a when a in ["deny", "denied", "block", "blocked", "drop", "dropped", "fail", "failed", "error"] -> "failure"
      _ -> "unknown"
    end
  end
  defp infer_outcome(_), do: nil

  defp normalize_severity(nil), do: nil
  defp normalize_severity(sev) when is_binary(sev) do
    case String.downcase(sev) do
      s when s in ["critical", "crit", "5", "emergency", "emerg"] -> "critical"
      s when s in ["high", "4", "alert", "error", "err"] -> "high"
      s when s in ["medium", "med", "3", "warning", "warn"] -> "medium"
      s when s in ["low", "2", "notice", "info", "informational"] -> "low"
      s when s in ["info", "1", "debug", "0"] -> "info"
      _ -> "info"
    end
  end
  defp normalize_severity(sev) when is_integer(sev) do
    cond do
      sev >= 5 -> "critical"
      sev >= 4 -> "high"
      sev >= 3 -> "medium"
      sev >= 2 -> "low"
      true -> "info"
    end
  end
  defp normalize_severity(_), do: nil

  defp infer_severity(event) do
    cond do
      event[:action] in ["block", "deny", "quarantine"] -> "medium"
      event[:threat_name] != nil -> "high"
      event[:action] == "alert" -> "medium"
      true -> "info"
    end
  end

  defp normalize_cloud_provider(nil), do: nil
  defp normalize_cloud_provider(provider) when is_binary(provider) do
    provider_lower = String.downcase(provider)
    cond do
      String.contains?(provider_lower, "aws") or String.contains?(provider_lower, "amazon") -> "aws"
      String.contains?(provider_lower, "azure") or String.contains?(provider_lower, "microsoft") -> "azure"
      String.contains?(provider_lower, "gcp") or String.contains?(provider_lower, "google") -> "gcp"
      true -> provider
    end
  end
  defp normalize_cloud_provider(_), do: nil

  defp normalize_email_recipients(nil), do: nil
  defp normalize_email_recipients(recipients) when is_list(recipients), do: Jason.encode!(recipients)
  defp normalize_email_recipients(recipient) when is_binary(recipient), do: recipient
  defp normalize_email_recipients(_), do: nil

  defp normalize_email_direction(nil), do: nil
  defp normalize_email_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      d when d in ["inbound", "in", "incoming", "received"] -> "inbound"
      d when d in ["outbound", "out", "outgoing", "sent"] -> "outbound"
      d when d in ["internal"] -> "internal"
      _ -> nil
    end
  end
  defp normalize_email_direction(_), do: nil

  defp extract_domain(nil), do: nil
  defp extract_domain(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> host
      _ -> nil
    end
  end
  defp extract_domain(_), do: nil

  defp extract_path(nil), do: nil
  defp extract_path(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{path: path} when is_binary(path) -> path
      _ -> nil
    end
  end
  defp extract_path(_), do: nil
end
