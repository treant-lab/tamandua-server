defmodule TamanduaServerWeb.GraphQL.Types.EventTypes do
  @moduledoc """
  GraphQL types for Telemetry Events.
  """
  use Absinthe.Schema.Notation

  @desc "Event type categories"
  enum :event_type do
    value :process, description: "Process creation/termination events"
    value :file, description: "File system events"
    value :network, description: "Network connection events"
    value :registry, description: "Windows registry events"
    value :dns, description: "DNS query events"
    value :authentication, description: "Authentication events"
    value :injection, description: "Process injection events"
    value :credential, description: "Credential access events"
    value :module, description: "Module/DLL load events"
  end

  @desc "A telemetry event from an agent"
  object :event do
    field :id, non_null(:id), description: "Unique event identifier"
    field :event_type, non_null(:string), description: "Event type category"
    field :timestamp, non_null(:datetime), description: "When the event occurred"
    field :payload, :json, description: "Event payload data"
    field :severity, :string, description: "Event severity"
    field :sha256, :string, description: "Associated file hash"
    field :enrichment, :json, description: "Enrichment data"
    field :created_at, :datetime, description: "When event was ingested"

    field :agent_id, :id

    field :agent, :agent do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.EventResolver.agent/3
    end

    field :related_alerts, list_of(:alert) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.EventResolver.related_alerts/3
    end
  end

  @desc "Process event details"
  object :process_event do
    field :pid, :integer, description: "Process ID"
    field :ppid, :integer, description: "Parent process ID"
    field :name, :string, description: "Process name"
    field :path, :string, description: "Executable path"
    field :cmdline, :string, description: "Command line"
    field :user, :string, description: "User name"
    field :sha256, :string, description: "Executable hash"
    field :is_elevated, :boolean, description: "Running elevated"
    field :is_signed, :boolean, description: "Digitally signed"
    field :signer, :string, description: "Signer name"
    field :parent_name, :string, description: "Parent process name"
    field :parent_path, :string, description: "Parent executable path"
    field :action, :string, description: "create, terminate, etc."
  end

  @desc "File event details"
  object :file_event do
    field :path, :string, description: "File path"
    field :action, :string, description: "create, modify, delete, rename"
    field :sha256, :string, description: "File hash"
    field :size, :integer, description: "File size in bytes"
    field :entropy, :float, description: "File entropy"
    field :owner, :string, description: "File owner"
    field :process_name, :string, description: "Process that performed action"
    field :process_pid, :integer, description: "Process ID"
    field :is_executable, :boolean, description: "Is executable file"
  end

  @desc "Network event details"
  object :network_event do
    field :local_ip, :string
    field :local_port, :integer
    field :remote_ip, :string
    field :remote_port, :integer
    field :protocol, :string, description: "TCP, UDP, etc."
    field :direction, :string, description: "inbound, outbound"
    field :action, :string, description: "connect, listen, close"
    field :bytes_sent, :integer
    field :bytes_received, :integer
    field :process_name, :string
    field :process_pid, :integer
    field :geo, :geo_info, description: "GeoIP information"
  end

  @desc "DNS event details"
  object :dns_event do
    field :query, :string, description: "Domain queried"
    field :query_type, :string, description: "A, AAAA, CNAME, etc."
    field :response, list_of(:string), description: "Response records"
    field :response_code, :string, description: "NOERROR, NXDOMAIN, etc."
    field :server_ip, :string, description: "DNS server used"
    field :process_name, :string
    field :process_pid, :integer
    field :is_blocked, :boolean, description: "Was query blocked"
    field :threat_intel, :domain_threat_intel, description: "Threat intel for domain"
  end

  @desc "Geographic IP information"
  object :geo_info do
    field :country, :string
    field :country_code, :string
    field :city, :string
    field :region, :string
    field :latitude, :float
    field :longitude, :float
    field :asn, :integer
    field :as_org, :string
  end

  @desc "Domain threat intelligence"
  object :domain_threat_intel do
    field :is_malicious, :boolean
    field :category, :string
    field :reputation_score, :float
    field :first_seen, :datetime
    field :sources, list_of(:string)
  end

  @desc "Event statistics"
  object :event_stats do
    field :total, non_null(:integer), description: "Total events"
    field :by_type, :json, description: "Count by event type"
    field :by_agent, list_of(:agent_event_count), description: "Count by agent"
    field :rate_per_minute, :float, description: "Current event rate"
    field :trend, list_of(:event_trend_point), description: "Event trend"
  end

  @desc "Event count per agent"
  object :agent_event_count do
    field :agent_id, :id
    field :hostname, :string
    field :count, :integer
  end

  @desc "Event trend data point"
  object :event_trend_point do
    field :timestamp, :datetime
    field :count, :integer
    field :event_type, :string
  end

  @desc "Filter input for events"
  input_object :event_filter do
    field :event_type, :string, description: "Filter by event type"
    field :agent_id, :id, description: "Filter by agent"
    field :severity, :string, description: "Filter by severity"
    field :since, :datetime, description: "Events since timestamp"
    field :until, :datetime, description: "Events until timestamp"
    field :search, :string, description: "Search in payload"
    field :sha256, :string, description: "Filter by file hash"
    field :process_name, :string, description: "Filter by process name"
    field :remote_ip, :string, description: "Filter by remote IP"
    field :domain, :string, description: "Filter by domain"
  end

  @desc "Input for event search using TQL"
  input_object :event_search_input do
    field :query, non_null(:string), description: "TQL query string"
    field :since, :datetime, description: "Search from timestamp"
    field :until, :datetime, description: "Search until timestamp"
    field :limit, :integer, default_value: 100, description: "Maximum results"
  end
end
