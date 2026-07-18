defmodule TamanduaServerWeb.GraphQL.Types.AgentTypes do
  @moduledoc """
  GraphQL types for Agents.
  """
  use Absinthe.Schema.Notation

  @desc "Agent status"
  enum :agent_status do
    value :online, description: "Agent is connected and reporting"
    value :offline, description: "Agent is not connected"
    value :isolated, description: "Agent is network isolated"
  end

  @desc "Operating system type"
  enum :os_type do
    value :windows, description: "Microsoft Windows"
    value :linux, description: "Linux"
    value :macos, description: "macOS"
  end

  @desc "An EDR agent deployed on an endpoint"
  object :agent do
    field :id, non_null(:id), description: "Unique agent identifier (UUID)"
    field :hostname, non_null(:string), description: "Endpoint hostname"
    field :ip_address, :string, description: "Primary IP address"
    field :os_type, :string, description: "Operating system type"
    field :os_version, :string, description: "Operating system version"
    field :agent_version, :string, description: "Tamandua agent version"
    field :status, :string, description: "Current agent status"
    field :last_seen_at, :datetime, description: "Last heartbeat timestamp"
    field :config, :json, description: "Agent configuration"
    field :tags, list_of(:string), description: "Agent tags for grouping"
    field :organization_id, :id, description: "Organization this agent belongs to"
    field :inserted_at, :datetime, description: "Agent registration timestamp"
    field :updated_at, :datetime, description: "Last update timestamp"

    field :alerts, list_of(:alert) do
      arg :status, :string, description: "Filter by alert status"
      arg :severity, :string, description: "Filter by severity"
      arg :limit, :integer, default_value: 50

      resolve &TamanduaServerWeb.GraphQL.Resolvers.AgentResolver.alerts/3
    end

    field :events, list_of(:event) do
      arg :event_type, :string, description: "Filter by event type"
      arg :since, :datetime, description: "Events since this timestamp"
      arg :limit, :integer, default_value: 100

      resolve &TamanduaServerWeb.GraphQL.Resolvers.AgentResolver.events/3
    end

    field :process_tree, list_of(:process_node) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.AgentResolver.process_tree/3
    end

    field :baseline_status, :baseline_status do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.AgentResolver.baseline_status/3
    end
  end

  @desc "Agent with real-time status information"
  object :agent_live do
    field :agent_id, non_null(:id)
    field :hostname, :string
    field :ip_address, :string
    field :os_type, :string
    field :os_version, :string
    field :agent_version, :string
    field :status, :string
    field :last_seen_at, :datetime
    field :organization_id, :id
  end

  @desc "A node in the process tree"
  object :process_node do
    field :pid, non_null(:integer), description: "Process ID"
    field :ppid, :integer, description: "Parent process ID"
    field :name, :string, description: "Process name"
    field :path, :string, description: "Executable path"
    field :cmdline, :string, description: "Command line arguments"
    field :user, :string, description: "User running the process"
    field :start_time, :datetime, description: "Process start time"
    field :sha256, :string, description: "Executable SHA256 hash"
    field :is_elevated, :boolean, description: "Running with elevated privileges"
    field :is_signed, :boolean, description: "Executable is digitally signed"
    field :signer, :string, description: "Code signing certificate subject"
    field :children, list_of(:process_node), description: "Child processes"
    field :detections, list_of(:string), description: "Detection tags"
  end

  @desc "Agent baseline learning status"
  object :baseline_status do
    field :status, :string, description: "Learning status (learning, active, disabled)"
    field :started_at, :datetime, description: "When baseline learning started"
    field :ends_at, :datetime, description: "When baseline learning will end"
    field :patterns_learned, :integer, description: "Number of patterns learned"
    field :anomalies_detected, :integer, description: "Number of anomalies since baseline"
  end

  @desc "Agent statistics"
  object :agent_stats do
    field :total, non_null(:integer), description: "Total number of agents"
    field :online, non_null(:integer), description: "Number of online agents"
    field :offline, non_null(:integer), description: "Number of offline agents"
    field :isolated, non_null(:integer), description: "Number of isolated agents"
    field :by_os, :json, description: "Agent count by operating system"
    field :by_version, :json, description: "Agent count by version"
  end

  @desc "Filter input for agents"
  input_object :agent_filter do
    field :status, :string, description: "Filter by status (online, offline, isolated)"
    field :os_type, :string, description: "Filter by OS type"
    field :hostname_contains, :string, description: "Filter by hostname pattern"
    field :ip_address, :string, description: "Filter by IP address"
    field :tags, list_of(:string), description: "Filter by tags (any match)"
    field :version, :string, description: "Filter by agent version"
  end

  @desc "Input for isolating an agent"
  input_object :isolate_agent_input do
    field :agent_id, non_null(:id), description: "Agent to isolate"
    field :reason, :string, description: "Reason for isolation"
    field :allow_local_dns, :boolean, default_value: false, description: "Allow local DNS resolution"
  end
end
