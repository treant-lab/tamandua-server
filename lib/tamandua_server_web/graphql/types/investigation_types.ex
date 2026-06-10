defmodule TamanduaServerWeb.GraphQL.Types.InvestigationTypes do
  @moduledoc """
  GraphQL types for Investigations and Forensics.
  """
  use Absinthe.Schema.Notation

  @desc "Investigation status"
  enum :investigation_status do
    value :open, description: "Active investigation"
    value :in_progress, description: "Being worked on"
    value :closed, description: "Investigation closed"
    value :escalated, description: "Escalated to higher tier"
  end

  @desc "Investigation priority"
  enum :investigation_priority do
    value :critical, description: "Critical priority"
    value :high, description: "High priority"
    value :medium, description: "Medium priority"
    value :low, description: "Low priority"
  end

  @desc "A security investigation case"
  object :investigation do
    field :id, non_null(:id)
    field :title, non_null(:string)
    field :description, :string
    field :status, :string
    field :priority, :string
    field :severity, :string
    field :created_by_id, :id
    field :assigned_to_id, :id
    field :organization_id, :id
    field :mitre_tactics, list_of(:string)
    field :mitre_techniques, list_of(:string)
    field :tags, list_of(:string)
    field :findings, :string
    field :recommendations, :string
    field :inserted_at, :datetime
    field :updated_at, :datetime
    field :closed_at, :datetime

    field :alerts, list_of(:alert) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.alerts/3
    end

    field :notes, list_of(:investigation_note) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.notes/3
    end

    field :timeline, list_of(:timeline_event) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.timeline/3
    end

    field :evidence, list_of(:evidence_item) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.evidence/3
    end

    field :created_by, :user do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.created_by/3
    end

    field :assigned_to, :user do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver.assigned_to/3
    end
  end

  @desc "A note on an investigation"
  object :investigation_note do
    field :id, :id
    field :content, :string
    field :author_id, :id
    field :author_name, :string
    field :created_at, :datetime
    field :is_internal, :boolean
  end

  @desc "An evidence item"
  object :evidence_item do
    field :id, :id
    field :type, :string, description: "file, process, network, registry"
    field :name, :string
    field :description, :string
    field :data, :json
    field :sha256, :string
    field :collected_at, :datetime
    field :agent_id, :id
    field :event_id, :id
  end

  @desc "Investigation graph for visualization"
  object :investigation_graph do
    field :nodes, list_of(:graph_node)
    field :edges, list_of(:graph_edge)
    field :clusters, list_of(:graph_cluster)
  end

  @desc "A node in the investigation graph"
  object :graph_node do
    field :id, non_null(:string)
    field :type, non_null(:string), description: "process, file, network, registry, user, host"
    field :label, :string
    field :properties, :json
    field :severity, :string
    field :is_suspicious, :boolean
  end

  @desc "An edge in the investigation graph"
  object :graph_edge do
    field :source, non_null(:string)
    field :target, non_null(:string)
    field :type, :string, description: "spawned, wrote, connected, accessed"
    field :label, :string
    field :timestamp, :datetime
  end

  @desc "A cluster in the investigation graph"
  object :graph_cluster do
    field :id, non_null(:string)
    field :label, :string
    field :node_ids, list_of(:string)
    field :type, :string
  end

  @desc "Forensic collection"
  object :forensic_collection do
    field :id, non_null(:id)
    field :agent_id, :id
    field :collection_type, :string, description: "memory, disk, logs, full"
    field :status, :string, description: "pending, in_progress, completed, failed"
    field :progress, :integer, description: "Percentage complete"
    field :artifacts, list_of(:forensic_artifact)
    field :size_bytes, :integer
    field :started_at, :datetime
    field :completed_at, :datetime
    field :error_message, :string
    field :requested_by_id, :id
  end

  @desc "A forensic artifact"
  object :forensic_artifact do
    field :id, :id
    field :name, :string
    field :path, :string
    field :type, :string
    field :size_bytes, :integer
    field :sha256, :string
    field :collected_at, :datetime
    field :analysis, :json
  end

  @desc "AI-powered investigation analysis"
  object :ai_investigation_analysis do
    field :summary, :string
    field :threat_level, :string
    field :confidence, :float
    field :attack_chain, list_of(:attack_chain_step)
    field :recommended_actions, list_of(:recommended_action)
    field :iocs_extracted, list_of(:extracted_ioc)
    field :mitre_mapping, list_of(:mitre_mapping)
    field :similar_incidents, list_of(:similar_incident)
  end

  @desc "Attack chain step from AI analysis"
  object :attack_chain_step do
    field :step_number, :integer
    field :tactic, :string
    field :technique, :string
    field :description, :string
    field :evidence, list_of(:string)
    field :timestamp, :datetime
  end

  @desc "Recommended action from AI analysis"
  object :recommended_action do
    field :action, :string
    field :priority, :string
    field :description, :string
    field :playbook_id, :id
    field :auto_executable, :boolean
  end

  @desc "Extracted IOC from AI analysis"
  object :extracted_ioc do
    field :type, :string
    field :value, :string
    field :confidence, :float
    field :context, :string
    field :is_known_bad, :boolean
  end

  @desc "MITRE ATT&CK mapping"
  object :mitre_mapping do
    field :tactic_id, :string
    field :tactic_name, :string
    field :technique_id, :string
    field :technique_name, :string
    field :confidence, :float
    field :evidence, list_of(:string)
  end

  @desc "Similar incident reference"
  object :similar_incident do
    field :investigation_id, :id
    field :similarity_score, :float
    field :title, :string
    field :date, :datetime
    field :resolution, :string
  end

  @desc "Investigation statistics"
  object :investigation_stats do
    field :total, :integer
    field :open, :integer
    field :closed, :integer
    field :by_status, :json
    field :by_priority, :json
    field :average_resolution_hours, :float
    field :mttr, :float, description: "Mean time to resolve"
  end

  @desc "Filter input for investigations"
  input_object :investigation_filter do
    field :status, :string
    field :priority, :string
    field :assigned_to_id, :id
    field :since, :datetime
    field :until, :datetime
    field :search, :string
    field :tags, list_of(:string)
  end

  @desc "Input for creating an investigation"
  input_object :create_investigation_input do
    field :title, non_null(:string)
    field :description, :string
    field :priority, :string, default_value: "medium"
    field :alert_ids, list_of(:id)
    field :tags, list_of(:string)
  end

  @desc "Input for updating an investigation"
  input_object :update_investigation_input do
    field :title, :string
    field :description, :string
    field :status, :string
    field :priority, :string
    field :assigned_to_id, :id
    field :findings, :string
    field :recommendations, :string
    field :tags, list_of(:string)
  end

  @desc "Input for adding a note to an investigation"
  input_object :add_investigation_note_input do
    field :investigation_id, non_null(:id)
    field :content, non_null(:string)
    field :is_internal, :boolean, default_value: false
  end

  @desc "Input for collecting forensics"
  input_object :collect_forensics_input do
    field :agent_id, non_null(:id)
    field :collection_type, :string, default_value: "full"
    field :paths, list_of(:string)
    field :include_memory, :boolean, default_value: false
    field :investigation_id, :id
  end
end
