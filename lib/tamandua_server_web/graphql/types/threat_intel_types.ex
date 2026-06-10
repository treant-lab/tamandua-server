defmodule TamanduaServerWeb.GraphQL.Types.ThreatIntelTypes do
  @moduledoc """
  GraphQL types for Threat Intelligence.
  """
  use Absinthe.Schema.Notation

  @desc "IOC type"
  enum :ioc_type do
    value :ip, description: "IP address"
    value :domain, description: "Domain name"
    value :url, description: "URL"
    value :hash_md5, description: "MD5 hash"
    value :hash_sha1, description: "SHA1 hash"
    value :hash_sha256, description: "SHA256 hash"
    value :email, description: "Email address"
    value :file_name, description: "File name"
    value :registry_key, description: "Registry key"
  end

  @desc "Indicator of Compromise"
  object :ioc do
    field :id, non_null(:id)
    field :type, non_null(:string)
    field :value, non_null(:string)
    field :source, :string
    field :description, :string
    field :severity, :string
    field :confidence, :float
    field :first_seen, :datetime
    field :last_seen, :datetime
    field :tags, list_of(:string)
    field :ttl, :integer, description: "Time to live in hours"
    field :is_active, :boolean
    field :enrichment, :json
    field :inserted_at, :datetime

    field :related_alerts, list_of(:alert) do
      arg :limit, :integer, default_value: 10
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.related_alerts/3
    end

    field :threat_actor, :threat_actor do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.threat_actor/3
    end
  end

  @desc "Threat actor profile"
  object :threat_actor do
    field :id, non_null(:id)
    field :name, non_null(:string)
    field :aliases, list_of(:string)
    field :description, :string
    field :motivation, :string, description: "financial, espionage, hacktivism, etc."
    field :sophistication, :string, description: "advanced, intermediate, basic"
    field :country, :string
    field :first_seen, :datetime
    field :last_seen, :datetime
    field :mitre_techniques, list_of(:string)
    field :target_sectors, list_of(:string)
    field :target_regions, list_of(:string)
    field :references, list_of(:string)
    field :inserted_at, :datetime

    field :iocs, list_of(:ioc) do
      arg :limit, :integer, default_value: 50
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.actor_iocs/3
    end

    field :campaigns, list_of(:campaign) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.actor_campaigns/3
    end
  end

  @desc "Threat campaign"
  object :campaign do
    field :id, non_null(:id)
    field :name, non_null(:string)
    field :description, :string
    field :threat_actor_id, :id
    field :start_date, :datetime
    field :end_date, :datetime
    field :status, :string, description: "active, concluded, unknown"
    field :targets, list_of(:string)
    field :malware_families, list_of(:string)
    field :mitre_techniques, list_of(:string)
    field :inserted_at, :datetime

    field :threat_actor, :threat_actor do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.campaign_actor/3
    end

    field :iocs, list_of(:ioc) do
      arg :limit, :integer, default_value: 50
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.campaign_iocs/3
    end
  end

  @desc "Threat intelligence feed"
  object :threat_feed do
    field :id, non_null(:id)
    field :name, non_null(:string)
    field :type, :string, description: "misp, taxii, stix, csv, json"
    field :url, :string
    field :enabled, :boolean
    field :last_sync, :datetime
    field :next_sync, :datetime
    field :sync_interval_minutes, :integer
    field :ioc_count, :integer
    field :error_count, :integer
    field :last_error, :string
    field :inserted_at, :datetime
  end

  @desc "IOC enrichment result"
  object :enrichment_result do
    field :ioc_type, :string
    field :ioc_value, :string
    field :is_malicious, :boolean
    field :confidence, :float
    field :sources, list_of(:enrichment_source)
    field :geo, :geo_info
    field :whois, :json
    field :dns, :json
    field :related_iocs, list_of(:ioc)
    field :threat_actors, list_of(:threat_actor)
    field :mitre_techniques, list_of(:string)
    field :first_seen, :datetime
    field :last_seen, :datetime
  end

  @desc "Enrichment source"
  object :enrichment_source do
    field :name, :string
    field :category, :string
    field :is_malicious, :boolean
    field :confidence, :float
    field :details, :json
    field :last_updated, :datetime
  end

  @desc "MITRE ATT&CK technique"
  object :mitre_technique do
    field :id, non_null(:string), description: "e.g., T1059.001"
    field :name, non_null(:string)
    field :description, :string
    field :tactic_id, :string
    field :tactic_name, :string
    field :platforms, list_of(:string)
    field :data_sources, list_of(:string)
    field :detection, :string
    field :mitigation, :string
    field :references, list_of(:string)

    field :alert_count, :integer do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ThreatIntelResolver.technique_alert_count/3
    end
  end

  @desc "MITRE ATT&CK tactic"
  object :mitre_tactic do
    field :id, non_null(:string), description: "e.g., TA0001"
    field :name, non_null(:string)
    field :description, :string
    field :techniques, list_of(:mitre_technique)
  end

  @desc "MITRE ATT&CK coverage"
  object :mitre_coverage do
    field :tactic_id, :string
    field :tactic_name, :string
    field :technique_count, :integer
    field :covered_count, :integer
    field :coverage_percentage, :float
    field :techniques, list_of(:technique_coverage)
  end

  @desc "Technique coverage detail"
  object :technique_coverage do
    field :technique_id, :string
    field :technique_name, :string
    field :is_covered, :boolean
    field :rule_count, :integer
    field :alert_count, :integer
  end

  @desc "Threat intelligence summary"
  object :threat_intel_summary do
    field :total_iocs, :integer
    field :active_iocs, :integer
    field :total_actors, :integer
    field :active_campaigns, :integer
    field :feeds_count, :integer
    field :feeds_healthy, :integer
    field :last_enrichment, :datetime
    field :iocs_by_type, :json
    field :iocs_by_severity, :json
    field :recent_iocs, list_of(:ioc)
    field :top_actors, list_of(:threat_actor)
  end

  @desc "Filter input for IOCs"
  input_object :ioc_filter do
    field :type, :string
    field :source, :string
    field :severity, :string
    field :is_active, :boolean
    field :search, :string
    field :since, :datetime
    field :tags, list_of(:string)
  end

  @desc "Input for creating an IOC"
  input_object :create_ioc_input do
    field :type, non_null(:string)
    field :value, non_null(:string)
    field :source, :string
    field :description, :string
    field :severity, :string, default_value: "medium"
    field :confidence, :float, default_value: 0.8
    field :tags, list_of(:string)
    field :ttl_hours, :integer
  end

  @desc "Input for bulk IOC import"
  input_object :bulk_ioc_input do
    field :iocs, non_null(list_of(:create_ioc_input))
    field :source, :string
    field :default_severity, :string
  end

  @desc "Input for IOC enrichment"
  input_object :enrich_ioc_input do
    field :type, non_null(:string)
    field :value, non_null(:string)
    field :sources, list_of(:string), description: "Specific sources to query"
    field :include_related, :boolean, default_value: true
  end

  @desc "Input for creating a threat actor"
  input_object :create_threat_actor_input do
    field :name, non_null(:string)
    field :aliases, list_of(:string)
    field :description, :string
    field :motivation, :string
    field :sophistication, :string
    field :country, :string
    field :mitre_techniques, list_of(:string)
    field :target_sectors, list_of(:string)
    field :target_regions, list_of(:string)
    field :references, list_of(:string)
  end
end
