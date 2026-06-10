defmodule TamanduaServerWeb.GraphQL.Mutations.Batch do
  @moduledoc """
  GraphQL batch operation mutations.

  Provides batch operations for alerts, IOCs, and agents with
  progress tracking and webhook notifications.

  ## Mutations

  - batchCloseAlerts(ids: [ID!], resolutionNotes: String): BatchResult!
  - batchAssignAlerts(ids: [ID!], assignedToId: ID!): BatchResult!
  - batchTagAlerts(ids: [ID!], addTags: [String!], removeTags: [String!]): BatchResult!
  - batchDeleteAlerts(ids: [ID!]): BatchResult!
  - batchImportIOCs(iocs: [IOCInput!]!, source: String, deduplicate: Boolean): ImportResult!
  - batchDeleteIOCs(ids: [ID!]): BatchResult!
  - batchUpdateIOCs(ids: [ID!], updates: IOCUpdateInput!): BatchResult!
  - batchExecuteCommand(agentIds: [ID!]!, command: String!, reason: String): JobResult!
  """

  use Absinthe.Schema.Notation

  alias TamanduaServerWeb.GraphQL.Resolvers.BatchResolver

  object :batch_mutations do
    @desc "Close multiple alerts"
    field :batch_close_alerts, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))
      arg :resolution_notes, :string

      resolve &BatchResolver.close_alerts/3
    end

    @desc "Assign multiple alerts to a user"
    field :batch_assign_alerts, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))
      arg :assigned_to_id, non_null(:id)

      resolve &BatchResolver.assign_alerts/3
    end

    @desc "Add or remove tags from multiple alerts"
    field :batch_tag_alerts, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))
      arg :add_tags, list_of(non_null(:string))
      arg :remove_tags, list_of(non_null(:string))

      resolve &BatchResolver.tag_alerts/3
    end

    @desc "Delete multiple alerts"
    field :batch_delete_alerts, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))

      resolve &BatchResolver.delete_alerts/3
    end

    @desc "Import multiple IOCs from CSV or JSON"
    field :batch_import_iocs, :import_result do
      arg :iocs, non_null(list_of(non_null(:ioc_input)))
      arg :source, :string, default_value: "graphql_import"
      arg :deduplicate, :boolean, default_value: true

      resolve &BatchResolver.import_iocs/3
    end

    @desc "Delete multiple IOCs"
    field :batch_delete_iocs, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))

      resolve &BatchResolver.delete_iocs/3
    end

    @desc "Update multiple IOCs"
    field :batch_update_iocs, :batch_result do
      arg :ids, non_null(list_of(non_null(:id)))
      arg :updates, non_null(:ioc_update_input)

      resolve &BatchResolver.update_iocs/3
    end

    @desc "Execute command on multiple agents (isolate, scan, collect_forensics)"
    field :batch_execute_command, :job_result do
      arg :agent_ids, non_null(list_of(non_null(:id)))
      arg :command, non_null(:string)
      arg :reason, :string

      resolve &BatchResolver.execute_command/3
    end

    @desc "Get batch job status and progress"
    field :batch_job_status, :job_status do
      arg :job_id, non_null(:id)

      resolve &BatchResolver.get_job_status/3
    end
  end

  # ===========================================================================
  # Input Objects
  # ===========================================================================

  input_object :ioc_input do
    field :type, non_null(:string)
    field :value, non_null(:string)
    field :description, :string
    field :severity, :string
    field :confidence, :float
    field :tags, list_of(non_null(:string))
    field :malware_family, :string
    field :threat_actor, :string
    field :campaign, :string
    field :expires_at, :datetime
  end

  input_object :ioc_update_input do
    field :expires_at, :datetime
    field :add_tags, list_of(non_null(:string))
    field :remove_tags, list_of(non_null(:string))
  end

  # ===========================================================================
  # Result Objects
  # ===========================================================================

  object :batch_result do
    field :success_count, non_null(:integer)
    field :failed, non_null(list_of(non_null(:batch_failure)))
  end

  object :batch_failure do
    field :id, non_null(:id)
    field :reason, non_null(:string)
  end

  object :import_result do
    @desc "Number of IOCs imported (sync operation)"
    field :imported, :integer

    @desc "Number of IOCs skipped due to deduplication"
    field :skipped, :integer

    @desc "Failed IOC imports"
    field :failed, list_of(non_null(:ioc_import_failure))

    @desc "Job ID for async operation"
    field :job_id, :id

    @desc "Status URL for tracking async operation"
    field :status_url, :string
  end

  object :ioc_import_failure do
    field :type, non_null(:string)
    field :value, non_null(:string)
    field :reason, non_null(:string)
  end

  object :job_result do
    field :job_id, non_null(:id)
    field :message, non_null(:string)
    field :status_url, non_null(:string)
  end

  object :job_status do
    field :id, non_null(:id)
    field :state, non_null(:string)
    field :queue, non_null(:string)
    field :worker, non_null(:string)
    field :progress, non_null(:integer)
    field :message, :string
    field :attempted_at, :datetime
    field :completed_at, :datetime
    field :scheduled_at, :datetime
    field :errors, list_of(non_null(:job_error))
    field :attempt, non_null(:integer)
    field :max_attempts, non_null(:integer)
  end

  object :job_error do
    field :attempt, non_null(:integer)
    field :at, non_null(:string)
    field :error, non_null(:string)
  end
end
