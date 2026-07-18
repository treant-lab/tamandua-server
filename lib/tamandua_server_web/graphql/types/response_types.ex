defmodule TamanduaServerWeb.GraphQL.Types.ResponseTypes do
  @moduledoc """
  GraphQL types for Response Actions.
  """
  use Absinthe.Schema.Notation

  @desc "Response action type"
  enum :response_action_type do
    value :kill_process, description: "Terminate a process"
    value :quarantine_file, description: "Quarantine a file"
    value :isolate_host, description: "Network isolate host"
    value :unisolate_host, description: "Remove network isolation"
    value :block_ip, description: "Block IP address"
    value :block_domain, description: "Block domain"
    value :collect_forensics, description: "Collect forensic data"
    value :scan_path, description: "Trigger malware scan"
    value :remediate, description: "Auto-remediate threat"
  end

  @desc "Response action status"
  enum :response_action_status do
    value :pending, description: "Awaiting execution"
    value :in_progress, description: "Currently executing"
    value :completed, description: "Successfully completed"
    value :failed, description: "Execution failed"
    value :cancelled, description: "Cancelled by user"
  end

  @desc "A response action"
  object :response_action do
    field :id, non_null(:id)
    field :action_type, non_null(:string)
    field :status, non_null(:string)
    field :agent_id, :id
    field :target, :string, description: "Target of action (PID, path, IP, etc.)"
    field :parameters, :json
    field :result, :json
    field :error_message, :string
    field :requested_by_id, :id do
      resolve(fn action, _, _ -> {:ok, action.executed_by_id} end)
    end
    field :alert_id, :id
    field :playbook_execution_id, :id
    field :started_at, :datetime
    field :completed_at, :datetime
    field :inserted_at, :datetime

    field :agent, :agent do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ResponseResolver.agent/3
    end

    field :requested_by, :user do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ResponseResolver.requested_by/3
    end

    field :alert, :alert do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.ResponseResolver.alert/3
    end
  end

  @desc "Result of a kill process action"
  object :kill_process_result do
    field :success, non_null(:boolean)
    field :agent_id, :id
    field :pid, :integer
    field :process_name, :string
    field :message, :string
    field :action_id, :id
    field :audit_status, :string
  end

  @desc "Result of a quarantine file action"
  object :quarantine_result do
    field :success, non_null(:boolean)
    field :agent_id, :id
    field :path, :string
    field :sha256, :string
    field :quarantine_path, :string
    field :message, :string
    field :action_id, :id
    field :audit_status, :string
  end

  @desc "Result of an isolate host action"
  object :isolate_result do
    field :success, non_null(:boolean)
    field :agent_id, :id
    field :hostname, :string
    field :previous_status, :string
    field :message, :string
    field :action_id, :id
  end

  @desc "Result of a block IP/domain action"
  object :block_result do
    field :success, non_null(:boolean)
    field :value, :string, description: "IP or domain blocked"
    field :type, :string, description: "ip or domain"
    field :agents_affected, :integer
    field :message, :string
  end

  @desc "Result of a scan action"
  object :scan_result do
    field :success, non_null(:boolean)
    field :agent_id, :id
    field :path, :string
    field :files_scanned, :integer
    field :threats_found, :integer
    field :threats, list_of(:scan_threat)
    field :action_id, :id
  end

  @desc "A threat found during scan"
  object :scan_threat do
    field :path, :string
    field :threat_name, :string
    field :sha256, :string
    field :severity, :string
    field :action_taken, :string
  end

  @desc "Result of a forensics collection"
  object :forensics_result do
    field :success, non_null(:boolean)
    field :collection_id, :id
    field :agent_id, :id
    field :status, :string
    field :artifacts_count, :integer
    field :size_bytes, :integer
    field :message, :string
  end

  @desc "Audit log for response actions"
  object :response_audit_entry do
    field :id, non_null(:id)
    field :action_type, :string
    field :status, :string
    field :agent_id, :id
    field :agent_hostname, :string
    field :target, :string
    field :requested_by_id, :id
    field :requested_by_email, :string
    field :alert_id, :id
    field :parameters, :json
    field :result, :json
    field :error_message, :string
    field :duration_ms, :integer
    field :inserted_at, :datetime
  end

  @desc "Input for killing a process"
  input_object :kill_process_input do
    field :agent_id, non_null(:id)
    field :pid, non_null(:integer)
    field :force, :boolean, default_value: false
    field :reason, :string
    field :alert_id, :id
  end

  @desc "Input for quarantining a file"
  input_object :quarantine_file_input do
    field :agent_id, non_null(:id)
    field :path, non_null(:string)
    field :reason, :string
    field :alert_id, :id
    field :delete_original, :boolean, default_value: false
  end

  @desc "Input for isolating a host"
  input_object :isolate_host_input do
    field :agent_id, non_null(:id)
    field :reason, :string
    field :alert_id, :id
    field :allow_dns, :boolean, default_value: false
    field :allow_edr, :boolean, default_value: true
  end

  @desc "Input for blocking an IP"
  input_object :block_ip_input do
    field :ip, non_null(:string)
    field :agent_id, :id, description: "Specific agent, or all if null"
    field :direction, :string, default_value: "both", description: "inbound, outbound, both"
    field :reason, :string
    field :duration_hours, :integer, description: "Auto-expire after hours"
  end

  @desc "Input for blocking a domain"
  input_object :block_domain_input do
    field :domain, non_null(:string)
    field :agent_id, :id
    field :reason, :string
    field :add_to_ioc, :boolean, default_value: true
  end

  @desc "Input for scanning a path"
  input_object :scan_path_input do
    field :agent_id, non_null(:id)
    field :path, non_null(:string)
    field :recursive, :boolean, default_value: true
    field :quick_scan, :boolean, default_value: false
    field :auto_quarantine, :boolean, default_value: false
  end

  @desc "Filter input for response audit"
  input_object :response_audit_filter do
    field :action_type, :string
    field :status, :string
    field :agent_id, :id
    field :requested_by_id, :id
    field :alert_id, :id
    field :since, :datetime
    field :until, :datetime
  end
end
