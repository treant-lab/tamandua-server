defmodule TamanduaServer.Agents.Policy do
  @moduledoc """
  Schema for agent policies.

  Policies define the configuration, resource limits, detection rules, and response
  actions for agents. Policies support inheritance (organization → group → agent)
  and versioning.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.{CollectorCatalog, Policy, PolicyGroupAssignment, PolicyAssignment}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(draft active inactive archived)
  @scopes ~w(organization group agent)
  @policy_types ~w(template custom)

  schema "agent_policies" do
    field(:name, :string)
    field(:description, :string)
    field(:version, :integer, default: 1)
    field(:status, :string, default: "draft")
    field(:scope, :string, default: "organization")
    field(:policy_type, :string, default: "custom")
    field(:template_name, :string)

    # Raw YAML config
    field(:config, :map, default: %{})

    # Parsed and validated policy data
    field(:policy_data, :map, default: %{})

    field(:compliance_tags, {:array, :string}, default: [])
    field(:tags, {:array, :string}, default: [])
    field(:metadata, :map, default: %{})

    belongs_to(:organization, Organization)
    belongs_to(:parent_policy, Policy, foreign_key: :parent_policy_id)
    belongs_to(:created_by, User, foreign_key: :created_by_id)
    belongs_to(:updated_by, User, foreign_key: :updated_by_id)

    has_many(:child_policies, Policy, foreign_key: :parent_policy_id)
    has_many(:group_assignments, PolicyGroupAssignment)
    has_many(:agent_assignments, PolicyAssignment)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :name,
      :description,
      :version,
      :status,
      :scope,
      :policy_type,
      :template_name,
      :config,
      :policy_data,
      :compliance_tags,
      :tags,
      :metadata,
      :organization_id,
      :parent_policy_id,
      :created_by_id,
      :updated_by_id
    ])
    |> validate_required([:name, :organization_id, :policy_data])
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:scope, @scopes)
    |> validate_inclusion(:policy_type, @policy_types)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_policy_data()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:parent_policy_id)
    |> unique_constraint([:organization_id, :name, :version],
      name: :agent_policies_org_name_version_index
    )
  end

  defp validate_policy_data(changeset) do
    case get_field(changeset, :policy_data) do
      nil ->
        add_error(changeset, :policy_data, "cannot be nil")

      policy_data when is_map(policy_data) ->
        errors = []

        errors =
          if Map.has_key?(policy_data, "profile") and
               not CollectorCatalog.valid_profile?(policy_data["profile"]) do
            [{:policy_data, "invalid performance profile: #{policy_data["profile"]}"} | errors]
          else
            errors
          end

        # Validate collectors section
        errors =
          if Map.has_key?(policy_data, "collectors") do
            validate_collectors(policy_data["collectors"], errors)
          else
            errors
          end

        # Validate resource_limits section
        errors =
          if Map.has_key?(policy_data, "resource_limits") do
            validate_resource_limits(policy_data["resource_limits"], errors)
          else
            errors
          end

        # Validate detection section
        errors =
          if Map.has_key?(policy_data, "detection") do
            validate_detection(policy_data["detection"], errors)
          else
            errors
          end

        # Validate response section
        errors =
          if Map.has_key?(policy_data, "response") do
            validate_response(policy_data["response"], errors)
          else
            errors
          end

        # Add all validation errors
        Enum.reduce(errors, changeset, fn {field, message}, cs ->
          add_error(cs, field, message)
        end)

      _ ->
        add_error(changeset, :policy_data, "must be a map")
    end
  end

  defp validate_collectors(collectors, errors) when is_map(collectors) do
    Enum.reduce(collectors, errors, fn {name, config}, acc ->
      normalized_name = CollectorCatalog.normalize_collector(name)

      cond do
        not CollectorCatalog.valid_collector?(normalized_name) ->
          [{:policy_data, "invalid collector: #{name}"} | acc]

        not is_map(config) ->
          [{:policy_data, "collector #{name} config must be a map"} | acc]

        valid_collector_config?(config) ->
          acc

        true ->
          [
            {:policy_data,
             "collector #{name} must have enabled boolean and optional positive interval_ms/sample_rate/priority"}
            | acc
          ]
      end
    end)
  end

  defp validate_collectors(_collectors, errors) do
    [{:policy_data, "collectors must be a map"} | errors]
  end

  defp valid_collector_config?(config) do
    enabled_valid? = is_boolean(config["enabled"])
    interval_valid? = is_nil(config["interval_ms"]) or positive_integer?(config["interval_ms"])
    sample_valid? = is_nil(config["sample_rate"]) or valid_sample_rate?(config["sample_rate"])

    priority_valid? =
      is_nil(config["priority"]) or config["priority"] in ~w(low normal high critical)

    enabled_valid? and interval_valid? and sample_valid? and priority_valid?
  end

  defp positive_integer?(value), do: is_integer(value) and value > 0

  defp valid_sample_rate?(value) when is_number(value), do: value > 0 and value <= 1
  defp valid_sample_rate?(_), do: false

  defp validate_resource_limits(limits, errors) when is_map(limits) do
    errors =
      if is_integer(limits["max_cpu_percent"]) and limits["max_cpu_percent"] > 0 and
           limits["max_cpu_percent"] <= 100 do
        errors
      else
        [{:policy_data, "max_cpu_percent must be between 1 and 100"} | errors]
      end

    errors =
      if is_integer(limits["max_memory_mb"]) and limits["max_memory_mb"] > 0 do
        errors
      else
        [{:policy_data, "max_memory_mb must be a positive integer"} | errors]
      end

    if is_integer(limits["max_disk_mb"]) and limits["max_disk_mb"] > 0 do
      errors
    else
      [{:policy_data, "max_disk_mb must be a positive integer"} | errors]
    end
  end

  defp validate_resource_limits(_limits, errors) do
    [{:policy_data, "resource_limits must be a map"} | errors]
  end

  defp validate_detection(detection, errors) when is_map(detection) do
    errors =
      if is_boolean(detection["yara_enabled"]) do
        errors
      else
        [{:policy_data, "yara_enabled must be a boolean"} | errors]
      end

    errors =
      if is_boolean(detection["sigma_enabled"]) do
        errors
      else
        [{:policy_data, "sigma_enabled must be a boolean"} | errors]
      end

    if is_boolean(detection["ml_enabled"]) do
      errors
    else
      [{:policy_data, "ml_enabled must be a boolean"} | errors]
    end
  end

  defp validate_detection(_detection, errors) do
    [{:policy_data, "detection must be a map"} | errors]
  end

  defp validate_response(response, errors) when is_map(response) do
    valid_actions = ~w(isolate kill_process quarantine delete_file restore_file screen_capture)

    errors =
      if is_list(response["allowed_actions"]) and
           Enum.all?(response["allowed_actions"], &(&1 in valid_actions)) do
        errors
      else
        [{:policy_data, "allowed_actions must be a list of valid actions"} | errors]
      end

    errors =
      if is_boolean(response["auto_response_enabled"]) do
        errors
      else
        [{:policy_data, "auto_response_enabled must be a boolean"} | errors]
      end

    errors =
      if is_integer(response["max_actions_per_hour"]) and response["max_actions_per_hour"] > 0 do
        errors
      else
        [{:policy_data, "max_actions_per_hour must be a positive integer"} | errors]
      end

    validate_screen_capture_policy(response["screen_capture"], errors)
  end

  defp validate_response(_response, errors) do
    [{:policy_data, "response must be a map"} | errors]
  end

  defp validate_screen_capture_policy(nil, errors), do: errors

  defp validate_screen_capture_policy(config, errors) when is_map(config) do
    mode = config["mode"]
    timing = config["notify_timing"]
    scopes = Map.get(config, "allowed_scopes", ["virtual_desktop"])
    redaction_required = Map.get(config, "redaction_required", false)

    errors =
      if is_list(scopes) and scopes != [] and
           Enum.all?(scopes, &(&1 in ~w(virtual_desktop monitor active_window))) do
        errors
      else
        [
          {:policy_data,
           "response.screen_capture.allowed_scopes must contain virtual_desktop, monitor, or active_window"}
          | errors
        ]
      end

    errors =
      if is_boolean(redaction_required),
        do: errors,
        else:
          [
            {:policy_data, "response.screen_capture.redaction_required must be boolean"}
            | errors
          ]

    cond do
      mode not in ~w(silent notify consent_required disabled) ->
        [
          {:policy_data,
           "response.screen_capture.mode must be silent, notify, consent_required, or disabled"}
          | errors
        ]

      mode == "notify" and timing not in ~w(before_capture after_capture) ->
        [
          {:policy_data,
           "response.screen_capture.notify_timing must be before_capture or after_capture for notify mode"}
          | errors
        ]

      mode != "notify" and not is_nil(timing) ->
        [
          {:policy_data, "response.screen_capture.notify_timing is only valid for notify mode"}
          | errors
        ]

      true ->
        errors
    end
  end

  defp validate_screen_capture_policy(_config, errors) do
    [{:policy_data, "response.screen_capture must be a map"} | errors]
  end

  @doc """
  Returns the default policy template names available.
  """
  def available_templates do
    ~w(baseline lightweight balanced aggressive server_safe vdi_safe high_value_asset forensic_burst performance forensics custom)
  end

  @doc """
  Merges a child policy with its parent policy, with child taking precedence.
  """
  def merge_with_parent(%Policy{parent_policy: nil} = policy), do: policy.policy_data

  def merge_with_parent(%Policy{parent_policy: parent} = policy) do
    parent_data = merge_with_parent(parent)
    deep_merge(parent_data, policy.policy_data)
  end

  defp deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, fn
      _k, v1, v2 when is_map(v1) and is_map(v2) -> deep_merge(v1, v2)
      _k, _v1, v2 -> v2
    end)
  end

  defp deep_merge(_left, right), do: right
end
