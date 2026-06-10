defmodule TamanduaServer.Alerts.SuppressionRule do
  @moduledoc """
  Schema for alert suppression rules.

  Suppression rules are created when analysts mark alerts as false positive
  and choose to suppress similar future alerts. They match on alert
  characteristics (rule name, process name, agent, file path, etc.) and
  either suppress the alert entirely or reduce its severity.

  Rules have a configurable TTL (default 30 days) and track how many
  alerts they have matched.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "alert_suppression_rules" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true

    # Matching criteria (AND logic -- all non-nil fields must match)
    field :rule_name_pattern, :string
    field :agent_id, :binary_id
    field :process_name_pattern, :string
    field :parent_process_pattern, :string
    field :file_path_pattern, :string
    field :title_pattern, :string
    field :severity, :string
    field :mitre_techniques, {:array, :string}, default: []
    field :tags, {:array, :string}, default: []

    # Full criteria as JSON for complex matching
    field :criteria, :map, default: %{}

    # Time window configuration
    field :time_window_type, :string  # "duration", "indefinite", "until_date"
    field :time_window_value, :integer  # seconds for duration
    field :expires_at, :utc_datetime_usec

    # Rule priority (higher number = higher priority)
    field :priority, :integer, default: 0

    # Exemptions
    field :exempted_agent_ids, {:array, :binary_id}, default: []
    field :exempted_users, {:array, :string}, default: []

    # Tracking
    field :match_count, :integer, default: 0
    field :last_matched_at, :utc_datetime_usec
    field :max_matches, :integer

    # Action: suppress, reduce_severity, tag
    field :action, :string, default: "suppress"
    field :reduce_to_severity, :string
    field :add_tags, {:array, :string}, default: []

    # Template support
    field :is_template, :boolean, default: false
    field :template_name, :string
    field :template_description, :string

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id, type: :binary_id
    belongs_to :source_alert, Alert, foreign_key: :source_alert_id, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @valid_actions ~w(suppress reduce_severity tag)
  @valid_severities ~w(critical high medium low info)
  @valid_time_window_types ~w(duration indefinite until_date)

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :name, :description, :enabled,
      :rule_name_pattern, :agent_id, :process_name_pattern,
      :parent_process_pattern, :file_path_pattern, :title_pattern,
      :severity, :mitre_techniques, :tags, :criteria,
      :time_window_type, :time_window_value, :expires_at,
      :priority, :exempted_agent_ids, :exempted_users,
      :match_count, :last_matched_at, :max_matches,
      :action, :reduce_to_severity, :add_tags,
      :is_template, :template_name, :template_description,
      :organization_id, :created_by_id, :source_alert_id
    ])
    |> validate_required([:name, :action])
    |> validate_inclusion(:action, @valid_actions)
    |> validate_inclusion(:reduce_to_severity, @valid_severities ++ [nil])
    |> validate_inclusion(:time_window_type, @valid_time_window_types ++ [nil])
    |> validate_has_criteria()
    |> validate_time_window()
    |> compute_expires_at()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
    |> foreign_key_constraint(:source_alert_id)
  end

  # Ensure at least one matching criterion is set
  defp validate_has_criteria(changeset) do
    criteria_fields = [
      :rule_name_pattern, :agent_id, :process_name_pattern,
      :parent_process_pattern, :file_path_pattern, :title_pattern,
      :severity
    ]

    has_criteria = Enum.any?(criteria_fields, fn field ->
      val = get_change(changeset, field) || get_field(changeset, field)
      val != nil and val != ""
    end)

    has_json_criteria = case get_change(changeset, :criteria) || get_field(changeset, :criteria) do
      criteria when is_map(criteria) and map_size(criteria) > 0 -> true
      _ -> false
    end

    has_mitre = case get_change(changeset, :mitre_techniques) || get_field(changeset, :mitre_techniques) do
      techniques when is_list(techniques) and length(techniques) > 0 -> true
      _ -> false
    end

    has_tags = case get_change(changeset, :tags) || get_field(changeset, :tags) do
      tags when is_list(tags) and length(tags) > 0 -> true
      _ -> false
    end

    if has_criteria or has_json_criteria or has_mitre or has_tags do
      changeset
    else
      add_error(changeset, :criteria, "at least one matching criterion must be specified")
    end
  end

  # Validate time window configuration
  defp validate_time_window(changeset) do
    time_window_type = get_change(changeset, :time_window_type) || get_field(changeset, :time_window_type)
    time_window_value = get_change(changeset, :time_window_value) || get_field(changeset, :time_window_value)

    case time_window_type do
      "duration" ->
        if is_nil(time_window_value) or time_window_value <= 0 do
          add_error(changeset, :time_window_value, "must be a positive integer when using duration type")
        else
          changeset
        end

      "until_date" ->
        expires_at = get_change(changeset, :expires_at) || get_field(changeset, :expires_at)
        if is_nil(expires_at) do
          add_error(changeset, :expires_at, "must be set when using until_date type")
        else
          changeset
        end

      _ ->
        changeset
    end
  end

  # Compute expires_at based on time_window_type and time_window_value
  defp compute_expires_at(changeset) do
    time_window_type = get_change(changeset, :time_window_type) || get_field(changeset, :time_window_type)
    time_window_value = get_change(changeset, :time_window_value) || get_field(changeset, :time_window_value)

    case time_window_type do
      "duration" when not is_nil(time_window_value) ->
        expires_at = DateTime.utc_now() |> DateTime.add(time_window_value, :second)
        put_change(changeset, :expires_at, expires_at)

      "indefinite" ->
        put_change(changeset, :expires_at, nil)

      _ ->
        changeset
    end
  end

  @type t :: %__MODULE__{}

  @doc """
  Check if this rule matches a given alert.

  All non-nil pattern fields must match (AND logic). Pattern fields
  support wildcards via `String.contains?` matching.

  Also checks exemptions - if the alert's agent or user is exempted,
  the rule will not match.
  """
  @spec matches_alert?(t(), Alert.t(), map()) :: boolean()
  def matches_alert?(%__MODULE__{} = rule, %Alert{} = alert, context \\ %{}) do
    # Check expiry
    if rule.expires_at && DateTime.compare(DateTime.utc_now(), rule.expires_at) == :gt do
      false
    else
      # Check max matches
      if rule.max_matches && rule.match_count >= rule.max_matches do
        false
      else
        # Check exemptions
        if is_exempted?(rule, alert, context) do
          false
        else
          matches_all_criteria?(rule, alert)
        end
      end
    end
  end

  # Check if the alert is exempted from this rule
  defp is_exempted?(rule, alert, context) do
    # Check agent exemption
    agent_exempted = alert.agent_id && alert.agent_id in (rule.exempted_agent_ids || [])

    # Check user exemption (from context)
    user_exempted = case context[:user_email] || context[:username] do
      nil -> false
      username -> username in (rule.exempted_users || [])
    end

    agent_exempted || user_exempted
  end

  defp matches_all_criteria?(rule, alert) do
    checks = [
      {rule.title_pattern, alert.title, :contains},
      {rule.severity, alert.severity, :exact},
      {rule.agent_id, alert.agent_id, :exact},
      {rule.rule_name_pattern, get_rule_name(alert), :contains},
      {rule.process_name_pattern, get_process_name(alert), :contains},
      {rule.parent_process_pattern, get_parent_process(alert), :contains},
      {rule.file_path_pattern, get_file_path(alert), :contains}
    ]

    # All non-nil criteria must match
    Enum.all?(checks, fn
      {nil, _actual, _mode} -> true
      {"", _actual, _mode} -> true
      {_pattern, nil, _mode} -> false
      {pattern, actual, :exact} -> pattern == actual
      {pattern, actual, :contains} ->
        pattern_lower = String.downcase(pattern)
        actual_lower = String.downcase(to_string(actual))

        if String.contains?(pattern_lower, "*") do
          # Wildcard matching: convert pattern to regex
          regex_str = pattern_lower
          |> Regex.escape()
          |> String.replace("\\*", ".*")

          case Regex.compile("^#{regex_str}$") do
            {:ok, regex} -> Regex.match?(regex, actual_lower)
            _ -> String.contains?(actual_lower, pattern_lower)
          end
        else
          String.contains?(actual_lower, pattern_lower)
        end
    end)
    |> then(fn result ->
      # Also check MITRE techniques if specified
      if result and rule.mitre_techniques != [] do
        alert_techniques = alert.mitre_techniques || []
        Enum.any?(rule.mitre_techniques, & &1 in alert_techniques)
      else
        result
      end
    end)
  end

  defp get_rule_name(alert) do
    case alert.detection_metadata do
      %{"rule_name" => name} -> name
      %{rule_name: name} -> name
      _ -> nil
    end
  end

  defp get_process_name(alert) do
    case alert.evidence do
      %{"process" => %{"name" => name}} -> name
      %{process: %{name: name}} -> name
      _ -> nil
    end
  end

  defp get_parent_process(alert) do
    case alert.evidence do
      %{"process" => %{"parent_name" => name}} -> name
      %{process: %{parent_name: name}} -> name
      _ ->
        # Try process chain
        case alert.process_chain do
          [parent | _] -> parent["name"] || parent[:name]
          _ -> nil
        end
    end
  end

  defp get_file_path(alert) do
    case alert.evidence do
      %{"process" => %{"path" => path}} -> path
      %{process: %{path: path}} -> path
      %{"file_hashes" => [%{"path" => path} | _]} -> path
      _ -> nil
    end
  end
end
